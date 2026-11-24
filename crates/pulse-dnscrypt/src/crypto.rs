//! Криптографическое ядро: `crypto_box_curve25519xchacha20poly1305`.
//!
//! Конструкция точно соответствует libsodium (DNSCrypt v2 §11):
//!
//! 1. `X25519(client-sk, resolver-pk)` → 32-байтовый shared secret;
//! 2. `key = HChaCha20(shared, 0^16)` (это делает [`crypto_box::ChaChaBox`]);
//! 3. `AEAD = crypto_secretbox_xchacha20poly1305`: XChaCha20 + Poly1305,
//!    MAC (16 байт) **впереди** шифротекста, associated data не используется.
//!
//! Именно эту конструкцию реализуют libsodium и `xsecretbox` из
//! dnscrypt-proxy, поэтому байты совместимы с существующими клиентами.
//! IETF-вариант `XChaCha20-Poly1305` (RFC 8439-стиль) сюда **не** подходит:
//! у него другой layout keystream и MAC.

use crypto_box::{ChaChaBox, aead::Aead as _};
use zeroize::Zeroizing;

use crate::error::Error;
use crate::keys::{ResolverKeypair, ResolverPublicKey};

/// Длина nonce AEAD.
pub const NONCE_LEN: usize = 24;

/// Длина nonce, выбираемая клиентом/резолвером (половина [`NONCE_LEN`]).
pub const HALF_NONCE_LEN: usize = 12;

/// Длина MAC Poly1305.
pub const MAC_LEN: usize = 16;

/// Собирает nonce запроса: 12 байт клиента + 12 нулевых байт.
#[must_use]
pub fn query_nonce(client_nonce: &[u8; HALF_NONCE_LEN]) -> [u8; NONCE_LEN] {
    let mut nonce = [0_u8; NONCE_LEN];
    if let Some(target) = nonce.get_mut(..HALF_NONCE_LEN) {
        target.copy_from_slice(client_nonce);
    }
    nonce
}

/// Собирает nonce ответа: `<client-nonce> <resolver-nonce>`.
#[must_use]
pub fn response_nonce(
    client_nonce: &[u8; HALF_NONCE_LEN],
    resolver_nonce: &[u8; HALF_NONCE_LEN],
) -> [u8; NONCE_LEN] {
    let mut nonce = [0_u8; NONCE_LEN];
    if let Some(left) = nonce.get_mut(..HALF_NONCE_LEN) {
        left.copy_from_slice(client_nonce);
    }
    if let Some(right) = nonce.get_mut(HALF_NONCE_LEN..) {
        right.copy_from_slice(resolver_nonce);
    }
    nonce
}

/// Выводит общий ключ `crypto_box_xchacha20poly1305` для пары ключей.
#[must_use]
pub(crate) fn shared_box(peer: &ResolverPublicKey, own: &ResolverKeypair) -> ChaChaBox {
    ChaChaBox::new(peer.as_box(), own.secret())
}

/// Шифрует и аутентифицирует `plaintext`; MAC добавляется в начало.
///
/// # Errors
///
/// [`Error::EncryptionFailed`] при ошибке AEAD (например, превышении лимита
/// длины сообщения).
pub(crate) fn seal(
    shared: &ChaChaBox,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    shared
        .encrypt(nonce.into(), plaintext)
        .map_err(|_| Error::EncryptionFailed)
}

/// Проверяет MAC и расшифровывает `ciphertext` (MAC в начале).
///
/// # Errors
///
/// [`Error::DecryptionFailed`], если MAC неверен или пакет повреждён.
pub(crate) fn open(
    shared: &ChaChaBox,
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    shared
        .decrypt(nonce.into(), ciphertext)
        .map(Zeroizing::new)
        .map_err(|_| Error::DecryptionFailed)
}

/// Заполняет буфер системным CSPRNG.
///
/// # Errors
///
/// [`Error::Random`], если источник случайных чисел недоступен.
pub fn random_bytes<const N: usize>() -> Result<[u8; N], Error> {
    let mut bytes = [0_u8; N];
    getrandom::fill(&mut bytes)?;
    Ok(bytes)
}
