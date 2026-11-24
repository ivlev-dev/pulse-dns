//! Долговременные и краткосрочные ключи DNSCrypt v2.
//!
//! - [`ProviderKeypair`] — Ed25519, подписывает сертификаты.
//! - [`ResolverKeypair`] — X25519 (через [`crypto_box::SecretKey`]),
//!   используется для `crypto_box_xchacha20poly1305`.
//!
//! Секретные ключи не выводятся через `Debug`; [`ResolverKeypair`] можно
//! сериализовать в [`zeroize::Zeroizing`]-буфер.

use std::fmt;

use crypto_box::{PublicKey as BoxPublicKey, SecretKey as BoxSecretKey};
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use zeroize::{Zeroize as _, Zeroizing};

use crate::error::Error;
use crate::util;

/// Длина открытого/секретного ключа X25519 и Ed25519.
pub const KEY_LEN: usize = 32;

/// Длина подписи Ed25519.
pub const SIGNATURE_LEN: usize = 64;

/// Долговременная пара ключей провайдера (Ed25519).
#[derive(Clone)]
pub struct ProviderKeypair {
    signing: SigningKey,
}

impl ProviderKeypair {
    /// Генерирует ключевую пару из системного CSPRNG.
    ///
    /// # Errors
    ///
    /// [`Error::Random`], если источник случайных чисел недоступен.
    pub fn generate() -> Result<Self, Error> {
        let mut seed = [0_u8; KEY_LEN];
        getrandom::fill(&mut seed)?;
        Ok(Self::from_seed(seed))
    }

    /// Создаёт ключевую пару из 32-байтового seed.
    ///
    /// Это детерминированный конструктор для тестов и восстановления из
    /// хранилища; seed является секретом.
    #[must_use]
    pub fn from_seed(seed: [u8; KEY_LEN]) -> Self {
        let mut seed = Zeroizing::new(seed);
        let signing = SigningKey::from_bytes(&seed);
        seed.zeroize();
        Self { signing }
    }

    /// Открытый ключ провайдера.
    #[must_use]
    pub fn public_key(&self) -> ProviderPublicKey {
        ProviderPublicKey {
            verifying: self.signing.verifying_key(),
        }
    }

    /// Подписывает сообщение (сертификат) Ed25519.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.signing.sign(message).to_bytes()
    }

    /// Секретный seed для резервного копирования.
    #[must_use]
    pub fn to_seed(&self) -> Zeroizing<[u8; KEY_LEN]> {
        Zeroizing::new(self.signing.to_bytes())
    }
}

impl fmt::Debug for ProviderKeypair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderKeypair")
            .field("public_key", &self.public_key())
            .field("secret_key", &"[REDACTED]")
            .finish()
    }
}

/// Открытый ключ провайдера (Ed25519).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ProviderPublicKey {
    verifying: VerifyingKey,
}

impl ProviderPublicKey {
    /// Импортирует открытый ключ из 32 байт.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidCertificateSignature`], если точка Ed25519 не является
    /// корректным открытым ключом.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Result<Self, Error> {
        let verifying =
            VerifyingKey::from_bytes(&bytes).map_err(|_| Error::InvalidCertificateSignature)?;
        Ok(Self { verifying })
    }

    /// Импортирует открытый ключ из hex-строки.
    ///
    /// # Errors
    ///
    /// [`Error::HexDecode`] или [`Error::InvalidCertificateSignature`].
    pub fn from_hex(text: &str) -> Result<Self, Error> {
        let bytes = util::from_hex(text)?;
        let array: [u8; KEY_LEN] = bytes
            .try_into()
            .map_err(|_| Error::InvalidCertificateSignature)?;
        Self::from_bytes(array)
    }

    /// Байты открытого ключа.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; KEY_LEN] {
        self.verifying.to_bytes()
    }

    /// Hex-представление (для TXT-записи `2.pubkey.<provider>`).
    #[must_use]
    pub fn to_hex(&self) -> String {
        util::to_hex(&self.to_bytes())
    }

    /// Проверяет подпись Ed25519.
    #[must_use]
    pub fn verify(&self, message: &[u8], signature: &[u8; SIGNATURE_LEN]) -> bool {
        let signature = ed25519_dalek::Signature::from_bytes(signature);
        self.verifying.verify_strict(message, &signature).is_ok()
    }
}

impl fmt::Debug for ProviderPublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ProviderPublicKey")
            .field(&self.to_hex())
            .finish()
    }
}

/// Краткосрочная пара ключей резолвера (X25519).
#[derive(Clone)]
pub struct ResolverKeypair {
    secret: BoxSecretKey,
}

impl ResolverKeypair {
    /// Генерирует ключевую пару из системного CSPRNG.
    ///
    /// # Errors
    ///
    /// [`Error::Random`], если источник случайных чисел недоступен.
    pub fn generate() -> Result<Self, Error> {
        let mut bytes = [0_u8; KEY_LEN];
        getrandom::fill(&mut bytes)?;
        let secret = BoxSecretKey::from_bytes(bytes);
        Ok(Self { secret })
    }

    /// Создаёт пару из 32-байтового секрета.
    ///
    /// X25519-clamping применяется при вычислении скаляра, как в libsodium.
    #[must_use]
    pub fn from_secret_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self {
            secret: BoxSecretKey::from_bytes(bytes),
        }
    }

    /// Открытый ключ резолвера.
    #[must_use]
    pub fn public_key(&self) -> ResolverPublicKey {
        ResolverPublicKey {
            public: self.secret.public_key(),
        }
    }

    /// Секретные байты для резервного копирования.
    #[must_use]
    pub fn to_secret_bytes(&self) -> Zeroizing<[u8; KEY_LEN]> {
        Zeroizing::new(self.secret.to_bytes())
    }

    /// Секретный ключ для AEAD-операций.
    pub(crate) const fn secret(&self) -> &BoxSecretKey {
        &self.secret
    }
}

impl fmt::Debug for ResolverKeypair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolverKeypair")
            .field("public_key", &self.public_key())
            .field("secret_key", &"[REDACTED]")
            .finish()
    }
}

/// Открытый ключ резолвера (X25519).
#[derive(Clone, PartialEq, Eq)]
pub struct ResolverPublicKey {
    public: BoxPublicKey,
}

impl ResolverPublicKey {
    /// Импортирует открытый ключ из 32 байт.
    ///
    /// # Errors
    ///
    /// В текущей реализации любая 32-байтовая последовательность является
    /// допустимым представлением `MontgomeryPoint`; ошибка не возвращается.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Result<Self, Error> {
        Ok(Self {
            public: BoxPublicKey::from_bytes(bytes),
        })
    }

    /// Байты открытого ключа.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; KEY_LEN] {
        self.public.to_bytes()
    }

    /// Hex-представление.
    #[must_use]
    pub fn to_hex(&self) -> String {
        util::to_hex(&self.to_bytes())
    }

    pub(crate) const fn as_box(&self) -> &BoxPublicKey {
        &self.public
    }
}

impl fmt::Debug for ResolverPublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ResolverPublicKey")
            .field(&self.to_hex())
            .finish()
    }
}
