//! Дополнение ISO/IEC 7816-4 для DNSCrypt v2 (§3, §5, §8).
//!
//! Дополнение всегда начинается с `0x80` и продолжается нулями. Нулевая
//! длина дополнения запрещена; [`unpad`] отвергает буфер без `0x80`.

use crate::crypto::{HALF_NONCE_LEN, MAC_LEN};
use crate::error::Error;

/// Минимальная длина дополнения (включая `0x80`).
pub const MIN_PAD_LEN: usize = 1;

/// Максимальная длина дополнения (включая `0x80`).
pub const MAX_PAD_LEN: usize = 256;

/// Размер блока, которому кратен дополненный текст.
pub const PAD_BLOCK_LEN: usize = 64;

/// Маркер начала дополнения.
pub const PAD_MARKER: u8 = 0x80;

/// Заголовок зашифрованного запроса: magic + client-pk + client-nonce.
pub const QUERY_HEADER_LEN: usize = 8 + 32 + HALF_NONCE_LEN;

/// Заголовок зашифрованного ответа: resolver-magic + полный nonce.
pub const RESPONSE_HEADER_LEN: usize = 8 + 24;

/// Накладные расходы зашифрованного запроса (заголовок + MAC).
pub const QUERY_PACKET_OVERHEAD: usize = QUERY_HEADER_LEN + MAC_LEN;

/// Накладные расходы зашифрованного ответа (заголовок + MAC).
pub const RESPONSE_PACKET_OVERHEAD: usize = RESPONSE_HEADER_LEN + MAC_LEN;

/// Минимальная длина DNSCrypt-пакета запроса (заголовок + MAC + маркер).
pub const MIN_QUERY_PACKET_LEN: usize = QUERY_PACKET_OVERHEAD + MIN_PAD_LEN;

/// Минимальная длина DNSCrypt-пакета ответа (заголовок + MAC + маркер).
pub const MIN_RESPONSE_PACKET_LEN: usize = RESPONSE_PACKET_OVERHEAD + MIN_PAD_LEN;

/// Дополняет `data` до длины `target_len` (`0x80` + нули).
///
/// # Errors
///
/// [`Error::InvalidPadding`], если `target_len <= data.len()` или итоговая
/// длина дополнения выходит за [`MIN_PAD_LEN`]..=[`MAX_PAD_LEN`].
pub fn pad_to_len(data: &[u8], target_len: usize) -> Result<Vec<u8>, Error> {
    let pad_len = target_len.saturating_sub(data.len());
    if !(MIN_PAD_LEN..=MAX_PAD_LEN).contains(&pad_len) {
        return Err(Error::InvalidPadding);
    }
    let mut out = Vec::with_capacity(target_len);
    out.extend_from_slice(data);
    out.push(PAD_MARKER);
    out.resize(target_len, 0);
    Ok(out)
}

/// Убирает дополнение ISO/IEC 7816-4.
///
/// # Errors
///
/// [`Error::InvalidPadding`], если маркер `0x80` не найден.
pub fn unpad(data: &[u8]) -> Result<&[u8], Error> {
    let Some(last_non_zero) = data.iter().rposition(|byte| *byte != 0) else {
        return Err(Error::InvalidPadding);
    };
    if data.get(last_non_zero).copied() != Some(PAD_MARKER) {
        return Err(Error::InvalidPadding);
    }
    data.get(..last_non_zero).ok_or(Error::InvalidPadding)
}

/// Округляет вверх до кратного [`PAD_BLOCK_LEN`].
#[must_use]
pub const fn round_up_block(len: usize) -> usize {
    let remainder = len % PAD_BLOCK_LEN;
    if remainder == 0 {
        len
    } else {
        len + (PAD_BLOCK_LEN - remainder)
    }
}

/// Вычисляет длину дополненного UDP-запроса: не меньше `min_query_len` и
/// кратна 64. `max_padded_len` уже должен быть кратен 64.
///
/// # Errors
///
/// [`Error::InvalidPadding`], если результат не помещается в лимит.
pub fn udp_query_padded_len(
    query_len: usize,
    min_query_len: usize,
    max_padded_len: usize,
) -> Result<usize, Error> {
    let next = round_up_block(query_len.saturating_add(MIN_PAD_LEN));
    let target = next.max(min_query_len);
    if target > max_padded_len || target.saturating_sub(query_len) > MAX_PAD_LEN {
        return Err(Error::InvalidPadding);
    }
    Ok(target)
}

/// Вычисляет длину дополнения TCP-запроса из случайного байта: одно из
/// значений `r, r+64, r+128, r+192`, где `r = (-query_len) mod 64`
/// (при `r == 0` используется 64), чтобы итог был кратен 64, а дополнение
/// лежало в 1..=256.
#[must_use]
pub fn tcp_pad_len(query_len: usize, selector: u8) -> usize {
    let remainder = query_len % PAD_BLOCK_LEN;
    let base = if remainder == 0 {
        PAD_BLOCK_LEN
    } else {
        PAD_BLOCK_LEN - remainder
    };
    let index = usize::from(selector % 4);
    base.saturating_add(index.saturating_mul(PAD_BLOCK_LEN))
}

/// Детерминированная длина случайной составляющей дополнения ответа.
///
/// Зависит только от клиентского nonce, поэтому постоянна для пары
/// `(resolver-sk, client-nonce)` и не требует секретного состояния.
#[must_use]
pub fn response_pad_seed(client_nonce: &[u8; HALF_NONCE_LEN]) -> usize {
    let high = usize::from(client_nonce.first().copied().unwrap_or(0));
    let low = usize::from(client_nonce.get(1).copied().unwrap_or(0));
    MIN_PAD_LEN + (((high << 8) | low) % MAX_PAD_LEN)
}

/// Вычисляет длину дополненного ответа: кратна 64, дополнение 1..=256.
///
/// # Errors
///
/// [`Error::InvalidPadding`], если дополнение не укладывается в лимиты.
pub fn response_padded_len(
    response_len: usize,
    client_nonce: &[u8; HALF_NONCE_LEN],
) -> Result<usize, Error> {
    let seed = response_pad_seed(client_nonce);
    let mut target = (response_len.saturating_add(seed)) & !(PAD_BLOCK_LEN - 1);
    if target <= response_len {
        target = target.saturating_add(2 * PAD_BLOCK_LEN);
    }
    let pad_len = target.saturating_sub(response_len);
    if !(MIN_PAD_LEN..=MAX_PAD_LEN).contains(&pad_len) {
        return Err(Error::InvalidPadding);
    }
    Ok(target)
}
