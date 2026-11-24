//! Кодирование сертификатов в hex/base64 и разбор текстовых форм.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::error::Error;

/// Кодирует байты в hex (нижний регистр).
#[must_use]
pub fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Декодирует hex (регистр не важен, пробелы не допускаются).
///
/// # Errors
///
/// [`Error::HexDecode`], если строка содержит посторонние символы или имеет
/// нечётную длину.
pub fn from_hex(text: &str) -> Result<Vec<u8>, Error> {
    hex::decode(text.trim()).map_err(|_| Error::HexDecode)
}

/// Кодирует байты в стандартный base64 с padding.
#[must_use]
pub fn to_base64(bytes: &[u8]) -> String {
    BASE64.encode(bytes)
}

/// Декодирует стандартный base64.
///
/// # Errors
///
/// [`Error::Base64Decode`] при некорректном алфавите или длине.
pub fn from_base64(text: &str) -> Result<Vec<u8>, Error> {
    BASE64.decode(text.trim()).map_err(|_| Error::Base64Decode)
}
