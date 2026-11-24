//! TCP framing для DNS-сообщений (RFC 1035 §4.2.2).

use std::io::{Read, Write};

use pulse_dns::MAX_MESSAGE_LEN;

use crate::error::TransferError;

/// Читает length-prefixed DNS-сообщение.
///
/// # Errors
///
/// [`TransferError::Io`], [`TransferError::Protocol`] при нулевой длине.
pub fn read_message(reader: &mut impl Read) -> Result<Vec<u8>, TransferError> {
    let mut length = [0u8; 2];
    reader.read_exact(&mut length)?;
    let length = usize::from(u16::from_be_bytes(length));
    if length == 0 {
        return Err(TransferError::protocol("zero-length DNS message"));
    }
    if length > MAX_MESSAGE_LEN {
        return Err(TransferError::MessageTooLarge { len: length });
    }
    let mut message = vec![0u8; length];
    reader.read_exact(&mut message)?;
    Ok(message)
}

/// Записывает length-prefixed DNS-сообщение.
///
/// # Errors
///
/// [`TransferError::MessageTooLarge`], [`TransferError::Protocol`] для пустого
/// сообщения и [`TransferError::Io`].
pub fn write_message(writer: &mut impl Write, message: &[u8]) -> Result<(), TransferError> {
    if message.is_empty() {
        return Err(TransferError::protocol("zero-length DNS message"));
    }
    let length = u16::try_from(message.len())
        .map_err(|_| TransferError::MessageTooLarge { len: message.len() })?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(message)?;
    writer.flush()?;
    Ok(())
}
