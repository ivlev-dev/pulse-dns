//! Низкоуровневый разбор wire-сообщения без повторного кодирования.
//!
//! Нужен, чтобы вырезать TSIG RR из уже переданного сообщения, не меняя
//! остальные байты: MAC считается по сообщению ровно в том виде, в каком оно
//! было отправлено (RFC 8945 §4.3.2).

use pulse_dns::Rtype;

use crate::error::TsigError;

/// Результат вырезания TSIG из сообщения.
pub(crate) struct Stripped {
    /// Сообщение без TSIG и с уменьшенным ARCOUNT.
    pub(crate) bytes: Vec<u8>,
    /// ID из заголовка до нормализации по `Original ID`.
    pub(crate) wire_id: u16,
}

/// Читает big-endian `u16` по смещению.
pub(crate) fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let slice = bytes.get(offset..offset.checked_add(2)?)?;
    let array = <[u8; 2]>::try_from(slice).ok()?;
    Some(u16::from_be_bytes(array))
}

/// Читает big-endian `u32` по смещению.
pub(crate) fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice = bytes.get(offset..offset.checked_add(4)?)?;
    let array = <[u8; 4]>::try_from(slice).ok()?;
    Some(u32::from_be_bytes(array))
}

/// Читает 48-битное целое по смещению.
pub(crate) fn read_u48(bytes: &[u8], offset: usize) -> Option<u64> {
    let high = u64::from(read_u32(bytes, offset)?);
    let low = u64::from(read_u16(bytes, offset.checked_add(4)?)?);
    Some((high << 16) | low)
}

/// Пропускает domain name (с указателем сжатия) и возвращает смещение после него.
pub(crate) fn skip_name(bytes: &[u8], offset: usize) -> Option<usize> {
    let mut position = offset;
    let mut labels = 0_usize;
    loop {
        let length = *bytes.get(position)?;
        if length == 0 {
            return position.checked_add(1);
        }
        if length & 0xC0 == 0xC0 {
            bytes.get(position.checked_add(1)?)?;
            return position.checked_add(2);
        }
        if length & 0xC0 != 0 {
            return None;
        }
        labels = labels.checked_add(1)?;
        if labels > 127 {
            return None;
        }
        position = position.checked_add(1 + usize::from(length))?;
        if position > bytes.len() {
            return None;
        }
    }
}

/// Пропускает вопрос и возвращает смещение после него.
fn skip_question(bytes: &[u8], offset: usize) -> Option<usize> {
    let after_name = skip_name(bytes, offset)?;
    let end = after_name.checked_add(4)?;
    if end > bytes.len() {
        return None;
    }
    Some(end)
}

/// Пропускает RR и возвращает `(смещение после RR, тип RR)`.
fn skip_rr(bytes: &[u8], offset: usize) -> Option<(usize, u16)> {
    let after_name = skip_name(bytes, offset)?;
    let rr_type = read_u16(bytes, after_name)?;
    let rdlength = usize::from(read_u16(bytes, after_name.checked_add(8)?)?);
    let end = after_name.checked_add(10)?.checked_add(rdlength)?;
    if end > bytes.len() {
        return None;
    }
    Some((end, rr_type))
}

/// Вырезает последний TSIG RR из additional.
///
/// Возвращает `None`, если TSIG нет. Если TSIG есть не последним или встречается
/// более одного раза, возвращает [`TsigError::Malformed`].
pub(crate) fn strip_tsig(raw: &[u8]) -> Result<Option<Stripped>, TsigError> {
    let wire_id = read_u16(raw, 0).ok_or(TsigError::Malformed {
        reason: "message shorter than DNS header",
    })?;
    let question_count = usize::from(read_u16(raw, 4).ok_or(TsigError::Malformed {
        reason: "no QDCOUNT",
    })?);
    let answer_count = usize::from(read_u16(raw, 6).ok_or(TsigError::Malformed {
        reason: "no ANCOUNT",
    })?);
    let authority_count = usize::from(read_u16(raw, 8).ok_or(TsigError::Malformed {
        reason: "no NSCOUNT",
    })?);
    let additional_count = usize::from(read_u16(raw, 10).ok_or(TsigError::Malformed {
        reason: "no ARCOUNT",
    })?);

    if additional_count == 0 {
        return Ok(None);
    }

    let mut position = 12_usize;
    for _ in 0..question_count {
        position = skip_question(raw, position).ok_or(TsigError::Malformed {
            reason: "truncated question section",
        })?;
    }
    for _ in 0..answer_count.saturating_add(authority_count) {
        let (next, _) = skip_rr(raw, position).ok_or(TsigError::Malformed {
            reason: "truncated answer/authority section",
        })?;
        position = next;
    }

    let mut last_start = position;
    let mut last_type = 0_u16;
    for index in 0..additional_count {
        let (next, rr_type) = skip_rr(raw, position).ok_or(TsigError::Malformed {
            reason: "truncated additional section",
        })?;
        if index + 1 == additional_count {
            last_start = position;
            last_type = rr_type;
        } else if rr_type == Rtype::TSIG.as_u16() {
            return Err(TsigError::Malformed {
                reason: "TSIG record is not last in additional section",
            });
        }
        position = next;
    }

    if position != raw.len() {
        return Err(TsigError::Malformed {
            reason: "trailing bytes after DNS message",
        });
    }
    if last_type != Rtype::TSIG.as_u16() {
        return Ok(None);
    }

    let bytes = raw.get(..last_start).ok_or(TsigError::Malformed {
        reason: "invalid TSIG offset",
    })?;
    let mut bytes = bytes.to_vec();
    let new_count = additional_count.saturating_sub(1);
    let new_count = u16::try_from(new_count).map_err(|_| TsigError::Malformed {
        reason: "ARCOUNT overflow while removing TSIG",
    })?;
    let slot = bytes.get_mut(10..12).ok_or(TsigError::Malformed {
        reason: "missing ARCOUNT",
    })?;
    slot.copy_from_slice(&new_count.to_be_bytes());
    Ok(Some(Stripped { bytes, wire_id }))
}
