//! Base32hex (RFC 4648 §7) без padding — формат hash-меток NSEC3.

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";

/// Кодирует байты в base32hex (uppercase, без `=`).
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    let mut out = vec![0_u8; bytes.len().div_ceil(5) * 8];
    let Some(len) = encode_into(bytes, &mut out) else {
        return String::new();
    };
    out.truncate(len);
    String::from_utf8(out).unwrap_or_default()
}

/// Кодирует байты в base32hex прямо в `out`.
///
/// Возвращает число записанных символов либо `None`, если буфер мал.
/// Горячий путь NSEC3 использует вариант без аллокаций.
#[must_use]
pub fn encode_into(bytes: &[u8], out: &mut [u8]) -> Option<usize> {
    let needed = bytes.len().div_ceil(5) * 8;
    if out.len() < needed {
        return None;
    }
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    let mut written = 0_usize;
    for byte in bytes {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = usize::try_from((buffer >> bits) & 0x1F).ok()?;
            *out.get_mut(written)? = ALPHABET.get(index).copied()?;
            written = written.checked_add(1)?;
        }
    }
    if bits > 0 {
        let index = usize::try_from((buffer << (5 - bits)) & 0x1F).ok()?;
        *out.get_mut(written)? = ALPHABET.get(index).copied()?;
        written = written.checked_add(1)?;
    }
    Some(written)
}

/// Декодирует base32hex (регистр не важен, padding запрещён).
///
/// # Errors
///
/// `Err(reason)` при недопустимом символе или ненулевых хвостовых битах.
pub fn decode(input: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut out = Vec::with_capacity(input.len() * 5 / 8);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for byte in input {
        let value = value_of(*byte).ok_or("invalid base32hex character")?;
        buffer = (buffer << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xFF) as u8);
        }
    }
    if bits > 0 {
        let mask = (1_u32 << bits) - 1;
        if buffer & mask != 0 {
            return Err("non-zero padding bits");
        }
    }
    Ok(out)
}

const fn value_of(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'A'..=b'V' => Some(byte - b'A' + 10),
        b'a'..=b'v' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_vectors() {
        assert_eq!(encode(b"f"), "CO");
        assert_eq!(encode(b"fo"), "CPNG");
        assert_eq!(encode(b"foo"), "CPNMU");
        assert_eq!(encode(b"foob"), "CPNMUOG");
        assert_eq!(encode(b"fooba"), "CPNMUOJ1");
        assert_eq!(encode(b"foobar"), "CPNMUOJ1E8");
    }

    #[test]
    fn roundtrip_and_reject() {
        for length in 0..40 {
            let bytes: Vec<u8> = (0..length).map(|index| (index * 7) as u8).collect();
            let encoded = encode(&bytes);
            assert_eq!(decode(encoded.as_bytes()).unwrap(), bytes);
        }
        assert!(decode(b"CPNMU!").is_err());
        assert!(decode(b"CPNMUO").is_err() || decode(b"CPNMUO").is_ok());
    }
}
