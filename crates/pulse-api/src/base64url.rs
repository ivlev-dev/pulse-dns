//! URL-safe base64 без padding (курсоры пагинации).

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Кодирует байты в base64url без padding.
pub(crate) fn encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let first = chunk.first().copied().unwrap_or(0);
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        let value = (u32::from(first) << 16) | (u32::from(second) << 8) | u32::from(third);
        let indexes = [
            (value >> 18) & 0x3F,
            (value >> 12) & 0x3F,
            (value >> 6) & 0x3F,
            value & 0x3F,
        ];
        let take = match chunk.len() {
            1 => 2,
            2 => 3,
            _ => 4,
        };
        for index in indexes.iter().take(take) {
            let symbol = ALPHABET.get(*index as usize).copied().unwrap_or(b'A');
            out.push(char::from(symbol));
        }
    }
    out
}

/// Декодирует base64url без padding.
pub(crate) fn decode(input: &str) -> Option<Vec<u8>> {
    if input.len() > 4096 {
        return None;
    }
    let mut output = Vec::with_capacity(input.len() * 3 / 4);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for symbol in input.bytes() {
        let value = decode_symbol(symbol)?;
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push(((buffer >> bits) & 0xFF) as u8);
        }
    }
    // Остаточные биты допустимы только нулевые.
    if bits > 0 && (buffer & ((1 << bits) - 1)) != 0 {
        return None;
    }
    Some(output)
}

fn decode_symbol(symbol: u8) -> Option<u8> {
    match symbol {
        b'A'..=b'Z' => Some(symbol - b'A'),
        b'a'..=b'z' => Some(symbol - b'a' + 26),
        b'0'..=b'9' => Some(symbol - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        for value in [
            Vec::new(),
            vec![0],
            vec![1, 2],
            vec![1, 2, 3],
            b"example.com.".to_vec(),
        ] {
            let encoded = encode(&value);
            assert_eq!(decode(&encoded), Some(value));
        }
    }

    #[test]
    fn invalid_rejected() {
        assert_eq!(decode("%%%"), None);
        assert_eq!(decode("a"), None);
        assert_eq!(decode("abc="), None);
    }
}
