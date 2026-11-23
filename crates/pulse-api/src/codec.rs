//! Кодирование и разбор мелких форматов: hex, percent-encoding, типы DNS.

use pulse_dns::Rtype;

/// Нижний hex.
pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let high = DIGITS.get(usize::from(*byte >> 4)).copied().unwrap_or(b'0');
        let low = DIGITS
            .get(usize::from(*byte & 0x0F))
            .copied()
            .unwrap_or(b'0');
        out.push(char::from(high));
        out.push(char::from(low));
    }
    out
}

/// Разбирает hex-строку (регистр любой).
pub(crate) fn parse_hex(input: &str) -> Option<Vec<u8>> {
    if !input.len().is_multiple_of(2) {
        return None;
    }
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(input.len() / 2);
    let mut index = 0;
    while index + 1 < bytes.len() {
        let high = hex_value(bytes.get(index).copied()?)?;
        let low = hex_value(bytes.get(index + 1).copied()?)?;
        out.push((high << 4) | low);
        index += 2;
    }
    Some(out)
}

fn hex_value(symbol: u8) -> Option<u8> {
    match symbol {
        b'0'..=b'9' => Some(symbol - b'0'),
        b'a'..=b'f' => Some(symbol - b'a' + 10),
        b'A'..=b'F' => Some(symbol - b'A' + 10),
        _ => None,
    }
}

/// Percent-decoding для path (`plus_as_space = false`) и query (`true`).
pub(crate) fn percent_decode(input: &str, plus_as_space: bool) -> Option<String> {
    if input.len() > 8192 {
        return None;
    }
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        match byte {
            b'%' => {
                let high = hex_value(bytes.get(index + 1).copied()?)?;
                let low = hex_value(bytes.get(index + 2).copied()?)?;
                out.push((high << 4) | low);
                index += 3;
            }
            b'+' if plus_as_space => {
                out.push(b' ');
                index += 1;
            }
            _ => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// Разбирает мнемонику типа (`A`, `AAAA`, …, `TYPE123`).
pub(crate) fn parse_rtype(input: &str) -> Option<Rtype> {
    let upper = input.trim().to_ascii_uppercase();
    let known = match upper.as_str() {
        "A" => Rtype::A,
        "NS" => Rtype::NS,
        "CNAME" => Rtype::CNAME,
        "SOA" => Rtype::SOA,
        "PTR" => Rtype::PTR,
        "MX" => Rtype::MX,
        "TXT" => Rtype::TXT,
        "AAAA" => Rtype::AAAA,
        "SRV" => Rtype::SRV,
        "DNAME" => Rtype::DNAME,
        "OPT" => Rtype::OPT,
        "DS" => Rtype::DS,
        "RRSIG" => Rtype::RRSIG,
        "NSEC" => Rtype::NSEC,
        "DNSKEY" => Rtype::DNSKEY,
        "NSEC3" => Rtype::NSEC3,
        "NSEC3PARAM" => Rtype::NSEC3PARAM,
        "TLSA" => Rtype::TLSA,
        "SVCB" => Rtype::SVCB,
        "HTTPS" => Rtype::HTTPS,
        "CAA" => Rtype::CAA,
        other => {
            let number = other.strip_prefix("TYPE")?;
            if number.is_empty() || number.len() > 5 || !number.bytes().all(|b| b.is_ascii_digit())
            {
                return None;
            }
            let value: u16 = number.parse().ok()?;
            Rtype::from_u16(value)
        }
    };
    Some(known)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip() {
        assert_eq!(hex_lower(&[0, 15, 255]), "000fff");
        assert_eq!(parse_hex("000fFf"), Some(vec![0, 15, 255]));
        assert_eq!(parse_hex("abc"), None);
        assert_eq!(parse_hex("zz"), None);
    }

    #[test]
    fn percent_decode_path_and_query() {
        assert_eq!(percent_decode("a%2Eb", false), Some("a.b".to_owned()));
        assert_eq!(percent_decode("a+b", true), Some("a b".to_owned()));
        assert_eq!(percent_decode("a+b", false), Some("a+b".to_owned()));
        assert_eq!(percent_decode("%ZZ", false), None);
        assert_eq!(percent_decode("%2", false), None);
    }

    #[test]
    fn rtype_parsing() {
        assert_eq!(parse_rtype("a"), Some(Rtype::A));
        assert_eq!(parse_rtype("TYPE65280"), Some(Rtype::from_u16(65280)));
        assert_eq!(parse_rtype("BOGUS"), None);
        assert_eq!(parse_rtype("TYPE"), None);
    }
}
