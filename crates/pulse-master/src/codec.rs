//! Кодек base16 (hex), base64 и base32hex без внешних зависимостей.
//!
//! Все функции работают с ASCII-представлением и не паникуют: любой вход
//! возвращает `Err(String)` с человекочитаемой причиной.

/// Декодирует hex-строку (регистр не важен).
///
/// # Errors
///
/// Нечётная длина или недопустимый символ.
pub(crate) fn decode_hex(input: &str) -> Result<Vec<u8>, String> {
    let bytes = input.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(format!("hex string has odd length {}", bytes.len()));
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.as_chunks::<2>().0 {
        let high = hex_value(pair[0])?;
        let low = hex_value(pair[1])?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(format!("invalid hex character {:?}", char::from(byte))),
    }
}

/// Кодирует байты в hex в верхнем регистре.
pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        let high = usize::from(byte >> 4);
        let low = usize::from(byte & 0x0F);
        out.push(char::from(DIGITS.get(high).copied().unwrap_or(b'0')));
        out.push(char::from(DIGITS.get(low).copied().unwrap_or(b'0')));
    }
    out
}

const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Декодирует стандартный base64 (padding опционален, пробелы игнорируются).
///
/// # Errors
///
/// Недопустимый символ, некорректная длина или padding не в конце.
pub(crate) fn decode_base64(input: &str) -> Result<Vec<u8>, String> {
    let mut quad = [0_u8; 4];
    let mut filled = 0_usize;
    let mut out = Vec::new();
    let mut padding = 0_usize;
    for byte in input.bytes() {
        if byte.is_ascii_whitespace() {
            continue;
        }
        if byte == b'=' {
            padding += 1;
            continue;
        }
        if padding > 0 {
            return Err("base64 padding in the middle of the string".to_owned());
        }
        let value = base64_value(byte)?;
        let Some(slot) = quad.get_mut(filled) else {
            return Err("base64 quartet overflow".to_owned());
        };
        *slot = value;
        filled += 1;
        if filled == 4 {
            out.push((quad[0] << 2) | (quad[1] >> 4));
            out.push((quad[1] << 4) | (quad[2] >> 2));
            out.push((quad[2] << 6) | quad[3]);
            filled = 0;
        }
    }
    match (filled, padding) {
        (0, 0) => {}
        (2, 0 | 2) => {
            let first = quad.first().copied().ok_or("base64 quartet")?;
            let second = quad.get(1).copied().ok_or("base64 quartet")?;
            out.push((first << 2) | (second >> 4));
        }
        (3, 0 | 1) => {
            let first = quad.first().copied().ok_or("base64 quartet")?;
            let second = quad.get(1).copied().ok_or("base64 quartet")?;
            let third = quad.get(2).copied().ok_or("base64 quartet")?;
            out.push((first << 2) | (second >> 4));
            out.push((second << 4) | (third >> 2));
        }
        _ => return Err("invalid base64 length/padding".to_owned()),
    }
    Ok(out)
}

fn base64_value(byte: u8) -> Result<u8, String> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(format!("invalid base64 character {:?}", char::from(byte))),
    }
}

/// Кодирует байты в стандартный base64 с padding.
pub(crate) fn encode_base64(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk.first().copied().unwrap_or(0);
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        out.push(char::from(
            BASE64_ALPHABET
                .get(usize::from(first >> 2))
                .copied()
                .unwrap_or(b'A'),
        ));
        out.push(char::from(
            BASE64_ALPHABET
                .get(usize::from((first & 0x03) << 4 | second >> 4))
                .copied()
                .unwrap_or(b'A'),
        ));
        if chunk.len() > 1 {
            out.push(char::from(
                BASE64_ALPHABET
                    .get(usize::from((second & 0x0F) << 2 | third >> 6))
                    .copied()
                    .unwrap_or(b'A'),
            ));
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(char::from(
                BASE64_ALPHABET
                    .get(usize::from(third & 0x3F))
                    .copied()
                    .unwrap_or(b'A'),
            ));
        } else {
            out.push('=');
        }
    }
    out
}

/// Декодирует base32hex без padding (RFC 4648 §7), регистр не важен.
///
/// # Errors
///
/// Недопустимый символ или некорректная длина.
pub(crate) fn decode_base32hex(input: &str) -> Result<Vec<u8>, String> {
    let mut buffer = 0_u32;
    let mut bits = 0_u32;
    let mut out = Vec::new();
    let mut symbols = 0_usize;
    let mut padding = false;
    for byte in input.bytes() {
        if byte.is_ascii_whitespace() {
            continue;
        }
        if byte == b'=' {
            padding = true;
            continue;
        }
        if padding {
            return Err("base32hex data after padding".to_owned());
        }
        let value = match byte {
            b'0'..=b'9' => byte - b'0',
            b'A'..=b'V' => byte - b'A' + 10,
            b'a'..=b'v' => byte - b'a' + 10,
            _ => {
                return Err(format!(
                    "invalid base32hex character {:?}",
                    char::from(byte)
                ));
            }
        };
        buffer = (buffer << 5) | u32::from(value);
        bits += 5;
        symbols += 1;
        if bits >= 8 {
            bits -= 8;
            out.push(
                u8::try_from((buffer >> bits) & 0xFF)
                    .map_err(|_| "base32hex overflow".to_owned())?,
            );
        }
    }
    if symbols % 8 == 1 || symbols % 8 == 3 || symbols % 8 == 6 {
        return Err(format!("invalid base32hex length {symbols}"));
    }
    if bits > 0 && (buffer & ((1_u32 << bits) - 1)) != 0 {
        return Err("non-zero base32hex padding bits".to_owned());
    }
    Ok(out)
}

/// Кодирует байты в base32hex без padding, верхний регистр.
pub(crate) fn encode_base32hex(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";
    let mut out = String::new();
    let mut buffer = 0_u32;
    let mut bits = 0_u32;
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = usize::try_from((buffer >> bits) & 0x1F).unwrap_or(0);
            out.push(char::from(ALPHABET.get(index).copied().unwrap_or(b'0')));
        }
    }
    if bits > 0 {
        let index = usize::try_from((buffer << (5 - bits)) & 0x1F).unwrap_or(0);
        out.push(char::from(ALPHABET.get(index).copied().unwrap_or(b'0')));
    }
    out
}

/// Разбирает время RRSIG: `YYYYMMDDHHMMSS` или `u32` секунд UNIX.
///
/// # Errors
///
/// Некорректная дата/время или число.
pub(crate) fn parse_rrsig_time(input: &str) -> Result<u32, String> {
    let bytes = input.as_bytes();
    if bytes.len() == 14 && bytes.iter().all(u8::is_ascii_digit) {
        let year = parse_component(bytes, 0, 4)?;
        let month = parse_component(bytes, 4, 2)?;
        let day = parse_component(bytes, 6, 2)?;
        let hour = parse_component(bytes, 8, 2)?;
        let minute = parse_component(bytes, 10, 2)?;
        let second = parse_component(bytes, 12, 2)?;
        if !(1..=12).contains(&month) {
            return Err("month is outside 1..=12".to_owned());
        }
        let max_day = days_in_month(year, month);
        if !(1..=max_day).contains(&day) {
            return Err(format!("day is outside 1..={max_day}"));
        }
        if hour > 23 || minute > 59 || second > 59 {
            return Err("time is outside 00:00:00..=23:59:59".to_owned());
        }
        let days = days_from_civil(i64::from(year), i64::from(month), i64::from(day));
        let seconds = days
            .checked_mul(86_400)
            .and_then(|value| value.checked_add(i64::from(hour) * 3_600))
            .and_then(|value| value.checked_add(i64::from(minute) * 60))
            .and_then(|value| value.checked_add(i64::from(second)))
            .ok_or_else(|| "timestamp overflow".to_owned())?;
        let wrapped = seconds.rem_euclid(1_i64 << 32);
        return u32::try_from(wrapped).map_err(|_| "timestamp overflow".to_owned());
    }
    input
        .parse::<u32>()
        .map_err(|_| "expected 14-digit date or 32-bit seconds".to_owned())
}

fn parse_component(bytes: &[u8], start: usize, length: usize) -> Result<u32, String> {
    let end = start.saturating_add(length);
    let slice = bytes
        .get(start..end)
        .ok_or_else(|| "truncated timestamp".to_owned())?;
    let text = std::str::from_utf8(slice).map_err(|_| "non-ASCII timestamp".to_owned())?;
    text.parse::<u32>()
        .map_err(|_| "non-numeric timestamp component".to_owned())
}

/// Форматирует секунды UNIX как `YYYYMMDDHHMMSS` (для диапазона 1970…2106).
pub(crate) fn format_rrsig_time(seconds: u32) -> String {
    let days = i64::from(seconds) / 86_400;
    let remainder = i64::from(seconds) % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = remainder / 3_600;
    let minute = (remainder % 3_600) / 60;
    let second = remainder % 60;
    format!("{year:04}{month:02}{day:02}{hour:02}{minute:02}{second:02}")
}

fn is_leap_year(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let shifted_month = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = if month <= 2 { year + 1 } else { year };
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trip() {
        for bytes in [
            Vec::new(),
            vec![0x00],
            vec![0xFF, 0x01],
            b"hello world".to_vec(),
            (0..=255_u8).collect(),
        ] {
            let encoded = encode_base64(&bytes);
            assert_eq!(decode_base64(&encoded).expect("decode"), bytes);
        }
        assert_eq!(decode_base64("aGVsbG8=").expect("hello"), b"hello");
        assert_eq!(decode_base64("aGVsbG8").expect("unpadded"), b"hello");
        assert!(decode_base64("a").is_err());
        assert!(decode_base64("aGVsbG8==").is_err());
        assert!(decode_base64("=").is_err());
        assert!(decode_base64("abcd=").is_err());
    }

    #[test]
    fn base32hex_round_trip_and_rfc_vector() {
        assert_eq!(
            decode_base32hex("CPNMUOJ1E8").expect("rfc vector"),
            b"foobar"
        );
        for bytes in [vec![0_u8], vec![1, 2, 3, 4, 5], (0..=255_u8).collect()] {
            let encoded = encode_base32hex(&bytes);
            assert_eq!(decode_base32hex(&encoded).expect("decode"), bytes);
        }
        assert!(decode_base32hex("A").is_err());
        assert!(decode_base32hex("81").is_err());
        assert!(decode_base32hex("CO=DE").is_err());
    }

    #[test]
    fn hex_round_trip() {
        assert_eq!(decode_hex("00ffA0").expect("hex"), vec![0, 255, 160]);
        assert_eq!(encode_hex(&[0, 255, 160]), "00FFA0");
        assert!(decode_hex("abc").is_err());
        assert!(decode_hex("zz").is_err());
    }

    #[test]
    fn rrsig_timestamps() {
        assert_eq!(
            parse_rrsig_time("20240101000000").expect("date"),
            1_704_067_200
        );
        assert_eq!(
            parse_rrsig_time("20240229123456").expect("leap"),
            1_709_210_096
        );
        assert!(parse_rrsig_time("20230229000000").is_err());
        assert!(parse_rrsig_time("20241301000000").is_err());
        assert_eq!(parse_rrsig_time("1704067200").expect("unix"), 1_704_067_200);
        assert_eq!(format_rrsig_time(1_704_067_200), "20240101000000");
        assert_eq!(format_rrsig_time(0), "19700101000000");
    }
}
