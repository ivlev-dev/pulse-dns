//! Разбор TTL и таймеров: `3600`, `1h`, `1h30m`, `2w`.
//!
//! TTL записи ограничен `2^31−1` (INV-3) и при импорте clamp'ится. Таймеры SOA
//! и `RRSIG.original_ttl` — полные `u32` и не clamp'ятся (INV-21/INV-24).

/// Разбирает продолжительность в секундах как полный `u32`.
///
/// Поддерживаются суффиксы `s`, `m`, `h`, `d`, `w` (регистр не важен) и их
/// конкатенация. Голое число трактуется как секунды.
///
/// # Errors
///
/// Пустая строка, неизвестный суффикс, переполнение `u32`.
pub(crate) fn parse_duration(input: &str) -> Result<u32, String> {
    if input.is_empty() {
        return Err("empty value".to_owned());
    }
    let bytes = input.as_bytes();
    let mut total: u64 = 0;
    let mut index = 0_usize;
    let mut parts = 0_usize;
    while index < bytes.len() {
        let start = index;
        while let Some(&byte) = bytes.get(index) {
            if byte.is_ascii_digit() {
                index = index.saturating_add(1);
            } else {
                break;
            }
        }
        if index == start {
            return Err(format!("expected a number at offset {start}"));
        }
        let number_text = std::str::from_utf8(bytes.get(start..index).unwrap_or_default())
            .map_err(|_| "non-ASCII digits".to_owned())?;
        let number = number_text
            .parse::<u64>()
            .map_err(|_| format!("{number_text:?} does not fit in 64 bits"))?;
        let multiplier = match bytes.get(index).copied() {
            None => 1_u64,
            Some(b's' | b'S') => {
                index = index.saturating_add(1);
                1
            }
            Some(b'm' | b'M') => {
                index = index.saturating_add(1);
                60
            }
            Some(b'h' | b'H') => {
                index = index.saturating_add(1);
                3_600
            }
            Some(b'd' | b'D') => {
                index = index.saturating_add(1);
                86_400
            }
            Some(b'w' | b'W') => {
                index = index.saturating_add(1);
                604_800
            }
            Some(other) => {
                return Err(format!("unknown unit {:?}", char::from(other)));
            }
        };
        total = total
            .checked_add(
                number
                    .checked_mul(multiplier)
                    .ok_or_else(|| "duration overflow".to_owned())?,
            )
            .ok_or_else(|| "duration overflow".to_owned())?;
        parts = parts.saturating_add(1);
        if total > u64::from(u32::MAX) {
            return Err(format!("value exceeds {}", u32::MAX));
        }
    }
    if parts == 0 {
        return Err("empty value".to_owned());
    }
    u32::try_from(total).map_err(|_| format!("value exceeds {}", u32::MAX))
}

/// Похож ли токен на TTL (начинается с цифры).
pub(crate) fn looks_like_ttl(token: &str) -> bool {
    token.as_bytes().first().is_some_and(u8::is_ascii_digit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_and_units() {
        assert_eq!(parse_duration("3600").expect("plain"), 3600);
        assert_eq!(parse_duration("1h").expect("hour"), 3600);
        assert_eq!(parse_duration("1d").expect("day"), 86_400);
        assert_eq!(parse_duration("1w").expect("week"), 604_800);
        assert_eq!(parse_duration("1h30m").expect("combined"), 5400);
        assert_eq!(parse_duration("2H30M15S").expect("upper"), 9015);
    }

    #[test]
    fn rejects_bad_values() {
        assert!(parse_duration("").is_err());
        assert!(parse_duration("h").is_err());
        assert!(parse_duration("12x").is_err());
        assert!(parse_duration("1h 30m").is_err());
        assert!(parse_duration("4294967296").is_err());
    }
}
