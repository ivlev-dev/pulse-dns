//! Разбор доменных имён в презентационном формате master-файла.
//!
//! В отличие от [`pulse_dns::Name::parse`], здесь поддерживается `\X` для
//! любого символа и относительные имена: имя без завершающей неэкранированной
//! точки дополняется текущим `$ORIGIN`.

use pulse_dns::Name;

use crate::error::{ErrorKind, Location, ParseError};

/// Декодирует байты токена с учётом escape-последовательностей.
///
/// `\DDD` даёт ровно один октет, `\X` — символ `X` (в UTF-8).
///
/// # Errors
///
/// [`ErrorKind::Rdata`] с сообщением о неполной escape-последовательности.
pub(crate) fn decode_escapes(
    raw: &str,
    rr_type: pulse_dns::Rtype,
    location: &Location,
) -> Result<Vec<u8>, ParseError> {
    decode_string_raw(raw)
        .map_err(|message| ParseError::new(location.clone(), ErrorKind::Rdata { rr_type, message }))
}

/// Декодирует escape-последовательности без привязки к типу RDATA.
///
/// # Errors
///
/// Строка с сообщением о неполной/некорректной последовательности.
pub(crate) fn decode_string_raw(raw: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            let mut buffer = [0_u8; 4];
            out.extend_from_slice(ch.encode_utf8(&mut buffer).as_bytes());
            continue;
        }
        let Some(next) = chars.next() else {
            return Err("trailing backslash".to_owned());
        };
        if next.is_ascii_digit() {
            let mut value = u16::from(next as u8 - b'0');
            for _ in 0..2 {
                let Some(digit) = chars.next() else {
                    return Err("`\\DDD` escape must contain exactly three digits".to_owned());
                };
                if !digit.is_ascii_digit() {
                    return Err("`\\DDD` escape must contain exactly three digits".to_owned());
                }
                value = value * 10 + u16::from(digit as u8 - b'0');
            }
            let Ok(byte) = u8::try_from(value) else {
                return Err(format!("`\\{value:03}` is not a single octet"));
            };
            out.push(byte);
        } else {
            let mut buffer = [0_u8; 4];
            out.extend_from_slice(next.encode_utf8(&mut buffer).as_bytes());
        }
    }
    Ok(out)
}

/// Разбирает имя и делает его абсолютным.
///
/// `@` означает текущий origin. Имя без завершающей неэкранированной точки
/// дополняется `origin`.
///
/// # Errors
///
/// [`ErrorKind::Name`] при пустой метке, слишком длинном имени или метке,
/// некорректной escape-последовательности.
pub(crate) fn parse_name(
    raw: &str,
    origin: &Name,
    location: &Location,
) -> Result<Name, ParseError> {
    if raw.is_empty() {
        return Err(name_error(raw, location, pulse_dns::NameError::EmptyName));
    }
    if raw == "@" {
        return Ok(origin.clone());
    }
    if raw == "." {
        return Ok(Name::root());
    }

    let mut labels: Vec<Vec<u8>> = Vec::new();
    let mut current: Vec<u8> = Vec::new();
    let mut chars = raw.chars();
    let mut absolute = false;

    while let Some(ch) = chars.next() {
        match ch {
            '.' => {
                if current.is_empty() {
                    return Err(name_error(raw, location, pulse_dns::NameError::EmptyLabel));
                }
                labels.push(std::mem::take(&mut current));
                absolute = chars.clone().next().is_none();
            }
            '\\' => {
                let Some(next) = chars.next() else {
                    return Err(name_error(
                        raw,
                        location,
                        pulse_dns::NameError::BadEscape { offset: 0 },
                    ));
                };
                if next.is_ascii_digit() {
                    let mut value = u16::from(next as u8 - b'0');
                    for _ in 0..2 {
                        let Some(digit) = chars.next() else {
                            return Err(name_error(
                                raw,
                                location,
                                pulse_dns::NameError::BadEscape { offset: 0 },
                            ));
                        };
                        if !digit.is_ascii_digit() {
                            return Err(name_error(
                                raw,
                                location,
                                pulse_dns::NameError::BadEscape { offset: 0 },
                            ));
                        }
                        value = value * 10 + u16::from(digit as u8 - b'0');
                    }
                    let Ok(byte) = u8::try_from(value) else {
                        return Err(name_error(
                            raw,
                            location,
                            pulse_dns::NameError::BadEscape { offset: 0 },
                        ));
                    };
                    current.push(byte);
                } else {
                    let mut buffer = [0_u8; 4];
                    current.extend_from_slice(next.encode_utf8(&mut buffer).as_bytes());
                }
                absolute = false;
            }
            _ => {
                let mut buffer = [0_u8; 4];
                current.extend_from_slice(ch.encode_utf8(&mut buffer).as_bytes());
                absolute = false;
            }
        }
    }

    if !current.is_empty() {
        labels.push(current);
    } else if !absolute {
        return Err(name_error(raw, location, pulse_dns::NameError::EmptyLabel));
    }

    let mut wire = Vec::new();
    for label in labels {
        if label.len() > pulse_dns::MAX_LABEL_LEN {
            return Err(name_error(
                raw,
                location,
                pulse_dns::NameError::LabelTooLong { len: label.len() },
            ));
        }
        let Ok(length) = u8::try_from(label.len()) else {
            return Err(name_error(
                raw,
                location,
                pulse_dns::NameError::LabelTooLong { len: label.len() },
            ));
        };
        wire.push(length);
        wire.extend_from_slice(&label);
    }
    if absolute {
        wire.push(0);
    } else {
        wire.extend_from_slice(origin.as_wire());
    }

    Name::from_wire(&wire).map_err(|source| name_error(raw, location, source))
}

fn name_error(raw: &str, location: &Location, source: pulse_dns::NameError) -> ParseError {
    ParseError::new(
        location.clone(),
        ErrorKind::Name {
            input: raw.to_owned(),
            source,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origin() -> Name {
        Name::parse("example.com.").expect("origin")
    }

    #[test]
    fn relative_and_absolute_names() {
        let location = Location::new("<test>", 1, 1);
        assert_eq!(
            parse_name("www", &origin(), &location).expect("relative"),
            Name::parse("www.example.com.").expect("expected")
        );
        assert_eq!(
            parse_name("www.example.com.", &origin(), &location).expect("absolute"),
            Name::parse("www.example.com.").expect("expected")
        );
        assert_eq!(
            parse_name("@", &origin(), &location).expect("apex"),
            origin()
        );
        assert_eq!(
            parse_name(".", &origin(), &location).expect("root"),
            Name::root()
        );
    }

    #[test]
    fn escapes_are_label_local() {
        let location = Location::new("<test>", 1, 1);
        let name = parse_name("a\\.b", &origin(), &location).expect("escaped dot");
        let labels: Vec<&[u8]> = name.labels().collect();
        assert_eq!(labels.first().copied(), Some(&b"a.b"[..]));
        let escaped = parse_name("a\\032b", &origin(), &location).expect("ddd");
        let labels: Vec<&[u8]> = escaped.labels().collect();
        assert_eq!(labels.first().copied(), Some(&b"a b"[..]));
    }

    #[test]
    fn rejects_empty_label() {
        let location = Location::new("<test>", 1, 1);
        assert!(matches!(
            parse_name("a..b", &origin(), &location),
            Err(ParseError {
                kind: ErrorKind::Name { .. },
                ..
            })
        ));
    }
}
