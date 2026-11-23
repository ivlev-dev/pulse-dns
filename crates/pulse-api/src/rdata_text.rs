//! Presentation-формат RDATA (RFC 1035) и RFC 3597.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use pulse_dns::{CaaTag, Name, Rdata, Rtype, Serial, SoaData, TxtData};
use thiserror::Error;

use crate::codec::{hex_lower, parse_hex};

/// Ошибка разбора presentation-строки RDATA.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RdataParseError {
    /// Пустая строка.
    #[error("rdata must not be empty")]
    Empty,
    /// Presentation-формат для типа не поддерживается; используйте RFC 3597.
    #[error("presentation format for type {rr_type} is not supported; use RFC 3597 `\\# len hex`")]
    Unsupported {
        /// Тип.
        rr_type: Rtype,
    },
    /// Некорректное значение.
    #[error("invalid {rr_type} rdata: {reason}")]
    Invalid {
        /// Тип.
        rr_type: Rtype,
        /// Причина.
        reason: String,
    },
}

impl RdataParseError {
    /// Код для problem+json `errors[]`.
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Empty => "empty-rdata",
            Self::Unsupported { .. } => "unsupported-rdata-format",
            Self::Invalid { .. } => "invalid-rdata",
        }
    }
}

/// Разбирает RDATA.
pub(crate) fn parse_rdata(rr_type: Rtype, text: &str) -> Result<Rdata, RdataParseError> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(RdataParseError::Empty);
    }
    if trimmed.starts_with("\\#") {
        return parse_generic(rr_type, trimmed);
    }
    match rr_type {
        Rtype::A => {
            let address = Ipv4Addr::from_str(trimmed).map_err(|error| invalid(rr_type, error))?;
            Ok(Rdata::A(address))
        }
        Rtype::AAAA => {
            let address = Ipv6Addr::from_str(trimmed).map_err(|error| invalid(rr_type, error))?;
            Ok(Rdata::Aaaa(address))
        }
        Rtype::NS => Ok(Rdata::Ns(parse_name(rr_type, trimmed)?)),
        Rtype::CNAME => Ok(Rdata::Cname(parse_name(rr_type, trimmed)?)),
        Rtype::PTR => Ok(Rdata::Ptr(parse_name(rr_type, trimmed)?)),
        Rtype::DNAME => Ok(Rdata::Dname(parse_name(rr_type, trimmed)?)),
        Rtype::MX => {
            let tokens: Vec<&str> = trimmed.split_whitespace().collect();
            if tokens.len() != 2 {
                return Err(invalid_reason(rr_type, "MX requires `preference exchange`"));
            }
            let preference = parse_u16(rr_type, tokens.first().copied().unwrap_or(""))?;
            let exchange = parse_name(rr_type, tokens.get(1).copied().unwrap_or(""))?;
            Ok(Rdata::Mx {
                preference,
                exchange,
            })
        }
        Rtype::SRV => {
            let tokens: Vec<&str> = trimmed.split_whitespace().collect();
            if tokens.len() != 4 {
                return Err(invalid_reason(
                    rr_type,
                    "SRV requires `priority weight port target`",
                ));
            }
            let priority = parse_u16(rr_type, tokens.first().copied().unwrap_or(""))?;
            let weight = parse_u16(rr_type, tokens.get(1).copied().unwrap_or(""))?;
            let port = parse_u16(rr_type, tokens.get(2).copied().unwrap_or(""))?;
            let target = parse_name(rr_type, tokens.get(3).copied().unwrap_or(""))?;
            Ok(Rdata::Srv {
                priority,
                weight,
                port,
                target,
            })
        }
        Rtype::TXT => {
            let segments =
                parse_txt_segments(trimmed).map_err(|reason| invalid_reason(rr_type, &reason))?;
            let data = TxtData::new(segments).map_err(|error| invalid(rr_type, error))?;
            Ok(Rdata::Txt(data))
        }
        Rtype::CAA => parse_caa(trimmed),
        Rtype::SOA => parse_soa(trimmed),
        _ => Err(RdataParseError::Unsupported { rr_type }),
    }
}

/// Форматирует RDATA в presentation-формат.
pub(crate) fn format_rdata(rdata: &Rdata) -> String {
    match rdata {
        Rdata::A(address) => address.to_string(),
        Rdata::Aaaa(address) => address.to_string(),
        Rdata::Ns(name) | Rdata::Cname(name) | Rdata::Ptr(name) | Rdata::Dname(name) => {
            name.to_string()
        }
        Rdata::Soa(soa) => format!(
            "{} {} {} {} {} {} {}",
            soa.mname,
            soa.rname,
            soa.serial.as_u32(),
            soa.refresh,
            soa.retry,
            soa.expire,
            soa.minimum
        ),
        Rdata::Mx {
            preference,
            exchange,
        } => format!("{preference} {exchange}"),
        Rdata::Txt(data) => data
            .segments()
            .iter()
            .map(|segment| format_quoted(segment))
            .collect::<Vec<_>>()
            .join(" "),
        Rdata::Srv {
            priority,
            weight,
            port,
            target,
        } => format!("{priority} {weight} {port} {target}"),
        Rdata::Caa { flags, tag, value } => format!(
            "{flags} {} {}",
            String::from_utf8_lossy(tag.as_bytes()),
            format_quoted(value)
        ),
        Rdata::Unknown { rdata, .. } => format_generic(rdata),
        other => format_generic(&other.to_canonical_wire()),
    }
}

/// Проверяет, управляется ли тип подписантом и не редактируется вручную.
pub(crate) fn is_managed_type(rr_type: Rtype) -> bool {
    matches!(
        rr_type,
        Rtype::RRSIG | Rtype::NSEC | Rtype::NSEC3 | Rtype::NSEC3PARAM | Rtype::DNSKEY
    )
}

fn invalid(rr_type: Rtype, error: impl fmt::Display) -> RdataParseError {
    RdataParseError::Invalid {
        rr_type,
        reason: error.to_string(),
    }
}

fn invalid_reason(rr_type: Rtype, reason: &str) -> RdataParseError {
    RdataParseError::Invalid {
        rr_type,
        reason: reason.to_owned(),
    }
}

fn parse_name(rr_type: Rtype, value: &str) -> Result<Name, RdataParseError> {
    Name::parse(value).map_err(|error| invalid(rr_type, error))
}

fn parse_u16(rr_type: Rtype, value: &str) -> Result<u16, RdataParseError> {
    value
        .parse::<u16>()
        .map_err(|error| invalid(rr_type, error))
}

fn parse_u32(rr_type: Rtype, value: &str) -> Result<u32, RdataParseError> {
    value
        .parse::<u32>()
        .map_err(|error| invalid(rr_type, error))
}

fn parse_generic(rr_type: Rtype, text: &str) -> Result<Rdata, RdataParseError> {
    let rest = text.strip_prefix("\\#").unwrap_or(text).trim();
    let mut parts = rest.split_whitespace();
    let length = parts
        .next()
        .ok_or_else(|| invalid_reason(rr_type, "missing RFC 3597 length"))?;
    let length: usize = length.parse().map_err(|error| invalid(rr_type, error))?;
    if length > usize::from(u16::MAX) {
        return Err(invalid_reason(rr_type, "rdata length exceeds 65535"));
    }
    let hex: String = parts.collect::<Vec<_>>().join("");
    let bytes =
        parse_hex(&hex).ok_or_else(|| invalid_reason(rr_type, "invalid RFC 3597 hex payload"))?;
    if bytes.len() != length {
        return Err(invalid_reason(
            rr_type,
            &format!(
                "RFC 3597 length {length} does not match {} octets",
                bytes.len()
            ),
        ));
    }
    Rdata::from_wire(rr_type, &bytes).map_err(|error| invalid(rr_type, error))
}

fn format_generic(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "\\# 0".to_owned();
    }
    format!("\\# {} {}", bytes.len(), hex_lower(bytes).to_uppercase())
}

fn parse_caa(text: &str) -> Result<Rdata, RdataParseError> {
    let mut rest = text.trim();
    let flags_token = take_token(&mut rest);
    let tag_token = take_token(&mut rest);
    let (Some(flags_token), Some(tag_token)) = (flags_token, tag_token) else {
        return Err(invalid_reason(Rtype::CAA, "CAA requires `flags tag value`"));
    };
    let flags = flags_token
        .parse::<u8>()
        .map_err(|error| invalid(Rtype::CAA, error))?;
    let tag = CaaTag::new(tag_token).map_err(|error| invalid(Rtype::CAA, error))?;
    let value_text = rest.trim();
    let value = if value_text.is_empty() {
        Vec::new()
    } else if value_text.starts_with('"') {
        let (bytes, consumed) =
            parse_quoted(value_text).map_err(|reason| invalid_reason(Rtype::CAA, &reason))?;
        if !value_text.get(consumed..).unwrap_or("").trim().is_empty() {
            return Err(invalid_reason(Rtype::CAA, "trailing data after CAA value"));
        }
        bytes
    } else {
        value_text.as_bytes().to_vec()
    };
    Ok(Rdata::Caa { flags, tag, value })
}

fn take_token<'a>(rest: &mut &'a str) -> Option<&'a str> {
    let trimmed = rest.trim_start();
    if trimmed.is_empty() {
        return None;
    }
    let end = trimmed.find(char::is_whitespace).unwrap_or(trimmed.len());
    let (token, remainder) = trimmed.split_at(end);
    *rest = remainder;
    Some(token)
}

fn parse_soa(text: &str) -> Result<Rdata, RdataParseError> {
    let tokens: Vec<&str> = text.split_whitespace().collect();
    if tokens.len() != 7 {
        return Err(invalid_reason(
            Rtype::SOA,
            "SOA requires `mname rname serial refresh retry expire minimum`",
        ));
    }
    let mname = parse_name(Rtype::SOA, tokens.first().copied().unwrap_or(""))?;
    let rname = parse_name(Rtype::SOA, tokens.get(1).copied().unwrap_or(""))?;
    let serial = parse_u32(Rtype::SOA, tokens.get(2).copied().unwrap_or(""))?;
    let refresh = parse_u32(Rtype::SOA, tokens.get(3).copied().unwrap_or(""))?;
    let retry = parse_u32(Rtype::SOA, tokens.get(4).copied().unwrap_or(""))?;
    let expire = parse_u32(Rtype::SOA, tokens.get(5).copied().unwrap_or(""))?;
    let minimum = parse_u32(Rtype::SOA, tokens.get(6).copied().unwrap_or(""))?;
    Ok(Rdata::Soa(SoaData::new(
        mname,
        rname,
        Serial::new(serial),
        refresh,
        retry,
        expire,
        minimum,
    )))
}

fn parse_txt_segments(text: &str) -> Result<Vec<Vec<u8>>, String> {
    let bytes = text.as_bytes();
    let mut index = 0;
    let mut segments = Vec::new();
    while index < bytes.len() {
        while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
            index += 1;
        }
        if index >= bytes.len() {
            break;
        }
        if bytes.get(index) == Some(&b'"') {
            let (segment, consumed) = parse_quoted(&text[index..])?;
            index += consumed;
            segments.push(segment);
        } else {
            let mut segment = Vec::new();
            while let Some(&byte) = bytes.get(index) {
                if byte.is_ascii_whitespace() {
                    break;
                }
                if byte == b'\\' {
                    let rest = bytes
                        .get(index..)
                        .ok_or_else(|| "invalid escape".to_owned())?;
                    let (value, consumed) = parse_escape(rest)?;
                    segment.push(value);
                    index += consumed;
                } else {
                    segment.push(byte);
                    index += 1;
                }
            }
            segments.push(segment);
        }
    }
    if segments.is_empty() {
        return Err("TXT requires at least one character-string".to_owned());
    }
    Ok(segments)
}

/// Разбирает quoted character-string. Возвращает байты и число consumed байт
/// входной строки (включая закрывающую кавычку).
fn parse_quoted(text: &str) -> Result<(Vec<u8>, usize), String> {
    let bytes = text.as_bytes();
    if bytes.first() != Some(&b'"') {
        return Err("expected opening quote".to_owned());
    }
    let mut index = 1;
    let mut output = Vec::new();
    loop {
        let Some(&byte) = bytes.get(index) else {
            return Err("unterminated quoted string".to_owned());
        };
        match byte {
            b'"' => {
                index += 1;
                return Ok((output, index));
            }
            b'\\' => {
                let rest = bytes
                    .get(index..)
                    .ok_or_else(|| "invalid escape".to_owned())?;
                let (value, consumed) = parse_escape(rest)?;
                output.push(value);
                index += consumed;
            }
            _ => {
                output.push(byte);
                index += 1;
            }
        }
    }
}

/// Разбирает escape-последовательность начиная с `\`.
fn parse_escape(bytes: &[u8]) -> Result<(u8, usize), String> {
    let Some(&next) = bytes.get(1) else {
        return Err("dangling escape".to_owned());
    };
    if next.is_ascii_digit() {
        let digits = bytes
            .get(1..4)
            .ok_or_else(|| "short decimal escape".to_owned())?;
        if digits.len() != 3 || !digits.iter().all(u8::is_ascii_digit) {
            return Err("decimal escape requires three digits".to_owned());
        }
        let mut value: u16 = 0;
        for digit in digits {
            value = value
                .checked_mul(10)
                .and_then(|value| value.checked_add(u16::from(digit - b'0')))
                .ok_or_else(|| "decimal escape overflow".to_owned())?;
        }
        if value > u16::from(u8::MAX) {
            return Err("decimal escape exceeds 255".to_owned());
        }
        Ok((
            u8::try_from(value).map_err(|_| "invalid escape".to_owned())?,
            4,
        ))
    } else {
        Ok((next, 2))
    }
}

fn format_quoted(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() + 2);
    out.push('"');
    for &byte in bytes {
        match byte {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7E => out.push(char::from(byte)),
            other => out.push_str(&format!("\\{other:03}")),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(rr_type: Rtype, text: &str) -> Rdata {
        let rdata = parse_rdata(rr_type, text).unwrap();
        assert_eq!(rdata.rr_type(), rr_type);
        let formatted = format_rdata(&rdata);
        let reparsed = parse_rdata(rr_type, &formatted).unwrap();
        assert_eq!(rdata, reparsed);
        rdata
    }

    #[test]
    fn address_types() {
        assert_eq!(
            round_trip(Rtype::A, "192.0.2.10"),
            Rdata::A("192.0.2.10".parse().unwrap())
        );
        assert_eq!(
            round_trip(Rtype::AAAA, "2001:db8::1"),
            Rdata::Aaaa("2001:db8::1".parse().unwrap())
        );
    }

    #[test]
    fn name_and_mx_types() {
        round_trip(Rtype::CNAME, "target.example.com.");
        round_trip(Rtype::MX, "10 mail.example.com.");
        round_trip(Rtype::SRV, "10 20 443 service.example.com.");
    }

    #[test]
    fn txt_quotes_and_spaces() {
        let rdata = round_trip(Rtype::TXT, "\"hello world\" \"second\"");
        let Rdata::Txt(data) = &rdata else {
            panic!("expected TXT");
        };
        assert_eq!(
            data.segments(),
            &[b"hello world".to_vec(), b"second".to_vec()]
        );
        let escaped = round_trip(Rtype::TXT, "\"quote \\\" and \\\\ slash\"");
        assert_eq!(format_rdata(&escaped), "\"quote \\\" and \\\\ slash\"");
    }

    #[test]
    fn caa_value() {
        let rdata = round_trip(Rtype::CAA, "0 issue \"letsencrypt.org\"");
        assert_eq!(format_rdata(&rdata), "0 issue \"letsencrypt.org\"");
    }

    #[test]
    fn rfc3597_unknown_and_known() {
        let unknown = round_trip(Rtype::from_u16(65280), "\\# 4 DEADBEEF");
        assert!(matches!(unknown, Rdata::Unknown { .. }));
        let parsed = parse_rdata(Rtype::A, "\\# 4 C0000201").unwrap();
        assert_eq!(parsed, Rdata::A("192.0.2.1".parse().unwrap()));
        assert!(parse_rdata(Rtype::A, "\\# 5 C0000201").is_err());
    }

    #[test]
    fn invalid_inputs_rejected() {
        assert!(parse_rdata(Rtype::A, "").is_err());
        assert!(parse_rdata(Rtype::A, "not-an-ip").is_err());
        assert!(parse_rdata(Rtype::MX, "10").is_err());
        assert!(parse_rdata(Rtype::TXT, "\"unterminated").is_err());
        assert!(parse_rdata(Rtype::A, "\\# 4 zz").is_err());
        assert!(parse_rdata(Rtype::TXT, "\"le\\999\" ").is_err());
    }

    #[test]
    fn managed_types() {
        assert!(is_managed_type(Rtype::RRSIG));
        assert!(is_managed_type(Rtype::DNSKEY));
        assert!(!is_managed_type(Rtype::A));
    }
}
