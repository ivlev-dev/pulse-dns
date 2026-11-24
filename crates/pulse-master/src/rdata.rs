//! Разбор RDATA из презентационной формы (RFC 1035 §5.1, RFC 3597, 9460).
//!
//! Каждый тип разбирается в соответствующий вариант [`pulse_dns::Rdata`];
//! неизвестные типы требуют generic-формы `\# <len> <hex>`.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use pulse_dns::{
    CaaTag, DnskeyData, DsData, Name, Nsec3Data, Nsec3ParamData, NsecData, Rdata, RrsigData, Rtype,
    SoaData, SvcParam, SvcbData, TlsaData, TxtData, TypeBitmap,
};

use crate::codec::{decode_base32hex, decode_base64, decode_hex, parse_rrsig_time};
use crate::error::{ErrorKind, Location, ParseError};
use crate::lexer::Token;
use crate::name::{decode_escapes, parse_name};
use crate::ttl::parse_duration;

/// Курсор по токенам RDATA.
struct Cursor<'a> {
    tokens: &'a [Token],
    index: usize,
    source: &'a str,
    rr_type: Rtype,
}

impl<'a> Cursor<'a> {
    fn new(tokens: &'a [Token], source: &'a str, rr_type: Rtype) -> Self {
        Self {
            tokens,
            index: 0,
            source,
            rr_type,
        }
    }

    fn next(&mut self, field: &'static str) -> Result<&'a Token, ParseError> {
        let Some(token) = self.tokens.get(self.index) else {
            return Err(self.error(format!("missing {field}")));
        };
        self.index = self.index.saturating_add(1);
        Ok(token)
    }

    fn rest(&mut self) -> &'a [Token] {
        let rest = self.tokens.get(self.index..).unwrap_or_default();
        self.index = self.tokens.len();
        rest
    }

    fn finish(&self) -> Result<(), ParseError> {
        if self.index < self.tokens.len() {
            return Err(self.error(format!(
                "unexpected extra field {:?}",
                self.tokens
                    .get(self.index)
                    .map(|token| token.text.as_str())
                    .unwrap_or_default()
            )));
        }
        Ok(())
    }

    fn error(&self, message: impl Into<String>) -> ParseError {
        let location = self.tokens.get(self.index).map_or_else(
            || {
                self.tokens.last().map_or_else(
                    || Location::new(self.source, 0, 0),
                    |token| token.location(self.source),
                )
            },
            |token| token.location(self.source),
        );
        ParseError::new(
            location,
            ErrorKind::Rdata {
                rr_type: self.rr_type,
                message: message.into(),
            },
        )
    }

    fn location(&self) -> Location {
        self.tokens.first().map_or_else(
            || Location::new(self.source, 0, 0),
            |token| token.location(self.source),
        )
    }

    fn last_location(&self) -> Location {
        let index = self.index.saturating_sub(1);
        self.tokens
            .get(index)
            .or_else(|| self.tokens.last())
            .map_or_else(
                || Location::new(self.source, 0, 0),
                |token| token.location(self.source),
            )
    }

    fn value<T>(&self, result: Result<T, pulse_dns::RdataError>) -> Result<T, ParseError> {
        result
            .map_err(|source| ParseError::new(self.last_location(), ErrorKind::RdataValue(source)))
    }

    fn codec<T>(&self, result: Result<T, String>, description: &str) -> Result<T, ParseError> {
        result.map_err(|message| {
            ParseError::new(
                self.last_location(),
                ErrorKind::Rdata {
                    rr_type: self.rr_type,
                    message: format!("invalid {description}: {message}"),
                },
            )
        })
    }
}

/// Разбирает RDATA заявленного типа.
///
/// # Errors
///
/// [`ErrorKind::Rdata`], [`ErrorKind::GenericRdata`], [`ErrorKind::Rdlength`]
/// или ошибка доменного конструктора.
#[allow(clippy::too_many_lines)]
pub(crate) fn parse_rdata(
    rr_type: Rtype,
    tokens: &[Token],
    source: &str,
    origin: &Name,
) -> Result<Rdata, ParseError> {
    let Some(first) = tokens.first() else {
        return Err(ParseError::new(
            Location::new(source, 0, 0),
            ErrorKind::Rdata {
                rr_type,
                message: "missing RDATA".to_owned(),
            },
        ));
    };

    if first.text == "\\#" {
        return parse_generic(rr_type, tokens, source);
    }
    if !rr_type.is_known() {
        return Err(ParseError::new(
            first.location(source),
            ErrorKind::Rdata {
                rr_type,
                message: "unknown type requires RFC 3597 generic form `\\# <length> <hex>`"
                    .to_owned(),
            },
        ));
    }

    let mut cursor = Cursor::new(tokens, source, rr_type);
    let rdata = match rr_type {
        Rtype::A => {
            let text = cursor.next("IPv4 address")?.text.clone();
            let address = text
                .parse::<Ipv4Addr>()
                .map_err(|_| cursor.error(format!("invalid IPv4 address {text:?}")))?;
            Rdata::A(address)
        }
        Rtype::AAAA => {
            let text = cursor.next("IPv6 address")?.text.clone();
            let address = text
                .parse::<Ipv6Addr>()
                .map_err(|_| cursor.error(format!("invalid IPv6 address {text:?}")))?;
            Rdata::Aaaa(address)
        }
        Rtype::NS => Rdata::Ns(cursor.name(origin, "name server")?),
        Rtype::CNAME => Rdata::Cname(cursor.name(origin, "canonical name")?),
        Rtype::DNAME => Rdata::Dname(cursor.name(origin, "delegation name")?),
        Rtype::PTR => Rdata::Ptr(cursor.name(origin, "pointer name")?),
        Rtype::MX => {
            let preference = cursor.number::<u16>("preference")?;
            let exchange = cursor.name(origin, "exchange")?;
            Rdata::Mx {
                preference,
                exchange,
            }
        }
        Rtype::TXT => {
            let mut segments = Vec::new();
            for token in cursor.rest() {
                segments.push(decode_escapes(
                    &token.text,
                    rr_type,
                    &token.location(source),
                )?);
            }
            Rdata::Txt(cursor.value(TxtData::new(segments))?)
        }
        Rtype::SOA => {
            let mname = cursor.name(origin, "mname")?;
            let rname = cursor.name(origin, "rname")?;
            let serial = cursor.number::<u32>("serial")?;
            let refresh = cursor.duration("refresh")?;
            let retry = cursor.duration("retry")?;
            let expire = cursor.duration("expire")?;
            let minimum = cursor.duration("minimum")?;
            validate_soa_timers(refresh, retry, expire, &cursor)?;
            Rdata::Soa(SoaData::new(
                mname,
                rname,
                pulse_dns::Serial::new(serial),
                refresh,
                retry,
                expire,
                minimum,
            ))
        }
        Rtype::SRV => {
            let priority = cursor.number::<u16>("priority")?;
            let weight = cursor.number::<u16>("weight")?;
            let port = cursor.number::<u16>("port")?;
            let target = cursor.name(origin, "target")?;
            Rdata::Srv {
                priority,
                weight,
                port,
                target,
            }
        }
        Rtype::CAA => {
            let flags = cursor.number::<u8>("flags")?;
            let tag_token = cursor.next("tag")?;
            let tag_bytes = decode_escapes(&tag_token.text, rr_type, &tag_token.location(source))?;
            let tag = cursor.value(CaaTag::new(&tag_bytes))?;
            let value_token = cursor.next("value")?;
            let value = decode_escapes(&value_token.text, rr_type, &value_token.location(source))?;
            Rdata::Caa { flags, tag, value }
        }
        Rtype::DS => {
            let key_tag = cursor.number::<u16>("key tag")?;
            let algorithm = cursor.number::<u8>("algorithm")?;
            let digest_type = cursor.number::<u8>("digest type")?;
            let digest_text = cursor.join_rest("digest", "hex digest")?;
            let digest = cursor.codec(decode_hex(&digest_text), "hex digest")?;
            Rdata::Ds(cursor.value(DsData::new(key_tag, algorithm, digest_type, digest))?)
        }
        Rtype::DNSKEY => {
            let flags = cursor.number::<u16>("flags")?;
            let protocol = cursor.number::<u8>("protocol")?;
            let algorithm = cursor.number::<u8>("algorithm")?;
            let key_text = cursor.join_rest("public key", "base64 key")?;
            let key = cursor.codec(decode_base64(&key_text), "base64 public key")?;
            Rdata::Dnskey(cursor.value(DnskeyData::new(flags, protocol, algorithm, key))?)
        }
        Rtype::RRSIG => {
            let type_covered = cursor.rtype("type covered")?;
            let algorithm = cursor.number::<u8>("algorithm")?;
            let labels = cursor.number::<u8>("labels")?;
            let original_ttl = cursor.duration("original TTL")?;
            let expiration_token = cursor.next("signature expiration")?;
            let expiration = parse_rrsig_time(&expiration_token.text).map_err(|message| {
                ParseError::new(
                    expiration_token.location(source),
                    ErrorKind::Timestamp {
                        input: expiration_token.text.clone(),
                        message,
                    },
                )
            })?;
            let inception_token = cursor.next("signature inception")?;
            let inception = parse_rrsig_time(&inception_token.text).map_err(|message| {
                ParseError::new(
                    inception_token.location(source),
                    ErrorKind::Timestamp {
                        input: inception_token.text.clone(),
                        message,
                    },
                )
            })?;
            let key_tag = cursor.number::<u16>("key tag")?;
            let signer_name = cursor.name(origin, "signer name")?;
            let signature_text = cursor.join_rest("signature", "base64 signature")?;
            let signature = cursor.codec(decode_base64(&signature_text), "base64 signature")?;
            Rdata::Rrsig(cursor.value(RrsigData::new(
                type_covered,
                algorithm,
                labels,
                original_ttl,
                expiration,
                inception,
                key_tag,
                signer_name,
                signature,
            ))?)
        }
        Rtype::NSEC => {
            let next_domain = cursor.name(origin, "next domain")?;
            let bitmap = cursor.bitmap()?;
            Rdata::Nsec(cursor.value(NsecData::new(next_domain, bitmap))?)
        }
        Rtype::NSEC3 => {
            let hash_algorithm = cursor.number::<u8>("hash algorithm")?;
            let flags = cursor.number::<u8>("flags")?;
            let iterations = cursor.number::<u16>("iterations")?;
            let salt = cursor.salt("salt")?;
            let next_token = cursor.next("next hashed owner")?;
            let next_hashed_owner = cursor.codec(
                decode_base32hex(&next_token.text),
                "base32hex next hashed owner",
            )?;
            let type_bitmap = cursor.bitmap_allow_empty()?;
            Rdata::Nsec3(cursor.value(Nsec3Data::new(
                hash_algorithm,
                flags,
                iterations,
                salt,
                next_hashed_owner,
                type_bitmap,
            ))?)
        }
        Rtype::NSEC3PARAM => {
            let hash_algorithm = cursor.number::<u8>("hash algorithm")?;
            let flags = cursor.number::<u8>("flags")?;
            let iterations = cursor.number::<u16>("iterations")?;
            let salt = cursor.salt("salt")?;
            Rdata::Nsec3Param(cursor.value(Nsec3ParamData::new(
                hash_algorithm,
                flags,
                iterations,
                salt,
            ))?)
        }
        Rtype::TLSA => {
            let usage = cursor.number::<u8>("usage")?;
            let selector = cursor.number::<u8>("selector")?;
            let matching = cursor.number::<u8>("matching type")?;
            let data_text = cursor.join_rest("association data", "hex data")?;
            let data = cursor.codec(decode_hex(&data_text), "hex association data")?;
            Rdata::Tlsa(cursor.value(TlsaData::new(usage, selector, matching, data))?)
        }
        Rtype::SVCB | Rtype::HTTPS => {
            let priority = cursor.number::<u16>("priority")?;
            let target = cursor.name(origin, "target")?;
            let params = parse_svcb_params(cursor.rest(), &cursor)?;
            let svcb = cursor.value(SvcbData::new(priority, target, params))?;
            if rr_type == Rtype::SVCB {
                Rdata::Svcb(svcb)
            } else {
                Rdata::Https(svcb)
            }
        }
        other => {
            return Err(ParseError::new(
                first.location(source),
                ErrorKind::Rdata {
                    rr_type: other,
                    message: format!("type {other} is not supported in presentation form"),
                },
            ));
        }
    };
    cursor.finish()?;
    Ok(rdata)
}

impl Cursor<'_> {
    fn name(&mut self, origin: &Name, field: &'static str) -> Result<Name, ParseError> {
        let token = self.next(field)?;
        parse_name(&token.text, origin, &token.location(self.source))
    }

    fn number<T>(&mut self, field: &'static str) -> Result<T, ParseError>
    where
        T: FromStr,
    {
        let token = self.next(field)?;
        token.text.parse::<T>().map_err(|_| {
            ParseError::new(
                token.location(self.source),
                ErrorKind::Number {
                    field,
                    input: token.text.clone(),
                },
            )
        })
    }

    fn duration(&mut self, field: &'static str) -> Result<u32, ParseError> {
        let token = self.next(field)?;
        parse_duration(&token.text).map_err(|message| {
            ParseError::new(
                token.location(self.source),
                ErrorKind::Rdata {
                    rr_type: self.rr_type,
                    message: format!("invalid {field} {:?}: {message}", token.text),
                },
            )
        })
    }

    fn rtype(&mut self, field: &'static str) -> Result<Rtype, ParseError> {
        let token = self.next(field)?;
        parse_rtype(&token.text, &token.location(self.source))
    }

    fn join_rest(
        &mut self,
        field: &'static str,
        description: &'static str,
    ) -> Result<String, ParseError> {
        let rest = self.rest();
        if rest.is_empty() {
            return Err(self.error(format!("missing {field}")));
        }
        let mut joined = String::new();
        for token in rest {
            joined.push_str(&token.text);
        }
        if joined.is_empty() {
            return Err(self.error(format!("empty {description}")));
        }
        Ok(joined)
    }

    fn salt(&mut self, field: &'static str) -> Result<Vec<u8>, ParseError> {
        let token = self.next(field)?;
        if token.text == "-" {
            return Ok(Vec::new());
        }
        decode_hex(&token.text).map_err(|message| {
            ParseError::new(
                token.location(self.source),
                ErrorKind::Rdata {
                    rr_type: self.rr_type,
                    message: format!("invalid salt hex: {message}"),
                },
            )
        })
    }

    fn bitmap(&mut self) -> Result<TypeBitmap, ParseError> {
        let rest = self.rest();
        if rest.is_empty() {
            return Err(self.error("missing type bitmap"));
        }
        let mut types = Vec::new();
        for token in rest {
            types.push(parse_rtype(&token.text, &token.location(self.source))?);
        }
        Ok(TypeBitmap::from_types(types))
    }

    fn bitmap_allow_empty(&mut self) -> Result<TypeBitmap, ParseError> {
        let rest = self.rest();
        let mut types = Vec::new();
        for token in rest {
            types.push(parse_rtype(&token.text, &token.location(self.source))?);
        }
        Ok(TypeBitmap::from_types(types))
    }
}

fn validate_soa_timers(
    refresh: u32,
    retry: u32,
    expire: u32,
    cursor: &Cursor<'_>,
) -> Result<(), ParseError> {
    if refresh == 0 {
        return Err(cursor.error("SOA refresh must be at least 1"));
    }
    if retry == 0 {
        return Err(cursor.error("SOA retry must be at least 1"));
    }
    let sum = u64::from(refresh) + u64::from(retry);
    if u64::from(expire) <= sum {
        return Err(cursor.error(format!(
            "SOA expire ({expire}) must be greater than refresh + retry ({sum})"
        )));
    }
    Ok(())
}

fn parse_generic(rr_type: Rtype, tokens: &[Token], source: &str) -> Result<Rdata, ParseError> {
    let mut cursor = Cursor::new(tokens, source, rr_type);
    cursor.next("generic marker")?;
    let length_token = cursor.next("generic length")?;
    let declared = length_token.text.parse::<usize>().map_err(|_| {
        ParseError::new(
            length_token.location(source),
            ErrorKind::GenericRdata {
                rr_type,
                message: format!("invalid length {:?}", length_token.text),
            },
        )
    })?;
    let hex = {
        let rest = cursor.rest();
        if rest.is_empty() {
            String::new()
        } else {
            let mut joined = String::new();
            for token in rest {
                joined.push_str(&token.text);
            }
            joined
        }
    };
    let bytes = if hex.is_empty() {
        Vec::new()
    } else {
        decode_hex(&hex).map_err(|message| {
            ParseError::new(
                length_token.location(source),
                ErrorKind::GenericRdata { rr_type, message },
            )
        })?
    };
    if bytes.len() != declared {
        return Err(ParseError::new(
            length_token.location(source),
            ErrorKind::Rdlength {
                declared,
                actual: bytes.len(),
            },
        ));
    }
    cursor.finish()?;
    if rr_type.is_known() {
        Rdata::from_wire(rr_type, &bytes).map_err(|error| {
            ParseError::new(
                length_token.location(source),
                ErrorKind::GenericRdata {
                    rr_type,
                    message: error.to_string(),
                },
            )
        })
    } else {
        Rdata::unknown(rr_type, bytes).map_err(|error| {
            ParseError::new(length_token.location(source), ErrorKind::RdataValue(error))
        })
    }
}

fn parse_svcb_params(tokens: &[Token], cursor: &Cursor<'_>) -> Result<Vec<SvcParam>, ParseError> {
    let mut params = Vec::new();
    for token in tokens {
        let location = token.location(cursor.source);
        let (key_text, raw_value) = match token.text.split_once('=') {
            Some((key, value)) => (key, Some(value)),
            None => (token.text.as_str(), None),
        };
        let key = parse_svc_key(key_text).map_err(|message| {
            ParseError::new(
                location.clone(),
                ErrorKind::Rdata {
                    rr_type: cursor.rr_type,
                    message,
                },
            )
        })?;
        let value = match raw_value {
            Some(raw) => Some(strip_quotes(raw, &location, cursor.rr_type)?),
            None => None,
        };
        let wire = encode_svc_value(key, value.as_deref(), &location, cursor.rr_type)?;
        let param = SvcParam::new(key, wire)
            .map_err(|source| ParseError::new(location.clone(), ErrorKind::RdataValue(source)))?;
        params.push(param);
    }
    params.sort_by_key(SvcParam::key);
    for pair in params.windows(2) {
        let (Some(left), Some(right)) = (pair.first(), pair.get(1)) else {
            continue;
        };
        if left.key() == right.key() {
            return Err(ParseError::new(
                cursor.location(),
                ErrorKind::Rdata {
                    rr_type: cursor.rr_type,
                    message: format!("duplicate SvcParam key {}", left.key()),
                },
            ));
        }
    }
    Ok(params)
}

fn strip_quotes(raw: &str, location: &Location, rr_type: Rtype) -> Result<String, ParseError> {
    if let Some(inner) = raw.strip_prefix('"') {
        let Some(inner) = inner.strip_suffix('"') else {
            return Err(ParseError::new(
                location.clone(),
                ErrorKind::Rdata {
                    rr_type,
                    message: "unterminated quoted SvcParam value".to_owned(),
                },
            ));
        };
        Ok(inner.to_owned())
    } else {
        Ok(raw.to_owned())
    }
}

fn parse_svc_key(text: &str) -> Result<u16, String> {
    let lower = text.to_ascii_lowercase();
    match lower.as_str() {
        "mandatory" => Ok(SvcParam::KEY_MANDATORY),
        "alpn" => Ok(SvcParam::KEY_ALPN),
        "no-default-alpn" => Ok(2),
        "port" => Ok(SvcParam::KEY_PORT),
        "ipv4hint" => Ok(SvcParam::KEY_IPV4HINT),
        "ech" => Ok(SvcParam::KEY_ECH),
        "ipv6hint" => Ok(SvcParam::KEY_IPV6HINT),
        other => {
            let number = other
                .strip_prefix("key")
                .ok_or_else(|| format!("unknown SvcParam key {text:?}"))?;
            number
                .parse::<u16>()
                .map_err(|_| format!("invalid SvcParam key {text:?}"))
        }
    }
}

#[allow(clippy::too_many_lines)]
fn encode_svc_value(
    key: u16,
    raw: Option<&str>,
    location: &Location,
    rr_type: Rtype,
) -> Result<Vec<u8>, ParseError> {
    let error =
        |message: String| ParseError::new(location.clone(), ErrorKind::Rdata { rr_type, message });
    match key {
        SvcParam::KEY_MANDATORY => {
            let Some(raw) = raw else {
                return Err(error("mandatory= requires a key list".to_owned()));
            };
            if raw.is_empty() {
                return Err(error("mandatory= requires a non-empty key list".to_owned()));
            }
            let mut keys = Vec::new();
            for part in split_escaped_commas(raw) {
                let bytes = decode_escapes(part, rr_type, location)?;
                let text = std::str::from_utf8(&bytes)
                    .map_err(|_| error("mandatory list is not ASCII".to_owned()))?;
                keys.push(parse_svc_key(text).map_err(error)?);
            }
            keys.sort_unstable();
            for pair in keys.windows(2) {
                if let (Some(left), Some(right)) = (pair.first(), pair.get(1))
                    && left == right
                {
                    return Err(error(format!("duplicate key {left} in mandatory list")));
                }
            }
            let mut wire = Vec::with_capacity(keys.len() * 2);
            for key in keys {
                wire.extend_from_slice(&key.to_be_bytes());
            }
            Ok(wire)
        }
        SvcParam::KEY_ALPN => {
            let Some(raw) = raw else {
                return Err(error("alpn= requires at least one protocol".to_owned()));
            };
            if raw.is_empty() {
                return Err(error("alpn= requires at least one protocol".to_owned()));
            }
            let mut wire = Vec::new();
            for part in split_escaped_commas(raw) {
                let protocol = decode_escapes(part, rr_type, location)?;
                if protocol.is_empty() {
                    return Err(error("alpn list contains an empty identifier".to_owned()));
                }
                let Ok(length) = u8::try_from(protocol.len()) else {
                    return Err(error("alpn identifier exceeds 255 octets".to_owned()));
                };
                wire.push(length);
                wire.extend_from_slice(&protocol);
            }
            Ok(wire)
        }
        2 => {
            if raw.is_some_and(|value| !value.is_empty()) {
                return Err(error("no-default-alpn must not have a value".to_owned()));
            }
            Ok(Vec::new())
        }
        SvcParam::KEY_PORT => {
            let Some(raw) = raw else {
                return Err(error("port= requires a value".to_owned()));
            };
            let bytes = decode_escapes(raw, rr_type, location)?;
            let text =
                std::str::from_utf8(&bytes).map_err(|_| error("port is not ASCII".to_owned()))?;
            let port = text
                .parse::<u16>()
                .map_err(|_| error(format!("invalid port {text:?}")))?;
            Ok(port.to_be_bytes().to_vec())
        }
        SvcParam::KEY_IPV4HINT => {
            let Some(raw) = raw else {
                return Err(error("ipv4hint= requires at least one address".to_owned()));
            };
            if raw.is_empty() {
                return Err(error("ipv4hint= requires at least one address".to_owned()));
            }
            let mut wire = Vec::new();
            for part in split_escaped_commas(raw) {
                let bytes = decode_escapes(part, rr_type, location)?;
                let text = std::str::from_utf8(&bytes)
                    .map_err(|_| error("ipv4hint is not ASCII".to_owned()))?;
                let address = text
                    .parse::<Ipv4Addr>()
                    .map_err(|_| error(format!("invalid IPv4 hint {text:?}")))?;
                wire.extend_from_slice(&address.octets());
            }
            Ok(wire)
        }
        SvcParam::KEY_IPV6HINT => {
            let Some(raw) = raw else {
                return Err(error("ipv6hint= requires at least one address".to_owned()));
            };
            if raw.is_empty() {
                return Err(error("ipv6hint= requires at least one address".to_owned()));
            }
            let mut wire = Vec::new();
            for part in split_escaped_commas(raw) {
                let bytes = decode_escapes(part, rr_type, location)?;
                let text = std::str::from_utf8(&bytes)
                    .map_err(|_| error("ipv6hint is not ASCII".to_owned()))?;
                let address = text
                    .parse::<Ipv6Addr>()
                    .map_err(|_| error(format!("invalid IPv6 hint {text:?}")))?;
                wire.extend_from_slice(&address.octets());
            }
            Ok(wire)
        }
        SvcParam::KEY_ECH => {
            let Some(raw) = raw else {
                return Err(error("ech= requires a value".to_owned()));
            };
            let bytes = decode_escapes(raw, rr_type, location)?;
            let text =
                std::str::from_utf8(&bytes).map_err(|_| error("ech is not ASCII".to_owned()))?;
            let bytes =
                decode_base64(text).map_err(|message| error(format!("invalid ech: {message}")))?;
            if bytes.is_empty() {
                return Err(error("ech must not be empty".to_owned()));
            }
            Ok(bytes)
        }
        _ => match raw {
            Some(raw) => decode_escapes(raw, rr_type, location),
            None => Ok(Vec::new()),
        },
    }
}

/// Делит значение SvcParam на компоненты по неэкранированным запятым.
fn split_escaped_commas(raw: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0_usize;
    let mut chars = raw.char_indices().peekable();
    while let Some((index, ch)) = chars.next() {
        match ch {
            '\\' => {
                if let Some(&(_, next)) = chars.peek() {
                    chars.next();
                    if next.is_ascii_digit() {
                        for _ in 0..2 {
                            if chars
                                .peek()
                                .is_some_and(|&(_, digit)| digit.is_ascii_digit())
                            {
                                chars.next();
                            } else {
                                break;
                            }
                        }
                    }
                }
            }
            ',' => {
                parts.push(raw.get(start..index).unwrap_or_default());
                start = index.saturating_add(1);
            }
            _ => {}
        }
    }
    parts.push(raw.get(start..).unwrap_or_default());
    parts
}

/// Разбирает мнемонику типа записи (`A`, `TYPE65280`) или число `TYPE####`.
///
/// # Errors
///
/// [`ErrorKind::Type`] для неизвестной мнемоники и
/// [`ErrorKind::NotZoneType`] для мета-типов.
pub(crate) fn parse_rtype(text: &str, location: &Location) -> Result<Rtype, ParseError> {
    if let Some(number) = text
        .to_ascii_uppercase()
        .strip_prefix("TYPE")
        .map(str::to_owned)
        .and_then(|digits| digits.parse::<u16>().ok())
    {
        let rr_type = Rtype::from_u16(number);
        ensure_zone_type(rr_type, location)?;
        return Ok(rr_type);
    }

    let upper = text.to_ascii_uppercase();
    let rr_type = match upper.as_str() {
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
        _ => {
            return Err(ParseError::new(
                location.clone(),
                ErrorKind::Type(text.to_owned()),
            ));
        }
    };
    ensure_zone_type(rr_type, location)?;
    Ok(rr_type)
}

fn ensure_zone_type(rr_type: Rtype, location: &Location) -> Result<(), ParseError> {
    if matches!(
        rr_type,
        Rtype::OPT | Rtype::AXFR | Rtype::IXFR | Rtype::TKEY | Rtype::TSIG | Rtype::ANY
    ) {
        return Err(ParseError::new(
            location.clone(),
            ErrorKind::NotZoneType(rr_type),
        ));
    }
    Ok(())
}
