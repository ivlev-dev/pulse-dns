//! Разбор RDATA из JSON-представления конфигурации.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use pulse_dns::{
    CaaTag, DnskeyData, DsData, Name, NsecData, Rdata, RrsigData, Rtype, Serial, SoaData, TlsaData,
    TxtData, TypeBitmap,
};
use serde_json::{Map, Value};

use crate::names;

/// Разбирает мнемонику типа записи (или `TYPE<number>`).
pub(crate) fn parse_type(text: &str) -> Result<Rtype, String> {
    let upper = text.trim().to_ascii_uppercase();
    let known = match upper.as_str() {
        "A" => Some(Rtype::A),
        "NS" => Some(Rtype::NS),
        "CNAME" => Some(Rtype::CNAME),
        "SOA" => Some(Rtype::SOA),
        "PTR" => Some(Rtype::PTR),
        "MX" => Some(Rtype::MX),
        "TXT" => Some(Rtype::TXT),
        "AAAA" => Some(Rtype::AAAA),
        "SRV" => Some(Rtype::SRV),
        "DNAME" => Some(Rtype::DNAME),
        "OPT" => Some(Rtype::OPT),
        "DS" => Some(Rtype::DS),
        "RRSIG" => Some(Rtype::RRSIG),
        "NSEC" => Some(Rtype::NSEC),
        "DNSKEY" => Some(Rtype::DNSKEY),
        "NSEC3" => Some(Rtype::NSEC3),
        "NSEC3PARAM" => Some(Rtype::NSEC3PARAM),
        "TLSA" => Some(Rtype::TLSA),
        "SVCB" => Some(Rtype::SVCB),
        "HTTPS" => Some(Rtype::HTTPS),
        "CAA" => Some(Rtype::CAA),
        "ANY" => Some(Rtype::ANY),
        _ => None,
    };
    if let Some(rr_type) = known {
        return Ok(rr_type);
    }
    let Some(number) = upper.strip_prefix("TYPE") else {
        return Err(format!("unknown record type {text:?}"));
    };
    let value = number
        .parse::<u16>()
        .map_err(|error| format!("invalid record type {text:?}: {error}"))?;
    if value == 0 || value == u16::MAX {
        return Err(format!("record type {value} is reserved"));
    }
    let rr_type = Rtype::from_u16(value);
    if rr_type.is_known() {
        return Err(format!(
            "TYPE{value} is a known type; use its mnemonic instead"
        ));
    }
    Ok(rr_type)
}

/// Разбирает RDATA указанного типа.
#[allow(clippy::too_many_lines)] // Диспетчеризация по типу: одна ветка на формат.
pub(crate) fn parse(rr_type: Rtype, value: &Value, origin: &Name) -> Result<Rdata, String> {
    match rr_type {
        Rtype::A => {
            let text = as_string(value, "A rdata")?;
            let address = text
                .parse()
                .map_err(|error| format!("invalid IPv4 address {text:?}: {error}"))?;
            Ok(Rdata::A(address))
        }
        Rtype::AAAA => {
            let text = as_string(value, "AAAA rdata")?;
            let address = text
                .parse()
                .map_err(|error| format!("invalid IPv6 address {text:?}: {error}"))?;
            Ok(Rdata::Aaaa(address))
        }
        Rtype::NS => name_value(value, "NS rdata", origin).map(Rdata::Ns),
        Rtype::CNAME => name_value(value, "CNAME rdata", origin).map(Rdata::Cname),
        Rtype::PTR => name_value(value, "PTR rdata", origin).map(Rdata::Ptr),
        Rtype::DNAME => name_value(value, "DNAME rdata", origin).map(Rdata::Dname),
        Rtype::MX => {
            let object = as_object(value, "MX rdata")?;
            Ok(Rdata::Mx {
                preference: u16_field(object, "preference", "MX")?,
                exchange: name_field(object, "exchange", "MX", origin)?,
            })
        }
        Rtype::TXT => parse_txt(value).map(Rdata::Txt),
        Rtype::SOA => {
            let object = as_object(value, "SOA rdata")?;
            Ok(Rdata::Soa(SoaData::new(
                name_field(object, "mname", "SOA", origin)?,
                name_field(object, "rname", "SOA", origin)?,
                Serial::new(u32_field(object, "serial", "SOA")?),
                u32_field(object, "refresh", "SOA")?,
                u32_field(object, "retry", "SOA")?,
                u32_field(object, "expire", "SOA")?,
                u32_field(object, "minimum", "SOA")?,
            )))
        }
        Rtype::SRV => {
            let object = as_object(value, "SRV rdata")?;
            Ok(Rdata::Srv {
                priority: u16_field(object, "priority", "SRV")?,
                weight: u16_field(object, "weight", "SRV")?,
                port: u16_field(object, "port", "SRV")?,
                target: name_field(object, "target", "SRV", origin)?,
            })
        }
        Rtype::CAA => {
            let object = as_object(value, "CAA rdata")?;
            let tag = as_string(required(object, "tag", "CAA")?, "CAA tag")?;
            let tag = CaaTag::new(tag).map_err(|error| format!("invalid CAA tag: {error}"))?;
            let value = as_string(required(object, "value", "CAA")?, "CAA value")?;
            Ok(Rdata::Caa {
                flags: u8_field(object, "flags", "CAA")?,
                tag,
                value: value.as_bytes().to_vec(),
            })
        }
        Rtype::DS => {
            let object = as_object(value, "DS rdata")?;
            let digest = as_string(required(object, "digest", "DS")?, "DS digest")?;
            let digest = decode_hex(digest, "DS digest")?;
            DsData::new(
                u16_field(object, "key_tag", "DS")?,
                u8_field(object, "algorithm", "DS")?,
                u8_field(object, "digest_type", "DS")?,
                digest,
            )
            .map(Rdata::Ds)
            .map_err(|error| format!("invalid DS rdata: {error}"))
        }
        Rtype::DNSKEY => {
            let object = as_object(value, "DNSKEY rdata")?;
            let key = as_string(
                required(object, "public_key", "DNSKEY")?,
                "DNSKEY public_key",
            )?;
            let key = decode_base64(key, "DNSKEY public_key")?;
            DnskeyData::new(
                u16_field(object, "flags", "DNSKEY")?,
                u8_field(object, "protocol", "DNSKEY")?,
                u8_field(object, "algorithm", "DNSKEY")?,
                key,
            )
            .map(Rdata::Dnskey)
            .map_err(|error| format!("invalid DNSKEY rdata: {error}"))
        }
        Rtype::RRSIG => {
            let object = as_object(value, "RRSIG rdata")?;
            let covered = as_string(
                required(object, "type_covered", "RRSIG")?,
                "RRSIG type_covered",
            )?;
            let covered = parse_type(covered)
                .map_err(|error| format!("invalid RRSIG type_covered: {error}"))?;
            let signature = as_string(required(object, "signature", "RRSIG")?, "RRSIG signature")?;
            let signature = decode_base64(signature, "RRSIG signature")?;
            RrsigData::new(
                covered,
                u8_field(object, "algorithm", "RRSIG")?,
                u8_field(object, "labels", "RRSIG")?,
                u32_field(object, "original_ttl", "RRSIG")?,
                u32_field(object, "signature_expiration", "RRSIG")?,
                u32_field(object, "signature_inception", "RRSIG")?,
                u16_field(object, "key_tag", "RRSIG")?,
                name_field(object, "signer_name", "RRSIG", origin)?,
                signature,
            )
            .map(Rdata::Rrsig)
            .map_err(|error| format!("invalid RRSIG rdata: {error}"))
        }
        Rtype::NSEC => {
            let object = as_object(value, "NSEC rdata")?;
            let next = name_field(object, "next_domain", "NSEC", origin)?;
            let types = required(object, "types", "NSEC")?
                .as_array()
                .ok_or_else(|| "NSEC types must be an array of type mnemonics".to_owned())?;
            if types.is_empty() {
                return Err("NSEC types must not be empty".to_owned());
            }
            let mut parsed = Vec::with_capacity(types.len());
            for entry in types {
                let text = as_string(entry, "NSEC type")?;
                parsed.push(parse_type(text)?);
            }
            let bitmap = TypeBitmap::from_types(parsed);
            NsecData::new(next, bitmap)
                .map(Rdata::Nsec)
                .map_err(|error| format!("invalid NSEC rdata: {error}"))
        }
        Rtype::TLSA => {
            let object = as_object(value, "TLSA rdata")?;
            let data = as_string(
                required(object, "certificate_association_data", "TLSA")?,
                "TLSA certificate_association_data",
            )?;
            let data = decode_hex(data, "TLSA certificate_association_data")?;
            TlsaData::new(
                u8_field(object, "usage", "TLSA")?,
                u8_field(object, "selector", "TLSA")?,
                u8_field(object, "matching", "TLSA")?,
                data,
            )
            .map(Rdata::Tlsa)
            .map_err(|error| format!("invalid TLSA rdata: {error}"))
        }
        Rtype::NSEC3 | Rtype::NSEC3PARAM | Rtype::SVCB | Rtype::HTTPS => Err(format!(
            "RDATA for {rr_type} is not supported by the configuration format in v1"
        )),
        other => parse_unknown(other, value),
    }
}

fn parse_txt(value: &Value) -> Result<TxtData, String> {
    let segments: Vec<Vec<u8>> = if let Some(text) = value.as_str() {
        vec![text.as_bytes().to_vec()]
    } else {
        let array = value
            .as_array()
            .ok_or_else(|| "TXT rdata must be a string or an array of strings".to_owned())?;
        let mut segments = Vec::with_capacity(array.len());
        for entry in array {
            segments.push(as_string(entry, "TXT segment")?.as_bytes().to_vec());
        }
        segments
    };
    TxtData::new(segments).map_err(|error| format!("invalid TXT rdata: {error}"))
}

fn parse_unknown(rr_type: Rtype, value: &Value) -> Result<Rdata, String> {
    let text = as_string(value, "unknown rdata")?;
    let text = text.trim();
    if text.is_empty() {
        return Err("unknown rdata must be hex (`\\# len hex`), `hex:…` or `b64:…`".to_owned());
    }
    let bytes = if let Some(rest) = text.strip_prefix("\\#") {
        parse_rfc3597(rest)?
    } else if let Some(hex_text) = text.strip_prefix("hex:") {
        decode_hex(hex_text, "unknown rdata")?
    } else if let Some(base64_text) = text.strip_prefix("b64:") {
        decode_base64(base64_text, "unknown rdata")?
    } else if is_hex(text) {
        decode_hex(text, "unknown rdata")?
    } else {
        decode_base64(text, "unknown rdata")?
    };
    Rdata::unknown(rr_type, bytes).map_err(|error| format!("invalid {rr_type} rdata: {error}"))
}

fn parse_rfc3597(rest: &str) -> Result<Vec<u8>, String> {
    let mut parts = rest.split_whitespace();
    let length = parts
        .next()
        .ok_or_else(|| "RFC 3597 rdata must be `\\# <length> <hex>`".to_owned())?
        .parse::<usize>()
        .map_err(|error| format!("invalid RFC 3597 length: {error}"))?;
    let hex_text: String = parts.collect();
    let bytes = decode_hex(&hex_text, "RFC 3597 rdata")?;
    if bytes.len() != length {
        return Err(format!(
            "RFC 3597 length mismatch: declared {length}, got {}",
            bytes.len()
        ));
    }
    Ok(bytes)
}

fn is_hex(text: &str) -> bool {
    let compact: String = text
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect();
    !compact.is_empty()
        && compact.len().is_multiple_of(2)
        && compact
            .chars()
            .all(|character| character.is_ascii_hexdigit())
}

fn decode_hex(text: &str, what: &str) -> Result<Vec<u8>, String> {
    let compact: String = text
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect();
    let compact = compact
        .strip_prefix("0x")
        .or_else(|| compact.strip_prefix("0X"))
        .unwrap_or(&compact);
    hex::decode(compact).map_err(|error| format!("{what} is not valid hex: {error}"))
}

fn decode_base64(text: &str, what: &str) -> Result<Vec<u8>, String> {
    let compact: String = text
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect();
    if compact.is_empty() {
        return Err(format!("{what} must not be empty"));
    }
    STANDARD
        .decode(&compact)
        .or_else(|_| STANDARD_NO_PAD.decode(&compact))
        .map_err(|error| format!("{what} is not valid base64: {error}"))
}

fn name_value(value: &Value, what: &str, origin: &Name) -> Result<Name, String> {
    let text = as_string(value, what)?;
    names::qualify(text, origin).map_err(|error| format!("{what}: {error}"))
}

fn name_field(
    object: &Map<String, Value>,
    key: &str,
    what: &str,
    origin: &Name,
) -> Result<Name, String> {
    name_value(
        required(object, key, what)?,
        &format!("{what}.{key}"),
        origin,
    )
}

fn as_string<'a>(value: &'a Value, what: &str) -> Result<&'a str, String> {
    value
        .as_str()
        .ok_or_else(|| format!("{what} must be a string"))
}

fn as_object<'a>(value: &'a Value, what: &str) -> Result<&'a Map<String, Value>, String> {
    value
        .as_object()
        .ok_or_else(|| format!("{what} must be an object"))
}

fn required<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    what: &str,
) -> Result<&'a Value, String> {
    object
        .get(key)
        .ok_or_else(|| format!("{what} rdata is missing field {key:?}"))
}

fn u8_field(object: &Map<String, Value>, key: &str, what: &str) -> Result<u8, String> {
    let value = required(object, key, what)?
        .as_u64()
        .ok_or_else(|| format!("{what}.{key} must be an unsigned integer"))?;
    u8::try_from(value).map_err(|_| format!("{what}.{key} is out of range: {value}"))
}

fn u16_field(object: &Map<String, Value>, key: &str, what: &str) -> Result<u16, String> {
    let value = required(object, key, what)?
        .as_u64()
        .ok_or_else(|| format!("{what}.{key} must be an unsigned integer"))?;
    u16::try_from(value).map_err(|_| format!("{what}.{key} is out of range: {value}"))
}

fn u32_field(object: &Map<String, Value>, key: &str, what: &str) -> Result<u32, String> {
    let value = required(object, key, what)?;
    let number = if let Some(number) = value.as_u64() {
        number
    } else if let Some(text) = value.as_str() {
        text.trim()
            .parse::<u64>()
            .map_err(|error| format!("{what}.{key} must be a u32: {error}"))?
    } else {
        return Err(format!("{what}.{key} must be an unsigned integer"));
    };
    u32::try_from(number).map_err(|_| format!("{what}.{key} is out of range: {number}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn origin() -> Name {
        Name::parse("example.com.").unwrap()
    }

    #[test]
    fn parses_addresses_and_names() {
        assert_eq!(
            parse(Rtype::A, &json!("192.0.2.1"), &origin()).unwrap(),
            Rdata::A("192.0.2.1".parse().unwrap())
        );
        assert_eq!(
            parse(Rtype::CNAME, &json!("www"), &origin()).unwrap(),
            Rdata::Cname(Name::parse("www.example.com.").unwrap())
        );
    }

    #[test]
    fn parses_mx_and_txt() {
        let mx = parse(
            Rtype::MX,
            &json!({"preference": 10, "exchange": "mail"}),
            &origin(),
        )
        .unwrap();
        assert_eq!(
            mx,
            Rdata::Mx {
                preference: 10,
                exchange: Name::parse("mail.example.com.").unwrap()
            }
        );
        let txt = parse(Rtype::TXT, &json!(["one", "two"]), &origin()).unwrap();
        assert!(matches!(txt, Rdata::Txt(_)));
    }

    #[test]
    fn parses_soa_srv_caa() {
        let soa = parse(
            Rtype::SOA,
            &json!({
                "mname": "ns1", "rname": "hostmaster", "serial": 7,
                "refresh": 3600, "retry": 600, "expire": 604_800, "minimum": 300
            }),
            &origin(),
        )
        .unwrap();
        assert!(matches!(soa, Rdata::Soa(_)));

        let srv = parse(
            Rtype::SRV,
            &json!({"priority": 10, "weight": 5, "port": 5060, "target": "sip"}),
            &origin(),
        )
        .unwrap();
        assert_eq!(
            srv,
            Rdata::Srv {
                priority: 10,
                weight: 5,
                port: 5060,
                target: Name::parse("sip.example.com.").unwrap()
            }
        );

        let caa = parse(
            Rtype::CAA,
            &json!({"flags": 0, "tag": "issue", "value": "letsencrypt.org"}),
            &origin(),
        )
        .unwrap();
        assert!(matches!(caa, Rdata::Caa { .. }));
    }

    #[test]
    fn parses_dnssec_records() {
        let digest = "ab".repeat(32);
        let ds = parse(
            Rtype::DS,
            &json!({"key_tag": 12345, "algorithm": 8, "digest_type": 2, "digest": digest}),
            &origin(),
        )
        .unwrap();
        assert!(matches!(ds, Rdata::Ds(_)));

        let dnskey = parse(
            Rtype::DNSKEY,
            &json!({"flags": 257, "protocol": 3, "algorithm": 8, "public_key": "AQAB"}),
            &origin(),
        )
        .unwrap();
        assert!(matches!(dnskey, Rdata::Dnskey(_)));

        let rrsig = parse(
            Rtype::RRSIG,
            &json!({
                "type_covered": "A", "algorithm": 8, "labels": 3,
                "original_ttl": 3600, "signature_expiration": 1_800_000_000_u32,
                "signature_inception": 1_790_000_000_u32, "key_tag": 12345,
                "signer_name": "example.com.", "signature": "AQID"
            }),
            &origin(),
        )
        .unwrap();
        assert!(matches!(rrsig, Rdata::Rrsig(_)));

        let nsec = parse(
            Rtype::NSEC,
            &json!({"next_domain": "next", "types": ["A", "AAAA", "RRSIG"]}),
            &origin(),
        )
        .unwrap();
        assert!(matches!(nsec, Rdata::Nsec(_)));
    }

    #[test]
    fn parses_tlsa() {
        let tlsa = parse(
            Rtype::TLSA,
            &json!({
                "usage": 3, "selector": 1, "matching": 0,
                "certificate_association_data": "deadbeef"
            }),
            &origin(),
        )
        .unwrap();
        assert!(matches!(tlsa, Rdata::Tlsa(_)));
    }

    #[test]
    fn parses_unknown_rfc3597() {
        let rr_type = Rtype::from_u16(65_280);
        let rdata = parse(rr_type, &json!("\\# 4 deadbeef"), &origin()).unwrap();
        assert_eq!(
            rdata,
            Rdata::Unknown {
                rr_type,
                rdata: vec![0xde, 0xad, 0xbe, 0xef]
            }
        );
    }

    #[test]
    fn rejects_bad_hex() {
        let rr_type = Rtype::from_u16(65_280);
        assert!(parse(rr_type, &json!("hex:xyz"), &origin()).is_err());
    }

    #[test]
    fn rejects_unknown_known_type() {
        assert!(parse_type("TYPE1").is_err());
        assert!(parse_type("TYPE0").is_err());
        assert!(parse_type("NOPE").is_err());
    }
}
