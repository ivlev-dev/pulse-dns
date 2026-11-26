//! Сериализация RDATA в стабильную презентационную форму.
//!
//! Формат вывода детерминирован: имена абсолютные, hex — в верхнем регистре,
//! base64 — с padding, base32hex — без padding, character-string — в кавычках
//! с escape-последовательностями.

use std::fmt::Write as _;

use pulse_dns::{Name, Rdata, SvcParam, SvcbData};

use crate::codec::{encode_base32hex, encode_base64, encode_hex, format_rrsig_time};

/// Сериализует RDATA.
#[allow(clippy::too_many_lines)]
pub(crate) fn rdata_to_text(rdata: &Rdata) -> String {
    match rdata {
        Rdata::A(address) => address.to_string(),
        Rdata::Aaaa(address) => address.to_string(),
        Rdata::Ns(name) | Rdata::Cname(name) | Rdata::Dname(name) | Rdata::Ptr(name) => {
            name_to_text(name)
        }
        Rdata::Soa(soa) => format!(
            "{} {} {} {} {} {} {}",
            name_to_text(&soa.mname),
            name_to_text(&soa.rname),
            soa.serial,
            soa.refresh,
            soa.retry,
            soa.expire,
            soa.minimum
        ),
        Rdata::Mx {
            preference,
            exchange,
        } => format!("{preference} {}", name_to_text(exchange)),
        Rdata::Txt(txt) => txt
            .segments()
            .iter()
            .map(|segment| quote_bytes(segment))
            .collect::<Vec<_>>()
            .join(" "),
        Rdata::Srv {
            priority,
            weight,
            port,
            target,
        } => format!("{priority} {weight} {port} {}", name_to_text(target)),
        Rdata::Caa { flags, tag, value } => {
            format!("{flags} {tag} {}", quote_bytes(value))
        }
        Rdata::Ds(ds) => format!(
            "{} {} {} {}",
            ds.key_tag(),
            ds.algorithm(),
            ds.digest_type(),
            encode_hex(ds.digest())
        ),
        Rdata::Dnskey(key) => format!(
            "{} {} {} {}",
            key.flags(),
            key.protocol(),
            key.algorithm(),
            encode_base64(key.public_key())
        ),
        Rdata::Rrsig(sig) => format!(
            "{} {} {} {} {} {} {} {} {}",
            sig.type_covered(),
            sig.algorithm(),
            sig.labels(),
            sig.original_ttl(),
            format_rrsig_time(sig.signature_expiration()),
            format_rrsig_time(sig.signature_inception()),
            sig.key_tag(),
            name_to_text(sig.signer_name()),
            encode_base64(sig.signature())
        ),
        Rdata::Nsec(nsec) => {
            let mut out = name_to_text(nsec.next_domain());
            for rr_type in nsec.type_bitmap().types() {
                out.push(' ');
                out.push_str(&rr_type.to_string());
            }
            out
        }
        Rdata::Nsec3(nsec3) => {
            let salt = if nsec3.salt().is_empty() {
                "-".to_owned()
            } else {
                encode_hex(nsec3.salt())
            };
            let mut out = format!(
                "{} {} {} {} {}",
                nsec3.hash_algorithm(),
                nsec3.flags(),
                nsec3.iterations(),
                salt,
                encode_base32hex(nsec3.next_hashed_owner())
            );
            for rr_type in nsec3.type_bitmap().types() {
                out.push(' ');
                out.push_str(&rr_type.to_string());
            }
            out
        }
        Rdata::Nsec3Param(param) => {
            let salt = if param.salt().is_empty() {
                "-".to_owned()
            } else {
                encode_hex(param.salt())
            };
            format!(
                "{} {} {} {}",
                param.hash_algorithm(),
                param.flags(),
                param.iterations(),
                salt
            )
        }
        Rdata::Tlsa(tlsa) => format!(
            "{} {} {} {}",
            tlsa.usage(),
            tlsa.selector(),
            tlsa.matching(),
            encode_hex(tlsa.certificate_association_data())
        ),
        Rdata::Svcb(data) | Rdata::Https(data) => svcb_to_text(data),
        Rdata::Unknown { rdata, .. } => {
            if rdata.is_empty() {
                "\\# 0".to_owned()
            } else {
                format!("\\# {} {}", rdata.len(), encode_hex(rdata))
            }
        }
        Rdata::Empty(_) => "\\# 0".to_owned(),
    }
}

fn svcb_to_text(data: &SvcbData) -> String {
    let mut out = format!("{} {}", data.priority(), name_to_text(data.target()));
    for param in data.params() {
        out.push(' ');
        out.push_str(&svc_param_to_text(param));
    }
    out
}

fn svc_param_to_text(param: &SvcParam) -> String {
    let key = param.key();
    let value = param.value();
    let name = svc_key_name(key);
    match key {
        SvcParam::KEY_MANDATORY => {
            let mut keys = Vec::new();
            for pair in value.as_chunks::<2>().0 {
                keys.push(svc_key_name(u16::from_be_bytes(*pair)));
            }
            format!("{name}={}", keys.join(","))
        }
        SvcParam::KEY_ALPN => {
            let mut protocols = Vec::new();
            let mut position = 0_usize;
            while let Some(&length) = value.get(position) {
                let start = position.saturating_add(1);
                let end = start.saturating_add(usize::from(length));
                let Some(protocol) = value.get(start..end) else {
                    break;
                };
                protocols.push(escape_svcb_component(protocol));
                position = end;
            }
            format!("{name}=\"{}\"", protocols.join(","))
        }
        2 => name,
        SvcParam::KEY_PORT => {
            let port = value
                .as_chunks::<2>()
                .0
                .first()
                .map_or(0, |pair| u16::from_be_bytes(*pair));
            format!("{name}={port}")
        }
        SvcParam::KEY_IPV4HINT => {
            let mut addresses = Vec::new();
            for octets in value.as_chunks::<4>().0 {
                addresses.push(std::net::Ipv4Addr::from(*octets).to_string());
            }
            format!("{name}={}", addresses.join(","))
        }
        SvcParam::KEY_ECH => format!("{name}={}", encode_base64(value)),
        SvcParam::KEY_IPV6HINT => {
            let mut addresses = Vec::new();
            for octets in value.as_chunks::<16>().0 {
                addresses.push(std::net::Ipv6Addr::from(*octets).to_string());
            }
            format!("{name}={}", addresses.join(","))
        }
        _ => {
            if value.is_empty() {
                name
            } else {
                format!("{name}=\"{}\"", escape_svcb_component(value))
            }
        }
    }
}

fn svc_key_name(key: u16) -> String {
    match key {
        SvcParam::KEY_MANDATORY => "mandatory".to_owned(),
        SvcParam::KEY_ALPN => "alpn".to_owned(),
        2 => "no-default-alpn".to_owned(),
        SvcParam::KEY_PORT => "port".to_owned(),
        SvcParam::KEY_IPV4HINT => "ipv4hint".to_owned(),
        SvcParam::KEY_ECH => "ech".to_owned(),
        SvcParam::KEY_IPV6HINT => "ipv6hint".to_owned(),
        other => format!("key{other}"),
    }
}

fn escape_svcb_component(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &byte in bytes {
        match byte {
            b',' | b'"' | b'\\' => {
                out.push('\\');
                out.push(char::from(byte));
            }
            0x20..=0x7E => out.push(char::from(byte)),
            _ => {
                let _ = write!(out, "\\{byte:03}");
            }
        }
    }
    out
}

/// Форматирует имя для master-файла.
///
/// В отличие от [`Name`]'s `Display`, экранирует символы, специальные для
/// лексера zone-файла (`"`, `;`, `(`, `)`, `$`), чтобы вывод гарантированно
/// разбирался обратно тем же лексером. Имя всегда абсолютное.
pub(crate) fn name_to_text(name: &Name) -> String {
    if name.labels().next().is_none() {
        return ".".to_owned();
    }
    let mut out = String::with_capacity(name.wire_len() + 2);
    for label in name.labels() {
        for &byte in label {
            match byte {
                b'.' | b'\\' | b'"' | b';' | b'(' | b')' | b'$' => {
                    out.push('\\');
                    out.push(char::from(byte));
                }
                0x21..=0x7E => out.push(char::from(byte)),
                _ => {
                    let _ = write!(out, "\\{byte:03}");
                }
            }
        }
        out.push('.');
    }
    out
}

/// Заключает байты в кавычки с escape-последовательностями master-файла.
pub(crate) fn quote_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() + 2);
    out.push('"');
    for &byte in bytes {
        match byte {
            b'"' | b'\\' => {
                out.push('\\');
                out.push(char::from(byte));
            }
            0x20..=0x7E => out.push(char::from(byte)),
            _ => {
                let _ = write!(out, "\\{byte:03}");
            }
        }
    }
    out.push('"');
    out
}
