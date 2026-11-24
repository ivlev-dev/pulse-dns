//! BIND-совместимые файлы ключей (`K*.private`, `K*.key`).
//!
//! Чтение `.private` поддерживается для алгоритмов 8, 13, 15; запись — в
//! том же формате. Публичный `.key` — обычная presentation-строка DNSKEY.
//! Секретный материал возвращается в [`SecretRef`].

use std::collections::BTreeMap;

use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, Ed25519KeyPair};
use base64::Engine as _;
use pulse_dns::{DnskeyData, Name, TTL_MAX};
use zeroize::{Zeroize, Zeroizing};

use crate::algorithm::Algorithm;
use crate::der;
use crate::error::KeyError;
use crate::key::PrivateKey;
use crate::secret::SecretRef;

/// Публичный ключ из `.key`-файла.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindDnskey {
    /// Владелец (зона).
    pub owner: Name,
    /// TTL из файла, если указан.
    pub ttl: Option<u32>,
    /// DNSKEY RDATA.
    pub dnskey: DnskeyData,
}

/// Разбирает текст `.private`-файла BIND и импортирует ключ.
///
/// # Errors
///
/// [`KeyError::BadBindPrivate`] при структурных проблемах,
/// [`KeyError::UnsupportedAlgorithm`] для неподдерживаемого алгоритма,
/// [`KeyError::KeyRejected`] при отклонении материала библиотекой.
pub fn parse_private_key(text: &str) -> Result<PrivateKey, KeyError> {
    let fields = parse_fields(text)?;
    let algorithm_value = fields
        .get("Algorithm")
        .ok_or(KeyError::MissingField { field: "Algorithm" })?;
    let algorithm = parse_algorithm_token(algorithm_value)?;
    if let Some(format) = fields.get("Private-key-format") {
        let version = std::str::from_utf8(format)
            .map_err(|_| KeyError::BadBindPrivate {
                reason: "non-UTF8 Private-key-format",
            })?
            .trim();
        if version != "v1.2" && version != "v1.3" {
            return Err(KeyError::BadBindPrivate {
                reason: "unsupported Private-key-format",
            });
        }
    }

    match algorithm.as_u8() {
        8 => import_rsa(&fields),
        13 => import_ecdsa(&fields),
        15 => import_ed25519(&fields),
        _ => Err(KeyError::UnsupportedAlgorithm { algorithm }),
    }
}

/// Сериализует ключ в BIND `.private` (обнуляется при выгрузке).
///
/// # Errors
///
/// [`KeyError::BindNotSupported`] для алгоритмов вне 8/13/15,
/// [`KeyError::Der`] при структурной ошибке PKCS#8.
pub fn format_private_key(key: &PrivateKey) -> Result<SecretRef, KeyError> {
    let algorithm = key.algorithm();
    let header = format!(
        "Private-key-format: v1.3\nAlgorithm: {} ({})\n",
        algorithm.as_u8(),
        algorithm.name()
    );
    let mut out = Zeroizing::new(header);
    match algorithm.as_u8() {
        8 => {
            let pkcs8 = key.pkcs8_der_zeroizing()?;
            let inner = der::parse_pkcs8_private_key_info(&pkcs8)?;
            let fields = der::parse_rsa_private_key(inner)?;
            let names = [
                "Modulus",
                "PublicExponent",
                "PrivateExponent",
                "Prime1",
                "Prime2",
                "Exponent1",
                "Exponent2",
                "Coefficient",
            ];
            for (name, value) in names.iter().zip(fields.iter()) {
                let encoded =
                    Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(value));
                out.push_str(name);
                out.push_str(": ");
                out.push_str(&encoded);
                out.push('\n');
            }
        }
        13 => {
            let pkcs8 = key.pkcs8_der_zeroizing()?;
            let inner = der::parse_pkcs8_private_key_info(&pkcs8)?;
            let scalar = parse_sec1_scalar(inner)?;
            let encoded = Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(scalar));
            out.push_str("PrivateKey: ");
            out.push_str(&encoded);
            out.push('\n');
        }
        15 => {
            let pkcs8 = key.pkcs8_der_zeroizing()?;
            let inner = der::parse_pkcs8_private_key_info(&pkcs8)?;
            let seed = parse_ed25519_seed(inner)?;
            let encoded = Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(seed));
            out.push_str("PrivateKey: ");
            out.push_str(&encoded);
            out.push('\n');
        }
        _ => {
            return Err(KeyError::BindNotSupported { algorithm });
        }
    }
    Ok(SecretRef::new(out.as_bytes().to_vec()))
}

/// Разбирает `.key`-файл (presentation-формат DNSKEY).
///
/// # Errors
///
/// [`KeyError::BadDnskeyFile`] при структурных проблемах,
/// [`KeyError::InvalidBase64`] для битого ключа.
pub fn parse_dnskey_file(text: &str) -> Result<BindDnskey, KeyError> {
    let mut tokens: Vec<&str> = Vec::new();
    for line in text.lines() {
        let line = line.split(';').next().unwrap_or("");
        for token in line.split_whitespace() {
            tokens.push(token);
        }
    }
    let position = tokens
        .iter()
        .position(|token| token.eq_ignore_ascii_case("DNSKEY"))
        .ok_or(KeyError::BadDnskeyFile {
            reason: "DNSKEY token not found",
        })?;
    let owner_text = tokens.first().ok_or(KeyError::BadDnskeyFile {
        reason: "empty file",
    })?;
    let owner = Name::parse(owner_text).map_err(|_| KeyError::BadDnskeyFile {
        reason: "invalid owner name",
    })?;

    let mut ttl: Option<u32> = None;
    for token in tokens.get(1..position).unwrap_or(&[]) {
        if let Ok(value) = token.parse::<u32>() {
            if value > TTL_MAX {
                return Err(KeyError::BadDnskeyFile {
                    reason: "TTL out of range",
                });
            }
            ttl = Some(value);
        }
    }

    let flags = parse_u16(tokens.get(position + 1), "DNSKEY flags")?;
    let protocol = parse_u8(tokens.get(position + 2), "DNSKEY protocol")?;
    let algorithm = parse_u8(tokens.get(position + 3), "DNSKEY algorithm")?;
    let key_text = tokens.get(position + 4).ok_or(KeyError::BadDnskeyFile {
        reason: "missing public key",
    })?;
    let cleaned: String = key_text.chars().filter(|c| !c.is_whitespace()).collect();
    let public_key = base64::engine::general_purpose::STANDARD
        .decode(cleaned)
        .map_err(|_| KeyError::InvalidBase64 {
            field: "DNSKEY public key",
        })?;
    let dnskey = DnskeyData::new(flags, protocol, algorithm, public_key).map_err(|_| {
        KeyError::BadDnskeyFile {
            reason: "invalid DNSKEY RDATA",
        }
    })?;
    Ok(BindDnskey { owner, ttl, dnskey })
}

/// Форматирует DNSKEY в presentation-строку `.key`-файла.
#[must_use]
pub fn format_dnskey_line(owner: &Name, ttl: u32, dnskey: &DnskeyData) -> String {
    let key = base64::engine::general_purpose::STANDARD.encode(dnskey.public_key());
    let owner = owner.to_string();
    format!(
        "{owner} {ttl} IN DNSKEY {} {} {} {key}\n",
        dnskey.flags(),
        dnskey.protocol(),
        dnskey.algorithm()
    )
}

fn parse_fields(text: &str) -> Result<PrivateFields, KeyError> {
    let mut fields = PrivateFields::default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        let name = name.trim().to_owned();
        let bytes = if is_base64_field(&name) {
            base64::engine::general_purpose::STANDARD
                .decode(value)
                .map_err(|_| KeyError::InvalidBase64 {
                    field: "private key component",
                })?
        } else {
            value.as_bytes().to_vec()
        };
        fields.map.insert(name, bytes);
    }
    Ok(fields)
}

fn is_base64_field(name: &str) -> bool {
    matches!(
        name,
        "Modulus"
            | "PublicExponent"
            | "PrivateExponent"
            | "Prime1"
            | "Prime2"
            | "Exponent1"
            | "Exponent2"
            | "Coefficient"
            | "PrivateKey"
    )
}

fn parse_algorithm_token(value: &[u8]) -> Result<Algorithm, KeyError> {
    let text = std::str::from_utf8(value).map_err(|_| KeyError::BadBindPrivate {
        reason: "non-UTF8 Algorithm field",
    })?;
    let number = text
        .split_whitespace()
        .next()
        .ok_or(KeyError::BadBindPrivate {
            reason: "empty Algorithm field",
        })?;
    let value = number.parse::<u8>().map_err(|_| KeyError::BadBindPrivate {
        reason: "non-numeric Algorithm field",
    })?;
    Ok(Algorithm::from_u8(value))
}

fn import_rsa(fields: &PrivateFields) -> Result<PrivateKey, KeyError> {
    let names = [
        "Modulus",
        "PublicExponent",
        "PrivateExponent",
        "Prime1",
        "Prime2",
        "Exponent1",
        "Exponent2",
        "Coefficient",
    ];
    let mut components: [&[u8]; 8] = [&[]; 8];
    for (slot, name) in components.iter_mut().zip(names.iter()) {
        *slot = fields
            .get(name)
            .map(Vec::as_slice)
            .ok_or(KeyError::MissingField {
                field: match *name {
                    "Modulus" => "Modulus",
                    "PublicExponent" => "PublicExponent",
                    "PrivateExponent" => "PrivateExponent",
                    "Prime1" => "Prime1",
                    "Prime2" => "Prime2",
                    "Exponent1" => "Exponent1",
                    "Exponent2" => "Exponent2",
                    _ => "Coefficient",
                },
            })?;
    }
    let der = der::encode_rsa_private_key(&components);
    PrivateKey::from_rsa_der(&der)
}

fn import_ecdsa(fields: &PrivateFields) -> Result<PrivateKey, KeyError> {
    let scalar = fields.get("PrivateKey").ok_or(KeyError::MissingField {
        field: "PrivateKey",
    })?;
    if scalar.len() != 32 {
        return Err(KeyError::BadBindPrivate {
            reason: "P-256 private key must be 32 bytes",
        });
    }
    let sec1 = der::encode_sec1_p256_private_key(scalar);
    EcdsaKeyPair::from_private_key_der(&ECDSA_P256_SHA256_FIXED_SIGNING, &sec1)
        .map(PrivateKey::EcdsaP256)
        .map_err(|error| KeyError::KeyRejected {
            reason: error.to_string(),
        })
}

fn import_ed25519(fields: &PrivateFields) -> Result<PrivateKey, KeyError> {
    let seed = fields.get("PrivateKey").ok_or(KeyError::MissingField {
        field: "PrivateKey",
    })?;
    if seed.len() != 32 {
        return Err(KeyError::BadBindPrivate {
            reason: "Ed25519 seed must be 32 bytes",
        });
    }
    Ed25519KeyPair::from_seed_unchecked(seed)
        .map(PrivateKey::Ed25519)
        .map_err(|error| KeyError::KeyRejected {
            reason: error.to_string(),
        })
}

fn parse_sec1_scalar(inner: &[u8]) -> Result<&[u8], KeyError> {
    let mut outer = der::DerReader::new(inner);
    let mut sequence = outer.sequence()?;
    sequence.expect_integer(1)?;
    let scalar = sequence.octet_string()?;
    if scalar.len() != 32 {
        return Err(KeyError::Der {
            reason: "P-256 scalar is not 32 bytes",
        });
    }
    Ok(scalar)
}

fn parse_ed25519_seed(inner: &[u8]) -> Result<&[u8], KeyError> {
    let mut outer = der::DerReader::new(inner);
    let seed = outer.octet_string()?;
    if seed.len() != 32 {
        return Err(KeyError::Der {
            reason: "Ed25519 seed is not 32 bytes",
        });
    }
    Ok(seed)
}

fn parse_u16(value: Option<&&str>, field: &'static str) -> Result<u16, KeyError> {
    let value = value.ok_or(KeyError::MissingField { field })?;
    value.parse::<u16>().map_err(|_| KeyError::BadDnskeyFile {
        reason: "invalid numeric field",
    })
}

fn parse_u8(value: Option<&&str>, field: &'static str) -> Result<u8, KeyError> {
    let value = value.ok_or(KeyError::MissingField { field })?;
    value.parse::<u8>().map_err(|_| KeyError::BadDnskeyFile {
        reason: "invalid numeric field",
    })
}

/// Промежуточные поля, обнуляемые при drop.
#[derive(Default)]
struct PrivateFields {
    map: BTreeMap<String, Vec<u8>>,
}

impl PrivateFields {
    fn get(&self, name: &str) -> Option<&Vec<u8>> {
        self.map.get(name)
    }
}

impl Drop for PrivateFields {
    fn drop(&mut self) {
        for value in self.map.values_mut() {
            value.zeroize();
        }
        self.map.clear();
    }
}
