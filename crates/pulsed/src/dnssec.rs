//! Загрузка ключей DNSSEC из конфигурации `pulsed`.
//!
//! Поддерживаются BIND-совместимые пары `K*.key`/`K*.private` (парсинг —
//! `pulse-dnssec::bind`/`keyfile`) и PKCS#8 PEM/DER. Приватные файлы обязаны
//! быть недоступны группе/остальным (режим `0600`); пути с более широкими
//! правами отвергаются. Материал ключа не логируется и не попадает в `Debug`.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use pulse_dns::Name;
use pulse_dnssec::{Algorithm, KeyError, KeyFileError, PrivateKey, bind};
use pulse_server::dnssec::{
    DenialPolicy, KeyRole, Nsec3Config, Nsec3ConfigError, SignZoneError, SignedZone, ZoneSigner,
    ZoneSignerError, ZoneSigningKey,
};
use thiserror::Error;

use crate::config::{Config, DnssecDenial, DnssecKeyConfig, DnssecKeyRole};

/// Подписант зоны вместе с denial-политикой из конфигурации.
struct ConfiguredZone {
    signer: ZoneSigner,
    denial: DenialPolicy,
}

/// Подписанты зон, загруженные при старте.
pub(crate) struct DnssecSigners {
    zones: HashMap<Name, ConfiguredZone>,
}

impl DnssecSigners {
    /// Подписант зоны, если она настроена на DNSSEC.
    pub(crate) fn signer(&self, origin: &Name) -> Option<&ZoneSigner> {
        self.zones.get(origin).map(|zone| &zone.signer)
    }

    /// Подписывает зону с настроенной denial-политикой.
    pub(crate) fn sign(
        &self,
        origin: &Name,
        rrsets: &[pulse_dns::Rrset],
        now: u32,
    ) -> Result<SignedZone, SignZoneError> {
        let zone = self
            .zones
            .get(origin)
            .ok_or_else(|| SignZoneError::NoKeys {
                zone: origin.clone(),
            })?;
        zone.signer
            .sign_zone_with(origin, rrsets, now, &zone.denial)
    }

    /// Настроенные origin'ы.
    pub(crate) fn origins(&self) -> impl Iterator<Item = &Name> {
        self.zones.keys()
    }
}

fn denial_policy(
    origin: &Name,
    zone_config: &crate::config::DnssecZoneConfig,
) -> Result<DenialPolicy, DnssecError> {
    match zone_config.denial.unwrap_or_default() {
        DnssecDenial::Nsec => Ok(DenialPolicy::Nsec),
        DnssecDenial::Nsec3 => {
            let salt = match &zone_config.nsec3_salt {
                Some(text) => {
                    hex::decode(text.trim()).map_err(|error| DnssecError::InvalidSalt {
                        zone: origin.to_string(),
                        reason: format!("not valid hex: {error}"),
                    })?
                }
                None => pulse_dnssec::denial::random_salt(8).map_err(|error| {
                    DnssecError::InvalidSalt {
                        zone: origin.to_string(),
                        reason: error.to_string(),
                    }
                })?,
            };
            let iterations = zone_config.nsec3_iterations.unwrap_or(0);
            let config =
                Nsec3Config::new(salt, iterations).map_err(|error| DnssecError::InvalidNsec3 {
                    zone: origin.to_string(),
                    source: error,
                })?;
            Ok(DenialPolicy::Nsec3(config))
        }
    }
}

/// Текущее время UNIX в секундах (насыщается на `u32`).
pub(crate) fn now_unix() -> u32 {
    let Ok(duration) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return 0;
    };
    u32::try_from(duration.as_secs()).unwrap_or(u32::MAX)
}

/// Загружает ключи всех зон из секции `dnssec`.
///
/// # Errors
///
/// [`DnssecError`] при некорректном origin, правах файла, разборе ключа или
/// пустом наборе ключей.
pub(crate) fn load(config: &Config) -> Result<DnssecSigners, DnssecError> {
    let mut zones: HashMap<Name, ConfiguredZone> = HashMap::with_capacity(config.dnssec.len());
    for (origin_text, zone_config) in &config.dnssec {
        let origin =
            Name::parse(origin_text.trim()).map_err(|source| DnssecError::InvalidOrigin {
                origin: origin_text.clone(),
                source,
            })?;
        if origin == Name::root() || origin.labels().any(|label| label == b"*") {
            return Err(DnssecError::BadOrigin {
                origin: origin_text.clone(),
            });
        }
        if zones.contains_key(&origin) {
            return Err(DnssecError::DuplicateZone {
                origin: origin.to_string(),
            });
        }
        if zone_config.keys.is_empty() {
            return Err(DnssecError::NoKeys {
                zone: origin.to_string(),
            });
        }
        let mut keys = Vec::with_capacity(zone_config.keys.len());
        for key_config in &zone_config.keys {
            keys.push(load_key(&origin, key_config)?);
        }
        let validity_days = zone_config.validity_days.unwrap_or(30);
        let validity = validity_days
            .checked_mul(86_400)
            .ok_or(DnssecError::InvalidValidity {
                zone: origin.to_string(),
                days: validity_days,
            })?;
        let signer = ZoneSigner::new(keys, validity, zone_config.inception_skew.unwrap_or(300))
            .map_err(|source| DnssecError::Signer {
                zone: origin.to_string(),
                source,
            })?;
        let denial = denial_policy(&origin, zone_config)?;
        zones.insert(origin, ConfiguredZone { signer, denial });
    }
    Ok(DnssecSigners { zones })
}

fn load_key(zone: &Name, config: &DnssecKeyConfig) -> Result<ZoneSigningKey, DnssecError> {
    let path = &config.path;
    let bytes = fs::read(path).map_err(|source| DnssecError::KeyRead {
        path: path.clone(),
        source,
    })?;

    let (private, private_path, sibling_flags) = if looks_like_pem(&bytes) {
        (
            parse_pkcs8_pem(&bytes, config.algorithm, path)?,
            path.clone(),
            sibling_flags(path),
        )
    } else if bytes.first() == Some(&0x30) && config.algorithm.is_some() {
        (
            parse_pkcs8_der(&bytes, config.algorithm, path)?,
            path.clone(),
            sibling_flags(path),
        )
    } else if is_bind_public_key(&bytes, path) {
        let flags = parse_public_flags(&bytes, path)?;
        let private_path = path.with_extension("private");
        if !private_path.exists() {
            return Err(DnssecError::MissingPrivateKey {
                zone: zone.to_string(),
                path: private_path,
            });
        }
        let private = read_bind_private(&private_path)?;
        (private, private_path, Some(flags))
    } else {
        let private = read_bind_private(path)?;
        (private, path.clone(), sibling_flags(path))
    };

    if let Some(expected) = config.algorithm {
        let expected = Algorithm::from_u8(expected);
        if private.algorithm() != expected {
            return Err(DnssecError::AlgorithmMismatch {
                path: private_path,
                expected,
                actual: private.algorithm(),
            });
        }
    }

    check_private_permissions(&private_path)?;

    let role = match (config.role, sibling_flags) {
        (Some(role), _) => map_role(role),
        (None, Some(flags)) => role_from_flags(flags),
        (None, None) => KeyRole::Csk,
    };
    let flags = config.flags.unwrap_or_else(|| role.flags());
    ZoneSigningKey::with_flags(private, role, flags).map_err(|source| DnssecError::Signer {
        zone: zone.to_string(),
        source,
    })
}

fn map_role(role: DnssecKeyRole) -> KeyRole {
    match role {
        DnssecKeyRole::Ksk => KeyRole::Ksk,
        DnssecKeyRole::Zsk => KeyRole::Zsk,
        DnssecKeyRole::Csk => KeyRole::Csk,
    }
}

fn role_from_flags(flags: u16) -> KeyRole {
    if flags & pulse_dnssec::DNSKEY_FLAG_SEP != 0 {
        KeyRole::Ksk
    } else {
        KeyRole::Zsk
    }
}

fn looks_like_pem(bytes: &[u8]) -> bool {
    bytes.starts_with(b"-----BEGIN")
}

fn is_bind_public_key(bytes: &[u8], path: &Path) -> bool {
    if path.extension().and_then(std::ffi::OsStr::to_str) != Some("key") {
        return false;
    }
    std::str::from_utf8(bytes).is_ok_and(|text| text.contains("DNSKEY"))
}

fn parse_public_flags(bytes: &[u8], path: &Path) -> Result<u16, DnssecError> {
    let text = std::str::from_utf8(bytes).map_err(|_| DnssecError::KeyRead {
        path: path.to_path_buf(),
        source: io::Error::new(io::ErrorKind::InvalidData, "public key file is not UTF-8"),
    })?;
    let dnskey = bind::parse_dnskey_file(text).map_err(|source| DnssecError::Key {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(dnskey.dnskey.flags())
}

fn sibling_flags(private_path: &Path) -> Option<u16> {
    let public_path = private_path.with_extension("key");
    let text = fs::read_to_string(public_path).ok()?;
    bind::parse_dnskey_file(&text)
        .ok()
        .map(|dnskey| dnskey.dnskey.flags())
}

fn read_bind_private(path: &Path) -> Result<PrivateKey, DnssecError> {
    pulse_dnssec::keyfile::read_private_key_file(path).map_err(|source| DnssecError::KeyFile {
        path: path.to_path_buf(),
        source,
    })
}

fn parse_pkcs8_pem(
    bytes: &[u8],
    algorithm: Option<u8>,
    path: &Path,
) -> Result<PrivateKey, DnssecError> {
    let text = std::str::from_utf8(bytes).map_err(|_| DnssecError::KeyRead {
        path: path.to_path_buf(),
        source: io::Error::new(io::ErrorKind::InvalidData, "PEM key is not UTF-8"),
    })?;
    if let Some(algorithm) = algorithm {
        return PrivateKey::from_pkcs8_pem(Algorithm::from_u8(algorithm), text).map_err(|source| {
            DnssecError::Key {
                path: path.to_path_buf(),
                source,
            }
        });
    }
    try_algorithms(|algorithm| PrivateKey::from_pkcs8_pem(algorithm, text)).map_err(|source| {
        DnssecError::Key {
            path: path.to_path_buf(),
            source,
        }
    })
}

fn parse_pkcs8_der(
    bytes: &[u8],
    algorithm: Option<u8>,
    path: &Path,
) -> Result<PrivateKey, DnssecError> {
    if let Some(algorithm) = algorithm {
        return PrivateKey::from_pkcs8_der(Algorithm::from_u8(algorithm), bytes).map_err(
            |source| DnssecError::Key {
                path: path.to_path_buf(),
                source,
            },
        );
    }
    try_algorithms(|algorithm| PrivateKey::from_pkcs8_der(algorithm, bytes)).map_err(|source| {
        DnssecError::Key {
            path: path.to_path_buf(),
            source,
        }
    })
}

/// Пробует алгоритмы подписи в порядке предпочтения. PKCS#8 не содержит
/// DNSKEY-номера, поэтому для файла без явного `algorithm` нужен перебор.
fn try_algorithms(
    mut parse: impl FnMut(Algorithm) -> Result<PrivateKey, KeyError>,
) -> Result<PrivateKey, KeyError> {
    let mut last_error = None;
    for algorithm in [
        Algorithm::ECDSAP256SHA256,
        Algorithm::ED25519,
        Algorithm::RSASHA256,
    ] {
        match parse(algorithm) {
            Ok(key) => return Ok(key),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or(KeyError::UnsupportedAlgorithm {
        algorithm: Algorithm::ECDSAP256SHA256,
    }))
}

fn check_private_permissions(path: &Path) -> Result<(), DnssecError> {
    let metadata = fs::metadata(path).map_err(|source| DnssecError::KeyRead {
        path: path.to_path_buf(),
        source,
    })?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(DnssecError::InsecurePermissions {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

/// Ошибка загрузки DNSSEC-ключей/конфигурации.
#[derive(Debug, Error)]
pub enum DnssecError {
    /// Некорректный origin.
    #[error("invalid DNSSEC origin {origin:?}: {source}")]
    InvalidOrigin {
        /// Строка из конфигурации.
        origin: String,
        /// Причина.
        #[source]
        source: pulse_dns::NameError,
    },
    /// Origin — root или содержит wildcard.
    #[error("DNSSEC origin {origin:?} must be a non-root name without wildcards")]
    BadOrigin {
        /// Строка из конфигурации.
        origin: String,
    },
    /// Один origin объявлен дважды в разных формах (`example.com` и
    /// `example.com.`).
    #[error("zone {origin} has duplicate DNSSEC configuration entries")]
    DuplicateZone {
        /// Канонический origin.
        origin: String,
    },
    /// Нет ключей для зоны.
    #[error("zone {zone}: at least one DNSSEC key is required")]
    NoKeys {
        /// Origin зоны.
        zone: String,
    },
    /// Слишком большой срок действия.
    #[error("zone {zone}: validity_days {days} exceeds the supported range")]
    InvalidValidity {
        /// Origin зоны.
        zone: String,
        /// Запрошенное число дней.
        days: u32,
    },
    /// Ошибка чтения файла.
    #[error("cannot read key file {path}: {source}")]
    KeyRead {
        /// Путь.
        path: PathBuf,
        /// Причина.
        #[source]
        source: io::Error,
    },
    /// У приватного файла слишком широкие права.
    #[error("private key {path} has insecure mode {mode:o}; expected 0600 or stricter")]
    InsecurePermissions {
        /// Путь.
        path: PathBuf,
        /// Фактический режим.
        mode: u32,
    },
    /// Ошибка разбора файла ключа.
    #[error("key file {path}: {source}")]
    KeyFile {
        /// Путь.
        path: PathBuf,
        /// Причина.
        #[source]
        source: KeyFileError,
    },
    /// Ошибка разбора/валидации ключа.
    #[error("key file {path}: {source}")]
    Key {
        /// Путь.
        path: PathBuf,
        /// Причина.
        #[source]
        source: KeyError,
    },
    /// Алгоритм из конфигурации не совпал с ключом.
    #[error("key file {path}: expected algorithm {expected}, got {actual}")]
    AlgorithmMismatch {
        /// Путь.
        path: PathBuf,
        /// Ожидаемый алгоритм.
        expected: Algorithm,
        /// Фактический алгоритм.
        actual: Algorithm,
    },
    /// Для `.key`-файла не найден парный `.private`.
    #[error("zone {zone}: private key {path} not found")]
    MissingPrivateKey {
        /// Origin зоны.
        zone: String,
        /// Ожидаемый путь.
        path: PathBuf,
    },
    /// Ошибка построения подписанта.
    #[error("zone {zone}: {source}")]
    Signer {
        /// Origin зоны.
        zone: String,
        /// Причина.
        #[source]
        source: ZoneSignerError,
    },
    /// Некорректная соль NSEC3.
    #[error("zone {zone}: invalid nsec3_salt: {reason}")]
    InvalidSalt {
        /// Origin зоны.
        zone: String,
        /// Причина.
        reason: String,
    },
    /// Некорректные параметры NSEC3.
    #[error("zone {zone}: invalid NSEC3 configuration: {source}")]
    InvalidNsec3 {
        /// Origin зоны.
        zone: String,
        /// Причина.
        #[source]
        source: Nsec3ConfigError,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DnssecZoneConfig;

    fn origin() -> Name {
        Name::parse("example.com.").expect("origin")
    }

    #[test]
    fn nsec3_without_salt_generates_random_salt() {
        let zone = DnssecZoneConfig {
            denial: Some(DnssecDenial::Nsec3),
            ..DnssecZoneConfig::default()
        };
        let DenialPolicy::Nsec3(config) = denial_policy(&origin(), &zone).expect("policy") else {
            panic!("expected NSEC3 policy");
        };
        assert_eq!(config.salt().len(), 8);
        assert_eq!(config.iterations(), 0);
    }

    #[test]
    fn nsec3_hex_salt_and_iterations_are_applied() {
        let zone = DnssecZoneConfig {
            denial: Some(DnssecDenial::Nsec3),
            nsec3_salt: Some("AAbb".to_owned()),
            nsec3_iterations: Some(7),
            ..DnssecZoneConfig::default()
        };
        let DenialPolicy::Nsec3(config) = denial_policy(&origin(), &zone).expect("policy") else {
            panic!("expected NSEC3 policy");
        };
        assert_eq!(config.salt(), &[0xAA, 0xBB]);
        assert_eq!(config.iterations(), 7);
    }

    #[test]
    fn nsec_denial_has_no_nsec3_parameters() {
        let zone = DnssecZoneConfig::default();
        assert_eq!(
            denial_policy(&origin(), &zone).expect("policy"),
            DenialPolicy::Nsec
        );
    }
}
