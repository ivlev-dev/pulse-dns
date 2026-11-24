//! JSON-конфигурация сервера и CLI-overrides.
//!
//! Конфигурация намеренно плоская: адреса транспортов, число UDP worker'ов,
//! уровень логирования, параметры TCP, persistence (`zonefile`/`durability`/
//! `map_size`) и список зон. Все записи зоны описаны в [`ZoneConfig`];
//! RDATA разбирается по типу в [`crate::zone`].
//!
//! # Пример
//!
//! ```
//! use pulsed::config::Config;
//!
//! let config = Config::from_json_str(r#"{
//!   "listen_udp": "127.0.0.1:0",
//!   "listen_tcp": "127.0.0.1:0",
//!   "zones": []
//! }"#).unwrap();
//! assert!(config.listen_udp.is_some());
//! ```

use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use pulse_dns::Name;
use pulse_transfer::TsigAlgorithm;
use pulse_zonefile::SyncMode;
use serde::Deserialize;
use thiserror::Error;

/// Размер map по умолчанию: 4 GiB (sparse-файл; страницы занимаются по мере
/// записи).
pub const DEFAULT_MAP_SIZE: u64 = 4 * 1024 * 1024 * 1024;

/// Уровень логирования.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// Только ошибки.
    Error,
    /// Ошибки и предупреждения.
    Warn,
    /// Штатные события (по умолчанию).
    #[default]
    Info,
    /// Диагностика обработки запросов.
    Debug,
    /// Подробная диагностика.
    Trace,
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        })
    }
}

impl FromStr for LogLevel {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "error" => Ok(Self::Error),
            "warn" | "warning" => Ok(Self::Warn),
            "info" => Ok(Self::Info),
            "debug" => Ok(Self::Debug),
            "trace" => Ok(Self::Trace),
            other => Err(format!(
                "unknown log level {other:?}; expected error, warn, info, debug or trace"
            )),
        }
    }
}

/// Режим durability записи в zonefile.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Durability {
    /// Данные и meta синхронизируются.
    Sync,
    /// Данные синхронизируются, meta — нет (по умолчанию).
    #[default]
    Flush,
    /// Без fsync (экспериментальный режим).
    Memory,
}

impl Durability {
    /// Режим `pulse-zonefile`.
    #[must_use]
    pub const fn sync_mode(self) -> SyncMode {
        match self {
            Self::Sync => SyncMode::Sync,
            Self::Flush => SyncMode::MetaNoSync,
            Self::Memory => SyncMode::NoSync,
        }
    }
}

impl fmt::Display for Durability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Sync => "sync",
            Self::Flush => "flush",
            Self::Memory => "memory",
        })
    }
}

impl FromStr for Durability {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "sync" => Ok(Self::Sync),
            "flush" => Ok(Self::Flush),
            "memory" => Ok(Self::Memory),
            other => Err(format!(
                "unknown durability {other:?}; expected sync, flush or memory"
            )),
        }
    }
}

/// Параметры TCP-транспорта.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TcpConfig {
    /// Максимальное число одновременных соединений.
    pub max_connections: usize,
    /// Таймаут простоя соединения в миллисекундах (между сообщениями).
    pub idle_timeout_ms: u64,
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            max_connections: 1024,
            idle_timeout_ms: 5000,
        }
    }
}

impl TcpConfig {
    /// Таймаут простоя как [`std::time::Duration`].
    #[must_use]
    pub const fn idle_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.idle_timeout_ms)
    }
}

/// TSIG-ключ для AXFR/IXFR/NOTIFY.
///
/// `secret` — base64 (как в BIND `key`-файле). Секрет не печатается в
/// `Debug` и не логируется.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TsigKeyConfig {
    /// Имя ключа (абсолютное или относительное DNS-имя).
    pub name: String,
    /// Алгоритм: `hmac-sha1`, `hmac-sha224`, `hmac-sha256`, `hmac-sha384`,
    /// `hmac-sha512` (по умолчанию `hmac-sha256`).
    #[serde(default = "default_tsig_algorithm")]
    pub algorithm: String,
    /// Base64-секрет.
    pub secret: String,
}

impl fmt::Debug for TsigKeyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TsigKeyConfig")
            .field("name", &self.name)
            .field("algorithm", &self.algorithm)
            .field("secret", &"***")
            .finish()
    }
}

fn default_tsig_algorithm() -> String {
    TsigAlgorithm::DEFAULT.name().to_owned()
}

/// Настройки входящих AXFR/IXFR и исходящих NOTIFY.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TransferSettings {
    /// Обслуживать AXFR/IXFR по TCP.
    pub enabled: bool,
    /// Требовать TSIG для трансферов и входящих NOTIFY.
    pub require_tsig: bool,
    /// IP-ACL для transfer/NOTIFY-in; пусто — любые источники.
    pub allow_from: Vec<IpAddr>,
    /// Разрешённые для transfer зоны; пусто — все загруженные зоны.
    pub allow_zones: Vec<String>,
    /// Сколько последних IXFR-дельт хранить в памяти.
    pub history_deltas: usize,
    /// Целевой размер сообщения AXFR/IXFR.
    pub message_bytes: usize,
    /// Максимум записей в одном трансфере.
    pub max_records: usize,
    /// Максимум байтов в одном трансфере.
    pub max_bytes: u64,
    /// Максимум сообщений в одном трансфере.
    pub max_messages: usize,
    /// Таймаут трансфера между операциями.
    pub timeout_ms: u64,
    /// Подписывать каждое N-е сообщение TSIG.
    pub tsig_every: usize,
    /// Разрешать IXFR fallback на AXFR.
    pub allow_axfr_fallback: bool,
    /// Адреса NOTIFY-out (UDP).
    pub notify: Vec<SocketAddr>,
    /// TSIG-ключ для NOTIFY-out (имя из `tsig_keys`).
    pub notify_tsig_key: Option<String>,
    /// Число повторов NOTIFY-out при ошибке отправки.
    pub notify_retries: u32,
    /// Таймаут одного NOTIFY-out в миллисекундах.
    pub notify_timeout_ms: u64,
    /// Ёмкость фоновой очереди NOTIFY-out.
    pub notify_queue: usize,
}

impl Default for TransferSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            require_tsig: true,
            allow_from: Vec::new(),
            allow_zones: Vec::new(),
            history_deltas: 32,
            message_bytes: 16 * 1024,
            max_records: 1_000_000,
            max_bytes: 64 * 1024 * 1024,
            max_messages: 100_000,
            timeout_ms: 30_000,
            tsig_every: 1,
            allow_axfr_fallback: true,
            notify: Vec::new(),
            notify_tsig_key: None,
            notify_retries: 3,
            notify_timeout_ms: 2_000,
            notify_queue: 1_024,
        }
    }
}

impl TransferSettings {
    /// Проверяет числовые ограничения transfer/NOTIFY.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] при выходе параметров за допустимые пределы.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !(1..=10_000).contains(&self.history_deltas) {
            return Err(ConfigError::Invalid(format!(
                "transfer.history_deltas must be in 1..=10000, got {}",
                self.history_deltas
            )));
        }
        if self.message_bytes < 256 {
            return Err(ConfigError::Invalid(format!(
                "transfer.message_bytes must be at least 256, got {}",
                self.message_bytes
            )));
        }
        if !(1..=100).contains(&self.tsig_every) {
            return Err(ConfigError::Invalid(format!(
                "transfer.tsig_every must be in 1..=100, got {}",
                self.tsig_every
            )));
        }
        if !(100..=600_000).contains(&self.timeout_ms) {
            return Err(ConfigError::Invalid(format!(
                "transfer.timeout_ms must be in 100..=600000, got {}",
                self.timeout_ms
            )));
        }
        if self.max_records == 0 || self.max_bytes == 0 || self.max_messages == 0 {
            return Err(ConfigError::Invalid(
                "transfer limits must be non-zero".to_owned(),
            ));
        }
        if self.notify_retries > 10 {
            return Err(ConfigError::Invalid(format!(
                "transfer.notify_retries must be in 0..=10, got {}",
                self.notify_retries
            )));
        }
        if !(1..=65_536).contains(&self.notify_queue) {
            return Err(ConfigError::Invalid(format!(
                "transfer.notify_queue must be in 1..=65536, got {}",
                self.notify_queue
            )));
        }
        if !(100..=600_000).contains(&self.notify_timeout_ms) {
            return Err(ConfigError::Invalid(format!(
                "transfer.notify_timeout_ms must be in 100..=600000, got {}",
                self.notify_timeout_ms
            )));
        }
        Ok(())
    }
}

/// Разбирает строку алгоритма TSIG.
///
/// # Errors
///
/// [`ConfigError::Invalid`] для неизвестного алгоритма.
pub fn parse_tsig_algorithm(value: &str) -> Result<TsigAlgorithm, ConfigError> {
    let normalized = value.trim().to_ascii_lowercase();
    let algorithm = match normalized.as_str() {
        "hmac-sha1" | "sha1" => TsigAlgorithm::HmacSha1,
        "hmac-sha224" | "sha224" => TsigAlgorithm::HmacSha224,
        "hmac-sha256" | "sha256" => TsigAlgorithm::HmacSha256,
        "hmac-sha384" | "sha384" => TsigAlgorithm::HmacSha384,
        "hmac-sha512" | "sha512" => TsigAlgorithm::HmacSha512,
        other => {
            return Err(ConfigError::Invalid(format!(
                "unknown TSIG algorithm {other:?}; expected hmac-sha1, hmac-sha224, hmac-sha256, hmac-sha384 or hmac-sha512"
            )));
        }
    };
    Ok(algorithm)
}

/// Запись зоны в конфигурации.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordConfig {
    /// Владелец: `@` (apex), относительное имя или абсолютное (с точкой).
    pub name: String,
    /// Тип записи: `A`, `AAAA`, `MX`, …, `TYPE65280`.
    #[serde(rename = "type")]
    pub rr_type: String,
    /// TTL; при отсутствии используется `default_ttl` зоны.
    #[serde(default)]
    pub ttl: Option<u32>,
    /// RDATA в JSON-форме, зависящей от типа.
    pub rdata: serde_json::Value,
}

/// Master-файл зоны (RFC 1035) в конфигурации.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZoneFileConfig {
    /// Origin зоны; он же передаётся в `pulse_master::parse_zone`.
    pub origin: String,
    /// Путь к master-файлу. Относительные пути считаются от текущего каталога.
    pub path: PathBuf,
}

/// Роль DNSSEC-ключа в конфигурации.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DnssecKeyRole {
    /// Key Signing Key (подписывает DNSKEY).
    Ksk,
    /// Zone Signing Key (подписывает данные).
    Zsk,
    /// Combined Signing Key (подписывает всё).
    Csk,
}

impl DnssecKeyRole {
    /// Разбирает имя роли без учёта регистра.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "ksk" => Some(Self::Ksk),
            "zsk" => Some(Self::Zsk),
            "csk" => Some(Self::Csk),
            _ => None,
        }
    }
}

/// Ключ подписи зоны.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnssecKeyConfig {
    /// Роль ключа. При отсутствии выводится из sibling `.key` (SEP-бит) или
    /// считается CSK для одиночного ключа.
    #[serde(default)]
    pub role: Option<DnssecKeyRole>,
    /// Путь к BIND `.private` (или парному `.key`), либо PKCS#8 PEM/DER.
    pub path: PathBuf,
    /// Алгоритм для PKCS#8 (обязателен, если роль/файл не задают его).
    #[serde(default)]
    pub algorithm: Option<u8>,
    /// Явные DNSKEY flags (переопределяют роль).
    #[serde(default)]
    pub flags: Option<u16>,
}

/// DNSSEC-настройки зоны.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnssecZoneConfig {
    /// Ключи подписи (непустой набор).
    #[serde(default)]
    pub keys: Vec<DnssecKeyConfig>,
    /// Срок действия подписи в днях (по умолчанию 30).
    #[serde(default)]
    pub validity_days: Option<u32>,
    /// Запас на расхождение часов в секундах (по умолчанию 300).
    #[serde(default)]
    pub inception_skew: Option<u32>,
}

/// Зона в конфигурации.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZoneConfig {
    /// Origin зоны (абсолютное или относительное имя).
    pub origin: String,
    /// Класс; в v1 поддерживается только `IN`.
    #[serde(default = "default_class")]
    pub class: String,
    /// TTL по умолчанию для записей без явного `ttl`.
    #[serde(default = "default_ttl")]
    pub default_ttl: u32,
    /// Записи зоны.
    #[serde(default)]
    pub records: Vec<RecordConfig>,
}

fn default_class() -> String {
    "IN".to_owned()
}

const fn default_ttl() -> u32 {
    3600
}

/// Полная конфигурация процесса.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Адрес UDP-транспорта; `null` отключает UDP.
    pub listen_udp: Option<SocketAddr>,
    /// Адрес TCP-транспорта; `null` отключает TCP.
    pub listen_tcp: Option<SocketAddr>,
    /// Число UDP worker'ов; `0` — по числу доступных ядер.
    pub workers: usize,
    /// Уровень логирования.
    pub log_level: LogLevel,
    /// Параметры TCP.
    pub tcp: TcpConfig,
    /// Файл persistence `pulse-zonefile`; `null`/отсутствие — без persistence.
    pub zonefile: Option<PathBuf>,
    /// Режим durability коммитов.
    pub durability: Durability,
    /// Размер map zonefile в байтах.
    pub map_size: u64,
    /// Обслуживаемые зоны в JSON-форме.
    pub zones: Vec<ZoneConfig>,
    /// Дополнительные зоны из master-файлов (RFC 1035).
    pub zones_files: Vec<ZoneFileConfig>,
    /// DNSSEC-подпись зон при загрузке (origin → ключи/политика).
    #[serde(default)]
    pub dnssec: BTreeMap<String, DnssecZoneConfig>,
    /// TSIG-ключи для transfer и NOTIFY.
    #[serde(default)]
    pub tsig_keys: Vec<TsigKeyConfig>,
    /// Настройки AXFR/IXFR и NOTIFY.
    #[serde(default)]
    pub transfer: TransferSettings,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_udp: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5353)),
            listen_tcp: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5353)),
            workers: 0,
            log_level: LogLevel::Info,
            tcp: TcpConfig::default(),
            zonefile: None,
            durability: Durability::Flush,
            map_size: DEFAULT_MAP_SIZE,
            zones: Vec::new(),
            zones_files: Vec::new(),
            dnssec: BTreeMap::new(),
            tsig_keys: Vec::new(),
            transfer: TransferSettings::default(),
        }
    }
}

impl Config {
    /// Читает конфигурацию из JSON-файла.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Read`] при ошибке чтения файла,
    /// [`ConfigError::Parse`] при некорректном JSON или схеме.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_json_str(&text).map_err(|error| error.with_path(path))
    }

    /// Разбирает конфигурацию из строки JSON.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Parse`] при некорректном JSON или схеме.
    pub fn from_json_str(text: &str) -> Result<Self, ConfigError> {
        serde_json::from_str(text).map_err(|source| ConfigError::Parse {
            path: PathBuf::from("<inline>"),
            source,
        })
    }

    /// Проверяет локальные ограничения конфигурации.
    ///
    /// Инварианты зон (SOA/NS в apex, CNAME-эксклюзивность) проверяются при
    /// загрузке зон в [`crate::zone`].
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`], если не задан ни один транспорт, число
    /// worker'ов выходит за разумные пределы или параметры TCP некорректны.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.listen_udp.is_none() && self.listen_tcp.is_none() {
            return Err(ConfigError::Invalid(
                "at least one of listen_udp/listen_tcp must be set".to_owned(),
            ));
        }
        if self.workers > 1024 {
            return Err(ConfigError::Invalid(format!(
                "workers must be in 0..=1024, got {}",
                self.workers
            )));
        }
        if self.tcp.max_connections == 0 || self.tcp.max_connections > 65_535 {
            return Err(ConfigError::Invalid(format!(
                "tcp.max_connections must be in 1..=65535, got {}",
                self.tcp.max_connections
            )));
        }
        if !(100..=600_000).contains(&self.tcp.idle_timeout_ms) {
            return Err(ConfigError::Invalid(format!(
                "tcp.idle_timeout_ms must be in 100..=600000, got {}",
                self.tcp.idle_timeout_ms
            )));
        }
        if self
            .zonefile
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
        {
            return Err(ConfigError::Invalid(
                "zonefile path must not be empty".to_owned(),
            ));
        }
        if self.map_size == 0 {
            return Err(ConfigError::Invalid(
                "map_size must be greater than zero".to_owned(),
            ));
        }
        self.transfer.validate()?;
        let mut key_names = std::collections::HashSet::with_capacity(self.tsig_keys.len());
        for key in &self.tsig_keys {
            let name = Name::parse(key.name.trim()).map_err(|error| {
                ConfigError::Invalid(format!("tsig_keys: invalid name {:?}: {error}", key.name))
            })?;
            if name == Name::root() || name.labels().any(|label| label == b"*") {
                return Err(ConfigError::Invalid(format!(
                    "tsig_keys: name {:?} must be a non-root name without wildcards",
                    key.name
                )));
            }
            if !key_names.insert(name.clone()) {
                return Err(ConfigError::Invalid(format!(
                    "tsig_keys: duplicate key {name}"
                )));
            }
            parse_tsig_algorithm(&key.algorithm)?;
            let secret = STANDARD.decode(key.secret.trim()).map_err(|error| {
                ConfigError::Invalid(format!(
                    "tsig_keys: key {name} secret is not base64: {error}"
                ))
            })?;
            if secret.is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "tsig_keys: key {name} secret must not be empty"
                )));
            }
        }
        for origin in &self.transfer.allow_zones {
            let name = Name::parse(origin.trim()).map_err(|error| {
                ConfigError::Invalid(format!(
                    "transfer.allow_zones: invalid origin {origin:?}: {error}"
                ))
            })?;
            if name == Name::root() || name.labels().any(|label| label == b"*") {
                return Err(ConfigError::Invalid(format!(
                    "transfer.allow_zones: origin {origin:?} must be a non-root name without wildcards"
                )));
            }
        }
        if let Some(key) = &self.transfer.notify_tsig_key {
            let name = Name::parse(key.trim()).map_err(|error| {
                ConfigError::Invalid(format!(
                    "transfer.notify_tsig_key: invalid name {key:?}: {error}"
                ))
            })?;
            if !key_names.contains(&name) {
                return Err(ConfigError::Invalid(format!(
                    "transfer.notify_tsig_key: key {name} is not declared in tsig_keys"
                )));
            }
        }
        Ok(())
    }

    /// Добавляет ключ подписи зоны (CLI `--dnssec-key`).
    ///
    /// Повторные ключи для той же зоны дополняют набор; порядок ключей
    /// сохраняется.
    pub fn add_dnssec_key(&mut self, origin: &str, role: Option<DnssecKeyRole>, path: PathBuf) {
        let entry = self.dnssec.entry(origin.to_owned()).or_default();
        entry.keys.push(DnssecKeyConfig {
            role,
            path,
            algorithm: None,
            flags: None,
        });
    }

    /// Добавляет TSIG-ключ (CLI `--tsig-key`).
    ///
    /// Секрет передаётся в base64. Повторное имя ключа обнаруживается
    /// [`Config::validate`].
    pub fn add_tsig_key(&mut self, name: String, algorithm: String, secret: String) {
        self.tsig_keys.push(TsigKeyConfig {
            name,
            algorithm,
            secret,
        });
    }

    /// Применяет CLI-overrides поверх файла.
    pub fn apply_overrides(&mut self, overrides: &Overrides) {
        if let Some(addr) = overrides.listen_udp {
            self.listen_udp = Some(addr);
        }
        if let Some(addr) = overrides.listen_tcp {
            self.listen_tcp = Some(addr);
        }
        if let Some(workers) = overrides.workers {
            self.workers = workers;
        }
        if let Some(level) = overrides.log_level {
            self.log_level = level;
        }
        if let Some(path) = &overrides.zonefile {
            self.zonefile = Some(path.clone());
        }
        if let Some(durability) = overrides.durability {
            self.durability = durability;
        }
        if let Some(map_size) = overrides.map_size {
            self.map_size = map_size;
        }
    }
}

/// Значения, переопределяющие конфигурационный файл из CLI.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Overrides {
    /// Новый адрес UDP.
    pub listen_udp: Option<SocketAddr>,
    /// Новый адрес TCP.
    pub listen_tcp: Option<SocketAddr>,
    /// Новое число UDP worker'ов.
    pub workers: Option<usize>,
    /// Новый уровень логирования.
    pub log_level: Option<LogLevel>,
    /// Путь к файлу persistence.
    pub zonefile: Option<PathBuf>,
    /// Режим durability.
    pub durability: Option<Durability>,
    /// Размер map zonefile.
    pub map_size: Option<u64>,
}

/// Ошибка чтения/разбора конфигурации.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Не удалось прочитать файл.
    #[error("cannot read configuration file {path}: {source}")]
    Read {
        /// Путь к файлу.
        path: PathBuf,
        /// Причина.
        #[source]
        source: std::io::Error,
    },
    /// JSON не соответствует схеме.
    #[error("invalid configuration {path}: {source}")]
    Parse {
        /// Путь к файлу (или `<inline>`).
        path: PathBuf,
        /// Причина.
        #[source]
        source: serde_json::Error,
    },
    /// Конфигурация синтаксически валидна, но нарушает ограничения.
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

impl ConfigError {
    fn with_path(self, path: &Path) -> Self {
        match self {
            Self::Parse { source, .. } => Self::Parse {
                path: path.to_path_buf(),
                source,
            },
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_loopback_and_valid() {
        let config = Config::default();
        assert_eq!(config.workers, 0);
        assert_eq!(config.tcp.max_connections, 1024);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn null_disables_transport() {
        let config = Config::from_json_str(r#"{"listen_udp": null, "listen_tcp": null}"#).unwrap();
        assert!(config.listen_udp.is_none());
        assert!(config.listen_tcp.is_none());
        assert!(config.validate().is_err());
    }

    #[test]
    fn overrides_apply() {
        let mut config = Config::default();
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        config.apply_overrides(&Overrides {
            listen_udp: Some(addr),
            listen_tcp: None,
            workers: Some(3),
            log_level: Some(LogLevel::Debug),
            zonefile: None,
            durability: Some(Durability::Sync),
            map_size: Some(64 * 1024 * 1024),
        });
        assert_eq!(config.listen_udp, Some(addr));
        assert_eq!(config.workers, 3);
        assert_eq!(config.log_level, LogLevel::Debug);
    }

    #[test]
    fn rejects_unknown_fields() {
        let error = Config::from_json_str(r#"{"listen_udp": "127.0.0.1:0", "wat": 1}"#);
        assert!(error.is_err());
    }

    #[test]
    fn parses_zone_files() {
        let config = Config::from_json_str(
            r#"{
                "listen_udp": null,
                "listen_tcp": null,
                "zones_files": [{"origin": "example.com.", "path": "examples/example.com.zone"}]
            }"#,
        )
        .unwrap();
        assert_eq!(config.zones_files.len(), 1);
        assert_eq!(config.zones_files[0].origin, "example.com.");
        assert_eq!(
            config.zones_files[0].path,
            PathBuf::from("examples/example.com.zone")
        );
    }

    #[test]
    fn log_level_parses_case_insensitively() {
        assert_eq!("WARN".parse::<LogLevel>().unwrap(), LogLevel::Warn);
        assert!("loud".parse::<LogLevel>().is_err());
    }

    #[test]
    fn transfer_and_tsig_config_parse() {
        let config = Config::from_json_str(
            r#"{
                "listen_udp": null,
                "listen_tcp": "127.0.0.1:0",
                "tsig_keys": [
                    {"name": "xfr.key.", "algorithm": "hmac-sha256", "secret": "c2VjcmV0"}
                ],
                "transfer": {
                    "require_tsig": true,
                    "allow_from": ["127.0.0.1"],
                    "allow_zones": ["example.com."],
                    "notify": ["127.0.0.1:5354"],
                    "notify_tsig_key": "xfr.key.",
                    "history_deltas": 8
                }
            }"#,
        )
        .unwrap();
        assert_eq!(config.tsig_keys.len(), 1);
        assert_eq!(config.transfer.history_deltas, 8);
        assert_eq!(config.transfer.allow_from.len(), 1);
        assert_eq!(config.transfer.notify.len(), 1);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn rejects_invalid_tsig_secret_and_notify_key() {
        let config = Config {
            tsig_keys: vec![TsigKeyConfig {
                name: "xfr.key.".to_owned(),
                algorithm: "hmac-sha256".to_owned(),
                secret: "not base64!".to_owned(),
            }],
            ..Config::default()
        };
        assert!(config.validate().is_err());

        let mut config = Config::default();
        config.transfer.notify_tsig_key = Some("missing.key.".to_owned());
        assert!(config.validate().is_err());
    }
}
