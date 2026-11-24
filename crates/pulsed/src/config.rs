//! JSON-конфигурация сервера и CLI-overrides.
//!
//! Конфигурация намеренно плоская: адреса транспортов, число UDP worker'ов,
//! уровень логирования, параметры TCP, persistence (`zonefile`/`durability`/
//! `map_size`), DNSSEC, secondary и transfer. Зоны в JSON больше не
//! принимаются: единственный источник истины — `pulse-zonefile` (`--data`).
//!
//! # Пример
//!
//! ```
//! use pulsed::config::Config;
//!
//! let config = Config::from_json_str(r#"{
//!   "listen_udp": "127.0.0.1:0",
//!   "listen_tcp": "127.0.0.1:0",
//!   "zonefile": "zones.pulse"
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
use pulse_zonefile::parallel::SyncModeV2;
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
    /// Режим `pulse-zonefile` v1.
    #[must_use]
    pub const fn sync_mode(self) -> SyncMode {
        match self {
            Self::Sync => SyncMode::Sync,
            Self::Flush => SyncMode::MetaNoSync,
            Self::Memory => SyncMode::NoSync,
        }
    }

    /// Режим durability v2.
    #[must_use]
    pub const fn sync_mode_v2(self) -> SyncModeV2 {
        match self {
            Self::Sync => SyncModeV2::Sync,
            Self::Flush => SyncModeV2::Flush,
            Self::Memory => SyncModeV2::Memory,
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

/// Режим коммита v2-стора.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CommitMode {
    /// Каждая зона коммитится своим writer'ом (2 fsync на коммит в `Sync`).
    #[default]
    PerZone,
    /// Коммиты зон батчатся координатором: 2 fsync на группу зон.
    Group,
}

impl CommitMode {
    /// Строковое представление для CLI/логов.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PerZone => "per-zone",
            Self::Group => "group",
        }
    }
}

impl fmt::Display for CommitMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for CommitMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "per-zone" | "per_zone" | "zone" => Ok(Self::PerZone),
            "group" | "group-commit" => Ok(Self::Group),
            other => Err(format!(
                "unknown commit mode {other:?}; expected per-zone or group"
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
    #[allow(clippy::too_many_lines)]
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

/// Вторичная зона: источник данных — AXFR/IXFR с master.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecondaryZoneConfig {
    /// Origin зоны.
    pub origin: String,
    /// Master-адреса (TCP для AXFR/IXFR, UDP/TCP для SOA-запроса).
    pub masters: Vec<SocketAddr>,
    /// TSIG-ключ из `tsig_keys`; `null` — без TSIG.
    #[serde(default)]
    pub tsig_key: Option<String>,
    /// Переопределение `refresh` из SOA (секунды).
    #[serde(default)]
    pub refresh: Option<u32>,
    /// Переопределение `retry` из SOA (секунды).
    #[serde(default)]
    pub retry: Option<u32>,
    /// Переопределение `expire` из SOA (секунды).
    #[serde(default)]
    pub expire: Option<u32>,
    /// IP-ACL для входящих NOTIFY этой зоны; пусто — общий `transfer.allow_from`.
    #[serde(default)]
    pub allow_notify_from: Vec<IpAddr>,
    /// Загружать зону через AXFR при старте, если её нет в store/zonefile.
    #[serde(default = "default_true")]
    pub bootstrap: bool,
}

const fn default_true() -> bool {
    true
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

/// Полная конфигурация процесса.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Адрес UDP-транспорта; `null` отключает UDP.
    pub listen_udp: Option<SocketAddr>,
    /// Адрес TCP-транспорта; `null` отключает TCP.
    pub listen_tcp: Option<SocketAddr>,
    /// Адрес DNS-over-TLS (RFC 7858); `null` отключает DoT.
    pub dot_listen: Option<SocketAddr>,
    /// Адрес DNS-over-HTTPS/1.1 (RFC 8484); `null` отключает DoH.
    pub doh_listen: Option<SocketAddr>,
    /// PEM-сертификат (цепочка) для DoT/DoH.
    pub tls_cert: Option<PathBuf>,
    /// PEM-закрытый ключ для DoT/DoH (права 0600).
    pub tls_key: Option<PathBuf>,
    /// Перечитывать TLS-сертификат каждые N секунд; `null` — только SIGHUP.
    pub tls_reload_secs: Option<u64>,
    /// IP/CIDR allowlist для DoT/DoH; пусто — разрешены все адреса.
    pub tls_allow_from: Vec<String>,
    /// Максимум одновременных DoT-соединений.
    pub dot_max_connections: usize,
    /// Максимум одновременных DoH-соединений.
    pub doh_max_connections: usize,
    /// Адрес DNSCrypt (UDP); `null` отключает DNSCrypt.
    pub dnscrypt_listen: Option<SocketAddr>,
    /// Файл Ed25519 seed провайдера (hex, 32 байта, права 0600).
    pub dnscrypt_provider_key: Option<PathBuf>,
    /// Файл X25519 secret резолвера (hex, 32 байта, права 0600).
    pub dnscrypt_resolver_key: Option<PathBuf>,
    /// Подписанный сертификат из `pulsed dnscrypt-gencert` (JSON).
    pub dnscrypt_cert: Option<PathBuf>,
    /// Полное имя провайдера, например `2.dnscrypt-cert.example.com.`.
    pub dnscrypt_provider_name: Option<String>,
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
    /// Режим коммита v2: per-zone или group.
    pub commit_mode: CommitMode,
    /// Размер map zonefile в байтах.
    pub map_size: u64,
    /// Устаревшее поле миграции: JSON-зоны больше не принимаются.
    #[serde(default)]
    pub zones: Option<serde_json::Value>,
    /// Устаревшее поле миграции: master-файлы в конфигурации не принимаются.
    #[serde(default)]
    pub zones_files: Option<serde_json::Value>,
    /// DNSSEC-подпись зон при загрузке (origin → ключи/политика).
    #[serde(default)]
    pub dnssec: BTreeMap<String, DnssecZoneConfig>,
    /// Вторичные зоны (AXFR/IXFR-in).
    #[serde(default)]
    pub secondary_zones: Vec<SecondaryZoneConfig>,
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
            dot_listen: None,
            doh_listen: None,
            tls_cert: None,
            tls_key: None,
            tls_reload_secs: None,
            tls_allow_from: Vec::new(),
            dot_max_connections: 1024,
            doh_max_connections: 1024,
            dnscrypt_listen: None,
            dnscrypt_provider_key: None,
            dnscrypt_resolver_key: None,
            dnscrypt_cert: None,
            dnscrypt_provider_name: None,
            workers: 0,
            log_level: LogLevel::Info,
            tcp: TcpConfig::default(),
            zonefile: None,
            durability: Durability::Flush,
            commit_mode: CommitMode::PerZone,
            map_size: DEFAULT_MAP_SIZE,
            zones: None,
            zones_files: None,
            dnssec: BTreeMap::new(),
            secondary_zones: Vec::new(),
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
    /// Конфигурация больше не содержит зон: JSON-поля `zones`/`zones_files`
    /// отвергаются с инструкцией миграции на `pulsed import --data`.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`], если не задан ни один транспорт, число
    /// worker'ов выходит за разумные пределы или параметры TCP некорректны.
    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.listen_udp.is_none()
            && self.listen_tcp.is_none()
            && self.dot_listen.is_none()
            && self.doh_listen.is_none()
            && self.dnscrypt_listen.is_none()
        {
            return Err(ConfigError::Invalid(
                "at least one of listen_udp/listen_tcp/dot_listen/doh_listen/dnscrypt_listen must be set"
                    .to_owned(),
            ));
        }
        self.validate_tls()?;
        self.validate_dnscrypt()?;
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
        if self.zonefile.is_none() && !self.secondary_zones.is_empty() {
            return Err(ConfigError::Invalid(
                "secondary_zones require a zonefile; pass --data <file>".to_owned(),
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
        if self.zones.is_some() || self.zones_files.is_some() {
            return Err(ConfigError::Invalid(
                "JSON zones are no longer supported: the configuration keys `zones` and \
                 `zones_files` have been removed. Put all zones into the binary zonefile \
                 (`pulsed import --data <file> --origin <origin> <zone-file>` for master \
                 files) and point the server at it with `--data <file>`."
                    .to_owned(),
            ));
        }
        let origins: std::collections::HashSet<Name> = std::collections::HashSet::new();
        let mut secondary_origins = std::collections::HashSet::new();
        for zone in &self.secondary_zones {
            let name = Name::parse(zone.origin.trim()).map_err(|error| {
                ConfigError::Invalid(format!(
                    "secondary_zones: invalid origin {:?}: {error}",
                    zone.origin
                ))
            })?;
            if name == Name::root() || name.labels().any(|label| label == b"*") {
                return Err(ConfigError::Invalid(format!(
                    "secondary_zones: origin {name} must be a non-root name without wildcards"
                )));
            }
            if !secondary_origins.insert(name.clone()) {
                return Err(ConfigError::Invalid(format!(
                    "secondary_zones: duplicate origin {name}"
                )));
            }
            if origins.contains(&name) {
                return Err(ConfigError::Invalid(format!(
                    "secondary_zones: origin {name} is also configured as primary"
                )));
            }
            if zone.masters.is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "secondary_zones: zone {name} has no masters"
                )));
            }
            for timer in [zone.refresh, zone.retry, zone.expire]
                .into_iter()
                .flatten()
            {
                if timer == 0 {
                    return Err(ConfigError::Invalid(format!(
                        "secondary_zones: zone {name} has a zero timer"
                    )));
                }
            }
            if let Some(key) = &zone.tsig_key {
                let key = Name::parse(key.trim()).map_err(|error| {
                    ConfigError::Invalid(format!(
                        "secondary_zones: zone {name} has invalid tsig_key: {error}"
                    ))
                })?;
                if !key_names.contains(&key) {
                    return Err(ConfigError::Invalid(format!(
                        "secondary_zones: zone {name} tsig_key {key} is not declared in tsig_keys"
                    )));
                }
            }
        }
        Ok(())
    }

    /// Проверяет параметры DoT/DoH.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`], если включён DoT/DoH без TLS-пары, лимиты
    /// выходят за допустимые пределы или ACL содержит некорректный CIDR.
    pub fn validate_tls(&self) -> Result<(), ConfigError> {
        let enabled = self.dot_listen.is_some() || self.doh_listen.is_some();
        if enabled && (self.tls_cert.is_none() || self.tls_key.is_none()) {
            return Err(ConfigError::Invalid(
                "dot_listen/doh_listen require both tls_cert and tls_key".to_owned(),
            ));
        }
        if let Some(path) = &self.tls_cert
            && path.as_os_str().is_empty()
        {
            return Err(ConfigError::Invalid(
                "tls_cert path must not be empty".to_owned(),
            ));
        }
        if let Some(path) = &self.tls_key
            && path.as_os_str().is_empty()
        {
            return Err(ConfigError::Invalid(
                "tls_key path must not be empty".to_owned(),
            ));
        }
        if let Some(seconds) = self.tls_reload_secs
            && !(1..=86_400).contains(&seconds)
        {
            return Err(ConfigError::Invalid(format!(
                "tls_reload_secs must be in 1..=86400, got {seconds}"
            )));
        }
        if !(1..=65_535).contains(&self.dot_max_connections) {
            return Err(ConfigError::Invalid(format!(
                "dot_max_connections must be in 1..=65535, got {}",
                self.dot_max_connections
            )));
        }
        if !(1..=65_535).contains(&self.doh_max_connections) {
            return Err(ConfigError::Invalid(format!(
                "doh_max_connections must be in 1..=65535, got {}",
                self.doh_max_connections
            )));
        }
        pulse_tls::Acl::from_cidrs(&self.tls_allow_from).map_err(|error| {
            ConfigError::Invalid(format!("tls_allow_from: invalid CIDR: {error}"))
        })?;
        Ok(())
    }

    /// Проверяет параметры DNSCrypt.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`], если включён DNSCrypt без ключей/сертификата
    /// или имя провайдера некорректно.
    pub fn validate_dnscrypt(&self) -> Result<(), ConfigError> {
        if let Some(name) = &self.dnscrypt_provider_name {
            let parsed = Name::parse(name.trim()).map_err(|error| {
                ConfigError::Invalid(format!(
                    "dnscrypt_provider_name {name:?} is not a valid DNS name: {error}"
                ))
            })?;
            if parsed == Name::root() || parsed.labels().any(|label| label == b"*") {
                return Err(ConfigError::Invalid(format!(
                    "dnscrypt_provider_name {name:?} must be a non-root name without wildcards"
                )));
            }
        }
        if self.dnscrypt_listen.is_none() {
            return Ok(());
        }
        for (field, value) in [
            ("dnscrypt_provider_key", &self.dnscrypt_provider_key),
            ("dnscrypt_resolver_key", &self.dnscrypt_resolver_key),
            ("dnscrypt_cert", &self.dnscrypt_cert),
        ] {
            match value {
                Some(path) if !path.as_os_str().is_empty() => {}
                _ => {
                    return Err(ConfigError::Invalid(format!(
                        "dnscrypt_listen requires {field}"
                    )));
                }
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
        if let Some(addr) = overrides.dot_listen {
            self.dot_listen = Some(addr);
        }
        if let Some(addr) = overrides.doh_listen {
            self.doh_listen = Some(addr);
        }
        if let Some(path) = &overrides.tls_cert {
            self.tls_cert = Some(path.clone());
        }
        if let Some(path) = &overrides.tls_key {
            self.tls_key = Some(path.clone());
        }
        if let Some(seconds) = overrides.tls_reload_secs {
            self.tls_reload_secs = Some(seconds);
        }
        if !overrides.tls_allow_from.is_empty() {
            self.tls_allow_from.clone_from(&overrides.tls_allow_from);
        }
        if let Some(addr) = overrides.dnscrypt_listen {
            self.dnscrypt_listen = Some(addr);
        }
        if let Some(path) = &overrides.dnscrypt_provider_key {
            self.dnscrypt_provider_key = Some(path.clone());
        }
        if let Some(path) = &overrides.dnscrypt_resolver_key {
            self.dnscrypt_resolver_key = Some(path.clone());
        }
        if let Some(path) = &overrides.dnscrypt_cert {
            self.dnscrypt_cert = Some(path.clone());
        }
        if let Some(name) = &overrides.dnscrypt_provider_name {
            self.dnscrypt_provider_name = Some(name.clone());
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
        if let Some(commit_mode) = overrides.commit_mode {
            self.commit_mode = commit_mode;
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
    /// Новый адрес DoT.
    pub dot_listen: Option<SocketAddr>,
    /// Новый адрес DoH.
    pub doh_listen: Option<SocketAddr>,
    /// Новый PEM-сертификат DoT/DoH.
    pub tls_cert: Option<PathBuf>,
    /// Новый PEM-ключ DoT/DoH.
    pub tls_key: Option<PathBuf>,
    /// Новый период перечитывания TLS-сертификата.
    pub tls_reload_secs: Option<u64>,
    /// Новый IP/CIDR allowlist DoT/DoH.
    pub tls_allow_from: Vec<String>,
    /// Новый адрес DNSCrypt.
    pub dnscrypt_listen: Option<SocketAddr>,
    /// Новый файл provider-ключа DNSCrypt.
    pub dnscrypt_provider_key: Option<PathBuf>,
    /// Новый файл resolver-ключа DNSCrypt.
    pub dnscrypt_resolver_key: Option<PathBuf>,
    /// Новый файл сертификата DNSCrypt.
    pub dnscrypt_cert: Option<PathBuf>,
    /// Новое имя DNSCrypt-провайдера.
    pub dnscrypt_provider_name: Option<String>,
    /// Новое число UDP worker'ов.
    pub workers: Option<usize>,
    /// Новый уровень логирования.
    pub log_level: Option<LogLevel>,
    /// Путь к файлу persistence.
    pub zonefile: Option<PathBuf>,
    /// Режим durability.
    pub durability: Option<Durability>,
    /// Режим коммита v2.
    pub commit_mode: Option<CommitMode>,
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
            dot_listen: None,
            doh_listen: None,
            tls_cert: None,
            tls_key: None,
            tls_reload_secs: None,
            tls_allow_from: Vec::new(),
            dnscrypt_listen: None,
            dnscrypt_provider_key: None,
            dnscrypt_resolver_key: None,
            dnscrypt_cert: None,
            dnscrypt_provider_name: None,
            workers: Some(3),
            log_level: Some(LogLevel::Debug),
            zonefile: None,
            durability: Some(Durability::Sync),
            commit_mode: Some(CommitMode::Group),
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
    fn json_zones_are_rejected_with_migration_hint() {
        for text in [
            r#"{"listen_udp": "127.0.0.1:0", "listen_tcp": null, "zones": []}"#,
            r#"{"listen_udp": "127.0.0.1:0", "listen_tcp": null, "zones_files": []}"#,
        ] {
            let config = Config::from_json_str(text).unwrap();
            let error = config.validate().unwrap_err().to_string();
            assert!(
                error.contains("JSON zones are no longer supported"),
                "{error}"
            );
            assert!(error.contains("pulsed import"), "{error}");
            assert!(error.contains("--data"), "{error}");
        }
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

    #[test]
    fn dot_requires_certificate_pair() {
        let mut config = Config {
            listen_udp: None,
            listen_tcp: None,
            dot_listen: Some("127.0.0.1:8853".parse().unwrap()),
            ..Config::default()
        };
        let error = config.validate().unwrap_err().to_string();
        assert!(
            error.contains("require both tls_cert and tls_key"),
            "{error}"
        );

        config.tls_cert = Some(PathBuf::from("cert.pem"));
        assert!(config.validate().is_err());
        config.tls_key = Some(PathBuf::from("key.pem"));
        assert!(config.validate().is_ok());
    }

    #[test]
    fn doh_only_configuration_is_accepted() {
        let config = Config {
            listen_udp: None,
            listen_tcp: None,
            doh_listen: Some("127.0.0.1:8443".parse().unwrap()),
            tls_cert: Some(PathBuf::from("cert.pem")),
            tls_key: Some(PathBuf::from("key.pem")),
            ..Config::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn tls_acl_and_limits_are_validated() {
        let mut config = Config {
            tls_cert: Some(PathBuf::from("cert.pem")),
            tls_key: Some(PathBuf::from("key.pem")),
            dot_listen: Some("127.0.0.1:8853".parse().unwrap()),
            ..Config::default()
        };
        config.tls_allow_from = vec!["192.0.2.0/24".to_owned()];
        assert!(config.validate().is_ok());
        config.tls_allow_from = vec!["not-a-cidr".to_owned()];
        assert!(config.validate().is_err());
        config.tls_allow_from.clear();
        config.dot_max_connections = 0;
        assert!(config.validate().is_err());
        config.dot_max_connections = 1024;
        config.tls_reload_secs = Some(0);
        assert!(config.validate().is_err());
    }

    #[test]
    fn dnscrypt_requires_material() {
        let mut config = Config {
            listen_udp: None,
            listen_tcp: None,
            dnscrypt_listen: Some("127.0.0.1:5443".parse().unwrap()),
            ..Config::default()
        };
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("dnscrypt_provider_key"), "{error}");

        config.dnscrypt_provider_key = Some(PathBuf::from("provider.key"));
        config.dnscrypt_resolver_key = Some(PathBuf::from("resolver.key"));
        config.dnscrypt_cert = Some(PathBuf::from("cert.json"));
        assert!(config.validate().is_ok());

        config.dnscrypt_provider_name = Some("bad..name".to_owned());
        assert!(config.validate().is_err());
        config.dnscrypt_provider_name = Some("2.dnscrypt-cert.example.com.".to_owned());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn transports_config_parses_from_json() {
        let config = Config::from_json_str(
            r#"{
                "listen_udp": null,
                "listen_tcp": null,
                "dot_listen": "127.0.0.1:8853",
                "doh_listen": "127.0.0.1:8443",
                "tls_cert": "cert.pem",
                "tls_key": "key.pem",
                "tls_reload_secs": 60,
                "tls_allow_from": ["127.0.0.0/8"],
                "dnscrypt_listen": "127.0.0.1:5443",
                "dnscrypt_provider_key": "provider.key",
                "dnscrypt_resolver_key": "resolver.key",
                "dnscrypt_cert": "cert.json",
                "dnscrypt_provider_name": "2.dnscrypt-cert.example.com."
            }"#,
        )
        .unwrap();
        assert_eq!(config.dot_listen, Some("127.0.0.1:8853".parse().unwrap()));
        assert_eq!(config.tls_allow_from, vec!["127.0.0.0/8"]);
        assert_eq!(
            config.dnscrypt_provider_name.as_deref(),
            Some("2.dnscrypt-cert.example.com.")
        );
        assert!(config.validate().is_ok());
    }
}
