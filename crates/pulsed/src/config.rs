//! TOML-конфигурация сервера (JSON — обратная совместимость) и CLI-overrides.
//!
//! Формат определяется расширением файла: `.toml` (рекомендуемый) или `.json`
//! (legacy). Конфигурация намеренно плоская: адреса транспортов, число UDP
//! worker'ов, уровень логирования, параметры TCP, persistence (`zonefile`/
//! `durability`/`map_size`), write-ahead journal REST-мутаций (`journal`/
//! `journal_path`/`journal_max_bytes`/`journal_fsync`), DNSSEC, secondary и
//! transfer. Зоны в конфигурации
//! больше не принимаются: единственный источник истины — `pulse-zonefile`
//! (`--data`).
//!
//! # Пример
//!
//! ```
//! use pulsed::config::Config;
//!
//! let config = Config::from_toml_str(r#"
//! listen_udp = "127.0.0.1:0"
//! listen_tcp = "127.0.0.1:0"
//! zonefile = "zones.pulse"
//! "#).unwrap();
//! assert!(config.listen_udp.is_some());
//! ```
//!
//! JSON-эквивалент читается через [`Config::from_json_str`] или файл `.json`.

use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use pulse_dns::Name;
use pulse_runtime::affinity::{self, MAX_CPU};
use pulse_transfer::TsigAlgorithm;
use pulse_zonefile::SyncMode;
use pulse_zonefile::parallel::SyncModeV2;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Размер map по умолчанию: 4 GiB (sparse-файл; страницы занимаются по мере
/// записи).
pub const DEFAULT_MAP_SIZE: u64 = 4 * 1024 * 1024 * 1024;

/// Уровень логирования.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
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

/// Роль процесса `pulsed`.
///
/// Разделение позволяет запустить DNS-транспорты и REST API отдельными
/// процессами на одном zonefile (multi-process v2, ADR 0007), чтобы REST не
/// голодал под DNS-нагрузкой.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Один процесс: DNS-транспорты и REST API (текущее поведение).
    #[default]
    All,
    /// Только DNS-транспорты; zonefile открыт в multi-process режиме.
    Dns,
    /// Только REST API и write-ahead journal; DNS-транспорты не поднимаются.
    Api,
}

impl Role {
    /// `true`, если роль требует multi-process открытия zonefile.
    #[must_use]
    pub const fn is_multi_process(self) -> bool {
        !matches!(self, Self::All)
    }

    /// Поднимает ли роль DNS-транспорты.
    #[must_use]
    pub const fn serves_dns(self) -> bool {
        matches!(self, Self::All | Self::Dns)
    }

    /// Поднимает ли роль REST API.
    #[must_use]
    pub const fn serves_api(self) -> bool {
        matches!(self, Self::All | Self::Api)
    }

    /// Строковое представление для CLI/логов.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Dns => "dns",
            Self::Api => "api",
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Role {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "all" => Ok(Self::All),
            "dns" => Ok(Self::Dns),
            "api" => Ok(Self::Api),
            other => Err(format!("unknown role {other:?}; expected all, dns or api")),
        }
    }
}

/// Политика transparent huge pages для mmap-регионов и арен.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HugePagesSetting {
    /// Best-effort `madvise(MADV_HUGEPAGE)`; ошибки не фатальны (по умолчанию).
    #[default]
    Auto,
    /// Подсказка обязательна: без THP или при ошибке `madvise` — ошибка старта.
    Always,
    /// THP выключен (`MADV_NOHUGEPAGE` для арен).
    Never,
}

impl HugePagesSetting {
    /// Строковое представление для CLI/логов.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Always => "always",
            Self::Never => "never",
        }
    }

    /// Политика для RX-арены `pulse-runtime`.
    #[must_use]
    pub const fn runtime(self) -> pulse_runtime::HugePages {
        match self {
            Self::Auto => pulse_runtime::HugePages::Auto,
            Self::Always => pulse_runtime::HugePages::Always,
            Self::Never => pulse_runtime::HugePages::Never,
        }
    }

    /// Политика для mmap-регионов `pulse-zonefile`.
    #[must_use]
    pub const fn zonefile(self) -> pulse_zonefile::HugePages {
        match self {
            Self::Auto => pulse_zonefile::HugePages::Auto,
            Self::Always => pulse_zonefile::HugePages::Always,
            Self::Never => pulse_zonefile::HugePages::Never,
        }
    }
}

impl fmt::Display for HugePagesSetting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for HugePagesSetting {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "always" => Ok(Self::Always),
            "never" => Ok(Self::Never),
            other => Err(format!(
                "unknown huge pages policy {other:?}; expected auto, always or never"
            )),
        }
    }
}

/// Список CPU в TOML/JSON: массив чисел или строка `"0,2,4-7"`.
fn deserialize_cpu_list<'de, D>(deserializer: D) -> Result<Vec<usize>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Spec {
        List(Vec<usize>),
        Text(String),
    }

    let cpus = match Spec::deserialize(deserializer)? {
        Spec::List(list) => list,
        Spec::Text(text) => affinity::parse_list(&text).map_err(serde::de::Error::custom)?,
    };
    if let Some(&cpu) = cpus.iter().find(|&&cpu| cpu >= MAX_CPU) {
        return Err(serde::de::Error::custom(format!(
            "CPU {cpu} is outside 0..{MAX_CPU}"
        )));
    }
    Ok(cpus)
}

/// Параметры TCP-транспорта.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
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
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
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
    #[serde(skip_serializing_if = "Option::is_none")]
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

/// Настройки входящих DNS UPDATE (RFC 2136).
///
/// По умолчанию UPDATE **выключен**: сервер отвечает `REFUSED`. При
/// включении TSIG обязателен (`require_tsig = true`), source ACL и allowlist
/// зон ограничивают доступ, а `tsig_keys` сужает набор ключей до перечисленных
/// в глобальной секции `tsig_keys` (пусто — любой объявленный ключ).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct UpdateSettings {
    /// Обслуживать opcode UPDATE.
    pub enabled: bool,
    /// Требовать валидный TSIG; `false` допустим только для доверенной сети.
    pub require_tsig: bool,
    /// IP/CIDR allowlist источника (`"192.0.2.0/24"`, `"::1/128"`, `"10.0.0.1"`).
    pub allow_from: Vec<String>,
    /// Зоны, доступные для UPDATE; пусто — все primary-зоны.
    pub allow_zones: Vec<String>,
    /// Имена ключей из глобальной секции `tsig_keys`; пусто — любой ключ.
    pub tsig_keys: Vec<String>,
}

impl Default for UpdateSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            require_tsig: true,
            allow_from: Vec::new(),
            allow_zones: Vec::new(),
            tsig_keys: Vec::new(),
        }
    }
}

/// Политика UPDATE: то же, что [`UpdateSettings`], под именем из RFC 2136.
///
/// `allow_zones` — это `allow_update` per-zone: пустой список разрешает все
/// primary-зоны, непустой — только перечисленные.
pub type UpdatePolicy = UpdateSettings;

impl UpdateSettings {
    /// Проверяет CIDR, имена зон и ссылки на TSIG-ключи.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] при некорректном CIDR/имени или ссылке на
    /// необъявленный ключ; включённый UPDATE без `zonefile` тоже ошибка.
    pub fn validate(&self, key_names: &std::collections::HashSet<Name>) -> Result<(), ConfigError> {
        if self.enabled && self.tsig_keys.is_empty() && key_names.is_empty() && self.require_tsig {
            return Err(ConfigError::Invalid(
                "update.require_tsig requires at least one key in tsig_keys".to_owned(),
            ));
        }
        for cidr in &self.allow_from {
            validate_cidr(cidr).map_err(|reason| {
                ConfigError::Invalid(format!(
                    "update.allow_from: invalid CIDR {cidr:?}: {reason}"
                ))
            })?;
        }
        let mut zones = std::collections::HashSet::with_capacity(self.allow_zones.len());
        for origin in &self.allow_zones {
            let name = Name::parse(origin.trim()).map_err(|error| {
                ConfigError::Invalid(format!(
                    "update.allow_zones: invalid origin {origin:?}: {error}"
                ))
            })?;
            if name == Name::root() || name.labels().any(|label| label == b"*") {
                return Err(ConfigError::Invalid(format!(
                    "update.allow_zones: origin {origin:?} must be a non-root name without wildcards"
                )));
            }
            if !zones.insert(name) {
                return Err(ConfigError::Invalid(format!(
                    "update.allow_zones: duplicate origin {origin:?}"
                )));
            }
        }
        let mut keys = std::collections::HashSet::with_capacity(self.tsig_keys.len());
        for key in &self.tsig_keys {
            let name = Name::parse(key.trim()).map_err(|error| {
                ConfigError::Invalid(format!("update.tsig_keys: invalid name {key:?}: {error}"))
            })?;
            if name == Name::root() || name.labels().any(|label| label == b"*") {
                return Err(ConfigError::Invalid(format!(
                    "update.tsig_keys: name {key:?} must be a non-root name without wildcards"
                )));
            }
            if !key_names.contains(&name) {
                return Err(ConfigError::Invalid(format!(
                    "update.tsig_keys: key {name} is not declared in tsig_keys"
                )));
            }
            if !keys.insert(name) {
                return Err(ConfigError::Invalid(format!(
                    "update.tsig_keys: duplicate key {key:?}"
                )));
            }
        }
        Ok(())
    }
}

/// Проверяет IP или CIDR (`addr/prefix`).
pub(crate) fn validate_cidr(value: &str) -> Result<(), String> {
    let value = value.trim();
    let (address, prefix) = match value.split_once('/') {
        Some((address, prefix)) => (address, Some(prefix)),
        None => (value, None),
    };
    let address: IpAddr = address
        .parse()
        .map_err(|error| format!("invalid IP address: {error}"))?;
    if let Some(prefix) = prefix {
        let prefix: u8 = prefix
            .parse()
            .map_err(|error| format!("invalid prefix length: {error}"))?;
        let max = if address.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(format!("prefix /{prefix} exceeds /{max}"));
        }
    }
    Ok(())
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
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecondaryZoneConfig {
    /// Origin зоны.
    pub origin: String,
    /// Master-адреса (TCP для AXFR/IXFR, UDP/TCP для SOA-запроса).
    pub masters: Vec<SocketAddr>,
    /// TSIG-ключ из `tsig_keys`; `null` — без TSIG.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tsig_key: Option<String>,
    /// Переопределение `refresh` из SOA (секунды).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh: Option<u32>,
    /// Переопределение `retry` из SOA (секунды).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry: Option<u32>,
    /// Переопределение `expire` из SOA (секунды).
    #[serde(default, skip_serializing_if = "Option::is_none")]
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

/// Механизм denial-of-existence при подписи зоны.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DnssecDenial {
    /// NSEC-цепочка (по умолчанию).
    #[default]
    Nsec,
    /// NSEC3-цепочка (SHA-1, без Opt-Out).
    Nsec3,
}

impl DnssecDenial {
    /// Строковое имя для логов.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Nsec => "nsec",
            Self::Nsec3 => "nsec3",
        }
    }
}

/// Роль DNSSEC-ключа в конфигурации.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DnssecKeyConfig {
    /// Роль ключа. При отсутствии выводится из sibling `.key` (SEP-бит) или
    /// считается CSK для одиночного ключа.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<DnssecKeyRole>,
    /// Путь к BIND `.private` (или парному `.key`), либо PKCS#8 PEM/DER.
    pub path: PathBuf,
    /// Алгоритм для PKCS#8 (обязателен, если роль/файл не задают его).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<u8>,
    /// Явные DNSKEY flags (переопределяют роль).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flags: Option<u16>,
}

/// DNSSEC-настройки зоны.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DnssecZoneConfig {
    /// Ключи подписи (непустой набор).
    #[serde(default)]
    pub keys: Vec<DnssecKeyConfig>,
    /// Срок действия подписи в днях (по умолчанию 30).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validity_days: Option<u32>,
    /// Запас на расхождение часов в секундах (по умолчанию 300).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inception_skew: Option<u32>,
    /// Denial-of-existence: `nsec` (по умолчанию) или `nsec3`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denial: Option<DnssecDenial>,
    /// Соль NSEC3 в hex. `null` — случайная соль на время жизни процесса.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nsec3_salt: Option<String>,
    /// Число NSEC3 hash-итераций (0..=100, по умолчанию 0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nsec3_iterations: Option<u16>,
    /// NSEC3 Opt-Out: не публиковать NSEC3 для insecure-делегирований.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nsec3_opt_out: Option<bool>,
    /// Автоматическая ротация ключей (RFC 7583); `null` — статический набор.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation: Option<DnssecRotationConfig>,
}

/// Настройки автоматической ротации ключей зоны.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DnssecRotationConfig {
    /// Каталог для сгенерированных ключей (`0700`).
    pub key_dir: PathBuf,
    /// Файл состояния ротации (атомарная запись `0600`).
    pub state_path: PathBuf,
    /// Алгоритм новых ключей (по умолчанию 15 — Ed25519).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<u8>,
    /// Срок жизни ZSK в днях (по умолчанию 90).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zsk_lifetime_days: Option<u32>,
    /// Срок жизни KSK в днях (по умолчанию 365).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ksk_lifetime_days: Option<u32>,
    /// Pre-publish фаза в секундах (по умолчанию 86400).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_publish_secs: Option<u32>,
    /// Double-sign фаза в секундах (по умолчанию 86400).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub double_sign_secs: Option<u32>,
    /// Сколько секунд retired-ключ остаётся опубликованным (по умолчанию 604800).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retire_secs: Option<u32>,
    /// Интервал фоновой проверки ротации (по умолчанию 300).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tick_secs: Option<u32>,
}

/// Кеш готовых DNS-ответов для статичных зон.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default)]
pub struct ResponseCacheSettings {
    /// Включён ли кеш ответов.
    pub enabled: bool,
    /// Максимум записей.
    pub max_entries: usize,
    /// Максимум памяти под записи в байтах.
    pub max_bytes: u64,
    /// Число шардов (1..=256).
    pub shards: usize,
}

impl Default for ResponseCacheSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            max_entries: pulse_server::DEFAULT_MAX_ENTRIES,
            max_bytes: pulse_server::DEFAULT_MAX_BYTES as u64,
            shards: pulse_server::DEFAULT_SHARDS,
        }
    }
}

impl ResponseCacheSettings {
    /// Преобразует настройки в конфигурацию движка.
    #[must_use]
    pub fn to_engine_config(self) -> pulse_server::ResponseCacheConfig {
        pulse_server::ResponseCacheConfig {
            enabled: self.enabled,
            max_entries: self.max_entries,
            max_bytes: usize::try_from(self.max_bytes).unwrap_or(usize::MAX),
            shards: self.shards,
        }
    }
}

/// Конфигурация сервера.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Адрес UDP-транспорта; `null` отключает UDP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen_udp: Option<SocketAddr>,
    /// Адрес TCP-транспорта; `null` отключает TCP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen_tcp: Option<SocketAddr>,
    /// Адрес DNS-over-TLS (RFC 7858); `null` отключает DoT.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dot_listen: Option<SocketAddr>,
    /// Адрес DNS-over-HTTPS/1.1 (RFC 8484); `null` отключает DoH.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doh_listen: Option<SocketAddr>,
    /// Адрес DNS-over-HTTPS/2 (RFC 8484 + RFC 9113); `null` отключает DoH h2.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doh_h2_listen: Option<SocketAddr>,
    /// Адрес DNS-over-HTTPS/3 (RFC 8484 + RFC 9114) поверх QUIC; `null`
    /// отключает DoH h3.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doh3_listen: Option<SocketAddr>,
    /// Адрес DNS-over-QUIC (RFC 9250); `null` отключает DoQ.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doq_listen: Option<SocketAddr>,
    /// PEM-сертификат (цепочка) для DoT/DoH/DoQ.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_cert: Option<PathBuf>,
    /// PEM-закрытый ключ для DoT/DoH/DoQ (права 0600).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_key: Option<PathBuf>,
    /// Перечитывать TLS-сертификат каждые N секунд; `null` — только SIGHUP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_reload_secs: Option<u64>,
    /// IP/CIDR allowlist для DoT/DoH/DoQ/DoH3; пусто — разрешены все адреса.
    pub tls_allow_from: Vec<String>,
    /// Максимум одновременных DoT-соединений.
    pub dot_max_connections: usize,
    /// Максимум одновременных DoH-соединений.
    pub doh_max_connections: usize,
    /// Максимум одновременных DoH/HTTP/2-соединений.
    pub doh_h2_max_connections: usize,
    /// Максимум одновременных HTTP/2 stream'ов на соединение.
    pub doh_h2_max_streams: u32,
    /// Максимум одновременных DoH/HTTP/3-соединений.
    pub doh3_max_connections: usize,
    /// Максимум одновременных HTTP/3-запросов на соединение.
    pub doh3_max_concurrent_requests: u32,
    /// Idle timeout DoH/HTTP/3-соединения в миллисекундах.
    pub doh3_idle_timeout_ms: u64,
    /// Максимум одновременных DoQ-соединений.
    pub doq_max_connections: usize,
    /// Максимум одновременных двунаправленных stream'ов DoQ на соединение.
    pub doq_max_streams: u32,
    /// Idle timeout DoQ-соединения в миллисекундах.
    pub doq_idle_timeout_ms: u64,
    /// Максимальный размер DoQ-сообщения (без 2-байтового префикса).
    pub doq_max_message_size: usize,
    /// Адрес DNSCrypt (UDP); `null` отключает DNSCrypt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dnscrypt_listen: Option<SocketAddr>,
    /// Файл Ed25519 seed провайдера (hex, 32 байта, права 0600).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dnscrypt_provider_key: Option<PathBuf>,
    /// Файл X25519 secret резолвера (hex, 32 байта, права 0600).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dnscrypt_resolver_key: Option<PathBuf>,
    /// Подписанный сертификат из `pulsed dnscrypt-gencert` (JSON).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dnscrypt_cert: Option<PathBuf>,
    /// Полное имя провайдера, например `2.dnscrypt-cert.example.com.`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dnscrypt_provider_name: Option<String>,
    /// Адрес DNSCrypt over TCP; `null` отключает TCP-транспорт DNSCrypt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dnscrypt_tcp_listen: Option<SocketAddr>,
    /// Максимум одновременных DNSCrypt TCP-соединений.
    pub dnscrypt_tcp_max_connections: usize,
    /// Idle timeout DNSCrypt TCP-соединения в миллисекундах.
    pub dnscrypt_tcp_idle_timeout_ms: u64,
    /// Максимум полезной нагрузки DNSCrypt TCP-кадра (без 2-байтового префикса).
    pub dnscrypt_tcp_max_frame: usize,
    /// Адрес REST API; `null` — API выключен.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_listen: Option<SocketAddr>,
    /// Bearer-токен REST API; пусто — `PULSED_API_TOKEN` или `--api-token`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_token: Option<String>,
    /// Per-zone allowlist REST API (точный origin или `*.suffix.`); пусто — все зоны.
    #[serde(alias = "api_scopes", default, skip_serializing_if = "Vec::is_empty")]
    pub api_scope: Vec<String>,
    /// Роль процесса (`all` — DNS+API, `dns` — только DNS, `api` — только REST).
    pub role: Role,
    /// Число UDP worker'ов; `0` — по числу доступных ядер.
    pub workers: usize,
    /// Переопределение числа DNS worker'ов (`null` — использовать `workers`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_workers: Option<usize>,
    /// Максимум одновременных API-соединений (по одному потоку на соединение).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_workers: Option<usize>,
    /// CPU для DNS worker'ов (UDP/DNSCrypt), список `"0,2,4-7"` или массив.
    ///
    /// Пересекается с `sched_getaffinity`/cpuset; пустое пересечение — ошибка
    /// старта. Не пересекается с `api_cpu_affinity`.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_cpu_list"
    )]
    pub dns_cpu_affinity: Vec<usize>,
    /// CPU для REST API: accept-поток и потоки соединений.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_cpu_list"
    )]
    pub api_cpu_affinity: Vec<usize>,
    /// Политика huge pages для RX-арены DNS worker'ов и mmap-регионов
    /// `pulse-zonefile` (v1 `FileMap`; v2 читает через page cache).
    #[serde(default)]
    pub huge_pages: HugePagesSetting,
    /// Rate limit REST API в запросах в секунду на токен.
    pub api_rate_limit_per_sec: u32,
    /// Интервал опроса новых версий зон ролью `dns`, мс (`0` — отключить).
    pub zone_poll_ms: u64,
    /// Уровень логирования.
    pub log_level: LogLevel,
    /// Число worker-потоков общего tokio event-loop TCP/DoT/DoH;
    /// `0` — по числу доступных CPU.
    pub tcp_workers: usize,
    /// Включать `TCP_NODELAY` на принятых TCP/DoT-соединениях.
    pub tcp_nodelay: bool,
    /// `SO_BUSY_POLL` для TCP/DoT-сокетов в микросекундах; `0` — выключено.
    pub busy_poll_us: u32,
    /// Таймаут чтения тела DoT-сообщения и записи ответа, миллисекунды.
    pub request_timeout_ms: u64,
    /// Параметры TCP.
    pub tcp: TcpConfig,
    /// Файл persistence `pulse-zonefile`; `null`/отсутствие — без persistence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zonefile: Option<PathBuf>,
    /// Режим durability коммитов.
    pub durability: Durability,
    /// Режим коммита v2: per-zone или group.
    pub commit_mode: CommitMode,
    /// Размер map zonefile в байтах.
    pub map_size: u64,
    /// Включить write-ahead journal REST-мутаций (по умолчанию `true`).
    #[serde(default = "default_true")]
    pub journal: bool,
    /// Путь журнала; `null` — `<zonefile>.journal`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub journal_path: Option<PathBuf>,
    /// Порог compaction журнала в байтах.
    pub journal_max_bytes: u64,
    /// Синхронизировать каждую запись журнала (`fsync`).
    pub journal_fsync: bool,
    /// Устаревшее поле миграции: JSON-зоны больше не принимаются.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zones: Option<serde_json::Value>,
    /// Устаревшее поле миграции: master-файлы в конфигурации не принимаются.
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
    /// Настройки входящих DNS UPDATE (RFC 2136).
    #[serde(default)]
    pub update: UpdateSettings,
    /// Кеш готовых ответов для статичных зон.
    #[serde(default)]
    pub response_cache: ResponseCacheSettings,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_udp: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5353)),
            listen_tcp: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5353)),
            dot_listen: None,
            doh_listen: None,
            doh_h2_listen: None,
            doh3_listen: None,
            doq_listen: None,
            tls_cert: None,
            tls_key: None,
            tls_reload_secs: None,
            tls_allow_from: Vec::new(),
            dot_max_connections: 1024,
            doh_max_connections: 1024,
            doh_h2_max_connections: 1024,
            doh_h2_max_streams: 100,
            doh3_max_connections: 1024,
            doh3_max_concurrent_requests: 100,
            doh3_idle_timeout_ms: 30_000,
            doq_max_connections: 1024,
            doq_max_streams: 100,
            doq_idle_timeout_ms: 30_000,
            doq_max_message_size: 65_535,
            dnscrypt_listen: None,
            dnscrypt_provider_key: None,
            dnscrypt_resolver_key: None,
            dnscrypt_cert: None,
            dnscrypt_provider_name: None,
            dnscrypt_tcp_listen: None,
            dnscrypt_tcp_max_connections: 1024,
            dnscrypt_tcp_idle_timeout_ms: 10_000,
            dnscrypt_tcp_max_frame: 65_535,
            api_listen: None,
            api_token: None,
            api_scope: Vec::new(),
            role: Role::All,
            workers: 0,
            dns_workers: None,
            api_workers: None,
            dns_cpu_affinity: Vec::new(),
            api_cpu_affinity: Vec::new(),
            huge_pages: HugePagesSetting::Auto,
            api_rate_limit_per_sec: pulse_api::config::DEFAULT_RATE_LIMIT_PER_SEC,
            zone_poll_ms: 250,
            log_level: LogLevel::Info,
            tcp_workers: 0,
            tcp_nodelay: true,
            busy_poll_us: 0,
            request_timeout_ms: 10_000,
            tcp: TcpConfig::default(),
            zonefile: None,
            durability: Durability::Flush,
            commit_mode: CommitMode::PerZone,
            map_size: DEFAULT_MAP_SIZE,
            journal: true,
            journal_path: None,
            journal_max_bytes: pulse_api::journal::DEFAULT_MAX_BYTES,
            journal_fsync: true,
            zones: None,
            zones_files: None,
            dnssec: BTreeMap::new(),
            secondary_zones: Vec::new(),
            tsig_keys: Vec::new(),
            transfer: TransferSettings::default(),
            update: UpdateSettings::default(),
            response_cache: ResponseCacheSettings::default(),
        }
    }
}

impl Config {
    /// Читает конфигурацию из файла.
    ///
    /// Формат выбирается по расширению: `.toml` (рекомендуемый) или `.json`
    /// (legacy-совместимость). Расширение сравнивается без учёта регистра.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Read`] при ошибке чтения файла,
    /// [`ConfigError::UnsupportedFormat`] для неизвестного расширения,
    /// [`ConfigError::Parse`] при некорректном синтаксисе или схеме (в
    /// сообщении есть путь, строка и колонка).
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let extension = path
            .extension()
            .and_then(std::ffi::OsStr::to_str)
            .map(str::to_ascii_lowercase);
        let parsed = match extension.as_deref() {
            Some("toml") => Self::from_toml_str(&text),
            Some("json") => Self::from_json_str(&text),
            _ => {
                return Err(ConfigError::UnsupportedFormat {
                    path: path.to_path_buf(),
                });
            }
        };
        parsed.map_err(|error| error.with_path(path))
    }

    /// Устаревший псевдоним [`Config::from_path`].
    ///
    /// # Errors
    ///
    /// См. [`Config::from_path`].
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        Self::from_path(path)
    }

    /// Разбирает конфигурацию из строки TOML (основной формат).
    ///
    /// # Errors
    ///
    /// [`ConfigError::Parse`] при некорректном TOML или схеме.
    pub fn from_toml_str(text: &str) -> Result<Self, ConfigError> {
        toml::from_str(text).map_err(|source| ConfigError::Parse {
            path: PathBuf::from("<inline>"),
            source: ParseSource::Toml(source),
        })
    }

    /// Разбирает конфигурацию из строки JSON (legacy-формат).
    ///
    /// # Errors
    ///
    /// [`ConfigError::Parse`] при некорректном JSON или схеме.
    pub fn from_json_str(text: &str) -> Result<Self, ConfigError> {
        serde_json::from_str(text).map_err(|source| ConfigError::Parse {
            path: PathBuf::from("<inline>"),
            source: ParseSource::Json(source),
        })
    }

    /// Сериализует конфигурацию в TOML (например, для дампа или примера).
    ///
    /// # Errors
    ///
    /// [`ConfigError::Serialize`], если значение нельзя представить в TOML.
    pub fn to_toml_string(&self) -> Result<String, ConfigError> {
        toml::to_string(self).map_err(ConfigError::Serialize)
    }

    /// Путь write-ahead журнала, если он включён и есть zonefile.
    #[must_use]
    pub fn journal_file(&self) -> Option<PathBuf> {
        if !self.journal {
            return None;
        }
        // Журнал без zonefile нечего восстанавливать; мутации и так
        // возвращают `storage-error`.
        self.zonefile.as_ref()?;
        match &self.journal_path {
            Some(path) => Some(path.clone()),
            None => self.zonefile.as_ref().map(|path| {
                let mut name = path.as_os_str().to_owned();
                name.push(pulse_api::JOURNAL_SUFFIX);
                PathBuf::from(name)
            }),
        }
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
        let dns_configured = self.listen_udp.is_some()
            || self.listen_tcp.is_some()
            || self.dot_listen.is_some()
            || self.doh_listen.is_some()
            || self.doh_h2_listen.is_some()
            || self.doh3_listen.is_some()
            || self.doq_listen.is_some()
            || self.dnscrypt_listen.is_some()
            || self.dnscrypt_tcp_listen.is_some();
        if self.role.serves_dns() && !dns_configured {
            return Err(ConfigError::Invalid(
                "at least one of listen_udp/listen_tcp/dot_listen/doh_listen/\
                 doh_h2_listen/doh3_listen/doq_listen/dnscrypt_listen/dnscrypt_tcp_listen must be set"
                    .to_owned(),
            ));
        }
        if self.role == Role::Api && self.api_listen.is_none() {
            return Err(ConfigError::Invalid(
                "role=api requires api_listen (or --api-listen)".to_owned(),
            ));
        }
        self.validate_tls()?;
        self.validate_dnscrypt()?;
        self.validate_dnssec()?;
        if self.workers > 1024 {
            return Err(ConfigError::Invalid(format!(
                "workers must be in 0..=1024, got {}",
                self.workers
            )));
        }
        if self.tcp_workers > 1024 {
            return Err(ConfigError::Invalid(format!(
                "tcp_workers must be in 0..=1024, got {}",
                self.tcp_workers
            )));
        }
        if self.busy_poll_us > 1_000_000 {
            return Err(ConfigError::Invalid(format!(
                "busy_poll_us must be in 0..=1000000, got {}",
                self.busy_poll_us
            )));
        }
        if self.request_timeout_ms == 0 || self.request_timeout_ms > 600_000 {
            return Err(ConfigError::Invalid(format!(
                "request_timeout_ms must be in 1..=600000, got {}",
                self.request_timeout_ms
            )));
        }
        if self.dns_workers.is_some_and(|workers| workers > 1024) {
            return Err(ConfigError::Invalid(format!(
                "dns_workers must be in 0..=1024, got {}",
                self.dns_workers.unwrap_or_default()
            )));
        }
        if let Some(workers) = self.api_workers
            && !(1..=65_535).contains(&workers)
        {
            return Err(ConfigError::Invalid(format!(
                "api_workers must be in 1..=65535, got {workers}"
            )));
        }
        self.validate_cpu_affinity()?;
        if self.api_rate_limit_per_sec == 0 {
            return Err(ConfigError::Invalid(
                "api_rate_limit_per_sec must be greater than zero".to_owned(),
            ));
        }
        if self.zone_poll_ms > 60_000 {
            return Err(ConfigError::Invalid(format!(
                "zone_poll_ms must be in 0..=60000, got {}",
                self.zone_poll_ms
            )));
        }
        if self.response_cache.enabled {
            if self.response_cache.max_entries == 0 {
                return Err(ConfigError::Invalid(
                    "response_cache.max_entries must be greater than zero".to_owned(),
                ));
            }
            if self.response_cache.max_bytes < 4096 {
                return Err(ConfigError::Invalid(format!(
                    "response_cache.max_bytes must be at least 4096, got {}",
                    self.response_cache.max_bytes
                )));
            }
            if !(1..=pulse_server::MAX_SHARDS).contains(&self.response_cache.shards) {
                return Err(ConfigError::Invalid(format!(
                    "response_cache.shards must be in 1..={}, got {}",
                    pulse_server::MAX_SHARDS,
                    self.response_cache.shards
                )));
            }
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
        if self.journal {
            if self
                .journal_path
                .as_ref()
                .is_some_and(|path| path.as_os_str().is_empty())
            {
                return Err(ConfigError::Invalid(
                    "journal_path must not be empty".to_owned(),
                ));
            }
            if self.journal_max_bytes < 4096 {
                return Err(ConfigError::Invalid(format!(
                    "journal_max_bytes must be at least 4096, got {}",
                    self.journal_max_bytes
                )));
            }
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
        self.update.validate(&key_names)?;
        if self.update.enabled && self.zonefile.is_none() {
            return Err(ConfigError::Invalid(
                "update.enabled requires a zonefile; pass --data <file>".to_owned(),
            ));
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

    /// Число DNS worker'ов с учётом `dns_workers` (роль `dns`/`all`).
    #[must_use]
    pub fn effective_dns_workers(&self) -> usize {
        self.dns_workers.unwrap_or(self.workers)
    }

    /// Проверяет списки CPU: границы, дубликаты и пересечение DNS/API.
    fn validate_cpu_affinity(&self) -> Result<(), ConfigError> {
        for (label, cpus) in [
            ("dns_cpu_affinity", &self.dns_cpu_affinity),
            ("api_cpu_affinity", &self.api_cpu_affinity),
        ] {
            let mut seen = std::collections::HashSet::with_capacity(cpus.len());
            for &cpu in cpus {
                if cpu >= MAX_CPU {
                    return Err(ConfigError::Invalid(format!(
                        "{label}: CPU {cpu} is outside 0..{MAX_CPU}"
                    )));
                }
                if !seen.insert(cpu) {
                    return Err(ConfigError::Invalid(format!(
                        "{label}: duplicate CPU {cpu}"
                    )));
                }
            }
        }
        if self
            .dns_cpu_affinity
            .iter()
            .any(|cpu| self.api_cpu_affinity.contains(cpu))
        {
            return Err(ConfigError::Invalid(
                "dns_cpu_affinity and api_cpu_affinity overlap".to_owned(),
            ));
        }
        Ok(())
    }

    /// Проверяет параметры DoT/DoH/DoQ.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`], если включён защищённый транспорт без
    /// TLS-пары, лимиты выходят за допустимые пределы или ACL содержит
    /// некорректный CIDR.
    #[allow(clippy::too_many_lines)]
    pub fn validate_tls(&self) -> Result<(), ConfigError> {
        let enabled = self.dot_listen.is_some()
            || self.doh_listen.is_some()
            || self.doh_h2_listen.is_some()
            || self.doh3_listen.is_some()
            || self.doq_listen.is_some();
        if enabled && (self.tls_cert.is_none() || self.tls_key.is_none()) {
            return Err(ConfigError::Invalid(
                "dot_listen/doh_listen/doh_h2_listen/doh3_listen/doq_listen require both tls_cert and tls_key"
                    .to_owned(),
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
        if !(1..=65_535).contains(&self.doh_h2_max_connections) {
            return Err(ConfigError::Invalid(format!(
                "doh_h2_max_connections must be in 1..=65535, got {}",
                self.doh_h2_max_connections
            )));
        }
        if !(1..=1000).contains(&self.doh_h2_max_streams) {
            return Err(ConfigError::Invalid(format!(
                "doh_h2_max_streams must be in 1..=1000, got {}",
                self.doh_h2_max_streams
            )));
        }
        if !(1..=65_535).contains(&self.doh3_max_connections) {
            return Err(ConfigError::Invalid(format!(
                "doh3_max_connections must be in 1..=65535, got {}",
                self.doh3_max_connections
            )));
        }
        if !(1..=1000).contains(&self.doh3_max_concurrent_requests) {
            return Err(ConfigError::Invalid(format!(
                "doh3_max_concurrent_requests must be in 1..=1000, got {}",
                self.doh3_max_concurrent_requests
            )));
        }
        if !(100..=600_000).contains(&self.doh3_idle_timeout_ms) {
            return Err(ConfigError::Invalid(format!(
                "doh3_idle_timeout_ms must be in 100..=600000, got {}",
                self.doh3_idle_timeout_ms
            )));
        }
        if !(1..=65_535).contains(&self.doq_max_connections) {
            return Err(ConfigError::Invalid(format!(
                "doq_max_connections must be in 1..=65535, got {}",
                self.doq_max_connections
            )));
        }
        if !(1..=1000).contains(&self.doq_max_streams) {
            return Err(ConfigError::Invalid(format!(
                "doq_max_streams must be in 1..=1000, got {}",
                self.doq_max_streams
            )));
        }
        if !(100..=600_000).contains(&self.doq_idle_timeout_ms) {
            return Err(ConfigError::Invalid(format!(
                "doq_idle_timeout_ms must be in 100..=600000, got {}",
                self.doq_idle_timeout_ms
            )));
        }
        if !(512..=65_535).contains(&self.doq_max_message_size) {
            return Err(ConfigError::Invalid(format!(
                "doq_max_message_size must be in 512..=65535, got {}",
                self.doq_max_message_size
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
        if self.dnscrypt_listen.is_none() && self.dnscrypt_tcp_listen.is_none() {
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
                        "dnscrypt listener requires {field}"
                    )));
                }
            }
        }
        if !(1..=65_535).contains(&self.dnscrypt_tcp_max_connections) {
            return Err(ConfigError::Invalid(format!(
                "dnscrypt_tcp_max_connections must be in 1..=65535, got {}",
                self.dnscrypt_tcp_max_connections
            )));
        }
        if !(100..=600_000).contains(&self.dnscrypt_tcp_idle_timeout_ms) {
            return Err(ConfigError::Invalid(format!(
                "dnscrypt_tcp_idle_timeout_ms must be in 100..=600000, got {}",
                self.dnscrypt_tcp_idle_timeout_ms
            )));
        }
        if !(512..=65_535).contains(&self.dnscrypt_tcp_max_frame) {
            return Err(ConfigError::Invalid(format!(
                "dnscrypt_tcp_max_frame must be in 512..=65535, got {}",
                self.dnscrypt_tcp_max_frame
            )));
        }
        Ok(())
    }

    /// Проверяет параметры DNSSEC-подписи.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] при некорректном denial/соли/итерациях.
    pub fn validate_dnssec(&self) -> Result<(), ConfigError> {
        for (origin, zone) in &self.dnssec {
            let denial = zone.denial.unwrap_or_default();
            match denial {
                DnssecDenial::Nsec => {
                    if zone.nsec3_salt.is_some() || zone.nsec3_iterations.is_some() {
                        return Err(ConfigError::Invalid(format!(
                            "dnssec zone {origin}: nsec3_salt/nsec3_iterations require denial=nsec3"
                        )));
                    }
                    if zone.nsec3_opt_out == Some(true) {
                        return Err(ConfigError::Invalid(format!(
                            "dnssec zone {origin}: nsec3_opt_out requires denial=nsec3"
                        )));
                    }
                }
                DnssecDenial::Nsec3 => {
                    if let Some(salt) = &zone.nsec3_salt {
                        let decoded = hex::decode(salt.trim()).map_err(|error| {
                            ConfigError::Invalid(format!(
                                "dnssec zone {origin}: nsec3_salt is not hex: {error}"
                            ))
                        })?;
                        if decoded.len() > usize::from(u8::MAX) {
                            return Err(ConfigError::Invalid(format!(
                                "dnssec zone {origin}: nsec3_salt is {} octets long (max 255)",
                                decoded.len()
                            )));
                        }
                    }
                    if let Some(iterations) = zone.nsec3_iterations
                        && iterations > pulse_dnssec::denial::MAX_NSEC3_ITERATIONS
                    {
                        return Err(ConfigError::Invalid(format!(
                            "dnssec zone {origin}: nsec3_iterations {} exceed limit {}",
                            iterations,
                            pulse_dnssec::denial::MAX_NSEC3_ITERATIONS
                        )));
                    }
                }
            }
            if let Some(rotation) = &zone.rotation {
                if rotation.key_dir.as_os_str().is_empty()
                    || rotation.state_path.as_os_str().is_empty()
                {
                    return Err(ConfigError::Invalid(format!(
                        "dnssec zone {origin}: rotation key_dir/state_path must not be empty"
                    )));
                }
                if let Some(algorithm) = rotation.algorithm
                    && !pulse_dnssec::Algorithm::from_u8(algorithm).is_sign_supported()
                {
                    return Err(ConfigError::Invalid(format!(
                        "dnssec zone {origin}: rotation algorithm {algorithm} is not supported for signing"
                    )));
                }
                for (name, value) in [
                    ("pre_publish_secs", rotation.pre_publish_secs),
                    ("double_sign_secs", rotation.double_sign_secs),
                    ("retire_secs", rotation.retire_secs),
                    ("tick_secs", rotation.tick_secs),
                ] {
                    if value == Some(0) {
                        return Err(ConfigError::Invalid(format!(
                            "dnssec zone {origin}: rotation {name} must be non-zero"
                        )));
                    }
                }
                let pre = u64::from(rotation.pre_publish_secs.unwrap_or(86_400));
                let double = u64::from(rotation.double_sign_secs.unwrap_or(86_400));
                let zsk = u64::from(rotation.zsk_lifetime_days.unwrap_or(90)) * 86_400;
                let ksk = u64::from(rotation.ksk_lifetime_days.unwrap_or(365)) * 86_400;
                if zsk <= pre + double || ksk <= pre + double {
                    return Err(ConfigError::Invalid(format!(
                        "dnssec zone {origin}: rotation lifetime must exceed pre_publish + double_sign"
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
    #[allow(clippy::too_many_lines)]
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
        if let Some(addr) = overrides.doh_h2_listen {
            self.doh_h2_listen = Some(addr);
        }
        if let Some(addr) = overrides.doh3_listen {
            self.doh3_listen = Some(addr);
        }
        if let Some(addr) = overrides.doq_listen {
            self.doq_listen = Some(addr);
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
        if let Some(addr) = overrides.dnscrypt_tcp_listen {
            self.dnscrypt_tcp_listen = Some(addr);
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
        if let Some(role) = overrides.role {
            self.role = role;
        }
        if let Some(workers) = overrides.dns_workers {
            self.dns_workers = Some(workers);
        }
        if let Some(workers) = overrides.api_workers {
            self.api_workers = Some(workers);
        }
        if let Some(cpus) = &overrides.dns_cpu_affinity {
            self.dns_cpu_affinity.clone_from(cpus);
        }
        if let Some(cpus) = &overrides.api_cpu_affinity {
            self.api_cpu_affinity.clone_from(cpus);
        }
        if let Some(policy) = overrides.huge_pages {
            self.huge_pages = policy;
        }
        if let Some(poll_ms) = overrides.zone_poll_ms {
            self.zone_poll_ms = poll_ms;
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
        self.apply_response_cache_overrides(overrides);
        if let Some(enabled) = overrides.update_enabled {
            self.update.enabled = enabled;
        }
        if let Some(require) = overrides.update_require_tsig {
            self.update.require_tsig = require;
        }
        if !overrides.update_allow_from.is_empty() {
            self.update
                .allow_from
                .clone_from(&overrides.update_allow_from);
        }
        if !overrides.update_zones.is_empty() {
            self.update.allow_zones.clone_from(&overrides.update_zones);
        }
    }

    fn apply_response_cache_overrides(&mut self, overrides: &Overrides) {
        if let Some(enabled) = overrides.response_cache {
            self.response_cache.enabled = enabled;
        }
        if let Some(entries) = overrides.response_cache_max_entries {
            self.response_cache.max_entries = entries;
        }
        if let Some(bytes) = overrides.response_cache_max_bytes {
            self.response_cache.max_bytes = bytes;
        }
        if let Some(shards) = overrides.response_cache_shards {
            self.response_cache.shards = shards;
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
    /// Новый адрес DoH/HTTP/2.
    pub doh_h2_listen: Option<SocketAddr>,
    /// Новый адрес DoH/HTTP/3.
    pub doh3_listen: Option<SocketAddr>,
    /// Новый адрес DoQ.
    pub doq_listen: Option<SocketAddr>,
    /// Новый PEM-сертификат DoT/DoH.
    pub tls_cert: Option<PathBuf>,
    /// Новый PEM-ключ DoT/DoH.
    pub tls_key: Option<PathBuf>,
    /// Новый период перечитывания TLS-сертификата.
    pub tls_reload_secs: Option<u64>,
    /// Новый IP/CIDR allowlist DoT/DoH.
    pub tls_allow_from: Vec<String>,
    /// Новый адрес DNSCrypt (UDP).
    pub dnscrypt_listen: Option<SocketAddr>,
    /// Новый адрес DNSCrypt over TCP.
    pub dnscrypt_tcp_listen: Option<SocketAddr>,
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
    /// Новая роль процесса.
    pub role: Option<Role>,
    /// Новое число DNS worker'ов.
    pub dns_workers: Option<usize>,
    /// Новый лимит API-соединений (API worker'ов).
    pub api_workers: Option<usize>,
    /// Новый список CPU для DNS worker'ов.
    pub dns_cpu_affinity: Option<Vec<usize>>,
    /// Новый список CPU для REST API.
    pub api_cpu_affinity: Option<Vec<usize>>,
    /// Новая политика huge pages.
    pub huge_pages: Option<HugePagesSetting>,
    /// Новый интервал опроса зон ролью `dns`.
    pub zone_poll_ms: Option<u64>,
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
    /// Включить/выключить кеш ответов.
    pub response_cache: Option<bool>,
    /// Максимум записей кеша ответов.
    pub response_cache_max_entries: Option<usize>,
    /// Максимум памяти кеша ответов.
    pub response_cache_max_bytes: Option<u64>,
    /// Число шардов кеша ответов.
    pub response_cache_shards: Option<usize>,
    /// Включить/выключить DNS UPDATE.
    pub update_enabled: Option<bool>,
    /// Требовать TSIG для UPDATE.
    pub update_require_tsig: Option<bool>,
    /// IP/CIDR allowlist UPDATE.
    pub update_allow_from: Vec<String>,
    /// Allowlist зон UPDATE.
    pub update_zones: Vec<String>,
}

/// Причина ошибки разбора конфигурационного файла.
///
/// Оба формата сообщают позицию (строка/колонка) в своём `Display`.
#[derive(Debug, Error)]
pub enum ParseSource {
    /// Ошибка JSON (legacy-формат).
    #[error("{0}")]
    Json(#[from] serde_json::Error),
    /// Ошибка TOML (основной формат).
    #[error("{0}")]
    Toml(#[from] toml::de::Error),
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
    /// Содержимое не соответствует схеме.
    #[error("invalid configuration {path}: {source}")]
    Parse {
        /// Путь к файлу (или `<inline>`).
        path: PathBuf,
        /// Причина.
        #[source]
        source: ParseSource,
    },
    /// Не удалось сериализовать конфигурацию в TOML.
    #[error("cannot serialize configuration: {0}")]
    Serialize(#[source] toml::ser::Error),
    /// Расширение файла не `.toml` и не `.json`.
    #[error(
        "unsupported configuration file {path}: expected a .toml file (recommended) or a .json file (legacy compatibility); rename the file or pass --config <path>.toml"
    )]
    UnsupportedFormat {
        /// Путь к файлу.
        path: PathBuf,
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
        assert_eq!(config.tcp_workers, 0);
        assert!(config.tcp_nodelay);
        assert_eq!(config.busy_poll_us, 0);
        assert_eq!(config.request_timeout_ms, 10_000);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn tcp_tuning_fields_roundtrip_and_validate() {
        let config = Config::from_toml_str(
            "listen_udp = \"127.0.0.1:0\"\n\
             tcp_workers = 4\n\
             tcp_nodelay = false\n\
             busy_poll_us = 50\n\
             request_timeout_ms = 2500\n",
        )
        .expect("tuning parses");
        assert_eq!(config.tcp_workers, 4);
        assert!(!config.tcp_nodelay);
        assert_eq!(config.busy_poll_us, 50);
        assert_eq!(config.request_timeout_ms, 2500);
        assert!(config.validate().is_ok());

        let invalid =
            Config::from_toml_str("listen_udp = \"127.0.0.1:0\"\nrequest_timeout_ms = 0\n")
                .expect("parse without validation");
        assert!(invalid.validate().is_err());
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
            doh_h2_listen: None,
            doh3_listen: None,
            doq_listen: None,
            tls_cert: None,
            tls_key: None,
            tls_reload_secs: None,
            tls_allow_from: Vec::new(),
            dnscrypt_listen: None,
            dnscrypt_tcp_listen: None,
            dnscrypt_provider_key: None,
            dnscrypt_resolver_key: None,
            dnscrypt_cert: None,
            dnscrypt_provider_name: None,
            workers: Some(3),
            role: None,
            dns_workers: None,
            api_workers: None,
            dns_cpu_affinity: None,
            api_cpu_affinity: None,
            huge_pages: None,
            zone_poll_ms: None,
            log_level: Some(LogLevel::Debug),
            zonefile: None,
            durability: Some(Durability::Sync),
            commit_mode: Some(CommitMode::Group),
            map_size: Some(64 * 1024 * 1024),
            response_cache: Some(false),
            response_cache_max_entries: Some(1024),
            response_cache_max_bytes: Some(2 * 1024 * 1024),
            response_cache_shards: Some(4),
            update_enabled: None,
            update_require_tsig: None,
            update_allow_from: Vec::new(),
            update_zones: Vec::new(),
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
    fn doh_h2_and_doq_configuration_is_validated() {
        let mut config = Config {
            listen_udp: None,
            listen_tcp: None,
            doh_h2_listen: Some("127.0.0.1:8443".parse().unwrap()),
            doh3_listen: Some("127.0.0.1:8445".parse().unwrap()),
            doq_listen: Some("127.0.0.1:8853".parse().unwrap()),
            ..Config::default()
        };
        let error = config.validate().unwrap_err().to_string();
        assert!(
            error.contains("require both tls_cert and tls_key"),
            "{error}"
        );

        config.tls_cert = Some(PathBuf::from("cert.pem"));
        config.tls_key = Some(PathBuf::from("key.pem"));
        assert!(config.validate().is_ok());

        config.doh_h2_max_streams = 0;
        assert!(config.validate().is_err());
        config.doh_h2_max_streams = 100;
        config.doh3_max_connections = 0;
        assert!(config.validate().is_err());
        config.doh3_max_connections = 1024;
        config.doh3_max_concurrent_requests = 1001;
        assert!(config.validate().is_err());
        config.doh3_max_concurrent_requests = 100;
        config.doh3_idle_timeout_ms = 10;
        assert!(config.validate().is_err());
        config.doh3_idle_timeout_ms = 30_000;
        config.doq_max_streams = 1001;
        assert!(config.validate().is_err());
        config.doq_max_streams = 100;
        config.doq_idle_timeout_ms = 10;
        assert!(config.validate().is_err());
        config.doq_idle_timeout_ms = 30_000;
        config.doq_max_message_size = 128;
        assert!(config.validate().is_err());
        config.doq_max_message_size = 65_535;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn h2_and_doq_overrides_apply() {
        let mut config = Config::default();
        let h2: SocketAddr = "127.0.0.1:9443".parse().unwrap();
        let h3: SocketAddr = "127.0.0.1:9445".parse().unwrap();
        let doq: SocketAddr = "127.0.0.1:9853".parse().unwrap();
        config.apply_overrides(&Overrides {
            doh_h2_listen: Some(h2),
            doh3_listen: Some(h3),
            doq_listen: Some(doq),
            ..Overrides::default()
        });
        assert_eq!(config.doh_h2_listen, Some(h2));
        assert_eq!(config.doh3_listen, Some(h3));
        assert_eq!(config.doq_listen, Some(doq));
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

    #[test]
    fn dnscrypt_tcp_requires_material_and_valid_limits() {
        let mut config = Config {
            listen_udp: None,
            listen_tcp: None,
            dnscrypt_tcp_listen: Some("127.0.0.1:5444".parse().unwrap()),
            ..Config::default()
        };
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("dnscrypt_provider_key"), "{error}");

        config.dnscrypt_provider_key = Some(PathBuf::from("provider.key"));
        config.dnscrypt_resolver_key = Some(PathBuf::from("resolver.key"));
        config.dnscrypt_cert = Some(PathBuf::from("cert.json"));
        assert!(config.validate().is_ok());

        config.dnscrypt_tcp_max_connections = 0;
        assert!(config.validate().is_err());
        config.dnscrypt_tcp_max_connections = 1024;
        config.dnscrypt_tcp_idle_timeout_ms = 10;
        assert!(config.validate().is_err());
        config.dnscrypt_tcp_idle_timeout_ms = 10_000;
        config.dnscrypt_tcp_max_frame = 128;
        assert!(config.validate().is_err());
        config.dnscrypt_tcp_max_frame = 65_535;
        assert!(config.validate().is_ok());
    }

    fn example_configs() -> Vec<(&'static str, Config, Config)> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples");
        [
            "pulsed",
            "persistent",
            "empty",
            "transports",
            "pair-primary",
            "pair-secondary",
            "dnssec-rotation",
            "transfer",
        ]
        .into_iter()
        .map(|name| {
            let toml = Config::from_path(root.join(format!("{name}.toml")))
                .unwrap_or_else(|error| panic!("{name}.toml: {error}"));
            let json = Config::from_path(root.join(format!("{name}.json")))
                .unwrap_or_else(|error| panic!("{name}.json: {error}"));
            (name, toml, json)
        })
        .collect()
    }

    #[test]
    fn toml_and_json_examples_are_equivalent() {
        for (name, toml, json) in example_configs() {
            assert_eq!(
                serde_json::to_value(&toml).expect("serialize toml config"),
                serde_json::to_value(&json).expect("serialize json config"),
                "{name}: TOML и JSON должны быть эквивалентны"
            );
        }
    }

    #[test]
    fn toml_round_trip_preserves_examples() {
        for (name, config, _) in example_configs() {
            let rendered = config.to_toml_string().expect("serialize toml");
            let reparsed = Config::from_toml_str(&rendered).expect("reparse rendered toml");
            assert_eq!(
                serde_json::to_value(&config).expect("serialize original"),
                serde_json::to_value(&reparsed).expect("serialize reparsed"),
                "{name}: round-trip через TOML должен сохранять конфигурацию"
            );
        }
    }

    #[test]
    fn toml_examples_parse_and_validate() {
        for (name, config, _) in example_configs() {
            config
                .validate()
                .unwrap_or_else(|error| panic!("{name}: {error}"));
        }
    }

    #[allow(clippy::too_many_lines)]
    #[test]
    fn toml_supports_all_sections() {
        let text = r#"
listen_udp = "127.0.0.1:5353"
listen_tcp = "127.0.0.1:5354"
dot_listen = "127.0.0.1:8853"
doh_listen = "127.0.0.1:8443"
doh_h2_listen = "127.0.0.1:8444"
doq_listen = "127.0.0.1:8854"
tls_cert = "cert.pem"
tls_key = "key.pem"
tls_reload_secs = 60
tls_allow_from = ["127.0.0.0/8", "::1"]
dot_max_connections = 10
doh_max_connections = 11
doh_h2_max_connections = 12
doh_h2_max_streams = 13
doq_max_connections = 14
doq_max_streams = 15
doq_idle_timeout_ms = 1000
doq_max_message_size = 4096
dnscrypt_listen = "127.0.0.1:5443"
dnscrypt_tcp_listen = "127.0.0.1:5444"
dnscrypt_provider_key = "provider.key"
dnscrypt_resolver_key = "resolver.key"
dnscrypt_cert = "dnscrypt-cert.json"
dnscrypt_provider_name = "2.dnscrypt-cert.example.com."
dnscrypt_tcp_max_connections = 16
dnscrypt_tcp_idle_timeout_ms = 2000
dnscrypt_tcp_max_frame = 65535
api_listen = "127.0.0.1:8080"
api_token = "secret-token"
api_scope = ["example.com.", "*.internal."]
workers = 4
log_level = "debug"
zonefile = "zones.pulse"
durability = "sync"
commit_mode = "group"
map_size = 1048576

[tcp]
max_connections = 32
idle_timeout_ms = 1000

[[tsig_keys]]
name = "xfr-key.example.com."
algorithm = "hmac-sha512"
secret = "c2VjcmV0"

[[secondary_zones]]
origin = "secondary.example."
masters = ["192.0.2.1:53", "[2001:db8::1]:53"]
tsig_key = "xfr-key.example.com."
refresh = 60
retry = 10
expire = 604800
allow_notify_from = ["192.0.2.1", "2001:db8::1"]
bootstrap = false

[transfer]
enabled = true
require_tsig = true
allow_from = ["192.0.2.1"]
allow_zones = ["example.com."]
history_deltas = 8
message_bytes = 4096
max_records = 100
max_bytes = 1048576
max_messages = 10
timeout_ms = 1000
tsig_every = 2
allow_axfr_fallback = false
notify = ["192.0.2.10:53"]
notify_tsig_key = "xfr-key.example.com."
notify_retries = 1
notify_timeout_ms = 500
notify_queue = 16

[dnssec."example.com."]
validity_days = 14
inception_skew = 120
denial = "nsec3"
nsec3_salt = "aabb"
nsec3_iterations = 5
nsec3_opt_out = true

[[dnssec."example.com.".keys]]
role = "ksk"
path = "keys/ksk.private"
algorithm = 15
flags = 257

[[dnssec."example.com.".keys]]
role = "zsk"
path = "keys/zsk.private"

[dnssec."example.com.".rotation]
key_dir = "keys/rotation"
state_path = "keys/rotation/state.json"
algorithm = 15
zsk_lifetime_days = 90
ksk_lifetime_days = 365
pre_publish_secs = 86400
double_sign_secs = 86400
retire_secs = 604800
tick_secs = 300
"#;
        let config = Config::from_toml_str(text).expect("all sections");
        config.validate().expect("all-sections config is valid");

        assert_eq!(
            config.listen_udp,
            Some("127.0.0.1:5353".parse().expect("addr"))
        );
        assert_eq!(
            config.listen_tcp,
            Some("127.0.0.1:5354".parse().expect("addr"))
        );
        assert_eq!(config.dot_listen, Some("127.0.0.1:8853".parse().unwrap()));
        assert_eq!(config.doh_listen, Some("127.0.0.1:8443".parse().unwrap()));
        assert_eq!(
            config.doh_h2_listen,
            Some("127.0.0.1:8444".parse().unwrap())
        );
        assert_eq!(config.doq_listen, Some("127.0.0.1:8854".parse().unwrap()));
        assert_eq!(config.tls_reload_secs, Some(60));
        assert_eq!(config.doh_h2_max_streams, 13);
        assert_eq!(config.doq_max_message_size, 4096);
        assert_eq!(config.dnscrypt_tcp_max_connections, 16);
        assert_eq!(config.api_listen, Some("127.0.0.1:8080".parse().unwrap()));
        assert_eq!(config.api_token.as_deref(), Some("secret-token"));
        assert_eq!(config.api_scope, vec!["example.com.", "*.internal."]);
        assert_eq!(config.workers, 4);
        assert_eq!(config.log_level, LogLevel::Debug);
        assert_eq!(config.durability, Durability::Sync);
        assert_eq!(config.commit_mode, CommitMode::Group);
        assert_eq!(config.map_size, 1_048_576);
        assert_eq!(config.tcp.max_connections, 32);
        assert_eq!(config.tcp.idle_timeout_ms, 1000);
        assert_eq!(config.tsig_keys[0].algorithm, "hmac-sha512");
        assert_eq!(config.secondary_zones[0].masters.len(), 2);
        assert_eq!(config.secondary_zones[0].refresh, Some(60));
        assert!(!config.secondary_zones[0].bootstrap);
        assert_eq!(config.transfer.history_deltas, 8);
        assert_eq!(config.transfer.tsig_every, 2);
        assert!(!config.transfer.allow_axfr_fallback);
        assert_eq!(config.transfer.notify_retries, 1);
        let zone = config.dnssec.get("example.com.").expect("dnssec zone");
        assert_eq!(zone.denial, Some(DnssecDenial::Nsec3));
        assert_eq!(zone.nsec3_iterations, Some(5));
        assert_eq!(zone.keys.len(), 2);
        assert_eq!(zone.keys[0].role, Some(DnssecKeyRole::Ksk));
        assert_eq!(zone.keys[0].algorithm, Some(15));
        assert_eq!(zone.keys[0].flags, Some(257));
        let rotation = zone.rotation.as_ref().expect("rotation");
        assert_eq!(rotation.zsk_lifetime_days, Some(90));

        let rendered = config.to_toml_string().expect("serialize all sections");
        let reparsed = Config::from_toml_str(&rendered).expect("reparse all sections");
        assert_eq!(
            serde_json::to_value(&config).expect("serialize original"),
            serde_json::to_value(&reparsed).expect("serialize reparsed")
        );
    }

    #[test]
    fn default_config_round_trips_through_toml() {
        let config = Config::default();
        let rendered = config.to_toml_string().expect("serialize default config");
        let reparsed = Config::from_toml_str(&rendered).expect("reparse default config");
        assert_eq!(config, reparsed);
    }

    #[test]
    fn toml_accepts_api_scopes_alias() {
        let config = Config::from_toml_str(
            "listen_udp = \"127.0.0.1:0\"\napi_scopes = [\"example.com.\"]\n",
        )
        .expect("alias parses");
        assert_eq!(config.api_scope, vec!["example.com."]);
        let rendered = config.to_toml_string().expect("serialize");
        assert!(rendered.contains("api_scope"), "{rendered}");
        assert!(!rendered.contains("api_scopes"), "{rendered}");
    }

    #[test]
    fn config_extension_is_case_insensitive() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("Config.TOML");
        std::fs::write(&path, "listen_udp = \"127.0.0.1:0\"\n").expect("write config");
        let config = Config::from_path(&path).expect("uppercase toml extension");
        assert!(config.listen_udp.is_some());
    }

    #[test]
    fn unknown_extension_is_rejected_with_hint() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("pulsed.yaml");
        std::fs::write(&path, "listen_udp: 127.0.0.1:5353\n").expect("write config");
        let error = Config::from_path(&path).expect_err("yaml must be rejected");
        let message = error.to_string();
        assert!(
            message.contains(path.to_str().expect("utf8 path")),
            "{message}"
        );
        assert!(message.contains("a .toml file (recommended)"), "{message}");
        assert!(
            message.contains("a .json file (legacy compatibility)"),
            "{message}"
        );
    }

    #[test]
    fn toml_unknown_field_reports_path_line_and_column() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("bad.toml");
        std::fs::write(&path, "listen_udp = \"127.0.0.1:0\"\nwat = 1\n").expect("write config");
        let error = Config::from_path(&path).expect_err("unknown field must be rejected");
        let message = error.to_string();
        assert!(
            message.contains(path.to_str().expect("utf8 path")),
            "{message}"
        );
        assert!(message.contains("unknown field `wat`"), "{message}");
        assert!(message.contains("line 2"), "{message}");
        assert!(message.contains("column 1"), "{message}");
    }

    #[test]
    fn toml_bad_type_reports_position() {
        let error = Config::from_toml_str("listen_udp = \"127.0.0.1:0\"\nworkers = \"many\"\n")
            .expect_err("bad type must be rejected");
        let message = error.to_string();
        assert!(message.contains("invalid type"), "{message}");
        assert!(message.contains("line 2"), "{message}");
        assert!(message.contains("column"), "{message}");
    }

    #[test]
    fn toml_syntax_error_reports_position() {
        let error = Config::from_toml_str("listen_udp = \"127.0.0.1:0\n")
            .expect_err("unterminated string must be rejected");
        let message = error.to_string();
        assert!(message.contains("TOML parse error"), "{message}");
        assert!(message.contains("line 1"), "{message}");
        assert!(message.contains("column"), "{message}");
    }

    #[test]
    fn json_unknown_field_reports_position() {
        let error = Config::from_json_str("{\"listen_udp\": \"127.0.0.1:0\", \"wat\": 1}")
            .expect_err("unknown field must be rejected");
        let message = error.to_string();
        assert!(message.contains("unknown field `wat`"), "{message}");
        assert!(message.contains("line 1"), "{message}");
        assert!(message.contains("column"), "{message}");
    }

    #[test]
    fn cli_overrides_apply_over_toml() {
        let text = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/pulsed.toml"),
        )
        .expect("read toml example");
        let mut config = Config::from_toml_str(&text).expect("parse toml");
        config.apply_overrides(&Overrides {
            listen_udp: Some("127.0.0.2:5300".parse().expect("addr")),
            listen_tcp: Some("127.0.0.2:5301".parse().expect("addr")),
            dot_listen: Some("127.0.0.2:8853".parse().expect("addr")),
            doh_listen: Some("127.0.0.2:8443".parse().expect("addr")),
            doh_h2_listen: Some("127.0.0.2:8444".parse().expect("addr")),
            doh3_listen: Some("127.0.0.2:8445".parse().expect("addr")),
            doq_listen: Some("127.0.0.2:8854".parse().expect("addr")),
            tls_cert: Some(PathBuf::from("cli-cert.pem")),
            tls_key: Some(PathBuf::from("cli-key.pem")),
            tls_reload_secs: Some(30),
            tls_allow_from: vec!["10.0.0.0/8".to_owned()],
            dnscrypt_listen: Some("127.0.0.2:5443".parse().expect("addr")),
            dnscrypt_tcp_listen: Some("127.0.0.2:5444".parse().expect("addr")),
            dnscrypt_provider_key: Some(PathBuf::from("cli-provider.key")),
            dnscrypt_resolver_key: Some(PathBuf::from("cli-resolver.key")),
            dnscrypt_cert: Some(PathBuf::from("cli-cert.json")),
            dnscrypt_provider_name: Some("2.dnscrypt-cert.cli.example.".to_owned()),
            workers: Some(3),
            role: None,
            dns_workers: None,
            api_workers: None,
            dns_cpu_affinity: Some(vec![2, 3]),
            api_cpu_affinity: Some(vec![4]),
            huge_pages: Some(HugePagesSetting::Never),
            zone_poll_ms: None,
            log_level: Some(LogLevel::Trace),
            zonefile: Some(PathBuf::from("cli.pulse")),
            durability: Some(Durability::Memory),
            commit_mode: Some(CommitMode::Group),
            map_size: Some(64 * 1024 * 1024),
            response_cache: Some(false),
            response_cache_max_entries: Some(1024),
            response_cache_max_bytes: Some(2 * 1024 * 1024),
            response_cache_shards: Some(4),
            update_enabled: None,
            update_require_tsig: None,
            update_allow_from: Vec::new(),
            update_zones: Vec::new(),
        });
        assert_eq!(
            config.listen_udp,
            Some("127.0.0.2:5300".parse().expect("addr"))
        );
        assert_eq!(
            config.listen_tcp,
            Some("127.0.0.2:5301".parse().expect("addr"))
        );
        assert_eq!(config.dot_listen, Some("127.0.0.2:8853".parse().unwrap()));
        assert_eq!(config.doh_listen, Some("127.0.0.2:8443".parse().unwrap()));
        assert_eq!(
            config.doh_h2_listen,
            Some("127.0.0.2:8444".parse().unwrap())
        );
        assert_eq!(config.doq_listen, Some("127.0.0.2:8854".parse().unwrap()));
        assert_eq!(config.tls_cert, Some(PathBuf::from("cli-cert.pem")));
        assert_eq!(config.tls_key, Some(PathBuf::from("cli-key.pem")));
        assert_eq!(config.tls_reload_secs, Some(30));
        assert_eq!(config.tls_allow_from, vec!["10.0.0.0/8"]);
        assert_eq!(
            config.dnscrypt_provider_name.as_deref(),
            Some("2.dnscrypt-cert.cli.example.")
        );
        assert_eq!(config.workers, 3);
        assert_eq!(config.log_level, LogLevel::Trace);
        assert_eq!(config.zonefile, Some(PathBuf::from("cli.pulse")));
        assert_eq!(config.durability, Durability::Memory);
        assert_eq!(config.commit_mode, CommitMode::Group);
        assert_eq!(config.map_size, 64 * 1024 * 1024);
    }

    #[test]
    fn nsec3_options_are_validated() {
        let mut config = Config::default();
        config.dnssec.insert(
            "example.com.".to_owned(),
            DnssecZoneConfig {
                denial: Some(DnssecDenial::Nsec3),
                nsec3_salt: Some("aabb".to_owned()),
                nsec3_iterations: Some(5),
                ..DnssecZoneConfig::default()
            },
        );
        assert!(config.validate().is_ok());

        config.dnssec.insert(
            "example.com.".to_owned(),
            DnssecZoneConfig {
                denial: Some(DnssecDenial::Nsec3),
                nsec3_salt: Some("zz".to_owned()),
                ..DnssecZoneConfig::default()
            },
        );
        assert!(config.validate().is_err());

        config.dnssec.insert(
            "example.com.".to_owned(),
            DnssecZoneConfig {
                denial: Some(DnssecDenial::Nsec3),
                nsec3_iterations: Some(101),
                ..DnssecZoneConfig::default()
            },
        );
        assert!(config.validate().is_err());

        config.dnssec.insert(
            "example.com.".to_owned(),
            DnssecZoneConfig {
                denial: Some(DnssecDenial::Nsec),
                nsec3_salt: Some("aabb".to_owned()),
                ..DnssecZoneConfig::default()
            },
        );
        assert!(config.validate().is_err());
    }

    #[test]
    fn journal_defaults_and_path_override() {
        let config = Config::default();
        assert!(config.journal);
        assert_eq!(config.journal_file(), None);

        let config = Config {
            zonefile: Some(PathBuf::from("/var/lib/pulse/zones.v2")),
            ..Config::default()
        };
        assert_eq!(
            config.journal_file(),
            Some(PathBuf::from("/var/lib/pulse/zones.v2.journal"))
        );

        let config = Config {
            zonefile: Some(PathBuf::from("/var/lib/pulse/zones.v2")),
            journal_path: Some(PathBuf::from("/var/lib/pulse/outbox")),
            ..Config::default()
        };
        assert_eq!(
            config.journal_file(),
            Some(PathBuf::from("/var/lib/pulse/outbox"))
        );

        let mut config = Config {
            zonefile: Some(PathBuf::from("/var/lib/pulse/zones.v2")),
            ..Config::default()
        };
        config.journal = false;
        assert_eq!(config.journal_file(), None);

        config.journal = true;
        config.journal_max_bytes = 1024;
        assert!(config.validate().is_err());
    }

    #[test]
    fn role_parses_and_defaults_to_all() {
        assert_eq!(Config::default().role, Role::All);
        for (text, expected) in [
            ("all", Role::All),
            ("dns", Role::Dns),
            ("api", Role::Api),
            (" DNS ", Role::Dns),
        ] {
            assert_eq!(text.parse::<Role>().expect("role"), expected);
        }
        assert!("worker".parse::<Role>().is_err());
        assert!(Role::Dns.is_multi_process());
        assert!(Role::Api.is_multi_process());
        assert!(!Role::All.is_multi_process());
    }

    #[test]
    fn api_role_does_not_require_dns_transports() {
        let config = Config {
            role: Role::Api,
            listen_udp: None,
            listen_tcp: None,
            api_listen: Some("127.0.0.1:8080".parse().expect("addr")),
            ..Config::default()
        };
        assert!(config.validate().is_ok());

        let missing_api = Config {
            role: Role::Api,
            listen_udp: None,
            listen_tcp: None,
            api_listen: None,
            ..Config::default()
        };
        assert!(missing_api.validate().is_err());

        let dns_without_transport = Config {
            role: Role::Dns,
            listen_udp: None,
            listen_tcp: None,
            ..Config::default()
        };
        assert!(dns_without_transport.validate().is_err());
    }

    #[test]
    fn role_examples_parse_and_validate() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples");
        let dns = Config::from_path(root.join("pulsed-dns.toml")).expect("pulsed-dns.toml");
        assert_eq!(dns.role, Role::Dns);
        dns.validate().expect("dns role example");
        let api = Config::from_path(root.join("pulsed-api.toml")).expect("pulsed-api.toml");
        assert_eq!(api.role, Role::Api);
        assert!(api.api_listen.is_some());
        api.validate().expect("api role example");
    }

    #[test]
    fn worker_overrides_and_poll_limits_are_validated() {
        let mut config = Config {
            dns_workers: Some(3),
            workers: 7,
            ..Config::default()
        };
        assert_eq!(config.effective_dns_workers(), 3);
        config.dns_workers = None;
        assert_eq!(config.effective_dns_workers(), 7);

        config.api_workers = Some(0);
        assert!(config.validate().is_err());
        config.api_workers = Some(64);
        config.zone_poll_ms = 60_001;
        assert!(config.validate().is_err());
    }

    #[test]
    fn cpu_affinity_parses_from_array_and_string() {
        let config = Config::from_toml_str(
            r#"
listen_udp = "127.0.0.1:0"
dns_cpu_affinity = [0, 2]
api_cpu_affinity = "4-5"
"#,
        )
        .expect("parse");
        assert_eq!(config.dns_cpu_affinity, vec![0, 2]);
        assert_eq!(config.api_cpu_affinity, vec![4, 5]);
        assert_eq!(config.huge_pages, HugePagesSetting::Auto);
        config.validate().expect("valid affinity");
    }

    #[test]
    fn cpu_affinity_rejects_overlap_and_bad_cpus() {
        let base = |dns: Vec<usize>, api: Vec<usize>| Config {
            dns_cpu_affinity: dns,
            api_cpu_affinity: api,
            ..Config::default()
        };
        // Пересечение data-plane и control-plane — ошибка конфигурации.
        let overlap = base(vec![0, 1], vec![1, 2]);
        let error = overlap.validate().expect_err("overlap must be rejected");
        assert!(error.to_string().contains("overlap"), "{error}");

        // Дубликаты внутри одного списка и CPU вне маски отвергаются.
        assert!(base(vec![1, 1], Vec::new()).validate().is_err());
        assert!(base(vec![MAX_CPU], Vec::new()).validate().is_err());
        // Непересекающиеся наборы валидны.
        base(vec![0, 1], vec![2, 3]).validate().expect("disjoint");
    }

    #[test]
    fn update_settings_parse_and_validate() {
        let config = Config::from_toml_str(
            r#"
listen_udp = "127.0.0.1:0"
zonefile = "/tmp/update-config.pulse"

[[tsig_keys]]
name = "update-key.example."
algorithm = "hmac-sha256"
secret = "c2VjcmV0"

[update]
enabled = true
require_tsig = true
allow_from = ["127.0.0.1/32", "::1/128"]
allow_zones = ["example.com."]
tsig_keys = ["update-key.example."]
"#,
        )
        .expect("parse");
        assert!(config.update.enabled);
        assert_eq!(config.update.allow_from.len(), 2);
        config.validate().expect("valid update config");

        let bad_cidr = Config::from_toml_str(
            r#"
zonefile = "/tmp/update-config.pulse"
[update]
enabled = true
require_tsig = false
allow_from = ["192.0.2.0/33"]
"#,
        )
        .expect("parse");
        assert!(bad_cidr.validate().is_err());

        let unknown_key = Config::from_toml_str(
            r#"
zonefile = "/tmp/update-config.pulse"
[update]
enabled = true
require_tsig = false
tsig_keys = ["missing-key.example."]
"#,
        )
        .expect("parse");
        assert!(unknown_key.validate().is_err());

        let without_zonefile = Config::from_toml_str(
            r#"
listen_udp = "127.0.0.1:0"
[update]
enabled = true
require_tsig = false
"#,
        )
        .expect("parse");
        assert!(without_zonefile.validate().is_err());

        let example = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/pulsed-update.toml"),
        )
        .expect("read update example");
        Config::from_toml_str(&example)
            .expect("parse update example")
            .validate()
            .expect("valid update example");
    }

    #[test]
    fn huge_pages_policy_roundtrips() {
        let config = Config::from_toml_str(
            r#"
listen_udp = "127.0.0.1:0"
huge_pages = "never"
"#,
        )
        .expect("parse");
        assert_eq!(config.huge_pages, HugePagesSetting::Never);
        let dumped = config.to_toml_string().expect("serialize");
        assert!(dumped.contains("huge_pages = \"never\""), "{dumped}");
        assert_eq!(
            "always".parse::<HugePagesSetting>().unwrap(),
            HugePagesSetting::Always
        );
        assert!("sometimes".parse::<HugePagesSetting>().is_err());
    }
}
