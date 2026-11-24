//! JSON-конфигурация резолвера и CLI-overrides.
//!
//! Значения по умолчанию безопасны: резолвер запускается только с явно
//! заданным транспортом, DNSSEC выключен, blocklist пуст, HTTP-метрики
//! выключены.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use pulse_dns::{Name, Rdata, Ttl};
use pulse_resolver::{
    BlockResponse, BlocklistConfig as ResolverBlocklistConfig, CacheConfig, DnssecConfig,
    ForwardConfig, IterativeConfig, Mode, Override, ResolverConfig, TimeoutConfig,
};
use serde::Deserialize;
use serde::de::{self, Deserializer};

use crate::anchors;
use crate::error::ConfigError;

/// Режим резолюции.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModeSetting {
    /// Пересылка настроенным рекурсивным серверам.
    #[default]
    Forward,
    /// Итеративный обход от root hints.
    Iterative,
}

/// Уровень логирования.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
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
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
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

/// Политика ответа на заблокированное имя.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BlockResponseSetting {
    /// NXDOMAIN.
    #[default]
    NxDomain,
    /// Синтетический `0.0.0.0` / `::`.
    Null,
}

impl From<BlockResponseSetting> for BlockResponse {
    fn from(value: BlockResponseSetting) -> Self {
        match value {
            BlockResponseSetting::NxDomain => Self::NxDomain,
            BlockResponseSetting::Null => Self::Null {
                ipv4: Ipv4Addr::UNSPECIFIED,
                ipv6: Ipv6Addr::UNSPECIFIED,
            },
        }
    }
}

/// Источник trust anchors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustAnchorSetting {
    /// Встроенные корневые KSK IANA (`"embedded"`).
    Embedded,
    /// Файл DS-записей (`{"path": "..."}`).
    PathFile(PathBuf),
}

impl<'de> Deserialize<'de> for TrustAnchorSetting {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;
        match value {
            serde_json::Value::String(text) if text.eq_ignore_ascii_case("embedded") => {
                Ok(Self::Embedded)
            }
            serde_json::Value::Object(map) => {
                let path = map
                    .get("path")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| {
                        de::Error::custom(
                            "trust_anchor must be \"embedded\" or {\"path\": \"<file>\"}",
                        )
                    })?;
                Ok(Self::PathFile(PathBuf::from(path)))
            }
            _ => Err(de::Error::custom(
                "trust_anchor must be \"embedded\" or {\"path\": \"<file>\"}",
            )),
        }
    }
}

/// Параметры blocklist.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlocklistSetting {
    /// Файлы blocklist (домены, hosts-формат, adblock, `@@allow`).
    #[serde(default)]
    pub paths: Vec<PathBuf>,
    /// Домены-исключения (включая поддомены).
    #[serde(default)]
    pub allowlist: Vec<String>,
    /// Политика ответа.
    #[serde(default)]
    pub response: BlockResponseSetting,
    /// Периодическая перезагрузка списков, секунды (`0` — только SIGHUP).
    #[serde(default)]
    pub reload_secs: u64,
}

/// Параметры кеша.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheSetting {
    /// Максимум записей.
    #[serde(default = "default_cache_entries")]
    pub max_entries: usize,
    /// Максимум приблизительной памяти, байт.
    #[serde(default = "default_cache_bytes")]
    pub max_bytes: usize,
    /// Минимальный TTL при вставке.
    #[serde(default)]
    pub min_ttl: u32,
    /// Максимальный TTL при вставке.
    #[serde(default = "default_max_ttl")]
    pub max_ttl: u32,
    /// Число шардов кеша.
    #[serde(default = "default_cache_shards")]
    pub shards: usize,
}

impl Default for CacheSetting {
    fn default() -> Self {
        Self {
            max_entries: default_cache_entries(),
            max_bytes: default_cache_bytes(),
            min_ttl: 0,
            max_ttl: default_max_ttl(),
            shards: default_cache_shards(),
        }
    }
}

impl CacheSetting {
    fn to_cache_config(&self) -> CacheConfig {
        CacheConfig {
            max_entries: self.max_entries,
            max_bytes: self.max_bytes,
            min_ttl: self.min_ttl,
            max_ttl: self.max_ttl,
            shards: self.shards,
        }
    }
}

/// Параметры TCP-транспорта.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TcpSetting {
    /// Максимум одновременных соединений.
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// Idle-таймаут чтения/записи, миллисекунды.
    #[serde(default = "default_tcp_idle_ms")]
    pub idle_timeout_ms: u64,
}

impl Default for TcpSetting {
    fn default() -> Self {
        Self {
            max_connections: default_max_connections(),
            idle_timeout_ms: default_tcp_idle_ms(),
        }
    }
}

impl TcpSetting {
    /// Idle-таймаут как `Duration`.
    #[must_use]
    pub fn idle_timeout(self) -> Duration {
        Duration::from_millis(self.idle_timeout_ms)
    }
}

/// Таймауты резолвера.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeoutSetting {
    /// Таймаут одного upstream-запроса, миллисекунды.
    #[serde(default = "default_per_query_ms")]
    pub per_query_ms: u64,
    /// Таймаут TCP-соединения, миллисекунды.
    #[serde(default = "default_tcp_ms")]
    pub tcp_ms: u64,
    /// Общий бюджет резолюции, миллисекунды.
    #[serde(default = "default_total_ms")]
    pub total_ms: u64,
}

impl Default for TimeoutSetting {
    fn default() -> Self {
        Self {
            per_query_ms: default_per_query_ms(),
            tcp_ms: default_tcp_ms(),
            total_ms: default_total_ms(),
        }
    }
}

impl TimeoutSetting {
    fn to_timeout_config(self) -> TimeoutConfig {
        TimeoutConfig {
            per_query: Duration::from_millis(self.per_query_ms),
            tcp: Duration::from_millis(self.tcp_ms),
            total: Duration::from_millis(self.total_ms),
        }
    }
}

/// Статическая запись override.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OverrideSetting {
    /// Владелец.
    pub name: String,
    /// TTL, секунды.
    #[serde(default = "default_override_ttl")]
    pub ttl: u32,
    /// IPv4-адреса.
    #[serde(default)]
    pub a: Vec<Ipv4Addr>,
    /// IPv6-адреса.
    #[serde(default)]
    pub aaaa: Vec<Ipv6Addr>,
    /// Цель CNAME.
    #[serde(default)]
    pub cname: Option<String>,
}

impl OverrideSetting {
    fn to_override(&self) -> Result<Override, ConfigError> {
        let name = Name::parse(self.name.trim()).map_err(|error| {
            ConfigError::invalid(format!("overrides: invalid name {:?}: {error}", self.name))
        })?;
        let ttl = Ttl::new(self.ttl).map_err(|error| {
            ConfigError::invalid(format!("overrides: {} has invalid ttl: {error}", self.name))
        })?;
        let mut data = Vec::new();
        if let Some(cname) = &self.cname {
            let target = Name::parse(cname.trim()).map_err(|error| {
                ConfigError::invalid(format!(
                    "overrides: {} has invalid cname {cname:?}: {error}",
                    self.name
                ))
            })?;
            data.push(Rdata::Cname(target));
        }
        data.extend(self.a.iter().copied().map(Rdata::A));
        data.extend(self.aaaa.iter().copied().map(Rdata::Aaaa));
        Override::new(name, ttl, data).map_err(|error| ConfigError::invalid(error.to_string()))
    }
}

/// Полная конфигурация процесса.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// UDP-listen.
    #[serde(default)]
    pub listen_udp: Option<SocketAddr>,
    /// TCP-listen.
    #[serde(default)]
    pub listen_tcp: Option<SocketAddr>,
    /// HTTP-метрики (`GET /metrics`, `GET /healthz`); только loopback.
    #[serde(default)]
    pub metrics_listen: Option<SocketAddr>,
    /// Число UDP worker'ов (`0` — по доступному параллелизму).
    #[serde(default)]
    pub workers: usize,
    /// Режим резолюции.
    #[serde(default)]
    pub mode: ModeSetting,
    /// Forwarder-ы для `mode = "forward"`.
    #[serde(default)]
    pub forwarders: Vec<SocketAddr>,
    /// Root hints для `mode = "iterative"` (пусто — встроенные IANA).
    #[serde(default)]
    pub root_hints: Vec<SocketAddr>,
    /// Порт авторитетных серверов в итеративном режиме.
    #[serde(default = "default_ns_port")]
    pub ns_port: u16,
    /// Включить DNSSEC-валидацию.
    #[serde(default)]
    pub dnssec_validate: bool,
    /// Trust anchors: встроенные корневые или файл DS-записей.
    #[serde(default)]
    pub trust_anchor: Option<TrustAnchorSetting>,
    /// Blocklist.
    #[serde(default)]
    pub blocklist: BlocklistSetting,
    /// Статические overrides.
    #[serde(default)]
    pub overrides: Vec<OverrideSetting>,
    /// Кеш.
    #[serde(default)]
    pub cache: CacheSetting,
    /// Транспорт TCP.
    #[serde(default)]
    pub tcp: TcpSetting,
    /// Таймауты резолвера.
    #[serde(default)]
    pub timeouts: TimeoutSetting,
    /// Уровень логирования.
    #[serde(default)]
    pub log_level: LogLevel,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_udp: None,
            listen_tcp: None,
            metrics_listen: None,
            workers: 0,
            mode: ModeSetting::default(),
            forwarders: Vec::new(),
            root_hints: Vec::new(),
            ns_port: default_ns_port(),
            dnssec_validate: false,
            trust_anchor: None,
            blocklist: BlocklistSetting::default(),
            overrides: Vec::new(),
            cache: CacheSetting::default(),
            tcp: TcpSetting::default(),
            timeouts: TimeoutSetting::default(),
            log_level: LogLevel::default(),
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
        Self::from_json_str(&text).map_err(|error| match error {
            ConfigError::Parse { source, .. } => ConfigError::Parse {
                path: path.to_path_buf(),
                source,
            },
            other => other,
        })
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
    /// # Errors
    ///
    /// [`ConfigError::Invalid`], если не задан ни один транспорт, параметры
    /// выходят за допустимые пределы или overrides некорректны.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.listen_udp.is_none() && self.listen_tcp.is_none() {
            return Err(ConfigError::invalid(
                "at least one of listen_udp/listen_tcp must be set",
            ));
        }
        if self.workers > 1024 {
            return Err(ConfigError::invalid(format!(
                "workers must be in 0..=1024, got {}",
                self.workers
            )));
        }
        if self.ns_port == 0 {
            return Err(ConfigError::invalid("ns_port must be non-zero"));
        }
        match self.mode {
            ModeSetting::Forward if self.forwarders.is_empty() => {
                return Err(ConfigError::invalid(
                    "forward mode requires at least one forwarder",
                ));
            }
            ModeSetting::Forward | ModeSetting::Iterative => {}
        }
        if let Some(metrics) = self.metrics_listen
            && !metrics.ip().is_loopback()
        {
            return Err(ConfigError::invalid(format!(
                "metrics_listen must be a loopback address, got {metrics}"
            )));
        }
        if self.cache.max_entries == 0
            || self.cache.max_bytes == 0
            || !(1..=256).contains(&self.cache.shards)
        {
            return Err(ConfigError::invalid("invalid cache limits"));
        }
        if self.cache.min_ttl > self.cache.max_ttl {
            return Err(ConfigError::invalid("cache min_ttl exceeds max_ttl"));
        }
        if self.timeouts.per_query_ms == 0
            || self.timeouts.tcp_ms == 0
            || self.timeouts.total_ms == 0
        {
            return Err(ConfigError::invalid("timeouts must be non-zero"));
        }
        if self.timeouts.per_query_ms > self.timeouts.total_ms {
            return Err(ConfigError::invalid(
                "timeouts.per_query_ms must not exceed total_ms",
            ));
        }
        if self.tcp.max_connections == 0 || self.tcp.max_connections > 65_535 {
            return Err(ConfigError::invalid(format!(
                "tcp.max_connections must be in 1..=65535, got {}",
                self.tcp.max_connections
            )));
        }
        if !(100..=600_000).contains(&self.tcp.idle_timeout_ms) {
            return Err(ConfigError::invalid(format!(
                "tcp.idle_timeout_ms must be in 100..=600000, got {}",
                self.tcp.idle_timeout_ms
            )));
        }
        if self.blocklist.reload_secs > 86_400 {
            return Err(ConfigError::invalid(
                "blocklist.reload_secs must be at most 86400",
            ));
        }
        if self
            .blocklist
            .paths
            .iter()
            .any(|path| path.as_os_str().is_empty())
        {
            return Err(ConfigError::invalid("blocklist paths must not be empty"));
        }
        if let Some(TrustAnchorSetting::PathFile(path)) = &self.trust_anchor
            && path.as_os_str().is_empty()
        {
            return Err(ConfigError::invalid("trust_anchor path must not be empty"));
        }
        for entry in &self.overrides {
            entry.to_override()?;
        }
        Ok(())
    }

    /// Строит конфигурацию `pulse-resolver` (с чтением trust anchors).
    ///
    /// # Errors
    ///
    /// [`ConfigError`] при невалидной конфигурации или ошибке чтения файла
    /// trust anchors.
    pub fn resolver_config(&self) -> Result<ResolverConfig, ConfigError> {
        self.validate()?;
        let mode = match self.mode {
            ModeSetting::Forward => Mode::Forward(ForwardConfig::new(self.forwarders.clone())),
            ModeSetting::Iterative => Mode::Iterative(IterativeConfig {
                root_hints: self.root_hints.clone(),
                ns_port: self.ns_port,
            }),
        };
        let anchors = if self.dnssec_validate {
            match &self.trust_anchor {
                None | Some(TrustAnchorSetting::Embedded) => Vec::new(),
                Some(TrustAnchorSetting::PathFile(path)) => anchors::load(path)?,
            }
        } else {
            Vec::new()
        };
        let overrides = self
            .overrides
            .iter()
            .map(OverrideSetting::to_override)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ResolverConfig {
            mode,
            timeouts: self.timeouts.to_timeout_config(),
            cache: self.cache.to_cache_config(),
            dnssec: DnssecConfig {
                enabled: self.dnssec_validate,
                anchors,
                ..DnssecConfig::default()
            },
            blocklist: ResolverBlocklistConfig {
                path: None,
                paths: self.blocklist.paths.clone(),
                allowlist: self.blocklist.allowlist.clone(),
                response: self.blocklist.response.into(),
            },
            overrides,
            ..ResolverConfig::default()
        })
    }

    /// Применяет CLI-overrides поверх файла.
    pub fn apply_overrides(&mut self, overrides: &Overrides) {
        if let Some(addr) = overrides.listen_udp {
            self.listen_udp = Some(addr);
        }
        if let Some(addr) = overrides.listen_tcp {
            self.listen_tcp = Some(addr);
        }
        if let Some(addr) = overrides.metrics_listen {
            self.metrics_listen = Some(addr);
        }
        if let Some(workers) = overrides.workers {
            self.workers = workers;
        }
        if !overrides.forwarders.is_empty() {
            self.mode = ModeSetting::Forward;
            self.forwarders.clone_from(&overrides.forwarders);
        }
        if !overrides.blocklists.is_empty() {
            self.blocklist
                .paths
                .extend(overrides.blocklists.iter().cloned());
        }
        if overrides.no_dnssec {
            self.dnssec_validate = false;
        }
        if let Some(level) = overrides.log_level {
            self.log_level = level;
        }
    }
}

/// Значения, переопределяющие конфигурационный файл из CLI.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Overrides {
    /// Новый UDP-адрес.
    pub listen_udp: Option<SocketAddr>,
    /// Новый TCP-адрес.
    pub listen_tcp: Option<SocketAddr>,
    /// Новый адрес HTTP-метрик.
    pub metrics_listen: Option<SocketAddr>,
    /// Новое число UDP worker'ов.
    pub workers: Option<usize>,
    /// Новые forwarder-ы (включают forward-режим).
    pub forwarders: Vec<SocketAddr>,
    /// Дополнительные файлы blocklist.
    pub blocklists: Vec<PathBuf>,
    /// Выключить DNSSEC-валидацию.
    pub no_dnssec: bool,
    /// Новый уровень логирования.
    pub log_level: Option<LogLevel>,
}

fn default_ns_port() -> u16 {
    53
}

fn default_cache_entries() -> usize {
    16_384
}

fn default_cache_bytes() -> usize {
    8 * 1024 * 1024
}

fn default_cache_shards() -> usize {
    16
}

fn default_max_ttl() -> u32 {
    86_400
}

fn default_per_query_ms() -> u64 {
    2_000
}

fn default_tcp_ms() -> u64 {
    3_000
}

fn default_total_ms() -> u64 {
    6_000
}

fn default_max_connections() -> usize {
    1_024
}

fn default_tcp_idle_ms() -> u64 {
    5_000
}

fn default_override_ttl() -> u32 {
    60
}

#[cfg(test)]
mod tests {
    use super::*;

    fn forward_config() -> Config {
        Config {
            listen_udp: Some("127.0.0.1:0".parse().unwrap()),
            forwarders: vec!["127.0.0.1:53".parse().unwrap()],
            ..Config::default()
        }
    }

    #[test]
    fn example_config_parses_and_validates() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/resolver.json");
        let config = Config::load(&path).expect("example config");
        config.validate().expect("example config is valid");
        assert_eq!(config.forwarders.len(), 2);
        assert!(config.dnssec_validate);
        assert_eq!(config.blocklist.paths.len(), 1);
    }

    #[test]
    fn defaults_parse_from_empty_json_and_validate_transport() {
        let config = Config::from_json_str("{}").unwrap();
        assert!(config.validate().is_err());
        assert_eq!(config.mode, ModeSetting::Forward);
        assert_eq!(config.timeouts.per_query_ms, 2_000);
        assert_eq!(config.cache.shards, 16);
    }

    #[test]
    fn forward_mode_requires_forwarders() {
        let config = Config {
            listen_udp: Some("127.0.0.1:0".parse().unwrap()),
            ..Config::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn trust_anchor_accepts_embedded_and_path() {
        let embedded: TrustAnchorSetting = serde_json::from_str("\"embedded\"").unwrap();
        assert_eq!(embedded, TrustAnchorSetting::Embedded);
        let file: TrustAnchorSetting = serde_json::from_str("{\"path\": \"root.ds\"}").unwrap();
        assert_eq!(file, TrustAnchorSetting::PathFile(PathBuf::from("root.ds")));
        assert!(serde_json::from_str::<TrustAnchorSetting>("\"file\"").is_err());
        assert!(serde_json::from_str::<TrustAnchorSetting>("{}").is_err());
    }

    #[test]
    fn overrides_convert_and_reject_mixed_cname() {
        let mut config = forward_config();
        config.overrides = vec![OverrideSetting {
            name: "router.home".to_owned(),
            ttl: 60,
            a: vec![Ipv4Addr::new(192, 168, 1, 1)],
            aaaa: vec!["fd00::1".parse().unwrap()],
            cname: None,
        }];
        let resolver = config.resolver_config().unwrap();
        assert_eq!(resolver.overrides.len(), 1);

        config.overrides[0].cname = Some("other.home.".to_owned());
        assert!(config.validate().is_err());
    }

    #[test]
    fn disabled_dnssec_ignores_anchor_file() {
        let mut config = forward_config();
        config.dnssec_validate = false;
        config.trust_anchor = Some(TrustAnchorSetting::PathFile(PathBuf::from(
            "/nonexistent/pulseresolved-root.ds",
        )));
        assert!(config.resolver_config().is_ok());
    }

    #[test]
    fn metrics_must_be_loopback() {
        let mut config = forward_config();
        config.metrics_listen = Some("0.0.0.0:9153".parse().unwrap());
        assert!(config.validate().is_err());
        config.metrics_listen = Some("127.0.0.1:9153".parse().unwrap());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn cli_overrides_switch_to_forward_and_append_blocklists() {
        let mut config = Config {
            mode: ModeSetting::Iterative,
            ..Config::default()
        };
        config.apply_overrides(&Overrides {
            forwarders: vec!["1.1.1.1:53".parse().unwrap()],
            blocklists: vec![PathBuf::from("a.txt"), PathBuf::from("b.txt")],
            no_dnssec: true,
            ..Overrides::default()
        });
        assert_eq!(config.mode, ModeSetting::Forward);
        assert_eq!(config.forwarders.len(), 1);
        assert_eq!(config.blocklist.paths.len(), 2);
        assert!(!config.dnssec_validate);
    }
}
