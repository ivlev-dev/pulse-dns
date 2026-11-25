//! TOML-конфигурация резолвера (JSON — обратная совместимость) и CLI-overrides.
//!
//! Формат определяется расширением файла: `.toml` (рекомендуемый) или
//! `.json` (legacy). Значения по умолчанию безопасны: резолвер запускается
//! только с явно заданным транспортом, DNSSEC выключен, blocklist пуст,
//! HTTP-метрики выключены.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pulse_dns::{Name, Rdata, Ttl};
use pulse_dnssec::{
    SharedTrustAnchors, TrustAnchor, TrustAnchorPolicy, TrustAnchorProvider, TrustAnchorStore,
};
use pulse_resolver::{
    BlockResponse, BlocklistConfig as ResolverBlocklistConfig, CacheConfig, DnssecConfig,
    ForwardConfig, IterativeConfig, Mode, Override, ResolverConfig, TimeoutConfig, UpstreamConfig,
    UpstreamPoolConfig,
};
use pulse_runtime::affinity::MAX_CPU;
use pulse_tls::{Acl, RateLimitConfig as TlsRateLimitConfig, RateLimiter};
use serde::de::{self, Deserializer};
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize, Serializer};

use crate::anchors;
use crate::error::{ConfigError, ParseSource};
use crate::rrl::{Rrl, RrlConfig, RrlRate};

/// Текущее время UNIX в секундах (насыщается на `u32`).
fn unix_now() -> u32 {
    let Ok(duration) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return 0;
    };
    u32::try_from(duration.as_secs()).unwrap_or(u32::MAX)
}

/// Режим резолюции.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ModeSetting {
    /// Пересылка настроенным рекурсивным серверам.
    #[default]
    Forward,
    /// Итеративный обход от root hints.
    Iterative,
}

/// Уровень логирования.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
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
    /// Файл DS-записей + RFC 5011 состояние обновления
    /// (`{"path": "...", "state": "..."}`).
    Managed {
        /// Начальный файл доверенных DS.
        path: PathBuf,
        /// Файл состояния RFC 5011 (атомарная запись `0600`).
        state: PathBuf,
        /// Add hold-down в секундах (по умолчанию 30 дней).
        add_hold_down: u32,
        /// Revoke hold-down в секундах (по умолчанию 30 дней).
        revoke_hold_down: u32,
    },
}

impl TrustAnchorSetting {
    /// Значение hold-down по умолчанию (RFC 5011 §2.4.1).
    pub const DEFAULT_HOLD_DOWN: u32 = 30 * 86_400;
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
                let Some(state) = map.get("state").and_then(serde_json::Value::as_str) else {
                    return Ok(Self::PathFile(PathBuf::from(path)));
                };
                let number = |key: &str| -> Result<u32, D::Error> {
                    map.get(key).and_then(serde_json::Value::as_u64).map_or(
                        Ok(Self::DEFAULT_HOLD_DOWN),
                        |value| {
                            u32::try_from(value).map_err(|_| {
                                de::Error::custom(format!("trust_anchor.{key} does not fit in u32"))
                            })
                        },
                    )
                };
                Ok(Self::Managed {
                    path: PathBuf::from(path),
                    state: PathBuf::from(state),
                    add_hold_down: number("add_hold_down")?,
                    revoke_hold_down: number("revoke_hold_down")?,
                })
            }
            _ => Err(de::Error::custom(
                "trust_anchor must be \"embedded\" or {\"path\": \"<file>\"}",
            )),
        }
    }
}

impl Serialize for TrustAnchorSetting {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Embedded => serializer.serialize_str("embedded"),
            Self::PathFile(path) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("path", path)?;
                map.end()
            }
            Self::Managed {
                path,
                state,
                add_hold_down,
                revoke_hold_down,
            } => {
                let mut map = serializer.serialize_map(Some(4))?;
                map.serialize_entry("path", path)?;
                map.serialize_entry("state", state)?;
                map.serialize_entry("add_hold_down", add_hold_down)?;
                map.serialize_entry("revoke_hold_down", revoke_hold_down)?;
                map.end()
            }
        }
    }
}

/// Bearer-токен control-plane API.
///
/// Печатается в `Debug` как `<redacted>`, чтобы случайный лог конфигурации не
/// раскрыл секрет. Значение доступно только через [`ControlToken::expose`].
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(transparent)]
pub struct ControlToken(String);

impl ControlToken {
    /// Создаёт токен.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Возвращает секрет.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Проверяет, что токен пригоден для `Authorization: Bearer`.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.0.is_empty()
            && self.0.len() <= 4096
            && self.0.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    }
}

impl fmt::Debug for ControlToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

/// Таймауты и лимиты control-plane HTTP-сервера.
#[derive(Debug, Clone, Copy, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlSetting {
    /// Дедлайн чтения запроса, миллисекунды.
    #[serde(default = "default_control_request_ms")]
    pub request_timeout_ms: u64,
    /// Таймаут записи ответа, миллисекунды.
    #[serde(default = "default_control_write_ms")]
    pub write_timeout_ms: u64,
    /// Ожидание завершения соединений при остановке, миллисекунды.
    #[serde(default = "default_control_shutdown_ms")]
    pub shutdown_timeout_ms: u64,
    /// Максимум одновременных соединений.
    #[serde(default = "default_control_connections")]
    pub max_connections: usize,
    /// Скорость токен-бакета на токен, запросов в секунду.
    #[serde(default = "default_control_qps")]
    pub rate_limit_qps: f64,
    /// Burst токен-бакета на токен.
    #[serde(default = "default_control_burst")]
    pub rate_limit_burst: u32,
}

impl Default for ControlSetting {
    fn default() -> Self {
        Self {
            request_timeout_ms: default_control_request_ms(),
            write_timeout_ms: default_control_write_ms(),
            shutdown_timeout_ms: default_control_shutdown_ms(),
            max_connections: default_control_connections(),
            rate_limit_qps: default_control_qps(),
            rate_limit_burst: default_control_burst(),
        }
    }
}

impl ControlSetting {
    fn validate(&self) -> Result<(), ConfigError> {
        if !(100..=600_000).contains(&self.request_timeout_ms)
            || !(100..=600_000).contains(&self.write_timeout_ms)
            || !(100..=600_000).contains(&self.shutdown_timeout_ms)
        {
            return Err(ConfigError::invalid(
                "control timeouts must be in 100..=600000 ms",
            ));
        }
        if !(1..=1024).contains(&self.max_connections) {
            return Err(ConfigError::invalid(format!(
                "control.max_connections must be in 1..=1024, got {}",
                self.max_connections
            )));
        }
        if !self.rate_limit_qps.is_finite() || self.rate_limit_qps <= 0.0 {
            return Err(ConfigError::invalid(
                "control.rate_limit_qps must be finite and positive",
            ));
        }
        if self.rate_limit_burst == 0 {
            return Err(ConfigError::invalid(
                "control.rate_limit_burst must be positive",
            ));
        }
        Ok(())
    }
}

/// Параметры blocklist.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
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

/// Общие лимиты защищённых транспортов (DoT, DoH/1.1, DoH/2, DoQ и DNSCrypt TCP).
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecureSetting {
    /// Максимум одновременных соединений на транспорт.
    #[serde(default = "default_secure_max_connections")]
    pub max_connections: usize,
    /// Максимум одновременных stream'ов (DoH/2 и DoQ).
    #[serde(default = "default_secure_max_streams")]
    pub max_streams: u32,
    /// Таймаут TLS/QUIC-рукопожатия, миллисекунды.
    #[serde(default = "default_secure_handshake_ms")]
    pub handshake_timeout_ms: u64,
    /// Таймаут чтения запроса/записи ответа (DoH/2, DoQ), миллисекунды.
    #[serde(default = "default_secure_request_ms")]
    pub request_timeout_ms: u64,
    /// Idle-таймаут соединения, миллисекунды.
    #[serde(default = "default_secure_idle_ms")]
    pub idle_timeout_ms: u64,
    /// Ожидание соединений при graceful shutdown, миллисекунды.
    #[serde(default = "default_secure_shutdown_ms")]
    pub shutdown_timeout_ms: u64,
    /// Максимальный размер DNS-сообщения/HTTP-тела.
    #[serde(default = "default_secure_max_message")]
    pub max_message_size: usize,
    /// Число worker-потоков tokio для DoH/2 и DoQ.
    #[serde(default = "default_secure_workers")]
    pub worker_threads: usize,
    /// Максимум запросов на одно keep-alive соединение DoT/DoH/1.1.
    #[serde(default = "default_secure_max_requests")]
    pub max_requests_per_connection: usize,
    /// Добавлять `Cache-Control: max-age=<min TTL>` к ответам DoH.
    #[serde(default = "default_true")]
    pub cache_control: bool,
}

impl Default for SecureSetting {
    fn default() -> Self {
        Self {
            max_connections: default_secure_max_connections(),
            max_streams: default_secure_max_streams(),
            handshake_timeout_ms: default_secure_handshake_ms(),
            request_timeout_ms: default_secure_request_ms(),
            idle_timeout_ms: default_secure_idle_ms(),
            shutdown_timeout_ms: default_secure_shutdown_ms(),
            max_message_size: default_secure_max_message(),
            worker_threads: default_secure_workers(),
            max_requests_per_connection: default_secure_max_requests(),
            cache_control: true,
        }
    }
}

impl SecureSetting {
    /// Таймаут рукопожатия.
    #[must_use]
    pub fn handshake_timeout(&self) -> Duration {
        Duration::from_millis(self.handshake_timeout_ms)
    }

    /// Таймаут одной операции чтения/записи (DoH/2, DoQ).
    #[must_use]
    pub fn request_timeout(&self) -> Duration {
        Duration::from_millis(self.request_timeout_ms)
    }

    /// Idle-таймаут соединения.
    #[must_use]
    pub fn idle_timeout(&self) -> Duration {
        Duration::from_millis(self.idle_timeout_ms)
    }

    /// Таймаут graceful shutdown.
    #[must_use]
    pub fn shutdown_timeout(&self) -> Duration {
        Duration::from_millis(self.shutdown_timeout_ms)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.max_connections == 0 || self.max_connections > 65_535 {
            return Err(ConfigError::invalid(format!(
                "secure.max_connections must be in 1..=65535, got {}",
                self.max_connections
            )));
        }
        if self.max_streams == 0 || self.max_streams > 65_535 {
            return Err(ConfigError::invalid(format!(
                "secure.max_streams must be in 1..=65535, got {}",
                self.max_streams
            )));
        }
        if self.max_message_size == 0 || self.max_message_size > usize::from(u16::MAX) {
            return Err(ConfigError::invalid(format!(
                "secure.max_message_size must be in 1..=65535, got {}",
                self.max_message_size
            )));
        }
        if self.worker_threads == 0 || self.worker_threads > 64 {
            return Err(ConfigError::invalid(format!(
                "secure.worker_threads must be in 1..=64, got {}",
                self.worker_threads
            )));
        }
        if self.max_requests_per_connection == 0 {
            return Err(ConfigError::invalid(
                "secure.max_requests_per_connection must be positive",
            ));
        }
        if self.handshake_timeout_ms == 0
            || self.request_timeout_ms == 0
            || self.idle_timeout_ms == 0
            || self.shutdown_timeout_ms == 0
        {
            return Err(ConfigError::invalid(
                "secure handshake/request/idle/shutdown timeouts must be non-zero",
            ));
        }
        Ok(())
    }
}

/// Параметры DNSCrypt v2-сервера.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DnscryptSetting {
    /// Минимальная длина дополненного UDP-запроса, кратна 64.
    #[serde(default = "default_dnscrypt_min_query_len")]
    pub min_query_len: usize,
    /// Максимальный размер UDP-пакета DNSCrypt.
    #[serde(default = "default_dnscrypt_max_udp")]
    pub max_udp_packet: usize,
    /// Максимальная полезная нагрузка TCP-кадра.
    #[serde(default = "default_dnscrypt_max_tcp")]
    pub max_tcp_packet: usize,
    /// Время жизни anti-replay записи, секунды.
    #[serde(default = "default_dnscrypt_replay_ttl")]
    pub replay_ttl_secs: u64,
    /// Ёмкость anti-replay кэша.
    #[serde(default = "default_dnscrypt_replay_capacity")]
    pub replay_capacity: usize,
    /// Включить anti-replay защиту от повторов nonce.
    #[serde(default = "default_true")]
    pub replay_protection: bool,
    /// Усекать большие UDP-ответы с TC вместо ошибки.
    #[serde(default = "default_true")]
    pub truncate_udp_responses: bool,
}

impl Default for DnscryptSetting {
    fn default() -> Self {
        Self {
            min_query_len: default_dnscrypt_min_query_len(),
            max_udp_packet: default_dnscrypt_max_udp(),
            max_tcp_packet: default_dnscrypt_max_tcp(),
            replay_ttl_secs: default_dnscrypt_replay_ttl(),
            replay_capacity: default_dnscrypt_replay_capacity(),
            replay_protection: true,
            truncate_udp_responses: true,
        }
    }
}

impl DnscryptSetting {
    /// Собирает `pulse-dnscrypt` `ServerConfig`.
    #[must_use]
    pub fn server_config(&self) -> pulse_dnscrypt::ServerConfig {
        pulse_dnscrypt::ServerConfig {
            min_query_len: self.min_query_len,
            max_udp_packet: self.max_udp_packet,
            max_tcp_packet: self.max_tcp_packet,
            replay_ttl_secs: self.replay_ttl_secs,
            replay_capacity: self.replay_capacity,
            replay_protection: self.replay_protection,
            truncate_udp_responses: self.truncate_udp_responses,
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.min_query_len == 0
            || !self
                .min_query_len
                .is_multiple_of(pulse_dnscrypt::PAD_BLOCK_LEN)
            || self.min_query_len > 4096
        {
            return Err(ConfigError::invalid(
                "dnscrypt.min_query_len must be a non-zero multiple of 64 and at most 4096",
            ));
        }
        if self.max_udp_packet < pulse_dnscrypt::MIN_QUERY_PACKET_LEN
            || self.max_udp_packet > pulse_dnscrypt::MAX_UDP_PACKET
        {
            return Err(ConfigError::invalid(format!(
                "dnscrypt.max_udp_packet must be in {}..={}",
                pulse_dnscrypt::MIN_QUERY_PACKET_LEN,
                pulse_dnscrypt::MAX_UDP_PACKET
            )));
        }
        if self.max_tcp_packet < pulse_dnscrypt::MIN_QUERY_PACKET_LEN
            || self.max_tcp_packet > pulse_dnscrypt::MAX_TCP_PACKET
        {
            return Err(ConfigError::invalid(format!(
                "dnscrypt.max_tcp_packet must be in {}..={}",
                pulse_dnscrypt::MIN_QUERY_PACKET_LEN,
                pulse_dnscrypt::MAX_TCP_PACKET
            )));
        }
        if self.replay_protection && (self.replay_ttl_secs == 0 || self.replay_capacity == 0) {
            return Err(ConfigError::invalid(
                "dnscrypt replay ttl/capacity must be positive when replay_protection is enabled",
            ));
        }
        Ok(())
    }
}

/// Действие при превышении per-source rate limit.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RateLimitAction {
    /// Ответить REFUSED.
    #[default]
    Refused,
    /// Молча отбросить запрос (для TCP — закрыть соединение).
    Drop,
    /// Ответить пустым усечённым (TC) ответом.
    #[serde(alias = "tc")]
    Truncate,
}

/// Настройки per-source token bucket (RRL-подобное ограничение).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitSetting {
    /// Включить ограничение.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Средняя скорость пополнения, запросов в секунду.
    #[serde(default = "default_rate_qps")]
    pub qps: f64,
    /// Максимальный burst (запас токенов).
    #[serde(default = "default_rate_burst")]
    pub burst: u32,
    /// Максимум отслеживаемых source IP.
    #[serde(default = "default_rate_entries")]
    pub max_entries: usize,
    /// Действие при превышении.
    #[serde(default)]
    pub action: RateLimitAction,
}

impl Default for RateLimitSetting {
    fn default() -> Self {
        Self {
            enabled: true,
            qps: default_rate_qps(),
            burst: default_rate_burst(),
            max_entries: default_rate_entries(),
            action: RateLimitAction::Refused,
        }
    }
}

impl RateLimitSetting {
    fn validate(&self) -> Result<(), ConfigError> {
        if !self.qps.is_finite() || self.qps <= 0.0 {
            return Err(ConfigError::invalid(
                "rate_limit.qps must be finite and positive",
            ));
        }
        if self.burst == 0 {
            return Err(ConfigError::invalid("rate_limit.burst must be positive"));
        }
        if self.max_entries == 0 || self.max_entries > 1_000_000 {
            return Err(ConfigError::invalid(
                "rate_limit.max_entries must be in 1..=1000000",
            ));
        }
        Ok(())
    }

    fn to_config(&self) -> TlsRateLimitConfig {
        TlsRateLimitConfig {
            burst: self.burst,
            refill_per_sec: self.qps,
            max_entries: self.max_entries,
        }
    }
}

/// Лимит одного класса ответов RRL.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RrlRateSetting {
    /// Средняя скорость пополнения, ответов в секунду.
    #[serde(default = "default_rrl_qps")]
    pub qps: f64,
    /// Максимальный burst (запас токенов).
    #[serde(default = "default_rrl_burst")]
    pub burst: u32,
}

impl Default for RrlRateSetting {
    fn default() -> Self {
        Self {
            qps: default_rrl_qps(),
            burst: default_rrl_burst(),
        }
    }
}

impl RrlRateSetting {
    fn to_rate(self) -> RrlRate {
        RrlRate::new(self.qps, self.burst)
    }
}

/// Полный RRL: limits по классам ответов, slip и политика.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RrlSetting {
    /// Включить RRL (применяется только к UDP-ответам).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// `1/N` ограниченных ответов отправляется (`0` — ни одного).
    #[serde(default = "default_rrl_slip")]
    pub slip: u32,
    /// Максимум записей таблицы бакетов.
    #[serde(default = "default_rrl_entries")]
    pub max_entries: usize,
    /// Действие для отправляемых ограниченных ответов.
    #[serde(default = "default_rrl_action")]
    pub action: RateLimitAction,
    /// Класс NOERROR (положительные и NODATA).
    #[serde(default = "default_rrl_noerror")]
    pub noerror: RrlRateSetting,
    /// Класс NXDOMAIN.
    #[serde(default = "default_rrl_nxdomain")]
    pub nxdomain: RrlRateSetting,
    /// Класс referral (делегирование).
    #[serde(default = "default_rrl_referral")]
    pub referral: RrlRateSetting,
    /// Класс ошибок (SERVFAIL/REFUSED/NOTIMP).
    #[serde(default = "default_rrl_error")]
    pub error: RrlRateSetting,
    /// Агрегированный лимит на источник (все имена и классы).
    #[serde(default = "default_rrl_source")]
    pub source: RrlRateSetting,
}

impl Default for RrlSetting {
    fn default() -> Self {
        Self {
            enabled: true,
            slip: default_rrl_slip(),
            max_entries: default_rrl_entries(),
            action: default_rrl_action(),
            noerror: default_rrl_noerror(),
            nxdomain: default_rrl_nxdomain(),
            referral: default_rrl_referral(),
            error: default_rrl_error(),
            source: default_rrl_source(),
        }
    }
}

impl RrlSetting {
    fn validate(&self) -> Result<(), ConfigError> {
        self.to_config().validate()
    }

    fn to_config(&self) -> RrlConfig {
        RrlConfig {
            slip: self.slip,
            max_entries: self.max_entries,
            action: self.action,
            rates: [
                self.noerror.to_rate(),
                self.nxdomain.to_rate(),
                self.referral.to_rate(),
                self.error.to_rate(),
            ],
            source: self.source.to_rate(),
        }
    }
}

/// Параметры пула keep-alive соединений к DoT/DoH upstream.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamPoolSetting {
    /// Число соединений на один upstream (оно же лимит in-flight).
    #[serde(default = "default_pool_size", alias = "size")]
    pub pool_size: usize,
    /// Начальная задержка переподключения, миллисекунды.
    #[serde(default = "default_pool_backoff_ms")]
    pub reconnect_backoff_ms: u64,
    /// Максимальная задержка переподключения, миллисекунды.
    #[serde(default = "default_pool_max_backoff_ms")]
    pub max_reconnect_backoff_ms: u64,
}

impl Default for UpstreamPoolSetting {
    fn default() -> Self {
        Self {
            pool_size: default_pool_size(),
            reconnect_backoff_ms: default_pool_backoff_ms(),
            max_reconnect_backoff_ms: default_pool_max_backoff_ms(),
        }
    }
}

impl UpstreamPoolSetting {
    fn validate(&self) -> Result<(), ConfigError> {
        if !(1..=pulse_tls::MAX_POOL_SIZE).contains(&self.pool_size) {
            return Err(ConfigError::invalid(format!(
                "upstream_pool.pool_size must be in 1..={}",
                pulse_tls::MAX_POOL_SIZE
            )));
        }
        if self.reconnect_backoff_ms == 0
            || self.max_reconnect_backoff_ms < self.reconnect_backoff_ms
        {
            return Err(ConfigError::invalid(
                "upstream_pool reconnect backoff must be positive and not exceed the maximum",
            ));
        }
        Ok(())
    }

    fn to_config(self) -> UpstreamPoolConfig {
        UpstreamPoolConfig {
            size: self.pool_size,
            reconnect_backoff: Duration::from_millis(self.reconnect_backoff_ms),
            max_reconnect_backoff: Duration::from_millis(self.max_reconnect_backoff_ms),
        }
    }
}

/// Один upstream: строка-URL или объект `{addr, tls, server_name, ca}`.
#[derive(Debug, Clone)]
pub struct UpstreamSetting {
    /// Разобранный upstream.
    pub upstream: UpstreamConfig,
}

impl<'de> Deserialize<'de> for UpstreamSetting {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;
        match value {
            serde_json::Value::String(text) => {
                let upstream = UpstreamConfig::parse(&text).map_err(de::Error::custom)?;
                Ok(Self { upstream })
            }
            serde_json::Value::Object(map) => {
                let ca = map
                    .get("ca")
                    .and_then(serde_json::Value::as_str)
                    .map(PathBuf::from);
                let raw = if let Some(url) = map.get("url").and_then(serde_json::Value::as_str) {
                    url.to_owned()
                } else {
                    let addr = map
                        .get("addr")
                        .and_then(serde_json::Value::as_str)
                        .ok_or_else(|| {
                            de::Error::custom("upstream object requires \"url\" or \"addr\" string")
                        })?;
                    let tls = map
                        .get("tls")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false);
                    let server_name = map.get("server_name").and_then(serde_json::Value::as_str);
                    if tls && !addr.to_ascii_lowercase().contains("://") {
                        match server_name {
                            Some(name) => format!("tls://{addr}#{name}"),
                            None => format!("tls://{addr}"),
                        }
                    } else {
                        addr.to_owned()
                    }
                };
                let upstream =
                    UpstreamConfig::parse_with_ca(&raw, ca).map_err(de::Error::custom)?;
                Ok(Self { upstream })
            }
            _ => Err(de::Error::custom(
                "upstream must be a URL string or an object",
            )),
        }
    }
}

impl Serialize for UpstreamSetting {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let ca = match &self.upstream {
            UpstreamConfig::Udp(_) | UpstreamConfig::Tcp(_) => None,
            UpstreamConfig::Tls(upstream) => upstream.ca.as_ref(),
            UpstreamConfig::Https(upstream) => upstream.ca.as_ref(),
        };
        match ca {
            None => serializer.serialize_str(&self.upstream.to_string()),
            Some(ca) => {
                let mut map = serializer.serialize_map(Some(2))?;
                map.serialize_entry("url", &self.upstream.to_string())?;
                map.serialize_entry("ca", ca)?;
                map.end()
            }
        }
    }
}

/// Таймауты резолвера.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Deserialize, Serialize)]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// UDP-listen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_udp: Option<SocketAddr>,
    /// TCP-listen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_tcp: Option<SocketAddr>,
    /// DNS over TLS listen (RFC 7858).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dot_listen: Option<SocketAddr>,
    /// DNS over HTTPS/1.1 listen (RFC 8484).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doh_listen: Option<SocketAddr>,
    /// DNS over HTTPS/2 listen (RFC 8484 + RFC 9113).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doh2_listen: Option<SocketAddr>,
    /// DNS over QUIC listen (RFC 9250, UDP).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doq_listen: Option<SocketAddr>,
    /// DNSCrypt v2 UDP listen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dnscrypt_listen: Option<SocketAddr>,
    /// DNSCrypt v2 TCP listen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dnscrypt_tcp_listen: Option<SocketAddr>,
    /// PEM-сертификат (цепочка) для DoT/DoH/DoH2/DoQ.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_cert: Option<PathBuf>,
    /// PEM-закрытый ключ TLS (права 0600).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_key: Option<PathBuf>,
    /// IP/CIDR клиентов защищённых TLS-транспортов. Пусто — общий `allow_from`.
    #[serde(default)]
    pub tls_allow_from: Vec<String>,
    /// Файл provider-ключа DNSCrypt (hex, права 0600).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dnscrypt_provider_key: Option<PathBuf>,
    /// Файл resolver-ключа DNSCrypt (hex, права 0600).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dnscrypt_resolver_key: Option<PathBuf>,
    /// Подписанный сертификат DNSCrypt (JSON `pulsed dnscrypt-gencert` или hex/base64).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dnscrypt_cert: Option<PathBuf>,
    /// Лимиты и таймауты TLS-транспортов.
    #[serde(default)]
    pub secure: SecureSetting,
    /// Параметры DNSCrypt-сервера.
    #[serde(default)]
    pub dnscrypt: DnscryptSetting,
    /// HTTP-метрики (`GET /metrics`, `GET /healthz`); только loopback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics_listen: Option<SocketAddr>,
    /// Control-plane REST API; только loopback. По умолчанию выключен.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_listen: Option<SocketAddr>,
    /// Bearer-токен control-plane API (env `PULSERESOLVED_API_TOKEN` важнее).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_token: Option<ControlToken>,
    /// Таймауты и лимиты control-plane.
    #[serde(default)]
    pub control: ControlSetting,
    /// Число UDP worker'ов (`0` — по доступному параллелизму).
    #[serde(default)]
    pub workers: usize,
    /// CPU для worker'ов резолвера (UDP/TCP/control), `"0,2,4-7"` или массив.
    ///
    /// Пересекается с `sched_getaffinity`/cpuset; пустое пересечение — ошибка
    /// старта, чужие CPU не используются.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_cpu_list"
    )]
    pub control_cpu_affinity: Vec<usize>,
    /// Режим резолюции.
    #[serde(default)]
    pub mode: ModeSetting,
    /// Forwarder-ы для `mode = "forward"` (legacy UDP-список).
    #[serde(default)]
    pub forwarders: Vec<SocketAddr>,
    /// Смешанные upstream: UDP/TCP/DoT/DoH (URL или объект).
    #[serde(default)]
    pub upstreams: Vec<UpstreamSetting>,
    /// IP/CIDR клиентов, которым разрешены запросы. Пусто — loopback.
    #[serde(default)]
    pub allow_from: Vec<String>,
    /// Per-source rate limit (RRL-подобное ограничение).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimitSetting>,
    /// Response Rate Limiting по классам ответов (только UDP).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rrl: Option<RrlSetting>,
    /// Пул keep-alive соединений к DoT/DoH upstream.
    #[serde(default)]
    pub upstream_pool: UpstreamPoolSetting,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
            dot_listen: None,
            doh_listen: None,
            doh2_listen: None,
            doq_listen: None,
            dnscrypt_listen: None,
            dnscrypt_tcp_listen: None,
            tls_cert: None,
            tls_key: None,
            tls_allow_from: Vec::new(),
            dnscrypt_provider_key: None,
            dnscrypt_resolver_key: None,
            dnscrypt_cert: None,
            secure: SecureSetting::default(),
            dnscrypt: DnscryptSetting::default(),
            metrics_listen: None,
            control_listen: None,
            control_token: None,
            control: ControlSetting::default(),
            workers: 0,
            control_cpu_affinity: Vec::new(),
            mode: ModeSetting::default(),
            forwarders: Vec::new(),
            upstreams: Vec::new(),
            allow_from: Vec::new(),
            rate_limit: None,
            rrl: None,
            upstream_pool: UpstreamPoolSetting::default(),
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

    /// Разбирает конфигурацию из строки TOML.
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

    /// Сериализует конфигурацию в TOML (например, для примера или дампа).
    ///
    /// # Errors
    ///
    /// [`ConfigError::Serialize`], если значение нельзя представить в TOML.
    pub fn to_toml_string(&self) -> Result<String, ConfigError> {
        toml::to_string(self).map_err(ConfigError::Serialize)
    }

    /// Проверяет локальные ограничения конфигурации.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`], если не задан ни один транспорт, параметры
    /// выходят за допустимые пределы или overrides некорректны.
    fn validate_control_cpu_affinity(&self) -> Result<(), ConfigError> {
        let mut seen = Vec::with_capacity(self.control_cpu_affinity.len());
        for &cpu in &self.control_cpu_affinity {
            if cpu >= MAX_CPU {
                return Err(ConfigError::invalid(format!(
                    "control_cpu_affinity: CPU {cpu} is outside 0..{MAX_CPU}"
                )));
            }
            if seen.contains(&cpu) {
                return Err(ConfigError::invalid(format!(
                    "control_cpu_affinity: duplicate CPU {cpu}"
                )));
            }
            seen.push(cpu);
        }
        Ok(())
    }

    /// Проверяет локальные ограничения конфигурации.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`], если не задан ни один транспорт, параметры
    /// выходят за допустимые пределы или overrides некорректны.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.has_any_transport() {
            return Err(ConfigError::invalid(
                "at least one transport must be configured: listen_udp, listen_tcp, dot_listen, doh_listen, doh2_listen, doq_listen, dnscrypt_listen or dnscrypt_tcp_listen",
            ));
        }
        if self.has_tls_transport() {
            if self
                .tls_cert
                .as_ref()
                .is_none_or(|path| path.as_os_str().is_empty())
            {
                return Err(ConfigError::invalid(
                    "tls_cert is required for dot_listen/doh_listen/doh2_listen/doq_listen",
                ));
            }
            if self
                .tls_key
                .as_ref()
                .is_none_or(|path| path.as_os_str().is_empty())
            {
                return Err(ConfigError::invalid(
                    "tls_key is required for dot_listen/doh_listen/doh2_listen/doq_listen",
                ));
            }
        }
        if self.has_dnscrypt_transport() {
            for (name, path) in [
                ("dnscrypt_provider_key", &self.dnscrypt_provider_key),
                ("dnscrypt_resolver_key", &self.dnscrypt_resolver_key),
                ("dnscrypt_cert", &self.dnscrypt_cert),
            ] {
                if path.as_ref().is_none_or(|path| path.as_os_str().is_empty()) {
                    return Err(ConfigError::invalid(format!(
                        "{name} is required for dnscrypt_listen/dnscrypt_tcp_listen"
                    )));
                }
            }
        }
        if let Some(path) = &self.tls_key {
            ensure_private(path, "tls_key")?;
        }
        if let Some(path) = &self.dnscrypt_provider_key {
            ensure_private(path, "dnscrypt_provider_key")?;
        }
        if let Some(path) = &self.dnscrypt_resolver_key {
            ensure_private(path, "dnscrypt_resolver_key")?;
        }
        self.build_tls_acl()?;
        self.secure.validate()?;
        self.dnscrypt.validate()?;
        if self.workers > 1024 {
            return Err(ConfigError::invalid(format!(
                "workers must be in 0..=1024, got {}",
                self.workers
            )));
        }
        self.validate_control_cpu_affinity()?;
        if self.ns_port == 0 {
            return Err(ConfigError::invalid("ns_port must be non-zero"));
        }
        match self.mode {
            ModeSetting::Forward if self.forwarders.is_empty() && self.upstreams.is_empty() => {
                return Err(ConfigError::invalid(
                    "forward mode requires at least one forwarder or upstream",
                ));
            }
            ModeSetting::Iterative if !self.upstreams.is_empty() => {
                return Err(ConfigError::invalid(
                    "upstreams are only supported in forward mode",
                ));
            }
            ModeSetting::Forward | ModeSetting::Iterative => {}
        }
        self.build_acl()?;
        if let Some(rate_limit) = &self.rate_limit
            && rate_limit.enabled
        {
            rate_limit.validate()?;
        }
        if let Some(metrics) = self.metrics_listen
            && !metrics.ip().is_loopback()
        {
            return Err(ConfigError::invalid(format!(
                "metrics_listen must be a loopback address, got {metrics}"
            )));
        }
        self.control.validate()?;
        if let Some(control) = self.control_listen {
            if !control.ip().is_loopback() {
                return Err(ConfigError::invalid(format!(
                    "control_listen must be a loopback address, got {control}"
                )));
            }
            let Some(token) = self.effective_control_token() else {
                return Err(ConfigError::invalid(
                    "control_listen requires control_token or PULSERESOLVED_API_TOKEN",
                ));
            };
            if !token.is_valid() {
                return Err(ConfigError::invalid(
                    "control token must be 1..=4096 visible ASCII characters without spaces",
                ));
            }
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
        match &self.trust_anchor {
            Some(TrustAnchorSetting::PathFile(path)) if path.as_os_str().is_empty() => {
                return Err(ConfigError::invalid("trust_anchor path must not be empty"));
            }
            Some(TrustAnchorSetting::Managed { path, state, .. })
                if path.as_os_str().is_empty() || state.as_os_str().is_empty() =>
            {
                return Err(ConfigError::invalid(
                    "trust_anchor path/state must not be empty",
                ));
            }
            _ => {}
        }
        self.upstream_pool.validate()?;
        if let Some(rrl) = &self.rrl
            && rrl.enabled
        {
            rrl.validate()?;
        }
        for entry in &self.overrides {
            entry.to_override()?;
        }
        Ok(())
    }

    /// Настроен ли хотя бы один транспорт.
    #[must_use]
    pub fn has_any_transport(&self) -> bool {
        self.has_plain_transport() || self.has_tls_transport() || self.has_dnscrypt_transport()
    }

    /// Настроен ли незашифрованный UDP/TCP.
    #[must_use]
    pub fn has_plain_transport(&self) -> bool {
        self.listen_udp.is_some() || self.listen_tcp.is_some()
    }

    /// Настроен ли DoT/DoH/DoH2/DoQ.
    #[must_use]
    pub fn has_tls_transport(&self) -> bool {
        self.dot_listen.is_some()
            || self.doh_listen.is_some()
            || self.doh2_listen.is_some()
            || self.doq_listen.is_some()
    }

    /// Настроен ли DNSCrypt (UDP или TCP).
    #[must_use]
    pub fn has_dnscrypt_transport(&self) -> bool {
        self.dnscrypt_listen.is_some() || self.dnscrypt_tcp_listen.is_some()
    }

    /// Строит ACL для TLS-транспортов: `tls_allow_from`, иначе общий `allow_from`.
    ///
    /// Возвращает `None`, если отдельного ACL нет и действует общий.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] при некорректном CIDR.
    pub fn build_tls_acl(&self) -> Result<Option<Acl>, ConfigError> {
        if self.tls_allow_from.is_empty() {
            return Ok(None);
        }
        Acl::from_cidrs(&self.tls_allow_from)
            .map(Some)
            .map_err(|error| ConfigError::invalid(format!("tls_allow_from: {error}")))
    }

    /// Пара файлов сертификата и ключа для TLS-транспортов.
    #[must_use]
    pub fn tls_paths(&self) -> Option<(&Path, &Path)> {
        match (&self.tls_cert, &self.tls_key) {
            (Some(cert), Some(key)) => Some((cert.as_path(), key.as_path())),
            _ => None,
        }
    }

    /// Строит ACL клиентов. Пустой `allow_from` означает loopback-only.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] при некорректном CIDR.
    pub fn build_acl(&self) -> Result<Acl, ConfigError> {
        if self.allow_from.is_empty() {
            return Acl::from_cidrs(["127.0.0.0/8", "::1/128"])
                .map_err(|error| ConfigError::invalid(format!("allow_from: {error}")));
        }
        Acl::from_cidrs(&self.allow_from)
            .map_err(|error| ConfigError::invalid(format!("allow_from: {error}")))
    }

    /// Строит rate limiter, если он включён.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] при некорректных параметрах.
    pub fn build_rate_limiter(&self) -> Result<Option<RateLimiter>, ConfigError> {
        let Some(rate_limit) = &self.rate_limit else {
            return Ok(None);
        };
        if !rate_limit.enabled {
            return Ok(None);
        }
        rate_limit.validate()?;
        RateLimiter::new(rate_limit.to_config())
            .map(Some)
            .map_err(|error| ConfigError::invalid(format!("rate_limit: {error}")))
    }

    /// Строит RRL, если он включён.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] при некорректных параметрах.
    pub fn build_rrl(&self) -> Result<Option<Arc<Rrl>>, ConfigError> {
        let Some(setting) = &self.rrl else {
            return Ok(None);
        };
        if !setting.enabled {
            return Ok(None);
        }
        let rrl = Rrl::new(setting.to_config())
            .map_err(|error| ConfigError::invalid(format!("rrl: {error}")))?;
        Ok(Some(Arc::new(rrl)))
    }

    /// Действие при превышении rate limit.
    #[must_use]
    pub fn rate_limit_action(&self) -> RateLimitAction {
        self.rate_limit
            .as_ref()
            .map_or(RateLimitAction::Refused, |setting| setting.action)
    }

    /// Действующий bearer-токен: env `PULSERESOLVED_API_TOKEN`, затем файл.
    #[must_use]
    pub fn effective_control_token(&self) -> Option<ControlToken> {
        if let Ok(value) = std::env::var("PULSERESOLVED_API_TOKEN")
            && !value.is_empty()
        {
            return Some(ControlToken::new(value));
        }
        self.control_token.clone()
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
            ModeSetting::Forward => {
                let mut upstreams: Vec<UpstreamConfig> = self
                    .forwarders
                    .iter()
                    .copied()
                    .map(UpstreamConfig::Udp)
                    .collect();
                upstreams.extend(
                    self.upstreams
                        .iter()
                        .map(|setting| setting.upstream.clone()),
                );
                Mode::Forward(ForwardConfig::with_upstreams(upstreams))
            }
            ModeSetting::Iterative => Mode::Iterative(IterativeConfig {
                root_hints: self.root_hints.clone(),
                ns_port: self.ns_port,
            }),
        };
        let (anchors, trust_anchor_provider) = if self.dnssec_validate {
            match &self.trust_anchor {
                None | Some(TrustAnchorSetting::Embedded) => (Vec::new(), None),
                Some(TrustAnchorSetting::PathFile(path)) => (anchors::load(path)?, None),
                Some(TrustAnchorSetting::Managed {
                    path,
                    state,
                    add_hold_down,
                    revoke_hold_down,
                }) => {
                    let loaded = anchors::load(path)?;
                    let now = unix_now();
                    let policy = TrustAnchorPolicy::new(*add_hold_down, *revoke_hold_down);
                    let mut store =
                        TrustAnchorStore::open(state.clone(), policy).map_err(|error| {
                            ConfigError::invalid(format!(
                                "cannot open trust anchor state {}: {error}",
                                state.display()
                            ))
                        })?;
                    let mut managed = Vec::new();
                    let mut static_anchors = Vec::new();
                    for anchor in loaded {
                        if anchor.zone == Name::root() {
                            let value =
                                TrustAnchor::from_ds(&anchor.ds, None, None).map_err(|error| {
                                    ConfigError::invalid(format!(
                                        "invalid root trust anchor: {error}"
                                    ))
                                })?;
                            managed.push(value);
                        } else {
                            static_anchors.push(anchor);
                        }
                    }
                    if store.anchors().is_empty() {
                        store.seed(&managed, now);
                    }
                    store.advance(now);
                    store.persist().map_err(|error| {
                        ConfigError::invalid(format!(
                            "cannot persist trust anchor state {}: {error}",
                            state.display()
                        ))
                    })?;
                    let provider: Arc<dyn TrustAnchorProvider> =
                        Arc::new(SharedTrustAnchors::new(store));
                    (static_anchors, Some(provider))
                }
            }
        } else {
            (Vec::new(), None)
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
            pool: self.upstream_pool.to_config(),
            dnssec: DnssecConfig {
                enabled: self.dnssec_validate,
                anchors,
                ..DnssecConfig::default()
            },
            trust_anchor_provider,
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
        if let Some(addr) = overrides.dot_listen {
            self.dot_listen = Some(addr);
        }
        if let Some(addr) = overrides.doh_listen {
            self.doh_listen = Some(addr);
        }
        if let Some(addr) = overrides.doh2_listen {
            self.doh2_listen = Some(addr);
        }
        if let Some(addr) = overrides.doq_listen {
            self.doq_listen = Some(addr);
        }
        if let Some(addr) = overrides.dnscrypt_listen {
            self.dnscrypt_listen = Some(addr);
        }
        if let Some(addr) = overrides.dnscrypt_tcp_listen {
            self.dnscrypt_tcp_listen = Some(addr);
        }
        if let Some(path) = &overrides.tls_cert {
            self.tls_cert = Some(path.clone());
        }
        if let Some(path) = &overrides.tls_key {
            self.tls_key = Some(path.clone());
        }
        if let Some(addr) = overrides.metrics_listen {
            self.metrics_listen = Some(addr);
        }
        if let Some(workers) = overrides.workers {
            self.workers = workers;
        }
        if let Some(cpus) = &overrides.control_cpu_affinity {
            self.control_cpu_affinity.clone_from(cpus);
        }
        if !overrides.forwarders.is_empty() {
            self.mode = ModeSetting::Forward;
            self.forwarders.clone_from(&overrides.forwarders);
        }
        if !overrides.upstreams.is_empty() {
            self.mode = ModeSetting::Forward;
            self.upstreams.extend(
                overrides
                    .upstreams
                    .iter()
                    .cloned()
                    .map(|upstream| UpstreamSetting { upstream }),
            );
        }
        if !overrides.blocklists.is_empty() {
            self.blocklist
                .paths
                .extend(overrides.blocklists.iter().cloned());
        }
        if let Some(state) = &overrides.trust_anchor_state {
            let path = overrides
                .trust_anchor
                .clone()
                .unwrap_or_else(|| PathBuf::from("root.ds"));
            let hold_down = overrides
                .trust_anchor_hold_down
                .unwrap_or(TrustAnchorSetting::DEFAULT_HOLD_DOWN);
            self.trust_anchor = Some(TrustAnchorSetting::Managed {
                path,
                state: state.clone(),
                add_hold_down: hold_down,
                revoke_hold_down: hold_down,
            });
            self.dnssec_validate = true;
        } else if let Some(path) = &overrides.trust_anchor {
            self.trust_anchor = Some(TrustAnchorSetting::PathFile(path.clone()));
            self.dnssec_validate = true;
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
    /// Новый DoT-адрес.
    pub dot_listen: Option<SocketAddr>,
    /// Новый DoH/1.1-адрес.
    pub doh_listen: Option<SocketAddr>,
    /// Новый DoH/2-адрес.
    pub doh2_listen: Option<SocketAddr>,
    /// Новый DoQ-адрес.
    pub doq_listen: Option<SocketAddr>,
    /// Новый DNSCrypt UDP-адрес.
    pub dnscrypt_listen: Option<SocketAddr>,
    /// Новый DNSCrypt TCP-адрес.
    pub dnscrypt_tcp_listen: Option<SocketAddr>,
    /// PEM-сертификат для защищённых транспортов.
    pub tls_cert: Option<PathBuf>,
    /// PEM-ключ для защищённых транспортов.
    pub tls_key: Option<PathBuf>,
    /// Новый адрес HTTP-метрик.
    pub metrics_listen: Option<SocketAddr>,
    /// Новое число UDP worker'ов.
    pub workers: Option<usize>,
    /// Новый список CPU для worker'ов резолвера.
    pub control_cpu_affinity: Option<Vec<usize>>,
    /// Новые forwarder-ы (включают forward-режим).
    pub forwarders: Vec<SocketAddr>,
    /// Дополнительные смешанные upstream (включают forward-режим).
    pub upstreams: Vec<UpstreamConfig>,
    /// Дополнительные файлы blocklist.
    pub blocklists: Vec<PathBuf>,
    /// Файл доверенных DS (включает DNSSEC).
    pub trust_anchor: Option<PathBuf>,
    /// Файл состояния RFC 5011 (включает автоматическое обновление).
    pub trust_anchor_state: Option<PathBuf>,
    /// Hold-down для RFC 5011 (add и revoke).
    pub trust_anchor_hold_down: Option<u32>,
    /// Выключить DNSSEC-валидацию.
    pub no_dnssec: bool,
    /// Новый уровень логирования.
    pub log_level: Option<LogLevel>,
}

/// Список CPU в TOML/JSON: массив чисел или строка `"0,2,4-7"`.
fn deserialize_cpu_list<'de, D>(deserializer: D) -> Result<Vec<usize>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum Spec {
        List(Vec<usize>),
        Text(String),
    }

    let cpus = match Spec::deserialize(deserializer)? {
        Spec::List(list) => list,
        Spec::Text(text) => {
            pulse_runtime::affinity::parse_list(&text).map_err(serde::de::Error::custom)?
        }
    };
    if let Some(&cpu) = cpus.iter().find(|&&cpu| cpu >= MAX_CPU) {
        return Err(serde::de::Error::custom(format!(
            "CPU {cpu} is outside 0..{MAX_CPU}"
        )));
    }
    Ok(cpus)
}

fn default_true() -> bool {
    true
}

fn default_rate_qps() -> f64 {
    20.0
}

fn default_rate_burst() -> u32 {
    100
}

fn default_rate_entries() -> usize {
    10_000
}

fn default_rrl_qps() -> f64 {
    20.0
}

fn default_rrl_burst() -> u32 {
    100
}

fn default_rrl_slip() -> u32 {
    2
}

fn default_rrl_entries() -> usize {
    20_000
}

fn default_rrl_action() -> RateLimitAction {
    RateLimitAction::Truncate
}

fn default_rrl_noerror() -> RrlRateSetting {
    RrlRateSetting {
        qps: 20.0,
        burst: 100,
    }
}

fn default_rrl_nxdomain() -> RrlRateSetting {
    RrlRateSetting {
        qps: 5.0,
        burst: 20,
    }
}

fn default_rrl_referral() -> RrlRateSetting {
    RrlRateSetting {
        qps: 10.0,
        burst: 40,
    }
}

fn default_rrl_error() -> RrlRateSetting {
    RrlRateSetting {
        qps: 5.0,
        burst: 20,
    }
}

fn default_rrl_source() -> RrlRateSetting {
    RrlRateSetting {
        qps: 50.0,
        burst: 200,
    }
}

fn default_pool_size() -> usize {
    4
}

fn default_pool_backoff_ms() -> u64 {
    100
}

fn default_pool_max_backoff_ms() -> u64 {
    5_000
}

fn default_secure_max_connections() -> usize {
    1_024
}

fn default_secure_max_streams() -> u32 {
    100
}

fn default_secure_handshake_ms() -> u64 {
    10_000
}

fn default_secure_request_ms() -> u64 {
    10_000
}

fn default_secure_idle_ms() -> u64 {
    30_000
}

fn default_secure_shutdown_ms() -> u64 {
    5_000
}

fn default_secure_max_message() -> usize {
    usize::from(u16::MAX)
}

fn default_secure_workers() -> usize {
    2
}

fn default_secure_max_requests() -> usize {
    100
}

fn default_dnscrypt_min_query_len() -> usize {
    pulse_dnscrypt::DEFAULT_MIN_QUERY_LEN
}

fn default_dnscrypt_max_udp() -> usize {
    pulse_dnscrypt::MAX_UDP_PACKET
}

fn default_dnscrypt_max_tcp() -> usize {
    pulse_dnscrypt::MAX_TCP_PACKET
}

fn default_dnscrypt_replay_ttl() -> u64 {
    pulse_dnscrypt::DEFAULT_REPLAY_TTL_SECS
}

fn default_dnscrypt_replay_capacity() -> usize {
    pulse_dnscrypt::DEFAULT_REPLAY_CAPACITY
}

/// Проверяет, что секретный файл недоступен группе и остальным (нет битов
/// `0o077`). Отсутствующий файл проверяется при запуске сервера, поэтому
/// примеры конфигурации остаются валидными без реальных ключей.
fn ensure_private(path: &Path, label: &str) -> Result<(), ConfigError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let Ok(metadata) = std::fs::metadata(path) else {
            return Ok(());
        };
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(ConfigError::invalid(format!(
                "{label} {} has insecure permissions {mode:03o}; expected 0600 or stricter",
                path.display()
            )));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, label);
    }
    Ok(())
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

fn default_control_request_ms() -> u64 {
    5_000
}

fn default_control_write_ms() -> u64 {
    5_000
}

fn default_control_shutdown_ms() -> u64 {
    5_000
}

fn default_control_connections() -> usize {
    32
}

fn default_control_qps() -> f64 {
    50.0
}

fn default_control_burst() -> u32 {
    100
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
        let config = Config::from_path(&path).expect("example config");
        config.validate().expect("example config is valid");
        assert_eq!(config.forwarders.len(), 2);
        assert!(config.dnssec_validate);
        assert_eq!(config.blocklist.paths.len(), 1);
    }

    #[test]
    fn toml_example_parses_and_validates() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/resolver.toml");
        let config = Config::from_path(&path).expect("toml example config");
        config.validate().expect("toml example config is valid");
        assert_eq!(config.forwarders.len(), 2);
        assert!(config.dnssec_validate);
        assert_eq!(config.trust_anchor, Some(TrustAnchorSetting::Embedded));
        assert_eq!(config.overrides.len(), 3);
        assert_eq!(config.blocklist.paths.len(), 1);
        assert_eq!(config.timeouts.total_ms, 6_000);
    }

    #[test]
    fn toml_and_json_examples_are_equivalent() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples");
        let toml = Config::from_path(root.join("resolver.toml")).expect("toml example");
        let json = Config::from_path(root.join("resolver.json")).expect("json example");
        assert_eq!(
            serde_json::to_value(&toml).expect("serialize toml config"),
            serde_json::to_value(&json).expect("serialize json config")
        );
    }

    #[test]
    fn toml_round_trip_preserves_config() {
        let text = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/resolver.toml"),
        )
        .expect("read toml example");
        let config = Config::from_toml_str(&text).expect("parse toml");
        let rendered = config.to_toml_string().expect("serialize toml");
        let reparsed = Config::from_toml_str(&rendered).expect("reparse rendered toml");
        assert_eq!(
            serde_json::to_value(&config).expect("serialize original"),
            serde_json::to_value(&reparsed).expect("serialize reparsed")
        );
        assert_eq!(reparsed.overrides.len(), 3);
        assert_eq!(reparsed.cache.max_bytes, 16_777_216);
    }

    #[test]
    fn toml_round_trip_preserves_upstreams_and_rate_limit() {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/resolver-secure.json");
        let config = Config::from_path(&path).expect("secure example");
        let rendered = config.to_toml_string().expect("serialize toml");
        let reparsed = Config::from_toml_str(&rendered).expect("reparse rendered toml");
        assert_eq!(
            serde_json::to_value(&config).expect("serialize original"),
            serde_json::to_value(&reparsed).expect("serialize reparsed")
        );
        assert_eq!(reparsed.upstreams.len(), 4);
        assert!(reparsed.rate_limit.is_some());
        assert_eq!(reparsed.allow_from.len(), 3);
    }

    #[test]
    fn toml_supports_all_config_fields() {
        let text = r#"
listen_udp = "127.0.0.1:5353"
listen_tcp = "127.0.0.1:5354"
metrics_listen = "127.0.0.1:9153"
workers = 0
mode = "iterative"
root_hints = ["198.41.0.4:53"]
ns_port = 53
dnssec_validate = true
trust_anchor = { path = "root.ds" }
log_level = "debug"

[blocklist]
paths = ["block.txt"]
allowlist = ["safe.example"]
response = "null"
reload_secs = 60

[[overrides]]
name = "router.home"
ttl = 120
a = ["192.168.1.1"]
aaaa = ["fd00::1"]

[[overrides]]
name = "printer.home"
cname = "router.home."

[rate_limit]
enabled = true
qps = 5.5
burst = 10
max_entries = 100
action = "truncate"

[cache]
max_entries = 100
max_bytes = 1048576
min_ttl = 1
max_ttl = 300
shards = 4

[tcp]
max_connections = 10
idle_timeout_ms = 1000

[timeouts]
per_query_ms = 500
tcp_ms = 1000
total_ms = 2000
"#;
        let config = Config::from_toml_str(text).expect("all fields");
        config.validate().expect("all-fields config is valid");
        assert_eq!(
            config.listen_udp,
            Some("127.0.0.1:5353".parse().expect("addr"))
        );
        assert_eq!(
            config.listen_tcp,
            Some("127.0.0.1:5354".parse().expect("addr"))
        );
        assert_eq!(
            config.metrics_listen,
            Some("127.0.0.1:9153".parse().expect("addr"))
        );
        assert_eq!(config.mode, ModeSetting::Iterative);
        assert_eq!(
            config.root_hints,
            vec!["198.41.0.4:53".parse::<SocketAddr>().expect("hint")]
        );
        assert_eq!(config.ns_port, 53);
        assert_eq!(
            config.trust_anchor,
            Some(TrustAnchorSetting::PathFile(PathBuf::from("root.ds")))
        );
        assert_eq!(config.blocklist.response, BlockResponseSetting::Null);
        assert_eq!(config.blocklist.reload_secs, 60);
        assert_eq!(config.overrides.len(), 2);
        assert_eq!(config.overrides[1].cname.as_deref(), Some("router.home."));
        let rate_limit = config.rate_limit.as_ref().expect("rate limit");
        assert!((rate_limit.qps - 5.5).abs() < f64::EPSILON);
        assert_eq!(rate_limit.action, RateLimitAction::Truncate);
        assert_eq!(config.cache.min_ttl, 1);
        assert_eq!(config.tcp.idle_timeout_ms, 1000);
        assert_eq!(config.timeouts.per_query_ms, 500);
        assert_eq!(config.log_level, LogLevel::Debug);

        let rendered = config.to_toml_string().expect("serialize all fields");
        let reparsed = Config::from_toml_str(&rendered).expect("reparse all fields");
        assert_eq!(
            serde_json::to_value(&config).expect("serialize original"),
            serde_json::to_value(&reparsed).expect("serialize reparsed")
        );
    }

    #[test]
    fn config_extension_is_case_insensitive() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("Config.TOML");
        std::fs::write(
            &path,
            "listen_udp = \"127.0.0.1:5353\"\nupstreams = [\"1.1.1.1\"]\n",
        )
        .expect("write config");
        let config = Config::from_path(&path).expect("uppercase toml extension");
        config.validate().expect("valid config");
    }

    #[test]
    fn unknown_extension_is_rejected_with_hint() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("resolver.yaml");
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
        std::fs::write(&path, "listen_udp = \"127.0.0.1:5353\"\nwat = 1\n").expect("write config");
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
        let error = Config::from_toml_str("listen_udp = \"127.0.0.1:5353\"\nworkers = \"many\"\n")
            .expect_err("bad type must be rejected");
        let message = error.to_string();
        assert!(message.contains("invalid type"), "{message}");
        assert!(message.contains("line 2"), "{message}");
        assert!(message.contains("column"), "{message}");
    }

    #[test]
    fn toml_syntax_error_reports_position() {
        let error = Config::from_toml_str("listen_udp = \"127.0.0.1:5353\n")
            .expect_err("unterminated string must be rejected");
        let message = error.to_string();
        assert!(message.contains("TOML parse error"), "{message}");
        assert!(message.contains("line 1"), "{message}");
        assert!(message.contains("column"), "{message}");
    }

    #[test]
    fn json_unknown_field_reports_position() {
        let error = Config::from_json_str("{\"listen_udp\": \"127.0.0.1:5353\", \"wat\": 1}")
            .expect_err("unknown field must be rejected");
        let message = error.to_string();
        assert!(message.contains("unknown field `wat`"), "{message}");
        assert!(message.contains("line 1"), "{message}");
        assert!(message.contains("column"), "{message}");
    }

    #[test]
    fn cli_overrides_apply_over_toml() {
        let text = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/resolver.toml"),
        )
        .expect("read toml example");
        let mut config = Config::from_toml_str(&text).expect("parse toml");
        config.apply_overrides(&Overrides {
            listen_udp: Some("127.0.0.2:5300".parse().expect("addr")),
            workers: Some(4),
            log_level: Some(LogLevel::Debug),
            blocklists: vec![PathBuf::from("extra-blocklist.txt")],
            no_dnssec: true,
            ..Overrides::default()
        });
        assert_eq!(
            config.listen_udp,
            Some("127.0.0.2:5300".parse().expect("addr"))
        );
        assert_eq!(config.workers, 4);
        assert_eq!(config.log_level, LogLevel::Debug);
        assert_eq!(config.mode, ModeSetting::Forward);
        assert_eq!(config.blocklist.paths.len(), 2);
        assert!(!config.dnssec_validate);
        config.validate().expect("overridden config is valid");
    }

    #[test]
    fn secure_example_config_parses() {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/resolver-secure.json");
        let config = Config::from_path(&path).expect("secure example");
        config.validate().expect("secure example is valid");
        assert_eq!(config.upstreams.len(), 4);
        assert!(config.rate_limit.is_some());
        assert_eq!(config.allow_from.len(), 3);
        let resolver = config.resolver_config().expect("resolver config");
        let Mode::Forward(forward) = resolver.mode else {
            panic!("forward mode expected");
        };
        assert_eq!(forward.effective_upstreams().len(), 4);
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
    fn control_listen_requires_loopback_and_token() {
        let mut config = forward_config();
        config.control_listen = Some("127.0.0.1:9154".parse().unwrap());
        assert!(config.validate().is_err(), "token is required");
        config.control_token = Some(ControlToken::new("control-secret"));
        assert!(config.validate().is_ok());

        config.control_listen = Some("0.0.0.0:9154".parse().unwrap());
        assert!(config.validate().is_err(), "non-loopback is rejected");

        let mut config = forward_config();
        config.control_listen = Some("127.0.0.1:9154".parse().unwrap());
        config.control_token = Some(ControlToken::new("bad token"));
        assert!(config.validate().is_err(), "spaces are rejected");

        let mut config = forward_config();
        config.control.rate_limit_burst = 0;
        assert!(config.validate().is_err());
        assert_eq!(
            format!("{:?}", ControlToken::new("control-secret")),
            "<redacted>"
        );
    }

    #[test]
    fn upstreams_parse_strings_and_objects() {
        let text = r#"{
            "listen_udp": "127.0.0.1:0",
            "upstreams": [
                "1.1.1.1",
                "tcp://9.9.9.9:53",
                "tls://dns.example:853#dns.example",
                {"addr": "127.0.0.1:8853", "tls": true, "server_name": "localhost"},
                {"url": "https://dns.example/dns-query", "ca": "ca.pem"}
            ]
        }"#;
        let config = Config::from_json_str(text).expect("config");
        config.validate().expect("valid");
        assert_eq!(config.upstreams.len(), 5);
        let resolver = config.resolver_config().expect("resolver");
        let Mode::Forward(forward) = resolver.mode else {
            panic!("forward mode expected");
        };
        assert_eq!(forward.effective_upstreams().len(), 5);
        assert_eq!(forward.effective_upstreams()[0].kind(), "udp");
        assert_eq!(forward.effective_upstreams()[1].kind(), "tcp");
        assert_eq!(forward.effective_upstreams()[2].kind(), "tls");
        assert_eq!(forward.effective_upstreams()[3].kind(), "tls");
        assert_eq!(forward.effective_upstreams()[4].kind(), "https");
    }

    #[test]
    fn allow_from_and_rate_limit_are_validated() {
        let mut config = forward_config();
        config.allow_from = vec!["192.0.2.0/24".to_owned(), "2001:db8::/32".to_owned()];
        let acl = config.build_acl().expect("acl");
        assert!(acl.allows("192.0.2.5".parse().unwrap()));
        assert!(acl.allows("2001:db8::1".parse().unwrap()));
        assert!(!acl.allows("198.51.100.1".parse().unwrap()));

        config.allow_from = vec!["not-a-cidr".to_owned()];
        assert!(config.validate().is_err());

        let mut config = forward_config();
        config.rate_limit = Some(RateLimitSetting {
            qps: 0.0,
            ..RateLimitSetting::default()
        });
        assert!(config.validate().is_err());
        config.rate_limit = Some(RateLimitSetting {
            burst: 0,
            ..RateLimitSetting::default()
        });
        assert!(config.validate().is_err());
        config.rate_limit = Some(RateLimitSetting::default());
        assert!(config.validate().is_ok());
        assert!(config.build_rate_limiter().expect("limiter").is_some());
    }

    #[test]
    fn rrl_and_pool_settings_parse_and_validate() {
        let text = r#"{
            "listen_udp": "127.0.0.1:0",
            "forwarders": ["127.0.0.1:53"],
            "upstream_pool": {
                "pool_size": 8,
                "reconnect_backoff_ms": 50,
                "max_reconnect_backoff_ms": 500
            },
            "rrl": {
                "enabled": true,
                "slip": 3,
                "action": "truncate",
                "nxdomain": { "qps": 2, "burst": 10 }
            }
        }"#;
        let config = Config::from_json_str(text).expect("config");
        config.validate().expect("valid");
        assert_eq!(config.upstream_pool.pool_size, 8);
        let rrl = config.rrl.as_ref().expect("rrl");
        assert_eq!(rrl.slip, 3);
        assert_eq!(rrl.nxdomain.qps, 2.0);
        assert_eq!(rrl.nxdomain.burst, 10);
        // Незаданные классы берут значения по умолчанию.
        assert_eq!(rrl.noerror.burst, default_rrl_noerror().burst);
        assert_eq!(rrl.source.qps, default_rrl_source().qps);
        let resolver = config.resolver_config().expect("resolver");
        assert_eq!(resolver.pool.size, 8);
        assert!(config.build_rrl().expect("rrl").is_some());

        let mut config = Config::from_json_str(text).expect("config");
        config.upstream_pool.pool_size = 0;
        assert!(config.validate().is_err());
        let mut config = Config::from_json_str(text).expect("config");
        config.upstream_pool.reconnect_backoff_ms = 1_000;
        config.upstream_pool.max_reconnect_backoff_ms = 10;
        assert!(config.validate().is_err());
        let mut config = Config::from_json_str(text).expect("config");
        if let Some(rrl) = config.rrl.as_mut() {
            rrl.nxdomain.burst = 0;
        }
        assert!(config.validate().is_err());
        let mut config = Config::from_json_str(text).expect("config");
        if let Some(rrl) = config.rrl.as_mut() {
            rrl.slip = 10_000;
        }
        assert!(config.validate().is_err());
    }

    #[test]
    fn disabled_rrl_is_not_built() {
        let mut config = forward_config();
        config.rrl = Some(RrlSetting {
            enabled: false,
            ..RrlSetting::default()
        });
        config.validate().expect("disabled rrl is not validated");
        assert!(config.build_rrl().expect("build").is_none());
    }

    #[test]
    fn iterative_mode_rejects_upstreams() {
        let mut config = Config {
            mode: ModeSetting::Iterative,
            ..Config::default()
        };
        config.listen_udp = Some("127.0.0.1:0".parse().unwrap());
        config.upstreams = vec![UpstreamSetting {
            upstream: UpstreamConfig::parse("1.1.1.1").unwrap(),
        }];
        assert!(config.validate().is_err());
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

    #[test]
    fn control_cpu_affinity_parses_and_validates() {
        let text = r#"
listen_udp = "127.0.0.1:0"
forwarders = ["1.1.1.1:53"]
control_cpu_affinity = "0,2-3"
"#;
        let config = Config::from_toml_str(text).expect("parse");
        assert_eq!(config.control_cpu_affinity, vec![0, 2, 3]);
        config.validate().expect("valid affinity");

        let array = Config::from_toml_str(
            r#"
listen_udp = "127.0.0.1:0"
control_cpu_affinity = [4, 5]
"#,
        )
        .expect("parse array");
        assert_eq!(array.control_cpu_affinity, vec![4, 5]);

        // Дубликаты и CPU вне маски отвергаются.
        let duplicate = Config {
            listen_udp: Some("127.0.0.1:0".parse().unwrap()),
            forwarders: vec!["1.1.1.1:53".parse().unwrap()],
            control_cpu_affinity: vec![1, 1],
            ..Config::default()
        };
        assert!(duplicate.validate().is_err());
        let outside = Config {
            listen_udp: Some("127.0.0.1:0".parse().unwrap()),
            forwarders: vec!["1.1.1.1:53".parse().unwrap()],
            control_cpu_affinity: vec![MAX_CPU],
            ..Config::default()
        };
        assert!(outside.validate().is_err());
        // Ошибка разбора диапазона видна на этапе конфигурации.
        assert!(
            Config::from_toml_str(
                r#"
listen_udp = "127.0.0.1:0"
control_cpu_affinity = "5-2"
"#
            )
            .is_err()
        );
    }

    #[test]
    fn control_cpu_affinity_override_applies() {
        let mut config = Config::from_toml_str(r#"listen_udp = "127.0.0.1:0""#).expect("parse");
        config.apply_overrides(&Overrides {
            control_cpu_affinity: Some(vec![1, 3]),
            ..Overrides::default()
        });
        assert_eq!(config.control_cpu_affinity, vec![1, 3]);
    }
}
