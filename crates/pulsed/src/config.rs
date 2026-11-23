//! JSON-конфигурация сервера и CLI-overrides.
//!
//! Конфигурация намеренно плоская: адреса транспортов, число UDP worker'ов,
//! уровень логирования, параметры TCP и список зон. Все записи зоны описаны
//! в [`ZoneConfig`]; RDATA разбирается по типу в [`crate::zone`].
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

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::Deserialize;
use thiserror::Error;

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
    /// Обслуживаемые зоны.
    pub zones: Vec<ZoneConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_udp: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5353)),
            listen_tcp: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5353)),
            workers: 0,
            log_level: LogLevel::Info,
            tcp: TcpConfig::default(),
            zones: Vec::new(),
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
        Ok(())
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
    }
}

/// Значения, переопределяющие конфигурационный файл из CLI.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Overrides {
    /// Новый адрес UDP.
    pub listen_udp: Option<SocketAddr>,
    /// Новый адрес TCP.
    pub listen_tcp: Option<SocketAddr>,
    /// Новое число UDP worker'ов.
    pub workers: Option<usize>,
    /// Новый уровень логирования.
    pub log_level: Option<LogLevel>,
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
    fn log_level_parses_case_insensitively() {
        assert_eq!("WARN".parse::<LogLevel>().unwrap(), LogLevel::Warn);
        assert!("loud".parse::<LogLevel>().is_err());
    }
}
