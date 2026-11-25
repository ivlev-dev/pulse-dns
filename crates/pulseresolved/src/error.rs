//! Ошибки конфигурации и запуска сервера.

use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use thiserror::Error;

/// Причина ошибки разбора конфигурационного файла.
///
/// Оба формата сообщают позицию (строка/колонка) в своём `Display`.
#[derive(Debug, Error)]
pub enum ParseSource {
    /// Ошибка JSON (legacy-формат).
    #[error("{0}")]
    Json(#[from] serde_json::Error),
    /// Ошибка TOML.
    #[error("{0}")]
    Toml(#[from] toml::de::Error),
}

/// Ошибка чтения, разбора или валидации конфигурации.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Не удалось прочитать файл.
    #[error("cannot read configuration file {path}: {source}")]
    Read {
        /// Путь к файлу.
        path: PathBuf,
        /// Причина.
        #[source]
        source: io::Error,
    },
    /// Содержимое файла не соответствует схеме.
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
    /// Создаёт ошибку валидации.
    pub(crate) fn invalid(reason: impl Into<String>) -> Self {
        Self::Invalid(reason.into())
    }

    /// Заменяет путь `<inline>` на путь реального файла.
    pub(crate) fn with_path(self, path: &Path) -> Self {
        match self {
            Self::Parse { source, .. } => Self::Parse {
                path: path.to_path_buf(),
                source,
            },
            other => other,
        }
    }
}

/// Ошибка запуска или остановки сервера.
#[derive(Debug, Error)]
pub enum ServerError {
    /// Некорректная конфигурация.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// Ошибка создания резолвера (конфигурация или blocklist).
    #[error(transparent)]
    Resolver(#[from] pulse_resolver::ResolverError),
    /// Ошибка UDP-рантайма.
    #[error(transparent)]
    Udp(#[from] pulse_runtime::RuntimeError),
    /// Не удалось запустить TCP-listener.
    #[error("cannot start TCP listener {addr}: {source}")]
    TcpStart {
        /// Запрошенный адрес.
        addr: SocketAddr,
        /// Причина.
        #[source]
        source: io::Error,
    },
    /// TCP-транспорт не остановился штатно.
    #[error("TCP shutdown failed: {0}")]
    Tcp(String),
    /// Не удалось запустить HTTP-сервер метрик.
    #[error("cannot start metrics listener {addr}: {source}")]
    MetricsStart {
        /// Запрошенный адрес.
        addr: SocketAddr,
        /// Причина.
        #[source]
        source: io::Error,
    },
    /// Не удалось запустить control-plane HTTP-сервер.
    #[error("cannot start control listener {addr}: {source}")]
    ControlStart {
        /// Запрошенный адрес.
        addr: SocketAddr,
        /// Причина.
        #[source]
        source: io::Error,
    },
    /// Не удалось запустить фоновый reload blocklist.
    #[error("cannot start blocklist reloader: {0}")]
    Reload(#[source] io::Error),
    /// Не удалось запустить TLS/QUIC-транспорт.
    #[error("cannot start {transport} listener {addr}: {source}")]
    SecureStart {
        /// Название транспорта.
        transport: &'static str,
        /// Запрошенный адрес.
        addr: SocketAddr,
        /// Причина.
        #[source]
        source: pulse_tls::Error,
    },
    /// Ошибка запуска, остановки или перезагрузки TLS/QUIC-транспорта.
    #[error("{transport}: {source}")]
    Secure {
        /// Название транспорта.
        transport: &'static str,
        /// Причина.
        #[source]
        source: pulse_tls::Error,
    },
    /// Ошибка DNSCrypt-транспорта или загрузки ключей.
    #[error("DNSCrypt: {0}")]
    Dnscrypt(String),
    /// Список CPU не пересекается с `sched_getaffinity`/cpuset.
    #[error("CPU affinity error: {0}")]
    Affinity(String),
}
