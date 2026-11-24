//! Ошибки конфигурации и запуска сервера.

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;

use thiserror::Error;

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
    /// Создаёт ошибку валидации.
    pub(crate) fn invalid(reason: impl Into<String>) -> Self {
        Self::Invalid(reason.into())
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
    /// Не удалось запустить фоновый reload blocklist.
    #[error("cannot start blocklist reloader: {0}")]
    Reload(#[source] io::Error),
}
