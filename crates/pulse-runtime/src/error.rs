//! Ошибки рантайма.

use std::io;
use std::net::SocketAddr;

use thiserror::Error;

/// Ошибка инициализации или работы `pulse-runtime`.
#[derive(Debug, Error)]
pub enum RuntimeError {
    /// Некорректная конфигурация.
    #[error("invalid runtime configuration: {0}")]
    Config(String),

    /// `io_uring_setup` недоступен (старое ядро, `kernel.io_uring_disabled`, seccomp).
    #[error(
        "io_uring is not available: {source}. \
         Check `sysctl kernel.io_uring_disabled` (must be 0), the seccomp profile of the \
         container, and the kernel version (>= 5.6, multishot requires >= 6.0); \
         alternatively build with `--features epoll-fallback` and select \
         `BackendPreference::Epoll`"
    )]
    IoUringUnavailable {
        /// Первопричина от ядра.
        #[source]
        source: io::Error,
    },

    /// io_uring настроен, но конкретная операция (регистрация, submit) не удалась.
    #[error("io_uring error during {context}: {source}")]
    IoUring {
        /// Что именно делали.
        context: &'static str,
        /// Ошибка ядра.
        #[source]
        source: io::Error,
    },

    /// Не удалось создать или сконфигурировать сокет.
    #[error("socket error for {addr}: {source}")]
    Socket {
        /// Адрес, с которым работали.
        addr: SocketAddr,
        /// Ошибка ОС.
        #[source]
        source: io::Error,
    },

    /// Внутренняя ошибка сокета без привязки к адресу (например, `getsockname`).
    #[error("socket error: {source}")]
    SocketIo {
        /// Ошибка ОС.
        #[source]
        source: io::Error,
    },

    /// epoll-бэкенд не скомпилирован.
    #[error(
        "epoll backend is not compiled in; rebuild with `--features epoll-fallback` \
         or use `BackendPreference::Auto`"
    )]
    EpollUnsupported,

    /// `start()` вызван повторно.
    #[error("server is already running")]
    AlreadyStarted,

    /// `wait()` вызван до `start()`.
    #[error("server is not started")]
    NotStarted,

    /// Рантайм уже остановлен; новые серверы не принимаются.
    #[error("runtime is already shut down")]
    Shutdown,

    /// Не удалось создать `eventfd` для пробуждения worker'а.
    #[error("eventfd creation failed: {source}")]
    Wake {
        /// Ошибка ОС.
        #[source]
        source: io::Error,
    },

    /// Worker-поток запаниковал.
    #[error("worker thread {worker} panicked")]
    WorkerPanicked {
        /// Индекс worker'а.
        worker: usize,
    },

    /// Worker не завершился за отведённый дедлайн.
    #[error("worker did not finish within the shutdown deadline")]
    WorkerTimeout,

    /// Worker завершился с ошибкой.
    #[error("worker {worker} failed: {source}")]
    Worker {
        /// Индекс worker'а.
        worker: usize,
        /// Причина.
        #[source]
        source: Box<RuntimeError>,
    },
}

impl RuntimeError {
    pub(crate) fn io_uring(context: &'static str, source: io::Error) -> Self {
        Self::IoUring { context, source }
    }
}
