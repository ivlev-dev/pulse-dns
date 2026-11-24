//! Ошибки TLS/DoT/DoH-серверов.

use std::io;
use std::net::IpAddr;
use std::time::Duration;

use thiserror::Error;

/// Ошибка конфигурации или обслуживания соединения.
#[derive(Debug, Error)]
pub enum Error {
    /// Ошибка ввода-вывода (сокет, файл сертификата, PEM).
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    /// Ошибка rustls (рукопожатие, сертификат, ALPN).
    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),
    /// Ошибка разбора PEM (сертификат или ключ).
    #[error("PEM error: {0}")]
    Pem(#[from] rustls_pki_types::pem::Error),
    /// Рукопожатие не уложилось в отведённое время.
    #[error("TLS handshake timed out")]
    HandshakeTimeout,
    /// Операция не уложилась в отведённый дедлайн.
    #[error("operation timed out")]
    Timeout,
    /// Клиент не согласовал ALPN.
    #[error("client did not negotiate ALPN")]
    AlpnMissing,
    /// Клиент согласовал не тот протокол ALPN.
    #[error("unexpected ALPN protocol: expected {expected:?}, got {got:?}")]
    AlpnMismatch {
        /// Ожидаемый протокол.
        expected: Vec<u8>,
        /// Фактически согласованный протокол.
        got: Vec<u8>,
    },
    /// В PEM-входе нет сертификатов.
    #[error("PEM input contains no certificates")]
    NoCertificates,
    /// В PEM-входе нет закрытого ключа.
    #[error("PEM input contains no private key")]
    NoPrivateKey,
    /// Некорректная конфигурация сервера.
    #[error("invalid configuration: {0}")]
    InvalidConfig(&'static str),
    /// Некорректный CIDR в ACL.
    #[error("invalid CIDR rule: {0}")]
    InvalidCidr(String),
    /// Некорректный URL upstream-сервера.
    #[error("invalid upstream URL: {0}")]
    InvalidUrl(String),
    /// Имя хоста upstream не разрешилось ни в один адрес.
    #[error("no addresses found for upstream host {0}")]
    NoAddresses(String),
    /// DoH-сервер вернул HTTP-статус, отличный от 200.
    #[error("DoH server returned HTTP status {status}")]
    HttpStatus {
        /// HTTP-статус.
        status: u16,
    },
    /// DoH-сервер вернул не `application/dns-message`.
    #[error("DoH response has unexpected Content-Type")]
    HttpContentType,
    /// Обработчик DNS-запроса запаниковал.
    #[error("DNS handler panicked")]
    HandlerPanic,
    /// DNS-сообщение или HTTP-тело превышает лимит.
    #[error("message exceeds limit of {limit} bytes")]
    MessageTooLarge {
        /// Лимит в байтах.
        limit: usize,
    },
    /// Соединение закрыто.
    #[error("connection closed")]
    Closed,
    /// Upstream в cooldown после неудачных подключений.
    #[error("upstream is cooling down for {retry_after:?}")]
    Cooldown {
        /// Сколько осталось до следующей попытки.
        retry_after: Duration,
    },
    /// Клиент превысил rate limit.
    #[error("rate limit exceeded")]
    RateLimited,
    /// IP-адрес не прошёл ACL.
    #[error("access denied for {0}")]
    AccessDenied(IpAddr),
    /// Некорректный HTTP-запрос.
    #[error("malformed HTTP request: {0}")]
    Http(String),
    /// Поток сервера завершился паникой.
    #[error("server thread panicked")]
    ThreadPanicked,
    /// Попытка перечитать сертификат из файлов, если они не были заданы.
    #[error("certificate paths are not configured")]
    NoCertificatePaths,
    /// Сервис уже остановлен.
    #[error("server is shut down")]
    Shutdown,
    /// Ошибка QUIC/DoQ/DoH3.
    #[cfg(any(feature = "doq", feature = "http3"))]
    #[error("QUIC error: {0}")]
    Quic(String),
}

impl Error {
    /// Признак таймаута сокета или рукопожатия.
    #[must_use]
    pub fn is_timeout(&self) -> bool {
        match self {
            Self::HandshakeTimeout | Self::Timeout => true,
            Self::Io(error) => matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ),
            _ => false,
        }
    }

    /// Признак ошибки, после которой имеет смысл переподключиться.
    #[must_use]
    pub(crate) fn is_retryable_connection(&self) -> bool {
        match self {
            Self::Closed => true,
            Self::Io(error) => !matches!(
                error.kind(),
                io::ErrorKind::WouldBlock
                    | io::ErrorKind::TimedOut
                    | io::ErrorKind::InvalidInput
                    | io::ErrorKind::NotFound
                    | io::ErrorKind::PermissionDenied
            ),
            _ => false,
        }
    }

    /// Признак штатного закрытия соединения клиентом.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        match self {
            Self::Closed => true,
            Self::Io(error) => matches!(
                error.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe
            ),
            _ => false,
        }
    }
}
