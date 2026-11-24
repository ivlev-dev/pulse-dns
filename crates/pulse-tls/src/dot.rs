//! DNS over TLS (RFC 7858): TLS 1.2/1.3, length-prefixed DNS, keep-alive
//! нескольких сообщений на соединение, idle timeout и graceful shutdown.

use std::net::{Shutdown as SocketShutdown, SocketAddr, TcpListener, TcpStream};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::acl::Acl;
use crate::error::Error;
use crate::ratelimit::{RateLimitConfig, RateLimiter};
use crate::server::{ConnectionGuard, ConnectionSet};
use crate::stats::{Stats, StatsSnapshot};
use crate::tls::TlsConfig;
use crate::transport::TlsStream;

/// Обработчик DNS-запроса: возвращает готовый DNS-ответ или `None`, чтобы
/// закрыть соединение без ответа.
pub type DnsHandler = Arc<dyn Fn(&[u8], SocketAddr) -> Option<Vec<u8>> + Send + Sync + 'static>;

const DEFAULT_MAX_CONNECTIONS: usize = 1024;
const DEFAULT_MAX_MESSAGE_SIZE: usize = 65_535;
const DEFAULT_MAX_MESSAGES: usize = 1000;

/// Конфигурация DoT-сервера.
#[derive(Clone, Debug)]
pub struct DotConfig {
    /// Адрес прослушивания.
    pub listen: SocketAddr,
    /// TLS-конфигурация с ALPN `dot`.
    pub tls: TlsConfig,
    /// Максимум одновременных TCP-соединений.
    pub max_connections: usize,
    /// Таймаут TLS-рукопожатия.
    pub handshake_timeout: Duration,
    /// Таймаут простоя между DNS-сообщениями.
    pub idle_timeout: Duration,
    /// Таймаут ожидания соединений при shutdown.
    pub shutdown_timeout: Duration,
    /// Максимальный размер DNS-сообщения (без 2-байтового префикса).
    pub max_message_size: usize,
    /// Максимум сообщений на одно TCP-соединение.
    pub max_messages_per_connection: usize,
    /// Опциональный ACL по IP.
    pub acl: Option<Acl>,
    /// Опциональный per-IP rate limit.
    pub rate_limit: Option<RateLimitConfig>,
}

impl DotConfig {
    /// Конфигурация с безопасными значениями по умолчанию.
    #[must_use]
    pub fn new(listen: SocketAddr, tls: TlsConfig) -> Self {
        Self {
            listen,
            tls,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            handshake_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(30),
            shutdown_timeout: Duration::from_secs(5),
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            max_messages_per_connection: DEFAULT_MAX_MESSAGES,
            acl: None,
            rate_limit: None,
        }
    }

    fn validate(&self) -> Result<(), Error> {
        if self.max_connections == 0 {
            return Err(Error::InvalidConfig("max_connections must be positive"));
        }
        if self.max_message_size == 0 || self.max_message_size > usize::from(u16::MAX) {
            return Err(Error::InvalidConfig(
                "max_message_size must be in 1..=65535",
            ));
        }
        if self.max_messages_per_connection == 0 {
            return Err(Error::InvalidConfig(
                "max_messages_per_connection must be positive",
            ));
        }
        if self.handshake_timeout.is_zero()
            || self.idle_timeout.is_zero()
            || self.shutdown_timeout.is_zero()
        {
            return Err(Error::InvalidConfig("timeouts must be positive"));
        }
        Ok(())
    }
}

struct Shared {
    config: DotConfig,
    handler: DnsHandler,
    limiter: Option<RateLimiter>,
    stats: Arc<Stats>,
    shutdown: Arc<AtomicBool>,
}

/// Запущенный DoT-сервер.
pub struct DotServer {
    local_addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    stats: Arc<Stats>,
    connections: Arc<ConnectionSet>,
    acceptor: Option<JoinHandle<()>>,
    shutdown_timeout: Duration,
    tls: TlsConfig,
}

impl std::fmt::Debug for DotServer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DotServer")
            .field("local_addr", &self.local_addr)
            .field("stats", &self.stats.snapshot())
            .finish_non_exhaustive()
    }
}

impl DotServer {
    /// Привязывает listener и запускает accept loop.
    ///
    /// # Errors
    ///
    /// Ошибка bind/настройки listener, некорректная конфигурация или
    /// невозможность создать поток.
    pub fn bind<H>(config: DotConfig, handler: H) -> Result<Self, Error>
    where
        H: Fn(&[u8], SocketAddr) -> Option<Vec<u8>> + Send + Sync + 'static,
    {
        Self::bind_with_stats(config, handler, Arc::new(Stats::new()))
    }

    /// То же, но с общими счётчиками.
    ///
    /// # Errors
    ///
    /// См. [`DotServer::bind`].
    pub fn bind_with_stats<H>(
        config: DotConfig,
        handler: H,
        stats: Arc<Stats>,
    ) -> Result<Self, Error>
    where
        H: Fn(&[u8], SocketAddr) -> Option<Vec<u8>> + Send + Sync + 'static,
    {
        Self::bind_shared(config, Arc::new(handler), stats)
    }

    /// Запускает сервер с уже разделяемым обработчиком.
    ///
    /// # Errors
    ///
    /// См. [`DotServer::bind`].
    pub fn bind_shared(
        config: DotConfig,
        handler: DnsHandler,
        stats: Arc<Stats>,
    ) -> Result<Self, Error> {
        config.validate()?;
        let limiter = match config.rate_limit {
            Some(rate_limit) => Some(RateLimiter::new(rate_limit)?),
            None => None,
        };
        let listener = TcpListener::bind(config.listen)?;
        let local_addr = listener.local_addr()?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let connections = Arc::new(ConnectionSet::new(Arc::clone(&stats)));
        let shared = Arc::new(Shared {
            config: config.clone(),
            handler,
            limiter,
            stats: Arc::clone(&stats),
            shutdown: Arc::clone(&shutdown),
        });
        let on_connection = {
            let shared = Arc::clone(&shared);
            Arc::new(
                move |stream: TcpStream, peer: SocketAddr, guard: ConnectionGuard| {
                    if let Some(acl) = &shared.config.acl
                        && !acl.allows(peer.ip())
                    {
                        shared.stats.connection_rejected();
                        let _ = stream.shutdown(SocketShutdown::Both);
                        return;
                    }
                    let stats = Arc::clone(&shared.stats);
                    let shared = Arc::clone(&shared);
                    let thread_name = format!("pulse-dot-{}", guard.id());
                    let spawned = thread::Builder::new().name(thread_name).spawn(move || {
                        let _guard = guard;
                        if let Err(error) = handle_connection(stream, peer, &shared) {
                            if error.is_timeout() {
                                shared.stats.timeout();
                            } else if !error.is_closed() {
                                shared.stats.error();
                            }
                        }
                    });
                    if spawned.is_err() {
                        stats.error();
                    }
                },
            )
        };
        let acceptor = crate::server::spawn_acceptor(
            "pulse-dot-accept".to_owned(),
            listener,
            Arc::clone(&shutdown),
            Arc::clone(&stats),
            Arc::clone(&connections),
            config.max_connections,
            on_connection,
        )?;
        Ok(Self {
            local_addr,
            shutdown,
            stats,
            connections,
            acceptor: Some(acceptor),
            shutdown_timeout: config.shutdown_timeout,
            tls: config.tls,
        })
    }

    /// Фактический адрес (полезен при `port = 0`).
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Текущая статистика.
    #[must_use]
    pub fn stats(&self) -> StatsSnapshot {
        self.stats.snapshot()
    }

    /// Проверяет, остановлен ли сервер.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Acquire)
    }

    /// Перечитывает сертификат из PEM-байтов для новых соединений.
    ///
    /// # Errors
    ///
    /// Ошибка парсинга или сборки rustls-конфигурации.
    pub fn reload(&self, cert_pem: &[u8], key_pem: &[u8]) -> Result<(), Error> {
        self.tls.reload(cert_pem, key_pem)
    }
    /// Перечитывает сертификат из файлов, заданных при создании `TlsConfig`.
    ///
    /// # Errors
    ///
    /// [`Error::NoCertificatePaths`] или ошибки чтения/парсинга.
    pub fn reload_from_files(&self) -> Result<(), Error> {
        self.tls.reload_from_files()
    }

    /// Останавливает accept loop и активные соединения.
    ///
    /// # Errors
    ///
    /// [`Error::ThreadPanicked`], если accept-поток запаниковал.
    pub fn shutdown(&mut self) -> Result<(), Error> {
        crate::server::stop(
            &self.shutdown,
            &mut self.acceptor,
            &self.connections,
            self.shutdown_timeout,
        )
    }
}

impl Drop for DotServer {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn handle_connection(stream: TcpStream, peer: SocketAddr, shared: &Shared) -> Result<(), Error> {
    let mut tls =
        match TlsStream::accept(&shared.config.tls, stream, shared.config.handshake_timeout) {
            Ok(tls) => {
                shared.stats.handshake_ok();
                tls
            }
            Err(error) => {
                shared.stats.handshake_failed();
                return Err(error);
            }
        };
    tls.set_idle_timeout(shared.config.idle_timeout)?;
    let mut messages = 0_usize;
    loop {
        if shared.shutdown.load(Ordering::Acquire)
            || messages >= shared.config.max_messages_per_connection
        {
            break;
        }
        let Some(length) = read_prefix(&mut tls)? else {
            break;
        };
        if length == 0 {
            return Err(Error::Http("zero-length DNS/TCP frame".to_owned()));
        }
        let length = usize::from(length);
        if length > shared.config.max_message_size {
            return Err(Error::MessageTooLarge {
                limit: shared.config.max_message_size,
            });
        }
        let mut request = vec![0_u8; length];
        tls.read_exact(&mut request)?;
        shared.stats.read_bytes(length);
        shared.stats.query();

        if let Some(limiter) = &shared.limiter
            && !limiter.allow(peer.ip())
        {
            shared.stats.rate_limited();
            return Err(Error::RateLimited);
        }

        let outcome = catch_unwind(AssertUnwindSafe(|| (shared.handler)(&request, peer)))
            .map_err(|_| Error::HandlerPanic)?;
        let Some(response) = outcome else {
            return Err(Error::Closed);
        };
        if response.is_empty() {
            return Err(Error::Http("empty DNS/TCP response".to_owned()));
        }
        if response.len() > shared.config.max_message_size || response.len() > usize::from(u16::MAX)
        {
            return Err(Error::MessageTooLarge {
                limit: shared.config.max_message_size,
            });
        }
        let response_length =
            u16::try_from(response.len()).map_err(|_| Error::MessageTooLarge {
                limit: usize::from(u16::MAX),
            })?;
        tls.write_all(&response_length.to_be_bytes())?;
        tls.write_all(&response)?;
        shared.stats.written_bytes(response.len() + 2);
        shared.stats.response();
        messages += 1;
    }
    tls.close();
    Ok(())
}

fn read_prefix(tls: &mut TlsStream) -> Result<Option<u16>, Error> {
    let mut prefix = [0_u8; 2];
    let mut filled = 0;
    while filled < prefix.len() {
        let rest = prefix
            .get_mut(filled..)
            .ok_or_else(|| Error::Http("prefix offset out of bounds".to_owned()))?;
        match tls.read(rest)? {
            0 if filled == 0 => return Ok(None),
            0 => return Err(Error::Closed),
            read => filled += read,
        }
    }
    Ok(Some(u16::from_be_bytes(prefix)))
}
