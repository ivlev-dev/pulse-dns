//! DNS over TLS (RFC 7858): TLS 1.2/1.3, length-prefixed DNS, keep-alive
//! нескольких сообщений на соединение, idle/request-таймауты и graceful
//! shutdown.
//!
//! Соединения обслуживаются задачами общего tokio event-loop
//! ([`crate::net::TcpServer`]), а не отдельными OS-потоками: тысяча idle
//! клиентов не создаёт тысячу потоков, а медленный клиент не блокирует
//! остальные соединения. Публичный API остаётся синхронным: [`DotServer`] —
//! RAII-объект с `local_addr`/`stats`/`shutdown`.

use std::net::{SocketAddr, TcpListener};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

use crate::acl::Acl;
use crate::error::Error;
use crate::net::{BufferPool, ConnectionHandler, ServerHooks, TcpServer};
use crate::ratelimit::{RateLimitConfig, RateLimiter};
use crate::stats::{Stats, StatsSnapshot};
use crate::tls::TlsConfig;

/// Обработчик DNS-запроса: возвращает готовый DNS-ответ или `None`, чтобы
/// закрыть соединение без ответа.
pub type DnsHandler = Arc<dyn Fn(&[u8], SocketAddr) -> Option<Vec<u8>> + Send + Sync + 'static>;

const DEFAULT_MAX_CONNECTIONS: usize = 1024;
const DEFAULT_MAX_MESSAGE_SIZE: usize = 65_535;
const DEFAULT_MAX_MESSAGES: usize = 1000;
const REQUEST_BUFFER_CHUNK: usize = 4096;
const REQUEST_BUFFER_POOL: usize = 1024;

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
    /// Таймаут чтения одного сообщения и записи ответа.
    ///
    /// Ограничивает slowloris: клиент, присылающий длину кадра и байты
    /// слишком медленно, закрывается, не занимая воркер бесконечно.
    pub request_timeout: Duration,
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
            request_timeout: Duration::from_secs(10),
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
            || self.request_timeout.is_zero()
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
    buffers: Arc<BufferPool>,
}

/// Запущенный DoT-сервер.
pub struct DotServer {
    tcp: TcpServer,
    stats: Arc<Stats>,
    tls: TlsConfig,
}

impl std::fmt::Debug for DotServer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DotServer")
            .field("local_addr", &self.tcp.local_addr())
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
    /// невозможность запустить event-loop.
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
        let shared = Arc::new(Shared {
            config: config.clone(),
            handler,
            limiter,
            stats: Arc::clone(&stats),
            buffers: Arc::new(BufferPool::new(REQUEST_BUFFER_CHUNK, REQUEST_BUFFER_POOL)),
        });
        let connection_handler = make_connection_handler(Arc::clone(&shared));
        let hooks = ServerHooks::new(
            Some({
                let stats = Arc::clone(&stats);
                Arc::new(move || stats.connection_rejected())
            }),
            Some({
                let stats = Arc::clone(&stats);
                Arc::new(move || stats.error())
            }),
        );
        let tcp = TcpServer::start(
            "pulse-dot",
            listener,
            config.max_connections,
            config.shutdown_timeout,
            hooks,
            connection_handler,
        )?;
        Ok(Self {
            tcp,
            stats,
            tls: config.tls,
        })
    }

    /// Фактический адрес (полезен при `port = 0`).
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.tcp.local_addr()
    }

    /// Текущая статистика.
    #[must_use]
    pub fn stats(&self) -> StatsSnapshot {
        self.stats.snapshot()
    }

    /// Проверяет, остановлен ли сервер.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.tcp.is_shutdown()
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
    /// [`Error::Io`] с [`std::io::ErrorKind::TimedOut`], если соединения не
    /// закрылись за `shutdown_timeout`.
    pub fn shutdown(&mut self) -> Result<(), Error> {
        self.tcp.shutdown().map_err(Error::Io)
    }
}

impl Drop for DotServer {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn make_connection_handler(shared: Arc<Shared>) -> ConnectionHandler {
    Arc::new(move |stream, peer, shutdown| {
        let shared = Arc::clone(&shared);
        Box::pin(async move {
            if let Some(acl) = &shared.config.acl
                && !acl.allows(peer.ip())
            {
                shared.stats.connection_rejected();
                return;
            }
            shared.stats.connection_opened();
            let _guard = ActiveGuard(Arc::clone(&shared.stats));
            if let Err(error) = handle_connection(stream, peer, &shared, shutdown).await {
                if error.is_timeout() {
                    shared.stats.timeout();
                } else if !error.is_closed() {
                    shared.stats.error();
                }
            }
        })
    })
}

struct ActiveGuard(Arc<Stats>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.connection_closed();
    }
}

async fn handle_connection(
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    shared: &Shared,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), Error> {
    if let Err(error) = stream.set_nodelay(true) {
        shared.stats.handshake_failed();
        return Err(Error::Io(error));
    }
    let acceptor = TlsAcceptor::from(shared.config.tls.server_config());
    let handshake = tokio::select! {
        biased;
        _ = shutdown.changed() => return Ok(()),
        result = timeout(shared.config.handshake_timeout, acceptor.accept(stream)) => result,
    };
    let mut tls = match handshake {
        Ok(Ok(tls)) => {
            shared.stats.handshake_ok();
            tls
        }
        Ok(Err(error)) => {
            shared.stats.handshake_failed();
            return Err(Error::Io(error));
        }
        Err(_) => {
            shared.stats.handshake_failed();
            return Err(Error::HandshakeTimeout);
        }
    };
    shared.config.tls.verify_alpn(tls.get_ref().1)?;

    let mut messages = 0_usize;
    while messages < shared.config.max_messages_per_connection {
        if *shutdown.borrow() {
            break;
        }
        let message = tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            message = read_message(&mut tls, shared) => message?,
        };
        let Some(request) = message else {
            break;
        };
        shared.stats.read_bytes(request.len());
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
        shared.stats.response();
        let write = async {
            tls.write_all(&response_length.to_be_bytes()).await?;
            tls.write_all(&response).await?;
            tls.flush().await?;
            Ok::<(), std::io::Error>(())
        };
        match timeout(shared.config.request_timeout, write).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return Err(Error::Io(error)),
            Err(_) => return Err(Error::Timeout),
        }
        shared.stats.written_bytes(response.len() + 2);
        messages += 1;
    }
    let _ = timeout(shared.config.request_timeout, tls.shutdown()).await;
    Ok(())
}

async fn read_message(
    tls: &mut TlsStream<tokio::net::TcpStream>,
    shared: &Shared,
) -> Result<Option<Vec<u8>>, Error> {
    let Some(length) = read_prefix(tls, shared).await? else {
        return Ok(None);
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
    let mut buffer = shared.buffers.acquire();
    let request = buffer.prepare(length);
    match timeout(shared.config.request_timeout, tls.read_exact(request)).await {
        Ok(Ok(_)) => Ok(Some(buffer.take_vec(length))),
        Ok(Err(error)) => Err(Error::Io(error)),
        Err(_) => Err(Error::Timeout),
    }
}

async fn read_prefix(
    tls: &mut TlsStream<tokio::net::TcpStream>,
    shared: &Shared,
) -> Result<Option<u16>, Error> {
    let mut prefix = [0_u8; 2];
    let (first, second) = prefix.split_at_mut(1);
    if !read_exact_deadline(tls, first, shared.config.idle_timeout).await? {
        return Ok(None);
    }
    if !read_exact_deadline(tls, second, shared.config.request_timeout).await? {
        return Err(Error::Closed);
    }
    Ok(Some(u16::from_be_bytes(prefix)))
}

async fn read_exact_deadline<S>(
    stream: &mut S,
    buffer: &mut [u8],
    deadline: Duration,
) -> Result<bool, Error>
where
    S: AsyncRead + Unpin,
{
    match timeout(deadline, stream.read_exact(buffer)).await {
        Ok(Ok(_)) => Ok(true),
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Ok(Err(error)) => Err(Error::Io(error)),
        Err(_) => Err(Error::Timeout),
    }
}
