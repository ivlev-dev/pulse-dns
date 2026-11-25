//! DNS over HTTPS/1.1 (RFC 8484) поверх TLS.
//!
//! Поддерживаются `GET /dns-query?dns=<base64url>`, `POST /dns-query` с
//! `Content-Type: application/dns-message` и `GET /healthz`. ALPN сервера —
//! `http/1.1`, preface HTTP/2 получает `505 HTTP Version Not Supported`.
//! Для HTTP/2 используйте `Doh2Server` (feature `http2`).
//!
//! Keep-alive-соединения обслуживаются задачами общего tokio event-loop
//! ([`crate::net::TcpServer`]). Медленный заголовок/тело ограничены
//! `request_timeout`, простой между запросами — `idle_timeout`; один
//! slowloris-клиент не блокирует остальные соединения.

use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;
use tokio::time::{Instant, timeout, timeout_at};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

use crate::acl::Acl;
use crate::doh_core::DohCore;
use crate::dot::DnsHandler;
use crate::error::Error;
use crate::http::{HttpResponse, Method, ParseError, find_head_end, parse_head};
use crate::net::{BufferPool, ConnectionHandler, ServerHooks, TcpServer, shrink};
use crate::ratelimit::RateLimitConfig;
use crate::stats::{Stats, StatsSnapshot};
use crate::tls::TlsConfig;

const DEFAULT_MAX_CONNECTIONS: usize = 1024;
const DEFAULT_MAX_BODY: usize = 65_535;
const DEFAULT_MAX_HEADER: usize = 16 * 1024;
const MAX_HEADER_SOFT_LIMIT: usize = 1024 * 1024;
const DEFAULT_MAX_REQUESTS: usize = 100;
const READ_CHUNK: usize = 4096;
const BODY_BUFFER_CHUNK: usize = 4096;
const BODY_BUFFER_POOL: usize = 512;
const PENDING_KEEP: usize = 8 * 1024;

/// Конфигурация DoH-сервера.
#[derive(Clone, Debug)]
pub struct DohConfig {
    /// Адрес прослушивания.
    pub listen: SocketAddr,
    /// TLS-конфигурация с ALPN `http/1.1`.
    pub tls: TlsConfig,
    /// Максимум одновременных TCP-соединений.
    pub max_connections: usize,
    /// Таймаут TLS-рукопожатия.
    pub handshake_timeout: Duration,
    /// Таймаут простоя между HTTP-запросами.
    pub idle_timeout: Duration,
    /// Таймаут чтения заголовка/тела одного запроса и записи ответа.
    pub request_timeout: Duration,
    /// Таймаут ожидания соединений при shutdown.
    pub shutdown_timeout: Duration,
    /// Максимальный размер HTTP-тела и DNS-сообщения.
    pub max_body_size: usize,
    /// Максимальный размер заголовка запроса.
    pub max_header_size: usize,
    /// Максимум HTTP-запросов на одно соединение (keep-alive).
    pub max_requests_per_connection: usize,
    /// Добавлять `Cache-Control: max-age=<min TTL>` к DNS-ответам.
    pub cache_control: bool,
    /// Опциональный ACL по IP.
    pub acl: Option<Acl>,
    /// Опциональный per-IP rate limit.
    pub rate_limit: Option<RateLimitConfig>,
}

impl DohConfig {
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
            max_body_size: DEFAULT_MAX_BODY,
            max_header_size: DEFAULT_MAX_HEADER,
            max_requests_per_connection: DEFAULT_MAX_REQUESTS,
            cache_control: false,
            acl: None,
            rate_limit: None,
        }
    }

    fn validate(&self) -> Result<(), Error> {
        if self.max_connections == 0 {
            return Err(Error::InvalidConfig("max_connections must be positive"));
        }
        if self.max_body_size == 0 || self.max_body_size > usize::from(u16::MAX) {
            return Err(Error::InvalidConfig("max_body_size must be in 1..=65535"));
        }
        if self.max_header_size < 64 || self.max_header_size > MAX_HEADER_SOFT_LIMIT {
            return Err(Error::InvalidConfig(
                "max_header_size must be in 64..=1048576",
            ));
        }
        if self.max_requests_per_connection == 0 {
            return Err(Error::InvalidConfig(
                "max_requests_per_connection must be positive",
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
    config: DohConfig,
    core: DohCore,
    stats: Arc<Stats>,
    buffers: Arc<BufferPool>,
}

/// Запущенный DoH-сервер.
pub struct DohServer {
    tcp: TcpServer,
    stats: Arc<Stats>,
    tls: TlsConfig,
}

impl std::fmt::Debug for DohServer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DohServer")
            .field("local_addr", &self.tcp.local_addr())
            .field("stats", &self.stats.snapshot())
            .finish_non_exhaustive()
    }
}

impl DohServer {
    /// Привязывает listener и запускает accept loop.
    ///
    /// # Errors
    ///
    /// Ошибка bind/настройки listener, некорректная конфигурация или
    /// невозможность запустить event-loop.
    pub fn bind<H>(config: DohConfig, handler: H) -> Result<Self, Error>
    where
        H: Fn(&[u8], SocketAddr) -> Option<Vec<u8>> + Send + Sync + 'static,
    {
        Self::bind_with_stats(config, handler, Arc::new(Stats::new()))
    }

    /// То же, но с общими счётчиками.
    ///
    /// # Errors
    ///
    /// См. [`DohServer::bind`].
    pub fn bind_with_stats<H>(
        config: DohConfig,
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
    /// См. [`DohServer::bind`].
    pub fn bind_shared(
        config: DohConfig,
        handler: DnsHandler,
        stats: Arc<Stats>,
    ) -> Result<Self, Error> {
        config.validate()?;
        let core = DohCore::new(
            config.max_body_size,
            config.cache_control,
            handler,
            config.rate_limit,
            Arc::clone(&stats),
        )?;
        let listener = TcpListener::bind(config.listen)?;
        let shared = Arc::new(Shared {
            config: config.clone(),
            core,
            stats: Arc::clone(&stats),
            buffers: Arc::new(BufferPool::new(BODY_BUFFER_CHUNK, BODY_BUFFER_POOL)),
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
            "pulse-doh",
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

impl Drop for DohServer {
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

#[derive(Debug)]
enum HeadError {
    Timeout,
    Closed,
    TooLarge,
    Failed(Error),
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

    let mut pending = Vec::new();
    let mut requests = 0_usize;
    while requests < shared.config.max_requests_per_connection {
        if *shutdown.borrow() {
            break;
        }
        let head = tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            head = read_head(&mut tls, &mut pending, shared) => head,
        };
        let head = match head {
            Ok(Some(head)) => head,
            Ok(None) | Err(HeadError::Closed) => break,
            Err(HeadError::Timeout) => {
                shared.stats.timeout();
                break;
            }
            Err(HeadError::TooLarge) => {
                shared.stats.http_error();
                let response = HttpResponse::error(400, "request header too large", true);
                send_response(
                    &mut tls,
                    &response,
                    &shared.stats,
                    shared.config.request_timeout,
                )
                .await?;
                break;
            }
            Err(HeadError::Failed(error)) => return Err(error),
        };
        requests += 1;
        shared.stats.http_request();
        let head = match parse_head(&head) {
            Ok(head) => head,
            Err(ParseError::UnsupportedVersion) => {
                shared.stats.http_error();
                let response = HttpResponse::error(505, "HTTP/2 is not supported", true);
                send_response(
                    &mut tls,
                    &response,
                    &shared.stats,
                    shared.config.request_timeout,
                )
                .await?;
                break;
            }
            Err(ParseError::Malformed) => {
                shared.stats.http_error();
                let response = HttpResponse::error(400, "malformed HTTP request", true);
                send_response(
                    &mut tls,
                    &response,
                    &shared.stats,
                    shared.config.request_timeout,
                )
                .await?;
                break;
            }
        };
        let keep_alive = head.headers.keep_alive(head.version)
            && requests < shared.config.max_requests_per_connection;
        if !shared.core.allow_rate(peer) {
            let response = HttpResponse::error(429, "rate limit exceeded", true);
            send_response(
                &mut tls,
                &response,
                &shared.stats,
                shared.config.request_timeout,
            )
            .await?;
            break;
        }
        let (method, target, _version, headers) = head.into_parts();
        if headers.has_transfer_encoding() {
            shared.stats.http_error();
            let response = HttpResponse::error(400, "Transfer-Encoding is not supported", true);
            send_response(
                &mut tls,
                &response,
                &shared.stats,
                shared.config.request_timeout,
            )
            .await?;
            break;
        }
        let content_length = match headers.content_length() {
            Ok(length) => length,
            Err(()) => {
                shared.stats.http_error();
                let response = HttpResponse::error(400, "invalid Content-Length", true);
                send_response(
                    &mut tls,
                    &response,
                    &shared.stats,
                    shared.config.request_timeout,
                )
                .await?;
                break;
            }
        };
        let body = match method {
            Method::Post => {
                let Some(length) = content_length else {
                    shared.stats.http_error();
                    let response = HttpResponse::error(400, "Content-Length is required", true);
                    send_response(
                        &mut tls,
                        &response,
                        &shared.stats,
                        shared.config.request_timeout,
                    )
                    .await?;
                    break;
                };
                if length > shared.config.max_body_size {
                    shared.stats.http_error();
                    let response = HttpResponse::error(413, "request body too large", true);
                    send_response(
                        &mut tls,
                        &response,
                        &shared.stats,
                        shared.config.request_timeout,
                    )
                    .await?;
                    break;
                }
                match read_body(&mut tls, &mut pending, length, shared).await {
                    Ok(body) => body,
                    Err(error) if error.is_timeout() => {
                        shared.stats.timeout();
                        break;
                    }
                    Err(error) if error.is_closed() => break,
                    Err(error) => return Err(error),
                }
            }
            _ => {
                if content_length.unwrap_or(0) > 0 {
                    shared.stats.http_error();
                    let response = HttpResponse::error(400, "request body is not allowed", true);
                    send_response(
                        &mut tls,
                        &response,
                        &shared.stats,
                        shared.config.request_timeout,
                    )
                    .await?;
                    break;
                }
                Vec::new()
            }
        };
        shared.stats.read_bytes(body.len());
        let mut response = shared
            .core
            .route(peer, method, &target, headers.content_type(), &body);
        drop(body);
        response.close |= !keep_alive;
        let status = response.status;
        let close = response.close;
        send_response(
            &mut tls,
            &response,
            &shared.stats,
            shared.config.request_timeout,
        )
        .await?;
        if status >= 400 {
            shared.stats.http_error();
        }
        if pending.capacity() > PENDING_KEEP {
            shrink(&mut pending, PENDING_KEEP);
        }
        if close {
            break;
        }
    }
    let _ = timeout(shared.config.request_timeout, tls.shutdown()).await;
    Ok(())
}

async fn read_head(
    tls: &mut TlsStream<tokio::net::TcpStream>,
    pending: &mut Vec<u8>,
    shared: &Shared,
) -> Result<Option<Vec<u8>>, HeadError> {
    let mut deadline: Option<Instant> = None;
    loop {
        if let Some(end) = find_head_end(pending) {
            let head = pending.get(..end).ok_or(HeadError::TooLarge)?.to_vec();
            pending.drain(..end);
            return Ok(Some(head));
        }
        if pending.len() >= shared.config.max_header_size {
            return Err(HeadError::TooLarge);
        }
        let capacity = shared.config.max_header_size - pending.len();
        let mut chunk = [0_u8; READ_CHUNK];
        let read_len = chunk.len().min(capacity);
        let buffer = chunk.get_mut(..read_len).ok_or(HeadError::TooLarge)?;
        let wait = deadline.map_or(shared.config.idle_timeout, |deadline| {
            deadline.saturating_duration_since(Instant::now())
        });
        let read = if deadline.is_some() {
            timeout_at(deadline.unwrap_or_else(Instant::now), tls.read(buffer)).await
        } else {
            timeout(wait, tls.read(buffer)).await
        };
        match read {
            Ok(Ok(0)) if pending.is_empty() => return Ok(None),
            Ok(Ok(0)) => return Err(HeadError::Closed),
            Ok(Ok(read)) => {
                deadline.get_or_insert_with(|| Instant::now() + shared.config.request_timeout);
                let data = chunk.get(..read).ok_or(HeadError::TooLarge)?;
                pending.extend_from_slice(data);
            }
            Ok(Err(error)) => return Err(HeadError::Failed(Error::Io(error))),
            Err(_) => return Err(HeadError::Timeout),
        }
    }
}

async fn read_body(
    tls: &mut TlsStream<tokio::net::TcpStream>,
    pending: &mut Vec<u8>,
    length: usize,
    shared: &Shared,
) -> Result<Vec<u8>, Error> {
    let mut body = shared.buffers.acquire();
    body.prepare(length);
    let take = length.min(pending.len());
    let initial = pending
        .get(..take)
        .ok_or_else(|| Error::Http("body offset out of bounds".to_owned()))?;
    body.get_mut(..take)
        .ok_or_else(|| Error::Http("body offset out of bounds".to_owned()))?
        .copy_from_slice(initial);
    pending.drain(..take);
    let end = body.len().min(length);
    let remaining = body
        .get_mut(take..end)
        .ok_or_else(|| Error::Http("body chunk out of bounds".to_owned()))?;
    match timeout(shared.config.request_timeout, tls.read_exact(remaining)).await {
        Ok(Ok(_)) => Ok(body.take_vec(length)),
        Ok(Err(error)) => Err(Error::Io(error)),
        Err(_) => Err(Error::Timeout),
    }
}

async fn send_response(
    tls: &mut TlsStream<tokio::net::TcpStream>,
    response: &HttpResponse,
    stats: &Stats,
    deadline: Duration,
) -> Result<(), Error> {
    let bytes = response.to_bytes();
    if response.status == 200 && response.content_type == "application/dns-message" {
        stats.response();
    }
    match timeout(deadline, tls.write_all(&bytes)).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => return Err(Error::Io(error)),
        Err(_) => return Err(Error::Timeout),
    }
    stats.written_bytes(bytes.len());
    Ok(())
}
