//! DNS over HTTPS (RFC 8484), только HTTP/1.1 поверх TLS.
//!
//! Поддерживаются `GET /dns-query?dns=<base64url>`, `POST /dns-query` с
//! `Content-Type: application/dns-message` и `GET /healthz`. HTTP/2 не
//! входит в MVP: ALPN сервера — только `http/1.1`, preface HTTP/2 получает
//! `505 HTTP Version Not Supported`.

use std::net::{Shutdown as SocketShutdown, SocketAddr, TcpListener, TcpStream};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};

use crate::acl::Acl;
use crate::dot::DnsHandler;
use crate::error::Error;
use crate::http::{
    HttpResponse, Method, ParseError, find_head_end, parse_head, query_param, response_max_age,
};
use crate::ratelimit::{RateLimitConfig, RateLimiter};
use crate::server::{ConnectionGuard, ConnectionSet};
use crate::stats::{Stats, StatsSnapshot};
use crate::tls::TlsConfig;
use crate::transport::TlsStream;

const DEFAULT_MAX_CONNECTIONS: usize = 1024;
const DEFAULT_MAX_BODY: usize = 65_535;
const DEFAULT_MAX_HEADER: usize = 16 * 1024;
const MAX_HEADER_SOFT_LIMIT: usize = 1024 * 1024;
const DEFAULT_MAX_REQUESTS: usize = 100;
const DNS_PATH: &str = "/dns-query";
const HEALTH_PATH: &str = "/healthz";

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
            || self.shutdown_timeout.is_zero()
        {
            return Err(Error::InvalidConfig("timeouts must be positive"));
        }
        Ok(())
    }
}

struct Shared {
    config: DohConfig,
    handler: DnsHandler,
    limiter: Option<RateLimiter>,
    stats: Arc<Stats>,
    shutdown: Arc<AtomicBool>,
}

/// Запущенный DoH-сервер.
pub struct DohServer {
    local_addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    stats: Arc<Stats>,
    connections: Arc<ConnectionSet>,
    acceptor: Option<JoinHandle<()>>,
    shutdown_timeout: Duration,
    tls: TlsConfig,
}

impl std::fmt::Debug for DohServer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DohServer")
            .field("local_addr", &self.local_addr)
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
    /// невозможность создать поток.
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
                    let thread_name = format!("pulse-doh-{}", guard.id());
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
            "pulse-doh-accept".to_owned(),
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

impl Drop for DohServer {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

#[derive(Debug)]
enum HeadError {
    Timeout,
    Closed,
    TooLarge,
    Failed(Error),
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
    let mut pending = Vec::new();
    let mut requests = 0_usize;
    loop {
        if shared.shutdown.load(Ordering::Acquire)
            || requests >= shared.config.max_requests_per_connection
        {
            break;
        }
        let head = match read_head(&mut tls, &mut pending, shared.config.max_header_size) {
            Ok(Some(head)) => head,
            Ok(None) | Err(HeadError::Closed) => break,
            Err(HeadError::Timeout) => {
                shared.stats.timeout();
                break;
            }
            Err(HeadError::TooLarge) => {
                shared.stats.http_error();
                let response = HttpResponse::error(400, "request header too large", true);
                send_response(&mut tls, &response, &shared.stats)?;
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
                send_response(&mut tls, &response, &shared.stats)?;
                break;
            }
            Err(ParseError::Malformed) => {
                shared.stats.http_error();
                let response = HttpResponse::error(400, "malformed HTTP request", true);
                send_response(&mut tls, &response, &shared.stats)?;
                break;
            }
        };
        let keep_alive = head.headers.keep_alive(head.version)
            && requests < shared.config.max_requests_per_connection;
        if let Some(limiter) = &shared.limiter
            && !limiter.allow(peer.ip())
        {
            shared.stats.rate_limited();
            shared.stats.http_error();
            let response = HttpResponse::error(429, "rate limit exceeded", true);
            send_response(&mut tls, &response, &shared.stats)?;
            break;
        }
        let (method, target, _version, headers) = head.into_parts();
        if headers.has_transfer_encoding() {
            shared.stats.http_error();
            let response = HttpResponse::error(400, "Transfer-Encoding is not supported", true);
            send_response(&mut tls, &response, &shared.stats)?;
            break;
        }
        let content_length = match headers.content_length() {
            Ok(length) => length,
            Err(()) => {
                shared.stats.http_error();
                let response = HttpResponse::error(400, "invalid Content-Length", true);
                send_response(&mut tls, &response, &shared.stats)?;
                break;
            }
        };
        let body = match method {
            Method::Post => {
                let Some(length) = content_length else {
                    shared.stats.http_error();
                    let response = HttpResponse::error(400, "Content-Length is required", true);
                    send_response(&mut tls, &response, &shared.stats)?;
                    break;
                };
                if length > shared.config.max_body_size {
                    shared.stats.http_error();
                    let response = HttpResponse::error(413, "request body too large", true);
                    send_response(&mut tls, &response, &shared.stats)?;
                    break;
                }
                match read_body(&mut tls, &mut pending, length) {
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
                    send_response(&mut tls, &response, &shared.stats)?;
                    break;
                }
                Vec::new()
            }
        };
        shared.stats.read_bytes(body.len());
        let mut response = route(shared, peer, method, &target, &headers, &body);
        response.close |= !keep_alive;
        let status = response.status;
        let close = response.close;
        send_response(&mut tls, &response, &shared.stats)?;
        if status >= 400 {
            shared.stats.http_error();
        }
        if close {
            break;
        }
    }
    tls.close();
    Ok(())
}

fn read_head(
    tls: &mut TlsStream,
    pending: &mut Vec<u8>,
    max_size: usize,
) -> Result<Option<Vec<u8>>, HeadError> {
    loop {
        if let Some(end) = find_head_end(pending) {
            let head = pending.get(..end).ok_or(HeadError::TooLarge)?.to_vec();
            pending.drain(..end);
            return Ok(Some(head));
        }
        if pending.len() >= max_size {
            return Err(HeadError::TooLarge);
        }
        let capacity = max_size - pending.len();
        let mut chunk = [0_u8; 4096];
        let read_len = chunk.len().min(capacity);
        let buffer = chunk.get_mut(..read_len).ok_or(HeadError::TooLarge)?;
        match tls.read(buffer) {
            Ok(0) if pending.is_empty() => return Ok(None),
            Ok(0) => return Err(HeadError::Closed),
            Ok(read) => {
                let data = chunk.get(..read).ok_or(HeadError::TooLarge)?;
                pending.extend_from_slice(data);
            }
            Err(error) if error.is_timeout() => return Err(HeadError::Timeout),
            Err(error) if error.is_closed() => return Err(HeadError::Closed),
            Err(error) => return Err(HeadError::Failed(error)),
        }
    }
}

fn read_body(tls: &mut TlsStream, pending: &mut Vec<u8>, length: usize) -> Result<Vec<u8>, Error> {
    let mut body = Vec::with_capacity(length);
    let take = length.min(pending.len());
    let initial = pending
        .get(..take)
        .ok_or_else(|| Error::Http("body offset out of bounds".to_owned()))?;
    body.extend_from_slice(initial);
    pending.drain(..take);
    while body.len() < length {
        let mut chunk = [0_u8; 8192];
        let want = (length - body.len()).min(chunk.len());
        let buffer = chunk
            .get_mut(..want)
            .ok_or_else(|| Error::Http("body chunk out of bounds".to_owned()))?;
        let read = tls.read(buffer)?;
        if read == 0 {
            return Err(Error::Closed);
        }
        let data = chunk
            .get(..read)
            .ok_or_else(|| Error::Http("body read out of bounds".to_owned()))?;
        body.extend_from_slice(data);
    }
    Ok(body)
}

fn route(
    shared: &Shared,
    peer: SocketAddr,
    method: Method,
    target: &str,
    headers: &crate::http::Headers,
    body: &[u8],
) -> HttpResponse {
    let path = target.split('?').next().unwrap_or(target);
    if path == HEALTH_PATH {
        return if method == Method::Get {
            HttpResponse::text(200, "ok\n", false)
        } else {
            let mut response = HttpResponse::method_not_allowed(false);
            response.allow = Some("GET");
            response
        };
    }
    if path != DNS_PATH {
        return HttpResponse::error(404, "not found", false);
    }
    match method {
        Method::Get => {
            let Some(encoded) = query_param(target, "dns") else {
                return HttpResponse::error(400, "missing dns query parameter", false);
            };
            let Some(query) = decode_dns(&encoded) else {
                return HttpResponse::error(400, "invalid base64url dns parameter", false);
            };
            if query.is_empty() {
                return HttpResponse::error(400, "empty dns message", false);
            }
            if query.len() > shared.config.max_body_size {
                return HttpResponse::error(413, "dns message too large", false);
            }
            invoke(shared, peer, &query)
        }
        Method::Post => {
            if !headers.content_type_is("application/dns-message") {
                return HttpResponse::error(
                    415,
                    "Content-Type must be application/dns-message",
                    false,
                );
            }
            if body.is_empty() {
                return HttpResponse::error(400, "empty dns message", false);
            }
            if body.len() > shared.config.max_body_size {
                return HttpResponse::error(413, "dns message too large", false);
            }
            invoke(shared, peer, body)
        }
        Method::Other => HttpResponse::method_not_allowed(false),
    }
}

fn invoke(shared: &Shared, peer: SocketAddr, query: &[u8]) -> HttpResponse {
    shared.stats.query();
    let outcome = catch_unwind(AssertUnwindSafe(|| (shared.handler)(query, peer)));
    let response = match outcome {
        Ok(Some(response)) => response,
        Ok(None) | Err(_) => {
            return HttpResponse::error(500, "DNS handler failed", false);
        }
    };
    if response.is_empty() {
        return HttpResponse::error(500, "DNS handler returned an empty response", false);
    }
    if response.len() > shared.config.max_body_size {
        return HttpResponse::error(500, "DNS response too large", false);
    }
    let cache = if shared.config.cache_control {
        response_max_age(&response)
    } else {
        None
    };
    HttpResponse::dns(response, cache, false)
}

fn decode_dns(encoded: &[u8]) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(encoded)
        .or_else(|_| URL_SAFE.decode(encoded))
        .ok()
}

fn send_response(tls: &mut TlsStream, response: &HttpResponse, stats: &Stats) -> Result<(), Error> {
    let bytes = response.to_bytes();
    tls.write_all(&bytes)?;
    stats.written_bytes(bytes.len());
    if response.status == 200 && response.content_type == "application/dns-message" {
        stats.response();
    }
    Ok(())
}
