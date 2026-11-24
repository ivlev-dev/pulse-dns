//! DNS over HTTPS/2 (RFC 8484 + RFC 9113) поверх TLS на tokio + h2.
//!
//! Модуль включается feature `http2`. Синхронный API `DoT`/`DoH/1.1`
//! остаётся доступным без tokio: сервер поднимает собственный
//! multi-thread runtime в фоновом потоке, а вызывающий код работает с
//! [`Doh2Server`] как с обычным RAII-объектом.
//!
//! Поддерживаются `POST /dns-query` (`application/dns-message`) и
//! `GET /dns-query?dns=<base64url>`, мультиплексирование потоков, лимиты
//! тела/заголовков/одновременных stream'ов, `GET /healthz`, keep-alive на
//! уровне HTTP/2, `Cache-Control` и graceful shutdown (GOAWAY).
//!
//! # Пример
//!
//! ```no_run
//! use pulse_tls::{Doh2Config, Doh2Server, TlsConfig};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let cert = std::fs::read("cert.pem")?;
//! let key = std::fs::read("key.pem")?;
//! let tls = TlsConfig::for_doh2(&cert, &key)?;
//! let mut server = Doh2Server::bind(
//!     Doh2Config::new("0.0.0.0:443".parse()?, tls),
//!     |query, _peer| Some(query.to_vec()),
//! )?;
//! println!("listening on {}", server.local_addr());
//! server.shutdown()?;
//! # Ok(())
//! # }
//! ```

use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use tokio::net::TcpListener as TokioListener;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

use crate::acl::Acl;
use crate::doh_core::DohCore;
use crate::dot::DnsHandler;
use crate::error::Error;
use crate::http::Method as DohMethod;
use crate::ratelimit::RateLimitConfig;
use crate::stats::{Stats, StatsSnapshot};
use crate::tls::TlsConfig;

const DEFAULT_MAX_CONNECTIONS: usize = 1024;
const DEFAULT_MAX_BODY: usize = 65_535;
const DEFAULT_MAX_HEADER: usize = 16 * 1024;
const DEFAULT_MAX_STREAMS: u32 = 100;
const DEFAULT_WORKER_THREADS: usize = 2;
const MAX_HEADER_SOFT_LIMIT: usize = 1024 * 1024;
const SHUTDOWN_POLL: Duration = Duration::from_millis(5);

/// Конфигурация DoH/HTTP/2-сервера.
#[derive(Clone, Debug)]
pub struct Doh2Config {
    /// Адрес прослушивания.
    pub listen: SocketAddr,
    /// TLS-конфигурация с ALPN `h2`.
    pub tls: TlsConfig,
    /// Максимум одновременных TCP-соединений.
    pub max_connections: usize,
    /// Максимум одновременных HTTP/2 stream'ов на соединение.
    pub max_concurrent_streams: u32,
    /// Таймаут TLS-рукопожатия.
    pub handshake_timeout: Duration,
    /// Таймаут простоя HTTP/2-соединения.
    pub idle_timeout: Duration,
    /// Таймаут чтения тела одного запроса.
    pub request_timeout: Duration,
    /// Таймаут ожидания соединений при shutdown.
    pub shutdown_timeout: Duration,
    /// Максимальный размер HTTP-тела и DNS-сообщения.
    pub max_body_size: usize,
    /// Максимальный размер списка заголовков запроса.
    pub max_header_size: usize,
    /// Число worker-потоков tokio runtime.
    pub worker_threads: usize,
    /// Добавлять `Cache-Control: max-age=<min TTL>` к DNS-ответам.
    pub cache_control: bool,
    /// Опциональный ACL по IP.
    pub acl: Option<Acl>,
    /// Опциональный per-IP rate limit.
    pub rate_limit: Option<RateLimitConfig>,
}

impl Doh2Config {
    /// Конфигурация с безопасными значениями по умолчанию.
    #[must_use]
    pub fn new(listen: SocketAddr, tls: TlsConfig) -> Self {
        Self {
            listen,
            tls,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            max_concurrent_streams: DEFAULT_MAX_STREAMS,
            handshake_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(30),
            request_timeout: Duration::from_secs(10),
            shutdown_timeout: Duration::from_secs(5),
            max_body_size: DEFAULT_MAX_BODY,
            max_header_size: DEFAULT_MAX_HEADER,
            worker_threads: DEFAULT_WORKER_THREADS,
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
        if self.max_concurrent_streams == 0 {
            return Err(Error::InvalidConfig(
                "max_concurrent_streams must be positive",
            ));
        }
        if self.worker_threads == 0 {
            return Err(Error::InvalidConfig("worker_threads must be positive"));
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
    config: Doh2Config,
    core: DohCore,
    stats: Arc<Stats>,
}

/// Запущенный DoH/HTTP/2-сервер.
pub struct Doh2Server {
    local_addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    shutdown_tx: watch::Sender<bool>,
    stats: Arc<Stats>,
    handle: Option<JoinHandle<()>>,
    shutdown_timeout: Duration,
    tls: TlsConfig,
}

impl std::fmt::Debug for Doh2Server {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Doh2Server")
            .field("local_addr", &self.local_addr)
            .field("stats", &self.stats.snapshot())
            .finish_non_exhaustive()
    }
}

impl Doh2Server {
    /// Привязывает listener и запускает tokio runtime в фоновом потоке.
    ///
    /// # Errors
    ///
    /// Некорректная конфигурация, ошибка bind или создание runtime/потока.
    pub fn bind<H>(config: Doh2Config, handler: H) -> Result<Self, Error>
    where
        H: Fn(&[u8], SocketAddr) -> Option<Vec<u8>> + Send + Sync + 'static,
    {
        Self::bind_with_stats(config, handler, Arc::new(Stats::new()))
    }

    /// То же, но с общими счётчиками.
    ///
    /// # Errors
    ///
    /// См. [`Doh2Server::bind`].
    pub fn bind_with_stats<H>(
        config: Doh2Config,
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
    /// См. [`Doh2Server::bind`].
    pub fn bind_shared(
        config: Doh2Config,
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
        listener.set_nonblocking(true)?;
        let local_addr = listener.local_addr()?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(config.worker_threads)
            .enable_all()
            .thread_name("pulse-doh2-rt")
            .build()?;
        let shared = Arc::new(Shared {
            config: config.clone(),
            core,
            stats: Arc::clone(&stats),
        });
        let handle = thread::Builder::new()
            .name("pulse-doh2".to_owned())
            .spawn(move || {
                runtime.block_on(serve(listener, shared, shutdown_rx));
            })?;
        Ok(Self {
            local_addr,
            shutdown,
            shutdown_tx,
            stats,
            handle: Some(handle),
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

    /// Останавливает accept loop, отправляет GOAWAY и ждёт задачи.
    ///
    /// # Errors
    ///
    /// [`Error::Timeout`], если соединения не закрылись за
    /// `shutdown_timeout`.
    pub fn shutdown(&mut self) -> Result<(), Error> {
        self.shutdown.store(true, Ordering::Release);
        let _ = self.shutdown_tx.send(true);
        let Some(handle) = self.handle.take() else {
            return Ok(());
        };
        let deadline = Instant::now() + self.shutdown_timeout;
        while !handle.is_finished() {
            if Instant::now() >= deadline {
                return Err(Error::Timeout);
            }
            thread::sleep(SHUTDOWN_POLL);
        }
        handle.join().map_err(|_| Error::ThreadPanicked)
    }
}

impl Drop for Doh2Server {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

async fn serve(listener: TcpListener, shared: Arc<Shared>, mut shutdown: watch::Receiver<bool>) {
    let listener = match TokioListener::from_std(listener) {
        Ok(listener) => listener,
        Err(_) => {
            shared.stats.error();
            return;
        }
    };
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, peer)) => admit(&shared, stream, peer, &shutdown, &mut connections),
                    Err(_) => {
                        shared.stats.error();
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                }
            }
        }
        while connections.try_join_next().is_some() {}
    }
    drop(listener);
    while connections.join_next().await.is_some() {}
}

fn admit(
    shared: &Arc<Shared>,
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    shutdown: &watch::Receiver<bool>,
    connections: &mut JoinSet<()>,
) {
    if let Some(acl) = &shared.config.acl
        && !acl.allows(peer.ip())
    {
        shared.stats.connection_rejected();
        return;
    }
    if !shared.stats.try_open(shared.config.max_connections) {
        return;
    }
    let shared = Arc::clone(shared);
    let shutdown = shutdown.clone();
    connections.spawn(async move {
        let _active = ActiveGuard(Arc::clone(&shared.stats));
        if let Err(error) = handle_connection(stream, peer, Arc::clone(&shared), shutdown).await {
            if error.is_timeout() {
                shared.stats.timeout();
            } else if !error.is_closed() {
                shared.stats.error();
            }
        }
    });
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
    shared: Arc<Shared>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), Error> {
    stream.set_nodelay(true).map_err(Error::Io)?;
    let acceptor = TlsAcceptor::from(shared.config.tls.server_config());
    let tls = match timeout(shared.config.handshake_timeout, acceptor.accept(stream)).await {
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

    let mut builder = h2::server::Builder::new();
    builder
        .max_concurrent_streams(shared.config.max_concurrent_streams)
        .max_header_list_size(u32::try_from(shared.config.max_header_size).unwrap_or(u32::MAX))
        .initial_window_size(
            u32::try_from(shared.config.max_body_size)
                .unwrap_or(65_535)
                .max(65_535),
        );
    let mut connection = builder
        .handshake::<_, Bytes>(tls)
        .await
        .map_err(|error| Error::Http(error.to_string()))?;

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    connection.graceful_shutdown();
                    break;
                }
            }
            accepted = connection.accept() => {
                let Some(result) = accepted else { break };
                match result {
                    Ok((request, respond)) => {
                        let shared = Arc::clone(&shared);
                        tokio::spawn(handle_stream(shared, peer, request, respond));
                    }
                    Err(error) => {
                        shared.stats.error();
                        return Err(Error::Http(error.to_string()));
                    }
                }
            }
            () = tokio::time::sleep(shared.config.idle_timeout) => {
                shared.stats.timeout();
                connection.graceful_shutdown();
                break;
            }
        }
    }
    Ok(())
}

async fn handle_stream(
    shared: Arc<Shared>,
    peer: SocketAddr,
    request: Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
) {
    shared.stats.http_request();
    let method = match *request.method() {
        http::Method::GET => DohMethod::Get,
        http::Method::POST => DohMethod::Post,
        _ => DohMethod::Other,
    };
    let target = request
        .uri()
        .path_and_query()
        .map_or_else(|| request.uri().path().to_owned(), ToString::to_string);
    let content_type = request
        .headers()
        .get(http::header::CONTENT_TYPE)
        .map(|value| value.as_bytes().to_vec());

    let mut body = Vec::new();
    let mut body_error: Option<u16> = None;
    let mut recv = request.into_body();
    loop {
        match timeout(shared.config.request_timeout, recv.data()).await {
            Ok(Some(Ok(chunk))) => {
                if body_error.is_none()
                    && body.len().saturating_add(chunk.len()) > shared.config.max_body_size
                {
                    body_error = Some(413);
                    body.clear();
                }
                if body_error.is_none() {
                    body.extend_from_slice(&chunk);
                }
            }
            Ok(Some(Err(_))) => {
                shared.stats.error();
                return;
            }
            Ok(None) => break,
            Err(_) => {
                shared.stats.timeout();
                return;
            }
        }
    }
    shared.stats.read_bytes(body.len());

    let response = if let Some(status) = body_error {
        crate::http::HttpResponse::error(status, "request body too large", false)
    } else if method != DohMethod::Post && !body.is_empty() {
        crate::http::HttpResponse::error(400, "request body is not allowed", false)
    } else if !shared.core.allow_rate(peer) {
        crate::http::HttpResponse::error(429, "rate limit exceeded", false)
    } else {
        shared
            .core
            .route(peer, method, &target, content_type.as_deref(), &body)
    };
    if response.status >= 400 {
        shared.stats.http_error();
    }
    if send_response(&mut respond, response, &shared.stats).is_err() {
        shared.stats.error();
    }
}

fn send_response(
    respond: &mut h2::server::SendResponse<Bytes>,
    response: crate::http::HttpResponse,
    stats: &Stats,
) -> Result<(), Error> {
    let status =
        StatusCode::from_u16(response.status).map_err(|error| Error::Http(error.to_string()))?;
    let mut builder = Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, response.content_type)
        .header(http::header::CONTENT_LENGTH, response.body.len())
        .header(http::header::SERVER, "pulse-tls");
    if let Some(max_age) = response.cache_max_age {
        builder = builder.header(http::header::CACHE_CONTROL, format!("max-age={max_age}"));
    }
    if let Some(allow) = response.allow {
        builder = builder.header(http::header::ALLOW, allow);
    }
    let response_head = builder
        .body(())
        .map_err(|error| Error::Http(error.to_string()))?;
    let end_stream = response.body.is_empty();
    let body_len = response.body.len();
    let mut stream = respond
        .send_response(response_head, end_stream)
        .map_err(|error| Error::Http(error.to_string()))?;
    if !end_stream {
        stream
            .send_data(Bytes::from(response.body), true)
            .map_err(|error| Error::Http(error.to_string()))?;
    }
    stats.written_bytes(body_len);
    if status == StatusCode::OK && response.content_type == "application/dns-message" {
        stats.response();
    }
    Ok(())
}
