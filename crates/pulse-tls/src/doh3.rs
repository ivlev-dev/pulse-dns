//! DNS over HTTPS/3 (RFC 9114 + RFC 8484) поверх QUIC на `quinn` + `h3`.
//!
//! Модуль включается feature `http3` (псевдоним `doh3`). Сервер поднимает
//! собственный tokio runtime в фоновом потоке и отдаёт синхронный RAII-API,
//! как DoH/2 и DoQ. Используется тот же модуль `doh_core`, поэтому
//! маршруты, коды ответов, `Cache-Control` и лимиты совпадают с DoH/1.1 и
//! DoH/2.
//!
//! Поддерживаются `POST /dns-query` (`application/dns-message`),
//! `GET /dns-query?dns=<base64url>` и `GET /healthz`. HTTP/3 multiplexing
//! даёт несколько одновременных запросов на одно QUIC-соединение; лимит
//! задаётся `max_concurrent_requests` (транспортный параметр QUIC).
//! 0-RTT не включается, ALPN — `h3`, TLS — только 1.3.
//!
//! # Пример
//!
//! ```no_run
//! use pulse_tls::{Doh3Config, Doh3Server, TlsConfig};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let cert = std::fs::read("cert.pem")?;
//! let key = std::fs::read("key.pem")?;
//! let tls = TlsConfig::for_doh3(&cert, &key)?;
//! let mut server = Doh3Server::bind(
//!     Doh3Config::new("0.0.0.0:443".parse()?, tls),
//!     |query, _peer| Some(query.to_vec()),
//! )?;
//! println!("listening on {}", server.local_addr());
//! server.shutdown()?;
//! # Ok(())
//! # }
//! ```

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc as std_mpsc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes};
use h3::error::Code;
use h3::server::RequestStream;
use http::{Response, StatusCode};
use quinn::crypto::rustls::HandshakeData;
use quinn::{
    Connection, Endpoint, EndpointConfig, IdleTimeout, ServerConfig, TransportConfig, VarInt,
};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::acl::Acl;
use crate::doh_core::DohCore;
use crate::dot::DnsHandler;
use crate::error::Error;
use crate::http::Method as DohMethod;
use crate::ratelimit::RateLimitConfig;
use crate::stats::{Stats, StatsSnapshot};
use crate::tls::TlsConfig;

const DEFAULT_MAX_CONNECTIONS: usize = 1024;
const DEFAULT_MAX_REQUESTS: u32 = 100;
const DEFAULT_MAX_BODY: usize = 65_535;
const DEFAULT_MAX_HEADER: usize = 16 * 1024;
const DEFAULT_WORKER_THREADS: usize = 2;
const MAX_HEADER_SOFT_LIMIT: usize = 1024 * 1024;
const SHUTDOWN_POLL: Duration = Duration::from_millis(5);
const SHUTDOWN_GOAWAY: Duration = Duration::from_secs(1);
/// HTTP/3 открывает три серверных unidirectional stream'а (control, QPACK
/// encoder/decoder); запас оставляем небольшим, клиентские uni-stream'ы не
/// нужны.
const SERVER_UNI_STREAMS: u32 = 8;

/// Конфигурация DoH/HTTP/3-сервера.
#[derive(Clone, Debug)]
pub struct Doh3Config {
    /// Адрес прослушивания (UDP).
    pub listen: SocketAddr,
    /// TLS-конфигурация с ALPN `h3` (TLS 1.3).
    pub tls: TlsConfig,
    /// Максимум одновременных QUIC-соединений.
    pub max_connections: usize,
    /// Максимум одновременных запросов (bidirectional stream'ов) на соединение.
    pub max_concurrent_requests: u32,
    /// Таймаут установления QUIC-соединения.
    pub handshake_timeout: Duration,
    /// Idle timeout соединения.
    pub idle_timeout: Duration,
    /// Таймаут чтения одного запроса и записи ответа.
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

impl Doh3Config {
    /// Конфигурация с безопасными значениями по умолчанию.
    #[must_use]
    pub fn new(listen: SocketAddr, tls: TlsConfig) -> Self {
        Self {
            listen,
            tls,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            max_concurrent_requests: DEFAULT_MAX_REQUESTS,
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
        if self.max_concurrent_requests == 0 {
            return Err(Error::InvalidConfig(
                "max_concurrent_requests must be positive",
            ));
        }
        if self.max_body_size == 0 || self.max_body_size > usize::from(u16::MAX) {
            return Err(Error::InvalidConfig("max_body_size must be in 1..=65535"));
        }
        if self.max_header_size < 64 || self.max_header_size > MAX_HEADER_SOFT_LIMIT {
            return Err(Error::InvalidConfig(
                "max_header_size must be in 64..=1048576",
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
    config: Doh3Config,
    core: DohCore,
    stats: Arc<Stats>,
}

enum Command {
    Reload {
        ack: std_mpsc::Sender<Result<(), Error>>,
    },
}

/// Запущенный DoH/HTTP/3-сервер.
pub struct Doh3Server {
    local_addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    shutdown_tx: watch::Sender<bool>,
    commands: mpsc::UnboundedSender<Command>,
    stats: Arc<Stats>,
    handle: Option<JoinHandle<()>>,
    shutdown_timeout: Duration,
    tls: TlsConfig,
}

impl std::fmt::Debug for Doh3Server {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Doh3Server")
            .field("local_addr", &self.local_addr)
            .field("stats", &self.stats.snapshot())
            .finish_non_exhaustive()
    }
}

impl Doh3Server {
    /// Привязывает UDP-сокет и запускает tokio runtime в фоновом потоке.
    ///
    /// # Errors
    ///
    /// Некорректная конфигурация, ошибка bind/создания endpoint или потока.
    pub fn bind<H>(config: Doh3Config, handler: H) -> Result<Self, Error>
    where
        H: Fn(&[u8], SocketAddr) -> Option<Vec<u8>> + Send + Sync + 'static,
    {
        Self::bind_with_stats(config, handler, Arc::new(Stats::new()))
    }

    /// То же, но с общими счётчиками.
    ///
    /// # Errors
    ///
    /// См. [`Doh3Server::bind`].
    pub fn bind_with_stats<H>(
        config: Doh3Config,
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
    /// См. [`Doh3Server::bind`].
    pub fn bind_shared(
        config: Doh3Config,
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
        let transport = build_transport(&config)?;
        let socket = UdpSocket::bind(config.listen)?;
        socket.set_nonblocking(true)?;
        let local_addr = socket.local_addr()?;
        let quic_config = config.tls.quic_server_config(Arc::clone(&transport))?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (commands, command_rx) = mpsc::unbounded_channel();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(config.worker_threads)
            .enable_all()
            .thread_name("pulse-doh3-rt")
            .build()?;
        let shared = Arc::new(Shared {
            config: config.clone(),
            core,
            stats: Arc::clone(&stats),
        });
        let handle = thread::Builder::new()
            .name("pulse-doh3".to_owned())
            .spawn(move || {
                runtime.block_on(serve(
                    socket,
                    quic_config,
                    transport,
                    shared,
                    shutdown_rx,
                    command_rx,
                ));
            })?;
        Ok(Self {
            local_addr,
            shutdown,
            shutdown_tx,
            commands,
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

    /// Перечитывает сертификат и применяет его к новым QUIC-соединениям.
    ///
    /// # Errors
    ///
    /// Ошибка чтения/парсинга PEM, [`Error::Shutdown`] или [`Error::Timeout`],
    /// если runtime уже остановлен/не ответил.
    pub fn reload(&self, cert_pem: &[u8], key_pem: &[u8]) -> Result<(), Error> {
        self.tls.reload(cert_pem, key_pem)?;
        self.apply_reload()
    }

    /// Перечитывает сертификат из файлов и применяет его к новым соединениям.
    ///
    /// # Errors
    ///
    /// См. [`Doh3Server::reload`].
    pub fn reload_from_files(&self) -> Result<(), Error> {
        self.tls.reload_from_files()?;
        self.apply_reload()
    }

    fn apply_reload(&self) -> Result<(), Error> {
        let (ack, result) = std_mpsc::channel();
        self.commands
            .send(Command::Reload { ack })
            .map_err(|_| Error::Shutdown)?;
        match result.recv_timeout(self.shutdown_timeout) {
            Ok(result) => result,
            Err(_) => Err(Error::Timeout),
        }
    }

    /// Закрывает endpoint и ждёт завершения задач.
    ///
    /// Каждому активному HTTP/3-соединению отправляется GOAWAY; после
    /// `shutdown_timeout` endpoint закрывается принудительно.
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

impl Drop for Doh3Server {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn build_transport(config: &Doh3Config) -> Result<Arc<TransportConfig>, Error> {
    let mut transport = TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(VarInt::from_u32(config.max_concurrent_requests))
        .max_concurrent_uni_streams(VarInt::from_u32(SERVER_UNI_STREAMS));
    let idle = IdleTimeout::try_from(config.idle_timeout)
        .map_err(|error| Error::Quic(format!("idle timeout: {error}")))?;
    transport.max_idle_timeout(Some(idle));
    Ok(Arc::new(transport))
}

async fn serve(
    socket: UdpSocket,
    quic_config: ServerConfig,
    transport: Arc<TransportConfig>,
    shared: Arc<Shared>,
    mut shutdown: watch::Receiver<bool>,
    mut commands: mpsc::UnboundedReceiver<Command>,
) {
    let endpoint = match Endpoint::new(
        EndpointConfig::default(),
        Some(quic_config),
        socket,
        Arc::new(quinn::TokioRuntime),
    ) {
        Ok(endpoint) => endpoint,
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
            command = commands.recv() => {
                let Some(command) = command else { break };
                match command {
                    Command::Reload { ack } => {
                        match shared.config.tls.quic_server_config(Arc::clone(&transport)) {
                            Ok(config) => {
                                endpoint.set_server_config(Some(config));
                                let _ = ack.send(Ok(()));
                            }
                            Err(error) => {
                                let _ = ack.send(Err(error));
                            }
                        }
                    }
                }
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                admit(&shared, incoming, &shutdown, &mut connections);
            }
        }
        while connections.try_join_next().is_some() {}
    }
    // Даём задачам отправить GOAWAY и закрыть соединения штатно.
    let drain = async { while connections.join_next().await.is_some() {} };
    let _ = timeout(shared.config.shutdown_timeout, drain).await;
    endpoint.close(VarInt::from_u32(0), b"shutdown");
}

fn admit(
    shared: &Arc<Shared>,
    incoming: quinn::Incoming,
    shutdown: &watch::Receiver<bool>,
    connections: &mut JoinSet<()>,
) {
    let peer = incoming.remote_address();
    if let Some(acl) = &shared.config.acl
        && !acl.allows(peer.ip())
    {
        shared.stats.connection_rejected();
        incoming.refuse();
        return;
    }
    if !shared.stats.try_open(shared.config.max_connections) {
        incoming.refuse();
        return;
    }
    let shared = Arc::clone(shared);
    let shutdown = shutdown.clone();
    connections.spawn(async move {
        let _active = ActiveGuard(Arc::clone(&shared.stats));
        match timeout(shared.config.handshake_timeout, incoming).await {
            Ok(Ok(connection)) => {
                shared.stats.handshake_ok();
                handle_connection(connection, peer, shared, shutdown).await;
            }
            Ok(Err(_)) | Err(_) => {
                shared.stats.handshake_failed();
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
    connection: Connection,
    peer: SocketAddr,
    shared: Arc<Shared>,
    mut shutdown: watch::Receiver<bool>,
) {
    if !negotiated_h3(&connection) {
        shared.stats.error();
        connection.close(VarInt::from_u32(0x100), b"ALPN");
        return;
    }
    let quinn_connection = connection.clone();
    let mut builder = h3::server::builder();
    builder
        .max_field_section_size(u64::try_from(shared.config.max_header_size).unwrap_or(u64::MAX))
        .send_grease(false);
    let mut h3_connection = match timeout(
        shared.config.handshake_timeout,
        builder.build(h3_quinn::Connection::new(connection)),
    )
    .await
    {
        Ok(Ok(connection)) => connection,
        Ok(Err(_)) | Err(_) => {
            shared.stats.error();
            quinn_connection.close(VarInt::from_u32(0x100), b"HTTP/3 handshake");
            return;
        }
    };

    let mut requests = JoinSet::new();
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    let _ = timeout(SHUTDOWN_GOAWAY, h3_connection.shutdown(0)).await;
                    break;
                }
            }
            accepted = h3_connection.accept() => {
                match accepted {
                    Ok(Some(resolver)) => {
                        let shared = Arc::clone(&shared);
                        requests.spawn(async move {
                            handle_request(resolver, peer, &shared).await;
                        });
                    }
                    Ok(None) => break,
                    Err(_) => {
                        shared.stats.error();
                        break;
                    }
                }
            }
            () = tokio::time::sleep(shared.config.idle_timeout) => {
                shared.stats.timeout();
                let _ = timeout(SHUTDOWN_GOAWAY, h3_connection.shutdown(0)).await;
                break;
            }
        }
        while requests.try_join_next().is_some() {}
    }
    drop(h3_connection);

    let drain = async { while requests.join_next().await.is_some() {} };
    if timeout(shared.config.shutdown_timeout, drain)
        .await
        .is_err()
    {
        requests.abort_all();
        while requests.join_next().await.is_some() {}
    }
    quinn_connection.close(VarInt::from_u32(0), b"shutdown");
}

fn negotiated_h3(connection: &Connection) -> bool {
    connection
        .handshake_data()
        .and_then(|data| data.downcast::<HandshakeData>().ok())
        .and_then(|data| data.protocol)
        .is_some_and(|protocol| protocol == b"h3")
}

async fn handle_request(
    resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
    peer: SocketAddr,
    shared: &Shared,
) {
    shared.stats.http_request();
    let (request, mut stream) =
        match timeout(shared.config.request_timeout, resolver.resolve_request()).await {
            Ok(Ok(parts)) => parts,
            Ok(Err(_)) => {
                shared.stats.error();
                return;
            }
            Err(_) => {
                shared.stats.timeout();
                return;
            }
        };
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
    loop {
        match timeout(shared.config.request_timeout, stream.recv_data()).await {
            Ok(Ok(Some(mut chunk))) => {
                while chunk.has_remaining() {
                    let bytes = chunk.chunk();
                    if body_error.is_none()
                        && body.len().saturating_add(bytes.len()) > shared.config.max_body_size
                    {
                        body_error = Some(413);
                        body.clear();
                    }
                    if body_error.is_none() {
                        body.extend_from_slice(bytes);
                    }
                    let advance = bytes.len();
                    chunk.advance(advance);
                }
                if body_error.is_some() {
                    stream.stop_sending(Code::H3_REQUEST_CANCELLED);
                    break;
                }
            }
            Ok(Ok(None)) => break,
            Ok(Err(_)) => {
                shared.stats.error();
                return;
            }
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
    if send_response(stream, response, shared).await.is_err() {
        shared.stats.error();
    }
}

async fn send_response(
    mut stream: RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    response: crate::http::HttpResponse,
    shared: &Shared,
) -> Result<(), Error> {
    let send = async {
        let status = StatusCode::from_u16(response.status)
            .map_err(|error| Error::Http(error.to_string()))?;
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
        let head = builder
            .body(())
            .map_err(|error| Error::Http(error.to_string()))?;
        let body_len = response.body.len();
        let is_dns = status == StatusCode::OK && response.content_type == "application/dns-message";
        stream
            .send_response(head)
            .await
            .map_err(|error| Error::Http(error.to_string()))?;
        if !response.body.is_empty() {
            stream
                .send_data(Bytes::from(response.body))
                .await
                .map_err(|error| Error::Http(error.to_string()))?;
        }
        stream
            .finish()
            .await
            .map_err(|error| Error::Http(error.to_string()))?;
        shared.stats.written_bytes(body_len);
        if is_dns {
            shared.stats.response();
        }
        Ok::<(), Error>(())
    };
    match timeout(shared.config.request_timeout, send).await {
        Ok(result) => result,
        Err(_) => {
            shared.stats.timeout();
            stream.stop_stream(Code::H3_REQUEST_CANCELLED);
            Err(Error::Timeout)
        }
    }
}
