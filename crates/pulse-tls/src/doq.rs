//! DNS over QUIC (RFC 9250) на `quinn`, включается feature `doq`.
//!
//! Один двунаправленный QUIC stream на запрос: 2-байтовый length-prefix
//! (big-endian, как DNS/TCP), затем DNS-сообщение. ALPN — `doq`, 0-RTT не
//! включается. Лимиты: одновременные соединения, двунаправленные stream'ы на
//! соединение, размер сообщения, idle timeout и таймаут одной операции.
//!
//! Сервер поднимает собственный tokio runtime в фоновом потоке; вызывающий
//! API синхронный и не зависит от `pulsed`/`pulse-server`.
//!
//! # Пример
//!
//! ```no_run
//! use pulse_tls::{DoqConfig, DoqServer, TlsConfig};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let cert = std::fs::read("cert.pem")?;
//! let key = std::fs::read("key.pem")?;
//! let tls = TlsConfig::for_doq(&cert, &key)?;
//! let mut server = DoqServer::bind(
//!     DoqConfig::new("0.0.0.0:853".parse()?, tls),
//!     |query, _peer| Some(query.to_vec()),
//! )?;
//! println!("listening on {}", server.local_addr());
//! server.shutdown()?;
//! # Ok(())
//! # }
//! ```

use std::net::{SocketAddr, UdpSocket};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc as std_mpsc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use quinn::crypto::rustls::HandshakeData;
use quinn::{Connection, Endpoint, EndpointConfig, IdleTimeout, TransportConfig, VarInt};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::acl::Acl;
use crate::dot::DnsHandler;
use crate::error::Error;
use crate::ratelimit::{RateLimitConfig, RateLimiter};
use crate::stats::{Stats, StatsSnapshot};
use crate::tls::TlsConfig;

const DEFAULT_MAX_CONNECTIONS: usize = 1024;
const DEFAULT_MAX_STREAMS: u32 = 100;
const DEFAULT_MAX_MESSAGE: usize = 65_535;
const DEFAULT_WORKER_THREADS: usize = 2;
const SHUTDOWN_POLL: Duration = Duration::from_millis(5);
const DOQ_PROTOCOL_ERROR: u32 = 0x2;
const DOQ_INTERNAL_ERROR: u32 = 0x1;

/// Конфигурация DoQ-сервера.
#[derive(Clone, Debug)]
pub struct DoqConfig {
    /// Адрес прослушивания (UDP).
    pub listen: SocketAddr,
    /// TLS-конфигурация с ALPN `doq` (TLS 1.3).
    pub tls: TlsConfig,
    /// Максимум одновременных QUIC-соединений.
    pub max_connections: usize,
    /// Максимум одновременных двунаправленных stream'ов на соединение.
    pub max_streams: u32,
    /// Максимальный размер DNS-сообщения (без 2-байтового префикса).
    pub max_message_size: usize,
    /// Таймаут установления QUIC-соединения.
    pub handshake_timeout: Duration,
    /// Idle timeout соединения (транспортный параметр QUIC).
    pub idle_timeout: Duration,
    /// Таймаут чтения запроса/записи ответа на одном stream.
    pub stream_timeout: Duration,
    /// Таймаут ожидания соединений при shutdown.
    pub shutdown_timeout: Duration,
    /// Число worker-потоков tokio runtime.
    pub worker_threads: usize,
    /// Опциональный ACL по IP.
    pub acl: Option<Acl>,
    /// Опциональный per-IP rate limit.
    pub rate_limit: Option<RateLimitConfig>,
}

impl DoqConfig {
    /// Конфигурация с безопасными значениями по умолчанию.
    #[must_use]
    pub fn new(listen: SocketAddr, tls: TlsConfig) -> Self {
        Self {
            listen,
            tls,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            max_streams: DEFAULT_MAX_STREAMS,
            max_message_size: DEFAULT_MAX_MESSAGE,
            handshake_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(30),
            stream_timeout: Duration::from_secs(10),
            shutdown_timeout: Duration::from_secs(5),
            worker_threads: DEFAULT_WORKER_THREADS,
            acl: None,
            rate_limit: None,
        }
    }

    fn validate(&self) -> Result<(), Error> {
        if self.max_connections == 0 {
            return Err(Error::InvalidConfig("max_connections must be positive"));
        }
        if self.max_streams == 0 {
            return Err(Error::InvalidConfig("max_streams must be positive"));
        }
        if self.max_message_size == 0 || self.max_message_size > usize::from(u16::MAX) {
            return Err(Error::InvalidConfig(
                "max_message_size must be in 1..=65535",
            ));
        }
        if self.worker_threads == 0 {
            return Err(Error::InvalidConfig("worker_threads must be positive"));
        }
        if self.handshake_timeout.is_zero()
            || self.idle_timeout.is_zero()
            || self.stream_timeout.is_zero()
            || self.shutdown_timeout.is_zero()
        {
            return Err(Error::InvalidConfig("timeouts must be positive"));
        }
        Ok(())
    }
}

struct Shared {
    config: DoqConfig,
    handler: DnsHandler,
    limiter: Option<RateLimiter>,
    stats: Arc<Stats>,
}

enum Command {
    Reload {
        ack: std_mpsc::Sender<Result<(), Error>>,
    },
}

/// Запущенный DoQ-сервер.
pub struct DoqServer {
    local_addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    shutdown_tx: watch::Sender<bool>,
    commands: mpsc::UnboundedSender<Command>,
    stats: Arc<Stats>,
    handle: Option<JoinHandle<()>>,
    shutdown_timeout: Duration,
    tls: TlsConfig,
}

impl std::fmt::Debug for DoqServer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DoqServer")
            .field("local_addr", &self.local_addr)
            .field("stats", &self.stats.snapshot())
            .finish_non_exhaustive()
    }
}

impl DoqServer {
    /// Привязывает UDP-сокет и запускает tokio runtime в фоновом потоке.
    ///
    /// # Errors
    ///
    /// Некорректная конфигурация, ошибка bind/создания endpoint или потока.
    pub fn bind<H>(config: DoqConfig, handler: H) -> Result<Self, Error>
    where
        H: Fn(&[u8], SocketAddr) -> Option<Vec<u8>> + Send + Sync + 'static,
    {
        Self::bind_with_stats(config, handler, Arc::new(Stats::new()))
    }

    /// То же, но с общими счётчиками.
    ///
    /// # Errors
    ///
    /// См. [`DoqServer::bind`].
    pub fn bind_with_stats<H>(
        config: DoqConfig,
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
    /// См. [`DoqServer::bind`].
    pub fn bind_shared(
        config: DoqConfig,
        handler: DnsHandler,
        stats: Arc<Stats>,
    ) -> Result<Self, Error> {
        config.validate()?;
        let limiter = match config.rate_limit {
            Some(rate_limit) => Some(RateLimiter::new(rate_limit)?),
            None => None,
        };
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
            .thread_name("pulse-doq-rt")
            .build()?;
        let shared = Arc::new(Shared {
            config: config.clone(),
            handler,
            limiter,
            stats: Arc::clone(&stats),
        });
        let handle = thread::Builder::new()
            .name("pulse-doq".to_owned())
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
    /// См. [`DoqServer::reload`].
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

    /// Закрывает endpoint (CONNECTION_CLOSE) и ждёт завершения задач.
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

impl Drop for DoqServer {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn build_transport(config: &DoqConfig) -> Result<Arc<TransportConfig>, Error> {
    let mut transport = TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(VarInt::from_u32(config.max_streams))
        .max_concurrent_uni_streams(VarInt::from_u32(0));
    let idle = IdleTimeout::try_from(config.idle_timeout)
        .map_err(|error| Error::Quic(format!("idle timeout: {error}")))?;
    transport.max_idle_timeout(Some(idle));
    Ok(Arc::new(transport))
}

async fn serve(
    socket: UdpSocket,
    quic_config: quinn::ServerConfig,
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
    endpoint.close(VarInt::from_u32(0), b"shutdown");
    let drain = async { while connections.join_next().await.is_some() {} };
    let _ = timeout(shared.config.shutdown_timeout, drain).await;
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
    if !negotiated_doq(&connection) {
        shared.stats.error();
        connection.close(VarInt::from_u32(DOQ_PROTOCOL_ERROR), b"ALPN");
        return;
    }
    let mut streams = JoinSet::new();
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    connection.close(VarInt::from_u32(0), b"shutdown");
                    break;
                }
            }
            accepted = connection.accept_bi() => {
                match accepted {
                    Ok((send, recv)) => {
                        let shared = Arc::clone(&shared);
                        streams.spawn(async move {
                            handle_stream(send, recv, peer, &shared).await;
                        });
                    }
                    Err(_) => break,
                }
            }
        }
        while streams.try_join_next().is_some() {}
    }
    streams.abort_all();
    while streams.join_next().await.is_some() {}
}

fn negotiated_doq(connection: &Connection) -> bool {
    connection
        .handshake_data()
        .and_then(|data| data.downcast::<HandshakeData>().ok())
        .and_then(|data| data.protocol)
        .is_some_and(|protocol| protocol == b"doq")
}

async fn handle_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    peer: SocketAddr,
    shared: &Shared,
) {
    let mut prefix = [0_u8; 2];
    if timeout(shared.config.stream_timeout, recv.read_exact(&mut prefix))
        .await
        .is_err()
    {
        shared.stats.timeout();
        let _ = send.reset(VarInt::from_u32(DOQ_INTERNAL_ERROR));
        return;
    }
    let length = usize::from(u16::from_be_bytes(prefix));
    if length == 0 || length > shared.config.max_message_size {
        shared.stats.error();
        let _ = send.reset(VarInt::from_u32(DOQ_PROTOCOL_ERROR));
        return;
    }
    let mut request = vec![0_u8; length];
    if timeout(shared.config.stream_timeout, recv.read_exact(&mut request))
        .await
        .is_err()
    {
        shared.stats.timeout();
        let _ = send.reset(VarInt::from_u32(DOQ_INTERNAL_ERROR));
        return;
    }
    shared.stats.read_bytes(length);
    shared.stats.query();
    if let Some(response) = non_zero_id_formerr(&request) {
        write_response(&mut send, &response, shared).await;
        return;
    }
    if let Some(limiter) = &shared.limiter
        && !limiter.allow(peer.ip())
    {
        shared.stats.rate_limited();
        let _ = send.reset(VarInt::from_u32(4));
        return;
    }
    let outcome = catch_unwind(AssertUnwindSafe(|| (shared.handler)(&request, peer)));
    let response = match outcome {
        Ok(Some(response)) if !response.is_empty() => response,
        _ => {
            shared.stats.error();
            let _ = send.reset(VarInt::from_u32(DOQ_INTERNAL_ERROR));
            return;
        }
    };
    write_response(&mut send, &response, shared).await;
}

/// RFC 9250 §4.2: сообщение с ненулевым ID получает FORMERR с ID 0.
fn non_zero_id_formerr(request: &[u8]) -> Option<Vec<u8>> {
    let id = u16::from_be_bytes([*request.first()?, *request.get(1)?]);
    if id == 0 {
        return None;
    }
    let mut response = request.to_vec();
    response.get_mut(..2)?.copy_from_slice(&[0, 0]);
    let flags = u16::from_be_bytes([*request.get(2)?, *request.get(3)?]);
    let flags = (flags & !0x000F) | 0x8000 | 0x0001;
    response
        .get_mut(2..4)?
        .copy_from_slice(&flags.to_be_bytes());
    response.get_mut(6..12)?.fill(0);
    Some(response)
}

async fn write_response(send: &mut quinn::SendStream, response: &[u8], shared: &Shared) {
    if response.len() > shared.config.max_message_size || response.len() > usize::from(u16::MAX) {
        shared.stats.error();
        let _ = send.reset(VarInt::from_u32(DOQ_INTERNAL_ERROR));
        return;
    }
    let Ok(response_length) = u16::try_from(response.len()) else {
        shared.stats.error();
        let _ = send.reset(VarInt::from_u32(DOQ_INTERNAL_ERROR));
        return;
    };
    let write = async {
        send.write_all(&response_length.to_be_bytes()).await?;
        send.write_all(response).await?;
        send.finish()?;
        Ok::<(), quinn::WriteError>(())
    };
    match timeout(shared.config.stream_timeout, write).await {
        Ok(Ok(())) => {
            shared.stats.written_bytes(response.len() + 2);
            shared.stats.response();
        }
        Ok(Err(_)) => shared.stats.error(),
        Err(_) => {
            shared.stats.timeout();
            let _ = send.reset(VarInt::from_u32(DOQ_INTERNAL_ERROR));
        }
    }
}
