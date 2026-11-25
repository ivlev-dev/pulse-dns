//! Защищённые транспорты: DoT (RFC 7858), DoH/1.1 и DoH/2 (RFC 8484),
//! DoQ (RFC 9250) и DNSCrypt v2 (UDP/TCP).
//!
//! Все транспорты используют один и тот же путь обработки запроса
//! ([`Processor`]): `MessageRef → Resolver::resolve_ref_into → wire`, поэтому
//! ACL, per-source rate limit, blocklist, overrides и кеш ведут себя
//! одинаково. На попадании в кеш ответ не строит `Message` и не аллоцирует.
//! RRL применяется только к открытому UDP; на TLS/QUIC-транспортах действует
//! token bucket по source IP.
//!
//! ACL и rate limit применяются внутри обработчика, а не на уровне accept:
//! клиент, не прошедший ACL, получает обычный `REFUSED` (для DNSCrypt — в
//! зашифрованном виде), а не молчаливое закрытие соединения.

use std::collections::HashMap;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Shutdown as SocketShutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use pulse_dnscrypt::{Certificate, DnscryptServer, ProviderKeypair, ResolverKeypair};
use pulse_tls::{
    DnsHandler, Doh2Config, Doh2Server, DohConfig, DohServer, DoqConfig, DoqServer, DotConfig,
    DotServer, Stats as TlsStats, TlsConfig,
};

use crate::config::Config;
use crate::error::{ConfigError, ServerError};
use crate::logging;
use crate::query::{Processor, Transport};
use crate::stats::Stats;

const UDP_POLL: Duration = Duration::from_millis(200);
const ACCEPT_POLL: Duration = Duration::from_millis(20);
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);
const SHUTDOWN_POLL: Duration = Duration::from_millis(5);
const SHUTDOWN_GRACE: Duration = Duration::from_millis(500);

static NEXT_DNSCRYPT_CONNECTION: AtomicU64 = AtomicU64::new(1);

/// Собирает TLS-конфигурацию из файлов для указанного ALPN.
fn tls_config(
    config: &Config,
    alpn: &[u8],
    transport: &'static str,
) -> Result<TlsConfig, ServerError> {
    let (cert, key) = config.tls_paths().ok_or_else(|| {
        ServerError::Config(ConfigError::invalid(
            "tls_cert and tls_key are required for secure transports",
        ))
    })?;
    TlsConfig::from_pem_files(cert, key, &[alpn])
        .map_err(|source| ServerError::Secure { transport, source })
}

/// Общий обработчик `DnsHandler` для всех TLS-транспортов.
pub(crate) fn handler(processor: Arc<Processor>, transport: Transport) -> DnsHandler {
    Arc::new(move |query: &[u8], peer: SocketAddr| processor.handle(query, transport, peer))
}

/// DoT-сервер.
pub(crate) struct DotService {
    server: DotServer,
    stats: Arc<TlsStats>,
}

impl DotService {
    pub(crate) fn start(
        addr: SocketAddr,
        config: &Config,
        handler: DnsHandler,
    ) -> Result<Self, ServerError> {
        let tls = tls_config(config, b"dot", "DoT")?;
        let mut dot = DotConfig::new(addr, tls);
        dot.max_connections = config.secure.max_connections;
        dot.handshake_timeout = config.secure.handshake_timeout();
        dot.idle_timeout = config.secure.idle_timeout();
        dot.shutdown_timeout = config.secure.shutdown_timeout();
        dot.max_message_size = config.secure.max_message_size;
        dot.max_messages_per_connection = config.secure.max_requests_per_connection;
        let stats = Arc::new(TlsStats::new());
        let server =
            DotServer::bind_shared(dot, handler, Arc::clone(&stats)).map_err(|source| {
                ServerError::SecureStart {
                    transport: "DoT",
                    addr,
                    source,
                }
            })?;
        Ok(Self { server, stats })
    }

    pub(crate) fn addr(&self) -> SocketAddr {
        self.server.local_addr()
    }

    pub(crate) fn stats(&self) -> pulse_tls::StatsSnapshot {
        self.stats.snapshot()
    }

    pub(crate) fn stats_handle(&self) -> Arc<TlsStats> {
        Arc::clone(&self.stats)
    }

    pub(crate) fn reload(&self) -> Result<(), ServerError> {
        self.server
            .reload_from_files()
            .map_err(|source| ServerError::Secure {
                transport: "DoT",
                source,
            })
    }

    pub(crate) fn shutdown(&mut self) -> Result<(), ServerError> {
        self.server
            .shutdown()
            .map_err(|source| ServerError::Secure {
                transport: "DoT",
                source,
            })
    }
}

/// DoH/1.1-сервер.
pub(crate) struct DohService {
    server: DohServer,
    stats: Arc<TlsStats>,
}

impl DohService {
    pub(crate) fn start(
        addr: SocketAddr,
        config: &Config,
        handler: DnsHandler,
    ) -> Result<Self, ServerError> {
        let tls = tls_config(config, b"http/1.1", "DoH")?;
        let mut doh = DohConfig::new(addr, tls);
        doh.max_connections = config.secure.max_connections;
        doh.handshake_timeout = config.secure.handshake_timeout();
        doh.idle_timeout = config.secure.idle_timeout();
        doh.shutdown_timeout = config.secure.shutdown_timeout();
        doh.max_body_size = config.secure.max_message_size;
        doh.max_requests_per_connection = config.secure.max_requests_per_connection;
        doh.cache_control = config.secure.cache_control;
        let stats = Arc::new(TlsStats::new());
        let server =
            DohServer::bind_shared(doh, handler, Arc::clone(&stats)).map_err(|source| {
                ServerError::SecureStart {
                    transport: "DoH",
                    addr,
                    source,
                }
            })?;
        Ok(Self { server, stats })
    }

    pub(crate) fn addr(&self) -> SocketAddr {
        self.server.local_addr()
    }

    pub(crate) fn stats(&self) -> pulse_tls::StatsSnapshot {
        self.stats.snapshot()
    }

    pub(crate) fn stats_handle(&self) -> Arc<TlsStats> {
        Arc::clone(&self.stats)
    }

    pub(crate) fn reload(&self) -> Result<(), ServerError> {
        self.server
            .reload_from_files()
            .map_err(|source| ServerError::Secure {
                transport: "DoH",
                source,
            })
    }

    pub(crate) fn shutdown(&mut self) -> Result<(), ServerError> {
        self.server
            .shutdown()
            .map_err(|source| ServerError::Secure {
                transport: "DoH",
                source,
            })
    }
}

/// DoH/HTTP/2-сервер.
pub(crate) struct Doh2Service {
    server: Doh2Server,
    stats: Arc<TlsStats>,
}

impl Doh2Service {
    pub(crate) fn start(
        addr: SocketAddr,
        config: &Config,
        handler: DnsHandler,
    ) -> Result<Self, ServerError> {
        let tls = tls_config(config, b"h2", "DoH/2")?;
        let mut doh = Doh2Config::new(addr, tls);
        doh.max_connections = config.secure.max_connections;
        doh.max_concurrent_streams = config.secure.max_streams;
        doh.handshake_timeout = config.secure.handshake_timeout();
        doh.idle_timeout = config.secure.idle_timeout();
        doh.request_timeout = config.secure.request_timeout();
        doh.shutdown_timeout = config.secure.shutdown_timeout();
        doh.max_body_size = config.secure.max_message_size;
        doh.worker_threads = config.secure.worker_threads;
        doh.cache_control = config.secure.cache_control;
        let stats = Arc::new(TlsStats::new());
        let server =
            Doh2Server::bind_shared(doh, handler, Arc::clone(&stats)).map_err(|source| {
                ServerError::SecureStart {
                    transport: "DoH/2",
                    addr,
                    source,
                }
            })?;
        Ok(Self { server, stats })
    }

    pub(crate) fn addr(&self) -> SocketAddr {
        self.server.local_addr()
    }

    pub(crate) fn stats(&self) -> pulse_tls::StatsSnapshot {
        self.stats.snapshot()
    }

    pub(crate) fn stats_handle(&self) -> Arc<TlsStats> {
        Arc::clone(&self.stats)
    }

    pub(crate) fn reload(&self) -> Result<(), ServerError> {
        self.server
            .reload_from_files()
            .map_err(|source| ServerError::Secure {
                transport: "DoH/2",
                source,
            })
    }

    pub(crate) fn shutdown(&mut self) -> Result<(), ServerError> {
        self.server
            .shutdown()
            .map_err(|source| ServerError::Secure {
                transport: "DoH/2",
                source,
            })
    }
}

/// DoQ-сервер.
pub(crate) struct DoqService {
    server: DoqServer,
    stats: Arc<TlsStats>,
}

impl DoqService {
    pub(crate) fn start(
        addr: SocketAddr,
        config: &Config,
        handler: DnsHandler,
    ) -> Result<Self, ServerError> {
        let tls = tls_config(config, b"doq", "DoQ")?;
        let mut doq = DoqConfig::new(addr, tls);
        doq.max_connections = config.secure.max_connections;
        doq.max_streams = config.secure.max_streams;
        doq.max_message_size = config.secure.max_message_size;
        doq.handshake_timeout = config.secure.handshake_timeout();
        doq.idle_timeout = config.secure.idle_timeout();
        doq.stream_timeout = config.secure.request_timeout();
        doq.shutdown_timeout = config.secure.shutdown_timeout();
        doq.worker_threads = config.secure.worker_threads;
        let stats = Arc::new(TlsStats::new());
        let server =
            DoqServer::bind_shared(doq, handler, Arc::clone(&stats)).map_err(|source| {
                ServerError::SecureStart {
                    transport: "DoQ",
                    addr,
                    source,
                }
            })?;
        Ok(Self { server, stats })
    }

    pub(crate) fn addr(&self) -> SocketAddr {
        self.server.local_addr()
    }

    pub(crate) fn stats(&self) -> pulse_tls::StatsSnapshot {
        self.stats.snapshot()
    }

    pub(crate) fn stats_handle(&self) -> Arc<TlsStats> {
        Arc::clone(&self.stats)
    }

    pub(crate) fn reload(&self) -> Result<(), ServerError> {
        self.server
            .reload_from_files()
            .map_err(|source| ServerError::Secure {
                transport: "DoQ",
                source,
            })
    }

    pub(crate) fn shutdown(&mut self) -> Result<(), ServerError> {
        self.server
            .shutdown()
            .map_err(|source| ServerError::Secure {
                transport: "DoQ",
                source,
            })
    }
}

/// Запущенный DNSCrypt v2 (UDP и/или TCP).
pub(crate) struct DnscryptService {
    udp_addr: Option<SocketAddr>,
    udp: Option<JoinHandle<()>>,
    tcp_addr: Option<SocketAddr>,
    tcp: Option<DnscryptTcp>,
    shutdown: Arc<AtomicBool>,
    stats: Arc<Stats>,
    idle_timeout: Duration,
}

struct DnscryptTcp {
    acceptor: Option<JoinHandle<()>>,
    connections: Arc<Mutex<HashMap<u64, TcpStream>>>,
}

impl DnscryptService {
    pub(crate) fn start(
        config: &Config,
        processor: Arc<Processor>,
        stats: Arc<Stats>,
    ) -> Result<Self, ServerError> {
        let server = Arc::new(load_dnscrypt_server(config)?);
        let shutdown = Arc::new(AtomicBool::new(false));
        let idle_timeout = config.secure.idle_timeout();
        let udp = match config.dnscrypt_listen {
            Some(addr) => Some(Self::start_udp(
                addr,
                Arc::clone(&server),
                Arc::clone(&processor),
                Arc::clone(&stats),
                Arc::clone(&shutdown),
            )?),
            None => None,
        };
        let tcp = match config.dnscrypt_tcp_listen {
            Some(addr) => Some(Self::start_tcp(
                addr,
                config,
                server,
                processor,
                Arc::clone(&stats),
                Arc::clone(&shutdown),
            )?),
            None => None,
        };
        Ok(Self {
            udp_addr: udp.as_ref().map(|(addr, _)| *addr),
            udp: udp.map(|(_, handle)| handle),
            tcp_addr: tcp.as_ref().map(|(addr, _)| *addr),
            tcp: tcp.map(|(_, state)| state),
            shutdown,
            stats,
            idle_timeout,
        })
    }

    fn start_udp(
        addr: SocketAddr,
        server: Arc<DnscryptServer>,
        processor: Arc<Processor>,
        stats: Arc<Stats>,
        shutdown: Arc<AtomicBool>,
    ) -> Result<(SocketAddr, JoinHandle<()>), ServerError> {
        let socket = UdpSocket::bind(addr)
            .map_err(|error| ServerError::Dnscrypt(format!("cannot bind UDP {addr}: {error}")))?;
        socket.set_read_timeout(Some(UDP_POLL)).map_err(|error| {
            ServerError::Dnscrypt(format!("cannot configure UDP {addr}: {error}"))
        })?;
        let local_addr = socket
            .local_addr()
            .map_err(|error| ServerError::Dnscrypt(format!("cannot read UDP address: {error}")))?;
        let handle = thread::Builder::new()
            .name("pulseresolved-dnscrypt-udp".to_owned())
            .spawn(move || udp_loop(socket, &server, &processor, &stats, &shutdown))
            .map_err(|error| ServerError::Dnscrypt(format!("cannot spawn UDP thread: {error}")))?;
        Ok((local_addr, handle))
    }

    fn start_tcp(
        addr: SocketAddr,
        config: &Config,
        server: Arc<DnscryptServer>,
        processor: Arc<Processor>,
        stats: Arc<Stats>,
        shutdown: Arc<AtomicBool>,
    ) -> Result<(SocketAddr, DnscryptTcp), ServerError> {
        let listener = TcpListener::bind(addr)
            .map_err(|error| ServerError::Dnscrypt(format!("cannot bind TCP {addr}: {error}")))?;
        listener.set_nonblocking(true).map_err(|error| {
            ServerError::Dnscrypt(format!("cannot configure TCP {addr}: {error}"))
        })?;
        let local_addr = listener
            .local_addr()
            .map_err(|error| ServerError::Dnscrypt(format!("cannot read TCP address: {error}")))?;
        let connections = Arc::new(Mutex::new(HashMap::new()));
        let context = Arc::new(TcpContext {
            server,
            processor,
            stats: Arc::clone(&stats),
            shutdown: Arc::clone(&shutdown),
            connections: Arc::clone(&connections),
            idle_timeout: config.secure.idle_timeout(),
            max_frame: config.dnscrypt.max_tcp_packet,
            max_connections: config.secure.max_connections,
        });
        let acceptor = {
            let context = Arc::clone(&context);
            thread::Builder::new()
                .name("pulseresolved-dnscrypt-tcp".to_owned())
                .spawn(move || tcp_accept_loop(&listener, &context))
                .map_err(|error| {
                    ServerError::Dnscrypt(format!("cannot spawn TCP thread: {error}"))
                })?
        };
        Ok((
            local_addr,
            DnscryptTcp {
                acceptor: Some(acceptor),
                connections,
            },
        ))
    }

    pub(crate) fn udp_addr(&self) -> Option<SocketAddr> {
        self.udp_addr
    }

    pub(crate) fn tcp_addr(&self) -> Option<SocketAddr> {
        self.tcp_addr
    }

    pub(crate) fn shutdown(&mut self) -> Result<(), ServerError> {
        self.shutdown.store(true, Ordering::Release);
        let mut first_error = None;
        if let Some(tcp) = self.tcp.take() {
            if let Some(acceptor) = tcp.acceptor
                && acceptor.join().is_err()
            {
                first_error = Some(ServerError::Dnscrypt(
                    "DNSCrypt TCP acceptor thread panicked".to_owned(),
                ));
            }
            let streams: Vec<TcpStream> = {
                let connections = tcp
                    .connections
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                connections
                    .values()
                    .filter_map(|stream| stream.try_clone().ok())
                    .collect()
            };
            for stream in streams {
                let _ = stream.shutdown(SocketShutdown::Both);
            }
            let deadline = Instant::now() + self.idle_timeout + SHUTDOWN_GRACE;
            while self.stats.dnscrypt_tcp_active() > 0 && Instant::now() < deadline {
                thread::sleep(SHUTDOWN_POLL);
            }
        }
        if let Some(handle) = self.udp.take()
            && handle.join().is_err()
        {
            first_error.get_or_insert_with(|| {
                ServerError::Dnscrypt("DNSCrypt UDP thread panicked".to_owned())
            });
        }
        first_error.map_or(Ok(()), Err)
    }
}

impl Drop for DnscryptService {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

/// Ошибка обработчика, когда ответ не требуется (drop/rate limit).
#[derive(Debug)]
struct NoResponse;

impl fmt::Display for NoResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DNS handler produced no response")
    }
}

impl std::error::Error for NoResponse {}

struct InnerHandler<'a> {
    processor: &'a Processor,
    transport: Transport,
    peer: SocketAddr,
}

impl pulse_dnscrypt::QueryHandler for InnerHandler<'_> {
    type Error = NoResponse;

    fn handle_query(&self, query: &[u8]) -> Result<Vec<u8>, NoResponse> {
        self.processor
            .handle(query, self.transport, self.peer)
            .ok_or(NoResponse)
    }
}

fn udp_loop(
    socket: UdpSocket,
    server: &DnscryptServer,
    processor: &Processor,
    stats: &Stats,
    shutdown: &AtomicBool,
) {
    let mut buffer = vec![0_u8; pulse_dnscrypt::MAX_UDP_PACKET];
    while !shutdown.load(Ordering::Acquire) {
        match socket.recv_from(&mut buffer) {
            Ok((length, peer)) => {
                let Some(packet) = buffer.get(..length) else {
                    continue;
                };
                let handler = InnerHandler {
                    processor,
                    transport: Transport::DnscryptUdp,
                    peer,
                };
                match server.handle_udp(packet, &handler) {
                    Ok(response) => {
                        if socket.send_to(&response, peer).is_err() {
                            stats.dnscrypt_udp_error();
                        }
                    }
                    Err(_) => stats.dnscrypt_udp_error(),
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => stats.dnscrypt_udp_error(),
        }
    }
}

struct TcpContext {
    server: Arc<DnscryptServer>,
    processor: Arc<Processor>,
    stats: Arc<Stats>,
    shutdown: Arc<AtomicBool>,
    connections: Arc<Mutex<HashMap<u64, TcpStream>>>,
    idle_timeout: Duration,
    max_frame: usize,
    max_connections: usize,
}

impl TcpContext {
    fn remove(&self, id: u64) {
        self.connections
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&id);
    }
}

fn tcp_accept_loop(listener: &TcpListener, context: &Arc<TcpContext>) {
    while !context.shutdown.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, peer)) => {
                let active = context.stats.dnscrypt_tcp_active();
                if active >= u64::try_from(context.max_connections).unwrap_or(u64::MAX) {
                    context.stats.dnscrypt_tcp_rejected();
                    let _ = stream.shutdown(SocketShutdown::Both);
                    continue;
                }
                context.stats.dnscrypt_tcp_opened();
                let id = NEXT_DNSCRYPT_CONNECTION.fetch_add(1, Ordering::Relaxed);
                if let Ok(tracked) = stream.try_clone() {
                    context
                        .connections
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .insert(id, tracked);
                }
                let connection_context = Arc::clone(context);
                let spawned = thread::Builder::new()
                    .name(format!("pulseresolved-dnscrypt-{id}"))
                    .spawn(move || {
                        if let Err(error) = handle_tcp_connection(stream, peer, &connection_context)
                        {
                            connection_context.stats.dnscrypt_tcp_error();
                            logging::debug(
                                "dnscrypt_connection",
                                &format!("connection {id} closed with error: {error}"),
                            );
                        }
                        connection_context.remove(id);
                        connection_context.stats.dnscrypt_tcp_closed();
                    });
                if let Err(error) = spawned {
                    context.stats.dnscrypt_tcp_error();
                    context.remove(id);
                    context.stats.dnscrypt_tcp_closed();
                    logging::warn(
                        "dnscrypt_spawn",
                        &format!("cannot spawn connection thread: {error}"),
                    );
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_POLL);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => {
                context.stats.dnscrypt_tcp_error();
                logging::warn("dnscrypt_accept", &format!("accept failed: {error}"));
                thread::sleep(ACCEPT_BACKOFF);
            }
        }
    }
}

fn handle_tcp_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    context: &TcpContext,
) -> io::Result<()> {
    stream.set_read_timeout(Some(context.idle_timeout))?;
    stream.set_write_timeout(Some(context.idle_timeout))?;
    stream.set_nodelay(true)?;
    loop {
        if context.shutdown.load(Ordering::Acquire) {
            return Ok(());
        }
        let Some(frame) = read_frame(&mut stream, context.max_frame)? else {
            return Ok(());
        };
        let handler = InnerHandler {
            processor: &context.processor,
            transport: Transport::DnscryptTcp,
            peer,
        };
        let response = match context.server.handle_tcp_frame(&frame, &handler) {
            Ok(response) => response,
            Err(error) => {
                context.stats.dnscrypt_tcp_error();
                logging::debug(
                    "dnscrypt_frame",
                    &format!("cannot process DNSCrypt frame: {error}"),
                );
                return Ok(());
            }
        };
        stream.write_all(&response)?;
        stream.flush()?;
    }
}

fn read_frame(stream: &mut TcpStream, max_frame: usize) -> io::Result<Option<Vec<u8>>> {
    let mut prefix = [0_u8; 2];
    if !read_exact_idle(stream, &mut prefix)? {
        return Ok(None);
    }
    let length = usize::from(u16::from_be_bytes(prefix));
    if length == 0 || length > max_frame {
        return Ok(None);
    }
    let mut payload = vec![0_u8; length];
    if !read_exact_idle(stream, &mut payload)? {
        return Ok(None);
    }
    let mut frame = Vec::with_capacity(2 + payload.len());
    frame.extend_from_slice(&prefix);
    frame.extend_from_slice(&payload);
    Ok(Some(frame))
}

fn read_exact_idle(stream: &mut TcpStream, buffer: &mut [u8]) -> io::Result<bool> {
    let mut filled = 0;
    while filled < buffer.len() {
        match stream.read(&mut buffer[filled..]) {
            Ok(0) => return Ok(false),
            Ok(read) => filled += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Ok(false);
            }
            Err(error) => return Err(error),
        }
    }
    Ok(true)
}

/// Загружает ключи и сертификат DNSCrypt и собирает сервер.
fn load_dnscrypt_server(config: &Config) -> Result<DnscryptServer, ServerError> {
    let provider_path = config.dnscrypt_provider_key.as_deref().ok_or_else(|| {
        ServerError::Dnscrypt("dnscrypt_provider_key is not configured".to_owned())
    })?;
    let resolver_path = config.dnscrypt_resolver_key.as_deref().ok_or_else(|| {
        ServerError::Dnscrypt("dnscrypt_resolver_key is not configured".to_owned())
    })?;
    let cert_path = config
        .dnscrypt_cert
        .as_deref()
        .ok_or_else(|| ServerError::Dnscrypt("dnscrypt_cert is not configured".to_owned()))?;

    let provider = ProviderKeypair::from_seed(read_secret(provider_path, "dnscrypt_provider_key")?);
    let resolver =
        ResolverKeypair::from_secret_bytes(read_secret(resolver_path, "dnscrypt_resolver_key")?);
    let certificate = read_certificate(cert_path)?;
    if certificate.resolver_pk() != &resolver.public_key().to_bytes() {
        return Err(ServerError::Dnscrypt(format!(
            "{}: resolver key does not match the certificate",
            cert_path.display()
        )));
    }
    let mut server = DnscryptServer::new(provider.public_key(), config.dnscrypt.server_config())
        .map_err(|error| ServerError::Dnscrypt(error.to_string()))?;
    server
        .add_certificate(certificate, resolver)
        .map_err(|error| ServerError::Dnscrypt(error.to_string()))?;
    Ok(server)
}

fn read_secret(path: &Path, label: &str) -> Result<[u8; pulse_dnscrypt::KEY_LEN], ServerError> {
    let text = std::fs::read_to_string(path).map_err(|error| {
        ServerError::Dnscrypt(format!("cannot read {label} {}: {error}", path.display()))
    })?;
    let bytes = pulse_dnscrypt::from_hex(&text).map_err(|error| {
        ServerError::Dnscrypt(format!(
            "{label} {} is not valid hex: {error}",
            path.display()
        ))
    })?;
    bytes.try_into().map_err(|_| {
        ServerError::Dnscrypt(format!(
            "{label} {} must contain exactly {} bytes of hex",
            path.display(),
            pulse_dnscrypt::KEY_LEN
        ))
    })
}

/// Поля JSON-сертификата, который пишет `pulsed dnscrypt-gencert`.
#[derive(serde::Deserialize)]
struct CertificateFile {
    certificate: String,
}

fn read_certificate(path: &Path) -> Result<Certificate, ServerError> {
    let text = std::fs::read_to_string(path).map_err(|error| {
        ServerError::Dnscrypt(format!(
            "cannot read dnscrypt_cert {}: {error}",
            path.display()
        ))
    })?;
    let trimmed = text.trim();
    if trimmed.starts_with('{') {
        let file: CertificateFile = serde_json::from_str(trimmed).map_err(|error| {
            ServerError::Dnscrypt(format!(
                "dnscrypt_cert {} is not valid JSON: {error}",
                path.display()
            ))
        })?;
        return Certificate::from_hex(&file.certificate).map_err(|error| {
            ServerError::Dnscrypt(format!(
                "dnscrypt_cert {} has invalid certificate: {error}",
                path.display()
            ))
        });
    }
    Certificate::from_hex(trimmed)
        .or_else(|_| Certificate::from_base64(trimmed))
        .map_err(|error| {
            ServerError::Dnscrypt(format!(
                "dnscrypt_cert {} is neither hex nor base64: {error}",
                path.display()
            ))
        })
}
