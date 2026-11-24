//! TCP-транспорт: std listener, поток на соединение, length-prefixed framing.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Shutdown as SocketShutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use pulse_server::Transport;

use crate::stats::Stats;
use crate::store::SharedZoneAdmin;
use crate::{dns, logging};

const ACCEPT_POLL: Duration = Duration::from_millis(20);
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

static NEXT_CONNECTION: AtomicU64 = AtomicU64::new(1);

/// Запущенный TCP-сервер.
pub(crate) struct TcpService {
    local_addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    stats: Arc<Stats>,
    connections: Arc<Mutex<HashMap<u64, TcpStream>>>,
    idle_timeout: Duration,
    acceptor: Option<JoinHandle<()>>,
}

impl TcpService {
    pub(crate) fn start(
        addr: SocketAddr,
        max_connections: usize,
        idle_timeout: Duration,
        admin: Arc<SharedZoneAdmin>,
        stats: Arc<Stats>,
    ) -> io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(true)?;
        let local_addr = listener.local_addr()?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let connections = Arc::new(Mutex::new(HashMap::new()));
        let acceptor = {
            let shutdown = Arc::clone(&shutdown);
            let connections = Arc::clone(&connections);
            let stats = Arc::clone(&stats);
            thread::Builder::new()
                .name("pulse-tcp-accept".to_owned())
                .spawn(move || {
                    accept_loop(
                        &listener,
                        max_connections,
                        idle_timeout,
                        &admin,
                        &stats,
                        &shutdown,
                        &connections,
                    );
                })?
        };
        Ok(Self {
            local_addr,
            shutdown,
            stats,
            connections,
            idle_timeout,
            acceptor: Some(acceptor),
        })
    }

    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub(crate) fn shutdown(&mut self) -> io::Result<()> {
        self.shutdown.store(true, Ordering::Release);
        if let Some(acceptor) = self.acceptor.take() {
            acceptor
                .join()
                .map_err(|_| io::Error::other("tcp acceptor thread panicked"))?;
        }
        let streams: Vec<TcpStream> = {
            let connections = self
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
        let deadline = Instant::now() + self.idle_timeout + Duration::from_millis(500);
        while self.stats.tcp_active() > 0 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        if self.stats.tcp_active() > 0 {
            logging::warn(
                "tcp_shutdown",
                &format!(
                    "{} TCP connection(s) still active after graceful deadline",
                    self.stats.tcp_active()
                ),
            );
        }
        Ok(())
    }
}

impl Drop for TcpService {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn accept_loop(
    listener: &TcpListener,
    max_connections: usize,
    idle_timeout: Duration,
    admin: &Arc<SharedZoneAdmin>,
    stats: &Arc<Stats>,
    shutdown: &Arc<AtomicBool>,
    connections: &Arc<Mutex<HashMap<u64, TcpStream>>>,
) {
    while !shutdown.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _peer)) => spawn_connection(
                stream,
                max_connections,
                idle_timeout,
                admin,
                stats,
                shutdown,
                connections,
            ),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_POLL);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => {
                stats.tcp_accept_error();
                logging::warn("tcp_accept", &format!("accept failed: {error}"));
                thread::sleep(ACCEPT_ERROR_BACKOFF);
            }
        }
    }
}

fn spawn_connection(
    stream: TcpStream,
    max_connections: usize,
    idle_timeout: Duration,
    admin: &Arc<SharedZoneAdmin>,
    stats: &Arc<Stats>,
    shutdown: &Arc<AtomicBool>,
    connections: &Arc<Mutex<HashMap<u64, TcpStream>>>,
) {
    let active = usize::try_from(stats.tcp_active()).unwrap_or(usize::MAX);
    if active >= max_connections {
        stats.tcp_rejected();
        return;
    }
    stats.tcp_connection_opened();
    let id = NEXT_CONNECTION.fetch_add(1, Ordering::Relaxed);
    let guard = ConnectionGuard {
        id,
        connections: Arc::clone(connections),
        stats: Arc::clone(stats),
    };
    if let Ok(tracked) = stream.try_clone() {
        guard
            .connections
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id, tracked);
    }
    let admin = Arc::clone(admin);
    let stats = Arc::clone(stats);
    let shutdown = Arc::clone(shutdown);
    let spawned = thread::Builder::new()
        .name(format!("pulse-tcp-{id}"))
        .spawn(move || {
            let _guard = guard;
            if let Err(error) = handle_connection(stream, &admin, &stats, &shutdown, idle_timeout) {
                stats.tcp_io_error();
                logging::debug(
                    "tcp_connection",
                    &format!("connection {id} closed with error: {error}"),
                );
            }
        });
    if let Err(error) = spawned {
        logging::warn(
            "tcp_spawn",
            &format!("cannot spawn connection thread: {error}"),
        );
    }
}

struct ConnectionGuard {
    id: u64,
    connections: Arc<Mutex<HashMap<u64, TcpStream>>>,
    stats: Arc<Stats>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.connections
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.id);
        self.stats.tcp_connection_closed();
    }
}

fn handle_connection(
    mut stream: TcpStream,
    admin: &SharedZoneAdmin,
    stats: &Stats,
    shutdown: &AtomicBool,
    idle_timeout: Duration,
) -> io::Result<()> {
    stream.set_read_timeout(Some(idle_timeout))?;
    stream.set_write_timeout(Some(idle_timeout))?;
    stream.set_nodelay(true)?;
    loop {
        if shutdown.load(Ordering::Acquire) {
            return Ok(());
        }
        let Some(length) = read_prefix(&mut stream)? else {
            return Ok(());
        };
        if length == 0 {
            return Ok(());
        }
        let mut request = vec![0_u8; usize::from(length)];
        if !read_exact_idle(&mut stream, &mut request)? {
            return Ok(());
        }
        let engine = admin.engine();
        let Some(response) = dns::respond(&request, Transport::Tcp, &engine, stats) else {
            continue;
        };
        let length = u16::try_from(response.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "response exceeds 65535 bytes")
        })?;
        stream.write_all(&length.to_be_bytes())?;
        stream.write_all(&response)?;
        stream.flush()?;
    }
}

fn read_prefix(stream: &mut TcpStream) -> io::Result<Option<u16>> {
    let mut prefix = [0_u8; 2];
    if !read_exact_idle(stream, &mut prefix)? {
        return Ok(None);
    }
    Ok(Some(u16::from_be_bytes(prefix)))
}

fn read_exact_idle(stream: &mut TcpStream, buffer: &mut [u8]) -> io::Result<bool> {
    let mut filled = 0;
    while filled < buffer.len() {
        match stream.read(&mut buffer[filled..]) {
            Ok(0) => return Ok(false),
            Ok(read) => filled += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if is_timeout(&error) => return Ok(false),
            Err(error) => return Err(error),
        }
    }
    Ok(true)
}

fn is_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}
