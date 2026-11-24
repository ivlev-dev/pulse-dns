//! Общий accept loop, учёт соединений и graceful shutdown.

use std::collections::HashMap;
use std::io;
use std::net::{Shutdown as SocketShutdown, SocketAddr, TcpListener, TcpStream};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::error::Error;
use crate::stats::Stats;

pub(crate) const ACCEPT_POLL: Duration = Duration::from_millis(20);
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

/// Разделяемый учёт активных соединений и их сокетов.
pub(crate) struct ConnectionSet {
    next_id: AtomicU64,
    streams: Arc<Mutex<HashMap<u64, TcpStream>>>,
    stats: Arc<Stats>,
}

impl ConnectionSet {
    pub(crate) fn new(stats: Arc<Stats>) -> Self {
        Self {
            next_id: AtomicU64::new(1),
            streams: Arc::new(Mutex::new(HashMap::new())),
            stats,
        }
    }

    pub(crate) fn active(&self) -> u64 {
        self.stats.active()
    }

    fn admit(&self, stream: &TcpStream, max_connections: usize) -> Option<ConnectionGuard> {
        if !self.stats.try_open(max_connections) {
            return None;
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        if let Ok(clone) = stream.try_clone() {
            self.streams
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(id, clone);
        }
        Some(ConnectionGuard {
            id,
            streams: Arc::clone(&self.streams),
            stats: Arc::clone(&self.stats),
        })
    }

    /// Закрывает все активные сокеты, чтобы разблокировать их потоки.
    pub(crate) fn close_all(&self) {
        let streams: Vec<TcpStream> = {
            let streams = self.streams.lock().unwrap_or_else(PoisonError::into_inner);
            streams
                .values()
                .filter_map(|stream| stream.try_clone().ok())
                .collect()
        };
        for stream in streams {
            let _ = stream.shutdown(SocketShutdown::Both);
        }
    }

    /// Ждёт завершения активных соединений до дедлайна.
    pub(crate) fn wait_closed(&self, timeout: Duration) {
        let deadline = Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(Instant::now);
        while self.active() > 0 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
    }
}

/// RAII-учёт соединения: при уничтожении убирает сокет и уменьшает счётчик.
pub(crate) struct ConnectionGuard {
    id: u64,
    streams: Arc<Mutex<HashMap<u64, TcpStream>>>,
    stats: Arc<Stats>,
}

impl ConnectionGuard {
    pub(crate) fn id(&self) -> u64 {
        self.id
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.id);
        self.stats.connection_closed();
    }
}

/// Создаёт nonblocking listener и поток accept loop.
pub(crate) fn spawn_acceptor(
    name: String,
    listener: TcpListener,
    shutdown: Arc<AtomicBool>,
    stats: Arc<Stats>,
    connections: Arc<ConnectionSet>,
    max_connections: usize,
    on_connection: Arc<dyn Fn(TcpStream, SocketAddr, ConnectionGuard) + Send + Sync>,
) -> Result<JoinHandle<()>, Error> {
    listener.set_nonblocking(true)?;
    thread::Builder::new()
        .name(name)
        .spawn(move || {
            accept_loop(
                &listener,
                &shutdown,
                &stats,
                &connections,
                max_connections,
                on_connection.as_ref(),
            );
        })
        .map_err(Error::Io)
}

fn accept_loop(
    listener: &TcpListener,
    shutdown: &AtomicBool,
    stats: &Stats,
    connections: &ConnectionSet,
    max_connections: usize,
    on_connection: &(dyn Fn(TcpStream, SocketAddr, ConnectionGuard) + Send + Sync),
) {
    while !shutdown.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, peer)) => {
                let Some(guard) = connections.admit(&stream, max_connections) else {
                    let _ = stream.shutdown(SocketShutdown::Both);
                    continue;
                };
                if catch_unwind(AssertUnwindSafe(|| on_connection(stream, peer, guard))).is_err() {
                    stats.error();
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_POLL);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => {
                stats.error();
                thread::sleep(ACCEPT_ERROR_BACKOFF);
            }
        }
    }
}

/// Останавливает accept loop, закрывает соединения и ждёт их завершения.
pub(crate) fn stop(
    shutdown: &AtomicBool,
    acceptor: &mut Option<JoinHandle<()>>,
    connections: &ConnectionSet,
    shutdown_timeout: Duration,
) -> Result<(), Error> {
    shutdown.store(true, Ordering::Release);
    if let Some(handle) = acceptor.take() {
        handle.join().map_err(|_| Error::ThreadPanicked)?;
    }
    connections.close_all();
    connections.wait_closed(shutdown_timeout);
    Ok(())
}
