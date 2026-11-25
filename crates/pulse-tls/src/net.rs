//! Общий неблокирующий TCP event-loop для DNS-транспортов.
//!
//! Модуль скрывает за синхронным RAII-API один tokio multi-thread runtime:
//!
//! * listener обслуживается одним accept-loop без потока на соединение;
//! * каждое соединение — отдельная задача (`tokio::task`), а не OS-поток;
//! * число одновременных соединений ограничено семафором;
//! * keep-alive, idle/request-таймауты и graceful shutdown задаются
//!   вызывающим транспортом;
//! * отклонённые соединения и ошибки `accept()` учитываются хуками, чтобы
//!   каждый сервер писал их в свои [`crate::Stats`].
//!
//! Runtime общий для процесса: DoT, DoH/1.1, plain TCP DNS в `pulsed` и
//! `pulseresolved` не создают по набору worker-потоков на сервер. Потоки
//! runtime именуются `pulse-net-*` и живут до конца процесса.
//!
//! [`TcpServer`] не навязывает протокол: вызывающий получает
//! [`tokio::net::TcpStream`] и [`tokio::sync::watch::Receiver`] для остановки.
//!
//! # Пример
//!
//! ```no_run
//! use std::sync::Arc;
//! use std::time::Duration;
//! use pulse_tls::net::{ServerHooks, TcpServer};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
//! let mut server = TcpServer::start(
//!     "example-tcp",
//!     listener,
//!     128,
//!     Duration::from_secs(5),
//!     ServerHooks::default(),
//!     Arc::new(|mut stream, _peer, mut shutdown| {
//!         Box::pin(async move {
//!             let mut buffer = [0_u8; 512];
//!             loop {
//!                 tokio::select! {
//!                     _ = shutdown.changed() => break,
//!                     read = tokio::io::AsyncReadExt::read(&mut stream, &mut buffer) => {
//!                         if read.unwrap_or(0) == 0 {
//!                             break;
//!                         }
//!                     }
//!                 }
//!             }
//!         })
//!     }),
//! )?;
//! println!("listening on {}", server.local_addr());
//! server.shutdown()?;
//! # Ok(())
//! # }
//! ```

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;

const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);
const ABORT_GRACE: Duration = Duration::from_millis(100);

/// Будущее одного соединения. Соединение закрывается, когда future
/// завершается или когда runtime отменяет задачу при shutdown.
pub type ConnectionFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// Обработчик нового соединения.
///
/// `stream` уже в nonblocking-режиме; `shutdown` становится `true`, когда
/// сервер останавливается.
pub type ConnectionHandler =
    Arc<dyn Fn(TcpStream, SocketAddr, watch::Receiver<bool>) -> ConnectionFuture + Send + Sync>;

/// Колбэки учёта отказов.
#[derive(Clone, Default)]
pub struct ServerHooks {
    /// Вызывается, когда соединение отклонено из-за лимита или ACL.
    pub on_reject: Option<Arc<dyn Fn() + Send + Sync>>,
    /// Вызывается при ошибке `accept()` или панике задачи соединения.
    pub on_error: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl ServerHooks {
    /// Создаёт хуки из двух замыканий.
    #[must_use]
    pub fn new(
        on_reject: Option<Arc<dyn Fn() + Send + Sync>>,
        on_error: Option<Arc<dyn Fn() + Send + Sync>>,
    ) -> Self {
        Self {
            on_reject,
            on_error,
        }
    }

    fn reject(&self) {
        if let Some(callback) = &self.on_reject {
            callback();
        }
    }

    fn error(&self) {
        if let Some(callback) = &self.on_error {
            callback();
        }
    }
}

/// Запущенный TCP event-loop.
///
/// `shutdown` закрывает listener, будит задачи соединений через watch-канал и
/// ждёт их завершения не дольше `shutdown_timeout`. Задачи, не завершившиеся
/// за это время, отменяются.
pub struct TcpServer {
    name: String,
    local_addr: SocketAddr,
    shutdown: watch::Sender<bool>,
    stopped: Arc<AtomicBool>,
    done: Option<std::sync::mpsc::Receiver<()>>,
    shutdown_timeout: Duration,
}

impl std::fmt::Debug for TcpServer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TcpServer")
            .field("name", &self.name)
            .field("local_addr", &self.local_addr)
            .field("shutdown_timeout", &self.shutdown_timeout)
            .finish_non_exhaustive()
    }
}

impl TcpServer {
    /// Запускает accept-loop на общем runtime.
    ///
    /// Listener переводится в nonblocking. `max_connections` ограничивает
    /// число одновременных задач; лишние соединения закрываются сразу и
    /// учитываются через [`ServerHooks::on_reject`].
    ///
    /// # Errors
    ///
    /// Ошибка настройки listener, инициализации runtime или создания
    /// служебного канала.
    pub fn start(
        name: &str,
        listener: std::net::TcpListener,
        max_connections: usize,
        shutdown_timeout: Duration,
        hooks: ServerHooks,
        handler: ConnectionHandler,
    ) -> io::Result<Self> {
        listener.set_nonblocking(true)?;
        let local_addr = listener.local_addr()?;
        let runtime = shared_runtime()?;
        let (shutdown, shutdown_rx) = watch::channel(false);
        let stopped = Arc::new(AtomicBool::new(false));
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        runtime.handle().spawn(async move {
            run_accept_loop(
                listener,
                max_connections,
                shutdown_timeout,
                hooks,
                handler,
                shutdown_rx,
                done_tx,
            )
            .await;
        });
        Ok(Self {
            name: name.to_owned(),
            local_addr,
            shutdown,
            stopped,
            done: Some(done_rx),
            shutdown_timeout,
        })
    }

    /// Фактический адрес listener'а.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Признак того, что [`TcpServer::shutdown`] уже вызывался.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }

    /// Останавливает сервер и ждёт завершения соединений.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::TimedOut`], если соединения не завершились за
    /// `shutdown_timeout`.
    pub fn shutdown(&mut self) -> io::Result<()> {
        self.stopped.store(true, Ordering::Release);
        let _ = self.shutdown.send(true);
        let Some(done) = self.done.take() else {
            return Ok(());
        };
        match done.recv_timeout(self.shutdown_timeout) {
            Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Ok(()),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "TCP connections did not close before the shutdown deadline",
            )),
        }
    }
}

impl Drop for TcpServer {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

async fn run_accept_loop(
    listener: std::net::TcpListener,
    max_connections: usize,
    shutdown_timeout: Duration,
    hooks: ServerHooks,
    handler: ConnectionHandler,
    mut shutdown: watch::Receiver<bool>,
    done: std::sync::mpsc::Sender<()>,
) {
    let listener = match TcpListener::from_std(listener) {
        Ok(listener) => listener,
        Err(_) => {
            hooks.error();
            let _ = done.send(());
            return;
        }
    };
    let permits = Arc::new(Semaphore::new(max_connections));
    let mut connections: JoinSet<()> = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            joined = connections.join_next(), if !connections.is_empty() => {
                if joined.is_some_and(|result| result.is_err()) {
                    hooks.error();
                }
            }
            accepted = listener.accept() => {
                let Ok((stream, peer)) = accepted else {
                    hooks.error();
                    tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                    continue;
                };
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                    hooks.reject();
                    drop(stream);
                    continue;
                };
                let handler = Arc::clone(&handler);
                let connection_shutdown = shutdown.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    handler(stream, peer, connection_shutdown).await;
                });
            }
        }
    }
    drop(listener);
    let deadline = tokio::time::Instant::now() + shutdown_timeout;
    loop {
        if connections.is_empty() {
            break;
        }
        match tokio::time::timeout_at(deadline, connections.join_next()).await {
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(_) => {
                connections.abort_all();
                let _ = tokio::time::timeout(ABORT_GRACE, async {
                    while connections.join_next().await.is_some() {}
                })
                .await;
                break;
            }
        }
    }
    let _ = done.send(());
}

static RUNTIME: OnceLock<Result<Arc<Runtime>, String>> = OnceLock::new();

/// Общий runtime для всех неблокирующих DNS-транспортов процесса.
///
/// # Errors
///
/// Ошибка создания tokio runtime (нехватка ресурсов).
pub(crate) fn shared_runtime() -> io::Result<Arc<Runtime>> {
    let entry = RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("pulse-net")
            .build()
            .map(Arc::new)
            .map_err(|error| error.to_string())
    });
    match entry {
        Ok(runtime) => Ok(Arc::clone(runtime)),
        Err(message) => Err(io::Error::other(message.clone())),
    }
}

/// Пул переиспользуемых буферов фиксированного размера.
///
/// На idle-соединении буфер не удерживается: транспорт берёт его только на
/// время чтения кадра и возвращает после обработки. Ёмкость пула ограничена,
/// поэтому пиковая память не растёт вместе с числом соединений.
///
/// Пул потокобезопасен и может разделяться между соединениями и серверами.
pub struct BufferPool {
    chunk: usize,
    limit: usize,
    free: Mutex<Vec<Vec<u8>>>,
    allocated: AtomicUsize,
}

impl BufferPool {
    /// Создаёт пул с `limit` буферами по `chunk` байт.
    ///
    /// Буферы выделяются лениво; `limit` ограничивает число одновременно
    /// удерживаемых пулом буферов.
    #[must_use]
    pub fn new(chunk: usize, limit: usize) -> Self {
        Self {
            chunk,
            limit,
            free: Mutex::new(Vec::new()),
            allocated: AtomicUsize::new(0),
        }
    }

    /// Берёт буфер из пула или выделяет новый.
    #[must_use]
    pub fn acquire(self: &Arc<Self>) -> PooledBuffer {
        let buffer = self
            .free
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop();
        match buffer {
            Some(mut buffer) => {
                buffer.clear();
                buffer.resize(self.chunk, 0);
                PooledBuffer {
                    buffer: Some(buffer),
                    pool: Arc::clone(self),
                }
            }
            None => {
                self.allocated.fetch_add(1, Ordering::Relaxed);
                PooledBuffer {
                    buffer: Some(vec![0_u8; self.chunk]),
                    pool: Arc::clone(self),
                }
            }
        }
    }
}

/// Буфер из [`BufferPool`]; при уничтожении возвращается в пул, если его
/// ёмкость не превышает исходный chunk.
pub struct PooledBuffer {
    buffer: Option<Vec<u8>>,
    pool: Arc<BufferPool>,
}

impl PooledBuffer {
    /// Гарантирует, что буфер содержит ровно `len` байт, и возвращает срез.
    pub fn prepare(&mut self, len: usize) -> &mut [u8] {
        if let Some(buffer) = &mut self.buffer {
            buffer.resize(len, 0);
            buffer.as_mut_slice()
        } else {
            &mut []
        }
    }

    /// Обрезает буфер до `len` и извлекает его из пула.
    #[must_use]
    pub fn take_vec(mut self, len: usize) -> Vec<u8> {
        if let Some(buffer) = &mut self.buffer {
            buffer.truncate(len);
        }
        self.buffer.take().unwrap_or_default()
    }
}

impl Deref for PooledBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.buffer.as_deref().unwrap_or_default()
    }
}

impl DerefMut for PooledBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.buffer.as_deref_mut().unwrap_or_default()
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        let Some(mut buffer) = self.buffer.take() else {
            return;
        };
        if buffer.capacity() > self.pool.chunk {
            return;
        }
        buffer.clear();
        let mut free = self
            .pool
            .free
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if free.len() < self.pool.limit {
            free.push(buffer);
        } else {
            self.pool.allocated.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// Освобождает память, удерживаемую буфером соединения, до `max` байт.
pub(crate) fn shrink(buffer: &mut Vec<u8>, max: usize) {
    if buffer.capacity() > max {
        let length = buffer.len().min(max);
        buffer.truncate(length);
        buffer.shrink_to(max);
    }
}
