//! Публичный фасад: [`Runtime`], [`UdpServer`], потоки и graceful shutdown.

use std::mem;
use std::net::SocketAddr;
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use rustix::event::{EventfdFlags, eventfd};

use crate::backend::probe;
use crate::config::{BackendKind, BackendPreference, Capabilities, RuntimeConfig};
use crate::error::RuntimeError;
use crate::handler::Handler;
use crate::socket;
use crate::stats::{ServerStats, WorkerCounters};

type WorkerOutcome = Result<(), RuntimeError>;

/// Разделяемое состояние рантайма.
struct RuntimeInner {
    cfg: RuntimeConfig,
    caps: Capabilities,
    shutdown: AtomicBool,
    hub: Arc<SignalHub>,
    servers: Mutex<Vec<Arc<ServerCore>>>,
}

/// Общий сигнал отказа: worker, завершившийся с ошибкой, будит всех остальных
/// (включая воркеров других серверов того же `Runtime`), чтобы `run()` не
/// завис на join'е живого соседа.
struct SignalHub {
    abort: Arc<AtomicBool>,
    wakes: Mutex<Vec<Arc<OwnedFd>>>,
}

impl Default for SignalHub {
    fn default() -> Self {
        Self {
            abort: Arc::new(AtomicBool::new(false)),
            wakes: Mutex::new(Vec::new()),
        }
    }
}

impl SignalHub {
    fn flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.abort)
    }

    fn register(&self, wake: Arc<OwnedFd>) {
        self.wakes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(wake);
    }

    fn abort(&self) {
        self.abort.store(true, Ordering::Release);
        self.wake_all();
    }

    fn wake_all(&self) {
        let wakes = self.wakes.lock().unwrap_or_else(PoisonError::into_inner);
        let counter = 1_u64.to_ne_bytes();
        for wake in wakes.iter() {
            let _ = rustix::io::write(wake.as_ref(), &counter);
        }
    }
}

/// Фабрика UDP-серверов с общим числом worker-потоков.
///
/// Один [`Runtime`] может обслуживать несколько [`UdpServer`] — каждый на своём
/// адресе; worker'ы создаются на сервер, а `shutdown()` останавливает все.
///
/// ```
/// use pulse_runtime::{BackendPreference, Runtime, RuntimeConfig};
///
/// let runtime = Runtime::new(
///     RuntimeConfig::default()
///         .with_workers(1)
///         .with_backend(BackendPreference::Auto),
/// )
/// .expect("io_uring must be available");
/// assert!(matches!(runtime.capabilities().backend, pulse_runtime::BackendKind::IoUring { .. }));
/// ```
pub struct Runtime {
    inner: Arc<RuntimeInner>,
}

impl Runtime {
    /// Создать рантайм и проверить доступность выбранного бэкенда.
    ///
    /// При `BackendPreference::Auto` и недоступном io_uring:
    /// - с feature `epoll-fallback` — переключение на epoll;
    /// - без неё — [`RuntimeError::IoUringUnavailable`] с подсказкой.
    ///
    /// # Errors
    ///
    /// [`RuntimeError::Config`] при некорректной конфигурации,
    /// [`RuntimeError::IoUringUnavailable`] / [`RuntimeError::EpollUnsupported`]
    /// при недоступном бэкенде.
    pub fn new(cfg: RuntimeConfig) -> Result<Self, RuntimeError> {
        crate::panic_hook::install();
        cfg.validate().map_err(RuntimeError::Config)?;
        let caps = resolve_capabilities(&cfg)?;
        Ok(Self {
            inner: Arc::new(RuntimeInner {
                cfg,
                caps,
                shutdown: AtomicBool::new(false),
                hub: Arc::new(SignalHub::default()),
                servers: Mutex::new(Vec::new()),
            }),
        })
    }

    /// Возможности выбранного бэкенда.
    #[must_use]
    pub fn capabilities(&self) -> Capabilities {
        self.inner.caps
    }

    /// Конфигурация рантайма.
    #[must_use]
    pub fn config(&self) -> &RuntimeConfig {
        &self.inner.cfg
    }

    /// Привязать UDP-сервер к адресу.
    ///
    /// Создаёт по сокету на worker (`SO_REUSEPORT`); при `port = 0` порт
    /// выбирается первым сокетом и переиспользуется остальными.
    ///
    /// # Errors
    ///
    /// [`RuntimeError::Socket`] при ошибке `socket`/`bind`, [`RuntimeError::Wake`]
    /// при невозможности создать `eventfd`, [`RuntimeError::Shutdown`] если
    /// рантайм уже остановлен.
    pub fn udp_bind(
        &self,
        addr: SocketAddr,
        handler: impl Handler,
    ) -> Result<UdpServer, RuntimeError> {
        if self.inner.shutdown.load(Ordering::Acquire) {
            return Err(RuntimeError::Shutdown);
        }
        let cfg = &self.inner.cfg;
        let workers = cfg.resolved_workers();
        let first = socket::bind_udp(addr, cfg.socket_recv_buffer, cfg.socket_send_buffer)
            .map_err(|source| RuntimeError::Socket { addr, source })?;
        let local_addr =
            socket::local_addr(&first).map_err(|source| RuntimeError::Socket { addr, source })?;

        let mut sockets = Vec::with_capacity(workers);
        sockets.push(Some(first));
        for _ in 1..workers {
            let fd = socket::bind_udp(local_addr, cfg.socket_recv_buffer, cfg.socket_send_buffer)
                .map_err(|source| RuntimeError::Socket {
                addr: local_addr,
                source,
            })?;
            sockets.push(Some(fd));
        }

        let mut counters = Vec::with_capacity(workers);
        let mut wake = Vec::with_capacity(workers);
        for _ in 0..workers {
            counters.push(Arc::new(WorkerCounters::default()));
            let fd =
                eventfd(0, EventfdFlags::CLOEXEC | EventfdFlags::NONBLOCK).map_err(|source| {
                    RuntimeError::Wake {
                        source: std::io::Error::from_raw_os_error(source.raw_os_error()),
                    }
                })?;
            let fd = Arc::new(fd);
            self.inner.hub.register(Arc::clone(&fd));
            wake.push(fd);
        }

        let core = Arc::new(ServerCore {
            local_addr,
            handler: Arc::new(handler),
            sockets: Mutex::new(sockets),
            wake: Arc::new(wake),
            counters,
            workers,
            threads: Mutex::new(ThreadState::Idle),
            started: AtomicBool::new(false),
            stop: Arc::new(AtomicBool::new(false)),
            hub: Arc::clone(&self.inner.hub),
            shutdown_timeout: self.inner.cfg.shutdown_timeout,
            fail_start: AtomicBool::new(false),
        });
        self.inner
            .servers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Arc::clone(&core));
        Ok(UdpServer {
            runtime: Arc::clone(&self.inner),
            core,
        })
    }

    /// Запустить все привязанные серверы и блокироваться до их остановки.
    ///
    /// # Errors
    ///
    /// [`RuntimeError::Config`] без привязанных серверов; ошибка worker'а
    /// (например, `io_uring_setup`) пробрасывается после остановки остальных.
    pub fn run(&self) -> Result<(), RuntimeError> {
        let servers: Vec<Arc<ServerCore>> = self
            .inner
            .servers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if servers.is_empty() {
            return Err(RuntimeError::Config(
                "no UDP servers bound to this runtime".into(),
            ));
        }
        for server in &servers {
            if let Err(err) = server.start(&self.inner) {
                // Частичный старт: остановить уже запущенных и не оставлять
                // потоки висеть после ошибки.
                let _ = self.shutdown();
                return Err(err);
            }
        }
        let mut first_error = None;
        for server in &servers {
            if let Err(err) = server.join() {
                first_error.get_or_insert(err);
                // Один упавший worker не должен оставлять живыми остальные.
                let _ = self.shutdown();
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    /// Остановить все серверы и дождаться завершения worker'ов.
    ///
    /// # Errors
    ///
    /// Ошибка отмены операций или паника worker'а.
    pub fn shutdown(&self) -> Result<(), RuntimeError> {
        let servers: Vec<Arc<ServerCore>> = self
            .inner
            .servers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        self.inner.shutdown.store(true, Ordering::Release);
        self.inner.hub.abort();
        let mut first_error = None;
        for server in &servers {
            if let Err(err) = server.shutdown() {
                first_error.get_or_insert(err);
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

impl Drop for RuntimeInner {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        self.hub.abort();
    }
}

/// UDP-сервер: `SO_REUSEPORT`-сокет на worker и собственный `io_uring`.
pub struct UdpServer {
    runtime: Arc<RuntimeInner>,
    core: Arc<ServerCore>,
}

impl UdpServer {
    /// Привязать сервер к адресу с `workers` worker-потоками (конфиг по умолчанию).
    ///
    /// # Errors
    ///
    /// См. [`Runtime::udp_bind`].
    pub fn bind(
        addr: SocketAddr,
        handler: impl Handler,
        workers: usize,
    ) -> Result<Self, RuntimeError> {
        let cfg = RuntimeConfig::default().with_workers(workers);
        Self::bind_with(addr, handler, cfg)
    }

    /// Привязать сервер с явной конфигурацией.
    ///
    /// # Errors
    ///
    /// См. [`Runtime::new`] и [`Runtime::udp_bind`].
    pub fn bind_with(
        addr: SocketAddr,
        handler: impl Handler,
        cfg: RuntimeConfig,
    ) -> Result<Self, RuntimeError> {
        let runtime = Runtime::new(cfg)?;
        runtime.udp_bind(addr, handler)
    }

    /// Локальный адрес (с реальным портом, если запрашивали `0`).
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.core.local_addr
    }

    /// Число worker-потоков.
    #[must_use]
    pub fn workers(&self) -> usize {
        self.core.workers
    }

    /// Возможности бэкенда.
    #[must_use]
    pub fn capabilities(&self) -> Capabilities {
        self.runtime.caps
    }

    /// Запустить worker'ы. Идемпотентно.
    ///
    /// # Errors
    ///
    /// [`RuntimeError::Config`] если сокет worker'а потерян, ошибка создания
    /// потока или `eventfd`.
    pub fn start(&self) -> Result<(), RuntimeError> {
        self.core.start(&self.runtime)
    }

    /// Запустить worker'ы и блокироваться до остановки.
    ///
    /// # Errors
    ///
    /// См. [`UdpServer::start`] и [`UdpServer::wait`].
    pub fn run(&self) -> Result<(), RuntimeError> {
        self.start()?;
        self.core.join()
    }

    /// Дождаться завершения worker'ов (после [`start`](Self::start)).
    ///
    /// # Errors
    ///
    /// [`RuntimeError::NotStarted`] до запуска; ошибка/паника worker'а.
    pub fn wait(&self) -> Result<(), RuntimeError> {
        if !self.core.started.load(Ordering::Acquire) {
            return Err(RuntimeError::NotStarted);
        }
        self.core.join()
    }

    /// Попросить worker'ы завершиться и дождаться их.
    ///
    /// Если сервер ещё не запускался, вызов просто помечает его остановленным.
    ///
    /// # Errors
    ///
    /// Ошибка отмены операций или паника worker'а.
    pub fn shutdown(&self) -> Result<(), RuntimeError> {
        self.core.shutdown()
    }

    /// Снимок счётчиков.
    #[must_use]
    pub fn stats(&self) -> ServerStats {
        ServerStats::from_workers(&self.core.counters)
    }

    /// Тестовый хук: следующий `start()` завершится ошибкой (частичный старт).
    #[doc(hidden)]
    pub fn force_start_failure(&self) {
        self.core.fail_start.store(true, Ordering::Release);
    }

    /// Бэкенд, которым реально работает сервер.
    #[must_use]
    pub fn backend(&self) -> BackendKind {
        self.runtime.caps.backend
    }
}

impl Drop for UdpServer {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

struct ServerCore {
    local_addr: SocketAddr,
    handler: Arc<dyn Handler>,
    sockets: Mutex<Vec<Option<OwnedFd>>>,
    wake: Arc<Vec<Arc<OwnedFd>>>,
    counters: Vec<Arc<WorkerCounters>>,
    workers: usize,
    threads: Mutex<ThreadState>,
    started: AtomicBool,
    stop: Arc<AtomicBool>,
    hub: Arc<SignalHub>,
    shutdown_timeout: Duration,
    /// Только для теста частичного старта (`force_start_failure`).
    fail_start: AtomicBool,
}

enum ThreadState {
    Idle,
    Running {
        handles: Vec<JoinHandle<()>>,
        results: mpsc::Receiver<(usize, WorkerOutcome)>,
    },
    Joining,
    Joined,
}

impl ServerCore {
    fn start(self: &Arc<Self>, runtime: &RuntimeInner) -> Result<(), RuntimeError> {
        let mut state = self.threads.lock().unwrap_or_else(PoisonError::into_inner);
        match &*state {
            ThreadState::Idle => {}
            ThreadState::Running { .. } | ThreadState::Joining | ThreadState::Joined => {
                return Ok(());
            }
        }
        if self.fail_start.load(Ordering::Acquire) {
            *state = ThreadState::Joined;
            return Err(RuntimeError::Config(
                "forced start failure (test hook)".into(),
            ));
        }

        let caps = runtime.caps;
        let cfg = Arc::new(runtime.cfg.clone());
        let stop = Arc::clone(&self.stop);
        let abort = self.hub.flag();
        let hub = Arc::clone(&self.hub);
        let allowed = socket::allowed_cpus();
        let (sender, results) = mpsc::channel();

        let mut handles = Vec::with_capacity(self.workers);
        for index in 0..self.workers {
            let socket = {
                let mut sockets = self.sockets.lock().unwrap_or_else(PoisonError::into_inner);
                sockets
                    .get_mut(index)
                    .and_then(Option::take)
                    .ok_or_else(|| {
                        RuntimeError::Config(format!("socket for worker {index} is missing"))
                    })?
            };
            let handler = Arc::clone(&self.handler);
            let counters = Arc::clone(&self.counters[index]);
            let wake = Arc::clone(&self.wake[index]);
            let cpu = if allowed.is_empty() {
                index
            } else {
                allowed[index % allowed.len()]
            };
            let stop = Arc::clone(&stop);
            let abort = Arc::clone(&abort);
            let hub = Arc::clone(&hub);
            let cfg = Arc::clone(&cfg);
            let sender = sender.clone();
            let result = thread::Builder::new()
                .name(format!("pulse-udp-{index}"))
                .spawn(move || {
                    if cfg.pin_to_cpu {
                        let _ = socket::pin_current_thread(cpu);
                    }
                    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        run_worker(
                            index,
                            socket,
                            &cfg,
                            handler,
                            counters,
                            Arc::clone(&stop),
                            Arc::clone(&abort),
                            wake,
                            caps,
                        )
                    }))
                    .unwrap_or(Err(RuntimeError::WorkerPanicked { worker: index }));
                    if outcome.is_err() {
                        // Будим и останавливаем всех: иначе run()/join зависнет
                        // на живых соседях.
                        stop.store(true, Ordering::Release);
                        hub.abort();
                    }
                    let _ = sender.send((index, outcome));
                });
            match result {
                Ok(handle) => handles.push(handle),
                Err(source) => {
                    drop(state);
                    self.stop.store(true, Ordering::Release);
                    self.hub.abort();
                    for handle in handles {
                        let _ = handle.join();
                    }
                    return Err(RuntimeError::SocketIo { source });
                }
            }
        }
        drop(sender);

        *state = ThreadState::Running { handles, results };
        self.started.store(true, Ordering::Release);
        Ok(())
    }

    fn signal_stop(&self) {
        self.stop.store(true, Ordering::Release);
        let counter = 1_u64.to_ne_bytes();
        for wake in self.wake.iter() {
            let _ = rustix::io::write(wake.as_ref(), &counter);
        }
    }

    fn shutdown(&self) -> Result<(), RuntimeError> {
        self.signal_stop();
        self.join()
    }

    fn join(&self) -> Result<(), RuntimeError> {
        let (handles, results) = {
            let mut state = self.threads.lock().unwrap_or_else(PoisonError::into_inner);
            match mem::replace(&mut *state, ThreadState::Joining) {
                ThreadState::Running { handles, results } => (handles, results),
                other => {
                    *state = other;
                    return Ok(());
                }
            }
        };

        // Дедлайн: graceful shutdown worker'а плюс запас на планировщик.
        let deadline = Instant::now() + self.shutdown_timeout + Duration::from_secs(2);
        let mut first_error = None;
        let mut timed_out = false;
        for _ in 0..self.workers {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match results.recv_timeout(remaining) {
                Ok((_, Ok(()))) => {}
                Ok((index, Err(source))) => {
                    first_error.get_or_insert(RuntimeError::Worker {
                        worker: index,
                        source: Box::new(source),
                    });
                }
                Err(_) => {
                    timed_out = true;
                    break;
                }
            }
        }

        if timed_out {
            // Не блокируемся в join бесконечно: будим всех и отсоединяем
            // handles, возвращая ошибку.
            self.stop.store(true, Ordering::Release);
            self.hub.abort();
            drop(handles);
            let mut state = self.threads.lock().unwrap_or_else(PoisonError::into_inner);
            *state = ThreadState::Joined;
            return Err(RuntimeError::WorkerTimeout);
        }

        for (index, handle) in handles.into_iter().enumerate() {
            if handle.join().is_err() {
                first_error.get_or_insert(RuntimeError::WorkerPanicked { worker: index });
            }
        }

        let mut state = self.threads.lock().unwrap_or_else(PoisonError::into_inner);
        *state = ThreadState::Joined;
        first_error.map_or(Ok(()), Err)
    }
}

#[allow(clippy::too_many_arguments)]
fn run_worker(
    _index: usize,
    socket: OwnedFd,
    cfg: &Arc<RuntimeConfig>,
    handler: Arc<dyn Handler>,
    counters: Arc<WorkerCounters>,
    stop: Arc<AtomicBool>,
    abort: Arc<AtomicBool>,
    wake: Arc<OwnedFd>,
    caps: Capabilities,
) -> WorkerOutcome {
    match caps.backend {
        BackendKind::IoUring { .. } => {
            let wake_owned = duplicate_eventfd(&wake)?;
            crate::backend::uring::UringWorker::new(
                socket,
                Arc::clone(cfg),
                handler,
                counters,
                stop,
                abort,
                wake_owned,
            )?
            .run()
        }
        BackendKind::Epoll => {
            #[cfg(feature = "epoll-fallback")]
            {
                crate::backend::epoll::run_worker(
                    socket,
                    Arc::clone(cfg),
                    handler,
                    counters,
                    stop,
                    abort,
                    wake,
                )
            }
            #[cfg(not(feature = "epoll-fallback"))]
            {
                let _ = (socket, handler, counters, stop, abort, wake);
                Err(RuntimeError::EpollUnsupported)
            }
        }
    }
}

/// Ядро не даёт «переслать» fd, поэтому worker получает свою копию `eventfd`.
fn duplicate_eventfd(wake: &OwnedFd) -> Result<OwnedFd, RuntimeError> {
    // F_DUPFD_CLOEXEC: копия не должна утекать в exec-потомков.
    rustix::io::fcntl_dupfd_cloexec(wake, 0).map_err(|source| RuntimeError::Wake {
        source: std::io::Error::from_raw_os_error(source.raw_os_error()),
    })
}

fn resolve_capabilities(cfg: &RuntimeConfig) -> Result<Capabilities, RuntimeError> {
    match cfg.backend {
        BackendPreference::Uring => probe::probe(cfg),
        BackendPreference::Epoll => epoll_capabilities(),
        BackendPreference::Auto => match probe::probe(cfg) {
            Ok(caps) => Ok(caps),
            Err(uring_error) => match epoll_capabilities() {
                Ok(caps) => {
                    // Фолбэк разрешён, но не молчаливый: фактический бэкенд
                    // также виден в `capabilities()`.
                    eprintln!(
                        "pulse-runtime: warning: io_uring unavailable ({uring_error}); \
                         falling back to epoll backend"
                    );
                    Ok(caps)
                }
                Err(_) => Err(uring_error),
            },
        },
    }
}

// Возвращает `Err` только в сборке без feature, поэтому `Result` нужен ради
// единой сигнатуры в `resolve_capabilities`.
#[allow(clippy::unnecessary_wraps)]
fn epoll_capabilities() -> Result<Capabilities, RuntimeError> {
    #[cfg(feature = "epoll-fallback")]
    {
        Ok(Capabilities {
            backend: BackendKind::Epoll,
            multishot_recv: false,
            provided_buffers: false,
            defer_taskrun: false,
            sqpoll: false,
            nodrop: false,
        })
    }
    #[cfg(not(feature = "epoll-fallback"))]
    {
        Err(RuntimeError::EpollUnsupported)
    }
}
