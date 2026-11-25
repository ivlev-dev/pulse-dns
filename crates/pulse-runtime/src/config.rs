//! Конфигурация рантайма и дескрипторы возможностей бэкенда.

use std::fmt;
use std::num::NonZeroU16;
use std::time::Duration;

use crate::mem::HugePages;

/// Приёмный режим UDP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RxMode {
    /// Автоматически: multishot + provided buffers, при отказе — батч одиночных `recvmsg`.
    #[default]
    Auto,
    /// Только `IORING_OP_RECVMSG` с `RECV_MULTISHOT` и ring'ом provided buffers.
    Multishot,
    /// Только батч одиночных `IORING_OP_RECVMSG` (L1-совместимый режим).
    RecvBatch,
}

/// Предпочтение бэкенда.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BackendPreference {
    /// io_uring, при недоступности — переход на epoll, если включена feature
    /// `epoll-fallback` (с предупреждением в `stderr`); иначе — ошибка
    /// [`RuntimeError::IoUringUnavailable`](crate::RuntimeError::IoUringUnavailable).
    #[default]
    Auto,
    /// Требовать io_uring.
    Uring,
    /// Требовать epoll-бэкенд (feature `epoll-fallback`).
    Epoll,
}

/// Реализованный бэкенд и его возможности.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    /// io_uring; `level` — L1 (`setup`), L2 (multishot + provided buffers), L3 (+ L3-флаги).
    IoUring {
        /// Уровень возможностей 1..=3 (см. spec §4.2).
        level: u8,
    },
    /// epoll + `recvmmsg`/`sendmmsg`.
    Epoll,
}

impl fmt::Display for BackendKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IoUring { level } => write!(f, "io_uring (L{level})"),
            Self::Epoll => f.write_str("epoll"),
        }
    }
}

/// Возможности выбранного бэкенда (spec §12.1 `Caps`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct Capabilities {
    /// Бэкенд и уровень.
    pub backend: BackendKind,
    /// Доступен multishot `recvmsg`.
    pub multishot_recv: bool,
    /// Доступны provided buffers (`IORING_REGISTER_PBUF_RING`).
    pub provided_buffers: bool,
    /// Приняты `IORING_SETUP_SINGLE_ISSUER | DEFER_TASKRUN`.
    pub defer_taskrun: bool,
    /// Принят `IORING_SETUP_COOP_TASKRUN` (не будить задачу из kernel task_work).
    pub coop_taskrun: bool,
    /// Принят `IORING_SETUP_SQPOLL` (фактически, а не запрошен).
    pub sqpoll: bool,
    /// Сокет и `eventfd` зарегистрированы (`IORING_REGISTER_FILES`).
    pub registered_files: bool,
    /// Ядро поддерживает `IORING_FEAT_NODROP` (переполнение CQ не теряет CQE).
    pub nodrop: bool,
}

/// Настройки `Runtime`.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct RuntimeConfig {
    /// Число worker-потоков (ring-per-worker). `0` — по числу доступных ядер.
    pub workers: usize,
    /// Предпочтение бэкенда.
    pub backend: BackendPreference,
    /// Размер SQ (степень двойки, ≥ 8).
    pub sq_entries: u32,
    /// Размер CQ (степень двойки, ≥ `sq_entries`).
    pub cq_entries: u32,
    /// Ёмкость полезной нагрузки одного RX-буфера (без заголовка `recvmsg`).
    pub rx_buffer_size: usize,
    /// Число RX-буферов (степень двойки, ≤ 32768) на worker.
    pub rx_buffers: u16,
    /// Число TX-слотов на worker.
    pub tx_slots: usize,
    /// Максимальный размер ответа (TX-слот).
    pub tx_slot_size: usize,
    /// Запрошенный `SO_RCVBUF`, байт.
    pub socket_recv_buffer: usize,
    /// Запрошенный `SO_SNDBUF`, байт.
    pub socket_send_buffer: usize,
    /// Глубина батча приёма для L1-режима и максимум CQE за проход.
    pub batch_size: usize,
    /// Максимум CQE, разбираемых за один проход без возврата в `submit`.
    pub cqe_batch: usize,
    /// Размер стека worker-потока, байт (`0` — размер по умолчанию ОС/`std`).
    pub thread_stack_size: usize,
    /// Прибить worker'ов к ядрам (`sched_setaffinity`); ошибки игнорируются.
    pub pin_to_cpu: bool,
    /// Явный список CPU для worker'ов (`sched_getaffinity`/cpuset учитываются);
    /// пусто — все разрешённые процессу CPU.
    ///
    /// Непустой список включает пиннинг worker'ов даже при `pin_to_cpu = false`;
    /// затем CPU раздаются по кругу (`allowed[index % len]`).
    pub cpu_affinity: Vec<usize>,
    /// Политика transparent huge pages для RX-арены (provided buffers).
    pub huge_pages: HugePages,
    /// Включить `IORING_SETUP_SQPOLL` с указанным idle-таймаутом.
    ///
    /// При отсутствии прав ядро вернёт ошибку; рантайм продолжит без SQPOLL
    /// (`Capabilities::sqpoll = false`).
    pub sqpoll_idle: Option<u32>,
    /// CPU для kernel-потока SQPOLL (`IORING_SETUP_SQ_AFF`); `None` — выбрать
    /// автоматически из разрешённых CPU.
    pub sqpoll_cpu: Option<usize>,
    /// `SO_BUSY_POLL`, микросекунды (`None`/`0` — выключено).
    pub busy_poll_us: Option<u16>,
    /// `SO_PREFER_BUSY_POLL` (обычно требует `CAP_NET_ADMIN`; ошибки игнорируются).
    pub prefer_busy_poll: bool,
    /// `SO_BUSY_POLL_BUDGET` — бюджет NAPI-опроса.
    pub busy_poll_budget: Option<u16>,
    /// Регистрировать сокет и `eventfd` в ring (`IORING_REGISTER_FILES`).
    pub register_files: bool,
    /// Пытаться включить `IORING_SETUP_COOP_TASKRUN` (опция, мягкая деградация).
    ///
    /// По умолчанию выключен: на современных ядрах с `DEFER_TASKRUN` выигрыш
    /// не измерен, а поведение доставки CQE меняется.
    pub coop_taskrun: bool,
    /// Режим приёма.
    pub rx_mode: RxMode,
    /// Таймаут graceful shutdown на worker, после которого операция отменяется.
    pub shutdown_timeout: Duration,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            workers: 0,
            backend: BackendPreference::Auto,
            sq_entries: 1024,
            cq_entries: 4096,
            rx_buffer_size: 2048,
            rx_buffers: 1024,
            tx_slots: 256,
            tx_slot_size: 4096,
            socket_recv_buffer: 4 * 1024 * 1024,
            socket_send_buffer: 4 * 1024 * 1024,
            batch_size: 64,
            cqe_batch: 256,
            thread_stack_size: 512 * 1024,
            pin_to_cpu: false,
            cpu_affinity: Vec::new(),
            huge_pages: HugePages::Auto,
            sqpoll_idle: None,
            sqpoll_cpu: None,
            busy_poll_us: None,
            prefer_busy_poll: false,
            busy_poll_budget: None,
            register_files: true,
            coop_taskrun: false,
            rx_mode: RxMode::Auto,
            shutdown_timeout: Duration::from_secs(2),
        }
    }
}

impl RuntimeConfig {
    /// Задать число worker-потоков.
    #[must_use]
    pub fn with_workers(mut self, workers: usize) -> Self {
        self.workers = workers;
        self
    }

    /// Задать предпочтение бэкенда.
    #[must_use]
    pub fn with_backend(mut self, backend: BackendPreference) -> Self {
        self.backend = backend;
        self
    }

    /// Задать режим приёма.
    #[must_use]
    pub fn with_rx_mode(mut self, mode: RxMode) -> Self {
        self.rx_mode = mode;
        self
    }

    /// Задать ёмкость полезной нагрузки RX-буфера.
    #[must_use]
    pub fn with_rx_buffer_size(mut self, size: usize) -> Self {
        self.rx_buffer_size = size;
        self
    }

    /// Задать число RX-буферов (степень двойки).
    #[must_use]
    pub fn with_rx_buffers(mut self, count: NonZeroU16) -> Self {
        self.rx_buffers = count.get();
        self
    }

    /// Задать число и размер TX-слотов.
    #[must_use]
    pub fn with_tx(mut self, slots: usize, slot_size: usize) -> Self {
        self.tx_slots = slots;
        self.tx_slot_size = slot_size;
        self
    }

    /// Задать размеры сокетных буферов.
    #[must_use]
    pub fn with_socket_buffers(mut self, recv: usize, send: usize) -> Self {
        self.socket_recv_buffer = recv;
        self.socket_send_buffer = send;
        self
    }

    /// Задать максимум CQE за проход.
    #[must_use]
    pub fn with_cqe_batch(mut self, batch: usize) -> Self {
        self.cqe_batch = batch;
        self
    }

    /// Задать размер стека worker-потока (`0` — по умолчанию ОС).
    #[must_use]
    pub fn with_thread_stack(mut self, bytes: usize) -> Self {
        self.thread_stack_size = bytes;
        self
    }

    /// Включить/выключить привязку к ядрам.
    #[must_use]
    pub fn with_cpu_pinning(mut self, pin: bool) -> Self {
        self.pin_to_cpu = pin;
        self
    }

    /// Ограничить worker'ов указанными CPU (в пересечении с `sched_getaffinity`).
    #[must_use]
    pub fn with_cpu_affinity(mut self, cpus: Vec<usize>) -> Self {
        self.cpu_affinity = cpus;
        self
    }

    /// Задать политику huge pages для RX-арены.
    #[must_use]
    pub const fn with_huge_pages(mut self, policy: HugePages) -> Self {
        self.huge_pages = policy;
        self
    }

    /// Включить SQPOLL с указанным idle-таймаутом.
    #[must_use]
    pub fn with_sqpoll(mut self, idle_ms: Option<u32>) -> Self {
        self.sqpoll_idle = idle_ms;
        self
    }

    /// Задать CPU для SQPOLL-потока (`None` — авто).
    #[must_use]
    pub fn with_sqpoll_cpu(mut self, cpu: Option<usize>) -> Self {
        self.sqpoll_cpu = cpu;
        self
    }

    /// Включить `SO_BUSY_POLL` на указанное число микросекунд (`0` — выключить).
    #[must_use]
    pub fn with_busy_poll(mut self, microseconds: u16) -> Self {
        self.busy_poll_us = (microseconds > 0).then_some(microseconds);
        self
    }

    /// Включить/выключить `SO_PREFER_BUSY_POLL`.
    #[must_use]
    pub fn with_prefer_busy_poll(mut self, prefer: bool) -> Self {
        self.prefer_busy_poll = prefer;
        self
    }

    /// Задать `SO_BUSY_POLL_BUDGET`.
    #[must_use]
    pub fn with_busy_poll_budget(mut self, budget: u16) -> Self {
        self.busy_poll_budget = (budget > 0).then_some(budget);
        self
    }

    /// Включить/выключить `IORING_REGISTER_FILES` для сокета и `eventfd`.
    #[must_use]
    pub fn with_register_files(mut self, register: bool) -> Self {
        self.register_files = register;
        self
    }

    /// Включить/выключить попытку `IORING_SETUP_COOP_TASKRUN`.
    #[must_use]
    pub fn with_coop_taskrun(mut self, coop: bool) -> Self {
        self.coop_taskrun = coop;
        self
    }

    /// Задать таймаут graceful shutdown.
    #[must_use]
    pub fn with_shutdown_timeout(mut self, timeout: Duration) -> Self {
        self.shutdown_timeout = timeout;
        self
    }

    /// Проверить корректность конфигурации.
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.sq_entries < 8 || !self.sq_entries.is_power_of_two() {
            return Err("sq_entries must be a power of two >= 8".into());
        }
        if self.cq_entries < self.sq_entries || !self.cq_entries.is_power_of_two() {
            return Err("cq_entries must be a power of two >= sq_entries".into());
        }
        if self.rx_buffer_size < 512 {
            return Err("rx_buffer_size must be >= 512".into());
        }
        if self.rx_buffers < 16 || !self.rx_buffers.is_power_of_two() {
            return Err("rx_buffers must be a power of two >= 16".into());
        }
        if self.tx_slots < 8 || self.tx_slots > usize::from(u16::MAX) {
            return Err("tx_slots must be in 8..=65535".into());
        }
        if self.tx_slot_size < 512 {
            return Err("tx_slot_size must be >= 512".into());
        }
        if self.batch_size == 0 || self.batch_size > usize::from(u16::MAX) {
            return Err("batch_size must be in 1..=65535".into());
        }
        if self.batch_size > self.sq_entries as usize {
            return Err("batch_size must not exceed sq_entries".into());
        }
        if self.cqe_batch == 0 || self.cqe_batch > self.cq_entries as usize {
            return Err("cqe_batch must be in 1..=cq_entries".into());
        }
        // 0 — оставить размер стека по умолчанию; иначе нужен запас на
        // обработчик и код io_uring (меньше 64 КиБ небезопасно).
        if self.thread_stack_size != 0 && self.thread_stack_size < 64 * 1024 {
            return Err("thread_stack_size must be 0 or >= 64 KiB".into());
        }
        if self.shutdown_timeout.is_zero() {
            return Err("shutdown_timeout must be > 0".into());
        }
        // Один цикл может завершить до rx_buffers recv, tx_slots send и
        // служебные CQE (wake/cancel); CQ обязан это вмещать, иначе NODROP
        // превратится в скрытую потерю событий.
        let needed = usize::from(self.rx_buffers) + self.tx_slots + 2;
        if needed > self.cq_entries as usize {
            return Err(format!(
                "cq_entries ({}) must be >= rx_buffers + tx_slots + 2 ({needed})",
                self.cq_entries
            ));
        }
        Ok(())
    }

    /// Число worker'ов с учётом `workers = 0`.
    pub(crate) fn resolved_workers(&self) -> usize {
        if self.workers == 0 {
            std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
        } else {
            self.workers
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        RuntimeConfig::default().validate().unwrap();
    }

    #[test]
    fn rejects_bad_shapes() {
        let bad = [
            RuntimeConfig::default()
                .with_workers(1)
                .with_rx_buffer_size(128),
            RuntimeConfig {
                sq_entries: 100,
                ..RuntimeConfig::default()
            },
            RuntimeConfig {
                cq_entries: 8,
                ..RuntimeConfig::default()
            },
            RuntimeConfig {
                rx_buffers: 24,
                ..RuntimeConfig::default()
            },
            RuntimeConfig {
                tx_slots: 4,
                ..RuntimeConfig::default()
            },
            RuntimeConfig {
                batch_size: 0,
                ..RuntimeConfig::default()
            },
            RuntimeConfig {
                shutdown_timeout: Duration::ZERO,
                ..RuntimeConfig::default()
            },
            // rx_buffers + tx_slots + 2 > cq_entries
            RuntimeConfig {
                cq_entries: 1024,
                ..RuntimeConfig::default()
            },
            RuntimeConfig {
                cqe_batch: 0,
                ..RuntimeConfig::default()
            },
            RuntimeConfig {
                cqe_batch: 8192,
                ..RuntimeConfig::default()
            },
            RuntimeConfig {
                thread_stack_size: 32 * 1024,
                ..RuntimeConfig::default()
            },
        ];
        for config in bad {
            assert!(config.validate().is_err(), "config must be rejected");
        }
    }

    #[test]
    fn tuning_builders_apply() {
        let cfg = RuntimeConfig::default()
            .with_cqe_batch(512)
            .with_thread_stack(256 * 1024)
            .with_cpu_affinity(vec![0, 2])
            .with_sqpoll(Some(1000))
            .with_sqpoll_cpu(Some(2))
            .with_busy_poll(50)
            .with_prefer_busy_poll(true)
            .with_busy_poll_budget(64)
            .with_register_files(false)
            .with_coop_taskrun(false);
        assert_eq!(cfg.cqe_batch, 512);
        assert_eq!(cfg.thread_stack_size, 256 * 1024);
        assert_eq!(cfg.cpu_affinity, vec![0, 2]);
        assert_eq!(cfg.huge_pages, HugePages::Auto);
        assert_eq!(
            cfg.clone().with_huge_pages(HugePages::Never).huge_pages,
            HugePages::Never
        );
        assert_eq!(cfg.sqpoll_idle, Some(1000));
        assert_eq!(cfg.sqpoll_cpu, Some(2));
        assert_eq!(cfg.busy_poll_us, Some(50));
        assert!(cfg.prefer_busy_poll);
        assert_eq!(cfg.busy_poll_budget, Some(64));
        assert!(!cfg.register_files);
        assert!(!cfg.coop_taskrun);
        assert!(cfg.validate().is_ok());
        // 0 выключает busy-poll/budget.
        let cfg = cfg.with_busy_poll(0).with_busy_poll_budget(0);
        assert_eq!(cfg.busy_poll_us, None);
        assert_eq!(cfg.busy_poll_budget, None);
    }

    #[test]
    fn zero_stack_size_keeps_os_default() {
        let cfg = RuntimeConfig::default().with_thread_stack(0);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn resolves_zero_workers_to_parallelism() {
        let cfg = RuntimeConfig::default().with_workers(0);
        assert!(cfg.resolved_workers() >= 1);
        let cfg = RuntimeConfig::default().with_workers(3);
        assert_eq!(cfg.resolved_workers(), 3);
    }
}
