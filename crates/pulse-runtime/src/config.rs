//! Конфигурация рантайма и дескрипторы возможностей бэкенда.

use std::fmt;
use std::num::NonZeroU16;
use std::time::Duration;

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
    /// Приняты флаги `SINGLE_ISSUER | DEFER_TASKRUN`.
    pub defer_taskrun: bool,
    /// Принят `IORING_SETUP_SQPOLL`.
    pub sqpoll: bool,
    /// Ядро поддерживает `IORING_FEAT_NODROP` (переполнение CQ не теряет CQE).
    pub nodrop: bool,
}

/// Настройки `Runtime`.
#[derive(Debug, Clone)]
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
    /// Прибить worker'ов к ядрам (`sched_setaffinity`); ошибки игнорируются.
    pub pin_to_cpu: bool,
    /// Включить `IORING_SETUP_SQPOLL` с указанным idle-таймаутом (нужны привилегии).
    pub sqpoll_idle: Option<u32>,
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
            tx_slots: 512,
            tx_slot_size: 4096,
            socket_recv_buffer: 4 * 1024 * 1024,
            socket_send_buffer: 4 * 1024 * 1024,
            batch_size: 64,
            pin_to_cpu: false,
            sqpoll_idle: None,
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

    /// Включить/выключить привязку к ядрам.
    #[must_use]
    pub fn with_cpu_pinning(mut self, pin: bool) -> Self {
        self.pin_to_cpu = pin;
        self
    }

    /// Включить SQPOLL с указанным idle-таймаутом.
    #[must_use]
    pub fn with_sqpoll(mut self, idle_ms: Option<u32>) -> Self {
        self.sqpoll_idle = idle_ms;
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
        ];
        for config in bad {
            assert!(config.validate().is_err(), "config must be rejected");
        }
    }

    #[test]
    fn resolves_zero_workers_to_parallelism() {
        let cfg = RuntimeConfig::default().with_workers(0);
        assert!(cfg.resolved_workers() >= 1);
        let cfg = RuntimeConfig::default().with_workers(3);
        assert_eq!(cfg.resolved_workers(), 3);
    }
}
