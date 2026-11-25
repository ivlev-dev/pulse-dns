//! Счётчики worker'ов и агрегированная статистика сервера.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Снимок счётчиков одного worker'а.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WorkerStats {
    /// Принято датаграмм (включая усечённые).
    pub packets_received: u64,
    /// Принято байт полезной нагрузки.
    pub bytes_received: u64,
    /// Отправлено датаграмм.
    pub packets_sent: u64,
    /// Отправлено байт полезной нагрузки.
    pub bytes_sent: u64,
    /// Ошибки приёма (кроме усечения и `-ENOBUFS`).
    pub recv_errors: u64,
    /// Ошибки отправки.
    pub send_errors: u64,
    /// Датаграммы больше RX-буфера: приняты, но не переданы обработчику.
    pub oversize_received: u64,
    /// Ответы, отброшенные обработчиком или из-за нехватки TX-слотов.
    pub responses_dropped: u64,
    /// События backpressure (буферы удержаны из-за нехватки TX-слотов).
    pub tx_pressure: u64,
    /// `recvmsg` завершился `-ENOBUFS` (provided buffers исчерпаны).
    pub pbuf_starve: u64,
    /// Паники обработчика (изолированы).
    pub handler_panics: u64,
    /// CQE с неизвестной/устаревшей генерацией либо неизвестным тегом.
    pub stale_completions: u64,
    /// Переполнение completion queue (`cq.overflow() > 0`): события потеряны.
    pub cq_overflow_total: u64,
}

impl WorkerStats {
    fn add(&mut self, other: &Self) {
        self.packets_received += other.packets_received;
        self.bytes_received += other.bytes_received;
        self.packets_sent += other.packets_sent;
        self.bytes_sent += other.bytes_sent;
        self.recv_errors += other.recv_errors;
        self.send_errors += other.send_errors;
        self.oversize_received += other.oversize_received;
        self.responses_dropped += other.responses_dropped;
        self.tx_pressure += other.tx_pressure;
        self.pbuf_starve += other.pbuf_starve;
        self.handler_panics += other.handler_panics;
        self.stale_completions += other.stale_completions;
        self.cq_overflow_total += other.cq_overflow_total;
    }
}

/// Агрегированная статистика сервера.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServerStats {
    /// Снимок по каждому worker'у.
    pub per_worker: Vec<WorkerStats>,
    /// Сумма по всем worker'ам.
    pub total: WorkerStats,
}

impl ServerStats {
    pub(crate) fn from_workers(workers: &[Arc<WorkerCounters>]) -> Self {
        let per_worker: Vec<WorkerStats> =
            workers.iter().map(|counters| counters.snapshot()).collect();
        let mut total = WorkerStats::default();
        for stats in &per_worker {
            total.add(stats);
        }
        Self { per_worker, total }
    }
}

/// Выровнен, чтобы счётчики соседних worker'ов не попадали в одну cache line.
#[repr(align(128))]
#[derive(Debug, Default)]
pub(crate) struct WorkerCounters {
    packets_received: AtomicU64,
    bytes_received: AtomicU64,
    packets_sent: AtomicU64,
    bytes_sent: AtomicU64,
    recv_errors: AtomicU64,
    send_errors: AtomicU64,
    oversize_received: AtomicU64,
    responses_dropped: AtomicU64,
    tx_pressure: AtomicU64,
    pbuf_starve: AtomicU64,
    handler_panics: AtomicU64,
    stale_completions: AtomicU64,
    cq_overflow_total: AtomicU64,
}

macro_rules! counter {
    ($name:ident, $field:ident) => {
        #[inline]
        pub(crate) fn $name(&self) {
            self.$field.fetch_add(1, Ordering::Relaxed);
        }
    };
}

macro_rules! counter_add {
    ($name:ident, $field:ident) => {
        #[inline]
        pub(crate) fn $name(&self, value: u64) {
            self.$field.fetch_add(value, Ordering::Relaxed);
        }
    };
}

// Без epoll-фолбэка атомарные инкременты не нужны: io_uring публикует
// локальную дельту через `publish`; методы остаются для epoll-бэкенда.
#[cfg_attr(not(feature = "epoll-fallback"), allow(dead_code))]
impl WorkerCounters {
    pub(crate) fn snapshot(&self) -> WorkerStats {
        WorkerStats {
            packets_received: self.packets_received.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            recv_errors: self.recv_errors.load(Ordering::Relaxed),
            send_errors: self.send_errors.load(Ordering::Relaxed),
            oversize_received: self.oversize_received.load(Ordering::Relaxed),
            responses_dropped: self.responses_dropped.load(Ordering::Relaxed),
            tx_pressure: self.tx_pressure.load(Ordering::Relaxed),
            pbuf_starve: self.pbuf_starve.load(Ordering::Relaxed),
            handler_panics: self.handler_panics.load(Ordering::Relaxed),
            stale_completions: self.stale_completions.load(Ordering::Relaxed),
            cq_overflow_total: self.cq_overflow_total.load(Ordering::Relaxed),
        }
    }

    counter_add!(add_received, packets_received);
    counter_add!(add_bytes_received, bytes_received);
    counter_add!(add_sent, packets_sent);
    counter_add!(add_bytes_sent, bytes_sent);
    counter!(recv_error, recv_errors);
    counter!(send_error, send_errors);
    counter!(oversize, oversize_received);
    counter!(response_dropped, responses_dropped);
    counter!(handler_panic, handler_panics);

    /// Опубликовать локально накопленную дельту worker'а.
    ///
    /// Горячий путь io_uring пишет в `WorkerStats` без атомиков, а сюда
    /// приходит один раз за проход completion-loop.
    pub(crate) fn publish(&self, delta: &WorkerStats) {
        // Ошибки/дропы обычно нулевые: не трогаем их cache line зря.
        macro_rules! publish_field {
            ($field:ident) => {
                if delta.$field != 0 {
                    self.$field.fetch_add(delta.$field, Ordering::Relaxed);
                }
            };
        }
        publish_field!(packets_received);
        publish_field!(bytes_received);
        publish_field!(packets_sent);
        publish_field!(bytes_sent);
        publish_field!(recv_errors);
        publish_field!(send_errors);
        publish_field!(oversize_received);
        publish_field!(responses_dropped);
        publish_field!(tx_pressure);
        publish_field!(pbuf_starve);
        publish_field!(handler_panics);
        publish_field!(stale_completions);
        publish_field!(cq_overflow_total);
    }
}
