//! Атомарные счётчики транспорта и резолвера.

use std::sync::atomic::{AtomicU64, Ordering};

/// Счётчики процесса без блокировок на горячем пути.
#[derive(Debug, Default)]
pub struct Stats {
    udp_queries: AtomicU64,
    tcp_queries: AtomicU64,
    udp_responses: AtomicU64,
    tcp_responses: AtomicU64,
    decode_errors: AtomicU64,
    encode_errors: AtomicU64,
    formerr: AtomicU64,
    refused: AtomicU64,
    truncated: AtomicU64,
    dropped: AtomicU64,
    tcp_active: AtomicU64,
    tcp_connections: AtomicU64,
    tcp_rejected: AtomicU64,
    tcp_io_errors: AtomicU64,
    reloads: AtomicU64,
    reload_failures: AtomicU64,
}

/// Снимок счётчиков процесса.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StatsSnapshot {
    /// UDP-запросы.
    pub udp_queries: u64,
    /// TCP-запросы.
    pub tcp_queries: u64,
    /// UDP-ответы.
    pub udp_responses: u64,
    /// TCP-ответы.
    pub tcp_responses: u64,
    /// Ошибки декодирования запроса.
    pub decode_errors: u64,
    /// Ошибки кодирования ответа.
    pub encode_errors: u64,
    /// Ответы FORMERR.
    pub formerr: u64,
    /// Ответы REFUSED.
    pub refused: u64,
    /// Усечённые (TC) ответы.
    pub truncated: u64,
    /// Отброшенные запросы (QR=1, мусор без заголовка).
    pub dropped: u64,
    /// Активные TCP-соединения.
    pub tcp_active: u64,
    /// Всего принятых TCP-соединений.
    pub tcp_connections: u64,
    /// Отклонённые TCP-соединения (лимит).
    pub tcp_rejected: u64,
    /// Ошибки ввода-вывода TCP.
    pub tcp_io_errors: u64,
    /// Успешные перезагрузки blocklist.
    pub reloads: u64,
    /// Неудачные перезагрузки blocklist.
    pub reload_failures: u64,
}

impl Stats {
    /// Создаёт нулевые счётчики.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Снимок.
    #[must_use]
    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            udp_queries: self.udp_queries.load(Ordering::Relaxed),
            tcp_queries: self.tcp_queries.load(Ordering::Relaxed),
            udp_responses: self.udp_responses.load(Ordering::Relaxed),
            tcp_responses: self.tcp_responses.load(Ordering::Relaxed),
            decode_errors: self.decode_errors.load(Ordering::Relaxed),
            encode_errors: self.encode_errors.load(Ordering::Relaxed),
            formerr: self.formerr.load(Ordering::Relaxed),
            refused: self.refused.load(Ordering::Relaxed),
            truncated: self.truncated.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            tcp_active: self.tcp_active.load(Ordering::Relaxed),
            tcp_connections: self.tcp_connections.load(Ordering::Relaxed),
            tcp_rejected: self.tcp_rejected.load(Ordering::Relaxed),
            tcp_io_errors: self.tcp_io_errors.load(Ordering::Relaxed),
            reloads: self.reloads.load(Ordering::Relaxed),
            reload_failures: self.reload_failures.load(Ordering::Relaxed),
        }
    }

    pub(crate) fn udp_query(&self) {
        self.udp_queries.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn tcp_query(&self) {
        self.tcp_queries.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn udp_response(&self) {
        self.udp_responses.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn tcp_response(&self) {
        self.tcp_responses.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn decode_error(&self) {
        self.decode_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn encode_error(&self) {
        self.encode_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn formerr(&self) {
        self.formerr.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn refused(&self) {
        self.refused.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn truncated(&self) {
        self.truncated.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn dropped(&self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn tcp_opened(&self) {
        self.tcp_connections.fetch_add(1, Ordering::Relaxed);
        self.tcp_active.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn tcp_closed(&self) {
        self.tcp_active.fetch_sub(1, Ordering::Relaxed);
    }

    pub(crate) fn tcp_active(&self) -> u64 {
        self.tcp_active.load(Ordering::Relaxed)
    }

    pub(crate) fn tcp_rejected(&self) {
        self.tcp_rejected.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn tcp_io_error(&self) {
        self.tcp_io_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn reload_ok(&self) {
        self.reloads.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn reload_failed(&self) {
        self.reload_failures.fetch_add(1, Ordering::Relaxed);
    }
}
