//! Атомарные счётчики сервера без блокировок на горячем пути.

use std::sync::atomic::{AtomicU64, Ordering};

/// Счётчики процесса.
///
/// Инкременты выполняются с `Relaxed`: они не участвуют в синхронизации
/// данных, важна только итоговая сумма. Снимок [`Stats::snapshot`] не
/// останавливает обработку запросов.
#[derive(Debug, Default)]
pub struct Stats {
    udp_queries: AtomicU64,
    tcp_queries: AtomicU64,
    responses: AtomicU64,
    decode_errors: AtomicU64,
    encode_errors: AtomicU64,
    dropped: AtomicU64,
    tcp_connections: AtomicU64,
    tcp_rejected: AtomicU64,
    tcp_active: AtomicU64,
    tcp_io_errors: AtomicU64,
    tcp_accept_errors: AtomicU64,
}

impl Stats {
    /// Создаёт обнулённые счётчики.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Согласованный по моментам чтения снимок.
    #[must_use]
    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            udp_queries: self.udp_queries.load(Ordering::Relaxed),
            tcp_queries: self.tcp_queries.load(Ordering::Relaxed),
            responses: self.responses.load(Ordering::Relaxed),
            decode_errors: self.decode_errors.load(Ordering::Relaxed),
            encode_errors: self.encode_errors.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            tcp_connections: self.tcp_connections.load(Ordering::Relaxed),
            tcp_rejected: self.tcp_rejected.load(Ordering::Relaxed),
            tcp_active: self.tcp_active.load(Ordering::Relaxed),
            tcp_io_errors: self.tcp_io_errors.load(Ordering::Relaxed),
            tcp_accept_errors: self.tcp_accept_errors.load(Ordering::Relaxed),
        }
    }

    pub(crate) fn udp_query(&self) {
        self.udp_queries.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn tcp_query(&self) {
        self.tcp_queries.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn response(&self) {
        self.responses.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn decode_error(&self) {
        self.decode_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn encode_error(&self) {
        self.encode_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn drop_response(&self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn tcp_connection_opened(&self) {
        self.tcp_connections.fetch_add(1, Ordering::Relaxed);
        self.tcp_active.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn tcp_connection_closed(&self) {
        let _ = self
            .tcp_active
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |active| {
                Some(active.saturating_sub(1))
            });
    }

    pub(crate) fn tcp_rejected(&self) {
        self.tcp_rejected.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn tcp_io_error(&self) {
        self.tcp_io_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn tcp_accept_error(&self) {
        self.tcp_accept_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn tcp_active(&self) -> u64 {
        self.tcp_active.load(Ordering::Relaxed)
    }
}

/// Снимок счётчиков.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StatsSnapshot {
    /// Разобранные UDP-запросы.
    pub udp_queries: u64,
    /// Разобранные TCP-запросы.
    pub tcp_queries: u64,
    /// Успешно закодированные ответы (UDP и TCP).
    pub responses: u64,
    /// Пакеты, которые не удалось декодировать.
    pub decode_errors: u64,
    /// Ошибки кодирования ответа.
    pub encode_errors: u64,
    /// Ответы, отброшенные из-за размера буфера.
    pub dropped: u64,
    /// Принятые TCP-соединения.
    pub tcp_connections: u64,
    /// TCP-соединения, отклонённые по лимиту.
    pub tcp_rejected: u64,
    /// Активные TCP-соединения на момент снимка.
    pub tcp_active: u64,
    /// Ошибки ввода-вывода TCP-соединений.
    pub tcp_io_errors: u64,
    /// Ошибки `accept()`.
    pub tcp_accept_errors: u64,
}

impl StatsSnapshot {
    /// Всего разобранных запросов.
    #[must_use]
    pub const fn queries(&self) -> u64 {
        self.udp_queries + self.tcp_queries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_are_monotonic() {
        let stats = Stats::new();
        stats.udp_query();
        stats.tcp_query();
        stats.response();
        stats.decode_error();
        stats.tcp_connection_opened();
        stats.tcp_connection_closed();
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.queries(), 2);
        assert_eq!(snapshot.responses, 1);
        assert_eq!(snapshot.decode_errors, 1);
        assert_eq!(snapshot.tcp_active, 0);
    }
}
