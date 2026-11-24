//! Атомарные счётчики DoT/DoH без блокировок на горячем пути.

use std::sync::atomic::{AtomicU64, Ordering};

/// Снимок статистики сервера.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StatsSnapshot {
    /// Всего принятых TCP-соединений.
    pub connections: u64,
    /// Соединений, отклонённых из-за лимита/ACL/rate limit.
    pub rejected_connections: u64,
    /// Активных соединений на момент снимка.
    pub active_connections: u64,
    /// Успешных TLS-рукопожатий.
    pub handshakes: u64,
    /// Неудачных TLS-рукопожатий.
    pub handshake_failures: u64,
    /// DNS-запросов, переданных обработчику.
    pub queries: u64,
    /// DNS-ответов, отправленных клиенту.
    pub responses: u64,
    /// HTTP-запросов (DoH), включая `/healthz` и ошибочные.
    pub http_requests: u64,
    /// HTTP-ответов со статусом 4xx/5xx.
    pub http_errors: u64,
    /// Запросов, отклонённых rate limiter.
    pub rate_limited: u64,
    /// Таймаутов рукопожатия и простоя.
    pub timeouts: u64,
    /// Прочих ошибок протокола/обработчика.
    pub errors: u64,
    /// Байт прикладных данных прочитано (DNS-сообщения и HTTP-тела).
    pub bytes_read: u64,
    /// Байт прикладных данных записано.
    pub bytes_written: u64,
}

/// Потокобезопасные счётчики сервера.
#[derive(Debug, Default)]
pub struct Stats {
    connections: AtomicU64,
    rejected_connections: AtomicU64,
    active_connections: AtomicU64,
    handshakes: AtomicU64,
    handshake_failures: AtomicU64,
    queries: AtomicU64,
    responses: AtomicU64,
    http_requests: AtomicU64,
    http_errors: AtomicU64,
    rate_limited: AtomicU64,
    timeouts: AtomicU64,
    errors: AtomicU64,
    bytes_read: AtomicU64,
    bytes_written: AtomicU64,
}

impl Stats {
    /// Создаёт обнулённые счётчики.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Возвращает согласованный-ish снимок счётчиков.
    #[must_use]
    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            connections: self.connections.load(Ordering::Relaxed),
            rejected_connections: self.rejected_connections.load(Ordering::Relaxed),
            active_connections: self.active_connections.load(Ordering::Relaxed),
            handshakes: self.handshakes.load(Ordering::Relaxed),
            handshake_failures: self.handshake_failures.load(Ordering::Relaxed),
            queries: self.queries.load(Ordering::Relaxed),
            responses: self.responses.load(Ordering::Relaxed),
            http_requests: self.http_requests.load(Ordering::Relaxed),
            http_errors: self.http_errors.load(Ordering::Relaxed),
            rate_limited: self.rate_limited.load(Ordering::Relaxed),
            timeouts: self.timeouts.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            bytes_read: self.bytes_read.load(Ordering::Relaxed),
            bytes_written: self.bytes_written.load(Ordering::Relaxed),
        }
    }

    pub(crate) fn try_open(&self, max_connections: usize) -> bool {
        let limit = u64::try_from(max_connections).unwrap_or(u64::MAX);
        let active = self.active_connections.fetch_add(1, Ordering::Relaxed) + 1;
        if active > limit {
            self.active_connections.fetch_sub(1, Ordering::Relaxed);
            self.rejected_connections.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        self.connections.fetch_add(1, Ordering::Relaxed);
        true
    }

    pub(crate) fn active(&self) -> u64 {
        self.active_connections.load(Ordering::Relaxed)
    }

    pub(crate) fn connection_rejected(&self) {
        self.rejected_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn connection_closed(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub(crate) fn handshake_ok(&self) {
        self.handshakes.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn handshake_failed(&self) {
        self.handshake_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn query(&self) {
        self.queries.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn response(&self) {
        self.responses.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn http_request(&self) {
        self.http_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn http_error(&self) {
        self.http_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn rate_limited(&self) {
        self.rate_limited.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn timeout(&self) {
        self.timeouts.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn read_bytes(&self, bytes: usize) {
        self.bytes_read
            .fetch_add(u64::try_from(bytes).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    pub(crate) fn written_bytes(&self, bytes: usize) {
        self.bytes_written
            .fetch_add(u64::try_from(bytes).unwrap_or(u64::MAX), Ordering::Relaxed);
    }
}
