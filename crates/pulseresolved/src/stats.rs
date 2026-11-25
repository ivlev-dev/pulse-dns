//! Атомарные счётчики транспорта и резолвера.

use std::sync::atomic::{AtomicU64, Ordering};

use pulse_dns::Rcode;

/// Счётчики процесса без блокировок на горячем пути.
#[derive(Debug, Default)]
pub struct Stats {
    udp_queries: AtomicU64,
    tcp_queries: AtomicU64,
    udp_responses: AtomicU64,
    tcp_responses: AtomicU64,
    dot_queries: AtomicU64,
    dot_responses: AtomicU64,
    doh_queries: AtomicU64,
    doh_responses: AtomicU64,
    doh_http2_queries: AtomicU64,
    doh_http2_responses: AtomicU64,
    doq_queries: AtomicU64,
    doq_responses: AtomicU64,
    dnscrypt_udp_queries: AtomicU64,
    dnscrypt_udp_responses: AtomicU64,
    dnscrypt_udp_errors: AtomicU64,
    dnscrypt_tcp_queries: AtomicU64,
    dnscrypt_tcp_responses: AtomicU64,
    dnscrypt_tcp_errors: AtomicU64,
    dnscrypt_tcp_active: AtomicU64,
    dnscrypt_tcp_connections: AtomicU64,
    dnscrypt_tcp_rejected: AtomicU64,
    tls_reloads: AtomicU64,
    tls_reload_failures: AtomicU64,
    decode_errors: AtomicU64,
    encode_errors: AtomicU64,
    formerr: AtomicU64,
    refused: AtomicU64,
    refused_acl: AtomicU64,
    rate_limited: AtomicU64,
    rate_limit_dropped: AtomicU64,
    rate_limit_refused: AtomicU64,
    rate_limit_truncated: AtomicU64,
    truncated: AtomicU64,
    dropped: AtomicU64,
    fast_path: AtomicU64,
    full_decode: AtomicU64,
    zero_alloc_responses: AtomicU64,
    rcodes: [AtomicU64; 16],
    rcode_extended: AtomicU64,
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
    /// DoT-запросы.
    pub dot_queries: u64,
    /// DoT-ответы.
    pub dot_responses: u64,
    /// DoH/1.1-запросы.
    pub doh_queries: u64,
    /// DoH/1.1-ответы.
    pub doh_responses: u64,
    /// DoH/2-запросы.
    pub doh_http2_queries: u64,
    /// DoH/2-ответы.
    pub doh_http2_responses: u64,
    /// DoQ-запросы.
    pub doq_queries: u64,
    /// DoQ-ответы.
    pub doq_responses: u64,
    /// DNSCrypt UDP-запросы.
    pub dnscrypt_udp_queries: u64,
    /// DNSCrypt UDP-ответы.
    pub dnscrypt_udp_responses: u64,
    /// Ошибки разбора/аутентификации DNSCrypt UDP.
    pub dnscrypt_udp_errors: u64,
    /// DNSCrypt TCP-запросы.
    pub dnscrypt_tcp_queries: u64,
    /// DNSCrypt TCP-ответы.
    pub dnscrypt_tcp_responses: u64,
    /// Ошибки DNSCrypt TCP.
    pub dnscrypt_tcp_errors: u64,
    /// Активные DNSCrypt TCP-соединения.
    pub dnscrypt_tcp_active: u64,
    /// Всего принятых DNSCrypt TCP-соединений.
    pub dnscrypt_tcp_connections: u64,
    /// Отклонённые DNSCrypt TCP-соединения (лимит).
    pub dnscrypt_tcp_rejected: u64,
    /// Успешные перезагрузки TLS-сертификата.
    pub tls_reloads: u64,
    /// Неудачные перезагрузки TLS-сертификата.
    pub tls_reload_failures: u64,
    /// Ошибки декодирования запроса.
    pub decode_errors: u64,
    /// Ошибки кодирования ответа.
    pub encode_errors: u64,
    /// Ответы FORMERR.
    pub formerr: u64,
    /// Ответы REFUSED.
    pub refused: u64,
    /// REFUSED из-за ACL клиентов.
    pub refused_acl: u64,
    /// Запросы, отклонённые rate limit.
    pub rate_limited: u64,
    /// Rate limit: отброшено без ответа.
    pub rate_limit_dropped: u64,
    /// Rate limit: REFUSED.
    pub rate_limit_refused: u64,
    /// Rate limit: пустой TC-ответ.
    pub rate_limit_truncated: u64,
    /// Усечённые (TC) ответы.
    pub truncated: u64,
    /// Отброшенные запросы (QR=1, мусор без заголовка).
    pub dropped: u64,
    /// Запросы, разобранные zero-copy путём (`MessageRef`).
    pub fast_path: u64,
    /// Запросы, потребовавшие полного `Message::decode`.
    pub full_decode: u64,
    /// Ответы, отданные без аллокаций (cache hit wire path).
    pub zero_alloc_responses: u64,
    /// Счётчики по младшим 4 битам RCODE (индекс — значение).
    pub rcodes: [u64; 16],
    /// RCODE с расширенными битами EDNS (>= 16).
    pub rcode_extended: u64,
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
            dot_queries: self.dot_queries.load(Ordering::Relaxed),
            dot_responses: self.dot_responses.load(Ordering::Relaxed),
            doh_queries: self.doh_queries.load(Ordering::Relaxed),
            doh_responses: self.doh_responses.load(Ordering::Relaxed),
            doh_http2_queries: self.doh_http2_queries.load(Ordering::Relaxed),
            doh_http2_responses: self.doh_http2_responses.load(Ordering::Relaxed),
            doq_queries: self.doq_queries.load(Ordering::Relaxed),
            doq_responses: self.doq_responses.load(Ordering::Relaxed),
            dnscrypt_udp_queries: self.dnscrypt_udp_queries.load(Ordering::Relaxed),
            dnscrypt_udp_responses: self.dnscrypt_udp_responses.load(Ordering::Relaxed),
            dnscrypt_udp_errors: self.dnscrypt_udp_errors.load(Ordering::Relaxed),
            dnscrypt_tcp_queries: self.dnscrypt_tcp_queries.load(Ordering::Relaxed),
            dnscrypt_tcp_responses: self.dnscrypt_tcp_responses.load(Ordering::Relaxed),
            dnscrypt_tcp_errors: self.dnscrypt_tcp_errors.load(Ordering::Relaxed),
            dnscrypt_tcp_active: self.dnscrypt_tcp_active.load(Ordering::Relaxed),
            dnscrypt_tcp_connections: self.dnscrypt_tcp_connections.load(Ordering::Relaxed),
            dnscrypt_tcp_rejected: self.dnscrypt_tcp_rejected.load(Ordering::Relaxed),
            tls_reloads: self.tls_reloads.load(Ordering::Relaxed),
            tls_reload_failures: self.tls_reload_failures.load(Ordering::Relaxed),
            decode_errors: self.decode_errors.load(Ordering::Relaxed),
            encode_errors: self.encode_errors.load(Ordering::Relaxed),
            formerr: self.formerr.load(Ordering::Relaxed),
            refused: self.refused.load(Ordering::Relaxed),
            refused_acl: self.refused_acl.load(Ordering::Relaxed),
            rate_limited: self.rate_limited.load(Ordering::Relaxed),
            rate_limit_dropped: self.rate_limit_dropped.load(Ordering::Relaxed),
            rate_limit_refused: self.rate_limit_refused.load(Ordering::Relaxed),
            rate_limit_truncated: self.rate_limit_truncated.load(Ordering::Relaxed),
            truncated: self.truncated.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            fast_path: self.fast_path.load(Ordering::Relaxed),
            full_decode: self.full_decode.load(Ordering::Relaxed),
            zero_alloc_responses: self.zero_alloc_responses.load(Ordering::Relaxed),
            rcodes: std::array::from_fn(|index| {
                self.rcodes
                    .get(index)
                    .map_or(0, |counter| counter.load(Ordering::Relaxed))
            }),
            rcode_extended: self.rcode_extended.load(Ordering::Relaxed),
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

    pub(crate) fn dot_query(&self) {
        self.dot_queries.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn dot_response(&self) {
        self.dot_responses.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn doh_query(&self) {
        self.doh_queries.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn doh_response(&self) {
        self.doh_responses.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn doh_http2_query(&self) {
        self.doh_http2_queries.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn doh_http2_response(&self) {
        self.doh_http2_responses.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn doq_query(&self) {
        self.doq_queries.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn doq_response(&self) {
        self.doq_responses.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn dnscrypt_udp_query(&self) {
        self.dnscrypt_udp_queries.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn dnscrypt_udp_response(&self) {
        self.dnscrypt_udp_responses.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn dnscrypt_udp_error(&self) {
        self.dnscrypt_udp_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn dnscrypt_tcp_query(&self) {
        self.dnscrypt_tcp_queries.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn dnscrypt_tcp_response(&self) {
        self.dnscrypt_tcp_responses.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn dnscrypt_tcp_error(&self) {
        self.dnscrypt_tcp_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn dnscrypt_tcp_opened(&self) {
        self.dnscrypt_tcp_connections
            .fetch_add(1, Ordering::Relaxed);
        self.dnscrypt_tcp_active.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn dnscrypt_tcp_closed(&self) {
        self.dnscrypt_tcp_active.fetch_sub(1, Ordering::Relaxed);
    }

    pub(crate) fn dnscrypt_tcp_active(&self) -> u64 {
        self.dnscrypt_tcp_active.load(Ordering::Relaxed)
    }

    pub(crate) fn dnscrypt_tcp_rejected(&self) {
        self.dnscrypt_tcp_rejected.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn tls_reload_ok(&self) {
        self.tls_reloads.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn tls_reload_failed(&self) {
        self.tls_reload_failures.fetch_add(1, Ordering::Relaxed);
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

    pub(crate) fn refused_acl(&self) {
        self.refused_acl.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn rate_limited(&self) {
        self.rate_limited.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn rate_limit_dropped(&self) {
        self.rate_limit_dropped.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn rate_limit_refused(&self) {
        self.rate_limit_refused.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn rate_limit_truncated(&self) {
        self.rate_limit_truncated.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn truncated(&self) {
        self.truncated.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn dropped(&self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn fast_path(&self) {
        self.fast_path.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn full_decode(&self) {
        self.full_decode.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn zero_alloc_response(&self) {
        self.zero_alloc_responses.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn rcode(&self, rcode: Rcode) {
        let value = usize::from(rcode.as_u16());
        if let Some(counter) = self.rcodes.get(value) {
            counter.fetch_add(1, Ordering::Relaxed);
        } else {
            self.rcode_extended.fetch_add(1, Ordering::Relaxed);
        }
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
