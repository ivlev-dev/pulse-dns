//! Счётчики DoT/DoH/DNSCrypt для `GET /metrics`.
//!
//! DoT/DoH используют атомарные счётчики `pulse-tls`; DNSCrypt ведёт
//! собственные счётчики пакетов/ответов/ошибок в `pulsed`. Метрики
//! добавляются к выводу `pulse-api` и не логируются.

use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use pulse_tls::Stats;

/// Какие защищённые транспорты включены.
#[derive(Debug, Clone, Copy, Default)]
#[allow(clippy::struct_excessive_bools)] // независимые флаги транспортов
pub(crate) struct EnabledTransports {
    /// DoT.
    pub dot: bool,
    /// DoH/HTTP/1.1.
    pub doh: bool,
    /// DoH/HTTP/2.
    pub doh_h2: bool,
    /// DoH/HTTP/3.
    pub doh3: bool,
    /// DoQ.
    pub doq: bool,
    /// DNSCrypt UDP.
    pub dnscrypt: bool,
    /// DNSCrypt TCP.
    pub dnscrypt_tcp: bool,
}

/// Общие счётчики защищённых транспортов.
#[derive(Debug, Default)]
#[allow(clippy::struct_excessive_bools)] // независимые флаги транспортов
pub(crate) struct TransportMetrics {
    dot_enabled: bool,
    doh_enabled: bool,
    doh_h2_enabled: bool,
    doh3_enabled: bool,
    doq_enabled: bool,
    dnscrypt_enabled: bool,
    dnscrypt_tcp_enabled: bool,
    dot: Arc<Stats>,
    doh: Arc<Stats>,
    doh_h2: Arc<Stats>,
    doh3: Arc<Stats>,
    doq: Arc<Stats>,
    dnscrypt_packets: AtomicU64,
    dnscrypt_queries: AtomicU64,
    dnscrypt_responses: AtomicU64,
    dnscrypt_errors: AtomicU64,
    dnscrypt_dropped: AtomicU64,
    dnscrypt_tcp_connections: AtomicU64,
    dnscrypt_tcp_rejected: AtomicU64,
    dnscrypt_tcp_active: AtomicU64,
    dnscrypt_tcp_queries: AtomicU64,
    dnscrypt_tcp_responses: AtomicU64,
    dnscrypt_tcp_errors: AtomicU64,
    tls_reloads: AtomicU64,
    tls_reload_errors: AtomicU64,
}

impl TransportMetrics {
    /// Создаёт набор счётчиков для включённых транспортов.
    pub(crate) fn new(enabled: EnabledTransports) -> Self {
        Self {
            dot_enabled: enabled.dot,
            doh_enabled: enabled.doh,
            doh_h2_enabled: enabled.doh_h2,
            doh3_enabled: enabled.doh3,
            doq_enabled: enabled.doq,
            dnscrypt_enabled: enabled.dnscrypt,
            dnscrypt_tcp_enabled: enabled.dnscrypt_tcp,
            dot: Arc::new(Stats::new()),
            doh: Arc::new(Stats::new()),
            doh_h2: Arc::new(Stats::new()),
            doh3: Arc::new(Stats::new()),
            doq: Arc::new(Stats::new()),
            ..Self::default()
        }
    }

    /// Счётчики DoT (для `DotServer`).
    pub(crate) fn dot_stats(&self) -> Arc<Stats> {
        Arc::clone(&self.dot)
    }

    /// Счётчики DoH (для `DohServer`).
    pub(crate) fn doh_stats(&self) -> Arc<Stats> {
        Arc::clone(&self.doh)
    }

    /// Счётчики DoH/HTTP/2 (для `Doh2Server`).
    pub(crate) fn doh_h2_stats(&self) -> Arc<Stats> {
        Arc::clone(&self.doh_h2)
    }

    pub(crate) fn doh3_stats(&self) -> Arc<Stats> {
        Arc::clone(&self.doh3)
    }

    /// Счётчики DoQ (для `DoqServer`).
    pub(crate) fn doq_stats(&self) -> Arc<Stats> {
        Arc::clone(&self.doq)
    }

    pub(crate) fn dnscrypt_packet(&self) {
        self.dnscrypt_packets.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn dnscrypt_query(&self) {
        self.dnscrypt_queries.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn dnscrypt_response(&self) {
        self.dnscrypt_responses.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn dnscrypt_error(&self) {
        self.dnscrypt_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn dnscrypt_drop(&self) {
        self.dnscrypt_dropped.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn dnscrypt_tcp_connection(&self) {
        self.dnscrypt_tcp_connections
            .fetch_add(1, Ordering::Relaxed);
        self.dnscrypt_tcp_active.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn dnscrypt_tcp_connection_closed(&self) {
        self.dnscrypt_tcp_active.fetch_sub(1, Ordering::Relaxed);
    }

    pub(crate) fn dnscrypt_tcp_rejected(&self) {
        self.dnscrypt_tcp_rejected.fetch_add(1, Ordering::Relaxed);
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

    pub(crate) fn tls_reload(&self) {
        self.tls_reloads.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn tls_reload_error(&self) {
        self.tls_reload_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Рендерит метрики в формате Prometheus.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn render(&self) -> String {
        let mut out = String::new();
        if self.dot_enabled {
            append_tls("dot", &self.dot.snapshot(), &mut out);
        }
        if self.doh_enabled {
            append_tls("doh", &self.doh.snapshot(), &mut out);
        }
        if self.doh_h2_enabled {
            append_tls("doh_http2", &self.doh_h2.snapshot(), &mut out);
        }
        if self.doh3_enabled {
            append_tls("doh_http3", &self.doh3.snapshot(), &mut out);
        }
        if self.doq_enabled {
            append_tls("doq", &self.doq.snapshot(), &mut out);
        }
        if self.dot_enabled
            || self.doh_enabled
            || self.doh_h2_enabled
            || self.doh3_enabled
            || self.doq_enabled
        {
            let _ = write!(
                out,
                "# HELP pulsed_tls_reload_total Successful TLS reloads.\n\
                 # TYPE pulsed_tls_reload_total counter\n\
                 pulsed_tls_reload_total {}\n\
                 # HELP pulsed_tls_reload_errors_total Failed TLS reloads.\n\
                 # TYPE pulsed_tls_reload_errors_total counter\n\
                 pulsed_tls_reload_errors_total {}\n",
                self.tls_reloads.load(Ordering::Relaxed),
                self.tls_reload_errors.load(Ordering::Relaxed)
            );
        }
        if self.dnscrypt_enabled {
            append_counter(
                &mut out,
                "dnscrypt_packets_total",
                "UDP packets received by the DNSCrypt listener.",
                self.dnscrypt_packets.load(Ordering::Relaxed),
            );
            append_counter(
                &mut out,
                "dnscrypt_queries_total",
                "Authenticated DNSCrypt queries answered.",
                self.dnscrypt_queries.load(Ordering::Relaxed),
            );
            append_counter(
                &mut out,
                "dnscrypt_responses_total",
                "DNSCrypt responses sent to clients.",
                self.dnscrypt_responses.load(Ordering::Relaxed),
            );
            append_counter(
                &mut out,
                "dnscrypt_errors_total",
                "DNSCrypt packets rejected or failed by the handler.",
                self.dnscrypt_errors.load(Ordering::Relaxed),
            );
            append_counter(
                &mut out,
                "dnscrypt_dropped_total",
                "DNSCrypt responses dropped because the transport buffer was too small.",
                self.dnscrypt_dropped.load(Ordering::Relaxed),
            );
        }
        if self.dnscrypt_tcp_enabled {
            append_counter(
                &mut out,
                "dnscrypt_tcp_connections_total",
                "Accepted DNSCrypt TCP connections.",
                self.dnscrypt_tcp_connections.load(Ordering::Relaxed),
            );
            append_counter(
                &mut out,
                "dnscrypt_tcp_connections_rejected_total",
                "DNSCrypt TCP connections rejected by the connection limit.",
                self.dnscrypt_tcp_rejected.load(Ordering::Relaxed),
            );
            let _ = write!(
                out,
                "# HELP dnscrypt_tcp_active_connections Currently open DNSCrypt TCP connections.\n\
                 # TYPE dnscrypt_tcp_active_connections gauge\n\
                 dnscrypt_tcp_active_connections {}\n",
                self.dnscrypt_tcp_active.load(Ordering::Relaxed)
            );
            append_counter(
                &mut out,
                "dnscrypt_tcp_queries_total",
                "Authenticated DNSCrypt queries answered over TCP.",
                self.dnscrypt_tcp_queries.load(Ordering::Relaxed),
            );
            append_counter(
                &mut out,
                "dnscrypt_tcp_responses_total",
                "DNSCrypt TCP responses sent to clients.",
                self.dnscrypt_tcp_responses.load(Ordering::Relaxed),
            );
            append_counter(
                &mut out,
                "dnscrypt_tcp_errors_total",
                "DNSCrypt TCP frames rejected or failed by the handler.",
                self.dnscrypt_tcp_errors.load(Ordering::Relaxed),
            );
        }
        out
    }
}

fn append_tls(prefix: &str, stats: &pulse_tls::StatsSnapshot, out: &mut String) {
    append_counter(
        out,
        &format!("{prefix}_connections_total"),
        "Accepted TCP connections.",
        stats.connections,
    );
    append_counter(
        out,
        &format!("{prefix}_connections_rejected_total"),
        "Connections rejected by limits.",
        stats.rejected_connections,
    );
    let _ = write!(
        out,
        "# HELP {prefix}_active_connections Currently active connections.\n\
         # TYPE {prefix}_active_connections gauge\n\
         {prefix}_active_connections {}\n",
        stats.active_connections
    );
    append_counter(
        out,
        &format!("{prefix}_handshakes_total"),
        "Successful TLS handshakes.",
        stats.handshakes,
    );
    append_counter(
        out,
        &format!("{prefix}_handshake_failures_total"),
        "Failed TLS handshakes.",
        stats.handshake_failures,
    );
    append_counter(
        out,
        &format!("{prefix}_queries_total"),
        "DNS queries passed to the engine.",
        stats.queries,
    );
    append_counter(
        out,
        &format!("{prefix}_responses_total"),
        "DNS responses sent.",
        stats.responses,
    );
    append_counter(
        out,
        &format!("{prefix}_bytes_read_total"),
        "Application bytes read.",
        stats.bytes_read,
    );
    append_counter(
        out,
        &format!("{prefix}_bytes_written_total"),
        "Application bytes written.",
        stats.bytes_written,
    );
    append_counter(
        out,
        &format!("{prefix}_errors_total"),
        "Protocol and handler errors.",
        stats.errors,
    );
    if prefix.starts_with("doh") {
        append_counter(
            out,
            &format!("{prefix}_http_requests_total"),
            "HTTP requests served.",
            stats.http_requests,
        );
        append_counter(
            out,
            &format!("{prefix}_http_errors_total"),
            "HTTP 4xx/5xx responses.",
            stats.http_errors,
        );
    }
}

fn append_counter(out: &mut String, name: &str, help: &str, value: u64) {
    let _ = write!(
        out,
        "# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}\n"
    );
}

/// Рендерит метрики кеша готовых ответов (`pulsed_response_cache_*`).
pub(crate) fn render_response_cache(metrics: &pulse_server::ResponseCacheMetrics) -> String {
    let mut out = String::new();
    append_counter(
        &mut out,
        "pulsed_response_cache_hits_total",
        "DNS responses served from the response cache.",
        metrics.hits,
    );
    append_counter(
        &mut out,
        "pulsed_response_cache_misses_total",
        "DNS responses that missed the response cache.",
        metrics.misses,
    );
    append_counter(
        &mut out,
        "pulsed_response_cache_inserts_total",
        "DNS responses stored in the response cache.",
        metrics.inserts,
    );
    append_counter(
        &mut out,
        "pulsed_response_cache_evictions_total",
        "DNS responses evicted by the response cache memory bound.",
        metrics.evictions,
    );
    append_counter(
        &mut out,
        "pulsed_response_cache_invalidations_total",
        "DNS responses removed after a zone or catalog version change.",
        metrics.invalidations,
    );
    let _ = write!(
        out,
        "# HELP pulsed_response_cache_entries Cached DNS responses.\n\
         # TYPE pulsed_response_cache_entries gauge\n\
         pulsed_response_cache_entries {}\n\
         # HELP pulsed_response_cache_bytes Memory held by the response cache.\n\
         # TYPE pulsed_response_cache_bytes gauge\n\
         pulsed_response_cache_bytes {}\n\
         # HELP pulsed_response_cache_hit_rate Response cache hit ratio.\n\
         # TYPE pulsed_response_cache_hit_rate gauge\n\
         pulsed_response_cache_hit_rate {:.6}\n",
        metrics.entries,
        metrics.bytes,
        metrics.hit_rate()
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_enabled_transports_only() {
        let metrics = TransportMetrics::new(EnabledTransports {
            dot: true,
            doh: false,
            doh_h2: true,
            doh3: true,
            doq: true,
            dnscrypt: true,
            dnscrypt_tcp: true,
        });
        metrics.dnscrypt_packet();
        metrics.dnscrypt_query();
        metrics.dnscrypt_response();
        metrics.dnscrypt_tcp_connection();
        metrics.dnscrypt_tcp_query();
        metrics.dnscrypt_tcp_response();
        metrics.tls_reload();
        let text = metrics.render();
        assert!(text.contains("dot_queries_total 0"));
        assert!(!text.contains("\ndoh_queries_total"));
        assert!(text.contains("doh_http2_queries_total 0"));
        assert!(text.contains("doh_http3_queries_total 0"));
        assert!(text.contains("doq_queries_total 0"));
        assert!(text.contains("dnscrypt_packets_total 1"));
        assert!(text.contains("dnscrypt_responses_total 1"));
        assert!(text.contains("dnscrypt_tcp_connections_total 1"));
        assert!(text.contains("dnscrypt_tcp_active_connections 1"));
        assert!(text.contains("dnscrypt_tcp_queries_total 1"));
        assert!(text.contains("pulsed_tls_reload_total 1"));
    }
}
