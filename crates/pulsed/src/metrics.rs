//! Счётчики DoT/DoH/DNSCrypt для `GET /metrics`.
//!
//! DoT/DoH используют атомарные счётчики `pulse-tls`; DNSCrypt ведёт
//! собственные счётчики пакетов/ответов/ошибок в `pulsed`. Метрики
//! добавляются к выводу `pulse-api` и не логируются.

use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use pulse_tls::Stats;

/// Общие счётчики защищённых транспортов.
#[derive(Debug, Default)]
pub(crate) struct TransportMetrics {
    dot_enabled: bool,
    doh_enabled: bool,
    dnscrypt_enabled: bool,
    dot: Arc<Stats>,
    doh: Arc<Stats>,
    dnscrypt_packets: AtomicU64,
    dnscrypt_queries: AtomicU64,
    dnscrypt_responses: AtomicU64,
    dnscrypt_errors: AtomicU64,
    dnscrypt_dropped: AtomicU64,
    tls_reloads: AtomicU64,
    tls_reload_errors: AtomicU64,
}

impl TransportMetrics {
    /// Создаёт набор счётчиков для включённых транспортов.
    #[allow(clippy::similar_names)] // dot/doh — имена протоколов, не опечатка.
    pub(crate) fn new(enable_dot: bool, enable_doh: bool, enable_dnscrypt: bool) -> Self {
        Self {
            dot_enabled: enable_dot,
            doh_enabled: enable_doh,
            dnscrypt_enabled: enable_dnscrypt,
            dot: Arc::new(Stats::new()),
            doh: Arc::new(Stats::new()),
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

    pub(crate) fn tls_reload(&self) {
        self.tls_reloads.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn tls_reload_error(&self) {
        self.tls_reload_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Рендерит метрики в формате Prometheus.
    pub(crate) fn render(&self) -> String {
        let mut out = String::new();
        if self.dot_enabled {
            append_tls("dot", &self.dot.snapshot(), &mut out);
        }
        if self.doh_enabled {
            append_tls("doh", &self.doh.snapshot(), &mut out);
        }
        if self.dot_enabled || self.doh_enabled {
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
    if prefix == "doh" {
        append_counter(
            out,
            "doh_http_requests_total",
            "HTTP requests served.",
            stats.http_requests,
        );
        append_counter(
            out,
            "doh_http_errors_total",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_enabled_transports_only() {
        let metrics = TransportMetrics::new(true, false, true);
        metrics.dnscrypt_packet();
        metrics.dnscrypt_query();
        metrics.dnscrypt_response();
        metrics.tls_reload();
        let text = metrics.render();
        assert!(text.contains("dot_queries_total 0"));
        assert!(!text.contains("doh_queries_total"));
        assert!(text.contains("dnscrypt_packets_total 1"));
        assert!(text.contains("dnscrypt_responses_total 1"));
        assert!(text.contains("pulsed_tls_reload_total 1"));
    }
}
