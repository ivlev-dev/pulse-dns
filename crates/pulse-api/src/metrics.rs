//! Prometheus-метрики процесса.

use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};

#[derive(Default)]
struct Inner {
    requests: BTreeMap<(String, String, u16), u64>,
    errors: BTreeMap<&'static str, u64>,
    denied_zone_out_of_scope: u64,
    auth_failed: u64,
    rate_limited: u64,
}

/// Счётчики API.
#[derive(Default)]
pub(crate) struct Metrics {
    inner: Mutex<Inner>,
}

impl Metrics {
    /// Учитывает запрос.
    pub(crate) fn record_request(&self, method: &str, route: &str, status: u16) {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let key = (method.to_owned(), route.to_owned(), status);
        *inner.requests.entry(key).or_insert(0) += 1;
    }

    /// Учитывает проблемный ответ.
    pub(crate) fn record_error(&self, code: &'static str) {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        *inner.errors.entry(code).or_insert(0) += 1;
    }

    /// Учитывает отказ по allowlist.
    pub(crate) fn denied_zone_out_of_scope(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.denied_zone_out_of_scope = inner.denied_zone_out_of_scope.saturating_add(1);
    }

    /// Учитывает неудачную аутентификацию.
    pub(crate) fn auth_failed(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.auth_failed = inner.auth_failed.saturating_add(1);
    }

    /// Учитывает rate limit.
    pub(crate) fn rate_limited(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.rate_limited = inner.rate_limited.saturating_add(1);
    }

    /// Рендерит метрики вместе со счётчиками `pulse-zonefile`.
    pub(crate) fn render_with(&self, zonefile: Option<crate::port::ZoneFileMetrics>) -> String {
        let inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let mut out = String::new();
        out.push_str("# HELP pulse_api_requests_total Total HTTP requests served.\n");
        out.push_str("# TYPE pulse_api_requests_total counter\n");
        for ((method, route, status), value) in &inner.requests {
            out.push_str(&format!(
                "pulse_api_requests_total{{method=\"{}\",route=\"{}\",status=\"{}\"}} {}\n",
                escape_label(method),
                escape_label(route),
                status,
                value
            ));
        }
        out.push_str("# HELP pulse_api_errors_total Problem responses by code.\n");
        out.push_str("# TYPE pulse_api_errors_total counter\n");
        for (code, value) in &inner.errors {
            out.push_str(&format!(
                "pulse_api_errors_total{{code=\"{}\"}} {}\n",
                escape_label(code),
                value
            ));
        }
        out.push_str(
            "# HELP pulse_api_denied_zone_out_of_scope_total Requests denied by zone allowlist.\n",
        );
        out.push_str("# TYPE pulse_api_denied_zone_out_of_scope_total counter\n");
        out.push_str(&format!(
            "pulse_api_denied_zone_out_of_scope_total {}\n",
            inner.denied_zone_out_of_scope
        ));
        out.push_str("# HELP pulse_api_auth_failed_total Failed bearer authentications.\n");
        out.push_str("# TYPE pulse_api_auth_failed_total counter\n");
        out.push_str(&format!(
            "pulse_api_auth_failed_total {}\n",
            inner.auth_failed
        ));
        out.push_str("# HELP pulse_api_rate_limited_total Requests rejected by rate limiting.\n");
        out.push_str("# TYPE pulse_api_rate_limited_total counter\n");
        out.push_str(&format!(
            "pulse_api_rate_limited_total {}\n",
            inner.rate_limited
        ));
        if let Some(zonefile) = zonefile {
            out.push_str("# HELP zonefile_snapshot_pins Zonefile snapshot pins taken.\n");
            out.push_str("# TYPE zonefile_snapshot_pins counter\n");
            out.push_str(&format!(
                "zonefile_snapshot_pins {}\n",
                zonefile.snapshot_pins
            ));
            out.push_str("# HELP zonefile_lookups Zonefile RRset lookups.\n");
            out.push_str("# TYPE zonefile_lookups counter\n");
            out.push_str(&format!("zonefile_lookups {}\n", zonefile.lookups));
            out.push_str("# HELP zonefile_commits Successful zonefile commits.\n");
            out.push_str("# TYPE zonefile_commits counter\n");
            out.push_str(&format!("zonefile_commits {}\n", zonefile.commits));
            out.push_str("# HELP zonefile_commit_errors Failed zonefile commits.\n");
            out.push_str("# TYPE zonefile_commit_errors counter\n");
            out.push_str(&format!(
                "zonefile_commit_errors {}\n",
                zonefile.commit_errors
            ));
            append_v2(&mut out, &zonefile);
        }
        out
    }
}

/// Метрики v2-стора (`ParallelStore`): alloc, commit, GC, cache, pins.
fn append_v2(out: &mut String, zonefile: &crate::port::ZoneFileMetrics) {
    for (name, help, kind, value) in [
        (
            "zonefile_v2_alloc_pages",
            "Data pages handed out by the v2 allocator.",
            "gauge",
            zonefile.v2_alloc_pages,
        ),
        (
            "zonefile_v2_alloc_cas_retries_total",
            "Allocator CAS retries.",
            "counter",
            zonefile.v2_alloc_cas_retries,
        ),
        (
            "zonefile_v2_page_cache_hits_total",
            "Validated page cache hits.",
            "counter",
            zonefile.v2_page_cache_hits,
        ),
        (
            "zonefile_v2_page_cache_misses_total",
            "Validated page cache misses.",
            "counter",
            zonefile.v2_page_cache_misses,
        ),
        (
            "zonefile_v2_node_cache_hits_total",
            "B+tree node cache hits.",
            "counter",
            zonefile.v2_node_cache_hits,
        ),
        (
            "zonefile_v2_node_cache_misses_total",
            "B+tree node cache misses.",
            "counter",
            zonefile.v2_node_cache_misses,
        ),
        (
            "zonefile_v2_reclaimed_pages_total",
            "Pages reclaimed by GC or the free pool.",
            "counter",
            zonefile.v2_reclaimed_pages,
        ),
        (
            "zonefile_v2_group_commits_total",
            "Group commits executed by the coordinator.",
            "counter",
            zonefile.v2_group_commits,
        ),
        (
            "zonefile_v2_group_fsyncs_total",
            "fdatasync calls made by group commit.",
            "counter",
            zonefile.v2_group_fsyncs,
        ),
        (
            "zonefile_v2_pins",
            "Active reader pins.",
            "gauge",
            zonefile.v2_pins,
        ),
        (
            "zonefile_v2_freeze_epoch",
            "Active shared/local freeze epoch (0 = none).",
            "gauge",
            zonefile.v2_freeze_epoch,
        ),
        (
            "zonefile_v2_sweep_runs_total",
            "Online leak sweep runs.",
            "counter",
            zonefile.v2_sweep_runs,
        ),
        (
            "zonefile_v2_sweep_scanned_pages_total",
            "Pages scanned by online leak sweep.",
            "counter",
            zonefile.v2_sweep_scanned_pages,
        ),
        (
            "zonefile_v2_sweep_reclaimed_pages_total",
            "Pages returned to the pool by online leak sweep.",
            "counter",
            zonefile.v2_sweep_reclaimed_pages,
        ),
        (
            "zonefile_v2_pending_pages",
            "Absolute pending reservation floor (0 = none).",
            "gauge",
            zonefile.v2_pending_pages,
        ),
    ] {
        out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} {kind}\n"));
        out.push_str(&format!("{name} {value}\n"));
    }
}

fn escape_label(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_contains_counts() {
        let metrics = Metrics::default();
        metrics.record_request("GET", "/healthz", 200);
        metrics.record_request("GET", "/healthz", 200);
        metrics.record_error("zone_not_found");
        metrics.denied_zone_out_of_scope();
        let text = metrics.render_with(None);
        assert!(text.contains(
            "pulse_api_requests_total{method=\"GET\",route=\"/healthz\",status=\"200\"} 2"
        ));
        assert!(text.contains("pulse_api_errors_total{code=\"zone_not_found\"} 1"));
        assert!(text.contains("pulse_api_denied_zone_out_of_scope_total 1"));
        assert!(text.contains("# TYPE pulse_api_requests_total counter"));
    }

    #[test]
    fn labels_are_escaped() {
        assert_eq!(escape_label("a\"b\\c"), "a\\\"b\\\\c");
    }
}
