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

    /// Рендерит Prometheus text exposition 0.0.4.
    pub(crate) fn render(&self) -> String {
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
        out
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
        let text = metrics.render();
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
