//! Prometheus-метрики, `GET /healthz` и минимальный HTTP-сервер на std.
//!
//! Сервер обслуживает только loopback-адрес (проверяется в конфигурации),
//! отвечает на `GET /metrics` и `GET /healthz` и закрывает соединение после
//! одного запроса.

use std::fmt::Write as _;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use pulse_resolver::Resolver;

use crate::stats::Stats;

const MAX_HTTP_CONNECTIONS: usize = 32;
const MAX_REQUEST_BYTES: usize = 8 * 1024;
const ACCEPT_POLL: Duration = Duration::from_millis(20);

/// Источник текста метрик.
pub(crate) struct MetricsSource {
    resolver: Resolver,
    stats: Arc<Stats>,
    started: Instant,
}

impl MetricsSource {
    pub(crate) fn new(resolver: Resolver, stats: Arc<Stats>) -> Self {
        Self {
            resolver,
            stats,
            started: Instant::now(),
        }
    }

    /// Рендерит Prometheus text exposition 0.0.4.
    pub(crate) fn render(&self) -> String {
        let stats = self.stats.snapshot();
        let resolver = self.resolver.stats();
        let uptime = self.started.elapsed().as_secs_f64();
        let mut out = String::with_capacity(4096);
        let _ = writeln!(
            out,
            "# HELP pulseresolved_build_info Build information.\n\
             # TYPE pulseresolved_build_info gauge\n\
             pulseresolved_build_info{{version=\"{}\"}} 1",
            env!("CARGO_PKG_VERSION")
        );
        out.push_str("# HELP pulseresolved_uptime_seconds Process uptime.\n");
        out.push_str("# TYPE pulseresolved_uptime_seconds gauge\n");
        let _ = writeln!(out, "pulseresolved_uptime_seconds {uptime:.3}");

        out.push_str("# HELP pulseresolved_queries_total DNS queries by transport.\n");
        out.push_str("# TYPE pulseresolved_queries_total counter\n");
        let _ = writeln!(
            out,
            "pulseresolved_queries_total{{transport=\"udp\"}} {}",
            stats.udp_queries
        );
        let _ = writeln!(
            out,
            "pulseresolved_queries_total{{transport=\"tcp\"}} {}",
            stats.tcp_queries
        );
        out.push_str("# HELP pulseresolved_responses_total DNS responses by transport.\n");
        out.push_str("# TYPE pulseresolved_responses_total counter\n");
        let _ = writeln!(
            out,
            "pulseresolved_responses_total{{transport=\"udp\"}} {}",
            stats.udp_responses
        );
        let _ = writeln!(
            out,
            "pulseresolved_responses_total{{transport=\"tcp\"}} {}",
            stats.tcp_responses
        );
        counter(
            &mut out,
            "pulseresolved_decode_errors_total",
            "Malformed requests.",
            stats.decode_errors,
        );
        counter(
            &mut out,
            "pulseresolved_encode_errors_total",
            "Response encoding failures.",
            stats.encode_errors,
        );
        counter(
            &mut out,
            "pulseresolved_formerr_total",
            "FORMERR responses.",
            stats.formerr,
        );
        counter(
            &mut out,
            "pulseresolved_refused_total",
            "REFUSED responses.",
            stats.refused,
        );
        counter(
            &mut out,
            "pulseresolved_truncated_total",
            "TC responses.",
            stats.truncated,
        );
        counter(
            &mut out,
            "pulseresolved_dropped_total",
            "Requests dropped without a response.",
            stats.dropped,
        );
        counter(
            &mut out,
            "pulseresolved_tcp_connections_total",
            "Accepted TCP connections.",
            stats.tcp_connections,
        );
        counter(
            &mut out,
            "pulseresolved_tcp_rejected_total",
            "TCP connections rejected by the limit.",
            stats.tcp_rejected,
        );
        counter(
            &mut out,
            "pulseresolved_tcp_io_errors_total",
            "TCP connection I/O errors.",
            stats.tcp_io_errors,
        );
        counter(
            &mut out,
            "pulseresolved_blocklist_reloads_total",
            "Successful blocklist reloads.",
            stats.reloads,
        );
        counter(
            &mut out,
            "pulseresolved_blocklist_reload_failures_total",
            "Failed blocklist reloads.",
            stats.reload_failures,
        );
        gauge(
            &mut out,
            "pulseresolved_tcp_active_connections",
            "Active TCP connections.",
            stats.tcp_active,
        );

        counter(
            &mut out,
            "pulseresolved_resolver_queries_total",
            "Queries handled by the resolver.",
            resolver.queries,
        );
        counter(
            &mut out,
            "pulseresolved_resolver_servfail_total",
            "Resolver SERVFAIL responses.",
            resolver.servfail,
        );
        counter(
            &mut out,
            "pulseresolved_blocked_total",
            "Answers from the blocklist.",
            resolver.blocked,
        );
        counter(
            &mut out,
            "pulseresolved_overridden_total",
            "Answers from overrides.",
            resolver.overridden,
        );
        counter(
            &mut out,
            "pulseresolved_dnssec_secure_total",
            "DNSSEC-secure answers.",
            resolver.dnssec_secure,
        );
        counter(
            &mut out,
            "pulseresolved_dnssec_insecure_total",
            "DNSSEC-proven-insecure answers.",
            resolver.dnssec_insecure,
        );
        counter(
            &mut out,
            "pulseresolved_dnssec_bogus_total",
            "DNSSEC-bogus answers.",
            resolver.dnssec_bogus,
        );
        counter(
            &mut out,
            "pulseresolved_cache_hits_total",
            "Resolver cache hits.",
            resolver.cache.hits,
        );
        counter(
            &mut out,
            "pulseresolved_cache_misses_total",
            "Resolver cache misses.",
            resolver.cache.misses,
        );
        counter(
            &mut out,
            "pulseresolved_cache_inserts_total",
            "Resolver cache inserts.",
            resolver.cache.inserts,
        );
        counter(
            &mut out,
            "pulseresolved_cache_evictions_total",
            "Resolver cache evictions.",
            resolver.cache.evictions,
        );
        gauge(
            &mut out,
            "pulseresolved_cache_entries",
            "Resolver cache entries.",
            resolver.cache.entries as u64,
        );
        gauge(
            &mut out,
            "pulseresolved_cache_bytes",
            "Approximate resolver cache size in bytes.",
            resolver.cache.bytes as u64,
        );
        counter(
            &mut out,
            "pulseresolved_upstream_udp_queries_total",
            "Upstream UDP queries.",
            resolver.upstream.udp_queries,
        );
        counter(
            &mut out,
            "pulseresolved_upstream_tcp_queries_total",
            "Upstream TCP queries.",
            resolver.upstream.tcp_queries,
        );
        counter(
            &mut out,
            "pulseresolved_upstream_retries_total",
            "Upstream retries.",
            resolver.upstream.retries,
        );
        counter(
            &mut out,
            "pulseresolved_upstream_timeouts_total",
            "Upstream timeouts.",
            resolver.upstream.timeouts,
        );
        counter(
            &mut out,
            "pulseresolved_upstream_mismatches_total",
            "Upstream response mismatches.",
            resolver.upstream.mismatches,
        );
        out
    }

    pub(crate) const fn healthz() -> &'static str {
        "ok\n"
    }
}

fn counter(out: &mut String, name: &str, help: &str, value: u64) {
    let _ = writeln!(
        out,
        "# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}"
    );
}

fn gauge(out: &mut String, name: &str, help: &str, value: u64) {
    let _ = writeln!(
        out,
        "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {value}"
    );
}

/// HTTP-сервер метрик.
pub(crate) struct MetricsService {
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    accept: Option<JoinHandle<()>>,
    workers: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl MetricsService {
    pub(crate) fn start(addr: SocketAddr, source: MetricsSource) -> io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let workers = Arc::new(Mutex::new(Vec::new()));
        let source = Arc::new(source);
        let accept = {
            let shutdown = Arc::clone(&shutdown);
            let workers = Arc::clone(&workers);
            thread::Builder::new()
                .name("pulseresolved-metrics".to_owned())
                .spawn(move || accept_loop(&listener, &source, &shutdown, &workers))?
        };
        Ok(Self {
            addr,
            shutdown,
            accept: Some(accept),
            workers,
        })
    }

    pub(crate) fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub(crate) fn shutdown(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(handle) = self.accept.take() {
            let _ = handle.join();
        }
        let workers = {
            let mut guard = self.workers.lock().unwrap_or_else(PoisonError::into_inner);
            std::mem::take(&mut *guard)
        };
        for worker in workers {
            let _ = worker.join();
        }
    }
}

impl Drop for MetricsService {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn accept_loop(
    listener: &TcpListener,
    source: &Arc<MetricsSource>,
    shutdown: &AtomicBool,
    workers: &Arc<Mutex<Vec<JoinHandle<()>>>>,
) {
    let active = Arc::new(AtomicUsize::new(0));
    while !shutdown.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _peer)) => {
                if active.fetch_add(1, Ordering::Relaxed) >= MAX_HTTP_CONNECTIONS {
                    active.fetch_sub(1, Ordering::Relaxed);
                    drop(stream);
                    continue;
                }
                let source = Arc::clone(source);
                let guard = ActiveGuard(Arc::clone(&active));
                let spawned = thread::Builder::new()
                    .name("pulseresolved-http".to_owned())
                    .spawn(move || {
                        let _guard = guard;
                        let _ = serve_connection(stream, &source);
                    });
                if let Ok(handle) = spawned {
                    workers
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push(handle);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_POLL);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => thread::sleep(ACCEPT_POLL),
        }
    }
}

struct ActiveGuard(Arc<AtomicUsize>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

fn serve_connection(mut stream: TcpStream, source: &MetricsSource) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut buffer = [0_u8; MAX_REQUEST_BYTES];
    let mut filled = 0;
    while filled < buffer.len() {
        let read = stream.read(&mut buffer[filled..])?;
        if read == 0 {
            break;
        }
        filled += read;
        if buffer
            .get(..filled)
            .is_some_and(|data| data.windows(4).any(|window| window == b"\r\n\r\n"))
        {
            break;
        }
    }
    let request = String::from_utf8_lossy(buffer.get(..filled).unwrap_or(&[]));
    let line = request.lines().next().unwrap_or("");
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let path = target.split('?').next().unwrap_or("");
    if method != "GET" {
        return respond(
            &mut stream,
            "405 Method Not Allowed",
            "text/plain",
            "method not allowed\n",
        );
    }
    match path {
        "/metrics" => {
            let body = source.render();
            respond(
                &mut stream,
                "200 OK",
                "text/plain; version=0.0.4; charset=utf-8",
                &body,
            )
        }
        "/healthz" => respond(
            &mut stream,
            "200 OK",
            "text/plain; charset=utf-8",
            MetricsSource::healthz(),
        ),
        _ => respond(&mut stream, "404 Not Found", "text/plain", "not found\n"),
    }
}

fn respond(stream: &mut TcpStream, status: &str, content_type: &str, body: &str) -> io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body.as_bytes())?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use pulse_resolver::ResolverConfig;

    use super::*;

    #[test]
    fn render_contains_transport_and_resolver_metrics() {
        let resolver = Resolver::new(ResolverConfig::forward(vec![
            "127.0.0.1:53".parse().unwrap(),
        ]))
        .unwrap();
        let stats = Arc::new(Stats::new());
        stats.udp_query();
        stats.reload_ok();
        let source = MetricsSource::new(resolver, stats);
        let text = source.render();
        assert!(text.contains("pulseresolved_queries_total{transport=\"udp\"} 1"));
        assert!(text.contains("pulseresolved_resolver_queries_total 0"));
        assert!(text.contains("pulseresolved_cache_entries 0"));
        assert!(text.contains("# TYPE pulseresolved_queries_total counter"));
        assert!(text.contains("pulseresolved_blocklist_reloads_total 1"));
        assert!(MetricsSource::healthz().starts_with("ok"));
    }

    #[test]
    fn http_serves_metrics_and_healthz() {
        let resolver = Resolver::new(ResolverConfig::forward(vec![
            "127.0.0.1:53".parse().unwrap(),
        ]))
        .unwrap();
        let stats = Arc::new(Stats::new());
        let source = MetricsSource::new(resolver, stats);
        let mut service = MetricsService::start("127.0.0.1:0".parse().unwrap(), source).unwrap();
        let addr = service.addr();
        assert!(http_get(addr, "/healthz").contains("200 OK"));
        let body = http_get(addr, "/metrics");
        assert!(body.contains("200 OK"));
        assert!(body.contains("pulseresolved_queries_total"));
        assert!(http_get(addr, "/nope").contains("404"));
        service.shutdown();
    }

    fn http_get(addr: SocketAddr, path: &str) -> String {
        let mut stream = TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        write!(stream, "GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    }
}
