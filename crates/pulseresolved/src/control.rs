//! Control-plane REST API на loopback.
//!
//! Сервис работает поверх `std::net::TcpListener` (HTTP/1.1, одно соединение —
//! один запрос, `Connection: close`) и не требует TLS: bind разрешён только на
//! loopback. Доступ защищён bearer-токеном; для всех ответов выставляется
//! `X-Request-Id`, ошибки отдаются как RFC 9457 `application/problem+json`.
//!
//! Горячий DNS-путь не блокируется: статистика кеша/резолвера читается через
//! атомарные счётчики, purge идёт по шардам, blocklist и trust anchors
//! подменяются атомарно, RRL-конфигурация обновляется через `RwLock`.

use std::fmt::Write as _;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pulse_dns::{Name, Rtype};
use pulse_dnssec::{TrustAnchorSnapshot, builtin_root_anchors};
use pulse_resolver::{Resolver, UpstreamStatus};
use serde::Deserialize;
use serde_json::{Value, json};
use subtle::ConstantTimeEq;

use crate::blocklist::BlocklistService;
use crate::config::{Config, ModeSetting, TrustAnchorSetting, UpstreamSetting};
use crate::logging;
use crate::metrics::MetricsSource;
use crate::rrl::{ResponseClass, Rrl, RrlRate};

/// Максимальный размер тела запроса (1 МиБ).
const MAX_BODY_BYTES: usize = 1024 * 1024;
const MAX_REQUEST_LINE_BYTES: usize = 8 * 1024;
const MAX_HEADER_BYTES: usize = 32 * 1024;
const MAX_HEADERS: usize = 100;
const MAX_CHUNK_LINE_BYTES: usize = 1024;
const MAX_TRAILER_BYTES: usize = 4096;
const ACCEPT_POLL: Duration = Duration::from_millis(20);
const SHUTDOWN_POLL: Duration = Duration::from_millis(10);
const READ_POLL: Duration = Duration::from_millis(100);

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Ошибка чтения HTTP-запроса.
#[derive(Debug, Clone, Copy)]
struct RequestError {
    status: u16,
    code: &'static str,
    detail: &'static str,
}

impl RequestError {
    const fn new(status: u16, code: &'static str, detail: &'static str) -> Self {
        Self {
            status,
            code,
            detail,
        }
    }

    const fn malformed(detail: &'static str) -> Self {
        Self::new(400, "bad-request", detail)
    }

    const fn too_large() -> Self {
        Self::new(
            413,
            "payload-too-large",
            "Request body or headers are too large.",
        )
    }

    const fn timeout() -> Self {
        Self::new(408, "bad-request", "Request read timed out.")
    }

    const fn shutting_down() -> Self {
        Self::new(503, "unavailable", "Server is shutting down.")
    }

    const fn io() -> Self {
        Self::new(400, "bad-request", "Malformed or truncated HTTP request.")
    }
}

/// Метод HTTP-запроса.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Method {
    Get,
    Post,
    Patch,
    Other(String),
}

impl Method {
    fn parse(value: &str) -> Self {
        match value {
            "GET" => Self::Get,
            "POST" => Self::Post,
            "PATCH" => Self::Patch,
            other => Self::Other(other.to_owned()),
        }
    }

    fn as_str(&self) -> &str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Patch => "PATCH",
            Self::Other(value) => value,
        }
    }
}

/// Разобранный HTTP-запрос.
struct HttpRequest {
    method: Method,
    path: String,
    query: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl HttpRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

/// HTTP-ответ.
struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl HttpResponse {
    fn json(status: u16, value: &Value) -> Self {
        let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
        let mut response = Self {
            status,
            headers: Vec::new(),
            body,
        };
        response.set_header("Content-Type", "application/json; charset=utf-8");
        response
    }

    fn problem(
        status: u16,
        code: &str,
        title: &str,
        detail: &str,
        instance: &str,
        id: &str,
    ) -> Self {
        let value = json!({
            "type": problem_type(code),
            "title": title,
            "status": status,
            "detail": detail,
            "instance": instance,
            "code": code,
            "request_id": id,
            "retryable": status == 429 || status >= 500,
        });
        let mut response = Self::json(status, &value);
        response.set_header("Content-Type", "application/problem+json");
        if status == 401 {
            response.set_header("WWW-Authenticate", "Bearer");
        }
        if status == 429 {
            response.set_header("Retry-After", "1");
        }
        response
    }

    fn set_header(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let name = name.into();
        let value = value.into();
        if let Some(existing) = self
            .headers
            .iter_mut()
            .find(|(key, _)| key.eq_ignore_ascii_case(&name))
        {
            existing.1 = value;
        } else {
            self.headers.push((name, value));
        }
    }
}

fn problem_type(code: &str) -> String {
    format!("https://pulse-dns.dev/problems/{}", code.replace('_', "-"))
}

fn title_for(code: &str) -> &'static str {
    match code {
        "bad-request" => "Bad request",
        "unauthenticated" => "Unauthenticated",
        "forbidden" => "Forbidden",
        "not-found" => "Not found",
        "method-not-allowed" => "Method not allowed",
        "payload-too-large" => "Payload too large",
        "rate-limited" => "Rate limited",
        "validation-failed" => "Validation failed",
        "unavailable" => "Unavailable",
        "reload-failed" => "Reload failed",
        "dnssec-disabled" => "DNSSEC is disabled",
        _ => "Request failed",
    }
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Content Too Large",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        _ => "Unknown",
    }
}

/// Токен-бакет для rate limit по токену.
struct TokenBucket {
    state: Mutex<BucketState>,
    qps: f64,
    burst: f64,
}

struct BucketState {
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    fn new(qps: f64, burst: u32) -> Self {
        let capacity = f64::from(burst.max(1));
        Self {
            state: Mutex::new(BucketState {
                tokens: capacity,
                last: Instant::now(),
            }),
            qps,
            burst: capacity,
        }
    }

    fn allow(&self) -> bool {
        let now = Instant::now();
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let elapsed = now.saturating_duration_since(state.last).as_secs_f64();
        state.tokens = (state.tokens + elapsed * self.qps).min(self.burst);
        state.last = now;
        if state.tokens >= 1.0 {
            state.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Общее состояние control-plane.
pub(crate) struct ControlState {
    resolver: Resolver,
    blocklist: Arc<BlocklistService>,
    rrl: Option<Arc<Rrl>>,
    metrics: MetricsSource,
    config: Config,
    token: Vec<u8>,
    limiter: TokenBucket,
    ready: AtomicBool,
    started: Instant,
}

impl ControlState {
    pub(crate) fn new(
        resolver: Resolver,
        blocklist: Arc<BlocklistService>,
        rrl: Option<Arc<Rrl>>,
        metrics: MetricsSource,
        config: Config,
        token: Vec<u8>,
    ) -> Arc<Self> {
        let setting = config.control;
        Arc::new(Self {
            resolver,
            blocklist,
            rrl,
            metrics,
            config,
            token,
            limiter: TokenBucket::new(setting.rate_limit_qps, setting.rate_limit_burst),
            ready: AtomicBool::new(true),
            started: Instant::now(),
        })
    }

    fn check_ready(&self) -> bool {
        if !self.ready.load(Ordering::Acquire) {
            return false;
        }
        let upstreams_ready = match self.config.mode {
            ModeSetting::Forward => !self.resolver.upstream_status().is_empty(),
            ModeSetting::Iterative => true,
        };
        let anchors_ready = !self.config.dnssec_validate
            || self.resolver.trust_anchor_provider().is_some()
            || matches!(
                self.config.trust_anchor,
                None | Some(TrustAnchorSetting::Embedded)
            )
            || !self.resolver.static_trust_anchors().is_empty();
        upstreams_ready && anchors_ready
    }

    fn authorized(&self, header: Option<&str>) -> AuthOutcome {
        let Some(value) = header else {
            return AuthOutcome::Missing;
        };
        let value = value.trim();
        let Some((scheme, token)) = value.split_once(' ') else {
            return AuthOutcome::Missing;
        };
        if !scheme.eq_ignore_ascii_case("bearer") {
            return AuthOutcome::Missing;
        }
        let token = token.trim();
        if token.is_empty() {
            return AuthOutcome::Missing;
        }
        if self.token.ct_eq(token.as_bytes()).into() {
            AuthOutcome::Allowed
        } else {
            AuthOutcome::Forbidden
        }
    }
}

enum AuthOutcome {
    Allowed,
    Missing,
    Forbidden,
}

/// HTTP-сервис control-plane.
pub(crate) struct ControlService {
    addr: SocketAddr,
    state: Arc<ControlState>,
    shutdown: Arc<AtomicBool>,
    active: Arc<AtomicUsize>,
    accept: Option<JoinHandle<()>>,
    workers: Arc<Mutex<Vec<JoinHandle<()>>>>,
    shutdown_timeout: Duration,
}

impl ControlService {
    pub(crate) fn start(
        addr: SocketAddr,
        state: Arc<ControlState>,
        cpu_affinity: &[usize],
    ) -> io::Result<Self> {
        if !addr.ip().is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "control API must bind to loopback",
            ));
        }
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let active = Arc::new(AtomicUsize::new(0));
        let workers = Arc::new(Mutex::new(Vec::new()));
        let setting = state.config.control;
        let cpus = Arc::new(cpu_affinity.to_vec());
        let accept = {
            let state = Arc::clone(&state);
            let shutdown = Arc::clone(&shutdown);
            let active = Arc::clone(&active);
            let workers = Arc::clone(&workers);
            let cpus = Arc::clone(&cpus);
            thread::Builder::new()
                .name("pulseresolved-control".to_owned())
                .spawn(move || {
                    if let Some(&cpu) = cpus.first() {
                        pin_current(cpu);
                    }
                    accept_loop(&listener, &state, shutdown, &active, &workers, &cpus);
                })?
        };
        Ok(Self {
            addr,
            state,
            shutdown,
            active,
            accept: Some(accept),
            workers,
            shutdown_timeout: Duration::from_millis(setting.shutdown_timeout_ms),
        })
    }

    pub(crate) fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub(crate) fn shutdown(&mut self) {
        self.state.ready.store(false, Ordering::Release);
        self.shutdown.store(true, Ordering::Release);
        if let Some(handle) = self.accept.take() {
            let _ = handle.join();
        }
        let deadline = Instant::now() + self.shutdown_timeout;
        while self.active.load(Ordering::Acquire) > 0 && Instant::now() < deadline {
            thread::sleep(SHUTDOWN_POLL);
        }
        let workers = {
            let mut guard = self.workers.lock().unwrap_or_else(PoisonError::into_inner);
            std::mem::take(&mut *guard)
        };
        if self.active.load(Ordering::Acquire) == 0 {
            for worker in workers {
                let _ = worker.join();
            }
        }
        // Соединения, не уложившиеся в shutdown_timeout, доживают свой
        // request timeout; их дескрипторы просто отсоединяются.
    }
}

impl Drop for ControlService {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn accept_loop(
    listener: &TcpListener,
    state: &Arc<ControlState>,
    shutdown: Arc<AtomicBool>,
    active: &Arc<AtomicUsize>,
    workers: &Arc<Mutex<Vec<JoinHandle<()>>>>,
    cpu_affinity: &Arc<Vec<usize>>,
) {
    let next_cpu = AtomicUsize::new(0);
    while !shutdown.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, peer)) => {
                let limit = state.config.control.max_connections;
                if active.fetch_add(1, Ordering::AcqRel) >= limit {
                    active.fetch_sub(1, Ordering::AcqRel);
                    drop(stream);
                    continue;
                }
                let state = Arc::clone(state);
                let guard = ActiveGuard(Arc::clone(active));
                let stop = Arc::clone(&shutdown);
                let cpu = if cpu_affinity.is_empty() {
                    None
                } else {
                    let index = next_cpu.fetch_add(1, Ordering::Relaxed);
                    Some(cpu_affinity[index % cpu_affinity.len()])
                };
                let spawned = thread::Builder::new()
                    .name("pulseresolved-control-http".to_owned())
                    .spawn(move || {
                        if let Some(cpu) = cpu {
                            pin_current(cpu);
                        }
                        let _guard = guard;
                        let _ = serve_connection(stream, peer, &state, &stop);
                    });
                if let Ok(handle) = spawned {
                    let mut guard = workers.lock().unwrap_or_else(PoisonError::into_inner);
                    guard.retain(|worker| !worker.is_finished());
                    guard.push(handle);
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

/// Прибить текущий поток к `cpu` (список уже пересечён с маской процесса).
fn pin_current(cpu: usize) {
    let _ = pulse_runtime::affinity::pin_current(cpu);
}

struct ActiveGuard(Arc<AtomicUsize>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn serve_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    state: &ControlState,
    shutdown: &AtomicBool,
) -> io::Result<()> {
    let initial_id = request_id(None);
    let limits = RequestLimits {
        request_timeout: Duration::from_millis(state.config.control.request_timeout_ms),
        write_timeout: Duration::from_millis(state.config.control.write_timeout_ms),
    };
    let request = match read_request(&mut stream, &limits, shutdown) {
        Ok(request) => request,
        Err(error) => {
            let mut response = HttpResponse::problem(
                error.status,
                error.code,
                title_for(error.code),
                error.detail,
                "/",
                &initial_id,
            );
            response.set_header("X-Request-Id", &initial_id);
            audit_failure(&peer, "-", "/", error.status, &initial_id);
            return write_response(&mut stream, &response, &limits);
        }
    };
    let request_id = request_id(request.header("x-request-id"));
    let instance = request.path.clone();
    let mut response = route(state, &request, &request_id, &instance);
    response.set_header("X-Request-Id", &request_id);
    if response.status >= 400 {
        audit_failure(
            &peer,
            request.method.as_str(),
            &request.path,
            response.status,
            &request_id,
        );
    }
    write_response(&mut stream, &response, &limits)
}

fn audit_failure(peer: &SocketAddr, method: &str, path: &str, status: u16, request_id: &str) {
    let event = match status {
        401 | 403 => "control_auth",
        429 => "control_rate_limit",
        413 => "control_payload",
        _ => "control_rejected",
    };
    logging::warn(
        event,
        &format!("peer={peer} method={method} path={path} status={status} request_id={request_id}"),
    );
}

fn route(state: &ControlState, request: &HttpRequest, id: &str, instance: &str) -> HttpResponse {
    let public = matches!(request.path.as_str(), "/healthz" | "/readyz");
    if !public {
        match state.authorized(request.header("authorization")) {
            AuthOutcome::Allowed => {
                if !state.limiter.allow() {
                    return HttpResponse::problem(
                        429,
                        "rate-limited",
                        title_for("rate-limited"),
                        "Too many requests for this token.",
                        instance,
                        id,
                    );
                }
            }
            AuthOutcome::Missing => {
                return HttpResponse::problem(
                    401,
                    "unauthenticated",
                    title_for("unauthenticated"),
                    "Bearer token is required.",
                    instance,
                    id,
                );
            }
            AuthOutcome::Forbidden => {
                return HttpResponse::problem(
                    403,
                    "forbidden",
                    title_for("forbidden"),
                    "Bearer token is not valid.",
                    instance,
                    id,
                );
            }
        }
    }
    let method = request.method.as_str();
    match request.path.as_str() {
        "/healthz" => {
            if let Some(response) = require_method(method, "GET", instance, id) {
                return response;
            }
            HttpResponse::json(
                200,
                &json!({
                    "status": "ok",
                    "version": env!("CARGO_PKG_VERSION"),
                    "uptime_seconds": state.started.elapsed().as_secs(),
                }),
            )
        }
        "/readyz" => {
            if let Some(response) = require_method(method, "GET", instance, id) {
                return response;
            }
            if state.check_ready() {
                HttpResponse::json(
                    200,
                    &json!({
                        "status": "ready",
                        "upstreams": state.resolver.upstream_status().len(),
                        "trust_anchors": trust_anchor_values(state).len(),
                    }),
                )
            } else {
                HttpResponse::problem(
                    503,
                    "unavailable",
                    title_for("unavailable"),
                    "Resolver is not ready.",
                    instance,
                    id,
                )
            }
        }
        "/metrics" => {
            if let Some(response) = require_method(method, "GET", instance, id) {
                return response;
            }
            let body = state.metrics.render();
            HttpResponse {
                status: 200,
                headers: vec![(
                    "Content-Type".to_owned(),
                    "text/plain; version=0.0.4; charset=utf-8".to_owned(),
                )],
                body: body.into_bytes(),
            }
        }
        "/api/v1/cache/stats" => {
            if let Some(response) = require_method(method, "GET", instance, id) {
                return response;
            }
            let cache = state.resolver.stats().cache;
            let total = cache.hits.saturating_add(cache.misses);
            let ratio = if total == 0 {
                0.0
            } else {
                cache.hits as f64 / total as f64
            };
            HttpResponse::json(
                200,
                &json!({
                    "entries": cache.entries,
                    "bytes": cache.bytes,
                    "hits": cache.hits,
                    "misses": cache.misses,
                    "inserts": cache.inserts,
                    "evictions": cache.evictions,
                    "hit_ratio": ratio,
                }),
            )
        }
        "/api/v1/cache/purge" => {
            if let Some(response) = require_method(method, "POST", instance, id) {
                return response;
            }
            match purge_cache(state, request) {
                Ok(value) => HttpResponse::json(200, &value),
                Err(detail) => HttpResponse::problem(
                    400,
                    "validation-failed",
                    title_for("validation-failed"),
                    &detail,
                    instance,
                    id,
                ),
            }
        }
        "/api/v1/blocklist" => {
            if let Some(response) = require_method(method, "GET", instance, id) {
                return response;
            }
            let blocklist = state.resolver.blocklist();
            let stats = blocklist.stats();
            let remote = state.blocklist.remote_statuses();
            HttpResponse::json(
                200,
                &json!({
                    "enabled": !state.config.blocklist.paths.is_empty()
                        || state.blocklist.remote_configured(),
                    "sources": state
                        .config
                        .blocklist
                        .paths
                        .iter()
                        .map(|path| path.display().to_string())
                        .collect::<Vec<_>>(),
                    "urls": state
                        .config
                        .blocklist
                        .remote_sources()
                        .iter()
                        .map(|source| source.url.clone())
                        .collect::<Vec<_>>(),
                    "blocked": stats.blocked,
                    "allowed": stats.allowed,
                    "skipped": stats.skipped,
                    "entries": blocklist.len(),
                    "allowlist": state.config.blocklist.allowlist,
                    "response": state.config.blocklist.response,
                    "reload_secs": state.config.blocklist.reload_secs,
                    "refresh_secs": state.config.blocklist.refresh_secs,
                    "remote": remote
                        .iter()
                        .map(|status| json!({
                            "url": status.url,
                            "active": status.active,
                            "last_success_ts": status.last_success_ts,
                            "bytes": status.bytes,
                            "refresh_secs": status.refresh_secs,
                            "next_refresh_in_secs": status.next_refresh_in_secs,
                            "etag": status.etag,
                            "last_modified": status.last_modified,
                            "last_error": status.last_error,
                        }))
                        .collect::<Vec<_>>(),
                }),
            )
        }
        "/api/v1/blocklist/reload" => {
            if let Some(response) = require_method(method, "POST", instance, id) {
                return response;
            }
            match state.blocklist.reload() {
                Ok(stats) => HttpResponse::json(
                    200,
                    &json!({
                        "reloaded": true,
                        "blocked": stats.blocked,
                        "allowed": stats.allowed,
                        "skipped": stats.skipped,
                        "results": state.blocklist.remote_statuses()
                            .iter()
                            .map(|status| json!({
                                "url": status.url,
                                "active": status.active,
                                "last_success_ts": status.last_success_ts,
                                "last_error": status.last_error,
                            }))
                            .collect::<Vec<_>>(),
                    }),
                ),
                Err(error) => HttpResponse::problem(
                    500,
                    "reload-failed",
                    title_for("reload-failed"),
                    &format!("blocklist reload failed; previous snapshot kept: {error}"),
                    instance,
                    id,
                ),
            }
        }
        "/api/v1/upstreams" => {
            if let Some(response) = require_method(method, "GET", instance, id) {
                return response;
            }
            let upstreams = state.resolver.upstream_status();
            HttpResponse::json(
                200,
                &json!({
                    "mode": mode_name(state.config.mode),
                    "upstreams": upstreams.iter().map(upstream_json).collect::<Vec<_>>(),
                }),
            )
        }
        "/api/v1/trust-anchors" => {
            if let Some(response) = require_method(method, "GET", instance, id) {
                return response;
            }
            HttpResponse::json(
                200,
                &json!({
                    "enabled": state.config.dnssec_validate,
                    "anchors": trust_anchor_values(state),
                }),
            )
        }
        "/api/v1/trust-anchors/reload" => {
            if let Some(response) = require_method(method, "POST", instance, id) {
                return response;
            }
            match reload_trust_anchors(state) {
                Ok(value) => HttpResponse::json(200, &value),
                Err((status, detail)) => HttpResponse::problem(
                    status,
                    if status == 400 {
                        "dnssec-disabled"
                    } else {
                        "reload-failed"
                    },
                    title_for(if status == 400 {
                        "dnssec-disabled"
                    } else {
                        "reload-failed"
                    }),
                    &detail,
                    instance,
                    id,
                ),
            }
        }
        "/api/v1/rrl/stats" => {
            if let Some(response) = require_method(method, "GET", instance, id) {
                return response;
            }
            HttpResponse::json(200, &rrl_json(state))
        }
        "/api/v1/rrl" => {
            if let Some(response) = require_method(method, "PATCH", instance, id) {
                return response;
            }
            match patch_rrl(state, request) {
                Ok(value) => HttpResponse::json(200, &value),
                Err((status, detail)) => HttpResponse::problem(
                    status,
                    "validation-failed",
                    title_for("validation-failed"),
                    &detail,
                    instance,
                    id,
                ),
            }
        }
        "/api/v1/config" => {
            if let Some(response) = require_method(method, "GET", instance, id) {
                return response;
            }
            HttpResponse::json(200, &safe_config(state))
        }
        _ => HttpResponse::problem(
            404,
            "not-found",
            title_for("not-found"),
            "Unknown control-plane endpoint.",
            instance,
            id,
        ),
    }
}

fn require_method(method: &str, expected: &str, instance: &str, id: &str) -> Option<HttpResponse> {
    if method == expected {
        return None;
    }
    let mut response = HttpResponse::problem(
        405,
        "method-not-allowed",
        title_for("method-not-allowed"),
        "Method is not allowed for this resource.",
        instance,
        id,
    );
    response.set_header("Allow", expected);
    Some(response)
}

fn mode_name(mode: ModeSetting) -> &'static str {
    match mode {
        ModeSetting::Forward => "forward",
        ModeSetting::Iterative => "iterative",
    }
}

fn upstream_json(status: &UpstreamStatus) -> Value {
    json!({
        "type": status.kind,
        "address": status.address,
        "healthy": status.healthy,
        "failures": status.failures,
        "cooldown": status.cooldown_ms > 0,
        "cooldown_ms": status.cooldown_ms,
        "pool": {
            "opens": status.pool.opens,
            "reuses": status.pool.reuses,
            "waits": status.pool.waits,
            "acquires": status.pool.acquires,
            "errors": status.pool.connect_failures.saturating_add(status.pool.discards),
            "discards": status.pool.discards,
            "cooldowns": status.pool.cooldowns,
        },
    })
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct PurgeRequest {
    name: Option<String>,
    #[serde(rename = "type")]
    rr_type: Option<String>,
}

fn purge_cache(state: &ControlState, request: &HttpRequest) -> Result<Value, String> {
    let (name, rr_type) = if request.body.is_empty() {
        query_parameters(&request.query)?
    } else {
        let parsed: PurgeRequest = serde_json::from_slice(&request.body)
            .map_err(|error| format!("invalid JSON body: {error}"))?;
        (parsed.name, parsed.rr_type)
    };
    let name = match name {
        Some(value) if !value.trim().is_empty() => Some(
            Name::parse(value.trim())
                .map_err(|error| format!("invalid name {:?}: {error}", value.trim()))?,
        ),
        _ => None,
    };
    let rr_type = match rr_type {
        Some(value) if !value.trim().is_empty() => Some(parse_rtype(value.trim())?),
        _ => None,
    };
    let removed = state
        .resolver
        .cache()
        .purge_matching(name.as_ref(), rr_type);
    Ok(json!({
        "purged": removed,
        "name": name.as_ref().map(Name::to_string),
        "type": rr_type.map(|rr_type| rr_type.to_string()),
    }))
}

fn query_parameters(query: &str) -> Result<(Option<String>, Option<String>), String> {
    let mut name = None;
    let mut rr_type = None;
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = percent_decode(key)?;
        let value = percent_decode(value)?;
        match key.as_str() {
            "name" => name = Some(value),
            "type" | "rr_type" => rr_type = Some(value),
            "" => {}
            other => return Err(format!("unknown query parameter {other:?}")),
        }
    }
    Ok((name, rr_type))
}

fn percent_decode(text: &str) -> Result<String, String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes.get(index) {
            Some(b'%') => {
                let high = bytes
                    .get(index + 1)
                    .and_then(|byte| hex_value(*byte))
                    .ok_or_else(|| "invalid percent-encoding".to_owned())?;
                let low = bytes
                    .get(index + 2)
                    .and_then(|byte| hex_value(*byte))
                    .ok_or_else(|| "invalid percent-encoding".to_owned())?;
                out.push((high << 4) | low);
                index += 3;
            }
            Some(b'+') => {
                out.push(b' ');
                index += 1;
            }
            Some(byte) => {
                out.push(*byte);
                index += 1;
            }
            None => break,
        }
    }
    String::from_utf8(out).map_err(|_| "query parameter is not valid UTF-8".to_owned())
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn parse_rtype(text: &str) -> Result<Rtype, String> {
    let upper = text.to_ascii_uppercase();
    let known = match upper.as_str() {
        "A" => Some(Rtype::A),
        "NS" => Some(Rtype::NS),
        "CNAME" => Some(Rtype::CNAME),
        "SOA" => Some(Rtype::SOA),
        "PTR" => Some(Rtype::PTR),
        "MX" => Some(Rtype::MX),
        "TXT" => Some(Rtype::TXT),
        "AAAA" => Some(Rtype::AAAA),
        "SRV" => Some(Rtype::SRV),
        "DNAME" => Some(Rtype::DNAME),
        "DS" => Some(Rtype::DS),
        "RRSIG" => Some(Rtype::RRSIG),
        "NSEC" => Some(Rtype::NSEC),
        "DNSKEY" => Some(Rtype::DNSKEY),
        "NSEC3" => Some(Rtype::NSEC3),
        "TLSA" => Some(Rtype::TLSA),
        "SVCB" => Some(Rtype::SVCB),
        "HTTPS" => Some(Rtype::HTTPS),
        "CAA" => Some(Rtype::CAA),
        "ANY" => Some(Rtype::ANY),
        _ => None,
    };
    if let Some(rr_type) = known {
        return Ok(rr_type);
    }
    let numeric = upper
        .strip_prefix("TYPE")
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| format!("unknown record type {text:?}"))?;
    Ok(Rtype::from_u16(numeric))
}

fn trust_anchor_values(state: &ControlState) -> Vec<Value> {
    if !state.config.dnssec_validate {
        return Vec::new();
    }
    let mut values = Vec::new();
    if let Some(provider) = state.resolver.trust_anchor_provider() {
        values.extend(provider.snapshot().iter().map(anchor_snapshot_json));
    }
    values.extend(state.resolver.static_trust_anchors().iter().map(|anchor| {
        json!({
            "zone": anchor.zone.to_string(),
            "key_tag": anchor.ds.key_tag(),
            "keyTag": anchor.ds.key_tag(),
            "algorithm": anchor.ds.algorithm(),
            "digest_type": anchor.ds.digest_type(),
            "state": "valid",
            "valid_from": Value::Null,
            "validFrom": Value::Null,
            "valid_until": Value::Null,
            "hold_down_until": Value::Null,
        })
    }));
    if values.is_empty()
        && matches!(
            state.config.trust_anchor,
            None | Some(TrustAnchorSetting::Embedded)
        )
    {
        values.extend(builtin_root_anchors().iter().map(|anchor| {
            json!({
                "zone": ".",
                "key_tag": anchor.key_tag(),
                "keyTag": anchor.key_tag(),
                "algorithm": anchor.algorithm(),
                "digest_type": anchor.digest_type(),
                "state": "valid",
                "valid_from": anchor.valid_from(),
                "validFrom": anchor.valid_from(),
                "valid_until": anchor.valid_until(),
                "hold_down_until": Value::Null,
            })
        }));
    }
    values
}

fn anchor_snapshot_json(snapshot: &TrustAnchorSnapshot) -> Value {
    json!({
        "zone": ".",
        "key_tag": snapshot.key_tag,
        "keyTag": snapshot.key_tag,
        "algorithm": snapshot.algorithm,
        "digest_type": snapshot.digest_type,
        "state": snapshot.state.as_str(),
        "valid_from": snapshot.valid_from,
        "validFrom": snapshot.valid_from,
        "valid_until": snapshot.valid_until,
        "hold_down_until": snapshot.hold_down_until,
    })
}

fn reload_trust_anchors(state: &ControlState) -> Result<Value, (u16, String)> {
    if !state.config.dnssec_validate {
        return Err((400, "DNSSEC validation is disabled.".to_owned()));
    }
    let now = unix_now();
    if let Some(provider) = state.resolver.trust_anchor_provider() {
        return provider.reload(now).map_or_else(
            |error| Err((500, format!("trust anchor state reload failed: {error}"))),
            |count| {
                Ok(json!({
                    "reloaded": true,
                    "anchors": trust_anchor_values(state).len(),
                    "count": count,
                }))
            },
        );
    }
    match &state.config.trust_anchor {
        Some(TrustAnchorSetting::PathFile(path)) => {
            let anchors = crate::anchors::load(path)
                .map_err(|error| (500, format!("trust anchor reload failed: {error}")))?;
            let count = state.resolver.replace_trust_anchors(anchors);
            Ok(json!({
                "reloaded": true,
                "anchors": trust_anchor_values(state).len(),
                "count": count,
            }))
        }
        _ => Ok(json!({
            "reloaded": true,
            "anchors": trust_anchor_values(state).len(),
            "count": 0,
            "note": "embedded trust anchors need no reload",
        })),
    }
}

fn unix_now() -> u32 {
    let Ok(duration) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return 0;
    };
    u32::try_from(duration.as_secs()).unwrap_or(u32::MAX)
}

fn rrl_json(state: &ControlState) -> Value {
    let Some(rrl) = &state.rrl else {
        return json!({ "enabled": false });
    };
    let config = rrl.config();
    let snapshot = rrl.snapshot();
    let classes = ResponseClass::ALL
        .iter()
        .map(|class| {
            let stats = snapshot.class(*class);
            let rate = config.rates[class_index(*class)];
            (
                class.as_str().to_owned(),
                json!({
                    "limited": stats.limited,
                    "slipped": stats.slipped,
                    "dropped": stats.dropped,
                    "qps": rate.qps,
                    "burst": rate.burst,
                }),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    json!({
        "enabled": true,
        "slip": config.slip,
        "max_entries": config.max_entries,
        "action": config.action,
        "entries": snapshot.entries,
        "classes": classes,
        "source": {
            "qps": config.source.qps,
            "burst": config.source.burst,
        },
    })
}

const fn class_index(class: ResponseClass) -> usize {
    match class {
        ResponseClass::NoError => 0,
        ResponseClass::NxDomain => 1,
        ResponseClass::Referral => 2,
        ResponseClass::Error => 3,
    }
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RatePatch {
    qps: Option<f64>,
    burst: Option<u32>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RrlPatch {
    slip: Option<u32>,
    max_entries: Option<usize>,
    action: Option<crate::config::RateLimitAction>,
    noerror: Option<RatePatch>,
    nxdomain: Option<RatePatch>,
    referral: Option<RatePatch>,
    error: Option<RatePatch>,
    source: Option<RatePatch>,
}

fn patch_rrl(state: &ControlState, request: &HttpRequest) -> Result<Value, (u16, String)> {
    let Some(rrl) = &state.rrl else {
        return Err((400, "RRL is disabled.".to_owned()));
    };
    if request.body.is_empty() {
        return Err((400, "request body is required".to_owned()));
    }
    let patch: RrlPatch = serde_json::from_slice(&request.body)
        .map_err(|error| (400, format!("invalid JSON body: {error}")))?;
    let mut next = (*rrl.config()).clone();
    if let Some(slip) = patch.slip {
        next.slip = slip;
    }
    if let Some(max_entries) = patch.max_entries {
        next.max_entries = max_entries;
    }
    if let Some(action) = patch.action {
        next.action = action;
    }
    apply_rate_patch(&mut next.rates[0], patch.noerror);
    apply_rate_patch(&mut next.rates[1], patch.nxdomain);
    apply_rate_patch(&mut next.rates[2], patch.referral);
    apply_rate_patch(&mut next.rates[3], patch.error);
    apply_rate_patch(&mut next.source, patch.source);
    rrl.update_config(next)
        .map_err(|error| (400, error.to_string()))?;
    Ok(rrl_json(state))
}

fn apply_rate_patch(rate: &mut RrlRate, patch: Option<RatePatch>) {
    let Some(patch) = patch else {
        return;
    };
    if let Some(qps) = patch.qps {
        rate.qps = qps;
    }
    if let Some(burst) = patch.burst {
        rate.burst = burst;
    }
}

fn safe_config(state: &ControlState) -> Value {
    let config = &state.config;
    json!({
        "version": env!("CARGO_PKG_VERSION"),
        "mode": mode_name(config.mode),
        "listen": {
            "udp": config.listen_udp.map(|addr| addr.to_string()),
            "tcp": config.listen_tcp.map(|addr| addr.to_string()),
            "dot": config.dot_listen.map(|addr| addr.to_string()),
            "doh": config.doh_listen.map(|addr| addr.to_string()),
            "doh2": config.doh2_listen.map(|addr| addr.to_string()),
            "doq": config.doq_listen.map(|addr| addr.to_string()),
            "dnscrypt_udp": config.dnscrypt_listen.map(|addr| addr.to_string()),
            "dnscrypt_tcp": config.dnscrypt_tcp_listen.map(|addr| addr.to_string()),
            "metrics": config.metrics_listen.map(|addr| addr.to_string()),
            "control": config.control_listen.map(|addr| addr.to_string()),
        },
        "workers": config.workers,
        "allow_from": config.allow_from,
        "tls_allow_from": config.tls_allow_from,
        "cache": {
            "max_entries": config.cache.max_entries,
            "max_bytes": config.cache.max_bytes,
            "min_ttl": config.cache.min_ttl,
            "max_ttl": config.cache.max_ttl,
            "shards": config.cache.shards,
        },
        "timeouts": {
            "per_query_ms": config.timeouts.per_query_ms,
            "tcp_ms": config.timeouts.tcp_ms,
            "total_ms": config.timeouts.total_ms,
        },
        "tcp": {
            "max_connections": config.tcp.max_connections,
            "idle_timeout_ms": config.tcp.idle_timeout_ms,
        },
        "blocklist": {
            "enabled": !config.blocklist.paths.is_empty(),
            "sources": config.blocklist.paths.iter().map(|path| path.display().to_string()).collect::<Vec<_>>(),
            "allowlist": config.blocklist.allowlist,
            "response": config.blocklist.response,
            "reload_secs": config.blocklist.reload_secs,
        },
        "dnssec": {
            "validate": config.dnssec_validate,
            "trust_anchor": trust_anchor_kind(config),
        },
        "upstreams": config
            .forwarders
            .iter()
            .map(|address| json!({ "type": "udp", "address": address.to_string() }))
            .chain(config.upstreams.iter().map(upstream_setting_json))
            .collect::<Vec<_>>(),
        "rate_limit": {
            "enabled": config.rate_limit.as_ref().is_some_and(|setting| setting.enabled),
        },
        "rrl": {
            "enabled": config.rrl.as_ref().is_some_and(|setting| setting.enabled),
        },
        "control": {
            "max_connections": config.control.max_connections,
            "request_timeout_ms": config.control.request_timeout_ms,
            "write_timeout_ms": config.control.write_timeout_ms,
            "shutdown_timeout_ms": config.control.shutdown_timeout_ms,
            "rate_limit_qps": config.control.rate_limit_qps,
            "rate_limit_burst": config.control.rate_limit_burst,
        },
        "log_level": config.log_level.to_string(),
    })
}

fn trust_anchor_kind(config: &Config) -> &'static str {
    match config.trust_anchor {
        Some(TrustAnchorSetting::Managed { .. }) => "managed",
        Some(TrustAnchorSetting::PathFile(_)) => "file",
        Some(TrustAnchorSetting::Embedded) | None => "embedded",
    }
}

fn upstream_setting_json(setting: &UpstreamSetting) -> Value {
    json!({
        "type": setting.upstream.kind(),
        "address": setting.upstream.to_string(),
    })
}

/// Лимиты чтения/записи.
struct RequestLimits {
    request_timeout: Duration,
    write_timeout: Duration,
}

fn read_request(
    stream: &mut TcpStream,
    limits: &RequestLimits,
    shutdown: &AtomicBool,
) -> Result<HttpRequest, RequestError> {
    let deadline = Instant::now() + limits.request_timeout;
    let mut reader = ConnReader {
        stream,
        buffer: Vec::new(),
        deadline,
        shutdown,
    };
    loop {
        if find_header_end(&reader.buffer).is_some() {
            break;
        }
        if reader.buffer.len() >= MAX_HEADER_BYTES {
            return Err(RequestError::too_large());
        }
        reader.fill()?;
    }
    let header_end = find_header_end(&reader.buffer).ok_or_else(RequestError::io)?;
    let header_bytes = reader
        .buffer
        .get(..header_end)
        .ok_or_else(RequestError::io)?
        .to_vec();
    let rest = reader
        .buffer
        .get(header_end + 4..)
        .ok_or_else(RequestError::io)?
        .to_vec();
    reader.buffer = rest;
    let header_text = std::str::from_utf8(&header_bytes)
        .map_err(|_| RequestError::malformed("Header block is not valid UTF-8."))?;
    let mut lines = header_text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| RequestError::malformed("Missing request line."))?;
    if request_line.len() > MAX_REQUEST_LINE_BYTES {
        return Err(RequestError::malformed("Request line is too long."));
    }
    let mut parts = request_line.split(' ');
    let method_text = parts
        .next()
        .ok_or_else(|| RequestError::malformed("Missing method."))?;
    let target = parts
        .next()
        .ok_or_else(|| RequestError::malformed("Missing request target."))?;
    let version = parts
        .next()
        .ok_or_else(|| RequestError::malformed("Missing HTTP version."))?;
    if parts.next().is_some() {
        return Err(RequestError::malformed("Malformed request line."));
    }
    if !is_token(method_text.as_bytes()) {
        return Err(RequestError::malformed("Invalid method token."));
    }
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(RequestError::new(
            505,
            "bad-request",
            "Only HTTP/1.0 and HTTP/1.1 are supported.",
        ));
    }
    let (path, query) = split_target(target)?;
    let mut headers = Vec::new();
    let mut count = 0_usize;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(RequestError::malformed(
                "Obsolete header folding is not allowed.",
            ));
        }
        count += 1;
        if count > MAX_HEADERS {
            return Err(RequestError::malformed("Too many headers."));
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| RequestError::malformed("Malformed header line."))?;
        if !is_token(name.as_bytes()) {
            return Err(RequestError::malformed("Invalid header name."));
        }
        let value = value.trim_matches([' ', '\t']);
        if value
            .bytes()
            .any(|byte| byte != b'\t' && !(0x20..=0x7e).contains(&byte))
        {
            return Err(RequestError::malformed("Invalid header value."));
        }
        headers.push((name.to_ascii_lowercase(), value.to_owned()));
    }
    let content_lengths: Vec<&str> = headers
        .iter()
        .filter(|(name, _)| name == "content-length")
        .map(|(_, value)| value.as_str())
        .collect();
    if content_lengths.len() > 1 {
        return Err(RequestError::malformed("Duplicate Content-Length."));
    }
    let content_length = match content_lengths.first() {
        Some(value) => Some(
            value
                .parse::<usize>()
                .map_err(|_| RequestError::malformed("Invalid Content-Length."))?,
        ),
        None => None,
    };
    let transfer_encodings: Vec<&str> = headers
        .iter()
        .filter(|(name, _)| name == "transfer-encoding")
        .map(|(_, value)| value.as_str())
        .collect();
    let chunked = !transfer_encodings.is_empty();
    if chunked && content_length.is_some() {
        return Err(RequestError::malformed(
            "Both Transfer-Encoding and Content-Length are present.",
        ));
    }
    if chunked {
        for (index, value) in transfer_encodings.iter().enumerate() {
            let tokens: Vec<&str> = value
                .split(',')
                .map(str::trim)
                .filter(|token| !token.is_empty())
                .collect();
            if tokens.is_empty() {
                return Err(RequestError::malformed("Empty Transfer-Encoding."));
            }
            for (position, token) in tokens.iter().enumerate() {
                if !token.eq_ignore_ascii_case("chunked") {
                    return Err(RequestError::malformed("Unsupported Transfer-Encoding."));
                }
                if index + 1 != transfer_encodings.len() || position + 1 != tokens.len() {
                    return Err(RequestError::malformed(
                        "chunked must be the final Transfer-Encoding.",
                    ));
                }
            }
        }
    }
    if let Some(length) = content_length
        && length > MAX_BODY_BYTES
    {
        return Err(RequestError::too_large());
    }
    if let Some(expect) = headers
        .iter()
        .find(|(name, _)| name == "expect")
        .map(|(_, value)| value.as_str())
    {
        if expect.eq_ignore_ascii_case("100-continue") {
            reader.send_continue()?;
        } else {
            return Err(RequestError::malformed("Unsupported Expect header."));
        }
    }
    let body = if chunked {
        read_chunked(&mut reader)?
    } else if let Some(length) = content_length {
        reader.take_exact(length)?
    } else {
        Vec::new()
    };
    Ok(HttpRequest {
        method: Method::parse(method_text),
        path,
        query,
        headers,
        body,
    })
}

fn split_target(target: &str) -> Result<(String, String), RequestError> {
    if target.len() > MAX_REQUEST_LINE_BYTES {
        return Err(RequestError::malformed("Request target is too long."));
    }
    let origin_form = if target.starts_with('/') {
        target
    } else if let Some(rest) = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))
    {
        let slash = rest.find('/').unwrap_or(rest.len());
        rest.get(slash..).unwrap_or("/")
    } else {
        return Err(RequestError::malformed(
            "Request target must be origin-form.",
        ));
    };
    let (path, query) = origin_form
        .split_once('?')
        .map_or((origin_form, ""), |(path, query)| (path, query));
    if path.is_empty() || !path.starts_with('/') {
        return Err(RequestError::malformed("Empty request path."));
    }
    if path.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
        return Err(RequestError::malformed("Invalid request path."));
    }
    Ok((path.to_owned(), query.to_owned()))
}

fn read_chunked(reader: &mut ConnReader<'_>) -> Result<Vec<u8>, RequestError> {
    let mut body = Vec::new();
    loop {
        let line = reader.read_line(MAX_CHUNK_LINE_BYTES)?;
        let size_text = line.split(';').next().unwrap_or("").trim();
        if size_text.is_empty() || size_text.len() > 16 {
            return Err(RequestError::malformed("Invalid chunk size."));
        }
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| RequestError::malformed("Invalid chunk size."))?;
        if size == 0 {
            let mut trailer_bytes = 0_usize;
            loop {
                let trailer = reader.read_line(MAX_CHUNK_LINE_BYTES)?;
                trailer_bytes = trailer_bytes.saturating_add(trailer.len() + 2);
                if trailer_bytes > MAX_TRAILER_BYTES {
                    return Err(RequestError::malformed("Trailer section is too large."));
                }
                if trailer.is_empty() {
                    break;
                }
            }
            break;
        }
        if body.len().saturating_add(size) > MAX_BODY_BYTES {
            return Err(RequestError::too_large());
        }
        let framed = reader.take_exact(size.saturating_add(2))?;
        let data = framed.get(..size).ok_or_else(RequestError::io)?;
        let terminator = framed.get(size..).ok_or_else(RequestError::io)?;
        if terminator != b"\r\n" {
            return Err(RequestError::malformed("Chunk is not terminated by CRLF."));
        }
        body.extend_from_slice(data);
    }
    Ok(body)
}

fn is_token(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes.iter().all(|byte| {
            matches!(
                byte,
                b'!' | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'.'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'|'
                    | b'~'
            ) || byte.is_ascii_alphanumeric()
        })
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

struct ConnReader<'a> {
    stream: &'a mut TcpStream,
    buffer: Vec<u8>,
    deadline: Instant,
    shutdown: &'a AtomicBool,
}

impl ConnReader<'_> {
    fn send_continue(&mut self) -> Result<(), RequestError> {
        self.stream
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .map_err(|_| RequestError::io())?;
        self.stream.flush().map_err(|_| RequestError::io())
    }

    fn fill(&mut self) -> Result<(), RequestError> {
        let mut chunk = [0_u8; 4096];
        loop {
            if self.shutdown.load(Ordering::Acquire) {
                return Err(RequestError::shutting_down());
            }
            let remaining = self.deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(RequestError::timeout());
            }
            let wait = remaining.min(READ_POLL);
            self.stream
                .set_read_timeout(Some(wait))
                .map_err(|_| RequestError::io())?;
            match self.stream.read(&mut chunk) {
                Ok(0) => return Err(RequestError::io()),
                Ok(read) => {
                    let data = chunk.get(..read).ok_or_else(RequestError::io)?;
                    self.buffer.extend_from_slice(data);
                    return Ok(());
                }
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock
                        || error.kind() == io::ErrorKind::TimedOut =>
                {
                    if Instant::now() >= self.deadline {
                        return Err(RequestError::timeout());
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return Err(RequestError::io()),
            }
        }
    }

    fn take_exact(&mut self, length: usize) -> Result<Vec<u8>, RequestError> {
        if length > MAX_BODY_BYTES {
            return Err(RequestError::too_large());
        }
        while self.buffer.len() < length {
            self.fill()?;
        }
        let data = self
            .buffer
            .get(..length)
            .ok_or_else(RequestError::io)?
            .to_vec();
        self.buffer.drain(..length);
        Ok(data)
    }

    fn read_line(&mut self, max: usize) -> Result<String, RequestError> {
        loop {
            if let Some(position) = self.buffer.windows(2).position(|window| window == b"\r\n") {
                if position > max {
                    return Err(RequestError::malformed("HTTP line is too long."));
                }
                let line = self
                    .buffer
                    .get(..position)
                    .ok_or_else(RequestError::io)?
                    .to_vec();
                self.buffer.drain(..position + 2);
                return String::from_utf8(line)
                    .map_err(|_| RequestError::malformed("HTTP line is not valid UTF-8."));
            }
            if self.buffer.len() > max {
                return Err(RequestError::malformed("HTTP line is too long."));
            }
            self.fill()?;
        }
    }
}

fn write_response(
    stream: &mut TcpStream,
    response: &HttpResponse,
    limits: &RequestLimits,
) -> io::Result<()> {
    let mut head = String::with_capacity(256);
    head.push_str("HTTP/1.1 ");
    head.push_str(&response.status.to_string());
    head.push(' ');
    head.push_str(reason_phrase(response.status));
    head.push_str("\r\nDate: ");
    head.push_str(&http_date(SystemTime::now()));
    head.push_str(
        "\r\nServer: pulseresolved/0.1\r\nX-Content-Type-Options: nosniff\r\n\
         Cache-Control: no-store\r\nConnection: close\r\nContent-Length: ",
    );
    head.push_str(&response.body.len().to_string());
    head.push_str("\r\n");
    for (name, value) in &response.headers {
        if name.bytes().any(|byte| byte == b'\r' || byte == b'\n')
            || value.bytes().any(|byte| byte == b'\r' || byte == b'\n')
        {
            continue;
        }
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    stream
        .set_write_timeout(Some(limits.write_timeout))
        .map_err(io::Error::other)?;
    stream.write_all(head.as_bytes())?;
    if !response.body.is_empty() {
        stream.write_all(&response.body)?;
    }
    stream.flush()?;
    let _ = stream.shutdown(std::net::Shutdown::Write);
    Ok(())
}

fn request_id(provided: Option<&str>) -> String {
    if let Some(value) = provided {
        let value = value.trim();
        if !value.is_empty()
            && value.len() <= 128
            && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
        {
            return value.to_owned();
        }
    }
    let counter = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    format!("{nanos:x}{counter:x}")
}

const SECONDS_PER_DAY: u64 = 86_400;

fn http_date(time: SystemTime) -> String {
    const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let since_epoch = time.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
    let seconds = since_epoch.as_secs();
    let days = seconds / SECONDS_PER_DAY;
    let remainder = seconds % SECONDS_PER_DAY;
    let (year, month, day) = civil_from_days(i64::try_from(days).unwrap_or(i64::MAX));
    let weekday_index = usize::try_from((days + 4) % 7).unwrap_or(0);
    let weekday = WEEKDAYS.get(weekday_index).copied().unwrap_or("Thu");
    let month_name = MONTHS
        .get(usize::try_from(month.saturating_sub(1)).unwrap_or(0))
        .copied()
        .unwrap_or("Jan");
    let hour = remainder / 3600;
    let minute = (remainder % 3600) / 60;
    let second = remainder % 60;
    let mut out = String::with_capacity(32);
    let _ = write!(
        out,
        "{weekday}, {day:02} {month_name} {year:04} {hour:02}:{minute:02}:{second:02} GMT"
    );
    out
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted / 146_097
    } else {
        (shifted - 146_096) / 146_097
    };
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    let year = year + i64::from(month <= 2);
    (
        year,
        u32::try_from(month).unwrap_or(1),
        u32::try_from(day).unwrap_or(1),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rrl::RrlConfig;
    use crate::stats::Stats;
    use pulse_resolver::ResolverConfig;

    fn test_state(config: Config, token: &str) -> Arc<ControlState> {
        let resolver = Resolver::new(ResolverConfig::forward(vec![
            "127.0.0.1:53".parse().expect("addr"),
        ]))
        .expect("resolver");
        let stats = Arc::new(Stats::new());
        let blocklist = Arc::new(
            BlocklistService::new(resolver.clone(), Arc::clone(&stats), &config)
                .expect("blocklist service"),
        );
        let metrics = MetricsSource::new(
            resolver.clone(),
            Arc::clone(&stats),
            None,
            crate::metrics::SecureMetrics::default(),
        );
        ControlState::new(
            resolver,
            blocklist,
            None,
            metrics,
            config,
            token.as_bytes().to_vec(),
        )
    }

    fn get(state: &ControlState, path: &str) -> HttpResponse {
        let request = HttpRequest {
            method: Method::Get,
            path: path.to_owned(),
            query: String::new(),
            headers: vec![("authorization".to_owned(), "Bearer secret-token".to_owned())],
            body: Vec::new(),
        };
        route(state, &request, "test", path)
    }

    #[test]
    fn auth_statuses_and_health() {
        let state = test_state(Config::default(), "secret-token");
        let missing = route(
            &state,
            &HttpRequest {
                method: Method::Get,
                path: "/api/v1/cache/stats".to_owned(),
                query: String::new(),
                headers: Vec::new(),
                body: Vec::new(),
            },
            "id",
            "/api/v1/cache/stats",
        );
        assert_eq!(missing.status, 401);
        let wrong = route(
            &state,
            &HttpRequest {
                method: Method::Get,
                path: "/api/v1/cache/stats".to_owned(),
                query: String::new(),
                headers: vec![("authorization".to_owned(), "Bearer wrong-token".to_owned())],
                body: Vec::new(),
            },
            "id",
            "/api/v1/cache/stats",
        );
        assert_eq!(wrong.status, 403);
        assert_eq!(get(&state, "/healthz").status, 200);
        assert_eq!(get(&state, "/api/v1/cache/stats").status, 200);
    }

    #[test]
    fn health_is_public_but_metrics_is_not() {
        let state = test_state(Config::default(), "secret-token");
        let public = route(
            &state,
            &HttpRequest {
                method: Method::Get,
                path: "/healthz".to_owned(),
                query: String::new(),
                headers: Vec::new(),
                body: Vec::new(),
            },
            "id",
            "/healthz",
        );
        assert_eq!(public.status, 200);
        let metrics = route(
            &state,
            &HttpRequest {
                method: Method::Get,
                path: "/metrics".to_owned(),
                query: String::new(),
                headers: Vec::new(),
                body: Vec::new(),
            },
            "id",
            "/metrics",
        );
        assert_eq!(metrics.status, 401);
    }

    #[test]
    fn rrl_patch_validates_and_applies() {
        let rrl = Arc::new(Rrl::new(RrlConfig::default()).expect("rrl"));
        let mut config = Config::default();
        config.rrl = Some(crate::config::RrlSetting::default());
        let state = test_state(config, "secret-token");
        let state = Arc::new(ControlState {
            resolver: state.resolver.clone(),
            blocklist: Arc::clone(&state.blocklist),
            rrl: Some(Arc::clone(&rrl)),
            metrics: state.metrics.clone(),
            config: state.config.clone(),
            token: state.token.clone(),
            limiter: TokenBucket::new(50.0, 100),
            ready: AtomicBool::new(true),
            started: Instant::now(),
        });
        let bad = patch_rrl(
            &state,
            &HttpRequest {
                method: Method::Patch,
                path: "/api/v1/rrl".to_owned(),
                query: String::new(),
                headers: Vec::new(),
                body: br#"{"nxdomain":{"qps":-1}}"#.to_vec(),
            },
        );
        assert!(bad.is_err());
        let ok = patch_rrl(
            &state,
            &HttpRequest {
                method: Method::Patch,
                path: "/api/v1/rrl".to_owned(),
                query: String::new(),
                headers: Vec::new(),
                body: br#"{"slip":7,"nxdomain":{"qps":2.5,"burst":9}}"#.to_vec(),
            },
        );
        assert!(ok.is_ok());
        let config = rrl.config();
        assert_eq!(config.slip, 7);
        assert_eq!(config.rates[1].qps, 2.5);
        assert_eq!(config.rates[1].burst, 9);
    }

    #[test]
    fn cache_purge_payload_is_validated() {
        let state = test_state(Config::default(), "secret-token");
        let response = route(
            &state,
            &HttpRequest {
                method: Method::Post,
                path: "/api/v1/cache/purge".to_owned(),
                query: String::new(),
                headers: vec![("authorization".to_owned(), "Bearer secret-token".to_owned())],
                body: br#"{"name":"example.com","type":"A"}"#.to_vec(),
            },
            "id",
            "/api/v1/cache/purge",
        );
        assert_eq!(response.status, 200);
        let invalid = route(
            &state,
            &HttpRequest {
                method: Method::Post,
                path: "/api/v1/cache/purge".to_owned(),
                query: String::new(),
                headers: vec![("authorization".to_owned(), "Bearer secret-token".to_owned())],
                body: br#"{"name":"bad name","type":"NOPE"}"#.to_vec(),
            },
            "id",
            "/api/v1/cache/purge",
        );
        assert_eq!(invalid.status, 400);
    }

    #[test]
    fn unknown_type_and_path_do_not_panic() {
        assert!(parse_rtype("NOPE").is_err());
        assert!(parse_rtype("TYPE65000").is_ok());
        assert!(percent_decode("%zz").is_err());
        let state = test_state(Config::default(), "secret-token");
        assert_eq!(get(&state, "/api/v1/%zz").status, 404);
    }
}
