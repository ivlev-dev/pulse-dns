//! Интеграционные тесты control-plane REST API.

mod support;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use pulse_dns::{Rcode, Rtype};
use pulseresolved::config::{Config, ControlSetting, ControlToken, RrlSetting, TrustAnchorSetting};
use pulseresolved::server::Server;
use serde_json::Value;

use support::e2e::{SOCKET_TIMEOUT, retry};
use support::{
    MockUpstream, a_record, base_config, make_query, positive_response, udp_query_retry,
};

const TOKEN: &str = "test-control-token";

struct RawResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl RawResponse {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("valid JSON response")
    }
}

fn control_config(upstream: SocketAddr) -> Config {
    let mut config = base_config(upstream);
    config.listen_tcp = None;
    config.control_listen = Some("127.0.0.1:0".parse().expect("control addr"));
    config.control_token = Some(ControlToken::new(TOKEN));
    config
}

fn request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    body: &[u8],
    token: Option<&str>,
) -> RawResponse {
    request_with_id(addr, method, path, body, token, None)
}

fn control_connect(addr: SocketAddr) -> TcpStream {
    retry(
        "control connect",
        || format!("control {addr}"),
        || TcpStream::connect(addr).map_err(|error| format!("connect {addr}: {error}")),
    )
}

fn request_with_id(
    addr: SocketAddr,
    method: &str,
    path: &str,
    body: &[u8],
    token: Option<&str>,
    request_id: Option<&str>,
) -> RawResponse {
    let mut stream = control_connect(addr);
    stream
        .set_read_timeout(Some(SOCKET_TIMEOUT))
        .expect("read timeout");
    stream
        .set_write_timeout(Some(SOCKET_TIMEOUT))
        .expect("write timeout");
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n",
        body.len()
    );
    if let Some(token) = token {
        head.push_str("Authorization: Bearer ");
        head.push_str(token);
        head.push_str("\r\n");
    }
    if let Some(request_id) = request_id {
        head.push_str("X-Request-Id: ");
        head.push_str(request_id);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).expect("write head");
    stream.write_all(body).expect("write body");
    stream.flush().expect("flush");
    read_response(&mut stream)
}

fn raw_request(addr: SocketAddr, bytes: &[u8]) -> RawResponse {
    let mut stream = control_connect(addr);
    stream
        .set_read_timeout(Some(SOCKET_TIMEOUT))
        .expect("read timeout");
    stream.write_all(bytes).expect("write raw");
    stream.flush().expect("flush");
    read_response(&mut stream)
}

fn read_response(stream: &mut TcpStream) -> RawResponse {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let read = match stream.read(&mut chunk) {
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => panic!("read response: {error}"),
        };
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    let split = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("header terminator");
    let head = String::from_utf8(bytes[..split].to_vec()).expect("header utf8");
    let body = bytes[split + 4..].to_vec();
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .expect("status");
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_owned(), value.trim().to_owned()))
        .collect();
    RawResponse {
        status,
        headers,
        body,
    }
}

fn upstream() -> MockUpstream {
    MockUpstream::start(|request| {
        let name = request.questions().first().map_or_else(
            || "example.com.".to_owned(),
            |question| question.qname().to_string(),
        );
        let record = a_record(&name, [192, 0, 2, 10], 60);
        Some(positive_response(request, record))
    })
}

#[test]
fn auth_statuses_problem_headers_and_request_id() {
    let upstream = upstream();
    let config = control_config(upstream.address());
    let server = Server::start(&config).expect("server");
    let addr = server.control_addr().expect("control addr");

    let missing = request(addr, "GET", "/api/v1/cache/stats", &[], None);
    assert_eq!(missing.status, 401);
    assert_eq!(
        missing.header("content-type"),
        Some("application/problem+json")
    );
    assert_eq!(missing.header("www-authenticate"), Some("Bearer"));
    assert!(missing.header("x-request-id").is_some());
    let problem = missing.json();
    assert_eq!(problem["status"], 401);
    assert_eq!(problem["code"], "unauthenticated");
    assert!(
        problem["request_id"]
            .as_str()
            .is_some_and(|id| !id.is_empty())
    );

    let wrong = request(addr, "GET", "/api/v1/cache/stats", &[], Some("wrong-token"));
    assert_eq!(wrong.status, 403);
    assert_eq!(wrong.json()["code"], "forbidden");

    let ok = request_with_id(
        addr,
        "GET",
        "/api/v1/cache/stats",
        &[],
        Some(TOKEN),
        Some("req-42"),
    );
    assert_eq!(ok.status, 200);
    assert_eq!(ok.header("x-request-id"), Some("req-42"));

    let health = request(addr, "GET", "/healthz", &[], None);
    assert_eq!(health.status, 200);
    let ready = request(addr, "GET", "/readyz", &[], None);
    assert_eq!(ready.status, 200);
    assert_eq!(ready.json()["status"], "ready");

    let metrics_without = request(addr, "GET", "/metrics", &[], None);
    assert_eq!(metrics_without.status, 401);
    let metrics = request(addr, "GET", "/metrics", &[], Some(TOKEN));
    assert_eq!(metrics.status, 200);
    assert!(String::from_utf8_lossy(&metrics.body).contains("pulseresolved_queries_total"));

    let unknown = request(addr, "GET", "/api/v1/nope", &[], Some(TOKEN));
    assert_eq!(unknown.status, 404);
    let wrong_method = request(addr, "POST", "/api/v1/cache/stats", &[], Some(TOKEN));
    assert_eq!(wrong_method.status, 405);
    assert_eq!(wrong_method.header("allow"), Some("GET"));

    drop(server);
}

#[test]
fn cache_stats_and_purge_by_name_and_type() {
    let upstream = upstream();
    let config = control_config(upstream.address());
    let server = Server::start(&config).expect("server");
    let addr = server.control_addr().expect("control addr");
    let dns = server.udp_addr().expect("udp");

    let query = make_query("first.example", Rtype::A, None);
    let response = udp_query_retry(dns, &query, "control cache DNS");
    assert_eq!(response.rcode(), Rcode::NOERROR);

    let stats = request(addr, "GET", "/api/v1/cache/stats", &[], Some(TOKEN));
    assert_eq!(stats.status, 200);
    assert!(stats.json()["entries"].as_u64().is_some_and(|n| n >= 1));

    let purge = request(
        addr,
        "POST",
        "/api/v1/cache/purge",
        br#"{"name":"first.example"}"#,
        Some(TOKEN),
    );
    assert_eq!(purge.status, 200);
    assert!(purge.json()["purged"].as_u64().is_some_and(|n| n >= 1));

    let query = make_query("second.example", Rtype::A, None);
    let _ = udp_query_retry(dns, &query, "control cache second DNS");
    let purge = request(
        addr,
        "POST",
        "/api/v1/cache/purge",
        br#"{"type":"A"}"#,
        Some(TOKEN),
    );
    assert_eq!(purge.status, 200);
    assert!(purge.json()["purged"].as_u64().is_some_and(|n| n >= 1));

    let stats = request(addr, "GET", "/api/v1/cache/stats", &[], Some(TOKEN));
    assert_eq!(stats.json()["entries"], 0);

    let invalid = request(
        addr,
        "POST",
        "/api/v1/cache/purge",
        br#"{"name":"bad name","type":"NOPE"}"#,
        Some(TOKEN),
    );
    assert_eq!(invalid.status, 400);
    drop(server);
}

#[test]
fn blocklist_reload_applies_new_file() {
    let upstream = upstream();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("blocklist.txt");
    std::fs::write(&path, "first.test\n").expect("write blocklist");

    let mut config = control_config(upstream.address());
    config.blocklist.paths = vec![path.clone()];
    let server = Server::start(&config).expect("server");
    let addr = server.control_addr().expect("control addr");

    let before = request(addr, "GET", "/api/v1/blocklist", &[], Some(TOKEN));
    assert_eq!(before.status, 200);
    assert_eq!(before.json()["blocked"], 1);
    assert_eq!(before.json()["sources"][0], path.display().to_string());

    std::fs::write(&path, "second.test\n").expect("rewrite blocklist");
    let reload = request(addr, "POST", "/api/v1/blocklist/reload", &[], Some(TOKEN));
    assert_eq!(reload.status, 200);
    assert_eq!(reload.json()["reloaded"], true);

    let after = request(addr, "GET", "/api/v1/blocklist", &[], Some(TOKEN));
    assert_eq!(after.json()["blocked"], 1);

    let dns = server.udp_addr().expect("udp");
    let query = make_query("second.test", Rtype::A, None);
    let response = udp_query_retry(dns, &query, "control blocklist DNS");
    assert_eq!(response.rcode(), Rcode::NXDOMAIN);
    drop(server);
}

#[test]
fn upstreams_report_health_and_pool() {
    let upstream = upstream();
    let config = control_config(upstream.address());
    let server = Server::start(&config).expect("server");
    let addr = server.control_addr().expect("control addr");

    let response = request(addr, "GET", "/api/v1/upstreams", &[], Some(TOKEN));
    assert_eq!(response.status, 200);
    let body = response.json();
    assert_eq!(body["mode"], "forward");
    let list = body["upstreams"].as_array().expect("upstreams array");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["type"], "udp");
    assert_eq!(list[0]["address"], upstream.address().to_string());
    assert_eq!(list[0]["healthy"], true);
    assert!(list[0]["pool"]["opens"].as_u64().is_some());
    assert!(list[0]["pool"]["errors"].as_u64().is_some());
    drop(server);
}

#[test]
fn trust_anchors_are_public_metadata_and_reload() {
    let upstream = upstream();
    let mut config = control_config(upstream.address());
    config.dnssec_validate = true;
    config.trust_anchor = Some(TrustAnchorSetting::Embedded);
    let server = Server::start(&config).expect("server");
    let addr = server.control_addr().expect("control addr");

    let response = request(addr, "GET", "/api/v1/trust-anchors", &[], Some(TOKEN));
    assert_eq!(response.status, 200);
    let body = response.json();
    assert_eq!(body["enabled"], true);
    let anchors = body["anchors"].as_array().expect("anchors array");
    assert_ne!(anchors.len(), 0);
    for anchor in anchors {
        assert!(anchor["key_tag"].as_u64().is_some());
        assert!(anchor["algorithm"].as_u64().is_some());
        assert!(anchor["state"].as_str().is_some());
        assert!(anchor.get("valid_from").is_some());
    }
    let text = String::from_utf8_lossy(&response.body);
    assert!(!text.contains("PRIVATE"));
    assert!(!text.contains("private_key"));

    let reload = request(
        addr,
        "POST",
        "/api/v1/trust-anchors/reload",
        &[],
        Some(TOKEN),
    );
    assert_eq!(reload.status, 200);
    assert_eq!(reload.json()["reloaded"], true);
    drop(server);
}

#[test]
fn trust_anchor_file_reload_applies_new_ds() {
    let upstream = upstream();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("root.ds");
    let digest = "e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d";
    std::fs::write(&path, format!(". DS 12345 8 2 {digest}\n")).expect("write ds");

    let mut config = control_config(upstream.address());
    config.dnssec_validate = true;
    config.trust_anchor = Some(TrustAnchorSetting::PathFile(path.clone()));
    let server = Server::start(&config).expect("server");
    let addr = server.control_addr().expect("control addr");

    let before = request(addr, "GET", "/api/v1/trust-anchors", &[], Some(TOKEN));
    assert_eq!(before.status, 200);
    assert_eq!(before.json()["anchors"][0]["key_tag"], 12345);

    std::fs::write(&path, format!(". DS 23456 8 2 {digest}\n")).expect("rewrite ds");
    let reload = request(
        addr,
        "POST",
        "/api/v1/trust-anchors/reload",
        &[],
        Some(TOKEN),
    );
    assert_eq!(reload.status, 200);
    assert_eq!(reload.json()["count"], 1);

    let after = request(addr, "GET", "/api/v1/trust-anchors", &[], Some(TOKEN));
    assert_eq!(after.json()["anchors"][0]["key_tag"], 23456);
    assert!(!String::from_utf8_lossy(&after.body).contains("digest\":"));
    drop(server);
}

#[test]
fn rrl_patch_applies_valid_limits_and_rejects_invalid() {
    let upstream = upstream();
    let mut config = control_config(upstream.address());
    config.rrl = Some(RrlSetting::default());
    let server = Server::start(&config).expect("server");
    let addr = server.control_addr().expect("control addr");

    let initial = request(addr, "GET", "/api/v1/rrl/stats", &[], Some(TOKEN));
    assert_eq!(initial.status, 200);
    assert_eq!(initial.json()["enabled"], true);

    let patch = request(
        addr,
        "PATCH",
        "/api/v1/rrl",
        br#"{"slip":7,"action":"drop","nxdomain":{"qps":2.5,"burst":9}}"#,
        Some(TOKEN),
    );
    assert_eq!(patch.status, 200);
    assert_eq!(patch.json()["slip"], 7);
    assert_eq!(patch.json()["action"], "drop");
    assert_eq!(patch.json()["classes"]["nxdomain"]["qps"], 2.5);
    assert_eq!(patch.json()["classes"]["nxdomain"]["burst"], 9);

    let stats = request(addr, "GET", "/api/v1/rrl/stats", &[], Some(TOKEN));
    assert_eq!(stats.json()["classes"]["nxdomain"]["qps"], 2.5);

    let invalid = request(
        addr,
        "PATCH",
        "/api/v1/rrl",
        br#"{"nxdomain":{"qps":-1}}"#,
        Some(TOKEN),
    );
    assert_eq!(invalid.status, 400);
    let unknown = request(addr, "PATCH", "/api/v1/rrl", br#"{"bogus":1}"#, Some(TOKEN));
    assert_eq!(unknown.status, 400);
    drop(server);
}

#[test]
fn body_limit_garbage_json_and_urls_do_not_panic() {
    let upstream = upstream();
    let config = control_config(upstream.address());
    let server = Server::start(&config).expect("server");
    let addr = server.control_addr().expect("control addr");

    let oversized = format!(
        "GET /api/v1/cache/stats HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {TOKEN}\r\nContent-Length: {}\r\n\r\n",
        1024 * 1024 + 1
    );
    let response = raw_request(addr, oversized.as_bytes());
    assert_eq!(response.status, 413);

    let garbage = request(addr, "POST", "/api/v1/cache/purge", b"{", Some(TOKEN));
    assert_eq!(garbage.status, 400);
    assert_eq!(
        garbage.header("content-type"),
        Some("application/problem+json")
    );

    let bad_url = request(addr, "GET", "/api/v1/%zz", &[], Some(TOKEN));
    assert_eq!(bad_url.status, 404);

    let malformed = raw_request(addr, b"GARBAGE\r\n\r\n");
    assert_eq!(malformed.status, 400);

    let bad_version = raw_request(addr, b"GET /healthz HTTP/9.9\r\nHost: localhost\r\n\r\n");
    assert_eq!(bad_version.status, 505);
    drop(server);
}

#[test]
fn rate_limit_is_per_token_and_returns_429() {
    let upstream = upstream();
    let mut config = control_config(upstream.address());
    config.control = ControlSetting {
        rate_limit_qps: 0.001,
        rate_limit_burst: 2,
        ..ControlSetting::default()
    };
    let server = Server::start(&config).expect("server");
    let addr = server.control_addr().expect("control addr");

    for _ in 0..2 {
        let response = request(addr, "GET", "/api/v1/cache/stats", &[], Some(TOKEN));
        assert_eq!(response.status, 200);
    }
    let limited = request(addr, "GET", "/api/v1/cache/stats", &[], Some(TOKEN));
    assert_eq!(limited.status, 429);
    assert_eq!(limited.header("retry-after"), Some("1"));
    assert_eq!(limited.json()["code"], "rate-limited");

    // Публичные health-эндпоинты не расходуют токен-бакет.
    let health = request(addr, "GET", "/healthz", &[], None);
    assert_eq!(health.status, 200);
    drop(server);
}

#[test]
fn graceful_shutdown_closes_listener_and_idle_connection() {
    let upstream = upstream();
    let config = control_config(upstream.address());
    let mut server = Server::start(&config).expect("server");
    let addr = server.control_addr().expect("control addr");
    let idle = TcpStream::connect(addr).expect("idle connection");
    let started = Instant::now();
    server.shutdown().expect("shutdown");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "shutdown must not wait for the full read timeout"
    );
    drop(idle);
    assert!(TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_err());
}

#[test]
fn config_endpoint_never_exposes_secrets() {
    let upstream = upstream();
    let mut config = control_config(upstream.address());
    config.dnssec_validate = true;
    config.trust_anchor = Some(TrustAnchorSetting::Embedded);
    let server = Server::start(&config).expect("server");
    let addr = server.control_addr().expect("control addr");

    let response = request(addr, "GET", "/api/v1/config", &[], Some(TOKEN));
    assert_eq!(response.status, 200);
    let text = String::from_utf8_lossy(&response.body);
    assert!(!text.contains(TOKEN));
    assert!(!text.contains("tls_key"));
    assert!(!text.contains("dnscrypt_provider_key"));
    let body = response.json();
    assert_eq!(body["mode"], "forward");
    assert_eq!(body["control"]["rate_limit_burst"], 100);
    drop(server);
}
