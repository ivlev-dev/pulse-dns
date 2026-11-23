//! End-to-end HTTP tests через стандартный `TcpStream`.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::sync::Barrier;
use std::time::Duration;

use pulse_api::auth::TokenConfig;
use pulse_api::config::ApiConfig;
use pulse_api::memory::InMemoryZoneAdmin;
use pulse_api::server::{RunningServer, serve};
use serde_json::Value;

const ADMIN: &str = "pd_live_admin_0123456789abcdef";
const READER: &str = "pd_live_reader_0123456789abcdef";
const WRITER: &str = "pd_live_writer_0123456789abcdef";
const DELETER: &str = "pd_live_deleter_0123456789abcdef";
const SCOPED: &str = "pd_live_scoped_0123456789abcdef";
const SCOPED_READER: &str = "pd_live_scopedreader_0123456789ab";

struct TestServer {
    server: Option<RunningServer>,
    addr: SocketAddr,
}

impl TestServer {
    fn start() -> Self {
        Self::start_with(|config| {
            config.rate_limit_per_sec = 1000;
        })
    }

    fn start_with(customize: impl FnOnce(&mut ApiConfig)) -> Self {
        let tokens = vec![
            token("admin", ADMIN, &["admin"], None),
            token("reader", READER, &["zones:read"], None),
            token("writer", WRITER, &["zones:read", "zones:write"], None),
            token(
                "deleter",
                DELETER,
                &["zones:read", "zones:write", "zones:delete"],
                None,
            ),
            token(
                "scoped",
                SCOPED,
                &["zones:read", "zones:write"],
                Some(&["*.internal."]),
            ),
            token(
                "scoped-reader",
                SCOPED_READER,
                &["zones:read"],
                Some(&["*.internal."]),
            ),
        ];
        let mut config = ApiConfig::new(tokens);
        config.bind = SocketAddr::from(([127, 0, 0, 1], 0));
        customize(&mut config);
        let store = Arc::new(InMemoryZoneAdmin::new());
        let server = serve(config, store).expect("server should start");
        let addr = server.addr();
        Self {
            server: Some(server),
            addr,
        }
    }

    fn addr(&self) -> SocketAddr {
        self.addr
    }

    fn shutdown(&mut self) {
        if let Some(server) = self.server.take() {
            server.shutdown();
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn token(id: &str, secret: &str, scopes: &[&str], zone_scope: Option<&[&str]>) -> TokenConfig {
    TokenConfig {
        id: id.to_owned(),
        token: secret.to_owned(),
        scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
        zone_scope: zone_scope.map(|patterns| {
            patterns
                .iter()
                .map(|pattern| (*pattern).to_owned())
                .collect()
        }),
    }
}

#[derive(Debug)]
struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("response should be JSON")
    }

    fn problem_code(&self) -> String {
        self.json()["code"].as_str().unwrap_or_default().to_owned()
    }
}

fn request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> Response {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .expect("write timeout");
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
    let mut has_content_type = false;
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-type") {
            has_content_type = true;
        }
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    if body.is_some() && !has_content_type {
        head.push_str("Content-Type: application/json\r\n");
    }
    if let Some(body) = body {
        head.push_str("Content-Length: ");
        head.push_str(&body.len().to_string());
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).expect("write head");
    if let Some(body) = body {
        stream.write_all(body).expect("write body");
    }
    stream.flush().expect("flush");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read response");
    parse_response(&raw)
}

fn parse_response(raw: &[u8]) -> Response {
    let header_end = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("response header terminator");
    let header_block = std::str::from_utf8(&raw[..header_end]).expect("ASCII headers");
    let mut lines = header_block.split("\r\n");
    let status_line = lines.next().expect("status line");
    let status = status_line
        .split(' ')
        .nth(1)
        .expect("status code")
        .parse::<u16>()
        .expect("numeric status");
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_owned(), value.trim().to_owned()))
        .collect();
    Response {
        status,
        headers,
        body: raw.get(header_end + 4..).expect("body").to_vec(),
    }
}

fn bearer(secret: &str) -> String {
    format!("Bearer {secret}")
}

fn create_zone(addr: SocketAddr, origin: &str) -> Response {
    request(
        addr,
        "PUT",
        &format!("/api/v1/zones/{origin}"),
        &[("Authorization", &bearer(ADMIN)), ("If-None-Match", "*")],
        Some(br#"{"kind":"primary","default_ttl":3600}"#),
    )
}

#[test]
fn health_ready_metrics_and_openapi() {
    let server = TestServer::start();
    let addr = server.addr();
    let health = request(addr, "GET", "/healthz", &[], None);
    assert_eq!(health.status, 200);
    assert_eq!(health.json()["status"], "ok");
    assert!(health.header("x-request-id").is_some());
    let ready = request(addr, "GET", "/readyz", &[], None);
    assert_eq!(ready.status, 200);
    let metrics = request(addr, "GET", "/metrics", &[], None);
    assert_eq!(metrics.status, 200);
    assert!(metrics.text().contains("pulse_api_requests_total"));
    let openapi = request(
        addr,
        "GET",
        "/api/v1/openapi.json",
        &[("Authorization", &bearer(ADMIN))],
        None,
    );
    assert_eq!(openapi.status, 200);
    assert_eq!(openapi.json()["openapi"], "3.1.0");
    let unauthorized = request(addr, "GET", "/api/v1/openapi.json", &[], None);
    assert_eq!(unauthorized.status, 401);
}

#[test]
fn authentication_and_scopes() {
    let server = TestServer::start();
    let addr = server.addr();
    let missing = request(addr, "GET", "/api/v1/zones", &[], None);
    assert_eq!(missing.status, 401);
    assert_eq!(missing.problem_code(), "unauthenticated");
    assert_eq!(missing.header("www-authenticate"), Some("Bearer"));
    assert!(
        missing
            .header("content-type")
            .is_some_and(|value| value.contains("application/problem+json"))
    );
    let invalid = request(
        addr,
        "GET",
        "/api/v1/zones",
        &[("Authorization", "Bearer nope")],
        None,
    );
    assert_eq!(invalid.status, 401);
    let read = request(
        addr,
        "GET",
        "/api/v1/zones",
        &[("Authorization", &bearer(READER))],
        None,
    );
    assert_eq!(read.status, 200);
    let write = request(
        addr,
        "PUT",
        "/api/v1/zones/example.com.",
        &[("Authorization", &bearer(READER)), ("If-None-Match", "*")],
        Some(br"{}"),
    );
    assert_eq!(write.status, 403);
    assert_eq!(write.problem_code(), "forbidden");
}

#[test]
fn zone_crud_and_etag() {
    let server = TestServer::start();
    let addr = server.addr();
    let created = create_zone(addr, "example.com.");
    assert_eq!(created.status, 201, "{}", created.text());
    assert_eq!(
        created.header("location"),
        Some("/api/v1/zones/example.com.")
    );
    let etag = created.header("etag").expect("etag").to_owned();
    assert_eq!(created.json()["origin"], "example.com.");

    let got = request(
        addr,
        "GET",
        "/api/v1/zones/example.com.",
        &[("Authorization", &bearer(ADMIN))],
        None,
    );
    assert_eq!(got.status, 200);
    assert_eq!(got.header("etag"), Some(etag.as_str()));

    let not_modified = request(
        addr,
        "GET",
        "/api/v1/zones/example.com.",
        &[("Authorization", &bearer(ADMIN)), ("If-None-Match", &etag)],
        None,
    );
    assert_eq!(not_modified.status, 304);
    assert_eq!(not_modified.body.len(), 0);

    let without_match = request(
        addr,
        "PUT",
        "/api/v1/zones/example.com.",
        &[("Authorization", &bearer(ADMIN))],
        Some(br#"{"default_ttl":300}"#),
    );
    assert_eq!(without_match.status, 428);
    assert_eq!(without_match.problem_code(), "precondition-required");

    let stale = request(
        addr,
        "PUT",
        "/api/v1/zones/example.com.",
        &[
            ("Authorization", &bearer(ADMIN)),
            ("If-Match", "\"z-stale\""),
        ],
        Some(br#"{"default_ttl":300}"#),
    );
    assert_eq!(stale.status, 412);
    assert_eq!(stale.problem_code(), "precondition-failed");
    assert!(stale.json()["current_etag"].is_string());
    assert!(stale.json()["current_version"].is_number());

    let replaced = request(
        addr,
        "PUT",
        "/api/v1/zones/example.com.",
        &[("Authorization", &bearer(ADMIN)), ("If-Match", &etag)],
        Some(br#"{"default_ttl":300}"#),
    );
    assert_eq!(replaced.status, 200);
    let new_etag = replaced.header("etag").expect("etag").to_owned();
    assert_ne!(etag, new_etag);

    let delete_stale = request(
        addr,
        "DELETE",
        "/api/v1/zones/example.com.",
        &[("Authorization", &bearer(ADMIN)), ("If-Match", &etag)],
        None,
    );
    assert_eq!(delete_stale.status, 412);
    let deleted = request(
        addr,
        "DELETE",
        "/api/v1/zones/example.com.",
        &[("Authorization", &bearer(ADMIN)), ("If-Match", &new_etag)],
        None,
    );
    assert_eq!(deleted.status, 204);
    let gone = request(
        addr,
        "GET",
        "/api/v1/zones/example.com.",
        &[("Authorization", &bearer(ADMIN))],
        None,
    );
    assert_eq!(gone.status, 404);
    assert_eq!(gone.problem_code(), "zone_not_found");
}

#[test]
fn zone_scope_is_indistinguishable_from_missing() {
    let server = TestServer::start();
    let addr = server.addr();
    assert_eq!(create_zone(addr, "a.example.").status, 201);
    assert_eq!(create_zone(addr, "a.internal.").status, 201);

    let outside = request(
        addr,
        "GET",
        "/api/v1/zones/a.example.",
        &[("Authorization", &bearer(SCOPED))],
        None,
    );
    let missing = request(
        addr,
        "GET",
        "/api/v1/zones/does-not-exist.example.",
        &[("Authorization", &bearer(SCOPED))],
        None,
    );
    assert_eq!(outside.status, 404);
    assert_eq!(missing.status, 404);
    assert_eq!(outside.problem_code(), "zone_not_found");
    assert_eq!(missing.problem_code(), "zone_not_found");
    assert_eq!(outside.json()["detail"], missing.json()["detail"]);

    let create_outside = request(
        addr,
        "PUT",
        "/api/v1/zones/outside.example.",
        &[("Authorization", &bearer(SCOPED)), ("If-None-Match", "*")],
        Some(br"{}"),
    );
    assert_eq!(create_outside.status, 404);

    let inside_no_scope = request(
        addr,
        "PUT",
        "/api/v1/zones/a.internal.",
        &[("Authorization", &bearer(SCOPED_READER)), ("If-Match", "*")],
        Some(br"{}"),
    );
    assert_eq!(inside_no_scope.status, 403);

    let list = request(
        addr,
        "GET",
        "/api/v1/zones",
        &[("Authorization", &bearer(SCOPED))],
        None,
    );
    assert_eq!(list.status, 200);
    let items = list.json()["items"].as_array().cloned().unwrap_or_default();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["origin"], "a.internal.");
}

#[test]
#[allow(clippy::too_many_lines)]
fn rrset_crud_patch_and_etag() {
    let server = TestServer::start();
    let addr = server.addr();
    assert_eq!(create_zone(addr, "example.com.").status, 201);
    let path = "/api/v1/zones/example.com./records/www.example.com./A";
    let created = request(
        addr,
        "PUT",
        path,
        &[("Authorization", &bearer(WRITER))],
        Some(br#"{"ttl":300,"records":["192.0.2.10"]}"#),
    );
    assert_eq!(created.status, 201, "{}", created.text());
    let etag = created.header("etag").expect("etag").to_owned();
    assert_eq!(created.json()["records"][0], "192.0.2.10");

    let got = request(
        addr,
        "GET",
        path,
        &[("Authorization", &bearer(READER))],
        None,
    );
    assert_eq!(got.status, 200);
    let not_modified = request(
        addr,
        "GET",
        path,
        &[("Authorization", &bearer(READER)), ("If-None-Match", &etag)],
        None,
    );
    assert_eq!(not_modified.status, 304);

    let replace_without_match = request(
        addr,
        "PUT",
        path,
        &[("Authorization", &bearer(WRITER))],
        Some(br#"{"ttl":300,"records":["192.0.2.20"]}"#),
    );
    assert_eq!(replace_without_match.status, 428);

    let patched = request(
        addr,
        "PATCH",
        path,
        &[("Authorization", &bearer(WRITER)), ("If-Match", &etag)],
        Some(br#"{"ttl":600,"add":["192.0.2.11"],"remove":["192.0.2.10"]}"#),
    );
    assert_eq!(patched.status, 200, "{}", patched.text());
    let body = patched.json();
    assert_eq!(body["added"], 1);
    assert_eq!(body["removed"], 1);
    assert_eq!(body["rrset"]["ttl"], 600);
    assert_eq!(body["rrset"]["records"].as_array().unwrap().len(), 1);
    assert_eq!(body["rrset"]["records"][0], "192.0.2.11");
    let etag = patched.header("etag").expect("etag").to_owned();

    let remove_last = request(
        addr,
        "PATCH",
        path,
        &[("Authorization", &bearer(WRITER)), ("If-Match", &etag)],
        Some(br#"{"remove":["192.0.2.11"]}"#),
    );
    assert_eq!(remove_last.status, 200);
    assert_eq!(remove_last.json()["deleted"], true);
    let gone = request(
        addr,
        "GET",
        path,
        &[("Authorization", &bearer(READER))],
        None,
    );
    assert_eq!(gone.status, 404);
    assert_eq!(gone.problem_code(), "rrset-not-found");

    let delete_missing = request(
        addr,
        "DELETE",
        path,
        &[("Authorization", &bearer(WRITER)), ("If-Match", "*")],
        None,
    );
    assert_eq!(delete_missing.status, 404);

    let recreate = request(
        addr,
        "PUT",
        path,
        &[("Authorization", &bearer(WRITER))],
        Some(br#"{"ttl":300,"records":["192.0.2.30"]}"#),
    );
    assert_eq!(recreate.status, 201);
    let etag = recreate.header("etag").expect("etag").to_owned();
    let deleted = request(
        addr,
        "DELETE",
        path,
        &[("Authorization", &bearer(WRITER)), ("If-Match", &etag)],
        None,
    );
    assert_eq!(deleted.status, 204);
}

#[test]
fn concurrent_if_match_has_one_winner() {
    let server = TestServer::start();
    let addr = server.addr();
    assert_eq!(create_zone(addr, "example.com.").status, 201);
    let path = "/api/v1/zones/example.com./records/www.example.com./A";
    let created = request(
        addr,
        "PUT",
        path,
        &[("Authorization", &bearer(WRITER))],
        Some(br#"{"ttl":300,"records":["192.0.2.10"]}"#),
    );
    assert_eq!(created.status, 201);
    let etag = created.header("etag").expect("etag").to_owned();
    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for address in ["192.0.2.20", "192.0.2.21"] {
        let barrier = Arc::clone(&barrier);
        let etag = etag.clone();
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            let body = format!("{{\"ttl\":300,\"records\":[\"{address}\"]}}");
            request(
                addr,
                "PUT",
                path,
                &[("Authorization", &bearer(WRITER)), ("If-Match", &etag)],
                Some(body.as_bytes()),
            )
            .status
        }));
    }
    let mut statuses: Vec<u16> = handles
        .into_iter()
        .map(|handle| handle.join().expect("thread"))
        .collect();
    statuses.sort_unstable();
    assert_eq!(statuses, vec![200, 412]);
}

#[test]
fn problem_json_and_input_validation() {
    let server = TestServer::start();
    let addr = server.addr();
    let unknown = request(
        addr,
        "GET",
        "/api/v1/zones/missing.example.",
        &[("Authorization", &bearer(ADMIN))],
        None,
    );
    assert_eq!(unknown.status, 404);
    assert!(
        unknown
            .header("content-type")
            .is_some_and(|value| value.contains("application/problem+json"))
    );
    let body = unknown.json();
    for field in [
        "type",
        "title",
        "status",
        "detail",
        "code",
        "instance",
        "request_id",
    ] {
        assert!(body.get(field).is_some(), "missing {field}");
    }
    assert_eq!(body["status"], 404);

    let malformed = request(
        addr,
        "PUT",
        "/api/v1/zones/example.com.",
        &[("Authorization", &bearer(ADMIN)), ("If-None-Match", "*")],
        Some(b"{not json"),
    );
    assert_eq!(malformed.status, 400);
    assert_eq!(malformed.problem_code(), "bad-request");

    let wrong_content_type = request(
        addr,
        "PUT",
        "/api/v1/zones/example.com.",
        &[
            ("Authorization", &bearer(ADMIN)),
            ("Content-Type", "text/plain"),
            ("If-None-Match", "*"),
        ],
        Some(b"{}"),
    );
    assert_eq!(wrong_content_type.status, 415);

    let bad_encoding = request(
        addr,
        "GET",
        "/api/v1/zones/%ZZ",
        &[("Authorization", &bearer(ADMIN))],
        None,
    );
    assert_eq!(bad_encoding.status, 400);

    let trace = request(
        addr,
        "TRACE",
        "/api/v1/zones",
        &[("Authorization", &bearer(ADMIN))],
        None,
    );
    assert_eq!(trace.status, 405);
    assert!(trace.header("allow").is_some());

    let bad_limit = request(
        addr,
        "GET",
        "/api/v1/zones?limit=501",
        &[("Authorization", &bearer(ADMIN))],
        None,
    );
    assert_eq!(bad_limit.status, 400);
    let bad_cursor = request(
        addr,
        "GET",
        "/api/v1/zones?cursor=%%%",
        &[("Authorization", &bearer(ADMIN))],
        None,
    );
    assert_eq!(bad_cursor.status, 400);

    let invalid_rdata = request(
        addr,
        "PUT",
        "/api/v1/zones/example.com./records/www.example.com./A",
        &[("Authorization", &bearer(ADMIN))],
        Some(br#"{"ttl":300,"records":["not-an-ip"]}"#),
    );
    assert_eq!(invalid_rdata.status, 422);
    assert_eq!(invalid_rdata.problem_code(), "validation-failed");
    assert!(
        invalid_rdata.json()["errors"]
            .as_array()
            .is_some_and(|errors| !errors.is_empty())
    );
}

#[test]
fn body_limit_is_enforced_before_reading() {
    let server = TestServer::start();
    let addr = server.addr();
    let limit = 16 * 1024 * 1024 + 1;
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    let head = format!(
        "PUT /api/v1/zones/example.com. HTTP/1.1\r\nHost: localhost\r\nAuthorization: {}\r\nContent-Type: application/json\r\nContent-Length: {limit}\r\nConnection: close\r\n\r\n",
        bearer(ADMIN)
    );
    stream.write_all(head.as_bytes()).expect("write");
    stream.flush().expect("flush");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read");
    let response = parse_response(&raw);
    assert_eq!(response.status, 413);
    assert_eq!(response.problem_code(), "payload-too-large");
}

#[test]
fn idempotency_replay_and_conflict() {
    let server = TestServer::start();
    let addr = server.addr();
    let path = "/api/v1/zones/example.com.";
    let first = request(
        addr,
        "PUT",
        path,
        &[
            ("Authorization", &bearer(ADMIN)),
            ("If-None-Match", "*"),
            ("Idempotency-Key", "order-12345678"),
        ],
        Some(br#"{"default_ttl":3600}"#),
    );
    assert_eq!(first.status, 201);
    let replay = request(
        addr,
        "PUT",
        path,
        &[
            ("Authorization", &bearer(ADMIN)),
            ("If-None-Match", "*"),
            ("Idempotency-Key", "order-12345678"),
        ],
        Some(br#"{"default_ttl":3600}"#),
    );
    assert_eq!(replay.status, 201);
    assert_eq!(replay.header("idempotent-replay"), Some("true"));
    assert_eq!(replay.json()["origin"], "example.com.");
    let conflict = request(
        addr,
        "PUT",
        path,
        &[
            ("Authorization", &bearer(ADMIN)),
            ("Idempotency-Key", "order-12345678"),
        ],
        Some(br#"{"default_ttl":300}"#),
    );
    assert_eq!(conflict.status, 409);
    assert_eq!(conflict.problem_code(), "idempotency-key-reuse");
    let invalid = request(
        addr,
        "PUT",
        "/api/v1/zones/other.example.",
        &[
            ("Authorization", &bearer(ADMIN)),
            ("Idempotency-Key", "short"),
        ],
        Some(br"{}"),
    );
    assert_eq!(invalid.status, 400);
}

#[test]
fn pagination_walks_all_zones() {
    let server = TestServer::start();
    let addr = server.addr();
    for index in 0..5 {
        let origin = format!("z{index}.example.");
        assert_eq!(create_zone(addr, &origin).status, 201);
    }
    let mut cursor: Option<String> = None;
    let mut seen = Vec::new();
    loop {
        let path = match &cursor {
            Some(cursor) => format!(
                "/api/v1/zones?limit=2&cursor={}",
                cursor.replace('+', "%2B").replace('/', "%2F")
            ),
            None => "/api/v1/zones?limit=2".to_owned(),
        };
        let response = request(
            addr,
            "GET",
            &path,
            &[("Authorization", &bearer(ADMIN))],
            None,
        );
        assert_eq!(response.status, 200, "{}", response.text());
        let body = response.json();
        let items = body["items"].as_array().cloned().unwrap_or_default();
        for item in &items {
            seen.push(item["origin"].as_str().unwrap_or_default().to_owned());
        }
        if body["has_more"] == false {
            break;
        }
        cursor = body["next_cursor"].as_str().map(str::to_owned);
        assert!(cursor.is_some());
    }
    seen.sort();
    seen.dedup();
    assert_eq!(seen.len(), 5);
}

#[test]
fn settings_patch_requires_if_match_and_bumps_zone_etag() {
    let server = TestServer::start();
    let addr = server.addr();
    let created = create_zone(addr, "example.com.");
    assert_eq!(created.status, 201);
    let zone_etag = created.header("etag").expect("etag").to_owned();
    let path = "/api/v1/zones/example.com./settings";
    let settings = request(
        addr,
        "GET",
        path,
        &[("Authorization", &bearer(READER))],
        None,
    );
    assert_eq!(settings.status, 200);
    assert_eq!(settings.json()["default_ttl"], 3600);
    let settings_etag = settings.header("etag").expect("etag").to_owned();

    let missing = request(
        addr,
        "PATCH",
        path,
        &[("Authorization", &bearer(WRITER))],
        Some(br#"{"default_ttl":600}"#),
    );
    assert_eq!(missing.status, 428);

    let patched = request(
        addr,
        "PATCH",
        path,
        &[
            ("Authorization", &bearer(WRITER)),
            ("If-Match", &settings_etag),
        ],
        Some(br#"{"default_ttl":600,"denial":"nsec3"}"#),
    );
    assert_eq!(patched.status, 200, "{}", patched.text());
    assert_eq!(patched.json()["default_ttl"], 600);
    assert_eq!(patched.json()["denial"], "nsec3");
    let zone = request(
        addr,
        "GET",
        "/api/v1/zones/example.com.",
        &[("Authorization", &bearer(READER))],
        None,
    );
    assert_eq!(zone.status, 200);
    assert_ne!(zone.header("etag"), Some(zone_etag.as_str()));
    assert_eq!(zone.json()["default_ttl"], 600);
    assert_eq!(zone.json()["denial"], "nsec3");
}

#[test]
fn rate_limit_returns_429_and_headers() {
    let server = TestServer::start_with(|config| {
        config.rate_limit_per_sec = 1;
    });
    let addr = server.addr();
    let first = request(
        addr,
        "GET",
        "/api/v1/zones",
        &[("Authorization", &bearer(ADMIN))],
        None,
    );
    assert_eq!(first.status, 200);
    let second = request(
        addr,
        "GET",
        "/api/v1/zones",
        &[("Authorization", &bearer(ADMIN))],
        None,
    );
    assert_eq!(second.status, 429);
    assert_eq!(second.problem_code(), "rate-limited");
    assert!(second.header("retry-after").is_some());
    assert!(second.header("ratelimit-limit").is_some());
    assert!(second.header("ratelimit-remaining").is_some());
}

#[test]
fn graceful_shutdown_stops_listener() {
    let mut server = TestServer::start();
    let addr = server.addr();
    assert_eq!(request(addr, "GET", "/healthz", &[], None).status, 200);
    server.shutdown();
    assert!(TcpStream::connect(addr).is_err());
}

#[test]
fn read_timeout_is_enforced() {
    let server = TestServer::start_with(|config| {
        config.request_timeout = Duration::from_millis(200);
    });
    let addr = server.addr();
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n")
        .expect("partial write");
    stream.flush().expect("flush");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read response");
    let response = parse_response(&raw);
    assert_eq!(response.status, 408);
}

#[test]
fn garbage_request_does_not_panic() {
    let server = TestServer::start();
    let addr = server.addr();
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    stream
        .write_all(b"\x00\xff\xfeGARBAGE\r\n\r\n")
        .expect("write");
    stream.flush().expect("flush");
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    let response = parse_response(&raw);
    assert_eq!(response.status, 400);
    let still_alive = request(addr, "GET", "/healthz", &[], None);
    assert_eq!(still_alive.status, 200);
}

#[test]
fn zone_body_validation_and_if_match_wildcard() {
    let server = TestServer::start();
    let addr = server.addr();
    let mismatch = request(
        addr,
        "PUT",
        "/api/v1/zones/example.com.",
        &[("Authorization", &bearer(ADMIN)), ("If-None-Match", "*")],
        Some(br#"{"origin":"other.example."}"#),
    );
    assert_eq!(mismatch.status, 422);
    assert_eq!(mismatch.json()["errors"][0]["pointer"], "/origin");

    let created = create_zone(addr, "example.com.");
    assert_eq!(created.status, 201);
    let replaced = request(
        addr,
        "PUT",
        "/api/v1/zones/example.com.",
        &[("Authorization", &bearer(ADMIN)), ("If-Match", "*")],
        Some(br#"{"default_ttl":120}"#),
    );
    assert_eq!(replaced.status, 200);
    let missing = request(
        addr,
        "PUT",
        "/api/v1/zones/missing.example.",
        &[("Authorization", &bearer(ADMIN)), ("If-Match", "*")],
        Some(br"{}"),
    );
    assert_eq!(missing.status, 412);

    let cname = request(
        addr,
        "PUT",
        "/api/v1/zones/example.com./records/alias.example.com./CNAME",
        &[("Authorization", &bearer(ADMIN))],
        Some(br#"{"ttl":300,"records":["target.example.com."]}"#),
    );
    assert_eq!(cname.status, 201);
    let conflict = request(
        addr,
        "PUT",
        "/api/v1/zones/example.com./records/alias.example.com./A",
        &[("Authorization", &bearer(ADMIN))],
        Some(br#"{"ttl":300,"records":["192.0.2.1"]}"#),
    );
    assert_eq!(conflict.status, 422);
    assert_eq!(conflict.json()["errors"][0]["code"], "cname-conflict");
}

#[test]
fn aliases_and_rrset_listing() {
    let server = TestServer::start();
    let addr = server.addr();
    assert_eq!(create_zone(addr, "example.com.").status, 201);
    for (owner, address) in [
        ("a.example.com.", "192.0.2.1"),
        ("b.example.com.", "192.0.2.2"),
    ] {
        let path = format!("/api/v1/zones/example.com./rrsets/{owner}/A");
        let created = request(
            addr,
            "PUT",
            &path,
            &[("Authorization", &bearer(WRITER))],
            Some(format!("{{\"ttl\":300,\"records\":[\"{address}\"]}}").as_bytes()),
        );
        assert_eq!(created.status, 201);
    }
    let list = request(
        addr,
        "GET",
        "/api/v1/zones/example.com./rrsets?limit=1",
        &[("Authorization", &bearer(READER))],
        None,
    );
    assert_eq!(list.status, 200);
    assert_eq!(list.json()["items"].as_array().unwrap().len(), 1);
    assert_eq!(list.json()["has_more"], true);
    let cursor = list.json()["next_cursor"]
        .as_str()
        .expect("cursor")
        .to_owned();
    let path = format!("/api/v1/zones/example.com./rrsets?limit=1&cursor={cursor}");
    let second = request(
        addr,
        "GET",
        &path,
        &[("Authorization", &bearer(READER))],
        None,
    );
    assert_eq!(second.status, 200);
    assert_eq!(second.json()["items"].as_array().unwrap().len(), 1);
    let filtered = request(
        addr,
        "GET",
        "/api/v1/zones/example.com./rrsets?type=A&owner=a.example.com.",
        &[("Authorization", &bearer(READER))],
        None,
    );
    assert_eq!(filtered.status, 200);
    assert_eq!(filtered.json()["items"].as_array().unwrap().len(), 1);
}
