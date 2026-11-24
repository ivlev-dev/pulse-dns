//! Интеграция REST API и DNS: мутации через HTTP видны UDP-запросам сразу.

mod common;

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

use pulse_dns::{
    DecodeLimits, EncodeOptions, Message, Name, Question, Rclass, Rcode, Rdata, Rtype,
};
use pulsed::config::Config;
use pulsed::server::{ApiOptions, Server};

const TOKEN: &str = "pd_live_pulsed_integration_0123456789abcdef";
const ORIGIN: &str = "dynamic.test.";
const ZONE_PATH: &str = "/api/v1/zones/dynamic.test.";

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

    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or(serde_json::Value::Null)
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
    let mut stream = TcpStream::connect(addr).expect("connect API");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
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
        let _ = write!(head, "Content-Length: {}\r\n", body.len());
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).expect("write head");
    if let Some(body) = body {
        stream.write_all(body).expect("write body");
    }
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read response");
    parse_response(&raw)
}

fn parse_response(raw: &[u8]) -> Response {
    let header_end = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("header terminator");
    let header_block = std::str::from_utf8(&raw[..header_end]).expect("ASCII headers");
    let mut lines = header_block.split("\r\n");
    let status = lines
        .next()
        .expect("status line")
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

fn auth() -> String {
    format!("Bearer {TOKEN}")
}

fn rrset_path(owner: &str, rr_type: &str) -> String {
    format!("{ZONE_PATH}/records/{owner}/{rr_type}")
}

fn test_config() -> (common::TempZone, Config) {
    let zone = common::TempZone::empty("api");
    let config = common::base_config(zone.path());
    (zone, config)
}

fn recv_from(socket: &UdpSocket, buffer: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
    loop {
        match socket.recv_from(buffer) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            result => return result,
        }
    }
}

fn dns_query(server: &Server, qname: &str, qtype: Rtype) -> Message {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("client socket");
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("read timeout");
    let query = Message::query(
        0x7711,
        Question::new(Name::parse(qname).expect("valid qname"), qtype, Rclass::IN),
    )
    .encode(&EncodeOptions::compressed())
    .expect("encode query");
    socket
        .send_to(&query, server.udp_addr().expect("udp enabled"))
        .expect("send query");
    let mut buffer = [0_u8; 4096];
    let (length, _) = recv_from(&socket, &mut buffer).expect("recv response");
    Message::decode(&buffer[..length], &DecodeLimits::default()).expect("decode response")
}

fn assert_a(server: &Server, expected: &str) {
    let response = dns_query(server, "www.dynamic.test.", Rtype::A);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert!(response.flags().aa());
    assert_eq!(response.answers().len(), 1);
    assert_eq!(
        response.answers()[0].rdata(),
        &Rdata::A(expected.parse().expect("ipv4"))
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn api_mutations_are_visible_to_dns() {
    let (_zone, config) = test_config();
    let mut server = Server::start_with_api(
        &config,
        Some(ApiOptions {
            listen: "127.0.0.1:0".parse().expect("api"),
            token: TOKEN.to_owned(),
            scopes: vec![ORIGIN.to_owned()],
        }),
    )
    .expect("start DNS+API");
    let api = server.api_addr().expect("api enabled");
    let udp = server.udp_addr().expect("udp enabled");

    let unauthorized = request(api, "GET", "/api/v1/zones", &[], None);
    assert_eq!(unauthorized.status, 401);
    assert_eq!(unauthorized.problem_code(), "unauthenticated");

    let bearer = auth();
    let outside_scope = request(
        api,
        "GET",
        "/api/v1/zones/blocked.test.",
        &[("Authorization", &bearer)],
        None,
    );
    assert_eq!(outside_scope.status, 404);
    assert_eq!(outside_scope.problem_code(), "zone_not_found");

    let created = request(
        api,
        "PUT",
        ZONE_PATH,
        &[("Authorization", &bearer), ("If-None-Match", "*")],
        Some(br#"{"kind":"primary","default_ttl":3600}"#),
    );
    assert_eq!(
        created.status,
        201,
        "{}",
        String::from_utf8_lossy(&created.body)
    );

    // Зона без apex SOA/NS — Initializing, DNS отвечает REFUSED.
    let response = dns_query(&server, "www.dynamic.test.", Rtype::A);
    assert_eq!(response.rcode(), Rcode::REFUSED);

    let soa = "ns1.dynamic.test. hostmaster.dynamic.test. 1 3600 600 604800 300";
    let created = request(
        api,
        "PUT",
        &rrset_path(ORIGIN, "SOA"),
        &[("Authorization", &bearer)],
        Some(format!(r#"{{"ttl":3600,"records":["{soa}"]}}"#).as_bytes()),
    );
    assert_eq!(
        created.status,
        201,
        "{}",
        String::from_utf8_lossy(&created.body)
    );

    // SOA есть, NS нет — зона всё ещё не обслуживается.
    let response = dns_query(&server, "www.dynamic.test.", Rtype::A);
    assert_eq!(response.rcode(), Rcode::REFUSED);

    let created = request(
        api,
        "PUT",
        &rrset_path(ORIGIN, "NS"),
        &[("Authorization", &bearer)],
        Some(br#"{"ttl":3600,"records":["ns1.dynamic.test."]}"#),
    );
    assert_eq!(
        created.status,
        201,
        "{}",
        String::from_utf8_lossy(&created.body)
    );

    let created = request(
        api,
        "PUT",
        &rrset_path("www.dynamic.test.", "A"),
        &[("Authorization", &bearer)],
        Some(br#"{"ttl":300,"records":["192.0.2.55"]}"#),
    );
    assert_eq!(
        created.status,
        201,
        "{}",
        String::from_utf8_lossy(&created.body)
    );
    let a_etag = created.header("etag").expect("rrset etag").to_owned();

    assert_a(&server, "192.0.2.55");

    let patched = request(
        api,
        "PATCH",
        &rrset_path("www.dynamic.test.", "A"),
        &[("Authorization", &bearer), ("If-Match", &a_etag)],
        Some(br#"{"ttl":300,"add":["192.0.2.66"],"remove":["192.0.2.55"]}"#),
    );
    assert_eq!(
        patched.status,
        200,
        "{}",
        String::from_utf8_lossy(&patched.body)
    );
    let a_etag = patched.header("etag").expect("patched etag").to_owned();

    assert_a(&server, "192.0.2.66");

    let deleted = request(
        api,
        "DELETE",
        &rrset_path("www.dynamic.test.", "A"),
        &[("Authorization", &bearer), ("If-Match", &a_etag)],
        None,
    );
    assert_eq!(
        deleted.status,
        204,
        "{}",
        String::from_utf8_lossy(&deleted.body)
    );

    // Имя остаётся существующим empty node: NODATA, а не NXDOMAIN.
    let response = dns_query(&server, "www.dynamic.test.", Rtype::A);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert!(response.flags().aa());
    assert_eq!(response.answers().len(), 0);

    let zone = request(api, "GET", ZONE_PATH, &[("Authorization", &bearer)], None);
    assert_eq!(zone.status, 200);
    let zone_etag = zone.header("etag").expect("zone etag").to_owned();
    let deleted = request(
        api,
        "DELETE",
        &format!("{ZONE_PATH}?confirm_origin={ORIGIN}"),
        &[("Authorization", &bearer), ("If-Match", &zone_etag)],
        None,
    );
    assert_eq!(
        deleted.status,
        204,
        "{}",
        String::from_utf8_lossy(&deleted.body)
    );

    // Удалённая зона не обслуживается: REFUSED.
    let response = dns_query(&server, "www.dynamic.test.", Rtype::A);
    assert_eq!(response.rcode(), Rcode::REFUSED);

    let metrics = request(api, "GET", "/metrics", &[("Authorization", &bearer)], None);
    assert_eq!(metrics.status, 200);
    let body = String::from_utf8_lossy(&metrics.body);
    assert!(body.contains("zonefile_snapshot_pins "), "{body}");
    assert!(body.contains("zonefile_lookups "), "{body}");
    assert!(body.contains("zonefile_commits "), "{body}");
    assert!(body.contains("zonefile_commit_errors "), "{body}");
    assert!(
        !body.contains("zonefile_lookups 0\n"),
        "DNS answers must use zonefile lookups: {body}"
    );

    server.shutdown().expect("shutdown");
    assert!(TcpStream::connect(api).is_err(), "API listener must close");
    let socket = UdpSocket::bind("127.0.0.1:0").expect("client socket");
    socket
        .set_read_timeout(Some(Duration::from_millis(300)))
        .expect("timeout");
    let query = Message::query(
        1,
        Question::new(
            Name::parse("www.dynamic.test.").expect("name"),
            Rtype::A,
            Rclass::IN,
        ),
    )
    .encode(&EncodeOptions::compressed())
    .expect("encode");
    socket.send_to(&query, udp).expect("send");
    let mut buffer = [0_u8; 512];
    assert!(
        recv_from(&socket, &mut buffer).is_err(),
        "UDP listener must close"
    );
}

fn wait_http_job(api: SocketAddr, location: &str) -> serde_json::Value {
    for _ in 0..200 {
        let response = request(api, "GET", location, &[("Authorization", &auth())], None);
        assert_eq!(
            response.status,
            200,
            "{}",
            String::from_utf8_lossy(&response.body)
        );
        let job = response.json();
        if matches!(job["state"].as_str(), Some("done" | "failed" | "cancelled")) {
            return job;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("job did not finish");
}

#[test]
#[allow(clippy::too_many_lines)]
fn api_post_serial_import_and_audit() {
    let (_zone, config) = test_config();
    let mut server = Server::start_with_api(
        &config,
        Some(ApiOptions {
            listen: "127.0.0.1:0".parse().expect("api"),
            token: TOKEN.to_owned(),
            scopes: Vec::new(),
        }),
    )
    .expect("start DNS+API");
    let api = server.api_addr().expect("api enabled");
    let bearer = auth();

    let created = request(
        api,
        "POST",
        "/api/v1/zones",
        &[
            ("Authorization", &bearer),
            ("Idempotency-Key", "pulsed-post-zone-1"),
        ],
        Some(br#"{"origin":"imported.test.","kind":"primary","default_ttl":3600}"#),
    );
    assert_eq!(
        created.status,
        201,
        "{}",
        String::from_utf8_lossy(&created.body)
    );
    assert_eq!(
        created.header("location"),
        Some("/api/v1/zones/imported.test.")
    );

    let zonefile = "$TTL 3600\n\
        @ IN SOA ns1.imported.test. hostmaster.imported.test. 7 3600 600 604800 300\n\
        @ IN NS ns1.imported.test.\n\
        www IN A 192.0.2.77\n";
    let accepted = request(
        api,
        "POST",
        "/api/v1/zones/imported.test./import",
        &[
            ("Authorization", &bearer),
            ("Content-Type", "text/plain"),
            ("Idempotency-Key", "pulsed-import-1"),
        ],
        Some(zonefile.as_bytes()),
    );
    assert_eq!(
        accepted.status,
        202,
        "{}",
        String::from_utf8_lossy(&accepted.body)
    );
    let location = accepted
        .header("location")
        .expect("job location")
        .to_owned();
    let job = wait_http_job(api, &location);
    assert_eq!(job["state"], "done");
    assert_eq!(job["result"]["applied"], true);
    assert_eq!(job["result"]["serial"], 7);

    let response = dns_query(&server, "www.imported.test.", Rtype::A);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert_eq!(
        response.answers().first().map(pulse_dns::Record::rdata),
        Some(&Rdata::A("192.0.2.77".parse().expect("ipv4")))
    );

    let serial = request(
        api,
        "GET",
        "/api/v1/zones/imported.test./serial",
        &[("Authorization", &bearer)],
        None,
    );
    assert_eq!(serial.status, 200);
    assert_eq!(serial.json()["serial"], 7);

    let incremented = request(
        api,
        "POST",
        "/api/v1/zones/imported.test./serial",
        &[("Authorization", &bearer)],
        Some(br#"{"mode":"increment"}"#),
    );
    assert_eq!(incremented.status, 200);
    assert_eq!(incremented.json()["new_serial"], 8);

    let outgoing = request(
        api,
        "POST",
        "/api/v1/zones/imported.test./transfers",
        &[("Authorization", &bearer)],
        Some(br#"{"kind":"axfr"}"#),
    );
    assert_eq!(outgoing.status, 200);
    assert_eq!(outgoing.json()["outgoing"], true);

    let transfers = request(
        api,
        "GET",
        "/api/v1/zones/imported.test./transfers",
        &[("Authorization", &bearer)],
        None,
    );
    assert_eq!(transfers.status, 200);
    assert_eq!(transfers.json()["zone"], "imported.test.");

    let audit = request(
        api,
        "GET",
        "/api/v1/audit?limit=5",
        &[("Authorization", &bearer)],
        None,
    );
    assert_eq!(audit.status, 200);
    assert!(
        audit.json()["items"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
    );

    server.shutdown().expect("shutdown");
}
