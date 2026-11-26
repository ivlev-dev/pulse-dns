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
    dns_query_id(server, qname, qtype, 0x7711)
}

fn dns_query_id(server: &Server, qname: &str, qtype: Rtype, id: u16) -> Message {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("client socket");
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("read timeout");
    let query = Message::query(
        id,
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

#[test]
#[allow(clippy::too_many_lines)]
fn response_cache_hits_and_invalidates_on_rest_mutations() {
    let (_zone, config) = test_config();
    assert!(config.response_cache.enabled, "cache enabled by default");
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
    let bearer = auth();

    let created = request(
        api,
        "PUT",
        ZONE_PATH,
        &[("Authorization", &bearer), ("If-None-Match", "*")],
        Some(br#"{"kind":"primary","default_ttl":3600}"#),
    );
    assert_eq!(created.status, 201);
    let soa = "ns1.dynamic.test. hostmaster.dynamic.test. 1 3600 600 604800 300";
    for (owner, rr_type, body) in [
        (
            ORIGIN,
            "SOA",
            format!(r#"{{"ttl":3600,"records":["{soa}"]}}"#),
        ),
        (
            ORIGIN,
            "NS",
            r#"{"ttl":3600,"records":["ns1.dynamic.test."]}"#.to_owned(),
        ),
        (
            "www.dynamic.test.",
            "A",
            r#"{"ttl":300,"records":["192.0.2.55"]}"#.to_owned(),
        ),
    ] {
        let response = request(
            api,
            "PUT",
            &rrset_path(owner, rr_type),
            &[("Authorization", &bearer)],
            Some(body.as_bytes()),
        );
        assert_eq!(
            response.status,
            201,
            "{owner}/{rr_type}: {}",
            String::from_utf8_lossy(&response.body)
        );
    }
    let etag = request(
        api,
        "GET",
        &rrset_path("www.dynamic.test.", "A"),
        &[("Authorization", &bearer)],
        None,
    )
    .header("etag")
    .expect("rrset etag")
    .to_owned();

    // Первый ответ — промах, второй с другим ID — попадание в кеш.
    let first = dns_query_id(&server, "www.dynamic.test.", Rtype::A, 0x1000);
    let second = dns_query_id(&server, "www.dynamic.test.", Rtype::A, 0x1001);
    assert_eq!(
        first.answers().first().map(pulse_dns::Record::rdata),
        second.answers().first().map(pulse_dns::Record::rdata)
    );
    let metrics = server.response_cache_metrics();
    assert!(metrics.entries >= 1, "{metrics:?}");
    assert!(metrics.hits >= 1, "{metrics:?}");

    // REST-правка поднимает версию зоны: следующий ответ обязан быть свежим.
    let patched = request(
        api,
        "PATCH",
        &rrset_path("www.dynamic.test.", "A"),
        &[("Authorization", &bearer), ("If-Match", &etag)],
        Some(br#"{"ttl":300,"add":["192.0.2.66"],"remove":["192.0.2.55"]}"#),
    );
    assert_eq!(
        patched.status,
        200,
        "{}",
        String::from_utf8_lossy(&patched.body)
    );
    let hits_before = server.response_cache_metrics().hits;
    assert_a(&server, "192.0.2.66");
    assert_eq!(
        server.response_cache_metrics().hits,
        hits_before,
        "REST edit must invalidate the cached response immediately"
    );
    // Повтор после инвалидации снова попадает в кеш.
    assert_a(&server, "192.0.2.66");
    assert!(server.response_cache_metrics().hits > hits_before);

    // Удаление зоны: ответ больше не обслуживается, записи кеша недостижимы.
    let zone = request(api, "GET", ZONE_PATH, &[("Authorization", &bearer)], None);
    let zone_etag = zone.header("etag").expect("zone etag").to_owned();
    let deleted = request(
        api,
        "DELETE",
        &format!("{ZONE_PATH}?confirm_origin={ORIGIN}"),
        &[("Authorization", &bearer), ("If-Match", &zone_etag)],
        None,
    );
    assert_eq!(deleted.status, 204);
    let response = dns_query(&server, "www.dynamic.test.", Rtype::A);
    assert_eq!(response.rcode(), Rcode::REFUSED);

    let rendered = request(api, "GET", "/metrics", &[("Authorization", &bearer)], None);
    assert_eq!(rendered.status, 200);
    let body = String::from_utf8_lossy(&rendered.body);
    assert!(body.contains("pulsed_response_cache_hits_total "), "{body}");
    assert!(
        body.contains("pulsed_response_cache_bytes "),
        "cache memory gauge must be exported: {body}"
    );

    server.shutdown().expect("shutdown");
}

const MANAGED_KEY: &str = "managed-key.test.";
const MANAGED_SECRET: &[u8] = b"managed-secret";

fn managed_zone() -> (common::TempZone, Config) {
    let (directory, path) = common::write_text(
        "api-managed-zone",
        "zone",
        "$ORIGIN example.com.\n$TTL 3600\n\
         @ IN SOA ns1.example.com. hostmaster.example.com. 1 7200 900 1209600 300\n\
         @ IN NS ns1.example.com.\n\
         ns1 IN A 192.0.2.53\n",
    );
    let zone = common::TempZone::with_import("api-managed", "example.com.", &path);
    drop(directory);
    let mut config = common::base_config(zone.path());
    config.update.enabled = true;
    config.update.require_tsig = true;
    config.update.allow_from = vec!["127.0.0.1/32".to_owned(), "::1/128".to_owned()];
    config.update.allow_zones = vec!["example.com.".to_owned()];
    (zone, config)
}

fn managed_update(owner: &str, address: &str, id: u16, key: &pulse_transfer::TsigKey) -> Vec<u8> {
    use pulse_dns::{EncodeOptions, Flags, Opcode, Record, Ttl};
    let mut message = Message::new(id, Flags::new().with_opcode(Opcode::UPDATE));
    message.add_question(Question::new(
        Name::parse("example.com.").unwrap(),
        Rtype::SOA,
        Rclass::IN,
    ));
    message.add_authority(
        Record::new(
            Name::parse(owner).unwrap(),
            Rtype::A,
            Rclass::IN,
            Ttl::new(300).unwrap(),
            Rdata::A(address.parse().unwrap()),
        )
        .unwrap(),
    );
    let base = message.encode(&EncodeOptions::compressed()).unwrap();
    let record = key.sign_request(&base, message.id(), common_now()).unwrap();
    pulse_transfer::append_tsig(base, &record).unwrap()
}

fn common_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn send_managed_update(server: &Server, raw: &[u8]) -> Rcode {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("client");
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    socket
        .send_to(raw, server.udp_addr().expect("udp"))
        .expect("send");
    let mut buffer = [0_u8; 4096];
    let (length, _) = recv_from(&socket, &mut buffer).expect("recv");
    Message::decode(buffer.get(..length).expect("len"), &DecodeLimits::default())
        .expect("decode")
        .rcode()
}

#[test]
#[allow(clippy::too_many_lines)]
fn managed_tsig_keys_crud_scopes_and_dynamic_update() {
    use base64::Engine as _;
    use pulse_transfer::{TsigAlgorithm, TsigKey};

    let (_zone, config) = managed_zone();
    let state_dir = tempfile::tempdir().expect("tempdir");
    let state_path = state_dir.path().join("tsig-keys.json");
    let mut config = config;
    config.tsig_state_file = Some(state_path.clone());
    // Политика ссылается на ключ, которого ещё нет в конфигурации: он
    // появится через REST и заработает без рестарта.
    config.update.policy = vec![pulsed::config::UpdatePolicyRule {
        principal: pulsed::config::UpdatePrincipal::TsigKey(MANAGED_KEY.to_owned()),
        zone: pulsed::config::UpdateName::Exact("example.com.".to_owned()),
        name: pulsed::config::UpdateName::Any,
        types: pulsed::config::UpdateTypes::Any,
        action: pulsed::config::UpdateAction::Grant,
    }];
    let mut server = Server::start_with_api(
        &config,
        Some(ApiOptions {
            listen: "127.0.0.1:0".parse().expect("api"),
            token: TOKEN.to_owned(),
            scopes: Vec::new(),
        }),
    )
    .expect("start");
    let api = server.api_addr().expect("api");
    let bearer = auth();

    let secret = base64::engine::general_purpose::STANDARD.encode(MANAGED_SECRET);
    let body =
        format!(r#"{{"name":"{MANAGED_KEY}","algorithm":"hmac-sha256","secret":"{secret}"}}"#);
    let created = request(
        api,
        "POST",
        "/api/v1/tsig-keys",
        &[("Authorization", &bearer)],
        Some(body.as_bytes()),
    );
    assert_eq!(
        created.status,
        201,
        "{}",
        String::from_utf8_lossy(&created.body)
    );
    let json = created.json();
    assert_eq!(json["name"], MANAGED_KEY);
    assert_eq!(json["algorithm"], "hmac-sha256");
    assert!(!String::from_utf8_lossy(&created.body).contains(&secret));

    let mode = {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(&state_path)
            .expect("state")
            .permissions()
            .mode()
            & 0o777
    };
    assert_eq!(mode, 0o600);

    let listed = request(
        api,
        "GET",
        "/api/v1/tsig-keys",
        &[("Authorization", &bearer)],
        None,
    );
    assert_eq!(listed.status, 200);
    assert!(!String::from_utf8_lossy(&listed.body).contains(&secret));
    assert_eq!(listed.json()["items"].as_array().expect("items").len(), 1);

    // Дубликат — 409.
    let duplicate = request(
        api,
        "POST",
        "/api/v1/tsig-keys",
        &[("Authorization", &bearer)],
        Some(body.as_bytes()),
    );
    assert_eq!(duplicate.status, 409);
    assert_eq!(duplicate.problem_code(), "tsig-key-exists");

    // Ключ работает без перезапуска.
    let key = TsigKey::new(
        Name::parse(MANAGED_KEY).unwrap(),
        TsigAlgorithm::HmacSha256,
        MANAGED_SECRET.to_vec(),
    )
    .expect("key");
    let raw = managed_update("dynamic.example.com.", "192.0.2.200", 90, &key);
    assert_eq!(send_managed_update(&server, &raw), Rcode::NOERROR);
    let listed = request(
        api,
        "GET",
        "/api/v1/tsig-keys",
        &[("Authorization", &bearer)],
        None,
    );
    assert!(
        !listed.json()["items"][0]["last_used"].is_null(),
        "{}",
        String::from_utf8_lossy(&listed.body)
    );

    // Удаление запрещает новые UPDATE.
    let deleted = request(
        api,
        "DELETE",
        &format!("/api/v1/tsig-keys/{MANAGED_KEY}"),
        &[("Authorization", &bearer)],
        None,
    );
    assert_eq!(deleted.status, 204);
    assert!(
        !state_path.exists() || {
            let text = std::fs::read_to_string(&state_path).unwrap_or_default();
            !text.contains(MANAGED_KEY)
        }
    );
    let missing = request(
        api,
        "DELETE",
        &format!("/api/v1/tsig-keys/{MANAGED_KEY}"),
        &[("Authorization", &bearer)],
        None,
    );
    assert_eq!(missing.status, 404);
    assert_eq!(missing.problem_code(), "tsig-key-not-found");

    let raw = managed_update("dynamic.example.com.", "192.0.2.201", 91, &key);
    assert_eq!(send_managed_update(&server, &raw), Rcode::NOTAUTH);

    server.shutdown().expect("shutdown");
}
