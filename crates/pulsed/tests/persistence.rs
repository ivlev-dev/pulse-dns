//! E2E persistence: `pulse-zonefile` write-through и reopen.

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use pulse_dns::{
    DecodeLimits, EncodeOptions, Message, Name, Question, Rclass, Rcode, Rdata, Rtype,
};
use pulsed::config::{Config, Durability, TcpConfig, ZoneFileConfig};
use pulsed::server::{ApiOptions, Server};

const TOKEN: &str = "pd_live_persistence_0123456789abcdef";
const ZONE_PATH: &str = "/api/v1/zones/persist.test.";

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "pulsed-persist-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).expect("temp dir");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn example_zone() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/example.com.zone")
}

fn base_config(data: &Path) -> Config {
    Config {
        listen_udp: Some("127.0.0.1:0".parse().expect("udp")),
        listen_tcp: Some("127.0.0.1:0".parse().expect("tcp")),
        workers: 1,
        tcp: TcpConfig {
            idle_timeout_ms: 2000,
            ..TcpConfig::default()
        },
        zonefile: Some(data.to_path_buf()),
        durability: Durability::Flush,
        map_size: 64 * 1024 * 1024,
        zones: Vec::new(),
        zones_files: Vec::new(),
        ..Config::default()
    }
}

fn api_options() -> ApiOptions {
    ApiOptions {
        listen: "127.0.0.1:0".parse().expect("api"),
        token: TOKEN.to_owned(),
        scopes: Vec::new(),
    }
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
        0x5151,
        Question::new(Name::parse(qname).expect("qname"), qtype, Rclass::IN),
    )
    .encode(&EncodeOptions::compressed())
    .expect("encode");
    socket
        .send_to(&query, server.udp_addr().expect("udp"))
        .expect("send");
    let mut buffer = [0_u8; 4096];
    let (len, _) = recv_from(&socket, &mut buffer).expect("recv");
    Message::decode(&buffer[..len], &DecodeLimits::default()).expect("decode")
}

struct Response {
    status: u16,
    headers: Vec<(String, String)>,
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

fn http(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&str>,
) -> Response {
    let mut stream = TcpStream::connect(addr).expect("connect API");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
    let mut has_type = false;
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-type") {
            has_type = true;
        }
        let _ = write!(head, "{name}: {value}\r\n");
    }
    if body.is_some() && !has_type {
        head.push_str("Content-Type: application/json\r\n");
    }
    if let Some(body) = body {
        let _ = write!(head, "Content-Length: {}\r\n", body.len());
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).expect("head");
    if let Some(body) = body {
        stream.write_all(body.as_bytes()).expect("body");
    }
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("response");
    parse_response(&raw)
}

fn parse_response(raw: &[u8]) -> Response {
    let end = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("header end");
    let head = std::str::from_utf8(&raw[..end]).expect("headers");
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .expect("status")
        .split(' ')
        .nth(1)
        .expect("code")
        .parse::<u16>()
        .expect("numeric");
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_owned(), value.trim().to_owned()))
        .collect();
    Response { status, headers }
}

fn auth() -> String {
    format!("Bearer {TOKEN}")
}

fn put(addr: SocketAddr, path: &str, body: &str, if_match: Option<&str>) -> Response {
    let bearer = auth();
    let mut headers = vec![("Authorization", bearer.as_str())];
    if let Some(tag) = if_match {
        headers.push(("If-Match", tag));
    }
    http(addr, "PUT", path, &headers, Some(body))
}

fn create_zone(addr: SocketAddr) -> Response {
    let bearer = auth();
    http(
        addr,
        "PUT",
        ZONE_PATH,
        &[("Authorization", &bearer), ("If-None-Match", "*")],
        Some(r#"{"kind":"primary","default_ttl":3600}"#),
    )
}

fn get_etag(addr: SocketAddr, path: &str) -> String {
    let bearer = auth();
    let response = http(addr, "GET", path, &[("Authorization", &bearer)], None);
    assert_eq!(response.status, 200, "GET {path}");
    response.header("etag").expect("etag").to_owned()
}

fn assert_a(server: &Server, address: &str, ttl: u32) {
    let response = dns_query(server, "www.persist.test.", Rtype::A);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert_eq!(response.answers().len(), 1);
    assert_eq!(
        response.answers()[0].rdata(),
        &Rdata::A(address.parse().expect("ipv4"))
    );
    assert_eq!(response.answers()[0].ttl().as_u32(), ttl);
}

#[test]
fn empty_file_bootstraps_zone_and_survives_reopen() {
    let dir = TempDir::new("bootstrap");
    let data = dir.path().join("pulse.zonefile");
    std::fs::write(&data, b"").expect("empty file");
    let mut config = base_config(&data);
    config.zones_files.push(ZoneFileConfig {
        origin: "example.com.".to_owned(),
        path: example_zone(),
    });

    let mut server = Server::start(&config).expect("first start");
    let response = dns_query(&server, "www.example.com.", Rtype::A);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert_eq!(
        response.answers()[0].rdata(),
        &Rdata::A("192.0.2.20".parse().expect("ipv4"))
    );
    server.shutdown().expect("shutdown");
    drop(server);

    let mut reopened = Server::start(&config).expect("reopen");
    let response = dns_query(&reopened, "www.example.com.", Rtype::A);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert_eq!(
        response.answers()[0].rdata(),
        &Rdata::A("192.0.2.20".parse().expect("ipv4"))
    );
    let response = dns_query(&reopened, "missing.example.com.", Rtype::A);
    assert_eq!(response.rcode(), Rcode::NXDOMAIN);
    reopened.shutdown().expect("shutdown");
}

#[test]
#[allow(clippy::too_many_lines)]
fn api_mutations_survive_reopen() {
    let dir = TempDir::new("api");
    let data = dir.path().join("pulse.zonefile");
    let config = base_config(&data);

    let mut server = Server::start_with_api(&config, Some(api_options())).expect("start");
    let api = server.api_addr().expect("api");
    assert_eq!(create_zone(api).status, 201);

    let soa = "ns1.persist.test. hostmaster.persist.test. 1 3600 600 604800 300";
    assert_eq!(
        put(
            api,
            &format!("{ZONE_PATH}/records/@/SOA"),
            &format!(r#"{{"ttl":3600,"records":["{soa}"]}}"#),
            None
        )
        .status,
        201
    );
    assert_eq!(
        put(
            api,
            &format!("{ZONE_PATH}/records/@/NS"),
            r#"{"ttl":3600,"records":["ns1.persist.test."]}"#,
            None
        )
        .status,
        201
    );
    let created = put(
        api,
        &format!("{ZONE_PATH}/records/www.persist.test./A"),
        r#"{"ttl":120,"records":["192.0.2.55"]}"#,
        None,
    );
    assert_eq!(created.status, 201);
    let a_etag = created.header("etag").expect("etag").to_owned();
    assert_a(&server, "192.0.2.55", 120);

    let patched = http(
        api,
        "PATCH",
        &format!("{ZONE_PATH}/records/www.persist.test./A"),
        &[("Authorization", &auth()), ("If-Match", &a_etag)],
        Some(r#"{"ttl":240,"add":["192.0.2.66"],"remove":["192.0.2.55"]}"#),
    );
    assert_eq!(patched.status, 200);
    assert_a(&server, "192.0.2.66", 240);
    server.shutdown().expect("shutdown");
    drop(server);

    let mut reopened = Server::start_with_api(&config, Some(api_options())).expect("reopen");
    assert_a(&reopened, "192.0.2.66", 240);
    let api = reopened.api_addr().expect("api");
    let a_etag = get_etag(api, &format!("{ZONE_PATH}/records/www.persist.test./A"));
    let deleted = http(
        api,
        "DELETE",
        &format!("{ZONE_PATH}/records/www.persist.test./A"),
        &[("Authorization", &auth()), ("If-Match", &a_etag)],
        None,
    );
    assert_eq!(deleted.status, 204);
    let response = dns_query(&reopened, "www.persist.test.", Rtype::A);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert_eq!(response.answers().len(), 0);
    reopened.shutdown().expect("shutdown");
    drop(reopened);

    let mut after_delete =
        Server::start_with_api(&config, Some(api_options())).expect("reopen after delete");
    let response = dns_query(&after_delete, "www.persist.test.", Rtype::A);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert_eq!(response.answers().len(), 0);
    let api = after_delete.api_addr().expect("api");
    let zone_etag = get_etag(api, ZONE_PATH);
    let deleted = http(
        api,
        "DELETE",
        ZONE_PATH,
        &[("Authorization", &auth()), ("If-Match", &zone_etag)],
        None,
    );
    assert_eq!(deleted.status, 204);
    assert_eq!(
        dns_query(&after_delete, "www.persist.test.", Rtype::A).rcode(),
        Rcode::REFUSED
    );
    after_delete.shutdown().expect("shutdown");
    drop(after_delete);

    let mut after_zone_delete =
        Server::start_with_api(&config, Some(api_options())).expect("reopen after zone delete");
    assert_eq!(
        dns_query(&after_zone_delete, "www.persist.test.", Rtype::A).rcode(),
        Rcode::REFUSED
    );
    after_zone_delete.shutdown().expect("shutdown");
}

#[test]
fn second_writer_gets_busy() {
    let dir = TempDir::new("busy");
    let data = dir.path().join("pulse.zonefile");
    let config = base_config(&data);
    let mut first = Server::start(&config).expect("first writer");
    let Err(error) = Server::start(&config) else {
        panic!("second writer must fail");
    };
    let message = error.to_string().to_lowercase();
    assert!(message.contains("busy"), "{message}");
    first.shutdown().expect("shutdown");
}

#[test]
fn truncated_file_is_rejected() {
    let dir = TempDir::new("corrupt");
    let data = dir.path().join("pulse.zonefile");
    let mut config = base_config(&data);
    config.zones_files.push(ZoneFileConfig {
        origin: "example.com.".to_owned(),
        path: example_zone(),
    });
    let mut server = Server::start(&config).expect("create valid file");
    server.shutdown().expect("shutdown");
    drop(server);

    let len = std::fs::metadata(&data).expect("metadata").len();
    assert!(len > 4096);
    std::fs::OpenOptions::new()
        .write(true)
        .open(&data)
        .expect("open")
        .set_len(4096)
        .expect("truncate");

    let error = match Server::start(&config) {
        Ok(_) => panic!("truncated file must be rejected"),
        Err(error) => error.to_string(),
    };
    let lower = error.to_lowercase();
    assert!(
        lower.contains("truncated") || lower.contains("corrupt") || lower.contains("zone file"),
        "{error}"
    );
}
