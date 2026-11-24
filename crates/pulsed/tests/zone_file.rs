//! Загрузка RFC 1035 master-файлов и совместная работа с REST/DNS.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime};

use pulse_dns::{
    DecodeLimits, EncodeOptions, Message, Name, Question, Rclass, Rcode, Rdata, Rtype,
};
use pulsed::config::{Config, ZoneFileConfig};
use pulsed::server::{ApiOptions, Server};

const TOKEN: &str = "pd_live_master_integration_0123456789abcdef";

fn example_zone() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/example.com.zone")
}

fn test_config() -> Config {
    Config {
        listen_udp: Some("127.0.0.1:0".parse().expect("udp")),
        listen_tcp: Some("127.0.0.1:0".parse().expect("tcp")),
        workers: 1,
        zones: Vec::new(),
        zones_files: vec![ZoneFileConfig {
            origin: "example.com.".to_owned(),
            path: example_zone(),
        }],
        ..Config::default()
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
        0x7a7a,
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

fn put_a(api: SocketAddr, path: &str, record: &str) {
    let mut stream = TcpStream::connect(api).expect("connect API");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    let body = format!(r#"{{"ttl":300,"records":["{record}"]}}"#);
    let request = format!(
        "PUT {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Authorization: Bearer {TOKEN}\r\nIf-Match: *\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).expect("write request");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read response");
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "unexpected API response: {response}"
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn master_file_zone_is_served_and_mutable_via_api() {
    let mut server = Server::start_with_api(
        &test_config(),
        Some(ApiOptions {
            listen: "127.0.0.1:0".parse().expect("api"),
            token: TOKEN.to_owned(),
            scopes: Vec::new(),
        }),
    )
    .expect("start DNS+API with master file");
    let api = server.api_addr().expect("api enabled");

    let response = dns_query(&server, "www.example.com.", Rtype::A);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert!(response.flags().aa());
    assert_eq!(
        response.answers()[0].rdata(),
        &Rdata::A("192.0.2.20".parse().expect("ipv4"))
    );

    let response = dns_query(&server, "missing.example.com.", Rtype::A);
    assert_eq!(response.rcode(), Rcode::NXDOMAIN);
    assert!(
        response
            .authority()
            .iter()
            .any(|record| record.rr_type() == Rtype::SOA)
    );

    put_a(
        api,
        "/api/v1/zones/example.com./records/www.example.com./A",
        "192.0.2.55",
    );
    let response = dns_query(&server, "www.example.com.", Rtype::A);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert_eq!(
        response.answers()[0].rdata(),
        &Rdata::A("192.0.2.55".parse().expect("ipv4"))
    );

    server.shutdown().expect("shutdown");
}

#[test]
fn json_and_master_sources_share_one_store() {
    let mut config = Config::from_json_str(
        r#"{
            "listen_udp": "127.0.0.1:0",
            "listen_tcp": "127.0.0.1:0",
            "workers": 1,
            "zones": [{
                "origin": "json.test.",
                "records": [
                    {"name": "@", "type": "SOA", "rdata": {
                        "mname": "ns1.json.test.", "rname": "hostmaster.json.test.",
                        "serial": 1, "refresh": 3600, "retry": 600,
                        "expire": 604800, "minimum": 300
                    }},
                    {"name": "@", "type": "NS", "rdata": "ns1.json.test."},
                    {"name": "host", "type": "A", "rdata": "192.0.2.77"}
                ]
            }]
        }"#,
    )
    .expect("JSON config");
    config.zones_files.push(ZoneFileConfig {
        origin: "example.com.".to_owned(),
        path: example_zone(),
    });
    let mut server = Server::start(&config).expect("start mixed sources");
    let json = dns_query(&server, "host.json.test.", Rtype::A);
    assert_eq!(json.rcode(), Rcode::NOERROR);
    assert_eq!(
        json.answers()[0].rdata(),
        &Rdata::A("192.0.2.77".parse().expect("ipv4"))
    );
    let master = dns_query(&server, "www.example.com.", Rtype::A);
    assert_eq!(master.rcode(), Rcode::NOERROR);
    assert_eq!(
        master.answers()[0].rdata(),
        &Rdata::A("192.0.2.20".parse().expect("ipv4"))
    );
    server.shutdown().expect("shutdown");
}

#[test]
fn conflicting_origin_fails_startup() {
    let mut config =
        Config::from_json_str(include_str!("../../../examples/zones.json")).expect("config");
    config.listen_udp = Some("127.0.0.1:0".parse().expect("udp"));
    config.listen_tcp = Some("127.0.0.1:0".parse().expect("tcp"));
    config.zones_files.push(ZoneFileConfig {
        origin: "example.com.".to_owned(),
        path: example_zone(),
    });
    let Err(error) = Server::start(&config) else {
        panic!("duplicate origin must fail");
    };
    let message = error.to_string();
    assert!(message.contains("declared more than once"), "{message}");
    assert!(message.contains("example.com."), "{message}");
}

#[test]
fn broken_master_file_exits_with_code_two_and_location() {
    let directory = std::env::temp_dir().join(format!(
        "pulsed-master-test-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    std::fs::create_dir_all(&directory).expect("temp dir");
    let zone = directory.join("bad.zone");
    std::fs::write(&zone, "$TTL 60\n@ IN A not-an-address\n").expect("write bad zone");
    let empty_config = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/empty.json");

    let started = Instant::now();
    let output = Command::new(env!("CARGO_BIN_EXE_pulsed"))
        .arg("--config")
        .arg(&empty_config)
        .arg("--listen-udp")
        .arg("127.0.0.1:0")
        .arg("--listen-tcp")
        .arg("127.0.0.1:0")
        .arg("--zone")
        .arg(format!("bad.test.={}", zone.display()))
        .env_remove("PULSED_API_TOKEN")
        .output()
        .expect("run pulsed");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "stderr: {stderr}");
    assert!(stderr.contains("bad.zone"), "stderr: {stderr}");
    assert!(stderr.contains(":2:"), "stderr: {stderr}");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "fail-fast expected"
    );
    let _ = std::fs::remove_dir_all(&directory);
}
