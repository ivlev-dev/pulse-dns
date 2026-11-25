//! E2E импорта master-файлов, mmap-ответов и миграции конфигурации.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::path::Path;
use std::time::{Duration, Instant};

use pulse_dns::{
    DecodeLimits, EncodeOptions, Message, Name, Question, Rclass, Rcode, Rdata, Rtype,
};
use pulsed::config::Config;
use pulsed::server::{ApiOptions, Server};

const TOKEN: &str = "pd_live_master_integration_0123456789abcdef";

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

const EXTRA_ZONE: &str = "$ORIGIN mmap.test.
$TTL 3600
@ IN SOA ns1.mmap.test. hostmaster.mmap.test. 1 3600 600 604800 300
@ IN NS ns1.mmap.test.
ns1 IN A 192.0.2.53
www IN A 192.0.2.20
www IN AAAA 2001:db8::20
*.wild IN A 192.0.2.99
deleg IN NS ns.deleg.mmap.test.
ns.deleg IN A 192.0.2.80
";

#[test]
#[allow(clippy::too_many_lines)]
fn master_file_zone_is_served_and_mutable_via_api() {
    let zone = common::TempZone::with_import("master", "example.com.", &common::example_zone());
    let config = common::base_config(zone.path());
    let mut server = Server::start_with_api(
        &config,
        Some(ApiOptions {
            listen: "127.0.0.1:0".parse().expect("api"),
            token: TOKEN.to_owned(),
            scopes: Vec::new(),
        }),
    )
    .expect("start DNS+API with imported zone");
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
    drop(server);

    // Рестарт без повторного импорта: данные и REST-правка на месте.
    let mut reopened = Server::start(&config).expect("reopen zonefile");
    let response = dns_query(&reopened, "www.example.com.", Rtype::A);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert_eq!(
        response.answers()[0].rdata(),
        &Rdata::A("192.0.2.55".parse().expect("ipv4"))
    );
    reopened.shutdown().expect("shutdown");
}

#[test]
fn mmap_serves_wildcard_delegation_aaaa_and_nxdomain() {
    let (_dir, path) = common::write_text("mmap", "mmap.zone", EXTRA_ZONE);
    let zone = common::TempZone::with_import("mmap-data", "mmap.test.", &path);
    let config = common::base_config(zone.path());
    let mut server = Server::start(&config).expect("start");

    let response = dns_query(&server, "www.mmap.test.", Rtype::A);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert_eq!(
        response.answers()[0].rdata(),
        &Rdata::A("192.0.2.20".parse().expect("ipv4"))
    );

    let response = dns_query(&server, "www.mmap.test.", Rtype::AAAA);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert!(matches!(response.answers()[0].rdata(), Rdata::Aaaa(_)));

    let response = dns_query(&server, "host.wild.mmap.test.", Rtype::A);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert_eq!(
        response.answers()[0].rdata(),
        &Rdata::A("192.0.2.99".parse().expect("ipv4"))
    );

    let response = dns_query(&server, "x.deleg.mmap.test.", Rtype::A);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert!(!response.flags().aa());
    assert!(
        response
            .authority()
            .iter()
            .any(|record| record.rr_type() == Rtype::NS)
    );

    let response = dns_query(&server, "missing.mmap.test.", Rtype::A);
    assert_eq!(response.rcode(), Rcode::NXDOMAIN);

    server.shutdown().expect("shutdown");
}

#[test]
fn empty_zonefile_refuses_queries_without_panic() {
    let zone = common::TempZone::empty("empty");
    let config = common::base_config(zone.path());
    let mut server = Server::start(&config).expect("start empty server");
    let response = dns_query(&server, "www.example.com.", Rtype::A);
    assert_eq!(response.rcode(), Rcode::REFUSED);
    server.shutdown().expect("shutdown");
}

#[test]
fn json_zones_config_fails_with_migration_hint() {
    let zone = common::TempZone::empty("migration");
    let mut config = common::base_config(zone.path());
    let parsed = Config::from_json_str(
        r#"{
            "listen_udp": "127.0.0.1:0",
            "listen_tcp": "127.0.0.1:0",
            "zones": []
        }"#,
    )
    .expect("schema allows migration fields");
    config.zones = parsed.zones;
    let error = config.validate().expect_err("JSON zones must be rejected");
    let message = error.to_string();
    assert!(
        message.contains("JSON zones are no longer supported"),
        "{message}"
    );
    assert!(message.contains("pulsed import"), "{message}");
    assert!(message.contains("--data"), "{message}");
}

#[test]
fn broken_master_file_exits_with_code_two_and_location() {
    let directory = tempfile::tempdir().expect("temp dir");
    let zone = directory.path().join("bad.zone");
    std::fs::write(&zone, "$TTL 60\n@ IN A not-an-address\n").expect("write bad zone");
    let data = directory.path().join("bad.pulse");

    let started = Instant::now();
    let mut command = common::pulsed();
    command
        .arg("import")
        .arg("--data")
        .arg(&data)
        .arg("--origin")
        .arg("bad.test.")
        .arg(&zone)
        .env_remove("PULSED_API_TOKEN");
    let output = common::run_cli(
        "pulsed import (bad zone)",
        &mut command,
        common::CLI_TIMEOUT,
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "stderr: {stderr}");
    assert!(stderr.contains("bad.zone"), "stderr: {stderr}");
    assert!(stderr.contains(":2:"), "stderr: {stderr}");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "fail-fast expected"
    );
    assert!(!Path::new(&data).exists() || std::fs::metadata(&data).is_ok());
}
