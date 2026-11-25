//! E2E разделения `pulsed` на роли `dns` и `api` на одном v2-zonefile
//! (multi-process, ADR 0007).
//!
//! Проверяется: одновременно `dns`+`api`, видимость REST-мутаций в DNS без
//! рестарта, удаление зоны, `Busy` для второго `all`, устойчивость каждой роли
//! к смерти другой и replay write-ahead журнала при рестарте `api`.

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

mod common;

use common::{PulsedChild, TempZone};
use pulse_dns::{
    DecodeLimits, EncodeOptions, Message, Name, Question, Rclass, Rcode, Rdata, Rtype,
};
use pulsed::config::{Config, Durability, Role, TcpConfig};

const TOKEN: &str = "pd_live_roles_0123456789abcdefabcd";
const ZONE: &str = "roles.test.";
const ZONE_PATH: &str = "/api/v1/zones/roles.test.";

struct Response {
    status: u16,
    body: String,
}

fn free_udp_port() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("udp");
    socket.local_addr().expect("addr").port()
}

fn reserved_tcp_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("tcp");
    listener.local_addr().expect("addr")
}

fn dns_config(data: &Path, port: u16, tcp: SocketAddr) -> Config {
    Config {
        role: Role::Dns,
        listen_udp: Some(SocketAddr::from(([127, 0, 0, 1], port))),
        listen_tcp: Some(tcp),
        workers: 2,
        dns_workers: Some(2),
        zone_poll_ms: 100,
        tcp: TcpConfig {
            idle_timeout_ms: 2000,
            ..TcpConfig::default()
        },
        zonefile: Some(data.to_path_buf()),
        durability: Durability::Flush,
        map_size: 64 * 1024 * 1024,
        journal: false,
        ..Config::default()
    }
}

fn api_config(data: &Path, listen: SocketAddr) -> Config {
    Config {
        role: Role::Api,
        listen_udp: None,
        listen_tcp: None,
        api_listen: Some(listen),
        api_token: Some(TOKEN.to_owned()),
        api_workers: Some(8),
        zonefile: Some(data.to_path_buf()),
        durability: Durability::Flush,
        map_size: 64 * 1024 * 1024,
        journal: true,
        ..Config::default()
    }
}

fn write_config(dir: &Path, name: &str, config: &Config) -> PathBuf {
    let path = dir.join(name);
    let text = config.to_toml_string().expect("serialize config");
    std::fs::write(&path, text).expect("write config");
    path
}

fn spawn(label: &str, config: &Path, crash: Option<&str>) -> PulsedChild {
    let mut command = Command::new(env!("CARGO_BIN_EXE_pulsed"));
    command
        .arg("--config")
        .arg(config)
        .env_remove("PULSED_API_TOKEN")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(point) = crash {
        command.env("PULSED_JOURNAL_CRASH", point);
    }
    PulsedChild::spawn(label, &mut command)
}

fn http(addr: SocketAddr, method: &str, path: &str, body: Option<&str>) -> Option<Response> {
    http_with_headers(addr, method, path, &[], body)
}

fn http_with_headers(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&str>,
) -> Option<Response> {
    let mut stream = TcpStream::connect(addr).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
    let _ = write!(head, "Authorization: Bearer {TOKEN}\r\n");
    for (name, value) in headers {
        let _ = write!(head, "{name}: {value}\r\n");
    }
    if let Some(body) = body {
        head.push_str("Content-Type: application/json\r\n");
        let _ = write!(head, "Content-Length: {}\r\n", body.len());
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).ok()?;
    if let Some(body) = body {
        stream.write_all(body.as_bytes()).ok()?;
    }
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).ok()?;
    let end = raw.windows(4).position(|window| window == b"\r\n\r\n")?;
    let head = std::str::from_utf8(raw.get(..end)?).ok()?;
    let status = head.lines().next()?.split(' ').nth(1)?.parse().ok()?;
    Some(Response {
        status,
        body: String::from_utf8_lossy(raw.get(end + 4..)?).into_owned(),
    })
}

fn wait_api(addr: SocketAddr, child: &mut PulsedChild) -> bool {
    child.wait_ready(common::CHILD_READY_TIMEOUT, || {
        http(addr, "GET", "/api/v1/zones", None).is_some_and(|response| response.status == 200)
    })
}

fn dns_query_opt(port: u16, qname: &str, qtype: Rtype) -> Option<Message> {
    let socket = UdpSocket::bind("127.0.0.1:0").ok()?;
    socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .ok()?;
    let query = Message::query(
        0x4242,
        Question::new(Name::parse(qname).expect("qname"), qtype, Rclass::IN),
    )
    .encode(&EncodeOptions::compressed())
    .ok()?;
    socket
        .send_to(&query, SocketAddr::from(([127, 0, 0, 1], port)))
        .ok()?;
    let mut buffer = [0_u8; 4096];
    let len = socket.recv(&mut buffer).ok()?;
    Message::decode(&buffer[..len], &DecodeLimits::default()).ok()
}

fn dns_query(port: u16, qname: &str, qtype: Rtype) -> Message {
    dns_query_opt(port, qname, qtype).expect("dns response")
}

fn wait_dns(port: u16, child: &mut PulsedChild, qname: &str, qtype: Rtype) -> bool {
    child.wait_ready(common::CHILD_READY_TIMEOUT, || {
        dns_query_opt(port, qname, qtype).is_some_and(|message| message.rcode() == Rcode::NOERROR)
    })
}

fn put(api: SocketAddr, path: &str, body: &str) -> Response {
    put_with_headers(api, path, &[], body)
}

fn put_with_headers(api: SocketAddr, path: &str, headers: &[(&str, &str)], body: &str) -> Response {
    for attempt in 0..100_u32 {
        let response =
            http_with_headers(api, "PUT", path, headers, Some(body)).expect("PUT response");
        if response.status != 429 {
            return response;
        }
        std::thread::sleep(Duration::from_millis(20 + u64::from(attempt)));
    }
    panic!("PUT {path}: rate limit did not clear");
}

fn create_zone(api: SocketAddr, origin: &str, path: &str) {
    let created = put(api, path, r#"{"kind":"primary","default_ttl":3600}"#);
    assert_eq!(
        created.status, 201,
        "create zone {origin}: {}",
        created.body
    );
    let soa = format!("ns1.{origin} hostmaster.{origin} 1 3600 600 604800 300");
    assert_eq!(
        put(
            api,
            &format!("{path}/records/@/SOA"),
            &format!(r#"{{"ttl":3600,"records":["{soa}"]}}"#)
        )
        .status,
        201,
        "SOA {origin}"
    );
    assert_eq!(
        put(
            api,
            &format!("{path}/records/@/NS"),
            &format!(r#"{{"ttl":3600,"records":["ns1.{origin}"]}}"#)
        )
        .status,
        201,
        "NS {origin}"
    );
}

fn a_record(api: SocketAddr, zone_path: &str, owner: &str, address: &str) -> Response {
    put(
        api,
        &format!("{zone_path}/records/{owner}/A"),
        &format!(r#"{{"ttl":60,"records":["{address}"]}}"#),
    )
}

fn a_record_update(api: SocketAddr, zone_path: &str, owner: &str, address: &str) -> Response {
    put_with_headers(
        api,
        &format!("{zone_path}/records/{owner}/A"),
        &[("If-Match", "*")],
        &format!(r#"{{"ttl":60,"records":["{address}"]}}"#),
    )
}

fn wait_until<F: FnMut() -> bool>(timeout: Duration, mut probe: F) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if probe() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    probe()
}

/// REST-запись, обновление и удаление зоны видны DNS без рестарта; каждая роль
/// переживает смерть другой.
#[test]
#[allow(clippy::too_many_lines)]
fn dns_and_api_share_zonefile_and_rest_writes_are_visible() {
    let zone = TempZone::with_import("roles-share", "example.com.", &common::example_zone());
    let dir = tempfile::tempdir().expect("dir");
    let udp_port = free_udp_port();
    let tcp_addr = reserved_tcp_addr();
    let api_addr = reserved_tcp_addr();
    let dns_path = write_config(
        dir.path(),
        "dns.toml",
        &dns_config(zone.path(), udp_port, tcp_addr),
    );
    let api_path = write_config(dir.path(), "api.toml", &api_config(zone.path(), api_addr));

    let mut dns = spawn("roles/dns", &dns_path, None);
    assert!(wait_dns(udp_port, &mut dns, "example.com.", Rtype::SOA));
    let mut api = spawn("roles/api", &api_path, None);
    assert!(wait_api(api_addr, &mut api));

    create_zone(api_addr, ZONE, ZONE_PATH);
    assert!(
        wait_until(Duration::from_secs(5), || {
            dns_query(udp_port, ZONE, Rtype::SOA).rcode() == Rcode::NOERROR
        }),
        "dns did not pick up a new zone from the api process"
    );

    let created = a_record(api_addr, ZONE_PATH, &format!("host.{ZONE}"), "192.0.2.10");
    assert_eq!(created.status, 201, "create A: {}", created.body);
    assert!(
        wait_until(Duration::from_secs(5), || {
            let response = dns_query(udp_port, &format!("host.{ZONE}"), Rtype::A);
            response.rcode() == Rcode::NOERROR && response.answers().len() == 1
        }),
        "dns did not see a new A record"
    );

    let updated = a_record_update(api_addr, ZONE_PATH, &format!("host.{ZONE}"), "192.0.2.11");
    assert_eq!(updated.status, 200, "update A: {}", updated.body);
    assert!(
        wait_until(Duration::from_secs(5), || {
            let response = dns_query(udp_port, &format!("host.{ZONE}"), Rtype::A);
            response.answers().first().is_some_and(|record| {
                matches!(record.rdata(), Rdata::A(address) if *address == Ipv4Addr::new(192, 0, 2, 11))
            })
        }),
        "dns did not see the updated A record"
    );

    // API продолжает работать после смерти DNS.
    assert!(dns.kill().is_some(), "dns did not stop");
    dns.assert_dead();
    let while_dns_down = a_record(api_addr, ZONE_PATH, &format!("down.{ZONE}"), "192.0.2.12");
    assert_eq!(
        while_dns_down.status, 201,
        "api must survive dns death: {}",
        while_dns_down.body
    );

    // DNS продолжает отвечать после смерти API и после рестарта видит запись,
    // сделанную при мёртвом DNS.
    let mut dns = spawn("roles/dns-restart", &dns_path, None);
    assert!(wait_dns(udp_port, &mut dns, "example.com.", Rtype::SOA));
    assert!(
        wait_until(Duration::from_secs(5), || {
            dns_query(udp_port, &format!("down.{ZONE}"), Rtype::A).rcode() == Rcode::NOERROR
        }),
        "restarted dns did not see a record written while it was down"
    );
    assert!(api.kill().is_some(), "api did not stop");
    api.assert_dead();
    assert_eq!(
        dns_query(udp_port, "www.example.com.", Rtype::A).rcode(),
        Rcode::NOERROR,
        "dns must keep serving after api death"
    );

    // Удаление зоны через API убирает её из DNS.
    let mut api = spawn("roles/api-restart", &api_path, None);
    assert!(wait_api(api_addr, &mut api));
    let deleted = http_with_headers(
        api_addr,
        "DELETE",
        ZONE_PATH,
        &[("If-Match", "*")],
        Some(r#"{"confirm_origin":"roles.test."}"#),
    )
    .expect("DELETE response");
    assert_eq!(deleted.status, 204, "delete zone: {}", deleted.body);
    assert!(
        wait_until(Duration::from_secs(5), || {
            dns_query(udp_port, ZONE, Rtype::SOA).rcode() != Rcode::NOERROR
        }),
        "dns still serves a deleted zone"
    );

    api.kill();
    dns.kill();
    api.assert_dead();
    dns.assert_dead();
}

/// Второй single-process `all` на том же файле получает `Busy`.
#[test]
fn second_all_process_is_busy() {
    let zone = TempZone::with_import("roles-busy", "example.com.", &common::example_zone());
    let dir = tempfile::tempdir().expect("dir");
    let udp_port = free_udp_port();
    let tcp_addr = reserved_tcp_addr();
    let api_addr = reserved_tcp_addr();
    let dns_path = write_config(
        dir.path(),
        "dns.toml",
        &dns_config(zone.path(), udp_port, tcp_addr),
    );
    let api_path = write_config(dir.path(), "api.toml", &api_config(zone.path(), api_addr));

    let mut dns = spawn("roles/busy-dns", &dns_path, None);
    assert!(wait_dns(udp_port, &mut dns, "example.com.", Rtype::SOA));
    let mut api = spawn("roles/busy-api", &api_path, None);
    assert!(wait_api(api_addr, &mut api));

    let all_path = dir.path().join("all.toml");
    let all = Config {
        role: Role::All,
        listen_udp: Some("127.0.0.1:0".parse().expect("udp")),
        listen_tcp: Some("127.0.0.1:0".parse().expect("tcp")),
        workers: 1,
        zonefile: Some(zone.path().to_path_buf()),
        durability: Durability::Flush,
        map_size: 64 * 1024 * 1024,
        journal: false,
        ..Config::default()
    };
    std::fs::write(&all_path, all.to_toml_string().expect("toml")).expect("write all config");
    let mut command = Command::new(env!("CARGO_BIN_EXE_pulsed"));
    command
        .arg("--config")
        .arg(&all_path)
        .env_remove("PULSED_API_TOKEN");
    let output = common::run_cli("roles/all-busy", &mut command, Duration::from_secs(20));
    assert!(!output.status.success(), "second all must fail");
    let stderr = String::from_utf8_lossy(&output.stderr).to_lowercase();
    assert!(
        stderr.contains("busy"),
        "expected Busy for the second all process, got: {stderr}"
    );

    api.kill();
    dns.kill();
}

/// Интент, оборвавшийся до применения, переигрывается при рестарте `api`;
/// результат виден роли `dns`.
#[test]
fn journal_replay_on_api_restart_is_visible_to_dns() {
    let zone = TempZone::with_import("roles-journal", "example.com.", &common::example_zone());
    let dir = tempfile::tempdir().expect("dir");
    let udp_port = free_udp_port();
    let tcp_addr = reserved_tcp_addr();
    let api_addr = reserved_tcp_addr();
    let dns_path = write_config(
        dir.path(),
        "dns.toml",
        &dns_config(zone.path(), udp_port, tcp_addr),
    );
    let api_path = write_config(dir.path(), "api.toml", &api_config(zone.path(), api_addr));

    let mut api = spawn("roles/journal-api", &api_path, None);
    assert!(wait_api(api_addr, &mut api));
    let owner = "replayed.example.com.";
    assert_eq!(
        a_record(api_addr, "/api/v1/zones/example.com.", owner, "192.0.2.77").status,
        201
    );
    api.kill();
    api.assert_dead();

    // Интент пишется, процесс падает до применения.
    let mut crashed = spawn("roles/journal-crash", &api_path, Some("after_intent"));
    assert!(wait_api(api_addr, &mut crashed));
    let body = r#"{"ttl":60,"records":["192.0.2.88"]}"#;
    let path = "/api/v1/zones/example.com./records/pending.example.com./A";
    let crashed_response = http(api_addr, "PUT", path, Some(body));
    assert!(
        crashed_response
            .as_ref()
            .is_none_or(|response| response.status >= 500),
        "crash hook must terminate the request, got status {:?}",
        crashed_response.as_ref().map(|response| response.status)
    );
    assert!(
        crashed.wait_for_exit(Duration::from_secs(10)).is_some(),
        "api did not crash after intent"
    );
    crashed.assert_dead();

    // Рестарт: recovery переигрывает интент; новая запись видна DNS.
    let mut api = spawn("roles/journal-replay", &api_path, None);
    assert!(wait_api(api_addr, &mut api));
    let metrics = http(api_addr, "GET", "/metrics", None).expect("metrics");
    assert!(
        metrics
            .body
            .lines()
            .any(|line| { line.starts_with("journal_replays_total ") && !line.ends_with(" 0") }),
        "journal replay was not counted: {}",
        metrics.body
    );

    let mut dns = spawn("roles/journal-dns", &dns_path, None);
    assert!(wait_dns(udp_port, &mut dns, "example.com.", Rtype::SOA));
    assert!(
        wait_until(Duration::from_secs(5), || {
            dns_query(udp_port, "pending.example.com.", Rtype::A).rcode() == Rcode::NOERROR
        }),
        "dns did not see the replayed record"
    );

    api.kill();
    dns.kill();
}
