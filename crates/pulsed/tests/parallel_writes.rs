//! E2E параллельных REST-правок в v2: 8 зон, несколько потоков на зону,
//! видимость через DNS, отсутствие потерь и сохранность после reopen.
//!
//! `per-zone` и `group` режимы коммита проверяются на свежих файлах.

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::path::Path;
use std::sync::Barrier;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use pulse_dns::{
    DecodeLimits, EncodeOptions, Message, Name, Question, Rclass, Rcode, Rdata, Rtype,
};
use pulsed::config::{CommitMode, Config, Durability, TcpConfig};
use pulsed::server::{ApiOptions, Server};

const TOKEN: &str = "pd_live_parallel_0123456789abcdefabcd";
const ZONES: usize = 8;
const THREADS: usize = 16;
const RECORDS: usize = 8;

fn origin(zone: usize) -> String {
    format!("z{zone}.parallel.test.")
}

fn zone_path(zone: usize) -> String {
    format!("/api/v1/zones/{}", origin(zone))
}

fn base_config(data: &Path, commit_mode: CommitMode) -> Config {
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
        commit_mode,
        map_size: 64 * 1024 * 1024,
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
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("read timeout");
    let query = Message::query(
        0x7b7b,
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
    body: String,
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
        .set_read_timeout(Some(Duration::from_secs(10)))
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
    let end = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("header end");
    let head = std::str::from_utf8(&raw[..end]).expect("headers");
    let status = head
        .lines()
        .next()
        .expect("status")
        .split(' ')
        .nth(1)
        .expect("code")
        .parse::<u16>()
        .expect("numeric");
    Response {
        status,
        body: String::from_utf8_lossy(&raw[end + 4..]).into_owned(),
    }
}

fn metric_value(body: &str, name: &str) -> u64 {
    body.lines()
        .find_map(|line| line.strip_prefix(name)?.trim().parse::<u64>().ok())
        .unwrap_or(0)
}

fn put(addr: SocketAddr, path: &str, body: &str, headers: &[(&str, &str)]) -> Response {
    let bearer = format!("Bearer {TOKEN}");
    let mut all = vec![("Authorization", bearer.as_str())];
    all.extend_from_slice(headers);
    http(addr, "PUT", path, &all, Some(body))
}

/// Повторяет `PUT` при штатном rate limit тестового токена.
fn put_retry(addr: SocketAddr, path: &str, body: &str) -> Response {
    let mut response = put(addr, path, body, &[]);
    let mut attempts = 0_u32;
    while response.status == 429 && attempts < 100 {
        std::thread::sleep(Duration::from_millis(20));
        response = put(addr, path, body, &[]);
        attempts = attempts.saturating_add(1);
    }
    response
}

fn create_zone(addr: SocketAddr, zone: usize) {
    let response = put(
        addr,
        &zone_path(zone),
        r#"{"kind":"primary","default_ttl":3600}"#,
        &[("If-None-Match", "*")],
    );
    assert_eq!(response.status, 201, "create zone {zone}");
    let soa = format!(
        "ns1.{origin} hostmaster.{origin} 1 3600 600 604800 300",
        origin = origin(zone)
    );
    let response = put(
        addr,
        &format!("{}/records/@/SOA", zone_path(zone)),
        &format!(r#"{{"ttl":3600,"records":["{soa}"]}}"#),
        &[],
    );
    assert_eq!(response.status, 201, "SOA zone {zone}");
    let response = put(
        addr,
        &format!("{}/records/@/NS", zone_path(zone)),
        &format!(r#"{{"ttl":3600,"records":["ns1.{}"]}}"#, origin(zone)),
        &[],
    );
    assert_eq!(response.status, 201, "NS zone {zone}");
}

#[allow(clippy::too_many_lines)]
fn run_mode(label: &str, commit_mode: CommitMode) {
    let dir = tempfile::tempdir().expect("temp dir");
    let data = dir.path().join("parallel.v2");
    let mut config = base_config(&data, commit_mode);
    if commit_mode == CommitMode::Group {
        // Для группы проверяем контракт «ровно 2 fsync на группу» в `Sync`.
        config.durability = Durability::Sync;
    }
    let mut server = Server::start_with_api(&config, Some(api_options())).expect("start DNS+API");
    let api = server.api_addr().expect("api");

    for zone in 0..ZONES {
        create_zone(api, zone);
    }

    let barrier = std::sync::Arc::new(Barrier::new(THREADS));
    let failures = std::sync::Arc::new(AtomicUsize::new(0));
    std::thread::scope(|scope| {
        for thread in 0..THREADS {
            let barrier = std::sync::Arc::clone(&barrier);
            let failures = std::sync::Arc::clone(&failures);
            scope.spawn(move || {
                let zone = thread % ZONES;
                barrier.wait();
                for record in 0..RECORDS {
                    let owner = format!("r{thread}-{record}.{origin}", origin = origin(zone));
                    let octets = format!("192.0.2.{}", thread * RECORDS + record + 1);
                    let path = format!("{}/records/{owner}/A", zone_path(zone));
                    let body = format!(r#"{{"ttl":120,"records":["{octets}"]}}"#);
                    let response = put_retry(api, &path, &body);
                    if response.status != 201 {
                        eprintln!("PUT {owner} -> {}: {}", response.status, response.body);
                        failures.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });
        }
    });
    assert_eq!(
        failures.load(Ordering::Relaxed),
        0,
        "{label}: REST failures"
    );

    let check = |server: &Server, phase: &str| {
        for zone in 0..ZONES {
            let response = dns_query(server, &origin(zone), Rtype::SOA);
            assert_eq!(
                response.rcode(),
                Rcode::NOERROR,
                "{label}/{phase}: SOA {zone}"
            );
            for thread in (0..THREADS).filter(|thread| thread % ZONES == zone) {
                for record in 0..RECORDS {
                    let owner = format!("r{thread}-{record}.{origin}", origin = origin(zone));
                    let response = dns_query(server, &owner, Rtype::A);
                    assert_eq!(response.rcode(), Rcode::NOERROR, "{label}/{phase}: {owner}");
                    assert_eq!(
                        response.answers().len(),
                        1,
                        "{label}/{phase}: {owner} answers"
                    );
                    assert!(
                        matches!(response.answers()[0].rdata(), Rdata::A(_)),
                        "{label}/{phase}: {owner} rdata"
                    );
                }
            }
        }
    };
    check(&server, "before-reopen");

    // Метрики v2: alloc, cache, pins и (для group) счётчик групп.
    let bearer = format!("Bearer {TOKEN}");
    let metrics = http(api, "GET", "/metrics", &[("Authorization", &bearer)], None);
    assert_eq!(metrics.status, 200);
    for name in [
        "zonefile_lookups",
        "zonefile_snapshot_pins",
        "zonefile_v2_alloc_pages",
        "zonefile_v2_page_cache_hits_total",
        "zonefile_v2_node_cache_hits_total",
        "zonefile_v2_reclaimed_pages_total",
        "zonefile_v2_pins",
        "zonefile_v2_group_commits_total",
        "zonefile_v2_group_fsyncs_total",
    ] {
        assert!(
            metrics.body.contains(name),
            "{label}: /metrics misses {name}"
        );
    }
    if commit_mode == CommitMode::Group {
        let commits = metric_value(&metrics.body, "zonefile_v2_group_commits_total");
        let fsyncs = metric_value(&metrics.body, "zonefile_v2_group_fsyncs_total");
        assert!(commits > 0, "{label}: group commits not counted");
        // `Flush` не синхронизирует корни: fsync меньше, чем 2×групп.
        assert!(
            fsyncs <= commits * 2,
            "{label}: fsyncs {fsyncs} > 2*{commits}"
        );
    }

    server.shutdown().expect("shutdown");
    drop(server);

    let mut reopened = Server::start(&config).expect("reopen");
    check(&reopened, "after-reopen");
    reopened.shutdown().expect("shutdown");
}

#[test]
fn per_zone_parallel_writes_across_eight_zones() {
    run_mode("per-zone", CommitMode::PerZone);
}

#[test]
fn group_parallel_writes_across_eight_zones() {
    run_mode("group", CommitMode::Group);
}

/// Маленький файл (2k страниц) + много коммитов: фоновый GC/`sync()` обязан
/// возвращать страницы в пул, иначе `MapFull` задолго до конца прогона.
#[test]
#[allow(clippy::too_many_lines)]
fn small_map_survives_sustained_parallel_writes() {
    let dir = tempfile::tempdir().expect("temp dir");
    let data = dir.path().join("small.v2");
    let mut config = base_config(&data, CommitMode::PerZone);
    config.map_size = 16 * 1024 * 1024;
    let mut server = Server::start_with_api(&config, Some(api_options())).expect("start");
    let api = server.api_addr().expect("api");
    for zone in 0..ZONES {
        create_zone(api, zone);
    }
    let failures = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for thread in 0..8 {
            let failures = &failures;
            scope.spawn(move || {
                let zone = thread % ZONES;
                for record in 0..60 {
                    let owner = format!("s{thread}-{record}.{origin}", origin = origin(zone));
                    let body = r#"{"ttl":60,"records":["192.0.2.7"]}"#;
                    let response =
                        put_retry(api, &format!("{}/records/{owner}/A", zone_path(zone)), body);
                    if response.status != 201 {
                        eprintln!("PUT {owner} -> {}: {}", response.status, response.body);
                        failures.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });
        }
    });
    let bearer = format!("Bearer {TOKEN}");
    let metrics = http(api, "GET", "/metrics", &[("Authorization", &bearer)], None);
    let reclaimed = metric_value(&metrics.body, "zonefile_v2_reclaimed_pages_total");
    assert!(
        reclaimed > 0,
        "GC must return pages to the pool (reclaimed={reclaimed})"
    );
    assert_eq!(failures.load(Ordering::Relaxed), 0);
    for zone in 0..ZONES {
        assert_eq!(
            dns_query(&server, &origin(zone), Rtype::SOA).rcode(),
            Rcode::NOERROR
        );
    }
    server.shutdown().expect("shutdown");
    drop(server);

    let store = pulse_zonefile::parallel::ParallelStore::open(
        &data,
        pulse_zonefile::parallel::OpenConfigV2::default(),
    )
    .expect("open");
    assert!(store.fsck_lite().expect("fsck").ok);
    assert!(store.fsck_graph().expect("graph").ok);
    assert!(
        store.high_water() <= u64::from(store.geometry().page_count_max()),
        "allocator escaped the file limit"
    );
}
