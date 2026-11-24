//! `RSS`-проверка: DNS-ответы читают `mmap` и не материализуют все `RRset`.
//!
//! Полный тест на 100k `RRset` помечен `#[ignore]`, потому что импорт большого
//! master-файла в debug-сборке занимает минуты. Обычный прогон проверяет тот
//! же инвариант на 2k `RRset`: анонимная память процесса растёт ограниченно,
//! а `zonefile_lookups` увеличивается после ответа из mmap.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use pulse_dns::{DecodeLimits, EncodeOptions, Message, Name, Question, Rclass, Rtype};
use pulsed::server::{ApiOptions, Server};

const TOKEN: &str = "pd_live_memory_0123456789abcdef";
const LOOKUP_DEADLINE: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Память процесса из `/proc/self/status`: `(VmRSS, RssAnon, RssFile)`.
fn rss() -> (u64, u64, u64) {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let field = |name: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|rest| rest.trim().strip_suffix("kB"))
            .and_then(|value| value.trim().parse::<u64>().ok())
            .unwrap_or(0)
            .saturating_mul(1024)
    };
    (field("VmRSS:"), field("RssAnon:"), field("RssFile:"))
}

fn master_zone(records: u32) -> String {
    let mut text = String::from(
        "$ORIGIN memory.test.\n$TTL 3600\n\
         @ IN SOA ns1.memory.test. hostmaster.memory.test. 1 3600 600 604800 300\n\
         @ IN NS ns1.memory.test.\n\
         ns1 IN A 192.0.2.53\n",
    );
    for index in 0..records {
        use std::fmt::Write as _;
        let _ = writeln!(text, "host{index} IN A 10.0.0.1");
    }
    text
}

#[allow(unused_assignments)]
fn query(server: &Server, qname: &str) -> Message {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("client");
    socket
        .set_read_timeout(Some(Duration::from_millis(100)))
        .expect("timeout");
    let address = server.udp_addr().expect("udp");
    let bytes = Message::query(
        1,
        Question::new(Name::parse(qname).expect("qname"), Rtype::A, Rclass::IN),
    )
    .encode(&EncodeOptions::compressed())
    .expect("encode");
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut buffer = [0_u8; 4096];
    let mut last_error = None;
    loop {
        if let Err(error) = socket.send_to(&bytes, address) {
            panic!("cannot send UDP query for {qname}: {error}");
        }
        match socket.recv_from(&mut buffer) {
            Ok((length, _)) => {
                return Message::decode(&buffer[..length], &DecodeLimits::default())
                    .expect("decode");
            }
            Err(error) => last_error = Some(error),
        }
        assert!(
            Instant::now() < deadline,
            "no UDP response for {qname} within 15s (last error: {:?},              server stats: {:?}, udp stats: {:?})",
            last_error,
            server.stats(),
            server.udp_stats()
        );
    }
}

fn metrics(api: SocketAddr) -> Option<String> {
    let mut stream = TcpStream::connect(api).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let request = format!(
        "GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Authorization: Bearer {TOKEN}\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    Some(response)
}

fn lookups(body: &str) -> Option<u64> {
    body.lines()
        .find_map(|line| line.strip_prefix("zonefile_lookups "))
        .and_then(|value| value.trim().parse().ok())
}

/// Читает `/metrics` до появления `zonefile_lookups > 0`.
///
/// Ответ на UDP уже получен, но HTTP-счётчик читается отдельным соединением;
/// повтор убирает зависимость от планировщика и коротких сетевых задержек.
fn wait_for_lookups(api: SocketAddr) -> (u64, String) {
    let deadline = Instant::now() + LOOKUP_DEADLINE;
    let mut last_body = String::new();
    loop {
        if let Some(body) = metrics(api) {
            if let Some(value) = lookups(&body)
                && value > 0
            {
                return (value, body);
            }
            last_body = body;
        }
        if Instant::now() >= deadline {
            return (0, last_body);
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn run(records: u32, max_anon_growth: u64, label: &str) {
    let (_dir, path) = common::write_text(label, "memory.zone", &master_zone(records));
    let zone = common::TempZone::with_import(label, "memory.test.", &path);
    let config = common::base_config(zone.path());

    let (_, anon_before, _) = rss();
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

    // Прогрев: несколько точечных ответов из разных частей дерева, затем
    // короткая пауза, чтобы фоновые потоки и аллокатор стабилизировались.
    for host in [0, records / 4, records / 2, records - 1] {
        let response = query(&server, &format!("host{host}.memory.test."));
        assert_eq!(
            response.rcode(),
            pulse_dns::Rcode::NOERROR,
            "{label}: lookup in mmap must answer for host{host}"
        );
    }
    std::thread::sleep(Duration::from_millis(150));

    let (lookup_count, body) = wait_for_lookups(api);
    assert!(
        lookup_count > 0,
        "{label}: answer path must use zonefile lookups: {body}"
    );
    assert!(body.contains("zonefile_snapshot_pins "), "{body}");

    // Сравниваем только анонимную память: file-backed страницы mmap/page cache
    // не должны выдаваться за материализацию зоны.
    let (_, anon_after, _) = rss();
    let growth = anon_after.saturating_sub(anon_before);
    assert!(
        growth < max_anon_growth,
        "{label}: anonymous RSS grew by {growth} bytes, expected < {max_anon_growth} \
         (VmRSS={} RssAnon={} RssFile={})",
        rss().0,
        anon_after,
        rss().2
    );
    server.shutdown().expect("shutdown");
}

#[test]
fn answer_path_does_not_materialize_zone() {
    run(2_000, 64 * 1024 * 1024, "rss-2k");
}

#[test]
#[ignore = "100k RRset import is slow in debug builds; run with --ignored --nocapture"]
fn answer_path_does_not_materialize_100k_rrsets() {
    run(100_000, 128 * 1024 * 1024, "rss-100k");
}
