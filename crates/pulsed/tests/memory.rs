//! `RSS`-проверка: DNS-ответы читают `mmap` и не материализуют все `RRset`.
//!
//! Полный тест на 100k `RRset` помечен `#[ignore]`, потому что импорт большого
//! master-файла в debug-сборке занимает минуты. Обычный прогон проверяет тот
//! же инвариант на 2k `RRset`: рост `RSS` ограничен, а `zonefile_lookups` растёт.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

use pulse_dns::{DecodeLimits, EncodeOptions, Message, Name, Question, Rclass, Rtype};
use pulsed::server::{ApiOptions, Server};

const TOKEN: &str = "pd_live_memory_0123456789abcdef";

fn rss_bytes() -> u64 {
    let statm = std::fs::read_to_string("/proc/self/statm").unwrap_or_default();
    let pages: u64 = statm
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    pages.saturating_mul(4096)
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

fn query(server: &Server, qname: &str) -> Message {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("client");
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("timeout");
    let bytes = Message::query(
        1,
        Question::new(Name::parse(qname).expect("qname"), Rtype::A, Rclass::IN),
    )
    .encode(&EncodeOptions::compressed())
    .expect("encode");
    socket
        .send_to(&bytes, server.udp_addr().expect("udp"))
        .expect("send");
    let mut buffer = [0_u8; 4096];
    let (length, _) = socket.recv_from(&mut buffer).expect("recv");
    Message::decode(&buffer[..length], &DecodeLimits::default()).expect("decode")
}

fn metrics(api: SocketAddr) -> String {
    let mut stream = TcpStream::connect(api).expect("connect api");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let request = format!(
        "GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Authorization: Bearer {TOKEN}\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).expect("write");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read");
    response
}

fn run(records: u32, max_rss_growth: u64, label: &str) {
    let (_dir, path) = common::write_text(label, "memory.zone", &master_zone(records));
    let zone = common::TempZone::with_import(label, "memory.test.", &path);
    let config = common::base_config(zone.path());
    let before = rss_bytes();
    let mut server = Server::start_with_api(
        &config,
        Some(ApiOptions {
            listen: "127.0.0.1:0".parse().expect("api"),
            token: TOKEN.to_owned(),
            scopes: Vec::new(),
        }),
    )
    .expect("start");
    let response = query(&server, &format!("host{}.memory.test.", records / 2));
    assert_eq!(
        response.rcode(),
        pulse_dns::Rcode::NOERROR,
        "lookup in mmap must answer"
    );
    let api = server.api_addr().expect("api");
    let body = metrics(api);
    assert!(body.contains("zonefile_lookups "), "{body}");
    assert!(
        !body.contains("zonefile_lookups 0\n"),
        "answer path must use zonefile lookups: {body}"
    );
    let after = rss_bytes();
    let growth = after.saturating_sub(before);
    assert!(
        growth < max_rss_growth,
        "{label}: RSS grew by {growth} bytes, expected < {max_rss_growth}"
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
    run(100_000, 256 * 1024 * 1024, "rss-100k");
}
