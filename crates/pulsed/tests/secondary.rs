//! E2E: primary → secondary (AXFR/IXFR-in), NOTIFY, persistence и expire.

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pulse_dns::{
    DecodeLimits, EncodeOptions, Message, Name, Question, Rclass, Rcode, Rdata, Record, Rtype,
    Serial, SoaData, Ttl,
};
use pulse_transfer::{IxfrClient, IxfrOutcome, TransferLimits, TsigAlgorithm, TsigKey};
use pulsed::config::{
    Config, Durability, RecordConfig, SecondaryZoneConfig, TcpConfig, TransferSettings,
    TsigKeyConfig, ZoneConfig,
};
use pulsed::server::{ApiOptions, Server};

const TOKEN: &str = "pd_live_secondary_0123456789abcdef";
const KEY_NAME: &str = "xfr-key.test.";
const SECRET: &str = "secret";
const ORIGIN: &str = "example.com.";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn name(text: &str) -> Name {
    Name::parse(text).expect("valid name")
}

fn key() -> TsigKey {
    TsigKey::new(
        name(KEY_NAME),
        TsigAlgorithm::HmacSha256,
        SECRET.as_bytes().to_vec(),
    )
    .expect("key")
}

fn key_config(secret: &str) -> TsigKeyConfig {
    TsigKeyConfig {
        name: KEY_NAME.to_owned(),
        algorithm: "hmac-sha256".to_owned(),
        secret: secret.to_owned(),
    }
}

fn soa_config(serial: u32) -> RecordConfig {
    RecordConfig {
        name: "@".to_owned(),
        rr_type: "SOA".to_owned(),
        ttl: Some(3600),
        rdata: serde_json::json!({
            "mname": "ns1.example.com.",
            "rname": "hostmaster.example.com.",
            "serial": serial,
            "refresh": 1,
            "retry": 1,
            "expire": 60,
            "minimum": 300
        }),
    }
}

fn ns_config() -> RecordConfig {
    RecordConfig {
        name: "@".to_owned(),
        rr_type: "NS".to_owned(),
        ttl: Some(3600),
        rdata: serde_json::json!("ns1.example.com."),
    }
}

fn a_config(address: &str) -> RecordConfig {
    RecordConfig {
        name: "www".to_owned(),
        rr_type: "A".to_owned(),
        ttl: Some(300),
        rdata: serde_json::json!(address),
    }
}

fn zone_config(serial: u32, address: &str) -> ZoneConfig {
    let mut records = vec![soa_config(serial), ns_config(), a_config(address)];
    for index in 0..100_u32 {
        records.push(RecordConfig {
            name: format!("host{index}"),
            rr_type: "A".to_owned(),
            ttl: Some(300),
            rdata: serde_json::json!(format!("10.0.0.{index}")),
        });
    }
    ZoneConfig {
        origin: ORIGIN.to_owned(),
        class: "IN".to_owned(),
        default_ttl: 3600,
        records,
    }
}

fn transfer_settings(timeout_ms: u64, notify: Vec<SocketAddr>) -> TransferSettings {
    TransferSettings {
        require_tsig: true,
        allow_from: vec!["127.0.0.1".parse().expect("ip")],
        timeout_ms,
        notify,
        notify_tsig_key: Some(KEY_NAME.to_owned()),
        notify_retries: 1,
        notify_timeout_ms: 500,
        ..TransferSettings::default()
    }
}

fn primary_config(zone: ZoneConfig, notify: Vec<SocketAddr>) -> Config {
    Config {
        listen_udp: Some("127.0.0.1:0".parse().expect("udp")),
        listen_tcp: Some("127.0.0.1:0".parse().expect("tcp")),
        workers: 1,
        tcp: TcpConfig {
            idle_timeout_ms: 2000,
            ..TcpConfig::default()
        },
        zones: vec![zone],
        tsig_keys: vec![key_config("c2VjcmV0")],
        transfer: transfer_settings(2_000, notify),
        ..Config::default()
    }
}

fn secondary_config(
    master: SocketAddr,
    udp: SocketAddr,
    zonefile: Option<PathBuf>,
    secret: &str,
    expire: u32,
) -> Config {
    Config {
        listen_udp: Some(udp),
        listen_tcp: Some("127.0.0.1:0".parse().expect("tcp")),
        workers: 1,
        tcp: TcpConfig {
            idle_timeout_ms: 2000,
            ..TcpConfig::default()
        },
        zones: Vec::new(),
        zonefile,
        durability: Durability::Flush,
        map_size: 64 * 1024 * 1024,
        tsig_keys: vec![key_config(secret)],
        secondary_zones: vec![SecondaryZoneConfig {
            origin: ORIGIN.to_owned(),
            masters: vec![master],
            tsig_key: Some(KEY_NAME.to_owned()),
            refresh: Some(1),
            retry: Some(1),
            expire: Some(expire),
            allow_notify_from: vec!["127.0.0.1".parse().expect("ip")],
            bootstrap: true,
        }],
        transfer: TransferSettings {
            timeout_ms: 500,
            notify_tsig_key: None,
            ..TransferSettings::default()
        },
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

fn free_udp_addr() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("free port");
    socket.local_addr().expect("addr")
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
    let socket = UdpSocket::bind("127.0.0.1:0").expect("client");
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("timeout");
    let query = Message::query(0x4242, Question::new(name(qname), qtype, Rclass::IN))
        .encode(&EncodeOptions::compressed())
        .expect("encode");
    socket
        .send_to(&query, server.udp_addr().expect("udp"))
        .expect("send");
    let mut buffer = [0_u8; 4096];
    let (length, _) = recv_from(&socket, &mut buffer).expect("recv");
    Message::decode(
        buffer.get(..length).expect("length"),
        &DecodeLimits::default(),
    )
    .expect("decode")
}

fn wait_for_serial(server: &Server, expected: u32, total: Duration) -> bool {
    let deadline = Instant::now() + total;
    while Instant::now() < deadline {
        let response = dns_query(server, ORIGIN, Rtype::SOA);
        if response.rcode() == Rcode::NOERROR
            && response
                .answers()
                .iter()
                .any(|record| record.rr_type() == Rtype::SOA && serial(record) == expected)
        {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

fn wait_for_a(server: &Server, expected: &str, total: Duration) -> bool {
    let deadline = Instant::now() + total;
    while Instant::now() < deadline {
        let response = dns_query(server, "www.example.com.", Rtype::A);
        if response.rcode() == Rcode::NOERROR
            && response
                .answers()
                .iter()
                .any(|record| record.rdata() == &Rdata::A(expected.parse().expect("ipv4")))
        {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

fn wait_for_rcode(server: &Server, rcode: Rcode, total: Duration) -> bool {
    let deadline = Instant::now() + total;
    while Instant::now() < deadline {
        if dns_query(server, ORIGIN, Rtype::SOA).rcode() == rcode {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

fn serial(record: &Record) -> u32 {
    match record.rdata() {
        Rdata::Soa(soa) => soa.serial.as_u32(),
        _ => 0,
    }
}

fn soa_record(value: u32) -> Record {
    Record::new(
        name(ORIGIN),
        Rtype::SOA,
        Rclass::IN,
        Ttl::new(3600).expect("ttl"),
        Rdata::Soa(SoaData::new(
            name("ns1.example.com."),
            name("hostmaster.example.com."),
            Serial::new(value),
            1,
            1,
            60,
            300,
        )),
    )
    .expect("soa")
}

fn ixfr_primary(
    address: SocketAddr,
    client_serial: u32,
) -> Result<IxfrOutcome, pulse_transfer::TransferError> {
    let stream = TcpStream::connect(address).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let mut client = IxfrClient::with_limits(
        stream,
        TransferLimits {
            timeout: Some(Duration::from_secs(5)),
            ..TransferLimits::default()
        },
    );
    client.transfer(
        &name(ORIGIN),
        &soa_record(client_serial),
        0x7777,
        Some(&key()),
        now(),
    )
}

fn put_a(api: SocketAddr, address: &str) -> (u16, Vec<u8>) {
    put(
        api,
        "/api/v1/zones/example.com./records/www.example.com./A",
        &format!(r#"{{"ttl":300,"records":["{address}"]}}"#),
        true,
    )
}

fn put(api: SocketAddr, path: &str, body: &str, if_match: bool) -> (u16, Vec<u8>) {
    let mut stream = TcpStream::connect(api).expect("connect API");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let auth = format!("Bearer {TOKEN}");
    let mut head = format!("PUT {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
    let _ = write!(head, "Authorization: {auth}\r\n");
    if if_match {
        head.push_str("If-Match: *\r\n");
    }
    head.push_str("Content-Type: application/json\r\n");
    let _ = write!(head, "Content-Length: {}\r\n\r\n", body.len());
    stream.write_all(head.as_bytes()).expect("head");
    stream.write_all(body.as_bytes()).expect("body");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read");
    let header_end = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("headers");
    let status = std::str::from_utf8(raw.get(..header_end).expect("headers"))
        .expect("ascii")
        .lines()
        .next()
        .expect("status")
        .split(' ')
        .nth(1)
        .expect("code")
        .parse::<u16>()
        .expect("numeric");
    (status, raw.get(header_end + 4..).expect("body").to_vec())
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "pulsed-secondary-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
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

#[test]
fn primary_to_secondary_bootstrap_update_ixfr_and_reopen() {
    let dir = TempDir::new("full");
    let data = dir.path().join("secondary.pulse");
    let secondary_udp = free_udp_addr();
    let mut primary = Server::start_with_api(
        &primary_config(zone_config(1, "192.0.2.10"), vec![secondary_udp]),
        Some(api_options()),
    )
    .expect("primary");
    let primary_tcp = primary.tcp_addr().expect("primary tcp");
    let primary_api = primary.api_addr().expect("primary api");

    let secondary_config = secondary_config(
        primary_tcp,
        secondary_udp,
        Some(data.clone()),
        "c2VjcmV0",
        60,
    );
    let mut secondary =
        Server::start_with_api(&secondary_config, Some(api_options())).expect("secondary");
    assert!(
        wait_for_serial(&secondary, 1, Duration::from_secs(10)),
        "secondary did not bootstrap: {:?}",
        secondary.secondary_last_error(&name(ORIGIN))
    );
    assert!(wait_for_a(&secondary, "192.0.2.10", Duration::from_secs(2)));

    // Три изменения primary: serial 2, 3, 4 и три IXFR-дельты.
    for address in ["192.0.2.21", "192.0.2.22", "192.0.2.23"] {
        let (status, body) = put_a(primary_api, address);
        assert!(
            matches!(status, 200 | 201),
            "PUT failed: {status} {}",
            String::from_utf8_lossy(&body)
        );
    }

    let outcome = ixfr_primary(primary_tcp, 1).expect("IXFR from primary");
    let IxfrOutcome::Incremental { deltas, .. } = outcome else {
        panic!("expected incremental IXFR, got {outcome:?}");
    };
    assert_eq!(deltas.len(), 3);

    assert!(
        wait_for_serial(&secondary, 4, Duration::from_secs(10)),
        "secondary did not update serial: {:?}",
        secondary.secondary_last_error(&name(ORIGIN))
    );
    assert!(wait_for_a(&secondary, "192.0.2.23", Duration::from_secs(5)));

    // Secondary read-only для RRset API.
    let api = secondary.api_addr().expect("secondary api");
    let (status, _) = put(
        api,
        "/api/v1/zones/example.com./records/www.example.com./A",
        r#"{"ttl":300,"records":["192.0.2.99"]}"#,
        true,
    );
    assert_eq!(status, 409);

    secondary.shutdown().expect("secondary shutdown");
    drop(secondary);
    primary.shutdown().expect("primary shutdown");
    drop(primary);

    // Рестарт secondary без master: данные должны прийти из zonefile.
    let mut secondary =
        Server::start_with_api(&secondary_config, Some(api_options())).expect("secondary reopen");
    assert!(
        wait_for_serial(&secondary, 4, Duration::from_secs(5)),
        "secondary did not load from zonefile"
    );
    assert!(wait_for_a(&secondary, "192.0.2.23", Duration::from_secs(2)));
    secondary.shutdown().expect("secondary shutdown");
}

#[test]
fn secondary_retries_and_expires_when_master_is_down() {
    let secondary_udp = free_udp_addr();
    let mut primary = Server::start(&primary_config(
        zone_config(1, "192.0.2.10"),
        vec![secondary_udp],
    ))
    .expect("primary");
    let primary_tcp = primary.tcp_addr().expect("primary tcp");
    let mut secondary = Server::start(&secondary_config(
        primary_tcp,
        secondary_udp,
        None,
        "c2VjcmV0",
        1,
    ))
    .expect("secondary");
    assert!(wait_for_serial(&secondary, 1, Duration::from_secs(10)));

    primary.shutdown().expect("primary shutdown");
    assert!(
        wait_for_rcode(&secondary, Rcode::SERVFAIL, Duration::from_secs(15)),
        "secondary did not expire: {:?}",
        secondary.secondary_last_error(&name(ORIGIN))
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && secondary.secondary_last_error(&name(ORIGIN)).is_none() {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(secondary.secondary_last_error(&name(ORIGIN)).is_some());
    secondary.shutdown().expect("secondary shutdown");
}

#[test]
fn secondary_rejects_wrong_tsig() {
    let secondary_udp = free_udp_addr();
    let mut primary =
        Server::start(&primary_config(zone_config(1, "192.0.2.10"), Vec::new())).expect("primary");
    let primary_tcp = primary.tcp_addr().expect("primary tcp");
    let mut secondary = Server::start(&secondary_config(
        primary_tcp,
        secondary_udp,
        None,
        "d3Jvbmc=",
        60,
    ))
    .expect("secondary");

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && secondary.secondary_last_error(&name(ORIGIN)).is_none() {
        std::thread::sleep(Duration::from_millis(100));
    }
    let error = secondary
        .secondary_last_error(&name(ORIGIN))
        .expect("TSIG error must be recorded");
    assert!(
        error.contains("NOTAUTH") || error.contains("TSIG") || error.contains("BADSIG"),
        "unexpected error: {error}"
    );
    let response = dns_query(&secondary, ORIGIN, Rtype::SOA);
    assert_eq!(response.rcode(), Rcode::REFUSED);

    secondary.shutdown().expect("secondary shutdown");
    primary.shutdown().expect("primary shutdown");
}

#[test]
fn bootstrap_false_waits_for_notify() {
    let secondary_udp = free_udp_addr();
    let mut primary = Server::start_with_api(
        &primary_config(zone_config(1, "192.0.2.10"), vec![secondary_udp]),
        Some(api_options()),
    )
    .expect("primary");
    let primary_tcp = primary.tcp_addr().expect("primary tcp");
    let primary_api = primary.api_addr().expect("primary api");
    let mut config = secondary_config(primary_tcp, secondary_udp, None, "c2VjcmV0", 60);
    config.secondary_zones[0].bootstrap = false;
    let mut secondary = Server::start(&config).expect("secondary");

    // Без bootstrap зоны нет: REFUSED.
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        assert_ne!(
            dns_query(&secondary, ORIGIN, Rtype::SOA).rcode(),
            Rcode::NOERROR
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    let (status, body) = put_a(primary_api, "192.0.2.11");
    assert!(
        matches!(status, 200 | 201),
        "PUT failed: {status} {}",
        String::from_utf8_lossy(&body)
    );
    assert!(
        wait_for_serial(&secondary, 2, Duration::from_secs(10)),
        "secondary did not bootstrap on NOTIFY: {:?}",
        secondary.secondary_last_error(&name(ORIGIN))
    );
    assert!(wait_for_a(&secondary, "192.0.2.11", Duration::from_secs(5)));

    secondary.shutdown().expect("secondary shutdown");
    primary.shutdown().expect("primary shutdown");
}
