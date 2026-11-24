//! E2E-тесты AXFR/IXFR, TSIG, ACL и NOTIFY на реальных сокетах.

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pulse_dns::{
    DecodeLimits, Message, Name, Opcode, Rclass, Rcode, Rdata, Record, Rtype, Serial, SoaData, Ttl,
};
use pulse_transfer::{
    AxfrClient, IxfrClient, IxfrOutcome, NotifyRequest, NotifyResponse, TransferError,
    TransferLimits, TsigAlgorithm, TsigKey, ZoneSnapshot, soa_serial,
};
use pulsed::config::{Config, RecordConfig, TcpConfig, TsigKeyConfig, ZoneConfig};
use pulsed::server::{ApiOptions, Server};

const TOKEN: &str = "pd_live_transfer_0123456789abcdef";
const KEY_NAME: &str = "xfr-key.test.";
const SECRET_B64: &str = "c2VjcmV0";

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
        b"secret".to_vec(),
    )
    .expect("key")
}

fn tsig_config(name: &str, secret: &str) -> TsigKeyConfig {
    TsigKeyConfig {
        name: name.to_owned(),
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
            "refresh": 7200,
            "retry": 900,
            "expire": 1_209_600,
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

fn a_config(owner: &str, address: &str) -> RecordConfig {
    RecordConfig {
        name: owner.to_owned(),
        rr_type: "A".to_owned(),
        ttl: Some(300),
        rdata: serde_json::json!(address),
    }
}

fn zone_config(records: Vec<RecordConfig>) -> ZoneConfig {
    ZoneConfig {
        origin: "example.com.".to_owned(),
        class: "IN".to_owned(),
        default_ttl: 3600,
        records,
    }
}

fn base_config(zone: ZoneConfig) -> Config {
    Config {
        listen_udp: Some("127.0.0.1:0".parse().expect("udp")),
        listen_tcp: Some("127.0.0.1:0".parse().expect("tcp")),
        workers: 1,
        tcp: TcpConfig {
            idle_timeout_ms: 5000,
            ..TcpConfig::default()
        },
        zones: vec![zone],
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

fn axfr(address: SocketAddr, key: Option<&TsigKey>) -> Result<ZoneSnapshot, TransferError> {
    let stream = TcpStream::connect(address).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("read timeout");
    let limits = TransferLimits {
        timeout: Some(Duration::from_secs(10)),
        ..TransferLimits::default()
    };
    let mut client = AxfrClient::with_limits(stream, limits);
    client.transfer(&name("example.com."), 0x7777, key, now())
}

fn soa_record(serial: u32) -> Record {
    Record::new(
        name("example.com."),
        Rtype::SOA,
        Rclass::IN,
        Ttl::new(3600).expect("ttl"),
        Rdata::Soa(SoaData::new(
            name("ns1.example.com."),
            name("hostmaster.example.com."),
            Serial::new(serial),
            7200,
            900,
            1_209_600,
            300,
        )),
    )
    .expect("soa")
}

fn ixfr(address: SocketAddr, client_serial: u32) -> Result<IxfrOutcome, TransferError> {
    let stream = TcpStream::connect(address).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("read timeout");
    let mut client = IxfrClient::with_limits(
        stream,
        TransferLimits {
            timeout: Some(Duration::from_secs(10)),
            ..TransferLimits::default()
        },
    );
    client.transfer(
        &name("example.com."),
        &soa_record(client_serial),
        0x7778,
        None,
        now(),
    )
}

#[test]
fn axfr_ten_thousand_records_with_and_without_tsig() {
    let mut records = Vec::with_capacity(10_002);
    records.push(soa_config(2_026_112_401));
    records.push(ns_config());
    for index in 0..10_000_u32 {
        let address = format!(
            "10.{}.{}.{}",
            (index >> 16) & 0xFF,
            (index >> 8) & 0xFF,
            index & 0xFF
        );
        records.push(a_config(&format!("host{index}"), &address));
    }

    let mut unsigned = base_config(zone_config(records.clone()));
    unsigned.transfer.require_tsig = false;
    let mut server = Server::start(&unsigned).expect("start unsigned");
    let snapshot = axfr(server.tcp_addr().expect("tcp"), None).expect("unsigned AXFR");
    assert_eq!(snapshot.serial(), Serial::new(2_026_112_401));
    assert_eq!(snapshot.records().len(), 10_001);
    assert_eq!(snapshot.records_with_soa().len(), 10_002);
    server.shutdown().expect("shutdown unsigned");

    let mut signed_config = base_config(zone_config(records));
    signed_config.tsig_keys = vec![tsig_config(KEY_NAME, SECRET_B64)];
    signed_config.transfer.require_tsig = true;
    let mut server = Server::start(&signed_config).expect("start signed");
    let key = key();
    let snapshot = axfr(server.tcp_addr().expect("tcp"), Some(&key)).expect("signed AXFR");
    assert_eq!(snapshot.serial(), Serial::new(2_026_112_401));
    assert_eq!(snapshot.records().len(), 10_001);
    server.shutdown().expect("shutdown signed");
}

#[test]
fn tsig_and_acl_rejections_are_notauth_or_refused() {
    let zone = || zone_config(vec![soa_config(1), ns_config()]);

    let mut config = base_config(zone());
    config.tsig_keys = vec![tsig_config(KEY_NAME, SECRET_B64)];
    let mut server = Server::start(&config).expect("start");
    let address = server.tcp_addr().expect("tcp");

    let unsigned = axfr(address, None).expect_err("unsigned must be rejected");
    assert!(matches!(
        unsigned,
        TransferError::Server {
            rcode: Rcode::NOTAUTH,
            ..
        }
    ));

    let wrong = TsigKey::new(
        name("other-key.test."),
        TsigAlgorithm::HmacSha256,
        b"wrong".to_vec(),
    )
    .expect("key");
    let bad = axfr(address, Some(&wrong)).expect_err("wrong key must be rejected");
    assert!(matches!(
        bad,
        TransferError::Server {
            rcode: Rcode::NOTAUTH,
            ..
        }
    ));
    server.shutdown().expect("shutdown");

    let mut denied = base_config(zone());
    denied.transfer.require_tsig = false;
    denied.transfer.allow_from = vec!["192.0.2.1".parse().expect("ip")];
    let mut server = Server::start(&denied).expect("start denied");
    let error = axfr(server.tcp_addr().expect("tcp"), None).expect_err("ACL must deny");
    assert!(matches!(
        error,
        TransferError::Server {
            rcode: Rcode::REFUSED,
            ..
        }
    ));
    server.shutdown().expect("shutdown");
}

#[test]
fn ixfr_incremental_and_axfr_fallback() {
    let mut records = vec![soa_config(1), ns_config()];
    for index in 0..100_u32 {
        records.push(a_config(
            &format!("host{index}"),
            &format!("10.0.0.{index}"),
        ));
    }
    records.push(a_config("www", "192.0.2.10"));
    let mut config = base_config(zone_config(records));
    config.transfer.require_tsig = false;
    let mut server = Server::start_with_api(&config, Some(api_options())).expect("start DNS+API");
    let tcp = server.tcp_addr().expect("tcp");
    let api = server.api_addr().expect("api");

    let up_to_date = ixfr(tcp, 1).expect("IXFR uptodate");
    assert!(matches!(up_to_date, IxfrOutcome::UpToDate { .. }));

    // Меняем данные и продвигаем SOA serial отдельным PUT: история ведётся
    // только по serial, поэтому дельта появляется после его роста.
    put_rrset(
        api,
        "www.example.com.",
        "A",
        r#"{"ttl":300,"records":["192.0.2.11"]}"#,
    );
    put_rrset(
        api,
        "example.com.",
        "SOA",
        r#"{"ttl":3600,"records":["ns1.example.com. hostmaster.example.com. 2 7200 900 1209600 300"]}"#,
    );

    let incremental = ixfr(tcp, 1).expect("IXFR incremental");
    let IxfrOutcome::Incremental {
        from,
        current,
        deltas,
    } = incremental
    else {
        panic!("expected incremental IXFR, got {incremental:?}");
    };
    assert_eq!(from, Serial::new(1));
    assert_eq!(soa_serial(&current), Some(Serial::new(2)));
    assert_eq!(deltas.len(), 1);
    assert_eq!(deltas[0].from(), Serial::new(1));
    assert_eq!(deltas[0].to(), Serial::new(2));

    let fallback = ixfr(tcp, 0).expect("IXFR fallback");
    let IxfrOutcome::AxfrFallback { zone } = fallback else {
        panic!("expected AXFR fallback, got {fallback:?}");
    };
    assert_eq!(zone.serial(), Serial::new(2));
    assert_eq!(zone.records().len(), 102);

    server.shutdown().expect("shutdown");
}

#[test]
fn rest_change_sends_notify_out_with_tsig() {
    let receiver = UdpSocket::bind("127.0.0.1:0").expect("receiver");
    receiver
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let receiver_addr = receiver.local_addr().expect("addr");

    let mut config = base_config(zone_config(vec![
        soa_config(7),
        ns_config(),
        a_config("www", "192.0.2.20"),
    ]));
    config.tsig_keys = vec![tsig_config(KEY_NAME, SECRET_B64)];
    config.transfer.notify = vec![receiver_addr];
    config.transfer.notify_tsig_key = Some(KEY_NAME.to_owned());
    config.transfer.notify_retries = 1;
    let mut server = Server::start_with_api(&config, Some(api_options())).expect("start DNS+API");
    let api = server.api_addr().expect("api");

    put_rrset(
        api,
        "www.example.com.",
        "A",
        r#"{"ttl":300,"records":["192.0.2.21"]}"#,
    );

    let mut buffer = [0_u8; 4096];
    let (length, _) = recv_from(&receiver, &mut buffer).expect("NOTIFY");
    let raw = buffer.get(..length).expect("length");
    let message = Message::decode(raw, &DecodeLimits::default()).expect("decode NOTIFY");
    assert_eq!(message.opcode(), Opcode::NOTIFY);
    assert_eq!(message.questions().len(), 1);
    assert_eq!(message.questions()[0].qname(), &name("example.com."));
    assert_eq!(message.answers().len(), 1);
    assert_eq!(message.answers()[0].rr_type(), Rtype::SOA);
    key()
        .verify_request(raw, now())
        .expect("NOTIFY TSIG must verify");

    server.shutdown().expect("shutdown");
}

#[test]
fn notify_in_returns_noerror_and_marks_zone() {
    let mut config = base_config(zone_config(vec![
        soa_config(3),
        ns_config(),
        a_config("www", "192.0.2.30"),
    ]));
    config.tsig_keys = vec![tsig_config(KEY_NAME, SECRET_B64)];
    let mut server = Server::start(&config).expect("start");
    let udp = server.udp_addr().expect("udp");
    let key = key();

    let request = NotifyRequest::new(0x5151, name("example.com."))
        .with_soa(soa_record(4))
        .expect("soa hint");
    let encoded = request.encode(Some(&key), now()).expect("encode");
    let socket = UdpSocket::bind("127.0.0.1:0").expect("client");
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("timeout");
    socket.send_to(&encoded.bytes, udp).expect("send");
    let mut buffer = [0_u8; 4096];
    let (length, _) = recv_from(&socket, &mut buffer).expect("response");
    let raw = buffer.get(..length).expect("length");
    let (response, _) = NotifyResponse::decode(
        raw,
        &request,
        encoded.request_mac.as_deref(),
        Some(&key),
        now(),
    )
    .expect("decode response");
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert_eq!(
        server.pending_transfer_updates(),
        vec![name("example.com.")]
    );

    // Без TSIG при require_tsig=true — NOTAUTH.
    let unsigned = NotifyRequest::new(0x5252, name("example.com."))
        .encode(None, now())
        .expect("encode");
    socket.send_to(&unsigned.bytes, udp).expect("send unsigned");
    let (length, _) = recv_from(&socket, &mut buffer).expect("refusal");
    let refusal = Message::decode(
        buffer.get(..length).expect("length"),
        &DecodeLimits::default(),
    )
    .expect("decode refusal");
    assert_eq!(refusal.rcode(), Rcode::NOTAUTH);

    server.shutdown().expect("shutdown");
}

#[test]
fn notify_in_unknown_zone_is_refused() {
    let mut config = base_config(zone_config(vec![soa_config(1), ns_config()]));
    config.transfer.require_tsig = false;
    let mut server = Server::start(&config).expect("start");
    let udp = server.udp_addr().expect("udp");

    let request = NotifyRequest::new(0x6161, name("other.test."))
        .encode(None, now())
        .expect("encode");
    let socket = UdpSocket::bind("127.0.0.1:0").expect("client");
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("timeout");
    socket.send_to(&request.bytes, udp).expect("send");
    let mut buffer = [0_u8; 4096];
    let (length, _) = recv_from(&socket, &mut buffer).expect("response");
    let response = Message::decode(
        buffer.get(..length).expect("length"),
        &DecodeLimits::default(),
    )
    .expect("decode");
    assert_eq!(response.rcode(), Rcode::REFUSED);

    server.shutdown().expect("shutdown");
}

#[test]
fn axfr_after_persistence_reopen_sees_rest_changes() {
    let dir = TempDir::new("transfer-reopen");
    let data = dir.path().join("zones.pulse");
    let mut config = base_config(zone_config(vec![
        soa_config(10),
        ns_config(),
        a_config("www", "192.0.2.40"),
    ]));
    config.zonefile = Some(data.clone());
    config.map_size = 64 * 1024 * 1024;
    config.tsig_keys = vec![tsig_config(KEY_NAME, SECRET_B64)];
    let key = key();

    {
        let mut server = Server::start_with_api(&config, Some(api_options())).expect("start first");
        let api = server.api_addr().expect("api");
        put_rrset(
            api,
            "www.example.com.",
            "A",
            r#"{"ttl":300,"records":["192.0.2.41"]}"#,
        );
        server.shutdown().expect("shutdown first");
    }

    let mut server = Server::start_with_api(&config, Some(api_options())).expect("reopen");
    let snapshot = axfr(server.tcp_addr().expect("tcp"), Some(&key)).expect("AXFR after reopen");
    assert!(
        snapshot
            .records()
            .iter()
            .any(|record| record.owner() == &name("www.example.com.")
                && record.rdata() == &Rdata::A("192.0.2.41".parse().expect("ipv4")))
    );
    server.shutdown().expect("shutdown second");
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "pulsed-transfer-{label}-{}-{}",
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

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

fn recv_from(socket: &UdpSocket, buffer: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
    loop {
        match socket.recv_from(buffer) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            result => return result,
        }
    }
}

fn put_rrset(api: SocketAddr, owner: &str, rr_type: &str, body: &str) {
    let path = format!("/api/v1/zones/example.com./records/{owner}/{rr_type}");
    let response = http(
        api,
        "PUT",
        &path,
        &[
            ("Authorization", &format!("Bearer {TOKEN}")),
            ("If-Match", "*"),
        ],
        Some(body.as_bytes()),
    );
    assert!(
        matches!(response.status, 200 | 201),
        "PUT {path} failed: {} {}",
        response.status,
        String::from_utf8_lossy(&response.body)
    );
}

fn http(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> HttpResponse {
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
    let header_end = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("header terminator");
    let header_block =
        std::str::from_utf8(raw.get(..header_end).expect("headers")).expect("ASCII headers");
    let status = header_block
        .lines()
        .next()
        .expect("status line")
        .split(' ')
        .nth(1)
        .expect("status code")
        .parse::<u16>()
        .expect("numeric status");
    HttpResponse {
        status,
        body: raw.get(header_end + 4..).expect("body").to_vec(),
    }
}
