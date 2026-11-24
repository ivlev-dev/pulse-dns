//! E2E: primary → secondary (AXFR/IXFR-in), NOTIFY, persistence и expire.

mod common;

use std::fmt::Write as _;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pulse_dns::{
    DecodeLimits, EncodeOptions, Message, Name, Question, Rclass, Rcode, Rdata, Record, Rtype,
    Serial, SoaData, Ttl,
};
use pulse_transfer::{IxfrClient, IxfrOutcome, TransferLimits, TsigAlgorithm, TsigKey};
use pulsed::config::{
    Config, Durability, SecondaryZoneConfig, TcpConfig, TransferSettings, TsigKeyConfig,
};
use pulsed::server::{ApiOptions, Server};

const TOKEN: &str = "pd_live_secondary_0123456789abcdef";
const KEY_NAME: &str = "xfr-key.test.";
const SECRET: &str = "secret";
const ORIGIN: &str = "example.com.";

/// Сколько раз целиком перезапускать пару primary+secondary при гонке за порт.
const START_ATTEMPTS: u32 = 5;

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

fn soa_config(serial: u32) -> String {
    format!("@ 3600 IN SOA ns1.example.com. hostmaster.example.com. {serial} 1 1 60 300")
}

fn ns_config() -> String {
    "@ 3600 IN NS ns1.example.com.".to_owned()
}

fn a_config(address: &str) -> String {
    format!("www 300 IN A {address}")
}

fn zone_config(serial: u32, address: &str) -> Vec<String> {
    let mut records = vec![soa_config(serial), ns_config(), a_config(address)];
    for index in 0..100_u32 {
        records.push(format!("host{index} 300 IN A 10.0.0.{index}"));
    }
    records
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

fn primary_config(
    records: Vec<String>,
    notify: Vec<SocketAddr>,
    listen_tcp: SocketAddr,
) -> (common::TempZone, Config) {
    let mut text = String::from("$ORIGIN example.com.\n$TTL 3600\n");
    for line in records {
        text.push_str(&line);
        text.push('\n');
    }
    let (_dir, path) = common::write_text("secondary-primary", "zone", &text);
    let zone = common::TempZone::with_import("secondary-primary", ORIGIN, &path);
    let mut config = common::base_config(zone.path());
    config.listen_tcp = Some(listen_tcp);
    config.tcp = TcpConfig {
        idle_timeout_ms: 2000,
        ..TcpConfig::default()
    };
    config.tsig_keys = vec![key_config("c2VjcmV0")];
    config.transfer = transfer_settings(2_000, notify);
    (zone, config)
}

fn secondary_config(
    master: SocketAddr,
    zonefile: Option<PathBuf>,
    secret: &str,
    expire: u32,
    refresh: u32,
    bootstrap: bool,
) -> Config {
    Config {
        // Порт 0: фактический адрес сообщает сам сервер. Резервировать UDP-порт
        // снаружи нельзя — `pulse-runtime` использует `SO_REUSEPORT`, и
        // «свободный» порт может молча достаться двум серверам сразу.
        listen_udp: Some("127.0.0.1:0".parse().expect("udp")),
        listen_tcp: Some("127.0.0.1:0".parse().expect("tcp")),
        workers: 1,
        tcp: TcpConfig {
            idle_timeout_ms: 2000,
            ..TcpConfig::default()
        },
        zonefile,
        durability: Durability::Flush,
        map_size: 64 * 1024 * 1024,
        tsig_keys: vec![key_config(secret)],
        secondary_zones: vec![SecondaryZoneConfig {
            origin: ORIGIN.to_owned(),
            masters: vec![master],
            tsig_key: Some(KEY_NAME.to_owned()),
            refresh: Some(refresh),
            retry: Some(1),
            expire: Some(expire),
            allow_notify_from: vec!["127.0.0.1".parse().expect("ip")],
            bootstrap,
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

fn start_optional_api(config: &Config, with_api: bool) -> Result<Server, String> {
    let started = if with_api {
        Server::start_with_api(config, Some(api_options()))
    } else {
        Server::start(config)
    };
    started.map_err(|error| error.to_string())
}

/// Описание пары primary+secondary для [`start_pair`].
///
/// Флаги независимы: это набор сценариев e2e, а не состояние автомата.
#[allow(clippy::struct_excessive_bools)]
struct PairSpec {
    records: Vec<String>,
    zone: Option<PathBuf>,
    secret: &'static str,
    expire: u32,
    refresh: u32,
    bootstrap: bool,
    primary_api: bool,
    secondary_api: bool,
    /// Передавать ли адрес secondary в `notify` primary (тогда secondary
    /// стартует первым, чтобы его UDP-порт был известен до старта primary).
    notify: bool,
}

/// Поднятая пара серверов; zone primary живёт столько же, сколько пара.
struct Pair {
    _primary_zone: common::TempZone,
    primary: Server,
    secondary: Server,
}

/// Поднимает primary и secondary, не угадывая UDP-порт secondary.
///
/// При `notify` secondary слушает UDP на `port = 0` → фактический адрес берётся
/// у сервера → он же уходит в `notify` primary. Иначе primary стартует первым.
/// Единственный «зарезервированный» адрес — TCP primary: там bind эксклюзивен,
/// поэтому редкая гонка видна как ошибка старта и снимается повтором всей пары.
fn start_pair(spec: &PairSpec) -> Pair {
    let mut last_error = String::new();
    for _ in 0..START_ATTEMPTS {
        let primary_addr = common::reserved_tcp_addr();
        if spec.notify {
            let secondary_cfg = secondary_config(
                primary_addr,
                spec.zone.clone(),
                spec.secret,
                spec.expire,
                spec.refresh,
                spec.bootstrap,
            );
            let secondary = match start_optional_api(&secondary_cfg, spec.secondary_api) {
                Ok(server) => server,
                Err(error) => {
                    last_error = error;
                    continue;
                }
            };
            let secondary_udp = secondary.udp_addr().expect("secondary UDP address");
            let (primary_zone, primary_cfg) =
                primary_config(spec.records.clone(), vec![secondary_udp], primary_addr);
            match start_optional_api(&primary_cfg, spec.primary_api) {
                Ok(primary) => {
                    return Pair {
                        _primary_zone: primary_zone,
                        primary,
                        secondary,
                    };
                }
                Err(error) => {
                    last_error = error;
                    drop(secondary);
                }
            }
        } else {
            let (primary_zone, primary_cfg) =
                primary_config(spec.records.clone(), Vec::new(), primary_addr);
            let primary = match start_optional_api(&primary_cfg, spec.primary_api) {
                Ok(server) => server,
                Err(error) => {
                    last_error = error;
                    continue;
                }
            };
            let secondary_cfg = secondary_config(
                primary_addr,
                spec.zone.clone(),
                spec.secret,
                spec.expire,
                spec.refresh,
                spec.bootstrap,
            );
            match start_optional_api(&secondary_cfg, spec.secondary_api) {
                Ok(secondary) => {
                    return Pair {
                        _primary_zone: primary_zone,
                        primary,
                        secondary,
                    };
                }
                Err(error) => {
                    last_error = error;
                    drop(primary);
                }
            }
        }
    }
    panic!("cannot start primary/secondary pair in {START_ATTEMPTS} attempts: {last_error}");
}

fn try_dns_query(server: &Server, qname: &str, qtype: Rtype) -> io::Result<Message> {
    let address = server
        .udp_addr()
        .ok_or_else(|| io::Error::other("server has no UDP address"))?;
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    socket.set_read_timeout(Some(common::SOCKET_TIMEOUT))?;
    let query = Message::query(0x4242, Question::new(name(qname), qtype, Rclass::IN))
        .encode(&EncodeOptions::compressed())
        .map_err(|error| io::Error::other(format!("encode: {error:?}")))?;
    common::udp_send_to(&socket, &query, address)?;
    let mut buffer = [0_u8; 4096];
    let (length, _) = common::udp_recv_from(&socket, &mut buffer)?;
    let bytes = buffer
        .get(..length)
        .ok_or_else(|| io::Error::other("response length out of range"))?;
    Message::decode(bytes, &DecodeLimits::default())
        .map_err(|error| io::Error::other(format!("decode: {error:?}")))
}

/// Запрос с диагностикой: таймаут/ошибка сети — паника с адресом и ошибкой.
fn dns_query(server: &Server, qname: &str, qtype: Rtype) -> Message {
    try_dns_query(server, qname, qtype).unwrap_or_else(|error| {
        panic!(
            "DNS query {qname} {qtype:?} failed: {error}; {}",
            server_context(server)
        )
    })
}

/// Диагностика secondary-зоны для сообщений об ошибках.
fn server_context(server: &Server) -> String {
    format!(
        "secondary_last_error={:?}, stats={:?}",
        server.secondary_last_error(&name(ORIGIN)),
        server.stats()
    )
}

fn wait_for_serial(server: &Server, expected: u32, total: Duration) -> bool {
    common::wait_until(total, || {
        try_dns_query(server, ORIGIN, Rtype::SOA).is_ok_and(|response| {
            response.rcode() == Rcode::NOERROR
                && response
                    .answers()
                    .iter()
                    .any(|record| record.rr_type() == Rtype::SOA && serial(record) == expected)
        })
    })
}

fn wait_for_a(server: &Server, expected: &str, total: Duration) -> bool {
    let expected = expected.parse().expect("ipv4");
    common::wait_until(total, || {
        try_dns_query(server, "www.example.com.", Rtype::A).is_ok_and(|response| {
            response.rcode() == Rcode::NOERROR
                && response
                    .answers()
                    .iter()
                    .any(|record| record.rdata() == &Rdata::A(expected))
        })
    })
}

fn wait_for_rcode(server: &Server, rcode: Rcode, total: Duration) -> bool {
    common::wait_until(total, || {
        try_dns_query(server, ORIGIN, Rtype::SOA).is_ok_and(|response| response.rcode() == rcode)
    })
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
    let pair = start_pair(&PairSpec {
        records: zone_config(1, "192.0.2.10"),
        zone: Some(data.clone()),
        secret: "c2VjcmV0",
        expire: 60,
        refresh: 1,
        bootstrap: true,
        primary_api: true,
        secondary_api: true,
        notify: true,
    });
    let primary_tcp = pair.primary.tcp_addr().expect("primary tcp");
    let primary_api = pair.primary.api_addr().expect("primary api");

    assert!(
        wait_for_serial(&pair.secondary, 1, common::E2E_DEADLINE),
        "secondary did not bootstrap: {}",
        server_context(&pair.secondary)
    );
    assert!(
        wait_for_a(&pair.secondary, "192.0.2.10", common::E2E_DEADLINE),
        "secondary has no www A after bootstrap: {}",
        server_context(&pair.secondary)
    );

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
        wait_for_serial(&pair.secondary, 4, common::E2E_DEADLINE),
        "secondary did not update serial: {}",
        server_context(&pair.secondary)
    );
    assert!(
        wait_for_a(&pair.secondary, "192.0.2.23", common::E2E_DEADLINE),
        "secondary did not apply the last IXFR delta: {}",
        server_context(&pair.secondary)
    );

    // Secondary read-only для RRset API.
    let api = pair.secondary.api_addr().expect("secondary api");
    let (status, _) = put(
        api,
        "/api/v1/zones/example.com./records/www.example.com./A",
        r#"{"ttl":300,"records":["192.0.2.99"]}"#,
        true,
    );
    assert_eq!(status, 409);

    let Pair {
        _primary_zone,
        mut primary,
        mut secondary,
    } = pair;
    secondary.shutdown().expect("secondary shutdown");
    drop(secondary);
    primary.shutdown().expect("primary shutdown");
    drop(primary);

    // Рестарт secondary без master: данные должны прийти из zonefile.
    let config = secondary_config(primary_tcp, Some(data.clone()), "c2VjcmV0", 60, 1, true);
    let mut secondary =
        Server::start_with_api(&config, Some(api_options())).expect("secondary reopen");
    assert!(
        wait_for_serial(&secondary, 4, common::E2E_DEADLINE),
        "secondary did not load from zonefile: {}",
        server_context(&secondary)
    );
    assert!(
        wait_for_a(&secondary, "192.0.2.23", common::E2E_DEADLINE),
        "secondary lost www A after reopen: {}",
        server_context(&secondary)
    );
    secondary.shutdown().expect("secondary shutdown");
}

#[test]
fn secondary_retries_and_expires_when_master_is_down() {
    let secondary_zone = common::TempZone::empty("secondary-expire");
    let mut pair = start_pair(&PairSpec {
        records: zone_config(1, "192.0.2.10"),
        zone: Some(secondary_zone.path().to_path_buf()),
        secret: "c2VjcmV0",
        expire: 1,
        refresh: 1,
        bootstrap: true,
        primary_api: false,
        secondary_api: false,
        notify: false,
    });
    assert!(
        wait_for_serial(&pair.secondary, 1, common::E2E_DEADLINE),
        "secondary did not bootstrap: {}",
        server_context(&pair.secondary)
    );

    pair.primary.shutdown().expect("primary shutdown");
    assert!(
        wait_for_rcode(&pair.secondary, Rcode::SERVFAIL, common::E2E_DEADLINE),
        "secondary did not expire: {}",
        server_context(&pair.secondary)
    );
    assert!(
        common::wait_until(common::SOCKET_TIMEOUT, || pair
            .secondary
            .secondary_last_error(&name(ORIGIN))
            .is_some()),
        "expired secondary must record the last refresh error: {}",
        server_context(&pair.secondary)
    );
    pair.secondary.shutdown().expect("secondary shutdown");
}

#[test]
fn secondary_rejects_wrong_tsig() {
    let secondary_zone = common::TempZone::empty("secondary-badtsig");
    let mut pair = start_pair(&PairSpec {
        records: zone_config(1, "192.0.2.10"),
        zone: Some(secondary_zone.path().to_path_buf()),
        secret: "d3Jvbmc=",
        expire: 60,
        refresh: 1,
        bootstrap: true,
        primary_api: false,
        secondary_api: false,
        notify: false,
    });

    // Ошибка должна быть именно TSIG/NOTAUTH: «connection refused» не считается.
    assert!(
        common::wait_until(common::E2E_DEADLINE, || pair
            .secondary
            .secondary_last_error(&name(ORIGIN))
            .is_some_and(|error| tsig_error(&error))),
        "TSIG error must be recorded: {}",
        server_context(&pair.secondary)
    );
    let response = dns_query(&pair.secondary, ORIGIN, Rtype::SOA);
    assert_eq!(response.rcode(), Rcode::REFUSED);

    pair.secondary.shutdown().expect("secondary shutdown");
    pair.primary.shutdown().expect("primary shutdown");
}

fn tsig_error(error: &str) -> bool {
    error.contains("NOTAUTH") || error.contains("TSIG") || error.contains("BADSIG")
}

#[test]
fn bootstrap_false_waits_for_notify() {
    let secondary_zone = common::TempZone::empty("secondary-notify");
    let mut pair = start_pair(&PairSpec {
        records: zone_config(1, "192.0.2.10"),
        zone: Some(secondary_zone.path().to_path_buf()),
        secret: "c2VjcmV0",
        expire: 60,
        // refresh заметно больше дедлайна: тест доказывает именно NOTIFY, а не
        // регулярный опрос master'а.
        refresh: 600,
        bootstrap: false,
        primary_api: true,
        secondary_api: false,
        notify: true,
    });
    let primary_api = pair.primary.api_addr().expect("primary api");

    // Без bootstrap зоны нет: REFUSED.
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        assert_ne!(
            dns_query(&pair.secondary, ORIGIN, Rtype::SOA).rcode(),
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
        wait_for_serial(&pair.secondary, 2, common::E2E_DEADLINE),
        "secondary did not bootstrap on NOTIFY (refresh=600s, so only NOTIFY could wake it): {}",
        server_context(&pair.secondary)
    );
    assert!(
        wait_for_a(&pair.secondary, "192.0.2.11", common::E2E_DEADLINE),
        "secondary did not apply NOTIFY-triggered transfer: {}",
        server_context(&pair.secondary)
    );

    pair.secondary.shutdown().expect("secondary shutdown");
    pair.primary.shutdown().expect("primary shutdown");
}
