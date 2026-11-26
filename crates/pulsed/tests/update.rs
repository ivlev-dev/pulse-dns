//! E2E RFC 2136: real UDP/TCP сокеты, TSIG, ответы и данные через DNS-запрос.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use pulse_dns::{
    DecodeLimits, EncodeOptions, Flags, Message, Name, Opcode, Question, Rclass, Rcode, Rdata,
    Record, Rtype, Ttl,
};
use pulse_transfer::{TsigAlgorithm, TsigErrorCode, TsigKey, append_tsig, parse_tsig};
use pulsed::config::{Config, TsigKeyConfig};
use pulsed::server::{ApiOptions, Server};

const ORIGIN: &str = "example.com.";
const KEY_NAME: &str = "update-key.test.";
const SECRET: &[u8] = b"secret";

fn name(text: &str) -> Name {
    Name::parse(text).expect("valid name")
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn tsig_config() -> TsigKeyConfig {
    TsigKeyConfig {
        name: KEY_NAME.to_owned(),
        algorithm: "hmac-sha256".to_owned(),
        secret: "c2VjcmV0".to_owned(),
    }
}

fn key() -> TsigKey {
    TsigKey::new(name(KEY_NAME), TsigAlgorithm::HmacSha256, SECRET.to_vec()).expect("key")
}

fn zone_text() -> String {
    "$ORIGIN example.com.\n\
     $TTL 3600\n\
     @ IN SOA ns1.example.com. hostmaster.example.com. 1 7200 900 1209600 300\n\
     @ IN NS ns1.example.com.\n\
     ns1 IN A 192.0.2.53\n\
     www IN A 192.0.2.10\n"
        .to_owned()
}

fn start(update: impl FnOnce(&mut Config)) -> (common::TempZone, Server) {
    let (dir, path) = common::write_text("update-zone", "zone", &zone_text());
    let zone = common::TempZone::with_import("update", ORIGIN, &path);
    let mut config = common::base_config(zone.path());
    config.update.enabled = true;
    config.update.require_tsig = false;
    config.update.allow_from = vec!["127.0.0.1/32".to_owned(), "::1/128".to_owned()];
    config.update.allow_zones = vec![ORIGIN.to_owned()];
    update(&mut config);
    let server = Server::start(&config).expect("start server");
    drop(dir);
    (zone, server)
}

fn start_default() -> (common::TempZone, Server) {
    start(|_| {})
}

fn update_message(id: u16) -> Message {
    update_message_for(id, ORIGIN)
}

fn update_message_for(id: u16, zone: &str) -> Message {
    let mut message = Message::new(id, Flags::new().with_opcode(Opcode::UPDATE));
    message.add_question(Question::new(name(zone), Rtype::SOA, Rclass::IN));
    message
}

fn add_record(message: &mut Message, owner: &str, rr_type: Rtype, ttl: u32, rdata: Rdata) {
    message.add_authority(
        Record::new(
            name(owner),
            rr_type,
            Rclass::IN,
            Ttl::new(ttl).expect("ttl"),
            rdata,
        )
        .expect("record"),
    );
}

fn delete_metavalue(message: &mut Message, owner: &str, rr_type: Rtype, class: Rclass) {
    message.add_authority(Record::update_metavalue(name(owner), rr_type, class));
}

fn encode(message: &Message, key: Option<&TsigKey>) -> (Vec<u8>, Option<Vec<u8>>) {
    let base = message
        .encode(&EncodeOptions::compressed())
        .expect("encode");
    let Some(key) = key else {
        return (base, None);
    };
    let record = key.sign_request(&base, message.id(), now()).expect("sign");
    let mac = record.mac().to_vec();
    (append_tsig(base, &record).expect("append tsig"), Some(mac))
}

fn send_udp(address: SocketAddr, message: &Message, key: Option<&TsigKey>) -> (Message, Vec<u8>) {
    let (bytes, mac) = encode(message, key);
    let socket = UdpSocket::bind("127.0.0.1:0").expect("client");
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    common::udp_send_to(&socket, &bytes, address).expect("send");
    let mut buffer = vec![0_u8; 65_535];
    let (length, _) = common::udp_recv_from(&socket, &mut buffer).expect("response");
    let raw = buffer.get(..length).expect("len").to_vec();
    if let Some(key) = key
        && let Ok(Some(envelope)) = parse_tsig(&raw)
        && envelope.record().error() == TsigErrorCode::NONE
        && !envelope.record().mac().is_empty()
    {
        key.verify_response(&raw, mac.as_deref().expect("mac"), message.id(), now())
            .expect("response TSIG");
    }
    let response = Message::decode(&raw, &DecodeLimits::default()).expect("decode response");
    (response, raw)
}

fn send_tcp(address: SocketAddr, message: &Message, key: Option<&TsigKey>) -> Message {
    let (bytes, mac) = encode(message, key);
    let mut stream = TcpStream::connect(address).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let length = u16::try_from(bytes.len()).expect("length");
    stream.write_all(&length.to_be_bytes()).expect("prefix");
    stream.write_all(&bytes).expect("write");
    let mut prefix = [0_u8; 2];
    stream.read_exact(&mut prefix).expect("read prefix");
    let length = usize::from(u16::from_be_bytes(prefix));
    let mut raw = vec![0_u8; length];
    stream.read_exact(&mut raw).expect("read response");
    if let Some(key) = key {
        key.verify_response(&raw, mac.as_deref().expect("mac"), message.id(), now())
            .expect("response TSIG");
    }
    Message::decode(&raw, &DecodeLimits::default()).expect("decode response")
}

fn query_udp(address: SocketAddr, owner: &str, rr_type: Rtype) -> Message {
    let query = Message::query(0x1000, Question::new(name(owner), rr_type, Rclass::IN));
    let bytes = query.encode(&EncodeOptions::compressed()).expect("encode");
    let socket = UdpSocket::bind("127.0.0.1:0").expect("client");
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    common::udp_send_to(&socket, &bytes, address).expect("send query");
    let mut buffer = vec![0_u8; 65_535];
    let (length, _) = common::udp_recv_from(&socket, &mut buffer).expect("query response");
    Message::decode(buffer.get(..length).expect("len"), &DecodeLimits::default())
        .expect("decode query response")
}

fn soa_serial(message: &Message) -> u32 {
    message
        .answers()
        .iter()
        .find(|record| record.rr_type() == Rtype::SOA)
        .and_then(|record| match record.rdata() {
            Rdata::Soa(soa) => Some(soa.serial.as_u32()),
            _ => None,
        })
        .expect("SOA answer")
}

#[test]
fn udp_add_delete_prerequisites_and_formerr() {
    let (_zone, mut server) = start_default();
    let udp = server.udp_addr().expect("udp");

    let mut add = update_message(1);
    add_record(
        &mut add,
        "host.example.com",
        Rtype::A,
        300,
        Rdata::A("192.0.2.55".parse().expect("ipv4")),
    );
    add_record(
        &mut add,
        "host.example.com",
        Rtype::A,
        300,
        Rdata::A("192.0.2.56".parse().expect("ipv4")),
    );
    add_record(
        &mut add,
        "host.example.com",
        Rtype::AAAA,
        300,
        Rdata::Aaaa("2001:db8::55".parse().expect("ipv6")),
    );
    let (response, _) = send_udp(udp, &add, None);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert_eq!(response.opcode(), Opcode::UPDATE);
    assert_eq!(response.questions().len(), 1);
    assert_eq!(response.questions()[0].qname(), &name(ORIGIN));

    let answer = query_udp(udp, "host.example.com.", Rtype::A);
    assert_eq!(answer.answers().len(), 2);
    let answer = query_udp(udp, "host.example.com.", Rtype::AAAA);
    assert_eq!(answer.answers().len(), 1);
    let serial_after_add = soa_serial(&query_udp(udp, ORIGIN, Rtype::SOA));
    assert!(serial_after_add > 1, "serial must grow");

    let mut delete_one = update_message(2);
    delete_one.add_authority(
        Record::new(
            name("host.example.com"),
            Rtype::A,
            Rclass::NONE,
            Ttl::ZERO,
            Rdata::A("192.0.2.55".parse().expect("ipv4")),
        )
        .expect("delete rr"),
    );
    let (response, _) = send_udp(udp, &delete_one, None);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    let answer = query_udp(udp, "host.example.com.", Rtype::A);
    assert_eq!(answer.answers().len(), 1);
    assert_eq!(
        answer.answers()[0].rdata(),
        &Rdata::A("192.0.2.56".parse().expect("ipv4"))
    );

    let mut delete_name = update_message(3);
    delete_metavalue(
        &mut delete_name,
        "host.example.com",
        Rtype::ANY,
        Rclass::ANY,
    );
    let (response, _) = send_udp(udp, &delete_name, None);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    let answer = query_udp(udp, "host.example.com.", Rtype::AAAA);
    assert_eq!(answer.answers(), []);
    let serial_after_delete = soa_serial(&query_udp(udp, ORIGIN, Rtype::SOA));
    assert!(serial_after_delete > serial_after_add);

    // Prerequisite отсутствующего RRset + add: NXRRSET, данные не появились.
    let mut atomic = update_message(4);
    atomic.add_answer(Record::update_metavalue(
        name("missing.example.com"),
        Rtype::A,
        Rclass::ANY,
    ));
    add_record(
        &mut atomic,
        "atomic.example.com",
        Rtype::A,
        60,
        Rdata::A("192.0.2.99".parse().expect("ipv4")),
    );
    let (response, _) = send_udp(udp, &atomic, None);
    assert_eq!(response.rcode(), Rcode::NXRRSET);
    let answer = query_udp(udp, "atomic.example.com.", Rtype::A);
    assert_eq!(answer.answers(), []);

    // NOTZONE.
    let mut notzone = update_message(5);
    add_record(
        &mut notzone,
        "www.other.test.",
        Rtype::A,
        60,
        Rdata::A("192.0.2.1".parse().expect("ipv4")),
    );
    let (response, _) = send_udp(udp, &notzone, None);
    assert_eq!(response.rcode(), Rcode::NOTZONE);

    // FORMERR: Zone-секция с ZTYPE != SOA.
    let mut malformed = Message::new(6, Flags::new().with_opcode(Opcode::UPDATE));
    malformed.add_question(Question::new(name(ORIGIN), Rtype::A, Rclass::IN));
    let (response, _) = send_udp(udp, &malformed, None);
    assert_eq!(response.rcode(), Rcode::FORMERR);

    server.shutdown().expect("shutdown");
}

#[test]
fn tsig_is_required_and_signed_response_verifies() {
    let (_zone, mut server) = start(|config| {
        config.tsig_keys = vec![tsig_config()];
        config.update.require_tsig = true;
        config.update.tsig_keys = vec![KEY_NAME.to_owned()];
    });
    let udp = server.udp_addr().expect("udp");
    let key = key();

    let mut unsigned = update_message(10);
    add_record(
        &mut unsigned,
        "tsig.example.com",
        Rtype::A,
        60,
        Rdata::A("192.0.2.20".parse().expect("ipv4")),
    );
    let (response, _) = send_udp(udp, &unsigned, None);
    assert_eq!(response.rcode(), Rcode::NOTAUTH);
    assert_eq!(query_udp(udp, "tsig.example.com.", Rtype::A).answers(), []);

    let wrong = TsigKey::new(
        name("other-key.test."),
        TsigAlgorithm::HmacSha256,
        b"wrong".to_vec(),
    )
    .expect("key");
    let (response, raw) = send_udp(udp, &unsigned, Some(&wrong));
    assert_eq!(response.rcode(), Rcode::NOTAUTH);
    let envelope = parse_tsig(&raw).expect("parse").expect("tsig");
    assert_eq!(envelope.record().error(), TsigErrorCode::BADKEY);

    let mut signed = update_message(11);
    add_record(
        &mut signed,
        "tsig.example.com",
        Rtype::A,
        60,
        Rdata::A("192.0.2.21".parse().expect("ipv4")),
    );
    let (response, raw) = send_udp(udp, &signed, Some(&key));
    assert_eq!(response.rcode(), Rcode::NOERROR);
    let envelope = parse_tsig(&raw).expect("parse").expect("tsig");
    assert_eq!(envelope.record().key_name(), key.name());
    assert!(
        query_udp(udp, "tsig.example.com.", Rtype::A)
            .answers()
            .iter()
            .any(|record| record.rdata() == &Rdata::A("192.0.2.21".parse().expect("ipv4")))
    );

    // Replay того же подписанного пакета отвергается.
    let mut replay_message = update_message(12);
    add_record(
        &mut replay_message,
        "replay.example.com",
        Rtype::A,
        60,
        Rdata::A("192.0.2.22".parse().expect("ipv4")),
    );
    let (bytes, replay_mac) = encode(&replay_message, Some(&key));
    let socket = UdpSocket::bind("127.0.0.1:0").expect("client");
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    common::udp_send_to(&socket, &bytes, udp).expect("send first");
    let mut buffer = vec![0_u8; 65_535];
    let (length, _) = common::udp_recv_from(&socket, &mut buffer).expect("first response");
    let first = Message::decode(buffer.get(..length).expect("len"), &DecodeLimits::default())
        .expect("decode first response");
    assert_eq!(first.rcode(), Rcode::NOERROR);
    key.verify_response(
        buffer.get(..length).expect("len"),
        replay_mac.as_deref().expect("mac"),
        replay_message.id(),
        now(),
    )
    .expect("first response TSIG");

    common::udp_send_to(&socket, &bytes, udp).expect("send replay");
    let (length, _) = common::udp_recv_from(&socket, &mut buffer).expect("replay response");
    let replay = Message::decode(buffer.get(..length).expect("len"), &DecodeLimits::default())
        .expect("decode replay response");
    assert_eq!(replay.rcode(), Rcode::NOTAUTH);

    server.shutdown().expect("shutdown");
}

#[test]
fn tcp_update_persists_after_reopen() {
    let (zone, mut server) = start_default();
    let tcp = server.tcp_addr().expect("tcp");

    let mut add = update_message(20);
    add_record(
        &mut add,
        "persist.example.com",
        Rtype::A,
        120,
        Rdata::A("192.0.2.30".parse().expect("ipv4")),
    );
    let response = send_tcp(tcp, &add, None);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    server.shutdown().expect("shutdown");
    drop(server);

    let mut config = common::base_config(zone.path());
    config.update.enabled = true;
    config.update.require_tsig = false;
    let mut reopened = Server::start(&config).expect("reopen");
    let udp = reopened.udp_addr().expect("udp");
    let answer = query_udp(udp, "persist.example.com.", Rtype::A);
    assert_eq!(answer.answers().len(), 1);
    assert_eq!(
        answer.answers()[0].rdata(),
        &Rdata::A("192.0.2.30".parse().expect("ipv4"))
    );
    assert!(soa_serial(&query_udp(udp, ORIGIN, Rtype::SOA)) > 1);
    reopened.shutdown().expect("shutdown reopened");
}

#[test]
fn update_emits_notify_out() {
    let receiver = UdpSocket::bind("127.0.0.1:0").expect("receiver");
    receiver
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let notify_addr = receiver.local_addr().expect("addr");
    let (_zone, mut server) = start(|config| {
        config.transfer.notify = vec![notify_addr];
        config.transfer.notify_retries = 1;
    });
    let udp = server.udp_addr().expect("udp");
    let mut add = update_message(70);
    add_record(
        &mut add,
        "notify.example.com",
        Rtype::A,
        60,
        Rdata::A("192.0.2.80".parse().expect("ipv4")),
    );
    let (response, _) = send_udp(udp, &add, None);
    assert_eq!(response.rcode(), Rcode::NOERROR);

    let mut buffer = vec![0_u8; 4096];
    let (length, _) = common::udp_recv_from(&receiver, &mut buffer).expect("NOTIFY");
    let notify = Message::decode(buffer.get(..length).expect("len"), &DecodeLimits::default())
        .expect("decode NOTIFY");
    assert_eq!(notify.opcode(), Opcode::NOTIFY);
    assert_eq!(notify.questions().len(), 1);
    assert_eq!(notify.questions()[0].qname(), &name(ORIGIN));
    assert_eq!(notify.answers().len(), 1);
    assert_eq!(notify.answers()[0].rr_type(), Rtype::SOA);
    server.shutdown().expect("shutdown");
}

#[test]
fn concurrent_updates_are_serialized_and_idempotent() {
    let (_zone, mut server) = start(|config| {
        config.workers = 2;
    });
    let udp = server.udp_addr().expect("udp");
    let mut handles = Vec::new();
    for index in 0..16_u32 {
        handles.push(std::thread::spawn(move || {
            let mut message = update_message(100 + u16::try_from(index).unwrap());
            add_record(
                &mut message,
                &format!("host{index}.example.com"),
                Rtype::A,
                60,
                Rdata::A(format!("192.0.2.{}", index + 1).parse().expect("ipv4")),
            );
            send_udp(udp, &message, None).0.rcode()
        }));
    }
    for handle in handles {
        assert_eq!(handle.join().expect("thread"), Rcode::NOERROR);
    }
    for index in 0..16_u32 {
        let answer = query_udp(udp, &format!("host{index}.example.com."), Rtype::A);
        assert_eq!(answer.answers().len(), 1);
    }
    let serial = soa_serial(&query_udp(udp, ORIGIN, Rtype::SOA));
    assert!(serial >= 17, "serial={serial}");

    // Идемпотентность: повтор того же add не плодит RR, только serial.
    let mut duplicate = update_message(200);
    add_record(
        &mut duplicate,
        "idem.example.com",
        Rtype::A,
        60,
        Rdata::A("192.0.2.200".parse().expect("ipv4")),
    );
    assert_eq!(send_udp(udp, &duplicate, None).0.rcode(), Rcode::NOERROR);
    assert_eq!(send_udp(udp, &duplicate, None).0.rcode(), Rcode::NOERROR);
    assert_eq!(
        query_udp(udp, "idem.example.com.", Rtype::A)
            .answers()
            .len(),
        1
    );

    server.shutdown().expect("shutdown");
}

#[test]
fn disabled_update_is_refused_and_zone_allowlist_enforced() {
    let (_zone, mut server) = start(|config| {
        config.update.enabled = false;
    });
    let udp = server.udp_addr().expect("udp");
    let mut message = update_message(30);
    add_record(
        &mut message,
        "off.example.com",
        Rtype::A,
        60,
        Rdata::A("192.0.2.40".parse().expect("ipv4")),
    );
    let (response, _) = send_udp(udp, &message, None);
    assert_eq!(response.rcode(), Rcode::REFUSED);
    server.shutdown().expect("shutdown");

    let (_zone, mut denied) = start(|config| {
        config.update.allow_zones = vec!["other.test.".to_owned()];
    });
    let udp = denied.udp_addr().expect("udp");
    let (response, _) = send_udp(udp, &message, None);
    assert_eq!(response.rcode(), Rcode::REFUSED);
    denied.shutdown().expect("shutdown denied");
}

#[test]
fn secondary_zone_is_refused() {
    let (dir, path) = common::write_text("update-secondary-zone", "zone", &zone_text());
    let zone = common::TempZone::with_import("update-secondary", ORIGIN, &path);
    drop(dir);
    let mut config = common::base_config(zone.path());
    config.update.enabled = true;
    config.update.require_tsig = false;
    config.update.allow_zones = vec!["sec.test.".to_owned()];
    let options = ApiOptions {
        listen: "127.0.0.1:0".parse().expect("api"),
        token: "pd_update_secondary_token".to_owned(),
        scopes: Vec::new(),
    };
    let mut server = Server::start_with_api(&config, Some(options)).expect("start");
    let api = server.api_addr().expect("api");
    let status = post_zone(
        api,
        "pd_update_secondary_token",
        r#"{"origin":"sec.test.","kind":"secondary","default_ttl":3600}"#,
    );
    assert_eq!(status, 201, "secondary zone creation");

    let udp = server.udp_addr().expect("udp");
    let mut message = update_message_for(50, "sec.test.");
    add_record(
        &mut message,
        "www.sec.test.",
        Rtype::A,
        60,
        Rdata::A("192.0.2.60".parse().expect("ipv4")),
    );
    let (response, _) = send_udp(udp, &message, None);
    assert_eq!(response.rcode(), Rcode::REFUSED);
    server.shutdown().expect("shutdown");
}

fn post_zone(api: SocketAddr, token: &str, body: &str) -> u16 {
    let mut stream = TcpStream::connect(api).expect("connect api");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let request = format!(
        "POST /api/v1/zones HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Authorization: Bearer {token}\r\nContent-Type: application/json\r\n\
         Idempotency-Key: pd-update-secondary\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).expect("write api");
    let mut raw = String::new();
    stream.read_to_string(&mut raw).expect("read api");
    raw.split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .expect("status code")
}

#[test]
fn update_survives_sigkill_reopen() {
    use std::process::Command;

    let (dir, path) = common::write_text("update-crash-zone", "zone", &zone_text());
    let zone = common::TempZone::with_import("update-crash", ORIGIN, &path);
    drop(dir);
    let tcp = common::reserved_tcp_addr();
    let config_text = format!(
        "listen_udp = \"127.0.0.1:0\"\nlisten_tcp = \"{tcp}\"\nworkers = 1\n\
         zonefile = \"{}\"\ndurability = \"sync\"\nmap_size = 67108864\n\
         [update]\nenabled = true\nrequire_tsig = false\n\
         allow_from = [\"127.0.0.1/32\"]\nallow_zones = [\"{ORIGIN}\"]\n",
        zone.path().display()
    );
    let (_config_dir, config_path) =
        common::write_text("update-crash-config", "pulsed.toml", &config_text);
    let mut command = Command::new(env!("CARGO_BIN_EXE_pulsed"));
    command
        .arg("--config")
        .arg(&config_path)
        .arg("--data")
        .arg(zone.path())
        .env_remove("PULSED_API_TOKEN");
    let mut child = common::PulsedChild::spawn("update-crash", &mut command);

    assert!(
        common::wait_until(common::CHILD_READY_TIMEOUT, || {
            query_tcp(tcp, ORIGIN, Rtype::SOA).is_some()
        }),
        "pulsed did not become ready on {tcp}"
    );

    let mut add = update_message(60);
    add_record(
        &mut add,
        "crash.example.com",
        Rtype::A,
        120,
        Rdata::A("192.0.2.70".parse().expect("ipv4")),
    );
    let response = send_tcp(tcp, &add, None);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    child.kill().expect("SIGKILL");

    let mut config = common::base_config(zone.path());
    config.update.enabled = true;
    config.update.require_tsig = false;
    let mut reopened = Server::start(&config).expect("reopen after SIGKILL");
    let udp = reopened.udp_addr().expect("udp");
    let answer = query_udp(udp, "crash.example.com.", Rtype::A);
    assert_eq!(answer.answers().len(), 1);
    assert_eq!(
        answer.answers()[0].rdata(),
        &Rdata::A("192.0.2.70".parse().expect("ipv4"))
    );
    reopened.shutdown().expect("shutdown");
}

fn query_tcp(address: SocketAddr, owner: &str, rr_type: Rtype) -> Option<Message> {
    let query = Message::query(0x3000, Question::new(name(owner), rr_type, Rclass::IN));
    let bytes = query.encode(&EncodeOptions::compressed()).ok()?;
    let mut stream = TcpStream::connect(address).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    let length = u16::try_from(bytes.len()).ok()?;
    stream.write_all(&length.to_be_bytes()).ok()?;
    stream.write_all(&bytes).ok()?;
    let mut prefix = [0_u8; 2];
    stream.read_exact(&mut prefix).ok()?;
    let length = usize::from(u16::from_be_bytes(prefix));
    let mut raw = vec![0_u8; length];
    stream.read_exact(&mut raw).ok()?;
    Message::decode(&raw, &DecodeLimits::default()).ok()
}

#[test]
fn prerequisite_yxdomain_and_yxrrset() {
    let (_zone, mut server) = start(|config| {
        config.update.allow_zones.clear();
    });
    let udp = server.udp_addr().expect("udp");

    let mut in_use = update_message(40);
    in_use.add_answer(Record::update_metavalue(
        name(ORIGIN),
        Rtype::ANY,
        Rclass::NONE,
    ));
    let (response, _) = send_udp(udp, &in_use, None);
    assert_eq!(response.rcode(), Rcode::YXDOMAIN);

    let mut rrset_exists = update_message(41);
    rrset_exists.add_answer(Record::update_metavalue(
        name(ORIGIN),
        Rtype::SOA,
        Rclass::NONE,
    ));
    let (response, _) = send_udp(udp, &rrset_exists, None);
    assert_eq!(response.rcode(), Rcode::YXRRSET);

    let mut name_required = update_message(42);
    name_required.add_answer(Record::update_metavalue(
        name("absent.example.com"),
        Rtype::ANY,
        Rclass::ANY,
    ));
    let (response, _) = send_udp(udp, &name_required, None);
    assert_eq!(response.rcode(), Rcode::NXDOMAIN);

    let mut unknown_zone = Message::new(43, Flags::new().with_opcode(Opcode::UPDATE));
    unknown_zone.add_question(Question::new(name("unknown.test."), Rtype::SOA, Rclass::IN));
    let (response, _) = send_udp(udp, &unknown_zone, None);
    assert_eq!(response.rcode(), Rcode::NOTAUTH);

    server.shutdown().expect("shutdown");
}

fn policy_rule(
    principal: pulsed::config::UpdatePrincipal,
    name: pulsed::config::UpdateName,
    types: pulsed::config::UpdateTypes,
    action: pulsed::config::UpdateAction,
) -> pulsed::config::UpdatePolicyRule {
    pulsed::config::UpdatePolicyRule {
        principal,
        zone: pulsed::config::UpdateName::Exact(ORIGIN.to_owned()),
        name,
        types,
        action,
    }
}

fn signed_add(owner: &str, rr_type: Rtype, rdata: Rdata) -> Message {
    let mut message = update_message(70);
    add_record(&mut message, owner, rr_type, 300, rdata);
    message
}

#[test]
fn per_name_policy_checks_principal_name_and_type() {
    let (_zone, mut server) = start(|config| {
        config.update.require_tsig = true;
        config.tsig_keys.push(tsig_config());
        config.update.policy = vec![policy_rule(
            pulsed::config::UpdatePrincipal::TsigKey(KEY_NAME.to_owned()),
            pulsed::config::UpdateName::Exact("host.example.com.".to_owned()),
            pulsed::config::UpdateTypes::List(vec!["A".to_owned()]),
            pulsed::config::UpdateAction::Grant,
        )];
    });
    let udp = server.udp_addr().expect("udp");
    let key = key();

    // Разрешено: тот principal, имя и тип.
    let response = send_udp(
        udp,
        &signed_add(
            "host.example.com",
            Rtype::A,
            Rdata::A("192.0.2.80".parse().unwrap()),
        ),
        Some(&key),
    )
    .0;
    assert_eq!(response.rcode(), Rcode::NOERROR);

    // Другой тип — REFUSED (политика непустая, правило не совпало).
    let response = send_udp(
        udp,
        &signed_add(
            "host.example.com",
            Rtype::AAAA,
            Rdata::Aaaa("2001:db8::80".parse().unwrap()),
        ),
        Some(&key),
    )
    .0;
    assert_eq!(response.rcode(), Rcode::REFUSED);

    // Другое имя — REFUSED.
    let response = send_udp(
        udp,
        &signed_add(
            "other.example.com",
            Rtype::A,
            Rdata::A("192.0.2.81".parse().unwrap()),
        ),
        Some(&key),
    )
    .0;
    assert_eq!(response.rcode(), Rcode::REFUSED);

    // Без TSIG при require_tsig — NOTAUTH до политики.
    let response = send_udp(
        udp,
        &signed_add(
            "host.example.com",
            Rtype::A,
            Rdata::A("192.0.2.82".parse().unwrap()),
        ),
        None,
    )
    .0;
    assert_eq!(response.rcode(), Rcode::NOTAUTH);

    server.shutdown().expect("shutdown");
}

#[test]
fn per_name_policy_wildcard_and_first_match_deny() {
    let (_zone, mut server) = start(|config| {
        config.update.require_tsig = false;
        config.update.policy = vec![
            policy_rule(
                pulsed::config::UpdatePrincipal::Any,
                pulsed::config::UpdateName::Exact("blocked.example.com.".to_owned()),
                pulsed::config::UpdateTypes::List(vec!["A".to_owned()]),
                pulsed::config::UpdateAction::Deny,
            ),
            policy_rule(
                pulsed::config::UpdatePrincipal::Any,
                pulsed::config::UpdateName::Wildcard("*.example.com.".to_owned()),
                pulsed::config::UpdateTypes::Any,
                pulsed::config::UpdateAction::Grant,
            ),
        ];
    });
    let udp = server.udp_addr().expect("udp");

    // Первое совпадение — deny для blocked/A.
    let response = send_udp(
        udp,
        &signed_add(
            "blocked.example.com",
            Rtype::A,
            Rdata::A("192.0.2.90".parse().unwrap()),
        ),
        None,
    )
    .0;
    assert_eq!(response.rcode(), Rcode::REFUSED);

    // Другой тип того же имени проходит по wildcard-правилу.
    let response = send_udp(
        udp,
        &signed_add(
            "blocked.example.com",
            Rtype::AAAA,
            Rdata::Aaaa("2001:db8::90".parse().unwrap()),
        ),
        None,
    )
    .0;
    assert_eq!(response.rcode(), Rcode::NOERROR);

    // Поддомен проходит, apex — нет (wildcard не совпадает с suffix).
    let response = send_udp(
        udp,
        &signed_add(
            "sub.blocked.example.com",
            Rtype::A,
            Rdata::A("192.0.2.91".parse().unwrap()),
        ),
        None,
    )
    .0;
    assert_eq!(response.rcode(), Rcode::NOERROR);
    let response = send_udp(
        udp,
        &signed_add(ORIGIN, Rtype::A, Rdata::A("192.0.2.92".parse().unwrap())),
        None,
    )
    .0;
    assert_eq!(response.rcode(), Rcode::REFUSED);

    server.shutdown().expect("shutdown");
}

const SIG0_PRINCIPAL: &str = "host.example.com.";

struct Sig0Fixture {
    _directory: tempfile::TempDir,
    key: pulse_dnssec::PrivateKey,
    dnskey: pulse_dns::DnskeyData,
    config: pulsed::config::Sig0KeyConfig,
}

fn sig0_fixture() -> Sig0Fixture {
    use pulse_dnssec::{Algorithm, NoopAudit, PrivateKey, key_tag, write_key_pair};
    let directory = tempfile::tempdir().expect("tempdir");
    let key = PrivateKey::generate(Algorithm::ED25519).expect("key");
    let dnskey = key.dnskey(256).expect("dnskey");
    let key_dir = directory.path().join("keys");
    pulse_dnssec::ensure_private_directory(&key_dir).expect("key dir");
    let paths =
        write_key_pair(&key_dir, &name("example.com."), &key, 256, &NoopAudit).expect("write key");
    let public_key = base64::engine::general_purpose::STANDARD.encode(dnskey.public_key());
    let tag = key_tag(&dnskey);
    Sig0Fixture {
        _directory: directory,
        key,
        dnskey,
        config: pulsed::config::Sig0KeyConfig {
            name: SIG0_PRINCIPAL.to_owned(),
            algorithm: "ed25519".to_owned(),
            public_key,
            key_tag: Some(tag),
            private_key: Some(paths.private),
        },
    }
}

fn sig0_request(
    message: &Message,
    fixture: &Sig0Fixture,
    inception: u32,
    expiration: u32,
) -> Vec<u8> {
    use pulse_dnssec::key_tag;
    use pulse_dnssec::sig0::Sig0Signature;
    let base = message
        .encode(&EncodeOptions::compressed())
        .expect("encode");
    let mut signature = Sig0Signature::new(
        fixture.dnskey.algorithm(),
        0,
        expiration,
        inception,
        key_tag(&fixture.dnskey),
        name(SIG0_PRINCIPAL),
    );
    let mut data = signature.rdata_without_signature();
    data.extend_from_slice(&base);
    signature.signature = fixture.key.sign_message(&data).expect("sign");
    let mut signed = message.clone();
    signed.add_additional(signature.to_record().expect("record"));
    signed
        .encode(&EncodeOptions::compressed())
        .expect("encode signed")
}

fn send_raw_udp(address: SocketAddr, raw: &[u8]) -> Vec<u8> {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("client");
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    common::udp_send_to(&socket, raw, address).expect("send");
    let mut buffer = vec![0_u8; 65_535];
    let (length, _) = common::udp_recv_from(&socket, &mut buffer).expect("response");
    buffer.get(..length).expect("len").to_vec()
}

fn send_raw_tcp(address: SocketAddr, raw: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(address).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let length = u16::try_from(raw.len()).expect("length");
    stream.write_all(&length.to_be_bytes()).expect("prefix");
    stream.write_all(raw).expect("write");
    let mut prefix = [0_u8; 2];
    stream.read_exact(&mut prefix).expect("read prefix");
    let length = usize::from(u16::from_be_bytes(prefix));
    let mut buffer = vec![0_u8; length];
    stream.read_exact(&mut buffer).expect("read response");
    buffer
}

fn decode(raw: &[u8]) -> Message {
    Message::decode(raw, &DecodeLimits::default()).expect("decode")
}

#[test]
fn sig0_valid_udp_tcp_and_signed_response() {
    let fixture = sig0_fixture();
    let (_zone, mut server) = start(|config| {
        config.update.require_tsig = true;
        config.update.sig0_keys.push(fixture.config.clone());
        config.update.policy = vec![policy_rule(
            pulsed::config::UpdatePrincipal::Sig0Key(SIG0_PRINCIPAL.to_owned()),
            pulsed::config::UpdateName::Exact("sig0.example.com.".to_owned()),
            pulsed::config::UpdateTypes::List(vec!["A".to_owned()]),
            pulsed::config::UpdateAction::Grant,
        )];
    });
    let now = now();
    let now32 = u32::try_from(now).expect("now");
    let message = signed_add(
        "sig0.example.com",
        Rtype::A,
        Rdata::A("192.0.2.100".parse().unwrap()),
    );
    let raw = sig0_request(&message, &fixture, now32 - 5, now32 + 300);

    let response_raw = send_raw_udp(server.udp_addr().expect("udp"), &raw);
    let response = decode(&response_raw);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    pulse_dnssec::verify_sig0_response(&raw, &response_raw, &fixture.dnskey, now32, 600)
        .expect("signed response");

    // Повтор того же запроса — replay.
    let replay = decode(&send_raw_udp(server.udp_addr().expect("udp"), &raw));
    assert_eq!(replay.rcode(), Rcode::NOTAUTH);

    // TCP с тем же ключом (новый запрос, чтобы не попасть в replay).
    let message = signed_add(
        "sig0.example.com",
        Rtype::A,
        Rdata::A("192.0.2.101".parse().unwrap()),
    );
    let raw = sig0_request(&message, &fixture, now32 - 5, now32 + 300);
    let response_raw = send_raw_tcp(server.tcp_addr().expect("tcp"), &raw);
    assert_eq!(decode(&response_raw).rcode(), Rcode::NOERROR);
    pulse_dnssec::verify_sig0_response(&raw, &response_raw, &fixture.dnskey, now32, 600)
        .expect("signed TCP response");

    // Политика по SIG(0)-principal: другое имя запрещено.
    let message = signed_add(
        "other.example.com",
        Rtype::A,
        Rdata::A("192.0.2.102".parse().unwrap()),
    );
    let raw = sig0_request(&message, &fixture, now32 - 5, now32 + 300);
    assert_eq!(
        decode(&send_raw_udp(server.udp_addr().expect("udp"), &raw)).rcode(),
        Rcode::REFUSED
    );

    server.shutdown().expect("shutdown");
}

#[test]
fn sig0_rejects_bad_signature_time_and_unknown_key() {
    let fixture = sig0_fixture();
    let (_zone, mut server) = start(|config| {
        config.update.require_tsig = true;
        config.update.sig0_keys.push(fixture.config.clone());
    });
    let now = now();
    let now32 = u32::try_from(now).expect("now");
    let udp = server.udp_addr().expect("udp");

    // Неверная подпись.
    let message = signed_add(
        "sig0.example.com",
        Rtype::A,
        Rdata::A("192.0.2.110".parse().unwrap()),
    );
    let mut raw = sig0_request(&message, &fixture, now32 - 5, now32 + 300);
    let last = raw.last_mut().expect("signature byte");
    *last ^= 0xFF;
    assert_eq!(decode(&send_raw_udp(udp, &raw)).rcode(), Rcode::NOTAUTH);

    // Просроченная подпись.
    let message = signed_add(
        "sig0.example.com",
        Rtype::A,
        Rdata::A("192.0.2.111".parse().unwrap()),
    );
    let raw = sig0_request(&message, &fixture, now32 - 900, now32 - 600);
    assert_eq!(decode(&send_raw_udp(udp, &raw)).rcode(), Rcode::NOTAUTH);

    // Неизвестный ключ с тем же principal.
    let other = pulse_dnssec::PrivateKey::generate(pulse_dnssec::Algorithm::ED25519).expect("key");
    let other_dnskey = other.dnskey(256).expect("dnskey");
    let message = signed_add(
        "sig0.example.com",
        Rtype::A,
        Rdata::A("192.0.2.112".parse().unwrap()),
    );
    let base = message
        .encode(&EncodeOptions::compressed())
        .expect("encode");
    let mut signature = pulse_dnssec::sig0::Sig0Signature::new(
        other_dnskey.algorithm(),
        0,
        now32 + 300,
        now32 - 5,
        pulse_dnssec::key_tag(&other_dnskey),
        name(SIG0_PRINCIPAL),
    );
    let mut data = signature.rdata_without_signature();
    data.extend_from_slice(&base);
    signature.signature = other.sign_message(&data).expect("sign");
    let mut signed = message.clone();
    signed.add_additional(signature.to_record().expect("record"));
    let raw = signed.encode(&EncodeOptions::compressed()).expect("encode");
    assert_eq!(decode(&send_raw_udp(udp, &raw)).rcode(), Rcode::NOTAUTH);

    server.shutdown().expect("shutdown");
}
