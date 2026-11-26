//! E2E: RFC 2136 UPDATE подписанной зоны с инкрементальной переподписью.
//!
//! Проверяет, что после add/delete RR/name:
//! - ответы `DO = 1` содержат валидные `RRSIG` (ZSK) и `NSEC`/`NSEC3`-доказательства;
//! - удалённые имена исчезают из denial-цепочки, новые — появляются;
//! - opt-out NSEC3 учитывает появление `DS`;
//! - подписанные данные и подписи переживают reopen без ключей.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pulse_dns::{
    DecodeLimits, DnskeyData, Edns, EncodeOptions, Flags, Message, Name, Opcode, Question, Rclass,
    Rcode, Rdata, Record, Rrset, RrsigData, Rtype, Ttl,
};
use pulse_dnssec::{
    Algorithm, DenialLimits, NoopAudit, PrivateKey, VerifyOptions, denial, verify_rrsig,
    write_key_pair,
};
use pulsed::config::Config;
use pulsed::server::Server;
use serde_json::{Value, json};

const ORIGIN: &str = "example.com.";

fn name(text: &str) -> Name {
    Name::parse(text).expect("name")
}

fn now() -> u32 {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).expect("clock");
    u32::try_from(duration.as_secs()).expect("timestamp")
}

fn zone_text() -> String {
    "$ORIGIN example.com.\n\
     $TTL 3600\n\
     @ IN SOA ns1.example.com. hostmaster.example.com. 1 7200 900 1209600 300\n\
     @ IN NS ns1.example.com.\n\
     ns1 IN A 192.0.2.53\n\
     www IN A 192.0.2.10\n\
     *.wild IN A 192.0.2.20\n\
     sub IN NS ns.sub.example.com.\n\
     ns.sub IN A 192.0.2.40\n\
     insecure IN NS ns.insecure.example.com.\n\
     ns.insecure IN A 192.0.2.41\n"
        .to_owned()
}

struct Fixture {
    _dir: tempfile::TempDir,
    _zone: common::TempZone,
    config: Config,
}

fn fixture(denial: Option<&Value>) -> Fixture {
    let directory = tempfile::tempdir().expect("temp dir");
    let zone_path = directory.path().join("example.zone");
    std::fs::write(&zone_path, zone_text()).expect("zone file");
    let zone = common::TempZone::with_import("update-dnssec", ORIGIN, &zone_path);

    let key_dir = directory.path().join("keys");
    let ksk = PrivateKey::generate(Algorithm::ED25519).expect("ksk");
    let zsk = PrivateKey::generate(Algorithm::ED25519).expect("zsk");
    let ksk_paths = write_key_pair(&key_dir, &name(ORIGIN), &ksk, 257, &NoopAudit).expect("ksk");
    let zsk_paths = write_key_pair(&key_dir, &name(ORIGIN), &zsk, 256, &NoopAudit).expect("zsk");

    let mut dnssec = json!({
        "keys": [
            {"role": "ksk", "path": ksk_paths.private},
            {"role": "zsk", "path": zsk_paths.private}
        ],
        "validity_days": 30,
        "inception_skew": 300
    });
    if let (Some(target), Some(extra)) = (dnssec.as_object_mut(), denial.and_then(Value::as_object))
    {
        for (key, value) in extra {
            target.insert(key.clone(), value.clone());
        }
    }
    let value = json!({
        "listen_udp": "127.0.0.1:0",
        "listen_tcp": null,
        "workers": 2,
        "zonefile": zone.path(),
        "durability": "flush",
        "map_size": 64 * 1024 * 1024,
        "dnssec": { ORIGIN: dnssec },
        "update": {
            "enabled": true,
            "require_tsig": false,
            "allow_from": ["127.0.0.1/32", "::1/128"],
            "allow_zones": [ORIGIN]
        }
    });
    let config = Config::from_json_str(&value.to_string()).expect("config parses");
    config.validate().expect("config validates");
    Fixture {
        _dir: directory,
        _zone: zone,
        config,
    }
}

fn start(config: &Config) -> Server {
    Server::start(config).expect("start server")
}

fn update_message(id: u16) -> Message {
    let mut message = Message::new(id, Flags::new().with_opcode(Opcode::UPDATE));
    message.add_question(Question::new(name(ORIGIN), Rtype::SOA, Rclass::IN));
    message
}

fn add_record(message: &mut Message, owner: &str, rr_type: Rtype, rdata: Rdata) {
    message.add_authority(
        Record::new(
            name(owner),
            rr_type,
            Rclass::IN,
            Ttl::new(300).expect("ttl"),
            rdata,
        )
        .expect("record"),
    );
}

fn delete_name(message: &mut Message, owner: &str) {
    message.add_authority(Record::update_metavalue(
        name(owner),
        Rtype::ANY,
        Rclass::ANY,
    ));
}

fn delete_rrset(message: &mut Message, owner: &str, rr_type: Rtype) {
    message.add_authority(Record::update_metavalue(name(owner), rr_type, Rclass::ANY));
}

fn send_update(address: SocketAddr, message: &Message) -> Message {
    let bytes = message
        .encode(&EncodeOptions::compressed())
        .expect("encode update");
    let socket = UdpSocket::bind("127.0.0.1:0").expect("client");
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    common::udp_send_to(&socket, &bytes, address).expect("send");
    let mut buffer = vec![0_u8; 65_535];
    let (length, _) = common::udp_recv_from(&socket, &mut buffer).expect("response");
    Message::decode(buffer.get(..length).expect("len"), &DecodeLimits::default())
        .expect("decode response")
}

fn send_update_tcp(address: SocketAddr, message: &Message) -> Message {
    let bytes = message
        .encode(&EncodeOptions::compressed())
        .expect("encode update");
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
    Message::decode(&raw, &DecodeLimits::default()).expect("decode response")
}

fn query(address: SocketAddr, qname: &str, qtype: Rtype) -> Message {
    let mut message = Message::query(0x4242, Question::new(name(qname), qtype, Rclass::IN));
    message.set_edns(Some(Edns::new(1232).with_dnssec_ok(true)));
    let bytes = message
        .encode(&EncodeOptions::compressed())
        .expect("encode query");
    let socket = UdpSocket::bind("127.0.0.1:0").expect("client");
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    common::udp_send_to(&socket, &bytes, address).expect("send query");
    let mut buffer = vec![0_u8; 65_535];
    let (length, _) = common::udp_recv_from(&socket, &mut buffer).expect("response");
    Message::decode(buffer.get(..length).expect("len"), &DecodeLimits::default())
        .expect("decode query response")
}

fn rrsets(records: &[Record]) -> Vec<Rrset> {
    let mut out = Vec::new();
    let mut owners: Vec<(Name, Rtype)> = records
        .iter()
        .map(|record| (record.owner().clone(), record.rr_type()))
        .collect();
    owners.sort_by(|left, right| {
        left.0
            .cmp_canonical(&right.0)
            .then_with(|| left.1.as_u16().cmp(&right.1.as_u16()))
    });
    owners.dedup();
    for (owner, rr_type) in owners {
        let matching: Vec<&Record> = records
            .iter()
            .filter(|record| record.owner() == &owner && record.rr_type() == rr_type)
            .collect();
        let Some(first) = matching.first() else {
            continue;
        };
        let Ok(rrset) = Rrset::new(
            owner,
            rr_type,
            first.class(),
            first.ttl(),
            matching.iter().map(|record| record.rdata().clone()),
        ) else {
            continue;
        };
        out.push(rrset);
    }
    out
}

fn dnskeys(message: &Message) -> Vec<DnskeyData> {
    message
        .answers()
        .iter()
        .chain(message.authority())
        .filter(|record| record.owner() == &name(ORIGIN) && record.rr_type() == Rtype::DNSKEY)
        .filter_map(|record| match record.rdata() {
            Rdata::Dnskey(key) => Some(key.clone()),
            _ => None,
        })
        .collect()
}

fn nsec_proofs(message: &Message) -> Vec<pulse_dnssec::NsecProof> {
    message
        .authority()
        .iter()
        .filter(|record| record.rr_type() == Rtype::NSEC)
        .filter_map(|record| pulse_dnssec::NsecProof::from_record(record).ok())
        .collect()
}

fn nsec3_proofs(message: &Message) -> Vec<pulse_dnssec::Nsec3Proof> {
    let limits = DenialLimits::new();
    message
        .authority()
        .iter()
        .filter(|record| record.rr_type() == Rtype::NSEC3)
        .filter_map(|record| pulse_dnssec::Nsec3Proof::from_record(record, limits).ok())
        .collect()
}

fn verify_response(message: &Message, keys: &[DnskeyData]) {
    let options = VerifyOptions::new(now());
    let records: Vec<Record> = message
        .answers()
        .iter()
        .chain(message.authority())
        .cloned()
        .collect();
    let sets = rrsets(&records);
    for rrset in &sets {
        if rrset.rr_type() == Rtype::RRSIG {
            continue;
        }
        let signatures: Vec<RrsigData> = records
            .iter()
            .filter(|record| record.owner() == rrset.owner() && record.rr_type() == Rtype::RRSIG)
            .filter_map(|record| match record.rdata() {
                Rdata::Rrsig(signature) if signature.type_covered() == rrset.rr_type() => {
                    Some(signature.clone())
                }
                _ => None,
            })
            .collect();
        if signatures.is_empty() {
            // NS/glue и opt-out записи не подписываются.
            assert!(
                matches!(rrset.rr_type(), Rtype::NS | Rtype::DS),
                "{} {} has no RRSIG",
                rrset.owner(),
                rrset.rr_type()
            );
            continue;
        }
        assert!(
            signatures.iter().any(|signature| {
                keys.iter()
                    .any(|key| verify_rrsig(rrset, signature, key, &options).is_ok())
            }),
            "invalid RRSIG for {} {}",
            rrset.owner(),
            rrset.rr_type()
        );
    }
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
fn signed_nsec_update_adds_deletes_and_proves_denial() {
    let fixture = fixture(None);
    let mut server = start(&fixture.config);
    let udp = server.udp_addr().expect("udp");

    let keys = dnskeys(&query(udp, ORIGIN, Rtype::DNSKEY));
    assert!(!keys.is_empty(), "DNSKEY must be served");

    let mut update = update_message(1);
    add_record(
        &mut update,
        "signed.example.com",
        Rtype::A,
        Rdata::A("192.0.2.100".parse().expect("ip")),
    );
    delete_rrset(&mut update, "www.example.com", Rtype::A);
    let response = send_update(udp, &update);
    assert_eq!(response.rcode(), Rcode::NOERROR);

    let serial = soa_serial(&query(udp, ORIGIN, Rtype::SOA));
    assert!(serial > 1, "serial must grow");
    let soa = query(udp, ORIGIN, Rtype::SOA);
    verify_response(&soa, &keys);

    let added = query(udp, "signed.example.com.", Rtype::A);
    assert_eq!(added.rcode(), Rcode::NOERROR);
    assert_eq!(
        added
            .answers()
            .iter()
            .filter(|record| record.rr_type() == Rtype::A)
            .count(),
        1
    );
    verify_response(&added, &keys);

    let deleted = query(udp, "www.example.com.", Rtype::A);
    assert_eq!(deleted.rcode(), Rcode::NXDOMAIN);
    let proofs = nsec_proofs(&deleted);
    denial::nsec_nxdomain(
        &name("www.example.com."),
        &name(ORIGIN),
        &proofs,
        DenialLimits::new(),
    )
    .expect("NXDOMAIN proof for deleted name");
    verify_response(&deleted, &keys);

    let nodata = query(udp, "signed.example.com.", Rtype::AAAA);
    assert_eq!(nodata.rcode(), Rcode::NOERROR);
    assert_eq!(nodata.answers(), []);
    denial::nsec_nodata(
        &name("signed.example.com."),
        Rtype::AAAA,
        &name(ORIGIN),
        &nsec_proofs(&nodata),
        DenialLimits::new(),
    )
    .expect("NODATA proof");
    verify_response(&nodata, &keys);

    let wildcard = query(udp, "foo.wild.example.com.", Rtype::A);
    assert_eq!(wildcard.rcode(), Rcode::NOERROR);
    assert_ne!(wildcard.answers().len(), 0);
    verify_response(&wildcard, &keys);

    // Удаление имени целиком: NSEC и подпись исчезают.
    let mut delete = update_message(2);
    delete_name(&mut delete, "signed.example.com");
    assert_eq!(send_update(udp, &delete).rcode(), Rcode::NOERROR);
    let gone = query(udp, "signed.example.com.", Rtype::A);
    assert_eq!(gone.rcode(), Rcode::NXDOMAIN);
    denial::nsec_nxdomain(
        &name("signed.example.com."),
        &name(ORIGIN),
        &nsec_proofs(&gone),
        DenialLimits::new(),
    )
    .expect("NXDOMAIN after delete name");
    verify_response(&gone, &keys);

    server.shutdown().expect("shutdown");
}

#[test]
fn signed_nsec3_opt_out_update_respects_ds_and_proves_denial() {
    let fixture = fixture(Some(&json!({
        "denial": "nsec3",
        "nsec3_salt": "aabbcc",
        "nsec3_iterations": 2,
        "nsec3_opt_out": true
    })));
    let mut server = start(&fixture.config);
    let udp = server.udp_addr().expect("udp");
    let keys = dnskeys(&query(udp, ORIGIN, Rtype::DNSKEY));
    assert_ne!(keys.len(), 0);

    let mut update = update_message(10);
    add_record(
        &mut update,
        "new.example.com",
        Rtype::A,
        Rdata::A("192.0.2.110".parse().expect("ip")),
    );
    add_record(
        &mut update,
        "insecure.example.com",
        Rtype::DS,
        Rdata::Ds(pulse_dns::DsData::new(4242, 15, 2, vec![0xAB; 32]).expect("ds")),
    );
    delete_rrset(&mut update, "www.example.com", Rtype::A);
    assert_eq!(send_update(udp, &update).rcode(), Rcode::NOERROR);

    let added = query(udp, "new.example.com.", Rtype::A);
    assert_eq!(added.rcode(), Rcode::NOERROR);
    verify_response(&added, &keys);

    let ds = query(udp, "insecure.example.com.", Rtype::DS);
    assert_eq!(ds.rcode(), Rcode::NOERROR);
    assert_eq!(
        ds.answers()
            .iter()
            .filter(|record| record.rr_type() == Rtype::DS)
            .count(),
        1
    );
    verify_response(&ds, &keys);

    let nodata = query(udp, "new.example.com.", Rtype::AAAA);
    denial::nsec3_nodata(
        &name("new.example.com."),
        Rtype::AAAA,
        &name(ORIGIN),
        &nsec3_proofs(&nodata),
        DenialLimits::new(),
    )
    .expect("NSEC3 NODATA");
    verify_response(&nodata, &keys);

    let nxdomain = query(udp, "absent.example.com.", Rtype::A);
    assert_eq!(nxdomain.rcode(), Rcode::NXDOMAIN);
    denial::nsec3_nxdomain(
        &name("absent.example.com."),
        &name(ORIGIN),
        &nsec3_proofs(&nxdomain),
        DenialLimits::new(),
    )
    .expect("NSEC3 NXDOMAIN");
    verify_response(&nxdomain, &keys);

    server.shutdown().expect("shutdown");
}

#[test]
fn signed_update_and_signatures_survive_reopen_without_keys() {
    let fixture = fixture(None);
    let mut server = start(&fixture.config);
    let udp = server.udp_addr().expect("udp");
    let keys = dnskeys(&query(udp, ORIGIN, Rtype::DNSKEY));

    let mut update = update_message(20);
    add_record(
        &mut update,
        "persist.example.com",
        Rtype::A,
        Rdata::A("192.0.2.120".parse().expect("ip")),
    );
    assert_eq!(send_update(udp, &update).rcode(), Rcode::NOERROR);
    server.shutdown().expect("shutdown");
    drop(server);

    // Перезапуск без DNSSEC-ключей: зона уже подписана, RRSIG/NSEC должны
    // остаться валидными и обслуживаться из zonefile.
    let mut config = fixture.config.clone();
    config.dnssec.clear();
    let mut reopened = Server::start(&config).expect("reopen");
    let udp = reopened.udp_addr().expect("udp");

    let answer = query(udp, "persist.example.com.", Rtype::A);
    assert_eq!(
        answer
            .answers()
            .iter()
            .filter(|record| record.rr_type() == Rtype::A)
            .count(),
        1
    );
    verify_response(&answer, &keys);

    let nxdomain = query(udp, "missing.example.com.", Rtype::A);
    assert_eq!(nxdomain.rcode(), Rcode::NXDOMAIN);
    denial::nsec_nxdomain(
        &name("missing.example.com."),
        &name(ORIGIN),
        &nsec_proofs(&nxdomain),
        DenialLimits::new(),
    )
    .expect("NXDOMAIN after reopen");
    verify_response(&nxdomain, &keys);

    reopened.shutdown().expect("shutdown reopened");
}

#[test]
fn concurrent_queries_during_signed_updates_never_see_broken_signatures() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let fixture = fixture(None);
    let mut server = start(&fixture.config);
    let udp = server.udp_addr().expect("udp");
    let keys = dnskeys(&query(udp, ORIGIN, Rtype::DNSKEY));
    let stop = Arc::new(AtomicBool::new(false));

    let readers: Vec<_> = (0..4)
        .map(|_| {
            let stop = Arc::clone(&stop);
            let keys = keys.clone();
            std::thread::spawn(move || {
                let mut checked = 0_u32;
                while !stop.load(Ordering::Acquire) {
                    let answer = query(udp, "www.example.com.", Rtype::A);
                    if answer.rcode() == Rcode::NOERROR {
                        verify_response(&answer, &keys);
                    }
                    let nxdomain = query(udp, "missing.example.com.", Rtype::A);
                    if nxdomain.rcode() == Rcode::NXDOMAIN {
                        denial::nsec_nxdomain(
                            &name("missing.example.com."),
                            &name(ORIGIN),
                            &nsec_proofs(&nxdomain),
                            DenialLimits::new(),
                        )
                        .expect("NXDOMAIN proof during update");
                        verify_response(&nxdomain, &keys);
                    }
                    checked = checked.saturating_add(1);
                }
                checked
            })
        })
        .collect();

    for index in 0..24_u16 {
        let mut update = update_message(300 + index);
        add_record(
            &mut update,
            &format!("host{index}.example.com."),
            Rtype::A,
            Rdata::A(format!("192.0.2.{}", 130 + index).parse().expect("ip")),
        );
        assert_eq!(send_update(udp, &update).rcode(), Rcode::NOERROR);
    }
    stop.store(true, Ordering::Release);
    let total: u32 = readers
        .into_iter()
        .map(|reader| reader.join().expect("reader"))
        .sum();
    assert!(total > 0, "readers must query during updates");

    server.shutdown().expect("shutdown");
}

#[test]
fn signed_update_emits_notify_after_commit() {
    let receiver = UdpSocket::bind("127.0.0.1:0").expect("receiver");
    receiver
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let notify_addr = receiver.local_addr().expect("addr");
    let mut fixture = fixture(None);
    fixture.config.transfer.notify = vec![notify_addr];
    fixture.config.transfer.notify_retries = 1;
    let mut server = start(&fixture.config);
    let udp = server.udp_addr().expect("udp");

    let mut update = update_message(650);
    add_record(
        &mut update,
        "notify-signed.example.com.",
        Rtype::A,
        Rdata::A("192.0.2.210".parse().expect("ip")),
    );
    assert_eq!(send_update(udp, &update).rcode(), Rcode::NOERROR);

    let mut buffer = vec![0_u8; 4096];
    let (length, _) = common::udp_recv_from(&receiver, &mut buffer).expect("NOTIFY");
    let notify = Message::decode(buffer.get(..length).expect("len"), &DecodeLimits::default())
        .expect("decode NOTIFY");
    assert_eq!(notify.opcode(), Opcode::NOTIFY);
    assert_eq!(notify.questions()[0].qname(), &name(ORIGIN));

    let keys = dnskeys(&query(udp, ORIGIN, Rtype::DNSKEY));
    verify_response(&query(udp, "notify-signed.example.com.", Rtype::A), &keys);
    server.shutdown().expect("shutdown");
}

#[test]
fn signed_update_survives_sigkill_reopen() {
    use std::process::Command;

    let directory = tempfile::tempdir().expect("temp dir");
    let zone_path = directory.path().join("example.zone");
    std::fs::write(&zone_path, zone_text()).expect("zone file");
    let zone = common::TempZone::with_import("signed-crash", ORIGIN, &zone_path);

    let key_dir = directory.path().join("keys");
    let ksk = PrivateKey::generate(Algorithm::ED25519).expect("ksk");
    let zsk = PrivateKey::generate(Algorithm::ED25519).expect("zsk");
    let ksk_paths = write_key_pair(&key_dir, &name(ORIGIN), &ksk, 257, &NoopAudit).expect("ksk");
    let zsk_paths = write_key_pair(&key_dir, &name(ORIGIN), &zsk, 256, &NoopAudit).expect("zsk");

    let tcp = common::reserved_tcp_addr();
    let config_text = format!(
        "listen_udp = \"127.0.0.1:0\"\nlisten_tcp = \"{tcp}\"\nworkers = 1\n\
         zonefile = \"{}\"\ndurability = \"sync\"\nmap_size = 67108864\n\
         [update]\nenabled = true\nrequire_tsig = false\n\
         allow_from = [\"127.0.0.1/32\"]\nallow_zones = [\"{ORIGIN}\"]\n\
         [dnssec.\"{ORIGIN}\"]\nvalidity_days = 30\ninception_skew = 300\n\
         [[dnssec.\"{ORIGIN}\".keys]]\nrole = \"ksk\"\npath = \"{}\"\n\
         [[dnssec.\"{ORIGIN}\".keys]]\nrole = \"zsk\"\npath = \"{}\"\n",
        zone.path().display(),
        ksk_paths.private.display(),
        zsk_paths.private.display()
    );
    let (_config_dir, config_path) =
        common::write_text("signed-crash-config", "pulsed.toml", &config_text);
    let mut command = Command::new(env!("CARGO_BIN_EXE_pulsed"));
    command
        .arg("--config")
        .arg(&config_path)
        .arg("--data")
        .arg(zone.path())
        .env_remove("PULSED_API_TOKEN");
    let mut child = common::PulsedChild::spawn("signed-crash", &mut command);

    assert!(
        common::wait_until(common::CHILD_READY_TIMEOUT, || {
            tcp_query(tcp, ORIGIN, Rtype::SOA).is_some()
        }),
        "pulsed did not become ready on {tcp}"
    );

    let mut update = update_message(700);
    add_record(
        &mut update,
        "crash.example.com.",
        Rtype::A,
        Rdata::A("192.0.2.200".parse().expect("ip")),
    );
    assert_eq!(send_update_tcp(tcp, &update).rcode(), Rcode::NOERROR);
    child.kill().expect("SIGKILL");

    let config = common::base_config(zone.path());
    let mut reopened = Server::start(&config).expect("reopen after SIGKILL");
    let udp = reopened.udp_addr().expect("udp");
    let keys = dnskeys(&query(udp, ORIGIN, Rtype::DNSKEY));
    assert_ne!(keys.len(), 0);
    let answer = query(udp, "crash.example.com.", Rtype::A);
    assert_eq!(
        answer
            .answers()
            .iter()
            .filter(|record| record.rr_type() == Rtype::A)
            .count(),
        1
    );
    verify_response(&answer, &keys);
    reopened.shutdown().expect("shutdown");
}

#[allow(dead_code)]
fn tcp_query(address: SocketAddr, qname: &str, qtype: Rtype) -> Option<Message> {
    let query = Message::query(0x7777, Question::new(name(qname), qtype, Rclass::IN));
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
