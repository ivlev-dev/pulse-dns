//! E2E: подпись `examples/example.com.zone`, отдача RRSIG/NSEC по UDP и
//! независимая проверка ответа через `pulse-dnssec`.

mod common;

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pulse_dns::{
    DecodeLimits, Edns, EncodeOptions, Message, Name, Question, Rclass, Rcode, Rdata, Record,
    Rrset, Rtype,
};
use pulse_dnssec::{
    Algorithm, DenialLimits, NoopAudit, Nsec3Proof, NsecProof, PrivateKey, VerifyOptions,
    denial::{
        nsec_nodata, nsec_nxdomain, nsec3_ds_nodata, nsec3_nodata, nsec3_nxdomain,
        nsec3_wildcard_answer, nsec3_wildcard_nodata,
    },
    verify_rrsig, write_key_pair,
};
use pulsed::config::Config;
use pulsed::server::{ApiOptions, Server};
use serde_json::json;

const TOKEN: &str = "pd_live_dnssec_e2e_0123456789abcdef";

fn now() -> u32 {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch");
    u32::try_from(duration.as_secs()).expect("timestamp fits u32")
}

fn origin() -> Name {
    Name::parse("example.com.").expect("origin")
}

fn name(text: &str) -> Name {
    Name::parse(text).expect("valid name")
}

struct Fixture {
    _dir: tempfile::TempDir,
    _zone: common::TempZone,
    config: Config,
}

fn fixture(with_api: bool) -> Fixture {
    fixture_with(with_api, None)
}

fn fixture_with(with_api: bool, denial: Option<serde_json::Value>) -> Fixture {
    let directory = tempfile::tempdir().expect("temp dir");
    let zone_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("examples/example.com.zone");

    let key_dir = directory.path().join("keys");
    let ksk = PrivateKey::generate(Algorithm::ED25519).expect("ksk");
    let zsk = PrivateKey::generate(Algorithm::ED25519).expect("zsk");
    let ksk_paths = write_key_pair(&key_dir, &origin(), &ksk, 257, &NoopAudit).expect("write ksk");
    let zsk_paths = write_key_pair(&key_dir, &origin(), &zsk, 256, &NoopAudit).expect("write zsk");

    let zone = common::TempZone::with_import("dnssec", "example.com.", &zone_path);
    let mut zone_config = json!({
        "keys": [
            {"role": "ksk", "path": ksk_paths.private},
            {"role": "zsk", "path": zsk_paths.private}
        ],
        "validity_days": 30,
        "inception_skew": 300
    });
    if let Some(denial) = denial
        && let (Some(target), Some(extra)) = (zone_config.as_object_mut(), denial.as_object())
    {
        for (key, value) in extra {
            target.insert(key.clone(), value.clone());
        }
    }
    let config_value = json!({
        "listen_udp": "127.0.0.1:0",
        "listen_tcp": null,
        "workers": 1,
        "zonefile": zone.path(),
        "durability": "flush",
        "map_size": 64 * 1024 * 1024,
        "dnssec": {
            "example.com.": zone_config
        }
    });
    let _ = with_api;
    let config = Config::from_json_str(&config_value.to_string()).expect("DNSSEC config parses");
    config.validate().expect("DNSSEC config validates");
    Fixture {
        _dir: directory,
        _zone: zone,
        config,
    }
}

fn nsec3_fixture(with_api: bool) -> Fixture {
    nsec3_fixture_with_salt(with_api, "aabbcc", 5)
}

fn nsec3_fixture_with_salt(with_api: bool, salt: &str, iterations: u16) -> Fixture {
    fixture_with(
        with_api,
        Some(json!({
            "denial": "nsec3",
            "nsec3_salt": salt,
            "nsec3_iterations": iterations
        })),
    )
}

fn start(config: &Config, api: Option<ApiOptions>) -> Server {
    Server::start_with_api(config, api).expect("start server")
}

fn udp_query(server: &Server, qname: &str, qtype: Rtype, dnssec_ok: bool) -> Message {
    let mut query = Message::query(0x5151, Question::new(name(qname), qtype, Rclass::IN));
    if dnssec_ok {
        query.set_edns(Some(Edns::new(1232).with_dnssec_ok(true)));
    }
    let bytes = query
        .encode(&EncodeOptions::compressed())
        .expect("encode query");
    let socket = UdpSocket::bind("127.0.0.1:0").expect("client socket");
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("read timeout");
    socket
        .send_to(&bytes, server.udp_addr().expect("udp enabled"))
        .expect("send query");
    let mut buffer = [0_u8; 4096];
    let (length, _) = loop {
        match socket.recv_from(&mut buffer) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            result => break result.expect("recv response"),
        }
    };
    Message::decode(&buffer[..length], &DecodeLimits::default()).expect("decode response")
}

fn rrset_from(records: &[Record], owner: &Name, rr_type: Rtype) -> Option<Rrset> {
    let matching: Vec<&Record> = records
        .iter()
        .filter(|record| record.owner() == owner && record.rr_type() == rr_type)
        .collect();
    let first = matching.first()?;
    Rrset::new(
        owner.clone(),
        rr_type,
        first.class(),
        first.ttl(),
        matching.iter().map(|record| record.rdata().clone()),
    )
    .ok()
}

fn rrsigs_from(records: &[Record], owner: &Name, covered: Rtype) -> Vec<pulse_dns::RrsigData> {
    records
        .iter()
        .filter(|record| record.owner() == owner && record.rr_type() == Rtype::RRSIG)
        .filter_map(|record| match record.rdata() {
            Rdata::Rrsig(signature) if signature.type_covered() == covered => {
                Some(signature.clone())
            }
            _ => None,
        })
        .collect()
}

fn verify_any(
    rrset: &Rrset,
    signatures: &[pulse_dns::RrsigData],
    dnskeys: &[pulse_dns::DnskeyData],
    at: u32,
) -> bool {
    let options = VerifyOptions::new(at);
    signatures.iter().any(|signature| {
        dnskeys
            .iter()
            .any(|dnskey| verify_rrsig(rrset, signature, dnskey, &options).is_ok())
    })
}

fn dnskeys_from(records: &[Record], owner: &Name) -> Vec<pulse_dns::DnskeyData> {
    records
        .iter()
        .filter(|record| record.owner() == owner && record.rr_type() == Rtype::DNSKEY)
        .filter_map(|record| match record.rdata() {
            Rdata::Dnskey(key) => Some(key.clone()),
            _ => None,
        })
        .collect()
}

fn verify_nsec_proofs(records: &[Record], dnskeys: &[pulse_dns::DnskeyData], at: u32) {
    let mut owners: Vec<Name> = records
        .iter()
        .filter(|record| record.rr_type() == Rtype::NSEC)
        .map(|record| record.owner().clone())
        .collect();
    owners.sort_by(Name::cmp_canonical);
    owners.dedup();
    assert!(!owners.is_empty(), "NSEC proof expected in authority");
    for owner in owners {
        let rrset = rrset_from(records, &owner, Rtype::NSEC).expect("NSEC rrset");
        let signatures = rrsigs_from(records, &owner, Rtype::NSEC);
        assert!(!signatures.is_empty(), "NSEC RRSIG expected for {owner}");
        assert!(
            verify_any(&rrset, &signatures, dnskeys, at),
            "NSEC RRSIG must verify for {owner}"
        );
    }
}

fn nsec3_proofs(records: &[Record]) -> Vec<Nsec3Proof> {
    records
        .iter()
        .filter_map(|record| Nsec3Proof::from_record(record, DenialLimits::new()).ok())
        .collect()
}

fn verify_nsec3_proofs(records: &[Record], dnskeys: &[pulse_dns::DnskeyData], at: u32) {
    let owners: Vec<Name> = records
        .iter()
        .filter(|record| record.rr_type() == Rtype::NSEC3)
        .map(|record| record.owner().clone())
        .collect();
    assert!(!owners.is_empty(), "NSEC3 proof expected in authority");
    for owner in owners {
        let rrset = rrset_from(records, &owner, Rtype::NSEC3).expect("NSEC3 rrset");
        let signatures = rrsigs_from(records, &owner, Rtype::NSEC3);
        assert!(!signatures.is_empty(), "NSEC3 RRSIG expected for {owner}");
        assert!(
            verify_any(&rrset, &signatures, dnskeys, at),
            "NSEC3 RRSIG must verify for {owner}"
        );
    }
}

#[test]
fn signed_zone_serves_verifiable_rrsig_and_nsec() {
    let fixture = fixture(false);
    let mut server = start(&fixture.config, None);
    let at = now();

    // 1. DNSKEY RRset + его подпись.
    let response = udp_query(&server, "example.com.", Rtype::DNSKEY, true);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert!(response.flags().aa());
    assert!(!response.flags().ad(), "AD must be 0 on authoritative");
    let dnskey_rrset =
        rrset_from(response.answers(), &origin(), Rtype::DNSKEY).expect("DNSKEY answer");
    let dnskeys = dnskeys_from(response.answers(), &origin());
    let ksk = dnskeys
        .iter()
        .find(|key| key.flags() & 0x0001 != 0)
        .expect("KSK present");
    let zsk = dnskeys
        .iter()
        .find(|key| key.flags() & 0x0001 == 0)
        .expect("ZSK present");
    let ksk_tag = pulse_dnssec::key_tag(ksk);
    let zsk_tag = pulse_dnssec::key_tag(zsk);
    let dnskey_signatures = rrsigs_from(response.answers(), &origin(), Rtype::DNSKEY);
    assert!(!dnskey_signatures.is_empty(), "DNSKEY RRSIG expected");
    assert!(
        dnskey_signatures
            .iter()
            .all(|signature| signature.key_tag() == ksk_tag),
        "DNSKEY RRset must be signed by the KSK"
    );
    assert!(
        verify_any(&dnskey_rrset, &dnskey_signatures, &dnskeys, at),
        "DNSKEY self-signature must verify"
    );

    // 2. Положительный ответ: A + RRSIG, проверка ZSK.
    let response = udp_query(&server, "www.example.com.", Rtype::A, true);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    let a_rrset =
        rrset_from(response.answers(), &name("www.example.com."), Rtype::A).expect("A answer");
    let a_signatures = rrsigs_from(response.answers(), &name("www.example.com."), Rtype::A);
    assert!(!a_signatures.is_empty(), "A RRSIG expected");
    assert!(
        a_signatures
            .iter()
            .all(|signature| signature.key_tag() == zsk_tag),
        "data RRset must be signed by the ZSK"
    );
    assert!(
        verify_any(&a_rrset, &a_signatures, &dnskeys, at),
        "A RRSIG must verify"
    );

    // 3. Без DO подписи не отдаются.
    let response = udp_query(&server, "www.example.com.", Rtype::A, false);
    assert!(
        response
            .answers()
            .iter()
            .all(|record| record.rr_type() != Rtype::RRSIG),
        "DO=0 must not return RRSIG"
    );

    // 4. NXDOMAIN: NSEC-доказательство + RRSIG.
    let qname = name("nope.example.com.");
    let response = udp_query(&server, "nope.example.com.", Rtype::A, true);
    assert_eq!(response.rcode(), Rcode::NXDOMAIN);
    let proofs: Vec<NsecProof> = response
        .authority()
        .iter()
        .filter_map(|record| NsecProof::from_record(record).ok())
        .collect();
    let outcome = nsec_nxdomain(&qname, &origin(), &proofs, DenialLimits::new())
        .expect("NSEC NXDOMAIN proof");
    assert_eq!(outcome.outcome, pulse_dnssec::DenialOutcome::NxDomain);
    verify_nsec_proofs(response.authority(), &dnskeys, at);

    // 5. NODATA: NSEC совпадает с именем и не содержит QTYPE.
    let qname = name("www.example.com.");
    let response = udp_query(&server, "www.example.com.", Rtype::AAAA, true);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert_eq!(response.answers().len(), 0);
    let proofs: Vec<NsecProof> = response
        .authority()
        .iter()
        .filter_map(|record| NsecProof::from_record(record).ok())
        .collect();
    let outcome = nsec_nodata(&qname, Rtype::AAAA, &origin(), &proofs, DenialLimits::new())
        .expect("NSEC NODATA proof");
    assert_eq!(outcome.outcome, pulse_dnssec::DenialOutcome::NoData);
    verify_nsec_proofs(response.authority(), &dnskeys, at);

    server.shutdown().expect("shutdown");
}

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

impl HttpResponse {
    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or(serde_json::Value::Null)
    }
}

fn http(addr: SocketAddr, method: &str, path: &str, body: Option<&[u8]>) -> HttpResponse {
    let mut stream = TcpStream::connect(addr).expect("connect API");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAuthorization: Bearer {TOKEN}\r\n"
    );
    if let Some(body) = body {
        let _ = write!(
            head,
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        );
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
        .expect("headers");
    let status = std::str::from_utf8(&raw[..header_end])
        .expect("ASCII headers")
        .lines()
        .next()
        .expect("status line")
        .split(' ')
        .nth(1)
        .expect("status code")
        .parse()
        .expect("numeric status");
    HttpResponse {
        status,
        body: raw[header_end + 4..].to_vec(),
    }
}

#[test]
fn keys_endpoint_and_resign() {
    let fixture = fixture(true);
    let mut server = start(
        &fixture.config,
        Some(ApiOptions {
            listen: "127.0.0.1:0".parse().expect("api addr"),
            token: TOKEN.to_owned(),
            scopes: vec!["example.com.".to_owned()],
        }),
    );
    let api = server.api_addr().expect("api enabled");

    let response = http(api, "GET", "/api/v1/zones/example.com./keys", None);
    assert_eq!(response.status, 200);
    let body = response.json();
    let keys = body["keys"].as_array().expect("keys array");
    assert_eq!(keys.len(), 2, "KSK + ZSK");
    assert!(keys.iter().all(|key| key.get("private").is_none()));
    assert_ne!(body["ds"].as_array().expect("ds array").len(), 0);

    let response = http(api, "POST", "/api/v1/zones/example.com./sign", Some(b"{}"));
    assert_eq!(
        response.status,
        200,
        "{}",
        String::from_utf8_lossy(&response.body)
    );

    let at = now();
    let response = udp_query(&server, "example.com.", Rtype::DNSKEY, true);
    let dnskeys = dnskeys_from(response.answers(), &origin());
    let rrset = rrset_from(response.answers(), &origin(), Rtype::DNSKEY).expect("DNSKEY");
    let signatures = rrsigs_from(response.answers(), &origin(), Rtype::DNSKEY);
    assert!(verify_any(&rrset, &signatures, &dnskeys, at));

    server.shutdown().expect("shutdown");
}

#[test]
fn import_sign_writes_rrsig_to_zonefile() {
    let directory = tempfile::tempdir().expect("temp dir");
    let key_dir = directory.path().join("keys");
    let ksk = PrivateKey::generate(Algorithm::ED25519).expect("ksk");
    let zsk = PrivateKey::generate(Algorithm::ED25519).expect("zsk");
    let ksk_paths = write_key_pair(&key_dir, &origin(), &ksk, 257, &NoopAudit).expect("ksk");
    let zsk_paths = write_key_pair(&key_dir, &origin(), &zsk, 256, &NoopAudit).expect("zsk");
    let zone = common::TempZone::empty("import-sign");
    let zone_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("examples/example.com.zone");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_pulsed"))
        .arg("import")
        .arg("--sign")
        .arg("--data")
        .arg(zone.path())
        .arg("--origin")
        .arg("example.com.")
        .arg("--dnssec-key")
        .arg(format!("example.com.=ksk:{}", ksk_paths.private.display()))
        .arg("--dnssec-key")
        .arg(format!("example.com.=zsk:{}", zsk_paths.private.display()))
        .arg(&zone_path)
        .env_remove("PULSED_API_TOKEN")
        .output()
        .expect("run import --sign");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Сервер запускается без dnssec-настроек: подписи уже лежат в zonefile.
    let config = common::base_config(zone.path());
    let mut server = Server::start(&config).expect("start signed zonefile");
    let response = udp_query(&server, "www.example.com.", Rtype::A, true);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert!(
        response
            .answers()
            .iter()
            .any(|record| record.rr_type() == Rtype::RRSIG),
        "import --sign must store RRSIG in the zonefile"
    );
    let response = udp_query(&server, "example.com.", Rtype::DNSKEY, true);
    let dnskeys = dnskeys_from(response.answers(), &origin());
    assert!(!dnskeys.is_empty(), "DNSKEY must be stored");
    server.shutdown().expect("shutdown");
}

#[test]
fn nsec3_signed_zone_serves_verifiable_denial_proofs() {
    let fixture = nsec3_fixture(false);
    let mut server = start(&fixture.config, None);
    let at = now();

    // DNSKEY для независимой проверки подписей.
    let response = udp_query(&server, "example.com.", Rtype::DNSKEY, true);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    let dnskeys = dnskeys_from(response.answers(), &origin());
    assert!(!dnskeys.is_empty(), "DNSKEY answer expected");

    // NSEC3PARAM: alg 1, flags 0, настроенные salt/iterations, RRSIG.
    let response = udp_query(&server, "example.com.", Rtype::NSEC3PARAM, true);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    let param = rrset_from(response.answers(), &origin(), Rtype::NSEC3PARAM).expect("NSEC3PARAM");
    let Rdata::Nsec3Param(data) = param.rdatas().first().expect("param rdata") else {
        panic!("expected NSEC3PARAM rdata");
    };
    assert_eq!(data.hash_algorithm(), 1);
    assert_eq!(data.flags(), 0);
    assert_eq!(data.salt(), &[0xAA, 0xBB, 0xCC]);
    assert_eq!(data.iterations(), 5);
    let param_sigs = rrsigs_from(response.answers(), &origin(), Rtype::NSEC3PARAM);
    assert!(
        verify_any(&param, &param_sigs, &dnskeys, at),
        "NSEC3PARAM RRSIG must verify"
    );

    // Положительный ответ.
    let response = udp_query(&server, "www.example.com.", Rtype::A, true);
    let owner = name("www.example.com.");
    let a = rrset_from(response.answers(), &owner, Rtype::A).expect("A answer");
    let sigs = rrsigs_from(response.answers(), &owner, Rtype::A);
    assert!(verify_any(&a, &sigs, &dnskeys, at));

    // NXDOMAIN: closest encloser + next closer + wildcard.
    let qname = name("nope.example.com.");
    let response = udp_query(&server, "nope.example.com.", Rtype::A, true);
    assert_eq!(response.rcode(), Rcode::NXDOMAIN);
    let proofs = nsec3_proofs(response.authority());
    let outcome = nsec3_nxdomain(&qname, &origin(), &proofs, DenialLimits::new())
        .expect("NSEC3 NXDOMAIN proof");
    assert_eq!(outcome.outcome, pulse_dnssec::DenialOutcome::NxDomain);
    assert!(outcome.is_secure(), "Opt-Out must be disabled");
    verify_nsec3_proofs(response.authority(), &dnskeys, at);
    assert!(
        response
            .authority()
            .iter()
            .all(|record| record.rr_type() != Rtype::NSEC),
        "NSEC3 zone must not emit NSEC"
    );

    // NODATA.
    let qname = name("www.example.com.");
    let response = udp_query(&server, "www.example.com.", Rtype::AAAA, true);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert_eq!(response.answers().len(), 0);
    let proofs = nsec3_proofs(response.authority());
    let outcome = nsec3_nodata(&qname, Rtype::AAAA, &origin(), &proofs, DenialLimits::new())
        .expect("NSEC3 NODATA proof");
    assert_eq!(outcome.outcome, pulse_dnssec::DenialOutcome::NoData);
    verify_nsec3_proofs(response.authority(), &dnskeys, at);

    // Wildcard answer: RRSIG + next closer proof.
    let qname = name("foo.wild.example.com.");
    let response = udp_query(&server, "foo.wild.example.com.", Rtype::A, true);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    let answer = rrset_from(response.answers(), &qname, Rtype::A).expect("wildcard A");
    let answer_sigs = rrsigs_from(response.answers(), &qname, Rtype::A);
    assert!(verify_any(&answer, &answer_sigs, &dnskeys, at));
    let proofs = nsec3_proofs(response.authority());
    let outcome = nsec3_wildcard_answer(
        &qname,
        &name("wild.example.com."),
        &origin(),
        &proofs,
        DenialLimits::new(),
    )
    .expect("NSEC3 wildcard answer proof");
    assert_eq!(
        outcome.outcome,
        pulse_dnssec::DenialOutcome::WildcardExpansion
    );

    // Wildcard NODATA.
    let qname = name("foo.wild.example.com.");
    let response = udp_query(&server, "foo.wild.example.com.", Rtype::AAAA, true);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    let proofs = nsec3_proofs(response.authority());
    let outcome =
        nsec3_wildcard_nodata(&qname, Rtype::AAAA, &origin(), &proofs, DenialLimits::new())
            .expect("NSEC3 wildcard NODATA proof");
    assert_eq!(outcome.outcome, pulse_dnssec::DenialOutcome::WildcardNoData);

    // DS NODATA в apex.
    let qname = origin();
    let response = udp_query(&server, "example.com.", Rtype::DS, true);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    let proofs = nsec3_proofs(response.authority());
    let outcome =
        nsec3_ds_nodata(&qname, &origin(), &proofs, DenialLimits::new()).expect("DS NODATA proof");
    assert_eq!(outcome.outcome, pulse_dnssec::DenialOutcome::NoData);

    // DO=0: без RRSIG и NSEC3.
    let response = udp_query(&server, "nope.example.com.", Rtype::A, false);
    assert_eq!(response.rcode(), Rcode::NXDOMAIN);
    assert!(
        response
            .answers()
            .iter()
            .chain(response.authority())
            .all(|record| record.rr_type() != Rtype::RRSIG && record.rr_type() != Rtype::NSEC3)
    );

    server.shutdown().expect("shutdown");
}

#[test]
fn nsec3_sign_endpoint_rebuilds_chain_with_same_salt() {
    let fixture = nsec3_fixture(true);
    let mut server = start(
        &fixture.config,
        Some(ApiOptions {
            listen: "127.0.0.1:0".parse().expect("api addr"),
            token: TOKEN.to_owned(),
            scopes: vec!["example.com.".to_owned()],
        }),
    );
    let api = server.api_addr().expect("api enabled");
    let at = now();

    let before = udp_query(&server, "example.com.", Rtype::NSEC3PARAM, true);
    let before_param =
        rrset_from(before.answers(), &origin(), Rtype::NSEC3PARAM).expect("NSEC3PARAM before");

    let response = http(api, "POST", "/api/v1/zones/example.com./sign", Some(b"{}"));
    assert_eq!(
        response.status,
        200,
        "{}",
        String::from_utf8_lossy(&response.body)
    );

    let after = udp_query(&server, "example.com.", Rtype::NSEC3PARAM, true);
    let after_param =
        rrset_from(after.answers(), &origin(), Rtype::NSEC3PARAM).expect("NSEC3PARAM after");
    assert_eq!(
        before_param
            .rdatas()
            .first()
            .map(pulse_dns::Rdata::to_canonical_wire),
        after_param
            .rdatas()
            .first()
            .map(pulse_dns::Rdata::to_canonical_wire),
        "re-sign must keep the configured salt/iterations"
    );

    let response = udp_query(&server, "nope.example.com.", Rtype::A, true);
    assert_eq!(response.rcode(), Rcode::NXDOMAIN);
    let dnskeys = dnskeys_from(
        udp_query(&server, "example.com.", Rtype::DNSKEY, true).answers(),
        &origin(),
    );
    let proofs = nsec3_proofs(response.authority());
    nsec3_nxdomain(
        &name("nope.example.com."),
        &origin(),
        &proofs,
        DenialLimits::new(),
    )
    .expect("NSEC3 proof after re-sign");
    verify_nsec3_proofs(response.authority(), &dnskeys, at);

    server.shutdown().expect("shutdown");
}

#[test]
fn nsec3_restart_with_new_salt_rebuilds_chain() {
    let first_fixture = nsec3_fixture_with_salt(false, "aabbcc", 5);
    let mut first = start(&first_fixture.config, None);
    let first_response = udp_query(&first, "example.com.", Rtype::NSEC3PARAM, true);
    let first_param = rrset_from(first_response.answers(), &origin(), Rtype::NSEC3PARAM)
        .expect("first NSEC3PARAM");
    let Rdata::Nsec3Param(first_data) = first_param.rdatas().first().expect("first rdata") else {
        panic!("expected NSEC3PARAM");
    };
    assert_eq!(first_data.salt(), &[0xAA, 0xBB, 0xCC]);
    first.shutdown().expect("shutdown first");

    let second_fixture = nsec3_fixture_with_salt(false, "ddeeff", 5);
    let mut second = start(&second_fixture.config, None);
    let second_response = udp_query(&second, "example.com.", Rtype::NSEC3PARAM, true);
    let second_param = rrset_from(second_response.answers(), &origin(), Rtype::NSEC3PARAM)
        .expect("second NSEC3PARAM");
    let Rdata::Nsec3Param(second_data) = second_param.rdatas().first().expect("second rdata")
    else {
        panic!("expected NSEC3PARAM");
    };
    assert_eq!(second_data.salt(), &[0xDD, 0xEE, 0xFF]);

    // Новая соль → новая цепочка; негативные доказательства валидируются.
    let response = udp_query(&second, "nope.example.com.", Rtype::A, true);
    assert_eq!(response.rcode(), Rcode::NXDOMAIN);
    let proofs = nsec3_proofs(response.authority());
    nsec3_nxdomain(
        &name("nope.example.com."),
        &origin(),
        &proofs,
        DenialLimits::new(),
    )
    .expect("NSEC3 proof with the new salt");
    second.shutdown().expect("shutdown second");
}
