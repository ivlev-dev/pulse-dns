//! Zero-copy путь для подписанных ответов, referral и `QTYPE = ANY`.
//!
//! Проверяется байтовая эквивалентность быстрого пути полному для `DO = 1`
//! (`NSEC`/`NSEC3`, wildcard, referral, `ANY`) и независимая валидация
//! подписей/denial-доказательств через `pulse-dnssec`.

mod common;

use common::{edns_query, engine_for, name, query, rrset};
use pulse_dns::{
    DecodeLimits, DnskeyData, EncodeOptions, Message, MessageRef, Rdata, Record, Rrset, Rtype,
};
use pulse_dnssec::denial::{
    nsec_nodata, nsec_nxdomain, nsec_wildcard_answer, nsec_wildcard_nodata, nsec3_ds_nodata,
    nsec3_nodata, nsec3_nxdomain, nsec3_wildcard_answer, nsec3_wildcard_nodata,
};
use pulse_dnssec::{
    Algorithm, DenialLimits, DenialOutcome, Nsec3Proof, NsecProof, PrivateKey, VerifyOptions,
    verify_rrsig,
};
use pulse_server::application::{QueryEngine, Scratch, Transport};
use pulse_server::dnssec::{DenialPolicy, KeyRole, Nsec3Config, ZoneSigner, ZoneSigningKey};
use pulse_server::testkit::InMemoryZone;

const EDNS_1232: u16 = 1232;

#[allow(clippy::too_many_lines)]
fn base_data() -> Vec<Rrset> {
    vec![
        rrset(
            "example.com",
            Rtype::SOA,
            3600,
            [Rdata::Soa(pulse_dns::SoaData::new(
                name("ns1.example.com"),
                name("hostmaster.example.com"),
                pulse_dns::Serial::new(1),
                3600,
                600,
                604_800,
                300,
            ))],
        ),
        rrset(
            "example.com",
            Rtype::NS,
            3600,
            [Rdata::Ns(name("ns1.example.com"))],
        ),
        rrset(
            "ns1.example.com",
            Rtype::A,
            3600,
            [Rdata::A("192.0.2.1".parse().expect("ipv4"))],
        ),
        rrset(
            "www.example.com",
            Rtype::A,
            300,
            [Rdata::A("192.0.2.20".parse().expect("ipv4"))],
        ),
        rrset(
            "*.wild.example.com",
            Rtype::A,
            300,
            [Rdata::A("192.0.2.99".parse().expect("ipv4"))],
        ),
        rrset(
            "wild.example.com",
            Rtype::TXT,
            300,
            [Rdata::Txt(
                pulse_dns::TxtData::new([b"base".to_vec()]).expect("txt"),
            )],
        ),
        rrset(
            "*.wc.example.com",
            Rtype::CNAME,
            120,
            [Rdata::Cname(name("www.example.com"))],
        ),
        rrset(
            "alias.example.com",
            Rtype::CNAME,
            120,
            [Rdata::Cname(name("www.example.com"))],
        ),
        rrset(
            "x.ent.example.com",
            Rtype::A,
            300,
            [Rdata::A("192.0.2.41".parse().expect("ipv4"))],
        ),
        rrset(
            "chain1.example.com",
            Rtype::CNAME,
            120,
            [Rdata::Cname(name("chain2.example.com"))],
        ),
        rrset(
            "chain2.example.com",
            Rtype::CNAME,
            120,
            [Rdata::Cname(name("www.example.com"))],
        ),
        // Secure delegation: DS опубликован, glue ниже cut.
        rrset(
            "sub.example.com",
            Rtype::NS,
            300,
            [Rdata::Ns(name("ns1.sub.example.com"))],
        ),
        rrset(
            "sub.example.com",
            Rtype::DS,
            300,
            [Rdata::Ds(
                pulse_dns::DsData::new(12_345, 8, 2, vec![0xAB; 32]).expect("ds"),
            )],
        ),
        rrset(
            "ns1.sub.example.com",
            Rtype::A,
            300,
            [Rdata::A("192.0.2.53".parse().expect("ipv4"))],
        ),
        // Insecure delegation: без DS.
        rrset(
            "insecure.example.com",
            Rtype::NS,
            300,
            [Rdata::Ns(name("ns.insecure.example.com"))],
        ),
        rrset(
            "ns.insecure.example.com",
            Rtype::A,
            300,
            [Rdata::A("192.0.2.54".parse().expect("ipv4"))],
        ),
    ]
}

fn signer() -> ZoneSigner {
    ZoneSigner::new(
        vec![
            ZoneSigningKey::new(
                PrivateKey::generate(Algorithm::ED25519).expect("key"),
                KeyRole::Csk,
            )
            .expect("key"),
        ],
        86_400,
        300,
    )
    .expect("signer")
}

fn signed_zone(policy: &DenialPolicy) -> (InMemoryZone, Vec<DnskeyData>) {
    let origin = name("example.com");
    let signed = signer()
        .sign_zone_with(&origin, &base_data(), 1_700_000_000, policy)
        .expect("sign zone");
    let mut zone = InMemoryZone::new(origin);
    for rrset in &signed.rrsets {
        zone.insert(rrset.clone()).expect("insert signed rrset");
    }
    (zone, signed.dnskeys)
}

struct Fixture {
    engine: QueryEngine,
    fast: Vec<u8>,
    legacy: Vec<u8>,
    fast_scratch: Scratch,
    legacy_scratch: Scratch,
}

impl Fixture {
    fn new(zone: InMemoryZone) -> Self {
        Self {
            engine: engine_for(zone),
            fast: vec![0_u8; 65_535],
            legacy: vec![0_u8; 65_535],
            fast_scratch: Scratch::new(),
            legacy_scratch: Scratch::new(),
        }
    }

    /// Проверяет эквивалентность быстрого и полного путей; возвращает `len`.
    fn check(&mut self, label: &str, request: &Message) -> (bool, Option<Vec<u8>>) {
        let wire = request
            .encode(&EncodeOptions::compressed())
            .expect("query encode");
        let parsed = MessageRef::decode_simple_edns(&wire)
            .unwrap_or_else(|| panic!("{label}: simple query expected"));
        let fast = self.engine.respond_ref_into(
            &parsed,
            Transport::Udp,
            &mut self.fast,
            &mut self.fast_scratch,
        );
        let legacy_len = self
            .engine
            .respond_into(
                request,
                Transport::Udp,
                &mut self.legacy,
                &mut self.legacy_scratch,
            )
            .unwrap_or_else(|error| panic!("{label}: streaming path failed: {error}"));
        let owned = self
            .engine
            .respond(request, Transport::Udp)
            .encode(&EncodeOptions::compressed())
            .unwrap_or_else(|error| panic!("{label}: owned path failed: {error}"));
        assert_eq!(
            &self.legacy[..legacy_len],
            owned.as_slice(),
            "{label}: streaming and owned paths diverged"
        );
        match fast {
            Some(fast_len) => {
                assert_eq!(
                    &self.fast[..fast_len],
                    &self.legacy[..legacy_len],
                    "{label}: fast path bytes differ"
                );
                (true, Some(self.fast[..fast_len].to_vec()))
            }
            None => (false, None),
        }
    }
}

fn decode(bytes: &[u8]) -> Message {
    Message::decode(bytes, &DecodeLimits::default()).expect("response decode")
}

fn rrset_from(records: &[Record], owner: &pulse_dns::Name, rr_type: Rtype) -> Option<Rrset> {
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

fn verify_any(rrset: &Rrset, signatures: &[pulse_dns::RrsigData], dnskeys: &[DnskeyData]) -> bool {
    let options = VerifyOptions::new(1_700_000_000);
    signatures.iter().any(|signature| {
        dnskeys
            .iter()
            .any(|dnskey| verify_rrsig(rrset, signature, dnskey, &options).is_ok())
    })
}

fn all_records(message: &Message) -> Vec<Record> {
    message
        .answers()
        .iter()
        .chain(message.authority())
        .chain(message.additional())
        .cloned()
        .collect()
}

/// Каждая `RRSIG` ответа должна сходиться со своим `RRset` и `DNSKEY`.
fn verify_signatures(message: &Message, dnskeys: &[DnskeyData]) -> usize {
    let records = all_records(message);
    let mut verified = 0_usize;
    for record in &records {
        let Rdata::Rrsig(signature) = record.rdata() else {
            continue;
        };
        let covered = signature.type_covered();
        let rrset = rrset_from(&records, record.owner(), covered).unwrap_or_else(|| {
            panic!(
                "RRSIG for {} {covered} without covered rrset",
                record.owner()
            )
        });
        assert!(
            verify_any(&rrset, std::slice::from_ref(signature), dnskeys),
            "RRSIG must verify for {} {covered}",
            record.owner()
        );
        verified += 1;
    }
    verified
}

fn nsec_proofs(records: &[Record]) -> Vec<NsecProof> {
    records
        .iter()
        .filter_map(|record| NsecProof::from_record(record).ok())
        .collect()
}

fn nsec3_proofs(records: &[Record]) -> Vec<Nsec3Proof> {
    records
        .iter()
        .filter_map(|record| Nsec3Proof::from_record(record, DenialLimits::new()).ok())
        .collect()
}

fn case_list(denial: &str) -> Vec<(&'static str, String, Rtype)> {
    let _ = denial;
    vec![
        ("positive", "www.example.com".to_owned(), Rtype::A),
        ("nxdomain", "nope.example.com".to_owned(), Rtype::A),
        ("nodata", "www.example.com".to_owned(), Rtype::AAAA),
        ("wildcard", "foo.wild.example.com".to_owned(), Rtype::A),
        (
            "wildcard-nodata",
            "foo.wild.example.com".to_owned(),
            Rtype::AAAA,
        ),
        ("wildcard-cname", "x.wc.example.com".to_owned(), Rtype::A),
        ("cname", "alias.example.com".to_owned(), Rtype::A),
        ("chain", "chain1.example.com".to_owned(), Rtype::A),
        (
            "referral-secure",
            "host.sub.example.com".to_owned(),
            Rtype::A,
        ),
        (
            "referral-insecure",
            "host.insecure.example.com".to_owned(),
            Rtype::A,
        ),
        ("referral-at-cut", "sub.example.com".to_owned(), Rtype::A),
        ("ds", "sub.example.com".to_owned(), Rtype::DS),
        ("ds-insecure", "insecure.example.com".to_owned(), Rtype::DS),
        ("ent-nodata", "ent.example.com".to_owned(), Rtype::A),
        ("any", "www.example.com".to_owned(), Rtype::ANY),
        ("any-alias", "alias.example.com".to_owned(), Rtype::ANY),
    ]
}

#[test]
fn signed_nsec_fast_path_matches_and_validates() {
    let (zone, dnskeys) = signed_zone(&DenialPolicy::Nsec);
    let mut fixture = Fixture::new(zone);
    for (label, qname, qtype) in case_list("nsec") {
        let request = edns_query(&qname, qtype, EDNS_1232, true);
        let (hot, bytes) = fixture.check(label, &request);
        assert!(hot, "{label}: expected hot path");
        let bytes = bytes.expect("fast bytes");
        let message = decode(&bytes);
        if qtype != Rtype::ANY {
            assert!(
                verify_signatures(&message, &dnskeys) > 0,
                "{label}: RRSIG expected"
            );
        }
        match (label, qtype) {
            ("nxdomain", _) => {
                let proofs = nsec_proofs(message.authority());
                let outcome = nsec_nxdomain(
                    &name(&qname),
                    &name("example.com"),
                    &proofs,
                    DenialLimits::new(),
                )
                .expect("NSEC NXDOMAIN");
                assert_eq!(outcome.outcome, DenialOutcome::NxDomain);
            }
            ("nodata", _) => {
                let proofs = nsec_proofs(message.authority());
                let outcome = nsec_nodata(
                    &name(&qname),
                    qtype,
                    &name("example.com"),
                    &proofs,
                    DenialLimits::new(),
                )
                .expect("NSEC NODATA");
                assert_eq!(outcome.outcome, DenialOutcome::NoData);
            }
            ("wildcard", _) => {
                let proofs = nsec_proofs(message.authority());
                let outcome = nsec_wildcard_answer(
                    &name(&qname),
                    &name("wild.example.com"),
                    &name("example.com"),
                    &proofs,
                    DenialLimits::new(),
                )
                .expect("NSEC wildcard answer");
                assert_eq!(outcome.outcome, DenialOutcome::WildcardExpansion);
            }
            ("wildcard-nodata", _) => {
                let proofs = nsec_proofs(message.authority());
                let outcome = nsec_wildcard_nodata(
                    &name(&qname),
                    qtype,
                    &name("example.com"),
                    &proofs,
                    DenialLimits::new(),
                )
                .expect("NSEC wildcard NODATA");
                assert_eq!(outcome.outcome, DenialOutcome::WildcardNoData);
            }
            ("referral-insecure", _) => {
                let proofs = nsec_proofs(message.authority());
                assert_eq!(proofs.len(), 1, "NSEC DS-absence proof expected");
            }
            _ => {}
        }
    }
}

#[test]
fn signed_nsec3_fast_path_matches_and_validates() {
    let config = Nsec3Config::new(vec![0xAA, 0xBB], 0)
        .expect("nsec3 config")
        .with_opt_out(true);
    let (zone, dnskeys) = signed_zone(&DenialPolicy::Nsec3(config));
    let mut fixture = Fixture::new(zone);
    for (label, qname, qtype) in case_list("nsec3") {
        let request = edns_query(&qname, qtype, EDNS_1232, true);
        let (hot, bytes) = fixture.check(label, &request);
        assert!(hot, "{label}: expected hot path");
        let bytes = bytes.expect("fast bytes");
        let message = decode(&bytes);
        if qtype != Rtype::ANY {
            assert!(
                verify_signatures(&message, &dnskeys) > 0,
                "{label}: RRSIG expected"
            );
        }
        match (label, qtype) {
            ("nxdomain", _) => {
                let proofs = nsec3_proofs(message.authority());
                let outcome = nsec3_nxdomain(
                    &name(&qname),
                    &name("example.com"),
                    &proofs,
                    DenialLimits::new(),
                )
                .expect("NSEC3 NXDOMAIN");
                assert_eq!(outcome.outcome, DenialOutcome::NxDomain);
            }
            ("nodata", _) => {
                let proofs = nsec3_proofs(message.authority());
                let outcome = nsec3_nodata(
                    &name(&qname),
                    qtype,
                    &name("example.com"),
                    &proofs,
                    DenialLimits::new(),
                )
                .expect("NSEC3 NODATA");
                assert_eq!(outcome.outcome, DenialOutcome::NoData);
            }
            ("wildcard", _) => {
                let proofs = nsec3_proofs(message.authority());
                let outcome = nsec3_wildcard_answer(
                    &name(&qname),
                    &name("wild.example.com"),
                    &name("example.com"),
                    &proofs,
                    DenialLimits::new(),
                )
                .expect("NSEC3 wildcard answer");
                assert_eq!(outcome.outcome, DenialOutcome::WildcardExpansion);
            }
            ("wildcard-nodata", _) => {
                let proofs = nsec3_proofs(message.authority());
                let outcome = nsec3_wildcard_nodata(
                    &name(&qname),
                    qtype,
                    &name("example.com"),
                    &proofs,
                    DenialLimits::new(),
                )
                .expect("NSEC3 wildcard NODATA");
                assert_eq!(outcome.outcome, DenialOutcome::WildcardNoData);
            }
            ("referral-insecure", _) => {
                let proofs = nsec3_proofs(message.authority());
                let outcome = nsec3_ds_nodata(
                    &name("insecure.example.com"),
                    &name("example.com"),
                    &proofs,
                    DenialLimits::new(),
                )
                .expect("NSEC3 opt-out DS proof");
                assert_eq!(outcome.outcome, DenialOutcome::NoData);
            }
            _ => {}
        }
    }
}

#[test]
fn signed_do_zero_never_emits_rrsig() {
    for policy in [
        DenialPolicy::Nsec,
        DenialPolicy::Nsec3(
            Nsec3Config::new(vec![0xAA, 0xBB], 0)
                .expect("nsec3 config")
                .with_opt_out(true),
        ),
    ] {
        let (zone, _) = signed_zone(&policy);
        let mut fixture = Fixture::new(zone);
        for (label, qname, qtype) in case_list("any") {
            let request = query(&qname, qtype);
            let (hot, bytes) = fixture.check(label, &request);
            assert!(hot, "{label}: expected hot path");
            let message = decode(&bytes.expect("fast bytes"));
            assert!(
                !message
                    .answers()
                    .iter()
                    .chain(message.authority())
                    .chain(message.additional())
                    .any(|record| record.rr_type() == Rtype::RRSIG),
                "{label}: RRSIG without DO"
            );
        }
    }
}

#[test]
fn any_hinfo_and_cname_match_full_path() {
    let mut zone = common::example_zone();
    zone.insert(rrset(
        "*.wc.example.com",
        Rtype::CNAME,
        120,
        [Rdata::Cname(name("www.example.com"))],
    ))
    .expect("wildcard cname");
    let mut fixture = Fixture::new(zone);
    for (label, qname) in [
        ("hinfo-existing", "www.example.com"),
        ("hinfo-apex", "example.com"),
        ("cname-owner", "alias.example.com"),
        ("wildcard-cname", "x.wc.example.com"),
        ("wildcard-hinfo", "foo.wild.example.com"),
        ("nxdomain", "missing.example.com"),
    ] {
        let request = query(qname, Rtype::ANY);
        let (hot, bytes) = fixture.check(label, &request);
        assert!(hot, "{label}: expected hot path");
        let message = decode(&bytes.expect("fast bytes"));
        assert!(
            message
                .answers()
                .iter()
                .all(|record| record.rr_type() == Rtype::CNAME
                    || record.rr_type() == Rtype::from_u16(13)),
            "{label}: only HINFO/CNAME allowed in ANY answer"
        );
    }
}

#[test]
fn edns_do_bit_is_echoed() {
    let (zone, _) = signed_zone(&DenialPolicy::Nsec);
    let mut fixture = Fixture::new(zone);
    let request = edns_query("www.example.com", Rtype::A, 4096, true);
    let (hot, bytes) = fixture.check("do-echo", &request);
    assert!(hot);
    let message = decode(&bytes.expect("fast bytes"));
    let edns = message.edns().expect("OPT echoed");
    assert!(edns.dnssec_ok(), "DO must be echoed");
    assert_eq!(edns.udp_payload_size(), EDNS_1232);

    let request = edns_query("www.example.com", Rtype::A, 4096, false);
    let (hot, bytes) = fixture.check("no-do", &request);
    assert!(hot);
    let message = decode(&bytes.expect("fast bytes"));
    assert!(!message.edns().expect("OPT echoed").dnssec_ok());
    assert!(rrset_from(message.answers(), &name("www.example.com"), Rtype::A).is_some());
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config { cases: 32, ..proptest::test_runner::Config::default() })]

    #[test]
    fn signed_fast_path_never_diverges(
        labels in proptest::collection::vec(
            proptest::sample::select(vec![
                "www", "missing", "wild", "foo", "sub", "host", "insecure", "nope", "x", "ent", "wc",
            ]),
            1..4,
        ),
        type_index in 0_usize..8,
        dnssec_ok in proptest::bool::ANY,
        nsec3 in proptest::bool::ANY,
    ) {
        let policy = if nsec3 {
            DenialPolicy::Nsec3(
                Nsec3Config::new(vec![0xAA, 0xBB], 0)
                    .expect("nsec3 config")
                    .with_opt_out(true),
            )
        } else {
            DenialPolicy::Nsec
        };
        let (zone, _) = signed_zone(&policy);
        let mut fixture = Fixture::new(zone);
        let qname = format!("{}.example.com", labels.join("."));
        let qtype = [
            Rtype::A,
            Rtype::AAAA,
            Rtype::MX,
            Rtype::TXT,
            Rtype::CNAME,
            Rtype::DS,
            Rtype::ANY,
            Rtype::SOA,
        ][type_index];
        let request = edns_query(&qname, qtype, EDNS_1232, dnssec_ok);
        let wire = request
            .encode(&EncodeOptions::compressed())
            .expect("query encode");
        let parsed = MessageRef::decode_simple_edns(&wire).expect("simple query");
        let fast = fixture.engine.respond_ref_into(
            &parsed,
            Transport::Udp,
            &mut fixture.fast,
            &mut fixture.fast_scratch,
        );
        if let Some(len) = fast {
            let legacy_len = fixture
                .engine
                .respond_into(
                    &request,
                    Transport::Udp,
                    &mut fixture.legacy,
                    &mut fixture.legacy_scratch,
                )
                .expect("streaming path");
            proptest::prop_assert_eq!(
                &fixture.fast[..len],
                &fixture.legacy[..legacy_len],
                "{} {} do={} nsec3={}",
                qname,
                qtype,
                dnssec_ok,
                nsec3
            );
        }
    }
}
