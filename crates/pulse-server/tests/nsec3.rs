//! NSEC3: подпись зоны, генерация цепочки и негативные доказательства в
//! движке запросов. Проверка — независимым валидатором `pulse-dnssec`.

use std::sync::Arc;

use pulse_dns::{
    DnskeyData, Edns, Message, Name, Question, Rclass, Rcode, Rdata, Record, Rrset, Rtype, Serial,
    SoaData, Ttl, TxtData,
};
use pulse_dnssec::denial::{
    nsec3_ds_nodata, nsec3_nodata, nsec3_nxdomain, nsec3_wildcard_answer, nsec3_wildcard_nodata,
};
use pulse_dnssec::{
    Algorithm, DenialLimits, DenialOutcome, Nsec3Proof, PrivateKey, VerifyOptions, verify_rrsig,
};
use pulse_server::application::{QueryEngine, Transport};
use pulse_server::dnssec::{DenialPolicy, KeyRole, Nsec3Config, ZoneSigner, ZoneSigningKey};
use pulse_server::testkit::InMemoryZone;

fn name(text: &str) -> Name {
    Name::parse(text).expect("test name")
}

fn ttl(value: u32) -> Ttl {
    Ttl::new(value).expect("test ttl")
}

fn rrset(owner: &str, rr_type: Rtype, rdatas: impl IntoIterator<Item = Rdata>) -> Rrset {
    Rrset::new(name(owner), rr_type, Rclass::IN, ttl(300), rdatas).expect("test rrset")
}

fn zone_data() -> Vec<Rrset> {
    vec![
        Rrset::new(
            name("example.com"),
            Rtype::SOA,
            Rclass::IN,
            ttl(3600),
            [Rdata::Soa(SoaData::new(
                name("ns1.example.com"),
                name("hostmaster.example.com"),
                Serial::new(1),
                3600,
                600,
                604_800,
                300,
            ))],
        )
        .expect("soa"),
        rrset(
            "example.com",
            Rtype::NS,
            [Rdata::Ns(name("ns1.example.com"))],
        ),
        rrset(
            "ns1.example.com",
            Rtype::A,
            [Rdata::A("192.0.2.1".parse().expect("ip"))],
        ),
        rrset(
            "www.example.com",
            Rtype::A,
            [Rdata::A("192.0.2.2".parse().expect("ip"))],
        ),
        rrset(
            "*.wild.example.com",
            Rtype::A,
            [Rdata::A("192.0.2.3".parse().expect("ip"))],
        ),
        Rrset::new(
            name("wild.example.com"),
            Rtype::TXT,
            Rclass::IN,
            ttl(300),
            [Rdata::Txt(
                TxtData::new([b"base".to_vec()]).expect("txt data"),
            )],
        )
        .expect("txt"),
        rrset(
            "sub.example.com",
            Rtype::NS,
            [Rdata::Ns(name("ns.sub.example.com"))],
        ),
    ]
}

struct Signed {
    zone: InMemoryZone,
    dnskeys: Vec<DnskeyData>,
    nsec3_owners: Vec<Name>,
}

fn sign_nsec3(salt: &[u8], iterations: u16) -> Signed {
    sign_nsec3_config(salt, iterations, false)
}

fn sign_nsec3_config(salt: &[u8], iterations: u16, opt_out: bool) -> Signed {
    let origin = name("example.com");
    let signer = ZoneSigner::new(
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
    .expect("signer");
    let config = Nsec3Config::new(salt.to_vec(), iterations)
        .expect("valid NSEC3 config")
        .with_opt_out(opt_out);
    let policy = DenialPolicy::Nsec3(config);
    let signed_zone = signer
        .sign_zone_with(&origin, &zone_data(), 1_700_000_000, &policy)
        .expect("sign NSEC3 zone");
    assert_eq!(signed_zone.denial, pulse_server::DenialKind::Nsec3);
    assert!(
        !signed_zone
            .rrsets
            .iter()
            .any(|rrset| rrset.rr_type() == Rtype::NSEC),
        "NSEC3 zone must not contain NSEC records"
    );
    let nsec3_owners: Vec<Name> = signed_zone
        .rrsets
        .iter()
        .filter(|rrset| rrset.rr_type() == Rtype::NSEC3)
        .map(|rrset| rrset.owner().clone())
        .collect();
    let mut zone = InMemoryZone::new(origin);
    for rrset in &signed_zone.rrsets {
        zone.insert(rrset.clone()).expect("insert signed rrset");
    }
    Signed {
        zone,
        dnskeys: signed_zone.dnskeys,
        nsec3_owners,
    }
}

fn query(engine: &QueryEngine, qname: &str, qtype: Rtype, dnssec_ok: bool) -> Message {
    let mut message = Message::query(0x1234, Question::new(name(qname), qtype, Rclass::IN));
    if dnssec_ok {
        message.set_edns(Some(Edns::new(1232).with_dnssec_ok(true)));
    }
    engine.respond(&message, Transport::Udp)
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

fn verify_any(rrset: &Rrset, signatures: &[pulse_dns::RrsigData], dnskeys: &[DnskeyData]) -> bool {
    let options = VerifyOptions::new(1_700_000_000);
    signatures.iter().any(|signature| {
        dnskeys
            .iter()
            .any(|dnskey| verify_rrsig(rrset, signature, dnskey, &options).is_ok())
    })
}

fn verify_nsec3_proofs(records: &[Record], dnskeys: &[DnskeyData]) {
    let owners: Vec<Name> = records
        .iter()
        .filter(|record| record.rr_type() == Rtype::NSEC3)
        .map(|record| record.owner().clone())
        .collect();
    assert!(!owners.is_empty(), "NSEC3 proof expected");
    for owner in owners {
        let rrset = rrset_from(records, &owner, Rtype::NSEC3).expect("NSEC3 rrset");
        let signatures = rrsigs_from(records, &owner, Rtype::NSEC3);
        assert!(!signatures.is_empty(), "NSEC3 RRSIG expected for {owner}");
        assert!(
            verify_any(&rrset, &signatures, dnskeys),
            "NSEC3 RRSIG must verify for {owner}"
        );
    }
}

fn nsec3_proofs(records: &[Record]) -> Vec<Nsec3Proof> {
    records
        .iter()
        .filter_map(|record| Nsec3Proof::from_record(record, DenialLimits::new()).ok())
        .collect()
}

#[test]
fn nsec3param_is_published_and_signed() {
    let signed = sign_nsec3(&[0xAA, 0xBB], 5);
    let engine = QueryEngine::new(vec![Arc::new(signed.zone.clone())]);
    let response = query(&engine, "example.com.", Rtype::NSEC3PARAM, true);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    let origin = name("example.com");
    let param = rrset_from(response.answers(), &origin, Rtype::NSEC3PARAM).expect("NSEC3PARAM");
    let Rdata::Nsec3Param(data) = param.rdatas().first().expect("param rdata") else {
        panic!("expected NSEC3PARAM rdata");
    };
    assert_eq!(data.hash_algorithm(), 1);
    assert_eq!(data.flags(), 0);
    assert_eq!(data.iterations(), 5);
    assert_eq!(data.salt(), &[0xAA, 0xBB]);
    let signatures = rrsigs_from(response.answers(), &origin, Rtype::NSEC3PARAM);
    assert!(
        verify_any(&param, &signatures, &signed.dnskeys),
        "NSEC3PARAM RRSIG must verify"
    );
    assert!(
        signed
            .nsec3_owners
            .iter()
            .all(|owner| owner.label_count() == origin.label_count() + 1),
        "NSEC3 owners must be <hash>.<zone>"
    );
}

#[test]
fn nsec3_positive_and_negative_answers_validate() {
    let signed = sign_nsec3(&[0x01, 0x02], 2);
    let engine = QueryEngine::new(vec![Arc::new(signed.zone.clone())]);

    // Положительный ответ: A + RRSIG.
    let response = query(&engine, "www.example.com.", Rtype::A, true);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    let owner = name("www.example.com");
    let a = rrset_from(response.answers(), &owner, Rtype::A).expect("A answer");
    let sigs = rrsigs_from(response.answers(), &owner, Rtype::A);
    assert!(
        verify_any(&a, &sigs, &signed.dnskeys),
        "A RRSIG must verify"
    );

    // NXDOMAIN: closest encloser + next closer + wildcard cover.
    let qname = name("nope.example.com");
    let response = query(&engine, "nope.example.com.", Rtype::A, true);
    assert_eq!(response.rcode(), Rcode::NXDOMAIN);
    let proofs = nsec3_proofs(response.authority());
    let outcome = nsec3_nxdomain(&qname, &name("example.com"), &proofs, DenialLimits::new())
        .expect("NSEC3 NXDOMAIN proof");
    assert_eq!(outcome.outcome, DenialOutcome::NxDomain);
    assert!(outcome.is_secure());
    verify_nsec3_proofs(response.authority(), &signed.dnskeys);

    // NODATA: exact NSEC3 без AAAA.
    let qname = name("www.example.com");
    let response = query(&engine, "www.example.com.", Rtype::AAAA, true);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    let proofs = nsec3_proofs(response.authority());
    let outcome = nsec3_nodata(
        &qname,
        Rtype::AAAA,
        &name("example.com"),
        &proofs,
        DenialLimits::new(),
    )
    .expect("NSEC3 NODATA proof");
    assert_eq!(outcome.outcome, DenialOutcome::NoData);
    verify_nsec3_proofs(response.authority(), &signed.dnskeys);

    // Wildcard answer: CE proof + next closer cover.
    let qname = name("foo.wild.example.com");
    let response = query(&engine, "foo.wild.example.com.", Rtype::A, true);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    let answer = rrset_from(response.answers(), &qname, Rtype::A).expect("wildcard A");
    let sigs = rrsigs_from(response.answers(), &qname, Rtype::A);
    assert!(verify_any(&answer, &sigs, &signed.dnskeys));
    let proofs = nsec3_proofs(response.authority());
    let outcome = nsec3_wildcard_answer(
        &qname,
        &name("wild.example.com"),
        &name("example.com"),
        &proofs,
        DenialLimits::new(),
    )
    .expect("NSEC3 wildcard answer proof");
    assert_eq!(outcome.outcome, DenialOutcome::WildcardExpansion);

    // Wildcard NODATA: wildcard существует, QTYPE отсутствует.
    let qname = name("foo.wild.example.com");
    let response = query(&engine, "foo.wild.example.com.", Rtype::AAAA, true);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    let proofs = nsec3_proofs(response.authority());
    let outcome = nsec3_wildcard_nodata(
        &qname,
        Rtype::AAAA,
        &name("example.com"),
        &proofs,
        DenialLimits::new(),
    )
    .expect("NSEC3 wildcard NODATA proof");
    assert_eq!(outcome.outcome, DenialOutcome::WildcardNoData);

    // DS NODATA в apex: exact NSEC3 без DS.
    let qname = name("example.com");
    let response = query(&engine, "example.com.", Rtype::DS, true);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    let proofs = nsec3_proofs(response.authority());
    let outcome = nsec3_ds_nodata(&qname, &name("example.com"), &proofs, DenialLimits::new())
        .expect("NSEC3 DS-NODATA proof");
    assert_eq!(outcome.outcome, DenialOutcome::NoData);

    // Insecure delegation: NSEC3 в cut доказывает отсутствие DS.
    let cut = name("sub.example.com");
    let response = query(&engine, "sub.example.com.", Rtype::DS, true);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    let proofs = nsec3_proofs(response.authority());
    let outcome = nsec3_ds_nodata(&cut, &name("example.com"), &proofs, DenialLimits::new())
        .expect("NSEC3 DS-NODATA at delegation");
    assert_eq!(outcome.outcome, DenialOutcome::NoData);

    // DO=0: без RRSIG и без NSEC3.
    let response = query(&engine, "nope.example.com.", Rtype::A, false);
    assert_eq!(response.rcode(), Rcode::NXDOMAIN);
    assert!(
        response
            .answers()
            .iter()
            .chain(response.authority())
            .all(|record| record.rr_type() != Rtype::RRSIG && record.rr_type() != Rtype::NSEC3)
    );
}

#[test]
fn nsec3_opt_out_proves_insecure_delegation() {
    let signed = sign_nsec3_config(&[0x33, 0x44], 0, true);
    let engine = QueryEngine::new(vec![Arc::new(signed.zone.clone())]);
    let origin = name("example.com");
    let cut = name("sub.example.com");

    // DS-NODATA в insecure cut: точного NSEC3 нет, доказываем CE + cover
    // с opt-out.
    let response = query(&engine, "sub.example.com.", Rtype::DS, true);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    let proofs = nsec3_proofs(response.authority());
    assert!(
        proofs.iter().any(Nsec3Proof::opt_out),
        "opt-out flag must be set on the covering NSEC3"
    );
    let outcome = nsec3_ds_nodata(&cut, &origin, &proofs, DenialLimits::new())
        .expect("NSEC3 opt-out DS-NODATA proof");
    assert_eq!(outcome.outcome, DenialOutcome::NoData);
    assert!(!outcome.is_secure(), "opt-out delegation is insecure");

    // Referral ниже cut доказывает то же самое.
    let response = query(&engine, "host.sub.example.com.", Rtype::A, true);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert!(
        response
            .authority()
            .iter()
            .any(|record| record.rr_type() == Rtype::NS),
        "referral expected"
    );
    let proofs = nsec3_proofs(response.authority());
    let outcome = nsec3_ds_nodata(&cut, &origin, &proofs, DenialLimits::new())
        .expect("NSEC3 opt-out referral proof");
    assert_eq!(outcome.outcome, DenialOutcome::NoData);
    assert!(!outcome.is_secure(), "opt-out referral is insecure");
}

#[test]
fn nsec3_salt_change_rebuilds_chain() {
    let first = sign_nsec3(&[0x10], 1);
    let second = sign_nsec3(&[0x20], 1);
    assert_eq!(first.nsec3_owners.len(), second.nsec3_owners.len());
    assert_ne!(
        first.nsec3_owners, second.nsec3_owners,
        "a different salt must produce a different NSEC3 chain"
    );
}

#[test]
fn nsec3_config_rejects_invalid_parameters() {
    assert!(Nsec3Config::new(vec![0; 256], 0).is_err());
    assert!(Nsec3Config::new(Vec::new(), 101).is_err());
    assert!(Nsec3Config::new(Vec::new(), 100).is_ok());
}
