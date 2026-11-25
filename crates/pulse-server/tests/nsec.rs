//! NSEC: негативные ответы и wildcard-доказательства подписанной зоны.
//! Проверка — независимым валидатором `pulse-dnssec`.

use std::sync::Arc;

use pulse_dns::{
    DnskeyData, Edns, Message, Name, Question, Rclass, Rcode, Rdata, Record, Rrset, Rtype, Serial,
    SoaData, Ttl, TxtData,
};
use pulse_dnssec::denial::{
    nsec_nodata, nsec_nxdomain, nsec_wildcard_answer, nsec_wildcard_nodata,
};
use pulse_dnssec::{
    Algorithm, DenialLimits, DenialOutcome, PrivateKey, VerifyOptions, verify_rrsig,
};
use pulse_server::application::{QueryEngine, Transport};
use pulse_server::dnssec::{DenialPolicy, KeyRole, ZoneSigner, ZoneSigningKey};
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
}

fn sign_nsec() -> Signed {
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
    let signed_zone = signer
        .sign_zone_with(&origin, &zone_data(), 1_700_000_000, &DenialPolicy::Nsec)
        .expect("sign NSEC zone");
    assert_eq!(signed_zone.denial, pulse_server::DenialKind::Nsec);
    assert!(
        signed_zone
            .rrsets
            .iter()
            .any(|rrset| rrset.rr_type() == Rtype::NSEC),
        "NSEC zone must contain NSEC records"
    );
    let mut zone = InMemoryZone::new(origin);
    for rrset in &signed_zone.rrsets {
        zone.insert(rrset.clone()).expect("insert signed rrset");
    }
    Signed {
        zone,
        dnskeys: signed_zone.dnskeys,
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

fn nsec_proofs(records: &[Record]) -> Vec<pulse_dnssec::NsecProof> {
    records
        .iter()
        .filter_map(|record| pulse_dnssec::NsecProof::from_record(record).ok())
        .collect()
}

fn verify_nsec_proofs(records: &[Record], dnskeys: &[DnskeyData]) {
    let owners: Vec<Name> = records
        .iter()
        .filter(|record| record.rr_type() == Rtype::NSEC)
        .map(|record| record.owner().clone())
        .collect();
    assert!(!owners.is_empty(), "NSEC proof expected");
    for owner in owners {
        let rrset = rrset_from(records, &owner, Rtype::NSEC).expect("NSEC rrset");
        let signatures = rrsigs_from(records, &owner, Rtype::NSEC);
        assert!(!signatures.is_empty(), "NSEC RRSIG expected for {owner}");
        assert!(
            verify_any(&rrset, &signatures, dnskeys),
            "NSEC RRSIG must verify for {owner}"
        );
    }
}

#[test]
fn nsec_positive_and_negative_answers_validate() {
    let signed = sign_nsec();
    let engine = QueryEngine::new(vec![Arc::new(signed.zone.clone())]);
    let origin = name("example.com");

    // Положительный ответ: A + RRSIG.
    let response = query(&engine, "www.example.com.", Rtype::A, true);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    let owner = name("www.example.com");
    let a = rrset_from(response.answers(), &owner, Rtype::A).expect("A answer");
    let sigs = rrsigs_from(response.answers(), &owner, Rtype::A);
    assert!(verify_any(&a, &sigs, &signed.dnskeys));

    // NXDOMAIN: QNAME + wildcard покрыты NSEC.
    let qname = name("nope.example.com");
    let response = query(&engine, "nope.example.com.", Rtype::A, true);
    assert_eq!(response.rcode(), Rcode::NXDOMAIN);
    let proofs = nsec_proofs(response.authority());
    let outcome =
        nsec_nxdomain(&qname, &origin, &proofs, DenialLimits::new()).expect("NSEC NXDOMAIN proof");
    assert_eq!(outcome.outcome, DenialOutcome::NxDomain);
    assert!(outcome.is_secure());
    verify_nsec_proofs(response.authority(), &signed.dnskeys);

    // NODATA: NSEC самого имени без AAAA.
    let qname = name("www.example.com");
    let response = query(&engine, "www.example.com.", Rtype::AAAA, true);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    let proofs = nsec_proofs(response.authority());
    let outcome = nsec_nodata(&qname, Rtype::AAAA, &origin, &proofs, DenialLimits::new())
        .expect("NSEC NODATA proof");
    assert_eq!(outcome.outcome, DenialOutcome::NoData);
    verify_nsec_proofs(response.authority(), &signed.dnskeys);

    // Wildcard answer: next closer покрыт NSEC.
    let qname = name("foo.wild.example.com");
    let response = query(&engine, "foo.wild.example.com.", Rtype::A, true);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    let answer = rrset_from(response.answers(), &qname, Rtype::A).expect("wildcard A");
    let sigs = rrsigs_from(response.answers(), &qname, Rtype::A);
    assert!(verify_any(&answer, &sigs, &signed.dnskeys));
    let proofs = nsec_proofs(response.authority());
    let outcome = nsec_wildcard_answer(
        &qname,
        &name("wild.example.com"),
        &origin,
        &proofs,
        DenialLimits::new(),
    )
    .expect("NSEC wildcard answer proof");
    assert_eq!(outcome.outcome, DenialOutcome::WildcardExpansion);

    // Wildcard NODATA: wildcard существует, QTYPE отсутствует.
    let qname = name("foo.wild.example.com");
    let response = query(&engine, "foo.wild.example.com.", Rtype::AAAA, true);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    let proofs = nsec_proofs(response.authority());
    let outcome = nsec_wildcard_nodata(&qname, Rtype::AAAA, &origin, &proofs, DenialLimits::new())
        .expect("NSEC wildcard NODATA proof");
    assert_eq!(outcome.outcome, DenialOutcome::WildcardNoData);

    // DS NODATA в apex: NSEC apex без DS.
    let qname = name("example.com");
    let response = query(&engine, "example.com.", Rtype::DS, true);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    let proofs = nsec_proofs(response.authority());
    let outcome = nsec_nodata(&qname, Rtype::DS, &origin, &proofs, DenialLimits::new())
        .expect("NSEC DS-NODATA proof");
    assert_eq!(outcome.outcome, DenialOutcome::NoData);

    // Insecure delegation: NSEC в cut доказывает отсутствие DS.
    let cut = name("sub.example.com");
    let response = query(&engine, "sub.example.com.", Rtype::DS, true);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    let proofs = nsec_proofs(response.authority());
    let outcome = nsec_nodata(&cut, Rtype::DS, &origin, &proofs, DenialLimits::new())
        .expect("NSEC DS-NODATA at delegation");
    assert_eq!(outcome.outcome, DenialOutcome::NoData);

    // DO=0: без RRSIG и без NSEC.
    let response = query(&engine, "nope.example.com.", Rtype::A, false);
    assert_eq!(response.rcode(), Rcode::NXDOMAIN);
    assert!(
        response
            .answers()
            .iter()
            .chain(response.authority())
            .all(|record| record.rr_type() != Rtype::RRSIG && record.rr_type() != Rtype::NSEC)
    );
}
