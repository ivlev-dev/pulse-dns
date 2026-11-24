//! DNSSEC: подписанная mock-зона `pulse-dnssec`, AD-бит и BOGUS → SERVFAIL.

mod support;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pulse_dns::{
    Name, NsecData, Rclass, Rcode, Rdata, Record, Rrset, RrsigData, Rtype, Serial, SoaData, Ttl,
    TypeBitmap,
};
use pulse_dnssec::{Algorithm, DsPolicy, PrivateKey, SignOptions, ds_from_dnskey, sign_rrset};
use pulseresolved::config::TrustAnchorSetting;
use pulseresolved::server::Server;
use support::{MockUpstream, base_config, make_query, udp_query};

const TIMEOUT: Duration = Duration::from_secs(3);

struct SignedZone {
    zone: Name,
    dnskey: Record,
    dnskey_sig: RrsigData,
    answer: Record,
    answer_sig: RrsigData,
    soa: Record,
    soa_sig: RrsigData,
    nsec: Record,
    nsec_sig: RrsigData,
}

#[allow(clippy::too_many_lines)]
fn signed_zone(tamper: bool) -> SignedZone {
    let zone = Name::parse("signed.test").expect("zone");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
        .try_into()
        .unwrap_or(u32::MAX);
    let key = PrivateKey::generate(Algorithm::ED25519).expect("key");
    let dnskey_data = key.dnskey(257).expect("dnskey");
    let ttl = Ttl::new(300).expect("ttl");

    let dnskey_rrset = Rrset::new(
        zone.clone(),
        Rtype::DNSKEY,
        Rclass::IN,
        ttl,
        [Rdata::Dnskey(dnskey_data.clone())],
    )
    .expect("dnskey rrset");
    let answer_rrset = Rrset::new(
        zone.clone(),
        Rtype::A,
        Rclass::IN,
        ttl,
        [Rdata::A("192.0.2.42".parse().expect("address"))],
    )
    .expect("a rrset");
    let options = SignOptions::new(zone.clone(), now, 3600).with_dnskey_flags(257);
    let answer_sig = sign_rrset(&key, &answer_rrset, &options).expect("sign a");
    let dnskey_sig = sign_rrset(&key, &dnskey_rrset, &options).expect("sign dnskey");

    let soa = SoaData::new(
        Name::parse("ns1.signed.test").expect("mname"),
        Name::parse("hostmaster.signed.test").expect("rname"),
        Serial::new(1),
        3600,
        600,
        86_400,
        60,
    );
    let soa_rrset = Rrset::new(
        zone.clone(),
        Rtype::SOA,
        Rclass::IN,
        ttl,
        [Rdata::Soa(soa.clone())],
    )
    .expect("soa rrset");
    let nsec_rrset = Rrset::new(
        zone.clone(),
        Rtype::NSEC,
        Rclass::IN,
        ttl,
        [Rdata::Nsec(
            NsecData::new(
                Name::parse("zzz.signed.test").expect("next"),
                TypeBitmap::from_types([
                    Rtype::A,
                    Rtype::NS,
                    Rtype::SOA,
                    Rtype::DNSKEY,
                    Rtype::RRSIG,
                    Rtype::NSEC,
                ]),
            )
            .expect("nsec"),
        )],
    )
    .expect("nsec rrset");
    let soa_sig = sign_rrset(&key, &soa_rrset, &options).expect("sign soa");
    let nsec_sig = sign_rrset(&key, &nsec_rrset, &options).expect("sign nsec");

    let answer_sig = if tamper {
        corrupt(&answer_sig)
    } else {
        answer_sig
    };

    SignedZone {
        zone: zone.clone(),
        dnskey: Record::new(
            zone.clone(),
            Rtype::DNSKEY,
            Rclass::IN,
            ttl,
            Rdata::Dnskey(dnskey_data),
        )
        .expect("dnskey record"),
        dnskey_sig,
        answer: Record::new(
            zone.clone(),
            Rtype::A,
            Rclass::IN,
            ttl,
            Rdata::A("192.0.2.42".parse().expect("address")),
        )
        .expect("a record"),
        answer_sig,
        soa: Record::new(zone.clone(), Rtype::SOA, Rclass::IN, ttl, Rdata::Soa(soa))
            .expect("soa record"),
        soa_sig,
        nsec: Record::new(
            zone.clone(),
            Rtype::NSEC,
            Rclass::IN,
            ttl,
            Rdata::Nsec(
                NsecData::new(
                    Name::parse("zzz.signed.test").expect("next"),
                    TypeBitmap::from_types([Rtype::A, Rtype::SOA, Rtype::DNSKEY, Rtype::RRSIG]),
                )
                .expect("nsec"),
            ),
        )
        .expect("nsec record"),
        nsec_sig,
    }
}

fn corrupt(signature: &RrsigData) -> RrsigData {
    let mut bytes = signature.signature().to_vec();
    if let Some(last) = bytes.last_mut() {
        *last ^= 0xFF;
    }
    RrsigData::new(
        signature.type_covered(),
        signature.algorithm(),
        signature.labels(),
        signature.original_ttl(),
        signature.signature_expiration(),
        signature.signature_inception(),
        signature.key_tag(),
        signature.signer_name().clone(),
        bytes,
    )
    .expect("corrupt sig")
}

fn rrsig_record(zone: &Name, signature: &RrsigData) -> Record {
    Record::new(
        zone.clone(),
        Rtype::RRSIG,
        Rclass::IN,
        Ttl::new(300).expect("ttl"),
        Rdata::Rrsig(signature.clone()),
    )
    .expect("rrsig record")
}

fn serve(zone: SignedZone) -> MockUpstream {
    MockUpstream::start(move |request| {
        let question = request.questions().first()?;
        let mut reply = pulse_dns::Message::response(request);
        if question.qname() != &zone.zone {
            reply.set_rcode(Rcode::NXDOMAIN);
            reply.add_authority(zone.soa.clone());
            reply.add_authority(rrsig_record(&zone.zone, &zone.soa_sig));
            reply.add_authority(zone.nsec.clone());
            reply.add_authority(rrsig_record(&zone.zone, &zone.nsec_sig));
            return Some(reply);
        }
        match question.qtype() {
            Rtype::DNSKEY => {
                reply.add_answer(zone.dnskey.clone());
                reply.add_answer(rrsig_record(&zone.zone, &zone.dnskey_sig));
            }
            Rtype::A => {
                reply.add_answer(zone.answer.clone());
                reply.add_answer(rrsig_record(&zone.zone, &zone.answer_sig));
            }
            _ => {
                reply.set_rcode(Rcode::NXDOMAIN);
                reply.add_authority(zone.soa.clone());
                reply.add_authority(rrsig_record(&zone.zone, &zone.soa_sig));
                reply.add_authority(zone.nsec.clone());
                reply.add_authority(rrsig_record(&zone.zone, &zone.nsec_sig));
            }
        }
        Some(reply)
    })
}

fn anchor_file(zone: &SignedZone) -> (tempfile::TempDir, std::path::PathBuf) {
    let Rdata::Dnskey(dnskey) = zone.dnskey.rdata() else {
        panic!("not a dnskey");
    };
    let ds = ds_from_dnskey(&zone.zone, dnskey, 2, DsPolicy::strict()).expect("ds");
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("root.ds");
    let mut digest = String::with_capacity(ds.digest().len() * 2);
    for byte in ds.digest() {
        use std::fmt::Write as _;
        write!(digest, "{byte:02x}").expect("hex");
    }
    std::fs::write(
        &path,
        format!(
            "{} 300 IN DS {} {} {} {digest}\n",
            zone.zone,
            ds.key_tag(),
            ds.algorithm(),
            ds.digest_type()
        ),
    )
    .expect("write anchor");
    (directory, path)
}

#[test]
fn validated_answer_sets_ad_and_is_cached() {
    let zone = signed_zone(false);
    let (_dir, anchor) = anchor_file(&zone);
    let upstream = serve(zone);
    let mut config = base_config(upstream.address());
    config.dnssec_validate = true;
    config.trust_anchor = Some(TrustAnchorSetting::PathFile(anchor));
    let server = Server::start(&config).unwrap();
    let addr = server.udp_addr().unwrap();
    let query = make_query("signed.test", Rtype::A, Some(1232));

    let first = udp_query(addr, &query, TIMEOUT).expect("validated answer");
    assert_eq!(first.rcode(), Rcode::NOERROR);
    assert_eq!(first.answers().len(), 1);
    assert!(first.flags().ad(), "AD must be set for a validated answer");
    assert!(server.resolver_stats().dnssec_secure >= 1);

    let second = udp_query(addr, &query, TIMEOUT).expect("cached answer");
    assert!(second.flags().ad(), "cached secure answer keeps AD");
    assert!(server.resolver_stats().cache.hits >= 1);
}

#[test]
fn corrupt_signature_becomes_servfail() {
    let zone = signed_zone(true);
    let (_dir, anchor) = anchor_file(&zone);
    let upstream = serve(zone);
    let mut config = base_config(upstream.address());
    config.dnssec_validate = true;
    config.trust_anchor = Some(TrustAnchorSetting::PathFile(anchor));
    let server = Server::start(&config).unwrap();
    let reply = udp_query(
        server.udp_addr().unwrap(),
        &make_query("signed.test", Rtype::A, Some(1232)),
        TIMEOUT,
    )
    .expect("servfail");

    assert_eq!(reply.rcode(), Rcode::SERVFAIL);
    assert!(!reply.flags().ad());
    assert!(server.resolver_stats().dnssec_bogus >= 1);
}

#[test]
fn missing_anchor_file_fails_startup() {
    let mut config = base_config("127.0.0.1:53".parse().unwrap());
    config.dnssec_validate = true;
    config.trust_anchor = Some(TrustAnchorSetting::PathFile(std::path::PathBuf::from(
        "/nonexistent/pulseresolved-root.ds",
    )));
    let Err(error) = Server::start(&config) else {
        panic!("startup must fail without the anchor file");
    };
    assert!(matches!(
        error,
        pulseresolved::error::ServerError::Config(_)
    ));
}

#[test]
fn unsigned_zone_is_insecure_without_ad() {
    let upstream = MockUpstream::start(|request| {
        let owner = request
            .questions()
            .first()
            .map(|question| question.qname().to_string())?;
        Some(support::positive_response(
            request,
            support::a_record(&owner, [192, 0, 2, 99], 300),
        ))
    });
    // Trust anchor для чужой зоны: ответ остаётся insecure-proven.
    let zone = signed_zone(false);
    let (_directory, anchor) = anchor_file(&zone);
    let mut config = base_config(upstream.address());
    config.dnssec_validate = true;
    config.trust_anchor = Some(TrustAnchorSetting::PathFile(anchor));
    let server = Server::start(&config).unwrap();
    let reply = udp_query(
        server.udp_addr().unwrap(),
        &make_query("unsigned.test", Rtype::A, Some(1232)),
        TIMEOUT,
    )
    .expect("insecure answer");
    assert_eq!(reply.rcode(), Rcode::NOERROR);
    assert!(!reply.flags().ad());
}
