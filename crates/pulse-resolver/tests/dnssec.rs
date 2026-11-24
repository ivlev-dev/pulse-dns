//! DNSSEC: подпись зоны `pulse-dnssec`, AD-бит, BOGUS → SERVFAIL.

mod support;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pulse_dns::{
    Name, NsecData, Rclass, Rcode, Rdata, Record, Rrset, RrsigData, Rtype, Serial, SoaData, Ttl,
    TypeBitmap,
};
use pulse_dnssec::{Algorithm, DsPolicy, PrivateKey, SignOptions, ds_from_dnskey, sign_rrset};
use pulse_resolver::{DnssecConfig, Resolver, ResolverConfig, TimeoutConfig, TrustAnchorConfig};
use support::{MockServer, RawHandler, encode, response};

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
    let zone = Name::parse("example.test").unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .try_into()
        .unwrap_or(u32::MAX);
    let key = PrivateKey::generate(Algorithm::ED25519).unwrap();
    let dnskey_data = key.dnskey(257).unwrap();
    let ttl = Ttl::new(300).unwrap();

    let dnskey_rrset = Rrset::new(
        zone.clone(),
        Rtype::DNSKEY,
        Rclass::IN,
        ttl,
        [Rdata::Dnskey(dnskey_data.clone())],
    )
    .unwrap();
    let answer_rrset = Rrset::new(
        zone.clone(),
        Rtype::A,
        Rclass::IN,
        ttl,
        [Rdata::A("192.0.2.42".parse().unwrap())],
    )
    .unwrap();
    let options = SignOptions::new(zone.clone(), now, 3600).with_dnskey_flags(257);
    let mut answer_sig = sign_rrset(&key, &answer_rrset, &options).unwrap();
    let dnskey_sig = sign_rrset(&key, &dnskey_rrset, &options).unwrap();

    let soa_rrset = Rrset::new(
        zone.clone(),
        Rtype::SOA,
        Rclass::IN,
        ttl,
        [Rdata::Soa(SoaData::new(
            Name::parse("ns1.example.test").unwrap(),
            Name::parse("hostmaster.example.test").unwrap(),
            Serial::new(1),
            3600,
            600,
            86_400,
            60,
        ))],
    )
    .unwrap();
    let nsec_rrset = Rrset::new(
        zone.clone(),
        Rtype::NSEC,
        Rclass::IN,
        ttl,
        [Rdata::Nsec(
            NsecData::new(
                Name::parse("zzz.example.test").unwrap(),
                TypeBitmap::from_types([
                    Rtype::A,
                    Rtype::NS,
                    Rtype::SOA,
                    Rtype::DNSKEY,
                    Rtype::RRSIG,
                    Rtype::NSEC,
                ]),
            )
            .unwrap(),
        )],
    )
    .unwrap();
    let soa_sig = sign_rrset(&key, &soa_rrset, &options).unwrap();
    let nsec_sig = sign_rrset(&key, &nsec_rrset, &options).unwrap();

    if tamper {
        answer_sig = corrupt(&answer_sig);
    }

    SignedZone {
        zone: zone.clone(),
        dnskey: Record::new(
            zone.clone(),
            Rtype::DNSKEY,
            Rclass::IN,
            ttl,
            Rdata::Dnskey(dnskey_data),
        )
        .unwrap(),
        dnskey_sig,
        answer: Record::new(
            zone.clone(),
            Rtype::A,
            Rclass::IN,
            ttl,
            Rdata::A("192.0.2.42".parse().unwrap()),
        )
        .unwrap(),
        answer_sig,
        soa: Record::new(
            zone.clone(),
            Rtype::SOA,
            Rclass::IN,
            ttl,
            Rdata::Soa(SoaData::new(
                Name::parse("ns1.example.test").unwrap(),
                Name::parse("hostmaster.example.test").unwrap(),
                Serial::new(1),
                3600,
                600,
                86_400,
                60,
            )),
        )
        .unwrap(),
        soa_sig,
        nsec: Record::new(
            zone.clone(),
            Rtype::NSEC,
            Rclass::IN,
            ttl,
            Rdata::Nsec(
                NsecData::new(
                    Name::parse("zzz.example.test").unwrap(),
                    TypeBitmap::from_types([
                        Rtype::A,
                        Rtype::NS,
                        Rtype::SOA,
                        Rtype::DNSKEY,
                        Rtype::RRSIG,
                        Rtype::NSEC,
                    ]),
                )
                .unwrap(),
            ),
        )
        .unwrap(),
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
    .unwrap()
}

fn rrsig_record(owner: &Name, signature: &RrsigData, ttl: u32) -> Record {
    Record::new(
        owner.clone(),
        Rtype::RRSIG,
        Rclass::IN,
        Ttl::new(ttl).unwrap(),
        Rdata::Rrsig(signature.clone()),
    )
    .unwrap()
}

fn config(server: SocketAddr, anchor: TrustAnchorConfig) -> ResolverConfig {
    let mut config = ResolverConfig::forward(vec![server]);
    config.timeouts = TimeoutConfig {
        per_query: Duration::from_millis(500),
        tcp: Duration::from_millis(700),
        total: Duration::from_secs(3),
    };
    config.retries = 1;
    config.use_0x20 = false;
    config.dnssec = DnssecConfig {
        enabled: true,
        anchors: vec![anchor],
        ..DnssecConfig::default()
    };
    config
}

fn anchor_for(zone: &SignedZone) -> TrustAnchorConfig {
    let Rdata::Dnskey(dnskey) = zone.dnskey.rdata() else {
        panic!("not a dnskey");
    };
    let ds = ds_from_dnskey(&zone.zone, dnskey, 2, DsPolicy::strict()).unwrap();
    TrustAnchorConfig::new(zone.zone.clone(), ds)
}

fn handler(zone: SignedZone) -> RawHandler {
    Arc::new(move |request, _tcp| {
        let question = request.questions().first()?;
        let mut reply = response(request, Rcode::NOERROR);
        if question.qname() != &zone.zone {
            reply.set_rcode(Rcode::NXDOMAIN);
            reply.add_authority(zone.soa.clone());
            reply.add_authority(rrsig_record(&zone.zone, &zone.soa_sig, 300));
            reply.add_authority(zone.nsec.clone());
            reply.add_authority(rrsig_record(&zone.zone, &zone.nsec_sig, 300));
            return Some(encode(&reply));
        }
        match question.qtype() {
            Rtype::DNSKEY => {
                reply.add_answer(zone.dnskey.clone());
                reply.add_answer(rrsig_record(&zone.zone, &zone.dnskey_sig, 300));
            }
            Rtype::A => {
                reply.add_answer(zone.answer.clone());
                reply.add_answer(rrsig_record(&zone.zone, &zone.answer_sig, 300));
            }
            _ => {
                reply.set_rcode(Rcode::NXDOMAIN);
                reply.add_authority(zone.soa.clone());
                reply.add_authority(rrsig_record(&zone.zone, &zone.soa_sig, 300));
                reply.add_authority(zone.nsec.clone());
                reply.add_authority(rrsig_record(&zone.zone, &zone.nsec_sig, 300));
            }
        }
        Some(encode(&reply))
    })
}

#[test]
fn signed_answer_sets_ad_and_is_cached_secure() {
    let zone = signed_zone(false);
    let anchor = anchor_for(&zone);
    let server = MockServer::spawn(handler(zone));
    let resolver = Resolver::new(config(server.address(), anchor)).unwrap();
    let name = Name::parse("example.test").unwrap();

    let first = resolver.resolve_qname(&name, Rtype::A);
    assert_eq!(first.rcode(), Rcode::NOERROR);
    assert_eq!(first.answers().len(), 1);
    assert!(first.flags().ad(), "AD must be set for a validated answer");
    assert!(resolver.stats().dnssec_secure >= 1);

    let second = resolver.resolve_qname(&name, Rtype::A);
    assert!(second.flags().ad(), "cached secure answer keeps AD");
    assert!(resolver.stats().cache.hits >= 1);
}

#[test]
fn signed_nxdomain_sets_ad() {
    let zone = signed_zone(false);
    let anchor = anchor_for(&zone);
    let server = MockServer::spawn(handler(zone));
    let resolver = Resolver::new(config(server.address(), anchor)).unwrap();
    let reply = resolver.resolve_qname(&Name::parse("missing.example.test").unwrap(), Rtype::A);
    assert_eq!(reply.rcode(), Rcode::NXDOMAIN);
    assert!(reply.flags().ad(), "NSEC proof must set AD");
    assert!(resolver.stats().dnssec_secure >= 1);
}

#[test]
fn corrupt_signature_is_servfail() {
    let zone = signed_zone(true);
    let anchor = anchor_for(&zone);
    let server = MockServer::spawn(handler(zone));
    let resolver = Resolver::new(config(server.address(), anchor)).unwrap();
    let reply = resolver.resolve_qname(&Name::parse("example.test").unwrap(), Rtype::A);
    assert_eq!(reply.rcode(), Rcode::SERVFAIL);
    assert!(!reply.flags().ad());
    assert!(resolver.stats().dnssec_bogus >= 1);
}

#[test]
fn unsigned_zone_is_insecure_passthrough() {
    let handler: RawHandler = Arc::new(|request, _tcp| {
        let mut reply = response(request, Rcode::NOERROR);
        reply.add_answer(support::a("unsigned.test", 300, [192, 0, 2, 5]));
        Some(encode(&reply))
    });
    let server = MockServer::spawn(handler);
    let zone = Name::parse("unsigned.test").unwrap();
    let dnskey_data = PrivateKey::generate(Algorithm::ED25519)
        .unwrap()
        .dnskey(257)
        .unwrap();
    let ds = ds_from_dnskey(&zone, &dnskey_data, 2, DsPolicy::strict()).unwrap();
    let resolver =
        Resolver::new(config(server.address(), TrustAnchorConfig::new(zone, ds))).unwrap();
    let reply = resolver.resolve_qname(&Name::parse("unsigned.test").unwrap(), Rtype::A);
    assert_eq!(reply.rcode(), Rcode::NOERROR);
    assert!(!reply.flags().ad());
}
