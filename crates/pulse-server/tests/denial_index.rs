//! Property: индексированный поиск denial-записей эквивалентен линейному
//! перебору (старый путь), включая полный ответ движка.

#![cfg(feature = "testkit")]

use std::cmp::Ordering;
use std::sync::Arc;

use proptest::prelude::*;
use pulse_dns::{
    DnskeyData, Edns, Message, Name, Question, Rclass, Rdata, Rrset, RrsigData, Rtype, Serial,
    SoaData, Ttl, TypeBitmap,
};
use pulse_server::application::{QueryEngine, Transport};
use pulse_server::testkit::InMemoryZone;
use pulse_server::{DenialKind, ZoneView};

fn name(text: &str) -> Name {
    Name::parse(text).expect("test name")
}

fn ttl(value: u32) -> Ttl {
    Ttl::new(value).expect("test ttl")
}

fn rrset(owner: &Name, rr_type: Rtype, rdatas: impl IntoIterator<Item = Rdata>) -> Rrset {
    Rrset::new(owner.clone(), rr_type, Rclass::IN, ttl(300), rdatas).expect("test rrset")
}

fn nsec_owner(rrset: &Rrset) -> Name {
    rrset.owner().clone()
}

fn nsec_next(rrset: &Rrset) -> Name {
    rrset
        .rdatas()
        .iter()
        .find_map(|rdata| match rdata {
            Rdata::Nsec(nsec) => Some(nsec.next_domain().clone()),
            _ => None,
        })
        .expect("NSEC next")
}

fn nsec3_owner_hash(rrset: &Rrset) -> Vec<u8> {
    let label = rrset.owner().first_label().expect("NSEC3 label");
    pulse_dnssec::denial::base32hex::decode(label).expect("NSEC3 hash")
}

fn nsec3_next(rrset: &Rrset) -> Vec<u8> {
    rrset
        .rdatas()
        .iter()
        .find_map(|rdata| match rdata {
            Rdata::Nsec3(data) => Some(data.next_hashed_owner().to_vec()),
            _ => None,
        })
        .expect("NSEC3 next")
}

/// RFC 4034 §4.1.2.
fn nsec_covers(owner: &Name, next: &Name, name: &Name) -> bool {
    if name == owner {
        return false;
    }
    match owner.cmp_canonical(next) {
        Ordering::Less => {
            owner.cmp_canonical(name) == Ordering::Less
                && name.cmp_canonical(next) == Ordering::Less
        }
        Ordering::Greater | Ordering::Equal => {
            owner.cmp_canonical(name) == Ordering::Less
                || name.cmp_canonical(next) == Ordering::Less
        }
    }
}

/// RFC 5155 §7.2.
fn nsec3_covers(owner: &[u8], next: &[u8], hash: &[u8]) -> bool {
    if hash == owner {
        return false;
    }
    match owner.cmp(next) {
        Ordering::Less => hash > owner && hash < next,
        Ordering::Greater | Ordering::Equal => hash > owner || hash < next,
    }
}

fn linear_nsec_cover(records: &[Rrset], name: &Name) -> Option<Rrset> {
    records.iter().find_map(|rrset| {
        let owner = nsec_owner(rrset);
        let next = nsec_next(rrset);
        nsec_covers(&owner, &next, name).then(|| rrset.clone())
    })
}

fn linear_nsec3_cover(records: &[Rrset], hash: &[u8]) -> Option<Rrset> {
    records.iter().find_map(|rrset| {
        let owner = nsec3_owner_hash(rrset);
        let next = nsec3_next(rrset);
        nsec3_covers(&owner, &next, hash).then(|| rrset.clone())
    })
}

/// Зона с линейным (старым) поиском cover; всё остальное делегируется
/// `InMemoryZone`.
struct LinearZone {
    inner: InMemoryZone,
    nsec: Vec<Rrset>,
    nsec3: Vec<Rrset>,
}

impl LinearZone {
    fn new(inner: InMemoryZone, records: &[Rrset]) -> Self {
        Self {
            inner,
            nsec: records
                .iter()
                .filter(|rrset| rrset.rr_type() == Rtype::NSEC)
                .cloned()
                .collect(),
            nsec3: records
                .iter()
                .filter(|rrset| rrset.rr_type() == Rtype::NSEC3)
                .cloned()
                .collect(),
        }
    }
}

impl ZoneView for LinearZone {
    fn origin(&self) -> &Name {
        self.inner.origin()
    }

    fn apex(&self) -> &Name {
        self.inner.apex()
    }

    fn soa(&self) -> Option<&Rrset> {
        self.inner.soa()
    }

    fn ns(&self) -> Option<&Rrset> {
        self.inner.ns()
    }

    fn class(&self) -> Rclass {
        self.inner.class()
    }

    fn state(&self) -> pulse_server::ZoneState {
        self.inner.state()
    }

    fn lookup(&self, name: &Name, rr_type: Rtype) -> pulse_server::LookupOutcome {
        self.inner.lookup(name, rr_type)
    }

    fn lookup_all_rrsig(&self, name: &Name, covered: Rtype) -> Vec<Rrset> {
        self.inner.lookup_all_rrsig(name, covered)
    }

    fn denial(&self) -> DenialKind {
        self.inner.denial()
    }

    fn nsec_at(&self, name: &Name) -> Option<Rrset> {
        self.inner.nsec_at(name)
    }

    fn nsec_cover(&self, name: &Name) -> Option<Rrset> {
        linear_nsec_cover(&self.nsec, name)
    }

    fn nsec3_param(&self) -> Option<Rrset> {
        self.inner.nsec3_param()
    }

    fn nsec3_at(&self, hash: &[u8]) -> Option<Rrset> {
        self.inner.nsec3_at(hash)
    }

    fn nsec3_cover(&self, hash: &[u8]) -> Option<Rrset> {
        linear_nsec3_cover(&self.nsec3, hash)
    }

    fn is_delegation(&self, name: &Name) -> bool {
        self.inner.is_delegation(name)
    }

    fn glue(&self, name: &Name) -> Vec<Rrset> {
        self.inner.glue(name)
    }

    fn node_exists(&self, name: &Name) -> bool {
        self.inner.node_exists(name)
    }
}

fn signed_skeleton(
    origin: &Name,
    data: Vec<Rrset>,
    denial_records: Vec<Rrset>,
) -> (InMemoryZone, Vec<Rrset>) {
    let mut records = data;
    records.extend(denial_records);
    records.push(rrset(
        origin,
        Rtype::DNSKEY,
        [Rdata::Dnskey(
            DnskeyData::new(257, 3, 8, vec![7_u8; 32]).expect("dnskey"),
        )],
    ));
    records.push(rrset(
        origin,
        Rtype::RRSIG,
        [Rdata::Rrsig(
            RrsigData::new(
                Rtype::DNSKEY,
                8,
                2,
                300,
                u32::MAX,
                1,
                1,
                origin.clone(),
                vec![9_u8; 64],
            )
            .expect("rrsig"),
        )],
    ));
    let mut zone = InMemoryZone::new(origin.clone());
    for rrset in &records {
        zone.insert(rrset.clone()).expect("insert");
    }
    (zone, records)
}

fn base_names(origin: &Name) -> Vec<Name> {
    let mut names = vec![
        origin.clone(),
        name("www.example.com"),
        name("wild.example.com"),
        name("*.wild.example.com"),
        name("sub.example.com"),
    ];
    names.sort_by(Name::cmp_canonical);
    names
}

fn nsec_zone(origin: &Name) -> (InMemoryZone, Vec<Rrset>) {
    let names = base_names(origin);
    let bitmap =
        TypeBitmap::from_types([Rtype::A, Rtype::NS, Rtype::SOA, Rtype::NSEC, Rtype::RRSIG]);
    let mut denial = Vec::new();
    for (index, owner) in names.iter().enumerate() {
        let next = names
            .get(index + 1)
            .cloned()
            .unwrap_or_else(|| origin.clone());
        denial.push(rrset(
            owner,
            Rtype::NSEC,
            [Rdata::Nsec(
                pulse_dns::NsecData::new(next, bitmap.clone()).expect("nsec"),
            )],
        ));
    }
    let data = vec![
        rrset(
            origin,
            Rtype::SOA,
            [Rdata::Soa(SoaData::new(
                name("ns1.example.com"),
                name("hostmaster.example.com"),
                Serial::new(1),
                3600,
                600,
                604_800,
                300,
            ))],
        ),
        rrset(origin, Rtype::NS, [Rdata::Ns(name("ns1.example.com"))]),
        rrset(
            &name("www.example.com"),
            Rtype::A,
            [Rdata::A("192.0.2.1".parse().expect("ip"))],
        ),
        rrset(
            &name("*.wild.example.com"),
            Rtype::A,
            [Rdata::A("192.0.2.2".parse().expect("ip"))],
        ),
        rrset(
            &name("wild.example.com"),
            Rtype::TXT,
            [Rdata::Txt(
                pulse_dns::TxtData::new([b"base".to_vec()]).expect("txt"),
            )],
        ),
        rrset(
            &name("sub.example.com"),
            Rtype::NS,
            [Rdata::Ns(name("ns.sub.example.com"))],
        ),
    ];
    signed_skeleton(origin, data, denial)
}

fn nsec3_zone(origin: &Name) -> (InMemoryZone, Vec<Rrset>) {
    let salt = vec![0xAA, 0xBB];
    let mut owners: Vec<Name> = base_names(origin);
    for index in 0..8 {
        owners.push(name(&format!("n{index}.example.com")));
    }
    let mut hashes: Vec<Vec<u8>> = owners
        .iter()
        .map(|owner| pulse_dnssec::rdata_util::nsec3_hash(owner, &salt, 2))
        .collect();
    hashes.sort();
    let bitmap = TypeBitmap::from_types([Rtype::A, Rtype::NS, Rtype::SOA, Rtype::RRSIG]);
    let mut denial = Vec::new();
    for (index, hash) in hashes.iter().enumerate() {
        let next = hashes
            .get(index + 1)
            .cloned()
            .unwrap_or_else(|| hashes[0].clone());
        let owner = pulse_dnssec::denial::nsec3_owner_name(origin, hash).expect("owner");
        denial.push(rrset(
            &owner,
            Rtype::NSEC3,
            [Rdata::Nsec3(
                pulse_dns::Nsec3Data::new(1, 0, 2, salt.clone(), next, bitmap.clone())
                    .expect("nsec3"),
            )],
        ));
    }
    let data = vec![
        rrset(
            origin,
            Rtype::SOA,
            [Rdata::Soa(SoaData::new(
                name("ns1.example.com"),
                name("hostmaster.example.com"),
                Serial::new(1),
                3600,
                600,
                604_800,
                300,
            ))],
        ),
        rrset(origin, Rtype::NS, [Rdata::Ns(name("ns1.example.com"))]),
        rrset(
            origin,
            Rtype::NSEC3PARAM,
            [Rdata::Nsec3Param(
                pulse_dns::Nsec3ParamData::new(1, 0, 2, salt.clone()).expect("param"),
            )],
        ),
        rrset(
            &name("www.example.com"),
            Rtype::A,
            [Rdata::A("192.0.2.1".parse().expect("ip"))],
        ),
        rrset(
            &name("*.wild.example.com"),
            Rtype::A,
            [Rdata::A("192.0.2.2".parse().expect("ip"))],
        ),
        rrset(
            &name("wild.example.com"),
            Rtype::TXT,
            [Rdata::Txt(
                pulse_dns::TxtData::new([b"base".to_vec()]).expect("txt"),
            )],
        ),
        rrset(
            &name("sub.example.com"),
            Rtype::NS,
            [Rdata::Ns(name("ns.sub.example.com"))],
        ),
    ];
    signed_skeleton(origin, data, denial)
}

fn query(qname: &str, qtype: Rtype) -> Message {
    let mut message = Message::query(0x1234, Question::new(name(qname), qtype, Rclass::IN));
    message.set_edns(Some(Edns::new(1232).with_dnssec_ok(true)));
    message
}

#[test]
fn nsec_negative_and_wildcard_match_linear_path() {
    let origin = name("example.com");
    let (zone, records) = nsec_zone(&origin);
    let reference = LinearZone::new(zone.clone(), &records);
    let engine = QueryEngine::new(vec![Arc::new(zone)]);
    let linear = QueryEngine::new(vec![Arc::new(reference)]);
    for (qname, qtype) in [
        ("nope.example.com.", Rtype::A),
        ("www.example.com.", Rtype::AAAA),
        ("foo.wild.example.com.", Rtype::A),
        ("foo.wild.example.com.", Rtype::AAAA),
        ("sub.example.com.", Rtype::DS),
        ("sub.example.com.", Rtype::A),
        ("example.com.", Rtype::DS),
    ] {
        let request = query(qname, qtype);
        assert_eq!(
            engine.respond(&request, Transport::Udp),
            linear.respond(&request, Transport::Udp),
            "{qname} {qtype}"
        );
    }
}

#[test]
fn nsec3_negative_and_wildcard_match_linear_path() {
    let origin = name("example.com");
    let (zone, records) = nsec3_zone(&origin);
    let reference = LinearZone::new(zone.clone(), &records);
    let engine = QueryEngine::new(vec![Arc::new(zone)]);
    let linear = QueryEngine::new(vec![Arc::new(reference)]);
    for (qname, qtype) in [
        ("nope.example.com.", Rtype::A),
        ("www.example.com.", Rtype::AAAA),
        ("foo.wild.example.com.", Rtype::A),
        ("foo.wild.example.com.", Rtype::AAAA),
        ("sub.example.com.", Rtype::DS),
        ("sub.example.com.", Rtype::A),
        ("example.com.", Rtype::DS),
    ] {
        let request = query(qname, qtype);
        assert_eq!(
            engine.respond(&request, Transport::Udp),
            linear.respond(&request, Transport::Udp),
            "{qname} {qtype}"
        );
    }
}

proptest! {
    #[test]
    fn nsec_cover_matches_linear(
        labels in proptest::collection::vec("[a-z0-9]{1,6}", 1..10),
        target in "[a-z0-9]{1,8}",
    ) {
        let origin = name("example.com");
        let mut owners: Vec<Name> = labels
            .iter()
            .map(|label| name(&format!("{label}.example.com")))
            .collect();
        owners.push(origin.clone());
        owners.sort_by(Name::cmp_canonical);
        owners.dedup();
        let bitmap = TypeBitmap::from_types([Rtype::A, Rtype::NSEC]);
        let mut records = Vec::new();
        for (index, owner) in owners.iter().enumerate() {
            let next = owners.get(index + 1).cloned().unwrap_or_else(|| origin.clone());
            records.push(rrset(
                owner,
                Rtype::NSEC,
                [Rdata::Nsec(
                    pulse_dns::NsecData::new(next, bitmap.clone()).expect("nsec"),
                )],
            ));
        }
        let mut zone = InMemoryZone::new(origin);
        for rrset in &records {
            zone.insert(rrset.clone()).expect("insert");
        }
        let targets = [
            name(&format!("{target}.example.com")),
            name(&format!("{target}{target}.example.com")),
        ];
        for target in &targets {
            prop_assert_eq!(zone.nsec_cover(target), linear_nsec_cover(&records, target));
        }
        for owner in &owners {
            prop_assert_eq!(zone.nsec_cover(owner), linear_nsec_cover(&records, owner));
        }
    }

    #[test]
    fn nsec3_cover_matches_linear(
        hashes in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 20), 1..12),
        target in proptest::collection::vec(any::<u8>(), 20),
    ) {
        let origin = name("example.com");
        let mut sorted = hashes;
        sorted.sort();
        sorted.dedup();
        let bitmap = TypeBitmap::from_types([Rtype::A]);
        let mut records = Vec::new();
        for (index, hash) in sorted.iter().enumerate() {
            let next = sorted.get(index + 1).cloned().unwrap_or_else(|| sorted[0].clone());
            let owner = pulse_dnssec::denial::nsec3_owner_name(&origin, hash).expect("owner");
            records.push(rrset(
                &owner,
                Rtype::NSEC3,
                [Rdata::Nsec3(
                    pulse_dns::Nsec3Data::new(1, 0, 0, Vec::new(), next, bitmap.clone())
                        .expect("nsec3"),
                )],
            ));
        }
        let mut zone = InMemoryZone::new(origin);
        for rrset in &records {
            zone.insert(rrset.clone()).expect("insert");
        }
        prop_assert_eq!(
            zone.nsec3_cover(&target),
            linear_nsec3_cover(&records, &target)
        );
        for hash in &sorted {
            prop_assert_eq!(zone.nsec3_cover(hash), linear_nsec3_cover(&records, hash));
        }
    }
}
