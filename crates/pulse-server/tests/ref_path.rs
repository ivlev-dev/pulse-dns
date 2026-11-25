//! Эквивалентность байтов обычного и zero-copy путей ответа.
//!
//! Быстрый путь обязан выдавать ровно те же октеты, что и `respond_into`
//! (и `respond` + `encode`) для всех горячих случаев: точные `A`/`AAAA`/`MX`/
//! `TXT`/`SRV`/`CNAME`, `CNAME`-цепочки, wildcard, `NXDOMAIN`/`NODATA`,
//! EDNS0 без `DO`, усечение по payload. Не-горячие случаи (делегирования,
//! `DNAME`, `ANY`, `DO = 1`, циклы) обязаны уходить на полный путь.

mod common;

use std::collections::HashMap;
use std::sync::Arc;

use common::{
    big_txt_rrset, edns_query, engine_for, example_zone, insert_cname_chain, name, query, rrset,
    ttl,
};
use pulse_dns::{
    DecodeLimits, EncodeOptions, Message, MessageRef, Name, NameRef, Rclass, Rcode, Rdata, Rrset,
    Rtype, Ttl,
};
use pulse_server::application::{QueryEngine, Scratch, Transport};
use pulse_server::testkit::InMemoryZone;
use pulse_server::{
    LookupOutcome, LookupOutcomeRef, RdataRef, RrsetRef, ZoneSnapshot, ZoneState, ZoneView,
};

const EDNS_1232: u16 = 1232;

struct Fixture {
    engine: QueryEngine,
    fast: Vec<u8>,
    legacy: Vec<u8>,
    fast_scratch: Scratch,
    legacy_scratch: Scratch,
}

impl Fixture {
    fn new(zone: InMemoryZone) -> Self {
        Self::from_engine(engine_for(zone))
    }

    fn from_engine(engine: QueryEngine) -> Self {
        Self {
            engine,
            fast: vec![0_u8; 65_535],
            legacy: vec![0_u8; 65_535],
            fast_scratch: Scratch::new(),
            legacy_scratch: Scratch::new(),
        }
    }

    /// Проверяет байтовую эквивалентность и возвращает `true`, если быстрый
    /// путь ответил сам.
    fn check(&mut self, label: &str, request: &Message, transport: Transport) -> bool {
        let wire = request
            .encode(&EncodeOptions::compressed())
            .expect("query encode");
        let parsed = MessageRef::decode_simple_edns(&wire)
            .unwrap_or_else(|| panic!("{label}: simple query expected"));

        let fast = self.engine.respond_ref_into(
            &parsed,
            transport,
            &mut self.fast,
            &mut self.fast_scratch,
        );
        let legacy_len = self
            .engine
            .respond_into(
                request,
                transport,
                &mut self.legacy,
                &mut self.legacy_scratch,
            )
            .unwrap_or_else(|error| panic!("{label}: streaming path failed: {error}"));
        let owned = self
            .engine
            .respond(request, transport)
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
                true
            }
            None => false,
        }
    }
}

fn zone() -> InMemoryZone {
    let mut zone = example_zone();
    zone.insert(big_txt_rrset(40)).expect("big txt");
    insert_cname_chain(&mut zone, 16);
    zone
}

#[test]
fn exact_types_and_negative_paths_match() {
    let mut fixture = Fixture::new(zone());
    let cases: &[(&str, &str, Rtype)] = &[
        ("a", "www.example.com", Rtype::A),
        ("apex-a", "example.com", Rtype::A),
        ("apex-aaaa", "example.com", Rtype::AAAA),
        ("mx", "example.com", Rtype::MX),
        ("txt", "txt.example.com", Rtype::TXT),
        ("srv", "_sip._tcp.example.com", Rtype::SRV),
        ("svcb", "svc.example.com", Rtype::SVCB),
        ("https", "https.example.com", Rtype::HTTPS),
        ("cname-query", "alias.example.com", Rtype::CNAME),
        ("nxdomain", "missing.example.com", Rtype::A),
        ("nodata", "www.example.com", Rtype::MX),
        ("nodata-apex", "example.com", Rtype::TXT),
    ];
    for (label, qname, qtype) in cases {
        let request = query(qname, *qtype);
        assert!(
            fixture.check(label, &request, Transport::Udp),
            "{label}: expected hot path"
        );
    }
}

#[test]
fn cname_chains_match() {
    let mut fixture = Fixture::new(zone());
    for (label, qname) in [
        ("single", "alias.example.com"),
        ("two", "chain1.example.com"),
        ("external", "external.example.com"),
        ("limit-16", "c0.example.com"),
        ("over-limit", "c17.example.com"),
    ] {
        let request = query(qname, Rtype::A);
        let hot = fixture.check(label, &request, Transport::Udp);
        if label == "external" || label == "limit-16" {
            assert!(hot, "{label}: expected hot path");
        }
    }
    // Цикл: быстрый путь обязан уступить полному (SERVFAIL, не NXDOMAIN).
    let request = query("loop1.example.com", Rtype::A);
    assert!(!fixture.check("loop", &request, Transport::Udp));
}

#[test]
fn wildcard_matches() {
    let mut fixture = Fixture::new(zone());
    for (label, qname, qtype, hot) in [
        ("wild-a", "anything.wild.example.com", Rtype::A, true),
        ("wild-aaaa", "anything.wild.example.com", Rtype::AAAA, true),
        ("wild-cname-owner", "wild.example.com", Rtype::A, true),
    ] {
        let request = query(qname, qtype);
        assert_eq!(
            fixture.check(label, &request, Transport::Udp),
            hot,
            "{label}: hot-path decision"
        );
    }
}

#[test]
fn edns_matches_and_echoes_opt() {
    let mut fixture = Fixture::new(zone());
    for (label, qname, qtype, payload) in [
        ("edns-a", "www.example.com", Rtype::A, EDNS_1232),
        ("edns-mx", "example.com", Rtype::MX, EDNS_1232),
        ("edns-nx", "missing.example.com", Rtype::A, EDNS_1232),
        ("edns-low-payload", "www.example.com", Rtype::A, 100),
        ("edns-high-payload", "www.example.com", Rtype::A, 4096),
        ("edns-txt-truncate", "big.example.com", Rtype::TXT, 512),
        ("edns-txt-1232", "big.example.com", Rtype::TXT, EDNS_1232),
    ] {
        let request = edns_query(qname, qtype, payload, false);
        assert!(
            fixture.check(label, &request, Transport::Udp),
            "{label}: expected hot path"
        );
    }

    // EDNS-опции не отражаются в ответе ни одним из путей.
    let mut request = edns_query("www.example.com", Rtype::A, EDNS_1232, false);
    let mut edns = pulse_dns::Edns::new(EDNS_1232);
    edns.push_option(pulse_dns::EdnsOption::new(65001, vec![1, 2, 3, 4]).expect("option"))
        .expect("push option");
    request.set_edns(Some(edns));
    assert!(
        fixture.check("edns-options", &request, Transport::Udp),
        "edns-options: expected hot path"
    );
}

#[test]
fn truncation_and_tcp_match() {
    let mut fixture = Fixture::new(zone());
    let request = query("big.example.com", Rtype::TXT);
    assert!(fixture.check("txt-512", &request, Transport::Udp));

    let request = edns_query("big.example.com", Rtype::TXT, EDNS_1232, false);
    assert!(fixture.check("txt-1232", &request, Transport::Udp));

    let request = query("big.example.com", Rtype::TXT);
    assert!(fixture.check("txt-tcp", &request, Transport::Tcp));
}

#[test]
fn non_hot_queries_fall_back() {
    let mut fixture = Fixture::new(zone());
    for (label, request) in [
        ("dname", query("host.dname.example.com", Rtype::A)),
        ("transfer", query("example.com", Rtype::AXFR)),
        ("outside", query("example.org", Rtype::A)),
    ] {
        assert!(
            !fixture.check(label, &request, Transport::Udp),
            "{label}: must use the full path"
        );
    }
}

#[test]
fn referral_and_any_use_hot_path() {
    let mut fixture = Fixture::new(zone());
    for (label, request) in [
        ("delegation", query("sub.example.com", Rtype::A)),
        ("below-cut", query("deep.sub.example.com", Rtype::A)),
        ("any", query("www.example.com", Rtype::ANY)),
        ("any-alias", query("alias.example.com", Rtype::ANY)),
        (
            "do-bit",
            edns_query("www.example.com", Rtype::A, EDNS_1232, true),
        ),
    ] {
        assert!(
            fixture.check(label, &request, Transport::Udp),
            "{label}: expected hot path"
        );
    }
}

#[test]
fn edns_badvers_falls_back() {
    use pulse_dns::{Edns, Question};

    let mut fixture = Fixture::new(zone());
    let mut request = Message::query(
        0x4321,
        Question::new(
            common::name("www.example.com"),
            Rtype::A,
            pulse_dns::Rclass::IN,
        ),
    );
    request.set_edns(Some(Edns::new(EDNS_1232).with_version(1)));
    assert!(
        !fixture.check("badvers", &request, Transport::Udp),
        "BADVERS must stay on the full path"
    );
    let response = fixture
        .engine
        .respond(&request, Transport::Udp)
        .encode(&EncodeOptions::compressed())
        .expect("badvers encode");
    let decoded = Message::decode(&response, &DecodeLimits::default()).expect("decode");
    assert_eq!(decoded.rcode(), Rcode::BADVERS);
}

proptest::proptest! {
    #[test]
    fn fast_path_never_diverges_from_full_path(
        labels in proptest::collection::vec(
            proptest::sample::select(vec![
                "a", "b", "www", "mail", "wild", "x", "deep", "sub", "nope", "chain1", "alias",
            ]),
            1..4,
        ),
        type_index in 0_usize..10,
        with_edns in proptest::bool::ANY,
    ) {
        let qname = format!("{}.example.com", labels.join("."));
        let qtype = [
            Rtype::A,
            Rtype::AAAA,
            Rtype::MX,
            Rtype::TXT,
            Rtype::SRV,
            Rtype::CNAME,
            Rtype::NS,
            Rtype::SOA,
            Rtype::DS,
            Rtype::HTTPS,
        ][type_index];
        let mut fixture = Fixture::new(zone());
        let mut request = query(&qname, qtype);
        if with_edns {
            request.set_edns(Some(pulse_dns::Edns::new(512)));
        }
        let wire = request.encode(&EncodeOptions::compressed()).expect("encode");
        let parsed = MessageRef::decode_simple_edns(&wire).expect("simple");
        let fast = fixture.engine.respond_ref_into(
            &parsed,
            Transport::Udp,
            &mut fixture.fast,
            &mut fixture.fast_scratch,
        );
        if let Some(len) = fast {
            let legacy_len = fixture.engine
                .respond_into(&request, Transport::Udp, &mut fixture.legacy, &mut fixture.legacy_scratch)
                .expect("streaming");
            proptest::prop_assert_eq!(&fixture.fast[..len], &fixture.legacy[..legacy_len],
                "{} {}", qname, qtype);
        }
    }
}

/// Зона, отдающая заимствованные `RRset` в wire-форме — как v2-адаптер.
///
/// Полный путь читает те же данные из `InMemoryZone` в доменной форме, поэтому
/// сравнение байтов проверяет, что zero-copy кодирование RDATA из payload'а
/// совпадает с кодированием из `Rdata`.
struct WireZone {
    inner: InMemoryZone,
    payloads: HashMap<(Vec<u8>, u16), (Ttl, Vec<u8>)>,
}

impl WireZone {
    fn new(origin: &str) -> Self {
        Self {
            inner: InMemoryZone::new(name(origin)),
            payloads: HashMap::new(),
        }
    }

    fn insert(&mut self, rrset: Rrset) {
        let key = (rrset.owner().as_wire().to_vec(), rrset.rr_type().as_u16());
        let mut payload = Vec::new();
        for rdata in rrset.rdatas() {
            let wire = rdata.to_canonical_wire();
            payload.extend_from_slice(
                &u16::try_from(wire.len())
                    .expect("rdata length")
                    .to_be_bytes(),
            );
            payload.extend_from_slice(&wire);
        }
        self.payloads.insert(key, (rrset.ttl(), payload));
        self.inner.insert(rrset).expect("insert");
    }

    fn wire_ref<'a>(&'a self, owner: NameRef<'a>, rr_type: Rtype) -> Option<RrsetRef<'a>> {
        let key = (owner.as_wire().to_vec(), rr_type.as_u16());
        let (ttl, payload) = self.payloads.get(&key)?;
        Some(RrsetRef::from_wire(
            owner,
            rr_type,
            Rclass::IN,
            *ttl,
            payload,
        ))
    }
}

impl ZoneView for WireZone {
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

    fn state(&self) -> ZoneState {
        self.inner.state()
    }

    fn lookup(&self, name: &Name, rr_type: Rtype) -> LookupOutcome {
        self.inner.lookup(name, rr_type)
    }

    fn lookup_all_rrsig(&self, name: &Name, covered: Rtype) -> Vec<Rrset> {
        self.inner.lookup_all_rrsig(name, covered)
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

    fn with_snapshot(&self, f: &mut dyn FnMut(&dyn ZoneSnapshot)) -> bool {
        f(self);
        true
    }
}

impl ZoneSnapshot for WireZone {
    fn origin_ref(&self) -> NameRef<'_> {
        NameRef::from_name(self.inner.origin())
    }

    fn class_ref(&self) -> Rclass {
        Rclass::IN
    }

    fn lookup_ref<'a>(&'a self, owner: NameRef<'a>, rr_type: Rtype) -> LookupOutcomeRef<'a> {
        if let Some(rrset) = self.wire_ref(owner, rr_type) {
            return LookupOutcomeRef::Answer(rrset);
        }
        if rr_type != Rtype::CNAME
            && let Some(cname) = self.wire_ref(owner, Rtype::CNAME)
            && let Some(RdataRef::Wire { bytes, .. }) = cname.first_record()
            && let Some(target) = wire_name(bytes, 0)
        {
            return LookupOutcomeRef::Cname(cname, target);
        }
        if self.node_exists_ref(owner) {
            LookupOutcomeRef::NoData
        } else {
            LookupOutcomeRef::NxDomain
        }
    }

    fn soa_ref(&self) -> Option<RrsetRef<'_>> {
        self.wire_ref(NameRef::from_name(self.inner.origin()), Rtype::SOA)
    }

    fn ns_ref(&self) -> Option<RrsetRef<'_>> {
        self.wire_ref(NameRef::from_name(self.inner.origin()), Rtype::NS)
    }

    fn records_ref<'a>(&'a self, _owner: NameRef<'a>) -> Vec<RrsetRef<'a>> {
        Vec::new()
    }

    fn lookup_all_ref<'b, 's: 'b>(
        &'s self,
        owner: NameRef<'b>,
        rr_type: Rtype,
    ) -> Vec<RrsetRef<'b>> {
        self.wire_ref(owner, rr_type).into_iter().collect()
    }

    fn glue_ref<'a>(&'a self, owner: NameRef<'a>) -> Vec<RrsetRef<'a>> {
        [Rtype::A, Rtype::AAAA]
            .into_iter()
            .filter_map(|rr_type| self.wire_ref(owner, rr_type))
            .collect()
    }

    fn node_exists_ref(&self, owner: NameRef<'_>) -> bool {
        owner
            .to_name()
            .is_ok_and(|name| self.inner.node_exists(&name))
    }

    fn is_delegation_ref(&self, owner: NameRef<'_>) -> bool {
        owner
            .to_name()
            .is_ok_and(|name| self.inner.is_delegation(&name))
    }
}

fn wire_name(bytes: &[u8], offset: usize) -> Option<NameRef<'_>> {
    let mut end = offset;
    loop {
        let length = *bytes.get(end)?;
        if length == 0 {
            end = end.checked_add(1)?;
            break;
        }
        if length & 0xC0 != 0 {
            return None;
        }
        end = end.checked_add(1 + usize::from(length))?;
        if end > bytes.len() {
            return None;
        }
    }
    NameRef::from_wire(bytes.get(offset..end)?).ok()
}

#[allow(clippy::too_many_lines)]
fn wire_zone() -> WireZone {
    let mut zone = WireZone::new("example.com");
    zone.insert(common::soa_example());
    zone.insert(rrset(
        "example.com",
        Rtype::NS,
        3600,
        [Rdata::Ns(name("ns1.example.com"))],
    ));
    zone.insert(rrset(
        "ns1.example.com",
        Rtype::A,
        3600,
        [Rdata::A("192.0.2.1".parse().expect("ipv4"))],
    ));
    zone.insert(rrset(
        "www.example.com",
        Rtype::A,
        300,
        [Rdata::A("192.0.2.20".parse().expect("ipv4"))],
    ));
    zone.insert(rrset(
        "www.example.com",
        Rtype::AAAA,
        300,
        [Rdata::Aaaa("2001:db8::20".parse().expect("ipv6"))],
    ));
    zone.insert(rrset(
        "example.com",
        Rtype::MX,
        600,
        [
            Rdata::Mx {
                preference: 10,
                exchange: name("mail.example.com"),
            },
            Rdata::Mx {
                preference: 20,
                exchange: name("mx.outside.test"),
            },
        ],
    ));
    zone.insert(rrset(
        "mail.example.com",
        Rtype::A,
        300,
        [Rdata::A("192.0.2.30".parse().expect("ipv4"))],
    ));
    zone.insert(rrset(
        "txt.example.com",
        Rtype::TXT,
        300,
        [Rdata::Txt(
            pulse_dns::TxtData::new([b"hello".to_vec(), b"world".to_vec()]).expect("txt"),
        )],
    ));
    zone.insert(rrset(
        "_sip._tcp.example.com",
        Rtype::SRV,
        300,
        [Rdata::Srv {
            priority: 10,
            weight: 5,
            port: 5060,
            target: name("sip.example.com"),
        }],
    ));
    zone.insert(rrset(
        "sip.example.com",
        Rtype::A,
        300,
        [Rdata::A("192.0.2.70".parse().expect("ipv4"))],
    ));
    zone.insert(rrset(
        "svc.example.com",
        Rtype::SVCB,
        300,
        [Rdata::Svcb(
            pulse_dns::SvcbData::new(1, name("svc-target.example.com"), Vec::new()).expect("svcb"),
        )],
    ));
    zone.insert(rrset(
        "svc-target.example.com",
        Rtype::A,
        300,
        [Rdata::A("192.0.2.71".parse().expect("ipv4"))],
    ));
    zone.insert(rrset(
        "https.example.com",
        Rtype::HTTPS,
        300,
        [Rdata::Https(
            pulse_dns::SvcbData::new(1, name("https-target.example.com"), Vec::new())
                .expect("https"),
        )],
    ));
    zone.insert(rrset(
        "https-target.example.com",
        Rtype::AAAA,
        300,
        [Rdata::Aaaa("2001:db8::71".parse().expect("ipv6"))],
    ));
    zone.insert(rrset(
        "alias.example.com",
        Rtype::CNAME,
        120,
        [Rdata::Cname(name("www.example.com"))],
    ));
    zone.insert(rrset(
        "c1.example.com",
        Rtype::CNAME,
        120,
        [Rdata::Cname(name("c2.example.com"))],
    ));
    zone.insert(rrset(
        "c2.example.com",
        Rtype::CNAME,
        120,
        [Rdata::Cname(name("www.example.com"))],
    ));
    zone.insert(rrset(
        "*.wild.example.com",
        Rtype::A,
        300,
        [Rdata::A("192.0.2.99".parse().expect("ipv4"))],
    ));
    zone.insert(rrset(
        "wild.example.com",
        Rtype::TXT,
        300,
        [Rdata::Txt(
            pulse_dns::TxtData::new([b"base".to_vec()]).expect("txt"),
        )],
    ));
    zone
}

#[test]
fn wire_backed_zone_matches_owned_path() {
    let mut fixture = Fixture::from_engine(QueryEngine::new(vec![Arc::new(wire_zone())]));
    for (label, qname, qtype) in [
        ("wire-a", "www.example.com", Rtype::A),
        ("wire-aaaa", "www.example.com", Rtype::AAAA),
        ("wire-mx", "example.com", Rtype::MX),
        ("wire-txt", "txt.example.com", Rtype::TXT),
        ("wire-srv", "_sip._tcp.example.com", Rtype::SRV),
        ("wire-svcb", "svc.example.com", Rtype::SVCB),
        ("wire-https", "https.example.com", Rtype::HTTPS),
        ("wire-ns", "example.com", Rtype::NS),
        ("wire-cname", "alias.example.com", Rtype::A),
        ("wire-chain", "c1.example.com", Rtype::A),
        ("wire-wild", "foo.wild.example.com", Rtype::A),
        ("wire-wild-nodata", "foo.wild.example.com", Rtype::AAAA),
        ("wire-nx", "missing.example.com", Rtype::A),
        ("wire-nodata", "www.example.com", Rtype::MX),
        ("wire-apex-soa", "example.com", Rtype::SOA),
    ] {
        let request = query(qname, qtype);
        assert!(
            fixture.check(label, &request, Transport::Udp),
            "{label}: expected hot path"
        );
    }
    let request = edns_query("missing.example.com", Rtype::A, EDNS_1232, false);
    assert!(
        fixture.check("wire-edns-nx", &request, Transport::Udp),
        "wire EDNS NX expected hot path"
    );
    let _ = ttl;
}
