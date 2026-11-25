//! Эквивалентность потокового пути (`respond_into`) прежнему (`respond`).
//!
//! Для каждого сценария сравниваются байты wire-формы, а не только декод:
//! компрессия и порядок записей должны совпадать побайтово.

mod common;

use common::{
    big_txt_rrset, edns_query, engine_for, example_engine, example_zone, insert_cname_chain, name,
    query, rrset, soa_for, txt_segments,
};
use pulse_dns::{EncodeOptions, Message, Question, Rdata, Rrset, Rtype, TxtData};
use pulse_dnssec::{Algorithm, PrivateKey};
use pulse_server::LookupOutcome;
use pulse_server::application::{QueryEngine, Scratch, Transport, ZoneView};
use pulse_server::dnssec::{DenialPolicy, KeyRole, Nsec3Config, ZoneSigner, ZoneSigningKey};
use pulse_server::testkit::InMemoryZone;

fn legacy_bytes(engine: &QueryEngine, request: &Message, transport: Transport) -> Vec<u8> {
    engine
        .respond(request, transport)
        .encode(&EncodeOptions::compressed())
        .expect("legacy response encodes")
}

fn streaming_bytes(
    engine: &QueryEngine,
    request: &Message,
    transport: Transport,
    scratch: &mut Scratch,
    capacity: usize,
) -> Vec<u8> {
    let mut out = vec![0_u8; capacity];
    let len = engine
        .respond_into(request, transport, &mut out, scratch)
        .expect("streaming response");
    out.truncate(len);
    out
}

fn assert_same(engine: &QueryEngine, request: &Message, transport: Transport) {
    let mut scratch = Scratch::new();
    let expected = legacy_bytes(engine, request, transport);
    let actual = streaming_bytes(engine, request, transport, &mut scratch, 65_535);
    assert_eq!(
        actual,
        expected,
        "wire mismatch for {:?} {} {:?}",
        transport,
        request
            .questions()
            .first()
            .map_or_else(|| "?".to_owned(), |q| q.qname().to_string()),
        request.questions().first().map(Question::qtype)
    );
}

fn sweep(engine: &QueryEngine) {
    let mut cases: Vec<(String, Rtype)> = vec![
        ("example.com".to_owned(), Rtype::SOA),
        ("example.com".to_owned(), Rtype::NS),
        ("example.com".to_owned(), Rtype::A),
        ("example.com".to_owned(), Rtype::AAAA),
        ("example.com".to_owned(), Rtype::MX),
        ("example.com".to_owned(), Rtype::ANY),
        ("www.example.com".to_owned(), Rtype::A),
        ("txt.example.com".to_owned(), Rtype::TXT),
        ("alias.example.com".to_owned(), Rtype::A),
        ("chain1.example.com".to_owned(), Rtype::A),
        ("external.example.com".to_owned(), Rtype::A),
        ("loop1.example.com".to_owned(), Rtype::A),
        ("missing.example.com".to_owned(), Rtype::A),
        ("foo.wild.example.com".to_owned(), Rtype::A),
        ("foo.wild.example.com".to_owned(), Rtype::TXT),
        ("ent.example.com".to_owned(), Rtype::A),
        ("x.ent.example.com".to_owned(), Rtype::A),
        ("sub.example.com".to_owned(), Rtype::NS),
        ("sub.example.com".to_owned(), Rtype::DS),
        ("deep.sub.example.com".to_owned(), Rtype::A),
        ("host.dname.example.com".to_owned(), Rtype::A),
        ("_sip._tcp.example.com".to_owned(), Rtype::SRV),
        ("svc.example.com".to_owned(), Rtype::SVCB),
        ("https.example.com".to_owned(), Rtype::HTTPS),
        ("outside.test".to_owned(), Rtype::A),
        ("example.com".to_owned(), Rtype::AXFR),
    ];
    for index in 0..20 {
        cases.push((format!("c{index}.example.com"), Rtype::A));
    }
    for (qname, qtype) in cases {
        let plain = query(&qname, qtype);
        assert_same(engine, &plain, Transport::Udp);
        assert_same(engine, &plain, Transport::Tcp);
        for (payload, do_bit) in [(512_u16, false), (1232, false), (4096, true)] {
            let request = edns_query(&qname, qtype, payload, do_bit);
            assert_same(engine, &request, Transport::Udp);
            assert_same(engine, &request, Transport::Tcp);
        }
    }
}

#[test]
fn unsiged_zone_matches_legacy() {
    sweep(&example_engine());
}

#[test]
fn big_rrsets_and_truncation_match_legacy() {
    let mut zone = example_zone();
    zone.insert(big_txt_rrset(30)).expect("big txt");
    zone.insert(rrset(
        "many-a.example.com",
        Rtype::A,
        300,
        (0..4096_u32).map(|index| Rdata::A(std::net::Ipv4Addr::from(0x0A00_0000 + index))),
    ))
    .expect("many a");
    zone.insert(rrset(
        "many-txt.example.com",
        Rtype::TXT,
        300,
        (0..4096_usize).map(|index| {
            Rdata::Txt(TxtData::new([format!("{index:04}-payload").into_bytes()]).expect("txt"))
        }),
    ))
    .expect("many txt");
    let engine = engine_for(zone);

    for (qname, qtype) in [
        ("big.example.com", Rtype::TXT),
        ("many-a.example.com", Rtype::A),
        ("many-txt.example.com", Rtype::TXT),
    ] {
        for request in [
            query(qname, qtype),
            edns_query(qname, qtype, 1232, false),
            edns_query(qname, qtype, 4096, true),
        ] {
            assert_same(&engine, &request, Transport::Udp);
            assert_same(&engine, &request, Transport::Tcp);
        }
    }

    // Точные границы 512/1232: потоковый путь усекает так же, как прежний.
    for (limit, edns) in [(512_u16, None), (1232_u16, Some(1232_u16))] {
        for payload in 0..3000_usize {
            let mut zone = example_zone();
            zone.insert(rrset(
                "txt.example.com",
                Rtype::TXT,
                300,
                [Rdata::Txt(
                    TxtData::new(txt_segments(payload)).expect("txt"),
                )],
            ))
            .expect("txt");
            let engine = engine_for(zone);
            let request = edns.map_or_else(
                || query("txt.example.com", Rtype::TXT),
                |payload| edns_query("txt.example.com", Rtype::TXT, payload, false),
            );
            let mut scratch = Scratch::new();
            let expected = legacy_bytes(&engine, &request, Transport::Udp);
            let actual = streaming_bytes(&engine, &request, Transport::Udp, &mut scratch, 65_535);
            assert_eq!(actual, expected, "limit {limit}, payload {payload}");
            assert!(actual.len() <= usize::from(limit));
            if actual.len() == usize::from(limit) {
                break;
            }
        }
    }
}

#[test]
fn record_over_65535_matches_legacy_servfail() {
    let mut segments = vec![vec![b'x'; 255]; 255];
    segments.push(vec![b'x'; 254]);
    let txt = TxtData::new(segments).expect("65535-byte rdata");
    let mut zone = InMemoryZone::new(name("example.com"));
    zone.insert(soa_for("example.com")).expect("soa");
    zone.insert(rrset(
        "huge.example.com",
        Rtype::TXT,
        300,
        [Rdata::Txt(txt)],
    ))
    .expect("huge txt");
    let engine = engine_for(zone);
    assert_same(
        &engine,
        &query("huge.example.com", Rtype::TXT),
        Transport::Udp,
    );
    assert_same(
        &engine,
        &query("huge.example.com", Rtype::TXT),
        Transport::Tcp,
    );
}

#[allow(clippy::similar_names)]
fn sign_zone(denial: &DenialPolicy, zone: &InMemoryZone) -> InMemoryZone {
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
    let rrsets: Vec<Rrset> = zone_rrsets(zone);
    let signed = signer
        .sign_zone_with(&origin, &rrsets, 1_700_000_000, denial)
        .expect("sign zone");
    let mut out = InMemoryZone::new(origin);
    for rrset in signed.rrsets {
        out.insert(rrset).expect("signed rrset");
    }
    out
}

fn zone_rrsets(zone: &InMemoryZone) -> Vec<Rrset> {
    let mut rrsets = Vec::new();
    for (qname, qtype) in [
        ("example.com", Rtype::SOA),
        ("example.com", Rtype::NS),
        ("example.com", Rtype::A),
        ("www.example.com", Rtype::A),
        ("alias.example.com", Rtype::CNAME),
        ("*.wild.example.com", Rtype::A),
        ("wild.example.com", Rtype::TXT),
        ("sub.example.com", Rtype::NS),
        ("ns1.sub.example.com", Rtype::A),
        ("big.example.com", Rtype::TXT),
    ] {
        if let LookupOutcome::Answer(rrset) = zone.lookup(&name(qname), qtype) {
            rrsets.push(rrset);
        }
    }
    rrsets
}

#[test]
fn signed_zone_matches_legacy() {
    let mut base = example_zone();
    insert_cname_chain(&mut base, 3);
    base.insert(big_txt_rrset(30)).expect("big txt");
    for denial in [
        DenialPolicy::Nsec,
        DenialPolicy::Nsec3(Nsec3Config::new(vec![0xAA, 0xBB], 1).expect("nsec3")),
    ] {
        let zone = sign_zone(&denial, &base);
        let engine = engine_for(zone);
        for (qname, qtype) in [
            ("example.com", Rtype::DNSKEY),
            ("www.example.com", Rtype::A),
            ("txt.example.com", Rtype::TXT),
            ("alias.example.com", Rtype::A),
            ("missing.example.com", Rtype::A),
            ("foo.wild.example.com", Rtype::A),
            ("foo.wild.example.com", Rtype::TXT),
            ("sub.example.com", Rtype::DS),
            ("deep.sub.example.com", Rtype::A),
            ("c1.example.com", Rtype::A),
            ("big.example.com", Rtype::TXT),
        ] {
            for do_bit in [false, true] {
                let request = edns_query(qname, qtype, 1232, do_bit);
                assert_same(&engine, &request, Transport::Udp);
                assert_same(&engine, &request, Transport::Tcp);
            }
        }
    }
}

#[test]
fn streaming_respects_small_caller_buffer() {
    let mut zone = example_zone();
    zone.insert(big_txt_rrset(30)).expect("big txt");
    let engine = engine_for(zone);
    let request = edns_query("big.example.com", Rtype::TXT, 4096, false);
    let mut scratch = Scratch::new();
    let mut out = [0_u8; 512];
    let len = engine
        .respond_into(&request, Transport::Udp, &mut out, &mut scratch)
        .expect("response in small buffer");
    assert!(len <= 512);
    let decoded = Message::decode(&out[..len], &pulse_dns::DecodeLimits::default())
        .expect("decodable response");
    assert!(decoded.flags().tc());
}

#[test]
fn streaming_reuses_scratch_across_queries() {
    let engine = example_engine();
    let request = query("example.com", Rtype::MX);
    let mut scratch = Scratch::new();
    let first = streaming_bytes(&engine, &request, Transport::Udp, &mut scratch, 65_535);
    for _ in 0..64 {
        let next = streaming_bytes(&engine, &request, Transport::Udp, &mut scratch, 65_535);
        assert_eq!(next, first);
    }
}
