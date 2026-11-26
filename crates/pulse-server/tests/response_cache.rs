//! Кеш готовых ответов: попадания, инвалидация, EDNS/DO, 0x20, concurrency.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use common::{edns_query, name, query, rrset};
use pulse_dns::{Edns, EdnsOption, EncodeOptions, Message, MessageRef, Rdata, Rrset, Rtype};
use pulse_dnssec::{Algorithm, PrivateKey};
use pulse_server::application::{
    EngineConfig, QueryEngine, QueryStats, ResponseCache, ResponseCacheConfig, Scratch, Transport,
};
use pulse_server::dnssec::{DenialPolicy, KeyRole, ZoneSigner, ZoneSigningKey};
use pulse_server::testkit::InMemoryZone;

const EDNS_1232: u16 = 1232;

fn cache(max_entries: usize) -> Arc<ResponseCache> {
    Arc::new(ResponseCache::new(ResponseCacheConfig {
        enabled: true,
        max_entries,
        max_bytes: 8 * 1024 * 1024,
        shards: 4,
    }))
}

fn cached_engine(zone: InMemoryZone, cache: Arc<ResponseCache>) -> QueryEngine {
    QueryEngine::with_cache(
        vec![Arc::new(zone)],
        Arc::new(QueryStats::new()),
        EngineConfig::default(),
        cache,
    )
}

fn wire_of(request: &Message) -> Vec<u8> {
    request
        .encode(&EncodeOptions::compressed())
        .expect("encode query")
}

fn respond(engine: &QueryEngine, wire: &[u8], transport: Transport) -> Option<Vec<u8>> {
    let parsed = MessageRef::decode_simple_edns(wire)?;
    let mut out = vec![0_u8; 65_535];
    let mut scratch = Scratch::new();
    let len = engine.respond_ref_into(&parsed, transport, &mut out, &mut scratch)?;
    out.truncate(len);
    Some(out)
}

/// Запрос с сохранением регистра `QNAME` (0x20).
fn uppercase_qname(wire: &mut [u8], name_len: usize) {
    for byte in wire.iter_mut().skip(12).take(name_len) {
        if byte.is_ascii_lowercase() {
            *byte = byte.to_ascii_uppercase();
        }
    }
}

#[test]
fn hit_is_byte_identical_and_ttl_not_decremented() {
    let cache = cache(1024);
    let cached = cached_engine(common::example_zone(), Arc::clone(&cache));
    let fresh = common::engine_for(common::example_zone());
    let cases = [
        ("www.example.com.", Rtype::A),
        ("example.com.", Rtype::AAAA),
        ("example.com.", Rtype::MX),
        ("txt.example.com.", Rtype::TXT),
        ("alias.example.com.", Rtype::A),
        ("www.example.com.", Rtype::TXT),
        ("missing.example.com.", Rtype::A),
        ("example.com.", Rtype::SRV),
        ("_sip._tcp.example.com.", Rtype::SRV),
        ("sub.example.com.", Rtype::A),
        ("svc.example.com.", Rtype::HTTPS),
        ("example.com.", Rtype::ANY),
    ];
    for (qname, qtype) in cases {
        for edns in [None, Some((EDNS_1232, false)), Some((EDNS_1232, true))] {
            let mut request = edns.map_or_else(
                || query(qname, qtype),
                |(payload, dnssec_ok)| edns_query(qname, qtype, payload, dnssec_ok),
            );
            request.set_id(0x1111);
            let wire = wire_of(&request);
            let expected = respond(&fresh, &wire, Transport::Udp).expect("fresh response");
            let first = respond(&cached, &wire, Transport::Udp).expect("cached first");
            assert_eq!(first, expected, "{qname} {qtype:?} edns={edns:?}: first");

            request.set_id(0x2222);
            let wire = wire_of(&request);
            let expected = respond(&fresh, &wire, Transport::Udp).expect("fresh response");
            let second = respond(&cached, &wire, Transport::Udp).expect("cached second");
            assert_eq!(
                second, expected,
                "{qname} {qtype:?} edns={edns:?}: cached hit must match fresh bytes"
            );
        }
    }
    let metrics = cache.metrics();
    assert!(metrics.hits > 0, "{metrics:?}");
    assert!(metrics.entries > 0, "{metrics:?}");
}

#[test]
fn qname_case_is_part_of_key() {
    let cache = cache(64);
    let cached = cached_engine(common::example_zone(), Arc::clone(&cache));
    let fresh = common::engine_for(common::example_zone());
    let request = query("www.example.com.", Rtype::A);
    let lower = wire_of(&request);
    let name_len = name("www.example.com.").as_wire().len();
    let mut upper = lower.clone();
    uppercase_qname(&mut upper, name_len);
    assert_ne!(lower, upper);

    let lower_bytes = respond(&cached, &lower, Transport::Udp).expect("lower");
    let upper_bytes = respond(&cached, &upper, Transport::Udp).expect("upper");
    assert_eq!(
        lower_bytes,
        respond(&fresh, &lower, Transport::Udp).expect("fresh")
    );
    assert_eq!(
        upper_bytes,
        respond(&fresh, &upper, Transport::Udp).expect("fresh")
    );

    // Оба варианта — отдельные записи; первые запросы были промахами.
    let after_inserts = cache.metrics();
    assert_eq!(after_inserts.inserts, 2, "{after_inserts:?}");
    let _ = respond(&cached, &lower, Transport::Udp).expect("lower hit");
    let _ = respond(&cached, &upper, Transport::Udp).expect("upper hit");
    let metrics = cache.metrics();
    assert_eq!(metrics.hits, 2, "{metrics:?}");
}

#[test]
fn do_edns_payload_and_cd_are_part_of_key() {
    let cache = cache(64);
    let cached = cached_engine(common::example_zone(), Arc::clone(&cache));
    let fresh = common::engine_for(common::example_zone());
    let mut variants = Vec::new();
    for (payload, dnssec_ok) in [(512, false), (1232, false), (1232, true), (1432, false)] {
        variants.push(edns_query("www.example.com.", Rtype::A, payload, dnssec_ok));
    }
    variants.push(query("www.example.com.", Rtype::A));
    let mut cd = query("www.example.com.", Rtype::A);
    cd.set_flags(cd.flags().with_cd(true));
    variants.push(cd);

    for request in &variants {
        let wire = wire_of(request);
        let expected = respond(&fresh, &wire, Transport::Udp).expect("fresh");
        assert_eq!(
            respond(&cached, &wire, Transport::Udp).expect("first"),
            expected
        );
    }
    // Все варианты попали в разные записи (payload >1232 нормализуется к 1232);
    // повтор каждого варианта — попадание.
    let inserts = cache.metrics().inserts;
    let hits_before = cache.metrics().hits;
    for request in &variants {
        let wire = wire_of(request);
        let expected = respond(&fresh, &wire, Transport::Udp).expect("fresh");
        assert_eq!(
            respond(&cached, &wire, Transport::Udp).expect("second"),
            expected
        );
    }
    let metrics = cache.metrics();
    assert_eq!(
        metrics.inserts, inserts,
        "no new entries for cached variants"
    );
    assert_eq!(
        metrics.hits - hits_before,
        variants.len() as u64,
        "{metrics:?}"
    );
}

#[test]
fn nxdomain_and_nodata_hit_and_counters_stay_consistent() {
    let cache = cache(64);
    let stats = Arc::new(QueryStats::new());
    let engine = QueryEngine::with_cache(
        vec![Arc::new(common::example_zone())],
        Arc::clone(&stats),
        EngineConfig::default(),
        Arc::clone(&cache),
    );
    for _ in 0..2 {
        let wire = wire_of(&query("missing.example.com.", Rtype::A));
        let response = respond(&engine, &wire, Transport::Udp).expect("nxdomain");
        let decoded = Message::decode(&response, &pulse_dns::DecodeLimits::default())
            .expect("decode nxdomain");
        assert_eq!(decoded.rcode(), pulse_dns::Rcode::NXDOMAIN);
    }
    for _ in 0..2 {
        let wire = wire_of(&query("www.example.com.", Rtype::AAAA));
        let response = respond(&engine, &wire, Transport::Udp).expect("nodata");
        let decoded =
            Message::decode(&response, &pulse_dns::DecodeLimits::default()).expect("decode nodata");
        assert_eq!(decoded.rcode(), pulse_dns::Rcode::NOERROR);
        assert_eq!(decoded.answers(), []);
    }
    let snapshot = stats.snapshot();
    assert_eq!(snapshot.nxdomain, 2, "{snapshot:?}");
    assert_eq!(snapshot.nodata, 2, "{snapshot:?}");
    assert!(cache.metrics().hits >= 2, "{:?}", cache.metrics());
}

#[test]
fn truncated_and_servfail_are_not_cached() {
    let cache = cache(64);
    let mut zone = common::example_zone();
    zone.insert(common::big_txt_rrset(40)).expect("big txt");
    let engine = cached_engine(zone, Arc::clone(&cache));

    let wire = wire_of(&query("big.example.com.", Rtype::TXT));
    let first = respond(&engine, &wire, Transport::Udp).expect("truncated");
    let second = respond(&engine, &wire, Transport::Udp).expect("truncated");
    assert_eq!(first, second);
    let metrics = cache.metrics();
    assert_eq!(metrics.inserts, 0, "truncated responses must not be cached");
    assert_eq!(metrics.hits, 0, "{metrics:?}");

    let loop_wire = wire_of(&query("loop1.example.com.", Rtype::A));
    let _ = respond(&engine, &loop_wire, Transport::Udp).expect("servfail");
    let _ = respond(&engine, &loop_wire, Transport::Udp).expect("servfail");
    let metrics = cache.metrics();
    assert_eq!(metrics.inserts, 0, "SERVFAIL must not be cached");
    assert_eq!(metrics.hits, 0, "{metrics:?}");
}

#[test]
fn edns_options_are_not_cached() {
    let cache = cache(64);
    let engine = cached_engine(common::example_zone(), Arc::clone(&cache));
    let mut request = edns_query("www.example.com.", Rtype::A, EDNS_1232, false);
    let mut edns = Edns::new(EDNS_1232);
    edns.push_option(EdnsOption::new(10, vec![0xAA; 8]).expect("cookie"))
        .expect("push option");
    request.set_edns(Some(edns));
    let wire = wire_of(&request);
    let first = respond(&engine, &wire, Transport::Udp).expect("first");
    let second = respond(&engine, &wire, Transport::Udp).expect("second");
    assert_eq!(first, second);
    let metrics = cache.metrics();
    assert_eq!(metrics.inserts, 0, "{metrics:?}");
    assert_eq!(metrics.hits, 0, "{metrics:?}");
}

#[test]
fn zone_version_change_invalidates_entries() {
    let cache = cache(64);
    let zone = Arc::new(common::example_zone());
    let engine = QueryEngine::with_cache(
        vec![zone.clone()],
        Arc::new(QueryStats::new()),
        EngineConfig::default(),
        Arc::clone(&cache),
    );
    let wire = wire_of(&query("www.example.com.", Rtype::A));
    let first = respond(&engine, &wire, Transport::Udp).expect("first");
    let second = respond(&engine, &wire, Transport::Udp).expect("second");
    assert_eq!(first, second);
    assert_eq!(cache.metrics().hits, 1);

    zone.set_cache_version(zone.cache_version() + 1);
    let third = respond(&engine, &wire, Transport::Udp).expect("third");
    assert_eq!(
        first, third,
        "version bump must not alter deterministic bytes"
    );
    let metrics = cache.metrics();
    assert_eq!(metrics.hits, 1, "old entry must not be served: {metrics:?}");
    assert_eq!(metrics.misses, 2, "{metrics:?}");
    assert_eq!(metrics.inserts, 2, "{metrics:?}");
}

#[test]
fn memory_bound_holds_under_many_names() {
    let cache = cache(8);
    let mut zone = common::example_zone();
    for index in 0..200_u16 {
        let owner = format!("n{index}.example.com.");
        zone.insert(
            Rrset::new(
                name(&owner),
                Rtype::A,
                pulse_dns::Rclass::IN,
                common::ttl(60),
                [Rdata::A(std::net::Ipv4Addr::from(
                    0x0A00_0000 | u32::from(index),
                ))],
            )
            .expect("rrset"),
        )
        .expect("insert");
    }
    let engine = cached_engine(zone, Arc::clone(&cache));
    for index in 0..200_u16 {
        let wire = wire_of(&query(&format!("n{index}.example.com."), Rtype::A));
        respond(&engine, &wire, Transport::Udp).expect("response");
    }
    let metrics = cache.metrics();
    assert!(metrics.entries <= 8, "{metrics:?}");
    assert!(metrics.evictions > 0, "{metrics:?}");
    assert!(metrics.bytes <= 8 * 1024 * 1024, "{metrics:?}");
}

#[test]
fn hundred_concurrent_readers_see_consistent_bytes() {
    let cache = cache(4096);
    let cached = Arc::new(cached_engine(common::example_zone(), Arc::clone(&cache)));
    let fresh = Arc::new(common::engine_for(common::example_zone()));
    let cases: Arc<Vec<(&'static str, Rtype, Transport)>> = Arc::new(vec![
        ("www.example.com.", Rtype::A, Transport::Udp),
        ("txt.example.com.", Rtype::TXT, Transport::Udp),
        ("example.com.", Rtype::MX, Transport::Udp),
        ("alias.example.com.", Rtype::A, Transport::Udp),
        ("missing.example.com.", Rtype::A, Transport::Udp),
        ("sub.example.com.", Rtype::A, Transport::Udp),
        ("www.example.com.", Rtype::A, Transport::Tcp),
    ]);
    let sequence = Arc::new(AtomicU64::new(0));
    let mut handles = Vec::new();
    for thread in 0..100_u64 {
        let cached = Arc::clone(&cached);
        let fresh = Arc::clone(&fresh);
        let cases = Arc::clone(&cases);
        let sequence = Arc::clone(&sequence);
        handles.push(std::thread::spawn(move || {
            for iteration in 0..40_u64 {
                let id = u16::try_from(thread * 40 + iteration).expect("id");
                let (qname, qtype, transport) = cases
                    .get(usize::try_from((thread + iteration) % 7).expect("index"))
                    .copied()
                    .expect("case");
                let mut request = query(qname, qtype);
                request.set_id(id);
                let wire = wire_of(&request);
                let expected = respond(&fresh, &wire, transport).expect("fresh");
                let actual = respond(&cached, &wire, transport).expect("cached");
                assert_eq!(
                    actual, expected,
                    "thread {thread} iter {iteration}: {qname} {qtype:?}"
                );
                sequence.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }
    for handle in handles {
        handle.join().expect("worker");
    }
    assert_eq!(sequence.load(Ordering::Relaxed), 100 * 40);
    let metrics = cache.metrics();
    assert!(metrics.hits > 0, "{metrics:?}");
    assert_eq!(metrics.hits + metrics.misses, 100 * 40, "{metrics:?}");
}

#[test]
fn signed_answers_are_cached_with_rrsig() {
    let origin = name("signed.test.");
    let base = vec![
        common::soa_for("signed.test."),
        rrset(
            "signed.test.",
            Rtype::NS,
            3600,
            [Rdata::Ns(name("ns1.signed.test."))],
        ),
        rrset(
            "ns1.signed.test.",
            Rtype::A,
            3600,
            [Rdata::A("192.0.2.1".parse().expect("ipv4"))],
        ),
        rrset(
            "www.signed.test.",
            Rtype::A,
            300,
            [Rdata::A("192.0.2.20".parse().expect("ipv4"))],
        ),
    ];
    let signer = ZoneSigner::new(
        vec![
            ZoneSigningKey::new(
                PrivateKey::generate(Algorithm::ED25519).expect("key"),
                KeyRole::Csk,
            )
            .expect("signing key"),
        ],
        86_400,
        300,
    )
    .expect("signer");
    let signed_zone = signer
        .sign_zone_with(&origin, &base, 1_700_000_000, &DenialPolicy::default())
        .expect("sign zone");
    let mut zone = InMemoryZone::new(origin);
    for rrset in &signed_zone.rrsets {
        zone.insert(rrset.clone()).expect("insert");
    }
    let cache = cache(64);
    let fresh = common::engine_for(zone.clone());
    let cached = cached_engine(zone, Arc::clone(&cache));

    let request = edns_query("www.signed.test.", Rtype::A, EDNS_1232, true);
    let wire = wire_of(&request);
    let expected = respond(&fresh, &wire, Transport::Udp).expect("fresh signed");
    let first = respond(&cached, &wire, Transport::Udp).expect("first");
    assert_eq!(first, expected, "first signed response");
    let first_message =
        Message::decode(&first, &pulse_dns::DecodeLimits::default()).expect("decode");
    assert!(
        first_message
            .answers()
            .iter()
            .any(|record| record.rr_type() == Rtype::RRSIG),
        "DO=1 answer must carry RRSIG"
    );
    let second = respond(&cached, &wire, Transport::Udp).expect("second");
    assert_eq!(second, expected, "signed hit must be byte-identical");
    assert_eq!(cache.metrics().hits, 1, "{:?}", cache.metrics());
}
