//! Интеграционные тесты forward-режима: кеш, negative, TC/TCP, EDNS, 0x20.

mod support;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pulse_dns::{Edns, Message, Name, Question, Rclass, Rcode, Rtype};
use pulse_resolver::{Resolver, ResolverConfig, TimeoutConfig};
use support::{HitCounter, MockServer, RawHandler, a, encode, response, soa, uppercase_question};

fn fast_config(server: SocketAddr) -> ResolverConfig {
    let mut config = ResolverConfig::forward(vec![server]);
    config.timeouts = TimeoutConfig {
        per_query: Duration::from_millis(400),
        tcp: Duration::from_millis(600),
        total: Duration::from_secs(2),
    };
    config.retries = 1;
    config.use_0x20 = false;
    config.cache.max_ttl = 300;
    config
}

#[test]
fn resolves_and_serves_from_cache() {
    let hits = HitCounter::new();
    let counter = Arc::clone(&hits);
    let handler: RawHandler = Arc::new(move |request, _tcp| {
        counter.hit();
        let mut reply = response(request, Rcode::NOERROR);
        reply.add_answer(a("example.com", 1, [192, 0, 2, 1]));
        Some(encode(&reply))
    });
    let server = MockServer::spawn(handler);
    let resolver = Resolver::new(fast_config(server.address())).unwrap();
    let name = Name::parse("example.com").unwrap();

    let first = resolver.resolve_qname(&name, Rtype::A);
    assert_eq!(first.rcode(), Rcode::NOERROR);
    assert_eq!(first.answers().len(), 1);
    let second = resolver.resolve_qname(&name, Rtype::A);
    assert_eq!(second.answers().len(), 1);
    assert_eq!(hits.count(), 1, "second answer must come from cache");
    assert!(resolver.stats().cache.hits >= 1);

    resolver.cache().purge();
    std::thread::sleep(Duration::from_millis(1100));
    let third = resolver.resolve_qname(&name, Rtype::A);
    assert_eq!(third.answers().len(), 1);
    assert!(hits.count() >= 2, "expired entry must be re-fetched");
}

#[test]
fn negative_answer_is_cached_with_soa_ttl() {
    let hits = HitCounter::new();
    let counter = Arc::clone(&hits);
    let handler: RawHandler = Arc::new(move |request, _tcp| {
        counter.hit();
        let mut reply = response(request, Rcode::NXDOMAIN);
        reply.add_authority(soa("example.com", 300, 30));
        Some(encode(&reply))
    });
    let server = MockServer::spawn(handler);
    let resolver = Resolver::new(fast_config(server.address())).unwrap();
    let name = Name::parse("missing.example.com").unwrap();

    let first = resolver.resolve_qname(&name, Rtype::A);
    assert_eq!(first.rcode(), Rcode::NXDOMAIN);
    assert_eq!(first.authority().len(), 1);
    assert!(first.authority()[0].ttl().as_u32() <= 30);

    let second = resolver.resolve_qname(&name, Rtype::AAAA);
    assert_eq!(second.rcode(), Rcode::NXDOMAIN);
    assert_eq!(hits.count(), 1, "NXDOMAIN should cover other types");
}

#[test]
fn nodata_is_cached_as_negative() {
    let hits = HitCounter::new();
    let counter = Arc::clone(&hits);
    let handler: RawHandler = Arc::new(move |request, _tcp| {
        counter.hit();
        let mut reply = response(request, Rcode::NOERROR);
        reply.add_authority(soa("example.com", 300, 45));
        Some(encode(&reply))
    });
    let server = MockServer::spawn(handler);
    let resolver = Resolver::new(fast_config(server.address())).unwrap();
    let name = Name::parse("empty.example.com").unwrap();

    let first = resolver.resolve_qname(&name, Rtype::A);
    assert_eq!(first.rcode(), Rcode::NOERROR);
    assert_eq!(first.answers().len(), 0);
    assert_eq!(first.authority().len(), 1);
    assert!(first.authority()[0].ttl().as_u32() <= 45);

    let second = resolver.resolve_qname(&name, Rtype::A);
    assert_eq!(second.rcode(), Rcode::NOERROR);
    assert_eq!(second.answers().len(), 0);
    assert_eq!(second.authority().len(), 1);
    assert_eq!(hits.count(), 1, "NODATA must be served from negative cache");
}

#[test]
fn tc_bit_triggers_tcp_fallback_and_edns_is_sent() {
    let observed = Arc::new(Mutex::new((0_u16, false)));
    let seen = Arc::clone(&observed);
    let handler: RawHandler = Arc::new(move |request, tcp| {
        if !tcp {
            let mut reply = response(request, Rcode::NOERROR);
            reply.set_flags(reply.flags().with_tc(true));
            return Some(encode(&reply));
        }
        if let Some(edns) = request.edns()
            && let Ok(mut guard) = seen.lock()
        {
            *guard = (edns.udp_payload_size(), edns.dnssec_ok());
        }
        let mut reply = response(request, Rcode::NOERROR);
        reply.add_answer(a("example.com", 60, [192, 0, 2, 9]));
        Some(encode(&reply))
    });
    let server = MockServer::spawn(handler);
    let resolver = Resolver::new(fast_config(server.address())).unwrap();
    let mut request = Message::query(
        7,
        Question::new(Name::parse("example.com").unwrap(), Rtype::A, Rclass::IN),
    );
    request.set_edns(Some(Edns::new(4096).with_dnssec_ok(true)));

    let reply = resolver.resolve(&request);
    assert_eq!(reply.rcode(), Rcode::NOERROR);
    assert_eq!(reply.answers().len(), 1);
    assert!(resolver.stats().upstream.tcp_queries >= 1);
    let (payload, dnssec_ok) = *observed.lock().unwrap();
    assert_eq!(payload, 1232);
    assert!(dnssec_ok);
}

#[test]
fn zero_x_mismatch_falls_back_to_case_insensitive_match() {
    let handler: RawHandler = Arc::new(move |request, _tcp| {
        let mut reply = response(request, Rcode::NOERROR);
        reply.add_answer(a(
            "abcdefghijklmnopqrstuvwxyz.example.com",
            60,
            [192, 0, 2, 7],
        ));
        Some(uppercase_question(encode(&reply)))
    });
    let server = MockServer::spawn(handler);
    let mut config = fast_config(server.address());
    config.use_0x20 = true;
    let resolver = Resolver::new(config).unwrap();
    let reply = resolver.resolve_qname(
        &Name::parse("abcdefghijklmnopqrstuvwxyz.example.com").unwrap(),
        Rtype::A,
    );
    assert_eq!(reply.rcode(), Rcode::NOERROR);
    assert_eq!(reply.answers().len(), 1);
    assert!(resolver.stats().upstream.zero_x_fallbacks >= 1);
}

#[test]
fn timeout_becomes_servfail() {
    let handler: RawHandler = Arc::new(|_request, _tcp| None);
    let server = MockServer::spawn(handler);
    let mut config = fast_config(server.address());
    config.timeouts.total = Duration::from_millis(600);
    config.timeouts.per_query = Duration::from_millis(150);
    config.retries = 1;
    let resolver = Resolver::new(config).unwrap();
    let reply = resolver.resolve_qname(&Name::parse("example.com").unwrap(), Rtype::A);
    assert_eq!(reply.rcode(), Rcode::SERVFAIL);
    assert!(resolver.stats().servfail >= 1);
    assert!(resolver.stats().upstream.timeouts >= 1);
}
