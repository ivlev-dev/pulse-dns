//! Эквивалентность `resolve_into` (wire fast path) и `resolve` (Message path).

mod support;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use pulse_dns::{
    DecodeLimits, Edns, EncodeOptions, Message, MessageRef, Name, Question, Rclass, Rcode, Rdata,
    Record, Rtype, Ttl,
};
use pulse_resolver::{Resolver, ResolverConfig, TimeoutConfig};
use support::{MockServer, RawHandler, a, encode, response, soa};

fn config(server: SocketAddr) -> ResolverConfig {
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

fn query(name: &str) -> Message {
    Message::query(
        0x4321,
        Question::new(Name::parse(name).unwrap(), Rtype::A, Rclass::IN),
    )
}

fn decode(bytes: &[u8], len: usize) -> Message {
    Message::decode(&bytes[..len], &DecodeLimits::default()).unwrap()
}

fn assert_equivalent(left: &Message, right: &Message) {
    assert_eq!(left.rcode(), right.rcode());
    assert_eq!(left.flags().ad(), right.flags().ad());
    assert_eq!(left.answers().len(), right.answers().len());
    assert_eq!(left.authority().len(), right.authority().len());
    for (a, b) in left.answers().iter().zip(right.answers()) {
        assert_eq!(a.owner(), b.owner());
        assert_eq!(a.rr_type(), b.rr_type());
        assert_eq!(a.rdata(), b.rdata());
    }
    for (a, b) in left.authority().iter().zip(right.authority()) {
        assert_eq!(a.owner(), b.owner());
        assert_eq!(a.rr_type(), b.rr_type());
        assert_eq!(a.rdata(), b.rdata());
    }
}

#[test]
fn cache_hit_into_matches_message_path() {
    let handler: RawHandler = Arc::new(|request, _tcp| {
        let mut reply = response(request, Rcode::NOERROR);
        reply.add_answer(a("example.com", 60, [192, 0, 2, 1]));
        Some(encode(&reply))
    });
    let server = MockServer::spawn(handler);
    let resolver = Resolver::new(config(server.address())).unwrap();
    let request = query("example.com");

    assert_eq!(resolver.resolve(&request).rcode(), Rcode::NOERROR);
    let message = resolver.resolve(&request);
    let hits_before = resolver.stats().cache.hits;
    let mut out = [0_u8; 512];
    let len = resolver.resolve_into(&request, &mut out).unwrap();
    let wire = decode(&out, len);
    assert_equivalent(&message, &wire);
    assert!(
        resolver.stats().cache.hits > hits_before,
        "wire path must actually hit the cache"
    );
}

#[test]
fn negative_answer_uses_wire_fast_path() {
    let handler: RawHandler = Arc::new(|request, _tcp| {
        let mut reply = response(request, Rcode::NXDOMAIN);
        reply.add_authority(soa("example.com", 300, 30));
        Some(encode(&reply))
    });
    let server = MockServer::spawn(handler);
    let resolver = Resolver::new(config(server.address())).unwrap();
    let request = query("missing.example.com");

    assert_eq!(resolver.resolve(&request).rcode(), Rcode::NXDOMAIN);
    let message = resolver.resolve(&request);
    let mut out = [0_u8; 512];
    let len = resolver.resolve_into(&request, &mut out).unwrap();
    let wire = decode(&out, len);
    assert_eq!(wire.rcode(), Rcode::NXDOMAIN);
    assert_equivalent(&message, &wire);
}

#[test]
fn edns_is_echoed_on_wire_fast_path() {
    let handler: RawHandler = Arc::new(|request, _tcp| {
        let mut reply = response(request, Rcode::NOERROR);
        reply.add_answer(a("edns.example", 60, [198, 51, 100, 7]));
        Some(encode(&reply))
    });
    let server = MockServer::spawn(handler);
    let resolver = Resolver::new(config(server.address())).unwrap();
    let mut request = query("edns.example");
    request.set_edns(Some(Edns::new(4096).with_dnssec_ok(true)));

    assert_eq!(resolver.resolve(&request).rcode(), Rcode::NOERROR);
    let message = resolver.resolve(&request);
    let mut out = [0_u8; 512];
    let len = resolver.resolve_into(&request, &mut out).unwrap();
    let wire = decode(&out, len);
    assert_equivalent(&message, &wire);
    let edns = wire.edns().expect("OPT must be echoed");
    assert_eq!(edns.udp_payload_size(), 1232);
    assert!(edns.dnssec_ok());
}

#[test]
fn cname_chain_falls_back_and_stays_equivalent() {
    let handler: RawHandler = Arc::new(|request, _tcp| {
        let question = request.questions().first()?;
        let mut reply = response(request, Rcode::NOERROR);
        if question.qname() == &Name::parse("alias.example").unwrap() {
            reply.add_answer(
                Record::new(
                    Name::parse("alias.example").unwrap(),
                    Rtype::CNAME,
                    Rclass::IN,
                    Ttl::new(60).unwrap(),
                    Rdata::Cname(Name::parse("target.example").unwrap()),
                )
                .unwrap(),
            );
            reply.add_answer(a("target.example", 60, [203, 0, 113, 5]));
        } else {
            reply.add_answer(a("target.example", 60, [203, 0, 113, 5]));
        }
        Some(encode(&reply))
    });
    let server = MockServer::spawn(handler);
    let resolver = Resolver::new(config(server.address())).unwrap();
    let request = query("alias.example");

    assert_eq!(resolver.resolve(&request).rcode(), Rcode::NOERROR);
    let message = resolver.resolve(&request);
    let mut out = [0_u8; 512];
    let len = resolver.resolve_into(&request, &mut out).unwrap();
    let wire = decode(&out, len);
    assert_eq!(wire.answers().len(), 2);
    assert_equivalent(&message, &wire);
}

fn ref_of(request: &Message) -> Vec<u8> {
    request
        .encode(&EncodeOptions::compressed())
        .expect("encode query")
}

#[test]
fn ref_into_cache_hit_matches_message_path_bytes() {
    let handler: RawHandler = Arc::new(|request, _tcp| {
        let mut reply = response(request, Rcode::NOERROR);
        reply.add_answer(a("bytes.example", 60, [192, 0, 2, 44]));
        Some(encode(&reply))
    });
    let server = MockServer::spawn(handler);
    let resolver = Resolver::new(config(server.address())).unwrap();
    let request = query("bytes.example");
    assert_eq!(resolver.resolve(&request).rcode(), Rcode::NOERROR);

    // Старый путь: Message + компрессия.
    let mut legacy = [0_u8; 512];
    let legacy_len = resolver.resolve(&request).encode_into(&mut legacy).unwrap();

    // Wire fast path по Message и по MessageRef.
    let mut message_out = [0_u8; 512];
    let message_len = resolver.resolve_into(&request, &mut message_out).unwrap();
    let query = ref_of(&request);
    let parsed = MessageRef::decode_simple_edns(&query).expect("simple query");
    let mut ref_out = [0_u8; 512];
    let report = resolver.resolve_ref_into(&parsed, &mut ref_out).unwrap();

    assert_eq!(message_len, legacy_len);
    assert_eq!(report.len, legacy_len);
    assert_eq!(&message_out[..message_len], &legacy[..legacy_len]);
    assert_eq!(&ref_out[..report.len], &legacy[..legacy_len]);
    assert!(report.meta.cache_hit);
    assert_eq!(report.meta.answers, 1);
    assert_eq!(report.meta.rcode, Rcode::NOERROR);
    assert!(!report.truncated);
}

#[test]
fn ref_into_reports_nxdomain_meta_and_matches_bytes() {
    let handler: RawHandler = Arc::new(|request, _tcp| {
        let mut reply = response(request, Rcode::NXDOMAIN);
        reply.add_authority(soa("example.com", 300, 30));
        Some(encode(&reply))
    });
    let server = MockServer::spawn(handler);
    let resolver = Resolver::new(config(server.address())).unwrap();
    let request = query("missing.example.com");
    assert_eq!(resolver.resolve(&request).rcode(), Rcode::NXDOMAIN);

    let query = ref_of(&request);
    let parsed = MessageRef::decode_simple_edns(&query).expect("simple query");
    let mut out = [0_u8; 512];
    let report = resolver.resolve_ref_into(&parsed, &mut out).unwrap();
    let decoded = decode(&out, report.len);
    assert_eq!(decoded.rcode(), Rcode::NXDOMAIN);
    assert_eq!(report.meta.rcode, Rcode::NXDOMAIN);
    assert_eq!(report.meta.answers, 0);
    assert!(report.meta.authority_soa);
    assert!(!report.meta.authority_ns);
    assert!(report.meta.cache_hit);
}

#[test]
fn ref_into_limit_truncates_by_client_payload_and_keeps_do() {
    let handler: RawHandler = Arc::new(|request, _tcp| {
        let mut reply = response(request, Rcode::NOERROR);
        for index in 0..30_u8 {
            let text = format!("{index:02}-{}", "x".repeat(100));
            reply.add_answer(
                Record::new(
                    Name::parse("big.example").unwrap(),
                    Rtype::TXT,
                    Rclass::IN,
                    Ttl::new(60).unwrap(),
                    Rdata::Txt(pulse_dns::TxtData::new([text.into_bytes()]).unwrap()),
                )
                .unwrap(),
            );
        }
        Some(encode(&reply))
    });
    let server = MockServer::spawn(handler);
    let resolver = Resolver::new(config(server.address())).unwrap();
    let mut request = query("big.example");
    request.set_edns(Some(Edns::new(4096).with_dnssec_ok(true)));
    assert_eq!(resolver.resolve(&request).rcode(), Rcode::NOERROR);

    let query = ref_of(&request);
    let parsed = MessageRef::decode_simple_edns(&query).expect("simple query");
    let mut out = [0_u8; 512];
    let report = resolver
        .resolve_ref_into_limited(&parsed, &mut out, 512)
        .unwrap();
    assert!(report.truncated);
    assert!(report.len <= 512);
    let decoded = decode(&out, report.len);
    assert!(decoded.flags().tc());
    assert_eq!(decoded.answers().len(), 0);
    let edns = decoded.edns().expect("OPT must survive truncation");
    assert_eq!(edns.udp_payload_size(), 1232);
    assert!(edns.dnssec_ok());
    // Метаданные относятся к полному ответу, а не к усечённому.
    assert_eq!(report.meta.answers, 30);
}

#[test]
fn ref_into_is_concurrency_safe_and_byte_stable() {
    let handler: RawHandler = Arc::new(|request, _tcp| {
        let mut reply = response(request, Rcode::NOERROR);
        reply.add_answer(a("threads.example", 60, [203, 0, 113, 77]));
        Some(encode(&reply))
    });
    let server = MockServer::spawn(handler);
    let resolver = Resolver::new(config(server.address())).unwrap();
    let request = query("threads.example");
    assert_eq!(resolver.resolve(&request).rcode(), Rcode::NOERROR);
    let query = Arc::new(ref_of(&request));
    let expected = {
        let parsed = MessageRef::decode_simple_edns(&query).unwrap();
        let mut out = [0_u8; 512];
        let report = resolver.resolve_ref_into(&parsed, &mut out).unwrap();
        out[..report.len].to_vec()
    };
    let mut threads = Vec::new();
    for _ in 0..8 {
        let resolver = resolver.clone();
        let query = Arc::clone(&query);
        let expected = expected.clone();
        threads.push(std::thread::spawn(move || {
            for _ in 0..2_000 {
                let parsed = MessageRef::decode_simple_edns(&query).unwrap();
                let mut out = [0_u8; 512];
                let report = resolver.resolve_ref_into(&parsed, &mut out).unwrap();
                assert_eq!(&out[..report.len], expected.as_slice());
            }
        }));
    }
    for thread in threads {
        thread.join().unwrap();
    }
}
