//! Эквивалентность `resolve_into` (wire fast path) и `resolve` (Message path).

mod support;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use pulse_dns::{
    DecodeLimits, Edns, Message, Name, Question, Rclass, Rcode, Rdata, Record, Rtype, Ttl,
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
