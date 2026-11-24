//! Интеграционные тесты итеративного режима: делегирование, glue, CNAME.

mod support;

use std::sync::Arc;
use std::time::Duration;

use pulse_dns::{Name, Rcode, Rtype};
use pulse_resolver::{IterativeConfig, Mode, Resolver, ResolverConfig, TimeoutConfig};
use support::{HitCounter, MockServer, RawHandler, a, cname, encode, ns, response, soa};

fn iterative_config(root: std::net::SocketAddr, ns_port: u16) -> ResolverConfig {
    let mut config = ResolverConfig {
        mode: Mode::Iterative(IterativeConfig {
            root_hints: vec![root],
            ns_port,
        }),
        ..ResolverConfig::default()
    };
    config.timeouts = TimeoutConfig {
        per_query: Duration::from_millis(400),
        tcp: Duration::from_millis(600),
        total: Duration::from_secs(2),
    };
    config.retries = 1;
    config.use_0x20 = false;
    config.parallel_ns = 2;
    config
}

#[test]
fn follows_referral_with_glue() {
    let auth_hits = HitCounter::new();
    let auth_counter = Arc::clone(&auth_hits);
    let auth_handler: RawHandler = Arc::new(move |request, _tcp| {
        auth_counter.hit();
        let mut reply = response(request, Rcode::NOERROR);
        reply.add_answer(a("www.example.test", 300, [192, 0, 2, 55]));
        Some(encode(&reply))
    });
    let auth = MockServer::spawn(auth_handler);

    let root_handler: RawHandler = Arc::new(move |request, _tcp| {
        let question = request.questions().first()?;
        if question.qtype() != Rtype::A {
            let mut reply = response(request, Rcode::NOERROR);
            reply.add_authority(soa("test", 300, 60));
            return Some(encode(&reply));
        }
        let mut reply = response(request, Rcode::NOERROR);
        reply.add_authority(ns("example.test", 300, "ns.example.test"));
        reply.add_additional(a("ns.example.test", 300, [127, 0, 0, 1]));
        Some(encode(&reply))
    });
    let root = MockServer::spawn(root_handler);

    let config = iterative_config(root.address(), auth.address().port());
    let resolver = Resolver::new(config).unwrap();
    let reply = resolver.resolve_qname(&Name::parse("www.example.test").unwrap(), Rtype::A);
    assert_eq!(reply.rcode(), Rcode::NOERROR);
    assert_eq!(reply.answers().len(), 1);
    assert!(auth_hits.count() >= 1, "auth server was not queried");
}

#[test]
fn cname_chain_is_followed() {
    let handler: RawHandler = Arc::new(|request, _tcp| {
        let question = request.questions().first()?;
        let mut reply = response(request, Rcode::NOERROR);
        match question.qname().to_string().as_str() {
            "alias.test." => reply.add_answer(cname("alias.test", 300, "target.test")),
            "target.test." => reply.add_answer(a("target.test", 300, [192, 0, 2, 77])),
            _ => return Some(encode(&response(request, Rcode::NXDOMAIN))),
        }
        Some(encode(&reply))
    });
    let server = MockServer::spawn(handler);
    let resolver = Resolver::new(iterative_config(server.address(), 53)).unwrap();
    let reply = resolver.resolve_qname(&Name::parse("alias.test").unwrap(), Rtype::A);
    assert_eq!(reply.rcode(), Rcode::NOERROR);
    assert_eq!(reply.answers().len(), 2);
    assert_eq!(reply.answers()[0].rr_type(), Rtype::CNAME);
    assert_eq!(reply.answers()[1].rr_type(), Rtype::A);
}

#[test]
fn cname_loop_is_servfail() {
    let handler: RawHandler = Arc::new(|request, _tcp| {
        let question = request.questions().first()?;
        let mut reply = response(request, Rcode::NOERROR);
        match question.qname().to_string().as_str() {
            "a.test." => reply.add_answer(cname("a.test", 300, "b.test")),
            "b.test." => reply.add_answer(cname("b.test", 300, "a.test")),
            _ => return Some(encode(&response(request, Rcode::NXDOMAIN))),
        }
        Some(encode(&reply))
    });
    let server = MockServer::spawn(handler);
    let resolver = Resolver::new(iterative_config(server.address(), 53)).unwrap();
    let reply = resolver.resolve_qname(&Name::parse("a.test").unwrap(), Rtype::A);
    assert_eq!(reply.rcode(), Rcode::SERVFAIL);
}

#[test]
fn answer_for_another_name_is_not_accepted() {
    let handler: RawHandler = Arc::new(|request, _tcp| {
        let mut reply = response(request, Rcode::NOERROR);
        reply.add_answer(a("attacker.test", 300, [6, 6, 6, 6]));
        Some(encode(&reply))
    });
    let server = MockServer::spawn(handler);
    let resolver = Resolver::new(iterative_config(server.address(), 53)).unwrap();
    let reply = resolver.resolve_qname(&Name::parse("victim.test").unwrap(), Rtype::A);
    assert_eq!(reply.rcode(), Rcode::SERVFAIL);
    assert_eq!(reply.answers().len(), 0);
}

#[test]
fn cname_chain_limit_is_enforced() {
    let handler: RawHandler = Arc::new(|request, _tcp| {
        let question = request.questions().first()?;
        let label = std::str::from_utf8(question.qname().first_label()?).ok()?;
        let index: u32 = label.strip_prefix('c')?.parse().ok()?;
        let mut reply = response(request, Rcode::NOERROR);
        if index < 20 {
            let target = format!("c{}.test", index + 1);
            reply.add_answer(cname(&question.qname().to_string(), 300, &target));
        } else {
            reply.add_answer(a(&question.qname().to_string(), 300, [192, 0, 2, 99]));
        }
        Some(encode(&reply))
    });
    let server = MockServer::spawn(handler);
    let resolver = Resolver::new(iterative_config(server.address(), 53)).unwrap();
    let reply = resolver.resolve_qname(&Name::parse("c0.test").unwrap(), Rtype::A);
    assert_eq!(reply.rcode(), Rcode::SERVFAIL);
}

#[test]
fn nxdomain_from_authoritative_is_returned() {
    let handler: RawHandler = Arc::new(|request, _tcp| {
        let mut reply = response(request, Rcode::NXDOMAIN);
        reply.add_authority(soa("test", 300, 60));
        Some(encode(&reply))
    });
    let server = MockServer::spawn(handler);
    let resolver = Resolver::new(iterative_config(server.address(), 53)).unwrap();
    let reply = resolver.resolve_qname(&Name::parse("missing.test").unwrap(), Rtype::A);
    assert_eq!(reply.rcode(), Rcode::NXDOMAIN);
    assert_eq!(reply.authority().len(), 1);
    assert_eq!(reply.authority()[0].rr_type(), Rtype::SOA);
}
