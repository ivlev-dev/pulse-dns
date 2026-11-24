//! Blocklist, allowlist, hosts-формат, reload и overrides.

mod support;

use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use pulse_dns::{Name, Rcode, Rtype, Ttl};
use pulse_resolver::{
    BlockResponse, BlocklistConfig, Override, Resolver, ResolverConfig, TimeoutConfig,
};
use support::{HitCounter, MockServer, RawHandler, a, encode, response};

fn upstream() -> (MockServer, Arc<HitCounter>) {
    let hits = HitCounter::new();
    let counter = Arc::clone(&hits);
    let handler: RawHandler = Arc::new(move |request, _tcp| {
        counter.hit();
        let question = request.questions().first()?;
        let mut reply = response(request, Rcode::NOERROR);
        reply.add_answer(a(&question.qname().to_string(), 60, [192, 0, 2, 10]));
        Some(encode(&reply))
    });
    (MockServer::spawn(handler), hits)
}

fn config(server: SocketAddr) -> ResolverConfig {
    let mut config = ResolverConfig::forward(vec![server]);
    config.timeouts = TimeoutConfig {
        per_query: Duration::from_millis(400),
        tcp: Duration::from_millis(600),
        total: Duration::from_secs(2),
    };
    config.retries = 1;
    config.use_0x20 = false;
    config
}

#[test]
fn blocklist_exact_subdomain_wildcard_allowlist_and_hosts() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("blocklist.txt");
    fs::write(
        &path,
        "# hosts-style\n0.0.0.0 exact.test sub.exact.test\n\
         *.wild.test\n\
         ||adblock.test^\n\
         tracked.test\n",
    )
    .unwrap();
    let (server, hits) = upstream();
    let mut config = config(server.address());
    config.blocklist = BlocklistConfig {
        path: Some(path),
        paths: Vec::new(),
        allowlist: vec!["safe.exact.test".to_owned()],
        response: BlockResponse::NxDomain,
    };
    let resolver = Resolver::new(config).unwrap();

    for blocked in [
        "exact.test",
        "www.exact.test",
        "sub.exact.test",
        "x.wild.test",
        "a.b.wild.test",
        "adblock.test",
        "tracked.test",
    ] {
        let reply = resolver.resolve_qname(&Name::parse(blocked).unwrap(), Rtype::A);
        assert_eq!(reply.rcode(), Rcode::NXDOMAIN, "{blocked} must be blocked");
    }
    assert_eq!(hits.count(), 0, "blocked names must not reach upstream");

    let wildcard_apex = resolver.resolve_qname(&Name::parse("wild.test").unwrap(), Rtype::A);
    assert_eq!(wildcard_apex.rcode(), Rcode::NOERROR);
    assert_eq!(wildcard_apex.answers().len(), 1);

    let allowed = resolver.resolve_qname(&Name::parse("safe.exact.test").unwrap(), Rtype::A);
    assert_eq!(allowed.rcode(), Rcode::NOERROR);
    assert_eq!(allowed.answers().len(), 1);
    assert!(hits.count() >= 1);
}

#[test]
fn null_policy_answers_sinkhole() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("blocklist.txt");
    fs::write(&path, "ads.test\n").unwrap();
    let (server, _hits) = upstream();
    let mut config = config(server.address());
    config.blocklist = BlocklistConfig {
        path: Some(path),
        paths: Vec::new(),
        allowlist: Vec::new(),
        response: BlockResponse::Null {
            ipv4: Ipv4Addr::UNSPECIFIED,
            ipv6: std::net::Ipv6Addr::UNSPECIFIED,
        },
    };
    let resolver = Resolver::new(config).unwrap();
    let reply = resolver.resolve_qname(&Name::parse("ads.test").unwrap(), Rtype::A);
    assert_eq!(reply.rcode(), Rcode::NOERROR);
    assert_eq!(reply.answers().len(), 1);
    assert_eq!(
        reply.answers()[0].rdata(),
        &pulse_dns::Rdata::A(Ipv4Addr::UNSPECIFIED)
    );

    let other = resolver.resolve_qname(&Name::parse("ads.test").unwrap(), Rtype::TXT);
    assert_eq!(other.rcode(), Rcode::NOERROR);
    assert_eq!(other.answers().len(), 0);
}

#[test]
fn blocklist_reload_is_atomic() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("blocklist.txt");
    fs::write(&path, "blocked.test\n").unwrap();
    let (server, hits) = upstream();
    let mut config = config(server.address());
    config.blocklist = BlocklistConfig {
        path: Some(path.clone()),
        paths: Vec::new(),
        allowlist: Vec::new(),
        response: BlockResponse::NxDomain,
    };
    let resolver = Resolver::new(config).unwrap();
    let blocked = Name::parse("blocked.test").unwrap();
    assert_eq!(
        resolver.resolve_qname(&blocked, Rtype::A).rcode(),
        Rcode::NXDOMAIN
    );

    fs::write(&path, "new-blocked.test\n").unwrap();
    let stats = resolver.reload_blocklist(&path).unwrap();
    assert_eq!(stats.blocked, 1);
    let after = resolver.resolve_qname(&blocked, Rtype::A);
    assert_eq!(after.rcode(), Rcode::NOERROR);
    assert_eq!(
        resolver
            .resolve_qname(&Name::parse("new-blocked.test").unwrap(), Rtype::A)
            .rcode(),
        Rcode::NXDOMAIN
    );
    assert!(hits.count() >= 1);
}

#[test]
fn overrides_take_priority_over_blocklist_and_upstream() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("blocklist.txt");
    fs::write(&path, "router.test\n").unwrap();
    let (server, hits) = upstream();
    let mut config = config(server.address());
    config.blocklist = BlocklistConfig {
        path: Some(path),
        paths: Vec::new(),
        allowlist: Vec::new(),
        response: BlockResponse::NxDomain,
    };
    config.overrides.push(Override::a(
        Name::parse("router.test").unwrap(),
        Ttl::new(60).unwrap(),
        Ipv4Addr::new(192, 168, 1, 1),
    ));
    let resolver = Resolver::new(config).unwrap();
    let reply = resolver.resolve_qname(&Name::parse("router.test").unwrap(), Rtype::A);
    assert_eq!(reply.rcode(), Rcode::NOERROR);
    assert_eq!(reply.answers().len(), 1);
    assert_eq!(
        reply.answers()[0].rdata(),
        &pulse_dns::Rdata::A(Ipv4Addr::new(192, 168, 1, 1))
    );
    assert_eq!(hits.count(), 0, "override must not call upstream");
    assert_eq!(resolver.stats().overridden, 1);
}
