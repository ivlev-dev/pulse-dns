//! E2E: forward-режим, кеш, NXDOMAIN, blocklist, overrides, TCP, TC, reload.

mod support;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use pulse_dns::{
    DecodeLimits, EncodeOptions, Message, Name, Rclass, Rcode, Rdata, Record, Rtype, Ttl, TxtData,
};
use pulseresolved::config::{BlockResponseSetting, OverrideSetting};
use pulseresolved::server::Server;
use support::{
    MockUpstream, a_record, base_config, make_query, nxdomain_response, positive_response,
    tcp_query, udp_query, udp_query_raw,
};

const TIMEOUT: Duration = Duration::from_secs(3);

fn record_for(request: &Message, address: [u8; 4]) -> Record {
    let name = request
        .questions()
        .first()
        .map(|question| question.qname().to_string())
        .unwrap_or_default();
    a_record(&name, address, 300)
}

#[test]
fn forward_a_answer_is_cached() {
    let upstream = MockUpstream::start(|request| {
        Some(positive_response(
            request,
            record_for(request, [192, 0, 2, 42]),
        ))
    });
    let config = base_config(upstream.address());
    let server = Server::start(&config).unwrap();
    let addr = server.udp_addr().unwrap();
    let query = make_query("cache.test", Rtype::A, None);

    let first = udp_query(addr, &query, TIMEOUT).expect("first response");
    assert_eq!(first.rcode(), Rcode::NOERROR);
    assert_eq!(first.answers().len(), 1);
    assert_eq!(
        first.answers()[0].rdata(),
        &Rdata::A([192, 0, 2, 42].into())
    );
    assert_eq!(upstream.hits(), 1);

    let second = udp_query(addr, &query, TIMEOUT).expect("cached response");
    assert_eq!(second.answers().len(), 1);
    assert_eq!(upstream.hits(), 1, "cached answer must not reach upstream");
    assert!(server.resolver_stats().cache.hits >= 1);
}

#[test]
fn nxdomain_is_returned_and_negatively_cached() {
    let upstream = MockUpstream::start(|request| Some(nxdomain_response(request, "example.test")));
    let config = base_config(upstream.address());
    let server = Server::start(&config).unwrap();
    let addr = server.udp_addr().unwrap();
    let query = make_query("missing.example.test", Rtype::A, None);

    let first = udp_query(addr, &query, TIMEOUT).expect("nxdomain response");
    assert_eq!(first.rcode(), Rcode::NXDOMAIN);
    assert_eq!(upstream.hits(), 1);
    let second = udp_query(addr, &query, TIMEOUT).expect("cached nxdomain");
    assert_eq!(second.rcode(), Rcode::NXDOMAIN);
    assert_eq!(upstream.hits(), 1, "negative answer must be cached");
}

#[test]
fn blocklist_returns_nxdomain_without_upstream() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("blocklist.txt");
    std::fs::write(&path, "ads.test\n").unwrap();
    let upstream = MockUpstream::start(|request| {
        Some(positive_response(
            request,
            record_for(request, [203, 0, 113, 1]),
        ))
    });
    let mut config = base_config(upstream.address());
    config.blocklist.paths = vec![path];
    let server = Server::start(&config).unwrap();
    let reply = udp_query(
        server.udp_addr().unwrap(),
        &make_query("ads.test", Rtype::A, None),
        TIMEOUT,
    )
    .expect("blocked response");

    assert_eq!(reply.rcode(), Rcode::NXDOMAIN);
    assert_eq!(upstream.hits(), 0);
    assert!(server.resolver_stats().blocked >= 1);
}

#[test]
fn blocklist_null_policy_answers_zero() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("blocklist.txt");
    std::fs::write(&path, "ads.test\n").unwrap();
    let upstream = MockUpstream::start(|request| {
        Some(positive_response(
            request,
            record_for(request, [203, 0, 113, 1]),
        ))
    });
    let mut config = base_config(upstream.address());
    config.blocklist.paths = vec![path];
    config.blocklist.response = BlockResponseSetting::Null;
    let server = Server::start(&config).unwrap();
    let reply = udp_query(
        server.udp_addr().unwrap(),
        &make_query("ads.test", Rtype::A, None),
        TIMEOUT,
    )
    .expect("sinkhole response");

    assert_eq!(reply.rcode(), Rcode::NOERROR);
    assert_eq!(reply.answers().len(), 1);
    assert_eq!(
        reply.answers()[0].rdata(),
        &Rdata::A(std::net::Ipv4Addr::UNSPECIFIED)
    );
    assert_eq!(upstream.hits(), 0);
}

#[test]
fn override_wins_over_blocklist_and_upstream() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("blocklist.txt");
    std::fs::write(&path, "router.test\n").unwrap();
    let upstream = MockUpstream::start(|request| {
        Some(positive_response(
            request,
            record_for(request, [203, 0, 113, 1]),
        ))
    });
    let mut config = base_config(upstream.address());
    config.blocklist.paths = vec![path];
    config.overrides = vec![OverrideSetting {
        name: "router.test".to_owned(),
        ttl: 60,
        a: vec![std::net::Ipv4Addr::new(192, 168, 1, 1)],
        aaaa: Vec::new(),
        cname: None,
    }];
    let server = Server::start(&config).unwrap();
    let reply = udp_query(
        server.udp_addr().unwrap(),
        &make_query("router.test", Rtype::A, None),
        TIMEOUT,
    )
    .expect("override response");

    assert_eq!(reply.rcode(), Rcode::NOERROR);
    assert_eq!(
        reply.answers()[0].rdata(),
        &Rdata::A(std::net::Ipv4Addr::new(192, 168, 1, 1))
    );
    assert_eq!(upstream.hits(), 0);
    assert!(server.resolver_stats().overridden >= 1);
}

#[test]
fn iterative_mode_uses_configured_root_hints() {
    let upstream = MockUpstream::start(|request| {
        Some(positive_response(
            request,
            record_for(request, [198, 51, 100, 7]),
        ))
    });
    let mut config = base_config(upstream.address());
    config.mode = pulseresolved::config::ModeSetting::Iterative;
    config.forwarders.clear();
    config.root_hints = vec![upstream.address()];
    let server = Server::start(&config).unwrap();
    let reply = udp_query(
        server.udp_addr().unwrap(),
        &make_query("iterative.test", Rtype::A, None),
        TIMEOUT,
    )
    .expect("iterative response");
    assert_eq!(reply.rcode(), Rcode::NOERROR);
    assert_eq!(
        reply.answers()[0].rdata(),
        &Rdata::A([198, 51, 100, 7].into())
    );
    assert_eq!(upstream.hits(), 1);
}

#[test]
fn tcp_query_uses_length_prefix() {
    let upstream = MockUpstream::start(|request| {
        Some(positive_response(
            request,
            record_for(request, [192, 0, 2, 7]),
        ))
    });
    let config = base_config(upstream.address());
    let server = Server::start(&config).unwrap();
    let reply = tcp_query(
        server.tcp_addr().unwrap(),
        &make_query("tcp.test", Rtype::A, None),
        TIMEOUT,
    )
    .expect("tcp response");
    assert_eq!(reply.rcode(), Rcode::NOERROR);
    assert_eq!(reply.answers().len(), 1);
    assert!(server.stats().tcp_connections >= 1);
}

#[test]
fn oversized_udp_response_is_truncated_and_edns_raises_limit() {
    let upstream = MockUpstream::start(|request| {
        let owner = Name::parse("big.test").unwrap();
        let mut response = Message::response(request);
        response.set_rcode(Rcode::NOERROR);
        for index in 0..20_u8 {
            let text = format!("{index:02}-{}", "x".repeat(100));
            let record = Record::new(
                owner.clone(),
                Rtype::TXT,
                Rclass::IN,
                Ttl::new(300).unwrap(),
                Rdata::Txt(TxtData::new([text.into_bytes()]).unwrap()),
            )
            .unwrap();
            response.add_answer(record);
        }
        Some(response)
    });
    let config = base_config(upstream.address());
    let server = Server::start(&config).unwrap();
    let addr = server.udp_addr().unwrap();

    let truncated = udp_query(addr, &make_query("big.test", Rtype::TXT, None), TIMEOUT)
        .expect("truncated response");
    assert!(truncated.flags().tc(), "TC must be set for a >512 answer");
    assert_eq!(truncated.answers().len(), 0);

    let full = udp_query(
        addr,
        &make_query("big.test", Rtype::TXT, Some(4096)),
        TIMEOUT,
    )
    .expect("edns response");
    assert!(!full.flags().tc());
    assert_eq!(full.answers().len(), 20);
    assert!(server.stats().truncated >= 1);
}

#[test]
fn edns_is_echoed() {
    let upstream = MockUpstream::start(|request| {
        Some(positive_response(
            request,
            record_for(request, [192, 0, 2, 8]),
        ))
    });
    let config = base_config(upstream.address());
    let server = Server::start(&config).unwrap();
    let reply = udp_query(
        server.udp_addr().unwrap(),
        &make_query("edns.test", Rtype::A, Some(4096)),
        TIMEOUT,
    )
    .expect("edns response");
    let edns = reply.edns().expect("EDNS must be echoed");
    assert!(edns.udp_payload_size() >= 512);
    assert!(!edns.dnssec_ok());
}

#[test]
fn axfr_is_refused_and_garbage_gets_formerr() {
    let upstream = MockUpstream::start(|request| {
        Some(positive_response(
            request,
            record_for(request, [192, 0, 2, 9]),
        ))
    });
    let config = base_config(upstream.address());
    let server = Server::start(&config).unwrap();
    let addr = server.udp_addr().unwrap();

    let transfer = udp_query(
        addr,
        &make_query("example.test", Rtype::AXFR, None),
        TIMEOUT,
    )
    .expect("axfr response");
    assert_eq!(transfer.rcode(), Rcode::REFUSED);
    assert_eq!(upstream.hits(), 0);

    // 12-байтовый заголовок с QDCOUNT=1, но без вопроса: decode → FORMERR.
    let mut broken = vec![0x12, 0x34, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    let reply = udp_query_raw(addr, &broken, Duration::from_secs(2)).expect("formerr");
    assert_eq!(reply.rcode(), Rcode::FORMERR);
    assert_eq!(reply.id(), 0x1234);

    // Слишком короткий пакет молча отбрасывается.
    broken.truncate(5);
    assert!(
        udp_query_raw(addr, &broken, Duration::from_millis(300)).is_none(),
        "5-byte garbage must be dropped"
    );
    assert!(server.stats().formerr >= 1);
    assert!(server.stats().dropped >= 1);
}

#[test]
fn blocklist_reload_swaps_snapshot() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("blocklist.txt");
    std::fs::write(&path, "first.test\n").unwrap();
    let upstream = MockUpstream::start(|request| {
        Some(positive_response(
            request,
            record_for(request, [192, 0, 2, 10]),
        ))
    });
    let mut config = base_config(upstream.address());
    config.blocklist.paths = vec![path.clone()];
    let server = Server::start(&config).unwrap();
    let addr = server.udp_addr().unwrap();

    let blocked = make_query("first.test", Rtype::A, None);
    assert_eq!(
        udp_query(addr, &blocked, TIMEOUT).unwrap().rcode(),
        Rcode::NXDOMAIN
    );
    assert_eq!(upstream.hits(), 0);

    std::fs::write(&path, "second.test\n").unwrap();
    let stats = server.reload_blocklist().unwrap();
    assert_eq!(stats.blocked, 1);
    assert!(server.stats().reloads >= 1);

    assert_eq!(
        udp_query(addr, &blocked, TIMEOUT).unwrap().rcode(),
        Rcode::NOERROR
    );
    assert_eq!(upstream.hits(), 1);
    let newly_blocked = make_query("second.test", Rtype::A, None);
    assert_eq!(
        udp_query(addr, &newly_blocked, TIMEOUT).unwrap().rcode(),
        Rcode::NXDOMAIN
    );
}

#[test]
fn periodic_blocklist_reload_is_applied() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("blocklist.txt");
    std::fs::write(&path, "first.test\n").unwrap();
    let upstream = MockUpstream::start(|request| {
        Some(positive_response(
            request,
            record_for(request, [192, 0, 2, 11]),
        ))
    });
    let mut config = base_config(upstream.address());
    config.blocklist.paths = vec![path.clone()];
    config.blocklist.reload_secs = 1;
    let server = Server::start(&config).unwrap();
    let addr = server.udp_addr().unwrap();
    let query = make_query("first.test", Rtype::A, None);
    assert_eq!(
        udp_query(addr, &query, TIMEOUT).unwrap().rcode(),
        Rcode::NXDOMAIN
    );

    std::fs::write(&path, "other.test\n").unwrap();
    let deadline = Instant::now() + Duration::from_secs(6);
    let mut reloaded = false;
    while Instant::now() < deadline {
        if udp_query(addr, &query, TIMEOUT).is_some_and(|reply| reply.rcode() == Rcode::NOERROR) {
            reloaded = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(
        reloaded,
        "periodic reload must drop the old blocklist entry"
    );
    assert!(server.stats().reloads >= 1);
}

#[test]
fn metrics_and_healthz_are_served_on_loopback() {
    let upstream = MockUpstream::start(|request| {
        Some(positive_response(
            request,
            record_for(request, [192, 0, 2, 12]),
        ))
    });
    let mut config = base_config(upstream.address());
    config.metrics_listen = Some("127.0.0.1:0".parse().unwrap());
    let server = Server::start(&config).unwrap();
    assert_eq!(
        udp_query(
            server.udp_addr().unwrap(),
            &make_query("metrics.test", Rtype::A, None),
            TIMEOUT,
        )
        .unwrap()
        .rcode(),
        Rcode::NOERROR
    );
    let metrics_addr = server.metrics_addr().unwrap();
    let health = http_get(metrics_addr, "/healthz");
    assert!(health.starts_with("HTTP/1.1 200 OK"), "{health}");
    let metrics = http_get(metrics_addr, "/metrics");
    assert!(metrics.contains("pulseresolved_queries_total{transport=\"udp\"} 1"));
    assert!(metrics.contains("pulseresolved_resolver_queries_total 1"));
    assert!(metrics.contains("pulseresolved_cache_entries"));
}

#[test]
fn shutdown_stops_both_transports_and_is_idempotent() {
    let upstream = MockUpstream::start(|request| {
        Some(positive_response(
            request,
            record_for(request, [192, 0, 2, 13]),
        ))
    });
    let config = base_config(upstream.address());
    let mut server = Server::start(&config).unwrap();
    let udp_addr = server.udp_addr().unwrap();
    let tcp_addr = server.tcp_addr().unwrap();
    assert!(
        udp_query(udp_addr, &make_query("alive.test", Rtype::A, None), TIMEOUT).is_some(),
        "server must answer before shutdown"
    );

    server.shutdown().expect("first shutdown");
    server.shutdown().expect("second shutdown must be a no-op");

    assert!(TcpStream::connect(tcp_addr).is_err() || tcp_connect_fails(tcp_addr));
    let after = udp_query_raw(
        udp_addr,
        &make_query("alive.test", Rtype::A, None)
            .encode(&EncodeOptions::default())
            .unwrap(),
        Duration::from_millis(300),
    );
    assert!(
        after.is_none(),
        "UDP listener must be closed after shutdown"
    );
}

fn tcp_connect_fails(addr: SocketAddr) -> bool {
    match TcpStream::connect_timeout(&addr, Duration::from_millis(200)) {
        Ok(mut stream) => {
            let _ = stream.write_all(&[]);
            false
        }
        Err(_) => true,
    }
}

fn http_get(addr: SocketAddr, path: &str) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect metrics");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    write!(stream, "GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

#[test]
fn malformed_query_never_panics_the_server() {
    let upstream = MockUpstream::start(|request| {
        Some(positive_response(
            request,
            record_for(request, [192, 0, 2, 14]),
        ))
    });
    let config = base_config(upstream.address());
    let server = Server::start(&config).unwrap();
    let addr = server.udp_addr().unwrap();
    let mut seed = 0x1234_5678_u32;
    for length in 0..64_usize {
        let mut packet = vec![0_u8; length];
        for byte in &mut packet {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *byte = (seed >> 24) as u8;
        }
        let _ = udp_query_raw(addr, &packet, Duration::from_millis(50));
    }
    let reply = udp_query(
        addr,
        &make_query("still-alive.test", Rtype::A, None),
        TIMEOUT,
    )
    .expect("server must stay alive");
    assert_eq!(reply.rcode(), Rcode::NOERROR);
    assert_eq!(
        Message::decode(
            &reply.encode(&EncodeOptions::default()).unwrap(),
            &DecodeLimits::default()
        )
        .unwrap()
        .rcode(),
        Rcode::NOERROR
    );
}
