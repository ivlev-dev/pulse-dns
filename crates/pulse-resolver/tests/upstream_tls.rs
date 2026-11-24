//! E2E upstream DoT/DoH: self-signed CA, keep-alive, failover и таймауты.

mod support;

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use pulse_dns::{
    DecodeLimits, EncodeOptions, Message, Name, Rclass, Rcode, Rdata, Record, Rtype, Ttl,
};
use pulse_resolver::{
    ForwardConfig, HttpsUpstream, Mode, Resolver, ResolverConfig, TlsUpstream, UpstreamConfig,
};
use pulse_tls::{DohConfig, DohServer, DotConfig, DotServer, TlsConfig};
use rcgen::{CertificateParams, KeyPair};

struct TestCert {
    cert_pem: String,
    key_pem: String,
}

fn test_cert() -> TestCert {
    let key = KeyPair::generate().expect("key");
    let params = CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
        .expect("params");
    let certificate = params.self_signed(&key).expect("self-signed");
    TestCert {
        cert_pem: certificate.pem(),
        key_pem: key.serialize_pem(),
    }
}

fn answer_handler(query: &[u8]) -> Option<Vec<u8>> {
    let request = Message::decode(query, &DecodeLimits::default()).ok()?;
    let question = request.questions().first()?;
    let record = Record::new(
        question.qname().clone(),
        Rtype::A,
        Rclass::IN,
        Ttl::new(60).ok()?,
        Rdata::A(Ipv4Addr::new(192, 0, 2, 53)),
    )
    .ok()?;
    let mut response = support::response(&request, Rcode::NOERROR);
    response.add_answer(record);
    Some(response.encode(&EncodeOptions::default()).expect("encode"))
}

fn dot_server(cert: &TestCert, delay: Option<Duration>) -> DotServer {
    let tls =
        TlsConfig::for_dot(cert.cert_pem.as_bytes(), cert.key_pem.as_bytes()).expect("DoT tls");
    let config = DotConfig::new("127.0.0.1:0".parse().expect("addr"), tls);
    DotServer::bind(config, move |query: &[u8], _peer: SocketAddr| {
        if let Some(delay) = delay {
            thread::sleep(delay);
        }
        answer_handler(query)
    })
    .expect("DoT server")
}

fn doh_server(cert: &TestCert) -> DohServer {
    let tls =
        TlsConfig::for_doh(cert.cert_pem.as_bytes(), cert.key_pem.as_bytes()).expect("DoH tls");
    let config = DohConfig::new("127.0.0.1:0".parse().expect("addr"), tls);
    DohServer::bind(config, |query: &[u8], _peer: SocketAddr| {
        answer_handler(query)
    })
    .expect("DoH server")
}

fn ca_file(dir: &tempfile::TempDir, cert: &TestCert) -> PathBuf {
    let path = dir.path().join("ca.pem");
    std::fs::write(&path, cert.cert_pem.as_bytes()).expect("write ca");
    path
}

fn resolver(upstreams: Vec<UpstreamConfig>) -> Resolver {
    let config = ResolverConfig {
        mode: Mode::Forward(ForwardConfig::with_upstreams(upstreams)),
        ..ResolverConfig::default()
    };
    Resolver::new(config).expect("resolver")
}

fn query_a(resolver: &Resolver, name: &str) -> Message {
    resolver.resolve_qname(&Name::parse(name).expect("name"), Rtype::A)
}

#[test]
fn dot_upstream_resolves_and_reuses_connection() {
    let cert = test_cert();
    let dir = tempfile::tempdir().expect("tempdir");
    let ca = ca_file(&dir, &cert);
    let mut server = dot_server(&cert, None);
    let port = server.local_addr().port();

    let resolver = resolver(vec![UpstreamConfig::Tls(TlsUpstream {
        host: "127.0.0.1".to_owned(),
        port,
        server_name: "localhost".to_owned(),
        ca: Some(ca),
    })]);

    for name in ["a.dot.test", "b.dot.test", "c.dot.test"] {
        let response = query_a(&resolver, name);
        assert_eq!(response.rcode(), Rcode::NOERROR, "{name}");
        assert_eq!(response.answers().len(), 1, "{name}");
    }
    let stats = resolver.stats();
    assert_eq!(stats.upstream.tls_queries, 3);
    assert_eq!(
        server.stats().handshakes,
        1,
        "DoT connection must be reused"
    );
    server.shutdown().expect("shutdown");
}

#[test]
fn doh_upstream_resolves_and_reuses_connection() {
    let cert = test_cert();
    let dir = tempfile::tempdir().expect("tempdir");
    let ca = ca_file(&dir, &cert);
    let mut server = doh_server(&cert);
    let port = server.local_addr().port();

    let resolver = resolver(vec![UpstreamConfig::Https(HttpsUpstream {
        url: format!("https://127.0.0.1:{port}/dns-query"),
        ca: Some(ca),
    })]);

    for name in ["a.doh.test", "b.doh.test"] {
        let response = query_a(&resolver, name);
        assert_eq!(response.rcode(), Rcode::NOERROR, "{name}");
        assert_eq!(response.answers().len(), 1, "{name}");
    }
    let stats = resolver.stats();
    assert_eq!(stats.upstream.https_queries, 2);
    assert_eq!(
        server.stats().connections,
        1,
        "DoH connection must be reused"
    );
    server.shutdown().expect("shutdown");
}

#[test]
fn wrong_certificate_fails_but_does_not_panic() {
    let cert = test_cert();
    let other = test_cert();
    let dir = tempfile::tempdir().expect("tempdir");
    let ca = ca_file(&dir, &other);
    let mut server = dot_server(&cert, None);

    let resolver = resolver(vec![UpstreamConfig::Tls(TlsUpstream {
        host: "127.0.0.1".to_owned(),
        port: server.local_addr().port(),
        server_name: "localhost".to_owned(),
        ca: Some(ca),
    })]);

    let response = query_a(&resolver, "untrusted.dot.test");
    assert_eq!(response.rcode(), Rcode::SERVFAIL);
    assert_eq!(resolver.stats().upstream.tls_queries, 1);
    server.shutdown().expect("shutdown");
}

#[test]
fn dot_timeout_becomes_servfail() {
    let cert = test_cert();
    let dir = tempfile::tempdir().expect("tempdir");
    let ca = ca_file(&dir, &cert);
    let mut server = dot_server(&cert, Some(Duration::from_millis(400)));

    let config = ResolverConfig {
        mode: Mode::Forward(ForwardConfig::with_upstreams(vec![UpstreamConfig::Tls(
            TlsUpstream {
                host: "127.0.0.1".to_owned(),
                port: server.local_addr().port(),
                server_name: "localhost".to_owned(),
                ca: Some(ca),
            },
        )])),
        timeouts: pulse_resolver::TimeoutConfig {
            per_query: Duration::from_millis(80),
            tcp: Duration::from_millis(500),
            total: Duration::from_millis(900),
        },
        ..ResolverConfig::default()
    };
    let resolver = Resolver::new(config).expect("resolver");

    let response = query_a(&resolver, "slow.dot.test");
    assert_eq!(response.rcode(), Rcode::SERVFAIL);
    assert!(resolver.stats().upstream.timeouts >= 1);
    server.shutdown().expect("shutdown");
}

#[test]
fn failover_from_untrusted_dot_to_udp() {
    let cert = test_cert();
    let other = test_cert();
    let dir = tempfile::tempdir().expect("tempdir");
    let ca = ca_file(&dir, &other);
    let mut dot = dot_server(&cert, None);

    let good = support::MockServer::spawn(std::sync::Arc::new(|request, _tcp| {
        let mut response = support::response(request, Rcode::NOERROR);
        let question = request.questions().first()?;
        response.add_answer(
            Record::new(
                question.qname().clone(),
                Rtype::A,
                Rclass::IN,
                Ttl::new(60).ok()?,
                Rdata::A(Ipv4Addr::new(198, 51, 100, 8)),
            )
            .ok()?,
        );
        Some(support::encode(&response))
    }));

    let resolver = resolver(vec![
        UpstreamConfig::Tls(TlsUpstream {
            host: "127.0.0.1".to_owned(),
            port: dot.local_addr().port(),
            server_name: "localhost".to_owned(),
            ca: Some(ca),
        }),
        UpstreamConfig::Udp(good.address()),
    ]);

    for index in 0..6 {
        let name = format!("mixed-failover-{index}.test");
        let response = query_a(&resolver, &name);
        assert_eq!(response.rcode(), Rcode::NOERROR, "{name}");
        assert_eq!(response.answers().len(), 1, "{name}");
    }
    let stats = resolver.stats();
    assert!(stats.upstream.tls_queries >= 1);
    assert!(stats.upstream.failovers >= 1);
    dot.shutdown().expect("shutdown");
}

#[test]
fn failover_to_second_upstream() {
    let good = support::MockServer::spawn(std::sync::Arc::new(|request, _tcp| {
        let mut response = support::response(request, Rcode::NOERROR);
        let question = request.questions().first()?;
        response.add_answer(
            Record::new(
                question.qname().clone(),
                Rtype::A,
                Rclass::IN,
                Ttl::new(60).ok()?,
                Rdata::A(Ipv4Addr::new(198, 51, 100, 7)),
            )
            .ok()?,
        );
        Some(support::encode(&response))
    }));

    // Порт, который гарантированно закрыт: TCP-connect завершится ошибкой.
    let dead = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.local_addr().expect("addr")
    };

    let resolver = resolver(vec![
        UpstreamConfig::Tcp(dead),
        UpstreamConfig::Udp(good.address()),
    ]);

    for index in 0..6 {
        let name = format!("failover-{index}.test");
        let response = query_a(&resolver, &name);
        assert_eq!(response.rcode(), Rcode::NOERROR, "{name}");
        assert_eq!(response.answers().len(), 1, "{name}");
    }
    assert!(
        resolver.stats().upstream.failovers >= 1,
        "at least one query must fail over from the dead upstream"
    );
}
