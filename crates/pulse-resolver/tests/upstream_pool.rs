//! E2E пула keep-alive соединений: 100 параллельных запросов через DoT/DoH
//! upstream, переиспользование соединений и переподключение после обрыва.

mod support;

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use pulse_dns::{
    DecodeLimits, EncodeOptions, Message, Name, Rclass, Rcode, Rdata, Record, Rtype, Ttl,
};
use pulse_resolver::{
    ForwardConfig, HttpsUpstream, Mode, Resolver, ResolverConfig, TlsUpstream, UpstreamConfig,
    UpstreamPoolConfig,
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
        Rdata::A(Ipv4Addr::new(203, 0, 113, 10)),
    )
    .ok()?;
    let mut response = support::response(&request, Rcode::NOERROR);
    response.add_answer(record);
    response.encode(&EncodeOptions::default()).ok()
}

fn ca_file(dir: &tempfile::TempDir, cert: &TestCert) -> PathBuf {
    let path = dir.path().join("ca.pem");
    std::fs::write(&path, cert.cert_pem.as_bytes()).expect("write ca");
    path
}

fn dot_server(cert: &TestCert) -> DotServer {
    let tls =
        TlsConfig::for_dot(cert.cert_pem.as_bytes(), cert.key_pem.as_bytes()).expect("DoT tls");
    let config = DotConfig::new("127.0.0.1:0".parse().expect("addr"), tls);
    DotServer::bind(config, |query: &[u8], _peer: SocketAddr| {
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

fn resolver(upstream: UpstreamConfig) -> Resolver {
    let config = ResolverConfig {
        mode: Mode::Forward(ForwardConfig::with_upstreams(vec![upstream])),
        pool: UpstreamPoolConfig {
            size: 4,
            reconnect_backoff: Duration::from_millis(20),
            max_reconnect_backoff: Duration::from_millis(100),
        },
        timeouts: pulse_resolver::TimeoutConfig {
            per_query: Duration::from_secs(2),
            tcp: Duration::from_secs(3),
            total: Duration::from_secs(10),
        },
        retries: 1,
        ..ResolverConfig::default()
    };
    Resolver::new(config).expect("resolver")
}

fn resolve_parallel(resolver: &Arc<Resolver>, prefix: &str, workers: usize) {
    let barrier = Arc::new(std::sync::Barrier::new(workers));
    let mut threads = Vec::new();
    for index in 0..workers {
        let resolver = Arc::clone(resolver);
        let barrier = Arc::clone(&barrier);
        let name = format!("{prefix}-{index}.pool.test");
        threads.push(thread::spawn(move || {
            let qname = Name::parse(&name).expect("name");
            barrier.wait();
            let response = resolver.resolve_qname(&qname, Rtype::A);
            assert_eq!(response.rcode(), Rcode::NOERROR, "{name}");
            assert_eq!(response.answers().len(), 1, "{name}");
            assert_eq!(response.answers()[0].owner(), &qname, "{name}");
        }));
    }
    for thread in threads {
        thread.join().expect("thread");
    }
}

#[test]
fn dot_pool_handles_hundred_parallel_queries() {
    let cert = test_cert();
    let dir = tempfile::tempdir().expect("tempdir");
    let ca = ca_file(&dir, &cert);
    let mut server = dot_server(&cert);
    let port = server.local_addr().port();

    let resolver = Arc::new(resolver(UpstreamConfig::Tls(TlsUpstream {
        host: "127.0.0.1".to_owned(),
        port,
        server_name: "localhost".to_owned(),
        ca: Some(ca),
    })));

    resolve_parallel(&resolver, "dot", 100);

    let upstream = resolver.stats().upstream;
    assert_eq!(upstream.tls_queries, 100);
    assert_eq!(resolver.stats().servfail, 0);
    let pool = upstream.pool;
    assert!(pool.opens <= 4, "opens: {}", pool.opens);
    assert!(pool.opens >= 1);
    assert!(pool.reuses > 0, "reuses: {}", pool.reuses);
    assert_eq!(pool.discards, 0);
    let stats = server.stats();
    assert!(stats.connections <= 4, "connections: {}", stats.connections);
    server.shutdown().expect("shutdown");
}

#[test]
fn doh_pool_handles_hundred_parallel_queries() {
    let cert = test_cert();
    let dir = tempfile::tempdir().expect("tempdir");
    let ca = ca_file(&dir, &cert);
    let mut server = doh_server(&cert);
    let port = server.local_addr().port();

    let resolver = Arc::new(resolver(UpstreamConfig::Https(HttpsUpstream {
        url: format!("https://127.0.0.1:{port}/dns-query"),
        ca: Some(ca),
    })));

    resolve_parallel(&resolver, "doh", 100);

    let upstream = resolver.stats().upstream;
    assert_eq!(upstream.https_queries, 100);
    assert_eq!(resolver.stats().servfail, 0);
    let pool = upstream.pool;
    assert!(pool.opens <= 4, "opens: {}", pool.opens);
    assert!(pool.reuses > 0, "reuses: {}", pool.reuses);
    let stats = server.stats();
    assert!(stats.connections <= 4, "connections: {}", stats.connections);
    server.shutdown().expect("shutdown");
}

#[test]
fn dot_pool_reuses_one_connection_for_sequential_queries() {
    let cert = test_cert();
    let dir = tempfile::tempdir().expect("tempdir");
    let ca = ca_file(&dir, &cert);
    let mut server = dot_server(&cert);

    let resolver = resolver(UpstreamConfig::Tls(TlsUpstream {
        host: "127.0.0.1".to_owned(),
        port: server.local_addr().port(),
        server_name: "localhost".to_owned(),
        ca: Some(ca),
    }));
    for index in 0..8 {
        let name = Name::parse(&format!("seq-{index}.pool.test")).expect("name");
        let response = resolver.resolve_qname(&name, Rtype::A);
        assert_eq!(response.rcode(), Rcode::NOERROR, "seq-{index}");
    }
    let pool = resolver.stats().upstream.pool;
    assert_eq!(pool.opens, 1, "opens: {}", pool.opens);
    assert_eq!(pool.reuses, 7, "reuses: {}", pool.reuses);
    assert_eq!(server.stats().connections, 1);
    server.shutdown().expect("shutdown");
}

#[test]
fn dot_pool_reconnects_after_connection_break() {
    let cert = test_cert();
    let dir = tempfile::tempdir().expect("tempdir");
    let ca = ca_file(&dir, &cert);
    let calls = Arc::new(AtomicUsize::new(0));
    let handler_calls = Arc::clone(&calls);
    let tls =
        TlsConfig::for_dot(cert.cert_pem.as_bytes(), cert.key_pem.as_bytes()).expect("DoT tls");
    let config = DotConfig::new("127.0.0.1:0".parse().expect("addr"), tls);
    let mut server = DotServer::bind(config, move |query: &[u8], _peer: SocketAddr| {
        if handler_calls.fetch_add(1, Ordering::SeqCst) == 0 {
            // Первое соединение рвётся без ответа.
            None
        } else {
            answer_handler(query)
        }
    })
    .expect("DoT server");

    let resolver = resolver(UpstreamConfig::Tls(TlsUpstream {
        host: "127.0.0.1".to_owned(),
        port: server.local_addr().port(),
        server_name: "localhost".to_owned(),
        ca: Some(ca),
    }));
    let name = Name::parse("reconnect.pool.test").expect("name");
    let response = resolver.resolve_qname(&name, Rtype::A);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert_eq!(response.answers().len(), 1);
    let pool = resolver.stats().upstream.pool;
    assert!(pool.discards >= 1, "discards: {}", pool.discards);
    assert!(pool.opens >= 2, "opens: {}", pool.opens);
    server.shutdown().expect("shutdown");
}
