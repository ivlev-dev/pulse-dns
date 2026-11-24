//! E2E `pulseresolved` → DoT/DoH upstream через JSON-конфиг `upstreams`.

mod support;

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use pulse_dns::{DecodeLimits, EncodeOptions, Message, Rclass, Rcode, Rdata, Record, Rtype, Ttl};
use pulse_resolver::{HttpsUpstream, TlsUpstream, UpstreamConfig};
use pulse_tls::{DohConfig, DohServer, DotConfig, DotServer, TlsConfig};
use pulseresolved::config::{Config, ModeSetting, UpstreamPoolSetting, UpstreamSetting};
use pulseresolved::server::Server;
use rcgen::{CertificateParams, KeyPair};

use support::{make_query, udp_query};

const TIMEOUT: Duration = Duration::from_secs(3);

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
        Rdata::A(Ipv4Addr::new(203, 0, 113, 9)),
    )
    .ok()?;
    let mut response = support::positive_response(&request, record);
    response.set_rcode(Rcode::NOERROR);
    response.encode(&EncodeOptions::default()).ok()
}

fn server_config(upload: UpstreamConfig) -> Config {
    Config {
        listen_udp: Some("127.0.0.1:0".parse().expect("addr")),
        listen_tcp: None,
        workers: 1,
        mode: ModeSetting::Forward,
        upstreams: vec![UpstreamSetting { upstream: upload }],
        ..Config::default()
    }
}

fn ca_file(dir: &tempfile::TempDir, cert: &TestCert) -> PathBuf {
    let path = dir.path().join("ca.pem");
    std::fs::write(&path, cert.cert_pem.as_bytes()).expect("write ca");
    path
}

fn resolve(server: &Server, name: &str) -> Message {
    let address = server.udp_addr().expect("udp");
    let query = make_query(name, Rtype::A, None);
    udp_query(address, &query, TIMEOUT).expect("response")
}

#[test]
fn dot_upstream_from_config() {
    let cert = test_cert();
    let dir = tempfile::tempdir().expect("tempdir");
    let ca = ca_file(&dir, &cert);
    let tls =
        TlsConfig::for_dot(cert.cert_pem.as_bytes(), cert.key_pem.as_bytes()).expect("dot tls");
    let config = DotConfig::new("127.0.0.1:0".parse().expect("addr"), tls);
    let mut upstream = DotServer::bind(config, |query: &[u8], _peer: SocketAddr| {
        answer_handler(query)
    })
    .expect("dot server");

    let config = server_config(UpstreamConfig::Tls(TlsUpstream {
        host: "127.0.0.1".to_owned(),
        port: upstream.local_addr().port(),
        server_name: "localhost".to_owned(),
        ca: Some(ca),
    }));
    let server = Server::start(&config).expect("server");
    let response = resolve(&server, "dot.secure.test");
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert_eq!(response.answers().len(), 1);
    assert_eq!(server.resolver_stats().upstream.tls_queries, 1);
    upstream.shutdown().expect("shutdown");
}

#[test]
fn doh_upstream_from_config() {
    let cert = test_cert();
    let dir = tempfile::tempdir().expect("tempdir");
    let ca = ca_file(&dir, &cert);
    let tls =
        TlsConfig::for_doh(cert.cert_pem.as_bytes(), cert.key_pem.as_bytes()).expect("doh tls");
    let config = DohConfig::new("127.0.0.1:0".parse().expect("addr"), tls);
    let mut upstream = DohServer::bind(config, |query: &[u8], _peer: SocketAddr| {
        answer_handler(query)
    })
    .expect("doh server");

    let config = server_config(UpstreamConfig::Https(HttpsUpstream {
        url: format!(
            "https://127.0.0.1:{}/dns-query",
            upstream.local_addr().port()
        ),
        ca: Some(ca),
    }));
    let server = Server::start(&config).expect("server");
    let response = resolve(&server, "doh.secure.test");
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert_eq!(response.answers().len(), 1);
    assert_eq!(server.resolver_stats().upstream.https_queries, 1);
    upstream.shutdown().expect("shutdown");
}

#[test]
fn wrong_ca_yields_servfail() {
    let cert = test_cert();
    let other = test_cert();
    let dir = tempfile::tempdir().expect("tempdir");
    let ca = ca_file(&dir, &other);
    let tls =
        TlsConfig::for_dot(cert.cert_pem.as_bytes(), cert.key_pem.as_bytes()).expect("dot tls");
    let config = DotConfig::new("127.0.0.1:0".parse().expect("addr"), tls);
    let mut upstream = DotServer::bind(config, |query: &[u8], _peer: SocketAddr| {
        answer_handler(query)
    })
    .expect("dot server");

    let config = server_config(UpstreamConfig::Tls(TlsUpstream {
        host: "127.0.0.1".to_owned(),
        port: upstream.local_addr().port(),
        server_name: "localhost".to_owned(),
        ca: Some(ca),
    }));
    let server = Server::start(&config).expect("server");
    let response = resolve(&server, "badca.secure.test");
    assert_eq!(response.rcode(), Rcode::SERVFAIL);
    upstream.shutdown().expect("shutdown");
}

#[test]
fn dot_pool_serves_parallel_clients() {
    let cert = test_cert();
    let dir = tempfile::tempdir().expect("tempdir");
    let ca = ca_file(&dir, &cert);
    let tls =
        TlsConfig::for_dot(cert.cert_pem.as_bytes(), cert.key_pem.as_bytes()).expect("dot tls");
    let config = DotConfig::new("127.0.0.1:0".parse().expect("addr"), tls);
    let mut upstream = DotServer::bind(config, |query: &[u8], _peer: SocketAddr| {
        answer_handler(query)
    })
    .expect("dot server");

    let mut config = server_config(UpstreamConfig::Tls(TlsUpstream {
        host: "127.0.0.1".to_owned(),
        port: upstream.local_addr().port(),
        server_name: "localhost".to_owned(),
        ca: Some(ca),
    }));
    config.upstream_pool = UpstreamPoolSetting {
        pool_size: 2,
        reconnect_backoff_ms: 50,
        max_reconnect_backoff_ms: 500,
    };
    let server = Server::start(&config).expect("server");
    let address = server.udp_addr().expect("udp");

    let mut threads = Vec::new();
    for index in 0..16 {
        threads.push(std::thread::spawn(move || {
            let query = make_query(&format!("pool-{index}.secure.test"), Rtype::A, None);
            let response = udp_query(address, &query, TIMEOUT).expect("response");
            assert_eq!(response.rcode(), Rcode::NOERROR, "pool-{index}");
            assert_eq!(response.answers().len(), 1, "pool-{index}");
        }));
    }
    for thread in threads {
        thread.join().expect("thread");
    }

    let stats = server.resolver_stats().upstream.pool;
    assert!(stats.opens <= 2, "opens: {}", stats.opens);
    assert!(stats.reuses > 0, "reuses: {}", stats.reuses);
    assert!(upstream.stats().connections <= 2);
    upstream.shutdown().expect("shutdown");
}
