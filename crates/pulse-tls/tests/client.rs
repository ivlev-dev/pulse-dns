//! Интеграционные тесты клиентов DoT/DoH: проверка сертификата, keep-alive,
//! отказ при неверном CA и таймауты.

mod common;

use std::time::Duration;

use common::{dns_query, echo_handler, test_cert};
use pulse_tls::client::{ClientTlsConfig, DohClient, DotClient};
use pulse_tls::{DohConfig, DohServer, DotConfig, DotServer, TlsConfig};

fn dot_server(cert: &common::TestCert) -> DotServer {
    let tls = TlsConfig::for_dot(cert.cert_pem.as_bytes(), cert.key_pem.as_bytes())
        .expect("DoT TLS config");
    let config = DotConfig::new("127.0.0.1:0".parse().expect("addr"), tls);
    DotServer::bind(config, echo_handler).expect("bind DoT server")
}

fn doh_server(cert: &common::TestCert) -> DohServer {
    let tls = TlsConfig::for_doh(cert.cert_pem.as_bytes(), cert.key_pem.as_bytes())
        .expect("DoH TLS config");
    let config = DohConfig::new("127.0.0.1:0".parse().expect("addr"), tls);
    DohServer::bind(config, echo_handler).expect("bind DoH server")
}

#[test]
fn dot_client_roundtrip_reuses_connection() {
    let cert = test_cert();
    let mut server = dot_server(&cert);
    let tls = ClientTlsConfig::with_ca_pem(cert.cert_pem.as_bytes(), b"dot").expect("client tls");
    let client =
        DotClient::from_addr_with_tls(server.local_addr(), "localhost", tls).expect("dot client");

    for id in [1_u16, 2, 3] {
        let query = dns_query(id);
        let response = client
            .query(&query, Duration::from_secs(2), Duration::from_secs(2))
            .expect("query");
        assert_eq!(response, query);
    }
    let stats = server.stats();
    assert_eq!(stats.queries, 3);
    assert_eq!(stats.handshakes, 1, "client must reuse one TLS connection");
    assert_eq!(client.reconnects(), 0);
    server.shutdown().expect("shutdown");
}

#[test]
fn dot_client_rejects_untrusted_certificate() {
    let cert = test_cert();
    let other = test_cert();
    let mut server = dot_server(&cert);
    let tls = ClientTlsConfig::with_ca_pem(other.cert_pem.as_bytes(), b"dot").expect("client tls");
    let client =
        DotClient::from_addr_with_tls(server.local_addr(), "localhost", tls).expect("client");
    let error = client
        .query(
            &dns_query(1),
            Duration::from_secs(2),
            Duration::from_secs(1),
        )
        .expect_err("self-signed certificate must be rejected");
    assert!(!error.is_timeout(), "verification failure is not a timeout");
    server.shutdown().expect("shutdown");
}

#[test]
fn dot_client_reports_timeout() {
    let cert = test_cert();
    let mut server = dot_server(&cert);
    let tls = ClientTlsConfig::with_ca_pem(cert.cert_pem.as_bytes(), b"dot").expect("client tls");
    let client =
        DotClient::from_addr_with_tls(server.local_addr(), "localhost", tls).expect("client");
    let error = client
        .query(
            &dns_query(1),
            Duration::from_millis(1),
            Duration::from_millis(1),
        )
        .expect_err("zero-ish timeout must fail");
    assert!(error.is_timeout() || error.is_closed());
    server.shutdown().expect("shutdown");
}

#[test]
fn doh_client_posts_and_reuses_connection() {
    let cert = test_cert();
    let mut server = doh_server(&cert);
    let tls =
        ClientTlsConfig::with_ca_pem(cert.cert_pem.as_bytes(), b"http/1.1").expect("client tls");
    let url = format!("https://{}/dns-query", server.local_addr());
    let client = DohClient::with_tls(&url, tls).expect("doh client");

    for id in [10_u16, 11, 12] {
        let query = dns_query(id);
        let response = client
            .query(&query, Duration::from_secs(2), Duration::from_secs(2))
            .expect("query");
        assert_eq!(response, query);
    }
    let stats = server.stats();
    assert_eq!(stats.http_requests, 3);
    assert_eq!(
        stats.connections, 1,
        "client must reuse one HTTPS connection"
    );
    assert_eq!(client.reconnects(), 0);
    server.shutdown().expect("shutdown");
}

#[test]
fn doh_client_rejects_untrusted_certificate() {
    let cert = test_cert();
    let other = test_cert();
    let mut server = doh_server(&cert);
    let tls =
        ClientTlsConfig::with_ca_pem(other.cert_pem.as_bytes(), b"http/1.1").expect("client tls");
    let url = format!("https://{}/dns-query", server.local_addr());
    let client = DohClient::with_tls(&url, tls).expect("client");
    assert!(
        client
            .query(
                &dns_query(1),
                Duration::from_secs(2),
                Duration::from_secs(1)
            )
            .is_err(),
        "self-signed certificate must be rejected"
    );
    server.shutdown().expect("shutdown");
}
