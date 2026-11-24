//! Интеграционные тесты клиентов DoT/DoH: проверка сертификата, keep-alive,
//! отказ при неверном CA и таймауты.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::time::Duration;

use common::{dns_query, echo_handler, test_cert};
use pulse_tls::client::{ClientTlsConfig, DohClient, DotClient, PoolConfig};
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

fn small_pool() -> PoolConfig {
    PoolConfig {
        size: 4,
        reconnect_backoff: Duration::from_millis(20),
        max_reconnect_backoff: Duration::from_millis(100),
    }
}

fn parallel_queries<F>(workers: usize, query: F) -> Vec<Vec<u8>>
where
    F: Fn(&[u8]) -> Vec<u8> + Send + Sync + 'static,
{
    let query = Arc::new(query);
    let barrier = Arc::new(Barrier::new(workers));
    let mut threads = Vec::new();
    for id in 0..workers {
        let query = Arc::clone(&query);
        let barrier = Arc::clone(&barrier);
        threads.push(std::thread::spawn(move || {
            let payload = dns_query(u16::try_from(id).expect("id"));
            barrier.wait();
            (payload.clone(), query(&payload))
        }));
    }
    let mut responses = Vec::new();
    for thread in threads {
        let (expected, response) = thread.join().expect("thread");
        assert_eq!(response, expected, "response must match the query");
        responses.push(response);
    }
    responses
}

#[test]
fn dot_pool_serves_parallel_queries() {
    let cert = test_cert();
    let mut server = dot_server(&cert);
    let tls = ClientTlsConfig::with_ca_pem(cert.cert_pem.as_bytes(), b"dot").expect("client tls");
    let client = Arc::new(
        DotClient::from_addr_with_tls_and_pool(server.local_addr(), "localhost", tls, small_pool())
            .expect("dot client"),
    );

    let query = Arc::clone(&client);
    let responses = parallel_queries(32, move |payload| {
        query
            .query(payload, Duration::from_secs(5), Duration::from_secs(5))
            .expect("query")
    });
    assert_eq!(responses.len(), 32);

    let stats = server.stats();
    assert_eq!(stats.queries, 32);
    assert!(stats.connections <= 4, "connections: {}", stats.connections);
    let pool = client.pool_stats();
    assert_eq!(pool.opens, stats.connections);
    assert!(pool.opens <= 4, "opens: {}", pool.opens);
    assert!(pool.reuses > 0, "reuses: {}", pool.reuses);
    assert_eq!(pool.discards, 0);
    server.shutdown().expect("shutdown");
}

#[test]
fn doh_pool_serves_parallel_queries() {
    let cert = test_cert();
    let mut server = doh_server(&cert);
    let tls =
        ClientTlsConfig::with_ca_pem(cert.cert_pem.as_bytes(), b"http/1.1").expect("client tls");
    let url = format!("https://{}/dns-query", server.local_addr());
    let client = Arc::new(
        DohClient::with_addresses_and_pool(&url, tls, vec![server.local_addr()], small_pool())
            .expect("doh client"),
    );

    let query = Arc::clone(&client);
    let responses = parallel_queries(32, move |payload| {
        query
            .query(payload, Duration::from_secs(5), Duration::from_secs(5))
            .expect("query")
    });
    assert_eq!(responses.len(), 32);

    let stats = server.stats();
    assert_eq!(stats.queries, 32);
    assert!(stats.connections <= 4, "connections: {}", stats.connections);
    let pool = client.pool_stats();
    assert!(pool.opens <= 4, "opens: {}", pool.opens);
    assert_eq!(pool.discards, 0);
    server.shutdown().expect("shutdown");
}

#[test]
fn dot_client_reconnects_after_connection_close() {
    let cert = test_cert();
    let calls = Arc::new(AtomicUsize::new(0));
    let handler_calls = Arc::clone(&calls);
    let tls = TlsConfig::for_dot(cert.cert_pem.as_bytes(), cert.key_pem.as_bytes())
        .expect("DoT TLS config");
    let config = DotConfig::new("127.0.0.1:0".parse().expect("addr"), tls);
    let mut server = DotServer::bind(config, move |query: &[u8], _peer| {
        let call = handler_calls.fetch_add(1, Ordering::SeqCst);
        if call == 0 {
            // Первое соединение закрывается без ответа.
            None
        } else {
            Some(query.to_vec())
        }
    })
    .expect("bind DoT server");

    let tls = ClientTlsConfig::with_ca_pem(cert.cert_pem.as_bytes(), b"dot").expect("client tls");
    let client =
        DotClient::from_addr_with_tls_and_pool(server.local_addr(), "localhost", tls, small_pool())
            .expect("dot client");

    let payload = dns_query(7);
    let response = client
        .query(&payload, Duration::from_secs(5), Duration::from_secs(5))
        .expect("query after reconnect");
    assert_eq!(response, payload);
    assert_eq!(client.reconnects(), 1);
    assert_eq!(client.pool_stats().discards, 1);
    assert!(server.stats().connections >= 2);
    server.shutdown().expect("shutdown");
}
