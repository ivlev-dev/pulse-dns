//! Интеграционные тесты DoH/HTTP/1.1: POST/GET, коды ошибок, keep-alive,
//! health, Cache-Control, rate limit, ALPN, мусорный HTTP и shutdown.

mod common;

use std::net::SocketAddr;
use std::thread;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::{TlsClient, dns_query, dns_response, echo_handler, test_cert};
use pulse_tls::{DohConfig, DohServer, RateLimitConfig, TlsConfig};

fn doh_server<H>(
    cert: &common::TestCert,
    handler: H,
    configure: impl FnOnce(&mut DohConfig),
) -> DohServer
where
    H: Fn(&[u8], SocketAddr) -> Option<Vec<u8>> + Send + Sync + 'static,
{
    let tls = TlsConfig::for_doh(cert.cert_pem.as_bytes(), cert.key_pem.as_bytes())
        .expect("DoH TLS config");
    let mut config = DohConfig::new("127.0.0.1:0".parse().expect("addr"), tls);
    configure(&mut config);
    DohServer::bind(config, handler).expect("bind DoH server")
}

fn post_request(path: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let mut request = head.into_bytes();
    request.extend_from_slice(body);
    request
}

fn get_request(path: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").into_bytes()
}

#[test]
fn post_get_health_and_errors() {
    let cert = test_cert();
    let mut server = doh_server(&cert, echo_handler, |_| {});
    let addr = server.local_addr();
    let mut client = TlsClient::connect(addr, &cert.cert_der, Some(b"http/1.1")).expect("client");
    assert_eq!(client.negotiated_alpn(), Some(b"http/1.1".as_slice()));

    let query = dns_query(21);
    let response = client
        .request(&post_request(
            "/dns-query",
            "application/dns-message",
            &query,
        ))
        .expect("POST");
    assert_eq!(response.status, 200);
    assert_eq!(
        response.header("content-type"),
        Some("application/dns-message")
    );
    assert_eq!(response.body, query);

    let encoded = URL_SAFE_NO_PAD.encode(&query);
    let response = client
        .request(&get_request(&format!("/dns-query?dns={encoded}")))
        .expect("GET");
    assert_eq!(response.status, 200);
    assert_eq!(response.body, query);

    let response = client.request(&get_request("/healthz")).expect("health");
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"ok\n");

    let response = client.request(&get_request("/nope")).expect("404");
    assert_eq!(response.status, 404);

    let response = client
        .request(b"PUT /dns-query HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")
        .expect("405");
    assert_eq!(response.status, 405);
    assert_eq!(response.header("allow"), Some("GET, POST"));

    let response = client
        .request(&get_request("/dns-query?dns=%%%"))
        .expect("bad base64");
    assert_eq!(response.status, 400);

    let response = client
        .request(&get_request("/dns-query"))
        .expect("missing dns");
    assert_eq!(response.status, 400);

    let response = client
        .request(&post_request("/dns-query", "text/plain", &query))
        .expect("415");
    assert_eq!(response.status, 415);

    let stats = server.stats();
    assert!(stats.queries >= 2);
    assert!(stats.http_errors >= 4);
    server.shutdown().expect("shutdown");
}

#[test]
fn body_limit_and_keep_alive() {
    let cert = test_cert();
    let mut server = doh_server(&cert, echo_handler, |config| {
        config.max_body_size = 16;
        config.max_requests_per_connection = 10;
    });
    let mut client =
        TlsClient::connect(server.local_addr(), &cert.cert_der, Some(b"http/1.1")).expect("client");
    let query = dns_query(22);
    let response = client
        .request(&post_request(
            "/dns-query",
            "application/dns-message",
            &query,
        ))
        .expect("413");
    assert_eq!(response.status, 413);
    server.shutdown().expect("shutdown");

    let mut server = doh_server(&cert, echo_handler, |config| {
        config.max_requests_per_connection = 10;
    });
    let mut client =
        TlsClient::connect(server.local_addr(), &cert.cert_der, Some(b"http/1.1")).expect("client");
    for id in [23_u16, 24, 25] {
        let query = dns_query(id);
        let response = client
            .request(&post_request(
                "/dns-query",
                "application/dns-message",
                &query,
            ))
            .expect("keep-alive POST");
        assert_eq!(response.status, 200);
        assert_eq!(response.body, query);
        assert_eq!(response.header("connection"), Some("keep-alive"));
    }
    let stats = server.stats();
    assert_eq!(stats.queries, 3);
    assert_eq!(stats.handshakes, 1);

    let response = client.request(&get_request("/healthz")).expect("health");
    assert_eq!(response.status, 200);
    server.shutdown().expect("shutdown");
}

#[test]
fn cache_control_from_response_ttl() {
    let cert = test_cert();
    let mut server = doh_server(
        &cert,
        |_query, _peer| Some(dns_response(30, 300)),
        |config| {
            config.cache_control = true;
        },
    );
    let mut client =
        TlsClient::connect(server.local_addr(), &cert.cert_der, Some(b"http/1.1")).expect("client");
    let response = client
        .request(&post_request(
            "/dns-query",
            "application/dns-message",
            &dns_query(30),
        ))
        .expect("cache");
    assert_eq!(response.status, 200);
    assert_eq!(response.header("cache-control"), Some("max-age=300"));
    server.shutdown().expect("shutdown");
}

#[test]
fn rate_limit_returns_429() {
    let cert = test_cert();
    let mut server = doh_server(&cert, echo_handler, |config| {
        config.rate_limit = Some(RateLimitConfig {
            burst: 1,
            refill_per_sec: 0.001,
            max_entries: 16,
        });
    });
    let mut client =
        TlsClient::connect(server.local_addr(), &cert.cert_der, Some(b"http/1.1")).expect("client");
    let query = dns_query(31);
    let response = client
        .request(&post_request(
            "/dns-query",
            "application/dns-message",
            &query,
        ))
        .expect("first");
    assert_eq!(response.status, 200);
    let response = client
        .request(&post_request(
            "/dns-query",
            "application/dns-message",
            &query,
        ))
        .expect("second");
    assert_eq!(response.status, 429);
    assert!(server.stats().rate_limited >= 1);
    server.shutdown().expect("shutdown");
}

#[test]
fn malformed_http_and_http2_preface_do_not_kill_server() {
    let cert = test_cert();
    let mut server = doh_server(&cert, echo_handler, |_| {});
    let addr = server.local_addr();

    {
        let mut client =
            TlsClient::connect(addr, &cert.cert_der, Some(b"http/1.1")).expect("client");
        let response = client.request(b"GARBAGE\r\n\r\n").expect("400 response");
        assert_eq!(response.status, 400);
    }
    {
        let mut client =
            TlsClient::connect(addr, &cert.cert_der, Some(b"http/1.1")).expect("client");
        let response = client
            .request(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            .expect("505 response");
        assert_eq!(response.status, 505);
    }
    {
        let mut client =
            TlsClient::connect(addr, &cert.cert_der, Some(b"http/1.1")).expect("client");
        let response = client
            .request(&post_request(
                "/dns-query",
                "application/dns-message",
                &dns_query(32),
            ))
            .expect("valid after garbage");
        assert_eq!(response.status, 200);
    }
    server.shutdown().expect("shutdown");
}

#[test]
fn rejects_wrong_alpn() {
    let cert = test_cert();
    let mut server = doh_server(&cert, echo_handler, |_| {});
    assert!(TlsClient::connect(server.local_addr(), &cert.cert_der, Some(b"dot")).is_err());
    assert!(TlsClient::connect(server.local_addr(), &cert.cert_der, Some(b"h2")).is_err());
    server.shutdown().expect("shutdown");
}

#[test]
fn shutdown_closes_listener() {
    let cert = test_cert();
    let mut server = doh_server(&cert, echo_handler, |config| {
        config.shutdown_timeout = Duration::from_millis(500);
    });
    let addr = server.local_addr();
    let _client = TlsClient::connect(addr, &cert.cert_der, Some(b"http/1.1")).expect("client");
    server.shutdown().expect("shutdown");
    assert!(std::net::TcpStream::connect(addr).is_err());
    thread::sleep(Duration::from_millis(20));
    assert_eq!(server.stats().active_connections, 0);
}

#[test]
fn slowloris_header_does_not_block_other_clients() {
    let cert = test_cert();
    let mut server = doh_server(&cert, echo_handler, |config| {
        config.idle_timeout = Duration::from_secs(5);
        config.request_timeout = Duration::from_millis(150);
    });
    let addr = server.local_addr();
    let mut slow =
        TlsClient::connect(addr, &cert.cert_der, Some(b"http/1.1")).expect("slow client");
    slow.send(b"POST /dns-query HTTP/1.1\r\nHost: localhost\r\n")
        .expect("partial header");

    let started = std::time::Instant::now();
    let mut fast =
        TlsClient::connect(addr, &cert.cert_der, Some(b"http/1.1")).expect("fast client");
    let query = dns_query(44);
    let response = fast
        .request(&post_request(
            "/dns-query",
            "application/dns-message",
            &query,
        ))
        .expect("fast request");
    assert_eq!(response.status, 200);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "slowloris blocked the active client: {:?}",
        started.elapsed()
    );

    assert!(
        slow.read_http().is_err(),
        "slowloris HTTP connection must be closed"
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    while server.stats().timeouts == 0 && std::time::Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(server.stats().timeouts >= 1);
    server.shutdown().expect("shutdown");
}
