//! Интеграционные тесты `DoT`: round-trip, несколько сообщений, таймауты,
//! ALPN, мусорный TLS, лимиты и shutdown.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use common::{TlsClient, dns_query, echo_handler, test_cert};
use pulse_tls::{Acl, DotConfig, DotServer, RateLimitConfig, TlsConfig};

fn dot_server(cert: &common::TestCert, configure: impl FnOnce(&mut DotConfig)) -> DotServer {
    let tls = TlsConfig::for_dot(cert.cert_pem.as_bytes(), cert.key_pem.as_bytes())
        .expect("DoT TLS config");
    let mut config = DotConfig::new("127.0.0.1:0".parse().expect("addr"), tls);
    configure(&mut config);
    DotServer::bind(config, echo_handler).expect("bind DoT server")
}

#[test]
fn roundtrip_and_multiple_messages() {
    let cert = test_cert();
    let mut server = dot_server(&cert, |_| {});
    let addr = server.local_addr();
    let mut client = TlsClient::connect(addr, &cert.cert_der, Some(b"dot")).expect("TLS client");
    assert_eq!(client.negotiated_alpn(), Some(b"dot".as_slice()));

    for id in [1_u16, 2, 3] {
        let query = dns_query(id);
        client.send_dot(&query).expect("send query");
        assert_eq!(client.read_dot().expect("read response"), query);
    }
    let stats = server.stats();
    assert_eq!(stats.queries, 3);
    assert_eq!(stats.responses, 3);
    assert_eq!(stats.handshakes, 1);
    assert_eq!(stats.active_connections, 1);
    server.shutdown().expect("shutdown");
    assert!(server.is_shutdown());
}

#[test]
fn idle_timeout_closes_connection() {
    let cert = test_cert();
    let mut server = dot_server(&cert, |config| {
        config.idle_timeout = Duration::from_millis(250);
    });
    let mut client =
        TlsClient::connect(server.local_addr(), &cert.cert_der, Some(b"dot")).expect("TLS client");
    let query = dns_query(7);
    client.send_dot(&query).expect("send");
    assert_eq!(client.read_dot().expect("read"), query);
    thread::sleep(Duration::from_millis(700));
    assert!(
        client.read_dot().is_err(),
        "server should close idle connection"
    );
    server.shutdown().expect("shutdown");
}

#[test]
fn rejects_wrong_and_missing_alpn() {
    let cert = test_cert();
    let mut server = dot_server(&cert, |_| {});
    let addr = server.local_addr();

    assert!(
        TlsClient::connect(addr, &cert.cert_der, Some(b"h2")).is_err(),
        "ALPN h2 must be rejected"
    );
    match TlsClient::connect(addr, &cert.cert_der, None) {
        Err(_) => {}
        Ok(mut client) => {
            let query = dns_query(9);
            let failed = client
                .send_dot(&query)
                .and_then(|()| client.read_dot())
                .is_err();
            assert!(failed, "connection without ALPN must be rejected");
        }
    }
    let mut client = TlsClient::connect(addr, &cert.cert_der, Some(b"dot")).expect("valid ALPN");
    let query = dns_query(10);
    client.send_dot(&query).expect("send");
    assert_eq!(client.read_dot().expect("read"), query);
    server.shutdown().expect("shutdown");
}

#[test]
fn garbage_tls_does_not_kill_server() {
    let cert = test_cert();
    let mut server = dot_server(&cert, |_| {});
    let addr = server.local_addr();
    {
        let mut socket = TcpStream::connect(addr).expect("connect raw");
        socket
            .set_write_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        socket
            .write_all(b"this is not a TLS ClientHello\r\n")
            .expect("write");
        let _ = socket.shutdown(std::net::Shutdown::Both);
    }
    let mut client = TlsClient::connect(addr, &cert.cert_der, Some(b"dot")).expect("valid client");
    let query = dns_query(11);
    client.send_dot(&query).expect("send");
    assert_eq!(client.read_dot().expect("read"), query);
    assert!(server.stats().handshake_failures >= 1);
    server.shutdown().expect("shutdown");
}

#[test]
fn oversized_message_is_rejected_and_server_survives() {
    let cert = test_cert();
    let mut server = dot_server(&cert, |config| {
        config.max_message_size = 64;
    });
    let addr = server.local_addr();
    {
        let mut client = TlsClient::connect(addr, &cert.cert_der, Some(b"dot")).expect("client");
        client
            .send(&100_u16.to_be_bytes())
            .expect("send oversized prefix");
        client.send(&[0_u8; 100]).expect("send oversized payload");
        assert!(
            client.read_dot().is_err(),
            "server must close oversized frame"
        );
    }
    let mut client = TlsClient::connect(addr, &cert.cert_der, Some(b"dot")).expect("client");
    let query = dns_query(12);
    client.send_dot(&query).expect("send");
    assert_eq!(client.read_dot().expect("read"), query);
    server.shutdown().expect("shutdown");
}

#[test]
fn acl_and_rate_limit() {
    let cert = test_cert();
    let mut server = dot_server(&cert, |config| {
        config.acl = Some(Acl::from_cidrs(["10.0.0.0/8"]).expect("acl"));
    });
    let addr = server.local_addr();
    assert!(TlsClient::connect(addr, &cert.cert_der, Some(b"dot")).is_err());
    server.shutdown().expect("shutdown");

    let mut server = dot_server(&cert, |config| {
        config.rate_limit = Some(RateLimitConfig {
            burst: 1,
            refill_per_sec: 0.001,
            max_entries: 16,
        });
    });
    let mut client =
        TlsClient::connect(server.local_addr(), &cert.cert_der, Some(b"dot")).expect("client");
    let query = dns_query(13);
    client.send_dot(&query).expect("send");
    assert_eq!(client.read_dot().expect("read"), query);
    client.send_dot(&query).expect("send second");
    assert!(client.read_dot().is_err(), "rate limited query must close");
    assert!(server.stats().rate_limited >= 1);
    server.shutdown().expect("shutdown");
}

#[test]
fn shutdown_closes_listener_and_active_connections() {
    let cert = test_cert();
    let mut server = dot_server(&cert, |_| {});
    let addr: SocketAddr = server.local_addr();
    let client = TlsClient::connect(addr, &cert.cert_der, Some(b"dot")).expect("client");
    server.shutdown().expect("shutdown");
    assert!(server.is_shutdown());
    assert!(
        TcpStream::connect(addr).is_err(),
        "listener must be closed after shutdown"
    );
    drop(client);
    assert_eq!(server.stats().active_connections, 0);
}

#[test]
fn hot_reload_certificate_for_new_connections() {
    let cert = test_cert();
    let replacement = test_cert();
    let mut server = dot_server(&cert, |_| {});
    let addr = server.local_addr();
    let mut existing =
        TlsClient::connect(addr, &cert.cert_der, Some(b"dot")).expect("existing client");

    server
        .reload(
            replacement.cert_pem.as_bytes(),
            replacement.key_pem.as_bytes(),
        )
        .expect("reload");

    let query = dns_query(14);
    existing.send_dot(&query).expect("send on old session");
    assert_eq!(existing.read_dot().expect("read on old session"), query);

    assert!(
        TlsClient::connect(addr, &cert.cert_der, Some(b"dot")).is_err(),
        "new connection must see the replacement certificate"
    );
    let mut client = TlsClient::connect(addr, &replacement.cert_der, Some(b"dot"))
        .expect("new certificate client");
    client.send_dot(&query).expect("send");
    assert_eq!(client.read_dot().expect("read"), query);
    server.shutdown().expect("shutdown");
}

#[test]
fn handshake_timeout_closes_stalled_client() {
    let cert = test_cert();
    let mut server = dot_server(&cert, |config| {
        config.handshake_timeout = Duration::from_millis(150);
    });
    let mut socket = TcpStream::connect(server.local_addr()).expect("raw connect");
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("read timeout");
    thread::sleep(Duration::from_millis(500));
    let mut byte = [0_u8; 1];
    match socket.read(&mut byte) {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
            ) => {}
        other => panic!("stalled handshake must be closed, got {other:?}"),
    }
    let stats = server.stats();
    assert!(stats.handshake_failures >= 1);
    server.shutdown().expect("shutdown");
}

#[test]
fn slowloris_prefix_does_not_block_other_clients() {
    let cert = test_cert();
    let mut server = dot_server(&cert, |config| {
        config.idle_timeout = Duration::from_secs(5);
        config.request_timeout = Duration::from_millis(150);
    });
    let addr = server.local_addr();
    let mut slow = TlsClient::connect(addr, &cert.cert_der, Some(b"dot")).expect("slow client");
    slow.send(&[0_u8]).expect("first prefix byte");

    let started = Instant::now();
    let mut fast = TlsClient::connect(addr, &cert.cert_der, Some(b"dot")).expect("fast client");
    let query = dns_query(41);
    fast.send_dot(&query).expect("fast send");
    assert_eq!(fast.read_dot().expect("fast read"), query);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "slow client blocked the active one: {:?}",
        started.elapsed()
    );

    assert!(
        slow.read_dot().is_err(),
        "slowloris connection must be closed by request timeout"
    );
    let deadline = Instant::now() + Duration::from_secs(1);
    while server.stats().timeouts == 0 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(server.stats().timeouts >= 1);
    server.shutdown().expect("shutdown");
}

#[test]
fn connection_limit_rejects_excess_and_keeps_existing() {
    let cert = test_cert();
    let mut server = dot_server(&cert, |config| {
        config.max_connections = 2;
    });
    let addr = server.local_addr();
    let mut first = TlsClient::connect(addr, &cert.cert_der, Some(b"dot")).expect("first");
    let second = TlsClient::connect(addr, &cert.cert_der, Some(b"dot")).expect("second");
    assert!(TlsClient::connect(addr, &cert.cert_der, Some(b"dot")).is_err());

    let query = dns_query(42);
    first.send_dot(&query).expect("first send");
    assert_eq!(first.read_dot().expect("first read"), query);
    drop(second);
    thread::sleep(Duration::from_millis(50));
    let mut third = TlsClient::connect(addr, &cert.cert_der, Some(b"dot")).expect("slot freed");
    third.send_dot(&query).expect("third send");
    assert_eq!(third.read_dot().expect("third read"), query);
    assert!(server.stats().rejected_connections >= 1);
    server.shutdown().expect("shutdown");
}
