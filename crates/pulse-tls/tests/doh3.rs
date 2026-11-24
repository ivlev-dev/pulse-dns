//! Интеграционные тесты DoH/HTTP/3 (RFC 9114 + RFC 8484): POST/GET,
//! мультиплексирование, A/AAAA/NXDOMAIN, большие ответы, лимиты,
//! неверный сертификат, hot-reload и graceful shutdown.

#![cfg(feature = "http3")]
#![allow(
    clippy::doc_markdown,
    clippy::similar_names,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::if_not_else
)]

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::{Buf, Bytes};
use common::{TestCert, decode_query, dns_query, echo_handler, test_cert, tls_client_config};
use http::{Method, Request};
use pulse_dns::{Message, Name, Question, Rclass, Rcode, Rdata, Record, Rtype, Ttl, TxtData};
use pulse_tls::{Acl, Doh3Config, Doh3Server, RateLimitConfig, TlsConfig};
use quinn::crypto::rustls::QuicClientConfig;

struct Client {
    send: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    driver: tokio::task::JoinHandle<()>,
    _endpoint: quinn::Endpoint,
}

impl Drop for Client {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

impl Client {
    async fn connect(addr: SocketAddr, cert_der: &[u8]) -> Self {
        Self::connect_with_alpn(addr, cert_der, b"h3").await
    }

    async fn connect_with_alpn(addr: SocketAddr, cert_der: &[u8], alpn: &[u8]) -> Self {
        let mut endpoint =
            quinn::Endpoint::client("127.0.0.1:0".parse().expect("client addr")).expect("endpoint");
        endpoint.set_default_client_config(h3_client_config(cert_der, alpn));
        let connection = endpoint
            .connect(addr, "localhost")
            .expect("connect")
            .await
            .expect("QUIC handshake");
        assert_eq!(
            connection
                .handshake_data()
                .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
                .and_then(|data| data.protocol),
            Some(alpn.to_vec())
        );
        let (mut h3_connection, send) = h3::client::new(h3_quinn::Connection::new(connection))
            .await
            .expect("HTTP/3 handshake");
        let driver = tokio::spawn(async move {
            let _ = h3_connection.wait_idle().await;
        });
        Self {
            send,
            driver,
            _endpoint: endpoint,
        }
    }

    async fn request(
        &mut self,
        method: Method,
        uri: String,
        content_type: Option<&str>,
        body: &[u8],
    ) -> (u16, Vec<u8>, Option<String>) {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(content_type) = content_type {
            builder = builder.header("content-type", content_type);
        }
        let request = builder.body(()).expect("request");
        let mut stream = self.send.send_request(request).await.expect("send request");
        if !body.is_empty() {
            stream
                .send_data(Bytes::copy_from_slice(body))
                .await
                .expect("send body");
        }
        stream.finish().await.expect("finish request");
        let response = stream.recv_response().await.expect("response");
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);
        (status, read_body(&mut stream).await, content_type)
    }
}

async fn read_body(
    stream: &mut h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
) -> Vec<u8> {
    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.expect("body chunk") {
        while chunk.has_remaining() {
            let bytes = chunk.chunk();
            body.extend_from_slice(bytes);
            let advance = bytes.len();
            chunk.advance(advance);
        }
    }
    body
}

fn h3_client_config(cert_der: &[u8], alpn: &[u8]) -> quinn::ClientConfig {
    let config = tls_client_config(cert_der, Some(alpn));
    let crypto = QuicClientConfig::try_from(config).expect("QUIC client config");
    quinn::ClientConfig::new(Arc::new(crypto))
}

fn server(
    cert: &TestCert,
    handler: impl Fn(&[u8], SocketAddr) -> Option<Vec<u8>> + Send + Sync + 'static,
    configure: impl FnOnce(&mut Doh3Config),
) -> Doh3Server {
    let tls = TlsConfig::for_doh3(cert.cert_pem.as_bytes(), cert.key_pem.as_bytes())
        .expect("HTTP/3 TLS config");
    let mut config = Doh3Config::new("127.0.0.1:0".parse().expect("addr"), tls);
    config.worker_threads = 2;
    configure(&mut config);
    Doh3Server::bind(config, handler).expect("bind DoH/3 server")
}

/// Отвечает A/AAAA по `example.com` и NXDOMAIN на остальные типы.
fn zone_handler(query: &[u8], _peer: SocketAddr) -> Option<Vec<u8>> {
    let request = decode_query(query);
    let question = request.questions().first()?.clone();
    let mut response = Message::response(&request);
    match question.qtype() {
        Rtype::A => response.add_answer(
            Record::new(
                question.qname().clone(),
                Rtype::A,
                Rclass::IN,
                Ttl::new(60).expect("ttl"),
                Rdata::A("192.0.2.1".parse().expect("ipv4")),
            )
            .expect("record"),
        ),
        Rtype::AAAA => response.add_answer(
            Record::new(
                question.qname().clone(),
                Rtype::AAAA,
                Rclass::IN,
                Ttl::new(60).expect("ttl"),
                Rdata::Aaaa("2001:db8::1".parse().expect("ipv6")),
            )
            .expect("record"),
        ),
        _ => response.set_rcode(Rcode::NXDOMAIN),
    }
    Some(
        response
            .encode(&pulse_dns::EncodeOptions::compressed())
            .expect("encode"),
    )
}

/// Возвращает большой (около 60 KiB) валидный DNS-ответ.
fn large_handler(query: &[u8], _peer: SocketAddr) -> Option<Vec<u8>> {
    let request = decode_query(query);
    let question = request.questions().first()?.clone();
    let mut response = Message::response(&request);
    for index in 0..300_u16 {
        let mut text = format!("record-{index}-").into_bytes();
        text.resize(190, b'x');
        response.add_answer(
            Record::new(
                question.qname().clone(),
                Rtype::TXT,
                Rclass::IN,
                Ttl::new(60).expect("ttl"),
                Rdata::Txt(TxtData::new(vec![text]).expect("txt")),
            )
            .expect("record"),
        );
    }
    let encoded = response
        .encode(&pulse_dns::EncodeOptions::compressed())
        .expect("encode");
    Some(encoded)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn post_get_health_and_errors() {
    let cert = test_cert();
    let mut server = server(&cert, echo_handler, |_| {});
    let addr = server.local_addr();
    let mut client = Client::connect(addr, &cert.cert_der).await;

    let query = dns_query(41);
    let (status, body, content_type) = client
        .request(
            Method::POST,
            "https://localhost/dns-query".to_owned(),
            Some("application/dns-message"),
            &query,
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(body, query);
    assert_eq!(content_type.as_deref(), Some("application/dns-message"));

    let encoded = URL_SAFE_NO_PAD.encode(&query);
    let (status, body, _) = client
        .request(
            Method::GET,
            format!("https://localhost/dns-query?dns={encoded}"),
            None,
            &[],
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(body, query);

    let (status, body, _) = client
        .request(
            Method::GET,
            "https://localhost/healthz".to_owned(),
            None,
            &[],
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(body, b"ok\n");

    let (status, _, _) = client
        .request(Method::GET, "https://localhost/nope".to_owned(), None, &[])
        .await;
    assert_eq!(status, 404);

    let (status, _, _) = client
        .request(
            Method::POST,
            "https://localhost/dns-query".to_owned(),
            Some("text/plain"),
            &query,
        )
        .await;
    assert_eq!(status, 415);

    let (status, _, _) = client
        .request(
            Method::POST,
            "https://localhost/dns-query".to_owned(),
            Some("application/dns-message"),
            &[],
        )
        .await;
    assert_eq!(status, 400);

    let stats = server.stats();
    assert!(stats.queries >= 2, "{stats:?}");
    assert!(stats.http_requests >= 6, "{stats:?}");
    assert!(stats.http_errors >= 3, "{stats:?}");
    server.shutdown().expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn answers_a_aaaa_and_nxdomain() {
    let cert = test_cert();
    let mut server = server(&cert, zone_handler, |_| {});
    let mut client = Client::connect(server.local_addr(), &cert.cert_der).await;

    for rr_type in [Rtype::A, Rtype::AAAA] {
        let name = Name::parse("example.com").expect("name");
        let query = Message::query(7, Question::new(name, rr_type, Rclass::IN))
            .encode(&pulse_dns::EncodeOptions::default())
            .expect("query");
        let (status, body, _) = client
            .request(
                Method::POST,
                "https://localhost/dns-query".to_owned(),
                Some("application/dns-message"),
                &query,
            )
            .await;
        assert_eq!(status, 200);
        let message = decode_query(&body);
        assert!(
            message
                .answers()
                .iter()
                .any(|record| record.rr_type() == rr_type),
            "{:?}",
            message.answers()
        );
    }

    let query = Message::query(
        9,
        Question::new(
            Name::parse("missing.example.com").expect("name"),
            Rtype::TXT,
            Rclass::IN,
        ),
    )
    .encode(&pulse_dns::EncodeOptions::default())
    .expect("query");
    let (status, body, _) = client
        .request(
            Method::POST,
            "https://localhost/dns-query".to_owned(),
            Some("application/dns-message"),
            &query,
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(decode_query(&body).rcode(), Rcode::NXDOMAIN);
    server.shutdown().expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multiplexes_ten_requests_on_one_connection() {
    let cert = test_cert();
    let mut server = server(&cert, echo_handler, |config| {
        config.max_concurrent_requests = 20;
    });
    let mut client = Client::connect(server.local_addr(), &cert.cert_der).await;
    let mut streams = Vec::new();
    for id in 0_u16..10 {
        let query = dns_query(100 + id);
        let request = Request::builder()
            .method(Method::POST)
            .uri("https://localhost/dns-query")
            .header("content-type", "application/dns-message")
            .body(())
            .expect("request");
        let mut stream = client
            .send
            .send_request(request)
            .await
            .expect("send request");
        stream
            .send_data(Bytes::from(query))
            .await
            .expect("send body");
        stream.finish().await.expect("finish");
        streams.push((id, stream));
    }
    for (id, mut stream) in streams {
        let response = stream.recv_response().await.expect("response");
        assert_eq!(response.status().as_u16(), 200);
        assert_eq!(read_body(&mut stream).await, dns_query(100 + id));
    }
    assert_eq!(server.stats().queries, 10);
    server.shutdown().expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn large_response_roundtrip() {
    let cert = test_cert();
    let mut server = server(&cert, large_handler, |_| {});
    let mut client = Client::connect(server.local_addr(), &cert.cert_der).await;
    let (status, body, content_type) = client
        .request(
            Method::POST,
            "https://localhost/dns-query".to_owned(),
            Some("application/dns-message"),
            &dns_query(3),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(content_type.as_deref(), Some("application/dns-message"));
    assert!(body.len() > 50_000, "response is {} bytes", body.len());
    assert!(body.len() <= 65_535);
    assert_eq!(decode_query(&body).answers().len(), 300);
    server.shutdown().expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn body_limit_returns_413() {
    let cert = test_cert();
    let mut server = server(&cert, echo_handler, |config| {
        config.max_body_size = 16;
    });
    let mut client = Client::connect(server.local_addr(), &cert.cert_der).await;
    let (status, _, _) = client
        .request(
            Method::POST,
            "https://localhost/dns-query".to_owned(),
            Some("application/dns-message"),
            &dns_query(42),
        )
        .await;
    assert_eq!(status, 413);
    server.shutdown().expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn acl_rejects_connections() {
    let cert = test_cert();
    let mut server = server(&cert, echo_handler, |config| {
        config.acl = Some(Acl::from_cidrs(&["10.0.0.0/8".to_owned()]).expect("acl"));
    });
    let mut endpoint =
        quinn::Endpoint::client("127.0.0.1:0".parse().expect("client")).expect("endpoint");
    endpoint.set_default_client_config(h3_client_config(&cert.cert_der, b"h3"));
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        endpoint
            .connect(server.local_addr(), "localhost")
            .expect("connect"),
    )
    .await;
    assert!(
        !matches!(result, Ok(Ok(_))),
        "connection from outside the ACL must fail"
    );
    server.shutdown().expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rate_limit_returns_429() {
    let cert = test_cert();
    let mut server = server(&cert, echo_handler, |config| {
        config.rate_limit = Some(RateLimitConfig {
            burst: 1,
            refill_per_sec: 1.0,
            max_entries: 16,
        });
    });
    let mut client = Client::connect(server.local_addr(), &cert.cert_der).await;
    let query = dns_query(5);
    let first = client
        .request(
            Method::POST,
            "https://localhost/dns-query".to_owned(),
            Some("application/dns-message"),
            &query,
        )
        .await;
    assert_eq!(first.0, 200);
    let second = client
        .request(
            Method::POST,
            "https://localhost/dns-query".to_owned(),
            Some("application/dns-message"),
            &query,
        )
        .await;
    assert_eq!(second.0, 429);
    assert_eq!(server.stats().rate_limited, 1);
    server.shutdown().expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_unknown_certificate_and_alpn() {
    let cert = test_cert();
    let mut server = server(&cert, echo_handler, |_| {});
    let addr = server.local_addr();

    let other = test_cert();
    let mut endpoint =
        quinn::Endpoint::client("127.0.0.1:0".parse().expect("client")).expect("endpoint");
    endpoint.set_default_client_config(h3_client_config(&other.cert_der, b"h3"));
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        endpoint.connect(addr, "localhost").expect("connect"),
    )
    .await;
    assert!(
        !matches!(result, Ok(Ok(_))),
        "connection with an unknown certificate must fail"
    );

    let mut endpoint =
        quinn::Endpoint::client("127.0.0.1:0".parse().expect("client")).expect("endpoint");
    endpoint.set_default_client_config(h3_client_config(&cert.cert_der, b"doq"));
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        endpoint.connect(addr, "localhost").expect("connect"),
    )
    .await;
    assert!(
        !matches!(result, Ok(Ok(_))),
        "connection with the wrong ALPN must fail"
    );
    server.shutdown().expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_sends_goaway_and_closes_connections() {
    let cert = test_cert();
    let mut server = server(&cert, echo_handler, |config| {
        config.shutdown_timeout = Duration::from_secs(2);
    });
    let addr = server.local_addr();
    let mut client = Client::connect(addr, &cert.cert_der).await;
    let (status, _, _) = client
        .request(
            Method::GET,
            "https://localhost/healthz".to_owned(),
            None,
            &[],
        )
        .await;
    assert_eq!(status, 200);

    let started = Instant::now();
    server.shutdown().expect("shutdown");
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(server.is_shutdown());
    assert_eq!(server.stats().active_connections, 0);

    let mut endpoint =
        quinn::Endpoint::client("127.0.0.1:0".parse().expect("client")).expect("endpoint");
    endpoint.set_default_client_config(h3_client_config(&cert.cert_der, b"h3"));
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        endpoint.connect(addr, "localhost").expect("connect"),
    )
    .await;
    assert!(
        !matches!(result, Ok(Ok(_))),
        "server must not accept new connections after shutdown"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hot_reload_applies_to_new_connections() {
    let first = test_cert();
    let second = test_cert();
    let mut server = server(&first, echo_handler, |_| {});
    let addr = server.local_addr();
    let mut client = Client::connect(addr, &first.cert_der).await;
    let (status, _, _) = client
        .request(
            Method::GET,
            "https://localhost/healthz".to_owned(),
            None,
            &[],
        )
        .await;
    assert_eq!(status, 200);

    server
        .reload(second.cert_pem.as_bytes(), second.key_pem.as_bytes())
        .expect("reload");
    let mut client = Client::connect(addr, &second.cert_der).await;
    let (status, _, _) = client
        .request(
            Method::GET,
            "https://localhost/healthz".to_owned(),
            None,
            &[],
        )
        .await;
    assert_eq!(status, 200);

    let mut endpoint =
        quinn::Endpoint::client("127.0.0.1:0".parse().expect("client")).expect("endpoint");
    endpoint.set_default_client_config(h3_client_config(&first.cert_der, b"h3"));
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        endpoint.connect(addr, "localhost").expect("connect"),
    )
    .await;
    assert!(
        !matches!(result, Ok(Ok(_))),
        "old certificate must be rejected after reload"
    );
    server.shutdown().expect("shutdown");
}
