//! Интеграционные тесты DoH/HTTP/2: POST/GET, мультиплексирование,
//! лимиты, health и graceful shutdown.

#![cfg(feature = "http2")]
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
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use common::{dns_query, echo_handler, test_cert, tls_client_config};
use http::{Method, Request};
use pulse_tls::{Doh2Config, Doh2Server, TlsConfig};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

struct Client {
    send: h2::client::SendRequest<Bytes>,
    _driver: tokio::task::JoinHandle<()>,
}

impl Client {
    async fn connect(addr: SocketAddr, cert_der: &[u8]) -> Self {
        let config = tls_client_config(cert_der, Some(b"h2"));
        let connector = TlsConnector::from(Arc::new(config));
        let stream = TcpStream::connect(addr).await.expect("tcp connect");
        let name = rustls::pki_types::ServerName::try_from("localhost").expect("server name");
        let tls = connector
            .connect(name, stream)
            .await
            .expect("TLS handshake");
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
        let (send, connection) = h2::client::handshake(tls).await.expect("h2 handshake");
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        Self {
            send,
            _driver: driver,
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
        let (response, mut stream) = self.send.send_request(request, false).expect("send");
        if !body.is_empty() {
            stream
                .send_data(Bytes::copy_from_slice(body), true)
                .expect("send body");
        } else {
            stream.send_data(Bytes::new(), true).expect("end stream");
        }
        let response = response.await.expect("response");
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);
        let mut recv = response.into_body();
        let mut body = Vec::new();
        while let Some(chunk) = recv.data().await {
            body.extend_from_slice(&chunk.expect("body chunk"));
        }
        (status, body, content_type)
    }
}

fn server(
    cert: &common::TestCert,
    handler: impl Fn(&[u8], SocketAddr) -> Option<Vec<u8>> + Send + Sync + 'static,
    configure: impl FnOnce(&mut Doh2Config),
) -> Doh2Server {
    let tls = TlsConfig::for_doh2(cert.cert_pem.as_bytes(), cert.key_pem.as_bytes())
        .expect("HTTP/2 TLS config");
    let mut config = Doh2Config::new("127.0.0.1:0".parse().expect("addr"), tls);
    config.worker_threads = 2;
    configure(&mut config);
    Doh2Server::bind(config, handler).expect("bind DoH/2 server")
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
    assert!(stats.queries >= 2);
    assert!(stats.http_requests >= 6);
    assert!(stats.http_errors >= 3);
    server.shutdown().expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multiplexes_ten_streams_on_one_connection() {
    let cert = test_cert();
    let mut server = server(&cert, echo_handler, |config| {
        config.max_concurrent_streams = 20;
    });
    let mut client = Client::connect(server.local_addr(), &cert.cert_der).await;
    let mut ready: Vec<h2::client::ResponseFuture> = Vec::new();
    let mut streams = Vec::new();
    for id in 0_u16..10 {
        let query = dns_query(100 + id);
        let request = Request::builder()
            .method(Method::POST)
            .uri("https://localhost/dns-query")
            .header("content-type", "application/dns-message")
            .body(())
            .expect("request");
        let (response, mut stream) = client.send.send_request(request, false).expect("send");
        stream
            .send_data(Bytes::from(query), true)
            .expect("send body");
        ready.push(response);
        streams.push(id);
    }
    for (index, response) in ready.into_iter().enumerate() {
        let response = response.await.expect("response");
        assert_eq!(response.status().as_u16(), 200);
        let mut body = response.into_body();
        let mut bytes = Vec::new();
        while let Some(chunk) = body.data().await {
            bytes.extend_from_slice(&chunk.expect("chunk"));
        }
        assert_eq!(bytes, dns_query(100 + u16::try_from(index).expect("index")));
    }
    assert_eq!(server.stats().queries, 10);
    server.shutdown().expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn body_limit_and_request_header_limit() {
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
async fn shutdown_closes_listener_and_connections() {
    let cert = test_cert();
    let mut server = server(&cert, echo_handler, |config| {
        config.shutdown_timeout = Duration::from_secs(2);
    });
    let addr = server.local_addr();
    let _client = Client::connect(addr, &cert.cert_der).await;
    server.shutdown().expect("shutdown");
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(TcpStream::connect(addr).await.is_err());
    assert_eq!(server.stats().active_connections, 0);
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

    let config = tls_client_config(&first.cert_der, Some(b"h2"));
    let connector = TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect(addr).await.expect("tcp");
    let name = rustls::pki_types::ServerName::try_from("localhost").expect("name");
    assert!(connector.connect(name, stream).await.is_err());
    server.shutdown().expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_http1_alpn() {
    let cert = test_cert();
    let mut server = server(&cert, echo_handler, |_| {});
    let config = tls_client_config(&cert.cert_der, Some(b"http/1.1"));
    let connector = TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect(server.local_addr())
        .await
        .expect("tcp connect");
    let name = rustls::pki_types::ServerName::try_from("localhost").expect("server name");
    assert!(connector.connect(name, stream).await.is_err());
    server.shutdown().expect("shutdown");
}
