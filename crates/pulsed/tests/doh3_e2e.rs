//! e2e `pulsed`: DoH/HTTP/3 (RFC 9114 + RFC 8484) поверх QUIC вместе с
//! UDP/TCP/DoT/DoH1/DoH2/DoQ, `/metrics`, мультиплексирование и reload.

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

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use http::{Method, Request};
use pulse_dns::{DecodeLimits, EncodeOptions, Message, Name, Question, Rclass, Rdata, Rtype};
use pulse_tls::client::{DohClient, DotClient};
use pulsed::config::Config;
use pulsed::server::Server;
use quinn::crypto::rustls::QuicClientConfig;
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};

struct TestCert {
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
    cert_der: Vec<u8>,
}

impl TestCert {
    fn generate() -> Self {
        let key = KeyPair::generate().expect("key");
        let params = CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
            .expect("params");
        let certificate = params.self_signed(&key).expect("self-signed");
        Self {
            cert_pem: certificate.pem().into_bytes(),
            key_pem: key.serialize_pem().into_bytes(),
            cert_der: certificate.der().to_vec(),
        }
    }
}

fn write_private(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).expect("write key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    }
}

fn cert_pair(dir: &Path, cert: &TestCert) -> (PathBuf, PathBuf) {
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, &cert.cert_pem).expect("write cert");
    write_private(&key_path, &cert.key_pem);
    (cert_path, key_path)
}

fn dns_query(name: &str, rr_type: Rtype, id: u16) -> Vec<u8> {
    Message::query(
        id,
        Question::new(Name::parse(name).expect("name"), rr_type, Rclass::IN),
    )
    .encode(&EncodeOptions::compressed())
    .expect("encode")
}

fn decode(bytes: &[u8]) -> Message {
    Message::decode(bytes, &DecodeLimits::default()).expect("decode")
}

fn a_records(message: &Message) -> Vec<String> {
    message
        .answers()
        .iter()
        .filter_map(|record| match record.rdata() {
            Rdata::A(address) => Some(address.to_string()),
            _ => None,
        })
        .collect()
}

fn secure_config(zone: &common::TempZone, cert: &TestCert, dir: &Path) -> Config {
    let (cert_path, key_path) = cert_pair(dir, cert);
    let mut config = common::base_config(zone.path());
    config.dot_listen = Some("127.0.0.1:0".parse().expect("dot"));
    config.doh_listen = Some("127.0.0.1:0".parse().expect("doh"));
    config.doh_h2_listen = Some("127.0.0.1:0".parse().expect("doh2"));
    config.doh3_listen = Some("127.0.0.1:0".parse().expect("doh3"));
    config.doq_listen = Some("127.0.0.1:0".parse().expect("doq"));
    config.tls_cert = Some(cert_path);
    config.tls_key = Some(key_path);
    config.doq_idle_timeout_ms = 2_000;
    config.doh3_idle_timeout_ms = 2_000;
    config
}

fn udp_query(addr: SocketAddr, query: &[u8]) -> Vec<u8> {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("udp socket");
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    common::udp_send_to(&socket, query, addr).expect("udp send");
    let mut buffer = [0_u8; 4096];
    let (length, _) = common::udp_recv_from(&socket, &mut buffer).expect("udp recv");
    buffer.get(..length).expect("bounds").to_vec()
}

fn tcp_query(addr: SocketAddr, query: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(addr).expect("tcp connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let length = u16::try_from(query.len()).expect("length");
    stream.write_all(&length.to_be_bytes()).expect("prefix");
    stream.write_all(query).expect("query");
    let mut prefix = [0_u8; 2];
    stream.read_exact(&mut prefix).expect("read prefix");
    let mut response = vec![0_u8; usize::from(u16::from_be_bytes(prefix))];
    stream.read_exact(&mut response).expect("read body");
    response
}

fn rustls_roots(cert_der: &[u8]) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(cert_der.to_vec()))
        .expect("root");
    roots
}

fn h2_client_config(cert_der: &[u8]) -> ClientConfig {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .expect("versions")
        .with_root_certificates(rustls_roots(cert_der))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    config
}

fn quic_base_client_config(cert_der: &[u8], alpn: &[u8]) -> ClientConfig {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS1.3")
        .with_root_certificates(rustls_roots(cert_der))
        .with_no_client_auth();
    config.alpn_protocols = vec![alpn.to_vec()];
    config
}

fn doq_client_config(cert_der: &[u8]) -> quinn::ClientConfig {
    let crypto =
        QuicClientConfig::try_from(quic_base_client_config(cert_der, b"doq")).expect("QUIC client");
    quinn::ClientConfig::new(Arc::new(crypto))
}

fn h3_client_config(cert_der: &[u8]) -> quinn::ClientConfig {
    let crypto =
        QuicClientConfig::try_from(quic_base_client_config(cert_der, b"h3")).expect("QUIC client");
    quinn::ClientConfig::new(Arc::new(crypto))
}

async fn h2_query(addr: SocketAddr, cert_der: &[u8], query: &[u8]) -> Vec<u8> {
    let connector = tokio_rustls::TlsConnector::from(Arc::new(h2_client_config(cert_der)));
    let stream = tokio::net::TcpStream::connect(addr).await.expect("tcp");
    let name = ServerName::try_from("localhost").expect("name");
    let tls = connector.connect(name, stream).await.expect("TLS");
    let (mut send, connection) = h2::client::handshake(tls).await.expect("h2");
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = Request::builder()
        .method(Method::POST)
        .uri("https://localhost/dns-query")
        .header("content-type", "application/dns-message")
        .body(())
        .expect("request");
    let (response, mut body) = send.send_request(request, false).expect("send");
    body.send_data(Bytes::copy_from_slice(query), true)
        .expect("body");
    let response = response.await.expect("response");
    assert_eq!(response.status().as_u16(), 200);
    let mut recv = response.into_body();
    let mut bytes = Vec::new();
    while let Some(chunk) = recv.data().await {
        bytes.extend_from_slice(&chunk.expect("chunk"));
    }
    driver.abort();
    bytes
}

async fn doq_query(connection: &quinn::Connection, query: &[u8]) -> Vec<u8> {
    let (mut send, mut recv) = connection.open_bi().await.expect("stream");
    let length = u16::try_from(query.len()).expect("length");
    send.write_all(&length.to_be_bytes()).await.expect("prefix");
    send.write_all(query).await.expect("query");
    send.finish().expect("finish");
    let mut prefix = [0_u8; 2];
    recv.read_exact(&mut prefix).await.expect("read prefix");
    let mut response = vec![0_u8; usize::from(u16::from_be_bytes(prefix))];
    recv.read_exact(&mut response).await.expect("read body");
    response
}

struct H3Client {
    send: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    _driver: tokio::task::JoinHandle<()>,
    _endpoint: quinn::Endpoint,
}

impl H3Client {
    async fn connect(addr: SocketAddr, cert_der: &[u8], alpn: &[u8]) -> Self {
        let mut endpoint =
            quinn::Endpoint::client("127.0.0.1:0".parse().expect("client")).expect("endpoint");
        let config = if alpn == b"h3" {
            h3_client_config(cert_der)
        } else {
            let crypto = QuicClientConfig::try_from(quic_base_client_config(cert_der, alpn))
                .expect("QUIC client");
            quinn::ClientConfig::new(Arc::new(crypto))
        };
        endpoint.set_default_client_config(config);
        let connection = endpoint
            .connect(addr, "localhost")
            .expect("connect")
            .await
            .expect("QUIC handshake");
        let (mut h3_connection, send) = h3::client::new(h3_quinn::Connection::new(connection))
            .await
            .expect("HTTP/3 handshake");
        let driver = tokio::spawn(async move {
            let _ = h3_connection.wait_idle().await;
        });
        Self {
            send,
            _driver: driver,
            _endpoint: endpoint,
        }
    }

    async fn query(&mut self, query: &[u8]) -> (u16, Vec<u8>) {
        let request = Request::builder()
            .method(Method::POST)
            .uri("https://localhost/dns-query")
            .header("content-type", "application/dns-message")
            .body(())
            .expect("request");
        let mut stream = self.send.send_request(request).await.expect("send request");
        stream
            .send_data(Bytes::copy_from_slice(query))
            .await
            .expect("body");
        stream.finish().await.expect("finish");
        let response = stream.recv_response().await.expect("response");
        let status = response.status().as_u16();
        let mut body = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await.expect("chunk") {
            while chunk.has_remaining() {
                let bytes = chunk.chunk();
                body.extend_from_slice(bytes);
                let advance = bytes.len();
                chunk.advance(advance);
            }
        }
        (status, body)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn all_transports_answer_in_parallel_and_export_http3_metrics() {
    let zone = common::TempZone::with_import("h3", "example.com.", &common::example_zone());
    let cert = TestCert::generate();
    let cert_dir = tempfile::tempdir().expect("cert dir");
    let (cert_path, _) = cert_pair(cert_dir.path(), &cert);
    let config = secure_config(&zone, &cert, cert_dir.path());
    let mut server = Server::start(&config).expect("start server");

    let query = dns_query("www.example.com.", Rtype::A, 0x2001);
    let udp = udp_query(server.udp_addr().expect("udp"), &query);
    let tcp = tcp_query(server.tcp_addr().expect("tcp"), &query);
    let dot = DotClient::from_addr(
        server.dot_addr().expect("dot"),
        "localhost",
        Some(&cert_path),
    )
    .expect("dot client")
    .query(&query, Duration::from_secs(5), Duration::from_secs(5))
    .expect("dot query");
    let doh = DohClient::new(
        &format!(
            "https://127.0.0.1:{}/dns-query#localhost",
            server.doh_addr().expect("doh").port()
        ),
        Some(&cert_path),
    )
    .expect("doh client")
    .query(&query, Duration::from_secs(5), Duration::from_secs(5))
    .expect("doh query");
    let h2 = h2_query(server.doh_h2_addr().expect("h2"), &cert.cert_der, &query).await;

    let mut endpoint =
        quinn::Endpoint::client("127.0.0.1:0".parse().expect("client")).expect("endpoint");
    endpoint.set_default_client_config(doq_client_config(&cert.cert_der));
    let doq_connection = endpoint
        .connect(server.doq_addr().expect("doq"), "localhost")
        .expect("connect")
        .await
        .expect("handshake");
    // RFC 9250 §4.2: DoQ-запрос должен иметь ID 0.
    let doq = doq_query(&doq_connection, &dns_query("www.example.com.", Rtype::A, 0)).await;

    let mut h3 = H3Client::connect(server.doh3_addr().expect("h3"), &cert.cert_der, b"h3").await;
    let (status, h3_body) = h3.query(&query).await;
    assert_eq!(status, 200);
    assert_eq!(a_records(&decode(&h3_body)), vec!["192.0.2.20"]);

    for (label, response) in [
        ("udp", &udp),
        ("tcp", &tcp),
        ("dot", &dot),
        ("doh", &doh),
        ("h2", &h2),
        ("doq", &doq),
    ] {
        assert_eq!(a_records(&decode(response)), vec!["192.0.2.20"], "{label}");
    }

    let stats = server.doh3_stats().expect("h3 stats");
    assert!(stats.queries >= 1, "{stats:?}");
    assert!(stats.http_requests >= 1, "{stats:?}");
    let metrics = server.transport_metrics();
    assert!(metrics.contains("doh_http3_queries_total"), "{metrics}");
    assert!(
        metrics.contains("doh_http3_http_requests_total"),
        "{metrics}"
    );

    endpoint.close(0_u32.into(), b"done");
    server.shutdown().expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http3_multiplexes_requests_and_handles_nxdomain() {
    let zone = common::TempZone::with_import("h3-mux", "example.com.", &common::example_zone());
    let cert = TestCert::generate();
    let cert_dir = tempfile::tempdir().expect("cert dir");
    let mut config = secure_config(&zone, &cert, cert_dir.path());
    config.doh3_max_concurrent_requests = 32;
    let mut server = Server::start(&config).expect("start server");
    let mut client =
        H3Client::connect(server.doh3_addr().expect("h3"), &cert.cert_der, b"h3").await;

    let mut streams = Vec::new();
    for id in 0_u16..10 {
        let query = dns_query("example.com.", Rtype::A, 0x3000 + id);
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
        let mut body = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await.expect("chunk") {
            while chunk.has_remaining() {
                let bytes = chunk.chunk();
                body.extend_from_slice(bytes);
                let advance = bytes.len();
                chunk.advance(advance);
            }
        }
        assert_eq!(decode(&body).id(), 0x3000 + id);
        assert_eq!(a_records(&decode(&body)), vec!["192.0.2.10"]);
    }

    let missing = dns_query("missing.example.com.", Rtype::A, 0x4000);
    let (status, body) = client.query(&missing).await;
    assert_eq!(status, 200);
    assert_eq!(decode(&body).rcode(), pulse_dns::Rcode::NXDOMAIN);

    assert_eq!(server.doh3_stats().expect("h3 stats").queries, 11);
    let metrics = server.transport_metrics();
    assert!(metrics.contains("doh_http3_queries_total"), "{metrics}");
    server.shutdown().expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http3_certificate_reload_applies_to_new_connections() {
    let zone = common::TempZone::with_import("h3-reload", "example.com.", &common::example_zone());
    let first = TestCert::generate();
    let second = TestCert::generate();
    let cert_dir = tempfile::tempdir().expect("cert dir");
    let config = secure_config(&zone, &first, cert_dir.path());
    let mut server = Server::start(&config).expect("start server");
    let addr = server.doh3_addr().expect("h3");
    let mut client = H3Client::connect(addr, &first.cert_der, b"h3").await;
    let query = dns_query("www.example.com.", Rtype::A, 0x5001);
    assert_eq!(client.query(&query).await.0, 200);

    cert_pair(cert_dir.path(), &second);
    server.reload_tls().expect("reload");

    let mut new_client = H3Client::connect(addr, &second.cert_der, b"h3").await;
    assert_eq!(new_client.query(&query).await.0, 200);

    let mut endpoint =
        quinn::Endpoint::client("127.0.0.1:0".parse().expect("client")).expect("endpoint");
    endpoint.set_default_client_config(h3_client_config(&first.cert_der));
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
