//! e2e `pulsed`: DoH/HTTP/2 и DoQ отвечают из mmap теми же данными, что
//! UDP/TCP, работают параллельно и попадают в `/metrics`.

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
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request};
use pulse_dns::{DecodeLimits, EncodeOptions, Message, Name, Question, Rclass, Rdata, Rtype};
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
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod key");
    }
}

fn cert_pair(dir: &Path, cert: &TestCert) -> (PathBuf, PathBuf) {
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, &cert.cert_pem).expect("write cert");
    write_private(&key_path, &cert.key_pem);
    (cert_path, key_path)
}

fn dns_query(name: &str, rr_type: Rtype) -> Vec<u8> {
    let name = Name::parse(name).expect("name");
    Message::query(0, Question::new(name, rr_type, Rclass::IN))
        .encode(&EncodeOptions::compressed())
        .expect("encode query")
}

fn decode(bytes: &[u8]) -> Message {
    Message::decode(bytes, &DecodeLimits::default()).expect("decode")
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

fn doq_client_config(cert_der: &[u8]) -> quinn::ClientConfig {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS1.3")
        .with_root_certificates(rustls_roots(cert_der))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"doq".to_vec()];
    let crypto = QuicClientConfig::try_from(config).expect("QUIC");
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

fn secure_config(zone: &common::TempZone, cert: &TestCert, dir: &Path) -> Config {
    let (cert_path, key_path) = cert_pair(dir, cert);
    let mut config = common::base_config(zone.path());
    config.dot_listen = Some("127.0.0.1:0".parse().expect("dot"));
    config.doh_listen = Some("127.0.0.1:0".parse().expect("doh"));
    config.doh_h2_listen = Some("127.0.0.1:0".parse().expect("doh2"));
    config.doq_listen = Some("127.0.0.1:0".parse().expect("doq"));
    config.tls_cert = Some(cert_path);
    config.tls_key = Some(key_path);
    config.doq_idle_timeout_ms = 2_000;
    config
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn doh_h2_and_doq_answer_from_mmap() {
    let zone = common::TempZone::with_import("h2doq", "example.com.", &common::example_zone());
    let cert = TestCert::generate();
    let cert_dir = tempfile::tempdir().expect("cert dir");
    let config = secure_config(&zone, &cert, cert_dir.path());
    let mut server = Server::start(&config).expect("start server");

    let h2_addr = server.doh_h2_addr().expect("h2 addr");
    let doq_addr = server.doq_addr().expect("doq addr");
    let query = dns_query("example.com.", Rtype::A);
    let response = h2_query(h2_addr, &cert.cert_der, &query).await;
    let message = decode(&response);
    assert!(message.answers().iter().any(
        |record| matches!(record.rdata(), Rdata::A(address) if *address == "192.0.2.10".parse::<std::net::Ipv4Addr>().unwrap())
    ));

    let mut endpoint =
        quinn::Endpoint::client("127.0.0.1:0".parse().expect("client")).expect("endpoint");
    endpoint.set_default_client_config(doq_client_config(&cert.cert_der));
    let connection = endpoint
        .connect(doq_addr, "localhost")
        .expect("connect")
        .await
        .expect("handshake");
    let aaaa = dns_query("example.com.", Rtype::AAAA);
    let response = doq_query(&connection, &aaaa).await;
    let message = decode(&response);
    assert!(message.answers().iter().any(
        |record| matches!(record.rdata(), Rdata::Aaaa(address) if *address == "2001:db8::10".parse::<std::net::Ipv6Addr>().unwrap())
    ));

    assert!(server.doh_h2_stats().expect("h2 stats").queries >= 1);
    assert!(server.doq_stats().expect("doq stats").queries >= 1);
    let metrics = server.transport_metrics();
    assert!(metrics.contains("doh_http2_queries_total"), "{metrics}");
    assert!(metrics.contains("doq_queries_total"), "{metrics}");
    assert!(
        metrics.contains("doh_http2_http_requests_total"),
        "{metrics}"
    );

    endpoint.close(0_u32.into(), b"done");
    server.shutdown().expect("shutdown");
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(std::net::TcpStream::connect(h2_addr).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_multiplex_and_doq_multiple_streams() {
    let zone = common::TempZone::with_import("h2doq-mux", "example.com.", &common::example_zone());
    let cert = TestCert::generate();
    let cert_dir = tempfile::tempdir().expect("cert dir");
    let mut config = secure_config(&zone, &cert, cert_dir.path());
    config.doh_h2_max_streams = 32;
    config.doq_max_streams = 32;
    let mut server = Server::start(&config).expect("start server");

    let connector = tokio_rustls::TlsConnector::from(Arc::new(h2_client_config(&cert.cert_der)));
    let stream = tokio::net::TcpStream::connect(server.doh_h2_addr().expect("h2"))
        .await
        .expect("tcp");
    let name = ServerName::try_from("localhost").expect("name");
    let tls = connector.connect(name, stream).await.expect("TLS");
    let (mut send, connection) = h2::client::handshake(tls).await.expect("h2");
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let query = dns_query("www.example.com.", Rtype::A);
    let mut pending = Vec::new();
    for _ in 0..10 {
        let request = Request::builder()
            .method(Method::POST)
            .uri("https://localhost/dns-query")
            .header("content-type", "application/dns-message")
            .body(())
            .expect("request");
        let (response, mut body) = send.send_request(request, false).expect("send");
        body.send_data(Bytes::from(query.clone()), true)
            .expect("body");
        pending.push(response);
    }
    for response in pending {
        let response = response.await.expect("response");
        assert_eq!(response.status().as_u16(), 200);
    }

    let mut endpoint =
        quinn::Endpoint::client("127.0.0.1:0".parse().expect("client")).expect("endpoint");
    endpoint.set_default_client_config(doq_client_config(&cert.cert_der));
    let connection = endpoint
        .connect(server.doq_addr().expect("doq"), "localhost")
        .expect("connect")
        .await
        .expect("handshake");
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..6 {
        let connection = connection.clone();
        let query = query.clone();
        tasks.spawn(async move {
            let response = doq_query(&connection, &query).await;
            assert_eq!(decode(&response).answers().len(), 1);
        });
    }
    while let Some(result) = tasks.join_next().await {
        result.expect("doq task");
    }

    assert_eq!(server.doh_h2_stats().expect("h2 stats").queries, 10);
    assert_eq!(server.doq_stats().expect("doq stats").queries, 6);
    driver.abort();
    endpoint.close(0_u32.into(), b"done");
    server.shutdown().expect("shutdown");
}
