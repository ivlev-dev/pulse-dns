//! Интеграционные тесты DoQ (RFC 9250): A/AAAA, большой ответ,
//! несколько stream'ов, неверный сертификат и idle timeout.

#![cfg(feature = "doq")]
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

use common::{TestCert, test_cert};
use pulse_dns::domain::{Message, Name, Question, Rclass, Rdata, Record, Rtype, Ttl};
use pulse_dns::wire::{DecodeLimits, EncodeOptions};
use pulse_tls::{DoqConfig, DoqServer, TlsConfig};
use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore};

fn client_config(cert_der: &[u8]) -> quinn::ClientConfig {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(cert_der.to_vec()))
        .expect("add root");
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"doq".to_vec()];
    let crypto = QuicClientConfig::try_from(config).expect("QUIC client config");
    quinn::ClientConfig::new(Arc::new(crypto))
}

async fn connect(server: SocketAddr, cert_der: &[u8]) -> (quinn::Endpoint, quinn::Connection) {
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().expect("client addr"))
        .expect("client endpoint");
    endpoint.set_default_client_config(client_config(cert_der));
    let connection = endpoint
        .connect(server, "localhost")
        .expect("connect")
        .await
        .expect("QUIC handshake");
    (endpoint, connection)
}

async fn query(connection: &quinn::Connection, message: &[u8]) -> Vec<u8> {
    let (mut send, mut recv) = connection.open_bi().await.expect("open stream");
    let length = u16::try_from(message.len()).expect("message fits");
    send.write_all(&length.to_be_bytes())
        .await
        .expect("write length");
    send.write_all(message).await.expect("write message");
    send.finish().expect("finish");
    let mut prefix = [0_u8; 2];
    recv.read_exact(&mut prefix).await.expect("read prefix");
    let length = usize::from(u16::from_be_bytes(prefix));
    let mut response = vec![0_u8; length];
    recv.read_exact(&mut response).await.expect("read response");
    response
}

fn server(
    cert: &TestCert,
    handler: impl Fn(&[u8], SocketAddr) -> Option<Vec<u8>> + Send + Sync + 'static,
    configure: impl FnOnce(&mut DoqConfig),
) -> DoqServer {
    let tls = TlsConfig::for_doq(cert.cert_pem.as_bytes(), cert.key_pem.as_bytes())
        .expect("DoQ TLS config");
    let mut config = DoqConfig::new("127.0.0.1:0".parse().expect("addr"), tls);
    config.worker_threads = 2;
    configure(&mut config);
    DoqServer::bind(config, handler).expect("bind DoQ server")
}

fn answer(_handler_type: Rtype) -> impl Fn(&[u8], SocketAddr) -> Option<Vec<u8>> {
    move |query: &[u8], _peer| {
        let message = Message::decode(query, &DecodeLimits::default()).ok()?;
        let question = message.questions().first()?.clone();
        let mut response = Message::response(&message);
        let rdata = match question.qtype() {
            Rtype::AAAA => Rdata::Aaaa("2001:db8::1".parse().expect("IPv6")),
            _ => Rdata::A("192.0.2.1".parse().expect("IPv4")),
        };
        response.add_answer(
            Record::new(
                question.qname().clone(),
                question.qtype(),
                Rclass::IN,
                Ttl::new(60).expect("ttl"),
                rdata,
            )
            .expect("record"),
        );
        response.encode(&EncodeOptions::default()).ok()
    }
}

fn query_for(id: u16, rr_type: Rtype) -> Vec<u8> {
    let name = Name::parse("example.com").expect("name");
    Message::query(id, Question::new(name, rr_type, Rclass::IN))
        .encode(&EncodeOptions::default())
        .expect("encode")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn answers_a_and_aaaa() {
    let cert = test_cert();
    let mut server = server(&cert, answer(Rtype::A), |_| {});
    let (endpoint, connection) = connect(server.local_addr(), &cert.cert_der).await;

    let response = query(&connection, &query_for(0, Rtype::A)).await;
    let message = Message::decode(&response, &DecodeLimits::default()).expect("decode A");
    assert_eq!(message.answers().len(), 1);
    assert!(
        matches!(message.answers()[0].rdata(), Rdata::A(address) if *address == std::net::Ipv4Addr::new(192, 0, 2, 1))
    );

    let response = query(&connection, &query_for(0, Rtype::AAAA)).await;
    let message = Message::decode(&response, &DecodeLimits::default()).expect("decode AAAA");
    assert!(
        matches!(message.answers()[0].rdata(), Rdata::Aaaa(address) if *address == "2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap())
    );

    assert_eq!(server.stats().queries, 2);
    assert_eq!(server.stats().responses, 2);
    drop(endpoint);
    server.shutdown().expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multiple_streams_are_multiplexed() {
    let cert = test_cert();
    let mut server = server(&cert, answer(Rtype::A), |config| {
        config.max_streams = 16;
    });
    let (_endpoint, connection) = connect(server.local_addr(), &cert.cert_der).await;
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0_u16..8 {
        let connection = connection.clone();
        tasks.spawn(async move {
            let response = query(&connection, &query_for(0, Rtype::A)).await;
            let message =
                Message::decode(&response, &DecodeLimits::default()).expect("decode stream");
            assert_eq!(message.id(), 0);
            assert_eq!(message.answers().len(), 1);
        });
    }
    while let Some(result) = tasks.join_next().await {
        result.expect("stream task");
    }
    assert_eq!(server.stats().queries, 8);
    server.shutdown().expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn large_response_is_not_truncated() {
    let cert = test_cert();
    let mut server = server(
        &cert,
        |query: &[u8], _peer| {
            let message = Message::decode(query, &DecodeLimits::default()).ok()?;
            let mut response = Message::response(&message);
            for index in 0_u8..40 {
                response.add_answer(
                    Record::new(
                        Name::parse("example.com").ok()?,
                        Rtype::A,
                        Rclass::IN,
                        Ttl::new(60).ok()?,
                        Rdata::A(std::net::Ipv4Addr::new(192, 0, 2, index)),
                    )
                    .ok()?,
                );
            }
            response.encode(&EncodeOptions::default()).ok()
        },
        |_| {},
    );
    let (_endpoint, connection) = connect(server.local_addr(), &cert.cert_der).await;
    let response = query(&connection, &query_for(0, Rtype::A)).await;
    assert!(response.len() > 512);
    let message = Message::decode(&response, &DecodeLimits::default()).expect("decode");
    assert_eq!(message.answers().len(), 40);
    server.shutdown().expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_zero_message_id_gets_formerr() {
    let cert = test_cert();
    let mut server = server(&cert, answer(Rtype::A), |_| {});
    let (_endpoint, connection) = connect(server.local_addr(), &cert.cert_der).await;
    let response = query(&connection, &query_for(7, Rtype::A)).await;
    let message = Message::decode(&response, &DecodeLimits::default()).expect("decode");
    assert_eq!(message.id(), 0);
    assert_eq!(message.rcode(), pulse_dns::domain::Rcode::FORMERR);
    server.shutdown().expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_wrong_certificate() {
    let cert = test_cert();
    let other = test_cert();
    let mut server = server(&cert, answer(Rtype::A), |_| {});
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().expect("client addr"))
        .expect("client endpoint");
    endpoint.set_default_client_config(client_config(&other.cert_der));
    let result = endpoint
        .connect(server.local_addr(), "localhost")
        .expect("connect")
        .await;
    assert!(result.is_err());
    server.shutdown().expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reload_applies_to_new_connections() {
    let first = test_cert();
    let second = test_cert();
    let mut server = server(&first, answer(Rtype::A), |_| {});
    let addr = server.local_addr();
    let (_endpoint, connection) = connect(addr, &first.cert_der).await;
    let response = query(&connection, &query_for(0, Rtype::A)).await;
    assert_eq!(
        Message::decode(&response, &DecodeLimits::default())
            .expect("decode")
            .answers()
            .len(),
        1
    );

    server
        .reload(second.cert_pem.as_bytes(), second.key_pem.as_bytes())
        .expect("reload");
    let (_endpoint, connection) = connect(addr, &second.cert_der).await;
    let response = query(&connection, &query_for(0, Rtype::A)).await;
    assert_eq!(
        Message::decode(&response, &DecodeLimits::default())
            .expect("decode")
            .answers()
            .len(),
        1
    );

    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().expect("client addr"))
        .expect("client endpoint");
    endpoint.set_default_client_config(client_config(&first.cert_der));
    assert!(
        endpoint
            .connect(addr, "localhost")
            .expect("connect")
            .await
            .is_err()
    );
    server.shutdown().expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idle_timeout_closes_connection() {
    let cert = test_cert();
    let mut server = server(&cert, answer(Rtype::A), |config| {
        config.idle_timeout = Duration::from_millis(200);
    });
    let (_endpoint, connection) = connect(server.local_addr(), &cert.cert_der).await;
    assert!(query(&connection, &query_for(0, Rtype::A)).await.len() > 12);
    tokio::time::sleep(Duration::from_secs(1)).await;
    let closed = tokio::time::timeout(Duration::from_secs(2), connection.closed()).await;
    assert!(
        closed.is_ok(),
        "server idle timeout must close the connection"
    );
    server.shutdown().expect("shutdown");
}
