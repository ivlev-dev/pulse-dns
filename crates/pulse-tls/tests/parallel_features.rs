//! Параллельная работа DoT, DoH/1.1, DoH/2 и DoQ на разных портах
//! с одним и тем же `DnsHandler`.

#![cfg(all(feature = "http2", feature = "doq"))]
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

use bytes::Bytes;
use common::{TlsClient, dns_query, echo_handler, test_cert, tls_client_config};
use http::{Method, Request};
use pulse_tls::{
    Doh2Config, Doh2Server, DohConfig, DohServer, DoqConfig, DoqServer, DotConfig, DotServer,
    TlsConfig,
};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

fn doq_client_config(cert_der: &[u8]) -> quinn::ClientConfig {
    use rustls::pki_types::CertificateDer;
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(cert_der.to_vec()))
        .expect("root");
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS1.3")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"doq".to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(config).expect("QUIC client");
    quinn::ClientConfig::new(Arc::new(crypto))
}

async fn doq_query(connection: &quinn::Connection, message: &[u8]) -> Vec<u8> {
    let (mut send, mut recv) = connection.open_bi().await.expect("stream");
    let length = u16::try_from(message.len()).expect("length");
    send.write_all(&length.to_be_bytes()).await.expect("prefix");
    send.write_all(message).await.expect("message");
    send.finish().expect("finish");
    let mut prefix = [0_u8; 2];
    recv.read_exact(&mut prefix).await.expect("read prefix");
    let mut response = vec![0_u8; usize::from(u16::from_be_bytes(prefix))];
    recv.read_exact(&mut response).await.expect("read body");
    response
}

async fn h2_query(addr: SocketAddr, cert_der: &[u8], query: &[u8]) -> Vec<u8> {
    let connector = TlsConnector::from(Arc::new(tls_client_config(cert_der, Some(b"h2"))));
    let stream = TcpStream::connect(addr).await.expect("tcp");
    let name = rustls::pki_types::ServerName::try_from("localhost").expect("name");
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
    let (response, mut body) = send.send_request(request, false).expect("request");
    body.send_data(Bytes::copy_from_slice(query), true)
        .expect("body");
    let response = response.await.expect("response");
    let mut recv = response.into_body();
    let mut bytes = Vec::new();
    while let Some(chunk) = recv.data().await {
        bytes.extend_from_slice(&chunk.expect("chunk"));
    }
    driver.abort();
    bytes
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn all_secure_transports_serve_in_parallel() {
    let cert = test_cert();
    let dot_tls =
        TlsConfig::for_dot(cert.cert_pem.as_bytes(), cert.key_pem.as_bytes()).expect("dot tls");
    let doh_tls =
        TlsConfig::for_doh(cert.cert_pem.as_bytes(), cert.key_pem.as_bytes()).expect("doh tls");
    let h2_tls =
        TlsConfig::for_doh2(cert.cert_pem.as_bytes(), cert.key_pem.as_bytes()).expect("h2 tls");
    let doq_tls =
        TlsConfig::for_doq(cert.cert_pem.as_bytes(), cert.key_pem.as_bytes()).expect("doq tls");
    let mut dot = DotServer::bind(
        DotConfig::new("127.0.0.1:0".parse().expect("addr"), dot_tls),
        echo_handler,
    )
    .expect("dot");
    let mut doh = DohServer::bind(
        DohConfig::new("127.0.0.1:0".parse().expect("addr"), doh_tls),
        echo_handler,
    )
    .expect("doh");
    let mut h2 = Doh2Server::bind(
        Doh2Config::new("127.0.0.1:0".parse().expect("addr"), h2_tls),
        echo_handler,
    )
    .expect("h2");
    let mut doq = DoqServer::bind(
        DoqConfig::new("127.0.0.1:0".parse().expect("addr"), doq_tls),
        echo_handler,
    )
    .expect("doq");

    let query = dns_query(77);
    let query_h2 = query.clone();
    let query_doq = dns_query(0);
    let cert_der = cert.cert_der.clone();
    let dot_addr = dot.local_addr();
    let doh_addr = doh.local_addr();
    let h2_addr = h2.local_addr();

    let sync_clients = tokio::task::spawn_blocking({
        let cert_der = cert_der.clone();
        let query = query.clone();
        move || {
            let mut dot_client =
                TlsClient::connect(dot_addr, &cert_der, Some(b"dot")).expect("dot client");
            dot_client.send_dot(&query).expect("dot send");
            let dot_response = dot_client.read_dot().expect("dot response");

            let mut doh_client =
                TlsClient::connect(doh_addr, &cert_der, Some(b"http/1.1")).expect("doh client");
            let request = format!(
                "POST /dns-query HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
                query.len()
            );
            let mut raw = request.into_bytes();
            raw.extend_from_slice(&query);
            let doh_response = doh_client.request(&raw).expect("doh response");
            (dot_response, doh_response)
        }
    });

    let h2_task = h2_query(h2_addr, &cert_der, &query_h2);
    let doq_task = async {
        let mut endpoint =
            quinn::Endpoint::client("127.0.0.1:0".parse().expect("addr")).expect("endpoint");
        endpoint.set_default_client_config(doq_client_config(&cert_der));
        let connection = endpoint
            .connect(doq.local_addr(), "localhost")
            .expect("connect")
            .await
            .expect("handshake");
        let response = doq_query(&connection, &query_doq).await;
        endpoint.close(0_u32.into(), b"done");
        response
    };

    let (sync_result, h2_response, doq_response) = tokio::join!(sync_clients, h2_task, doq_task);
    let (dot_response, doh_response) = sync_result.expect("sync clients");
    assert_eq!(dot_response, query);
    assert_eq!(doh_response.status, 200);
    assert_eq!(doh_response.body, query);
    assert_eq!(h2_response, query);
    assert_eq!(doq_response, query_doq);

    dot.shutdown().expect("dot shutdown");
    doh.shutdown().expect("doh shutdown");
    h2.shutdown().expect("h2 shutdown");
    doq.shutdown().expect("doq shutdown");
    tokio::time::sleep(Duration::from_millis(20)).await;
}
