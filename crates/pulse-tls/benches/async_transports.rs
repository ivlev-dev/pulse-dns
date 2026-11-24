#![allow(missing_docs)]

//! Benchmarks: DoH/HTTP/2 с мультиплексированием и DoQ round-trip.
//!
//! Запуск: `cargo bench -p pulse-tls --features http2,doq --bench async_transports`.
//! Числа на loopback зависят от загрузки хоста и не являются SLA.

#![allow(
    clippy::doc_markdown,
    clippy::similar_names,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::if_not_else
)]

use std::hint::black_box;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use http::{Method, Request};
use pulse_dns::{EncodeOptions, Message, Name, Question, Rclass, Rtype};
use pulse_tls::{Doh2Config, Doh2Server, DoqConfig, DoqServer, TlsConfig};

#[path = "../tests/common/mod.rs"]
mod common;

use common::{echo_handler, test_cert, tls_client_config};

const MULTIPLEX_STREAMS: usize = 10;

fn dns_query(id: u16) -> Vec<u8> {
    let name = Name::parse("example.com").expect("name");
    Message::query(id, Question::new(name, Rtype::A, Rclass::IN))
        .encode(&EncodeOptions::default())
        .expect("encode")
}

fn h2_client(
    runtime: &tokio::runtime::Runtime,
    addr: SocketAddr,
    cert_der: &[u8],
) -> h2::client::SendRequest<Bytes> {
    runtime.block_on(async {
        use tokio::net::TcpStream;
        let connector =
            tokio_rustls::TlsConnector::from(Arc::new(tls_client_config(cert_der, Some(b"h2"))));
        let stream = TcpStream::connect(addr).await.expect("tcp");
        let name = rustls::pki_types::ServerName::try_from("localhost").expect("name");
        let tls = connector.connect(name, stream).await.expect("TLS");
        let (send, connection) = h2::client::handshake(tls).await.expect("h2");
        tokio::spawn(async move {
            let _ = connection.await;
        });
        send
    })
}

fn h2_roundtrip(
    runtime: &tokio::runtime::Runtime,
    send: &mut h2::client::SendRequest<Bytes>,
    query: &[u8],
    streams: usize,
) {
    runtime.block_on(async {
        let mut pending = Vec::with_capacity(streams);
        for _ in 0..streams {
            let request = Request::builder()
                .method(Method::POST)
                .uri("https://localhost/dns-query")
                .header("content-type", "application/dns-message")
                .body(())
                .expect("request");
            let (response, mut body) = send.send_request(request, false).expect("send");
            body.send_data(Bytes::copy_from_slice(query), true)
                .expect("body");
            pending.push(response);
        }
        for response in pending {
            let response = response.await.expect("response");
            let mut body = response.into_body();
            let mut bytes = Vec::new();
            while let Some(chunk) = body.data().await {
                bytes.extend_from_slice(&chunk.expect("chunk"));
            }
            black_box(bytes);
        }
    });
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

fn doh_h2_benchmark(criterion: &mut Criterion) {
    let cert = test_cert();
    let tls =
        TlsConfig::for_doh2(cert.cert_pem.as_bytes(), cert.key_pem.as_bytes()).expect("h2 tls");
    let mut config = Doh2Config::new("127.0.0.1:0".parse().expect("addr"), tls);
    config.max_concurrent_streams = 64;
    config.idle_timeout = Duration::from_secs(60);
    let mut server = Doh2Server::bind(config, echo_handler).expect("h2 server");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    let mut client = h2_client(&runtime, server.local_addr(), &cert.cert_der);
    let query = dns_query(0);

    let mut group = criterion.benchmark_group("doh_http2");
    group.throughput(Throughput::Elements(
        u64::try_from(MULTIPLEX_STREAMS).expect("streams"),
    ));
    group.bench_function("multiplexed_qps", |bencher| {
        bencher.iter(|| {
            h2_roundtrip(&runtime, &mut client, black_box(&query), MULTIPLEX_STREAMS);
        });
    });
    group.finish();
    server.shutdown().expect("shutdown");
}

fn doq_benchmark(criterion: &mut Criterion) {
    let cert = test_cert();
    let tls =
        TlsConfig::for_doq(cert.cert_pem.as_bytes(), cert.key_pem.as_bytes()).expect("doq tls");
    let mut config = DoqConfig::new("127.0.0.1:0".parse().expect("addr"), tls);
    config.max_streams = 64;
    config.idle_timeout = Duration::from_secs(60);
    let mut server = DoqServer::bind(config, echo_handler).expect("doq server");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    let (endpoint, connection) = runtime.block_on(async {
        let mut endpoint =
            quinn::Endpoint::client("127.0.0.1:0".parse().expect("client addr")).expect("endpoint");
        endpoint.set_default_client_config(doq_client_config(&cert.cert_der));
        let connection = endpoint
            .connect(server.local_addr(), "localhost")
            .expect("connect")
            .await
            .expect("handshake");
        (endpoint, connection)
    });
    let query = dns_query(0);

    let mut group = criterion.benchmark_group("doq");
    group.throughput(Throughput::Elements(1));
    group.bench_function("roundtrip_qps", |bencher| {
        bencher.iter(|| {
            let response = runtime.block_on(doq_query(&connection, black_box(&query)));
            black_box(response);
        });
    });
    group.finish();
    endpoint.close(0_u32.into(), b"done");
    server.shutdown().expect("shutdown");
}

fn benchmarks(criterion: &mut Criterion) {
    doh_h2_benchmark(criterion);
    doq_benchmark(criterion);
}

criterion_group!(benches, benchmarks);
criterion_main!(benches);
