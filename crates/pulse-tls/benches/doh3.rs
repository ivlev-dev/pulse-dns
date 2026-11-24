#![allow(missing_docs)]

//! Benchmark DoH/HTTP/3 на loopback: одиночный round-trip и
//! мультиплексированные запросы на одном QUIC-соединении.
//!
//! Запуск: `cargo bench -p pulse-tls --features http3 --bench doh3`.
//! Числа зависят от загрузки хоста и не являются SLA.

#![allow(
    clippy::doc_markdown,
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

use bytes::{Buf, Bytes};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use http::{Method, Request};
use pulse_dns::{EncodeOptions, Message, Name, Question, Rclass, Rtype};
use pulse_tls::{Doh3Config, Doh3Server, TlsConfig};
use quinn::crypto::rustls::QuicClientConfig;

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

fn h3_client_config(cert_der: &[u8]) -> quinn::ClientConfig {
    let config = tls_client_config(cert_der, Some(b"h3"));
    let crypto = QuicClientConfig::try_from(config).expect("QUIC client config");
    quinn::ClientConfig::new(Arc::new(crypto))
}

struct Client {
    send: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    _driver: tokio::task::JoinHandle<()>,
    _endpoint: quinn::Endpoint,
}

impl Client {
    fn connect(runtime: &tokio::runtime::Runtime, addr: SocketAddr, cert_der: &[u8]) -> Self {
        runtime.block_on(async {
            let mut endpoint =
                quinn::Endpoint::client("127.0.0.1:0".parse().expect("addr")).expect("endpoint");
            endpoint.set_default_client_config(h3_client_config(cert_der));
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
        })
    }

    async fn send(
        send: &mut h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
        query: &[u8],
    ) -> h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes> {
        let request = Request::builder()
            .method(Method::POST)
            .uri("https://localhost/dns-query")
            .header("content-type", "application/dns-message")
            .body(())
            .expect("request");
        let mut stream = send.send_request(request).await.expect("send request");
        stream
            .send_data(Bytes::copy_from_slice(query))
            .await
            .expect("body");
        stream.finish().await.expect("finish");
        stream
    }

    async fn read(
        mut stream: h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    ) -> Vec<u8> {
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
        body
    }
}

fn single_roundtrip(
    runtime: &tokio::runtime::Runtime,
    send: &mut h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    query: &[u8],
) {
    runtime.block_on(async {
        let stream = Client::send(send, query).await;
        black_box(Client::read(stream).await);
    });
}

fn multiplexed_roundtrip(
    runtime: &tokio::runtime::Runtime,
    send: &mut h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    query: &[u8],
) {
    runtime.block_on(async {
        let mut streams = Vec::with_capacity(MULTIPLEX_STREAMS);
        for _ in 0..MULTIPLEX_STREAMS {
            streams.push(Client::send(send, query).await);
        }
        let mut tasks = tokio::task::JoinSet::new();
        for stream in streams {
            tasks.spawn(Client::read(stream));
        }
        while let Some(result) = tasks.join_next().await {
            black_box(result.expect("request"));
        }
    });
}

fn doh3_benchmark(criterion: &mut Criterion) {
    let cert = test_cert();
    let tls =
        TlsConfig::for_doh3(cert.cert_pem.as_bytes(), cert.key_pem.as_bytes()).expect("h3 tls");
    let mut config = Doh3Config::new("127.0.0.1:0".parse().expect("addr"), tls);
    config.max_concurrent_requests = 64;
    config.idle_timeout = Duration::from_secs(60);
    let mut server = Doh3Server::bind(config, echo_handler).expect("h3 server");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    let mut client = Client::connect(&runtime, server.local_addr(), &cert.cert_der);
    let query = dns_query(0);

    let mut group = criterion.benchmark_group("doh_http3");
    group.throughput(Throughput::Elements(1));
    group.bench_function("roundtrip_qps", |bencher| {
        bencher.iter(|| single_roundtrip(&runtime, &mut client.send, black_box(&query)));
    });
    group.finish();

    let mut group = criterion.benchmark_group("doh_http3");
    group.throughput(Throughput::Elements(
        u64::try_from(MULTIPLEX_STREAMS).expect("streams"),
    ));
    group.bench_function("multiplexed_qps", |bencher| {
        bencher.iter(|| multiplexed_roundtrip(&runtime, &mut client.send, black_box(&query)));
    });
    group.finish();

    server.shutdown().expect("shutdown");
}

criterion_group!(benches, doh3_benchmark);
criterion_main!(benches);
