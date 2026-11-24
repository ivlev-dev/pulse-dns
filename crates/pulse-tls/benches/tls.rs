#![allow(missing_docs)]

//! Benchmark DoT/DoH round-trip QPS на loopback с self-signed сертификатом.
//!
//! Запуск: `cargo bench -p pulse-tls`. Каждый benchmark использует одно
//! долгоживущее TLS-соединение (keep-alive), поэтому измеряется
//! преимущественно стоимость запроса/ответа, а не рукопожатия.

use std::time::Duration;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use pulse_tls::{DohConfig, DohServer, DotConfig, DotServer, TlsConfig};

#[path = "../tests/common/mod.rs"]
mod common;

use common::{TlsClient, dns_query, echo_handler, test_cert};

fn dot_benchmark(c: &mut Criterion) {
    let cert = test_cert();
    let tls = TlsConfig::for_dot(cert.cert_pem.as_bytes(), cert.key_pem.as_bytes())
        .expect("DoT TLS config");
    let mut config = DotConfig::new("127.0.0.1:0".parse().expect("addr"), tls);
    config.max_messages_per_connection = 1_000_000;
    config.idle_timeout = Duration::from_secs(60);
    let mut server = DotServer::bind(config, echo_handler).expect("DoT server");
    let mut client =
        TlsClient::connect(server.local_addr(), &cert.cert_der, Some(b"dot")).expect("DoT client");
    let query = dns_query(0x1234);

    let mut group = c.benchmark_group("dot");
    group.throughput(Throughput::Elements(1));
    group.bench_function("roundtrip_qps", |bencher| {
        bencher.iter(|| {
            client.send_dot(&query).expect("send");
            let response = client.read_dot().expect("read");
            assert_eq!(response, query);
        });
    });
    group.finish();
    server.shutdown().expect("shutdown");
}

fn doh_benchmark(c: &mut Criterion) {
    let cert = test_cert();
    let tls = TlsConfig::for_doh(cert.cert_pem.as_bytes(), cert.key_pem.as_bytes())
        .expect("DoH TLS config");
    let mut config = DohConfig::new("127.0.0.1:0".parse().expect("addr"), tls);
    config.max_requests_per_connection = 1_000_000;
    config.idle_timeout = Duration::from_secs(60);
    let mut server = DohServer::bind(config, echo_handler).expect("DoH server");
    let mut client = TlsClient::connect(server.local_addr(), &cert.cert_der, Some(b"http/1.1"))
        .expect("DoH client");
    let query = dns_query(0x4321);
    let request = post_request("/dns-query", &query);

    let mut group = c.benchmark_group("doh");
    group.throughput(Throughput::Elements(1));
    group.bench_function("post_qps", |bencher| {
        bencher.iter(|| {
            let response = client.request(&request).expect("POST");
            assert_eq!(response.status, 200);
            assert_eq!(response.body, query);
        });
    });
    group.finish();
    server.shutdown().expect("shutdown");
}

fn post_request(path: &str, body: &[u8]) -> Vec<u8> {
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let mut request = head.into_bytes();
    request.extend_from_slice(body);
    request
}

fn benchmarks(c: &mut Criterion) {
    dot_benchmark(c);
    doh_benchmark(c);
}

criterion_group!(benches, benchmarks);
criterion_main!(benches);
