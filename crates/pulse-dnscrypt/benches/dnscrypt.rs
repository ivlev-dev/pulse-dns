//! Бенчмарки шифрования/расшифровки и полного round-trip `DNSCrypt` v2.
#![allow(missing_docs)]

use std::net::Ipv4Addr;

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use pulse_dns::{Message, Name, Question, Rclass, Rdata, Record, Rtype, Ttl};
use pulse_dnscrypt::{
    Certificate, CertificateParams, DnscryptClient, DnscryptServer, ProviderKeypair,
    ResolverKeypair, ServerConfig, Transport,
};

const NOW: u64 = 1_700_000_000;

struct Fixture {
    server: DnscryptServer,
    client: DnscryptClient,
    query: Vec<u8>,
    response: Vec<u8>,
}

fn dns_query() -> Vec<u8> {
    let question = Question::new(Name::parse("example.com").unwrap(), Rtype::A, Rclass::IN);
    Message::query(0x1234, question)
        .encode(&pulse_dns::EncodeOptions::default())
        .unwrap()
}

fn dns_response() -> Vec<u8> {
    let question = Question::new(Name::parse("example.com").unwrap(), Rtype::A, Rclass::IN);
    let mut response = Message::response(&Message::query(0x1234, question));
    response.add_answer(
        Record::new(
            Name::parse("example.com").unwrap(),
            Rtype::A,
            Rclass::IN,
            Ttl::new(60).unwrap(),
            Rdata::A(Ipv4Addr::new(192, 0, 2, 1)),
        )
        .unwrap(),
    );
    response
        .encode(&pulse_dns::EncodeOptions::default())
        .unwrap()
}

fn fixture() -> Fixture {
    let provider = ProviderKeypair::from_seed([7_u8; 32]);
    let resolver = ResolverKeypair::from_secret_bytes([9_u8; 32]);
    let params = CertificateParams::new(
        resolver.public_key().to_bytes(),
        [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80],
        1,
        1_600_000_000,
        2_000_000_000,
    );
    let certificate = Certificate::sign(&provider, params).expect("certificate");
    let mut server =
        DnscryptServer::new(provider.public_key(), ServerConfig::default()).expect("server");
    server
        .add_certificate(certificate.clone(), resolver)
        .expect("add certificate");
    let client = DnscryptClient::new(certificate, provider.public_key(), NOW).expect("client");
    Fixture {
        server,
        client,
        query: dns_query(),
        response: dns_response(),
    }
}

fn bench_roundtrip(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("dnscrypt-roundtrip");
    for size in [64_usize, 512, 1232] {
        let fixture = fixture();
        let query = vec![0x42; size];
        group.throughput(Throughput::Elements(1));
        group.bench_function(format!("udp-query-{size}"), |bencher| {
            let response = fixture.response.clone();
            bencher.iter(|| {
                let pending = fixture
                    .client
                    .build_query(black_box(&query), Transport::Udp)
                    .expect("query");
                let packet = fixture
                    .server
                    .handle_udp_at(pending.packet(), NOW, &|_: &[u8]| {
                        Ok::<_, std::io::Error>(response.clone())
                    })
                    .expect("response");
                fixture
                    .client
                    .decrypt_response(&pending, &packet)
                    .expect("decrypt")
            });
        });
    }
    group.finish();
}

fn bench_encrypt(criterion: &mut Criterion) {
    let fixture = fixture();
    let mut group = criterion.benchmark_group("dnscrypt-encrypt");
    group.throughput(Throughput::Bytes(fixture.query.len() as u64));
    group.bench_function("udp", |bencher| {
        let nonce = [0x5a; 12];
        bencher.iter(|| {
            fixture
                .client
                .build_query_with_nonce(black_box(&fixture.query), Transport::Udp, nonce)
                .expect("query")
        });
    });
    group.finish();
}

fn bench_decrypt(criterion: &mut Criterion) {
    let fixture = fixture();
    let pending = fixture
        .client
        .build_query_with_nonce(&fixture.query, Transport::Udp, [0x5b; 12])
        .expect("query");
    let packet = fixture
        .server
        .handle_udp_at(pending.packet(), NOW, &|_: &[u8]| {
            Ok::<_, std::io::Error>(fixture.response.clone())
        })
        .expect("response");
    let mut group = criterion.benchmark_group("dnscrypt-decrypt");
    group.throughput(Throughput::Bytes(fixture.response.len() as u64));
    group.bench_function("udp", |bencher| {
        bencher.iter(|| {
            fixture
                .client
                .decrypt_response(&pending, black_box(&packet))
                .expect("decrypt")
        });
    });
    group.finish();
}

criterion_group!(benches, bench_roundtrip, bench_encrypt, bench_decrypt);
criterion_main!(benches);
