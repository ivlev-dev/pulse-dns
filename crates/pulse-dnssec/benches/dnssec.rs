//! Бенчмарки подписи и валидации `RRset` для алгоритмов 8/13/15.
#![allow(missing_docs)]

use std::net::Ipv4Addr;

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use pulse_dns::{Name, Rclass, Rdata, Rrset, Rtype, Ttl};
use pulse_dnssec::{
    Algorithm, PrivateKey, RsaKeySize, SignOptions, VerifyOptions, sign_rrset, verify_rrsig,
};

fn rrset() -> Rrset {
    let owner = Name::parse("www.example.com").unwrap();
    let rdatas: Vec<Rdata> = (1..=8)
        .map(|index| Rdata::A(Ipv4Addr::new(192, 0, 2, index)))
        .collect();
    Rrset::new(owner, Rtype::A, Rclass::IN, Ttl::new(300).unwrap(), rdatas).unwrap()
}

fn bench_algorithms(criterion: &mut Criterion) {
    let now = 1_700_000_000_u32;
    let rrset = rrset();
    let cases = [
        ("alg8-rsa2048", Algorithm::RSASHA256, RsaKeySize::Bits2048),
        ("alg8-rsa4096", Algorithm::RSASHA256, RsaKeySize::Bits4096),
        (
            "alg13-p256",
            Algorithm::ECDSAP256SHA256,
            RsaKeySize::Bits2048,
        ),
        ("alg15-ed25519", Algorithm::ED25519, RsaKeySize::Bits2048),
    ];

    let mut group = criterion.benchmark_group("dnssec");
    group.sample_size(50);
    group.throughput(Throughput::Elements(1));

    for (label, algorithm, size) in cases {
        let key = PrivateKey::generate_with_rsa_size(algorithm, size).unwrap();
        let dnskey = key.dnskey(256).unwrap();
        let options = SignOptions::new(Name::parse("example.com").unwrap(), now, 86_400)
            .with_dnskey_flags(256);
        let rrsig = sign_rrset(&key, &rrset, &options).unwrap();
        let verify_options = VerifyOptions::new(now);

        group.bench_with_input(BenchmarkId::new("sign", label), &(), |bencher, ()| {
            bencher.iter(|| {
                black_box(sign_rrset(&key, black_box(&rrset), &options).unwrap());
            });
        });
        group.bench_with_input(BenchmarkId::new("verify", label), &(), |bencher, ()| {
            bencher.iter(|| {
                verify_rrsig(
                    black_box(&rrset),
                    black_box(&rrsig),
                    black_box(&dnskey),
                    &verify_options,
                )
                .unwrap();
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_algorithms);
criterion_main!(benches);
