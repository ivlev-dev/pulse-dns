//! Бенчмарки `pulse-resolver`: cache hit, резолюция через mock upstream и
//! throughput в элементах/сек (Criterion `Throughput::Elements`).

#![allow(missing_docs)]

#[path = "../tests/support/mod.rs"]
mod support;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use criterion::{BatchSize, Criterion, Throughput, black_box, criterion_group, criterion_main};
use pulse_dns::{Message, Name, Question, Rclass, Rcode, Rtype};
use pulse_resolver::{Resolver, ResolverConfig, TimeoutConfig};
use support::{MockServer, RawHandler, a, encode, response};

fn config(server: SocketAddr) -> ResolverConfig {
    let mut config = ResolverConfig::forward(vec![server]);
    config.timeouts = TimeoutConfig {
        per_query: Duration::from_millis(500),
        tcp: Duration::from_millis(700),
        total: Duration::from_secs(3),
    };
    config.retries = 1;
    config.use_0x20 = false;
    config.cache.max_ttl = 3600;
    config
}

fn mock() -> MockServer {
    let handler: RawHandler = Arc::new(|request, _tcp| {
        let mut reply = response(request, Rcode::NOERROR);
        reply.add_answer(a("bench.example", 3600, [192, 0, 2, 1]));
        Some(encode(&reply))
    });
    MockServer::spawn(handler)
}

fn request() -> Message {
    Message::query(
        0x1234,
        Question::new(Name::parse("bench.example").unwrap(), Rtype::A, Rclass::IN),
    )
}

fn cache_hit(criterion: &mut Criterion) {
    let server = mock();
    let resolver = Resolver::new(config(server.address())).unwrap();
    let query = request();
    let warm = resolver.resolve(&query);
    assert_eq!(warm.rcode(), Rcode::NOERROR);

    let mut group = criterion.benchmark_group("resolver/cache");
    group.throughput(Throughput::Elements(1));
    group.bench_function("hit", |bencher| {
        bencher.iter(|| {
            let reply = resolver.resolve(black_box(&query));
            black_box(reply);
        });
    });
    group.finish();
    assert!(
        resolver.stats().cache.hits > 0,
        "cache-hit benchmark must actually hit the cache"
    );
}

fn resolve_mock(criterion: &mut Criterion) {
    let server = mock();
    let resolver = Resolver::new(config(server.address())).unwrap();
    let query = request();
    let warm = resolver.resolve(&query);
    assert_eq!(warm.rcode(), Rcode::NOERROR);

    let mut group = criterion.benchmark_group("resolver/upstream");
    group.throughput(Throughput::Elements(1));
    group.bench_function("udp_roundtrip", |bencher| {
        bencher.iter_batched(
            || {
                resolver.cache().purge();
                query.clone()
            },
            |query| {
                let reply = resolver.resolve(black_box(&query));
                black_box(reply);
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

criterion_group!(benches, cache_hit, resolve_mock);
criterion_main!(benches);
