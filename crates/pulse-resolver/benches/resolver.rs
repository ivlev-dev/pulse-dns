//! Бенчмарки `pulse-resolver`: cache hit, резолюция через mock upstream и
//! throughput в элементах/сек (Criterion `Throughput::Elements`).

#![allow(missing_docs)]

#[path = "../tests/support/mod.rs"]
mod support;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use criterion::{BatchSize, Criterion, Throughput, black_box, criterion_group, criterion_main};
use pulse_dns::{DecodeLimits, EncodeOptions, Message, Name, Question, Rclass, Rcode, Rtype};
use pulse_resolver::{
    ForwardConfig, Mode, Resolver, ResolverConfig, TimeoutConfig, TlsUpstream, UpstreamConfig,
    UpstreamPoolConfig,
};
use pulse_tls::{DotConfig, DotServer, TlsConfig};
use rcgen::{CertificateParams, KeyPair};
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
    // Гарантируем hits даже при запуске с фильтром имени бенчмарка.
    for _ in 0..3 {
        let hit = resolver.resolve(&query);
        assert_eq!(hit.rcode(), Rcode::NOERROR);
    }

    let mut group = criterion.benchmark_group("resolver/cache");
    group.throughput(Throughput::Elements(1));
    group.bench_function("hit", |bencher| {
        bencher.iter(|| {
            let reply = resolver.resolve(black_box(&query));
            black_box(reply);
        });
    });
    let mut out = [0_u8; 512];
    group.bench_function("hit_into", |bencher| {
        bencher.iter(|| {
            let length = resolver
                .resolve_into(black_box(&query), &mut out)
                .expect("encode");
            black_box(length);
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

struct PoolBench {
    resolver: Arc<Resolver>,
    _server: DotServer,
    _dir: tempfile::TempDir,
}

fn pool_bench(size: usize) -> PoolBench {
    let key = KeyPair::generate().expect("key");
    let params = CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
        .expect("params");
    let certificate = params.self_signed(&key).expect("self-signed");
    let tls = TlsConfig::for_dot(certificate.pem().as_bytes(), key.serialize_pem().as_bytes())
        .expect("dot tls");
    let config = DotConfig::new("127.0.0.1:0".parse().expect("addr"), tls);
    let server = DotServer::bind(config, |query: &[u8], _peer: SocketAddr| {
        let request = Message::decode(query, &DecodeLimits::default()).ok()?;
        let question = request.questions().first()?;
        let record = pulse_dns::Record::new(
            question.qname().clone(),
            Rtype::A,
            Rclass::IN,
            pulse_dns::Ttl::new(60).ok()?,
            pulse_dns::Rdata::A([203, 0, 113, 10].into()),
        )
        .ok()?;
        let mut response = response(&request, Rcode::NOERROR);
        response.add_answer(record);
        response.encode(&EncodeOptions::default()).ok()
    })
    .expect("dot server");
    let dir = tempfile::tempdir().expect("tempdir");
    let ca = dir.path().join("ca.pem");
    std::fs::write(&ca, certificate.pem()).expect("write ca");
    let config = ResolverConfig {
        mode: Mode::Forward(ForwardConfig::with_upstreams(vec![UpstreamConfig::Tls(
            TlsUpstream {
                host: "127.0.0.1".to_owned(),
                port: server.local_addr().port(),
                server_name: "localhost".to_owned(),
                ca: Some(ca),
            },
        )])),
        pool: UpstreamPoolConfig {
            size,
            reconnect_backoff: Duration::from_millis(50),
            max_reconnect_backoff: Duration::from_millis(200),
        },
        timeouts: TimeoutConfig {
            per_query: Duration::from_secs(2),
            tcp: Duration::from_secs(3),
            total: Duration::from_secs(10),
        },
        ..ResolverConfig::default()
    };
    PoolBench {
        resolver: Arc::new(Resolver::new(config).expect("resolver")),
        _server: server,
        _dir: dir,
    }
}

fn pool_round(resolver: &Arc<Resolver>, round: u64, workers: u64, per_worker: u64) {
    let mut threads = Vec::new();
    for worker in 0..workers {
        let resolver = Arc::clone(resolver);
        threads.push(thread::spawn(move || {
            for index in 0..per_worker {
                let name = format!("bench-{round}-{worker}-{index}.pool.test");
                let qname = Name::parse(&name).expect("name");
                let reply = resolver.resolve_qname(&qname, Rtype::A);
                assert_eq!(reply.rcode(), Rcode::NOERROR);
            }
        }));
    }
    for thread in threads {
        thread.join().expect("thread");
    }
}

fn pool_throughput(criterion: &mut Criterion) {
    const WORKERS: u64 = 8;
    const PER_WORKER: u64 = 10;
    let pooled = pool_bench(4);
    let single = pool_bench(1);
    let counter = AtomicU64::new(0);
    pool_round(&pooled.resolver, 0, WORKERS, PER_WORKER);
    pool_round(&single.resolver, 0, WORKERS, PER_WORKER);

    let mut group = criterion.benchmark_group("resolver/pool");
    group.throughput(Throughput::Elements(WORKERS * PER_WORKER));
    for (label, bench) in [("dot_pool4_8x10", &pooled), ("dot_pool1_8x10", &single)] {
        group.bench_function(label, |bencher| {
            bencher.iter(|| {
                let round = counter.fetch_add(1, Ordering::Relaxed) + 1;
                pool_round(black_box(&bench.resolver), round, WORKERS, PER_WORKER);
            });
        });
    }
    group.finish();
    for bench in [&pooled, &single] {
        let stats = bench.resolver.stats().upstream.pool;
        // `opens` кумулятивный: за долгий прогон соединения переоткрываются
        // (лимит сообщений на соединение), поэтому проверяем переиспользование.
        assert!(stats.opens >= 1, "pool must open connections");
        assert!(stats.reuses > 0, "pool must be reused: {}", stats.reuses);
    }
}

criterion_group!(benches, cache_hit, resolve_mock, pool_throughput);
criterion_main!(benches);
