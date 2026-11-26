//! Перцентили латентности cache hit: `resolve` (Message) и `resolve_into`
//! (wire fast path), плюс closed-loop QPS одного потока.
//!
//! Запуск:
//!
//! ```text
//! cargo bench -p pulse-resolver --bench latency
//! PULSE_LATENCY_ITERS=1000000 cargo bench -p pulse-resolver --bench latency
//! ```

#![allow(missing_docs, clippy::cast_precision_loss)]

/// Сколько операций выполнять между двумя `Instant::now()`.
const BATCH: usize = 64;

#[path = "../tests/support/mod.rs"]
mod support;

use std::hint::black_box;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

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

fn percentile(samples: &[u64], numerator: usize, denominator: usize) -> u64 {
    if samples.is_empty() {
        return 0;
    }
    let rank = samples
        .len()
        .saturating_mul(numerator)
        .saturating_div(denominator)
        .saturating_sub(1);
    samples.get(rank).copied().unwrap_or(0)
}

fn report(label: &str, mut samples: Vec<u64>, total: Duration, batch: usize) {
    samples.sort_unstable();
    let p50 = percentile(&samples, 50, 100);
    let p90 = percentile(&samples, 90, 100);
    let p99 = percentile(&samples, 99, 100);
    let p999 = percentile(&samples, 999, 1000);
    let max = samples.last().copied().unwrap_or(0);
    let ops = samples.len().saturating_mul(batch);
    let qps = if total.is_zero() {
        0.0
    } else {
        ops as f64 / total.as_secs_f64()
    };
    // Один timestamp на batch: `clock_gettime` в этой среде стоит ~1.5 µs
    // и при замере на каждую операцию полностью маскирует горячий путь.
    eprintln!(
        "{label:<12} ops={ops:<8} batch={batch:<4} p50={:>7.0} ns  p90={:>7.0} ns  p99={:>7.0} ns  p99.9={:>8.0} ns  max={:>8.0} ns  qps={qps:>10.0}",
        p50 as f64, p90 as f64, p99 as f64, p999 as f64, max as f64,
    );
}

fn main() {
    let iterations: usize = std::env::var("PULSE_LATENCY_ITERS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(200_000);
    // `PULSE_LATENCY_ONLY=wire` измеряет только горячий wire-путь: удобно для
    // `perf stat`, где Message-путь (медленный, аллоцирующий) даёт шум.
    let only = std::env::var("PULSE_LATENCY_ONLY").unwrap_or_default();
    let handler: RawHandler = Arc::new(|request, _tcp| {
        let mut reply = response(request, Rcode::NOERROR);
        reply.add_answer(a("bench.example", 3600, [192, 0, 2, 1]));
        Some(encode(&reply))
    });
    let server = MockServer::spawn(handler);
    let resolver = Resolver::new(config(server.address())).expect("resolver");
    let query = Message::query(
        0x1234,
        Question::new(
            Name::parse("bench.example").expect("name"),
            Rtype::A,
            Rclass::IN,
        ),
    );
    assert_eq!(resolver.resolve(&query).rcode(), Rcode::NOERROR);
    for _ in 0..100 {
        black_box(resolver.resolve(&query));
    }

    let batches = iterations.saturating_div(BATCH).max(1);
    if only != "wire" {
        let mut message_samples = Vec::with_capacity(batches);
        let started = Instant::now();
        for _ in 0..batches {
            let begin = Instant::now();
            for _ in 0..BATCH {
                black_box(resolver.resolve(black_box(&query)));
            }
            let per_op = begin.elapsed().as_nanos().saturating_div(BATCH as u128);
            message_samples.push(u64::try_from(per_op).unwrap_or(u64::MAX));
        }
        let message_total = started.elapsed();
        report("resolve", message_samples, message_total, BATCH);
    }

    if only != "message" {
        let mut out = [0_u8; 512];
        for _ in 0..100 {
            black_box(resolver.resolve_into(&query, &mut out).expect("encode"));
        }
        let mut wire_samples = Vec::with_capacity(batches);
        let started = Instant::now();
        for _ in 0..batches {
            let begin = Instant::now();
            for _ in 0..BATCH {
                let length = resolver
                    .resolve_into(black_box(&query), &mut out)
                    .expect("encode");
                black_box(length);
            }
            let per_op = begin.elapsed().as_nanos().saturating_div(BATCH as u128);
            wire_samples.push(u64::try_from(per_op).unwrap_or(u64::MAX));
        }
        let wire_total = started.elapsed();
        report("resolve_into", wire_samples, wire_total, BATCH);
        eprintln!("cache stats: {:?}", resolver.stats().cache);
    }
}
