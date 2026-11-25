//! Бюджет аллокаций горячего пути через `dhat` counting allocator.
//!
//! Запуск (один поток, profiler не допускает параллельных экземпляров):
//!
//! ```text
//! cargo test -p pulse-resolver --test allocations -- --ignored --nocapture --test-threads=1
//! ```

#![allow(clippy::cast_precision_loss)]

mod support;

use std::hint::black_box;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use pulse_dns::{Message, Name, Question, Rclass, Rcode, Rtype};
use pulse_resolver::blocklist::Blocklist;
use pulse_resolver::{Override, Overrides, Resolver, ResolverConfig, TimeoutConfig};
use support::{MockServer, RawHandler, a, encode, response};

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

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

fn measure(name: &str, ops: u64, mut function: impl FnMut()) {
    for _ in 0..100 {
        function();
    }
    let before = dhat::HeapStats::get();
    for _ in 0..ops {
        function();
    }
    let after = dhat::HeapStats::get();
    let allocations = after.total_blocks.saturating_sub(before.total_blocks);
    let bytes = after.total_bytes.saturating_sub(before.total_bytes);
    eprintln!(
        "{name:<20} ops={ops:<8} allocs={allocations:<10} bytes={bytes:<10} allocs/op={:.3}",
        allocations as f64 / ops as f64
    );
    assert_eq!(allocations, 0, "{name} must not allocate on the hot path");
}

#[test]
#[ignore = "allocation probe: run explicitly with --test-threads=1"]
fn cache_hit_allocation_budget() {
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
    let mut out = [0_u8; 512];

    let _profiler = dhat::Profiler::builder()
        .testing()
        .trim_backtraces(Some(4))
        .build();

    measure("resolve_into hit", 10_000, || {
        let length = resolver.resolve_into(&query, &mut out).expect("encode");
        black_box(length);
    });

    let blocklist = Blocklist::parse(
        (0..2_000)
            .map(|index| format!("ads{index}.example"))
            .collect::<Vec<_>>()
            .join("\n")
            .as_str(),
        &[],
    );
    let missing = Name::parse("clean.example").expect("name");
    measure("blocklist miss", 100_000, || {
        black_box(blocklist.is_blocked(&missing));
    });

    let overrides = Overrides::build(&[Override::a(
        Name::parse("override.example").expect("name"),
        pulse_dns::Ttl::new(60).expect("ttl"),
        std::net::Ipv4Addr::new(192, 0, 2, 9),
    )])
    .expect("overrides");
    measure("overrides miss", 100_000, || {
        black_box(overrides.lookup(&missing, Rtype::A));
    });

    // Legacy Message-path для сравнения: он по контракту материализует
    // записи и поэтому аллоцирует, но не является горячим wire-путём.
    let before = dhat::HeapStats::get();
    for _ in 0..1_000 {
        black_box(resolver.resolve(&query));
    }
    let after = dhat::HeapStats::get();
    let allocations = after.total_blocks.saturating_sub(before.total_blocks);
    eprintln!(
        "legacy resolve       ops=1000     allocs={allocations:<10} allocs/op={:.3}",
        allocations as f64 / 1_000.0
    );
}
