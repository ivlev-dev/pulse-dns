//! Bench «оставшихся» случаев zero-copy пути: `DNAME`, циклы `CNAME`/`DNAME`,
//! wildcard-`CNAME` и oversized `RRset`.
//!
//! Для каждого сценария печатает p50/p99 одного запроса и среднее число
//! аллокаций для полного (`respond_into`) и заимствованного
//! (`respond_ref_into`) путей. Если заимствованный путь уступает полному,
//! печатается `fallback` — это значение «до» оптимизации.
//!
//! Запуск: `cargo bench -p pulse-server --bench fast_paths` (release).

#![allow(
    unsafe_code,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;

use pulse_dns::{
    EncodeOptions, Message, MessageRef, Name, Question, Rclass, Rdata, Rrset, Rtype, Serial,
    SoaData, Ttl, TxtData,
};
use pulse_server::application::{QueryEngine, Scratch, Transport};
use pulse_server::testkit::InMemoryZone;

static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static COUNTING: AtomicBool = AtomicBool::new(false);

struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.realloc(pointer, layout, size) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn name(text: &str) -> Name {
    Name::parse(text).expect("name")
}

fn ttl(value: u32) -> Ttl {
    Ttl::new(value).expect("ttl")
}

fn rrset(owner: &str, rr_type: Rtype, rdatas: impl IntoIterator<Item = Rdata>) -> Rrset {
    Rrset::new(name(owner), rr_type, Rclass::IN, ttl(300), rdatas).expect("rrset")
}

fn base_zone(origin: &str) -> InMemoryZone {
    let mut zone = InMemoryZone::new(name(origin));
    zone.insert(rrset(
        origin,
        Rtype::SOA,
        [Rdata::Soa(SoaData::new(
            name(&format!("ns1.{origin}")),
            name(&format!("hostmaster.{origin}")),
            Serial::new(1),
            3600,
            600,
            604_800,
            300,
        ))],
    ))
    .expect("soa");
    zone.insert(rrset(
        origin,
        Rtype::NS,
        [Rdata::Ns(name(&format!("ns1.{origin}")))],
    ))
    .expect("ns");
    zone.insert(rrset(
        &format!("www.{origin}"),
        Rtype::A,
        [Rdata::A("192.0.2.20".parse().expect("ipv4"))],
    ))
    .expect("www");
    zone
}

fn chain_zone() -> InMemoryZone {
    let mut zone = base_zone("example.com");
    zone.insert(rrset(
        "dname.example.com",
        Rtype::DNAME,
        [Rdata::Dname(name("dname-target.example.com"))],
    ))
    .expect("dname");
    zone.insert(rrset(
        "host.dname-target.example.com",
        Rtype::A,
        [Rdata::A("192.0.2.60".parse().expect("ipv4"))],
    ))
    .expect("dname target");
    zone.insert(rrset(
        "dname-ext.example.com",
        Rtype::DNAME,
        [Rdata::Dname(name("target.outside.test"))],
    ))
    .expect("dname external");
    zone.insert(rrset(
        "loop1.example.com",
        Rtype::CNAME,
        [Rdata::Cname(name("loop2.example.com"))],
    ))
    .expect("loop1");
    zone.insert(rrset(
        "loop2.example.com",
        Rtype::CNAME,
        [Rdata::Cname(name("loop1.example.com"))],
    ))
    .expect("loop2");
    zone.insert(rrset(
        "a.example.com",
        Rtype::DNAME,
        [Rdata::Dname(name("b.example.com"))],
    ))
    .expect("dname a");
    zone.insert(rrset(
        "b.example.com",
        Rtype::DNAME,
        [Rdata::Dname(name("a.example.com"))],
    ))
    .expect("dname b");
    zone.insert(rrset(
        "*.wc.example.com",
        Rtype::CNAME,
        [Rdata::Cname(name("c1.example.com"))],
    ))
    .expect("wildcard cname");
    zone.insert(rrset(
        "c1.example.com",
        Rtype::CNAME,
        [Rdata::Cname(name("c2.example.com"))],
    ))
    .expect("c1");
    zone.insert(rrset(
        "c2.example.com",
        Rtype::CNAME,
        [Rdata::Cname(name("www.example.com"))],
    ))
    .expect("c2");
    zone.insert(rrset(
        "big.example.com",
        Rtype::TXT,
        (0..40).map(|index| {
            Rdata::Txt(
                TxtData::new([format!("{index:04}-{}", "x".repeat(100)).into_bytes()])
                    .expect("txt"),
            )
        }),
    ))
    .expect("big txt");
    zone
}

fn yxdomain_zone() -> InMemoryZone {
    let label = "a".repeat(63);
    let target = format!("{label}.{label}.{label}");
    let mut zone = base_zone("dlong.example");
    zone.insert(rrset(
        "long.dlong.example",
        Rtype::DNAME,
        [Rdata::Dname(name(&target))],
    ))
    .expect("dname");
    zone
}

fn query(qname: &str, qtype: Rtype) -> Message {
    Message::query(0x1234, Question::new(name(qname), qtype, Rclass::IN))
}

fn percentile(sorted: &[f64], fraction: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let index = ((sorted.len() - 1) as f64 * fraction).round() as usize;
    sorted.get(index).copied().unwrap_or_default()
}

fn engine_run(
    engine: &QueryEngine,
    request: &Message,
    transport: Transport,
    fast: bool,
    warm: usize,
) -> (f64, f64, f64) {
    let wire = request
        .encode(&EncodeOptions::compressed())
        .expect("query encode");
    let parsed = MessageRef::decode_simple_edns(&wire).expect("simple query");
    let mut scratch = Scratch::new();
    let mut out = vec![0_u8; 65_535];
    let samples = 500_usize;
    let batch = 50_usize;
    let mut timings = Vec::with_capacity(samples);
    for _ in 0..warm {
        let _ = if fast {
            engine.respond_ref_into(&parsed, transport, &mut out, &mut scratch)
        } else {
            engine
                .respond_into(request, transport, &mut out, &mut scratch)
                .ok()
        };
    }
    if fast
        && engine
            .respond_ref_into(&parsed, transport, &mut out, &mut scratch)
            .is_none()
    {
        return (f64::NAN, f64::NAN, f64::NAN);
    }
    for _ in 0..samples {
        let start = Instant::now();
        for _ in 0..batch {
            if fast {
                black_box(engine.respond_ref_into(&parsed, transport, &mut out, &mut scratch));
            } else {
                black_box(
                    engine
                        .respond_into(request, transport, &mut out, &mut scratch)
                        .ok(),
                );
            }
        }
        timings.push(start.elapsed().as_secs_f64() * 1e9 / batch as f64);
    }
    timings.sort_by(|left, right| left.partial_cmp(right).expect("finite"));
    let p50 = percentile(&timings, 0.50);
    let p99 = percentile(&timings, 0.99);

    ALLOCS.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    for _ in 0..samples * batch {
        if fast {
            black_box(engine.respond_ref_into(&parsed, transport, &mut out, &mut scratch));
        } else {
            black_box(
                engine
                    .respond_into(request, transport, &mut out, &mut scratch)
                    .ok(),
            );
        }
    }
    COUNTING.store(false, Ordering::Relaxed);
    let allocs = ALLOCS.load(Ordering::Relaxed) as f64 / (samples * batch) as f64;
    (p50, p99, allocs)
}

fn bench_engine(label: &str, engine: &QueryEngine, cases: &[(&str, Message, Transport)]) {
    for (case, request, transport) in cases {
        let (full_p50, full_p99, full_allocs) = engine_run(engine, request, *transport, false, 500);
        let (fast_p50, fast_p99, fast_allocs) = engine_run(engine, request, *transport, true, 500);
        let fast = if fast_p50.is_nan() {
            "fallback".to_owned()
        } else {
            format!("p50 {fast_p50:>8.0} ns  p99 {fast_p99:>8.0} ns  allocs {fast_allocs:.2}")
        };
        println!(
            "{label:<10} {case:<22} full p50 {full_p50:>8.0} ns  p99 {full_p99:>8.0} ns  allocs {full_allocs:.2} | fast {fast}"
        );
    }
}

fn main() {
    let chain = QueryEngine::new(vec![Arc::new(chain_zone())]);
    bench_engine(
        "chain",
        &chain,
        &[
            (
                "dname-in-zone",
                query("host.dname.example.com", Rtype::A),
                Transport::Udp,
            ),
            (
                "dname-outside",
                query("host.dname-ext.example.com", Rtype::A),
                Transport::Udp,
            ),
            (
                "cname-loop",
                query("loop1.example.com", Rtype::A),
                Transport::Udp,
            ),
            (
                "dname-loop",
                query("x.a.example.com", Rtype::A),
                Transport::Udp,
            ),
            (
                "wildcard-cname-chain",
                query("x.wc.example.com", Rtype::A),
                Transport::Udp,
            ),
            (
                "oversized-txt-udp",
                query("big.example.com", Rtype::TXT),
                Transport::Udp,
            ),
            (
                "oversized-txt-tcp",
                query("big.example.com", Rtype::TXT),
                Transport::Tcp,
            ),
        ],
    );

    let yxdomain = QueryEngine::new(vec![Arc::new(yxdomain_zone())]);
    let label = "a".repeat(63);
    bench_engine(
        "yxdomain",
        &yxdomain,
        &[(
            "dname-yxdomain",
            query(&format!("{label}.long.dlong.example"), Rtype::A),
            Transport::Udp,
        )],
    );
}
