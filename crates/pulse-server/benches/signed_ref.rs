//! Bench zero-copy пути для подписанных ответов (`DO = 1`).
//!
//! Сравнивает `respond_into` (полный путь) и `respond_ref_into` (refs) для
//! `NSEC`/`NSEC3` зон, подписанных `ZoneSigner`: positive `A` и `NXDOMAIN`.
//! Печатает p50/p99, qps одного потока и аллокации на запрос после прогрева.
//!
//! Запуск: `cargo bench -p pulse-server --bench signed_ref` (release).
//! Размер зоны — `PULSE_BENCH_SIZE` (по умолчанию 20 000 имён).

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
    Edns, EncodeOptions, Message, MessageRef, Name, Question, Rclass, Rdata, Rrset, Rtype, Serial,
    SoaData, Ttl,
};
use pulse_dnssec::{Algorithm, PrivateKey};
use pulse_server::application::{QueryEngine, Scratch, Transport};
use pulse_server::dnssec::{DenialPolicy, KeyRole, Nsec3Config, ZoneSigner, ZoneSigningKey};
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

fn rrset(owner: &Name, rr_type: Rtype, rdatas: impl IntoIterator<Item = Rdata>) -> Rrset {
    Rrset::new(owner.clone(), rr_type, Rclass::IN, ttl(300), rdatas).expect("rrset")
}

fn zone_data(size: usize) -> Vec<Rrset> {
    let origin = name("example.com");
    let mut records = vec![
        rrset(
            &origin,
            Rtype::SOA,
            [Rdata::Soa(SoaData::new(
                name("ns1.example.com"),
                name("hostmaster.example.com"),
                Serial::new(1),
                3600,
                600,
                604_800,
                300,
            ))],
        ),
        rrset(&origin, Rtype::NS, [Rdata::Ns(name("ns1.example.com"))]),
        rrset(
            &name("ns1.example.com"),
            Rtype::A,
            [Rdata::A("192.0.2.1".parse().expect("ipv4"))],
        ),
        rrset(
            &name("www.example.com"),
            Rtype::A,
            [Rdata::A("192.0.2.20".parse().expect("ipv4"))],
        ),
    ];
    records.extend((0..size).map(|index| {
        rrset(
            &name(&format!("n{index}.example.com")),
            Rtype::A,
            [Rdata::A("192.0.2.100".parse().expect("ipv4"))],
        )
    }));
    records
}

fn signed_zone(policy: &DenialPolicy, size: usize) -> InMemoryZone {
    let origin = name("example.com");
    let signer = ZoneSigner::new(
        vec![
            ZoneSigningKey::new(
                PrivateKey::generate(Algorithm::ED25519).expect("key"),
                KeyRole::Csk,
            )
            .expect("key"),
        ],
        86_400,
        300,
    )
    .expect("signer");
    let signed_zone = signer
        .sign_zone_with(&origin, &zone_data(size), 1_700_000_000, policy)
        .expect("sign zone");
    let mut zone = InMemoryZone::new(origin);
    for rrset in &signed_zone.rrsets {
        zone.insert(rrset.clone()).expect("insert signed rrset");
    }
    zone
}

fn request(qname: &str, qtype: Rtype) -> Message {
    let mut message = Message::query(0x1234, Question::new(name(qname), qtype, Rclass::IN));
    message.set_edns(Some(Edns::new(1232).with_dnssec_ok(true)));
    message
}

struct Stats {
    p50: u64,
    p99: u64,
    allocs: usize,
}

#[allow(clippy::unit_arg)]
fn measure(iterations: usize, mut run: impl FnMut()) -> Stats {
    for _ in 0..(iterations / 10).max(1) {
        black_box(run());
    }
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let begin = Instant::now();
        black_box(run());
        samples.push(u64::try_from(begin.elapsed().as_nanos()).unwrap_or(u64::MAX));
    }
    samples.sort_unstable();
    ALLOCS.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    for _ in 0..iterations {
        black_box(run());
    }
    COUNTING.store(false, Ordering::Relaxed);
    let allocs = ALLOCS.load(Ordering::Relaxed) / iterations.max(1);
    Stats {
        p50: samples[samples.len() / 2],
        p99: samples[(samples.len() * 99 / 100).min(samples.len() - 1)],
        allocs,
    }
}

fn print_row(label: &str, stats: &Stats) {
    println!(
        "{label:<40} p50 {:>7.2} us  p99 {:>7.2} us  qps {:>10.0}  allocs {:>3}",
        stats.p50 as f64 / 1000.0,
        stats.p99 as f64 / 1000.0,
        1e9 / stats.p50.max(1) as f64,
        stats.allocs,
    );
}

fn main() {
    let size = std::env::var("PULSE_BENCH_SIZE")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(20_000);
    let iterations = std::env::var("PULSE_BENCH_ITERATIONS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(20_000);
    println!("signed zone: {size} names, {iterations} samples/query (DO=1)\n");

    for (label, policy) in [
        ("NSEC", DenialPolicy::Nsec),
        (
            "NSEC3",
            DenialPolicy::Nsec3(
                Nsec3Config::new(vec![0xAA, 0xBB], 0)
                    .expect("nsec3 config")
                    .with_opt_out(true),
            ),
        ),
    ] {
        let started = Instant::now();
        let engine = QueryEngine::new(vec![Arc::new(signed_zone(&policy, size))]);
        println!(
            "{label}: zone signed in {:.2} s",
            started.elapsed().as_secs_f64()
        );
        let mut scratch = Scratch::new();
        let mut out = vec![0_u8; 65_535];

        for (case, request) in [
            ("A www", request("www.example.com", Rtype::A)),
            (
                "NXDOMAIN",
                request(&format!("missing{}.example.com", size / 2), Rtype::A),
            ),
        ] {
            let stats = measure(iterations, || {
                engine
                    .respond_into(&request, Transport::Udp, &mut out, &mut scratch)
                    .expect("full path");
            });
            print_row(&format!("{label} {case} | full"), &stats);

            let wire = request
                .encode(&EncodeOptions::compressed())
                .expect("query encode");
            let parsed = MessageRef::decode_simple_edns(&wire).expect("simple query");
            let stats = measure(iterations, || {
                engine
                    .respond_ref_into(&parsed, Transport::Udp, &mut out, &mut scratch)
                    .expect("zero-copy");
            });
            print_row(&format!("{label} {case} | zero-copy"), &stats);
        }
        println!();
    }
}
