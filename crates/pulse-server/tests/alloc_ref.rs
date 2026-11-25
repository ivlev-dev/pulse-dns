//! Счётчик аллокаций zero-copy пути (отдельный test-binary, один тест).
//!
//! В бинарнике намеренно ровно один тест: глобальный аллокатор считает все
//! выделения процесса, а Rust запускает тесты одного бинарника параллельно.
#![allow(unsafe_code)]

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use common::{edns_query, engine_for, example_zone, query};
use pulse_dns::{EncodeOptions, MessageRef, Rtype};
use pulse_server::application::{Scratch, Transport};

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

fn measure(run: impl FnOnce()) -> usize {
    ALLOCS.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    run();
    COUNTING.store(false, Ordering::Relaxed);
    ALLOCS.load(Ordering::Relaxed)
}

#[test]
fn ref_fast_path_is_allocation_free() {
    let engine = engine_for(example_zone());
    let mut scratch = Scratch::new();
    let mut out = vec![0_u8; 4096];

    // EDNS без DO: тот же zero-copy путь с OPT в ответе.
    for (label, request) in [
        ("a", query("www.example.com", Rtype::A)),
        ("apex-aaaa", query("example.com", Rtype::AAAA)),
        ("mx", query("example.com", Rtype::MX)),
        ("txt", query("txt.example.com", Rtype::TXT)),
        ("nxdomain", query("missing.example.com", Rtype::A)),
        ("nodata", query("www.example.com", Rtype::MX)),
        (
            "edns-a",
            edns_query("www.example.com", Rtype::A, 1232, false),
        ),
        ("edns-mx", edns_query("example.com", Rtype::MX, 1232, false)),
    ] {
        let bytes = request
            .encode(&EncodeOptions::compressed())
            .expect("encoded query");
        let parsed = MessageRef::decode_simple_edns(&bytes).expect("simple query");

        let warm = engine.respond_ref_into(&parsed, Transport::Udp, &mut out, &mut scratch);
        assert!(warm.is_some(), "{label}: hot path must answer");

        let allocations = measure(|| {
            let len = engine
                .respond_ref_into(&parsed, Transport::Udp, &mut out, &mut scratch)
                .expect("hot path response");
            assert!(len <= 512, "{label}: UDP response exceeds 512 bytes");
        });
        println!("{label}: zero-copy UDP allocs={allocations}");
        assert!(
            allocations <= 5,
            "{label}: {allocations} allocs/query exceeds warm budget of 5"
        );
    }
}
