//! Counting allocator: аллокации полного пути ответа (UDP).
//!
//! Сравнивается прежний путь (`respond` + `Message::encode`) с потоковым
//! (`respond_into`). Декод запроса и выборка из зоны сюда не входят.
#![allow(unsafe_code)]

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use common::{big_txt_rrset, edns_query, engine_for, example_engine, example_zone, query};
use pulse_dns::{EncodeOptions, Rtype};
use pulse_server::application::{QueryEngine, Scratch, Transport};

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

fn legacy(engine: &QueryEngine, request: &pulse_dns::Message, transport: Transport) -> usize {
    engine
        .respond(request, transport)
        .encode(&EncodeOptions::compressed())
        .expect("legacy encode")
        .len()
}

fn streaming(
    engine: &QueryEngine,
    request: &pulse_dns::Message,
    transport: Transport,
    out: &mut [u8],
    scratch: &mut Scratch,
) -> usize {
    engine
        .respond_into(request, transport, out, scratch)
        .expect("streaming response")
}

#[test]
fn response_path_allocations() {
    let mut zone = example_zone();
    zone.insert(big_txt_rrset(30)).expect("big txt");
    let engine = engine_for(zone);
    let mut scratch = Scratch::new();
    let mut out = vec![0_u8; 4096];

    for (label, request) in [
        ("a", query("www.example.com", Rtype::A)),
        ("mx", query("example.com", Rtype::MX)),
        ("any", query("example.com", Rtype::ANY)),
        ("nxdomain", query("missing.example.com", Rtype::A)),
        ("big-txt", query("big.example.com", Rtype::TXT)),
        (
            "edns-big",
            edns_query("big.example.com", Rtype::TXT, 1232, false),
        ),
    ] {
        // Разогрев.
        let _ = legacy(&engine, &request, Transport::Udp);
        let _ = streaming(&engine, &request, Transport::Udp, &mut out, &mut scratch);

        let legacy_allocs = measure(|| {
            let _ = legacy(&engine, &request, Transport::Udp);
        });
        let streaming_allocs = measure(|| {
            let _ = streaming(&engine, &request, Transport::Udp, &mut out, &mut scratch);
        });
        println!(
            "{label}: UDP allocs legacy={legacy_allocs} streaming={streaming_allocs} \
             (delta {})",
            i64::try_from(legacy_allocs).unwrap_or(i64::MAX)
                - i64::try_from(streaming_allocs).unwrap_or(i64::MAX)
        );
        assert!(
            streaming_allocs < legacy_allocs,
            "{label}: streaming path must allocate less"
        );
    }
    let _ = example_engine();
}
