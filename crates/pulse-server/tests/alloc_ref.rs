//! Счётчик аллокаций zero-copy пути (отдельный test-binary, один тест).
//!
//! В бинарнике намеренно ровно один тест: глобальный аллокатор считает все
//! выделения процесса, а Rust запускает тесты одного бинарника параллельно.
#![allow(unsafe_code)]

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use common::{edns_query, engine_for, example_zone, name, query, rrset};
use pulse_dns::{DnskeyData, EncodeOptions, MessageRef, Rdata, Rrset, Rtype};
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

fn measure(run: impl FnOnce()) -> usize {
    ALLOCS.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    run();
    COUNTING.store(false, Ordering::Relaxed);
    ALLOCS.load(Ordering::Relaxed)
}

fn signed_zone_data() -> Vec<Rrset> {
    vec![
        rrset(
            "example.com",
            Rtype::SOA,
            3600,
            [Rdata::Soa(pulse_dns::SoaData::new(
                name("ns1.example.com"),
                name("hostmaster.example.com"),
                pulse_dns::Serial::new(1),
                3600,
                600,
                604_800,
                300,
            ))],
        ),
        rrset(
            "example.com",
            Rtype::NS,
            3600,
            [Rdata::Ns(name("ns1.example.com"))],
        ),
        rrset(
            "ns1.example.com",
            Rtype::A,
            3600,
            [Rdata::A("192.0.2.1".parse().expect("ipv4"))],
        ),
        rrset(
            "www.example.com",
            Rtype::A,
            300,
            [Rdata::A("192.0.2.20".parse().expect("ipv4"))],
        ),
        rrset(
            "sub.example.com",
            Rtype::NS,
            300,
            [Rdata::Ns(name("ns1.sub.example.com"))],
        ),
        rrset(
            "sub.example.com",
            Rtype::DS,
            300,
            [Rdata::Ds(
                pulse_dns::DsData::new(12_345, 8, 2, vec![0xAB; 32]).expect("ds"),
            )],
        ),
        rrset(
            "ns1.sub.example.com",
            Rtype::A,
            300,
            [Rdata::A("192.0.2.53".parse().expect("ipv4"))],
        ),
    ]
}

fn signed_engine(policy: &DenialPolicy) -> (QueryEngine, Vec<DnskeyData>) {
    let origin = name("example.com");
    let signer = ZoneSigner::new(
        vec![
            ZoneSigningKey::new(
                pulse_dnssec::PrivateKey::generate(pulse_dnssec::Algorithm::ED25519).expect("key"),
                KeyRole::Csk,
            )
            .expect("key"),
        ],
        86_400,
        300,
    )
    .expect("signer");
    let signed_zone = signer
        .sign_zone_with(&origin, &signed_zone_data(), 1_700_000_000, policy)
        .expect("sign zone");
    let mut zone = InMemoryZone::new(origin);
    for rrset in &signed_zone.rrsets {
        zone.insert(rrset.clone()).expect("insert rrset");
    }
    (engine_for(zone), signed_zone.dnskeys)
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

    // Подписанные ответы, referral и ANY: те же refs, никаких `Vec`/`Message`.
    for (kind, policy) in [
        ("nsec", DenialPolicy::Nsec),
        (
            "nsec3",
            DenialPolicy::Nsec3(
                Nsec3Config::new(vec![0xAA, 0xBB], 0)
                    .expect("nsec3 config")
                    .with_opt_out(true),
            ),
        ),
    ] {
        let (signed, dnskeys) = signed_engine(&policy);
        assert_ne!(dnskeys.len(), 0);
        for (label, request) in [
            (
                "signed-a",
                edns_query("www.example.com", Rtype::A, 1232, true),
            ),
            (
                "signed-nxdomain",
                edns_query("missing.example.com", Rtype::A, 1232, true),
            ),
            (
                "signed-nodata",
                edns_query("www.example.com", Rtype::AAAA, 1232, true),
            ),
            (
                "signed-referral",
                edns_query("host.sub.example.com", Rtype::A, 1232, true),
            ),
            ("any", edns_query("www.example.com", Rtype::ANY, 1232, true)),
        ] {
            let bytes = request
                .encode(&EncodeOptions::compressed())
                .expect("encoded query");
            let parsed = MessageRef::decode_simple_edns(&bytes).expect("simple query");
            let warm = signed.respond_ref_into(&parsed, Transport::Udp, &mut out, &mut scratch);
            assert!(warm.is_some(), "{kind}-{label}: hot path must answer");
            let allocations = measure(|| {
                let len = signed
                    .respond_ref_into(&parsed, Transport::Udp, &mut out, &mut scratch)
                    .expect("hot path response");
                assert!(len <= 1232, "{kind}-{label}: response too large");
            });
            println!("{kind}-{label}: zero-copy UDP allocs={allocations}");
            assert!(
                allocations <= 5,
                "{kind}-{label}: {allocations} allocs/query exceeds warm budget of 5"
            );
        }
    }
}
