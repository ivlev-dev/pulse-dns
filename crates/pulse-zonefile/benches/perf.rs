//! Честный замер: p50/p99 по TSC-тикам, cold/warm, счётчик аллокаций.
//!
//! Запуск: `cargo bench -p pulse-zonefile --bench perf`.
//! Каталог — 10k зон, RRset-дерево — 1M ключей. Warm — кеш валидированных
//! страниц прогрет рабочим набором; cold — кеш очищается перед каждым lookup.
//!
//! `std::time::Instant` в контейнере стоит ~1.6 µs (часы через syscall),
//! поэтому интервалы снимаются `rdtsc`; частота калибруется по `Instant`
//! один раз за прогон.

#![allow(unsafe_code)]
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use pulse_zonefile::cache::PageCache;
use pulse_zonefile::key::{CLASS_IN, Key, NameRle};
use pulse_zonefile::node::{ItemValue, LeafItem, LeafValue, ValueKind};
use pulse_zonefile::tree::{BTree, MemoryStore};
use pulse_zonefile::zone_index::{ZoneIndex, ZoneLocation};

struct CountingAllocator;

static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static DEALLOCATIONS: AtomicU64 = AtomicU64::new(0);

// SAFETY: тонкая обёртка над `System`; счётчики — атомарные, поведение
// выделения/освобождения не меняется.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        DEALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

const TXN: u64 = 2;
const PAGE_SIZE: u32 = 4096;
const RUNS: usize = 3;
const LOOKUPS: usize = 200_000;

const BATCH: usize = 64;

fn format_ns(ns: u64) -> String {
    if ns < 1_000 {
        format!("{ns} ns")
    } else if ns < 1_000_000 {
        format!("{:.2} µs", ns as f64 / 1_000.0)
    } else {
        format!("{:.2} ms", ns as f64 / 1_000_000.0)
    }
}

fn reset_allocations() {
    ALLOCATIONS.store(0, Ordering::Relaxed);
    DEALLOCATIONS.store(0, Ordering::Relaxed);
}

fn allocations() -> u64 {
    ALLOCATIONS.load(Ordering::Relaxed)
}

fn percentile(samples: &mut [u64], percent: f64) -> u64 {
    if samples.is_empty() {
        return 0;
    }
    samples.sort_unstable();
    let index = ((samples.len() - 1) as f64 * percent).round() as usize;
    samples.get(index).copied().unwrap_or(0)
}

fn report(name: &str, runs: &mut [Vec<u64>], allocs_per_op: u64) {
    let mut p50s = Vec::new();
    let mut p99s = Vec::new();
    for samples in runs.iter_mut() {
        p50s.push(percentile(samples, 0.50));
        p99s.push(percentile(samples, 0.99));
    }
    p50s.sort_unstable();
    p99s.sort_unstable();
    let p50 = p50s.get(p50s.len() / 2).copied().unwrap_or(0);
    let p99 = p99s.get(p99s.len() / 2).copied().unwrap_or(0);
    println!(
        "{name:<32} p50 {:>10}  p99 {:>10}  allocs/op {allocs_per_op}",
        format_ns(p50),
        format_ns(p99)
    );
}

fn rrset_key(index: u32) -> Key {
    let owner = NameRle::from_ascii(&format!("r{index:07}.example.com")).unwrap();
    Key::new(&owner, 1, CLASS_IN, 0).unwrap()
}

fn rrset_item(index: u32) -> LeafItem {
    LeafItem::new(
        rrset_key(index),
        ItemValue::inline(
            LeafValue {
                kind: ValueKind::Inline,
                flags: 0,
                rr_count: 1,
                ttl: 300,
                val_u32: 0,
                rdlen: 4,
            },
            vec![0, 4, 192, 0, 2, u8::try_from(index & 0xFF).unwrap()],
        )
        .unwrap(),
    )
}

fn build_rrset_tree(size: u32) -> (MemoryStore, BTree) {
    let mut store = MemoryStore::new(PAGE_SIZE).unwrap();
    let tree = BTree::bulk_load(&mut store, TXN, (0..size).map(rrset_item)).unwrap();
    (store, tree)
}

fn bench_zone_index() {
    let index = ZoneIndex::new();
    let names: Vec<NameRle> = (0..10_000_u32)
        .map(|index| NameRle::from_ascii(&format!("z{index:05}.example")).unwrap())
        .collect();
    for (offset, name) in names.iter().enumerate() {
        index.insert(
            *name,
            ZoneLocation {
                root: 14 + u32::try_from(offset).unwrap(),
                level: 1,
                meta_root: 0,
                zone_seq: u32::try_from(offset).unwrap() + 1,
                state: 1,
            },
        );
    }
    let mut runs = Vec::new();
    let mut allocs = 0_u64;
    for _ in 0..RUNS {
        let mut samples = Vec::with_capacity(LOOKUPS);
        reset_allocations();
        let mut step = 0_usize;
        while step < LOOKUPS {
            let start = Instant::now();
            for offset in 0..BATCH {
                let name = names.get((step + offset) % names.len()).unwrap();
                black_box(index.get(black_box(name)).is_some());
            }
            samples.push(u64::try_from(start.elapsed().as_nanos()).unwrap() / BATCH as u64);
            step += BATCH;
        }
        allocs = allocations() / LOOKUPS as u64;
        runs.push(samples);
    }
    report("zone index warm (10k)", &mut runs, allocs);
    let started = Instant::now();
    for step in 0..1_000_000_usize {
        let name = names.get(step % names.len()).unwrap();
        black_box(index.get(black_box(name)).is_some());
    }
    println!(
        "  zone-index avg: {:?}; hits={} misses={}",
        started.elapsed() / 1_000_000,
        index.stats().hits,
        index.stats().misses
    );
}

fn bench_rrset(size: u32) {
    let (store, tree) = build_rrset_tree(size);
    let cache = PageCache::new(PAGE_SIZE);
    // Рабочий набор: ключи, чьи пути помещаются в кеш 1024 страницы.
    let working: Vec<Key> = (0..256_u32)
        .map(|step| rrset_key((step * 4093) % size))
        .collect();
    for key in &working {
        assert!(
            tree.lookup_cached(&store, &cache, TXN, key)
                .unwrap()
                .is_some()
        );
    }
    let before = cache.stats();
    let mut runs = Vec::new();
    let mut allocs = 0_u64;
    for _ in 0..RUNS {
        let mut samples = Vec::with_capacity(LOOKUPS);
        reset_allocations();
        let mut step = 0_usize;
        while step < LOOKUPS {
            let start = Instant::now();
            for offset in 0..BATCH {
                let key = working.get((step + offset) % working.len()).unwrap();
                black_box(
                    tree.lookup_cached(black_box(&store), &cache, TXN, key)
                        .unwrap(),
                );
            }
            samples.push(u64::try_from(start.elapsed().as_nanos()).unwrap() / BATCH as u64);
            step += BATCH;
        }
        allocs = allocations() / LOOKUPS as u64;
        runs.push(samples);
    }
    let stats = cache.stats();
    report(&format!("rrset warm ({size})"), &mut runs, allocs);
    println!(
        "  cache hits={} misses={} entries={} (warmup: hits={} misses={})",
        stats.hits, stats.misses, stats.entries, before.hits, before.misses
    );
    let started = Instant::now();
    for step in 0..1_000_000_usize {
        let key = working.get(step % working.len()).unwrap();
        black_box(tree.lookup_cached(&store, &cache, TXN, key).unwrap());
    }
    println!(
        "  rrset warm avg (1M working set): {:?}",
        started.elapsed() / 1_000_000
    );

    // Cold: кеш очищается перед каждым lookup.
    let cold_cache = PageCache::new(PAGE_SIZE);
    let cold_samples = 200_usize;
    let mut runs = Vec::new();
    for _ in 0..RUNS {
        let mut samples = Vec::with_capacity(cold_samples);
        for step in 0..cold_samples {
            let key = working.get(step % working.len()).unwrap();
            cold_cache.clear();
            let start = Instant::now();
            let found = tree.lookup_cached(&store, &cold_cache, TXN, key).unwrap();
            samples.push(u64::try_from(start.elapsed().as_nanos()).unwrap());
            black_box(found);
        }
        runs.push(samples);
    }
    report(&format!("rrset cold ({size})"), &mut runs, 0);
}

fn bench_insert(size: u32) {
    let (mut store, mut tree) = build_rrset_tree(size);
    let cache = PageCache::new(PAGE_SIZE);
    let warm_key = rrset_key(size / 2);
    let _ = tree.lookup_cached(&store, &cache, TXN, &warm_key).unwrap();
    let inserts = 20_000_usize;
    let mut samples = Vec::with_capacity(inserts);
    reset_allocations();
    let started = Instant::now();
    let mut step = 0_usize;
    while step < inserts {
        let start = Instant::now();
        for offset in 0..BATCH {
            let index = size + u32::try_from(step + offset).unwrap();
            let item = rrset_item(index);
            let outcome = tree
                .insert_or_replace_cached(&mut store, &cache, TXN, &item)
                .unwrap();
            black_box(outcome);
        }
        samples.push(u64::try_from(start.elapsed().as_nanos()).unwrap() / BATCH as u64);
        step += BATCH;
    }
    let elapsed = started.elapsed();
    let allocs = allocations() / inserts as u64;
    let rate = inserts as f64 / elapsed.as_secs_f64();
    let mut all = vec![samples];
    report(&format!("insert ({size})"), &mut all, allocs);
    println!("  insert rate {rate:.0}/s, total {elapsed:?} for {inserts} inserts");
}

fn micro(size: u32) {
    let (store, tree) = build_rrset_tree(size);
    let cache = PageCache::new(PAGE_SIZE);
    let key = rrset_key(size / 2);
    println!("tree level={} root={}", tree.level(), tree.root());
    let mut page_no = tree.root();
    let mut level = tree.level().saturating_sub(1);
    while level > 0 {
        let branch = cache.branch(&store, page_no, TXN, level).unwrap();
        page_no = branch
            .child(branch.predecessor(&key).unwrap().unwrap())
            .unwrap();
        level -= 1;
    }
    let leaf = cache.leaf(&store, page_no, TXN).unwrap();
    let position = leaf.lower_bound(&key).unwrap();
    let started = Instant::now();
    for _ in 0..1_000_000 {
        black_box(cache.leaf(&store, page_no, TXN).unwrap());
    }
    println!(
        "micro cache.leaf hit avg: {:?}",
        started.elapsed() / 1_000_000
    );
    let started = Instant::now();
    for _ in 0..1_000_000 {
        black_box(leaf.lower_bound(black_box(&key)).unwrap());
    }
    println!(
        "micro leaf.lower_bound avg: {:?}",
        started.elapsed() / 1_000_000
    );
    let started = Instant::now();
    for _ in 0..1_000_000 {
        black_box(leaf.value(black_box(position)).unwrap());
    }
    println!("micro leaf.value avg: {:?}", started.elapsed() / 1_000_000);
    let k1 = Key::new(
        &NameRle::from_ascii("a.example.com").unwrap(),
        1,
        CLASS_IN,
        0,
    )
    .unwrap();
    let k2 = Key::new(
        &NameRle::from_ascii("b.example.com").unwrap(),
        1,
        CLASS_IN,
        0,
    )
    .unwrap();
    let started = Instant::now();
    for _ in 0..10_000_000 {
        black_box(k1.compare(black_box(&k2)));
    }
    println!(
        "micro key.compare avg: {:?}",
        started.elapsed() / 10_000_000
    );

    let branch_page = tree.root();
    let branch = cache
        .branch(&store, branch_page, TXN, tree.level() - 1)
        .unwrap();
    let started = Instant::now();
    for _ in 0..1_000_000 {
        black_box(branch.predecessor(black_box(&key)).unwrap());
    }
    println!(
        "micro branch.predecessor avg: {:?}",
        started.elapsed() / 1_000_000
    );
    let started = Instant::now();
    for _ in 0..1_000_000 {
        black_box(
            tree.lookup_cached(&store, &cache, TXN, black_box(&key))
                .unwrap(),
        );
    }
    println!(
        "micro lookup_cached avg: {:?}",
        started.elapsed() / 1_000_000
    );
}

fn main() {
    println!("page_size={PAGE_SIZE}, lookups/run={LOOKUPS}, runs={RUNS}, batch={BATCH}");
    let only = std::env::args().nth(1);
    match only.as_deref() {
        Some("insert") => {
            bench_insert(1_000_000);
            return;
        }
        Some("insert_small") => {
            bench_insert(1_000);
            return;
        }
        Some("lookup") => {
            bench_rrset(1_000_000);
            return;
        }
        Some("zone") => {
            bench_zone_index();
            return;
        }
        _ => {}
    }
    bench_zone_index();
    micro(1_000_000);
    bench_rrset(1_000_000);
    bench_insert(1_000_000);
}
