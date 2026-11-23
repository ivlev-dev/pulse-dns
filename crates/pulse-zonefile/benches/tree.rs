#![allow(missing_docs)]
//! Criterion-бенчмарки B+tree: steady-state, cold/warm, без `iter_batched`.
//!
//! Числа p50/p99 и счётчик аллокаций — в `benches/perf.rs`.

use std::hint::black_box;
use std::time::Duration;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};

use pulse_zonefile::cache::PageCache;
use pulse_zonefile::key::{CLASS_IN, Key, NameRle};
use pulse_zonefile::node::{ItemValue, LeafItem, LeafValue, ValueKind};
use pulse_zonefile::tree::{BTree, MemoryStore};

const TXN: u64 = 2;
const PAGE_SIZE: u32 = 4096;

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

fn build(size: u32) -> (MemoryStore, BTree) {
    let mut store = MemoryStore::new(PAGE_SIZE).unwrap();
    let tree = BTree::bulk_load(&mut store, TXN, (0..size).map(rrset_item)).unwrap();
    (store, tree)
}

fn bench_lookup(criterion: &mut Criterion) {
    for size in [10_000_u32, 1_000_000] {
        let (store, tree) = build(size);
        let cache = PageCache::new(PAGE_SIZE);
        let key = rrset_key(size / 2);
        // Прогрев: путь к ключу в кеше.
        assert!(
            tree.lookup_cached(&store, &cache, TXN, &key)
                .unwrap()
                .is_some()
        );

        let mut group = criterion.benchmark_group(format!("rrset_lookup_{size}"));
        group.throughput(Throughput::Elements(1));
        group.sample_size(30);
        group.measurement_time(Duration::from_secs(3));
        group.bench_function("warm", |bencher| {
            bencher.iter(|| {
                tree.lookup_cached(black_box(&store), &cache, TXN, black_box(&key))
                    .unwrap()
            });
        });

        let cold_cache = PageCache::new(PAGE_SIZE);
        group.bench_function("cold", |bencher| {
            bencher.iter(|| {
                cold_cache.clear();
                tree.lookup_cached(black_box(&store), &cold_cache, TXN, black_box(&key))
                    .unwrap()
            });
        });
        group.finish();
    }
}

fn bench_insert(criterion: &mut Criterion) {
    let size = 1_000_000_u32;
    let (mut store, mut tree) = build(size);
    let cache = PageCache::new(PAGE_SIZE);
    let mut next = size;
    let mut group = criterion.benchmark_group("insert");
    group.throughput(Throughput::Elements(1));
    group.sample_size(30);
    group.measurement_time(Duration::from_secs(3));
    group.bench_function("steady_state_1m", |bencher| {
        bencher.iter(|| {
            let index = next;
            next = next.wrapping_add(1);
            let outcome = tree
                .insert_or_replace_cached(&mut store, &cache, TXN, &rrset_item(index))
                .unwrap();
            black_box(outcome);
        });
    });
    group.finish();
}

criterion_group!(benches, bench_lookup, bench_insert);
criterion_main!(benches);
