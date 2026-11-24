#![allow(missing_docs)]
//! Бенчи фазы A: аллокатор, публикация корней, пины, выбор версии, chain.

use criterion::{Criterion, black_box, criterion_group, criterion_main};

use pulse_zonefile::parallel::{
    Allocator, ParallelError, ParallelStore, RootEntry, RootState, StoreConfig,
};

fn publish(store: &ParallelStore, zone: u32, version: u64) {
    let ticket = store.reserve_pages(1).unwrap();
    store.write_raw_page(ticket.first_page, b"bench").unwrap();
    let entry = RootEntry {
        owner_zone: zone,
        version,
        root_page: ticket.first_page,
        state: RootState::Serving,
        ..RootEntry::default()
    };
    for _ in 0..64 {
        match store.publish_root(entry) {
            Ok(_) => return,
            Err(ParallelError::ReaderContended) => {}
            Err(error) => panic!("publish failed: {error:?}"),
        }
    }
    panic!("publish retry limit");
}

fn bench_alloc(c: &mut Criterion) {
    let mut group = c.benchmark_group("pw_alloc_cas");
    for pages in [1_u32, 16, 64] {
        group.bench_function(format!("reserve_exact_{pages}"), |b| {
            let allocator = Allocator::new(100, 2, u32::MAX).unwrap();
            b.iter(|| black_box(allocator.reserve_exact(pages).unwrap()));
        });
    }
    group.finish();

    let mut group = c.benchmark_group("pw_alloc_cached");
    group.bench_function("reserve_1_of_64", |b| {
        let allocator = Allocator::new(100, 2, u32::MAX).unwrap();
        let handle = allocator.handle();
        b.iter(|| black_box(handle.reserve(1).unwrap()));
    });
    group.finish();

    let mut group = c.benchmark_group("pw_txn");
    group.bench_function("next_txn_block64", |b| {
        let allocator = Allocator::new(100, 2, u32::MAX).unwrap();
        let handle = allocator.handle();
        b.iter(|| black_box(handle.next_txn().unwrap()));
    });
    group.finish();
}

fn bench_publish(c: &mut Criterion) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bench.v2");
    let mut config = StoreConfig::small(16, 1 << 20);
    config.max_root_chain_pages = 4096;
    let store = ParallelStore::create(&path, config).unwrap();
    let mut version = 2_u64;
    let mut group = c.benchmark_group("pw_commit_sync_x1");
    group.sample_size(10);
    group.bench_function("publish_root", |b| {
        b.iter(|| {
            publish(&store, 1, version);
            version += 1;
        });
    });
    group.finish();
}

fn bench_read_path(c: &mut Criterion) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bench-read.v2");
    let mut config = StoreConfig::small(16, 1 << 20);
    config.max_root_chain_pages = 4096;
    let store = ParallelStore::create(&path, config).unwrap();
    for version in 2..=8 {
        publish(&store, 1, version);
    }
    let reader = store.reader().unwrap();

    let mut group = c.benchmark_group("pw_zone_snapshot");
    group.bench_function("pin_drop", |b| {
        b.iter(|| {
            let snapshot = store.zone_snapshot(&reader, 1).unwrap();
            black_box(snapshot.version());
        });
    });
    group.finish();

    let mut group = c.benchmark_group("pw_select_root");
    group.bench_function("head", |b| {
        b.iter(|| black_box(store.select_root(1, u64::MAX).unwrap()));
    });
    group.bench_function("ring_ceiling", |b| {
        b.iter(|| black_box(store.select_root(1, 6).unwrap()));
    });
    group.finish();

    // Chain глубины 8: отдельный стор, пин на v2 удерживается всё время.
    let chain_path = dir.path().join("bench-chain.v2");
    let chain_store = ParallelStore::create(&chain_path, config).unwrap();
    publish(&chain_store, 1, 2);
    let chain_reader = chain_store.reader().unwrap();
    let snapshot = chain_store.zone_snapshot(&chain_reader, 1).unwrap();
    for version in 3..=34 {
        publish(&chain_store, 1, version);
    }
    let mut group = c.benchmark_group("pw_root_chain_walk");
    group.bench_function("chain_depth_8", |b| {
        b.iter(|| black_box(chain_store.select_root(1, 2).unwrap()));
    });
    group.finish();
    drop(snapshot);
}

criterion_group!(benches, bench_alloc, bench_publish, bench_read_path);
criterion_main!(benches);
