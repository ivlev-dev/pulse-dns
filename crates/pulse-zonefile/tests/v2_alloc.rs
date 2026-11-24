//! Аллокатор: 8 потоков × 10k резерваций, уникальность, монотонность, кеш,
//! `txn`, `MapFull`.

use std::collections::HashSet;
use std::sync::Arc;

use pulse_zonefile::parallel::{AllocTicket, ParallelStore, StoreConfig};

fn create_store(dir: &tempfile::TempDir, pages: u32) -> ParallelStore {
    let path = dir.path().join("alloc.v2");
    ParallelStore::create(&path, StoreConfig::small(8, pages)).unwrap()
}

#[test]
fn eight_threads_ten_thousand_exact_reservations() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(create_store(&dir, 120_000));
    let start = store.allocator().start_page_limit();
    let threads = 8;
    let per_thread = 10_000_u32;

    let mut all: Vec<AllocTicket> = Vec::with_capacity((threads * per_thread) as usize);
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for _ in 0..threads {
            let store = Arc::clone(&store);
            handles.push(scope.spawn(move || {
                let mut tickets = Vec::with_capacity(per_thread as usize);
                for _ in 0..per_thread {
                    tickets.push(store.reserve_pages(1).unwrap());
                }
                tickets
            }));
        }
        for handle in handles {
            all.extend(handle.join().unwrap());
        }
    });

    let total = u64::from(threads * per_thread);
    assert_eq!(store.allocator().cursor(), start + total);
    assert_eq!(all.len() as u64, total);

    let mut seen = HashSet::with_capacity(all.len());
    for ticket in &all {
        assert_eq!(ticket.pages, 1);
        assert!(seen.insert(ticket.first_page), "повтор PageId");
    }
    let min = seen.iter().copied().min().unwrap();
    let max = seen.iter().copied().max().unwrap();
    assert!(u64::from(min) >= start);
    assert_eq!(u64::from(max) + 1, start + total);
}

#[test]
fn multi_page_ranges_do_not_overlap() {
    let dir = tempfile::tempdir().unwrap();
    let store = create_store(&dir, 4096);
    let mut ranges = Vec::new();
    for size in [3_u32, 5, 16, 1, 64, 17] {
        ranges.push(store.reserve_pages(size).unwrap());
    }
    ranges.sort_by_key(|ticket| ticket.first_page);
    let mut previous_end = store.allocator().start_page_limit();
    for ticket in &ranges {
        assert_eq!(u64::from(ticket.first_page), previous_end);
        previous_end += u64::from(ticket.pages);
    }
    assert_eq!(previous_end, store.allocator().cursor());
}

#[test]
fn cached_handles_are_unique_and_cursor_accounts_for_cache() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(create_store(&dir, 120_000));
    let start = store.allocator().start_page_limit();
    let threads = 8;
    let per_thread = 5_000_u32;

    let (tickets, cached) = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for _ in 0..threads {
            let store = Arc::clone(&store);
            handles.push(scope.spawn(move || {
                let alloc = store.alloc_handle();
                let mut ids = Vec::with_capacity(per_thread as usize);
                for _ in 0..per_thread {
                    ids.push(alloc.reserve(1).unwrap().first_page);
                }
                (ids, alloc.cached_pages())
            }));
        }
        let mut tickets = Vec::new();
        let mut cached = 0_u32;
        for handle in handles {
            let (mut ids, leftover) = handle.join().unwrap();
            cached += leftover;
            tickets.append(&mut ids);
        }
        (tickets, cached)
    });

    let issued = u64::from(threads * per_thread);
    assert_eq!(
        store.allocator().cursor(),
        start + issued + u64::from(cached),
        "cursor = DP + выданные + остаток кеша"
    );
    let mut seen = HashSet::with_capacity(tickets.len());
    for page in &tickets {
        assert!(seen.insert(*page), "повтор PageId из кеша");
    }
    assert!(cached <= threads * 64);
}

#[test]
fn txn_tickets_are_unique_and_monotonic() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(create_store(&dir, 4096));
    let start = store.allocator().txn_cursor();
    let threads = 8;
    let per_thread = 2_000_u32;

    let (txns, cached) = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for _ in 0..threads {
            let store = Arc::clone(&store);
            handles.push(scope.spawn(move || {
                let alloc = store.alloc_handle();
                let mut values = Vec::with_capacity(per_thread as usize);
                for _ in 0..per_thread {
                    values.push(alloc.next_txn().unwrap());
                }
                (values, alloc.cached_txn())
            }));
        }
        let mut txns = Vec::new();
        let mut cached = 0_u64;
        for handle in handles {
            let (mut values, leftover) = handle.join().unwrap();
            cached += leftover;
            txns.append(&mut values);
        }
        (txns, cached)
    });

    let mut seen = HashSet::with_capacity(txns.len());
    for txn in &txns {
        assert!(seen.insert(*txn), "txn переиспользован");
        assert!(*txn >= start);
    }
    assert_eq!(
        store.allocator().txn_cursor(),
        start + u64::from(threads * per_thread) + cached
    );
}

#[test]
fn map_full_is_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    // data_first = 42 при max_zones = 8.
    let store = create_store(&dir, 45);
    assert_eq!(store.geometry().page_data_first(), 42);
    for _ in 0..3 {
        store.reserve_pages(1).unwrap();
    }
    let before = store.allocator().cursor();
    let error = store.reserve_pages(1).unwrap_err();
    assert!(matches!(
        error,
        pulse_zonefile::parallel::ParallelError::MapFull {
            high_water: 45,
            page_count_max: 45
        }
    ));
    assert_eq!(store.allocator().cursor(), before);
    assert_eq!(
        store.allocator().leaked_pages(store.durable_page_limit()),
        3
    );
}

#[test]
fn create_rejects_prelude_larger_than_map() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("too-small.v2");
    let error = ParallelStore::create(&path, StoreConfig::small(8, 20)).unwrap_err();
    assert!(matches!(
        error,
        pulse_zonefile::parallel::ParallelError::MapFull { .. }
    ));
    assert!(!path.exists(), "неудачный create убирает файл");
}

#[test]
fn large_cached_reservation_near_limit_fits_exactly() {
    let dir = tempfile::tempdir().unwrap();
    let store = create_store(&dir, 142);
    let handle = store.alloc_handle();
    let ticket = handle.reserve(100).unwrap();
    assert_eq!(ticket.pages, 100);
    assert_eq!(ticket.first_page, 42);
    assert_eq!(store.allocator().cursor(), 142);
    assert_eq!(handle.cached_pages(), 0);
    assert!(handle.reserve(1).is_err());
}

#[test]
fn reserve_exact_zero_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let store = create_store(&dir, 512);
    assert!(store.reserve_pages(0).is_err());
    assert!(store.allocator().reserve_exact(0).is_err());
}
