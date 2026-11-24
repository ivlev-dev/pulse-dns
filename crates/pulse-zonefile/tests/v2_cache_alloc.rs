//! B2a: warm `lookup` не аллоцирует (счётчик глобального аллокатора).
//!
//! Файл — отдельный test-binary: глобальный аллокатор считает все выделения,
//! поэтому в нём только один тест (нет параллельного шума).

use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicUsize, Ordering};

use pulse_zonefile::key::NameRle;
use pulse_zonefile::parallel::{
    ParallelStore, ParallelZones, RrsetData, StoreConfig, ZoneCreateMeta,
};

struct Counting;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

#[allow(unsafe_code)]
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc_zeroed(layout) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

#[test]
fn warm_lookup_ref_does_not_allocate() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("alloc.v2");
    let store = ParallelStore::create(&path, StoreConfig::small(8, 4096)).unwrap();
    let apex = NameRle::from_ascii("alloc.example").unwrap();
    let name = NameRle::from_ascii("www.alloc.example").unwrap();
    let mut zones = ParallelZones::open(&store).unwrap();
    zones
        .create_zone(&apex, ZoneCreateMeta { soa_serial: 1 })
        .unwrap();
    {
        let mut writer = zones.writer(&apex).unwrap();
        writer
            .upsert_rrset(
                &name,
                1,
                0,
                &RrsetData::from_slices(60, 0, &[&[192, 0, 2, 1]]).unwrap(),
            )
            .unwrap();
        writer.commit().unwrap();
    }
    let reader = store.reader().unwrap();
    let view = zones.read(&reader, &apex).unwrap();
    // Прогрев: локальная арена, кеш страниц и кеш узлов заполнены.
    assert!(view.lookup_ref(&name, 1, 0).unwrap().is_some());
    assert!(store.page_cache_stats().entries > 0);
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for _ in 0..1000 {
        black_box(view.lookup_ref(&name, 1, 0).unwrap());
    }
    let allocations = ALLOCATIONS.load(Ordering::Relaxed).saturating_sub(before);
    assert_eq!(
        allocations, 0,
        "warm lookup_ref аллоцировал {allocations} раз"
    );
    let hits = store.page_cache_stats().hits;
    for _ in 0..10 {
        black_box(view.lookup_ref(&name, 1, 0).unwrap());
    }
    assert!(store.page_cache_stats().hits >= hits);
}
