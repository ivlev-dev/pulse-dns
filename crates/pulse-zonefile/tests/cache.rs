//! Поведение кеша валидированных страниц.

use pulse_zonefile::cache::PageCache;
use pulse_zonefile::consts::{PAGE_SIZE_DEFAULT, PAGE_TYPE_LEAF};
use pulse_zonefile::key::{Key, NameRle};
use pulse_zonefile::node::{
    BranchItem, EncodeContext, ItemValue, LeafItem, encode_branch, encode_leaf,
};
use pulse_zonefile::tree::{MemoryStore, PageIo};

const TXN: u64 = 2;

fn node_item(label: &str) -> LeafItem {
    let name = NameRle::from_ascii(label).unwrap();
    LeafItem::new(Key::new(&name, 0, 0, 0).unwrap(), ItemValue::node(0))
}

fn write_leaf(store: &mut MemoryStore, label: &str) -> u32 {
    let page_no = store.alloc_page().unwrap();
    let mut page = vec![0_u8; PAGE_SIZE_DEFAULT as usize];
    encode_leaf(
        &mut page,
        EncodeContext {
            page_no,
            page_size: PAGE_SIZE_DEFAULT,
            txn: TXN,
            lsn: 0,
        },
        &[node_item(label)],
    )
    .unwrap();
    store.write_page(page_no, &page).unwrap();
    page_no
}

#[test]
fn hits_misses_and_capacity() {
    let mut store = MemoryStore::new(PAGE_SIZE_DEFAULT).unwrap();
    let page_a = write_leaf(&mut store, "a.example.com");
    let page_b = write_leaf(&mut store, "b.example.com");
    let page_c = write_leaf(&mut store, "c.example.com");
    let cache = PageCache::with_capacity(PAGE_SIZE_DEFAULT, 2);

    assert_eq!(cache.leaf(&store, page_a, TXN).unwrap().len(), 1);
    assert_eq!(cache.leaf(&store, page_b, TXN).unwrap().len(), 1);
    assert_eq!(cache.stats().misses, 2);
    assert_eq!(cache.stats().entries, 2);

    assert_eq!(cache.leaf(&store, page_a, TXN).unwrap().len(), 1);
    assert_eq!(cache.stats().hits, 1);

    // Третья страница вытесняет самую старую (page_b), ёмкость соблюдена.
    assert_eq!(cache.leaf(&store, page_c, TXN).unwrap().len(), 1);
    assert!(cache.stats().entries <= 2);
    let misses = cache.stats().misses;
    let _ = cache.leaf(&store, page_a, TXN).unwrap();
    let _ = cache.leaf(&store, page_b, TXN).unwrap();
    assert!(
        cache.stats().misses > misses,
        "evicted page must be revalidated"
    );

    cache.clear();
    assert_eq!(cache.stats().entries, 0);
}

#[test]
fn branch_level_is_checked() {
    let mut store = MemoryStore::new(PAGE_SIZE_DEFAULT).unwrap();
    let child_a = write_leaf(&mut store, "a.example.com");
    let child_b = write_leaf(&mut store, "b.example.com");
    let page_no = store.alloc_page().unwrap();
    let mut page = vec![0_u8; PAGE_SIZE_DEFAULT as usize];
    let name_a = NameRle::from_ascii("a.example.com").unwrap();
    let name_b = NameRle::from_ascii("b.example.com").unwrap();
    let items = [
        BranchItem::new(Key::new(&name_a, 0, 0, 0).unwrap(), child_a),
        BranchItem::new(Key::new(&name_b, 0, 0, 0).unwrap(), child_b),
    ];
    encode_branch(
        &mut page,
        EncodeContext {
            page_no,
            page_size: PAGE_SIZE_DEFAULT,
            txn: TXN,
            lsn: 0,
        },
        1,
        &items,
    )
    .unwrap();
    store.write_page(page_no, &page).unwrap();

    let cache = PageCache::new(PAGE_SIZE_DEFAULT);
    let branch = cache.branch(&store, page_no, TXN, 1).unwrap();
    assert_eq!(branch.len(), 2);
    assert_eq!(branch.child(0).unwrap(), child_a);
    assert!(cache.branch(&store, page_no, TXN, 2).is_err());
    assert!(cache.leaf(&store, page_no, TXN).is_err());
}

#[test]
fn rejects_page_newer_than_snapshot() {
    let mut store = MemoryStore::new(PAGE_SIZE_DEFAULT).unwrap();
    let page_no = write_leaf(&mut store, "a.example.com");
    let cache = PageCache::new(PAGE_SIZE_DEFAULT);
    assert!(cache.leaf(&store, page_no, TXN - 1).is_err());
    let page = store.read_page(page_no).unwrap();
    assert_eq!(
        u32::from_le_bytes(page.get(0..4).unwrap().try_into().unwrap()),
        PAGE_TYPE_LEAF
    );
}
