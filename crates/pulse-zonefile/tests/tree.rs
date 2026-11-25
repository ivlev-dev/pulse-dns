//! Тесты B+tree зоны: lookup, split, ENT/APEX, property, overflow.

use std::cmp::Ordering;

use proptest::prelude::*;

use pulse_zonefile::ZoneFileError;
use pulse_zonefile::key::{CLASS_IN, NameRle, T_NODE, name_cmp};
use pulse_zonefile::node::{
    DecodedBranch, DecodedLeaf, LeafItem, LeafValue, RR_FLAG_APEX, RR_FLAG_CHILDREN_MAY_EXIST,
    RR_FLAG_EMPTY_NON_TERMINAL, ValueKind,
};
use pulse_zonefile::tree::{BTree, MemoryStore, PageIo, RrsetData, ZoneTree};

const TXN: u64 = 2;

fn name(text: &str) -> NameRle {
    NameRle::from_ascii(text).unwrap()
}

fn zone() -> ZoneTree {
    ZoneTree::empty(name("example.com"))
}

fn store(page_size: u32) -> MemoryStore {
    MemoryStore::new(page_size).unwrap()
}

fn rrset(rdata: &[&[u8]]) -> RrsetData {
    RrsetData::from_slices(300, 0, rdata).unwrap()
}

fn a_record(byte: u8) -> RrsetData {
    rrset(&[&[192, 0, 2, byte]])
}

fn insert_a(tree: &mut ZoneTree, store: &mut MemoryStore, owner: &NameRle, byte: u8) -> bool {
    tree.upsert_rrset(store, TXN, owner, 1, 0, &a_record(byte))
        .unwrap()
        .changed
}

fn lookup_payload(tree: &ZoneTree, store: &MemoryStore, owner: &NameRle) -> Option<Vec<u8>> {
    let entry = tree.lookup(store, TXN, owner, 1, 0).unwrap()?;
    match entry.value {
        pulse_zonefile::node::DecodedValue::Rrset { payload, .. } => Some(payload.to_vec()),
        pulse_zonefile::node::DecodedValue::ZoneEntry(_) => None,
    }
}

#[test]
fn lookup_empty_single_and_missing() {
    let mut store = store(4096);
    let mut tree = zone();
    assert!(
        tree.lookup(&store, TXN, &name("example.com"), 1, 0)
            .unwrap()
            .is_none()
    );

    let apex = name("example.com");
    assert!(insert_a(&mut tree, &mut store, &apex, 1));
    let entry = tree.lookup(&store, TXN, &apex, 1, 0).unwrap().unwrap();
    match entry.value {
        pulse_zonefile::node::DecodedValue::Rrset { value, payload } => {
            assert_eq!(value.kind, ValueKind::Inline);
            assert_eq!(value.ttl, 300);
            assert_eq!(payload, &[0, 4, 192, 0, 2, 1]);
        }
        pulse_zonefile::node::DecodedValue::ZoneEntry(_) => panic!("expected RRset"),
    }
    assert!(tree.lookup(&store, TXN, &apex, 28, 0).unwrap().is_none());
    assert!(
        tree.lookup(&store, TXN, &name("other.example.com"), 1, 0)
            .unwrap()
            .is_none()
    );
}

#[test]
fn missing_key_between_present_keys() {
    let mut store = store(4096);
    let mut tree = zone();
    for label in ["a", "m", "z"] {
        insert_a(
            &mut tree,
            &mut store,
            &name(&format!("{label}.example.com")),
            1,
        );
    }
    assert!(
        tree.lookup(&store, TXN, &name("b.example.com"), 1, 0)
            .unwrap()
            .is_none()
    );
    assert!(
        tree.lookup(&store, TXN, &name("m.example.com"), 1, 0)
            .unwrap()
            .is_some()
    );
    assert!(
        tree.lookup(&store, TXN, &name("aa.example.com"), 1, 0)
            .unwrap()
            .is_none()
    );
}

#[test]
fn node_ent_apex_s1() {
    let mut store = store(4096);
    let mut tree = zone();
    insert_a(&mut tree, &mut store, &name("a.b.example.com"), 1);
    insert_a(&mut tree, &mut store, &name("c.b.example.com"), 2);

    let b = tree.node(&store, TXN, &name("b.example.com")).unwrap();
    assert!(b.exists);
    assert!(b.has_children);
    assert!(b.is_empty_non_terminal);
    assert!(!b.is_apex);
    assert_eq!(
        b.flags & RR_FLAG_CHILDREN_MAY_EXIST,
        RR_FLAG_CHILDREN_MAY_EXIST
    );

    let apex = tree.node(&store, TXN, &name("example.com")).unwrap();
    assert!(apex.exists);
    assert!(apex.is_apex);
    assert!(apex.has_children);
    assert_eq!(apex.flags & RR_FLAG_APEX, RR_FLAG_APEX);
    assert_eq!(apex.flags & RR_FLAG_EMPTY_NON_TERMINAL, 0);
}

#[test]
fn node_ent_s2_delete_a_keeps_b() {
    // Удаление не реализовано (фаза 2): состояние S2 строится как «есть
    // только c.b», что эквивалентно дереву после удаления a.b.
    let mut store = store(4096);
    let mut tree = zone();
    insert_a(&mut tree, &mut store, &name("c.b.example.com"), 2);
    let b = tree.node(&store, TXN, &name("b.example.com")).unwrap();
    assert!(b.exists && b.has_children && b.is_empty_non_terminal);
    let apex = tree.node(&store, TXN, &name("example.com")).unwrap();
    assert!(apex.has_children);
}

#[test]
fn node_ent_s3_no_children_removes_b() {
    // Состояние S3: удалены оба ребёнка — в фазе 2 строится только apex.
    let mut store = store(4096);
    let mut tree = zone();
    insert_a(&mut tree, &mut store, &name("example.com"), 1);
    let b = tree.node(&store, TXN, &name("b.example.com")).unwrap();
    assert!(!b.exists);
    let apex = tree.node(&store, TXN, &name("example.com")).unwrap();
    assert!(apex.exists && apex.is_apex);
    assert!(!apex.has_children);
    assert_eq!(apex.flags & RR_FLAG_CHILDREN_MAY_EXIST, 0);
}

#[test]
fn node_ent_s4_materializes_b() {
    let mut store = store(4096);
    let mut tree = zone();
    insert_a(&mut tree, &mut store, &name("example.com"), 1);
    insert_a(&mut tree, &mut store, &name("a.b.example.com"), 2);
    let b = tree.node(&store, TXN, &name("b.example.com")).unwrap();
    assert!(b.exists && b.is_empty_non_terminal && b.has_children && !b.is_apex);
    let apex = tree.node(&store, TXN, &name("example.com")).unwrap();
    assert!(apex.is_apex && apex.has_children);
}

#[test]
fn node_ent_s5_empty_zone_root_creation() {
    let mut store = store(4096);
    let mut tree = zone();
    assert_eq!(tree.root(), 0);
    insert_a(&mut tree, &mut store, &name("x.example.com"), 1);
    let apex = tree.node(&store, TXN, &name("example.com")).unwrap();
    assert!(apex.exists && apex.is_apex && apex.has_children && !apex.is_empty_non_terminal);
    let x = tree.node(&store, TXN, &name("x.example.com")).unwrap();
    assert!(x.exists);
    assert!(!x.is_empty_non_terminal);
}

#[test]
fn node_ent_s6_apex_only() {
    let mut store = store(4096);
    let mut tree = zone();
    insert_a(&mut tree, &mut store, &name("example.com"), 1);
    let apex = tree.node(&store, TXN, &name("example.com")).unwrap();
    assert!(apex.exists && apex.is_apex);
    assert!(!apex.has_children);
    assert_eq!(apex.flags & RR_FLAG_CHILDREN_MAY_EXIST, 0);
}

#[test]
fn ent_becomes_owner_clears_ent() {
    let mut store = store(4096);
    let mut tree = zone();
    insert_a(&mut tree, &mut store, &name("a.b.example.com"), 1);
    let before = tree.node(&store, TXN, &name("b.example.com")).unwrap();
    assert!(before.is_empty_non_terminal && before.has_children);
    // Теперь b становится владельцем RRset: ENT снимается, дети остаются.
    insert_a(&mut tree, &mut store, &name("b.example.com"), 2);
    let after = tree.node(&store, TXN, &name("b.example.com")).unwrap();
    assert!(after.exists && !after.is_empty_non_terminal && after.has_children);
    assert!(
        tree.lookup(&store, TXN, &name("b.example.com"), 1, 0)
            .unwrap()
            .is_some()
    );
    let apex = tree.node(&store, TXN, &name("example.com")).unwrap();
    assert!(apex.is_apex && apex.has_children && !apex.is_empty_non_terminal);
}

#[test]
fn ancestor_with_data_is_not_ent() {
    let mut store = store(4096);
    let mut tree = zone();
    insert_a(&mut tree, &mut store, &name("a.b.example.com"), 1);
    insert_a(&mut tree, &mut store, &name("b.example.com"), 2);
    insert_a(&mut tree, &mut store, &name("d.b.example.com"), 3);
    let b = tree.node(&store, TXN, &name("b.example.com")).unwrap();
    assert!(b.exists && b.has_children);
    assert!(
        !b.is_empty_non_terminal,
        "имя с собственным RRset не является ENT даже как предок"
    );
    assert!(
        tree.lookup(&store, TXN, &name("b.example.com"), 1, 0)
            .unwrap()
            .is_some()
    );
    // Внутренний wildcard-предок сохраняет WILDCARD независимо от is_owner.
    insert_a(&mut tree, &mut store, &name("*.example.com"), 4);
    insert_a(&mut tree, &mut store, &name("x.*.example.com"), 5);
    let wildcard = tree.node(&store, TXN, &name("*.example.com")).unwrap();
    assert_eq!(
        wildcard.flags & pulse_zonefile::node::RR_FLAG_WILDCARD,
        1 << 5
    );
    assert!(!wildcard.is_empty_non_terminal);
}

#[test]
fn catalog_btree_lookup() {
    let mut store = store(4096);
    let apexes = ["a.example", "b.example", "c.example"];
    let items: Vec<LeafItem> = apexes
        .iter()
        .map(|text| {
            let apex = name(text);
            let key = pulse_zonefile::key::ZoneEntryKey::new(&apex).unwrap();
            LeafItem::new(
                *key.key(),
                pulse_zonefile::node::ItemValue::zone_entry(&[0x5A_u8; 72]).unwrap(),
            )
        })
        .collect();
    let tree = BTree::bulk_load(&mut store, TXN, items).unwrap();
    for text in apexes {
        let key = pulse_zonefile::key::ZoneEntryKey::new(&name(text)).unwrap();
        let entry = tree.lookup(&store, TXN, key.key()).unwrap().unwrap();
        assert!(matches!(
            entry.value,
            pulse_zonefile::node::DecodedValue::ZoneEntry(bytes) if bytes == [0x5A_u8; 72]
        ));
    }
    let missing = pulse_zonefile::key::ZoneEntryKey::new(&name("d.example")).unwrap();
    assert!(tree.lookup(&store, TXN, missing.key()).unwrap().is_none());
}

#[test]
fn wildcard_flag_and_children() {
    let mut store = store(4096);
    let mut tree = zone();
    insert_a(&mut tree, &mut store, &name("*.example.com"), 1);
    let wildcard = tree.node(&store, TXN, &name("*.example.com")).unwrap();
    assert_eq!(
        wildcard.flags & pulse_zonefile::node::RR_FLAG_WILDCARD,
        1 << 5
    );
    assert!(!wildcard.has_children);
}

#[test]
fn leaf_and_root_splits_keep_all_keys() {
    let mut store = store(4096);
    let mut tree = zone();
    let mut owners = Vec::new();
    for index in 0..400_u32 {
        let owner = name(&format!("n{index}.example.com"));
        insert_a(
            &mut tree,
            &mut store,
            &owner,
            u8::try_from(index % 250).unwrap(),
        );
        owners.push(owner);
    }
    assert!(tree.level() >= 2, "root must become a branch");
    for owner in &owners {
        assert!(
            tree.lookup(&store, TXN, owner, 1, 0).unwrap().is_some(),
            "missing {owner}"
        );
    }
    assert!(
        tree.lookup(&store, TXN, &name("absent.example.com"), 1, 0)
            .unwrap()
            .is_none()
    );
}

#[test]
fn rightmost_split_preserves_tail() {
    let mut store = store(4096);
    let mut tree = zone();
    let mut last = name("example.com");
    for index in 0..500_u32 {
        last = name(&format!("zz{index}.example.com"));
        insert_a(&mut tree, &mut store, &last, 7);
    }
    assert!(tree.level() >= 2);
    assert!(tree.lookup(&store, TXN, &last, 1, 0).unwrap().is_some());
    let previous = name("zz499.example.com");
    assert!(tree.lookup(&store, TXN, &previous, 1, 0).unwrap().is_some());
}

#[test]
fn three_level_tree() {
    let mut store = store(1024);
    let mut tree = zone();
    let mut owners = Vec::new();
    for index in 0..3000_u32 {
        let owner = name(&format!("k{index}.example.com"));
        insert_a(&mut tree, &mut store, &owner, 1);
        owners.push(owner);
    }
    assert_eq!(tree.level(), 3, "expected root branch over branches");
    for owner in owners.iter().step_by(97) {
        assert!(tree.lookup(&store, TXN, owner, 1, 0).unwrap().is_some());
    }
    let root = tree.root();
    let page = store.read_page(root).unwrap();
    let branch = DecodedBranch::decode(page, root, TXN, 1024).unwrap();
    assert!(branch.len() > 1);
}

#[test]
fn next_name_walks_canonical_order() {
    let mut store = store(4096);
    let mut tree = zone();
    let raw = [
        "z.example.com",
        "a.example.com",
        "m.example.com",
        "*.example.com",
    ];
    for text in raw {
        insert_a(&mut tree, &mut store, &name(text), 1);
    }
    // Apex materialized как T_NODE, поэтому первое имя — example.com.
    let mut walked = Vec::new();
    let mut current = tree.next_name(&store, TXN, None).unwrap();
    while let Some(name) = current {
        walked.push(name);
        current = tree.next_name(&store, TXN, Some(&name)).unwrap();
    }
    assert_eq!(walked.len(), 5);
    assert_eq!(walked.first().unwrap(), &name("example.com"));
    for pair in walked.windows(2) {
        let [left, right] = pair else { unreachable!() };
        assert_eq!(
            name_cmp(left.as_rle(), right.as_rle()).unwrap(),
            Ordering::Less
        );
    }
    let expected = [
        "*.example.com",
        "a.example.com",
        "m.example.com",
        "z.example.com",
    ];
    for text in expected {
        assert!(walked.contains(&name(text)), "missing {text}");
    }
}

#[test]
fn prev_name_walks_canonical_order_backwards() {
    let mut store = store(4096);
    let mut tree = zone();
    let raw = [
        "z.example.com",
        "a.example.com",
        "m.example.com",
        "*.example.com",
    ];
    for text in raw {
        insert_a(&mut tree, &mut store, &name(text), 1);
    }
    let expected = [
        "z.example.com",
        "m.example.com",
        "a.example.com",
        "*.example.com",
        "example.com",
    ];
    let mut walked = Vec::new();
    let mut current = tree.prev_name(&store, TXN, None).unwrap();
    while let Some(name) = current {
        walked.push(name);
        current = tree.prev_name(&store, TXN, Some(&name)).unwrap();
    }
    assert_eq!(walked.len(), expected.len());
    for (got, want) in walked.iter().zip(expected.iter()) {
        assert_eq!(got, &name(want), "unexpected predecessor order");
    }
    for pair in walked.windows(2) {
        let [left, right] = pair else { unreachable!() };
        assert_eq!(
            name_cmp(left.as_rle(), right.as_rle()).unwrap(),
            Ordering::Greater
        );
    }
    // Строгий предшественник: для самого первого имени — `None`.
    assert!(
        tree.prev_name(&store, TXN, Some(&name("example.com")))
            .unwrap()
            .is_none()
    );
}

#[test]
fn prev_name_crosses_leaf_pages() {
    let mut store = store(4096);
    let mut tree = zone();
    for index in 0..600_u32 {
        let owner = name(&format!("h{index:04}.example.com"));
        insert_a(&mut tree, &mut store, &owner, 1);
    }
    let mut forward = Vec::new();
    let mut after = None;
    while let Some(name) = tree.next_name(&store, TXN, after.as_ref()).unwrap() {
        forward.push(name);
        after = Some(name);
    }
    assert!(forward.len() >= 600);
    let mut backward = Vec::new();
    let mut before = None;
    while let Some(name) = tree.prev_name(&store, TXN, before.as_ref()).unwrap() {
        backward.push(name);
        before = Some(name);
    }
    forward.reverse();
    assert_eq!(
        forward, backward,
        "prev_name must mirror next_name across pages"
    );
    // Начало и конец последовательности — реальные владельцы зоны.
    assert_eq!(backward.last(), Some(&name("example.com")));
    assert_eq!(backward.first(), Some(&name("h0599.example.com")));
}

#[test]
fn lookup_all_rrsig_by_subtype() {
    let mut store = store(4096);
    let mut tree = zone();
    let apex = name("example.com");
    let rrsig_one = rrset(&[&[0, 1, 8, 1, 2, 3, 4]]);
    let rrsig_two = rrset(&[&[0, 2, 8, 5, 6, 7, 8]]);
    tree.upsert_rrset(&mut store, TXN, &apex, 46, 1, &rrsig_one)
        .unwrap();
    tree.upsert_rrset(&mut store, TXN, &apex, 46, 2, &rrsig_two)
        .unwrap();
    let groups = tree.lookup_all(&store, TXN, &apex, 46).unwrap();
    assert_eq!(groups.len(), 2);
    let subtypes: Vec<_> = groups.iter().map(|item| item.key.subtype()).collect();
    assert_eq!(subtypes, vec![1, 2]);
    assert!(tree.lookup(&store, TXN, &apex, 46, 1).unwrap().is_some());
    assert!(matches!(
        tree.lookup(&store, TXN, &apex, 46, 0),
        Err(ZoneFileError::WrongAccessor)
    ));
    let non_rrsig = tree.lookup_all(&store, TXN, &apex, 1).unwrap();
    assert_eq!(non_rrsig.len(), 0);
}

#[test]
fn repeated_upsert_is_idempotent() {
    let mut store = store(4096);
    let mut tree = zone();
    let apex = name("example.com");
    let first = tree
        .upsert_rrset(&mut store, TXN, &apex, 1, 0, &a_record(1))
        .unwrap();
    assert!(first.changed && first.inserted && !first.replaced);
    let pages = store.allocated_pages();
    let second = tree
        .upsert_rrset(&mut store, TXN, &apex, 1, 0, &a_record(1))
        .unwrap();
    assert!(!second.changed && !second.inserted && second.replaced);
    assert_eq!(
        store.allocated_pages(),
        pages,
        "idempotent upsert must not write pages"
    );

    let changed = tree
        .upsert_rrset(&mut store, TXN, &apex, 1, 0, &a_record(2))
        .unwrap();
    assert!(changed.changed && changed.replaced);
    assert_eq!(
        lookup_payload(&tree, &store, &apex).unwrap(),
        &[0, 4, 192, 0, 2, 2]
    );
}

#[test]
fn overflow_upsert_and_read() {
    let mut store = store(4096);
    let mut tree = zone();
    let apex = name("example.com");
    let rdata = vec![0xAB_u8; 6000];
    let data = rrset(&[&rdata]);
    tree.upsert_rrset(&mut store, TXN, &apex, 16, 0, &data)
        .unwrap();
    let entry = tree.lookup(&store, TXN, &apex, 16, 0).unwrap().unwrap();
    let value = match entry.value {
        pulse_zonefile::node::DecodedValue::Rrset { value, payload } => {
            assert_eq!(payload.len(), 0);
            value
        }
        pulse_zonefile::node::DecodedValue::ZoneEntry(_) => panic!("expected RRset"),
    };
    assert_eq!(value.kind, ValueKind::Overflow);
    let chain = tree.read_overflow(&store, TXN, &value).unwrap().unwrap();
    assert_eq!(chain.len(), 1);
    let rr = chain.rr(0).unwrap().unwrap();
    assert_eq!(rr.len(), 6000);
    let chunks: Vec<_> = rr.chunks().collect();
    assert_eq!(chunks.len(), 2);
    let mut copied = vec![0_u8; 6000];
    assert_eq!(rr.copy_into(&mut copied).unwrap(), 6000);
    assert!(copied.iter().all(|&byte| byte == 0xAB));

    // Повторный идентичный upsert не пишет страницы.
    let pages = store.allocated_pages();
    let again = tree
        .upsert_rrset(&mut store, TXN, &apex, 16, 0, &data)
        .unwrap();
    assert!(!again.changed);
    assert_eq!(store.allocated_pages(), pages);
}

#[test]
fn overflow_two_rrs_chunks() {
    let mut store = store(4096);
    let mut tree = zone();
    let apex = name("example.com");
    let first = vec![0xAA_u8; 6000];
    let second = vec![0xBB_u8; 6000];
    let data = rrset(&[&first, &second]);
    tree.upsert_rrset(&mut store, TXN, &apex, 16, 0, &data)
        .unwrap();
    let entry = tree.lookup(&store, TXN, &apex, 16, 0).unwrap().unwrap();
    let value = match entry.value {
        pulse_zonefile::node::DecodedValue::Rrset { value, .. } => value,
        pulse_zonefile::node::DecodedValue::ZoneEntry(_) => panic!("expected RRset"),
    };
    let chain = tree.read_overflow(&store, TXN, &value).unwrap().unwrap();
    assert_eq!(chain.len(), 2);
    let chunks: Vec<_> = chain.rr(1).unwrap().unwrap().chunks().collect();
    assert_eq!(
        chunks.iter().map(|chunk| chunk.len()).collect::<Vec<_>>(),
        vec![2092, 3908]
    );
}

#[test]
fn inline_empty_rdata() {
    let mut store = store(4096);
    let mut tree = zone();
    let apex = name("example.com");
    let data = rrset(&[&[]]);
    tree.upsert_rrset(&mut store, TXN, &apex, 99, 0, &data)
        .unwrap();
    let entry = tree.lookup(&store, TXN, &apex, 99, 0).unwrap().unwrap();
    match entry.value {
        pulse_zonefile::node::DecodedValue::Rrset { value, payload } => {
            assert_eq!(value.kind, ValueKind::Inline);
            assert_eq!(value.rdlen, 0);
            assert_eq!(payload, &[0, 0]);
        }
        pulse_zonefile::node::DecodedValue::ZoneEntry(_) => panic!("expected RRset"),
    }
}

#[test]
fn bulk_load_builds_valid_tree() {
    let mut store = store(4096);
    let mut tree = zone();
    for index in 0..50_u32 {
        let owner = name(&format!("b{index:04}.example.com"));
        insert_a(&mut tree, &mut store, &owner, 1);
    }
    let items: Vec<LeafItem> = (0..500_u32)
        .map(|index| {
            let owner = name(&format!("n{index:03}.example.com"));
            let key = pulse_zonefile::key::Key::new(&owner, 1, CLASS_IN, 0).unwrap();
            LeafItem::new(
                key,
                pulse_zonefile::node::ItemValue::inline(
                    LeafValue {
                        kind: ValueKind::Inline,
                        flags: 0,
                        rr_count: 1,
                        ttl: 60,
                        val_u32: 0,
                        rdlen: 4,
                    },
                    vec![0, 4, 192, 0, 2, 1],
                )
                .unwrap(),
            )
        })
        .collect();
    let bulk = BTree::bulk_load(&mut store, TXN, items).unwrap();
    let zone_bulk = ZoneTree::new(name("example.com"), bulk.root(), bulk.level()).unwrap();
    for index in 0..500_u32 {
        let owner = name(&format!("n{index:03}.example.com"));
        assert!(
            zone_bulk
                .lookup(&store, TXN, &owner, 1, 0)
                .unwrap()
                .is_some()
        );
    }
    assert!(
        zone_bulk
            .lookup(&store, TXN, &name("n500.example.com"), 1, 0)
            .unwrap()
            .is_none()
    );
}

#[test]
fn split_on_item_size_bounds() {
    use pulse_zonefile::cache::PageCache;
    // Максимальный inline-payload (512 Б): item ~555 Б; 7 влезают, 8-й вызывает split.
    fn big_item(index: u32) -> LeafItem {
        let owner = name(&format!("m{index}.e"));
        let key = pulse_zonefile::key::Key::new(&owner, 1, CLASS_IN, 0).unwrap();
        let payload = {
            let mut payload = vec![0_u8; 2];
            payload.copy_from_slice(&510_u16.to_be_bytes());
            payload.extend(std::iter::repeat_n(0xAB_u8, 510));
            payload
        };
        LeafItem::new(
            key,
            pulse_zonefile::node::ItemValue::inline(
                LeafValue {
                    kind: ValueKind::Inline,
                    flags: 0,
                    rr_count: 1,
                    ttl: 60,
                    val_u32: 0,
                    rdlen: 510,
                },
                payload,
            )
            .unwrap(),
        )
    }
    let mut store = store(4096);
    let mut tree = BTree::empty();
    let cache = PageCache::new(4096);
    for index in 0..8_u32 {
        tree.insert_or_replace_cached(&mut store, &cache, TXN, &big_item(index))
            .unwrap();
    }
    assert!(tree.level() >= 2, "8 max-size items must split");
    for index in 0..8_u32 {
        assert!(
            tree.lookup_cached(&store, &cache, TXN, &big_item(index).key)
                .unwrap()
                .is_some()
        );
    }
    // 2-way split доказуемо покрывает лимиты: 8×557 < 2×4096 с заголовками.

    // Один item больше страницы — invariant, не паника.
    let mut tiny_store = MemoryStore::new(512).unwrap();
    let mut tiny_tree = BTree::empty();
    let tiny_cache = PageCache::new(512);
    assert!(matches!(
        tiny_tree.insert_or_replace_cached(&mut tiny_store, &tiny_cache, TXN, &big_item(0)),
        Err(ZoneFileError::InvariantViolation(_))
    ));
}

#[test]
fn upsert_rejects_out_of_zone_and_reserved_types() {
    let mut store = store(4096);
    let mut tree = zone();
    let data = a_record(1);
    assert!(matches!(
        tree.upsert_rrset(&mut store, TXN, &name("other.net"), 1, 0, &data),
        Err(ZoneFileError::NameOutsideZone)
    ));
    assert!(matches!(
        RrsetData::from_slices(u32::MAX, 0, &[&[1]]),
        Err(ZoneFileError::TtlOutOfRange { .. })
    ));
    assert!(matches!(
        tree.upsert_rrset(&mut store, TXN, &name("example.com"), T_NODE, 0, &data),
        Err(ZoneFileError::InvariantViolation(_))
    ));
    assert!(matches!(
        tree.upsert_rrset(&mut store, TXN, &name("example.com"), 46, 0, &data),
        Err(ZoneFileError::WrongAccessor)
    ));
}

#[test]
fn cached_lookup_matches_uncached_and_warms() {
    use pulse_zonefile::cache::PageCache;
    let mut store = store(4096);
    let mut tree = zone();
    let names: Vec<_> = (0..300_u32)
        .map(|index| name(&format!("c{index:03}.example.com")))
        .collect();
    for (index, owner) in names.iter().enumerate() {
        insert_a(
            &mut tree,
            &mut store,
            owner,
            u8::try_from(index % 250).unwrap(),
        );
    }
    let cache = PageCache::new(4096);
    for owner in &names {
        let cached = tree
            .lookup_cached(&store, &cache, TXN, owner, 1, 0)
            .unwrap();
        let uncached = tree.lookup(&store, TXN, owner, 1, 0).unwrap();
        assert!(cached.is_some());
        match (cached, uncached) {
            (Some(left), Some(right)) => {
                assert_eq!(left.key, right.key);
                match (left.value, right.value) {
                    (
                        pulse_zonefile::node::DecodedValue::Rrset {
                            value: a,
                            payload: pa,
                        },
                        pulse_zonefile::node::DecodedValue::Rrset {
                            value: b,
                            payload: pb,
                        },
                    ) => {
                        assert_eq!(a, b);
                        assert_eq!(pa, pb);
                    }
                    _ => panic!("unexpected value kind"),
                }
            }
            _ => panic!("cached/uncached mismatch"),
        }
    }
    let stats = cache.stats();
    assert!(stats.misses > 0 && stats.hits > 0);
    let hits_before = stats.hits;
    for owner in &names {
        assert!(
            tree.lookup_cached(&store, &cache, TXN, owner, 1, 0)
                .unwrap()
                .is_some()
        );
    }
    assert!(cache.stats().hits > hits_before);
    assert!(
        tree.lookup_cached(&store, &cache, TXN, &name("absent.example.com"), 1, 0)
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        tree.lookup_cached(&store, &cache, TXN, &name("example.com"), 46, 0),
        Err(ZoneFileError::WrongAccessor)
    ));
}

#[test]
fn cached_insert_and_lookup() {
    use pulse_zonefile::cache::PageCache;
    let mut store = store(4096);
    let mut tree = zone();
    let cache = PageCache::new(4096);
    let apex = name("example.com");
    let item = {
        let data = a_record(9);
        let payload = data.payload().unwrap();
        LeafItem::new(
            pulse_zonefile::key::Key::new(&apex, 1, CLASS_IN, 0).unwrap(),
            pulse_zonefile::node::ItemValue::inline(
                LeafValue {
                    kind: ValueKind::Inline,
                    flags: 0,
                    rr_count: data.rr_count().unwrap(),
                    ttl: data.ttl(),
                    val_u32: 0,
                    rdlen: data.rdlen().unwrap(),
                },
                payload,
            )
            .unwrap(),
        )
    };
    tree.btree_mut()
        .insert_or_replace_cached(&mut store, &cache, TXN, &item)
        .unwrap();
    let entry = tree
        .lookup_cached(&store, &cache, TXN, &apex, 1, 0)
        .unwrap();
    assert!(entry.is_some());
}

#[test]
fn property_10k_random_inserts() {
    let mut store = store(1024);
    let mut tree = zone();
    let mut state = 0x1234_5678_9ABC_DEF0_u64;
    let mut owners = Vec::new();
    let mut seen = std::collections::HashSet::new();
    while owners.len() < 10_000 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let label = format!("r{:016x}", state & 0xFFFF_FFFF);
        let owner = name(&format!("{label}.example.com"));
        if !seen.insert(owner) {
            continue;
        }
        insert_a(
            &mut tree,
            &mut store,
            &owner,
            u8::try_from(state & 0xFF).unwrap(),
        );
        owners.push(owner);
    }
    for owner in &owners {
        assert!(
            tree.lookup(&store, TXN, owner, 1, 0).unwrap().is_some(),
            "loss: {owner}"
        );
    }
    let mut walked = Vec::new();
    let mut current = tree.next_name(&store, TXN, None).unwrap();
    while let Some(name) = current {
        walked.push(name);
        current = tree.next_name(&store, TXN, Some(&name)).unwrap();
    }
    assert_eq!(walked.len(), 10_001, "apex T_NODE + 10k owners");
    for pair in walked.windows(2) {
        let [left, right] = pair else { unreachable!() };
        assert_eq!(
            name_cmp(left.as_rle(), right.as_rle()).unwrap(),
            Ordering::Less
        );
    }
    let unique: std::collections::HashSet<_> = walked.iter().collect();
    assert_eq!(unique.len(), walked.len(), "duplicate names in traversal");

    // Нормализуем значение первого владельца, затем проверяем идемпотентность.
    let _ = tree
        .upsert_rrset(&mut store, TXN, &owners[0], 1, 0, &a_record(1))
        .unwrap();
    let pages = store.allocated_pages();
    let again = tree
        .upsert_rrset(&mut store, TXN, &owners[0], 1, 0, &a_record(1))
        .unwrap();
    assert!(!again.changed);
    assert_eq!(store.allocated_pages(), pages);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn garbage_pages_never_panic(
        bytes in proptest::collection::vec(any::<u8>(), 0..9000),
        page_no in any::<u32>(),
        txn in any::<u64>(),
    ) {
        let leaf = DecodedLeaf::decode(&bytes, page_no, txn, 4096);
        if let Ok(leaf) = leaf {
            let _ = leaf.to_owned();
        }
        let branch = DecodedBranch::decode(&bytes, page_no, txn, 4096);
        if let Ok(branch) = branch {
            let _ = branch.to_owned();
        }
    }

    #[test]
    fn mutated_valid_leaf_never_panics(flips in proptest::collection::vec((0_usize..4096, any::<u8>()), 1..16)) {
        let mut store = MemoryStore::new(4096).unwrap();
        let mut tree = zone();
        insert_a(&mut tree, &mut store, &name("example.com"), 1);
        let mut page = store.read_page(tree.root()).unwrap().to_vec();
        for (offset, value) in flips {
            if let Some(byte) = page.get_mut(offset) {
                *byte = value;
            }
        }
        if let Ok(leaf) = DecodedLeaf::decode(&page, tree.root(), TXN, 4096) {
            let _ = leaf.to_owned();
        }
    }
}
