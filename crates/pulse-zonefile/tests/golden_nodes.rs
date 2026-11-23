//! Golden-страницы §22: побайтовая раскладка узлов и `encoded_size`.

use pulse_zonefile::consts::PAGE_SIZE_DEFAULT;
use pulse_zonefile::key::{CLASS_IN, Key, NameRle, T_NODE, ZoneEntryKey};
use pulse_zonefile::node::{
    DecodedLeaf, EncodeContext, ItemValue, LeafItem, LeafValue, RR_FLAG_APEX, ValueKind,
    encode_leaf,
};

const PAGE_SIZE: usize = 4096;

fn name(text: &str) -> NameRle {
    NameRle::from_ascii(text).unwrap()
}

fn ctx(page_no: u32) -> EncodeContext {
    EncodeContext {
        page_no,
        page_size: PAGE_SIZE_DEFAULT,
        txn: 2,
        lsn: 0,
    }
}

fn put(target: &mut [u8], offset: usize, bytes: &[u8]) {
    target
        .get_mut(offset..offset + bytes.len())
        .unwrap()
        .copy_from_slice(bytes);
}

fn zone_entry_golden() -> [u8; 72] {
    let mut value = [0_u8; 72];
    put(&mut value, 0, &1_u16.to_le_bytes()); // class = IN
    put(&mut value, 4, &14_u32.to_le_bytes()); // tree_root
    put(&mut value, 8, &1_u16.to_le_bytes()); // tree_level
    // state = 0 (Initializing), reserved0 = 0
    put(&mut value, 12, &1_u32.to_le_bytes()); // rrset_count
    put(&mut value, 40, &1_u32.to_le_bytes()); // rr_count
    put(&mut value, 56, &13_u32.to_le_bytes()); // zone_origin_len
    put(&mut value, 60, &1_u32.to_le_bytes()); // zone_seq
    put(&mut value, 64, &15_u32.to_le_bytes()); // meta_root
    value
}

fn inline_value(flags: u16, ttl: u32, rdlen: u16) -> LeafValue {
    LeafValue {
        kind: ValueKind::Inline,
        flags,
        rr_count: 1,
        ttl,
        val_u32: 0,
        rdlen,
    }
}

#[test]
fn page13_zone_catalog_golden() {
    let apex = name("example.com");
    let key = ZoneEntryKey::new(&apex).unwrap();
    let item = LeafItem::new(
        *key.key(),
        ItemValue::zone_entry(&zone_entry_golden()).unwrap(),
    );
    let mut page = vec![0_u8; PAGE_SIZE];
    let encoded = encode_leaf(&mut page, ctx(13), &[item]).unwrap();
    assert_eq!(encoded.encoded_size, 155);
    assert_eq!(encoded.free_bytes, 3941);
    assert_eq!(encoded.n_items, 1);
    assert_eq!(encoded.n_restarts, 1);

    let mut expected = vec![0_u8; PAGE_SIZE];
    put(&mut expected, 40, &0_u16.to_le_bytes()); // level
    put(&mut expected, 42, &1_u16.to_le_bytes()); // n_items
    put(&mut expected, 44, &1_u16.to_le_bytes()); // n_restarts
    put(&mut expected, 46, &1_u16.to_le_bytes()); // SORTED_VALIDATED
    put(&mut expected, 48, &3941_u32.to_le_bytes()); // free_bytes
    put(&mut expected, 52, &4001_u32.to_le_bytes()); // items_start
    put(&mut expected, 56, &4001_u16.to_le_bytes()); // restart[0]
    put(&mut expected, 58, &4001_u16.to_le_bytes()); // slot[0]
    // item
    put(&mut expected, 4001, &0_u16.to_le_bytes()); // shared_len
    put(&mut expected, 4003, &19_u16.to_le_bytes()); // suffix_len
    put(
        &mut expected,
        4005,
        &[
            3, b'c', b'o', b'm', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0, 0xFE, 0xFF, 0, 0,
            0, 0,
        ],
    );
    put(&mut expected, 4024, &zone_entry_golden());

    assert_eq!(
        page.get(40..).unwrap(),
        expected.get(40..).unwrap(),
        "node area must match §22 page 13 byte-for-byte"
    );

    let decoded = DecodedLeaf::decode(&page, 13, 2, PAGE_SIZE_DEFAULT).unwrap();
    assert_eq!(decoded.encoded_size(), 155);
    assert_eq!(decoded.free_bytes(), 3941);
    assert_eq!(decoded.key(0).unwrap(), *key.key());
    assert_eq!(decoded.to_owned().unwrap().items.len(), 1);
}

/// §22 page 14 (исправлено): `example.com IN A` — `shared=13`, `suffix=6`,
/// `item_bytes=36`, `encoded_size=141`. Исходная арифметика §22 (14/5/35/140)
/// кодировала `type=256, class=256` и была дефектом спеки.
#[test]
fn page14_rrset_golden_bytes() {
    let example = name("example.com");
    let node_key = Key::new(&example, T_NODE, 0, 0).unwrap();
    let a_key = Key::new(&example, 1, CLASS_IN, 0).unwrap();
    let items = vec![
        LeafItem::new(node_key, ItemValue::node(RR_FLAG_APEX)),
        LeafItem::new(
            a_key,
            ItemValue::inline(inline_value(0, 300, 4), vec![0, 4, 0xC0, 0, 2, 1]).unwrap(),
        ),
    ];
    let mut page = vec![0_u8; PAGE_SIZE];
    let encoded = encode_leaf(&mut page, ctx(14), &items).unwrap();
    assert_eq!(encoded.encoded_size, 141);
    assert_eq!(encoded.free_bytes, 3955);
    assert_eq!(encoded.n_items, 2);
    assert_eq!(encoded.n_restarts, 1);

    let mut expected = vec![0_u8; PAGE_SIZE];
    put(&mut expected, 40, &0_u16.to_le_bytes());
    put(&mut expected, 42, &2_u16.to_le_bytes());
    put(&mut expected, 44, &1_u16.to_le_bytes());
    put(&mut expected, 46, &1_u16.to_le_bytes());
    put(&mut expected, 48, &3955_u32.to_le_bytes());
    put(&mut expected, 52, &4017_u32.to_le_bytes());
    put(&mut expected, 56, &4017_u16.to_le_bytes()); // restart[0]
    put(&mut expected, 58, &4017_u16.to_le_bytes()); // slot[0]
    put(&mut expected, 60, &4060_u16.to_le_bytes()); // slot[1]

    // item 0: T_NODE(example.com), shared=0, suffix=19, LeafValue 20.
    put(&mut expected, 4017, &0_u16.to_le_bytes());
    put(&mut expected, 4019, &19_u16.to_le_bytes());
    put(
        &mut expected,
        4021,
        &[
            3, b'c', b'o', b'm', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0, 0, 0, 0, 0, 0,
        ],
    );
    put(
        &mut expected,
        4040,
        &[0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    );

    // item 1: shared=13, suffix=6 (`01 00 01 00 00 00`), LeafValue + payload.
    put(&mut expected, 4060, &13_u16.to_le_bytes());
    put(&mut expected, 4062, &6_u16.to_le_bytes());
    put(&mut expected, 4064, &[1, 0, 1, 0, 0, 0]);
    put(
        &mut expected,
        4070,
        &[
            1, 0, 0, 0, 1, 0, 0, 0, 0x2C, 1, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0,
        ],
    );
    put(&mut expected, 4090, &[0, 4, 0xC0, 0, 2, 1]);

    assert_eq!(
        page.get(40..).unwrap(),
        expected.get(40..).unwrap(),
        "node area must match corrected §22 page 14 byte-for-byte"
    );
    let decoded = DecodedLeaf::decode(&page, 14, 2, PAGE_SIZE_DEFAULT).unwrap();
    assert_eq!(decoded.encoded_size(), 141);
    assert_eq!(decoded.key(0).unwrap(), node_key);
    assert_eq!(decoded.key(1).unwrap(), a_key);
    assert_eq!(decoded.leaf_value(1).unwrap().unwrap().ttl, 300);
    assert_eq!(decoded.inline_payload(1).unwrap(), &[0, 4, 0xC0, 0, 2, 1]);
    assert_eq!(decoded.to_owned().unwrap().items, items);
}

#[test]
fn encoded_size_matches_page_formula() {
    let example = name("example.com");
    let items: Vec<_> = (1_u16..=20)
        .map(|rr_type| {
            LeafItem::new(
                Key::new(&example, rr_type, CLASS_IN, 0).unwrap(),
                ItemValue::inline(inline_value(0, 60, 4), vec![0, 4, 192, 0, 2, 1]).unwrap(),
            )
        })
        .collect();
    let size = pulse_zonefile::node::leaf_encoded_size(&items).unwrap();
    let mut page = vec![0_u8; PAGE_SIZE];
    let encoded = encode_leaf(&mut page, ctx(20), &items).unwrap();
    assert_eq!(encoded.encoded_size, size);
    assert_eq!(encoded.free_bytes, PAGE_SIZE_DEFAULT - size);
    let decoded = DecodedLeaf::decode(&page, 20, 2, PAGE_SIZE_DEFAULT).unwrap();
    assert_eq!(decoded.len(), items.len());
    assert_eq!(decoded.encoded_size(), size);
    assert_eq!(decoded.node_flags() & 1, 1);
}
