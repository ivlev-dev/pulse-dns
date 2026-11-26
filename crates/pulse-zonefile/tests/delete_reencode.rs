//! Регрессия flaky `InvariantViolation(EncodedSize)` при удалении в B+tree v2.
//!
//! Причина: длина item'а при фронт-кодировании зависит от позиции restart'а
//! (`shared_len = 0` каждые `LEAF_INTERVAL`/`BRANCH_INTERVAL` item'ов). Любая
//! правка списка item'ов (удаление, перенос при заимствовании) сдвигает
//! последующие позиции, поэтому узел с меньшим числом item'ов может кодироваться
//! **длиннее** и перестать помещаться в страницу. Раньше delete/rebalance-путь
//! писал такой узел без проверки размера и получал `EncodedSize`.
//!
//! В проде это стреляло у secondary на `replace_zone` (IXFR): при заимствовании
//! из правого соседа у него удалялись первые item'ы, сосед с 103 item'ами
//! перекодировался в 4098 Б при странице 4096 Б.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use pulse_zonefile::key::{CLASS_IN, Key, NameRle, name_cmp};
use pulse_zonefile::node::{
    BranchItem, DecodedValue, EncodeContext, ItemValue, LeafItem, LeafValue, ValueKind,
    branch_encoded_size, encode_branch, encode_leaf, leaf_encoded_size,
};
use pulse_zonefile::parallel::ParallelError;
use pulse_zonefile::parallel::{
    OpenConfigV2, ParallelStore, ParallelZones, RrsetData, StoreConfig, ZoneCreateMeta,
};
use pulse_zonefile::tree::{BTree, MemoryStore, PageIo, ZoneTree};

const TXN: u64 = 2;

fn name(text: &str) -> NameRle {
    NameRle::from_ascii(text).unwrap()
}

fn rr(rdata: &[u8]) -> RrsetData {
    RrsetData::from_slices(300, 0, &[rdata]).unwrap()
}

fn soa_record(serial: u32) -> RrsetData {
    let mut rdata = Vec::new();
    rdata.extend_from_slice(&serial.to_be_bytes());
    rdata.extend_from_slice(&[0, 0, 0x0e, 0x10]);
    rdata.extend_from_slice(&[0, 0, 0x07, 0x08]);
    rdata.extend_from_slice(&[0, 0, 0x09, 0x3a]);
    rdata.extend_from_slice(&[0, 0, 0x0e, 0x10]);
    // ns.example.com.
    rdata.extend_from_slice(&[
        2, b'n', b's', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
    ]);
    // hostmaster.example.com.
    rdata.extend_from_slice(&[
        10, b'h', b'o', b's', b't', b'm', b'a', b's', b't', b'e', b'r', 7, b'e', b'x', b'a', b'm',
        b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
    ]);
    RrsetData::from_slices(300, 0, &[&rdata]).unwrap()
}

fn ns_record() -> RrsetData {
    RrsetData::from_slices(
        300,
        0,
        &[&[
            2, b'n', b's', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]],
    )
    .unwrap()
}

fn host_name(index: u32) -> NameRle {
    name(&format!("host{index}.example.com"))
}

/// Ожидаемый inline-payload `{u16 be len; rdata}` для одного RR.
fn payload_bytes(rdata: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(rdata.len() + 2);
    out.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
    out.extend_from_slice(rdata);
    out
}

/// Проверяет, что значение item'а соответствует ожидаемому RDATA.
fn assert_entry_rdata(entry: &pulse_zonefile::tree::StoredEntry, rdata: &[u8], context: &str) {
    match &entry.value {
        DecodedValue::Rrset { value, payload } => {
            if value.kind == ValueKind::Inline {
                assert_eq!(payload.to_vec(), payload_bytes(rdata), "{context}");
            } else {
                // Overflow: rdata живёт в цепочке страниц, сравнение — по длинам.
                assert_eq!(usize::from(value.rdlen), rdata.len(), "{context}");
                assert_eq!(value.rr_count, 1, "{context}");
            }
        }
        DecodedValue::ZoneEntry(_) => panic!("{context}: ожидался RRset, получен ZoneEntry"),
    }
}

/// Полная перезапись содержимого зоны: удалить все имена и записать заново.
/// Точная копия того, что делает `replace_zone` у secondary при IXFR.
fn replace_zone(
    tree: &mut ZoneTree,
    store: &mut MemoryStore,
    txn: u64,
    serial: u32,
    www: u8,
) -> Result<(), String> {
    let items = tree
        .collect_items(store, txn)
        .map_err(|error| format!("collect: {error:?}"))?;
    let mut owners: Vec<NameRle> = Vec::new();
    for item in &items {
        let owner = item
            .key
            .owner()
            .map_err(|error| format!("owner: {error:?}"))?;
        if !owners.contains(&owner) {
            owners.push(owner);
        }
    }
    for owner in &owners {
        tree.delete_name(store, txn, owner)
            .map_err(|error| format!("delete_name {owner}: {error:?}"))?;
    }
    let apex = name("example.com");
    tree.upsert_rrset(store, txn, &apex, 6, 0, &soa_record(serial))
        .map_err(|error| format!("soa: {error:?}"))?;
    tree.upsert_rrset(store, txn, &apex, 2, 0, &ns_record())
        .map_err(|error| format!("ns: {error:?}"))?;
    tree.upsert_rrset(
        store,
        txn,
        &name("www.example.com"),
        1,
        0,
        &rr(&[192, 0, 2, www]),
    )
    .map_err(|error| format!("www: {error:?}"))?;
    for index in 0..100_u32 {
        let octets = [10, 0, 0, u8::try_from(index).unwrap()];
        tree.upsert_rrset(store, txn, &host_name(index), 1, 0, &rr(&octets))
            .map_err(|error| format!("host{index}: {error:?}"))?;
    }
    Ok(())
}

fn assert_zone(tree: &ZoneTree, store: &MemoryStore, txn: u64, www: u8) {
    let items = tree.collect_items(store, txn).expect("collect");
    assert!(
        items
            .windows(2)
            .all(|pair| pair[0].key.compare(&pair[1].key).is_lt()),
        "ключи дерева не по возрастанию"
    );
    let apex = name("example.com");
    assert!(
        tree.lookup(store, txn, &apex, 6, 0).expect("soa").is_some(),
        "потерян SOA"
    );
    assert!(
        tree.lookup(store, txn, &apex, 2, 0).expect("ns").is_some(),
        "потерян NS"
    );
    let www_entry = tree
        .lookup(store, txn, &name("www.example.com"), 1, 0)
        .expect("www")
        .expect("потерян www A");
    assert_entry_rdata(&www_entry, &[192, 0, 2, www], "старый www A");
    for index in 0..100_u32 {
        let octets = [10, 0, 0, u8::try_from(index).unwrap()];
        let owner = host_name(index);
        let entry = tree
            .lookup(store, txn, &owner, 1, 0)
            .expect("lookup")
            .unwrap_or_else(|| panic!("потерян {owner}"));
        assert_entry_rdata(&entry, &octets, &format!("payload {owner}"));
    }
}

/// Детерминированный репродьюсер: до фикса падает на втором цикле замены
/// (`delete_name host42.example.com`; правый сосед после заимствования — 103
/// item'а, 4098 Б при странице 4096 Б).
#[test]
fn replace_zone_cycles_do_not_overflow_on_delete() {
    let mut store = MemoryStore::new(4096).unwrap();
    let mut tree = ZoneTree::empty(name("example.com"));
    let mut txn = TXN;
    for serial in 1..=4_u32 {
        replace_zone(
            &mut tree,
            &mut store,
            txn,
            serial,
            10 + u8::try_from(serial).unwrap(),
        )
        .expect("replace_zone");
        assert_zone(&tree, &store, txn, 10 + u8::try_from(serial).unwrap());
        txn += 1;
    }
    // После четырёх перезаписей дерево должно оставаться валидным по страницам.
    let items = tree.collect_items(&store, txn - 1).expect("collect");
    assert_eq!(
        items.iter().filter(|item| item.key.rr_type() != 0).count(),
        103,
        "SOA + NS + www + 100 host A"
    );
}

/// Детерминированный PRNG (xorshift64*), чтобы тест был воспроизводим.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut state = self.0;
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        self.0 = state;
        state
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

fn stress_owner(index: u32) -> NameRle {
    // Разные длины меток и общие префиксы: front-coding должен «гулять».
    match index % 4 {
        0 => name(&format!("a{index:03}.long-prefix.stress.example.com")),
        1 => name(&format!("b.{index}.stress.example.com")),
        2 => name(&format!("www{index}.stress.example.com")),
        _ => name(&format!("x{}y.stress.example.com", index % 7)),
    }
}

/// Property: 10k операций `upsert` (replace)/`delete_rrset`/`delete_name` в дереве
/// с проверкой содержимого и порядка ключей каждые 250 операций.
#[test]
fn delete_replace_merge_property_10k() {
    const OPS: u32 = 10_000;
    const OWNERS: u32 = 300;
    const TYPES: [u16; 3] = [1, 28, 16];

    let mut store = MemoryStore::new(4096).unwrap();
    let mut tree = ZoneTree::empty(name("stress.example.com"));
    let apex = name("stress.example.com");
    tree.upsert_rrset(&mut store, TXN, &apex, 6, 0, &soa_record(1))
        .unwrap();

    // Ожидаемое содержимое: owner -> (type -> payload).
    // Ключ — RLE-байты имени: `NameRle` не реализует `Ord`.
    let mut expected: BTreeMap<Vec<u8>, BTreeMap<u16, Vec<u8>>> = BTreeMap::new();
    expected
        .entry(apex.as_rle().to_vec())
        .or_default()
        .insert(6, soa_record(1).rdata().first().cloned().unwrap());
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for step in 0..OPS {
        let owner_index = u32::try_from(rng.below(u64::from(OWNERS))).unwrap();
        let owner = stress_owner(owner_index);
        let rr_type = TYPES[usize::try_from(rng.below(3)).unwrap()];
        match rng.below(10) {
            0..=5 => {
                // upsert/replace; изредка — большой payload (overflow-цепочка).
                let len = if rng.below(97) == 0 {
                    600_usize
                } else {
                    4 + usize::try_from(rng.below(12)).unwrap()
                };
                let mut rdata = vec![0_u8; len];
                for (index, byte) in rdata.iter_mut().enumerate() {
                    *byte = u8::try_from((step as usize + index) % 251).unwrap();
                }
                tree.upsert_rrset(&mut store, TXN, &owner, rr_type, 0, &rr(&rdata))
                    .unwrap();
                expected
                    .entry(owner.as_rle().to_vec())
                    .or_default()
                    .insert(rr_type, rdata);
            }
            6..=8 => {
                let key = owner.as_rle().to_vec();
                let present = tree
                    .delete_rrset(&mut store, TXN, &owner, rr_type, 0)
                    .unwrap();
                let removed = expected
                    .get_mut(&key)
                    .and_then(|types| types.remove(&rr_type));
                assert_eq!(
                    present,
                    removed.is_some(),
                    "delete_rrset {owner} type {rr_type}"
                );
                if expected.get(&key).is_some_and(BTreeMap::is_empty) {
                    expected.remove(&key);
                }
            }
            _ => {
                let key = owner.as_rle().to_vec();
                let had = expected.contains_key(&key);
                let removed = tree.delete_name(&mut store, TXN, &owner).unwrap();
                assert_eq!(removed, had, "delete_name {owner}");
                expected.remove(&key);
            }
        }
        if step % 250 == 249 {
            let items = tree.collect_items(&store, TXN).unwrap();
            assert!(
                items
                    .windows(2)
                    .all(|pair| pair[0].key.compare(&pair[1].key).is_lt()),
                "порядок ключей нарушен на шаге {step}"
            );
            let present: BTreeSet<(Vec<u8>, u16)> = items
                .iter()
                .filter(|item| item.key.rr_type() != 0 && item.key.class() == CLASS_IN)
                .map(|item| (item.key.owner_bytes().to_vec(), item.key.rr_type()))
                .collect();
            let wanted: BTreeSet<(Vec<u8>, u16)> = expected
                .iter()
                .flat_map(|(owner, types)| {
                    types.keys().map(move |&rr_type| (owner.clone(), rr_type))
                })
                .collect();
            assert_eq!(present, wanted, "содержимое разошлось на шаге {step}");
        }
    }
    // Финальная сверка значений.
    for (owner, types) in &expected {
        let owner = NameRle::parse(owner).unwrap();
        for (rr_type, rdata) in types {
            let entry = tree
                .lookup(&store, TXN, &owner, *rr_type, 0)
                .unwrap()
                .unwrap_or_else(|| panic!("потерян {owner} type {rr_type}"));
            assert_entry_rdata(&entry, rdata, &format!("payload {owner} type {rr_type}"));
        }
    }
}

fn config() -> StoreConfig {
    StoreConfig::small(32, 131_072)
}

fn leaf_item(label: &str) -> LeafItem {
    let name = NameRle::from_ascii(&format!("{label}.example.com")).unwrap();
    let key = Key::new(&name, 1, CLASS_IN, 0).unwrap();
    let value = LeafValue::new(ValueKind::Inline, 0, 300, 1, 4).unwrap();
    LeafItem::new(
        key,
        ItemValue::inline(value, vec![0, 4, 192, 0, 2, 1]).unwrap(),
    )
}

/// Прямая регрессия split-пути удаления: лист помещается в страницу, но после
/// удаления одного item'а позиции restart'ов сдвигаются, кодирование
/// удлиняется и перестаёт помещаться. Узел обязан разделиться (с ростом уровня
/// дерева), а не упасть с `EncodedSize`.
#[test]
fn leaf_delete_reencode_overflow_splits_node() {
    const PAGE: u32 = 1024;
    let mut items = Vec::new();
    for index in 0..8_u32 {
        items.push(leaf_item(&format!("{}{index:02}", "a".repeat(60))));
    }
    for index in 0..10_u32 {
        items.push(leaf_item(&format!("{}{index:03}", "b".repeat(60))));
    }
    items.sort_by(|left, right| left.key.compare(&right.key));
    assert!(leaf_encoded_size(&items).unwrap() <= PAGE);

    let target = items[0].key;
    let mut remaining = items.clone();
    remaining.remove(0);
    // Предусловие кейса: повторное кодирование после удаления не помещается.
    assert!(
        leaf_encoded_size(&remaining).unwrap() > PAGE,
        "кейс должен переполнять лист после удаления"
    );

    let mut store = MemoryStore::new(PAGE).unwrap();
    let page_no = store.alloc_page().unwrap();
    let mut raw = vec![0_u8; usize::try_from(PAGE).unwrap()];
    let ctx = EncodeContext {
        page_no,
        page_size: PAGE,
        txn: TXN,
        lsn: 0,
    };
    encode_leaf(&mut raw, ctx, &items).unwrap();
    store.write_page(page_no, &raw).unwrap();
    let mut tree = BTree::new(page_no, 1).unwrap();

    tree.delete(&mut store, TXN, &target).expect("delete");
    assert_eq!(tree.level(), 2, "ожидался root split");
    assert!(tree.lookup(&store, TXN, &target).unwrap().is_none());

    let mut cursor = tree.cursor(&store, TXN);
    let mut seen = Vec::new();
    let mut more = cursor.seek_first().unwrap();
    while more {
        seen.push(cursor.key().unwrap().expect("key"));
        more = cursor.advance().unwrap();
    }
    assert_eq!(seen.len(), remaining.len());
    assert!(
        seen.windows(2)
            .all(|pair| pair[0].compare(&pair[1]).is_lt()),
        "порядок ключей нарушен"
    );
    for item in &remaining {
        assert!(
            tree.lookup(&store, TXN, &item.key).unwrap().is_some(),
            "потерян ключ {:?}",
            item.key
        );
    }
}

/// Читательский цикл: пин версии, чтение снапшота и проверка порядка `RRset`.
fn reader_loop(
    zones: &ParallelZones<'_>,
    store: &ParallelStore,
    apex: &NameRle,
    done: &AtomicBool,
    failed: &AtomicBool,
) {
    while !done.load(Ordering::Acquire) {
        let reader = match store.reader() {
            Ok(reader) => reader,
            // Пин-слоты заняты другим читателем — повторяем.
            Err(ParallelError::ReaderContended) => {
                thread::sleep(std::time::Duration::from_millis(1));
                continue;
            }
            Err(error) => {
                eprintln!("reader: {error:?}");
                failed.store(true, Ordering::Release);
                return;
            }
        };
        match zones.read(&reader, apex) {
            Ok(view) => match view.records() {
                Ok(records) => {
                    let ordered = records.windows(2).all(|pair| {
                        name_cmp(pair[0].name.as_rle(), pair[1].name.as_rle())
                            .is_ok_and(std::cmp::Ordering::is_le)
                    });
                    if !ordered {
                        eprintln!("reader: порядок RRset нарушен");
                        failed.store(true, Ordering::Release);
                        return;
                    }
                }
                Err(error) => {
                    eprintln!("reader records: {error:?}");
                    failed.store(true, Ordering::Release);
                    return;
                }
            },
            // `ReaderContended` — документированный retryable-исход гонки с
            // публикацией (пин не успел за 8 попыток); под нагрузкой он
            // ожидаем и не является ошибкой читателя.
            Err(ParallelError::ReaderContended) => {
                thread::sleep(std::time::Duration::from_millis(1));
                continue;
            }
            Err(error) => {
                eprintln!("reader view: {error:?}");
                failed.store(true, Ordering::Release);
                return;
            }
        }
        thread::sleep(std::time::Duration::from_millis(1));
    }
}

fn inline_value() -> ItemValue {
    let value = LeafValue::new(ValueKind::Inline, 0, 300, 1, 4).unwrap();
    ItemValue::inline(value, vec![0, 4, 192, 0, 2, 1]).unwrap()
}

fn long_key(label_index: u32, label_len: usize, fill: char) -> Key {
    let base = usize::try_from(label_index).unwrap();
    let label = format!(
        "{}{base:0width$}",
        fill.to_string().repeat(label_len - 2),
        width = 2
    );
    Key::new(
        &NameRle::from_ascii(&format!("{label}.example.com")).unwrap(),
        1,
        CLASS_IN,
        0,
    )
    .unwrap()
}

/// Прямая регрессия: удаление item'а из **ветвления** тоже может удлинить
/// кодирование (restart-разметка), после чего ветвление обязано разделиться и
/// вырастить корень, а не упасть с `EncodedSize`.
#[test]
fn branch_delete_reencode_overflow_splits_node() {
    const PAGE: u32 = 512;
    let mut keys = Vec::new();
    for index in 0..4_u32 {
        keys.push(long_key(index, 62, 'a'));
    }
    for index in 0..7_u32 {
        keys.push(long_key(index, 63, 'b'));
    }
    keys.sort_by(Key::compare);

    let mut store = MemoryStore::new(PAGE).unwrap();
    let mut children = Vec::new();
    for key in &keys {
        let page_no = store.alloc_page().unwrap();
        let mut raw = vec![0_u8; usize::try_from(PAGE).unwrap()];
        encode_leaf(
            &mut raw,
            EncodeContext {
                page_no,
                page_size: PAGE,
                txn: TXN,
                lsn: 0,
            },
            &[LeafItem::new(*key, inline_value())],
        )
        .unwrap();
        store.write_page(page_no, &raw).unwrap();
        children.push(page_no);
    }
    let branch_items: Vec<BranchItem> = keys
        .iter()
        .zip(children.iter())
        .map(|(key, &child)| BranchItem::new(*key, child))
        .collect();
    assert!(branch_encoded_size(&branch_items).unwrap() <= PAGE);
    let remaining_keys = keys.get(1..).expect("хвост");
    assert!(
        branch_encoded_size(&branch_items[1..]).unwrap() > PAGE,
        "кейс должен переполнять ветвление после удаления"
    );

    let root = store.alloc_page().unwrap();
    let mut raw = vec![0_u8; usize::try_from(PAGE).unwrap()];
    encode_branch(
        &mut raw,
        EncodeContext {
            page_no: root,
            page_size: PAGE,
            txn: TXN,
            lsn: 0,
        },
        1,
        &branch_items,
    )
    .unwrap();
    store.write_page(root, &raw).unwrap();
    let mut tree = BTree::new(root, 2).unwrap();

    let target = keys[0];
    tree.delete(&mut store, TXN, &target).expect("delete");
    assert_eq!(tree.level(), 3, "ожидался root split ветвления");
    assert!(tree.lookup(&store, TXN, &target).unwrap().is_none());
    let mut cursor = tree.cursor(&store, TXN);
    let mut seen = Vec::new();
    let mut more = cursor.seek_first().unwrap();
    while more {
        seen.push(cursor.key().unwrap().expect("key"));
        more = cursor.advance().unwrap();
    }
    assert_eq!(seen.len(), remaining_keys.len());
    for key in remaining_keys {
        assert!(tree.lookup(&store, TXN, key).unwrap().is_some());
    }
}

/// Параллельные читатели не должны видеть повреждённое дерево, пока writer
/// многократно заменяет содержимое зоны (`delete_name` + повторная запись).
#[test]
fn replace_zone_under_concurrent_readers() {
    const ROUNDS: usize = 6;
    const HOSTS: u32 = 60;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("delete-reencode.v2");
    let store = ParallelStore::create(&path, config()).unwrap();
    let apex = name("example.com");
    let mut zones = ParallelZones::open(&store).unwrap();
    zones
        .create_zone(&apex, ZoneCreateMeta { soa_serial: 1 })
        .unwrap();
    {
        let mut writer = zones.writer(&apex).unwrap();
        for index in 0..HOSTS {
            writer
                .upsert_rrset(
                    &host_name(index),
                    1,
                    0,
                    &rr(&[10, 0, 0, u8::try_from(index).unwrap()]),
                )
                .unwrap();
        }
        writer.commit().unwrap();
    }

    let done = AtomicBool::new(false);
    let failed = AtomicBool::new(false);
    thread::scope(|scope| {
        for _ in 0..4 {
            let zones = &zones;
            let store = &store;
            let apex = &apex;
            let done = &done;
            let failed = &failed;
            scope.spawn(move || reader_loop(zones, store, apex, done, failed));
        }

        let mut writer = zones.writer(&apex).unwrap();
        for round in 0..ROUNDS {
            let records = writer.records().unwrap();
            let mut owners: Vec<NameRle> = Vec::new();
            for record in &records {
                if !owners.contains(&record.name) {
                    owners.push(record.name);
                }
            }
            for owner in owners {
                writer.delete_name(&owner).unwrap();
            }
            for index in 0..HOSTS {
                let value = u8::try_from((usize::try_from(index).unwrap() + round) % 250).unwrap();
                writer
                    .upsert_rrset(
                        &host_name(index),
                        1,
                        0,
                        &rr(&[10, 0, u8::try_from(round).unwrap(), value]),
                    )
                    .unwrap();
            }
            writer.commit().unwrap();
        }
        done.store(true, Ordering::Release);
    });
    assert!(!failed.load(Ordering::Acquire), "читатель увидел ошибку");

    let last = zones.writer(&apex).unwrap();
    let records = last.records().unwrap();
    assert_eq!(records.len(), usize::try_from(HOSTS).unwrap());
    drop(last);
    drop(zones);
    drop(store);
    let reopened = ParallelStore::open(&path, OpenConfigV2::default()).unwrap();
    assert!(reopened.fsck_lite().unwrap().ok);
}
