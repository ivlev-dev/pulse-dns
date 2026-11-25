//! Read-path v2: order-key поиск, zero-copy `lookup_ref`, лимиты кешей.
//!
//! Проверяет, что `memcmp`-префиксы не меняют выдачу: результат с кешем узлов
//! совпадает с путём без кеша (полный RLE-компаратор), включая имена с длинным
//! общим суффиксом, метки с `0x00` и ключи, различающиеся только хвостом.

use pulse_zonefile::key::NameRle;
use pulse_zonefile::parallel::{
    ParallelStore, ParallelZones, RrsetData, StoreConfig, ZoneCreateMeta,
};

fn rr(value: u8) -> RrsetData {
    RrsetData::from_slices(60, 0, &[&[10, 20, 30, value]]).unwrap()
}

fn rle(labels: &[&[u8]]) -> NameRle {
    let mut bytes = Vec::new();
    for label in labels {
        bytes.push(u8::try_from(label.len()).unwrap());
        bytes.extend_from_slice(label);
    }
    bytes.push(0);
    NameRle::parse(&bytes).unwrap()
}

fn names() -> Vec<NameRle> {
    let mut names = Vec::new();
    // Длинный общий суффикс: префикс 16 Б не доходит до owner-метки.
    for index in 0..400_u32 {
        names.push(NameRle::from_ascii(&format!("h{index}.long.suffix.example")).unwrap());
    }
    // Метки с 0x00 и «похожие» имена (проверка экранирования).
    for tail in 0..16_u8 {
        names.push(rle(&[b"example", b"zero", &[b'a', 0x00, tail]]));
        names.push(rle(&[b"example", b"zero", &[b'a', tail]]));
        names.push(rle(&[b"example", b"zero", b"a"]));
        names.push(rle(&[b"example", b"zero", b"ab"]));
        names.push(rle(&[b"example", b"zero", b"b"]));
    }
    // Одно и то же имя с разными type/subtype.
    names.push(NameRle::from_ascii("tail.example").unwrap());
    names
}

fn create(entries: usize) -> (tempfile::TempDir, ParallelStore, NameRle, Vec<NameRle>) {
    let dir = tempfile::tempdir().unwrap();
    let mut config = StoreConfig::small(8, 1 << 16);
    config.page_cache_entries = entries;
    let store = ParallelStore::create(&dir.path().join("read.v2"), config).unwrap();
    let apex = NameRle::from_ascii("example").unwrap();
    let mut zones = ParallelZones::open(&store).unwrap();
    zones
        .create_zone(&apex, ZoneCreateMeta { soa_serial: 1 })
        .unwrap();
    let names = names();
    {
        let mut writer = zones.writer(&apex).unwrap();
        for (index, name) in names.iter().enumerate() {
            let value = u8::try_from(index % 251).unwrap();
            writer.upsert_rrset(name, 16, 0, &rr(value)).unwrap();
            if index % 64 == 63 {
                writer.commit().unwrap();
            }
        }
        // То же имя, другие type/subtype: хвост ключа отличается.
        for subtype in 0..4_u16 {
            writer
                .upsert_rrset(&names[0], 46, subtype + 1, &rr(7))
                .unwrap();
        }
        writer.commit().unwrap();
    }
    (dir, store, apex, names)
}

fn lookups(
    zones: &ParallelZones<'_>,
    apex: &NameRle,
    names: &[NameRle],
) -> Vec<Option<Vec<Vec<u8>>>> {
    let reader = zones.store().reader().unwrap();
    let view = zones.read(&reader, apex).unwrap();
    let mut out = Vec::new();
    for name in names {
        out.push(view.lookup(name, 16, 0).unwrap().map(|record| record.rdata));
        out.push(view.lookup(name, 1, 0).unwrap().map(|record| record.rdata));
        out.push(view.lookup(name, 46, 1).unwrap().map(|record| record.rdata));
    }
    // Промахи.
    let absent = NameRle::from_ascii("absent.example").unwrap();
    out.push(
        view.lookup(&absent, 16, 0)
            .unwrap()
            .map(|record| record.rdata),
    );
    out
}

#[test]
fn order_key_path_matches_full_comparator() {
    let (_dir_a, cached, apex_a, names_a) = create(1024);
    let (_dir_b, plain, apex_b, names_b) = create(0);
    let cached_values = {
        let zones = ParallelZones::open(&cached).unwrap();
        lookups(&zones, &apex_a, &names_a)
    };
    let plain_values = {
        let zones = ParallelZones::open(&plain).unwrap();
        lookups(&zones, &apex_b, &names_b)
    };
    assert_eq!(cached_values, plain_values);
    assert_eq!(
        cached_values.iter().filter(|value| value.is_some()).count(),
        names_a.len() + 1
    );
    assert!(cached.node_cache_stats().hits > 0);
    assert_eq!(plain.node_cache_stats().capacity, 0);
}

#[test]
fn lookup_ref_is_zero_copy_and_matches_lookup() {
    let (_dir, store, apex, names) = create(1024);
    let zones = ParallelZones::open(&store).unwrap();
    let reader = store.reader().unwrap();
    let view = zones.read(&reader, &apex).unwrap();
    for name in names.iter().take(64) {
        let owned = view.lookup(name, 16, 0).unwrap().unwrap();
        let borrowed = view.lookup_ref(name, 16, 0).unwrap().unwrap();
        assert_eq!(borrowed.ttl, owned.ttl);
        assert_eq!(borrowed.flags, owned.flags);
        assert_eq!(borrowed.name, *name);
        // INLINE payload: один RR, rdlen 4 → `[len_hi, len_lo] || rdata`.
        assert_eq!(borrowed.payload.len(), 6);
        assert_eq!(&borrowed.payload[2..], owned.rdata[0].as_slice());
    }
}

#[test]
fn tail_only_differences_and_classes_are_found() {
    let (_dir, store, apex, names) = create(64);
    let zones = ParallelZones::open(&store).unwrap();
    let reader = store.reader().unwrap();
    let view = zones.read(&reader, &apex).unwrap();
    // Ключи одного имени, различающиеся type/subtype.
    for subtype in 1..=4_u16 {
        let record = view.lookup(&names[0], 46, subtype).unwrap();
        assert!(record.is_some(), "subtype {subtype}");
    }
    // `RRSIG` с subtype = 0 — `WrongAccessor` (§12.5), проверяем отдельно.
    assert!(matches!(
        view.lookup(&names[0], 46, 0),
        Err(pulse_zonefile::parallel::ParallelError::Tree(
            pulse_zonefile::ZoneFileError::WrongAccessor
        ))
    ));
    assert_eq!(
        view.lookup(&names[0], 16, 0).unwrap().unwrap().rdata[0].len(),
        4
    );
}

#[test]
fn cache_memory_is_bounded_by_entries() {
    let (_dir, store, apex, names) = create(32);
    let zones = ParallelZones::open(&store).unwrap();
    let reader = store.reader().unwrap();
    let view = zones.read(&reader, &apex).unwrap();
    for _ in 0..4 {
        for name in &names {
            let _ = view.lookup_ref(name, 16, 0).unwrap();
        }
    }
    let page = store.page_cache_stats();
    assert_eq!(page.capacity, 32);
    assert!(page.entries <= 32);
    assert!(store.node_cache_stats().entries <= 32);
    let node = store.node_cache().unwrap();
    assert!(node.evictions() > 0 || page.evictions > 0);
    // 32 страницы по 4 КиБ + метаданные узлов с запасом.
    assert!(
        store.cache_memory_bytes() <= 32 * (4096 + 4096),
        "cache memory {} B",
        store.cache_memory_bytes()
    );
}
