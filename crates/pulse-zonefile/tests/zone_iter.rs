//! Публичное чтение всех зон и их записей для загрузки в сервер.

use pulse_zonefile::key::NameRle;
use pulse_zonefile::node::{RR_FLAG_APEX, RR_FLAG_EMPTY_NON_TERMINAL};
use pulse_zonefile::{CreateConfig, RrsetData, SyncMode, ZoneFile, ZoneItemValue, ZoneItems};

fn name(text: &str) -> NameRle {
    NameRle::from_ascii(text).unwrap()
}

fn rrset(value: u8) -> RrsetData {
    RrsetData::from_slices(300, 0, &[&[192, 0, 2, value]]).expect("rrset")
}

fn collect(items: ZoneItems<'_>) -> Vec<(String, u16, u32)> {
    items
        .map(|item| {
            let item = item.unwrap();
            match item.value {
                ZoneItemValue::Node { flags } => (
                    format!("node:{}", item.name.as_rle().len()),
                    item.rr_type,
                    u32::from(flags),
                ),
                ZoneItemValue::Rrset(view) => {
                    (format!("rr:{}", view.rdata.len()), item.rr_type, view.ttl)
                }
            }
        })
        .collect()
}

#[test]
#[allow(clippy::too_many_lines)]
fn zones_zone_by_origin_and_zone_items() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    let mut zonefile = ZoneFile::create(
        &path,
        CreateConfig {
            map_size: 64 * 1024 * 1024,
            ..CreateConfig::default()
        },
    )
    .unwrap();
    let apex = name("example.com");
    let www = name("www.example.com");
    let b = name("b.example.com");
    let a_b = name("a.b.example.com");
    let c_b = name("c.b.example.com");
    {
        let mut writer = zonefile.write().unwrap();
        writer.create_zone(&apex, 0).unwrap();
        writer
            .upsert_rrset(
                &apex,
                &apex,
                6,
                0,
                &RrsetData::from_slices(300, 0, &[&[1, 2, 3, 4]]).unwrap(),
            )
            .unwrap();
        writer
            .upsert_rrset(
                &apex,
                &apex,
                2,
                0,
                &RrsetData::from_slices(300, 0, &[&[1, 2]]).unwrap(),
            )
            .unwrap();
        writer.upsert_rrset(&apex, &www, 1, 0, &rrset(1)).unwrap();
        let big: Vec<u8> = (0..600)
            .map(|index| u8::try_from(index % 251).unwrap())
            .collect();
        writer
            .upsert_rrset(
                &apex,
                &name("big.example.com"),
                16,
                0,
                &RrsetData::from_slices(300, 0, &[&big]).unwrap(),
            )
            .unwrap();
        writer.upsert_rrset(&apex, &a_b, 1, 0, &rrset(2)).unwrap();
        writer.upsert_rrset(&apex, &c_b, 1, 0, &rrset(3)).unwrap();
        writer.commit(SyncMode::Sync).unwrap();
    }

    assert!(zonefile.zone_by_origin(&apex).unwrap().is_some());
    assert_eq!(zonefile.zones().unwrap().len(), 1);
    let items: Vec<_> = zonefile
        .zone_items(&apex)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(items.iter().any(|item| {
        item.name == apex
            && item.rr_type == 0
            && matches!(item.value, ZoneItemValue::Node { flags } if flags & RR_FLAG_APEX != 0)
    }));
    assert!(items.iter().any(|item| {
        item.name == b
            && item.rr_type == 0
            && matches!(item.value, ZoneItemValue::Node { flags } if flags & RR_FLAG_EMPTY_NON_TERMINAL != 0)
    }));
    assert!(
        items
            .iter()
            .any(|item| item.name == www && item.rr_type == 1)
    );
    assert!(
        items
            .iter()
            .any(|item| item.name == a_b && item.rr_type == 1)
    );
    assert!(
        items
            .iter()
            .any(|item| item.name == c_b && item.rr_type == 1)
    );
    assert!(items.iter().any(|item| {
        item.name == name("big.example.com")
            && item.rr_type == 16
            && matches!(&item.value, ZoneItemValue::Rrset(view)
                if view.rdata.first().is_some_and(|rdata| rdata.len() == 600))
    }));
    assert!(
        items
            .iter()
            .any(|item| item.name == apex && item.rr_type == 6)
    );
    assert!(
        items
            .iter()
            .any(|item| item.name == apex && item.rr_type == 2)
    );
    let _ = collect(zonefile.zone_items(&apex).unwrap());

    // Пустая зона: дерева ещё нет — итератор пуст.
    let empty = name("empty.example");
    {
        let mut writer = zonefile.write().unwrap();
        writer.create_zone(&empty, 0).unwrap();
        writer.commit(SyncMode::Sync).unwrap();
    }
    assert!(zonefile.zone_items(&empty).unwrap().next().is_none());

    // Tombstone: зона не видна через zone_by_origin и не даёт записей.
    {
        let mut writer = zonefile.write().unwrap();
        writer.delete_zone(&apex).unwrap();
        writer.commit(SyncMode::Sync).unwrap();
    }
    assert!(zonefile.zone_by_origin(&apex).unwrap().is_none());
    assert!(zonefile.zone_items(&apex).unwrap().next().is_none());
    assert_eq!(zonefile.zones().unwrap().len(), 1); // empty.example
}
