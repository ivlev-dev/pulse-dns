//! Freelist/reclaim: повторное использование страниц и границы watermark.

use pulse_zonefile::key::NameRle;
use pulse_zonefile::{CreateConfig, RrsetData, SyncMode, ZoneFile, is_reclaimable};

fn rrset(value: u8) -> RrsetData {
    RrsetData::from_slices(300, 0, &[&[192, 0, 2, value]]).expect("rrset")
}

#[test]
fn reclaim_boundaries_are_strict() {
    assert!(!is_reclaimable(1, 1, u64::MAX));
    assert!(!is_reclaimable(2, 2, u64::MAX));
    assert!(is_reclaimable(1, 2, u64::MAX));
    assert!(!is_reclaimable(3, 4, 2));
    assert!(is_reclaimable(3, 4, 3));
    assert!(is_reclaimable(3, 5, 3));
}

#[test]
fn steady_updates_do_not_grow_file_linearly() {
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
    let apex = NameRle::from_ascii("example.com").unwrap();
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
        writer.commit(SyncMode::Sync).unwrap();
    }
    let mut high_water = zonefile.meta().page_count_high_water;
    for value in 0_u8..200 {
        let mut writer = zonefile.write().unwrap();
        writer
            .upsert_rrset(&apex, &apex, 1, 0, &rrset(value))
            .unwrap();
        writer.commit(SyncMode::Sync).unwrap();
        if value == 20 {
            high_water = zonefile.meta().page_count_high_water;
        }
    }
    // На стабильной нагрузке high_water колеблется на несколько страниц,
    // а не растёт на O(коммитов).
    assert!(
        zonefile.meta().page_count_high_water <= high_water + 8,
        "high_water grew from {high_water} to {}",
        zonefile.meta().page_count_high_water
    );
    assert!(
        zonefile.meta().freelist_buckets <= 4,
        "unexpected bucket proliferation: {}",
        zonefile.meta().freelist_buckets
    );
    assert!(zonefile.meta().freelist_entries > 0);
    assert!(zonefile.fsck().unwrap().is_ok());
    drop(zonefile);

    let reopened = ZoneFile::open(&path, pulse_zonefile::OpenConfig::default()).unwrap();
    assert_eq!(
        reopened
            .lookup_rrset(&apex, &apex, 1, 0)
            .unwrap()
            .unwrap()
            .rdata,
        vec![vec![192, 0, 2, 199]]
    );
    assert!(reopened.fsck().unwrap().is_ok());
}

#[test]
fn young_pages_are_not_reused_without_watermark() {
    // Flush-файл без sync(): durable_watermark = 1, reclaim_txn = 0,
    // страницы освобождённые в F >= 2 не переиспользуются.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    let mut zonefile = ZoneFile::create(
        &path,
        CreateConfig {
            map_size: 64 * 1024 * 1024,
            sync_mode: SyncMode::MetaNoSync,
            ..CreateConfig::default()
        },
    )
    .unwrap();
    let apex = NameRle::from_ascii("example.com").unwrap();
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
        writer.commit(SyncMode::MetaNoSync).unwrap();
    }
    let high_water = zonefile.meta().page_count_high_water;
    assert_eq!(zonefile.durable_watermark(), 1);
    assert_eq!(zonefile.meta().reclaim_txn, 0);
    for value in 0_u8..8 {
        let mut writer = zonefile.write().unwrap();
        writer
            .upsert_rrset(&apex, &apex, 1, 0, &rrset(value))
            .unwrap();
        writer.commit(SyncMode::MetaNoSync).unwrap();
    }
    assert!(
        zonefile.meta().page_count_high_water > high_water,
        "Flush without sync must grow high_water"
    );
    // sync() — единственный способ поднять watermark.
    zonefile.sync().unwrap();
    assert!(zonefile.durable_watermark() > 1);
    assert!(zonefile.meta().reclaim_txn > 0);
    let mut writer = zonefile.write().unwrap();
    writer.upsert_rrset(&apex, &apex, 1, 0, &rrset(42)).unwrap();
    // После sync() режим липко Sync; слабый коммит запрещён.
    assert!(writer.commit(SyncMode::MetaNoSync).is_err());
}
