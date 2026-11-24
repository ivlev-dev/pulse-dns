//! B2b: tombstone-GC каталога — удаление записи после durable-удаления,
//! переиспользование `zone_seq`, повторное создание origin и безопасность
//! reopen/`kill -9`-границ.

use pulse_zonefile::key::NameRle;
use pulse_zonefile::parallel::{
    OpenConfigV2, ParallelStore, ParallelZones, RootState, RrsetData, StoreConfig, SyncModeV2,
    ZoneCreateMeta,
};

fn config() -> StoreConfig {
    StoreConfig::small(16, 8192)
}

fn apex() -> NameRle {
    NameRle::from_ascii("gone.example").unwrap()
}

fn name(commit: u32) -> NameRle {
    NameRle::from_ascii(&format!("r{commit}.gone.example")).unwrap()
}

fn rr(commit: u32) -> RrsetData {
    RrsetData::from_slices(60, 0, &[&[10, 0, 0, u8::try_from(commit % 256).unwrap()]]).unwrap()
}

#[test]
fn tombstone_gc_removes_catalog_and_reuses_slot() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("catalog.v2");
    let store = ParallelStore::create(&path, config()).unwrap();
    let mut zones = ParallelZones::open(&store).unwrap();
    let seq = zones
        .create_zone(&apex(), ZoneCreateMeta { soa_serial: 7 })
        .unwrap();
    {
        let mut writer = zones.writer(&apex()).unwrap();
        writer.upsert_rrset(&name(0), 1, 0, &rr(0)).unwrap();
        writer.commit().unwrap();
    }
    let outcome = zones.delete_zone(&apex()).unwrap();
    assert!(outcome.changed);
    assert_eq!(zones.zones().len(), 0);
    assert_eq!(zones.zone_seq(&apex()), Some(seq));
    let head = store.select_root(seq, u64::MAX).unwrap();
    assert!(head.is_tombstone());
    assert_eq!(head.deleted_txn, outcome.version);

    // Каталог ещё не очищен — GC после durable tombstone.
    let removed = zones.gc_catalog().unwrap();
    assert_eq!(removed, vec![apex()]);
    assert_eq!(zones.zone_seq(&apex()), None);
    assert_eq!(zones.zones().len(), 0);

    // Idempotent: повторный GC ничего не удаляет.
    assert_eq!(zones.gc_catalog().unwrap().len(), 0);
    assert!(store.fsck_lite().unwrap().ok);
    assert!(store.fsck_graph().unwrap().ok);

    // Повторное создание origin переиспользует slot `zone_seq`.
    let again = zones
        .create_zone(&apex(), ZoneCreateMeta { soa_serial: 8 })
        .unwrap();
    assert_eq!(again, seq, "tombstone-slot не переиспользован");
    assert!(again != 0);
    {
        let mut writer = zones.writer(&apex()).unwrap();
        writer.upsert_rrset(&name(1), 1, 0, &rr(1)).unwrap();
        writer.commit().unwrap();
    }
    let reader = store.reader().unwrap();
    let view = zones.read(&reader, &apex()).unwrap();
    assert!(view.version() > outcome.version);
    assert!(view.lookup(&name(1), 1, 0).unwrap().is_some());
    assert!(view.lookup(&name(0), 1, 0).unwrap().is_none());
    drop(view);
    drop(reader);
    assert!(store.fsck_lite().unwrap().ok);
    assert!(store.fsck_graph().unwrap().ok);
    drop(zones);
    drop(store);

    // Reopen: каталог содержит только пересозданную зону, tombstone-слот занят ею.
    let reopened = ParallelStore::open(&path, OpenConfigV2::default()).unwrap();
    let zones = ParallelZones::open(&reopened).unwrap();
    assert_eq!(zones.zone_seq(&apex()), Some(seq));
    assert_eq!(zones.zones().len(), 1);
    assert_eq!(zones.zones()[0].state, RootState::Serving);
    assert!(reopened.fsck_graph().unwrap().ok);
}

#[test]
fn gc_catalog_waits_for_durable_tombstone() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("catalog-flush.v2");
    let config = StoreConfig {
        sync_mode: SyncModeV2::Flush,
        ..config()
    };
    let store = ParallelStore::create(&path, config).unwrap();
    let mut zones = ParallelZones::open(&store).unwrap();
    let seq = zones
        .create_zone(&apex(), ZoneCreateMeta { soa_serial: 1 })
        .unwrap();
    zones.delete_zone(&apex()).unwrap();
    assert_eq!(store.durable_version(seq), 0);
    // Tombstone не durable → каталог не трогаем.
    assert_eq!(zones.gc_catalog().unwrap().len(), 0);
    assert_eq!(zones.zone_seq(&apex()), Some(seq));
    // `sync()` делает tombstone durable — теперь GC разрешён.
    store.sync().unwrap();
    assert!(store.durable_version(seq) > 0);
    assert_eq!(zones.gc_catalog().unwrap(), vec![apex()]);
    assert_eq!(zones.zone_seq(&apex()), None);
    assert!(store.fsck_graph().unwrap().ok);
}

#[test]
fn recreate_after_gc_and_reopen_keeps_new_data() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("catalog-recreate.v2");
    let store = ParallelStore::create(&path, config()).unwrap();
    let mut zones = ParallelZones::open(&store).unwrap();
    for round in 0..3_u32 {
        let seq = zones
            .create_zone(&apex(), ZoneCreateMeta { soa_serial: round })
            .unwrap();
        let mut writer = zones.writer(&apex()).unwrap();
        writer.upsert_rrset(&name(round), 1, 0, &rr(round)).unwrap();
        writer.commit().unwrap();
        drop(writer);
        zones.delete_zone(&apex()).unwrap();
        assert_eq!(zones.gc_catalog().unwrap(), vec![apex()]);
        assert_eq!(zones.zone_seq(&apex()), None);
        assert_eq!(seq, 1, "первый slot должен переиспользоваться");
        assert!(store.fsck_lite().unwrap().ok);
        assert!(store.fsck_graph().unwrap().ok);
    }
    drop(zones);
    drop(store);
    let reopened = ParallelStore::open(&path, OpenConfigV2::default()).unwrap();
    let zones = ParallelZones::open(&reopened).unwrap();
    assert_eq!(zones.zones().len(), 0);
    // Slot 1 снова доступен для создания.
    let mut zones = zones;
    let seq = zones
        .create_zone(&apex(), ZoneCreateMeta { soa_serial: 9 })
        .unwrap();
    assert_eq!(seq, 1);
    assert!(reopened.fsck_graph().unwrap().ok);
}
