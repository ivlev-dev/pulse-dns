//! B3: пользовательские метаданные зоны в каталоге v2 — запись, обновление,
//! reopen и открытие writer/reader без загрузки каталога.

use pulse_zonefile::key::NameRle;
use pulse_zonefile::parallel::{
    OpenConfigV2, ParallelStore, ParallelZones, RrsetData, StoreConfig, SyncModeV2, ZoneCreateMeta,
    ZoneMetaV2, ZoneReader,
};

fn apex() -> NameRle {
    NameRle::from_ascii("meta.example").expect("apex")
}

fn store(dir: &tempfile::TempDir) -> (std::path::PathBuf, ParallelStore) {
    let path = dir.path().join("meta.v2");
    let store = ParallelStore::create(&path, StoreConfig::small(8, 4096)).expect("store");
    (path, store)
}

#[test]
fn zone_meta_roundtrip_update_and_reopen() {
    let dir = tempfile::tempdir().expect("dir");
    let (path, store) = store(&dir);
    let mut zones = ParallelZones::open(&store).expect("catalog");
    let meta = ZoneMetaV2 {
        kind_flags: 1,
        default_ttl: 7200,
        denial: 1,
        created_unix_ns: 11,
        updated_unix_ns: 22,
    };
    let seq = zones
        .create_zone_with_meta(&apex(), ZoneCreateMeta { soa_serial: 5 }, meta)
        .expect("create");
    assert_eq!(zones.zone_meta(&apex()), Some(meta));
    assert_eq!(zones.zone_meta_by_seq(seq), Some(meta));
    let info = zones.zones();
    assert_eq!(info.len(), 1);
    assert_eq!(info[0].meta, meta);

    let changed = ZoneMetaV2 {
        kind_flags: 2,
        default_ttl: 600,
        denial: 0,
        created_unix_ns: 11,
        updated_unix_ns: 33,
    };
    assert!(zones.set_zone_meta(&apex(), changed).expect("set meta"));
    assert!(
        !zones
            .set_zone_meta(&apex(), changed)
            .expect("idempotent meta")
    );
    assert!(
        zones
            .set_zone_meta(&NameRle::from_ascii("none.example").expect("name"), changed)
            .is_err()
    );

    // Writer/reader без загрузки каталога.
    let mut writer =
        pulse_zonefile::parallel::ParallelZone::open_uncached(&store, apex(), seq).expect("writer");
    let name = NameRle::from_ascii("www.meta.example").expect("name");
    writer
        .upsert_rrset(
            &name,
            1,
            0,
            &RrsetData::from_slices(60, 0, &[&[192, 0, 2, 1]]).expect("rr"),
        )
        .expect("upsert");
    writer.set_soa_serial(5);
    writer.commit_with(SyncModeV2::Sync).expect("commit");
    drop(writer);
    drop(zones);
    store.sync().expect("sync");
    drop(store);

    let reopened = ParallelStore::open(&path, OpenConfigV2::default()).expect("reopen");
    let zones = ParallelZones::open(&reopened).expect("catalog");
    assert_eq!(zones.zone_meta(&apex()), Some(changed));
    let reader = reopened.reader().expect("reader");
    let view = ZoneReader::open(&reopened, &reader, apex(), seq).expect("zone reader");
    assert!(view.lookup(&name, 1, 0).expect("lookup").is_some());
    assert!(reopened.fsck_lite().expect("fsck").ok);
}
