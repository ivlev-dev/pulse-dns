//! Много зон: ветвление каталога, сепараторы, fsck и индекс.

use pulse_zonefile::key::NameRle;
use pulse_zonefile::{CreateConfig, LockMode, OpenConfig, RrsetData, SyncMode, ZoneFile};

fn a(value: u8) -> RrsetData {
    RrsetData::from_slices(300, 0, &[&[192, 0, 2, value]]).expect("rrset")
}

#[test]
fn catalog_branch_separators_and_zone_index() {
    const ZONES: u32 = 200;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    let mut zonefile = ZoneFile::create(
        &path,
        CreateConfig {
            map_size: 256 * 1024 * 1024,
            ..CreateConfig::default()
        },
    )
    .unwrap();
    {
        let mut writer = zonefile.write().unwrap();
        for index in 0..ZONES {
            let apex = NameRle::from_ascii(&format!("z{index:04}.example")).unwrap();
            writer.create_zone(&apex, 0).unwrap();
            writer
                .upsert_rrset(&apex, &apex, 1, 0, &a(u8::try_from(index % 250).unwrap()))
                .unwrap();
        }
        writer.commit(SyncMode::Sync).unwrap();
    }
    let entry = zonefile.meta();
    assert_eq!(entry.zone_count, ZONES);
    assert!(entry.zone_dir_level > 1, "catalog must branch");
    assert_eq!(
        zonefile.zones().unwrap().len(),
        usize::try_from(ZONES).unwrap()
    );
    for index in [0_u32, 1, 99, 100, ZONES - 1] {
        let apex = NameRle::from_ascii(&format!("z{index:04}.example")).unwrap();
        assert!(zonefile.find_zone(&apex).unwrap().is_some());
        let view = zonefile.lookup_rrset(&apex, &apex, 1, 0).unwrap().unwrap();
        assert_eq!(
            view.rdata,
            vec![vec![192, 0, 2, u8::try_from(index % 250).unwrap()]]
        );
    }
    // Индекс ускоряет повторный поиск и инвалидируется коммитом.
    let apex = NameRle::from_ascii("z0100.example").unwrap();
    assert!(zonefile.find_zone(&apex).unwrap().is_some());
    {
        let mut writer = zonefile.write().unwrap();
        assert!(writer.delete_zone(&apex).unwrap());
        writer.commit(SyncMode::Sync).unwrap();
    }
    assert!(zonefile.find_zone(&apex).unwrap().is_none());
    assert_eq!(zonefile.meta().zone_count, ZONES - 1);
    assert!(zonefile.fsck().unwrap().is_ok());
    drop(zonefile);

    let reopened = ZoneFile::open(
        &path,
        OpenConfig {
            lock_mode: LockMode::Writer,
            ..OpenConfig::default()
        },
    )
    .unwrap();
    assert_eq!(reopened.meta().zone_count, ZONES - 1);
    assert!(reopened.fsck().unwrap().is_ok());
}
