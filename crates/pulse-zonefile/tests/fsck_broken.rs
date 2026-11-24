//! fsck на сломанных файлах: CRC графа и несовпадение freelist-счётчиков.

use std::os::unix::fs::FileExt;

use pulse_zonefile::key::NameRle;
use pulse_zonefile::{CreateConfig, OpenConfig, RrsetData, SyncMode, ZoneFile};

fn rrset(value: u8) -> RrsetData {
    RrsetData::from_slices(300, 0, &[&[192, 0, 2, value]]).expect("rrset")
}

fn build(path: &std::path::Path) {
    let mut zonefile = ZoneFile::create(
        path,
        CreateConfig {
            map_size: 64 * 1024 * 1024,
            ..CreateConfig::default()
        },
    )
    .unwrap();
    let apex = NameRle::from_ascii("example.com").unwrap();
    for value in 0_u8..2 {
        let mut writer = zonefile.write().unwrap();
        if value == 0 {
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
        }
        writer
            .upsert_rrset(&apex, &apex, 1, 0, &rrset(value))
            .unwrap();
        writer.commit(SyncMode::Sync).unwrap();
    }
}

#[test]
fn fsck_detects_broken_graph_page() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    build(&path);
    let root = {
        let zonefile = ZoneFile::open(&path, OpenConfig::default()).unwrap();
        assert!(zonefile.fsck().unwrap().is_ok());
        zonefile.meta().zone_dir_root
    };
    assert_ne!(root, 0);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let mut byte = [0_u8; 1];
    file.read_exact_at(&mut byte, u64::from(root) * 4096 + 100)
        .unwrap();
    byte[0] ^= 0xFF;
    file.write_all_at(&byte, u64::from(root) * 4096 + 100)
        .unwrap();
    drop(file);

    let zonefile = ZoneFile::open(&path, OpenConfig::default()).unwrap();
    assert!(zonefile.fsck().is_err());
}

#[test]
fn fsck_detects_freelist_counter_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    build(&path);
    let (meta, page_size) = {
        let zonefile = ZoneFile::open(&path, OpenConfig::default()).unwrap();
        let meta = *zonefile.meta();
        assert!(meta.freelist_entries > 0);
        (meta, zonefile.superblock().page_size)
    };
    let mut broken = meta;
    broken.freelist_entries = broken.freelist_entries.saturating_add(1);
    broken.free_page_count = broken.freelist_entries;
    let image = broken.encode();
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    file.write_all_at(&image, u64::from(meta.page_no) * u64::from(page_size))
        .unwrap();
    drop(file);

    let zonefile = ZoneFile::open(&path, OpenConfig::default()).unwrap();
    assert!(zonefile.fsck().is_err());
}
