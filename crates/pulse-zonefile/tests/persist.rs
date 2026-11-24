//! Персистентность: commit → reopen → lookup, удаление и freelist.

use pulse_zonefile::key::NameRle;
use pulse_zonefile::{
    CreateConfig, LockMode, OpenConfig, RrsetData, SyncMode, ZoneFile, ZoneState, ZoneTree,
};

fn writer_cfg() -> OpenConfig {
    OpenConfig {
        lock_mode: LockMode::Writer,
        ..OpenConfig::default()
    }
}

fn rrset(rdata: &[&[u8]]) -> RrsetData {
    RrsetData::from_slices(300, 0, rdata).expect("rrset")
}

fn a(byte: u8) -> RrsetData {
    rrset(&[&[192, 0, 2, byte]])
}

fn name(text: &str) -> NameRle {
    NameRle::from_ascii(text).unwrap()
}

#[test]
fn commit_and_reopen_roundtrip() {
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
    {
        let mut writer = zonefile.write().unwrap();
        writer.create_zone(&apex, 0).unwrap();
        writer
            .upsert_rrset(&apex, &apex, 6, 0, &rrset(&[&[1, 2, 3, 4]]))
            .unwrap();
        writer
            .upsert_rrset(&apex, &apex, 2, 0, &rrset(&[&[1, 2]]))
            .unwrap();
        writer
            .upsert_rrset(&apex, &name("www.example.com"), 1, 0, &a(1))
            .unwrap();
        let outcome = writer.commit(SyncMode::Sync).unwrap();
        assert_eq!(outcome.txnid, 2);
        assert!(outcome.durable);
    }
    assert_eq!(zonefile.txnid(), 2);
    assert_eq!(zonefile.meta().zone_count, 1);
    assert_eq!(
        zonefile
            .lookup_rrset(&apex, &name("www.example.com"), 1, 0)
            .unwrap()
            .unwrap()
            .rdata,
        vec![vec![192, 0, 2, 1]]
    );
    let fsck = zonefile.fsck().unwrap();
    assert!(fsck.is_ok(), "{fsck:?}");
    drop(zonefile);

    let zonefile = ZoneFile::open(&path, writer_cfg()).unwrap();
    assert_eq!(zonefile.txnid(), 2);
    assert_eq!(zonefile.meta().zone_count, 1);
    let entry = zonefile.zone_entry(&apex).unwrap().unwrap();
    assert_eq!(entry.state, ZoneState::Serving);
    assert_eq!(entry.rrset_count, 3);
    assert_eq!(entry.rr_count, 3);
    assert_eq!(
        zonefile
            .lookup_rrset(&apex, &apex, 6, 0)
            .unwrap()
            .unwrap()
            .rdata,
        vec![vec![1, 2, 3, 4]]
    );
    let (found, _) = zonefile
        .find_zone_suffix(&name("x.www.example.com"))
        .unwrap()
        .unwrap();
    assert_eq!(found, apex);
    assert!(
        zonefile.fsck().unwrap().is_ok(),
        "{:?}",
        zonefile.fsck().unwrap()
    );
}

#[test]
fn delete_last_rrset_keeps_apex_marker() {
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
    let mut writer = zonefile.write().unwrap();
    writer.create_zone(&apex, 0).unwrap();
    writer.upsert_rrset(&apex, &apex, 1, 0, &a(9)).unwrap();
    writer.commit(SyncMode::Sync).unwrap();
    {
        let mut writer = zonefile.write().unwrap();
        assert!(writer.delete_rrset(&apex, &apex, 1, 0).unwrap());
        writer.commit(SyncMode::Sync).unwrap();
    }
    assert!(zonefile.lookup_rrset(&apex, &apex, 1, 0).unwrap().is_none());
    let entry = zonefile.zone_entry(&apex).unwrap().unwrap();
    assert_eq!(entry.rrset_count, 0);
    assert!(entry.tree_root != 0, "apex T_NODE remains as the root leaf");
    let node = ZoneTree::new(apex, entry.tree_root, entry.tree_level).unwrap();
    let info = node.node(&zonefile, zonefile.txnid(), &apex).unwrap();
    assert!(info.exists && info.is_apex && !info.has_children);
    assert!(zonefile.fsck().unwrap().is_ok());
}

#[test]
fn compact_zone_preserves_overflow_values() {
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
    let mut writer = zonefile.write().unwrap();
    writer.create_zone(&apex, 0).unwrap();
    writer
        .upsert_rrset(&apex, &apex, 6, 0, &rrset(&[&[1, 2, 3, 4]]))
        .unwrap();
    let big: Vec<u8> = (0..600)
        .map(|index| u8::try_from(index % 251).unwrap())
        .collect();
    writer
        .upsert_rrset(&apex, &name("big.example.com"), 16, 0, &rrset(&[&big]))
        .unwrap();
    writer.commit(SyncMode::Sync).unwrap();
    let before = zonefile
        .lookup_rrset(&apex, &name("big.example.com"), 16, 0)
        .unwrap()
        .unwrap();
    {
        let mut writer = zonefile.write().unwrap();
        assert!(writer.compact_zone(&apex).unwrap());
        writer.commit(SyncMode::Sync).unwrap();
    }
    let after = zonefile
        .lookup_rrset(&apex, &name("big.example.com"), 16, 0)
        .unwrap()
        .unwrap();
    assert_eq!(before, after);
    assert!(zonefile.fsck().unwrap().is_ok());
}

#[test]
fn snapshot_reads_old_value_after_commit() {
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
    let mut writer = zonefile.write().unwrap();
    writer.create_zone(&apex, 0).unwrap();
    writer.upsert_rrset(&apex, &apex, 1, 0, &a(1)).unwrap();
    writer.commit(SyncMode::Sync).unwrap();
    let reader = zonefile.reader();
    let snapshot = reader.snapshot().unwrap();
    drop(reader);
    {
        let mut writer = zonefile.write().unwrap();
        writer.upsert_rrset(&apex, &apex, 1, 0, &a(2)).unwrap();
        writer.commit(SyncMode::Sync).unwrap();
    }
    let old = zonefile
        .lookup_rrset_at(snapshot.txnid(), &apex, &apex, 1, 0)
        .unwrap()
        .unwrap();
    assert_eq!(old.rdata, vec![vec![192, 0, 2, 1]]);
    let new = zonefile.lookup_rrset(&apex, &apex, 1, 0).unwrap().unwrap();
    assert_eq!(new.rdata, vec![vec![192, 0, 2, 2]]);
    drop(snapshot);
    assert!(zonefile.fsck().unwrap().is_ok());
}

#[test]
fn delete_last_rrset_name_and_zone() {
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
    let deep = name("a.b.example.com");
    {
        let mut writer = zonefile.write().unwrap();
        writer.create_zone(&apex, 0).unwrap();
        writer
            .upsert_rrset(&apex, &apex, 6, 0, &rrset(&[&[1, 2, 3, 4]]))
            .unwrap();
        writer
            .upsert_rrset(&apex, &apex, 2, 0, &rrset(&[&[1, 2]]))
            .unwrap();
        writer.upsert_rrset(&apex, &www, 1, 0, &a(1)).unwrap();
        writer.upsert_rrset(&apex, &deep, 1, 0, &a(2)).unwrap();
        writer.commit(SyncMode::Sync).unwrap();
    }
    {
        let mut writer = zonefile.write().unwrap();
        assert!(writer.delete_rrset(&apex, &www, 1, 0).unwrap());
        assert!(!writer.delete_rrset(&apex, &www, 1, 0).unwrap());
        assert!(
            writer
                .delete_subtree(&apex, &name("b.example.com"))
                .unwrap()
        );
        writer.commit(SyncMode::Sync).unwrap();
    }
    assert!(zonefile.lookup_rrset(&apex, &www, 1, 0).unwrap().is_none());
    assert!(zonefile.lookup_rrset(&apex, &deep, 1, 0).unwrap().is_none());
    assert!(
        zonefile.fsck().unwrap().is_ok(),
        "{:?}",
        zonefile.fsck().unwrap()
    );
    {
        let mut writer = zonefile.write().unwrap();
        assert!(writer.delete_zone(&apex).unwrap());
        let outcome = writer.commit(SyncMode::Sync).unwrap();
        assert!(outcome.txnid > 2);
    }
    assert!(zonefile.find_zone(&apex).unwrap().is_none());
    assert_eq!(zonefile.meta().zone_count, 0);
    // Tombstone остаётся записью каталога.
    assert_eq!(
        zonefile.zone_entry(&apex).unwrap().unwrap().state,
        ZoneState::Tombstone
    );
    drop(zonefile);
    let zonefile = ZoneFile::open(&path, writer_cfg()).unwrap();
    assert!(zonefile.find_zone(&apex).unwrap().is_none());
    assert!(
        zonefile.fsck().unwrap().is_ok(),
        "{:?}",
        zonefile.fsck().unwrap()
    );
}
