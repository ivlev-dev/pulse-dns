//! Property: 10k вставок и удалений, проверка после каждого коммита и reopen.

use std::collections::BTreeSet;

use pulse_zonefile::key::NameRle;
use pulse_zonefile::{CreateConfig, LockMode, OpenConfig, RrsetData, SyncMode, ZoneFile};

fn writer_cfg() -> OpenConfig {
    OpenConfig {
        lock_mode: LockMode::Writer,
        ..OpenConfig::default()
    }
}

fn rrset(value: u8) -> RrsetData {
    RrsetData::from_slices(300, 0, &[&[192, 0, 2, value]]).expect("rrset")
}

fn owner(index: u32) -> NameRle {
    NameRle::from_ascii(&format!("h{index:05}.example.com")).unwrap()
}

/// Детерминированная перестановка `0..n` (xorshift + Fisher-Yates).
fn shuffled(n: u32) -> Vec<u32> {
    let mut values: Vec<u32> = (0..n).collect();
    let mut state = 0x9E37_79B9_u64;
    for index in (1..values.len()).rev() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let swap = usize::try_from(state % u64::try_from(index + 1).unwrap()).unwrap();
        values.swap(index, swap);
    }
    values
}

#[test]
#[ignore = "10k insert/delete property test (~4-5 min in debug); run with --ignored"]
#[allow(clippy::too_many_lines)]
fn insert_and_delete_10k_with_reopen() {
    const TOTAL: u32 = 10_000;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zones.zonefile");
    let mut zonefile = ZoneFile::create(
        &path,
        CreateConfig {
            map_size: 512 * 1024 * 1024,
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
        writer
            .upsert_rrset(
                &apex,
                &apex,
                2,
                0,
                &RrsetData::from_slices(300, 0, &[&[1, 2]]).unwrap(),
            )
            .unwrap();
        writer.commit(SyncMode::Sync).unwrap();
    }

    let order = shuffled(TOTAL);
    for chunk in order.chunks(1000) {
        let mut writer = zonefile.write().unwrap();
        for &index in chunk {
            writer
                .upsert_rrset(
                    &apex,
                    &owner(index),
                    1,
                    0,
                    &rrset(u8::try_from(index % 250).unwrap()),
                )
                .unwrap();
        }
        writer.commit(SyncMode::Sync).unwrap();
    }
    let entry = zonefile.zone_entry(&apex).unwrap().unwrap();
    assert_eq!(entry.rrset_count, TOTAL + 2);
    assert_eq!(entry.rr_count, TOTAL + 2);
    assert!(zonefile.fsck().unwrap().is_ok());

    let mut deleted = BTreeSet::new();
    let mut remaining = BTreeSet::new();
    for &index in order.iter().take(5000) {
        deleted.insert(index);
    }
    for &index in order.iter().skip(5000) {
        remaining.insert(index);
    }
    for chunk in order.chunks(500).take(10) {
        let mut writer = zonefile.write().unwrap();
        for &index in chunk {
            assert!(writer.delete_rrset(&apex, &owner(index), 1, 0).unwrap());
            assert!(!writer.delete_rrset(&apex, &owner(index), 1, 0).unwrap());
        }
        writer.commit(SyncMode::Sync).unwrap();
    }
    for index in &deleted {
        assert!(
            zonefile
                .lookup_rrset(&apex, &owner(*index), 1, 0)
                .unwrap()
                .is_none(),
            "deleted {index} still present"
        );
    }
    for index in &remaining {
        assert!(
            zonefile
                .lookup_rrset(&apex, &owner(*index), 1, 0)
                .unwrap()
                .is_some(),
            "remaining {index} lost"
        );
    }
    let entry = zonefile.zone_entry(&apex).unwrap().unwrap();
    assert_eq!(entry.rrset_count, 5002);
    assert!(zonefile.fsck().unwrap().is_ok());
    drop(zonefile);

    let zonefile = ZoneFile::open(&path, writer_cfg()).unwrap();
    for index in deleted.iter().take(200) {
        assert!(
            zonefile
                .lookup_rrset(&apex, &owner(*index), 1, 0)
                .unwrap()
                .is_none()
        );
    }
    for index in remaining.iter().take(200) {
        assert!(
            zonefile
                .lookup_rrset(&apex, &owner(*index), 1, 0)
                .unwrap()
                .is_some()
        );
    }
    assert!(zonefile.fsck().unwrap().is_ok());
}
