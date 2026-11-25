//! `huge_pages` для mmap-данных v1: `auto` не фатален, `never`/`always`
//! открываются на THP-системе, формат и чтение не зависят от политики.

use std::path::Path;

use pulse_zonefile::key::NameRle;
use pulse_zonefile::mem::{ThpStatus, thp_status};
use pulse_zonefile::{CreateConfig, HugePages, OpenConfig, RrsetData, SyncMode, ZoneFile};

const MAP: u64 = 16 * 1024 * 1024;

fn write_zone(path: &Path, huge_pages: HugePages) {
    let mut zonefile = ZoneFile::create(
        path,
        CreateConfig {
            map_size: MAP,
            huge_pages,
            ..CreateConfig::default()
        },
    )
    .expect("create");
    let apex = NameRle::from_ascii("huge.example").expect("apex");
    let mut writer = zonefile.write().expect("writer");
    writer.create_zone(&apex, 0).expect("zone");
    writer
        .upsert_rrset(
            &apex,
            &apex,
            1,
            0,
            &RrsetData::from_slices(300, 0, &[&[192, 0, 2, 1]]).expect("rrset"),
        )
        .expect("upsert");
    writer.commit(SyncMode::Sync).expect("commit");
}

#[test]
fn default_policy_is_auto() {
    assert_eq!(OpenConfig::default().huge_pages, HugePages::Auto);
    assert_eq!(CreateConfig::default().huge_pages, HugePages::Auto);
    assert_eq!(HugePages::default(), HugePages::Auto);
    assert_eq!("always".parse::<HugePages>().unwrap(), HugePages::Always);
}

#[test]
fn create_and_open_with_each_policy() {
    let policies = if thp_status() == ThpStatus::Never {
        // Система без THP: `always` обязан падать, остальные — работать.
        vec![HugePages::Auto, HugePages::Never]
    } else {
        vec![HugePages::Auto, HugePages::Always, HugePages::Never]
    };
    for policy in policies {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("huge.zonefile");
        write_zone(&path, policy);

        let zonefile = ZoneFile::open(
            &path,
            OpenConfig {
                huge_pages: policy,
                ..OpenConfig::default()
            },
        )
        .unwrap_or_else(|error| panic!("open with {policy}: {error}"));
        let apex = NameRle::from_ascii("huge.example").expect("apex");
        assert!(
            zonefile
                .lookup_rrset(&apex, &apex, 1, 0)
                .expect("lookup")
                .is_some(),
            "read must work with huge_pages={policy}"
        );
    }
}

#[test]
fn always_fails_only_when_thp_is_disabled() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("always.zonefile");
    let result = ZoneFile::create(
        &path,
        CreateConfig {
            map_size: MAP,
            huge_pages: HugePages::Always,
            ..CreateConfig::default()
        },
    );
    if thp_status() == ThpStatus::Never {
        let Err(error) = result else {
            panic!("huge_pages=always must fail without THP");
        };
        assert!(error.to_string().contains("madvise"), "{error}");
    } else {
        assert!(result.is_ok(), "THP is enabled, create must succeed");
    }
}
