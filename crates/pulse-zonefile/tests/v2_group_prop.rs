//! B2b property: произвольные батчи group commit сохраняют монотонность версий,
//! max-valid выбор и восстановление после reopen без порчи.

use proptest::prelude::*;

use pulse_zonefile::parallel::{
    GroupCommitRequest, OpenConfigV2, ParallelStore, RootEntry, RootState, StoreConfig, SyncModeV2,
};

fn config() -> StoreConfig {
    StoreConfig::small(8, 4096)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn group_commit_preserves_version_monotonicity(
        ops in prop::collection::vec((0_u32..4, 1_u8..4), 1..48),
    ) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("prop.v2");
        let store = ParallelStore::create(&path, config()).unwrap();
        let mut next = [2_u64; 5];
        let mut index = 0_usize;
        while index < ops.len() {
            let (_, batch_hint) = ops[index];
            let size = usize::from(batch_hint).min(ops.len() - index);
            let mut requests = Vec::new();
            for (zone_index, _) in &ops[index..index + size] {
                let zone = zone_index + 1;
                let version = next[usize::try_from(zone).unwrap()];
                next[usize::try_from(zone).unwrap()] = version + 1;
                requests.push(GroupCommitRequest::new(
                    RootEntry {
                        owner_zone: zone,
                        version,
                        state: RootState::Serving,
                        soa_serial: 1,
                        ..RootEntry::default()
                    },
                    SyncModeV2::Sync,
                ));
            }
            let outcomes = store.commit_group(requests);
            for outcome in outcomes {
                prop_assert!(outcome.is_ok(), "group: {outcome:?}");
            }
            index += size;
        }
        let stats = store.stats();
        prop_assert_eq!(stats.group_fsyncs, stats.group_commits * 2);
        for zone in 1..=4_u32 {
            if next[zone as usize] == 2 {
                continue;
            }
            let head = store.select_root(zone, u64::MAX).unwrap();
            prop_assert_eq!(head.version, next[zone as usize] - 1);
        }
        drop(store);

        let reopened = ParallelStore::open(&path, OpenConfigV2::default()).unwrap();
        for zone in 1..=4_u32 {
            if next[zone as usize] == 2 {
                continue;
            }
            let expected = next[zone as usize] - 1;
            let head = reopened.select_root(zone, u64::MAX).unwrap();
            prop_assert_eq!(head.version, expected);
            for ceiling in expected.saturating_sub(2).max(2)..=expected {
                let selected = reopened.select_root(zone, ceiling).unwrap();
                prop_assert!(selected.version <= ceiling);
                prop_assert!(selected.version <= expected);
            }
        }
        prop_assert!(reopened.fsck_lite().unwrap().ok);
    }
}
