//! Замер масштабирования каталога: создание 1000 и 4096 зон (Memory).
//!
//! Запуск: `cargo test -p pulse-zonefile --test v2_zone_scale -- --ignored --nocapture`.
//! Печатает время создания, логический/занятый размер файла, RSS HWM и число
//! записей каталога. В обычном `cargo test` пропускается (`#[ignore]`).

use std::os::unix::fs::MetadataExt;
use std::time::Instant;

use pulse_zonefile::key::NameRle;
use pulse_zonefile::parallel::{
    ParallelStore, ParallelZones, StoreConfig, SyncModeV2, ZoneCreateMeta,
};

fn origin(index: u32) -> NameRle {
    NameRle::from_ascii(&format!("z{index}.bench.example")).unwrap()
}

fn rss_hwm_kb() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|text| {
            text.lines()
                .find(|line| line.starts_with("VmHWM:"))
                .and_then(|line| line.split_whitespace().nth(1)?.parse().ok())
        })
        .unwrap_or(0)
}

#[test]
#[ignore = "замер масштабирования: 1000/4096 зон"]
fn scale() {
    for zones in [1000_u32, 4096_u32] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(format!("scale-{zones}.v2"));
        let config = StoreConfig {
            sync_mode: SyncModeV2::Memory,
            ..StoreConfig::small(zones + 8, 1 << 16)
        };
        let rss_before = rss_hwm_kb();
        let store = ParallelStore::create(&path, config).unwrap();
        let started = Instant::now();
        let mut catalog = ParallelZones::open(&store).unwrap();
        for index in 1..=zones {
            catalog
                .create_zone(&origin(index), ZoneCreateMeta { soa_serial: index })
                .unwrap();
        }
        let elapsed = started.elapsed();
        let meta = std::fs::metadata(&path).unwrap();
        let fsck = store.fsck_lite().unwrap();
        println!(
            "zones={zones} create={elapsed:?} logical={} MiB allocated={} MiB rss_hwm={} MiB (delta {} MiB) entries={} chain_pages={} ok={}",
            meta.len() / (1 << 20),
            meta.blocks() * 512 / (1 << 20),
            rss_hwm_kb() / 1024,
            rss_hwm_kb().saturating_sub(rss_before) / 1024,
            catalog.zones().len(),
            fsck.chain_pages,
            fsck.ok,
        );
        assert!(fsck.ok, "fsck: {fsck:?}");
    }
}
