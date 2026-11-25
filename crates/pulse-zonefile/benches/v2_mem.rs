#![allow(missing_docs)]
#![allow(clippy::too_many_lines)]
//! Память и RSS read-path v2: 1k/100k/1M `RRset` и 1/100/1000 зон, soak.
//!
//! Запуск:
//!
//! ```text
//! cargo bench -p pulse-zonefile --bench v2_mem -- --keys 100000 --zones 100
//! cargo bench -p pulse-zonefile --bench v2_mem -- --keys 1000000 --soak-secs 600
//! ```
//!
//! Печатает `RssAnon`/`VmHWM` из `/proc/self/status`, оценку кешей, статистику.

use std::hint::black_box;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use pulse_zonefile::key::NameRle;
use pulse_zonefile::parallel::{
    OpenConfigV2, ParallelStore, ParallelZones, RrsetData, StoreConfig, ZoneCreateMeta,
};

fn status_kb(field: &str) -> u64 {
    let Ok(text) = std::fs::read_to_string("/proc/self/status") else {
        return 0;
    };
    text.lines()
        .find_map(|line| {
            let rest = line.strip_prefix(field)?.strip_prefix(':')?;
            rest.split_whitespace().next()?.parse().ok()
        })
        .unwrap_or(0)
}

fn rss_anon_kb() -> u64 {
    status_kb("RssAnon")
}

fn hwm_kb() -> u64 {
    status_kb("VmHWM")
}

fn rr(value: u8) -> RrsetData {
    RrsetData::from_slices(60, 0, &[&[192, 0, 2, value]]).unwrap()
}

fn origin(index: u32) -> NameRle {
    NameRle::from_ascii(&format!("m{index}.example")).unwrap()
}

struct Args {
    keys: u32,
    zones: u32,
    pages: u32,
    cache_entries: usize,
    soak: Duration,
    batch: u32,
    path: Option<PathBuf>,
    open_only: bool,
    skip_warm: bool,
}

fn parse_args() -> Args {
    let mut args = Args {
        keys: 1_000,
        zones: 1,
        pages: 0,
        cache_entries: 1024,
        soak: Duration::ZERO,
        batch: 0,
        path: None,
        open_only: false,
        skip_warm: false,
    };
    let mut iter = std::env::args().skip(1);
    while let Some(flag) = iter.next() {
        let mut value = || {
            iter.next()
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(0)
        };
        match flag.as_str() {
            "--keys" => args.keys = u32::try_from(value()).unwrap_or(u32::MAX),
            "--zones" => args.zones = u32::try_from(value()).unwrap_or(u32::MAX),
            "--pages" => args.pages = u32::try_from(value()).unwrap_or(u32::MAX),
            "--cache-entries" => {
                args.cache_entries = usize::try_from(value()).unwrap_or(usize::MAX);
            }
            "--soak-secs" => args.soak = Duration::from_secs(value()),
            "--batch" => args.batch = u32::try_from(value()).unwrap_or(u32::MAX),
            "--path" => {
                args.path = Some(PathBuf::from(iter.next().unwrap_or_default()));
            }
            "--open-only" => args.open_only = true,
            "--skip-warm" => args.skip_warm = true,
            other if other.starts_with('-') => {
                // `cargo bench` добавляет свои флаги (например, `--bench`).
            }
            other => panic!("неизвестный аргумент: {other}"),
        }
    }
    args
}

fn main() {
    let args = parse_args();
    assert!(args.zones >= 1 && args.keys >= 1);
    let base_anon = rss_anon_kb();
    let base_rss = status_kb("VmRSS");

    if args.open_only {
        let path = args.path.clone().expect("--open-only требует --path");
        let store = ParallelStore::open(
            &path,
            OpenConfigV2 {
                page_cache_entries: args.cache_entries,
                ..OpenConfigV2::default()
            },
        )
        .unwrap();
        let zones = ParallelZones::open(&store).unwrap();
        let per_zone = zones
            .zones()
            .iter()
            .map(|info| info.rrset_count.saturating_add(1))
            .max()
            .unwrap_or(0);
        println!(
            "opened {}: zones={} keys/zone<={per_zone}, RssAnon={} KiB, RssFile={} KiB, cache={} B",
            path.display(),
            zones.zones().len(),
            rss_anon_kb(),
            status_kb("RssFile"),
            store.cache_memory_bytes()
        );
        read_phase(&store, &zones, &args, base_anon, base_rss, per_zone);
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let path = args
        .path
        .clone()
        .unwrap_or_else(|| dir.path().join("mem.v2"));
    println!(
        "fixture: keys={} zones={} cache_entries={} path={}",
        args.keys,
        args.zones,
        args.cache_entries,
        path.display()
    );
    let batch = if args.batch == 0 {
        (args.keys / 50).clamp(100, 10_000)
    } else {
        args.batch
    };
    // COW в текущей txn держит ~10 страниц на upsert до коммита.
    let pages = if args.pages == 0 {
        12 * batch + args.keys / 200 + 4096
    } else {
        args.pages
    };
    let mut config = StoreConfig::small(args.zones + 2, pages);
    config.page_cache_entries = args.cache_entries;
    let store = ParallelStore::create(&path, config).unwrap();
    println!(
        "after open: RssAnon={} KiB, RssShmem={} KiB, RssFile={} KiB, VmRSS={} KiB, pages={pages}",
        rss_anon_kb(),
        status_kb("RssShmem"),
        status_kb("RssFile"),
        status_kb("VmRSS")
    );
    let mut zones = ParallelZones::open(&store).unwrap();
    for index in 0..args.zones {
        zones
            .create_zone(
                &origin(index),
                ZoneCreateMeta {
                    soa_serial: index + 1,
                },
            )
            .unwrap();
    }

    let per_zone = args.keys.div_ceil(args.zones);
    let start = Instant::now();
    let mut last_report = start;
    for zone in 0..args.zones {
        let name = origin(zone);
        let mut writer = zones.writer(&name).unwrap();
        let mut inserted = 0_u32;
        for index in 0..per_zone {
            let key = NameRle::from_ascii(&format!("k{index}.m{zone}.example")).unwrap();
            writer
                .upsert_rrset(&key, 1, 0, &rr(u8::try_from(index % 250).unwrap_or(0)))
                .unwrap();
            inserted += 1;
            if inserted.is_multiple_of(batch) {
                writer.commit().unwrap();
                if last_report.elapsed() >= Duration::from_secs(2) {
                    last_report = Instant::now();
                    println!(
                        "insert {}/{} ({:?})",
                        zone * per_zone + inserted,
                        args.keys,
                        start.elapsed()
                    );
                }
            }
        }
        writer.commit().unwrap();
    }
    let after_insert = rss_anon_kb();
    println!(
        "after insert: RssAnon={} KiB (+{}), RssShmem={} KiB, VmHWM={} KiB, cache={} B, stats={:?}",
        after_insert,
        after_insert.saturating_sub(base_anon),
        status_kb("RssShmem"),
        hwm_kb(),
        store.cache_memory_bytes(),
        store.stats()
    );
    drop(zones);

    let zones = ParallelZones::open(&store).unwrap();
    read_phase(&store, &zones, &args, base_anon, base_rss, per_zone);
}

fn read_phase(
    store: &ParallelStore,
    zones: &ParallelZones<'_>,
    args: &Args,
    base_anon: u64,
    base_rss: u64,
    per_zone: u32,
) {
    let reader = store.reader().unwrap();
    let warm_start = Instant::now();
    let mut hits = 0_u64;
    for zone in 0..args
        .zones
        .min(u32::try_from(zones.zones().len()).unwrap_or(0))
    {
        if args.skip_warm {
            break;
        }
        let Some(origin) = zones.origin(zone + 1) else {
            continue;
        };
        let view = zones.read(&reader, &origin).unwrap();
        for index in 0..per_zone {
            let key = NameRle::from_ascii(&format!("k{index}.m{zone}.example")).unwrap();
            if view.lookup_ref(&key, 1, 0).unwrap().is_some() {
                hits += 1;
            }
        }
    }
    let after_warm = rss_anon_kb();
    println!(
        "after warm ({:?}, hits={hits}): RssAnon={} KiB (+{}), page={:?}, node={:?}, cache={} B",
        warm_start.elapsed(),
        after_warm,
        after_warm.saturating_sub(base_anon),
        store.page_cache_stats(),
        store.node_cache_stats(),
        store.cache_memory_bytes()
    );

    if !args.soak.is_zero() {
        soak(store, zones, args, after_warm, per_zone);
    }

    let final_anon = rss_anon_kb();
    println!(
        "final: RssAnon={} KiB (base {base_rss}), VmHWM={} KiB, page={:?}, node={:?}, cache={} B",
        final_anon,
        hwm_kb(),
        store.page_cache_stats(),
        store.node_cache_stats(),
        store.cache_memory_bytes()
    );
    assert!(store.fsck_lite().unwrap().ok);
}

/// Равномерные чтения на протяжении `soak`; печатает RSS раз в 10 секунд.
fn soak(
    store: &ParallelStore,
    zones: &ParallelZones<'_>,
    args: &Args,
    warm_anon: u64,
    per_zone: u32,
) {
    use std::fmt::Write as _;
    let reader = store.reader().unwrap();
    let zone_count = u32::try_from(zones.zones().len()).unwrap_or(0).max(1);
    let start = Instant::now();
    let mut next_report = Duration::from_secs(10);
    let mut seed = 0x9E37_79B9_u64;
    let mut min = rss_anon_kb();
    let mut max = min;
    let mut text = String::with_capacity(64);
    let mut ops = 0_u64;
    while start.elapsed() < args.soak {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let zone = u32::try_from(seed % u64::from(zone_count)).unwrap_or(0);
        let index = u32::try_from((seed >> 32) % u64::from(per_zone.max(1))).unwrap_or(0);
        let key = {
            text.clear();
            write!(text, "k{index}.m{zone}.example").unwrap();
            NameRle::from_ascii(&text).unwrap()
        };
        // Новый снапшот на операцию: арена живёт только внутри запроса.
        let found = zones.origin(zone + 1).is_some_and(|origin| {
            let Ok(view) = zones.read(&reader, &origin) else {
                return false;
            };
            view.lookup_ref(&key, 1, 0).ok().flatten().is_some()
        });
        black_box(found);
        ops += 1;
        let elapsed = start.elapsed();
        if elapsed >= next_report {
            let anon = rss_anon_kb();
            min = min.min(anon);
            max = max.max(anon);
            println!(
                "soak {:?}: ops={ops} RssAnon={anon} KiB (warm {warm_anon}, min {min}, max {max}), cache={} B",
                elapsed,
                store.cache_memory_bytes()
            );
            next_report += Duration::from_secs(10);
        }
    }
    let anon = rss_anon_kb();
    println!(
        "soak done: ops={ops} RssAnon={anon} KiB (warm {warm_anon}, delta {}), cache={} B",
        anon.saturating_sub(warm_anon),
        store.cache_memory_bytes()
    );
}
