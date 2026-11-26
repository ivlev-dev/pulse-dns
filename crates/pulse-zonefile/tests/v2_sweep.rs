//! Онлайн-sweep утечек: `[DP, cursor)`/хвост `[max_head_limit, DP)`,
//! безопасность при активных writers, fsck и crash.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use pulse_zonefile::key::NameRle;
use pulse_zonefile::parallel::{
    CrashHook, CrashPoint, OpenConfigV2, ParallelStore, ParallelZones, RrsetData, StoreConfig,
    SweepConfig, SyncModeV2, ZoneCreateMeta,
};

fn config() -> StoreConfig {
    StoreConfig {
        multi_process: true,
        sync_mode: SyncModeV2::Sync,
        ..StoreConfig::small(8, 1 << 18)
    }
}

fn create_store(path: &std::path::Path) -> ParallelStore {
    ParallelStore::create(path, config()).unwrap()
}

fn open_multi(path: &std::path::Path) -> ParallelStore {
    ParallelStore::open(
        path,
        OpenConfigV2 {
            read_only: false,
            writer_lock: false,
            multi_process: true,
            ..OpenConfigV2::default()
        },
    )
    .unwrap()
}

fn origin(index: u32) -> NameRle {
    NameRle::from_ascii(&format!("sweep{index}.example")).unwrap()
}

fn key(index: u32, item: u32) -> NameRle {
    NameRle::from_ascii(&format!("k{item}.sweep{index}.example")).unwrap()
}

fn rr(value: u8) -> RrsetData {
    RrsetData::from_slices(60, 0, &[&[192, 0, 2, value]]).unwrap()
}

fn seed(store: &ParallelStore, index: u32, items: u32) -> u32 {
    let mut zones = ParallelZones::open(store).unwrap();
    let seq = zones
        .create_zone(&origin(index), ZoneCreateMeta { soa_serial: 1 })
        .unwrap();
    let mut writer = zones.writer_by_seq(seq).unwrap();
    for item in 0..items {
        writer
            .upsert_rrset(
                &key(index, item),
                1,
                0,
                &rr(u8::try_from(item).unwrap_or(1)),
            )
            .unwrap();
    }
    writer.commit().unwrap();
    seq
}

fn make_durable_leak(store: &ParallelStore, pages: u32) {
    let ticket = store.reserve_pages(pages).unwrap();
    for page in ticket.first_page..=ticket.last_page() {
        store
            .write_raw_page(page, b"unreferenced aborted/leaked page")
            .unwrap();
    }
    store.sync().unwrap();
}

fn small_sweep() -> SweepConfig {
    SweepConfig {
        max_scan_pages: 64,
        max_leaks_per_call: 64,
        max_duration: Duration::from_millis(5),
        orphan_buckets: true,
    }
}

#[test]
fn sweep_reclaims_tail_leaks_and_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sweep.v2");
    let store = create_store(&path);
    seed(&store, 0, 8);
    make_durable_leak(&store, 16);
    let before = store.leak_report().unwrap();
    assert!(before.leaked_pages >= 16, "{before:?}");

    let mut total = 0_u64;
    for _ in 0..64 {
        let report = store.sweep_leaks(small_sweep()).unwrap();
        total = total.saturating_add(report.reclaimed_pages);
        assert!(report.ok, "{report:?}");
        if report.complete_pass {
            break;
        }
    }
    assert!(total >= 16, "sweep вернул {total} страниц");
    let after = store.leak_report().unwrap();
    // Онлайн-sweep трогает только заведомо недостижимое (хвост/orphan/aborted);
    // внутренние durable-утечки ниже max(page_limit) требуют offline-verify.
    assert!(
        after.leaked_pages + total <= before.leaked_pages,
        "before={before:?} after={after:?} reclaimed={total}"
    );
    assert!(after.leaked_pages < before.leaked_pages);
    assert!(store.fsck_graph().unwrap().ok);
    // Повторный прогон на чистом файле ничего не возвращает.
    let again = store.sweep_leaks(small_sweep()).unwrap();
    assert_eq!(again.reclaimed_pages, 0);
    assert!(again.ok);
    // Данные зоны по-прежнему читаются.
    let reader = store.reader().unwrap();
    let snapshot = store.zone_snapshot(&reader, 1).unwrap();
    assert!(snapshot.version() > 0);
}

#[test]
fn sweep_reclaims_aborted_only_when_no_reservations() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("aborted.v2");
    let store = create_store(&path);
    seed(&store, 0, 4);
    // Выделено, записано, но DP не двигался: `[DP, cursor)`.
    let ticket = store.reserve_pages(32).unwrap();
    for page in ticket.first_page..=ticket.last_page() {
        store.write_raw_page(page, b"aborted").unwrap();
    }
    let before = store.stats().aborted_pages_estimate;
    assert!(before >= 32, "{before}");
    let report = store.sweep_leaks(SweepConfig {
        max_scan_pages: 4096,
        max_leaks_per_call: 4096,
        max_duration: Duration::from_secs(1),
        orphan_buckets: true,
    });
    let report = report.unwrap();
    assert!(report.aborted_pages >= 32, "{report:?}");
    assert!(report.reclaimed_pages >= 32, "{report:?}");
    assert_eq!(store.stats().aborted_pages_estimate, 0);
    assert!(store.fsck_graph().unwrap().ok);
}

#[test]
fn sweep_with_active_writers_does_not_corrupt() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("concurrent.v2");
    let store = Arc::new(create_store(&path));
    let seq = seed(&store, 0, 32);
    make_durable_leak(&store, 64);

    let stop = Arc::new(AtomicBool::new(false));
    let writer_store = Arc::clone(&store);
    let reader_store = Arc::clone(&store);
    let writer_stop = Arc::clone(&stop);
    let reader_stop = Arc::clone(&stop);
    let writer = std::thread::spawn(move || {
        let zones = ParallelZones::open(&writer_store).unwrap();
        let mut writer = zones.writer_by_seq(seq).unwrap();
        let mut round = 0_u32;
        while !writer_stop.load(Ordering::Acquire) {
            for item in 0..64_u32 {
                writer
                    .upsert_rrset(
                        &key(0, item),
                        1,
                        0,
                        &rr(u8::try_from((item + round) % 200).unwrap_or(1)),
                    )
                    .unwrap();
            }
            if round.is_multiple_of(3) {
                for item in 0..16_u32 {
                    let _ = writer.delete_rrset(&key(0, item), 1, 0);
                }
            }
            // Конкурентный пин может сделать публикацию невыполнимой в этом
            // раунде (`ReaderContended` retryable по контракту) — пропускаем
            // раунд, а не считаем это порчей.
            match writer.commit() {
                Ok(_) | Err(pulse_zonefile::parallel::ParallelError::ReaderContended) => {}
                Err(error) => panic!("writer commit: {error:?}"),
            }
            round = round.wrapping_add(1);
        }
    });
    let reader = std::thread::spawn(move || {
        let mut seen = 0_u64;
        while !reader_stop.load(Ordering::Acquire) {
            let reader = reader_store.reader().unwrap();
            match reader_store.zone_snapshot(&reader, seq) {
                Ok(snapshot) => {
                    assert!(snapshot.version() > 0);
                    seen = seen.saturating_add(1);
                }
                // Пин мог пересечься с публикацией — retryable по контракту.
                Err(pulse_zonefile::parallel::ParallelError::ReaderContended) => {}
                Err(error) => panic!("reader: {error:?}"),
            }
        }
        seen
    });
    let mut reports = 0_u32;
    let mut reclaimed = 0_u64;
    let deadline = Instant::now() + Duration::from_millis(1200);
    while Instant::now() < deadline {
        match store.sweep_leaks(SweepConfig {
            orphan_buckets: false,
            ..small_sweep()
        }) {
            Ok(report) => {
                reports = reports.saturating_add(1);
                reclaimed = reclaimed.saturating_add(report.reclaimed_pages);
            }
            Err(pulse_zonefile::parallel::ParallelError::Busy) => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("sweep: {error:?}"),
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    stop.store(true, Ordering::Release);
    writer.join().unwrap();
    let reads = reader.join().unwrap();
    let graph = store.fsck_graph().unwrap();
    if !graph.ok {
        eprintln!("fsck after concurrent sweep: {graph:?}");
    }
    assert!(graph.ok, "sweep повредил граф");
    assert!(reads > 0);
    assert!(reports > 0);
    // Внутренние durable-утечки под нагрузкой допустимы; важно, что граф цел
    // и sweep не переиспользовал достижимые страницы.
    let reader = store.reader().unwrap();
    let snapshot = store.zone_snapshot(&reader, seq).unwrap();
    assert!(snapshot.version() > 0);
    eprintln!("sweep concurrent: reports={reports} reclaimed={reclaimed} reads={reads}");
}

struct KillAfterSweep {
    armed: Arc<AtomicBool>,
}

impl CrashHook for KillAfterSweep {
    fn at(&self, point: CrashPoint) {
        assert!(
            !(point == CrashPoint::AfterPhase1Writes && self.armed.swap(false, Ordering::AcqRel)),
            "injected sweep crash"
        );
    }
}

#[test]
fn sweep_crash_after_phase1_recovers_without_corruption() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("crash.v2");
    {
        let mut store = create_store(&path);
        seed(&store, 0, 8);
        make_durable_leak(&store, 16);
        let armed = Arc::new(AtomicBool::new(true));
        store.set_crash_hook(Box::new(KillAfterSweep { armed }));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = store.sweep_leaks(SweepConfig {
                max_scan_pages: 4096,
                max_leaks_per_call: 4096,
                max_duration: Duration::from_secs(1),
                orphan_buckets: true,
            });
        }));
        assert!(result.is_err(), "краш-хук не сработал");
    }
    let store = open_multi(&path);
    assert!(store.fsck_graph().unwrap().ok, "после краха граф повреждён");
    // Данные читаются, повторный sweep дочищает утечку/хвост.
    let reader = store.reader().unwrap();
    let snapshot = store.zone_snapshot(&reader, 1).unwrap();
    assert!(snapshot.version() > 0);
    for _ in 0..64 {
        match store.sweep_leaks(small_sweep()) {
            Ok(report) if report.complete_pass => break,
            Ok(_) | Err(pulse_zonefile::parallel::ParallelError::Busy) => {}
            Err(error) => panic!("sweep after crash: {error:?}"),
        }
    }
    assert!(store.fsck_graph().unwrap().ok);
}

#[test]
fn online_repair_without_lock_ex_returns_leaks() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("online-repair.v2");
    let store = create_store(&path);
    seed(&store, 0, 8);
    store.repair_leaks().unwrap();
    assert_eq!(store.leak_report().unwrap().leaked_pages, 0);
    make_durable_leak(&store, 24);
    assert!(store.leak_report().unwrap().leaked_pages >= 24);

    // Второй процесс/стор открывает файл в multi (LOCK_SH), без LOCK_EX.
    let report = pulse_zonefile::parallel::fsck_repair_online(&path).unwrap();
    assert!(report.repaired_pages >= 24, "{report:?}");
    assert!(report.ok, "{report:?}");
    assert!(store.fsck_graph().unwrap().ok);
    let after = store.leak_report().unwrap();
    assert_eq!(after.leaked_pages, 0, "{after:?}");
    // Исходный writer продолжает работать после онлайн-ремонта.
    let zones = ParallelZones::open(&store).unwrap();
    let mut writer = zones.writer_by_seq(1).unwrap();
    writer.upsert_rrset(&key(0, 0), 1, 0, &rr(7)).unwrap();
    writer.commit().unwrap();
    assert!(store.fsck_graph().unwrap().ok);
}

#[test]
#[ignore = "heavy: 100k RRset upsert/delete cycles"]
fn hundred_thousand_alloc_cycles_keep_watermarks_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cycles.v2");
    let store = ParallelStore::create(
        &path,
        StoreConfig {
            multi_process: true,
            sync_mode: SyncModeV2::Sync,
            ..StoreConfig::small(8, 1 << 16)
        },
    )
    .unwrap();
    let seq = seed(&store, 0, 8);
    let zones = ParallelZones::open(&store).unwrap();
    let mut writer = zones.writer_by_seq(seq).unwrap();
    let mut freed = 0_u64;
    for round in 0..100_u32 {
        for item in 0..1000_u32 {
            writer
                .upsert_rrset(
                    &key(0, item),
                    1,
                    0,
                    &rr(u8::try_from(round % 200).unwrap_or(1)),
                )
                .unwrap();
        }
        writer.commit().unwrap();
        for item in 0..1000_u32 {
            if writer.delete_rrset(&key(0, item), 1, 0).unwrap_or(false) {
                freed = freed.saturating_add(1);
            }
        }
        writer.commit().unwrap();
        if round % 10 == 0 {
            let _ = store.sweep_leaks(SweepConfig {
                max_scan_pages: 1024,
                max_leaks_per_call: 1024,
                max_duration: Duration::from_millis(10),
                orphan_buckets: false,
            });
        }
    }
    assert!(freed >= 99_000, "удалено {freed}");
    assert!(store.fsck_graph().unwrap().ok);
    let high_water = store.high_water();
    assert!(high_water < 1 << 16, "high_water {high_water}");
    eprintln!("100k cycles: freed={freed} high_water={high_water}");
}

#[test]
fn sweep_after_offline_cleanup_reclaims_to_zero() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("clean-then-sweep.v2");
    let store = create_store(&path);
    seed(&store, 0, 8);
    // Убираем batch-slack seed-коммита offline-путём, затем создаём «хвостовую»
    // утечку и проверяем, что онлайн-sweep доводит её до нуля.
    store.repair_leaks().unwrap();
    assert_eq!(store.leak_report().unwrap().leaked_pages, 0);
    make_durable_leak(&store, 16);
    assert!(store.leak_report().unwrap().leaked_pages >= 16);
    for _ in 0..64 {
        let report = store
            .sweep_leaks(SweepConfig {
                max_scan_pages: 4096,
                max_leaks_per_call: 4096,
                max_duration: Duration::from_secs(1),
                orphan_buckets: true,
            })
            .unwrap();
        if report.complete_pass {
            break;
        }
    }
    assert_eq!(store.leak_report().unwrap().leaked_pages, 0);
    assert!(store.fsck_graph().unwrap().ok);
}
