//! Bulk-загрузка v2: эквивалентность incremental, overflow/ENT/wildcard,
//! reopen/fsck, замена существующей зоны и fail-closed по порядку входа.

use std::time::Instant;

use pulse_zonefile::key::NameRle;
use pulse_zonefile::parallel::{
    BulkRrset, OpenConfigV2, ParallelError, ParallelStore, ParallelZones, RrsetData, StoreConfig,
    ZoneCreateMeta,
};

const APEX: &str = "example.com";
const RECORDS: u32 = 10_006;

fn config() -> StoreConfig {
    StoreConfig::small(64, 1 << 20)
}

fn rr(ttl: u32, octets: &[u8]) -> RrsetData {
    RrsetData::from_slices(ttl, 0, &[octets]).unwrap()
}

fn bulk(name: &str, rr_type: u16, subtype: u16, data: RrsetData) -> BulkRrset {
    BulkRrset {
        name: NameRle::from_ascii(name).unwrap(),
        rr_type,
        subtype,
        data,
    }
}

fn sort_bulk(records: &mut [BulkRrset]) {
    records.sort_by(|left, right| left.key().unwrap().compare(&right.key().unwrap()));
}

fn sample_records(apex: &str) -> Vec<BulkRrset> {
    let mut records = Vec::new();
    records.push(bulk(
        apex,
        6,
        0,
        RrsetData::from_slices(60, 0, &[&[0, 0, 0, 0, 0, 1]]).unwrap(),
    ));
    records.push(bulk(apex, 2, 0, rr(60, &[0, 1])));
    records.push(bulk(&format!("ns1.{apex}"), 1, 0, rr(60, &[127, 0, 0, 1])));
    for index in 0..10_000_u32 {
        let name = format!("r{index:05}.{apex}");
        let data = match index % 4 {
            0 => rr(60, &[10, 0, 0, u8::try_from(index % 250).unwrap()]),
            1 => rr(
                60,
                &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1],
            ),
            2 => rr(60, &[0, 10, 0, 0, 0, 0, 0, 0]),
            _ => rr(60, b"pulse bulk equivalence"),
        };
        records.push(bulk(&name, [1, 28, 16, 16][index as usize % 4], 0, data));
    }
    records.push(bulk(
        &format!("deep.a.b.{apex}"),
        1,
        0,
        rr(60, &[10, 1, 2, 3]),
    ));
    records.push(bulk(
        &format!("*.wild.{apex}"),
        1,
        0,
        rr(60, &[10, 9, 9, 9]),
    ));
    let large = vec![b'x'; 700];
    records.push(bulk(
        &format!("big.{apex}"),
        16,
        0,
        RrsetData::from_slices(60, 0, &[&large]).unwrap(),
    ));
    sort_bulk(&mut records);
    records
}

fn create_zone(path: &std::path::Path) -> (ParallelStore, u32) {
    let store = ParallelStore::create(path, config()).unwrap();
    let mut zones = ParallelZones::open(&store).unwrap();
    let seq = zones
        .create_zone(
            &NameRle::from_ascii(APEX).unwrap(),
            ZoneCreateMeta { soa_serial: 11 },
        )
        .unwrap();
    drop(zones);
    (store, seq)
}

#[test]
fn bulk_matches_incremental_and_reopens() {
    let dir = tempfile::tempdir().unwrap();
    let bulk_path = dir.path().join("bulk.v2");
    let inc_path = dir.path().join("inc.v2");
    let (bulk_store, bulk_seq) = create_zone(&bulk_path);
    let (inc_store, inc_seq) = create_zone(&inc_path);
    let records = sample_records(APEX);

    {
        let zones = ParallelZones::open(&bulk_store).unwrap();
        let mut writer = zones.writer_by_seq(bulk_seq).unwrap();
        let outcome = writer.bulk_load(records.iter().cloned()).unwrap();
        assert_eq!(outcome.rrsets, RECORDS);
        assert_eq!(writer.rrset_count(), RECORDS);
        let committed = writer.commit().unwrap();
        assert!(committed.changed);
        assert_eq!(committed.rrset_count, RECORDS);
        assert_eq!(committed.root_page, outcome.root_page);
    }
    {
        let zones = ParallelZones::open(&inc_store).unwrap();
        let mut writer = zones.writer_by_seq(inc_seq).unwrap();
        for record in &records {
            writer
                .upsert_rrset(&record.name, record.rr_type, record.subtype, &record.data)
                .unwrap();
        }
        assert_eq!(writer.commit().unwrap().rrset_count, RECORDS);
    }

    {
        let bulk_zones = ParallelZones::open(&bulk_store).unwrap();
        let inc_zones = ParallelZones::open(&inc_store).unwrap();
        let bulk_reader = bulk_store.reader().unwrap();
        let inc_reader = inc_store.reader().unwrap();
        let apex = NameRle::from_ascii(APEX).unwrap();
        let bulk_view = bulk_zones.read(&bulk_reader, &apex).unwrap();
        let inc_view = inc_zones.read(&inc_reader, &apex).unwrap();
        assert_eq!(bulk_view.records().unwrap(), inc_view.records().unwrap());
        for name in [APEX, "deep.a.b.example.com", "*.wild.example.com"] {
            let name = NameRle::from_ascii(name).unwrap();
            assert_eq!(
                bulk_view.node(&name).unwrap(),
                inc_view.node(&name).unwrap(),
                "node {name}"
            );
        }
        let ent = NameRle::from_ascii("b.example.com").unwrap();
        let bulk_ent = bulk_view.node(&ent).unwrap();
        let inc_ent = inc_view.node(&ent).unwrap();
        assert!(bulk_ent.is_empty_non_terminal);
        assert_eq!(bulk_ent, inc_ent);
        let big = NameRle::from_ascii("big.example.com").unwrap();
        let bulk_big = bulk_view.lookup(&big, 16, 0).unwrap().expect("overflow");
        let inc_big = inc_view.lookup(&big, 16, 0).unwrap().expect("overflow");
        assert_eq!(bulk_big, inc_big);
        assert_eq!(bulk_big.rdata.first().map(Vec::len), Some(700));
    }
    assert!(bulk_store.fsck_lite().unwrap().ok);
    assert!(inc_store.fsck_lite().unwrap().ok);
    drop(bulk_store);
    drop(inc_store);

    let bulk_store = ParallelStore::open(&bulk_path, OpenConfigV2::default()).unwrap();
    let inc_store = ParallelStore::open(&inc_path, OpenConfigV2::default()).unwrap();
    {
        let bulk_zones = ParallelZones::open(&bulk_store).unwrap();
        let inc_zones = ParallelZones::open(&inc_store).unwrap();
        let bulk_reader = bulk_store.reader().unwrap();
        let inc_reader = inc_store.reader().unwrap();
        let apex = NameRle::from_ascii(APEX).unwrap();
        let bulk_view = bulk_zones.read(&bulk_reader, &apex).unwrap();
        let inc_view = inc_zones.read(&inc_reader, &apex).unwrap();
        assert_eq!(bulk_view.records().unwrap(), inc_view.records().unwrap());
    }
    assert!(bulk_store.fsck_lite().unwrap().ok);
}

#[test]
fn bulk_replaces_existing_zone_and_frees_old_pages() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("replace.v2");
    let store = ParallelStore::create(&path, config()).unwrap();
    let mut zones = ParallelZones::open(&store).unwrap();
    let apex = NameRle::from_ascii("replace.example.com").unwrap();
    let seq = zones
        .create_zone(&apex, ZoneCreateMeta { soa_serial: 1 })
        .unwrap();
    let mut first = Vec::new();
    for index in 0..500_u32 {
        first.push(bulk(
            &format!("r{index:04}.replace.example.com"),
            1,
            0,
            rr(60, &[10, 0, 0, u8::try_from(index % 250).unwrap()]),
        ));
    }
    sort_bulk(&mut first);
    {
        let mut writer = zones.writer_by_seq(seq).unwrap();
        assert_eq!(writer.bulk_load(first).unwrap().rrsets, 500);
        writer.commit().unwrap();
    }
    let mut second = Vec::new();
    for index in 0..200_u32 {
        second.push(bulk(
            &format!("s{index:04}.replace.example.com"),
            1,
            0,
            rr(60, &[10, 0, 1, u8::try_from(index % 250).unwrap()]),
        ));
    }
    sort_bulk(&mut second);
    {
        let mut writer = zones.writer_by_seq(seq).unwrap();
        assert_eq!(writer.bulk_load(second).unwrap().rrsets, 200);
        let committed = writer.commit().unwrap();
        assert_eq!(committed.rrset_count, 200);
    }
    let reader = store.reader().unwrap();
    let view = zones.read(&reader, &apex).unwrap();
    assert_eq!(view.records().unwrap().len(), 200);
    assert!(
        view.lookup(
            &NameRle::from_ascii("r0000.replace.example.com").unwrap(),
            1,
            0
        )
        .unwrap()
        .is_none()
    );
    assert!(
        view.lookup(
            &NameRle::from_ascii("s0000.replace.example.com").unwrap(),
            1,
            0
        )
        .unwrap()
        .is_some()
    );
    assert!(store.fsck_lite().unwrap().ok);
}

#[test]
fn bulk_rejects_unsorted_without_state_change() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("order.v2");
    let store = ParallelStore::create(&path, config()).unwrap();
    let mut zones = ParallelZones::open(&store).unwrap();
    let apex = NameRle::from_ascii("order.example.com").unwrap();
    let seq = zones
        .create_zone(&apex, ZoneCreateMeta { soa_serial: 1 })
        .unwrap();
    let mut writer = zones.writer_by_seq(seq).unwrap();
    let before = writer.version();
    let records = vec![
        bulk("b.order.example.com", 1, 0, rr(60, &[10, 0, 0, 2])),
        bulk("a.order.example.com", 1, 0, rr(60, &[10, 0, 0, 1])),
    ];
    match writer.bulk_load(records) {
        Err(ParallelError::BulkOrder) => {}
        other => panic!("expected BulkOrder, got {other:?}"),
    }
    assert_eq!(writer.version(), before);
    assert_eq!(writer.rrset_count(), 0);
    assert_eq!(writer.records().unwrap().len(), 0);
    let mut good = vec![bulk("a.order.example.com", 1, 0, rr(60, &[10, 0, 0, 1]))];
    sort_bulk(&mut good);
    assert_eq!(writer.bulk_load(good).unwrap().rrsets, 1);
    let committed = writer.commit().unwrap();
    assert_eq!(committed.rrset_count, 1);
}

#[test]
fn memory_commit_publishes_allocator_cursor() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cursor.v2");
    let store = ParallelStore::create(
        &path,
        StoreConfig {
            sync_mode: pulse_zonefile::parallel::SyncModeV2::Memory,
            ..config()
        },
    )
    .unwrap();
    let mut zones = ParallelZones::open(&store).unwrap();
    let apex = NameRle::from_ascii("cursor.example.com").unwrap();
    let seq = zones
        .create_zone(&apex, ZoneCreateMeta { soa_serial: 1 })
        .unwrap();
    // Страницы, выданные после корня и не попавшие ни в root_page, ни в пул:
    // `Memory`-голова обязана нести cursor, иначе reopen возьмёт DP ниже.
    let ticket = store.reserve_pages(512).unwrap();
    let records = vec![bulk("a.cursor.example.com", 1, 0, rr(60, &[10, 0, 0, 1]))];
    {
        let mut writer = zones.writer_by_seq(seq).unwrap();
        writer.bulk_load(records).unwrap();
        writer
            .commit_with(pulse_zonefile::parallel::SyncModeV2::Memory)
            .unwrap();
    }
    let head = store.zone_head(seq).unwrap();
    assert!(
        u64::from(head.page_limit_at_commit) > u64::from(ticket.last_page()),
        "page_limit={} cursor={}",
        head.page_limit_at_commit,
        store.allocator().cursor()
    );
    drop(zones);
    drop(store);
    let reopened = ParallelStore::open(&path, OpenConfigV2::default()).unwrap();
    assert!(
        reopened.allocator().cursor() > u64::from(ticket.last_page()),
        "recovery regressed cursor to {}",
        reopened.allocator().cursor()
    );
    assert!(reopened.fsck_lite().unwrap().ok);
}

/// Большой сценарий (не входит в обычный `cargo test`): 1M `RRset`, проверка
/// времени/пикового RSS и fsck. Запуск:
/// `cargo test -p pulse-zonefile --release --test v2_bulk -- --ignored large`.
#[test]
#[ignore = "1M RRset benchmark, run manually"]
fn bulk_1m_time_and_memory() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bulk1m.v2");
    let store = ParallelStore::create(
        &path,
        StoreConfig {
            sync_mode: pulse_zonefile::parallel::SyncModeV2::Memory,
            ..StoreConfig::small(4, 1 << 26)
        },
    )
    .unwrap();
    let mut zones = ParallelZones::open(&store).unwrap();
    let apex = NameRle::from_ascii("bulk1m.example").unwrap();
    let seq = zones
        .create_zone(&apex, ZoneCreateMeta { soa_serial: 1 })
        .unwrap();
    let started = Instant::now();
    let mut writer = zones.writer_by_seq(seq).unwrap();
    let head = vec![
        bulk("bulk1m.example", 2, 0, rr(60, &[0, 1])),
        bulk("bulk1m.example", 6, 0, rr(60, &[0, 0, 0, 0, 0, 1])),
        bulk("ns1.bulk1m.example", 1, 0, rr(60, &[127, 0, 0, 1])),
    ];
    let generated = head.into_iter().chain((0..1_000_000_u32).map(|index| {
        let name = format!("r{index:07}.bulk1m.example");
        let octets = index.to_be_bytes();
        let data = match index % 4 {
            0 => rr(60, &[10, octets[2], octets[3], 1]),
            1 => rr(60, &[10, 1, octets[2], octets[3]]),
            2 => rr(60, &[10, 2, octets[2], octets[3]]),
            _ => rr(60, b"pulse bulk 1m"),
        };
        bulk(&name, [1, 28, 16, 16][index as usize % 4], 0, data)
    }));
    let outcome = writer.bulk_load(generated).unwrap();
    assert_eq!(outcome.rrsets, 1_000_003);
    let committed = writer
        .commit_with(pulse_zonefile::parallel::SyncModeV2::Memory)
        .unwrap();
    assert_eq!(committed.rrset_count, 1_000_003);
    let elapsed = started.elapsed();
    let rss_kib = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|text| {
            text.lines()
                .find(|line| line.starts_with("VmHWM:"))
                .and_then(|line| line.split_whitespace().nth(1))
                .and_then(|value| value.parse::<u64>().ok())
        })
        .unwrap_or(0);
    eprintln!(
        "bulk 1M: {elapsed:?}, dirty={} pages ({} MiB), VmHWM={} MiB",
        outcome.pages,
        u64::from(outcome.pages) * 4096 / (1024 * 1024),
        rss_kib / 1024
    );
    assert!(elapsed.as_secs() < 300, "1M bulk took {elapsed:?}");
    assert!(rss_kib < 512 * 1024, "peak RSS {rss_kib} KiB");
    assert!(store.fsck_lite().unwrap().ok);
}
