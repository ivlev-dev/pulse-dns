//! Bench v2-адаптера: NXDOMAIN на подписанной (synthetic DNSSEC) зоне через
//! реальный UDP-сервер, против старого линейного перебора denial-записей.
//!
//! Запуск: `cargo bench -p pulsed --bench negative` (release).
//! Размер зоны — `PULSE_BENCH_SIZE` (по умолчанию 100k), число legacy-сэмплов
//! (полный скан зоны) — `PULSE_BENCH_LEGACY_ITERS` (по умолчанию 30).

#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::similar_names
)]

use std::cmp::Ordering;
use std::io::ErrorKind;
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use pulse_dns::{Edns, EncodeOptions, Message, Name, Question, Rclass, Rdata, Rtype};
use pulse_zonefile::key::{NameRle, name_cmp};
use pulse_zonefile::parallel::{
    OpenConfigV2, ParallelStore, ParallelZone, ParallelZones, RrsetData, StoreConfig, SyncModeV2,
    ZoneCreateMeta,
};
use pulsed::config::Config;
use pulsed::server::Server;

fn name(text: &str) -> Name {
    Name::parse(text).expect("name")
}

fn rle(text: &str) -> NameRle {
    NameRle::from_ascii(text).expect("rle name")
}

fn bench_dir(label: &str) -> PathBuf {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pulsed-bench")
        .join(format!("{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).expect("bench dir");
    base
}

fn put(writer: &mut ParallelZone<'_>, owner: &NameRle, rr_type: u16, subtype: u16, wire: Vec<u8>) {
    let data = RrsetData::new(300, 0, vec![wire]).expect("rrset data");
    writer
        .upsert_rrset(owner, rr_type, subtype, &data)
        .expect("upsert");
}

#[allow(clippy::needless_pass_by_value)]
fn put_rrset(writer: &mut ParallelZone<'_>, owner: &NameRle, rdata: Rdata, rr_type: Rtype) {
    put(
        writer,
        owner,
        rr_type.as_u16(),
        0,
        rdata.to_canonical_wire(),
    );
}

fn base_zone(writer: &mut ParallelZone<'_>, origin: &Name, origin_rle: &NameRle) {
    put_rrset(
        writer,
        origin_rle,
        Rdata::Soa(pulse_dns::SoaData::new(
            name("ns1.example.com"),
            name("hostmaster.example.com"),
            pulse_dns::Serial::new(1),
            3600,
            600,
            604_800,
            300,
        )),
        Rtype::SOA,
    );
    put_rrset(
        writer,
        origin_rle,
        Rdata::Ns(name("ns1.example.com")),
        Rtype::NS,
    );
    put_rrset(
        writer,
        origin_rle,
        Rdata::Dnskey(pulse_dns::DnskeyData::new(257, 3, 8, vec![7_u8; 32]).expect("dnskey")),
        Rtype::DNSKEY,
    );
    let rrsig = pulse_dns::RrsigData::new(
        Rtype::DNSKEY,
        8,
        2,
        300,
        u32::MAX,
        1,
        1,
        origin.clone(),
        vec![9_u8; 64],
    )
    .expect("rrsig");
    put(
        writer,
        origin_rle,
        Rtype::RRSIG.as_u16(),
        Rtype::DNSKEY.as_u16(),
        Rdata::Rrsig(rrsig).to_canonical_wire(),
    );
    let www = rle("www.example.com.");
    put_rrset(
        writer,
        &www,
        Rdata::A("192.0.2.1".parse().expect("ip")),
        Rtype::A,
    );
    put_rrset(
        writer,
        origin_rle,
        Rdata::A("192.0.2.254".parse().expect("ip")),
        Rtype::A,
    );
}

fn owners(size: usize) -> Vec<Name> {
    let mut owners = Vec::with_capacity(size + 2);
    owners.push(name("example.com."));
    owners.push(name("www.example.com."));
    for index in 0..size {
        owners.push(name(&format!("n{index}.example.com.")));
    }
    owners.sort_by(Name::cmp_canonical);
    owners.dedup();
    owners
}

fn page_count_max(size: usize) -> u32 {
    if size >= 1_000_000 { 1 << 23 } else { 1 << 20 }
}

fn populate_nsec(path: &Path, size: usize) {
    let store = ParallelStore::create(
        path,
        StoreConfig {
            max_zones: 4,
            page_count_max: page_count_max(size),
            sync_mode: SyncModeV2::Memory,
            ..StoreConfig::default()
        },
    )
    .expect("create store");
    let mut zones = ParallelZones::open(&store).expect("catalog");
    let origin = name("example.com.");
    let apex = rle("example.com.");
    zones
        .create_zone(&apex, ZoneCreateMeta { soa_serial: 1 })
        .expect("zone");
    let owners = owners(size);
    let bitmap = pulse_dns::TypeBitmap::from_types([
        Rtype::A,
        Rtype::NS,
        Rtype::SOA,
        Rtype::NSEC,
        Rtype::RRSIG,
    ]);
    {
        let mut writer = zones.writer(&apex).expect("writer");
        base_zone(&mut writer, &origin, &apex);
        for (index, owner) in owners.iter().enumerate() {
            let next = owners
                .get(index + 1)
                .cloned()
                .unwrap_or_else(|| origin.clone());
            let nsec = pulse_dns::NsecData::new(next, bitmap.clone()).expect("nsec");
            put_rrset(
                &mut writer,
                &rle(&owner.to_string()),
                Rdata::Nsec(nsec),
                Rtype::NSEC,
            );
        }
        writer.commit().expect("commit");
    }
    drop(zones);
    store.sync().expect("sync");
}

fn populate_nsec3(path: &Path, size: usize) {
    let store = ParallelStore::create(
        path,
        StoreConfig {
            max_zones: 4,
            page_count_max: page_count_max(size),
            sync_mode: SyncModeV2::Memory,
            ..StoreConfig::default()
        },
    )
    .expect("create store");
    let mut zones = ParallelZones::open(&store).expect("catalog");
    let origin = name("example.com.");
    let apex = rle("example.com.");
    zones
        .create_zone(&apex, ZoneCreateMeta { soa_serial: 1 })
        .expect("zone");
    let salt = vec![0xAA, 0xBB];
    let mut hashes: Vec<Vec<u8>> = owners(size)
        .iter()
        .map(|owner| pulse_dnssec::rdata_util::nsec3_hash(owner, &salt, 0))
        .collect();
    hashes.sort();
    let bitmap = pulse_dns::TypeBitmap::from_types([Rtype::A, Rtype::NS, Rtype::RRSIG]);
    {
        let mut writer = zones.writer(&apex).expect("writer");
        base_zone(&mut writer, &origin, &apex);
        put_rrset(
            &mut writer,
            &apex,
            Rdata::Nsec3Param(
                pulse_dns::Nsec3ParamData::new(1, 0, 0, salt.clone()).expect("param"),
            ),
            Rtype::NSEC3PARAM,
        );
        for (index, hash) in hashes.iter().enumerate() {
            let next = hashes
                .get(index + 1)
                .cloned()
                .unwrap_or_else(|| hashes[0].clone());
            let owner_time = pulse_dnssec::denial::nsec3_owner_name(&origin, hash).expect("owner");
            let owner = rle(&owner_time.to_string());
            let nsec3 = pulse_dns::Nsec3Data::new(1, 0, 0, salt.clone(), next, bitmap.clone())
                .expect("nsec3");
            put_rrset(&mut writer, &owner, Rdata::Nsec3(nsec3), Rtype::NSEC3);
        }
        writer.commit().expect("commit");
    }
    drop(zones);
    store.sync().expect("sync");
}

fn request(qname: &str, qtype: Rtype) -> Vec<u8> {
    let mut message = Message::query(0x1234, Question::new(name(qname), qtype, Rclass::IN));
    message.set_edns(Some(Edns::new(1232).with_dnssec_ok(true)));
    message
        .encode(&EncodeOptions::compressed())
        .expect("encode query")
}

fn start_server(path: &Path) -> Server {
    let config = format!(
        r#"{{"listen_udp":"127.0.0.1:0","listen_tcp":null,"workers":1,
        "zonefile":"{}","durability":"memory","map_size":536870912}}"#,
        path.display()
    );
    let config = Config::from_json_str(&config).expect("config");
    config.validate().expect("valid config");
    Server::start(&config).expect("server")
}

struct Stats {
    p50: u64,
    p99: u64,
    mean: f64,
}

fn stats(mut samples: Vec<u64>, elapsed: Duration) -> Stats {
    samples.sort_unstable();
    let p50 = samples[samples.len() / 2];
    let p99 = samples[(samples.len() * 99 / 100).min(samples.len() - 1)];
    Stats {
        p50,
        p99,
        mean: elapsed.as_secs_f64() * 1e9 / samples.len() as f64,
    }
}

fn measure_udp(server: &Server, request: &[u8], iterations: usize) -> Stats {
    let address = server.udp_addr().expect("udp");
    let socket = UdpSocket::bind("127.0.0.1:0").expect("socket");
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("timeout");
    let mut buffer = [0_u8; 4096];
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..(iterations / 10).max(1) {
        socket.send_to(request, address).expect("send");
        loop {
            match socket.recv_from(&mut buffer) {
                Ok(_) => break,
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) => panic!("warmup recv: {error}"),
            }
        }
    }
    let start = Instant::now();
    for _ in 0..iterations {
        let begin = Instant::now();
        socket.send_to(request, address).expect("send");
        loop {
            match socket.recv_from(&mut buffer) {
                Ok(_) => break,
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) => panic!("recv: {error}"),
            }
        }
        samples.push(u64::try_from(begin.elapsed().as_nanos()).unwrap_or(u64::MAX));
    }
    stats(samples, start.elapsed())
}

fn nsec_covers(owner: &NameRle, next: &NameRle, target: &NameRle) -> bool {
    if owner == target {
        return false;
    }
    match name_cmp(owner.as_rle(), next.as_rle()).expect("name cmp") {
        Ordering::Less => {
            name_cmp(owner.as_rle(), target.as_rle()).expect("cmp") == Ordering::Less
                && name_cmp(target.as_rle(), next.as_rle()).expect("cmp") == Ordering::Less
        }
        Ordering::Greater | Ordering::Equal => {
            name_cmp(owner.as_rle(), target.as_rle()).expect("cmp") == Ordering::Less
                || name_cmp(target.as_rle(), next.as_rle()).expect("cmp") == Ordering::Less
        }
    }
}

fn nsec3_covers(owner: &[u8], next: &[u8], hash: &[u8]) -> bool {
    if hash == owner {
        return false;
    }
    match owner.cmp(next) {
        Ordering::Less => hash > owner && hash < next,
        Ordering::Greater | Ordering::Equal => hash > owner || hash < next,
    }
}

/// Полный скан зоны как в старом `nsec_cover`/`nsec3_cover` адаптера.
fn legacy_cover(
    store: &ParallelStore,
    zones: &ParallelZones<'_>,
    apex: &NameRle,
    target: &NameRle,
    target_hash: Option<&[u8]>,
) -> bool {
    let reader = store.reader().expect("reader");
    let view = zones.read(&reader, apex).expect("zone view");
    let records = view.records().expect("records");
    for record in records {
        if let Some(hash) = target_hash {
            if record.rr_type != Rtype::NSEC3.as_u16() {
                continue;
            }
            let Some(label) = record.name.first_label() else {
                continue;
            };
            let Ok(owner) = pulse_dnssec::denial::base32hex::decode(label) else {
                continue;
            };
            let Some(bytes) = record.rdata.first() else {
                continue;
            };
            let Ok(Rdata::Nsec3(data)) = Rdata::from_wire(Rtype::NSEC3, bytes) else {
                continue;
            };
            if nsec3_covers(&owner, data.next_hashed_owner(), hash) {
                return true;
            }
        } else {
            if record.rr_type != Rtype::NSEC.as_u16() {
                continue;
            }
            let Some(bytes) = record.rdata.first() else {
                continue;
            };
            let Ok(Rdata::Nsec(next)) = Rdata::from_wire(Rtype::NSEC, bytes) else {
                continue;
            };
            let Ok(next) = NameRle::from_wire(next.next_domain().as_wire()) else {
                continue;
            };
            if nsec_covers(&record.name, &next, target) {
                return true;
            }
        }
    }
    false
}

fn measure_legacy(
    store: &ParallelStore,
    zones: &ParallelZones<'_>,
    apex: &NameRle,
    target: &NameRle,
    target_hash: Option<&[u8]>,
    iterations: usize,
) -> Stats {
    let mut samples = Vec::with_capacity(iterations);
    let start = Instant::now();
    for _ in 0..iterations {
        let begin = Instant::now();
        let found = legacy_cover(store, zones, apex, target, target_hash);
        std::hint::black_box(found);
        samples.push(u64::try_from(begin.elapsed().as_nanos()).unwrap_or(u64::MAX));
    }
    stats(samples, start.elapsed())
}

fn print_row(label: &str, stats: &Stats) {
    println!(
        "{label:<36} p50 {:>9.1} us  p99 {:>9.1} us  mean {:>9.1} us  qps {:>9.0}",
        stats.p50 as f64 / 1000.0,
        stats.p99 as f64 / 1000.0,
        stats.mean / 1000.0,
        1e9 / stats.mean,
    );
}

fn scenario(nsec3: bool, size: usize, iterations: usize, legacy_iterations: usize) {
    let label = if nsec3 { "NSEC3" } else { "NSEC" };
    let dir = bench_dir(&format!(
        "negative-{}",
        if nsec3 { "nsec3" } else { "nsec" }
    ));
    let path = dir.join("zones.v2");
    let started = Instant::now();
    if nsec3 {
        populate_nsec3(&path, size);
    } else {
        populate_nsec(&path, size);
    }
    println!(
        "{label}: zonefile built in {:.2} s",
        started.elapsed().as_secs_f64()
    );

    let miss_name = format!("missing{}.example.com.", size / 2);
    let miss = request(&miss_name, Rtype::A);
    let hit = request("www.example.com.", Rtype::A);

    let server = start_server(&path);
    let new_neg = measure_udp(&server, &miss, iterations);
    let new_pos = measure_udp(&server, &hit, iterations);
    print_row(&format!("{label} NXDOMAIN indexed (UDP)"), &new_neg);
    print_row(&format!("{label} A www indexed (UDP)"), &new_pos);
    drop(server);

    let store = ParallelStore::open(&path, OpenConfigV2::default()).expect("open store");
    let zones = ParallelZones::open(&store).expect("catalog");
    let apex = rle("example.com.");
    let target = rle(&miss_name);
    let salt = vec![0xAA, 0xBB];
    let target_hash =
        nsec3.then(|| pulse_dnssec::rdata_util::nsec3_hash(&name(&miss_name), &salt, 0));
    let old_neg = measure_legacy(
        &store,
        &zones,
        &apex,
        &target,
        target_hash.as_deref(),
        legacy_iterations,
    );
    print_row(&format!("{label} NXDOMAIN legacy scan"), &old_neg);
    drop(zones);
    drop(store);
    let _ = std::fs::remove_dir_all(&dir);

    println!(
        "{label} speedup NXDOMAIN p99: {:.0}x; NXDOMAIN/positive p50: {:.2}x\n",
        old_neg.p99 as f64 / new_neg.p99.max(1) as f64,
        new_neg.p50 as f64 / new_pos.p50.max(1) as f64,
    );
}

fn main() {
    let size = std::env::var("PULSE_BENCH_SIZE")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(100_000);
    let iterations = std::env::var("PULSE_BENCH_ITERATIONS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(10_000);
    let legacy_iterations = std::env::var("PULSE_BENCH_LEGACY_ITERS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(30);
    println!(
        "pulsed v2: signed zone {size} names, {iterations} UDP samples, {legacy_iterations} legacy scans (DO=1)\n"
    );
    scenario(false, size, iterations, legacy_iterations);
    scenario(true, size, iterations, legacy_iterations);
}
