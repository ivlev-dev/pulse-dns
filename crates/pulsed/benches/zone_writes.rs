//! End-to-end bench v2: query QPS при параллельных REST-записях в 8 зон и
//! latency коммитов per-zone/group на этой машине.
//!
//! Запуск: `cargo bench -p pulsed --bench zone_writes` (release).
//! Печатает таблицы; критерии прохождения нет — это замер, а не тест.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::similar_names
)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use pulse_dns::{EncodeOptions, Message, Name, Question, Rclass, Rtype};
use pulse_zonefile::key::NameRle;
use pulse_zonefile::parallel::{
    GroupCommitter, ParallelStore, ParallelZones, RrsetData, StoreConfig, SyncModeV2,
    ZoneCreateMeta,
};
use pulsed::config::{CommitMode, Config, Durability, TcpConfig};
use pulsed::server::{ApiOptions, Server};

const TOKEN: &str = "pd_bench_token_0123456789abcdef";
const ZONES: usize = 8;
const ZONE_RECORDS: usize = 200;

/// Каталог на реальной ФС (не `/tmp` на tmpfs), чтобы `fdatasync` был честным.
fn bench_dir(label: &str) -> std::path::PathBuf {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pulsed-bench")
        .join(format!("{label}-{}", std::process::id()));
    std::fs::create_dir_all(&base).expect("bench dir");
    base
}

fn origin(zone: usize) -> String {
    format!("b{zone}.bench.test.")
}

fn rr(octets: [u8; 4]) -> RrsetData {
    RrsetData::from_slices(60, 0, &[&octets]).expect("rrset")
}

fn populate(data: &Path) {
    let store = ParallelStore::create(
        data,
        StoreConfig {
            max_zones: 32,
            page_count_max: 1 << 16,
            sync_mode: SyncModeV2::Sync,
            ..StoreConfig::default()
        },
    )
    .expect("create store");
    let mut zones = ParallelZones::open(&store).expect("catalog");
    for zone in 0..ZONES {
        let apex = NameRle::from_ascii(&origin(zone)).expect("apex");
        zones
            .create_zone(&apex, ZoneCreateMeta { soa_serial: 1 })
            .expect("zone");
        let mut writer = zones.writer(&apex).expect("writer");
        for record in 0..ZONE_RECORDS {
            let name = NameRle::from_ascii(&format!("r{record}.{}", origin(zone))).expect("name");
            writer
                .upsert_rrset(
                    &name,
                    1,
                    0,
                    &rr([10, 0, (zone % 250) as u8, (record % 250) as u8]),
                )
                .expect("upsert");
        }
        writer.commit().expect("commit");
    }
    drop(zones);
    store.sync().expect("sync");
}

struct Http {
    addr: SocketAddr,
}

impl Http {
    fn put(&self, path: &str, body: &str) -> Option<u16> {
        let mut stream = TcpStream::connect(self.addr).ok()?;
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
        let head = format!(
            "PUT {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
             Authorization: Bearer {TOKEN}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\n\r\n",
            body.len()
        );
        stream.write_all(head.as_bytes()).ok()?;
        stream.write_all(body.as_bytes()).ok()?;
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).ok()?;
        let text =
            std::str::from_utf8(&raw[..raw.windows(4).position(|w| w == b"\r\n\r\n")?]).ok()?;
        text.lines().next()?.split(' ').nth(1)?.parse::<u16>().ok()
    }
}

fn query(name: &str) -> Vec<u8> {
    Message::query(
        0x1234,
        Question::new(Name::parse(name).expect("name"), Rtype::A, Rclass::IN),
    )
    .encode(&EncodeOptions::compressed())
    .expect("encode")
}

fn qps(server: &Server, writers: usize, readers: usize, duration: Duration) -> (u64, u64) {
    let addr = server.udp_addr().expect("udp");
    let stop = Arc::new(AtomicBool::new(false));
    let answered = Arc::new(AtomicU64::new(0));
    let writes = Arc::new(AtomicU64::new(0));
    let api = Http {
        addr: server.api_addr().expect("api"),
    };
    let barrier = Arc::new(Barrier::new(readers + writers + 1));
    std::thread::scope(|scope| {
        for reader in 0..readers {
            let stop = Arc::clone(&stop);
            let answered = Arc::clone(&answered);
            let barrier = Arc::clone(&barrier);
            scope.spawn(move || {
                let socket = UdpSocket::bind("127.0.0.1:0").expect("socket");
                socket
                    .set_read_timeout(Some(Duration::from_millis(200)))
                    .expect("timeout");
                let mut buffer = [0_u8; 512];
                let mut index = reader;
                barrier.wait();
                while !stop.load(Ordering::Acquire) {
                    let zone = index % ZONES;
                    let record = index % ZONE_RECORDS;
                    let name = format!("r{record}.{}", origin(zone));
                    let bytes = query(&name);
                    if socket.send_to(&bytes, addr).is_ok() {
                        loop {
                            match socket.recv_from(&mut buffer) {
                                Ok(_) => {
                                    answered.fetch_add(1, Ordering::Relaxed);
                                    break;
                                }
                                Err(error)
                                    if matches!(
                                        error.kind(),
                                        std::io::ErrorKind::WouldBlock
                                            | std::io::ErrorKind::TimedOut
                                    ) =>
                                {
                                    break;
                                }
                                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                                Err(_) => break,
                            }
                        }
                    }
                    index = index.wrapping_add(1);
                }
            });
        }
        for writer in 0..writers {
            let stop = Arc::clone(&stop);
            let writes = Arc::clone(&writes);
            let barrier = Arc::clone(&barrier);
            let http = Http { addr: api.addr };
            scope.spawn(move || {
                let zone = writer % ZONES;
                let mut record = 0_usize;
                barrier.wait();
                while !stop.load(Ordering::Acquire) {
                    let owner = format!("w{writer}-{record}.{}", origin(zone));
                    let body = r#"{"ttl":60,"records":["192.0.2.1"]}"#;
                    if http.put(
                        &format!("/api/v1/zones/{}/records/{owner}/A", origin(zone)),
                        body,
                    ) == Some(201)
                    {
                        writes.fetch_add(1, Ordering::Relaxed);
                    }
                    record = record.saturating_add(1);
                }
            });
        }
        barrier.wait();
        std::thread::sleep(duration);
        stop.store(true, Ordering::Release);
    });
    (
        answered.load(Ordering::Relaxed),
        writes.load(Ordering::Relaxed),
    )
}

struct Latency {
    mean_ms: f64,
    p50_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
    wall_ms: f64,
    commits: usize,
    fsyncs: u64,
}

fn percent(sorted: &[u64], fraction: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let index = ((sorted.len() - 1) as f64 * fraction).round() as usize;
    sorted[index.min(sorted.len() - 1)] as f64 / 1000.0
}

fn commit_latency(group: bool, sync_delay: Duration, commits: usize) -> Latency {
    let dir = bench_dir("commit");
    let path = dir.join("commit.v2");
    let mut store = ParallelStore::create(
        &path,
        StoreConfig {
            max_zones: 32,
            page_count_max: 1 << 16,
            sync_mode: SyncModeV2::Sync,
            ..StoreConfig::default()
        },
    )
    .expect("store");
    store.set_sync_delay(sync_delay);
    let store = Arc::new(store);
    let mut zones = ParallelZones::open(&store).expect("catalog");
    for zone in 0..ZONES {
        zones
            .create_zone(
                &NameRle::from_ascii(&origin(zone)).expect("apex"),
                ZoneCreateMeta { soa_serial: 1 },
            )
            .expect("zone");
    }
    let committer = group.then(|| GroupCommitter::new(Arc::clone(&store)).expect("committer"));
    let start = Instant::now();
    let latencies: Vec<Vec<u64>> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..ZONES)
            .map(|zone| {
                let zones = &zones;
                let committer = committer.as_ref();
                scope.spawn(move || {
                    let apex = NameRle::from_ascii(&origin(zone)).expect("apex");
                    let mut writer = zones.writer(&apex).expect("writer");
                    let mut samples = Vec::with_capacity(commits);
                    for record in 0..commits {
                        let name = NameRle::from_ascii(&format!("c{record}.{}", origin(zone)))
                            .expect("name");
                        writer
                            .upsert_rrset(
                                &name,
                                1,
                                0,
                                &rr([10, 1, (zone % 250) as u8, (record % 250) as u8]),
                            )
                            .expect("upsert");
                        let started = Instant::now();
                        if let Some(committer) = committer {
                            writer
                                .commit_via_with(committer, SyncModeV2::Sync)
                                .expect("group commit");
                        } else {
                            writer.commit_with(SyncModeV2::Sync).expect("commit");
                        }
                        samples.push(u64::try_from(started.elapsed().as_micros()).unwrap_or(0));
                    }
                    samples
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("writer"))
            .collect()
    });
    let wall_ms = start.elapsed().as_secs_f64() * 1000.0;
    let mut all: Vec<u64> = latencies.into_iter().flatten().collect();
    all.sort_unstable();
    let total: u64 = all.iter().sum();
    let commits = all.len();
    let mean_ms = if commits == 0 {
        0.0
    } else {
        total as f64 / commits as f64 / 1000.0
    };
    let stats = store.stats();
    drop(zones);
    drop(store);
    let _ = std::fs::remove_dir_all(&dir);
    Latency {
        mean_ms,
        p50_ms: percent(&all, 0.50),
        p95_ms: percent(&all, 0.95),
        p99_ms: percent(&all, 0.99),
        wall_ms,
        commits,
        fsyncs: stats.group_fsyncs,
    }
}

fn print_latency(label: &str, latency: &Latency) {
    println!(
        "{label:<34} mean={:.2}ms p50={:.2}ms p95={:.2}ms p99={:.2}ms wall={:.1}ms \
         commits={} group_fsyncs={}",
        latency.mean_ms,
        latency.p50_ms,
        latency.p95_ms,
        latency.p99_ms,
        latency.wall_ms,
        latency.commits,
        latency.fsyncs
    );
}

fn run_qps_bench() {
    let dir = bench_dir("qps");
    let data = dir.join("qps.v2");
    populate(&data);
    let config = Config {
        listen_udp: Some("127.0.0.1:0".parse().expect("udp")),
        listen_tcp: None,
        workers: 4,
        tcp: TcpConfig {
            idle_timeout_ms: 2000,
            ..TcpConfig::default()
        },
        zonefile: Some(data),
        durability: Durability::Flush,
        map_size: 64 * 1024 * 1024,
        ..Config::default()
    };
    let mut server = Server::start_with_api(
        &config,
        Some(ApiOptions {
            listen: "127.0.0.1:0".parse().expect("api"),
            token: TOKEN.to_owned(),
            scopes: Vec::new(),
        }),
    )
    .expect("server");

    let (baseline, _) = qps(&server, 0, 4, Duration::from_secs(1));
    let (concurrent, writes) = qps(&server, 8, 4, Duration::from_secs(2));
    println!(
        "QPS baseline (no writes, 4 readers): {:.0} q/s",
        baseline as f64
    );
    println!(
        "QPS with 8 writer threads / 8 zones (2s): {:.0} q/s, acked REST writes={}",
        concurrent as f64 / 2.0,
        writes
    );
    server.shutdown().expect("shutdown");
    drop(server);
    let _ = std::fs::remove_dir_all(&dir);
}

fn main() {
    println!("pulsed v2 zone writes bench (release build)");
    println!(
        "host: {} cpus, fsync delay emulation via ParallelStore::set_sync_delay",
        std::thread::available_parallelism().map_or(0, std::num::NonZeroUsize::get)
    );
    run_qps_bench();

    println!("\nCommit latency, 8 zones x 50 commits (2 threads per zone):");
    let per_zone = commit_latency(false, Duration::ZERO, 50);
    print_latency("per-zone, real fsync", &per_zone);
    let group_real = commit_latency(true, Duration::ZERO, 50);
    print_latency("group, real fsync", &group_real);
    let per_zone_slow = commit_latency(false, Duration::from_millis(2), 50);
    print_latency("per-zone, simulated 2ms fsync", &per_zone_slow);
    let group_slow = commit_latency(true, Duration::from_millis(2), 50);
    print_latency("group, simulated 2ms fsync", &group_slow);
    let speedup = per_zone_slow.wall_ms / group_slow.wall_ms.max(0.001);
    println!(
        "\nGroup/parallel throughput vs per-zone at 2ms fsync: {speedup:.2}x \
         (group helps when fsync is expensive; at local NVMe latency the batcher adds overhead)"
    );
    let _ = CommitMode::Group;
}
