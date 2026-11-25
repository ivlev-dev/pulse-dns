//! Процессный bench разделения ролей: DNS-нагрузка + REST PUT одновременно.
//!
//! Сравниваются два сценария на одинаковом zonefile:
//! * `all` — один процесс (DNS + REST), текущее поведение;
//! * `split` — отдельные процессы `dns` и `api` на одном файле (multi-process).
//!
//! Запуск:
//! ```bash
//! cargo build --release -p pulsed
//! cargo bench -p pulsed --bench role_split -- --seconds 5
//! ```

#![allow(clippy::cast_precision_loss)]

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use pulse_dns::{DecodeLimits, EncodeOptions, Message, Name, Question, Rclass, Rtype};
use pulsed::config::{Config, Durability, Role, TcpConfig};

const TOKEN: &str = "pd_bench_roles_0123456789abcdefabcd";
const RECORDS: usize = 32;
const ZONES: usize = 8;
const DNS_THREADS: usize = 8;
const REST_THREADS: usize = 8;

struct Guard {
    child: Child,
}

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Stats {
    count: usize,
    seconds: f64,
    p50_us: f64,
    p99_us: f64,
}

impl Stats {
    fn rate(&self) -> f64 {
        self.count as f64 / self.seconds
    }
}

fn pulsed_bin() -> PathBuf {
    let exe = std::env::current_exe().expect("current exe");
    let profile = exe
        .parent()
        .and_then(Path::parent)
        .expect("profile directory");
    let bin = profile.join("pulsed");
    assert!(
        bin.exists(),
        "{} not found; run `cargo build --release -p pulsed` first",
        bin.display()
    );
    bin
}

fn free_udp_port() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("udp");
    socket.local_addr().expect("addr").port()
}

fn reserved_tcp_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("tcp");
    listener.local_addr().expect("addr")
}

fn zone_origin(zone: usize) -> String {
    format!("bench{zone}.test.")
}

fn master_zone(zone: usize) -> String {
    let origin = zone_origin(zone);
    let mut text = format!(
        "$ORIGIN {origin}\n$TTL 60\n\
         @ IN SOA ns1.{origin} hostmaster.{origin} 1 3600 600 604800 300\n\
         @ IN NS ns1.{origin}\n\
         ns1 IN A 192.0.2.53\n"
    );
    for index in 0..RECORDS {
        let _ = writeln!(text, "r{index} IN A 192.0.2.{}", index % 250 + 1);
    }
    text
}

fn prepare_data(bin: &Path, dir: &Path, name: &str, map_size: u64) -> PathBuf {
    let data = dir.join(format!("{name}.v2"));
    for zone in 0..ZONES {
        let master = dir.join(format!("{name}-{zone}.zone"));
        std::fs::write(&master, master_zone(zone)).expect("write master");
        let output = Command::new(bin)
            .arg("import")
            .arg("--data")
            .arg(&data)
            .arg("--origin")
            .arg(zone_origin(zone))
            .arg("--durability")
            .arg("flush")
            .arg("--map-size")
            .arg(map_size.to_string())
            .arg(&master)
            .stdin(Stdio::null())
            .output()
            .expect("run pulsed import");
        assert!(
            output.status.success(),
            "import failed: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    data
}

fn config(
    role: Role,
    data: &Path,
    udp: Option<u16>,
    tcp: Option<SocketAddr>,
    api: Option<SocketAddr>,
    map_size: u64,
) -> Config {
    Config {
        role,
        listen_udp: udp.map(|port| SocketAddr::from(([127, 0, 0, 1], port))),
        listen_tcp: tcp,
        api_listen: api,
        api_token: Some(TOKEN.to_owned()),
        api_workers: Some(64),
        api_rate_limit_per_sec: 100_000,
        workers: 0,
        dns_workers: Some(DNS_THREADS),
        zone_poll_ms: 100,
        tcp: TcpConfig {
            idle_timeout_ms: 2000,
            ..TcpConfig::default()
        },
        zonefile: Some(data.to_path_buf()),
        durability: Durability::Flush,
        map_size,
        journal: false,
        ..Config::default()
    }
}

fn write_config(dir: &Path, name: &str, config: &Config) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, config.to_toml_string().expect("toml")).expect("write config");
    path
}

fn spawn(config: &Path) -> Guard {
    let child = Command::new(pulsed_bin())
        .arg("--config")
        .arg(config)
        .env_remove("PULSED_API_TOKEN")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn pulsed");
    Guard { child }
}

fn http(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&str>,
) -> Option<(u16, String)> {
    let mut stream = TcpStream::connect(addr).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok()?;
    stream.set_nodelay(true).ok()?;
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
    let _ = write!(head, "Authorization: Bearer {TOKEN}\r\n");
    for (name, value) in headers {
        let _ = write!(head, "{name}: {value}\r\n");
    }
    if let Some(body) = body {
        head.push_str("Content-Type: application/json\r\n");
        let _ = write!(head, "Content-Length: {}\r\n", body.len());
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).ok()?;
    if let Some(body) = body {
        stream.write_all(body.as_bytes()).ok()?;
    }
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).ok()?;
    let end = raw.windows(4).position(|window| window == b"\r\n\r\n")?;
    let head = std::str::from_utf8(raw.get(..end)?).ok()?;
    let status = head.lines().next()?.split(' ').nth(1)?.parse().ok()?;
    Some((
        status,
        String::from_utf8_lossy(raw.get(end + 4..)?).into_owned(),
    ))
}

fn wait_ready(api: Option<SocketAddr>, udp: Option<u16>) -> bool {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        let api_ok = api.is_none_or(|addr| {
            http(addr, "GET", "/api/v1/zones", &[], None).is_some_and(|(status, _)| status == 200)
        });
        let dns_ok =
            udp.is_none_or(|port| dns_roundtrip(port, &format!("r0.{}", zone_origin(0))).is_some());
        if api_ok && dns_ok {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

fn dns_roundtrip(port: u16, qname: &str) -> Option<u64> {
    let socket = UdpSocket::bind("127.0.0.1:0").ok()?;
    socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .ok()?;
    let query = Message::query(
        0x1234,
        Question::new(Name::parse(qname).ok()?, Rtype::A, Rclass::IN),
    )
    .encode(&EncodeOptions::compressed())
    .ok()?;
    let started = Instant::now();
    socket
        .send_to(&query, SocketAddr::from(([127, 0, 0, 1], port)))
        .ok()?;
    let mut buffer = [0_u8; 4096];
    let len = socket.recv(&mut buffer).ok()?;
    let message = Message::decode(&buffer[..len], &DecodeLimits::default()).ok()?;
    (message.answers().len() == 1)
        .then(|| u64::try_from(started.elapsed().as_micros()).unwrap_or(0))
}

fn percentiles(mut values: Vec<u64>) -> (f64, f64) {
    if values.is_empty() {
        return (0.0, 0.0);
    }
    values.sort_unstable();
    let index = |percent: usize| {
        let position = values.len().saturating_mul(percent) / 100;
        let position = position.min(values.len() - 1);
        values[position] as f64
    };
    (index(50), index(99))
}

fn run_dns_load(port: u16, seconds: u64) -> Stats {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let barrier = Arc::new(Barrier::new(DNS_THREADS));
    let started = Instant::now();
    let latencies = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..DNS_THREADS)
            .map(|thread| {
                let barrier = Arc::clone(&barrier);
                scope.spawn(move || {
                    let socket = UdpSocket::bind("127.0.0.1:0").expect("udp client");
                    socket
                        .set_read_timeout(Some(Duration::from_millis(250)))
                        .expect("timeout");
                    let qname = format!("r{}.{}", thread % RECORDS, zone_origin(thread % ZONES));
                    let query = Message::query(
                        0x4321,
                        Question::new(Name::parse(&qname).expect("qname"), Rtype::A, Rclass::IN),
                    )
                    .encode(&EncodeOptions::compressed())
                    .expect("encode");
                    let mut buffer = [0_u8; 4096];
                    let mut latencies = Vec::new();
                    barrier.wait();
                    while Instant::now() < deadline {
                        let started = Instant::now();
                        if socket
                            .send_to(&query, SocketAddr::from(([127, 0, 0, 1], port)))
                            .is_err()
                        {
                            continue;
                        }
                        let Ok(len) = socket.recv(&mut buffer) else {
                            continue;
                        };
                        let Ok(message) = Message::decode(&buffer[..len], &DecodeLimits::default())
                        else {
                            continue;
                        };
                        if message.answers().len() == 1 {
                            latencies.push(
                                u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
                            );
                        }
                    }
                    latencies
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|handle| handle.join().unwrap_or_default())
            .collect::<Vec<_>>()
    });
    let elapsed = started.elapsed().as_secs_f64();
    let (p50_us, p99_us) = percentiles(latencies.clone());
    Stats {
        count: latencies.len(),
        seconds: elapsed,
        p50_us,
        p99_us,
    }
}

fn run_rest_load(api: SocketAddr, seconds: u64) -> Stats {
    // Один hot-RRset на поток: создаём, дальше обновляем под `If-Match: *`.
    let mut owners = Vec::with_capacity(REST_THREADS);
    for thread in 0..REST_THREADS {
        let origin = zone_origin(thread % ZONES);
        let owner = format!("u{thread}.{origin}");
        let body = format!(r#"{{"ttl":60,"records":["192.0.2.{}"]}}"#, thread + 1);
        let path = format!("/api/v1/zones/{origin}/records/{owner}/A");
        let (status, response) =
            http(api, "PUT", &path, &[], Some(&body)).expect("create hot rrset");
        assert_eq!(status, 201, "create hot rrset: {response}");
        owners.push(path);
    }
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let owners = Arc::new(owners);
    let barrier = Arc::new(Barrier::new(REST_THREADS));
    let started = Instant::now();
    let latencies = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..REST_THREADS)
            .map(|thread| {
                let owners = Arc::clone(&owners);
                let barrier = Arc::clone(&barrier);
                scope.spawn(move || {
                    let path = &owners[thread];
                    let mut latencies = Vec::new();
                    barrier.wait();
                    let mut value = thread + 1;
                    while Instant::now() < deadline {
                        value = value % 250 + 1;
                        let payload = format!(r#"{{"ttl":60,"records":["192.0.2.{value}"]}}"#);
                        let started = Instant::now();
                        let Some((status, _)) =
                            http(api, "PUT", path, &[("If-Match", "*")], Some(&payload))
                        else {
                            continue;
                        };
                        if (200..300).contains(&status) {
                            latencies.push(
                                u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
                            );
                        }
                    }
                    latencies
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|handle| handle.join().unwrap_or_default())
            .collect::<Vec<_>>()
    });
    let elapsed = started.elapsed().as_secs_f64();
    let (p50_us, p99_us) = percentiles(latencies.clone());
    Stats {
        count: latencies.len(),
        seconds: elapsed,
        p50_us,
        p99_us,
    }
}

fn run_scenario(label: &str, split: bool, seconds: u64, dir: &Path) -> (Stats, Stats) {
    let map_size = 512 * 1024 * 1024;
    let data = prepare_data(&pulsed_bin(), dir, label, map_size);
    let udp = free_udp_port();
    let tcp = reserved_tcp_addr();
    let api = reserved_tcp_addr();
    let mut guards = Vec::new();
    if split {
        let dns_config = config(Role::Dns, &data, Some(udp), Some(tcp), None, map_size);
        let api_config = config(Role::Api, &data, None, None, Some(api), map_size);
        guards.push(spawn(&write_config(
            dir,
            &format!("{label}-dns.toml"),
            &dns_config,
        )));
        guards.push(spawn(&write_config(
            dir,
            &format!("{label}-api.toml"),
            &api_config,
        )));
    } else {
        let all = config(Role::All, &data, Some(udp), Some(tcp), Some(api), map_size);
        guards.push(spawn(&write_config(
            dir,
            &format!("{label}-all.toml"),
            &all,
        )));
    }
    assert!(wait_ready(Some(api), Some(udp)), "{label}: not ready");

    let barrier = Arc::new(Barrier::new(2));
    let (dns, rest) = std::thread::scope(|scope| {
        let dns_barrier = Arc::clone(&barrier);
        let dns = scope.spawn(move || {
            dns_barrier.wait();
            run_dns_load(udp, seconds)
        });
        let rest_barrier = Arc::clone(&barrier);
        let rest = scope.spawn(move || {
            rest_barrier.wait();
            run_rest_load(api, seconds)
        });
        (
            dns.join().expect("dns load"),
            rest.join().expect("rest load"),
        )
    });
    drop(guards);
    (dns, rest)
}

fn main() {
    let mut seconds = 5_u64;
    let args: Vec<String> = std::env::args().collect();
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--seconds" | "-s" => {
                index += 1;
                seconds = args
                    .get(index)
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(seconds);
            }
            _ => {}
        }
        index += 1;
    }
    let dir = std::env::temp_dir().join(format!("pulse-role-bench-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("bench dir");
    println!(
        "role bench: {DNS_THREADS} DNS threads, {REST_THREADS} REST threads, {seconds}s per scenario"
    );
    for (label, split) in [("all", false), ("split", true)] {
        let (dns, rest) = run_scenario(label, split, seconds, &dir);
        println!(
            "{label:>5}: dns_qps={:>8.0} dns_p50={:>6.0}us dns_p99={:>7.0}us \
             rest_put_s={:>8.0} rest_p50={:>7.0}us rest_p99={:>8.0}us",
            dns.rate(),
            dns.p50_us,
            dns.p99_us,
            rest.rate(),
            rest.p50_us,
            rest.p99_us
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}
