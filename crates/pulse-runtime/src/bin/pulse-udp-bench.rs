//! Нагрузочная утилита: UDP echo-сервер на `pulse-runtime` + N клиентов.
//!
//! Замеряет qps и перцентили RTT по HDR-подобной гистограмме (латентности не
//! хранятся в `Vec`), с прогревом и медианой по нескольким прогонам. Проверяет
//! байты ответа (echo должен вернуть ровно отправленный payload).
//!
//! ```text
//! cargo run --release -p pulse-runtime --bin pulse-udp-bench -- \
//!     --workers 4 --clients 4 --window 16 --duration 5 --warmup 1 --runs 3
//! ```

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_lines
)]

use std::net::{SocketAddr, UdpSocket};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use pulse_runtime::{BackendPreference, Reply, RuntimeConfig, UdpServer};
use rustix::net::sockopt;

#[derive(Debug, Clone, Copy)]
struct Args {
    workers: usize,
    clients: usize,
    duration: Duration,
    warmup: Duration,
    runs: usize,
    payload: usize,
    window: usize,
    rx_buffer: usize,
    rx_buffers: Option<u16>,
    tx_slots: usize,
    cqe_batch: usize,
    stack_kb: usize,
    backend: BackendPreference,
    pin: bool,
    sqpoll: Option<u32>,
    sqpoll_cpu: Option<usize>,
    register_files: bool,
    coop: bool,
    busy_poll: Option<u16>,
    prefer_busy_poll: bool,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            workers: 4,
            clients: 4,
            duration: Duration::from_secs(5),
            warmup: Duration::from_secs(1),
            runs: 3,
            payload: 64,
            window: 1,
            rx_buffer: 4096,
            rx_buffers: None,
            tx_slots: 256,
            cqe_batch: 256,
            stack_kb: 512,
            backend: BackendPreference::Auto,
            pin: false,
            sqpoll: None,
            sqpoll_cpu: None,
            register_files: true,
            coop: false,
            busy_poll: None,
            prefer_busy_poll: false,
        }
    }
}

fn main() -> ExitCode {
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(Some(args)) => args,
        Ok(None) => {
            print_usage();
            return ExitCode::SUCCESS;
        }
        Err(message) => {
            eprintln!("error: {message}");
            print_usage();
            return ExitCode::FAILURE;
        }
    };
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn parse_args(mut argv: impl Iterator<Item = String>) -> Result<Option<Args>, String> {
    let mut args = Args::default();
    while let Some(flag) = argv.next() {
        let mut value = || {
            argv.next()
                .ok_or_else(|| format!("missing value for {flag}"))
        };
        match flag.as_str() {
            "-h" | "--help" => return Ok(None),
            "--workers" => args.workers = parse_usize(&value()?, &flag)?,
            "--clients" => args.clients = parse_usize(&value()?, &flag)?,
            "--duration" => {
                args.duration = Duration::from_secs(parse_usize(&value()?, &flag)? as u64);
            }
            "--warmup" => args.warmup = Duration::from_secs(parse_usize(&value()?, &flag)? as u64),
            "--runs" => args.runs = parse_usize(&value()?, &flag)?.max(1),
            "--payload" => args.payload = parse_usize(&value()?, &flag)?.max(9),
            "--window" => args.window = parse_usize(&value()?, &flag)?.max(1),
            "--rx-buffer" => args.rx_buffer = parse_usize(&value()?, &flag)?.max(512),
            "--rx-buffers" => {
                args.rx_buffers = Some(
                    u16::try_from(parse_usize(&value()?, &flag)?)
                        .map_err(|_| "rx-buffers out of range".to_string())?,
                );
            }
            "--tx-slots" => args.tx_slots = parse_usize(&value()?, &flag)?.max(8),
            "--cqe-batch" => args.cqe_batch = parse_usize(&value()?, &flag)?.max(1),
            "--stack-kb" => args.stack_kb = parse_usize(&value()?, &flag)?,
            "--pin" => args.pin = true,
            "--sqpoll" => {
                args.sqpoll = Some(
                    u32::try_from(parse_usize(&value()?, &flag)?)
                        .map_err(|_| "sqpoll idle out of range".to_string())?,
                );
            }
            "--sqpoll-cpu" => args.sqpoll_cpu = Some(parse_usize(&value()?, &flag)?),
            "--no-register-files" => args.register_files = false,
            "--coop" => args.coop = true,
            "--busy-poll" => {
                args.busy_poll = Some(
                    u16::try_from(parse_usize(&value()?, &flag)?)
                        .map_err(|_| "busy-poll out of range".to_string())?,
                );
            }
            "--prefer-busy-poll" => args.prefer_busy_poll = true,
            "--backend" => {
                args.backend = match value()?.as_str() {
                    "auto" => BackendPreference::Auto,
                    "uring" => BackendPreference::Uring,
                    "epoll" => BackendPreference::Epoll,
                    other => return Err(format!("unknown backend {other}")),
                };
            }
            other => return Err(format!("unknown flag {other}")),
        }
    }
    if args.workers == 0 || args.clients == 0 {
        return Err("workers and clients must be >= 1".into());
    }
    if args.payload > args.rx_buffer {
        return Err("payload must not exceed rx-buffer".into());
    }
    if args.duration.is_zero() {
        return Err("duration must be > 0".into());
    }
    Ok(Some(args))
}

fn parse_usize(text: &str, flag: &str) -> Result<usize, String> {
    text.parse()
        .map_err(|_| format!("invalid number for {flag}: {text}"))
}

fn print_usage() {
    println!(
        "pulse-udp-bench [options]\n\
         \n\
         --workers N     worker-потоков сервера (по умолчанию 4)\n\
         --clients N     клиентских потоков (по умолчанию 4)\n\
         --duration S    длительность замера в секундах (по умолчанию 5)\n\
         --warmup S      прогрев перед каждым прогоном (по умолчанию 1)\n\
         --runs N        число прогонов, печатается медиана (по умолчанию 3)\n\
         --payload N     размер запроса в байтах (по умолчанию 64)\n\
         --window N      запросов в полёте на клиента (по умолчанию 1)\n\
         --rx-buffer N   RX-буфер сервера в байтах (по умолчанию 4096)\n\
         --rx-buffers N  число provided-буферов на worker (по умолчанию 1024)\n\
         --tx-slots N    TX-слотов на worker (по умолчанию 256)\n\
         --cqe-batch N   максимум CQE за проход (по умолчанию 256)\n\
         --stack-kb N    стек worker-потока в КиБ (по умолчанию 512, 0 — ОС)\n\
         --pin           прибить worker'ов к разрешённым CPU\n\
         --sqpoll MS     включить SQPOLL с idle-таймаутом\n\
         --sqpoll-cpu N  CPU для SQ_AFF (по умолчанию авто)\n\
         --no-register-files  не регистрировать fd (IORING_REGISTER_FILES)\n\
         --coop          попытаться включить COOP_TASKRUN\n\
         --busy-poll US  SO_BUSY_POLL в микросекундах\n\
         --prefer-busy-poll   SO_PREFER_BUSY_POLL\n\
         --backend KIND  auto | uring | epoll (epoll требует feature epoll-fallback)"
    );
}

fn run(args: Args) -> Result<(), String> {
    let mut config = RuntimeConfig::default()
        .with_workers(args.workers)
        .with_backend(args.backend)
        .with_rx_buffer_size(args.rx_buffer)
        .with_tx(args.tx_slots, 4096.max(args.rx_buffer + 512))
        .with_socket_buffers(8 * 1024 * 1024, 8 * 1024 * 1024)
        .with_cqe_batch(args.cqe_batch)
        .with_thread_stack(args.stack_kb * 1024)
        .with_cpu_pinning(args.pin)
        .with_register_files(args.register_files)
        .with_coop_taskrun(args.coop)
        .with_sqpoll(args.sqpoll)
        .with_sqpoll_cpu(args.sqpoll_cpu);
    if let Some(buffers) = args.rx_buffers {
        config.rx_buffers = buffers;
    }
    if let Some(microseconds) = args.busy_poll {
        config = config.with_busy_poll(microseconds);
    }
    config = config.with_prefer_busy_poll(args.prefer_busy_poll);
    // Инвариант CQ: rx_buffers + tx_slots + 2 <= cq_entries.
    let needed = usize::from(config.rx_buffers) + config.tx_slots + 2;
    if needed > config.cq_entries as usize {
        config.cq_entries = (needed.next_power_of_two()).try_into().unwrap_or(u32::MAX);
    }

    let tuning = (config.rx_buffers, config.tx_slots, config.cqe_batch);
    let server = UdpServer::bind_with(
        "127.0.0.1:0".parse().expect("static address"),
        move |request: &[u8], _peer: SocketAddr, out: &mut [u8]| {
            let len = request.len().min(out.len());
            out[..len].copy_from_slice(&request[..len]);
            Reply::Send(len)
        },
        config,
    )
    .map_err(|err| format!("bind failed: {err}"))?;

    let addr = server.local_addr();
    let caps = server.capabilities();
    server
        .start()
        .map_err(|err| format!("server start failed: {err}"))?;

    println!("pulse-udp-bench");
    println!("  backend      : {}", caps.backend);
    println!(
        "  workers      : {} (multishot={}, provided_buffers={}, defer={}, coop={}, sqpoll={}, fixed_files={}, nodrop={})",
        server.workers(),
        caps.multishot_recv,
        caps.provided_buffers,
        caps.defer_taskrun,
        caps.coop_taskrun,
        caps.sqpoll,
        caps.registered_files,
        caps.nodrop
    );
    println!(
        "  tuning       : rx_buf={}B, rx_buffers={}, tx_slots={}, cqe_batch={}, stack={}KiB, pin={}, busy_poll={:?}",
        args.rx_buffer, tuning.0, tuning.1, tuning.2, args.stack_kb, args.pin, args.busy_poll
    );
    println!(
        "  clients      : {} (window {}, {} B payload)",
        args.clients, args.window, args.payload
    );
    println!(
        "  runs         : {} (warmup {:?}, measure {:?})",
        args.runs, args.warmup, args.duration
    );
    println!("  listen       : {addr}");

    let mut qps_samples = Vec::with_capacity(args.runs);
    let mut p99_samples = Vec::with_capacity(args.runs);
    let mut total_corrupt = 0_u64;

    for run_index in 1..=args.runs {
        let result = run_once(&args, addr)?;
        total_corrupt += result.corrupt;
        qps_samples.push(result.qps);
        p99_samples.push(result.p99_ns as f64);
        println!("\nrun {run_index}/{}", args.runs);
        println!(
            "  qps          : {:.0} ({} ответов / {} запросов, {} потеряно, {} corrupt)",
            result.qps, result.received, result.sent, result.lost, result.corrupt
        );
        println!("  rtt mean     : {:.2} us", result.mean_ns as f64 / 1000.0);
        println!("  rtt p50      : {:.2} us", result.p50_ns as f64 / 1000.0);
        println!("  rtt p99      : {:.2} us", result.p99_ns as f64 / 1000.0);
        println!("  rtt p999     : {:.2} us", result.p999_ns as f64 / 1000.0);
        println!("  rtt max      : {:.2} us", result.max_ns as f64 / 1000.0);
    }

    let shutdown_at = Instant::now();
    let stats = server.stats();
    server
        .shutdown()
        .map_err(|err| format!("shutdown: {err}"))?;
    let shutdown_time = shutdown_at.elapsed();

    let median_qps = median(&mut qps_samples);
    let median_p99 = median(&mut p99_samples);
    println!("\nmedian over {} runs", args.runs);
    println!("  qps          : {median_qps:.0}");
    println!("  rtt p99      : {:.2} us", median_p99 / 1000.0);
    println!("  corrupt      : {total_corrupt}");
    println!(
        "  server rx    : {} пакетов / {} байт",
        stats.total.packets_received, stats.total.bytes_received
    );
    println!(
        "  server tx    : {} пакетов / {} байт",
        stats.total.packets_sent, stats.total.bytes_sent
    );
    println!(
        "  server errs  : recv={}, send={}, oversize={}, dropped={}, tx_pressure={}, pbuf_starve={}, panics={}, cq_overflow={}",
        stats.total.recv_errors,
        stats.total.send_errors,
        stats.total.oversize_received,
        stats.total.responses_dropped,
        stats.total.tx_pressure,
        stats.total.pbuf_starve,
        stats.total.handler_panics,
        stats.total.cq_overflow_total
    );
    println!(
        "  shutdown     : {:.1} ms",
        shutdown_time.as_secs_f64() * 1000.0
    );
    let (user, sys) = process_cpu();
    println!("  process cpu  : user {user:.2} s, sys {sys:.2} s");
    println!(
        "  peak rss/vm  : {} / {} KiB",
        process_peak_rss_kib(),
        process_peak_vm_kib()
    );
    if total_corrupt > 0 {
        return Err(format!("{total_corrupt} corrupted response(s)"));
    }
    Ok(())
}

/// CPU-время процесса (все потоки) из `/proc/self/stat` в секундах.
///
/// Linux `USER_HZ` для `x86_64` зафиксирован ABI и равен 100.
fn process_cpu() -> (f64, f64) {
    const USER_HZ: f64 = 100.0;
    let Ok(stat) = std::fs::read_to_string("/proc/self/stat") else {
        return (0.0, 0.0);
    };
    let Some(rest) = stat.rfind(')').map(|end| &stat[end + 1..]) else {
        return (0.0, 0.0);
    };
    let ticks: Vec<u64> = rest
        .split_whitespace()
        .skip(11)
        .take(2)
        .filter_map(|value| value.parse().ok())
        .collect();
    if ticks.len() < 2 {
        return (0.0, 0.0);
    }
    (ticks[0] as f64 / USER_HZ, ticks[1] as f64 / USER_HZ)
}

fn process_peak_rss_kib() -> u64 {
    process_status_kib("VmHWM:")
}

fn process_peak_vm_kib() -> u64 {
    process_status_kib("VmPeak:")
}

fn process_status_kib(field: &str) -> u64 {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return 0;
    };
    status
        .lines()
        .find_map(|line| line.strip_prefix(field))
        .and_then(|value| value.split_whitespace().next())
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

struct RunResult {
    sent: u64,
    received: u64,
    lost: u64,
    corrupt: u64,
    qps: f64,
    mean_ns: u64,
    p50_ns: u64,
    p99_ns: u64,
    p999_ns: u64,
    max_ns: u64,
}

fn run_once(args: &Args, addr: SocketAddr) -> Result<RunResult, String> {
    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(args.clients + 1));
    let measure_at = Instant::now() + args.warmup;
    let mut handles = Vec::with_capacity(args.clients);
    for index in 0..args.clients {
        let stop = Arc::clone(&stop);
        let barrier = Arc::clone(&barrier);
        let payload = args.payload;
        let window = args.window;
        let handle = thread::Builder::new()
            .name(format!("pulse-bench-client-{index}"))
            .spawn(move || client(addr, payload, window, measure_at, &stop, &barrier))
            .map_err(|err| format!("spawn client: {err}"))?;
        handles.push(handle);
    }

    barrier.wait();
    thread::sleep(args.warmup + args.duration);
    stop.store(true, Ordering::Relaxed);
    let elapsed = Instant::now().saturating_duration_since(measure_at);
    let elapsed = elapsed.max(Duration::from_millis(1));

    let mut sent = 0_u64;
    let mut received = 0_u64;
    let mut lost = 0_u64;
    let mut corrupt = 0_u64;
    let mut histogram = Histogram::new();
    for handle in handles {
        let result = handle.join().map_err(|_| "client panicked".to_string())?;
        sent += result.sent;
        received += result.received;
        lost += result.lost;
        corrupt += result.corrupt;
        histogram.merge(&result.histogram);
    }

    Ok(RunResult {
        sent,
        received,
        lost,
        corrupt,
        qps: received as f64 / elapsed.as_secs_f64(),
        mean_ns: histogram.mean(),
        p50_ns: histogram.percentile(0.50),
        p99_ns: histogram.percentile(0.99),
        p999_ns: histogram.percentile(0.999),
        max_ns: histogram.max(),
    })
}

fn median(samples: &mut [f64]) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    samples[samples.len() / 2]
}

struct ClientResult {
    sent: u64,
    received: u64,
    lost: u64,
    corrupt: u64,
    histogram: Histogram,
}

fn client(
    addr: SocketAddr,
    payload: usize,
    window: usize,
    measure_at: Instant,
    stop: &AtomicBool,
    barrier: &Barrier,
) -> ClientResult {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("client bind");
    socket.connect(addr).expect("client connect");
    socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .expect("read timeout");
    let _ = sockopt::set_socket_recv_buffer_size(&socket, 4 * 1024 * 1024);
    let _ = sockopt::set_socket_send_buffer_size(&socket, 4 * 1024 * 1024);

    let mut request = vec![0_u8; payload];
    let mut response = vec![0_u8; payload.max(512)];
    let mut sent = 0_u64;
    let mut received = 0_u64;
    let mut lost = 0_u64;
    let mut corrupt = 0_u64;
    let mut histogram = Histogram::new();
    // `(время отправки, засчитывать ли в измерение)` по номеру запроса.
    let mut in_flight: Vec<Option<(Instant, bool)>> = vec![None; window];
    let mut outstanding = 0_usize;

    barrier.wait();
    let mut next_seq = 0_u64;
    while !stop.load(Ordering::Relaxed) {
        while outstanding < window && !stop.load(Ordering::Relaxed) {
            let seq = next_seq;
            fill_request(&mut request, seq);
            let slot = (seq % window as u64) as usize;
            let sent_at = Instant::now();
            match socket.send(&request) {
                Ok(_) => {
                    let measuring = sent_at >= measure_at;
                    if measuring {
                        sent += 1;
                    }
                    next_seq += 1;
                    in_flight[slot] = Some((sent_at, measuring));
                    outstanding += 1;
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    std::hint::spin_loop();
                }
                Err(err) => panic!("send failed: {err}"),
            }
        }
        if outstanding == 0 {
            continue;
        }
        match socket.recv(&mut response) {
            Ok(len) => {
                let Some(seq) = parse_seq(&response[..len]) else {
                    corrupt += 1;
                    continue;
                };
                let slot = (seq % window as u64) as usize;
                if let Some((sent_at, measuring)) = in_flight[slot].take() {
                    outstanding -= 1;
                    if !verify_response(&response[..len], seq, payload) {
                        corrupt += 1;
                    }
                    if measuring {
                        received += 1;
                        histogram.record(sent_at.elapsed().as_nanos() as u64);
                    }
                }
            }
            Err(err)
                if err.kind() == std::io::ErrorKind::WouldBlock
                    || err.kind() == std::io::ErrorKind::TimedOut =>
            {
                for entry in &mut in_flight {
                    if let Some((_, measuring)) = entry.take()
                        && measuring
                    {
                        lost += 1;
                    }
                }
                outstanding = 0;
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => panic!("recv failed: {err}"),
        }
    }

    socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .expect("read timeout");
    while outstanding > 0 {
        if let Ok(len) = socket.recv(&mut response) {
            if let Some(seq) = parse_seq(&response[..len]) {
                let slot = (seq % window as u64) as usize;
                if let Some((sent_at, measuring)) = in_flight[slot].take() {
                    outstanding -= 1;
                    if !verify_response(&response[..len], seq, payload) {
                        corrupt += 1;
                    }
                    if measuring {
                        received += 1;
                        histogram.record(sent_at.elapsed().as_nanos() as u64);
                    }
                }
            }
        } else {
            for entry in &mut in_flight {
                if let Some((_, measuring)) = entry.take()
                    && measuring
                {
                    lost += 1;
                }
            }
            outstanding = 0;
        }
    }

    ClientResult {
        sent,
        received,
        lost,
        corrupt,
        histogram,
    }
}

fn fill_request(buf: &mut [u8], seq: u64) {
    buf[..8].copy_from_slice(&seq.to_be_bytes());
    for (offset, byte) in buf.iter_mut().enumerate().skip(8) {
        *byte = payload_byte(seq, offset);
    }
}

fn parse_seq(response: &[u8]) -> Option<u64> {
    let raw: [u8; 8] = response.get(..8)?.try_into().ok()?;
    Some(u64::from_be_bytes(raw))
}

fn verify_response(response: &[u8], seq: u64, payload: usize) -> bool {
    if response.len() != payload {
        return false;
    }
    if parse_seq(response) != Some(seq) {
        return false;
    }
    response
        .iter()
        .enumerate()
        .skip(8)
        .all(|(offset, byte)| *byte == payload_byte(seq, offset))
}

fn payload_byte(seq: u64, offset: usize) -> u8 {
    (seq as u8) ^ (offset as u8)
}

/// HDR-подобная гистограмма: фиксированные бакеты, без хранения всех замеров.
struct Histogram {
    bounds: Vec<u64>,
    counts: Vec<u64>,
    overflow: u64,
    total: u64,
    sum: u128,
    max: u64,
}

impl Histogram {
    fn new() -> Self {
        let mut bounds = Vec::new();
        for value in (1_000..=200_000).step_by(1_000) {
            bounds.push(value);
        }
        for value in (210_000..=2_000_000).step_by(10_000) {
            bounds.push(value);
        }
        for value in (2_100_000..=20_000_000).step_by(100_000) {
            bounds.push(value);
        }
        for value in (21_000_000..=2_000_000_000).step_by(1_000_000) {
            bounds.push(value);
        }
        let counts = vec![0_u64; bounds.len()];
        Self {
            bounds,
            counts,
            overflow: 0,
            total: 0,
            sum: 0,
            max: 0,
        }
    }

    fn record(&mut self, nanos: u64) {
        let index = self.bounds.partition_point(|&bound| bound < nanos);
        if index < self.counts.len() {
            self.counts[index] += 1;
        } else {
            self.overflow += 1;
        }
        self.total += 1;
        self.sum += u128::from(nanos);
        self.max = self.max.max(nanos);
    }

    fn merge(&mut self, other: &Self) {
        debug_assert_eq!(self.bounds.len(), other.bounds.len());
        for (mine, theirs) in self.counts.iter_mut().zip(&other.counts) {
            *mine += *theirs;
        }
        self.overflow += other.overflow;
        self.total += other.total;
        self.sum += other.sum;
        self.max = self.max.max(other.max);
    }

    fn mean(&self) -> u64 {
        if self.total == 0 {
            0
        } else {
            u64::try_from(self.sum / u128::from(self.total)).unwrap_or(u64::MAX)
        }
    }

    fn percentile(&self, percentile: f64) -> u64 {
        if self.total == 0 {
            return 0;
        }
        let rank = ((self.total as f64 - 1.0) * percentile).round() as u64;
        let mut seen = 0_u64;
        for (index, &count) in self.counts.iter().enumerate() {
            seen += count;
            if seen > rank {
                return self.bounds[index];
            }
        }
        self.max
    }

    fn max(&self) -> u64 {
        self.max
    }
}
