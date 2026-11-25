//! `pulse-loadgen` — клиент нагрузки для `pulsed`.
//!
//! Примеры:
//!
//! ```text
//! pulse-loadgen --server 127.0.0.1:5353 --mode udp --threads 8 --qps 50000 \
//!               --duration 10 --warmup 3 --mix a=40,aaaa=20,mx=15,txt=10,nx=15 \
//!               --zones 8 --rrsets-per-zone 1000 --json-out run.json
//! pulse-loadgen --server 127.0.0.1:5353 --mode udp --threads 4 --window 32 --duration 10
//! pulse-loadgen --server 127.0.0.1:853 --mode dot --ca target/bench/cert.pem --threads 8
//! pulse-loadgen --server 127.0.0.1:8443 --mode doh-h2 --ca target/bench/cert.pem --threads 8
//! ```

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use pulse_loadgen::mix::Mix;
use pulse_loadgen::rest::RestConfig;
use pulse_loadgen::{ClientConfig, Mode};

#[derive(Debug, Parser)]
#[command(
    name = "pulse-loadgen",
    version,
    about = "DNS load generator with HDR latency and drop accounting"
)]
struct Args {
    /// Адрес сервера (UDP/TCP/DoT/DoH h2 listener).
    #[arg(long)]
    server: SocketAddr,
    /// Транспорт.
    #[arg(long, value_enum, default_value = "udp")]
    mode: ModeArg,
    /// Потоков-клиентов (соединений для DoH/DoT).
    #[arg(long, default_value_t = 4)]
    threads: usize,
    /// Целевая ставка, запросов/с; 0 или отсутствие — closed-loop.
    #[arg(long)]
    qps: Option<f64>,
    /// Окно in-flight (closed-loop).
    #[arg(long, default_value_t = 16)]
    window: usize,
    /// Длительность измерения, с.
    #[arg(long, default_value_t = 10.0)]
    duration: f64,
    /// Прогрев, с.
    #[arg(long, default_value_t = 3.0)]
    warmup: f64,
    /// Таймаут ответа, мс.
    #[arg(long, default_value_t = 1000)]
    timeout_ms: u64,
    /// Профиль `a=40,aaaa=20,mx=15,txt=10,nx=15`.
    #[arg(long, default_value = "a=40,aaaa=20,mx=15,txt=10,nx=15")]
    mix: String,
    /// Число зон в стенде (имена `z{0..zones}.bench.test.`).
    #[arg(long, default_value_t = 1)]
    zones: u32,
    /// `RRset` на зону.
    #[arg(long, default_value_t = 1000)]
    rrsets_per_zone: u32,
    /// Seed детерминированного потока.
    #[arg(long, default_value_t = 0x5eed_1234_abcd_0001)]
    seed: u64,
    /// Размер рабочего набора пакетов на поток.
    #[arg(long, default_value_t = 16384)]
    working_set: usize,
    /// CA в PEM для DoT/DoH (self-signed).
    #[arg(long)]
    ca: Option<PathBuf>,
    /// SNI/имя сертификата.
    #[arg(long, default_value = "localhost")]
    server_name: String,
    /// `DoH` path.
    #[arg(long, default_value = "/dns-query")]
    doh_path: String,
    /// Полная валидация каждой N-й выборки; 0 — выключить.
    #[arg(long, default_value_t = 64)]
    validate_every: u32,
    /// Максимум in-flight для open-loop.
    #[arg(long, default_value_t = 8192)]
    max_inflight: usize,
    /// REST API для параллельной записи.
    #[arg(long)]
    rest_api: Option<SocketAddr>,
    /// Bearer token для REST.
    #[arg(long, default_value = "pd_bench_token")]
    rest_token: String,
    /// Число зон для REST-записей.
    #[arg(long, default_value_t = 8)]
    rest_zones: u32,
    /// Потоков REST-писателей.
    #[arg(long, default_value_t = 8)]
    rest_threads: usize,
    /// Суммарная ставка REST, записей/с.
    #[arg(long, default_value_t = 80.0)]
    rest_rate: f64,
    /// JSON-файл результата.
    #[arg(long)]
    json_out: Option<PathBuf>,
    /// CPU клиентских потоков (например `1,3,5,7`). Проверяется против
    /// `sched_getaffinity`; потоки пиннятся round-robin.
    #[arg(long)]
    client_cpus: Option<String>,
    /// CPU серверного процесса (информационно: `pulse-loadgen` не запускает
    /// сервер; для пиннинга сервера используйте `pulse-bench --server-cpus`).
    #[arg(long)]
    server_cpus: Option<String>,
    /// CPU REST-писателей; по умолчанию — вторая половина `--client-cpus`.
    #[arg(long)]
    rest_cpus: Option<String>,
    /// Добавлять EDNS0 DO в запросы (ответы DNSSEC-подписанной зоны).
    #[arg(long)]
    dnssec_do: bool,
    /// Не печатать human-таблицу.
    #[arg(long)]
    quiet: bool,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum ModeArg {
    Udp,
    Tcp,
    Dot,
    #[value(name = "doh-h2")]
    DohH2,
}

impl From<ModeArg> for Mode {
    fn from(value: ModeArg) -> Self {
        match value {
            ModeArg::Udp => Self::Udp,
            ModeArg::Tcp => Self::Tcp,
            ModeArg::Dot => Self::Dot,
            ModeArg::DohH2 => Self::DohH2,
        }
    }
}

#[allow(clippy::too_many_lines)]
fn main() -> Result<(), String> {
    let args = Args::parse();
    if args.server_cpus.is_some() {
        eprintln!(
            "pulse-loadgen: --server-cpus не применяется этим бинарником \
             (сервер не запускается); используйте pulse-bench --server-cpus"
        );
    }
    let allowed = pulse_loadgen::affinity::allowed_cpus()?;
    let client_cpus = args
        .client_cpus
        .as_deref()
        .map(pulse_loadgen::affinity::CpuSet::parse)
        .transpose()?;
    if let Some(cpus) = &client_cpus {
        for cpu in cpus.cpus() {
            if !allowed.contains(*cpu) {
                return Err(format!(
                    "--client-cpus: CPU {cpu} вне allowed {}",
                    allowed.as_list()
                ));
            }
        }
    }
    if let Some(rest) = &args.rest_cpus {
        for cpu in pulse_loadgen::affinity::CpuSet::parse(rest)?.cpus() {
            if !allowed.contains(*cpu) {
                return Err(format!(
                    "--rest-cpus: CPU {cpu} вне allowed {}",
                    allowed.as_list()
                ));
            }
        }
    }
    let (dns_cpus, rest_cpus) = match (&client_cpus, &args.rest_cpus) {
        (Some(set), Some(rest)) => (
            Some(set.cpus().to_vec()),
            Some(
                pulse_loadgen::affinity::CpuSet::parse(rest)?
                    .cpus()
                    .to_vec(),
            ),
        ),
        (Some(set), None) => {
            let (dns, rest) = set.split_at_half();
            (
                Some(dns.cpus().to_vec()),
                (!rest.is_empty()).then(|| rest.cpus().to_vec()),
            )
        }
        (None, Some(rest)) => (
            None,
            Some(
                pulse_loadgen::affinity::CpuSet::parse(rest)?
                    .cpus()
                    .to_vec(),
            ),
        ),
        (None, None) => (None, None),
    };
    let mix = Mix::parse(&args.mix)?;
    let mode: Mode = args.mode.into();
    let qps = args.qps.filter(|qps| *qps > 0.0);
    let rest = args.rest_api.map(|api| RestConfig {
        api,
        token: args.rest_token.clone(),
        zones: args.rest_zones,
        threads: args.rest_threads,
        rate: args.rest_rate,
        timeout: Duration::from_secs(5),
        tag: String::new(),
        cpus: rest_cpus,
    });
    let config = ClientConfig {
        target: args.server,
        mode,
        threads: args.threads,
        qps,
        window: args.window,
        duration: Duration::from_secs_f64(args.duration.max(0.1)),
        warmup: Duration::from_secs_f64(args.warmup.max(0.0)),
        timeout: Duration::from_millis(args.timeout_ms.max(1)),
        mix,
        zones: args.zones.max(1),
        rrsets_per_zone: args.rrsets_per_zone.max(4),
        seed: args.seed,
        working_set: args.working_set,
        ca: args.ca,
        server_name: args.server_name,
        doh_path: args.doh_path,
        validate_every: args.validate_every,
        rest,
        max_inflight: args.max_inflight,
        cpus: dns_cpus,
        edns_do: args.dnssec_do,
    };
    let result = match mode {
        Mode::Udp => pulse_loadgen::udp::run(&config)?,
        Mode::Tcp => pulse_loadgen::stream::run_tcp(&config)?,
        Mode::Dot => pulse_loadgen::stream::run_dot(&config)?,
        Mode::DohH2 => pulse_loadgen::doh::run(&config)?,
    };
    if let Some(path) = &args.json_out {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let json = serde_json::to_string_pretty(&result).map_err(|error| error.to_string())?;
        std::fs::write(path, json).map_err(|error| error.to_string())?;
    }
    if !args.quiet {
        print_human(&result);
    }
    Ok(())
}

fn print_human(result: &pulse_loadgen::RunResult) {
    let latency = &result.latency;
    println!(
        "{}: threads={} qps_target={} sent={} recv={} timeout={} errors={} invalid={} suppressed={}",
        result.mode.as_str(),
        result.threads,
        result
            .qps_target
            .map_or_else(|| "closed".to_owned(), |qps| format!("{qps:.0}")),
        result.sent,
        result.received,
        result.timeouts,
        result.errors,
        result.invalid,
        result.suppressed
    );
    println!(
        "client_qps={:.0}  p50={:.2}us p90={:.2}us p99={:.2}us p999={:.2}us max={:.2}us mean={:.2}us",
        result.client_qps,
        latency.p50 as f64 / 1000.0,
        latency.p90 as f64 / 1000.0,
        latency.p99 as f64 / 1000.0,
        latency.p999 as f64 / 1000.0,
        latency.max as f64 / 1000.0,
        latency.mean / 1000.0
    );
    println!(
        "kernel: rcvbuf_errors Δ={} in_errors Δ={} in_datagrams Δ={} out_datagrams Δ={}",
        result.kernel.rcvbuf_errors(),
        result.kernel.in_errors(),
        result.kernel.in_datagrams(),
        result.kernel.out_datagrams()
    );
    for (class, stats) in &result.classes {
        println!(
            "  {class:<9} sent={:<8} recv={:<8} p50={:.2}us p99={:.2}us",
            stats.sent,
            stats.received,
            latency_from_hist_value(stats.latency.p50),
            latency_from_hist_value(stats.latency.p99)
        );
    }
    if let Some(rest) = &result.rest {
        println!(
            "rest: requests={} acked={} errors={} qps={:.1} p50={:.2}ms p99={:.2}ms",
            rest.requests,
            rest.acked,
            rest.errors,
            rest.qps,
            rest.latency_us.p50 as f64 / 1000.0,
            rest.latency_us.p99 as f64 / 1000.0
        );
    }
}

fn latency_from_hist_value(ns: u64) -> f64 {
    ns as f64 / 1000.0
}
