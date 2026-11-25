//! `pulse-bench` — воспроизводимый baseline: генерация зон, запуск `pulsed`,
//! нагрузка (UDP/TCP/DoT/DoH h2/REST), память, `perf`, отчёт.
//!
//! ```text
//! cargo build --release -p pulsed -p pulse-loadgen
//! target/release/pulse-bench --quick          # smoke, ~1–2 мин
//! target/release/pulse-bench                  # полный baseline (включая soak 10 мин)
//! ```
//!
//! Скрипт не меняет production-код и не трогает git; все артефакты — в
//! `target/bench`, отчёты — в `docs/bench`.

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]

use std::fmt::Write as _;
use std::fs::File;
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use clap::Parser;
use pulse_dns::{EncodeOptions, Message, Name, Question, Rclass, Rtype};
use pulse_loadgen::mix::Mix;
use pulse_loadgen::report::{
    self, AllocRow, BaselineReport, ExtraSection, Hotspot, PerfReport, Scenario, ServerStats,
};
use pulse_loadgen::storegen::{self, GenSpec};
use pulse_loadgen::{ClientConfig, Mode, mem, sysinfo};

#[derive(Debug, Parser)]
#[command(
    name = "pulse-bench",
    version,
    about = "Reproducible pulsed baseline: load, memory, perf"
)]
#[allow(clippy::struct_excessive_bools)]
struct Args {
    /// Путь к release-бинарнику pulsed.
    #[arg(long, default_value = "target/release/pulsed")]
    pulsed: PathBuf,
    /// Каталог артефактов.
    #[arg(long, default_value = "target/bench")]
    out_dir: PathBuf,
    /// Markdown-отчёт (по умолчанию `docs/bench/baseline.md`
    /// или `docs/bench/isolated.md` для `--isolated`).
    #[arg(long)]
    report: Option<PathBuf>,
    /// JSON-отчёт (по умолчанию `docs/bench/baseline.json`
    /// или `docs/bench/isolated.json` для `--isolated`).
    #[arg(long)]
    json: Option<PathBuf>,
    /// Изолированный стенд: сервер и клиент на разных CPU, сценарии `iso-*`
    /// и контрольные `shared-*` на общем наборе.
    #[arg(long)]
    isolated: bool,
    /// CPU серверного процесса (например `0-3`); применяется через `taskset`.
    #[arg(long)]
    server_cpus: Option<String>,
    /// CPU клиентских потоков (например `4-7`); `sched_setaffinity`.
    #[arg(long)]
    client_cpus: Option<String>,
    /// CPU REST-писателей; по умолчанию — вторая половина клиентского набора.
    #[arg(long)]
    rest_cpus: Option<String>,
    /// Авто-раскладка по SMT-группам (целые физические ядра на сторону).
    #[arg(long)]
    auto_layout: bool,
    /// Не запускать контрольные `shared-*` сценарии в isolated-режиме.
    #[arg(long)]
    no_shared_controls: bool,
    /// `perf stat`/`perf record` для каждого isolated-сценария.
    #[arg(long)]
    perf_scenarios: bool,
    /// Короткий smoke-прогон (1 rep, 2 c, без 1M/soak/perf).
    #[arg(long)]
    quick: bool,
    /// Повторов на сценарий (медиана).
    #[arg(long, default_value_t = 3)]
    reps: usize,
    /// Длительность измерения, с.
    #[arg(long, default_value_t = 10.0)]
    duration: f64,
    /// Soak, с.
    #[arg(long, default_value_t = 600.0)]
    soak_secs: f64,
    /// Не генерировать store заново, если файл уже есть.
    #[arg(long)]
    reuse: bool,
    /// Пропустить memory-сценарии.
    #[arg(long)]
    skip_memory: bool,
    /// Пропустить perf.
    #[arg(long)]
    skip_profile: bool,
    /// Пропустить soak.
    #[arg(long)]
    skip_soak: bool,
    /// Пропустить сравнение commit-режимов (`pulsed --bench zone_writes`).
    #[arg(long)]
    skip_commit: bool,
    /// Выполнить только сценарии, чьё имя содержит подстроку.
    #[arg(long)]
    only: Option<String>,
    /// Дополнить существующий JSON (заменить сценарии с теми же именами),
    /// не перезапуская memory/soak/perf/commit.
    #[arg(long)]
    merge: bool,
    /// Перечитать JSON, пересчитать memory-сводки и перерендерить Markdown.
    #[arg(long)]
    render_only: bool,
}

#[derive(Debug, Clone, Copy)]
struct StoreSpec {
    name: &'static str,
    zones: u32,
    rrsets_per_zone: u32,
}

const STORE_1K: StoreSpec = StoreSpec {
    name: "z1k",
    zones: 1,
    rrsets_per_zone: 1_000,
};
const STORE_8: StoreSpec = StoreSpec {
    name: "z8",
    zones: 8,
    rrsets_per_zone: 1_000,
};
const STORE_100K: StoreSpec = StoreSpec {
    name: "z100k",
    zones: 1,
    rrsets_per_zone: 100_000,
};
const STORE_100: StoreSpec = StoreSpec {
    name: "z100",
    zones: 100,
    rrsets_per_zone: 1_000,
};
const STORE_1000: StoreSpec = StoreSpec {
    // v2 deadlock'ает на zone_seq=256 (lease-шард каталога); безопасный
    // максимум — 255 зон. Ось «число зон» фиксирует суммарные ~100k RRset.
    name: "z255",
    zones: 255,
    rrsets_per_zone: 392,
};
const STORE_1M: StoreSpec = StoreSpec {
    name: "z1m",
    zones: 1,
    rrsets_per_zone: 1_000_000,
};

struct StoreFiles {
    spec: StoreSpec,
    path: PathBuf,
    rrsets: u64,
    gen_ms: u64,
    file_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transport {
    Udp,
    Tcp,
    Dot,
    DohH2,
}

impl Transport {
    fn mode(self) -> Mode {
        match self {
            Self::Udp => Mode::Udp,
            Self::Tcp => Mode::Tcp,
            Self::Dot => Mode::Dot,
            Self::DohH2 => Mode::DohH2,
        }
    }
}

#[derive(Clone)]
struct ScenarioDef {
    name: &'static str,
    description: &'static str,
    store: StoreSpec,
    transport: Transport,
    workers: usize,
    threads: usize,
    qps: Option<f64>,
    window: usize,
    mix: Mix,
    rest: bool,
    working_set: usize,
    duration: Option<f64>,
    reps: Option<usize>,
    notes: Vec<&'static str>,
}

impl ScenarioDef {
    /// Сценарий с пиннингом CPU (isolated-стенд).
    fn affinity(&self) -> bool {
        self.name.starts_with("iso-")
    }

    /// Запросы с EDNS0 DO (DNSSEC-сценарий).
    fn edns_do(&self) -> bool {
        self.name.contains("signed")
    }
}

#[allow(clippy::too_many_lines)]
fn scenarios(quick: bool) -> Vec<ScenarioDef> {
    let mut list = vec![
        ScenarioDef {
            name: "udp-w1",
            description: "UDP, 1 worker, open-loop 10k qps, mix A/AAAA/MX/TXT/NXDOMAIN.",
            store: STORE_100K,
            transport: Transport::Udp,
            workers: 1,
            threads: 1,
            qps: Some(10_000.0),
            window: 1,
            mix: Mix::default(),
            rest: false,
            working_set: 16_384,
            duration: None,
            reps: None,
            notes: vec!["Open-loop: ставка задаётся клиентом; `suppressed > 0` — клиент не успел."],
        },
        ScenarioDef {
            name: "udp-w4",
            description: "UDP, 4 worker'а, open-loop 10k qps.",
            store: STORE_100K,
            transport: Transport::Udp,
            workers: 4,
            threads: 4,
            qps: Some(10_000.0),
            window: 1,
            mix: Mix::default(),
            rest: false,
            working_set: 16_384,
            duration: None,
            reps: None,
            notes: vec![],
        },
        ScenarioDef {
            name: "udp-w8",
            description: "UDP, 8 worker'ов, open-loop 10k qps.",
            store: STORE_100K,
            transport: Transport::Udp,
            workers: 8,
            threads: 8,
            qps: Some(10_000.0),
            window: 1,
            mix: Mix::default(),
            rest: false,
            working_set: 16_384,
            duration: None,
            reps: None,
            notes: vec![],
        },
        ScenarioDef {
            name: "udp-closed-w8",
            description: "UDP, 8 worker'ов, closed-loop окно 64: максимум qps на loopback.",
            store: STORE_100K,
            transport: Transport::Udp,
            workers: 8,
            threads: 8,
            qps: None,
            window: 64,
            mix: Mix::default(),
            rest: false,
            working_set: 16_384,
            duration: None,
            reps: None,
            notes: vec!["Closed-loop окно 64: латентность включает очередь в сокете клиента."],
        },
        ScenarioDef {
            name: "udp-nx-w8",
            description: "UDP, 8 worker'ов, 100% NXDOMAIN (худший путь перебора суффиксов).",
            store: STORE_100K,
            transport: Transport::Udp,
            workers: 8,
            threads: 8,
            qps: Some(10_000.0),
            window: 1,
            mix: Mix::parse("a=0,aaaa=0,mx=0,txt=0,nx=100").expect("mix"),
            rest: false,
            working_set: 16_384,
            duration: None,
            reps: None,
            notes: vec![],
        },
        ScenarioDef {
            name: "tcp-w8",
            description: "TCP, 8 соединений, closed-loop окно 16 (length-prefix).",
            store: STORE_100K,
            transport: Transport::Tcp,
            workers: 8,
            threads: 8,
            qps: None,
            window: 16,
            mix: Mix::default(),
            rest: false,
            working_set: 16_384,
            duration: None,
            reps: None,
            notes: vec![
                "TCP закрывает соединение по idle timeout 5 с; reconnect считается ошибкой.",
            ],
        },
        ScenarioDef {
            name: "dot-w8",
            description: "DoT, 8 соединений, closed-loop (rustls, keep-alive pool).",
            store: STORE_100K,
            transport: Transport::Dot,
            workers: 8,
            threads: 8,
            qps: None,
            window: 1,
            mix: Mix::default(),
            rest: false,
            working_set: 16_384,
            duration: None,
            reps: None,
            notes: vec![
                "DoT: латентность включает TLS-запись/чтение и аллокацию ответа в клиенте.",
            ],
        },
        ScenarioDef {
            name: "doh-h2-w8",
            description: "DoH/HTTP/2, 8 соединений × окно 16 stream'ов, closed-loop.",
            store: STORE_100K,
            transport: Transport::DohH2,
            workers: 8,
            threads: 8,
            qps: None,
            window: 16,
            mix: Mix::default(),
            rest: false,
            working_set: 16_384,
            duration: None,
            reps: None,
            notes: vec!["DoH h2: TLS+h2 handshake на соединение; ответ — HTTP body."],
        },
        ScenarioDef {
            name: "udp-rest-8z",
            description: "UDP 10k qps + REST PUT в 8 зон (80 записей/с, 8 writer'ов).",
            store: STORE_8,
            transport: Transport::Udp,
            workers: 8,
            threads: 8,
            qps: Some(10_000.0),
            window: 1,
            mix: Mix::default(),
            rest: true,
            working_set: 4_096,
            duration: None,
            reps: None,
            notes: vec!["REST-запись идёт параллельно измерению; серверный qps — только DNS."],
        },
    ];
    if quick {
        list.retain(|scenario| matches!(scenario.name, "udp-w1" | "udp-w8" | "udp-rest-8z"));
        for scenario in &mut list {
            scenario.duration = Some(2.0);
            scenario.reps = Some(1);
        }
    }
    list
}

/// Сценарии изолированного стенда: сервер на `--server-cpus`, клиент на
/// `--client-cpus`; плюс контрольные `shared-*` копии без пиннинга.
#[allow(clippy::too_many_lines)]
fn isolated_scenarios() -> Vec<ScenarioDef> {
    let a_only = Mix::parse("a=100,aaaa=0,mx=0,txt=0,nx=0").expect("mix a=100");
    let nx_only = Mix::parse("a=0,aaaa=0,mx=0,txt=0,nx=100").expect("mix nx=100");
    vec![
        ScenarioDef {
            name: "iso-udp-a",
            description: "UDP, A-only, closed-loop окно 64: лучший путь (positive hit).",
            store: STORE_100K,
            transport: Transport::Udp,
            workers: 4,
            threads: 8,
            qps: None,
            window: 64,
            mix: a_only,
            rest: false,
            working_set: 16_384,
            duration: Some(5.0),
            reps: Some(3),
            notes: vec!["Сервер/клиент на разных физических ядрах (см. раздел «CPU-раскладка»)."],
        },
        ScenarioDef {
            name: "iso-udp-mix",
            description: "UDP, mix A/AAAA/MX/TXT/NXDOMAIN, closed-loop окно 64.",
            store: STORE_100K,
            transport: Transport::Udp,
            workers: 4,
            threads: 8,
            qps: None,
            window: 64,
            mix: Mix::default(),
            rest: false,
            working_set: 16_384,
            duration: Some(5.0),
            reps: Some(3),
            notes: vec![],
        },
        ScenarioDef {
            name: "iso-udp-nx",
            description: "UDP, 100% NXDOMAIN, closed-loop окно 64: худший путь перебора суффиксов.",
            store: STORE_100K,
            transport: Transport::Udp,
            workers: 4,
            threads: 8,
            qps: None,
            window: 64,
            mix: nx_only,
            rest: false,
            working_set: 16_384,
            duration: Some(5.0),
            reps: Some(3),
            notes: vec![],
        },
        ScenarioDef {
            name: "iso-udp-signed",
            description: "UDP, DNSSEC-подписанная зона (EDNS DO=1), mix, closed-loop окно 64.",
            store: STORE_1K,
            transport: Transport::Udp,
            workers: 4,
            threads: 8,
            qps: None,
            window: 64,
            mix: Mix::default(),
            rest: false,
            working_set: 1_000,
            duration: Some(5.0),
            reps: Some(3),
            notes: vec![
                "Зона `z0.bench.test.` подписывается `pulsed` при загрузке (CSK Ed25519); \
                 клиент шлёт EDNS0 с DO=1.",
            ],
        },
        ScenarioDef {
            name: "iso-tcp",
            description: "TCP, 8 соединений, closed-loop окно 16 (length-prefix).",
            store: STORE_100K,
            transport: Transport::Tcp,
            workers: 4,
            threads: 8,
            qps: None,
            window: 16,
            mix: Mix::default(),
            rest: false,
            working_set: 16_384,
            duration: Some(5.0),
            reps: Some(3),
            notes: vec![],
        },
        ScenarioDef {
            name: "iso-doh-h2",
            description: "DoH/HTTP/2, 8 соединений × 16 stream'ов, closed-loop.",
            store: STORE_100K,
            transport: Transport::DohH2,
            workers: 4,
            threads: 8,
            qps: None,
            window: 16,
            mix: Mix::default(),
            rest: false,
            working_set: 16_384,
            duration: Some(5.0),
            reps: Some(3),
            notes: vec![],
        },
        ScenarioDef {
            name: "iso-udp-rest",
            description: "UDP 10k qps + REST PUT в 8 зон; клиентские роли DNS/REST разведены по CPU.",
            store: STORE_8,
            transport: Transport::Udp,
            workers: 4,
            threads: 4,
            qps: Some(10_000.0),
            window: 1,
            mix: Mix::default(),
            rest: true,
            working_set: 4_096,
            duration: Some(5.0),
            reps: Some(3),
            notes: vec![
                "DNS-клиент — первая половина `--client-cpus`, REST-писатели — вторая \
                 (или `--rest-cpus`). API `pulsed` живёт в том же процессе, что DNS.",
            ],
        },
    ]
}

/// Копия сценария без пиннинга (контроль «loopback-общий»).
fn shared_twin(scenario: &ScenarioDef) -> ScenarioDef {
    ScenarioDef {
        name: Box::leak(
            format!("shared-{}", scenario.name.trim_start_matches("iso-")).into_boxed_str(),
        ),
        description: Box::leak(
            format!(
                "{} (контроль: сервер и клиент на общем наборе CPU).",
                scenario.description
            )
            .into_boxed_str(),
        ),
        notes: vec!["Без affinity: все потоки могут мигрировать по всем CPU."],
        ..scenario.clone()
    }
}

#[derive(Debug, Clone, Default)]
struct Layout {
    server: Option<Vec<usize>>,
    client: Option<Vec<usize>>,
    rest: Option<Vec<usize>>,
    note: String,
    warnings: Vec<String>,
}

impl Layout {
    fn enabled(&self) -> bool {
        self.server.is_some() && self.client.is_some()
    }
}

#[allow(clippy::too_many_lines)]
fn resolve_layout(args: &Args) -> Result<Layout, String> {
    let allowed = pulse_loadgen::affinity::allowed_cpus()?;
    let mut server = args
        .server_cpus
        .as_deref()
        .map(pulse_loadgen::affinity::CpuSet::parse)
        .transpose()?;
    let mut client = args
        .client_cpus
        .as_deref()
        .map(pulse_loadgen::affinity::CpuSet::parse)
        .transpose()?;
    let mut notes = Vec::new();
    let groups = pulse_loadgen::affinity::topology();
    let auto = args.auto_layout || (args.isolated && (server.is_none() || client.is_none()));
    if auto {
        let suggestion = pulse_loadgen::affinity::suggest_layout(&groups)?;
        notes.push(suggestion.note.clone());
        if server.is_none() {
            server = Some(suggestion.server);
        }
        if client.is_none() {
            client = Some(suggestion.client);
        }
    }
    if server.is_some() != client.is_some() {
        return Err(
            "укажите оба набора (--server-cpus и --client-cpus) либо ни одного; \
             частичный пиннинг искажает сравнение"
                .to_owned(),
        );
    }
    let mut warnings = Vec::new();
    let (server, client) = match (server, client) {
        (Some(server), Some(client)) => {
            pulse_loadgen::affinity::validate_partition(&server, &client, &allowed)?;
            // Проверяем право на sched_setaffinity заранее: если контейнер
            // запрещает, клиент продолжит без пиннинга с явным предупреждением.
            if let Some(cpu) = client.cpus().first()
                && let Err(error) = pulse_loadgen::affinity::set_current_thread_affinity(&[*cpu])
            {
                warnings.push(format!(
                    "sched_setaffinity недоступен ({error}); клиентские потоки будут без                      пиннинга, сервер всё равно пиннится через taskset"
                ));
                let _ = pulse_loadgen::affinity::set_current_thread_affinity(allowed.cpus());
            } else {
                let _ = pulse_loadgen::affinity::set_current_thread_affinity(allowed.cpus());
            }
            let shared = pulse_loadgen::affinity::shared_groups(&server, &client, &groups);
            if !shared.is_empty() {
                warnings.push(format!(
                    "сервер и клиент делят SMT-сиблингов: {:?}. Это не изолированный стенд — \
                     qps/p99 содержат SMT-конкуренцию; для чистого замера возьмите целые \
                     физические ядра на сторону (например 0-3 / 4-7 на 4 ядрах).",
                    shared
                        .iter()
                        .map(pulse_loadgen::affinity::CpuSet::as_list)
                        .collect::<Vec<_>>()
                ));
            }
            notes.push(format!(
                "allowed: {}, server: {}, client: {}; topology: {}",
                allowed.as_list(),
                server.as_list(),
                client.as_list(),
                pulse_loadgen::affinity::topology_report(&groups)
            ));
            (Some(server), Some(client))
        }
        _ => (None, None),
    };
    let rest = match &args.rest_cpus {
        Some(text) => Some(pulse_loadgen::affinity::CpuSet::parse(text)?),
        None => client
            .as_ref()
            .map(pulse_loadgen::affinity::CpuSet::split_at_half)
            .and_then(|(_, rest)| (!rest.is_empty()).then_some(rest)),
    };
    if let (Some(server), Some(client), Some(rest)) = (&server, &client, &rest) {
        let rest_set = rest.clone();
        if server.intersects(&rest_set) {
            return Err(format!(
                "--rest-cpus {} пересекается с серверными CPU {}",
                rest.as_list(),
                server.as_list()
            ));
        }
        if !rest_set.cpus().iter().all(|cpu| client.contains(*cpu)) {
            warnings.push(format!(
                "--rest-cpus {} выходит за клиентский набор {}; REST-роль может конкурировать \
                 с сервером",
                rest.as_list(),
                client.as_list()
            ));
        }
        let (dns, _) = client.split_at_half();
        if args.rest_cpus.is_some() && rest_set.intersects(&dns) {
            warnings.push(format!(
                "--rest-cpus {} пересекается с DNS-клиентскими CPU {}; роли не разведены",
                rest.as_list(),
                dns.as_list()
            ));
        }
    }
    Ok(Layout {
        server: server.map(|set| set.cpus().to_vec()),
        client: client.map(|set| set.cpus().to_vec()),
        rest: rest.map(|set| set.cpus().to_vec()),
        note: notes.join("; "),
        warnings,
    })
}

#[allow(clippy::too_many_lines)]
fn main() -> Result<(), String> {
    let mut args = Args::parse();
    let suffix = if args.isolated {
        "isolated"
    } else {
        "baseline"
    };
    if args.report.is_none() {
        args.report = Some(PathBuf::from(format!("docs/bench/{suffix}.md")));
    }
    if args.json.is_none() {
        args.json = Some(PathBuf::from(format!("docs/bench/{suffix}.json")));
    }
    let report_path = args.report.clone().ok_or("report path is not resolved")?;
    let json_path = args.json.clone().ok_or("json path is not resolved")?;
    if args.render_only {
        let text = std::fs::read_to_string(&json_path).map_err(|error| error.to_string())?;
        let mut report: BaselineReport = serde_json::from_str(&text)
            .map_err(|error| format!("{}: {error}", json_path.display()))?;
        for memory in &mut report.memory {
            memory.summary = mem::summarize(
                &memory.samples,
                Duration::from_millis(memory.summary.duration_ms),
            );
        }
        if !args.isolated
            && let Ok(rows) = read_alloc(&args.out_dir)
            && !rows.is_empty()
        {
            report.alloc = rows;
        }
        report.recommendations = recommendations(&report);
        report::write_json(&report, &json_path)?;
        report::write_markdown(&report, &report_path)?;
        println!("re-rendered {}", report_path.display());
        return Ok(());
    }
    if args.reps == 0 {
        args.reps = 1;
    }
    if args.quick {
        args.reps = 1;
        args.duration = 2.0;
        args.skip_soak = true;
        args.skip_profile = true;
        args.skip_commit = true;
    }
    if args.isolated {
        args.skip_memory = true;
        args.skip_soak = true;
        args.skip_commit = true;
        args.perf_scenarios = true;
    }
    let pulsed = args.pulsed.clone();
    if !pulsed.exists() {
        return Err(format!(
            "{} not found; run `cargo build --release -p pulsed` first",
            pulsed.display()
        ));
    }
    let layout = resolve_layout(&args)?;
    for warning in &layout.warnings {
        eprintln!("WARN affinity: {warning}");
    }
    if layout.enabled() {
        eprintln!(
            "affinity: server {}, client {}, rest {}",
            layout
                .server
                .as_deref()
                .map_or_else(String::new, pulse_loadgen::affinity::format_cpus),
            layout
                .client
                .as_deref()
                .map_or_else(String::new, pulse_loadgen::affinity::format_cpus),
            layout
                .rest
                .as_deref()
                .map_or_else(String::new, pulse_loadgen::affinity::format_cpus),
        );
    }
    std::fs::create_dir_all(&args.out_dir).map_err(|error| error.to_string())?;
    let scenario_list = if args.isolated {
        let mut bases = isolated_scenarios();
        if args.quick {
            bases.retain(|scenario| matches!(scenario.name, "iso-udp-mix" | "iso-udp-rest"));
            for scenario in &mut bases {
                scenario.duration = Some(2.0);
                scenario.reps = Some(1);
            }
        }
        // Пары iso/shared идут подряд: дрейф нагрузки хоста меньше искажает
        // сравнение методик.
        let mut list = Vec::with_capacity(bases.len() * 2);
        for base in bases {
            if !args.no_shared_controls && !args.quick {
                list.push(shared_twin(&base));
            }
            list.push(base);
        }
        list
    } else {
        scenarios(args.quick)
    };
    let mut store_specs: Vec<StoreSpec> = Vec::new();
    let mut add = |spec: StoreSpec| {
        if !store_specs.iter().any(|known| known.name == spec.name) {
            store_specs.push(spec);
        }
    };
    for scenario in &scenario_list {
        add(scenario.store);
    }
    if !args.skip_memory {
        for spec in [
            STORE_1K, STORE_8, STORE_100K, STORE_100, STORE_1000, STORE_1M,
        ] {
            add(spec);
        }
    }
    if !args.skip_soak {
        add(STORE_1M);
    }
    let mut stores = Vec::new();
    for spec in &store_specs {
        let store = ensure_store(&args, *spec)?;
        stores.push(store);
    }
    let cert = ensure_cert(&args.out_dir)?;
    if args.merge {
        args.skip_memory = true;
        args.skip_soak = true;
        args.skip_profile = true;
        args.skip_commit = true;
    }
    let mut report = if args.merge && json_path.exists() {
        let text = std::fs::read_to_string(&json_path).map_err(|error| error.to_string())?;
        serde_json::from_str(&text)
            .map_err(|error| format!("merge {}: {error}", json_path.display()))?
    } else {
        BaselineReport {
            title: args
                .isolated
                .then(|| "Isolated: pulsed, сервер и клиент на разных физических ядрах".to_owned()),
            scope_note: args.isolated.then(|| {
                "Методика: `iso-*` — сервер пиннится через `taskset`, клиентские потоки — \
                 `sched_setaffinity`; `shared-*` — тот же сценарий без пиннинга (контроль \
                 loopback-общий). 3 прогона, медиана; HDR p50/p99/p999. Сервер и клиент \
                 на одной машине (loopback), поэтому абсолютные qps — нижняя оценка."
                    .to_owned()
            }),
            pulsed_version: version(&pulsed),
            git_rev: git_rev(),
            host: sysinfo::host_info(),
            ..BaselineReport::default()
        }
    };
    report.generated_unix = report::now_unix();
    if args.isolated {
        report.extra.retain(|section| {
            !matches!(
                section.title.as_str(),
                "CPU-раскладка и права" | "Методика и CPU-раскладка" | "Isolated vs loopback-общий"
            )
        });
    }
    if !args.merge && !args.isolated {
        use std::os::unix::fs::MetadataExt;
        let mut body = String::from(
            "| Store | Зон | RRset | Logical MiB | Диск MiB | Генерация, с |\n|---|---|---|---|---|---|\n",
        );
        for store in &stores {
            let disk =
                std::fs::metadata(&store.path).map_or(0, |meta| meta.blocks().saturating_mul(512));
            let _ = std::fmt::Write::write_fmt(
                &mut body,
                format_args!(
                    "| `{}` | {} | {} | {:.1} | {:.1} | {:.1} |\n",
                    store.spec.name,
                    store.spec.zones,
                    store.rrsets,
                    store.file_bytes as f64 / (1024.0 * 1024.0),
                    disk as f64 / (1024.0 * 1024.0),
                    store.gen_ms as f64 / 1000.0
                ),
            );
        }
        body.push_str(
            "\nСтоимость bulk-load: v2-writer аллоцирует ~6 COW-страниц на RRset; \
             страницы уходят в free pool, но `page_count_max`/allocator cursor растёт \
             (для 1M — до ~24 GiB cursor; на диске ~16 GiB за счёт переиспользования). \
             Это стоимость bulk-load, а не чтения.",
        );
        report.extra.push(ExtraSection {
            title: "Генерация store".to_owned(),
            body,
        });
        report.extra.push(ExtraSection {
            title: "Блокер: 1000 зон".to_owned(),
            body: "Сценарий `1000 зон` воспроизводимо **зависает** в v2-writer'е: \
                процесс создаёт 255 зон и уходит в `__futex_wait` без CPU/прогресса. \
                `fsck` убитого файла: `zones=257`, `ok=true`; последняя зона — 255. \
                Похоже на коллизию lease-шарда: `zone_seq=256` даёт `256 % 256 = 0`, \
                тот же шард, что у каталога (зона 0), и нереентерабельный mutex \
                каталога берётся повторно при `create_zone`.\n\nВоспроизведение: `pulse-zonegen --zones 1000 --rrsets 100` (зависает \
                на ~255 зонах). Работает `--zones 255 --rrsets 392` (100 725 RRset). \
                Поэтому ось «число зон» в baseline — **255**, а не 1000; это дефект \
                production-кода, не харнесса. Исправление вне рамок задачи \
                (production-код не менялся).".to_owned(),
        });
    }

    let signed_key = ensure_sign_key(&args.out_dir)?;
    if args.isolated {
        let groups = pulse_loadgen::affinity::topology();
        let mut body = String::new();
        let _ = writeln!(
            body,
            "| Роль | CPU |\n|---|---|\n| Сервер (`taskset`) | `{}` |\n| Клиент DNS (`sched_setaffinity`) | `{}` |\n| REST-писатели | `{}` |",
            layout.server.as_deref().map_or_else(
                || "(без пиннинга)".to_owned(),
                pulse_loadgen::affinity::format_cpus
            ),
            layout.client.as_deref().map_or_else(
                || "(без пиннинга)".to_owned(),
                pulse_loadgen::affinity::format_cpus
            ),
            layout.rest.as_deref().map_or_else(
                || "(вторая половина клиента)".to_owned(),
                pulse_loadgen::affinity::format_cpus
            ),
        );
        let _ = writeln!(
            body,
            "\nSMT-группы (одно физическое ядро): `{}`.\n",
            pulse_loadgen::affinity::topology_report(&groups)
        );
        if !layout.note.is_empty() {
            let _ = writeln!(body, "{}\n", layout.note);
        }
        for warning in &layout.warnings {
            let _ = writeln!(body, "> **Внимание:** {warning}\n");
        }
        let _ = writeln!(
            body,
            "**Методика.** Сервер запускается как `taskset -c <server> pulsed`; каждый \
             клиентский поток в первой инструкции вызывает `sched_setaffinity(0, <один CPU>)` \
             (round-robin по `--client-cpus`). Наборы проверяются на непустоту, вхождение в \
             `Cpus_allowed_list` и непересечение; фактический affinity сервера сверяется по \
             `/proc/<pid>/status` после `exec`. В `iso-udp-rest` DNS-клиент занимает первую \
             половину клиентских CPU, REST-писатели — вторую. 3 прогона, в таблицу идёт \
             медиана по клиентскому qps; латентность — HDR (3 значащие цифры), клиентская, \
             `CLOCK_MONOTONIC` вокруг send/recv. `shared-*` — тот же сценарий без affinity, \
             запускается сразу после `iso-*`, чтобы дрейф нагрузки хоста меньше влиял на \
             сравнение."
        );
        let _ = writeln!(
            body,
            "\n`perf_event_paranoid={}`: `perf stat` (cycles/instructions/cache/TLB) доступен; \
             `perf record -e cycles:u` без call-graph тоже доступен, но `--call-graph dwarf` и \
             `-g` при paranoid=2 **запрещены** (`Failure to open event`). Harness пробует dwarf \
             и откатывается на плоский `cycles:u`; flamegraph тогда без стеков, hotspots — по \
             символам. Для dwarf-стеков нужен `CAP_PERFMON` или paranoid≤1.",
            perf_paranoid()
        );
        let _ = writeln!(
            body,
            "\n**SMT-сиблинги** (из `/sys/devices/system/cpu/cpu*/topology/thread_siblings_list`): \
             все `cpuN` внутри одной группы — одно физическое ядро. Рекомендуемая раскладка — \
             целые ядра: `server=0-3`, `client=4-7` (используется здесь). Если серверу хватает \
             двух логических CPU, более строгий вариант — `server=0,2`, `client=4,6`, а \
             сиблинги `1,3,5,7` оставить idle. Раскладка `0,2,4,6` / `1,3,5,7` **не является \
             изоляцией**: каждая пара CPU — сиблинги одного ядра, и сервер конкурирует с \
             клиентом за SMT-порты."
        );
        let _ = writeln!(
            body,
            "\n**Ограничения.** Один хост, loopback; 4 физических ядра / 8 SMT-потоков \
             (Ryzen 5 3500U), SMT и turbo не отключались, governor не менялся. На хосте \
             параллельно работали другие процессы (см. `loadavg` ниже), поэтому абсолютные \
             qps/p99 — нижняя оценка, а сравнение `iso`/`shared` валидно только в пределах \
             этого прогона. UDP-сценарии `iso-udp-*` — closed-loop окно 64: p50/p99 включают \
             очередь в клиентском сокете, это метрика насыщения, а не service time."
        );
        report.extra.push(ExtraSection {
            title: "Методика и CPU-раскладка".to_owned(),
            body,
        });
    }
    let list = scenario_list;
    for scenario in &list {
        if let Some(only) = &args.only
            && !scenario.name.contains(only.as_str())
        {
            continue;
        }
        let store = stores
            .iter()
            .find(|store| store.spec.name == scenario.store.name)
            .ok_or_else(|| format!("store {} missing", scenario.store.name))?;
        let reps = scenario.reps.unwrap_or(args.reps);
        let duration = scenario.duration.unwrap_or(args.duration);
        eprintln!(
            "== {}: {} rep(s) x {duration}s, workers={} threads={}",
            scenario.name, reps, scenario.workers, scenario.threads
        );
        let scenario_report = run_scenario(
            &args,
            scenario,
            store,
            &cert,
            reps,
            duration,
            &layout,
            &signed_key,
        )?;
        if let Some(existing) = report
            .scenarios
            .iter_mut()
            .find(|existing| existing.name == scenario_report.name)
        {
            *existing = scenario_report;
        } else {
            report.scenarios.push(scenario_report);
        }
    }
    // На случай старого JSON с дублями: оставляем последнее вхождение.
    let mut last_seen: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    for (index, scenario) in report.scenarios.iter().enumerate() {
        last_seen.insert(scenario.name.clone(), index);
    }
    let mut deduped = Vec::with_capacity(report.scenarios.len());
    for (index, scenario) in report.scenarios.iter().enumerate() {
        if last_seen.get(&scenario.name) == Some(&index) {
            deduped.push(scenario.clone());
        }
    }
    report.scenarios = deduped;

    if args.isolated {
        report.extra.push(ExtraSection {
            title: "Isolated vs loopback-общий".to_owned(),
            body: comparison_table(&report),
        });
    }

    if !args.skip_memory {
        for spec in [
            STORE_1K, STORE_8, STORE_100K, STORE_100, STORE_1000, STORE_1M,
        ] {
            let store = stores
                .iter()
                .find(|store| store.spec.name == spec.name)
                .ok_or_else(|| format!("store {} missing", spec.name))?;
            eprintln!(
                "== memory {}: {} zone(s) x {} RRset",
                spec.name, spec.zones, spec.rrsets_per_zone
            );
            let memory = run_memory(&args, store, &cert)?;
            report.memory.push(memory);
        }
    }

    if !args.skip_profile {
        let targets: Vec<&str> = if args.isolated || args.perf_scenarios {
            list.iter()
                .filter(|scenario| scenario.affinity())
                .map(|scenario| scenario.name)
                .collect()
        } else {
            vec!["udp-w8"]
        };
        for name in targets {
            if let Some(only) = &args.only
                && !name.contains(only.as_str())
            {
                continue;
            }
            let Some(scenario) = list.iter().find(|scenario| scenario.name == name) else {
                continue;
            };
            let Some(store) = stores
                .iter()
                .find(|store| store.spec.name == scenario.store.name)
            else {
                continue;
            };
            eprintln!("== profile {name}: perf stat/record, cycles:u");
            match run_profile(&args, scenario, store, &cert, &layout, &signed_key) {
                Ok(perf) => report.perf.push(perf),
                Err(error) => {
                    report.perf.push(PerfReport {
                        label: name.to_owned(),
                        note: format!("perf недоступен: {error}"),
                        ..PerfReport::default()
                    });
                }
            }
        }
    }

    if !args.skip_soak {
        eprintln!("== soak: {}s на z1m, 20k qps", args.soak_secs);
        let store = stores
            .iter()
            .find(|store| store.spec.name == "z1m")
            .ok_or("z1m store missing")?;
        let memory = run_soak(&args, store, &cert)?;
        report.memory.push(memory);
    }

    if !args.skip_commit {
        let body = run_commit_bench()?;
        report.extra.push(ExtraSection {
            title: "Commit-режимы v2".to_owned(),
            body,
        });
    }

    report.alloc = if args.isolated {
        Vec::new()
    } else {
        read_alloc(&args.out_dir)?
    };
    report.recommendations = recommendations(&report);
    report.commands = commands(&args);
    report::write_json(&report, &json_path)?;
    report::write_markdown(&report, &report_path)?;
    println!(
        "baseline: {} scenario(s), {} memory row(s), {} alloc row(s) -> {} / {}",
        report.scenarios.len(),
        report.memory.len(),
        report.alloc.len(),
        report_path.display(),
        json_path.display()
    );
    Ok(())
}

fn ensure_store(args: &Args, spec: StoreSpec) -> Result<StoreFiles, String> {
    let path = args.out_dir.join(format!("{}.v2", spec.name));
    let report_path = args.out_dir.join(format!("{}.json", spec.name));
    if !args.reuse || !path.exists() {
        let spec_gen = GenSpec {
            path: path.clone(),
            zones: spec.zones,
            rrsets_per_zone: spec.rrsets_per_zone,
            page_count_max: GenSpec::pages_for(spec.zones, spec.rrsets_per_zone),
            sync_mode: pulse_zonefile::parallel::SyncModeV2::Memory,
            resume: false,
        };
        eprintln!(
            "== store {}: {} zone(s) x {} RRset",
            spec.name, spec.zones, spec.rrsets_per_zone
        );
        let started = Instant::now();
        let generated = storegen::generate(&spec_gen)?;
        eprintln!(
            "   {} RRset, {:.1} MiB, {} ms",
            generated.rrsets,
            generated.file_bytes as f64 / (1024.0 * 1024.0),
            started.elapsed().as_millis()
        );
        let json = serde_json::to_string_pretty(&generated).map_err(|error| error.to_string())?;
        std::fs::write(&report_path, json).map_err(|error| error.to_string())?;
        Ok(StoreFiles {
            spec,
            path,
            rrsets: generated.rrsets,
            gen_ms: generated.elapsed_ms,
            file_bytes: generated.file_bytes,
        })
    } else {
        let zones = spec.zones;
        let rrsets = u64::from(zones) * u64::from(spec.rrsets_per_zone);
        let file_bytes = std::fs::metadata(&path).map_or(0, |meta| meta.len());
        let gen_ms = std::fs::read_to_string(&report_path)
            .ok()
            .and_then(|text| serde_json::from_str::<storegen::GenReport>(&text).ok())
            .map_or(0, |generated| generated.elapsed_ms);
        Ok(StoreFiles {
            spec,
            path,
            rrsets,
            gen_ms,
            file_bytes,
        })
    }
}

/// Готовит Ed25519 CSK для подписи `z0.bench.test.` (сценарий `iso-udp-signed`).
fn ensure_sign_key(out_dir: &Path) -> Result<PathBuf, String> {
    let dir = out_dir.join("dnssec");
    let marker = dir.join("z0.key.private");
    if let Ok(text) = std::fs::read_to_string(&marker) {
        let path = PathBuf::from(text.trim());
        if path.is_file() {
            return Ok(path);
        }
    }
    std::fs::create_dir_all(&dir).map_err(|error| error.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| error.to_string())?;
    }
    let owner = Name::parse("z0.bench.test.").map_err(|error| error.to_string())?;
    let key = pulse_dnssec::PrivateKey::generate(pulse_dnssec::Algorithm::ED25519)
        .map_err(|error| format!("dnssec key: {error}"))?;
    let paths = pulse_dnssec::write_key_pair(&dir, &owner, &key, 257, &pulse_dnssec::NoopAudit)
        .map_err(|error| format!("dnssec key file: {error}"))?;
    std::fs::write(&marker, paths.private.display().to_string())
        .map_err(|error| error.to_string())?;
    Ok(paths.private)
}

fn ensure_cert(out_dir: &Path) -> Result<PathBuf, String> {
    let cert_path = out_dir.join("cert.pem");
    let key_path = out_dir.join("key.pem");
    if cert_path.exists() && key_path.exists() {
        return Ok(cert_path);
    }
    let key = rcgen::KeyPair::generate().map_err(|error| error.to_string())?;
    let params =
        rcgen::CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
            .map_err(|error| error.to_string())?;
    let certificate = params
        .self_signed(&key)
        .map_err(|error| error.to_string())?;
    std::fs::write(&cert_path, certificate.pem()).map_err(|error| error.to_string())?;
    std::fs::write(&key_path, key.serialize_pem()).map_err(|error| error.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&key_path, permissions).map_err(|error| error.to_string())?;
    }
    Ok(cert_path)
}

fn version(pulsed: &Path) -> String {
    Command::new(pulsed)
        .arg("--version")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map_or_else(|| "unknown".to_owned(), |text| text.trim().to_owned())
}

fn git_rev() -> Option<String> {
    let head = std::fs::read_to_string(".git/HEAD").ok()?;
    let head = head.trim();
    if let Some(reference) = head.strip_prefix("ref: ") {
        std::fs::read_to_string(format!(".git/{reference}"))
            .ok()
            .map(|value| value.trim().to_owned())
    } else {
        Some(head.to_owned())
    }
}

struct RunningServer {
    child: Child,
    pid: u32,
    udp: u16,
    tcp: u16,
    dot: u16,
    doh_h2: u16,
    api: u16,
    log: PathBuf,
    started: Instant,
    start_ticks: Option<(u64, u64)>,
    cpus: String,
}

impl RunningServer {
    fn address(&self, transport: Transport, api: bool) -> SocketAddr {
        let port = if api {
            self.api
        } else {
            match transport {
                Transport::Udp => self.udp,
                Transport::Tcp => self.tcp,
                Transport::Dot => self.dot,
                Transport::DohH2 => self.doh_h2,
            }
        };
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn stop(mut self, duration: f64) -> ServerStats {
        let rss_kb = sysinfo::process_rss_kb(self.pid).unwrap_or(0);
        let end_ticks = sysinfo::process_cpu_ticks_split(self.pid);
        let wall = self.started.elapsed().as_secs_f64();
        let cpus = pulse_loadgen::affinity::pid_cpus(self.pid)
            .map_or_else(String::new, |set| set.as_list());
        let _ = Command::new("kill")
            .arg("-TERM")
            .arg(self.pid.to_string())
            .status();
        let started = Instant::now();
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) | Err(_) => break,
                Ok(None) if started.elapsed() < Duration::from_secs(15) => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Ok(None) => {
                    let _ = Command::new("kill")
                        .arg("-KILL")
                        .arg(self.pid.to_string())
                        .status();
                    let _ = self.child.wait();
                    break;
                }
            }
        }
        let text = std::fs::read_to_string(&self.log).unwrap_or_default();
        let mut stats = parse_server_stats(&text, duration);
        stats.rss_kb = rss_kb;
        stats.cpus = if cpus.is_empty() {
            self.cpus.clone()
        } else {
            cpus
        };
        let hz = sysinfo::clock_ticks_per_sec().max(1) as f64;
        if let (Some((user0, sys0)), Some((user1, sys1))) = (self.start_ticks, end_ticks)
            && wall > 0.0
        {
            #[allow(clippy::cast_precision_loss)]
            {
                stats.cpu_user_pct = user1.saturating_sub(user0) as f64 / hz / wall * 100.0;
                stats.cpu_sys_pct = sys1.saturating_sub(sys0) as f64 / hz / wall * 100.0;
            }
        }
        stats
    }
}

impl Drop for RunningServer {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = Command::new("kill")
                .args(["-KILL", &self.pid.to_string()])
                .status();
            let _ = self.child.wait();
        }
    }
}

struct ServerOptions {
    workers: usize,
    store: PathBuf,
    dot: bool,
    doh_h2: bool,
    api: bool,
    label: String,
    cpus: Option<Vec<usize>>,
    sign_key: Option<PathBuf>,
}

struct ServerPorts {
    udp: u16,
    tcp: u16,
    dot: u16,
    doh_h2: u16,
    api: u16,
}

fn start_server(
    args: &Args,
    options: &ServerOptions,
    cert: &Path,
) -> Result<RunningServer, String> {
    spawn_server(args, options, cert, &[])
}

/// Запускает сервер под внешней командой (`perf stat`/`perf record`), которая
/// становится parent'ом — иначе `ptrace_scope=1` не даёт attach.
fn start_profiled(
    args: &Args,
    options: &ServerOptions,
    cert: &Path,
    prefix: &[&str],
) -> Result<RunningServer, String> {
    spawn_server(args, options, cert, prefix)
}

#[allow(clippy::too_many_lines)]
fn spawn_server(
    args: &Args,
    options: &ServerOptions,
    cert: &Path,
    prefix: &[&str],
) -> Result<RunningServer, String> {
    let ports = ServerPorts {
        udp: free_udp_port()?,
        tcp: free_tcp_port()?,
        dot: free_tcp_port()?,
        doh_h2: free_tcp_port()?,
        api: free_tcp_port()?,
    };
    let key = args.out_dir.join("key.pem");
    let config_path = args
        .out_dir
        .join("configs")
        .join(format!("{}.toml", options.label));
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let mut config = format!(
        "listen_udp = \"127.0.0.1:{}\"\n\
         listen_tcp = \"127.0.0.1:{}\"\n\
         workers = {}\n\
         log_level = \"info\"\n\
         zonefile = \"{}\"\n\
         durability = \"memory\"\n\
         map_size = 4294967296\n\
         journal = false\n",
        ports.udp,
        ports.tcp,
        options.workers,
        options.store.display(),
    );
    if options.dot || options.doh_h2 {
        let _ = write!(
            config,
            "tls_cert = \"{}\"\ntls_key = \"{}\"\n",
            cert.display(),
            key.display()
        );
    }
    if options.dot {
        let _ = writeln!(config, "dot_listen = \"127.0.0.1:{}\"", ports.dot);
    }
    if options.doh_h2 {
        let _ = writeln!(config, "doh_h2_listen = \"127.0.0.1:{}\"", ports.doh_h2);
    }
    if options.api {
        let _ = write!(
            config,
            "api_listen = \"127.0.0.1:{}\"\napi_token = \"pd_bench_token\"\n",
            ports.api
        );
    }
    if let Some(key) = &options.sign_key {
        let _ = write!(
            config,
            "[dnssec.\"z0.bench.test.\"]\nvalidity_days = 30\n\
             [[dnssec.\"z0.bench.test.\".keys]]\nrole = \"csk\"\npath = \"{}\"\n",
            key.display()
        );
    }
    std::fs::write(&config_path, config).map_err(|error| error.to_string())?;
    let log_path = args
        .out_dir
        .join("logs")
        .join(format!("{}.log", options.label));
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let log = File::create(&log_path).map_err(|error| error.to_string())?;
    let stderr = log.try_clone().map_err(|error| error.to_string())?;
    let mut full: Vec<String> = prefix.iter().map(|value| (*value).to_owned()).collect();
    if let Some(cpus) = &options.cpus {
        full.push("taskset".to_owned());
        full.push("-c".to_owned());
        full.push(pulse_loadgen::affinity::format_cpus(cpus));
    }
    full.push(args.pulsed.display().to_string());
    let mut command = Command::new(&full[0]);
    command.env("LC_ALL", "C");
    if full.len() > 1 {
        command.args(&full[1..]);
    }
    let mut child = command
        .arg("--config")
        .arg(&config_path)
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(stderr))
        .spawn()
        .map_err(|error| format!("spawn server: {error}"))?;
    let wrapper_pid = child.id();
    // Под perf parent'ом реальный pid сервера — дочерний. `taskset` делает
    // exec, поэтому без perf pid совпадает с wrapper'ом.
    let pid = if prefix.is_empty() {
        wrapper_pid
    } else {
        let started = Instant::now();
        loop {
            if let Some(pid) = child_pid(wrapper_pid) {
                break pid;
            }
            if let Ok(Some(status)) = child.try_wait() {
                let tail: String = std::fs::read_to_string(&log_path)
                    .unwrap_or_default()
                    .lines()
                    .rev()
                    .take(12)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect::<Vec<_>>()
                    .join("\n");
                return Err(format!(
                    "wrapper {wrapper_pid} exited ({status}) before pulsed; log tail:\n{tail}"
                ));
            }
            if started.elapsed() > Duration::from_secs(5) {
                return Err(format!(
                    "cannot find pulsed child of wrapper {wrapper_pid}; see {}",
                    log_path.display()
                ));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    };
    let mut server = RunningServer {
        child,
        pid,
        udp: ports.udp,
        tcp: ports.tcp,
        dot: ports.dot,
        doh_h2: ports.doh_h2,
        api: ports.api,
        log: log_path,
        started: Instant::now(),
        start_ticks: None,
        cpus: options
            .cpus
            .as_deref()
            .map_or_else(String::new, pulse_loadgen::affinity::format_cpus),
    };
    if let Some(cpus) = &options.cpus {
        let expected = pulse_loadgen::affinity::format_cpus(cpus);
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match pulse_loadgen::affinity::pid_cpus(pid) {
                Some(actual) if actual.as_list() == expected => break,
                _ if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Some(actual) => {
                    return Err(format!(
                        "taskset не применился: сервер pid {pid} имеет affinity {}, ожидался \
                         {expected}",
                        actual.as_list()
                    ));
                }
                None => {
                    return Err(format!(
                        "не удалось прочитать affinity сервера pid {pid} (ожидался {expected})"
                    ));
                }
            }
        }
    }
    wait_ready(&server, options.workers)?;
    server.started = Instant::now();
    server.start_ticks = sysinfo::process_cpu_ticks_split(pid);
    Ok(server)
}

fn child_pid(parent: u32) -> Option<u32> {
    let output = Command::new("pgrep")
        .arg("-P")
        .arg(parent.to_string())
        .output()
        .ok()?;
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .and_then(|pid| pid.parse().ok())
}

fn wait_ready(server: &RunningServer, _workers: usize) -> Result<(), String> {
    let query = Message::query(
        0x1234,
        Question::new(
            Name::parse("r0000000.z0.bench.test.").map_err(|error| error.to_string())?,
            Rtype::A,
            Rclass::IN,
        ),
    )
    .encode(&EncodeOptions::compressed())
    .map_err(|error| error.to_string())?;
    let socket = UdpSocket::bind("127.0.0.1:0").map_err(|error| error.to_string())?;
    socket
        .set_read_timeout(Some(Duration::from_millis(100)))
        .map_err(|error| error.to_string())?;
    let address = SocketAddr::from(([127, 0, 0, 1], server.udp));
    let started = Instant::now();
    let mut buffer = [0_u8; 4096];
    while started.elapsed() < Duration::from_secs(20) {
        if socket.send_to(&query, address).is_ok() && socket.recv_from(&mut buffer).is_ok() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let log = std::fs::read_to_string(&server.log).unwrap_or_default();
    let tail: String = log.lines().rev().take(5).collect::<Vec<_>>().join("\n");
    Err(format!("server did not become ready; log tail:\n{tail}"))
}

fn free_udp_port() -> Result<u16, String> {
    let socket = UdpSocket::bind("127.0.0.1:0").map_err(|error| error.to_string())?;
    socket
        .local_addr()
        .map(|address| address.port())
        .map_err(|error| error.to_string())
}

fn free_tcp_port() -> Result<u16, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|error| error.to_string())?;
    listener
        .local_addr()
        .map(|address| address.port())
        .map_err(|error| error.to_string())
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn run_scenario(
    args: &Args,
    scenario: &ScenarioDef,
    store: &StoreFiles,
    cert: &Path,
    reps: usize,
    duration: f64,
    layout: &Layout,
    signed_key: &Path,
) -> Result<Scenario, String> {
    let mut runs = Vec::new();
    let mut servers = Vec::new();
    let mut client_cpu = Vec::new();
    for rep in 0..reps {
        let label = format!("{}-{rep}", scenario.name);
        let options = ServerOptions {
            workers: scenario.workers,
            store: store.path.clone(),
            dot: scenario.transport == Transport::Dot,
            doh_h2: scenario.transport == Transport::DohH2,
            api: scenario.rest,
            label: label.clone(),
            cpus: scenario.affinity().then(|| layout.server.clone()).flatten(),
            sign_key: scenario.edns_do().then(|| signed_key.to_path_buf()),
        };
        let server = start_server(args, &options, cert)?;
        let rest = rest_config(scenario, &server, rep, layout);
        let mut config = client_config(scenario, store, &server, cert, rep, layout, duration);
        config.rest = rest;
        let before = sysinfo::process_cpu_ticks_split(std::process::id());
        let elapsed = Instant::now();
        let run = run_client(&config)?;
        let wall = elapsed.elapsed().as_secs_f64();
        let after = sysinfo::process_cpu_ticks_split(std::process::id());
        let usage = cpu_usage(before, after, wall);
        let mut server_stats = server.stop(wall.max(duration));
        let measured_responses = server_stats.responses.saturating_sub(run.warmup_received);
        #[allow(clippy::cast_precision_loss)]
        {
            server_stats.qps = measured_responses as f64 / duration.max(0.001);
        }
        eprintln!(
            "   rep {rep}: client {:.0} qps, p99 {:.1}us, server {:.0} qps, rcvbuf Δ {}, \
             cpu cl {:.0}/{:.0}% srv {:.0}/{:.0}%",
            run.client_qps,
            run.latency.p99 as f64 / 1000.0,
            server_stats.qps,
            run.kernel.rcvbuf_errors(),
            usage.user_pct,
            usage.sys_pct,
            server_stats.cpu_user_pct,
            server_stats.cpu_sys_pct,
        );
        runs.push(run);
        servers.push(server_stats);
        client_cpu.push(usage);
    }
    let median = report::median_run_index(&runs);
    Ok(Scenario {
        name: scenario.name.to_owned(),
        description: scenario.description.to_owned(),
        runs,
        server: servers,
        median,
        notes: scenario
            .notes
            .iter()
            .map(|note| (*note).to_owned())
            .collect(),
        client_cpu,
    })
}

fn client_config(
    scenario: &ScenarioDef,
    store: &StoreFiles,
    server: &RunningServer,
    cert: &Path,
    rep: usize,
    layout: &Layout,
    duration: f64,
) -> ClientConfig {
    ClientConfig {
        target: server.address(scenario.transport, false),
        mode: scenario.transport.mode(),
        threads: scenario.threads,
        qps: scenario.qps,
        window: scenario.window,
        duration: Duration::from_secs_f64(duration),
        warmup: Duration::from_secs_f64(if duration >= 5.0 { 3.0 } else { 0.5 }),
        timeout: Duration::from_secs(2),
        mix: scenario.mix,
        zones: store.spec.zones,
        rrsets_per_zone: store.spec.rrsets_per_zone,
        seed: 0x5eed_1234_abcd_0001 ^ u64::try_from(rep).unwrap_or(0),
        working_set: scenario.working_set.min(
            usize::try_from(u64::from(store.spec.zones) * u64::from(store.spec.rrsets_per_zone))
                .unwrap_or(scenario.working_set)
                .max(5),
        ),
        ca: (scenario.transport == Transport::Dot || scenario.transport == Transport::DohH2)
            .then(|| cert.to_path_buf()),
        server_name: "localhost".to_owned(),
        doh_path: "/dns-query".to_owned(),
        validate_every: 64,
        rest: None,
        max_inflight: 8192,
        cpus: scenario.affinity().then(|| layout.client.clone()).flatten(),
        edns_do: scenario.edns_do(),
    }
}

fn rest_config(
    scenario: &ScenarioDef,
    server: &RunningServer,
    rep: usize,
    layout: &Layout,
) -> Option<pulse_loadgen::rest::RestConfig> {
    scenario.rest.then(|| pulse_loadgen::rest::RestConfig {
        api: server.address(Transport::Udp, true),
        token: "pd_bench_token".to_owned(),
        zones: 8,
        threads: 4,
        rate: 80.0,
        timeout: Duration::from_secs(5),
        tag: format!("{}-r{rep}-{}", scenario.name, std::process::id()),
        cpus: scenario.affinity().then(|| layout.rest.clone()).flatten(),
    })
}

fn cpu_usage(
    before: Option<(u64, u64)>,
    after: Option<(u64, u64)>,
    wall_secs: f64,
) -> report::CpuUsage {
    let (Some(before), Some(after)) = (before, after) else {
        return report::CpuUsage {
            wall_secs,
            ..report::CpuUsage::default()
        };
    };
    let hz = sysinfo::clock_ticks_per_sec().max(1) as f64;
    #[allow(clippy::cast_precision_loss)]
    let percent = |delta: u64| -> f64 {
        if wall_secs <= 0.0 {
            0.0
        } else {
            delta as f64 / hz / wall_secs * 100.0
        }
    };
    report::CpuUsage {
        user_pct: percent(after.0.saturating_sub(before.0)),
        sys_pct: percent(after.1.saturating_sub(before.1)),
        wall_secs,
    }
}

fn run_client(config: &ClientConfig) -> Result<pulse_loadgen::RunResult, String> {
    match config.mode {
        Mode::Udp => pulse_loadgen::udp::run(config),
        Mode::Tcp => pulse_loadgen::stream::run_tcp(config),
        Mode::Dot => pulse_loadgen::stream::run_dot(config),
        Mode::DohH2 => pulse_loadgen::doh::run(config),
    }
}

fn run_memory(args: &Args, store: &StoreFiles, cert: &Path) -> Result<mem::MemoryReport, String> {
    let server = start_server(
        args,
        &ServerOptions {
            workers: 4,
            store: store.path.clone(),
            dot: false,
            doh_h2: false,
            api: false,
            label: format!("memory-{}", store.spec.name),
            cpus: None,
            sign_key: None,
        },
        cert,
    )?;
    let base = ClientConfig {
        target: server.address(Transport::Udp, false),
        mode: Mode::Udp,
        threads: 4,
        qps: None,
        window: 32,
        duration: Duration::from_secs(5),
        warmup: Duration::ZERO,
        timeout: Duration::from_secs(2),
        mix: Mix::default(),
        zones: store.spec.zones,
        rrsets_per_zone: store.spec.rrsets_per_zone,
        seed: 0x1234_5678,
        working_set: usize::try_from(
            u64::from(store.spec.zones) * u64::from(store.spec.rrsets_per_zone),
        )
        .unwrap_or(200_000)
        .clamp(5, 200_000),
        ca: None,
        server_name: "localhost".to_owned(),
        doh_path: "/dns-query".to_owned(),
        validate_every: 0,
        rest: None,
        max_inflight: 8192,
        cpus: None,
        edns_do: false,
    };
    // Прогрев: страницы page cache и аллокаторы прогреты до сэмплирования.
    let _ = pulse_loadgen::udp::run(&base)?;
    let sampler = mem::Sampler::start(server.pid, store.path.clone(), Duration::from_millis(1000));
    let mut measured = base.clone();
    measured.duration = Duration::from_secs(10);
    let _run = pulse_loadgen::udp::run(&measured)?;
    let mut memory = sampler.finish(store.spec.zones, store.rrsets);
    memory.pid = server.pid;
    memory.data = store.path.display().to_string();
    server.stop(10.0);
    Ok(memory)
}

fn run_soak(args: &Args, store: &StoreFiles, cert: &Path) -> Result<mem::MemoryReport, String> {
    let server = start_server(
        args,
        &ServerOptions {
            workers: 8,
            store: store.path.clone(),
            dot: false,
            doh_h2: false,
            api: false,
            label: "soak".to_owned(),
            cpus: None,
            sign_key: None,
        },
        cert,
    )?;
    let base = ClientConfig {
        target: server.address(Transport::Udp, false),
        mode: Mode::Udp,
        threads: 8,
        qps: Some(20_000.0),
        window: 1,
        duration: Duration::from_secs(5),
        warmup: Duration::ZERO,
        timeout: Duration::from_secs(2),
        mix: Mix::default(),
        zones: store.spec.zones,
        rrsets_per_zone: store.spec.rrsets_per_zone,
        seed: 0x9abc_def0,
        working_set: 16_384,
        ca: None,
        server_name: "localhost".to_owned(),
        doh_path: "/dns-query".to_owned(),
        validate_every: 0,
        rest: None,
        max_inflight: 8192,
        cpus: None,
        edns_do: false,
    };
    let _ = pulse_loadgen::udp::run(&base)?;
    let sampler = mem::Sampler::start(server.pid, store.path.clone(), Duration::from_millis(2000));
    let mut soak = base.clone();
    soak.duration = Duration::from_secs_f64(args.soak_secs.max(10.0));
    let run = pulse_loadgen::udp::run(&soak)?;
    let mut memory = sampler.finish(store.spec.zones, store.rrsets);
    memory.pid = server.pid;
    memory.data = store.path.display().to_string();
    server.stop(soak.duration.as_secs_f64());
    eprintln!(
        "   soak: client {:.0} qps, rcvbuf Δ {}, RSS {} -> {} KiB ({:.2}%)",
        run.client_qps,
        run.kernel.rcvbuf_errors(),
        memory.summary.rss_first_kb,
        memory.summary.rss_last_kb,
        memory.summary.rss_growth_pct
    );
    Ok(memory)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn run_profile(
    args: &Args,
    scenario: &ScenarioDef,
    store: &StoreFiles,
    cert: &Path,
    layout: &Layout,
    signed_key: &Path,
) -> Result<PerfReport, String> {
    let duration = scenario.duration.unwrap_or(5.0).clamp(2.0, 5.0);
    let cpus = scenario.affinity().then(|| layout.server.clone()).flatten();
    let stat_path = args
        .out_dir
        .join(format!("perf-stat-{}.txt", scenario.name));
    let record_path = args.out_dir.join(format!("perf-{}.data", scenario.name));
    let _ = std::fs::remove_file(&stat_path);
    let _ = std::fs::remove_file(&record_path);
    let options = ServerOptions {
        workers: scenario.workers,
        store: store.path.clone(),
        dot: scenario.transport == Transport::Dot,
        doh_h2: scenario.transport == Transport::DohH2,
        api: scenario.rest,
        label: format!("perf-stat-{}", scenario.name),
        cpus: cpus.clone(),
        sign_key: scenario.edns_do().then(|| signed_key.to_path_buf()),
    };
    let stat_prefix = vec![
        "perf",
        "stat",
        "-o",
        stat_path.to_str().ok_or("perf-stat path")?,
        "-e",
        "cycles,instructions,cache-references,cache-misses,L1-dcache-loads,\
         L1-dcache-load-misses,dTLB-loads,dTLB-load-misses,iTLB-load-misses,\
         branches,branch-misses,page-faults,context-switches,cpu-migrations",
        "--",
    ];
    let stat_server = start_profiled(args, &options, cert, &stat_prefix)?;
    let mut load_config = client_config(scenario, store, &stat_server, cert, 0, layout, duration);
    load_config.warmup = Duration::from_secs(1);
    let stat_run = run_client(&load_config)?;
    stat_server.stop(load_config.duration.as_secs_f64());
    let stat_text = std::fs::read_to_string(&stat_path).unwrap_or_default();
    let mut counters = parse_perf_stat(&stat_text);
    derive_ratios(&mut counters);

    let mut note = format!(
        "perf stat: perf — parent, сервер — child (ptrace_scope={}). Клиент: {:.0} qps, p99 {:.1} µs. user-space cycles: paranoid={}.",
        ptrace_scope(),
        stat_run.client_qps,
        stat_run.latency.p99 as f64 / 1000.0,
        perf_paranoid()
    );
    let mut hotspots = Vec::new();
    let mut flamegraph = None;
    let mut record_errors: Vec<String> = Vec::new();
    let mut recorded = false;
    for (mode, dwarf) in [("dwarf", true), ("plain", false)] {
        if recorded {
            break;
        }
        let _ = std::fs::remove_file(&record_path);
        let record_options = ServerOptions {
            workers: scenario.workers,
            store: store.path.clone(),
            dot: scenario.transport == Transport::Dot,
            doh_h2: scenario.transport == Transport::DohH2,
            api: scenario.rest,
            label: format!("perf-record-{}-{mode}", scenario.name),
            cpus: cpus.clone(),
            sign_key: scenario.edns_do().then(|| signed_key.to_path_buf()),
        };
        let mut record_prefix = vec![
            "perf".to_owned(),
            "record".to_owned(),
            "-e".to_owned(),
            "cycles:u".to_owned(),
            "-o".to_owned(),
            record_path.display().to_string(),
            "-F".to_owned(),
            "199".to_owned(),
        ];
        if dwarf {
            record_prefix.push("--call-graph".to_owned());
            record_prefix.push("dwarf".to_owned());
        }
        record_prefix.push("--".to_owned());
        let prefix_refs: Vec<&str> = record_prefix.iter().map(String::as_str).collect();
        let record_server = match start_profiled(args, &record_options, cert, &prefix_refs) {
            Ok(server) => server,
            Err(error) => {
                record_errors.push(format!("{mode}: {error}"));
                continue;
            }
        };
        let mut load = client_config(
            scenario,
            store,
            &record_server,
            cert,
            0,
            layout,
            duration.min(4.0),
        );
        load.warmup = Duration::from_secs(1);
        let record_run = match run_client(&load) {
            Ok(run) => run,
            Err(error) => {
                record_errors.push(format!("{mode}: load: {error}"));
                continue;
            }
        };
        record_server.stop(load.duration.as_secs_f64());
        let report_text = Command::new("perf")
            .env("LC_ALL", "C")
            .args([
                "report",
                "--stdio",
                "--no-children",
                "--sort",
                "symbol",
                "--percent-limit",
                "0.5",
                "-i",
                record_path.to_str().ok_or("perf.data path")?,
            ])
            .output()
            .ok()
            .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
            .unwrap_or_default();
        hotspots = parse_hotspots(&report_text);
        flamegraph = make_flamegraph(&record_path, &args.out_dir, scenario.name);
        let graph = if dwarf {
            "dwarf call-graph"
        } else {
            "без call-graph (paranoid=2 запрещает dwarf/fp)"
        };
        let _ = write!(
            note,
            " perf record ({graph}): {:.0} qps, p99 {:.1} µs.",
            record_run.client_qps,
            record_run.latency.p99 as f64 / 1000.0
        );
        recorded = true;
    }
    if !recorded {
        let _ = write!(
            note,
            " perf record недоступен ({}); hotspots/flamegraph не построены. \
             При paranoid=2 kernel-space и call-graph sampling запрещены; нужен CAP_PERFMON \
             или paranoid≤1. `perf stat` при этом доступен.",
            record_errors.join("; ")
        );
    }

    Ok(PerfReport {
        label: format!(
            "{} ({duration:.0}s, {})",
            scenario.name,
            scenario.transport.mode().as_str()
        ),
        counters,
        hotspots,
        flamegraph,
        note,
    })
}

fn derive_ratios(counters: &mut std::collections::BTreeMap<String, f64>) {
    if let (Some(instructions), Some(cycles)) = (
        counters.get("instructions").copied(),
        counters.get("cycles").copied(),
    ) && cycles > 0.0
    {
        counters.insert("ipc".to_owned(), instructions / cycles);
    }
    if let (Some(misses), Some(references)) = (
        counters.get("cache-misses").copied(),
        counters.get("cache-references").copied(),
    ) && references > 0.0
    {
        counters.insert("cache-miss-pct".to_owned(), misses * 100.0 / references);
    }
    if let (Some(misses), Some(loads)) = (
        counters.get("dTLB-load-misses").copied(),
        counters.get("dTLB-loads").copied(),
    ) && loads > 0.0
    {
        counters.insert("dtlb-miss-pct".to_owned(), misses * 100.0 / loads);
    }
}

fn perf_paranoid() -> String {
    std::fs::read_to_string("/proc/sys/kernel/perf_event_paranoid")
        .map_or_else(|_| "?".to_owned(), |value| value.trim().to_owned())
}

fn ptrace_scope() -> String {
    std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .map_or_else(|_| "?".to_owned(), |value| value.trim().to_owned())
}

fn parse_perf_stat(text: &str) -> std::collections::BTreeMap<String, f64> {
    let mut counters = std::collections::BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        let mut fields = line.split_whitespace();
        let Some(number) = fields.next() else {
            continue;
        };
        let normalized = number.replace(',', "");
        let Ok(value) = normalized.parse::<f64>() else {
            continue;
        };
        let Some(name) = fields.next() else {
            continue;
        };
        let name = name
            .trim_end_matches(":u")
            .trim_end_matches(":k")
            .trim_end_matches(":uk")
            .to_owned();
        counters.insert(name, value);
    }
    counters
}

fn parse_hotspots(text: &str) -> Vec<Hotspot> {
    let mut hotspots = Vec::new();
    for line in text.lines() {
        let Some(percent_index) = line.find('%') else {
            continue;
        };
        let percent_text = line.get(..percent_index).unwrap_or_default().trim();
        let Ok(percent) = percent_text.parse::<f64>() else {
            continue;
        };
        let rest = line.get(percent_index + 1..).unwrap_or_default();
        let symbol = rest
            .split_once(']')
            .map_or_else(
                || rest.split_whitespace().last().unwrap_or_default(),
                |(_, tail)| tail.trim(),
            )
            .split("  ")
            .next()
            .unwrap_or_default()
            .trim()
            .to_owned();
        if !symbol.is_empty() && symbol != "symbol" {
            hotspots.push(Hotspot { symbol, percent });
        }
        if hotspots.len() >= 25 {
            break;
        }
    }
    hotspots
}

fn make_flamegraph(perf_data: &Path, out_dir: &Path, label: &str) -> Option<String> {
    let script = Command::new("perf")
        .env("LC_ALL", "C")
        .args(["script", "-i", &perf_data.display().to_string()])
        .output()
        .ok()?;
    if !script.status.success() || script.stdout.is_empty() {
        return None;
    }
    let script_path = out_dir.join(format!("perf-script-{label}.txt"));
    std::fs::write(&script_path, &script.stdout).ok()?;
    let script_text = String::from_utf8_lossy(&script.stdout);
    let folded = pulse_loadgen::flame::collapse(&script_text);
    if folded.is_empty() {
        return None;
    }
    let folded_path = out_dir.join(format!("perf-{label}.folded"));
    std::fs::write(&folded_path, &folded).ok()?;
    let svg_path = out_dir.join(format!("flamegraph-{label}.svg"));
    if let (Some(collapse), Some(flamegraph)) =
        (which("inferno-collapse-perf"), which("inferno-flamegraph"))
    {
        let collapsed_path = out_dir.join(format!("perf-{label}.inferno.folded"));
        let collapsed = Command::new(collapse)
            .stdin(Stdio::from(File::open(&script_path).ok()?))
            .stdout(Stdio::from(File::create(&collapsed_path).ok()?))
            .output()
            .ok()?;
        if collapsed.status.success() {
            let svg = Command::new(flamegraph)
                .arg(&collapsed_path)
                .stdout(Stdio::from(File::create(&svg_path).ok()?))
                .output()
                .ok()?;
            if svg.status.success() {
                return Some(svg_path.display().to_string());
            }
        }
    }
    let svg = pulse_loadgen::flame::render_svg(&folded, label);
    if svg.is_empty() {
        return None;
    }
    std::fs::write(&svg_path, svg).ok()?;
    Some(svg_path.display().to_string())
}

fn which(binary: &str) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(binary))
        .find(|path| path.is_file())
        .map(|path| path.display().to_string())
}

fn run_commit_bench() -> Result<String, String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new("cargo")
        .args(["bench", "-p", "pulsed", "--bench", "zone_writes"])
        .current_dir(&root)
        .output()
        .map_err(|error| format!("cargo bench: {error}"))?;
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    if !output.status.success() {
        return Ok(format!(
            "`cargo bench -p pulsed --bench zone_writes` завершился с ошибкой.\n\n```\n{text}\n```"
        ));
    }
    let mut body = String::from(
        "Сравнение per-zone/group commit (`crates/pulsed/benches/zone_writes.rs`):\n\n```\n",
    );
    for line in text.lines() {
        if line.contains("QPS")
            || line.contains("per-zone")
            || line.contains("group")
            || line.contains("Group/parallel")
            || line.contains("host:")
        {
            body.push_str(line);
            body.push('\n');
        }
    }
    body.push_str("```\n");
    Ok(body)
}

fn read_alloc(out_dir: &Path) -> Result<Vec<AllocRow>, String> {
    let path = out_dir.join("alloc.json");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(&path).map_err(|error| error.to_string())?;
    serde_json::from_str(&text).map_err(|error| format!("alloc.json: {error}"))
}

fn parse_server_stats(text: &str, duration: f64) -> ServerStats {
    let mut stats = ServerStats::default();
    for line in text.lines() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let event = value
            .get("event")
            .and_then(|event| event.as_str())
            .unwrap_or_default();
        let message = value
            .get("msg")
            .and_then(|message| message.as_str())
            .unwrap_or_default();
        match event {
            "stats" => {
                stats.queries_udp = field(message, "udp").unwrap_or(stats.queries_udp);
                stats.queries_tcp = field(message, "tcp").unwrap_or(stats.queries_tcp);
                stats.responses = field(message, "responses").unwrap_or(stats.responses);
                stats.decode_errors =
                    field(message, "decode_errors").unwrap_or(stats.decode_errors);
                stats.encode_errors =
                    field(message, "encode_errors").unwrap_or(stats.encode_errors);
                stats.dropped = field(message, "dropped").unwrap_or(stats.dropped);
            }
            "udp_stats" => {
                stats.udp_received = field(message, "received").unwrap_or(stats.udp_received);
                stats.udp_sent = field(message, "sent").unwrap_or(stats.udp_sent);
                stats.udp_recv_errors =
                    field(message, "recv_errors").unwrap_or(stats.udp_recv_errors);
                stats.udp_send_errors =
                    field(message, "send_errors").unwrap_or(stats.udp_send_errors);
                stats.udp_dropped = field(message, "dropped").unwrap_or(stats.udp_dropped);
                stats.udp_oversize = field(message, "oversize").unwrap_or(stats.udp_oversize);
            }
            "query_stats" => {
                stats.nxdomain = field(message, "nxdomain").unwrap_or(stats.nxdomain);
                stats.nodata = field(message, "nodata").unwrap_or(stats.nodata);
                stats.refused = field(message, "refused").unwrap_or(stats.refused);
                stats.servfail = field(message, "servfail").unwrap_or(stats.servfail);
            }
            _ => {}
        }
    }
    let responses = if stats.responses > 0 {
        stats.responses
    } else {
        stats.udp_sent
    };
    #[allow(clippy::cast_precision_loss)]
    {
        stats.qps = responses as f64 / duration.max(0.001);
    }
    stats
}

fn field(message: &str, key: &str) -> Option<u64> {
    for token in message.split([' ', ',', '(', ')', '\n', '\t']) {
        if let Some((name, value)) = token.split_once('=')
            && name == key
        {
            return value.parse().ok();
        }
    }
    None
}

#[allow(clippy::cast_precision_loss)]
fn comparison_table(report: &BaselineReport) -> String {
    let mut body = String::from(
        "| Сценарий | iso qps | shared qps | Δ qps | iso p50 µs | shared p50 µs | \
         iso p99 µs | shared p99 µs | iso p999 µs | iso srv user/sys % | shared srv user/sys % | \
         iso RSS MiB | shared RSS MiB |\n\
         |---|---|---|---|---|---|---|---|---|---|---|---|---|\n",
    );
    let mut rows = 0;
    for scenario in report
        .scenarios
        .iter()
        .filter(|scenario| scenario.name.starts_with("iso-"))
    {
        let Some(iso_run) = scenario.runs.get(scenario.median) else {
            continue;
        };
        let iso_cpu = scenario
            .server
            .get(scenario.median)
            .cloned()
            .unwrap_or_default();
        let shared_name = format!("shared-{}", scenario.name.trim_start_matches("iso-"));
        let Some(shared) = report
            .scenarios
            .iter()
            .find(|candidate| candidate.name == shared_name)
        else {
            let _ = writeln!(
                body,
                "| {} | {:.0} | — | — | {:.2} | — | {:.2} | — | {:.2} | {:.0}/{:.0} | — | {:.1} | — |",
                scenario.name,
                iso_run.client_qps,
                iso_run.latency.p50 as f64 / 1000.0,
                iso_run.latency.p99 as f64 / 1000.0,
                iso_run.latency.p999 as f64 / 1000.0,
                iso_cpu.cpu_user_pct,
                iso_cpu.cpu_sys_pct,
                iso_cpu.rss_kb as f64 / 1024.0,
            );
            continue;
        };
        let Some(shared_run) = shared.runs.get(shared.median) else {
            continue;
        };
        let shared_cpu = shared
            .server
            .get(shared.median)
            .cloned()
            .unwrap_or_default();
        let delta =
            (iso_run.client_qps - shared_run.client_qps) / shared_run.client_qps.max(1.0) * 100.0;
        let _ = writeln!(
            body,
            "| {} | {:.0} | {:.0} | {:+.1}% | {:.2} | {:.2} | {:.2} | {:.2} | {:.2} | \
             {:.0}/{:.0} | {:.0}/{:.0} | {:.1} | {:.1} |",
            scenario.name,
            iso_run.client_qps,
            shared_run.client_qps,
            delta,
            iso_run.latency.p50 as f64 / 1000.0,
            shared_run.latency.p50 as f64 / 1000.0,
            iso_run.latency.p99 as f64 / 1000.0,
            shared_run.latency.p99 as f64 / 1000.0,
            iso_run.latency.p999 as f64 / 1000.0,
            iso_cpu.cpu_user_pct,
            iso_cpu.cpu_sys_pct,
            shared_cpu.cpu_user_pct,
            shared_cpu.cpu_sys_pct,
            iso_cpu.rss_kb as f64 / 1024.0,
            shared_cpu.rss_kb as f64 / 1024.0,
        );
        rows += 1;
    }
    if rows == 0 {
        body.push_str(
            "\nКонтрольные `shared-*` не запускались (`--no-shared-controls`). \
             Запустите без флага для сравнения с loopback-общим.\n",
        );
    } else {
        body.push_str(
            "\n`shared-*` — тот же сценарий без affinity (все потоки мигрируют по 8 vCPU). \
             Δ qps = (iso − shared) / shared; положительное значение — вклад изоляции. \
             Оба варианта — loopback, поэтому это сравнение методики, а не абсолютный потолок. \
             `shared-*` может выигрывать по qps: без пиннинга каждый процесс получает доступ \
             ко всем 8 vCPU, тогда как `iso-*` ограничивает сторону 4 CPU. Изоляция убирает \
             SMT-конкуренцию, но не увеличивает суммарное число CPU.\n",
        );
    }
    body
}

fn isolated_recommendations(report: &BaselineReport) -> Vec<String> {
    let mut items = Vec::new();
    let mut best = None;
    for scenario in report
        .scenarios
        .iter()
        .filter(|scenario| scenario.name.starts_with("iso-"))
    {
        let Some(run) = scenario.runs.get(scenario.median) else {
            continue;
        };
        let shared = report.scenarios.iter().find(|candidate| {
            candidate.name == format!("shared-{}", scenario.name.trim_start_matches("iso-"))
        });
        let shared_qps = shared
            .and_then(|shared| shared.runs.get(shared.median))
            .map_or(0.0, |run| run.client_qps);
        if shared_qps > 0.0 {
            let delta = (run.client_qps - shared_qps) / shared_qps * 100.0;
            items.push(format!(
                "{}: {:.0} qps (shared {shared_qps:.0}, {:+.1}%), p50 {:.1} µs, p99 {:.1} µs, \
                 p999 {:.1} µs.",
                scenario.name,
                run.client_qps,
                delta,
                run.latency.p50 as f64 / 1000.0,
                run.latency.p99 as f64 / 1000.0,
                run.latency.p999 as f64 / 1000.0,
            ));
        } else {
            items.push(format!(
                "{}: {:.0} qps, p50 {:.1} µs, p99 {:.1} µs, p999 {:.1} µs.",
                scenario.name,
                run.client_qps,
                run.latency.p50 as f64 / 1000.0,
                run.latency.p99 as f64 / 1000.0,
                run.latency.p999 as f64 / 1000.0,
            ));
        }
        if run.kernel.rcvbuf_errors() > 0 {
            items.push(format!(
                "{}: `UdpRcvbufErrors` Δ {} — сервер/ядро теряли датаграммы; qps занижен, \
                 поднимите `SO_RCVBUF`/уменьшите окно или число клиентских потоков.",
                scenario.name,
                run.kernel.rcvbuf_errors()
            ));
        }
        if best.as_ref().is_none_or(|(_, qps)| run.client_qps > *qps) {
            best = Some((scenario.name.clone(), run.client_qps));
        }
    }
    if let Some((name, qps)) = best {
        items.push(format!(
            "Максимальный клиентский qps в прогоне — `{name}`: {qps:.0}. Это не потолок \
             платформы: стенд loopback на 4 серверных CPU и шумном хосте; для приёмки \
             100k qps нужен отдельный клиентский хост."
        ));
    }
    if let Some(nx) = report
        .scenarios
        .iter()
        .find(|scenario| scenario.name == "iso-udp-nx")
        && let Some(hit) = report
            .scenarios
            .iter()
            .find(|scenario| scenario.name == "iso-udp-mix")
        && let (Some(nx_run), Some(hit_run)) = (nx.runs.get(nx.median), hit.runs.get(hit.median))
    {
        items.push(format!(
            "NXDOMAIN против mix: p99 {:.1} µs против {:.1} µs ({:.1}×). Негативный путь — \
             главный вклад в хвост; оптимизация перебора суффиксов даёт больше, чем qps.",
            nx_run.latency.p99 as f64 / 1000.0,
            hit_run.latency.p99 as f64 / 1000.0,
            nx_run.latency.p99 as f64 / hit_run.latency.p99.max(1) as f64
        ));
    }
    if report.perf.iter().all(|perf| perf.hotspots.is_empty()) {
        items.push(
            "Функциональные hotspots не сняты: `perf record -e cycles:u` не дал сэмплов \
             (paranoid≥3 или perf.data пуст). `perf stat`-счётчики при этом доступны; для \
             flamegraph нужен `CAP_PERFMON` либо `kernel.perf_event_paranoid≤1`."
                .to_owned(),
        );
    }
    items.push(
        "Изоляция проверяется по `Cpus_allowed_list` сервера и SMT-группам: сервер и клиент \
         не должны делить физическое ядро. Раскладка 0,2,4,6/1,3,5,7 формально не пересекается, \
         но оставляет каждого с сиблингом на чужой стороне — это не isolated."
            .to_owned(),
    );
    items
}

#[allow(clippy::too_many_lines)]
fn recommendations(report: &BaselineReport) -> Vec<String> {
    if report
        .title
        .as_deref()
        .is_some_and(|title| title.contains("Isolated"))
    {
        return isolated_recommendations(report);
    }
    let mut items = Vec::new();
    if let Some(udp) = report
        .scenarios
        .iter()
        .find(|scenario| scenario.name == "udp-w8")
        && let Some(run) = udp.runs.get(udp.median)
    {
        if run.kernel.rcvbuf_errors() == 0 && run.timeouts == 0 {
            items.push(format!(
                "UDP 8 worker'ов держит 10k qps без потерь и таймаутов (p99 {:.1} µs); запаса по дропам на этой ставке нет смысла искать — поднимайте ставку до насыщения.",
                run.latency.p99 as f64 / 1000.0
            ));
        } else {
            items.push(format!(
                "На udp-w8 есть потери/таймауты: rcvbuf Δ {}, timeout {}, `suppressed` {}. Уменьшите ставку или увеличьте `SO_RCVBUF`/число worker'ов.",
                run.kernel.rcvbuf_errors(),
                run.timeouts,
                run.suppressed
            ));
        }
    }
    if let (Some(positive), Some(nx)) = (
        report
            .scenarios
            .iter()
            .find(|scenario| scenario.name == "udp-w8"),
        report
            .scenarios
            .iter()
            .find(|scenario| scenario.name == "udp-nx-w8"),
    ) && let (Some(positive_run), Some(nx_run)) =
        (positive.runs.get(positive.median), nx.runs.get(nx.median))
    {
        let ratio = nx_run.latency.p99 as f64 / positive_run.latency.p99.max(1) as f64;
        items.push(format!(
            "NXDOMAIN на той же ставке 10k: p99 {:.1} ms против {:.1} µs у mix-hit ({ratio:.0}×). \
             Узкое место — перебор суффиксов/негативный ответ; оптимизация NX-пути даёт \
             наибольший выигрыш по p99 (порядок — единицы/десятки раз), затем уже qps.",
            nx_run.latency.p99 as f64 / 1_000_000.0,
            positive_run.latency.p99 as f64 / 1000.0
        ));
    }
    if let Some(rest) = report
        .scenarios
        .iter()
        .find(|scenario| scenario.name == "udp-rest-8z")
        && let Some(run) = rest.runs.get(rest.median)
        && let Some(rest_result) = &run.rest
    {
        items.push(format!(
            "REST под DNS-нагрузкой: {:.0} PUT/s (цель 80), ошибок {}, p50 {:.1} ms / p99 {:.1} ms. \
             API-путь чувствителен к CPU-конкуренции с UDP-worker'ами; выносить API на отдельные \
             ядра/процесс или батчить записи.",
            rest_result.qps,
            rest_result.errors,
            rest_result.latency_us.p50 as f64 / 1000.0,
            rest_result.latency_us.p99 as f64 / 1000.0
        ));
    }
    items.push(
        "Bulk-load 1M RRset: ~6 COW-страниц на RRset, cursor до ~24 GiB, 26 мин и 16 GiB \
         на диске; при импорте 1000 зон writer зависает на zone_seq=256 (см. раздел «Блокер»). \
         Это главный практический дефект, не влияющий на чтение, но блокирующий большие стенды."
            .to_owned(),
    );
    if let Some(memory) = report
        .memory
        .iter()
        .find(|memory| memory.zones == 1 && memory.rrsets >= 1_000_000)
    {
        let summary = &memory.summary;
        items.push(format!(
            "1M RRset: RSS {:.0} MiB (anon {:.0} MiB, file {:.0} MiB, mmap {:.0} MiB); бюджет 512 MiB {}.",
            summary.rss_last_kb as f64 / 1024.0,
            summary.anon_last_kb as f64 / 1024.0,
            summary.file_last_kb as f64 / 1024.0,
            summary.mmap_last_kb as f64 / 1024.0,
            if summary.rss_last_kb <= 512 * 1024 { "выполнен" } else { "превышен" }
        ));
        items.push(format!(
            "RssAnon на 1M RRset {:.0} MiB — это heap/index/кэш, не mmap; рост RssAnon в soak — утечка, рост RssFile/mmap — page cache (норма).",
            summary.anon_last_kb as f64 / 1024.0
        ));
    }
    if let Some(soak) = report
        .memory
        .iter()
        .find(|memory| memory.summary.duration_ms >= 590_000)
    {
        items.push(format!(
            "Soak {:.0} мин: RSS {:.0} → {:.0} MiB ({:+.2}%), наклон {:.1} KiB/мин → {}.",
            soak.summary.duration_ms as f64 / 60_000.0,
            soak.summary.rss_first_kb as f64 / 1024.0,
            soak.summary.rss_last_kb as f64 / 1024.0,
            soak.summary.rss_growth_pct,
            soak.summary.rss_slope_kib_per_min,
            if soak.summary.leak_suspected {
                "есть подозрение на утечку"
            } else {
                "стабильно"
            }
        ));
    }
    if let Some(perf) = report.perf.first()
        && let Some(hotspot) = perf.hotspots.first()
    {
        items.push(format!(
            "Top hotspot: `{}` ({:.1}%). Смотреть в сторону уменьшения копий/аллокаций на этом пути; IPC {:?}.",
            hotspot.symbol,
            hotspot.percent,
            perf.counters.get("ipc").map(|value| format!("{value:.2}"))
        ));
    }
    if report
        .perf
        .first()
        .is_some_and(|perf| perf.hotspots.is_empty())
    {
        items.push(
            "Функциональные hotspots не сняты: `perf record -g/--call-graph dwarf` заблокирован \
             `kernel.perf_event_paranoid=2`, хотя `perf stat` и плоский `perf record -e cycles:u` \
             работают. Для flamegraph со стеками нужен paranoid≤1 или CAP_PERFMON."
                .to_owned(),
        );
    }
    if let Some(tcp) = report
        .scenarios
        .iter()
        .find(|scenario| scenario.name == "tcp-w8")
        && let Some(doh) = report
            .scenarios
            .iter()
            .find(|scenario| scenario.name == "doh-h2-w8")
        && let (Some(tcp_run), Some(doh_run)) = (tcp.runs.get(tcp.median), doh.runs.get(doh.median))
    {
        items.push(format!(
            "Транспорты: TCP {:.0} qps, DoH h2 {:.0} qps при 8 соединениях; разница — TLS/h2 \
             handshake и HTTP-обработка. Для DoH масштабирование упирается в число \
             соединений/stream'ов клиента, а не в UDP worker'ы.",
            tcp_run.client_qps, doh_run.client_qps
        ));
    }
    if let Some(row) = report.alloc.iter().find(|row| row.op == "lookup_ref") {
        items.push(format!(
            "`lookup_ref` (zero-copy) — {:.4} allocs/op, {:.1} B/op; `lookup` материализует RRset и аллоцирует — на горячем пути предпочтителен `lookup_ref`.",
            row.allocs_per_op, row.bytes_per_op
        ));
    }
    items.push(
        "Loopback + SMT: клиент и сервер делят 8 vCPU; абсолютные qps занижены, p99 завышен. Для приёмки C1 (100k qps) нужен отдельный клиентский хост и отключённый SMT/turbo.".to_owned(),
    );
    items
}

fn commands(args: &Args) -> Vec<String> {
    let report = args.report.as_deref().map_or_else(
        || "docs/bench/baseline.md".to_owned(),
        |path| path.display().to_string(),
    );
    let json = args.json.as_deref().map_or_else(
        || "docs/bench/baseline.json".to_owned(),
        |path| path.display().to_string(),
    );
    let mut commands = vec![
        "cargo build --release -p pulsed -p pulse-loadgen".to_owned(),
        format!(
            "target/release/pulse-bench --out-dir {} --report {report} --json {json}",
            args.out_dir.display()
        ),
    ];
    if args.isolated {
        commands.push(format!(
            "target/release/pulse-bench --isolated --reuse --auto-layout \\
             --server-cpus {} --client-cpus {} --rest-cpus {} \\
             --out-dir {} --report {report} --json {json}",
            args.server_cpus.as_deref().unwrap_or("0-3"),
            args.client_cpus.as_deref().unwrap_or("4-7"),
            args.rest_cpus.as_deref().unwrap_or("6-7"),
            args.out_dir.display()
        ));
        commands.push(
            "taskset -c 4-7 target/release/pulse-loadgen --server 127.0.0.1:5353 \\
             --mode udp --threads 8 --window 64 --client-cpus 4-7 --json-out run.json"
                .to_owned(),
        );
    }
    commands.push(
        "cargo run -p pulse-loadgen --release --features alloc --bin pulse-alloc -- \\
         --data target/bench/z1m.v2 --rrsets 1000000 --ops 20000 \\
         --json-out target/bench/alloc.json"
            .to_owned(),
    );
    commands.push("cargo bench -p pulsed --bench zone_writes".to_owned());
    commands
}
