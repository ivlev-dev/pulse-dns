//! `pulse-mem` — сэмплер памяти процесса сервера.
//!
//! ```text
//! pulse-mem --pid $(cat /run/pulsed.pid) --duration 600 --data target/bench/z1m.v2 \
//!           --zones 1 --rrsets 1000000 --json-out mem-soak.json
//! ```

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]

use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "pulse-mem",
    version,
    about = "Sample pulsed RSS/VmRSS/RssAnon/RssFile/mmap and fd dynamics"
)]
struct Args {
    /// PID сервера.
    #[arg(long)]
    pid: u32,
    /// Длительность наблюдения, с.
    #[arg(long, default_value_t = 10.0)]
    duration: f64,
    /// Интервал, мс.
    #[arg(long, default_value_t = 250)]
    interval_ms: u64,
    /// Путь к zonefile (для вклада mmap и размера файла).
    #[arg(long, default_value = "")]
    data: PathBuf,
    /// Зон в файле (для отчёта).
    #[arg(long, default_value_t = 0)]
    zones: u32,
    /// `RRset` в файле (для отчёта).
    #[arg(long, default_value_t = 0)]
    rrsets: u64,
    /// JSON-файл.
    #[arg(long)]
    json_out: Option<PathBuf>,
}

fn main() -> Result<(), String> {
    let args = Args::parse();
    let sampler = pulse_loadgen::mem::Sampler::start(
        args.pid,
        args.data.clone(),
        Duration::from_millis(args.interval_ms.max(20)),
    );
    std::thread::sleep(Duration::from_secs_f64(args.duration.max(0.2)));
    let mut report = sampler.finish(args.zones, args.rrsets);
    report.pid = args.pid;
    report.data = args.data.display().to_string();
    if let Some(path) = &args.json_out {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let json = serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?;
        std::fs::write(path, json).map_err(|error| error.to_string())?;
    }
    let summary = &report.summary;
    println!(
        "pid={} samples={} duration={}ms rss: first={}KiB last={}KiB peak={}KiB growth={}KiB ({:.2}%) slope={:.1}KiB/min",
        report.pid,
        summary.samples,
        summary.duration_ms,
        summary.rss_first_kb,
        summary.rss_last_kb,
        summary.rss_max_kb,
        summary.rss_growth_kb,
        summary.rss_growth_pct,
        summary.rss_slope_kib_per_min
    );
    println!(
        "  anon last={}KiB file last={}KiB mmap_rss last={}KiB file_bytes={} cpu={:.1}% leak_suspected={}",
        summary.anon_last_kb,
        summary.file_last_kb,
        summary.mmap_last_kb,
        summary.file_bytes,
        summary.cpu_pct,
        summary.leak_suspected
    );
    Ok(())
}
