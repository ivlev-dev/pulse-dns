//! `pulse-zonegen` — генерация v2-zonefile для замеров.
//!
//! ```text
//! pulse-zonegen --path target/bench/z1k.v2 --zones 1 --rrsets 1000 \
//!               --json-out target/bench/z1k.json
//! pulse-zonegen --path target/bench/z1m.v2 --zones 1 --rrsets 1000000
//! ```

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]

use std::path::PathBuf;

use clap::Parser;
use pulse_loadgen::storegen::{self, GenSpec};
use pulse_zonefile::parallel::SyncModeV2;

#[derive(Debug, Parser)]
#[command(
    name = "pulse-zonegen",
    version,
    about = "Generate a pulse-zonefile v2 store for benchmarks"
)]
struct Args {
    /// Путь к создаваемому zonefile.
    #[arg(long)]
    path: PathBuf,
    /// Только показать сведения о существующем store.
    #[arg(long)]
    info: bool,
    /// Число зон.
    #[arg(long, default_value_t = 1)]
    zones: u32,
    /// `RRset` на зону (не считая apex SOA/NS/A).
    #[arg(long, default_value_t = 1000)]
    rrsets: u32,
    /// Лимит страниц (по умолчанию — оценка по числу `RRset`).
    #[arg(long)]
    page_count: Option<u32>,
    /// Durability: memory (по умолчанию) или sync.
    #[arg(long, value_parser = parse_sync, default_value = "memory")]
    sync: SyncModeV2,
    /// Продолжить существующий store с текущего `rrset_count`.
    #[arg(long)]
    resume: bool,
    /// JSON-файл с отчётом.
    #[arg(long)]
    json_out: Option<PathBuf>,
}

fn parse_sync(value: &str) -> Result<SyncModeV2, String> {
    match value {
        "memory" => Ok(SyncModeV2::Memory),
        "flush" => Ok(SyncModeV2::Flush),
        "sync" => Ok(SyncModeV2::Sync),
        other => Err(format!("sync must be memory|flush|sync, got {other:?}")),
    }
}

fn main() -> Result<(), String> {
    let args = Args::parse();
    if args.info {
        let info = storegen::info(&args.path)?;
        println!(
            "{}: {} zone(s), {} RRset, logical {} bytes, disk {} bytes",
            args.path.display(),
            info.zones,
            info.rrsets,
            info.file_bytes,
            info.disk_bytes
        );
        if let Some(path) = &args.json_out {
            let json = serde_json::to_string_pretty(&info).map_err(|error| error.to_string())?;
            std::fs::write(path, json).map_err(|error| error.to_string())?;
        }
        return Ok(());
    }
    let page_count_max = args
        .page_count
        .unwrap_or_else(|| GenSpec::pages_for(args.zones, args.rrsets));
    let spec = GenSpec {
        path: args.path,
        zones: args.zones,
        rrsets_per_zone: args.rrsets,
        page_count_max,
        sync_mode: args.sync,
        resume: args.resume,
    };
    let report = storegen::generate(&spec)?;
    if let Some(path) = &args.json_out {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let json = serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?;
        std::fs::write(path, json).map_err(|error| error.to_string())?;
    }
    println!(
        "generated {} zone(s) / {} RRset in {} ms: {} ({} bytes)",
        report.zones, report.rrsets, report.elapsed_ms, report.path, report.file_bytes
    );
    Ok(())
}
