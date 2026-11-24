//! `pulse-zonec`: разбор, проверка и нормализация master-файла зоны.
//!
//! Использование:
//!
//! ```text
//! pulse-zonec parse     <origin> <zone-file>
//! pulse-zonec validate  <origin> <zone-file>
//! pulse-zonec normalize <origin> <zone-file>
//! ```
//!
//! `origin` — имя зоны; файл читается целиком, `$INCLUDE` разрешён только
//! внутри каталога файла.

use std::path::PathBuf;
use std::process::ExitCode;

use pulse_dns::Name;
use pulse_master::{ParseOptions, TextOptions, parse_zone_with_options, to_text};

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = arguments.first() else {
        return usage();
    };
    let (Some(origin_text), Some(file_text)) = (arguments.get(1), arguments.get(2)) else {
        return usage();
    };
    if arguments.len() != 3 {
        return usage();
    }
    let Ok(origin) = Name::parse(origin_text) else {
        eprintln!("pulse-zonec: invalid origin {origin_text:?}");
        return ExitCode::FAILURE;
    };
    let path = PathBuf::from(file_text);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) => {
            eprintln!("pulse-zonec: cannot read {}: {error}", path.display());
            return ExitCode::FAILURE;
        }
    };
    let include_root = path
        .parent()
        .map(std::fs::canonicalize)
        .and_then(Result::ok);
    let options = ParseOptions {
        include_root,
        ..ParseOptions::default()
    };
    let zone = match parse_zone_with_options(origin, &text, &options) {
        Ok(zone) => zone,
        Err(error) => {
            eprintln!("pulse-zonec: {error}");
            return ExitCode::FAILURE;
        }
    };
    for warning in &zone.warnings {
        eprintln!("{warning}");
    }
    match command.as_str() {
        "parse" => {
            println!(
                "zone {}: {} records, default TTL {}, {} warning(s)",
                zone.origin,
                zone.records.len(),
                zone.default_ttl
                    .map_or_else(|| "none".to_owned(), |ttl| ttl.to_string()),
                zone.warnings.len()
            );
            ExitCode::SUCCESS
        }
        "validate" => {
            println!("ok: zone {} is valid", zone.origin);
            ExitCode::SUCCESS
        }
        "normalize" => {
            print!(
                "{}",
                to_text(
                    &zone.records,
                    &TextOptions {
                        origin: Some(zone.origin.clone()),
                        default_ttl: zone.default_ttl,
                        sort: true,
                    },
                )
            );
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("pulse-zonec: unknown command {other:?}");
            usage()
        }
    }
}

fn usage() -> ExitCode {
    eprintln!("usage: pulse-zonec <parse|validate|normalize> <origin> <zone-file>");
    ExitCode::FAILURE
}
