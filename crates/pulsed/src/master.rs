//! Загрузка master-файлов (RFC 1035) через `pulse-master`.

use std::collections::HashMap;

use pulse_dns::{Name, Rclass, Rdata, Rrset, Rtype, Ttl};
use pulse_master::{Location, ParseError, ParseOptions, parse_zone_with_options};

use crate::logging;

/// Зона, прочитанная из master-файла.
pub(crate) struct LoadedZone {
    pub(crate) origin: Name,
    pub(crate) default_ttl: Ttl,
    pub(crate) rrsets: Vec<Rrset>,
}

type RrsetKey = (Name, Rtype);
type PendingRrset = (Ttl, Vec<Rdata>);

/// Читает и разбирает master-файл, переводя `Record` в RRset'ы.
pub(crate) fn load_zone_file(origin: &str, path: &std::path::Path) -> Result<LoadedZone, String> {
    let origin = Name::parse(origin.trim()).map_err(|error| {
        format!(
            "invalid origin {origin:?} for zone file {}: {error}",
            path.display()
        )
    })?;
    if origin == Name::root() || origin.labels().any(|label| label == b"*") {
        return Err(format!(
            "origin {origin} must be a non-root name without wildcards"
        ));
    }
    let text = std::fs::read_to_string(path)
        .map_err(|error| format!("cannot read zone file {}: {error}", path.display()))?;
    let include_root = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map_or_else(
            || std::path::PathBuf::from("."),
            std::path::Path::to_path_buf,
        );
    let options = ParseOptions {
        include_root: Some(include_root),
        ..ParseOptions::default()
    };
    let parsed = parse_zone_with_options(origin, &text, &options)
        .map_err(|error| format_parse_error(path, &error))?;
    for warning in &parsed.warnings {
        logging::warn(
            "zone_import",
            &format!(
                "{}: warning: {}",
                format_location(path, &warning.location),
                warning.kind
            ),
        );
    }
    let default_ttl = parsed.default_ttl.unwrap_or_else(|| Ttl::from_wire(3600));
    let mut groups: HashMap<RrsetKey, PendingRrset> = HashMap::new();
    for record in parsed.records {
        let key = (record.owner().clone(), record.rr_type());
        match groups.entry(key) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                if entry.get().0 != record.ttl() {
                    return Err(format!(
                        "{}: TTL mismatch for {} {}: {} and {}",
                        path.display(),
                        record.owner(),
                        record.rr_type(),
                        entry.get().0,
                        record.ttl()
                    ));
                }
                entry.get_mut().1.push(record.rdata().clone());
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert((record.ttl(), vec![record.rdata().clone()]));
            }
        }
    }
    let mut entries: Vec<(RrsetKey, PendingRrset)> = groups.into_iter().collect();
    entries.sort_by(|(left, _), (right, _)| {
        left.0
            .to_string()
            .cmp(&right.0.to_string())
            .then_with(|| left.1.as_u16().cmp(&right.1.as_u16()))
    });
    let mut rrsets = Vec::with_capacity(entries.len());
    for ((owner, rr_type), (ttl, rdatas)) in entries {
        let rrset =
            Rrset::new(owner.clone(), rr_type, Rclass::IN, ttl, rdatas).map_err(|error| {
                format!(
                    "{}: cannot build RRset {owner} {rr_type}: {error}",
                    path.display()
                )
            })?;
        rrsets.push(rrset);
    }
    Ok(LoadedZone {
        origin: parsed.origin,
        default_ttl,
        rrsets,
    })
}

fn format_parse_error(path: &std::path::Path, error: &ParseError) -> String {
    format!(
        "{}: {}",
        format_location(path, error.location()),
        error.kind()
    )
}

fn format_location(path: &std::path::Path, location: &Location) -> String {
    let source = if matches!(location.source.as_str(), "<input>" | "<zone>") {
        path.display().to_string()
    } else {
        location.source.clone()
    };
    if location.line == 0 {
        source
    } else {
        format!("{source}:{}:{}", location.line, location.column)
    }
}
