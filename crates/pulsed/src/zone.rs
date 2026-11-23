//! Загрузка зон из конфигурации в in-memory store и валидация инвариантов.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use pulse_dns::{Name, Rclass, Rdata, Rrset, Rtype, Ttl};
use pulse_server::testkit::InMemoryZone;
use pulse_server::{QueryEngine, ZoneView};
use thiserror::Error;

use crate::config::ZoneConfig;
use crate::{names, rdata};

/// Ошибка загрузки зоны.
///
/// Сообщение содержит зону, индекс записи и конкретное нарушение; цепочка
/// источников намеренно сведена к строке, потому что ошибка конфигурации
/// исправляется человеком, а не программно.
#[derive(Debug, Error)]
#[error("{0}")]
pub struct ZoneError(String);

impl ZoneError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

/// Собирает [`QueryEngine`] из конфигурации зон.
///
/// # Errors
///
/// [`ZoneError`], если origin/имя/тип/RDATA некорректны, отсутствуют apex
/// `SOA`/`NS`, нарушена CNAME-эксклюзивность, обнаружен цикл CNAME или
/// различаются TTL записей одного RRset.
pub fn build_engine(zones: &[ZoneConfig]) -> Result<QueryEngine, ZoneError> {
    let mut views: Vec<Arc<dyn ZoneView>> = Vec::with_capacity(zones.len());
    let mut origins = HashSet::with_capacity(zones.len());
    for config in zones {
        let zone = build_zone(config)?;
        if !origins.insert(zone.origin().clone()) {
            return Err(ZoneError::new(format!(
                "zone {} is declared more than once",
                zone.origin()
            )));
        }
        views.push(Arc::new(zone));
    }
    Ok(QueryEngine::new(views))
}

struct Pending {
    ttl: Ttl,
    rdatas: Vec<Rdata>,
}

#[allow(clippy::too_many_lines)]
fn build_zone(config: &ZoneConfig) -> Result<InMemoryZone, ZoneError> {
    let origin = Name::parse(config.origin.trim()).map_err(|error| {
        ZoneError::new(format!("invalid zone origin {:?}: {error}", config.origin))
    })?;
    if !config.class.eq_ignore_ascii_case("IN") && config.class != "1" {
        return Err(ZoneError::new(format!(
            "zone {origin}: class {:?} is not supported (only IN)",
            config.class
        )));
    }
    let default_ttl = Ttl::new(config.default_ttl).map_err(|error| {
        ZoneError::new(format!(
            "zone {origin}: invalid default_ttl {}: {error}",
            config.default_ttl
        ))
    })?;

    let mut groups: HashMap<(Name, Rtype), Pending> = HashMap::new();
    for (index, record) in config.records.iter().enumerate() {
        let number = index + 1;
        let owner = names::qualify(&record.name, &origin).map_err(|error| {
            ZoneError::new(format!(
                "zone {origin}, record {number}: invalid owner {:?}: {error}",
                record.name
            ))
        })?;
        let rr_type = rdata::parse_type(&record.rr_type).map_err(|error| {
            ZoneError::new(format!(
                "zone {origin}, record {number} ({owner}): invalid type {:?}: {error}",
                record.rr_type
            ))
        })?;
        if matches!(
            rr_type,
            Rtype::OPT | Rtype::ANY | Rtype::AXFR | Rtype::IXFR | Rtype::TKEY | Rtype::TSIG
        ) {
            return Err(ZoneError::new(format!(
                "zone {origin}, record {number} ({owner}): {rr_type} is not zone data"
            )));
        }
        let ttl = Ttl::new(record.ttl.unwrap_or(default_ttl.as_u32())).map_err(|error| {
            ZoneError::new(format!(
                "zone {origin}, record {number} ({owner} {rr_type}): invalid ttl: {error}"
            ))
        })?;
        let value = rdata::parse(rr_type, &record.rdata, &origin).map_err(|error| {
            ZoneError::new(format!(
                "zone {origin}, record {number} ({owner} {rr_type}): {error}"
            ))
        })?;
        match groups.entry((owner.clone(), rr_type)) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                if entry.get().ttl != ttl {
                    return Err(ZoneError::new(format!(
                        "zone {origin}: TTL mismatch for {owner} {rr_type}: {} and {}",
                        entry.get().ttl,
                        ttl.as_u32()
                    )));
                }
                entry.get_mut().rdatas.push(value);
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(Pending {
                    ttl,
                    rdatas: vec![value],
                });
            }
        }
    }

    validate_apex(&origin, &groups)?;
    validate_cnames(&origin, &groups)?;

    let mut zone = InMemoryZone::new(origin.clone());
    let mut entries: Vec<((Name, Rtype), Pending)> = groups.into_iter().collect();
    entries.sort_by(|(left_key, _), (right_key, _)| {
        left_key
            .0
            .to_string()
            .cmp(&right_key.0.to_string())
            .then_with(|| left_key.1.as_u16().cmp(&right_key.1.as_u16()))
    });
    for ((owner, rr_type), pending) in entries {
        let rrset = Rrset::new(
            owner.clone(),
            rr_type,
            Rclass::IN,
            pending.ttl,
            pending.rdatas,
        )
        .map_err(|error| {
            ZoneError::new(format!(
                "zone {origin}: cannot build RRset {owner} {rr_type}: {error}"
            ))
        })?;
        zone.insert(rrset).map_err(|error| {
            ZoneError::new(format!(
                "zone {origin}: cannot insert RRset {owner} {rr_type}: {error}"
            ))
        })?;
    }
    Ok(zone)
}

fn validate_apex(origin: &Name, groups: &HashMap<(Name, Rtype), Pending>) -> Result<(), ZoneError> {
    for (owner, rr_type) in groups.keys() {
        if *rr_type == Rtype::SOA && owner != origin {
            return Err(ZoneError::new(format!(
                "zone {origin}: SOA is only allowed at the apex, found at {owner}"
            )));
        }
    }
    let Some(soa) = groups.get(&(origin.clone(), Rtype::SOA)) else {
        return Err(ZoneError::new(format!(
            "zone {origin}: apex SOA record is required"
        )));
    };
    if soa.rdatas.len() != 1 {
        return Err(ZoneError::new(format!(
            "zone {origin}: apex must contain exactly one SOA record, got {}",
            soa.rdatas.len()
        )));
    }
    let Some(ns) = groups.get(&(origin.clone(), Rtype::NS)) else {
        return Err(ZoneError::new(format!(
            "zone {origin}: apex NS record is required"
        )));
    };
    if ns.rdatas.is_empty() {
        return Err(ZoneError::new(format!(
            "zone {origin}: apex NS record set is empty"
        )));
    }
    Ok(())
}

fn validate_cnames(
    origin: &Name,
    groups: &HashMap<(Name, Rtype), Pending>,
) -> Result<(), ZoneError> {
    let mut by_owner: HashMap<Name, Vec<Rtype>> = HashMap::new();
    for (owner, rr_type) in groups.keys() {
        by_owner.entry(owner.clone()).or_default().push(*rr_type);
    }

    for (owner, types) in &by_owner {
        if !types.contains(&Rtype::CNAME) {
            continue;
        }
        if owner == origin {
            return Err(ZoneError::new(format!(
                "zone {origin}: CNAME is not allowed at the apex"
            )));
        }
        let others: Vec<Rtype> = types
            .iter()
            .copied()
            .filter(|rr_type| {
                *rr_type != Rtype::CNAME
                    && !matches!(*rr_type, Rtype::RRSIG | Rtype::NSEC | Rtype::NSEC3)
            })
            .collect();
        if !others.is_empty() {
            let others = others
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            return Err(ZoneError::new(format!(
                "zone {origin}: CNAME at {owner} cannot coexist with {others}"
            )));
        }
        let Some(cname) = groups.get(&(owner.clone(), Rtype::CNAME)) else {
            continue;
        };
        if cname.rdatas.len() != 1 {
            return Err(ZoneError::new(format!(
                "zone {origin}: CNAME at {owner} must have exactly one target, got {}",
                cname.rdatas.len()
            )));
        }
        let Some(Rdata::Cname(target)) = cname.rdatas.first() else {
            return Err(ZoneError::new(format!(
                "zone {origin}: CNAME at {owner} has unexpected rdata"
            )));
        };
        detect_cname_loop(origin, owner, target, groups)?;
    }
    Ok(())
}

fn detect_cname_loop(
    origin: &Name,
    start: &Name,
    target: &Name,
    groups: &HashMap<(Name, Rtype), Pending>,
) -> Result<(), ZoneError> {
    const MAX_CHAIN: usize = 64;
    let mut current = target.clone();
    let mut visited = HashSet::new();
    visited.insert(start.clone());
    for _ in 0..MAX_CHAIN {
        if &current == start || !visited.insert(current.clone()) {
            return Err(ZoneError::new(format!(
                "zone {origin}: CNAME loop starting at {start}"
            )));
        }
        if !current.is_subdomain_of(origin) {
            return Ok(());
        }
        let Some(next) = groups.get(&(current.clone(), Rtype::CNAME)) else {
            return Ok(());
        };
        let Some(Rdata::Cname(next_target)) = next.rdatas.first() else {
            return Ok(());
        };
        current = next_target.clone();
    }
    Err(ZoneError::new(format!(
        "zone {origin}: CNAME chain starting at {start} exceeds {MAX_CHAIN} links"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn engine_from(json: &str) -> Result<QueryEngine, ZoneError> {
        let config = Config::from_json_str(json).unwrap();
        build_engine(&config.zones)
    }

    const HEADER: &str = r#"{
        "listen_udp": null,
        "listen_tcp": null,
        "zones": [{
            "origin": "example.com.",
            "records": [
                {"name": "@", "type": "SOA", "rdata": {
                    "mname": "ns1", "rname": "hostmaster", "serial": 1,
                    "refresh": 3600, "retry": 600, "expire": 604800, "minimum": 300
                }},
                {"name": "@", "type": "NS", "rdata": "ns1"}
            ]
        }]
    }"#;

    #[test]
    fn loads_minimal_zone() {
        assert!(engine_from(HEADER).is_ok());
    }

    #[test]
    fn requires_apex_soa() {
        let json = HEADER.replace("\"type\": \"SOA\"", "\"type\": \"TXT\"");
        assert!(engine_from(&json).is_err());
    }

    #[test]
    fn rejects_cname_conflict() {
        let json = r#"{
            "zones": [{
                "origin": "example.com.",
                "records": [
                    {"name": "@", "type": "SOA", "rdata": {
                        "mname": "ns1", "rname": "hostmaster", "serial": 1,
                        "refresh": 3600, "retry": 600, "expire": 604800, "minimum": 300
                    }},
                    {"name": "@", "type": "NS", "rdata": "ns1"},
                    {"name": "www", "type": "CNAME", "rdata": "target"},
                    {"name": "www", "type": "A", "rdata": "192.0.2.1"}
                ]
            }]
        }"#;
        assert!(engine_from(json).is_err());
    }

    #[test]
    fn rejects_cname_loop() {
        let json = r#"{
            "zones": [{
                "origin": "example.com.",
                "records": [
                    {"name": "@", "type": "SOA", "rdata": {
                        "mname": "ns1", "rname": "hostmaster", "serial": 1,
                        "refresh": 3600, "retry": 600, "expire": 604800, "minimum": 300
                    }},
                    {"name": "@", "type": "NS", "rdata": "ns1"},
                    {"name": "a", "type": "CNAME", "rdata": "b"},
                    {"name": "b", "type": "CNAME", "rdata": "a"}
                ]
            }]
        }"#;
        assert!(engine_from(json).is_err());
    }

    #[test]
    fn rejects_ttl_mismatch() {
        let json = r#"{
            "zones": [{
                "origin": "example.com.",
                "records": [
                    {"name": "@", "type": "SOA", "ttl": 3600, "rdata": {
                        "mname": "ns1", "rname": "hostmaster", "serial": 1,
                        "refresh": 3600, "retry": 600, "expire": 604800, "minimum": 300
                    }},
                    {"name": "@", "type": "NS", "ttl": 3600, "rdata": "ns1"},
                    {"name": "www", "type": "A", "ttl": 60, "rdata": "192.0.2.1"},
                    {"name": "www", "type": "A", "ttl": 120, "rdata": "192.0.2.2"}
                ]
            }]
        }"#;
        assert!(engine_from(json).is_err());
    }
}
