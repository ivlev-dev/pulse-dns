//! Статические overrides (hosts/локальные зоны).
//!
//! Overrides имеют приоритет выше blocklist и upstream. Поддерживаются
//! `A`, `AAAA` и `CNAME`; `CNAME`-цепочка разрешается внутри самих
//! overrides и не ходит в сеть.

use std::collections::HashMap;

use pulse_dns::{Name, Rclass, Rdata, Record, Rtype, Ttl};

use crate::config::Override;

/// Результат поиска в overrides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverrideOutcome {
    /// Готовый ответ.
    Answer(Vec<Record>),
    /// Имя задано, но запрошенного типа нет.
    NoData,
    /// Имени нет в overrides.
    Miss,
}

#[derive(Debug)]
struct Entry {
    ttl: Ttl,
    data: Vec<Rdata>,
}

/// Снимок статических overrides.
#[derive(Debug, Default)]
pub struct Overrides {
    exact: HashMap<Name, Entry>,
    wildcard: HashMap<Name, Entry>,
}

impl Overrides {
    /// Строит overrides из конфигурации.
    ///
    /// # Errors
    ///
    /// [`crate::ResolverError::Config`] при противоречивых записях
    /// (CNAME вместе с адресами, разные TTL для одного имени).
    pub fn build(entries: &[Override]) -> Result<Self, crate::ResolverError> {
        let mut all: HashMap<Name, Entry> = HashMap::new();
        for entry in entries {
            if !entry
                .data
                .iter()
                .all(|rdata| matches!(rdata.rr_type(), Rtype::A | Rtype::AAAA | Rtype::CNAME))
            {
                return Err(crate::ResolverError::config(
                    "override supports only A, AAAA and CNAME records",
                ));
            }
            let cnames = entry
                .data
                .iter()
                .filter(|rdata| rdata.rr_type() == Rtype::CNAME)
                .count();
            if cnames > 1 || (cnames == 1 && entry.data.len() > 1) {
                return Err(crate::ResolverError::config(
                    "override must be either one CNAME or address records",
                ));
            }
            let existing = all.entry(entry.name.clone()).or_insert_with(|| Entry {
                ttl: entry.ttl,
                data: Vec::new(),
            });
            if !existing.data.is_empty() {
                if existing.ttl != entry.ttl {
                    return Err(crate::ResolverError::config(
                        "override TTL must be consistent for one name",
                    ));
                }
                let has_cname = existing
                    .data
                    .iter()
                    .any(|rdata| rdata.rr_type() == Rtype::CNAME);
                if has_cname
                    || entry
                        .data
                        .iter()
                        .any(|rdata| rdata.rr_type() == Rtype::CNAME)
                {
                    return Err(crate::ResolverError::config(
                        "duplicate CNAME or CNAME mixed with address records",
                    ));
                }
            }
            for rdata in &entry.data {
                if !existing.data.contains(rdata) {
                    existing.data.push(rdata.clone());
                }
            }
        }

        let mut overrides = Self::default();
        for (name, entry) in all {
            if name.is_wildcard_owner() {
                let Some(parent) = name.parent() else {
                    return Err(crate::ResolverError::config(
                        "wildcard override cannot be the root",
                    ));
                };
                if overrides.wildcard.insert(parent, entry).is_some() {
                    return Err(crate::ResolverError::config("duplicate wildcard override"));
                }
            } else {
                overrides.exact.insert(name, entry);
            }
        }
        Ok(overrides)
    }

    /// Ищет ответ, NODATA или промах.
    ///
    /// Промах не аллоцирует: обход идёт по wire-суффиксам имени, а
    /// `HashMap` ищется по заимствованному `&[u8]`.
    #[must_use]
    pub fn lookup(&self, name: &Name, qtype: Rtype) -> OverrideOutcome {
        if self.exact.is_empty() && self.wildcard.is_empty() {
            return OverrideOutcome::Miss;
        }
        let mut current = name.as_wire();
        let mut answer = Vec::new();
        let mut visited = [&[][..]; 16];
        for step in 0..16 {
            if visited.get(..step).unwrap_or(&[]).contains(&current) {
                return OverrideOutcome::Answer(answer);
            }
            if let Some(slot) = visited.get_mut(step) {
                *slot = current;
            }
            let Some(entry) = self.find(current) else {
                return if answer.is_empty() {
                    OverrideOutcome::Miss
                } else {
                    OverrideOutcome::Answer(answer)
                };
            };
            if let Some(cname) = entry
                .data
                .iter()
                .find(|rdata| rdata.rr_type() == Rtype::CNAME)
            {
                if let Ok(owner) = Name::from_wire(current)
                    && let Some(record) = build_record(&owner, entry.ttl, cname)
                {
                    answer.push(record);
                }
                if qtype == Rtype::CNAME {
                    return OverrideOutcome::Answer(answer);
                }
                let Rdata::Cname(target) = cname else {
                    return OverrideOutcome::Answer(answer);
                };
                current = target.as_wire();
                continue;
            }
            let Ok(owner) = Name::from_wire(current) else {
                return OverrideOutcome::Answer(answer);
            };
            let matching: Vec<Record> = entry
                .data
                .iter()
                .filter(|rdata| rdata.rr_type() == qtype)
                .filter_map(|rdata| build_record(&owner, entry.ttl, rdata))
                .collect();
            if matching.is_empty() {
                return if answer.is_empty() {
                    OverrideOutcome::NoData
                } else {
                    OverrideOutcome::Answer(answer)
                };
            }
            answer.extend(matching);
            return OverrideOutcome::Answer(answer);
        }
        OverrideOutcome::Answer(answer)
    }

    fn find(&self, wire: &[u8]) -> Option<&Entry> {
        if let Some(entry) = self.exact.get(wire) {
            return Some(entry);
        }
        let mut position = 0_usize;
        loop {
            let length = *wire.get(position)?;
            if length == 0 {
                return None;
            }
            position = position
                .checked_add(1)
                .and_then(|value| value.checked_add(usize::from(length)))?;
            let suffix = wire.get(position..)?;
            if let Some(entry) = self.wildcard.get(suffix) {
                return Some(entry);
            }
        }
    }

    /// Число заданных имён.
    #[must_use]
    pub fn len(&self) -> usize {
        self.exact.len() + self.wildcard.len()
    }

    /// Пусты ли overrides.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn build_record(owner: &Name, ttl: Ttl, rdata: &Rdata) -> Option<Record> {
    Record::new(
        owner.clone(),
        rdata.rr_type(),
        Rclass::IN,
        ttl,
        rdata.clone(),
    )
    .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn name(value: &str) -> Name {
        Name::parse(value).unwrap()
    }

    #[test]
    fn exact_override_answers() {
        let overrides = Overrides::build(&[Override::a(
            name("example.com"),
            Ttl::new(60).unwrap(),
            Ipv4Addr::new(192, 0, 2, 1),
        )])
        .unwrap();
        match overrides.lookup(&name("example.com"), Rtype::A) {
            OverrideOutcome::Answer(records) => assert_eq!(records.len(), 1),
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(
            overrides.lookup(&name("example.com"), Rtype::AAAA),
            OverrideOutcome::NoData
        );
        assert_eq!(
            overrides.lookup(&name("other.example.com"), Rtype::A),
            OverrideOutcome::Miss
        );
    }

    #[test]
    fn wildcard_override_matches_subdomains() {
        let overrides = Overrides::build(&[Override::a(
            name("*.example.com"),
            Ttl::new(60).unwrap(),
            Ipv4Addr::new(192, 0, 2, 2),
        )])
        .unwrap();
        match overrides.lookup(&name("www.example.com"), Rtype::A) {
            OverrideOutcome::Answer(records) => {
                assert_eq!(
                    records.first().map(Record::owner),
                    Some(&name("www.example.com"))
                );
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(
            overrides.lookup(&name("example.com"), Rtype::A),
            OverrideOutcome::Miss
        );
    }

    #[test]
    fn cname_chain_is_followed() {
        let overrides = Overrides::build(&[
            Override::cname(
                name("alias.example.com"),
                Ttl::new(60).unwrap(),
                name("host.example.com"),
            ),
            Override::a(
                name("host.example.com"),
                Ttl::new(60).unwrap(),
                Ipv4Addr::new(192, 0, 2, 3),
            ),
        ])
        .unwrap();
        match overrides.lookup(&name("alias.example.com"), Rtype::A) {
            OverrideOutcome::Answer(records) => {
                assert_eq!(records.len(), 2);
                assert_eq!(records.first().map(Record::rr_type), Some(Rtype::CNAME));
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}
