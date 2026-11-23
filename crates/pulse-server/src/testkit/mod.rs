//! In-memory реализация [`ZoneView`] для тестов и встраивания без zone store.
//!
//! Зона хранится как `HashMap<(Name, Rtype), Rrset>` плюс множество узлов
//! (включая empty non-terminals) и множество zone cut'ов. Порядок RDATA внутри
//! набора наследуется от [`Rrset`] (каноническая форма), поэтому ответы
//! детерминированы.

use std::collections::{HashMap, HashSet};

use pulse_dns::{Name, Rclass, Rdata, Rrset, Rtype};
use thiserror::Error;

use crate::application::ZoneView;
use crate::domain::{LookupOutcome, ZoneState};

/// Ошибка наполнения in-memory зоны.
#[derive(Debug, Error)]
pub enum MemoryZoneError {
    /// Владелец RRset вне origin зоны.
    #[error("owner {owner} is outside zone {origin}")]
    OwnerOutsideZone {
        /// Владелец набора.
        owner: Name,
        /// Origin зоны.
        origin: Name,
    },
    /// Класс RRset не совпадает с классом зоны.
    #[error("rrset class {class} does not match zone class {zone}")]
    ClassMismatch {
        /// Класс набора.
        class: Rclass,
        /// Класс зоны.
        zone: Rclass,
    },
    /// `SOA` вне apex запрещён (INV-4).
    #[error("SOA must be at zone apex {origin}, got {owner}")]
    SoaNotAtApex {
        /// Владелец `SOA`.
        owner: Name,
        /// Origin зоны.
        origin: Name,
    },
    /// `DNAME` в apex запрещён (INV-6).
    #[error("DNAME must not be at zone apex {origin}")]
    DnameAtApex {
        /// Origin зоны.
        origin: Name,
    },
}

/// In-memory зона, реализующая [`ZoneView`].
///
/// Используется в тестах и как референсная реализация порта. Данные
/// добавляются через [`InMemoryZone::insert`]; повторная вставка того же
/// `(owner, type)` заменяет набор целиком (как `UpsertRrset`).
///
/// Реализация намеренно не проверяет все инварианты зоны (`CNAME`-
/// эксклюзивность, `DNAME`/`CNAME`-конфликты, данные ниже cut): это
/// ответственность zone store, а тестам нужна возможность собрать и
/// намеренно спорную конфигурацию. Проверяются только `SOA` в apex (INV-4)
/// и запрет `DNAME` в apex (INV-6).
#[derive(Debug, Clone)]
pub struct InMemoryZone {
    origin: Name,
    class: Rclass,
    state: ZoneState,
    rrsets: HashMap<(Name, Rtype), Rrset>,
    nodes: HashSet<Name>,
    cuts: HashSet<Name>,
    soa: Option<Rrset>,
    ns: Option<Rrset>,
}

impl InMemoryZone {
    /// Создаёт пустую `Serving`-зону класса `IN`.
    ///
    /// Пустая `Serving`-зона без `SOA` не отвечает на запросы (движок вернёт
    /// `SERVFAIL`); наполните её хотя бы apex `SOA`/`NS`.
    #[must_use]
    pub fn new(origin: Name) -> Self {
        Self {
            origin,
            class: Rclass::IN,
            state: ZoneState::Serving,
            rrsets: HashMap::new(),
            nodes: HashSet::new(),
            cuts: HashSet::new(),
            soa: None,
            ns: None,
        }
    }

    /// Задаёт состояние зоны.
    #[must_use]
    pub fn with_state(mut self, state: ZoneState) -> Self {
        self.state = state;
        self
    }

    /// Добавляет или заменяет RRset.
    ///
    /// # Errors
    ///
    /// [`MemoryZoneError`], если владелец вне зоны, класс не совпадает или
    /// `SOA` находится не в apex.
    pub fn insert(&mut self, rrset: Rrset) -> Result<(), MemoryZoneError> {
        if rrset.class() != self.class {
            return Err(MemoryZoneError::ClassMismatch {
                class: rrset.class(),
                zone: self.class,
            });
        }
        if !rrset.owner().is_subdomain_of(&self.origin) {
            return Err(MemoryZoneError::OwnerOutsideZone {
                owner: rrset.owner().clone(),
                origin: self.origin.clone(),
            });
        }
        if rrset.rr_type() == Rtype::SOA && rrset.owner() != &self.origin {
            return Err(MemoryZoneError::SoaNotAtApex {
                owner: rrset.owner().clone(),
                origin: self.origin.clone(),
            });
        }
        if rrset.rr_type() == Rtype::DNAME && rrset.owner() == &self.origin {
            return Err(MemoryZoneError::DnameAtApex {
                origin: self.origin.clone(),
            });
        }

        self.register_node(rrset.owner());
        if rrset.rr_type() == Rtype::NS && rrset.owner() != &self.origin {
            self.cuts.insert(rrset.owner().clone());
        }
        if rrset.owner() == &self.origin {
            match rrset.rr_type() {
                Rtype::SOA => self.soa = Some(rrset.clone()),
                Rtype::NS => self.ns = Some(rrset.clone()),
                _ => {}
            }
        }
        self.rrsets
            .insert((rrset.owner().clone(), rrset.rr_type()), rrset);
        Ok(())
    }

    fn register_node(&mut self, owner: &Name) {
        let mut current = Some(owner.clone());
        while let Some(name) = current {
            let is_origin = name == self.origin;
            self.nodes.insert(name.clone());
            if is_origin {
                break;
            }
            current = name.parent();
        }
    }

    fn delegation_for(&self, name: &Name) -> Option<&Name> {
        self.cuts
            .iter()
            .filter(|cut| name.is_subdomain_of(cut))
            .max_by_key(|cut| cut.label_count())
    }
}

impl ZoneView for InMemoryZone {
    fn origin(&self) -> &Name {
        &self.origin
    }

    fn apex(&self) -> &Name {
        &self.origin
    }

    fn soa(&self) -> Option<&Rrset> {
        self.soa.as_ref()
    }

    fn ns(&self) -> Option<&Rrset> {
        self.ns.as_ref()
    }

    fn class(&self) -> Rclass {
        self.class
    }

    fn state(&self) -> ZoneState {
        self.state
    }

    fn lookup(&self, name: &Name, rtype: Rtype) -> LookupOutcome {
        if !name.is_subdomain_of(&self.origin) {
            return LookupOutcome::ZoneNotFound;
        }

        if let Some(cut) = self.delegation_for(name) {
            if name != cut {
                return LookupOutcome::Referral;
            }
            if rtype == Rtype::DS {
                return match self.rrsets.get(&(name.clone(), Rtype::DS)) {
                    Some(ds) => LookupOutcome::Answer(ds.clone()),
                    None => LookupOutcome::NoData,
                };
            }
            let ns = self.rrsets.get(&(cut.clone(), Rtype::NS));
            let ds = self.rrsets.get(&(cut.clone(), Rtype::DS));
            return match ns {
                Some(ns) => LookupOutcome::Delegation {
                    ns: ns.clone(),
                    ds: ds.cloned(),
                },
                None => LookupOutcome::Referral,
            };
        }

        if let Some(rrset) = self.rrsets.get(&(name.clone(), rtype)) {
            return LookupOutcome::Answer(rrset.clone());
        }
        if rtype != Rtype::CNAME
            && let Some(cname) = self.rrsets.get(&(name.clone(), Rtype::CNAME))
        {
            let target = cname.rdatas().iter().find_map(|rdata| match rdata {
                Rdata::Cname(target) => Some(target.clone()),
                _ => None,
            });
            if let Some(target) = target {
                return LookupOutcome::Cname(cname.clone(), target);
            }
        }
        if self.nodes.contains(name) {
            LookupOutcome::NoData
        } else {
            LookupOutcome::NxDomain
        }
    }

    fn lookup_all_rrsig(&self, name: &Name, covered: Rtype) -> Vec<Rrset> {
        let Some(rrsig) = self.rrsets.get(&(name.clone(), Rtype::RRSIG)) else {
            return Vec::new();
        };
        let rdatas: Vec<Rdata> = rrsig
            .rdatas()
            .iter()
            .filter(|rdata| match rdata {
                Rdata::Rrsig(signature) => signature.type_covered() == covered,
                _ => false,
            })
            .cloned()
            .collect();
        if rdatas.is_empty() {
            return Vec::new();
        }
        match Rrset::new(
            name.clone(),
            Rtype::RRSIG,
            rrsig.class(),
            rrsig.ttl(),
            rdatas,
        ) {
            Ok(rrset) => vec![rrset],
            Err(_) => Vec::new(),
        }
    }

    fn is_delegation(&self, name: &Name) -> bool {
        self.cuts.contains(name)
    }

    fn glue(&self, name: &Name) -> Vec<Rrset> {
        if !name.is_subdomain_of(&self.origin) {
            return Vec::new();
        }
        let mut result = Vec::new();
        for rtype in [Rtype::A, Rtype::AAAA] {
            if let Some(rrset) = self.rrsets.get(&(name.clone(), rtype)) {
                result.push(rrset.clone());
            }
        }
        result
    }

    fn node_exists(&self, name: &Name) -> bool {
        self.nodes.contains(name)
    }
}
