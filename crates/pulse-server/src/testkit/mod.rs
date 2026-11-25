//! In-memory реализация [`ZoneView`] для тестов и встраивания без zone store.
//!
//! Зона хранится как `HashMap<(Name, Rtype), Rrset>` плюс множество узлов
//! (включая empty non-terminals) и множество zone cut'ов. Порядок RDATA внутри
//! набора наследуется от [`Rrset`] (каноническая форма), поэтому ответы
//! детерминированы.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

use pulse_dns::{Name, NameRef, Rclass, Rdata, Rrset, Rtype};
use thiserror::Error;

use crate::application::{ZoneSnapshot, ZoneView};
use crate::domain::{DenialKind, LookupOutcome, LookupOutcomeRef, RefLookup, RrsetRef, ZoneState};

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
    rrsets: HashMap<Name, HashMap<Rtype, Rrset>>,
    nodes: HashSet<Name>,
    cuts: HashSet<Name>,
    soa: Option<Rrset>,
    ns: Option<Rrset>,
    /// NSEC-наборы в каноническом порядке владельцев.
    nsec: Vec<(Name, Rrset)>,
    /// NSEC3-наборы по hashed-владельцу (декодированный hash, возрастание).
    nsec3: Vec<(Vec<u8>, Rrset)>,
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
            nsec: Vec::new(),
            nsec3: Vec::new(),
        }
    }

    /// Задаёт состояние зоны.
    #[must_use]
    pub fn with_state(mut self, state: ZoneState) -> Self {
        self.state = state;
        self
    }

    /// Регистрирует узел без RRset (empty node / empty non-terminal).
    ///
    /// Нужно адаптерам store-to-`ZoneView`: после удаления последнего RRset
    /// имя может остаться существующим и отвечать `NODATA`, а не `NXDOMAIN`.
    ///
    /// # Errors
    ///
    /// [`MemoryZoneError::OwnerOutsideZone`], если имя вне origin зоны.
    pub fn insert_node(&mut self, name: Name) -> Result<(), MemoryZoneError> {
        if !name.is_subdomain_of(&self.origin) {
            return Err(MemoryZoneError::OwnerOutsideZone {
                owner: name,
                origin: self.origin.clone(),
            });
        }
        self.register_node(&name);
        Ok(())
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
        let is_nsec = rrset.rr_type() == Rtype::NSEC;
        let nsec_owner = is_nsec.then(|| (rrset.owner().clone(), rrset.clone()));
        let nsec3_entry = if rrset.rr_type() == Rtype::NSEC3 {
            nsec3_hash_of(rrset.owner()).map(|hash| (hash, rrset.clone()))
        } else {
            None
        };
        self.rrsets
            .entry(rrset.owner().clone())
            .or_default()
            .insert(rrset.rr_type(), rrset);
        if let Some((owner, nsec)) = nsec_owner {
            Self::insert_sorted(&mut self.nsec, owner, nsec, |owner, other| {
                owner.cmp_canonical(other)
            });
        }
        if let Some((hash, nsec3)) = nsec3_entry {
            Self::insert_sorted(&mut self.nsec3, hash, nsec3, |hash, other| {
                hash.as_slice().cmp(other.as_slice())
            });
        }
        Ok(())
    }

    /// Вставляет элемент в отсортированный `Vec`, заменяя равный ключ.
    fn insert_sorted<K, V>(
        items: &mut Vec<(K, V)>,
        key: K,
        value: V,
        compare: impl Fn(&K, &K) -> Ordering,
    ) {
        let position =
            items.partition_point(|(existing, _)| compare(existing, &key) == Ordering::Less);
        let equal = items
            .get(position)
            .is_some_and(|(existing, _)| compare(existing, &key) == Ordering::Equal);
        if equal {
            if let Some(slot) = items.get_mut(position) {
                slot.1 = value;
            }
        } else {
            items.insert(position, (key, value));
        }
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

    fn rrsets_at(&self, name: &Name) -> Option<&HashMap<Rtype, Rrset>> {
        self.rrsets.get(name.as_wire())
    }

    fn get_rrset(&self, name: &Name, rtype: Rtype) -> Option<&Rrset> {
        self.rrsets_at(name)?.get(&rtype)
    }

    fn get_rrset_wire(&self, wire: &[u8], rtype: Rtype) -> Option<&Rrset> {
        self.rrsets.get(wire)?.get(&rtype)
    }

    fn delegation_for(&self, name: &Name) -> Option<&Name> {
        self.cuts
            .iter()
            .filter(|cut| name.is_subdomain_of(cut))
            .max_by_key(|cut| cut.label_count())
    }

    fn delegation_for_ref(&self, name: NameRef<'_>) -> Option<&Name> {
        self.cuts
            .iter()
            .filter(|cut| name.is_subdomain_of_name(cut))
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
                return match self.get_rrset(name, Rtype::DS) {
                    Some(ds) => LookupOutcome::Answer(ds.clone()),
                    None => LookupOutcome::NoData,
                };
            }
            let ns = self.get_rrset(cut, Rtype::NS);
            let ds = self.get_rrset(cut, Rtype::DS);
            return match ns {
                Some(ns) => LookupOutcome::Delegation {
                    ns: ns.clone(),
                    ds: ds.cloned(),
                },
                None => LookupOutcome::Referral,
            };
        }

        if let Some(rrset) = self.get_rrset(name, rtype) {
            return LookupOutcome::Answer(rrset.clone());
        }
        if rtype != Rtype::CNAME
            && let Some(cname) = self.get_rrset(name, Rtype::CNAME)
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
        let Some(rrsig) = self.get_rrset(name, Rtype::RRSIG) else {
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
            if let Some(rrset) = self.get_rrset(name, rtype) {
                result.push(rrset.clone());
            }
        }
        result
    }

    fn node_exists(&self, name: &Name) -> bool {
        self.nodes.contains(name)
    }

    fn with_snapshot(&self, f: &mut dyn FnMut(&dyn ZoneSnapshot)) -> bool {
        f(self);
        true
    }

    fn soa_ref(&self) -> Option<RrsetRef<'_>> {
        <Self as ZoneSnapshot>::soa_ref(self)
    }

    fn ns_ref(&self) -> Option<RrsetRef<'_>> {
        <Self as ZoneSnapshot>::ns_ref(self)
    }

    fn records_ref<'a>(&'a self, name: NameRef<'a>) -> Vec<RrsetRef<'a>> {
        <Self as ZoneSnapshot>::records_ref(self, name)
    }

    fn lookup_all_ref<'a>(&'a self, name: NameRef<'a>, rtype: Rtype) -> Vec<RrsetRef<'a>> {
        <Self as ZoneSnapshot>::lookup_all_ref(self, name, rtype)
    }

    fn lookup_ref<'a>(&'a self, name: NameRef<'a>, rtype: Rtype) -> LookupOutcomeRef<'a> {
        <Self as ZoneSnapshot>::lookup_ref(self, name, rtype)
    }

    fn nsec_at(&self, name: &Name) -> Option<Rrset> {
        self.get_rrset(name, Rtype::NSEC).cloned()
    }

    fn nsec_cover(&self, name: &Name) -> Option<Rrset> {
        let (owner, rrset) = nsec_candidate(&self.nsec, NameRef::from_name(name))?;
        if owner.as_wire() == name.as_wire() {
            return None;
        }
        let next = rrset.rdatas().iter().find_map(|rdata| match rdata {
            Rdata::Nsec(nsec) => Some(nsec.next_domain()),
            _ => None,
        })?;
        nsec_covers_ref(owner, NameRef::from_name(next), NameRef::from_name(name))
            .then(|| rrset.clone())
    }

    fn denial(&self) -> DenialKind {
        if self.get_rrset(&self.origin, Rtype::NSEC3PARAM).is_some() {
            DenialKind::Nsec3
        } else {
            DenialKind::Nsec
        }
    }

    fn nsec3_param(&self) -> Option<Rrset> {
        self.get_rrset(&self.origin, Rtype::NSEC3PARAM).cloned()
    }

    fn nsec3_at(&self, hash: &[u8]) -> Option<Rrset> {
        let owner = pulse_dnssec::denial::nsec3_owner_name(&self.origin, hash).ok()?;
        self.get_rrset(&owner, Rtype::NSEC3).cloned()
    }

    fn nsec3_cover(&self, hash: &[u8]) -> Option<Rrset> {
        let (owner_hash, rrset) = nsec3_candidate(&self.nsec3, hash)?;
        if owner_hash == hash {
            return None;
        }
        let next = rrset.rdatas().iter().find_map(|rdata| match rdata {
            Rdata::Nsec3(data) => Some(data.next_hashed_owner()),
            _ => None,
        })?;
        nsec3_covers(owner_hash, next, hash).then(|| rrset.clone())
    }
}

impl ZoneSnapshot for InMemoryZone {
    fn origin_ref(&self) -> NameRef<'_> {
        NameRef::from_name(&self.origin)
    }

    fn class_ref(&self) -> Rclass {
        self.class
    }

    fn lookup_ref<'a>(&'a self, name: NameRef<'a>, rtype: Rtype) -> LookupOutcomeRef<'a> {
        if !name.is_subdomain_of_name(&self.origin) {
            return LookupOutcomeRef::ZoneNotFound;
        }

        if let Some(cut) = self.delegation_for_ref(name) {
            if name.as_wire() != cut.as_wire() {
                return LookupOutcomeRef::Referral;
            }
            if rtype == Rtype::DS {
                return match self.get_rrset(cut, Rtype::DS) {
                    Some(ds) => LookupOutcomeRef::Answer(RrsetRef::from_owned(ds)),
                    None => LookupOutcomeRef::NoData,
                };
            }
            let ns = self.get_rrset(cut, Rtype::NS);
            let ds = self.get_rrset(cut, Rtype::DS);
            return match ns {
                Some(ns) => LookupOutcomeRef::Delegation {
                    ns: RrsetRef::from_owned(ns),
                    ds: ds.map(RrsetRef::from_owned),
                },
                None => LookupOutcomeRef::Referral,
            };
        }

        if let Some(rrset) = self.get_rrset_wire(name.as_wire(), rtype) {
            return LookupOutcomeRef::Answer(RrsetRef::from_owned(rrset));
        }
        if rtype != Rtype::CNAME
            && let Some(cname) = self.get_rrset_wire(name.as_wire(), Rtype::CNAME)
        {
            let target = cname.rdatas().iter().find_map(|rdata| match rdata {
                Rdata::Cname(target) => Some(NameRef::from_name(target)),
                _ => None,
            });
            if let Some(target) = target {
                return LookupOutcomeRef::Cname(RrsetRef::from_owned(cname), target);
            }
        }
        if self.nodes.contains(name.as_wire()) {
            LookupOutcomeRef::NoData
        } else {
            LookupOutcomeRef::NxDomain
        }
    }

    fn soa_ref(&self) -> Option<RrsetRef<'_>> {
        self.soa.as_ref().map(RrsetRef::from_owned)
    }

    fn ns_ref(&self) -> Option<RrsetRef<'_>> {
        self.ns.as_ref().map(RrsetRef::from_owned)
    }

    fn records_ref<'a>(&'a self, name: NameRef<'a>) -> Vec<RrsetRef<'a>> {
        self.rrsets
            .get(name.as_wire())
            .map(|by_type| by_type.values().map(RrsetRef::from_owned).collect())
            .unwrap_or_default()
    }

    fn lookup_all_ref<'b, 's: 'b>(&'s self, name: NameRef<'b>, rtype: Rtype) -> Vec<RrsetRef<'b>> {
        self.get_rrset_wire(name.as_wire(), rtype)
            .map(RrsetRef::from_owned)
            .into_iter()
            .collect()
    }

    fn glue_ref<'a>(&'a self, name: NameRef<'a>) -> Vec<RrsetRef<'a>> {
        if !name.is_subdomain_of_name(&self.origin) {
            return Vec::new();
        }
        [Rtype::A, Rtype::AAAA]
            .into_iter()
            .filter_map(|rtype| self.get_rrset_wire(name.as_wire(), rtype))
            .map(RrsetRef::from_owned)
            .collect()
    }

    fn node_exists_ref(&self, name: NameRef<'_>) -> bool {
        self.nodes.contains(name.as_wire())
    }

    fn is_delegation_ref(&self, name: NameRef<'_>) -> bool {
        self.cuts.contains(name.as_wire())
    }

    fn glue_at_ref<'b, 's: 'b>(&'s self, name: NameRef<'b>, rtype: Rtype) -> RefLookup<'b> {
        if !name.is_subdomain_of_name(&self.origin) {
            return RefLookup::Absent;
        }
        self.get_rrset_wire(name.as_wire(), rtype)
            .map(RrsetRef::from_owned)
            .map_or(RefLookup::Absent, RefLookup::Found)
    }

    fn rrsig_ref<'b, 's: 'b>(&'s self, name: NameRef<'b>, covered: Rtype) -> RefLookup<'b> {
        self.get_rrset_wire(name.as_wire(), Rtype::RRSIG)
            .map(RrsetRef::from_owned)
            .filter(|rrset| rrset.covers(covered))
            .map_or(RefLookup::Absent, RefLookup::Found)
    }

    fn nsec_at_ref<'b, 's: 'b>(&'s self, name: NameRef<'b>) -> RefLookup<'b> {
        if !name.is_subdomain_of_name(&self.origin) {
            return RefLookup::Absent;
        }
        self.get_rrset_wire(name.as_wire(), Rtype::NSEC)
            .map(RrsetRef::from_owned)
            .map_or(RefLookup::Absent, RefLookup::Found)
    }

    fn nsec_cover_ref<'b, 's: 'b>(
        &'s self,
        name: NameRef<'_>,
        _owner_wire: &'b mut [u8; pulse_dns::MAX_NAME_WIRE_LEN],
    ) -> RefLookup<'b> {
        let Some((owner, rrset)) = nsec_candidate(&self.nsec, name) else {
            return RefLookup::Absent;
        };
        if owner.as_wire() == name.as_wire() {
            return RefLookup::Absent;
        }
        let next = rrset.rdatas().iter().find_map(|rdata| match rdata {
            Rdata::Nsec(nsec) => Some(NameRef::from_name(nsec.next_domain())),
            _ => None,
        });
        let Some(next) = next else {
            return RefLookup::Absent;
        };
        if nsec_covers_ref(owner, next, name) {
            RefLookup::Found(RrsetRef::from_owned(rrset))
        } else {
            RefLookup::Absent
        }
    }

    fn nsec3_param_ref(&self) -> RefLookup<'_> {
        self.get_rrset(&self.origin, Rtype::NSEC3PARAM)
            .map(RrsetRef::from_owned)
            .map_or(RefLookup::Absent, RefLookup::Found)
    }

    fn nsec3_at_ref<'b, 's: 'b>(
        &'s self,
        hash: &[u8],
        _owner_wire: &'b mut [u8; pulse_dns::MAX_NAME_WIRE_LEN],
    ) -> RefLookup<'b> {
        let position = self
            .nsec3
            .partition_point(|(owner, _)| owner.as_slice() < hash);
        self.nsec3
            .get(position)
            .filter(|(owner, _)| owner.as_slice() == hash)
            .map_or(RefLookup::Absent, |(_, rrset)| {
                RefLookup::Found(RrsetRef::from_owned(rrset))
            })
    }

    fn nsec3_cover_ref<'b, 's: 'b>(
        &'s self,
        hash: &[u8],
        _owner_wire: &'b mut [u8; pulse_dns::MAX_NAME_WIRE_LEN],
    ) -> RefLookup<'b> {
        let Some((owner_hash, rrset)) = nsec3_candidate(&self.nsec3, hash) else {
            return RefLookup::Absent;
        };
        if owner_hash == hash {
            return RefLookup::Absent;
        }
        let next = rrset.rdatas().iter().find_map(|rdata| match rdata {
            Rdata::Nsec3(data) => Some(data.next_hashed_owner()),
            _ => None,
        });
        let Some(next) = next else {
            return RefLookup::Absent;
        };
        if nsec3_covers(owner_hash, next, hash) {
            RefLookup::Found(RrsetRef::from_owned(rrset))
        } else {
            RefLookup::Absent
        }
    }

    fn denial_ref(&self) -> DenialKind {
        if self.get_rrset(&self.origin, Rtype::NSEC3PARAM).is_some() {
            DenialKind::Nsec3
        } else {
            DenialKind::Nsec
        }
    }

    fn signed_ref(&self) -> bool {
        self.get_rrset(&self.origin, Rtype::DNSKEY).is_some()
            && self
                .get_rrset(&self.origin, Rtype::RRSIG)
                .is_some_and(|rrsig| RrsetRef::from_owned(rrsig).covers(Rtype::DNSKEY))
    }
}

/// Наибольший NSEC-владелец не больше `name` (с заворотом на последний).
fn nsec_candidate<'a>(
    items: &'a [(Name, Rrset)],
    name: NameRef<'_>,
) -> Option<(NameRef<'a>, &'a Rrset)> {
    let position = items.partition_point(|(owner, _)| {
        NameRef::from_name(owner).cmp_canonical(name) == Ordering::Less
    });
    if let Some((owner, rrset)) = items.get(position)
        && owner.as_wire() == name.as_wire()
    {
        return Some((NameRef::from_name(owner), rrset));
    }
    let (owner, rrset) = if position == 0 {
        items.last()
    } else {
        items.get(position.saturating_sub(1))
    }?;
    Some((NameRef::from_name(owner), rrset))
}

/// Наибольший NSEC3-hash не больше `hash` (с заворотом на последний).
fn nsec3_candidate<'a>(
    items: &'a [(Vec<u8>, Rrset)],
    hash: &[u8],
) -> Option<(&'a [u8], &'a Rrset)> {
    let position = items.partition_point(|(owner, _)| owner.as_slice() < hash);
    if let Some((owner, rrset)) = items.get(position)
        && owner.as_slice() == hash
    {
        return Some((owner.as_slice(), rrset));
    }
    let (owner, rrset) = if position == 0 {
        items.last()
    } else {
        items.get(position.saturating_sub(1))
    }?;
    Some((owner.as_slice(), rrset))
}

/// Декодирует hash из первой метки hashed-владельца NSEC3.
fn nsec3_hash_of(owner: &Name) -> Option<Vec<u8>> {
    let label = owner.first_label()?;
    pulse_dnssec::denial::base32hex::decode(label).ok()
}

/// RFC 5155 §7.2: покрывает ли hash-интервал `(owner, next)` значение `hash`.
fn nsec3_covers(owner: &[u8], next: &[u8], hash: &[u8]) -> bool {
    if hash == owner {
        return false;
    }
    match owner.cmp(next) {
        Ordering::Less => hash > owner && hash < next,
        Ordering::Greater | Ordering::Equal => hash > owner || hash < next,
    }
}

/// RFC 4034 §4.1.2: покрывает ли интервал `(owner, next)` имя `name`.
fn nsec_covers_ref(owner: NameRef<'_>, next: NameRef<'_>, name: NameRef<'_>) -> bool {
    if name.as_wire() == owner.as_wire() {
        return false;
    }
    match owner.cmp_canonical(next) {
        Ordering::Less => {
            owner.cmp_canonical(name) == Ordering::Less
                && name.cmp_canonical(next) == Ordering::Less
        }
        Ordering::Greater | Ordering::Equal => {
            owner.cmp_canonical(name) == Ordering::Less
                || name.cmp_canonical(next) == Ordering::Less
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_node_creates_empty_name() {
        let origin = Name::parse("example.com.").unwrap();
        let empty = Name::parse("empty.example.com.").unwrap();
        let mut zone = InMemoryZone::new(origin);
        zone.insert_node(empty.clone()).unwrap();
        assert!(zone.node_exists(&empty));
        assert!(matches!(
            zone.lookup(&empty, Rtype::A),
            LookupOutcome::NoData
        ));
    }

    #[test]
    fn insert_node_rejects_outside_owner() {
        let mut zone = InMemoryZone::new(Name::parse("example.com.").unwrap());
        let outside = Name::parse("outside.test.").unwrap();
        assert!(matches!(
            zone.insert_node(outside),
            Err(MemoryZoneError::OwnerOutsideZone { .. })
        ));
    }
}
