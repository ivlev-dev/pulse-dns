//! Инкрементальная переподпись зоны после RFC 2136 UPDATE.
//!
//! Полная подпись зоны (`dnssec::sign_zone_with`) строит `DNSKEY`, denial-цепочку
//! и подписи для всех имён. После UPDATE переписывать 100k-зону целиком нельзя,
//! поэтому здесь меняется только затронутая часть:
//!
//! 1. `RRSIG` изменённых RRset (ZSK/CSK) и удаление подписей исчезнувших
//!    наборов. `DNSKEY` UPDATE не трогает, поэтому KSK в этом пути не нужен.
//! 2. `NSEC`/`NSEC3` для имён, у которых изменился набор типов, появилось или
//!    исчезло имя (включая empty non-terminals и cut).
//! 3. Соседние denial-записи, у которых изменился `next` (только
//!    предшественник вставленного/удалённого имени).
//! 4. Подпись `SOA` после роста serial.
//!
//! # Локальность
//!
//! NSEC- и NSEC3-цепочки индексируются в памяти (`DenialIndex`): множество
//! владельцев NSEC и упорядоченная по SHA-1 карта NSEC3. Предшественник и
//! преемник ищутся за `O(log n)`; `O(zone)` возникает только при холодном
//! индексе (первый UPDATE после внешней записи), смене TTL/`MINIMUM` SOA или
//! изменении zone cut, когда обязаны поменяться все имена поддерева.
//!
//! # Атомарность
//!
//! Все чтения/записи идут через [`ZoneEdit`] поверх незакоммиченной
//! транзакции writer'а зоны. Любая ошибка возвращается до `commit`, поэтому
//! читатель не видит частично переподписанную зону.
//!
//! # Пример
//!
//! ```
//! use pulse_dns::{Name, Rtype};
//! use pulse_dnssec::Algorithm;
//! use pulse_server::dnssec::{DenialPolicy, KeyRole, ZoneSigner, ZoneSigningKey};
//! use pulse_server::dnssec_incremental::{UpdateChanges, sign_zone_update};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // В реальном вызове `edit` — адаптер над writer'ом `pulse-zonefile`.
//! let origin = Name::parse("example.com")?;
//! let signer = ZoneSigner::new(
//!     vec![ZoneSigningKey::new(
//!         pulse_dnssec::PrivateKey::generate(Algorithm::ED25519)?,
//!         KeyRole::Csk,
//!     )?],
//!     86_400,
//!     300,
//! )?;
//! let changes = UpdateChanges {
//!     rrsets: Vec::new(),
//!     cut_changes: Vec::new(),
//! };
//! let _ = (&origin, &signer, &changes, Rtype::A);
//! # Ok(())
//! # }
//! ```

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use pulse_dns::{Name, Nsec3Data, NsecData, Rclass, Rdata, Rrset, Rtype, TTL_MAX, Ttl, TypeBitmap};
use pulse_dnssec::denial::{base32hex, nsec3_owner_name};
use pulse_dnssec::rdata_util::nsec3_hash;

use crate::dnssec::{DenialPolicy, Nsec3Config, SignZoneError, ZoneSigner};

/// Изменения, которые UPDATE уже применил к незакоммиченному дереву.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpdateChanges {
    /// Реально изменившиеся RRset (до/после не равны).
    pub rrsets: Vec<(Name, Rtype)>,
    /// Имена, у которых изменился статус zone cut (NS появился/исчез).
    pub cut_changes: Vec<Name>,
}

impl UpdateChanges {
    /// `true`, если менять нечего.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rrsets.is_empty() && self.cut_changes.is_empty()
    }
}

/// Факты об имени, нужные для denial-цепочки.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignNode {
    /// `T_NODE` существует (включая ENT).
    pub exists: bool,
    /// Имя — точка делегирования (NS без SOA, не apex).
    pub is_zone_cut: bool,
    /// У имени есть потомки.
    pub has_children: bool,
}

/// Транзакционный порт для инкрементальной подписи.
///
/// Все операции видят незакоммиченные правки UPDATE (`read-your-writes`) и
/// попадают в тот же commit. Ошибки хранилища должны возвращаться как
/// [`SignZoneError::Edit`].
pub trait ZoneEdit {
    /// RRset `(name, rr_type)` или `None`.
    ///
    /// # Errors
    ///
    /// Ошибка чтения хранилища.
    fn rrset(&mut self, name: &Name, rr_type: Rtype) -> Result<Option<Rrset>, SignZoneError>;

    /// Состояние имени.
    ///
    /// # Errors
    ///
    /// Ошибка чтения хранилища.
    fn node(&mut self, name: &Name) -> Result<SignNode, SignZoneError>;

    /// Все типы RRset имени, включая DNSSEC-типы.
    ///
    /// # Errors
    ///
    /// Ошибка чтения хранилища.
    fn owner_types(&mut self, name: &Name) -> Result<Vec<Rtype>, SignZoneError>;

    /// Типы, покрытые существующими `RRSIG` имени.
    ///
    /// # Errors
    ///
    /// Ошибка чтения хранилища.
    fn rrsig_subtypes(&mut self, name: &Name) -> Result<Vec<Rtype>, SignZoneError>;

    /// Записывает RRset (для `RRSIG` — по subtype покрытого типа).
    ///
    /// # Errors
    ///
    /// Ошибка записи хранилища.
    fn put_rrset(&mut self, rrset: &Rrset) -> Result<(), SignZoneError>;

    /// Удаляет RRset (без `RRSIG`; для подписи — [`ZoneEdit::delete_rrsig`]).
    ///
    /// # Errors
    ///
    /// Ошибка записи хранилища.
    fn delete_rrset(&mut self, name: &Name, rr_type: Rtype) -> Result<(), SignZoneError>;

    /// Удаляет `RRSIG`, покрывающий `covered`.
    ///
    /// # Errors
    ///
    /// Ошибка записи хранилища.
    fn delete_rrsig(&mut self, name: &Name, covered: Rtype) -> Result<(), SignZoneError>;

    /// Владельцы всех `NSEC` зоны (для пересборки индекса).
    ///
    /// # Errors
    ///
    /// Ошибка чтения хранилища.
    fn nsec_owners(&mut self) -> Result<Vec<Name>, SignZoneError>;

    /// Владельцы всех `NSEC3` зоны (для пересборки индекса).
    ///
    /// # Errors
    ///
    /// Ошибка чтения хранилища.
    fn nsec3_owners(&mut self) -> Result<Vec<Name>, SignZoneError>;

    /// Следующее имя в каноническом порядке (`None` — первое).
    ///
    /// Нужен для обхода поддерева при появлении/исчезновении zone cut.
    ///
    /// # Errors
    ///
    /// Ошибка чтения хранилища.
    fn next_name(&mut self, after: Option<&Name>) -> Result<Option<Name>, SignZoneError>;

    /// Удаляет все `RRSIG` имени.
    ///
    /// # Errors
    ///
    /// Ошибка записи/чтения хранилища.
    fn delete_rrsigs(&mut self, name: &Name) -> Result<(), SignZoneError> {
        for covered in self.rrsig_subtypes(name)? {
            self.delete_rrsig(name, covered)?;
        }
        Ok(())
    }
}

/// Обёртка над [`Name`] с каноническим порядком RFC 4034 §6.1.
#[derive(Debug, Clone)]
struct CanonicalName(Name);

impl PartialEq for CanonicalName {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for CanonicalName {}

impl PartialOrd for CanonicalName {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CanonicalName {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp_canonical(&other.0)
    }
}

/// In-memory индекс владельцев `NSEC` в каноническом порядке.
#[derive(Debug, Clone, Default)]
pub struct NsecChain {
    version: u64,
    names: BTreeSet<CanonicalName>,
}

impl NsecChain {
    /// Строит индекс из владельцев `NSEC`.
    #[must_use]
    pub fn from_names(version: u64, names: impl IntoIterator<Item = Name>) -> Self {
        Self {
            version,
            names: names.into_iter().map(CanonicalName).collect(),
        }
    }

    /// Версия зоны, для которой построен индекс.
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }

    /// Число владельцев.
    #[must_use]
    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// `true`, если цепочка пуста (невалидная подписанная зона).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// Владельцы в каноническом порядке.
    pub fn names(&self) -> impl Iterator<Item = &Name> {
        self.names.iter().map(|name| &name.0)
    }

    fn contains(&self, name: &Name) -> bool {
        self.names.contains(&CanonicalName(name.clone()))
    }

    fn insert(&mut self, name: &Name) -> bool {
        self.names.insert(CanonicalName(name.clone()))
    }

    fn remove(&mut self, name: &Name) -> bool {
        self.names.remove(&CanonicalName(name.clone()))
    }

    fn successor(&self, name: &Name) -> Option<&Name> {
        self.names
            .range((
                std::ops::Bound::Excluded(CanonicalName(name.clone())),
                std::ops::Bound::Unbounded,
            ))
            .next()
            .map(|entry| &entry.0)
            .or_else(|| self.names.iter().next().map(|entry| &entry.0))
    }

    fn predecessor(&self, name: &Name) -> Option<&Name> {
        self.names
            .range(..CanonicalName(name.clone()))
            .next_back()
            .map(|entry| &entry.0)
            .or_else(|| self.names.iter().next_back().map(|entry| &entry.0))
    }
}

/// In-memory индекс `NSEC3` в порядке SHA-1 хешей.
///
/// Значение `None` означает «имя неизвестно»: индекс пересобран из zonefile,
/// где NSEC3-владелец синтетический. Для уже затронутых UPDATE имён имя
/// заполняется, что позволяет обнаруживать коллизии.
#[derive(Debug, Clone, Default)]
pub struct Nsec3Chain {
    version: u64,
    hashes: BTreeMap<Vec<u8>, Option<Name>>,
}

impl Nsec3Chain {
    /// Строит индекс из пар `(hash, name)`.
    #[must_use]
    pub fn from_hashes(
        version: u64,
        hashes: impl IntoIterator<Item = (Vec<u8>, Option<Name>)>,
    ) -> Self {
        Self {
            version,
            hashes: hashes.into_iter().collect(),
        }
    }

    /// Версия зоны, для которой построен индекс.
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }

    /// Число хешей в цепочке.
    #[must_use]
    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    /// `true`, если цепочка пуста.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    /// Хеши в порядке цепочки.
    pub fn hashes(&self) -> impl Iterator<Item = &[u8]> {
        self.hashes.keys().map(Vec::as_slice)
    }

    fn contains(&self, hash: &[u8]) -> bool {
        self.hashes.contains_key(hash)
    }

    fn owner(&self, hash: &[u8]) -> Option<&Option<Name>> {
        self.hashes.get(hash)
    }

    fn successor(&self, hash: &[u8]) -> Option<&[u8]> {
        self.hashes
            .range((
                std::ops::Bound::Excluded(hash.to_vec()),
                std::ops::Bound::Unbounded,
            ))
            .next()
            .map(|(entry, _)| entry.as_slice())
            .or_else(|| self.hashes.keys().next().map(Vec::as_slice))
    }

    fn predecessor(&self, hash: &[u8]) -> Option<&[u8]> {
        self.hashes
            .range(..hash.to_vec())
            .next_back()
            .map(|(entry, _)| entry.as_slice())
            .or_else(|| self.hashes.keys().next_back().map(Vec::as_slice))
    }
}

/// Индекс denial-записей зоны.
#[derive(Debug, Clone)]
pub enum DenialIndex {
    /// NSEC-цепочка.
    Nsec(NsecChain),
    /// NSEC3-цепочка.
    Nsec3(Nsec3Chain),
}

impl DenialIndex {
    /// Строит индекс из подписанных RRset (полная подпись/импорт).
    #[must_use]
    pub fn from_rrsets(version: u64, denial: &DenialPolicy, rrsets: &[Rrset]) -> Self {
        match denial {
            DenialPolicy::Nsec => Self::Nsec(NsecChain::from_names(
                version,
                rrsets
                    .iter()
                    .filter(|rrset| rrset.rr_type() == Rtype::NSEC)
                    .map(|rrset| rrset.owner().clone()),
            )),
            DenialPolicy::Nsec3(config) => {
                let mut hashes: BTreeMap<Vec<u8>, Option<Name>> = rrsets
                    .iter()
                    .filter(|rrset| rrset.rr_type() == Rtype::NSEC3)
                    .filter_map(|rrset| {
                        let label = rrset.owner().first_label()?;
                        let hash = base32hex::decode(label).ok()?;
                        Some((hash, None))
                    })
                    .collect();
                if let Some(apex) = rrsets
                    .iter()
                    .find(|rrset| rrset.rr_type() == Rtype::SOA)
                    .map(Rrset::owner)
                {
                    let hash = nsec3_hash(apex, config.salt(), config.iterations());
                    hashes.insert(hash, Some(apex.clone()));
                }
                Self::Nsec3(Nsec3Chain::from_hashes(version, hashes))
            }
        }
    }

    /// Версия зоны, для которой построен индекс.
    #[must_use]
    pub const fn version(&self) -> u64 {
        match self {
            Self::Nsec(chain) => chain.version(),
            Self::Nsec3(chain) => chain.version(),
        }
    }

    /// Устанавливает версию зоны (после успешного commit).
    pub fn set_version(&mut self, version: u64) {
        match self {
            Self::Nsec(chain) => chain.version = version,
            Self::Nsec3(chain) => chain.version = version,
        }
    }

    /// NSEC-цепочка, если это индекс NSEC.
    #[must_use]
    pub const fn as_nsec(&self) -> Option<&NsecChain> {
        match self {
            Self::Nsec(chain) => Some(chain),
            Self::Nsec3(_) => None,
        }
    }

    /// NSEC3-цепочка, если это индекс NSEC3.
    #[must_use]
    pub const fn as_nsec3(&self) -> Option<&Nsec3Chain> {
        match self {
            Self::Nsec3(chain) => Some(chain),
            Self::Nsec(_) => None,
        }
    }

    fn matches(&self, denial: &DenialPolicy) -> bool {
        matches!(
            (self, denial),
            (Self::Nsec(_), DenialPolicy::Nsec) | (Self::Nsec3(_), DenialPolicy::Nsec3(_))
        )
    }

    fn rebuild(
        version: u64,
        origin: &Name,
        denial: &DenialPolicy,
        edit: &mut dyn ZoneEdit,
    ) -> Result<Self, SignZoneError> {
        match denial {
            DenialPolicy::Nsec => Ok(Self::Nsec(NsecChain::from_names(
                version,
                edit.nsec_owners()?,
            ))),
            DenialPolicy::Nsec3(config) => {
                let mut hashes: BTreeMap<Vec<u8>, Option<Name>> = BTreeMap::new();
                for owner in edit.nsec3_owners()? {
                    let Some(label) = owner.first_label() else {
                        continue;
                    };
                    let Ok(hash) = base32hex::decode(label) else {
                        continue;
                    };
                    hashes.insert(hash, None);
                }
                let apex_hash = nsec3_hash(origin, config.salt(), config.iterations());
                hashes.insert(apex_hash, Some(origin.clone()));
                Ok(Self::Nsec3(Nsec3Chain::from_hashes(version, hashes)))
            }
        }
    }
}

/// Инкрементально переподписывает зону после UPDATE.
///
/// `index` берётся из [`DenialIndex::from_rrsets`] (или пересобирается, если
/// версия не совпала с `base_version`). При ошибке индекс остаётся
/// невалидным: следующий вызов пересоберёт его из zonefile.
///
/// # Errors
///
/// [`SignZoneError`] при отсутствии `SOA`, ошибке хранилища, ключа или
/// подписи; вызывающий обязан откатить транзакцию.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub fn sign_zone_update(
    origin: &Name,
    signer: &ZoneSigner,
    denial: &DenialPolicy,
    edit: &mut dyn ZoneEdit,
    changes: &UpdateChanges,
    index: &mut Option<DenialIndex>,
    base_version: u64,
    now: u32,
) -> Result<(), SignZoneError> {
    let soa = edit
        .rrset(origin, Rtype::SOA)?
        .ok_or_else(|| SignZoneError::MissingSoa {
            zone: origin.clone(),
        })?;
    let nsec_ttl = denial_ttl(origin, &soa)?;

    let stale = !matches!(index, Some(current) if current.version() == base_version && current.matches(denial));
    if stale {
        *index = Some(DenialIndex::rebuild(base_version, origin, denial, edit)?);
    }

    let affected = collect_affected(origin, edit, changes)?;
    let cut_names = &changes.cut_changes;
    let force_resign: BTreeSet<CanonicalName> = affected
        .cut_regions
        .iter()
        .flat_map(|(_, region)| region.iter().cloned().map(CanonicalName))
        .collect();

    sign_changed(origin, signer, edit, changes, cut_names, now)?;
    reconcile_cuts(origin, signer, edit, &affected, now)?;

    match (denial, index.as_mut()) {
        (DenialPolicy::Nsec, Some(DenialIndex::Nsec(chain))) => {
            update_nsec(
                origin,
                signer,
                edit,
                &affected.names,
                &force_resign,
                chain,
                nsec_ttl,
                now,
            )?;
        }
        (DenialPolicy::Nsec3(config), Some(DenialIndex::Nsec3(chain))) => {
            update_nsec3(
                origin,
                signer,
                edit,
                &affected.names,
                &force_resign,
                chain,
                config,
                nsec_ttl,
                now,
            )?;
        }
        _ => {}
    }
    Ok(())
}

/// TTL denial-записей: `min(SOA.ttl, SOA.MINIMUM, TTL_MAX)`.
fn denial_ttl(zone: &Name, soa: &Rrset) -> Result<Ttl, SignZoneError> {
    let ttl = soa.ttl().as_u32();
    let minimum = soa
        .rdatas()
        .iter()
        .find_map(|rdata| match rdata {
            Rdata::Soa(data) => Some(data.minimum),
            _ => None,
        })
        .unwrap_or(ttl);
    Ttl::new(ttl.min(minimum).min(TTL_MAX)).map_err(|source| SignZoneError::Ttl {
        zone: zone.clone(),
        source,
    })
}

/// Имя и все потомки из zone cut-поддерева.
struct Affected {
    names: Vec<Name>,
    cut_regions: Vec<(Name, Vec<Name>)>,
}

fn collect_affected(
    origin: &Name,
    edit: &mut dyn ZoneEdit,
    changes: &UpdateChanges,
) -> Result<Affected, SignZoneError> {
    let mut names: BTreeSet<CanonicalName> = BTreeSet::new();
    for (name, _) in &changes.rrsets {
        names.insert(CanonicalName(name.clone()));
        let mut current = name.parent();
        while let Some(parent) = current {
            if !parent.is_subdomain_of(origin) {
                break;
            }
            let at_origin = &parent == origin;
            names.insert(CanonicalName(parent.clone()));
            if at_origin {
                break;
            }
            current = parent.parent();
        }
    }
    let mut cut_regions = Vec::with_capacity(changes.cut_changes.len());
    for cut in &changes.cut_changes {
        let mut region = vec![cut.clone()];
        let mut after = Some(cut.clone());
        while let Some(next) = edit.next_name(after.as_ref())? {
            if !next.is_subdomain_of(cut) || &next == cut {
                break;
            }
            region.push(next.clone());
            names.insert(CanonicalName(next.clone()));
            after = Some(next);
        }
        cut_regions.push((cut.clone(), region));
    }
    Ok(Affected {
        names: names.into_iter().map(|name| name.0).collect(),
        cut_regions,
    })
}

fn cut_contains(cut_names: &[Name], name: &Name) -> bool {
    cut_names.iter().any(|cut| cut == name)
}

fn authoritative(
    origin: &Name,
    edit: &mut dyn ZoneEdit,
    name: &Name,
) -> Result<bool, SignZoneError> {
    if name == origin {
        return Ok(true);
    }
    let mut current = name.parent();
    while let Some(parent) = current {
        if &parent == origin {
            break;
        }
        if edit.node(&parent)?.is_zone_cut {
            return Ok(false);
        }
        current = parent.parent();
    }
    Ok(true)
}

fn data_types(
    edit: &mut dyn ZoneEdit,
    name: &Name,
    is_cut: bool,
) -> Result<BTreeSet<Rtype>, SignZoneError> {
    let mut types = BTreeSet::new();
    for rr_type in edit.owner_types(name)? {
        if is_chain_managed(rr_type) {
            continue;
        }
        if is_cut && !matches!(rr_type, Rtype::NS | Rtype::DS) {
            continue;
        }
        types.insert(rr_type);
    }
    Ok(types)
}

const fn is_chain_managed(rr_type: Rtype) -> bool {
    matches!(
        rr_type.as_u16(),
        46 | 47 | 50 | 51 // RRSIG, NSEC, NSEC3, NSEC3PARAM
    )
}

fn nsec_bitmap(types: &BTreeSet<Rtype>) -> TypeBitmap {
    let mut bitmap = types.clone();
    bitmap.insert(Rtype::NSEC);
    bitmap.insert(Rtype::RRSIG);
    TypeBitmap::from_types(bitmap)
}

fn nsec3_bitmap(types: &BTreeSet<Rtype>, is_apex: bool) -> TypeBitmap {
    let mut bitmap = types.clone();
    if is_apex {
        bitmap.insert(Rtype::DNSKEY);
        bitmap.insert(Rtype::NSEC3PARAM);
    }
    if !bitmap.is_empty() {
        bitmap.insert(Rtype::RRSIG);
    }
    TypeBitmap::from_types(bitmap)
}

fn sign_and_write(
    origin: &Name,
    signer: &ZoneSigner,
    edit: &mut dyn ZoneEdit,
    rrset: &Rrset,
    now: u32,
) -> Result<(), SignZoneError> {
    let signatures = signer.sign_data_rrset(origin, rrset, now)?;
    if signatures.is_empty() {
        edit.delete_rrsig(rrset.owner(), rrset.rr_type())
    } else {
        let rrsig = Rrset::new(
            rrset.owner().clone(),
            Rtype::RRSIG,
            Rclass::IN,
            rrset.ttl(),
            signatures.into_iter().map(Rdata::Rrsig),
        )
        .map_err(|source| SignZoneError::Rrset {
            zone: origin.clone(),
            source,
        })?;
        edit.put_rrset(&rrsig)
    }
}

fn should_sign(
    origin: &Name,
    edit: &mut dyn ZoneEdit,
    name: &Name,
    rr_type: Rtype,
) -> Result<bool, SignZoneError> {
    if !authoritative(origin, edit, name)? {
        return Ok(false);
    }
    if edit.node(name)?.is_zone_cut {
        return Ok(rr_type == Rtype::DS);
    }
    Ok(true)
}

fn sign_changed(
    origin: &Name,
    signer: &ZoneSigner,
    edit: &mut dyn ZoneEdit,
    changes: &UpdateChanges,
    cut_names: &[Name],
    now: u32,
) -> Result<(), SignZoneError> {
    for (name, rr_type) in &changes.rrsets {
        if is_chain_managed(*rr_type) {
            continue;
        }
        if cut_contains(cut_names, name) {
            continue;
        }
        match edit.rrset(name, *rr_type)? {
            Some(rrset) if should_sign(origin, edit, name, *rr_type)? => {
                sign_and_write(origin, signer, edit, &rrset, now)?;
            }
            _ => edit.delete_rrsig(name, *rr_type)?,
        }
    }
    Ok(())
}

fn reconcile_cuts(
    origin: &Name,
    signer: &ZoneSigner,
    edit: &mut dyn ZoneEdit,
    affected: &Affected,
    now: u32,
) -> Result<(), SignZoneError> {
    if affected.cut_regions.is_empty() {
        return Ok(());
    }
    for (_, region) in &affected.cut_regions {
        for name in region {
            edit.delete_rrsigs(name)?;
            if !authoritative(origin, edit, name)? {
                continue;
            }
            let node = edit.node(name)?;
            for rr_type in edit.owner_types(name)? {
                if is_chain_managed(rr_type) {
                    continue;
                }
                if node.is_zone_cut && rr_type != Rtype::DS {
                    continue;
                }
                if let Some(rrset) = edit.rrset(name, rr_type)? {
                    sign_and_write(origin, signer, edit, &rrset, now)?;
                }
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn update_nsec(
    origin: &Name,
    signer: &ZoneSigner,
    edit: &mut dyn ZoneEdit,
    affected: &[Name],
    force_resign: &BTreeSet<CanonicalName>,
    chain: &mut NsecChain,
    nsec_ttl: Ttl,
    now: u32,
) -> Result<(), SignZoneError> {
    let current_ttl = edit.rrset(origin, Rtype::NSEC)?.map(|rrset| rrset.ttl());
    let ttl_changed = current_ttl.is_some_and(|ttl| ttl != nsec_ttl);
    let mut names: Vec<Name> = affected.to_vec();
    if ttl_changed {
        names.extend(chain.names().cloned());
        names.sort_by(Name::cmp_canonical);
        names.dedup_by(|left, right| left == right);
    }

    let mut desired: BTreeMap<CanonicalName, Option<TypeBitmap>> = BTreeMap::new();
    for name in &names {
        let node = edit.node(name)?;
        let is_cut = node.is_zone_cut;
        let types = data_types(edit, name, is_cut)?;
        let auth = authoritative(origin, edit, name)?;
        let exists = name == origin || !types.is_empty() || node.has_children;
        let bitmap = if auth && exists {
            Some(nsec_bitmap(&types))
        } else {
            None
        };
        desired.insert(CanonicalName(name.clone()), bitmap);
    }

    let mut presence_changed: Vec<Name> = Vec::new();
    for name in desired.keys() {
        let old = chain.contains(&name.0);
        let new = desired.get(name).is_some_and(Option::is_some);
        if old != new {
            presence_changed.push(name.0.clone());
        }
    }
    let removed: Vec<Name> = desired
        .iter()
        .filter(|(name, bitmap)| bitmap.is_none() && chain.contains(&name.0))
        .map(|(name, _)| name.0.clone())
        .collect();
    for name in removed {
        chain.remove(&name);
        edit.delete_rrset(&name, Rtype::NSEC)?;
        edit.delete_rrsig(&name, Rtype::NSEC)?;
    }
    let mut inserted: BTreeSet<CanonicalName> = BTreeSet::new();
    for (name, bitmap) in &desired {
        if bitmap.is_some() && !chain.contains(&name.0) {
            chain.insert(&name.0);
            inserted.insert(name.clone());
        }
    }

    let desired_present: BTreeSet<CanonicalName> = desired
        .iter()
        .filter(|(_, bitmap)| bitmap.is_some())
        .map(|(name, _)| (*name).clone())
        .collect();

    for (name, bitmap) in &desired {
        let Some(bitmap) = bitmap else {
            continue;
        };
        let Some(next) = chain.successor(&name.0) else {
            continue;
        };
        let rrset = Rrset::new(
            name.0.clone(),
            Rtype::NSEC,
            Rclass::IN,
            nsec_ttl,
            [Rdata::Nsec(
                NsecData::new(next.clone(), bitmap.clone()).map_err(|source| {
                    SignZoneError::Rdata {
                        zone: origin.clone(),
                        source,
                    }
                })?,
            )],
        )
        .map_err(|source| SignZoneError::Rrset {
            zone: origin.clone(),
            source,
        })?;
        let force = inserted.contains(name)
            || ttl_changed
            || force_resign.contains(&CanonicalName(name.0.clone()));
        write_if_changed(origin, signer, edit, &rrset, force, now)?;
    }

    let mut predecessors: BTreeSet<CanonicalName> = BTreeSet::new();
    for name in &presence_changed {
        if let Some(previous) = chain.predecessor(name) {
            let entry = CanonicalName(previous.clone());
            if !desired_present.contains(&entry) {
                predecessors.insert(entry);
            }
        }
    }
    for previous in predecessors {
        if let Some(next) = chain.successor(&previous.0) {
            refresh_nsec_next(origin, signer, edit, &previous.0, next, nsec_ttl, now)?;
        }
    }
    Ok(())
}

fn refresh_nsec_next(
    origin: &Name,
    signer: &ZoneSigner,
    edit: &mut dyn ZoneEdit,
    name: &Name,
    next: &Name,
    nsec_ttl: Ttl,
    now: u32,
) -> Result<(), SignZoneError> {
    let Some(current) = edit.rrset(name, Rtype::NSEC)? else {
        return Ok(());
    };
    let Some(bitmap) = current.rdatas().iter().find_map(|rdata| match rdata {
        Rdata::Nsec(nsec) => Some(nsec.type_bitmap().clone()),
        _ => None,
    }) else {
        return Ok(());
    };
    let rrset = Rrset::new(
        name.clone(),
        Rtype::NSEC,
        Rclass::IN,
        nsec_ttl,
        [Rdata::Nsec(NsecData::new(next.clone(), bitmap).map_err(
            |source| SignZoneError::Rdata {
                zone: origin.clone(),
                source,
            },
        )?)],
    )
    .map_err(|source| SignZoneError::Rrset {
        zone: origin.clone(),
        source,
    })?;
    write_if_changed(origin, signer, edit, &rrset, true, now)
}

fn write_if_changed(
    origin: &Name,
    signer: &ZoneSigner,
    edit: &mut dyn ZoneEdit,
    rrset: &Rrset,
    force: bool,
    now: u32,
) -> Result<(), SignZoneError> {
    if !force && edit.rrset(rrset.owner(), rrset.rr_type())?.as_ref() == Some(rrset) {
        return Ok(());
    }
    edit.put_rrset(rrset)?;
    sign_and_write(origin, signer, edit, rrset, now)
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::similar_names
)]
fn update_nsec3(
    origin: &Name,
    signer: &ZoneSigner,
    edit: &mut dyn ZoneEdit,
    affected: &[Name],
    force_resign: &BTreeSet<CanonicalName>,
    chain: &mut Nsec3Chain,
    config: &Nsec3Config,
    nsec_ttl: Ttl,
    now: u32,
) -> Result<(), SignZoneError> {
    let apex_hash = nsec3_hash(origin, config.salt(), config.iterations());
    let apex_owner =
        nsec3_owner_name(origin, &apex_hash).map_err(|source| SignZoneError::Denial {
            zone: origin.clone(),
            source,
        })?;
    let current_ttl = edit
        .rrset(&apex_owner, Rtype::NSEC3)?
        .map(|rrset| rrset.ttl());
    let ttl_changed = current_ttl.is_some_and(|ttl| ttl != nsec_ttl);
    let names: Vec<Name> = affected.to_vec();

    let mut desired: BTreeMap<CanonicalName, Option<(Vec<u8>, TypeBitmap)>> = BTreeMap::new();
    for name in &names {
        let node = edit.node(name)?;
        let is_cut = node.is_zone_cut;
        let types = data_types(edit, name, is_cut)?;
        let auth = authoritative(origin, edit, name)?;
        let exists = name == origin || !types.is_empty() || node.has_children;
        let insecure = is_cut && !types.contains(&Rtype::DS);
        let omitted = config.opt_out() && insecure;
        let hash = nsec3_hash(name, config.salt(), config.iterations());
        let bitmap = if auth && exists && !omitted {
            Some((hash, nsec3_bitmap(&types, name == origin)))
        } else {
            None
        };
        desired.insert(CanonicalName(name.clone()), bitmap);
    }

    let mut presence_changed: Vec<Name> = Vec::new();
    for (name, bitmap) in &desired {
        let hash = nsec3_hash(&name.0, config.salt(), config.iterations());
        let old = chain.contains(&hash);
        let new = bitmap.is_some();
        if old != new {
            presence_changed.push(name.0.clone());
        }
    }

    // Удалённые хеши: владелец однозначно определяется детерминированным hash.
    for (name, bitmap) in &desired {
        if bitmap.is_some() {
            continue;
        }
        let hash = nsec3_hash(&name.0, config.salt(), config.iterations());
        if !chain.contains(&hash) {
            continue;
        }
        if let Some(Some(owner)) = chain.owner(&hash)
            && owner != &name.0
        {
            return Err(SignZoneError::Nsec3Collision {
                zone: origin.clone(),
                first: owner.clone(),
                second: name.0.clone(),
            });
        }
        chain.hashes.remove(&hash);
        let owner = nsec3_owner_name(origin, &hash).map_err(|source| SignZoneError::Denial {
            zone: origin.clone(),
            source,
        })?;
        edit.delete_rrset(&owner, Rtype::NSEC3)?;
        edit.delete_rrsig(&owner, Rtype::NSEC3)?;
    }

    let mut inserted: BTreeSet<CanonicalName> = BTreeSet::new();
    for (name, bitmap) in &desired {
        let Some((hash, _)) = bitmap else {
            continue;
        };
        match chain.hashes.get(hash) {
            Some(Some(owner)) if owner != &name.0 => {
                return Err(SignZoneError::Nsec3Collision {
                    zone: origin.clone(),
                    first: owner.clone(),
                    second: name.0.clone(),
                });
            }
            Some(Some(_)) => {}
            Some(None) => {
                chain.hashes.insert(hash.clone(), Some(name.0.clone()));
            }
            None => {
                chain.hashes.insert(hash.clone(), Some(name.0.clone()));
                inserted.insert(name.clone());
            }
        }
    }

    let desired_hashes: BTreeSet<Vec<u8>> = desired
        .values()
        .filter_map(|bitmap| bitmap.as_ref().map(|(hash, _)| hash.clone()))
        .collect();

    for (name, bitmap) in &desired {
        let Some((hash, bitmap)) = bitmap else {
            continue;
        };
        let Some(next) = chain.successor(hash) else {
            continue;
        };
        let owner = nsec3_owner_name(origin, hash).map_err(|source| SignZoneError::Denial {
            zone: origin.clone(),
            source,
        })?;
        let rrset = nsec3_rrset(origin, &owner, config, next, bitmap.clone(), nsec_ttl)?;
        let force = inserted.contains(name)
            || ttl_changed
            || force_resign.contains(&CanonicalName(name.0.clone()));
        write_if_changed(origin, signer, edit, &rrset, force, now)?;
    }

    let mut predecessors: BTreeSet<Vec<u8>> = BTreeSet::new();
    for name in &presence_changed {
        let hash = nsec3_hash(name, config.salt(), config.iterations());
        if let Some(previous) = chain.predecessor(&hash)
            && !desired_hashes.contains(previous)
        {
            predecessors.insert(previous.to_vec());
        }
    }
    for previous in predecessors {
        let Some(next) = chain.successor(&previous) else {
            continue;
        };
        let owner =
            nsec3_owner_name(origin, &previous).map_err(|source| SignZoneError::Denial {
                zone: origin.clone(),
                source,
            })?;
        refresh_nsec3_next(origin, signer, edit, &owner, config, next, nsec_ttl, now)?;
    }

    if ttl_changed {
        for hash in chain.hashes.keys().cloned().collect::<Vec<_>>() {
            let owner =
                nsec3_owner_name(origin, &hash).map_err(|source| SignZoneError::Denial {
                    zone: origin.clone(),
                    source,
                })?;
            let Some(next) = chain.successor(&hash).map(<[u8]>::to_vec) else {
                continue;
            };
            if let Some(current) = edit.rrset(&owner, Rtype::NSEC3)? {
                let Some(bitmap) = current.rdatas().iter().find_map(|rdata| match rdata {
                    Rdata::Nsec3(data) => Some(data.type_bitmap().clone()),
                    _ => None,
                }) else {
                    continue;
                };
                let rrset = nsec3_rrset(origin, &owner, config, &next, bitmap, nsec_ttl)?;
                write_if_changed(origin, signer, edit, &rrset, true, now)?;
            }
        }
    }
    Ok(())
}

fn nsec3_rrset(
    origin: &Name,
    owner: &Name,
    config: &Nsec3Config,
    next: &[u8],
    bitmap: TypeBitmap,
    ttl: Ttl,
) -> Result<Rrset, SignZoneError> {
    let data = Nsec3Data::new(
        Nsec3Config::HASH_SHA1,
        u8::from(config.opt_out()),
        config.iterations(),
        config.salt().to_vec(),
        next.to_vec(),
        bitmap,
    )
    .map_err(|source| SignZoneError::Rdata {
        zone: origin.clone(),
        source,
    })?;
    Rrset::new(
        owner.clone(),
        Rtype::NSEC3,
        Rclass::IN,
        ttl,
        [Rdata::Nsec3(data)],
    )
    .map_err(|source| SignZoneError::Rrset {
        zone: origin.clone(),
        source,
    })
}

#[allow(clippy::too_many_arguments)]
fn refresh_nsec3_next(
    origin: &Name,
    signer: &ZoneSigner,
    edit: &mut dyn ZoneEdit,
    owner: &Name,
    config: &Nsec3Config,
    next: &[u8],
    nsec_ttl: Ttl,
    now: u32,
) -> Result<(), SignZoneError> {
    let Some(current) = edit.rrset(owner, Rtype::NSEC3)? else {
        return Ok(());
    };
    let Some(bitmap) = current.rdatas().iter().find_map(|rdata| match rdata {
        Rdata::Nsec3(data) => Some(data.type_bitmap().clone()),
        _ => None,
    }) else {
        return Ok(());
    };
    let rrset = nsec3_rrset(origin, owner, config, next, bitmap, nsec_ttl)?;
    write_if_changed(origin, signer, edit, &rrset, true, now)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::similar_names, clippy::too_many_lines)]

    use super::*;
    use std::collections::HashMap;

    use pulse_dns::{DnskeyData, RrsigData, Serial, SoaData};
    use pulse_dnssec::{Algorithm, DenialLimits, PrivateKey, VerifyOptions, verify_rrsig};

    use crate::dnssec::ZoneSigningKey;

    struct MemoryEdit {
        origin: Name,
        rrsets: HashMap<(Name, Rtype), Rrset>,
    }

    impl MemoryEdit {
        fn from_zone(origin: &Name, rrsets: &[Rrset]) -> Self {
            let mut map = HashMap::new();
            for rrset in rrsets {
                map.insert((rrset.owner().clone(), rrset.rr_type()), rrset.clone());
            }
            Self {
                origin: origin.clone(),
                rrsets: map,
            }
        }

        fn put(&mut self, rrset: Rrset) {
            if rrset.rr_type() == Rtype::RRSIG {
                let key = (rrset.owner().clone(), Rtype::RRSIG);
                let new_covered: BTreeSet<Rtype> = rrset
                    .rdatas()
                    .iter()
                    .filter_map(|rdata| match rdata {
                        Rdata::Rrsig(signature) => Some(signature.type_covered()),
                        _ => None,
                    })
                    .collect();
                let mut rdatas: Vec<Rdata> = self
                    .rrsets
                    .get(&key)
                    .into_iter()
                    .flat_map(|existing| existing.rdatas().iter())
                    .filter(|rdata| match rdata {
                        Rdata::Rrsig(signature) => !new_covered.contains(&signature.type_covered()),
                        _ => true,
                    })
                    .cloned()
                    .collect();
                rdatas.extend(rrset.rdatas().iter().cloned());
                let ttl = self
                    .rrsets
                    .get(&key)
                    .map_or(rrset.ttl(), |existing| existing.ttl().min(rrset.ttl()));
                let merged =
                    Rrset::new(rrset.owner().clone(), Rtype::RRSIG, Rclass::IN, ttl, rdatas)
                        .expect("merged rrsig");
                self.rrsets.insert(key, merged);
            } else {
                self.rrsets
                    .insert((rrset.owner().clone(), rrset.rr_type()), rrset);
            }
        }

        fn remove(&mut self, name: &Name, rr_type: Rtype) {
            self.rrsets.remove(&(name.clone(), rr_type));
        }

        fn get(&self, name: &Name, rr_type: Rtype) -> Option<&Rrset> {
            self.rrsets.get(&(name.clone(), rr_type))
        }

        fn names(&self) -> Vec<Name> {
            let mut names: Vec<Name> = self.rrsets.keys().map(|(owner, _)| owner.clone()).collect();
            names.sort_by(Name::cmp_canonical);
            names.dedup();
            names
        }
    }

    impl ZoneEdit for MemoryEdit {
        fn rrset(&mut self, name: &Name, rr_type: Rtype) -> Result<Option<Rrset>, SignZoneError> {
            Ok(self.get(name, rr_type).cloned())
        }

        fn node(&mut self, name: &Name) -> Result<SignNode, SignZoneError> {
            let exists = self
                .rrsets
                .keys()
                .any(|(owner, _)| owner == name || owner.is_subdomain_of(name));
            let has_children = self
                .rrsets
                .keys()
                .any(|(owner, _)| owner != name && owner.is_subdomain_of(name));
            let is_zone_cut = name != &self.origin
                && self.get(name, Rtype::NS).is_some()
                && self.get(name, Rtype::SOA).is_none();
            Ok(SignNode {
                exists,
                is_zone_cut,
                has_children,
            })
        }

        fn owner_types(&mut self, name: &Name) -> Result<Vec<Rtype>, SignZoneError> {
            let mut types: Vec<Rtype> = self
                .rrsets
                .keys()
                .filter(|(owner, _)| owner == name)
                .map(|(_, rr_type)| *rr_type)
                .collect();
            types.sort();
            types.dedup();
            Ok(types)
        }

        fn rrsig_subtypes(&mut self, name: &Name) -> Result<Vec<Rtype>, SignZoneError> {
            let Some(rrset) = self.get(name, Rtype::RRSIG) else {
                return Ok(Vec::new());
            };
            let mut covered: Vec<Rtype> = rrset
                .rdatas()
                .iter()
                .filter_map(|rdata| match rdata {
                    Rdata::Rrsig(signature) => Some(signature.type_covered()),
                    _ => None,
                })
                .collect();
            covered.sort();
            covered.dedup();
            Ok(covered)
        }

        fn put_rrset(&mut self, rrset: &Rrset) -> Result<(), SignZoneError> {
            self.put(rrset.clone());
            Ok(())
        }

        fn delete_rrset(&mut self, name: &Name, rr_type: Rtype) -> Result<(), SignZoneError> {
            self.remove(name, rr_type);
            Ok(())
        }

        fn delete_rrsig(&mut self, name: &Name, covered: Rtype) -> Result<(), SignZoneError> {
            let Some(rrset) = self.get(name, Rtype::RRSIG).cloned() else {
                return Ok(());
            };
            let remaining: Vec<Rdata> = rrset
                .rdatas()
                .iter()
                .filter(|rdata| match rdata {
                    Rdata::Rrsig(signature) => signature.type_covered() != covered,
                    _ => true,
                })
                .cloned()
                .collect();
            if remaining.is_empty() {
                self.remove(name, Rtype::RRSIG);
            } else {
                self.rrsets.insert(
                    (name.clone(), Rtype::RRSIG),
                    Rrset::new(
                        name.clone(),
                        Rtype::RRSIG,
                        Rclass::IN,
                        rrset.ttl(),
                        remaining,
                    )
                    .expect("rrsig rrset"),
                );
            }
            Ok(())
        }

        fn nsec_owners(&mut self) -> Result<Vec<Name>, SignZoneError> {
            Ok(self
                .rrsets
                .keys()
                .filter(|(_, rr_type)| *rr_type == Rtype::NSEC)
                .map(|(owner, _)| owner.clone())
                .collect())
        }

        fn nsec3_owners(&mut self) -> Result<Vec<Name>, SignZoneError> {
            Ok(self
                .rrsets
                .keys()
                .filter(|(_, rr_type)| *rr_type == Rtype::NSEC3)
                .map(|(owner, _)| owner.clone())
                .collect())
        }

        fn next_name(&mut self, after: Option<&Name>) -> Result<Option<Name>, SignZoneError> {
            Ok(self.names().into_iter().find(|name| {
                after.is_none_or(|after| name.cmp_canonical(after) == Ordering::Greater)
            }))
        }
    }

    fn name(text: &str) -> Name {
        Name::parse(text).expect("name")
    }

    fn ttl(value: u32) -> Ttl {
        Ttl::new(value).expect("ttl")
    }

    fn rrset(owner: &str, rr_type: Rtype, rdatas: impl IntoIterator<Item = Rdata>) -> Rrset {
        Rrset::new(name(owner), rr_type, Rclass::IN, ttl(300), rdatas).expect("rrset")
    }

    fn soa(serial: u32) -> Rrset {
        Rrset::new(
            name("example.com"),
            Rtype::SOA,
            Rclass::IN,
            ttl(3600),
            [Rdata::Soa(SoaData::new(
                name("ns1.example.com"),
                name("hostmaster.example.com"),
                Serial::new(serial),
                3600,
                600,
                604_800,
                300,
            ))],
        )
        .expect("soa")
    }

    fn signer() -> ZoneSigner {
        ZoneSigner::new(
            vec![
                ZoneSigningKey::new(
                    PrivateKey::generate(Algorithm::ED25519).expect("key"),
                    crate::dnssec::KeyRole::Csk,
                )
                .expect("key"),
            ],
            86_400,
            300,
        )
        .expect("signer")
    }

    fn base_zone() -> Vec<Rrset> {
        vec![
            soa(1),
            rrset(
                "example.com",
                Rtype::NS,
                [Rdata::Ns(name("ns1.example.com"))],
            ),
            rrset(
                "ns1.example.com",
                Rtype::A,
                [Rdata::A("192.0.2.1".parse().expect("ip"))],
            ),
            rrset(
                "www.example.com",
                Rtype::A,
                [Rdata::A("192.0.2.2".parse().expect("ip"))],
            ),
            rrset(
                "*.wild.example.com",
                Rtype::A,
                [Rdata::A("192.0.2.3".parse().expect("ip"))],
            ),
            rrset(
                "sub.example.com",
                Rtype::NS,
                [Rdata::Ns(name("ns.sub.example.com"))],
            ),
            rrset(
                "ns.sub.example.com",
                Rtype::A,
                [Rdata::A("192.0.2.4".parse().expect("ip"))],
            ),
        ]
    }

    fn dnskeys(signed: &crate::dnssec::SignedZone) -> Vec<DnskeyData> {
        signed.dnskeys.clone()
    }

    fn signatures(edit: &MemoryEdit, owner: &Name, covered: Rtype) -> Vec<RrsigData> {
        let Some(rrset) = edit.get(owner, Rtype::RRSIG) else {
            return Vec::new();
        };
        rrset
            .rdatas()
            .iter()
            .filter_map(|rdata| match rdata {
                Rdata::Rrsig(signature) if signature.type_covered() == covered => {
                    Some(signature.clone())
                }
                _ => None,
            })
            .collect()
    }

    fn assert_valid(
        edit: &MemoryEdit,
        keys: &[DnskeyData],
        owner: &Name,
        rr_type: Rtype,
        now: u32,
    ) {
        let rrset = edit
            .get(owner, rr_type)
            .unwrap_or_else(|| panic!("missing {owner} {rr_type}"));
        let sigs = signatures(edit, owner, rr_type);
        assert!(!sigs.is_empty(), "no RRSIG for {owner} {rr_type}");
        let options = VerifyOptions::new(now);
        assert!(
            sigs.iter().any(|signature| keys
                .iter()
                .any(|key| verify_rrsig(rrset, signature, key, &options).is_ok())),
            "invalid RRSIG for {owner} {rr_type}"
        );
    }

    fn nsec_proofs(edit: &MemoryEdit) -> Vec<pulse_dnssec::NsecProof> {
        edit.rrsets
            .values()
            .filter(|rrset| rrset.rr_type() == Rtype::NSEC)
            .filter_map(|rrset| {
                let rdata = rrset.rdatas().iter().next()?.clone();
                let record = pulse_dns::Record::new(
                    rrset.owner().clone(),
                    Rtype::NSEC,
                    Rclass::IN,
                    rrset.ttl(),
                    rdata,
                )
                .ok()?;
                pulse_dnssec::NsecProof::from_record(&record).ok()
            })
            .collect()
    }

    fn nsec3_proofs(edit: &MemoryEdit) -> Vec<pulse_dnssec::Nsec3Proof> {
        let limits = DenialLimits::new();
        edit.rrsets
            .values()
            .filter(|rrset| rrset.rr_type() == Rtype::NSEC3)
            .filter_map(|rrset| {
                let rdata = rrset.rdatas().iter().next()?.clone();
                let record = pulse_dns::Record::new(
                    rrset.owner().clone(),
                    Rtype::NSEC3,
                    Rclass::IN,
                    rrset.ttl(),
                    rdata,
                )
                .ok()?;
                pulse_dnssec::Nsec3Proof::from_record(&record, limits).ok()
            })
            .collect()
    }

    #[test]
    fn nsec_add_delete_resigns_locally_and_preserves_others() {
        let origin = name("example.com");
        let signer = signer();
        let now = 1_700_000_000;
        let signed = signer.sign_zone(&origin, &base_zone(), now).expect("sign");
        let mut edit = MemoryEdit::from_zone(&origin, &signed.rrsets);
        let mut index = Some(DenialIndex::from_rrsets(
            7,
            &DenialPolicy::Nsec,
            &signed.rrsets,
        ));
        let ns1_before = signatures(&edit, &name("ns1.example.com"), Rtype::A);

        edit.put(soa(2));
        edit.put(rrset(
            "new.example.com",
            Rtype::A,
            [Rdata::A("192.0.2.55".parse().expect("ip"))],
        ));
        edit.remove(&name("www.example.com"), Rtype::A);
        let changes = UpdateChanges {
            rrsets: vec![
                (origin.clone(), Rtype::SOA),
                (name("new.example.com"), Rtype::A),
                (name("www.example.com"), Rtype::A),
            ],
            cut_changes: Vec::new(),
        };
        sign_zone_update(
            &origin,
            &signer,
            &DenialPolicy::Nsec,
            &mut edit,
            &changes,
            &mut index,
            7,
            now,
        )
        .expect("incremental sign");

        let keys = dnskeys(&signed);
        assert_valid(&edit, &keys, &origin, Rtype::SOA, now);
        assert_valid(&edit, &keys, &name("new.example.com"), Rtype::A, now);
        assert_eq!(
            signatures(&edit, &name("www.example.com"), Rtype::A).len(),
            0
        );
        assert!(edit.get(&name("www.example.com"), Rtype::NSEC).is_none());
        assert_eq!(
            ns1_before,
            signatures(&edit, &name("ns1.example.com"), Rtype::A),
            "unchanged RRSIG must be preserved"
        );

        let records: Vec<Rrset> = edit
            .rrsets
            .values()
            .filter(|rrset| rrset.rr_type() == Rtype::NSEC)
            .cloned()
            .collect();
        let mut owners: Vec<Name> = records.iter().map(|rrset| rrset.owner().clone()).collect();
        owners.sort_by(Name::cmp_canonical);
        assert!(owners.contains(&name("new.example.com")));
        for (index, owner) in owners.iter().enumerate() {
            let rrset = records
                .iter()
                .find(|rrset| rrset.owner() == owner)
                .expect("nsec");
            let Rdata::Nsec(nsec) = rrset.rdatas().iter().next().expect("nsec rdata") else {
                panic!("NSEC rdata");
            };
            assert_eq!(
                nsec.next_domain(),
                owners.get((index + 1) % owners.len()).expect("next"),
                "NSEC next at {owner}"
            );
        }

        let proofs = nsec_proofs(&edit);
        let limits = DenialLimits::new();
        pulse_dnssec::denial::nsec_nxdomain(&name("gone.example.com"), &origin, &proofs, limits)
            .expect("NXDOMAIN proof");
        pulse_dnssec::denial::nsec_nodata(
            &name("new.example.com"),
            Rtype::AAAA,
            &origin,
            &proofs,
            limits,
        )
        .expect("NODATA proof");
    }

    #[test]
    fn nsec_ent_and_cut_changes_keep_chain_valid() {
        let origin = name("example.com");
        let signer = signer();
        let now = 1_700_000_001;
        let signed = signer.sign_zone(&origin, &base_zone(), now).expect("sign");
        let mut edit = MemoryEdit::from_zone(&origin, &signed.rrsets);
        let mut index = Some(DenialIndex::from_rrsets(
            1,
            &DenialPolicy::Nsec,
            &signed.rrsets,
        ));

        // a.b.example.com создаёт ENT b.example.com.
        edit.put(rrset(
            "a.b.example.com",
            Rtype::A,
            [Rdata::A("192.0.2.60".parse().expect("ip"))],
        ));
        // Новый cut над существующим именем: host.deleg перестаёт быть
        // авторитетным (glue), его NSEC/RRSIG удаляются.
        edit.put(rrset(
            "deleg.example.com",
            Rtype::NS,
            [Rdata::Ns(name("ns.deleg.example.com"))],
        ));
        edit.put(rrset(
            "host.deleg.example.com",
            Rtype::A,
            [Rdata::A("192.0.2.61".parse().expect("ip"))],
        ));
        let changes = UpdateChanges {
            rrsets: vec![
                (origin.clone(), Rtype::SOA),
                (name("a.b.example.com"), Rtype::A),
                (name("deleg.example.com"), Rtype::NS),
                (name("host.deleg.example.com"), Rtype::A),
            ],
            cut_changes: vec![name("deleg.example.com")],
        };
        sign_zone_update(
            &origin,
            &signer,
            &DenialPolicy::Nsec,
            &mut edit,
            &changes,
            &mut index,
            1,
            now,
        )
        .expect("incremental sign");

        assert!(edit.get(&name("b.example.com"), Rtype::NSEC).is_some());
        assert!(edit.get(&name("a.b.example.com"), Rtype::NSEC).is_some());
        assert!(edit.get(&name("deleg.example.com"), Rtype::NSEC).is_some());
        assert!(
            edit.get(&name("host.deleg.example.com"), Rtype::NSEC)
                .is_none()
        );
        assert_eq!(
            signatures(&edit, &name("host.deleg.example.com"), Rtype::A).len(),
            0
        );
        assert_eq!(
            signatures(&edit, &name("deleg.example.com"), Rtype::NS).len(),
            0
        );

        // Снимаем cut: host снова авторитетен, NSEC и подпись возвращаются.
        edit.remove(&name("deleg.example.com"), Rtype::NS);
        let changes = UpdateChanges {
            rrsets: vec![
                (origin.clone(), Rtype::SOA),
                (name("deleg.example.com"), Rtype::NS),
            ],
            cut_changes: vec![name("deleg.example.com")],
        };
        sign_zone_update(
            &origin,
            &signer,
            &DenialPolicy::Nsec,
            &mut edit,
            &changes,
            &mut index,
            1,
            now,
        )
        .expect("incremental sign after cut removal");

        assert!(
            edit.get(&name("host.deleg.example.com"), Rtype::NSEC)
                .is_some()
        );
        assert_valid(
            &edit,
            &dnskeys(&signed),
            &name("host.deleg.example.com"),
            Rtype::A,
            now,
        );
        let deleg_nsec = edit
            .get(&name("deleg.example.com"), Rtype::NSEC)
            .expect("ENT keeps NSEC");
        let Rdata::Nsec(deleg_data) = deleg_nsec.rdatas().iter().next().expect("nsec rdata") else {
            panic!("NSEC rdata");
        };
        assert!(!deleg_data.type_bitmap().contains(Rtype::NS));
        let proofs = nsec_proofs(&edit);
        let limits = DenialLimits::new();
        pulse_dnssec::denial::nsec_nodata(
            &name("host.deleg.example.com"),
            Rtype::AAAA,
            &origin,
            &proofs,
            limits,
        )
        .expect("NODATA after cut removal");
    }

    #[test]
    fn nsec3_opt_out_adds_secure_delegation_and_resigns() {
        let origin = name("example.com");
        let signer = signer();
        let now = 1_700_000_002;
        let config = Nsec3Config::new(vec![0xAA, 0xBB], 2)
            .expect("config")
            .with_opt_out(true);
        let denial = DenialPolicy::Nsec3(config.clone());
        let mut zone = base_zone();
        zone.push(rrset(
            "insecure.example.com",
            Rtype::NS,
            [Rdata::Ns(name("ns.insecure.example.com"))],
        ));
        zone.push(rrset(
            "ns.insecure.example.com",
            Rtype::A,
            [Rdata::A("192.0.2.70".parse().expect("ip"))],
        ));
        let signed = signer
            .sign_zone_with(&origin, &zone, now, &denial)
            .expect("sign nsec3");
        let mut edit = MemoryEdit::from_zone(&origin, &signed.rrsets);
        let mut index = Some(DenialIndex::from_rrsets(3, &denial, &signed.rrsets));

        let insecure_hash = nsec3_hash(
            &name("insecure.example.com"),
            config.salt(),
            config.iterations(),
        );
        assert!(
            !index
                .as_ref()
                .and_then(DenialIndex::as_nsec3)
                .expect("nsec3")
                .contains(&insecure_hash)
        );

        // DS делает делегирование secure: hash появляется в цепочке.
        edit.put(rrset(
            "insecure.example.com",
            Rtype::DS,
            [Rdata::Ds(
                pulse_dns::DsData::new(1234, 15, 2, vec![0xCD; 32]).expect("ds"),
            )],
        ));
        edit.put(rrset(
            "new.example.com",
            Rtype::A,
            [Rdata::A("192.0.2.71".parse().expect("ip"))],
        ));
        edit.remove(&name("www.example.com"), Rtype::A);
        let changes = UpdateChanges {
            rrsets: vec![
                (origin.clone(), Rtype::SOA),
                (name("insecure.example.com"), Rtype::DS),
                (name("new.example.com"), Rtype::A),
                (name("www.example.com"), Rtype::A),
            ],
            cut_changes: Vec::new(),
        };
        sign_zone_update(
            &origin, &signer, &denial, &mut edit, &changes, &mut index, 3, now,
        )
        .expect("incremental nsec3");

        let chain = index
            .as_ref()
            .and_then(DenialIndex::as_nsec3)
            .expect("nsec3");
        assert!(chain.contains(&insecure_hash));
        assert_valid(
            &edit,
            &dnskeys(&signed),
            &name("new.example.com"),
            Rtype::A,
            now,
        );
        assert_valid(
            &edit,
            &dnskeys(&signed),
            &name("insecure.example.com"),
            Rtype::DS,
            now,
        );

        let proofs = nsec3_proofs(&edit);
        let limits = DenialLimits::new();
        pulse_dnssec::denial::nsec3_nxdomain(&name("gone.example.com"), &origin, &proofs, limits)
            .expect("NSEC3 NXDOMAIN");
        pulse_dnssec::denial::nsec3_nodata(
            &name("new.example.com"),
            Rtype::AAAA,
            &origin,
            &proofs,
            limits,
        )
        .expect("NSEC3 NODATA");
    }
}
