//! Опциональная DNSSEC-валидация ответа.
//!
//! Валидация запускается только при `DnssecConfig::enabled`. Цепочка
//! строится от настроенного trust anchor (или встроенных корневых KSK) через
//! DS → DNSKEY → RRSIG с помощью `pulse-dnssec`. Негативные ответы
//! проверяются NSEC/NSEC3 denial-функциями того же крейта.
//!
//! # Ограничения MVP
//!
//! - Ответ без единой RRSIG считается **insecure** (downgrade-resistance
//!   ограничена): для полного доказательства отсутствия подписи нужен
//!   отдельный проход по DS-цепочке.
//! - NSEC3 opt-out учитывается denial-функциями, но EDE-опции не
//!   генерируются.
//! - Результат валидации кешируется отдельно от RRset: проверенная цепочка
//!   (`zone` + отпечаток DNSKEY RRset) и пара RRset+RRSIG. Смена DNSKEY
//!   RRset или trust anchors инвалидирует доказательства, а смена DS
//!   приводит к новому набору ключей; сам RRset по-прежнему хранит
//!   secure-флаг вместе с записью.

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use pulse_dns::{DsData, Name, Rcode, Rdata, Record, Rrset, RrsigData, Rtype};
use pulse_dnssec::denial::{
    nsec_nodata, nsec_nxdomain, nsec3_ds_nodata, nsec3_nodata, nsec3_nxdomain,
};
use pulse_dnssec::{
    DenialLimits, DenialOutcome, DsPolicy, ValidatedDnskeySet, VerifyOptions, builtin_root_anchors,
    validate_dnskey_rrset,
};

use crate::error::ResolverError;
use crate::resolver::{Resolution, ResolveContext, Resolver};
use crate::rrutil::{group_rrsets, rrsigs_for, soa_zone};

/// Результат DNSSEC-проверки.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Security {
    /// Все данные ответа аутентифицированы.
    Secure,
    /// Зона доказанно не подписана.
    Insecure,
    /// Валидация не выполнялась.
    Unvalidated,
}

/// Итог валидации.
#[derive(Debug, Clone)]
pub(crate) struct ValidationOutcome {
    pub(crate) state: Security,
    pub(crate) validated: HashSet<(Name, Rtype)>,
}

#[derive(Debug)]
struct CachedKeyset {
    keys: ValidatedDnskeySet,
    fingerprint: Box<[u8]>,
    expires: u32,
}

/// Кеш результатов DNSSEC-валидации.
///
/// Хранит два вида доказательств:
///
/// - **цепочка**: валидированный `DNSKEY`-набор зоны вместе с отпечатком
///   самого RRset. На следующем запросе достаточно сравнить отпечаток
///   свежего DNSKEY RRset — криптография DS → DNSKEY не повторяется;
/// - **подпись**: факт успешной проверки конкретного RRset конкретными
///   RRSIG под конкретным набором ключей. Ключ кеша — точные wire-байты
///   RRset, RRSIG и отпечатка keyset, поэтому смена DS/ключей или подписи
///   автоматически промахивается.
///
/// Обе таблицы ограничены по числу записей; при переполнении вытесняется
/// произвольная запись (`O(1)`), а не выполняется полный перебор.
#[derive(Debug)]
pub(crate) struct ValidationCache {
    keys: RwLock<HashMap<Box<[u8]>, CachedKeyset>>,
    signatures: RwLock<HashMap<Box<[u8]>, u32>>,
    hits: AtomicU64,
    misses: AtomicU64,
    limit: usize,
}

impl ValidationCache {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
            signatures: RwLock::new(HashMap::new()),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            limit: limit.max(16),
        }
    }

    /// Есть ли для зоны неистёкший кандидат keyset-кеша.
    fn has_keys(&self, zone: &Name, now: u32) -> bool {
        let Ok(guard) = self.keys.read() else {
            return false;
        };
        guard
            .get(zone.as_wire())
            .is_some_and(|entry| entry.expires > now)
    }

    /// Возвращает валидированный набор, если отпечаток DNSKEY RRset совпал.
    fn lookup_keys(&self, zone: &Name, fingerprint: &[u8], now: u32) -> Option<ValidatedDnskeySet> {
        let Ok(mut guard) = self.keys.write() else {
            return None;
        };
        let Some(entry) = guard.get(zone.as_wire()) else {
            self.misses.fetch_add(1, Ordering::Relaxed);
            return None;
        };
        if entry.expires <= now || entry.fingerprint.as_ref() != fingerprint {
            guard.remove(zone.as_wire());
            self.misses.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let keys = entry.keys.clone();
        self.hits.fetch_add(1, Ordering::Relaxed);
        Some(keys)
    }

    fn store_keys(
        &self,
        zone: &Name,
        fingerprint: Box<[u8]>,
        keys: ValidatedDnskeySet,
        expires: u32,
    ) {
        if expires == 0 {
            return;
        }
        let Ok(mut guard) = self.keys.write() else {
            return;
        };
        if guard.len() >= self.limit
            && !guard.contains_key(zone.as_wire())
            && let Some(victim) = guard.keys().next().cloned()
        {
            guard.remove(&victim);
        }
        guard.insert(
            zone.as_wire().into(),
            CachedKeyset {
                keys,
                fingerprint,
                expires,
            },
        );
    }

    fn invalidate_keys(&self, zone: &Name) {
        if let Ok(mut guard) = self.keys.write() {
            guard.remove(zone.as_wire());
        }
    }

    /// Проверяет, что эта пара RRset+RRSIG уже успешно валидирована.
    fn signature_valid(&self, key: &[u8], now: u32) -> bool {
        let Ok(guard) = self.signatures.read() else {
            return false;
        };
        let valid = guard.get(key).is_some_and(|expires| *expires > now);
        if valid {
            self.hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
        }
        valid
    }

    fn store_signature(&self, key: Box<[u8]>, expires: u32) {
        if expires == 0 {
            return;
        }
        let Ok(mut guard) = self.signatures.write() else {
            return;
        };
        if guard.len() >= self.limit
            && !guard.contains_key(key.as_ref())
            && let Some(victim) = guard.keys().next().cloned()
        {
            guard.remove(&victim);
        }
        guard.insert(key, expires);
    }

    /// Полностью сбрасывает кеш (например, при смене trust anchors).
    pub(crate) fn clear(&self) {
        if let Ok(mut guard) = self.keys.write() {
            guard.clear();
        }
        if let Ok(mut guard) = self.signatures.write() {
            guard.clear();
        }
    }

    /// `(hits, misses)` для метрик.
    pub(crate) fn snapshot(&self) -> (u64, u64) {
        (
            self.hits.load(Ordering::Relaxed),
            self.misses.load(Ordering::Relaxed),
        )
    }
}

pub(crate) fn validate(
    resolver: &Resolver,
    qname: &Name,
    qtype: Rtype,
    resolution: &Resolution,
    context: &ResolveContext,
) -> Result<ValidationOutcome, ResolverError> {
    let now = unix_now();
    let mut validator = Validator {
        resolver,
        context,
        now,
        verify_options: VerifyOptions::new(now),
        memo: HashMap::new(),
        keyset_fingerprints: HashMap::new(),
        raw_cache: HashMap::new(),
        visiting: HashSet::new(),
        verifications: 0,
    };
    if resolution.answers.is_empty() {
        validator.validate_negative(qname, qtype, resolution)
    } else {
        validator.validate_positive(resolution)
    }
}

struct Validator<'a> {
    resolver: &'a Resolver,
    context: &'a ResolveContext,
    now: u32,
    verify_options: VerifyOptions,
    memo: HashMap<Name, Option<ValidatedDnskeySet>>,
    keyset_fingerprints: HashMap<Name, Box<[u8]>>,
    raw_cache: HashMap<(Name, Rtype), Resolution>,
    visiting: HashSet<Name>,
    verifications: usize,
}

impl Validator<'_> {
    fn validate_positive(
        &mut self,
        resolution: &Resolution,
    ) -> Result<ValidationOutcome, ResolverError> {
        let groups = group_rrsets(&resolution.answers);
        if groups.is_empty() {
            return Ok(insecure());
        }
        let has_signature = resolution
            .answers
            .iter()
            .any(|record| record.rr_type() == Rtype::RRSIG);
        if !has_signature {
            return Ok(insecure());
        }
        let mut validated = HashSet::new();
        for group in groups {
            let signatures = rrsigs_for(&resolution.answers, &group.owner, group.rr_type);
            if signatures.is_empty() {
                return Err(bogus("rrset without RRSIG in signed answer"));
            }
            let signer = signatures
                .first()
                .map(RrsigData::signer_name)
                .ok_or_else(|| bogus("empty RRSIG"))?
                .clone();
            let Some(keys) = self.keys_for(&signer)? else {
                return Ok(insecure());
            };
            let rrset = group.to_rrset().ok_or_else(|| bogus("invalid rrset"))?;
            self.verify_rrset(&keys, &rrset, &signatures)?;
            validated.insert((group.owner.clone(), group.rr_type));
        }
        Ok(ValidationOutcome {
            state: Security::Secure,
            validated,
        })
    }

    fn validate_negative(
        &mut self,
        qname: &Name,
        qtype: Rtype,
        resolution: &Resolution,
    ) -> Result<ValidationOutcome, ResolverError> {
        let Some(zone) = soa_zone(&resolution.authority) else {
            let signed = resolution
                .authority
                .iter()
                .any(|record| record.rr_type() == Rtype::RRSIG);
            return if signed {
                Err(bogus("negative answer without SOA"))
            } else {
                Ok(insecure())
            };
        };
        let signed = resolution
            .authority
            .iter()
            .any(|record| record.rr_type() == Rtype::RRSIG);
        if !signed {
            return Ok(insecure());
        }
        let Some(keys) = self.keys_for(&zone)? else {
            return Ok(insecure());
        };
        let validated =
            self.verify_negative(qname, qtype, resolution.rcode, &resolution.authority, &keys)?;
        Ok(ValidationOutcome {
            state: Security::Secure,
            validated,
        })
    }

    fn verify_negative(
        &mut self,
        qname: &Name,
        qtype: Rtype,
        rcode: Rcode,
        authority: &[Record],
        keys: &ValidatedDnskeySet,
    ) -> Result<HashSet<(Name, Rtype)>, ResolverError> {
        let zone = keys.zone().clone();
        let mut validated = HashSet::new();
        for group in group_rrsets(authority) {
            if !matches!(group.rr_type, Rtype::SOA | Rtype::NSEC | Rtype::NSEC3) {
                continue;
            }
            let signatures = rrsigs_for(authority, &group.owner, group.rr_type);
            if signatures.is_empty() {
                return Err(bogus("denial rrset without RRSIG"));
            }
            let rrset = group
                .to_rrset()
                .ok_or_else(|| bogus("invalid denial rrset"))?;
            self.verify_rrset(keys, &rrset, &signatures)?;
            validated.insert((group.owner.clone(), group.rr_type));
        }

        let limits = DenialLimits::default();
        let nsec: Vec<pulse_dnssec::NsecProof> = authority
            .iter()
            .filter(|record| record.rr_type() == Rtype::NSEC)
            .map(pulse_dnssec::NsecProof::from_record)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| bogus(error.to_string()))?;
        if !nsec.is_empty() {
            let result = if rcode == Rcode::NXDOMAIN {
                nsec_nxdomain(qname, &zone, &nsec, limits)
            } else {
                nsec_nodata(qname, qtype, &zone, &nsec, limits)
            }
            .map_err(|error| bogus(error.to_string()))?;
            if rcode == Rcode::NXDOMAIN && result.outcome != DenialOutcome::NxDomain {
                return Err(bogus("nsec proved the wrong outcome"));
            }
            return Ok(validated);
        }

        let nsec3: Vec<pulse_dnssec::Nsec3Proof> = authority
            .iter()
            .filter(|record| record.rr_type() == Rtype::NSEC3)
            .map(|record| pulse_dnssec::Nsec3Proof::from_record(record, limits))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| bogus(error.to_string()))?;
        if !nsec3.is_empty() {
            let result = if rcode == Rcode::NXDOMAIN {
                nsec3_nxdomain(qname, &zone, &nsec3, limits)
            } else if qtype == Rtype::DS {
                nsec3_ds_nodata(qname, &zone, &nsec3, limits)
            } else {
                nsec3_nodata(qname, qtype, &zone, &nsec3, limits)
            }
            .map_err(|error| bogus(error.to_string()))?;
            if rcode == Rcode::NXDOMAIN && result.outcome != DenialOutcome::NxDomain {
                return Err(bogus("nsec3 proved the wrong outcome"));
            }
            return Ok(validated);
        }

        Err(bogus("negative answer without NSEC/NSEC3"))
    }

    fn verify_rrset(
        &mut self,
        keys: &ValidatedDnskeySet,
        rrset: &Rrset,
        signatures: &[RrsigData],
    ) -> Result<(), ResolverError> {
        let config = &self.resolver.inner.config.dnssec;
        if signatures.len() > config.max_rrsigs_per_rrset {
            return Err(bogus("too many RRSIG records"));
        }
        let fingerprint = self
            .keyset_fingerprints
            .get(keys.zone())
            .map_or_else(Vec::new, |fingerprint| fingerprint.to_vec());
        let cache_key = signature_cache_key(rrset, signatures, &fingerprint);
        if self
            .resolver
            .inner
            .validation
            .signature_valid(&cache_key, self.now)
        {
            return Ok(());
        }
        self.verifications = self.verifications.saturating_add(signatures.len().max(1));
        if self.verifications > config.max_verifications {
            return Err(bogus("verification budget exhausted"));
        }
        keys.verify_rrset(rrset, signatures, &self.verify_options)
            .map_err(|error| bogus(error.to_string()))?;
        let expires = signature_expiry(rrset.ttl().as_u32(), signatures, self.now);
        self.resolver
            .inner
            .validation
            .store_signature(cache_key.into_boxed_slice(), expires);
        Ok(())
    }

    fn keys_for(&mut self, zone: &Name) -> Result<Option<ValidatedDnskeySet>, ResolverError> {
        if let Some(cached) = self.memo.get(zone) {
            return Ok(cached.clone());
        }
        if !self.visiting.insert(zone.clone()) {
            return Err(bogus("dnssec chain loop"));
        }
        let result = self.compute_keys(zone);
        self.visiting.remove(zone);
        if let Ok(keys) = &result {
            self.memo.insert(zone.clone(), keys.clone());
        }
        result
    }

    fn compute_keys(&mut self, zone: &Name) -> Result<Option<ValidatedDnskeySet>, ResolverError> {
        if self.resolver.inner.validation.has_keys(zone, self.now)
            && let Some(keys) = self.try_cached_keys(zone)?
        {
            return Ok(Some(keys));
        }
        let anchors = self.anchors_for(zone);
        let ds_set = if let Some(anchors) = anchors {
            anchors
        } else {
            let Some(parent) = zone.parent() else {
                return Ok(None);
            };
            let parent_keys = self.keys_for(&parent)?;
            let Some(parent_keys) = parent_keys else {
                return Ok(None);
            };
            let ds_resolution = self.raw_lookup(zone, Rtype::DS)?;
            let ds_records: Vec<Record> = ds_resolution
                .answers
                .iter()
                .filter(|record| record.owner() == zone && record.rr_type() == Rtype::DS)
                .cloned()
                .collect();
            if ds_records.is_empty() {
                self.verify_negative(
                    zone,
                    Rtype::DS,
                    ds_resolution.rcode,
                    &ds_resolution.authority,
                    &parent_keys,
                )?;
                return Ok(None);
            }
            let group = group_rrsets(&ds_records)
                .into_iter()
                .next()
                .ok_or_else(|| bogus("invalid DS rrset"))?;
            let rrset = group.to_rrset().ok_or_else(|| bogus("invalid DS rrset"))?;
            let signatures = rrsigs_for(&ds_resolution.answers, zone, Rtype::DS);
            if signatures.is_empty() {
                return Err(bogus("DS rrset without RRSIG"));
            }
            self.verify_rrset(&parent_keys, &rrset, &signatures)?;
            let mut values = Vec::new();
            for record in &ds_records {
                if let Rdata::Ds(ds) = record.rdata() {
                    values.push(ds.clone());
                }
            }
            if values.is_empty() {
                return Err(bogus("DS rrset without DS data"));
            }
            values
        };

        let key_resolution = self.raw_lookup(zone, Rtype::DNSKEY)?;
        let key_group = group_rrsets(&key_resolution.answers)
            .into_iter()
            .find(|group| group.owner == *zone && group.rr_type == Rtype::DNSKEY)
            .ok_or_else(|| bogus("zone has DS but no DNSKEY"))?;
        let max_keys = self.resolver.inner.config.dnssec.max_dnskeys;
        if key_group.rdatas.len() > max_keys {
            return Err(bogus("too many DNSKEY records"));
        }
        let rrset = key_group
            .to_rrset()
            .ok_or_else(|| bogus("invalid DNSKEY rrset"))?;
        let signatures = rrsigs_for(&key_resolution.answers, zone, Rtype::DNSKEY);
        if signatures.is_empty() {
            return Err(bogus("DNSKEY rrset without RRSIG"));
        }
        let config = &self.resolver.inner.config.dnssec;
        if signatures.len() > config.max_rrsigs_per_rrset {
            return Err(bogus("too many RRSIG records on DNSKEY"));
        }
        self.verifications = self.verifications.saturating_add(signatures.len().max(1));
        if self.verifications > config.max_verifications {
            return Err(bogus("verification budget exhausted"));
        }
        let validated = validate_dnskey_rrset(
            zone,
            &rrset,
            &signatures,
            &ds_set,
            &self.verify_options,
            DsPolicy::strict(),
        )
        .map_err(|error| bogus(error.to_string()))?;
        if let Some(provider) = &self.resolver.inner.config.trust_anchor_provider {
            provider.observe_validated_dnskey(zone, &rrset, self.now);
        }
        let fingerprint = keyset_fingerprint(&rrset);
        let expires = keyset_expiry(&key_resolution, &signatures, self.now);
        self.resolver.inner.validation.store_keys(
            zone,
            fingerprint.clone().into_boxed_slice(),
            validated.clone(),
            expires,
        );
        self.keyset_fingerprints
            .insert(zone.clone(), fingerprint.into_boxed_slice());
        Ok(Some(validated))
    }

    /// Проверяет кеш цепочки по свежему DNSKEY RRset.
    fn try_cached_keys(
        &mut self,
        zone: &Name,
    ) -> Result<Option<ValidatedDnskeySet>, ResolverError> {
        let key_resolution = self.raw_lookup(zone, Rtype::DNSKEY)?;
        let Some(key_group) = group_rrsets(&key_resolution.answers)
            .into_iter()
            .find(|group| group.owner == *zone && group.rr_type == Rtype::DNSKEY)
        else {
            self.resolver.inner.validation.invalidate_keys(zone);
            return Ok(None);
        };
        let Some(rrset) = key_group.to_rrset() else {
            self.resolver.inner.validation.invalidate_keys(zone);
            return Ok(None);
        };
        let fingerprint = keyset_fingerprint(&rrset);
        let Some(keys) = self
            .resolver
            .inner
            .validation
            .lookup_keys(zone, &fingerprint, self.now)
        else {
            return Ok(None);
        };
        self.keyset_fingerprints
            .insert(zone.clone(), fingerprint.into_boxed_slice());
        Ok(Some(keys))
    }

    fn anchors_for(&self, zone: &Name) -> Option<Vec<DsData>> {
        if let Some(provider) = &self.resolver.inner.config.trust_anchor_provider {
            let provided = provider.anchors(zone, self.now);
            if !provided.is_empty() {
                return Some(provided);
            }
        }
        let configured: Vec<DsData> = self
            .resolver
            .static_trust_anchors()
            .iter()
            .filter(|anchor| &anchor.zone == zone)
            .map(|anchor| anchor.ds.clone())
            .collect();
        if !configured.is_empty() {
            return Some(configured);
        }
        if zone != &Name::root() {
            return None;
        }
        let anchors = builtin_root_anchors();
        let active: Vec<DsData> = anchors
            .iter()
            .filter(|anchor| anchor.is_active_at(self.now))
            .filter_map(|anchor| anchor.to_ds().ok())
            .collect();
        if !active.is_empty() {
            return Some(active);
        }
        let all: Vec<DsData> = anchors
            .iter()
            .filter_map(|anchor| anchor.to_ds().ok())
            .collect();
        (!all.is_empty()).then_some(all)
    }

    fn raw_lookup(&mut self, name: &Name, rr_type: Rtype) -> Result<Resolution, ResolverError> {
        if let Some(cached) = self.raw_cache.get(&(name.clone(), rr_type)) {
            return Ok(cached.clone());
        }
        let resolution =
            if let Some(cached) = self.resolver.cache_ref().lookup_exact(name, rr_type, true) {
                let mut answers = cached.records;
                if rr_type != Rtype::RRSIG
                    && let Some(signatures) =
                        self.resolver
                            .cache_ref()
                            .lookup_exact(name, Rtype::RRSIG, true)
                {
                    answers.extend(signatures.records);
                }
                Resolution {
                    rcode: Rcode::NOERROR,
                    answers,
                    authority: Vec::new(),
                    additional: Vec::new(),
                    zone: Name::root(),
                }
            } else if let Some(negative) = self
                .resolver
                .cache_ref()
                .lookup_negative(name, rr_type, true)
            {
                Resolution {
                    rcode: negative.rcode,
                    answers: Vec::new(),
                    authority: negative.authority,
                    additional: Vec::new(),
                    zone: Name::root(),
                }
            } else {
                match &self.resolver.inner.config.mode {
                    crate::config::Mode::Forward(_) => {
                        crate::forward::resolve(self.resolver, name, rr_type, true, self.context)?
                    }
                    crate::config::Mode::Iterative(_) => {
                        crate::iterative::resolve(self.resolver, name, rr_type, true, self.context)?
                    }
                }
            };
        self.raw_cache
            .insert((name.clone(), rr_type), resolution.clone());
        Ok(resolution)
    }
}

fn keyset_fingerprint(rrset: &Rrset) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(rrset.owner().as_wire());
    out.extend_from_slice(&rrset.rr_type().as_u16().to_be_bytes());
    for rdata in rrset.rdatas() {
        let bytes = rdata.to_canonical_wire();
        out.extend_from_slice(&u16::try_from(bytes.len()).unwrap_or(u16::MAX).to_be_bytes());
        out.extend_from_slice(&bytes);
    }
    out
}

fn signature_cache_key(
    rrset: &Rrset,
    signatures: &[RrsigData],
    keyset_fingerprint: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(keyset_fingerprint.len().saturating_add(256));
    out.extend_from_slice(keyset_fingerprint);
    out.extend_from_slice(rrset.owner().as_wire());
    out.extend_from_slice(&rrset.rr_type().as_u16().to_be_bytes());
    for rdata in rrset.rdatas() {
        let bytes = rdata.to_canonical_wire();
        out.extend_from_slice(&u16::try_from(bytes.len()).unwrap_or(u16::MAX).to_be_bytes());
        out.extend_from_slice(&bytes);
    }
    for signature in signatures {
        let bytes = Rdata::Rrsig(signature.clone()).to_canonical_wire();
        out.extend_from_slice(&u16::try_from(bytes.len()).unwrap_or(u16::MAX).to_be_bytes());
        out.extend_from_slice(&bytes);
    }
    out
}

fn keyset_expiry(resolution: &Resolution, signatures: &[RrsigData], now: u32) -> u32 {
    let ttl = resolution
        .answers
        .iter()
        .filter(|record| record.rr_type() == Rtype::DNSKEY)
        .map(|record| record.ttl().as_u32())
        .min()
        .unwrap_or(0);
    let mut expires = now.saturating_add(ttl.min(86_400));
    for signature in signatures {
        expires = expires.min(signature.signature_expiration());
    }
    if expires <= now { 0 } else { expires }
}

fn signature_expiry(rrset_ttl: u32, signatures: &[RrsigData], now: u32) -> u32 {
    let mut expires = now.saturating_add(rrset_ttl.min(86_400));
    for signature in signatures {
        expires = expires.min(signature.signature_expiration());
    }
    if expires <= now { 0 } else { expires }
}

fn insecure() -> ValidationOutcome {
    ValidationOutcome {
        state: Security::Insecure,
        validated: HashSet::new(),
    }
}

fn bogus(reason: impl Into<String>) -> ResolverError {
    ResolverError::Bogus {
        reason: reason.into(),
    }
}

fn unix_now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u32::try_from(duration.as_secs()).unwrap_or(u32::MAX)
        })
}

#[cfg(test)]
mod tests {
    use pulse_dns::{Rclass, Ttl};
    use pulse_dnssec::{
        Algorithm, DsPolicy, PrivateKey, SignOptions, VerifyOptions, ds_from_dnskey, sign_rrset,
        validate_dnskey_rrset,
    };

    use super::*;

    fn validated_keyset(now: u32) -> (Name, ValidatedDnskeySet, Rrset) {
        let zone = Name::parse("example.test").unwrap();
        let key = PrivateKey::generate(Algorithm::ED25519).unwrap();
        let dnskey = key.dnskey(257).unwrap();
        let rrset = Rrset::new(
            zone.clone(),
            Rtype::DNSKEY,
            Rclass::IN,
            Ttl::new(300).unwrap(),
            [Rdata::Dnskey(dnskey.clone())],
        )
        .unwrap();
        let signature = sign_rrset(
            &key,
            &rrset,
            &SignOptions::new(zone.clone(), now, 3600).with_dnskey_flags(257),
        )
        .unwrap();
        let ds = ds_from_dnskey(&zone, &dnskey, 2, DsPolicy::strict()).unwrap();
        let validated = validate_dnskey_rrset(
            &zone,
            &rrset,
            std::slice::from_ref(&signature),
            std::slice::from_ref(&ds),
            &VerifyOptions::new(now),
            DsPolicy::strict(),
        )
        .unwrap();
        (zone, validated, rrset)
    }

    #[test]
    fn keyset_cache_hits_and_invalidates_on_fingerprint_change() {
        let now = unix_now();
        let (zone, keys, rrset) = validated_keyset(now);
        let cache = ValidationCache::new(16);
        let fingerprint = keyset_fingerprint(&rrset);
        cache.store_keys(
            &zone,
            fingerprint.clone().into_boxed_slice(),
            keys,
            now + 300,
        );
        assert!(cache.has_keys(&zone, now));
        assert!(cache.lookup_keys(&zone, &fingerprint, now).is_some());
        assert!(!cache.has_keys(&zone, now.saturating_add(301)));

        cache.store_keys(
            &zone,
            fingerprint.clone().into_boxed_slice(),
            {
                let (_, keys, _) = validated_keyset(now);
                keys
            },
            now + 300,
        );
        assert!(cache.lookup_keys(&zone, b"different", now).is_none());
        assert!(!cache.has_keys(&zone, now));
    }

    #[test]
    fn signature_cache_expires() {
        let now = unix_now();
        let cache = ValidationCache::new(16);
        cache.store_signature(b"sig-key".as_slice().into(), now.saturating_add(10));
        assert!(cache.signature_valid(b"sig-key", now));
        assert!(!cache.signature_valid(b"sig-key", now.saturating_add(11)));
        assert!(!cache.signature_valid(b"missing", now));
        let (hits, misses) = cache.snapshot();
        assert_eq!(hits, 1);
        assert!(misses >= 2);
    }
}
