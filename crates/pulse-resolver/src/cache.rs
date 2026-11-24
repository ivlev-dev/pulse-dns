//! Шардированный RRset-кеш с LRU-вытеснением и negative caching.
//!
//! Горячий путь чтения берёт только `RwLock::read` своего шарда; recency
//! обновляется атомарным счётчиком. Своя LRU выбрана вместо crate `lru`,
//! потому что `lru::LruCache` требует `&mut self` на `get` и тем самым
//! заставляет держать эксклюзивный мьютекс на каждом попадании.
//!
//! Ключ — `(name, type, class)`. Положительная запись хранит один RRset,
//! отрицательная — RCODE и authority (SOA/NSEC) с TTL по RFC 2308.
//! `NXDOMAIN` дополнительно кладётся под типом `ANY`, чтобы отрицательный
//! ответ покрывал все типы имени.

use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use pulse_dns::{Name, Rclass, Rcode, Record, Rtype, Ttl};

use crate::config::CacheConfig;

/// Тип записи, под которым кешируется NXDOMAIN.
const NXDOMAIN_TYPE: Rtype = Rtype::ANY;

/// Состояние DNSSEC-проверки записи.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SecurityState {
    /// Запись получена без валидации (DNSSEC выключен).
    Unvalidated,
    /// Зона/ответ доказанно insecure.
    Insecure,
    /// Все RRset прошли валидацию.
    Secure,
}

/// Ключ кеша.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    name: Name,
    rr_type: Rtype,
    class: Rclass,
}

impl CacheKey {
    fn new(name: &Name, rr_type: Rtype, class: Rclass) -> Self {
        Self {
            name: name.clone(),
            rr_type,
            class,
        }
    }
}

#[derive(Debug, Clone)]
enum CachedValue {
    Positive(Vec<Record>),
    Negative {
        rcode: Rcode,
        authority: Vec<Record>,
    },
}

struct Entry {
    value: CachedValue,
    ttl: u32,
    expires: Instant,
    size: usize,
    secure: SecurityState,
    last_used: AtomicU64,
}

impl std::fmt::Debug for Entry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Entry")
            .field("ttl", &self.ttl)
            .field("size", &self.size)
            .field("secure", &self.secure)
            .finish_non_exhaustive()
    }
}

impl Entry {
    fn remaining(&self, now: Instant) -> u32 {
        if self.expires <= now {
            return 0;
        }
        let seconds = u32::try_from(self.expires.saturating_duration_since(now).as_secs())
            .unwrap_or(u32::MAX);
        seconds.max(1)
    }

    fn snapshot(&self, now: Instant) -> Option<EntryView> {
        let remaining = self.remaining(now);
        if remaining == 0 {
            return None;
        }
        Some(EntryView {
            value: self.value.clone(),
            remaining,
            secure: self.secure,
        })
    }
}

struct EntryView {
    value: CachedValue,
    remaining: u32,
    secure: SecurityState,
}

#[derive(Debug, Default)]
struct Shard {
    map: HashMap<CacheKey, Entry>,
    bytes: usize,
    clock: AtomicU64,
}

#[derive(Debug, Default)]
struct Counters {
    hits: AtomicU64,
    misses: AtomicU64,
    inserts: AtomicU64,
    evictions: AtomicU64,
}

/// Снимок статистики кеша.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CacheSnapshot {
    /// Попадания.
    pub hits: u64,
    /// Промахи (включая просроченные записи).
    pub misses: u64,
    /// Вставки.
    pub inserts: u64,
    /// Вытеснения.
    pub evictions: u64,
    /// Текущее число записей.
    pub entries: usize,
    /// Приблизительный размер в байтах.
    pub bytes: usize,
}

/// Результат поиска положительного ответа.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheAnswer {
    /// Записи ответа с уменьшенным TTL.
    pub records: Vec<Record>,
    /// Все записи цепочки были DNSSEC-secure.
    pub secure: bool,
}

/// Результат поиска отрицательного ответа.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegativeAnswer {
    /// RCODE.
    pub rcode: Rcode,
    /// Authority-записи с уменьшенным TTL.
    pub authority: Vec<Record>,
    /// Ответ был DNSSEC-secure.
    pub secure: bool,
}

/// Шардированный кеш.
#[derive(Debug)]
pub struct Cache {
    shards: Box<[RwLock<Shard>]>,
    config: CacheConfig,
    counters: Counters,
}

impl Cache {
    pub(crate) fn new(config: CacheConfig) -> Self {
        let shards = (0..config.shards)
            .map(|_| RwLock::new(Shard::default()))
            .collect::<Vec<_>>();
        Self {
            shards: shards.into_boxed_slice(),
            config,
            counters: Counters::default(),
        }
    }

    /// Удаляет всё содержимое кеша.
    pub fn purge(&self) {
        for shard in &self.shards {
            if let Ok(mut guard) = shard.write() {
                guard.map.clear();
                guard.bytes = 0;
            }
        }
    }

    /// Удаляет записи по имени и/или типу.
    ///
    /// `None` означает «любое значение». Возвращает число удалённых записей.
    /// Удаление идёт по шардам под короткой write-блокировкой, поэтому
    /// параллельные чтения горячего пути не теряют уже полученные ответы.
    pub fn purge_matching(&self, name: Option<&Name>, rr_type: Option<Rtype>) -> usize {
        if name.is_none() && rr_type.is_none() {
            let mut removed = 0_usize;
            for shard in &self.shards {
                let Ok(mut guard) = shard.write() else {
                    continue;
                };
                removed = removed.saturating_add(guard.map.len());
                guard.map.clear();
                guard.bytes = 0;
            }
            return removed;
        }
        let mut removed = 0_usize;
        for shard in &self.shards {
            let Ok(mut guard) = shard.write() else {
                continue;
            };
            let before = guard.map.len();
            guard.map.retain(|key, _| {
                let name_matches = name.is_none_or(|name| &key.name == name);
                let type_matches = rr_type.is_none_or(|rr_type| key.rr_type == rr_type);
                !(name_matches && type_matches)
            });
            let after = guard.map.len();
            removed = removed.saturating_add(before.saturating_sub(after));
            if after != before {
                guard.bytes = guard.map.values().map(|entry| entry.size).sum();
            }
        }
        removed
    }

    /// Текущее число записей.
    #[must_use]
    pub fn len(&self) -> usize {
        self.shards
            .iter()
            .filter_map(|shard| shard.read().ok().map(|guard| guard.map.len()))
            .sum()
    }

    /// Пуст ли кеш.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Снимок статистики.
    #[must_use]
    pub fn snapshot(&self) -> CacheSnapshot {
        let mut entries = 0_usize;
        let mut bytes = 0_usize;
        for shard in &self.shards {
            if let Ok(guard) = shard.read() {
                entries += guard.map.len();
                bytes += guard.bytes;
            }
        }
        CacheSnapshot {
            hits: self.counters.hits.load(Ordering::Relaxed),
            misses: self.counters.misses.load(Ordering::Relaxed),
            inserts: self.counters.inserts.load(Ordering::Relaxed),
            evictions: self.counters.evictions.load(Ordering::Relaxed),
            entries,
            bytes,
        }
    }

    /// Ищет положительный ответ, при необходимости проходя CNAME-цепочку.
    ///
    /// `accept_unvalidated` включается только для внутренних DNSSEC-запросов
    /// (DS/DNSKEY), которым нужны сырые данные.
    #[must_use]
    pub(crate) fn lookup_answer(
        &self,
        name: &Name,
        rr_type: Rtype,
        accept_unvalidated: bool,
    ) -> Option<CacheAnswer> {
        let now = Instant::now();
        let mut current = name.clone();
        let mut records = Vec::new();
        let mut secure = true;
        for _ in 0..16 {
            if let Some(view) = self.get(&CacheKey::new(&current, rr_type, Rclass::IN), now) {
                if view.secure == SecurityState::Unvalidated && !accept_unvalidated {
                    return None;
                }
                let CachedValue::Positive(positive) = view.value else {
                    return None;
                };
                secure &= view.secure == SecurityState::Secure;
                records.extend(apply_ttl(CachedValue::Positive(positive), view.remaining));
                if rr_type != Rtype::RRSIG {
                    self.append_signatures(&mut records, &current, now, accept_unvalidated);
                }
                return Some(CacheAnswer { records, secure });
            }
            let cname_key = CacheKey::new(&current, Rtype::CNAME, Rclass::IN);
            let view = self.get(&cname_key, now)?;
            if view.secure == SecurityState::Unvalidated && !accept_unvalidated {
                return None;
            }
            secure &= view.secure == SecurityState::Secure;
            let CachedValue::Positive(cname_records) = view.value else {
                return None;
            };
            let target = cname_records
                .iter()
                .find_map(|record| match record.rdata() {
                    pulse_dns::Rdata::Cname(target) => Some(target.clone()),
                    _ => None,
                });
            records.extend(apply_ttl(
                CachedValue::Positive(cname_records),
                view.remaining,
            ));
            self.append_signatures(&mut records, &current, now, accept_unvalidated);
            current = target?;
        }
        None
    }

    fn append_signatures(
        &self,
        records: &mut Vec<Record>,
        owner: &Name,
        now: Instant,
        accept_unvalidated: bool,
    ) {
        let key = CacheKey::new(owner, Rtype::RRSIG, Rclass::IN);
        let Some(view) = self.peek(&key, now) else {
            return;
        };
        if view.secure == SecurityState::Unvalidated && !accept_unvalidated {
            return;
        }
        let CachedValue::Positive(signatures) = view.value else {
            return;
        };
        records.extend(apply_ttl(CachedValue::Positive(signatures), view.remaining));
    }

    /// Ищет ровно один RRset (без CNAME-обхода).
    #[must_use]
    pub(crate) fn lookup_exact(
        &self,
        name: &Name,
        rr_type: Rtype,
        accept_unvalidated: bool,
    ) -> Option<CacheAnswer> {
        let now = Instant::now();
        let view = self.get(&CacheKey::new(name, rr_type, Rclass::IN), now)?;
        if view.secure == SecurityState::Unvalidated && !accept_unvalidated {
            return None;
        }
        let CachedValue::Positive(positive) = view.value else {
            return None;
        };
        Some(CacheAnswer {
            records: apply_ttl(CachedValue::Positive(positive), view.remaining),
            secure: view.secure == SecurityState::Secure,
        })
    }

    /// Ищет отрицательный ответ по типу, затем NXDOMAIN-запись имени.
    #[must_use]
    pub(crate) fn lookup_negative(
        &self,
        name: &Name,
        rr_type: Rtype,
        accept_unvalidated: bool,
    ) -> Option<NegativeAnswer> {
        let now = Instant::now();
        for key_type in [rr_type, NXDOMAIN_TYPE] {
            let key = CacheKey::new(name, key_type, Rclass::IN);
            let Some(view) = self.get(&key, now) else {
                continue;
            };
            if view.secure == SecurityState::Unvalidated && !accept_unvalidated {
                return None;
            }
            let CachedValue::Negative { rcode, authority } = view.value else {
                continue;
            };
            return Some(NegativeAnswer {
                rcode,
                authority: apply_ttl(CachedValue::Negative { rcode, authority }, view.remaining),
                secure: view.secure == SecurityState::Secure,
            });
        }
        None
    }

    /// Вставляет положительный RRset.
    pub(crate) fn insert_rrset(
        &self,
        name: &Name,
        rr_type: Rtype,
        class: Rclass,
        records: &[Record],
        secure: SecurityState,
    ) {
        let Some(first) = records.first() else {
            return;
        };
        let ttl = self.clamp_ttl(first.ttl().as_u32());
        if ttl == 0 {
            return;
        }
        self.insert(
            CacheKey::new(name, rr_type, class),
            CachedValue::Positive(records.to_vec()),
            ttl,
            secure,
        );
    }

    /// Вставляет отрицательный ответ.
    pub(crate) fn insert_negative(
        &self,
        name: &Name,
        rr_type: Rtype,
        rcode: Rcode,
        authority: &[Record],
        ttl: u32,
        secure: SecurityState,
    ) {
        let ttl = self.clamp_ttl(ttl);
        if ttl == 0 {
            return;
        }
        let key = CacheKey::new(name, rr_type, Rclass::IN);
        self.insert(
            key,
            CachedValue::Negative {
                rcode,
                authority: authority.to_vec(),
            },
            ttl,
            secure,
        );
        if rcode == Rcode::NXDOMAIN && rr_type != NXDOMAIN_TYPE {
            self.insert(
                CacheKey::new(name, NXDOMAIN_TYPE, Rclass::IN),
                CachedValue::Negative {
                    rcode,
                    authority: authority.to_vec(),
                },
                ttl,
                secure,
            );
        }
    }

    fn clamp_ttl(&self, ttl: u32) -> u32 {
        ttl.max(self.config.min_ttl).min(self.config.max_ttl)
    }

    fn insert(&self, key: CacheKey, value: CachedValue, ttl: u32, secure: SecurityState) {
        let Some(shard) = self.shard(&key) else {
            return;
        };
        let size = approximate_size(&value);
        let now = Instant::now();
        let Some(expires) = now.checked_add(std::time::Duration::from_secs(u64::from(ttl))) else {
            return;
        };
        let Ok(mut guard) = shard.write() else {
            return;
        };
        let clock = guard.clock.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        if let Some(previous) = guard.map.remove(&key) {
            guard.bytes = guard.bytes.saturating_sub(previous.size);
        }
        guard.map.insert(
            key,
            Entry {
                value,
                ttl,
                expires,
                size,
                secure,
                last_used: AtomicU64::new(clock),
            },
        );
        guard.bytes = guard.bytes.saturating_add(size);
        self.counters.inserts.fetch_add(1, Ordering::Relaxed);
        self.evict(&mut guard);
    }

    fn evict(&self, shard: &mut Shard) {
        let max_entries = (self.config.max_entries / self.config.shards).max(1);
        let max_bytes = (self.config.max_bytes / self.config.shards).max(512);
        while shard.map.len() > max_entries || shard.bytes > max_bytes {
            let Some(victim) = shard
                .map
                .iter()
                .min_by_key(|(_, entry)| entry.last_used.load(Ordering::Relaxed))
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            if let Some(removed) = shard.map.remove(&victim) {
                shard.bytes = shard.bytes.saturating_sub(removed.size);
                self.counters.evictions.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn peek(&self, key: &CacheKey, now: Instant) -> Option<EntryView> {
        let shard = self.shard(key)?;
        let guard = shard.read().ok()?;
        let entry = guard.map.get(key)?;
        if entry.expires <= now {
            return None;
        }
        entry.snapshot(now)
    }

    fn get(&self, key: &CacheKey, now: Instant) -> Option<EntryView> {
        let shard = self.shard(key)?;
        let expired = {
            let Ok(guard) = shard.read() else {
                return None;
            };
            let Some(entry) = guard.map.get(key) else {
                self.counters.misses.fetch_add(1, Ordering::Relaxed);
                return None;
            };
            if entry.expires <= now {
                true
            } else {
                let view = entry.snapshot(now);
                let Some(view) = view else {
                    self.counters.misses.fetch_add(1, Ordering::Relaxed);
                    return None;
                };
                entry.last_used.store(
                    guard.clock.fetch_add(1, Ordering::Relaxed).wrapping_add(1),
                    Ordering::Relaxed,
                );
                self.counters.hits.fetch_add(1, Ordering::Relaxed);
                return Some(view);
            }
        };
        if expired
            && let Ok(mut guard) = shard.write()
            && let Some(removed) = guard.map.remove(key)
        {
            guard.bytes = guard.bytes.saturating_sub(removed.size);
        }
        self.counters.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    fn shard(&self, key: &CacheKey) -> Option<&RwLock<Shard>> {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        let index = usize::try_from(hasher.finish()).unwrap_or(0) % self.shards.len().max(1);
        self.shards.get(index).or_else(|| self.shards.first())
    }
}

fn apply_ttl(value: CachedValue, ttl: u32) -> Vec<Record> {
    let records = match value {
        CachedValue::Positive(records) => records,
        CachedValue::Negative { authority, .. } => authority,
    };
    let ttl = Ttl::from_wire(ttl);
    records
        .into_iter()
        .filter_map(|record| {
            Record::new(
                record.owner().clone(),
                record.rr_type(),
                record.class(),
                ttl,
                record.rdata().clone(),
            )
            .ok()
        })
        .collect()
}

fn approximate_size(value: &CachedValue) -> usize {
    let records: &[Record] = match value {
        CachedValue::Positive(records) => records,
        CachedValue::Negative { authority, .. } => authority,
    };
    records
        .iter()
        .map(|record| record.owner().wire_len() + record.rdata().wire_len() + 32)
        .sum::<usize>()
        + 64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::thread;
    use std::time::Duration;

    use pulse_dns::{Rdata, Ttl};

    fn name(value: &str) -> Name {
        Name::parse(value).unwrap()
    }

    fn record(owner: &str, ttl: u32, address: u8) -> Record {
        Record::new(
            name(owner),
            Rtype::A,
            Rclass::IN,
            Ttl::new(ttl).unwrap(),
            Rdata::A(Ipv4Addr::new(192, 0, 2, address)),
        )
        .unwrap()
    }

    fn cache(max_ttl: u32) -> Cache {
        Cache::new(CacheConfig {
            max_entries: 128,
            max_bytes: 1 << 20,
            min_ttl: 0,
            max_ttl,
            shards: 4,
        })
    }

    #[test]
    fn hit_and_ttl_decrement() {
        let cache = cache(300);
        let rrset = vec![record("example.com", 10, 1)];
        cache.insert_rrset(
            &name("example.com"),
            Rtype::A,
            Rclass::IN,
            &rrset,
            SecurityState::Secure,
        );
        let answer = cache
            .lookup_answer(&name("example.com"), Rtype::A, false)
            .unwrap();
        assert!(answer.secure);
        assert_eq!(answer.records.len(), 1);
        assert!(answer.records[0].ttl().as_u32() <= 10);
        let snapshot = cache.snapshot();
        assert_eq!(snapshot.hits, 1);
        assert_eq!(snapshot.misses, 0);
    }

    #[test]
    fn expiry_is_miss() {
        let cache = cache(300);
        let rrset = vec![record("example.com", 1, 1)];
        cache.insert_rrset(
            &name("example.com"),
            Rtype::A,
            Rclass::IN,
            &rrset,
            SecurityState::Insecure,
        );
        thread::sleep(Duration::from_millis(1100));
        assert!(
            cache
                .lookup_answer(&name("example.com"), Rtype::A, false)
                .is_none()
        );
        assert!(cache.snapshot().misses >= 1);
    }

    #[test]
    fn ttl_is_clamped_on_insert() {
        let cache = cache(50);
        let rrset = vec![record("example.com", 1000, 1)];
        cache.insert_rrset(
            &name("example.com"),
            Rtype::A,
            Rclass::IN,
            &rrset,
            SecurityState::Unvalidated,
        );
        let answer = cache
            .lookup_answer(&name("example.com"), Rtype::A, true)
            .unwrap();
        assert!(answer.records[0].ttl().as_u32() <= 50);
    }

    #[test]
    fn negative_nxdomain_matches_any_type() {
        let cache = cache(300);
        let soa = vec![record("example.com", 30, 1)];
        cache.insert_negative(
            &name("missing.example.com"),
            Rtype::A,
            Rcode::NXDOMAIN,
            &soa,
            30,
            SecurityState::Secure,
        );
        let answer = cache
            .lookup_negative(&name("missing.example.com"), Rtype::AAAA, false)
            .unwrap();
        assert_eq!(answer.rcode, Rcode::NXDOMAIN);
        assert!(answer.secure);
    }

    #[test]
    fn eviction_respects_entry_limit() {
        let cache = Cache::new(CacheConfig {
            max_entries: 4,
            max_bytes: 1 << 20,
            min_ttl: 0,
            max_ttl: 300,
            shards: 1,
        });
        for index in 0..16_u8 {
            let owner = format!("host{index}.example.com");
            let rrset = vec![record(&owner, 30, index)];
            cache.insert_rrset(
                &name(&owner),
                Rtype::A,
                Rclass::IN,
                &rrset,
                SecurityState::Unvalidated,
            );
        }
        assert!(cache.len() <= 4);
        assert!(cache.snapshot().evictions >= 12);
    }

    #[test]
    fn unvalidated_is_rejected_when_validation_enabled() {
        let cache = cache(300);
        let rrset = vec![record("example.com", 30, 1)];
        cache.insert_rrset(
            &name("example.com"),
            Rtype::A,
            Rclass::IN,
            &rrset,
            SecurityState::Unvalidated,
        );
        assert!(
            cache
                .lookup_answer(&name("example.com"), Rtype::A, false)
                .is_none()
        );
        assert!(
            cache
                .lookup_answer(&name("example.com"), Rtype::A, true)
                .is_some()
        );
    }

    #[test]
    fn cname_chain_is_resolved() {
        let cache = cache(300);
        let cname = vec![
            Record::new(
                name("alias.example.com"),
                Rtype::CNAME,
                Rclass::IN,
                Ttl::new(30).unwrap(),
                Rdata::Cname(name("target.example.com")),
            )
            .unwrap(),
        ];
        cache.insert_rrset(
            &name("alias.example.com"),
            Rtype::CNAME,
            Rclass::IN,
            &cname,
            SecurityState::Secure,
        );
        cache.insert_rrset(
            &name("target.example.com"),
            Rtype::A,
            Rclass::IN,
            &[record("target.example.com", 30, 9)],
            SecurityState::Secure,
        );
        let answer = cache
            .lookup_answer(&name("alias.example.com"), Rtype::A, false)
            .unwrap();
        assert_eq!(answer.records.len(), 2);
        assert_eq!(answer.records[0].rr_type(), Rtype::CNAME);
        assert_eq!(answer.records[1].rr_type(), Rtype::A);
    }
}
