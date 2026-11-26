//! Кеш готовых wire-ответов для статичных зон.
//!
//! Ключ включает идентичность зоны (`zone_seq` + опубликованная версия),
//! исходную (0x20-совместимую) wire-форму `QNAME`, `QTYPE`/`QCLASS`, биты
//! `DO`/`CD`/`RD`, согласованный EDNS payload и транспорт. Значение — полный
//! wire-ответ с `ID = 0`; при выдаче патчатся только два байта идентификатора,
//! поэтому `TTL` остаются авторскими и не декрементируются.
//!
//! Кеш разбит на шарды (`Mutex` на шард), память ограничена числом записей и
//! байтами; вытеснение приближённое LRU (выборка самых старых отметок).
//! Инвалидация — по смене версии зоны (ключ перестаёт совпадать) и явная
//! [`ResponseCache::invalidate_zone`] при пересборке view зоны.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use super::query::Transport;

/// Значение по умолчанию для `max_entries`.
pub const DEFAULT_MAX_ENTRIES: usize = 100_000;
/// Значение по умолчанию для `max_bytes`.
pub const DEFAULT_MAX_BYTES: usize = 64 * 1024 * 1024;
/// Значение по умолчанию для числа шардов.
pub const DEFAULT_SHARDS: usize = 16;
/// Верхняя граница числа шардов.
pub const MAX_SHARDS: usize = 256;

/// Сколько записей просматривать при выборе жертвы приближённого LRU.
const EVICTION_SAMPLE: usize = 8;
/// Постоянные накладные расходы записи (ключ, `Arc`, метаданные).
const ENTRY_OVERHEAD: usize = 96;

/// Идентичность версии зоны для ключа кеша.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ZoneIdentity {
    /// Слот зоны (`zone_seq`).
    pub zone_seq: u64,
    /// Опубликованная версия головы зоны.
    pub zone_version: u64,
}

/// Настройки кеша ответов.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseCacheConfig {
    /// Включён ли кеш.
    pub enabled: bool,
    /// Максимум записей.
    pub max_entries: usize,
    /// Максимум байт (ключ + значение + накладные расходы).
    pub max_bytes: usize,
    /// Число шардов (1..=[`MAX_SHARDS`]).
    pub shards: usize,
}

impl Default for ResponseCacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_entries: DEFAULT_MAX_ENTRIES,
            max_bytes: DEFAULT_MAX_BYTES,
            shards: DEFAULT_SHARDS,
        }
    }
}

impl ResponseCacheConfig {
    /// Отключает кеш.
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            enabled: false,
            max_entries: 0,
            max_bytes: 0,
            shards: 1,
        }
    }

    /// Нормализованное число шардов.
    #[must_use]
    pub fn normalized_shards(self) -> usize {
        self.shards.clamp(1, MAX_SHARDS)
    }
}

/// Итог ответа, сохранённый рядом с wire-байтами.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CachedOutcome {
    /// Положительный ответ.
    Answer,
    /// `NODATA` (`NOERROR`, пустой answer).
    NoData,
    /// `NXDOMAIN`.
    NxDomain,
    /// Referral (`AA = 0`).
    Referral,
    /// `YXDOMAIN` при переполнении синтеза `DNAME`.
    YxDomain,
}

/// Ключ кеша готового ответа.
///
/// Конструируется движком; поля непрозрачны для вызывающего.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResponseCacheKey {
    zone_seq: u64,
    zone_version: u64,
    qname: [u8; pulse_dns::MAX_NAME_WIRE_LEN],
    qname_len: u8,
    qtype: u16,
    qclass: u16,
    dnssec_ok: bool,
    checking_disabled: bool,
    recursion_desired: bool,
    edns_payload: Option<u16>,
    transport: Transport,
}

impl ResponseCacheKey {
    /// Собирает ключ из идентичности зоны и параметров запроса.
    ///
    /// `None` — `QNAME` длиннее wire-лимита (не может прийти из валидного
    /// запроса, но контракт не паникует).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        identity: ZoneIdentity,
        qname: &[u8],
        qtype: u16,
        qclass: u16,
        dnssec_ok: bool,
        checking_disabled: bool,
        recursion_desired: bool,
        edns_payload: Option<u16>,
        transport: Transport,
    ) -> Option<Self> {
        let mut wire = [0_u8; pulse_dns::MAX_NAME_WIRE_LEN];
        let dst = wire.get_mut(..qname.len())?;
        dst.copy_from_slice(qname);
        Some(Self {
            zone_seq: identity.zone_seq,
            zone_version: identity.zone_version,
            qname: wire,
            qname_len: u8::try_from(qname.len()).ok()?,
            qtype,
            qclass,
            dnssec_ok,
            checking_disabled,
            recursion_desired,
            edns_payload,
            transport,
        })
    }

    /// `zone_seq`, к которому относится запись.
    #[must_use]
    pub const fn zone_seq(&self) -> u64 {
        self.zone_seq
    }

    fn qname(&self) -> &[u8] {
        self.qname.get(..usize::from(self.qname_len)).unwrap_or(&[])
    }

    const fn charge() -> usize {
        std::mem::size_of::<Self>()
    }

    fn shard_index(&self, shards: usize) -> usize {
        let mut hash = 0xcbf2_9ce4_8422_2325_u64;
        fnv(&mut hash, &self.zone_seq.to_le_bytes());
        fnv(&mut hash, &self.zone_version.to_le_bytes());
        fnv(&mut hash, self.qname());
        fnv(&mut hash, &self.qtype.to_le_bytes());
        fnv(&mut hash, &self.qclass.to_le_bytes());
        let flags = u8::from(self.dnssec_ok)
            | (u8::from(self.checking_disabled) << 1)
            | (u8::from(self.recursion_desired) << 2);
        fnv(&mut hash, &[flags]);
        match self.edns_payload {
            Some(payload) => {
                fnv(&mut hash, &[1]);
                fnv(&mut hash, &payload.to_le_bytes());
            }
            None => fnv(&mut hash, &[0]),
        }
        fnv(
            &mut hash,
            &[match self.transport {
                Transport::Udp => 0,
                Transport::Tcp => 1,
            }],
        );
        usize::try_from(hash).unwrap_or(usize::MAX) % shards.max(1)
    }
}

fn fnv(hash: &mut u64, bytes: &[u8]) {
    for byte in bytes {
        *hash ^= u64::from(*byte);
        *hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
}

/// Снимок метрик кеша.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResponseCacheMetrics {
    /// Текущее число записей.
    pub entries: u64,
    /// Текущий объём записей в байтах.
    pub bytes: u64,
    /// Попадания.
    pub hits: u64,
    /// Промахи.
    pub misses: u64,
    /// Вставки.
    pub inserts: u64,
    /// Вытеснения по лимиту памяти/записей.
    pub evictions: u64,
    /// Явные инвалидации (записи, удалённые при смене версии зоны/каталога).
    pub invalidations: u64,
}

impl ResponseCacheMetrics {
    /// Доля попаданий (`hits / (hits + misses)`); `0.0` без запросов.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits.saturating_add(self.misses);
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
    }
}

/// Результат попадания в кеш.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CacheHit {
    /// Длина скопированного ответа.
    pub len: usize,
    /// Сохранённый итог ответа.
    pub outcome: CachedOutcome,
}

struct CacheEntry {
    bytes: Arc<[u8]>,
    stamp: u64,
    charge: usize,
}

struct Shard {
    entries: HashMap<ResponseCacheKey, CacheEntry>,
    bytes: usize,
    clock: u64,
}

impl Shard {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            bytes: 0,
            clock: 0,
        }
    }

    fn tick(&mut self) -> u64 {
        self.clock = self.clock.wrapping_add(1);
        self.clock
    }

    fn evict_one(&mut self) -> bool {
        let Some(victim) = self
            .entries
            .iter()
            .take(EVICTION_SAMPLE)
            .min_by_key(|(_, entry)| entry.stamp)
            .map(|(key, _)| key.clone())
        else {
            return false;
        };
        if let Some(entry) = self.entries.remove(&victim) {
            self.bytes = self.bytes.saturating_sub(entry.charge);
            return true;
        }
        false
    }
}

/// Потокобезопасный кеш готовых ответов.
pub struct ResponseCache {
    enabled: bool,
    max_entries_per_shard: usize,
    max_bytes_per_shard: usize,
    shards: Vec<Mutex<Shard>>,
    hits: AtomicU64,
    misses: AtomicU64,
    inserts: AtomicU64,
    evictions: AtomicU64,
    invalidations: AtomicU64,
}

impl core::fmt::Debug for ResponseCache {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ResponseCache")
            .field("enabled", &self.enabled)
            .field("shards", &self.shards.len())
            .finish_non_exhaustive()
    }
}

impl ResponseCache {
    /// Создаёт кеш по конфигурации; нулевые лимиты нормализуются к минимуму.
    #[must_use]
    pub fn new(config: ResponseCacheConfig) -> Self {
        let shards = config.normalized_shards();
        let min_per_shard = usize::from(config.enabled);
        let max_entries_per_shard = config.max_entries.div_ceil(shards).max(min_per_shard);
        let max_bytes_per_shard = config.max_bytes.div_ceil(shards).max(min_per_shard);
        Self {
            enabled: config.enabled,
            max_entries_per_shard,
            max_bytes_per_shard,
            shards: (0..shards).map(|_| Mutex::new(Shard::new())).collect(),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            inserts: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
            invalidations: AtomicU64::new(0),
        }
    }

    /// Включён ли кеш.
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    fn shard(&self, key: &ResponseCacheKey) -> Option<&Mutex<Shard>> {
        self.shards.get(key.shard_index(self.shards.len()))
    }

    /// Ищет ответ, копирует его в `out` и патчит `ID`.
    ///
    /// `None` — промах либо `out` меньше сохранённого ответа.
    pub(crate) fn lookup(
        &self,
        key: &ResponseCacheKey,
        id: u16,
        out: &mut [u8],
    ) -> Option<CacheHit> {
        if !self.enabled {
            return None;
        }
        let shard = self.shard(key);
        let mut shard = shard?.lock().unwrap_or_else(PoisonError::into_inner);
        let stamp = shard.tick();
        let Some(entry) = shard.entries.get_mut(key) else {
            drop(shard);
            self.misses.fetch_add(1, Ordering::Relaxed);
            return None;
        };
        entry.stamp = stamp;
        let bytes = Arc::clone(&entry.bytes);
        let outcome = entry_outcome(&bytes)?;
        drop(shard);

        let payload = bytes.get(OUTCOME_PREFIX..)?;
        let dst = out.get_mut(..payload.len())?;
        dst.copy_from_slice(payload);
        let id_bytes = dst.get_mut(..2)?;
        id_bytes.copy_from_slice(&id.to_be_bytes());
        self.hits.fetch_add(1, Ordering::Relaxed);
        Some(CacheHit {
            len: payload.len(),
            outcome,
        })
    }

    /// Сохраняет готовый ответ. Первые два байта (`ID`) обнуляются.
    pub(crate) fn insert(&self, key: ResponseCacheKey, response: &[u8], outcome: CachedOutcome) {
        if !self.enabled || response.len() < 2 {
            return;
        }
        let mut value = response.to_vec();
        if let Some(id) = value.get_mut(..2) {
            id.fill(0);
        }
        let charge = ResponseCacheKey::charge() + value.len() + OUTCOME_PREFIX + ENTRY_OVERHEAD;
        if charge > self.max_bytes_per_shard {
            return;
        }
        let bytes: Arc<[u8]> = Arc::from(encode_outcome(outcome, value).into_boxed_slice());
        let Some(shard) = self.shard(&key) else {
            return;
        };
        let mut shard = shard.lock().unwrap_or_else(PoisonError::into_inner);
        let stamp = shard.tick();
        if let Some(previous) = shard.entries.remove(&key) {
            shard.bytes = shard.bytes.saturating_sub(previous.charge);
        }
        shard.bytes = shard.bytes.saturating_add(charge);
        shard.entries.insert(
            key,
            CacheEntry {
                bytes,
                stamp,
                charge,
            },
        );
        self.inserts.fetch_add(1, Ordering::Relaxed);
        while shard.entries.len() > self.max_entries_per_shard
            || shard.bytes > self.max_bytes_per_shard
        {
            if !shard.evict_one() {
                break;
            }
            self.evictions.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Удаляет все записи зоны `zone_seq`; возвращает число удалённых.
    ///
    /// Вызывается при пересборке view зоны (REST-правка/удаление), чтобы не
    /// держать в памяти недостижимые по версии записи.
    pub fn invalidate_zone(&self, zone_seq: u64) -> usize {
        let mut removed = 0_usize;
        for shard in &self.shards {
            let mut shard = shard.lock().unwrap_or_else(PoisonError::into_inner);
            let mut freed = 0_usize;
            let before = shard.entries.len();
            shard.entries.retain(|key, entry| {
                let keep = key.zone_seq != zone_seq;
                if !keep {
                    freed = freed.saturating_add(entry.charge);
                }
                keep
            });
            removed = removed.saturating_add(before.saturating_sub(shard.entries.len()));
            shard.bytes = shard.bytes.saturating_sub(freed);
        }
        if removed > 0 {
            self.invalidations
                .fetch_add(removed as u64, Ordering::Relaxed);
        }
        removed
    }

    /// Полностью очищает кеш (смена каталога зон).
    pub fn invalidate_all(&self) -> usize {
        let mut removed = 0_usize;
        for shard in &self.shards {
            let mut shard = shard.lock().unwrap_or_else(PoisonError::into_inner);
            removed = removed.saturating_add(shard.entries.len());
            shard.entries.clear();
            shard.bytes = 0;
        }
        if removed > 0 {
            self.invalidations
                .fetch_add(removed as u64, Ordering::Relaxed);
        }
        removed
    }

    /// Снимок метрик.
    #[must_use]
    pub fn metrics(&self) -> ResponseCacheMetrics {
        let mut entries = 0_u64;
        let mut bytes = 0_u64;
        for shard in &self.shards {
            let shard = shard.lock().unwrap_or_else(PoisonError::into_inner);
            entries = entries.saturating_add(shard.entries.len() as u64);
            bytes = bytes.saturating_add(shard.bytes as u64);
        }
        ResponseCacheMetrics {
            entries,
            bytes,
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            inserts: self.inserts.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
            invalidations: self.invalidations.load(Ordering::Relaxed),
        }
    }
}

/// Маркер итога кодируется в первом байте служебного префикса.
///
/// Значение хранится рядом с wire-ответом, чтобы попадание не открывало зону
/// повторно ради счётчиков `NXDOMAIN`/`NODATA`.
const OUTCOME_PREFIX: usize = 1;

fn encode_outcome(outcome: CachedOutcome, mut response: Vec<u8>) -> Vec<u8> {
    let mut framed = Vec::with_capacity(response.len() + OUTCOME_PREFIX);
    framed.push(outcome_tag(outcome));
    framed.append(&mut response);
    framed
}

fn entry_outcome(entry: &[u8]) -> Option<CachedOutcome> {
    match entry.first().copied()? {
        0 => Some(CachedOutcome::Answer),
        1 => Some(CachedOutcome::NoData),
        2 => Some(CachedOutcome::NxDomain),
        3 => Some(CachedOutcome::Referral),
        4 => Some(CachedOutcome::YxDomain),
        _ => None,
    }
}

const fn outcome_tag(outcome: CachedOutcome) -> u8 {
    match outcome {
        CachedOutcome::Answer => 0,
        CachedOutcome::NoData => 1,
        CachedOutcome::NxDomain => 2,
        CachedOutcome::Referral => 3,
        CachedOutcome::YxDomain => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seq: u64, version: u64, name: &[u8], transport: Transport) -> ResponseCacheKey {
        ResponseCacheKey::new(
            ZoneIdentity {
                zone_seq: seq,
                zone_version: version,
            },
            name,
            pulse_dns::Rtype::A.as_u16(),
            pulse_dns::Rclass::IN.as_u16(),
            false,
            false,
            false,
            None,
            transport,
        )
        .expect("key")
    }

    fn response(id: u16, payload: &[u8]) -> Vec<u8> {
        let mut bytes = id.to_be_bytes().to_vec();
        bytes.extend_from_slice(payload);
        bytes
    }

    #[test]
    fn hit_patches_id_and_keeps_payload() {
        let cache = ResponseCache::new(ResponseCacheConfig::default());
        let key = key(1, 1, b"\x03www\x07example\x03com\x00", Transport::Udp);
        cache.insert(
            key.clone(),
            &response(0xAAAA, b"payload"),
            CachedOutcome::Answer,
        );
        let mut out = [0_u8; 16];
        let hit = cache.lookup(&key, 0x1234, &mut out).expect("hit");
        assert_eq!(hit.len, 9);
        assert_eq!(&out[..2], &0x1234_u16.to_be_bytes());
        assert_eq!(&out[2..9], b"payload");
        assert_eq!(cache.metrics().hits, 1);
    }

    #[test]
    fn miss_after_version_change() {
        let cache = ResponseCache::new(ResponseCacheConfig::default());
        let old = key(1, 1, b"\x00", Transport::Udp);
        cache.insert(old.clone(), &response(0, b"x"), CachedOutcome::Answer);
        let new = key(1, 2, b"\x00", Transport::Udp);
        assert!(cache.lookup(&new, 1, &mut [0_u8; 8]).is_none());
        assert_eq!(cache.metrics().misses, 1);
    }

    #[test]
    fn invalidate_zone_frees_entries() {
        let cache = ResponseCache::new(ResponseCacheConfig::default());
        for seq in 1..=4 {
            let key = key(seq, 1, b"\x00", Transport::Udp);
            cache.insert(key, &response(0, b"x"), CachedOutcome::Answer);
        }
        assert_eq!(cache.invalidate_zone(2), 1);
        assert_eq!(cache.metrics().entries, 3);
        let gone = key(2, 1, b"\x00", Transport::Udp);
        assert!(cache.lookup(&gone, 1, &mut [0_u8; 8]).is_none());
    }

    #[test]
    fn memory_bound_evicts() {
        let cache = ResponseCache::new(ResponseCacheConfig {
            enabled: true,
            max_entries: 4,
            max_bytes: 16 * 1024,
            shards: 1,
        });
        for index in 0..64_u64 {
            let name = index.to_be_bytes();
            let cache_key = key(index, 1, &name, Transport::Udp);
            cache.insert(cache_key, &response(0, &[0_u8; 32]), CachedOutcome::Answer);
        }
        let metrics = cache.metrics();
        assert!(metrics.entries <= 4, "{metrics:?}");
        assert!(metrics.evictions > 0, "{metrics:?}");
    }

    #[test]
    fn disabled_cache_never_stores() {
        let cache = ResponseCache::new(ResponseCacheConfig::disabled());
        let cache_key = key(1, 1, b"\x00", Transport::Udp);
        cache.insert(cache_key.clone(), &response(0, b"x"), CachedOutcome::Answer);
        assert!(cache.lookup(&cache_key, 1, &mut [0_u8; 8]).is_none());
        assert_eq!(cache.metrics().entries, 0);
    }
}
