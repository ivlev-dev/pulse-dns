//! Шардированный RRset-кеш с approximate-LRU и negative caching.
//!
//! Горячий путь чтения берёт только `RwLock::read` своего шарда и не
//! аллоцирует: ключ собирается в стековом буфере как
//! `qname-wire + qtype + qclass`, поиск идёт по открытой адресации, а
//! значение — компактная wire-форма RRset без доменных структур.
//!
//! TTL хранится как абсолютный unix-deadline (`u32`), поэтому вычисление
//! остатка — одно вычитание. Вытеснение — approximate LRU: из шарда берётся
//! несколько случайных занятых слотов (`O(1)`), удаляется самый старый по
//! `last_used`. Полный перебор шарда на каждой вставке не выполняется.
//!
//! Положительная запись хранит один RRset, отрицательная — RCODE и
//! authority (SOA/NSEC) с TTL по RFC 2308. `NXDOMAIN` дополнительно
//! кладётся под типом `ANY`, чтобы отрицательный ответ покрывал все типы
//! имени.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{OnceLock, RwLock, RwLockReadGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pulse_dns::{DecodeLimits, Message, Name, Rclass, Rcode, Record, Rtype};

use crate::config::CacheConfig;

/// Тип записи, под которым кешируется NXDOMAIN.
const NXDOMAIN_TYPE: Rtype = Rtype::ANY;

/// Максимальный размер ключа: wire-имя (255) + тип (2) + класс (2).
const MAX_KEY_LEN: usize = pulse_dns::MAX_NAME_WIRE_LEN + 4;

/// Начальная ёмкость шарда (power of two).
const INITIAL_CAPACITY: usize = 16;

/// Приблизительный overhead одной записи в учёте памяти (struct, без таблицы).
const ENTRY_OVERHEAD: usize = 48;

/// Порог заполнения таблицы шарда (80 %).
const LOAD_NUMERATOR: usize = 8;
/// Знаменатель порога заполнения.
const LOAD_DENOMINATOR: usize = 10;

/// Сколько случайных слотов смотреть при вытеснении.
const EVICTION_SAMPLES: usize = 8;

/// Ограничение числа проб при поиске жертвы в одном сэмпле.
const EVICTION_PROBES: usize = 16;

/// Период фонового обновления общего coarse-clock.
///
/// `SystemTime::now` на виртуализированных хостах может стоить дороже самого
/// поиска в кеше, поэтому горячий путь читает `AtomicU64`, а системные часы
/// опрашиваются отдельным потоком раз в 10 мс. Погрешность TTL — не более
/// периода обновления и не зависит от QPS/простоя.
const CLOCK_TICK: Duration = Duration::from_millis(10);

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

/// Компактная запись кеша.
///
/// Ключ и wire-форма RRset лежат в одной аллокации `blob`:
/// `[key][rrset]`. Пустой blob с `key_len == 0` — tombstone удалённой
/// записи; `None` в слоте — свободный слот.
struct Entry {
    /// `qname-wire + qtype + qclass` и сразу за ним RRset.
    blob: Box<[u8]>,
    /// Длина ключевой части в `blob`.
    key_len: u16,
    /// Хеш ключа (для сравнения и rehash).
    hash: u64,
    /// Абсолютный TTL-deadline, unix seconds.
    deadline: u32,
    /// RCODE для negative-записи.
    rcode: Rcode,
    /// Число RR в `rrset`.
    records: u16,
    /// Запись отрицательная.
    negative: bool,
    /// Состояние DNSSEC.
    secure: SecurityState,
    /// Монотонный счётчик использования для approximate LRU.
    last_used: AtomicU64,
}

impl std::fmt::Debug for Entry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Entry")
            .field("key_len", &self.key_len)
            .field("rrset_len", &self.rrset().len())
            .field("deadline", &self.deadline)
            .field("records", &self.records)
            .field("negative", &self.negative)
            .field("secure", &self.secure)
            .finish_non_exhaustive()
    }
}

impl Entry {
    fn tombstone() -> Self {
        Self {
            blob: Box::new([]),
            key_len: 0,
            hash: 0,
            deadline: 0,
            rcode: Rcode::NOERROR,
            records: 0,
            negative: false,
            secure: SecurityState::Unvalidated,
            last_used: AtomicU64::new(0),
        }
    }

    fn occupied(&self) -> bool {
        self.key_len != 0
    }

    fn key(&self) -> &[u8] {
        self.blob.get(..usize::from(self.key_len)).unwrap_or(&[])
    }

    fn rrset(&self) -> &[u8] {
        self.blob.get(usize::from(self.key_len)..).unwrap_or(&[])
    }

    fn remaining(&self, now: u32) -> u32 {
        if self.deadline <= now {
            return 0;
        }
        self.deadline.saturating_sub(now)
    }

    fn size(&self) -> usize {
        self.blob.len().saturating_add(ENTRY_OVERHEAD)
    }
}

/// Один шард: открытая адресация с линейным пробированием.
#[derive(Debug)]
struct Shard {
    slots: Vec<Option<Entry>>,
    len: usize,
    tombstones: usize,
    bytes: usize,
    clock: AtomicU64,
    rng: u64,
}

impl Default for Shard {
    fn default() -> Self {
        Self {
            slots: Vec::new(),
            len: 0,
            tombstones: 0,
            bytes: 0,
            clock: AtomicU64::new(0),
            rng: 0x9E37_79B9_7F4A_7C15,
        }
    }
}

impl Shard {
    fn clear(&mut self) {
        self.slots.clear();
        self.len = 0;
        self.tombstones = 0;
        self.bytes = 0;
    }

    fn locate(&self, key: &[u8], hash: u64) -> Option<usize> {
        if self.slots.is_empty() {
            return None;
        }
        let capacity = self.slots.len();
        let mut index = usize::try_from(hash).unwrap_or(0) % capacity;
        for _ in 0..capacity {
            let entry = self.slots.get(index)?.as_ref()?;
            if entry.occupied() && entry.hash == hash && entry.key() == key {
                return Some(index);
            }
            index = index.wrapping_add(1) % capacity;
        }
        None
    }

    fn ensure_capacity(&mut self) {
        if self.slots.is_empty() {
            self.rehash(INITIAL_CAPACITY);
            return;
        }
        let capacity = self.slots.len();
        let used = self
            .len
            .saturating_add(self.tombstones)
            .saturating_add(1)
            .saturating_mul(LOAD_DENOMINATOR);
        if used > capacity.saturating_mul(LOAD_NUMERATOR) {
            let grows = self
                .len
                .saturating_add(1)
                .saturating_mul(LOAD_DENOMINATOR)
                .gt(&capacity.saturating_mul(LOAD_NUMERATOR));
            let target = if grows {
                let needed = self
                    .len
                    .saturating_add(1)
                    .saturating_mul(LOAD_DENOMINATOR)
                    .saturating_div(LOAD_NUMERATOR)
                    .saturating_add(1);
                // Геометрический рост: иначе таблица увеличивается на один
                // слот и каждая вставка превращается в O(n) rehash.
                capacity.saturating_mul(3).saturating_div(2).max(needed)
            } else {
                capacity
            };
            self.rehash(target);
        }
    }

    fn rehash(&mut self, target: usize) {
        let capacity = target.max(INITIAL_CAPACITY);
        let mut fresh: Vec<Option<Entry>> = (0..capacity).map(|_| None).collect();
        let old = std::mem::take(&mut self.slots);
        for entry in old.into_iter().flatten() {
            if entry.occupied() {
                place(&mut fresh, entry);
            }
        }
        self.slots = fresh;
        self.tombstones = 0;
    }

    fn insert(&mut self, entry: Entry) {
        self.ensure_capacity();
        let capacity = self.slots.len();
        if capacity == 0 {
            return;
        }
        let hash = entry.hash;
        let size = entry.size();
        if let Some(index) = self.locate(entry.key(), hash) {
            self.replace(index, entry, size);
            return;
        }
        let mut index = usize::try_from(hash).unwrap_or(0) % capacity;
        let mut tombstone = None;
        for _ in 0..capacity {
            match self.slots.get(index) {
                Some(None) => {
                    let target = tombstone.unwrap_or(index);
                    self.write_slot(target, entry, size);
                    self.len = self.len.saturating_add(1);
                    if tombstone.is_some() {
                        self.tombstones = self.tombstones.saturating_sub(1);
                    }
                    return;
                }
                Some(Some(existing)) if existing.occupied() => {}
                Some(Some(_)) => {
                    if tombstone.is_none() {
                        tombstone = Some(index);
                    }
                }
                None => return,
            }
            index = index.wrapping_add(1) % capacity;
        }
        if let Some(target) = tombstone {
            self.write_slot(target, entry, size);
            self.len = self.len.saturating_add(1);
            self.tombstones = self.tombstones.saturating_sub(1);
        }
    }

    fn replace(&mut self, index: usize, entry: Entry, size: usize) {
        let Some(slot) = self.slots.get_mut(index) else {
            return;
        };
        let previous = slot.replace(entry);
        if let Some(previous) = previous {
            self.bytes = self.bytes.saturating_sub(previous.size());
        }
        self.bytes = self.bytes.saturating_add(size);
    }

    fn write_slot(&mut self, index: usize, entry: Entry, size: usize) {
        let Some(slot) = self.slots.get_mut(index) else {
            return;
        };
        *slot = Some(entry);
        self.bytes = self.bytes.saturating_add(size);
    }

    fn remove_at(&mut self, index: usize) -> Option<Entry> {
        let slot = self.slots.get_mut(index)?;
        let previous = slot.replace(Entry::tombstone())?;
        if !previous.occupied() {
            return None;
        }
        self.len = self.len.saturating_sub(1);
        self.tombstones = self.tombstones.saturating_add(1);
        self.bytes = self.bytes.saturating_sub(previous.size());
        Some(previous)
    }

    fn sample_victim(&mut self) -> Option<usize> {
        if self.len == 0 || self.slots.is_empty() {
            return None;
        }
        let capacity = self.slots.len();
        let mut best: Option<(usize, u64)> = None;
        for _ in 0..EVICTION_SAMPLES {
            self.rng = self.rng.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.rng;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            let mut index = usize::try_from(z).unwrap_or(0) % capacity;
            for _ in 0..EVICTION_PROBES.min(capacity) {
                if let Some(entry) = self.slots.get(index).and_then(Option::as_ref)
                    && entry.occupied()
                {
                    let used = entry.last_used.load(Ordering::Relaxed);
                    if best.is_none_or(|(_, current)| used < current) {
                        best = Some((index, used));
                    }
                    break;
                }
                index = index.wrapping_add(1) % capacity;
            }
        }
        best.map(|(index, _)| index)
    }
}

/// Вставляет запись в свежую таблицу без замены (rehash).
fn place(slots: &mut [Option<Entry>], entry: Entry) {
    if slots.is_empty() {
        return;
    }
    let capacity = slots.len();
    let mut index = usize::try_from(entry.hash).unwrap_or(0) % capacity;
    for _ in 0..capacity {
        if slots.get(index).is_some_and(Option::is_none) {
            if let Some(slot) = slots.get_mut(index) {
                *slot = Some(entry);
            }
            return;
        }
        index = index.wrapping_add(1) % capacity;
    }
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

/// Заимствованный результат попадания в кеш.
///
/// Держит read-lock шарда до вызова [`CacheHit::finish`]. Это позволяет
/// закодировать ответ прямо из wire-байтов кеша, не копируя RRset.
pub(crate) struct CacheHit<'a> {
    guard: RwLockReadGuard<'a, Shard>,
    index: usize,
    remaining: u32,
}

impl CacheHit<'_> {
    fn entry(&self) -> Option<&Entry> {
        self.guard
            .slots
            .get(self.index)
            .and_then(Option::as_ref)
            .filter(|entry| entry.occupied())
    }

    /// Остаток TTL в секундах.
    pub(crate) fn remaining(&self) -> u32 {
        self.remaining
    }

    /// Wire-форма RRset.
    pub(crate) fn rrset(&self) -> &[u8] {
        self.entry().map_or(&[], Entry::rrset)
    }

    /// Число RR в [`CacheHit::rrset`].
    pub(crate) fn records(&self) -> u16 {
        self.entry().map_or(0, |entry| entry.records)
    }

    /// DNSSEC-состояние записи.
    pub(crate) fn secure(&self) -> SecurityState {
        self.entry()
            .map_or(SecurityState::Unvalidated, |entry| entry.secure)
    }

    /// Отрицательная запись.
    pub(crate) fn negative(&self) -> bool {
        self.entry().is_some_and(|entry| entry.negative)
    }

    /// RCODE (для отрицательной записи).
    pub(crate) fn rcode(&self) -> Rcode {
        self.entry().map_or(Rcode::NOERROR, |entry| entry.rcode)
    }

    /// Материализует RRset в доменные записи (медленный путь).
    pub(crate) fn decode(&self) -> Vec<Record> {
        decode_rrset(self.rrset(), self.remaining)
    }
}

/// Шардированный кеш.
#[derive(Debug)]
pub struct Cache {
    shards: Box<[RwLock<Shard>]>,
    config: CacheConfig,
    counters: Counters,
    may_have_signatures: AtomicBool,
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
            may_have_signatures: AtomicBool::new(false),
        }
    }

    /// Была ли в кеш когда-либо вставлена RRSIG-запись.
    ///
    /// Дешёвый консервативный признак: `false` гарантирует, что искать
    /// подписи для ответа не нужно, и горячий путь экономит второй lookup.
    pub(crate) fn may_have_signatures(&self) -> bool {
        self.may_have_signatures.load(Ordering::Relaxed)
    }

    /// Удаляет всё содержимое кеша.
    pub fn purge(&self) {
        self.may_have_signatures.store(false, Ordering::Relaxed);
        for shard in &self.shards {
            if let Ok(mut guard) = shard.write() {
                guard.clear();
            }
        }
    }

    /// Удаляет записи по имени и/или типу.
    ///
    /// `None` означает «любое значение». Возвращает число удалённых записей.
    /// Удаление идёт по шардам под короткой write-блокировкой, поэтому
    /// параллельные чтения горячего пути не теряют уже полученные ответы.
    pub fn purge_matching(&self, name: Option<&Name>, rr_type: Option<Rtype>) -> usize {
        let mut removed = 0_usize;
        for shard in &self.shards {
            let Ok(mut guard) = shard.write() else {
                continue;
            };
            let old = std::mem::take(&mut guard.slots);
            guard.len = 0;
            guard.tombstones = 0;
            guard.bytes = 0;
            for entry in old.into_iter().flatten() {
                if !entry.occupied() {
                    continue;
                }
                if entry_matches(&entry, name, rr_type) {
                    removed = removed.saturating_add(1);
                } else {
                    guard.insert(entry);
                }
            }
        }
        removed
    }

    /// Текущее число записей.
    #[must_use]
    pub fn len(&self) -> usize {
        self.shards
            .iter()
            .filter_map(|shard| shard.read().ok().map(|guard| guard.len))
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
                entries = entries.saturating_add(guard.len);
                bytes = bytes.saturating_add(guard.bytes);
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
        let mut current = name.clone();
        let mut records = Vec::new();
        let mut secure = true;
        for _ in 0..16 {
            if let Some(hit) = self.lookup(&current, rr_type, Rclass::IN, accept_unvalidated) {
                if hit.secure() == SecurityState::Unvalidated && !accept_unvalidated {
                    return None;
                }
                if hit.negative() {
                    return None;
                }
                secure &= hit.secure() == SecurityState::Secure;
                records.extend(hit.decode());
                drop(hit);
                if rr_type != Rtype::RRSIG {
                    self.append_signatures(&mut records, &current, accept_unvalidated);
                }
                return Some(CacheAnswer { records, secure });
            }
            let hit = self.lookup(&current, Rtype::CNAME, Rclass::IN, accept_unvalidated)?;
            if hit.secure() == SecurityState::Unvalidated && !accept_unvalidated {
                return None;
            }
            secure &= hit.secure() == SecurityState::Secure;
            let cname_records = hit.decode();
            drop(hit);
            let target = cname_records
                .iter()
                .find_map(|record| match record.rdata() {
                    pulse_dns::Rdata::Cname(target) => Some(target.clone()),
                    _ => None,
                });
            records.extend(cname_records);
            self.append_signatures(&mut records, &current, accept_unvalidated);
            current = target?;
        }
        None
    }

    fn append_signatures(&self, records: &mut Vec<Record>, owner: &Name, accept_unvalidated: bool) {
        let Some(hit) = self.peek(owner, Rtype::RRSIG, Rclass::IN, accept_unvalidated) else {
            return;
        };
        if hit.secure() == SecurityState::Unvalidated && !accept_unvalidated {
            return;
        }
        records.extend(hit.decode());
    }

    /// Ищет ровно один RRset (без CNAME-обхода).
    #[must_use]
    pub(crate) fn lookup_exact(
        &self,
        name: &Name,
        rr_type: Rtype,
        accept_unvalidated: bool,
    ) -> Option<CacheAnswer> {
        let hit = self.lookup(name, rr_type, Rclass::IN, accept_unvalidated)?;
        if hit.secure() == SecurityState::Unvalidated && !accept_unvalidated {
            return None;
        }
        if hit.negative() {
            return None;
        }
        Some(CacheAnswer {
            records: hit.decode(),
            secure: hit.secure() == SecurityState::Secure,
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
        for key_type in [rr_type, NXDOMAIN_TYPE] {
            let Some(hit) = self.lookup(name, key_type, Rclass::IN, accept_unvalidated) else {
                continue;
            };
            if hit.secure() == SecurityState::Unvalidated && !accept_unvalidated {
                return None;
            }
            if !hit.negative() {
                continue;
            }
            return Some(NegativeAnswer {
                rcode: hit.rcode(),
                authority: hit.decode(),
                secure: hit.secure() == SecurityState::Secure,
            });
        }
        None
    }

    /// Ищет запись без изменения статистики и recency (для RRSIG).
    pub(crate) fn peek<'a>(
        &'a self,
        name: &Name,
        rr_type: Rtype,
        class: Rclass,
        accept_unvalidated: bool,
    ) -> Option<CacheHit<'a>> {
        self.peek_wire(name.as_wire(), rr_type, class, accept_unvalidated)
    }

    /// `peek` по канонической wire-форме имени.
    ///
    /// Горячий путь получает имя из [`MessageRef`](pulse_dns::MessageRef) и не
    /// материализует [`Name`].
    pub(crate) fn peek_wire<'a>(
        &'a self,
        name: &[u8],
        rr_type: Rtype,
        class: Rclass,
        accept_unvalidated: bool,
    ) -> Option<CacheHit<'a>> {
        self.lookup_inner(name, rr_type, class, accept_unvalidated, false)
    }

    /// Ищет запись, обновляя статистику и approximate-LRU.
    pub(crate) fn lookup<'a>(
        &'a self,
        name: &Name,
        rr_type: Rtype,
        class: Rclass,
        accept_unvalidated: bool,
    ) -> Option<CacheHit<'a>> {
        self.lookup_wire(name.as_wire(), rr_type, class, accept_unvalidated)
    }

    /// `lookup` по канонической wire-форме имени.
    pub(crate) fn lookup_wire<'a>(
        &'a self,
        name: &[u8],
        rr_type: Rtype,
        class: Rclass,
        accept_unvalidated: bool,
    ) -> Option<CacheHit<'a>> {
        self.lookup_inner(name, rr_type, class, accept_unvalidated, true)
    }

    fn lookup_inner<'a>(
        &'a self,
        name: &[u8],
        rr_type: Rtype,
        class: Rclass,
        accept_unvalidated: bool,
        count: bool,
    ) -> Option<CacheHit<'a>> {
        let mut buffer = [0_u8; MAX_KEY_LEN];
        let len = fill_key(name, rr_type, class, &mut buffer)?;
        let key = buffer.get(..len)?;
        let hash = hash_key(key);
        let shard_index = self.shard_index(hash)?;
        let shard = self.shards.get(shard_index)?;
        let now = coarse_now();
        let expired;
        {
            let guard = shard.read().ok()?;
            let Some(index) = guard.locate(key, hash) else {
                if count {
                    self.counters.misses.fetch_add(1, Ordering::Relaxed);
                }
                return None;
            };
            let Some(entry) = guard
                .slots
                .get(index)
                .and_then(Option::as_ref)
                .filter(|entry| entry.occupied())
            else {
                if count {
                    self.counters.misses.fetch_add(1, Ordering::Relaxed);
                }
                return None;
            };
            let remaining = entry.remaining(now);
            if remaining == 0 {
                expired = true;
            } else {
                if count {
                    if entry.secure == SecurityState::Unvalidated && !accept_unvalidated {
                        self.counters.hits.fetch_add(1, Ordering::Relaxed);
                        return None;
                    }
                    let counter = guard.clock.fetch_add(1, Ordering::Relaxed);
                    entry
                        .last_used
                        .store(counter.wrapping_add(1), Ordering::Relaxed);
                    self.counters.hits.fetch_add(1, Ordering::Relaxed);
                } else if entry.secure == SecurityState::Unvalidated && !accept_unvalidated {
                    return None;
                }
                return Some(CacheHit {
                    guard,
                    index,
                    remaining,
                });
            }
        }
        if expired {
            self.expire(shard_index, key, hash);
        }
        if count {
            self.counters.misses.fetch_add(1, Ordering::Relaxed);
        }
        None
    }

    fn expire(&self, shard_index: usize, key: &[u8], hash: u64) {
        let Some(shard) = self.shards.get(shard_index) else {
            return;
        };
        let Ok(mut guard) = shard.write() else {
            return;
        };
        if let Some(index) = guard.locate(key, hash) {
            guard.remove_at(index);
        }
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
        let (rrset, count) = serialize_records(records);
        if count == 0 {
            return;
        }
        self.insert(
            name,
            rr_type,
            class,
            rrset,
            count,
            Rcode::NOERROR,
            false,
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
        let (rrset, count) = serialize_records(authority);
        self.insert(
            name,
            rr_type,
            Rclass::IN,
            rrset.clone(),
            count,
            rcode,
            true,
            ttl,
            secure,
        );
        if rcode == Rcode::NXDOMAIN && rr_type != NXDOMAIN_TYPE {
            self.insert(
                name,
                NXDOMAIN_TYPE,
                Rclass::IN,
                rrset,
                count,
                rcode,
                true,
                ttl,
                secure,
            );
        }
    }

    fn clamp_ttl(&self, ttl: u32) -> u32 {
        ttl.max(self.config.min_ttl).min(self.config.max_ttl)
    }

    #[allow(clippy::too_many_arguments)]
    fn insert(
        &self,
        name: &Name,
        rr_type: Rtype,
        class: Rclass,
        rrset: Box<[u8]>,
        records: u16,
        rcode: Rcode,
        negative: bool,
        ttl: u32,
        secure: SecurityState,
    ) {
        let mut buffer = [0_u8; MAX_KEY_LEN];
        let Some(len) = fill_key(name.as_wire(), rr_type, class, &mut buffer) else {
            return;
        };
        let Some(key) = buffer.get(..len) else {
            return;
        };
        let hash = hash_key(key);
        if rr_type == Rtype::RRSIG {
            self.may_have_signatures.store(true, Ordering::Relaxed);
        }
        let Some(shard_index) = self.shard_index(hash) else {
            return;
        };
        let Some(shard) = self.shards.get(shard_index) else {
            return;
        };
        let now = coarse_now();
        let Some(deadline) = now.checked_add(ttl) else {
            return;
        };
        let Ok(mut guard) = shard.write() else {
            return;
        };
        let Ok(key_len) = u16::try_from(len) else {
            return;
        };
        let Some(capacity) = len.checked_add(rrset.len()) else {
            return;
        };
        let mut blob = Vec::with_capacity(capacity);
        blob.extend_from_slice(key);
        blob.extend_from_slice(&rrset);
        guard.insert(Entry {
            blob: blob.into_boxed_slice(),
            key_len,
            hash,
            deadline,
            rcode,
            records,
            negative,
            secure,
            last_used: AtomicU64::new(0),
        });
        self.counters.inserts.fetch_add(1, Ordering::Relaxed);
        self.evict(&mut guard);
    }

    fn evict(&self, shard: &mut Shard) {
        let shards = self.config.shards.max(1);
        let max_entries = (self.config.max_entries / shards).max(1);
        let max_bytes = (self.config.max_bytes / shards).max(512);
        while shard.len > max_entries || shard.bytes > max_bytes {
            let Some(index) = shard.sample_victim() else {
                break;
            };
            if shard.remove_at(index).is_some() {
                self.counters.evictions.fetch_add(1, Ordering::Relaxed);
            } else {
                break;
            }
        }
    }

    fn shard_index(&self, hash: u64) -> Option<usize> {
        let shards = self.shards.len().max(1);
        let index = usize::try_from(hash).unwrap_or(0) % shards;
        (index < self.shards.len()).then_some(index)
    }
}

/// Один RR из wire-последовательности кеша.
#[derive(Debug, Clone, Copy)]
pub(crate) struct WireRr<'a> {
    /// Владелец в несжатой wire-форме.
    pub(crate) owner: &'a [u8],
    /// Тип записи.
    pub(crate) rr_type: Rtype,
    /// Класс записи.
    pub(crate) class: Rclass,
    /// RDATA без RDLENGTH.
    pub(crate) rdata: &'a [u8],
}

/// Итератор по RR в wire-последовательности кеша.
pub(crate) struct WireRrs<'a> {
    blob: &'a [u8],
    position: usize,
}

impl<'a> Iterator for WireRrs<'a> {
    type Item = WireRr<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.position >= self.blob.len() {
            return None;
        }
        let rest = self.blob.get(self.position..)?;
        let length = rr_wire_len(rest)?;
        let rr = rest.get(..length)?;
        let view = split_rr(rr)?;
        self.position = self.position.checked_add(length)?;
        Some(view)
    }
}

/// Итерирует RR из wire-последовательности кеша.
pub(crate) fn wire_rrs(blob: &[u8]) -> WireRrs<'_> {
    WireRrs { blob, position: 0 }
}

fn split_rr(rr: &[u8]) -> Option<WireRr<'_>> {
    let mut position = 0_usize;
    loop {
        let length = *rr.get(position)?;
        position = position.checked_add(1)?;
        if length == 0 {
            break;
        }
        position = position.checked_add(usize::from(length))?;
        if position > rr.len() {
            return None;
        }
    }
    let owner = rr.get(..position)?;
    let rr_type = u16::from_be_bytes(
        rr.get(position..position.checked_add(2)?)?
            .try_into()
            .ok()?,
    );
    let class = u16::from_be_bytes(
        rr.get(position + 2..position.checked_add(4)?)?
            .try_into()
            .ok()?,
    );
    let rdlength = usize::from(u16::from_be_bytes(
        rr.get(position + 8..position.checked_add(10)?)?
            .try_into()
            .ok()?,
    ));
    let rdata_start = position.checked_add(10)?;
    let rdata_end = rdata_start.checked_add(rdlength)?;
    let rdata = rr.get(rdata_start..rdata_end)?;
    Some(WireRr {
        owner,
        rr_type: Rtype::from_u16(rr_type),
        class: Rclass::from_u16(class),
        rdata,
    })
}

fn rr_wire_len(rr: &[u8]) -> Option<usize> {
    let mut position = 0_usize;
    loop {
        let length = *rr.get(position)?;
        position = position.checked_add(1)?;
        if length == 0 {
            break;
        }
        position = position.checked_add(usize::from(length))?;
        if position > rr.len() {
            return None;
        }
    }
    let rdlength = usize::from(u16::from_be_bytes(
        rr.get(position + 8..position.checked_add(10)?)?
            .try_into()
            .ok()?,
    ));
    position.checked_add(10)?.checked_add(rdlength)
}

fn fill_key(
    wire: &[u8],
    rr_type: Rtype,
    class: Rclass,
    buffer: &mut [u8; MAX_KEY_LEN],
) -> Option<usize> {
    let end = wire.len().checked_add(4)?;
    buffer.get_mut(..wire.len())?.copy_from_slice(wire);
    let tail = buffer.get_mut(wire.len()..end)?;
    tail.get_mut(..2)?
        .copy_from_slice(&rr_type.as_u16().to_be_bytes());
    tail.get_mut(2..4)?
        .copy_from_slice(&class.as_u16().to_be_bytes());
    Some(end)
}

fn hash_key(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
    }
    hash
}

fn unix_now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u32::try_from(duration.as_secs()).unwrap_or(u32::MAX)
        })
}

struct CoarseClock {
    now: AtomicU64,
}

static CLOCK: OnceLock<CoarseClock> = OnceLock::new();
static CLOCK_THREAD: OnceLock<bool> = OnceLock::new();

/// Текущее unix-время из общего coarse-clock.
///
/// Горячий путь не вызывает `clock_gettime`: значение обновляет фоновый
/// поток раз в [`CLOCK_TICK`]. Если поток не удалось запустить, часы
/// обновляются синхронно (деградация по скорости, но не по TTL).
fn coarse_now() -> u32 {
    let clock = CLOCK.get_or_init(|| CoarseClock {
        now: AtomicU64::new(u64::from(unix_now())),
    });
    let running = *CLOCK_THREAD.get_or_init(|| start_clock_thread().is_ok());
    if !running {
        clock.now.store(u64::from(unix_now()), Ordering::Relaxed);
    }
    u32::try_from(clock.now.load(Ordering::Relaxed)).unwrap_or(u32::MAX)
}

fn start_clock_thread() -> std::io::Result<()> {
    std::thread::Builder::new()
        .name("pulse-dns-clock".to_owned())
        .spawn(|| {
            loop {
                std::thread::sleep(CLOCK_TICK);
                if let Some(clock) = CLOCK.get() {
                    clock.now.store(u64::from(unix_now()), Ordering::Relaxed);
                }
            }
        })
        .map(|_| ())
}

fn entry_matches(entry: &Entry, name: Option<&Name>, rr_type: Option<Rtype>) -> bool {
    let key = entry.key();
    let Some(split) = key.len().checked_sub(4) else {
        return false;
    };
    let Some(key_name) = key.get(..split) else {
        return false;
    };
    let Some(type_bytes) = key.get(split..split.saturating_add(2)) else {
        return false;
    };
    let Ok(type_bytes) = <[u8; 2]>::try_from(type_bytes) else {
        return false;
    };
    let key_type = Rtype::from_u16(u16::from_be_bytes(type_bytes));
    let name_matches = name.is_none_or(|name| name.as_wire() == key_name);
    let type_matches = rr_type.is_none_or(|rr_type| key_type == rr_type);
    name_matches && type_matches
}

fn serialize_records(records: &[Record]) -> (Box<[u8]>, u16) {
    let mut out = Vec::new();
    let mut count = 0_u16;
    for record in records {
        if record.write_canonical_wire(&mut out).is_ok() {
            count = count.saturating_add(1);
        }
    }
    (out.into_boxed_slice(), count)
}

fn decode_rrset(blob: &[u8], ttl: u32) -> Vec<Record> {
    if blob.is_empty() {
        return Vec::new();
    }
    let mut count = 0_u16;
    for _ in wire_rrs(blob) {
        count = count.saturating_add(1);
    }
    if count == 0 {
        return Vec::new();
    }
    let Some(capacity) = 12_usize.checked_add(blob.len()) else {
        return Vec::new();
    };
    let mut wire = Vec::with_capacity(capacity);
    wire.extend_from_slice(&0_u16.to_be_bytes());
    wire.extend_from_slice(&0x8000_u16.to_be_bytes());
    wire.extend_from_slice(&0_u16.to_be_bytes());
    wire.extend_from_slice(&count.to_be_bytes());
    wire.extend_from_slice(&[0_u8; 4]);
    wire.extend_from_slice(blob);
    patch_ttls(&mut wire, 12, ttl);
    Message::decode(&wire, &DecodeLimits::default())
        .map(|message| message.answers().to_vec())
        .unwrap_or_default()
}

fn patch_ttls(wire: &mut [u8], offset: usize, ttl: u32) {
    let Some(mut rest) = wire.get_mut(offset..) else {
        return;
    };
    let ttl = ttl.to_be_bytes();
    while !rest.is_empty() {
        let mut position = 0_usize;
        loop {
            let Some(&length) = rest.get(position) else {
                return;
            };
            position = position.saturating_add(1);
            if length == 0 {
                break;
            }
            position = position.saturating_add(usize::from(length));
        }
        let Some(ttl_start) = position.checked_add(4) else {
            return;
        };
        if let Some(slot) = rest.get_mut(ttl_start..ttl_start.saturating_add(4)) {
            slot.copy_from_slice(&ttl);
        }
        let Some(rdlength_start) = position.checked_add(8) else {
            return;
        };
        let Some(rdlength_bytes) = rest.get(rdlength_start..rdlength_start.saturating_add(2))
        else {
            return;
        };
        let Ok(rdlength_bytes) = <[u8; 2]>::try_from(rdlength_bytes) else {
            return;
        };
        let Some(total) = position
            .checked_add(10)
            .and_then(|value| value.checked_add(usize::from(u16::from_be_bytes(rdlength_bytes))))
        else {
            return;
        };
        let Some(next) = rest.get_mut(total..) else {
            return;
        };
        rest = next;
    }
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
        for index in 0..64_u8 {
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
        assert!(cache.snapshot().evictions >= 60);
    }

    #[test]
    fn eviction_respects_byte_limit() {
        let cache = Cache::new(CacheConfig {
            max_entries: 10_000,
            max_bytes: 2048,
            min_ttl: 0,
            max_ttl: 300,
            shards: 1,
        });
        for index in 0..128_u8 {
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
        let snapshot = cache.snapshot();
        assert!(snapshot.bytes <= 2048);
        assert!(snapshot.evictions > 0);
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

    #[test]
    fn purge_matching_filters_by_name_and_type() {
        let cache = cache(300);
        cache.insert_rrset(
            &name("a.example.com"),
            Rtype::A,
            Rclass::IN,
            &[record("a.example.com", 30, 1)],
            SecurityState::Secure,
        );
        cache.insert_rrset(
            &name("a.example.com"),
            Rtype::AAAA,
            Rclass::IN,
            &[Record::new(
                name("a.example.com"),
                Rtype::AAAA,
                Rclass::IN,
                Ttl::new(30).unwrap(),
                Rdata::Aaaa(std::net::Ipv6Addr::LOCALHOST),
            )
            .unwrap()],
            SecurityState::Secure,
        );
        assert_eq!(
            cache.purge_matching(Some(&name("a.example.com")), Some(Rtype::A)),
            1
        );
        assert_eq!(cache.len(), 1);
        assert!(
            cache
                .lookup_exact(&name("a.example.com"), Rtype::AAAA, false)
                .is_some()
        );
    }

    #[test]
    fn wire_roundtrip_preserves_records() {
        let cache = cache(300);
        let rrset = vec![record("example.com", 30, 4), record("example.com", 30, 5)];
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
        assert_eq!(answer.records, rrset);
    }

    #[test]
    fn expiry_uses_deadline_and_removes_entry() {
        let cache = cache(300);
        let rrset = vec![record("example.com", 1, 1)];
        cache.insert_rrset(
            &name("example.com"),
            Rtype::A,
            Rclass::IN,
            &rrset,
            SecurityState::Secure,
        );
        thread::sleep(Duration::from_millis(1100));
        assert!(
            cache
                .lookup(&name("example.com"), Rtype::A, Rclass::IN, true)
                .is_none()
        );
        assert_eq!(cache.len(), 0);
    }

    #[test]
    #[allow(clippy::cast_precision_loss)]
    fn memory_footprint_probe() {
        let count: usize = std::env::var("CACHE_ENTRIES")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(100_000);
        let cache = Cache::new(CacheConfig {
            max_entries: count.saturating_mul(2),
            max_bytes: usize::MAX / 2,
            min_ttl: 0,
            max_ttl: 3600,
            shards: 16,
        });
        for index in 0..count {
            let owner = format!("host{index}.example.com");
            let rrset = vec![record(
                &owner,
                3600,
                u8::try_from(index & 0xff).unwrap_or(0),
            )];
            cache.insert_rrset(
                &name(&owner),
                Rtype::A,
                Rclass::IN,
                &rrset,
                SecurityState::Unvalidated,
            );
        }
        let snapshot = cache.snapshot();
        let per_entry = if snapshot.entries == 0 {
            0.0
        } else {
            snapshot.bytes as f64 / snapshot.entries as f64
        };
        eprintln!(
            "cache memory: entries={} bytes={} bytes/entry={per_entry:.1}",
            snapshot.entries, snapshot.bytes
        );
        assert_eq!(snapshot.entries, count);
    }
}
