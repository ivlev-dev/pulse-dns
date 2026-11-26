//! Шардированный RRset-кеш с approximate-LRU и negative caching.
//!
//! Горячий путь чтения берёт только `RwLock::read` своего шарда и не
//! аллоцирует: ключ собирается в стековом буфере как
//! `qname-wire + qtype + qclass`, поиск идёт по открытой адресации, а
//! значение — компактная wire-форма RRset без доменных структур.
//!
//! # Раскладка записи
//!
//! Одна запись владеет одной аллокацией `blob = [key][value]`:
//!
//! - `key` — `qname-wire + qtype + qclass` (канонический регистр);
//! - `value` — либо компактная последовательность `[rdlen u16][rdata]…`,
//!   либо канонические wire-RR (fallback для записей с чужим owner или
//!   смешанными типами). В компактной форме owner/type/class/TTL не
//!   дублируются: они берутся из ключа и метаданных записи.
//!
//! Метаданные (`hash`, `deadline`, `last_used`, `key_len`, флаги) занимают
//! 32 байта, поэтому типичная A-запись укладывается в ~66 байт. Bucket-
//! массив открытой адресации учитывается отдельно (`CacheSnapshot::table_bytes`).
//!
//! TTL хранится как абсолютный unix-deadline (`u32`), поэтому вычисление
//! остатка — одно вычитание. Вытеснение — approximate LRU: из шарда берётся
//! несколько случайных занятых слотов (`O(1)`), просроченные удаляются
//! первыми, иначе удаляется самый старый по `last_used`. Полный перебор
//! шарда на каждой вставке не выполняется. Просроченные записи также
//! инкрементально вычищаются случайной выборкой при вставках — без
//! полного сканирования шарда.
//!
//! Положительная запись хранит один RRset, отрицательная — RCODE и
//! authority (SOA/NSEC) с TTL по RFC 2308. `NXDOMAIN` дополнительно
//! кладётся под типом `ANY`, чтобы отрицательный ответ покрывал все типы
//! имени.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
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

/// Порог заполнения таблицы шарда (80 %).
const LOAD_NUMERATOR: usize = 8;
/// Знаменатель порога заполнения.
const LOAD_DENOMINATOR: usize = 10;

/// Сколько случайных слотов смотреть при вытеснении и очистке.
const EVICTION_SAMPLES: usize = 8;

/// Ограничение числа проб при поиске жертвы в одном сэмпле.
const EVICTION_PROBES: usize = 16;

/// Раз во сколько вставок шард делает ограниченную выборку просроченных.
const SWEEP_INTERVAL: u32 = 32;

/// Флаг: запись отрицательная (в начале value лежит `rcode: u16`).
const FLAG_NEGATIVE: u8 = 1;
/// Флаг: DNSSEC-состояние `Secure`.
const FLAG_SECURE: u8 = 2;
/// Флаг: DNSSEC-состояние `Insecure`.
const FLAG_INSECURE: u8 = 4;
/// Флаг: value в компактной форме `[rdlen u16][rdata]…`.
const FLAG_COMPACT: u8 = 8;

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

/// Компактная запись кеша (32 байта метаданных).
///
/// Ключ и значение лежат в одной аллокации `blob`:
/// `[key][value]`. Пустой blob с `key_len == 0` — tombstone удалённой
/// записи; `None` в слоте — свободный слот.
struct Entry {
    /// `qname-wire + qtype + qclass` и сразу за ним значение.
    blob: Box<[u8]>,
    /// 32-битный отпечаток хеша ключа (коллизии разрешаются сравнением ключа).
    hash: u32,
    /// Абсолютный TTL-deadline, unix seconds.
    deadline: u32,
    /// Монотонный счётчик использования для approximate LRU.
    last_used: AtomicU32,
    /// Длина ключевой части в `blob`.
    key_len: u16,
    /// Флаги: negative, secure/insecure, compact.
    flags: u8,
}

impl std::fmt::Debug for Entry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Entry")
            .field("key_len", &self.key_len)
            .field("value_len", &self.value().len())
            .field("deadline", &self.deadline)
            .field("negative", &self.negative())
            .field("secure", &self.security())
            .field("compact", &self.compact())
            .finish_non_exhaustive()
    }
}

impl Entry {
    fn tombstone() -> Self {
        Self {
            blob: Box::new([]),
            hash: 0,
            deadline: 0,
            last_used: AtomicU32::new(0),
            key_len: 0,
            flags: 0,
        }
    }

    fn occupied(&self) -> bool {
        self.key_len != 0
    }

    fn key(&self) -> &[u8] {
        self.blob.get(..usize::from(self.key_len)).unwrap_or(&[])
    }

    /// Значение без ключа, включая заголовок RCODE у отрицательной записи.
    fn value(&self) -> &[u8] {
        self.blob.get(usize::from(self.key_len)..).unwrap_or(&[])
    }

    /// Полезная нагрузка значения без заголовка RCODE.
    fn payload(&self) -> &[u8] {
        if self.negative() {
            self.value().get(2..).unwrap_or(&[])
        } else {
            self.value()
        }
    }

    fn remaining(&self, now: u32) -> u32 {
        if self.deadline <= now {
            return 0;
        }
        self.deadline.saturating_sub(now)
    }

    fn negative(&self) -> bool {
        self.flags & FLAG_NEGATIVE != 0
    }

    fn compact(&self) -> bool {
        self.flags & FLAG_COMPACT != 0
    }

    fn security(&self) -> SecurityState {
        if self.flags & FLAG_SECURE != 0 {
            SecurityState::Secure
        } else if self.flags & FLAG_INSECURE != 0 {
            SecurityState::Insecure
        } else {
            SecurityState::Unvalidated
        }
    }

    fn rcode(&self) -> Rcode {
        if self.negative()
            && let Some(bytes) = self.value().get(..2)
            && let Ok(bytes) = <[u8; 2]>::try_from(bytes)
        {
            return Rcode::from_u16(u16::from_be_bytes(bytes));
        }
        Rcode::NOERROR
    }

    /// Итератор по RR значения.
    fn rrs(&self) -> WireRrs<'_> {
        if self.compact() {
            let key = self.key();
            let Some(split) = key.len().checked_sub(4) else {
                return WireRrs::full(&[]);
            };
            let (Some(name), Some(tail)) = (key.get(..split), key.get(split..)) else {
                return WireRrs::full(&[]);
            };
            let (Some(type_bytes), Some(class_bytes)) = (tail.get(..2), tail.get(2..4)) else {
                return WireRrs::full(&[]);
            };
            let (Ok(type_bytes), Ok(class_bytes)) = (
                <[u8; 2]>::try_from(type_bytes),
                <[u8; 2]>::try_from(class_bytes),
            ) else {
                return WireRrs::full(&[]);
            };
            WireRrs::compact(
                name,
                Rtype::from_u16(u16::from_be_bytes(type_bytes)),
                Rclass::from_u16(u16::from_be_bytes(class_bytes)),
                self.payload(),
            )
        } else {
            WireRrs::full(self.payload())
        }
    }

    fn decode(&self, ttl: u32) -> Vec<Record> {
        decode_rrset(self.rrs(), ttl)
    }

    fn size(&self) -> usize {
        self.blob.len().saturating_add(std::mem::size_of::<Self>())
    }
}

#[cfg(target_pointer_width = "64")]
const _: () = assert!(
    std::mem::size_of::<Entry>() == 32,
    "cache entry metadata must stay at 32 bytes"
);

/// Один шард: открытая адресация с линейным пробированием.
#[derive(Debug)]
struct Shard {
    slots: Vec<Option<Entry>>,
    len: usize,
    tombstones: usize,
    bytes: usize,
    clock: AtomicU32,
    rng: u64,
    ops: u32,
}

impl Default for Shard {
    fn default() -> Self {
        Self {
            slots: Vec::new(),
            len: 0,
            tombstones: 0,
            bytes: 0,
            clock: AtomicU32::new(0),
            rng: 0x9E37_79B9_7F4A_7C15,
            ops: 0,
        }
    }
}

impl Shard {
    fn clear(&mut self) {
        self.slots.clear();
        self.len = 0;
        self.tombstones = 0;
        self.bytes = 0;
        self.ops = 0;
    }

    fn locate(&self, key: &[u8], hash: u32) -> Option<usize> {
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

    /// Случайный индекс слота (xorshift, без внешнего RNG).
    fn random_index(&mut self) -> Option<usize> {
        if self.slots.is_empty() {
            return None;
        }
        self.rng = self.rng.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.rng;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        Some(usize::try_from(z).unwrap_or(0) % self.slots.len())
    }

    /// Выбирает жертву: просроченную запись либо самую старую из выборки.
    fn sample_victim(&mut self, now: u32) -> Option<usize> {
        if self.len == 0 || self.slots.is_empty() {
            return None;
        }
        let capacity = self.slots.len();
        let mut best: Option<(usize, u32)> = None;
        for _ in 0..EVICTION_SAMPLES {
            let mut index = self.random_index()?;
            for _ in 0..EVICTION_PROBES.min(capacity) {
                match self.slots.get(index).and_then(Option::as_ref) {
                    Some(entry) if entry.occupied() => {
                        if entry.remaining(now) == 0 {
                            return Some(index);
                        }
                        let used = entry.last_used.load(Ordering::Relaxed);
                        if best.is_none_or(|(_, current)| older(used, current)) {
                            best = Some((index, used));
                        }
                        break;
                    }
                    Some(_) => {}
                    None => break,
                }
                index = index.wrapping_add(1) % capacity;
            }
        }
        best.map(|(index, _)| index)
    }

    /// Удаляет до `samples` просроченных записей случайной выборкой.
    ///
    /// Это не полный обход шарда: работа ограничена `samples * EVICTION_PROBES`
    /// пробами независимо от числа записей.
    fn sweep_expired(&mut self, now: u32, samples: usize) -> usize {
        if self.len == 0 || self.slots.is_empty() {
            return 0;
        }
        let capacity = self.slots.len();
        let mut removed = 0_usize;
        for _ in 0..samples {
            let Some(mut index) = self.random_index() else {
                break;
            };
            for _ in 0..EVICTION_PROBES.min(capacity) {
                match self.slots.get(index).and_then(Option::as_ref) {
                    Some(entry) if entry.occupied() => {
                        if entry.remaining(now) == 0 && self.remove_at(index).is_some() {
                            removed = removed.saturating_add(1);
                        }
                        break;
                    }
                    Some(_) => {}
                    None => break,
                }
                index = index.wrapping_add(1) % capacity;
            }
        }
        removed
    }
}

/// Сравнение монотонных `u32`-меток с учётом переполнения.
fn older(a: u32, b: u32) -> bool {
    b.wrapping_sub(a) < 0x8000_0000
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
    /// Приблизительный размер данных записей в байтах (blob + метаданные
    /// `Entry`), без пустых слотов bucket-массива.
    pub bytes: usize,
    /// Размер bucket-массива в байтах, включая inline-метаданные занятых
    /// слотов. Фактическая память ≈ `table_bytes + blob-байты`, поэтому не
    /// складывайте `bytes` и `table_bytes` напрямую.
    pub table_bytes: usize,
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
/// Держит read-lock шарда до дропа. Это позволяет закодировать ответ прямо
/// из wire-байтов кеша, не копируя RRset.
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

    /// Итератор по RR значения в канонической wire-форме.
    pub(crate) fn rrs(&self) -> WireRrs<'_> {
        self.entry().map_or_else(|| WireRrs::full(&[]), Entry::rrs)
    }

    /// DNSSEC-состояние записи.
    pub(crate) fn secure(&self) -> SecurityState {
        self.entry()
            .map_or(SecurityState::Unvalidated, Entry::security)
    }

    /// Отрицательная запись.
    pub(crate) fn negative(&self) -> bool {
        self.entry().is_some_and(Entry::negative)
    }

    /// RCODE (для отрицательной записи).
    pub(crate) fn rcode(&self) -> Rcode {
        self.entry().map_or(Rcode::NOERROR, Entry::rcode)
    }

    /// Материализует RRset в доменные записи (медленный путь).
    pub(crate) fn decode(&self) -> Vec<Record> {
        match self.entry() {
            Some(entry) => entry.decode(self.remaining),
            None => Vec::new(),
        }
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
        let mut table_bytes = 0_usize;
        for shard in &self.shards {
            if let Ok(guard) = shard.read() {
                entries = entries.saturating_add(guard.len);
                bytes = bytes.saturating_add(guard.bytes);
                table_bytes = table_bytes.saturating_add(
                    guard
                        .slots
                        .len()
                        .saturating_mul(std::mem::size_of::<Option<Entry>>()),
                );
            }
        }
        CacheSnapshot {
            hits: self.counters.hits.load(Ordering::Relaxed),
            misses: self.counters.misses.load(Ordering::Relaxed),
            inserts: self.counters.inserts.load(Ordering::Relaxed),
            evictions: self.counters.evictions.load(Ordering::Relaxed),
            entries,
            bytes,
            table_bytes,
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
                    if entry.security() == SecurityState::Unvalidated && !accept_unvalidated {
                        self.counters.hits.fetch_add(1, Ordering::Relaxed);
                        return None;
                    }
                    let counter = guard.clock.fetch_add(1, Ordering::Relaxed);
                    entry
                        .last_used
                        .store(counter.wrapping_add(1), Ordering::Relaxed);
                    self.counters.hits.fetch_add(1, Ordering::Relaxed);
                } else if entry.security() == SecurityState::Unvalidated && !accept_unvalidated {
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

    fn expire(&self, shard_index: usize, key: &[u8], hash: u32) {
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
        let (value, compact) = serialize_rrset(name.as_wire(), rr_type, class, records);
        if value.is_empty() {
            return;
        }
        self.insert(name, rr_type, class, &value, compact, false, ttl, secure);
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
        let (payload, compact) = serialize_rrset(name.as_wire(), rr_type, Rclass::IN, authority);
        let mut value = Vec::with_capacity(payload.len().saturating_add(2));
        value.extend_from_slice(&rcode.as_u16().to_be_bytes());
        value.extend_from_slice(&payload);
        self.insert(
            name,
            rr_type,
            Rclass::IN,
            &value,
            compact,
            true,
            ttl,
            secure,
        );
        if rcode == Rcode::NXDOMAIN && rr_type != NXDOMAIN_TYPE {
            if compact {
                // Ключ ANY не совпадает с типом authority-записей, поэтому
                // компактная форма (type берётся из ключа) здесь неприменима.
                let full = serialize_full(authority);
                let mut strict = Vec::with_capacity(full.len().saturating_add(2));
                strict.extend_from_slice(&rcode.as_u16().to_be_bytes());
                strict.extend_from_slice(&full);
                self.insert(
                    name,
                    NXDOMAIN_TYPE,
                    Rclass::IN,
                    &strict,
                    false,
                    true,
                    ttl,
                    secure,
                );
            } else {
                self.insert(
                    name,
                    NXDOMAIN_TYPE,
                    Rclass::IN,
                    &value,
                    false,
                    true,
                    ttl,
                    secure,
                );
            }
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
        value: &[u8],
        compact: bool,
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
        let Some(capacity) = len.checked_add(value.len()) else {
            return;
        };
        let mut blob = Vec::with_capacity(capacity);
        blob.extend_from_slice(key);
        blob.extend_from_slice(value);
        let mut flags = 0_u8;
        if negative {
            flags |= FLAG_NEGATIVE;
        }
        if compact {
            flags |= FLAG_COMPACT;
        }
        flags |= security_flag(secure);
        guard.insert(Entry {
            blob: blob.into_boxed_slice(),
            hash,
            deadline,
            key_len,
            flags,
            last_used: AtomicU32::new(0),
        });
        self.counters.inserts.fetch_add(1, Ordering::Relaxed);
        guard.ops = guard.ops.wrapping_add(1);
        if guard.ops % SWEEP_INTERVAL == 0 {
            guard.sweep_expired(now, EVICTION_SAMPLES);
        }
        self.evict(&mut guard, now);
    }

    fn evict(&self, shard: &mut Shard, now: u32) {
        let shards = self.config.shards.max(1);
        let max_entries = (self.config.max_entries / shards).max(1);
        let max_bytes = (self.config.max_bytes / shards).max(512);
        while shard.len > max_entries || shard.bytes > max_bytes {
            let Some(index) = shard.sample_victim(now) else {
                break;
            };
            if shard.remove_at(index).is_some() {
                self.counters.evictions.fetch_add(1, Ordering::Relaxed);
            } else {
                break;
            }
        }
    }

    fn shard_index(&self, hash: u32) -> Option<usize> {
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

/// Источник RR значения.
#[derive(Clone, Copy)]
enum RrSource<'a> {
    /// Канонические wire-RR (owner/type/class в каждом RR).
    Full(&'a [u8]),
    /// Компактно: owner/type/class берутся из ключа, в data — `[rdlen][rdata]`.
    Compact {
        owner: &'a [u8],
        rr_type: Rtype,
        class: Rclass,
        data: &'a [u8],
    },
}

/// Итератор по RR значения кеша.
#[derive(Clone)]
pub(crate) struct WireRrs<'a> {
    source: RrSource<'a>,
    position: usize,
}

impl<'a> WireRrs<'a> {
    fn full(blob: &'a [u8]) -> Self {
        Self {
            source: RrSource::Full(blob),
            position: 0,
        }
    }

    fn compact(owner: &'a [u8], rr_type: Rtype, class: Rclass, data: &'a [u8]) -> Self {
        Self {
            source: RrSource::Compact {
                owner,
                rr_type,
                class,
                data,
            },
            position: 0,
        }
    }
}

impl<'a> Iterator for WireRrs<'a> {
    type Item = WireRr<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.source {
            RrSource::Full(blob) => {
                if self.position >= blob.len() {
                    return None;
                }
                let rest = blob.get(self.position..)?;
                let length = rr_wire_len(rest)?;
                let rr = rest.get(..length)?;
                let view = split_rr(rr)?;
                self.position = self.position.checked_add(length)?;
                Some(view)
            }
            RrSource::Compact {
                owner,
                rr_type,
                class,
                data,
            } => {
                let length = usize::from(u16::from_be_bytes(
                    data.get(self.position..self.position.checked_add(2)?)?
                        .try_into()
                        .ok()?,
                ));
                let start = self.position.checked_add(2)?;
                let end = start.checked_add(length)?;
                let rdata = data.get(start..end)?;
                self.position = end;
                Some(WireRr {
                    owner,
                    rr_type,
                    class,
                    rdata,
                })
            }
        }
    }
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

fn hash_key(bytes: &[u8]) -> u32 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
    }
    u32::try_from((hash ^ (hash >> 32)) & 0xFFFF_FFFF).unwrap_or(0)
}

const fn security_flag(state: SecurityState) -> u8 {
    match state {
        SecurityState::Unvalidated => 0,
        SecurityState::Insecure => FLAG_INSECURE,
        SecurityState::Secure => FLAG_SECURE,
    }
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

/// Сериализует RRset в value.
///
/// Если все записи принадлежат `owner` с типом `rr_type` и классом `class`,
/// используется компактная форма: owner/type/class/TTL не дублируются,
/// остаётся `[rdlen u16][rdata]…`. Иначе — канонические wire-RR.
fn serialize_rrset(
    owner: &[u8],
    rr_type: Rtype,
    class: Rclass,
    records: &[Record],
) -> (Vec<u8>, bool) {
    let compact = records.iter().all(|record| {
        record.owner().as_wire() == owner && record.rr_type() == rr_type && record.class() == class
    });
    if compact {
        let mut out = Vec::new();
        for record in records {
            let rdata = record.rdata().to_canonical_wire();
            let Ok(length) = u16::try_from(rdata.len()) else {
                return (serialize_full(records), false);
            };
            out.extend_from_slice(&length.to_be_bytes());
            out.extend_from_slice(&rdata);
        }
        return (out, true);
    }
    (serialize_full(records), false)
}

fn serialize_full(records: &[Record]) -> Vec<u8> {
    let mut out = Vec::new();
    for record in records {
        // Ошибка записи не добавляет частичных байтов (см. write_canonical_wire).
        let _ = record.write_canonical_wire(&mut out);
    }
    out
}

fn decode_rrset(rrs: WireRrs<'_>, ttl: u32) -> Vec<Record> {
    let mut count = 0_usize;
    let mut capacity = 12_usize;
    for rr in rrs.clone() {
        count = count.saturating_add(1);
        capacity = capacity
            .saturating_add(rr.owner.len())
            .saturating_add(10)
            .saturating_add(rr.rdata.len());
    }
    if count == 0 {
        return Vec::new();
    }
    let Ok(count) = u16::try_from(count) else {
        return Vec::new();
    };
    let mut wire = Vec::with_capacity(capacity);
    wire.extend_from_slice(&0_u16.to_be_bytes());
    wire.extend_from_slice(&0x8000_u16.to_be_bytes());
    wire.extend_from_slice(&0_u16.to_be_bytes());
    wire.extend_from_slice(&count.to_be_bytes());
    wire.extend_from_slice(&[0_u8; 4]);
    for rr in rrs {
        let Ok(length) = u16::try_from(rr.rdata.len()) else {
            return Vec::new();
        };
        wire.extend_from_slice(rr.owner);
        wire.extend_from_slice(&rr.rr_type.as_u16().to_be_bytes());
        wire.extend_from_slice(&rr.class.as_u16().to_be_bytes());
        wire.extend_from_slice(&ttl.to_be_bytes());
        wire.extend_from_slice(&length.to_be_bytes());
        wire.extend_from_slice(rr.rdata);
    }
    Message::decode(&wire, &DecodeLimits::default())
        .map(|message| message.answers().to_vec())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::{Arc, Barrier};
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

    fn comparable(records: &[Record]) -> Vec<(Name, Rtype, Rclass, Rdata)> {
        records
            .iter()
            .map(|record| {
                (
                    record.owner().clone(),
                    record.rr_type(),
                    record.class(),
                    record.rdata().clone(),
                )
            })
            .collect()
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
    fn nxdomain_any_copy_keeps_authority_types() {
        let cache = cache(300);
        // Патологический, но валидный negative: authority-запись совпадает
        // по owner/type с ключом, поэтому первичная запись компактна.
        let authority = vec![record("missing.example.com", 30, 3)];
        cache.insert_negative(
            &name("missing.example.com"),
            Rtype::A,
            Rcode::NXDOMAIN,
            &authority,
            30,
            SecurityState::Secure,
        );
        let answer = cache
            .lookup_negative(&name("missing.example.com"), Rtype::AAAA, false)
            .unwrap();
        assert_eq!(answer.rcode, Rcode::NXDOMAIN);
        assert_eq!(answer.authority.len(), 1);
        assert_eq!(answer.authority[0].rr_type(), Rtype::A);
        assert_eq!(comparable(&answer.authority), comparable(&authority));
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
        assert_eq!(comparable(&answer.records), comparable(&rrset));
    }

    #[test]
    fn compact_encoding_is_used_for_matching_rrset() {
        let cache = cache(300);
        let rrset = vec![record("example.com", 30, 1), record("example.com", 30, 2)];
        cache.insert_rrset(
            &name("example.com"),
            Rtype::A,
            Rclass::IN,
            &rrset,
            SecurityState::Secure,
        );
        let hit = cache
            .lookup(&name("example.com"), Rtype::A, Rclass::IN, false)
            .unwrap();
        let entry = hit.entry().unwrap();
        assert!(entry.compact(), "matching RRset must use compact value");
        assert_eq!(entry.payload().len(), 2 * (2 + 4));
        assert_eq!(comparable(&hit.decode()), comparable(&rrset));
    }

    #[test]
    fn compact_and_full_encodings_decode_identically() {
        let records = vec![
            record("alias.example.com", 300, 1),
            record("alias.example.com", 300, 2),
        ];
        let owner = name("alias.example.com");
        let (compact, is_compact) =
            serialize_rrset(owner.as_wire(), Rtype::A, Rclass::IN, &records);
        assert!(is_compact);
        let full = serialize_full(&records);
        let compact_decoded = decode_rrset(
            WireRrs::compact(owner.as_wire(), Rtype::A, Rclass::IN, &compact),
            300,
        );
        let full_decoded = decode_rrset(WireRrs::full(&full), 300);
        assert_eq!(comparable(&compact_decoded), comparable(&full_decoded));
        assert_eq!(comparable(&compact_decoded), comparable(&records));
    }

    #[test]
    fn wire_iterator_compact_matches_full() {
        let owner = name("iter.example.com");
        let records = vec![
            record("iter.example.com", 300, 1),
            record("iter.example.com", 300, 9),
        ];
        let (compact, is_compact) =
            serialize_rrset(owner.as_wire(), Rtype::A, Rclass::IN, &records);
        assert!(is_compact);
        let full = serialize_full(&records);
        let compact_wire: Vec<_> =
            WireRrs::compact(owner.as_wire(), Rtype::A, Rclass::IN, &compact)
                .map(|rr| (rr.owner.to_vec(), rr.rr_type, rr.class, rr.rdata.to_vec()))
                .collect();
        let full_wire: Vec<_> = WireRrs::full(&full)
            .map(|rr| (rr.owner.to_vec(), rr.rr_type, rr.class, rr.rdata.to_vec()))
            .collect();
        assert_eq!(compact_wire, full_wire);
    }

    #[test]
    fn compact_preserves_rdata_for_non_address_types() {
        let owner = name("alias.example.com");
        let records = vec![
            Record::new(
                owner.clone(),
                Rtype::CNAME,
                Rclass::IN,
                Ttl::new(300).unwrap(),
                Rdata::Cname(name("target.example.com")),
            )
            .unwrap(),
            Record::new(
                owner.clone(),
                Rtype::TXT,
                Rclass::IN,
                Ttl::new(300).unwrap(),
                Rdata::Txt(pulse_dns::TxtData::new(vec![b"hello".to_vec()]).unwrap()),
            )
            .unwrap(),
        ];
        let (mixed, is_compact) =
            serialize_rrset(owner.as_wire(), Rtype::CNAME, Rclass::IN, &records);
        // У записей разные типы: компактная форма неприменима, есть fallback.
        assert!(!is_compact);
        assert_ne!(mixed, Vec::<u8>::new());
        let (compact, is_compact) =
            serialize_rrset(owner.as_wire(), Rtype::CNAME, Rclass::IN, &records[..1]);
        assert!(is_compact);
        let decoded = decode_rrset(
            WireRrs::compact(owner.as_wire(), Rtype::CNAME, Rclass::IN, &compact),
            300,
        );
        assert_eq!(comparable(&decoded), comparable(&records[..1]));
    }

    #[test]
    fn full_fallback_keeps_foreign_owner() {
        let cache = cache(300);
        let key = name("alias.example.com");
        let records = vec![record("other.example.com", 30, 7)];
        cache.insert_rrset(&key, Rtype::A, Rclass::IN, &records, SecurityState::Secure);
        let hit = cache.lookup(&key, Rtype::A, Rclass::IN, false).unwrap();
        assert!(!hit.entry().unwrap().compact());
        assert_eq!(comparable(&hit.decode()), comparable(&records));
    }

    #[test]
    fn miss_is_counted_and_returns_none() {
        let cache = cache(300);
        assert!(
            cache
                .lookup(&name("absent.example.com"), Rtype::A, Rclass::IN, false)
                .is_none()
        );
        let snapshot = cache.snapshot();
        assert_eq!(snapshot.misses, 1);
        assert_eq!(snapshot.hits, 0);
        assert_eq!(snapshot.entries, 0);
    }

    #[test]
    fn secure_state_survives_compact_and_full_modes() {
        let cache = cache(300);
        cache.insert_rrset(
            &name("secure.example.com"),
            Rtype::A,
            Rclass::IN,
            &[record("secure.example.com", 30, 1)],
            SecurityState::Secure,
        );
        cache.insert_rrset(
            &name("full.example.com"),
            Rtype::A,
            Rclass::IN,
            &[record("foreign.example.com", 30, 2)],
            SecurityState::Insecure,
        );
        assert_eq!(
            cache
                .lookup(&name("secure.example.com"), Rtype::A, Rclass::IN, false)
                .unwrap()
                .secure(),
            SecurityState::Secure
        );
        assert_eq!(
            cache
                .lookup(&name("full.example.com"), Rtype::A, Rclass::IN, false)
                .unwrap()
                .secure(),
            SecurityState::Insecure
        );
    }

    #[test]
    fn purge_clears_entries_and_signature_flag() {
        let cache = cache(300);
        cache.insert_rrset(
            &name("example.com"),
            Rtype::A,
            Rclass::IN,
            &[record("example.com", 30, 1)],
            SecurityState::Secure,
        );
        assert!(!cache.is_empty());
        cache.purge();
        assert!(cache.is_empty());
        let snapshot = cache.snapshot();
        assert_eq!(snapshot.entries, 0);
        assert_eq!(snapshot.bytes, 0);
        assert!(!cache.may_have_signatures());
    }

    #[test]
    fn eviction_prefers_expired_entries() {
        let cache = Cache::new(CacheConfig {
            max_entries: 128,
            max_bytes: 1 << 20,
            min_ttl: 0,
            max_ttl: 300,
            shards: 1,
        });
        for index in 0..8_u8 {
            let owner = format!("expired{index}.example.com");
            cache.insert_rrset(
                &name(&owner),
                Rtype::A,
                Rclass::IN,
                &[record(&owner, 1, index)],
                SecurityState::Unvalidated,
            );
        }
        thread::sleep(Duration::from_millis(1100));
        let now = coarse_now();
        let mut guard = cache.shards[0].write().unwrap();
        let index = guard.sample_victim(now).unwrap();
        let entry = guard.slots[index].as_ref().unwrap();
        assert_eq!(entry.remaining(now), 0);
    }

    #[test]
    fn sweep_removes_expired_without_full_scan() {
        let cache = Cache::new(CacheConfig {
            max_entries: 1024,
            max_bytes: 1 << 20,
            min_ttl: 0,
            max_ttl: 300,
            shards: 1,
        });
        for index in 0..64_u8 {
            let owner = format!("sweep{index}.example.com");
            cache.insert_rrset(
                &name(&owner),
                Rtype::A,
                Rclass::IN,
                &[record(&owner, 1, index)],
                SecurityState::Unvalidated,
            );
        }
        thread::sleep(Duration::from_millis(1100));
        let now = coarse_now();
        let mut guard = cache.shards[0].write().unwrap();
        let removed = guard.sweep_expired(now, EVICTION_SAMPLES);
        assert!(removed > 0, "sweep must remove expired entries");
        assert!(guard.len < 64);
    }

    #[test]
    fn hundred_threads_share_one_cache() {
        let cache = Arc::new(Cache::new(CacheConfig {
            max_entries: 65_536,
            max_bytes: 64 << 20,
            min_ttl: 0,
            max_ttl: 300,
            shards: 8,
        }));
        let barrier = Arc::new(Barrier::new(100));
        let mut threads = Vec::new();
        for worker in 0..100_u32 {
            let cache = Arc::clone(&cache);
            let barrier = Arc::clone(&barrier);
            threads.push(thread::spawn(move || {
                barrier.wait();
                for index in 0..100_u32 {
                    let owner = format!("worker{worker}-{index}.example.com");
                    let rrset = vec![record(&owner, 30, u8::try_from(index).unwrap_or(0))];
                    cache.insert_rrset(
                        &name(&owner),
                        Rtype::A,
                        Rclass::IN,
                        &rrset,
                        SecurityState::Unvalidated,
                    );
                    let hit = cache
                        .lookup(&name(&owner), Rtype::A, Rclass::IN, true)
                        .expect("own insert must be visible");
                    assert_eq!(comparable(&hit.decode()), comparable(&rrset));
                }
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }
        let snapshot = cache.snapshot();
        assert_eq!(snapshot.entries, 100 * 100);
        assert!(snapshot.entries <= 65_536);
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
    #[ignore = "latency probe: run explicitly with --release --nocapture"]
    fn lookup_latency_probe() {
        let iters: usize = std::env::var("CACHE_LOOKUPS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(2_000_000);
        let cache = cache(3600);
        let rrset = vec![record("bench.example", 3600, 1)];
        cache.insert_rrset(
            &name("bench.example"),
            Rtype::A,
            Rclass::IN,
            &rrset,
            SecurityState::Unvalidated,
        );
        let owner = name("bench.example");
        let mut sink = 0_u32;
        let started = std::time::Instant::now();
        for _ in 0..iters {
            if let Some(hit) = cache.lookup(&owner, Rtype::A, Rclass::IN, true) {
                sink = sink.wrapping_add(hit.remaining());
                std::hint::black_box(&hit);
            }
        }
        let elapsed = started.elapsed();
        eprintln!(
            "cache lookup: iters={iters} total={elapsed:?} per_op={:?} sink={sink}",
            elapsed / u32::try_from(iters).unwrap_or(u32::MAX)
        );
    }

    #[test]
    #[allow(clippy::cast_precision_loss)]
    fn memory_footprint_probe() {
        let count: usize = std::env::var("CACHE_ENTRIES")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(100_000);
        memory_probe(count);
    }

    #[test]
    #[ignore = "1M-entry memory probe: run explicitly with --release --nocapture"]
    fn memory_footprint_probe_1m() {
        memory_probe(1_000_000);
    }

    #[allow(clippy::cast_precision_loss)]
    fn memory_probe(count: usize) {
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
        // `snapshot.bytes` уже включает метаданные Entry, которые физически
        // лежат в bucket-массиве: для фактического итога считаем blob-байты
        // отдельно и не складываем метаданные дважды.
        let metadata = snapshot
            .entries
            .saturating_mul(std::mem::size_of::<Entry>());
        let payload = snapshot.bytes.saturating_sub(metadata);
        let total_bytes = snapshot.table_bytes.saturating_add(payload);
        eprintln!(
            "cache memory: entries={} bytes={} bytes/entry={per_entry:.1} table={} total={}",
            snapshot.entries, snapshot.bytes, snapshot.table_bytes, total_bytes
        );
        assert_eq!(snapshot.entries, count);
        assert!(
            per_entry <= 80.0,
            "cache must stay within 80 B/entry, got {per_entry:.1}"
        );
    }
}
