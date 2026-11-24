//! Кеш валидированных страниц данных v2 (`PageCacheV2`, фаза B2a).
//!
//! Валидация страницы (CRC, `owner_zone`, `page.txn ≤ snapshot.version`,
//! структура) выполняется **один раз** на пару `(page_no, txn)`. Кеш хранит
//! нормализованный образ страницы (`owner_zone` обнулён — его ожидает
//! v1-декодер), поэтому warm-чтение не делает ни syscall, ни CRC, ни
//! аллокаций: выдаётся `Arc<[u8]>` (клонирование — атомарный инкремент).
//!
//! Инвалидация — по `(page_no, txn)`: COW всегда пишет новую страницу, версия
//! неизменяема. `PageCacheV2` не кеширует meta/reader table/root directory —
//! сюда попадают только страницы, прочитанные через `ReaderIo`, то есть
//! leaf/branch/overflow (и каталог-`B+tree`, который тоже является страницей
//! данных). Метрики hit/miss/eviction доступны через
//! [`PageCacheV2::stats`]; лимит задаётся [`PageCacheV2::with_capacity`].

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use crate::parallel::consts::PAGE_SIZE_V2;

/// Ёмкость кеша по умолчанию: 1024 страницы (4 `МиБ` при 4 `КиБ`).
pub const DEFAULT_PAGE_CACHE_V2_ENTRIES: usize = 1024;

/// Число независимых шардов кеша (снижает конкуренцию на read-path).
const CACHE_SHARDS: usize = 16;
/// Ассоциативность внутри шарда (приближённый LRU).
const CACHE_WAYS: usize = 4;

/// Метрики кеша страниц v2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PageCacheV2Stats {
    /// Попаданий (страница отдана без чтения/CRC).
    pub hits: u64,
    /// Промахов (страница прочитана и валидирована).
    pub misses: u64,
    /// Вытеснений.
    pub evictions: u64,
    /// Текущее число записей.
    pub entries: usize,
    /// Предел записей.
    pub capacity: usize,
}

impl PageCacheV2Stats {
    /// Доля попаданий (0..=1); при отсутствии обращений — 0.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn hit_ratio(self) -> f64 {
        let total = self.hits.saturating_add(self.misses);
        if total == 0 {
            return 0.0;
        }
        self.hits as f64 / total as f64
    }
}

struct Entry {
    page: u32,
    txn: u64,
    owner: u32,
    data: Arc<[u8]>,
    used: AtomicU64,
}

#[derive(Clone, Default)]
struct Set {
    ways: [Option<Arc<Entry>>; CACHE_WAYS],
}

/// Потокобезопасный кеш валидированных страниц v2.
pub struct PageCacheV2 {
    capacity: usize,
    shard_count: usize,
    shards: Box<[RwLock<Vec<Set>>]>,
    hits: AtomicU64,
    misses: AtomicU64,
    evictions: AtomicU64,
    clock: AtomicU64,
}

impl std::fmt::Debug for PageCacheV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PageCacheV2")
            .field("stats", &self.stats())
            .finish_non_exhaustive()
    }
}

impl PageCacheV2 {
    /// Кеш с ёмкостью по умолчанию ([`DEFAULT_PAGE_CACHE_V2_ENTRIES`]).
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_PAGE_CACHE_V2_ENTRIES)
    }

    /// Кеш на `capacity` страниц (0 трактуется как 1).
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        let shard_count = CACHE_SHARDS.min(capacity.div_ceil(CACHE_WAYS)).max(1);
        let per_shard = capacity.div_ceil(shard_count);
        let sets_per_shard = per_shard.div_ceil(CACHE_WAYS).max(1);
        let shards = (0..shard_count)
            .map(|_| RwLock::new(vec![Set::default(); sets_per_shard]))
            .collect::<Vec<_>>();
        Self {
            capacity,
            shard_count,
            shards: shards.into_boxed_slice(),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
            clock: AtomicU64::new(0),
        }
    }

    /// Ёмкость.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Текущие метрики.
    #[must_use]
    pub fn stats(&self) -> PageCacheV2Stats {
        let entries = self
            .shards
            .iter()
            .filter_map(|shard| shard.read().ok())
            .map(|sets| {
                sets.iter()
                    .map(|set| set.ways.iter().filter(|way| way.is_some()).count())
                    .sum::<usize>()
            })
            .sum();
        PageCacheV2Stats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
            entries,
            capacity: self.capacity,
        }
    }

    /// Сбрасывает метрики (не кеш).
    pub fn reset_stats(&self) {
        self.hits.store(0, Ordering::Relaxed);
        self.misses.store(0, Ordering::Relaxed);
        self.evictions.store(0, Ordering::Relaxed);
    }

    /// Полностью очищает кеш.
    pub fn clear(&self) {
        for shard in &self.shards {
            if let Ok(mut sets) = shard.write() {
                for set in sets.iter_mut() {
                    set.ways = std::array::from_fn(|_| None);
                }
            }
        }
    }

    /// Ищет валидированную страницу по номеру (версия — в заголовке образа).
    ///
    /// COW пишет страницу заново, поэтому в кеше всегда лежит актуальный образ
    /// `page_no`; вызывающий проверяет `page.txn ≤ snapshot.version` по срезу
    /// (8 байт заголовка, без syscall).
    #[must_use]
    pub fn get(&self, page: u32, owner: u32) -> Option<Arc<[u8]>> {
        let index = self.shard_index(page);
        let shard = self.shards.get(index)?;
        let sets = shard.read().ok()?;
        let set = sets.get(Self::set_index(page, sets.len()))?;
        let entry = set
            .ways
            .iter()
            .flatten()
            .find(|entry| entry.page == page && entry.owner == owner);
        let Some(entry) = entry else {
            drop(sets);
            self.misses.fetch_add(1, Ordering::Relaxed);
            return None;
        };
        let data = Arc::clone(&entry.data);
        let used = entry.used.load(Ordering::Relaxed);
        drop(sets);
        self.clock
            .fetch_max(used.saturating_add(1), Ordering::Relaxed);
        self.hits.fetch_add(1, Ordering::Relaxed);
        Some(data)
    }

    /// Кладёт валидированную страницу (заменяет образ `page_no`).
    pub fn insert(&self, page: u32, txn: u64, owner: u32, data: Arc<[u8]>) {
        if data.len() != PAGE_SIZE_V2 as usize {
            return;
        }
        let index = self.shard_index(page);
        let Some(shard) = self.shards.get(index) else {
            return;
        };
        let Ok(mut sets) = shard.write() else {
            return;
        };
        let index = Self::set_index(page, sets.len());
        let Some(set) = sets.get_mut(index) else {
            return;
        };
        for way in &mut set.ways {
            if let Some(existing) = way
                && existing.page == page
            {
                if existing.txn == txn {
                    return;
                }
                // COW: тот же номер, новая версия — заменяем образ.
                let used = self.clock.fetch_add(1, Ordering::Relaxed);
                let entry = Arc::new(Entry {
                    page,
                    txn,
                    owner,
                    data,
                    used: AtomicU64::new(used),
                });
                *way = Some(entry);
                return;
            }
        }
        let used = self.clock.fetch_add(1, Ordering::Relaxed);
        let entry = Arc::new(Entry {
            page,
            txn,
            owner,
            data,
            used: AtomicU64::new(used),
        });
        for way in &mut set.ways {
            if way.is_none() {
                *way = Some(entry);
                return;
            }
        }
        let victim = set
            .ways
            .iter()
            .enumerate()
            .min_by_key(|(_, way)| {
                way.as_ref()
                    .map_or(0, |entry| entry.used.load(Ordering::Relaxed))
            })
            .map(|(index, _)| index);
        if let Some(victim) = victim
            && let Some(way) = set.ways.get_mut(victim)
        {
            *way = Some(entry);
            self.evictions.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Удаляет все версии страницы (после `pwrite`/переиспользования).
    pub fn invalidate(&self, page: u32) {
        let index = self.shard_index(page);
        let Some(shard) = self.shards.get(index) else {
            return;
        };
        let Ok(mut sets) = shard.write() else {
            return;
        };
        for set in sets.iter_mut() {
            for way in &mut set.ways {
                if way.as_ref().is_some_and(|entry| entry.page == page) {
                    *way = None;
                }
            }
        }
    }

    fn shard_index(&self, page: u32) -> usize {
        (usize::try_from(page).unwrap_or(0) >> 3) % self.shard_count.max(1)
    }

    fn set_index(page: u32, set_count: usize) -> usize {
        ((page.wrapping_mul(0x9E37_79B1) >> 8) as usize) % set_count.max(1)
    }
}

impl Default for PageCacheV2 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(byte: u8) -> Arc<[u8]> {
        vec![byte; PAGE_SIZE_V2 as usize].into()
    }

    #[test]
    fn hit_miss_and_cow_replaces_version() {
        let cache = PageCacheV2::with_capacity(8);
        assert!(cache.get(7, 1).is_none());
        cache.insert(7, 3, 1, page(0xAA));
        assert_eq!(cache.get(7, 1).map(|data| data[0]), Some(0xAA));
        // COW: тот же номер с новым txn заменяет образ.
        cache.insert(7, 4, 1, page(0xBB));
        assert_eq!(cache.get(7, 1).map(|data| data[0]), Some(0xBB));
        // Чужой владелец не получает страницу.
        assert!(cache.get(7, 2).is_none());
        let stats = cache.stats();
        assert_eq!(stats.hits, 2);
        assert_eq!(stats.misses, 2);
        assert_eq!(stats.entries, 1);
    }

    #[test]
    fn capacity_is_bounded_and_invalidate_drops_all_versions() {
        let cache = PageCacheV2::with_capacity(4);
        for index in 0..32_u32 {
            cache.insert(index, 2, 1, page(u8::try_from(index).unwrap_or(0)));
        }
        assert!(cache.stats().entries <= 4);
        assert_eq!(cache.stats().capacity, 4);
        assert!(cache.stats().evictions > 0);
        cache.insert(5, 2, 1, page(1));
        cache.insert(5, 3, 1, page(2));
        cache.invalidate(5);
        assert!(cache.get(5, 1).is_none());
    }
}
