//! In-memory индекс каталога зон: `apex → root/meta_root` (`zonefile-v1.md` §12.4).
//!
//! Каталог зон читается из B+tree каталога один раз при построении индекса;
//! горячий `find_zone` идёт в память и не трогает B+tree. Инвалидация — по
//! поколению (`generation`): `invalidate()` атомарно повышает поколение и
//! очищает записи, поэтому старые значения не могут «ожить».
//!
//! ```
//! use pulse_zonefile::key::NameRle;
//! use pulse_zonefile::zone_index::{ZoneIndex, ZoneLocation};
//! let index = ZoneIndex::new();
//! index.insert(
//!     NameRle::from_ascii("example.com").unwrap(),
//!     ZoneLocation { root: 14, level: 1, meta_root: 15, zone_seq: 1, state: 1 },
//! );
//! assert!(index.get(&NameRle::from_ascii("example.com").unwrap()).is_some());
//! ```

use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::hash::FastMap;
use crate::key::NameRle;

/// Расположение зоны в файле (значения `ZoneEntry`, нужные поиску).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZoneLocation {
    /// Корень дерева зоны (`0` — пусто).
    pub root: u32,
    /// Уровень дерева (`ZoneEntry.tree_level`).
    pub level: u16,
    /// Корень per-zone metadata-блока.
    pub meta_root: u32,
    /// Стабильный `ZoneId`.
    pub zone_seq: u32,
    /// `ZoneState` (0/1/2).
    pub state: u8,
}

/// Метрики индекса зон.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZoneIndexStats {
    /// Попаданий.
    pub hits: u64,
    /// Промахов.
    pub misses: u64,
    /// Число зон в индексе.
    pub zones: usize,
}

/// Потокобезопасный индекс каталога зон в памяти.
#[derive(Debug)]
pub struct ZoneIndex {
    generation: AtomicU64,
    entries: RwLock<FastMap<NameRle, (u64, ZoneLocation)>>,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl Default for ZoneIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl ZoneIndex {
    /// Пустой индекс.
    #[must_use]
    pub fn new() -> Self {
        Self {
            generation: AtomicU64::new(0),
            entries: RwLock::new(FastMap::default()),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Текущее поколение.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Число зон.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.read().map_or(0, |entries| entries.len())
    }

    /// Истина для пустого индекса.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Полная инвалидация: повышает поколение и очищает записи.
    pub fn invalidate(&self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
        if let Ok(mut entries) = self.entries.write() {
            entries.clear();
        }
    }

    /// Добавляет/заменяет зону в текущем поколении.
    pub fn insert(&self, apex: NameRle, location: ZoneLocation) {
        let generation = self.generation();
        if let Ok(mut entries) = self.entries.write() {
            entries.insert(apex, (generation, location));
        }
    }

    /// Ищет зону; запись другого поколения считается отсутствующей.
    #[must_use]
    pub fn get(&self, apex: &NameRle) -> Option<ZoneLocation> {
        let generation = self.generation();
        let Ok(entries) = self.entries.read() else {
            self.misses.fetch_add(1, Ordering::Relaxed);
            return None;
        };
        match entries.get(apex) {
            Some((entry_generation, location)) if *entry_generation == generation => {
                let location = *location;
                drop(entries);
                self.hits.fetch_add(1, Ordering::Relaxed);
                Some(location)
            }
            _ => {
                drop(entries);
                self.misses.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    /// Метрики (включая hit/miss).
    #[must_use]
    pub fn stats(&self) -> ZoneIndexStats {
        ZoneIndexStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            zones: self.len(),
        }
    }

    /// Сбрасывает только метрики.
    pub fn reset_stats(&self) {
        self.hits.store(0, Ordering::Relaxed);
        self.misses.store(0, Ordering::Relaxed);
    }
}
