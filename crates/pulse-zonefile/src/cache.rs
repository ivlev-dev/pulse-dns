//! Кеш валидированных узлов B+tree (`PageCache`).
//!
//! CRC и структурная валидация страницы выполняются один раз на версию
//! страницы; дальше поиск идёт по [`NodeRef`] без повторного разбора и без
//! аллокаций. Кеш ограничен (по умолчанию 1024 страницы), потокобезопасен и
//! ведёт метрики hit/miss. Reader table, meta и superblock не кешируются —
//! сюда попадают только страницы `LEAF`/`BRANCH`.
//!
//! Инвалидация — по паре `(page_no, txn)`: COW всегда пишет новую страницу,
//! поэтому версия страницы неизменяема. При переполнении вытесняется запись
//! с наименьшим счётчиком использования (приближённый LRU).
//!
//! ```
//! # use pulse_zonefile::tree::{MemoryStore, PageIo};
//! # use pulse_zonefile::cache::PageCache;
//! # use pulse_zonefile::node::{encode_leaf, EncodeContext, ItemValue, LeafItem};
//! # use pulse_zonefile::key::{Key, NameRle};
//! let mut store = MemoryStore::new(4096).unwrap();
//! let page_no = store.alloc_page().unwrap();
//! let mut page = vec![0_u8; 4096];
//! let name = NameRle::from_ascii("example.com").unwrap();
//! let items = [LeafItem::new(Key::new(&name, 0, 0, 0).unwrap(), ItemValue::node(0))];
//! encode_leaf(&mut page, EncodeContext { page_no, page_size: 4096, txn: 2, lsn: 0 }, &items).unwrap();
//! store.write_page(page_no, &page).unwrap();
//! let cache = PageCache::new(4096);
//! let node = cache.leaf(&store, page_no, 2).unwrap();
//! assert_eq!(node.len(), 1);
//! assert_eq!(cache.stats().misses, 1);
//! let _ = cache.leaf(&store, page_no, 2).unwrap();
//! assert_eq!(cache.stats().hits, 1);
//! ```

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use crate::errors::{CorruptDetail, CorruptKind, ZoneFileError};
use crate::node::{BranchItem, LeafItem, NodeMeta, NodeRef};
use crate::tree::PageIo;
use crate::wire;

/// Ёмкость кеша по умолчанию: 1024 страницы (~4 `МиБ` при 4 `КиБ`).
pub const DEFAULT_PAGE_CACHE_ENTRIES: usize = 1024;

/// Метрики кеша страниц.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheStats {
    /// Попаданий.
    pub hits: u64,
    /// Промахов.
    pub misses: u64,
    /// Текущее число записей.
    pub entries: usize,
    /// Предел записей.
    pub capacity: usize,
}

impl CacheStats {
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

struct CacheEntry {
    meta: Arc<NodeMeta>,
    used: AtomicU64,
}

const WAYS: usize = 4;

#[derive(Default, Clone)]
struct CacheSet {
    ways: [Option<Arc<CacheEntry>>; WAYS],
}

/// Потокобезопасный кеш валидированных страниц узлов.
///
/// Роль — только метаданные узла (`Arc<NodeMeta>`); сырые байты страниц живут
/// в [`PageCacheV2`](crate::parallel::pagecache::PageCacheV2). Hit-путь не
/// пишет в разделяемые атомики: метка `used` обновляется при вставке, поэтому
/// вытеснение приближённо FIFO внутри 4-way набора (для read-only кеша это
/// дешевле и не создаёт cache-line ping-pong).
pub struct PageCache {
    page_size: u32,
    capacity: usize,
    ways: usize,
    entries: RwLock<Vec<CacheSet>>,
    hits: AtomicU64,
    misses: AtomicU64,
    evictions: AtomicU64,
    clock: AtomicU64,
}

impl std::fmt::Debug for PageCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let stats = self.stats();
        f.debug_struct("PageCache")
            .field("page_size", &self.page_size)
            .field("stats", &stats)
            .finish_non_exhaustive()
    }
}

impl PageCache {
    /// Кеш с ёмкостью по умолчанию ([`DEFAULT_PAGE_CACHE_ENTRIES`]).
    #[must_use]
    pub fn new(page_size: u32) -> Self {
        Self::with_capacity(page_size, DEFAULT_PAGE_CACHE_ENTRIES)
    }

    /// Кеш с заданной ёмкостью (0 трактуется как 1).
    #[must_use]
    pub fn with_capacity(page_size: u32, capacity: usize) -> Self {
        let capacity = capacity.max(1);
        let ways = capacity.min(WAYS);
        Self {
            page_size,
            capacity,
            ways,
            entries: RwLock::new(vec![CacheSet::default(); capacity.div_ceil(ways)]),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
            clock: AtomicU64::new(0),
        }
    }

    /// Размер страницы.
    #[must_use]
    pub fn page_size(&self) -> u32 {
        self.page_size
    }

    /// Текущие метрики.
    #[must_use]
    pub fn stats(&self) -> CacheStats {
        let entries = self.entries.read().map_or(0, |sets| {
            sets.iter()
                .map(|set| set.ways.iter().filter(|way| way.is_some()).count())
                .sum()
        });
        CacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
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

    /// Число вытеснений с момента создания/сброса метрик.
    #[must_use]
    pub fn evictions(&self) -> u64 {
        self.evictions.load(Ordering::Relaxed)
    }

    /// Оценка памяти, занятой метаданными кеша (без `Arc`-оверхеда).
    #[must_use]
    pub fn memory_bytes(&self) -> usize {
        let Ok(sets) = self.entries.read() else {
            return 0;
        };
        sets.iter()
            .flat_map(|set| set.ways.iter().flatten())
            .map(|entry| std::mem::size_of::<CacheEntry>() + entry.meta.heap_bytes())
            .sum()
    }

    /// Полностью очищает кеш (используется при смене снапшота/бенчмарками).
    pub fn clear(&self) {
        if let Ok(mut entries) = self.entries.write() {
            for set in entries.iter_mut() {
                set.ways = std::array::from_fn(|_| None);
            }
        }
    }

    /// Возвращает валидированный лист.
    ///
    /// # Errors
    ///
    /// `Corrupt` — страница повреждена или не является листом; `txn` новее
    /// снапшота; ошибки [`PageIo`].
    pub fn leaf<'a, P: PageIo + ?Sized>(
        &self,
        io: &'a P,
        page_no: u32,
        snapshot_txn: u64,
    ) -> Result<NodeRef<'a>, ZoneFileError> {
        self.get(io, page_no, snapshot_txn, NodeKind::Leaf, 0)
    }

    /// Возвращает валидированное ветвление с ожидаемым уровнем.
    ///
    /// # Errors
    ///
    /// `Corrupt` — страница повреждена/не ветвление/уровень не совпал;
    /// ошибки [`PageIo`].
    pub fn branch<'a, P: PageIo + ?Sized>(
        &self,
        io: &'a P,
        page_no: u32,
        snapshot_txn: u64,
        expected_level: u16,
    ) -> Result<NodeRef<'a>, ZoneFileError> {
        self.get(io, page_no, snapshot_txn, NodeKind::Branch, expected_level)
    }

    fn get<'a, P: PageIo + ?Sized>(
        &self,
        io: &'a P,
        page_no: u32,
        snapshot_txn: u64,
        kind: NodeKind,
        expected_level: u16,
    ) -> Result<NodeRef<'a>, ZoneFileError> {
        let page = io.read_page(page_no)?;
        let page_txn = wire::read_u64(page, 16)
            .ok_or_else(|| corrupt(Some(page_no), CorruptKind::Bounds, CorruptDetail::Truncated))?;
        let key = (page_no, page_txn);
        if page_txn > snapshot_txn {
            return Err(corrupt(
                Some(page_no),
                CorruptKind::Bounds,
                CorruptDetail::OffsetOutOfRange,
            ));
        }
        if let Some(entry) = self.lookup_entry(key) {
            verify_kind(&entry.meta, kind, expected_level, page_no)?;
            self.hits.fetch_add(1, Ordering::Relaxed);
            return Ok(NodeRef::new(page, Arc::clone(&entry.meta)));
        }
        self.misses.fetch_add(1, Ordering::Relaxed);
        let validated = match kind {
            NodeKind::Leaf => NodeMeta::validate_leaf(page, page_no, snapshot_txn, self.page_size)?,
            NodeKind::Branch => {
                NodeMeta::validate_branch(page, page_no, snapshot_txn, self.page_size)?
            }
        };
        verify_kind(&validated, kind, expected_level, page_no)?;
        let meta = Arc::new(validated);
        self.insert(key, Arc::clone(&meta));
        Ok(NodeRef::new(page, meta))
    }

    /// Кладёт в кеш только что закодированный лист (доверенный путь записи).
    pub(crate) fn put_encoded_leaf(&self, page_no: u32, txn: u64, page: &[u8], items: &[LeafItem]) {
        if let Ok(meta) = NodeMeta::from_encoded_leaf(page, page_no, txn, self.page_size, items) {
            self.insert((page_no, txn), Arc::new(meta));
        }
    }

    /// Кладёт в кеш только что закодированное ветвление.
    pub(crate) fn put_encoded_branch(
        &self,
        page_no: u32,
        txn: u64,
        page: &[u8],
        items: &[BranchItem],
    ) {
        if let Ok(meta) = NodeMeta::from_encoded_branch(page, page_no, txn, self.page_size, items) {
            self.insert((page_no, txn), Arc::new(meta));
        }
    }

    fn lookup_entry(&self, key: (u32, u64)) -> Option<Arc<CacheEntry>> {
        let sets = self.entries.read().ok()?;
        let set = sets.get(Self::set_index_for(key.0, sets.len()))?;
        let entry = set
            .ways
            .iter()
            .flatten()
            .find(|entry| entry.meta.page_no == key.0 && entry.meta.txn == key.1)?;
        // Hit не пишет в разделяемые атомики (см. doc-комментарий типа).
        Some(Arc::clone(entry))
    }

    fn set_index_for(page_no: u32, set_count: usize) -> usize {
        ((page_no.wrapping_mul(0x9E37_79B1) >> 8) as usize) % set_count.max(1)
    }

    fn insert(&self, key: (u32, u64), meta: Arc<NodeMeta>) {
        let Ok(mut sets) = self.entries.write() else {
            return;
        };
        let set_count = sets.len().max(1);
        let index = Self::set_index_for(key.0, set_count);
        let Some(set) = sets.get_mut(index) else {
            return;
        };
        let used = self.clock.fetch_add(1, Ordering::Relaxed);
        let entry = Arc::new(CacheEntry {
            meta,
            used: AtomicU64::new(used),
        });
        for way in set.ways.iter_mut().take(self.ways) {
            match way {
                Some(existing) if existing.meta.page_no == key.0 && existing.meta.txn == key.1 => {
                    return;
                }
                None => {
                    *way = Some(entry);
                    return;
                }
                Some(_) => {}
            }
        }
        // Обе линии заняты — вытесняем менее используемую.
        let victim = set
            .ways
            .iter()
            .take(self.ways)
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
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum NodeKind {
    Leaf,
    Branch,
}

fn verify_kind(
    meta: &NodeMeta,
    kind: NodeKind,
    expected_level: u16,
    page_no: u32,
) -> Result<(), ZoneFileError> {
    let kind_matches = match kind {
        NodeKind::Leaf => meta.is_leaf,
        NodeKind::Branch => !meta.is_leaf && meta.header.level == expected_level,
    };
    if kind_matches {
        Ok(())
    } else {
        Err(corrupt(
            Some(page_no),
            CorruptKind::Bounds,
            CorruptDetail::PageType,
        ))
    }
}

fn corrupt(page: Option<u32>, kind: CorruptKind, detail: CorruptDetail) -> ZoneFileError {
    ZoneFileError::corrupt(kind, page, detail)
}
