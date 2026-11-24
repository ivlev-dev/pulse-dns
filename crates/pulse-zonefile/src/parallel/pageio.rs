//! Страничный I/O v2 для B+tree (`PageIo` поверх [`ParallelStore`]).
//!
//! Дерево v1 работает через [`crate::tree::PageIo`] и декодирует заголовок
//! [`crate::PageHeader`]. В v2 `PageHeader.reserved1` (+12) содержит
//! `owner_zone` (`docs/spec/parallel-writes-v2.md` §4.7), а CRC по-прежнему
//! считается по `reserved1 = 0` — так его вычисляют энкодеры `node`. Поэтому:
//!
//! * перед записью [`WriteIo`] проставляет владельца в `reserved1`;
//! * перед чтением страница валидируется (владелец, `txn ≤ version`, CRC) и
//!   копия для v1-декодеров обнуляет `reserved1`.
//!
//! Дополнительно:
//!
//! * [`ReaderIo`] — read-only слой снапшота: страница валидируется один раз на
//!   `page_no` через [`PageCacheV2`] и дальше отдаётся zero-copy (`Arc<[u8]>`);
//!   локальная арена держит `Arc`, поэтому ссылки живут столько же, сколько
//!   слой;
//! * [`WriteIo`] — COW-слой записи: `alloc` берётся из
//!   [`crate::parallel::AllocHandle`] (батчи по 64 страницы) либо из
//!   per-zone пула (см. [`crate::parallel::freepool`]); освобождённые страницы
//!   копятся в `freed` и уходят в bucket коммита;
//! * dirty-страницы пишутся одной пачкой при коммите.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::consts::PAGE_OFF_TXN;
use crate::errors::{CorruptDetail, CorruptKind, InvariantId, ZoneFileError};
use crate::page::{self, PageHeader};
use crate::parallel::consts::PAGE_SIZE_V2;
use crate::parallel::error::{ParallelError, V2CorruptKind};
use crate::parallel::pagecache::PageCacheV2;
use crate::parallel::store::ParallelStore;
use crate::tree::PageIo;
use crate::wire;

/// Размер страницы v2 (фаза A/B1 — только 4096).
pub const V2_PAGE_BYTES: u32 = PAGE_SIZE_V2;

/// Арена прочитанных страниц: только append, слоты не переиспользуются.
///
/// Ссылка на страницу живёт столько же, сколько `&self`; буферы — отдельные
/// `Arc<[u8]>`, поэтому рост `Vec` их не перемещает.
#[derive(Debug, Default)]
struct PageArena {
    pages: RefCell<Vec<(u32, Arc<[u8]>)>>,
}

impl PageArena {
    // Обоснование `unsafe`: арена только дополняется, `Arc<[u8]>` не
    // перемещаются при росте `Vec`, а очистка доступна лишь через `&mut self`,
    // поэтому выданный срез живёт не дольше заимствования арены.
    #[allow(unsafe_code)]
    fn lookup(&self, page: u32) -> Option<&[u8]> {
        let pages = self.pages.borrow();
        let (_, buffer) = pages.iter().rev().find(|(number, _)| *number == page)?;
        let pointer = buffer.as_ptr();
        let length = buffer.len();
        // SAFETY: `pages` — append-only арена; `Arc<[u8]>` не перемещаются и не
        // освобождаются, пока жив `&self`. Возвращаемый срез привязан к
        // `&self`, а `PageArena` очищается только через `&mut self`.
        Some(unsafe { std::slice::from_raw_parts(pointer, length) })
    }

    #[allow(unsafe_code)]
    fn store(&self, page: u32, buffer: Arc<[u8]>) -> &[u8] {
        let mut pages = self.pages.borrow_mut();
        pages.push((page, buffer));
        let Some((_, buffer)) = pages.last() else {
            return &[];
        };
        let pointer = buffer.as_ptr();
        let length = buffer.len();
        // SAFETY: см. `lookup`; буфер только что добавлен и не будет
        // удалён/заменён до конца жизни `&self`.
        unsafe { std::slice::from_raw_parts(pointer, length) }
    }

    fn clear(&mut self) {
        self.pages.get_mut().clear();
    }

    fn len(&self) -> usize {
        self.pages.borrow().len()
    }
}

/// Проверяет v2-заголовок, владельца и `txn`; обнуляет `owner_zone` для v1.
fn prepare_page(
    buffer: &mut [u8],
    page_no: u32,
    ceiling: u64,
    owner_zone: u32,
) -> Result<(), ParallelError> {
    let txn = wire::read_u64(buffer, PAGE_OFF_TXN).ok_or(ParallelError::Corrupt {
        kind: V2CorruptKind::Bounds,
        page: Some(page_no),
    })?;
    let owner = page::parallel_owner(buffer).ok_or(ParallelError::Corrupt {
        kind: V2CorruptKind::Bounds,
        page: Some(page_no),
    })?;
    if owner != owner_zone {
        return Err(ParallelError::Corrupt {
            kind: V2CorruptKind::ForeignOwner,
            page: Some(page_no),
        });
    }
    if txn > ceiling {
        return Err(ParallelError::Corrupt {
            kind: V2CorruptKind::PageTxn,
            page: Some(page_no),
        });
    }
    page::clear_parallel_owner(buffer);
    PageHeader::decode(buffer, page_no, ceiling, V2_PAGE_BYTES).map_err(|error| match error {
        ZoneFileError::Io(error) => ParallelError::Io(error),
        _ => ParallelError::Corrupt {
            kind: V2CorruptKind::Bounds,
            page: Some(page_no),
        },
    })?;
    Ok(())
}

fn placeholder(page_no: u32, error: &ParallelError) -> ZoneFileError {
    match error {
        ParallelError::Corrupt { .. } => ZoneFileError::corrupt(
            CorruptKind::Bounds,
            Some(page_no),
            CorruptDetail::OffsetOutOfRange,
        ),
        _ => ZoneFileError::Io(std::io::Error::other("v2 page I/O failed")),
    }
}

/// Read-only страничный слой снапшота версии `version`.
#[derive(Debug)]
pub(crate) struct ReaderIo<'a> {
    store: &'a ParallelStore,
    zone: u32,
    version: u64,
    cache: Option<&'a PageCacheV2>,
    arena: PageArena,
    error: RefCell<Option<ParallelError>>,
}

impl<'a> ReaderIo<'a> {
    pub(crate) fn new(store: &'a ParallelStore, zone: u32, version: u64) -> Self {
        Self {
            store,
            zone,
            version,
            cache: store.raw_page_cache(),
            arena: PageArena::default(),
            error: RefCell::new(None),
        }
    }

    /// Забирает последнюю точную `ParallelError` (для публичного API).
    pub(crate) fn take_error(&self) -> Option<ParallelError> {
        self.error.borrow_mut().take()
    }

    /// Число прочитанных и закэшированных страниц (диагностика/тесты).
    #[must_use]
    pub(crate) fn cached_pages(&self) -> usize {
        self.arena.len()
    }

    fn stash(&self, page_no: u32, error: ParallelError) -> ZoneFileError {
        let mapped = placeholder(page_no, &error);
        self.error.replace(Some(error));
        mapped
    }

    fn read(&self, page_no: u32) -> Result<&[u8], ZoneFileError> {
        if let Some(page) = self.arena.lookup(page_no) {
            return Ok(page);
        }
        if let Some(cache) = self.cache
            && let Some(data) = cache.get(page_no, self.zone)
        {
            let Some(txn) = wire::read_u64(&data, PAGE_OFF_TXN) else {
                return Err(self.stash(
                    page_no,
                    ParallelError::Corrupt {
                        kind: V2CorruptKind::Bounds,
                        page: Some(page_no),
                    },
                ));
            };
            if txn > self.version {
                return Err(self.stash(
                    page_no,
                    ParallelError::Corrupt {
                        kind: V2CorruptKind::PageTxn,
                        page: Some(page_no),
                    },
                ));
            }
            return Ok(self.arena.store(page_no, data));
        }
        let mut buffer = vec![0_u8; V2_PAGE_BYTES as usize];
        self.store
            .read_page_into(page_no, &mut buffer)
            .map_err(|error| self.stash(page_no, error))?;
        let txn = wire::read_u64(&buffer, PAGE_OFF_TXN).ok_or_else(|| {
            self.stash(
                page_no,
                ParallelError::Corrupt {
                    kind: V2CorruptKind::Bounds,
                    page: Some(page_no),
                },
            )
        })?;
        prepare_page(&mut buffer, page_no, self.version, self.zone)
            .map_err(|error| self.stash(page_no, error))?;
        let data: Arc<[u8]> = buffer.into_boxed_slice().into();
        if let Some(cache) = self.cache {
            cache.insert(page_no, txn, self.zone, Arc::clone(&data));
        }
        Ok(self.arena.store(page_no, data))
    }
}

impl PageIo for ReaderIo<'_> {
    fn page_size(&self) -> u32 {
        V2_PAGE_BYTES
    }

    fn alloc_page(&mut self) -> Result<u32, ZoneFileError> {
        Err(ZoneFileError::corrupt(
            CorruptKind::Bounds,
            None,
            CorruptDetail::OffsetOutOfRange,
        ))
    }

    fn read_page(&self, page_no: u32) -> Result<&[u8], ZoneFileError> {
        self.read(page_no)
    }

    fn write_page(&mut self, page_no: u32, _page: &[u8]) -> Result<(), ZoneFileError> {
        Err(ZoneFileError::corrupt(
            CorruptKind::Bounds,
            Some(page_no),
            CorruptDetail::OffsetOutOfRange,
        ))
    }

    fn free_page(&mut self, _page_no: u32) -> Result<(), ZoneFileError> {
        Ok(())
    }
}

/// COW-слой записи одной зоны (или каталога `0`).
///
/// Живёт не дольше коммита/транзакции: все изменённые страницы собираются в
/// `dirty` и пишутся в [`ParallelStore`] только при коммите. Освобождённые
/// страницы (`free_page`) копятся в `freed` и становятся bucket-группой
/// `drop_txn = V` того же коммита.
#[derive(Debug)]
pub(crate) struct WriteIo<'a> {
    store: &'a ParallelStore,
    zone: u32,
    version: Cell<u64>,
    alloc: crate::parallel::AllocHandle<'a>,
    dirty: RefCell<BTreeMap<u32, Box<[u8]>>>,
    allocated: RefCell<BTreeSet<u32>>,
    freed: RefCell<BTreeSet<u32>>,
    arena: PageArena,
    error: RefCell<Option<ParallelError>>,
}

impl<'a> WriteIo<'a> {
    pub(crate) fn new(store: &'a ParallelStore, zone: u32, version: u64) -> Self {
        Self {
            store,
            zone,
            version: Cell::new(version),
            alloc: store.alloc_handle(),
            dirty: RefCell::new(BTreeMap::new()),
            allocated: RefCell::new(BTreeSet::new()),
            freed: RefCell::new(BTreeSet::new()),
            arena: PageArena::default(),
            error: RefCell::new(None),
        }
    }

    pub(crate) fn set_version(&self, version: u64) {
        self.version.set(version);
    }

    /// Резервирует `txn` коммита (глобальный CAS-блок `TXN_BATCH`).
    pub(crate) fn next_txn(&self) -> Result<u64, ParallelError> {
        self.alloc.next_txn()
    }

    pub(crate) fn take_error(&self) -> Option<ParallelError> {
        self.error.borrow_mut().take()
    }

    /// Забирает dirty-страницы в порядке номеров (детерминированная запись).
    pub(crate) fn take_dirty(&mut self) -> Vec<(u32, Box<[u8]>)> {
        std::mem::take(self.dirty.get_mut()).into_iter().collect()
    }

    /// Забирает страницы, освобождённые в этой транзакции.
    pub(crate) fn take_freed(&mut self) -> Vec<u32> {
        std::mem::take(self.freed.get_mut()).into_iter().collect()
    }

    /// Сбрасывает кэш страниц (между публичными операциями/коммитами).
    pub(crate) fn clear_cache(&mut self) {
        self.arena.clear();
    }

    /// Успешный коммит: сбросить учёт, не возвращая страницы в пул.
    pub(crate) fn finish_commit(&mut self) {
        self.dirty.get_mut().clear();
        self.allocated.get_mut().clear();
        self.freed.get_mut().clear();
        self.arena.clear();
        self.error.borrow_mut().take();
    }

    /// Сбрасывает всю незакоммиченную работу (rollback).
    ///
    /// Страницы, выданные в этой транзакции (из пула или bump-курсора), не
    /// достижимы ни из одной durable-головы, поэтому возвращаются в пул
    /// немедленно (`NEVER_PUBLISHED`, §3.3 A-10).
    pub(crate) fn clear(&mut self) {
        let returned: Vec<u32> = self.allocated.get_mut().iter().copied().collect();
        if !returned.is_empty() {
            self.store.return_pages(self.zone, &returned);
        }
        self.dirty.get_mut().clear();
        self.allocated.get_mut().clear();
        self.freed.get_mut().clear();
        self.arena.clear();
        self.error.borrow_mut().take();
    }

    #[must_use]
    pub(crate) fn cached_pages(&self) -> usize {
        self.arena.len()
    }

    #[must_use]
    pub(crate) fn dirty_pages(&self) -> usize {
        self.dirty.borrow().len()
    }

    fn stash(&self, page_no: u32, error: ParallelError) -> ZoneFileError {
        let mapped = placeholder(page_no, &error);
        self.error.replace(Some(error));
        mapped
    }

    fn read(&self, page_no: u32) -> Result<&[u8], ZoneFileError> {
        if let Some(page) = self.arena.lookup(page_no) {
            return Ok(page);
        }
        let dirty = self.dirty.borrow().get(&page_no).map(|page| page.to_vec());
        if let Some(mut buffer) = dirty {
            prepare_page(&mut buffer, page_no, self.version.get(), self.zone)
                .map_err(|error| self.stash(page_no, error))?;
            let data: Arc<[u8]> = buffer.into_boxed_slice().into();
            return Ok(self.arena.store(page_no, data));
        }
        if let Some(cache) = self.store.raw_page_cache()
            && let Some(data) = cache.get(page_no, self.zone)
        {
            let Some(txn) = wire::read_u64(&data, PAGE_OFF_TXN) else {
                return Err(self.stash(
                    page_no,
                    ParallelError::Corrupt {
                        kind: V2CorruptKind::Bounds,
                        page: Some(page_no),
                    },
                ));
            };
            if txn > self.version.get() {
                return Err(self.stash(
                    page_no,
                    ParallelError::Corrupt {
                        kind: V2CorruptKind::PageTxn,
                        page: Some(page_no),
                    },
                ));
            }
            return Ok(self.arena.store(page_no, data));
        }
        let mut buffer = vec![0_u8; V2_PAGE_BYTES as usize];
        self.store
            .read_page_into(page_no, &mut buffer)
            .map_err(|error| self.stash(page_no, error))?;
        let txn = wire::read_u64(&buffer, PAGE_OFF_TXN).ok_or_else(|| {
            self.stash(
                page_no,
                ParallelError::Corrupt {
                    kind: V2CorruptKind::Bounds,
                    page: Some(page_no),
                },
            )
        })?;
        prepare_page(&mut buffer, page_no, self.version.get(), self.zone)
            .map_err(|error| self.stash(page_no, error))?;
        let data: Arc<[u8]> = buffer.into_boxed_slice().into();
        if let Some(cache) = self.store.raw_page_cache() {
            cache.insert(page_no, txn, self.zone, Arc::clone(&data));
        }
        Ok(self.arena.store(page_no, data))
    }
}

impl PageIo for WriteIo<'_> {
    fn page_size(&self) -> u32 {
        V2_PAGE_BYTES
    }

    fn alloc_page(&mut self) -> Result<u32, ZoneFileError> {
        let current_version = self.version.get();
        if let Some(page) = self
            .store
            .take_pool_page(self.zone, current_version)
            .map_err(|error| self.stash(0, error))?
        {
            if !self.allocated.borrow_mut().insert(page) {
                return Err(ZoneFileError::InvariantViolation(
                    InvariantId::DuplicatePage,
                ));
            }
            return Ok(page);
        }
        let ticket = self
            .alloc
            .reserve(1)
            .map_err(|error| self.stash(0, error))?;
        let page = ticket.first_page;
        if !self.allocated.borrow_mut().insert(page) {
            return Err(ZoneFileError::InvariantViolation(
                InvariantId::DuplicatePage,
            ));
        }
        Ok(page)
    }

    fn read_page(&self, page_no: u32) -> Result<&[u8], ZoneFileError> {
        self.read(page_no)
    }

    fn write_page(&mut self, page_no: u32, page_bytes: &[u8]) -> Result<(), ZoneFileError> {
        if page_bytes.len() != V2_PAGE_BYTES as usize {
            return Err(ZoneFileError::corrupt(
                CorruptKind::Bounds,
                Some(page_no),
                CorruptDetail::OffsetOutOfRange,
            ));
        }
        if !self.allocated.borrow().contains(&page_no) {
            return Err(ZoneFileError::corrupt(
                CorruptKind::Bounds,
                Some(page_no),
                CorruptDetail::PageNo,
            ));
        }
        let mut buffer = page_bytes.to_vec().into_boxed_slice();
        page::seal_parallel_owner(&mut buffer, self.zone);
        // Новая версия страницы могла быть прочитана ранее (cache) — не
        // переиспользуем слот, чтобы не инвалидировать выданные ссылки.
        self.dirty.borrow_mut().insert(page_no, buffer);
        Ok(())
    }

    fn free_page(&mut self, page_no: u32) -> Result<(), ZoneFileError> {
        if !self.freed.borrow_mut().insert(page_no) {
            return Err(ZoneFileError::InvariantViolation(
                InvariantId::DuplicatePage,
            ));
        }
        Ok(())
    }
}
