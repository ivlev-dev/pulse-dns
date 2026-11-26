//! Lock-free аллокатор страниц и `txn`-билетов (D-C, §3).
//!
//! `reserve_cursor`/`reserve_txn` живут только в памяти процесса и
//! инициализируются из durable-барьера при открытии. На диск пишется только
//! `ALLOC_RECORD` (две копии в разных страницах). Курсор монотонен: CAS только
//! вперёд, `[DP, cursor)` — учтённая утечка.

use std::cell::Cell;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::parallel::consts::{
    ALLOC_EXTENT_PAGES, ALLOC_THREAD_CACHE_PAGES, NO_VERSION, TXN_BATCH,
};
use crate::parallel::coord::SharedCoord;
use crate::parallel::error::ParallelError;

/// Выданный диапазон страниц.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AllocTicket {
    /// Первая страница диапазона.
    pub first_page: u32,
    /// Число страниц.
    pub pages: u32,
}

impl AllocTicket {
    /// Последняя страница диапазона (включительно).
    #[must_use]
    pub const fn last_page(self) -> u32 {
        self.first_page.saturating_add(self.pages).saturating_sub(1)
    }

    /// Входит ли страница в диапазон.
    #[must_use]
    pub const fn contains(self, page: u32) -> bool {
        page >= self.first_page && page <= self.last_page()
    }
}

/// Общий аллокатор файла.
#[derive(Debug)]
pub struct Allocator {
    reserve_cursor: AtomicU64,
    reserve_txn: AtomicU64,
    /// Общий (межпроцессный) курсор и `txn` в `MAP_SHARED`-стороне.
    ///
    /// При наличии `shared` локальные атомики не используются: курсор и `txn`
    /// живут в sidecar-файле координатора и резервируются CAS между процессами
    /// (ADR 0007 §4).
    shared: Option<Arc<SharedCoord>>,
    hard_limit: u64,
    start_page_limit: u64,
    cas_retries: AtomicU64,
    txn_cas_retries: AtomicU64,
}

impl Allocator {
    /// Создаёт аллокатор из восстановленных `DP`/`next_txn`.
    ///
    /// # Errors
    ///
    /// `InvalidArgument` — `hard_limit`/`dp` вне контракта.
    pub fn new(dp: u64, next_txn: u64, hard_limit: u32) -> Result<Self, ParallelError> {
        if dp == 0 || dp > u64::from(hard_limit) {
            return Err(ParallelError::InvalidArgument {
                field: "durable_page_limit",
            });
        }
        if next_txn == 0 {
            return Err(ParallelError::InvalidArgument { field: "next_txn" });
        }
        Ok(Self {
            reserve_cursor: AtomicU64::new(dp),
            reserve_txn: AtomicU64::new(next_txn),
            shared: None,
            hard_limit: u64::from(hard_limit),
            start_page_limit: dp,
            cas_retries: AtomicU64::new(0),
            txn_cas_retries: AtomicU64::new(0),
        })
    }

    /// Создаёт аллокатор поверх общего `MAP_SHARED`-курсора.
    ///
    /// Значения курсора/`txn` уже установлены [`SharedCoord::open`] (с учётом
    /// `DP` и живых писателей), поэтому здесь они только читаются.
    ///
    /// # Errors
    ///
    /// `InvalidArgument` — `dp`/`next_txn` вне контракта.
    pub(crate) fn new_shared(
        dp: u64,
        next_txn: u64,
        hard_limit: u32,
        shared: Arc<SharedCoord>,
    ) -> Result<Self, ParallelError> {
        if dp == 0 || dp > u64::from(hard_limit) {
            return Err(ParallelError::InvalidArgument {
                field: "durable_page_limit",
            });
        }
        if next_txn == 0 {
            return Err(ParallelError::InvalidArgument { field: "next_txn" });
        }
        Ok(Self {
            reserve_cursor: AtomicU64::new(dp),
            reserve_txn: AtomicU64::new(next_txn),
            shared: Some(shared),
            hard_limit: u64::from(hard_limit),
            start_page_limit: dp,
            cas_retries: AtomicU64::new(0),
            txn_cas_retries: AtomicU64::new(0),
        })
    }

    fn load_cursor(&self) -> u64 {
        match &self.shared {
            Some(coord) => coord.cursor().load(Ordering::Acquire),
            None => self.reserve_cursor.load(Ordering::Acquire),
        }
    }

    fn cas_cursor(&self, current: u64, next: u64) -> bool {
        match &self.shared {
            Some(coord) => coord
                .cursor()
                .compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok(),
            None => self
                .reserve_cursor
                .compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok(),
        }
    }

    fn load_txn(&self) -> u64 {
        match &self.shared {
            Some(coord) => coord.txn().load(Ordering::Acquire),
            None => self.reserve_txn.load(Ordering::Acquire),
        }
    }

    fn cas_txn(&self, current: u64, next: u64) -> bool {
        match &self.shared {
            Some(coord) => coord
                .txn()
                .compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok(),
            None => self
                .reserve_txn
                .compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok(),
        }
    }

    /// Первая невыданная страница.
    #[must_use]
    pub fn cursor(&self) -> u64 {
        self.load_cursor()
    }

    /// Следующий `txn`, который будет выдан.
    #[must_use]
    pub fn txn_cursor(&self) -> u64 {
        self.load_txn()
    }

    /// Жёсткий лимит страниц.
    #[must_use]
    pub const fn hard_limit(&self) -> u64 {
        self.hard_limit
    }

    /// `DP` на момент открытия.
    #[must_use]
    pub const fn start_page_limit(&self) -> u64 {
        self.start_page_limit
    }

    /// Число CAS-повторов страниц.
    #[must_use]
    pub fn cas_retries(&self) -> u64 {
        self.cas_retries.load(Ordering::Relaxed)
    }

    /// Число CAS-повторов `txn`.
    #[must_use]
    pub fn txn_cas_retries(&self) -> u64 {
        self.txn_cas_retries.load(Ordering::Relaxed)
    }

    /// Оценка утечки «выделено, но не опубликовано»: `cursor − durable`.
    #[must_use]
    pub fn leaked_pages(&self, durable_page_limit: u64) -> u64 {
        self.cursor().saturating_sub(durable_page_limit)
    }

    /// Резервирует ровно `pages` страниц (без локального кеша).
    ///
    /// CAS `cursor → cursor + pages`; диапазоны не пересекаются и не убывают.
    ///
    /// # Errors
    ///
    /// `MapFull` — страницы не помещаются в `hard_limit`;
    /// `InvalidArgument` — `pages == 0`.
    pub fn reserve_exact(&self, pages: u32) -> Result<AllocTicket, ParallelError> {
        if pages == 0 {
            return Err(ParallelError::InvalidArgument { field: "pages" });
        }
        let requested = u64::from(pages);
        loop {
            let current = self.load_cursor();
            let Some(next) = current.checked_add(requested) else {
                return Err(ParallelError::MapFull {
                    high_water: current,
                    page_count_max: u32::try_from(self.hard_limit).unwrap_or(u32::MAX),
                });
            };
            if next > self.hard_limit {
                return Err(ParallelError::MapFull {
                    high_water: current,
                    page_count_max: u32::try_from(self.hard_limit).unwrap_or(u32::MAX),
                });
            }
            if self.cas_cursor(current, next) {
                let ticket = ticket(current, pages)?;
                self.bump_generations(ticket.first_page, pages);
                return Ok(ticket);
            }
            self.cas_retries.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Помечает выданный диапазон новой генерацией (multi-process).
    ///
    /// Генерация — часть ключа кеша страниц: страница, выданная заново после
    /// освобождения, не должна попадать в кеш под старым ключом.
    fn bump_generations(&self, first: u32, pages: u32) {
        if let Some(coord) = &self.shared {
            coord.bump_page_generations(first, pages);
        }
    }

    /// Создаёт per-thread handle с локальным кешем страниц и `txn`.
    #[must_use]
    pub fn handle(&self) -> AllocHandle<'_> {
        AllocHandle {
            allocator: self,
            pages_start: Cell::new(0),
            pages_len: Cell::new(0),
            txn_start: Cell::new(0),
            txn_len: Cell::new(0),
            exact: false,
        }
    }

    /// Создаёт handle без локального кеша: каждая страница/`txn` резервируется
    /// ровно на запрос.
    ///
    /// Нужен короткоживущим writer'ам (например, REST-запросу), которые не
    /// успевают использовать батч из 64 страниц и иначе теряли бы его.
    #[must_use]
    pub fn handle_exact(&self) -> AllocHandle<'_> {
        AllocHandle {
            allocator: self,
            pages_start: Cell::new(0),
            pages_len: Cell::new(0),
            txn_start: Cell::new(0),
            txn_len: Cell::new(0),
            exact: true,
        }
    }

    /// Выдаёт следующий `txn` одним CAS (без кеша; для тестов/утилит).
    ///
    /// # Errors
    ///
    /// `InvalidArgument` — `txn` переполнен.
    pub fn next_txn_exact(&self) -> Result<u64, ParallelError> {
        loop {
            let current = self.load_txn();
            let Some(next) = current.checked_add(1) else {
                return Err(ParallelError::InvalidArgument { field: "txn" });
            };
            if self.cas_txn(current, next) {
                return Ok(current);
            }
            self.txn_cas_retries.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn reserve_batch(&self, minimum: u32) -> Result<(u64, u32), ParallelError> {
        loop {
            let current = self.load_cursor();
            let remaining = self.hard_limit.saturating_sub(current);
            let available = u32::try_from(remaining).unwrap_or(u32::MAX);
            let batch = if remaining >= u64::from(ALLOC_THREAD_CACHE_PAGES) {
                let want = u64::from(ALLOC_THREAD_CACHE_PAGES.max(minimum));
                let extent = u64::from(ALLOC_EXTENT_PAGES);
                let rounded = want.div_ceil(extent).saturating_mul(extent);
                u32::try_from(rounded).unwrap_or(u32::MAX).min(available)
            } else {
                minimum.max(ALLOC_EXTENT_PAGES).min(available)
            };
            if batch < minimum {
                return Err(ParallelError::MapFull {
                    high_water: current,
                    page_count_max: u32::try_from(self.hard_limit).unwrap_or(u32::MAX),
                });
            }
            let Some(next) = current.checked_add(u64::from(batch)) else {
                return Err(ParallelError::MapFull {
                    high_water: current,
                    page_count_max: u32::try_from(self.hard_limit).unwrap_or(u32::MAX),
                });
            };
            if next > self.hard_limit {
                return Err(ParallelError::MapFull {
                    high_water: current,
                    page_count_max: u32::try_from(self.hard_limit).unwrap_or(u32::MAX),
                });
            }
            if self.cas_cursor(current, next) {
                return Ok((current, batch));
            }
            self.cas_retries.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn reserve_txn_batch(&self) -> Result<u64, ParallelError> {
        loop {
            let current = self.load_txn();
            let Some(next) = current.checked_add(TXN_BATCH) else {
                return Err(ParallelError::InvalidArgument { field: "txn" });
            };
            if self.cas_txn(current, next) {
                return Ok(current);
            }
            self.txn_cas_retries.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Per-thread handle аллокатора с кешем 64 страниц и блоком 64 `txn`.
///
/// Не `Sync`: кеш — `Cell`, handle создаётся на поток.
#[derive(Debug)]
pub struct AllocHandle<'a> {
    allocator: &'a Allocator,
    pages_start: Cell<u64>,
    pages_len: Cell<u32>,
    txn_start: Cell<u64>,
    txn_len: Cell<u64>,
    exact: bool,
}

impl AllocHandle<'_> {
    /// Резервирует `pages` страниц из локального кеша или батча.
    ///
    /// # Errors
    ///
    /// `MapFull` — страницы не помещаются; `InvalidArgument` — `pages == 0`.
    pub fn reserve(&self, pages: u32) -> Result<AllocTicket, ParallelError> {
        if pages == 0 {
            return Err(ParallelError::InvalidArgument { field: "pages" });
        }
        if self.exact {
            return self.allocator.reserve_exact(pages);
        }
        if self.pages_len.get() < pages {
            let (start, batch) = self.allocator.reserve_batch(pages)?;
            self.pages_start.set(start);
            self.pages_len.set(batch);
        }
        let start = self.pages_start.get();
        let first = u32::try_from(start).map_err(|_| ParallelError::MapFull {
            high_water: start,
            page_count_max: u32::try_from(self.allocator.hard_limit).unwrap_or(u32::MAX),
        })?;
        self.pages_start.set(start + u64::from(pages));
        self.pages_len.set(self.pages_len.get() - pages);
        let ticket = AllocTicket {
            first_page: first,
            pages,
        };
        self.allocator
            .bump_generations(ticket.first_page, ticket.pages);
        Ok(ticket)
    }

    /// Остаток локального кеша страниц.
    #[must_use]
    pub fn cached_pages(&self) -> u32 {
        self.pages_len.get()
    }

    /// Следующий `txn` из локального блока.
    ///
    /// # Errors
    ///
    /// `InvalidArgument` — `txn` переполнен.
    pub fn next_txn(&self) -> Result<u64, ParallelError> {
        if self.exact {
            return self.allocator.next_txn_exact();
        }
        if self.txn_len.get() == 0 {
            self.txn_start.set(self.allocator.reserve_txn_batch()?);
            self.txn_len.set(TXN_BATCH);
        }
        let txn = self.txn_start.get();
        self.txn_start.set(txn + 1);
        self.txn_len.set(self.txn_len.get() - 1);
        Ok(txn)
    }

    /// Остаток локального блока `txn`.
    #[must_use]
    pub fn cached_txn(&self) -> u64 {
        self.txn_len.get()
    }

    /// Ссылка на общий аллокатор.
    #[must_use]
    pub fn allocator(&self) -> &Allocator {
        self.allocator
    }
}

fn ticket(start: u64, pages: u32) -> Result<AllocTicket, ParallelError> {
    let first =
        u32::try_from(start).map_err(|_| ParallelError::InvalidArgument { field: "page_id" })?;
    Ok(AllocTicket {
        first_page: first,
        pages,
    })
}

/// Значение `NO_VERSION` как «пинов нет» (для тестов `MP`).
pub const NO_PIN_VERSION: u64 = NO_VERSION;
