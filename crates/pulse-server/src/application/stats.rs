//! Счётчики запросов без глобальных блокировок.

use std::sync::atomic::{AtomicU64, Ordering};

/// Атомарные счётчики авторитетного движка.
///
/// Все операции — `Relaxed`: счётчики не участвуют в синхронизации данных,
/// важна только итоговая сумма. Инкременты не блокируют поток запроса.
#[derive(Debug, Default)]
pub struct QueryStats {
    queries: AtomicU64,
    nxdomain: AtomicU64,
    nodata: AtomicU64,
    refused: AtomicU64,
    truncated: AtomicU64,
    notimp: AtomicU64,
    badvers: AtomicU64,
    formerr: AtomicU64,
    servfail: AtomicU64,
}

impl QueryStats {
    /// Создаёт обнулённые счётчики.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Снимок счётчиков: каждое поле читается отдельно (`Relaxed`), поэтому
    /// значения могут относиться к немного разным моментам времени. Для
    /// метрик этого достаточно; это не транзакционный снимок.
    #[must_use]
    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            queries: self.queries.load(Ordering::Relaxed),
            nxdomain: self.nxdomain.load(Ordering::Relaxed),
            nodata: self.nodata.load(Ordering::Relaxed),
            refused: self.refused.load(Ordering::Relaxed),
            truncated: self.truncated.load(Ordering::Relaxed),
            notimp: self.notimp.load(Ordering::Relaxed),
            badvers: self.badvers.load(Ordering::Relaxed),
            formerr: self.formerr.load(Ordering::Relaxed),
            servfail: self.servfail.load(Ordering::Relaxed),
        }
    }

    /// Число обработанных запросов.
    #[must_use]
    pub fn queries(&self) -> u64 {
        self.queries.load(Ordering::Relaxed)
    }

    /// Число ответов `NXDOMAIN`.
    #[must_use]
    pub fn nxdomain(&self) -> u64 {
        self.nxdomain.load(Ordering::Relaxed)
    }

    /// Число ответов `NODATA`.
    #[must_use]
    pub fn nodata(&self) -> u64 {
        self.nodata.load(Ordering::Relaxed)
    }

    /// Число ответов `REFUSED`.
    #[must_use]
    pub fn refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }

    /// Число усечённых ответов (`TC = 1`).
    #[must_use]
    pub fn truncated(&self) -> u64 {
        self.truncated.load(Ordering::Relaxed)
    }

    /// Число ответов `NOTIMP`.
    #[must_use]
    pub fn notimp(&self) -> u64 {
        self.notimp.load(Ordering::Relaxed)
    }

    /// Число ответов `BADVERS`.
    #[must_use]
    pub fn badvers(&self) -> u64 {
        self.badvers.load(Ordering::Relaxed)
    }

    /// Число ответов `FORMERR`.
    #[must_use]
    pub fn formerr(&self) -> u64 {
        self.formerr.load(Ordering::Relaxed)
    }

    /// Число ответов `SERVFAIL`.
    #[must_use]
    pub fn servfail(&self) -> u64 {
        self.servfail.load(Ordering::Relaxed)
    }

    pub(crate) fn record_query(&self) {
        self.queries.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_nxdomain(&self) {
        self.nxdomain.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_nodata(&self) {
        self.nodata.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_refused(&self) {
        self.refused.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_truncated(&self) {
        self.truncated.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_notimp(&self) {
        self.notimp.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_badvers(&self) {
        self.badvers.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_formerr(&self) {
        self.formerr.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_servfail(&self) {
        self.servfail.fetch_add(1, Ordering::Relaxed);
    }
}

/// Снимок [`QueryStats`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StatsSnapshot {
    /// Обработано запросов.
    pub queries: u64,
    /// Ответов `NXDOMAIN`.
    pub nxdomain: u64,
    /// Ответов `NODATA`.
    pub nodata: u64,
    /// Ответов `REFUSED`.
    pub refused: u64,
    /// Ответов с `TC = 1`.
    pub truncated: u64,
    /// Ответов `NOTIMP`.
    pub notimp: u64,
    /// Ответов `BADVERS`.
    pub badvers: u64,
    /// Ответов `FORMERR`.
    pub formerr: u64,
    /// Ответов `SERVFAIL`.
    pub servfail: u64,
}
