//! Фаза A параллельной записи v2.0 (`ParallelStore`).
//!
//! Фаза A: нормативная раскладка
//! [`docs/spec/parallel-writes-v2.md`](../../../../docs/spec/parallel-writes-v2.md)
//! (`LayoutHead` A/B, `ALLOC_RECORD` A/B, root ring 4×2, chain-страницы,
//! `RootEntry` 64 Б, lock-free аллокатор, пины с `EpochGuard`/`MP`/`RV`,
//! recovery и `fsck`-lite). Фаза B1: B+tree поверх стора (`pageio`), per-zone
//! writer/commit (`zone`), каталог зон в слоте 0 и read snapshots.
//!
//! Фаза B2a: [`PageCacheV2`] (валидация страницы один раз на `(page_no, txn)`,
//! zero-copy warm lookup) и рекламация — per-zone bucket'ы с `drop_txn`,
//! `free_head` в `RootEntry`, `is_reclaimable`, chain-GC, освобождение
//! overflow/tombstone и donation.
//!
//! Фаза B2b: group commit ([`GroupCommitter`], [`ParallelStore::commit_group`]):
//! батчинг зон, ровно два `fdatasync` на группу, backpressure и ack после
//! публикации; `Flush`/`Memory` и липкий `Sync`; tombstone-GC каталога
//! ([`ParallelZones::gc_catalog`]); sweep утечек ([`ParallelStore::leak_report`],
//! [`ParallelStore::repair_leaks`], [`fsck_repair`]). M3 (ADR 0007):
//! `multi_process` — общий sidecar-координатор (`coord`), per-zone
//! `fcntl`-lease, reader table и seqlock публикации; каталог пишут все
//! процессы под catalog lease, durable-пулы рекламируются под lease с гейтом
//! `drop_txn < min(D_z, MP, freeze)`. B3: `pulsed` работает
//! поверх v2 (`--data`), а пользовательские
//! метаданные зоны (вид, TTL по умолчанию, denial) хранятся в записи каталога
//! ([`ZoneMetaV2`]); v1-модули остаются для чтения legacy-файлов и
//! `pulsed convert`.
//!
//! # Пример
//!
//! ```
//! use pulse_zonefile::parallel::{ParallelStore, RootEntry, RootState, StoreConfig};
//!
//! let dir = tempfile::tempdir().unwrap();
//! let path = dir.path().join("zones.v2");
//! let store = ParallelStore::create(&path, StoreConfig::small(8, 512)).unwrap();
//! let ticket = store.reserve_pages(1).unwrap();
//! store.write_raw_page(ticket.first_page, b"leaf").unwrap();
//! let entry = RootEntry {
//!     owner_zone: 1,
//!     version: 2,
//!     root_page: ticket.first_page,
//!     state: RootState::Serving,
//!     ..RootEntry::default()
//! };
//! store.publish_root(entry).unwrap();
//! let reader = store.reader().unwrap();
//! let snapshot = store.zone_snapshot(&reader, 1).unwrap();
//! assert_eq!(snapshot.version(), 2);
//! ```

#![doc = include_str!("README.md")]

pub mod alloc;
pub mod consts;
pub mod coord;
pub mod error;
pub mod freepool;
pub mod geometry;
pub mod group;
pub mod layout;
pub mod pagecache;
mod pageio;
pub mod pins;
pub mod recovery;
pub mod ring;
pub mod root;
pub mod store;
pub mod verify;
pub mod zone;

pub use alloc::{AllocHandle, AllocTicket, Allocator};
pub use error::{CopySource, FatalKind, ParallelError, V2CorruptKind};
pub use freepool::is_reclaimable;
pub use geometry::{Geometry, ZoneSlot};
pub use group::{GroupCommitConfig, GroupCommitter, GroupStats};
pub use layout::{
    AllocRecord, ChainPage, FilePin, FileReaderSlot, LayoutHead, SuperblockV2, SyncModeV2,
    WriterRegistry,
};
pub use pagecache::{DEFAULT_PAGE_CACHE_V2_ENTRIES, PageCacheV2, PageCacheV2Stats};
pub use pageio::V2_PAGE_BYTES;
pub use pins::{EpochGuard, FreezeGuard, GcState, PinGuard, PinTable, Reader};
pub use recovery::{FsckLiteReport, OpenConfigV2, RecoveryReport};
pub use ring::{CellView, CopyState, SlotView};
pub use root::{RootEntry, RootFieldError, RootFlags, RootState};
pub use store::{
    CrashHook, CrashPoint, GroupCommitRequest, IoFaultHook, LeakReport, ParallelStore,
    PublishOutcome, RepairReport, StoreConfig, StoreStats, ZoneSnapshot, fsck_repair,
    open_read_only,
};
pub use verify::GraphReport;
pub use zone::{
    BULK_MAX_OWNER_BYTES, BulkOutcome, BulkRrset, CommitOutcome, ParallelZone, ParallelZones,
    RrsetRecord, RrsetRef, ZONE_KIND_FLAG_FORWARD, ZONE_KIND_FLAG_SECONDARY, ZoneCreateMeta,
    ZoneInfo, ZoneMetaV2, ZoneReader,
};

/// Алиас режима durability v2: `Durability::Sync`/`Flush`/`Memory` (§7.2).
pub type Durability = SyncModeV2;

// v1-типы, с которыми работает B1-API зон (переиспользование, не копия).
pub use crate::tree::{RrsetData, UpsertOutcome};
