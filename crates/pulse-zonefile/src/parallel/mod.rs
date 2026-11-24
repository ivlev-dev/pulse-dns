//! Фаза A параллельной записи v2.0 (`ParallelStore`).
//!
//! Модуль реализует нормативную раскладку
//! [`docs/spec/parallel-writes-v2.md`](../../../../docs/spec/parallel-writes-v2.md):
//! `LayoutHead` A/B, `ALLOC_RECORD` A/B, root ring 4×2, chain-страницы,
//! `RootEntry` 64 Б, lock-free аллокатор (`reserve_cursor`/`reserve_txn` в
//! памяти), in-process пины читателей с `EpochGuard`/`MP`/`RV`, recovery и
//! `fsck`-lite.
//!
//! B+tree, per-zone пулы, donation, group commit, `Flush`/`Memory` и
//! межпроцессная запись — фаза B. v1-модули и `pulsed` не затронуты.
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
pub mod error;
pub mod geometry;
pub mod layout;
pub mod pins;
pub mod recovery;
pub mod ring;
pub mod root;
pub mod store;

pub use alloc::{AllocHandle, AllocTicket, Allocator};
pub use error::{CopySource, FatalKind, ParallelError, V2CorruptKind};
pub use geometry::{Geometry, ZoneSlot};
pub use layout::{
    AllocRecord, ChainPage, FilePin, FileReaderSlot, LayoutHead, SuperblockV2, SyncModeV2,
    WriterRegistry,
};
pub use pins::{EpochGuard, FreezeGuard, GcState, PinGuard, PinTable, Reader};
pub use recovery::{FsckLiteReport, OpenConfigV2, RecoveryReport};
pub use ring::{CellView, CopyState, SlotView};
pub use root::{RootEntry, RootFieldError, RootFlags, RootState};
pub use store::{
    CrashHook, CrashPoint, ParallelStore, PublishOutcome, StoreConfig, StoreStats, ZoneSnapshot,
    open_read_only,
};
