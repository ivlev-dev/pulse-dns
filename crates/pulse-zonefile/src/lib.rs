//! Прототип формата файла зон pulse (v1), фазы 1–3.
//!
//! Фаза 1: константы формата, CRC-32C, superblock, meta-страницы, pager
//! (создание/открытие), lock-файл writer'а, таблица читателей с двухфазным
//! пином, восстановление активной meta (max-valid, torn-диагностика,
//! `Memory`-фолбэк/read-only), липкий режим durability, правило
//! переиспользования страниц и ленивые проверки заголовка страницы.
//!
//! Фаза 2: RLE-ключи и канонический компаратор ([`key`]), узлы B+tree с
//! фронт-кодированием и валидацией ([`node`]), overflow-цепочки RDATA
//! ([`overflow`]), B+tree зоны с `T_NODE`/ENT-материализацией и абстракция
//! страничного I/O ([`tree`]). Горячий путь чтения — [`cache::PageCache`]:
//! страница валидируется один раз на версию, далее поиск идёт по zero-copy
//! [`node::NodeRef`] без аллокаций. Каталог зон в памяти — [`zone_index`].
//!
//! Фаза 3: персистентный стор — [`freelist`] (bucket-страницы, COW-образы,
//! граница `reclaim_txn`), транзакционный оверлей и аллокатор (`store`),
//! коммит страниц/меты (`ZoneFile::write` → [`ZoneWriter::commit`]),
//! удаление RRset/имени/поддерева и tombstone-зон, `compact_zone`, `sync()`
//! и offline [`ZoneFile::fsck`]. Каталог зон — [`zone_meta`].
//!
//! # Пример
//!
//! ```
//! use pulse_zonefile::key::NameRle;
//! use pulse_zonefile::{CreateConfig, OpenConfig, RrsetData, SyncMode, ZoneFile};
//!
//! let dir = tempfile::tempdir().unwrap();
//! let path = dir.path().join("zones.zonefile");
//! let mut zonefile = ZoneFile::create(&path, CreateConfig {
//!     map_size: 64 * 1024 * 1024,
//!     ..CreateConfig::default()
//! }).unwrap();
//! let apex = NameRle::from_ascii("example.com").unwrap();
//! let mut writer = zonefile.write().unwrap();
//! writer.create_zone(&apex, 0).unwrap();
//! writer.upsert_rrset(
//!     &apex,
//!     &apex,
//!     1,
//!     0,
//!     &RrsetData::from_slices(300, 0, &[&[192, 0, 2, 1]]).unwrap(),
//! ).unwrap();
//! writer.commit(SyncMode::Sync).unwrap();
//! drop(zonefile);
//!
//! let reopened = ZoneFile::open(&path, OpenConfig::default()).unwrap();
//! assert!(reopened.lookup_rrset(&apex, &apex, 1, 0).unwrap().is_some());
//! ```

#![deny(unsafe_op_in_unsafe_fn)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

pub mod cache;
pub mod checksum;
pub mod consts;
mod crash_tests;
mod errors;
pub mod freelist;
mod fsck;
mod hash;
pub mod key;
mod lock;
mod map;
pub mod mem;
pub mod meta;
pub mod node;
pub mod overflow;
mod page;
mod pager;
pub mod parallel;
pub mod readers;
mod recovery;
mod store;
pub mod superblock;
pub mod tree;
mod wire;
pub mod zone_index;
pub mod zone_meta;
mod zonefile;

pub use errors::{CorruptDetail, CorruptKind, InvariantId, Version, ZoneFileError};
pub use freelist::{Bucket, Freelist};
pub use mem::{HugePages, ThpStatus};
pub use meta::Meta;
pub use page::PageHeader;
pub use pager::{LockMode, OpenConfig};
pub use readers::{Reader, ReaderTable, Snapshot};
pub use recovery::is_reclaimable;
pub use superblock::{CreateConfig, SectionDescriptor, Superblock, SyncMode};
pub use tree::{BTree, PageIo, RrsetData, UpsertOutcome, ZoneTree};
pub use zone_meta::{ZoneEntry, ZoneMetaBlock, ZoneState};
pub use zonefile::{
    CommitOutcome, FsckReport, RrsetView, ZoneFile, ZoneItem, ZoneItemValue, ZoneItems, ZoneWriter,
};
