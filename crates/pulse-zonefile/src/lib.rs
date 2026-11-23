//! Прототип формата файла зон pulse (v1), фаза 1.
//!
//! Реализовано: константы формата, CRC-32C, superblock, meta-страницы, pager
//! (создание/открытие), lock-файл writer'а, таблица читателей с двухфазным
//! пином, восстановление активной meta (max-valid, torn-диагностика,
//! `Memory`-фолбэк/read-only), липкий режим durability, правило
//! переиспользования страниц и ленивые проверки заголовка страницы.
//!
//! Не реализовано (следующие фазы): B+tree, каталог зон, overflow-цепочки,
//! freelist, коммит правок и `fsck`.
//!
//! # Пример
//!
//! ```
//! use pulse_zonefile::{CreateConfig, OpenConfig, ZoneFile};
//!
//! let dir = tempfile::tempdir().unwrap();
//! let path = dir.path().join("zones.zonefile");
//! let config = CreateConfig {
//!     map_size: 64 * 1024 * 1024,
//!     ..CreateConfig::default()
//! };
//! let zonefile = ZoneFile::create(&path, config).unwrap();
//! assert_eq!(zonefile.meta().txnid, 1);
//! drop(zonefile);
//!
//! let reopened = ZoneFile::open(&path, OpenConfig::default()).unwrap();
//! assert_eq!(reopened.txnid(), 1);
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

pub mod checksum;
pub mod consts;
mod errors;
mod lock;
mod map;
pub mod meta;
mod page;
mod pager;
pub mod readers;
mod recovery;
pub mod superblock;
mod wire;
mod zonefile;

pub use errors::{CorruptDetail, CorruptKind, InvariantId, Version, ZoneFileError};
pub use meta::Meta;
pub use page::PageHeader;
pub use pager::{LockMode, OpenConfig};
pub use readers::{Reader, ReaderTable, Snapshot};
pub use recovery::is_reclaimable;
pub use superblock::{CreateConfig, SectionDescriptor, Superblock, SyncMode};
pub use zonefile::ZoneFile;
