//! Геометрия файла v2.0 и root directory (§10.1, §4.2).
//!
//! Все номера страниц вычисляются из `max_zones` и размера страницы. Фаза A
//! поддерживает только `page_size = 4096`, поэтому раскладка ring — ровно
//! 16 зон × 256 Б на страницу-копию.

use crate::parallel::consts::{
    DEFAULT_MAX_ZONES, DEFAULT_PAGE_COUNT_MAX, MAX_ROOT_CHAIN_PAGES, MAX_ZONES_V2,
    PAGE_ALLOC_RECORD_A, PAGE_ALLOC_RECORD_B, PAGE_LAYOUT_HEAD_A, PAGE_LAYOUT_HEAD_B,
    PAGE_READER_TABLE, PAGE_SIZE_V2, PAGE_WRITER_REG, READER_PAGE_DESC_SIZE, READER_SLOT_SIZE_V2,
    READER_SLOTS_V2, ROOT_BLOCK_SIZE, ROOT_ENTRY_SIZE, ROOT_VERSIONS, ZONES_PER_DIR_PAGE,
};
use crate::parallel::error::ParallelError;

/// Полная геометрия файла v2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Geometry {
    page_size: u32,
    max_zones: u32,
    page_count_max: u32,
    max_root_chain_pages: u32,
    reader_slots: u32,
    reader_pages: u32,
    root_dir_pages: u32,
    page_layout_head_a: u32,
    page_layout_head_b: u32,
    page_writer_reg: u32,
    page_alloc_record_a: u32,
    page_alloc_record_b: u32,
    page_reader_table: u32,
    page_root_dir_a_first: u32,
    page_root_dir_b_first: u32,
    page_data_first: u32,
}

/// Координаты одной зоны в root directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZoneSlot {
    /// Страница-копия A.
    pub page_a: u32,
    /// Страница-копия B.
    pub page_b: u32,
    /// Смещение блока зоны внутри страницы (0..4096, кратно 256).
    pub block_offset: u32,
}

impl ZoneSlot {
    /// Смещение ячейки версии `version % 4` внутри блока.
    ///
    /// Модуль версии всегда `< 4`, поэтому приведение не теряет данные.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub const fn cell_offset(self, version: u64) -> usize {
        let group = (version % ROOT_VERSIONS as u64) as usize;
        self.block_offset as usize + group * ROOT_ENTRY_SIZE as usize
    }
}

impl Geometry {
    /// Создаёт геометрию и проверяет, что пролог помещается в файл.
    ///
    /// # Errors
    ///
    /// `InvalidArgument` — нулевые/слишком большие `max_zones`,
    /// `page_count_max`, `max_root_chain_pages`, `reader_slots`; `Unsupported` —
    /// размер страницы, отличный от 4096; `MapFull` — пролог не влезает.
    pub fn new(
        max_zones: u32,
        page_count_max: u32,
        max_root_chain_pages: u32,
        reader_slots: u32,
    ) -> Result<Self, ParallelError> {
        if max_zones == 0 || max_zones > MAX_ZONES_V2 {
            return Err(ParallelError::InvalidArgument { field: "max_zones" });
        }
        if max_root_chain_pages == 0 || max_root_chain_pages > MAX_ROOT_CHAIN_PAGES {
            return Err(ParallelError::InvalidArgument {
                field: "max_root_chain_pages",
            });
        }
        if reader_slots == 0 || reader_slots > READER_SLOTS_V2 {
            return Err(ParallelError::InvalidArgument {
                field: "reader_slots",
            });
        }
        let page_size = PAGE_SIZE_V2;
        let reader_pages = reader_pages(page_size, reader_slots)?;
        let root_dir_pages = root_dir_pages_per_region(max_zones)?;
        let a_start =
            PAGE_READER_TABLE
                .checked_add(reader_pages)
                .ok_or(ParallelError::InvalidArgument {
                    field: "page_root_dir_a_first",
                })?;
        let b_start =
            a_start
                .checked_add(root_dir_pages)
                .ok_or(ParallelError::InvalidArgument {
                    field: "page_root_dir_b_first",
                })?;
        let data_start =
            b_start
                .checked_add(root_dir_pages)
                .ok_or(ParallelError::InvalidArgument {
                    field: "page_data_first",
                })?;
        if page_count_max == 0 || data_start > page_count_max {
            return Err(ParallelError::MapFull {
                high_water: u64::from(data_start),
                page_count_max,
            });
        }
        Ok(Self {
            page_size,
            max_zones,
            page_count_max,
            max_root_chain_pages,
            reader_slots,
            reader_pages,
            root_dir_pages,
            page_layout_head_a: PAGE_LAYOUT_HEAD_A,
            page_layout_head_b: PAGE_LAYOUT_HEAD_B,
            page_writer_reg: PAGE_WRITER_REG,
            page_alloc_record_a: PAGE_ALLOC_RECORD_A,
            page_alloc_record_b: PAGE_ALLOC_RECORD_B,
            page_reader_table: PAGE_READER_TABLE,
            page_root_dir_a_first: a_start,
            page_root_dir_b_first: b_start,
            page_data_first: data_start,
        })
    }

    /// Создаёт геометрию с дефолтными `max_zones`/`page_count_max`/chain/slots.
    ///
    /// # Errors
    ///
    /// См. [`Geometry::new`].
    pub fn with_defaults() -> Result<Self, ParallelError> {
        Self::new(
            DEFAULT_MAX_ZONES,
            DEFAULT_PAGE_COUNT_MAX,
            MAX_ROOT_CHAIN_PAGES,
            READER_SLOTS_V2,
        )
    }

    /// Проверяет, что геометрия самосогласована (для декодированного `LayoutHead`).
    ///
    /// # Errors
    ///
    /// `Unsupported`/`InvalidArgument` — поля не сходятся; `MapFull` — пролог
    /// не влезает в `page_count_max`.
    pub fn verify(&self) -> Result<(), ParallelError> {
        let reference = Self::new(
            self.max_zones,
            self.page_count_max,
            self.max_root_chain_pages,
            self.reader_slots,
        )?;
        if reference != *self {
            return Err(ParallelError::Corrupt {
                kind: crate::parallel::error::V2CorruptKind::LayoutHead,
                page: Some(self.page_layout_head_a),
            });
        }
        Ok(())
    }

    /// Размер страницы.
    #[must_use]
    pub const fn page_size(self) -> u32 {
        self.page_size
    }

    /// Максимальное число зон (слот 0 зарезервирован под каталог).
    #[must_use]
    pub const fn max_zones(self) -> u32 {
        self.max_zones
    }

    /// Жёсткий лимит страниц файла.
    #[must_use]
    pub const fn page_count_max(self) -> u32 {
        self.page_count_max
    }

    /// Лимит chain-страниц на зону.
    #[must_use]
    pub const fn max_root_chain_pages(self) -> u32 {
        self.max_root_chain_pages
    }

    /// Число слотов файловой reader table.
    #[must_use]
    pub const fn reader_slots(self) -> u32 {
        self.reader_slots
    }

    /// Число страниц reader region.
    #[must_use]
    pub const fn reader_pages(self) -> u32 {
        self.reader_pages
    }

    /// Число страниц одной копии root directory.
    #[must_use]
    pub const fn root_dir_pages(self) -> u32 {
        self.root_dir_pages
    }

    /// Страница `LayoutHead` A.
    #[must_use]
    pub const fn page_layout_head_a(self) -> u32 {
        self.page_layout_head_a
    }

    /// Страница `LayoutHead` B.
    #[must_use]
    pub const fn page_layout_head_b(self) -> u32 {
        self.page_layout_head_b
    }

    /// Страница writer registry.
    #[must_use]
    pub const fn page_writer_reg(self) -> u32 {
        self.page_writer_reg
    }

    /// Страница `ALLOC_RECORD` A.
    #[must_use]
    pub const fn page_alloc_record_a(self) -> u32 {
        self.page_alloc_record_a
    }

    /// Страница `ALLOC_RECORD` B.
    #[must_use]
    pub const fn page_alloc_record_b(self) -> u32 {
        self.page_alloc_record_b
    }

    /// Первая страница reader region.
    #[must_use]
    pub const fn page_reader_table(self) -> u32 {
        self.page_reader_table
    }

    /// Первая страница копии A root directory.
    #[must_use]
    pub const fn page_root_dir_a_first(self) -> u32 {
        self.page_root_dir_a_first
    }

    /// Первая страница копии B root directory.
    #[must_use]
    pub const fn page_root_dir_b_first(self) -> u32 {
        self.page_root_dir_b_first
    }

    /// Первая страница данных (chain/buckets/B+tree).
    #[must_use]
    pub const fn page_data_first(self) -> u32 {
        self.page_data_first
    }

    /// Полный размер файла в байтах.
    #[must_use]
    pub const fn file_size(self) -> u64 {
        self.page_count_max as u64 * self.page_size as u64
    }

    /// Смещение страницы в файле.
    ///
    /// # Errors
    ///
    /// `Corrupt(Bounds)` — страница вне `page_count_max`.
    pub fn page_offset(self, page: u32) -> Result<u64, ParallelError> {
        if page >= self.page_count_max {
            return Err(ParallelError::Corrupt {
                kind: crate::parallel::error::V2CorruptKind::Bounds,
                page: Some(page),
            });
        }
        Ok(u64::from(page) * u64::from(self.page_size))
    }

    /// Координаты зоны в root directory.
    ///
    /// # Errors
    ///
    /// `InvalidArgument` — `zone == 0` (каталог) или `zone >= max_zones`.
    pub fn zone_slot(self, zone: u32) -> Result<ZoneSlot, ParallelError> {
        if zone == 0 || zone >= self.max_zones {
            return Err(ParallelError::InvalidArgument { field: "zone_seq" });
        }
        let page_index = zone / ZONES_PER_DIR_PAGE;
        let index_in_page = zone % ZONES_PER_DIR_PAGE;
        let page_a = self
            .page_root_dir_a_first
            .checked_add(page_index)
            .ok_or(ParallelError::InvalidArgument { field: "page_a" })?;
        let page_b = self
            .page_root_dir_b_first
            .checked_add(page_index)
            .ok_or(ParallelError::InvalidArgument { field: "page_b" })?;
        let block_offset =
            index_in_page
                .checked_mul(ROOT_BLOCK_SIZE)
                .ok_or(ParallelError::InvalidArgument {
                    field: "block_offset",
                })?;
        Ok(ZoneSlot {
            page_a,
            page_b,
            block_offset,
        })
    }

    /// Смещение файлового слота reader table.
    ///
    /// # Errors
    ///
    /// `InvalidArgument` — слот вне региона.
    pub fn reader_slot_offset(self, slot: u32) -> Result<(u32, u64), ParallelError> {
        if slot >= self.reader_slots {
            return Err(ParallelError::InvalidArgument {
                field: "reader_slot",
            });
        }
        let usable = self.page_size.checked_sub(READER_PAGE_DESC_SIZE).ok_or(
            ParallelError::Unsupported {
                what: "page_size smaller than reader page descriptor",
            },
        )?;
        let slots_per_page = usable / READER_SLOT_SIZE_V2;
        if slots_per_page == 0 {
            return Err(ParallelError::Unsupported {
                what: "reader slot does not fit a page",
            });
        }
        let page = self.page_reader_table + slot / slots_per_page;
        let index = slot % slots_per_page;
        let offset = u64::from(page) * u64::from(self.page_size)
            + u64::from(READER_PAGE_DESC_SIZE)
            + u64::from(index) * u64::from(READER_SLOT_SIZE_V2);
        Ok((page, offset))
    }
}

/// Число страниц reader region для заданного размера страницы.
///
/// # Errors
///
/// `Unsupported` — страница меньше дескриптора или не вмещает слот.
pub fn reader_pages(page_size: u32, reader_slots: u32) -> Result<u32, ParallelError> {
    if page_size != PAGE_SIZE_V2 {
        return Err(ParallelError::Unsupported {
            what: "page_size (phase A supports 4096 only)",
        });
    }
    let usable =
        page_size
            .checked_sub(READER_PAGE_DESC_SIZE)
            .ok_or(ParallelError::Unsupported {
                what: "page_size smaller than reader page descriptor",
            })?;
    let total =
        reader_slots
            .checked_mul(READER_SLOT_SIZE_V2)
            .ok_or(ParallelError::InvalidArgument {
                field: "reader_slots",
            })?;
    Ok(total.div_ceil(usable))
}

/// Число страниц одной копии root directory: `ceil(max_zones / 16)`.
///
/// # Errors
///
/// `InvalidArgument` — `max_zones == 0`.
pub fn root_dir_pages_per_region(max_zones: u32) -> Result<u32, ParallelError> {
    if max_zones == 0 {
        return Err(ParallelError::InvalidArgument { field: "max_zones" });
    }
    Ok(max_zones.div_ceil(ZONES_PER_DIR_PAGE))
}
