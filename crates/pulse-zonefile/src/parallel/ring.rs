//! Root ring 4×2, chain-страницы и низкоуровневые чтения/записи (§4).
//!
//! Ring-страницы не имеют заголовка: валидность определяется CRC `RootEntry` и
//! `owner_zone`. Chain-страницы имутабельны и содержат одну 64-байтовую запись.

use std::fs::File;
use std::os::unix::fs::FileExt;

use crate::parallel::consts::{PAGE_SIZE_V2, ROOT_ENTRY_SIZE, ROOT_VERSIONS};
use crate::parallel::error::{ParallelError, V2CorruptKind};
use crate::parallel::geometry::{Geometry, ZoneSlot};
use crate::parallel::layout::ChainPage;
use crate::parallel::root::RootEntry;

/// Состояние пары копий A/B в одной ячейке ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyState {
    /// Обе копии невалидны.
    Empty,
    /// Валидна только A.
    OnlyA,
    /// Валидна только B.
    OnlyB,
    /// Обе валидны и совпадают по версии.
    BothSame,
    /// Обе валидны, но версии разошлись (крах между записями).
    BothDiverged,
}

/// Пара копий одной версии ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CellView {
    /// Копия A.
    pub a: Option<RootEntry>,
    /// Копия B.
    pub b: Option<RootEntry>,
    /// Состояние пары.
    pub state: CopyState,
    /// Запись с максимальной версией (tie-break — копия A).
    pub best: Option<RootEntry>,
}

impl CellView {
    fn new(a: Option<RootEntry>, b: Option<RootEntry>) -> Self {
        let best = match (a, b) {
            (Some(left), Some(right)) => {
                if left.version >= right.version {
                    Some(left)
                } else {
                    Some(right)
                }
            }
            (Some(left), None) => Some(left),
            (None, Some(right)) => Some(right),
            (None, None) => None,
        };
        let state = match (a, b) {
            (None, None) => CopyState::Empty,
            (Some(_), None) => CopyState::OnlyA,
            (None, Some(_)) => CopyState::OnlyB,
            (Some(left), Some(right)) => {
                if left.version == right.version {
                    CopyState::BothSame
                } else {
                    CopyState::BothDiverged
                }
            }
        };
        Self { a, b, state, best }
    }
}

/// Просмотр всех 4 ячеек зоны в ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotView {
    /// Зона.
    pub zone: u32,
    /// Координаты зоны.
    pub slot: ZoneSlot,
    /// Ячейки `version % 4`.
    pub cells: [CellView; ROOT_VERSIONS as usize],
}

impl SlotView {
    /// Запись с максимальной валидной версией (ring-голова).
    #[must_use]
    pub fn best(&self) -> Option<RootEntry> {
        self.cells
            .iter()
            .filter_map(|cell| cell.best)
            .max_by_key(|entry| entry.version)
    }

    /// Лучшая валидная запись в ячейке группы `g`.
    #[must_use]
    pub fn cell(&self, g: usize) -> Option<RootEntry> {
        self.cells.get(g).and_then(|cell| cell.best)
    }
}

/// Низкоуровневый доступ к root ring и chain-страницам.
pub(crate) struct Ring<'a> {
    file: &'a File,
    geometry: &'a Geometry,
}

impl<'a> Ring<'a> {
    pub(crate) fn new(file: &'a File, geometry: &'a Geometry) -> Self {
        Self { file, geometry }
    }

    pub(crate) fn read_page(&self, page: u32) -> Result<Vec<u8>, ParallelError> {
        let offset = self.geometry.page_offset(page)?;
        let mut buffer = vec![0_u8; PAGE_SIZE_V2 as usize];
        self.file.read_exact_at(&mut buffer, offset)?;
        Ok(buffer)
    }

    pub(crate) fn write_page(&self, page: u32, data: &[u8]) -> Result<(), ParallelError> {
        if data.len() < PAGE_SIZE_V2 as usize {
            return Err(ParallelError::InvalidArgument {
                field: "page payload",
            });
        }
        let offset = self.geometry.page_offset(page)?;
        let payload = data
            .get(..PAGE_SIZE_V2 as usize)
            .ok_or(ParallelError::InvalidArgument {
                field: "page payload",
            })?;
        self.file.write_all_at(payload, offset)?;
        Ok(())
    }

    /// Читает все 4 ячейки зоны из обеих копий.
    pub(crate) fn read_slot(&self, zone: u32) -> Result<SlotView, ParallelError> {
        let slot = self.geometry.zone_slot(zone)?;
        self.read_slot_at(slot, zone)
    }

    /// Читает слот по готовым координатам (нужно каталогу `zone = 0`).
    pub(crate) fn read_slot_at(
        &self,
        slot: ZoneSlot,
        zone: u32,
    ) -> Result<SlotView, ParallelError> {
        let page_a = self.read_page(slot.page_a)?;
        let page_b = self.read_page(slot.page_b)?;
        let mut cells = [CellView::new(None, None); ROOT_VERSIONS as usize];
        for (g, cell) in cells.iter_mut().enumerate() {
            let off = slot.block_offset as usize + g * ROOT_ENTRY_SIZE as usize;
            let a_raw = page_a.get(off..off + ROOT_ENTRY_SIZE as usize);
            let b_raw = page_b.get(off..off + ROOT_ENTRY_SIZE as usize);
            let a = a_raw.and_then(RootEntry::decode);
            let b = b_raw.and_then(RootEntry::decode);
            if let Some(entry) = a {
                if entry.owner_zone != zone {
                    return Err(ParallelError::Corrupt {
                        kind: V2CorruptKind::ForeignOwner,
                        page: Some(slot.page_a),
                    });
                }
                if entry.version % u64::from(ROOT_VERSIONS) != g as u64 {
                    return Err(ParallelError::Corrupt {
                        kind: V2CorruptKind::RingSlotMismatch,
                        page: Some(slot.page_a),
                    });
                }
            }
            if let Some(entry) = b {
                if entry.owner_zone != zone {
                    return Err(ParallelError::Corrupt {
                        kind: V2CorruptKind::ForeignOwner,
                        page: Some(slot.page_b),
                    });
                }
                if entry.version % u64::from(ROOT_VERSIONS) != g as u64 {
                    return Err(ParallelError::Corrupt {
                        kind: V2CorruptKind::RingSlotMismatch,
                        page: Some(slot.page_b),
                    });
                }
            }
            *cell = CellView::new(a, b);
        }
        Ok(SlotView { zone, slot, cells })
    }

    /// Читает всю страницу-копию root directory в буфер.
    pub(crate) fn read_dir_page(&self, page: u32) -> Result<Vec<u8>, ParallelError> {
        self.read_page(page)
    }

    /// Пишет одну 64-байтовую ячейку ring.
    pub(crate) fn write_cell(
        &self,
        page: u32,
        offset: usize,
        record: &RootEntry,
    ) -> Result<(), ParallelError> {
        if offset + ROOT_ENTRY_SIZE as usize > PAGE_SIZE_V2 as usize {
            return Err(ParallelError::InvalidArgument {
                field: "cell offset",
            });
        }
        let page_offset = self.geometry.page_offset(page)?;
        let raw = record.encode();
        self.file.write_all_at(&raw, page_offset + offset as u64)?;
        Ok(())
    }

    /// Читает chain-страницу; `None` — torn/невалидная (конец chain).
    pub(crate) fn read_chain(&self, page: u32) -> Result<Option<ChainPage>, ParallelError> {
        if page < self.geometry.page_data_first() || page >= self.geometry.page_count_max() {
            return Ok(None);
        }
        let raw = self.read_page(page)?;
        Ok(ChainPage::decode(&raw, page))
    }

    /// Пишет chain-страницу.
    pub(crate) fn write_chain(&self, chain: &ChainPage) -> Result<(), ParallelError> {
        if chain.page_no < self.geometry.page_data_first()
            || chain.page_no >= self.geometry.page_count_max()
        {
            return Err(ParallelError::InvalidArgument {
                field: "chain page",
            });
        }
        let raw = chain.encode();
        self.write_page(chain.page_no, &raw)
    }
}

/// Проверяет, что запись владеет слотом (для recovery).
pub(crate) fn record_matches_slot(record: &RootEntry, zone: u32, group: usize) -> bool {
    record.owner_zone == zone && record.version % u64::from(ROOT_VERSIONS) == group as u64
}
