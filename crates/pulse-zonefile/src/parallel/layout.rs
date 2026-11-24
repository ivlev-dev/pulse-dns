//! Структуры пролога v2.0: superblock, `LayoutHead`, `ALLOC_RECORD`, writer
//! registry и файловый слот reader table.
//!
//! Раскладка — `docs/spec/parallel-writes-v2.md` §3.4, §5.2, §10.1. Все записи
//! кодируются в фиксированные little-endian буферы; CRC считается по всей
//! записи с обнулённым полем CRC.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::checksum::page_crc32c;
use crate::consts::{CHECKSUM_ALGO_CRC32C, ENDIANNESS_LITTLE, SUPERBLOCK_RECORD_SIZE};
use crate::parallel::consts::{
    ALLOC_OFF_CRC, ALLOC_OFF_EPOCH_HINT, ALLOC_OFF_FLAGS, ALLOC_OFF_LEADER_TERM,
    ALLOC_OFF_PAGE_LIMIT, ALLOC_OFF_PAGE_NO, ALLOC_OFF_PAGE_TYPE, ALLOC_OFF_RESERVED,
    ALLOC_OFF_SEQ, ALLOC_OFF_TXN_LIMIT, ALLOC_OFF_VERSION, ALLOC_OFF_WRITE_NS,
    ALLOC_OFF_WRITER_PID, ALLOC_RECORD_SEQ_FIRST, ALLOC_RECORD_SIZE, ALLOC_RECORD_VERSION,
    CHAIN_OFF_CRC, CHAIN_OFF_ENTRY, CHAIN_OFF_EVICTED_TXN, CHAIN_OFF_FLAGS, CHAIN_OFF_OWNER,
    CHAIN_OFF_PAGE_NO, CHAIN_OFF_PAGE_TYPE, CHAIN_OFF_RESERVED, CHAIN_OFF_RESERVED0,
    CHAIN_OFF_VERSION, CHAIN_VERSION, FORMAT_VERSION_MAJOR_V2, FORMAT_VERSION_MINOR_V2,
    FRS_OFF_EPOCH, FRS_OFF_FLAGS, FRS_OFF_HEARTBEAT_NS, FRS_OFF_KIND, FRS_OFF_N_PINS,
    FRS_OFF_OWNER_TOKEN, FRS_OFF_PAD, FRS_OFF_PINS, FRS_OFF_RESERVED, LAYOUT_HEAD_MAGIC,
    LAYOUT_HEAD_RECORD_SIZE, LAYOUT_HEAD_VERSION, LEADER_TERM_M1, LH_OFF_ALLOC_A, LH_OFF_ALLOC_B,
    LH_OFF_CRC, LH_OFF_CREATED_NS, LH_OFF_DATA_FIRST, LH_OFF_FEATURES, LH_OFF_FLAGS,
    LH_OFF_GENERATION, LH_OFF_LAYOUT_A, LH_OFF_LAYOUT_B, LH_OFF_LAYOUT_SEQ, LH_OFF_LEADER_TERM,
    LH_OFF_MAGIC, LH_OFF_MAX_CHAIN, LH_OFF_MAX_ZONES, LH_OFF_PAGE_COUNT_MAX, LH_OFF_PAGE_NO,
    LH_OFF_PAGE_SIZE, LH_OFF_PAGE_TYPE, LH_OFF_READER_LEN, LH_OFF_READER_OFF, LH_OFF_READER_SLOTS,
    LH_OFF_READER_TABLE, LH_OFF_RESERVED, LH_OFF_ROOT_DIR_A_FIRST, LH_OFF_ROOT_DIR_B_FIRST,
    LH_OFF_ROOT_DIR_PAGES, LH_OFF_VERSION, LH_OFF_WRITER_REG, MAGIC_V2, PAGE_TYPE_ALLOC_RECORD,
    PAGE_TYPE_LAYOUT_HEAD, PAGE_TYPE_ROOT_CHAIN, PAGE_TYPE_WRITER_REG, READER_PIN_SIZE,
    READER_PINS, READER_SLOT_SIZE_V2, REG_OFF_CRC, REG_OFF_FLAGS, REG_OFF_HEARTBEAT_NS,
    REG_OFF_LEADER_TERM, REG_OFF_PAGE_NO, REG_OFF_PAGE_TYPE, REG_OFF_RESERVED, REG_OFF_VERSION,
    REG_OFF_WRITER_COUNT, REG_OFF_WRITER_PID, ROOT_ENTRY_SIZE, SB2_OFF_ALLOC_A, SB2_OFF_ALLOC_B,
    SB2_OFF_CHECKSUM_ALGO, SB2_OFF_COPY, SB2_OFF_CRC, SB2_OFF_CREATED_NS, SB2_OFF_DATA_FIRST,
    SB2_OFF_ENDIANNESS, SB2_OFF_FEATURE_REQUIRED, SB2_OFF_LAYOUT_A, SB2_OFF_LAYOUT_B,
    SB2_OFF_LAYOUT_VERSION, SB2_OFF_MAGIC, SB2_OFF_MAX_CHAIN, SB2_OFF_MAX_ZONES,
    SB2_OFF_PAGE_COUNT_MAX, SB2_OFF_PAGE_SIZE, SB2_OFF_READER_SLOTS, SB2_OFF_READER_TABLE,
    SB2_OFF_RESERVED, SB2_OFF_ROOT_DIR_FIRST, SB2_OFF_SYNC_MODE, SB2_OFF_UUID,
    SB2_OFF_VERSION_MAJOR, SB2_OFF_VERSION_MINOR, SB2_OFF_WRITER_REG,
};
use crate::parallel::error::ParallelError;
use crate::parallel::geometry::Geometry;
use crate::parallel::root::RootEntry;

/// Режим durability в superblock v2 (фаза A пишет только `Sync`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SyncModeV2 {
    /// Данные и корни fsync'нуты.
    #[default]
    Sync,
    /// Данные fsync'нуты, корни — нет (фаза B).
    Flush,
    /// Без fsync (фаза B).
    Memory,
}

impl SyncModeV2 {
    /// Дисковое значение.
    #[must_use]
    pub const fn to_disk(self) -> u8 {
        match self {
            Self::Sync => 0,
            Self::Flush => 1,
            Self::Memory => 2,
        }
    }

    /// Разбор дискового значения.
    #[must_use]
    pub const fn from_disk(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Sync),
            1 => Some(Self::Flush),
            2 => Some(Self::Memory),
            _ => None,
        }
    }

    /// Класс durability: `Memory < Flush < Sync`.
    #[must_use]
    pub const fn durability_rank(self) -> u8 {
        match self {
            Self::Memory => 0,
            Self::Flush => 1,
            Self::Sync => 2,
        }
    }

    /// Эффективный режим файла при `durable_txn_limit` (§7.2).
    ///
    /// После первого durable-барьера (`DT > 1`: `Sync`-группа или `sync()`)
    /// файл липко ведёт себя как [`SyncModeV2::Sync`]: запись слабее запрещена,
    /// иначе recovery доверял бы durable-водоразделу, за которым остались
    /// несинхронизированные страницы.
    #[must_use]
    pub const fn effective_mode(self, durable_txn: u64) -> Self {
        if durable_txn > 1 { Self::Sync } else { self }
    }

    /// Проверяет, что запрошенный режим не слабее эффективного.
    ///
    /// # Errors
    ///
    /// [`ParallelError::DurabilityBelowFileMode`], если `requested` слабее
    /// [`SyncModeV2::effective_mode`].
    pub fn check_commit(
        self,
        durable_txn: u64,
        requested: Self,
    ) -> Result<(), crate::parallel::error::ParallelError> {
        if requested.durability_rank() < self.effective_mode(durable_txn).durability_rank() {
            return Err(
                crate::parallel::error::ParallelError::DurabilityBelowFileMode {
                    requested,
                    effective: self.effective_mode(durable_txn),
                },
            );
        }
        Ok(())
    }
}

/// Superblock v2 (страницы 0 и 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuperblockV2 {
    /// Магия.
    pub magic: [u8; 8],
    /// Мажорная версия.
    pub version_major: u16,
    /// Минорная версия.
    pub version_minor: u16,
    /// Размер страницы.
    pub page_size: u32,
    /// Жёсткий лимит страниц.
    pub page_count_max: u32,
    /// Обязательные feature-биты (в v2.0 — 0).
    pub feature_required: u64,
    /// Номер копии: 0 = A, 1 = B.
    pub copy: u8,
    /// CRC-32C всей записи с обнулённым полем.
    pub crc32c: u32,
    /// UUID инстанса.
    pub instance_uuid: [u8; 16],
    /// Время создания, unix ns.
    pub created_unix_ns: u64,
    /// Страница `LayoutHead` A.
    pub page_layout_head_a: u32,
    /// Страница `LayoutHead` B.
    pub page_layout_head_b: u32,
    /// Страница writer registry.
    pub page_writer_reg: u32,
    /// Страница `ALLOC_RECORD` A.
    pub page_alloc_record_a: u32,
    /// Страница `ALLOC_RECORD` B.
    pub page_alloc_record_b: u32,
    /// Первая страница reader region.
    pub page_reader_table: u32,
    /// Первая страница root directory.
    pub page_root_dir_first: u32,
    /// Первая страница данных.
    pub page_data_first: u32,
    /// Максимальное число зон.
    pub max_zones: u32,
    /// Лимит chain-страниц на зону.
    pub max_root_chain_pages: u32,
    /// Число слотов reader region.
    pub reader_slots: u32,
    /// Режим durability.
    pub sync_mode: SyncModeV2,
    /// Версия раскладки.
    pub layout_version: u8,
}

impl SuperblockV2 {
    /// Создаёт superblock для новой геометрии.
    #[must_use]
    pub fn for_geometry(
        geometry: Geometry,
        copy: u8,
        uuid: [u8; 16],
        sync_mode: SyncModeV2,
    ) -> Self {
        Self {
            magic: MAGIC_V2,
            version_major: FORMAT_VERSION_MAJOR_V2,
            version_minor: FORMAT_VERSION_MINOR_V2,
            page_size: geometry.page_size(),
            page_count_max: geometry.page_count_max(),
            feature_required: 0,
            copy,
            crc32c: 0,
            instance_uuid: uuid,
            created_unix_ns: unix_now_ns(),
            page_layout_head_a: geometry.page_layout_head_a(),
            page_layout_head_b: geometry.page_layout_head_b(),
            page_writer_reg: geometry.page_writer_reg(),
            page_alloc_record_a: geometry.page_alloc_record_a(),
            page_alloc_record_b: geometry.page_alloc_record_b(),
            page_reader_table: geometry.page_reader_table(),
            page_root_dir_first: geometry.page_root_dir_a_first(),
            page_data_first: geometry.page_data_first(),
            max_zones: geometry.max_zones(),
            max_root_chain_pages: geometry.max_root_chain_pages(),
            reader_slots: geometry.reader_slots(),
            sync_mode,
            layout_version: 1,
        }
    }

    /// Кодирует запись в 4096 байт.
    #[must_use]
    pub fn encode(&self) -> [u8; SUPERBLOCK_RECORD_SIZE as usize] {
        let mut raw = [0_u8; SUPERBLOCK_RECORD_SIZE as usize];
        put(&mut raw, SB2_OFF_MAGIC, &self.magic);
        put_u16(&mut raw, SB2_OFF_VERSION_MAJOR, self.version_major);
        put_u16(&mut raw, SB2_OFF_VERSION_MINOR, self.version_minor);
        put_u32(&mut raw, SB2_OFF_PAGE_SIZE, self.page_size);
        put_u32(&mut raw, SB2_OFF_PAGE_COUNT_MAX, self.page_count_max);
        put_u64(&mut raw, SB2_OFF_FEATURE_REQUIRED, self.feature_required);
        put_u16(&mut raw, SB2_OFF_CHECKSUM_ALGO, CHECKSUM_ALGO_CRC32C);
        put_u8(&mut raw, SB2_OFF_ENDIANNESS, ENDIANNESS_LITTLE);
        put_u8(&mut raw, SB2_OFF_COPY, self.copy);
        put(&mut raw, SB2_OFF_UUID, &self.instance_uuid);
        put_u64(&mut raw, SB2_OFF_CREATED_NS, self.created_unix_ns);
        put_u32(&mut raw, SB2_OFF_LAYOUT_A, self.page_layout_head_a);
        put_u32(&mut raw, SB2_OFF_LAYOUT_B, self.page_layout_head_b);
        put_u32(&mut raw, SB2_OFF_WRITER_REG, self.page_writer_reg);
        put_u32(&mut raw, SB2_OFF_ALLOC_A, self.page_alloc_record_a);
        put_u32(&mut raw, SB2_OFF_ALLOC_B, self.page_alloc_record_b);
        put_u32(&mut raw, SB2_OFF_READER_TABLE, self.page_reader_table);
        put_u32(&mut raw, SB2_OFF_ROOT_DIR_FIRST, self.page_root_dir_first);
        put_u32(&mut raw, SB2_OFF_DATA_FIRST, self.page_data_first);
        put_u32(&mut raw, SB2_OFF_MAX_ZONES, self.max_zones);
        put_u32(&mut raw, SB2_OFF_MAX_CHAIN, self.max_root_chain_pages);
        put_u32(&mut raw, SB2_OFF_READER_SLOTS, self.reader_slots);
        put_u8(&mut raw, SB2_OFF_SYNC_MODE, self.sync_mode.to_disk());
        put_u8(&mut raw, SB2_OFF_LAYOUT_VERSION, self.layout_version);
        if let Some(crc) = page_crc32c(&raw, SB2_OFF_CRC) {
            put_u32(&mut raw, SB2_OFF_CRC, crc);
        }
        raw
    }

    /// Декодирует и валидирует запись.
    #[must_use]
    pub fn decode(raw: &[u8]) -> Option<Self> {
        let record = raw.get(..SUPERBLOCK_RECORD_SIZE as usize)?;
        let stored = get_u32(record, SB2_OFF_CRC)?;
        if page_crc32c(record, SB2_OFF_CRC)? != stored {
            return None;
        }
        let magic: [u8; 8] = record
            .get(SB2_OFF_MAGIC..SB2_OFF_MAGIC + 8)?
            .try_into()
            .ok()?;
        if magic != MAGIC_V2 {
            return None;
        }
        if get_u16(record, SB2_OFF_CHECKSUM_ALGO)? != CHECKSUM_ALGO_CRC32C {
            return None;
        }
        if get_u8(record, SB2_OFF_ENDIANNESS)? != ENDIANNESS_LITTLE {
            return None;
        }
        if record
            .get(SB2_OFF_RESERVED..)?
            .iter()
            .any(|byte| *byte != 0)
        {
            return None;
        }
        let uuid: [u8; 16] = record
            .get(SB2_OFF_UUID..SB2_OFF_UUID + 16)?
            .try_into()
            .ok()?;
        Some(Self {
            magic,
            version_major: get_u16(record, SB2_OFF_VERSION_MAJOR)?,
            version_minor: get_u16(record, SB2_OFF_VERSION_MINOR)?,
            page_size: get_u32(record, SB2_OFF_PAGE_SIZE)?,
            page_count_max: get_u32(record, SB2_OFF_PAGE_COUNT_MAX)?,
            feature_required: get_u64(record, SB2_OFF_FEATURE_REQUIRED)?,
            copy: get_u8(record, SB2_OFF_COPY)?,
            crc32c: stored,
            instance_uuid: uuid,
            created_unix_ns: get_u64(record, SB2_OFF_CREATED_NS)?,
            page_layout_head_a: get_u32(record, SB2_OFF_LAYOUT_A)?,
            page_layout_head_b: get_u32(record, SB2_OFF_LAYOUT_B)?,
            page_writer_reg: get_u32(record, SB2_OFF_WRITER_REG)?,
            page_alloc_record_a: get_u32(record, SB2_OFF_ALLOC_A)?,
            page_alloc_record_b: get_u32(record, SB2_OFF_ALLOC_B)?,
            page_reader_table: get_u32(record, SB2_OFF_READER_TABLE)?,
            page_root_dir_first: get_u32(record, SB2_OFF_ROOT_DIR_FIRST)?,
            page_data_first: get_u32(record, SB2_OFF_DATA_FIRST)?,
            max_zones: get_u32(record, SB2_OFF_MAX_ZONES)?,
            max_root_chain_pages: get_u32(record, SB2_OFF_MAX_CHAIN)?,
            reader_slots: get_u32(record, SB2_OFF_READER_SLOTS)?,
            sync_mode: SyncModeV2::from_disk(get_u8(record, SB2_OFF_SYNC_MODE)?)?,
            layout_version: get_u8(record, SB2_OFF_LAYOUT_VERSION)?,
        })
    }

    /// Проверяет версию, размер страницы и что геометрия соответствует полям.
    ///
    /// # Errors
    ///
    /// `Unsupported` — версия/страница/feature-биты; `Corrupt` — поля
    /// суперблока не совпадают с `LayoutHead`.
    pub fn verify(&self, geometry: &Geometry, file_size: u64) -> Result<(), ParallelError> {
        if self.version_major != FORMAT_VERSION_MAJOR_V2
            || self.version_minor != FORMAT_VERSION_MINOR_V2
        {
            return Err(ParallelError::Unsupported {
                what: "format version (expected 2.0)",
            });
        }
        if self.page_size != geometry.page_size() {
            return Err(ParallelError::Unsupported {
                what: "page_size (expected 4096)",
            });
        }
        if self.feature_required != 0 {
            return Err(ParallelError::Unsupported {
                what: "required feature bits",
            });
        }
        if self.layout_version != 1 {
            return Err(ParallelError::Unsupported {
                what: "layout version",
            });
        }
        if self.page_count_max != geometry.page_count_max()
            || self.max_zones != geometry.max_zones()
            || self.max_root_chain_pages != geometry.max_root_chain_pages()
            || self.reader_slots != geometry.reader_slots()
            || self.page_layout_head_a != geometry.page_layout_head_a()
            || self.page_layout_head_b != geometry.page_layout_head_b()
            || self.page_writer_reg != geometry.page_writer_reg()
            || self.page_alloc_record_a != geometry.page_alloc_record_a()
            || self.page_alloc_record_b != geometry.page_alloc_record_b()
            || self.page_reader_table != geometry.page_reader_table()
            || self.page_root_dir_first != geometry.page_root_dir_a_first()
            || self.page_data_first != geometry.page_data_first()
        {
            return Err(ParallelError::Corrupt {
                kind: crate::parallel::error::V2CorruptKind::Superblock,
                page: None,
            });
        }
        let expected_size = u64::from(self.page_count_max) * u64::from(self.page_size);
        if file_size < expected_size {
            return Err(ParallelError::Corrupt {
                kind: crate::parallel::error::V2CorruptKind::Truncated,
                page: None,
            });
        }
        Ok(())
    }
}

/// Запись `LayoutHead` (512 Б) — корень раскладки файла.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayoutHead {
    /// Номер страницы (2 или 3).
    pub page_no: u32,
    /// Монотонный `seq` копий.
    pub layout_seq: u64,
    /// Поколение файла.
    pub generation: u64,
    /// Геометрия.
    pub geometry: Geometry,
    /// Время создания, unix ns.
    pub created_unix_ns: u64,
    /// `leader_term` (M1 = 1).
    pub leader_term: u64,
    /// Feature-биты, требуемые для чтения.
    pub feature_required: u64,
}

impl LayoutHead {
    /// Создаёт запись для геометрии.
    #[must_use]
    pub fn for_geometry(
        geometry: Geometry,
        page_no: u32,
        layout_seq: u64,
        generation: u64,
        feature_required: u64,
    ) -> Self {
        Self {
            page_no,
            layout_seq,
            generation,
            geometry,
            created_unix_ns: unix_now_ns(),
            leader_term: LEADER_TERM_M1,
            feature_required,
        }
    }

    /// Кодирует запись в 512 байт.
    #[must_use]
    pub fn encode(&self) -> [u8; LAYOUT_HEAD_RECORD_SIZE as usize] {
        let mut raw = [0_u8; LAYOUT_HEAD_RECORD_SIZE as usize];
        put_u32(&mut raw, LH_OFF_PAGE_TYPE, PAGE_TYPE_LAYOUT_HEAD);
        put_u16(&mut raw, LH_OFF_VERSION, LAYOUT_HEAD_VERSION);
        put_u16(&mut raw, LH_OFF_FLAGS, 0);
        put_u32(&mut raw, LH_OFF_PAGE_NO, self.page_no);
        put_u64(&mut raw, LH_OFF_LAYOUT_SEQ, self.layout_seq);
        put_u64(&mut raw, LH_OFF_GENERATION, self.generation);
        put_u32(&mut raw, LH_OFF_PAGE_SIZE, self.geometry.page_size());
        put_u32(&mut raw, LH_OFF_MAX_ZONES, self.geometry.max_zones());
        put_u32(
            &mut raw,
            LH_OFF_ROOT_DIR_PAGES,
            self.geometry.root_dir_pages(),
        );
        put_u32(
            &mut raw,
            LH_OFF_ROOT_DIR_A_FIRST,
            self.geometry.page_root_dir_a_first(),
        );
        put_u32(
            &mut raw,
            LH_OFF_ROOT_DIR_B_FIRST,
            self.geometry.page_root_dir_b_first(),
        );
        put_u32(
            &mut raw,
            LH_OFF_READER_TABLE,
            self.geometry.page_reader_table(),
        );
        put_u64(
            &mut raw,
            LH_OFF_READER_OFF,
            u64::from(self.geometry.page_reader_table()) * u64::from(self.geometry.page_size()),
        );
        put_u64(
            &mut raw,
            LH_OFF_READER_LEN,
            u64::from(self.geometry.reader_pages()) * u64::from(self.geometry.page_size()),
        );
        put_u32(&mut raw, LH_OFF_DATA_FIRST, self.geometry.page_data_first());
        put_u32(&mut raw, LH_OFF_WRITER_REG, self.geometry.page_writer_reg());
        put_u32(
            &mut raw,
            LH_OFF_ALLOC_A,
            self.geometry.page_alloc_record_a(),
        );
        put_u32(
            &mut raw,
            LH_OFF_ALLOC_B,
            self.geometry.page_alloc_record_b(),
        );
        put_u32(
            &mut raw,
            LH_OFF_LAYOUT_A,
            self.geometry.page_layout_head_a(),
        );
        put_u32(
            &mut raw,
            LH_OFF_LAYOUT_B,
            self.geometry.page_layout_head_b(),
        );
        put_u32(
            &mut raw,
            LH_OFF_MAX_CHAIN,
            self.geometry.max_root_chain_pages(),
        );
        put_u32(&mut raw, LH_OFF_READER_SLOTS, self.geometry.reader_slots());
        put_u32(
            &mut raw,
            LH_OFF_PAGE_COUNT_MAX,
            self.geometry.page_count_max(),
        );
        put_u64(&mut raw, LH_OFF_CREATED_NS, self.created_unix_ns);
        put_u64(&mut raw, LH_OFF_LEADER_TERM, self.leader_term);
        put(&mut raw, LH_OFF_MAGIC, &LAYOUT_HEAD_MAGIC);
        put_u64(&mut raw, LH_OFF_FEATURES, self.feature_required);
        if let Some(crc) = page_crc32c(&raw, LH_OFF_CRC) {
            put_u32(&mut raw, LH_OFF_CRC, crc);
        }
        raw
    }

    /// Декодирует и строго валидирует запись.
    #[must_use]
    pub fn decode(raw: &[u8]) -> Option<Self> {
        let record = raw.get(..LAYOUT_HEAD_RECORD_SIZE as usize)?;
        let stored = get_u32(record, LH_OFF_CRC)?;
        if page_crc32c(record, LH_OFF_CRC)? != stored {
            return None;
        }
        if get_u32(record, LH_OFF_PAGE_TYPE)? != PAGE_TYPE_LAYOUT_HEAD {
            return None;
        }
        if get_u16(record, LH_OFF_VERSION)? != LAYOUT_HEAD_VERSION {
            return None;
        }
        if get_u16(record, LH_OFF_FLAGS)? != 0 {
            return None;
        }
        let magic: [u8; 8] = record
            .get(LH_OFF_MAGIC..LH_OFF_MAGIC + 8)?
            .try_into()
            .ok()?;
        if magic != LAYOUT_HEAD_MAGIC {
            return None;
        }
        if record.get(LH_OFF_RESERVED..)?.iter().any(|byte| *byte != 0) {
            return None;
        }
        let page_no = get_u32(record, LH_OFF_PAGE_NO)?;
        if page_no != crate::parallel::consts::PAGE_LAYOUT_HEAD_A
            && page_no != crate::parallel::consts::PAGE_LAYOUT_HEAD_B
        {
            return None;
        }
        let geometry = Geometry::new(
            get_u32(record, LH_OFF_MAX_ZONES)?,
            get_u32(record, LH_OFF_PAGE_COUNT_MAX)?,
            get_u32(record, LH_OFF_MAX_CHAIN)?,
            get_u32(record, LH_OFF_READER_SLOTS)?,
        )
        .ok()?;
        if get_u32(record, LH_OFF_PAGE_SIZE)? != geometry.page_size()
            || get_u32(record, LH_OFF_ROOT_DIR_PAGES)? != geometry.root_dir_pages()
            || get_u32(record, LH_OFF_ROOT_DIR_A_FIRST)? != geometry.page_root_dir_a_first()
            || get_u32(record, LH_OFF_ROOT_DIR_B_FIRST)? != geometry.page_root_dir_b_first()
            || get_u32(record, LH_OFF_READER_TABLE)? != geometry.page_reader_table()
            || get_u32(record, LH_OFF_DATA_FIRST)? != geometry.page_data_first()
            || get_u32(record, LH_OFF_WRITER_REG)? != geometry.page_writer_reg()
            || get_u32(record, LH_OFF_ALLOC_A)? != geometry.page_alloc_record_a()
            || get_u32(record, LH_OFF_ALLOC_B)? != geometry.page_alloc_record_b()
            || get_u32(record, LH_OFF_LAYOUT_A)? != geometry.page_layout_head_a()
            || get_u32(record, LH_OFF_LAYOUT_B)? != geometry.page_layout_head_b()
            || get_u64(record, LH_OFF_READER_OFF)?
                != u64::from(geometry.page_reader_table()) * u64::from(geometry.page_size())
            || get_u64(record, LH_OFF_READER_LEN)?
                != u64::from(geometry.reader_pages()) * u64::from(geometry.page_size())
        {
            return None;
        }
        let leader_term = get_u64(record, LH_OFF_LEADER_TERM)?;
        if leader_term != LEADER_TERM_M1 {
            return None;
        }
        Some(Self {
            page_no,
            layout_seq: get_u64(record, LH_OFF_LAYOUT_SEQ)?,
            generation: get_u64(record, LH_OFF_GENERATION)?,
            geometry,
            created_unix_ns: get_u64(record, LH_OFF_CREATED_NS)?,
            leader_term,
            feature_required: get_u64(record, LH_OFF_FEATURES)?,
        })
    }

    /// Совпадает ли геометрия двух копий.
    #[must_use]
    pub fn same_geometry(&self, other: &Self) -> bool {
        self.geometry == other.geometry
            && self.feature_required == other.feature_required
            && self.leader_term == other.leader_term
    }
}

/// Запись `ALLOC_RECORD` (256 Б) — durable-барьер аллокатора.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllocRecord {
    /// Номер страницы-носителя (5 или 6).
    pub page_no: u32,
    /// Монотонный `seq`.
    pub seq: u64,
    /// Durable `page_limit` (`DP`).
    pub page_limit: u64,
    /// Durable `txn_limit` (`DT`).
    pub txn_limit: u64,
    /// Время записи, unix ns.
    pub write_unix_ns: u64,
    /// `leader_term` (M1 = 1).
    pub leader_term: u64,
    /// Подсказка `epoch` (диагностика).
    pub epoch_hint: u64,
    /// PID писателя.
    pub writer_pid: u64,
}

impl AllocRecord {
    /// Создаёт запись.
    #[must_use]
    pub const fn new(page_no: u32, seq: u64, page_limit: u64, txn_limit: u64) -> Self {
        Self {
            page_no,
            seq,
            page_limit,
            txn_limit,
            write_unix_ns: 0,
            leader_term: LEADER_TERM_M1,
            epoch_hint: 0,
            writer_pid: 0,
        }
    }

    /// Создаёт первую запись при создании файла.
    #[must_use]
    pub fn initial(page_no: u32, page_limit: u64) -> Self {
        let mut record = Self::new(page_no, ALLOC_RECORD_SEQ_FIRST, page_limit, 1);
        record.write_unix_ns = unix_now_ns();
        record.writer_pid = u64::from(std::process::id());
        record
    }

    /// Кодирует запись в 256 байт.
    #[must_use]
    pub fn encode(&self) -> [u8; ALLOC_RECORD_SIZE as usize] {
        let mut raw = [0_u8; ALLOC_RECORD_SIZE as usize];
        put_u32(&mut raw, ALLOC_OFF_PAGE_TYPE, PAGE_TYPE_ALLOC_RECORD);
        put_u16(&mut raw, ALLOC_OFF_VERSION, ALLOC_RECORD_VERSION);
        put_u16(&mut raw, ALLOC_OFF_FLAGS, 0);
        put_u32(&mut raw, ALLOC_OFF_PAGE_NO, self.page_no);
        put_u64(&mut raw, ALLOC_OFF_SEQ, self.seq);
        put_u64(&mut raw, ALLOC_OFF_PAGE_LIMIT, self.page_limit);
        put_u64(&mut raw, ALLOC_OFF_TXN_LIMIT, self.txn_limit);
        put_u64(&mut raw, ALLOC_OFF_WRITE_NS, self.write_unix_ns);
        put_u64(&mut raw, ALLOC_OFF_LEADER_TERM, self.leader_term);
        put_u64(&mut raw, ALLOC_OFF_EPOCH_HINT, self.epoch_hint);
        put_u64(&mut raw, ALLOC_OFF_WRITER_PID, self.writer_pid);
        let _ = ALLOC_OFF_RESERVED;
        if let Some(crc) = page_crc32c(&raw, ALLOC_OFF_CRC) {
            put_u32(&mut raw, ALLOC_OFF_CRC, crc);
        }
        raw
    }

    /// Декодирует и строго валидирует запись.
    #[must_use]
    pub fn decode(raw: &[u8], reader_page_count_max: u32) -> Option<Self> {
        let record = raw.get(..ALLOC_RECORD_SIZE as usize)?;
        let stored = get_u32(record, ALLOC_OFF_CRC)?;
        if page_crc32c(record, ALLOC_OFF_CRC)? != stored {
            return None;
        }
        if get_u32(record, ALLOC_OFF_PAGE_TYPE)? != PAGE_TYPE_ALLOC_RECORD {
            return None;
        }
        if get_u16(record, ALLOC_OFF_VERSION)? != ALLOC_RECORD_VERSION {
            return None;
        }
        if get_u16(record, ALLOC_OFF_FLAGS)? != 0 {
            return None;
        }
        let page_no = get_u32(record, ALLOC_OFF_PAGE_NO)?;
        if page_no != crate::parallel::consts::PAGE_ALLOC_RECORD_A
            && page_no != crate::parallel::consts::PAGE_ALLOC_RECORD_B
        {
            return None;
        }
        if record
            .get(ALLOC_OFF_RESERVED..)?
            .iter()
            .any(|byte| *byte != 0)
        {
            return None;
        }
        let page_limit = get_u64(record, ALLOC_OFF_PAGE_LIMIT)?;
        if page_limit == 0 || page_limit > u64::from(reader_page_count_max) {
            return None;
        }
        let txn_limit = get_u64(record, ALLOC_OFF_TXN_LIMIT)?;
        if txn_limit == 0 {
            return None;
        }
        if get_u64(record, ALLOC_OFF_LEADER_TERM)? != LEADER_TERM_M1 {
            return None;
        }
        Some(Self {
            page_no,
            seq: get_u64(record, ALLOC_OFF_SEQ)?,
            page_limit,
            txn_limit,
            write_unix_ns: get_u64(record, ALLOC_OFF_WRITE_NS)?,
            leader_term: LEADER_TERM_M1,
            epoch_hint: get_u64(record, ALLOC_OFF_EPOCH_HINT)?,
            writer_pid: get_u64(record, ALLOC_OFF_WRITER_PID)?,
        })
    }
}

/// Writer registry (страница 4). В M1 валиден, `leader_term = 1`, пуст.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriterRegistry {
    /// `leader_term`.
    pub leader_term: u64,
    /// PID лидера (диагностика).
    pub writer_pid: u64,
    /// Heartbeat, unix ns.
    pub heartbeat_unix_ns: u64,
    /// Число зарегистрированных писателей (M1 = 0).
    pub writer_count: u32,
}

impl Default for WriterRegistry {
    fn default() -> Self {
        Self {
            leader_term: LEADER_TERM_M1,
            writer_pid: u64::from(std::process::id()),
            heartbeat_unix_ns: unix_now_ns(),
            writer_count: 0,
        }
    }
}

impl WriterRegistry {
    /// Кодирует страницу registry (4096 Б).
    #[must_use]
    pub fn encode(&self) -> [u8; crate::parallel::consts::PAGE_SIZE_V2 as usize] {
        let mut raw = [0_u8; crate::parallel::consts::PAGE_SIZE_V2 as usize];
        put_u32(&mut raw, REG_OFF_PAGE_TYPE, PAGE_TYPE_WRITER_REG);
        put_u16(&mut raw, REG_OFF_VERSION, 1);
        put_u16(&mut raw, REG_OFF_FLAGS, 0);
        put_u32(
            &mut raw,
            REG_OFF_PAGE_NO,
            crate::parallel::consts::PAGE_WRITER_REG,
        );
        put_u64(&mut raw, REG_OFF_LEADER_TERM, self.leader_term);
        put_u64(&mut raw, REG_OFF_WRITER_PID, self.writer_pid);
        put_u64(&mut raw, REG_OFF_HEARTBEAT_NS, self.heartbeat_unix_ns);
        put_u32(&mut raw, REG_OFF_WRITER_COUNT, self.writer_count);
        let _ = REG_OFF_RESERVED;
        if let Some(crc) = page_crc32c(&raw, REG_OFF_CRC) {
            put_u32(&mut raw, REG_OFF_CRC, crc);
        }
        raw
    }

    /// Декодирует страницу registry.
    #[must_use]
    pub fn decode(raw: &[u8]) -> Option<Self> {
        let page = raw.get(..crate::parallel::consts::PAGE_SIZE_V2 as usize)?;
        let stored = get_u32(page, REG_OFF_CRC)?;
        if page_crc32c(page, REG_OFF_CRC)? != stored {
            return None;
        }
        if get_u32(page, REG_OFF_PAGE_TYPE)? != PAGE_TYPE_WRITER_REG
            || get_u16(page, REG_OFF_VERSION)? != 1
            || get_u16(page, REG_OFF_FLAGS)? != 0
            || get_u32(page, REG_OFF_PAGE_NO)? != crate::parallel::consts::PAGE_WRITER_REG
        {
            return None;
        }
        if page.get(REG_OFF_RESERVED..)?.iter().any(|byte| *byte != 0) {
            return None;
        }
        Some(Self {
            leader_term: get_u64(page, REG_OFF_LEADER_TERM)?,
            writer_pid: get_u64(page, REG_OFF_WRITER_PID)?,
            heartbeat_unix_ns: get_u64(page, REG_OFF_HEARTBEAT_NS)?,
            writer_count: get_u32(page, REG_OFF_WRITER_COUNT)?,
        })
    }
}

/// Один пин зоны в файловом слоте reader table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FilePin {
    /// `zone_seq`.
    pub zone_seq: u32,
    /// `version` (`txn` коммита).
    pub version: u64,
}

/// Файловый слот reader table v2 (128 Б).
///
/// Фаза A не пишет и не читает reader region (пины живут только в памяти), но
/// раскладка нужна для `fsck`/golden и совместимости с фазой B.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileReaderSlot {
    /// `pid << 32 | incarnation`.
    pub owner_token: u64,
    /// EPOCH-значение для `kind = EPOCH`.
    pub epoch: u64,
    /// Число активных пинов (0..=6).
    pub n_pins: u16,
    /// 0 = EPOCH, 1 = ZONE.
    pub kind: u8,
    /// Флаги слота.
    pub flags: u8,
    /// Heartbeat, unix ns.
    pub heartbeat_unix_ns: u64,
    /// Пины зон.
    pub pins: [FilePin; READER_PINS],
}

impl FileReaderSlot {
    /// Кодирует слот в 128 байт.
    #[must_use]
    pub fn encode(&self) -> [u8; READER_SLOT_SIZE_V2 as usize] {
        let mut raw = [0_u8; READER_SLOT_SIZE_V2 as usize];
        put_u64(&mut raw, FRS_OFF_OWNER_TOKEN, self.owner_token);
        put_u64(&mut raw, FRS_OFF_EPOCH, self.epoch);
        put_u16(&mut raw, FRS_OFF_N_PINS, self.n_pins);
        put_u8(&mut raw, FRS_OFF_KIND, self.kind);
        put_u8(&mut raw, FRS_OFF_FLAGS, self.flags);
        put_u32(&mut raw, FRS_OFF_PAD, 0);
        put_u64(&mut raw, FRS_OFF_HEARTBEAT_NS, self.heartbeat_unix_ns);
        for (index, pin) in self.pins.iter().enumerate() {
            let off = FRS_OFF_PINS + index * READER_PIN_SIZE as usize;
            put_u32(&mut raw, off, pin.zone_seq);
            put_u32(&mut raw, off + 4, 0);
            put_u64(&mut raw, off + 8, pin.version);
        }
        let _ = FRS_OFF_RESERVED;
        raw
    }

    /// Декодирует слот.
    #[must_use]
    pub fn decode(raw: &[u8]) -> Option<Self> {
        let record = raw.get(..READER_SLOT_SIZE_V2 as usize)?;
        if record
            .get(FRS_OFF_RESERVED..)?
            .iter()
            .any(|byte| *byte != 0)
        {
            return None;
        }
        let n_pins = get_u16(record, FRS_OFF_N_PINS)?;
        if usize::from(n_pins) > READER_PINS {
            return None;
        }
        if get_u32(record, FRS_OFF_PAD)? != 0 {
            return None;
        }
        let mut pins = [FilePin::default(); READER_PINS];
        for (index, pin) in pins.iter_mut().enumerate() {
            let off = FRS_OFF_PINS + index * READER_PIN_SIZE as usize;
            if get_u32(record, off + 4)? != 0 {
                return None;
            }
            *pin = FilePin {
                zone_seq: get_u32(record, off)?,
                version: get_u64(record, off + 8)?,
            };
        }
        let kind = get_u8(record, FRS_OFF_KIND)?;
        if kind > 1 {
            return None;
        }
        Some(Self {
            owner_token: get_u64(record, FRS_OFF_OWNER_TOKEN)?,
            epoch: get_u64(record, FRS_OFF_EPOCH)?,
            n_pins,
            kind,
            flags: get_u8(record, FRS_OFF_FLAGS)?,
            heartbeat_unix_ns: get_u64(record, FRS_OFF_HEARTBEAT_NS)?,
            pins,
        })
    }
}

/// Одна chain-страница (`PAGE_TYPE_ROOT_CHAIN = 11`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainPage {
    /// Собственный номер страницы.
    pub page_no: u32,
    /// Зона-владелец.
    pub owner_zone: u32,
    /// `txn` вытеснения (диагностика).
    pub evicted_txn: u64,
    /// Вытесненная запись; её `prev_record` → предыдущая chain-страница.
    pub entry: RootEntry,
}

impl ChainPage {
    /// Кодирует страницу 4096 Б.
    #[must_use]
    pub fn encode(&self) -> [u8; crate::parallel::consts::PAGE_SIZE_V2 as usize] {
        let mut raw = [0_u8; crate::parallel::consts::PAGE_SIZE_V2 as usize];
        put_u32(&mut raw, CHAIN_OFF_PAGE_TYPE, PAGE_TYPE_ROOT_CHAIN);
        put_u16(&mut raw, CHAIN_OFF_VERSION, CHAIN_VERSION);
        put_u16(&mut raw, CHAIN_OFF_FLAGS, 0);
        put_u32(&mut raw, CHAIN_OFF_PAGE_NO, self.page_no);
        // +12: crc32c MUST 0 — страница неизменяема, валидность даёт CRC записи.
        put_u32(&mut raw, CHAIN_OFF_CRC, 0);
        put_u32(&mut raw, CHAIN_OFF_OWNER, self.owner_zone);
        put_u32(&mut raw, CHAIN_OFF_RESERVED0, 0);
        put_u64(&mut raw, CHAIN_OFF_EVICTED_TXN, self.evicted_txn);
        put(&mut raw, CHAIN_OFF_ENTRY, &self.entry.encode());
        let _ = CHAIN_OFF_RESERVED;
        raw
    }

    /// Декодирует и валидирует страницу.
    ///
    /// `None` — torn/чужая/невалидная страница (конец chain, не паника).
    #[must_use]
    pub fn decode(raw: &[u8], expected_page: u32) -> Option<Self> {
        let page = raw.get(..crate::parallel::consts::PAGE_SIZE_V2 as usize)?;
        if get_u32(page, CHAIN_OFF_PAGE_TYPE)? != PAGE_TYPE_ROOT_CHAIN
            || get_u16(page, CHAIN_OFF_VERSION)? != CHAIN_VERSION
            || get_u16(page, CHAIN_OFF_FLAGS)? != 0
            || get_u32(page, CHAIN_OFF_PAGE_NO)? != expected_page
            || get_u32(page, CHAIN_OFF_CRC)? != 0
            || get_u32(page, CHAIN_OFF_RESERVED0)? != 0
        {
            return None;
        }
        let owner_zone = get_u32(page, CHAIN_OFF_OWNER)?;
        let entry = RootEntry::decode(
            page.get(CHAIN_OFF_ENTRY..CHAIN_OFF_ENTRY + ROOT_ENTRY_SIZE as usize)?,
        )?;
        if entry.owner_zone != owner_zone {
            return None;
        }
        if entry.prev_record != 0 && entry.prev_record >= expected_page {
            // Цепочка только назад: новая chain-страница всегда имеет больший
            // PageId, чем вытесненная (bump-аллокатор).
            return None;
        }
        if page
            .get(CHAIN_OFF_RESERVED..)?
            .iter()
            .any(|byte| *byte != 0)
        {
            return None;
        }
        Some(Self {
            page_no: expected_page,
            owner_zone,
            evicted_txn: get_u64(page, CHAIN_OFF_EVICTED_TXN)?,
            entry,
        })
    }
}

/// Новый UUID инстанса.
#[must_use]
pub fn new_instance_uuid() -> [u8; 16] {
    // UUID v4 без внешней зависимости: PID + время + адрес стека.
    let now = unix_now_ns();
    let pid = u64::from(std::process::id());
    let mut uuid = [0_u8; 16];
    uuid[..8].copy_from_slice(&now.to_le_bytes());
    uuid[8..].copy_from_slice(&(pid ^ now.rotate_left(17)).to_le_bytes());
    uuid[6] = (uuid[6] & 0x0F) | 0x40;
    uuid[8] = (uuid[8] & 0x3F) | 0x80;
    uuid
}

fn unix_now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
        })
}

fn get_u8(data: &[u8], off: usize) -> Option<u8> {
    data.get(off).copied()
}

fn get_u16(data: &[u8], off: usize) -> Option<u16> {
    let bytes: [u8; 2] = data.get(off..off + 2)?.try_into().ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn get_u32(data: &[u8], off: usize) -> Option<u32> {
    let bytes: [u8; 4] = data.get(off..off + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn get_u64(data: &[u8], off: usize) -> Option<u64> {
    let bytes: [u8; 8] = data.get(off..off + 8)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

fn put(data: &mut [u8], off: usize, value: &[u8]) {
    if let Some(span) = data.get_mut(off..off + value.len()) {
        span.copy_from_slice(value);
    }
}

fn put_u8(data: &mut [u8], off: usize, value: u8) {
    put(data, off, &[value]);
}

fn put_u16(data: &mut [u8], off: usize, value: u16) {
    put(data, off, &value.to_le_bytes());
}

fn put_u32(data: &mut [u8], off: usize, value: u32) {
    put(data, off, &value.to_le_bytes());
}

fn put_u64(data: &mut [u8], off: usize, value: u64) {
    put(data, off, &value.to_le_bytes());
}
