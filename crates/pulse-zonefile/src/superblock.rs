//! Superblock (page 0 и page 1), спецификация §4.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::checksum;
use crate::consts::{
    CHECKSUM_ALGO_CRC32C, DEFAULT_MAP_SIZE, ENDIANNESS_LITTLE, FORMAT_VERSION_MAJOR,
    FORMAT_VERSION_MINOR, KNOWN_REQUIRED_FLAGS, MAGIC, MAX_FILE_PAGES, MAX_SECTIONS, PAGE_META_A,
    PAGE_META_B, PAGE_SIZE_ALLOWED, PAGE_SIZE_DEFAULT, READER_SLOTS, ReaderGeometry,
    SB_OFF_CHECKSUM_ALGO, SB_OFF_CRC32C, SB_OFF_CREATED_UNIX_NS, SB_OFF_ENDIANNESS,
    SB_OFF_FEATURE_OPTIONAL, SB_OFF_FEATURE_REQUIRED, SB_OFF_INSTANCE_UUID, SB_OFF_MAGIC,
    SB_OFF_PAGE_COUNT_MAX, SB_OFF_PAGE_DATA_FIRST, SB_OFF_PAGE_META_A, SB_OFF_PAGE_META_B,
    SB_OFF_PAGE_READER_TABLE, SB_OFF_PAGE_READER_TABLE_COUNT, SB_OFF_PAGE_SIZE,
    SB_OFF_READER_REGION_ALIGN, SB_OFF_READER_REGION_LEN, SB_OFF_READER_REGION_OFF,
    SB_OFF_SECTION_COUNT, SB_OFF_SECTIONS, SB_OFF_SUPERBLOCK_COPY, SB_OFF_SYNC_MODE,
    SB_OFF_SYNC_MODE_VERSION, SB_OFF_VERSION_MAJOR, SB_OFF_VERSION_MINOR, SEC_OFF_FIRST_PAGE,
    SEC_OFF_FLAGS, SEC_OFF_ID, SEC_OFF_PAD, SEC_OFF_PAGE_COUNT, SEC_OFF_RESERVED, SEC_OFF_VERSION,
    SECTION_CORE, SECTION_DESCRIPTOR_SIZE, SECTION_PAD_SIZE, SECTION_RESERVED_SIZE,
    SUPERBLOCK_RECORD_SIZE, SYNC_MODE_FIELD_VERSION,
};
use crate::errors::{CorruptDetail, CorruptKind, Version, ZoneFileError};
use crate::wire;

/// Дескриптор секции файла (32 байта в wire-форме).
///
/// Раскладка (§4): `id u16 @0 | version u16 @2 | first_page u32 @4 |
/// page_count u32 @8 | pad[4] @12 | flags u64 @16 | reserved[8] @24`.
/// `repr(C)` даёт ровно эти смещения и размер 32 байта.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SectionDescriptor {
    /// Идентификатор секции.
    pub id: u16,
    /// Версия секции.
    pub version: u16,
    /// Первая страница секции.
    pub first_page: u32,
    /// Число страниц секции.
    pub page_count: u32,
    /// Выравнивающее поле; при записи всегда нули.
    pub pad: [u8; SECTION_PAD_SIZE as usize],
    /// Флаги секции.
    pub flags: u64,
    /// Зарезервированный хвост; при записи всегда нули.
    pub reserved: [u8; SECTION_RESERVED_SIZE as usize],
}

impl SectionDescriptor {
    fn encode_into(self, record: &mut [u8], off: usize) {
        let mut raw = [0_u8; SECTION_DESCRIPTOR_SIZE as usize];
        wire::write_u16(&mut raw, SEC_OFF_ID, self.id);
        wire::write_u16(&mut raw, SEC_OFF_VERSION, self.version);
        wire::write_u32(&mut raw, SEC_OFF_FIRST_PAGE, self.first_page);
        wire::write_u32(&mut raw, SEC_OFF_PAGE_COUNT, self.page_count);
        // `pad` и `reserved` по формату всегда нулевые; поля структуры нужны
        // только для смещений layout и не попадают в файл.
        wire::write_u64(&mut raw, SEC_OFF_FLAGS, self.flags);
        wire::write_bytes(record, off, &raw);
    }

    fn decode(raw: &[u8]) -> Option<Self> {
        let pad = raw.get(SEC_OFF_PAD..SEC_OFF_PAD + SECTION_PAD_SIZE as usize)?;
        let reserved =
            raw.get(SEC_OFF_RESERVED..SEC_OFF_RESERVED + SECTION_RESERVED_SIZE as usize)?;
        // Формат: `pad` и `reserved` MUST 0. Ненулевые значения — Corrupt,
        // а не «расширение»: иначе читатель вернул бы наружу неизвестный layout.
        if pad.iter().any(|&byte| byte != 0) || reserved.iter().any(|&byte| byte != 0) {
            return None;
        }
        Some(Self {
            id: wire::read_u16(raw, SEC_OFF_ID)?,
            version: wire::read_u16(raw, SEC_OFF_VERSION)?,
            first_page: wire::read_u32(raw, SEC_OFF_FIRST_PAGE)?,
            page_count: wire::read_u32(raw, SEC_OFF_PAGE_COUNT)?,
            pad: pad.try_into().ok()?,
            flags: wire::read_u64(raw, SEC_OFF_FLAGS)?,
            reserved: reserved.try_into().ok()?,
        })
    }
}

/// Режим durability, хранимый в superblock (спецификация §2/§4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SyncMode {
    /// `Sync` (`SYNC_MODE_SYNC = 0`): данные и meta синхронизируются.
    #[default]
    Sync,
    /// `Flush` (`SYNC_MODE_FLUSH = 1`): данные синхронизируются, meta — нет.
    MetaNoSync,
    /// `Memory` (`SYNC_MODE_MEMORY = 2`): без fsync (экспериментальный).
    NoSync,
}

impl SyncMode {
    /// Persistent-байт на диске (`SYNC_MODE_*`, §4.1).
    ///
    /// `0 = Sync` выбран безопасным legacy-default: старые файлы с нулевым
    /// байтом `+624` трактуются как `Sync`. Это **не** `MODE_*`: syscall-режимы
    /// имеют другой числовой порядок.
    #[must_use]
    pub const fn to_disk(self) -> u8 {
        match self {
            Self::NoSync => crate::consts::SYNC_MODE_MEMORY,
            Self::MetaNoSync => crate::consts::SYNC_MODE_FLUSH,
            Self::Sync => crate::consts::SYNC_MODE_SYNC,
        }
    }

    /// Разбор persistent-байта с диска (`SYNC_MODE_*`, §4.1).
    #[must_use]
    pub const fn from_disk(value: u8) -> Option<Self> {
        match value {
            crate::consts::SYNC_MODE_SYNC => Some(Self::Sync),
            crate::consts::SYNC_MODE_FLUSH => Some(Self::MetaNoSync),
            crate::consts::SYNC_MODE_MEMORY => Some(Self::NoSync),
            _ => None,
        }
    }

    /// Класс durability: `Memory < Flush < Sync`.
    ///
    /// Числовые persistent-коды (`SYNC_MODE_*`) для сравнения не годятся:
    /// `Memory = 2`, но это самый слабый класс.
    #[must_use]
    pub const fn durability_rank(self) -> u8 {
        match self {
            Self::NoSync => 0,
            Self::MetaNoSync => 1,
            Self::Sync => 2,
        }
    }

    /// Эффективный режим файла при заданном `durable_txn` (§4.1, §13.6).
    ///
    /// После первого durable-водораздела (`durable_txn > 1`, то есть успешного
    /// `Sync`-коммита или `sync()`) файл **липко** ведёт себя как `Sync`.
    /// Причина: recovery доверяет `superblock.sync_mode` и принимает meta новее
    /// `durable_txn` без `NEEDS_FSCK`. Если бы после `sync()` разрешить
    /// `Flush`/`Memory`-коммит, его данные не были бы fsync'нуты, а watermark
    /// уже сдвинут — повторная потеря meta откатила бы файл на страницы,
    /// которые recovery считает подтверждёнными.
    #[must_use]
    pub const fn effective_mode(self, durable_txn: u64) -> Self {
        if durable_txn > 1 { Self::Sync } else { self }
    }

    /// Проверяет, что коммит с режимом `requested` не слабее эффективного.
    ///
    /// # Errors
    ///
    /// [`ZoneFileError::InvariantViolation`] с
    /// [`InvariantId::DurabilityBelowFileMode`](crate::InvariantId::DurabilityBelowFileMode),
    /// если `requested` слабее [`SyncMode::effective_mode`].
    pub fn check_commit(self, durable_txn: u64, requested: Self) -> Result<(), ZoneFileError> {
        if requested.durability_rank() < self.effective_mode(durable_txn).durability_rank() {
            return Err(ZoneFileError::InvariantViolation(
                crate::errors::InvariantId::DurabilityBelowFileMode,
            ));
        }
        Ok(())
    }
}

/// Параметры создания нового файла.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateConfig {
    /// Размер страницы: 4096, 8192 или 16384.
    pub page_size: u32,
    /// Размер карты файла в байтах.
    pub map_size: u64,
    /// Обязательные feature-флаги.
    pub feature_flags_required: u64,
    /// Опциональные feature-флаги.
    pub feature_flags_optional: u64,
    /// Режим durability; влияет на recovery (§13.7).
    pub sync_mode: SyncMode,
}

impl Default for CreateConfig {
    fn default() -> Self {
        Self {
            page_size: PAGE_SIZE_DEFAULT,
            map_size: DEFAULT_MAP_SIZE,
            feature_flags_required: KNOWN_REQUIRED_FLAGS,
            feature_flags_optional: 0,
            sync_mode: SyncMode::Sync,
        }
    }
}

/// Superblock: конфигурация файла (запись 4096 байт).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Superblock {
    /// Мажорная версия формата.
    pub version_major: u16,
    /// Минорная версия формата.
    pub version_minor: u16,
    /// Размер страницы.
    pub page_size: u32,
    /// Максимальное число страниц.
    pub page_count_max: u32,
    /// Обязательные feature-флаги.
    pub feature_flags_required: u64,
    /// Опциональные feature-флаги.
    pub feature_flags_optional: u64,
    /// Копия superblock: 0 = A, 1 = B.
    pub superblock_copy: u8,
    /// UUID экземпляра файла (`UUIDv7`).
    pub instance_uuid: [u8; 16],
    /// Момент создания файла, unix ns.
    pub created_unix_ns: u64,
    /// Смещение региона reader table.
    pub reader_region_off: u64,
    /// Длина региона reader table.
    pub reader_region_len: u64,
    /// Выравнивание региона reader table.
    pub reader_region_align: u32,
    /// Номер страницы meta A.
    pub page_meta_a: u32,
    /// Номер страницы meta B.
    pub page_meta_b: u32,
    /// Первая страница данных.
    pub page_data_first: u32,
    /// Первая страница reader table.
    pub page_reader_table: u32,
    /// Число страниц reader table.
    pub page_reader_table_count: u32,
    /// Число используемых дескрипторов секций.
    pub section_count: u32,
    /// Дескрипторы секций.
    pub sections: [SectionDescriptor; MAX_SECTIONS as usize],
    /// Режим durability, зафиксированный при создании.
    pub sync_mode: SyncMode,
    /// Версия поля `sync_mode` (§4.1): `1` для новых файлов, `0` — legacy.
    pub sync_mode_version: u8,
}

impl Superblock {
    /// Создаёт superblock для нового файла.
    ///
    /// # Errors
    ///
    /// `UnsupportedVersion` — недопустимый `page_size` или неизвестные
    /// обязательные флаги; `MapAllocFailed` — `map_size` не кратен `page_size`
    /// или число страниц выходит за лимит формата.
    pub fn for_new(
        cfg: CreateConfig,
        instance_uuid: [u8; 16],
        created_unix_ns: u64,
    ) -> Result<Self, ZoneFileError> {
        let geometry = ReaderGeometry::for_page_size(cfg.page_size).ok_or({
            ZoneFileError::UnsupportedVersion {
                found: Version {
                    major: FORMAT_VERSION_MAJOR,
                    minor: FORMAT_VERSION_MINOR,
                },
                supported: Version {
                    major: FORMAT_VERSION_MAJOR,
                    minor: FORMAT_VERSION_MINOR,
                },
                required_flags: cfg.feature_flags_required,
            }
        })?;
        if cfg.feature_flags_required & !KNOWN_REQUIRED_FLAGS != 0 {
            return Err(ZoneFileError::UnsupportedVersion {
                found: Version {
                    major: FORMAT_VERSION_MAJOR,
                    minor: FORMAT_VERSION_MINOR,
                },
                supported: Version {
                    major: FORMAT_VERSION_MAJOR,
                    minor: FORMAT_VERSION_MINOR,
                },
                required_flags: cfg.feature_flags_required & !KNOWN_REQUIRED_FLAGS,
            });
        }
        if cfg.feature_flags_required & KNOWN_REQUIRED_FLAGS != KNOWN_REQUIRED_FLAGS {
            return Err(ZoneFileError::UnsupportedVersion {
                found: Version {
                    major: FORMAT_VERSION_MAJOR,
                    minor: FORMAT_VERSION_MINOR,
                },
                supported: Version {
                    major: FORMAT_VERSION_MAJOR,
                    minor: FORMAT_VERSION_MINOR,
                },
                required_flags: KNOWN_REQUIRED_FLAGS & !cfg.feature_flags_required,
            });
        }
        if cfg.map_size == 0 || !cfg.map_size.is_multiple_of(u64::from(cfg.page_size)) {
            return Err(ZoneFileError::MapAllocFailed {
                size: cfg.map_size,
                errno: 22,
                hint: "map_size must be a non-zero multiple of page_size",
            });
        }
        let pages = cfg.map_size / u64::from(cfg.page_size);
        let page_count_max = u32::try_from(pages).map_err(|_| ZoneFileError::MapAllocFailed {
            size: cfg.map_size,
            errno: 22,
            hint: "map_size exceeds the 32-bit page numbering range",
        })?;
        if !(16..=MAX_FILE_PAGES).contains(&page_count_max) {
            return Err(ZoneFileError::MapAllocFailed {
                size: cfg.map_size,
                errno: 22,
                hint: "map_size must cover at least 16 pages and at most MAX_FILE_PAGES",
            });
        }
        let mut sections = [SectionDescriptor::default(); MAX_SECTIONS as usize];
        sections[0] = SectionDescriptor {
            id: SECTION_CORE,
            version: 1,
            first_page: 0,
            page_count: page_count_max,
            pad: [0; SECTION_PAD_SIZE as usize],
            flags: 0,
            reserved: [0; SECTION_RESERVED_SIZE as usize],
        };
        Ok(Self {
            version_major: FORMAT_VERSION_MAJOR,
            version_minor: FORMAT_VERSION_MINOR,
            page_size: cfg.page_size,
            page_count_max,
            feature_flags_required: cfg.feature_flags_required,
            feature_flags_optional: cfg.feature_flags_optional,
            superblock_copy: 0,
            instance_uuid,
            created_unix_ns,
            reader_region_off: geometry.region_off,
            reader_region_len: geometry.region_len,
            reader_region_align: geometry.region_align,
            page_meta_a: PAGE_META_A,
            page_meta_b: PAGE_META_B,
            page_data_first: geometry.data_first(),
            page_reader_table: geometry.first_page,
            page_reader_table_count: geometry.pages,
            section_count: 1,
            sections,
            sync_mode: cfg.sync_mode,
            sync_mode_version: SYNC_MODE_FIELD_VERSION,
        })
    }

    /// Полный размер карты файла в байтах.
    #[must_use]
    pub fn map_size(&self) -> u64 {
        u64::from(self.page_count_max) * u64::from(self.page_size)
    }

    /// Геометрия reader table, вычисленная из `page_size`.
    #[must_use]
    pub fn reader_geometry(&self) -> Option<ReaderGeometry> {
        ReaderGeometry::for_page_size(self.page_size)
    }

    /// Копия B этого superblock (для записи во вторую страницу).
    #[must_use]
    pub fn as_copy_b(&self) -> Self {
        let mut copy = *self;
        copy.superblock_copy = 1;
        copy
    }

    /// Кодирует запись superblock (4096 байт) с корректным CRC.
    #[must_use]
    pub fn encode(&self) -> [u8; SUPERBLOCK_RECORD_SIZE as usize] {
        let mut record = [0_u8; SUPERBLOCK_RECORD_SIZE as usize];
        wire::write_bytes(&mut record, SB_OFF_MAGIC, &MAGIC);
        wire::write_u16(&mut record, SB_OFF_VERSION_MAJOR, self.version_major);
        wire::write_u16(&mut record, SB_OFF_VERSION_MINOR, self.version_minor);
        wire::write_u32(&mut record, SB_OFF_PAGE_SIZE, self.page_size);
        wire::write_u32(&mut record, SB_OFF_PAGE_COUNT_MAX, self.page_count_max);
        wire::write_u64(
            &mut record,
            SB_OFF_FEATURE_REQUIRED,
            self.feature_flags_required,
        );
        wire::write_u64(
            &mut record,
            SB_OFF_FEATURE_OPTIONAL,
            self.feature_flags_optional,
        );
        wire::write_u16(&mut record, SB_OFF_CHECKSUM_ALGO, CHECKSUM_ALGO_CRC32C);
        wire::write_u8(&mut record, SB_OFF_ENDIANNESS, ENDIANNESS_LITTLE);
        wire::write_u8(&mut record, SB_OFF_SUPERBLOCK_COPY, self.superblock_copy);
        wire::write_bytes(&mut record, SB_OFF_INSTANCE_UUID, &self.instance_uuid);
        wire::write_u64(&mut record, SB_OFF_CREATED_UNIX_NS, self.created_unix_ns);
        wire::write_u64(
            &mut record,
            SB_OFF_READER_REGION_OFF,
            self.reader_region_off,
        );
        wire::write_u64(
            &mut record,
            SB_OFF_READER_REGION_LEN,
            self.reader_region_len,
        );
        wire::write_u32(
            &mut record,
            SB_OFF_READER_REGION_ALIGN,
            self.reader_region_align,
        );
        wire::write_u32(&mut record, SB_OFF_PAGE_META_A, self.page_meta_a);
        wire::write_u32(&mut record, SB_OFF_PAGE_META_B, self.page_meta_b);
        wire::write_u32(&mut record, SB_OFF_PAGE_DATA_FIRST, self.page_data_first);
        wire::write_u32(
            &mut record,
            SB_OFF_PAGE_READER_TABLE,
            self.page_reader_table,
        );
        wire::write_u32(
            &mut record,
            SB_OFF_PAGE_READER_TABLE_COUNT,
            self.page_reader_table_count,
        );
        wire::write_u32(&mut record, SB_OFF_SECTION_COUNT, self.section_count);
        wire::write_u8(&mut record, SB_OFF_SYNC_MODE, self.sync_mode.to_disk());
        wire::write_u8(
            &mut record,
            SB_OFF_SYNC_MODE_VERSION,
            self.sync_mode_version,
        );
        let limit = usize::try_from(self.section_count.min(MAX_SECTIONS)).unwrap_or(0);
        for index in 0..limit {
            if let Some(section) = self.sections.get(index) {
                section.encode_into(
                    &mut record,
                    SB_OFF_SECTIONS + index * SECTION_DESCRIPTOR_SIZE as usize,
                );
            }
        }
        if let Some(crc) = checksum::page_crc32c(&record, SB_OFF_CRC32C) {
            wire::write_u32(&mut record, SB_OFF_CRC32C, crc);
        }
        record
    }

    /// Декодирует и валидирует запись superblock.
    ///
    /// Проверяются длина, магия, CRC, алгоритм контрольной суммы, порядок байт
    /// и мажорная версия. Структурные инварианты проверяет
    /// [`Superblock::validate_layout`].
    ///
    /// # Errors
    ///
    /// `Corrupt` — запись короче 4096 байт, неверная магия или CRC, а также
    /// неверный `section_count`; `UnsupportedVersion` — неизвестная версия,
    /// размер страницы или обязательные feature-флаги.
    #[allow(clippy::too_many_lines)]
    pub fn decode(record: &[u8]) -> Result<Self, ZoneFileError> {
        let record = record
            .get(..SUPERBLOCK_RECORD_SIZE as usize)
            .ok_or_else(|| {
                ZoneFileError::corrupt(CorruptKind::NoValidMeta, None, CorruptDetail::Truncated)
            })?;

        let magic = record
            .get(SB_OFF_MAGIC..SB_OFF_MAGIC + MAGIC.len())
            .ok_or_else(|| {
                ZoneFileError::corrupt(CorruptKind::NoValidMeta, None, CorruptDetail::Truncated)
            })?;
        if magic != MAGIC {
            return Err(ZoneFileError::corrupt(
                CorruptKind::NoValidMeta,
                None,
                CorruptDetail::BadMagic,
            ));
        }

        let stored_crc = wire::read_u32(record, SB_OFF_CRC32C).ok_or_else(|| {
            ZoneFileError::corrupt(CorruptKind::NoValidMeta, None, CorruptDetail::Truncated)
        })?;
        if !checksum::verify_page_crc(record, SB_OFF_CRC32C, stored_crc) {
            return Err(ZoneFileError::corrupt(
                CorruptKind::NoValidMeta,
                None,
                CorruptDetail::Checksum,
            ));
        }

        let version_major = field(wire::read_u16(record, SB_OFF_VERSION_MAJOR))?;
        let version_minor = field(wire::read_u16(record, SB_OFF_VERSION_MINOR))?;
        let page_size = field(wire::read_u32(record, SB_OFF_PAGE_SIZE))?;
        let page_count_max = field(wire::read_u32(record, SB_OFF_PAGE_COUNT_MAX))?;
        let feature_flags_required = field(wire::read_u64(record, SB_OFF_FEATURE_REQUIRED))?;
        let feature_flags_optional = field(wire::read_u64(record, SB_OFF_FEATURE_OPTIONAL))?;
        let checksum_algo = field(wire::read_u16(record, SB_OFF_CHECKSUM_ALGO))?;
        let endianness = field(wire::read_u8(record, SB_OFF_ENDIANNESS))?;
        let superblock_copy = field(wire::read_u8(record, SB_OFF_SUPERBLOCK_COPY))?;
        let instance_uuid = uuid_at(record)?;
        let created_unix_ns = field(wire::read_u64(record, SB_OFF_CREATED_UNIX_NS))?;
        let reader_region_off = field(wire::read_u64(record, SB_OFF_READER_REGION_OFF))?;
        let reader_region_len = field(wire::read_u64(record, SB_OFF_READER_REGION_LEN))?;
        let reader_region_align = field(wire::read_u32(record, SB_OFF_READER_REGION_ALIGN))?;
        let page_meta_a = field(wire::read_u32(record, SB_OFF_PAGE_META_A))?;
        let page_meta_b = field(wire::read_u32(record, SB_OFF_PAGE_META_B))?;
        let page_data_first = field(wire::read_u32(record, SB_OFF_PAGE_DATA_FIRST))?;
        let page_reader_table = field(wire::read_u32(record, SB_OFF_PAGE_READER_TABLE))?;
        let page_reader_table_count =
            field(wire::read_u32(record, SB_OFF_PAGE_READER_TABLE_COUNT))?;
        let section_count = field(wire::read_u32(record, SB_OFF_SECTION_COUNT))?;
        let sync_mode_version = field(wire::read_u8(record, SB_OFF_SYNC_MODE_VERSION))?;
        let sync_mode_byte = field(wire::read_u8(record, SB_OFF_SYNC_MODE))?;
        let sync_mode = match sync_mode_version {
            // Файлы до появления поля: reserved нулевые, по умолчанию Sync.
            0 if sync_mode_byte == 0 => SyncMode::Sync,
            0 => {
                return Err(ZoneFileError::corrupt(
                    CorruptKind::Bounds,
                    None,
                    CorruptDetail::OffsetOutOfRange,
                ));
            }
            SYNC_MODE_FIELD_VERSION => SyncMode::from_disk(sync_mode_byte).ok_or_else(|| {
                ZoneFileError::corrupt(CorruptKind::Bounds, None, CorruptDetail::OffsetOutOfRange)
            })?,
            // Версия поля новее, чем понимает сборка: не открывать «на удачу».
            _ => {
                return Err(ZoneFileError::UnsupportedVersion {
                    found: Version {
                        major: version_major,
                        minor: u16::from(sync_mode_version),
                    },
                    supported: Version {
                        major: version_major,
                        minor: u16::from(SYNC_MODE_FIELD_VERSION),
                    },
                    required_flags: 0,
                });
            }
        };
        if section_count > MAX_SECTIONS {
            return Err(ZoneFileError::corrupt(
                CorruptKind::Bounds,
                None,
                CorruptDetail::OffsetOutOfRange,
            ));
        }
        let mut sections = [SectionDescriptor::default(); MAX_SECTIONS as usize];
        let limit = usize::try_from(section_count).unwrap_or(0);
        for (index, section) in sections.iter_mut().take(limit).enumerate() {
            let off = SB_OFF_SECTIONS + index * SECTION_DESCRIPTOR_SIZE as usize;
            let raw = record
                .get(off..off + SECTION_DESCRIPTOR_SIZE as usize)
                .ok_or_else(|| {
                    ZoneFileError::corrupt(CorruptKind::Bounds, None, CorruptDetail::Truncated)
                })?;
            *section = SectionDescriptor::decode(raw).ok_or_else(|| {
                ZoneFileError::corrupt(CorruptKind::Bounds, None, CorruptDetail::OffsetOutOfRange)
            })?;
        }

        if checksum_algo != CHECKSUM_ALGO_CRC32C || endianness != ENDIANNESS_LITTLE {
            return Err(ZoneFileError::UnsupportedVersion {
                found: Version {
                    major: version_major,
                    minor: version_minor,
                },
                supported: Version {
                    major: FORMAT_VERSION_MAJOR,
                    minor: FORMAT_VERSION_MINOR,
                },
                required_flags: 0,
            });
        }
        let found = Version {
            major: version_major,
            minor: version_minor,
        };
        let supported = Version {
            major: FORMAT_VERSION_MAJOR,
            minor: FORMAT_VERSION_MINOR,
        };
        if version_major != FORMAT_VERSION_MAJOR {
            return Err(ZoneFileError::UnsupportedVersion {
                found,
                supported,
                required_flags: 0,
            });
        }
        if !PAGE_SIZE_ALLOWED.contains(&page_size) {
            return Err(ZoneFileError::UnsupportedVersion {
                found,
                supported,
                required_flags: 0,
            });
        }
        if feature_flags_required & !KNOWN_REQUIRED_FLAGS != 0 {
            return Err(ZoneFileError::UnsupportedVersion {
                found,
                supported,
                required_flags: feature_flags_required & !KNOWN_REQUIRED_FLAGS,
            });
        }
        if feature_flags_required & KNOWN_REQUIRED_FLAGS != KNOWN_REQUIRED_FLAGS {
            return Err(ZoneFileError::UnsupportedVersion {
                found,
                supported,
                required_flags: KNOWN_REQUIRED_FLAGS & !feature_flags_required,
            });
        }
        if superblock_copy > 1 || page_count_max == 0 {
            return Err(ZoneFileError::corrupt(
                CorruptKind::Bounds,
                None,
                CorruptDetail::OffsetOutOfRange,
            ));
        }

        Ok(Self {
            version_major,
            version_minor,
            page_size,
            page_count_max,
            feature_flags_required,
            feature_flags_optional,
            superblock_copy,
            instance_uuid,
            created_unix_ns,
            reader_region_off,
            reader_region_len,
            reader_region_align,
            page_meta_a,
            page_meta_b,
            page_data_first,
            page_reader_table,
            page_reader_table_count,
            section_count,
            sections,
            sync_mode,
            sync_mode_version,
        })
    }

    /// Проверяет физическую геометрию файла.
    ///
    /// # Errors
    ///
    /// `TruncatedFile` — размер файла не равен `page_count_max * page_size`;
    /// `Corrupt` — несогласованная раскладка (номера страниц, регион reader
    /// table, выравнивание, границы секций).
    pub fn validate_layout(&self, file_size: u64) -> Result<ReaderGeometry, ZoneFileError> {
        let geometry = self.reader_geometry().ok_or_else(|| {
            ZoneFileError::corrupt(CorruptKind::Bounds, None, CorruptDetail::BadReaderRegion)
        })?;
        let expected = self.map_size();
        if file_size < expected {
            return Err(ZoneFileError::TruncatedFile);
        }
        if file_size > expected {
            return Err(ZoneFileError::corrupt(
                CorruptKind::Bounds,
                None,
                CorruptDetail::OffsetOutOfRange,
            ));
        }
        if self.page_count_max < 16 || self.page_count_max > MAX_FILE_PAGES {
            return Err(ZoneFileError::corrupt(
                CorruptKind::Bounds,
                None,
                CorruptDetail::OffsetOutOfRange,
            ));
        }
        let consistent = self.page_meta_a == PAGE_META_A
            && self.page_meta_b == PAGE_META_B
            && self.page_reader_table == geometry.first_page
            && self.page_reader_table_count == geometry.pages
            && self.page_data_first == geometry.data_first()
            && self.reader_region_off == geometry.region_off
            && self.reader_region_len == geometry.region_len
            && self.reader_region_align == geometry.region_align;
        if !consistent {
            return Err(ZoneFileError::corrupt(
                CorruptKind::Bounds,
                None,
                CorruptDetail::BadReaderRegion,
            ));
        }
        if !self.reader_region_off.is_multiple_of(64) {
            return Err(ZoneFileError::corrupt(
                CorruptKind::Bounds,
                None,
                CorruptDetail::BadReaderRegion,
            ));
        }
        let region_end = self
            .reader_region_off
            .checked_add(self.reader_region_len)
            .ok_or_else(|| {
                ZoneFileError::corrupt(CorruptKind::Bounds, None, CorruptDetail::OffsetOutOfRange)
            })?;
        if region_end > expected {
            return Err(ZoneFileError::corrupt(
                CorruptKind::Bounds,
                None,
                CorruptDetail::BadReaderRegion,
            ));
        }
        if geometry.capacity() < READER_SLOTS {
            return Err(ZoneFileError::corrupt(
                CorruptKind::Bounds,
                None,
                CorruptDetail::BadReaderRegion,
            ));
        }
        let limit = usize::try_from(self.section_count.min(MAX_SECTIONS)).unwrap_or(0);
        for section in self.sections.iter().take(limit) {
            let end = section
                .first_page
                .checked_add(section.page_count)
                .ok_or_else(|| {
                    ZoneFileError::corrupt(CorruptKind::Bounds, None, CorruptDetail::ChildRange)
                })?;
            if end > self.page_count_max {
                return Err(ZoneFileError::corrupt(
                    CorruptKind::Bounds,
                    None,
                    CorruptDetail::ChildRange,
                ));
            }
        }
        Ok(geometry)
    }
}

fn field<T>(value: Option<T>) -> Result<T, ZoneFileError> {
    value.ok_or_else(|| {
        ZoneFileError::corrupt(CorruptKind::NoValidMeta, None, CorruptDetail::Truncated)
    })
}

fn uuid_at(record: &[u8]) -> Result<[u8; 16], ZoneFileError> {
    let end = SB_OFF_INSTANCE_UUID + 16;
    let raw = record.get(SB_OFF_INSTANCE_UUID..end).ok_or_else(|| {
        ZoneFileError::corrupt(CorruptKind::NoValidMeta, None, CorruptDetail::Truncated)
    })?;
    raw.try_into().map_err(|_| {
        ZoneFileError::corrupt(CorruptKind::NoValidMeta, None, CorruptDetail::Truncated)
    })
}

/// Генерирует `UUIDv7` (48 бит времени + версия 7 + вариант 10xx).
#[must_use]
pub fn new_instance_uuid() -> [u8; 16] {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    let ms = u64::try_from(now_ms).unwrap_or(u64::MAX);
    let mut rand = [0_u8; 10];
    let random_ok = std::fs::File::open("/dev/urandom")
        .and_then(|mut file| std::io::Read::read_exact(&mut file, &mut rand))
        .is_ok();
    if !random_ok {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let pid = u128::from(std::process::id());
        let mut state = nanos ^ (pid << 64) ^ u128::from(ms);
        for byte in &mut rand {
            state = state.wrapping_mul(0x9E37_79B9_7F4A_7C15).rotate_left(17);
            *byte = u8::try_from(state & 0xFF).unwrap_or(0);
        }
    }
    let mut uuid = [0_u8; 16];
    uuid[0] = u8::try_from((ms >> 40) & 0xFF).unwrap_or(0);
    uuid[1] = u8::try_from((ms >> 32) & 0xFF).unwrap_or(0);
    uuid[2] = u8::try_from((ms >> 24) & 0xFF).unwrap_or(0);
    uuid[3] = u8::try_from((ms >> 16) & 0xFF).unwrap_or(0);
    uuid[4] = u8::try_from((ms >> 8) & 0xFF).unwrap_or(0);
    uuid[5] = u8::try_from(ms & 0xFF).unwrap_or(0);
    uuid[6] = 0x70 | (rand[0] & 0x0F);
    uuid[7] = rand[1];
    uuid[8] = 0x80 | (rand[2] & 0x3F);
    uuid[9..].copy_from_slice(&rand[3..10]);
    uuid
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::F_FRONT_CODED_KEYS;
    use proptest::prelude::*;

    fn golden() -> Superblock {
        Superblock::for_new(
            CreateConfig::default(),
            [0x11; 16],
            1_700_000_000_000_000_000,
        )
        .expect("valid default config")
    }

    #[test]
    fn golden_superblock_matches_spec_section_22() {
        let superblock = golden();
        let record = superblock.encode();
        assert_eq!(record.get(0..8), Some(MAGIC.as_slice()));
        assert_eq!(wire::read_u16(&record, 8), Some(1));
        assert_eq!(wire::read_u16(&record, 10), Some(0));
        assert_eq!(wire::read_u32(&record, 12), Some(4096));
        assert_eq!(wire::read_u32(&record, 16), Some(1_048_576));
        assert_eq!(wire::read_u64(&record, 20), Some(0x3F));
        assert_eq!(wire::read_u64(&record, 28), Some(0));
        assert_eq!(wire::read_u16(&record, 36), Some(1));
        assert_eq!(wire::read_u8(&record, 38), Some(0));
        assert_eq!(wire::read_u8(&record, 39), Some(0));
        let stored = wire::read_u32(&record, 40).unwrap();
        assert_eq!(checksum::page_crc32c(&record, 40), Some(stored));
        assert_eq!(record.get(44..60), Some([0x11_u8; 16].as_slice()));
        assert_eq!(wire::read_u64(&record, 60), Some(1_700_000_000_000_000_000));
        assert_eq!(wire::read_u64(&record, 68), Some(16_384));
        assert_eq!(wire::read_u64(&record, 76), Some(36_864));
        assert_eq!(wire::read_u32(&record, 84), Some(4096));
        assert_eq!(wire::read_u32(&record, 88), Some(2));
        assert_eq!(wire::read_u32(&record, 92), Some(3));
        assert_eq!(wire::read_u32(&record, 96), Some(13));
        assert_eq!(wire::read_u32(&record, 100), Some(4));
        assert_eq!(wire::read_u32(&record, 104), Some(9));
        assert_eq!(wire::read_u32(&record, 108), Some(1));
        assert_eq!(wire::read_u16(&record, 112), Some(SECTION_CORE));
        assert_eq!(wire::read_u16(&record, 114), Some(1));
        assert_eq!(wire::read_u32(&record, 116), Some(0));
        assert_eq!(wire::read_u32(&record, 120), Some(1_048_576));
        assert_eq!(wire::read_u64(&record, 128), Some(0));
        assert_eq!(
            wire::read_u8(&record, SB_OFF_SYNC_MODE),
            Some(crate::consts::SYNC_MODE_SYNC)
        );
        assert_eq!(
            wire::read_u8(&record, SB_OFF_SYNC_MODE_VERSION),
            Some(SYNC_MODE_FIELD_VERSION)
        );
        assert!(
            record
                .get(626..4088)
                .is_some_and(|tail| tail.iter().all(|&byte| byte == 0))
        );
        assert_eq!(wire::read_u32(&record, 4088), Some(0));
        assert_eq!(wire::read_u32(&record, 4092), Some(0));
    }

    #[test]
    fn copy_b_differs_only_in_copy_flag() {
        let superblock = golden();
        let copy = superblock.as_copy_b();
        assert_eq!(copy.superblock_copy, 1);
        let a = superblock.encode();
        let b = copy.encode();
        assert_eq!(a.get(0..39), b.get(0..39));
        assert_eq!(a.get(44..), b.get(44..));
        assert_ne!(a.get(39), b.get(39));
        assert_ne!(a.get(40..44), b.get(40..44));
    }

    #[test]
    fn roundtrip() {
        let superblock = golden();
        assert_eq!(
            Superblock::decode(&superblock.encode()).unwrap(),
            superblock
        );
    }

    #[test]
    fn reader_geometry_golden() {
        for (page_size, pages, len) in [(4096, 9, 36_864), (8192, 5, 40_960), (16384, 3, 49_152)] {
            let geometry = ReaderGeometry::for_page_size(page_size).unwrap();
            assert_eq!(geometry.pages, pages);
            assert_eq!(geometry.region_off, 16_384 * u64::from(page_size) / 4096);
            assert_eq!(geometry.region_len, len);
            assert_eq!(geometry.region_len % 64, 0);
            assert_eq!(geometry.data_first(), 4 + pages);
        }
        assert!(ReaderGeometry::for_page_size(2048).is_none());
    }

    #[test]
    fn instance_uuid_is_v7() {
        let uuid = new_instance_uuid();
        assert_eq!(uuid[6] >> 4, 7);
        assert_eq!(uuid[8] & 0xC0, 0x80);
        assert_ne!(uuid, [0; 16]);
    }

    #[test]
    fn section_descriptor_flags_are_at_offset_16() {
        let mut superblock = golden();
        superblock.sections[0] = SectionDescriptor {
            id: SECTION_CORE,
            version: 3,
            first_page: 7,
            page_count: 42,
            pad: [0; SECTION_PAD_SIZE as usize],
            flags: 0x1122_3344_5566_7788,
            reserved: [0; SECTION_RESERVED_SIZE as usize],
        };
        let record = superblock.encode();
        let base = SB_OFF_SECTIONS;
        assert_eq!(wire::read_u32(&record, base + SEC_OFF_PAD), Some(0));
        assert_eq!(
            wire::read_u64(&record, base + SEC_OFF_FLAGS),
            Some(0x1122_3344_5566_7788)
        );
        assert_eq!(wire::read_u64(&record, base + SEC_OFF_RESERVED), Some(0));
        let decoded = Superblock::decode(&record).unwrap();
        assert_eq!(decoded.sections[0].flags, 0x1122_3344_5566_7788);
        assert_eq!(decoded.sections[0].version, 3);
        assert_eq!(decoded.sections[0].first_page, 7);
        assert_eq!(decoded.sections[0].page_count, 42);
    }

    #[test]
    fn encode_zeroes_section_pad_and_reserved() {
        let mut superblock = golden();
        superblock.sections[0].pad = [0xAA; SECTION_PAD_SIZE as usize];
        superblock.sections[0].reserved = [0xBB; SECTION_RESERVED_SIZE as usize];
        let record = superblock.encode();
        let base = SB_OFF_SECTIONS;
        assert_eq!(
            record.get(base + SEC_OFF_PAD..base + SEC_OFF_PAD + SECTION_PAD_SIZE as usize),
            Some(&[0_u8; SECTION_PAD_SIZE as usize][..])
        );
        assert_eq!(
            record.get(
                base + SEC_OFF_RESERVED..base + SEC_OFF_RESERVED + SECTION_RESERVED_SIZE as usize
            ),
            Some(&[0_u8; SECTION_RESERVED_SIZE as usize][..])
        );
        // decode видит канонический zero-layout, а не исходные поля структуры.
        let decoded = Superblock::decode(&record).unwrap();
        assert_eq!(decoded.sections[0].pad, [0; SECTION_PAD_SIZE as usize]);
        assert_eq!(
            decoded.sections[0].reserved,
            [0; SECTION_RESERVED_SIZE as usize]
        );
    }

    #[test]
    fn decode_rejects_nonzero_section_pad_and_reserved() {
        let superblock = golden();
        let mut record = superblock.encode();
        let base = SB_OFF_SECTIONS;
        wire::write_bytes(
            &mut record,
            base + SEC_OFF_PAD,
            &[0xAA; SECTION_PAD_SIZE as usize],
        );
        let crc = checksum::page_crc32c(&record, SB_OFF_CRC32C).unwrap();
        wire::write_u32(&mut record, SB_OFF_CRC32C, crc);
        assert!(matches!(
            Superblock::decode(&record),
            Err(ZoneFileError::Corrupt {
                kind: CorruptKind::Bounds,
                ..
            })
        ));

        let mut record = superblock.encode();
        wire::write_bytes(
            &mut record,
            base + SEC_OFF_RESERVED,
            &[0xBB; SECTION_RESERVED_SIZE as usize],
        );
        let crc = checksum::page_crc32c(&record, SB_OFF_CRC32C).unwrap();
        wire::write_u32(&mut record, SB_OFF_CRC32C, crc);
        assert!(matches!(
            Superblock::decode(&record),
            Err(ZoneFileError::Corrupt {
                kind: CorruptKind::Bounds,
                ..
            })
        ));
    }

    #[test]
    fn sync_mode_disk_codes_match_spec_section_4_1() {
        for (mode, code) in [
            (SyncMode::Sync, 0),
            (SyncMode::MetaNoSync, 1),
            (SyncMode::NoSync, 2),
        ] {
            assert_eq!(mode.to_disk(), code);
            assert_eq!(SyncMode::from_disk(code), Some(mode));
        }
        assert_eq!(SyncMode::from_disk(3), None);
        assert_eq!(SyncMode::from_disk(u8::MAX), None);
    }

    #[test]
    fn sync_mode_roundtrips_through_superblock_record() {
        for mode in [SyncMode::Sync, SyncMode::MetaNoSync, SyncMode::NoSync] {
            let mut superblock = golden();
            superblock.sync_mode = mode;
            let record = superblock.encode();
            assert_eq!(
                wire::read_u8(&record, SB_OFF_SYNC_MODE),
                Some(mode.to_disk())
            );
            let decoded = Superblock::decode(&record).unwrap();
            assert_eq!(decoded.sync_mode, mode);
        }
    }

    #[test]
    fn legacy_zero_reserved_defaults_to_sync() {
        let superblock = golden();
        let mut record = superblock.encode();
        wire::write_u8(&mut record, SB_OFF_SYNC_MODE, 0);
        wire::write_u8(&mut record, SB_OFF_SYNC_MODE_VERSION, 0);
        let crc = checksum::page_crc32c(&record, SB_OFF_CRC32C).unwrap();
        wire::write_u32(&mut record, SB_OFF_CRC32C, crc);
        let decoded = Superblock::decode(&record).unwrap();
        assert_eq!(decoded.sync_mode, SyncMode::Sync);
    }

    #[test]
    fn legacy_nonzero_sync_mode_is_corrupt() {
        let superblock = golden();
        for byte in 1..=u8::MAX {
            let mut record = superblock.encode();
            wire::write_u8(&mut record, SB_OFF_SYNC_MODE, byte);
            wire::write_u8(&mut record, SB_OFF_SYNC_MODE_VERSION, 0);
            let crc = checksum::page_crc32c(&record, SB_OFF_CRC32C).unwrap();
            wire::write_u32(&mut record, SB_OFF_CRC32C, crc);
            assert!(matches!(
                Superblock::decode(&record),
                Err(ZoneFileError::Corrupt {
                    kind: CorruptKind::Bounds,
                    detail: CorruptDetail::OffsetOutOfRange,
                    ..
                })
            ));
        }
    }

    #[test]
    fn newer_sync_mode_field_version_is_unsupported() {
        let superblock = golden();
        for version in 2..=u8::MAX {
            let mut record = superblock.encode();
            wire::write_u8(&mut record, SB_OFF_SYNC_MODE_VERSION, version);
            let crc = checksum::page_crc32c(&record, SB_OFF_CRC32C).unwrap();
            wire::write_u32(&mut record, SB_OFF_CRC32C, crc);
            assert!(matches!(
                Superblock::decode(&record),
                Err(ZoneFileError::UnsupportedVersion { found, supported, required_flags })
                    if found.major == FORMAT_VERSION_MAJOR
                        && found.minor == u16::from(version)
                        && supported.minor == u16::from(SYNC_MODE_FIELD_VERSION)
                        && required_flags == 0
            ));
        }
    }

    #[test]
    fn invalid_sync_mode_encoding_is_corrupt() {
        let superblock = golden();
        let mut record = superblock.encode();
        wire::write_u8(&mut record, SB_OFF_SYNC_MODE, 9);
        let crc = checksum::page_crc32c(&record, SB_OFF_CRC32C).unwrap();
        wire::write_u32(&mut record, SB_OFF_CRC32C, crc);
        assert!(matches!(
            Superblock::decode(&record),
            Err(ZoneFileError::Corrupt {
                kind: CorruptKind::Bounds,
                ..
            })
        ));
    }

    #[test]
    fn effective_mode_is_sticky_after_durable_watermark() {
        for mode in [SyncMode::MetaNoSync, SyncMode::NoSync] {
            assert_eq!(mode.effective_mode(1), mode);
            assert_eq!(mode.effective_mode(2), SyncMode::Sync);
            assert_eq!(mode.effective_mode(u64::MAX), SyncMode::Sync);
        }
        assert_eq!(SyncMode::Sync.effective_mode(1), SyncMode::Sync);
        assert_eq!(SyncMode::Sync.effective_mode(2), SyncMode::Sync);
    }

    #[test]
    fn commit_below_effective_mode_is_invariant_violation() {
        use crate::errors::InvariantId;

        assert!(SyncMode::NoSync.check_commit(1, SyncMode::NoSync).is_ok());
        assert!(
            SyncMode::NoSync
                .check_commit(1, SyncMode::MetaNoSync)
                .is_ok()
        );
        assert!(SyncMode::NoSync.check_commit(1, SyncMode::Sync).is_ok());
        assert!(
            SyncMode::MetaNoSync
                .check_commit(1, SyncMode::MetaNoSync)
                .is_ok()
        );
        assert!(SyncMode::MetaNoSync.check_commit(1, SyncMode::Sync).is_ok());
        assert!(matches!(
            SyncMode::MetaNoSync.check_commit(1, SyncMode::NoSync),
            Err(ZoneFileError::InvariantViolation(
                InvariantId::DurabilityBelowFileMode
            ))
        ));
        // После durable-водораздела эффективный режим — Sync для всех классов.
        for mode in [SyncMode::MetaNoSync, SyncMode::NoSync] {
            assert!(matches!(
                mode.check_commit(2, SyncMode::MetaNoSync),
                Err(ZoneFileError::InvariantViolation(
                    InvariantId::DurabilityBelowFileMode
                ))
            ));
            assert!(matches!(
                mode.check_commit(2, SyncMode::NoSync),
                Err(ZoneFileError::InvariantViolation(
                    InvariantId::DurabilityBelowFileMode
                ))
            ));
            assert!(mode.check_commit(2, SyncMode::Sync).is_ok());
        }
    }

    #[test]
    fn rejects_missing_required_flags() {
        let config = CreateConfig {
            feature_flags_required: F_FRONT_CODED_KEYS,
            ..CreateConfig::default()
        };
        assert!(matches!(
            Superblock::for_new(config, [0; 16], 0),
            Err(ZoneFileError::UnsupportedVersion { .. })
        ));
    }

    #[test]
    fn decode_rejects_missing_required_flags() {
        let mut superblock = golden();
        superblock.feature_flags_required = F_FRONT_CODED_KEYS;
        let record = superblock.encode();
        assert!(matches!(
            Superblock::decode(&record),
            Err(ZoneFileError::UnsupportedVersion { .. })
        ));
    }

    #[test]
    fn rejects_unknown_required_flags() {
        let config = CreateConfig {
            feature_flags_required: 1 << 40,
            ..CreateConfig::default()
        };
        assert!(matches!(
            Superblock::for_new(config, [0; 16], 0),
            Err(ZoneFileError::UnsupportedVersion { .. })
        ));
    }

    #[test]
    fn rejects_bad_page_size_and_map_size() {
        let config = CreateConfig {
            page_size: 2048,
            ..CreateConfig::default()
        };
        assert!(Superblock::for_new(config, [0; 16], 0).is_err());
        let config = CreateConfig {
            map_size: 1024 * 1024 + 1,
            ..CreateConfig::default()
        };
        assert!(Superblock::for_new(config, [0; 16], 0).is_err());
    }

    #[test]
    fn decode_rejects_garbage() {
        let record = [0xAA_u8; SUPERBLOCK_RECORD_SIZE as usize];
        assert!(Superblock::decode(&record).is_err());
        assert!(Superblock::decode(&record[..10]).is_err());
    }

    fn page_size_strategy() -> impl Strategy<Value = u32> {
        prop_oneof![Just(4096_u32), Just(8192_u32), Just(16_384_u32)]
    }

    prop_compose! {
        fn arbitrary_superblock()(
            page_size in page_size_strategy(),
            page_count_max in 16_u32..2_000_000,
            required in Just(KNOWN_REQUIRED_FLAGS),
            optional in any::<u64>(),
            created in any::<u64>(),
            uuid in any::<[u8; 16]>(),
            section_count in Just(16_u32),
            section_raw in prop::collection::vec((any::<u16>(), any::<u16>(), any::<u32>(), any::<u32>(), any::<u64>()), 16),
        ) -> Superblock {
            let geometry = ReaderGeometry::for_page_size(page_size).unwrap();
            let mut sections = [SectionDescriptor::default(); 16];
            for (index, section) in sections.iter_mut().enumerate() {
                let (id, version, first, count, flags) = section_raw[index];
                *section = SectionDescriptor {
                    id,
                    version,
                    first_page: first,
                    page_count: count,
                    pad: [0; SECTION_PAD_SIZE as usize],
                    flags,
                    reserved: [0; SECTION_RESERVED_SIZE as usize],
                };
            }
            Superblock {
                version_major: FORMAT_VERSION_MAJOR,
                version_minor: FORMAT_VERSION_MINOR,
                page_size,
                page_count_max,
                feature_flags_required: required,
                feature_flags_optional: optional,
                superblock_copy: 0,
                instance_uuid: uuid,
                created_unix_ns: created,
                reader_region_off: geometry.region_off,
                reader_region_len: geometry.region_len,
                reader_region_align: geometry.region_align,
                page_meta_a: PAGE_META_A,
                page_meta_b: PAGE_META_B,
                page_data_first: geometry.data_first(),
                page_reader_table: geometry.first_page,
                page_reader_table_count: geometry.pages,
                section_count,
                sections,
                sync_mode: SyncMode::Sync,
                sync_mode_version: SYNC_MODE_FIELD_VERSION,
            }
        }
    }

    proptest! {
        #[test]
        fn proptest_roundtrip(superblock in arbitrary_superblock()) {
            let decoded = Superblock::decode(&superblock.encode()).unwrap();
            prop_assert_eq!(decoded, superblock);
        }

        #[test]
        fn proptest_garbage_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..5000)) {
            let _ = Superblock::decode(&bytes);
        }
    }
}
