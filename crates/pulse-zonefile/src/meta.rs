//! Meta-страница (page 2 и page 3), спецификация §5.

use crate::checksum;
use crate::consts::{
    FORMAT_VERSION_MAJOR, FORMAT_VERSION_MINOR, FSCK_HINT_LEN, MAX_TREE_DEPTH,
    META_FLAG_NEEDS_FSCK, META_OFF_CHANGESET_LOG_ROOT, META_OFF_COMMIT_UNIX_NS, META_OFF_CRC32C,
    META_OFF_DURABLE_TXN, META_OFF_FLAGS, META_OFF_FREE_PAGE_COUNT, META_OFF_FREELIST_BUCKETS,
    META_OFF_FREELIST_ENTRIES, META_OFF_FREELIST_HEAD, META_OFF_FREELIST_TAIL, META_OFF_FSCK_HINT,
    META_OFF_HIGH_WATER, META_OFF_LAST_ERROR_CODE, META_OFF_LAST_ERROR_PAGE,
    META_OFF_LAST_ERROR_TXN, META_OFF_MANIFEST_ROOT, META_OFF_NAME_DICT_ROOT,
    META_OFF_NEXT_ZONE_SEQ, META_OFF_OLDEST_READER_TXN, META_OFF_PAGE_NO, META_OFF_PAGE_SIZE,
    META_OFF_PAGE_TYPE, META_OFF_READER_REGION_LEN, META_OFF_READER_REGION_OFF,
    META_OFF_RECLAIM_TXN, META_OFF_TOTAL_RRS, META_OFF_TOTAL_RRSETS, META_OFF_TXNID,
    META_OFF_VERSION_MAJOR, META_OFF_VERSION_MINOR, META_OFF_ZONE_COUNT, META_OFF_ZONE_DIR_LEVEL,
    META_OFF_ZONE_DIR_ROOT, PAGE_DATA_FIRST, PAGE_META_A, PAGE_SIZE_DEFAULT, PAGE_TYPE_META,
};
use crate::errors::{CorruptDetail, CorruptKind, Version, ZoneFileError};
use crate::wire;

/// Meta-страница: полный набор корней и счётчиков состояния.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Meta {
    /// Флаги meta.
    pub meta_flags: u16,
    /// Номер страницы (2 или 3).
    pub page_no: u32,
    /// Идентификатор транзакции.
    pub txnid: u64,
    /// Максимальный `txnid`, данные и meta которого на диске.
    pub durable_txn: u64,
    /// Мажорная версия формата.
    pub version_major: u16,
    /// Минорная версия формата.
    pub version_minor: u16,
    /// Размер страницы (копия).
    pub page_size: u32,
    /// Первый невыданный номер страницы.
    pub page_count_high_water: u32,
    /// Число страниц в freelist.
    pub free_page_count: u32,
    /// Корень каталога зон (0 = пусто).
    pub zone_dir_root: u32,
    /// Уровень каталога зон (0 = пусто).
    pub zone_dir_level: u16,
    /// Число живых зон.
    pub zone_count: u32,
    /// Голова freelist.
    pub freelist_head: u32,
    /// Хвост freelist.
    pub freelist_tail: u32,
    /// Число bucket-страниц freelist.
    pub freelist_buckets: u32,
    /// Суммарное число `PageId` в freelist.
    pub freelist_entries: u32,
    /// Смещение региона reader table (копия).
    pub reader_region_off: u32,
    /// Длина региона reader table (копия).
    pub reader_region_len: u32,
    /// Самый старый удерживаемый `txnid` (advisory).
    pub oldest_reader_txn: u64,
    /// Суммарное число `RRset`.
    pub total_rrsets: u64,
    /// Суммарное число RR.
    pub total_rrs: u64,
    /// Момент коммита, unix ns.
    pub commit_unix_ns: u64,
    /// Граница переиспользования страниц.
    pub reclaim_txn: u64,
    /// Аллокатор `ZoneId`.
    pub next_zone_seq: u32,
    /// Корень словаря имён (0 в v1).
    pub name_dict_root: u32,
    /// Корень журнала изменений (0 в v1).
    pub changeset_log_root: u32,
    /// Корень манифеста (0 в v1).
    pub manifest_root: u32,
    /// Код последней ошибки (диагностика).
    pub last_error_code: u32,
    /// Страница последней ошибки (диагностика).
    pub last_error_page: u32,
    /// Транзакция последней ошибки (диагностика).
    pub last_error_txn: u64,
    /// ASCIIZ-подсказка `fsck`.
    pub fsck_hint: [u8; FSCK_HINT_LEN],
}

impl Default for Meta {
    fn default() -> Self {
        Self {
            meta_flags: 0,
            page_no: PAGE_META_A,
            txnid: 1,
            durable_txn: 1,
            version_major: FORMAT_VERSION_MAJOR,
            version_minor: FORMAT_VERSION_MINOR,
            page_size: PAGE_SIZE_DEFAULT,
            page_count_high_water: PAGE_DATA_FIRST,
            free_page_count: 0,
            zone_dir_root: 0,
            zone_dir_level: 0,
            zone_count: 0,
            freelist_head: 0,
            freelist_tail: 0,
            freelist_buckets: 0,
            freelist_entries: 0,
            reader_region_off: 0,
            reader_region_len: 0,
            oldest_reader_txn: 0,
            total_rrsets: 0,
            total_rrs: 0,
            commit_unix_ns: 0,
            reclaim_txn: 0,
            next_zone_seq: 1,
            name_dict_root: 0,
            changeset_log_root: 0,
            manifest_root: 0,
            last_error_code: 0,
            last_error_page: 0,
            last_error_txn: 0,
            fsck_hint: [0; FSCK_HINT_LEN],
        }
    }
}

impl Meta {
    /// Начальная meta нового файла: `txnid = 1`, `durable_txn = 1`, все корни 0.
    #[must_use]
    pub fn initial(
        page_no: u32,
        page_size: u32,
        page_data_first: u32,
        reader_off: u32,
        reader_len: u32,
        created_unix_ns: u64,
    ) -> Self {
        Self {
            meta_flags: 0,
            page_no,
            txnid: 1,
            durable_txn: 1,
            version_major: FORMAT_VERSION_MAJOR,
            version_minor: FORMAT_VERSION_MINOR,
            page_size,
            page_count_high_water: page_data_first,
            free_page_count: 0,
            zone_dir_root: 0,
            zone_dir_level: 0,
            zone_count: 0,
            freelist_head: 0,
            freelist_tail: 0,
            freelist_buckets: 0,
            freelist_entries: 0,
            reader_region_off: reader_off,
            reader_region_len: reader_len,
            oldest_reader_txn: 0,
            total_rrsets: 0,
            total_rrs: 0,
            commit_unix_ns: created_unix_ns,
            reclaim_txn: 0,
            next_zone_seq: 1,
            name_dict_root: 0,
            changeset_log_root: 0,
            manifest_root: 0,
            last_error_code: 0,
            last_error_page: 0,
            last_error_txn: 0,
            fsck_hint: [0; FSCK_HINT_LEN],
        }
    }

    /// Требует ли файл `fsck`.
    #[must_use]
    pub fn needs_fsck(&self) -> bool {
        self.meta_flags & META_FLAG_NEEDS_FSCK != 0
    }

    /// Устанавливает флаг `NEEDS_FSCK`.
    pub fn set_needs_fsck(&mut self) {
        self.meta_flags |= META_FLAG_NEEDS_FSCK;
    }

    /// `fsck_hint` как ASCII-строка (до первого NUL).
    #[must_use]
    pub fn fsck_hint_str(&self) -> &str {
        let end = self
            .fsck_hint
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(FSCK_HINT_LEN);
        self.fsck_hint
            .get(..end)
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .unwrap_or("")
    }

    /// Кодирует meta-страницу с корректным CRC.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let len = usize::try_from(self.page_size).unwrap_or(PAGE_SIZE_DEFAULT as usize);
        let mut page = vec![0_u8; len];
        wire::write_u32(&mut page, META_OFF_PAGE_TYPE, PAGE_TYPE_META);
        wire::write_u16(&mut page, META_OFF_FLAGS, self.meta_flags);
        wire::write_u32(&mut page, META_OFF_PAGE_NO, self.page_no);
        wire::write_u64(&mut page, META_OFF_TXNID, self.txnid);
        wire::write_u64(&mut page, META_OFF_DURABLE_TXN, self.durable_txn);
        wire::write_u16(&mut page, META_OFF_VERSION_MAJOR, self.version_major);
        wire::write_u16(&mut page, META_OFF_VERSION_MINOR, self.version_minor);
        wire::write_u32(&mut page, META_OFF_PAGE_SIZE, self.page_size);
        wire::write_u32(&mut page, META_OFF_HIGH_WATER, self.page_count_high_water);
        wire::write_u32(&mut page, META_OFF_FREE_PAGE_COUNT, self.free_page_count);
        wire::write_u32(&mut page, META_OFF_ZONE_DIR_ROOT, self.zone_dir_root);
        wire::write_u16(&mut page, META_OFF_ZONE_DIR_LEVEL, self.zone_dir_level);
        wire::write_u32(&mut page, META_OFF_ZONE_COUNT, self.zone_count);
        wire::write_u32(&mut page, META_OFF_FREELIST_HEAD, self.freelist_head);
        wire::write_u32(&mut page, META_OFF_FREELIST_TAIL, self.freelist_tail);
        wire::write_u32(&mut page, META_OFF_FREELIST_BUCKETS, self.freelist_buckets);
        wire::write_u32(&mut page, META_OFF_FREELIST_ENTRIES, self.freelist_entries);
        wire::write_u32(
            &mut page,
            META_OFF_READER_REGION_OFF,
            self.reader_region_off,
        );
        wire::write_u32(
            &mut page,
            META_OFF_READER_REGION_LEN,
            self.reader_region_len,
        );
        wire::write_u64(
            &mut page,
            META_OFF_OLDEST_READER_TXN,
            self.oldest_reader_txn,
        );
        wire::write_u64(&mut page, META_OFF_TOTAL_RRSETS, self.total_rrsets);
        wire::write_u64(&mut page, META_OFF_TOTAL_RRS, self.total_rrs);
        wire::write_u64(&mut page, META_OFF_COMMIT_UNIX_NS, self.commit_unix_ns);
        wire::write_u64(&mut page, META_OFF_RECLAIM_TXN, self.reclaim_txn);
        wire::write_u32(&mut page, META_OFF_NEXT_ZONE_SEQ, self.next_zone_seq);
        wire::write_u32(&mut page, META_OFF_NAME_DICT_ROOT, self.name_dict_root);
        wire::write_u32(
            &mut page,
            META_OFF_CHANGESET_LOG_ROOT,
            self.changeset_log_root,
        );
        wire::write_u32(&mut page, META_OFF_MANIFEST_ROOT, self.manifest_root);
        wire::write_u32(&mut page, META_OFF_LAST_ERROR_CODE, self.last_error_code);
        wire::write_u32(&mut page, META_OFF_LAST_ERROR_PAGE, self.last_error_page);
        wire::write_u64(&mut page, META_OFF_LAST_ERROR_TXN, self.last_error_txn);
        wire::write_bytes(&mut page, META_OFF_FSCK_HINT, &self.fsck_hint);
        if let Some(crc) = checksum::page_crc32c(&page, META_OFF_CRC32C) {
            wire::write_u32(&mut page, META_OFF_CRC32C, crc);
        }
        page
    }

    /// Декодирует и валидирует meta-страницу.
    ///
    /// # Errors
    ///
    /// `Corrupt` — неверная длина, тип страницы, номер слота, CRC, версия,
    /// размер страницы, `high_water`, границы корней, глубина каталога,
    /// `freelist_entries` или `durable_txn > txnid`; `UnsupportedVersion` —
    /// мажорная версия не поддерживается.
    pub fn decode(
        page: &[u8],
        expected_page_no: u32,
        page_size: u32,
        page_count_max: u32,
    ) -> Result<Self, ZoneFileError> {
        let corrupt =
            |detail| ZoneFileError::corrupt(CorruptKind::Bounds, Some(expected_page_no), detail);
        let page = page
            .get(..usize::try_from(page_size).unwrap_or(0))
            .ok_or_else(|| corrupt(CorruptDetail::Truncated))?;
        let page_type = wire::read_u32(page, META_OFF_PAGE_TYPE)
            .ok_or_else(|| corrupt(CorruptDetail::Truncated))?;
        if page_type != PAGE_TYPE_META {
            return Err(ZoneFileError::corrupt(
                CorruptKind::Bounds,
                Some(expected_page_no),
                CorruptDetail::PageType,
            ));
        }
        let page_no = wire::read_u32(page, META_OFF_PAGE_NO)
            .ok_or_else(|| corrupt(CorruptDetail::Truncated))?;
        if page_no != expected_page_no {
            return Err(ZoneFileError::corrupt(
                CorruptKind::Bounds,
                Some(expected_page_no),
                CorruptDetail::PageNo,
            ));
        }
        let stored_crc = wire::read_u32(page, META_OFF_CRC32C)
            .ok_or_else(|| corrupt(CorruptDetail::Truncated))?;
        if !checksum::verify_page_crc(page, META_OFF_CRC32C, stored_crc) {
            return Err(ZoneFileError::corrupt(
                CorruptKind::PageChecksum,
                Some(expected_page_no),
                CorruptDetail::Checksum,
            ));
        }
        let version_major = read(page, META_OFF_VERSION_MAJOR)?;
        let version_minor = read(page, META_OFF_VERSION_MINOR)?;
        if version_major != FORMAT_VERSION_MAJOR {
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
        let meta_page_size = read(page, META_OFF_PAGE_SIZE)?;
        if meta_page_size != page_size {
            return Err(corrupt(CorruptDetail::OffsetOutOfRange));
        }
        let txnid = read(page, META_OFF_TXNID)?;
        let durable_txn = read(page, META_OFF_DURABLE_TXN)?;
        if txnid == 0 || durable_txn > txnid {
            return Err(corrupt(CorruptDetail::OffsetOutOfRange));
        }
        let high_water = read(page, META_OFF_HIGH_WATER)?;
        if high_water > page_count_max {
            return Err(corrupt(CorruptDetail::ChildRange));
        }
        let free_page_count = read(page, META_OFF_FREE_PAGE_COUNT)?;
        let freelist_entries = read(page, META_OFF_FREELIST_ENTRIES)?;
        if free_page_count > high_water || freelist_entries > high_water {
            return Err(corrupt(CorruptDetail::ChildRange));
        }
        let meta = Self {
            meta_flags: read(page, META_OFF_FLAGS)?,
            page_no,
            txnid,
            durable_txn,
            version_major,
            version_minor,
            page_size: meta_page_size,
            page_count_high_water: high_water,
            free_page_count,
            zone_dir_root: read(page, META_OFF_ZONE_DIR_ROOT)?,
            zone_dir_level: read(page, META_OFF_ZONE_DIR_LEVEL)?,
            zone_count: read(page, META_OFF_ZONE_COUNT)?,
            freelist_head: read(page, META_OFF_FREELIST_HEAD)?,
            freelist_tail: read(page, META_OFF_FREELIST_TAIL)?,
            freelist_buckets: read(page, META_OFF_FREELIST_BUCKETS)?,
            freelist_entries,
            reader_region_off: read(page, META_OFF_READER_REGION_OFF)?,
            reader_region_len: read(page, META_OFF_READER_REGION_LEN)?,
            oldest_reader_txn: read(page, META_OFF_OLDEST_READER_TXN)?,
            total_rrsets: read(page, META_OFF_TOTAL_RRSETS)?,
            total_rrs: read(page, META_OFF_TOTAL_RRS)?,
            commit_unix_ns: read(page, META_OFF_COMMIT_UNIX_NS)?,
            reclaim_txn: read(page, META_OFF_RECLAIM_TXN)?,
            next_zone_seq: read(page, META_OFF_NEXT_ZONE_SEQ)?,
            name_dict_root: read(page, META_OFF_NAME_DICT_ROOT)?,
            changeset_log_root: read(page, META_OFF_CHANGESET_LOG_ROOT)?,
            manifest_root: read(page, META_OFF_MANIFEST_ROOT)?,
            last_error_code: read(page, META_OFF_LAST_ERROR_CODE)?,
            last_error_page: read(page, META_OFF_LAST_ERROR_PAGE)?,
            last_error_txn: read(page, META_OFF_LAST_ERROR_TXN)?,
            fsck_hint: fsck_hint_at(page)?,
        };
        meta.validate(page_count_max)?;
        Ok(meta)
    }

    /// Проверяет границы корней, счётчики и согласованность полей meta.
    ///
    /// # Errors
    ///
    /// `Corrupt` — корень вне `[0, high_water)`, `zone_dir_level` больше
    /// `MAX_TREE_DEPTH`, `durable_txn == 0`, `reclaim_txn > durable_txn`,
    /// `free_page_count != freelist_entries`, рассогласованы
    /// `zone_dir_root`/`zone_dir_level` или `next_zone_seq == 0`.
    pub fn validate(&self, page_count_max: u32) -> Result<(), ZoneFileError> {
        let corrupt =
            |detail| ZoneFileError::corrupt(CorruptKind::Bounds, Some(self.page_no), detail);
        if self.durable_txn == 0 || self.durable_txn > self.txnid {
            return Err(corrupt(CorruptDetail::OffsetOutOfRange));
        }
        if self.reclaim_txn > self.durable_txn {
            return Err(corrupt(CorruptDetail::OffsetOutOfRange));
        }
        if self.free_page_count != self.freelist_entries {
            return Err(corrupt(CorruptDetail::ChildRange));
        }
        if (self.zone_dir_root == 0) != (self.zone_dir_level == 0) {
            return Err(corrupt(CorruptDetail::ChildRange));
        }
        if self.next_zone_seq == 0 {
            return Err(corrupt(CorruptDetail::OffsetOutOfRange));
        }
        if self.page_count_high_water > page_count_max || self.zone_dir_level > MAX_TREE_DEPTH {
            return Err(corrupt(CorruptDetail::ChildRange));
        }
        for root in [
            self.zone_dir_root,
            self.freelist_head,
            self.freelist_tail,
            self.name_dict_root,
            self.changeset_log_root,
            self.manifest_root,
        ] {
            if root != 0 && root >= self.page_count_high_water {
                return Err(corrupt(CorruptDetail::ChildRange));
            }
        }
        if self.freelist_buckets > self.freelist_entries
            || self.freelist_entries > self.page_count_high_water
        {
            return Err(corrupt(CorruptDetail::ChildRange));
        }
        Ok(())
    }

    /// Пересчитывает advisory-поле `reclaim_txn` в памяти (§5, §13.7, §14).
    ///
    /// `reclaim_txn = min(durable_watermark − 1, oldest_reader_txn)`; при
    /// watermark `1` всегда 0. Watermark — единый максимум по валидным метам,
    /// а не `self.durable_txn` выбранной meta: при регрессии durable (W-10)
    /// граница не должна откатываться к заниженному значению. Сохранённое в
    /// файле значение — advisory и при открытии пересчитывается. Метод не
    /// пишет в файл — это делает только коммит.
    pub(crate) fn refresh_reclaim_txn(&mut self, durable_watermark: u64, oldest_reader_txn: u64) {
        self.reclaim_txn = durable_watermark.saturating_sub(1).min(oldest_reader_txn);
    }
}

fn read<T>(page: &[u8], off: usize) -> Result<T, ZoneFileError>
where
    T: FromWire,
{
    T::read(page, off)
        .ok_or_else(|| ZoneFileError::corrupt(CorruptKind::Bounds, None, CorruptDetail::Truncated))
}

trait FromWire: Sized {
    fn read(page: &[u8], off: usize) -> Option<Self>;
}

impl FromWire for u16 {
    fn read(page: &[u8], off: usize) -> Option<Self> {
        wire::read_u16(page, off)
    }
}

impl FromWire for u32 {
    fn read(page: &[u8], off: usize) -> Option<Self> {
        wire::read_u32(page, off)
    }
}

impl FromWire for u64 {
    fn read(page: &[u8], off: usize) -> Option<Self> {
        wire::read_u64(page, off)
    }
}

fn fsck_hint_at(page: &[u8]) -> Result<[u8; FSCK_HINT_LEN], ZoneFileError> {
    let raw = page
        .get(META_OFF_FSCK_HINT..META_OFF_FSCK_HINT + FSCK_HINT_LEN)
        .ok_or_else(|| {
            ZoneFileError::corrupt(CorruptKind::Bounds, None, CorruptDetail::Truncated)
        })?;
    raw.try_into()
        .map_err(|_| ZoneFileError::corrupt(CorruptKind::Bounds, None, CorruptDetail::Truncated))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::PAGE_META_B;
    use proptest::prelude::*;

    fn initial() -> Meta {
        Meta::initial(
            PAGE_META_A,
            4096,
            13,
            16_384,
            36_864,
            1_700_000_000_000_000_000,
        )
    }

    #[test]
    fn golden_initial_meta_layout() {
        let meta = initial();
        let page = meta.encode();
        assert_eq!(page.len(), 4096);
        assert_eq!(wire::read_u32(&page, 0), Some(1));
        assert_eq!(wire::read_u16(&page, 4), Some(0));
        assert_eq!(wire::read_u16(&page, 6), Some(0));
        assert_eq!(wire::read_u32(&page, 8), Some(2));
        let stored = wire::read_u32(&page, 12).unwrap();
        assert_eq!(checksum::page_crc32c(&page, 12), Some(stored));
        assert_eq!(wire::read_u64(&page, 16), Some(1));
        assert_eq!(wire::read_u64(&page, 24), Some(1));
        assert_eq!(wire::read_u16(&page, 32), Some(1));
        assert_eq!(wire::read_u16(&page, 34), Some(0));
        assert_eq!(wire::read_u32(&page, 36), Some(4096));
        assert_eq!(wire::read_u32(&page, 40), Some(13));
        assert_eq!(wire::read_u32(&page, 44), Some(0));
        assert_eq!(wire::read_u32(&page, 48), Some(0));
        assert_eq!(wire::read_u16(&page, 52), Some(0));
        assert_eq!(wire::read_u32(&page, 56), Some(0));
        assert_eq!(wire::read_u32(&page, 60), Some(0));
        assert_eq!(wire::read_u32(&page, 64), Some(0));
        assert_eq!(wire::read_u32(&page, 68), Some(0));
        assert_eq!(wire::read_u32(&page, 72), Some(0));
        assert_eq!(wire::read_u32(&page, 76), Some(16_384));
        assert_eq!(wire::read_u32(&page, 80), Some(36_864));
        assert_eq!(wire::read_u64(&page, 88), Some(0));
        assert_eq!(wire::read_u64(&page, 112), Some(1_700_000_000_000_000_000));
        // initial: durable_txn = 1 → reclaim_txn = 0 (переиспользование запрещено).
        assert_eq!(wire::read_u64(&page, 120), Some(0));
        assert_eq!(wire::read_u32(&page, 128), Some(1));
        assert_eq!(wire::read_u32(&page, 144), Some(0));
        assert_eq!(wire::read_u64(&page, 152), Some(0));
        assert!(
            page.get(192..)
                .is_some_and(|tail| tail.iter().all(|&byte| byte == 0))
        );
        assert_eq!(
            Meta::decode(&page, PAGE_META_A, 4096, 1_048_576).unwrap(),
            meta
        );
    }

    #[test]
    fn golden_meta_a_from_section_22() {
        let mut meta = initial();
        meta.txnid = 2;
        meta.durable_txn = 2;
        meta.page_count_high_water = 16;
        meta.zone_dir_root = 13;
        meta.zone_dir_level = 1;
        meta.zone_count = 1;
        meta.next_zone_seq = 2;
        meta.commit_unix_ns = 42;
        // §22 golden: durable_txn = 2 → reclaim_txn = min(1, oldest) = 1.
        meta.reclaim_txn = 1;
        let page = meta.encode();
        assert_eq!(wire::read_u64(&page, 16), Some(2));
        assert_eq!(wire::read_u64(&page, 24), Some(2));
        assert_eq!(wire::read_u32(&page, 40), Some(16));
        assert_eq!(wire::read_u32(&page, 48), Some(13));
        assert_eq!(wire::read_u16(&page, 52), Some(1));
        assert_eq!(wire::read_u32(&page, 56), Some(1));
        assert_eq!(wire::read_u32(&page, 60), Some(0));
        assert_eq!(wire::read_u32(&page, 64), Some(0));
        assert_eq!(wire::read_u32(&page, 72), Some(0));
        assert_eq!(wire::read_u64(&page, 120), Some(1));
        assert_eq!(wire::read_u32(&page, 128), Some(2));
        assert_eq!(wire::read_u32(&page, 76), Some(16_384));
        assert_eq!(wire::read_u32(&page, 80), Some(36_864));
        let stored = wire::read_u32(&page, 12).unwrap();
        assert_eq!(checksum::page_crc32c(&page, 12), Some(stored));
        assert_eq!(
            Meta::decode(&page, PAGE_META_A, 4096, 1_048_576).unwrap(),
            meta
        );
    }

    #[test]
    fn decode_rejects_wrong_slot_and_checksum() {
        let meta = initial();
        let page = meta.encode();
        assert!(Meta::decode(&page, PAGE_META_B, 4096, 1_048_576).is_err());
        let mut broken = page.clone();
        wire::write_u64(&mut broken, META_OFF_TXNID, 7);
        assert!(matches!(
            Meta::decode(&broken, PAGE_META_A, 4096, 1_048_576),
            Err(ZoneFileError::Corrupt {
                kind: CorruptKind::PageChecksum,
                ..
            })
        ));
    }

    #[test]
    fn decode_rejects_zero_page() {
        assert!(Meta::decode(&[0_u8; 4096], PAGE_META_A, 4096, 1_048_576).is_err());
    }

    #[test]
    fn validation_rejects_inconsistent_meta_fields() {
        let base = initial();
        assert!(base.validate(1_048_576).is_ok());

        let mut zero_durable = base;
        zero_durable.durable_txn = 0;
        assert!(zero_durable.validate(1_048_576).is_err());

        let mut reclaim_ahead = base;
        reclaim_ahead.reclaim_txn = reclaim_ahead.durable_txn + 1;
        assert!(reclaim_ahead.validate(1_048_576).is_err());

        let mut free_mismatch = base;
        free_mismatch.free_page_count = 1;
        assert!(free_mismatch.validate(1_048_576).is_err());

        let mut root_without_level = base;
        root_without_level.zone_dir_root = 5;
        assert!(root_without_level.validate(1_048_576).is_err());

        let mut level_without_root = base;
        level_without_root.zone_dir_level = 1;
        assert!(level_without_root.validate(1_048_576).is_err());

        let mut zero_seq = base;
        zero_seq.next_zone_seq = 0;
        assert!(zero_seq.validate(1_048_576).is_err());
    }

    #[test]
    fn decode_rejects_durable_zero() {
        let mut meta = initial();
        meta.durable_txn = 0;
        let page = meta.encode();
        assert!(Meta::decode(&page, PAGE_META_A, 4096, 1_048_576).is_err());
    }

    #[test]
    fn reclaim_txn_is_recomputed_advisory() {
        let mut meta = initial();
        meta.txnid = 7;
        meta.durable_txn = 5;
        // Сохранённое значение игнорируется и пересчитывается от watermark.
        meta.reclaim_txn = 4;
        meta.refresh_reclaim_txn(5, 2);
        assert_eq!(meta.reclaim_txn, 2);
        meta.refresh_reclaim_txn(5, 9);
        assert_eq!(meta.reclaim_txn, 4);
        // При регрессии durable (W-10) watermark выше meta.durable_txn,
        // но граница всё равно считается от watermark.
        let mut regressed = initial();
        regressed.txnid = 9;
        regressed.durable_txn = 1;
        regressed.refresh_reclaim_txn(6, 9);
        assert_eq!(regressed.reclaim_txn, 5);

        // watermark = 1 → переиспользование запрещено, даже с читателем.
        let mut fresh = initial();
        fresh.reclaim_txn = 1;
        fresh.refresh_reclaim_txn(1, 9);
        assert_eq!(fresh.reclaim_txn, 0);
    }

    #[test]
    fn fsck_hint_roundtrip() {
        let mut meta = initial();
        meta.fsck_hint[..5].copy_from_slice(b"crash");
        let decoded = Meta::decode(&meta.encode(), PAGE_META_A, 4096, 1_048_576).unwrap();
        assert_eq!(decoded.fsck_hint_str(), "crash");
    }

    fn page_size_strategy() -> impl Strategy<Value = u32> {
        prop_oneof![Just(4096_u32), Just(8192_u32), Just(16_384_u32)]
    }

    prop_compose! {
        fn arbitrary_meta()(
            page_size in page_size_strategy(),
            page_no in prop_oneof![Just(PAGE_META_A), Just(PAGE_META_B)],
            txnid in 1_u64..1_000_000,
            durable_delta in 0_u64..1_000,
            high_water in 16_u32..2_000_000,
            zone_dir_level in 0_u16..=MAX_TREE_DEPTH,
            flags in any::<u16>(),
            fsck_hint in any::<[u8; FSCK_HINT_LEN]>(),
            counters in (any::<u64>(), any::<u64>(), any::<u64>(), any::<u64>()),
            roots in (any::<u32>(), any::<u32>(), any::<u32>(), any::<u32>()),
        ) -> Meta {
            let durable_txn = txnid.saturating_sub(durable_delta).max(1);
            let (zone_dir_root, freelist_head, freelist_tail, last_error_page) = roots;
            let (zone_dir_root, zone_dir_level) = if zone_dir_level == 0 {
                (0, 0)
            } else {
                (zone_dir_root % high_water.saturating_sub(1).max(1) + 1, zone_dir_level)
            };
            Meta {
                meta_flags: flags,
                page_no,
                txnid,
                durable_txn,
                version_major: FORMAT_VERSION_MAJOR,
                version_minor: FORMAT_VERSION_MINOR,
                page_size,
                page_count_high_water: high_water,
                free_page_count: 0,
                zone_dir_root,
                zone_dir_level,
                zone_count: 0,
                freelist_head: freelist_head % high_water,
                freelist_tail: freelist_tail % high_water,
                freelist_buckets: 0,
                freelist_entries: 0,
                reader_region_off: 16_384,
                reader_region_len: 36_864,
                oldest_reader_txn: 0,
                total_rrsets: counters.0,
                total_rrs: counters.1,
                commit_unix_ns: counters.2,
                reclaim_txn: counters.3 % (durable_txn + 1),
                next_zone_seq: 1,
                name_dict_root: 0,
                changeset_log_root: 0,
                manifest_root: 0,
                last_error_code: 0,
                last_error_page: last_error_page % high_water,
                last_error_txn: 0,
                fsck_hint,
            }
        }
    }

    proptest! {
        #[test]
        fn proptest_roundtrip(meta in arbitrary_meta()) {
            let page = meta.encode();
            let decoded = Meta::decode(&page, meta.page_no, meta.page_size, 2_000_000).unwrap();
            prop_assert_eq!(decoded, meta);
        }

        #[test]
        fn proptest_garbage_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..20_000)) {
            let _ = Meta::decode(&bytes, PAGE_META_A, 4096, 1_048_576);
            let _ = Meta::decode(&bytes, PAGE_META_B, 16_384, 1_048_576);
        }
    }
}
