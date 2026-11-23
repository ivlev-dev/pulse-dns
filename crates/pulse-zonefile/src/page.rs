//! Заголовок страницы данных и ленивые проверки при чтении (§7).
//!
//! Проверки выполняются на каждом чтении страницы, а не только при открытии:
//! после `Memory`-восстановления с `allow_unsynced_memory_recovery` граф может
//! ссылаться на страницы, которые не долетели на диск, поэтому `page.txn`,
//! CRC, границы и `payload_len` — единственный барьер до offline `fsck`
//! (спецификация §13.7).

use crate::checksum;
use crate::consts::{
    FREELIST_HEADER_SIZE, OVERFLOW_HEADER_SIZE, PAGE_FLAG_FRONT_CODED, PAGE_FLAG_HAS_OVERFLOW,
    PAGE_HEADER_SIZE, PAGE_OFF_CRC32C, PAGE_OFF_LSN, PAGE_OFF_PAGE_FLAGS, PAGE_OFF_PAGE_NO,
    PAGE_OFF_PAGE_TYPE, PAGE_OFF_PAYLOAD_LEN, PAGE_OFF_RESERVED0, PAGE_OFF_RESERVED1, PAGE_OFF_TXN,
    PAGE_TYPE_BRANCH, PAGE_TYPE_FREELIST, PAGE_TYPE_LEAF, PAGE_TYPE_NAME_DICT, PAGE_TYPE_OVERFLOW,
    PAGE_TYPE_SECTION_DIR, PAGE_TYPE_ZONE_META, ZONE_META_HEADER_SIZE,
};
use crate::errors::{CorruptDetail, CorruptKind, ZoneFileError};
use crate::wire;

/// Разобранный заголовок страницы данных (40 байт, §7).
///
/// Заголовок уже проверен: `page_no` совпадает со слотом, `txn` не новее
/// снапшота, CRC сходится, reserved-поля и `payload_len` в границах типа.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageHeader {
    /// Тип страницы (`PAGE_TYPE_*`, 2..9).
    pub page_type: u32,
    /// Флаги страницы (`PAGE_FLAG_*`).
    pub page_flags: u16,
    /// Номер страницы; равен запрошенному слоту.
    pub page_no: u32,
    /// `txnid` создавшей версии.
    pub txn: u64,
    /// Монотонный счётчик записи (диагностика).
    pub lsn: u64,
    /// Длина payload, включая заголовок.
    pub payload_len: u32,
}

impl PageHeader {
    /// Декодирует и проверяет заголовок страницы данных.
    ///
    /// Проверки (§7): полная длина страницы, `page_type`, reserved-байты,
    /// `page_no == expected_page_no`, `txn <= snapshot_txn`, CRC, `payload_len`
    /// согласован с типом и не превышает `page_size`.
    ///
    /// # Errors
    ///
    /// `Corrupt` — страница короче `page_size`, неизвестный/недопустимый
    /// `page_type`, несовпадение `page_no`, `txn` новее снапшота, битый CRC,
    /// ненулевые reserved-байты или некорректный `payload_len`.
    pub(crate) fn decode(
        page: &[u8],
        expected_page_no: u32,
        snapshot_txn: u64,
        page_size: u32,
    ) -> Result<Self, ZoneFileError> {
        let corrupt =
            |detail| ZoneFileError::corrupt(CorruptKind::Bounds, Some(expected_page_no), detail);
        let page = page
            .get(..usize::try_from(page_size).unwrap_or(0))
            .filter(|page| page.len() >= PAGE_HEADER_SIZE as usize)
            .ok_or_else(|| corrupt(CorruptDetail::Truncated))?;

        let page_type = wire::read_u32(page, PAGE_OFF_PAGE_TYPE)
            .ok_or_else(|| corrupt(CorruptDetail::Truncated))?;
        Self::payload_limit(page_type, page_size)
            .ok_or_else(|| corrupt(CorruptDetail::PageType))?;

        let page_flags = wire::read_u16(page, PAGE_OFF_PAGE_FLAGS)
            .ok_or_else(|| corrupt(CorruptDetail::Truncated))?;
        if page_flags & !(PAGE_FLAG_FRONT_CODED | PAGE_FLAG_HAS_OVERFLOW) != 0 {
            return Err(corrupt(CorruptDetail::OffsetOutOfRange));
        }
        let reserved0 = wire::read_u16(page, PAGE_OFF_RESERVED0)
            .ok_or_else(|| corrupt(CorruptDetail::Truncated))?;
        let reserved1 = wire::read_u32(page, PAGE_OFF_RESERVED1)
            .ok_or_else(|| corrupt(CorruptDetail::Truncated))?;
        if reserved0 != 0 || reserved1 != 0 {
            return Err(corrupt(CorruptDetail::OffsetOutOfRange));
        }

        let page_no = wire::read_u32(page, PAGE_OFF_PAGE_NO)
            .ok_or_else(|| corrupt(CorruptDetail::Truncated))?;
        if page_no != expected_page_no {
            return Err(corrupt(CorruptDetail::PageNo));
        }

        let txn =
            wire::read_u64(page, PAGE_OFF_TXN).ok_or_else(|| corrupt(CorruptDetail::Truncated))?;
        if txn > snapshot_txn {
            // Страница новее снапшота: граф снапшота на неё ссылаться не может.
            return Err(corrupt(CorruptDetail::OffsetOutOfRange));
        }
        let lsn =
            wire::read_u64(page, PAGE_OFF_LSN).ok_or_else(|| corrupt(CorruptDetail::Truncated))?;

        let stored_crc = wire::read_u32(page, PAGE_OFF_CRC32C)
            .ok_or_else(|| corrupt(CorruptDetail::Truncated))?;
        if !checksum::verify_page_crc(page, PAGE_OFF_CRC32C, stored_crc) {
            return Err(ZoneFileError::corrupt(
                CorruptKind::PageChecksum,
                Some(expected_page_no),
                CorruptDetail::Checksum,
            ));
        }

        let payload_len = wire::read_u32(page, PAGE_OFF_PAYLOAD_LEN)
            .ok_or_else(|| corrupt(CorruptDetail::Truncated))?;
        let (min, max) = Self::payload_limit(page_type, page_size)
            .ok_or_else(|| corrupt(CorruptDetail::PageType))?;
        if payload_len < min || payload_len > max {
            return Err(corrupt(CorruptDetail::OffsetOutOfRange));
        }

        Ok(Self {
            page_type,
            page_flags,
            page_no,
            txn,
            lsn,
            payload_len,
        })
    }

    /// Допустимый диапазон `payload_len` для типа страницы (§7).
    ///
    /// Возвращает `None` для типов, которые не используют общий заголовок
    /// (meta, reader table) или неизвестны.
    const fn payload_limit(page_type: u32, page_size: u32) -> Option<(u32, u32)> {
        match page_type {
            PAGE_TYPE_BRANCH | PAGE_TYPE_LEAF => Some((page_size, page_size)),
            PAGE_TYPE_OVERFLOW => Some((OVERFLOW_HEADER_SIZE, page_size)),
            PAGE_TYPE_FREELIST => Some((FREELIST_HEADER_SIZE, page_size)),
            PAGE_TYPE_ZONE_META => Some((ZONE_META_HEADER_SIZE, page_size)),
            PAGE_TYPE_NAME_DICT | PAGE_TYPE_SECTION_DIR => Some((PAGE_HEADER_SIZE, page_size)),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::{PAGE_SIZE_DEFAULT, PAGE_TYPE_READER_TABLE};

    fn page(page_type: u32, page_no: u32, txn: u64, payload_len: u32) -> Vec<u8> {
        let mut page = vec![0_u8; PAGE_SIZE_DEFAULT as usize];
        wire::write_u32(&mut page, PAGE_OFF_PAGE_TYPE, page_type);
        wire::write_u16(&mut page, PAGE_OFF_PAGE_FLAGS, 0);
        wire::write_u32(&mut page, PAGE_OFF_PAGE_NO, page_no);
        wire::write_u64(&mut page, PAGE_OFF_TXN, txn);
        wire::write_u64(&mut page, PAGE_OFF_LSN, 7);
        wire::write_u32(&mut page, PAGE_OFF_PAYLOAD_LEN, payload_len);
        let crc = checksum::page_crc32c(&page, PAGE_OFF_CRC32C).unwrap();
        wire::write_u32(&mut page, PAGE_OFF_CRC32C, crc);
        page
    }

    #[test]
    fn decodes_valid_leaf_header() {
        let header = PageHeader::decode(
            &page(PAGE_TYPE_LEAF, 13, 4, PAGE_SIZE_DEFAULT),
            13,
            4,
            PAGE_SIZE_DEFAULT,
        )
        .unwrap();
        assert_eq!(header.page_type, PAGE_TYPE_LEAF);
        assert_eq!(header.page_no, 13);
        assert_eq!(header.txn, 4);
        assert_eq!(header.payload_len, PAGE_SIZE_DEFAULT);
    }

    #[test]
    fn accepts_page_older_than_snapshot() {
        assert!(
            PageHeader::decode(
                &page(PAGE_TYPE_LEAF, 13, 3, PAGE_SIZE_DEFAULT),
                13,
                9,
                PAGE_SIZE_DEFAULT
            )
            .is_ok()
        );
    }

    #[test]
    fn rejects_page_newer_than_snapshot() {
        assert!(matches!(
            PageHeader::decode(
                &page(PAGE_TYPE_LEAF, 13, 5, PAGE_SIZE_DEFAULT),
                13,
                4,
                PAGE_SIZE_DEFAULT
            ),
            Err(ZoneFileError::Corrupt {
                kind: CorruptKind::Bounds,
                ..
            })
        ));
    }

    #[test]
    fn rejects_wrong_slot_type_and_checksum() {
        assert!(
            PageHeader::decode(
                &page(PAGE_TYPE_LEAF, 14, 4, PAGE_SIZE_DEFAULT),
                13,
                4,
                PAGE_SIZE_DEFAULT
            )
            .is_err()
        );
        assert!(
            PageHeader::decode(
                &page(PAGE_TYPE_READER_TABLE, 13, 4, PAGE_SIZE_DEFAULT),
                13,
                4,
                PAGE_SIZE_DEFAULT
            )
            .is_err()
        );
        let mut broken = page(PAGE_TYPE_LEAF, 13, 4, PAGE_SIZE_DEFAULT);
        wire::write_u64(&mut broken, PAGE_OFF_LSN, 8);
        assert!(matches!(
            PageHeader::decode(&broken, 13, 4, PAGE_SIZE_DEFAULT),
            Err(ZoneFileError::Corrupt {
                kind: CorruptKind::PageChecksum,
                ..
            })
        ));
    }

    #[test]
    fn rejects_inconsistent_payload_len() {
        assert!(
            PageHeader::decode(
                &page(PAGE_TYPE_LEAF, 13, 4, PAGE_SIZE_DEFAULT - 1),
                13,
                4,
                PAGE_SIZE_DEFAULT
            )
            .is_err()
        );
        assert!(
            PageHeader::decode(
                &page(PAGE_TYPE_OVERFLOW, 13, 4, OVERFLOW_HEADER_SIZE + 10),
                13,
                4,
                PAGE_SIZE_DEFAULT
            )
            .is_ok()
        );
        assert!(
            PageHeader::decode(
                &page(PAGE_TYPE_OVERFLOW, 13, 4, OVERFLOW_HEADER_SIZE - 1),
                13,
                4,
                PAGE_SIZE_DEFAULT
            )
            .is_err()
        );
        assert!(
            PageHeader::decode(
                &page(PAGE_TYPE_FREELIST, 13, 4, PAGE_SIZE_DEFAULT + 1),
                13,
                4,
                PAGE_SIZE_DEFAULT
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_unexpected_reserved_and_flags() {
        let mut reserved = page(PAGE_TYPE_LEAF, 13, 4, PAGE_SIZE_DEFAULT);
        wire::write_u16(&mut reserved, PAGE_OFF_RESERVED0, 1);
        let crc = checksum::page_crc32c(&reserved, PAGE_OFF_CRC32C).unwrap();
        wire::write_u32(&mut reserved, PAGE_OFF_CRC32C, crc);
        assert!(PageHeader::decode(&reserved, 13, 4, PAGE_SIZE_DEFAULT).is_err());

        let mut flags = page(PAGE_TYPE_LEAF, 13, 4, PAGE_SIZE_DEFAULT);
        wire::write_u16(&mut flags, PAGE_OFF_PAGE_FLAGS, 1 << 9);
        let crc = checksum::page_crc32c(&flags, PAGE_OFF_CRC32C).unwrap();
        wire::write_u32(&mut flags, PAGE_OFF_CRC32C, crc);
        assert!(PageHeader::decode(&flags, 13, 4, PAGE_SIZE_DEFAULT).is_err());
    }

    #[test]
    fn rejects_short_page() {
        assert!(PageHeader::decode(&[0_u8; 39], 13, 4, PAGE_SIZE_DEFAULT).is_err());
    }

    proptest::proptest! {
        #[test]
        fn proptest_garbage_never_panics(
            bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..20_000),
            page_size in proptest::sample::select(vec![4096_u32, 8192, 16_384]),
            snapshot in proptest::prelude::any::<u64>(),
        ) {
            let _ = PageHeader::decode(&bytes, 13, snapshot, page_size);
            let _ = PageHeader::decode(&bytes, 0, snapshot, page_size);
        }
    }
}
