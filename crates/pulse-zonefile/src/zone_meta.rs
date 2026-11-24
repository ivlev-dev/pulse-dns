//! Каталог зон: `ZoneEntry` и per-zone metadata-блок (`zonefile-v1.md` §12).
//!
//! `ZoneEntry` — 72-байтовое значение ключа `RLE(apex) || T_ZONE_ENTRY || 0 || 0`.
//! Оно хранит корни дерева и блока настроек, `zone_seq`, состояние зоны и
//! счётчики. Блок `PAGE_TYPE_ZONE_META` — отдельная COW-страница; в v1
//! upstream-записи не используются, поэтому достаточно одного блока без
//! overflow-цепочки.

use crate::consts::{
    MAX_FORWARD_BLOB, MAX_FORWARD_UPSTREAMS, MAX_TTL, PAGE_TYPE_ZONE_META, ZONE_META_HEADER_SIZE,
};
use crate::errors::{CorruptDetail, CorruptKind, ZoneFileError};
use crate::node::{self, EncodeContext};
use crate::page::PageHeader;
use crate::wire;

/// Размер `ZoneEntry` (§12.1).
pub const ZONE_ENTRY_BYTES: usize = 72;

const ZE_OFF_CLASS: usize = 0;
const ZE_OFF_FLAGS: usize = 2;
const ZE_OFF_TREE_ROOT: usize = 4;
const ZE_OFF_TREE_LEVEL: usize = 8;
const ZE_OFF_STATE: usize = 10;
const ZE_OFF_RESERVED0: usize = 11;
const ZE_OFF_RRSET_COUNT: usize = 12;
const ZE_OFF_DELETED_TXN: usize = 16;
const ZE_OFF_LAST_COMMIT_TXN: usize = 24;
const ZE_OFF_LAST_CHANGE: usize = 32;
const ZE_OFF_RR_COUNT: usize = 40;
const ZE_OFF_SOA_SERIAL: usize = 44;
const ZE_OFF_IXFR_ROOT: usize = 48;
const ZE_OFF_IXFR_COUNT: usize = 52;
const ZE_OFF_ORIGIN_LEN: usize = 56;
const ZE_OFF_ZONE_SEQ: usize = 60;
const ZE_OFF_META_ROOT: usize = 64;
const ZE_OFF_RESERVED1: usize = 68;

/// Флаг `ZoneEntry.flags`: зона secondary.
pub const ZONE_FLAG_SECONDARY: u16 = 1 << 0;
/// Флаг `ZoneEntry.flags`: forward-зона.
pub const ZONE_FLAG_FORWARD: u16 = 1 << 1;
/// Флаг `ZoneEntry.flags`: dynamic-update.
pub const ZONE_FLAG_DYNAMIC: u16 = 1 << 2;
/// Флаг `ZoneEntry.flags`: заморожена.
pub const ZONE_FLAG_FROZEN: u16 = 1 << 3;
const ZONE_FLAG_RESERVED: u16 = !0x000F;

/// Флаг блока настроек: зона подписана.
pub const ZONE_META_FLAG_SIGNED: u16 = 1 << 0;
const ZONE_META_FLAG_RESERVED: u16 = !0x0001;

/// Состояние зоны (`ZoneState`, §12.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ZoneState {
    /// Создана, содержимое ещё не готово; домен отвечает `REFUSED`.
    Initializing,
    /// Штатная зона.
    Serving,
    /// Удалена; не видима `find_zone`/`zones`.
    Tombstone,
}

impl ZoneState {
    /// Числовой код состояния.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Initializing => 0,
            Self::Serving => 1,
            Self::Tombstone => 2,
        }
    }

    /// Разбор кода состояния.
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Initializing),
            1 => Some(Self::Serving),
            2 => Some(Self::Tombstone),
            _ => None,
        }
    }
}

/// Запись каталога зон (72 байта, §12.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZoneEntry {
    /// Класс (всегда `IN = 1`).
    pub class: u16,
    /// Флаги `ZONE_FLAG_*`.
    pub flags: u16,
    /// Корень дерева зоны (`0` — пусто).
    pub tree_root: u32,
    /// Уровень дерева (`0` — пусто, `1` — корень-лист).
    pub tree_level: u16,
    /// Состояние зоны.
    pub state: ZoneState,
    /// Число `RRset` без `T_NODE`.
    pub rrset_count: u32,
    /// Txn перехода в `Tombstone`; `0` — не tombstone.
    pub deleted_txn: u64,
    /// Txn последнего коммита, изменившего зону.
    pub last_commit_txn: u64,
    /// Время последнего изменения, unix ns.
    pub last_change_unix_ns: u64,
    /// Число RR.
    pub rr_count: u32,
    /// SOA serial.
    pub soa_serial: u32,
    /// Корень IXFR (0 в v1).
    pub ixfr_root: u32,
    /// Число IXFR serial (0 в v1).
    pub ixfr_serial_count: u32,
    /// Длина RLE(apex).
    pub zone_origin_len: u32,
    /// Стабильный `ZoneId`.
    pub zone_seq: u32,
    /// Корень per-zone metadata-блока.
    pub meta_root: u32,
}

impl Default for ZoneEntry {
    fn default() -> Self {
        Self {
            class: 1,
            flags: 0,
            tree_root: 0,
            tree_level: 0,
            state: ZoneState::Initializing,
            rrset_count: 0,
            deleted_txn: 0,
            last_commit_txn: 0,
            last_change_unix_ns: 0,
            rr_count: 0,
            soa_serial: 1,
            ixfr_root: 0,
            ixfr_serial_count: 0,
            zone_origin_len: 0,
            zone_seq: 0,
            meta_root: 0,
        }
    }
}

impl ZoneEntry {
    /// Создаёт запись новой зоны.
    #[must_use]
    pub fn new(zone_seq: u32, meta_root: u32, origin_len: usize, txn: u64, now_ns: u64) -> Self {
        Self {
            class: 1,
            flags: 0,
            tree_root: 0,
            tree_level: 0,
            state: ZoneState::Initializing,
            rrset_count: 0,
            deleted_txn: 0,
            last_commit_txn: txn,
            last_change_unix_ns: now_ns,
            rr_count: 0,
            soa_serial: 1,
            ixfr_root: 0,
            ixfr_serial_count: 0,
            zone_origin_len: u32::try_from(origin_len).unwrap_or(u32::MAX),
            zone_seq,
            meta_root,
        }
    }

    /// Живая ли зона (не tombstone).
    #[must_use]
    pub const fn is_live(self) -> bool {
        !matches!(self.state, ZoneState::Tombstone)
    }

    /// Кодирует запись в 72 байта.
    #[must_use]
    pub fn encode(self) -> [u8; ZONE_ENTRY_BYTES] {
        let mut out = [0_u8; ZONE_ENTRY_BYTES];
        wire::write_u16(&mut out, ZE_OFF_CLASS, self.class);
        wire::write_u16(&mut out, ZE_OFF_FLAGS, self.flags);
        wire::write_u32(&mut out, ZE_OFF_TREE_ROOT, self.tree_root);
        wire::write_u16(&mut out, ZE_OFF_TREE_LEVEL, self.tree_level);
        wire::write_u8(&mut out, ZE_OFF_STATE, self.state.as_u8());
        wire::write_u8(&mut out, ZE_OFF_RESERVED0, 0);
        wire::write_u32(&mut out, ZE_OFF_RRSET_COUNT, self.rrset_count);
        wire::write_u64(&mut out, ZE_OFF_DELETED_TXN, self.deleted_txn);
        wire::write_u64(&mut out, ZE_OFF_LAST_COMMIT_TXN, self.last_commit_txn);
        wire::write_u64(&mut out, ZE_OFF_LAST_CHANGE, self.last_change_unix_ns);
        wire::write_u32(&mut out, ZE_OFF_RR_COUNT, self.rr_count);
        wire::write_u32(&mut out, ZE_OFF_SOA_SERIAL, self.soa_serial);
        wire::write_u32(&mut out, ZE_OFF_IXFR_ROOT, self.ixfr_root);
        wire::write_u32(&mut out, ZE_OFF_IXFR_COUNT, self.ixfr_serial_count);
        wire::write_u32(&mut out, ZE_OFF_ORIGIN_LEN, self.zone_origin_len);
        wire::write_u32(&mut out, ZE_OFF_ZONE_SEQ, self.zone_seq);
        wire::write_u32(&mut out, ZE_OFF_META_ROOT, self.meta_root);
        wire::write_u32(&mut out, ZE_OFF_RESERVED1, 0);
        out
    }

    /// Декодирует и валидирует запись каталога.
    ///
    /// # Errors
    ///
    /// `Corrupt(BadZoneMeta)` — неверный класс, reserved-биты, состояние,
    /// несогласованные `tree_root`/`tree_level`, пустой `zone_seq`/`meta_root`.
    pub fn decode(bytes: &[u8]) -> Result<Self, ZoneFileError> {
        let bytes = bytes
            .get(..ZONE_ENTRY_BYTES)
            .ok_or_else(|| corrupt(CorruptDetail::ZoneMetaField))?;
        let read_u16 =
            |off| wire::read_u16(bytes, off).ok_or_else(|| corrupt(CorruptDetail::Truncated));
        let read_u32 =
            |off| wire::read_u32(bytes, off).ok_or_else(|| corrupt(CorruptDetail::Truncated));
        let read_u64 =
            |off| wire::read_u64(bytes, off).ok_or_else(|| corrupt(CorruptDetail::Truncated));
        let class = read_u16(ZE_OFF_CLASS)?;
        let flags = read_u16(ZE_OFF_FLAGS)?;
        let tree_root = read_u32(ZE_OFF_TREE_ROOT)?;
        let tree_level = read_u16(ZE_OFF_TREE_LEVEL)?;
        let state_byte =
            wire::read_u8(bytes, ZE_OFF_STATE).ok_or_else(|| corrupt(CorruptDetail::Truncated))?;
        let reserved0 = wire::read_u8(bytes, ZE_OFF_RESERVED0)
            .ok_or_else(|| corrupt(CorruptDetail::Truncated))?;
        let rrset_count = read_u32(ZE_OFF_RRSET_COUNT)?;
        let deleted_txn = read_u64(ZE_OFF_DELETED_TXN)?;
        let last_commit_txn = read_u64(ZE_OFF_LAST_COMMIT_TXN)?;
        let last_change_unix_ns = read_u64(ZE_OFF_LAST_CHANGE)?;
        let rr_count = read_u32(ZE_OFF_RR_COUNT)?;
        let soa_serial = read_u32(ZE_OFF_SOA_SERIAL)?;
        let ixfr_root = read_u32(ZE_OFF_IXFR_ROOT)?;
        let ixfr_serial_count = read_u32(ZE_OFF_IXFR_COUNT)?;
        let zone_origin_len = read_u32(ZE_OFF_ORIGIN_LEN)?;
        let zone_seq = read_u32(ZE_OFF_ZONE_SEQ)?;
        let meta_root = read_u32(ZE_OFF_META_ROOT)?;
        let reserved1 = read_u32(ZE_OFF_RESERVED1)?;
        let state =
            ZoneState::from_u8(state_byte).ok_or_else(|| corrupt(CorruptDetail::ZoneMetaField))?;
        if class != 1
            || flags & ZONE_FLAG_RESERVED != 0
            || reserved0 != 0
            || reserved1 != 0
            || (tree_root == 0) != (tree_level == 0)
            || tree_level > crate::consts::MAX_TREE_DEPTH
            || zone_seq == 0
            || meta_root == 0
            || zone_origin_len == 0
            || zone_origin_len as usize > crate::key::NAME_MAX
            || (state == ZoneState::Tombstone) != (deleted_txn != 0)
            || ixfr_root != 0
            || ixfr_serial_count != 0
        {
            return Err(corrupt(CorruptDetail::ZoneMetaField));
        }
        Ok(Self {
            class,
            flags,
            tree_root,
            tree_level,
            state,
            rrset_count,
            deleted_txn,
            last_commit_txn,
            last_change_unix_ns,
            rr_count,
            soa_serial,
            ixfr_root,
            ixfr_serial_count,
            zone_origin_len,
            zone_seq,
            meta_root,
        })
    }
}

/// Per-zone metadata-блок (`PAGE_TYPE_ZONE_META`, §12.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZoneMetaBlock {
    /// Флаги (`ZONE_META_FLAG_*`).
    pub flags: u16,
    /// Denial: 0 = NSEC, 1 = NSEC3.
    pub denial: u8,
    /// TTL по умолчанию.
    pub default_ttl: u32,
    /// SOA refresh.
    pub soa_refresh: u32,
    /// SOA retry.
    pub soa_retry: u32,
    /// SOA expire.
    pub soa_expire: u32,
    /// SOA minimum.
    pub soa_minimum: u32,
    /// Txn создания блока (для диагностики).
    pub txn: u64,
}

impl Default for ZoneMetaBlock {
    fn default() -> Self {
        Self {
            flags: 0,
            denial: 0,
            default_ttl: 3600,
            soa_refresh: 3600,
            soa_retry: 600,
            soa_expire: 604_800,
            soa_minimum: 300,
            txn: 0,
        }
    }
}

impl ZoneMetaBlock {
    /// Проверяет поля блока (без чтения страницы).
    ///
    /// # Errors
    ///
    /// `Corrupt(BadZoneMeta)` — reserved-биты, недопустимый denial или TTL.
    pub fn validate(&self) -> Result<(), ZoneFileError> {
        if self.flags & ZONE_META_FLAG_RESERVED != 0
            || self.denial > 1
            || self.default_ttl > MAX_TTL
        {
            return Err(corrupt(CorruptDetail::ZoneMetaField));
        }
        Ok(())
    }

    /// Кодирует блок в целую страницу.
    ///
    /// # Errors
    ///
    /// `Corrupt(BadZoneMeta)` — поля не проходят валидацию; `InvariantViolation`
    /// при невозможности закодировать страницу.
    pub fn encode(&self, page_no: u32, page_size: u32, txn: u64) -> Result<Vec<u8>, ZoneFileError> {
        self.validate()?;
        let len =
            usize::try_from(page_size).map_err(|_| corrupt(CorruptDetail::ZoneMetaTooLarge))?;
        let mut page = vec![0_u8; len];
        let ctx = EncodeContext {
            page_no,
            page_size,
            txn,
            lsn: 0,
        };
        node::write_page_header(&mut page, ctx, PAGE_TYPE_ZONE_META, 0)?;
        wire::write_u16(&mut page, 40, self.flags);
        wire::write_u8(&mut page, 42, self.denial);
        wire::write_u8(&mut page, 43, 0);
        wire::write_u32(&mut page, 44, self.default_ttl);
        wire::write_u32(&mut page, 48, self.soa_refresh);
        wire::write_u32(&mut page, 52, self.soa_retry);
        wire::write_u32(&mut page, 56, self.soa_expire);
        wire::write_u32(&mut page, 60, self.soa_minimum);
        wire::write_u16(&mut page, 64, 0);
        wire::write_u16(&mut page, 66, 0);
        wire::write_u8(&mut page, 68, 0);
        wire::write_u32(&mut page, 72, 0);
        wire::write_u32(&mut page, 76, 0);
        node::finish_page(&mut page, len)?;
        Ok(page)
    }

    /// Декодирует блок.
    ///
    /// # Errors
    ///
    /// `Corrupt` — заголовок/поля блока невалидны.
    pub fn decode(
        page: &[u8],
        page_no: u32,
        snapshot_txn: u64,
        page_size: u32,
    ) -> Result<Self, ZoneFileError> {
        let header = PageHeader::decode(page, page_no, snapshot_txn, page_size)?;
        if header.page_type != PAGE_TYPE_ZONE_META {
            return Err(corrupt(CorruptDetail::PageType));
        }
        let read_u8 =
            |off| wire::read_u8(page, off).ok_or_else(|| corrupt(CorruptDetail::Truncated));
        let read_u16 =
            |off| wire::read_u16(page, off).ok_or_else(|| corrupt(CorruptDetail::Truncated));
        let read_u32 =
            |off| wire::read_u32(page, off).ok_or_else(|| corrupt(CorruptDetail::Truncated));
        let flags = read_u16(40)?;
        let denial = read_u8(42)?;
        let reserved0 = read_u8(43)?;
        let default_ttl = read_u32(44)?;
        let soa_refresh = read_u32(48)?;
        let soa_retry = read_u32(52)?;
        let soa_expire = read_u32(56)?;
        let soa_minimum = read_u32(60)?;
        let upstream_count = read_u16(64)?;
        let upstream_bytes = read_u16(66)?;
        let upstream_layout = read_u8(68)?;
        let upstream_ref = read_u32(72)?;
        let upstream_total = read_u32(76)?;
        if reserved0 != 0
            || upstream_count > MAX_FORWARD_UPSTREAMS
            || u32::from(upstream_bytes) > MAX_FORWARD_BLOB
            || upstream_layout > 1
            || upstream_ref != 0
            || upstream_total != 0
            || usize::try_from(ZONE_META_HEADER_SIZE).map_or(true, |min| page.len() < min)
        {
            return Err(corrupt(CorruptDetail::ZoneMetaField));
        }
        let block = Self {
            flags,
            denial,
            default_ttl,
            soa_refresh,
            soa_retry,
            soa_expire,
            soa_minimum,
            txn: header.txn,
        };
        block.validate()?;
        Ok(block)
    }
}

fn corrupt(detail: CorruptDetail) -> ZoneFileError {
    ZoneFileError::corrupt(CorruptKind::BadZoneMeta, None, detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zone_entry_roundtrip_and_validation() {
        let entry = ZoneEntry::new(7, 33, 13, 9, 123);
        let bytes = entry.encode();
        assert_eq!(bytes.len(), ZONE_ENTRY_BYTES);
        assert_eq!(ZoneEntry::decode(&bytes).unwrap(), entry);

        let mut broken = bytes;
        broken[ZE_OFF_CLASS] = 2;
        assert!(ZoneEntry::decode(&broken).is_err());

        let mut tombstone = entry;
        tombstone.state = ZoneState::Tombstone;
        assert!(ZoneEntry::decode(&tombstone.encode()).is_err());
        tombstone.deleted_txn = 12;
        assert!(ZoneEntry::decode(&tombstone.encode()).is_ok());
    }

    #[test]
    fn zone_meta_block_roundtrip() {
        let block = ZoneMetaBlock {
            flags: ZONE_META_FLAG_SIGNED,
            denial: 1,
            default_ttl: 7200,
            txn: 3,
            ..ZoneMetaBlock::default()
        };
        let page = block.encode(40, 4096, 3).unwrap();
        let decoded = ZoneMetaBlock::decode(&page, 40, 3, 4096).unwrap();
        assert_eq!(decoded, block);
    }
}
