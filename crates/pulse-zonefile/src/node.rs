//! Узлы B+tree: заголовок, фронт-кодирование, поиск и кодирование
//! (`zonefile-v1.md` §10, §11.1–11.3).
//!
//! Узел занимает всю страницу. Заголовок страницы — 40 байт (§7), заголовок
//! узла — 16 байт (смещение +40): `level u16`, `n_items u16`, `n_restarts u16`,
//! `node_flags u16`, `free_bytes u32`, `items_start u32`. Далее идут
//! `restart_offsets u16[n_restarts]`, `slots u16[n_items]` и область элементов
//! от `items_start` до конца страницы.
//!
//! Все многобайтовые поля страницы — little-endian, кроме префиксов длины
//! внутри payload'а RDATA: `u16 rdlength` кодируется **big-endian** (DNS wire,
//! как в golden-примере §22: `00 04 C0 00 02 01`).
//!
//! ```
//! # use pulse_zonefile::consts::PAGE_SIZE_DEFAULT;
//! # use pulse_zonefile::key::{Key, NameRle, CLASS_IN};
//! # use pulse_zonefile::node::{encode_leaf, EncodeContext, ItemValue, LeafItem, LeafValue, ValueKind};
//! let name = NameRle::from_ascii("example.com").unwrap();
//! let item = LeafItem::new(
//!     Key::new(&name, 0, 0, 0).unwrap(),
//!     ItemValue::node(0),
//! );
//! let mut page = vec![0_u8; PAGE_SIZE_DEFAULT as usize];
//! let ctx = EncodeContext { page_no: 14, page_size: PAGE_SIZE_DEFAULT, txn: 2, lsn: 0 };
//! let encoded = encode_leaf(&mut page, ctx, &[item]).unwrap();
//! assert_eq!(encoded.encoded_size, 56 + 2 + 2 + 43);
//! ```

use std::cmp::Ordering;
use std::fmt;

use crate::checksum;
use crate::consts::{
    BRANCH_RESTART_INTERVAL, INLINE_VALUE_MAX, LEAF_RESTART_INTERVAL, LEAF_VALUE_SIZE,
    MAX_RDLENGTH, MAX_RRSET_PAYLOAD, MAX_TREE_DEPTH, MAX_TTL, NODE_HEADER_SIZE,
    PAGE_FLAG_FRONT_CODED, PAGE_FLAG_HAS_OVERFLOW, PAGE_HEADER_SIZE, PAGE_OFF_CRC32C, PAGE_OFF_LSN,
    PAGE_OFF_PAGE_FLAGS, PAGE_OFF_PAGE_NO, PAGE_OFF_PAGE_TYPE, PAGE_OFF_PAYLOAD_LEN,
    PAGE_OFF_RESERVED0, PAGE_OFF_RESERVED1, PAGE_OFF_TXN, PAGE_TYPE_BRANCH, PAGE_TYPE_LEAF,
};
use crate::errors::{CorruptDetail, CorruptKind, InvariantId, ZoneFileError};
use crate::key::{
    KEY_MAX, KEY_TAIL_SIZE, Key, NameRle, OrderKey, T_NODE, T_ZONE_ENTRY, compare_raw_keys,
    compare_raw_to_key_len, compare_validated, name_len_unchecked, owner_from_raw,
    validate_name_rle,
};
use crate::page::PageHeader;
use crate::wire;

/// Интервал restart-точек листа.
pub const LEAF_INTERVAL: usize = LEAF_RESTART_INTERVAL as usize;
/// Интервал restart-точек ветвления.
pub const BRANCH_INTERVAL: usize = BRANCH_RESTART_INTERVAL as usize;
/// Размер заголовка узла.
pub const NODE_HEADER_BYTES: usize = NODE_HEADER_SIZE as usize;
/// Размер заголовка item'а (`shared_len` + `suffix_len`).
pub const ITEM_HEADER_BYTES: usize = 4;
/// Размер указателя на ребёнка в item'е ветвления.
pub const BRANCH_CHILD_BYTES: usize = 4;
/// Размер `LeafValue`.
pub const LEAF_VALUE_BYTES: usize = LEAF_VALUE_SIZE as usize;
/// Размер `ZoneEntry` в листе каталога.
pub const ZONE_ENTRY_BYTES: usize = 72;

/// Бит `node_flags`: страница проверена writer'ом на порядок ключей.
pub const NODE_FLAG_SORTED_VALIDATED: u16 = 1 << 0;
/// Все известные биты `node_flags`.
pub const NODE_FLAG_KNOWN: u16 = NODE_FLAG_SORTED_VALIDATED;

/// Флаг `RR_FLAG_APEX`: owner — apex зоны.
pub const RR_FLAG_APEX: u16 = 1 << 0;
/// Флаг `RR_FLAG_DELEGATION`: cut (NS без SOA).
pub const RR_FLAG_DELEGATION: u16 = 1 << 1;
/// Флаг `RR_FLAG_SECURE_DELEGATION`: cut с DS.
pub const RR_FLAG_SECURE_DELEGATION: u16 = 1 << 2;
/// Флаг `RR_FLAG_GLUE`: glue ниже cut.
pub const RR_FLAG_GLUE: u16 = 1 << 3;
/// Флаг `RR_FLAG_OCCLUDED`: ниже cut, не authoritative.
pub const RR_FLAG_OCCLUDED: u16 = 1 << 4;
/// Флаг `RR_FLAG_WILDCARD`: owner начинается с `*`.
pub const RR_FLAG_WILDCARD: u16 = 1 << 5;
/// Флаг `RR_FLAG_EMPTY_NON_TERMINAL`: имя существует только как предок (ENT).
pub const RR_FLAG_EMPTY_NON_TERMINAL: u16 = 1 << 6;
/// Флаг `RR_FLAG_DNSSEC_SIGNED`: есть `RRSIG` покрывающего типа.
pub const RR_FLAG_DNSSEC_SIGNED: u16 = 1 << 7;
/// Флаг `RR_FLAG_TTL_NORMALIZED`: TTL изменён writer'ом.
pub const RR_FLAG_TTL_NORMALIZED: u16 = 1 << 8;
/// Флаг `RR_FLAG_CHILDREN_MAY_EXIST`: у имени есть потомки.
pub const RR_FLAG_CHILDREN_MAY_EXIST: u16 = 1 << 9;
/// Флаг `RR_FLAG_NSEC3`: резерв.
pub const RR_FLAG_NSEC3: u16 = 1 << 10;
/// Флаг `RR_FLAG_CUT_BELOW`: ниже есть cut.
pub const RR_FLAG_CUT_BELOW: u16 = 1 << 11;
/// Зарезервированные биты `LeafValue.flags`.
pub const RR_FLAG_RESERVED: u16 = 0xF000;

/// Вид значения листа (`LeafValue.kind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ValueKind {
    /// Маркер `T_NODE`: у имени нет payload'а.
    Node = 0,
    /// Payload встроен в item.
    Inline = 1,
    /// Payload в overflow-цепочке; `val_u32` — первая страница.
    Overflow = 2,
}

impl ValueKind {
    /// Разбирает код вида.
    ///
    /// # Errors
    ///
    /// `Corrupt(Bounds)` — код вне 0..=2.
    pub fn from_u8(code: u8) -> Result<Self, ZoneFileError> {
        match code {
            0 => Ok(Self::Node),
            1 => Ok(Self::Inline),
            2 => Ok(Self::Overflow),
            _ => Err(corrupt_none(
                CorruptKind::Bounds,
                CorruptDetail::OffsetOutOfRange,
            )),
        }
    }

    /// Код вида для файла.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for ValueKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Node => "Node",
            Self::Inline => "Inline",
            Self::Overflow => "Overflow",
        })
    }
}

/// Значение листа, 20 байт (§11.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LeafValue {
    /// Вид значения.
    pub kind: ValueKind,
    /// Флаги (`RR_FLAG_*`, `NODE_FLAG_*`).
    pub flags: u16,
    /// Число RR в наборе.
    pub rr_count: u16,
    /// TTL набора (один на `RRset`).
    pub ttl: u32,
    /// `INLINE`: 0; `OVERFLOW`: первый `PageId`.
    pub val_u32: u32,
    /// Сумма `rdlength` всех RR.
    pub rdlen: u16,
}

impl LeafValue {
    /// Создаёт и проверяет значение листа.
    ///
    /// # Errors
    ///
    /// `Corrupt(BadTtl)` — TTL больше `2^31−1`; `Corrupt(Bounds)` — флаги
    /// используют зарезервированные биты или поля не согласованы с видом.
    pub fn new(
        kind: ValueKind,
        flags: u16,
        ttl: u32,
        rr_count: u16,
        rdlen: u16,
    ) -> Result<Self, ZoneFileError> {
        let value = Self {
            kind,
            flags,
            rr_count,
            ttl,
            val_u32: 0,
            rdlen,
        };
        value.validate()?;
        Ok(value)
    }

    /// Значение маркера `T_NODE`.
    #[must_use]
    pub fn node(flags: u16) -> Self {
        Self {
            kind: ValueKind::Node,
            flags,
            rr_count: 0,
            ttl: 0,
            val_u32: 0,
            rdlen: 0,
        }
    }

    /// Значение overflow-набора с первой страницей цепочки.
    ///
    /// # Errors
    ///
    /// `Corrupt` — `first_page == 0` или поля выходят за лимиты.
    pub fn overflow(
        flags: u16,
        ttl: u32,
        rr_count: u16,
        rdlen: u16,
        first_page: u32,
    ) -> Result<Self, ZoneFileError> {
        let value = Self {
            kind: ValueKind::Overflow,
            flags,
            rr_count,
            ttl,
            val_u32: first_page,
            rdlen,
        };
        value.validate()?;
        Ok(value)
    }

    /// Число байт payload'а: `rdlen + 2*rr_count`.
    ///
    /// # Errors
    ///
    /// `Corrupt(BadRdata)` — переполнение или превышение лимита формата.
    pub fn payload_bytes(&self) -> Result<u32, ZoneFileError> {
        let rdlen = u32::from(self.rdlen);
        let count = u32::from(self.rr_count);
        count
            .checked_mul(2)
            .and_then(|extra| rdlen.checked_add(extra))
            .filter(|&total| total <= MAX_RRSET_PAYLOAD)
            .ok_or_else(|| corrupt_none(CorruptKind::BadRdata, CorruptDetail::RdataSum))
    }

    /// Проверяет инварианты полей без привязки к ключу.
    ///
    /// # Errors
    ///
    /// `Corrupt` — TTL/флаги/payload вне допустимых значений.
    pub fn validate(&self) -> Result<(), ZoneFileError> {
        if self.flags & RR_FLAG_RESERVED != 0 {
            return Err(corrupt_none(
                CorruptKind::Bounds,
                CorruptDetail::OffsetOutOfRange,
            ));
        }
        if self.ttl > MAX_TTL {
            return Err(corrupt_none(
                CorruptKind::BadTtl,
                CorruptDetail::TtlOutOfRange,
            ));
        }
        let payload_bytes = self.payload_bytes()?;
        match self.kind {
            ValueKind::Node => {
                if self.rr_count != 0 || self.rdlen != 0 || self.ttl != 0 || self.val_u32 != 0 {
                    return Err(corrupt_none(
                        CorruptKind::Bounds,
                        CorruptDetail::OffsetOutOfRange,
                    ));
                }
            }
            ValueKind::Inline => {
                if self.val_u32 != 0 || payload_bytes > INLINE_VALUE_MAX {
                    return Err(corrupt_none(
                        CorruptKind::Bounds,
                        CorruptDetail::OffsetOutOfRange,
                    ));
                }
            }
            ValueKind::Overflow => {
                if self.val_u32 == 0 || payload_bytes <= INLINE_VALUE_MAX {
                    return Err(corrupt_none(
                        CorruptKind::BadRdata,
                        CorruptDetail::OverflowChain,
                    ));
                }
            }
        }
        Ok(())
    }

    /// Кодирует значение в 20 байт.
    fn encode(&self, out: &mut [u8]) -> Result<(), ZoneFileError> {
        if out.len() < LEAF_VALUE_BYTES {
            return Err(corrupt_none(
                CorruptKind::Bounds,
                CorruptDetail::OffsetOutOfRange,
            ));
        }
        put_u8(out, 0, self.kind.as_u8())?;
        put_u8(out, 1, 0)?;
        put_u16(out, 2, self.flags)?;
        put_u16(out, 4, self.rr_count)?;
        put_u16(out, 6, 0)?;
        put_u32(out, 8, self.ttl)?;
        put_u32(out, 12, self.val_u32)?;
        put_u16(out, 16, self.rdlen)?;
        put_u16(out, 18, 0)
    }

    /// Декодирует значение из 20 байт с полной проверкой.
    ///
    /// # Errors
    ///
    /// `Corrupt` — короткий срез, ненулевые reserved-поля, невалидные
    /// `kind`/TTL/флаги/payload.
    pub fn decode(bytes: &[u8]) -> Result<Self, ZoneFileError> {
        if bytes.len() < LEAF_VALUE_BYTES {
            return Err(corrupt_none(CorruptKind::Bounds, CorruptDetail::Truncated));
        }
        let kind = ValueKind::from_u8(wire::read_u8(bytes, 0).ok_or_else(truncated)?)?;
        let reserved0 = wire::read_u8(bytes, 1).ok_or_else(truncated)?;
        let flags = wire::read_u16(bytes, 2).ok_or_else(truncated)?;
        let rr_count = wire::read_u16(bytes, 4).ok_or_else(truncated)?;
        let reserved1 = wire::read_u16(bytes, 6).ok_or_else(truncated)?;
        let ttl = wire::read_u32(bytes, 8).ok_or_else(truncated)?;
        let val_u32 = wire::read_u32(bytes, 12).ok_or_else(truncated)?;
        let rdlen = wire::read_u16(bytes, 16).ok_or_else(truncated)?;
        let reserved2 = wire::read_u16(bytes, 18).ok_or_else(truncated)?;
        if reserved0 != 0 || reserved1 != 0 || reserved2 != 0 {
            return Err(corrupt_none(
                CorruptKind::Bounds,
                CorruptDetail::OffsetOutOfRange,
            ));
        }
        let value = Self {
            kind,
            flags,
            rr_count,
            ttl,
            val_u32,
            rdlen,
        };
        value.validate()?;
        Ok(value)
    }
}

fn truncated() -> ZoneFileError {
    corrupt_none(CorruptKind::Bounds, CorruptDetail::Truncated)
}

fn corrupt(page: Option<u32>, kind: CorruptKind, detail: CorruptDetail) -> ZoneFileError {
    ZoneFileError::corrupt(kind, page, detail)
}

fn corrupt_none(kind: CorruptKind, detail: CorruptDetail) -> ZoneFileError {
    ZoneFileError::corrupt(kind, None, detail)
}

fn put_u8(out: &mut [u8], off: usize, value: u8) -> Result<(), ZoneFileError> {
    *out.get_mut(off)
        .ok_or_else(|| corrupt_none(CorruptKind::Bounds, CorruptDetail::OffsetOutOfRange))? = value;
    Ok(())
}

fn put_u16(out: &mut [u8], off: usize, value: u16) -> Result<(), ZoneFileError> {
    let dst = out
        .get_mut(off..off + 2)
        .ok_or_else(|| corrupt_none(CorruptKind::Bounds, CorruptDetail::OffsetOutOfRange))?;
    dst.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

pub(crate) fn put_u32(out: &mut [u8], off: usize, value: u32) -> Result<(), ZoneFileError> {
    let dst = out
        .get_mut(off..off + 4)
        .ok_or_else(|| corrupt_none(CorruptKind::Bounds, CorruptDetail::OffsetOutOfRange))?;
    dst.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn get_u16(page: &[u8], off: usize, page_no: u32) -> Result<u16, ZoneFileError> {
    wire::read_u16(page, off)
        .ok_or_else(|| corrupt(Some(page_no), CorruptKind::Bounds, CorruptDetail::Truncated))
}

fn get_u32(page: &[u8], off: usize, page_no: u32) -> Result<u32, ZoneFileError> {
    wire::read_u32(page, off)
        .ok_or_else(|| corrupt(Some(page_no), CorruptKind::Bounds, CorruptDetail::Truncated))
}

/// Значение item'а листа.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ItemValue {
    /// 72-байтовый `ZoneEntry` каталога зон (§12.1) — без `LeafValue`.
    ZoneEntry([u8; ZONE_ENTRY_BYTES]),
    /// `LeafValue` + payload (payload непуст только для `INLINE`).
    Leaf {
        /// 20-байтовое значение.
        value: LeafValue,
        /// Встроенный payload `{u16 rdlength; rdata}*rr_count` (big-endian
        /// префиксы длин, DNS wire).
        payload: Vec<u8>,
    },
}

impl ItemValue {
    /// Значение `ZoneEntry`.
    ///
    /// # Errors
    ///
    /// `Corrupt(Bounds)` — длина не 72 байта.
    pub fn zone_entry(bytes: &[u8]) -> Result<Self, ZoneFileError> {
        let array: [u8; ZONE_ENTRY_BYTES] = bytes
            .try_into()
            .map_err(|_| corrupt_none(CorruptKind::Bounds, CorruptDetail::OffsetOutOfRange))?;
        Ok(Self::ZoneEntry(array))
    }

    /// Значение маркера `T_NODE`.
    #[must_use]
    pub fn node(flags: u16) -> Self {
        Self::Leaf {
            value: LeafValue::node(flags),
            payload: Vec::new(),
        }
    }

    /// Встроенное значение `RRset`.
    ///
    /// # Errors
    ///
    /// `Corrupt` — значение не является `INLINE` или payload не сходится
    /// с `rdlen`/`rr_count`.
    pub fn inline(value: LeafValue, payload: Vec<u8>) -> Result<Self, ZoneFileError> {
        if value.kind != ValueKind::Inline {
            return Err(value_mismatch());
        }
        let item = Self::Leaf { value, payload };
        item.validate_leaf_contract()?;
        Ok(item)
    }

    /// Значение `RRset` в overflow-цепочке.
    ///
    /// # Errors
    ///
    /// `Corrupt` — значение не является `OVERFLOW`.
    pub fn overflow(value: LeafValue) -> Result<Self, ZoneFileError> {
        let item = Self::Leaf {
            value,
            payload: Vec::new(),
        };
        item.validate_leaf_contract()?;
        Ok(item)
    }

    /// `LeafValue`, если значение не `ZoneEntry`.
    #[must_use]
    pub const fn leaf_value(&self) -> Option<LeafValue> {
        match self {
            Self::Leaf { value, .. } => Some(*value),
            Self::ZoneEntry(_) => None,
        }
    }

    /// Встроенный payload (пустой для `ZoneEntry`/`NODE`/`OVERFLOW`).
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        match self {
            Self::Leaf { payload, .. } => payload,
            Self::ZoneEntry(_) => &[],
        }
    }

    fn validate_leaf_contract(&self) -> Result<(), ZoneFileError> {
        let Self::Leaf { value, payload } = self else {
            return Ok(());
        };
        value.validate()?;
        match value.kind {
            ValueKind::Node => {
                if !payload.is_empty() {
                    return Err(corrupt_none(
                        CorruptKind::Bounds,
                        CorruptDetail::OffsetOutOfRange,
                    ));
                }
            }
            ValueKind::Inline => {
                let expected = usize::try_from(value.payload_bytes()?)
                    .map_err(|_| corrupt_none(CorruptKind::BadRdata, CorruptDetail::RdataSum))?;
                if payload.len() != expected {
                    return Err(corrupt_none(CorruptKind::BadRdata, CorruptDetail::RdataSum));
                }
                validate_payload(payload, value.rr_count, value.rdlen)?;
            }
            ValueKind::Overflow => {
                if !payload.is_empty() {
                    return Err(corrupt_none(
                        CorruptKind::BadRdata,
                        CorruptDetail::OverflowChain,
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Item листа: полный ключ и значение.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafItem {
    /// Полный ключ `RLE(name) || type || class || subtype`.
    pub key: Key,
    /// Значение, согласованное с типом ключа.
    pub value: ItemValue,
}

impl LeafItem {
    /// Создаёт item.
    #[must_use]
    pub const fn new(key: Key, value: ItemValue) -> Self {
        Self { key, value }
    }
}

/// Item ветвления: сепаратор (точный минимум поддерева) и ребёнок.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BranchItem {
    /// Минимальный ключ поддерева ребёнка.
    pub key: Key,
    /// Номер дочерней страницы.
    pub child: u32,
}

impl BranchItem {
    /// Создаёт item ветвления.
    #[must_use]
    pub const fn new(key: Key, child: u32) -> Self {
        Self { key, child }
    }
}

/// Логический лист (полный набор item'ов, без фронт-кодирования).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LeafNode {
    /// Item'ы строго по возрастанию ключа.
    pub items: Vec<LeafItem>,
}

/// Логическое ветвление.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BranchNode {
    /// Сепараторы строго по возрастанию; `items[i].key` — минимум поддерева.
    pub items: Vec<BranchItem>,
}

/// Параметры кодирования страницы узла.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodeContext {
    /// Номер страницы (пишется в `PageHeader`).
    pub page_no: u32,
    /// Размер страницы.
    pub page_size: u32,
    /// `txnid` создаваемой версии.
    pub txn: u64,
    /// Монотонный `lsn` (диагностика).
    pub lsn: u64,
}

/// Результат кодирования узла.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodedNode {
    /// `NODE_HEADER_SIZE + 2*(n_restarts + n_items) + Σ item_bytes`.
    pub encoded_size: u32,
    /// `page_size - encoded_size`.
    pub free_bytes: u32,
    /// Число item'ов.
    pub n_items: u16,
    /// Число restart-точек.
    pub n_restarts: u16,
}

fn invalid_order() -> ZoneFileError {
    ZoneFileError::InvariantViolation(InvariantId::KeyOrder)
}

fn encoded_too_large() -> ZoneFileError {
    ZoneFileError::InvariantViolation(InvariantId::EncodedSize)
}

fn value_mismatch() -> ZoneFileError {
    corrupt_none(CorruptKind::Bounds, CorruptDetail::OffsetOutOfRange)
}

/// Проверяет payload `{u16 rdlength; rdata}*rr_count` (§11.2).
///
/// # Errors
///
/// `Corrupt(BadRdata)` — длины не сходятся, `sum(rdlength) != rdlen` или
/// `rdlength > 65535`.
pub fn validate_payload(payload: &[u8], rr_count: u16, rdlen: u16) -> Result<(), ZoneFileError> {
    let expected = usize::from(rr_count)
        .checked_mul(2)
        .and_then(|extra| usize::from(rdlen).checked_add(extra))
        .ok_or_else(|| corrupt_none(CorruptKind::BadRdata, CorruptDetail::RdataSum))?;
    if payload.len() != expected {
        return Err(corrupt_none(CorruptKind::BadRdata, CorruptDetail::RdataSum));
    }
    let mut offset = 0_usize;
    let mut sum = 0_usize;
    for _ in 0..rr_count {
        let length = usize::from(
            wire::read_u16_be(payload, offset)
                .ok_or_else(|| corrupt_none(CorruptKind::BadRdata, CorruptDetail::RdataSum))?,
        );
        let max_rdlength = usize::try_from(MAX_RDLENGTH)
            .map_err(|_| corrupt_none(CorruptKind::BadRdata, CorruptDetail::RdataSum))?;
        if length > max_rdlength {
            return Err(corrupt_none(CorruptKind::BadRdata, CorruptDetail::RdataSum));
        }
        offset = offset
            .checked_add(2)
            .and_then(|next| next.checked_add(length))
            .filter(|&next| next <= payload.len())
            .ok_or_else(|| corrupt_none(CorruptKind::BadRdata, CorruptDetail::RdataSum))?;
        sum = sum
            .checked_add(length)
            .ok_or_else(|| corrupt_none(CorruptKind::BadRdata, CorruptDetail::RdataSum))?;
    }
    if offset != payload.len() || sum != usize::from(rdlen) {
        return Err(corrupt_none(CorruptKind::BadRdata, CorruptDetail::RdataSum));
    }
    Ok(())
}

fn value_region_len_fast(key: &Key, value: &ItemValue) -> usize {
    match value {
        ItemValue::ZoneEntry(_) => ZONE_ENTRY_BYTES,
        ItemValue::Leaf { value, payload } => {
            if key.rr_type() == T_NODE || value.kind != ValueKind::Inline {
                LEAF_VALUE_BYTES
            } else {
                LEAF_VALUE_BYTES + payload.len()
            }
        }
    }
}

fn leaf_value_region_len(key: &Key, value: &ItemValue) -> Result<usize, ZoneFileError> {
    match key.rr_type() {
        T_ZONE_ENTRY => {
            if key.class() != 0 || key.subtype() != 0 {
                return Err(value_mismatch());
            }
            match value {
                ItemValue::ZoneEntry(_) => Ok(ZONE_ENTRY_BYTES),
                ItemValue::Leaf { .. } => Err(value_mismatch()),
            }
        }
        T_NODE => {
            if key.class() != 0 || key.subtype() != 0 {
                return Err(value_mismatch());
            }
            match value {
                ItemValue::Leaf { value, payload }
                    if value.kind == ValueKind::Node && payload.is_empty() =>
                {
                    Ok(LEAF_VALUE_BYTES)
                }
                _ => Err(value_mismatch()),
            }
        }
        _ => match value {
            ItemValue::Leaf { value, payload } => {
                value.validate()?;
                match value.kind {
                    ValueKind::Node => Err(value_mismatch()),
                    ValueKind::Inline => {
                        let expected = usize::try_from(value.payload_bytes()?)
                            .map_err(|_| encoded_too_large())?;
                        if payload.len() != expected {
                            return Err(corrupt_none(
                                CorruptKind::BadRdata,
                                CorruptDetail::RdataSum,
                            ));
                        }
                        Ok(LEAF_VALUE_BYTES + expected)
                    }
                    ValueKind::Overflow => {
                        if !payload.is_empty() {
                            return Err(value_mismatch());
                        }
                        Ok(LEAF_VALUE_BYTES)
                    }
                }
            }
            ItemValue::ZoneEntry(_) => Err(value_mismatch()),
        },
    }
}

fn shared_len_for(prev: Option<&Key>, index: usize, key: &Key, interval: usize) -> usize {
    let shared = match prev {
        _ if index.is_multiple_of(interval) => 0,
        Some(previous) => common_prefix(previous.as_bytes(), key.as_bytes()),
        None => 0,
    };
    shared.min(key.len().saturating_sub(1))
}

/// Длина item'а листа при фронт-кодировании (для инкрементального bulk load).
pub(crate) fn leaf_item_len(
    prev: Option<&Key>,
    index: usize,
    item: &LeafItem,
) -> Result<usize, ZoneFileError> {
    let shared = shared_len_for(prev, index, &item.key, LEAF_INTERVAL);
    let value_len = leaf_value_region_len(&item.key, &item.value)?;
    ITEM_HEADER_BYTES
        .checked_add(item.key.len() - shared)
        .and_then(|len| len.checked_add(value_len))
        .ok_or_else(encoded_too_large)
}

/// Длина item'а ветвления при фронт-кодировании.
pub(crate) fn branch_item_len(
    prev: Option<&Key>,
    index: usize,
    item: &BranchItem,
) -> Result<usize, ZoneFileError> {
    if item.child == 0 {
        return Err(corrupt_none(CorruptKind::Bounds, CorruptDetail::ChildRange));
    }
    let shared = shared_len_for(prev, index, &item.key, BRANCH_INTERVAL);
    ITEM_HEADER_BYTES
        .checked_add(item.key.len() - shared)
        .and_then(|len| len.checked_add(BRANCH_CHILD_BYTES))
        .ok_or_else(encoded_too_large)
}

fn common_prefix(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b.iter()).take_while(|(x, y)| x == y).count()
}

struct Layout {
    shared_len: usize,
    item_len: usize,
}

fn plan_leaf_inner(
    items: &[LeafItem],
    validate: bool,
) -> Result<(Vec<Layout>, u32), ZoneFileError> {
    let mut layouts = Vec::with_capacity(items.len());
    let mut total = 0_u32;
    let mut prev: Option<&Key> = None;
    for (index, item) in items.iter().enumerate() {
        if validate
            && let Some(previous) = prev
            && compare_validated(previous, &item.key) != Ordering::Less
        {
            return Err(invalid_order());
        }
        let mut shared_len = match prev {
            _ if index % LEAF_INTERVAL == 0 => 0,
            Some(previous) => common_prefix(previous.as_bytes(), item.key.as_bytes()),
            None => 0,
        };
        shared_len = shared_len.min(item.key.len().saturating_sub(1));
        let suffix_len = item
            .key
            .len()
            .checked_sub(shared_len)
            .filter(|&len| len >= 1)
            .ok_or_else(encoded_too_large)?;
        let value_len = if validate {
            leaf_value_region_len(&item.key, &item.value)?
        } else {
            value_region_len_fast(&item.key, &item.value)
        };
        let item_len = ITEM_HEADER_BYTES
            .checked_add(suffix_len)
            .and_then(|len| len.checked_add(value_len))
            .ok_or_else(encoded_too_large)?;
        total = total
            .checked_add(u32::try_from(item_len).map_err(|_| encoded_too_large())?)
            .ok_or_else(encoded_too_large)?;
        layouts.push(Layout {
            shared_len,
            item_len,
        });
        prev = Some(&item.key);
    }
    Ok((layouts, total))
}

fn plan_branch_inner(
    items: &[BranchItem],
    validate: bool,
) -> Result<(Vec<Layout>, u32), ZoneFileError> {
    let mut layouts = Vec::with_capacity(items.len());
    let mut total = 0_u32;
    let mut prev: Option<&Key> = None;
    for (index, item) in items.iter().enumerate() {
        if validate && item.child == 0 {
            return Err(corrupt_none(CorruptKind::Bounds, CorruptDetail::ChildRange));
        }
        if validate
            && let Some(previous) = prev
            && compare_validated(previous, &item.key) != Ordering::Less
        {
            return Err(invalid_order());
        }
        let mut shared_len = match prev {
            _ if index % BRANCH_INTERVAL == 0 => 0,
            Some(previous) => common_prefix(previous.as_bytes(), item.key.as_bytes()),
            None => 0,
        };
        shared_len = shared_len.min(item.key.len().saturating_sub(1));
        let suffix_len = item
            .key
            .len()
            .checked_sub(shared_len)
            .filter(|&len| len >= 1)
            .ok_or_else(encoded_too_large)?;
        let item_len = ITEM_HEADER_BYTES
            .checked_add(suffix_len)
            .and_then(|len| len.checked_add(BRANCH_CHILD_BYTES))
            .ok_or_else(encoded_too_large)?;
        total = total
            .checked_add(u32::try_from(item_len).map_err(|_| encoded_too_large())?)
            .ok_or_else(encoded_too_large)?;
        layouts.push(Layout {
            shared_len,
            item_len,
        });
        prev = Some(&item.key);
    }
    Ok((layouts, total))
}

fn restart_count(n_items: usize, interval: usize) -> usize {
    n_items.div_ceil(interval)
}

fn arrays_size(n_items: usize, n_restarts: usize) -> Result<usize, ZoneFileError> {
    n_restarts
        .checked_add(n_items)
        .and_then(|count| count.checked_mul(2))
        .and_then(|bytes| NODE_HEADER_BYTES.checked_add(bytes))
        .ok_or_else(encoded_too_large)
}

/// Вычисляет `encoded_size` листа без записи страницы.
///
/// # Errors
///
/// `InvariantViolation(KeyOrder)` — ключи не по возрастанию;
/// `InvariantViolation(EncodedSize)` — размер не помещается в `u32`;
/// `Corrupt` — значение не согласовано с типом ключа.
pub fn leaf_encoded_size(items: &[LeafItem]) -> Result<u32, ZoneFileError> {
    leaf_encoded_size_inner(items, true)
}

/// `encoded_size` без повторной валидации элементов (доверенный путь записи).
pub(crate) fn leaf_encoded_size_fast(items: &[LeafItem]) -> Result<u32, ZoneFileError> {
    leaf_encoded_size_inner(items, false)
}

fn leaf_encoded_size_inner(items: &[LeafItem], validate: bool) -> Result<u32, ZoneFileError> {
    let (_, total) = plan_leaf_inner(items, validate)?;
    let n_restarts = restart_count(items.len(), LEAF_INTERVAL);
    let arrays = arrays_size(items.len(), n_restarts)?;
    u32::try_from(arrays)
        .ok()
        .and_then(|arrays| arrays.checked_add(total))
        .ok_or_else(encoded_too_large)
}

/// Вычисляет `encoded_size` ветвления без записи страницы.
///
/// # Errors
///
/// `InvariantViolation(KeyOrder)` — ключи не по возрастанию;
/// `InvariantViolation(EncodedSize)` — размер не помещается в `u32`;
/// `Corrupt(Bounds)` — нулевой дочерний указатель.
pub fn branch_encoded_size(items: &[BranchItem]) -> Result<u32, ZoneFileError> {
    branch_encoded_size_inner(items, true)
}

/// `encoded_size` ветвления без повторной валидации.
pub(crate) fn branch_encoded_size_fast(items: &[BranchItem]) -> Result<u32, ZoneFileError> {
    branch_encoded_size_inner(items, false)
}

fn branch_encoded_size_inner(items: &[BranchItem], validate: bool) -> Result<u32, ZoneFileError> {
    let (_, total) = plan_branch_inner(items, validate)?;
    let n_restarts = restart_count(items.len(), BRANCH_INTERVAL);
    let arrays = arrays_size(items.len(), n_restarts)?;
    u32::try_from(arrays)
        .ok()
        .and_then(|arrays| arrays.checked_add(total))
        .ok_or_else(encoded_too_large)
}

pub(crate) fn write_page_header(
    page: &mut [u8],
    ctx: EncodeContext,
    page_type: u32,
    page_flags: u16,
) -> Result<(), ZoneFileError> {
    put_u32(page, PAGE_OFF_PAGE_TYPE, page_type)?;
    put_u16(page, PAGE_OFF_PAGE_FLAGS, page_flags)?;
    put_u16(page, PAGE_OFF_RESERVED0, 0)?;
    put_u32(page, PAGE_OFF_PAGE_NO, ctx.page_no)?;
    put_u32(page, PAGE_OFF_RESERVED1, 0)?;
    put_u64(page, PAGE_OFF_TXN, ctx.txn)?;
    put_u64(page, PAGE_OFF_LSN, ctx.lsn)?;
    put_u32(page, PAGE_OFF_CRC32C, 0)?;
    put_u32(page, PAGE_OFF_PAYLOAD_LEN, ctx.page_size)
}

fn put_u64(out: &mut [u8], off: usize, value: u64) -> Result<(), ZoneFileError> {
    let dst = out
        .get_mut(off..off + 8)
        .ok_or_else(|| corrupt_none(CorruptKind::Bounds, CorruptDetail::OffsetOutOfRange))?;
    dst.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

pub(crate) fn finish_page(page: &mut [u8], page_size: usize) -> Result<(), ZoneFileError> {
    let crc = checksum::page_crc32c(
        page.get(..page_size).ok_or_else(truncated)?,
        PAGE_OFF_CRC32C,
    )
    .ok_or_else(truncated)?;
    put_u32(page, PAGE_OFF_CRC32C, crc)
}

fn begin_page(page: &mut [u8], ctx: EncodeContext) -> Result<(), ZoneFileError> {
    let page_size = usize::try_from(ctx.page_size).map_err(|_| encoded_too_large())?;
    let dst = page.get_mut(..page_size).ok_or_else(encoded_too_large)?;
    dst.fill(0);
    Ok(())
}

fn finish_node(
    page: &mut [u8],
    ctx: EncodeContext,
    layout: &[Layout],
    items_start: usize,
    interval: usize,
    level: u16,
) -> Result<EncodedNode, ZoneFileError> {
    let page_size = usize::try_from(ctx.page_size).map_err(|_| encoded_too_large())?;
    let n_items = layout.len();
    let n_restarts = restart_count(n_items, interval);
    let arrays = arrays_size(n_items, n_restarts)?;
    if items_start < arrays || items_start > page_size {
        return Err(encoded_too_large());
    }
    let total_items = layout
        .iter()
        .try_fold(0_usize, |sum, item| sum.checked_add(item.item_len))
        .ok_or_else(encoded_too_large)?;
    let encoded_size = arrays
        .checked_add(total_items)
        .filter(|&size| size <= page_size)
        .ok_or_else(encoded_too_large)?;
    let n_items_u16 = u16::try_from(n_items).map_err(|_| encoded_too_large())?;
    let n_restarts_u16 = u16::try_from(n_restarts).map_err(|_| encoded_too_large())?;
    let free_bytes = page_size - encoded_size;

    let mut offset = items_start;
    let restart_base = NODE_HEADER_BYTES;
    let slot_base = restart_base + 2 * n_restarts;
    for (index, item) in layout.iter().enumerate() {
        put_u16(
            page,
            slot_base + 2 * index,
            u16::try_from(offset).map_err(|_| encoded_too_large())?,
        )?;
        if index % interval == 0 {
            put_u16(
                page,
                restart_base + 2 * (index / interval),
                u16::try_from(offset).map_err(|_| encoded_too_large())?,
            )?;
        }
        offset += item.item_len;
    }
    put_u16(page, 40, level)?;
    put_u16(page, 42, n_items_u16)?;
    put_u16(page, 44, n_restarts_u16)?;
    put_u16(page, 46, NODE_FLAG_SORTED_VALIDATED)?;
    put_u32(
        page,
        PAGE_HEADER_SIZE as usize + 8,
        u32::try_from(free_bytes).map_err(|_| encoded_too_large())?,
    )?;
    put_u32(
        page,
        PAGE_HEADER_SIZE as usize + 12,
        u32::try_from(items_start).map_err(|_| encoded_too_large())?,
    )?;
    if offset != page_size {
        return Err(encoded_too_large());
    }
    Ok(EncodedNode {
        encoded_size: u32::try_from(encoded_size).map_err(|_| encoded_too_large())?,
        free_bytes: u32::try_from(free_bytes).map_err(|_| encoded_too_large())?,
        n_items: n_items_u16,
        n_restarts: n_restarts_u16,
    })
}

/// Кодирует лист в страницу целиком, включая `PageHeader` и CRC.
///
/// # Errors
///
/// `InvariantViolation(KeyOrder)` — ключи не по возрастанию;
/// `InvariantViolation(EncodedSize)` — узел не помещается в страницу;
/// `Corrupt` — значение не согласовано с типом ключа.
pub fn encode_leaf(
    page: &mut [u8],
    ctx: EncodeContext,
    items: &[LeafItem],
) -> Result<EncodedNode, ZoneFileError> {
    encode_leaf_inner(page, ctx, items, true)
}

/// Кодирование листа без повторной валидации (доверенный путь записи).
pub(crate) fn encode_leaf_trusted(
    page: &mut [u8],
    ctx: EncodeContext,
    items: &[LeafItem],
) -> Result<EncodedNode, ZoneFileError> {
    encode_leaf_inner(page, ctx, items, false)
}

fn encode_leaf_inner(
    page: &mut [u8],
    ctx: EncodeContext,
    items: &[LeafItem],
    validate: bool,
) -> Result<EncodedNode, ZoneFileError> {
    let page_size = usize::try_from(ctx.page_size).map_err(|_| encoded_too_large())?;
    let (layout, total) = plan_leaf_inner(items, validate)?;
    let n_restarts = restart_count(items.len(), LEAF_INTERVAL);
    let arrays = arrays_size(items.len(), n_restarts)?;
    let items_start = page_size
        .checked_sub(usize::try_from(total).map_err(|_| encoded_too_large())?)
        .filter(|&start| start >= arrays)
        .ok_or_else(encoded_too_large)?;
    begin_page(page, ctx)?;

    let page_flags = {
        let mut flags = 0_u16;
        if layout.iter().any(|item| item.shared_len > 0) {
            flags |= PAGE_FLAG_FRONT_CODED;
        }
        if items.iter().any(|item| {
            item.value
                .leaf_value()
                .is_some_and(|v| v.kind == ValueKind::Overflow)
        }) {
            flags |= PAGE_FLAG_HAS_OVERFLOW;
        }
        flags
    };
    write_page_header(page, ctx, PAGE_TYPE_LEAF, page_flags)?;

    let mut offset = items_start;
    for (item, plan) in items.iter().zip(layout.iter()) {
        let suffix_start = offset
            .checked_add(ITEM_HEADER_BYTES)
            .ok_or_else(encoded_too_large)?;
        let suffix_end = suffix_start
            .checked_add(item.key.len() - plan.shared_len)
            .ok_or_else(encoded_too_large)?;
        put_u16(
            page,
            offset,
            u16::try_from(plan.shared_len).map_err(|_| encoded_too_large())?,
        )?;
        put_u16(
            page,
            offset + 2,
            u16::try_from(item.key.len() - plan.shared_len).map_err(|_| encoded_too_large())?,
        )?;
        let suffix = item
            .key
            .as_bytes()
            .get(plan.shared_len..)
            .ok_or_else(encoded_too_large)?;
        page.get_mut(suffix_start..suffix_end)
            .ok_or_else(encoded_too_large)?
            .copy_from_slice(suffix);
        write_item_value(page, suffix_end, &item.value)?;
        offset += plan.item_len;
    }
    let encoded = finish_node(page, ctx, &layout, items_start, LEAF_INTERVAL, 0)?;
    finish_page(page, page_size)?;
    Ok(encoded)
}

fn write_item_value(
    page: &mut [u8],
    offset: usize,
    value: &ItemValue,
) -> Result<(), ZoneFileError> {
    match value {
        ItemValue::ZoneEntry(bytes) => {
            page.get_mut(offset..offset + ZONE_ENTRY_BYTES)
                .ok_or_else(encoded_too_large)?
                .copy_from_slice(bytes);
        }
        ItemValue::Leaf { value, payload } => {
            let head = page
                .get_mut(offset..offset + LEAF_VALUE_BYTES)
                .ok_or_else(encoded_too_large)?;
            value.encode(head)?;
            if !payload.is_empty() {
                page.get_mut(offset + LEAF_VALUE_BYTES..offset + LEAF_VALUE_BYTES + payload.len())
                    .ok_or_else(encoded_too_large)?
                    .copy_from_slice(payload);
            }
        }
    }
    Ok(())
}

/// Кодирует ветвление в страницу целиком, включая `PageHeader` и CRC.
///
/// # Errors
///
/// `InvariantViolation(KeyOrder)` — ключи не по возрастанию;
/// `InvariantViolation(EncodedSize)` — узел не помещается в страницу;
/// `Corrupt(Bounds)` — нулевой дочерний указатель.
pub fn encode_branch(
    page: &mut [u8],
    ctx: EncodeContext,
    level: u16,
    items: &[BranchItem],
) -> Result<EncodedNode, ZoneFileError> {
    encode_branch_inner(page, ctx, level, items, true)
}

/// Кодирование ветвления без повторной валидации.
pub(crate) fn encode_branch_trusted(
    page: &mut [u8],
    ctx: EncodeContext,
    level: u16,
    items: &[BranchItem],
) -> Result<EncodedNode, ZoneFileError> {
    encode_branch_inner(page, ctx, level, items, false)
}

fn encode_branch_inner(
    page: &mut [u8],
    ctx: EncodeContext,
    level: u16,
    items: &[BranchItem],
    validate: bool,
) -> Result<EncodedNode, ZoneFileError> {
    if level == 0 || level > MAX_TREE_DEPTH {
        return Err(ZoneFileError::InvariantViolation(
            InvariantId::DepthExceeded,
        ));
    }
    let page_size = usize::try_from(ctx.page_size).map_err(|_| encoded_too_large())?;
    let (layout, total) = plan_branch_inner(items, validate)?;
    let n_restarts = restart_count(items.len(), BRANCH_INTERVAL);
    let arrays = arrays_size(items.len(), n_restarts)?;
    let items_start = page_size
        .checked_sub(usize::try_from(total).map_err(|_| encoded_too_large())?)
        .filter(|&start| start >= arrays)
        .ok_or_else(encoded_too_large)?;
    begin_page(page, ctx)?;
    let page_flags = if layout.iter().any(|item| item.shared_len > 0) {
        PAGE_FLAG_FRONT_CODED
    } else {
        0
    };
    write_page_header(page, ctx, PAGE_TYPE_BRANCH, page_flags)?;

    let mut offset = items_start;
    for (item, plan) in items.iter().zip(layout.iter()) {
        let suffix_start = offset
            .checked_add(ITEM_HEADER_BYTES)
            .ok_or_else(encoded_too_large)?;
        let suffix = item
            .key
            .as_bytes()
            .get(plan.shared_len..)
            .ok_or_else(encoded_too_large)?;
        put_u16(
            page,
            offset,
            u16::try_from(plan.shared_len).map_err(|_| encoded_too_large())?,
        )?;
        put_u16(
            page,
            offset + 2,
            u16::try_from(suffix.len()).map_err(|_| encoded_too_large())?,
        )?;
        page.get_mut(suffix_start..suffix_start + suffix.len())
            .ok_or_else(encoded_too_large)?
            .copy_from_slice(suffix);
        put_u32(page, suffix_start + suffix.len(), item.child)?;
        offset += plan.item_len;
    }
    let encoded = finish_node(page, ctx, &layout, items_start, BRANCH_INTERVAL, level)?;
    finish_page(page, page_size)?;
    Ok(encoded)
}

/// Заголовок узла (16 байт после `PageHeader`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeHeader {
    /// Уровень узла: 0 — лист, `> 0` — ветвление.
    pub level: u16,
    /// Число item'ов.
    pub n_items: u16,
    /// Число restart-точек.
    pub n_restarts: u16,
    /// Флаги узла.
    pub node_flags: u16,
    /// Свободные байты страницы.
    pub free_bytes: u32,
    /// Первый байт области item'ов.
    pub items_start: u32,
}

#[derive(Debug, Clone, Copy)]
struct ItemParts<'a> {
    slot: usize,
    shared_len: usize,
    suffix: &'a [u8],
    value_off: usize,
    end: usize,
}

/// Собирает ключ item'а во фронт-кодированный буфер.
///
/// `buffer[..shared_len]` уже содержит общий префикс (хвост предыдущего ключа
/// группы); функция дописывает суффикс. Сам [`Key`] не материализуется.
fn assemble_key_bytes(
    prev_len: usize,
    parts: &ItemParts<'_>,
    buffer: &mut [u8; KEY_MAX],
) -> Result<usize, ZoneFileError> {
    let total = parts
        .shared_len
        .checked_add(parts.suffix.len())
        .filter(|&total| total <= KEY_MAX && parts.shared_len <= prev_len)
        .ok_or_else(|| corrupt(None, CorruptKind::Bounds, CorruptDetail::OffsetOutOfRange))?;
    buffer
        .get_mut(parts.shared_len..total)
        .ok_or_else(|| corrupt(None, CorruptKind::Bounds, CorruptDetail::OffsetOutOfRange))?
        .copy_from_slice(parts.suffix);
    Ok(total)
}

#[derive(Debug, Clone)]
struct RawNode<'a> {
    page: &'a [u8],
    page_size: usize,
    page_no: u32,
    header: NodeHeader,
    interval: usize,
    slots: [u16; MAX_ITEMS_PER_PAGE],
    restarts: [u16; MAX_RESTARTS_PER_PAGE],
    name_lens: [u8; MAX_ITEMS_PER_PAGE],
    zone_entry: [u64; MAX_ZONE_BITS],
}

const MAX_ZONE_BITS: usize = MAX_ITEMS_PER_PAGE / 64;

const MAX_ITEMS_PER_PAGE: usize = 1024;
const MAX_RESTARTS_PER_PAGE: usize = MAX_ITEMS_PER_PAGE;

impl<'a> RawNode<'a> {
    #[allow(clippy::too_many_lines)]
    fn decode(
        page: &'a [u8],
        page_no: u32,
        page_size: u32,
        expected_level: u16,
        interval: usize,
    ) -> Result<Self, ZoneFileError> {
        let page_size_usize = usize::try_from(page_size).map_err(|_| encoded_too_large())?;
        let data = page
            .get(..page_size_usize)
            .ok_or_else(|| corrupt(Some(page_no), CorruptKind::Bounds, CorruptDetail::Truncated))?;
        let level = get_u16(data, 40, page_no)?;
        let n_items = get_u16(data, 42, page_no)?;
        let n_restarts = get_u16(data, 44, page_no)?;
        let node_flags = get_u16(data, 46, page_no)?;
        let free_bytes = get_u32(data, 48, page_no)?;
        let items_start = get_u32(data, 52, page_no)?;
        if level != expected_level || node_flags & !NODE_FLAG_KNOWN != 0 {
            return Err(corrupt(
                Some(page_no),
                CorruptKind::Bounds,
                CorruptDetail::OffsetOutOfRange,
            ));
        }
        if (expected_level == 0 && interval != LEAF_INTERVAL)
            || (expected_level > 0 && interval != BRANCH_INTERVAL)
        {
            return Err(corrupt(
                Some(page_no),
                CorruptKind::Bounds,
                CorruptDetail::PageType,
            ));
        }
        if expected_level > MAX_TREE_DEPTH {
            return Err(corrupt(
                Some(page_no),
                CorruptKind::Bounds,
                CorruptDetail::DepthExceeded,
            ));
        }
        let n_items_usize = usize::from(n_items);
        let n_restarts_usize = usize::from(n_restarts);
        if n_items_usize > MAX_ITEMS_PER_PAGE || n_restarts_usize > MAX_RESTARTS_PER_PAGE {
            return Err(corrupt(
                Some(page_no),
                CorruptKind::Bounds,
                CorruptDetail::OffsetOutOfRange,
            ));
        }
        if n_restarts_usize != restart_count(n_items_usize, interval) {
            return Err(corrupt(
                Some(page_no),
                CorruptKind::Bounds,
                CorruptDetail::OffsetOutOfRange,
            ));
        }
        let arrays = arrays_size(n_items_usize, n_restarts_usize).map_err(|_| {
            corrupt(
                Some(page_no),
                CorruptKind::Bounds,
                CorruptDetail::OffsetOutOfRange,
            )
        })?;
        let items_start_usize = usize::try_from(items_start).map_err(|_| {
            corrupt(
                Some(page_no),
                CorruptKind::Bounds,
                CorruptDetail::OffsetOutOfRange,
            )
        })?;
        if items_start_usize < arrays || items_start_usize > page_size_usize {
            return Err(corrupt(
                Some(page_no),
                CorruptKind::Bounds,
                CorruptDetail::OffsetOutOfRange,
            ));
        }
        if n_items_usize == 0 {
            if free_bytes != page_size.saturating_sub(NODE_HEADER_SIZE) {
                return Err(corrupt(
                    Some(page_no),
                    CorruptKind::Bounds,
                    CorruptDetail::OffsetOutOfRange,
                ));
            }
            return Ok(Self {
                page: data,
                page_size: page_size_usize,
                page_no,
                header: NodeHeader {
                    level,
                    n_items,
                    n_restarts,
                    node_flags,
                    free_bytes,
                    items_start,
                },
                interval,
                slots: [0; MAX_ITEMS_PER_PAGE],
                restarts: [0; MAX_RESTARTS_PER_PAGE],
                name_lens: [0; MAX_ITEMS_PER_PAGE],
                zone_entry: [0; MAX_ZONE_BITS],
            });
        }

        let restart_base = NODE_HEADER_BYTES;
        let slot_base = restart_base + 2 * n_restarts_usize;
        let mut slots = [0_u16; MAX_ITEMS_PER_PAGE];
        let mut restarts = [0_u16; MAX_RESTARTS_PER_PAGE];
        let mut previous = None;
        for index in 0..n_restarts_usize {
            let value = get_u16(data, restart_base + 2 * index, page_no)?;
            let value_usize = usize::from(value);
            if value_usize < items_start_usize || value_usize >= page_size_usize {
                return Err(corrupt(
                    Some(page_no),
                    CorruptKind::Bounds,
                    CorruptDetail::OffsetOutOfRange,
                ));
            }
            if let Some(previous) = previous
                && value <= previous
            {
                return Err(corrupt(
                    Some(page_no),
                    CorruptKind::TreeOrder,
                    CorruptDetail::KeyOrder,
                ));
            }
            previous = Some(value);
            if let Some(slot) = restarts.get_mut(index) {
                *slot = value;
            }
        }
        let mut previous = None;
        for index in 0..n_items_usize {
            let value = get_u16(data, slot_base + 2 * index, page_no)?;
            let value_usize = usize::from(value);
            if value_usize < items_start_usize || value_usize >= page_size_usize {
                return Err(corrupt(
                    Some(page_no),
                    CorruptKind::Bounds,
                    CorruptDetail::OffsetOutOfRange,
                ));
            }
            if let Some(previous) = previous
                && value <= previous
            {
                return Err(corrupt(
                    Some(page_no),
                    CorruptKind::TreeOrder,
                    CorruptDetail::KeyOrder,
                ));
            }
            previous = Some(value);
            if let Some(slot) = slots.get_mut(index) {
                *slot = value;
            }
        }
        if usize::from(slots.first().copied().unwrap_or(0)) != items_start_usize
            || usize::from(restarts.first().copied().unwrap_or(0)) != items_start_usize
        {
            return Err(corrupt(
                Some(page_no),
                CorruptKind::Bounds,
                CorruptDetail::OffsetOutOfRange,
            ));
        }
        for index in 0..n_restarts_usize {
            let expected = slots.get(index * interval).copied().unwrap_or(0);
            if restarts.get(index).copied().unwrap_or(0) != expected {
                return Err(corrupt(
                    Some(page_no),
                    CorruptKind::Bounds,
                    CorruptDetail::OffsetOutOfRange,
                ));
            }
        }
        Ok(Self {
            page: data,
            page_size: page_size_usize,
            page_no,
            header: NodeHeader {
                level,
                n_items,
                n_restarts,
                node_flags,
                free_bytes,
                items_start,
            },
            interval,
            slots,
            restarts,
            name_lens: [0; MAX_ITEMS_PER_PAGE],
            zone_entry: [0; MAX_ZONE_BITS],
        })
    }

    fn n_items(&self) -> usize {
        usize::from(self.header.n_items)
    }

    fn n_restarts(&self) -> usize {
        usize::from(self.header.n_restarts)
    }

    fn slot(&self, index: usize) -> u16 {
        self.slots.get(index).copied().unwrap_or(0)
    }

    fn restart(&self, index: usize) -> u16 {
        self.restarts.get(index).copied().unwrap_or(0)
    }

    fn item_parts(&self, index: usize) -> Result<ItemParts<'a>, ZoneFileError> {
        if index >= self.n_items() {
            return Err(corrupt(
                Some(self.page_no),
                CorruptKind::Bounds,
                CorruptDetail::OffsetOutOfRange,
            ));
        }
        let slot = usize::from(self.slot(index));
        let end = if index + 1 < self.n_items() {
            usize::from(self.slot(index + 1))
        } else {
            self.page_size
        };
        let shared_len = usize::from(get_u16(self.page, slot, self.page_no)?);
        let suffix_len = usize::from(get_u16(self.page, slot + 2, self.page_no)?);
        if suffix_len == 0 {
            return Err(corrupt(
                Some(self.page_no),
                CorruptKind::Bounds,
                CorruptDetail::OffsetOutOfRange,
            ));
        }
        let suffix_start = slot.checked_add(ITEM_HEADER_BYTES).ok_or_else(|| {
            corrupt(
                Some(self.page_no),
                CorruptKind::Bounds,
                CorruptDetail::OffsetOutOfRange,
            )
        })?;
        let value_off = suffix_start
            .checked_add(suffix_len)
            .filter(|&off| off <= end)
            .ok_or_else(|| {
                corrupt(
                    Some(self.page_no),
                    CorruptKind::Bounds,
                    CorruptDetail::OffsetOutOfRange,
                )
            })?;
        if index.is_multiple_of(self.interval) && shared_len != 0 {
            return Err(corrupt(
                Some(self.page_no),
                CorruptKind::Bounds,
                CorruptDetail::OffsetOutOfRange,
            ));
        }
        let suffix = self.page.get(suffix_start..value_off).ok_or_else(|| {
            corrupt(
                Some(self.page_no),
                CorruptKind::Bounds,
                CorruptDetail::Truncated,
            )
        })?;
        Ok(ItemParts {
            slot,
            shared_len,
            suffix,
            value_off,
            end,
        })
    }

    fn name_len_at(&self, index: usize) -> Result<usize, ZoneFileError> {
        self.name_lens
            .get(index)
            .copied()
            .filter(|&len| len != 0)
            .map(usize::from)
            .ok_or_else(|| {
                corrupt(
                    Some(self.page_no),
                    CorruptKind::Bounds,
                    CorruptDetail::OffsetOutOfRange,
                )
            })
    }

    fn walk_group<F>(
        &self,
        group: usize,
        mut compare: F,
        strict: bool,
    ) -> Result<usize, ZoneFileError>
    where
        F: FnMut(&[u8], usize) -> Result<Ordering, ZoneFileError>,
    {
        let start = group.saturating_mul(self.interval);
        let end = (start + self.interval).min(self.n_items());
        let mut buffer = [0_u8; KEY_MAX];
        let mut prev_len = 0_usize;
        let mut index = start;
        while index < end {
            let parts = self.item_parts(index)?;
            prev_len = assemble_key_bytes(prev_len, &parts, &mut buffer)?;
            let name_len = self.name_len_at(index)?;
            let order = compare(buffer.get(..prev_len).unwrap_or(&[]), name_len)?;
            let matched = if strict {
                order == Ordering::Greater
            } else {
                order != Ordering::Less
            };
            if matched {
                return Ok(index);
            }
            index += 1;
        }
        Ok(end)
    }

    fn bound_by<F>(&self, mut compare: F, strict: bool) -> Result<usize, ZoneFileError>
    where
        F: FnMut(&[u8], usize) -> Result<Ordering, ZoneFileError>,
    {
        if self.n_items() == 0 {
            return Ok(0);
        }
        let mut low = 0_usize;
        let mut high = self.n_restarts();
        while low < high {
            let middle = low + (high - low) / 2;
            let (bytes, name_len) = self.restart_bytes(middle)?;
            let order = compare(bytes, name_len)?;
            let matched = if strict {
                order == Ordering::Greater
            } else {
                order != Ordering::Less
            };
            if matched {
                high = middle;
            } else {
                low = middle + 1;
            }
        }
        let group = low.saturating_sub(1);
        self.walk_group(group, compare, strict)
    }

    fn restart_bytes(&self, restart: usize) -> Result<(&'a [u8], usize), ZoneFileError> {
        let slot = usize::from(self.restart(restart));
        let shared_len = usize::from(get_u16(self.page, slot, self.page_no)?);
        let suffix_len = usize::from(get_u16(self.page, slot + 2, self.page_no)?);
        let start = slot + ITEM_HEADER_BYTES;
        let suffix = self.page.get(start..start + suffix_len).ok_or_else(|| {
            corrupt(
                Some(self.page_no),
                CorruptKind::Bounds,
                CorruptDetail::Truncated,
            )
        })?;
        if shared_len != 0 {
            return Err(corrupt(
                Some(self.page_no),
                CorruptKind::TreeOrder,
                CorruptDetail::KeyOrder,
            ));
        }
        let item_index = restart.saturating_mul(self.interval);
        let name_len = self.name_len_at(item_index)?;
        Ok((suffix, name_len))
    }

    fn key_bytes_at(
        &self,
        index: usize,
        buffer: &mut [u8; KEY_MAX],
    ) -> Result<usize, ZoneFileError> {
        let group = index / self.interval * self.interval;
        let mut prev_len = 0_usize;
        for position in group..=index {
            let parts = self.item_parts(position)?;
            prev_len = assemble_key_bytes(prev_len, &parts, buffer)?;
        }
        Ok(prev_len)
    }

    fn key_at(&self, index: usize) -> Result<Key, ZoneFileError> {
        let mut buffer = [0_u8; KEY_MAX];
        let len = self.key_bytes_at(index, &mut buffer)?;
        Key::from_validated(buffer.get(..len).unwrap_or(&[])).ok_or_else(|| {
            corrupt(
                Some(self.page_no),
                CorruptKind::Bounds,
                CorruptDetail::KeyOrder,
            )
        })
    }

    fn check_payload_sum(
        &self,
        parts: &ItemParts<'a>,
        value: &LeafValue,
    ) -> Result<usize, ZoneFileError> {
        match value.kind {
            ValueKind::Inline => {
                let payload_bytes = usize::try_from(value.payload_bytes()?).map_err(|_| {
                    corrupt(
                        Some(self.page_no),
                        CorruptKind::BadRdata,
                        CorruptDetail::RdataSum,
                    )
                })?;
                let payload_end = parts
                    .value_off
                    .checked_add(LEAF_VALUE_BYTES)
                    .and_then(|end| end.checked_add(payload_bytes))
                    .filter(|&end| end <= parts.end)
                    .ok_or_else(|| {
                        corrupt(
                            Some(self.page_no),
                            CorruptKind::BadRdata,
                            CorruptDetail::RdataSum,
                        )
                    })?;
                let payload = self
                    .page
                    .get(parts.value_off + LEAF_VALUE_BYTES..payload_end)
                    .ok_or_else(|| {
                        corrupt(
                            Some(self.page_no),
                            CorruptKind::BadRdata,
                            CorruptDetail::RdataSum,
                        )
                    })?;
                validate_payload(payload, value.rr_count, value.rdlen).map_err(|_| {
                    corrupt(
                        Some(self.page_no),
                        CorruptKind::BadRdata,
                        CorruptDetail::RdataSum,
                    )
                })?;
                Ok(LEAF_VALUE_BYTES + payload_bytes)
            }
            ValueKind::Node | ValueKind::Overflow => Ok(LEAF_VALUE_BYTES),
        }
    }

    /// Проверяет элементы листа и собирает `OrderKey` за один проход.
    ///
    /// Ключ собирается в стек-буфер как `RLE(name) || type || class || subtype`
    /// без материализации [`Key`]; порядок проверяется по сырым байтам.
    fn validate_leaf_items(&mut self) -> Result<Box<[OrderKey]>, ZoneFileError> {
        let count = self.n_items();
        let mut order_keys = vec![OrderKey::default(); count].into_boxed_slice();
        let mut current = [0_u8; KEY_MAX];
        let mut previous = [0_u8; KEY_MAX];
        let mut previous_len = 0_usize;
        let mut previous_name_len = 0_usize;
        let mut sum = 0_usize;
        for index in 0..count {
            let parts = self.item_parts(index)?;
            let len = assemble_key_bytes(previous_len, &parts, &mut current)?;
            let bytes = current.get(..len).unwrap_or(&[]);
            let (name_len, rr_type, class, subtype) = self.validate_item_key(
                index,
                bytes,
                &mut order_keys,
                previous.get(..previous_len).unwrap_or(&[]),
                previous_name_len,
            )?;
            let value_len = if rr_type == T_ZONE_ENTRY {
                if class != 0 || subtype != 0 {
                    return Err(value_mismatch());
                }
                if let Some(word) = self.zone_entry.get_mut(index / 64) {
                    *word |= 1_u64 << (index % 64);
                }
                ZONE_ENTRY_BYTES
            } else {
                let head = self
                    .page
                    .get(parts.value_off..parts.value_off + LEAF_VALUE_BYTES)
                    .ok_or_else(|| {
                        corrupt(
                            Some(self.page_no),
                            CorruptKind::Bounds,
                            CorruptDetail::Truncated,
                        )
                    })?;
                let value = LeafValue::decode(head).map_err(|error| match error {
                    ZoneFileError::Corrupt { kind, detail, .. } => {
                        corrupt(Some(self.page_no), kind, detail)
                    }
                    other => other,
                })?;
                match (rr_type, value.kind) {
                    (T_NODE, ValueKind::Node) => {
                        if class != 0 || subtype != 0 {
                            return Err(value_mismatch());
                        }
                    }
                    (T_NODE, _) | (_, ValueKind::Node) => return Err(value_mismatch()),
                    _ => {}
                }
                self.check_payload_sum(&parts, &value)?
            };
            sum = self.add_item_len(sum, &parts, value_len)?;
            previous
                .get_mut(..len)
                .ok_or_else(|| corrupt(None, CorruptKind::Bounds, CorruptDetail::OffsetOutOfRange))?
                .copy_from_slice(bytes);
            previous_len = len;
            previous_name_len = name_len;
        }
        self.check_free_bytes(sum)?;
        Ok(order_keys)
    }

    fn validate_branch_items(&mut self) -> Result<Box<[OrderKey]>, ZoneFileError> {
        let count = self.n_items();
        let mut order_keys = vec![OrderKey::default(); count].into_boxed_slice();
        let mut current = [0_u8; KEY_MAX];
        let mut previous = [0_u8; KEY_MAX];
        let mut previous_len = 0_usize;
        let mut previous_name_len = 0_usize;
        let mut sum = 0_usize;
        for index in 0..count {
            let parts = self.item_parts(index)?;
            let len = assemble_key_bytes(previous_len, &parts, &mut current)?;
            let bytes = current.get(..len).unwrap_or(&[]);
            let (name_len, _rr_type, _class, _subtype) = self.validate_item_key(
                index,
                bytes,
                &mut order_keys,
                previous.get(..previous_len).unwrap_or(&[]),
                previous_name_len,
            )?;
            let child = get_u32(self.page, parts.value_off, self.page_no)?;
            if child == 0 {
                return Err(corrupt(
                    Some(self.page_no),
                    CorruptKind::Bounds,
                    CorruptDetail::ChildRange,
                ));
            }
            sum = self.add_item_len(sum, &parts, BRANCH_CHILD_BYTES)?;
            previous
                .get_mut(..len)
                .ok_or_else(|| corrupt(None, CorruptKind::Bounds, CorruptDetail::OffsetOutOfRange))?
                .copy_from_slice(bytes);
            previous_len = len;
            previous_name_len = name_len;
        }
        self.check_free_bytes(sum)?;
        Ok(order_keys)
    }

    /// Проверяет ключ item'а, заполняет `name_lens`/`order_keys` и порядок.
    fn validate_item_key(
        &mut self,
        index: usize,
        bytes: &[u8],
        order_keys: &mut [OrderKey],
        previous: &[u8],
        previous_name_len: usize,
    ) -> Result<(usize, u16, u16, u16), ZoneFileError> {
        let name_len = name_len_unchecked(bytes);
        if name_len + KEY_TAIL_SIZE != bytes.len() {
            return Err(corrupt(
                Some(self.page_no),
                CorruptKind::Bounds,
                CorruptDetail::KeyOrder,
            ));
        }
        validate_name_rle(bytes.get(..name_len).unwrap_or(&[]), true)?;
        let current_order = OrderKey::from_validated(bytes, name_len);
        if index > 0 {
            let previous_order = order_keys.get(index - 1).copied().unwrap_or_default();
            match previous_order.cmp(&current_order) {
                Ordering::Less => {}
                Ordering::Greater => {
                    return Err(corrupt(
                        Some(self.page_no),
                        CorruptKind::TreeOrder,
                        CorruptDetail::KeyOrder,
                    ));
                }
                Ordering::Equal => {
                    // Префикс не различает ключи (имя длиннее `ORDER_KEY_BYTES`):
                    // сравниваем полностью, чтобы поймать равные/обратные ключи.
                    if compare_raw_keys(previous, previous_name_len, bytes, name_len)
                        != Ordering::Less
                    {
                        return Err(corrupt(
                            Some(self.page_no),
                            CorruptKind::TreeOrder,
                            CorruptDetail::KeyOrder,
                        ));
                    }
                }
            }
        }
        if let Some(slot) = self.name_lens.get_mut(index) {
            *slot = u8::try_from(name_len).map_err(|_| {
                corrupt(
                    Some(self.page_no),
                    CorruptKind::BadName,
                    CorruptDetail::BadNameEncoding,
                )
            })?;
        }
        if let Some(slot) = order_keys.get_mut(index) {
            *slot = current_order;
        }
        let tail = |offset: usize| {
            wire::read_u16(bytes, name_len + offset).ok_or_else(|| {
                corrupt(
                    Some(self.page_no),
                    CorruptKind::Bounds,
                    CorruptDetail::KeyOrder,
                )
            })
        };
        Ok((name_len, tail(0)?, tail(2)?, tail(4)?))
    }

    fn add_item_len(
        &self,
        sum: usize,
        parts: &ItemParts<'_>,
        value_len: usize,
    ) -> Result<usize, ZoneFileError> {
        let item_len = parts
            .value_off
            .checked_sub(parts.slot)
            .and_then(|len| len.checked_add(value_len))
            .filter(|&len| parts.slot + len <= parts.end)
            .ok_or_else(|| {
                corrupt(
                    Some(self.page_no),
                    CorruptKind::Bounds,
                    CorruptDetail::OffsetOutOfRange,
                )
            })?;
        sum.checked_add(item_len).ok_or_else(|| {
            corrupt(
                Some(self.page_no),
                CorruptKind::Bounds,
                CorruptDetail::OffsetOutOfRange,
            )
        })
    }

    fn check_free_bytes(&self, item_sum: usize) -> Result<(), ZoneFileError> {
        let encoded = arrays_size(self.n_items(), self.n_restarts())?
            .checked_add(item_sum)
            .ok_or_else(|| {
                corrupt(
                    Some(self.page_no),
                    CorruptKind::Bounds,
                    CorruptDetail::OffsetOutOfRange,
                )
            })?;
        let expected_free = self.page_size.checked_sub(encoded).ok_or_else(|| {
            corrupt(
                Some(self.page_no),
                CorruptKind::Bounds,
                CorruptDetail::OffsetOutOfRange,
            )
        })?;
        if expected_free != usize::try_from(self.header.free_bytes).unwrap_or(usize::MAX) {
            return Err(corrupt(
                Some(self.page_no),
                CorruptKind::Bounds,
                CorruptDetail::OffsetOutOfRange,
            ));
        }
        Ok(())
    }
}

/// Декодированный лист с валидацией всех инвариантов страницы.
#[derive(Debug, Clone)]
pub struct DecodedLeaf<'a> {
    raw: RawNode<'a>,
}

impl<'a> DecodedLeaf<'a> {
    /// Декодирует и валидирует лист.
    ///
    /// Проверки: `PageHeader` (§7), заголовок узла, `n_restarts`, границы
    /// массивов и item'ов, монотонность слотов/restart'ов, `shared_len ≤`
    /// длины предыдущего ключа, RLE-валидность **до** сравнения, порядок
    /// ключей, согласованность значения с типом ключа, `sum(rdlength) == rdlen`
    /// и `free_bytes`.
    ///
    /// # Errors
    ///
    /// `Corrupt` — любое нарушение; `page_no`/`page_type` — не совпадают
    /// с ожидаемыми.
    pub fn decode(
        page: &'a [u8],
        page_no: u32,
        snapshot_txn: u64,
        page_size: u32,
    ) -> Result<Self, ZoneFileError> {
        let header = PageHeader::decode(page, page_no, snapshot_txn, page_size)?;
        if header.page_type != PAGE_TYPE_LEAF {
            return Err(corrupt(
                Some(page_no),
                CorruptKind::Bounds,
                CorruptDetail::PageType,
            ));
        }
        let mut raw = RawNode::decode(page, page_no, page_size, 0, LEAF_INTERVAL)?;
        raw.validate_leaf_items()?;
        Ok(Self { raw })
    }

    /// Номер страницы.
    #[must_use]
    pub const fn page_no(&self) -> u32 {
        self.raw.page_no
    }

    /// Число item'ов.
    #[must_use]
    pub fn len(&self) -> usize {
        self.raw.n_items()
    }

    /// Истина для пустого листа.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.raw.n_items() == 0
    }

    /// `encoded_size` страницы.
    #[must_use]
    pub fn encoded_size(&self) -> u32 {
        u32::try_from(self.raw.page_size)
            .unwrap_or(u32::MAX)
            .saturating_sub(self.raw.header.free_bytes)
    }

    /// Свободные байты.
    #[must_use]
    pub const fn free_bytes(&self) -> u32 {
        self.raw.header.free_bytes
    }

    /// Флаги узла.
    #[must_use]
    pub const fn node_flags(&self) -> u16 {
        self.raw.header.node_flags
    }

    /// Полный ключ item'а.
    ///
    /// # Errors
    ///
    /// `Corrupt(Bounds)` — индекс вне диапазона.
    pub fn key(&self, index: usize) -> Result<Key, ZoneFileError> {
        self.raw.key_at(index)
    }

    /// Значение item'а.
    ///
    /// # Errors
    ///
    /// `Corrupt(Bounds)` — индекс вне диапазона.
    pub fn value(&self, index: usize) -> Result<DecodedValue<'a>, ZoneFileError> {
        let parts = self.raw.item_parts(index)?;
        if self.raw.key_at(index)?.rr_type() == T_ZONE_ENTRY {
            let bytes = self
                .raw
                .page
                .get(parts.value_off..parts.value_off + ZONE_ENTRY_BYTES)
                .ok_or_else(truncated)?;
            return Ok(DecodedValue::ZoneEntry(bytes));
        }
        let head = self
            .raw
            .page
            .get(parts.value_off..parts.value_off + LEAF_VALUE_BYTES)
            .ok_or_else(truncated)?;
        let value = LeafValue::decode(head)?;
        let payload = match value.kind {
            ValueKind::Inline => {
                let len = usize::try_from(value.payload_bytes()?)
                    .map_err(|_| corrupt_none(CorruptKind::BadRdata, CorruptDetail::RdataSum))?;
                self.raw
                    .page
                    .get(
                        parts.value_off + LEAF_VALUE_BYTES
                            ..parts.value_off + LEAF_VALUE_BYTES + len,
                    )
                    .unwrap_or(&[])
            }
            ValueKind::Node | ValueKind::Overflow => &[],
        };
        Ok(DecodedValue::Rrset { value, payload })
    }

    /// `LeafValue`, если item — не `ZoneEntry`.
    ///
    /// # Errors
    ///
    /// `Corrupt(Bounds)` — индекс вне диапазона.
    pub fn leaf_value(&self, index: usize) -> Result<Option<LeafValue>, ZoneFileError> {
        match self.value(index)? {
            DecodedValue::Rrset { value, .. } => Ok(Some(value)),
            DecodedValue::ZoneEntry(_) => Ok(None),
        }
    }

    /// Встроенный payload item'а (пустой для не-`INLINE`).
    ///
    /// # Errors
    ///
    /// `Corrupt(Bounds)` — индекс вне диапазона.
    pub fn inline_payload(&self, index: usize) -> Result<&'a [u8], ZoneFileError> {
        match self.value(index)? {
            DecodedValue::Rrset { payload, .. } => Ok(payload),
            DecodedValue::ZoneEntry(_) => Ok(&[]),
        }
    }

    /// Первый ключ листа.
    ///
    /// # Errors
    ///
    /// `Corrupt(Bounds)` — лист пуст.
    pub fn first_key(&self) -> Result<Key, ZoneFileError> {
        self.raw.key_at(0)
    }

    /// Первый индекс с `key >= target` (или `len`).
    ///
    /// # Errors
    ///
    /// `Corrupt` — страница повреждена (недостижимо после `decode`).
    pub fn lower_bound(&self, target: &Key) -> Result<usize, ZoneFileError> {
        self.lower_bound_raw_by(|bytes, name_len| {
            Ok(compare_raw_to_key_len(bytes, name_len, target))
        })
    }

    /// Первый индекс с `key > target` (или `len`).
    ///
    /// # Errors
    ///
    /// `Corrupt` — страница повреждена (недостижимо после `decode`).
    pub fn upper_bound(&self, target: &Key) -> Result<usize, ZoneFileError> {
        self.upper_bound_raw_by(|bytes, name_len| {
            Ok(compare_raw_to_key_len(bytes, name_len, target))
        })
    }

    /// Последний индекс с `key <= target`.
    ///
    /// # Errors
    ///
    /// `Corrupt` — страница повреждена (недостижимо после `decode`).
    pub fn predecessor(&self, target: &Key) -> Result<Option<usize>, ZoneFileError> {
        let bound = self.upper_bound(target)?;
        Ok(bound.checked_sub(1))
    }

    /// `lower_bound` по сырым байтам ключа (без материализации [`Key`]).
    ///
    /// # Errors
    ///
    /// `Corrupt` — страница повреждена; ошибка компаратора пробрасывается.
    pub(crate) fn lower_bound_raw_by<F>(&self, compare: F) -> Result<usize, ZoneFileError>
    where
        F: FnMut(&[u8], usize) -> Result<Ordering, ZoneFileError>,
    {
        self.raw.bound_by(compare, false)
    }

    /// `upper_bound` по сырым байтам ключа (без материализации [`Key`]).
    ///
    /// # Errors
    ///
    /// `Corrupt` — страница повреждена; ошибка компаратора пробрасывается.
    pub(crate) fn upper_bound_raw_by<F>(&self, compare: F) -> Result<usize, ZoneFileError>
    where
        F: FnMut(&[u8], usize) -> Result<Ordering, ZoneFileError>,
    {
        self.raw.bound_by(compare, true)
    }

    /// `lower_bound` с произвольным компаратором.
    ///
    /// # Errors
    ///
    /// `Corrupt` — страница повреждена; ошибка компаратора пробрасывается.
    pub fn lower_bound_by<F>(&self, mut compare: F) -> Result<usize, ZoneFileError>
    where
        F: FnMut(&Key) -> Result<Ordering, ZoneFileError>,
    {
        self.raw.bound_by(
            move |bytes, _name_len| {
                let key = Key::from_validated(bytes)
                    .ok_or_else(|| corrupt(None, CorruptKind::Bounds, CorruptDetail::KeyOrder))?;
                compare(&key)
            },
            false,
        )
    }

    /// `upper_bound` с произвольным компаратором.
    ///
    /// # Errors
    ///
    /// `Corrupt` — страница повреждена; ошибка компаратора пробрасывается.
    pub fn upper_bound_by<F>(&self, mut compare: F) -> Result<usize, ZoneFileError>
    where
        F: FnMut(&Key) -> Result<Ordering, ZoneFileError>,
    {
        self.raw.bound_by(
            move |bytes, _name_len| {
                let key = Key::from_validated(bytes)
                    .ok_or_else(|| corrupt(None, CorruptKind::Bounds, CorruptDetail::KeyOrder))?;
                compare(&key)
            },
            true,
        )
    }

    /// Имя владельца item'а без материализации [`Key`].
    ///
    /// # Errors
    ///
    /// `Corrupt` — страница повреждена.
    pub(crate) fn owner_at(&self, index: usize) -> Result<NameRle, ZoneFileError> {
        let mut buffer = [0_u8; KEY_MAX];
        let len = self.raw.key_bytes_at(index, &mut buffer)?;
        let name_len = self.raw.name_len_at(index)?;
        owner_from_raw(buffer.get(..len).unwrap_or(&[]), name_len)
            .ok_or_else(|| corrupt(None, CorruptKind::Bounds, CorruptDetail::KeyOrder))
    }

    /// Сырые байты ключа item'а в переданный буфер.
    ///
    /// # Errors
    ///
    /// `Corrupt` — страница повреждена.
    pub(crate) fn key_raw(
        &self,
        index: usize,
        buffer: &mut [u8; KEY_MAX],
    ) -> Result<usize, ZoneFileError> {
        self.raw.key_bytes_at(index, buffer)
    }

    /// Длина RLE-имени item'а.
    ///
    /// # Errors
    ///
    /// `Corrupt` — страница повреждена.
    pub(crate) fn name_len_at(&self, index: usize) -> Result<usize, ZoneFileError> {
        self.raw.name_len_at(index)
    }

    /// Материализует лист в логический [`LeafNode`].
    ///
    /// # Errors
    ///
    /// `Corrupt` — страница повреждена (недостижимо после `decode`).
    pub fn to_owned(&self) -> Result<LeafNode, ZoneFileError> {
        let mut items = Vec::with_capacity(self.len());
        for index in 0..self.len() {
            let key = self.raw.key_at(index)?;
            let value = match self.value(index)? {
                DecodedValue::ZoneEntry(bytes) => ItemValue::zone_entry(bytes)?,
                DecodedValue::Rrset { value, payload } => {
                    if value.kind == ValueKind::Inline {
                        ItemValue::inline(value, payload.to_vec())?
                    } else {
                        ItemValue::Leaf {
                            value,
                            payload: Vec::new(),
                        }
                    }
                }
            };
            items.push(LeafItem::new(key, value));
        }
        Ok(LeafNode { items })
    }
}

/// Значение, прочитанное из листа (zero-copy).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodedValue<'a> {
    /// 72-байтовый `ZoneEntry`.
    ZoneEntry(&'a [u8]),
    /// `LeafValue` и встроенный payload (пустой для `NODE`/`OVERFLOW`).
    Rrset {
        /// 20-байтовое значение.
        value: LeafValue,
        /// Встроенный payload.
        payload: &'a [u8],
    },
}

/// Декодированное ветвление с валидацией.
#[derive(Debug, Clone)]
pub struct DecodedBranch<'a> {
    raw: RawNode<'a>,
}

impl<'a> DecodedBranch<'a> {
    /// Декодирует и валидирует ветвление.
    ///
    /// # Errors
    ///
    /// `Corrupt` — любое нарушение; `page_no`/`level`/`page_type` не совпадают.
    pub fn decode(
        page: &'a [u8],
        page_no: u32,
        snapshot_txn: u64,
        page_size: u32,
    ) -> Result<Self, ZoneFileError> {
        let header = PageHeader::decode(page, page_no, snapshot_txn, page_size)?;
        if header.page_type != PAGE_TYPE_BRANCH {
            return Err(corrupt(
                Some(page_no),
                CorruptKind::Bounds,
                CorruptDetail::PageType,
            ));
        }
        let level = get_u16(page, 40, page_no)?;
        if level == 0 || level > MAX_TREE_DEPTH {
            return Err(corrupt(
                Some(page_no),
                CorruptKind::Bounds,
                CorruptDetail::DepthExceeded,
            ));
        }
        let mut raw = RawNode::decode(page, page_no, page_size, level, BRANCH_INTERVAL)?;
        raw.validate_branch_items()?;
        Ok(Self { raw })
    }

    /// Номер страницы.
    #[must_use]
    pub const fn page_no(&self) -> u32 {
        self.raw.page_no
    }

    /// Уровень узла (`> 0`).
    #[must_use]
    pub const fn level(&self) -> u16 {
        self.raw.header.level
    }

    /// Число item'ов.
    #[must_use]
    pub fn len(&self) -> usize {
        self.raw.n_items()
    }

    /// Истина для пустого ветвления (недопустимо в дереве, но валидно как узел).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.raw.n_items() == 0
    }

    /// Сепаратор item'а (точный минимум поддерева).
    ///
    /// # Errors
    ///
    /// `Corrupt(Bounds)` — индекс вне диапазона.
    pub fn separator(&self, index: usize) -> Result<Key, ZoneFileError> {
        self.raw.key_at(index)
    }

    /// Номер дочерней страницы.
    ///
    /// # Errors
    ///
    /// `Corrupt(Bounds)` — индекс вне диапазона.
    pub fn child(&self, index: usize) -> Result<u32, ZoneFileError> {
        let parts = self.raw.item_parts(index)?;
        get_u32(self.raw.page, parts.value_off, self.raw.page_no)
    }

    /// Первый сепаратор.
    ///
    /// # Errors
    ///
    /// `Corrupt(Bounds)` — ветвление пусто.
    pub fn first_key(&self) -> Result<Key, ZoneFileError> {
        self.raw.key_at(0)
    }

    /// Последний индекс с `key <= target`.
    ///
    /// # Errors
    ///
    /// `Corrupt` — страница повреждена.
    pub fn predecessor(&self, target: &Key) -> Result<Option<usize>, ZoneFileError> {
        let bound = self.raw.bound_by(
            |bytes, name_len| Ok(compare_raw_to_key_len(bytes, name_len, target)),
            true,
        )?;
        Ok(bound.checked_sub(1))
    }

    /// `predecessor` по сырым байтам ключа (без материализации [`Key`]).
    ///
    /// # Errors
    ///
    /// `Corrupt` — страница повреждена; ошибка компаратора пробрасывается.
    pub(crate) fn predecessor_raw_by<F>(&self, compare: F) -> Result<Option<usize>, ZoneFileError>
    where
        F: FnMut(&[u8], usize) -> Result<Ordering, ZoneFileError>,
    {
        let bound = self.raw.bound_by(compare, true)?;
        Ok(bound.checked_sub(1))
    }

    /// `predecessor` с произвольным компаратором.
    ///
    /// # Errors
    ///
    /// `Corrupt` — страница повреждена; ошибка компаратора пробрасывается.
    pub fn predecessor_by<F>(&self, mut compare: F) -> Result<Option<usize>, ZoneFileError>
    where
        F: FnMut(&Key) -> Result<Ordering, ZoneFileError>,
    {
        self.predecessor_raw_by(move |bytes, _name_len| {
            let key = Key::from_validated(bytes)
                .ok_or_else(|| corrupt(None, CorruptKind::Bounds, CorruptDetail::KeyOrder))?;
            compare(&key)
        })
    }

    /// Материализует ветвление.
    ///
    /// # Errors
    ///
    /// `Corrupt` — страница повреждена.
    pub fn to_owned(&self) -> Result<BranchNode, ZoneFileError> {
        let mut items = Vec::with_capacity(self.len());
        for index in 0..self.len() {
            items.push(BranchItem::new(self.raw.key_at(index)?, self.child(index)?));
        }
        Ok(BranchNode { items })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::{CLASS_IN, NameRle};
    use proptest::prelude::*;

    fn name(text: &str) -> NameRle {
        NameRle::from_ascii(text).unwrap()
    }

    fn inline_item(owner: &str, rr_type: u16, ttl: u32, rdata: &[u8]) -> LeafItem {
        let payload = {
            let mut payload = vec![0_u8; 2];
            payload[..2].copy_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
            payload.extend_from_slice(rdata);
            payload
        };
        let value = LeafValue {
            kind: ValueKind::Inline,
            flags: 0,
            rr_count: 1,
            ttl,
            val_u32: 0,
            rdlen: u16::try_from(rdata.len()).unwrap(),
        };
        LeafItem::new(
            Key::new(&name(owner), rr_type, CLASS_IN, 0).unwrap(),
            ItemValue::inline(value, payload).unwrap(),
        )
    }

    fn ctx(page_no: u32) -> EncodeContext {
        EncodeContext {
            page_no,
            page_size: 4096,
            txn: 2,
            lsn: 0,
        }
    }

    #[test]
    fn roundtrip_leaf() {
        let items = vec![
            inline_item("example.com", 1, 300, &[192, 0, 2, 1]),
            inline_item("www.example.com", 1, 300, &[192, 0, 2, 2]),
        ];
        let mut page = vec![0_u8; 4096];
        let encoded = encode_leaf(&mut page, ctx(14), &items).unwrap();
        assert_eq!(encoded.encoded_size, leaf_encoded_size(&items).unwrap());
        let decoded = DecodedLeaf::decode(&page, 14, 2, 4096).unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded.key(0).unwrap(), items[0].key);
        assert_eq!(decoded.to_owned().unwrap().items, items);
    }

    fn ordered_items(labels: &[String], types: &[u16]) -> Vec<LeafItem> {
        let value = LeafValue {
            kind: ValueKind::Inline,
            flags: 0,
            rr_count: 1,
            ttl: 300,
            val_u32: 0,
            rdlen: 4,
        };
        let mut items: Vec<LeafItem> = labels
            .iter()
            .zip(types)
            .enumerate()
            .map(|(index, (label, &rr_type))| {
                let owner = name(&format!("{label}{index}.example.com"));
                LeafItem::new(
                    Key::new(&owner, rr_type, CLASS_IN, 0).unwrap(),
                    ItemValue::inline(value, vec![0, 4, 192, 0, 2, 1]).unwrap(),
                )
            })
            .collect();
        items.sort_by(|left, right| compare_validated(&left.key, &right.key));
        items.dedup_by(|left, right| left.key == right.key);
        items
    }

    fn linear_bounds(items: &[LeafItem], target: &Key) -> (usize, usize, Option<usize>) {
        let lower = items
            .iter()
            .position(|item| compare_validated(&item.key, target) != Ordering::Less)
            .unwrap_or(items.len());
        let upper = items
            .iter()
            .position(|item| compare_validated(&item.key, target) == Ordering::Greater)
            .unwrap_or(items.len());
        (lower, upper, upper.checked_sub(1))
    }

    proptest! {
        /// Бинарный поиск по `OrderKey` даёт те же границы, что и полный
        /// линейный проход полного компаратора, включая длинные имена
        /// (равные префиксы) и цели вне диапазона.
        #[test]
        fn order_key_bounds_match_linear_scan(
            labels in prop::collection::vec("[a-z]{1,24}", 20..=40),
            types in prop::collection::vec(1_u16..=64, 20..=40),
            targets in prop::collection::vec(
                ("[a-z]{1,24}", 1_u16..=64, 0_u16..=64),
                1..=12,
            ),
        ) {
            let items = ordered_items(&labels, &types);
            prop_assume!(items.len() >= 16);
            let mut page = vec![0_u8; 4096];
            encode_leaf(&mut page, ctx(14), &items).unwrap();
            let decoded = DecodedLeaf::decode(&page, 14, 2, 4096).unwrap();
            let node = NodeRef::validate_leaf(&page, 14, 2, 4096).unwrap();
            for (label, rr_type, subtype) in targets {
                let owner = name(&format!("{label}0.example.com"));
                let target = Key::new(&owner, rr_type, CLASS_IN, subtype).unwrap();
                let expected = linear_bounds(&items, &target);
                prop_assert_eq!(node.lower_bound(&target).unwrap(), expected.0);
                prop_assert_eq!(decoded.lower_bound(&target).unwrap(), expected.0);
                prop_assert_eq!(node.upper_bound(&target).unwrap(), expected.1);
                prop_assert_eq!(node.predecessor(&target).unwrap(), expected.2);
                let (position, captured) = node.lower_bound_capture(&target).unwrap();
                prop_assert_eq!(position, expected.0);
                if let Some(key) = captured {
                    prop_assert_eq!(Some(&key), items.get(position).map(|item| &item.key));
                }
            }
        }
    }
}

// --- Zero-copy представление провалидированной страницы ---------------------

use std::sync::Arc;

/// Минимальное число item'ов в узле, при котором `memcmp`-префикс окупается.
///
/// На маленьких узлах (типичный горячий лист) полный компаратор дешевле
/// вычисления `OrderKey` целиком.
const ORDER_KEY_MIN_ITEMS: usize = 16;

/// Метаданные валидированного узла, отделённые от байтов страницы.
///
/// Хранятся в [`crate::cache::PageCache`] (`Arc`), поэтому горячий поиск не
/// перечитывает слоты/restart'ы и не валидирует страницу повторно.
#[derive(Clone)]
pub(crate) struct NodeMeta {
    pub(crate) page_no: u32,
    pub(crate) txn: u64,
    pub(crate) is_leaf: bool,
    pub(crate) header: NodeHeader,
    pub(crate) interval: usize,
    pub(crate) page_size: usize,
    slots: Box<[u16]>,
    restarts: Box<[u16]>,
    name_lens: Box<[u8]>,
    zone_entry: Box<[u64]>,
    /// Байтово-сравнимый префикс каждого item'а (`memcmp` на горячем пути).
    order_keys: Box<[OrderKey]>,
}

impl std::fmt::Debug for NodeMeta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeMeta")
            .field("page_no", &self.page_no)
            .field("txn", &self.txn)
            .field("is_leaf", &self.is_leaf)
            .field("header", &self.header)
            .finish_non_exhaustive()
    }
}

impl NodeMeta {
    /// Оценка heap-памяти метаданных (без заголовков аллокатора).
    #[must_use]
    pub(crate) fn heap_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.slots.len() * std::mem::size_of::<u16>()
            + self.restarts.len() * std::mem::size_of::<u16>()
            + self.name_lens.len()
            + self.zone_entry.len() * std::mem::size_of::<u64>()
            + self.order_keys.len() * std::mem::size_of::<OrderKey>()
    }

    /// Валидирует лист целиком (структура + элементы) и сохраняет метаданные.
    pub(crate) fn validate_leaf(
        page: &[u8],
        page_no: u32,
        snapshot_txn: u64,
        page_size: u32,
    ) -> Result<Self, ZoneFileError> {
        let header = PageHeader::decode(page, page_no, snapshot_txn, page_size)?;
        if header.page_type != PAGE_TYPE_LEAF {
            return Err(corrupt(
                Some(page_no),
                CorruptKind::Bounds,
                CorruptDetail::PageType,
            ));
        }
        let mut raw = RawNode::decode(page, page_no, page_size, 0, LEAF_INTERVAL)?;
        let order_keys = raw.validate_leaf_items()?;
        Ok(raw.into_meta(true, header.txn, order_keys))
    }

    /// Строит метаданные только что закодированного листа без перечитывания
    /// элементов (доверенный путь записи: page/items уже согласованы).
    pub(crate) fn from_encoded_leaf(
        page: &[u8],
        page_no: u32,
        txn: u64,
        page_size: u32,
        items: &[LeafItem],
    ) -> Result<Self, ZoneFileError> {
        let mut meta = Self::header_only(page, page_no, txn, page_size, true, LEAF_INTERVAL)?;
        meta.fill_item_meta(
            items.len(),
            |index| items.get(index).map(|item| &item.key),
            |index| items.get(index).map(|item| &item.value),
        )?;
        Ok(meta)
    }

    /// То же для ветвления.
    pub(crate) fn from_encoded_branch(
        page: &[u8],
        page_no: u32,
        txn: u64,
        page_size: u32,
        items: &[BranchItem],
    ) -> Result<Self, ZoneFileError> {
        let level = get_u16(page, 40, page_no)?;
        let mut meta = Self::header_only(page, page_no, txn, page_size, false, BRANCH_INTERVAL)?;
        meta.header.level = level;
        meta.fill_item_meta(
            items.len(),
            |index| items.get(index).map(|item| &item.key),
            |_| None,
        )?;
        Ok(meta)
    }

    fn header_only(
        page: &[u8],
        page_no: u32,
        txn: u64,
        page_size: u32,
        is_leaf: bool,
        interval: usize,
    ) -> Result<Self, ZoneFileError> {
        let level = get_u16(page, 40, page_no)?;
        let n_items = get_u16(page, 42, page_no)?;
        let n_restarts = get_u16(page, 44, page_no)?;
        let node_flags = get_u16(page, 46, page_no)?;
        let free_bytes = get_u32(page, 48, page_no)?;
        let items_start = get_u32(page, 52, page_no)?;
        let n_items_usize = usize::from(n_items);
        let n_restarts_usize = usize::from(n_restarts);
        if n_items_usize > MAX_ITEMS_PER_PAGE || n_restarts_usize > MAX_RESTARTS_PER_PAGE {
            return Err(corrupt(
                Some(page_no),
                CorruptKind::Bounds,
                CorruptDetail::OffsetOutOfRange,
            ));
        }
        let restart_base = NODE_HEADER_BYTES;
        let slot_base = restart_base + 2 * n_restarts_usize;
        let mut restarts = Vec::with_capacity(n_restarts_usize);
        for index in 0..n_restarts_usize {
            restarts.push(get_u16(page, restart_base + 2 * index, page_no)?);
        }
        let mut slots = Vec::with_capacity(n_items_usize);
        for index in 0..n_items_usize {
            slots.push(get_u16(page, slot_base + 2 * index, page_no)?);
        }
        Ok(Self {
            page_no,
            txn,
            is_leaf,
            header: NodeHeader {
                level,
                n_items,
                n_restarts,
                node_flags,
                free_bytes,
                items_start,
            },
            interval,
            page_size: usize::try_from(page_size).map_err(|_| {
                corrupt(
                    Some(page_no),
                    CorruptKind::Bounds,
                    CorruptDetail::OffsetOutOfRange,
                )
            })?,
            slots: slots.into_boxed_slice(),
            restarts: restarts.into_boxed_slice(),
            name_lens: vec![0_u8; n_items_usize].into_boxed_slice(),
            zone_entry: vec![0_u64; n_items_usize.div_ceil(64)].into_boxed_slice(),
            order_keys: vec![OrderKey::default(); n_items_usize].into_boxed_slice(),
        })
    }

    fn fill_item_meta<'k, 'v>(
        &mut self,
        count: usize,
        key: impl Fn(usize) -> Option<&'k Key>,
        value: impl Fn(usize) -> Option<&'v ItemValue>,
    ) -> Result<(), ZoneFileError> {
        for index in 0..count {
            let key = key(index).ok_or_else(|| {
                corrupt(
                    Some(self.page_no),
                    CorruptKind::Bounds,
                    CorruptDetail::OffsetOutOfRange,
                )
            })?;
            let name_len = u8::try_from(key.owner_len()).map_err(|_| {
                corrupt(
                    Some(self.page_no),
                    CorruptKind::BadName,
                    CorruptDetail::BadNameEncoding,
                )
            })?;
            if let Some(slot) = self.name_lens.get_mut(index) {
                *slot = name_len;
            }
            if let Some(slot) = self.order_keys.get_mut(index) {
                *slot = OrderKey::of_key(key);
            }
            if let Some(value) = value(index)
                && matches!(value, ItemValue::ZoneEntry(_))
                && let Some(word) = self.zone_entry.get_mut(index / 64)
            {
                *word |= 1_u64 << (index % 64);
            }
        }
        Ok(())
    }

    /// Валидирует ветвление целиком и сохраняет метаданные.
    pub(crate) fn validate_branch(
        page: &[u8],
        page_no: u32,
        snapshot_txn: u64,
        page_size: u32,
    ) -> Result<Self, ZoneFileError> {
        let header = PageHeader::decode(page, page_no, snapshot_txn, page_size)?;
        if header.page_type != PAGE_TYPE_BRANCH {
            return Err(corrupt(
                Some(page_no),
                CorruptKind::Bounds,
                CorruptDetail::PageType,
            ));
        }
        let level = get_u16(page, 40, page_no)?;
        if level == 0 || level > MAX_TREE_DEPTH {
            return Err(corrupt(
                Some(page_no),
                CorruptKind::Bounds,
                CorruptDetail::DepthExceeded,
            ));
        }
        let mut raw = RawNode::decode(page, page_no, page_size, level, BRANCH_INTERVAL)?;
        let order_keys = raw.validate_branch_items()?;
        Ok(raw.into_meta(false, header.txn, order_keys))
    }
}

impl RawNode<'_> {
    fn into_meta(self, is_leaf: bool, txn: u64, order_keys: Box<[OrderKey]>) -> NodeMeta {
        NodeMeta {
            page_no: self.page_no,
            txn,
            is_leaf,
            header: self.header,
            interval: self.interval,
            page_size: self.page_size,
            slots: self
                .slots
                .get(..self.n_items())
                .unwrap_or(&[])
                .to_vec()
                .into_boxed_slice(),
            restarts: self
                .restarts
                .get(..self.n_restarts())
                .unwrap_or(&[])
                .to_vec()
                .into_boxed_slice(),
            name_lens: self
                .name_lens
                .get(..self.n_items())
                .unwrap_or(&[])
                .to_vec()
                .into_boxed_slice(),
            zone_entry: self
                .zone_entry
                .get(..self.n_items().div_ceil(64))
                .unwrap_or(&[])
                .to_vec()
                .into_boxed_slice(),
            order_keys,
        }
    }
}

/// Zero-copy view провалидированного узла (`NodeRef`).
///
/// Не аллоцирует: держит `Arc<NodeMeta>` (готовые слоты/restart'ы) и срез
/// страницы. Ключи восстанавливаются в stack-буфере ≤261 Б.
pub struct NodeRef<'a> {
    page: &'a [u8],
    meta: Arc<NodeMeta>,
}

impl std::fmt::Debug for NodeRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeRef")
            .field("page_no", &self.meta.page_no)
            .field("level", &self.meta.header.level)
            .field("n_items", &self.meta.header.n_items)
            .finish_non_exhaustive()
    }
}

impl<'a> NodeRef<'a> {
    pub(crate) fn new(page: &'a [u8], meta: Arc<NodeMeta>) -> Self {
        Self { page, meta }
    }

    pub(crate) fn validate_leaf(
        page: &'a [u8],
        page_no: u32,
        snapshot_txn: u64,
        page_size: u32,
    ) -> Result<Self, ZoneFileError> {
        let meta = NodeMeta::validate_leaf(page, page_no, snapshot_txn, page_size)?;
        Ok(Self::new(page, Arc::new(meta)))
    }

    pub(crate) fn validate_branch(
        page: &'a [u8],
        page_no: u32,
        snapshot_txn: u64,
        page_size: u32,
    ) -> Result<Self, ZoneFileError> {
        let meta = NodeMeta::validate_branch(page, page_no, snapshot_txn, page_size)?;
        Ok(Self::new(page, Arc::new(meta)))
    }

    /// Номер страницы.
    #[must_use]
    pub fn page_no(&self) -> u32 {
        self.meta.page_no
    }

    /// Уровень узла: 0 — лист.
    #[must_use]
    pub fn level(&self) -> u16 {
        self.meta.header.level
    }

    /// Истина для листа.
    #[must_use]
    pub fn is_leaf(&self) -> bool {
        self.meta.is_leaf
    }

    /// Число item'ов.
    #[must_use]
    pub fn len(&self) -> usize {
        usize::from(self.meta.header.n_items)
    }

    /// Истина для пустого узла.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.meta.header.n_items == 0
    }

    /// Свободные байты.
    #[must_use]
    pub fn free_bytes(&self) -> u32 {
        self.meta.header.free_bytes
    }

    /// `encoded_size`.
    #[must_use]
    pub fn encoded_size(&self) -> u32 {
        u32::try_from(self.meta.page_size)
            .unwrap_or(u32::MAX)
            .saturating_sub(self.meta.header.free_bytes)
    }

    /// Флаги узла.
    #[must_use]
    pub fn node_flags(&self) -> u16 {
        self.meta.header.node_flags
    }

    fn page_size(&self) -> usize {
        self.meta.page_size
    }

    fn item_parts(&self, index: usize) -> Result<ItemParts<'a>, ZoneFileError> {
        if index >= self.len() {
            return Err(corrupt(
                Some(self.meta.page_no),
                CorruptKind::Bounds,
                CorruptDetail::OffsetOutOfRange,
            ));
        }
        let slot = usize::from(self.meta.slots.get(index).copied().ok_or_else(|| {
            corrupt(
                Some(self.meta.page_no),
                CorruptKind::Bounds,
                CorruptDetail::OffsetOutOfRange,
            )
        })?);
        let end = if index + 1 < self.len() {
            usize::from(self.meta.slots.get(index + 1).copied().ok_or_else(|| {
                corrupt(
                    Some(self.meta.page_no),
                    CorruptKind::Bounds,
                    CorruptDetail::OffsetOutOfRange,
                )
            })?)
        } else {
            self.page_size()
        };
        let shared_len = usize::from(get_u16(self.page, slot, self.meta.page_no)?);
        let suffix_len = usize::from(get_u16(self.page, slot + 2, self.meta.page_no)?);
        let suffix_start = slot + ITEM_HEADER_BYTES;
        let value_off = suffix_start
            .checked_add(suffix_len)
            .filter(|&off| off <= end)
            .ok_or_else(|| {
                corrupt(
                    Some(self.meta.page_no),
                    CorruptKind::Bounds,
                    CorruptDetail::OffsetOutOfRange,
                )
            })?;
        let suffix = self.page.get(suffix_start..value_off).ok_or_else(|| {
            corrupt(
                Some(self.meta.page_no),
                CorruptKind::Bounds,
                CorruptDetail::Truncated,
            )
        })?;
        Ok(ItemParts {
            slot,
            shared_len,
            suffix,
            value_off,
            end,
        })
    }

    fn key_bytes_at(
        &self,
        index: usize,
        buffer: &mut [u8; KEY_MAX],
    ) -> Result<usize, ZoneFileError> {
        let group = index / self.meta.interval * self.meta.interval;
        let mut prev_len = 0_usize;
        for position in group..=index {
            let parts = self.item_parts(position)?;
            prev_len = assemble_key_bytes(prev_len, &parts, buffer)?;
        }
        Ok(prev_len)
    }

    fn key_at(&self, index: usize) -> Result<Key, ZoneFileError> {
        let mut buffer = [0_u8; KEY_MAX];
        let len = self.key_bytes_at(index, &mut buffer)?;
        Key::from_validated(buffer.get(..len).unwrap_or(&[])).ok_or_else(|| {
            corrupt(
                Some(self.meta.page_no),
                CorruptKind::Bounds,
                CorruptDetail::KeyOrder,
            )
        })
    }

    fn name_len_at(&self, index: usize) -> Result<usize, ZoneFileError> {
        self.meta
            .name_lens
            .get(index)
            .copied()
            .filter(|&len| len != 0)
            .map(usize::from)
            .ok_or_else(|| {
                corrupt(
                    Some(self.meta.page_no),
                    CorruptKind::Bounds,
                    CorruptDetail::OffsetOutOfRange,
                )
            })
    }

    /// Имя владельца item'а без материализации [`Key`].
    pub(crate) fn owner_at(&self, index: usize) -> Result<NameRle, ZoneFileError> {
        let mut buffer = [0_u8; KEY_MAX];
        let len = self.key_bytes_at(index, &mut buffer)?;
        let name_len = self.name_len_at(index)?;
        owner_from_raw(buffer.get(..len).unwrap_or(&[]), name_len).ok_or_else(|| {
            corrupt(
                Some(self.meta.page_no),
                CorruptKind::Bounds,
                CorruptDetail::KeyOrder,
            )
        })
    }

    fn compare_index_to_target(
        &self,
        index: usize,
        target: &Key,
    ) -> Result<Ordering, ZoneFileError> {
        let mut buffer = [0_u8; KEY_MAX];
        let len = self.key_bytes_at(index, &mut buffer)?;
        let name_len = self.name_len_at(index)?;
        Ok(compare_raw_to_key_len(
            buffer.get(..len).unwrap_or(&[]),
            name_len,
            target,
        ))
    }

    fn walk_group_capture<F>(
        &self,
        group: usize,
        mut compare: F,
        strict: bool,
        capture: bool,
    ) -> Result<(usize, Option<Key>), ZoneFileError>
    where
        F: FnMut(&[u8], usize) -> Result<Ordering, ZoneFileError>,
    {
        let start = group.saturating_mul(self.meta.interval);
        let end = (start + self.meta.interval).min(self.len());
        let mut buffer = [0_u8; KEY_MAX];
        let mut prev_len = 0_usize;
        let mut index = start;
        while index < end {
            let parts = self.item_parts(index)?;
            prev_len = assemble_key_bytes(prev_len, &parts, &mut buffer)?;
            let name_len = self.name_len_at(index)?;
            let order = compare(buffer.get(..prev_len).unwrap_or(&[]), name_len)?;
            let matched = if strict {
                order == Ordering::Greater
            } else {
                order != Ordering::Less
            };
            if matched {
                let key = if capture {
                    Key::from_validated(buffer.get(..prev_len).unwrap_or(&[]))
                } else {
                    None
                };
                return Ok((index, key));
            }
            index += 1;
        }
        Ok((end, None))
    }

    fn bound_by_capture<F>(
        &self,
        mut compare: F,
        strict: bool,
        capture: bool,
    ) -> Result<(usize, Option<Key>), ZoneFileError>
    where
        F: FnMut(&[u8], usize) -> Result<Ordering, ZoneFileError>,
    {
        if self.is_empty() {
            return Ok((0, None));
        }
        let mut low = 0_usize;
        let mut high = usize::from(self.meta.header.n_restarts);
        while low < high {
            let middle = low + (high - low) / 2;
            let index = middle.saturating_mul(self.meta.interval);
            let mut buffer = [0_u8; KEY_MAX];
            let len = self.key_bytes_at(index, &mut buffer)?;
            let name_len = self.name_len_at(index)?;
            let order = compare(buffer.get(..len).unwrap_or(&[]), name_len)?;
            let matched = if strict {
                order == Ordering::Greater
            } else {
                order != Ordering::Less
            };
            if matched {
                high = middle;
            } else {
                low = middle + 1;
            }
        }
        let group = low.saturating_sub(1);
        let (index, key) = self.walk_group_capture(group, compare, strict, capture)?;
        if capture && key.is_none() && index < self.len() {
            return Ok((index, Some(self.key_at(index)?)));
        }
        Ok((index, key))
    }

    fn bound_by<F>(&self, compare: F, strict: bool) -> Result<usize, ZoneFileError>
    where
        F: FnMut(&[u8], usize) -> Result<Ordering, ZoneFileError>,
    {
        self.bound_by_capture(compare, strict, false)
            .map(|(index, _)| index)
    }

    fn order_key_at(&self, index: usize) -> Result<OrderKey, ZoneFileError> {
        self.meta.order_keys.get(index).copied().ok_or_else(|| {
            corrupt(
                Some(self.meta.page_no),
                CorruptKind::Bounds,
                CorruptDetail::OffsetOutOfRange,
            )
        })
    }

    /// Двоичный поиск по `OrderKey` всего узла.
    ///
    /// Префиксы монотонны, поэтому `partition_point` находит первый item, чей
    /// полный ключ не меньше (или больше при `strict`) целевого. Ключ
    /// собирается только для item'ов с равным префиксом (обычно 0–1 штука)
    /// и для захвата результата.
    fn bound_by_order(
        &self,
        target: &Key,
        target_order: &OrderKey,
        strict: bool,
        capture: bool,
    ) -> Result<(usize, Option<Key>, bool), ZoneFileError> {
        if self.is_empty() {
            return Ok((0, None, false));
        }
        let len = self.len();
        let mut index = self
            .meta
            .order_keys
            .partition_point(|key| key.cmp(target_order) == Ordering::Less);
        let mut equal = false;
        while index < len && self.order_key_at(index)? == *target_order {
            let order = self.compare_index_to_target(index, target)?;
            let matched = if strict {
                order == Ordering::Greater
            } else {
                order != Ordering::Less
            };
            if matched {
                equal = order == Ordering::Equal;
                break;
            }
            index += 1;
        }
        if index >= len {
            return Ok((len, None, false));
        }
        let key = if capture {
            Some(self.key_at(index)?)
        } else {
            None
        };
        Ok((index, key, equal))
    }

    /// Первый индекс с `key >= target`.
    ///
    /// # Errors
    ///
    /// `Corrupt` — недостижимо после валидации.
    pub fn lower_bound(&self, target: &Key) -> Result<usize, ZoneFileError> {
        let order = OrderKey::of_key(target);
        self.lower_bound_with_order(target, &order)
    }

    /// `lower_bound` с заранее вычисленным `OrderKey` (горячий lookup).
    ///
    /// # Errors
    ///
    /// `Corrupt` — недостижимо после валидации.
    pub(crate) fn lower_bound_with_order(
        &self,
        target: &Key,
        order: &OrderKey,
    ) -> Result<usize, ZoneFileError> {
        if self.len() < ORDER_KEY_MIN_ITEMS {
            return self.bound_by(
                |bytes, name_len| Ok(compare_raw_to_key_len(bytes, name_len, target)),
                false,
            );
        }
        self.bound_by_order(target, order, false, false)
            .map(|(index, _, _)| index)
    }

    /// `lower_bound` с одновременной материализацией найденного ключа.
    ///
    /// Позволяет не реконструировать ключ второй раз в горячем lookup.
    ///
    /// # Errors
    ///
    /// `Corrupt` — недостижимо после валидации.
    pub fn lower_bound_capture(&self, target: &Key) -> Result<(usize, Option<Key>), ZoneFileError> {
        let order = OrderKey::of_key(target);
        self.lower_bound_capture_with_order(target, &order)
    }

    /// `lower_bound_capture` с заранее вычисленным `OrderKey`.
    ///
    /// # Errors
    ///
    /// `Corrupt` — недостижимо после валидации.
    pub(crate) fn lower_bound_capture_with_order(
        &self,
        target: &Key,
        order: &OrderKey,
    ) -> Result<(usize, Option<Key>), ZoneFileError> {
        self.lower_bound_capture_match_with_order(target, order)
            .map(|(index, key, _)| (index, key))
    }

    /// `lower_bound_capture` + признак равенства без заранее вычисленного
    /// `OrderKey`.
    ///
    /// Для маленьких листьев `OrderKey` не вычисляется вовсе.
    ///
    /// # Errors
    ///
    /// `Corrupt` — недостижимо после валидации.
    pub(crate) fn lower_bound_capture_match(
        &self,
        target: &Key,
    ) -> Result<(usize, Option<Key>, bool), ZoneFileError> {
        if self.len() < ORDER_KEY_MIN_ITEMS {
            let mut matched_order = Ordering::Greater;
            let (index, key) = self.bound_by_capture(
                |bytes, name_len| {
                    let order = compare_raw_to_key_len(bytes, name_len, target);
                    if order != Ordering::Less {
                        matched_order = order;
                    }
                    Ok(order)
                },
                false,
                true,
            )?;
            let equal = key.is_some() && matched_order == Ordering::Equal;
            return Ok((index, key, equal));
        }
        let order = OrderKey::of_key(target);
        self.bound_by_order(target, &order, false, true)
    }

    /// `lower_bound_capture` + признак точного равенства найденного ключа.
    ///
    /// Признак считается в том же проходе, поэтому горячему lookup не нужно
    /// сравнивать найденный ключ с целевым повторно.
    ///
    /// # Errors
    ///
    /// `Corrupt` — недостижимо после валидации.
    pub(crate) fn lower_bound_capture_match_with_order(
        &self,
        target: &Key,
        order: &OrderKey,
    ) -> Result<(usize, Option<Key>, bool), ZoneFileError> {
        if self.len() < ORDER_KEY_MIN_ITEMS {
            let mut matched_order = Ordering::Greater;
            let (index, key) = self.bound_by_capture(
                |bytes, name_len| {
                    let order = compare_raw_to_key_len(bytes, name_len, target);
                    if order != Ordering::Less {
                        matched_order = order;
                    }
                    Ok(order)
                },
                false,
                true,
            )?;
            let equal = key.is_some() && matched_order == Ordering::Equal;
            return Ok((index, key, equal));
        }
        self.bound_by_order(target, order, false, true)
    }

    /// Первый индекс с `key > target`.
    ///
    /// # Errors
    ///
    /// `Corrupt` — недостижимо после валидации.
    pub fn upper_bound(&self, target: &Key) -> Result<usize, ZoneFileError> {
        let order = OrderKey::of_key(target);
        self.upper_bound_with_order(target, &order)
    }

    /// `upper_bound` с заранее вычисленным `OrderKey`.
    ///
    /// # Errors
    ///
    /// `Corrupt` — недостижимо после валидации.
    pub(crate) fn upper_bound_with_order(
        &self,
        target: &Key,
        order: &OrderKey,
    ) -> Result<usize, ZoneFileError> {
        if self.len() < ORDER_KEY_MIN_ITEMS {
            return self.bound_by(
                |bytes, name_len| Ok(compare_raw_to_key_len(bytes, name_len, target)),
                true,
            );
        }
        self.bound_by_order(target, order, true, false)
            .map(|(index, _, _)| index)
    }

    /// Последний индекс с `key <= target`.
    ///
    /// # Errors
    ///
    /// `Corrupt` — недостижимо после валидации.
    pub fn predecessor(&self, target: &Key) -> Result<Option<usize>, ZoneFileError> {
        let order = OrderKey::of_key(target);
        self.predecessor_with_order(target, &order)
    }

    /// `predecessor` с заранее вычисленным `OrderKey`.
    ///
    /// # Errors
    ///
    /// `Corrupt` — недостижимо после валидации.
    pub(crate) fn predecessor_with_order(
        &self,
        target: &Key,
        order: &OrderKey,
    ) -> Result<Option<usize>, ZoneFileError> {
        let bound = self.upper_bound_with_order(target, order)?;
        Ok(bound.checked_sub(1))
    }

    /// `lower_bound` с произвольным компаратором.
    ///
    /// # Errors
    ///
    /// `Corrupt` — недостижимо после валидации; ошибка компаратора.
    pub fn lower_bound_by<F>(&self, mut compare: F) -> Result<usize, ZoneFileError>
    where
        F: FnMut(&Key) -> Result<Ordering, ZoneFileError>,
    {
        self.bound_by(
            move |bytes, _name_len| {
                let key = Key::from_validated(bytes)
                    .ok_or_else(|| corrupt(None, CorruptKind::Bounds, CorruptDetail::KeyOrder))?;
                compare(&key)
            },
            false,
        )
    }

    /// `predecessor` с произвольным компаратором.
    ///
    /// # Errors
    ///
    /// `Corrupt` — недостижимо после валидации; ошибка компаратора.
    pub fn predecessor_by<F>(&self, mut compare: F) -> Result<Option<usize>, ZoneFileError>
    where
        F: FnMut(&Key) -> Result<Ordering, ZoneFileError>,
    {
        let bound = self.bound_by(
            move |bytes, _name_len| {
                let key = Key::from_validated(bytes)
                    .ok_or_else(|| corrupt(None, CorruptKind::Bounds, CorruptDetail::KeyOrder))?;
                compare(&key)
            },
            true,
        )?;
        Ok(bound.checked_sub(1))
    }

    /// Полный ключ item'а.
    ///
    /// # Errors
    ///
    /// `Corrupt` — индекс вне диапазона.
    pub fn key(&self, index: usize) -> Result<Key, ZoneFileError> {
        self.key_at(index)
    }

    /// Проверяет равенство ключа item'а и `target` без материализации `Key`.
    ///
    /// # Errors
    ///
    /// `Corrupt` — индекс вне диапазона.
    pub fn key_eq(&self, index: usize, target: &Key) -> Result<bool, ZoneFileError> {
        let mut buffer = [0_u8; KEY_MAX];
        let len = self.key_bytes_at(index, &mut buffer)?;
        let name_len = usize::from(self.meta.name_lens.get(index).copied().ok_or_else(|| {
            corrupt(
                Some(self.meta.page_no),
                CorruptKind::Bounds,
                CorruptDetail::OffsetOutOfRange,
            )
        })?);
        Ok(
            compare_raw_to_key_len(buffer.get(..len).unwrap_or(&[]), name_len, target)
                == Ordering::Equal,
        )
    }

    /// Первый ключ.
    ///
    /// # Errors
    ///
    /// `Corrupt` — узел пуст.
    pub fn first_key(&self) -> Result<Key, ZoneFileError> {
        self.key_at(0)
    }

    /// Значение листа.
    ///
    /// # Errors
    ///
    /// `Corrupt` — узел не лист или индекс вне диапазона.
    pub fn value(&self, index: usize) -> Result<DecodedValue<'a>, ZoneFileError> {
        if !self.meta.is_leaf {
            return Err(corrupt(
                Some(self.meta.page_no),
                CorruptKind::Bounds,
                CorruptDetail::PageType,
            ));
        }
        let parts = self.item_parts(index)?;
        let is_zone_entry = self
            .meta
            .zone_entry
            .get(index / 64)
            .is_some_and(|word| word & (1_u64 << (index % 64)) != 0);
        if is_zone_entry {
            let bytes = self
                .page
                .get(parts.value_off..parts.value_off + ZONE_ENTRY_BYTES)
                .ok_or_else(truncated)?;
            return Ok(DecodedValue::ZoneEntry(bytes));
        }
        let head = self
            .page
            .get(parts.value_off..parts.value_off + LEAF_VALUE_BYTES)
            .ok_or_else(truncated)?;
        let value = LeafValue::decode(head)?;
        let payload = match value.kind {
            ValueKind::Inline => {
                let length = usize::try_from(value.payload_bytes()?)
                    .map_err(|_| corrupt_none(CorruptKind::BadRdata, CorruptDetail::RdataSum))?;
                self.page
                    .get(
                        parts.value_off + LEAF_VALUE_BYTES
                            ..parts.value_off + LEAF_VALUE_BYTES + length,
                    )
                    .unwrap_or(&[])
            }
            ValueKind::Node | ValueKind::Overflow => &[],
        };
        Ok(DecodedValue::Rrset { value, payload })
    }

    /// `LeafValue`, если item — не `ZoneEntry`.
    ///
    /// # Errors
    ///
    /// `Corrupt` — индекс вне диапазона.
    pub fn leaf_value(&self, index: usize) -> Result<Option<LeafValue>, ZoneFileError> {
        match self.value(index)? {
            DecodedValue::Rrset { value, .. } => Ok(Some(value)),
            DecodedValue::ZoneEntry(_) => Ok(None),
        }
    }

    /// Встроенный payload item'а.
    ///
    /// # Errors
    ///
    /// `Corrupt` — индекс вне диапазона.
    pub fn inline_payload(&self, index: usize) -> Result<&'a [u8], ZoneFileError> {
        match self.value(index)? {
            DecodedValue::Rrset { payload, .. } => Ok(payload),
            DecodedValue::ZoneEntry(_) => Ok(&[]),
        }
    }

    /// Номер дочерней страницы (для ветвления).
    ///
    /// # Errors
    ///
    /// `Corrupt` — узел не ветвление или индекс вне диапазона.
    pub fn child(&self, index: usize) -> Result<u32, ZoneFileError> {
        if self.meta.is_leaf {
            return Err(corrupt(
                Some(self.meta.page_no),
                CorruptKind::Bounds,
                CorruptDetail::PageType,
            ));
        }
        let parts = self.item_parts(index)?;
        get_u32(self.page, parts.value_off, self.meta.page_no)
    }

    /// Сепаратор item'а ветвления.
    ///
    /// # Errors
    ///
    /// `Corrupt` — индекс вне диапазона.
    pub fn separator(&self, index: usize) -> Result<Key, ZoneFileError> {
        self.key_at(index)
    }

    /// Материализует лист (аллоцирует; только путь записи/диагностики).
    ///
    /// # Errors
    ///
    /// `Corrupt` — узел не лист или повреждён.
    pub fn to_leaf(&self) -> Result<LeafNode, ZoneFileError> {
        if !self.meta.is_leaf {
            return Err(corrupt(
                Some(self.meta.page_no),
                CorruptKind::Bounds,
                CorruptDetail::PageType,
            ));
        }
        let mut items = Vec::with_capacity(self.len());
        for index in 0..self.len() {
            let key = self.key_at(index)?;
            let value = match self.value(index)? {
                DecodedValue::ZoneEntry(bytes) => ItemValue::zone_entry(bytes)?,
                DecodedValue::Rrset { value, payload } => {
                    if value.kind == ValueKind::Inline {
                        ItemValue::inline(value, payload.to_vec())?
                    } else {
                        ItemValue::Leaf {
                            value,
                            payload: Vec::new(),
                        }
                    }
                }
            };
            items.push(LeafItem::new(key, value));
        }
        Ok(LeafNode { items })
    }

    /// Материализует ветвление (аллоцирует).
    ///
    /// # Errors
    ///
    /// `Corrupt` — узел не ветвление или повреждён.
    pub fn to_branch(&self) -> Result<BranchNode, ZoneFileError> {
        if self.meta.is_leaf {
            return Err(corrupt(
                Some(self.meta.page_no),
                CorruptKind::Bounds,
                CorruptDetail::PageType,
            ));
        }
        let mut items = Vec::with_capacity(self.len());
        for index in 0..self.len() {
            items.push(BranchItem::new(self.key_at(index)?, self.child(index)?));
        }
        Ok(BranchNode { items })
    }
}
