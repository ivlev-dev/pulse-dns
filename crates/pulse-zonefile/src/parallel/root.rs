//! `RootEntry` — 64-байтовая самодостаточная запись версии зоны (D-A).
//!
//! Раскладка — `docs/spec/parallel-writes-v2.md` §4.1. CRC покрывает
//! `[4, 64)` (поле CRC в диапазон не входит), поэтому запись валидируется без
//! обращения к странице. Все поля — little-endian.

use crate::checksum::crc32c;
use crate::consts::MAX_TREE_DEPTH;
use crate::parallel::consts::{
    ROOT_ENTRY_SIZE, ROOT_OFF_CRC, ROOT_OFF_DELETED_TXN, ROOT_OFF_FLAGS, ROOT_OFF_FREE_HEAD,
    ROOT_OFF_IXFR_ROOT, ROOT_OFF_META_ROOT, ROOT_OFF_OWNER, ROOT_OFF_PAGE_LIMIT,
    ROOT_OFF_PREV_RECORD, ROOT_OFF_ROOT_PAGE, ROOT_OFF_RRSET_COUNT, ROOT_OFF_SOA_SERIAL,
    ROOT_OFF_STATE, ROOT_OFF_TREE_LEVEL, ROOT_OFF_VERSION,
};

/// Состояние зоны в записи корня.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum RootState {
    /// Зона создана, но ещё не объявлена обслуживаемой.
    #[default]
    Init,
    /// Зона обслуживается.
    Serving,
    /// Tombstone: зона удалена, `deleted_txn != 0`.
    Tombstone,
}

impl RootState {
    /// Дисковое значение.
    #[must_use]
    pub const fn to_disk(self) -> u8 {
        match self {
            Self::Init => 0,
            Self::Serving => 1,
            Self::Tombstone => 2,
        }
    }

    /// Разбор дискового значения.
    #[must_use]
    pub const fn from_disk(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Init),
            1 => Some(Self::Serving),
            2 => Some(Self::Tombstone),
            _ => None,
        }
    }
}

/// Флаги `RootEntry.flags`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct RootFlags(u8);

impl RootFlags {
    /// Запись каталога (слот 0).
    pub const CATALOG: Self = Self(1 << 0);
    /// Рекомендована компакция.
    pub const COMPACTION: Self = Self(1 << 1);
    /// Зоне нужен `fsck`.
    pub const NEEDS_FSCK: Self = Self(1 << 2);
    /// Все известные биты.
    pub const KNOWN: u8 = Self::CATALOG.0 | Self::COMPACTION.0 | Self::NEEDS_FSCK.0;

    /// Пустой набор флагов.
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Сырое значение.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Разбор с проверкой зарезервированных битов.
    #[must_use]
    pub const fn from_bits(value: u8) -> Option<Self> {
        if value & !Self::KNOWN == 0 {
            Some(Self(value))
        } else {
            None
        }
    }

    /// Установлен ли флаг.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Объединение.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// Нарушение семантики `RootEntry` (zone-fatal).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RootFieldError {
    /// `version < 2`.
    Version,
    /// `state > 2`.
    State,
    /// `deleted_txn` не согласован с `state = Tombstone`.
    DeletedTxn,
    /// `soa_serial > 0x7fff_ffff`.
    Serial,
    /// Зарезервированные биты `flags` не нулевые.
    Flags,
    /// `tree_level > MAX_TREE_DEPTH`.
    TreeLevel,
    /// `ixfr_root != 0` в v2.0.
    IxfrRoot,
    /// `root_page`/`meta_root`/`free_head`/`prev_record` за `page_limit_at_commit`.
    PointerBeyondLimit,
    /// `page_limit_at_commit` за пределами файла.
    PageLimit,
}

/// 64-байтовая запись версии зоны.
///
/// Поля соответствуют §4.1; `crc32c` вычисляется при [`RootEntry::encode`] и
/// проверяется при [`RootEntry::decode`].
#[derive(Debug, Clone, Copy)]
pub struct RootEntry {
    /// CRC-32C диапазона `[4, 64)`.
    pub crc32c: u32,
    /// `zone_seq`; 0 = каталог.
    pub owner_zone: u32,
    /// `txn` коммита зоны.
    pub version: u64,
    /// Корень B+tree; 0 = пусто.
    pub root_page: u32,
    /// Все страницы версии строго меньше этого значения.
    pub page_limit_at_commit: u32,
    /// Chain-страница предыдущей вытесненной версии; 0 = нет.
    pub prev_record: u32,
    /// Per-zone metadata-блок v1; 0 = нет.
    pub meta_root: u32,
    /// IXFR-корень; в v2.0 обязан быть 0.
    pub ixfr_root: u32,
    /// `txn` удаления; 0 ⟺ не tombstone.
    pub deleted_txn: u64,
    /// Число `RRset` без `T_NODE`.
    pub rrset_count: u32,
    /// SOA serial (RFC 1982).
    pub soa_serial: u32,
    /// Первый per-zone bucket; 0 = нет.
    pub free_head: u32,
    /// Уровень корня B+tree; 0 = пусто/лист.
    pub tree_level: u16,
    /// Состояние зоны.
    pub state: RootState,
    /// Флаги записи.
    pub flags: RootFlags,
}

impl PartialEq for RootEntry {
    /// Сравнение игнорирует `crc32c`: CRC — производное поле, его пересчитывает
    /// [`RootEntry::encode`].
    fn eq(&self, other: &Self) -> bool {
        self.owner_zone == other.owner_zone
            && self.version == other.version
            && self.root_page == other.root_page
            && self.page_limit_at_commit == other.page_limit_at_commit
            && self.prev_record == other.prev_record
            && self.meta_root == other.meta_root
            && self.ixfr_root == other.ixfr_root
            && self.deleted_txn == other.deleted_txn
            && self.rrset_count == other.rrset_count
            && self.soa_serial == other.soa_serial
            && self.free_head == other.free_head
            && self.tree_level == other.tree_level
            && self.state == other.state
            && self.flags == other.flags
    }
}

impl Eq for RootEntry {}

impl std::hash::Hash for RootEntry {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.owner_zone.hash(state);
        self.version.hash(state);
        self.root_page.hash(state);
        self.page_limit_at_commit.hash(state);
        self.prev_record.hash(state);
        self.meta_root.hash(state);
        self.ixfr_root.hash(state);
        self.deleted_txn.hash(state);
        self.rrset_count.hash(state);
        self.soa_serial.hash(state);
        self.free_head.hash(state);
        self.tree_level.hash(state);
        self.state.hash(state);
        self.flags.hash(state);
    }
}

impl Default for RootEntry {
    fn default() -> Self {
        Self {
            crc32c: 0,
            owner_zone: 0,
            version: 0,
            root_page: 0,
            page_limit_at_commit: 0,
            prev_record: 0,
            meta_root: 0,
            ixfr_root: 0,
            deleted_txn: 0,
            rrset_count: 0,
            soa_serial: 0,
            free_head: 0,
            tree_level: 0,
            state: RootState::Init,
            flags: RootFlags::empty(),
        }
    }
}

impl RootEntry {
    /// Кодирует запись в 64 байта и пересчитывает CRC.
    #[must_use]
    pub fn encode(&self) -> [u8; ROOT_ENTRY_SIZE as usize] {
        let mut raw = [0_u8; ROOT_ENTRY_SIZE as usize];
        put_u32(&mut raw, ROOT_OFF_OWNER, self.owner_zone);
        put_u64(&mut raw, ROOT_OFF_VERSION, self.version);
        put_u32(&mut raw, ROOT_OFF_ROOT_PAGE, self.root_page);
        put_u32(&mut raw, ROOT_OFF_PAGE_LIMIT, self.page_limit_at_commit);
        put_u32(&mut raw, ROOT_OFF_PREV_RECORD, self.prev_record);
        put_u32(&mut raw, ROOT_OFF_META_ROOT, self.meta_root);
        put_u32(&mut raw, ROOT_OFF_IXFR_ROOT, self.ixfr_root);
        put_u64(&mut raw, ROOT_OFF_DELETED_TXN, self.deleted_txn);
        put_u32(&mut raw, ROOT_OFF_RRSET_COUNT, self.rrset_count);
        put_u32(&mut raw, ROOT_OFF_SOA_SERIAL, self.soa_serial);
        put_u32(&mut raw, ROOT_OFF_FREE_HEAD, self.free_head);
        put_u16(&mut raw, ROOT_OFF_TREE_LEVEL, self.tree_level);
        put_u8(&mut raw, ROOT_OFF_STATE, self.state.to_disk());
        put_u8(&mut raw, ROOT_OFF_FLAGS, self.flags.bits());
        let crc = root_crc(&raw);
        put_u32(&mut raw, ROOT_OFF_CRC, crc);
        raw
    }

    /// Декодирует запись, проверяя длину и CRC.
    ///
    /// Возвращает `None` для torn/нулевой записи (не паникует на мусоре).
    #[must_use]
    pub fn decode(raw: &[u8]) -> Option<Self> {
        Self::decode_impl(raw, true)
    }

    /// Декодирует образ, уже проверенный seqlock-протоколом публикации.
    ///
    /// CRC на диске защищает от torn-записи и проверяется при чтении/открытии;
    /// в памяти [`crate::parallel::store`] публикует целостный 64-байтный образ
    /// под seqlock, поэтому повторный CRC на каждом снапшоте не нужен. Поля
    /// (`flags`, `state`, границы) по-прежнему валидируются.
    #[must_use]
    pub(crate) fn decode_published(raw: &[u8]) -> Option<Self> {
        Self::decode_impl(raw, false)
    }

    fn decode_impl(raw: &[u8], verify_crc: bool) -> Option<Self> {
        let record = raw.get(..ROOT_ENTRY_SIZE as usize)?;
        let stored_crc = get_u32(record, ROOT_OFF_CRC)?;
        if verify_crc {
            if root_crc(record) != stored_crc {
                return None;
            }
        } else if record.iter().all(|&byte| byte == 0) {
            // Нулевой образ — сентинел «головы нет» (`PublishedHead::new`).
            return None;
        }
        let flags = RootFlags::from_bits(get_u8(record, ROOT_OFF_FLAGS)?)?;
        let state = RootState::from_disk(get_u8(record, ROOT_OFF_STATE)?)?;
        Some(Self {
            crc32c: stored_crc,
            owner_zone: get_u32(record, ROOT_OFF_OWNER)?,
            version: get_u64(record, ROOT_OFF_VERSION)?,
            root_page: get_u32(record, ROOT_OFF_ROOT_PAGE)?,
            page_limit_at_commit: get_u32(record, ROOT_OFF_PAGE_LIMIT)?,
            prev_record: get_u32(record, ROOT_OFF_PREV_RECORD)?,
            meta_root: get_u32(record, ROOT_OFF_META_ROOT)?,
            ixfr_root: get_u32(record, ROOT_OFF_IXFR_ROOT)?,
            deleted_txn: get_u64(record, ROOT_OFF_DELETED_TXN)?,
            rrset_count: get_u32(record, ROOT_OFF_RRSET_COUNT)?,
            soa_serial: get_u32(record, ROOT_OFF_SOA_SERIAL)?,
            free_head: get_u32(record, ROOT_OFF_FREE_HEAD)?,
            tree_level: get_u16(record, ROOT_OFF_TREE_LEVEL)?,
            state,
            flags,
        })
    }

    /// Проверяет семантические границы записи (§4.1).
    ///
    /// `page_count_max` ограничивает `page_limit_at_commit`.
    ///
    /// # Errors
    ///
    /// [`RootFieldError`] — первое нарушенное поле.
    pub fn check_fields(&self, page_count_max: u32) -> Result<(), RootFieldError> {
        if self.version < 2 {
            return Err(RootFieldError::Version);
        }
        if self.state.to_disk() > 2 {
            return Err(RootFieldError::State);
        }
        let is_tombstone = self.state == RootState::Tombstone;
        if is_tombstone != (self.deleted_txn != 0) {
            return Err(RootFieldError::DeletedTxn);
        }
        if self.soa_serial > 0x7FFF_FFFF {
            return Err(RootFieldError::Serial);
        }
        if RootFlags::from_bits(self.flags.bits()).is_none() {
            return Err(RootFieldError::Flags);
        }
        if self.tree_level > MAX_TREE_DEPTH {
            return Err(RootFieldError::TreeLevel);
        }
        if self.ixfr_root != 0 {
            return Err(RootFieldError::IxfrRoot);
        }
        if self.page_limit_at_commit == 0 || self.page_limit_at_commit > page_count_max {
            return Err(RootFieldError::PageLimit);
        }
        for pointer in [
            self.root_page,
            self.meta_root,
            self.free_head,
            self.prev_record,
        ] {
            if pointer != 0 && pointer >= self.page_limit_at_commit {
                return Err(RootFieldError::PointerBeyondLimit);
            }
        }
        Ok(())
    }

    /// Tombstone-запись (зона удалена).
    #[must_use]
    pub const fn is_tombstone(&self) -> bool {
        matches!(self.state, RootState::Tombstone) || self.deleted_txn != 0
    }

    /// Запись принадлежит зоне `zone` и валидна по CRC (уже проверен в decode).
    #[must_use]
    pub const fn belongs_to(&self, zone: u32) -> bool {
        self.owner_zone == zone
    }
}

/// CRC `RootEntry`: диапазон `[4, 64)` (поле CRC исключено).
fn root_crc(record: &[u8]) -> u32 {
    record.get(ROOT_OFF_OWNER..).map_or(0, crc32c)
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

fn put_u8(data: &mut [u8], off: usize, value: u8) {
    if let Some(span) = data.get_mut(off..off + 1) {
        span.copy_from_slice(&[value]);
    }
}

fn put_u16(data: &mut [u8], off: usize, value: u16) {
    if let Some(span) = data.get_mut(off..off + 2) {
        span.copy_from_slice(&value.to_le_bytes());
    }
}

fn put_u32(data: &mut [u8], off: usize, value: u32) {
    if let Some(span) = data.get_mut(off..off + 4) {
        span.copy_from_slice(&value.to_le_bytes());
    }
}

fn put_u64(data: &mut [u8], off: usize, value: u64) {
    if let Some(span) = data.get_mut(off..off + 8) {
        span.copy_from_slice(&value.to_le_bytes());
    }
}
