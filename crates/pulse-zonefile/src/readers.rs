//! Таблица читателей: регистрация слотов, двухфазный пин, `oldest_reader_txn`
//! (спецификация §6).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::ThreadId;
use std::time::Duration;

use rustix::time::{ClockId, clock_gettime};

use crate::consts::{
    PAGE_READER_TABLE, PAGE_TYPE_READER_TABLE, PIN_ATTEMPTS, READER_FLAG_IN_PROCESS,
    READER_FLAG_LONG_HOLD, READER_PAGE_DESC_SIZE, READER_SLOT_SIZE, READER_SLOTS,
    READER_SLOTS_PER_THREAD, RTP_OFF_CRC32C, RTP_OFF_PAGE_FLAGS, RTP_OFF_PAGE_NO,
    RTP_OFF_PAGE_TYPE, RTP_OFF_VERSION,
};
use crate::errors::{CorruptDetail, CorruptKind, ZoneFileError};
use crate::map::{ReaderRegion, SlotAtomics};

/// Текущий опубликованный `txnid` (in-process `arc-swap` в полной реализации).
#[derive(Debug)]
pub(crate) struct ActiveTxn {
    txnid: AtomicU64,
}

impl ActiveTxn {
    /// Создаёт публикатор с начальным `txnid`.
    #[must_use]
    pub(crate) fn new(txnid: u64) -> Self {
        Self {
            txnid: AtomicU64::new(txnid),
        }
    }

    /// Читает текущий `txnid` с `Acquire`.
    #[must_use]
    pub(crate) fn load(&self) -> u64 {
        self.txnid.load(Ordering::Acquire)
    }

    /// Публикует новый `txnid` с `Release` (внутренняя операция writer'а).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn publish(&self, txnid: u64) {
        self.txnid.store(txnid, Ordering::Release);
    }
}

/// Результат проверки процесса по PID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProcessState {
    /// Процесс существует, `starttime` (incarnation) известен.
    Alive(u32),
    /// PID отсутствует (`ENOENT`).
    Dead,
    /// Прочитать/распарсить `/proc/<pid>/stat` не удалось (EACCES и т.п.).
    Unknown,
}

/// Проверка процесса по PID; trait нужен для fault injection в тестах.
pub(crate) trait ProcessProbe {
    /// Возвращает состояние процесса и его `incarnation`.
    fn probe(&self, pid: u32) -> ProcessState;
}

/// Production-реализация через `/proc/<pid>/stat`.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ProcProcessProbe;

impl ProcessProbe for ProcProcessProbe {
    fn probe(&self, pid: u32) -> ProcessState {
        let path = format!("/proc/{pid}/stat");
        match std::fs::read_to_string(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => ProcessState::Dead,
            Err(_) => ProcessState::Unknown,
            Ok(stat) => match parse_starttime(&stat) {
                Some(incarnation) => ProcessState::Alive(incarnation),
                None => ProcessState::Unknown,
            },
        }
    }
}

fn parse_starttime(stat: &str) -> Option<u32> {
    let (_, tail) = stat.rsplit_once(')')?;
    let field = tail.split_whitespace().nth(19)?;
    let starttime = field.parse::<u64>().ok()?;
    u32::try_from(starttime & u64::from(u32::MAX)).ok()
}

/// Глобальная таблица читателей поверх writable-региона reader table.
#[derive(Debug)]
pub struct ReaderTable {
    region: ReaderRegion,
    slots_per_page: u32,
    per_thread: Mutex<HashMap<ThreadId, u32>>,
    next_slot: AtomicU32,
}

impl ReaderTable {
    /// Создаёт таблицу поверх отображённого региона.
    ///
    /// # Errors
    ///
    /// `Corrupt` — регион не вмещает [`READER_SLOTS`] слотов.
    pub(crate) fn new(region: ReaderRegion) -> Result<Self, ZoneFileError> {
        let slots_per_page = region.slots_per_page();
        if u64::from(region.pages()) * u64::from(slots_per_page) < u64::from(READER_SLOTS) {
            return Err(ZoneFileError::corrupt(
                CorruptKind::Bounds,
                None,
                CorruptDetail::BadReaderRegion,
            ));
        }
        Ok(Self {
            region,
            slots_per_page,
            per_thread: Mutex::new(HashMap::new()),
            next_slot: AtomicU32::new(0),
        })
    }

    /// Число страниц reader table.
    #[must_use]
    pub fn pages(&self) -> u32 {
        self.region.pages()
    }

    /// Число слотов на страницу.
    #[must_use]
    pub fn slots_per_page(&self) -> u32 {
        self.slots_per_page
    }

    /// Регистрирует слот читателя для текущего потока.
    ///
    /// На поток выделяется не более [`READER_SLOTS_PER_THREAD`] слотов.
    ///
    /// # Errors
    ///
    /// `ReaderContended` — у потока уже занято максимум слотов;
    /// `TooManyReaders` — свободных слотов в таблице нет.
    pub(crate) fn register(self: &Arc<Self>) -> Result<ReaderSlot, ZoneFileError> {
        self.register_with(&ProcProcessProbe)
    }

    /// Регистрация с явным probe; тесты подменяют `/proc`.
    fn register_with(
        self: &Arc<Self>,
        probe: &impl ProcessProbe,
    ) -> Result<ReaderSlot, ZoneFileError> {
        let thread_id = std::thread::current().id();
        let mut counts = self
            .per_thread
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let used = counts.get(&thread_id).copied().unwrap_or(0);
        if used >= READER_SLOTS_PER_THREAD {
            return Err(ZoneFileError::ReaderContended);
        }
        let token = owner_token(probe);
        let start = self.next_slot.fetch_add(1, Ordering::Relaxed);
        for offset in 0..READER_SLOTS {
            let index = start.wrapping_add(offset) % READER_SLOTS;
            let Some(atoms) = self.region.slot(index) else {
                continue;
            };
            if atoms
                .owner
                .compare_exchange(0, token, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                atoms.active.store(0, Ordering::Release);
                atoms.heartbeat.store(monotonic_ns(), Ordering::Relaxed);
                atoms.flags.store(READER_FLAG_IN_PROCESS, Ordering::Relaxed);
                increment_slots_used(&self.region, index, self.slots_per_page);
                let entry = counts.entry(thread_id).or_insert(0);
                *entry = entry.saturating_add(1);
                drop(counts);
                return Ok(ReaderSlot {
                    table: Arc::clone(self),
                    index,
                    owner_thread: thread_id,
                });
            }
        }
        Err(ZoneFileError::TooManyReaders)
    }

    /// Минимальный удерживаемый `txnid`.
    ///
    /// Участвуют только слоты, у которых `owner_token != 0` и
    /// `active_txn != 0`. Если таких нет, возвращается `active_txn`.
    #[must_use]
    pub fn oldest_reader_txn(&self, active_txn: u64) -> u64 {
        let mut oldest: Option<u64> = None;
        for index in 0..READER_SLOTS {
            let Some(atoms) = self.region.slot(index) else {
                continue;
            };
            if atoms.owner.load(Ordering::Acquire) == 0 {
                continue;
            }
            let active = atoms.active.load(Ordering::Acquire);
            if active == 0 {
                continue;
            }
            oldest = Some(oldest.map_or(active, |current| current.min(active)));
        }
        oldest.unwrap_or(active_txn)
    }

    /// Число зарегистрированных (не обязательно пиннутых) слотов.
    #[must_use]
    pub fn registered_slots(&self) -> usize {
        (0..READER_SLOTS)
            .filter(|&index| {
                self.region
                    .slot(index)
                    .is_some_and(|atoms| atoms.owner.load(Ordering::Acquire) != 0)
            })
            .count()
    }

    fn release(&self, index: u32, thread_id: ThreadId) {
        let Some(atoms) = self.region.slot(index) else {
            return;
        };
        atoms.active.store(0, Ordering::Release);
        atoms.flags.store(0, Ordering::Relaxed);
        // Счётчик меняется до публикации `owner = 0`: иначе новый владелец
        // успеет сделать increment, а наш decrement потеряет его.
        decrement_slots_used(&self.region, index, self.slots_per_page);
        atoms.owner.store(0, Ordering::Release);
        let mut counts = self
            .per_thread
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = counts.get_mut(&thread_id) {
            if *count > 1 {
                *count -= 1;
            } else {
                counts.remove(&thread_id);
            }
        }
    }
    /// Санитизирует reader table после выбора активной meta (§13.7 шаг 8).
    ///
    /// Мёртвые PID и несовпавший `incarnation` вытесняются: `active_txn = 0`,
    /// `flags = 0`, затем `owner_token = 0`. Живой PID с совпадающим
    /// `incarnation` не вытесняется никогда; слот с `incarnation == 0`
    /// («неизвестен», регистрация при `ProcessProbe::Unknown`) тоже не
    /// вытесняется и даёт `NEEDS_FSCK`. Для вытесняемого слота нарушения
    /// (`active_txn > txnid(active)`, reserved-биты `flags`) сбрасываются с
    /// диагностикой `NEEDS_FSCK`; для живого слота такие нарушения — fail-closed
    /// `Corrupt(BadReaderRegion)`, потому что очистка живого читателя запрещена.
    ///
    /// Возвращает `true`, если требуется `NEEDS_FSCK`.
    ///
    /// # Errors
    ///
    /// `Corrupt` — живой слот содержит `active_txn > txnid(active)`, reserved-биты
    /// флагов или некорректный `owner_token`.
    pub(crate) fn sanitize(
        &self,
        active_txn: u64,
        probe: &impl ProcessProbe,
    ) -> Result<bool, ZoneFileError> {
        let mut needs_fsck = false;
        for index in 0..READER_SLOTS {
            let Some(atoms) = self.region.slot(index) else {
                continue;
            };
            let owner = atoms.owner.load(Ordering::Acquire);
            if owner == 0 {
                continue;
            }
            let pid = u32::try_from(owner >> 32).unwrap_or(0);
            let incarnation = u32::try_from(owner & u64::from(u32::MAX)).unwrap_or(0);
            let active = atoms.active.load(Ordering::Acquire);
            let flags = atoms.flags.load(Ordering::Relaxed);
            let reserved = flags & !(READER_FLAG_LONG_HOLD | READER_FLAG_IN_PROCESS) != 0;
            let page_no = PAGE_READER_TABLE.saturating_add(index / self.slots_per_page);
            if incarnation == 0 {
                // Регистрация при `ProcessProbe::Unknown`: incarnation не
                // доказан. «Мёртвым» его считать нельзя — слот остаётся живым,
                // recovery выставляет NEEDS_FSCK (safe > available).
                needs_fsck = true;
            } else {
                let (alive, unknown) = match probe.probe(pid) {
                    ProcessState::Alive(found) if found == incarnation => (true, false),
                    ProcessState::Alive(_) | ProcessState::Dead => (false, false),
                    // Не смогли прочитать/распарсить /proc: считаем живым и не
                    // вытесняем (SEC-ZF-007), но диагностируем NEEDS_FSCK.
                    ProcessState::Unknown => (true, true),
                };
                if unknown {
                    needs_fsck = true;
                }
                if !alive {
                    // Любое вытеснение мёртвого/несовпавшего слота — диагностика.
                    needs_fsck = true;
                    atoms.active.store(0, Ordering::Release);
                    atoms.flags.store(0, Ordering::Relaxed);
                    // Счётчик уменьшается до публикации owner=0 (как в release).
                    decrement_slots_used(&self.region, index, self.slots_per_page);
                    atoms.owner.store(0, Ordering::Release);
                    continue;
                }
            }
            if active > active_txn {
                return Err(ZoneFileError::corrupt(
                    CorruptKind::Bounds,
                    Some(page_no),
                    CorruptDetail::BadReaderRegion,
                ));
            }
            if reserved {
                return Err(ZoneFileError::corrupt(
                    CorruptKind::Bounds,
                    Some(page_no),
                    CorruptDetail::BadReaderRegion,
                ));
            }
        }
        Ok(needs_fsck)
    }
}

/// Занятый слот читателя; освобождается при `Drop`.
#[derive(Debug)]
pub(crate) struct ReaderSlot {
    table: Arc<ReaderTable>,
    index: u32,
    owner_thread: ThreadId,
}

#[cfg_attr(not(test), allow(dead_code))]
impl ReaderSlot {
    fn atoms(&self) -> Option<SlotAtomics<'_>> {
        self.table.region.slot(self.index)
    }

    /// Глобальный индекс слота.
    #[must_use]
    pub(crate) fn index(&self) -> u32 {
        self.index
    }

    /// Двухфазный пин (§6.3). Внутренняя операция; публично — [`Snapshot`].
    ///
    /// Публикует выбранный `txnid`, затем повторно читает глобальный `active_txn`;
    /// при расхождении откатывает публикацию и повторяет (до [`PIN_ATTEMPTS`]).
    /// До успешной проверки ни одна страница данных не читается.
    ///
    /// # Errors
    ///
    /// `ReaderContended` — активная meta продвинулась [`PIN_ATTEMPTS`] раз подряд.
    pub(crate) fn pin(&self, active: &ActiveTxn) -> Result<u64, ZoneFileError> {
        let atoms = self.atoms().ok_or_else(|| {
            ZoneFileError::corrupt(CorruptKind::Bounds, None, CorruptDetail::BadReaderRegion)
        })?;
        for _ in 0..PIN_ATTEMPTS {
            let txnid = active.load();
            atoms.active.store(txnid, Ordering::Release);
            let check = active.load();
            if check == txnid {
                atoms.heartbeat.store(monotonic_ns(), Ordering::Relaxed);
                return Ok(txnid);
            }
            atoms.active.store(0, Ordering::Release);
        }
        std::thread::sleep(Duration::from_micros(10));
        Err(ZoneFileError::ReaderContended)
    }

    /// Снимает пин: `active_txn = 0` с `Release`.
    pub(crate) fn unpin(&self) {
        if let Some(atoms) = self.atoms() {
            atoms.active.store(0, Ordering::Release);
        }
    }

    /// `txnid`, удерживаемый слотом, если пин взят.
    #[must_use]
    pub(crate) fn pinned_txn(&self) -> Option<u64> {
        let active = self.atoms()?.active.load(Ordering::Acquire);
        (active != 0).then_some(active)
    }
}

/// Поток-локальный вход читателя (возвращается [`crate::ZoneFile::reader`]).
///
/// Слоты занимаются лениво при каждом [`Reader::snapshot`] (до
/// `READER_SLOTS_PER_THREAD`), а [`Snapshot`] владеет пинном и отпускает его
/// при `Drop`.
#[derive(Debug)]
pub struct Reader<'a> {
    table: Arc<ReaderTable>,
    active: &'a ActiveTxn,
    instance_uuid: [u8; 16],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(
        table: Arc<ReaderTable>,
        active: &'a ActiveTxn,
        instance_uuid: [u8; 16],
    ) -> Self {
        Self {
            table,
            active,
            instance_uuid,
        }
    }

    /// Берёт снапшот: занимает слот и выполняет двухфазный `pin` (§6.3).
    ///
    /// Каждый независимый `Snapshot` (не `Clone`) занимает отдельный слот; на
    /// поток допускается [`READER_SLOTS_PER_THREAD`]. `Clone` снапшота не
    /// пиннит повторно, а увеличивает refcount.
    ///
    /// # Errors
    ///
    /// `ReaderContended` — у потока уже 4 снапшота; `TooManyReaders` — таблица
    /// заполнена; `ReaderContended` также при 8 неудачных попытках пина.
    pub fn snapshot(&self) -> Result<Snapshot, ZoneFileError> {
        let slot = self.table.register()?;
        let txnid = slot.pin(self.active)?;
        Ok(Snapshot {
            inner: Arc::new(SnapshotInner {
                _slot: slot,
                txnid,
                instance_uuid: self.instance_uuid,
            }),
        })
    }
}

/// Иммутабельный снапшот `txnid`; держит reader-слот до последнего `Drop`.
#[derive(Debug, Clone)]
pub struct Snapshot {
    inner: Arc<SnapshotInner>,
}

#[derive(Debug)]
struct SnapshotInner {
    // Drop слота выполняет `unpin` и `dereg`; поле читается только через Drop.
    _slot: ReaderSlot,
    txnid: u64,
    /// `instance_uuid` файла, создавшего снапшот (§4): привязывает пин к
    /// reader table конкретного `ZoneFile`.
    instance_uuid: [u8; 16],
}

impl Snapshot {
    /// Зафиксированный `txnid`.
    #[must_use]
    pub fn txnid(&self) -> u64 {
        self.inner.txnid
    }

    /// `instance_uuid` файла, создавшего снапшот.
    ///
    /// Используется [`crate::ZoneFile::page`] для проверки, что снапшот
    /// принадлежит этому файлу: пин чужой reader table не защищает страницы.
    #[must_use]
    pub(crate) fn instance_uuid(&self) -> [u8; 16] {
        self.inner.instance_uuid
    }
}

impl Drop for ReaderSlot {
    fn drop(&mut self) {
        self.table.release(self.index, self.owner_thread);
    }
}

/// Проверяет дескрипторы страниц reader table (§6.1, SEC-ZF-014).
///
/// # Errors
///
/// `Corrupt` — неверный `page_type`/`version`/`page_no`, превышено
/// `slots_used_in_page` или `crc32c != 0`.
pub(crate) fn validate_pages(
    region: &ReaderRegion,
    page_count: u32,
    slots_per_page: u32,
) -> Result<(), ZoneFileError> {
    if region.pages() < page_count || region.page_size() < READER_PAGE_DESC_SIZE {
        return Err(ZoneFileError::corrupt(
            CorruptKind::Bounds,
            None,
            CorruptDetail::BadReaderRegion,
        ));
    }
    for page_index in 0..page_count {
        let page_no = PAGE_READER_TABLE.saturating_add(page_index);
        let bad = || {
            ZoneFileError::corrupt(
                CorruptKind::Bounds,
                Some(page_no),
                CorruptDetail::BadReaderRegion,
            )
        };
        let page_type = region
            .descriptor_u32(page_no, RTP_OFF_PAGE_TYPE)
            .ok_or_else(bad)?;
        let version = region
            .descriptor_u16(page_no, RTP_OFF_VERSION)
            .ok_or_else(bad)?;
        let flags = region
            .descriptor_u16(page_no, RTP_OFF_PAGE_FLAGS)
            .ok_or_else(bad)?;
        let stored_page_no = region
            .descriptor_u32(page_no, RTP_OFF_PAGE_NO)
            .ok_or_else(bad)?;
        let crc = region
            .descriptor_u32(page_no, RTP_OFF_CRC32C)
            .ok_or_else(bad)?;
        let used = region
            .slots_used(page_no)
            .ok_or_else(bad)?
            .load(Ordering::Acquire);
        if page_type != PAGE_TYPE_READER_TABLE
            || version != 1
            || flags != 0
            || stored_page_no != page_no
            || used > slots_per_page
            || crc != 0
        {
            return Err(ZoneFileError::corrupt(
                CorruptKind::Bounds,
                Some(page_no),
                CorruptDetail::BadReaderRegion,
            ));
        }
    }
    Ok(())
}

/// Число слотов на страницу для размера страницы.
#[must_use]
pub fn slots_per_page(page_size: u32) -> Option<u32> {
    let usable = page_size.checked_sub(READER_PAGE_DESC_SIZE)?;
    let slots = usable / READER_SLOT_SIZE;
    (slots > 0).then_some(slots)
}

fn increment_slots_used(region: &ReaderRegion, index: u32, slots_per_page: u32) {
    let page_no = PAGE_READER_TABLE.saturating_add(index / slots_per_page);
    if let Some(counter) = region.slots_used(page_no) {
        let _ = counter.try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        });
    }
}

fn decrement_slots_used(region: &ReaderRegion, index: u32, slots_per_page: u32) {
    let page_no = PAGE_READER_TABLE.saturating_add(index / slots_per_page);
    if let Some(counter) = region.slots_used(page_no) {
        let _ = counter.try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_sub(1)
        });
    }
}

/// `owner_token` для слота: PID + incarnation.
///
/// `ProcessProbe::Unknown` не означает «мёртв»: incarnation пишется как `0`
/// («неизвестен»), а `sanitize` такой слот не вытесняет и выставляет
/// `NEEDS_FSCK` (safe > available, SEC-ZF-007).
fn owner_token(probe: &impl ProcessProbe) -> u64 {
    let pid = std::process::id();
    let incarnation = match probe.probe(pid) {
        ProcessState::Alive(incarnation) => incarnation,
        ProcessState::Dead | ProcessState::Unknown => 0,
    };
    let token = (u64::from(pid) << 32) | u64::from(incarnation);
    if token == 0 { 1 } else { token }
}

fn monotonic_ns() -> u64 {
    let ts = clock_gettime(ClockId::Monotonic);
    let secs = u64::try_from(ts.tv_sec).unwrap_or(0);
    let nanos = u64::try_from(ts.tv_nsec).unwrap_or(0);
    secs.saturating_mul(1_000_000_000).saturating_add(nanos)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    fn table(page_size: u32) -> Arc<ReaderTable> {
        let geometry = crate::consts::ReaderGeometry::for_page_size(page_size).unwrap();
        let file = tempfile::tempfile().unwrap();
        file.set_len(geometry.region_off + geometry.region_len)
            .unwrap();
        let region = ReaderRegion::map(
            &file,
            geometry.region_off,
            geometry.region_len,
            page_size,
            geometry.pages,
            geometry.slots_per_page,
        )
        .unwrap();
        Arc::new(ReaderTable::new(region).unwrap())
    }

    #[test]
    fn free_slots_do_not_count_as_readers() {
        let table = table(4096);
        assert_eq!(table.oldest_reader_txn(7), 7);
        let slot = table.register().unwrap();
        assert_eq!(table.oldest_reader_txn(7), 7);
        assert_eq!(slot.pinned_txn(), None);
    }

    #[test]
    fn pinned_reader_is_visible_and_unpin_clears_it() {
        let table = table(4096);
        let active = ActiveTxn::new(5);
        let slot = table.register().unwrap();
        assert_eq!(slot.pin(&active).unwrap(), 5);
        assert_eq!(table.oldest_reader_txn(99), 5);
        assert_eq!(slot.pinned_txn(), Some(5));
        slot.unpin();
        assert_eq!(table.oldest_reader_txn(99), 99);
        assert_eq!(slot.pinned_txn(), None);
    }

    #[test]
    fn oldest_is_minimum_over_live_readers() {
        let table = table(4096);
        let active = ActiveTxn::new(10);
        let first = table.register().unwrap();
        let second = table.register().unwrap();
        first.pin(&active).unwrap();
        active.publish(4);
        second.pin(&active).unwrap();
        assert_eq!(table.oldest_reader_txn(100), 4);
        drop(second);
        assert_eq!(table.oldest_reader_txn(100), 10);
        drop(first);
        assert_eq!(table.oldest_reader_txn(100), 100);
    }

    #[test]
    fn thread_limit_is_four_slots() {
        let table = table(4096);
        let slots: Vec<_> = (0..READER_SLOTS_PER_THREAD)
            .map(|_| table.register().unwrap())
            .collect();
        assert_eq!(slots.len(), 4);
        assert!(matches!(
            table.register(),
            Err(ZoneFileError::ReaderContended)
        ));
        assert_eq!(table.registered_slots(), 4);
        drop(slots);
        assert_eq!(table.registered_slots(), 0);
        let _slot = table.register().unwrap();
    }

    #[test]
    fn registration_is_visible_in_page_counter() {
        let table = table(4096);
        let slot = table.register().unwrap();
        let page_no = PAGE_READER_TABLE + slot.index() / table.slots_per_page();
        assert_eq!(
            table
                .region
                .slots_used(page_no)
                .unwrap()
                .load(Ordering::Relaxed),
            1
        );
        drop(slot);
        assert_eq!(
            table
                .region
                .slots_used(page_no)
                .unwrap()
                .load(Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn pinned_reader_keeps_its_txn_after_meta_advance() {
        let table = table(8192);
        let active = ActiveTxn::new(3);
        let slot = table.register().unwrap();
        assert_eq!(slot.pin(&active).unwrap(), 3);
        active.publish(9);
        assert_eq!(slot.pinned_txn(), Some(3));
        assert_eq!(table.oldest_reader_txn(9), 3);
        slot.unpin();
        assert_eq!(slot.pin(&active).unwrap(), 9);
    }

    fn write_slot(table: &ReaderTable, index: u32, owner: u64, active: u64, flags: u64) {
        let atoms = table.region.slot(index).unwrap();
        atoms.owner.store(owner, Ordering::Release);
        atoms.active.store(active, Ordering::Release);
        atoms.flags.store(flags, Ordering::Release);
    }

    fn slot_values(table: &ReaderTable, index: u32) -> (u64, u64, u64) {
        let atoms = table.region.slot(index).unwrap();
        (
            atoms.owner.load(Ordering::Acquire),
            atoms.active.load(Ordering::Acquire),
            atoms.flags.load(Ordering::Acquire),
        )
    }

    fn live_owner_token() -> u64 {
        owner_token(&ProcProcessProbe)
    }

    #[test]
    fn sanitize_evicts_dead_pid() {
        let table = table(4096);
        let dead = (0xFFFF_FFFE_u64 << 32) | 7;
        write_slot(&table, 0, dead, 0, READER_FLAG_IN_PROCESS);
        assert!(table.sanitize(1, &ProcProcessProbe).unwrap());
        assert_eq!(slot_values(&table, 0), (0, 0, 0));
        assert_eq!(
            table
                .region
                .slots_used(PAGE_READER_TABLE)
                .unwrap()
                .load(Ordering::Acquire),
            0
        );
    }

    #[test]
    fn sanitize_evicts_incarnation_mismatch() {
        let table = table(8192);
        let pid = u64::from(std::process::id());
        let wrong = match ProcProcessProbe.probe(std::process::id()) {
            ProcessState::Alive(value) => value.wrapping_add(1),
            ProcessState::Dead | ProcessState::Unknown => 1,
        };
        write_slot(
            &table,
            127,
            (pid << 32) | u64::from(wrong),
            0,
            READER_FLAG_IN_PROCESS,
        );
        assert!(table.sanitize(1, &ProcProcessProbe).unwrap());
        assert_eq!(slot_values(&table, 127), (0, 0, 0));
    }

    #[test]
    fn sanitize_keeps_live_reader() {
        let table = table(16384);
        let token = live_owner_token();
        write_slot(&table, 5, token, 1, READER_FLAG_IN_PROCESS);
        table
            .region
            .slots_used(PAGE_READER_TABLE)
            .unwrap()
            .store(1, Ordering::Release);
        assert!(!table.sanitize(1, &ProcProcessProbe).unwrap());
        assert_eq!(slot_values(&table, 5), (token, 1, READER_FLAG_IN_PROCESS));
        assert_eq!(
            table
                .region
                .slots_used(PAGE_READER_TABLE)
                .unwrap()
                .load(Ordering::Acquire),
            1
        );
    }

    #[test]
    fn sanitize_rejects_live_reader_with_active_txn_above_meta() {
        let table = table(4096);
        let token = live_owner_token();
        write_slot(&table, 0, token, 5, READER_FLAG_IN_PROCESS);
        assert!(matches!(
            table.sanitize(1, &ProcProcessProbe),
            Err(ZoneFileError::Corrupt {
                kind: CorruptKind::Bounds,
                detail: CorruptDetail::BadReaderRegion,
                ..
            })
        ));
        assert_eq!(slot_values(&table, 0).0, token);
    }

    #[test]
    fn sanitize_rejects_live_reader_with_reserved_flags() {
        let table = table(4096);
        let token = live_owner_token();
        write_slot(&table, 0, token, 1, READER_FLAG_IN_PROCESS | (1 << 5));
        assert!(matches!(
            table.sanitize(1, &ProcProcessProbe),
            Err(ZoneFileError::Corrupt { .. })
        ));
    }

    #[test]
    fn sanitize_dead_reader_with_bad_state_clears_and_marks_fsck() {
        let table = table(4096);
        let dead = (0xFFFF_FFFE_u64 << 32) | 7;
        write_slot(&table, 0, dead, 9, READER_FLAG_IN_PROCESS | (1 << 5));
        assert!(table.sanitize(1, &ProcProcessProbe).unwrap());
        assert_eq!(slot_values(&table, 0), (0, 0, 0));
    }

    struct UnknownProbe;

    impl ProcessProbe for UnknownProbe {
        fn probe(&self, _pid: u32) -> ProcessState {
            ProcessState::Unknown
        }
    }

    struct AliveProbe(u32);

    impl ProcessProbe for AliveProbe {
        fn probe(&self, _pid: u32) -> ProcessState {
            ProcessState::Alive(self.0)
        }
    }

    #[test]
    fn unknown_incarnation_at_register_is_not_evicted() {
        let table = table(4096);
        let slot = table.register_with(&UnknownProbe).unwrap();
        let index = slot.index();
        let (owner, active, flags) = slot_values(&table, index);
        // incarnation неизвестен → 0, но PID записан: это не «мёртвый» слот.
        assert_ne!(owner, 0);
        assert_eq!(owner & u64::from(u32::MAX), 0);
        // Позднее probe знает настоящую incarnation: слот не вытесняется,
        // но recovery обязан выставить NEEDS_FSCK.
        assert!(table.sanitize(1, &AliveProbe(42)).unwrap());
        assert_eq!(slot_values(&table, index), (owner, active, flags));
        assert_eq!(
            table
                .region
                .slots_used(PAGE_READER_TABLE)
                .unwrap()
                .load(Ordering::Acquire),
            1
        );
    }

    #[test]
    fn sanitize_keeps_reader_when_proc_is_unreadable_and_marks_fsck() {
        let table = table(4096);
        let token = live_owner_token();
        write_slot(&table, 0, token, 1, READER_FLAG_IN_PROCESS);
        table
            .region
            .slots_used(PAGE_READER_TABLE)
            .unwrap()
            .store(1, Ordering::Release);
        // Unknown = «жив, но не подтверждён»: слот не вытесняется, но recovery
        // обязан выставить NEEDS_FSCK.
        assert!(table.sanitize(1, &UnknownProbe).unwrap());
        assert_eq!(slot_values(&table, 0), (token, 1, READER_FLAG_IN_PROCESS));
        assert_eq!(
            table
                .region
                .slots_used(PAGE_READER_TABLE)
                .unwrap()
                .load(Ordering::Acquire),
            1
        );
    }

    #[test]
    fn sanitize_recomputes_slots_used() {
        let table = table(4096);
        let dead = (0xFFFF_FFFE_u64 << 32) | 7;
        write_slot(&table, 0, live_owner_token(), 1, READER_FLAG_IN_PROCESS);
        write_slot(&table, 127, dead, 5, READER_FLAG_IN_PROCESS);
        table
            .region
            .slots_used(PAGE_READER_TABLE)
            .unwrap()
            .store(1, Ordering::Release);
        table
            .region
            .slots_used(PAGE_READER_TABLE + 1)
            .unwrap()
            .store(1, Ordering::Release);
        assert!(table.sanitize(1, &ProcProcessProbe).unwrap());
        assert_eq!(
            table
                .region
                .slots_used(PAGE_READER_TABLE)
                .unwrap()
                .load(Ordering::Acquire),
            1
        );
        assert_eq!(
            table
                .region
                .slots_used(PAGE_READER_TABLE + 1)
                .unwrap()
                .load(Ordering::Acquire),
            0
        );
    }

    #[test]
    fn concurrent_register_and_sanitize_keep_slots_used_consistent() {
        let table = table(4096);
        let mut handles = Vec::new();
        for _ in 0..4 {
            let table = Arc::clone(&table);
            handles.push(std::thread::spawn(move || {
                for _ in 0..200 {
                    let slot = table.register().unwrap();
                    drop(slot);
                }
            }));
        }
        for _ in 0..100 {
            table.sanitize(1, &ProcProcessProbe).unwrap();
        }
        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(table.registered_slots(), 0);
        for page in 0..table.pages() {
            assert_eq!(
                table
                    .region
                    .slots_used(PAGE_READER_TABLE + page)
                    .unwrap()
                    .load(Ordering::Acquire),
                0
            );
        }
    }

    #[test]
    fn two_phase_pin_never_returns_stale_txn() {
        let table = Arc::new(table(16_384));
        let active = Arc::new(ActiveTxn::new(1));
        let stop = Arc::new(AtomicBool::new(false));
        let publisher = {
            let active = Arc::clone(&active);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut txn = 1_u64;
                while !stop.load(Ordering::Relaxed) {
                    txn += 1;
                    active.publish(txn);
                }
            })
        };
        let slot = table.register().unwrap();
        let mut previous = 0;
        for _ in 0..5_000 {
            let txn = loop {
                match slot.pin(&active) {
                    Ok(txn) => break txn,
                    Err(ZoneFileError::ReaderContended) => {}
                    Err(error) => panic!("unexpected pin error: {error}"),
                }
            };
            assert!(txn >= previous);
            assert_eq!(slot.pinned_txn(), Some(txn));
            previous = txn;
            slot.unpin();
        }
        stop.store(true, Ordering::Relaxed);
        publisher.join().unwrap();
    }
}
