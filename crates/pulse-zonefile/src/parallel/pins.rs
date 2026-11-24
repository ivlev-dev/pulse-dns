//! In-process пины читателей, `EpochGuard`, `MP(z)`/`RV_z` (фаза A).
//!
//! Файловая reader table в фазе A не используется (межпроцессные пины — M3).
//! Слот читателя содержит 6 пинов по 16 Б (`zone_seq u32 | pad u32 | version
//! u64`) и защищён seqlock: GC читает слот без блокировок, а писатель слота —
//! только сам поток-читатель.
//!
//! Порядок памяти повторяет ADR-0006 §8.2: `pin` — `Release`,
//! `fence(SeqCst)` перед чтением guard, GC читает пины `Acquire` под нечётным
//! guard.

use std::cell::Cell;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering, fence};

use crate::parallel::consts::{NO_VERSION, READER_PINS};
use crate::parallel::error::ParallelError;

/// Смещение `zone_seq` в пине (для golden/тестов).
pub const PIN_OFF_ZONE: usize = 0;
/// Смещение `version` в пине.
pub const PIN_OFF_VERSION: usize = 8;

/// Один пин (16 Б в файловой раскладке: `zone_seq u32 | pad u32 | version u64`).
#[derive(Debug)]
struct PinEntry {
    zone: AtomicU32,
    pad: AtomicU32,
    version: AtomicU64,
}

impl PinEntry {
    fn new() -> Self {
        Self {
            zone: AtomicU32::new(0),
            pad: AtomicU32::new(0),
            version: AtomicU64::new(0),
        }
    }

    fn clear(&self) {
        self.zone.store(0, Ordering::Release);
        self.pad.store(0, Ordering::Release);
        self.version.store(0, Ordering::Release);
    }
}

/// Слот читателя: 6 пинов + overflow-EPOCH + seqlock.
#[derive(Debug)]
struct PinSlot {
    owner_token: AtomicU64,
    seq: AtomicU64,
    pins: [PinEntry; READER_PINS],
    overflow_count: AtomicU32,
    overflow_epoch: AtomicU64,
}

impl PinSlot {
    fn new() -> Self {
        Self {
            owner_token: AtomicU64::new(0),
            seq: AtomicU64::new(0),
            pins: std::array::from_fn(|_| PinEntry::new()),
            overflow_count: AtomicU32::new(0),
            overflow_epoch: AtomicU64::new(NO_VERSION),
        }
    }
}

/// Ключ занятого пина.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PinKey {
    /// Пин конкретной зоны.
    Zone(usize),
    /// EPOCH-пин (переполнение 6 слотов): удерживает всё `≤ epoch`.
    Overflow,
}

/// Таблица in-process читателей.
#[derive(Debug)]
pub struct PinTable {
    slots: Box<[PinSlot]>,
    token_seq: AtomicU64,
    overflow_total: AtomicU64,
}

impl PinTable {
    /// Создаёт таблицу на `slots` читателей.
    ///
    /// # Errors
    ///
    /// `InvalidArgument` — `slots == 0`.
    pub fn new(slots: u32) -> Result<Self, ParallelError> {
        if slots == 0 {
            return Err(ParallelError::InvalidArgument {
                field: "reader_slots",
            });
        }
        let count = usize::try_from(slots).map_err(|_| ParallelError::InvalidArgument {
            field: "reader_slots",
        })?;
        let mut vec = Vec::new();
        vec.try_reserve_exact(count)
            .map_err(|_| ParallelError::TooManyReaders)?;
        vec.resize_with(count, PinSlot::new);
        Ok(Self {
            slots: vec.into_boxed_slice(),
            token_seq: AtomicU64::new(1),
            overflow_total: AtomicU64::new(0),
        })
    }

    /// Число слотов.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.slots.len()
    }

    /// Число случаев переполнения 6 пинов (метрика `pw_reader_pin_overflow_total`).
    #[must_use]
    pub fn overflow_total(&self) -> u64 {
        self.overflow_total.load(Ordering::Relaxed)
    }

    fn register(&self) -> Result<(usize, u64), ParallelError> {
        let incarnation = self.token_seq.fetch_add(1, Ordering::AcqRel);
        let pid = u64::from(std::process::id());
        let token = (pid << 32) | (incarnation & 0xFFFF_FFFF);
        for (index, slot) in self.slots.iter().enumerate() {
            if slot
                .owner_token
                .compare_exchange(0, token, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Ok((index, token));
            }
        }
        Err(ParallelError::TooManyReaders)
    }

    fn unregister(&self, index: usize, token: u64) {
        if let Some(slot) = self.slots.get(index) {
            let _ =
                slot.owner_token
                    .compare_exchange(token, 0, Ordering::AcqRel, Ordering::Acquire);
            slot.seq.fetch_add(1, Ordering::AcqRel);
            for pin in &slot.pins {
                pin.clear();
            }
            slot.overflow_count.store(0, Ordering::Release);
            slot.overflow_epoch.store(NO_VERSION, Ordering::Release);
            slot.seq.fetch_add(1, Ordering::Release);
        }
    }

    fn begin_write(&self, index: usize) -> Option<&PinSlot> {
        let slot = self.slots.get(index)?;
        slot.seq.fetch_add(1, Ordering::AcqRel);
        Some(slot)
    }

    fn end_write(slot: &PinSlot) {
        slot.seq.fetch_add(1, Ordering::Release);
    }

    /// Занимает пин зоны; при переполнении — EPOCH-пин.
    ///
    /// `epoch` — значение `e0` (`published_txn` до чтения головы).
    pub(crate) fn pin_zone(&self, index: usize, zone: u32, version: u64, epoch: u64) -> PinKey {
        let Some(slot) = self.begin_write(index) else {
            return PinKey::Overflow;
        };
        let mut key = PinKey::Overflow;
        for (pin_index, pin) in slot.pins.iter().enumerate() {
            if pin.zone.load(Ordering::Acquire) == 0 {
                pin.zone.store(zone, Ordering::Release);
                pin.pad.store(0, Ordering::Release);
                pin.version.store(version, Ordering::Release);
                key = PinKey::Zone(pin_index);
                break;
            }
        }
        if matches!(key, PinKey::Overflow) {
            slot.overflow_count.fetch_add(1, Ordering::AcqRel);
            let mut current = slot.overflow_epoch.load(Ordering::Acquire);
            loop {
                let next = current.min(epoch);
                match slot.overflow_epoch.compare_exchange_weak(
                    current,
                    next,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => break,
                    Err(observed) => current = observed,
                }
            }
            self.overflow_total.fetch_add(1, Ordering::Relaxed);
        }
        Self::end_write(slot);
        key
    }

    /// Снимает пин.
    pub(crate) fn unpin(&self, index: usize, key: PinKey) {
        let Some(slot) = self.begin_write(index) else {
            return;
        };
        match key {
            PinKey::Zone(pin_index) => {
                if let Some(pin) = slot.pins.get(pin_index) {
                    pin.clear();
                }
            }
            PinKey::Overflow => {
                let previous = slot.overflow_count.fetch_sub(1, Ordering::AcqRel);
                if previous <= 1 {
                    slot.overflow_count.store(0, Ordering::Release);
                    slot.overflow_epoch.store(NO_VERSION, Ordering::Release);
                }
            }
        }
        Self::end_write(slot);
    }

    /// Минимальный удерживаемый `version` зоны (или EPOCH-граница).
    ///
    /// `None` — пинов нет.
    #[must_use]
    pub fn oldest_reader(&self, zone: u32) -> Option<u64> {
        let mut oldest: Option<u64> = None;
        for slot in &self.slots {
            let Some(first) = Self::read_slot(slot) else {
                continue;
            };
            for pin in &first.pins {
                if pin.0 == zone && pin.1 != 0 {
                    oldest = Some(oldest.map_or(pin.1, |value| value.min(pin.1)));
                }
            }
            if first.overflow {
                oldest = Some(oldest.map_or(first.epoch, |value| value.min(first.epoch)));
            }
        }
        oldest
    }

    /// Все активные пины (для диагностики/тестов).
    #[must_use]
    pub fn snapshot_pins(&self) -> Vec<(u32, u64)> {
        let mut pins = Vec::new();
        for slot in &self.slots {
            if let Some(view) = Self::read_slot(slot) {
                for pin in view.pins {
                    if pin.0 != 0 && pin.1 != 0 {
                        pins.push(pin);
                    }
                }
            }
        }
        pins
    }

    fn read_slot(slot: &PinSlot) -> Option<SlotView> {
        let seq_before = slot.seq.load(Ordering::Acquire);
        if seq_before & 1 != 0 {
            return None;
        }
        let mut pins = [(0_u32, 0_u64); READER_PINS];
        for (index, pin) in pins.iter_mut().enumerate() {
            let entry = slot.pins.get(index)?;
            if entry.pad.load(Ordering::Acquire) != 0 {
                return None;
            }
            *pin = (
                entry.zone.load(Ordering::Acquire),
                entry.version.load(Ordering::Acquire),
            );
        }
        let overflow_count = slot.overflow_count.load(Ordering::Acquire);
        let overflow_epoch = slot.overflow_epoch.load(Ordering::Acquire);
        let seq_after = slot.seq.load(Ordering::Acquire);
        if seq_before != seq_after || seq_after & 1 != 0 {
            return None;
        }
        Some(SlotView {
            pins,
            overflow: overflow_count > 0,
            epoch: overflow_epoch,
        })
    }
}

struct SlotView {
    pins: [(u32, u64); READER_PINS],
    overflow: bool,
    epoch: u64,
}

/// RAII-держатель слота читателя.
///
/// `!Send`/`!Sync`: слот принадлежит потоку (пины — per-thread; мёртвый поток
/// живого процесса не вытесняется, §6.5).
pub struct Reader<'a> {
    table: &'a PinTable,
    index: usize,
    token: u64,
    _not_send: PhantomData<Rc<()>>,
}

impl std::fmt::Debug for Reader<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reader")
            .field("slot", &self.index)
            .field("token", &self.token)
            .finish()
    }
}

impl<'a> Reader<'a> {
    /// Занимает свободный слот.
    ///
    /// # Errors
    ///
    /// `TooManyReaders` — все слоты заняты.
    pub fn register(table: &'a PinTable) -> Result<Self, ParallelError> {
        let (index, token) = table.register()?;
        Ok(Self {
            table,
            index,
            token,
            _not_send: PhantomData,
        })
    }

    /// Индекс слота.
    #[must_use]
    pub const fn slot(&self) -> usize {
        self.index
    }

    /// Захватывает пин зоны (низкоуровневый API; обычно через `zone_snapshot`).
    ///
    /// Пин заимствует читателя на всё время жизни: слот нельзя освободить,
    /// пока жив хотя бы один `PinGuard`.
    #[must_use]
    pub fn pin(&'a self, zone: u32, version: u64, epoch: u64) -> PinGuard<'a> {
        let key = self.table.pin_zone(self.index, zone, version, epoch);
        PinGuard {
            table: self.table,
            index: self.index,
            key,
            zone,
            version,
            _not_send: PhantomData,
        }
    }
}

impl Drop for Reader<'_> {
    fn drop(&mut self) {
        self.table.unregister(self.index, self.token);
    }
}

/// RAII-пин: снимается в `Drop` (успех/паника/ранний выход).
#[derive(Debug)]
pub struct PinGuard<'a> {
    table: &'a PinTable,
    index: usize,
    key: PinKey,
    zone: u32,
    version: u64,
    _not_send: PhantomData<Rc<()>>,
}

impl PinGuard<'_> {
    /// Зона пина (0 для EPOCH-overflow).
    #[must_use]
    pub const fn zone(&self) -> u32 {
        self.zone
    }

    /// Версия пина.
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }

    /// Переполнение слотов (EPOCH-пин).
    #[must_use]
    pub const fn is_overflow(&self) -> bool {
        matches!(self.key, PinKey::Overflow)
    }
}

impl Drop for PinGuard<'_> {
    fn drop(&mut self) {
        self.table.unpin(self.index, self.key);
    }
}

/// RAII-обёртка над `zone_guard[z]` (PW-I14, F-11).
///
/// Нечётное значение существует только внутри `EpochGuard`; `Drop` возвращает
/// чётность при любом выходе, включая `panic = unwind`.
#[derive(Debug)]
pub struct EpochGuard<'a> {
    guard: &'a AtomicU32,
}

impl<'a> EpochGuard<'a> {
    /// Входит в критическую секцию: `guard += 1` (нечёт) + `fence(SeqCst)`.
    #[must_use]
    pub fn enter(guard: &'a AtomicU32) -> Self {
        guard.fetch_add(1, Ordering::AcqRel);
        fence(Ordering::SeqCst);
        Self { guard }
    }
}

impl Drop for EpochGuard<'_> {
    fn drop(&mut self) {
        self.guard.fetch_add(1, Ordering::Release);
    }
}

/// Кэш `MP(z)`/`RV_z` и `freeze_epoch`.
#[derive(Debug)]
pub struct GcState {
    mp: Box<[AtomicU64]>,
    dirty: Box<[AtomicBool]>,
    freeze_epoch: AtomicU64,
    freeze_active: AtomicBool,
}

impl GcState {
    /// Создаёт состояние для `max_zones` зон.
    ///
    /// # Errors
    ///
    /// `InvalidArgument`/`MapFull` — `max_zones == 0` или не хватает памяти.
    pub fn new(max_zones: u32) -> Result<Self, ParallelError> {
        if max_zones == 0 {
            return Err(ParallelError::InvalidArgument { field: "max_zones" });
        }
        let count = usize::try_from(max_zones)
            .map_err(|_| ParallelError::InvalidArgument { field: "max_zones" })?;
        let mut mp = Vec::new();
        mp.try_reserve_exact(count)
            .map_err(|_| ParallelError::MapFull {
                high_water: u64::from(max_zones),
                page_count_max: max_zones,
            })?;
        mp.resize_with(count, || AtomicU64::new(NO_VERSION));
        let mut dirty = Vec::new();
        dirty
            .try_reserve_exact(count)
            .map_err(|_| ParallelError::MapFull {
                high_water: u64::from(max_zones),
                page_count_max: max_zones,
            })?;
        dirty.resize_with(count, || AtomicBool::new(false));
        Ok(Self {
            mp: mp.into_boxed_slice(),
            dirty: dirty.into_boxed_slice(),
            freeze_epoch: AtomicU64::new(0),
            freeze_active: AtomicBool::new(false),
        })
    }

    /// Текущее `MP(z)` (`u64::MAX` — пинов не было).
    #[must_use]
    pub fn mp(&self, zone: u32) -> u64 {
        self.mp
            .get(zone as usize)
            .map_or(NO_VERSION, |value| value.load(Ordering::Acquire))
    }

    /// `fetch_min` при пине (кэш, не источник истины).
    pub(crate) fn note_pin(&self, zone: u32, version: u64) {
        if let Some(slot) = self.mp.get(zone as usize) {
            slot.fetch_min(version, Ordering::AcqRel);
        }
    }

    /// Помечает зону грязной для GC-прохода.
    pub(crate) fn mark_dirty(&self, zone: u32) {
        if let Some(flag) = self.dirty.get(zone as usize) {
            flag.store(true, Ordering::Release);
        }
    }

    /// Пересчитывает `MP(z)` под guard'ом и снимает dirty-флаг.
    ///
    /// # Errors
    ///
    /// `InvalidArgument` — зона вне диапазона.
    pub fn refresh(
        &self,
        zone: u32,
        pins: &PinTable,
        guards: &[AtomicU32],
    ) -> Result<u64, ParallelError> {
        let guard = guards
            .get(zone as usize)
            .ok_or(ParallelError::InvalidArgument { field: "zone_seq" })?;
        let slot = self
            .mp
            .get(zone as usize)
            .ok_or(ParallelError::InvalidArgument { field: "zone_seq" })?;
        let dirty = self
            .dirty
            .get(zone as usize)
            .ok_or(ParallelError::InvalidArgument { field: "zone_seq" })?;
        let epoch_guard = EpochGuard::enter(guard);
        let value = pins.oldest_reader(zone).unwrap_or(NO_VERSION);
        slot.store(value, Ordering::Release);
        dirty.store(false, Ordering::Release);
        drop(epoch_guard);
        Ok(value)
    }

    /// `RV_z = min(D_z − 1, MP(z), freeze_epoch)`; 0, если версий нет.
    #[must_use]
    pub fn reclaim_version(&self, zone: u32, durable_version: u64) -> u64 {
        if durable_version == 0 {
            return 0;
        }
        let freeze = self.freeze_epoch.load(Ordering::Acquire);
        let mut rv = durable_version - 1;
        rv = rv.min(self.mp(zone));
        if freeze != 0 {
            rv = rv.min(freeze);
        }
        rv
    }

    /// Активный `freeze_epoch` (0 — freeze нет).
    #[must_use]
    pub fn freeze_epoch(&self) -> u64 {
        self.freeze_epoch.load(Ordering::Acquire)
    }

    /// Устанавливает `freeze_epoch` (только через [`FreezeGuard`]).
    fn set_freeze(&self, epoch: u64) -> bool {
        if epoch == 0 {
            return false;
        }
        if self
            .freeze_active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.freeze_epoch.store(epoch, Ordering::Release);
            true
        } else {
            false
        }
    }

    fn clear_freeze(&self) {
        self.freeze_epoch.store(0, Ordering::Release);
        self.freeze_active.store(false, Ordering::Release);
    }

    /// Есть ли грязные зоны.
    #[must_use]
    pub fn has_dirty(&self) -> bool {
        self.dirty.iter().any(|flag| flag.load(Ordering::Acquire))
    }

    /// Индексы грязных зон.
    #[must_use]
    pub fn dirty_zones(&self) -> Vec<u32> {
        let mut zones = Vec::new();
        for (index, flag) in self.dirty.iter().enumerate() {
            if flag.load(Ordering::Acquire)
                && let Ok(zone) = u32::try_from(index)
            {
                zones.push(zone);
            }
        }
        zones
    }
}

/// In-process `freeze()`: EPOCH-барьер удержания (фаза A без файлового пина).
#[derive(Debug)]
pub struct FreezeGuard<'a> {
    gc: &'a GcState,
    epoch: u64,
    _not_send: PhantomData<Cell<()>>,
}

impl<'a> FreezeGuard<'a> {
    /// Устанавливает `freeze_epoch = published_txn`.
    ///
    /// # Errors
    ///
    /// `Busy` — freeze уже активен.
    pub fn new(gc: &'a GcState, published_txn: u64) -> Result<Self, ParallelError> {
        if gc.set_freeze(published_txn) {
            Ok(Self {
                gc,
                epoch: published_txn,
                _not_send: PhantomData,
            })
        } else {
            Err(ParallelError::Busy)
        }
    }

    /// Зафиксированное `E`.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }
}

impl Drop for FreezeGuard<'_> {
    fn drop(&mut self) {
        self.gc.clear_freeze();
    }
}
