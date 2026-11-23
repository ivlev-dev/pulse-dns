//! Выбор активной meta, torn-диагностика и граница переиспользования страниц
//! (спецификация §13.7, §14).

use crate::consts::{META_FLAG_NEEDS_FSCK, ROLLBACK_ALERT_AGE_MS};
use crate::errors::ZoneFileError;
use crate::meta::Meta;
use crate::superblock::SyncMode;

/// Состояние одного слота meta после чтения и структурной проверки.
#[derive(Debug, Clone, Copy)]
pub(crate) enum MetaSlot {
    /// Слот валиден и прошёл проверку против superblock.
    Valid(Meta),
    /// Слот никогда не записывался: страница целиком нулевая (§4 шаг 8).
    NotPersisted,
    /// В слоте есть данные, но meta невалидна (torn write или порча).
    Torn {
        /// `txnid` из поля `+16`, если его удалось прочитать (CRC при этом
        /// не проверяется): нужен только для диагностики «мог быть новее».
        readable_txnid: Option<u64>,
    },
}

impl MetaSlot {
    /// Слот содержит torn-запись (данные есть, meta невалидна).
    fn is_torn(self) -> bool {
        matches!(self, Self::Torn { .. })
    }

    /// `txnid` слота, если он известен: из валидной meta или из читаемого поля.
    fn txnid(self) -> Option<u64> {
        match self {
            Self::Valid(meta) => Some(meta.txnid),
            Self::NotPersisted => None,
            Self::Torn { readable_txnid } => readable_txnid,
        }
    }
}

/// Результат выбора активной meta.
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct Recovered {
    /// Выбранная meta; при необходимости с выставленным `NEEDS_FSCK`.
    pub(crate) meta: Meta,
    /// Recovery принял meta новее `durable_watermark` (`Sync`/`Flush` или
    /// `Memory` + opt-in). Диагностика, не ошибка; watermark не повышается.
    /// Чистый `Memory`-фолбэк на durable-мету этот флаг не выставляет — см.
    /// [`Recovered::memory_tail_discarded`].
    pub(crate) unsynced: bool,
    /// Один слот оказался torn при валидном втором — штатный крах, не повод
    /// для `NEEDS_FSCK`. Диагностика для `Stats`/логов.
    pub(crate) torn_meta: bool,
    /// Запись запрещена до offline `fsck` (только `Memory` + opt-in).
    pub(crate) write_locked: bool,
    /// `Memory`: recovery чистым откатом отбросил неподтверждённый хвост (§13.7 шаг 7a).
    pub(crate) memory_tail_discarded: bool,
    /// Единый durable-watermark файла: максимум `min(durable_txn, txnid)` по
    /// валидным метам. Липкий режим, `check_commit_mode` и advisory
    /// `reclaim_txn` считаются от него, а не от `meta.durable_txn` выбранной
    /// meta (§4.1 п. 6, §14, W-10).
    pub(crate) durable_watermark: u64,
}

/// Выбирает активную meta из двух слотов по §13.7.
///
/// Выбирается самая новая валидная meta (tie-break — больший номер слота),
/// а не «`txnid <= durable_txn`»: после падения процесса meta из page cache может
/// быть новее `durable_txn`, но граф при этом цел.
///
/// Torn-слот при валидном втором — штатный крах: выставляется только
/// диагностический `torn_meta`, `NEEDS_FSCK` **не** выставляется. Исключение —
/// у невалидного слота читается `txnid >` выбранного: доказать, что он не
/// новее, нельзя, поэтому `NEEDS_FSCK`. Если невалидны оба слота —
/// `CorruptNoValidMeta`.
///
/// Единый `durable_watermark` — максимум `min(durable_txn, txnid)` по валидным
/// метам; он же возвращается в [`Recovered::durable_watermark`] и используется
/// runtime-проверками. Если durable выбранной meta меньше watermark (W-10:
/// watermark не убывает), это нарушение/порча: `NEEDS_FSCK` + `write_locked`
/// (read-only до offline `fsck`), а не тихое принятие.
///
/// Политика применяется к **эффективному** режиму
/// `sync_mode.effective_mode(durable_watermark)` (§4.1 п. 6):
/// после `durable_txn > 1` `Flush`/`Memory`-файл липко ведёт себя как `Sync`,
/// поэтому неподтверждённый хвост — roll-forward, а не Memory-opt-in.
///
/// Если `txnid(active) > durable_txn`:
/// - эффективный `Sync`/`Flush` — meta принимается, выставляется только
///   диагностический `recovered_unsynced`;
/// - эффективный `Memory` — сначала ищется самая новая валидная meta с
///   `txnid <= durable_txn`: она открывается чисто, `recovered_unsynced`
///   остаётся `false`, отброшенный хвост отмечается `memory_tail_discarded`;
///   если такой нет — без `allow_unsynced_memory_recovery` отказ
///   `UnsyncedMemoryRecovery`, с флагом max-valid принимается с `NEEDS_FSCK`
///   и `write_locked` (запись запрещена до offline `fsck`).
///
/// `empty_slot` — один из слотов пуст (все нули). Для initial-файла
/// (`active.txnid == 1`) это норма: второй слот ещё не записывался. Если же
/// выбранная meta имеет `txnid > 1`, пустой слот — аномалия (освобождён/затёрт
/// без коммита) → `NEEDS_FSCK`. Равные `txnid` с разными корнями/счётчиками
/// также дают `NEEDS_FSCK`.
///
/// # Errors
///
/// `CorruptNoValidMeta` — нет валидных мет; `UnsyncedMemoryRecovery` — Memory
/// без явного разрешения и без durable-фолбэка.
pub(crate) fn select(
    slot_a: MetaSlot,
    slot_b: MetaSlot,
    empty_slot: bool,
    sync_mode: SyncMode,
    allow_unsynced_memory_recovery: bool,
) -> Result<Recovered, ZoneFileError> {
    let slots = [slot_a, slot_b];
    let torn_meta = slots.iter().any(|slot| slot.is_torn());
    let valid: Vec<Meta> = slots
        .iter()
        .filter_map(|slot| match slot {
            MetaSlot::Valid(meta) => Some(*meta),
            MetaSlot::NotPersisted | MetaSlot::Torn { .. } => None,
        })
        .collect();

    // Липкий режим (§4.1 п. 6): классифицируем по эффективному режиму файла,
    // а не сырому `superblock.sync_mode`. Watermark берём как максимум
    // `durable_txn` по валидным метам: после первого успешного `sync()`/`Sync`
    // (`durable_txn > 1`) файл навсегда коммитит `Sync`, поэтому неподтверждённый
    // хвост — roll-forward, а не Memory-opt-in. Torn-слоты watermark не
    // подтверждают и в максимум не входят.
    let durable_max = valid
        .iter()
        .map(|meta| meta.durable_txn.min(meta.txnid))
        .max()
        .unwrap_or(1);
    let effective_mode = sync_mode.effective_mode(durable_max);

    let mut active: Option<Meta> = None;
    let mut needs_fsck = false;
    for meta in &valid {
        let replace = active.is_none_or(|current| {
            meta.txnid > current.txnid
                || (meta.txnid == current.txnid && meta.page_no > current.page_no)
        });
        if replace {
            if let Some(current) = active
                && current.txnid == meta.txnid
                && !same_state(&current, meta)
            {
                needs_fsck = true;
            }
            active = Some(*meta);
        }
    }
    let mut meta = active.ok_or(ZoneFileError::CorruptNoValidMeta)?;

    // Пустой слот при active.txnid > 1 — аномалия: он не был «ещё не записан»
    // (initial-файл имеет txnid = 1), значит его затёрли вне протокола коммита.
    if empty_slot && meta.txnid > 1 {
        needs_fsck = true;
    }

    // Torn-слот с читаемым txnid новее выбранного: нельзя доказать, что он не
    // был новее, значит граф мог быть изменён — нужен fsck. Ненадёжный/нулевой
    // txnid не даёт основания: это штатный torn-write.
    if slots
        .iter()
        .any(|slot| slot.is_torn() && slot.txnid().is_some_and(|txnid| txnid > meta.txnid))
    {
        needs_fsck = true;
    }

    meta.durable_txn = meta.durable_txn.min(meta.txnid);
    // W-10: durable-watermark не убывает. Меньший durable у выбранной meta —
    // нарушение/порча: молча принимать нельзя, запись запрещена до offline fsck.
    let durable_regression = meta.durable_txn < durable_max;
    if durable_regression {
        needs_fsck = true;
    }
    // recovered_unsynced определяется watermark'ом (§13.7 шаг 6), а не
    // durable выбранной meta.
    let mut recovered_unsynced = meta.txnid > durable_max;
    let mut write_locked = durable_regression;
    let mut memory_tail_discarded = false;
    if recovered_unsynced {
        match effective_mode {
            SyncMode::Sync | SyncMode::MetaNoSync => {}
            SyncMode::NoSync => {
                let fallback = valid
                    .iter()
                    .copied()
                    .filter(|candidate| candidate.txnid <= durable_max)
                    .max_by(|a, b| {
                        a.txnid
                            .cmp(&b.txnid)
                            .then_with(|| a.page_no.cmp(&b.page_no))
                    });
                if let Some(fallback) = fallback {
                    // Durable-фолбэк: выбранная meta не новее watermark.
                    // Если её durable ниже watermark — это W-10, не «чисто».
                    meta = fallback;
                    memory_tail_discarded = true;
                    recovered_unsynced = meta.txnid > durable_max;
                    if meta.durable_txn < durable_max {
                        needs_fsck = true;
                        write_locked = true;
                    }
                } else if allow_unsynced_memory_recovery {
                    needs_fsck = true;
                    write_locked = true;
                } else {
                    return Err(ZoneFileError::UnsyncedMemoryRecovery {
                        txnid: meta.txnid,
                        durable_txn: durable_max,
                    });
                }
            }
        }
    }
    if needs_fsck {
        meta.meta_flags |= META_FLAG_NEEDS_FSCK;
    }
    Ok(Recovered {
        meta,
        unsynced: recovered_unsynced,
        torn_meta,
        write_locked,
        memory_tail_discarded,
        durable_watermark: durable_max,
    })
}

/// Правило переиспользования страницы, освобождённой в `free_txn = F` (§14).
///
/// Страница пригодна к выдаче только при **обоих** условиях:
/// `F < durable_txn` **и** `F <= oldest_reader_txn`.
///
/// - Строгое `<` для `durable_txn` намеренно: watermark — нижняя граница
///   восстановления, и страница, освобождённая в самой граничной транзакции,
///   не выдаётся до следующего подтверждённого watermark. `F == durable_txn`
///   → `false`.
/// - `F == oldest_reader_txn` допустимо при `F < durable_txn`: самый старый
///   читатель уже видит состояние `F`, поэтому страницы, заменённые в `F`,
///   ему не нужны.
/// - При `durable_txn == 1` не переиспользуется ничего: первая пользовательская
///   транзакция — 2, а initial-состояние не имеет подтверждённого предка.
///
/// Пока freelist не реализован, функция — единственный источник правила для
/// будущего аллокатора, recovery и `fsck`.
#[must_use]
pub fn is_reclaimable(free_txn: u64, durable_txn: u64, oldest_reader_txn: u64) -> bool {
    durable_txn > 1 && free_txn < durable_txn && free_txn <= oldest_reader_txn
}

fn same_state(a: &Meta, b: &Meta) -> bool {
    a.page_count_high_water == b.page_count_high_water
        && a.zone_dir_root == b.zone_dir_root
        && a.zone_dir_level == b.zone_dir_level
        && a.zone_count == b.zone_count
        && a.freelist_head == b.freelist_head
        && a.freelist_tail == b.freelist_tail
        && a.freelist_buckets == b.freelist_buckets
        && a.freelist_entries == b.freelist_entries
        && a.total_rrsets == b.total_rrsets
        && a.total_rrs == b.total_rrs
}

/// Применяет правило отката к initial meta (§13.7, шаг 11).
///
/// Если активная meta имеет `txnid == 1`, а файл создан заметно раньше открытия,
/// это признак потери данных: выставляется `NEEDS_FSCK`. Старт продолжается только
/// при `allow_rollback_to_initial`.
///
/// # Errors
///
/// `RolledBackToInitial` — откат обнаружен, но не разрешён конфигурацией.
pub(crate) fn apply_rollback_policy(
    mut meta: Meta,
    instance_uuid: [u8; 16],
    created_unix_ns: u64,
    now_unix_ns: u64,
    allow_rollback_to_initial: bool,
) -> Result<Meta, ZoneFileError> {
    if meta.txnid != 1 {
        return Ok(meta);
    }
    let age_ns = now_unix_ns.saturating_sub(created_unix_ns);
    if age_ns <= ROLLBACK_ALERT_AGE_MS.saturating_mul(1_000_000) {
        return Ok(meta);
    }
    meta.set_needs_fsck();
    if allow_rollback_to_initial {
        Ok(meta)
    } else {
        Err(ZoneFileError::RolledBackToInitial {
            instance_uuid,
            created_unix_ns,
        })
    }
}

/// Текущее время в unix-наносекундах.
#[must_use]
pub(crate) fn now_unix_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::{PAGE_META_A, PAGE_META_B, PAGE_SIZE_DEFAULT};

    fn meta(page_no: u32, txnid: u64, durable: u64) -> Meta {
        Meta {
            page_no,
            txnid,
            durable_txn: durable,
            page_size: PAGE_SIZE_DEFAULT,
            page_count_high_water: 16,
            ..Meta::default()
        }
    }

    fn valid(page_no: u32, txnid: u64, durable: u64) -> MetaSlot {
        MetaSlot::Valid(meta(page_no, txnid, durable))
    }

    fn torn(readable_txnid: Option<u64>) -> MetaSlot {
        MetaSlot::Torn { readable_txnid }
    }

    #[test]
    fn selects_newest_valid_meta() {
        let result = select(
            valid(PAGE_META_A, 3, 3),
            valid(PAGE_META_B, 4, 4),
            false,
            SyncMode::Sync,
            false,
        )
        .unwrap();
        assert_eq!(result.meta.txnid, 4);
        assert_eq!(result.meta.page_no, PAGE_META_B);
        assert!(!result.unsynced);
        assert!(!result.torn_meta);
        assert!(!result.write_locked);
        assert_eq!(result.durable_watermark, 4);
    }

    #[test]
    fn selects_newest_even_above_durable_for_sync() {
        let result = select(
            valid(PAGE_META_A, 7, 5),
            valid(PAGE_META_B, 5, 5),
            false,
            SyncMode::Sync,
            false,
        )
        .unwrap();
        assert_eq!(result.meta.txnid, 7);
        assert!(result.unsynced);
        assert!(!result.meta.needs_fsck());
    }

    #[test]
    fn flush_unsynced_is_accepted_with_diagnostic() {
        let result = select(
            valid(PAGE_META_A, 6, 4),
            MetaSlot::NotPersisted,
            false,
            SyncMode::MetaNoSync,
            false,
        )
        .unwrap();
        assert_eq!(result.meta.txnid, 6);
        assert!(result.unsynced);
        assert!(!result.meta.needs_fsck());
        assert!(!result.torn_meta);
    }

    #[test]
    fn memory_unsynced_requires_flag_and_marks_fsck() {
        let denied = select(
            valid(PAGE_META_A, 9, 1),
            MetaSlot::NotPersisted,
            false,
            SyncMode::NoSync,
            false,
        );
        assert!(matches!(
            denied,
            Err(ZoneFileError::UnsyncedMemoryRecovery {
                txnid: 9,
                durable_txn: 1
            })
        ));
        let allowed = select(
            valid(PAGE_META_A, 9, 1),
            MetaSlot::NotPersisted,
            false,
            SyncMode::NoSync,
            true,
        )
        .unwrap();
        assert!(allowed.unsynced);
        assert!(allowed.meta.needs_fsck());
        assert!(allowed.write_locked);
    }

    #[test]
    fn memory_falls_back_to_initial_meta_without_fsck() {
        // durable_max = 1: подтверждена только initial meta (txnid 1).
        let result = select(
            valid(PAGE_META_A, 1, 1),
            valid(PAGE_META_B, 9, 1),
            false,
            SyncMode::NoSync,
            false,
        )
        .unwrap();
        assert_eq!(result.meta.txnid, 1);
        assert_eq!(result.meta.page_no, PAGE_META_A);
        // Выбранная meta не новее durable: это не recovered_unsynced,
        // а отдельная диагностика отброшенного Memory-хвоста.
        assert!(!result.unsynced);
        assert!(result.memory_tail_discarded);
        assert!(!result.meta.needs_fsck());
        assert!(!result.write_locked);
    }

    #[test]
    fn memory_does_not_fall_back_to_unsynced_txn() {
        // txn 4 > durable 1: это не подтверждённая meta, фолбэка нет.
        let denied = select(
            valid(PAGE_META_A, 4, 1),
            valid(PAGE_META_B, 9, 1),
            false,
            SyncMode::NoSync,
            false,
        );
        assert!(matches!(
            denied,
            Err(ZoneFileError::UnsyncedMemoryRecovery {
                txnid: 9,
                durable_txn: 1
            })
        ));
    }

    #[test]
    fn sticky_sync_rolls_forward_memory_tail() {
        // Memory-файл после sync(): durable_max = 4 > 1, значит эффективный
        // режим — Sync. Max-valid meta новее durable принимается roll-forward,
        // без Memory-фолбэка/opt-in/fsck/write-locked.
        let result = select(
            valid(PAGE_META_A, 4, 4),
            valid(PAGE_META_B, 9, 4),
            false,
            SyncMode::NoSync,
            false,
        )
        .unwrap();
        assert_eq!(result.meta.txnid, 9);
        assert_eq!(result.meta.page_no, PAGE_META_B);
        assert!(result.unsynced);
        assert!(!result.meta.needs_fsck());
        assert!(!result.write_locked);
        assert!(!result.memory_tail_discarded);
    }

    #[test]
    fn sticky_sync_accepts_lone_unsynced_meta() {
        // Даже без второго валидного слота sticky-Sync не требует Memory-opt-in.
        let result = select(
            valid(PAGE_META_A, 9, 4),
            torn(None),
            false,
            SyncMode::NoSync,
            false,
        )
        .unwrap();
        assert_eq!(result.meta.txnid, 9);
        assert!(result.unsynced);
        assert!(!result.meta.needs_fsck());
        assert!(!result.write_locked);
        assert!(!result.memory_tail_discarded);
    }

    #[test]
    fn durable_regression_is_not_silently_accepted() {
        // W-10: watermark не убывает. Выбранная B (txn 9) имеет durable 1,
        // но watermark по валидным метам — 6. Это порча: NEEDS_FSCK + read-only.
        let result = select(
            valid(PAGE_META_A, 7, 6),
            valid(PAGE_META_B, 9, 1),
            false,
            SyncMode::NoSync,
            false,
        )
        .unwrap();
        assert_eq!(result.meta.txnid, 9);
        assert_eq!(result.meta.durable_txn, 1);
        assert_eq!(result.durable_watermark, 6);
        assert!(result.unsynced);
        assert!(result.meta.needs_fsck());
        assert!(result.write_locked);
        assert!(!result.memory_tail_discarded);
    }

    #[test]
    fn durable_watermark_comes_from_any_valid_meta() {
        // Durable-водораздел может быть в более старом слоте: runtime обязан
        // использовать watermark (6), а не durable выбранной (4).
        let result = select(
            valid(PAGE_META_A, 7, 6),
            valid(PAGE_META_B, 9, 4),
            false,
            SyncMode::NoSync,
            false,
        )
        .unwrap();
        assert_eq!(result.durable_watermark, 6);
        assert!(result.meta.needs_fsck());
        assert!(result.write_locked);
    }

    #[test]
    fn fully_synced_is_clean() {
        let result = select(
            valid(PAGE_META_A, 5, 5),
            MetaSlot::NotPersisted,
            false,
            SyncMode::NoSync,
            false,
        )
        .unwrap();
        assert!(!result.unsynced);
        assert!(!result.meta.needs_fsck());
        assert!(!result.write_locked);
    }

    #[test]
    fn preserves_needs_fsck_flag() {
        let mut flagged = meta(PAGE_META_A, 3, 3);
        flagged.set_needs_fsck();
        let result = select(
            MetaSlot::Valid(flagged),
            MetaSlot::NotPersisted,
            false,
            SyncMode::Sync,
            false,
        )
        .unwrap();
        assert!(result.meta.needs_fsck());
    }

    #[test]
    fn tie_break_prefers_higher_slot() {
        let result = select(
            valid(PAGE_META_A, 5, 5),
            valid(PAGE_META_B, 5, 5),
            false,
            SyncMode::Sync,
            false,
        )
        .unwrap();
        assert_eq!(result.meta.page_no, PAGE_META_B);
        assert!(!result.meta.needs_fsck());
    }

    #[test]
    fn equal_txnid_with_different_roots_marks_needs_fsck() {
        let mut second = meta(PAGE_META_B, 5, 5);
        second.zone_dir_root = 12;
        second.zone_dir_level = 1;
        let result = select(
            valid(PAGE_META_A, 5, 5),
            MetaSlot::Valid(second),
            false,
            SyncMode::Sync,
            false,
        )
        .unwrap();
        assert_eq!(result.meta.page_no, PAGE_META_B);
        assert!(result.meta.needs_fsck());
    }

    #[test]
    fn closed_torn_slot_with_valid_peer_is_not_fsck() {
        let result = select(
            valid(PAGE_META_A, 5, 5),
            torn(Some(4)),
            false,
            SyncMode::Sync,
            false,
        )
        .unwrap();
        assert_eq!(result.meta.txnid, 5);
        assert!(result.torn_meta);
        assert!(!result.meta.needs_fsck());
    }

    #[test]
    fn unreadable_torn_slot_is_not_fsck() {
        let result = select(
            valid(PAGE_META_A, 5, 5),
            torn(None),
            false,
            SyncMode::Sync,
            false,
        )
        .unwrap();
        assert!(result.torn_meta);
        assert!(!result.meta.needs_fsck());
    }

    #[test]
    fn torn_slot_newer_than_active_marks_needs_fsck() {
        let result = select(
            valid(PAGE_META_A, 5, 5),
            torn(Some(6)),
            false,
            SyncMode::Sync,
            false,
        )
        .unwrap();
        assert_eq!(result.meta.txnid, 5);
        assert!(result.torn_meta);
        assert!(result.meta.needs_fsck());
    }

    #[test]
    fn torn_slot_with_readable_txnid_equal_to_active_is_not_fsck() {
        let result = select(
            valid(PAGE_META_A, 5, 5),
            torn(Some(5)),
            false,
            SyncMode::Sync,
            false,
        )
        .unwrap();
        assert!(result.torn_meta);
        assert!(!result.meta.needs_fsck());
    }

    #[test]
    fn both_invalid_is_corrupt() {
        assert!(matches!(
            select(
                torn(None),
                MetaSlot::NotPersisted,
                false,
                SyncMode::Sync,
                false
            ),
            Err(ZoneFileError::CorruptNoValidMeta)
        ));
        assert!(matches!(
            select(torn(Some(3)), torn(Some(4)), false, SyncMode::Sync, false),
            Err(ZoneFileError::CorruptNoValidMeta)
        ));
    }

    #[test]
    fn empty_slot_after_initial_marks_needs_fsck() {
        let result = select(
            valid(PAGE_META_A, 3, 3),
            MetaSlot::NotPersisted,
            true,
            SyncMode::Sync,
            false,
        )
        .unwrap();
        assert!(result.meta.needs_fsck());
    }

    #[test]
    fn empty_slot_in_initial_state_is_not_torn() {
        // initial-файл: второй слот ещё не записывался — норма без fsck.
        let result = select(
            valid(PAGE_META_A, 1, 1),
            MetaSlot::NotPersisted,
            true,
            SyncMode::Sync,
            false,
        )
        .unwrap();
        assert!(!result.torn_meta);
        assert!(!result.meta.needs_fsck());
    }

    #[test]
    fn reclaim_requires_strict_durable_boundary() {
        // F == durable -> не переиспользуется.
        assert!(!is_reclaimable(5, 5, 10));
        assert!(!is_reclaimable(10, 10, 100));
        // F < durable и F <= oldest_reader -> можно.
        assert!(is_reclaimable(4, 5, 4));
        assert!(is_reclaimable(4, 5, 9));
        // F < durable, но F > oldest_reader -> нельзя.
        assert!(!is_reclaimable(5, 6, 4));
        // F > durable -> нельзя.
        assert!(!is_reclaimable(6, 5, 10));
        // durable == 1 -> ничего не переиспользуется.
        assert!(!is_reclaimable(0, 1, 1));
        assert!(!is_reclaimable(1, 1, 1));
        // durable == 0 (защитно) -> нельзя.
        assert!(!is_reclaimable(0, 0, 0));
    }

    #[test]
    fn rollback_to_initial_requires_opt_in() {
        let meta = meta(PAGE_META_A, 1, 1);
        let old = 1_000_000_000_u64;
        let now = old + 120_000_000_000;
        let denied = apply_rollback_policy(meta, [7; 16], old, now, false);
        assert!(matches!(
            denied,
            Err(ZoneFileError::RolledBackToInitial { .. })
        ));
        let allowed = apply_rollback_policy(meta, [7; 16], old, now, true).unwrap();
        assert!(allowed.needs_fsck());
    }

    #[test]
    fn fresh_initial_meta_is_not_rollback() {
        let meta = meta(PAGE_META_A, 1, 1);
        let now = 10_000_000_000_u64;
        let result = apply_rollback_policy(meta, [7; 16], now - 1_000_000, now, false).unwrap();
        assert!(!result.needs_fsck());
    }
}
