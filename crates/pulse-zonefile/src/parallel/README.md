# `pulse-zonefile::parallel` — фаза A параллельной записи v2.0

Модуль реализует **фазу A** нормативной раскладки
[`docs/spec/parallel-writes-v2.md`](../../../../docs/spec/parallel-writes-v2.md) и
решений ADR-0005 (D-A, D-C, F-8, F-9) / ADR-0006 (PW-I*, §9.2). v1-модули,
их публичный API и поведение не изменены: v2 — отдельный тип
[`ParallelStore`] и отдельный файловый формат 2.0.

## Что реализовано (фаза A)

| Раздел спеки | Реализация |
|---|---|
| §10.1 пролог | superblock A/B (0/1), `LayoutHead` A/B (2/3, 512 Б + CRC), writer registry (4), `ALLOC_RECORD` A/B (5/6), reader region (7…), root directory A/B, данные |
| §4.1 `RootEntry` | ровно 64 Б: `crc [4,64)`, `owner_zone`, `version`, `root_page`, `page_limit_at_commit`, `prev_record`, `meta_root`, `ixfr_root`, `deleted_txn`, `rrset_count`, `soa_serial`, `free_head`, `tree_level`, `state`, `flags`; полная семантическая валидация |
| §3 аллокатор | `reserve_cursor`/`reserve_txn` — `AtomicU64` в памяти; init из `DP`/`DT`; CAS только вперёд; батч 16/кеш 64 и `TXN_BATCH=64`; `[DP, cursor)` — учтённая утечка; `MapFull` на жёстком лимите |
| §3.4 `ALLOC_RECORD` | 256 Б, две копии в **разных** страницах, CRC, `seq`, `page_limit`, `txn_limit`, `leader_term`, `writer_pid`; max-valid по `seq`, регрессия → file-fatal |
| §4.2 ring | 4 версии × 2 копии, A/B в разных 4 `КиБ` страницах, 16 зон/страницу-копию (256 Б на зону) |
| §4.3–4.4 chain | `PAGE_TYPE_ROOT_CHAIN = 11`, одна запись на страницу, `prev_record`; вытеснение при живом пине; лимит `max_root_chain_pages` (по умолчанию 4096); чтение ring → chain до `version ≤ ceiling`; torn/цикл — fail-closed |
| §4.5 публикация | две фазы и **ровно два** `fdatasync`: (1) `ALLOC_RECORD` + chain-страницы → sync, (2) две копии `RootEntry` → sync, затем публикация головы в памяти; `page_limit_at_commit ≤ DP`, `version ≤ DT` |
| §5.2–5.4 пины | in-process слоты: 6 пинов × (`zone_seq`, `pad`, `version`), seqlock; `PinGuard`/`EpochGuard`/`FreezeGuard` — RAII; переполнение 6 пинов → EPOCH-пин; `oldest_reader`/`MP(z)`/`RV_z`; `ZoneDegraded` после `PIN_ATTEMPTS=8` guard-неудач |
| §5.3 `zone_snapshot` | `e0` до головы, пин, `fence(SeqCst)`, `c1==c2` чётный, `e2==e0`, повторное чтение головы; `ceiling = ∞`; tombstone → `NoZoneVersion` |
| §3.5/§9 recovery | выбор валидных копий, `DP = max(ALLOC_RECORD, roots, page_data_first)`, `DT`, `next_txn`, регрессии → `write_locked` + чтение; `fsck_lite()` |
| §11/§12 | инварианты PW-S*/PW-I* проверяются тестами; скрытых глобальных блокировок на read-path нет |

## API

```rust,no_run
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use pulse_zonefile::parallel::{ParallelStore, RootEntry, RootState, StoreConfig, OpenConfigV2};

let dir = tempfile::tempdir()?;
let path = dir.path().join("zones.v2");
let store = ParallelStore::create(&path, StoreConfig::small(64, 4096))?;
let ticket = store.reserve_pages(1)?;
store.write_raw_page(ticket.first_page, b"page payload")?;
store.publish_root(RootEntry {
    owner_zone: 1,
    version: 2,
    root_page: ticket.first_page,
    state: RootState::Serving,
    ..RootEntry::default()
})?;

let reader = store.reader()?;
let snapshot = store.zone_snapshot(&reader, 1)?;   // пин + стабильная версия
drop(snapshot);                                    // unpin

let record = store.select_root(1, u64::MAX)?;      // ring → chain
let report = store.fsck_lite()?;
let reopened = ParallelStore::open(&path, OpenConfigV2::default())?;
# Ok(())
# }
```

- `publish_root` возвращает `ReaderContended` (retryable), если кольцо надо
  вытеснить, а пин появился между планом и фазой 2; повторная публикация
  запишет chain-страницу.
- `store.reader()` — один слот на поток; `Reader` намеренно `!Send`.
  `ZoneSnapshot` держит пин и допускает вложенные снапшоты (6 на читателя).
- Все методы принимают `&self`; стор рассчитан на `Arc<ParallelStore>`.
- `set_crash_hook` — публичный тестовый harness для crash-injection
  (точки `CrashPoint`), в production не устанавливается.

## Инварианты PW-*

| ID | Где проверяется |
|---|---|
| PW-I1/I1a | `RootEntry` кодирует все поля зоны; голова публикуется после durable-фазы; `check_fields` |
| PW-I2/I2a | `EpochGuard` вокруг фазы 2, `e0/c1/c2/e2/root2.version`, `MP += fetch_min` на пине, подъём `MP` только в `gc_pass` под guard |
| PW-I2b/I8 | ring 4×2, chain как safety valve, `prev_record`, лимит 4096, torn одной копии не теряет версию |
| PW-I3/I13 | уникальность `PageId` (bump-аллокатор), `owner_zone` при чтении, chain/bucket-порядок (bucket — фаза B) |
| PW-I4 | `DP`/`DT` только вперёд (`fetch_max`-семантика записи), recovery `max(...)`, `page_limit_at_commit ≤ DP` |
| PW-I5 | ровно два `fdatasync`; корень после durable `ALLOC_RECORD` |
| PW-I6/I6 | `txn` строго возрастает; `next_txn = max(DT, version) + 1`; `txn` не переиспользуется (сгоревшие диапазоны допустимы) |
| PW-I7 | `select(z, ceiling)` = max-valid, tie-break копия A, ring → chain |
| PW-I9 | `MapFull` вместо порчи; резервы/GC-бюджет — фаза B |
| PW-I10 | recovery только под `LOCK_EX` (M1), до публикации; идемпотентен |
| PW-I11 | A/B всех структур — разные 4 `КиБ` страницы (`geometry` + тесты) |
| PW-I12 | `snapshot_seq` отсутствует как ceiling; `zone_snapshot` берёт последнюю версию |
| PW-I14 | `EpochGuard` RAII, `Drop` возвращает чётность, `ZoneDegraded` после 8 попыток |
| PW-S1 | `reserve_cursor`/`reserve_txn` не пишутся в файл |
| PW-S2 | публикация только при `DP > max_allocated_id ∧ DT ≥ V` |
| PW-S3 | A/B не делят страницу; page 3 — `LayoutHead` B |
| PW-S5 | `MP`/`RV` меняются только `gc_pass` под `EpochGuard`; `freeze_epoch` входит в `RV` |
| PW-S6 | `owner_zone` проверяется с CRC; несовпадение → file-fatal |
| PW-S9 | `NoZoneVersion` только «зоны нет/tombstone» |
| PW-S10 | `zone_guard` только через `EpochGuard` |

## Тесты и бенчи

```text
cargo test -p pulse-zonefile --test v2_format   # golden/раскладка/CRC/мусор
cargo test -p pulse-zonefile --test v2_alloc    # 8×10k reserve, уникальность
cargo test -p pulse-zonefile --test v2_ring     # ring/torn/chain/history
cargo test -p pulse-zonefile --test v2_pins     # пины/MP/RV/ZoneDegraded
cargo test -p pulse-zonefile --test v2_recovery # DP/DT/регрессии/file-fatal
cargo test -p pulse-zonefile --test v2_prop     # proptest: encode/decode, мусор
cargo test -p pulse-zonefile --test v2_crash    # fork/kill -9 harness (100+)
cargo bench -p pulse-zonefile --bench v2        # reserve/publish/pin/select
```

`v2_crash` переиспользует собственный test-binary как child (без `unsafe`):
родитель запускает `--exact v2_crash_child`, ребёнок публикует корни и пишет
ack-лог с `sync_data`, родитель убивает его `SIGKILL` (случайная задержка или
детерминированная точка `CrashPoint`). После каждого краха проверяются
`DP ≥ max acked page_limit`, `head.version ≥ max acked version`, отсутствие
`Corrupt`/`fatal` и монотонность `DP` между итерациями.

## Остаток для фазы B

1. B+tree/ключи/overflow-страницы, `owner_zone` в `PageHeader`, проверка
   `page.txn ≤ version` на чтении.
2. Per-zone bucket/donation, `is_reclaimable`, `free_head`, `MP`/`RV`-гейт
   выдачи; chain-GC; возврат утёкших страниц `< DP`.
3. Group commit: batching зон, ровно два fsync на группу, backpressure-очередь,
   `Flush`/`Memory` и sticky-`Sync`.
4. Каталог зон 24 Б (слот 0/`zones()`/`find_zone`), tombstone-GC, слоты
   reader table в файле (межпроцессные пины, M3), writer registry/`LOCK_SH`.
5. `fsck --repair`, `fsck --at-epoch`, дизъюнктность множеств страниц битсетом,
   `MAX_LEAK_RATIO`, метрики/алерты.
6. Страницы 8192/16384 (геометрия ring = 16 зон зафиксирована для 4096).
7. Loom-модели, ARM64 CI, `dm-log-writes`-реплей, `perf c2c`.

## Осознанные ограничения фазы A

- Только `page_size = 4096`; v2-файл с другим размером отвергается.
- Только режим `Sync`; `Flush`/`Memory` → `Unsupported`.
- Txn-курсор и пины — в памяти процесса (M1); второй writer → `Busy`.
- `publish_root` выполняет по два `fdatasync` на вызов (групповой батчинг —
  фаза B), поэтому throughput упирается в fsync одного inode.
- `publish_root` принимает `version` от вызывающего и проверяет монотонность
  внутри зоны; глобальный `txn`-билет выдаёт `AllocHandle::next_txn`, привязка
  `Version = txn` выполняется коммитом фазы B (в фазе A `next_txn` не
  расходуется на публикацию).
- Узкое окно «пин после фазы 2, до публикации головы» может привести к
  перезаписи ring-версии без chain; в фазе A это не даёт use-after-reuse
  (рекламации данных нет), но `select` на такую версию вернёт более старую
  доступную историю. Фаза B закрывает окно повторной проверкой `MP` под guard
  координатора перед рекламацией.
- Головы в памяти хранятся как 8-словный seqlock (`[AtomicU64; 8]` + nonce)
  вместо `ArcSwap<Arc<RootEntry>>`: читатель получает стабильную копию 64 Б без
  блокировок, семантика `Acquire`/`Release` и проверка `root2.version`
  сохранены.
- Writer lease — 256 шардированных `Mutex` (writer-side, не read-path):
  публикации в разные зоны параллельны, коллизия шардов лишь сериализует запись.
- `freeze()` в фазе A — in-process `freeze_epoch` + `FreezeGuard`; файловый
  EPOCH-пин и таймаут-алерт `pw_freeze_timeout_total` — фаза B.
- Leak-accounting `fsck` ограничен `cursor − DP`: без B+tree/pools полный
  обход достижимости невозможен, поэтому отчёт честно называет метрику
  оценкой.
