# `pulse-zonefile::parallel` — параллельная запись v2.0 (фазы A, B1 и B2a)

Модуль реализует **фазу A** нормативной раскладки
[`docs/spec/parallel-writes-v2.md`](../../../../docs/spec/parallel-writes-v2.md) и
решений ADR-0005 (D-A, D-C, F-8, F-9) / ADR-0006 (PW-I*, §9.2), а также
**фазу B1** — B+tree поверх `ParallelStore`, per-zone commit и read snapshots.
v1-модули, их публичный API и поведение не изменены: v2 — отдельные типы
[`ParallelStore`], [`ParallelZones`], [`ParallelZone`], [`ZoneReader`] и
отдельный файловый формат 2.0.

## Что реализовано (фаза B2a): кеш и рекламация

| Раздел спеки | Реализация |
|---|---|
| §5.7/§8.1 `PageCache` | `PageCacheV2` (лимит 1024, 16 шардов × 4 way, метка recency при вставке): страница валидируется один раз на `page_no` (CRC, `owner_zone`, `page.txn ≤ snapshot.version`, структура) и отдаётся `Arc<[u8]>`; warm lookup — без syscall/CRC/аллокаций. Второй уровень — v1 `PageCache` узлов (`store.node_cache()`), поэтому `ZoneReader::lookup/lookup_ref` не декодирует страницу повторно. Метрики: `store.page_cache_stats()`, `store.node_cache_stats()`, `StoreStats::{page_cache_hits, page_cache_misses}` |
| §6.1 bucket | `PAGE_TYPE_FREELIST = 5`: `next_bucket`, `owner_zone`, `drop_txn`, `count`, `flags`, `page_ids[]` (1008 @ 4096); цепочка отсортирована по `drop_txn`, COW-пересборка в коммите; `RootEntry.free_head` |
| §6.2 `is_reclaimable` | `parallel::is_reclaimable(drop_txn, D_z, RV_z, current_version)`; `RV_z = min(D_z−1, MP, freeze)`; выдача только после durable `D_z > drop_txn` |
| §6.3 порядок | bucket `dropped(V)` + старые bucket-образы пишутся в фазе 1; `free_head` — в `RootEntry V`; коммит фиксирует пул в памяти только после fsync фазы 2 (retry `ReaderContended` не удваивает `dropped(V)`) |
| §4.4 chain-GC | `gc_pass` освобождает chain-страницы с `version < min(MP, freeze)` в группу `drop_txn = head.version`; переиспользованный хвост читается как конец chain (`StaleRoot`), не порча |
| overflow/tombstone | `ParallelZone::delete_zone` собирает leaf/branch/overflow-страницы удаляемой зоны в bucket; `free_page` больше не no-op |
| §6.4 donation | `ParallelZone::donate(max_pages)`: durable-коммит с уменьшенным `free_head`, затем перенос в donation-пул; пул любой зоны при отсутствии своих страниц берёт donation (`owner_zone` переписывается при записи) |
| §9.2 | `fsck_lite` валидирует durable free-chain; `fsck_graph` проверяет дерево/overflow/chain/bucket/free, пересечения (`FatalKind::PageOverlap`) и утечки; ошибка фазы 2 → `CommitUncertain` (запись запрещена) |

`fsck_graph()` — структурная проверка (тесты B2a); `fsck_lite()` сохранён
для фазы A, где `root_page` может быть произвольным.

## Что реализовано (фаза B1)

| Раздел спеки | Реализация |
|---|---|
| §4.7 `PageHeader.owner_zone` | `pageio`: `reserved1` (+12) = `owner_zone`, CRC считается по `reserved1 = 0`; `WriteIo` проставляет владельца, `ReaderIo`/`WriteIo` проверяют `owner_zone` и `page.txn ≤ version` до v1-декодера, затем обнуляют `reserved1` |
| §10.2 B+tree | `WriteIo`/`ReaderIo` реализуют v1 [`crate::tree::PageIo`]; COW-дерево (`ZoneTree`) переиспользовано без копирования; overflow-цепочки — v1 |
| §3.2 alloc | страницы — из `AllocHandle` (батч 64), `txn` — из `TXN_BATCH`-блока; каждый коммит пишет только dirty-страницы |
| §4.5 commit | dirty → `pwrite`, `ALLOC_RECORD` + chain → `fdatasync`, две копии `RootEntry` → `fdatasync`, публикация головы; ошибка → rollback (дерево перечитывается от опубликованной головы). `Durability::Sync`; `Flush`/`Memory` → `Unsupported` |
| §5.1–5.3 read | `zones.read(&Reader, origin)` → `ZoneReader`: `ZoneSnapshot` держит пин, дерево читается по версии головы, writer не блокируется; `lookup`, `lookup_ref` (zero-alloc inline), `lookup_all`, `node`, `next_name`, `records` |
| каталог зон | слот `0` root directory (`owner_zone = 0`, `RootFlags::CATALOG`): B+tree `RLE(origin) || T_ZONE_ENTRY` → 72 Б `{magic, zone_seq, soa_serial, origin_len, created_txn}`; `create_zone`/`delete_zone`/`zones`/`writer` |
| writer lease | lease зоны (256 шардов) удерживается на весь `ParallelZone`; один writer на зону, разные зоны пишутся параллельно; same-zone writer ждёт (сериализация), порчи/потерь нет |
| §9.2 file-fatal | чужая `owner_zone` → `Corrupt{ForeignOwner}`, `page.txn > version` → `Corrupt{PageTxn}` (класс file-fatal) |

### B1 API

```rust,no_run
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use pulse_zonefile::key::NameRle;
use pulse_zonefile::parallel::{
    ParallelStore, ParallelZones, RrsetData, StoreConfig, ZoneCreateMeta,
};

let dir = tempfile::tempdir()?;
let path = dir.path().join("zones.v2");
let store = ParallelStore::create(&path, StoreConfig::small(32, 65536))?;
let apex = NameRle::from_ascii("example.com")?;
let mut zones = ParallelZones::open(&store)?;
let zone_seq = zones.create_zone(&apex, ZoneCreateMeta { soa_serial: 1 })?;

let mut writer = zones.writer(&apex)?;              // lease зоны
let www = NameRle::from_ascii("www.example.com")?;
writer.upsert_rrset(&www, 1, 0, &RrsetData::from_slices(300, 0, &[&[192, 0, 2, 1]])?)?;
let outcome = writer.commit()?;                     // 2 fdatasync, публикация головы
drop(writer);

let reader = store.reader()?;                       // один слот на поток
let view = zones.read(&reader, &apex)?;             // пин + версия головы
assert!(view.lookup(&www, 1, 0)?.is_some());
assert_eq!(view.version(), outcome.version);
# Ok(())
# }
```

- `create_zone` — два коммита (пустой `RootEntry` зоны, затем каталог); крах
  между ними оставляет недостижимую зону (PW-L7), не порчу.
- `ParallelZone` — `!Send` (lease + `AllocHandle`): writer открывается в том
  потоке, который пишет; `ParallelZones` — `Sync` для параллельных writers.
  Lease — `std::sync::Mutex`: повторное открытие writer'а той же зоны в том же
  потоке заблокируется (берите один writer на зону).
- `ZoneReader` держит `ZoneSnapshot`: пока он жив, версия и её страницы не
  рекламируются; после `Drop` — `gc_pass`/`MP` (B2).
- Каталог и `zone_seq` восстанавливаются при `ParallelStore::open` из
  встроенного сканирования root directory (включая слот `0`).

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
cargo test -p pulse-zonefile --test v2_zone     # B1: 8 зон × 4 потока, snapshots, reopen
cargo test -p pulse-zonefile --test v2_commit_crash # B1/B2a: kill -9 на фазах коммита
cargo test -p pulse-zonefile --test v2_cache    # B2a: общий кеш, COW, лимит
cargo test -p pulse-zonefile --test v2_cache_alloc # B2a: 0 аллокаций warm lookup
cargo test -p pulse-zonefile --test v2_reclaim  # B2a: пул/пины/GC/donation/10k
cargo test -p pulse-zonefile --test v2_reclaim -- --ignored --nocapture # 10k+10k
cargo bench -p pulse-zonefile --bench v2        # reserve/publish/pin/select
cargo bench -p pulse-zonefile --bench v2_zones  # B1: commit ops/s 1/4/8 потоков, read ns
cargo bench -p pulse-zonefile --bench v2_cache  # B2a: lookup ns, commit+GC, high_water
```

`v2_crash` переиспользует собственный test-binary как child (без `unsafe`):
родитель запускает `--exact v2_crash_child`, ребёнок публикует корни и пишет
ack-лог с `sync_data`, родитель убивает его `SIGKILL` (случайная задержка или
детерминированная точка `CrashPoint`). После каждого краха проверяются
`DP ≥ max acked page_limit`, `head.version ≥ max acked version`, отсутствие
`Corrupt`/`fatal` и монотонность `DP` между итерациями.

## Остаток для фазы B2b

1. Group commit: batching зон, ровно два fsync на группу, backpressure-очередь,
   `Flush`/`Memory` и sticky-`Sync`. Сейчас каждый `commit` — своя группа.
2. Каталог: tombstone-GC (запись каталога и слот `zone_seq`), `MAX_LEAK_RATIO`
   alert, `fsck --repair`.
3. Слоты reader table в файле (межпроцессные пины, M3), writer registry/`LOCK_SH`.
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
- **B1:** каталог — B+tree в слоте `0`, а не 24-Б записи `§5.6`; `meta_root` и
  `free_head` всегда `0` (per-zone meta/bucket — B2).
- **B1:** CRC v2-страницы не покрывает `owner_zone` (`reserved1`): владелец
  аутентифицируется сравнением с зоной, поэтому CRC остаётся совместимым с
  v1-энкодерами без пересчёта.
- **B2a:** каждый `commit` — отдельная группа (2 `fdatasync`); группировка зон —
  B2b. `free_page` собирает страницы в bucket коммита (COW-мусор возвращается
  через `is_reclaimable`).
- **B2a:** `ZoneReader` берёт валидированные страницы из `PageCacheV2` и узлы из
  v1 `PageCache`; холодный первый lookup читает с диска и валидирует CRC.
- **B2a:** аллокатор сначала выдаёт durable-eligible страницы пула, затем
  bump-курсор (спека §6.5 допускает bump-first; выбран пул-first ради
  стабилизации `high_water`). Утечки `< DP` (batch slack/крах) считает
  `fsck_graph`, порог-алерт — B2b.
