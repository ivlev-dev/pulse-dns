# `pulse-zonefile::parallel` — параллельная запись v2.0 (фазы A, B1, B2a и B2b)

Модуль реализует **фазу A** нормативной раскладки
[`docs/spec/parallel-writes-v2.md`](../../../../docs/spec/parallel-writes-v2.md) и
решений ADR-0005 (D-A, D-C, F-8, F-9) / ADR-0006 (PW-I*, §9.2), а также
**фазу B1** — B+tree поверх `ParallelStore`, per-zone commit и read snapshots.
**Фаза B2b** — group commit (батчинг зон, ровно два `fdatasync` на группу),
`Flush`/`Memory` и липкий `Sync`, tombstone-GC каталога, sweep утечек и
offline `fsck --repair`. **M3 (ADR 0007)** — sidecar-координатор, per-zone
lease/fencing, общая reader table, multi-writer каталог и межпроцессная
рекламация durable-пулов.
v1-модули, их публичный API и поведение не изменены: v2 — отдельные типы
[`ParallelStore`], [`ParallelZones`], [`ParallelZone`], [`ZoneReader`] и
отдельный файловый формат 2.0.

## Что реализовано (фаза B2b): group commit, durability, GC каталога, repair

| Раздел спеки | Реализация |
|---|---|
| §7.1 group commit | `GroupCommitter` (channel + фоновый координатор) батчит подготовленные коммиты разных зон: `MAX_BATCH_ZONES = 256`, `MAX_BATCH_BYTES = 1 MiB`, `MAX_BATCH_DELAY = 1 мс`, bulk-коммит > `256 КиБ` — отдельной группой. Фаза 1: `ALLOC_RECORD` + chain/bucket всех зон → `fdatasync`; фаза 2: две копии `RootEntry` всех зон → `fdatasync`; затем публикация голов и ack. Синхронный вход — `ParallelStore::commit_group`. |
| §7.1/§7.3 backpressure | Очередь координатора `QUEUE_ZONES = 1024` (bounded `sync_channel`) + байтовый шлюз `QUEUE_BYTES = 64 MiB` (condvar). Писатель ждёт ack; ошибка I/O → `CommitUncertain` (`write_locked`) для **всех** зон группы и ни одной публикации; `ReaderContended` — per-zone retryable. |
| §7.2 `Flush`/`Memory` | `commit_with(Durability)`/`commit_via_with`: `Sync` — 2 fsync и двигает `D_z`; `Flush` — fsync данных (фаза 1), корни без fsync, `D_z`/`DT` не двигаются; `Memory` — ни одного fsync. Липкий `Sync` (`DT > 1` или `sync_mode = Sync`) → слабее нельзя (`DurabilityBelowFileMode`). `sync()` — durable-чекпойнт: alloc + fsync, `D_z := head.version`, липкий `Sync`. Recovery учитывает режим: корни новее `ALLOC_RECORD` для `Flush`/`Memory` не file-fatal. |
| §5.6/§6.5 tombstone-GC | `delete_zone` пишет tombstone; `ParallelZones::gc_catalog` удаляет каталог-запись **после** durable `deleted_txn`, после чего `zone_seq` переиспользуется `create_zone` (origin можно создать заново). Крах на любой стадии не оставляет каталог-запись на удалённую зону. |
| §6.5/R4 утечки | `ParallelStore::leak_report` (leaked `[data_first, DP)`, aborted `[DP, cursor)`, `MAX_LEAK_RATIO = 1 %`); `repair_leaks` возвращает утёкшие страницы durable-free в bucket каталога, проверяет дизъюнктность и идемпотентность; `fsck_repair(path)` — offline `LOCK_EX`. Пересечение множеств (`PageOverlap`) — отказ, не «починка». |
| §7.3 метрики | `StoreStats::{group_commits, group_members, group_fsyncs, group_max_members, group_aborted, aborted_pages_estimate}`, `GroupStats`, `LeakReport::{leaked_pages, ratio, max_ratio, exceeds_max_ratio}`. |
| §7.1/§7.5 межпроцессная группа (M3) | Очередь клиентов в sidecar (v4): писатель кладёт 64-Б `RootEntry` в свой слот, координатор (любой процесс, взявший `fcntl`-lease `COMMIT`) собирает пачку ≤256 зон за `SHARED_SETTLE = 1 мс`, пишет `ALLOC_RECORD` + один `fdatasync`, затем все копии корней + второй `fdatasync`, публикует `D_z`/`published` и подтверждает слоты (CAS `READY→DONE` + futex wake). `ParallelStore::shared_group_stats()` — `groups/fsyncs/members/max_members` по всей очереди; `shared_leader()` — `(term, pid, starttime)`. |

### B2b API

```rust,no_run
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use std::sync::Arc;
use pulse_zonefile::key::NameRle;
use pulse_zonefile::parallel::{
    Durability, GroupCommitter, ParallelStore, ParallelZones, RrsetData, StoreConfig,
    ZoneCreateMeta,
};

let dir = tempfile::tempdir()?;
let path = dir.path().join("zones.v2");
let store = Arc::new(ParallelStore::create(&path, StoreConfig::small(64, 1 << 20))?);
let mut zones = ParallelZones::open(&store)?;
let apex = NameRle::from_ascii("example.com")?;
zones.create_zone(&apex, ZoneCreateMeta { soa_serial: 1 })?;

let committer = GroupCommitter::new(Arc::clone(&store))?;
let mut writer = zones.writer(&apex)?;
let www = NameRle::from_ascii("www.example.com")?;
writer.upsert_rrset(&www, 1, 0, &RrsetData::from_slices(300, 0, &[&[192, 0, 2, 1]])?)?;
let outcome = writer.commit_via(&committer)?;        // ack после публикации головы
drop(writer);
committer.shutdown();

// `Flush`/`Memory` — только для файла, созданного в этом режиме.
// `sync()` делает коммиты durable и включает липкий `Sync`.
assert_eq!(store.effective_mode(), Durability::Sync);
assert!(store.durable_version(outcome.zone) >= outcome.version);

// Утечки и offline `fsck --repair`.
let report = store.leak_report()?;
let repaired = report.leaked_pages;
let _ = repaired;
drop(zones);
drop(store);
let repair = pulse_zonefile::parallel::fsck_repair(&path)?;
assert!(repair.ok || repair.remaining_leaks == 0);
# Ok(())
# }
```

- `commit_via` батчится с другими зонами; одна зона без компании всё равно
  получает 2 `fdatasync` (ожидаемая плата за ack-семантику).
- `GroupCommitter::stats()` — собственные счётчики: `fsyncs == groups * 2` для
  `Sync`, `max_members`, `aborted`.
- `create_zone` переиспользует свободный tombstone-слот; каталог чистится
  `gc_catalog` (после durable-удаления).

## Bulk-load: полная замена зоны без COW на каждый `RRset`

`ParallelZone::bulk_load` строит B+tree **снизу вверх** из отсортированного
потока `BulkRrset` (листья → ветвления → корень), пишет каждую страницу один
раз и делает **один** `commit`/`commit_with`. `T_NODE`/ENT и overflow-цепочки
материализуются на лету; старые страницы дерева уходят в `drops` того же
коммита (ring/chain/catalog/PageCache/GC работают штатно).

```rust,no_run
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use pulse_zonefile::key::NameRle;
use pulse_zonefile::parallel::{BulkRrset, ParallelStore, ParallelZones, RrsetData, StoreConfig, ZoneCreateMeta};
let dir = tempfile::tempdir()?;
let store = ParallelStore::create(&dir.path().join("z.v2"), StoreConfig::small(4, 1 << 20))?;
let mut zones = ParallelZones::open(&store)?;
let apex = NameRle::from_ascii("example.com")?;
let seq = zones.create_zone(&apex, ZoneCreateMeta { soa_serial: 1 })?;
let name = NameRle::from_ascii("www.example.com")?;
let mut writer = zones.writer_by_seq(seq)?;
writer.bulk_load([BulkRrset {
    name,
    rr_type: 1,
    subtype: 0,
    data: RrsetData::from_slices(300, 0, &[&[192, 0, 2, 1]])?,
}])?;                                   // вход строго по каноническому ключу
writer.commit()?;                       // одна публикация; старый root в drops
# Ok(())
# }
```

Инварианты:

- вход строго возрастает по `(owner, type, subtype)` (`RRSIG` — по covered
  type); нарушение/дубликат → `ParallelError::BulkOrder` **до** публикации,
  writer откатывается к опубликованной голове;
- на одного owner'а буферизуется не больше
  [`BULK_MAX_OWNER_BYTES`](crate::parallel::BULK_MAX_OWNER_BYTES) = 256 MiB
  (нужно для точного `CHILDREN_MAY_EXIST` по следующему имени); превышение →
  `BulkTooLarge`;
- память самого загрузчика — O(лист + ветвление + один owner), а не O(зона);
- `Memory`-коммит публикует `page_limit_at_commit ≥ cursor` (F-4): после
  reopen recovery не занижает `DP` и не выдаёт занятые страницы повторно;
- `pulsed import`/`--replace`, secondary/sign и `pulse-zonegen` используют
  bulk; обычный `upsert_rrset`/`delete_*` не изменены.

Замер (`pulse-zonegen --sync memory`, AMD Ryzen 5 3500U, loopback-стенд):

| RRset | было (COW) | bulk | страниц записано | пик RSS |
|---|---|---|---|---|
| 100k | ~60 с, 2.3 GiB диска | **0.25 с**, 9.2 MiB диска | 2 369 (9.3 MiB) | 14 MiB |
| 1M | ~1578 с, 16 GiB диска | **2.5–2.8 с**, 91 MiB диска | 20 292 (79 MiB) | 91–103 MiB |

## Что реализовано (фаза B2a): кеш и рекламация

| Раздел спеки | Реализация |
|---|---|
| §5.7/§8.1 `PageCache` | `PageCacheV2` (лимит `page_cache_entries`, 16 шардов × 4 way, метка recency при вставке): страница валидируется один раз на `(page_no, generation)` (CRC, `owner_zone`, `page.txn ≤ snapshot.version`, структура) и отдаётся `Arc<[u8]>`; warm lookup — без syscall/CRC/аллокаций. В multi `generation` читается из sidecar (`page_gen`, ADR 0007 §7.4) и возрастает при выдаче/освобождении/записи; в single — всегда 0. Второй уровень — v1 `PageCache` узлов (`store.node_cache()`), ключ в multi `(page_no, generation, snapshot_version)`, поэтому `ZoneReader::lookup/lookup_ref` не декодирует страницу повторно: кеш хранит только метаданные (`NodeMeta` с точными `Box<[T]>`, без фиксированных массивов на 1024 item'а) и байтово-сравнимые 16-Б префиксы ключей. Роли разделены: `PageCacheV2` — образы страниц, `PageCache` — разобранные узлы; hit не пишет в разделяемые атомики. Метрики: `store.page_cache_stats()`, `store.node_cache_stats()`, `store.cache_memory_bytes()`, `store.page_generation_bytes()`, `PageCache::evictions()`, `StoreStats::{page_cache_hits, page_cache_misses}` |
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
cargo test -p pulse-zonefile --test v2_group    # B2b: group commit, fsync/группу, backpressure
cargo test -p pulse-zonefile --test v2_group -- --ignored --nocapture # нативный wall-clock замер
cargo test -p pulse-zonefile --test v2_durability # B2b: Flush/Memory/sticky/sync, kill -9, torn
cargo test -p pulse-zonefile --test v2_catalog_gc # B2b: tombstone-GC + recreate
cargo test -p pulse-zonefile --test v2_multiprocess # M3: shared allocator/lease/reader, 1000 зон
cargo test -p pulse-zonefile --test v2_multiprocess_reclaim # M3: 4×insert/delete, kill -9, reader
cargo test -p pulse-zonefile --test v2_multiprocess_reclaim -- --ignored --nocapture # 10k insert+delete
cargo test -p pulse-zonefile --test v2_leak     # B2b: leak sweep/repair/MAX_LEAK_RATIO
cargo test -p pulse-zonefile --test v2_group_crash # B2b: kill -9 групп (random + точки)
cargo test -p pulse-zonefile --test v2_group_prop  # B2b: proptest монотонности/выбора
cargo bench -p pulse-zonefile --bench v2        # reserve/publish/pin/select
cargo bench -p pulse-zonefile --bench v2_multiprocess_reclaim # create/commit/reclaim
cargo bench -p pulse-zonefile --bench v2_zones  # B1: commit ops/s 1/4/8 потоков, read ns
cargo bench -p pulse-zonefile --bench v2_cache  # B2a: lookup ns, commit+GC, high_water
cargo bench -p pulse-zonefile --bench v2_group  # B2b: group vs per-zone, fsync/группу, p50/p99
```

`v2_crash` переиспользует собственный test-binary как child (без `unsafe`):
родитель запускает `--exact v2_crash_child`, ребёнок публикует корни и пишет
ack-лог с `sync_data`, родитель убивает его `SIGKILL` (случайная задержка или
детерминированная точка `CrashPoint`). После каждого краха проверяются
`DP ≥ max acked page_limit`, `head.version ≥ max acked version`, отсутствие
`Corrupt`/`fatal` и монотонность `DP` между итерациями. `v2_group_crash`
делает то же для группового коммита: ack-лог после публикации головы, случайный
`SIGKILL` и детерминированные точки фаз группы.

### Замер B2b (8 потоков, 32 зоны, `COMMITS=16`)

| Устройство | per-zone | group | ratio | p50 group | p99 group | fsync/группу |
|---|---|---|---|---|---|---|
| локальная btrfs (`fdatasync ≈ 30–60 µs`) | 38.6k z/s | 23.3k z/s | 0.60× | 204 µs | 530 µs | 2.00 |
| модель durable-устройства (`fdatasync = 400 µs`, сериализован) | 1.05k z/s | 4.47k z/s | **4.28×** | 2.03 ms | 2.18 ms | 2.00 |

На 4 потоках — 2.60×, на 1 потоке — 0.47× (батчинга нет, платится
`MAX_BATCH_DELAY`). Нативный fsync на локальной ФС почти бесплатен, поэтому
group commit там проигрывает на накладных расходах; выигрыш — на устройстве, где
fsync доминирует (целевой режим спеки §7.4).

## M3: межпроцессная запись (ADR 0007)

M3 реализован отдельным координатором `<file>.pulsecoord` (`MAP_SHARED`):
общий CAS-курсор/`txn`, per-zone `fcntl`-lease с fencing `(pid, starttime,
generation)`, общая reader table, per-zone seqlock публикации и глобальный
commit-lock для `ALLOC_RECORD`/двух `fdatasync`. Формат данных v2.0 не изменён;
`SEC-ZF-014` (один writable-регион файла данных) сохранён.

```rust,no_run
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use pulse_zonefile::parallel::{OpenConfigV2, ParallelStore};
let store = ParallelStore::open(
    std::path::Path::new("zones.v2"),
    OpenConfigV2 { multi_process: true, writer_lock: false, ..OpenConfigV2::default() },
)?;
let reader = store.reader()?;                 // общий слот reader table
let _snap = store.zone_snapshot(&reader, 1)?; // seqlock + пин
# let _ = store;
# Ok(())
# }
```

Тесты: `tests/v2_multiprocess.rs` (4×4 зоны, `ZoneBusy`, читатель в другом
процессе, `kill -9` писателя/читателя/во время коммита, 10k циклов в 2
процессах + `fsck`). Bench: `cargo bench -p pulse-zonefile --bench v2_multiprocess`.

## Остаток до фазы C

1. Выборный лидер M3 (`leader_term`, writer registry) и `fsck --verify` уровня
   «полный scrub»: битсет-дизъюнктность на больших файлах, `fsck --at-epoch`,
   проверка `page.txn ≤ version` по всем достижимым страницам.
2. Страницы 8192/16384 (геометрия ring = 16 зон зафиксирована для 4096).
3. Loom-модели, ARM64 CI, `dm-log-writes`-реплей, `perf c2c`, `strace -c`.
4. Bulk-lane и шардирование координатора для потолка `fdatasync` (R7).

## Осознанные ограничения фазы A

- Только `page_size = 4096`; v2-файл с другим размером отвергается.
- Single-process (по умолчанию): txn-курсор и пины — в памяти процесса; второй
  writer файла → `Busy`. M3 включается `multi_process: true` (ADR 0007).
- В multi рекламация durable-пулов идёт под lease зоны с гейтом
  `drop_txn < min(D_z, MP всех процессов, freeze)`; append-only + COW-компакция.
  Каталог могут менять все процессы (catalog lease + commit-lock), readers
  обновляются `refresh()`. Page/node-кеш в multi включён: ключ содержит общую
  генерацию страницы из sidecar (`COORD_VERSION = 4`, ADR 0007 §7.4); в v4
  добавлена очередь group commit (`clients` + счётчики групп/fsync/лидера).
  `fsck --repair` и `[DP, cursor)` после `kill -9` — офлайн (M3-L11).
  При единственном живом сторе (`alive_hint == 1`) коммит идёт прежним
  локальным путём — single-process поведение и latency не меняются;
  `PULSE_MP_DIRECT_COMMIT` принудительно включает старый путь для бенчей.
- `publish_root` (низкоуровневый API фазы A) всегда выполняет два `fdatasync`;
  группировка — `commit_group`/`GroupCommitter` (B2b).
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
- **B2a:** `free_page` собирает страницы в bucket коммита (COW-мусор
  возвращается через `is_reclaimable`).
- **B2a:** `ZoneReader` берёт валидированные страницы из `PageCacheV2` и узлы из
  v1 `PageCache`; холодный первый lookup читает с диска и валидирует CRC.
  Арена снапшота — `HashMap<page_no, Arc<[u8]>>` (поиск `O(1)`).
- **read-path:** поиск в узле сравнивает 16-Б байтово-сравнимый префикс ключа
  (`memcmp`) и собирает полный ключ только при равных префиксах; префикс —
  производная в памяти, на диске его нет. `lookup_ref` отдаёт заимствованный
  payload без копирования; `NameRle` берётся из уже провалидированного ключа.
- **snapshot:** `zone_snapshot` подтверждает стабильность головы повторным
  чтением seqlock-счётчика, а не полным CRC/декодированием `RootEntry`.
- **B2a:** аллокатор сначала выдаёт durable-eligible страницы пула, затем
  bump-курсор (спека §6.5 допускает bump-first; выбран пул-first ради
  стабилизации `high_water`).
- **B2b:** `LeakReport.leaked_pages` включает batch slack аллокатора (до 64
  страниц на активный handle): это честная оценка `fsck`, а не порча.
  `repair_leaks` — offline-операция (без активных писателей), иначе возможна
  гонка с выдачей из батча.
- **B2b:** `fsck_repair` возвращает утёкшие страницы в durable bucket каталога;
  кросс-зонное перераспределение остаётся donation-ом (`ParallelZone::donate`).
- **B2b:** один поток без компании платит `MAX_BATCH_DELAY` + два fsync за
  коммит; выигрыш group commit начинается с ≥ 4 одновременных писателей и
  заметного fsync (модельный замер — 4.3× на 8 потоках).
- **B2b:** `ReaderContended` внутри группы отменяет только эту зону; уже
  записанные в фазе 1 bucket/chain-образы остаются недостижимыми (утечка,
  `group_aborted`), её возвращает `fsck --repair`. Публикации головы зоны при
  этом не происходит.
