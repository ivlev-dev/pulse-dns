# Спецификация v2: аллокатор, публикация корней, пины, GC и group commit

- **Файл:** `docs/spec/parallel-writes-v2.md` · **Формат:** 2.0 · **Статус:** проект на утверждение
- **Роль:** нормативная **раскладка полей и пошаговые протоколы** для `docs/adr/0005-parallel-writers.md` (решения, границы, цена, миграция, отклонения D-A…D-D) и `docs/adr/0006-parallel-writers-safety.md` (инварианты `PW-I*`, crash-матрица `PW-C*`, `SEC-PW-*`, условия C-1…C-11). Дельта формата к v1 — `docs/spec/zonefile-v1.md` §25.
- **Реализует:** `pulse-zonefile` — allocator, root ring/chain, reader pins, free pools, group commit, recovery, `fsck`.
- **Правило чтения:** этот документ — единственная нормативная раскладка полей. Решения и обоснование — ADR-0005; требования безопасности — ADR-0006/ADR-0004 §1.3.

> **Принятые решения, которым подчинён документ:** **D-A** — `RootEntry` **64 Б**, без отдельного `ZoneRootBlock`; **D-C** — курсор и `txn`-билет **в памяти**, в файле только `ALLOC_RECORD` (A/B в разных страницах), второго writable-региона нет; **F-9** — `snapshot_seq` **не ceiling** (`ceiling = ∞`), retention — только `freeze()`.
>
> **M3 (ADR 0007):** межпроцессная запись не меняет раскладку данных. Общий
> курсор/`txn`, lease-слоты, `zone_write_seq`, reader table и `D_z[]` живут в
> sidecar `<file>.pulsecoord` (`MAP_SHARED`, **D-E**); durable-барьер —
> по-прежнему `ALLOC_RECORD` в файле данных под глобальным commit-lock.
> В multi-режиме bucket-цепочка публикуется **append-only** (`next = старый
> head`, on-disk порядок `drop_txn` убывает; `FreeChain::load` понимает оба
> порядка, **D-F**). Durable-пулы переиспользуются под lease зоны при
> `drop_txn < min(D_z, MP всех процессов, freeze)`; при появлении `dirty`
> цепочка пересобирается COW, при ≥64 группах — сливается (ADR 0007 §7).

---

## 0. Область и нормативные решения

**Входит:** структуры/смещения/порядки памяти для аллокатора, ring+chain, пинов/`MP(z)`/`freeze()`, free pools/donation, двухфазного group commit, recovery, file-fatal политики, метрик, миграции и приёмки M1.

**Не входит:** B+tree/ключи/overflow (v1 без изменений), NSEC3, WAL, онлайн-рост `map_size`, межпроцессная запись — ADR 0007 (sidecar, lease, reader table).

| # | Решение | Раздел |
|---|---|---|
| 1 | **D-A**: `RootEntry` 64 Б (все мутируемые поля зоны), ring 4×2 в разных страницах, **16 зон/страница-копия** | §4.1–4.2 |
| 2 | **F-8**: ring — быстрый путь; при исчерпании писатель **не блокируется**, вытесняя самую старую версию в chain (`PAGE_TYPE_ROOT_CHAIN = 11`, `prev_record`); chain достижим из durable-записи | §4.3–4.4 |
| 3 | **D-C**: `reserve_cursor`/`reserve_txn` — `AtomicU64` в памяти; durable-барьер — `ALLOC_RECORD` (2 копии в разных страницах); writable-регион один (reader table) | §3.1, §3.5 |
| 4 | **F-9**: `snapshot_seq` — не ceiling; `ZoneSnapshot` берёт последнюю версию; `NoZoneVersion` — только «зоны нет/tombstone»; чтение-на-T — `freeze()` + EPOCH-пин | §5.1, §5.3, §5.7 |
| 5 | **F-10**: bucket `dropped(V)` — в фазе 1 того же коммита; `free_head` — **в `RootEntry V`** | §4.5, §6.3 |
| 6 | **F-11**: `zone_guard` — RAII (`EpochGuard`); после `PIN_ATTEMPTS = 8` — `ZoneDegraded`, не спин | §5.3, §5.4 |
| 7 | **F-6**: явный file-fatal список; `strict_corruption = zone` к нему не применяется | §9.2 |
| 8 | **page 3**: `LayoutHead` B и writer registry — разные страницы; пролог и golden пересчитаны | §10.1 |
| 9 | **C-1…C-11** — нормативные условия приёмки M1 | §15 |

**Обязательно фиксируется:** ограничения `PW-L1…PW-L12` — §11; отсутствие скрытых глобальных блокировок на чтении — §12.

**Не-цели v2.0:** выборный лидер (`term = 1`), `LOCK_SH` (M1 — `LOCK_EX`), запись из нескольких процессов.

---

## 1. Журнал: что закрыто и чем

| Дефект / требование | Решение в раскладке | Где |
|---|---|---|
| F-1: пин после загрузки головы | `e0` до головы; `pin`; `fence(SeqCst)`; `guard` c1==c2; `e2==e0` | §5.3 |
| F-2: копии в одном секторе | A/B — **разные 4 KiB страницы** (`RootEntry`, `ALLOC_RECORD`, `LayoutHead`) | §4.1, §3.4, §10.1 |
| F-3: барьер аллокаций | `page_limit_at_commit` в записи + `ALLOC_RECORD` | §3.4, §4.5 |
| F-4: три fsync | ровно **два** `fdatasync` на группу | §4.5, §7.1 |
| F-8: ring исчерпан | chain-вытеснение; запись не блокируется | §4.3–4.4 |
| F-9: `snapshot_seq` как ceiling | `ceiling = ∞`; `freeze()` — отдельный retention | §5.1, §5.7 |
| F-10: пул без связи с головой | bucket — фаза 1, `free_head` — в `RootEntry V` | §6.3 |
| F-11: нечётный guard | `EpochGuard` (RAII) + `ZoneDegraded` после 8 попыток | §5.4 |
| F-6: file-fatal | список §9.2 | §9.2 |
| page 3 (LayoutHead B / writer registry) | пролог: стр. 2/3 — LayoutHead A/B, стр. 4 — registry | §10.1 |
| D-A: 64 Б | запись корня 64 Б; `ZoneRootBlock` отсутствует | §4.1 |
| D-C: курсор в памяти | `ALLOC_CTRL` отсутствует; `ALLOC_RECORD` — 2 страницы | §3.1, §3.4 |
| D-D: 6 пинов × u64 (16 Б) | слот 128 Б, `pins[6]`; версия — полный `u64` | §5.2 |

Типы страниц: `ROOT_DIR = 10`, `ROOT_CHAIN = 11`, `ALLOC_RECORD = 12`, `WRITER_REG = 13` (ранее 13 резервировался под `ZONE_ROOT` — не используется), `14` — резерв (ранее `ALLOC_CTRL`, не используется), `LAYOUT_HEAD = 16`. `PAGE_TYPE_META = 1` не переиспользуется.

---

## 2. Величины

| Величина | Тип | Где | Смысл |
|---|---|---|---|
| `txn` | u64, глобально монотонный | CAS-блок **в памяти** (`TXN_BATCH = 64`) | номер коммита; порядок для `fsck`/`freeze`/аудита, не для атомарности |
| `version(Z)` | u64 | `RootEntry` | `txn` коммита зоны; монотонен внутри зоны |
| `DP`/`DT` | u64 | `ALLOC_RECORD` + память | durable `page_limit`/`txn_limit` |
| `D_z` | u64 | память | max версия, чей корень fsync'нут |
| `MP(z)` | u64 | память (GC) | минимум пинов зоны; `∞` = нет пинов |
| `RV_z` | u64 | память (GC) | `min(D_z − 1, MP(z), freeze_epoch)`; гейт выдачи |
| `published_txn` | u64 | память | max опубликованный `txn` |
| `snapshot_seq` | u64 | `Snapshot` | `published_txn` на момент `snapshot()`; **аудит/`X-Commit-Txn`, не ceiling** |
| `freeze_epoch` | u64 | память | `0` = нет freeze; иначе EPOCH-барьер удержания |
| `chain_depth` | u32 | память (зона) | число chain-страниц; восстанавливается обходом |
| `zone_guard[z]` | u32 | память | seqlock зоны (чётный = стабильно) |
| `leader_term` | u64 | `ALLOC_RECORD` | fencing; M1 = 1 |

> Синонимы: `deleted_epoch` ≡ `deleted_txn`; `epoch` в ADR ≡ `txn`; `zone_write_epoch` ≡ `zone_guard`.

Инварианты `PW-I1…PW-I10` (ADR-0006 §5) действуют; уточнения — §12.

---

## 3. Аллокатор

### 3.1. Курсор в памяти (D-C)

```
struct AllocState {                 // в памяти процесса, не в файле
    reserve_cursor: AtomicU64,      // первая невыданная страница
    reserve_txn:    AtomicU64,      // блок из TXN_BATCH=64 значений
}
```

- Инициализация при open: `reserve_cursor = DP` (§3.5), `reserve_txn = max(DT, max ring/chain(version)) + 1`.
- `pwrite` по ним не выполняется; второго writable-региона нет — **SEC-ZF-014 сохраняется дословно** (writable только reader table).
- Курсор не персистится: после краха он откатывается к `DP`. Это безопасно — страницы, аллоцированные после durable `DP`, не достижимы ни из одной durable-головы (корень пишется только после фазы 1, §4.5), значит их можно выдать повторно.
- Для M3 (N процессов) общий durable-курсор вынесен в sidecar ADR 0007; раскладка v2.0 при этом не меняется.

### 3.2. Резервирование

```
alloc(n):
  if local_cache.free >= n: return local_cache.take(n)                 # 0 атомиков
  loop:
    c = reserve_cursor.load(Acquire)
    if c + ALLOC_THREAD_CACHE_PAGES > hard_limit:
        return NoSpace{zone} | MapFull{high_water, page_count_max}
    if cas(reserve_cursor, c, c + ALLOC_THREAD_CACHE_PAGES, AcqRel, Acquire).is_ok():
        local_cache.refill(c, ALLOC_THREAD_CACHE_PAGES); continue
```

| Параметр | Значение | Смысл |
|---|---|---|
| `ALLOC_EXTENT_PAGES` | 16 | гранулярность диапазона (64 КиБ @4096) |
| `ALLOC_THREAD_CACHE_PAGES` | 64 | 1 CAS / 64 страницы ⇒ ~0.02 CAS/коммит |
| `GC_RESERVE_PAGES` | 1024 | резерв GC, не выдаётся обычным коммитам |
| `ROOT_RESERVE_PAGES` | 64 | резерв под корень/chain при полном файле |

- `n` — оценка `depth + splits + overflow + chain(0–1) + 1` (6–13); хвост батча остаётся у потока.
- Публикация ограничена durable-границей (§4.5), а не `alloc`.
- `NoSpace{zone}` — упёрлись в `hard_limit`, в пуле зоны нет eligible; `MapFull` — `hard_limit == page_count_max`.

### 3.3. Кэш, аборт, «выделено, но не опубликовано»

| Ситуация | Действие |
|---|---|
| успешный коммит | остаток кэша остаётся у потока |
| `Abort`/Drop до `pwrite` | страницы «never published» → в кэш/пул немедленно (A-10) |
| `Abort` после `pwrite` | не достижимы → в пул с `drop_txn`, флаг `NEVER_PUBLISHED` |
| крах | курсор откатывается к `DP`; страницы сверх `DP` выдаются повторно; страницы `< DP` без ссылки — утечка, `fsck` возвращает |

Тождество (`fsck`): `DP = reachable ∪ pools ∪ leaked`, попарно дизъюнктны. `MAX_LEAK_RATIO = 0.01` → алерт.

### 3.4. `ALLOC_RECORD` (256 Б × 2 копии, разные страницы)

| Смещение | Размер | Поле |
|---|---|---|
| +0 | 4 | `page_type` = 12 |
| +4 | 2 | `version` = 1 |
| +6 | 2 | `flags` |
| +8 | 4 | `page_no` |
| +12 | 4 | `crc32c` (вся страница, поле = 0) |
| +16 | 8 | `seq` |
| +24 | 8 | `page_limit` (`DP`) |
| +32 | 8 | `txn_limit` (`DT`) |
| +40 | 8 | `write_unix_ns` |
| +48 | 8 | `leader_term` |
| +56 | 8 | `epoch_hint` |
| +64 | 8 | `writer_pid` |
| +72 | … | `reserved` |

Копии — **разные страницы**; `seq` монотонен; `page_limit`/`txn_limit` монотонны (понижение → file-fatal); выбор — max-valid по `seq`; обе невалидны → `CorruptNoValidMeta`.

### 3.5. Восстановление

```
dp = max(ALLOC_RECORD.page_limit,
         max over ring/chain(page_limit_at_commit),
         max over pools(page_id) + 1,
         page_data_first)
dt = ALLOC_RECORD.txn_limit
if dp < ALLOC_RECORD.page_limit || dp < max ring/chain(page_limit_at_commit):
    AllocWatermarkRegression -> file-fatal (§9.2): write_locked + read-only
reserve_cursor := dp                       # курсор только в памяти (D-C)
reserve_txn    := max(dt, max ring/chain(version)) + 1
```

- Понижение `dp`/`dt` невозможно (`PW-I4`).
- `max page.txn` на открытии не считается; `fsck --verify` проверяет `page.txn ≤ version` и при `page.txn ≥ reserve_txn` поднимает `reserve_txn` + `NEEDS_FSCK`.
- Курсор не читается из файла (D-C): `reserve_cursor := dp` до первого `alloc`.

### 3.6. Почему нет ABA и двойной выдачи

`reserve_cursor` монотонен в пределах жизни процесса и инициализируется из `DP`; `PageId` глобален; `owner_zone` проверяется при выдаче; пул выдаёт только `is_reclaimable`; «never published» не может быть живой; `txn` не переиспользуется; double allocation возможен только при нарушении F-10-порядка и детектится (`drop_txn ≥ D_z`).

---

## 4. Публикация корня

### 4.1. `RootEntry` (64 Б, D-A)

| Смещение | Размер | Поле | Примечание |
|---|---|---|---|
| +0 | 4 | `crc32c` | CRC `[4,64)`, поле = 0 |
| +4 | 4 | `owner_zone` | `zone_seq`; 0 = каталог |
| +8 | 8 | `version` | `txn` коммита |
| +16 | 4 | `root_page` | корень B+tree; 0 = пусто |
| +20 | 4 | `page_limit_at_commit` | ≤ `DP` |
| +24 | 8 | `prev_record` | chain-страница; 0 = нет |
| +32 | 4 | `meta_root` | блок §12.2 v1 |
| +36 | 4 | `ixfr_root` | 0 в v2 |
| +40 | 8 | `deleted_txn` | 0 ⟺ не tombstone (8-выровнено) |
| +48 | 4 | `rrset_count` | без `T_NODE` |
| +52 | 4 | `soa_serial` | RFC 1982 |
| +56 | 4 | `free_head` | первый per-zone bucket; 0 = нет |
| +60 | 2 | `tree_level` | 0 = пусто/лист |
| +62 | 1 | `state` | 0 Init, 1 Serving, 2 Tombstone |
| +63 | 1 | `flags` | CATALOG, COMPACTION, NEEDS_FSCK; reserved = 0 |

`rr_count`/`free_pages` в записи не хранятся (статистика в памяти); `max_page_id` заменён более сильным `page_limit_at_commit` (PW-I4).

**Валидность:** CRC; `owner_zone` = каталога; `version ≥ 2`; `root_page`/`meta_root`/`free_head`/`prev_record` = 0 или `< page_limit_at_commit`; `page_limit_at_commit ≤ DP`; `tree_level ≤ MAX_TREE_DEPTH`; `state ≤ 2`; `deleted_txn = 0 ⟺ state ≠ 2`; `soa_serial ≤ 0x7FFF_FFFF`; `flags` reserved = 0.

**Выбор:** `select(z, ceiling) = argmax { version : owner=z ∧ crc_ok ∧ version ≤ ceiling }`, tie-break — копия 0; при `ceiling = ∞` — max-valid (= ring-голова). `zones()`/`find_zone`/`serial` читают одну запись — второй страницы на зону нет.

### 4.2. Ring (4 версии × 2 копии, 16 зон/страница-копия)

- Копия A — в A-регионе, копия B — в B-регионе; **разные 4 KiB страницы** (F-2).
- Ячейка версии — 64 Б; блок зоны в странице-копии — `4 × 64 = 256 Б`; **16 зон × 256 Б = 4096 Б** ⇒ страница-копия без заголовка (номер/роль — из `LayoutHead`; валидность — CRC записи + `owner_zone`).
- `head_slot → A_page = A_first + s/16, B_page = B_first + s/16, idx = s%16`; группа версии `g = version mod 4`.
- Запись версии `V` — два элемента одного `pwritev` (A и B). Стоимость — 512 Б/зона; `root_dir_pages = 2 × ceil(max_zones / 16)`.

### 4.3. Вытеснение в chain (F-8)

```
g = V mod 4;  old = ring[z][g]
if old valid:
    if old.version >= MP(z):                    # версия нужна читателю
        chain_evict(z, old)                     # §4.4: запись в chain ДО перезаписи
    elif old.version >= D_z:                     # мешает только durability
        promote_to_sync(z)                      # auto-promotion (sticky) — затем перезапись
write 2 копии record(V), record(V).prev_record = current_chain_head(z)
```

- `promote_to_sync` — глобальный липкий `Sync` (как `sync()`): двигает `D_z` по всем зонам; применяется, только если блокирует `D_z`, а **не** пин. Если после promotion версия всё ещё `≥ MP` — chain.
- Writer **не блокируется** на пинах: chain — safety valve. `ZoneWriterStalled{zone}` — только патология: chain-лимит/невозможность выделить страницу/I/O (§4.4).
- Chain пишется **в фазе 1**; `record(V).prev_record` указывает на новейшую chain-страницу, поэтому chain достижим из durable-головы.

### 4.4. Chain (`PAGE_TYPE_ROOT_CHAIN = 11`)

**Формат страницы** (immutable, append-only):

| Смещение | Размер | Поле |
|---|---|---|
| +0 | 4 | `page_type` = 11 |
| +4 | 2 | `version` = 1 |
| +6 | 2 | `flags` |
| +8 | 4 | `page_no` |
| +12 | 4 | `crc32c` MUST 0 (страница неизменяема, но CRC записи достаточен) |
| +16 | 4 | `owner_zone` |
| +20 | 4 | `reserved0` |
| +24 | 8 | `evicted_txn` (диагностика) |
| +32 | 64 | `RootEntry` вытесненной версии (её `prev_record` → предыдущая chain-страница) |
| +96 | … | `reserved` |

- Одна запись на страницу (4 КиБ/версия) — цена только при застрявшем читателе.
- `current_chain_head(z)` = `prev_record` последней опубликованной записи (или 0); в памяти — `chain_depth{zone}` (восстанавливается обходом при open/первом коммите).

**Чтение.** `select(z, ceiling)`:
1. ring: max-valid `version ≤ ceiling`; при `ceiling = ∞` — ring-голова, chain не читается;
2. иначе обход от `record.prev_record`: каждая страница валидируется (`page_type=11`, `owner_zone`, CRC записи, `version` строго убывает); до первой `version ≤ ceiling`, ≤ `MAX_ROOT_CHAIN_HOPS = 4096`;
3. первая невалидная/чужая страница = конец chain (хвост освобождён) → если подходящая версия не найдена: `StaleRoot{zone, requested, oldest_retained}`; зона отсутствует/tombstone → `NoZoneVersion`;
4. цикл/превышение hops → `Corrupt{zone}`.

**Освобождение.** GC считает `floor = min(MP(z), freeze_epoch)` (∞ → нет пола). Chain-страницы с `version < floor` **и** `< D_z` недостижимы для чтения и переносятся в bucket (`drop_txn = V`); `prev_record` сохраняемой страницы остаётся «висячим», но читатель останавливается на первой невалидной странице (§4.4 п. 3), а `fsck` считает освобождённый хвост ожидаемым (не ошибкой). Стоимость — O(depth) при GC-проходе, не на hot-path.

**Лимит/порог.** `MAX_ROOT_CHAIN_PAGES = 4096` (16 МиБ/зона @4096). При превышении: `ZoneWriterStalled{zone}` (retryable, только эта зона), алерт `pw_root_chain_depth`, `pw_zone_writer_stalled_total`; другие зоны пишутся. Это патология (живой «застрявший» читатель дольше ~4096 коммитов или утечка пина), а не штатный AXFR-сценарий.

**Crash.** Chain-страница durable до записи корня (фаза 1). Крах между фазами: корень не опубликован → зона на `V−1`, chain-копия недостижима → утечка (`fsck`). Потеря chain-страницы при целой записи (bit rot) → откат этого диапазона версий, `StaleRoot`, не порча. Torn chain-запись (CRC) → пропуск, обход по `prev_record`.

**Метрики:** `pw_root_chain_depth{zone}`, `pw_root_chain_evictions_total{zone}`, `pw_root_chain_hops{zone}`, `pw_root_chain_free_total{zone}`, `pw_zone_writer_stalled_total{zone}`.

### 4.5. Порядок публикации, `page_limit_at_commit`, два fsync

```
writer(z):  lease → plan → alloc (данные + bucket(V) + chain-страницы, если есть)
            → encode (owner_zone!, CRC, free_head=bucket, prev_record=chain_head)
            → pwritev(phase1) → CommitRequest{ z, V, record, max_allocated_id }
            → wait ack

coordinator(group):
  page_limit = max(max_allocated_id + 1, cursor);  txn_limit = max(V)
  # ФАЗА 1: данные + bucket(dropped(V)) + chain-страницы + ALLOC_RECORD
  write ALLOC_RECORD { seq+1, page_limit, txn_limit, term }        # 2 страницы
  fdatasync(fd)
  publish DP/DT (Release)
  # ФАЗА 2: записи корня (2 копии), только при DP > max_allocated_id ∧ DT ≥ V
  for m in members:
      g = EpochGuard::enter(z)                    # RAII (F-11), guard odd
      select group (MP, D_z); pwritev(2 копии RootEntry)
      drop(g)                                     # guard even
  fdatasync(fd)
  for m: D_z = V (Release); published_txn = max; heads[z].store(Arc<RootEntry>, Release)
  ack(CommitOutcome{ zone_version, txn })
```

**Ring+chain не ломают лимиты и два fsync:**
1. Chain-страницы и bucket аллоцируются **до** вычисления `max_allocated_id` ⇒ `page_limit_at_commit ≥ chain_page+1`, `≥ bucket_page+1`.
2. Chain/bucket — в фазе 1; запись — в фазе 2 ⇒ по-прежнему **ровно два** `fdatasync`.
3. `prev_record` и `free_head` валидируются как `< page_limit_at_commit` (в т.ч. `fsck`).
4. Крах после фазы 1 до корня: chain/bucket durable, но недостижимы из durable-головы → утечка, не double-free.

### 4.6. Что видит читатель

| Состояние | Результат |
|---|---|
| обычное чтение (`ceiling = ∞`) | ring-голова (max-valid) |
| одна копия версии torn | вторая копия (потерь нет) |
| обе копии новейшей torn | предыдущая группа/chain, `torn_root` |
| `ceiling` (freeze) ниже ring-версий | chain до первой `≤ ceiling` |
| chain исчерпан/хвост освобождён | `StaleRoot` |
| зона отсутствует/tombstone | `NoZoneVersion` |
| чужая `owner_zone`/`version` при валидном CRC | **file-fatal** (§9.2) |
| ring+chain все биты | `Corrupt{zone}`; `fsck --repair --zone` |

### 4.7. Платформа

64-байтовая запись не атомарна; валидность — CRC + `version`. x86_64: 8-байтовые атомики управляющих слов. ARM64: `fence(SeqCst)` между публикацией пина и валидацией; `Acquire` на загрузке указателей. Порядок «данные → запись → видимость» — `pwrite`/`fence(Release)`/`ArcSwap(Release)`; `msync` не используется. `PageHeader.reserved1` (+12) = `owner_zone` под `F_PARALLEL_WRITES`; несовпадение при валидном CRC — **file-fatal**.

---

## 5. Пины, видимость, MVCC

### 5.1. Семантика снапшота (F-9)

- `SnapshotHandle { snapshot_seq, catalog_version }` — **не** ceiling: `snapshot_seq` — аудит/`X-Commit-Txn`/запрос `freeze()`; отказа по нему **нет**.
- `zone_snapshot(z)` всегда разрешает **последнюю** опубликованную версию (`select(z, ∞)`); зона, изменённая после `snapshot()`, **читается** (новее).
- `ZoneSnapshot { Arc<RootEntry>, pin }` стабилен на всё время жизни; повторный `zone_snapshot(z)` может вернуть новую версию (для повторяемости держать `ZoneSnapshot`).
- `NoZoneVersion` — только «зоны нет/tombstone»; `StaleRoot` — только при `freeze()`-запросе версии ниже доступной истории chain.
- Чтение согласованного среза на `T` — только `freeze()` + `ZoneSnapshot`/EPOCH-пин или `fsck --at-epoch T` (§5.7).

### 5.2. Слот читателя (128 Б)

| Смещение | Размер | Поле |
|---|---|---|
| +0 | 8 | `owner_token` (`pid<<32 | incarnation`) |
| +8 | 8 | `epoch` (для `kind = EPOCH` = `freeze_epoch`/`snapshot_seq`) |
| +16 | 2 | `n_pins` (0..6) |
| +18 | 1 | `kind` (0 = EPOCH, 1 = ZONE) |
| +19 | 1 | `flags` (LONG_HOLD, IN_PROCESS, PIN_OVERFLOW) |
| +20 | 4 | `pad` = 0 |
| +24 | 8 | `heartbeat_ns` |
| +32 | 96 | `pins[6]`: `{ zone_seq u32, pad u32, version u64 }` (16 Б; `version` 8-выровнена) |

`active_txn` выводится из `pins[]`. Версия пина — полный `u64` `txn` (D-D: 32-битная версия исчерпалась бы за ~5 суток при 10⁴ коммитов/с). `> MAX_PINNED_ZONES_PER_SNAPSHOT = 64` зон → EPOCH-пин (`PIN_OVERFLOW`, защита усиливается).

### 5.3. Протокол пина (F-1, F-9, F-11)

```
zone_snapshot(z):
  e0 = published_txn.load(Acquire)                 # до головы; НЕ ceiling
  for attempt in 0..PIN_ATTEMPTS (=8):
      root = heads[z].load(Acquire)
      if root is None or state == Tombstone: return NoZoneVersion
      pin(z, root.version)                         # Release; overflow → EPOCH
      fence(SeqCst)
      c1 = zone_guard[z].load(Acquire)
      e2 = published_txn.load(Acquire)
      root2 = heads[z].load(Acquire)
      c2 = zone_guard[z].load(Acquire)
      if c1 == c2 && even(c1) && e2 == e0 && root2.version == root.version:
          return ZoneSnapshot{ root, pin }         # ceiling = ∞, зафиксирована последняя версия
      unpin(z); backoff(10 µs)
  if все 8 отказов — из-за guard (нечётный/меняющийся):
      return ZoneDegraded { zone, epoch }          # зона read-only/NEEDS_FSCK, не спин
  return ReaderContended                           # churn публикаций, retryable
```

`ZoneDegraded` — только если причина — **guard**; рост `published_txn`/смена версии → `ReaderContended`. `ZoneDegraded` выставляет `NEEDS_FSCK` зоны, `pw_zone_degraded_total`, алерт.

Корректность: Dekker. Актор, меняющий голову/`MP`/`RV`, делает `guard += 1` (нечёт), `fence(SeqCst)`, затем читает пины; читатель — `pin` (Release), `fence(SeqCst)`, затем `guard`. Хотя бы одна сторона видит другую. `e0/e2` закрывают окно «голова загружена, пин не опубликован».

### 5.4. `EpochGuard` (F-11) и `MP(z)`/`RV_z`

**F-11.** `zone_guard[z]` меняется только через RAII:

```
EpochGuard::enter(z):  guard[z].fetch_add(1, AcqRel)   # odd
EpochGuard::drop:      guard[z].fetch_add(1, Release)  # even (успех, Abort, Io, panic=unwind)
```

`panic = abort` kill-процесса чётность не восстанавливает — не требуется (guard in-memory, переинициализируется при open). Writer и GC используют guard обязательно; «ручной» инкремент без Drop запрещён.

**MP/RV.** Скан 1024×6 на коммите запрещён:

```
pin(z, v):   slot.pin = v (Release); MP[z].fetch_min(v, AcqRel)
unpin(z):    slot.pin = 0 (Release); mark_dirty(z)      # MP не поднимается

GC pass (10 мс; по требованию при NoSpace):
  for z in dirty:
      g = EpochGuard::enter(z)                          # odd + fence(SeqCst)
      m = min(version по всем пинам z, epoch_min)       # Acquire-скан
      MP[z].store(m, Release)                           # подъём только здесь
      drop(g)                                           # even
  RV_z = min(D_z − 1, MP[z], freeze_epoch); publish (Release)
```

`MP[z].fetch_min` — кэш скана, не источник истины; подъём — только GC под guard. «Устаревшее низкое» лишь задерживает реюз. Стоимость — 2–5 мкс на проход, не зависит от коммитов.

### 5.5. Стоимость

| Операция | Оценка |
|---|---|
| `ZoneSnapshot` (pin+drop) | 25–45 нс |
| `SnapshotHandle` | 1 load ≈ 5 нс |
| `ZoneSnapshot` из hot-path | 10–20 нс (пин на батч/AXFR) |
| `select(z, ∞)` | ring-голова, ≤ 2 записей по 64 Б |
| `lookup` | без атомиков (v1) |
| GC-скан | 2–5 мкс / 10 мс |

### 5.6. AXFR / перечисление

- AXFR/`enumerate`: `ZoneSnapshot` держит пин; дерево immutable; ≤ 1 копия RR (v1 G-8). Ring заполняется → chain; запись не блокируется (T-1).
- `zones()`: каталог + `ArcSwap`-головы, без пинов; состав/содержимое могут быть из разных моментов (PW-L1). Согласованный срез — `freeze()`.
- `delete_zone`: только запись (`state = Tombstone`, `deleted_txn`); каталог не пишется; GC удалит каталог-запись и вернёт `head_slot` при `deleted_txn ≤ RV_z`.

### 5.7. `freeze()` — глобальный retention

| Свойство | Нормативно |
|---|---|
| Захват | `FreezeGuard::new()`: EPOCH-пин на `E = published_txn` (`kind = EPOCH`), публикация `freeze_epoch = E` (Release) |
| Кто освобождает | владелец `FreezeGuard` (maintenance/CLI) в `Drop`; очищает `freeze_epoch` и пин |
| Влияние на запись | **нет**: коммиты продолжаются, версии > E публикуются нормально |
| Влияние на GC | `RV_z = min(D_z−1, MP(z), freeze_epoch)`; ring/chain сохраняют нужные версии; файл растёт |
| Таймаут | `FREEZE_TIMEOUT_MS = 300 000` — **алерт** `pw_freeze_timeout_total`, не принудительное снятие (живой держатель не вытесняется) |
| Смерть держателя | слот санитизируется по мёртвому PID/incarnation (v1 §13.7 шаг 9) → freeze снят, `NEEDS_FSCK` |
| Граница | версия ≤ E доступна, пока freeze жив; ниже доступной истории chain — `StaleRoot`; зоны нет → `NoZoneVersion` |
| `fsck --at-epoch T` | только при активном freeze с `E ≥ T` (или offline-копии) |

**T-2:** `Reader::snapshot()` → 100 коммитов в другие зоны (и ≥ 10 в ту же) → `zone_snapshot(z)` успешен, версия ≥ исходной, без `NoZoneVersion`.

---

## 6. GC и рекламация

### 6.1. Bucket (per-zone)

`PAGE_TYPE_FREELIST = 5`, COW:

| Смещение | Размер | Поле |
|---|---|---|
| +0 | 40 | `PageHeader` (type 5) |
| +40 | 4 | `next_bucket` |
| +44 | 4 | `owner_zone` (0 = donation) |
| +48 | 8 | `drop_txn` |
| +56 | 4 | `count` |
| +60 | 4 | `flags` (DONATED, NEVER_PUBLISHED) |
| +64 | 4·count | `page_ids[]` (1008 @4096) |

Порядок по `drop_txn` возрастает; `owner_zone` совпадает с владельцем страниц; пустых bucket'ов нет; выдача/добавление — COW-образ.

### 6.2. Условие

```
is_reclaimable(drop_txn, z, D_z, RV_z, current_version_z) =
      drop_txn >= 2
   && drop_txn <  D_z                 # строго: худшая восстановимая = D_z−1
   && drop_txn <= RV_z
   && drop_txn <  current_version_z
```

`RV_z` включает `freeze_epoch`. `NEVER_PUBLISHED` — без гейта (A-10).

### 6.3. Bucket — фаза 1 того же коммита, `free_head` в `RootEntry V` (F-10)

```
коммит V зоны z:
  1. построить корень V; dropped(V) = страницы, выброшенные в V
  2. bucket(V) := COW-образ с dropped(V), drop_txn = V
  3. record(V).free_head := bucket_page
  4. ФАЗА 1: pwritev(данные + bucket V + chain + ALLOC_RECORD) → fdatasync
  5. ФАЗА 2: pwritev(2 копии record V, page_limit_at_commit ≥ bucket_page+1) → fdatasync
  6. D_z := V
```

- **Достижимость:** `RootEntry V → free_head → bucket`. После краха bucket достижим **только** из durable-головы `V`; если `V` не опубликована, bucket недостижим.
- **Порядок «durable drop → free publish»:** drop становится durable в фазе 2 (запись `V`); bucket durable раньше (фаза 1), но логически опубликован только через `free_head` в `V`. Reuse гейтится `drop_txn < D_z` — не раньше `V+1`. Двухгрупповой задержки нет.
- **Крах между фазой 1 и корнем:** bucket durable, но не связан → **утечка**, не double-free; `fsck` возвращает (PW-C26 / S-21).
- **Donation** — двумя фазами (durable drop → donate-record → выдача при `donated_at_txn < DP`), в следующей группе после drop.

### 6.4. Donation

Только при удалении/offline compact: (1) durable — корень больше не ссылается; (2) durable — `donate`-запись (следующая группа); (3) выдача при `donated_at_txn < DP`; (4) при выдаче переписать `owner_zone`/`txn`. Объединение фаз возвращает double-free. Единственный способ перераспределить место (PW-L3).

### 6.5. Политика, паузы, застрявший читатель

| Сценарий | Поведение |
|---|---|
| Bump-first | `DP / page_count_max < 0.85` — из `reserve_cursor`; далее пул зоны, затем donation |
| `NoSpace{zone}` | пул пуст, `hard_limit` достигнут; ждать GC/`sync()`/donation; другие зоны пишутся |
| `MapFull` | `hard_limit == page_count_max`; чтение работает |
| Ring исчерпан | вытеснение в chain; **запись не блокируется**; `pw_root_chain_depth` растёт |
| `D_z` блокирует, пинов нет | auto-promotion в `Sync` (sticky), затем перезапись без chain |
| Chain > 4096 страниц | `ZoneWriterStalled{zone}` (патология), алерт; другие зоны пишутся |
| Застрявший живой читатель | не вытесняется (SEC-ZF-007); GC стоит; файл растёт |
| Мёртвый PID / incarnation mismatch | слот очищается CAS, `NEEDS_FSCK`; `MP` пересчитывается |
| Мёртвый поток живого процесса | не вытесняется; `pw_stuck_reader_seconds`, алерт |
| GC-бюджет | ≤ 16 зон / 8192 страницы за группу; вне критической секции |
| `Flush`/`Memory` | `D_z` не двигается → пул голодает; `sync()`; chain работает (запись не встаёт) |

Worst-case пауза: `fdatasync` группы + `pwritev` корней + GC-бюджет (0.3–1 мс); читателей не блокирует.

---

## 7. Group commit

### 7.1. Фазы и правила

Последовательность — §4.5. Обязательные свойства:

| # | Свойство |
|---|---|
| 1 | `ALLOC_RECORD` durable **до** любого корня группы |
| 2 | корень только при `DP > max_allocated_id ∧ DT ≥ V`; опоздавший — следующая группа |
| 3 | `page_limit`/`txn_limit` — максимум по участникам |
| 4 | лимиты монотонны; понижение → file-fatal |
| 5 | `txn` — глобальный CAS-блок (`TXN_BATCH = 64`) в памяти, не per-zone |
| 6 | M1: один процесс, `LOCK_EX`, фиксированный координатор, `term = 1`; M3: `LOCK_SH` + registry + выборный лидер |
| 7 | лидер перечитывает `term` перед записью `ALLOC_RECORD`; расхождение → отказ (M3) |
| 8 | `MAX_BATCH_ZONES = 256`, `MAX_BATCH_BYTES = 1 MiB`, `MAX_BATCH_DELAY = 1 мс` |
| 9 | bulk-коммит > 256 КиБ — отдельная группа (`batch = 1`) |
| 10 | **ровно два `fdatasync`**; chain/bucket — фаза 1, записи — фаза 2 |

### 7.2. Режимы

| Режим | Фаза 1 | Фаза 2 | `D_z` | Гарантия |
|---|---|---|---|---|
| `Sync` | да | да | двигается | подтверждённый коммит переживает power loss |
| `Flush` | да | корни без fsync | не двигается | переживает рестарт процесса; power loss → откат зоны на `V−1` |
| `Memory` | нет | нет | не двигается | гарантий нет (v1 §13.7) |

Липкий `Sync`: после первой durable-группы (`DT > 1`) только `Sync`. `sync()` — глобальный барьер (PW-L9). `Flush`/`Memory` деградируют неравномерно; auto-promotion в `Sync` срабатывает только по правилу §4.3 (`D_z` блокирует ring, пинов нет). `freeze()` не блокирует запись, только задерживает рекламацию.

### 7.3. Ошибки

| Точка | Действие | Последствие |
|---|---|---|
| `pwrite` данных | Abort, страницы «never published»/в пул | `Io`; корень не менялся |
| фаза 1 fsync | группа не публикуется | все `Io`; `ALLOC_RECORD` мог не долететь — безопасно |
| фаза 2 fsync | `D_z` не двигается; при повторной ошибке — `write_locked` | `Io`; исход неопределён (fsync-семантика) |
| `panic` в writer/GC | `EpochGuard::drop` возвращает чётность | коммит не опубликован, зона не деградирует |
| `ZoneDegraded` | зона read-only/`NEEDS_FSCK`, метрика+алерт | другие зоны работают |
| `ZoneWriterStalled` | только патология chain (лимит/I/O) | retryable; другие зоны работают |
| file-fatal (§9.2) | `write_locked` + read-only | файл не пишется до `fsck` |
| `Corrupt{zone}` | зона read-only | остальные работают |

Backpressure: очередь `QUEUE_ZONES = 1024`, `QUEUE_BYTES = 64 МиБ`; переполнение → писатель ждёт ack (condvar), вне read-path.

### 7.4. Латентность

```
T_commit = T_build + T_wait_batch + T_fsync1 + T_fsync2;  T_wait_batch ≤ MAX_BATCH_DELAY + ε
throughput = MAX_BATCH_ZONES / (T_fsync1 + T_fsync2)
```

| Режим | p50 | p99 |
|---|---|---|
| `Memory` | 40–120 µs | ≤ 600 µs |
| `Flush` | 250–600 µs | ≤ 2 мс |
| `Sync` | 0.8–1.6 мс | ≤ 4 мс |

Потолок — `fdatasync` одного inode (2 на группу): 20–80k зона-коммитов/с на NVMe при пачке 8–256.

---

## 8. Производительность

### 8.1. Цели

| Метрика | p50 | p99 |
|---|---|---|
| `lookup` 1M, тёплый кеш | ≤ 500 нс | ≤ 2 µs |
| `ZoneSnapshot` (pin+drop) | ≤ 100 нс | ≤ 300 нс |
| `commit` 1 RR `Sync`, 1 зона | ≤ 1.5 мс | ≤ 4 мс |
| `commit` 1 RR `Sync`, 32 зоны | ≤ 2 мс | ≤ 5 мс |
| `commit` `Memory` | ≤ 120 µs | ≤ 600 µs |
| throughput | ≥ 20k зона-коммитов/с | — |
| масштабирование чтения 1→32 ядра | ≥ 24× | — |

Накладные расходы v2: +0 страниц на коммит (64-Б запись вместо блока), +1 чтение при разрешении `ZoneSnapshot` (ring-голова), chain-страница только при застрявшем читателе.

### 8.2. Contended cache lines

| Линия | Кто | Частота | Смягчение |
|---|---|---|---|
| `reserve_cursor` | все писатели | 1 CAS / 64 страницы | кэш 64 |
| `reserve_txn` | все писатели | 1 CAS / 64 коммита | `TXN_BATCH` |
| `published_txn` | координатор | 1/группу | read-mostly |
| `zone_guard[z]` | координатор, GC | 2 RMW/коммит | 64 Б на зону при > 4096 |
| `ArcSwap[]` | координатор | 1/коммит | 8 Б/слот; 64 Б при > 4096 |
| `MP[z]` | читатели (CAS-min), GC | пин/GC | 64 Б при > 4096 |
| reader slot (128 Б) | свой поток | pin/unpin | 2 линии на слот |
| ring/chain-страницы | координатор | 1 pwritev/группу | 16 зон/страница-копия |

### 8.3. Метрики (обязательные)

`pw_alloc_cas_retries_total`, `pw_alloc_leaked_pages_estimate`, `pw_page_limit`, `pw_txn_seq`, `pw_zone_durable_version{zone}`, `pw_zone_min_pinned{zone}`, `pw_root_chain_depth{zone}`, `pw_root_chain_evictions_total{zone}`, `pw_root_chain_hops{zone}`, `pw_root_chain_free_total{zone}`, `pw_zone_writer_stalled_total{zone}`, `pw_freeze_epoch`, `pw_freeze_seconds`, `pw_freeze_timeout_total`, `pw_zone_degraded_total{zone}`, `pw_zone_epoch_stuck_total{zone}`, `pw_file_fatal_total{kind}`, `pw_gc_backlog_pages`, `pw_group_commit_size`, `pw_group_fsync_seconds`, `pw_torn_root_total`, `pw_reader_pin_overflow_total`, `pw_stuck_reader_seconds`, `pw_free_pool_starved_total{zone}`.

### 8.4. Как мерить

`criterion`: `pw_pin_zone`, `pw_pin_overflow`, `pw_zone_snapshot`, `pw_lookup_1m_pinned`, `pw_alloc_cas_{1,8,32}`, `pw_commit_{memory,flush,sync}_x{1,8,32}`, `pw_group_sweep{1..256}`, `pw_gc_scan`, `pw_free_pool_pop`, `pw_root_chain_walk_{0,1,16,4096}`. `perf c2c` — HITM только на `reserve_cursor`/`reserve_txn`/`published_txn`. `perf stat`, `iai-callgrind`. `strace -c`: 2 `fdatasync` на группу, 0 syscall на запрос. Crash: `V:crash` (failpoints всех F2-точек + `dm-log-writes`/`dm-flakey`), 10⁴ `kill -9`, `V:loom` (5 моделей), `Miri`, ARM64 CI. Нагрузочный: `pulseload` 95/5, 1/8/32 зоны, HDR. Интеграционные: T-1…T-5.

---

## 9. Crash-матрица и file-fatal

### 9.1. Матрица

`R(proc)` — падение процесса, `R(power)` — потеря питания. Полная — ADR-0006 §7 (`PW-C1…C28`); здесь — консолидированная.

| # | Точка | Диск/кэш | Читатели | Recovery | Потери | PW-C |
|---|---|---|---|---|---|---|
| S-1 | частичный `pwritev` данных | старый корень | старые | старый | leak | C1 |
| S-2 | данные до фазы 1 | подмножество | старые | старый | leak | C2 |
| S-3 | во время фазы 1 | data/alloc — подмножество | старые | `DP` max-valid/прежний | leak | C3 |
| S-4 | после фазы 1, до корней | data+bucket+chain+alloc durable | старые | старый, `DP` выше | leak | C4 |
| S-5 | torn одной копии записи | вторая копия — другая страница | новая | max-valid | нет | C5 |
| S-6 | torn обеих копий новейшей | предыдущая группа/chain цела | старая | откат ≤ 1 версии | 1 коммит зоны | C6 |
| S-7 | запись корня не долетела (`R(proc)`), `Flush` | page cache | новая | новая | нет | C7 |
| S-8 | запись корня не долетела (`R(power)`) | — | — | `V−1` | 1 коммит зоны | C8 |
| S-9 | во время фазы 2 | подмножество корней | часть зон новая | max-valid по зоне | межзонная атомарность не обещана | C9/10 |
| S-10 | во время CAS курсора | курсор в памяти; после краха = `DP` | старые | `dp = max(ALLOC_RECORD, roots, pools)` | страницы сверх `DP` переиспользуются | C11 |
| S-11 | во время `txn` | `txn_limit` мог откатиться | — | `next_txn = max(...) + 1` | диапазон сгорел; ABA исключён | C12 |
| S-12 | смерть координатора (M1 — перезапуск) | фаза 1 могла пройти | старые | `term+1` | `CommitAborted` | C13/14 |
| S-13 | free publish без durable drop | — | — | детект `drop_txn ≥ D_z` → `NEEDS_FSCK` | **порча**, детект | C15 |
| S-14 | durable drop, bucket потерян | корень `V`, bucket-страница не долетела | новая | `V`; bucket недостижим | leak | C17 |
| S-15 | donation раньше drop | страница жива | — | детект `donated_at_txn < DP` | **порча**, фазы предотвращают | C18 |
| S-16 | застрявший/битый пин | — | — | мёртвый PID probe+CAS; живой не вытесняется | chain/рост файла | C19/23 |
| S-17 | ring исчерпан (все 4 ≥ MP) | — | — | chain-вытеснение | нет | C25 |
| S-18 | chain-страница durable, корень нет | chain недостижим | старые | старый | leak | C26 |
| S-19 | chain > 4096 | — | — | `ZoneWriterStalled{zone}` (патология) | отказ записи в зону | C25 |
| S-20 | bucket durable, корень нет (F-10) | bucket не связан | старые | старый | leak, **не** double-free | C26 |
| S-21 | ложное «слот свободен» | — | retry/`ReaderContended`/`ZoneDegraded` | — | при §5.3 невозможно | C20 |
| S-22 | два recovery | — | — | `LOCK_EX` | порча при нарушении | C21 |
| S-23 | GC при полном файле | — | — | `GC_RESERVE_PAGES` | дедлок → `NeedsFsck` | C22 |
| S-24 | `owner_zone` mismatch при валидном CRC | — | **file-fatal** | read-only + `fsck` | файл | C24 |
| S-25 | обе копии `ALLOC_RECORD`/`LayoutHead` невалидны | — | — | `CorruptNoValidMeta` | файл | Q7 |
| S-26 | `freeze` держится, крах | — | после рестарта пинов нет | слот санитизирован | freeze снят | C23 |
| S-27 | `zone_guard` «застрял» (panic без Drop) | — | `ZoneDegraded` за ≤ 8 попыток | повторный open сбрасывает guard | зона read-only | C28 |
| S-28 | file-fatal признак (§9.2) | — | — | `write_locked` + read-only | файл до `fsck` | — |

**Инварианты восстановления:** (1) `dp = max(ALLOC_RECORD.page_limit, max ring/chain(page_limit_at_commit), max pool page+1, page_data_first)`; (2) `dp`/`dt` не понижаются; (3) `root_page`/`prev_record`/`free_head` = 0 или `< page_limit_at_commit ≤ dp`; (4) `next_txn = max(dt, max ring/chain(version)) + 1`; (5) `RV_z ≤ MP(z)`; (6) `select` — max-valid ≤ ceiling, tie-break копия 0.

### 9.2. File-fatal vs zone-fatal (F-6)

**File-fatal (всегда `write_locked` + read-only до `fsck`; `strict_corruption` не применяется):**

| Признак | Где обнаруживается |
|---|---|
| `head.page_limit_at_commit > DP` после `max`-коррекции | open, чтение записи |
| пересечение множеств страниц разных зон | `fsck`, scrub |
| `owner_zone` страницы ≠ владельцу при валидном CRC; `version`/`owner_zone` записи от чужой зоны | ленивое чтение |
| битый/несовместимый `LayoutHead`, `ALLOC_RECORD`, каталог | open |
| регрессия `DP`/`DT`/`txn` (`AllocWatermarkRegression`, `dt`/`txn` вниз) | open |
| `page.txn > version` у достижимой страницы при валидном CRC (cross-zone ABA) | ленивое чтение, `fsck` |

Ошибка: `Corrupt { scope: File, kind }`; `pw_file_fatal_total{kind}`; запись запрещена до offline `fsck --repair`.

**Zone-fatal (деградирует только зона):** обе копии записи torn; `page_limit_at_commit < root_page` у собственной записи; CRC/`page_no`/`payload_len` собственной страницы; `state`/`deleted_txn` несогласованы; `ZoneDegraded`. `strict_corruption = zone` (дефолт) применяется **только** к этому классу; `file` возвращает v1-поведение (любая зона → файл read-only).

---

## 10. Раскладка v2, миграция, golden

### 10.1. Фиксированный пролог (page 3 исправлен)

| Страница | Содержимое | Примечание |
|---|---|---|
| 0 | Superblock A | |
| 1 | Superblock B | |
| 2 | `LayoutHead` A | 512 Б записи, CRC |
| 3 | `LayoutHead` B | **отдельная страница** (F-2, коллизия page 3 устранена) |
| 4 | Writer registry | M3; в M1 `term = 1`, страница валидна и пуста |
| 5 | `ALLOC_RECORD` A | |
| 6 | `ALLOC_RECORD` B | отдельная страница |
| 7 … 7+N−1 | Reader table | N = 33 @4096, 17 @8192, 9 @16384 |
| далее | Root directory A/B регионы | `2 × ceil(max_zones / 16)` страниц |
| далее | data pages | branch/leaf/overflow/zone-meta/chain/buckets |

```
page_reader_table   = 7
reader_region_off   = 7 * page_size          # % 64 == 0
reader_region_len   = N * page_size
page_root_dir_first = 7 + N
root_dir_pages      = 2 * ceil(max_zones / 16)
page_data_first     = page_root_dir_first + root_dir_pages
```

Superblock v2 хранит: `page_layout_head_a/b = 2/3`, `page_writer_reg = 4`, `page_alloc_record_a/b = 5/6`, `page_reader_table = 7`, `page_root_dir_first`, `max_zones`, `page_data_first`. Проверки `mmap` — как v1 §6.1 (`off % 64 == 0`, `len`, `dev/ino`). **Второго writable-региона нет** (D-C).

**Golden:** v1-фикстуры страниц данных/ключей переиспользуются. v2-фикстуры пролога и ring/chain/`ALLOC_RECORD`/reader-слота **регенерируются** (page 3 → LayoutHead B, registry → page 4, ALLOC_RECORD → 5/6, reader → page 7). Конвертер v1→v2 пишет новый пролог.

### 10.2. Переиспользуется / меняется

**Переиспользуется:** `PageHeader` 40 Б (+`owner_zone`), CRC32C, COW B+tree, RLE/компаратор/overflow/`LeafValue`/`ZoneMeta`, `ZoneState`/`zone_seq`, `sync_mode` + sticky, `NEEDS_FSCK`, lock-файл/`O_NOFOLLOW`/`fstat`/SIGBUS, двухфазный пин (структура), bucket-механика, recovery-скелет, `fsck`-обходы.

**Меняется:** глобальная meta → `LayoutHead` + ring/chain + `ALLOC_RECORD`; `txnid/durable_txn/reclaim_txn` → `txn/version/D_z/MP/RV`; глобальный freelist → per-zone пулы + donation; `ZoneEntry` 72→24 Б; reader slot 32→128 Б; delete = запись корня; `snapshot.txnid` → `snapshot_seq` (аудит) + `ZoneSnapshot`.

### 10.3. Конвертер

`zonefile convert --in v1 --out v2`: v1 read-only → v2 create (новый пролог) → для каждой зоны канонический `enumerate` → записать дерево/`ZoneMeta` → `RootEntry` 64 Б (`version` = новый `txn`, счётчики/state/serial из v1 `ZoneEntry`, `free_head=0`) → каталог 24 Б → `LayoutHead`/`ALLOC_RECORD`/reader region → `fdatasync` + `fsync` каталога + `rename` → `fsck --verify` + сравнение дампов. Не пишет в исходник, идемпотентен. v1 под writer'ом v2 → `ReadOnly{ConvertRequired}`; v2 под v1 → `UnsupportedVersion`.

---

## 11. Фиксация ограничений (гейт C-11 ADR-0006)

| ID | Ограничение | Где здесь |
|---|---|---|
| PW-L1 | нет атомарности между зонами | §5.1, §5.6, §5.7, S-9 |
| PW-L2 | изоляция зон — производительная, не security | §4.7, §6.1 (`owner_zone` — детект) |
| PW-L3 | нет глобального перераспределения без donation | §3.2, §6.4 |
| PW-L4 | `durable_watermark` → вектор | §2, §8.1 |
| PW-L5 | `PIN_OVERFLOW` → глобальная деградация | §5.2, §5.4 |
| PW-L6 | `Busy` на файл только в M1 (`LOCK_EX`) | §7.1 п.6 |
| PW-L7 | create зоны не атомарен с содержимым | §5.6 |
| PW-L8 | `snapshot.txnid` теряет смысл | §5.1 |
| PW-L9 | `sync()` — глобальный барьер; `Flush` неравномерен | §7.2, §6.5 |
| PW-L10 | `NoSpace{zone}` vs `MapFull{global}` | §3.2 |
| PW-L11 | blast radius torn-страницы корней | §4.2, §4.6 |
| PW-L12 | утечки при крахе | §3.3, §3.5, S-18/S-20/S-14 |

---

## 12. Инварианты и отсутствие скрытых блокировок

`PW-I1…PW-I10` действуют; уточнения:

| ID | Инвариант |
|---|---|
| PW-S1 | `reserve_cursor`/`reserve_txn` — только CAS в памяти; `pwrite` по ним запрещён; второго writable-региона нет (D-C) |
| PW-S2 | Запись корня только при `DP > max_allocated_id ∧ DT ≥ V` |
| PW-S3 | Две копии одной записи (`RootEntry`, `ALLOC_RECORD`, `LayoutHead`) не делят 512-байтовый сектор; `LayoutHead` B и registry — разные страницы |
| PW-S4 | Bucket `dropped(V)` — в фазе 1 коммита `V`, `free_head` — в `RootEntry V`; reuse — `drop_txn < D_z` |
| PW-S5 | `MP(z)`/`RV_z` меняются только GC под `EpochGuard`; `RV_z` не понижается; `freeze_epoch` входит в `RV_z` |
| PW-S6 | `PageHeader.owner_zone` = `zone_seq`; несовпадение при валидном CRC — **file-fatal** |
| PW-S7 | Bucket и chain — фаза 1; durable-запись ⇒ durable-пул/chain |
| PW-S8 | Ring исчерпан → chain-вытеснение; `ZoneWriterStalled` — только патология цепочки (лимит/I/O) |
| PW-S9 | `snapshot_seq` не ограничивает выбор версии; `NoZoneVersion` — только «зоны нет» |
| PW-S10 | `zone_guard` — только через `EpochGuard` (RAII); читатель → `ZoneDegraded` после 8 guard-неудач |

**Read-path:** `SnapshotHandle` (1 load), `ZoneSnapshot` (1 Acquire + пин + fence + 2 load + `fetch_min`), `lookup` — ни mutex/rwlock, ни RMW на данных, ни syscall, ни аллокаций. Cross-core записи: `published_txn` (1/группу), `reserve_cursor`/`reserve_txn` (CAS), `zone_guard` (2/коммит зоны), `MP[z]` (fetch_min на пин), `ArcSwap` (1/коммит зоны). **Commit-path:** глобального mutex нет; каталог-writer — единственная сериализация, вне hot-path; `LOCK_EX` — процессный.

---

## 13. Открытые вопросы

| # | Вопрос | Предложение/статус |
|---|---|---|
| Q1 | `MAX_ROOT_CHAIN_PAGES` (4096) | принять; калибровать по `pw_zone_writer_stalled_total` (штатно 0) |
| Q2 | Ёмкость root directory: 512 Б/зона ⇒ 25.6 МиБ/50k, 512 МиБ/1M | `max_zones` при создании (дефолт 65536) |
| Q3 | Пины: 6 × 16 Б (D-D) | принять; при overflow — EPOCH-пин; `V:loom`/ARM64 CI обязательны |
| Q4 | `MAX_BATCH_DELAY`/`MAX_BATCH_ZONES` | калибровка на M3 |
| Q5 | `freeze()`: таймаут 300 с — алерт, не вытеснение | принять; оператор снимает держателя |
| Q6 | `strict_corruption` | дефолт `zone`; `file` — «всё или ничего»; file-fatal не ослабляется |
| Q7 | Общий курсор для M3 | решено ADR 0007: sidecar `cursor`/`txn` (D-C) |

## 14. Риски

| # | Риск | Митигация |
|---|---|---|
| R1 | Seqlock на ARM64 (store→load) | `fence(SeqCst)`, loom, ARM64 CI |
| R2 | Подъём `MP` гоняет с пином | §5.4 (GC под guard), loom `epoch_min` |
| R3 | Double allocation через пул | F-10-порядок, S-13/S-20, property-тест |
| R4 | Утечки chain/bucket после краха | `fsck`, `pw_alloc_leaked_pages_estimate`, порог 1 % |
| R5 | Рост chain у застрявшего читателя | лимит 4096 + `ZoneWriterStalled` (патология), алерт |
| R6 | `freeze` держит рекламацию | таймаут-алерт, оператор; запись не блокируется |
| R7 | Единый fsync-поток — потолок | bulk-lane, шардирование координатора, порог WAL |
| R8 | Рост root directory | Q2, `max_zones`, compact |
| R9 | Reader starvation из-за `e0==e2` под churn | `ReaderContended` (retryable), не `ZoneDegraded`; backoff |
| R10 | File-fatal ложное срабатывание | строгие условия §9.2, `fsck --repair`, T-5 |

---

## 15. Приёмка M1: C-1…C-11 (нормативно)

Условия ADR-0006 §12; непройденное условие = M1 не принят. Тесты — `V:crash`/`V:loom`/`V:prop` (+`V:unit`/`V:integ`).

| # | Условие | Где | Тесты |
|---|---|---|---|
| C-1 | Пин: `e0` до головы, `fence(SeqCst)`, `c1==c2` чётный, `e2==e0`, `root2.version==root.version` (F-1) | §5.3 | `V:loom` `pin_capture`; негатив: убрать `e0`/`c1c2` → падает; `V:unit` |
| C-2 | A/B **всех** структур — в разных 4 KiB страницах; page 3 исправлен (F-2) | §4.2, §3.4, §10.1 | `V:crash` S-5/S-25; `V:unit` геометрия; golden пролога |
| C-3 | Барьер аллокаций; `DP=max(...)`; `reserve_cursor := DP` до первого alloc (F-3, D-C) | §3.5, §4.5 | `V:crash` S-10; `V:prop` №1 |
| C-4 | Ровно два fsync; `page_limit_at_commit` в записи (F-4) | §4.5, §7.1 | `V:crash` S-3/S-4/S-8/S-9; `V:bench`; `strace -c` |
| C-5 | File-fatal vs zone-fatal; список §9.2 при любом `strict_corruption` (F-6) | §9.2 | `V:unit` (каждый признак → read-only); `V:integ` |
| C-6 | `is_reclaimable` 4 условия; donation двумя фазами; пул связан с durable-головой (F-10) | §6.2–6.4 | `V:crash` S-13/S-15/S-20; `V:prop` №4 |
| C-7 | Резервы (`GC_RESERVE_PAGES`, `ROOT_RESERVE_PAGES`, `ZONE_PAGE_QUOTA`) | §3.2, §6.5 | `V:crash` S-23; `V:bench` |
| C-8 | `zone_write_epoch` — RAII; `ZoneDegraded` после `PIN_ATTEMPTS` (F-11) | §5.3, §5.4 | `V:crash` S-27; `V:unit` panic между odd/even; `V:loom` `epoch_min` |
| C-9 | Семантика `Snapshot`: `ceiling = ∞`, `freeze()` — retention (F-9) | §5.1, §5.7 | `V:prop` №6; `V:integ` T-2; `V:loom` `pin_capture` |
| C-10 | Ring/chain: AXFR+10 коммитов/с без отказа записи (F-8) | §4.3–4.4 | `V:integ` T-1; `V:crash` S-17/S-18/S-19 |
| C-11 | M3 (N процессов) не включается без F-5 | §7.1 п.6 | ревью; отдельный ADR |

**T-1 (F-8):** AXFR держит `ZoneSnapshot` ≥ 5 с, 10 коммитов/с в ту же зону → 0 `ZoneWriterStalled`, 0 `Corrupt`, `fsck` зелёный; `pw_root_chain_depth` растёт и падает после AXFR.
**T-2 (F-9):** `Reader::snapshot()` → 100 коммитов в другие зоны и ≥ 10 в ту же → `zone_snapshot(z)` успешен, `version` ≥ исходной, без `NoZoneVersion`.
**T-3 (F-11):** `panic` между odd/even (writer и GC) → `catch_unwind`/`Drop` → guard чётный; «застрявший» guard → `ZoneDegraded` за ≤ 8 попыток; `fsck` снимает флаг.
**T-4 (F-10):** крах между durable bucket и публикацией `RootEntry V` → recovery либо видит `free_head`, либо страницы недостижимы (leak); property: ни одна страница не в двух местах; нет 2-групповой задержки.
**T-5 (F-6):** каждый признак §9.2 → read-only файла, `NEEDS_FSCK`; ни один не «деградирует только зону».
