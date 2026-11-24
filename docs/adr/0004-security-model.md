# ADR-0004: Модель безопасности (принятые меры)

- **Статус:** Proposed — требует утверждения Оркестратора/пользователя
- **Дата:** 2026-11-23
- **Контекст:** [Модель угроз](../spec/threat-model.md), [Инвентарь криптографии](../spec/crypto-inventory.md)
- **Затрагивает:** `pulse-zonefile`, `pulse-dns`, `pulse-runtime`, `pulse-server`, `pulse-resolver`, `pulse-api`

---

## Контекст

pulse-dns — неблокирующий DNS-сервер на Rust с единым mmap-файлом зон и **инкрементальными правками на месте**. Это создаёт три класса угроз, нетипичных для «обычного» DNS-демона:

1. **Данные и код в одном адресном пространстве.** Байты файла интерпретируются как offsets/lengths/счётчики. Ошибка валидации = чтение за границей отображения, UB или SIGBUS.
2. **Конкурентное чтение и запись.** Запросы читают зону, пока REST-оператор правит её инкрементально. Нужна защита от «рваного» чтения без блокировок на горячем пути.
3. **Файл — это граница доверия.** Он может быть повреждён, усечён или подменён локальным пользователем; процесс не должен падать и не должен отдавать испорченные данные как валидные.

ADR фиксирует **принятые меры** и **способ проверки каждой меры**. Требования не должны противоречить производительности; там, где компромисс неизбежен, он указан явно (раздел 10).

### Соглашения

- `SEC-*` — требование; ссылки на сценарии `S-*` и риски `R-*` из threat-model.
- Метки проверки: `V:unit`, `V:prop`, `V:fuzz`, `V:integ`, `V:lint`, `V:ci`, `V:cfg`, `V:bench`, `V:miri`, `V:manual`.
- «MUST» — обязательно для соответствующего milestone; «SHOULD» — рекомендуется, отклонение требует записи в ADR.

---

## Решение

Принять перечисленные ниже меры как обязательные. Каждое требование имеет идентификатор, формулировку и проверку. Реализация без проверки не считается выполненной.

---

## 1. Файл зон и mmap (`pulse-zonefile`)

Связанные сценарии: S-14, S-15, S-21, S-22, S-23. Риски: R-03, R-04, R-10, R-17, R-23, R-24, R-25.

> **Режимы записи.** §1.1–1.2 описывают базовый формат и модель «один писатель + глобальная meta» (реализовано в фазе 1). §1.3 задаёт дополнительные требования для режима **параллельной записи по зонам** (ADR-0006). В параллельном режиме требования §1.3 действуют совместно с §1.1–1.2; где они расходятся (публикация корней, freelist, watermark, эксклюзивность писателя), приоритет имеет §1.3, а §1.1–1.2 сохраняются в части чтения, CRC, границ, прав файла и fail-closed. Идентификаторы `SEC-ZF-*` не переименовываются.

### 1.1. Формат и валидация

| ID | Требование | Проверка |
|---|---|---|
| SEC-ZF-001 | Superblock (A/B) self-describing: `magic`, `version_major/minor`, `page_size`, `page_count_max`, `checksum_algo`, `crc32c`, `instance_uuid`, дескрипторы секций. Активная meta выбирается по максимальному валидному `txnid`. Неизвестная/более новая версия или расхождение копий → `UnsupportedVersion`/`Corrupt`, отказ старта. | `V:unit` (все версии, включая future), `V:integ` (старт) |
| SEC-ZF-002 | Все сохраняемые ссылки — **PageId/offsets+lengths от базы**, не сырые указатели. Любой доступ идёт через checked-accessor: `offset.checked_add(len) <= payload_len`, `count.checked_mul(size) <= remaining`; `page_no` из заголовка сверяется со слотом. Запрещены сужающие `as`-касты в модулях чтения. | `V:unit` (граничные/overflow-кейсы), `V:lint` (`#![deny(clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::cast_possible_wrap)]` в reader-модулях) |
| SEC-ZF-003 | Целостность: CRC32C на **все страницы, кроме reader-table региона** (слоты меняются конкурентно, CRC невозможен: `crc32c` MUST 0, валидатор и `fsck` регион пропускают); superblock — байты `[0,4096)`. Для reader table — только атомарные слоты (`AtomicU64`) и валидация `active_txn == 0 \|\| active_txn ≤ txnid(active)` + reserved-битов; порча слота даёт лишь ложный «жив/свободен» или неверный пиннинг (деревья не затрагиваются, §6.1). CRC остальных страниц проверяется один раз на версию и кешируется в per-snapshot bitset; несовпадение → `Corrupt`, SERVFAIL. **Паники запрещены.** | `V:unit` (CRC skip + slot-валидация), `V:integ` (SERVFAIL + метрика), `V:fuzz` (`reader_table_state`), `V:bench` |
| SEC-ZF-004 | Путь чтения без паник: запрещены `unwrap`, `expect`, `panic!`, прямой индексирующий доступ (`[]`), целочисленное деление без проверки. Ошибки — через `Result`. | `V:lint` (`#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]` на reader-модулях) |
| SEC-ZF-005 | Счётчики валидируются против формата и оставшихся байт **до** любой аллокации. Лимит считается в **RRset, не в RR**: hard limit формата — **50 000 000 RRset/зону** (`MAX_RRSETS_PER_ZONE`, §2, §16), операционный дефолт — **10 000 000 RRset/зону**, калибруется в M3. Аллокации ограничены (bounded). | `V:unit` (huge count), `V:fuzz` (OOM-детект через ограничение памяти) |
| SEC-ZF-006 | DNS-компрессии в файле **нет** (RLE-метки в обратном порядке, §8.1), поэтому «декомпрессия с указателями» **не применимо по построению**. Эквивалентные проверки: метка 1..63, имя ≤ 255 с одним терминатором, **≤ 127 меток**, `0xC0..0xFF` в позиции длины запрещены (§8.1, §8.4); `shared_len + suffix_len ≤ MAX_KEY_SIZE = 261` (§10.2); overflow-цепочка ≤ 64 страниц с детектом циклов (§11.4, `MAX_OVERFLOW_PAGES`); глубина **дерева** ≤ 8 (`I-9` §3.2, §16) — это не глубина меток. | `V:unit` (reject `0xC0..0xFF`, name/label bounds, overflow chain/cycle, depth), `V:fuzz` |
| SEC-ZF-007 | Инкрементальные правки атомарны через **COW + double-buffered meta**: writer пишет новые страницы по новым `PageId`, затем неактивную meta с новым `txnid`; публикация `active_txn` — только после durability. Читатель держит снапшот `txnid` (reader slot) и видит только committed-граф; незакоммиченные страницы недостижимы. **`durable_watermark = max(min(durable_txn, txnid))` по всем валидным meta** (per-meta `durable_txn` — поле конкретной meta, участвует только в вычислении watermark); watermark двигается только успешным `Sync`/`sync()` (fsync данных и meta), не двигается `Flush`/`Memory`/recovery. Переиспользование страниц, освобождённых в транзакции `F`, — только при `F < durable_watermark` **и** `F ≤ oldest_reader_txn`; при `durable_watermark = 1` переиспользование запрещено. Регрессия `durable_txn(selected) < durable_watermark` → W-10: `NEEDS_FSCK` + `write_locked`. **Живой процесс (PID существует и `incarnation` совпадает) не вытесняется никогда, независимо от heartbeat**; следствие — writer может ждать до `NoSpace`/`ReadersStalled`: это диагностируемое состояние (safety > availability), метрика `readers_stalled` + инструкция оператору (дождаться/остановить читателя, `sync()`), **без принудительного освобождения**. `stale_reader_timeout` — только `LONG_HOLD`-диагностика и слоты мёртвых PID (ADR-0003 §5.4). | `V:unit` (crash-recovery, stale/live reader), `V:integ` (kill -9 в середине коммита), `V:prop` (инвариант «читатель видит только committed `txnid`») |
| SEC-ZF-008 | Порядок durability: данные → `fdatasync` → запись неактивной meta (`durable_txn` — per-meta поле, CRC) → `fdatasync` meta (только `Sync`/`sync()`) → `fence(Release)` → publish `active_txn`. Recovery выбирает max-valid meta; для `Sync`/`Flush` её данные fsync'нуты до meta, roll-forward разрешён (`recovered_unsynced = true` — диагностика, `NEEDS_FSCK` не выставляется). **`durable_watermark = max(min(durable_txn, txnid))` по всем валидным meta.** `Memory`: только откат к `txnid ≤ durable_watermark` либо явный opt-in `allow_unsynced_memory_recovery` с `NEEDS_FSCK` и read-only до `fsck`; иначе `UnsyncedMemoryRecovery`. Гарантия `Sync` требует липкого режима: после первого `Sync`/`sync()` (`durable_watermark > 1`) все коммиты — `Sync`, понижение до `Flush`/`Memory` запрещено; регрессия `durable_txn(selected) < durable_watermark` → W-10 (`NEEDS_FSCK` + `write_locked`). | `V:unit`, `V:integ` (эмуляция частичной записи), `V:prop` |
| SEC-ZF-009 | SIGBUS/усечение и блокировки: **writer-эксклюзивность — отдельный lock-файл `<zonefile>.lock`** (`0600`, `flock(LOCK_EX\|LOCK_NB)`; второй writer → `Busy`); читатели **flock не берут вообще** и регистрируются только через reader table. `fstat`-размер проверяется при открытии; `dev/ino` сверяются **перед каждым `mmap`** (данные и reader region), но **не на каждом доступе к странице**; аварийный обработчик SIGBUS (`SA_SIGINFO`) логирует `si_addr` и делает fail-stop (`abort()`). Внешнее усечение предотвращается правами. | `V:unit` (путь lock-файла), `V:integ` (второй writer → `Busy`; truncate → fail-stop), `V:manual` (аудит обработчика) |
| SEC-ZF-010 | Права и владелец: файл `0600` (создание `O_CREAT\|O_EXCL` + `fchmod`), каталог `0700`, владелец — `pulse-dns`. Открытие с `O_NOFOLLOW`; после `open` — `fstat`: обычный файл, `st_uid == geteuid()`, `mode & 0o077 == 0`, повторная сверка `dev/ino` перед `mmap` (закрытие TOCTOU). | `V:unit` (mode-проверки), `V:integ` (symlink/wrong-owner → отказ), `V:cfg` |
| SEC-ZF-011 | Повреждённый/враждебный файл: **отказ старта** с машиночитаемой причиной (`ZoneFileError`: `Corrupt`, `CorruptNoValidMeta`, `UnsupportedVersion`, `TruncatedFile`). Авторемонт запрещён; восстановление — только offline `zonefile fsck`/`--repair`. `ftruncate` до `map_size` допустим **только** при создании нового файла (`O_CREAT\|O_EXCL`); если существующий файл короче `page_count_max * page_size` → `TruncatedFile` (fail-closed) и для writer, и для reader, без молчаливого расширения. | `V:integ` (порча, усечённый существующий vs новый файл), `V:unit` (коды ошибок) |
| SEC-ZF-012 | Fuzz-таргеты: (a) reader на произвольных байтах, (b) writer round-trip, (c) differential read→write→read, (d) `reader_table_state` (слоты/пиннинг). Инвариант: нет паник, нет OOM, нет чтения/записи за границей. Nightly-бюджет в CI. | `V:fuzz` (`zonefile_read`, `zonefile_write`, `zonefile_roundtrip`, `reader_table_state`) |
| SEC-ZF-013 | Miri на чистой логике parse/serialize (in-memory `Vec`, без mmap-сисколлов) для проверки отсутствия UB в unsafe-обёртках. | `V:miri` |
| SEC-ZF-014 | Политика `unsafe` и mmap в `pulse-zonefile`: `unsafe` только в модуле привязки mmap; каждый блок — с `// SAFETY:`; `#![deny(unsafe_op_in_unsafe_fn)]`; остальные доменные крейты — `#![forbid(unsafe_code)]`. **Маппинг:** данные, дерево, overflow, meta, superblock — строго `PROT_READ` (запись только через `pwritev`); отдельный `MAP_SHARED` writable-маппинг разрешён **только** для региона reader table: начало выровнено на cache line (64 B; page-aligned по построению), слоты — 8-байтовые atomic `u64`, длина вычисляется как `pages = ceil(READER_SLOTS * 32 / (page_size - 32))`, `len = pages * page_size` (§6.1). При открытии: `[off, off+len)` в границах файла, `off % 64 == 0`, формула `pages`/`len` сверена, после `mmap` повторно сверяются `page_count_high_water` и `dev/ino`. Запись за пределы региона невозможна: writable-маппинг создаётся только на диапазон reader table, data-диапазоны `PROT_READ`, writable-срез не выдаётся наружу. **FD-режим (принято для M1):** writable reader-region требует один `O_RDWR` fd; это не граница привилегий — код с доступом к `ZoneFile::file()` может `pwrite` данные в обход COW. Публичный API не должен отдавать `O_RDWR` fd reader-роли; для M3 (межпроцессные читатели) — отдельный slot-файл либо отдельные fd (read-only данные + writable-регион). | `V:unit` (границы/выравнивание/размер региона), `V:integ` (дочерний процесс: запись в data-регион → SIGSEGV; ASan; reader без writer-fd), `V:fuzz` (`reader_table_state`), `V:miri`, `V:lint` |
| SEC-ZF-015 | Torn-meta recovery: одна невалидная meta (CRC/поля) при валидной второй — штатный крах с откатом к валидной; `NEEDS_FSCK` не выставляется, если `txnid` невалидной не читается или `≤` выбранного. `NEEDS_FSCK` — только при обеих невалидных (`CorruptNoValidMeta`, offline `fsck`) или читаемом `txnid` невалидной `>` выбранного (нельзя доказать, что потерян более новый коммит). Невалидная meta не «чинится» молча. | `V:unit` (одна/обе невалидны, читаемый/нечитаемый `txnid`), `V:integ` (kill -9 в момент записи meta), `V:prop` |

### 1.2. Конкурентность без блокировок на горячем пути

Принята **MVCC-схема на COW + double-buffered meta** (см. `zonefile-v1` §14) вместо глобального `RwLock`:

- writer копирует изменяемый путь страниц по новым `PageId`, готовит неактивную meta с новым `txnid` и публикует `active_txn` только после `fdatasync`;
- читатель фиксирует снапшот `txnid` (reader slot) и читает неизменяемый граф; незакоммиченные страницы недостижимы;
- CRC страницы проверяется один раз на версию и кешируется в per-snapshot bitset, поэтому на горячем пути — атомарная публикация снапшота (`arc-swap`), без блокировок.

**Границы маппинга и блокировок (см. SEC-ZF-014, SEC-ZF-009):**
- данные/дерево/overflow/meta/superblock — `PROT_READ`, запись только `pwritev`; writable `MAP_SHARED` — **только** регион reader table (cache-line aligned, atomic `u64`-слоты);
- writer-эксклюзивность — отдельный `<zonefile>.lock` (`LOCK_EX|LOCK_NB`); читатели flock не берут и регистрируются в reader table;
- читатель с живым PID и совпадающим `incarnation` не вытесняется никогда; `stale_reader_timeout` — только `LONG_HOLD`-диагностика и мёртвые PID (ADR-0003 §5.4).

Обоснование: запросы к зоне доминируют над правками; глобальная блокировка на чтение убила бы заявленную производительность. MVCC даёт wait-free чтение и атомарность без WAL.

### 1.3. Параллельная запись по зонам (`SEC-PW-*`)

Детальный анализ — [ADR-0006](0006-parallel-writers-safety.md) (инварианты `PW-I1..PW-I14`, crash-матрица `PW-C1..PW-C29`, ограничения `PW-L1..PW-L14`, приёмочные тесты `PW-AT-1…PW-AT-8`). Здесь — **источник истины по идентификаторам**; ADR-0006 и `parallel-writes-v2` ссылаются сюда.

**Статус приёмки:** F-8…F-11 и page 3 закрыты решениями Оркестратора и переведены в нормативные требования. **M1 принимается при выполнении C-1…C-10 и зелёных PW-AT-1…PW-AT-8**; единственный блокер — **M3** (C-11/F-5, межпроцессная запись), к M1 не относится.

Связанные сценарии: S-21 (порча чужой зоны / гонка публикации), S-22 (double-free/двойная аллокация), S-23 (застрявший reader блокирует запись). Риски: R-23, R-24, R-25.

Границы модели (обязательны для корректного чтения требований):

- **v2 (M1/M3): один процесс-писатель** (`flock(LOCK_EX)`), N потоков-writer'ов, один координатор group commit, один GC (ADR-0005 §1.5). Несколько процессов-писателей — **v3**, отдельный ADR; до него запуск N процессов на один файл запрещён.
- Потоки-писатели взаимно доверенные (один бинарь/uid). Изоляция зон — **производительная, не security** (`PW-L2`, RR-9). Защита от злонамеренного писателя в этой модели не заявляется.
- Межзонная атомарность коммитов **не предоставляется** (`PW-L1`, RR-8): `Snapshot` — набор per-zone версий; согласованный срез — только `freeze()`.
- Платформы — `x86_64` и `aarch64` Linux, локальная ФС; 32-битные цели исключены (`AtomicU64` не lock-free).

| ID | Требование | Проверка |
|---|---|---|
| SEC-PW-001 | **Публикация корня зоны (ring).** `RootEntry` 64 Б: `crc32c`, `owner_zone`, `version` (=глобальный `txn`), `root_page`, `page_limit_at_commit`, `meta_root`, `tree_level`, `state`, `deleted_txn`, `free_head`. На зону — 4 версии × 2 копии (`version mod 4` — группа). **Копии A/B — в разных 4 KiB страницах** (PW-I11): иначе torn-сектор уничтожает обе. Перезапись группы только при `group.version < MP(z)` ∧ `< D_z` ∧ `< V`; иначе коммит пишет **chain** (`ROOT_CHAIN`, `prev_record`, фаза 1) — **без** `ZoneWriterStalled` и без блокировки. `select` — ring → chain до `version ≤ ceiling`; `MAX_ROOT_CHAIN_HOPS=4096`; chain GC при `version < MP ∧ < D_z` (C-10, PW-AT-1). Выбор — max-valid с `version ≤ ceiling`, tie-break A; битый CRC не чинится. Обе копии всех групп биты → `Corrupt{zone}`, файл работает. | `V:unit` (torn, геометрия, выбор), `V:crash` (PW-C5/C-6/C-7/C-25), `V:prop` №2, **PW-AT-1/PW-AT-7** |
| SEC-PW-002 | **Видимость и семантика снапшота.** Для `ZoneSnapshot`: `page.txn ≤ snapshot.version` и `owner_zone` проверяются на чтении (PW-I1). Глобальный `Snapshot { snapshot_seq, catalog_version }` **не** обещает согласованного среза (PW-L1) и **не является ceiling**: `ZoneSnapshot` берёт последнюю версию на момент взятия (`ceiling = ∞`); зона, изменённая после `Reader::snapshot()`, читается (новее), `NoZoneVersion` — только «зоны нет/tombstone». Повторный `zone_snapshot` в том же `Snapshot` не даёт версию ниже уже виденной. Чтение-на-T — только `freeze()` + `EPOCH`-пин / `fsck --at-epoch`. `snapshot_seq` — для порядка/аудита (`X-Commit-Txn`), не для отказа (PW-I12, C-9, PW-AT-2). | `V:loom` (`root_publish`), `V:unit` (NoZoneVersion только «зоны нет»), `V:prop` №6, `V:integ`, **PW-AT-2** |
| SEC-PW-003 | **Аллокатор (курсор в памяти, D-C).** `reserve_cursor`/`reserve_txn` — `AtomicU64` в памяти, только CAS; второй writable-регион **не вводится** (SEC-ZF-014 сохраняется). `ALLOC_RECORD` (256 Б, 2 копии в **разных** страницах, CRC) фиксирует `page_limit`/`txn_limit`/`term`; **фаза 1 fsync** делает их durable до публикации корней. Writer резервирует до `CommitRequest`; между `CommitRequest` и `CommitAck` новых `fetch_add`/refill нет. Корень пишется только при `DP > max_allocated_id` и `DT ≥ V`. Recovery: `DP = max(record.page_limit, cursor, max head.page_limit_at_commit, max pool page+1, page_data_first)`, `next_txn = max(DT, roots, pages)+1`, `reserve_cursor := DP` **до первого** `alloc`; понижение запрещено. `[DP, cursor)` — утечка, не выдаётся. | `V:loom` (`alloc_record`), `V:crash` (PW-C3/C-4/C-12/C-14/C-17), `V:prop` №1 |
| SEC-PW-004 | **Per-zone пулы и порядок освобождения.** Bucket (COW, `PAGE_TYPE_FREELIST`) с `owner_zone`, `free_epoch`, `next_bucket`; `free_head` — в `RootEntry`. Переиспользование: `F ≥ 2 ∧ F < D_z ∧ F ≤ RV_z ∧ F < current_version(z)`; единственная реализация — `is_reclaimable`. **Bucket `dropped(V)` пишется в фазе 1 того же коммита**, `free_head` — в `RootEntry V` (фаза 2); `PoolHead` не нужен. Крах между bucket и корнем → orphan (утечка, `fsck` возвращает), **не** double-free; 2-групповой задержки нет (PW-I13, C-6, PW-AT-4). Donation — двумя фазами, только для полностью реклеймленных страниц. Обратный порядок = double allocation. | `V:crash` (PW-C16..C-19/C-26), `V:prop` №4, `V:fsck`, **PW-AT-4** |
| SEC-PW-005 | **Group commit: два fsync.** Фаза 1: `pwrite` данных + `ALLOC_RECORD` (2 копии) → `fdatasync`; фаза 2: `pwrite` корней (2 копии в разных страницах) → `fdatasync`; затем `D_z`/`published_txn`/publish. Один `fdatasync` на данные+корни **запрещён** (fsync не упорядочивает диапазоны; возможен корень без данных). Участник, не прошедший `DP > max_alloc ∧ DT ≥ V`, ждёт следующую группу. `Flush` — без второго fsync, `D_z` не двигается; `Memory` — без обоих. | `V:crash` (PW-C2..C-4/C-8..C-11), `V:bench` (потолок), `V:loom` |
| SEC-PW-006 | **Глобальный порядок версий и владелец.** `txn` — глобально монотонный CAS-блок; `version(Z) = txn`; `PageHeader.txn = txn`. Это — защита от кросс-зонного ABA: переиспользованная страница получает новый `txn` > любого старого `version`. `PageHeader.reserved1` (+12) = `owner_zone u32` под required-флагом `F_PARALLEL_WRITES` (0 — служебные) как **defense-in-depth**: `page.owner_zone ≠ head.owner_zone` → `Corrupt`. `zone_seq` головы сверяется с каталогом. Per-zone `txn` без глобального порядка **запрещён**. | `V:unit` (негатив: `page.txn > version`, чужая зона), `V:fsck` (дизъюнктность), `V:prop` |
| SEC-PW-007 | **Пин читателя (v2 §5.3) и RAII-guard.** Порядок: `e0 = published_txn` **до** чтения головы; `ceiling = ∞`; `root = heads[z]`; `pin(root.version, Release)`; `fence(SeqCst)`; `c1 = zone_write_epoch[z]`; `e2 = published_txn`; `root2 = heads[z]`; `c2 = zone_write_epoch[z]`; успех только при `c1==c2` (чётный), `e2==e0`, `root2.version==root.version`. Любой актор (коммит, GC), меняющий голову/`MP`/`RV`, инкрементирует guard (odd→even) и читает пины `Acquire` после инкремента. `zone_write_epoch` — только через RAII-`EpochGuard`: успех/`Abort`/`Io`/`panic=unwind` возвращают чётность; иначе зона недоступна. Читатель после `PIN_ATTEMPTS = 8` → `ZoneDegraded{zone, epoch}` (зона `NEEDS_FSCK`, read-only по зоне), **не** вечный retry; другие зоны работают (PW-I14, C-8, PW-AT-3). Живой читатель не вытесняется никогда (SEC-ZF-007). | `V:loom` (`pin_capture` с тестом «убрать `e0`/`c1c2` падает», `pin_vs_reclaim`, `epoch_min`, `epoch_stuck`), `V:crash` (PW-C20/C-21/C-28), `V:unit` №3/14, `V:ci` (ARM64), **PW-AT-3/PW-AT-7** |
| SEC-PW-008 | **GC и живость.** GC/компакция — обычный коммит зоны: новый граф → durable корень → пул; запрещено освобождать при `F ≥ D_z` или при живом пине. Crash в любой точке GC → утечка, **никогда** double-free; `MAX_GC_ZONES_PER_GROUP`/`MAX_GC_PAGES_PER_GROUP`, `GC_RESERVE_PAGES=32` (не выдаётся обычным коммитам), иначе дедлок при полном файле. `dirty_zones`/`MP` подъём — только в GC-окне под guard. | `V:crash` (PW-C16..C-19/C-23/C-26), `V:prop` №4/5, `V:integ` (GC-шторм), `V:bench` |
| SEC-PW-009 | **Область процессов.** M1: ровно один процесс-писатель, `flock(LOCK_EX)` (второй → `Busy`, SEC-ZF-009 сохраняется), N потоков, один координатор, один GC; `zone_write_epoch`/`MP`/`RV`/`D_z`/`published_txn`/`heads[]` — в памяти процесса. **M3 (N процессов) запрещён** до отдельного ADR: нужны общие `zone_write_epoch`/`published_txn` (или вывод из ring/`ALLOC_RECORD`), общий durable-курсор/`txn`, shared head index, `LOCK_SH`+byte-range lease, generation-recovery, `term`+fencing (F-5). Изоляция зон не является security-границей (T-9/PW-L2). | `V:integ` (второй процесс → `Busy`), `V:unit` (конфликт lease), `V:manual` |
| SEC-PW-010 | **Recovery и классификация повреждений.** `LOCK_EX`, до публикации первого `ZoneRoot`; идемпотентен. Порядок: superblock → `LayoutHead` A/B (разные страницы) → `ALLOC_RECORD` A/B (разные страницы) → каталог → ring → `DP/txn`/`reserve_cursor` → reader table/`MP`/`RV` → Snapshot. **File-fatal** (независимо от `strict_corruption`): `head.page_limit_at_commit > DP` после `max`-коррекции, пересечение множеств зон, `owner_zone`/`version` чужой зоны при валидном CRC, битый `LayoutHead`/`ALLOC_RECORD`/каталог, регрессия `DP`/`DT`/`txn` → `NEEDS_FSCK` + `write_locked` + read-only до `fsck`. **Zone-fatal**: CRC/границы/поля `RootEntry` одной зоны → зона read-only, файл работает (`strict_corruption = file` — v1-поведение). | `V:crash` (PW-C7/C-14/C-22), `V:unit` (негатив: file-fatal vs zone-fatal, регрессия), `V:integ` |
| SEC-PW-011 | **Не обещать межзонную атомарность.** `Snapshot` — каталог + per-zone версии; `zones()`/содержимое — из разных моментов. Согласованный срез — только `freeze()` (`EpochPinned`); multi-zone операции (create дочерней + делегирование) — отдельными коммитами с идемпотентным повтором. `Snapshot::txnid(): u64` → `SnapshotId`/`snapshot_seq` + per-zone `version`; правка `domain-model` §5.1/§5.2 обязательна. | `V:manual` (контракт), `V:integ` (multi-zone без атомарности) |
| SEC-PW-012 | **Формальные инварианты — гейт merge.** `PW-I1` (per-ZoneSnapshot), `PW-I1a` (нет полу-головы), `PW-I2` (переиспользование), `PW-I2a` (pin/commit/GC race), `PW-I2b` (ring/chain), `PW-I3` (нет двойной публикации/освобождения), `PW-I4` (фронтир), `PW-I5` (данные→голова), `PW-I6` (txn), `PW-I7` (выбор), `PW-I8` (нет потери версии), `PW-I9` (GC-живучесть), `PW-I10` (recovery), `PW-I11` (геометрия копий), `PW-I12` (семантика снапшота), `PW-I13` (связывание пула), `PW-I14` (живучесть guard). Реализация без зелёных property/loom/crash-тестов не принимается. | `V:prop`, `V:loom`, `V:crash`, `V:ci` |
| SEC-PW-013 | **DoS-лимиты и деградация.** `PINS_PER_SLOT=8`, `MAX_PINNED_ZONES=64`, `ALLOC_EXTENT_PAGES`, `ALLOC_THREAD_CACHE_PAGES`, `MAX_BATCH_ZONES/BYTES/DELAY`, GC/donation-бюджеты, `ZONE_PAGE_QUOTA_RATIO`, `GC_RESERVE_PAGES`, `MAX_LEAK_RATIO`. Метрики `pw_*` и алерты: застрявший reader, `pw_root_chain_depth`/`pw_chain_pages` (chain), `pw_zone_degraded_total` (guard), `pw_zone_epoch_stuck_total`, `pw_no_zone_version_total` (ожидается 0, кроме tombstone), `pw_orphan_bucket_pages`, `pw_zone_writer_stalled_total` (только отказ chain — аномалия), утечки, fsync-потолок, torn root, `recovered_unsynced_zones`. `NoSpace{zone}` vs `MapFull{global}` различимы в API. | `V:bench`, `V:integ` (штормы/исчерпание), `V:cfg` |
| SEC-PW-014 | **Портируемость memory model.** Только `x86_64`/`aarch64`; `#[cfg(target_has_atomic = "64")]` + отрицательный тест сборки для 32-бит. `Acquire`/`Release` для публикации; `Relaxed` для публикаций запрещён; `fence(SeqCst)` между pin и `c1` (store-load на ARM); никакого dependency ordering; только выровненные `AtomicU64`; управляющие слова не пишутся `pwrite`; смешанный доступ к одному байту запрещён. ARM64 CI-прогон обязателен (loom/TSan ARM не моделируют). | `V:ci` (ARM64 job), `V:lint`, `V:loom` |
| SEC-PW-015 | **Доступность при долгом читателе.** Ring 4 версии даёт 3 коммита быстрого пути; далее коммит **обязан** идти в chain (`ROOT_CHAIN`, фаза 1) — `ZoneWriterStalled` не возвращается. `MAX_ROOT_CHAIN_HOPS=4096`; chain GC при `version < MP ∧ < D_z`; метрики `pw_root_chain_depth`/`pw_chain_pages`. Обязательный тест **PW-AT-1**: AXFR ≥ 5 с + 10 коммитов/с в ту же зону → 0 stall/`Corrupt`, chain растёт и GC-ится. Застрявший guard → `ZoneDegraded` за ≤ 8 попыток (PW-AT-3); `Snapshot` — `ceiling=∞` (PW-AT-2). | `V:integ` (PW-AT-1), `V:crash` (PW-C25/C-27/C-28), `V:prop` №2/6, `V:cfg` |

**Матрица допустимых состояний (сводка для ревью PR):**

| Наблюдение | Вердикт |
|---|---|
| `commit()` вернулся, но корень не fsync'нут | нарушение SEC-PW-005 |
| Голова при `page_limit_at_commit > DP` | нарушение SEC-PW-003 (double allocation после краха) |
| Пин без `e0`/`c1c2`/`e2`/`root2` | нарушение SEC-PW-007 (use-after-reuse) |
| `zone_write_epoch` оставлен нечётным при выходе | нарушение SEC-PW-007/015 (зона недоступна) |
| Копии A/B в одной 4 KiB странице/секторе | нарушение SEC-PW-001 (torn теряет обе) |
| Перезаписана группа с `version ≥ MP(z)` | нарушение SEC-PW-001 |
| Страница выдана при `F ≥ D_z` | нарушение SEC-PW-004 |
| Пул версии `V` не достижим из durable-состояния | нарушение SEC-PW-004 (orphan → утечка) |
| Пересечение зон лечено как zone-fatal | нарушение SEC-PW-010 |
| Один `fdatasync` на данные+корни | нарушение SEC-PW-005 |
| AXFR + 10 коммитов → отказ записи (нет chain) | нарушение SEC-PW-015/C-10 |
| `Snapshot.snapshot_seq` используется как ceiling → `NoZoneVersion` | нарушение SEC-PW-002/C-9 |
| Запущено N процессов-писателей | нарушение SEC-PW-009 (M3 — отдельный ADR) |

**Поглощение ID из ADR-0005.** 0005 §10 предлагает `SEC-ZF-016..019`. Чтобы не иметь двух систем нумерации для одной области, они **не присваиваются**; их содержание покрыто:

| Предложение 0005 | Покрыто |
|---|---|
| SEC-ZF-016 (валидация головы) | SEC-PW-001, SEC-PW-006 |
| SEC-ZF-017 (монотонность фронтира) | SEC-PW-003 (`max(...)` в recovery) |
| SEC-ZF-018 (порядок публикации) | SEC-PW-005 |
| SEC-ZF-019 (изоляция зон) | SEC-PW-003, SEC-PW-006, SEC-PW-010, SEC-PW-012 |

---

## 2. DNS-протокол и сервер (`pulse-dns`, `pulse-server`)

Связанные сценарии: S-01, S-04, S-07, S-10, S-11. Риски: R-01, R-10, R-11, R-12, R-21.

### 2.1. Парсер и лимиты

| ID | Требование | Проверка |
|---|---|---|
| SEC-DNS-001 | Жёсткие лимиты: имя ≤ 255 октетов (wire), метка ≤ 63, сообщение ≤ 65535, UDP payload — honor 512 / EDNS 1232 / cap 4096. Превышение → FORMERR/TC, без аллокации сверх лимита. | `V:unit` (границы), `V:fuzz` (wire-парсер) |
| SEC-DNS-002 | Compression pointers: строго назад (`ptr < current`), лимит цепочки 128, детект петель, bounds check. | `V:unit` (loop, forward-ptr, chain), `V:fuzz` |
| SEC-DNS-003 | Лимиты количества записей и размера RRset (max RRset records — 4096, sanity-дефолт, калибруется в M3) для защиты памяти/CPU. | `V:unit`, `V:cfg`, `V:integ` (huge RRset → SERVFAIL/TC) |
| SEC-DNS-004 | Парсер без паник и без неограниченных аллокаций; ошибки — `Result`. | `V:lint` (те же deny-атрибуты), `V:fuzz` (`dns_wire_parse`) |
| SEC-DNS-005 | Усечение: если ответ превышает буфер клиента — выставляется TC и отдаётся минимальный корректный ответ. | `V:unit` (512/1232/4096), `V:integ` |
| SEC-DNS-006 | Anti-amplification: RRL per source-subnet/response-type; DNS Cookies (RFC 7873, RFC 9018) — серверные cookie, stateless HMAC; ANY-минимизация (RFC 8482). | `V:unit` (RRL-окно, cookie-валидация), `V:integ` (reflection-симуляция), `V:bench` |
| SEC-DNS-007 | EDNS-политика: обрабатываются только известные опции, неизвестные безопасно игнорируются; BADVERS; лимит размера опций; ECS **выключен по умолчанию**. | `V:unit` (BADVERS, unknown-option), `V:cfg` |
| SEC-DNS-008 | TCP: 2-байтный length-prefix, max message 65535, лимиты соединений (global + per-IP), лимит pipelining, idle/read timeout, max queries/connection — защита от slowloris. | `V:integ` (slowloris-симуляция), `V:cfg`, `V:bench` |
| SEC-DNS-009 | Рекурсия закрыта по умолчанию: `allow-recursion` ACL; неавторизованный клиент получает отказ/только авторитативные данные. | `V:unit` (ACL-логика), `V:integ` (refused), `V:cfg` |
| SEC-DNS-010 | UDP: ответы только на валидные запросы; rate limit на источники; cookies как условие для «дорогих» ответов. | `V:integ`, `V:bench` |
| SEC-DNS-011 | Эхо регистра QNAME (0x20) на ответе без искажения семантики; имена сравниваются case-insensitive. | `V:unit` |

### 2.2. Sanity-дефолты лимитов

Значения фиксируются как дефолты конфигурации; **калибруются в M3 по нагрузочным тестам** (изменение — через конфиг и `V:bench`, без изменения кода).

| Параметр | Дефолт | Требование |
|---|---|---|
| Max UDP payload (EDNS) | 1232 | SEC-DNS-001, SEC-DNS-005 |
| Max TCP message | 65535 | SEC-DNS-008 |
| Max RRset records | 4096 | SEC-DNS-003 |
| Max RRsets per zone | 10 000 000 default / 50 000 000 hard (format), в RRset | SEC-ZF-005 |
| Max name (wire) | 255 | SEC-DNS-001 |
| Max label | 63 | SEC-DNS-001 |
| Max compression pointers (wire chain) | 128 | SEC-DNS-002 |
| Max CNAME chain | 16 | SEC-RES-006 |
| Max recursion depth (referrals) | 32 | SEC-RES-006 |
| REST body | 16 MiB | SEC-API-005 |
| REST rate limit | 100 rps/token | SEC-API-004 |
| Blocklist feed size | 64 MiB | SEC-API-010 |

---

## 3. Рекурсивный резолвер (`pulse-resolver` / бинарник `pulseresolved`)

Требования раздела обязательны для бинарника `pulseresolved` (M4) и **не блокируют** M3 (`pulsed`). Рекурсия по умолчанию закрыта — только доверенные сети/ACL.

Связанные сценарии: S-02, S-03, S-05, S-12, S-13. Риски: R-02, R-09, R-11, R-14, R-15.

| ID | Требование | Проверка |
|---|---|---|
| SEC-RES-001 | CSPRNG (`getrandom`) для TXID (16 бит) и source port на **каждый** запрос; tuple (id, port, addr) уникален среди in-flight. | `V:unit` (уникальность/распределение), `V:integ` |
| SEC-RES-002 | 0x20 case randomization **включена по умолчанию**; отключается настройкой per-upstream (совместимость с legacy-middlebox); авто-отключение при сбоях с логом. | `V:unit`, `V:integ` (middlebox-эмуляция), `V:cfg` |
| SEC-RES-003 | Строгий матчинг ответа: source addr + port, TXID, question (имя/тип/класс), RD/RA. Несовпадение → дроп, без кеширования. | `V:unit` (негативные кейсы), `V:integ` (spoofing-симуляция) |
| SEC-RES-004 | Bailiwick: принимаются только записи внутри зоны авторитетного NS; glue не считается авторитетным вне своей зоны. | `V:unit` (out-of-bailiwick), `V:prop` |
| SEC-RES-005 | DNSSEC-валидация — основной барьер для рекурсивного режима. Bogus → SERVFAIL (не кешируется как insecure); AD выставляется только при полной валидации; EDE (RFC 8914) для диагностики. | `V:unit` (bogus/insecure/secure), `V:integ` (реальные подписанные зоны) |
| SEC-RES-006 | Бюджеты против DoS: лимит CNAME-цепи (16), всего запросов на резолюцию (64), глубина рекурсии/referral (32), размер NS-набора, число DNSKEY/RRSIG на RRset, NSEC3 iterations = 0 (RFC 9276), бюджет криптоопераций и таймаут валидации (KeyTrap). | `V:unit` (бюджеты), `V:integ` (KeyTrap-подобный ответ), `V:bench` |
| SEC-RES-007 | Negative caching по RFC 2308 с clamp TTL (min/max); SOA минимальный TTL учитывается. | `V:unit` |
| SEC-RES-008 | Защита кеша: TTL clamp, no out-of-bailiwick caching, flush записи при провале валидации, изоляция по зоне. | `V:unit`, `V:prop` (инвариант кеша) |
| SEC-RES-009 | Защита от NXNSAttack: лимит уникальных NS/glue и concurrent subqueries на резолюцию; rate limit egress. | `V:unit`, `V:integ` (delegation-explosion) |
| SEC-RES-010 | **Вне v1 — известное ограничение:** политика отказа приватных ответов (DNS rebinding) не реализуется; риск R-09 принимается как остаточный (RR-7). Обязательно: **предупреждение в конфиг/лог при включённой рекурсии на интерфейсе, доступном из недоверенной сети, и пункт в документации**. При появлении — отдельный ADR. | `V:cfg` (warning), `V:manual` (docs) |
| SEC-RES-011 | Upstream выбирается только из конфигурации; запрос клиента не может задать произвольный upstream (нет SSRF из query-path). | `V:unit`, `V:integ` |
| SEC-RES-012 | Фрагментация: EDNS buffer 1232 по умолчанию, предпочтение TCP при TC, лимит размера; избегаем фрагментации на egress. | `V:unit`, `V:bench` |
| SEC-RES-013 | **Security gate:** при старте `pulseresolved` с включённой рекурсией и **выключенной** DNSSEC-валидацией — явное предупреждение (лог + health), раздел в README/доках о запрете недоверенных сетей; R-02 открыт до M5. | `V:cfg` (warning), `V:integ` (сценарий старта) |

---

## 4. Криптография и ключи (`pulse-server`, `pulse-api`)

Связанные сценарии: S-12, S-16, S-17. Риски: R-05, R-14, R-17. Детали алгоритмов — в [crypto-inventory.md](../spec/crypto-inventory.md).

| ID | Требование | Проверка |
|---|---|---|
| SEC-CR-001 | Один проверенный крипто-бэкенд (`aws-lc-rs`) для TLS, подписей и HMAC; собственные реализации крипто запрещены. Смена бэкенда — только через поправку к ADR. | `V:ci` (`cargo-deny` ban), `V:manual` (review) |
| SEC-CR-002 | Политика DNSSEC-алгоритмов: **8 (RSA/SHA-256) обязателен для совместимости**, 13 (ECDSA P-256) — дефолт для новых ключей, 15 (Ed25519) — рекомендуется; 16 (Ed448) — optional/по возможности; валидация — 8, 10, 13, 14, 15. SHA-1 (5/7) — только legacy-валидация при явном opt-in, **подпись запрещена**; DSA (3/6) и RSAMD5 (1) запрещены. | `V:unit` (матрица алгоритмов, KAT), `V:ci` (feature-flag legacy off) |
| SEC-CR-003 | Хранение приватных ключей: отдельный каталог `0700`, файлы `0600`, выделенный пользователь; ключ только в памяти; `zeroize`/`ZeroizeOnDrop` при выгрузке; `mlock`; ключи никогда не попадают в логи, дампы, argv; **аудит-лог операций с ключами**. HSM/PKCS#11 — **не в v1** (roadmap, отдельный ADR). | `V:unit` (zeroize-путь), `V:lint` (нет Debug-дампа секретов), `V:integ` (права, аудит), `V:manual` |
| SEC-CR-004 | Генерация ключей через CSPRNG; ECDSA-подпись — только vetted-реализация (детерминированная/hedged, без риска nonce-reuse). | `V:unit` (KAT), `V:manual` |
| SEC-CR-005 | Constant-time сравнение для токенов, MAC и результатов проверки подписи (`subtle::ConstantTimeEq` / vetted verify). | `V:lint` (запрет `==` на секретах через обёртку-тип), `V:manual` |
| SEC-CR-006 | Ротация ключей: pre-publish → double-sign → retire по RFC 6781/7583; автоматические проверки безопасности (не оставить зону без валидной подписи), аудит каждой смены. | `V:integ` (сценарий ротации), `V:unit` (тайминги) |
| SEC-CR-007 | Trust anchors: **встроенный IANA root KSK в поставке**, обновляется с релизами ПО; владелец — команда проекта; RFC 5011 — v1.1. CI-проверка наличия anchor и срока действия на каждом релизе. | `V:unit`, `V:integ`, `V:ci` (anchor presence/expiry) |
| SEC-CR-008 | TSIG: HMAC-SHA256 по умолчанию (SHA-512 допустим), fudge 300 с, проверка времени и MAC constant-time, защита от replay. HMAC-MD5 — **только per-key флаг `allow_legacy_hmac_md5 = true`, по умолчанию выключен**; при использовании — warning в лог и метрика; помечен deprecated, удаление — v1.1. | `V:unit` (KAT, replay, skew), `V:ci`, `V:cfg` (флаг) |
| SEC-CR-009 | TLS: `rustls`, TLS 1.3 приоритетно + 1.2, только AEAD-сьюты, валидация цепочки; корни — **`webpki-roots` по умолчанию, опция системных**; без renegotiation; mTLS для репликации. | `V:unit` (политика), `V:integ` (рукопожатие), `V:ci` |
| SEC-CR-010 | Токены: 256-бит CSPRNG, в хранилище — SHA-256 (не plaintext) + публичный префикс-ID; сравнение constant-time. Пароли людей (если появятся) — Argon2id. | `V:unit`, `V:integ` (аутентификация), `V:manual` |

---

## 5. REST API (`pulse-api`)

Модель — **single-tenant: один оператор на инстанс**; мультитенантность и изоляция по tenant — вне scope v1.

Связанные сценарии: S-08, S-09, S-18. Риски: R-06, R-07, R-18, R-19.

| ID | Требование | Проверка |
|---|---|---|
| SEC-API-001 | По умолчанию bind `127.0.0.1` и/или Unix-socket. Публичный интерфейс — только по явному флагу и только с TLS. | `V:cfg` (старт без флага), `V:integ` |
| SEC-API-002 | Bearer-токены: 256-бит CSPRNG, хранится SHA-256-хеш + префикс-ID; scopes/RBAC (`zones:read/write/delete`, `keys:read/write`, `replication:manage`, `admin`) с per-zone ограничением. | `V:unit` (scopes), `V:integ` (матрица 401/403/404 по §5.1), `V:manual` |
| SEC-API-003 | mTLS для репликации/админ-эндпоинтов (опционально обязательно); TLS обязателен вне loopback. | `V:integ`, `V:cfg` |
| SEC-API-004 | Rate limiting per IP и per token (**дефолт 100 rps/token**); экспоненциальный backoff и временная блокировка на серию неудачных аутентификаций. | `V:unit` (лимитер), `V:integ` (brute-force симуляция) |
| SEC-API-005 | Лимиты тела/JSON: **max body 16 MiB**, max depth, max array/object, max размер зоны на bulk-операцию. | `V:unit` (границы), `V:integ` (413/400) |
| SEC-API-006 | CSRF неприменим: аутентификация — bearer-заголовок, нет ambient cookies. Если появятся cookie-сессии — обязательны `SameSite` + CSRF-токен (зафиксировать новым ADR). | `V:manual` (ревью дизайна), `V:integ` (нет Set-Cookie) |
| SEC-API-007 | Аудит-лог: actor (token-ID, не секрет), action, target, результат, request-ID, source IP, время; append-only; секреты редактируются; опционально hash-chain для tamper-evidence. | `V:unit` (редакция), `V:integ` (запись события), `V:manual` |
| SEC-API-008 | Idempotency-Key привязан к `token-ID + method + path + body-hash`; повтор с другим телом → 409; TTL; никаких коллизий между tenant. | `V:unit` (коллизии/конфликт), `V:integ` |
| SEC-API-009 | Валидация и канонизация входных имён/RR-данных; отклонение невалидного; запрет управления сырыми offsets. | `V:unit`, `V:fuzz` (`api_json`) |
| SEC-API-010 | SSRF-защита для forward-зон, upstream-адресов и blocklist-URL. Blocklist: **только `https` + allowlist хостов в конфиге, max 64 MiB, timeout, запрет редиректов на другие хосты**; resolve + проверка IP против denylist (loopback, link-local, metadata `169.254.169.254`, RFC1918 — если не разрешено явно); egress-политика. Проверка подписи фидов — **не в v1** (roadmap). | `V:unit` (классификатор адресов/allowlist), `V:integ` (попытка SSRF/redirect → отказ) |
| SEC-API-011 | Ответы об ошибках без внутренних деталей/секретов; редактирование в логах; единый формат ошибок. | `V:unit`, `V:manual` |
| SEC-API-012 | CORS deny-by-default; отключён TRACE; allowlist методов; лимиты заголовков и таймауты. | `V:cfg`, `V:integ` |
| SEC-API-013 | Экспорт приватных ключей: только отдельный scope + mTLS + аудит + повторная аутентификация; никогда в plaintext через GET; по умолчанию запрещён. | `V:integ` (403/требование mTLS), `V:unit` |
| SEC-API-014 | Anti-enumeration: zone-scoped endpoint с зоной **вне per-zone allowlist → 404**, неотличимый от несуществующей зоны; 403 — только при отсутствии operation-scope; 401 — только при невалидной аутентификации. Полная матрица и правила — §5.1. | `V:unit` (resolver правил), `V:integ` (матрица статусов) |

### 5.1. Семантика отказов и защита от перечисления зон

**Решение:** доступ к зоне вне per-zone allowlist токена возвращает **404**, идентичный несуществующей зоне. `403` остаётся для отсутствия operation-scope (класса операции), `401` — только для невалидной/просроченной аутентификации.

Порядок проверок: **authenticate → zone allowlist → operation scope → resource existence**. Out-of-scope зона завершает запрос до любого lookup ресурса.

| Ситуация | Код | Тело/заголовки | Аудит-событие |
|---|---|---|---|
| Нет/битый/просроченный токен | 401 | generic; `WWW-Authenticate: Bearer` | `auth_failed` |
| Нет operation-scope (коллекция/глобальный endpoint) | 403 | generic, без имён зон | `denied_scope` |
| Zone-scoped endpoint, зона вне allowlist | 404 | `zone_not_found`, идентично несуществующей; без `Allow`/`WWW-Authenticate` | `denied_zone_out_of_scope` (не `not_found`) |
| Zone-scoped endpoint, зона в allowlist, нет operation-scope | 403 | generic | `denied_scope` |
| Zone-scoped endpoint, зона в allowlist, ресурс отсутствует | 404 | `zone_not_found` | `not_found` |
| `GET /zones` и любые коллекции | 200 | только зоны из allowlist; фильтр по чужой/несуществующей → пустой список | — |
| `POST /zones` вне allowlist | 403 | generic; проверка **до** existence (никогда 409) | `denied_zone_out_of_scope` |
| `/zones/{z}/keys` вне allowlist | 404 | как несуществующая зона | `denied_zone_out_of_scope` |
| Key export в allowlist без `keys:export`/mTLS/re-auth | 403 / 401 | generic | `denied_export` |
| Глобальные replication/audit/admin endpoints без scope | 403 | generic | `denied_scope` |

**Правила:**
- 404 для out-of-scope и для реально несуществующей зоны **неразличимы**: статус, схема тела, код ошибки, заголовки; никаких имён других зон, списков allowlist или подсказок. 403/401 также без имён зон.
- Коллекции **никогда** не отвечают 403 из-за фильтрации; 403 — только при отсутствии operation-scope. Out-of-scope фильтр даёт пустой набор.
- Bulk-операции: per-item 404 для out-of-scope, идентичный несуществующей зоне; не агрегировать «forbidden»-список; действует лимит batch.
- Idempotency-Key: для denied-запросов (403/404) запись **не сохраняется**, чтобы исключить probing через повтор.
- Аудит: отказ фиксируется с reason (`denied_zone_out_of_scope`), даже если наружу отдан 404; аудит недоступен zone-scoped токену (нужен `audit:read`/`admin`).
- Перечисление сдерживается rate limit (SEC-API-004), метрикой `api_denied_zone_out_of_scope_total` и алертом на всплеск.
- Timing: allowlist проверяется до lookup, форма ответа идентична; остаточное различие по времени документируется и не считается границей конфиденциальности (имена зон в single-tenant низкочувствительны), перечисление сдерживается rate limit и аудитом.
- Запрещено: 403 для out-of-scope зоны; 404 для отсутствия operation-scope; любой `409` на `POST /zones` вне allowlist.

---

## 6. Репликация (`pulse-server`)

**Single-host:** репликация — только штатная DNS (AXFR/IXFR/NOTIFY); сетевое FS и консенсус/межхостовый кластер — вне scope v1.

Связанные сценарии: S-06, S-16. Риски: R-08, R-13.

| ID | Требование | Проверка |
|---|---|---|
| SEC-REP-001 | AXFR/IXFR только для пиров из ACL **и** с валидным TSIG; AXFR по UDP запрещён; сообщения об отказе не раскрывают зону. | `V:integ` (ACL/TSIG-матрица), `V:unit` |
| SEC-REP-002 | NOTIFY: TSIG + ACL + rate limit; неизвестный источник игнорируется с метрикой. | `V:integ`, `V:unit` |
| SEC-REP-003 | Secondary валидирует принятую зону: формат/границы, монотонность SOA serial, DNSSEC (если подписана); при провале — карантин и алерт, зона не публикуется. | `V:integ` (отравленный трансфер), `V:unit` |
| SEC-REP-004 | Лимиты трансфера: max размер, max время, rate limit на пира — защита primary от abusive secondary. | `V:unit`, `V:integ` |
| SEC-REP-005 | mTLS в дополнение к TSIG (опционально обязательно) для репликации; pinning сертификатов пиров опционален. | `V:integ` |

---

## 7. Процесс, хост, песочница (ops)

Связанные риски: R-17, R-04.

| ID | Требование | Проверка |
|---|---|---|
| SEC-OPS-001 | Выделенный непривилегированный пользователь `pulse-dns`; bind :53 через `CAP_NET_BIND_SERVICE` или systemd socket activation; после старта root не нужен. | `V:integ` (проверка capabilities), `V:cfg` |
| SEC-OPS-002 | Профиль systemd-hardening: `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `MemoryDenyWriteExecute`, `SystemCallFilter`, `LockPersonality`, `RestrictNamespaces`. | `V:ci` (systemd-analyze security в гейте), `V:manual` |
| SEC-OPS-003 | Секреты не в world-readable конфиге и не в argv; конфиг `0600`, секреты — из файла/окружения с ограниченными правами. | `V:cfg`, `V:integ` (права), `V:lint` |
| SEC-OPS-004 | Приватность по умолчанию: client IP и qname в лог запросов **НЕ пишутся**; только агрегированные метрики. Включение детального лога — явной настройкой с предупреждением; редактирование секретов. | `V:unit` (редакция/дефолт), `V:cfg` (предупреждение), `V:manual` |
| SEC-OPS-005 | Health/metrics — только loopback/внутренняя сеть; метрики без секретов и персональных данных. | `V:cfg`, `V:integ` |
| SEC-OPS-006 | Fail-closed при краше; core dumps отключены (`LimitCore=0`), ключи под `mlock`, `ptrace` ограничен (Yama). | `V:cfg`, `V:manual` |
| SEC-OPS-007 | Зависимость от синхронизации часов (TSIG fudge, DNSSEC validity): дрейф трактуется как ошибка, не как успех; метрика/алерт. | `V:unit` (skew), `V:integ` |
| SEC-OPS-008 | Подписанные релизы (cosign) + checksums; процедура обновления/отката. | `V:ci`, `V:manual` |

---

## 8. Supply chain, фиды и `unsafe` (`SEC-SC`)

Связанные сценарии: S-19, S-20. Риски: R-16, R-20.

Blocklist-фиды трактуются как недоверенные данные (S-19): источник — **только `https` + allowlist хостов**, лимит 64 MiB, timeout, запрет редиректов на другие хосты; размер и формат валидируются до применения (SEC-API-005, SEC-API-010), парсер фида покрыт fuzz (SEC-DNS-004), ошибочный фид уходит в карантин, а не применяется частично. Проверка подписи фидов — не в v1 (roadmap).

| ID | Требование | Проверка |
|---|---|---|
| SEC-SC-001 | В CI: `cargo-audit` (advisories) и `cargo-deny` (advisories, licenses, bans, sources); падение гейта блокирует merge. | `V:ci` |
| SEC-SC-002 | `Cargo.lock` в репозитории; версии запинены; минимум зависимостей; git-зависимости — только после review. | `V:ci`, `V:manual` |
| SEC-SC-003 | Allowlist лицензий (Apache-2.0, MIT, BSD-2/3, ISC, Zlib, Unicode-3.0; MPL-2.0 — с review); GPL/AGPL/SSPL запрещены. | `V:ci` (`cargo-deny` licenses) |
| SEC-SC-004 | Политика `unsafe`: `#![forbid(unsafe_code)]` во всех доменных крейтах; `unsafe` только в `pulse-zonefile` (mmap) и `pulse-runtime` (io_uring), каждый блок с `// SAFETY:`; `#![deny(unsafe_op_in_unsafe_fn)]`. | `V:lint`, `V:manual` (аудит) |
| SEC-SC-005 | Воспроизводимые сборки; SBOM; подпись артефактов. | `V:ci` |
| SEC-SC-006 | Fuzz + Miri в CI; ASan/TSan для крейтов с `unsafe` (nightly-джоба). | `V:fuzz`, `V:miri`, `V:ci` |
| SEC-SC-007 | Процесс review нового крейта: мейнтейнер, число загрузок, история аудитов, наличие `unsafe`/`build.rs`, лицензия. | `V:manual` (чек-лист в PR) |

---

## 9. Аудит и мониторинг безопасности

- Метрики: `rrl_dropped`, `cookie_invalid`, `auth_failed`, `auth_locked`, `zone_degraded`, `zonefile_corrupt_total{kind}`, `validation_bogus`, `validation_budget_exceeded`, `axfr_denied`, `sigbus_detected`, `readers_stalled`.
- Метрики параллельной записи (`SEC-PW-013`): `pw_page_limit`, `pw_txn_limit`, `pw_alloc_leaked_pages_estimate`, `pw_orphan_bucket_pages`, `pw_free_pages_ratio{zone}`, `pw_reclaim_version{zone}`, `pw_zone_min_pinned{zone}`, `pw_root_ring_free_groups{zone}`, `pw_root_chain_depth{zone}`, `pw_chain_pages`, `pw_zone_degraded_total{zone}`, `pw_zone_epoch_stuck_total{zone}`, `pw_no_zone_version_total`, `pw_donated_pages_total`, `pw_donation_backlog_pages`, `pw_group_commit_size`, `pw_group_fsync_seconds`, `pw_batch_delay_seconds`, `pw_torn_root_total`, `pw_recovered_unsynced_zones`, `pw_stuck_reader_seconds`, `pw_reader_pin_overflow_total`, `pw_catalog_write_wait_seconds`, `pw_leaked_head_slots_total`, `pw_strict_corruption_mode`.
- Алерты (обязательные): `zonefile_corrupt_total`, `sigbus_detected`, `readers_stalled`, `validation_bogus` (рост), `axfr_denied` (всплеск), `auth_failed` (всплеск); `pw_alloc_leaked_pages_estimate > MAX_LEAK_RATIO`, `pw_root_chain_depth > 1024` дольше 60 с, `pw_zone_degraded_total > 0`, `pw_zone_epoch_stuck_total > 0`, `pw_stuck_reader_seconds > 300`, `pw_torn_root_total > 0`, `pw_recovered_unsynced_zones` непусто на `Sync`-файле, `pw_donation_backlog_pages` растёт, `pw_group_fsync_seconds` p99 выше бюджета, `pw_free_pages_ratio{zone} > 40 %` дольше часа, `pw_no_zone_version_total` всплеск.
- Аудит изменений (SEC-API-007) не смешивается с query-log (SEC-OPS-004).

---

## 10. Компромиссы с производительностью

| Мера | Стоимость | Обоснование / как держим в бюджете | Гейт |
|---|---|---|---|
| CRC32C на страницу | Аппаратный CRC (SSE4.2/ARMv8) ~ГБ/с; проверка один раз на версию страницы | На горячем пути фактически 0 (per-snapshot bitset) | `V:bench` |
| MVCC-снапшот (`arc-swap`) | 1 atomic RMW + clone `Arc` (≤ 20 нс) | Пренебрежимо; нет блокировок чтения | `V:bench` |
| Bounds/checked math | Предсказуемые ветки | < 1 %; компилятор оптимизирует в `Result`-путь | `V:bench` |
| BLAKE3-манифест | Только старт/явная верификация | Не на пути запроса | — |
| DNSSEC-валидация | Доминирует крипто; кеш валидированных RRset | Кеш + `aws-lc-rs`; валидируются только uncached | `V:bench` |
| RRL | Hash-lookup на ответ | ~1–2 %; снимается при `rrl=off` | `V:bench` |
| DNS Cookies | HMAC на ответ с cookie | ~1 % и только для cookie-клиентов | `V:bench` |
| 0x20 | Кодирование/декодирование + возможные retry | Включена по умолчанию; отключается настройкой (legacy-middlebox); авто-отключение при сбоях | `V:bench` |
| Лимиты TCP | Память на соединение | Снижает риск OOM; ёмкость планируется | `V:bench` |
| `mlock` ключей | Небольшой объём несвапируемой памяти | Приемлемо для KSK/ZSK | — |
| COW-коммит + group commit | Write amplification на правку | Правки редки относительно запросов; group commit ≤ 1 мс | `V:bench` |
| Двухфазный fsync группы (параллельный режим) | Два `fdatasync` на группу вместо одного | Это цена корректности: один fsync не даёт порядок «данные → корень» (`SEC-PW-005`, D-1); группы коалесцируются, амортизированная стоимость на коммит падает | `V:bench` (`pw_group_fsync_seconds`) |
| Разнесение копий A/B | 2 страницы на 16 зон (512 Б/зона) вместо 128 Б подряд | Иначе torn-сектор уничтожает обе копии и CRC-пара бесполезна (`SEC-PW-001`, F-2) | `V:crash` (torn), `V:bench` (плотность) |
| Per-zone free pools | Нет глобального перераспределения страниц (`PW-L3`) | Глобальный freelist в параллельном режиме даёт double-free после краха (`SEC-PW-004`, D-4) | `V:bench` (фрагментация), `V:integ` |
| `e0`/`e2` + `zone_write_epoch` + `fence(SeqCst)` | 2 загрузки `published_txn`, 2 — guard, барьер на пин (пин — на батч) | Без `e0`/`c1c2` — use-after-reuse (F-1); без барьера — на ARM64 (SEC-PW-007) | `V:loom`, `V:bench`, `V:ci` (ARM64) |
| Ring 4 версии + chain | 3 коммита быстрого пути; далее 1 страница chain на версию | 512 Б/зона; chain — safety valve | `V:integ` (PW-AT-1: AXFR+commit), `V:bench`, `SEC-PW-015` |
| CAS-аллокатор экстентами | Контеншен на `next_page` | `ALLOC_EXTENT_PAGES=16` + локальный кэш 64 снижают RMW-частоту | `V:bench` (`pw_alloc_extents_total`) |

**Правило:** любая новая мера, добавляющая работу на путь запроса, обязана иметь `V:bench`-гейт с порогом регрессии (например, ≤ 3 % p99). Иначе мера переносится off-path.

---

## 11. Альтернативы и почему отклонены

| Альтернатива | Почему отклонена |
|---|---|
| `RwLock` на всю зону | Сериализует чтения, убивает заявленную производительность; MVCC-снапшоты выигрывают. |
| Отдельный файл на зону | Усложняет атомарность и инкрементальные правки; требование — единый mmap. |
| CRC только на весь файл | Не локализует повреждение; проверка всего файла на запрос недопустима. |
| Открытый резолвер «как у всех» | Amplification/репутация; закрываем по умолчанию. |
| DNSSEC validation «опционально» | Без неё cache poisoning не блокируется надёжно; включаем по умолчанию в рекурсивном режиме. |
| Собственный DNS-парсер с `unsafe` для скорости | Риск UB/RCE; safe Rust + fuzz достаточны, горячие места оптимизируем позже с бенчмарками. |
| `openssl`/`native-tls` | Тяжёлая C-зависимость, сложнее аудит; `rustls` + `aws-lc-rs`. |
| Хранить токены plaintext | Утечка БД = полный захват; храним хеш. |
| Глобальный freelist в параллельном режиме | Освобождение страницы одной зоной публикуется независимо от durability её корня → double allocation после краха; глобальная мутация сериализует писателей (D-4). Заменён per-zone пулами + donation (SEC-PW-004). |
| Копии A/B головы в одном секторе/блоке | Torn-запись сектора уничтожает обе версии, CRC-пара не даёт избыточности (F-2). Копии разнесены (SEC-PW-001). |
| Один `fdatasync` на данные и корни | fsync не упорядочивает диапазоны: при крахе корень может долететь раньше данных (D-1). Заменён двухфазным fsync (SEC-PW-005). |
| Per-zone файлы ради изоляции | Противоречит «один файл»; тысячи `mmap`/`fsync`; нет атомарности даже внутри зоны при IXFR-out. Для security-изоляции писателей — только отдельный ADR (PW-L2), не v1. |
| Per-zone `txn` вместо глобального `epoch` | `page.txn ≤ version` перестаёт ловить кросс-зонный ABA: страница зоны B с меньшим `txn` проходит проверку снапшота зоны A (SEC-PW-006). |
| N процессов-писателей в v2 | In-process lease и отсутствие file-side seqlock/истории голов делают пин/публикацию недоказуемыми; v2 сохраняет `LOCK_EX`, мультипроцессность — v3 с отдельным ADR (SEC-PW-009, PW-L6). |

---

## 12. Последствия

**Положительные:**
- Повреждённый/враждебный файл зон не роняет процесс и не отдаёт мусор как валидные данные.
- Cache poisoning требует обхода DNSSEC + рандомизации + bailiwick одновременно.
- Amplification закрыт по умолчанию (закрытая рекурсия + RRL + cookies).
- Ключи и токены не утекают через логи/API/дампы.
- Каждое требование проверяемо в CI.

**Отрицательные / издержки:**
- Дополнительная сложность формата (COW, `txnid`, checksums, reader table) в `pulse-zonefile`.
- Feature-флаги для legacy (SHA-1/MD5) требуют дисциплины, чтобы не включились в проде.
- Ограничения лимитов могут потребовать тюнинга под реальные зоны (см. открытые вопросы).
- 0x20 и rebinding-политика — источники совместимостных компромиссов.

---

## 13. Чек-листы приёмки безопасности по milestone

> Схема milestone зафиксирована: M0 — фундамент, M1 — `pulse-zonefile`, M2 — `pulse-dns`, M3 — `pulsed`, M4 — `pulseresolved`, M5 — DNSSEC-интеграция + DNSCrypt, M6 — DoT/DoH, observability, нагрузка, финальная приёмка.

### M0 — Фундамент, ADR, спецификации

- [ ] Утверждены `threat-model.md`, `ADR-0004`, `crypto-inventory.md`; ID требований и метки проверки зафиксированы.
- [ ] CI-скелет: `cargo-audit`, `cargo-deny`, secret-scan (`SEC-SC-001`, `SEC-SC-003`).
- [ ] Политика `unsafe` и структура крейтов (`SEC-SC-004`); единый крипто-бэкенд `aws-lc-rs` (`SEC-CR-001`).
- [ ] Sanity-лимиты (§2.2) зафиксированы как дефолты; открытые вопросы вынесены пользователю.

### M1 — `pulse-zonefile`: формат v1 + прототип writer/reader

- [ ] SEC-ZF-001..006 реализованы; граничные/overflow-тесты зелёные (`V:unit`).
- [ ] SEC-ZF-007, SEC-ZF-008, SEC-ZF-015: crash-recovery, частичная запись и torn-meta (`V:integ`, `V:prop`).
- [ ] SEC-ZF-009: внешний `truncate` → fail-stop; второй writer → `Busy`; writer и reader одновременно (в M1 — intra-process; межпроцессный доступ — M3).
- [ ] SEC-ZF-010: symlink/wrong-owner/group-writable → отказ (`V:integ`).
- [ ] SEC-ZF-011: порча/усечение существующего файла → `TruncatedFile`/`Corrupt`, без `ftruncate`; `ftruncate` только для нового файла (`V:integ`).
- [ ] SEC-ZF-012: четыре fuzz-таргета (включая `reader_table_state`), ночной прогон без падений/OOM (`V:fuzz`).
- [ ] SEC-ZF-013: Miri на parse/serialize зелёный (`V:miri`).
- [ ] SEC-ZF-014: `forbid(unsafe_code)` в доменных крейтах; data/дерево `PROT_READ`, writable только reader table (границы/выравнивание/размер), негативный тест записи в data-регион; SAFETY-аудит (`V:lint`, `V:integ`, `V:manual`).
- [ ] **SEC-PW-001..008, 010, 012, 015 (параллельная запись, M1 — один процесс, N потоков):** два fsync (`SEC-PW-005`), курсор в памяти + `ALLOC_RECORD` A/B + барьер + `max(...)`/`reserve_cursor := DP` в recovery (`SEC-PW-003`), `RootEntry` ring 4×2 с A/B в разных страницах (`SEC-PW-001`), глобальный `txn` в `PageHeader.txn` + `owner_zone` (`SEC-PW-006`), per-zone buckets + donation с порядком «durable drop → free publish» и связыванием пула (`SEC-PW-004`), GC с резервами (`SEC-PW-008`), file-fatal vs zone-fatal и recovery под `LOCK_EX` (`SEC-PW-010`), инварианты `PW-I1..PW-I14` (`SEC-PW-012`), chain при долгом AXFR (`SEC-PW-015`, C-10, PW-AT-1), `ZoneDegraded`/RAII (C-8, PW-AT-3), `ceiling=∞` (C-9, PW-AT-2) (`V:crash`, `V:loom`, `V:prop`, `V:unit`, `V:integ`; приёмочные **PW-AT-1…PW-AT-8**).
- [ ] **Приёмка M1:** C-1…C-10 и PW-AT-1…PW-AT-8 зелёные — M1 принимается. **M1 не блокируется** F-8…F-11 (закрыты нормативно) и F-7 (эксплуатация).
- [ ] SEC-PW-007 (пин): `e0 = published_txn` до головы; пин `root.version`; `fence(SeqCst)`; `c1==c2` чётный, `e2==e0`, `root2.version==root.version`; `EpochGuard` RAII; `ZoneDegraded` за ≤ 8 попыток; loom-модели `pin_capture`/`pin_vs_reclaim`/`epoch_min`/`epoch_stuck`; PW-AT-3/PW-AT-7 (`V:loom`, `V:unit`, `V:crash`).
- [ ] SEC-PW-014: только `x86_64`/`aarch64`, `target_has_atomic=64`, ARM64 CI-прогон, запрет `Relaxed` для публикаций (`V:ci`, `V:lint`).
- [ ] `V:bench`: чтение зоны не регрессировало > 3 % p99 против baseline.

### M2 — `pulse-dns`: wire-format, RR-типы, сжатие, EDNS0, TSIG, DNSSEC-примитивы

- [ ] SEC-DNS-001..005: границы (255/63/512/1232/4096/65535), compression loops с лимитом 128, huge RRset, усечение (`V:unit`, `V:fuzz`).
- [ ] SEC-DNS-007: EDNS-политика, BADVERS, неизвестные опции, ECS off (`V:unit`, `V:cfg`).
- [ ] SEC-CR-008: TSIG — KAT (HMAC-SHA256/512), replay, clock skew (`V:unit`).
- [ ] SEC-CR-002 (примитивы), SEC-CR-004, SEC-CR-005: матрица алгоритмов KAT, генерация/подпись/verify, constant-time (`V:unit`, `V:manual`).
- [ ] Общий wire-парсер покрыт fuzz (`dns_wire_parse`) и property-тестами (`V:fuzz`, `V:prop`).
- [ ] `V:bench`: парсер/сериализатор в бюджете.

### M3 — `pulsed`: authoritative, UDP/TCP, primary/secondary, AXFR/IXFR/NOTIFY, REST CRUD

- [ ] SEC-DNS-006: RRL + cookies + ANY-минимизация; reflection-симуляция не амплифицирует (`V:integ`).
- [ ] SEC-DNS-008: slowloris-симуляция не исчерпывает ресурсы (`V:integ`).
- [ ] SEC-DNS-009..011: закрытая рекурсия, UDP-rate-limit, эхо QNAME (`V:integ`, `V:unit`).
- [ ] SEC-REP-001..005: ACL+TSIG-матрица, NOTIFY, валидация трансфера, лимиты, mTLS (`V:integ`).
- [ ] SEC-API-001,002,004..009,011,012,014; SEC-CR-010: bind localhost, scopes/RBAC, токены (256-bit, хеш), rate limit 100 rps/token, лимиты тела 16 MiB, аудит, Idempotency-Key, валидация, ошибки, CORS, матрица 401/403/404 (§5.1) (`V:integ`, `V:unit`).
- [ ] SEC-API-003, SEC-CR-009 (baseline): TLS для off-loopback REST, mTLS для репликации (`V:integ`).
- [ ] SEC-API-010 (начало): валидация операторских сетевых целей (forwarders/feeds: `https`+allowlist, 64 MiB, no cross-host redirects) (`V:unit`, `V:integ`).
- [ ] SEC-OPS-001, SEC-OPS-002: запуск без root, `systemd-analyze security` в гейте (`V:ci`).
- [ ] **SEC-PW-009, 011, 013 (параллельная запись, M3 — один процесс, N потоков):** `LOCK_EX`/`Busy` для второго процесса (`SEC-PW-009`), API/домен не опираются на межзонную атомарность, `SnapshotId` + per-zone версии (`SEC-PW-011`), DoS-лимиты и алерты `pw_*` (`SEC-PW-013`) (`V:integ`, `V:bench`, `V:manual`).
- [ ] **M3 multi-process gate (не входит в M1):** N процессов-писателей не включаются без общих `zone_write_epoch`/`published_txn`/`MP`/`RV`/`D_z`/курсора, `LOCK_SH`+byte-range lease, generation-recovery и fencing (отдельный ADR, `SEC-PW-009`, PW-L6, F-5).
- [ ] `pulse-runtime`/io_uring: `unsafe` только в привязке, ASan/TSan, bounds/отмена/таймауты (`V:ci`, `V:integ`).
- [ ] `V:bench`: QPS/латентность в бюджете с включёнными RRL/cookies; калибровка §2.2.

### M4 — `pulseresolved`: рекурсивный резолвер, кеш, ad-block, overrides

- [ ] SEC-RES-001, SEC-RES-003: CSPRNG ID/порт, строгий матчинг (`V:unit`, `V:integ`).
- [ ] SEC-RES-002: 0x20 включена по умолчанию, отключаемая настройкой (`V:integ`, `V:cfg`).
- [ ] SEC-RES-004: bailiwick (`V:unit`, `V:prop`).
- [ ] SEC-RES-006 (без DNSSEC-части): бюджеты глубины/цепочек/NS, NXNSAttack (`V:integ`).
- [ ] SEC-RES-007, SEC-RES-008: negative caching, защита кеша (`V:unit`).
- [ ] SEC-RES-009: NXNSAttack-симуляция ограничена (`V:integ`).
- [ ] SEC-RES-011, SEC-RES-012: upstream-политика, фрагментация (`V:unit`, `V:cfg`).
- [ ] **Security gate:** `pulseresolved` не разворачивается в недоверенной сети до M5 (DNSSEC-валидация, `SEC-RES-005`); startup-warning при выключенной валидации, README-раздел (`SEC-RES-013`). До M5 R-02 считается **открытым**; допустим только режим доверенной сети/ACL.
- [ ] SEC-RES-010: rebinding **не реализуется** (RR-7), но есть предупреждение в конфиг/лог при рекурсии на недоверенном интерфейсе и пункт в документации (`V:cfg`, `V:manual`).
- [ ] Blocklist/overrides: лимиты фида и SSRF-проверка источника (`SEC-API-005`, `SEC-API-010`) (`V:integ`).
- [ ] `V:bench`: resolver QPS/латентность в бюджете.

### M5 — DNSSEC sign+validate (интеграция), затем DNSCrypt

- [ ] SEC-CR-002: полная матрица; RSA/SHA-256 обязателен; SHA-1-подпись невозможна (`V:unit`, `V:ci`).
- [ ] SEC-CR-003: права ключей, key-only-in-memory, zeroize при выгрузке, аудит операций с ключами (`V:integ`, `V:lint`).
- [ ] SEC-CR-004, SEC-CR-005: генерация/подпись/сравнение через vetted-крипто (`V:unit`, `V:manual`).
- [ ] SEC-CR-006: полный сценарий ротации без «дыры» в подписи (`V:integ`).
- [ ] SEC-CR-007: trust anchors и обновление (`V:integ`).
- [ ] SEC-RES-005: DNSSEC secure/insecure/bogus, SERVFAIL на bogus (`V:integ`).
- [ ] SEC-RES-006 (DNSSEC-часть): KeyTrap-бюджеты (`V:integ`, `V:bench`).
- [ ] Интероп: зоны проходят `ldns-verify-zone`/`delv` (`V:integ`).
- [ ] DNSCrypt: до реализации — расширение `crypto-inventory.md` и отдельный ADR (алгоритмы/ключи); без этого пункт не закрывается.

### M6 — DoT/DoH (DoQ опц.), observability, нагрузочные тесты, финальная приёмка

- [ ] SEC-CR-009 (полная): TLS 1.3/1.2, AEAD-сьюты, DoT/DoH-листенеры; SEC-API-003 mTLS (`V:unit`, `V:integ`).
- [ ] SEC-API-013: экспорт ключей закрыт по умолчанию (`V:integ`).
- [ ] SEC-OPS-003..008: секреты, приватность логов (client IP/qname не пишутся), health, fail-closed, часы, подпись релизов (`V:cfg`, `V:integ`, `V:ci`).
- [ ] SEC-SC-005..007: reproducible builds, SBOM, ASan/TSan, review крейтов (`V:ci`).
- [ ] Нагрузочные тесты: High/Critical риски закрыты мерами или подписанным остаточным риском; §2.2 откалиброван.
- [ ] Финальная приёмка: все чек-листы M1–M6 и сквозные закрыты артефактами.

### Сквозные (все milestone)

- [ ] SEC-SC-001..007: `cargo-audit`/`cargo-deny` зелёные, lockfile, лицензии, SBOM (`V:ci`).
- [ ] SEC-OPS-003..008: секреты, логи, health, fail-closed, часы, подпись релизов.

---

## 14. Трассировка риск → требование

> **Источник истины по идентификаторам `SEC-*` — этот ADR.** Любые маппинги требований в других документах (спецификации, чек-листы) ссылаются на ADR-0004; при расхождении нумерации правит владелец соответствующего документа.

| Риск | Требования |
|---|---|
| R-01 | SEC-DNS-006, SEC-DNS-009, SEC-RES-012 |
| R-02 | SEC-RES-001..005, SEC-RES-008, SEC-RES-013 |
| R-03 | SEC-ZF-001..004, SEC-ZF-012, SEC-ZF-013, SEC-ZF-014 |
| R-04 | SEC-ZF-009, SEC-ZF-010 |
| R-05 | SEC-CR-003, SEC-API-013 |
| R-06 | SEC-API-002, SEC-API-004 |
| R-07 | SEC-API-010 |
| R-08 | SEC-REP-001, SEC-REP-004 |
| R-09 | SEC-RES-010 (warning/docs) |
| R-10 | SEC-DNS-002, SEC-DNS-004, SEC-ZF-006 |
| R-11 | SEC-DNS-003, SEC-RES-006 |
| R-12 | SEC-DNS-008 |
| R-13 | SEC-REP-003, SEC-REP-005 |
| R-14 | SEC-RES-006, SEC-CR-002 |
| R-15 | SEC-RES-009 |
| R-16 | SEC-SC-001..007 |
| R-17 | SEC-ZF-010, SEC-CR-003, SEC-OPS-006 |
| R-18 | SEC-API-007 |
| R-19 | SEC-API-008 |
| R-20 | SEC-API-005, SEC-API-010 |
| R-21 | SEC-DNS-001, SEC-RES-012 |
| R-22 | SEC-DNS-006, SEC-DNS-008 |
| R-23 | SEC-PW-001..007, SEC-PW-010, SEC-PW-012, SEC-PW-014 |
| R-24 | SEC-PW-003, SEC-PW-004, SEC-PW-008, SEC-PW-010, SEC-PW-012 |
| R-25 | SEC-PW-002, SEC-PW-007, SEC-PW-013 |

---

## 15. Открытые вопросы

**Все вопросы закрыты Оркестратором:** оба бинарника, рекурсия закрыта по умолчанию; DNSSEC — RSA/SHA-256 обязателен, ECDSA P-256 дефолт, Ed25519 рекомендуется, Ed448 optional; HSM — не в v1 (roadmap); 0x20 — включена по умолчанию, отключаемая; приватность — client IP/qname не логируются по умолчанию; rebinding — вне v1, но с warning/docs (RR-7); схема M0–M6 зафиксирована; **multi-tenancy — нет (single-tenant)**; blocklist — `https`+allowlist+64 MiB+no redirects, подпись — roadmap; **кластер — нет (single-host, только штатная DNS-репликация)**; калибровка §2.2 — в M3 по нагрузочным тестам; hmac-md5 — только per-key, deprecated, удаление v1.1; trust anchors — встроенный IANA KSK, обновление с релизами, CI-проверка, RFC 5011 в v1.1; TLS-корни — `webpki-roots` по умолчанию, опция системных; DNSCrypt — отдельный ADR + расширение crypto-inventory в M5; M4 gate — `SEC-RES-013`.

**Открытых вопросов по базовому режиму (один писатель) нет.**

**Открытые вопросы параллельного режима** (§1.3, ADR-0006 §13):

1. **Разрядность `version` в пине:** 32 бита (v2) с `NEEDS_FSCK` при `txn > 2³¹` vs 64 бита/5×16. SEC-PW-007.
2. **`MAX_PINNED_ZONES=64`** — подтвердить профилем `zones()`/AXFR-каталога. SEC-PW-007/013.
3. **`MAX_LEAK_RATIO`** (1 %) и абсолютный минимум в страницах для малых файлов. SEC-PW-013.
4. **`freeze()` в v2.0** — минимальный maintenance-вариант (все lease/ожидание), `EpochPinned`/`Busy`; только read-at-T. SEC-PW-011.
5. **Chain-GC-тюнинг** — `MAX_ROOT_CHAIN_HOPS=4096`, `CHAIN_GC_BATCH`, порог `pw_root_chain_depth`; калибровка на M3. SEC-PW-015.
6. **`domain-model` §5.1/§5.2** — `Snapshot{snapshot_seq}`/`ZoneSnapshot` (последняя; `NoZoneVersion` только «зоны нет») и `freeze()`; владелец — Архитектор ПО.
7. **M3-ADR (F-5)** — единственный блокер (M3): общие guard/epoch/MP/RV/`D_z`/курсор, shared head index, `LOCK_SH`+byte-range lease, generation-recovery, `term`+fencing. До него `LOCK_EX` и N потоков.
