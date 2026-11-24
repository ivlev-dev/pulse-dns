# ADR-0006: Безопасность параллельной записи в один mmap-файл зон

- **Статус:** Proposed — ревью безопасности ADR-0005 и `parallel-writes-v2`; F-1…F-4 проверены, F-6/F-8…F-11 закрыты нормативно (C-10, C-9, C-8, C-6, C-5, C-2). **M1 принимается по C-1…C-10 + PW-AT-1…PW-AT-8; блокер — только M3 (F-5)**
- **Дата:** 2026-11-24
- **Роль-владелец:** Специалист по безопасности (параллелизм, crash-consistency, memory model)
- **Область:** один файл зон; параллельная запись по зонам (один писатель на зону, разные зоны параллельно); bump-аллокация; per-zone ring записей корня; epoch-пины читателей; GC и per-zone пулы; двухфазный group commit
- **Ревьюируемые документы:** [ADR-0005](0005-parallel-writers.md) (актуальная редакция), [`parallel-writes-v2.md`](../spec/parallel-writes-v2.md) (формат 2.0), `zonefile-v1.md` 1.5.3
- **Связанные:** [ADR-0004](0004-security-model.md) §1.3 (`SEC-PW-*` — источник истины по ID), [`threat-model.md`](../spec/threat-model.md)
- **Вне области:** B+tree/ключи/overflow (v1 без изменений), WAL, межпроцессная запись (M3 — отдельный ADR), онлайн-рост `map_size`

---

## 0. Резюме для Оркестратора

Направление **безопасно**. F-1…F-4 закрыты в v2; F-6, F-8…F-11 и коллизия page 3 **закрыты решениями Оркестратора** и переведены в нормативные требования с приёмочными тестами (PW-AT-1…PW-AT-8). Открытых дефектов, блокирующих **M1**, нет. Единственный блокер — **M3 (N процессов-писателей)**: без отдельного ADR (F-5) он недоказуем на текущих in-memory структурах. F-7 (метрики утечек) — эксплуатационное требование, не блокер.

### 0.1. Закрытые находки (проверено)

| Находка | Как закрыта | Остаточное требование |
|---|---|---|
| **F-1** пин без «пред-значения» → use-after-reuse | v2 §5.3: `e0` до головы; пин; `fence(SeqCst)`; `c1==c2` (чётный); `e2==e0`; `root2.version==root.version` | loom-модель; тест «убрать `e0`/`c1c2` → падает» (PW-AT-3-родственный); ARM64 CI |
| **F-2** копии A/B в одном секторе | v2 §1.1/1.2: A/B — разные 4 KiB страницы для `RootEntry`, `ALLOC_RECORD`, `LayoutHead` | PW-AT-6 (page 3), PW-AT-7 (torn A/B) |
| **F-3** аллокация после снимка фронтира | writer аллоцирует до `CommitRequest`; корень только при `DP > max_alloc ∧ DT ≥ V`; recovery `DP = max(record, cursor, roots, pools)` | PW-AT-8 (инъекция в окне) |
| **F-4** три fsync | ровно два: данные+`ALLOC_RECORD` → fsync → корни → fsync | `V:bench` |
| Writable-курсор (второй writable-регион) | Отклонён (D-C): курсор в памяти; SEC-ZF-014 сохраняется | M3 — отдельный ADR |
| Мультипроцессная запись в M1 | Отклонена: M1 — один процесс, `LOCK_EX`, `Busy` сохраняется | M3 (F-5) |

### 0.2. Нормативные решения по F-6, F-8…F-11 (закрыто Оркестратором)

| # | Решение | Точный критерий | Тест |
|---|---|---|---|
| **F-8** | **Chain — safety valve, блокировки записи нет.** При исчерпании ring (все 4 группы `≥ MP(z)` или `≥ D_z`) писатель **не** возвращает `ZoneWriterStalled`, а добавляет `PAGE_TYPE_ROOT_CHAIN = 11`: одна 64-Б запись на страницу в `+32`, `prev_record` → предыдущая версия; страница входит в **фазу 1** (durable до корня). `select(z, ceiling)`: max-valid в ring ≤ ceiling, иначе обход chain до первой `≤ ceiling`, лимит `MAX_ROOT_CHAIN_HOPS = 4096` (превышение/цикл → `Corrupt{zone}`). Chain-страницы GC-ятся при `version < MP(z) ∧ version < D_z`. Коммит **никогда** не блокируется читателем | AXFR (≥ 5 с) + 10 коммитов/с в ту же зону: 0 `ZoneWriterStalled`, 0 `Corrupt`, `fsck` зелёный; `pw_root_chain_depth` растёт и падает после AXFR | **PW-AT-1** |
| **F-9** | **`snapshot_seq` — не ceiling.** `Snapshot { snapshot_seq, catalog_version }` — каталог/аудит/порядок; `ZoneSnapshot` всегда берёт **последнюю** версию зоны на момент взятия (`ceiling = ∞`). Зона, изменённая после `Reader::snapshot()`, **читается** (новее), а не отвергается; `NoZoneVersion` — только «зоны нет/tombstone». Чтение-на-T — только `freeze()` + `EPOCH`-пин, `fsck --at-epoch`. `snapshot_seq` можно отдавать в `X-Commit-Txn`, но не использовать для отказа | `Reader::snapshot()` → 100 коммитов в **другие** зоны (и ≥ 10 в ту же) → `zone_snapshot(z)` успешен, версия ≥ исходной, без `NoZoneVersion`; монотонность per-zone сохранена | **PW-AT-2** |
| **F-11** | **RAII-guard + `ZoneDegraded`.** `zone_write_epoch[z]` меняется только через `EpochGuard`, который в `Drop` возвращает чётность (успех, `Abort`, `Io`, `panic=unwind`). Если читатель после `PIN_ATTEMPTS = 8` видит нечётный/нестабильный guard → `ZoneDegraded { zone, epoch }` + зона `NEEDS_FSCK` (read-only по зоне), метрика, **без бесконечного retry**. Другие зоны работают | Инъекция `panic` между odd/even (writer и GC) → guard чётный после `catch_unwind`/`Drop`; при намеренно «застрявшем» guard читатель получает `ZoneDegraded` за ≤ 8 попыток; `fsck` снимает флаг | **PW-AT-3** |
| **F-10** | **Bucket в фазе 1 + `free_head` в `RootEntry V`.** Bucket `dropped(V)` пишется в **той же фазе 1**, что и данные коммита `V`; `RootEntry V.free_head` указывает на него. Порядок: данные+bucket durable → корень durable → `D_z := V`. Переиспользование всё равно гейтится `F < D_z` (т.е. не раньше `V+1`). Отдельный `PoolHead` не нужен. Крах между фазой 1 и корнем → bucket durable, но не связан → **утечка**, не double-free; `fsck` возвращает | Крах в каждой точке между durable bucket и публикацией `RootEntry V`: recovery либо видит `free_head`, либо страницы недостижимы (leak); property: ни одна страница не в двух местах; 2-групповой задержки нет | **PW-AT-4** |
| **F-6** | **File-fatal-список.** Признаки ниже — **всегда** `write_locked` + read-only до `fsck`, независимо от `strict_corruption`: `head.page_limit_at_commit > DP` после `max`-коррекции; пересечение множеств страниц зон; `owner_zone`/`version` чужой зоны при валидном CRC; битый/несовместимый `LayoutHead`/`ALLOC_RECORD`/каталог; регрессия `DP`/`DT`/`txn`. `strict_corruption = file` оставляет v1-поведение; `zone` **не** ослабляет file-fatal | Каждый признак по отдельности → read-only файла, `NEEDS_FSCK`, без записи; ни один не «деградирует только зону» | **PW-AT-5** |
| **page 3** | **Разнесена.** `LayoutHead` A/B — в двух разных страницах; writer registry переносится в data-регион; page 3 — резерв/выравнивание. `RootEntry`/`ALLOC_RECORD` — тоже в разных страницах | `fsck`/`open` отвергают LayoutHead, если A и B в одной странице или совпадают; layout-константы и golden v2 обновлены | **PW-AT-6** |

### 0.3. Что осталось

| # | Пробел | Блокирует | Требование |
|---|---|---|---|
| **F-5** | **M3: N процессов-писателей.** `zone_write_epoch`, `MP`, `RV`, `D_z`, `published_txn`, `heads[]` — в памяти процесса | **M3** (не M1) | Отдельный ADR: `zone_write_epoch`/`published_txn` в общий файл (или вывод из ring/`ALLOC_RECORD`), shared head index, общий durable-курсор/`txn`, generation-recovery, `LOCK_SH`+byte-range lease, `term`+fencing. До этого — `LOCK_EX` и N потоков |
| **F-7** | Учёт утечек/пулов: нет обязательного порога и метрик для `[DP, cursor)`, orphan-bucket, donation | нет (эксплуатация) | `pw_alloc_leaked_pages_estimate`, `pw_orphan_bucket_pages`, `MAX_LEAK_RATIO`, `fsck` возвращает; алерт |

Плюс ограничения, которые не «чинятся»: межзонная атомарность отсутствует (PW-L1; `freeze()`), изоляция зон — не security (PW-L2).

**Вердикт:** **M1 может быть принят** при выполнении условий C-1…C-10 и зелёных тестах PW-AT-1…PW-AT-8. Блокеров M1 нет; **M3 блокирован** до ADR по F-5. F-7 — эксплуатационное, не приёмка.

---

## 1. Методология и обозначения

### 1.1. Идентификаторы

| Префикс | Значение | Где |
|---|---|---|
| `F-*` | находка ревью | §0 |
| `PW-I*` | формальный инвариант | §5 |
| `PW-C*` | точка отказа | §7 |
| `TW-*` | угроза | §3.3 |
| `SEC-PW-*` | требование безопасности | ADR-0004 §1.3 |
| `PW-L*` | принятое ограничение | §11 |

Существующие `SEC-ZF-*`, `A-1..A-12` (0005), `D-A..D-D` (v2) не переименовываются.

### 1.2. Метки проверки

Дополняют `threat-model.md` §1.3:

| Метка | Значение |
|---|---|
| `V:crash` | инъекция краха: `kill -9`, `dm-log-writes` (power-loss replay), `dm-flakey` (I/O error), детерминированный failpoint-стенд |
| `V:loom` | модель памяти для публикации/пина/GC (обязательна; TSan — дополнительно) |

### 1.3. Допущения

1. Хост один, ФС локальная (не NFS/SMB/FUSE) — `threat-model.md` §9; когерентность `MAP_SHARED` + `pwrite` на сетевых ФС не гарантируется.
2. **M1: ровно один процесс-писатель** (`flock(LOCK_EX)`), N потоков-writer'ов, один координатор group commit, один GC. Межпроцессная запись — M3, отдельный ADR (F-5).
3. Платформы: `x86_64` и `aarch64` Linux; 32-битные цели исключены (`AtomicU64` не lock-free).
4. `pwrite`/mmap-когерентность — допущение ОС, не модели Rust; фиксируется в `parallel-writes-v2`.
5. Атомарность записи страницы/сектора не предполагается: валидность — CRC + версия; сбой — произвольное подмножество байт. Отсюда PW-I11 (геометрия копий).

---

## 2. Сверка: что вытеснено и что потеряно

| Механизм 1.5.3 | Замена (0005 + v2) | Что теряем | Статус |
|---|---|---|---|
| Единая meta A/B — точка публикации (I-3, I-12, W-1) | `LayoutHead` A/B + `ALLOC_RECORD` A/B + per-zone `RootEntry` ring (4 версии × 2 копии) | Атомарность между зонами (PW-L1); `recovered_unsynced`/`torn` per-zone | OK; F-2 закрыт для всех A/B (v2 §1.1/1.2) |
| Глобальный `txnid` (I-5) | `txn` — глобально монотонный CAS-блок (в памяти), `version(Z) = txn`; `PageHeader.txn = txn` | Ничего: `page.txn ≤ version` — корректная защита от ABA | OK; `owner_zone` — defense-in-depth, не замена глобальному `txn` |
| Глобальный freelist COW (I-4, I-6, W-21) | Per-zone bucket (COW) + `free_ring` в памяти + donation | Немедленное перераспределение; файл = сумма пиков зон (PW-L3) | OK; bucket в фазе 1, `free_head` в `RootEntry` (PW-I13, PW-AT-4) |
| `durable_txn`/`reclaim_txn` (§14) | `D_z`, `DP`, `DT`, `MP(z)`, `RV_z` | Одно число → вектор; `Flush`/`Memory` деградируют неравномерно (PW-L4) | OK; `MP/RV` — память (M1) → F-5 для M3 |
| `oldest_reader_txn` на каждый коммит (§6.4) | `MP(z)` инкрементально (`fetch_min`) + GC-подъём под `zone_write_epoch` | Память слота 128 Б; EPOCH-пин грубее ZONE-пина (PW-L5) | OK; доказать loom (F-1) |
| Эксклюзивность `flock(LOCK_EX)` (SEC-ZF-009) | **Сохраняется в M1**; N потоков, lease in-memory | Мультипроцессность — M3 | OK для M1; M3 — F-5 |
| Каждая meta самодостаточна (I-12) | `RootEntry` самодостаточен; `LayoutHead`/`ALLOC_RECORD`/каталог — глобальные объекты | Создание зоны не атомарно с содержимым (PW-L7); порча глобального объекта — file-fatal | OK + F-6 |
| `Snapshot::txnid()` — одно `u64` | `Snapshot{snapshot_seq, catalog_version}` + `ZoneSnapshot.version`; `freeze()` | Нельзя сравнить состояние одним числом (PW-L8) | OK; `ceiling=∞`, чтение-на-T — `freeze()` (PW-I12, PW-AT-2) |
| `sync()` — липкий чекпойнт | Глобальный барьер; липкий `Sync` — свойство файла | Нельзя синхронизировать одну зону (PW-L9) | OK |
| `NoSpace`/`MapFull` — глобальные | `NoSpace{zone}` + `MapFull{global}`; квоты | Две ошибки пространства (PW-L10) | OK |
| `compact_zone` (§13.8) | Обычный коммит зоны; не блокирует другие (PR-3) | Не собирает чужие дыры; глобальная дефрагментация — donation/offline | OK |

**Что обязано сохраниться:**

1. **`page.txn ≤ snapshot.version`** — реальная защита от ABA; требует глобально монотонного `txn` (A-3).
2. **«Живой читатель не вытесняется никогда»** (SEC-ZF-007). Цена — chain-страницы при backlog читателя; коммит не блокируется (PW-I2b).
3. **Fail-closed на сомнении**, с границей zone-fatal/file-fatal (F-6).

---

## 3. Модель угроз

### 3.1. Активы и границы (дельта к `threat-model.md`)

| Актив | Что добавляется |
|---|---|
| A-2 | Управляющие структуры: `LayoutHead`, `ALLOC_RECORD`, `RootEntry` ring, `free_head`/bucket'ы, `zone_write_epoch`. Их порча опаснее порчи данных: даёт выдачу живых страниц без CRC-сигнала |
| A-2a | Доверие между потоками-писателями и координатором |
| A-8 | Застрявший пин → рост chain/файла, fsync-потолок координатора |

### 3.2. Нарушители (дельта к `threat-model.md` §3)

| ID | Нарушитель | Возможности | В модели? |
|---|---|---|---|
| T-4 | Локальный пользователь | Подмена/усечение файла → `O_NOFOLLOW`/`0600`/`fstat` (SEC-ZF-010) | да |
| T-9 | **Багованный писатель** — поток (M1) или процесс (M3) с правом записи | Произвольные страницы/головы, завышение курсора, освобождение чужих страниц, вечный пин | частично: от аварии — да; от злонамеренного — нет (PW-L2) |
| T-5 | Вредоносный/повреждённый файл | Включая «файл от другой версии» → recovery валидирует всё как недоверенный ввод | да |
| T-10 | Планировщик/ОС: задержка, OOM, смерть координатора/GC, паника потока | Потеря неподтверждённой пачки, застрявший `zone_write_epoch`, задержка GC | да (fail-closed) |

### 3.3. Реестр угроз `TW-*`

| ID | Угроза | Вектор | L | I | R | Мера |
|---|---|---|---|---|---|---|
| TW-1 | Порча чужой зоны | Запись в страницу другой зоны / переиспользование `PageId` | 2 | 5 | **10** | Глобальный `PageId`/`txn`, `owner_zone`, `page_limit_at_commit`, `fsck` дизъюнктность |
| TW-2 | Гонка публикации корня | Читатель получает версию, чьи страницы уже переиспользованы; частично записанная запись | 4 | 4 | **16** | CRC + ring 4×2 + `zone_write_epoch` + пин `e0/e2/c1/c2` |
| TW-3 | Torn root | Частичная запись 64 Б / сектора | 3 | 3 | 9 | CRC каждой копии; A/B в разных 4 KiB страницах (v2 §1.1) |
| TW-4 | Потеря аллокации (leak) | Краш между резервированием и `ALLOC_RECORD`; аборт | 5 | 1 | 5 | Утечка измеряется; `[DP, cursor)` не выдаётся; `fsck` возвращает |
| TW-5 | Дублирование аллокации | `DP` ниже живой головы; курсор восстановлен низко | 2 | 5 | **10** | `DP = max(record, cursor, roots, pools)`; публикация только при `DP > max_alloc` |
| TW-6 | Двойное освобождение | Пул опубликован до durable drop; donation раньше drop | 2 | 5 | **10** | `is_reclaimable`; порядок §6.5; детект `drop_txn ≥ D_z` → `NEEDS_FSCK` |
| TW-7 | Use-after-reuse читателем | Пин не виден GC/коммиту; ring перезаписан под читателем | 2 | 5 | **10** | `zone_write_epoch` + `fence(SeqCst)` + `e0/e2`; RAII от F-11 |
| TW-8 | Застрявший reader вызывает chain-рост | Долгий AXFR/снапшот; ring исчерпан | 4 | 3 | 12 | Chain как safety valve (PW-I2b); коммит не блокируется; `pw_root_chain_depth` алерт |
| TW-9 | Багованный/злонамеренный писатель | Подмена пулов/голов/курсора | 1 | 5 | 5 | `owner_zone`, `fsck`, квоты; security-изоляция — PW-L2 |
| TW-10 | Два координатора (M3) | Ложный таймаут, два процесса | 1 | 5 | 5 | M1: один процесс. M3: fencing/term + byte-range lease (F-5) |
| TW-11 | Два recovery (M3) | Параллельное восстановление | 1 | 5 | 5 | M1: `LOCK_EX`. M3: generation (F-5) |
| TW-12 | GC/fsync-шторм | Массовые удаления, donation-лавина | 3 | 3 | 9 | Бюджеты `MAX_GC_*`, пачки, backpressure |
| TW-13 | Фрагментация / исчерпание | Файл = сумма пиков зон | 4 | 3 | 12 | Donation, `compact_zone`, квоты, резерв GC |
| TW-14 | Кросс-зонный ABA по `txn` | Per-zone `txn` без глобального порядка | 2 | 4 | 8 | Глобальный `txn` в `PageHeader.txn`; `owner_zone`; `fsck` |
| TW-15 | Неверная граница durability | Один fsync на данные+корни | 3 | 5 | **15** | Два fsync (v2 §7.1), `PW-I5` |

TW-10/TW-11 в M1 не применимы (один процесс, один координатор, один recovery); остаются гейтом M3.

---

## 4. Обязательные уточнения к v2 (решения зафиксированы)

1. **Геометрия копий — для всех A/B.** `RootEntry`, `ALLOC_RECORD`, `LayoutHead` — копии в **разных** 4 KiB страницах (PW-I11); `LayoutHead` B не делит page 3 с writer registry; registry — в data-регионе, page 3 — резерв/выравнивание.
2. **Барьер аллокаций.** Writer резервирует до `CommitRequest`; между `CommitRequest` и `CommitAck` новых `reserve_cursor`/refill нет; корень — только при `DP > max_allocated_id` и `DT ≥ V`. Инъекция в окне — тест PW-AT-8.
3. **Пин — ровно формула v2 §5.3** (`e0`, `ceiling=∞`, пин, `fence(SeqCst)`, `c1==c2` чётный, `e2==e0`, `root2.version`). Любое упрощение — дефект.
4. **`zone_write_epoch` — RAII-`EpochGuard`.** Успех, `Abort`, `Io`, `panic=unwind` возвращают чётность. Читатель после 8 попыток → `ZoneDegraded` (PW-I14, PW-AT-3).
5. **`Snapshot` — не ceiling.** `Snapshot.snapshot_seq` — каталог/аудит/порядок; `ZoneSnapshot` — последняя версия на момент взятия (`ceiling = ∞`); чтение-на-T — только `freeze()` + `EPOCH`-пин / `fsck --at-epoch`. `NoZoneVersion` — только «зоны нет/tombstone» (PW-I12, PW-AT-2). Требует правки `domain-model` §5.1/§5.2.
6. **Ring + chain — обязательны.** При исчерпании ring коммит пишет `ROOT_CHAIN` (`PAGE_TYPE_ROOT_CHAIN = 11`), а не блокируется; `select` идёт ring → chain; `MAX_ROOT_CHAIN_HOPS = 4096`; chain-страницы GC-ятся при `version < MP(z) ∧ < D_z`; `zone_write_epoch` защищает и chain (PW-I2b, PW-AT-1).
7. **Bucket — в фазе 1, `free_head` — в `RootEntry V`.** `dropped(V)` пишется в том же коммите (данные+bucket до корня); переиспользование — `F < D_z`; отдельный `PoolHead` не нужен; крах между bucket и корнем = утечка, не double-free (PW-I13, PW-AT-4).
8. **File-fatal-список** §6.7 — обязателен при любом `strict_corruption` (PW-AT-5).
9. **Область процессов.** M1 — один процесс (`LOCK_EX`). Любая межпроцессная запись — отдельный ADR (F-5).
10. **Резервы и квоты** (`GC_RESERVE_PAGES`, `ZONE_PAGE_QUOTA_RATIO`, `MAX_LEAK_RATIO`, `MAX_GC_*`) — часть безопасности.
11. **page 3 и layout-константы** обновляются синхронно с v2; golden v2 перегенерируется; `fsck` сверяет регионы с `LayoutHead` (PW-AT-6).

## 5. Формальные инварианты

Инварианты 0005 `A-1..A-12` — базовые; ниже уточнения, проверяемые независимо. `V_z` — `version` головы; `P.txn` — `PageHeader.txn`; `MP(z)`; `D_z`; `RV_z`; `DP`/`DT`; `ring(z)`/`chain(z)`.

### 5.1. Видимость

**PW-I1 (per-ZoneSnapshot).** Глобальный `Snapshot` не обещает согласованного среза зон (PW-L1). Для `ZoneSnapshot`:
```
∀ r, z, P: reachable(z, V_z(r)) ⇒ P.txn ≤ V_z(r) ∧ (P.owner_zone ∈ {z, 0})
```
Проверка `page.txn ≤ snapshot.version` и `owner_zone` — на чтении вместе с CRC; нарушение → `Corrupt`. Глобальный срез — `freeze()`.

**PW-I1a (нет «полу-головы»).** `V_z` видна, только если её данные durable (v2 §7.1); writer не публикует голову, чьи страницы не прошли кодирование/CRC.

### 5.2. Переиспользование и пин

**PW-I2 (no reuse of live pages).** Страница зоны `z`, освобождённая в `F`, выдаётся снова только при:
```
F >= 2 ∧ F < D_z ∧ F <= RV_z ∧ F < current_version(z)
```
(`NEVER_PUBLISHED` — без гейта, A-10.)

**PW-I2a (pin/commit/GC race).** Если читатель успешно взял `pin(z)=V`, ни коммит `> V`, ни GC не приводят к рекламации страниц, освобождённых в `F ≤ V`. Обеспечивается: `e0` до головы, `fence(SeqCst)`, `c1==c2` (чётный) под `zone_write_epoch`, `e2==e0`, `root2.version==root.version`; GC/координатор читают пины `Acquire` **после** нечётного инкремента guard'а. Проверка — `V:loom` (`pin_capture`, `pin_vs_reclaim`, `epoch_min`).

**PW-I2b (ring + chain, без блокировки коммита).** При одном сбое записи версия не теряется: A/B в разных 4 KiB страницах (PW-I11); потеря обеих копий одной версии — откат ≤ 1 версии. Если все 4 группы ring `≥ MP(z)` или `≥ D_z`, коммит **не** блокируется и **не** перезаписывает нужную версию: он пишет `ROOT_CHAIN` (одна 64-Б запись на страницу, `prev_record` → предыдущая; страница входит в фазу 1). `select` идёт ring → chain до первой `version ≤ ceiling`; лимит `MAX_ROOT_CHAIN_HOPS = 4096`, превышение/цикл → `Corrupt{zone}`. Chain-страница удаляется GC при `version < MP(z) ∧ version < D_z`. `ZoneWriterStalled` при исправном chain **не возникает**; тихая перезапись запрещена.

### 5.3. Публикация, владение, монотонность

**PW-I3 (no double publish / double free).**
```
∀ P: |{ z : P reachable from selected head(z) }| ≤ 1
∀ P: P ∈ pool(z) ⇒ P не достижима ни из одной восстановимой головы
```
Первое — глобальный `PageId` + A-8 (+ `fsck`). Второе — `is_reclaimable` + порядок §6.5 + `owner_zone`.

**PW-I4 (фронтир).**
```
DP(t+1) ≥ DP(t) ∧ DT(t+1) ≥ DT(t)
∀ head: head.max_page_id < head.page_limit_at_commit ≤ DP
recovery: DP := max(ALLOC_RECORD.page_limit, cursor, max head.page_limit_at_commit,
                    max pool page_id + 1, page_data_first)
```
Понижение невозможно; ниже живой головы → `AllocWatermarkRegression` → `NEEDS_FSCK` + read-only.

**PW-I5 (данные раньше головы).** `head_durable(V) ⇒ data_durable(V)`: два fsync (v2 §7.1). Один fsync инвариант не даёт.

**PW-I6 (txn).**
```
txn(V+1) > txn(V); version(Z) = txn коммита
recovery: next_txn = max(DT, max head.version, max page.txn) + 1
```
`PageId` не переиспользуется (глобальный bump), поэтому ABA по `(PageId, txn)` невозможен; сканировать все страницы при open не требуется.

**PW-I7 (выбор головы).**
```
select(z, ceiling) = argmax{ version : owner_zone = z, crc_ok, version ≤ ceiling }
```
Tie-break — копия 0; невалидный CRC не выбирается и не чинится. Если в ring подходящей версии нет — обход chain (`prev_record`) до первой `≤ ceiling`; `ceiling = ∞` для обычного `ZoneSnapshot` (PW-I12).

**PW-I8 (нет потери версии).** См. PW-I2b; потеря обеих копий из-за общей атомарной единицы — дефект, не допустимый крах.

**PW-I9 (GC не дедлочится).** Резервы §4 п. 10; исчерпание резерва → `NeedsFsck`/алерт, не порча.

**PW-I10 (recovery единственен).** M1: при открытии под `LOCK_EX`, до публикации первого `ZoneRoot`; идемпотентен. M3: `LOCK_EX` + generation (F-5).

**PW-I11 (геометрия копий).** Для любой пары копий одной записи (`RootEntry`, `ALLOC_RECORD`, `LayoutHead`, будущие A/B): расстояние ≥ 4 KiB (минимум — разные 512-байтовые секторы); одна копия — один `pwrite` (или два элемента `pwritev` в **разных** страницах). Иначе CRC-пара не даёт избыточности.

**PW-I12 (семантика снапшота).** `Snapshot { snapshot_seq, catalog_version }` — каталог/аудит/порядок; он **не** является ceiling для зон. `ZoneSnapshot(z)` берёт **последнюю** версию на момент взятия (`ceiling = ∞`) и гарантирует per-zone монотонность: повторный `zone_snapshot` в том же `Snapshot` не даёт версию ниже уже виденной. `NoZoneVersion` — только «зоны нет/tombstone». Чтение-на-T — исключительно `freeze()` + `EPOCH`-пин / `fsck --at-epoch`; `snapshot_seq` можно публиковать (`X-Commit-Txn`), но нельзя использовать для отказа. Смешение «ceiling без истории» запрещено.

**PW-I13 (связывание пула с durable-головой).** Bucket `dropped(V)` записывается в **фазе 1** коммита `V` (вместе с данными); `RootEntry V.free_head` указывает на него; `RootEntry V` попадает на диск в фазе 2. Следствия:
```
bucket(V) durable ∧ RootEntry V durable ⇒ пул достижим
bucket(V) durable ∧ RootEntry V потерян ⇒ пул недостижим (утечка), не double-free
```
Переиспользование страниц пула — только при `F < D_z` (т.е. не раньше `V+1`). Отдельный `PoolHead` не требуется.

**PW-I14 (живучесть guard).** `zone_write_epoch[z]` принимает нечётное значение только внутри `EpochGuard`; `Drop` возвращает чётность при любом выходе (успех, `Abort`, `Io`, `panic=unwind`). Читатель, не получивший стабильный чётный guard за `PIN_ATTEMPTS = 8`, возвращает `ZoneDegraded{zone, epoch}` (зона → `NEEDS_FSCK`, read-only по зоне) и метрику, а не повторяет бесконечно. Другие зоны не затронуты.

### 5.4. Отображение

| Источник | Наш инвариант | Комментарий |
|---|---|---|
| A-4, A-9 | PW-I2 | добавлено `F ≥ 2` и `F < current_version` |
| A-5, A-6, A-7 | PW-I4, PW-I7, PW-I8, PW-I11 | усилены `max(...)`, геометрией, ring/chain |
| A-7 | PW-I4, PW-I5 | барьер + `page_limit_at_commit` |
| A-8 | PW-I3 | `fsck`, не runtime |
| A-10 | PW-I2 (исключение) | `NEVER_PUBLISHED` |
| A-11 | PW-I3 | tombstone/`deleted_txn` |
| A-12 | PW-I2a, PW-I14 | `MP` инкрементальный + GC-подъём под guard; guard-живучесть |
| A-6 (расширение) | PW-I2b, PW-I7 | chain как safety valve |
| A-4 (расширение) | PW-I13 | bucket в фазе 1 |
| I-1..I-14, W-1, W-21 | §2 | заменены/ослаблены осознанно |

---

## 6. Уточнённые протоколы

### 6.1. Пин читателя (принятая формула v2 §5.3)

```
zone_snapshot(z, snap):
  e0 = published_txn.load(Acquire)                  # ОБЯЗАТЕЛЬНО до головы
  ceiling = ∞                                       # PW-I12: snapshot_seq — не ceiling
  for attempt in 0..8:
      root = heads[z].load(Acquire)                 # ArcSwap, in-process
      if root is None: return NoZoneVersion          # только «зоны нет/tombstone»
      if !slot.pin(z, root.version): return ReaderContended
      fence(SeqCst)                                 # store→load на ARM64
      c1 = zone_write_epoch[z].load(Acquire)
      e2 = published_txn.load(Acquire)
      root2 = heads[z].load(Acquire)
      c2 = zone_write_epoch[z].load(Acquire)
      if c1 == c2 && c1 % 2 == 0 && e2 == e0 && root2.version == root.version:
          return ZoneSnapshot { root, pin }
      slot.unpin(z); backoff(10 µs)
  return ReaderContended
```

**Корректность (что должно быть в loom-модели).** Любой актор, меняющий голову **или** `MP(z)`/`RV_z` (координатор, GC), инкрементирует guard (odd → работа → even) и читает пины `Acquire` **после** инкремента. Если читатель увидел `c1==c2` чётный и ту же версию, то либо актор завершился до `c1` (версия в голове другая — отказ), либо начнётся после `c2` (его чтение пинов — после публикации пина, упорядоченной `fence(SeqCst)`). `e0/e2` закрывают окно «голова загружена — пин опубликован». `root2.version` закрывает гонку с `ArcSwap`.

**F-11 = PW-I14 (RAII).** `zone_write_epoch` инкрементируется только через `EpochGuard`, возвращающий чётность в `Drop` (успех, `Abort`, `Io`, `panic=unwind`). Читатель после `PIN_ATTEMPTS` возвращает `ZoneDegraded{zone, epoch}` (fail-closed по зоне) и метрику; зона уходит в `NEEDS_FSCK` (read-only по зоне), другие зоны продолжают работу. Бесконечный retry запрещён.

**`freeze()` и чтение-на-T.** `Snapshot.snapshot_seq` не ограничивает зоны (PW-I12). Согласованный срез/чтение-на-T: `freeze()` берёт все zone-lease (или ждёт), делает `sync()`, возвращает `E` и держит `EPOCH`-пин; на это время запись — `Busy`/`EpochPinned`. `fsck --at-epoch` использует тот же механизм.

**Запрещено:** пин после чтения данных; доверять `slot.pin` без guard-валидации; `Relaxed` для `pin`/`published_txn`; вытеснять живой слот (SEC-ZF-007); трактовать `MP(z)` как глобальный минимум.

### 6.2. Ring, chain и опубликованная версия

| Правило | Значение |
|---|---|
| Раскладка | `RootEntry` 64 Б; 4 версии × 2 копии; A/B — разные 4 KiB страницы (v2 §1.1) |
| Выбор группы | `V mod 4`; перезапись только при `group.version < MP(z) ∧ < D_z ∧ < V` |
| Исчерпание | **Chain обязателен:** пишется `ROOT_CHAIN` (фаза 1), `RootEntry.prev_record` → предыдущая; коммит не блокируется. `ZoneWriterStalled` при живом chain не возвращается |
| Chain-выбор | ring → chain до первой `version ≤ ceiling`; `MAX_ROOT_CHAIN_HOPS = 4096`; цикл/превышение → `Corrupt{zone}` |
| Chain-GC | `version < MP(z) ∧ version < D_z`; возврат страницы в пул зоны; `pw_root_chain_depth`/`pw_chain_pages` |
| Torn | одна копия → валидна вторая; обе копии версии → откат ≤ 1 версии |
| Все группы биты | `Corrupt{zone}`, файл работает; `fsck --repair --zone` |
| Валидация | CRC, `owner_zone` = каталогу, `version ≥ 2`, `root_page`/`meta_root`/`free_head` < `page_limit_at_commit`, `tree_level ≤ 8`, `state ≤ 2`, `deleted_txn` ⟺ `state=2` |

**Почему ring + chain.** Ring даёт быстрый путь (4 версии, A/B, 3 коммита headroom); chain — safety valve для долгого читателя (AXFR), чтобы коммит не блокировался. Chain стоит 1 страницу на версию и существует только при backlog читателя; в норме `pw_chain_pages = 0`. Это закрывает F-8 нормативно (PW-AT-1).

### 6.3. Аллокатор (курсор в памяти, D-C)

```
alloc(n):
  if local_cache.free_pages >= n: return take(n)
  loop:
    c = reserve_cursor.load(Acquire)
    if c + ALLOC_THREAD_CACHE_PAGES > hard_limit: return NoSpace{zone}|MapFull
    if cas(reserve_cursor, c, c + ALLOC_THREAD_CACHE_PAGES, AcqRel, Acquire).is_ok():
        local_cache.refill(c, ALLOC_THREAD_CACHE_PAGES); continue
```

Правила:
1. `hard_limit = page_count_max − GC_RESERVE_PAGES`; `DP/DT` — durability-барьер, не аллокатор.
2. Барьер F-3: все резервации — до `CommitRequest`; между запросом и ack — ни одного `fetch_add`.
3. Публикация: `page_limit_at_commit ≤ DP` и `max_allocated_id < DP`; `version ≤ DT`.
4. Recovery: `DP = max(ALLOC_RECORD.page_limit, cursor, roots, pools, page_data_first)`; `next_txn = max(DT, roots, pages)+1`; **`reserve_cursor := DP` до первого `alloc`** (M1 — единственный процесс).
5. `[DP, cursor)` — «выделено, но не опубликовано»: не выдаётся, учитывается `pw_alloc_leaked_pages_estimate`, возвращается `fsck`.
6. Курсор в памяти: после power loss он теряется; восстановление из `ALLOC_RECORD`/корней. **Занижение курсора запрещено** (double allocation); завышение — утечка.
7. **M3:** общий durable-курсор/`txn` требует отдельного ADR (F-5); текущая схема — один процесс.

### 6.4. Group commit: два fsync

```
coordinator(group):
  1. batch: все CommitRequest; page_limit = max(max_allocated_id+1, cursor); txn_limit = max(V)
  2. write ALLOC_RECORD { seq+1, page_limit, txn_limit, term } (2 копии, разные страницы)
  3. fdatasync(fd)                                  # ФАЗА 1: данные + ALLOC_RECORD
  4. publish DP/DT (Release)
  5. for m where DP > m.max_allocated_id && DT >= m.V:
        zone_write_epoch[z] odd → select group (MP, D_z) → pwrite 2 копии → even
  6. fdatasync(fd)                                  # ФАЗА 2: корни
  7. D_z = V (Release); published_txn = max; heads[z].store(Arc<ZoneRoot>, Release)
  8. ack
```

- Участник, не прошедший барьер, ждёт следующую группу (`CommitAborted`/retry).
- `Flush`: шаги 1–5 без 6; `D_z` не двигается; после power loss — откат зоны на `V−1`.
- `Memory`: только `pwrite` корней; durability не обещана.
- Смерть координатора = смерть процесса (M1): головы части групп могли быть записаны; каждая зона — на своей max-valid версии; подтверждённые коммиты не теряются (ack не пришёл → повтор).
- `fsync`-ошибка: группа не опубликована, `Io`, координатор — read-only до `sync()`/рестарта.
- **Почему два fsync:** fsync не упорядочивает диапазоны; при крахе во время единственного fsync корень может долететь раньше данных. `ALLOC_RECORD` до фазы 1 безопасен: страницы выше `page_limit` не адресуемы ни одной головой.

### 6.5. Освобождение, bucket, donation

```
коммит V зоны z:
  1. новый граф V; dropped(V)
  2. фаза 1: данные + bucket(V) (COW-образ пула, free_epoch=V) → fdatasync
  3. фаза 2: RootEntry V (free_head → bucket(V)) durable; D_z := V
  4. is_reclaimable(F) = F≥2 ∧ F<D_z ∧ F≤RV_z ∧ F<current_version(z)
     ⇒ страницы bucket(V) не выдаются до D_z ≥ V+1
  5. donation: только для страниц, где is_reclaimable для **всех**; отдельная фаза
  6. крах между (2) и (3): bucket durable, не связан → утечка (не double-free); fsck возвращает
```

Проверки: bucket COW; `free_epoch ≥ 2`; нет пересечений bucket↔граф; `owner_zone` каждой страницы; orphan-bucket (durable, но недостижим) = утечка, не double-free; `fsck` возвращает.

### 6.6. Область процессов

**M1 (в v2):** один процесс, `LOCK_EX`; N потоков-writer'ов; `zone_write_epoch`/`MP`/`RV`/`D_z`/`published_txn`/`heads[]` — в памяти процесса. Второй процесс → `Busy` (SEC-ZF-009 сохраняется).

**M3 (не входит):** до включения обязательны (F-5):
1. `zone_write_epoch` и `published_txn` — в общем файле (или выводятся из ring/`ALLOC_RECORD`); file-side валидация пина.
2. `MP(z)`/`RV_z`/`D_z` — из общих структур (reader table уже общая; `D_z` — из max-valid ring + `DT`).
3. Общий durable-курсор/`txn` (CAS на общем слове, не памяти процесса).
4. Writer registry/generation, byte-range lease на голову, `term`+fencing координатора.
5. `LOCK_SH` для писателей, `LOCK_EX` для recovery/fsck; generation-recovery.
6. Отдельная crash-матрица и тесты §10.

До этого запуск N процессов-писателей **запрещён**.

### 6.7. Recovery и классификация повреждений

```
recover():                                  # LOCK_EX, до публикации ZoneRoot
 1. superblock → конфиг (1.5.3)
 2. LayoutHead A/B (разные страницы) → max-valid; обе невалидны → CorruptNoValidMeta (file-fatal)
 3. ALLOC_RECORD A/B (разные страницы) → max-valid; обе невалидны → file-fatal
 4. каталог → зоны (origin → zone_seq → head_slot)
 5. select(z) по ring → при отсутствии chain (prev_record, ≤ MAX_ROOT_CHAIN_HOPS) → RootEntry | нет версии (Initializing)
 6. LayoutHead/ALLOC_RECORD/RootEntry: A/B в разных страницах; page 3 не занята LayoutHead
 7. DP := max(record.page_limit, cursor, roots, pools, page_data_first); txn := max(DT, roots, pages)+1
    reserve_cursor := DP (до первого alloc)
 8. file-fatal проверки (ниже); иначе — зона/файл по правилам
 9. reader table: санитизация; MP/RV пересчёт (GC); guard-флаги (odd → ZoneDegraded/NeedsFsck)
10. Snapshot; Stats: torn_root[], recovered_unsynced_zones[], leaked_pages, chain_pages
```

**File-fatal (F-6, независимо от `strict_corruption`):**

| Признак | Почему файл |
|---|---|
| `head.page_limit_at_commit > DP` после `max`-коррекции | Возможна выдача живых страниц |
| Пересечение множеств страниц зон | Нарушена A-8/PW-I3 |
| `owner_zone`/`version` из чужой зоны при валидном CRC | Подмена/переиспользование, не локальная порча |
| Битый/несовместимый `LayoutHead`, `ALLOC_RECORD`, каталог | Нет доверенного корня раскладки |
| Регрессия `DP`/`DT`/`txn`/`epoch_hint` | Признак отката структуры |

**Zone-fatal:** CRC/границы/поля `RootEntry` одной зоны → зона read-only (`Corrupt`), остальные работают; `strict_corruption = file` возвращает v1-поведение.

---

## 7. Crash-матрица (M1: один процесс, один координатор)

| ID | Точка отказа | На диске | Recovery | Потери/утечки |
|---|---|---|---|---|
| PW-C1 | частичный `pwritev` данных | старый корень; страница не адресуема | старая версия | leak; `txn` сгорел |
| PW-C2 | данные записаны, до фазы 1 | подмножество data | старая версия | leak; порчи нет |
| PW-C3 | torn `ALLOC_RECORD` (одна из 2 копий) | вторая валидна | max-valid | leak страниц выше выбранного `DP` |
| PW-C4 | во время фазы 1 fsync | data/record — подмножество | старая версия; `DP` max-valid/прежний | leak; порчи нет |
| PW-C5 | torn-корень, одна копия, A/B в разных страницах | вторая копия валидна | max-valid | ≤ 1 версии, зона жива |
| PW-C6 | обе копии одной версии биты | предыдущая группа цела | откат ≤ 1 версии | один неподтверждённый коммит |
| PW-C7 | все 4 группы биты | — | `Corrupt{zone}` | зона до `fsck`; файл работает |
| PW-C8 | корень записан, до фазы 2 (`Flush`; `R(proc)`) | в page cache, долетит | версия принимается; `D_z` не двигался | нет после рестарта процесса; `recovered_unsynced_zones += z` |
| PW-C9 | то же (`R(power)`) | корень мог не долететь | `V−1` по зоне | 1 коммит зоны |
| PW-C10 | во время фазы 2 fsync | подмножество корней группы | каждая зона индивидуально max-valid | межзонная атомарность отсутствует (PW-L1) |
| PW-C11 | смерть координатора посреди группы | часть корней записана | каждая зона max-valid; ack не пришёл | подтверждённые не теряются; остальное retry |
| PW-C12 | аллокация после `CommitRequest` (нарушение F-3) | корень ссылается на `≥ DP` | recovery `max(...)` спасает; иначе double allocation | `NEEDS_FSCK` + leak; без `max` — порча |
| PW-C13 | ошибка `pwrite` данных | корня нет; страницы не опубликованы | `V−1`; `Io`/`Abort` | `NEVER_PUBLISHED` — реюз; иначе leak |
| PW-C14 | обе копии `ALLOC_RECORD` биты | нет `DP/DT` | file-fatal | файл не открывается; offline `fsck` |
| PW-C15 | writer-поток падает в `apply` | корня нет | `V−1`; lease освобождается | страницы локального кэша leak |
| PW-C16 | пул опубликован до durable drop (нарушение) | корень `V−1` ссылается; пул содержит | double allocation | **порча**; детект `drop_txn ≥ D_z` → `NEEDS_FSCK` |
| PW-C17 | durable drop, пул не долетел | корень `V`, страниц в пуле нет | `V`; пул недостижим | leak до `fsck` (PW-I13) |
| PW-C18 | donation раньше drop (нарушение) | страница, живая в `V−1`, в пуле | double allocation | **порча**; две фазы + `donated_at_txn < DP` |
| PW-C19 | donation после drop, запись пула потеряна | страницы нигде | — | leak; порчи нет |
| PW-C20 | пин без `e0`/guard-валидации | — | — | use-after-reuse; только `V:loom` |
| PW-C21 | `kill -9` читателя с пином | слот пина остался | санитизация при открытии (живой PID не вытесняется) | рекламация стоит → рост; порчи нет |
| PW-C22 | два recovery одновременно (M3 без lock) | оба пишут `ALLOC_RECORD`/пулы | `Corrupt` | **порча**; в M1 `LOCK_EX` |
| PW-C23 | GC/`compact` при полном файле без резерва | некуда писать корень/пул | дедлок → `NeedsFsck` | предотвращается `GC_RESERVE_PAGES` |
| PW-C24 | порча `owner_zone` (bit rot) | страница с чужим owner | `Corrupt{zone}` | одна зона (SERVFAIL), не тихо |
| PW-C25 | **все 4 группы `≥ MP(z)`** | ring исчерпан | коммит пишет chain-страницу (фаза 1) → `RootEntry.prev_record` | отказа записи нет; +1 страница/версия; chain GC после снятия пина |
| PW-C26 | **orphan bucket** (PW-I13) | bucket durable, не связан с головой | `fsck` возвращает | leak; double-free нет |
| PW-C27 | **коммит в другую зону** между `Snapshot` и `ZoneSnapshot` | — | зона читается на последней версии (`ceiling=∞`); `NoZoneVersion` только «зоны нет» | отказа чтения нет; per-zone монотонность сохранена (PW-I12) |
| PW-C28 | **`zone_write_epoch` остался нечётным** (паника вне RAII/баг) | — | `EpochGuard` возвращает чётность; при намеренно застрявшем guard читатель → `ZoneDegraded` за ≤ 8 попыток | отказ чтения **одной** зоны; другие работают (PW-I14) |
| PW-C29 | медиа-сбой страницы корней | одна копия 15 зон бита | вторая копия в другой странице | 0 зон потеряно; при второй независимой ошибке — ≤ 15 зон |

**Итог.** При соблюдении §6 тихой порчи нет. C-16/C-18 — порча при нарушении порядка (негативные тесты). C-20 — невидимая порча при нарушении пина (только loom). C-25/C-27 — штатные сценарии (chain/чтение последней), C-28 — отказ одной зоны с fail-closed. C-26 — утечка, не порча.

---

## 8. Гонки атомиков и memory model

### 8.1. Платформы

| Платформа | Статус | Требования |
|---|---|---|
| `x86_64` Linux | обязательна | TSO |
| `aarch64` Linux | обязательна | RCpc; `LDAR`/`STLR`; store→load требует `fence(SeqCst)`; `Relaxed` не даёт dependency ordering |
| 32-bit | исключена | `AtomicU64` не lock-free |

Гейт: `#[cfg(target_has_atomic = "64")]` + отрицательный тест сборки.

### 8.2. Порядок операций

| Объект | Писатель | Читатель | Ordering | Запрет |
|---|---|---|---|---|
| `published_txn` | координатор | читатель | `Release`/`Acquire` | `Relaxed`; `e2` без `e0` |
| `heads[z]` (ArcSwap) | координатор | читатель | `Release`/`Acquire` | чтение головы через файл на hot-path (M1) |
| `slot.pin` | читатель | GC | `Release`/`Acquire` + `fence(SeqCst)` перед `c1` | `Relaxed` |
| `zone_write_epoch` | координатор, GC | читатель | `AcqRel` RMW / `Acquire` | оставить нечётным (F-11) |
| `MP[z]` | читатель (`fetch_min`), GC (`store`) | GC/писатель | `AcqRel`/`Acquire`/`Release` | подъём вне GC-окна под guard |
| `RV_z`, `D_z` | GC/координатор | писатель зоны | `Release`/`Acquire` | понижение `RV/D` |
| `reserve_cursor`, `reserve_txn` | все writer'ы | все | CAS `AcqRel` | `pwrite`, `Relaxed` |
| `ALLOC_RECORD`/`RootEntry` (файл) | координатор | recovery/fsck | `pwrite`; `Release`-fence перед публикацией в память | считать валидным до CRC |
| `ALLOC_RECORD.term` | лидер | лидер | `SeqCst` | takeover без fencing (M3) |

### 8.3. ARM64 (обязательные)

1. **Store-load.** `pin(Release)` → `c1(Acquire)` не упорядочены на ARMv8 (RCpc) → `fence(SeqCst)` (DMB ISH) между ними. Иначе GC не увидит пин → use-after-reuse (невидимо для CRC/TSan).
2. **Dependency ordering.** `Relaxed`-загрузка указателя + чтение заголовка страницы небезопасны; только `Acquire`.
3. **64-бит атомарность:** только выровненные `AtomicU64`; управляющие слова — на 8-байтовых смещениях; страницы выровнены по `page_size`.
4. **Смешанный доступ:** один байт нельзя одновременно писать `pwrite` и читать/писать атомарно. Управляющие слова — только атомарно; payload — `pwrite` до публикации, затем чтение.
5. **`pwrite` → видимость:** `pwrite` завершается в page cache до возврата; `fence(Release)` + публикация головы дают порядок «данные раньше головы» в пределах хоста. Межпроцессно — допущение ОС §1.3.4.
6. **CRC:** вычисление не барьер; барьер — публикация. `P.txn ≤ version` и CRC проверяются до использования полей.

### 8.4. Loom-модели (обязательные)

| Модель | Инвариант | Участники |
|---|---|---|
| `pin_capture` | PW-I2a; без `e0`/`c1c2` — нарушение | reader, coordinator, `published_txn`, guard |
| `pin_vs_reclaim` | PW-I2, PW-I2a | reader, GC, reclaim |
| `epoch_min` | `MP` подъём/опускание (F-1) | 3 читателя, 2 зоны, GC |
| `root_publish` | PW-I7, PW-I2b | coordinator, reader, recovery |
| `alloc_record` | PW-I4, PW-I6 | 2 writer'а, coordinator, recovery |
| `pool_publish` | PW-I2, PW-I3 | writer, GC, recovery, crash-cut |
| `epoch_stuck` | F-11: RAII возвращает чётность | writer/GC abort |

TSan — для `unsafe`-обёрток mmap; ложные срабатывания на file-backed памяти подавляются точечно.

---

## 9. DoS и деградация

### 9.1. Сценарии

| Сценарий | Влияние | Мера |
|---|---|---|
| Застрявший читатель (TW-8) | `RV_z` стоит → зона растёт; ring исчерпан → **chain** (коммит идёт) | Chain (PW-I2b); алерты `pw_root_chain_depth`/`pw_stuck_reader_seconds`; живой не вытесняется |
| Долгий AXFR на активной зоне | После 3 коммитов — chain-страницы, запись продолжается | `V:integ` PW-AT-1; алерт на `pw_chain_pages`; документированная цена 1 стр/версию |
| `Snapshot` до коммитов в другие зоны | Зоны читаются на последней версии; `NoZoneVersion` только «зоны нет» (PW-I12) | PW-AT-2; метрика `pw_no_zone_version_total` (ожидается 0, кроме tombstone) |
| `zone_write_epoch` нечётный | Только при панике вне RAII/баге; читатель → `ZoneDegraded` за ≤ 8 попыток | `EpochGuard` (PW-I14); `pw_zone_epoch_stuck_total`; PW-AT-3 |
| GC/fsync-шторм (TW-12) | Латентность коммитов | `MAX_GC_*`, `MAX_BATCH_*`, backpressure |
| Фрагментация (TW-13) | `MapFull` при свободных страницах в чужих пулах | Donation, `compact_zone`, квоты, offline compact |
| Исчерпание файла | `MapFull`/`NoSpace{zone}` | `GC_RESERVE_PAGES`, алерт 90 %, запрет новых зон < 5 % |
| Контеншен `reserve_cursor` | Падение throughput | `ALLOC_THREAD_CACHE_PAGES=64`, ~0.02 CAS/коммит |
| fsync-потолок | Верхняя граница | `MAX_BATCH_ZONES/BYTES/DELAY`; два fsync |
| Багованный писатель | DoS/порча | `owner_zone`, `fsck`, квоты; M1 — доверие к своему коду |

### 9.2. Метрики

`pw_page_limit`, `pw_txn_limit`, `pw_alloc_leaked_pages_estimate`, `pw_orphan_bucket_pages`, `pw_free_pages_ratio{zone}`, `pw_reclaim_version{zone}`, `pw_zone_min_pinned{zone}`, `pw_root_ring_free_groups{zone}`, `pw_root_chain_depth{zone}`, `pw_chain_pages`, `pw_zone_degraded_total{zone}`, `pw_zone_epoch_stuck_total{zone}`, `pw_no_zone_version_total`, `pw_donated_pages_total`, `pw_donation_backlog_pages`, `pw_group_commit_size`, `pw_group_fsync_seconds`, `pw_batch_delay_seconds`, `pw_torn_root_total`, `pw_recovered_unsynced_zones`, `pw_stuck_reader_seconds`, `pw_reader_pin_overflow_total`, `pw_catalog_write_wait_seconds`, `pw_leaked_head_slots_total`, `pw_strict_corruption_mode`.

### 9.3. Алерты

`pw_alloc_leaked_pages_estimate` > `MAX_LEAK_RATIO` от `DP`; `pw_root_chain_depth > 1024` дольше 60 с; `pw_zone_degraded_total > 0`; `pw_zone_epoch_stuck_total > 0`; `pw_stuck_reader_seconds > 300`; `pw_free_pages_ratio{zone} > 40 %` дольше часа; `pw_donation_backlog_pages` растёт; `pw_group_fsync_seconds` p99 выше бюджета; `pw_torn_root_total > 0`; `pw_recovered_unsynced_zones` непусто на `Sync`-файле; `pw_no_zone_version_total` всплеск; `pw_catalog_write_wait_seconds > 50 мс`.

### 9.4. Лимиты (дефолты)

| Параметр | Значение | Смысл |
|---|---|---|
| `ROOT_RING_VERSIONS` | 4 | быстрый путь; при исчерпании — chain |
| `ROOT_RING_COPIES` | 2 | A/B в разных страницах |
| `ROOT_RECORD_SIZE` | 64 | запись корня |
| `ROOT_ZONES_PER_PAGE` | 16 | 512 Б/зона |
| `ALLOC_EXTENT_PAGES` | 16 | гранулярность |
| `ALLOC_THREAD_CACHE_PAGES` | 64 | 0.02 CAS/коммит |
| `PINS_PER_SLOT` | 8 | 12 Б/пин, версия u32 |
| `MAX_PINNED_ZONES` | 64 | далее `EPOCH`-пин |
| `MAX_GC_ZONES_PER_GROUP` | 16 | бюджет |
| `MAX_GC_PAGES_PER_GROUP` | 8192 | бюджет |
| `MAX_BATCH_ZONES` | 256 | пачка |
| `MAX_BATCH_BYTES` | 1 MiB | пачка |
| `MAX_BATCH_DELAY_US` | 1000 | латентность |
| `GC_RESERVE_PAGES` | 32 | резерв GC |
| `ZONE_PAGE_QUOTA_RATIO` | 0.40 | против «одна зона съела файл» |
| `MAX_LEAK_RATIO` | 0.01 | порог алерта/`fsck` |
| `MAX_ROOT_CHAIN_HOPS` | 4096 | защита от петли/DoS обхода chain |
| `CHAIN_GC_BATCH` | 4096 | chain-страниц на GC-проход |

---

## 10. Требования к тестам

### 10.1. Crash-injection (`V:crash`)

| Точка | Как | Ожидание |
|---|---|---|
| Каждая `PW-C*` | failpoint до/после syscall; `_exit(9)` | PW-I1…PW-I12; `fsck --verify` зелёный |
| Power loss | `dm-log-writes` → реплей произвольного префикса | Каждая зона `V` или `V−1`; межзонная атомарность не ожидается |
| I/O error | `dm-flakey` | `Io`/`Abort`, `NEEDS_FSCK` где положено, без тихой порчи |
| `kill -9` в цикле | 10⁴ итераций, случайная задержка | 0 `Corrupt` на валидных данных; потеря ≤ 1 неподтверждённого коммита зоны |
| Torn root | половина копии; копии в разных страницах и **искусственно в одном секторе** | Разные страницы → зона жива; один сектор → тест-детектор F-2 |
| Torn `ALLOC_RECORD`/`LayoutHead` | половина A и/или B | Одна валидна → max-valid; обе — file-fatal |
| Ring exhaustion | AXFR-пин + 10 коммитов | 0 `ZoneWriterStalled`/`Corrupt`; `pw_root_chain_depth > 0`; после AXFR chain GC-ится (PW-AT-1) |
| Orphan bucket | краш между drop и публикацией пула | «Пул достижим или утечка», не double-free (PW-I13) |
| Guard stuck | abort между odd/even | RAII возвращает чётность; иначе `ZoneDegraded` (F-11) |

### 10.2. Модели памяти (`V:loom`)

Модели §8.4. Отдельно: тест «убрать `e0` → падает», «убрать `c1==c2` → падает», «поднять `MP` вне guard → падает». ARM64 CI (native/QEMU); TSan — ночной.

### 10.3. Property-тесты (`V:prop`)

1. **Allocator:** `next_page` не убывает; диапазоны не пересекаются; ни одна голова не ссылается на `≥ DP`; `DP`/`DT` не убывают.
2. **Ring/version:** `select` детерминирован; `version` растёт; откат ≤ 1; при исчерпании ring — chain, не перезапись и не отказ записи.
3. **Crash-replay:** случайная программа + крах → recovery → зона `V`/`V−1`; нет смеси; `DP`/`txn` не уменьшились.
4. **Free/pool/donation:** выданная страница не достижима из восстановимой головы; orphan не double-free; donation не отдаёт живую.
5. **Pin:** рекламация никогда не срабатывает для `F > MP(z)`; `MP` после unpin поднимается только GC; `RV` не понижается.
6. **Snapshot (PW-I12/PW-AT-2):** после `Reader::snapshot()` — 100 коммитов в другие зоны и ≥ 10 в ту же; `zone_snapshot(z)` успешен (нет `NoZoneVersion`), версия не ниже; `freeze()`-вариант возвращает ровно `T`.

### 10.4. Негативные API-тесты

1. `commit` с `max_page_id ≥ DP` → `InvariantViolation`, файл не меняется.
2. Аллокация между `CommitRequest` и `CommitAck` → `Busy`/`InvariantViolation`.
3. Пин без `e0`/`c1c2` (тестовая «неверная» реализация) → детектор; чтение после перезаписи → `Corrupt`/retry.
4. `page.txn > version` или `owner_zone` ≠ зоны → `Corrupt`.
5. Страница с `F ≥ D_z` выдана из пула → отказ + `NeedsFsck`.
6. Пул/donation для страницы, живой в восстановимой голове → `NeedsFsck`, не выдана.
7. Второй процесс-писатель в M1 → `Busy`.
8. `alloc` сверх `ZONE_PAGE_QUOTA` → `ZoneQuotaExceeded`, файл не меняется.
9. `Snapshot` от другого файла → `SnapshotFromDifferentFile`.
10. `pwrite` в управляющее слово (симуляция) → `fsck`, `NEEDS_FSCK`.
11. 32-битная сборка → ошибка компиляции.
12. `strict_corruption = zone` + пересечение зон → всё равно file-fatal.
13. AXFR + 10 коммитов → 0 `ZoneWriterStalled`, `chain_depth > 0`, после AXFR `chain_depth = 0` (PW-AT-1).
14. `zone_write_epoch` stuck → `ZoneDegraded` за ≤ 8 попыток, не вечный retry (PW-AT-3).

### 10.5. `fsck` (расширение §13.9 v1)

`max_page_id < page_limit_at_commit ≤ DP`; `owner_zone` каждой страницы; дизъюнктность множеств зон (битсет); `free_head`/bucket: `drop_txn < D_z`, `owner`, нет пересечений; orphan-bucket'ы в пул владельца; `DP = max(page)+1`; `txn > max(page.txn)`; `reserve_cursor`/`txn` не ниже `DP`/`DT`; head-слоты удалённых зон возвращаются каталогу.

### 10.6. Трассировка SEC-PW → тест

| SEC-PW | Тесты |
|---|---|
| 001 | `V:crash` C-5/C-6/C-7/C-25, `V:unit` torn/геометрия, `V:prop` №2, **PW-AT-1/PW-AT-7** |
| 002 | `V:loom` `root_publish`, `V:unit` №3/4, `V:prop` №2/№6, **PW-AT-2** |
| 003 | `V:loom` `alloc_record`, `V:crash` C-3/C-4/C-12/C-14, `V:prop` №1, **PW-AT-8** |
| 004 | `V:crash` C-16..C-19/C-26, `V:prop` №4, **PW-AT-4** |
| 005 | `V:crash` C-2/C-3/C-8/C-9/C-10/C-11, `V:bench` |
| 006 | `V:unit` №4/5, `V:prop` №3, `V:fsck` §10.5 |
| 007 | `V:loom` `pin_capture`/`pin_vs_reclaim`/`epoch_min`, `V:crash` C-20/C-21/C-28, `V:unit` №3/14, **PW-AT-3/PW-AT-7** |
| 008 | `V:crash` C-16..C-19/C-23/C-26, `V:prop` №4, `V:integ` (GC-шторм) |
| 009 | `V:integ` (второй процесс → `Busy`), `V:manual` |
| 010 | `V:crash` C-14/C-22, `V:unit` №12, `V:integ`, **PW-AT-5/PW-AT-6** |
| 011 | `V:manual` (контракт), `V:integ` (multi-zone без атомарности) |
| 012 | Все `V:loom` + `V:crash` + `V:prop` + PW-AT-1…PW-AT-8 (гейт merge) |
| 013 | `V:bench`, `V:integ` (исчерпание/штормы), `V:cfg` |
| 014 | `V:ci` (ARM64, `target_has_atomic=64`), `V:lint` |
| 015 | **PW-AT-1** (AXFR+commit), **PW-AT-3** (guard), **PW-AT-2** (snapshot) |

### 10.7. Приёмочные тесты PW-AT-1…PW-AT-8 (обязательны для M1)

| ID | Сценарий (точно) | Критерий прохождения |
|---|---|---|
| **PW-AT-1** | Зона `z` пишется 10 коммитов/с (`Sync`); параллельно один `ZoneSnapshot(z)` удерживается ≥ 5 с (AXFR-подобный поток) | 0 `ZoneWriterStalled`, 0 `Corrupt`, 0 `NEEDS_FSCK`; `pw_root_chain_depth > 0` во время удержания; после снятия пина chain GC-ится до 0; `fsck --verify` зелёный; чтение AXFR отдаёт стабильную версию |
| **PW-AT-2** | `s = Reader::snapshot()`; затем 100 коммитов в **другие** зоны и ≥ 10 в ту же `z`; затем `zone_snapshot(z, s)` и повторный вызов | Оба вызова успешны (нет `NoZoneVersion`), версия `z` ≥ исходной, per-zone монотонность (второй ≥ первый), `snapshot_seq` не влияет на выбор; `freeze()`-вариант отдельно: read-at-T возвращает ровно `T` |
| **PW-AT-3** | Инъекция `panic`/`Abort` между `zone_write_epoch += 1` (odd) и `+= 1` (even) в writer'е и в GC; `catch_unwind` | После `Drop` guard чётный; зона читается; при намеренно «застрявшем» guard (тестовая подмена) читатель получает `ZoneDegraded` за ≤ 8 попыток, зона → `NEEDS_FSCK`, **другие зоны читаются/пишутся**; `fsck` снимает флаг |
| **PW-AT-4** | Крах (power-loss replay) в каждой точке между durable bucket `V` (фаза 1) и публикацией `RootEntry V` (фаза 2) | Recovery: либо `free_head` указывает на bucket (страницы реклеймятся по `F < D_z`), либо страницы недостижимы (утечка, `fsck` возвращает); **никогда** страница не в двух местах и не выдана при `F ≥ D_z`; 2-групповой задержки нет |
| **PW-AT-5** | По одному: `head.page_limit_at_commit > DP`; пересечение множеств зон; `owner_zone` чужой; `version` чужой; битый `LayoutHead`/`ALLOC_RECORD`/каталог; регрессия `DP`/`DT`/`txn` | Каждый → файл `read-only` + `NEEDS_FSCK` + `write_locked`; ни один не «деградирует только зону»; с `strict_corruption = zone` поведение то же |
| **PW-AT-6** | Layout/`ALLOC_RECORD`/`RootEntry`: A и B в одной странице (искусственно); page 3 занята `LayoutHead`; registry в page 3 | `open`/`fsck` отвергают layout (A/B не разнесены); page 3 не используется `LayoutHead`; golden v2 соответствует; `fsck` сверяет регионы с `LayoutHead` |
| **PW-AT-7** | Torn root: одна копия версии бита (копии в разных страницах); затем обе копии одной версии биты | Одна копия → версия читается, 0 потерь; обе → откат ≤ 1 версии, зона жива, `torn_root` диагностика; пин на предыдущую версию не ломается (`V:loom` + интеграция) |
| **PW-AT-8** | Writer выполняет `fetch_add(reserve_cursor)` между `CommitRequest` и `CommitAck` (тестовая инъекция) | Коммит отклонён (`Busy`/`InvariantViolation`) **или** корень не публикуется; после краха `DP = max(record, cursor, roots, pools)` не допускает double allocation; `fsck` фиксирует leak, не порчу |

---

## 11. Что нельзя сохранить и принятые ограничения

| ID | Ограничение | Почему неизбежно | Компенсация |
|---|---|---|---|
| **PW-L1** | Нет атомарности между зонами | Публикация per-zone; единая точка = глобальная сериализация | `Snapshot` — набор per-zone версий; `freeze()`; multi-zone операции — отдельными коммитами (0005 §7) |
| **PW-L2** | Изоляция зон — не security | Один файл, один процесс/uid; нет MMU-границы | `owner_zone`/`fsck`/квоты — от аварии; от злонамеренного — per-zone файлы (RR-9) |
| **PW-L3** | Нет мгновенного перераспределения страниц; файл ≈ сумма пиков зон | Кросс-зонная передача требует durable drop + donation | Donation, `compact_zone`, offline compact; планирование по худшему |
| **PW-L4** | `durable/reclaim` → вектор | Durability per-zone | `D_z`, `DP`, `DT`, `MP`, `RV`; per-zone метрики |
| **PW-L5** | Слот 128 Б; `EPOCH`-пин грубее `ZONE`-пина | Ограниченная память слота | `MAX_PINNED_ZONES`; `EPOCH` короткоживущий; порог/метрика |
| **PW-L6** | Мультипроцессная запись — M3 | In-memory guard/MP/RV/heads | Отдельный ADR (F-5); до него `LOCK_EX` и `Busy` |
| **PW-L7** | `create_zone` не атомарен с содержимым | Каталог и корень — разные публикации | `Initializing`/`REFUSED`; идемпотентность; `zone_seq` не переиспользуется |
| **PW-L8** | `Snapshot::txnid` теряет смысл глобального состояния | Состояние — вектор | `SnapshotId`/`snapshot_seq` для порядка; per-zone версии; `freeze()` |
| **PW-L9** | `sync()` — глобальный барьер; `Flush`/`Memory` деградируют неравномерно | Липкий `Sync` + общий alloc record | Эксплуатационный вызов; per-zone `free_pages_ratio` |
| **PW-L10** | `NoSpace{zone}` vs `MapFull{global}` | Аллокация глобальна, реюз зональный | Разные коды/метрики/инструкции |
| **PW-L11** | Медиа-сбой страницы корней | 16 зон/страница-копию | A/B в разных страницах → одна ошибка стоит одну копию, не зону; ≤ 15 зон теряют копию; `fsck`/scrub |
| **PW-L12** | Утечки при крахе/аборте | Нет журнала намерений (WAL отклонён) | `pw_alloc_leaked_pages_estimate`, `MAX_LEAK_RATIO`, `fsck` |
| **PW-L13** | Ring 4 версии = 3 коммита быстрого пути; далее — chain-страница на версию | 512 Б/зона; chain — safety valve (решение Оркестратора) | Chain в фазе 1; `MAX_ROOT_CHAIN_HOPS`; GC при `version < MP ∧ < D_z`; `pw_chain_pages`; PW-AT-1 |
| **PW-L14** | **`Snapshot` не даёт «чтения на T»** — зона читается на последней версии | `ceiling = ∞`; in-process heads = последняя | Явно: `Snapshot` — каталог/диагностика; чтение-на-T — `freeze()`+`EPOCH`-пин / `fsck --at-epoch`; PW-AT-2 |

Явно: глобальная атомарность **не требуется** сценариями v1 (AXFR/IXFR/DNSSEC/REST — по зоне; create/delete — редкие каталог-операции). Принято как PW-L1.

---

## 12. Условия безопасности и приёмка

### 12.1. Условия C-1…C-11

| # | Условие | Приёмка (тест) | Milestone |
|---|---|---|---|
| **C-1** | Пин ровно по формуле v2 §5.3: `e0` до головы, `fence(SeqCst)`, `c1==c2` чётный, `e2==e0`, `root2.version==root.version`; `ceiling = ∞` | `V:loom` `pin_capture` (негатив: убрать `e0`/`c1c2` — падает); **PW-AT-7** (torn A/B + пин); ARM64 CI | M1 |
| **C-2** | A/B **всех** структур (`RootEntry`, `ALLOC_RECORD`, `LayoutHead`) — в разных 4 KiB страницах; page 3 не занята `LayoutHead`; registry — в data-регионе | **PW-AT-6** (page 3/геометрия), **PW-AT-7** (torn: одна копия), `V:crash` C-5 | M1 |
| **C-3** | Барьер аллокаций; `DP=max(...)`; `reserve_cursor := DP` до первого `alloc` | **PW-AT-8** (инъекция аллокации в окне), `V:crash` C-12, `V:prop` №1 | M1 |
| **C-4** | Ровно два fsync; `page_limit_at_commit` в `RootEntry`; `Flush` без второго, `D_z` не двигается | `V:crash` C-2..C-4/C-8..C-11; `V:bench` (потолок) | M1 |
| **C-5** | File-fatal-список §6.7 при любом `strict_corruption`; `zone` не ослабляет file-fatal | **PW-AT-5** (каждый признак → read-only файла); `V:unit` №12 | M1 |
| **C-6** | `is_reclaimable` (`F≥2 ∧ F<D_z ∧ F≤RV_z ∧ F<current_version`); bucket — в фазе 1; `free_head` в `RootEntry V`; donation двумя фазами | **PW-AT-4** (крах между bucket и root), `V:crash` C-16..C-19, `V:prop` №4 | M1 |
| **C-7** | Резервы (`GC_RESERVE_PAGES`, `ZONE_PAGE_QUOTA`) и лимиты §9.4 | `V:crash` C-23, `V:bench`, `V:cfg` | M1 |
| **C-8** | `EpochGuard` RAII; читатель после 8 попыток → `ZoneDegraded` (зона `NEEDS_FSCK`), не спин | **PW-AT-3** (panic между odd/even), `V:unit` №14 | M1 |
| **C-9** | `snapshot_seq` — **не** ceiling; `ZoneSnapshot` — последняя; `NoZoneVersion` только «зоны нет/tombstone»; чтение-на-T — `freeze()`+`EPOCH`-пин | **PW-AT-2** (100 коммитов в другие зоны + ≥10 в ту же), `V:prop` №6 | M1 |
| **C-10** | **Chain обязателен:** исчерпание ring → `ROOT_CHAIN` (фаза 1), коммит не блокируется; `MAX_ROOT_CHAIN_HOPS=4096`; chain GC при `version < MP ∧ < D_z` | **PW-AT-1** (AXFR ≥ 5 с + 10 коммитов/с: 0 stall, 0 `Corrupt`, chain растёт/падает), `V:crash` C-25 | M1 |
| **C-11** | **M3:** N процессов-писателей не включаются без общего `zone_write_epoch`/`published_txn`/`MP`/`RV`/`D_z`/курсора, shared head index, `LOCK_SH`+byte-range lease, generation-recovery, `term`+fencing | Отдельный ADR + расширенная crash-матрица/loom | **M3** |

**Приёмка M1:** C-1…C-10 выполнены, тесты PW-AT-1…PW-AT-8 зелёные, DoD ADR-0004 §13 выполнен. **M1 не блокируется** F-8…F-11 (они закрыты нормативно) и F-7 (эксплуатация). **C-11 — единственный блокер**, и он относится к **M3**, а не к M1.

### 12.2. Согласование с решениями (chain / freeze / ZoneDegraded)

| Решение | Как отражено в C-* | Возможное противоречие | Статус |
|---|---|---|---|
| **Chain** (F-8) | C-10: chain обязателен, `ZoneWriterStalled` при живом chain не возвращается; C-1/C-6 не зависят от способа хранения версии | C-10 в прежней редакции допускал «либо `AXFR_MAX_SNAPSHOT_MS`+stall» — **удалено** | согласовано |
| **`freeze()` для retention** (F-9) | C-9: `ceiling=∞`; `freeze()`/`fsck --at-epoch` — единственный read-at-T; `Snapshot` не пинит зоны | `freeze()` не требует истории ring для обычных читателей; использует `EPOCH`-пин, не меняет PW-I2 (гейт `F ≤ RV_z`) | согласовано |
| **`ZoneDegraded`** (F-11) | C-8: RAII + `ZoneDegraded` за ≤ 8 попыток; другие зоны работают | `ZoneDegraded` — **zone-fatal**, не file-fatal; C-5 (file-fatal) не пересекается; `NEEDS_FSCK` по зоне не блокирует файл | согласовано |
| **Bucket в фазе 1** (F-10) | C-6: bucket — часть фазы 1, `free_head` в `RootEntry V`; `PoolHead` не нужен | Прежняя формулировка «следующая группа» **удалена**; `is_reclaimable` уже содержит `F < D_z`, поэтому преждевременного реюза нет | согласовано |
| **page 3 разнесена** (F-2) | C-2: A/B LayoutHead в разных страницах; registry в data-регионе | Нет исключений для page 3 | согласовано |
| **File-fatal** (F-6) | C-5: список §6.7 обязателен; `strict_corruption=zone` его не ослабляет | Не конфликтует с zone-fatal для CRC/границ головы | согласовано |

---

## 13. Открытые вопросы

1. **Разрядность `version` в пине** — 32 бита (v2) при `txn > 2³¹` → `NEEDS_FSCK`; подтвердить или перейти на 64-битный/5×16 слот.
2. **`MAX_PINNED_ZONES = 64`** — подтвердить профилем `zones()`/AXFR-каталога; иначе — внешняя таблица пинов.
3. **`MAX_LEAK_RATIO = 1 %`** — абсолютный минимум в страницах для малых файлов; частота `fsck`.
4. **`freeze()` в v2.0** — минимальный maintenance-вариант (все lease или ожидание), `EpochPinned`/`Busy`; влияет только на read-at-T, не на M1-запись.
5. **Chain-GC-тюнинг** — `MAX_ROOT_CHAIN_HOPS=4096`, `CHAIN_GC_BATCH`, порог алерта `pw_root_chain_depth`; калибруется на M3.
6. **`domain-model` §5.1/§5.2** — синхронизировать `Snapshot{snapshot_seq}`/`ZoneSnapshot` (последняя версия, `NoZoneVersion` только «зоны нет») и `freeze()`; владелец — Архитектор ПО.
7. **M3-ADR (F-5)** — владелец/сроки; до него `LOCK_EX` и N потоков, N процессов запрещены. **Единственный блокер** (M3).

---

## 14. Последствия

**Положительные:**
- Параллельные зоны не сериализуются на публикации; коммит зависит от fsync-пачки.
- Чтение wait-free; пины не блокируют коммиты: при исчерпании ring коммит уходит в chain (PW-I2b).
- Повреждение одной зоны не роняет файл; глобальные объекты защищены A/B и file-fatal.
- Каждый инвариант §5 имеет исполнимую проверку, включая power loss и loom.

**Отрицательные / цена:**
- Формат 2.0: ring, `ALLOC_RECORD`, `LayoutHead`, per-zone пулы, reader slot 128 Б, `owner_zone`, `fsck` — существенный объём нового кода.
- Два fsync на пачку и один координатор — потолок throughput; WAL — следующий шаг.
- Эксплуатация сложнее: векторные метрики, две ошибки пространства, глобальный `sync()`, квоты, donation.
- Теряются глобальная атомарность (PW-L1), глобальный freelist (PW-L3), мультипроцессность (PW-L6), `Snapshot`-на-T без `freeze` (PW-L14); после 3 коммитов быстрого пути — chain-страница на версию (PW-L13).

**Итог приёмки.** M1 принимается при C-1…C-10 и зелёных PW-AT-1…PW-AT-8; F-8…F-11 закрыты нормативно (chain / `ceiling=∞`+`freeze` / RAII+`ZoneDegraded` / bucket в фазе 1), page 3 и file-fatal зафиксированы. Единственный блокер — **M3** (C-11/F-5), к M1 не относится.

**Что делает направление небезопасным (нарушение нормативных требований):** пин без `e0`/guard, копии в одной атомарной единице, аллокация после снимка фронтира, один fsync, file-fatal как zone-fatal, отсутствие chain при долгом читателе, `snapshot_seq` как ceiling, orphan-пулы, guard без RAII. Каждое проверяется PW-AT-1…PW-AT-8.
