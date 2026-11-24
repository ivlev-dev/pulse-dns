# ADR 0007. Межпроцессная параллельная запись в один файл (M3)

- **Статус:** принято (закрывает блокер M3 — C-11/F-5 из ADR-0006 §12 и ADR-0005 §7 п. 6)
- **Дата:** 2026-11-24
- **Этап:** M3 — N процессов пишут **разные зоны** одного v2-файла, читателей — любое число
- **Роль-владелец:** Архитектор ПО. Раскладка данных не меняется: источник истины — `docs/spec/parallel-writes-v2.md`; здесь — модель конкурентности, локи, fencing, восстановление и границы
- **Связанные:** ADR-0005 (решения M1), ADR-0006 (`PW-I*`, `PW-C*`, `SEC-PW-*`), ADR-0004 §1.3 (`SEC-ZF-014`), `docs/spec/parallel-writes-v2.md`, `crates/pulse-zonefile/src/parallel/coord.rs`

## 0. Резюме

| # | Решение | Следствие |
|---|---|---|
| 1 | Общий координатор — **sidecar** `<file>.pulsecoord`, `MAP_SHARED`, а не второй writable-регион файла данных | формат v2.0/golden не меняются; `SEC-ZF-014` (ровно один writable-регион данных — reader table) сохраняется дословно; v1/`pulsed` не затрагиваются |
| 2 | Аллокатор: `reserve_cursor`/`reserve_txn` — выровненные `AtomicU64` в разделяемой памяти, CAS между процессами | те же батчи (`ALLOC_EXTENT_PAGES`/`TXN_BATCH`), что и M1; durable-барьер по-прежнему `ALLOC_RECORD` |
| 3 | Durable-барьер обновляется под **глобальным commit-lock** (`fcntl`, байтовый диапазон) с монотонностью `DP`/`DT` | ровно два `fdatasync` на группу сохраняются; `dp = max(ALLOC_RECORD, roots, cursor?)`, понижение → file-fatal |
| 4 | **Per-zone writer lease** — `fcntl`-блокировка байтового диапазона на зону; второй писатель → `ZoneBusy` | разные зоны параллельны; lock снимается ядром при смерти/закрытии fd |
| 5 | **Fencing** — слот `(pid, starttime, generation)` в координаторе + `writer_pid`/`epoch_hint` в `ALLOC_RECORD`; `version` монотонен | зомби-процесс/потеря lease не могут опубликовать корень |
| 6 | Reader table v2 — общие слоты 128 Б в разделяемой памяти, `(pid, starttime, зона, версия)`, seqlock | `MP(z)`/`RV_z` учитывают чужие пины; мёртвые слоты санитизируются по `pid+starttime` |
| 7 | Публикация/чтение — per-zone seqlock `zone_write_seq` + барьеры | читатель видит либо согласованную старую, либо новую версию; torn-запись не ломает старую |
| 8 | Рекламация в multi — **bump-only** + append-only bucket-цепочка | нет двойной выдачи между процессами; цена — файл растёт до quiescent-момента (PW-L12/новая L13) |
| 9 | API: `StoreConfig.multi_process` / `OpenConfigV2.multi_process`, по умолчанию `false` | одиночный процесс идёт по пути M1 без регрессий |
| 10 | `fsck --repair`/`donation` в multi — только при отсутствии живых процессов (`try_maintenance`) | maintenance не гоняется с писателями |

## 1. Контекст

M1 (ADR-0005) реализован и принят: один процесс, `LOCK_EX`, N потоков, per-zone ring/chain, `ALLOC_RECORD`, in-process пины, group commit. M3 требует, чтобы N **процессов** писали разные зоны одного файла, а читателей было сколько угодно. Блокер (C-11/F-5) — в M1 всё, что должно быть общим, живёт в памяти процесса:

1. `reserve_cursor`/`reserve_txn` — `AtomicU64` процесса; два процесса выдали бы одни и те же страницы.
2. Lease зоны — `std::sync::Mutex`; не видит другие процессы.
3. Reader table — in-process; GC одного процесса не видит пины другого и переиспользовал бы страницы под живым читателем.
4. `ALLOC_RECORD`/`DP`/`DT`/`D_z`/`published_txn` — кэш процесса; другой процесс их не обновляет.
5. `ArcSwap`-головы зон — процесс видит только свои публикации.

`SEC-PW-009` разрешает M3 только отдельным ADR; этот ADR его и вводит.

## 2. Что именно должно быть общим (и почему не в файле данных)

| Сущность | Где | Почему |
|---|---|---|
| `reserve_cursor`, `reserve_txn` | sidecar | CAS между процессами; durable-барьер — `ALLOC_RECORD` в файле данных |
| `DP`, `DT`, `published_txn`, `D_z[]` | sidecar (атомики) | read-mostly между процессами; истина для recovery — файл данных |
| lease-слоты зон | sidecar | fencing; исключение даёт `fcntl` |
| `zone_write_seq[]` | sidecar | seqlock публикации (писатель↔читатель в разных процессах) |
| reader table (1024×128 Б) | sidecar | пины других процессов для `MP(z)`/`RV_z` |
| `ALLOC_RECORD`, ring/chain, bucket | файл данных | crash-safety, `fsck`, recovery; без изменений |

**D-E (отклонение от буквы §10.1 «writable-регион один, reader table»).** Reader table по спецификации — writable-регион **файла данных**. Мы оставляем её там (для `fsck`/golden), но межпроцессные пины публикуем в sidecar. Причина: спека v2.0 заморожена (golden-пролог, `LayoutHead`, `ALLOC_RECORD`): добавление общего курсора/lease в файл данных изменило бы смысл `SEC-ZF-014` и потребовало бы нового `FORMAT_VERSION`. Sidecar не содержит пользовательских данных, пересоздаётся при старте и не участвует в recovery. Эквивалентность: (а) данные/корни/пулы по-прежнему только в файле данных под `pwritev`; (б) sidecar можно потерять — теряются только координация и кэш `D_z`, не данные; (в) в single-process режиме sidecar вообще не создаётся.

**Имя/права.** `<file>.pulsecoord`, `O_CREAT|O_RDWR|O_CLOEXEC|O_NOFOLLOW`, `0600`, `fstat` → regular file, `fchmod 0600`. Симлинк/каталог/FIFO отвергаются (`NotRegularFile`).

**Раскладка sidecar.** Заголовок (магия `PULSCD01`, версия, `max_zones`, `reader_slots`, `page_count_max`, `page_size`, UUID инстанса); страница 1 — скаляры `cursor`, `txn`, `durable_pages`, `durable_txn`, `published`, `generation`, `alive_hint` (каждый на своей cache line); далее — lease-слоты `32 Б/зона`, `zone_write_seq u64/зона`, `D_z u64/зона`, reader-слоты `128 Б`. Все поля — выровненные атомики на фиксированных смещениях. Размер детерминирован геометрией, поэтому все процессы вычисляют одинаковые смещения.

## 3. Инициализация sidecar и `DP`/`txn` при открытии

Каждый процесс держит `LOCK_SH` на байтовом диапазоне `ALIVE` всё время жизни (и писатель, и читатель — читатель тоже пишет пины и не должен потерять слот при «пересоздании» sidecar).

```
open:
  mmap sidecar; ftruncate до layout.len (только рост)
  if try LOCK_EX(ALIVE):                       # живых держателей нет
      if header(geometry,uuid) валиден: reset_ephemeral
      else: initialize (обнулить регионы, записать заголовок)
      LOCK_SH(ALIVE)                            # атомарная замена EX→SH (OFD)
  else:
      LOCK_SH(ALIVE)                            # ждём init-окно другого процесса
      header обязан совпасть, иначе Busy
      raise_watermarks(init)
```

`reset_ephemeral` (никого живого):

* `cursor := DP` — страницы `[DP, старый cursor)` после краха не достижимы ни из одной durable-головы (§3.5 v2), их можно выдать повторно;
* `txn := max(старый txn, next_txn)` — `txn` не переиспользуется;
* `DP/DT/published` — из recovery файла данных; `D_z[]` — из ring-голов;
* lease-слоты, `zone_write_seq`, reader-слоты — обнуляются (все держатели мертвы; `generation` начинается заново только после полной смерти).

`raise_watermarks` (кто-то жив): только `fetch_max` для `cursor`/`txn`/`DP`/`DT`/`published`/`D_z` — монотонность, без сброса.

**Ограничение (операционное).** Удаление/подмена `.pulsecoord` при живых процессах недопустимы: живой процесс держит старый (возможно, уже unlinked) inode, новый процесс создаст независимый курсор → двойная выдача. `fsck`/`repair` не удаляют sidecar; `create` пересоздаёт его при новом UUID файла.

## 4. Аллокатор

- `Allocator` получает `shared: Option<Arc<SharedCoord>>`; при наличии — CAS по `coord.cursor()`/`coord.txn()` вместо локальных атомиков. Алгоритм, батчи и лимиты — те же, что в M1 (§3.1–3.2 v2).
- Durable-барьер — `ALLOC_RECORD` (2 копии в разных страницах) — обновляется **только под глобальным commit-lock**.
- Публикация ограничена durable-границей: корень пишется при `DP > max_allocated ∧ DT ≥ V`.
- `[DP, cursor)` — «выделено, но не durable» (утечка при крахе), `fsck` учитывает.
- При открытии без живых процессов курсор откатывается к `DP` (см. §3) — утечки краха возвращаются.

## 5. Writer lease и fencing

**5.1. Lease.** `fcntl(F_OFD_SETLK, F_WRLCK)` на 1 байт `LEASE_BASE + zone` в sidecar (fallback `F_SETLK` на не-Linux). OFD-локи выбраны потому, что они привязаны к open-file-description, а не к процессу: два независимых открытия файла в одном процессе конфликтуют (защита от двойного `ParallelStore`), а закрытие «чужого» fd не снимает lease. Ядро снимает лок при закрытии fd/смерти процесса.

- Внутри процесса lease дополнен `Mutex`-шардом: `try_lock` → `ZoneBusy` (в multi; в M1 поведение прежнее — ожидание).
- Второй писатель той же зоны → `ParallelError::ZoneBusy { zone }` (retryable).
- Разные зоны не пересекаются, даже если шарды `Mutex` совпали: `fcntl`-диапазон точен по зоне.

**5.2. Fencing.** После взятия lease процесс:

1. инкрементирует глобальный `generation` (монотонный, `u64`);
2. пишет в слот `generation`, `pid`, `starttime`;
3. ставит `state = BUSY` (`Release`).

Слот читается в фазе 2 под commit-lock: коммит разрешён, только если `state == BUSY ∧ pid == self.pid ∧ starttime == self.starttime ∧ generation == generation_at_prepare`. Иначе `ZoneBusy`, запись не выполняется. Дополнительно:

* `version` записи обязан быть строго больше текущей головы (проверка под commit-lock);
* `ALLOC_RECORD` пишется с `writer_pid` и `epoch_hint = generation` (диагностика/аудит);
* зомби-процесс не может коммитить: его lease снят ядром, слот перезаписан новым владельцем, generation другой; попытка `fcntl`-захвата после смерти всегда успешна только у нового владельца.

`RootEntry` 64 Б не имеет свободного поля, поэтому fencing-токен не дублируется в записи корня. Эквивалентность: корень становится видимым только после проверки токена под глобальным commit-lock; `version` монотонен, `owner_zone` проверяется при чтении. `fsck`/recovery от токена не зависят.

**5.3. Порядок снятия.** `state = FREE` (только если generation наш) → `fcntl UNLCK`. При `kill -9` шаг 1 не выполняется, но лок снят ядром; следующий владелец инкрементирует generation и перезаписывает слот. Stale `BUSY` без живого `pid` (starttime не совпал) не блокирует: `fcntl` свободен.

## 6. Публикация и чтение между процессами

### 6.1. Per-zone seqlock

В sidecar — `zone_write_seq[z]` (`u64`, `SeqCst`). Писатель (фаза 2, под commit-lock):

```
seq[z]++            # odd
fence(SeqCst)
mp = min(MP_local(z), oldest_pin_shared(z))
if нет chain-вытеснения ∧ old.version >= mp:
    seq[z]++ ; Zone → ReaderContended
write RootEntry A; write RootEntry B
seq[z]++            # even
```

Читатель:

```
s0 = seq[z] (SeqCst); if odd → retry
head = read ring (pread)
pin(z, head.version)      # Release в общем слоте
fence(SeqCst)
s1 = seq[z]
if s0 == s1 ∧ even → snapshot стабилен
```

**Корректность.** Если окно писателя пересекает `[s0, s1]` — читатель видит изменение seq и повторяет. Если окно писателя целиком после `s1`, то его скан пинов идёт после публикации пина читателя (SeqCst total order) → писатель увидит пин и уйдёт в chain/`ReaderContended`. Третьего варианта нет: либо читатель читает новую версию, либо старый корень защищён пином. `ceiling = ∞` сохраняется: `zone_snapshot` всегда берёт последнюю опубликованную версию.

Torn-запись одной копии: `RootEntry::decode` отвергает CRC, читатель берёт вторую копию; обе torn → предыдущая группа/chain; целостность старой версии не зависит от новой записи.

### 6.2. Видимость голов

В multi-режиме `head(zone)` читает ring из файла (`pread`, 2 страницы), а не `ArcSwap`-кэш. В single — кэш, как в M1 (без регрессий). `select_root`/`zone_snapshot`/`zone_head`/`catalog_head` используют этот путь. Плата — до 2–5 `pread` на снапшот в multi; read-path single не изменён.

### 6.3. `published_txn`/`D_z`

`published` и `D_z[]` пишутся в sidecar:

* `published.fetch_max(V)` — после записи корней (для диагностики/аудита; читатель multi им не пользуется);
* `D_z[z].fetch_max(V)` — **только** после `fdatasync` фазы 2 в `Sync`-режиме. Другой процесс использует `D_z` как гейт рекламации.
* `DP`/`DT` — после durable-фазы 1; при `Flush`/`Memory` не двигаются.

`sync()` в multi берёт commit-lock, перечитывает `ALLOC_RECORD` из файла (max-valid), двигает `DP` до курсора и `DT` до `published`, пишет и синхронизирует; `D_z` локальных голов публикует.

## 7. Рекламация и GC в multi-режиме

**Почему не переиспользуются durable-пулы.** `FreeChain` — кэш в памяти процесса. После того как зону писал процесс A, кэш процесса B устарел; выдача из него дала бы двойную аллокацию. Поэтому в multi:

1. **Bump-only**: `take_pool_page`/`allocate_from_pool` не выдают страницы из durable bucket'ов (только `immediate` — «никогда не опубликованные», локальные и безопасные).
2. **Append-only bucket**: drop-группы коммита пишутся одной новой страницей (`next = старый free_head`), без COW-перестройки всей цепочки. `FreeChain::load` понимает оба порядка (`drop_txn` возрастает после COW-пересборки и убывает в append-режиме) и нормализует цепочку в память по возрастанию.
3. **Chain-GC не переносит страницы в пул**: chain-страницы достижимы из durable-головы и учитываются `fsck`; перенос не дал бы рекламации.
4. Кэш зоны инвалидируется при **взятии** lease (а не на each commit): под lease зону пишет только этот процесс, поэтому внутри lease кэш авторитетен.

`MP(z)`/`RV_z` учитывают общие пины (`effective_mp = min(local MP, shared oldest_pin)`); `RV_z = min(D_z−1, MP, freeze)`. `oldest_pin` игнорирует и CAS-очищает слоты мёртвых `(pid, starttime)`.

**Ограничение PW-L13.** В multi-режиме durable-пул не выдаётся: после долгой нагрузки файл растёт (drop'ы остаются reachable-free, не утечка). Рекламация возобновляется в quiescent-окне (все процессы завершены → `repair_leaks`/`donation`/обычный single-process коммит) либо в будущем v2.1 (per-zone lease + перечитывание пула под ним). `NoSpace` в multi — ожидаемое поведение при исчерпании `page_count_max`.

## 8. Модель конкурентности и lock-порядок

| Структура | Кто пишет | Кто читает | Примитив |
|---|---|---|---|
| `cursor`, `txn` | все писатели | все | CAS `AtomicU64` в MAP_SHARED |
| `ALLOC_RECORD` | держатель **commit-lock** | recovery/`fsck`, держатель commit-lock | pwritev 2 копии + `fdatasync` |
| `DP/DT/published/D_z` | держатель commit-lock | все | `fetch_max`/`store(Release)` |
| lease-слот зоны | владелец lease | владелец + диагностика | `fcntl` + атомики |
| `zone_write_seq[z]` | писатель зоны / GC этой зоны | читатели зоны | `SeqCst` seqlock |
| reader-слот | свой процесс | GC всех процессов | seqlock + `pid/starttime` |
| ring/chain/bucket/данные | владелец lease зоны | читатели | `pwritev`/`pread`, COW |

**Lock-порядок (единственный допустимый):**

```
L1  in-process Mutex(shard зоны)          # только multi: try_lock
L2  fcntl lease(zone)                     # OFD, non-blocking
L3  in-process commit_gate Mutex
L4  fcntl commit-lock                     # глобальный, blocking
L5  fcntl maintenance(ALIVE EX)           # только fsck/repair, до L3
L6  shard-мьютекс пула                    # под L2/L4; не берёт L1–L4
```

Правила: L1→L2 (lease), L3→L4 (окно коммита), L5 берётся до L3 и никогда внутри L4; пул (`L6`) не берётся при удержании L3/L4 и не берёт lease. `lease_guard` берёт L1→L2→L6 (инвалидация кэша). `prepare_reclaim_multi` держит L6 и не берёт L1–L4.

**Deadlock-анализ.**

1. `fcntl`-leas'ы non-blocking (L2): нет ожидания → нет цикла. Два процесса на одну зону: один получает `ZoneBusy`, не ждёт.
2. Commit-lock (L4) берётся **после** lease и никогда до него; lease (L2) не берётся под L4 → цикл L2→L4→L2 невозможен.
3. Внутрипроцессный `commit_gate` (L3) — только вокруг L4; порядок один у всех потоков.
4. `maintenance` (L5) требует отсутствия живых `LOCK_SH` (все lease/reader отпущены ОС при смерти/закрытии); взяв L5, процесс не берёт lease других зон, а `repair_leaks` берёт только lease каталога (L2) после L5 — порядок L5→L2, обратного нет.
5. Пул (L6) не вызывает код, берущий L1–L4; `load_zone_chain` читает файл, не локи.
6. `fcntl(F_SETLKW)` используется только для commit-lock и SH-ALIVE; оба — верхнеуровневые и не вложены в пул/данные.

Итог: граф ожиданий ацикличен; единственная блокировка — L4 (сериализация durable-фазы), она ограничена стоимостью двух `fdatasync` и не держится на read-path.

## 9. Crash/kill -9

| Точка | Что происходит | Recovery |
|---|---|---|
| kill -9 писателя вне коммита | lease снят ядром; reader-слоты этого процесса санитизируются по `pid+starttime` | другие процессы продолжают; новый писатель зоны проходит |
| kill -9 после фазы 1, до корней | `ALLOC_RECORD`/данные/bucket durable, корень нет | `DP` не откатывается (`max`), зона на `V−1`, bucket/страницы — утечка (`fsck`), не порча |
| kill -9 во время фазы 2 (между копиями) | одна копия валидна | max-valid по зоне, откат ≤ 1 версии |
| kill -9 во время `pwrite` ячейки | torn-копия | CRC/вторая копия/предыдущая группа; seqlock-читатель повторит |
| kill -9 читателя | пин остался в слоте | `pid/starttime` не совпал → слот очищается CAS, `MP` пересчитывается; живой читатель не вытесняется |
| kill -9 владельца lease | `state=BUSY` без живого pid | `fcntl` свободен; новый владелец инкрементирует generation |
| потеря sidecar | координация потеряна, данные целы | sidecar пересоздаётся из recovery; в multi — только при отсутствии живых процессов |
| повреждена одна зона | ring/chain/дерево зоны | `NEEDS_FSCK`/`ZoneDegraded` только для зоны; file-fatal-список §9.2 не ослаблен |

**Границы.** `DP` не убывает (проверка в `reload_durable` + recovery max). `txn` не переиспользуется (shared CAS + `next_txn`). Чужие committed-зоны не затрагиваются: каждая зона имеет свои ring/chain/пул, commits сериализуются только на durable-барьере.

## 10. Ограничения (что требует глобального lock / что нельзя)

| ID | Ограничение |
|---|---|
| M3-L1 | **Каталог** (`create_zone`/`delete_zone`/`set_zone_meta`) — один writer: каталог-зона `0` под lease. В multi каталог-мутации должен выполнять один процесс (или переоткрывать `ParallelZones` после взятия lease); иначе возможна потеря обновления каталога. Запись **разных зон** при стабильном каталоге параллельна |
| M3-L2 | Durable-фаза (2 `fdatasync`) сериализована глобальным commit-lock — потолок throughput остаётся «fsync одного inode» (ADR-0005 §4.5) |
| M3-L3 | `sync()` — глобальный барьер (как PW-L9) |
| M3-L4 | `freeze()` реален только в процессе-владельце: `freeze_epoch` локален, а GC другого процесса его не видит. Для кросс-процессного среза — quiesce/`try_maintenance` |
| M3-L5 | Reclamation (bucket/donation/`repair_leaks`) — только bump-only до quiescent-окна (PW-L13) |
| M3-L6 | `read_only`-читатель в multi открывает sidecar RW (нужен для пинов); данные файла — `PROT_READ`/`RDONLY` |
| M3-L7 | Linux (`F_OFD_SETLK`, `/proc/<pid>/stat`); на не-Linux — `F_SETLK` fallback с classic-семантикой закрытия fd (документировано) |
| M3-L8 | `max_zones`/`reader_slots` фиксированы геометрией; sidecar растёт с ними (32+8+8 Б/зона + 128 Б/слот) |
| M3-L9 | Single-process писатель держит `LOCK_EX` на lock-файле, multi-процессы — `LOCK_SH`; смешанный режим (`single-writer` + `multi-reader`) невозможен (`Busy`), потому что single-writer не участвует в per-zone seqlock |

## 11. API и совместимость

```rust
// создание/открытие
StoreConfig { multi_process: true, .. }          // create
OpenConfigV2 { multi_process: true, .. }         // open (writer/reader)

// читатель
let reader = store.reader()?;                    // регистрирует общий слот
let snap = store.zone_snapshot(&reader, zone)?;  // seqlock-протокол

// писатель
let mut zone = ParallelZone::open(&store, origin, zone_seq)?; // lease до Drop
zone.upsert_rrset(...)?;
zone.commit()?;                                   // commit-lock внутри
```

* По умолчанию `multi_process = false`: путь M1 (`LOCK_EX`, in-process пины, без sidecar) не изменён; `pulsed` и v1 не затронуты.
* `commit_group`/`publish_root_with_drops` — низкоуровневые: в multi вызывающий обязан держать lease зоны (как `GroupCommitter` под `ParallelZone`). `publish_root` берёт lease сам.
* `repair_leaks`/`fsck_repair` в multi требуют `try_maintenance` (нет живых держателей), иначе `Busy`.
* `open_read_only` остаётся single-process/read-only; для межпроцессного чтения — `multi_process: true`.

## 12. Приёмка M3

| # | Условие | Где проверено |
|---|---|---|
| C-11.1 | Общий аллокатор: 4 процесса × 4 зоны, нет потерь/дублей страниц | `tests/v2_multiprocess.rs::four_processes_four_zones_each_without_loss_or_duplicates` + `fsck_graph` |
| C-11.2 | Второй writer той же зоны → `ZoneBusy`; lease освобождается при смерти | `second_writer_same_zone_gets_busy_and_recovers_after_kill` |
| C-11.3 | Читатель другого процесса видит согласованные старые/новые версии | `reader_in_other_process_sees_consistent_versions` |
| C-11.4 | `kill -9` писателя: lease/reader очищены, чужие зоны целы, reopen | `kill9_writer_cleans_lease_and_reader_and_keeps_other_zones`, `kill9_reader_slot_is_sanitized` |
| C-11.5 | `kill -9` в середине коммита: `DP` не убывает, зона на `V−1`/`V`, файл пишется | `kill9_during_commit_recovers_previous_version` |
| C-11.6 | 10 000 alloc/commit в 2 процессах: нет пересечений страниц | `ten_thousand_commits_in_two_processes_do_not_overlap_pages` |
| C-11.7 | Чтение/durability single-process без регрессий | весь `cargo test -p pulse-zonefile` |
| C-11.8 | `unsafe` локализован (mmap/atomics/fcntl) с SAFETY | `src/parallel/coord.rs` (`#![allow(unsafe_code)]`) |

**Остаточные риски.** (R1) Сериализация durable-фазы — потолок throughput (не регресс, а свойство одного inode). (R2) При append-only bucket цепочка растёт O(коммитов); `FreeChain::load` линейна при открытии — кэш инвалидируется только при смене lease. (R3) `zone_write_seq` исключает ложную публикацию, но не даёт wait-free чтения: под непрерывной записью одной зоны читатель может получить `ReaderContended` (retryable). (R4) Каталог требует одного писателя (M3-L1). (R5) На не-Linux fencing/lease деградируют до classic `fcntl` (задокументировано).
