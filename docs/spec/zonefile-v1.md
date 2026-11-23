# Спецификация формата файла зон pulse (v1)

- **Файл:** один, содержит все зоны, подключается через `mmap`
- **Версия формата:** 1.0 (спецификация — ревизия 1.2, после независимого ревью)
- **Статус:** проект, на утверждение
- **Реализует:** `pulse-zonefile` (адаптер портов `ZoneStore` / `ZoneWriter`)
- **Источник истины по ID безопасности:** `docs/adr/0004-security-model.md` §1.1
- **Связанные:** `docs/adr/0003-zonefile-format.md`, `docs/adr/0001-ddd-architecture.md`, `docs/spec/domain-model.md` (§5.1–5.2)

Документ самодостаточен для реализации: все поля, смещения, порядок байт и инварианты. Любое «на усмотрение реализации» помечено и снабжено списком допустимых вариантов.

---

## 1. Термины и обозначения

| Термин | Значение |
|---|---|
| `page_size` | размер страницы файла: 4096, 8192 или 16384 байт |
| `PageId` | номер страницы, `u32`; смещение = `PageId * page_size` (u64) |
| `txnid` | идентификатор транзакции (коммита), `u64`, строго возрастает |
| RLE | reversed-label encoding: имя в wire-формате с обратным порядком меток (§8) |
| RRset | набор RR с одним owner/type/class/subtype |
| ENT | empty non-terminal: имя существует только как предок другого имени |
| cut | zone cut: точка делегирования (`NS` без `SOA`) |
| COW | copy-on-write: изменение страницы = новая версия по новому `PageId` |
| `durable_txn` | максимальный `txnid`, про который известно, что его данные и meta на диске |
| `reclaim_txn` | `min(durable_txn, oldest_reader_txn)` — граница переиспользования страниц |
| reader / snapshot | зафиксированный `txnid`, по которому читаются данные |
| writer | единственный поток/процесс, выполняющий коммиты |

Соглашения:

- Все целые — **little-endian**.
- Структуры плотные, без паддинга, кроме явных `reserved`.
- Смещения внутри страницы — `u16` от начала страницы (страница ≤ 16384 < 65536).
- Смещения/размеры файла — `u32` (`PageId`) или `u64` (байты).
- `reserved` пишется нулями, при чтении не проверяется (кроме «MUST be 0»).
- Нарушение инварианта — `Corrupt`, fail-closed.

---

## 2. Константы

```
MAGIC                    = b"PULSEZF1"
FORMAT_VERSION_MAJOR     = 1
FORMAT_VERSION_MINOR     = 0
PAGE_SIZE_DEFAULT        = 4096
PAGE_SIZE_ALLOWED        = {4096, 8192, 16384}

PAGE_TYPE_META           = 1
PAGE_TYPE_BRANCH         = 2
PAGE_TYPE_LEAF           = 3
PAGE_TYPE_OVERFLOW       = 4
PAGE_TYPE_FREELIST       = 5
PAGE_TYPE_NAME_DICT      = 6      // зарезервировано (v1.1)
PAGE_TYPE_READER_TABLE   = 7
PAGE_TYPE_SECTION_DIR    = 8      // зарезервировано
PAGE_TYPE_ZONE_META      = 9      // per-zone metadata-блок (§12.2)

PAGE_SUPERBLOCK_A        = 0
PAGE_SUPERBLOCK_B        = 1
PAGE_META_A              = 2
PAGE_META_B              = 3
PAGE_DATA_FIRST          = 4

SUPERBLOCK_RECORD_SIZE   = 4096
PAGE_HEADER_SIZE         = 40     // txn и lsn — u64 (B-2, R-2)
NODE_HEADER_SIZE         = 56     // 40 (page) + 16 (node)
LEAF_VALUE_SIZE          = 20     // flags u16 (B-1)
OVERFLOW_HEADER_SIZE     = 48     // 40 + next u32 + data_len u32
FREELIST_HEADER_SIZE     = 64     // 40 + next u32 + rsv u32 + free_txn u64 + count u32 + rsv u32
ZONE_META_HEADER_SIZE    = 80

MAX_TREE_DEPTH           = 8
MAX_NAME_WIRE            = 255
MAX_LABEL                = 63
MAX_KEY_SIZE             = MAX_NAME_WIRE + 6          // 261
LEAF_RESTART_INTERVAL    = 8
BRANCH_RESTART_INTERVAL  = 4
MAX_OVERFLOW_PAGES       = 64
MAX_RDLENGTH             = 65535  // предел протокола для одного RR (u16)

MIN_LEAF_ITEM_BYTES      = 25     // 4 + 1 (минимальный ключ) + 20 (LeafValue)
MIN_BRANCH_ITEM_BYTES    = 9      // 4 + 1 + 4 (child_page)
INLINE_VALUE_MAX         = 512
MAX_RRSET_PAYLOAD        = 196_605   // 65535 (rdlen) + 2*65535 (префиксы длин); цепочка покрывает с запасом
MAX_RRSETS_PER_ZONE      = 50_000_000  // hard limit формата; операционный дефолт 10M
MAX_CUT_SUBTREE_RECORDS  = 100_000
MAX_FORWARD_UPSTREAMS    = 32
MAX_FORWARD_BLOB         = 4096
MAX_ZONE_META            = 262_144   // 256 KiB — предел блока §12.2 с overflow-цепочкой
MAX_ZONE_META_PAGES      = ceil(MAX_ZONE_META / (page_size - OVERFLOW_HEADER_SIZE))  // 65 @4096, 33 @8192, 17 @16384

MODE_NOSYNC              = 0
MODE_NOMETASYNC          = 1
MODE_SYNC                = 2
DEFAULT_SYNC_MODE        = MODE_SYNC          // MODE_NOSYNC — экспериментальный, по умолчанию выключен (§13.6)

READER_SLOTS             = 1024
READER_SLOTS_PER_THREAD  = 4        // вложенные снапшоты одного потока (§6.3)
GC_INTERVAL_MS           = 3_600_000 // maintenance-задача GC tombstone-зон раз в час (§13.8)
MAX_RECLAIM_ZONES_PER_COMMIT = 16       // opportunistic GC на коммите (домен §5.2.4)
MAX_RECLAIM_PAGES_PER_COMMIT = 8_192    // предохранитель latency коммита; format-side default
READER_SLOT_SIZE         = 32
READER_PAGE_DESC_SIZE    = 32     // собственный дескриптор страницы reader table (не §7)
STALE_READER_TIMEOUT_MS  = 30_000     // только для диагностики/метрик, НЕ для вытеснения (R-4, SEC-ZF-007)

LOCK_FILE_SUFFIX         = ".lock"    // <zonefile>.lock, LOCK_EX|LOCK_NB только у writer (SEC-ZF-009)

MAX_TTL                  = 0x7FFF_FFFF
MAX_FILE_PAGES           = 0xFFFF_FFFE

MAX_COMPARISONS_PER_LOOKUP = 8 * (8 + LEAF_RESTART_INTERVAL)   // 128, §10.3 (R-13)
```

Количество страниц таблицы читателей (B-2), фиксированная точка по **собственному** дескриптору страницы:

```
usable_per_page = page_size - READER_PAGE_DESC_SIZE          // slots начинаются с +32 на каждой странице
pages           = ceil(READER_SLOTS * READER_SLOT_SIZE / usable_per_page)
region_len      = pages * page_size                          // кратен page_size ⇒ кратен 64
```

| `page_size` | usable | pages | `region_len` |
|---|---|---|---|
| 4096 | 4064 | **9** | 36 864 |
| 8192 | 8160 | 5 | 40 960 |
| 16384 | 16352 | 3 | 49 152 |

Регион всегда начинается с `page_reader_table * page_size` (кратно `page_size` ≥ 4096), поэтому `off % 64 == 0` выполняется тождественно; проверка при открытии обязательна (SEC-ZF-014).

Типы-маркеры ключей:

| Имя | Значение | Назначение |
|---|---|---|
| `T_NODE` | 0x0000 | псевдо-RR: атрибуты имени (ENT, cut, glue, apex) |
| `T_ZONE_ENTRY` | 0xFFFE | приватный диапазон RFC 6895; ключ каталога зон |
| `T_RRSIG` | 46 | настоящий тип; `subtype` = covered type |
| `class IN` | 1 | единственный класс v1 |

Флаги `feature_flags_required` / `feature_flags_optional`:

| Бит | Имя | Обяз. | Смысл |
|---|---|---|---|
| 0 | F_FRONT_CODED_KEYS | да | leaf/branch items фронт-кодированы |
| 1 | F_RRSIG_SUBTYPE | да | в ключе есть `subtype` |
| 2 | F_READER_TABLE | да | таблица читателей присутствует |
| 3 | F_OVERFLOW_V1 | да | overflow-страницы v1 (байтовый поток, RDATA может разрываться, §11.4) |
| 4 | F_NSEC_CANONICAL_ORDER | да | порядок ключей = RFC 4034 §6.1 |
| 5 | F_ZONE_META_BLOCK | да | `ZoneEntry.meta_root` и блок §12.2 |
| 8 | F_NSEC3 | нет | резерв: NSEC3-дерево |
| 9 | F_RDATA_NAME_REFS | нет | резерв: компрессия имён в RDATA (v1.1) |
| 10 | F_MANIFEST_BLAKE3 | нет | резерв: секция манифеста |
| 63 | F_EXPERIMENTAL | нет | экспериментальная сборка |

**Совместимость:** неизвестный бит в `required` → `UnsupportedVersion`; в `optional` — игнорируется.

---

## 3. Физическая раскладка файла

```
offset 0                +-----------------------------------+
                        | Superblock A (запись 4096 байт)   |  page 0
                        +-----------------------------------+
     1 * page_size      | Superblock B (копия)              |  page 1
                        +-----------------------------------+
     2 * page_size      | Meta A                            |  page 2
                        +-----------------------------------+
     3 * page_size      | Meta B                            |  page 3
                        +-----------------------------------+
     4 * page_size      | Reader table (9 страниц @4096)    |  pages 4..12
                        +-----------------------------------+
                        | data pages                        |  pages 13..
                        |  branch / leaf / overflow         |
                        |  freelist bucket / zone meta      |
                        |  зарезервированные секции         |
                        +-----------------------------------+
                       page_count_max * page_size = map_size (EOF, sparse)
```

- Файл создаётся `ftruncate(map_size)`; **дефолт `map_size = 4 GiB`** (1 048 576 страниц по 4096), в тестах 64–256 МиБ.
- `page_count_max = map_size / page_size` ≥ 16.
- Страницы 0–3 занимаются при создании и не переиспользуются.
- Данные — непрерывный диапазон `[page_data_first, page_count_high_water)`.
- `page_data_first` вычисляется, а не фиксирован: `4 + reader_table_pages`.
- **Reader table — отдельный регион** `[page_reader_table*page_size, +pages*page_size)`: `off % 64 == 0`, `len = pages*page_size`, `pages = ceil(32768/(page_size−32))`. Это **единственный** writable-маппинг (`PROT_READ|PROT_WRITE`, `MAP_SHARED`); всё остальное — `PROT_READ`, запись через `pwritev` (§6.1, §21.4).

### 3.1. `map_size`, квоты и стратегия роста

| Аспект | Поведение |
|---|---|
| Дефолт | 4 GiB (`--map-size`) |
| Тесты/CI | 64–256 МиБ; stability-тест 10M RRset — 2 GiB |
| Квота контейнера | `ftruncate` sparse обычно не расходует квоту; на ФС без sparse / с project quota возможен отказ |
| `mmap` невозможен (ENOMEM/EPERM/ENODEV) | отказ старта `MapAllocFailed { size, errno, hint }`; тихое урезание запрещено |
| Файл короче `page_count_max * page_size` | `TruncatedFile` — и для writer, и для reader; `ftruncate` только в цикле создания (§4, §13.1) |
| Проверка перед **каждым** `mmap` | `fstat`: `dev/ino` совпадают с полученными при `open` **и** `st_size == page_count_max * page_size`; иначе `TruncatedFile` (а не SIGBUS при truncate-race) |
| `high_water == page_count_max` | `MapFull` при записи; чтение продолжает работать (§16) |

**Стратегия роста (в M1 не реализуется).** В v1 `page_count_max` живёт только в неизменяемом superblock, поэтому роста «на ходу» нет:

1. writer фиксирует намерение `grow` и перестаёт публиковать новые снапшоты;
2. ждёт освобождения всех снапшотов (`oldest_reader_txn == txnid`, бюджет ≤ 1 мс, иначе `ReadersStalled`);
3. выполняет offline `zonefile compact --out <new> --map-size <new>` → `fsync` → `rename` → `reopen`; переключение между батчами;
4. v1.1 (резерв): `map_size` в meta + протокол «quiesce → `ftruncate` → `mmap` → resume».

### 3.2. Инварианты файла

| ID | Инвариант |
|---|---|
| I-1 | `MAGIC`, `version_major`, `page_size` в обеих копиях superblock совпадают; иначе `Corrupt` |
| I-2 | `page_count_high_water ≤ page_count_max`; размер файла = `page_count_max * page_size` |
| I-3 | Активна ровно одна meta: среди валидных мет с `txnid ≤ durable_txn` выбирается максимальная (§13.7) |
| I-4 | Страницы, достижимые из `meta(T)`, не изменяются, пока `reclaim_txn < T` (правило §14) |
| I-5 | `txnid` строго возрастает, `txnid ≠ 0` |
| I-6 | `durable_txn ≤ txnid(active)`; страница с `free_txn > reclaim_txn` не выдаётся (правило и обоснование — §14) |
| I-7 | Ключи в дереве строго возрастают по компаратору §8.3 |
| I-8 | `branch.key[i]` = точный минимум поддерева `branch.child[i]` |
| I-9 | Глубина любого дерева ≤ `MAX_TREE_DEPTH` |
| I-10 | Ни одна страница не достижима из двух мест |
| I-11 | Свободные страницы не достижимы из активной meta |
| I-12 | Каждая meta содержит **полный** набор корней (дерево зон, freelist, reader table, счётчики) — восстановление не зависит от предыдущей meta |

---

## 4. Superblock (page 0 и page 1)

Запись 4096 байт; остаток страницы (при `page_size > 4096`) не используется и не валидируется.

| Смещение | Размер | Поле | Описание |
|---|---|---|---|
| +0 | 8 | `magic` | `b"PULSEZF1"` |
| +8 | 2 | `version_major` | 1 |
| +10 | 2 | `version_minor` | 0 |
| +12 | 4 | `page_size` | 4096/8192/16384 |
| +16 | 4 | `page_count_max` | `map_size / page_size` |
| +20 | 8 | `feature_flags_required` | §2 |
| +28 | 8 | `feature_flags_optional` | §2 |
| +36 | 2 | `checksum_algo` | 1 = crc32c (§19) |
| +38 | 1 | `endianness` | 0 = little |
| +39 | 1 | `superblock_copy` | 0 = A, 1 = B |
| +40 | 4 | `crc32c` | CRC записи `[0,4096)` с этим полем = 0 |
| +44 | 16 | `instance_uuid` | UUIDv7 |
| +60 | 8 | `created_unix_ns` | |
| +68 | 8 | `reader_region_off` | `= page_reader_table * page_size` (B-5: отдельный writable-маппинг) |
| +76 | 8 | `reader_region_len` | `= reader_table_pages * page_size` |
| +84 | 4 | `reader_region_align` | `= page_size` |
| +88 | 4 | `page_meta_a` | 2 |
| +92 | 4 | `page_meta_b` | 3 |
| +96 | 4 | `page_data_first` | `4 + reader_table_pages` |
| +100 | 4 | `page_reader_table` | 4 |
| +104 | 4 | `page_reader_table_count` | 9 при 4096 (`ceil(32768/(page_size-32))`) |
| +108 | 4 | `section_count` | 0..16 |
| +112 | 512 | `sections[16]` | 16 дескрипторов по 32 байта |
| +624 | … | `reserved` | нули до 4088 |
| +4088 | 4 | `reserved_tail` | 0 |
| +4092 | 4 | `reserved_tail2` | 0 (последние 4 байта записи) |

> `sections` занимает байты `[+112, +624)`; байты `[+624, +4088)` — `reserved` (нули).

Дескриптор секции (32 байта): `id u16 | version u16 | first_page u32 | page_count u32 | flags u64 | reserved[12]`.

| id | Имя | v1 | Назначение |
|---|---|---|---|
| 1 | CORE | да | superblock, meta, деревья, freelist, reader table |
| 2 | NAME_DICT | нет | резерв: словарь имён (v1.1) |
| 3 | CHANGESET_LOG | нет | резерв: журнал изменений каталога (инкрементальный `ZoneIndex`) |
| 4 | ZONE_STATS | нет | резерв |
| 5 | KEYRING_REFS | нет | резерв |
| 6 | MANIFEST | нет | резерв: BLAKE3-манифест |
| 7 | IXFR_HISTORY | нет | резерв: персистентная история IXFR-out |
| 0x8000+ | vendor | — | приватные расширения |

Superblock B — копия с `superblock_copy = 1`. Расхождение `page_size`/`page_count_max`/`instance_uuid` между копиями → `Corrupt`. При открытии побеждает копия с валидным CRC (при обеих — A).

**Создание файла** (B-12) — строгая последовательность, один раз:

```
1. open(path, O_CREAT|O_EXCL|O_RDWR, 0600) + fchmod(0600)   # только создание
2. ftruncate(map_size); mmap(PROT_READ)
3. записать superblock A и B (fields, CRC); pwrite, оба
4. записать начальную meta в page 2:
     txnid = 1, durable_txn = 1, все корни 0,
     page_count_high_water = page_data_first, free_page_count = 0,
     next_zone_seq = 1, meta_flags = 0
5. записать страницы reader table (type 7, crc=0, все слоты 0)
6. page 3 оставить нулевой (второй meta-слот невалиден)
7. fdatasync(fd); fsync каталога
```

`durable_txn = 1` обязателен: иначе правило выбора meta (§13.7: `txnid ≤ durable_txn`) не находит ни одной валидной meta и свежий файл не открывается. **Первый пользовательский коммит — `txnid = 2`.**

**Отказы при создании (R-20).** Частично созданный файл не восстанавливается и не открывается; удаляет его **создатель** (`ZoneFile::create`), а не `open`:

| Момент | Ошибка | Кто удаляет файл |
|---|---|---|
| шаг 1–2 (создание/`ftruncate`) | `MapAllocFailed` / `Io` | создатель (файл мог не появиться — удаление best-effort) |
| шаг 3–5 (superblock/meta/reader) | `Io` | создатель |
| шаг 7 (`fdatasync`/`fsync`) | `Io` | создатель |
| `open()` на существующем частичном файле | `CorruptNoValidMeta` / `BadReaderRegion` / `TruncatedFile` | **никто** — `open` read-only по контракту, файл остаётся для диагностики |

`open()` никогда не удаляет и не «дочинивает» файл (SEC-ZF-011); решение об удалении — только у администратора.

---

## 5. Meta-страница (page 2 и page 3)

Собственная раскладка (не §7). Активна валидная с максимальным `txnid` при условии `txnid ≤ durable_txn` (§13.7).

| Смещение | Размер | Поле | Описание |
|---|---|---|---|
| +0 | 4 | `page_type` | 1 |
| +4 | 2 | `meta_flags` | bit0 NEEDS_FSCK, bit1 READONLY_HINT, bit2 COMPACTION_SUGGESTED, bit3 EXPERIMENTAL |
| +6 | 2 | `reserved0` | 0 |
| +8 | 4 | `page_no` | 2 или 3 |
| +12 | 4 | `crc32c` | CRC всей страницы, поле = 0 |
| +16 | 8 | `txnid` | ≥ 1 |
| +24 | 8 | `durable_txn` | ≤ `txnid`; см. §13.7 |
| +32 | 2 | `version_major` | 1 |
| +34 | 2 | `version_minor` | 0 |
| +36 | 4 | `page_size` | копия |
| +40 | 4 | `page_count_high_water` | |
| +44 | 4 | `free_page_count` | страниц в freelist (включая «молодые») |
| +48 | 4 | `zone_dir_root` | 0 = каталог пуст |
| +52 | 2 | `zone_dir_level` | 0 = пусто, 1 = корень-лист |
| +54 | 2 | `reserved1` | 0 |
| +56 | 4 | `zone_count` | живые зоны (без tombstone) |
| +60 | 4 | `freelist_head` | первый bucket (самый старый `free_txn`) |
| +64 | 4 | `freelist_tail` | последний bucket |
| +68 | 4 | `freelist_buckets` | число bucket-страниц |
| +72 | 4 | `freelist_entries` | суммарное число `PageId` |
| +76 | 4 | `reader_region_off` | копия |
| +80 | 4 | `reader_region_len` | копия |
| +84 | 4 | `reserved2` | 0 |
| +88 | 8 | `oldest_reader_txn` | advisory (на момент коммита) |
| +96 | 8 | `total_rrsets` | |
| +104 | 8 | `total_rrs` | |
| +112 | 8 | `commit_unix_ns` | |
| +120 | 8 | `reclaim_txn` | вычислен при коммите |
| +128 | 4 | `next_zone_seq` | аллокатор `ZoneId` (§12.3) |
| +132 | 4 | `name_dict_root` | 0 в v1 |
| +136 | 4 | `changeset_log_root` | 0 в v1 |
| +140 | 4 | `manifest_root` | 0 в v1 |
| +144 | 4 | `last_error_code` | диагностика |
| +148 | 4 | `last_error_page` | диагностика |
| +152 | 8 | `last_error_txn` | диагностика |
| +160 | 32 | `fsck_hint` | ASCIIZ |
| +192 | … | `reserved` | нули до конца страницы |

Валидация meta при чтении: `page_type`, `page_no == слот`, CRC, версия, `page_size`, `page_count_high_water ≤ page_count_max`, корни < `high_water` (или 0), `zone_dir_level ≤ MAX_TREE_DEPTH`, `freelist_entries ≤ page_count_high_water`, `durable_txn ≤ txnid`.

**Правило записи:** writer всегда пишет **неактивную** meta (младший `txnid`); активная не перезаписывается.

---

## 6. Таблица читателей: регион, маппинг, протокол

### 6.1. Регион, маппинг, дескриптор страницы (B-5, SEC-ZF-014)

| Свойство | Значение |
|---|---|
| Смещение | `reader_region_off = page_reader_table * page_size` |
| Длина | `reader_region_len = pages * page_size`, `pages = ceil(32768 / (page_size − 32))` |
| Выравнивание | `off % 64 == 0` **обязательно** (проверяется при открытии; выполняется, т.к. `page_size` кратен 64) |
| Слоты | с каждого `page_base + 32`, шаг 32 байта, 8-байтовые атомарные поля |
| Маппинг №1 | весь файл: `PROT_READ | MAP_SHARED` — superblock, meta, деревья, overflow, freelist, zone meta |
| Маппинг №2 | **только регион reader table**: `PROT_READ|PROT_WRITE | MAP_SHARED`, тот же fd, `offset = reader_region_off`, `len = reader_region_len` |
| Запись данных | исключительно `pwritev` по fd; writable-маппинга данных нет |
| CRC | страницы reader table **исключены**: `crc32c` MUST 0, валидатор и `fsck` пропускают |
| Содержимое региона | дескрипторы страниц и слоты; ссылок в граф нет |

Собственный дескриптор страницы reader table (32 байта; **не** §7):

| Смещение | Размер | Поле |
|---|---|---|
| +0 | 4 | `page_type` = 7 |
| +4 | 2 | `version` = 1 |
| +6 | 2 | `page_flags` (0) |
| +8 | 4 | `page_no` (проверяется против слота) |
| +12 | 4 | `slots_used_in_page` (≤ `(page_size−32)/32`) |
| +16 | 4 | `crc32c` MUST 0 (поле зарезервировано под будущий формат) |
| +20 | 4 | `reserved0` |
| +24 | 8 | `reserved1` |
| +32 | … | слоты |

`payload_len` для `PAGE_TYPE_READER_TABLE` = **`page_size − 32`** — это и есть область слотов страницы; значение не меняется при частичном заполнении (в отличие от overflow/freelist, где `payload_len` отражает фактические данные). Пустые слоты — нули.

**Проверки при открытии (SEC-ZF-014):**

1. `off % 64 == 0`.
2. `pages == ceil(READER_SLOTS*32 / (page_size − 32))` и `len == pages * page_size`.
3. `off + len ≤ page_count_max * page_size`.
4. `st_dev/st_ino` файла совпадают с полученными при `open` (закрытие TOCTOU перед `mmap`).
5. `mmap` региона с `PROT_WRITE` — единственный; при неудаче → `MapAllocFailed`.
6. Каждая страница: `page_type == 7`, `page_no` совпадает, `slots_used_in_page ≤ (page_size−32)/32`.

**Правило когерентности:** оба маппинга — `MAP_SHARED` на один inode; изменения видны через page cache немедленно. Все обращения к полям слотов — **только** атомарные (`AtomicU64`, `Relaxed`/`Acquire`/`Release`), включая чтение: обычная загрузка `u64` не даёт гарантий против переупорядочивания и разрыва. Слоты выровнены на 8 байт (база кратна 32).

**Границы ущерба:** слот не содержит ссылок; его порча даёт только (а) ложное «читатель жив» (writer тормозит → `ReadersStalled`), (б) ложное «свободен» (утечка страниц до `fsck`), (в) неверный `active_txn` (пиннинг не тех страниц → ловится CRC при чтении). Повреждение деревьев невозможно — запись только внутри региона.

### 6.1.1. Эксклюзивность writer'а и блокировки (SEC-ZF-009)

| Роль | Механизм | Правило |
|---|---|---|
| writer | отдельный файл `<zonefile>.lock`: `O_CREAT|O_RDWR, 0600`, `flock(LOCK_EX|LOCK_NB)` | второй writer → `Busy`; lock снимается смертью процесса |
| reader | **никаких flock** | регистрируется только в reader table; не блокирует writer'а и не блокируется им |
| внешний писатель | исключён правами (`0600`, каталог `0700`) + `O_NOFOLLOW` | `fstat`/`dev`/`ino` перед `mmap` |

Читатель и writer открывают **данные** без блокировок; единственный «замок» — lock-файл, который берёт только writer. Это снимает прежнее требование `LOCK_SH` у читателей (оно мешало эксклюзивности и не защищало от усечения).

### 6.2. Слот (32 байта)

| Смещение | Размер | Поле | Описание |
|---|---|---|---|
| +0 | 8 | `owner_token` | 0 = свободен; `(pid<<32) | incarnation` |
| +8 | 8 | `active_txn` | 0 = не держит; иначе удерживаемый `txnid` |
| +16 | 8 | `heartbeat_ns` | `CLOCK_MONOTONIC` |
| +24 | 8 | `flags` | bit0 LONG_HOLD, bit1 IN_PROCESS |

`incarnation` — `starttime` (поле 22 `/proc/<pid>/stat`), усечённое до u32.

### 6.3. Двухфазный пин (B-4) и жизненный цикл снапшота (R-4, R-5)

Пиннинг выполняет **сам адаптер** при взятии снапшота: `ZoneFile::snapshot()` → `pin()`, `Drop` последнего держателя → `unpin()`. Пользователь (домен/сервер) не вызывает `pin`/`unpin` напрямую — это внутренние операции адаптера.

Нормативная модель (refcount):

| Сущность | Поведение |
|---|---|
| `SnapshotInner` | общий `Arc`-объект: `map`, `txnid`, `slot_id`, `pins: u32` (refcount держателей) |
| `Snapshot` | тонкая обёртка над `Arc<SnapshotInner>`; `Clone` **не** пиннит повторно (атомарный refcount, ≤ 20 нс) |
| Первый держатель | выполняет `pin()` (двухфазный протокол ниже), заполняет `slot_id` |
| Последний `Drop` | выполняет `unpin()` (RAII-`DropGuard`), затем освобождает `SnapshotInner` |
| Вложенные снапшоты | разрешены: на поток выделяется до `READER_SLOTS_PER_THREAD = 4` слотов; каждый независимый снапшот занимает свой слот. Если все слоты потока заняты — `ReaderContended` (backoff 10 µs, ≤ 8 попыток) |
| Утечка держателя | живой поток, забывший `Snapshot`, держит `active_txn` → writer не переиспользует страницы этого txn; при исчерпании — `NoSpace` (retryable), метрика `readers_stalled`, алерт. Вытеснение — только по мёртвому PID (§6.4); «лечение» утечки — рестарт потока/процесса |

Требование к `Drop`: `unpin` выполняется **до** освобождения `Arc` и не паникует; порядок «сначала `active_txn = 0`, потом декремент `pins`» не критичен, но `active_txn = 0` обязан быть виден writer'у (`Release`).

```
pin() -> Txn:
  for attempt in 0..PIN_ATTEMPTS(=8):
      T = load(active_txn_global, Acquire)      # in-process arc-swap
      store(slot.active_txn, T, Release)        # фаза 1: публикация
      T2 = load(active_txn_global, Acquire)     # фаза 2: пере-проверка
      if T2 == T: return T
      store(slot.active_txn, 0, Release)        # откат публикации
  return Err(ReaderContended)                   # 8 попыток недостаточно — backoff 10 мкс и снова

unpin(): store(slot.active_txn, 0, Release)
```

**Почему это корректно.** Пока `T` — активная meta, writer не может освободить страницы графа `T`: освобождение страниц, заменённых в `T+1`, требует `T+1 ≤ reclaim_txn ≤ oldest_reader_txn`, а `oldest_reader_txn ≤ txnid(active) = T < T+1` (пока `T` активна). Если за время между фазами 1 и 2 meta продвинулась, читатель откатывается и повторяет — и **до** успешной проверки не читает ни одной страницы данных. После успешной проверки `slot.active_txn = T` гарантирует, что любой следующий коммит увидит `oldest_reader_txn ≤ T` и не тронет граф `T`.

Refcount-вариант (для вложенных снапшотов в одном потоке): на поток — 2–4 слота; `pin` занимает любой свободный слот потока; `unpin` освобождает. Требование «один писатель `active_txn` на слот» сохраняется (слот принадлежит одному потоку).

### 6.4. Регистрация и вытеснение (R-4)

| Операция | Правило |
|---|---|
| Регистрация | CAS `owner_token: 0 → token`; слоты распределяются по потокам; нет свободных → `TooManyReaders` |
| Dereg | `active_txn = 0`, затем `owner_token = 0` (порядок обязателен) |
| Heartbeat | раз в 1 с `store_relaxed(heartbeat_ns, now)` |
| Вытеснение | **только** если PID мёртв **или** `incarnation` не совпадает. Живой PID с совпадающим `incarnation` не вытесняется **никогда** (SEC-ZF-007) |
| `heartbeat` старше `STALE_READER_TIMEOUT_MS` | вытеснения нет; это только диагностика: метрика `readers_stalled`, событие `ReadersStalled`, предупреждение для `LONG_HOLD`-слотов |
| `LONG_HOLD` | снимается только смертью процесса; влияет на диагностику (порог предупреждения), не на вытеснение |

`oldest_reader_txn` = минимум `active_txn` по слотам, где **`owner_token ≠ 0` И `active_txn ≠ 0`**.

- Слот с `active_txn = 0` **никогда не считается читателем**: 0 означает «пин не взят» (простой потока, откат двухфазного пина §6.3, окно между `dereg`-записями). Включение такого слота в минимум дало бы `oldest_reader_txn = 0` → `reclaim_txn = 0` → переиспользование невозможно → ложный `NoSpace`/`MapFull`.
- Если подходящих слотов нет — **читателей нет**, и берётся `txnid(active)` (консервативный запас: страницы, освобождённые текущей транзакцией, всё равно не выдаются — §11.7 п.3).

`reclaim_txn = min(durable_txn, oldest_reader_txn)`.

**Worked example (B-1).** 1024 слота, на поток до 4:

| Слот | `owner_token` | `active_txn` | Участвует в минимуме? |
|---|---|---|---|
| #0 | 0 (свободен) | 0 | нет (не занят) |
| #1 | pid=42 | **0** (откат фазы 1 пина) | **нет** (транзиентный 0) |
| #2 | pid=42 | `T` | да |

→ `oldest_reader_txn = T`. Если бы учитывался #1, минимум был бы 0 и writer не смог бы вернуть ни одной страницы.

| Слот | `owner_token` | `active_txn` | Результат |
|---|---|---|---|
| #0–#3 | pid=42 | 0 | читателей нет → `oldest_reader_txn = txnid(active)` |

Правило нормативно: транзиентный `0` в `active_txn` **никогда** не трактуется как «читатель на txn 0»; `txnid` начинается с 1 (§4).

**Порядок памяти (R-4).** Writer **обязан** читать `owner_token` и `active_txn` с `Acquire` (а не `Relaxed`): иначе публикация `active_txn = T` читателем (`Release`) может не наблюдаться, и writer освободит страницы графа `T`. Цена — один барьер на слот в начале коммита, вне hot-path. Читатель пишет `active_txn` с `Release`, `heartbeat_ns` — `Relaxed`.

> **Область M1:** внутрипроцессно (потоки одного сервера). Межпроцессный доступ не требуется в M1; структура и правила сохранены; тесты — M3.

---

## 7. Заголовок страницы данных (40 байт)

Для страниц типов **2..6, 8, 9**. Superblock (§4), meta (§5) и страницы reader table (§6.1) имеют собственные раскладки.

| Смещение | Размер | Поле | Описание |
|---|---|---|---|
| +0 | 4 | `page_type` | 2..9 |
| +4 | 2 | `page_flags` | bit0 FRONT_CODED, bit1 HAS_OVERFLOW, bit2..15 = 0 |
| +6 | 2 | `reserved0` | 0 |
| +8 | 4 | `page_no` | MUST совпадать со слотом |
| +12 | 4 | `reserved1` | 0 (выравнивание `txn`) |
| +16 | 8 | `txn` | **u64**, txnid создавшей версии |
| +24 | 8 | `lsn` | монотонный счётчик записи (диагностика) |
| +32 | 4 | `crc32c` | CRC всей страницы, поле = 0; для reader table — 0 и не проверяется |
| +36 | 4 | `payload_len` | см. таблицу |

| Тип | `payload_len` (включая заголовок) |
|---|---|
| BRANCH / LEAF | `page_size` |
| OVERFLOW | `48 + data_len` |
| FREELIST | `64 + 4*count` |
| ZONE_META | `80 + inline_len` |
| READER_TABLE | **не §7**: собственный дескриптор, `payload_len = page_size − 32` (§6.1) |

**Почему `txn` — `u64` (R-2).** Сравнение «страница создана не позже моего снапшота» при 32-битном `txn` требует epoch-арифметики (`wrap-safe` сравнение вида `(a - b) as i32 < 0`), которая ломается после 2³² коммитов и трудно проверяема в `fsck`. 8 байт на страницу — 0.2% при 4096 — дешевле риска молчаливой путаницы версий.

Проверки при чтении (R-7, дополнено):

1. `page_no` == номер слота.
2. `page_type` == ожидаемый для контекста: при `level > 0` — BRANCH, при `level == 0` — LEAF; overflow-переход — OVERFLOW; freelist — FREELIST; `ZoneEntry.meta_root` — ZONE_META. Несовпадение → `Corrupt`.
3. `txn ≤ txnid(snapshot)`.
4. CRC (кроме READER_TABLE; для неё — §6.1).
5. `payload_len` согласован с типом и не превышает `page_size`.
6. `n_items`, `n_restarts` — по фактической вместимости (§16 п.3, R-8).
7. `slots` и `restart_offsets` строго возрастают и лежат в `[items_start, page_size)`; `restart_offsets[0] == slots[0]` (item 0 всегда restart-точка); `items_start == slots[0]`.
8. `n_restarts == ceil(n_items / INTERVAL)` (фиксированный интервал; иное → `Corrupt`).
9. `shared_len ≤ длина предыдущего ключа`, `shared_len + suffix_len ≤ MAX_KEY_SIZE`.
10. RLE-имя ключа валидируется (метки 1..63, терминатор, длина ≤ 255) **до** использования в компараторе.
11. `items_start ≥ NODE_HEADER_SIZE + 2*(n_restarts + n_items)`.

---

## 8. Имена

### 8.1. Хранение

RLE: `len(label_n) label_n … len(label_1) label_1 0x00`, где `name = label_n … label_1`.

Пример: `www.example.com` → `03 63 6f 6d | 07 65 78 61 6d 70 6c 65 | 03 77 77 77 | 00`.

| Проверка | Значение |
|---|---|
| `len(label)` | 1..63; `0x00` только терминатор |
| суммарная длина | ≤ 255 байт включая терминатор |
| `0xC0..0xFF` в позиции длины | запрещено (компрессии нет) |
| терминатор | ровно один, последний байт |
| пустое имя | недопустимо |

**Инвариант lowercase (R-12).** Все имена в файле — lowercase ASCII (A–Z → a–z). Владельцы и имена внутри RDATA для типов, канонизация которых требует lowercase (RFC 6840 §5.1: NS, MD, MF, CNAME, SOA, MB, MG, MR, PTR, MINFO, MX, RP, AFSDB, RT, SIG, PX, NXT, NAPTR, KX, SRV, DNAME, A6, RRSIG, NSEC), нормализуются **загрузчиком**. Читатель RDATA-имена не парсит (это RDATA-opaque), поэтому инвариант проверяется `fsck`, а не hot-path; нарушение — дефект writer'а, а не «повреждение файла», обнаруживаемое при чтении. Для owner-имён (ключи) валидация выполняется всегда.

### 8.1.1. Выравнивание

| Объект | Требование |
|---|---|
| Страницы файла | выровнены на `page_size`; `pwritev` — page-aligned, целыми страницами |
| Слоты reader table | 8 байт (база 32-кратна) |
| `u64`-поля заголовков (`txn`, `lsn`, `durable_txn`) | 8 байт (смещения 16/24 в заголовке, 24 в meta) |
| `LeafValue`, `ZoneEntry` | 2 байта; читаются через `read_unaligned`/копию |
| `crc32c` | 4 байта (смещения 32/40/12) |
| База `mmap` | ≥ `page_size` |

### 8.2. Зачем обратный порядок

1. Канонический порядок RFC 4034 §6.1 становится порядком «слева направо».
2. Общий суффикс домена — общий **префикс** ключей → фронт-кодирование сжимает суффиксы.
3. Поддерево непрерывно; предок сортируется перед потомками (`0x00` < любой length).

### 8.3. Компаратор

`key_cmp` (не `memcmp`, см. ADR §8.2). `name_cmp` — по меткам, `memcmp` содержимого, префикс-метка меньше.

Проверочные векторы: `aa < b`; `ab < abc`; `example.com < a.example.com`; `example.com < example.org`; `z.example.com > example.com`.

### 8.4. Валидация RLE (обязательна перед сравнением, R-7)

```
validate_rle(bytes) -> Result<name_len>:
  i = 0; labels = 0
  loop:
    if i >= MAX_NAME_WIRE: return Corrupt(BadNameEncoding)
    l = bytes[i]
    if l == 0: return Ok(i+1)               # ровно один терминатор, конец
    if l > 63: return Corrupt(BadNameEncoding)
    if i + 1 + l > MAX_NAME_WIRE: return Corrupt
    i += 1 + l; labels += 1
    if labels > 127: return Corrupt(BadNameEncoding)
```

Компаратор вызывается только на провалидированных именах; при ошибке — `Corrupt`, до любого `memcmp`.

### 8.5. Словарь имён (секция `NAME_DICT`, резерв v1.1)

В v1 не используется (владельцы — в ключах, RDATA — дословно). Зарезервировано для компрессии имён в RDATA: арена `NameEntry { u16 flags, u16 entry_len, u32 parent_ref, u8 labels[] }`, дедупликация по хешу полного RLE, suffix-компрессия через `parent_ref` (имя без первой метки). Включение — `F_RDATA_NAME_REFS` + `section id 2` + `meta.name_dict_root`. Сжатые имена требуют материализации RDATA в буфер ответа — поэтому фича вне v1.

---

## 9. Ключ записи

```
key = RLE(name) || u16 type || u16 class || u16 subtype
```

| Дерево | `type` | `class` | `subtype` |
|---|---|---|---|
| Каталог зон | `T_ZONE_ENTRY` (0xFFFE) | 0 | 0 |
| Маркер имени | `T_NODE` (0x0000) | 0 | 0 |
| RRset | реальный тип | 1 (IN) | 0, кроме `T_RRSIG` (= covered type) |

`T_NODE` — всегда первый ключ имени. `RRSIG` различается по `subtype` (RFC 4034 §3). Максимальный ключ 261 байт. Ключи уникальны.

---

## 10. Узлы B+tree

### 10.1. Заголовок узла

Следует за заголовком страницы (+40), 16 байт.

| Смещение | Размер | Поле |
|---|---|---|
| +40 | 2 | `level` (0 = лист) |
| +42 | 2 | `n_items` |
| +44 | 2 | `n_restarts` |
| +46 | 2 | `node_flags` (bit0 SORTED_VALIDATED) |
| +48 | 4 | `free_bytes` |
| +52 | 4 | `items_start` (первый байт области элементов) |

```
+56                        restart_offsets: u16[n_restarts]
+56+2*n_restarts           slots:           u16[n_items]
items_start .. page_size   items (упакованы вниз от конца страницы)
```

**Единая формула размера (B-9):**

```
encoded_size = NODE_HEADER_SIZE + 2*(n_restarts + n_items) + Σ item_bytes
free_bytes   = page_size - encoded_size          # ≥ 0 обязательно
```

Порог переполнения **один** для листа и ветвления: `encoded_size > page_size`. Заголовок **входит** в `encoded_size`. Прежние расхождения (`page_size-48` для листа, `page_size-32` для ветвления) отменены.

### 10.2. Фронт-кодирование

Item листа:

| Смещение | Размер | Поле |
|---|---|---|
| +0 | 2 | `shared_len` (0 у restart) |
| +2 | 2 | `suffix_len` (≥ 1) |
| +4 | `suffix_len` | `suffix` |
| +4+suffix_len | 20 | `LeafValue` (§11.1) |
| +4+suffix_len+20 | `payload_bytes` | `payload` только при `kind=INLINE` |

`item_bytes = 4 + suffix_len + 20 + (INLINE ? rdlen + 2*rr_count : 0)`.

Item ветвления: `shared_len u16 | suffix_len u16 | suffix | child_page u32`.

Правила: полный ключ = `prev_key[0..shared_len] || suffix`; restart — `shared_len = 0`; restart-точки каждые 8 (лист) / 4 (ветвление), первая всегда; `n_restarts == ceil(n_items/INTERVAL)`; writer при любом изменении **перестраивает страницу целиком** из логического массива `(key, value)`.

**Формат значения зависит от типа ключа (`type` в хвосте ключа):**

| `type` | Значение в листе | `item_bytes` |
|---|---|---|
| `T_ZONE_ENTRY` (0xFFFE) | `ZoneEntry` (72 байта, §12.1) — **без `LeafValue`** | `4 + suffix_len + 72` |
| `T_NODE` (0x0000) | `LeafValue` (20) с `kind = NODE` | `4 + suffix_len + 20` |
| остальные (RRset) | `LeafValue` + payload при `INLINE` | `4 + suffix_len + 20 + payload` |

`fsck` проверяет соответствие: для `T_ZONE_ENTRY` длина item'а ровно `4 + suffix_len + 72` и `rdlen`/`rr_count` из `LeafValue` не читаются; для `T_NODE` — `kind == 0`, `rr_count == 0`; для RRset — `kind ∈ {1,2}` и payload сходится с `rdlen + 2*rr_count`.

### 10.3. Три примитива поиска (B-6, R-13)

```
node_lower_bound(page, k) -> usize      # первый i: key[i] >= k   (или n_items)
node_upper_bound(page, k) -> usize      # первый i: key[i] >  k   (или n_items)
node_predecessor(page, k) -> Option<usize>  # последний i: key[i] <= k
```

Все три — бинарный поиск по restart-точкам (ключи restart доступны напрямую) + линейный проход внутри группы (≤ INTERVAL). `predecessor(k) = upper_bound(k) - 1`; если `k < key[0]` → `None`.

| Операция | Примитив |
|---|---|
| Спуск по ветвлению | `predecessor` (сепаратор = минимум ребёнка) |
| Точный поиск RRset | `lower_bound`, затем сравнение `key == target` |
| Вставка | `insert_pos = upper_bound` (для уникальных ключей совпадает с точкой вставки после равного) |
| Удаление | `lower_bound` + проверка равенства |

**Бюджет сравнений (R-13):** на уровень ≤ `log2(n_restarts) + INTERVAL` ≈ 7 + 8; глубина ≤ 8; итого ≤ `MAX_COMPARISONS_PER_LOOKUP = 128`. Курсор `next_name` — не более `4 * MAX_KEY_SIZE` байт сравнений на шаг.

### 10.4. Сепараторы

`branch.key[i]` = точный минимум поддерева. Обновляется на COW-пути при изменении первого ключа ребёнка (вставка/удаление/borrow/merge/collapse).

---

## 11. Значение листа: RRset

### 11.1. `LeafValue` (20 байт, B-1)

| Смещение | Размер | Поле |
|---|---|---|
| +0 | 1 | `kind` (0 = NODE, 1 = INLINE, 2 = OVERFLOW) |
| +1 | 1 | `reserved0` |
| +2 | 2 | `flags` — **u16**, `RR_FLAG_*` / `NODE_FLAG_*` |
| +4 | 2 | `rr_count` |
| +6 | 2 | `reserved1` |
| +8 | 4 | `ttl` |
| +12 | 4 | `val_u32` (INLINE: 0; OVERFLOW: первый `PageId`) |
| +16 | 2 | `rdlen` |
| +18 | 2 | `reserved2` |

`flags` расширены до u16, потому что `NODE_FLAG_*` использует биты 0..11 (в u8 не помещались).

### 11.2. Payload

```
payload = { u16 rdlength; u8 rdata[rdlength] } * rr_count
```

Инварианты: `0 ≤ rdlength ≤ MAX_RDLENGTH (65535)` (u16 — предел протокола; 0 допустим для типов, где это законно); `sum(rdlength) == rdlen`; `payload_bytes = rdlen + 2*rr_count ≤ MAX_RRSET_PAYLOAD`; RR отсортированы по каноническому RDATA (RFC 4034 §6.3); `kind=INLINE` ⟺ `payload_bytes ≤ INLINE_VALUE_MAX` **и** item целиком влезает в страницу (иначе OVERFLOW); `kind=NODE` ⟺ ключ `T_NODE`, `rr_count=rdlen=0`, `ttl=0`.

### 11.3. Флаги

| Бит | Имя | Смысл |
|---|---|---|
| 0 | APEX | owner = apex |
| 1 | DELEGATION | NS без SOA (cut) |
| 2 | SECURE_DELEGATION | cut с DS |
| 3 | GLUE | ниже cut, glue (A/AAAA) |
| 4 | OCCLUDED | ниже cut, не authoritative |
| 5 | WILDCARD | owner начинается с `*` |
| 6 | EMPTY_NON_TERMINAL | только предок |
| 7 | DNSSEC_SIGNED | есть RRSIG с этим covered type |
| 8 | TTL_NORMALIZED | TTL изменён writer'ом (clamp при записи / min при импорте), §11.5 |
| 9 | CHILDREN_MAY_EXIST | есть потомки: существует ключ с префиксом `RLE(n)` **без терминатора**, у которого следующий байт ∈ `0x01..0x3F` (длина метки); байт `0x00` там означает владельца, а не потомка (§13.3) |
| 10 | NSEC3 | резерв |
| 11 | CUT_BELOW | ниже есть cut |
| 12..15 | reserved | 0 |

Флаги материализуются writer'ом; query-путь по предкам не ходит.

### 11.4. Overflow: RDATA может разрываться между страницами (B-11, решение Оркестратора)

**Выбор:** overflow-цепочка — это единый **байтовый поток**, нарезанный по границам страниц; ни RR, ни его RDATA не обязаны совпадать с границей страницы. Причина: ограничение «один RR ≤ page_size−50» (4046 байт при 4096) ниже протокольного максимума `rdlength = 65535` и отсекало бы легитимные крупные TXT/URI-записи — это дыра совместимости, а не осознанный компромисс.

| Смещение | Размер | Поле |
|---|---|---|
| +0 | 40 | `PageHeader` (`page_type = 4`) |
| +40 | 4 | `next_page` (0 = конец цепочки) |
| +44 | 4 | `data_len` (≤ `page_size − 48`) |
| +48 | `data_len` | `data` — очередной кусок байтового потока |

**Логическое содержимое цепочки** — ровно `payload_bytes = rdlen + 2*rr_count` байт:

```
payload = { u16 rdlength; u8 rdata[rdlength] } * rr_count
```

нарезанные последовательно: страница 1 несёт первые `data_len` байт, страница 2 — следующие и т.д. Разрыв может проходить внутри `rdlength`, внутри `rdata`, между RR — это норма.

Инварианты:

- `sum(data_len по цепочке) == payload_bytes` (проверять с `checked_add`).
- `0 ≤ rdlength ≤ 65535` для каждого RR (u16 — предел протокола). `RdataTooLarge` возникает только при попытке записи RR с `rdata.len() > 65535` из домена; `rdlength = 0` допустим для типов, где это законно (NULL и т.п.) — решает домен.
- `payload_bytes ≤ MAX_RRSET_PAYLOAD = 196 605` (= 65 535 + 2×65 535, предел протокола и полей формата).
- `payload_bytes ≤ MAX_OVERFLOW_PAGES × (page_size − 48)`: при 4096 это 259 072 ≥ 196 605, поэтому лимит страниц не связывает; максимальное практическое число страниц — **49** (`ceil(196605/4048)`).
- Циклы запрещены (детект по счётчику переходов, ≤ `MAX_OVERFLOW_PAGES`), каждая страница проходит CRC.
- `page_flags.HAS_OVERFLOW` выставляется в листе, `val_u32` = первый `PageId`.

**Чтение (контракт API, §20.3).** RDATA отдаётся как `Rr<'a>` (`domain-model` §5.1):

| Метод `Rr` | Поведение |
|---|---|
| `len() -> usize` | `rdlength` |
| `as_slice() -> Option<&'a [u8]>` | `Some` только если байты **непрерывны** в маппинге: inline-RDATA или RR, целиком попавший в одну overflow-страницу; иначе `None` |
| `chunks() -> RdataChunks<'a>` | итератор по непрерывным кускам (`&'a [u8]`) в порядке потока; сумма длин == `len()`; без аллокаций |
| `copy_into(&mut [u8]) -> Result<usize, BufferTooSmall>` | копирует ровно `len()` байт; `dst.len() < len()` → `Err` **без частичной записи**; 0 аллокаций |

Энкодер ответа либо пишет `chunks()` прямо в выходной буфер, либо `copy_into` в слот ответа. **Материализация всего RRset или зоны запрещена:** копируется максимум **один RR** (или его RDATA), даже при AXFR — поток идёт RR за RR. Гарантия G-8 (§20.2) ограничивает чтение: ≤ `MAX_OVERFLOW_PAGES` страниц на RRset.

> `as_slice()` для overflow — оптимизация, а не гарантия: реализация вправе всегда возвращать `None` для `kind = OVERFLOW`, и вызывающий код обязан работать через `chunks()`/`copy_into`.

### 11.5. TTL: clamp, а не маскирование (R-5)

Политика задаётся `WriteIntent` и **не переопределяется** здесь: источник истины — `domain-model` §2.6, §5.2.1, INV-3. Таблица ниже фиксирует, как обязан вести себя writer формата.

| `WriteIntent` | Разные TTL в RRset | Значение > `2^31−1` | Что возвращается |
|---|---|---|---|
| `Transaction` (API/DNS) | `InvariantViolation(TTL_MISMATCH)` (INV-1), откат | clamp до `0x7FFF_FFFF` + `TTL_NORMALIZED` (проверяется доменом до writer'а) | ошибка при конфликте TTL |
| `Import` (zone-файл) | `min(ttl)`; дубликаты RDATA удаляются | clamp + `TTL_NORMALIZED` | `normalized[]`: `TtlNormalized`, `TtlClamped`, `DuplicateRdataRemoved`; `warnings[]` |
| `Replication` (AXFR/IXFR-in) | как `Import` + строгая монотонность serial (проверяет домен) | как `Import` | как `Import` + `serial` в `CommitOutcome` |
| `Signing` (DNSSEC) | TTL не меняется; пытаться изменить → `IntentForbidden` | — | `warnings` пуст |

| Правило формата | Поведение |
|---|---|
| Значение в файле > `2^31−1` при чтении | `Corrupt(BadTtl)` — clamp и маскирование на чтении запрещены |
| Хранение TTL | один `u32` на RRset в `LeafValue.ttl`; флаг `TTL_NORMALIZED` выставляется writer'ом при clamp/min/импорте |
| Метрика clamp | `ttl_clamped_total` (а не `ttl_masked_total`: маскирования нет) |

> Расхождение, зафиксированное ревью (маскирование `0x80000001 → 1`), устранено в `domain-model` §2.6/INV-3: используется clamp. Спецификация и домен совпадают.

### 11.6. Готовность к DNSSEC (формат v1, без крипто-пайплайна)

| Свойство | Где |
|---|---|
| RDATA — wire-форма без компрессии; lowercase там, где требует RFC 6840 §5.1 | §8.1, §11.2 |
| RR внутри RRset отсортированы по каноническому RDATA | §11.2 |
| Порядок ключей = канонический (RFC 4034 §6.1) → NSEC без сортировки | §8.3 |
| `RRSIG` различаются по covered type | §9 |
| `NSEC` = обход `next_name` | §13.2, §10.3 |
| `SOA serial` | §12.1 |
| NSEC3 | резерв (`F_NSEC3`, секция) |

### 11.7. Freelist: bucket-страницы и правила переиспользования (B-3)

Freelist — односвязный список bucket-страниц, упорядоченный по `free_txn` **по возрастанию** (голова — самый старый). `meta.freelist_head`, `meta.freelist_tail`, `meta.freelist_buckets`, `meta.freelist_entries` описывают список целиком; отдельного дерева/индекса нет.

Bucket-страница (`PAGE_TYPE_FREELIST`, `payload_len = 64 + 4*count`):

| Смещение | Размер | Поле | Описание |
|---|---|---|---|
| +0 | 40 | `PageHeader` | `page_type = 5`, `txn` = txn создания bucket'а |
| +40 | 4 | `next_bucket` | следующий bucket; 0 = конец |
| +44 | 4 | `reserved0` | 0 |
| +48 | 8 | `free_txn` | txn, в котором освобождены эти страницы (u64) |
| +56 | 4 | `count` | число `PageId`; 0 = пустой bucket (см. ниже) |
| +60 | 4 | `reserved1` | 0 |
| +64 | 4·count | `page_ids[count]` | освобождённые страницы |

Ёмкость: `(page_size − 64) / 4` = 1008 при 4096.

**Правила.**

1. **Порядок.** `free_txn` монотонно возрастает вдоль списка (инвариант; проверяется `fsck`). Новый bucket добавляется в **хвост** за O(1) (`freelist_tail`).
2. **Выдача.** Аллокатор идёт от головы и берёт страницы только из bucket'ов с `free_txn ≤ reclaim_txn` **и** `free_txn < current_txn`. Так как список отсортирован, при первом «слишком молодом» bucket'е обход прекращается — стоимость O(число отданных страниц), не O(длина списка).
3. **Запрет выдачи в той же транзакции (двойное освобождение).** Страницы, освобождённые в txn `T`, попадают в bucket с `free_txn = T` и в txn `T` не выдаются никогда. Причина: они ещё достижимы из `meta(T-1)`, а `reclaim_txn ≤ T-1` до публикации `T`. Нарушение этого правила — единственный способ получить страницу, на которую ссылаются два места (I-10). `fsck` проверяет: нет `PageId` в двух bucket'ах, нет `PageId` одновременно в freelist и в графе.
4. **Bucket-страницы неизменяемы: только COW (N-5).** Bucket, достижимый из активной meta, **никогда не мутируется на месте** — иначе читатель/восстановление увидят freelist, не соответствующий своей meta. Любая выдача из bucket `B` (и любое добавление) порождает новую страницу-образ:

   - пусть из `B` берётся `k` страниц. Пишется новый bucket `B'` (`free_txn = B.free_txn`, `count = B.count − k`, оставшиеся `page_ids`) в **свободную страницу** `p`; `val`-указатель головы/соседа переключается на `B'` при коммите.
   - `B` (старый образ) отправляется в набор «освобождено в текущей транзакции» и попадёт в bucket с `free_txn = T` (см. п. 5). Так он не теряется и не становится недостижимым.
   - если `B` опустел (`count == k`), новый образ не пишется: `B` просто уходит в набор освобождённых, а указатель соседа/головы снимается. Поэтому **пустых bucket'ов в цепочке не существует**.
   - откуда взять `p` (единый порядок, как в п. 7): (1) **eligible**-страница — та, что уже разрешена к выдаче (`free_txn ≤ reclaim_txn`), тогда `high_water` не растёт; (2) иначе `high_water`; (3) если исчерпан и он — одна из `k` выдаваемых страниц (`p` не возвращается вызывающему: он стал bucket-страницей). Рекурсия «чтобы освободить страницу, нужна страница» исключена: `p` либо свободная, либо новая, либо уже отдаваемая. Если `p` взята из **другого** bucket'а (не из `B`), тот тоже получает COW-образ — итого 0–2 образа на проход выдачи; это учтено в оценке п. 5.

   **Инвариант отсутствия сирот:** каждая bucket-страница либо достижима из `meta` по цепочке `next_bucket`, либо лежит в `page_ids` некоторого bucket'а этой же цепочки (то есть «свободна как данные»), либо является образом, который будет записан в текущем коммите. Третьего состояния нет: старый образ `B` всегда попадает в набор освобождённых того же коммита, а набор освобождённых всегда конвертируется в bucket до записи meta (§13.6). `fsck` проверяет: множества {bucket-страницы} и {page_ids} не пересекаются с графом данных и не теряют ни одной страницы из `page_count_high_water`.
5. **Стоимость коммита O(depth).** Все страницы, освобождённые транзакцией `T` (включая старые образы bucket'ов), собираются в **один** новый bucket и добавляются в хвост — амортизированно O(1), без обхода списка. Выдача страниц внутри транзакции даёт 0–1 COW-образ на затронутый bucket (обычно один и тот же, пока он не опустеет). Размер списка не влияет на латентность коммита.
6. **Слияние bucket'ов запрещено**: слияние потребовало бы перезаписи `free_txn`, что ломает инвариант порядка и COW-семантику.
7. **Следствие «+1 страница на коммит с освобождениями».** Каждому коммиту, который что-то освободил, нужна одна страница под образ нового bucket'а. Она берётся в порядке п. 4: сначала **eligible**-страница (тогда `high_water` не растёт), иначе `high_water` — и это `+1` к файлу. Такая страница становится доступной как данные только после того, как её `free_txn` перестанет быть «молодым» (следующие коммиты), — то есть `high_water` монотонно растёт на «холодном» старте и после всплесков удалений. Возврат в оборот: `compact_zone` (или offline `zonefile compact`) пересобирает freelist и обнуляет этот запас; на стабильной нагрузке число bucket-страниц ограничено непустыми bucket'ами (§11.7 п.4) и не растёт.
8. **`free_page_count`** в meta = `freelist_entries` (включая «молодые»); для метрики «сколько реально доступно сейчас» используется производная `reclaim_txn` (считается при коммите).

---

## 12. Каталог зон и жизненный цикл зоны (B-13)

Ключ: `RLE(apex) || T_ZONE_ENTRY || 0 || 0`. Значение — `ZoneEntry` (72 байта, §12.1).

### 12.1. `ZoneEntry` (72 байта)

| Смещение | Размер | Поле | Описание |
|---|---|---|---|
| +0 | 2 | `class` | 1 |
| +2 | 2 | `flags` | bit0 SECONDARY, bit1 FORWARD, bit2 DYNAMIC, bit3 FROZEN; bit4..15 reserved = 0 |
| +4 | 4 | `tree_root` | 0 = дерево пусто |
| +8 | 2 | `tree_level` | 0 = пусто, 1 = корень-лист |
| +10 | 1 | `state` | `ZoneState` (0/1/2) |
| +11 | 1 | `reserved0` | 0 |
| +12 | 4 | `rrset_count` | без `T_NODE` |
| +16 | 8 | `deleted_txn` | txnid перехода в `Tombstone`; **0 = не tombstone** (домен `Option<Txn>`: `None ↔ 0`, `Some(0)` запрещён — `Corrupt(BadZoneMeta)`/`InvalidEdit`) (R-13) |
| +24 | 8 | `last_commit_txn` | последний коммит, **изменивший зону** |
| +32 | 8 | `last_change_unix_ns` | |
| +40 | 4 | `rr_count` | |
| +44 | 4 | `soa_serial` | RFC 1982 |
| +48 | 4 | `ixfr_root` | 0 в v1 |
| +52 | 4 | `ixfr_serial_count` | 0 в v1 |
| +56 | 4 | `zone_origin_len` | длина RLE(apex) |
| +60 | 4 | `zone_seq` | стабильный `ZoneId` |
| +64 | 4 | `meta_root` | `PageId` блока §12.2; 0 недопустим для живой зоны |
| +68 | 4 | `reserved1` | 0 |

**Единственный источник классификации (R-14).** `SECONDARY`/`FORWARD`/`DYNAMIC`/`FROZEN` живут **только** в `ZoneEntry.flags`; `SIGNED`/`denial` — **только** в meta-блоке §12.2. `DS_AT_APEX` и `NSEC3_PRESENT` как поля удалены: первое выводится из наличия `DS`-RRset, второе — из `SIGNED ∧ denial = NSEC3`. Дублирование запрещено и проверяется `fsck` (мета-блок не содержит FORWARD, `ZoneEntry` — не содержит SIGNED).

`ZoneState` — **единственный** источник истины о состоянии зоны. Ранее предложенный бит `TOMBSTONE` в `flags` отменён (дублирование состояния — источник расхождений); `flags.bit7` MUST быть 0.

| `state` | Видимость | Допустимые ответы (решает домен) |
|---|---|---|
| 0 Initializing | `find_zone` возвращает зону с этим состоянием | `REFUSED` (зона создана, но не заполнена) |
| 1 Serving | видима | штатная семантика |
| 2 Tombstone | **мгновенно** исчезает из `zones()`/`find_zone` | — (зона удалена) |

Переходы: `Initializing → Serving` (первый успешный коммит содержимого), `Serving → Tombstone` (удаление), `Initializing → Tombstone`. Обратных переходов нет; повторное создание того же origin — новый `zone_seq` (§12.3).

### 12.2. Per-zone metadata-блок (`PAGE_TYPE_ZONE_META`)

| Смещение | Размер | Поле | Описание |
|---|---|---|---|
| +0 | 40 | `PageHeader` | `page_type = 9` |
| +40 | 2 | `flags` | bit0 SIGNED; bit1..15 reserved = 0 (FORWARD — только в `ZoneEntry.flags`, NSEC3 — из `SIGNED ∧ denial`) |
| +42 | 1 | `denial` | 0 = NSEC, 1 = NSEC3 |
| +43 | 1 | `reserved0` | 0 |
| +44 | 4 | `default_ttl` | |
| +48 | 4 | `soa_refresh` | |
| +52 | 4 | `soa_retry` | |
| +56 | 4 | `soa_expire` | |
| +60 | 4 | `soa_minimum` | |
| +64 | 2 | `upstream_count` | ≤ `MAX_FORWARD_UPSTREAMS` (32) |
| +66 | 2 | `upstream_bytes` | суммарно, ≤ `MAX_FORWARD_BLOB` (4096) |
| +68 | 1 | `upstream_layout` | 0 = inline, 1 = overflow |
| +69 | 3 | `reserved1` | 0 |
| +72 | 4 | `upstream_ref` | `PageId` первой overflow-страницы или 0 |
| +76 | 4 | `upstream_total` | байт в цепочке (для валидации) |
| +80 | … | `upstreams` | при layout=0: записи `u16 len + bytes[]` |

**Ёмкость и лимиты.**

| Параметр | Значение |
|---|---|
| inline | `80 + upstream_bytes ≤ page_size` (4016 байт данных при `page_size=4096`, 8112 при 8192) |
| overflow | байтовая цепочка, `upstream_bytes ≤ MAX_FORWARD_BLOB = 4096`, `upstream_total == upstream_bytes` |
| предел блока | `MAX_ZONE_META = 256 KiB` — логический потолок; сегодня блок занимает `80 + upstream_bytes` (≤ 4176), остальное зарезервировано под будущие поля и большие наборы |
| страниц в цепочке | `ceil(upstream_bytes / (page_size − 48))`; при 4096 это 2 (4048·2 = 8096 ≥ 4096), при 8192/16384 — 1 |
| записей | формат: ≤ `MAX_FORWARD_UPSTREAMS = 32`; домен (`domain-model` §2.7, §5.2.2) допускает ≤ 16 — writer обязан отклонять > 16 по intents, формат терпит до 32 ради будущего расширения без смены версии |

**Почему `MAX_ZONE_META = 256 KiB` не конфликтует с лимитами страниц.** 256 KiB — это верхняя граница *логического* размера блока (для будущих полей и больших upstream-наборов), а не требование уместить 256 KiB в цепочку из `MAX_OVERFLOW_PAGES = 64`. Если блок когда-либо достигнет 256 KiB, ему понадобится `ceil(262144/(page_size−48))` = 65 страниц при 4096 (33 при 8192, 17 при 16384). Поэтому для цепочек `ZONE_META` действует отдельный лимит `MAX_ZONE_META_PAGES` (§2), а `MAX_OVERFLOW_PAGES = 64` остаётся только для RRset. Расчёт: 65 > 64 — вот почему нельзя было обойтись общим лимитом; это зафиксировано явно, а не «подогнано».

**Атомарность.** `SetZoneMeta` и правки RRset идут в одной транзакции: writer пишет новый блок (COW, новые `PageId`), обновляет `ZoneEntry.meta_root` и данные зоны, коммит — единый (§13.6). Промежуточного состояния «новые RRset, старые настройки» не существует.

**Чтение.** `ZoneSettingsRef` — zero-copy срез блока: фиксированные поля (`default_ttl`, `denial`, SOA-таймеры, `flags`) читаются за O(1) без обхода цепочки. `forward_upstreams` отдаются итератором, который при `layout=1` проходит цепочку (≤ `MAX_ZONE_META_PAGES`), т.е. O(1) на элемент, а не копирование всего блоба. Каждая запись upstream — opaque-блоб (адреса/порты в формате домена); его интерпретирует `pulse-server`, хранилище не парсит.

### 12.3. Создание, удаление, `zone_seq`

**Создание** (одна транзакция):

1. `seq = meta.next_zone_seq`; если `seq == 0xFFFF_FFFF` → `IdSpaceExhausted` (R-11).
2. Записать блок §12.2 с дефолтами (`default_ttl` из конфига, `denial=0`), `state = Initializing`.
3. Создать лист с `T_NODE`(APEX) — **или** оставить `tree_root=0` для secondary до первого трансфера. Пустая зона: первая вставка создаёт корень-лист (§13.3 шаг 1); удаление последнего элемента снова даёт `tree_root = 0`, `tree_level = 0` (§13.4).
4. Вставить `ZoneEntry { zone_seq = seq, meta_root = <block>, tree_root, tree_level, state }`.
   Если по этому origin уже есть запись в состоянии `Tombstone`, её значение **заменяется** новым `ZoneEntry` (COW: старый снапшот продолжает видеть старую запись); страницы старого дерева/блока остаются в freelist удаления и освобождаются по §14.
5. `meta.next_zone_seq = seq+1`; `zone_count += 1`; при `Initializing` зона уже видима `find_zone` (но домен ответит `REFUSED`).

`zone_seq = 0` зарезервирован как «не назначен» (начальное значение `next_zone_seq = 1`); 0 в `ZoneEntry` живой зоны → `Corrupt(BadZoneMeta)`.

**Переход в `Serving`** — первым успешным коммитом содержимого (SOA+NS минимум); отдельной транзакции не требует.

**Удаление** — tombstone (`R-13`):

1. `state = Tombstone`, `deleted_txn = txnid(этого коммита)`; `zone_count -= 1`; `zones()`/`find_zone` не видят зону **немедленно** (фильтр по `state`).
2. `tree_root`, `meta_root` и сама `ZoneEntry` **не освобождаются** — на них ссылаются живые снапшоты. **Никакие страницы в freelist на этом шаге не попадают** (прежняя формулировка была неверной).
3. Освобождение — только двумя путями, и оба используют `free_txn = txnid` того коммита, который их освобождает:
   - **повторное создание того же origin**: значение `ZoneEntry` заменяется новым (новый `zone_seq`), а страницы старого дерева/блока попадают в набор освобождённых **этого** коммита;
   - **GC-проход**: оппортунистически при каждом `commit` (если `reclaim_txn ≥ deleted_txn`) и maintenance-задачей раз в час (`GC_INTERVAL_MS`); сканирует каталог O(Z), находит tombstone с `deleted_txn ≤ reclaim_txn` и в одной транзакции удаляет запись и освобождает её страницы. Лимиты opportunistic-прохода: ≤ `MAX_RECLAIM_ZONES_PER_COMMIT = 16` зон и ≤ `MAX_RECLAIM_PAGES_PER_COMMIT = 8192` страниц на коммит; остаток добирают следующие коммиты или `compact_zone`. Тот же проход выполняет `compact_zone`/offline-compact.
4. `zone_seq` не переиспользуется никогда, поэтому `ZoneId` из старых `ZoneMeta` не «оживает» как другая зона.
5. Пока `reclaim_txn < deleted_txn`, GC не трогает запись — иначе живой читатель увидит удалённую зону (нарушение snapshot isolation).

### 12.4. Индекс зон в памяти

`ZoneIndex { by_name: HashMap<NameHash, SmallVec<ZoneSeq>>, by_depth }`. Поиск — перебор суффиксов QNAME (≤ 127, практически 2–5) с верификацией байтов; 15–40 нс, без диска. Перестройка O(Z) при коммите, меняющем каталог; при Z > 50k — `CHANGESET_LOG` (v1.1).

### 12.5. RRSIG и `lookup_all` (B-13)

`RRSIG`-наборы одного имени различаются `subtype`. Требования:

- **`lookup` для `qtype = RRSIG` запрещён** → `WrongAccessor`. Причина: `lookup` возвращает один набор, а у RRSIG их несколько (по covered type); молчаливый выбор одного набора даёт неполный ответ (анти-паттерн, который ревью и ловил).
- `lookup(origin, name, RRSIG, subtype=k)` — точный набор по covered type `k` (доступен через `lookup_by_subtype`, если такая форма нужна домену).
- **`lookup_all(origin, name, type)`** — итерация по всем `subtype` данного типа. Реализация: `node_lower_bound` на `(name, type, class, 0)` и последовательный обход, пока `name/type/class` совпадают; каждый элемент — `RrsetRef` со своим `subtype`. Для не-RRSIG типов возвращается ровно одна группа.
- Ответ на `qtype=RRSIG` собирает домен из `lookup_all`; адаптер не склеивает наборы в один и не сортирует их.
- Число групп ограничено доменом (`MAX_RRSIG_SUBTYPES = 64`, `domain-model` §5.1); адаптер отдаёт группы лениво и не проверяет этот лимит.
- Порт получает `lookup_all` (и правило `WrongAccessor`); `domain-model` обновляет Архитектор ПО.

### 12.6. Состояния зоны и корректные ответы

| `state` | `tree_root` | `node(apex)` | `lookup` | Ответ (решает домен) |
|---|---|---|---|---|
| Initializing | 0 или ≠ 0 | по дереву: `exists` как обычно, `is_apex: true` | значения, если `tree_root ≠ 0`; иначе `None` | **`REFUSED`** — состояние важнее содержимого (домен не отвечает по данным) |
| Serving, apex-only (SOA+NS) | ≠ 0 | `exists: true, is_apex: true, has_children: false` | `None` для не-apex типов | `NODATA` в apex и `NXDOMAIN` ниже (SOA есть → negative caching корректен, RFC 2308) |
| Serving, нормальная | ≠ 0 | `exists: true` | значения | штатная семантика |
| Serving **невозможно** без SOA в apex (W-11): secondary до первого трансфера и частично загруженная зона остаются `Initializing` | — | — | — | `SERVFAIL`/`REFUSED` по политике: без SOA `NXDOMAIN` отдавать нельзя (RFC 2308 §2) |
| Tombstone | — | зона не находится | — | зона отсутствует → `REFUSED` по политике |

Хранилище rcode не выбирает — отдаёт состояние, `ZoneEntry` и примитивы. `tree_root=0` ⇒ все поиски `None`, `next_name` → `None`, `node(apex)` = `{exists:false, is_apex:true}`.

---

## 13. Алгоритмы

### 13.1. Открытие (mount)

```
open(path, cfg):
  1. open(path, O_RDONLY|O_NOFOLLOW|O_CLOEXEC); fstat → обычный файл, owner/mode/uid (§21.4)
  2. read 4096 @0 и @page_size → superblock A/B; валидировать (magic/version/page_size/CRC)
  3. валидировать регион reader table: off % 64 == 0,
     pages == ceil(1024*32/(page_size-32)), len == pages*page_size,
     off + len <= page_count_max*page_size
  4. размер файла < page_count_max*page_size → TruncatedFile (и writer, и reader).
     ftruncate допустим ТОЛЬКО в цикле создания файла (§4); существующий файл не «доращивается»
  5. writer: open(path + ".lock", O_CREAT|O_RDWR, 0600) + flock(LOCK_EX|LOCK_NB) → Busy
     reader: ничего не блокирует (SEC-ZF-009)
  6. ПЕРЕД КАЖДЫМ mmap: fstat + сверка `dev/ino` (TOCTOU) И
     `st_size == page_count_max * page_size`; иначе TruncatedFile
     (truncate-race между open и mmap иначе даёт SIGBUS вместо чистого отказа)
  7. mmap #1: PROT_READ, MAP_SHARED, весь файл
  8. mmap #2: PROT_READ|PROT_WRITE, MAP_SHARED, [reader_region_off, reader_region_len)
     — единственный writable-маппинг (SEC-ZF-014); неудача → MapAllocFailed
  9. валидировать каждую страницу региона: page_type=7, page_no, slots_used_in_page, crc=0
 10. выбрать meta (§13.7); валидировать поля
 11. зарегистрировать слот(ы) читателя (CAS в reader table, §6.4)
 12. построить ZoneIndex (O(Z*depth))
```

Порядок важен: регион и meta валидируются **до** первой публикации слота, чтобы читатель не мог держать снапшот на невалидном файле.

### 13.2. Поиск зоны и RRset

```
find_zone(qname): суффиксы от длинного к короткому по ZoneIndex; tombstone пропускается
rrset(zone, name, type, class=IN, subtype=0):
  target = RLE(name)||type||class||subtype
  page = zone.tree_root; if page == 0: return None
  while page.level > 0:
      i = node_predecessor(page, target); if None: return None
      page = child[i]
  i = node_lower_bound(page, target)
  if i == n_items or key(i) != target: return None
  return value(i)
```

`next_name` = обход с пропуском остальных типов того же owner; используется для NSEC/AXFR/`enumerate`.

### 13.3. Upsert: две фазы (B-7)

```
upsert(zone, key, rrset):
  # --- фаза 1: план ---
  1. если zone.tree_root == 0 (пустая зона: create_zone без данных, secondary до
     трансфера — §12.3) → создать корень-лист: tree_root = new page, tree_level = 1,
     путь = [root]; иначе — спуск до листа (COW-копии всех страниц пути в dirty-set)
  2. pos = node_upper_bound(leaf, key)
  3. payload_bytes = rdlen + 2*rr_count
     inline = payload_bytes <= INLINE_VALUE_MAX
     # худший item: 4 + MAX_KEY_SIZE(261) + 20 + 512 = 797 << 4096, поэтому
     # «влезает ли в пустую страницу» проверять не нужно — только порог размера
  4. собрать логический массив items: заменить/вставить; старый value (если был) запомнить
  5. пересчитать фронт-кодирование и encoded_size; при encoded_size > page_size → split по медиане
     (рекурсивно до корня; при переполнении корня — новый корень, level+1)
  # --- фаза 2: размещение ---
  6. если inline: payload дописывается сразу за LeafValue в item
     иначе: payload (единый байтовый поток, §11.4) пишется в overflow-цепочку
            страницами по (page_size−48) байт; val_u32 = first PageId
  7. финальное кодирование страницы (фронт-кодирование с реальными длинами).
     ПОВТОРНАЯ ПРОВЕРКА (R-6): после split первый item правой страницы становится
     restart (shared_len = 0), общий префикс теряется, фактические длины больше
     плановых. Если encoded_size > page_size — повторить split (≤ 2 итерации);
     после второй неудачи — split по 3 частям.
  8. освободить старую overflow-цепочку, если значение заменено
     (в набор освобождённых с free_txn = текущий txn; в этом же txn не выдаётся, §14)
  9. материализовать T_NODE и ENT (N-2):
     a. если T_NODE у имени нет — создать (kind=NODE) с флагами:
        APEX (name == apex), WILDCARD (первая метка == "*"),
        CHILDREN_MAY_EXIST = has_children(name)  (предикат — ниже);
        если T_NODE был и стоял EMPTY_NON_TERMINAL — снять его (у имени появился RRset);
     b. для каждого отсутствующего предка вставить T_NODE:
        ENT=1, CHILDREN=1; если предок == apex → APEX=1, ENT=0
        (apex-маркер не является ENT); до 127 меток, на практике 2–5;
     c. у существующих предков выставить CHILDREN_MAY_EXIST; EMPTY_NON_TERMINAL
        у них СОХРАНЯЕТСЯ (они по-прежнему имена-предки без данных);
 10. обновить сепараторы ВСЕХ затронутых путей (основная вставка + каждая вставка
     предка из шага 9b) и счётчики каталога (rrset_count/rr_count/soa_serial)
```

Инвариант: фаза 1 не размещает payload — значит split-решение не зависит от физического размещения и детерминировано. Одинаковые входные данные дают одинаковый файл (важно для golden-тестов).

**Предикат `has_children(n)` (B-2).** В RLE владелец-ключ = `RLE(n)` **с** терминатором; потомок = `RLE(n)` **без** терминатора + байт длины метки `0x01..0x3F`. Поэтому «следующий ключ начинается с `RLE(n)`» истинно для собственных ключей имени и ложно для потомков — использовать это нельзя. Правильно:

```
p    = RLE(n) без последнего байта (терминатора)      # len == |RLE(n)|-1
k    = lower_bound(p || 0x01)                          # первый ключ >= p||0x01
has_children(n) ⇔ k существует ∧ k[0..|p|] == p ∧ k[|p|] ∈ 0x01..0x3F
```

`p || 0x01` больше любого ключа самого имени (у них в позиции `|p|` стоит `0x00`) и меньше любого потомка, поэтому `lower_bound` не может вернуть ключ самого имени; если кандидат не найден или префикс не совпал — потомков нет. O(log n).

**Почему шаг 9 обязателен (N-2).** `T_NODE` — не «декор»: на нём держатся ENT-семантика (`node().exists` для пустого не-терминала), `CHILDREN_MAY_EXIST` (NXDOMAIN vs NODATA), wildcard-синтез (нужно знать, что имя-предок существует) и referral (`DELEGATION` живёт в `T_NODE`). Без материализации ENT ответы на NXDOMAIN/NODATA/wildcard становятся неверными; поэтому шаги 9a–9c входят в каждую транзакцию, изменяющую набор имён.

### 13.4. Удаление и underflow (B-8)

```
delete(zone, key):
  if zone.tree_root == 0: return KeyNotFound
  спуск (COW) → лист; pos = node_lower_bound; если key != target → KeyNotFound
  удалить item; освободить overflow-цепочку
  if leaf пуст:
      удалить слот из родителя (рекурсивно: родитель тоже может опустеть)
      if родитель — ветвление, оставшееся с 1 ребёнком: root-or-node = ребёнок, level-1
      if корень-ветвление опустел (0 детей): tree_root = 0, tree_level = 0   # R-7
      if корень-лист пуст: tree_root = 0, tree_level = 0
  else if fill(page) < 0.25 and page != root:
      sib = сосед через родителя (сначала правый)
      if content(page) + content(sib) <= 0.75 * usable: merge; удалить сепаратор; обновить сепаратор правого
      elif content(sib) >= 0.40 * usable: borrow
           borrow-left:  последний item левого → в начало текущего; сепаратор(текущий) = его первый ключ
           borrow-right: первый item правого → в конец текущего; сепаратор(правый) = новый первый ключ
      иначе: оставить (гистерезис 25/75)
  if удалён RRset и у имени не осталось ни одного RRset:
      if has_children(name)  (предикат §13.3)  или флаг APEX:
          T_NODE остаётся: выставить EMPTY_NON_TERMINAL (если не APEX), снять WILDCARD/
          DNSSEC_SIGNED/DELEGATION-биты, пересчитать CHILDREN_MAY_EXIST               # N-2
      else:
          удалить T_NODE;
          # каскад вверх: у каждого предка пересчитать CHILDREN_MAY_EXIST
          # по предикату §13.3; если предок == apex — оставить (APEX),
          # только снять CHILDREN_MAY_EXIST, если потомков не осталось;
          # если предок — EMPTY_NON_TERMINAL без RRset и без потомков —
          # удалить и продолжить вверх (≤ 127 шагов)
  обновить сепараторы всех затронутых путей (минимумы детей)
```

**Метрики заполнения (R-7).** Заголовок (56 Б) не должен искажать коэффициент:

```
content(page) = encoded_size - NODE_HEADER_SIZE      # только элементы
usable        = page_size - NODE_HEADER_SIZE
fill(page)    = content(page) / usable
```

Полосы: после split — 40–60% (по `content`); bulk load — до 90%; стабильное состояние 50–90%; underflow `< 25%`; merge — только если суммарный `content` ≤ 75% `usable`.

**Правило «не удалять `T_NODE`».** `T_NODE` удаляется только если у имени нет ни одного RRset, нет потомков и нет обязательных флагов (`APEX`). `DELEGATION`/`GLUE`/`OCCLUDED` без RRset не существуют по определению (они выставляются при наличии NS/A), поэтому отдельного условия не требуют.

### 13.5. Материализация флагов при изменении cut

Диапазон `[RLE(name), successor_of_prefix)` переписывается в одной транзакции: `GLUE` / `OCCLUDED` / `CUT_BELOW`. Guard `MAX_CUT_SUBTREE_RECORDS` (100 000); превышение → `InvariantViolation(CutSubtreeTooLarge)` с рекомендацией `compact_zone`.

### 13.6. Коммит, `sync()`, group commit (B-12)

```
commit(mode):        # mode ∈ {NOSYNC=0, NOMETASYNC=1, SYNC=2}
  1. инварианты в памяти: порядок ключей, нет дублей PageId в dirty-set,
     overflow-цепочки замкнуты, depth ≤ MAX, encoded_size ≤ page_size
  2. собрать набор освобождённых страниц (заменённые/удалённые + старые образы
     bucket'ов из §11.7) в ОДИН новый bucket с free_txn = txnid+1; bucket — часть
     dirty-set (N-4). Обновить freelist_head/tail/buckets/entries/free_page_count
     в НОВОМ образе meta (не в текущей).
  3. заполнить PageHeader каждой dirty-страницы (page_no, txn, lsn, crc, payload_len)
  4. pwritev(dirty, включая bucket) — целыми страницами, батчами ≤ 64
  5. if mode >= NOMETASYNC: fdatasync(fd)          # данные ДО любой meta
  6. durable' = if mode >= NOMETASYNC then txnid else durable_txn
  7. write(meta, неактивный слот): txnid+1, все корни (вкл. новый freelist),
     durable_txn = durable', reclaim_txn = min(durable', oldest_reader_txn),
     page_count_high_water, счётчики
  8. if mode == SYNC: fdatasync(fd)
  9. fence(Release); publish(active_txn = txnid+1)
 10. CommitOutcome { commit_id, ... }
```

**Почему bucket формируется до записи meta (N-4).** Страницы, освобождённые транзакцией, должны быть достижимы из **новой** meta — иначе после публикации они не принадлежат ни графу, ни freelist (нарушение I-11/W-9 и утечка на каждом удалении). Поэтому bucket входит в тот же `pwritev`, что и данные, а `freelist_head/entries` пишутся в новую meta; старая meta продолжает указывать на старую цепочку, где этих страниц ещё нет — и это корректно, поскольку старая meta их всё ещё использует как граф.

**Group commit.** `fdatasync` шага 5 может покрывать данные нескольких готовых коммитов; порядок диапазонов не важен, но **все** диапазоны данных синхронизируются до записи **любой** meta. Затем metas пишутся по возрастанию `txnid`. Каждая meta самодостаточна (§I-12), поэтому восстановление не зависит от порядка их записи.

**`sync()`** (обязателен в `NOSYNC`):

```
sync():
  1. fdatasync(fd) по всем данным, записанным с прошлого sync/коммита
  2. write(неактивная meta, txnid+1, те же корни, durable_txn = txnid+1)
  3. fdatasync(fd)
  4. publish(active_txn = txnid+1); durable_txn := txnid+1
```

Без `sync()` в `NOSYNC` `durable_txn` не растёт → `reclaim_txn` не растёт → freelist не отдаёт «молодые» страницы → возможен `MapFull` при живом свободном месте. Это осознанная цена режима и задокументирована в §15.

**`MODE_NOSYNC` — экспериментальный и по умолчанию выключен** (`DEFAULT_SYNC_MODE = MODE_SYNC`). Он даёт защиту от **порчи** файла, но не от потери: правило восстановления (`txnid ≤ durable_txn`) откатывает состояние к последнему `sync()`, в том числе после падения процесса. Включается явным конфигом и помечается в `meta_flags.EXPERIMENTAL`.

### 13.7. Восстановление (B-12)

```
recover():
  1. superblock A/B → конфигурация; иначе Corrupt
  2. прочитать обе meta; валидные = CRC + page_no + версия + page_size
  3. D = max(meta.durable_txn) по валидным метам; если нет валидных → CorruptNoValidMeta
  4. candidates = валидные meta с txnid <= D; если пусто → CorruptNoValidMeta
  5. active = max(candidates, by txnid)        # НЕ просто max valid txnid
  6. durable_txn = min(active.durable_txn, active.txnid)
  7. проверить high_water, границы корней, reader region
  8. санитизировать reader table (только мёртвые PID / несовпадение incarnation)
  9. если meta_flags.NEEDS_FSCK или durable_txn < txnid(active): выставить NEEDS_FSCK
     (диагностика; режим sync в файле не хранится и на восстановление не влияет)
 10. ОТКАТ НА INITIAL META: если active.txnid == 1 (initial-состояние), а
     created_unix_ns старше ROLLBACK_ALERT_AGE_MS (=60 000) на момент открытия —
     это признак ранее существовавшего файла, а не нового: выставить NEEDS_FSCK,
     вернуть RolledBackToInitial { instance_uuid, created_unix_ns }, писать алерт;
     старт продолжается только при OpenConfig.allow_rollback_to_initial = true
     (явное подтверждение оператора). instance_uuid логируется для корреляции.
 11. опубликовать снапшот
```

Обе meta содержат полный набор корней, поэтому откат на `T-1` не требует чтения `T`.

Правило шага 10 нужно, чтобы откат к `txnid=1` не выглядел как «новый пустой файл»: новый файл имеет `created_unix_ns ≈ now`, ранее существовавший — заметно старше. Порог намеренно грубый (60 с): он различает «только что создан» и «жил и потерял данные», а не измеряет время точно.

### 13.8. Компакция

1. merge/split при правках (§13.3–13.4).
2. `compact_zone(zone)`: перезапись дерева зоны в свежие страницы одной транзакцией; `tree_root` меняется, `zone_seq` — нет.
3. offline `zonefile compact --in --out` + `rename` (смена `page_size`/`map_size`).
4. **GC tombstone-зон** (§12.3) — два триггера, как в домене (`domain-model` §5.2.4/§5.2.6):
   - **оппортунистически на каждом `commit`**: если `reclaim_txn ≥ deleted_txn` хотя бы одной tombstone-зоны (проверка по каталогу O(Z), Z мало), её запись удаляется и страницы освобождаются в том же коммите; лимиты — `MAX_RECLAIM_ZONES_PER_COMMIT = 16` зон и `MAX_RECLAIM_PAGES_PER_COMMIT = 8192` страниц;
   - **maintenance-задача раз в час** (`GC_INTERVAL_MS = 3 600 000`) — полный проход на случай, если коммитов не было.

   Освобождение всегда с `free_txn = txnid` того коммита, который его выполняет; `reclaim_after == deleted_txn` — порог условия `reclaim_txn ≥ deleted_txn`, не дедлайн. До условия запись и страницы нетронуты. Повторное создание того же origin освобождает старые страницы в своём коммите.

Критерий `COMPACTION_SUGGESTED`: `free_page_count / high_water > 40%` или `avg_leaf_fill < 55%` (по `content(page)/usable`, §13.4) в течение часа.

### 13.9. fsck (R-3)

`verify()` проверяет:

- обход всех деревьев: CRC (кроме reader table), порядок ключей, сепараторы, `n_restarts` по формуле, `items_start`, `shared_len ≤ len(prev)`;
- overflow: `sum(data_len) == payload_bytes` (сходимость потока) и отсутствие циклов; разрыв RR/RDATA между страницами — норма (§11.4) и нарушением не считается;
- **тип значения по ключу** (R-19): `T_ZONE_ENTRY` → item ровно `4+suffix+72`, `rdlen/rr_count` не читаются; `T_NODE` → `kind=0, rr_count=0`; RRset → `kind∈{1,2}`, payload = `rdlen + 2*rr_count`;
- freelist: отсутствие пересечений (страница в двух bucket'ах / в bucket'е и в графе), монотонность `free_txn`, **неизменяемость bucket'ов** (bucket-страницы не входят в граф данных, §11.7), отсутствие пустых bucket'ов;
- `ZoneEntry`: `state`/`deleted_txn` согласованы (0 ⟺ не tombstone), `meta_root ≠ 0` для живой, флаги не дублируются с meta-блоком (R-14);
- lower-case инвариант ключей, отсортированность RDATA, `TTL ≤ 2^31−1`.

`repair(--to-txn T)`: разрешён **только** при `T ≥ reclaim_txn` (иначе страницы `T` могли быть переиспользованы) → `RefuseToRollback`. Утечки возвращаются в freelist, выставляется `NEEDS_FSCK`.

---

## 14. MVCC, пиннинг и переиспользование

- Состояние = `(meta(T), граф страниц T)`. Writer создаёт новый граф; неизменённые страницы общие.
- Публикация — атомарная запись meta + `publish` (§13.6 шаги 7–9). Читатель фиксирует `T` через протокол §6.3.
- Страницы, заменённые в транзакции `F` (то есть достижимые из `F-1`), разрешено переиспользовать только при `F ≤ reclaim_txn`, где `reclaim_txn = min(durable_txn, oldest_reader_txn)`. `oldest_reader_txn` writer читает из слотов с `Acquire` (§6.4) — иначе публикация читателя может быть не видна и страницы освободятся преждевременно.
- Bucket-страницы freelist тоже подчиняются COW (§11.7): мутация на месте запрещена, старый образ уходит в набор освобождённых того же коммита.

  Обоснование обеих границ:
  - `F ≤ durable_txn`: если meta `F` на диске, восстановление никогда не откатится на `F-1`; иначе страницы `F-1` обязаны быть целы.
  - `F ≤ oldest_reader_txn`: все живые читатели видят мету ≥ `F`, значит страницы, заменённые в `F`, им не нужны.
  - При отсутствии читателей `oldest_reader_txn = txnid(active)` — поэтому «молодые» страницы не выдаются мгновенно, что даёт запас на откат.

- **В `NOSYNC`** `durable_txn` растёт только через `sync()`; следовательно `reclaim_txn` стоит на месте, freelist голодает, а при исчерпании `high_water` коммит возвращает `MapFull`. Это документированное поведение, а не баг.
- Если свободных страниц нет, но они есть в freelist — `NoSpace` (retry после `sync()`/освобождения читателей). Разграничение — §16.
- `ReadersStalled` — диагностика, когда `reclaim_txn` не двигается дольше `STALE_READER_TIMEOUT_MS` при живом слоте; данные при этом не портятся.

---

## 15. Матрица отказов

| # | Момент | Диск/кэш | После рестарта | Потери |
|---|---|---|---|---|
| F-1 | во время записи data (SYNC/NOMETASYNC) | старый meta валиден | `T` | нет |
| F-2 | после fdatasync данных, до meta | старый meta | `T` | нет |
| F-3 | torn-write meta | CRC не сходится → meta невалидна | `T` | нет |
| F-4 | NOMETASYNC: meta в кэше, питания нет | meta могла не долететь | `T` или `T+1`, **файл валиден** | последние коммиты |
| F-5 | SYNC: оба fsync прошли | всё на диске | `T+1` | нет |
| F-6 | NOSYNC: потеря питания/сбой ОС | произвольное подмножество кэша | состояние последнего `Sync`/`Flush`-коммита или последнего `sync()`; возможна потеря всех коммитов после него | данные после последней синхронизации |
| F-6a | NOSYNC: **падение только процесса** (kill -9) | page cache цел, файл не испорчен | `recover()` выбирает meta с `txnid ≤ durable_txn`, поэтому откат к последнему `sync()` | коммиты после последнего `sync()` не видны (но физически в кэше); порчи нет |
| F-7 | переиспользование при живом читателе | запрещено I-6/§14 | — | невозможно |
| F-8 | bit rot | CRC не сходится | `Corrupt` на ветви → SERVFAIL | запись недоступна |
| F-9 | усечение файла (внешнее или после сбоя) | размер < `page_count_max × page_size` | `TruncatedFile` при open — **и у writer, и у reader**; `ftruncate` не выполняется, файл не «доращивается»; работающий процесс — SIGBUS fail-stop | восстановление из бэкапа/пересоздание |
| F-10 | второй writer | занят `<zonefile>.lock` (`LOCK_EX\|LOCK_NB`) | `Busy` | — |

**Усечение — fail-closed.** `ftruncate` разрешён только в цикле создания (§4, `O_CREAT|O_EXCL`). Если открывается существующий файл короче `page_count_max × page_size`, это признак потери данных, а не «недороста»: и writer, и reader получают `TruncatedFile`. Автоматическое «доращивание» маскировало бы усечение и могло бы вернуть мусор вместо данных.

**Уточнение формулировок (B-12).** В `NOSYNC` гарантий сохранности нет ни при потере питания, ни при падении процесса: восстановление всегда откатывается к `durable_txn`, то есть к последнему `sync()` (F-6, F-6a). Гарантируется только отсутствие порчи (откат идёт на целую мету, а не на смесь). Слово «консистентен» в прежней редакции было неточным.

**Почему читатель не видит полу-запись во всех трёх режимах.** Видимость определяется не чтением meta-страницы, а in-process указателем `active_txn`, который публикуется после полной записи meta (шаг 8). Читатель никогда не сканирует meta на hot-path, поэтому torn-страница в page cache не может быть прочитана как данные. Граф `T` неизменяем до `reclaim_txn ≥ T` (§14). В `NOSYNC` это свойство сохраняется в пределах жизни процесса/ядра; после F-6 снапшот откатывается целиком, но не «размазывается».

---

## 16. Лимиты и защита от переполнения

| Объект | Лимит | При превышении |
|---|---|---|
| `page_size` | 4096/8192/16384 | `UnsupportedVersion` |
| `page_count` | ≤ 2³²−2; фактически `map_size/page_size` | `MapFull` |
| `map_size` | дефолт 4 GiB; тесты 64–256 МиБ | `MapFull` / `MapAllocFailed` |
| размер зоны | ограничен `map_size` (≈ 90–100 MiB на 1M RRset → ~45M RRset при 4 GiB) | `MapFull` |
| имя / метка / ключ | 255 / 63 / 261 | `InvariantViolation` |
| `rdlength` одного RR | `65535` (предел протокола; u16) | невозможно по типу поля |
| RRset payload | 196 605 байт (= 65 535 + 2×65 535) | `InvariantViolation(RrsetTooLarge)` |
| overflow-страниц | 64 (фактически ≤ 49 при 4096; ёмкость 64×4048 = 259 072 > 196 605) | `Corrupt` / `InvariantViolation` |
| TTL | `2^31−1`, clamp при записи, reject при чтении | `TTL_NORMALIZED` / `Corrupt(BadTtl)` |
| RRset на зону | 50M hard, 10M дефолт | `InvariantViolation(ZoneTooLarge)` |
| зон в файле | guard 1M (`zone_count` u32) | `InvariantViolation(TooManyZones)` |
| `zone_seq` | u32, монотонный, без переиспользования | `IdSpaceExhausted` |
| `upstream_blob` | 4096 байт, ≤ 32 записи | `InvariantViolation(UpstreamTooLarge)` |
| **per-zone meta-блок** | `MAX_ZONE_META = 256 KiB` логически; страниц цепочки ≤ `MAX_ZONE_META_PAGES` (65 @4096) | `InvariantViolation(ZoneMetaTooLarge)` / `Corrupt` |
| глубина дерева | 8 | `Corrupt` |
| читателей | 1024 | `TooManyReaders` |
| сравнений на lookup | 128 | (алгоритмическая гарантия, тест) |
| `txnid` | u64 | пересборка файла |

**`MapFull` vs `NoSpace` (R-6):**

| Ошибка | Условие | Действие |
|---|---|---|
| `MapFull` | `page_count_high_water == page_count_max` (адресное пространство файла исчерпано) | расширить `map_size` (offline compact) |
| `NoSpace` | `high_water < page_count_max`, но все свободные страницы «молодые» (`free_txn > reclaim_txn`) | выполнить `sync()` / дождаться читателей; повторить |
| `MapAllocFailed` | `ftruncate`/`mmap` не удались (квота, ENOMEM) | отказ старта с подсказкой |

Правила арифметики (MUST, тесты + Miri):

1. Суммы/произведения — `checked_*` в `u64`; переполнение = `Corrupt`.
2. `off + len ≤ payload_len` перед каждым доступом.
3. **Guards по фактической вместимости (R-8, R-15).** Учитываются не только item'ы, но и служебные массивы: `2` байта slot на item и `2/INTERVAL` байт restart на item.
   `effective = min_item + 2 + 2/INTERVAL`; `n_items ≤ floor((page_size − 56) / effective)`.
   Для `page_size = 4096`: лист `4040 / (25 + 2 + 0.25) = 4040/27.25 → **148**`; ветвление `4040 / (9 + 2 + 0.5) = 4040/11.5 → **351**`.
   Дополнительно `n_restarts == ceil(n_items/INTERVAL)` и `items_start ≥ 56 + 2*(n_restarts + n_items)`.
4. Индексы слотов/restart читаются только после проверки монотонности.
5. Никаких сужающих `as`; `try_into()`; в reader-модулях `deny(clippy::cast_possible_truncation, cast_sign_loss, cast_possible_wrap)`.
6. `page_no` сверяется со слотом.
7. `deny(clippy::unwrap_used, expect_used, panic, indexing_slicing)` на reader-модулях.
8. `unsafe` — только в модуле привязки mmap/reader-region; `// SAFETY:`; `deny(unsafe_op_in_unsafe_fn)`; остальное `forbid(unsafe_code)`.
9. `Miri` на чистой логике; **4 fuzz-таргета**: `zonefile_read` (произвольные байты), `zonefile_write` (round-trip), `zonefile_roundtrip` (read→write→read), `reader_table_state` (слоты: `active_txn`, reserved-биты, границы региона, `slots_used_in_page`).
10. **Конкурентная атомарность (отдельно от fuzz):** `loom`-модель (или TSan-прогон) для `pin`/`unpin` × writer `oldest_reader_txn`/`reclaim_txn` с проверяемым инвариантом «страница с `free_txn > reader_txn` не выдаётся и не перезаписывается». Покрывает порядок `Release`/`Acquire` (§6.3–6.4) и гонку публикации `active_txn`.

### 16.1. Выбор `page_size`

| Размер | Когда | Цена |
|---|---|---|
| 4096 (дефолт) | любые зоны | depth 3 на 1M RRset |
| 8192/16384 | > 5M RRset | фрагментация мелких зон; write amplification |

Размер фиксируется при создании; смена — только `compact`. При `page_size < 4096` или не кратном 4096 — отказ.

---

## 17. Инварианты записи

| ID | Инвариант |
|---|---|
| W-1 | Пишется только неактивная meta |
| W-2 | Имена — lowercase RLE (§8.1) |
| W-3 | RR отсортированы по каноническому RDATA |
| W-4 | `T_NODE` существует для каждого имени с RRset, для apex и для каждого ENT (имя-предок без данных); отсутствующие предки материализуются в той же транзакции (§13.3 шаг 9) |
| W-5 | Флаги §11.3 согласованы с содержимым |
| W-6 | Байтовый поток overflow-цепочки равен `payload_bytes` (сумма `data_len` == `rdlen + 2*rr_count`); `sum(rdlength) == rdlen`; RR и RDATA **могут** пересекать границы страниц; цепочка сходится и не содержит циклов (§11.4) |
| W-7 | `branch.key[i]` = минимум поддерева |
| W-8 | Каждый `PageId` в графе один раз |
| W-9 | Освобождённые страницы → bucket с `free_txn = txn`; в этом txn не выдаются |
| W-10 | `durable_txn` не уменьшается; `reclaim_txn` вычисляется при коммите |
| W-11 | `DELEGATION` не содержит SOA; **в состоянии `Serving`** apex содержит SOA+NS (INV-4/INV-9 применяются только к `Serving`); для `Initializing` SOA/NS не обязательны — допустимое частично заполненное состояние |
| W-12 | CNAME не сосуществует с другими типами (домен валидирует) |
| W-13 | TTL: clamp при записи, `InvariantViolation` для транзакции, `min` для импорта |
| W-14 | `page_count_high_water == page_count_max` → `MapFull` до начала записи |
| W-15 | `zone_seq` не переиспользуется; tombstone не виден `zones()`/`find_zone`; `deleted_txn` заполнен только у tombstone и не меняется; `0` ⟺ не tombstone, `Some(0)` из домена запрещён (→ `InvalidEdit`) |
| W-16 | Для живой (`state ≠ Tombstone`) зоны `meta_root ≠ 0` |
| W-17 | `Import`/`Replication`: дубликаты RDATA в RRset удалены (дедуп до записи), TTL нормализован; `Transaction`/`Signing` — без нормализации (§11.5) |
| W-18 | Freelist-страницы не мутируются на месте: только COW-образ (§11.7); освобождённые страницы входят в bucket **до** записи meta (§13.6) |
| W-19 | Классификация зоны (`SECONDARY/FORWARD/DYNAMIC/FROZEN`) — только в `ZoneEntry.flags`; `SIGNED/denial` — только в meta-блоке (§12.1) |

---

## 18. Расширяемость

Minor: новые поля в `reserved`, новые секции, новые `optional`-флаги — старый читатель игнорирует. Major: изменение раскладки → `version_major++`, старый читатель отказывается, миграция — `compact`. Неизвестный `page_type` на пути обхода → `Corrupt` (fail-closed). `instance_uuid` — ключ кешей/аудита.

---

## 19. Контрольные суммы

- CRC-32C (Castagnoli, reflected, init/final `0xFFFFFFFF`), вектор `crc32c("123456789") = 0xE3069283`.
- Покрытие: вся страница, поле `crc32c` = 0 при расчёте.
- Superblock: `[0,4096)`; meta/leaf/branch/overflow/freelist/zone-meta: `page_size`.
- **Reader table исключена** (writable-регион): `crc32c` MUST 0, проверка пропускается, `fsck` пропускает.
- Проверка один раз на версию страницы; кеш — per-snapshot bitset.
- **Бюджет битсета (R-9):** 1 бит/страница; 1M страниц = 125 KiB. Битсет шардируется по 4 KiB (32 768 страниц/чанк) и чанк выделяется лениво при первом обращении; краткоживущие снапшоты обычно не выделяют ничего. Битсет — кеш, не источник истины: при вытеснении страница проверяется повторно.
- Стоимость 4 KiB ≈ 0.3–1.5 µs (SSE4.2/ARMv8-CRC); на hot-path ≈ 0.

---

## 20. Контракт для `pulse-dns` / `pulse-server`

### 20.1. Что отдаётся (zero-copy)

- **Owner-имя** — `NameRef` = **RLE-срез** (`&'a [u8]`, обратный порядок меток, lowercase). Forward-wire-срез **не обещается** (B-10): энкодер получает метки и пишет их в обратном порядке без промежуточной копии.
- **RDATA одного RR** — `Rr<'a>` (wire-форма, без компрессии): `as_slice()` для непрерывных байт (inline или один RR в одной странице) и `chunks()`/`copy_into()` для overflow-цепочки, где RDATA может разрываться между страницами (§11.4).
- TTL/флаги — `Copy`. Итераторы без аллокаций. Ошибки — `Result`, без panic.
- **Копирование ограничено одним RR**: ни `RrsetRef`, ни `enumerate`, ни AXFR не материализуют набор или зону.

### 20.2. Гарантии времени жизни

| ID | Гарантия |
|---|---|
| G-1 | Срезы указывают в `mmap`; копирования из файла нет |
| G-2 | Срез живёт не дольше `&Snapshot` |
| G-3 | Маппинг не перемещается и не ремапится, пока жив `ZoneFile` |
| G-4 | Снапшот иммутабелен и детерминирован |
| G-5 | `Snapshot` — `Send + Sync`; клон ≤ 20 нс |
| G-6 | Нет паник на данных файла |
| G-7 | Чтение не выходит за `[0, high_water)` |
| G-8 | Ни один `RrsetRef` не требует чтения более `MAX_TREE_DEPTH + MAX_OVERFLOW_PAGES` страниц; материализация ≥ 2 RR одновременно не требуется ни одним методом |

### 20.3. API-эскиз

**(A) `pulse-zonefile` — примитивы:**

```rust
pub struct ZoneFile { /* Arc<File>, Arc<Mmap>, ReaderRegion, OpenConfig, ZoneIndex */ }
pub struct Snapshot { inner: Arc<SnapshotInner> }        // Clone ≤ 20 ns

pub struct OpenConfig { pub read_only: bool, pub map_size: u64,
                        pub lock_mode: LockMode, pub strict: bool,
                        pub allow_rollback_to_initial: bool }   // §13.7 шаг 10

impl ZoneFile {
    pub fn open(path: &Path, cfg: OpenConfig) -> Result<Self, ZoneFileError>;
    pub fn snapshot(&self) -> Snapshot;                  // O(1), без syscall
    pub fn writer(&self) -> Result<Writer<'_>, ZoneFileError>;
    pub fn stats(&self) -> Stats;                        // high_water, free, fill, map_size
}

impl Snapshot {
    pub fn txnid(&self) -> u64;
    pub fn zone(&self, origin: &NameRef<'_>) -> Option<ZoneRef<'_>>;
    pub fn find_zone(&self, qname: &NameRef<'_>) -> Option<ZoneRef<'_>>;
    pub fn zones(&self) -> ZoneIter<'_>;                 // без tombstone
}

impl<'a> ZoneRef<'a> {
    pub fn zone_seq(&self) -> u32;                       // стабильный ZoneId
    pub fn state(&self) -> ZoneState;                     // Initializing | Serving | Tombstone
    pub fn apex(&self) -> NameRef<'a>;
    pub fn serial(&self) -> u32;
    pub fn flags(&self) -> ZoneFlags;
    /// Настройки зоны: O(1) zero-copy для фиксированных полей, итератор для upstreams.
    pub fn meta(&self) -> ZoneSettingsRef<'a>;
    pub fn cursor(&self, name: &NameRef<'_>) -> Cursor<'a>;
    pub fn cursor_first(&self) -> Cursor<'a>;
}

/// Zero-copy вид настроек (§12.2) — в форме домена `ZoneSettings` (§2.7).
/// `state` сюда НЕ входит: состояние — только `ZoneEntry.state` (§12.1).
pub struct ZoneSettingsRef<'a> {
    pub default_ttl: Ttl,
    pub denial: Denial,
    pub soa_timers: SoaTimers,
    upstreams: UpstreamIter<'a>,                        // ленивый обход overflow-цепочки
}
impl<'a> ZoneSettingsRef<'a> {
    pub fn forward_upstreams(&self) -> UpstreamIter<'a>;  // Item = &'a UpstreamSpec (opaque для формата)
}

pub struct Cursor<'a> { /* путь фиксированного размера; без аллокаций */ }
impl<'a> Cursor<'a> {
    pub fn key(&self) -> Option<(NameRef<'a>, RecordType, Class, u16)>;
    pub fn node(&self) -> Option<NodeRef<'a>>;
    pub fn rrset(&self) -> Option<RrsetRef<'a>>;
    pub fn rrset_by_subtype(&self, subtype: u16) -> Option<RrsetRef<'a>>;
    pub fn next(&mut self) -> bool;
    pub fn next_name(&mut self) -> bool;
}

pub struct NodeRef<'a> { pub name: NameRef<'a>, pub exists: bool, pub is_apex: bool,
                        pub is_zone_cut: bool, pub has_children: bool }

/// Реализация порта записи (§20.3(C)): тип объявлен здесь, чтобы он был определён.
pub struct Writer<'f> { /* lock-file guard, dirty-set, allocator, freelist */ }
impl<'f> ZoneWriter for Writer<'f> { /* 6 методов — §20.3(C) */ }

/// Публичные методы — ровно как в `domain-model` §5.1 (источник истины по API).
pub struct RrsetRef<'a> { pub owner: NameRef<'a>, pub rr_type: RecordType,
                          pub subtype: Option<RecordType>, pub class: Class, pub ttl: u32 }
impl<'a> RrsetRef<'a> {
    pub fn len(&self) -> usize;                          // число RR
    pub fn iter(&self) -> RrIter<'a>;                    // Item = Rr<'a>
    pub fn to_owned(&self) -> Rrset;                     // только на границе снапшота
}

pub struct RrIter<'a> { /* index + raw */ }
impl<'a> Iterator for RrIter<'a> { type Item = Rr<'a>; }

/// Один RR в снапшоте: RDATA как 1..=N сегментов (§11.4).
pub struct Rr<'a> { /* сегменты, без владения */ }
impl<'a> Rr<'a> {
    pub fn len(&self) -> usize;                          // длина RDATA
    pub fn as_slice(&self) -> Option<&'a [u8]>;          // Some только при непрерывности
    pub fn chunks(&self) -> RdataChunks<'a>;             // 1..=N сегментов в порядке байтов
    /// Копирует ровно `len()` байт. `dst.len() < len()` → `Err(BufferTooSmall)`
    /// **без частичной записи**; при успехе возвращает `len()`. Не паникует (R-18).
    pub fn copy_into(&self, dst: &mut [u8]) -> Result<usize, BufferTooSmall>;
}

pub struct RdataChunks<'a> { /* page-walk, без аллокаций */ }
impl<'a> Iterator for RdataChunks<'a> { type Item = &'a [u8]; }

/// `lookup_all`: 0..N групп по subtype.
pub struct RrsetsRef<'a> { /* inline ≤ 4; иначе курсор внутри снапшота */ }
impl<'a> RrsetsRef<'a> {
    pub fn len(&self) -> usize;
    pub fn iter(&self) -> impl Iterator<Item = RrsetRef<'a>>;
}

/// Имя: RLE-срез (B-10). Прямого wire-среза нет; владение — только через `to_name`.
pub struct NameRef<'a> { /* rle: &'a [u8] */ }
impl<'a> NameRef<'a> {
    pub fn label_count(&self) -> u8;
    /// Метки в порядке хранения: TLD → owner (обратный к wire). Без буферизации.
    pub fn labels_rev(&self) -> impl Iterator<Item = &'a [u8]>;
    /// Прямой wire без сжатия: owner → TLD, с длинами и терминальным 0.
    pub fn write_wire(&self, out: &mut impl std::io::Write) -> std::io::Result<usize>;
    pub fn to_name(&self) -> Name;                       // владение — только при необходимости
}
```

`write_wire` обходит метки RLE от конца к началу и пишет `(len, bytes)` в forward-порядке; промежуточный буфер не нужен, стоимость O(255), ноль аллокаций. Отдельного `labels_wire` нет: прямой порядок получается только через `write_wire`, обратный — `labels_rev` (R-8).

**(B) Адаптер порта `ZoneStore`** (в `pulse-server::infrastructure`):

| Метод порта | Примитив |
|---|---|
| `snapshot()` | `ZoneFile::snapshot()`; `SnapshotHandle = Arc<SnapshotInner>` |
| `zones()` / `zone_meta()` | `Snapshot::zones()`, `zone()`; `meta()` → `ZoneSettingsRef` (O(1) для фиксированных полей) |
| `find_zone(qname)` | `Snapshot::find_zone` (§12.4) |
| `serial(zone)` | `ZoneRef::serial()` |
| `state(zone)` | `ZoneRef::state()` (`Initializing` → REFUSED, §12.6) |
| `lookup(origin, qname, qtype)` | `cursor` + `node_lower_bound`; для `qtype = RRSIG` → `WrongAccessor` (§12.5) |
| `lookup_all(origin, qname, type)` | обход по `subtype` (§12.5); все группы, без склейки |
| `node(origin, name)` | `Cursor::node()` |
| `next_name(after)` | `cursor` + `next_name()` |
| `enumerate(from, visitor)` | `cursor` + `next_name()`; visitor получает **`RrsetRef<'a>`** (заимствован из снапшота, не владеющий `Rrset`), возвращает `ControlFlow`; при `Break` возвращается `Some(Name)` для продолжения (R-10, `domain-model` §5.1) |

Ни один метод не выполняет DNS-композицию (wildcard/CNAME/referral/NXDOMAIN) — это доменный сервис.

**(C) Запись — реализация порта `ZoneWriter` (`domain-model` §5.2.6, 6 методов):**

Сигнатуры — **ровно** как в `docs/spec/domain-model.md` §5.2.6. Транзакция **неявная**: первый `apply` открывает её, `commit(zone, policy)` завершает.

```rust
pub trait ZoneWriter: Send {
    fn create_zone(&mut self, origin: Origin, class: Class, options: ZoneOptions)
        -> Result<ZoneId, WriteError>;

    fn delete_zone(&mut self, zone: ZoneId) -> Result<DeleteOutcome, WriteError>;

    fn apply(&mut self, zone: ZoneId, intent: WriteIntent, edit: Edit)
        -> Result<ApplyOutcome, WriteError>;

    fn commit(&mut self, zone: ZoneId, policy: CommitPolicy) -> Result<CommitResult, WriteError>;

    fn sync(&mut self) -> Result<(), WriteError>;

    fn compact_zone(&mut self, zone: ZoneId, opts: CompactOptions)
        -> Result<CompactOutcome, WriteError>;
}

pub enum CommitPolicy { Commit(Durability), Abort }
pub enum CommitResult { Committed(CommitOutcome), Aborted }
```

Правила (из домена, формат их не меняет):

- одновременно активна максимум одна неявная транзакция; `create_zone`/`delete_zone`/`compact_zone`/`sync` при активной транзакции → `Busy`;
- повторный `apply` должен совпадать по `(zone, intent)`, иначе `Busy`;
- `commit` без активной транзакции → `UnknownTxn`; `CommitPolicy::Abort` = откат;
- `apply` после `Commit`/`Abort` начинает новую транзакцию; drop `ZoneWriter` отбрасывает неприменённое (`dangling_txn_total`);
- `create_zone`/`delete_zone`/`compact_zone` — самостоятельные внутренние коммиты;
- ошибка любого `apply` переводит неявную транзакцию в failed: допустим только `commit(zone, CommitPolicy::Abort)`, затем — новая транзакция.

**Маппинг формата на домен (B-4):**

| Домен | Формат | Правило |
|---|---|---|
| `DeleteOutcome { zone, deleted_txn: Txn, reclaim_after: Txn }` | `ZoneEntry.deleted_txn: u64` | `reclaim_after == deleted_txn` — порог условия `reclaim_txn ≥ deleted_txn`, не дедлайн |
| `ZoneMeta.deleted_txn: Option<Txn>` | `ZoneEntry.deleted_txn: u64` | `0 ↔ None`; **`Some(0)` запрещён** (`Corrupt(BadZoneMeta)` на чтении, `InvalidEdit` на записи) |
| `CommitResult::Committed(CommitOutcome)` | `CommitOutcome { commit_id, snapshot, … }` | `commit_id` = `txnid` опубликованной meta |
| `CommitPolicy::Commit(Durability)` | `MODE_SYNC` / `MODE_NOMETASYNC` / `MODE_NOSYNC` | §5.2 ADR 0003 |
| `CompactOutcome { zone, pages_before, pages_after, commit_id, snapshot }` | `compact_zone` | `pages_*` — по `page_count_high_water`/`free_page_count` до и после |
| `ZoneOptions { kind, default_ttl, denial, initial_soa, initial_ns, forward_upstreams, durability }` | `ZoneEntry` + блок §12.2 | `initial_soa`/`initial_ns` в той же транзакции → `Serving`; без них — `Initializing` |
| `ZoneSettings { default_ttl, denial, soa_timers, forward_upstreams }` | `ZoneSettingsRef` | `state` в meta-блоке отсутствует: только `ZoneEntry.state` |

**Метаданные зоны — только через порт:** правка настроек идёт как `apply(zone, intent, Edit { ops: [EditOp::SetZoneMeta { patch }] })` (`domain-model` §5.2.2). Отдельного `Writer::set_zone_meta`, типа `ZoneSpec` и методов `begin`/`abort` нет.

### 20.4. Разделение ответственности

| Слой | Знает | Не знает |
|---|---|---|
| `pulse-zonefile` | страницы, RLE, COW, txn, CRC, зоны | RFC-семантику ответа |
| `pulse-server::domain` | RFC 1034 §4.3.2, RFC 4592, DNSSEC | формат, `PageId`, RLE |
| `pulse-server::application` | порты, use cases | ни того, ни другого |

`ZoneStore` реализуется в `pulse-server::infrastructure` (тонкая обёртка над `Snapshot` + доменный сервис); `pulse-zonefile` не зависит от `pulse-server` (DAG ADR 0001 §4.1). Соответствие: `SnapshotHandle = Arc<SnapshotInner>`; `Rrset` строится из `RrsetRef`: inline-RDATA — без копирования, overflow — по одному RR через `copy_into`; полная материализация набора — только при выходе за границу снапшота (`to_owned()` для API/экспорта), не на query-пути.

**Таблица соответствия типов спека ↔ `domain-model` (R-11, источник истины — домен):**

| В спеке (адаптер) | В `domain-model` | Расхождение |
|---|---|---|
| `RrsetRef { owner, rr_type: RecordType, subtype: Option<RecordType>, class, ttl: u32 }` | `RrsetRef { owner, rr_type: RrType, subtype: Option<RrType>, class, ttl: Ttl }` (§5.1) | адаптер конвертирует `RecordType → RrType`, `u32 → Ttl`; `flags: RrsetFlags` — внутреннее поле, наружу не выходит |
| `RrsetRef::len()/iter()/to_owned()` | то же | нет |
| `RrsetRef::rr(i)` | — | адаптер-локальный доступ по индексу; наружу — только `iter()` |
| `Rr::len()/as_slice()/chunks()/copy_into()` | то же | `copy_into` → `Result<usize, BufferTooSmall>` (R-18) |
| `RrsetsRef` | `RrsetsRef` | нет |
| `NameRef::{label_count, write_wire, to_name}` | то же | `labels_rev` — **только адаптер** (в порту нет); `as_rle`/`write_wire_buf`/`labels_wire` удалены (R-8) |
| `NodeRef { name, exists, is_apex, is_zone_cut, has_children }` | то же | нет (переименовано из `NodeView`) |
| `ZoneSettingsRef { default_ttl, denial, soa_timers, forward_upstreams }` | то же (§5.1) | `state` не входит (только `ZoneEntry.state`) |
| `enumerate(from, visitor: FnMut(RrsetRef<'a>) -> ControlFlow)` | то же | `Some(Name)`-курсор при `Break` |
| `Corrupt { kind, page: Option<u32>, detail }` | `Corrupt { kind, page }` | `detail` — только для логов/`fsck`, наружу не выходит |

**Таблица `CorruptKind` (9 значений домена) и внутренних причин:**

| `CorruptKind` | `CorruptDetail` (внутреннее) | Когда |
|---|---|---|
| `NoValidMeta` | `BadMagic`, `NoValidMeta` | обе meta невалидны / magic |
| `PageChecksum` | `Checksum` | CRC не сходится |
| `TreeOrder` | `KeyOrder`, `SeparatorMismatch` | порядок ключей/сепараторы |
| `Bounds` | `PageNo`, `PageType`, `ChildRange`, `DepthExceeded`, `OffsetOutOfRange`, `Truncated`, `BadReaderRegion` | границы/типы/глубина/регион reader table |
| `FreelistCycle` | `Cycle`, `Overlap` | цикл/пересечение freelist |
| `BadTtl` | `TtlOutOfRange` | TTL > `2^31−1` в файле |
| `BadZoneMeta` | `ZoneMetaField`, `ZoneMetaTooLarge` | meta-блок |
| `BadRdata` | `OverflowChain`, `RdataSum` | цепочка/RDATA |
| `BadName` | `BadNameEncoding`, `CompressionByte` | RLE/метки |

`CorruptNoValidMeta` и `TruncatedFile` остаются отдельными вариантами `ZoneFileError` (их требует ADR 0004 SEC-ZF-011) и отображаются в `Corrupt { kind: NoValidMeta | Bounds }` без потери причины.

### 20.5. Нормализация QNAME

QNAME → RLE-lowercase один раз на запрос, буфер ≤ 255 байт на стеке; `\DDD`/`\X` разворачивает `pulse-dns`; сравнение — компаратором §8.3.

---

## 21. Ошибки и защита

### 21.1. Типы

```rust
pub struct Version { pub major: u16, pub minor: u16 }

pub enum ZoneFileError {
    Io(std::io::Error),
    /// Публичная часть совпадает с `StoreError::Corrupt`; `detail` — только для логов/fsck.
    Corrupt { kind: CorruptKind, page: Option<u32>, detail: CorruptDetail },
    CorruptNoValidMeta,                            // = Corrupt{NoValidMeta}; вариант для ADR 0004
    TruncatedFile,                                 // = Corrupt{Bounds}; файл короче page_count_max*page_size
    UnsupportedVersion { found: Version, supported: Version, required_flags: u64 },
    Busy,                                          // второй writer (lock-файл)
    TooManyReaders,                                // reader table заполнена
    ReaderContended,                               // 8 попыток пиннинга не удались
    ReadersStalled { oldest_txn: u64, since_ns: u64 },
    MapFull { high_water: u32, page_count_max: u32 },          // адресное пространство исчерпано
    NoSpace { needed: u32, free: u32 },                        // страницы есть, но «молодые»
    MapAllocFailed { size: u64, errno: i32, hint: &'static str },
    IdSpaceExhausted,                              // zone_seq исчерпан (R-11)
    WrongAccessor,                                 // lookup() для RRSIG (§12.5)
    NameTooLong, LabelTooLong, RdataTooLarge, RrsetTooLarge,   // RdataTooLarge: rdata.len() > 65535
    ZoneTooLarge, UpstreamTooLarge, ZoneMetaTooLarge,
    InvariantViolation(InvariantId),
    ReadOnly,
    RefuseToRollback,                              // fsck --to-txn < reclaim_txn (R-3)
    RolledBackToInitial { instance_uuid: [u8;16], created_unix_ns: u64 },  // §13.7 шаг 10
}

/// 9 значений — ровно как в `domain-model` §6.
pub enum CorruptKind { NoValidMeta, PageChecksum, TreeOrder, Bounds,
                       FreelistCycle, BadTtl, BadZoneMeta, BadRdata, BadName }

/// Внутренняя детализация (в публичный `StoreError` не выходит) — §20.4.
pub enum CorruptDetail { BadMagic, Checksum, KeyOrder, SeparatorMismatch,
    PageNo, PageType, ChildRange, DepthExceeded, OffsetOutOfRange, Truncated,
    Cycle, Overlap, TtlOutOfRange, ZoneMetaField, ZoneMetaTooLarge,
    OverflowChain, RdataSum, BadNameEncoding, CompressionByte, BadReaderRegion }
```

> В тексте `Corrupt(Kind)` — сокращение для `Corrupt { kind: Kind, page: None, detail }`; `detail` уточняет причину, `kind` — то, что видит домен.

### 21.2. Политика при повреждении

- Чтение: `Corrupt` → SERVFAIL, `zonefile_corrupt_total{kind}`, `zone_degraded`; частичных ответов нет.
- Запись: сомнение → `abort`, файл не меняется, `NEEDS_FSCK`.
- `--repair` — только офлайн; авторемонта нет.
- SIGBUS → fail-stop, `sigbus_detected`.

### 21.3. Бюджеты чтения

≤ 8 уровней дерева + 2 каталога, ≤ 64 overflow-страниц, ≤ 255 байт имени, ≤ 128 сравнений (§10.3), ≤ 50 уровней CNAME (домен).

### 21.4. Защита файла (SEC-ZF-009, SEC-ZF-010, SEC-ZF-014)

| Правило | Деталь |
|---|---|
| Открытие данных | `O_NOFOLLOW | O_CLOEXEC`; `fstat`: обычный файл, `st_uid == geteuid()` (владелец `pulse-dns`), `mode & 0o077 == 0` |
| TOCTOU | `st_dev/st_ino` перепроверяются непосредственно перед каждым `mmap` (оба маппинга) |
| Создание | `O_CREAT|O_EXCL|O_RDWR, 0600` + `fchmod(0600)`; каталог `0700` |
| Эксклюзивность writer'а | **отдельный** файл `<zonefile>.lock` (0600), `flock(LOCK_EX|LOCK_NB)`; второй writer → `Busy` |
| Читатели | **flock не берут**; регистрируются только в reader table. Читатель не блокирует writer'а и не блокируется им |
| Writable-маппинг | **один**, только регион reader table (`PROT_READ|PROT_WRITE`, `MAP_SHARED`, `off % 64 == 0`, длина по формуле §6.1). Данные/деревья/overflow/meta — строго `PROT_READ`; запись через `pwritev` |
| SIGBUS | обработчик `SA_SIGINFO`: `si_addr` в лог, `sigbus_detected++`, `abort()` (fail-stop) |
| Прочее | `madvise(MADV_RANDOM)`/`MADV_WILLNEED` — опционально |

Почему lock-файл, а не `flock` на самом файле зон: `flock` на данных заставил бы читателей брать разделяемую блокировку (иначе writer неотличим от чужого процесса), что противоречит «читатель не блокирует writer'а» и не защищает от усечения. Отдельный lock-файл отделяет эксклюзивность записи от жизненного цикла данных.

---

## 22. Golden-пример (пересчитан: заголовок 40, LeafValue 20, reader table 9×4064)

Зона `example.com`, RRset `www.example.com. IN A 192.0.2.1`, `page_size = 4096`, `map_size = 4 GiB`.

```
page 0  SUPERBLOCK_A: magic "PULSEZF1", ver 1.0, page_size 4096,
        page_count_max 1048576 (4 GiB),
        feature_flags_required = 0x3F (F0..F5),
        reader_region_off = 16384, reader_region_len = 36864,
        reader_region_align = 4096,
        page_meta_a = 2, page_meta_b = 3, page_data_first = 13,
        page_reader_table = 4, page_reader_table_count = 9,
        sections[0] = {id=1, CORE, first_page=0, page_count=1048576}
page 1  SUPERBLOCK_B: копия, superblock_copy = 1
page 2  META_A: txnid=2, durable_txn=2, page_count_high_water=16,
        zone_dir_root=13, zone_dir_level=1, zone_count=1,
        freelist_head=0, freelist_tail=0, freelist_entries=0, free_page_count=0,
        next_zone_seq=2, reader_region_off=16384, reader_region_len=36864
page 3  META_B: нули (невалидна; второй слот пуст)
pages 4..12  READER_TABLE (9 страниц, собственный дескриптор §6.1):
        каждая: page_type=7, version=1, page_no=4..12, slots_used_in_page=0, crc32c=0
        payload_len — ВЫЧИСЛЯЕМОЕ значение (поля в дескрипторе нет) = page_size − 32 = 4064;
        slots_used_in_page=0 означает, что на момент фикстуры нет ни одного читателя
        (ни один поток не зарегистрировал слот), поэтому все 1024×32 Б — нули
page 13 LEAF (каталог зон), level=0, n_items=1, n_restarts=1:
        item0: shared_len=0, suffix_len=19
               suffix = RLE(example.com) [13 байт] || FE FF | 00 00 | 00 00
                      = 03 63 6f 6d 07 65 78 61 6d 70 6c 65 00 FE FF 00 00 00 00
               значение — 72-байтовый ZoneEntry (для ключа T_ZONE_ENTRY LeafValue
               не используется; область значения интерпретируется по типу ключа):
                 class=1, flags=0, tree_root=14, tree_level=1,
                 state=Initializing(0), deleted_txn=0,
                 rrset_count=1, rr_count=1, soa_serial=0,
                 zone_origin_len=13, zone_seq=1, meta_root=15
        item_bytes = 4 + 19 + 72 = 95
        encoded_size = 56 + 2*1 + 2*1 + 95 = 155; free_bytes = 3941
page 14 LEAF (дерево зоны), level=0, n_items=2, n_restarts=1:
        item0: shared_len=0, suffix_len=19
               suffix = RLE(example.com) || 00 00 | 00 00 | 00 00        (T_NODE)
               LeafValue: kind=NODE, flags=APEX, ttl=0, rr_count=0, rdlen=0, val_u32=0
               item_bytes = 4 + 19 + 20 = 43
        item1: shared_len=14, suffix_len=5
               суффикс = 01 00 01 00 00     (type=1 A, class=1, subtype=0)
               LeafValue: kind=INLINE, flags=0, ttl=300, rr_count=1, rdlen=4, val_u32=0
               payload (сразу за LeafValue) = 00 04 C0 00 02 01
               item_bytes = 4 + 5 + 20 + 6 = 35
        encoded_size = 56 + 2*1 + 2*2 + 43 + 35 = 140; free_bytes = 3956
page 15 ZONE_META (type 9): flags=0, denial=0 (NSEC), default_ttl=300,
        soa_refresh=3600, soa_retry=600, soa_expire=604800, soa_minimum=300,
        upstream_count=0, upstream_bytes=0, upstream_layout=0, upstream_ref=0
```

Проверки согласованности:

| Проверка | Расчёт |
|---|---|
| страниц reader table | `ceil(1024*32 / (4096−32)) = ceil(32768/4064) = 9` → pages 4..12 |
| `reader_region_off` | `4 * 4096 = 16384`; `16384 % 64 == 0` ✓ |
| `reader_region_len` | `9 * 4096 = 36864` ✓ |
| `page_data_first` | `4 + 9 = 13` ✓ |
| `high_water` | первый невыданный номер после страниц 13, 14, 15 → **16** ✓ |
| ключ item1 | 13 байт имени + 6 байт хвоста = 19; `shared_len=14` (13 байт имени + первый `0x00` хвоста item0), суффикс 5 байт ✓ |
| порядок | `T_NODE` (0x0000) < `A` (0x0001) ✓ |
| `encoded_size` каталога | `56 + 2 + 2 + 95 = 155` ✓ (ZoneEntry 72 байта) |
| `encoded_size` дерева | `56 + 2 + 4 + 43 + 35 = 140` ✓ |
| `zone_seq` | первый выданный = 1 (0 зарезервирован как «не назначен»), `next_zone_seq = 2` ✓ |
| `txnid` | создание файла = 1 (§4), первый пользовательский коммит = **2**; `durable_txn = 2` ✓ |
| `state` | `Initializing` (0): SOA ещё нет — допустимо только в этом состоянии (W-11); apex-only/Serving появится после первого коммита с SOA+NS |

Golden-file в тестах: побайтово все 16 страниц (0..15), включая дескрипторы reader table (crc=0) и 72-байтовый `ZoneEntry`.

> **Статус фикстуры.** Это байтовый артефакт формата: зона и её данные записаны **одной** транзакцией (`txnid=2`). Через порт то же состояние недостижимо одной транзакцией: `create_zone` — отдельный коммит (`txnid=2`), затем `apply`+`commit` (`txnid=3`). Фикстура нужна для проверки парсера/сериализатора, а не для воспроизведения через API.

### 22.1. Тест-векторы RLE и `has_children` (B-2)

Базовое дерево: apex `example.com` (SOA+NS), ENT `b.example.com`, записи `a.b.example.com` и `c.b.example.com`.

```
RLE(example.com)     = 03 63 6f 6d 07 65 78 61 6d 70 6c 65 00              (13 Б)
RLE(b.example.com)   = 03 63 6f 6d 07 65 78 61 6d 70 6c 65 01 62 00        (15 Б)
RLE(a.b.example.com) = 03 63 6f 6d 07 65 78 61 6d 70 6c 65 01 62 01 61 00  (17 Б)
RLE(c.b.example.com) = 03 63 6f 6d 07 65 78 61 6d 70 6c 65 01 62 01 63 00  (17 Б)

ключ A-записи в b.example.com = RLE(b.example.com) || 00 01 | 00 01 | 00 00   (21 Б)
ключ T_NODE  в b.example.com  = RLE(b.example.com) || 00 00 | 00 00 | 00 00   (21 Б)
```

Разбор предиката: `p = RLE(b.example.com)` без терминатора = первые 14 Б, оканчиваются на `01 62`.
`lower_bound(p || 0x01)`:
- владелец `b` имеет на позиции 14 байт `0x00` (терминатор) → «потомков нет»;
- потомок `a.b` имеет на позиции 14 байт `0x01` (длина метки) → **потомки есть**.

| Проверка | `p` (hex) | байт на позиции `len(p)` | `has_children` |
|---|---|---|---|
| `b.example.com` | `…07 65 78 61 6d 70 6c 65 01 62` | `01` (у `a.b`/`c.b`) | **true** |
| `b.example.com` (в дереве только его собственные ключи) | то же | кандидат за границей/префикс не совпал | false |
| `example.com` | `…07 65 78 61 6d 70 6c 65` | `01` (у `b`) | **true** |
| `a.b.example.com` | `…01 62 01 61` | следующий ключ `> p`, префикс не совпал | false |

Сценарии (все проверяются как golden-тесты):

| # | Действие | `node(b)` (exists / has_children) | `node(example)` has_children | Комментарий |
|---|---|---|---|---|
| S1 | базовое дерево | `true` (ENT) / `true` | `true` | `b` — ENT с двумя детьми |
| S2 | удалить A в `a.b` | `true` (ENT) / `true` | `true` | у `b` остался `c.b`; каскада нет |
| S3 | удалить A в `c.b` | **key absent** | **false** | `b` удалён (нет RRset/потомков); `example` остался с `APEX`, `CHILDREN_MAY_EXIST` снят |
| S4 | вставить `a.b` при наличии только `example` | `true` (ENT, создан) / `true` | `true` | шаг 9b: `b` материализован как ENT, а не APEX |
| S5 | вставить `x.example.com` в пустую зону (`tree_root = 0`) | — | `true` | шаг 1 создаёт корень-лист; шаг 9b материализует предка `example` как `APEX=1, ENT=0`; S5 выполним именно благодаря ветке `tree_root == 0` (§13.3 шаг 1) |
| S6 | удалить единственного ребёнка `x.example.com` | — | **false** | `example` остаётся (APEX), флаг `CHILDREN_MAY_EXIST` снят |


> Разрыв RDATA (`§11.4`, ревизия 1.3) этот пример не затрагивает: единственный RR — `INLINE` (payload 6 байт). Для overflow-случая в тестах отдельный golden-кейс: RRset из 2 RR по 6000 байт RDATA → `payload_bytes = 12 004`, `kind = OVERFLOW`, три страницы (4048 + 4048 + 3908), RDATA второго RR пересекает границу второй и третьей страницы; `chunks()` для RDATA **второго RR** даёт **2** куска: 2092 байта (хвост второй страницы) + 3908 байт (третья страница) = 6000; три — это число страниц цепочки, а не сегментов одного RR. `copy_into` отдаёт 6000 байт без материализации набора.

---

## 23. Трассировка требований ADR 0004 (SEC-ZF-*)

Источник истины — `docs/adr/0004-security-model.md` §1.1. Покрыты все 14 требований.

| Req | Где закрыто | Проверка |
|---|---|---|
| SEC-ZF-001 | §4 (self-describing, CRC, UUID, секции), §5, §13.1 шаги 2–4, §13.7 | `V:unit`, `V:integ` |
| SEC-ZF-002 | §7 (page_no/тип/txn), §16 п.1–2,5–6, §10.1, §11.4 | `V:unit`, `V:lint` |
| SEC-ZF-003 | §19 (CRC, исключение reader region, битсет), §7, §14, §21.2; валидация `active_txn`/reserved-битов слотов — §6.2, §6.4 | `V:unit`, `V:integ`, `V:bench` |
| SEC-ZF-004 | §16 п.7, §21.1–21.2 | `V:lint` |
| SEC-ZF-005 | §16 (лимиты, guards), §21.3, §2 | `V:unit`, `V:fuzz` |
| SEC-ZF-006 | не применимо (компрессия запрещена, §8.1); эквиваленты: §8.4, §11.4, §16 | `V:unit`, `V:fuzz` |
| SEC-ZF-007 | §13.6, §14, §6.3–6.4 (живой PID не вытесняется; `stale` — только диагностика), §15 (F-7) | `V:unit`, `V:integ`, `V:prop` |
| SEC-ZF-008 | §13.6 (порядок), §13.7, §15 (F-1..F-6), §19 | `V:unit`, `V:integ`, `V:prop` |
| SEC-ZF-009 | §21.4, §6.1.1, §15 F-9, §13.1 шаги 5–6 | `V:integ`, `V:manual` |
| SEC-ZF-010 | §21.4 (права, `O_NOFOLLOW`, lock-файл 0600), §4 | `V:unit`, `V:integ` |
| SEC-ZF-011 | §21.1 (`Corrupt{kind,page}`, `CorruptNoValidMeta`, `UnsupportedVersion`, `TruncatedFile`), §13.1 шаг 4 (**усечённый существующий файл → `TruncatedFile` и для writer, и для reader**; `ftruncate` только при создании, §4), **§13.1 шаг 6/§3.1: перед каждым `mmap` сверяется `st_size`, а не только `dev/ino`** (truncate-race → `TruncatedFile`, не SIGBUS), §13.9, §13.7 | `V:integ` (truncate существующего файла, в т.ч. между `open` и `mmap`), `V:unit` |
| SEC-ZF-012 | §16 п.9 (**4 таргета**: `zonefile_read`, `zonefile_write`, `zonefile_roundtrip`, `reader_table_state`) + §22, §21.2 | `V:fuzz` (4 таргета) |
| SEC-ZF-013 | §16 п.9, §8.3, §10.2, §11.2 | `V:miri` |
| SEC-ZF-014 | §16 п.8, §6.1 (дескриптор, `off % 64`, формула длины, валидация при открытии), §21.4, §20.2 | `V:lint`, `V:manual` |

---

## 24. Открытые вопросы

Статус после ревизии 1.4 (второй аудит): все N-1…N-6 и R-1…R-20 закрыты; открытыми остаются вопросы, требующие решений вне формата.

1. **`CHANGESET_LOG`** при Z > 50k зон — v1 или v1.1 (§12.4).
2. **Формат upstream-блоба** (opaque 4096 байт) — согласовать с `pulse-server`; домен ограничивает 16 записей, формат допускает 32 (§12.2).
3. **Интервал GC** (`GC_INTERVAL_MS = 300 000`): подтвердить; влияет только на скорость возврата места после удаления зоны, не на корректность (§12.3, §13.8).
4. **`ZoneEntry` 72 байта**: раскладка зафиксирована в ревизии 1.4 (добавлен `deleted_txn`). Формат ещё не реализован, поэтому миграция не нужна; если фикстуры уже сгенерированы — перегенерировать (§12.1, §22).

Ранее закрытые (для истории): TTL clamp (§11.5), `WriteIntent`/`Edit`/`ApplyOutcome` (ссылки, §11.5), `lookup_all`/`WrongAccessor` (§12.5), `Memory`-режим (§13.6), `MAX_ZONE_META_PAGES` (§12.2), `TooManyReaders` (§21.1), лимит `rdlength` (§11.4).

**Известные компромиссы ревизии 1.4** (описаны, не «тихие»):

| Компромисс | Цена | Почему принят |
|---|---|---|
| COW bucket-страниц (§11.7) | +1 страница-образ на проход выдачи и на коммит с освобождениями; при исчерпании high-water образ берётся из числа выдаваемых | без COW мутация freelist ломает восстановление (и MVCC-инвариант) |
| GC tombstone раз в 5 мин (§13.8) | место возвращается с задержкой до интервала | мгновенное освобождение невозможно: на страницы ссылаются живые снапшоты |
| Публичный `CorruptKind` — 9 значений (§20.4) | домен теряет детализацию причины (она остаётся в `detail` для логов) | единый контракт ошибок с `domain-model` §6 |
| `FORWARD` — в `ZoneEntry`, `SIGNED/denial` — в meta-блоке (§12.1) | `meta()` читает страницу при проверке подписи | устранено дублирование; `find_zone` остаётся одностраничным для классификации |
| Guard 148/351 item'ов (§16 п.3) | верхняя оценка; фактическая ёмкость зависит от длин суффиксов | guard защищает от «бомбы» в файле, а не моделирует раскладку |
