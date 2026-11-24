# Спецификация формата файла зон pulse (v1)

- **Файл:** один, содержит все зоны, подключается через `mmap`
- **Версия формата:** 1.0 (разделы §1–§24); **2.0** — дельта §25 (параллельная запись по зонам)
- **Версия спецификации:** ревизия 1.6, 2026-11-24 (добавлена §25, решение — `docs/adr/0005-parallel-writers.md`)
- **Статус:** проект, на утверждение
- **Реализует:** `pulse-zonefile` (адаптер портов `ZoneStore` / `ZoneWriter`)
- **Источник истины по ID безопасности:** `docs/adr/0004-security-model.md` §1.1
- **Связанные:** `docs/adr/0003-zonefile-format.md`, `docs/adr/0005-parallel-writers.md`, `docs/adr/0001-ddd-architecture.md`, `docs/spec/domain-model.md` (§5.1–5.2)

Документ самодостаточен для реализации: все поля, смещения, порядок байт и инварианты. Любое «на усмотрение реализации» помечено и снабжено списком допустимых вариантов.

> **Читать вместе с §25.** §1–§24 описывают раскладку и алгоритмы для одного writer'а на файл (формат 1.0). §25 — нормативная дельта формата 2.0: головы зон вместо глобальной meta, `epoch`/`version`, per-zone freelist, group commit, recovery по зонам. При расхождении §25 имеет приоритет.

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
| `durable_txn` | поле meta: последний `txnid`, чьи данные **и эта meta** гарантированно на диске для данной меты; `≤ txnid`, может быть меньше у `Flush`/`Memory` |
| `durable_watermark` | `max` по всем валидным meta от `min(durable_txn, txnid)` — **единственный** watermark, который используют recovery, `effective_mode`/`check_commit` и advisory `reclaim_txn`; не понижается выбором более старой meta |
| `reclaim_txn` | `min(durable_watermark − 1, oldest_reader_txn)` — **строгая** граница переиспользования; при `durable_watermark = 1` равна 0 (переиспользование невозможно) |
| `recovered_unsynced` | диагностический признак: recovery принял meta `T > durable_watermark` по политике `Sync`/`Flush` (§13.7) |
| `torn_meta` | диагностический признак: один из двух слотов meta невалиден (torn/недописан), второй валиден; сам по себе **не** требует `NEEDS_FSCK` (§13.7 шаг 5) |
| `memory_tail_discarded` | диагностический признак: `Memory`-файл открыт чисто на подтверждённой meta `txnid ≤ durable_watermark`; неподтверждённый хвост отброшен (§13.7 шаг 7a) |
| reader / snapshot | зафиксированный `txnid`, по которому читаются данные |
| writer | единственный поток/процесс, выполняющий коммиты |

Соглашения:

- Все целые **поля структур и ключей** — **little-endian** (`type`/`class`/`subtype` в ключе, `LeafValue.*`, `rdlen`, `ttl`, `val_u32` и т. д.).
- **Исключение — DNS wire:** `u16 rdlength` внутри inline/overflow `payload` (§11.2/§11.4) хранится **big-endian**, как в DNS-сообщении; сама `rdata[]` — opaque wire-байты (порядок задаёт тип RR). Это единственное место, где байты payload не LE.
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
// MAX_ZONE_META_PAGES — функция от page_size (не константа файла):
// const fn max_zone_meta_pages(page_size: u32) -> u32 {
//     ceil(MAX_ZONE_META / (page_size - OVERFLOW_HEADER_SIZE))
// }  → 65 @4096, 33 @8192, 17 @16384

MODE_NOSYNC              = 0
MODE_NOMETASYNC          = 1
MODE_SYNC                = 2
DEFAULT_SYNC_MODE        = MODE_SYNC          // MODE_NOSYNC — экспериментальный, по умолчанию выключен (§13.6)

// Persistent-коды поля superblock.sync_mode (§4). Это ОТДЕЛЬНЫЙ enum:
// его значения НЕ совпадают с кодами MODE_* выше.
SYNC_MODE_SYNC           = 0    // Sync: данные и meta fsync'нуты
SYNC_MODE_FLUSH          = 1    // Flush: данные fsync'нуты, meta — нет
SYNC_MODE_MEMORY         = 2    // Memory: ни данные, ни meta не форсируются
SYNC_MODE_FIELD_VERSION  = 1    // версия поля (+625); 0 в legacy-файле = «поля не было»

READER_SLOTS             = 1024
READER_SLOTS_PER_THREAD  = 4        // вложенные снапшоты одного потока (§6.3)
GC_INTERVAL_MS           = 3_600_000 // maintenance-задача GC tombstone-зон раз в час (§13.8)
SYNC_INTERVAL_MS         = 1_000     // эксплуатационный максимум между sync() в Flush/Memory (§13.6); не формат
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
| I-3 | Активна ровно одна meta: среди валидных (прошедших проверку против superblock) выбирается **самая новая по `txnid`**; ограничение `txnid ≤ durable_txn` снято (§13.7) |
| I-4 | Страницы, достижимые из `meta(T)`, не изменяются: страница, освобождённая в `F`, переиспользуется только при `F < durable_watermark` **и** `F ≤ oldest_reader_txn` (эквивалентно `F ≤ reclaim_txn`, §14) |
| I-5 | `txnid` строго возрастает, `txnid ≠ 0` |
| I-6 | `durable_watermark ≤ txnid(active)`; watermark не понижается при recovery/приёме `Flush`-meta; страница с `free_txn ≥ durable_watermark` не выдаётся, даже если `oldest_reader_txn` больше (правило и обоснование — §14) |
| I-7 | Ключи в дереве строго возрастают по компаратору §8.3 |
| I-8 | `branch.key[i]` = точный минимум поддерева `branch.child[i]` |
| I-9 | Глубина любого дерева ≤ `MAX_TREE_DEPTH` |
| I-10 | Ни одна страница не достижима из двух мест |
| I-11 | Свободные страницы не достижимы из активной meta |
| I-12 | Каждая meta содержит **полный** набор корней (дерево зон, freelist, reader table, счётчики) — восстановление не зависит от предыдущей meta |
| I-13 | `sync_mode` — нижняя граница durability; после `durable_watermark > 1` (первый успешный `Sync`/`sync()`) все последующие коммиты обязаны быть `Sync` (липкий режим, §4.1/§13.6) |
| I-14 | `durable_watermark = max(min(durable_txn, txnid))` по валидным meta; recovery и runtime используют только его. `durable_txn(selected) < durable_watermark` — нарушение монотонности: `NEEDS_FSCK` + `write_locked` (read-only до offline fsck), не тихое принятие (§13.7, §17 W-10) |

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
| +624 | 1 | `sync_mode` | persistent-режим durability: 0 = Sync, 1 = Flush, 2 = Memory; иное → `Corrupt` |
| +625 | 1 | `sync_mode_version` | `1` для новых файлов; хранится в superblock и пишется при encode; `0` = поля не было (legacy) → Sync |
| +626 | … | `reserved` | нули до 4088 |
| +4088 | 4 | `reserved_tail` | 0 |
| +4092 | 4 | `reserved_tail2` | 0 (последние 4 байта записи) |

> `sections` занимает байты `[+112, +624)`; `sync_mode`/`sync_mode_version` — `[+624, +626)`; байты `[+626, +4088)` — `reserved` (нули). Смещения всех полей до `+624` не менялись, поэтому golden-файлы, где `sync_mode = Sync = 0`, сохраняют нулевой байт в `+624`.

Дескриптор секции (32 байта, выровненный layout):

| Смещение | Размер | Поле |
|---|---|---|
| +0 | 2 | `id` |
| +2 | 2 | `version` |
| +4 | 4 | `first_page` |
| +8 | 4 | `page_count` |
| +12 | 4 | `pad` (MUST 0) |
| +16 | 8 | `flags` |
| +24 | 8 | `reserved` (MUST 0) |

`pad[4]` существует только для выравнивания `u64 flags` по 8 байт: плотная упаковка поставила бы `flags` на +12, что на некоторых архитектурах делает доступ невыровненным и ломает детерминированные смещения. С `pad` все поля лежат по естественным адресам, `size_of == 32`, и смещения одинаковы на любой платформе. Читатель проверяет `pad == 0` и `reserved == 0` при декодировании всегда (несовпадение — `Corrupt(Bounds)`); `strict` эту проверку не ослабляет, а на значения полей в рантайме полагаться нельзя.

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

### 4.1. `sync_mode`: persistent-режим durability

`sync_mode` — **неизменяемое свойство файла**, задаётся при создании из `CreateConfig.sync_mode` и описывает, какой класс durability разрешён коммитам этого файла. Причина, по которой поле живёт в superblock, а не в meta: recovery обязан знать, гарантированы ли данные у **самой новой** валидной meta, ещё до выбора/принятия этой meta (§13.7).

| `sync_mode` | Порт (`Durability`) | Runtime-константа (§2) | Что гарантировано для данных meta |
|---|---|---|---|
| 0 `Sync` | `Sync` | `MODE_SYNC = 2` | данные и meta fsync'нуты |
| 1 `Flush` | `Flush` | `MODE_NOMETASYNC = 1` | данные fsync'нуты до записи meta; сама meta не форсируется |
| 2 `Memory` | `Memory` | `MODE_NOSYNC = 0` | данные не форсируются; meta может пережить данные |

Правила:

1. **Валидация.** Поле занимает два байта: `sync_mode` (`u8`, `+624`) и `sync_mode_version` (`u8`, `+625`, `SYNC_MODE_FIELD_VERSION = 1`). Проверка выполняется при открытии, до выбора/принятия meta (fail-closed):
   - `sync_mode_version == 0` — legacy-файл, поля не было: допустим **только** при `sync_mode == 0` и трактуется как `Sync`; `sync_mode != 0` при версии 0 → `Corrupt { kind: Bounds, detail: OffsetOutOfRange }`;
   - `sync_mode_version == 1` — требует `sync_mode ∈ {0,1,2}`; `sync_mode > 2` (в частности, любое значение вне enum) → `Corrupt { kind: Bounds, detail: OffsetOutOfRange }`;
   - `sync_mode_version ∉ {0,1}` — версия поля новее, чем понимает сборка → `UnsupportedVersion { found: Version { major: FORMAT_VERSION_MAJOR, minor: u16::from(sync_mode_version) }, supported: Version { major: FORMAT_VERSION_MAJOR, minor: 1 }, required_flags: 0 }` (§21.1). Не открывать файл «на удачу».
2. **Копии A/B и хранение.** Поле пишется в **обе** копии superblock при создании (шаг 5 ниже, `pwrite` в page 0 и page 1) и после создания не меняется. `sync_mode` и `sync_mode_version` — **отдельные сохраняемые поля** superblock: обе величины обязаны храниться в in-memory структуре, записываться при encode (а не подставляться константой), декодироваться при open и сравниваться между A и B наравне. Обе валидные копии обязаны иметь одинаковые `sync_mode` и `sync_mode_version`; расхождение любой из двух величин, в частности `A: version=1, B: version=0`, → `Corrupt` (как для `page_size`/`page_count_max`/`instance_uuid`). Поле неизменяемо после создания, поэтому расхождение — признак порчи, а не «штатного» обновления.
3. **Режим — нижняя граница, а не потолок.** Коммит вправе быть **сильнее** файлового режима (`Flush`-файл может коммитить `Sync`; `Memory`-файл — любой до первого `sync()`), но не слабее: `commit(Durability::Memory)` на `Sync`/`Flush`-файле и `commit(Flush)` на `Sync`-файле отклоняются `InvariantViolation(DurabilityBelowFileMode)`. Иначе recovery доверился бы `sync_mode` и принял бы meta, чьи данные не fsync'нуты. Числовые `MODE_*` (runtime, §2) и дисковые коды `sync_mode` (0/1/2) — **разные enum'ы** с противоположным порядком; сравнивать их напрямую запрещено, сравнение — только по классу `Memory < Flush < Sync`.
4. **`0 = Sync` — безопасный legacy-default.** В файлах, созданных до появления поля, байт `+624` нулевой; трактовка «0 = Sync» сохраняет их поведение и не ломает golden-байты. `sync_mode_version = 0` отличает такие файлы от новых.
5. **Смена режима — только пересозданием/компакцией** (`zonefile compact --out`), как `page_size`/`map_size`; на ходу поле не меняется. Это осознанный компромисс: один файл — один класс durability, зато recovery не зависит от истории коммитов.
6. **Липкое повышение (sticky upgrade).** После первого успешного `Sync`/`sync()` (`durable_watermark > 1`, см. §13.7/§14) единственный допустимый режим коммита — `Sync`. Правило выводится из единого watermark, отдельного поля не требуется: два последующих слабых коммита затирают слоты, включая слот durable-меты `D` (`D+1` пишется вместо `D−1`, `D+2` — вместо `D`), и power loss откатил бы состояние ниже подтверждённого `Sync`. Поэтому `sync()` в `Flush`/`Memory`-файле — **чекпойнт**: после него файл навсегда коммитит `Sync`; понижение запрещено (`InvariantViolation(DurabilityBelowFileMode)`, §15 F-12). `superblock.sync_mode` при этом не меняется — он остаётся нижней границей и историческим классом файла.

Superblock B — копия с `superblock_copy = 1`. Расхождение `page_size`/`page_count_max`/`instance_uuid`/`sync_mode`/`sync_mode_version` между копиями → `Corrupt`. При открытии побеждает копия с валидным CRC (при обеих — A).

**Создание файла** (B-12) — строгая последовательность, один раз:

```
1. проверить существование пути (lstat): существует → AlreadyExists (ДО lock'а,
   чтобы повторное создание не выглядело как Busy)
2. open(path + ".lock", O_CREAT|O_RDWR, 0600) + flock(LOCK_EX|LOCK_NB) → Busy
3. open(path, O_CREAT|O_EXCL|O_RDWR, 0600) + fchmod(0600)   # только создание
4. ftruncate(map_size); mmap(PROT_READ)
5. записать superblock A и B (fields, CRC, `sync_mode = CreateConfig.sync_mode`,
     `sync_mode_version = 1`); pwrite, оба
6. записать начальную meta в page 2:
     txnid = 1, durable_txn = 1, все корни 0,
     page_count_high_water = page_data_first, free_page_count = 0,
     next_zone_seq = 1, meta_flags = 0, commit_unix_ns = created_unix_ns
7. записать страницы reader table (type 7, crc=0, все слоты 0)
8. page 3 оставить нулевой (второй meta-слот невалиден)
9. fdatasync(fd); fsync каталога
```

**`commit_unix_ns` начальной meta равен `created_unix_ns`** (а не 0): время создания — единственная осмысленная метка для initial-состояния; 0 означал бы «никогда не коммитили» и ломал бы эвристику §13.7 шаг 11.

`durable_txn = 1` начальной meta даёт `durable_watermark = 1`: recovery берёт самую новую валидную meta (§13.7), поэтому свежий файл открывается. **Первый пользовательский коммит — `txnid = 2`.** Пока `durable_watermark = 1`, `reclaim_txn = min(0, oldest_reader_txn) = 0`: переиспользование страниц невозможно; для `Flush`/`Memory` это означает обязательный периодический `sync()` (§13.6, §16).

**Отказы при создании (R-20).** Частично созданный файл не восстанавливается и не открывается; удаляет его **создатель** (`ZoneFile::create`), а не `open`:

| Момент | Ошибка | Кто удаляет файл |
|---|---|---|
| шаг 1 (путь существует) | `AlreadyExists` | — (ничего не создано, lock не берётся) |
| шаг 2 (lock занят) | `Busy` | lock-файл не удаляется (владелец — другой процесс) |
| шаг 3–4 (создание/`ftruncate`) | `MapAllocFailed` / `Io` | создатель: закрыть fd, `unlink(path)` (best-effort), затем отпустить и `unlink` `<zonefile>.lock` |
| шаг 5–8 (superblock/meta/reader) | `Io` | создатель: то же (файл + lock-файл) |
| шаг 9 (`fdatasync`/`fsync`) | `Io` | создатель: то же |
| `open()` на существующем частичном файле | `CorruptNoValidMeta` / `BadReaderRegion` / `TruncatedFile` | **никто** — `open` не удаляет и не «дочинивает» (SEC-ZF-011) |

**Очистка при отказе создания.** Ошибка на шагах 3–9 не должна оставлять ни частичный файл, ни lock-файл: создатель в обратном порядке `munmap` → `close` → `unlink(path)` → `flock(UN)` → `close(lock_fd)` → `unlink(lock)`. Если `unlink` не удался (нет прав/RO-ФС), исходная ошибка возвращается, а путь логируется — «осиротевший» частичный файл затем даёт `CorruptNoValidMeta`/`AlreadyExists` при следующей попытке, что диагностируемо. `open()` никогда не удаляет файл: решение — за администратором.

---

## 5. Meta-страница (page 2 и page 3)

Собственная раскладка (не §7). Активна **самая новая валидная meta** (максимальный `txnid`, прошедшая проверку против superblock) — ограничение `txnid ≤ durable_txn` снято (§13.7). `durable_txn` в meta — per-meta значение; единый `durable_watermark` вычисляется как `max(min(durable_txn, txnid))` по валидным meta и используется для sticky/reclaim (§13.7, §14).

| Смещение | Размер | Поле | Описание |
|---|---|---|---|
| +0 | 4 | `page_type` | 1 |
| +4 | 2 | `meta_flags` | bit0 NEEDS_FSCK, bit1 READONLY_HINT, bit2 COMPACTION_SUGGESTED, bit3 EXPERIMENTAL |
| +6 | 2 | `reserved0` | 0 |
| +8 | 4 | `page_no` | 2 или 3 |
| +12 | 4 | `crc32c` | CRC всей страницы, поле = 0 |
| +16 | 8 | `txnid` | ≥ 1 |
| +24 | 8 | `durable_txn` | ≤ `txnid`; per-meta watermark: последняя meta, чьи данные **и** она сама были гарантированно на диске; может быть `< txnid` (Flush/Memory, §13.7). Агрегат по валидным метам — `durable_watermark` (§1, §13.7) |
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
| +120 | 8 | `reclaim_txn` | `min(durable_watermark − 1, oldest_reader_txn)` на момент коммита; 0 = переиспользование запрещено |
| +128 | 4 | `next_zone_seq` | аллокатор `ZoneId` (§12.3) |
| +132 | 4 | `name_dict_root` | 0 в v1 |
| +136 | 4 | `changeset_log_root` | 0 в v1 |
| +140 | 4 | `manifest_root` | 0 в v1 |
| +144 | 4 | `last_error_code` | диагностика |
| +148 | 4 | `last_error_page` | диагностика |
| +152 | 8 | `last_error_txn` | диагностика |
| +160 | 32 | `fsck_hint` | ASCIIZ |
| +192 | … | `reserved` | нули до конца страницы |

Валидация meta при чтении: `page_type`, `page_no == слот`, CRC, версия, `page_size`, `page_count_high_water ≤ page_count_max`, корни < `high_water` (или 0), `zone_dir_level ≤ MAX_TREE_DEPTH`, `freelist_entries ≤ page_count_high_water`, `durable_txn ≤ txnid`, `reclaim_txn ≤ durable_txn`. `durable_txn < txnid` — **допустимое** состояние (unsynced tail после Flush/Memory), а не ошибка; recovery его не «исправляет» повышением `durable_txn`. `reclaim_txn` — advisory-значение коммита: при открытии он пересчитывается как `min(durable_watermark − 1, oldest_reader_txn)` и не является доверенным входом для выдачи страниц (§13.7).

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
| writer | отдельный файл `<zonefile>.lock`: `O_CREAT\|O_RDWR`, 0600, `O_NOFOLLOW`, `fstat` → regular-file, `flock(LOCK_EX\|LOCK_NB)` | второй writer → `Busy`; lock не regular → `NotRegularFile`; lock снимается смертью процесса |
| reader | **никаких flock** | регистрируется только в reader table; не блокирует writer'а и не блокируется им |
| внешний писатель | исключён правами (`0600`, каталог `0700`) + `O_NOFOLLOW` | `fstat`/`dev`/`ino` перед `mmap` |

Читатель и writer открывают **данные** без блокировок; единственный «замок» — lock-файл, который берёт только writer. Это снимает прежнее требование `LOCK_SH` у читателей (оно мешало эксклюзивности и не защищало от усечения).

### 6.2. Слот (32 байта)

| Смещение | Размер | Поле | Описание |
|---|---|---|---|
| +0 | 8 | `owner_token` | 0 = свободен; `(pid<<32) | incarnation`; `incarnation = 0` — «неизвестен» (probe `Unknown` при регистрации), не «мёртв» |
| +8 | 8 | `active_txn` | 0 = не держит; иначе удерживаемый `txnid` |
| +16 | 8 | `heartbeat_ns` | `CLOCK_MONOTONIC` |
| +24 | 8 | `flags` | bit0 LONG_HOLD, bit1 IN_PROCESS |

`incarnation` — `starttime` (поле 22 `/proc/<pid>/stat`), усечённое до u32. `0` зарезервирован как «неизвестен»: он не доказывает смерть PID и не даёт права вытеснять слот (§6.4.1).

### 6.3. Двухфазный пин (B-4) и жизненный цикл снапшота (R-4, R-5)

Пиннинг выполняет **сам адаптер** при взятии снапшота: успешный `Reader::snapshot()` → `pin()`, `Drop` последнего держателя → `unpin()`. Пользователь (домен/сервер) не вызывает `pin`/`unpin` напрямую — это внутренние операции адаптера (`pub(crate)`), публично доступен только RAII-`Snapshot` (§20.3).

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

**Почему это корректно.** Пока `T` — активная meta, writer не может освободить страницы графа `T`: освобождение страниц, заменённых в `T+1`, требует `T+1 ≤ oldest_reader_txn`, но `oldest_reader_txn ≤ txnid(active) = T < T+1` (пока `T` активна). Строгая граница по `durable_watermark` добавляет независимую защиту от отката recovery и здесь не ослабляет правило. Если за время между фазами 1 и 2 meta продвинулась, читатель откатывается и повторяет — и **до** успешной проверки не читает ни одной страницы данных. После успешной проверки `slot.active_txn = T` гарантирует, что любой следующий коммит увидит `oldest_reader_txn ≤ T` и не тронет граф `T`.

Refcount-вариант (для вложенных снапшотов в одном потоке): на поток — 2–4 слота; `pin` занимает любой свободный слот потока; `unpin` освобождает. Требование «один писатель `active_txn` на слот» сохраняется (слот принадлежит одному потоку).

### 6.4. Регистрация и вытеснение (R-4)

| Операция | Правило |
|---|---|
| Регистрация | CAS `owner_token: 0 → token`; слоты распределяются по потокам; нет свободных → `TooManyReaders` |
| Dereg | `active_txn = 0`, затем `owner_token = 0` (порядок обязателен) |
| Heartbeat | раз в 1 с `store_relaxed(heartbeat_ns, now)` |
| Вытеснение | **только** если PID мёртв **или** `incarnation` не совпадает **и известен (`≠ 0`)**. Живой PID с совпадающим `incarnation` не вытесняется **никогда** (SEC-ZF-007). `incarnation = 0` (probe вернул `Unknown` при регистрации) — «неизвестен», трактуется как живой, не вытесняется, `NEEDS_FSCK`. `ProcessProbe::Unknown` (EACCES/parse error/`/proc` недоступен) — также живой, не вытесняется (§6.4.1) |
| `heartbeat` старше `STALE_READER_TIMEOUT_MS` | вытеснения нет; это только диагностика: метрика `readers_stalled`, событие `ReadersStalled`, предупреждение для `LONG_HOLD`-слотов |
| `LONG_HOLD` | снимается только смертью процесса; влияет на диагностику (порог предупреждения), не на вытеснение |

#### 6.4.1. Проверка процесса: `ProcessProbe`

Вытеснение слота требует ответа «процесс мёртв», а не «не удалось проверить». Поэтому probe трёхзначен и вынесен за тестируемую абстракцию (в тестах подменяется без `/proc`):

```rust
pub(crate) trait ProcessProbe {
    /// Liveness и incarnation для PID. Ошибки чтения не маскируются под смерть.
    fn probe(&self, pid: u32) -> ProcStatus;
}

pub(crate) enum ProcStatus {
    Alive { incarnation: u32 },   // /proc/<pid>/stat прочитан, starttime получен
    Dead,                          // ENOENT/ESRCH: PID не существует
    Unknown { errno: i32 },        // EACCES/EPERM, parse error, таймаут, /proc недоступен
}
```

| `ProcStatus` | Действие |
|---|---|
| `Alive { incarnation }` и `incarnation` совпадает с `owner_token` | слот принадлежит живому читателю; **не вытесняется** (§6.4/SEC-ZF-007) |
| `Alive { incarnation }`, но `incarnation` не совпадает | PID переиспользован → слот мёртв: очистить и **всегда** `NEEDS_FSCK` (§13.7 шаг 9) |
| `Dead` | слот мёртв: очистить и **всегда** `NEEDS_FSCK` |
| `incarnation` слота `= 0` (неизвестен) | трактуется как живой: **не вытеснять**, `NEEDS_FSCK` (нельзя доказать ни жизнь, ни смерть); `active_txn` сохраняется, метрика `process_probe_unknown_total`. Проверка `incarnation = 0` выполняется **до** сравнения с probe |
| `Unknown` | считать **живым**, не вытеснять, выставить `NEEDS_FSCK` (safe > available); метрика `process_probe_unknown_total` |

Правило «ENOENT → `Dead`» относится к **конкретному** PID. Если недоступен сам `/proc` (нет каталога/точки монтирования), это `Unknown` для всех PID, а не массовая смерть: probe обязан различать «PID нет» и «/proc нет». Внутрипроцессные слоты (`flags.IN_PROCESS`) проверяются по in-process реестру потоков; `/proc` для них — только источник `incarnation` и fallback-диагностика. Тесты используют `MockProcessProbe` (Alive/Dead/Unknown/incarnation-mismatch/parse-error) — `/proc` в тестах не требуется.

Слот с `incarnation = 0` **никогда** не вытесняется по несовпадению: `0` означает «при регистрации probe не дал incarnation» (`Dead`/`Unknown`), а не «умер». Если probe позже отвечает `Alive { incarnation: x ≠ 0 }`, это не доказывает переиспользование PID — слот остаётся живым, выставляется `NEEDS_FSCK`, `active_txn` сохраняется.

`Unknown` **не** даёт права освободить страницы: слот продолжает удерживать `active_txn`, writer может дойти до `NoSpace`/`ReadersStalled` — это диагностируемое состояние, а не повод для вытеснения.


`oldest_reader_txn` = минимум `active_txn` по слотам, где **`owner_token ≠ 0` И `active_txn ≠ 0`**.

- Слот с `active_txn = 0` **никогда не считается читателем**: 0 означает «пин не взят» (простой потока, откат двухфазного пина §6.3, окно между `dereg`-записями). Включение такого слота в минимум дало бы `oldest_reader_txn = 0` → `reclaim_txn = 0` → переиспользование невозможно → ложный `NoSpace`/`MapFull`.
- Если подходящих слотов нет — **читателей нет**, и берётся `txnid(active)` (консервативный запас: страницы, освобождённые текущей транзакцией, всё равно не выдаются — §11.7 п.3).

`reclaim_txn = min(durable_watermark − 1, oldest_reader_txn)`. При `durable_watermark = 1` это 0: freelist не отдаёт ничего, пока не выполнен первый `sync()`/`Sync` (§13.6, §14).

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

**Порядок байт.** `rdlength` — **big-endian** (DNS wire, как в самом сообщении); `rdata[]` — opaque wire-байты. Поля страницы (`LeafValue.rdlen`, `rr_count`, `ttl`, `val_u32`) — **little-endian** (§1). Это разные поля: `LeafValue.rdlen` — суммарная длина RDATA набора (LE), `payload`-`rdlength` — длина одного RR (BE).

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

нарезанные последовательно: страница 1 несёт первые `data_len` байт, страница 2 — следующие и т.д. Разрыв может проходить внутри `rdlength`, внутри `rdata`, между RR — это норма. `rdlength` внутри потока — **big-endian** (DNS wire), как в §11.2; `data_len`/`next_page` — LE поля страницы.

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

1. **Порядок.** `free_txn` монотонно возрастает вдоль списка (инвариант; проверяется `fsck`) и всегда `free_txn ≥ 2`: txn 1 — initial-состояние, страниц не освобождает; bucket с `free_txn < 2` — `Corrupt`. Новый bucket добавляется в **хвост** за O(1) (`freelist_tail`).
2. **Выдача.** Аллокатор идёт от головы и берёт страницы только из bucket'ов с `free_txn ≤ reclaim_txn`, где `reclaim_txn = min(durable_watermark − 1, oldest_reader_txn)`, **и** `free_txn < current_txn`. Иначе говоря: `free_txn < durable_watermark` **и** `free_txn ≤ oldest_reader_txn`. Так как список отсортирован, при первом «слишком молодом» bucket'е обход прекращается — стоимость O(число отданных страниц), не O(длина списка). Строгость по `durable_watermark` обязательна: худшая восстановимая meta — `durable_watermark−1`, поэтому страницы, освобождённые в `durable_watermark`, ещё достижимы из неё. `durable_watermark` **не понижается** recovery/приёмом `Flush`-meta (§14) и не берётся из одной выбранной meta: иначе страницы с `free_txn ≥ durable_watermark` стали бы доступны, и откат после потери meta прочитал бы перезаписанные данные.
3. **Запрет выдачи в той же транзакции (двойное освобождение).** Страницы, освобождённые в txn `T`, попадают в bucket с `free_txn = T` и в txn `T` не выдаются никогда (`free_txn < current_txn`). Причина: они ещё достижимы из `meta(T-1)`, а recovery может выбрать `T-1` или новее. Нарушение этого правила — единственный способ получить страницу, на которую ссылаются два места (I-10). `fsck` проверяет: нет `PageId` в двух bucket'ах, нет `PageId` одновременно в freelist и в графе.
4. **Bucket-страницы неизменяемы: только COW (N-5).** Bucket, достижимый из активной meta, **никогда не мутируется на месте** — иначе читатель/восстановление увидят freelist, не соответствующий своей meta. Любая выдача из bucket `B` (и любое добавление) порождает новую страницу-образ:

   - пусть из `B` берётся `k` страниц. Пишется новый bucket `B'` (`free_txn = B.free_txn`, `count = B.count − k`, оставшиеся `page_ids`) в **свободную страницу** `p`; `val`-указатель головы/соседа переключается на `B'` при коммите.
   - `B` (старый образ) отправляется в набор «освобождено в текущей транзакции» и попадёт в bucket с `free_txn = T` (см. п. 5). Так он не теряется и не становится недостижимым.
   - если `B` опустел (`count == k`), новый образ не пишется: `B` просто уходит в набор освобождённых, а указатель соседа/головы снимается. Поэтому **пустых bucket'ов в цепочке не существует**.
   - откуда взять `p` (единый порядок, как в п. 7): (1) **eligible**-страница — та, что уже разрешена к выдаче (`free_txn ≤ reclaim_txn`, см. п. 2), тогда `high_water` не растёт; (2) иначе `high_water`; (3) если исчерпан и он — одна из `k` выдаваемых страниц (`p` не возвращается вызывающему: он стал bucket-страницей). Рекурсия «чтобы освободить страницу, нужна страница» исключена: `p` либо свободная, либо новая, либо уже отдаваемая. Если `p` взята из **другого** bucket'а (не из `B`), тот тоже получает COW-образ — итого 0–2 образа на проход выдачи; это учтено в оценке п. 5.

   **Инвариант отсутствия сирот:** каждая bucket-страница либо достижима из `meta` по цепочке `next_bucket`, либо лежит в `page_ids` некоторого bucket'а этой же цепочки (то есть «свободна как данные»), либо является образом, который будет записан в текущем коммите. Третьего состояния нет: старый образ `B` всегда попадает в набор освобождённых того же коммита, а набор освобождённых всегда конвертируется в bucket до записи meta (§13.6). `fsck` проверяет: множества {bucket-страницы} и {page_ids} не пересекаются с графом данных и не теряют ни одной страницы из `page_count_high_water`.
5. **Стоимость коммита O(depth).** Все страницы, освобождённые транзакцией `T` (включая старые образы bucket'ов), собираются в **один** новый bucket и добавляются в хвост — амортизированно O(1), без обхода списка. Выдача страниц внутри транзакции даёт 0–1 COW-образ на затронутый bucket (обычно один и тот же, пока он не опустеет). Размер списка не влияет на латентность коммита.
6. **Слияние bucket'ов запрещено**: слияние потребовало бы перезаписи `free_txn`, что ломает инвариант порядка и COW-семантику.
7. **Следствие «+1 страница на коммит с освобождениями».** Каждому коммиту, который что-то освободил, нужна одна страница под образ нового bucket'а. Она берётся в порядке п. 4: сначала **eligible**-страница (тогда `high_water` не растёт), иначе `high_water` — и это `+1` к файлу. Такая страница становится доступной как данные только после того, как её `free_txn` перестанет быть «молодой»: нужно `free_txn < durable_watermark` и `free_txn ≤ oldest_reader_txn`, то есть обычно ещё один-два успешных `Sync`/`sync()` (строгая граница `durable_watermark−1` добавляет один коммит задержки). На «холодном» старте и после всплесков удалений `high_water` растёт; возврат в оборот: `compact_zone` (или offline `zonefile compact`) пересобирает freelist и обнуляет этот запас; на стабильной нагрузке число bucket-страниц ограничено непустыми bucket'ами (§11.7 п.4) и не растёт.
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
| страниц в цепочке | `ceil(upstream_bytes / (page_size − 48))`; при 4096 это 2 (4048·2 = 8096 ≥ 4096), при 8192/16384 — 1. Предел блока — `max_zone_meta_pages(page_size)` = `ceil(MAX_ZONE_META / (page_size − 48))` → 65/33/17 |
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
  1. open(path, O_RDWR|O_NOFOLLOW|O_CLOEXEC); fstat → обычный файл, owner/mode/uid (§21.4).
     O_RDWR нужен и читателю: он пишет слоты в writable reader-table (§6.1), поэтому
     **у читателя должны быть права на запись в файл**; данные/деревья всё равно
     маппятся PROT_READ и через этот дескриптор не пишутся
  2. read 4096 @0 и @page_size → superblock A/B; валидировать (magic/version/page_size/CRC/sync_mode §4.1)
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
 11. слоты читателя здесь НЕ занимаются: регистрация ленивая, при первом `snapshot()` (§6.3)
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
commit(mode):        # runtime mode ∈ {NOSYNC=0, NOMETASYNC=1, SYNC=2} (MODE_* §2;
                     #  это НЕ disk-коды sync_mode §4.1 — см. таблицу соответствия)
  1. floor = max_class(superblock.sync_mode,
                       if durable_watermark > 1 { Sync } else { superblock.sync_mode })
     проверить: mode не слабее floor (класс durability: Memory < Flush < Sync;
     числовые коды MODE_* и disk-коды §4.1 НЕ сравнивать напрямую — они инвертированы),
     иначе InvariantViolation(DurabilityBelowFileMode) (§4.1, §15 F-12)
  2. инварианты в памяти: порядок ключей, нет дублей PageId в dirty-set,
     overflow-цепочки замкнуты, depth ≤ MAX, encoded_size ≤ page_size
  3. собрать набор освобождённых страниц (заменённые/удалённые + старые образы
     bucket'ов из §11.7) в ОДИН новый bucket с free_txn = txnid+1; bucket — часть
     dirty-set (N-4). Обновить freelist_head/tail/buckets/entries/free_page_count
     в НОВОМ образе meta (не в текущей).
  4. заполнить PageHeader каждой dirty-страницы (page_no, txn, lsn, crc, payload_len)
  5. pwritev(dirty, включая bucket) — целыми страницами, батчами ≤ 64
  6. if mode >= NOMETASYNC: fdatasync(fd)          # данные ДО любой meta
  7. durable_watermark' = if mode == SYNC then txnid+1 else durable_watermark
     # Sync:  новая meta становится durable-водоразделом (txnid+1)
     # Flush: данные fsync'нуты, но meta — нет; watermark НЕ двигается
     # Memory: ни данные, ни meta не форсируются; watermark НЕ двигается
  8. write(meta, неактивный слот): txnid+1, все корни (вкл. новый freelist),
     durable_txn = durable_watermark', reclaim_txn = min(durable_watermark' − 1, oldest_reader_txn),
     page_count_high_water, счётчики
  9. if mode == SYNC: fdatasync(fd)
 10. fence(Release); publish(active_txn = txnid+1)
 11. CommitOutcome { commit_id, ... }
```

**`durable_watermark' = txnid+1`, а не `txnid`.** Новая meta описывает **свой** коммит `txnid+1`; в `Sync` она и есть последняя гарантированно записанная meta. В `Flush` `durable_watermark` остаётся на последнем `Sync`/`sync()`: meta не fsync'нута, поэтому объявлять её durable нельзя. Именно это удерживает watermark переиспользования страниц ниже неподтверждённой meta (§14) и делает откат после потери meta безопасным.

**Липкий режим.** Если `durable_watermark > 1`, шаг 1 требует `mode = Sync`; коммит `Flush`/`Memory` отклоняется `DurabilityBelowFileMode`, даже если `superblock.sync_mode` — `Flush`/`Memory`. Это защищает подтверждённый `Sync` от затирания durable-слота слабыми метами (§4.1 п. 6, §15 F-12).

**Почему bucket формируется до записи meta (N-4).** Страницы, освобождённые транзакцией, должны быть достижимы из **новой** meta — иначе после публикации они не принадлежат ни графу, ни freelist (нарушение I-11/W-9 и утечка на каждом удалении). Поэтому bucket входит в тот же `pwritev`, что и данные, а `freelist_head/entries` пишутся в новую meta; старая meta продолжает указывать на старую цепочку, где этих страниц ещё нет — и это корректно, поскольку старая meta их всё ещё использует как граф.

**Group commit.** `fdatasync` шага 6 может покрывать данные нескольких готовых коммитов; порядок диапазонов не важен, но **все** диапазоны данных синхронизируются до записи **любой** meta. Затем metas пишутся по возрастанию `txnid`. Каждая meta самодостаточна (§I-12), поэтому восстановление не зависит от порядка их записи.

**`sync()`** (обязателен для прогресса в `Flush` и `Memory`):

```
sync():
  1. fdatasync(fd) по всем данным, записанным с прошлого sync/коммита
  2. write(неактивная meta, txnid+1, те же корни, durable_txn = txnid+1,
           reclaim_txn = min(txnid, oldest_reader_txn))
  3. fdatasync(fd)
  4. publish(active_txn = txnid+1); durable_watermark := txnid+1
```

`sync()` — единственный способ поднять `durable_watermark` в `Flush`/`Memory`. Пока он не вызван, `reclaim_txn` стоит на месте (при `durable_watermark = 1` — равен 0), freelist не отдаёт страницы с `free_txn ≥ durable_watermark`, и при исчерпании `high_water` коммит возвращает `NoSpace`/`MapFull` при живом свободном месте. Это осознанная цена: переиспользовать страницу выше последней fsync'нутой meta нельзя, иначе откат после потери meta прочитает перезаписанные данные (§14).

**`sync()` — односторонний чекпойнт.** Успешный `sync()` в `Flush`/`Memory`-файле делает `durable_watermark > 1`; с этого момента режим файла **навсегда** `Sync` (липко, §4.1 п. 6). Понижение до `Flush`/`Memory` невозможно (`DurabilityBelowFileMode`). Поэтому `sync()` не «бесплатная» расконсервация freelist: он поднимает класс durability файла.

**Эксплуатационное требование (Flush/Memory).** Пока `durable_watermark = 1`, любая страница, освобождённая коммитом `F ≥ 2`, не может быть переиспользована (`F < 1` невозможно): файл только растёт, а power loss может оставить оба meta-слота невалидными (initial-meta затёрта слабыми коммитами). Поэтому writer обязан выполнять `sync()` периодически — не реже `SYNC_INTERVAL_MS` (§2) и/или при приближении к `MapFull`, а также перед graceful shutdown. Метрики: `durable_lag_txns = txnid(active) − durable_watermark` (должна быть ограничена; при `durable_watermark = 1` и ненулевом `durable_lag_txns` — алерт), `freelist_eligible_pages` (страницы с `free_txn ≤ reclaim_txn`; ноль при живом свободном месте — сигнал вызвать `sync()`), `no_space_total`, `sync_total`. Для `Sync`-файла `durable_lag_txns` всегда 0 после успешного коммита.

**`Flush` (MODE_NOMETASYNC) — «переживает рестарт процесса, не гарантирует power loss».** Режим применим только до первого `sync()` (`durable_watermark = 1`): после него липкий режим требует `Sync` (§4.1 п. 6). Данные fsync'нуты до записи meta, поэтому после падения процесса (`kill -9`) вся page cache цела: recovery выбирает самую новую валидную meta `T > durable_watermark`, принимает её с `recovered_unsynced = true` и **без** `NEEDS_FSCK` — `reclaim_txn = 0`, страницы не переиспользовались, граф `T` цел. При потере питания meta `T` могла не долететь на диск: recovery откатывается к последней **долетевшей** валидной meta (не ниже `durable_watermark`), данные выбранной meta fsync'нуты, файл валиден; теряются только коммиты, чья meta не долетела. Битый/пустой второй слот — штатный `torn_meta`; `NEEDS_FSCK` — только если у битого слота читаемый `txnid` больше выбранного (§13.7 шаг 5). Гарантия `Flush` — «подтверждённый коммит виден после рестарта процесса»; durability после power loss даёт только `Sync`/`sync()`.

**`Memory` (MODE_NOSYNC) — экспериментальный и по умолчанию выключен** (`DEFAULT_SYNC_MODE = MODE_SYNC`). Ни данные, ни meta не форсируются; ядро вправе записать meta раньше данных, поэтому после power loss валидная meta `T > durable_watermark` **может ссылаться на отсутствующие данные**. Recovery сначала пытается открыть самую новую валидную meta с `txnid ≤ durable_watermark` (чисто, без fsck): теряются только неподтверждённые Memory-коммиты. Если такой meta нет — без `allow_unsynced_memory_recovery` отказ `UnsyncedMemoryRecovery { txnid, durable_txn: durable_watermark }` (файл не меняется, `NEEDS_FSCK` не выставляется); с флагом — принимается max-valid, `NEEDS_FSCK`, файл **read-only до offline fsck** и ленивые проверки на каждом чтении (§13.7). Даже падение процесса не даёт гарантии: recovery не отличает его от power loss и применяет ту же политику. Режим помечается `meta_flags.EXPERIMENTAL`.

### 13.7. Восстановление (B-12)

```
recover():
  1. superblock A/B → конфигурация; проверить sync_mode/sync_mode_version (§4.1),
     A/B должны совпадать; mode > 2 или расхождение → Corrupt,
     version ∉ {0,1} → UnsupportedVersion
  2. прочитать обе meta; структурно валидные = CRC + page_no + версия + page_size.
     Валидные кандидаты = структурно валидные И прошедшие проверку против
     superblock (high_water, корни, reader region). Meta, прошедшая CRC, но не
     superblock, в кандидаты и в watermark НЕ входит; её txnid запоминается
     только для политики шага 5 (диагностика, не выбор).
     durable_watermark = max по валидным кандидатам от min(durable_txn, txnid)
  3. если валидных кандидатов нет → CorruptNoValidMeta
  4. active = валидная meta с МАКСИМАЛЬНЫМ txnid    # не «txnid <= durable_txn»
     tie-break при равных txnid: больший номер слота (B, page 3)
     Равные txnid с разными корнями/счётчиками → NEEDS_FSCK.
  5. torn/невалидная meta (диагностика `torn_meta`):
     - слот пуст (все нули) → норма, если он никогда не записывался
       (initial-файл); иначе — аномалия → NEEDS_FSCK;
     - одна meta невалидна, вторая валидна → ШТАТНЫЙ крах: torn_meta = true,
       NEEDS_FSCK НЕ выставляется; выбирается валидная;
     - исключение: у невалидного слота поле txnid декодируется (≥1) и
       txnid > active.txnid → NEEDS_FSCK (нельзя доказать, что потерянный
       коммит был неподтверждённым);
     - невалидный слот с txnid <= active.txnid или с нечитаемым txnid →
       только диагностика (torn-запись не несёт информации о коммите);
     - обе meta невалидны → CorruptNoValidMeta (шаг 3).
     Если сама active не проходит финальную проверку границ/high_water/reader
     region → Corrupt (fail-closed), без отката на более старую meta.
  6. durable_watermark уже вычислен на шаге 2.
     если active.durable_txn < durable_watermark:
        NEEDS_FSCK, write_locked = true   # нарушение монотонности, W-10
        # read-only до offline fsck; не тихое принятие
     recovered_unsynced = active.txnid > durable_watermark
     durable_watermark НЕ понижается до active.durable_txn: это watermark §14.
  7. политика по recovered_unsynced и ЭФФЕКТИВНОМУ режиму
     mode = superblock.sync_mode.effective_mode(durable_watermark)
     (§4.1 п.6: после durable_watermark > 1 файл липко Sync; сырой sync_mode
     здесь неприменим — иначе Memory-файл после sync() ушёл бы в opt-in-ветку):
     - mode ∈ {Sync, Flush}: принять meta; если recovered_unsynced = true —
       только диагностика, NEEDS_FSCK из этого факта НЕ выставляется (данные
       fsync'нуты до meta; free_txn >= durable_watermark не переиспользовались);
       W-10/NEEDS_FSCK с шага 6 не снимается;
     - mode == Memory и recovered_unsynced:
       a. найти самую новую валидную meta с txnid <= durable_watermark.
          Если найдена:
            active = fallback; memory_tail_discarded = true;
            если fallback.durable_txn < durable_watermark →
              NEEDS_FSCK, write_locked = true (W-10, не «чисто»);
            иначе — чисто: NEEDS_FSCK не выставляется, recovered_unsynced = false;
            теряются только неподтверждённые Memory-коммиты;
       b. иначе (подтверждённой meta нет):
          allow_unsynced_memory_recovery = false → отказ
            UnsyncedMemoryRecovery { txnid, durable_txn: durable_watermark },
            файл не меняется;
          true → принять max-valid, NEEDS_FSCK, write_locked = true,
            READ-ONLY до offline fsck;
            ленивые проверки на каждом чтении: page.txn <= snapshot.txnid,
            CRC, границы, payload_len; freelist НЕ использовать для выдачи.
     - Memory и !recovered_unsynced: принять, если W-10 с шага 6 не сработал;
       иначе остаётся NEEDS_FSCK + read-only.
  8. проверить high_water, границы корней, reader region активной meta
  9. санитизировать reader table по политике ниже (fail-closed для живого читателя;
     мёртвый PID/incarnation mismatch (incarnation ≠ 0) → очистка и ВСЕГДА NEEDS_FSCK;
     incarnation = 0 → считать живым, не вытеснять, NEEDS_FSCK;
     ProcessProbe::Unknown → считать живым, не вытеснять, NEEDS_FSCK)
  9a. reclaim_txn = min(durable_watermark − 1, oldest_reader_txn) по санитизированной
      таблице; обновить advisory-поле в памяти (в файл не писать, §5/§14)
 10. если meta_flags.NEEDS_FSCK или NEEDS_FSCK выставлен шагами 5/6/7/9 → сохранить:
     при writable-открытии — записать в meta (штатный путь); в read-only
     (Memory opt-in / W-10) — только Stats/лог, meta не меняется, флаг
     переоткрывается заново при следующем старте, пока offline fsck не снимет причину
 11. ОТКАТ НА INITIAL META: если active.txnid == 1 (initial-состояние), а
     created_unix_ns старше ROLLBACK_ALERT_AGE_MS (=60 000) на момент открытия —
     это признак ранее существовавшего файла, а не нового: выставить NEEDS_FSCK,
     вернуть RolledBackToInitial { instance_uuid, created_unix_ns }, писать алерт;
     старт продолжается только при OpenConfig.allow_rollback_to_initial = true
     (явное подтверждение оператора). instance_uuid логируется для корреляции.
 12. опубликовать снапшот; recovered_unsynced отдать в Stats/логи
```

Обе meta содержат полный набор корней, поэтому откат на `T-1` не требует чтения `T`.

**Единый `durable_watermark` — не `durable_txn` выбранной meta.** Watermark вычисляется по **всем** валидным кандидатам: `max(min(durable_txn, txnid))`. Recovery, `effective_mode`/`check_commit` и advisory `reclaim_txn` используют только его; это закрывает обход sticky через выбор меты с меньшим `durable_txn`. Если `durable_txn(selected) < durable_watermark` — нарушение монотонности (W-10): `NEEDS_FSCK` + `write_locked=true` (read-only до offline fsck), а не тихое принятие. Это же правило ловит Memory-фолбэк на мету старше подтверждённого watermark.

**Почему выбирается max-valid, а не `txnid ≤ durable_txn`.** Старое правило отбрасывало любую meta новее `durable_txn`, а `Flush` не fsync'ит meta и потому не поднимает watermark. В результате коммиты `Flush` исчезали даже после обычного рестарта процесса, хотя их данные уже были на диске. Новое правило принимает самую новую **валидную** meta, потому что COW-граф цел: страницы, освобождённые при `txn > durable_watermark`, не переиспользовались (строгая граница `free_txn < durable_watermark`, §14), а данные meta `Flush`/`Sync` fsync'нуты до её записи. `durable_watermark` остаётся границей переиспользования и диагностическим watermark, а не фильтром выбора.

**`recovered_unsynced` — диагностика, не ошибка.** `true` означает «принята meta новее `durable_watermark`»; для `Flush` это норма после рестарта процесса, для `Sync` — аномалия «meta дописана, fsync не подтверждён», для `Memory` — только вместе с `NEEDS_FSCK`/opt-in. Чистый `Memory`-фолбэк на meta `txnid ≤ durable_watermark` выставляет не `recovered_unsynced`, а `memory_tail_discarded` (если durable-мета не ниже watermark; иначе — W-10). Флаг не влияет на `reclaim_txn` и не понижает watermark.

**`torn_meta` — диагностика штатного краха.** Один невалидный слот при валидном втором — ожидаемый результат незавершённой записи meta (torn write). Это **не** повреждение графа и не повод для `fsck`: теряется максимум незавершённый (неподтверждённый) коммит. `NEEDS_FSCK` выставляется только когда потеря подтверждённого коммита доказуема или вероятна: у невалидного слота **декодируется** `txnid > active.txnid`, либо есть иная неопределённость (аномально пустой слот при `active.txnid > 1`, расхождение корней при равных `txnid`). Обе meta невалидны → `CorruptNoValidMeta` (открывать нечего). Нечитаемый `txnid` сам по себе трактуется как «информации о более новом коммите нет».

**Read-only Memory-recovery (opt-in).** Когда подтверждённой meta `txnid ≤ durable_watermark` нет, а оператор разрешил `allow_unsynced_memory_recovery`, файл открывается **read-only** (`writer()` → `ReadOnly`, коммиты и запись meta/данных запрещены; регистрация и санитизация слотов reader table по §6/шагу 9 допустимы — это не данные зон) с `NEEDS_FSCK` в памяти/Stats (meta не переписывается, пока файл read-only), потому что meta могла пережить данные и граф может ссылаться на потерянные страницы. До offline `zonefile fsck --verify`/`--repair` каждое чтение выполняет ленивые проверки: `page.txn ≤ snapshot.txnid`, CRC, границы, `payload_len`, `page_no`/`page_type` (§7); при первом нарушении — `Corrupt` (SERVFAIL), без частичных ответов. Freelist в этом состоянии **не используется для выдачи** (он может указывать на потерянные bucket-страницы); это дополнительно гарантируется read-only-режимом. После успешного offline `fsck --repair` причина устраняется, флаг `NEEDS_FSCK` снимается, файл переоткрывается для записи. Тот же read-only-режим действует при W-10 (`durable_txn(selected) < durable_watermark`): чтение разрешено, запись — только после fsck.

Правило шага 11 нужно, чтобы откат к `txnid=1` не выглядел как «новый пустой файл»: новый файл имеет `created_unix_ns ≈ now`, ранее существовавший — заметно старше. Порог намеренно грубый (60 с): он различает «только что создан» и «жил и потерял данные», а не измеряет время точно.

**Политика санитизации reader table (шаг 9) — нормативно:**

| Состояние слота | Действие |
|---|---|
| `owner_token = 0` (пуст), файл в initial-состоянии (`txnid(active) = 1`) | норма (файл только что создан), ничего не делаем |
| `owner_token = 0` (пуст), `txnid(active) > 1` | **аномалия**: слот освобождён без `dereg` (баг/частичная запись) → `NEEDS_FSCK`, метрика `reader_slot_leaked_total`; слот остаётся свободным |
| `owner_token ≠ 0`, `incarnation = 0` | **неизвестен**: считать живым, **не вытеснять**, `NEEDS_FSCK`; `active_txn` сохраняется. Проверяется до сравнения с probe (§6.4.1) |
| PID мёртв (`ProcStatus::Dead`) **или** `incarnation` не совпадает (при `incarnation ≠ 0`) | слот очищается (`owner_token = 0`), **ВСЕГДА** `NEEDS_FSCK` — независимо от того, выглядели ли `active_txn`/`flags` корректно; инвариант «занятый слот принадлежит живому процессу» нарушен |
| `ProcessProbe::Unknown` (EACCES/EPERM, parse error, `/proc` недоступен) | считать живым, **не вытеснять**, `NEEDS_FSCK` (safe > available); слот продолжает удерживать `active_txn` (§6.4.1) |
| PID жив, `incarnation` совпадает, `active_txn > txnid(active)` | **fail-closed**: `Corrupt { kind: Bounds, detail: BadReaderRegion }` — слот ссылается на несуществующий снапшот; **не вытесняется** (живой процесс, возможно, читает) |
| PID жив, `incarnation` совпадает, ненулевые reserved-биты `flags` | **fail-closed**: `Corrupt { kind: Bounds, detail: BadReaderRegion }` — формат не знает такой семантики; **не вытесняется** |
| PID жив, `incarnation` совпадает, `active_txn ≤ txnid(active)` | норма, слот сохраняется как есть |

Правило «живой читатель не вытесняется никогда» (§6.4, SEC-ZF-007) действует и здесь: при сомнении восстановление отказывает (`Corrupt`) либо не вытесняет и помечает `NEEDS_FSCK`, но не «чинит» слот — иначе можно освободить страницы, которые процесс ещё читает.


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
- freelist: отсутствие пересечений (страница в двух bucket'ах / в bucket'е и в графе), монотонность `free_txn` и `free_txn ≥ 2`, **неизменяемость bucket'ов** (bucket-страницы не входят в граф данных, §11.7), отсутствие пустых bucket'ов;
- `ZoneEntry`: `state`/`deleted_txn` согласованы (0 ⟺ не tombstone), `meta_root ≠ 0` для живой, флаги не дублируются с meta-блоком (R-14);
- lower-case инвариант ключей, отсортированность RDATA, `TTL ≤ 2^31−1`.

`repair(--to-txn T)`: разрешён **только** при `T ≥ durable_watermark − 1` **и** `T ≥ oldest_reader_txn` (иначе страницы, освобождённые после `T`, могли быть переиспользованы или удерживаются читателем) → `RefuseToRollback`. Порог по watermark строгий: страницы, освобождённые в `F`, переиспользуются только при `F < durable_watermark`, поэтому откат на `durable_watermark−1` безопасен, а на `durable_watermark−2` — уже нет (страницы `durable_watermark−1` могли быть выданы и перезаписаны). Утечки возвращаются в freelist, выставляется `NEEDS_FSCK`.

`verify()` не считает torn одного из двух meta повреждением, если второй валиден и выбранная meta проходит все проверки: это штатный след незавершённой записи (`torn_meta`), а не bit rot. `--repair` при одном валидном слоте не «дочинивает» второй, а оставляет его пустым/невалидным до следующего коммита.

---

## 14. MVCC, пиннинг и переиспользование

- Состояние = `(meta(T), граф страниц T)`. Writer создаёт новый граф; неизменённые страницы общие.
- Публикация — атомарная запись meta + `publish` (§13.6 шаги 7–9). Читатель фиксирует `T` через протокол §6.3.
- Страницы, заменённые в транзакции `F` (то есть достижимые из `F-1`), разрешено переиспользовать только при `F < durable_watermark` **и** `F ≤ oldest_reader_txn`; эквивалентно `F ≤ reclaim_txn`, где `reclaim_txn = min(durable_watermark − 1, oldest_reader_txn)`. `oldest_reader_txn` writer читает из слотов с `Acquire` (§6.4) — иначе публикация читателя может быть не видна и страницы освободятся преждевременно. Единственная реализация правила — `pulse_zonefile::is_reclaimable(free_txn, durable_watermark, oldest_reader_txn)`; при `durable_watermark = 1` она всегда `false`, при `F == durable_watermark` — `false`.
- Bucket-страницы freelist тоже подчиняются COW (§11.7): мутация на месте запрещена, старый образ уходит в набор освобождённых того же коммита.

  Обоснование границ:
  - `F < durable_watermark` (строго): `D = durable_watermark` — подтверждённый водораздел по **всем** валидным метам. Recovery не обязан увидеть мету `≥ D`: слот `D` может быть затёрт начатой записью `D+2`, пока meta `D+1` не долетела, поэтому худшая восстановимая meta — `D−1`. Страницы, освобождённые в `F = D`, ещё достижимы из `D−1`, значит переиспользовать их нельзя. При `F < D` любая восстановимая meta `≥ D−1 ≥ F` уже не содержит эти страницы.
  - `F ≤ oldest_reader_txn`: все живые читатели видят мету `≥ F`, значит страницы, заменённые в `F`, им не нужны (читатель на `F` уже не содержит старую версию).
  - При отсутствии читателей `oldest_reader_txn = txnid(active)` — «молодые» страницы не выдаются мгновенно, что даёт запас на откат.
  - При `durable_watermark = 1` (`Flush`/`Memory` без `sync()`) `reclaim_txn = 0`: переиспользование невозможно в принципе. Это эксплуатационное требование к периодическому `sync()` (§13.6), а не «утечка»: пока нет подтверждённой meta, любой откат может потребовать любую освобождённую страницу.

- **Recovery не понижает `durable_watermark`.** Принятие meta `T > durable_watermark` в `Sync`/`Flush` (§13.7) — это выбор состояния, а не подтверждение durability: watermark остаётся на максимуме подтверждённых мет. Иначе `Flush` легализовал бы переиспользование страниц `F ∈ [watermark, T]`, а последующая потеря meta `T` (power loss) откатила бы recovery на перезаписанные данные. Именно правило «`free_txn ≥ durable_watermark` не переиспользуется» делает выбор max-valid meta в `Flush` безопасным. Если `durable_txn(selected) < durable_watermark`, это W-10: `NEEDS_FSCK` + read-only, а не тихое понижение (§13.7, §17).
- **В `Flush`** режим применим только до первого `sync()` (`durable_watermark = 1`): после него липкий режим требует `Sync` (§4.1 п.6). Пока `durable_watermark = 1`, `reclaim_txn = 0`; файл только растёт, поэтому нужен периодический `sync()` до исчерпания `high_water`. Это документированная цена безопасного `Flush`, а не баг.
- **В `Memory` (NOSYNC)** — то же (`reclaim_txn = 0` до `sync()`), плюс recovery не доверяет meta новее `durable_watermark`: сначала чистый откат на meta `≤ durable_watermark`, иначе `NEEDS_FSCK`/opt-in и read-only до offline fsck (§13.7).
- Если свободных страниц нет, но они есть в freelist — `NoSpace` (retry после `sync()`/освобождения читателей). Разграничение — §16.
- `ReadersStalled` — диагностика, когда `reclaim_txn` не двигается дольше `STALE_READER_TIMEOUT_MS` при живом слоте; данные при этом не портятся.

---

## 15. Матрица отказов

| # | Момент | Диск/кэш | После рестарта | Потери |
|---|---|---|---|---|
| F-1 | во время записи data (`Sync`/`Flush`) | старый meta валиден | `T` | нет |
| F-2 | после fdatasync данных, до meta | старый meta валиден; новые данные не достижимы | `T` | нет |
| F-3 | torn-write meta | CRC не сходится → слот невалиден | `T` (последняя валидная); `torn_meta = true`; `NEEDS_FSCK` — только если у битого слота декодируется `txnid > T`, иначе чисто (§13.7 шаг 5) | данных нет; последний (неподтверждённый) коммит не виден |
| F-4 | `Flush`: meta в кэше, **потеря питания** (сценарий применим только при `durable_watermark = 1`, до первого `sync()`) | данные fsync'нуты, meta могла не долететь | последняя **долетевшая** валидная meta; данные выбранной meta fsync'нуты, **файл валиден**; пустой/старый второй слот — чисто, `NEEDS_FSCK` — только по §13.7 шаг 5. Если оба слота не долетели/битые — `CorruptNoValidMeta` (цена отсутствия `sync()`). После первого `sync()` режим липко `Sync` (§4.1 п.6), поэтому слабых коммитов больше нет | коммиты, чья meta не долетела; данные выбранной meta fsync'нуты |
| F-4a | `Flush`: **падение только процесса** (kill -9), `durable_watermark = 1` | page cache цел; данные fsync'нуты, meta валидна | самая новая валидная meta `T+1` принимается (`recovered_unsynced = true`, `sync_mode = Flush`) **без** `NEEDS_FSCK`; `reclaim_txn = 0`, переиспользования не было | нет — `Flush` переживает рестарт процесса |
| F-4b | `Sync`/`Flush`: активная meta новее `durable_watermark` (ручной/аномальный сценарий, сбой между записью meta и её подтверждением) | meta структурно валидна, `txnid > durable_watermark` | meta принимается, `recovered_unsynced = true`, `NEEDS_FSCK` **не** выставляется; watermark не понижается | нет: у `Sync`/`Flush` данные fsync'нуты до meta |
| F-5 | `Sync`: оба fsync прошли | всё на диске | `T+1` | нет |
| F-6 | `Memory`: потеря питания/сбой ОС | произвольное подмножество кэша; meta могла пережить данные | сначала чистое открытие последней валидной meta `txnid ≤ durable_watermark` (теряются только неподтверждённые Memory-коммиты); если такой нет — `NEEDS_FSCK` + `allow_unsynced_memory_recovery`, файл read-only до offline fsck; без флага — отказ `UnsyncedMemoryRecovery` | неподтверждённые Memory-коммиты (до первого `sync()`; после него режим липко `Sync`); при opt-in возможна порча графа (ловится CRC/fsck) |
| F-6a | `Memory`: **падение только процесса** (kill -9) | page cache цел, но recovery не отличает его от power loss | та же политика: сначала meta `≤ durable_watermark` чисто; иначе `NEEDS_FSCK` + opt-in + read-only до fsck; без флага — отказ | гарантий нет; подтверждённые коммиты не теряются, неподтверждённые Memory-коммиты могут не восстановиться |
| F-7 | переиспользование при живом читателе | запрещено I-6/§14 | — | невозможно |
| F-8 | bit rot | CRC не сходится | `Corrupt` на ветви → SERVFAIL | запись недоступна |
| F-9 | усечение файла (внешнее или после сбоя) | размер < `page_count_max × page_size` | `TruncatedFile` при open — **и у writer, и у reader**; `ftruncate` не выполняется, файл не «доращивается»; работающий процесс — SIGBUS fail-stop | восстановление из бэкапа/пересоздание |
| F-10 | второй writer | занят `<zonefile>.lock` (`LOCK_EX\|LOCK_NB`) | `Busy` | — |
| F-11 | невалидный/неизвестный `sync_mode`, неизвестная версия поля, расхождение A/B | поле не читается по §4.1 | `Corrupt` для mode/расхождения; `UnsupportedVersion` для `sync_mode_version ∉ {0,1}` | работа невозможна до fsck/пересоздания |
| F-12 | попытка коммита слабее floor: `Memory` в `Flush`/`Sync`-файле, `Flush`/`Memory` после первого `Sync`/`sync()` (`durable_watermark > 1`) | файл не меняется, meta не пишется | `InvariantViolation(DurabilityBelowFileMode)`; `superblock.sync_mode` не меняется, липкий режим сохраняется | нет; понижение режима запрещено |
| F-13 | **регрессия watermark**: `durable_txn(selected) < durable_watermark` (в т.ч. Memory-фолбэк на мету старше подтверждённого watermark) | обе/несколько meta валидны, но выбранная несёт меньший `durable_txn` | `NEEDS_FSCK` + `write_locked = true`: read-only до offline fsck; watermark не понижается, `effective_mode`/`check_commit`/`reclaim_txn` считаются от `durable_watermark` | подтверждённые после `durable_txn(selected)` коммиты могут быть не видны; решает fsck |

**Усечение — fail-closed.** `ftruncate` разрешён только в цикле создания (§4, `O_CREAT|O_EXCL`). Если открывается существующий файл короче `page_count_max × page_size`, это признак потери данных, а не «недороста»: и writer, и reader получают `TruncatedFile`. Автоматическое «доращивание» маскировало бы усечение и могло бы вернуть мусор вместо данных.

**Гарантии по режимам (B-12, ревизия 1.5.3).**

- `Sync`: подтверждённый коммит переживает и рестарт процесса, и потерю питания (F-5). `durable_watermark` двигается каждым коммитом. Строгая граница `free_txn < durable_watermark` даёт запас: страницы последнего durable-коммита не переиспользуются, пока не появится следующий `Sync`.
- `Flush`: коммит-гарантия действует только до первого `sync()` (`durable_watermark = 1`): подтверждённый коммит **гарантированно** виден после рестарта процесса (F-4a), данные fsync'нуты до meta, переиспользования не было (`reclaim_txn = 0`). При потере питания возможен откат к последней долетевшей meta, данные выбранного состояния fsync'нуты, файл валиден (F-4); `NEEDS_FSCK` — только по §13.7 шаг 5. После первого `sync()` режим липко `Sync` (§4.1 п.6), поэтому гарантия `Sync` не теряется последующими `Flush` (F-12).
- `Memory`: гарантий сохранности нет ни при потере питания, ни при падении процесса (F-6/F-6a). Meta может пережить данные; recovery сначала чисто откатывается на meta `txnid ≤ durable_watermark`, иначе требует `allow_unsynced_memory_recovery`, `NEEDS_FSCK` и read-only до offline `fsck`. Гарантируется только структурная валидность страниц, а не консистентность графа, пока не выполнен `fsck`.

**Почему `Flush`-коммиты больше не теряются при рестарте процесса.** Старое правило `txnid ≤ durable_txn` отбрасывало meta `T+1`, потому что `Flush` не fsync'ит meta и не поднимает watermark; данные при этом уже были на диске. Новое правило (§13.7) выбирает max-valid meta, а `durable_watermark` остаётся границей `reclaim_txn`. Безопасность обеспечивает §14: страницы с `free_txn ≥ durable_watermark` не переиспользуются, поэтому граф принятой meta цел; принятие meta **не** повышает watermark. При `durable_watermark = 1` не переиспользуется вообще ничего, так что граф цел тривиально.

**Почему читатель не видит полу-запись во всех трёх режимах.** Видимость определяется не чтением meta-страницы, а in-process указателем `active_txn`, который публикуется после полной записи meta (шаг 10 §13.6). Читатель никогда не сканирует meta на hot-path, поэтому torn-страница в page cache не может быть прочитана как данные. Граф `T` неизменяем, пока жив хотя бы один читатель `T`: страницы, освобождённые в `F > T`, не выдаются, так как `F ≤ oldest_reader_txn ≤ T` невозможно (§14). В `Memory` это свойство сохраняется в пределах жизни процесса/ядра; после F-6 снапшот откатывается целиком (или принимается только через opt-in+fsck), но не «размазывается».

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
| `NoSpace` | `high_water < page_count_max`, но все свободные страницы «молодые»: `free_txn ≥ durable_watermark` или `free_txn > oldest_reader_txn` (эквивалентно `free_txn > reclaim_txn`) | выполнить `sync()` / дождаться читателей; повторить. В `Flush`/`Memory` до первого `sync()` `durable_watermark = 1`, `reclaim_txn = 0` — переиспользование невозможно; нужен периодический `sync()` (§13.6) |
| `MapAllocFailed` | `ftruncate`/`mmap` не удались (квота, ENOMEM) | отказ старта с подсказкой |

**Влияние строгой границы `free_txn < durable_watermark` на лимиты.** Освобождённые страницы становятся доступны только после того, как `durable_watermark` перешагнёт их `free_txn` (и читатели отпустят эпоху), то есть обычно после одного-двух успешных `Sync`/`sync()`. На `Sync`-файле это задерживает возврат страниц на один коммит относительно старой границы `≤ watermark`; на `Flush`/`Memory` без `sync()` возврата нет вообще (`reclaim_txn = 0`). Watermark берётся как максимум по валидным метам, а не из выбранной meta; регрессия `durable_txn(selected) < durable_watermark` блокирует запись (W-10, §13.7). Практические следствия:
- при `durable_watermark = 1` серия удалений/перезаписей монотонно растит `page_count_high_water` и упирается в `MapFull`, даже если в freelist есть страницы; это ожидаемое поведение, лечится `sync()` (он же делает режим липко-`Sync`) или offline `compact`;
- метрика `freelist_eligible_pages` (страницы с `free_txn ≤ reclaim_txn`) и `durable_lag_txns` (§13.6) — эксплуатационные индикаторы: `eligible = 0` при `free_page_count > 0` означает «нужен `sync()`»;
- планировщик ёмкости обязан считать худший случай без переиспользования, пока не подтверждён хотя бы один `Sync`.

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
| W-10 | `durable_watermark = max(min(durable_txn, txnid))` по валидным meta не уменьшается; повышается только успешным `fdatasync` meta (`Sync`/`sync()`), **не** коммитом `Flush`/`Memory` и **не** recovery; `reclaim_txn = min(durable_watermark−1, oldest_reader_txn)` вычисляется при коммите. `durable_txn(selected) < durable_watermark` — нарушение монотонности: `NEEDS_FSCK` + `write_locked=true`, не тихое принятие. После `durable_watermark > 1` коммит только `Sync` (липкий режим) |
| W-11 | `DELEGATION` не содержит SOA; **в состоянии `Serving`** apex содержит SOA+NS (INV-4/INV-9 применяются только к `Serving`); для `Initializing` SOA/NS не обязательны — допустимое частично заполненное состояние |
| W-12 | CNAME не сосуществует с другими типами (домен валидирует) |
| W-13 | TTL: clamp при записи, `InvariantViolation` для транзакции, `min` для импорта |
| W-14 | `page_count_high_water == page_count_max` → `MapFull` до начала записи |
| W-15 | `zone_seq` не переиспользуется; tombstone не виден `zones()`/`find_zone`; `deleted_txn` заполнен только у tombstone и не меняется; `0` ⟺ не tombstone, `Some(0)` из домена запрещён (→ `InvalidEdit`) |
| W-16 | Для живой (`state ≠ Tombstone`) зоны `meta_root ≠ 0` |
| W-17 | `Import`/`Replication`: дубликаты RDATA в RRset удалены (дедуп до записи), TTL нормализован; `Transaction`/`Signing` — без нормализации (§11.5) |
| W-18 | Freelist-страницы не мутируются на месте: только COW-образ (§11.7); освобождённые страницы входят в bucket **до** записи meta (§13.6) |
| W-19 | Классификация зоны (`SECONDARY/FORWARD/DYNAMIC/FROZEN`) — только в `ZoneEntry.flags`; `SIGNED/denial` — только в meta-блоке (§12.1) |
| W-20 | `superblock.sync_mode` неизменяем после создания; коммит слабее файлового режима → `InvariantViolation(DurabilityBelowFileMode)` (§4.1) |
| W-21 | Страница с `free_txn ≥ durable_watermark` не выдаётся из freelist, даже если `free_txn ≤ oldest_reader_txn`; выдача разрешена только при `free_txn < durable_watermark` **и** `free_txn ≤ oldest_reader_txn` (§14) |
| W-22 | `superblock.sync_mode_version` хранится как поле (не константа), пишется при encode, декодируется при open и сравнивается A/B наравне с `sync_mode`; `A:1/B:0` → `Corrupt` (§4.1) |

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
| G-7 | Чтение данных не выходит за `[page_data_first, high_water)`; публичного raw-`page()` нет. Любое чтение — только `page_header` (валидирует CRC, `txn ≤ snapshot`, page_no/type, reserved, `payload_len`) + типизированные accessor'ы; невалидная страница → `Corrupt` |
| G-8 | Ни один `RrsetRef` не требует чтения более `MAX_TREE_DEPTH + MAX_OVERFLOW_PAGES` страниц; материализация ≥ 2 RR одновременно не требуется ни одним методом |

### 20.3. API-эскиз

**(A) `pulse-zonefile` — примитивы:**

```rust
pub struct ZoneFile { /* Arc<File>, Arc<Mmap>, ReaderRegion, OpenConfig, ZoneIndex */ }
pub struct Snapshot { inner: Arc<SnapshotInner> }        // Clone ≤ 20 ns

pub struct OpenConfig { pub read_only: bool,   // логический режим, файл всё равно O_RDWR (п.7)
                        pub map_size: u64,
                        pub lock_mode: LockMode,
                        pub strict: bool,       // только тесты; в production игнорируется (п.8)
                        pub allow_rollback_to_initial: bool,        // §13.7 шаг 11
                        pub allow_unsynced_memory_recovery: bool }  // §13.7 шаг 7; default false

impl ZoneFile {
    /// Открывает существующий файл. Слоты reader table НЕ занимает.
    pub fn open(path: &Path, cfg: OpenConfig) -> Result<Self, ZoneFileError>;
    /// Создаёт новый файл (§4): AlreadyExists → Busy → O_EXCL → ftruncate.
    pub fn create(path: &Path, cfg: CreateConfig) -> Result<Self, ZoneFileError>;
    /// Ленивый вход читателя: слот(ы) занимаются при первом `Reader::snapshot()`.
    pub fn reader(&self) -> Reader<'_>;
    // Публичного `ZoneFile::snapshot()` нет: единственный вход — `Reader::snapshot()`,
    // чтобы пиннинг/RAII нельзя было обойти и забыть `unpin`.
    pub fn writer(&self) -> Result<Writer<'_>, ZoneFileError>;
    pub fn stats(&self) -> Stats;                        // high_water, free, fill, map_size,
                                                         // durable_watermark, reclaim_txn, diagnostics
    /// Единственный публичный путь чтения страницы: заголовок с проверками §7.
    /// Только страницы данных `[page_data_first, high_water)`; raw-байты наружу
    /// не отдаются (типизированное чтение — фаза 2). Снапшот обязан принадлежать
    /// этому файлу (`instance_uuid`), иначе `SnapshotFromDifferentFile`: чужой
    /// пин не защищает страницы от переиспользования.
    pub fn page_header(&self, snapshot: &Snapshot, page_no: u32)
        -> Result<PageHeader, ZoneFileError>;
}

pub struct Stats {
    pub high_water: u32,
    pub free_page_count: u32,
    pub fill_ratio: f32,
    pub map_size: u64,
    /// `durable_watermark = max(min(durable_txn, txnid))` по валидным meta;
    /// не `durable_txn` одной выбранной meta.
    pub durable_watermark: u64,
    /// Текущая граница переиспользования: `min(durable_watermark − 1, oldest_reader_txn)`.
    pub reclaim_txn: u64,
    /// Recovery принял meta с `txnid > durable_watermark` (§13.7); диагностика, не ошибка.
    pub recovered_unsynced: bool,
    /// Один meta-слот невалиден (torn), второй валиден; штатный крах, не ошибка.
    pub torn_meta: bool,
    /// `Memory`: recovery чистым откатом отбросил неподтверждённый хвост (§13.7 шаг 7a).
    pub memory_tail_discarded: bool,
}

/// Параметры создания файла (§4). Намеренно отдельный от `OpenConfig`:
/// при создании задаются величины, которых у существующего файла уже нет.
pub struct CreateConfig {
    // общее с OpenConfig:
    pub map_size: u64,              // 0 = дефолт 4 GiB (§3.1)
    pub lock_mode: LockMode,        // Writer | None (reader при создании не нужен)
    // только при создании:
    pub page_size: u32,             // 4096 | 8192 | 16384 (§2), фиксируется навсегда
    pub instance_uuid: Option<[u8; 16]>,   // None = сгенерировать UUIDv7
    pub created_unix_ns: Option<u64>,      // None = now(); задаётся и в meta.commit_unix_ns
    pub feature_flags_required: u64,       // §2, дефолт F0..F5
    pub sync_mode: SyncMode,               // неизменяем; дефолт Sync; см. §4.1
}

/// Persistent-коды §4.1 (НЕ совпадают с MODE_* §2).
pub enum SyncMode { Sync /* disk 0 */, Flush /* disk 1 */, Memory /* disk 2 */ }
// OpenConfig (для открытия) содержит read_only/map_size/lock_mode/strict/
// allow_rollback_to_initial/allow_unsynced_memory_recovery; page_size/uuid/
// created_ns/sync_mode берутся из файла и задать их при открытии нельзя.

/// Поток-локальный читатель: держит до READER_SLOTS_PER_THREAD лениво занятых слотов.
/// `pin`/`unpin` — `pub(crate)`; наружу торчит только RAII-`Snapshot`.
pub struct Reader<'a> { /* &'a ZoneFile + lazily claimed slots */ }
impl<'a> Reader<'a> {
    /// Пиннит слот: первый держатель делает `pin()`, `Drop` последнего — `unpin()`.
    /// Вложенные снапшоты того же потока занимают отдельные слоты (≤ 4), клон —
    /// только refcount, без повторного пина.
    /// Ошибки: `ReaderContended` — у потока уже 4 снапшота либо 8 попыток пина
    /// не удались; `TooManyReaders` — свободных слотов в таблице нет (весь файл).
    pub fn snapshot(&self) -> Result<Snapshot, ZoneFileError>;
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

**Пиннинг и RAII — нормативно.**

1. `pin`/`unpin` — **`pub(crate)`**; публичного API для них нет. Пользователь получает только `Result<Snapshot, ZoneFileError>` из `Reader::snapshot()`.
2. `Snapshot` — RAII: первый держатель (из `Reader::snapshot()`) выполняет двухфазный `pin()` (§6.3), последний `Drop` — `unpin()`, затем освобождает `SnapshotInner`.
3. `Snapshot: Clone` не пиннит повторно: клон только увеличивает refcount `Arc<SnapshotInner>` (≤ 20 нс); `unpin` — ровно один раз, на `Drop` последнего клона.
4. Вложенные снапшоты одного потока (несколько вызовов `Reader::snapshot()`) занимают отдельные слоты (≤ `READER_SLOTS_PER_THREAD = 4`); исчерпание слотов потока или 8 неудачных попыток пина — `ReaderContended`; исчерпание слотов всей таблицы (1024) — `TooManyReaders`. Оба случая возвращаются `Result`, снапшот не создаётся и слот не остаётся занятым. Внутри одного `Snapshot` клоны делят один слот/refcount.
5. `Drop` не паникует; `active_txn = 0` публикуется с `Release` **до** освобождения `Arc`/слота, чтобы writer увидел снятие пина.
6. **Публичного raw-доступа к страницам нет.** `ZoneFile::page()` удалён; единственный путь чтения — `page_header(snapshot, page_no)` с обязательной валидацией `PageHeader` (CRC, `txn ≤ snapshot.txnid`, page_no/type, reserved, `payload_len`, диапазон `[page_data_first, page_count_high_water)`) и типизированные accessor'ы поверх него. `page_no < page_data_first` (superblock/meta/reader table) → `Ok(None)`/`Corrupt` по контракту `page_header`; reader-region наружу не отдаётся. Срез/заголовок живёт не дольше `Snapshot`; читать без живого пина нельзя.
7. **`read_only` — логический режим, не `O_RDONLY`.** `OpenConfig.read_only = true` запрещает `writer()` (→ `ReadOnly`) и любые мутации (superblock/meta/reader-region), но файл всё равно открывается `O_RDWR`: читателю нужны права на запись в reader table (слоты, §6.1). `read_only` не мешает `reader()`/`snapshot()`.
8. **`strict` — только для тестов.** В production проверки идентичности файла (владелец, права, `st_dev/st_ino`, `pad`/`reserved`) выполняются всегда, а значение `OpenConfig.strict` игнорируется. Ослабление (`strict = false`) допускается только в тестовых сборках/фикстурах; переносить его в production-конфиг нельзя (SEC-ZF-009/010).

**(B) Адаптер порта `ZoneStore`** (в `pulse-server::infrastructure`):

| Метод порта | Примитив |
|---|---|
| `snapshot()` | `ZoneFile::reader().snapshot()?`; `SnapshotHandle = Arc<SnapshotInner>`; `Drop` последнего держателя → `unpin()`. `ReaderContended`/`TooManyReaders` пробрасываются как ошибка порта (не паника) |
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
- `sync` — `fdatasync` данных + запись/fdatasync meta; в `Flush`/`Memory`-файле это **односторонний** чекпойнт: `durable_watermark > 1`, после чего все коммиты обязаны быть `Sync` (§4.1 п.6); в read-only-режиме (`Memory` opt-in recovery / W-10) → `ReadOnly`;
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
| `CommitPolicy::Commit(Durability)` | `MODE_SYNC` / `MODE_NOMETASYNC` / `MODE_NOSYNC` | §5.2 ADR 0003; режим не слабее floor (файлового `superblock.sync_mode` или липкого `Sync` при `durable_watermark > 1`), иначе `InvariantViolation(DurabilityBelowFileMode)` §4.1 |
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
                                                   // версия формата/страницы/поля sync_mode (§4.1)
    AlreadyExists,                                 // create(): путь уже существует (проверяется до lock)
    Busy,                                          // второй writer (lock-файл)
    NotRegularFile,                                // lock-файл (или файл зон) не regular: O_NOFOLLOW+fstat
    TooManyReaders,                                // reader table заполнена
    ReaderContended,                               // у потока уже 4 снапшота или 8 попыток пиннинга не удались
    ReadersStalled { oldest_txn: u64, since_ns: u64 },
    UnsyncedMemoryRecovery { txnid: u64, durable_txn: u64 },   // Memory: нет meta ≤ durable_watermark; durable_txn = watermark (§13.7)
    MapFull { high_water: u32, page_count_max: u32 },          // адресное пространство исчерпано
    NoSpace { needed: u32, free: u32 },                        // страницы есть, но «молодые»
    MapAllocFailed { size: u64, errno: i32, hint: &'static str },
    IdSpaceExhausted,                              // zone_seq исчерпан (R-11)
    WrongAccessor,                                 // lookup() для RRSIG (§12.5)
    NameTooLong, LabelTooLong, RdataTooLarge, RrsetTooLarge,   // RdataTooLarge: rdata.len() > 65535
    ZoneTooLarge, UpstreamTooLarge, ZoneMetaTooLarge,
    InvariantViolation(InvariantId),
    ReadOnly,
    SnapshotFromDifferentFile,                     // Snapshot от другого ZoneFile (instance_uuid mismatch)
    RefuseToRollback,                              // fsck --to-txn T < max(durable_watermark−1, oldest_reader_txn) (R-3, §13.9)
    RolledBackToInitial { instance_uuid: [u8;16], created_unix_ns: u64 },  // §13.7 шаг 11
}

/// 9 значений — ровно как в `domain-model` §6.
pub enum CorruptKind { NoValidMeta, PageChecksum, TreeOrder, Bounds,
                       FreelistCycle, BadTtl, BadZoneMeta, BadRdata, BadName }

/// Внутренняя детализация (в публичный `StoreError` не выходит) — §20.4.
pub enum CorruptDetail { NoValidMeta, BadMagic, Checksum, KeyOrder, SeparatorMismatch,
    PageNo, PageType, ChildRange, DepthExceeded, OffsetOutOfRange, Truncated,
    Cycle, Overlap, TtlOutOfRange, ZoneMetaField, ZoneMetaTooLarge,
    OverflowChain, RdataSum, BadNameEncoding, CompressionByte, BadReaderRegion }
```

> В тексте `Corrupt(Kind)` — сокращение для `Corrupt { kind: Kind, page: None, detail }`; `detail` уточняет причину, `kind` — то, что видит домен.

**Новые варианты (ревизия 1.5.3):**

- `UnsyncedMemoryRecovery { txnid, durable_txn }` — `Memory`-файл, recovery выбрал meta `txnid > durable_watermark`, а валидной meta с `txnid ≤ durable_watermark` нет, и `OpenConfig.allow_unsynced_memory_recovery = false`. Отказ fail-closed: meta могла пережить данные; оператор либо разрешает старт с `NEEDS_FSCK`+read-only+`fsck`, либо откатывает файл. Если подтверждённая meta `≤ durable_watermark` есть, recovery открывает её чисто (при условии, что её `durable_txn` не ниже watermark; иначе W-10) (§13.7 шаг 7).
- `NotRegularFile` — `<zonefile>.lock` (или сам файл зон) не является regular-файлом (FIFO/device/dir/symlink после `O_NOFOLLOW`). Возвращается до `flock`; lock-файл **не удаляется** и не пересоздаётся (SEC-ZF-009/010).
- `SnapshotFromDifferentFile` — `ZoneFile::page_header` получил `Snapshot`, созданный другим `ZoneFile` (несовпадение `instance_uuid`). Ошибка использования API, не повреждение файла: пин чужой reader table не удерживает `oldest_reader_txn` этого файла и не защищает страницы от переиспользования.
- `InvariantViolation(DurabilityBelowFileMode)` — `commit` запросил режим слабее floor (§4.1): файлового `superblock.sync_mode` или липкого `Sync` после `durable_watermark > 1` (§15 F-12). `InvariantId` получает вариант `DurabilityBelowFileMode`. Понижение режима запрещено.
- `Stats.durable_watermark` / `Stats.recovered_unsynced` / `Stats.torn_meta` / `Stats.memory_tail_discarded` — диагностика §13.7 (метрики `recovered_unsynced_total`, `torn_meta_total`, `memory_tail_discarded_total`, лог при старте). `durable_watermark` — единый агрегат, не `durable_txn` выбранной meta. Для `Flush` `recovered_unsynced` — норма после рестарта процесса; `torn_meta` — норма после незавершённой записи meta (без `NEEDS_FSCK`, если второй слот валиден и не новее); для `Memory` `recovered_unsynced` — только вместе с `NEEDS_FSCK`/opt-in.
- Неизвестный `sync_mode` (`> 2`), `sync_mode_version != 1` (кроме legacy `0`) или расхождение A/B → файл не открывается (§4.1): `mode > 2` / legacy `version = 0` при `mode != 0` / расхождение копий → `Corrupt { kind: Bounds, detail: OffsetOutOfRange }`; `version ∉ {0,1}` → `UnsupportedVersion` (в `found.minor` — версия поля, `supported.minor = 1`, `required_flags = 0`).
- `ReaderContended` / `TooManyReaders` возвращает только `Reader::snapshot()` (§20.3 п.4): потолок слотов потока/8 неудачных пинов и заполненная таблица соответственно; `Snapshot` при этом не создаётся.


### 21.2. Политика при повреждении

- Чтение: `Corrupt` → SERVFAIL, `zonefile_corrupt_total{kind}`, `zone_degraded`; частичных ответов нет.
- Recovery: `recovered_unsynced = true` → `recovered_unsynced_total`, запись в лог старта; для `Flush` это норма, `NEEDS_FSCK` не выставляется. `Memory` при `txnid > durable_watermark` сначала пытается чисто открыть meta `≤ durable_watermark`; если такой нет и `allow_unsynced_memory_recovery = false` → отказ старта `UnsyncedMemoryRecovery` (файл не меняется), иначе — `NEEDS_FSCK` и read-only до offline `fsck` (§13.7).
- Recovery: `durable_txn(selected) < durable_watermark` (W-10) → `NEEDS_FSCK`, `write_locked`, read-only до offline `fsck`, метрика `durable_watermark_regression_total`; не тихое принятие.
- Запись: сомнение → `abort`, файл не меняется, `NEEDS_FSCK`.
- `--repair` — только офлайн; авторемонта нет.
- SIGBUS → fail-stop, `sigbus_detected`.

### 21.3. Бюджеты чтения

≤ 8 уровней дерева + 2 каталога, ≤ 64 overflow-страниц, ≤ 255 байт имени, ≤ 128 сравнений (§10.3), ≤ 50 уровней CNAME (домен).

### 21.4. Защита файла (SEC-ZF-009, SEC-ZF-010, SEC-ZF-014)

| Правило | Деталь |
|---|---|
| Открытие данных | `O_RDWR | O_NOFOLLOW | O_CLOEXEC` (и writer, и reader — reader'у нужны права на запись из-за reader-table, §6.1); `fstat`: обычный файл, `st_uid == geteuid()` (владелец `pulse-dns`), `mode & 0o077 == 0` |
| TOCTOU | `st_dev/st_ino` перепроверяются непосредственно перед каждым `mmap` (оба маппинга) |
| Создание | `O_CREAT|O_EXCL|O_RDWR, 0600` + `fchmod(0600)`; каталог `0700` |
| Эксклюзивность writer'а | **отдельный** файл `<zonefile>.lock` (0600), `O_CREAT\|O_RDWR\|O_NOFOLLOW`, `fstat` → regular-file, `flock(LOCK_EX\|LOCK_NB)`; второй writer → `Busy`; не regular → `NotRegularFile` |
| Читатели | **flock не берут**; регистрируются только в reader table. Читатель не блокирует writer'а и не блокируется им |
| Writable-маппинг | **один**, только регион reader table (`PROT_READ|PROT_WRITE`, `MAP_SHARED`, `off % 64 == 0`, длина по формуле §6.1). Данные/деревья/overflow/meta — строго `PROT_READ`; запись через `pwritev` |
| SIGBUS | обработчик `SA_SIGINFO`: `si_addr` в лог, `sigbus_detected++`, `abort()` (fail-stop) |
| Прочее | `madvise(MADV_RANDOM)`/`MADV_WILLNEED` — опционально |

Почему lock-файл, а не `flock` на самом файле зон: `flock` на данных заставил бы читателей брать разделяемую блокировку (иначе writer неотличим от чужого процесса), что противоречит «читатель не блокирует writer'а» и не защищает от усечения. Отдельный lock-файл отделяет эксклюзивность записи от жизненного цикла данных.

---

## 22. Golden-пример (пересчитан: заголовок 40, LeafValue 20, reader table 9×4064; apex A, ключи LE, rdlength BE)

Зона `example.com`, RRset `example.com. IN A 192.0.2.1` (apex; A-запись — item1 дерева зоны), `page_size = 4096`, `map_size = 4 GiB`.

```
page 0  SUPERBLOCK_A: magic "PULSEZF1", ver 1.0, page_size 4096,
        page_count_max 1048576 (4 GiB),
        feature_flags_required = 0x3F (F0..F5),
        reader_region_off = 16384, reader_region_len = 36864,
        reader_region_align = 4096,
        page_meta_a = 2, page_meta_b = 3, page_data_first = 13,
        page_reader_table = 4, page_reader_table_count = 9,
        sync_mode = 0 (Sync), sync_mode_version = 1,
        sections[0] = {id=1, CORE, first_page=0, page_count=1048576}
page 1  SUPERBLOCK_B: копия, superblock_copy = 1
page 2  META_A: txnid=2, durable_txn=2, reclaim_txn=1, page_count_high_water=16,
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
        arrays: restart_offsets=[4001], slots=[4001]; items_start=4001
        item0 @4001: shared_len=0, suffix_len=19
               suffix = RLE(example.com) [13 байт] || FE FF | 00 00 | 00 00   (T_ZONE_ENTRY=0xFFFE, LE)
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
        arrays: restart_offsets=[4017] (2 Б), slots=[4017, 4060] (4 Б);
                items_start=4017 (заголовок+массивы = 62 Б; свободно [62,4017) = 3955 Б)
        item0 @4017: shared_len=0, suffix_len=19
               suffix = RLE(example.com) || 00 00 | 00 00 | 00 00        (T_NODE: type=0, class=0, subtype=0; LE)
               LeafValue: kind=NODE, flags=APEX, ttl=0, rr_count=0, rdlen=0, val_u32=0
               item_bytes = 4 + 19 + 20 = 43
        item1 @4060: shared_len=13, suffix_len=6
               суффикс = 01 00 | 01 00 | 00 00     (type=A(1), class=IN(1), subtype=0; LE)
               LeafValue: kind=INLINE, flags=0, ttl=300, rr_count=1, rdlen=4, val_u32=0
               payload (сразу за LeafValue) = 00 04 C0 00 02 01
                        (u16 rdlength = 00 04 — big-endian DNS wire = 4; rdata C0 00 02 01 = 192.0.2.1)
               item_bytes = 4 + 6 + 20 + 6 = 36
        encoded_size = 56 + 2*1 + 2*2 + 43 + 36 = 141; free_bytes = 3955
        restart_offsets[0] == slots[0] == items_start ✓; n_restarts = ceil(2/8) = 1 ✓
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
| ключ item1 | `RLE(example.com)` 13 Б + 6 Б хвоста = 19; `shared_len=13` (имя целиком, включая терминатор), суффикс 6 Б = `01 00 01 00 00 00` ✓ |
| порядок | `T_NODE` (0x0000) < `A` (0x0001) ✓ |
| `encoded_size` каталога | `56 + 2 + 2 + 95 = 155` ✓ (ZoneEntry 72 байта) |
| `encoded_size` дерева | `56 + 2 + 4 + 43 + 36 = 141` ✓ |
| массивы page 14 | `items_start=4017`; `slots=[4017,4060]`; `restart=[4017]`; `62 + 3955 + 79 = 4096` ✓ |
| payload item1 | `rdlength = 00 04` (**BE**) = 4; `rdata = C0 00 02 01` = 192.0.2.1; `LeafValue.rdlen = 04 00` (**LE**) = 4 ✓ |
| `zone_seq` | первый выданный = 1 (0 зарезервирован как «не назначен»), `next_zone_seq = 2` ✓ |
| `txnid` | создание файла = 1 (§4), первый пользовательский коммит = **2**; `durable_txn = 2` в meta (коммит `Sync`) ✓ |
| `durable_watermark` | `max(min(durable_txn, txnid))` по валидным meta = `min(2,2) = 2` ✓ |
| `reclaim_txn` | `min(durable_watermark − 1, oldest_reader_txn) = min(1, ≥1) = 1` (читателей нет, `oldest_reader_txn` ≥ 1 по §6.4) ✓ |
| `sync_mode` | `0` (Sync), `sync_mode_version = 1`; байт `+624` нулевой, смещения golden не сдвинуты ✓ |
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

ключ A-записи в b.example.com = RLE(b.example.com) || 01 00 | 01 00 | 00 00   (21 Б; type=A(1), class=IN(1) — LE)
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
| SEC-ZF-008 | §13.6 (порядок), §13.7, §15 (F-1..F-6a, F-11..F-13), §19 | `V:unit`, `V:integ`, `V:prop` |
| SEC-ZF-009 | §21.4, §6.1.1, §15 F-9, §13.1 шаги 5–6 | `V:integ`, `V:manual` |
| SEC-ZF-010 | §21.4 (права, `O_NOFOLLOW`, lock-файл 0600), §4 | `V:unit`, `V:integ` |
| SEC-ZF-011 | §21.1 (`Corrupt{kind,page}`, `CorruptNoValidMeta`, `UnsupportedVersion`, `TruncatedFile`), §13.1 шаг 4 (**усечённый существующий файл → `TruncatedFile` и для writer, и для reader**; `ftruncate` только при создании, §4), **§13.1 шаг 6/§3.1: перед каждым `mmap` сверяется `st_size`, а не только `dev/ino`** (truncate-race → `TruncatedFile`, не SIGBUS), §13.9, §13.7 | `V:integ` (truncate существующего файла, в т.ч. между `open` и `mmap`), `V:unit` |
| SEC-ZF-012 | §16 п.9 (**4 таргета**: `zonefile_read`, `zonefile_write`, `zonefile_roundtrip`, `reader_table_state`) + §22, §21.2 | `V:fuzz` (4 таргета) |
| SEC-ZF-013 | §16 п.9, §8.3, §10.2, §11.2 | `V:miri` |
| SEC-ZF-014 | §16 п.8, §6.1 (дескриптор, `off % 64`, формула длины, валидация при открытии), §13.1 шаг 1 (**reader тоже `O_RDWR`: права на запись нужны для слотов; данные — `PROT_READ`**), §21.4, §20.2 | `V:lint`, `V:manual` |

---

## 24. Открытые вопросы

Статус после ревизии 1.4 (второй аудит): все N-1…N-6 и R-1…R-20 закрыты; открытыми остаются вопросы, требующие решений вне формата.

1. **`CHANGESET_LOG`** при Z > 50k зон — v1 или v1.1 (§12.4).
2. **Формат upstream-блоба** (opaque 4096 байт) — согласовать с `pulse-server`; домен ограничивает 16 записей, формат допускает 32 (§12.2).
3. **Интервал GC** (`GC_INTERVAL_MS = 300 000`): подтвердить; влияет только на скорость возврата места после удаления зоны, не на корректность (§12.3, §13.8).
4. **`ZoneEntry` 72 байта**: раскладка зафиксирована в ревизии 1.4 (добавлен `deleted_txn`). Формат ещё не реализован, поэтому миграция не нужна; если фикстуры уже сгенерированы — перегенерировать (§12.1, §22).

Ранее закрытые (для истории): TTL clamp (§11.5), `WriteIntent`/`Edit`/`ApplyOutcome` (ссылки, §11.5), `lookup_all`/`WrongAccessor` (§12.5), `Memory`-режим (§13.6), `MAX_ZONE_META_PAGES` (§12.2), `TooManyReaders` (§21.1), лимит `rdlength` (§11.4).

**Известные компромиссы ревизии 1.4/1.5.3** (описаны, не «тихие»):

| Компромисс | Цена | Почему принят |
|---|---|---|
| COW bucket-страниц (§11.7) | +1 страница-образ на проход выдачи и на коммит с освобождениями; при исчерпании high-water образ берётся из числа выдаваемых | без COW мутация freelist ломает восстановление (и MVCC-инвариант) |
| `Flush` не двигает `durable_watermark` (§13.6/§14) | `reclaim_txn = 0` до первого `sync()`: файл только растёт, нужен периодический `sync()`; после него режим липко `Sync` | иначе откат после потери meta прочитает переиспользованные страницы; `Flush` обязан переживать рестарт процесса без порчи |
| строгая граница `free_txn < durable_watermark` (§14) | страницы последнего durable-коммита возвращаются в оборот на один коммит позже, чем при `≤ watermark`; `high_water` растёт чуть выше после всплесков удалений | худшая восстановимая meta — `watermark−1`; переиспользование `F = watermark` могло бы отдать страницу, ещё достижимую из `D−1` |
| единый `durable_watermark` + W-10 (§13.7/§17) | `durable_txn(selected) < watermark` переводит файл в read-only до fsck; выбор «самой новой» меты не может тихо понизить watermark | иначе sticky обходится метой с меньшим `durable_txn`, а `effective_mode`/reclaim считаются от неё |
| липкий `Sync` после первого `sync()` (§4.1 п.6) | `Flush`/`Memory` нельзя использовать как «постоянно слабый» режим; `sync()` необратимо повышает класс файла | два слабых коммита после `Sync` затирают durable-слот, и power loss откатывает ниже подтверждённого коммита |
| `sync_mode` — свойство файла, не коммита (§4.1) | нельзя менять класс durability на ходу; коммит слабее floor отклоняется | одно persistent-поле не может честно описывать смесь режимов; recovery должен знать класс данных до выбора meta |
| `Memory` требует `allow_unsynced_memory_recovery` (§13.7) | при отсутствии подтверждённой meta — отказ старта вместо «тихого» принятия meta без данных; opt-in даёт read-only до offline fsck | safety > availability: meta могла пережить данные |
| GC tombstone раз в 5 мин (§13.8) | место возвращается с задержкой до интервала | мгновенное освобождение невозможно: на страницы ссылаются живые снапшоты |
| Публичный `CorruptKind` — 9 значений (§20.4) | домен теряет детализацию причины (она остаётся в `detail` для логов) | единый контракт ошибок с `domain-model` §6 |
| `FORWARD` — в `ZoneEntry`, `SIGNED/denial` — в meta-блоке (§12.1) | `meta()` читает страницу при проверке подписи | устранено дублирование; `find_zone` остаётся одностраничным для классификации |
| Guard 148/351 item'ов (§16 п.3) | верхняя оценка; фактическая ёмкость зависит от длин суффиксов | guard защищает от «бомбы» в файле, а не моделирует раскладку |

---

## 25. Дельта формата v2: параллельная запись по зонам

Раздел нормативен для **v2.0** в части **семантики** и **границ применимости**. Точная раскладка полей и пошаговые протоколы — `docs/spec/parallel-writes-v2.md` (единственная нормативная детализация; этот раздел её не дублирует). Решения и обоснование — `docs/adr/0005-parallel-writers.md`; требования безопасности — `docs/adr/0006-parallel-writers-safety.md` и `docs/adr/0004-security-model.md` §1.3 (`SEC-PW-001..014`). Приоритет при расхождении: ADR-0006 → ADR-0005 → `parallel-writes-v2` → этот раздел.

Принятые решения, на которых стоит раздел: **D-A** — запись корня 64 Б (без отдельного `ZoneRootBlock`); **D-C** — курсор аллокатора и `txn`-билет в памяти, второй writable-регион не вводится; **F-9** — `snapshot_seq` не ceiling (`ceiling = ∞`), retention — только `freeze()`.

### 25.1. Что вытесняется

| Положение v1 | Замена |
|---|---|
| §3 «Meta A / Meta B», §5 (meta, `durable_txn`, `reclaim_txn`, `freelist_*`, `zone_dir_root`) | root ring + chain + `ALLOC_RECORD` (`parallel-writes-v2` §3–§4) |
| `PAGE_META_A/B` (2, 3) | `page 2` — `LayoutHead` A, **`page 3` — `LayoutHead` B**; `PAGE_WRITER_REG = 4`; `PAGE_ALLOC_RECORD_A/B = 5/6`; `PAGE_READER_TABLE = 7`; `PAGE_TYPE_META` зарезервирован |
| §5 «пишется только неактивная meta» | §25.3 (выбор версии ring/chain) |
| §6.2 слот 32 Б, `active_txn` | слот 128 Б, `pins[6]` по 16 Б (u64-версия), seqlock (`parallel-writes-v2` §5.2–5.3) |
| §7 `reserved1` (+12) = 0 | `owner_zone` под `F_PARALLEL_WRITES` |
| §11.7 глобальный freelist | per-zone пулы; bucket — фаза 1, `free_head` — в `RootEntry V` |
| §12.1 `ZoneEntry` 72 Б | 24 Б идентичности; мутируемое — в 64-байтовой записи корня |
| §13.6/§13.7 (коммит/recovery) | §25.6/§25.7 |
| §14 (`oldest_reader_txn`/`reclaim_txn`) | §25.8 (`MP(z)`/`RV_z`/`freeze_epoch`) |
| I-3, I-4, I-6, I-12, I-14, W-1, W-9, W-21 | §25.10 |

Без изменений: `LeafValue` (§11.1), payload/overflow (§11.2–11.4), ключи/компаратор (§8–§10), `ZoneMeta`-блок (§12.2), `ZoneState`-семантика (§12.6), CRC (§19), лимиты (§16), суперблок/секции (§4) — кроме `version_major = 2` и новых required-флагов.

### 25.2. Физическая раскладка v2

| Страница | Содержимое |
|---|---|
| 0, 1 | Superblock A / B |
| 2, 3 | `LayoutHead` A / **B** (отдельные страницы, F-2) |
| 4 | Writer registry (M3; в M1 `term = 1`) |
| 5, 6 | `ALLOC_RECORD` A / B (отдельные страницы) |
| 7 … 7+N−1 | Reader table; N = 33 @4096, 17 @8192, 9 @16384 |
| далее | Root directory A/B регионы: `2 × ceil(max_zones / 16)` страниц |
| далее | data pages: branch/leaf/overflow/zone-meta/chain/buckets |

```
reader_region_off   = 7 * page_size            # % 64 == 0
page_root_dir_first = 7 + N
page_data_first     = page_root_dir_first + 2 * ceil(max_zones / 16)
```

`max_zones` фиксируется при создании (дефолт 65536). **Второго writable-региона нет**: единственный writable — reader table (SEC-ZF-014 сохраняется); `reserve_cursor`/`reserve_txn` живут в памяти процесса (D-C), durable-барьер — `ALLOC_RECORD` (`pwritev`, 2 копии в разных страницах).

### 25.3. Версии и выбор состояния

| Величина | Смысл |
|---|---|
| `txn` | глобальный монотонный номер коммита (CAS-блок в памяти); не per-zone |
| `version(Z)` | `txn` последнего коммита зоны; строго возрастает внутри зоны |
| `DP` / `DT` | durable `page_limit` / `txn_limit` из `ALLOC_RECORD`; не убывают |
| `D_z` | max версия, чей корень fsync'нут |
| `MP(z)` | минимум пинов зоны (∞ = нет пинов) |
| `RV_z` | `min(D_z − 1, MP(z), freeze_epoch)`; гейт выдачи страниц |
| `snapshot_seq` | `published_txn` на момент `snapshot()`; **аудит/`X-Commit-Txn`, не ceiling** |
| `freeze_epoch` | `0` = нет freeze; иначе EPOCH-барьер удержания |
| `zone_guard[z]` | seqlock зоны (чётный = стабильно) |

Выбор версии: `select(z, ceiling) = max { version : CRC ok ∧ owner_zone ok ∧ version ≤ ceiling }`; tie-break — копия A. Обычное чтение — `ceiling = ∞` (последняя версия); при отсутствии в ring — chain до `MAX_ROOT_CHAIN_HOPS = 4096`; цикл/превышение — `Corrupt`; версия ниже доступной истории — `StaleRoot`; зоны нет/tombstone — `NoZoneVersion`. Чтение-на-`T` — только `freeze()` + EPOCH-пин или `fsck --at-epoch T`.

**`PageHeader.txn`** — `txn` создавшей версии; проверка `page.txn ≤ version` выполняется **только вместе с** `owner_zone == zone_seq` (иначе страница чужой зоны с меньшим `txn` прошла бы проверку — кросс-зонный ABA; это file-fatal, §25.9).

### 25.4. Новые объекты (детали — `parallel-writes-v2`)

| Объект | Назначение |
|---|---|
| `RootEntry` 64 Б (D-A) | immutable-запись версии: `root_page`, `tree_level`, `meta_root`, `state`, `deleted_txn`, `soa_serial`, `rrset_count`, `free_head`, `prev_record`, `page_limit_at_commit`; `zones()`/`find_zone`/`serial` — одна запись, без второй страницы |
| Root ring 4 версии × 2 копии в **разных** A/B-страницах, 16 зон/страница-копия | публикация корня без глобальной meta; torn одной копии без потерь |
| `PAGE_TYPE_ROOT_CHAIN = 11` | safety valve: одна запись на страницу, `prev_record` → предыдущая; достижим из durable-записи |
| `ALLOC_RECORD` (2 копии в разных страницах) | durable `page_limit`/`txn_limit`/`leader_term`/`seq` |
| `owner_zone` в `PageHeader.reserved1` | привязка страницы к зоне; 0 = глобальный объект |
| Reader slot 128 Б, `pins[6]` × 16 Б | per-zone пины (u64-версия) + EPOCH-пин при overflow |
| Per-zone free pools (bucket) | реюз только после durable drop |

`ZoneRootBlock` и `ALLOC_CTRL` **не существуют** (D-A/D-C): все поля зоны — в `RootEntry`; курсор — в памяти.

### 25.5. `owner_zone`

| Значение | Смысл |
|---|---|
| 0 | глобальный объект: superblock, `LayoutHead`, каталог, `ALLOC_RECORD`, root dir/chain, reader table, donation-пул |
| `zone_seq` | страница принадлежит зоне; ставится до публикации, проверяется при чтении |

Несовпадение `owner_zone` при валидном CRC (или `version`/`owner_zone` записи от чужой зоны) — **file-fatal** (§25.9), а не деградация зоны: это признак нарушения изоляции множеств страниц. `owner_zone` иммутабелен для опубликованной страницы; free-страница переписывается новым владельцем при выдаче. v1-файлы (read-only): `owner_zone = 0`, проверка пропускается; конвертер проставляет владельцев.

### 25.6. Коммит и durability

Нормативная последовательность — `parallel-writes-v2` §4.5: **фаза 1** (`ALLOC_RECORD` + данные + bucket `dropped(V)` + chain-страницы → `fdatasync`), **фаза 2** (2 копии `RootEntry` → `fdatasync`), публикация, ack. Два `fdatasync` на пачку; один fsync (данные+корни) запрещён (`PW-I5`). Корень не пишется, пока `DP > max_allocated_id` и `DT ≥ V`. `free_head` и `prev_record` входят в `RootEntry V` и валидируются `< page_limit_at_commit`.

| Режим | Фаза 1 | Фаза 2 | `D_z` | Гарантия |
|---|---|---|---|---|
| `Sync` | да | да | двигается | подтверждённый коммит переживает power loss |
| `Flush` | да | корни без fsync | не двигается | переживает рестарт процесса; power loss → откат зоны на `V−1` |
| `Memory` | нет | нет | не двигается | гарантий нет (политика v1 §13.7) |

Sticky-`Sync` — как §4.1 п.6: после первой durable-группы (`DT > 1`) только `Sync`. `sync()` — глобальный барьер (двигает `D_z` всех зон). Auto-promotion в `Sync` — только когда ring блокирует `D_z` при отсутствии пинов (`parallel-writes-v2` §4.3); при пинах — chain, запись не блокируется. `freeze()` запись не блокирует, только задерживает рекламацию.

### 25.7. Восстановление

`recover()` (только под `LOCK_EX`): superblock → `LayoutHead` → reader region → `ALLOC_RECORD` (max-valid по `seq`; обе невалидны → `CorruptNoValidMeta`) → каталог → для каждой зоны `select(z, +inf)` (ring/chain) → проверки (`owner_zone`, `root_page`/`prev_record`/`free_head`, `page_limit_at_commit`, `state`/`deleted_txn`) → `DP = max(ALLOC_RECORD.page_limit, max root.page_limit_at_commit, max pool.page_id+1, page_data_first)`; `DT` — максимум → `reserve_txn = max(DT, max version) + 1`; `reserve_cursor := DP` (курсор только в памяти, D-C) → `D_z = version`, `RV_z = min(D_z − 1, MP(z), freeze_epoch)` → санитизация reader table (§13.7 шаг 9) → публикация.

`max page.txn` на открытии не считается (обход деревьев запрещён); `fsck --verify` проверяет `page.txn ≤ version` и при `page.txn ≥ reserve_txn` поднимает `reserve_txn` + `NEEDS_FSCK`. Откат «всего файла» не существует: каждая зона выбирается независимо (PW-L1). Понижение `DP`/`DT` → `AllocWatermarkRegression` → **file-fatal** (§25.9). Обе версии записи корня невалидны → `Corrupt(BadZoneHead)` **по зоне**; при `strict_corruption = file` — отказ файла.

### 25.8. Рекламация

`RV_z = min(D_z − 1, MP(z), freeze_epoch)`, где `MP(z)` — минимум пинов зоны и EPOCH-пинов; обновляет GC-проход (10 мс, плюс по требованию при `NoSpace`) под `zone_guard[z]` (RAII `EpochGuard`); писатели не сканируют таблицу. Условие выдачи страницы зоне `Z`:

```
drop_txn ≥ 2 ∧ drop_txn < D_z ∧ drop_txn ≤ RV_z ∧ drop_txn < current_version(Z)
```

Страницы «never published» реюзаются без гейта. **Порядок F-10:** bucket `dropped(V)` пишется в фазе 1 того же коммита, `RootEntry V.free_head` указывает на него; после краха bucket достижим только из durable-головы. Drop становится durable в фазе 2; reuse — не раньше `V+1` (`drop_txn < D_z`). Крах между фазой 1 и корнем → bucket недостижим (утечка), не double-free. Donation — двумя фазами (durable drop → donate-record следующей группой → выдача при `donated_at_txn < DP`).

### 25.9. File-fatal vs zone-fatal (F-6)

**File-fatal** (всегда `write_locked` + read-only до `fsck`; `strict_corruption` не применяется): `head.page_limit_at_commit > DP`; пересечение множеств страниц зон; `owner_zone`/`version` чужой зоны при валидном CRC; битый/несовместимый `LayoutHead`/`ALLOC_RECORD`/каталог; регрессия `DP`/`DT`/`txn`; `page.txn > version` у достижимой страницы при валидном CRC.

**Zone-fatal** (деградирует только зона): обе копии записи torn; `page_limit_at_commit < root_page`; CRC/`page_no`/`payload_len` собственной страницы; `state`/`deleted_txn` несогласованы; `ZoneDegraded`. `strict_corruption = zone` (дефолт) применяется **только** к этому классу; `file` возвращает v1-поведение.

### 25.10. Инварианты v2

| ID | v2 |
|---|---|
| I-3 | Для зоны активна версия с максимальным валидным `version ≤ ceiling` (`ceiling = ∞` по умолчанию); tie-break — копия A |
| I-4 | Страницы версии `V` неизменны, пока `V ≥ RV_z + 1` или удерживаются пином |
| I-6 | `DP`/`DT` не убывают; `D_z` не понижается при recovery |
| I-12 | Запись корня самодостаточна для выбора версии (все поля зоны в ней); глобально recovery зависит от `LayoutHead`/каталога/`ALLOC_RECORD` (PW-L7) |
| I-14 | `DT > 1` ⇒ файл липко `Sync` |
| I-15 | `root_page`/`meta_root`/`free_head`/`prev_record` = 0 или `< page_limit_at_commit` |
| I-16 | Множества страниц разных зон не пересекаются |
| I-17 | `version(Z)` и `txn` строго возрастают; `txn` не переиспользуется |
| I-18 | `owner_zone` опубликованной страницы зоны `Z` = `Z`; проверяется при чтении |
| I-19 | Ring исчерпан ⇒ вытеснение в chain; chain достижим из durable-записи; запись не блокируется (патология — `ZoneWriterStalled{zone}`) |
| I-20 | `snapshot_seq` не ограничивает `zone_snapshot`; отказ чтения по нему запрещён |
| W-1' | Пишется группа версии ring; версия `≥ MP(z)` вытесняется в chain, версия `≥ D_z` при отсутствии пинов — auto-promotion `Sync`, затем перезапись |
| W-9' | Выброшенные страницы — в bucket фазы 1 того же коммита; `free_head` — в `RootEntry V` |
| W-21' | Выдача страницы — четыре условия §25.8 |

### 25.11. `fsck` v2

Дополнения к §13.9: валидность ring и выбор max-valid; chain (монотонность `version`, `owner_zone`, CRC, освобождённый хвост — не ошибка); `owner_zone` записи корня и каждой страницы; `root_page`/`prev_record`/`free_head < page_limit_at_commit`; `page.txn ≤ version`; дизъюнктность множеств зон битсетом; `drop_txn < D_z` в пулах; возврат утёкших страниц `< DP`; `page_limit ≥ max root.page_limit_at_commit`. `--repair --zone <origin>` при `V ≥ D_z − 1` ∧ `V ≥ RV_z`, иначе `RefuseToRollback`.

### 25.12. Совместимость, миграция, golden

v1-файл: читается (reader-путь v1 на один релизный цикл); writer → `ReadOnly { reason: ConvertRequired }`. v2 под v1-сборкой → `UnsupportedVersion`. Конвертер — ADR 0005 §9. Даунгрейд не поддерживается. Golden-фикстуры страниц/ключей v1 переиспользуются; **v2-фикстуры пролога и ring/chain/`ALLOC_RECORD`/reader-слота регенерируются** (page 3 → `LayoutHead` B, registry → 4, `ALLOC_RECORD` → 5/6, reader → 7).

### 25.13. Приёмка M1

Нормативные условия **C-1…C-11** (ADR-0006 §12) и тесты **T-1…T-5** — `parallel-writes-v2` §15. Раздел §25 их не дублирует; непройденное условие = M1 не принят.

### 25.14. Что этот раздел намеренно не содержит

Раскладку полей, пошаговые протоколы пина/публикации/chain/GC, значения лимитов и матрицу отказов — всё это в `parallel-writes-v2.md` и ADR-0006. Дублирование здесь создало бы второй источник истины.

