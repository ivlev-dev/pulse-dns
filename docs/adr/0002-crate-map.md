# ADR 0002. Карта крейтов и защита от циклов зависимостей

- **Статус:** принято (v1)
- **Дата:** 2026-11-23
- **Область:** Cargo workspace, публичные API крейтов, владение данными
- **Связанные документы:** `docs/adr/0001-ddd-architecture.md`, `docs/adr/0003-zonefile-format.md`, `docs/adr/0004-security-model.md` (действующие требования; их статус Proposed относится к формальной зрелости до M1), `docs/spec/domain-model.md`, `docs/api/rest-v1.md`

---

## 1. Контекст

Набор крейтов зафиксирован: `pulse-dns`, `pulse-zonefile`, `pulse-runtime`, `pulse-server`, `pulse-resolver`, `pulse-api`; бинарники `pulsed`, `pulseresolved`. Требования:

1. Направление зависимостей должно быть проверяемым в CI, а не «по договорённости».
2. Authoritative, резолвер и API разрабатываются независимо (разные люди/агенты, разные релизные ритмы).
3. Домен не должен тянуть I/O; резолвер не должен тянуть mmap-формат; API не должен тянуть реализацию сервера.
4. Данные имеют одного владельца; «общая» запись состояния запрещена.

Решение — **слоистая карта крейтов с явным списком разрешённых рёбер и dependency inversion на границе Control API**.

---

## 2. Таблица крейтов

| Крейт | Тип | Слои | Ответственность | Разрешённые зависимости (workspace) | **НЕ входит** | Владелец данных |
|---|---|---|---|---|---|---|
| **pulse-dns** | lib, L0 | `domain` (только), `wire` | Wire-format RFC 1035 (кодирование/декодирование, сжатие имён), типы RR (`Rdata`, `Record`, `Rrset`, `Name`, `Ttl`, `Serial`), EDNS0, TSIG-примитивы, DNSSEC-примитивы (RRSIG/NSEC/NSEC3/DS/DNSKEY, canonical order, key tag), presentation-парсер RDATA | — (лист) | Сеть, файлы, async, mmap, кеш, политики, HTTP, конфигурация, `Zone`/`ZoneId` | Определения протокола: байтовый контракт и семантика RR-типов |
| **pulse-runtime** | lib, L0 | `reactor`, `net`, `task`, `time` | Адаптер I/O: io_uring (Linux) с fallback на epoll; UDP/TCP-сокеты, accept-loop, таймеры, spawn/join, graceful shutdown, backpressure-примитивы; трейсинг-контекст задачи | — (лист; внешние: `io-uring`, `libc`, `mio`/`epoll`, `pin-project`, `tracing`) | Знания о DNS, зонах, HTTP, конфигурации домена | Runtime-ресурсы процесса (fds, регистрации io_uring, таймерное колесо) |
| **pulse-zonefile** | lib, L1 | `domain`, `application`, `infrastructure` | Zone Store: бинарный формат всех зон в одном mmap-файле, reader/writer, `ZoneId`-аллокатор (стабильный `zone_seq`, не `tree_root`), снапшоты (RCU/epoch), транзакции `Edit`, crash-safety, жизненный цикл зон (`create_zone`/`delete_zone`, tombstone, освобождение после reclaim), meta-блок настроек (`meta_root`) | `pulse-dns` | DNS-ответы, NOTIFY-логика, DNSSEC-подпись, HTTP, политики, знание о том, кто такой клиент; retention IXFR-дельт (v1 — in-memory в `pulse-server`) | Файл зон (единственный источник правды по содержимому зон и настройкам зоны), его layout и версия формата, `ZoneId` |
| **pulse-server** | lib, L2 | `domain`, `application`, `infrastructure`, `interface` | Authoritative: lookup-семантика (wildcard/CNAME/DNAME/zone cut), сборка ответов, UDP/TCP-транспорт, EDNS, TSIG-проверка, DNSSEC-подпись на выдаче, AXFR/IXFR-out, NOTIFY-out, AXFR/IXFR-in, приём NOTIFY, состояние трансферов, ACL зон | `pulse-dns`, `pulse-zonefile`, `pulse-runtime` | Рекурсивные итерации, кеш ответов, HTTP/REST, управление токенами, blocklist'ы | Runtime-состояние авторитетного сервиса: `TransferState`, `Peer`-конфигурация, история NOTIFY, DNSSEC-ключи (публичные части + `SecretRef`) — персистентно в **state-файле в state-dir** (атомарная запись + fsync, версионирование), не в зонном файле |
| **pulse-resolver** | lib, L2 | `domain`, `application`, `infrastructure`, `interface` | Рекурсивный резолвер: итерации от корня, кеш (positive/negative), DNSSEC-валидация, qname-minimization, ECS-политика, Policy/Filtering (blocklist, overrides, rules) | `pulse-dns`, `pulse-runtime` | Authoritative-обслуживание, mmap-формат, HTTP/REST, управление ключами зон, Notify/трансферы зон | Кеш резолвера (только память), правила политики и blocklist-источники (персистентность — конфиг-каталог резолвера), состоянии upstream-ов |
| **pulse-api** | lib, L3 | `domain`, `application`, `interface` | REST API v1: роутинг, DTO, валидация запросов, problem+json, authN/Z (токены, scopes, RBAC), jobs, аудит, OpenAPI-схема. **Только контракты** для управления: объявляет required ports | `pulse-dns` (только value objects для DTO) | Реализация хранения зон, DNS-логика, сетевые DNS-транспорты, прямой доступ к mmap, знание о `pulse-server`/`pulse-resolver` | Токены (хеши), scopes/роли, jobs, аудит-журнал, idempotency-записи, настройки API |
| **pulsed** | bin, L4 | wiring | Composition root authoritative-процесса: конфиг, открытие Zone Store, сборка `pulse-server`, подъём `pulse-api` с реализациями портов, сигналы, lifecycle | все библиотечные крейты | Доменная логика, прямые SQL/файловые операции в обход портов | — (не владеет данными) |
| **pulseresolved** | bin, L4 | wiring | Composition root резолвер-процесса: конфиг, сборка `pulse-resolver`, подъём `pulse-api` (профиль resolver), реализация портов API над резолвером | `pulse-resolver`, `pulse-api`, `pulse-runtime`, `pulse-dns` | Доменная логика | — |

Уровни (L) — не формальность: ребро разрешено только `L(n) → L(m)` при `m < n`, плюс явные исключения из таблицы (их нет).

**Процессная топология (v1):** два независимых бинарника — `pulsed` (authoritative) и `pulseresolved` (resolver). Объединённый режим — вне scope v1. У каждого процесса свой API-инстанс, свой jobs/аудит, свой `/metrics`; `ZoneStore` есть только у `pulsed`, кеш резолвера — только у `pulseresolved`. Кросс-процессное взаимодействие — по сети (DNS; управление — HTTPS+mTLS). `pulse-api` не зависит от того, в каком процессе он поднят.

---

## 3. Разрешённые рёбра и их обоснование

| Ребро | Зачем нужно | Что было бы нарушением |
|---|---|---|
| `pulse-zonefile → pulse-dns` | Переиспользовать канонические `Rrset`/`Rdata`/`Serial`/`Ttl` вместо дублирования модели; один источник правды по семантике RR | Своя копия `Rdata` в zonefile (рассинхронизация wire/RRset-семантики) |
| `pulse-server → pulse-zonefile` | Authoritative читает зоны только через `ZoneStore`/`ZoneWriter` | Прямое чтение mmap из `pulse-server` |
| `pulse-server → pulse-runtime` | UDP/TCP-транспорт, таймеры репликации, spawn | `tokio` напрямую в домене/application сервера |
| `pulse-resolver → pulse-runtime` | Сетевой клиент, таймеры кеша, spawn итераций | Свой event loop внутри резолвера |
| `pulse-api → pulse-dns` | DTO используют `Name`/`Rdata`/`Rrset`-представления (presentation-парсинг/валидация) | Импорт `pulse-server`/`pulse-resolver` ради типов |
| `pulsed → pulse-*` | Composition root | Доменная логика в бинарнике |
| `pulseresolved → pulse-*` | Composition root | Доменная логика в бинарнике |

### 3.1. Запрещённые рёбра (проверяются в CI)

| Запрет | Причина |
|---|---|
| `pulse-dns → *` | shared kernel обязан быть листом; иначе он превращается в свалку |
| `pulse-runtime → *` | runtime не знает про DNS |
| `pulse-zonefile → pulse-server` | Zone Store — поставщик, а не клиент authoritative |
| `pulse-server → pulse-resolver` | разные контексты, разные процессы/жизненные циклы |
| `pulse-resolver → pulse-server` | то же; плюс резолвер не должен получать доступ к зонам в обход `ZoneStore` |
| `pulse-api → pulse-server` / `pulse-api → pulse-resolver` | API не должен зависеть от реализаций; см. §4 |
| `pulse-zonefile → pulse-api` | контрольная плоскость не является зависимостью хранилища |
| любой lib → `pulsed`/`pulseresolved` | бинарники не библиотеки |
| `pulse-server → pulse-runtime` **только** через `infrastructure`/`interface` | домен и application не должны видеть `pulse-runtime` типы (проверка по `use`-дереву слоёв) |

> Технически `pulse-server → pulse-runtime` разрешён как ребро Cargo, но **на уровне модулей** тип `pulse_runtime::*` допустим только в `infrastructure/` и `interface/`. Application-слой работает с `Future`/`Stream` из `core` и с портами (`Timer`, `Spawner`), объявленными в `application::port`.

---

## 4. Как избежать циклов между сервером, резолвером и API

### 4.1. Проблема

Наивная схема «API знает про сервер и резолвер» даёт:

```
pulse-server ──▶ pulse-zonefile ──▶ pulse-dns
      ▲                                   ▲
      │                                   │
pulse-api ──────────▶ pulse-resolver ─────┘   (ребро api→server→zonefile,
                                               api→resolver→dns — циклов нет,
                                               но есть жёсткая связанность)
```

Цикла формально нет, но появляются реальные проблемы:
- API нельзя собрать/протестировать без mmap, сокетов и io_uring;
- любая правка внутреннего API сервера ломает HTTP-слой (нет границы контекста);
- `pulseresolved` тянет `pulse-server` (или наоборот) ради «общих» админ-функций;
- при попытке добавить обратное ребро (серверу нужен API, например для аудита) — цикл.

### 4.2. Решение: required ports в `pulse-api`

`pulse-api::application::port` объявляет **только то, что нужно Control API**:

```rust
// pulse-api::application::port
pub trait ZoneAdmin: Send + Sync {
    fn list(&self, q: ZoneQuery) -> Result<Page<ZoneDescriptor>, AdminError>;
    fn get(&self, origin: &Origin) -> Result<ZoneDescriptor, AdminError>;
    fn create(&self, cmd: CreateZone) -> Result<ZoneDescriptor, AdminError>;
    fn delete(&self, origin: &Origin, confirm: &str) -> Result<(), AdminError>;
    fn bump_serial(&self, origin: &Origin, mode: SerialMode) -> Result<SerialChange, AdminError>;
    // ...
}
pub trait RrsetAdmin: Send + Sync { /* list/get/put/patch/delete */ }
pub trait TransferAdmin: Send + Sync { /* peers, trigger, status, notify */ }
pub trait DnssecAdmin: Send + Sync { /* keys, rollover, ds, sign status */ }
pub trait CacheAdmin: Send + Sync { /* stats, purge */ }
pub trait PolicyAdmin: Send + Sync { /* rules, blocklists, overrides */ }
pub trait SettingsAdmin: Send + Sync { /* get/patch section, reload */ }
pub trait MetricsSource: Send + Sync { fn snapshot(&self) -> MetricSnapshot; }
pub trait JobQueue: Send + Sync { fn submit(&self, spec: JobSpec) -> Result<JobId, JobError>; }
pub trait AuditSink: Send + Sync { fn record(&self, event: AuditEvent); }
pub trait Authorizer: Send + Sync { /* authenticate/authorize */ }
```

Реализации живут **в бинарниках** и делегируют в application-сервисы контекстов:

```rust
// pulsed::wiring::api_adapters
struct ServerZoneAdmin { store: Arc<dyn ZoneStore>, writer: ZoneWriterHandle, changes: ChangeFeed }
impl ZoneAdmin for ServerZoneAdmin { /* маппинг DTO API ↔ домен сервера */ }

// pulseresolved::wiring::api_adapters
struct ResolverCacheAdmin { cache: Arc<ResolverCache> }
impl CacheAdmin for ResolverCacheAdmin { /* ... */ }
```

Итоговый граф:

```
pulse-api ──▶ pulse-dns                     (только value objects)
pulsed ──▶ pulse-api, pulse-server, pulse-zonefile
pulseresolved ──▶ pulse-api, pulse-resolver
```
`pulse-api` **не имеет** ребра ни к серверу, ни к резолверу. Цикл невозможен по построению: рёбра идут только «вниз» от бинарников.

### 4.3. Цена и правила

- **Маппинг DTO** (`ZoneDescriptor` ⟷ `ZoneMeta`, `RrsetDocument` ⟷ `Rrset`) — в бинарнике, в модуле `wiring::api_adapters::<context>`. Дублирование структур осознанно: это ACL.
- **Один адаптер на контекст**, ≤ 400 строк; если больше — выносить в `pulse-api::application` (доменный сервис API, не знающий источника).
- **Порты API — синхронные**, если операция быстрая (чтение/валидация), и возвращают `Future`, если она длительная. Длительные операции — через `JobQueue` (не блокируют HTTP-воркер).
- **Ошибки**: каждый адаптер переводит `ServerError`/`ResolverError` в `AdminError` (коды problem+json). Не пробрасывать чужие ошибки в HTTP.
- **Профили**: `pulseresolved` реализует только `CacheAdmin`, `PolicyAdmin`, `SettingsAdmin`(resolver-секции), `MetricsSource`, `JobQueue`, `AuditSink`; `ZoneAdmin`/`TransferAdmin`/`DnssecAdmin` отсутствуют → `404`, и `capabilities` это отражает.

### 4.4. Если однажды понадобится третья сторона

Правило: **новый потребитель объявляет свой порт; реализация — в composition root.** Запрещено «для удобства» добавлять ребро `api → server`. Если порт нужен нескольким потребителям и его нельзя разместить в `pulse-dns` по смыслу (это не протокол) — это повод для ADR о новом крейте, а не для обхода правила.

---

## 5. Владение данными (system of record)

| Данные | Владелец (запись) | Читатели | Механизм чтения |
|---|---|---|---|
| Содержимое зон (RRset) | `pulse-zonefile` (файл зон) | `pulse-server`, `pulsed` (API-адаптер) | `ZoneStore::snapshot` + `lookup`/`lookup_all`/`enumerate` (zero-copy `RrsetRef`) |
| Настройки зоны (`default_ttl`, `denial`, SOA-таймеры, forward-upstreams) | `pulse-zonefile` (meta-блок, `ZoneEntry.meta_root`) | `pulse-server`, `pulse-api` | `ZoneStore::meta`; запись — `EditOp::SetZoneMeta` |
| Жизненный цикл зоны (создание/удаление, tombstone) | `pulse-zonefile` (`create_zone`/`delete_zone`, освобождение после reclaim) | `pulse-server`, `pulse-api` | `ZoneWriter`; tombstone не виден в `zone_meta`/`find_zone` |
| `ZoneId`-пространство | `pulse-zonefile` — стабильный `zone_seq`, не `tree_root` | все | `ZoneMeta`; идентификатор переживает `compact_zone` |
| Версия/восстановление формата | `pulse-zonefile` | — | открытие файла, `StoreError::UnsupportedVersion` |
| IXFR-дельты (окно retention) | `pulse-server` — in-memory ринг в v1; `pulse-zonefile` — зарезервированная `IXFR_HISTORY`-секция | `pulse-server` (IXFR-out) | доменный сервис `ZoneDiff` поверх истории версий; при отсутствии истории — `AxfrRequired` |
| `TransferState`, `Peer`, NOTIFY-история | `pulse-server` → **state-файл в state-dir** (атомарная запись + fsync, версионирование; не zonefile) | `pulse-api` (адаптер), метрики | application-сервисы сервера; `infrastructure::state` |
| DNSSEC-ключи (публичные) и `SecretRef` | `pulse-server` → state-файл в state-dir | `pulse-api`, `pulse-dns` (для подписи) | `DnssecKeyRepository` (порт сервера) |
| Приватный ключевой материал | `SecretStore`: файл 0600 в каталоге 0700 (v1); PKCS#11/KMS — roadmap | `pulse-server` (подпись) | `SecretStore::get`, никогда не покидает процесс в открытом виде |
| Кеш резолвера | `pulse-resolver` (память, не персистится) | `pulse-api` (stats/purge) | `CacheAdmin` |
| Policy-правила, blocklist-источники | `pulse-resolver` (конфиг-каталог процесса) | `pulse-api` | `PolicyAdmin` |
| Токены (хеши), роли, jobs, аудит, idempotency | `pulse-api` (state-dir процесса) | `pulse-api` | внутренние репозитории API |
| Bootstrap-токен | env `PULSED_BOOTSTRAP_TOKEN` одноразово при пустом хранилище → хеш в state API | `pulse-api` | `Authorizer`, см. `docs/api/rest-v1.md` §2.6 |
| Конфигурация узла | composition root / файл конфигурации | все | передаётся в конструкторы (иммутабельные снапшоты настроек) |

Правила:
1. **Пишет только владелец.** Другие контексты получают данные через порт/адаптер, не через файл/таблицу напрямую.
2. **Нет общего изменяемого состояния.** Разделяются только immutable value objects (`pulse-dns`) и `Arc<ZoneSnapshot>` (immutable).
3. **Границы процессов.** `pulsed` и `pulseresolved` не делят ни хранилищ, ни метрик: у каждого свой `ZoneStore`/кеш, свой API-state и свой `/metrics`. Объединённый режим — вне scope v1.
4. **Персистентность серверного состояния** — только state-файл в state-dir (`infrastructure::state`, владелец спецификации — крейт `pulse-server`): **JSON** с обязательным целым `schema_version`; запись temp + `fsync` + atomic rename; при неизвестной или более новой версии — отказ старта (`StateError::UnsupportedVersion`), а не «тихое» обнуление; миграции — последовательные функции `vN → vN+1`. Лимит размера — 32 MiB. Секреты в state-файл не пишутся (только `SecretRef`), приватные ключи в открытом виде запрещены. Полная спецификация — `docs/spec/server-state-v1.md` на этапе M3; до M2 достаточно этих требований.
5. **Хранилища токенов раздельные:** `pulsed` и `pulseresolved` — независимые сервисы со своими state-dir, токены/bootstrap не разделяются.

---

## 6. Модульная раскладка (обязательная)

```
pulse-dns/        src/{domain/{name,rdata,rr,rrset,record,ttl,serial,question,dnssec},
                        wire/{decode,encode,compression,edns,tsig}, presentation}
pulse-runtime/    src/{reactor/{uring,epoll}, net/{udp,tcp,listener,stream}, task, time, shutdown}
pulse-zonefile/   src/{domain/{zone,snapshot,edit,error},
                        application/{port/{zone_store,zone_writer}, use_case},
                        infrastructure/{pager, superblock, meta, btree, freelist, readers,
                                        name_rle, checksum, zone_dir, overflow,
                                        snapshot_publish, lifecycle,
                                        name_dict /* резерв v1.1 */,
                                        ixfr_history /* резерв: персистентная история IXFR */}}
pulse-server/     src/{domain/{resolve,wildcard,dname,acl,transfer,dnssec},
                        application/{port,use_case},
                        infrastructure/{transport,dnssec,transfer,state},
                        interface/{dns/{udp,tcp}, metrics}}
pulse-resolver/   src/{domain/{cache,dnssec,policy,iteration},
                        application/{port,use_case},
                        infrastructure/{upstream,cache,policy},
                        interface/{dns, metrics}}
pulse-api/        src/{domain/{job,token,scope,audit},
                        application/{port,use_case,error},
                        interface/http/{router,handlers,middleware,problem,openapi}}
pulsed/           src/{main,config,wiring/{contexts,api_adapters,signals}}
pulseresolved/    src/{main,config,wiring/{contexts,api_adapters,signals}}
```

Тесты: unit — рядом с кодом; `tests/` на крейт для интеграционных; общий `testkit`-крейт **не создаётся** (вне фиксированного списка) — in-memory реализации портов живут в `src/testkit.rs` под `feature = "testkit"` и подключаются как dev-dependency `path = "../pulse-zonefile", features = ["testkit"]`.

---

## 7. Cargo и сборка

```toml
[workspace]
resolver = "3"
members = ["crates/pulse-dns", "crates/pulse-runtime", "crates/pulse-zonefile",
           "crates/pulse-server", "crates/pulse-resolver", "crates/pulse-api",
           "bin/pulsed", "bin/pulseresolved"]

[workspace.package]
edition = "2024"
rust-version = "1.99"
license = "MIT OR Apache-2.0"

[workspace.dependencies]
pulse-dns = { path = "crates/pulse-dns", version = "0.1" }
# ... остальные по тому же шаблону
```

Правила:
- **Версии внешних зависимостей — только в `[workspace.dependencies]`**, в крейтах — `{ workspace = true }`. Единая версия `tokio`-подобных крейтов исключает конфликты фич.
- Библиотечные крейты: `publish = false` до стабилизации; версия `0.x`; semver ломается при изменении публичного API.
- `pulse-dns`/`pulse-runtime`: **без `unsafe`**, `#![forbid(unsafe_code)]`.
- `pulse-zonefile`/`pulse-runtime`: `unsafe` разрешён **только** в `infrastructure`/`reactor` с обязательным блоком `// SAFETY:` на каждый блок; `#![deny(clippy::undocumented_unsafe_blocks)]`. В `pulse-zonefile::domain` unsafe запрещён.
- Feature-флаги: `testkit` (in-memory адаптеры) — только для dev/test; `io-uring` (включается на Linux, выключается для CI на не-Linux); `metrics-prometheus`.
- Профили: `release` — `lto = "thin"`, `codegen-units = 1`; `bench` — отдельный профиль с `debug = true` для профайлеров.
- Бенчмарки: `criterion` в `benches/` у `pulse-dns` (codec), `pulse-zonefile` (exact lookup, enumerate, commit), `pulse-resolver` (cache hit path), `pulse-server` (end-to-end lookup-композиция). Критерии приёмки M1 — в спецификации формата/бенчмарка.

---

## 8. Проверки в CI (обязательные)

1. **`architecture_test`** (интеграционный тест в `pulsed/tests/` или `xtask`): парсит `Cargo.toml` и сверяет рёбра с таблицей §2/§3.1. Новое ребро без правки ADR → падение.
2. **`cargo tree -p pulse-dns --edges normal`** не содержит `pulse-*`.
3. **Слойный линт:** скрипт проверяет, что в `crates/*/src/domain/**` нет `use tokio`, `use hyper`, `use memmap2`, `use pulse_runtime`, `std::fs`, `std::net`, `SystemTime::now`.
4. **`cargo deny`** — лицензии, дубликаты версий, запрещённые крейты, advisory.
5. **`cargo clippy --workspace --all-targets -D warnings`**, **`cargo fmt --check`**, **`cargo test --workspace --all-features`**.
6. **`cargo semver-checks`** для библиотечных крейтов (в отдельных job'ах) — публичный API не ломается без решения.
7. **Контрактные тесты API:** `/api/v1/openapi.json` валиден и примеры из `docs/api/rest-v1.md` проходят проверку схемой (ручной реестр примеров в `pulse-api/tests/contract/`).

---

## 9. Как добавить зависимость или крейт

Чек-лист для автора PR:
1. Ребро есть в §2/§3.1? Если нет — ADR с обоснованием, затем правка таблицы.
2. Новый крейт? Согласование с пользователем (список фиксирован); минимум: ответственность, владелец данных, слои, рёбра.
3. Импорт внешнего крейта — в `[workspace.dependencies]`; проверить, не протекает ли его тип в `domain`.
4. Слойное размещение (`domain`/`application`/`infrastructure`/`interface`), тесты и порт-контракт на месте.
5. `architecture_test` и слойный линт проходят локально.

Рецепт разрыва цикла (если он всё же появился):
1. Найти минимальный тип, который нужен обеим сторонам.
2. Если это протокол — перенести в `pulse-dns` (только immutable value object).
3. Если это операция — объявить порт у потребителя и реализовать в composition root.
4. Если это данные — определить владельца и читать через порт владельца.
5. Записать решение в ADR; «временный» обход (`cfg(feature)`-хак, дублирование типа) запрещён.

---

## 10. Открытые вопросы

Решено Оркестратором: два бинарника без объединённого режима; серверное состояние (`TransferState`/`Peer`/ключи) — state-файл в state-dir; `SecretStore` v1 — файл 0600 в каталоге 0700; overrides и policy — собственные данные резолвера (без `pulse-zonefile`); IXFR — in-memory ринг; формат state-файла — JSON + `schema_version`, спецификация `docs/spec/server-state-v1.md` на M3; bootstrap-токены — отдельные env на процесс, хранилища токенов раздельные. Открытым остаётся:

1. **Общий `testkit`-крейт** — сейчас in-memory адаптеры живут фичами в крейтах; если фича-подход окажется неудобным, потребуется согласование нового dev-only крейта.
