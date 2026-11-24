# ADR 0001. DDD-архитектура pulse-dns: контексты, слои, зависимости

- **Статус:** принято (v1)
- **Дата:** 2026-11-23
- **Область:** весь монорепозиторий (все крейты, оба бинарника)
- **Связанные документы:** `docs/adr/0002-crate-map.md`, `docs/adr/0003-zonefile-format.md` (бинарный layout — другой архитектор), `docs/adr/0004-security-model.md`, `docs/spec/domain-model.md`, `docs/api/rest-v1.md`. ADR 0003/0004 действуют как обязательные требования (статус Proposed — формальная зрелость до M1)

---

## 1. Контекст

pulse-dns — модульный асинхронный DNS-сервер (authoritative + recursive) с REST-управлением.
Требования, определившие решение:

1. **Высокая пропускная способность и отсутствие блокировок на hot-path.** DNS-ответ должен собираться без syscall'ов и без взятия мьютексов; источник зон — mmap-файл, читаемый конкурентно.
2. **Инкрементальные правки зон** в том же mmap-файле, crash-safe, при одновременных читателях.
3. **Чистое ядро.** Логика DNS (сериализация RRset, RFC 1982, CNAME-правила, DNSSEC-подписи) должна тестироваться без сети и диска и не зависеть от io_uring/epoll/HTTP.
4. **Полное управление через REST**, включая репликацию, DNSSEC-ключи и кеш резолвера.
5. **Фиксированный набор крейтов** (`pulse-zonefile`, `pulse-dns`, `pulse-runtime`, `pulse-server`, `pulse-resolver`, `pulse-api`); добавлять крейты без согласования нельзя.

Из (1)–(3) следует вывод: **домен синхронный и чистый, асинхронность и I/O живут только в адаптерах**, а границы контекстов должны быть проведены так, чтобы authoritative-сервер, рекурсивный резолвер и REST-API не зависели друг от друга напрямую.

---

## 2. Решение

### 2.1. Bounded contexts

Система делится на шесть ограниченных контекстов. Каждый контекст имеет собственный ubiquitous language, собственную модель и **единственного владельца данных**.

| Контекст | Ответственность | Крейт-носитель | Ключевые понятия (ubiquitous language) |
|---|---|---|---|
| **Zone Store** | Система записи зон: бинарный формат, mmap-файл, снапшоты, транзакционные инкрементальные правки, crash-safety, сериализация зон, жизненный цикл зон (create/delete, tombstone) | `pulse-zonefile` | `Zone`, `ZoneId`, `ZoneState`, `ZoneSettings`, `Origin`, `Rrset`, `Record`, `Serial`, `Ttl`, `ZoneSnapshot`, `Edit`, `WriteIntent`, `CommitOutcome` |
| **Authoritative Serving** | Отдача авторитетных ответов по UDP/TCP, wildcard/CNAME/DNAME-семантика, зона-кат, NXDOMAIN/NODATA, EDNS0, TSIG, DNSSEC-подпись на выдаче, AXFR/IXFR-out, NOTIFY-out | `pulse-server` | `Question`, `Answer`, `Authority`, `ZoneCut`, `TransferState`, `Notify`, `AclRule` |
| **Recursive Resolution** | Рекурсивный резолвер: итерация от корня, кеш, отрицательное кеширование, DNSSEC-валидация, ECS-политика | `pulse-resolver` | `CacheEntry`, `Upstream`, `ValidationState`, `Delegation`, `CacheKey` |
| **Policy / Filtering** | ad-block, локальные overrides, правила блокировки/переписывания, счётчики срабатываний | `pulse-resolver` (модуль `policy`) | `PolicyRule`, `Blocklist`, `Override`, `Action`, `Decision` |
| **Replication** | Secondary-сторона: приём NOTIFY, планирование и выполнение AXFR/IXFR-in, применение трансфера, состояние и таймеры SOA, peers | `pulse-server` (модуль `transfer`) | `TransferState`, `Notify`, `Peer`, `TransferMode`, `RefreshTimer` |
| **Control API** | REST-поверхность управления: CRUD зон и RRset, ключи, кеш, политики, настройки, метрики, jobs, аутентификация и авторизация | `pulse-api` | `Principal`, `Scope`, `Role`, `Job`, `ZoneDescriptor`, `RrsetDocument` |

Дополнительно существует **Shared Kernel** — `pulse-dns`. Это не контекст, а опубликованный язык протокола (published language): `Name`, `Rdata`, `Record`, `Rrset`, `Ttl`, `Serial`, wire-codec, EDNS0, TSIG-примитивы, DNSSEC-примитивы. Жёсткое правило: `pulse-dns` — чистый синхронный код без I/O, без async, без зависимости от других крейтов workspace (см. §4.1 и ADR 0002).

> **Почему `Zone`, `Rrset`, `Serial` оказались в shared kernel, а не в `pulse-zonefile`.**
> Резолверу нужны `Record`/`Rrset`/`Serial`/`Name`/`Rdata` для кеша и валидации, но он не должен тянуть mmap-формат (`pulse-zonefile`). Поэтому протокольные value objects (то, что определено RFC, а не нашим хранилищем) живут в `pulse-dns`. Понятия, специфичные для *системы записи* (`Zone`, `ZoneId`, `ZoneSnapshot`, `Edit`, транзакции), живут в `pulse-zonefile::domain`.

### 2.2. Контекстная карта

```
                    ┌──────────────────────────────────────────────┐
                    │        Control API (pulse-api)               │
                    │  driving adapter: HTTP/REST, jobs, authN/Z   │
                    └───────┬───────────────────────┬──────────────┘
        required ports      │                       │   required ports
   (ZoneAdmin, RrsetAdmin,  │                       │  (CacheAdmin, PolicyAdmin)
    DnssecAdmin, TransferAdmin,                     │
    SettingsAdmin, MetricsSource, JobQueue)         │
                            ▼                       ▼
    ┌───────────────────────────────┐   ┌───────────────────────────────┐
    │ Authoritative Serving         │   │ Recursive Resolution + Policy │
    │ (pulse-server)                │   │ (pulse-resolver)              │
    │                               │   │                               │
    │  ┌─────────────────────────┐  │   │  ┌─────────────────────────┐  │
    │  │ Replication (transfer)  │  │   │  │ Policy / Filtering      │  │
    │  └─────────────────────────┘  │   │  └─────────────────────────┘  │
    └───────┬───────────────┬───────┘   └────────────┬──────────────────┘
            │ ZoneStore /   │ UpstreamClient (AXFR/  │ UpstreamClient
            │ ZoneWriter    │ IXFR-in, NOTIFY-out)   │ (итерации)
            ▼               ▼                        ▼
    ┌───────────────────────────────┐        ┌──────────────────────┐
    │ Zone Store (pulse-zonefile)   │        │  Network / async     │
    │ mmap + snapshots + txn        │        │  I/O (pulse-runtime) │
    └───────────────────────────────┘        └──────────────────────┘
                        ▲
                        │ shared kernel (published language, без I/O)
                        └──────────── pulse-dns ───────────────────────
```

Отношения по DDD-таксономии:

| Отношение | Описание | Правило |
|---|---|---|
| Zone Store → Authoritative Serving | **Customer/Supplier** (Zone Store — поставщик, authoritative — клиент) | Authoritative читает только через `ZoneStore`-порт; Zone Store не знает о DNS-ответах |
| Authoritative Serving ↔ Replication | **Partnership** (оба в `pulse-server`, один релизный цикл) | Внутренние интерфейсы модулей, но с явными портами на границе модуля |
| Recursive Resolution ↔ Policy/Filtering | **Partnership** (оба в `pulse-resolver`) | Policy вызывается как доменный сервис/порт из resolve-use-case, не наоборот |
| Control API → все | **Customer/Supplier через dependency inversion** | API объявляет *свои требуемые порты*; реализует их composition root, а не API-крейт (см. ADR 0002 §4) |
| `pulse-dns` → все | **Shared Kernel / Published Language** | Изменения только по RFC, с обязательным прохождением всех потребителей (semver minor в рамках 0.x) |
| Внешние DNS-серверы, HTTP-клиенты | **Anti-Corruption Layer** | Трансляция wire ↔ domain внутри `infrastructure`; домен не видит байтов |

**Запрет:** контексты не разделяют изменяемое состояние. Единственные разделяемые типы — value objects из `pulse-dns` (immutable) и `Arc<ZoneSnapshot>` (immutable по контракту).

### 2.3. Процессная топология (v1)

**Решение: два независимых процесса, объединённый режим «всё в одном» — вне scope v1.**

| Процесс | Контексты | Состояние, которым владеет |
|---|---|---|
| `pulsed` | Zone Store, Authoritative Serving, Replication, Control API (профиль authoritative) | зонный mmap-файл, `TransferState`/`Peer`/ключи в state-файле (state-dir), токены/jobs/аудит API |
| `pulseresolved` | Recursive Resolution, Policy/Filtering, Control API (профиль resolver) | кеш (память), policy-правила/blocklist'ы, токены/jobs/аудит API |

Следствия:
- Общий код (`pulse-dns`, `pulse-runtime`, `pulse-api`) не означает общего состояния: у каждого процесса свой экземпляр API, свой jobs-реестр, свой аудит и **свои `/metrics`**. Кросс-процессной агрегации метрик в v1 нет; сборщик опрашивает оба эндпоинта.
- У резолвера **нет** `ZoneStore`, у authoritative **нет** кеша резолвера. Взаимодействие — только по сети (DNS-протокол; управляющие вызовы — HTTPS+mTLS).
- При необходимости authoritative может использовать резолвер как upstream через порт `UpstreamClient`; реализация — адаптер в `pulsed`, а не ребро крейтов (см. §4.2).
- **Bootstrap admin-токена:** при первом старте, если в state пусто, токен берётся из env `PULSED_BOOTSTRAP_TOKEN` (одноразовый, обязательная ротация после создания постоянного; при непустом хранилище env игнорируется с warning). Детали — `docs/api/rest-v1.md` §2.6.

---

## 3. Слои внутри крейта

Каждый крейт-контекст (кроме `pulse-dns` и `pulse-runtime`) имеет одинаковую структуру модулей. Исключение — `pulse-api`: у него **нет** `infrastructure`, потому что его driven-адаптеры (реализации required ports) живут в composition root (`pulsed`/`pulseresolved`), см. ADR 0002 §4:

```
pulse-<crate>/src/
├── domain/            # сущности, value objects, инварианты, доменные сервисы, доменные ошибки
│   ├── mod.rs
│   ├── entity/
│   ├── value/
│   ├── service/       # чистая логика, требующая нескольких сущностей
│   └── error.rs       # thiserror, без I/O-ошибок
├── application/       # use cases + порты (traits) + команды/результаты
│   ├── port/          # driven ports (ZoneStore, Clock, Metrics, ...)
│   ├── use_case/      # оркестрация: читает порты, вызывает домен, пишет через порты
│   ├── command.rs     # входные DTO application-слоя
│   └── error.rs       # ApplicationError: Domain | Port | Conflict | NotFound | ...
├── infrastructure/    # адаптеры driven ports (mmap, tokio/io_uring, reqwest, fs)
│   └── ...
└── interface/         # driving adapters (UDP/TCP listener, HTTP router) — если применимо
```

### 3.1. Правило зависимостей (The Dependency Rule)

Направление зависимостей — **только внутрь**:

```
interface ──▶ application ──▶ domain
                  ▲
infrastructure ───┘   (infrastructure зависит от application+domain,
                       application НЕ знает про infrastructure)
```

Конкретно:

| Слой | Может зависеть от | НЕ может зависеть от |
|---|---|---|
| `domain` | `core`, `alloc`, `std` (только `String`, `Vec`, `HashMap`, `Duration`, `SystemTime`-типы как значения, **не** `SystemTime::now()`), `thiserror` | `tokio`, `async-trait`, `std::fs`, `std::net`, `memmap2`, `io-uring`, `hyper`/`axum`, `serde_json`, `tracing`-спаны с I/O |
| `application` | `domain`, `pulse-dns`, async-рантайм-агностичные `Future`/`Stream`, `async-trait`, `thiserror` | конкретные адаптеры (`tokio::net`, `memmap2`), HTTP-типы, формат файла |
| `infrastructure` | `application`, `domain`, любые внешние крейты | `interface` |
| `interface` | `application`, `domain`, DTO своего протокола | `infrastructure` напрямую (только через порты/фабрики) |

Дополнительные запреты:

- **Домен не логирует через `tracing`.** Диагностика домена — возврат типизированных ошибок; логирует application/interface.
- **Домен не измеряет время сам.** Время приходит через `Clock`-порт в application или как аргумент доменного сервиса.
- **Домен не сериализуется.** Никаких `#[derive(Serialize)]` на доменных типах: представление — забота interface-слоя (ACL).
- **Ошибки не склеиваются в `anyhow::Error` внутри библиотечных крейтов.** `anyhow` допустим только в бинарниках (`pulsed`, `pulseresolved`) и тестах.

### 3.2. Почему домен синхронный, а async — в адаптерах

1. **Домен не делает I/O**, значит ему нечего ждать: ни `await`, ни `Pin<Box<dyn Future>>`.
2. **Синхронный домен тестируется мгновенно и детерминированно** — без `tokio::test`, без таймеров, без `#[should_panic]` на гонках.
3. **Отсутствие `Send + Sync`-требований** на доменных типах упрощает их (нет `Arc<Mutex<...>>` внутри сущностей).
4. **Асинхронность — деталь транспорта.** Один и тот же use case должен работать под tokio, под io_uring-рантаймом и в тесте с in-memory адаптером. Если `async` протекает в домен, смена рантайма становится рефакторингом домена.

Практическое следствие: доменные сервисы возвращают значения и ошибки, а «ожидание» появляется только в `application::use_case` при обращении к порту.

```rust
// domain: синхронно, чисто
impl Zone {
    pub fn plan_insert(&self, rrset: Rrset) -> Result<Edit, DomainError> { /* ... */ }
}

// application: async, оркестрация записи
pub async fn upsert_rrset(
    store: &dyn ZoneStore,
    writer: &mut dyn ZoneWriter,
    clock: &dyn Clock,
    metrics: &dyn Metrics,
    cmd: UpsertRrset,
) -> Result<CommitOutcome, ApplicationError> {
    let snap = store.snapshot();
    let meta = store.zone_meta(&snap, &cmd.origin).ok_or(ApplicationError::NotFound)?;
    // ≤ 64 точечных чтений: owner, предки, apex (SOA/NS), признак zone cut
    let facts = collect_zone_facts(store, &snap, &meta, &cmd.owner)?;
    let edit = plan_rrset_change(&facts, cmd.into_request(clock.now()))?;   // чистый домен
    writer.apply(meta.id(), WriteIntent::Transaction, edit)?;   // неявная транзакция
    let result = writer.commit(meta.id(), CommitPolicy::Commit(Durability::Sync))?;
    let outcome = match result { CommitResult::Committed(o) => o, CommitResult::Aborted => unreachable!() };
    metrics.counter("zone_writes_total", &[("zone", meta.origin().as_str())], 1);
    Ok(outcome)
}
```

### 3.3. Порты: где объявляются и как типизируются

- **Driven ports** (нужен домену/приложению: хранилище, время, метрики, сеть) объявляются в `application::port` **того крейта, который их потребляет**.
- Порт — это `trait`, а не структура. Реализация — в `infrastructure` того же крейта **или** в composition root (бинарнике), если она склеивает контексты.
- Асинхронные порты объявляются через `#[async_trait]`, чтобы trait оставался object-safe (`&dyn ZoneStore`, `Arc<dyn UpstreamClient>`) и не требовал generic-параметров по всему application-слою. Допустимая альтернатива для горячих путей — enum-dispatch, но только по согласованию: это меняет сигнатуры use case.
- Потоковые порты (трансферы, перечисление зон) используют **callbacks/`mpsc`-каналы с backpressure**, а не `Box<dyn Stream>` там, где нужен синхронный домен (см. `ZoneStore::enumerate` в `docs/spec/domain-model.md`).
- **Каждый порт имеет документированный контракт**: гарантии, ошибки, требования к конкурентности, поведение при отмене. Незадокументированный порт не считается готовым.

### 3.4. Как application оркестрирует порты

Единый паттерн use case:

1. **Прочитать снапшот** через порт чтения (O(1), без блокировок).
2. **Провалидировать/спланировать изменение** чистым доменным кодом (никакого I/O).
3. **Начать транзакцию** через write-порт (один писатель).
4. **Применить и зафиксировать** (durability — на совести адаптера, но семантика зафиксирована в порте).
5. **Опубликовать результат** (новый снапшот/серийный номер) и обновить метрики.
6. **Вернуть** результат или типизированную ошибку.

Оркестрация не содержит DNS-логики: любые правила (CNAME-эксклюзивность, RFC 1982, зона-кат) живут в `domain`. Если в use case появился `if qtype == CNAME`, это ошибка размещения.

Транзакционность: application-слой владеет **границей транзакции**, домен — её содержимым. Откат — `CommitPolicy::Abort`, повтор — идемпотентное применение `Edit` (каждый `Edit` имеет `EditId` для дедупликации при ретраях). Полные определения `WriteIntent`/`Edit`/`EditOp`/`ApplyOutcome`/`CommitOutcome`/`CommitPolicy`, жизненного цикла зоны (`create_zone`/`delete_zone`, tombstone) и meta-блока настроек — `docs/spec/domain-model.md` §5.2.1–5.2.6.

Отмена: `Future` может быть дропнут в любой момент. Правило — **отмена безопасна только до `commit`**; после начала `commit` операция доводится до конца (commit неотменяем, короткий и детерминированный). Долгие операции (импорт, AXFR) оформляются как job в application-слое с явными точками отмены, а не как «долгий await».

---

## 4. Граф зависимостей крейтов

### 4.1. DAG

```
L0   pulse-dns        (shared kernel: wire, RR-типы, EDNS0, TSIG, DNSSEC-примитивы)
L0   pulse-runtime    (async/io_uring/epoll I/O primitives; без DNS-знаний)
L1   pulse-zonefile   -> pulse-dns
L2   pulse-server     -> pulse-dns, pulse-zonefile, pulse-runtime
L2   pulse-resolver   -> pulse-dns, pulse-runtime
L3   pulse-api        -> pulse-dns                      (только value objects для DTO)
L4   pulsed           -> pulse-server, pulse-zonefile, pulse-api, pulse-runtime, pulse-dns
L4   pulseresolved    -> pulse-resolver, pulse-api, pulse-runtime, pulse-dns
```

Ребро `A -> B` означает «A зависит от B». Граф ациклический. Полная таблица ответственности и запретов — в `docs/adr/0002-crate-map.md`.

### 4.2. Правила, удерживающие DAG

1. **`pulse-dns` и `pulse-runtime` — листья.** Ни один из них не зависит от других крейтов workspace. Проверяется в CI (`cargo tree --package pulse-dns --edges normal` не должен содержать `pulse-*`).
2. **`pulse-api` не зависит от `pulse-server`/`pulse-resolver`.** Управление идёт через порты, объявленные в `pulse-api::application::port`, реализованные в composition root.
3. **`pulse-server` и `pulse-resolver` не зависят друг от друга.** Если authoritative нужен резолвер (например, для `CNAME`-цепочки в forward-зоне или для upstream-проверок), это делается через порт `UpstreamClient`, реализованный в бинарнике над `pulse-resolver`.
4. **`pulse-zonefile` не знает про DNS-ответы.** Он предоставляет `ZoneStore`/`ZoneWriter`; интерпретация записей — в `pulse-server`.
5. **Бинарники — единственное место, где разрешены «все обо всех».** В них нет доменной логики: только конфигурация, wiring, сигналы, lifecycle.
6. **Циклы запрещены на уровне Cargo.** Обходной «цикл через trait в общем крейте» допустим только если trait объявлен в крейте-*потребителе* (dependency inversion), а не в новом общем крейте.

### 4.3. Проверка в CI

- `cargo deny`/`cargo tree` — отсутствие циклов и запрещённых рёбер (список разрешённых зависимостей фиксируется в `xtask`-проверке).
- `cargo modules`/`grep`-линт: `use tokio` внутри `domain/` → ошибка сборки (через `#![deny]`-обёртку в `domain/mod.rs` не выйдет — используется custom линт-скрипт или feature-флаг `domain-isolation`).
- Тест `architecture_test`: парсит `Cargo.toml` воркспейса и сверяет рёбра с таблицей из ADR 0002.

---

## 5. Правила тестирования

### 5.1. Пирамида и владение

| Уровень | Что проверяет | Где живёт | Требования к окружению |
|---|---|---|---|
| Доменные unit-тесты | Инварианты, RFC 1982, CNAME/DNAME/wildcard, кодеки, DNSSEC-математика | `src/domain/**` рядом с кодом, `#[cfg(test)]` | **Ноль I/O, ноль async, ноль сети, ноль диска, ноль времени** |
| Property-тесты | Инварианты на случайных данных (сериализация round-trip, serial-порядок) | `tests/proptest/` | `proptest` с фиксированным seed в CI |
| Application-тесты | Use cases на in-memory адаптерах | `tests/application/` | Асинхронный executor — `tokio` **только как dev-dependency**; без сокетов |
| Infrastructure-тесты | mmap-файл, crash-recovery, TCP/UDP framing, HTTP-роутер | `tests/integration/` | `tempfile`, loopback-сокеты, `#[ignore]` для тяжёлых |
| E2E | Бинарник + реальные пакеты | `tests/e2e/` | Отдельный job в CI |

### 5.2. Обязательные правила

1. **Домен тестируется без сети и диска.** Каждый порт имеет in-memory реализацию в `testkit`-модуле (`#[cfg(any(test, feature = "testkit"))]`): `InMemoryZoneStore`, `FixedClock`, `NoopMetrics`, `StaticUpstream`, `AllowAllAuthorizer`.
2. **Время только через `FixedClock`.** Тесты не вызывают `SystemTime::now()`; иначе они недетерминированы (TTL-экспирация, DNSSEC-validity, refresh-таймеры).
3. **Никаких `sleep` в тестах домена/application.** Ожидание событий — через `tokio::sync::Notify`/каналы, а не по таймеру. `sleep` допустим только в infrastructure-тестах с реальными таймаутами сокетов.
4. **Инварианты проверяются на границе.** Любой конструктор сущности либо возвращает `Result`, либо доказуемо валиден (private fields + validating constructors). Тесты обязаны проверять *отказ*, а не только успех.
5. **Concurrency-тесты Zone Store обязательны:** N читателей + 1 писатель, читатель держит снапшот во время `commit` — не должно быть UB/падений, чтение обязано видеть либо старую, либо новую версию целиком (никаких «полуобновлённых» зон). Используется `loom` или стресс-тест с `--release`. Thread sanitizer / Miri требуют nightly-toolchain и запускаются в отдельном **необязательном** CI-job; production-сборка — только stable 1.99.1.
6. **Golden-тесты wire-формата** для `pulse-dns`: зафиксированные байтовые дампы пакетов (включая сжатие имён, EDNS0, TSIG) в `tests/golden/*.bin` с человекочитаемым `.txt`-описанием.
7. **Запрещены тесты, зависящие от публичной сети.** Внешние DNS-серверы эмулируются в процессе (fake UDP/TCP-сервер на loopback).

---

## 6. Последствия

### Положительные
- Hot-path чтения зоны не касается async и не берёт блокировок: снапшот — `Arc`, чтение — обход неизменяемых структур.
- Домен тестируется за миллисекунды, покрытие инвариантов достижимо.
- `pulse-api` можно разрабатывать параллельно: контракт — порты, а не крейты сервера.
- Смена I/O-движка (io_uring ↔ epoll) не затрагивает домен и application (кроме выбора реализации `pulse-runtime`).

### Отрицательные / цена
- Дублирование DTO: доменные типы ≠ API-типы (это осознанно — граница контекста; маппинг в composition root).
- `#[async_trait]` даёт аллокацию на вызов порта; для hot-path (кеш-промах, lookup) выбираются синхронные порты (`ZoneStore`) — там аллокации нет.
- Требуется дисциплина: соблазн «просто вызвать `tokio::fs` из use case» нужно ловить линтом и ревью.
- Composition root (`pulsed`) становится точкой связанности — растёт при добавлении адаптеров; компенсируется модульностью wiring по контекстам.

### Рассмотренные альтернативы

| Альтернатива | Почему отклонена |
|---|---|
| Один крейт с модулями | Невозможно проверить направление зависимостей; домен протекает в I/O; время сборки растёт |
| Async-домен (`async fn` в сущностях) | Нетестируем без рантайма, `Send`-шум, рантайм протекает в модель |
| `pulse-api` зависит от `pulse-server`/`pulse-resolver` напрямую | Появляется ребро API→домены, дублирование прав доступа, невозможно поднять API без сервера/резолвера и наоборот |
| Общий крейт `pulse-core` для «всего общего» | Превращается в свалку и создаёт циклы; shared kernel ограничен протоколом (`pulse-dns`) |
| Порт-трейты в отдельном крейте контрактов | Новый крейт вне фиксированного списка; в v1 порты объявляются потребителем |

---

## 7. Открытые вопросы

Решено Оркестратором (см. §2.3 и ADR 0002): два процесса без объединённого режима; `TransferState`/`Peer`/ключи — state-файл сервера (JSON + `schema_version`, спецификация `docs/spec/server-state-v1.md` на M3); `SecretStore` v1 — файл 0600 в каталоге 0700; IXFR — in-memory ринг; NSEC/NSEC3 — подпись обоих механизмов (NSEC3: SHA-1, Opt-Out = 0; обновлено после реализации); bootstrap-токены и хранилища токенов — раздельные на процесс. Остаются:

1. **Мультиарендность:** нужны ли изолированные namespace'ы зон (арендаторы) в v1? Сейчас модель — единый владелец; при добавлении потребуется `TenantId` в `ZoneId` и в токенах.
2. **Политика версионирования shared kernel** при 0.x: считается ли удаление варианта `Rdata` breaking (предлагается — да, minor bump + миграция формата).
