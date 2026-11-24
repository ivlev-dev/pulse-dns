# Спецификация доменной модели pulse-dns

- **Версия:** 1.0 (v1)
- **Область:** доменный слой всех контекстов; контракты портов (driven ports)
- **Статус:** обязательно к исполнению; изменения — через ADR
- **Связанные документы:** `docs/adr/0001-ddd-architecture.md`, `docs/adr/0002-crate-map.md`, `docs/adr/0003-zonefile-format.md`, `docs/adr/0004-security-model.md`, `docs/api/rest-v1.md`
- **Вне области:** бинарный layout зонного файла (ADR 0003), дизайн io_uring (отдельный документ), wire-codec детали (см. RFC 1035/2308/4034/6891/8945)

Соглашения:
- Идентификаторы кода — английские; текст — русский.
- Все типы домена **immutable после конструирования**, не реализуют `Serialize`/`Deserialize`, не содержат `Arc<Mutex<…>>`, не делают I/O.
- Время в домен приходит как значение (`Timestamp`, `Mono`), никогда не читается из системы.
- Денежные/бинарные единицы: октеты, секунды (u32), TTL (u32, 31 бит значимый).

---

## 1. Инвентарь типов и их размещение

| Тип | Вид | Крейт / модуль | Контекст-владелец |
|---|---|---|---|
| `Name` | VO | `pulse-dns::domain::name` | Shared kernel |
| `Rdata` | VO (enum) | `pulse-dns::domain::rdata` | Shared kernel |
| `RrType`, `Class`, `Rcode`, `Opcode` | VO (newtype + enum) | `pulse-dns::domain::rr` | Shared kernel |
| `Record` | VO (полная запись) | `pulse-dns::domain::record` | Shared kernel |
| `Rrset` | сущность (immutable value-entity) | `pulse-dns::domain::rrset` | Shared kernel |
| `Ttl` | VO | `pulse-dns::domain::ttl` | Shared kernel |
| `Serial` | VO | `pulse-dns::domain::serial` | Shared kernel |
| `Timestamp`, `Mono`, `Duration` | VO | `pulse-dns::domain::time` | Shared kernel |
| `ZoneId` | VO | `pulse-zonefile::domain::zone` | Zone Store |
| `Origin` | VO (валидированный `Name`) | `pulse-zonefile::domain::zone` | Zone Store |
| `Zone`, `ZoneKind` | aggregate root / enum | `pulse-zonefile::domain::zone` | Zone Store |
| `ZoneMeta` | VO | `pulse-zonefile::domain::zone` | Zone Store |
| `Epoch`, `ZoneVersion`, `SnapshotId` | VO (newtype `u64`) | `pulse-zonefile::domain::zone` | Zone Store |
| `ZoneSnapshot` | immutable view (opaque) | `pulse-zonefile::domain::snapshot` | Zone Store |
| `Edit`, `EditId`, `EditOp`, `WriteIntent`, `ApplyOutcome`, `ApplyCounts`, `Normalization`, `EditWarning`, `CommitOutcome` | VO / команды | `pulse-zonefile::domain::edit` | Zone Store |
| `Question`, `Query` | VO | `pulse-dns::domain::question` | Shared kernel |
| `LookupResult`, `Answer`, `ZoneCut` | VO | `pulse-server::domain::resolve` | Authoritative Serving |
| `TransferState`, `TransferMode` | VO (enum + state) | `pulse-server::domain::transfer` | Replication |
| `Notify` | сущность | `pulse-server::domain::transfer` | Replication |
| `Peer` | сущность | `pulse-server::domain::transfer` | Replication |
| `AclRule` | VO | `pulse-server::domain::acl` | Authoritative Serving |
| `CacheEntry`, `CacheKey` | сущность / VO | `pulse-resolver::domain::cache` | Recursive Resolution |
| `ValidationState` | VO (enum) | `pulse-resolver::domain::dnssec` | Recursive Resolution |
| `PolicyRule`, `Blocklist`, `Override` | сущность / VO | `pulse-resolver::domain::policy` | Policy / Filtering |
| `Key`, `KeyId`, `KeyRole`, `KeyState` | сущность / VO | `pulse-server::domain::dnssec` | Authoritative Serving |
| `SecretRef` | VO | `pulse-server::domain::dnssec` (импортируемый API) | Authoritative Serving |

> `Zone` и `ZoneId` живут в `pulse-zonefile`, потому что Zone Store — **система записи** зон. `Rrset`/`Record`/`Serial`/`Ttl` живут в `pulse-dns`, потому что они определены протоколом и нужны резолверу без mmap-зависимости. Это осознанное разграничение: shared kernel содержит только то, что описано в RFC, и ничего про хранение. `Timestamp`/`Mono` — тоже протокольно-нейтральные VO в shared kernel, чтобы все контексты использовали один тип времени вместо `SystemTime`.

Мелкие newtype'ы, не требующие отдельной спецификации: `PeerAddr` (адрес peer'а с опциональным портом), `KeyName` (TSIG/DNSSEC-имя ключа), `TsigKeyRef`, `CommitId`, `Txn`, `EditId`, `PolicyId`, `KeyId`, `PrincipalId`, `Role`, `ScopeSet`, `ResourceRef`, `ChangeKind`, а также `Denial` (`Nsec | Nsec3`), `SoaTimers`, `UpstreamSpec`, `RrsetChange`, `BufferTooSmall`. Каждый — обёртка/enum с валидирующим конструктором и без `Deref` в «сырой» тип.


---

## 2. Value objects и сущности

### 2.1. `Name`

```rust
pub struct Name { /* private */ }
```

- Хранит **каноническую форму**: ASCII, lower-case, метки без точек внутри, абсолютное имя с завершающей точкой в презентации.
- Инварианты: суммарная длина wire-формы ≤ 255 октетов; каждая метка 1..=63 октетов; пустая метка допустима только как терминатор (корень — `Name::root()`).
- Не хранит указатели на сжатие. Сжатие — деталь wire-codec, разворачивается при разборе. Wire-парсер (`pulse-dns::wire`) **отвергает** compression pointer, указывающий в заголовок сообщения или в **середину метки** (RFC 1035 §4.1.4: указатель обязан указывать на начало метки), а также вперёд и по циклу; домен сжатие не моделирует — `Name` всегда развёрнутая каноническая форма.
- **Эхо 0x20 (SEC-DNS-011, M3).** `Name` канонически lower-case, поэтому исходный регистр QNAME не восстановим. Сервер (`pulse-server`) обязан сохранять **сырые байты QNAME** запроса рядом с разобранным `Name` и копировать их в question-секцию ответа байт-в-байт; сравнение имён остаётся case-insensitive. Тип `Name` не меняется: хранение сырого QNAME — обязанность транспорта/сборки ответа, не домена.
- API: `labels()`, `is_subdomain_of(&Origin)`, `parent()`, `to_wire_uncompressed()`, `Display` (каноническая презентация), `cmp_canonical()` (RFC 4034 §6.1 — для DNSSEC-сортировки), `Hash` (по канонической форме).
- `Name::parse(&str)` — единственный вход извне; ошибки `NameError::{TooLong, LabelTooLong, BadCharacter, EmptyLabel}`.
- **Не реализует `Ord`** (лексикографический `Ord` не равен каноническому DNSSEC-порядку и провоцирует ошибки). Только `cmp_canonical`.

### 2.2. `Origin`

```rust
pub struct Origin(Name); // гарантирует: absolute, не root (v1), канонизировано
```
- `Origin::new(name)` валидирует; `Zone::origin()` возвращает `&Origin`.
- Владелец любой записи зоны обязан быть `is_subdomain_of(origin)`, включая apex (равенство).

### 2.3. `Rdata`

```rust
pub enum Rdata {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Ns(Name),
    Cname(Name),
    Soa(SoaData),
    Ptr(Name),
    Mx { preference: u16, exchange: Name },
    Txt(TxtData),                    // segments: Vec<Vec<u8>>, каждый 0..=255 (пустая строка легальна)
    Srv { priority: u16, weight: u16, port: u16, target: Name },
    Caa { flags: u8, tag: CaaTag, value: Vec<u8> },
    Dname(Name),
    Ds(DsData),
    Dnskey(DnskeyData),
    Rrsig(RrsigData),
    Nsec(NsecData),
    Nsec3(Nsec3Data),
    Nsec3Param(Nsec3ParamData),
    Tlsa(TlsaData),
    Svcb(SvcbData),
    Https(SvcbData),
    Unknown { rr_type: RrType, rdata: Vec<u8> }, // RFC 3597, непрозрачно
}
```
- `SoaData { mname: Name, rname: Name, serial: Serial, refresh: u32, retry: u32, expire: u32, minimum: u32 }` — таймеры **полные `u32`**, не `Ttl` (§2.3.1).
- Все `Name` внутри `Rdata` — канонические абсолютные.
- `Unknown` используется для типов, которые сервер не интерпретирует; пересылается байт-в-байт (RFC 3597). В зоне `Unknown` не участвует в семантических правилах, кроме CNAME-эксклюзивности.
- `Rdata::rr_type()` — детерминированное отображение варианта в `RrType`.
- Equality/Hash — по канонической байтовой форме (важно для дедупликации в `Rrset`).

#### 2.3.1. Wire-точность отдельных RDATA

- **TXT (`TxtData`).** `TxtData { segments: Vec<Vec<u8>> }`, `1..=N` сегментов; каждый — character-string `0..=255` октетов, **пустая строка (длина 0) легальна** (RFC 1035 §3.3.14). Суммарная длина RDATA `Σ(1 + len) ≤ 65535`. `TxtData::new([b""])` — валидная запись с одной пустой строкой; `RDLENGTH = 0` (ноль сегментов) — `BadRdata`/`FormErr`, а не «пустой TXT». `""`, `[""]` и `["", ""]` — разные байтовые формы (дедупликация — по форме).
- **SOA-таймеры (`SoaData`).** `refresh/retry/expire/minimum` — полные `u32` (RFC 1035 §3.3.13), **без clamp и без маскирования**. Проверки домена: `refresh ≥ 1`, `retry ≥ 1`, `expire > refresh + retry` (сложение в `u64`, чтобы `0xFFFF_FFFF` не переполнял). `Ttl` применяется **только** к TTL самой RR (`Record.ttl`/`Rrset.ttl`), не к таймерам. `SoaTimers { refresh: u32, retry: u32, expire: u32, minimum: u32 }` — те же поля/валидация для настроек зоны (§5.2.5); тип не наследует `Ttl`.
- **CAA (`CaaTag`).** `tag` — opaque-байты `1..=255` (RFC 8659 §4.1), регистр **сохраняется** в wire, файле и `Hash`. Сравнение тегов case-insensitive — отдельная семантика (`CaaTag::eq_ignore_ascii_case`), используется для проверок вида «два `issue` с разным регистром в одном RRset — семантический конфликт»; нормализации при разборе и сериализации нет. Пустой тег или > 255 октетов → `BadRdata`.
- **NSEC / NSEC3.** `NsecData.type_bitmap` **непуст** (RFC 4034 §4.1.2; для authoritative-данных как минимум `NSEC` и `RRSIG`, это проверяет домен при подписи). `Nsec3Data.type_bitmap` **может быть пустым** — empty non-terminal (RFC 5155 §8.5); пустой NSEC3-bitmap — валидная запись, не `BadRdata`.
- **RRSIG (`RrsigData.original_ttl`).** Поле — полный `u32` («signed data»): **не clamp’ится и не нормализуется**, даже при значении `> 2^31−1`, иначе подпись перестанет проверяться. Clamp применяется только к TTL RRset (`Ttl`) при приёме; при переподписи `original_ttl` берётся из TTL подписываемого набора (уже `≤ 2^31−1`).

### 2.4. `Record`

```rust
pub struct Record { owner: Name, rr_type: RrType, class: Class, ttl: Ttl, rdata: Rdata }
```
- Используется в трансферах, API и как единица потоковой передачи. В хранилище канонический вид — `Rrset`.
- `Record::validate()` проверяет согласованность: `rdata.rr_type() == rr_type`, `class == Class::IN` (v1).

### 2.5. `Rrset`

```rust
pub struct Rrset {
    owner: Name,
    rr_type: RrType,
    class: Class,
    ttl: Ttl,
    rdata: BTreeSet<Rdata>,   // отсортировано по канонической форме, дедуплицировано
}
```
- Агрегат атомарности: **любое изменение набора записей одного owner/type — одна транзакция**.
- TTL один на весь набор (RFC 2181 §5.2). Политика конфликта зафиксирована:
  - **`WriteIntent::Transaction`** (API/динамические записи; `Rrset::new`, `merge`) — разный TTL у записей одного набора → `InvariantViolation(INV-1)` / `422 ttl-mismatch`, без молчаливого `min` (оператор не должен терять ошибку);
  - **`WriteIntent::Import` / `Replication`** (zone-файл, AXFR/IXFR-in) — парсер группирует записи по `(owner, type, class)`; при разных TTL берётся `min` (RFC 2181 §5.2), факт фиксируется warning'ом в результате job (`warnings[]`), а не ошибкой;
  - **подпись/DNSSEC** TTL не меняет.

Это закрывает открытый вопрос ADR 0003 §9.3: молчаливого `min` при записи нет; `min` допустим только при импорте/AXFR с warning'ом. Полная матрица по `WriteIntent` — §5.2.1, поведение при чтении — §2.6.
- Пустой `Rrset` не существует: удаление последней записи = удаление `Rrset` (`Option<Rrset>` / `EditOp::DeleteRrset`).
- `Rrset::merge`/`Rrset::subtract` возвращают `Result`, проверяя инварианты; после вычитания может получиться пустой набор — вызывающий обязан удалить RRset.

### 2.6. `Ttl`, `Serial`

```rust
pub struct Ttl(u32);   // INV: 0..=2_147_483_647
pub struct Serial(u32);
```
- `Ttl` — 31-битное значение (RFC 2181 §8). Политика по источникам:
  - **wire (DNS-пакет, AXFR/IXFR-RDATA):** `Ttl::from_wire` **clamp** к `0x7FFF_FFFF`, флаг `TTL_NORMALIZED`, `Normalization::TtlClamped`/warning, метрика `ttl_clamped_total`. Маскирования нет: `0x8000_0001` → `0x7FFF_FFFF`, **не** `1`.
  - **бинарный файл зон:** значение > `0x7FFF_FFFF` — порча данных → `Corrupt(BadTtl)`, не clamp и не маскирование (файл пишется только писателем, который clamp'ит при приёме).
  - **текстовый zone-файл (import):** TTL-токен > максимума clamp'ится с `ttl_clamped`-warning (политика `WriteIntent::Import`, §5.2.1).
- **`Ttl` — только TTL RR.** SOA-таймеры (`refresh`/`retry`/`expire`/`minimum`) и `RRSIG.original_ttl` — полные `u32` и этому clamp не подвержены (§2.3.1). Для negative caching используется `min(Ttl(SOA), SOA.minimum)`, что ограничено TTL RR.
- `Serial` — полное 32-битное пространство, арифметика **только** по RFC 1982:
  - `s1 < s2` ⟺ `(s2 − s1) mod 2^32 ∈ [1, 2^31 − 1]`;
  - `s1 == s2` при равенстве;
  - разность ровно `2^31` — **неопределённость**, `Serial::cmp_rfc1982() -> Option<Ordering>` возвращает `None`;
  - `succ()` = `+1 mod 2^32` (пропуск неопределённой пары на практике недостижим, но `succ` от значения, дающего 2^31-сдвиг, документируется как допустимый: 2^31 подряд идемпотентных инкрементов невозможны);
  - `Serial::is_newer_than(self, other) -> Option<bool>`.
- **Запрещено** использовать `Serial` в `Ord`/`PartialOrd` для сортировки или `>`; компилятор защищает отсутствием impl.
- `Serial::ZERO` — начальное значение новой зоны до первого SOA; сериализуется как есть.

### 2.7. `ZoneId`, `Zone`, `ZoneMeta`

```rust
pub struct ZoneId(u32);                 // opaque, stable, never reused
pub struct Epoch(u64);                  // глобальный номер коммита (ADR 0005)
pub struct ZoneVersion(u64);            // версия зоны = Epoch её последнего коммита
pub struct ZoneMeta { id: ZoneId, origin: Origin, kind: ZoneKind, state: ZoneState,
                      serial: Serial, version: ZoneVersion,
                      deleted_txn: Option<Txn> }   // настройки — через ZoneStore::meta()
pub enum ZoneKind { Primary, Secondary, Forward }
pub enum ZoneState { Initializing, Serving, Tombstone }
pub struct ZoneSettings { default_ttl: Ttl, denial: Denial, soa_timers: SoaTimers,
                          forward_upstreams: Vec<UpstreamSpec> /* ≤16; формат допускает 32 */ }
```

- **`Epoch`, `ZoneVersion`, `SnapshotId` (ADR 0005).** `Epoch` — доменное имя глобального `txn` формата (§25.2 спецификации; в файле и ADR — `txn`); глобально монотонный номер коммита. `ZoneVersion` — версия конкретной зоны, равная `Epoch` её последнего коммита; `Txn` в документе означает `ZoneVersion`. Типы разделены, чтобы нельзя было случайно сравнить `Epoch` чужой зоны с `ZoneVersion` этой. `SnapshotId` — значение глобального `txn` на момент `snapshot()`; только аудит/диагностика, **не** ceiling и не версия глобального состояния (PW-L8): состояние — набор per-zone версий, а `zone_snapshot` всегда читает последнюю. `ZoneMeta.version` — то, что клиент видит как `ETag`/`zone_version` и что используется в `If-Match` (`docs/api/rest-v1.md` §5.2).
- `ZoneId` выдаётся Zone Store монотонно, сохраняется в файле, **никогда не переиспользуется** (даже после удаления зоны). Исчерпание u32 — фатальная ошибка открытия (`StoreError::IdSpaceExhausted`), не тихая перезапись.
- **`ZoneId` — логическая идентичность, а не физический адрес.** `ZoneId` = стабильный `zone_seq` (принято автором формата); корень B+tree/`PageId`/offset идентификатором больше не является. `compact_zone` и перестройка страниц **не меняют** `ZoneId`: читательский порт `ZoneStore` переживает компакцию без смены идентификатора (меняется только `ZoneSnapshot`/`ZoneVersion`). Домен, API (`id`), аудит, метрики и `TransferState`/`Key` ссылаются только на стабильный `ZoneId`.
- `Zone` — aggregate root: `origin`, `id`, `kind`, `default_ttl`, `soa: Option<SoaData>` (у secondary до первого трансфера — `None`), `dnssec_policy`, `transfer: TransferState` (только для `Secondary`/`Forward`).
- Зона **не материализуется в память целиком**: чтение — через примитивы `ZoneStore`, запись — через `ZoneFacts` (ограниченный снимок затронутых узлов) и чистые `plan_*`-функции. Загрузка зоны на 5M RRset ради одной правки запрещена.
- `ZoneFacts` — VO для write-path: `meta`, `apex: ApexFacts { soa: Option<SoaData>, ns: Option<Rrset> }`, `affected: BTreeMap<Name, Vec<Rrset>>` (owner, его предки до apex и, при необходимости, ближайшие потомки; жёсткий лимит 64 записи), `delegation: Option<Name>`. Собирается application-слоем через `node`/`lookup`; домен работает только с ним.
- `plan_rrset_change(facts: &ZoneFacts, req: RrsetChange) -> Result<Edit, DomainError>` — единственный вход мутации RRset; проверяет INV-1..8, 10–12 локально по фактам. INV-4 (SOA/NS в apex) проверяется только когда `state == Serving` или при переходе в `Serving`; в `Initializing` SOA/NS не обязательны (W-11), допускается зона с одной A-записью (golden-фикстура). Нарушение лимита фактов → `DomainError::FactSetTooLarge` (сигнал, что запрос выходит за рамки локальной правки и требует отдельного use case, например массового импорта).
- `Zone::plan_*` — тонкие обёртки над `plan_rrset_change` для случаев, когда факты уже собраны (например, при применении IXFR-серии, где факты известны из чанка).
- Для `Forward`-зон `Zone` содержит только `origin` + список upstream-ов; собственных RRset нет.
- **Жизненный цикл:** `create_zone` → `Initializing`; после атомарного коммита apex `SOA`+`NS` → `Serving`; `delete_zone` → `Tombstone`. `ZoneState` входит в `ZoneMeta`; tombstones не возвращаются `zones()`/`find_zone()`. В `Initializing` допустима любая валидная RR-нагрузка без `SOA`/`NS` (W-11, golden «одна A-запись»); INV-4 применяется только при переходе в `Serving`.
- **Пустая зона (согласовано с автором формата):** `ZoneEntry.tree_root = 0`, в `ZoneEntry` выставлен `APEX`-маркер, per-zone metadata — `meta_root` (§5.2.5). В `Initializing` зона не авторитативна (нет `SOA`): DNS-ответ — `REFUSED`; API-операции, требующие `Serving`, → `409 invalid-zone-state`.
- **Apex-only (`Serving`, только `SOA`+`NS`):** запрос в apex → `NODATA` + `SOA` в authority; любой qname ниже apex → `NXDOMAIN` + `SOA`; wildcard/referral отсутствуют. Это корректные ответы, а не `REFUSED`.
- **Tombstone:** зона сразу исчезает из поиска (DNS → `REFUSED`, API → `404 zone_not_found`); `ZoneId` не переиспользуется; новая зона с тем же origin получает новый `ZoneId`. `ZoneEntry.deleted_txn = Some(txn)` фиксирует момент удаления (в записи корня v2 — `deleted_txn`, 0-сентинел: `None ↔ 0`, `Some(t) ↔ t`, `t ≥ 1`; см. §5.2.3); страницы и metadata освобождаются **только** когда `deleted_txn ≤ MP(z)` (см. §5.2.4).

### 2.8. `TransferState` (Replication)

```rust
pub enum TransferState {
    Idle,
    NotifyReceived { serial: Option<Serial>, at: Timestamp },
    Transferring { mode: TransferMode, started_at: Timestamp, base_serial: Option<Serial> },
    Applying { mode: TransferMode, received_rrsets: u32 },
    UpToDate { serial: Serial, last_success: Timestamp },
    Failed { kind: TransferFailure, attempts: u16, next_attempt_at: Timestamp },
    Expired { since: Timestamp },       // SOA expire истёк, зона не обслуживается
}
pub enum TransferMode { Axfr, Ixfr { from: Serial } }
```
- Переходы только по разрешённым рёбрам (см. INV-13), реализуется `TransferState::transition(...)` — единственная точка мутации.
- Таймеры (`refresh`, `retry`, `expire`) берутся из SOA зоны, а не из конфига (полные `u32`, INV-21); `Failed::next_attempt_at = now + saturating(retry * backoff(attempts))` — вычисление в `u64` с насыщением: огромный `retry` (например, `0xFFFF_FFFF`) означает «никогда в обозримом будущем», а не переполнение `Timestamp`.
- `Expired` — терминальное для обслуживания состояние: authoritative **обязан** отвечать `SERVFAIL` на запросы в эту зону, но продолжать попытки трансфера (RFC 1034 §4.3.5).
- Перед публикацией принятой зоны обязательна валидация (формат/границы, монотонность SOA serial, DNSSEC-подписи, если зона подписана). Провал → `Failed { kind: Validation }`, зона остаётся на предыдущем валидном снапшоте (карантин, ADR 0004 SEC-REP-003); частично применённая зона не публикуется никогда.
- **Персистентность:** `TransferState`, `Peer`, история NOTIFY и публичные части ключей сохраняются в **state-файле процесса в state-dir** (JSON + обязательный `schema_version`, temp+`fsync`+rename, отказ при неизвестной/более новой версии, последовательные миграции, лимит 32 MiB), а не в зонном файле (ADR 0002 §5). Домен от способа хранения не зависит: получает/отдаёт значения через application-порт `ServerStateRepository`.

### 2.9. `Notify`, `Peer`

```rust
pub struct Notify { zone: Origin, serial: Option<Serial>, from: PeerAddr, tsig_key: Option<KeyName>, received_at: Timestamp }
pub struct Peer { addr: SocketAddr, tsig_key: Option<KeyName>, role: PeerRole /* Primary|Secondary */, acl: Vec<AclRule> }
```
- `Notify` — неизменяемый факт приёма; дедупликация по `(zone, serial, from)` в пределах `refresh`-окна, чтобы флуд NOTIFY не запускал шторм трансферов.
- NOTIFY, serial которого **не новее** текущего (`Serial::is_newer_than` = `Some(false)`/`None`), не инициирует трансфер, но обновляет `last_notify`.

### 2.10. `CacheEntry` (Recursive Resolution)

```rust
pub struct CacheKey { name: Name, rr_type: RrType, class: Class, dnssec_ok: bool, ecs: Option<EcsScope> }
pub enum CacheRdata {
    Positive { rrsets: Vec<Rrset>, authority_hint: Option<Rrset> },
    Negative { rcode: Rcode, soa: Rrset },     // NXDOMAIN / NODATA
}
pub struct CacheEntry {
    key: CacheKey,
    data: CacheRdata,
    inserted_at: Timestamp,
    expires_at: Timestamp,
    original_ttl: Ttl,
    validation: ValidationState,
    source: UpstreamId,
}
pub enum ValidationState { Secure, Insecure, Bogus { reason: ValidationError }, Indeterminate }
```
- `expires_at = inserted_at + min(ttl_of_records)`; для negative — `min(SOA.ttl, SOA.minimum)` (RFC 2308 §5), и `≤ 3h` практический cap (конфигурируемый, но cap — инвариант домена: `NEGATIVE_TTL_CAP = 10_800`).
- `Bogus`-ответы не отдаются клиенту (→ `SERVFAIL`) и кешируются на короткий срок (`BOGUS_TTL = 60`) для защиты от шторма.
- `expires_at` не продлевается при выдаче (RFC 2181 §5.3 — TTL уменьшается).
- В `CacheKey` **не входит** EDNS `bufsize`, `DO`-бит входит (влияет на DNSSEC-записи), `CD`-бит входит как отдельный флаг `checking_disabled`.

### 2.11. `PolicyRule`, `Blocklist`, `Override` (Policy / Filtering)

```rust
pub struct PolicyRule {
    id: PolicyId,
    priority: u32,               // меньше = раньше
    matcher: PolicyMatcher,      // NamePattern | SuffixSet | Regex | ClientGroup
    qtypes: Option<BTreeSet<RrType>>,
    action: PolicyAction,
    enabled: bool,
}
pub enum PolicyAction {
    Block { rcode: Rcode },              // NXDOMAIN по умолчанию
    Refuse,
    Rewrite { rdata: Vec<Rdata>, ttl: Ttl },
    Allow,                               // явное исключение из blocklist
    LogOnly,
}
```
- Приоритеты уникальны; при конфликте — детерминированный порядок `(priority, id)`.
- `Allow` имеет приоритет над `Block` независимо от номера (whitelist-first) — **правило домена**, а не настройка.
- Правило применяется только к резолверу; authoritative им не пользуется (там — `AclRule` на уровне зоны/транспорта).

### 2.12. `Key` (DNSSEC)

```rust
pub struct Key {
    id: KeyId,
    zone: Origin,
    role: KeyRole,                 // Ksk | Zsk | Csk
    algorithm: DnssecAlgorithm,    // EcdsaP256Sha256 | Ed25519 | RsaSha256
    bits: Option<u16>,
    state: KeyState,               // Generated | Published | Active | Retired | Removed
    publish_at: Option<Timestamp>,
    activate_at: Option<Timestamp>,
    retire_at: Option<Timestamp>,
    remove_at: Option<Timestamp>,
    dnskey: DnskeyData,            // публичная часть
    private: SecretRef,            // ссылка, не материал
    ds: Option<DsData>,
}
```
- Приватный ключ **никогда** не хранится в домене: только `SecretRef`, разрешаемый через `SecretStore`. Backend v1: файл `0600` в каталоге `0700` (ADR 0004); PKCS#11/KMS — roadmap, интерфейс порта не меняется.
- Временные окна монотонны: `publish_at ≤ activate_at < retire_at ≤ remove_at` (INV-15).
- `Key` и `Zone` связаны по `Origin`; генерация/ротация — use case в `pulse-server::application::dnssec`.
- Публичная часть `Key` и метаданные (`state`, окна) персистятся в state-файле процесса (state-dir), не в зонном файле.

---

## 3. Инварианты домена

Каждый инвариант имеет идентификатор, точку принудительной проверки и тест.

| ID | Инвариант | Где проверяется | Тест |
|---|---|---|---|
| INV-1 | `Rrset` однороден: один owner, один `RrType`, один `Class`, один `Ttl` | `Rrset::new`, `merge`, `subtract`, десериализация из зоны | unit + proptest |
| INV-2 | В `Rrset` нет дубликатов `Rdata`; порядок канонический | `BTreeSet` + `Rdata: Ord` по канонической форме | unit |
| INV-3 | `0 ≤ TTL ≤ 2^31−1` **для TTL RR**; wire/import — clamp к `0x7FFF_FFFF` + `TTL_NORMALIZED` (без маскирования); в бинарном файле > максимума → `Corrupt(BadTtl)`. SOA-таймеры и `RRSIG.original_ttl` — не TTL и не clamp’ятся (INV-21/INV-24) | `Ttl::new`, `Ttl::from_wire`, reader | proptest |
| INV-4 | В зоне ровно один `SOA`, только в apex; в apex есть ≥1 `NS` (для `Serving`; у `Secondary` — после первого успешного трансфера). **Исключение (W-11):** для `Initializing` SOA/NS могут отсутствовать; обязательны при переходе в `Serving` и у любой `Serving`-зоны | `validate_zone_facts` (apex) при `state == Serving`/переходе в `Serving`; `plan_commit` | unit + golden |
| INV-5 | Владелец `CNAME` не имеет других типов, кроме `RRSIG`/`NSEC`/`NSEC3` (DNSSEC-метаданные); `CNAME` не в apex | `plan_rrset_change` | unit |
| INV-6 | `DNAME` не в apex и не сосуществует с `CNAME` в том же owner | `plan_rrset_change` | unit |
| INV-7 | Все owner'ы — поддомены `Origin` (включая apex) | `Name::is_subdomain_of`, `validate_zone_facts` | proptest |
| INV-8 | Ниже zone cut (делегирования) допустимы только `NS` (в точке cut), `DS`, `A`/`AAAA`-glue и DNSSEC-записи; прочие данные ниже cut не отдаются authoritative-ответом | `AuthoritativeResolver::lookup` (доменный сервис) | unit + RFC-кейсы |
| INV-9 | `Serial` строго новее предыдущего на каждом `commit` (RFC 1982), изменения серийного номера атомарны с изменением SOA | `ZoneWriter::commit` + `plan_commit` | unit + concurrency |
| INV-10 | Только `Class::IN` в v1; попытка записать `CH`/`HS` — `UnsupportedClass` | конструкторы `Record`/`Rrset` | unit |
| INV-11 | Имя: ≤255 октетов wire, метка 1..=63, канонический lowercase; wildcard `*` — только левая метка и не более одной | `Name::new`, `Name::parse` | proptest |
| INV-12 | Зона не может содержать два `Rrset` с одинаковыми `(owner, type)` | ключ индекса зоны; `plan_rrset_change` | unit |
| INV-13 | `TransferState` меняется только по разрешённым переходам (см. §3.1) | `TransferState::transition` | state-machine test |
| INV-14 | Negative-ответ содержит SOA с TTL `= min(SOA.ttl, SOA.minimum) ≤ 10_800` | `CacheEntry::negative` | unit |
| INV-15 | Окна `Key` монотонны; `Removed` — терминальное состояние | `Key::rotate_to` | state-machine test |
| INV-16 | `ZoneId` неизменяем и не переиспользуется | Zone Store (аллокатор id) | integration |
| INV-17 | TXT: `1..=N` сегментов, каждый `0..=255` октетов (**пустая строка легальна**), `Σ(1+len) ≤ 65535`; `RDLENGTH = 0` запрещён | `TxtData::new` | proptest |
| INV-18 | `RRSIG` inception/expiration сравниваются по RFC 1982 (секунды, 32 бита) | `RrsigData::is_valid_at` | unit |
| INV-19 | Policy: приоритеты уникальны; `Allow` доминирует над `Block` | `PolicySet::insert` | unit |
| INV-20 | Любая зона, отдаваемая authoritative, имеет либо `UpToDate`/`Idle` (primary), либо `Expired` → `SERVFAIL`; `Transferring` не отдаёт частичных данных | `TransferState::serving_policy` | unit |
| INV-21 | SOA-таймеры — полные `u32` без clamp; `refresh ≥ 1`, `retry ≥ 1`, `expire > refresh + retry` (u64-арифметика) | `SoaData::validate` | unit + proptest |
| INV-22 | NSEC `type_bitmap` непуст; NSEC3 `type_bitmap` может быть пустым (ENT, RFC 5155 §8.5) | `NsecData::new`, `Nsec3Data::new` | unit |
| INV-23 | CAA `tag` — 1..=255 opaque-байт, регистр сохраняется; семантическое сравнение case-insensitive; пустой/длиннее 255 → `BadRdata` | `CaaTag::new`, `CaaTag::eq_ignore_ascii_case` | unit + proptest |
| INV-24 | `RRSIG.original_ttl` — полный `u32`, не clamp’ится и не нормализуется | `RrsigData::new` | unit + round-trip |

### 3.1. Разрешённые переходы `TransferState`

```
Idle            -> NotifyReceived | Transferring(manual)
NotifyReceived  -> Transferring | UpToDate(no-op: serial не новее) | Idle(таймаут)
Transferring    -> Applying | Failed
Applying        -> UpToDate | Failed
Failed          -> Transferring(retry) | Expired
UpToDate        -> NotifyReceived | Transferring(refresh/ixfr) | Idle
Expired         -> Transferring(retry) | Expired
```
Запрещённые переходы возвращают `TransferError::IllegalTransition`. `Applying` обязан быть атомарным: применение IXFR-серии — одна транзакция `ZoneWriter`; при ошибке — `CommitPolicy::Abort`, состояние → `Failed`, зона остаётся на старом сериале.

---

## 4. Доменные сервисы (семантика)

### 4.1. Authoritative lookup (RFC 1034 §4.3.2, RFC 4592, RFC 6672)

Алгоритм чистый, выполняется по снапшоту через примитивные операции `ZoneStore` (`lookup`/`node`/`next_name`), без I/O. Порядок:

1. **Zone cut:** найти ближайший делегированный узел (`NS` без `SOA`) на пути от apex к qname. Если qname ниже cut — ответ `REFERRAL` (authority = NS, additional = glue), данные ниже cut не раскрываются. `DS` в точке cut — исключение (отдаётся вместе с referral для DNSSEC).
2. **Точное совпадение** `(qname, qtype)` → `Answer`.
3. **CNAME:** если в qname есть `CNAME` и `qtype != CNAME` — вернуть CNAME + продолжить поиск цели внутри зоны (цепочка), с лимитом `MAX_CHAIN = 16` и защитой от циклов. Выход за пределы зоны — `PartialAnswer` (клиент/резолвер продолжит).
4. **DNAME:** ближайший предок с `DNAME` → синтезировать `CNAME` (RFC 6672), лимит длины (255) и цепочки.
5. **Wildcard:** ближайший предок вида `*.<suffix>` при условии, что между qname и wildcard-узлом **нет существующих имён** (RFC 4592 §2.2.1 — «closest encloser proof»). Синтезированный owner = qname.
6. **NODATA / NXDOMAIN:** точное имя существует без qtype → NODATA + SOA в authority; имени нет (и нет wildcard-совпадения) → NXDOMAIN + SOA.

Инвариант результата: `LookupResult` содержит ровно один из `Answer`, `Referral`, `NxDomain`, `NoData`, `PartialAnswer`; `aa=true` для всех, кроме `PartialAnswer`/`Referral`.

Поиск — **zero-copy**: `LookupResult<'a>` ссылается на данные снапшота, время жизни привязано к `ZoneSnapshot` (v2 — пин версии зоны, ADR 0005). Копирование (`to_owned`) выполняется только на границе отправки пакета.

### 4.2. `SerialArithmetic`

Отдельный доменный сервис: `diff(a, b) -> Option<u32>`, `is_newer(a, b) -> Option<bool>`, `plan_bump(current, requested) -> Result<Serial, SerialError>`.
- `plan_bump`: `requested > current` (RFC 1982) → принимать; иначе — `SerialNotNewer`; при `2^31`-неопределённости — `SerialAmbiguous`.
- IXFR: `diff(from, to)` ограничен `2^31−1`; больше — требуется AXFR (`IxfrTooLarge`).

### 4.3. `ZoneDiff` (IXFR-out)

Чистая функция `diff(old: &ZoneSnapshot, new: &ZoneSnapshot) -> Vec<RrsetDelta>`, сгруппированная по транзакциям (для IXFR по RFC 1995 нужна история версий). **Решение (v1):** история IXFR-out — **in-memory ринг в `pulse-server`**, персистентность IXFR не требуется; домен требует лишь: для каждого сериала в окне IXFR доступен набор дельт. Если история недоступна (рестарт, вытеснение окна) или `from` вне окна — `AxfrRequired`.

Явный дегрейд: после рестарта или вытеснения окна ответ на IXFR — `AxfrRequired` (клиент получит AXFR). Персистентная история зарезервирована форматом (`IXFR_HISTORY`-секция) и доменом не требуется.

### 4.4. `SigningPlan` (DNSSEC-out)

`plan_sign(zone, keys, now) -> Result<SignedZone, SignError>`: определяет, какие `Rrset` подписываются, `RRSIG`-окна (`inception = now − clock_skew`, `expiration = now + validity`), цепочку denial-of-existence, `DS` для KSK. Криптография — через порт `Signer` (в `pulse-dns`, реализация в `pulse-server::infrastructure`); домен только формирует план и валидирует результат по инвариантам.

**Решение по NSEC/NSEC3 (v1):**
- домен моделирует `denial: Nsec | Nsec3` (`Zone.dnssec_policy`), валидатор (`pulseresolved`, M5) обязан поддерживать **оба** типа;
- **подпись в v1 — только NSEC**; NSEC3-подпись — v1.1. `SigningPlan` с `denial = Nsec3` возвращает `SignError::NotImplemented` (API → `501`, см. `docs/api/rest-v1.md` §7.6);
- импорт/secondary могут содержать NSEC3-подписанные зоны — они валидируются и обслуживаются как есть (без переподписи); валидатор обязан принимать **пустой type bitmap** в NSEC3 (empty non-terminal, RFC 5155 §8.5), тогда как пустой bitmap в NSEC — `BadRdata` (INV-22).

### 4.5. Прикладывание `RRSIG` к ответу (политика домена)

`RRSIG` в хранилище индексируется subtype (`type covered`), поэтому читается через `lookup_all(name, RRSIG)`, а не `lookup`. Прикладывает подписи **домен** (`pulse-server::domain::resolve`) при сборке ответа; адаптер лишь отдаёт `RrsetRef` с `subtype`.

- **Когда прикладываются:** зона `Serving` и подписана (есть apex `DNSKEY` и/или `RRSIG`) и (`DO=1` **или** `qtype ∈ {RRSIG, ANY}`). Для `DO=0` подписи в ответ не попадают (кроме явного `qtype=RRSIG`).
- **Какие:** `lookup_all(owner, RRSIG)`, фильтр `subtype == qtype` (для `ANY` — все группы); для CNAME/DNAME-цепочки — подписи каждого звена; для referral — `RRSIG(DS)` вместе с `DS`, `RRSIG(NS)` в referral не включается (RFC 4035 §3.1.4).
- **Подписанная зона, но подпись отсутствует** при `DO=1` → `SERVFAIL` + метрика `dnssec_missing_rrsig_total` (fail-closed, ADR 0004). Ответ без подписи «как будто не подписано» запрещён.
- **Неподписанная зона** → `RRSIG` не добавляются, `DO` игнорируется (зона честно insecure).
- **Просроченные/невалидные по времени** подписи не подменяются и не выдумываются: отдаются как есть + метрика `rrsig_expired_total`; переподпись — job подписанта. Валидацию (secure/bogus) выполняет резолвер, не authoritative.
- **Denial of existence:** NSEC-цепочка (`next_name` + `lookup_all(NSEC)`) строится доменом для NXDOMAIN/NODATA; для импортированных NSEC3-зон — по `lookup_all(NSEC3)`/`NSEC3PARAM` (v1 их не подписывает, §4.4).

---

## 5. Порты (driven ports)

Общие требования ко всем портам:
- `Send + Sync` (кроме `ZoneWriter`: `Send`, не `Sync`; один экземпляр = аренда одной зоны, экземпляров может быть много — по одному на зону в разных потоках).
- Реализации **не паникуют** на ожидаемых ошибках; всё — через `Result`.
- Ошибки порта типизированы и конвертируются в `ApplicationError` в одном месте (`From`-impl).
- Порты не логируют бизнес-события; логирование — в адаптере на уровне `tracing` с `trace_id`.

### 5.1. `ZoneStore` — чтение зон (snapshot-модель)

```rust
pub trait ZoneStore: Send + Sync + 'static {
    /// O(1), lock-free. Снимок каталога + `SnapshotId` (аудит/диагностика).
    /// НЕ ограничивает версию зоны (ceiling = ∞) и НЕ пинит страницы:
    /// согласованный срез нескольких зон даёт только `freeze()`.
    fn snapshot(&self) -> SnapshotHandle;

    /// O(1), lock-free. Берёт ПОСЛЕДНЮЮ опубликованную версию зоны и ПИНИТ её:
    /// все срезы защищены от переиспользования до Drop. Обязателен для любого
    /// чтения данных зоны (zero-copy). `StaleRoot` — валидной версии нет вовсе
    /// (ring+chain биты) или зона пересоздана (retryable после нового snapshot()).
    fn zone_snapshot(&self, snap: &SnapshotHandle, zone: ZoneId)
        -> Result<ZoneSnapshot, StoreError>;

    /// То же по origin (longest-suffix уже разрешён вызывающим).
    fn zone_snapshot_by_origin(&self, snap: &SnapshotHandle, origin: &Origin)
        -> Result<ZoneSnapshot, StoreError>;

    /// Метаданные зон (только живые).
    fn zones(&self, snap: &SnapshotHandle) -> Vec<ZoneMeta>;

    /// Поиск метаданных по origin.
    fn zone_meta(&self, snap: &SnapshotHandle, origin: &Origin) -> Option<ZoneMeta>;

    /// Самая специфичная (longest-suffix) зона для qname. O(labels), без аллокаций.
    fn find_zone(&self, snap: &SnapshotHandle, qname: &Name) -> Option<ZoneMeta>;

    /// Serial зоны без разбора SOA-RDATA. Читается из записи корня версии зоны.
    fn serial(&self, zs: &ZoneSnapshot) -> Serial;

    /// Per-zone metadata из meta-блока (`head.meta_root`): default_ttl, denial,
    /// SOA-таймеры, forward-upstreams. Zero-copy, lifetime = `ZoneSnapshot`.
    fn meta<'a>(&self, zs: &'a ZoneSnapshot) -> Result<ZoneSettingsRef<'a>, StoreError>;

    /// Точное чтение RRset по (qname, qtype): zero-copy, результат живёт не дольше снапшота.
    /// НЕ выполняет DNS-композицию (wildcard/CNAME/referral/NXDOMAIN) — это домен.
    /// Для `RRSIG` возвращает `WrongAccessor` — используйте `lookup_all`.
    fn lookup<'a>(
        &self,
        zs: &'a ZoneSnapshot,
        qname: &Name,
        qtype: RrType,
    ) -> Result<Option<RrsetRef<'a>>, StoreError>;

    /// Все RRset для (qname, qtype): 0..N, канонический порядок по subtype.
    /// Для `RRSIG` — все groups, различающиеся `type covered`; для прочих типов 0 или 1.
    /// `RRSIG` в хранилище индексируется subtype (= covered type), поэтому один `lookup`
    /// не может вернуть все подписи имени.
    fn lookup_all<'a>(
        &self,
        zs: &'a ZoneSnapshot,
        qname: &Name,
        qtype: RrType,
    ) -> Result<RrsetsRef<'a>, StoreError>;

    /// Существование узла и его флаги (apex, zone cut, наличие потомков)
    /// без чтения всех RRset — для closest-encloser/wildcard/referral.
    fn node<'a>(
        &self,
        zs: &'a ZoneSnapshot,
        name: &Name,
    ) -> Result<Option<NodeRef<'a>>, StoreError>;

    /// Следующее имя в каноническом порядке (RFC 4034 §6.1) — для NSEC и потокового обхода.
    fn next_name<'a>(
        &self,
        zs: &'a ZoneSnapshot,
        after: Option<&Name>,
    ) -> Result<Option<NameRef<'a>>, StoreError>;

    /// Потоковое перечисление RRset зоны в каноническом порядке (zero-copy).
    /// visitor получает `RrsetRef<'a>` (заимствован из снапшота) и обязан не сохранять его
    /// за пределами вызова. ControlFlow::Break останавливает обход; в этом случае
    /// возвращается курсор для продолжения (`enumerate(..., from: Some(cursor), ...)`).
    fn enumerate<'a>(
        &'a self,
        zs: &'a ZoneSnapshot,
        from: Option<&Name>,
        visitor: &mut dyn FnMut(RrsetRef<'a>) -> std::ops::ControlFlow<()>,
    ) -> Result<Option<Name>, StoreError>;
}
```

**Разделение ответственности (обязательно):** порт отдаёт **примитивы** — точный RRset, узел, следующее имя. Композиция ответа (wildcard, CNAME/DNAME-цепочка, referral, NXDOMAIN/NODATA, additional/glue) выполняется доменным сервисом `pulse-server::domain::resolve` поверх `lookup`/`node`/`next_name` (см. ADR 0003 §20.4). Адаптер, реализующий `lookup` как «готовый DNS-ответ», считается нарушением слоёв.

**Источник истины:** публичные сигнатуры §5.1/§5.2 — эталон для §20.3/§20.4 спецификации формата; изменение API порта требует синхронной правки обоих документов.

```rust
pub struct RrsetRef<'a> {
    pub owner: NameRef<'a>,
    pub rr_type: RrType,
    pub subtype: Option<RrType>,   // для RRSIG = type covered; иначе None
    pub class: Class,
    pub ttl: Ttl,
}
impl<'a> RrsetRef<'a> {
    pub fn len(&self) -> usize;                     // число RR в наборе
    pub fn iter(&self) -> impl Iterator<Item = Rr<'a>>;
    pub fn to_owned(&self) -> Rrset;                // только на границе снапшота
}

/// Один RR (RDATA) в снапшоте. RDATA может разрываться между страницами
/// и/или лежать в overflow-цепочке (решение формата B-11), поэтому
/// один `&[u8]` на RDATA не гарантируется.
pub struct Rr<'a> { /* 1..=N сегментов, без владения */ }
impl<'a> Rr<'a> {
    pub fn len(&self) -> usize;                              // длина RDATA в байтах
    pub fn as_slice(&self) -> Option<&'a [u8]>;              // Some только для непрерывной RDATA
    pub fn chunks(&self) -> impl Iterator<Item = &'a [u8]>;  // 1..=N сегментов в порядке байтов
    /// Копирует ровно `len()` байт. Если `dst.len() < len()` — `Err(BufferTooSmall)`
    /// **без частичной записи**; при успехе возвращает `len()`. Никогда не паникует.
    pub fn copy_into(&self, dst: &mut [u8]) -> Result<usize, BufferTooSmall>;
}

pub struct RrsetsRef<'a> { /* inline ≤ 4; при большем числе subtypes — cursor внутри снапшота */ }
impl<'a> RrsetsRef<'a> {
    pub fn iter(&self) -> impl Iterator<Item = RrsetRef<'a>>;
    pub fn len(&self) -> usize;
}

pub struct ZoneSettingsRef<'a> { /* поля ZoneSettings + forward_upstreams-срез, всё заимствовано */ }

pub struct NodeRef<'a> {
    pub name: NameRef<'a>, pub exists: bool, pub is_apex: bool,
    pub is_zone_cut: bool,      // есть NS и нет SOA
    pub has_children: bool,
}

/// Имя хранится в файле в RLE-виде с обратным порядком меток (TLD→owner).
/// Прямого wire-среза нет: owner отдаётся в энкодер через `write_wire`
/// (прямой порядок, без сжатия); для разбора — `to_name()`.
pub struct NameRef<'a> { /* RLE-срез, без владения */ }
impl<'a> NameRef<'a> {
    pub fn label_count(&self) -> u8;
    /// Прямой wire-формат без сжатия: owner → TLD, с длинами и терминальным 0.
    pub fn write_wire(&self, out: &mut impl std::io::Write) -> std::io::Result<usize>;
    pub fn to_name(&self) -> Name;                            // владение — только при необходимости
}
```

Всё, что отдают порты, формат может предоставить без материализации: `RrsetRef` — заголовок RRset + `Rr`-сегменты; `NameRef` — RLE-срез; `subtype` — из типа ключа; настройки — из `meta_root`; `has_children` — из диапазона ключей (следующий ключ с префиксом имени). Единственная операция копирования — `Rr::copy_into` для одной RDATA; весь RRset не материализуется никогда.

Пример AXFR-потока (нулевое копирование RRset, максимум — один RR при `copy_into`):

```rust
let zs = store.zone_snapshot(&snap, zone)?;   // пин версии зоны на весь трансфер
store.enumerate(&zs, from, &mut |rrset| {
    for rr in rrset.iter() {
        out.put_u16(rr.len() as u16);                 // RDLENGTH
        match rr.as_slice() {
            Some(s) => out.extend_from_slice(s),      // непрерывная RDATA — без копии
            None => for chunk in rr.chunks() {        // разрыв страницы — сегмент за сегментом
                out.extend_from_slice(chunk);
            },
        }
    }
    ControlFlow::Continue(())
})?;
```
- Домен не парсит RDATA, которые не участвуют в семантике: для A/AAAA/TXT/MX и т.п. сегменты `Rr` копируются в ответ как есть. Для CNAME/NS/DNAME/SOA разбор — on-demand (`NameRef::to_name()`), только по этим типам.
- Owner (имя) не копируется в `Name`: энкодер пишет метки из `NameRef::write_wire` прямо в выходной буфер; `Name` создаётся только когда нужен владелец (ключ кеша, ответ API).
- Владение (`Rrset`, `Record`, `Name`) появляется только при выходе за границу снапшота: API-ответ, экспорт, запись в трансфер. Внутри обработки запроса — заимствование, lifetime = `ZoneSnapshot`.

**Снапшоты: две ступени (ADR 0005).**

| Ступень | Что это | Что гарантирует | Цена |
|---|---|---|---|
| `SnapshotHandle` | каталог + `SnapshotId` (диагностика) | «какие зоны есть»; **не** ограничивает версию зоны (ceiling = ∞), **не** удерживает страницы и **не** даёт согласованный срез | 1 acquire-load |
| `ZoneSnapshot` | последняя опубликованная версия `V` + пин в reader table | атомарный набор данных одной зоны: `lookup`/`node`/`next_name`/`enumerate` видят ровно версию `V`; срезы защищены от переиспользования до `Drop`; `version()`/`zone()` — accessor'ы | 2 атомарных store/load + `fence(SeqCst)` + refcount |

Правила:

1. **Любое чтение данных зоны идёт через `ZoneSnapshot`.** `lookup`/`node`/`next_name`/`enumerate`/`meta` принимают `&ZoneSnapshot`, а не `&SnapshotHandle`; иначе срез `mmap` может быть переиспользован writer'ом (в v1 это закрывалось единым пином файла, в v2 пин — зоно-локальный).
2. `ZoneSnapshot` — `Send + Sync`, клонируется как `Arc`-refcount без повторного пина; `unpin` — на `Drop` последнего держателя.
3. Зона живёт независимо: `ZoneSnapshot` остаётся валидным, даже если зону удалили (tombstone) — читатель дочитывает свою версию, страницы освобождаются GC только после снятия пина (A-11 ADR 0005).
3a. **Ceiling = ∞:** `snapshot()` не фиксирует «версию мира». Снапшот зоны всегда отражает последнюю опубликованную версию на момент `zone_snapshot()`; повторный `zone_snapshot` той же зоны в том же батче может дать более новую версию. Если нужен стабильный срез многих зон — `freeze()` (maintenance), не `SnapshotHandle`.
4. Кросс-зонная согласованность **не гарантируется**. Для «среза всех зон» — административная `freeze()` (maintenance, не порт) или offline-копия; см. `docs/adr/0005-parallel-writers.md` §7.3.
5. `StaleRoot { zone, requested: ZoneVersion, oldest_retained: ZoneVersion }` — не штатная ошибка чтения: в ring+chain нет ни одной валидной версии (порча/исчерпание history) либо зона пересоздана и `version` начались заново. Retryable после `fsck`/нового `snapshot()`; при исчерпании ring писатель уходит в chain (ADR 0005 §3.2), а не возвращает ошибку читателю.

**Гарантии:**
- `snapshot()` — Acquire-load атомарного указателя; не блокирует писателя и других читателей. Может вызываться из любого потока, включая hot-path DNS-обработчика.
- `zone_snapshot()` — двухфазный per-zone пин: структура протокола — `docs/spec/zonefile-v1.md` §6.3, v2-детали (seqlock, `fence(SeqCst)`, 6 пинов × 16 Б) — `docs/spec/parallel-writes-v2.md` §5.2–5.3; ≤ 40 ns, без syscall и без аллокаций; при переполнении слотов/пинов — `ReaderContended`, при > `MAX_PINNED_ZONES_PER_SNAPSHOT` (64) зон — широкий EPOCH-пин (`PIN_OVERFLOW`, консервативная деградация, данные целы).
- `SnapshotHandle`/`ZoneSnapshot` — дешёвые копии (`Arc`-подобные), клонирование ≤ 20 ns, без syscall. `SnapshotHandle` не является retention-барьером: держать его долго безопасно, но он не гарантирует «старый мир» (ceiling = ∞).
- `lookup`/`node`/`next_name` детерминированы: два вызова с одним снапшотом дают идентичный результат; снапшот иммутабелен. Все три — O(log n) и без аллокаций.
- `lookup_all` для `RRSIG` возвращает до `MAX_RRSIG_SUBTYPES = 64` групп; превышение — `Corrupt` (формат не должен допускать такого имени). Для не-RRSIG типов результат — 0 или 1 элемент.
- `meta()` — O(1) чтение meta-блока, не зависит от числа RRset; не парсит содержимое зоны.
- `enumerate` не материализует `Rrset` и не копирует RDATA: `RrsetRef<'a>` заимствован из снапшота, действителен **только во время вызова visitor**; сохранять его (или `Rr`/сегменты) за пределами вызова запрещено контрактом. AXFR-путь пишет сегменты RDATA напрямую в буфер отправки (пример выше).
- `enumerate` возвращает `Some(cursor)`, если visitor вернул `Break`; продолжение — `enumerate(from: Some(cursor))` даёт ровно те же записи, начиная со следующей. Ошибка посреди обхода → `Err`; полученный до ошибки поток **не является полным обходом зоны** — AXFR обязан прервать трансфер (без `End`/commit), а не отдавать частичную зону как целую.
- `find_zone` — longest-suffix по меткам, O(labels) (≤ 127), без аллокаций; при нескольких зонах с перекрытием выбирается самая специфичная.
- `enumerate` даёт стабильный порядок (канонический по `(owner, type)`) — нужен для AXFR, NSEC и детерминированных тестов/экспорта.
- Читатель может удерживать `ZoneSnapshot` неограниченно долго; writer не переиспользует освобождённые области, пока пин этой версии жив (см. ADR 0005 §6, `docs/spec/zonefile-v1.md` §25.11). Следствие: долгоживущий читатель задерживает рекламацию **только своей зоны**, а не файла.

**Ошибки:** `StoreError::{Io { source }, Corrupt { kind: CorruptKind, zone: Option<ZoneId>, page: Option<u32> }, UnsupportedVersion { found: u16, supported: u16 }, ZoneNotFound, WrongAccessor { rrtype: RrType }, StaleRoot { zone: ZoneId, requested: ZoneVersion, oldest_retained: ZoneVersion }, ZoneDegraded { zone: ZoneId, epoch: Epoch }, ReaderContended, IdSpaceExhausted, MapFull, NoSpace, TooManyReaders, Internal}`. `MapFull`/`NoSpace`/`IdSpaceExhausted` на чистом чтении не возникают, но входят в общий тип для единого ACL-маппинга ошибок формата (см. §6); `CorruptKind` — структурированная причина (`NoValidMeta`, `PageChecksum`, `TreeOrder`, `Bounds`, `FreelistCycle`, `BadTtl`, `BadZoneMeta`, `BadRdata`, `BadName`, `BadZoneHead`), не строка. `Corrupt` теперь несёт `zone`, если порча локализована зоной (ADR-0006 PW-C24/§7): остальные зоны продолжают обслуживаться. `zone_snapshot()` после `PIN_ATTEMPTS = 8` различает причины: застрявший `zone_guard` → `ZoneDegraded` (зона read-only + `NEEDS_FSCK`, не retryable в этом вызове), churn публикаций (`e0`/версия сменились) → `ReaderContended` (retryable с backoff).
**Конкурентность:** много читателей / много писателей по разным зонам; `ZoneStore` сам по себе read-only фасад.
**Производительность (цель):** `lookup` p50 ≤ 300 ns; полный авторитетный ответ (доменная композиция + адаптер) p50 ≤ 500 ns, p99 ≤ 2 µs на зону 1M RRset в горячем кеше CPU; `snapshot()` не аллоцирует.

### 5.2. `ZoneWriter` — транзакционная запись

#### 5.2.1. Модель транзакции и аренда зоны

Транзакция **неявная и зоно-локальная**: первый `apply(intent, edit)` на `ZoneWriter` открывает её, последующие `apply` накапливают правки, `commit(CommitPolicy)` завершает. **Одна транзакция = ровно один `commit`**; между `apply` изменения не видны читателям (COW-страницы, публикация версии корня зоны при `commit`). Несколько `apply` допустимы (батчинг импорта/трансфера), но каждый `Edit` — атомарная единица валидации. Явных `begin`/`abort` нет: откат — `CommitPolicy::Abort`; API §5.2.6 — источник истины для §20.3 спеки формата.

**`ZoneWriter` — handle на одну зону, а не на файл.** Экземпляр создаётся `ZoneStore::writer(zone)` / `writer_by_origin(origin)` и удерживает **аренду (lease)** этой зоны до `Drop`. Пока аренда удерживается, никакой другой `ZoneWriter` этой зоны существовать не может; другие зоны пишутся параллельно.

| Свойство | Правило |
|---|---|
| Сколько писателей | `N` экземпляров `ZoneWriter` на разные зоны — одновременно, без общего лока; на одну зону — ровно один (аренда) |
| `Send`/`Sync` | `ZoneWriter: Send`, **не** `Sync` (мутация — из одного потока); `ZoneStore: Send + Sync` |
| Получение аренды | `writer()` — `Busy` сразу, если зона занята; `writer_timeout(d)` — ждёт до `d`, затем `Busy`; `try_writer()` — не блокирует |
| Активная транзакция | одна на экземпляр; `apply` с другим `intent` → `Busy`; `Drop` без `commit` = `Abort` |
| Долгая операция | `compact_zone`/импорт держат аренду только своей зоны: остальные зоны пишутся (PR-3 ADR 0005) |
| Кросс-зонные операции | `create_zone`/`delete_zone` — не через `ZoneWriter`; см. §5.2.4 |
| Порядок | правки одной зоны сериализованы арендой; между зонами общего порядка нет |

**Атомарность и видимость.** `commit` атомарен в области **одной зоны**: либо вся транзакция видна читателям зоны, либо ничего. Кросс-зонная атомарность не предоставляется и не требуется (`docs/adr/0005-parallel-writers.md` §7).

**Precondition внутри транзакции.** `Edit` может нести `precondition: Option<Precondition>` (`IfZoneVersion(ZoneVersion)` / `IfRrsetEtag(hash)`). Проверка выполняется адаптером **внутри** аренды, против версии, на которой построен `Edit`, — этим закрывается TOCTOU между `GET` (ETag) и записью: несовпадение → `WriteError::PreconditionFailed { current: ZoneVersion, current_etag }` (HTTP `412`), файл не меняется. Без precondition поведение прежнее (`ZoneStore`-чтение снаружи транзакции).

`WriteIntent` задаёт **политику инвариантов и нормализации**. Это единственное место, где TTL-политика различается (ср. §2.5):

```rust
pub enum WriteIntent {
    Transaction,   // REST/API, динамические обновления: строгие инварианты
    Import,        // загрузка zone-файла: TTL → min + warning
    Signing,       // DNSSEC-подпись: TTL не меняется, только DNSSEC-типы
    Replication,   // AXFR/IXFR-in: как Import + строгая монотонность serial
}
```

| Intent | Строгие инварианты | Что нормализуется | Что в отчёте |
|---|---|---|---|
| `Transaction` | INV-1..12 целиком; разный TTL в RRset → `InvariantViolation(INV-1)`; CNAME/DNAME-конфликт → ошибка | ничего (нормализация запрещена) | `warnings` пуст; любое отклонение — ошибка |
| `Import` | структура зоны, owner ∈ origin, class IN, CNAME/DNAME/wildcard (INV-5..8,10–12) — строго; INV-4 — только при переходе в `Serving` (в `Initializing` SOA/NS не обязательны); INV-1 по TTL — **нормализуется** | разный TTL → `min` (RFC 2181 §5.2); дубликаты RDATA — дедуп; TTL > 2^31−1 (wire/текст) — clamp + `TTL_NORMALIZED` (данные **бинарного** файла с таким TTL — `Corrupt(BadTtl)`, см. §2.6) | `normalized[]` + `warnings[]` (`ttl_normalized`, `duplicate_rdata_removed`, `ttl_clamped`) |
| `Signing` | все INV строго; разрешены только DNSSEC-типы (`RRSIG`/`NSEC`/`NSEC3`/`DNSKEY`/`DS`); прочие типы → `IntentForbidden` | **никогда** (попытка изменить TTL/обычные RRset → `IntentForbidden`) | `warnings` пуст |
| `Replication` | как `Import`, плюс: принятая зона обязана завершиться `Serving` (SOA+NS присутствуют, иначе `InvariantViolation(INV-4)` → карантин, не публикуется); новый SOA serial новее текущего (RFC 1982), иначе `SerialConflict`; `subtree`-удаления разрешены | как `Import` | как `Import` + `serial` в `CommitOutcome` |

`Signing` v1 подписывает только NSEC (`Zone.dnssec_policy.denial = Nsec`); NSEC3-подпись — v1.1 (§4.4), до неё `plan_sign` возвращает `SignError::NotImplemented` и writer не вызывается. `NSEC3`/`NSEC3PARAM` как типы данных в `Signing`-правке допустимы только для импортированных/secondary зон (переподпись в NSEC3 не выполняется).

#### 5.2.2. `Edit` и операции

```rust
pub struct Edit { pub id: EditId, pub ops: Vec<EditOp> }   // 1..=4096 операций

pub enum EditOp {
    /// Создать или полностью заменить набор (идемпотентно по конечному состоянию).
    UpsertRrset { owner: Name, rr_type: RrType, class: Class, ttl: Ttl, rdata: Vec<Rdata> },
    /// Заменить существующий набор; отсутствие → Conflict.
    ReplaceRrset { owner: Name, rr_type: RrType, class: Class, ttl: Ttl, rdata: Vec<Rdata> },
    /// Удалить набор; if_exists=false и набора нет → Conflict, if_exists=true → no-op.
    DeleteRrset { owner: Name, rr_type: RrType, class: Class, if_exists: bool },
    /// Добавить записи к набору (TTL берётся у набора; ttl не передаётся; набора нет → Conflict).
    AddRecords { owner: Name, rr_type: RrType, class: Class, rdata: Vec<Rdata> },
    /// Удалить конкретные записи; отсутствующие — no-op (идемпотентно).
    RemoveRecords { owner: Name, rr_type: RrType, class: Class, rdata: Vec<Rdata> },
    /// Сменить TTL всего набора; набора нет → Conflict.
    SetTtl { owner: Name, rr_type: RrType, class: Class, ttl: Ttl },
    /// Удалить все RRset имени; subtree=true — и всех потомков (Import/Replication only).
    DeleteName { name: Name, subtree: bool },
    /// Метаданные зоны из meta-блока (`ZoneEntry.meta_root`); serial/origin/id не меняются
    /// (serial — только commit). Атомарно с правками RRset в той же транзакции.
    SetZoneMeta { patch: ZoneSettingsPatch },
}
```

Ограничения `Edit` (проверяются `Edit::validate(intent)` **до** первой записи):

- непустой (`WriteError::EditEmpty`), ≤ 4096 операций на `Edit` (`EditTooLarge`), суммарный RDATA payload ≤ 1 MiB на `Edit` (`EditTooLarge`);
- операции применяются **в указанном порядке**; каждая валидируется против состояния после предыдущих операций этой же транзакции;
- один и тот же `(owner, type, class)` не может быть целью двух *структурных* операций (`Upsert/Replace/Delete/SetTtl`) в одном `Edit` → `DuplicateTarget`; `AddRecords`/`RemoveRecords` могут повторяться и комбинироваться со структурной операцией, применяясь последовательно (итоговое состояние обязано удовлетворять INV);
- `ReplaceRrset` с пустым `rdata` → `InvalidEdit` (для удаления — `DeleteRrset`); `UpsertRrset` с пустым `rdata` запрещён;
- `DeleteName { subtree: true }` разрешён только для `Import`/`Replication` (API → `IntentForbidden`); реализуется диапазонным удалением, стоимость O(subtree); при превышении лимита `MAX_CUT_SUBTREE_RECORDS` — полная перестройка зоны (`compact_zone`) в той же транзакции;
- `SetZoneMeta` не может изменить `origin`, `ZoneId`, `SOA.serial`; попытка → `InvalidEdit`;
- `SetZoneMeta` пишет meta-блок; сериализованный `ZoneSettingsPatch` ≤ 4 KiB **всего** (inline — по ёмкости страницы: 4016 байт при `page_size=4096`, иначе overflow-страницы до 256 KiB; лимит согласуется с автором формата; превышение → `InvalidEdit`); `forward_upstreams` только для `Forward`-зоны (иначе `InvalidEdit`), в домене ≤ 16 записей (формат допускает 32 — домен строже); смена `denial` требует переподписи — writer лишь сохраняет настройку, переподпись запускает application (job);
- пустой результат набора (удалена последняя запись) означает удаление RRset, а не пустой `Rrset` (§2.5);
- `EditId` уникален в рамках транзакции; повтор → `DuplicateEdit` (защита от ретраев).

#### 5.2.3. `ApplyOutcome` и `CommitOutcome`

```rust
pub struct ApplyOutcome {
    pub txn_id: Txn,
    pub edit_id: EditId,
    pub applied_ops: u32,
    pub counts: ApplyCounts,               // inserted/updated/deleted/unchanged
    pub normalized: Vec<Normalization>,    // TtlNormalized, TtlClamped, DuplicateRdataRemoved
    pub warnings: Vec<EditWarning>,
}

pub struct CommitOutcome {
    pub apply: ApplyOutcome,               // агрегат по всем apply этой транзакции
    pub zone: ZoneId,
    pub old_serial: Serial,
    pub new_serial: Serial,
    pub commit_id: CommitId,               // (zone_seq, epoch)
    pub epoch: Epoch,                      // глобальный номер коммита
    pub zone_version: ZoneVersion,         // = epoch; то, что уходит в ETag/If-Match
    pub snapshot: ZoneSnapshot,            // единственная точка публикации
}
```

- `snapshot` — **`ZoneSnapshot`** (пин версии этой зоны), а не глобальный `SnapshotHandle`: публикуется именно версия зоны, и держатель обязан видеть её целиком. Глобальная эпоха доступна как `CommitOutcome.epoch`.
- `zone_version` — монотонная версия зоны; используется для `ETag`, `If-Match` и идемпотентной проверки «применил ли я свою правку».
- `commit_id` = `(zone_seq, epoch)`; строковое представление для API — `z<zone_seq>-e<epoch>`.
- `snapshot` появляется **только** в `CommitOutcome` (`CommitResult::Committed`): до `commit` снапшота не существует (§5.1 «apply не виден читателям»); `CommitResult::Aborted` не публикует ничего (отчётность — по ранее возвращённым `ApplyOutcome`).
- **`deleted_txn` (унификация с форматом):** хранимая `ZoneMeta` — `Option<Txn>`; в записи корня (v2) — `deleted_txn: u64`, 0-сентинел. Маппинг: `None ↔ 0`, `Some(t) ↔ t`, допустимы только `t ≥ 1`; `Some(0)` запрещён (`InvalidEdit` при записи, `Corrupt(BadZoneHead)` при чтении). `deleted_txn` зоны равен `version(zone)` коммита удаления, поэтому сравнение с `MP(z)` корректно. У live-зоны `None`; у tombstone — версия удаления. В `DeleteOutcome` — **всегда `Txn`** (не `Option`): `delete_zone` сам является коммитом, момент удаления существует всегда (`t ≥ 1`); `None` в результате невозможен.
- `commit` атомарно переписывает apex `SOA` (serial = `old_serial.succ()` либо serial из `ReplaceRrset`/`UpsertRrset` SOA, если он новее — RFC 1982) и публикует снапшот; серийный номер и содержимое SOA меняются одной транзакцией (INV-9).
- Гарантия «всё или ничего»: ошибка любой операции → `ApplyOutcome` не возвращается, транзакция переходит в failed; `CommitPolicy::Abort` (или Drop `ZoneWriter`) не оставляет в файле ни одной **опубликованной** страницы транзакции — неопубликованные страницы немедленно возвращаются в per-zone free pool (ADR 0005 A-10), запись корня не меняется. Повторный `commit`/`apply` после ошибки → `UnknownTxn`.
- `MapFull` — исчерпано **адресное пространство файла** (`high_water == page_count_max`): нужен больший `map_size`/пересоздание файла. `NoSpace { zone }` — у **этой зоны** нет выдаваемых страниц: свободные есть, но «молодые» (`drop_txn ≥ D_z` или `> MP(z)`) или их нет вовсе (retryable: повтор после `sync()`/освобождения читателей/`donation`). Оба — ошибка `commit`, файл консистентен на предыдущей версии зоны; частичных изменений нет. Важно: `NoSpace` одной зоны **не** блокирует запись в другие (они берут страницы из bump-фронтира или своих пулов).

#### 5.2.4. Жизненный цикл зоны (`create_zone` / `delete_zone`)

`create_zone` и `delete_zone` — самостоятельные операции **`ZoneStore`** (не `ZoneWriter`): каждая выполняет внутренний коммит, возвращает опубликованное состояние. Активная транзакция в `ZoneWriter` на ту же зону в момент вызова → `Busy` (аренда занята); на другие зоны — не влияет.

| Операция | Что пишет | Сериализация | Ошибки |
|---|---|---|---|
| `create_zone` | каталог (идентичность) + новая запись корня + `root_entry_index` + `next_zone_seq` | каталог-writer (единый) | `Conflict{ZoneExists}`, `IdSpaceExhausted`, `TooManyZones`, `Busy { scope: Catalog }` |
| `delete_zone` | **только запись корня** зоны (tombstone) | аренда зоны | `ZoneNotFound`, `Busy { zone }`, `ReadOnly` |

Это следствие ADR 0005 §3.3/§7.2: мутируемые поля зоны не живут в каталоге, поэтому удаление не требует каталог-коммита и не сериализуется с другими зонами.

```rust
pub struct ZoneOptions {
    pub kind: ZoneKind,
    pub default_ttl: Ttl,
    pub denial: Denial,
    pub initial_soa: Option<SoaData>,      // если Some → initial_ns обязателен
    pub initial_ns: Vec<Rdata>,            // apex NS, 1..=16 (для Primary/Secondary)
    pub forward_upstreams: Vec<UpstreamSpec>, // только Forward, 1..=16
    pub durability: Durability,            // по умолчанию Sync
}
pub struct DeleteOutcome { pub zone: ZoneId, pub deleted_txn: Txn, pub reclaim_after: Txn }
// reclaim_after == deleted_txn: порог условия reclaim, не оценка времени.
```

- **Аллокация:** `create_zone` выделяет стабильный `zone_seq` (§2.7), пишет `ZoneEntry` (`tree_root = 0`, `APEX`-маркер, `meta_root` с `ZoneSettings`), атомарно публикует снапшот. `Conflict { ZoneExists }` — origin уже обслуживается (включая `Initializing`); `IdSpaceExhausted` — исчерпан `u32`. INV-4 (SOA/NS) при создании `Initializing` не применяется (W-11).
- **Состояние после создания:** с `initial_soa`+`initial_ns` та же транзакция пишет apex `SOA`/`NS`, после commit зона `Serving` (apex-only семантика — §2.7). Без них (`Secondary`, ожидающая AXFR; `Primary` без данных) — `Initializing` (DNS `REFUSED`). `Forward` — сразу `Serving` (нужен ≥1 upstream), собственных RRset нет.
- **Идемпотентность:** повторный `create_zone` с теми же параметрами — не идемпотентен по контракту; вызывающий использует `Idempotency-Key` на уровне API.
- **`delete_zone`:** выставляет `Tombstone`, зона немедленно исчезает из `find_zone`/`zones`, DNS → `REFUSED`, API → `404 zone_not_found`; `ZoneId` не переиспользуется. Повторный `delete_zone` → `ZoneNotFound` (не идемпотентен; API идемпотентен на уровне HTTP-семантики `DELETE`). Для `Secondary` отменяет запланированные/идущие трансферы (in-flight `commit` получит `ZoneNotFound`/`UnknownTxn`); для `Forward` удаляет upstream-конфигурацию; для `Primary` — разрешено (API требует `confirm_origin`).
- **Освобождение (N-7):** страницы RRset, meta-блок и сама запись корня освобождаются **только** при `deleted_txn ≤ MP(z)` (для tombstone `deleted_txn == version` зоны, ADR 0005 A-11); никакого вытеснения живого читателя по таймауту нет (SEC-ZF-007). До выполнения условия старые `ZoneSnapshot` читаются без изменений. `reclaim_after` (= `deleted_txn`) — порог условия, не дедлайн и не оценка времени.
- **Кто запускает reclaim:** (а) **GC-проход** (ADR 0005 §6.1) пересчитывает `MP(z)` и возвращает страницы в per-zone free pool; (б) tombstone-зоны освобождаются, когда `deleted_txn ≤ MP(z)`, — тем же проходом; (в) `compact_zone` — полный проход по зоне; (г) `donation` — передача полностью реклеймленных страниц зоны в глобальный пул (GC-проход или maintenance). Отдельного «force GC» нет; проход по требованию инициируется при `NoSpace`.
- **Ограничение работы на коммит:** обычный `commit` не выполняет GC и не сканирует reader table (A-12 ADR 0005); он лишь читает `MP(z)`. Бюджет `MAX_GC_ZONES_PER_GROUP`/`MAX_GC_PAGES_PER_GROUP` относится к maintenance-проходу, а не к коммиту, и не влияет на latency `commit`.
- **Диагностика утечки читателя:** если живой процесс держит пины старой версии, `MP(z)` не растёт → страницы этой зоны и её tombstones не освобождаются → со временем `NoSpace` **только у этой зоны** (другие зоны живут). Это наблюдаемое состояние: метрики `pw_zone_min_pinned{zone}`, `pw_free_pool_starved_total{zone}`, `readers_active`, `no_space_total{zone}`; оператор устраняет застрявший процесс/баг, а не «выдавливает» его. Автоматического eviction нет.
- **Повторное создание origin:** после tombstone разрешено; получает новый `ZoneId`; старый `ZoneId` навсегда `ZoneNotFound`.

#### 5.2.5. Метаданные зоны (`ZoneSettings` / `meta_root`)

Согласовано с автором формата: per-zone metadata хранится в отдельном meta-блоке, ссылка — `ZoneEntry.meta_root`; `tree_root` не используется для настроек.

```rust
pub struct ZoneSettingsPatch {
    pub default_ttl: Option<Ttl>,
    pub denial: Option<Denial>,
    pub soa_timers: Option<SoaTimers>,
    pub forward_upstreams: Option<Vec<UpstreamSpec>>,  // Some(vec![]) = очистить (только Forward)
}
```

- **Формат:** ≤ 4 KiB **всего**; inline — по ёмкости страницы (4016 байт при `page_size=4096`), иначе overflow-страницы; суммарный лимит `MAX_ZONE_META = 256 KiB` (подтверждается вместе с форматом); превышение → `InvalidEdit`/`EditTooLarge`. `ZoneId`, `origin`, `kind`, `SOA.serial` в meta-блок не входят (kind/origin — в `ZoneEntry`, serial — в apex `SOA`).
- **Валидация:** `default_ttl` ≤ `MAX_TTL`; `soa_timers`: `refresh ≥ 1`, `retry ≥ 1`, `expire > refresh + retry` (u64), полные `u32` без clamp (INV-21); `forward_upstreams` ≤ 16 и только для `Forward`; `denial = Nsec3` допустим для импортированных/secondary зон, но не включает NSEC3-подпись (§4.4).
- **Атомарность:** `SetZoneMeta` в одном `Edit`/транзакции с RRset-правками — либо применяются все, либо ни одной; читатели видят старую или новую meta целиком (в рамках снапшота). `commit` не публикует meta и RRset раздельно.
- **Чтение:** `ZoneStore::meta(snap, zone) -> ZoneSettingsRef<'a>` — O(1), zero-copy; серверу не нужно разбирать `SOA`-RDATA и обходить зону, чтобы получить `default_ttl`/`denial`/таймеры.
- **Смена `denial`** сохраняется как настройка; переподпись NSEC→NSEC3 (когда появится в v1.1) выполняет application-job, writer её не инициирует.
- **Единственный путь записи:** `EditOp::SetZoneMeta`. Отдельного метода `set_zone_meta` в порте нет; application-хелпер `apply_zone_meta(zone, patch, durability)` — тонкая обёртка `begin → apply(Edit{SetZoneMeta}) → commit`, без собственной логики.

#### 5.2.6. Обслуживание: `sync` и `compact_zone`

```rust
pub struct CompactOptions { pub durability: Durability }
pub struct CompactOutcome { pub zone: ZoneId, pub pages_before: u32, pub pages_after: u32,
                            pub commit_id: CommitId, pub zone_version: ZoneVersion,
                            pub snapshot: ZoneSnapshot }
pub struct SyncOutcome { pub txn: Epoch, pub durable_zones: u32, pub txn_limit: u64 }
```

- **`sync()`** (на `ZoneStore`, глобальный) — `fdatasync` данных, `ALLOC_RECORD` и ring'ов всех зон, затем `D_z = version[z]` для всех; без изменения содержимого. Обязателен для гарантий после `Durability::Memory` и для прогресса per-zone free pool в `Flush`/`Memory`; идемпотентен; ошибки `Io`/`Corrupt`; **не** возвращает `Busy` за транзакции других зон (он их не отменяет и не ждёт: ring'ы читаются на момент вызова).
- **`compact_zone()`** — одна транзакция зоны (`Sync`/`Flush` по `opts.durability`), атомарно публикует новую версию: переупаковывает дерево зоны, возвращает «мёртвые» байты, перестраивает per-zone free-цепочку, обновляет `tree_root`/`meta_root`/`free_head` **в записи корня зоны**. `ZoneId`/`zone_seq` не меняются, `serial` не меняется (содержимое эквивалентно — клиенты не видят новый serial), подписи остаются валидными. Другие зоны не блокируются (PR-3).
- Читатели во время компакции держат `ZoneSnapshot` старой версии; освобождение старых страниц — по общему правилу `drop_txn ≤ MP(z)` (N-7, ADR 0005 §6.2).
- Ошибки: `Busy { zone }` (аренда занята/активная транзакция), `ZoneNotFound`, `NoSpace { zone }`/`MapFull`, `Corrupt`, `Io`. Компакция блокирующая и может быть длительной — вызывать из maintenance-задачи, не с async reactor-потока.
- `compact_zone` — единственный полный GC-проход **по зоне**; рекламация страниц выполняется GC-проходом (§5.2.4), а не на обычном `commit`.

```rust
pub enum CommitPolicy { Commit(Durability), Abort }
pub enum CommitResult { Committed(CommitOutcome), Aborted }

/// Параметры group commit. Store-уровневые, не на каждый вызов.
pub struct CommitConfig {
    pub max_batch_zones: u16,          // <= MAX_BATCH_ZONES (256)
    pub max_batch_bytes: u32,          // <= MAX_BATCH_BYTES (1 MiB)
    pub max_batch_delay: Duration,     // 0 = публиковать без ожидания (дороже по fsync)
}
/// BusyScope: Zone (аренда зоны), Catalog (create/GC), File (flock, M1).
pub struct WriterOptions {
    pub lease_timeout: Option<Duration>,   // None = Busy сразу
    pub commit_timeout: Duration,          // дефолт 5 s; иначе CommitTimeout
}

/// Фабрика writer'ов и редкие (кросс-зонные) операции. `&self`, `Send + Sync`.
pub trait ZoneStore {
    /// Аренда зоны. Занята → `Busy { zone }` (или ожидание до `lease_timeout`).
    fn writer(&self, zone: ZoneId) -> Result<ZoneWriter, WriteError>;
    fn writer_by_origin(&self, origin: &Origin) -> Result<ZoneWriter, WriteError>;
    fn writer_with(&self, zone: ZoneId, opts: WriterOptions) -> Result<ZoneWriter, WriteError>;

    /// Создание зоны (каталог-коммит). `Conflict{ZoneExists}`, `IdSpaceExhausted`.
    fn create_zone(&self, origin: Origin, class: Class, options: ZoneOptions)
        -> Result<ZoneId, WriteError>;

    /// Удаление зоны (tombstone-коммит записи корня). Повтор → `ZoneNotFound`.
    fn delete_zone(&self, zone: ZoneId) -> Result<DeleteOutcome, WriteError>;

    /// Глобальный чекпойнт: fdatasync данных + корней, поднять D_z всех зон.
    /// Обязателен после серии `Memory`; липко переводит файл в `Sync`.
    fn sync(&self) -> Result<SyncOutcome, WriteError>;

    fn commit_config(&self) -> CommitConfig;
    fn set_commit_config(&self, cfg: CommitConfig) -> Result<(), WriteError>;
}

/// Один экземпляр = аренда одной зоны. `Send`, не `Sync`, не `Clone`.
/// Drop без `commit` = `Abort` + освобождение аренды.
pub trait ZoneWriter: Send {
    fn zone(&self) -> ZoneId;
    /// Версия зоны, от которой открыта (или была открыта) транзакция.
    fn base_version(&self) -> ZoneVersion;

    /// Применяет `Edit`. Первый вызов открывает неявную транзакцию с `intent`;
    /// последующие должны совпадать по `intent`, иначе `Busy`.
    fn apply(&mut self, intent: WriteIntent, edit: Edit)
        -> Result<ApplyOutcome, WriteError>;

    /// Завершает неявную транзакцию: `Commit(durability)` или `Abort`.
    /// Нет активной транзакции → `UnknownTxn`.
    fn commit(&mut self, policy: CommitPolicy)
        -> Result<CommitResult, WriteError>;

    /// Полный GC/дефрагментация зоны (одна транзакция; `ZoneId`/serial не меняются).
    fn compact_zone(&mut self, opts: CompactOptions)
        -> Result<CompactOutcome, WriteError>;
}
```

Правила:
1. **Аренда.** `writer(zone)` либо даёт эксклюзивную аренду, либо `Busy { zone }`; аренда снимается на `Drop` (в т.ч. после паники — через `DropGuard`) и при завершении процесса. Один экземпляр `ZoneWriter` — одна зона; параллельная запись в разные зоны — это `N` экземпляров в `N` потоках.
2. `create_zone`/`delete_zone`/`sync` — на `ZoneStore`, не на `ZoneWriter`: они не являются транзакцией одной зоны (`delete_zone` берёт аренду внутри себя).
3. Одновременно у экземпляра активна максимум одна неявная транзакция; `compact_zone` при активной транзакции → `Busy`; `apply` после `Abort`/`Commit` начинает новую.
4. Владение на уровне архитектуры: пул writer-потоков (`pulse-server`) + один maintenance-поток для `sync()`/GC/`freeze()` (см. ADR 0005 §4, §12 и `io-uring-runtime` §2.1). Отдельного «глобального писателя» больше нет.

```rust
pub enum Durability { Memory, Flush, Sync }
// Конкретные режимы (ADR 0003 §5.2); msync на пути коммита не используется.
```

| Режим | Что делает (group commit) | Durability | Карта режима |
|---|---|---|---|
| `Sync` | `fdatasync` данных пачки + `ALLOC_RECORD` → запись ring'ов пачки → `fdatasync` корней | подтверждённый коммит переживает power loss | `MODE_SYNC` |
| `Flush` | `fdatasync` данных + `ALLOC_RECORD` → запись корней **без** отдельного fsync | данные на диске; корни коммита не форсируются — durability достигается на **следующем `Sync`**; переживает рестарт процесса | `MODE_NOMETASYNC` |
| `Memory` | только запись в page cache | виден читателям процесса; ничего не гарантируется на диске | `MODE_NOSYNC` |

> **Предупреждения.** `Memory` теряет **подтверждённые** коммиты при падении процесса (не только при потере питания). `Flush` переживает падение процесса, но при потере питания/сбое ОС корни могут откатиться к предыдущей валидной версии **по каждой зоне независимо** — файл останется валидным, «откат» будет неравномерным по зонам. После первого `sync()` файл навсегда `Sync` (ADR 0005 §5.2).

**Гарантии:**
- **Изоляция зон — производительная, не security** (PW-L2): любой writer в процессе технически может записать любую страницу; `owner_zone` ловит аварию, не атаку. Реальная изоляция — отдельные процессы/uid (roadmap).
- **Много писателей по разным зонам, один — на зону.** `ZoneWriter` не `Clone`/не `Sync`; эксклюзивность обеспечивает аренда (`Busy` только по той же зоне). `apply` с другим `intent` → `WriteError::Busy`. Параллельные правки разных зон не сериализуются (нет общего лоcка, общего meta-слота, общего freelist).
- `apply` не виден читателям до `commit`; чтение страницы с чужим `owner_zone` → `Corrupt` (кросс-зонный ABA закрыт).
- `commit` **атомарен и crash-safe в области одной зоны**: COW-страницы по новым номерам, публикация — запись версии корня зоны (`version` + CRC) после fsync данных; либо версия `V` видна целиком, либо `V-1`. Кросс-зонная атомарность не предоставляется. WAL/журнала нет (ADR 0003 §5.1–5.2, §8.5; ADR 0005 §5).
- `commit` с `Durability::Sync` возвращается только после гарантии сохранности на диске (в составе пачки group commit — латентность включает ожидание пачки ≤ `max_batch_delay`); `Flush` — после `fdatasync` данных; `Memory` — только публикация в памяти.
- После успешного `commit` любой последующий `zone_snapshot(zone)` возвращает версию `≥ zone_version` этой транзакции (happens-before через release/acquire). Глобальный `snapshot()` не обязан видеть все зоны одной эпохи — это осознанно (ADR 0005 §7).
- В M1 (один процесс) писатели берут `flock(LOCK_EX)` на `<zonefile>.lock` — второй **процесс** получает `Busy { scope: File }`; в M3 (SEC-PW-009) — `LOCK_SH` для набора писателей + recovery `LOCK_EX`, и `Busy` на файл исчезает (PW-L6). Аренда зоны (in-memory) действует в обоих режимах.
- `apply`/`commit` **блокирующие** (mmap I/O + `fdatasync` в режиме `Sync` + ожидание пачки). Application обязан вызывать их в blocking-контексте (`spawn_blocking` или выделенный поток); вызов на async reactor-потоке — ошибка реализации.
- `Edit` содержит `EditId`; повторное применение того же `EditId` в рамках транзакции → `WriteError::DuplicateEdit` (защита от ретраев). `Edit.precondition` проверяется внутри аренды до применения (TOCTOU закрыт).
- `commit` может вернуть `CommitTimeout` (координатор не ответил) — файл не изменён, транзакция завершена как aborted, повтор допустим с новым `Edit`.

**Ошибки:** `WriteError::{Busy { zone: Option<ZoneId>, scope: BusyScope }, UnknownTxn, ReadOnly { reason: ReadOnlyReason }, ZoneNotFound, NotFound, Conflict { kind }, InvariantViolation { id, detail }, EditEmpty, EditTooLarge, DuplicateTarget, InvalidEdit, IntentForbidden, SerialConflict, PreconditionFailed { current: ZoneVersion, current_etag }, IdSpaceExhausted, MapFull, NoSpace { zone: ZoneId }, CommitTimeout { waited_ms: u32 }, ZoneWriterStalled { zone: ZoneId }, EpochPinned { epoch: u64, holders: u16 }, TooManyZones, ZoneQuotaExceeded, CommitAborted, DuplicateEdit, Io { source }, Corrupt { kind: CorruptKind, zone: Option<ZoneId>, page: Option<u32> }}`.

Семантика: `Busy` — аренда зоны занята (`scope = Zone`) или каталог занят create/GC (`scope = Catalog`), retryable; `ReadOnly` — файл открыт только для чтения, `reason = ConvertRequired` для v1-файла; `InvariantViolation` — нарушен INV-1..12; `ZoneNotFound` — зоны нет/Tombstone; `UnknownTxn` — `commit` без активной неявной транзакции; `Conflict` — `ZoneExists`, ожидаемое состояние не совпало; `PreconditionFailed` — `Edit.precondition` не совпал (HTTP 412), файл не изменён; `IdSpaceExhausted` — исчерпан `zone_seq`; `MapFull` — `high_water == page_count_max`, нужно расширение файла; `NoSpace` — у **этой** зоны нет выдаваемых страниц (retryable после `sync()`/GC/donation); `CommitTimeout` — координатор group commit не ответил за `commit_timeout`; `ZoneWriterStalled` — ring корней зоны исчерпан живыми пинами (все 4 версии `≥ MP(z)`), retryable и **только для этой зоны**; `TooManyZones` — исчерпана ёмкость root directory/ring (`max_zones`), нужен offline compact; `ZoneQuotaExceeded` — зона превысила `ZONE_PAGE_QUOTA_RATIO × page_count_max` (нужен `compact_zone`, другие зоны пишутся); `CommitAborted` — группа не опубликована (смерть/смена лидера, не пройден барьер `DP`/`DT`), retryable; `EpochPinned` — операция требует глобального среза, а пины держат эпоху (только `freeze`/checkpoint/reshape; обычный `commit` его не возвращает); `Corrupt` — структурированная причина с опциональной зоной.
**Отмена:** незавершённая транзакция отбрасывается `CommitPolicy::Abort` или Drop `ZoneWriter` (метрика `dangling_txn_total`); неопубликованные страницы немедленно возвращаются в per-zone free pool, частичных изменений в файле не остаётся.

### 5.3. `UpstreamClient` — сетевой DNS-клиент (резолвер и secondary)

```rust
#[async_trait]
pub trait UpstreamClient: Send + Sync {
    async fn query(&self, q: Query, opts: QueryOpts) -> Result<UpstreamResponse, UpstreamError>;

    /// Трансфер зоны: bounded mpsc (backpressure), поток чанков.
    fn transfer(&self, req: TransferRequest) -> mpsc::Receiver<Result<TransferChunk, TransferError>>;
}
pub struct QueryOpts { pub timeout: Duration, pub edns: Option<EdnsOpts>, pub tsig: Option<TsigKeyRef>,
                       pub source: Option<IpAddr>, pub tcp_only: bool }
pub struct UpstreamResponse { pub rcode: Rcode, pub answer: Vec<Record>, pub authority: Vec<Record>,
                              pub additional: Vec<Record>, pub edns: Option<EdnsResponse>, pub rtt: Duration }
```
- `query`: таймаут соблюдается адаптером; отмена future = отмена запроса (UDP) или закрытие соединения (TCP).
- Идемпотентность: `query` можно повторять; ретраи — на стороне вызывающего (application), с джиттером.
- `transfer`: канал ёмкостью ≥ 1, отправитель блокируется/приостанавливается при заполнении (backpressure обязателен: зона может быть гигабайтной). `TransferChunk::{Soa(Record), Rrset(Rrset), End{serial}}`. Получатель обязан применить чанки до `End` в одной транзакции, затем `commit`.
- **Ошибки:** `UpstreamError::{Timeout, Network, Malformed, Refused, ServFail, FormErr, NotAuth, Tsig, DnssecBogus, Cancelled}`; `TransferError::{Refused, NoAxfr, BadSerial, Tsig, Truncated, RateLimited, Io}`.
- **Конкурентность:** `&self`-методы, много параллельных запросов; реализация обязана иметь пул соединений и лимит in-flight (не более `MAX_INFLIGHT`, по умолчанию 1024).

### 5.4. `Clock`

```rust
pub trait Clock: Send + Sync {
    fn now(&self) -> Timestamp;        // wall clock, UTC, секунды/наносекунды
    fn monotonic(&self) -> Mono;       // для RTT/таймеров
}
```
- Домен получает время только значением; никаких `SystemTime::now()` в `domain/`.
- Тесты используют `FixedClock` с возможностью `advance(d)`; `advance` — метод тестового адаптера, не порта.
- Требование к монотонности: `monotonic()` не убывает даже при переводе часов; TTL/expiry считаются по `now()`, таймауты — по `monotonic()`.

### 5.5. `Metrics`

```rust
pub trait Metrics: Send + Sync {
    fn counter(&self, name: &'static str, labels: &[(&'static str, &str)], delta: u64);
    fn gauge(&self, name: &'static str, labels: &[(&'static str, &str)], value: i64);
    fn histogram(&self, name: &'static str, labels: &[(&'static str, &str)], value: f64);
    fn timer(&self, name: &'static str) -> TimerGuard<'_>;   // RAII, hist в секундах
}
```
- Имена метрик и ключи меток — `&'static str` из **предобъявленного реестра**; значения могут быть динамическими (`&str`), но обязаны иметь ограниченную кардинальность (например, `zone` — только обслуживаемые зоны, значения интернируются реализацией, чтобы не аллоцировать на hot-path).
- Вызов должен быть неблокирующим и без аллокаций на hot-path.
- **Запрещены метки с qname/origin/IP-адресом клиента** (взрыв кардинальности). Разрешены: `zone` (ограниченный набор), `qtype`, `rcode`, `transport`, `result`.
- Неизвестная метрика в production-режиме — `debug!`-лог адаптера и счётчик `metrics_unknown_total`, не паника.

### 5.6. `Authorizer`

Объявляется в `pulse-api::application::port` (см. ADR 0002 §4.2) — это порт **контрольной плоскости**. DNS-плоскость аутентификацией токенов не занимается: доступ к трансферам/зонам ограничивается `AclRule` и TSIG на транспорте.

```rust
pub trait Authorizer: Send + Sync {
    fn authenticate(&self, credential: &Credential) -> Result<Principal, AuthError>;
    fn authorize(&self, principal: &Principal, action: Action, resource: &ResourceRef)
        -> Result<(), AuthError>;
}
pub struct Principal { pub id: PrincipalId, pub roles: Vec<Role>, pub scopes: ScopeSet }
```
- Синхронный: верификация токена идёт по локальному кешу (токены хранятся хешированными в конфиге/БД), JWKS-обновление — фоновой задачей адаптера, не в hot-path.
- `authenticate` отличает `Invalid` (401) от `Expired` (401 + `WWW-Authenticate`) и `Locked` (423).
- `authorize` — чистая проверка `scopes ⊇ required(action)` плюс ресурсная область (зона/префикс). Возвращает `Forbidden` без утечки деталей (не раскрывать существование ресурса при отсутствии прав).
- Аудит: каждое решение `authorize` с `deny` публикуется в `AuditSink` (порт объявлен в `pulse-api`, см. ADR 0002); домен аудита не знает.

### 5.7. `SecretStore`

```rust
#[async_trait]
pub trait SecretStore: Send + Sync {
    async fn get(&self, r: &SecretRef) -> Result<Secret, SecretError>;
    async fn put(&self, r: &SecretRef, s: Secret, meta: SecretMeta) -> Result<SecretVersion, SecretError>;
    async fn rotate(&self, r: &SecretRef) -> Result<SecretVersion, SecretError>;
    async fn delete(&self, r: &SecretRef) -> Result<(), SecretError>;
}
pub struct Secret(/* zeroize on drop; no Clone, no Debug, no Serialize */);
```
- `Secret` не реализует `Debug`/`Display`/`Serialize`; при `Drop` — `zeroize`. Логирование материала запрещено на уровне типов.
- **Backend v1:** каталог `0700`, файлы `0600`, атомарная запись (temp + `fsync` + rename), версия секрета в имени/заголовке. PKCS#11 и внешний KMS — roadmap; порт от них не меняется (ADR 0004).
- `get` — асинхронный (на случай будущего KMS); реализация обязана кешировать на короткое время с явной инвалидацией по `SecretVersion`.
- Ошибки: `SecretError::{NotFound, AccessDenied, Backend, Corrupt, UnsupportedVersion}`.
- Все операции пишутся в аудит (кто, какой `SecretRef`, какая версия) — без значения секрета.

### 5.8. Дополнительные порты (объявляются контекстами, не входят в список выше)

| Порт | Крейт | Назначение |
|---|---|---|
| `SnapshotPublisher` | `pulse-zonefile` (internal) | Публикация нового снапшота после `commit`; не публичный порт контекста |
| `Signer` / `Verifier` | `pulse-dns` (trait), реализация в `pulse-server` | Криптография DNSSEC; домен не работает с ключевым материалом напрямую |
| `Timer` / `Spawner` | `pulse-runtime` | Таймеры и фоновые задачи для application-слоя |
| `AuditSink` | `pulse-api::application::port` | Аудит управляющих операций |
| `JobQueue` | `pulse-api::application::port` | Асинхронные операции (202 + job id) |
| `ChangeFeed` | `pulse-server::application::port` | Публикация `ZoneChanged` для NOTIFY-out и инвалидации кеша |
| `ServerStateRepository` | `pulse-server::application::port` | Атомарная загрузка/сохранение `TransferState`/`Peer`/ключей в state-файле state-dir: JSON + `schema_version`, temp+fsync+rename, отказ при неизвестной версии, миграции `vN→vN+1`, ≤ 32 MiB, только `SecretRef` (спецификация — `docs/spec/server-state-v1.md`, M3) |

`ChangeFeed` событие:
```rust
pub struct ZoneChanged { pub zone: ZoneId, pub origin: Origin, pub old: Serial, pub new: Serial,
                         pub kind: ChangeKind /* Created|Updated|Deleted|Transferred */ }
```

---

## 6. Anti-Corruption Layer (ACL)

Домен не знает о бинарном формате, mmap и wire-байтах. Границы ACL:

| Что снаружи | Что внутри домена | Где трансляция |
|---|---|---|
| Байты mmap, offset'ы, `memmap2::Mmap`, указатели | `ZoneSnapshot`, `RrsetRef`, `ZoneSettingsRef`, `Record` | `pulse-zonefile::infrastructure::{pager,btree,meta,readers}` |
| Wire-формат пакета (`&[u8]` с compression pointers) | `Question`, `Record`, `Rdata` | `pulse-dns::wire::decoder` |
| HTTP JSON, path-параметры, проблемные документы | команды application (`UpsertRrset`, `CreateZone`) | `pulse-api::interface::http::mapper` |
| Заголовки DNS-транспорта (TSIG MAC, TSIG-ошибки) | `TsigVerification` (VO) | `pulse-server::infrastructure::transport` |
| Ошибки внешних библиотек (`io::Error`, `hyper::Error`, `h2::Error`) | `StoreError`, `UpstreamError`, `AuthError` | адаптер, через `From` в один `ApplicationError` |
| Конфигурация (TOML/env) | типизированные настройки application | composition root (бинарник) |

Правила ACL:
1. **Ни один тип из `memmap2`, `io-uring`, `hyper`, `axum`, `reqwest`, `rustls` не появляется в `domain`/`application`.** Проверяется линтом по `use`-дереву и `cargo tree`-ограничением фич.
2. **Ошибки переводятся, а не заворачиваются.** `StoreError::Corrupt` → `ApplicationError::Unavailable` (не 500 с текстом io-ошибки); детали — в лог, не в ответ.
3. **Версионирование на границе:** reader проверяет `format_version` до построения доменных типов; неизвестная версия — `UnsupportedVersion`, а не «попробуем прочитать».
4. **Валидация на входе, а не на выходе.** Любые данные из wire/файла проходят через валидирующие конструкторы домена; доверенных байтов не существует.
5. **Домен не возвращает offset'ы и длины.** Если нужен zero-copy, наружу отдаётся `&[u8]`-слайс с lifetime снапшота, но без числовых смещений (смещение — внутренняя деталь).

**Отображение ошибок формата (без потери причины):**

| Ошибка `pulse-zonefile` | Доменная ошибка |
|---|---|
| `CorruptNoValidMeta`, `PageChecksum`, `TreeOrder`, `Bounds`, `FreelistCycle`, `BadTtl`, `BadZoneMeta`, `BadRdata`, `BadName`, `BadZoneHead` | `StoreError::Corrupt { kind, zone, page }` |
| `UnsupportedVersion { found }` | `StoreError::UnsupportedVersion { found, supported }` |
| `ENOSPC` / все свободные страницы зоны «молодые» и не выдаются в текущей txn | `WriteError::NoSpace { zone }` (retryable после `sync`/GC/donation; файл консистентен, другие зоны пишутся) |
| `high_water == page_count_max` (адресное пространство исчерпано) | `WriteError::MapFull` (нужно расширение `map_size`/пересоздание) |
| `flock(LOCK_EX)` занят другим процессом-писателем | `WriteError::Busy { scope: File }` (читатели flock не берут) |
| Аренда зоны занята другим `ZoneWriter` | `WriteError::Busy { zone: Some(z), scope: Zone }` (retryable) |
| Каталог занят `create_zone`/GC | `WriteError::Busy { scope: Catalog }` |
| В ring+chain нет валидной версии (порча/пересоздание зоны) | `StoreError::StaleRoot { zone, requested, oldest_retained }` (retryable после `fsck`/нового `snapshot()`) |
| Файл v1 открыт для записи | `WriteError::ReadOnly { reason: ConvertRequired }` |
| `page_limit`/`txn_limit` понизились при open | `StoreError::Corrupt { kind: Bounds }` + `NEEDS_FSCK` + read-only (метрика `pw_alloc_watermark_regression_total`) |
| `PageHeader.owner_zone ≠ zone_seq` при чтении | `StoreError::Corrupt { kind: BadZoneHead, zone, page }` |
| Исчерпана reader table | `StoreError::TooManyReaders` |
| Исчерпан `zone_seq` | `IdSpaceExhausted` |
| `io::Error` | `Io { source }` (source сохраняется, наружу не отдаётся) |
| Прочее внутреннее | `Internal` + `tracing::error` с контекстом (зона, версия, страница) |

Причина сохраняется структурированно (`kind`, `page`, `found/supported`, `source()`), строки ошибок не парсятся; HTTP-слой отдаёт generic `problem+json` без деталей (ADR 0004 SEC-API-011).

**Единый набор `CorruptKind` (источник истины; §20.4 спеки формата сопоставляет свои имена):**

| `CorruptKind` | Причина | Смысл |
|---|---|---|
| `NoValidMeta` | `CorruptNoValidMeta` | обе meta-копии невалидны |
| `PageChecksum` | `PageChecksum` / CRC | CRC страницы/заголовка не сходится |
| `TreeOrder` | `TreeOrder` | нарушен канонический порядок ключей |
| `Bounds` | `Bounds` / `OffsetOutOfRange` | смещение/длина вне файла |
| `FreelistCycle` | `FreelistCycle` / `FreelistOverlap` | цикл или пересечение freelist |
| `BadTtl` | `BadTtl` | TTL > `0x7FFF_FFFF` в бинарном файле |
| `BadZoneMeta` | `BadZoneMeta` | meta-блок битый/неизвестная версия |
| `BadRdata` | `BadRdata` | RDATA/overflow-цепочка некорректны |
| `BadName` | `BadName` | RLE-имя/метки некорректны |
| `BadZoneHead` | `BadZoneHead` | обе версии записи корня невалидны или корень не соответствует каталогу (порча локализована зоной) |

---

## 7. Матрица тестов домена

| Группа | Обязательные кейсы |
|---|---|
| `Name` | максимальная длина 255/256, метка 63/64, IDN-punycode как opaque ASCII, сравнение case-insensitive, канонический порядок RFC 4034 |
| `Serial` | `0 vs 1`, `1 vs 0`, `2^31−1 vs 0`, ровно `2^31` → `None`, `u32::MAX vs 0`, IXFR-диапазон |
| `Rrset` | дубликаты RDATA, разный TTL, пустой набор, merge/subtract, канонический порядок |
| `Zone` | apex SOA/NS, CNAME-конфликт, DNAME, wildcard, owner вне origin, два SOA, отсутствие SOA |
| Lookup | 12 RFC-кейсов wildcard (4592), DNAME-синтез (6672), referral + DS, glue, CNAME-цепочка 16/17, NXDOMAIN vs NODATA |
| `CacheEntry` | negative TTL cap, истечение, bogus-кеш, TTL не продлевается |
| `TransferState` | все разрешённые переходы, все запрещённые, expire во время `Transferring` |
| `Key` | окна вне порядка, `Removed` терминален, rollover-план |
| `Policy` | `Allow` доминирует, приоритеты, regex-таймаут (не более 1 ms на правило) |
| Lifecycle | `create_zone` без SOA → `Initializing`/`REFUSED`; apex-only → `NODATA`/`NXDOMAIN`; `delete_zone` → `REFUSED`/404; повторное создание origin → новый `ZoneId`; `IdSpaceExhausted` |
| TTL | wire `0x8000_0001` → `0x7FFF_FFFF` + `TTL_NORMALIZED` (не `1`); бинарный файл `0x8000_0001` → `Corrupt(BadTtl)`; import — clamp + warning |
| RDATA-wire | TXT `[""]`/`["",""]`/256-байтный сегмент/`RDLENGTH=0`; SOA `minimum=0xFFFF_FFFF` не clamp’ится; CAA тег `iSSue` сохраняет регистр и сравнивается case-insensitive; NSEC3 пустой bitmap валиден, NSEC пустой — `BadRdata`; RRSIG `original_ttl=0x8000_0001` round-trip без clamp |
| 0x20 | ответ эхом повторяет сырые байты QNAME (регистр), сравнение case-insensitive; `Name` остаётся lower-case (M3, SEC-DNS-011) |
| Compression | указатель в заголовок / в середину метки / вперёд / цикл → `FORMERR`, без паники и без чтения за границей |
| Meta | `SetZoneMeta` ≤4 KiB всего (inline 4016 при page_size=4096) → overflow; >256 KiB → `EditTooLarge`; атомарность с RRset; `forward_upstreams` только Forward |
| Space | все страницы «молодые» → `NoSpace` (retryable); `high_water == page_count_max` → `MapFull`; различие сохраняется в маппинге |
| RRSIG | `lookup_all` фильтр по `subtype`; DO=0 не добавляет; signed+DO без подписи → `SERVFAIL`; expired — отдаётся + метрика |
| `enumerate` | zero-copy (нет аллокаций RDATA), `Break`→cursor→продолжение без потерь/дублей, ошибка посреди → `Err` без частичной зоны |
| Параллельные писатели | 8 зон × 8 потоков одновременно: все коммиты успешны, ни одна зона не видит чужую правку, кросс-зонной блокировки нет; 8 потоков на одну зону → 7 × `Busy`; `loom`-модель пина/рекламации и публикации корня |
| Аренда | `writer()` → `Busy` при занятой зоне; Drop освобождает; после паники аренда снимается (`DropGuard`); `compact_zone` держит аренду только своей зоны (другие пишутся) |
| Снапшоты | `zone_snapshot` берёт последнюю версию и держит её: страницы не переиспользуются до Drop; `StaleRoot` только при отсутствии валидной версии/пересоздании; `ZoneSnapshot` переживает удаление зоны; ceiling = ∞ (кросс-зонная согласованность не обещана, для среза — `freeze()`); 8 отказов пина: guard → `ZoneDegraded`, churn → `ReaderContended` |
| Precondition | `IfZoneVersion`/`IfRrsetEtag` проверяются внутри аренды: конкурентная правка → `PreconditionFailed` (412), файл не изменён; TOCTOU-окно отсутствует |
| Group commit | несколько зон в одной пачке: `txn` уникальны и возрастают, порядок корней внутри пачки не важен, при `kill -9` координатора каждая зона на своей max-valid версии (F2-9 ADR 0005) |
