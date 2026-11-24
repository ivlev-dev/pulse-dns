# REST API v1 (pulse-dns)

- **Версия API:** `v1` (префикс `/api/v1`)
- **Статус:** спецификация к реализации
- **Транспорт:** HTTP/1.1 и HTTP/2 (h2c запрещён, только поверх TLS, если TLS включён)
- **Связанные документы:** `docs/adr/0001-ddd-architecture.md`, `docs/spec/domain-model.md`, `docs/adr/0002-crate-map.md`

---

## 1. Общие принципы

| Аспект | Правило |
|---|---|
| Base URL | `https://<host>:<port>/api/v1` (по умолчанию bind `127.0.0.1:8080`, TLS выключен; допустим Unix-socket; внешний bind — только явным флагом и с TLS, ADR 0004 SEC-API-001) |
| Формат | JSON UTF-8 (`application/json`), проблемные ответы — `application/problem+json` (RFC 9457) |
| Имена полей | `snake_case`; DNS-имена — всегда в **канонической презентации с завершающей точкой** (`example.com.`) |
| Типы DNS | `UPPER_CASE` (`A`, `AAAA`, `CNAME`, `TXT`, `SVCB`) |
| RDATA | Presentation-формат RFC 1035 (строка, как в zonefile), для неизвестных типов — `\# <len> <hex>` (RFC 3597) |
| Время | RFC 3339 UTC с миллисекундами: `2026-11-23T18:04:05.123Z` |
| Длительности | целое число секунд (`ttl`, `refresh`), строки с суффиксом только в настройках (`"5m"`, `"1h"` — если указано явно) |
| Serial | беззнаковое 32-битное число; сравнение всегда по RFC 1982 (см. `docs/spec/domain-model.md` §2.6) |
| ID | зоны адресуются по `origin` в path; прочие сущности — по непрозрачным строковым id (`job_...`, `key_...`, `peer_...`, `rule_...`) |
| Path-кодирование | `origin`/`owner` percent-encoded; `@` в `owner` означает apex зоны |
| CORS | отключён (веб-UI нет, cookies не используются) |
| CSRF | не применим (только `Authorization: Bearer`, без cookie-сессий) |
| Трейсинг | `X-Request-Id` (входящий принимается, иначе генерируется `req_<ulid>`), `traceparent` (W3C) пробрасывается |
| Сжатие | `gzip` для ответов > 1 KiB при `Accept-Encoding: gzip` |
| Кэширование ответов | `GET` отдаёт `ETag`; поддерживается `If-None-Match` → `304` |

### 1.1. Профили инстанса

`pulsed` (authoritative) и `pulseresolved` (recursive) поднимают **подмножества** API. Недоступная группа возвращает `404` (не `501`). Фактический набор групп — в `GET /api/v1/capabilities`:

```json
{
  "version": "1.0.0",
  "groups": {
    "zones": true, "rrsets": true, "replication": true, "keys": true,
    "resolver_cache": false, "policy": false, "server_settings": true,
    "metrics": true, "jobs": true
  },
  "features": { "dnssec": true, "axfr": true, "ixfr": true, "notify": true, "ecs": false,
                "dnssec_denial": ["nsec"], "dnssec_denial_validation": ["nsec", "nsec3"] }
}
```

`features.dnssec_denial` — что процесс умеет **подписывать** (v1: только `nsec`); `dnssec_denial_validation` — что умеет валидировать (оба). Каждый процесс имеет собственные `jobs`, аудит, хранилище токенов и `/metrics`; кросс-процессной агрегации в v1 нет — Prometheus опрашивает оба инстанса.

---

## 2. Аутентификация и авторизация

### 2.1. Bearer-токены

```
Authorization: Bearer pd_live_7Q2m...   # непрозрачный токен, префикс pd_<env>_
```
- Токены хранятся на сервере **только в виде хеша**: 256-битное CSPRNG-значение, в хранилище — SHA-256 + публичный префикс-ID, сравнение constant-time (ADR 0004 SEC-CR-010, SEC-API-002). Argon2id применяется только к паролям людей, которых в v1 нет. В API токен не возвращается после создания.
- Срок жизни задаётся при создании токена (`expires_at`, опционально). Истёкший → `401` + `WWW-Authenticate: Bearer error="invalid_token", error_description="expired"`.
- Ротация: `POST /api/v1/auth/tokens/{id}/rotate` создаёт новый секрет и инвалидирует старый (окно перекрытия 300 с).
- Первый административный токен при пустом хранилище — bootstrap через env, см. §2.6.
- Токен **не** даёт прав на DNS-порт; это независимые плоскости.

### 2.2. Scopes

| Scope | Права |
|---|---|
| `zones:read` | чтение зон, RRset, serial, transfer-статуса |
| `zones:write` | создание/изменение зон, RRset, serial bump, reload, import; экспорт — только с `zones:export` |
| `zones:delete` | удаление зон (только `operator`/`admin`) |
| `zones:export` | экспорт зон целиком |
| `replication:read` | чтение peers, состояния трансферов, истории NOTIFY |
| `replication:manage` | запуск AXFR/IXFR-in, отправка NOTIFY, CRUD peers, TSIG-ключи трансфера |
| `keys:read` | чтение ключей, DS, статуса подписи |
| `keys:write` | генерация/активация/retire/rollover ключей, включение подписи |
| `keys:export` | экспорт приватного ключа (в v1 endpoint отсутствует; scope зарезервирован под ADR 0004 SEC-API-013) |
| `cache:read` | статистика и (опционально) дамп кеша |
| `cache:purge` | очистка кеша |
| `policy:read` | правила, blocklist'ы, overrides |
| `policy:write` | изменение правил, blocklist'ов, overrides |
| `server:read` | настройки сервера, статус, версия |
| `server:write` | изменение настроек, reload конфигурации |
| `metrics:read` | метрики |
| `jobs:read` | чтение статуса jobs |
| `jobs:cancel` | отмена jobs |
| `audit:read` | чтение аудит-журнала (глобальный endpoint; `admin`/`audit:read`) |
| `tokens:admin` | управление токенами (только для `admin`) |
| `admin` | синоним `*`: полный доступ, включая `tokens:admin` (ADR 0004) |

Синтаксис: точный scope, `group:*` (например `zones:*`), `*` (полный доступ; только роль `admin`).
Неизвестный scope в токене → токен отклоняется при загрузке (`401`).

Соответствие ADR 0004 (SEC-API-002): базовый набор `zones:read|write|delete`, `keys:read|write`, `replication:manage`, `admin` сохранён; `zones:export`, `replication:read`, `cache:*`, `policy:*`, `server:*`, `metrics:read`, `jobs:*`, `tokens:admin` — уточняющие scopes v1, которые **не ослабляют** требования ADR 0004 (каждый мутирующий доступ по-прежнему требует явного scope).

### 2.3. Роли (RBAC)

Роль — именованный набор scopes; токен получает одну или несколько ролей.

| Роль | Scopes |
|---|---|
| `viewer` | `zones:read`, `replication:read`, `keys:read`, `cache:read`, `policy:read`, `server:read`, `metrics:read`, `jobs:read` |
| `zone-editor` | `viewer` + `zones:write`, `zones:export`, `cache:purge`, `policy:write`, `jobs:cancel` |
| `dnssec-admin` | `viewer` + `keys:write`, `jobs:cancel` |
| `replication-admin` | `viewer` + `replication:manage`, `jobs:cancel` |
| `operator` | `zone-editor` + `dnssec-admin` + `replication:manage` + `zones:delete` + `server:write` |
| `admin` | `*` (включая `tokens:admin`) |

Ресурсное сужение (`zone_scope`, ADR 0004 SEC-API-002/014): поле токена — список origin-шаблонов (`example.com.`, `*.internal.`). Порядок проверок: **authenticate → zone allowlist → operation scope → resource existence**; out-of-scope зона завершает запрос до любого lookup ресурса.

| Ситуация | Код | Поведение |
|---|---|---|
| Нет/битый/просроченный токен | `401` | generic + `WWW-Authenticate: Bearer`; аудит `auth_failed` |
| Zone-scoped endpoint, зона вне allowlist | `404` | ответ **побайтово неотличим** от несуществующей зоны (тот же статус, тело, `code: zone_not_found`, заголовки); аудит `denied_zone_out_of_scope` |
| Zone-scoped endpoint, зона в allowlist, нет operation-scope | `403` | generic, без имён зон; аудит `denied_scope` |
| Zone-scoped endpoint, зона в allowlist, ресурс отсутствует | `404` | `zone_not_found`; аудит `not_found` |
| `GET /zones` и коллекции | `200` | только зоны из allowlist; фильтр по чужой/несуществующей зоне → пустой список (не `403`) |
| `POST /zones` вне allowlist | `403` | проверка **до** existence; никогда `409` |
| `/zones/{z}/keys` вне allowlist | `404` | как несуществующая зона |
| Key export в allowlist без `keys:export`/mTLS/re-auth | `403`/`401` | экспорт в v1 не реализован; правило действует при включении |
| Глобальные endpoints (replication/audit/admin/tokens) без scope | `403` | generic; аудит `denied_scope` |

- `zone_scope` применяется и к `zones:delete`, и к `keys:*`. Отсутствие поля = доступ ко всем зонам (bootstrap-совместимость).
- Out-of-scope и несуществующая зона неразличимы: никаких имён других зон, списков allowlist и подсказок; `403`/`401` также без имён зон.
- Bulk-операции: per-item `404` для out-of-scope, без агрегированного «forbidden»-списка.
- `Idempotency-Key` для denied-запросов (`403`/`404`) не сохраняется (исключение probing через повтор).
- Аудит фиксирует `denied_zone_out_of_scope` даже при внешнем `404`; метрика `api_denied_zone_out_of_scope_total`, алерт на всплеск.

### 2.4. mTLS для репликации

- Взаимодействие primary ↔ secondary на уровне **управления** (триггер трансфера, запрос статуса у peer'а) идёт по HTTPS с mTLS (клиентский сертификат из `replication.trust_bundle`).
- TSIG остаётся обязательным для **DNS-трансферов** (AXFR/IXFR/NOTIFY) — mTLS не заменяет TSIG.
- CN/SAN клиентского сертификата должен совпасть с `peer.fingerprint` (SHA-256 отпечаток сертификата) — pinning. Несовпадение → `403` + код `peer-identity-mismatch`.
- Отозванные сертификаты — CRL/OCSP не поддерживаются в v1; вместо этого `peer` удаляется/перевыпускается сертификат.

### 2.5. Ограничения

| Ограничение | Значение по умолчанию | Поведение при превышении |
|---|---|---|
| Max body | 8 MiB (кроме `/content` — 256 MiB, стриминг) | `413` + `problem+json` (без чтения тела целиком: лимит по `Content-Length` и по потоку) |
| Rate limit (управляющие запросы) | 100 rps на токен, 20 rps на IP для неаутентифицированных | `429` + `Retry-After` + `RateLimit-*` |
| Rate limit (login/токены) | 5 rps | `429` |
| Неудачные аутентификации | 10 подряд с одного IP/токена → блокировка 5 мин | `429` / `423` (ADR 0004 SEC-API-004) |
| Параллельные jobs на токен | 4 | `429` + код `too-many-jobs` |
| Размер ответа списка | `limit` ≤ 500 | `400` |
| Таймаут запроса | 30 с (jobs — вне таймаута) | `504` + `Retry-After` |

Заголовки лимитов (draft-ietf-httpapi-ratelimit-headers): `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset`, `RateLimit-Policy`.

### 2.6. Bootstrap первого администратора

- При старте процесс проверяет своё хранилище токенов (state-dir процесса). Если токенов **нет**, а переменная окружения задана, токен создаётся из env-значения:
  - `pulsed` → `PULSED_BOOTSTRAP_TOKEN`;
  - `pulseresolved` → `PULSERESOLVED_BOOTSTRAP_TOKEN`.
- Токен выдаётся с ролью `admin`, помечается `bootstrap: true`, срок жизни ≤ 24 ч, и **обязателен к ротации**: первый созданный постоянный токен (`POST /auth/tokens`) автоматически инвалидирует bootstrap-токен. До ротации все ответы содержат заголовок `Warning: 199 pulse-dns "bootstrap token in use"`.
- Если хранилище непусто, env **игнорируется**, в лог пишется `warn!` (`bootstrap token ignored: token store is not empty`). Повторного «включения» bootstrap через env не существует.
- Env-значение не логируется, не попадает в аудит (только `token_id` и пометка `bootstrap`), читается один раз при старте и не хранится в памяти после создания хеша.
- Требования к значению: ≥ 32 символа, генерируется оператором (`openssl rand -base64 48`); при слабом значении — отказ старта (`ConfigurationError::WeakBootstrapToken`), а не warning.

---

## 3. Ошибки (RFC 9457)

```json
{
  "type": "https://pulse-dns.dev/problems/zone-not-found",
  "title": "Zone not found",
  "status": 404,
  "detail": "Zone 'example.org.' is not served by this instance.",
  "instance": "/api/v1/zones/example.org.",
  "code": "zone_not_found",
  "request_id": "req_01JCA8Z3K4",
  "retryable": false,
  "errors": []
}
```

Правила:
- `type` — стабильный URI из реестра ниже; `code` — машиночитаемый короткий идентификатор (совпадает с последним сегментом `type`).
- `detail` — человекочитаемый, **без внутренних путей, стектрейсов, io-ошибок и имён файлов**. Детали — в логе по `request_id`.
- `errors[]` — field-level ошибки: `{"pointer": "/ttl", "code": "ttl-out-of-range", "detail": "TTL must be 0..2147483647"}` (JSON Pointer, RFC 6901).
- `instance` — path запроса.
- `retryable` — подсказка клиенту; `Retry-After` дублируется заголовком.

### 3.1. Реестр кодов

| `code` | HTTP | Когда |
|---|---|---|
| `bad-request` | 400 | синтаксически некорректный запрос (не JSON, битый query) |
| `validation-failed` | 422 | семантическая ошибка полей (см. `errors[]`) |
| `unauthenticated` | 401 | нет/битый/истёкший токен |
| `forbidden` | 403 | валидный токен, но нет operation-scope/роли; глобальный endpoint без scope; mTLS-несовпадение. **Не используется** для зоны вне allowlist |
| `zone_not_found` | 404 | зона не обслуживается **или** вне allowlist токена (ответы неотличимы, ADR 0004 SEC-API-014) |
| `rrset-not-found` | 404 | RRset отсутствует |
| `key-not-found` | 404 | DNSSEC-ключ отсутствует |
| `peer-not-found` | 404 | peer отсутствует |
| `job-not-found` | 404 | job отсутствует/истёк |
| `rule-not-found` | 404 | policy-правило отсутствует |
| `zone-exists` | 409 | создание существующей зоны |
| `rrset-exists` | 409 | создание существующего RRset без `If-Match` |
| `serial-not-newer` | 409 | запрошенный serial не новее текущего (RFC 1982) |
| `serial-ambiguous` | 409 | разница ровно 2^31 (RFC 1982) |
| `zone-busy` | 409 | зона занята: идёт трансфер/импорт/компакция либо параллельная правка **той же** зоны (аренда). Относится только к этой зоне; другие зоны доступны. `Retry-After` рекомендуется |
| `zone-read-only` | 409 | попытка править secondary/forward-зону напрямую |
| `invalid-zone-state` | 409 | операция недопустима в текущем `TransferState` |
| `transfer-in-progress` | 409 | повторный триггер трансфера |
| `precondition-failed` | 412 | `If-Match` не совпал |
| `precondition-required` | 428 | операция требует `If-Match` (если включён строгий режим) |
| `payload-too-large` | 413 | превышен `max body` |
| `unsupported-media-type` | 415 | `Content-Type` не поддерживается |
| `rate-limited` | 429 | превышен лимит |
| `too-many-jobs` | 429 | превышено число параллельных jobs |
| `internal-error` | 500 | непредвиденная ошибка (детали — в логе) |
| `not-implemented` | 501 | функция заявлена, но не реализована в v1 |
| `nsec3-signing-not-implemented` | 501 | подпись NSEC3 отложена до v1.1 (домен/валидатор NSEC3 поддерживают) |
| `peer-identity-mismatch` | 403 | mTLS-сертификат peer'а не совпал с закреплённым отпечатком |
| `unavailable` | 503 | сервис не готов (зона `Expired`, store закрыт, идёт восстановление, таймаут координатора коммита — транзакция не опубликована, повтор безопасен) |
| `gateway-timeout` | 504 | превышен таймаут операции |
| `idempotency-key-reuse` | 409 | тот же `Idempotency-Key` с другим телом (ADR 0004 SEC-API-008) |
| `idempotency-in-progress` | 409 | повторный запрос с тем же ключом, пока первый выполняется |
| `unsupported-version` | 400 | неизвестная версия API в path (`/api/v2`) → `404`; версия формата — `400` |

### 3.2. Правила кодов состояния

- `200` — успешное чтение/изменение с телом.
- `201` — создание; `Location` обязателен; тело — созданный ресурс.
- `202` — принято в фоновую обработку; `Location` → `/api/v1/jobs/{id}`, `Retry-After` рекомендован.
- `204` — успех без тела (DELETE, purge).
- `304` — `If-None-Match` совпал.
- `405`/`406`/`415` — стандартные; `Allow` / `Accept` заполняются.
- Никогда не возвращается `200` с `{"error": ...}`.

---

## 4. Коллекции: пагинация, фильтры, сортировка

### 4.1. Пагинация (cursor-based)

```
GET /api/v1/zones/example.com./rrsets?limit=100&cursor=eyJvIjoiYS5leGFtcGxlLmNvbS4iLCJ0IjoiQSJ9
```
```json
{ "items": [ ... ], "next_cursor": "eyJvIjoiYi5leGFtcGxlLmNvbS4iLCJ0IjoiQUFBQSJ9", "has_more": true }
```
- `limit` — 1..500, по умолчанию 50.
- `cursor` — непрозрачный base64url; клиент **не** разбирает; недействительный → `400 bad-request`.
- Keyset-пагинация по стабильному ключу (`owner`, `type` для RRset; `id` для остальных).
- Ответ **не содержит `total`** (дорого и нестабильно). Для подсчётов — отдельный `?count=true` (допустимо только для малых коллекций, лимит 100k).
- Порядок: детерминированный, по умолчанию `owner ASC, type ASC` (RRset) / `id ASC`.
- `order=asc|desc` — только для поддерживающих коллекций; `desc` меняет направление курсора.

### 4.2. Фильтры

| Параметр | Применимость | Семантика |
|---|---|---|
| `owner` | RRset | точное имя (FQDN) |
| `owner_suffix` | RRset | все имена под указанным суффиксом |
| `type` | RRset | один или несколько через запятую |
| `qname` | cache entries | точное имя |
| `state` | zones (transfer), jobs | enum, через запятую |
| `kind` | zones | `primary`, `secondary`, `forward` |
| `enabled` | policy rules | bool |
| `since`/`until` | jobs, audit | RFC 3339 |

Неизвестные query-параметры **игнорируются** (совместимость). Неизвестные значения enum → `400`.

---

## 5. Идемпотентность и конкурентность

### 5.1. `Idempotency-Key`

- Заголовок `Idempotency-Key: <8..128 символов, [A-Za-z0-9._-]>`.
- **Обязателен** для всех POST-эндпоинтов, помеченных `✔` в колонке `Idem` (§7): создание зоны/peer/ключа, импорт, transfer/notify, dnssec enable/disable/sign/rollover, cache purge, blocklist create/refresh, overrides import.
- Семантика: ключ уникален в рамках `(token_id, method, path)`; тело участвует в сравнении через хеш (ADR 0004 SEC-API-008). Повтор с тем же телом → возврат сохранённого ответа (включая статус) с заголовком `Idempotent-Replay: true`. Повтор с другим телом → `409 idempotency-key-reuse`. Пока первый запрос выполняется → `409 idempotency-in-progress` (различать по `code`).
- Хранение: 24 ч, in-memory + опционально на диске (переживание рестарта — не гарантируется в v1; документируется).
- Ответы `5xx` не сохраняются (клиент может повторить).

### 5.2. Оптимистическая блокировка (ETag / If-Match)

- `GET` ресурса возвращает `ETag`. Две формы:
  - **зона:** `"z42-v118-t9042"` = `zone_id`, `zone_version` (версия зоны, ADR 0005) и `txn` (глобальный номер коммита); меняется на **любом** коммите этой зоны (serial, RRset, настройки). Поле `zone_version` дублируется в теле объекта зоны как `version` (целое).
  - **RRset:** `"rr_8f3a2b"` = хеш канонического набора `(owner, type, class, ttl, sorted rdata)`. **Не зависит** от правок других owner'ов в той же зоне — параллельная запись в другой RRset не инвалидирует ETag.
- `PUT`/`PATCH`/`DELETE` RRset и `PUT`/`PATCH` настроек **требуют** `If-Match` при `strict_preconditions=true` (по умолчанию включено для RRset); иначе `428`.
- **Проверка выполняется внутри транзакции записи** (внутри аренды зоны, ADR 0005 §5.3): условие передаётся в `Edit.precondition`, адаптер сверяет его с версией, на которой держится аренда. Окна TOCTOU между `GET` и записью нет. Несовпадение → `412 precondition-failed` с актуальным `current_etag`/`current_version`.
- `If-Match: *` разрешён для «перезаписать что есть» (осознанное перезаписывание).
- `If-None-Match: *` на `PUT` = «создать, только если нет» → `412`, если существует.
- ETag зоны **не** используется для защиты конкретного RRset: правка чужого RRset меняет `zone_version` и «сбросила» бы `If-Match` зоны. Для RRset-эндпоинтов обязателен RRset-ETag; `If-Match` зоны принимается только там, где меняется зона целиком (`PUT /zones/{z}/content`, `PATCH /zones/{z}`).

### 5.3. Атомарность RRset

- Все изменения набора `(owner, type, class)` применяются одной транзакцией `ZoneWriter` (см. `docs/spec/domain-model.md` §5.2).
- `PATCH` с `add`+`remove` применяется как единое целое: либо всё, либо ничего.
- Изменение TTL — операция над всем набором (`Rrset.ttl`), не над отдельной записью.

### 5.4. Параллельные правки зон

Запись параллельна **по зонам**: правки разных зон выполняются одновременно и не блокируют друг друга; правки одной зоны сериализуются арендой (`docs/adr/0005-parallel-writers.md` §4–§5).

| Ситуация | Ответ | `code` | Поведение клиента |
|---|---|---|---|
| Две правки **разных** зон одновременно | `200`/`201`/`204` обе | — | без изменений; общего лока нет |
| Две правки **одной** зоны одновременно | один запрос `200`, второй `409` | `zone-busy` + `Retry-After: 0` | повторить (backoff 10–50 мс) или использовать `If-Match` и разрешить конфликт |
| `If-Match` не совпал (кто-то успел раньше) | `412` | `precondition-failed` + `current_etag` | перечитать и повторить |
| Долгая операция (импорт, трансфер, `compact`) в зоне | `409` для правок **этой** зоны | `zone-busy` (импорт/трансфер), `invalid-zone-state` | ждать; другие зоны доступны |
| Долгая операция в одной зоне, правки в **других** | `200` | — | без изменений (PR-3 ADR 0005) |
| Создание зоны, пока идёт запись в другие | `201` | — | каталог-коммит короткий; при занятости — `409 zone-busy` с `Retry-After` |
| Удаление зоны, пока её пишут | `409` | `zone-busy` | дождаться завершения транзакции зоны |
| `commit` не уложился в таймаут координатора | `503` | `unavailable` + `Retry-After` | повтор безопасен (транзакция не опубликована) |

Правила:

1. **`409 zone-busy` — только про ту зону, к которой относится запрос.** Он **не** означает «сервер занят» и не должен приводить к глобальному backoff клиента.
2. `Retry-After` для `zone-busy` — `0` (секунд) при аренде (конфликт микросекундный); при импорте/трансфере — оценка оставшегося времени, если известна, иначе `1`.
3. Идемпотентность (`Idempotency-Key`) не меняется: повтор с тем же ключом и телом возвращает сохранённый ответ; `zone-busy`/`412` **не** сохраняются как ответ (клиент вправе повторить).
4. **Bulk-операции** (`PUT /zones/{z}/content`, импорт) — одна транзакция одной зоны: параллельность достигается запуском нескольких независимых jobs на разные зоны; один job на зону.
5. **Rate limit** остаётся per-token/IP (`§2.5`); параллелизм зон не даёт права обходить лимит. При массовых правках многих зон рекомендуется несколько `Idempotency-Key` и последовательные пачки, а не один запрос на 1000 зон.
6. `GET`-запросы во время правок не блокируются и не возвращают `409`: они видят либо версию до, либо после (MVCC).

---

## 6. Асинхронные операции (jobs)

### 6.1. Модель

Длительные операции (импорт, AXFR/IXFR, генерация/rollover ключей, re-sign, refresh blocklist, массовый purge) выполняются как job:

```
POST /api/v1/zones/example.com./transfer
Prefer: respond-async
→ 202 Accepted
Location: /api/v1/jobs/job_01JCA9...
Retry-After: 2
```
```json
{ "job_id": "job_01JCA9...", "state": "queued", "kind": "zone_transfer",
  "resource": "/api/v1/zones/example.com.", "created_at": "2026-11-23T18:00:00Z" }
```

`GET /api/v1/jobs/{id}`:
```json
{
  "job_id": "job_01JCA9...",
  "kind": "zone_transfer",
  "state": "running",              // queued | running | succeeded | failed | cancelled
  "progress": { "percent": 42, "current": 4200, "total": 10000, "unit": "rrsets" },
  "resource": "/api/v1/zones/example.com.",
  "result": null,
  "error": null,
  "created_at": "...", "started_at": "...", "finished_at": null,
  "cancellable": true,
  "expires_at": "2026-11-24T18:00:00Z"
}
```
- Без `Prefer: respond-async` сервер вправе выполнить операцию синхронно и вернуть `200`/`201`. Клиент **обязан** обрабатывать оба варианта.
- `DELETE /jobs/{id}` → `202` (отмена запрошена) или `409` если job неотменяем (например, `commit` уже начат). Идемпотентно: повторная отмена → `200` с финальным состоянием.
- `GET /api/v1/jobs?state=running&kind=zone_transfer&limit=50` — список своих jobs (admin видит все).
- Jobs живут 24 ч после завершения, затем `404 job-not-found`.
- `result` для успешного трансфера: `{"serial": 2026112305, "rrsets": 10000, "mode": "ixfr"}`.
- Прогресс обновляется не чаще 1 раза в секунду (не нагружать API).

---

## 7. Ресурсы и эндпоинты

Сводная таблица. `Idem` = обязателен `Idempotency-Key`. `Async` = может вернуть `202` c `Prefer: respond-async`.

### 7.1. Служебные

| Метод | Путь | Scope | Ответы |
|---|---|---|---|
| GET | `/healthz` | — (без auth, отдельный listener `:8081` рекомендуется) | `200 {"status":"ok"}` |
| GET | `/readyz` | — | `200` / `503` |
| GET | `/api/v1/status` | `server:read` | `200` |
| GET | `/api/v1/capabilities` | `server:read` | `200` |
| GET | `/api/v1/version` | `server:read` | `200` |
| GET | `/api/v1/openapi.json` | `server:read` | `200` (OpenAPI 3.1, генерируется из кода) |

`GET /api/v1/status`:
```json
{
  "role": ["authoritative"],            // или ["recursive"], или оба
  "version": "1.0.0",
  "build": { "git_sha": "a1b2c3d", "built_at": "2026-11-20T10:00:00Z", "rustc": "1.99.1" },
  "uptime_seconds": 86400,
  "started_at": "2026-11-22T18:00:00Z",
  "zones": { "total": 12, "primary": 9, "secondary": 3, "expired": 0 },
  "queries": { "qps_1m": 18400.5, "total": 1234567890 },
  "degraded": []
}
```
`/healthz` — только liveness (процесс жив, event loop крутится), **без** проверки диска/сети. `/readyz` — готовность обслуживать (store открыт, зоны загружены, для secondary — нет `Expired`-зон в critical-наборе).

### 7.2. Настройки сервера

| Метод | Путь | Scope | Примечание |
|---|---|---|---|
| GET | `/api/v1/server/settings` | `server:read` | эффективная конфигурация (секреты замаскированы) |
| GET | `/api/v1/server/settings/{section}` | `server:read` | `general`, `dns`, `resolver`, `api`, `logging`, `dnssec` |
| PUT | `/api/v1/server/settings/{section}` | `server:write` | полная замена секции, `If-Match` рекомендуется |
| PATCH | `/api/v1/server/settings/{section}` | `server:write` | частичное изменение |
| POST | `/api/v1/server/reload` | `server:write` | перечитать конфиг/файлы зон, `Async` |
| POST | `/api/v1/server/shutdown` | `server:write` | корректная остановка (только localhost/admin), `202` |

Семантика:
- Секции: `general` (node id, hostname, log level), `dns` (listen-адреса, `max_udp_payload`, `tcp_idle_timeout`, `axfr_enabled`, `ixfr_window`, `serial_scheme`), `resolver` (upstreams, `qname_minimization`, `dnssec_validation`, `ecs`), `api` (bind, tls, rate limits), `logging`, `dnssec` (default algorithm, validity, NSEC/NSEC3).
- Изменения, требующие рестарта, помечаются в ответе: `{"applied": true, "restart_required": true, "restart_reasons": ["dns.listen"]}`.
- Невалидная конфигурация → `422` с `errors[]`, изменения **не применяются** (валидация до применения).
- Секреты (TSIG, TLS-ключи, upstream-креды) в `GET` маскируются: `"***"`; запись `"***"` означает «не менять».

### 7.3. Метрики

| Метод | Путь | Scope |
|---|---|---|
| GET | `/api/v1/metrics` | `metrics:read` |
| GET | `/api/v1/metrics/{name}` | `metrics:read` |

- `Accept: text/plain` (или `?format=prometheus`) → Prometheus text exposition 0.0.4.
- `Accept: application/json` → `{"metrics":[{"name":"dns_queries_total","type":"counter","labels":{"qtype":"A","rcode":"NOERROR"},"value":123}]}`.
- `GET /metrics/{name}?labels=...` — только для известных имён; неизвестное → `404`.
- Метки с высокой кардинальностью запрещены (см. `Metrics`-порт).
- Метрики отражают **только этот процесс** (`pulsed` или `pulseresolved`); агрегатора в v1 нет. Сборщик обязан скрейпить оба инстанса и различать их по `job`/`instance`.
- `node_role` (например `authoritative`/`recursive`) добавляется как константная метка, чтобы объединённые дашборды не смешивали процессы.

### 7.4. Зоны

| Метод | Путь | Scope | Idem | Async | Ответы |
|---|---|---|---|---|---|
| GET | `/api/v1/zones` | `zones:read` | | | `200` |
| POST | `/api/v1/zones` | `zones:write` | ✔ | | `201`, `409 zone-exists`, `422` |
| GET | `/api/v1/zones/{origin}` | `zones:read` | | | `200`, `404` |
| PATCH | `/api/v1/zones/{origin}` | `zones:write` | | | `200`, `404`, `409 zone-read-only`, `412` |
| DELETE | `/api/v1/zones/{origin}` | `zones:delete` | | | `204`, `404`, `409 zone-busy` |
| GET | `/api/v1/zones/{origin}/serial` | `zones:read` | | | `200` |
| POST | `/api/v1/zones/{origin}/serial` | `zones:write` | | | `200`, `409 serial-not-newer/ambiguous` |
| POST | `/api/v1/zones/{origin}/reload` | `zones:write` | | ✔ | `200`/`202`, `409 zone-read-only` |
| GET | `/api/v1/zones/{origin}/content` | `zones:export` | | | `200` (`text/dns` или JSON) |
| PUT | `/api/v1/zones/{origin}/content` | `zones:write` | | ✔ | `200`/`202`, `413`, `422` |
| POST | `/api/v1/imports` | `zones:write` | ✔ | ✔ (всегда) | `202` |

Правила доступа к коллекции и созданию (ADR 0004 SEC-API-014):
- `GET /zones` возвращает `200` только с зонами из allowlist токена; фильтр по чужой/несуществующей зоне даёт пустой список, а не `403`.
- `POST /zones` для origin вне allowlist → `403` **до** проверки существования (никогда `409 zone-exists`); аудит `denied_zone_out_of_scope`.

Объект зоны:
```json
{
  "id": 42,
  "origin": "example.com.",
  "kind": "primary",
  "serial": 2026112301,
  "version": 118,
  "default_ttl": 3600,
  "rrsets": 1482,
  "dnssec": { "signed": true, "algorithm": "ecdsa-p256-sha256", "denial": "nsec" },
  "transfer": null,
  "forward": null,
  "created_at": "2026-01-10T09:00:00Z",
  "updated_at": "2026-11-23T18:00:00Z"
}
```
Для `secondary`:
```json
"transfer": {
  "state": "up_to_date", "serial": 2026112301,
  "mode": "ixfr", "peer_id": "peer_ns1",
  "last_success": "2026-11-23T18:00:00Z",
  "next_refresh": "2026-11-23T19:00:00Z",
  "soa_timers": { "refresh": 3600, "retry": 600, "expire": 604800, "minimum": 300 },
  "last_error": null
}
```
Для `forward`:
```json
"forward": { "upstreams": ["192.0.2.53:53", "tls://dns.example:853"], "fallback": "refuse" }
```

Создание зоны:
```json
POST /api/v1/zones
{
  "origin": "example.com.",
  "kind": "primary",
  "default_ttl": 3600,
  "nameservers": ["ns1.example.com.", "ns2.example.com."],
  "soa": { "mname": "ns1.example.com.", "rname": "hostmaster.example.com.",
           "refresh": 3600, "retry": 600, "expire": 604800, "minimum": 300 }
}
```
- `201` + `Location: /api/v1/zones/example.com.` + `ETag`.
- `ETag` зоны — `"z<id>-v<version>-t<txn>"`; `version` монотонно растёт на каждом коммите зоны и возвращается в теле (`version`). Для условных запросов на уровне зоны (`PUT /content`, `PATCH /zones/{z}`) `If-Match` принимает эту форму.
- **MVP:** `PUT /zones/{origin}` создаёт пустую зону и не генерирует apex
  `SOA`/`NS`; поля `nameservers`/`soa` пока не принимаются. Зона остаётся в
  `Initializing` (DNS `REFUSED`), пока `SOA` и `NS` не добавлены RRset API.
  В целевой схеме эти записи генерируются из `nameservers`/`soa` (INV-4).
- `nameservers` без `glue` допустимы; glue добавляется вручную RRset'ами.
- `PATCH` зоны позволяет менять только `default_ttl`, `kind` (primary↔forward только при пустой зоне), `nameservers` (перегенерирует apex NS). Serial меняется **только** через `/serial` или транзакционно при правках.
- `DELETE` для secondary разрешён (удаление подписки), для primary — требует `?confirm_origin=<origin>` (защита от опечатки), иначе `400 validation-failed`.

`POST /zones/{origin}/serial`:
```json
{ "mode": "increment" }                      // +1 по RFC 1982
{ "mode": "set", "value": 2026112400 }       // только если новее текущего
```
Ответ: `{"zone":"example.com.","old_serial":2026112301,"new_serial":2026112302,"commit_id":"c_8812"}`. `zones:write` обязателен; для secondary → `409 zone-read-only`.

Импорт зон (`POST /api/v1/imports`):
- `Content-Type: application/zip` или `multipart/form-data` (несколько зон) или `text/dns` (одна зона).
- Тело — BIND zonefile (`$ORIGIN`/`$TTL`/`$INCLUDE` **не** поддерживается в v1: `$INCLUDE` запрещён, `$ORIGIN`/`$TTL` допустимы).
- Query: `mode=replace|merge|check`, `format=zonefile|json`, `strict=true`.
- `check` — dry-run: `422` с перечнем нарушений и `200` с отчётом, если всё валидно; изменения не применяются.
- Всегда `202` + `Location: /jobs/{id}`; результат job: `{"zones":[{"origin":"...","rrsets":123,"warnings":[]}], "ignored":[]}`.
- Лимиты: 256 MiB body (стриминг), 5M RRset на зону, 60 с на парсинг батча; превышение → `413`/`422`.

Экспорт (`GET /zones/{origin}/content?format=zonefile`):
- `text/dns; charset=utf-8`, `Content-Disposition: attachment; filename="example.com.zone"`, стриминг.
- `format=json` → `application/json` с массивом `Rrset` (тот же формат, что в RRset API).
- `ETag`/`If-None-Match` поддерживаются.
- Секреты (TSIG, приватные ключи) никогда не экспортируются.

`POST /zones/{origin}/reload`:
- Перечитывает зону из источника (для primary — из зонного файла/каталога, указанного в настройках), атомарно подменяет снапшот.
- Для secondary/forward → `409 zone-read-only`.

`PUT /zones/{origin}/content`:
- Полная замена содержимого зоны. Требует `If-Match` (ETag зоны) или `?force=true` (осознанное перезаписывание, попадает в аудит); иначе `428`.
- `mode=merge` — добавляет/заменяет RRset из тела, не удаляя отсутствующие; `mode=replace` (по умолчанию) — удаляет отсутствующие в теле RRset, кроме apex `SOA`/`NS` (они пересобираются из тела).
- Валидация всего тела до применения: при любой ошибке зона не меняется (`422`), частичное применение запрещено.

### 7.5. RRset

| Метод | Путь | Scope | Idem | Ответы |
|---|---|---|---|---|
| GET | `/api/v1/zones/{origin}/rrsets` | `zones:read` | | `200` (пагинация, фильтры) |
| GET | `/api/v1/zones/{origin}/rrsets/{owner}/{type}` | `zones:read` | | `200`, `404` |
| POST | `/api/v1/zones/{origin}/rrsets` | `zones:write` | | `201`, `409 rrset-exists`, `422` |
| PUT | `/api/v1/zones/{origin}/rrsets/{owner}/{type}` | `zones:write` | | `200`, `404`, `412`, `422` |
| PATCH | `/api/v1/zones/{origin}/rrsets/{owner}/{type}` | `zones:write` | | `200`, `404`, `409`, `412`, `422` |
| DELETE | `/api/v1/zones/{origin}/rrsets/{owner}/{type}` | `zones:write` | | `204`, `404`, `412` |

`{owner}`: FQDN (`www.example.com.`) или `@` для apex; `{type}` — `UPPER_CASE`.
`{type}` `SOA`: разрешён только в apex, ровно одна запись. **MVP-отклонение
от будущей схемы serial:** `SOA.serial` задаётся явно в RDATA через этот
эндпоинт (`/serial` и автоматический serial scheme ещё не реализованы);
сравнение версий идёт по ETag/`version`, а не по SOA serial. `DELETE` apex
`SOA`/`NS` в MVP разрешён и переводит зону в `Initializing`: DNS отвечает
`REFUSED`, пока apex `SOA` и `NS` не будут восстановлены.

Объект RRset:
```json
{
  "zone": "example.com.",
  "owner": "www.example.com.",
  "type": "A",
  "class": "IN",
  "ttl": 300,
  "records": ["192.0.2.10", "192.0.2.11"],
  "etag": "\"rr_8f3a2b\"",
  "updated_at": "2026-11-23T18:00:00Z"
}
```
- `records` — массив presentation-строк RDATA; порядок нормализован сервером (канонический), клиент не должен полагаться на порядок.
- `ttl` — один на набор; `PUT`/`POST` с разными TTL у записей невозможен (TTL на уровне RRset).

Создание:
```json
POST /api/v1/zones/example.com./rrsets
{ "owner": "www.example.com.", "type": "A", "ttl": 300, "records": ["192.0.2.10"] }
```
`PUT` (полная замена набора):
```json
PUT /api/v1/zones/example.com./rrsets/www.example.com./A
If-Match: "rr_8f3a2b"
{ "ttl": 300, "records": ["192.0.2.10", "192.0.2.11"] }
```
`PATCH` (атомарная дельта):
```json
PATCH /api/v1/zones/example.com./rrsets/www.example.com./A
If-Match: "rr_8f3a2b"
{ "ttl": 600, "add": ["192.0.2.12"], "remove": ["192.0.2.10"] }
```
- `add` и `remove` применяются одновременно; удаление последней записи → удаление RRset (`204`? нет: `200` с `{"deleted": true}`).
- Дубликат в `add` — идемпотентно игнорируется; отсутствующий в `remove` — идемпотентно игнорируется (но в ответе `removed: 0`).
- Нарушение инвариантов (CNAME-конфликт, TTL, чужой owner) → `422` + `errors[]` с `pointer` и `code` ∈ `cname-conflict`, `dname-conflict`, `ttl-mismatch`, `owner-out-of-zone`, `apex-ns-required`, `soa-apex-only`, `unsupported-class`.

Ошибка конфликта с текущей версией:
```json
412 Precondition Failed
{
  "type": "https://pulse-dns.dev/problems/precondition-failed", "code": "precondition-failed",
  "status": 412, "title": "ETag mismatch",
  "detail": "The RRset was modified. Re-read and retry.",
  "current_etag": "\"rr_9c11d4\"", "current_version": 119,
  "instance": "/api/v1/zones/example.com./rrsets/www.example.com./A",
  "request_id": "req_..."
}
```

Замечания:
- Правки в secondary/forward-зоне → `409 zone-read-only`.
- Правки во время активного AXFR/IXFR *в эту* зону → `409 zone-busy` (кроме `serial`/`reload`, которые сами меняют снапшот). Правки **других** зон в это время проходят: параллельность — по зонам (§5.4).
- `If-Match` проверяется в той же транзакции, что и запись (`Edit.precondition`): при конкурентной правке того же RRset второй запрос получает `412`, а не «потерянную запись». `current_etag`/`current_version` в теле — актуальные на момент отказа.
- Правка RRset не меняет ETag других RRset той же зоны: RRset-ETag — хеш содержимого набора, а не версии зоны.
- DNSSEC-подписи (`RRSIG`, `NSEC`/`NSEC3`) **не редактируются вручную**: попытка → `422` с `code=managed-by-signer`. Они генерируются подписантом.
- `CNAME` нельзя создать, если у owner есть другие типы (кроме DNSSEC-метаданных), и наоборот → `422 cname-conflict`.

### 7.6. Ключи DNSSEC и подпись

| Метод | Путь | Scope | Idem | Async |
|---|---|---|---|---|
| GET | `/api/v1/zones/{origin}/dnssec` | `keys:read` | | |
| POST | `/api/v1/zones/{origin}/dnssec/enable` | `keys:write` | ✔ | ✔ |
| POST | `/api/v1/zones/{origin}/dnssec/disable` | `keys:write` | ✔ | ✔ |
| POST | `/api/v1/zones/{origin}/dnssec/sign` | `keys:write` | ✔ | ✔ (всегда, если >1000 RRset) |
| GET | `/api/v1/zones/{origin}/dnssec/ds` | `keys:read` | | |
| GET | `/api/v1/zones/{origin}/dnssec/keys` | `keys:read` | | |
| POST | `/api/v1/zones/{origin}/dnssec/keys` | `keys:write` | ✔ | |
| GET | `/api/v1/zones/{origin}/dnssec/keys/{key_id}` | `keys:read` | | |
| POST | `/api/v1/zones/{origin}/dnssec/keys/{key_id}/activate` | `keys:write` | | |
| POST | `/api/v1/zones/{origin}/dnssec/keys/{key_id}/retire` | `keys:write` | | |
| DELETE | `/api/v1/zones/{origin}/dnssec/keys/{key_id}` | `keys:write` | | `204` только если `state=Removed` |
| POST | `/api/v1/zones/{origin}/dnssec/rollover` | `keys:write` | ✔ | `202` |

Доступ: зона вне allowlist → `404` (как несуществующая); зона в allowlist без нужного scope → `403`; экспорт приватного ключа в v1 не реализован (потребует `keys:export` + mTLS + повторную аутентификацию, ADR 0004 SEC-API-013).

Статус:
```json
{
  "zone": "example.com.",
  "signed": true,
  "denial": "nsec",
  "nsec3": null,
  "keys": { "ksk": 1, "zsk": 1, "csk": 0 },
  "signature_valid_until": "2026-12-23T18:00:00Z",
  "rrsig_refresh_at": "2026-12-16T18:00:00Z",
  "last_signed_at": "2026-11-23T18:00:00Z",
  "issues": []
}
```

Ключ:
```json
{
  "key_id": "key_01JCB0...",
  "zone": "example.com.",
  "role": "ksk",
  "algorithm": "ecdsa-p256-sha256",
  "bits": 256,
  "state": "active",
  "dnskey": "257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0d...",
  "ds": [ { "key_tag": 45321, "algorithm": 13, "digest_type": 2, "digest": "A1B2..." } ],
  "timings": { "publish_at": "2026-01-01T00:00:00Z", "activate_at": "2026-01-08T00:00:00Z",
               "retire_at": null, "remove_at": null },
  "created_at": "2026-01-01T00:00:00Z"
}
```
- Приватный материал **никогда** не возвращается и не принимается по API (только через `SecretStore`/конфиг): ADR 0004 SEC-API-013 требует для экспорта отдельный scope + mTLS + повторную аутентификацию, поэтому в v1 экспорт приватных ключей отсутствует как функция.
- Алгоритмы v1: `ecdsa-p256-sha256` (13), `ed25519` (15), `rsa-sha256` (8). Неизвестный → `422`.
- Создание: `{"role":"ksk","algorithm":"ecdsa-p256-sha256","bits":null,"publish_at":null,"activate_at":null}`. Окна по умолчанию: publish = now, activate = now + 7d (pre-publish).
- `POST /dnssec/rollover`:
```json
{ "scheme": "pre_publish", "role": "ksk", "overlap": "7d", "retire_after": "30d" }
{ "scheme": "double_signature", "role": "zsk", "overlap": "14d" }
```
Ответ `202` → job, который применяет шаги по таймеру; повторный rollover при активном → `409 zone-busy`.
- `POST /dnssec/enable` принимает `{"denial":"nsec","nsec3":null,"validity":"30d","algorithm":"ecdsa-p256-sha256"}`; несовместимый с уже существующими ключами алгоритм → `422`.
- **NSEC/NSEC3 (решение):** домен и валидатор поддерживают оба типа denial; **подпись в v1 — только NSEC**. `denial: "nsec3"` на `enable`/`sign`/`rollover` → `501 Not Implemented` с `code: "nsec3-signing-not-implemented"` и `detail` о плане v1.1. `GET /dnssec` может возвращать `denial: "nsec3"` для импортированной/secondary зоны — она обслуживается как есть, переподпись в NSEC3 не выполняется.
- `GET /dnssec/ds` → `{"ds":[{"key_tag":...,"algorithm":13,"digest_type":2,"digest":"..."}]}` в presentation-формате для передачи регистратору.

### 7.7. Репликация

| Метод | Путь | Scope | Idem | Примечание |
|---|---|---|---|---|
| GET | `/api/v1/replication/peers` | `replication:read` | | |
| POST | `/api/v1/replication/peers` | `replication:manage` | ✔ | `201` |
| GET | `/api/v1/replication/peers/{peer_id}` | `replication:read` | | |
| PUT | `/api/v1/replication/peers/{peer_id}` | `replication:manage` | | `200`, `412` |
| DELETE | `/api/v1/replication/peers/{peer_id}` | `replication:manage` | | `204`, `409` если используется зонами |
| GET | `/api/v1/zones/{origin}/transfer` | `replication:read` | | статус + история |
| POST | `/api/v1/zones/{origin}/transfer` | `replication:manage` | ✔ | `200`/`202` |
| POST | `/api/v1/zones/{origin}/notify` | `replication:manage` | ✔ | `202`/`200` |
| GET | `/api/v1/zones/{origin}/notify` | `replication:read` | | история входящих NOTIFY |

Peer:
```json
{
  "peer_id": "peer_ns1",
  "address": "192.0.2.53:53",
  "role": "primary",
  "tsig_key_name": "xfr-ns1.",
  "tls": { "server_name": "ns1.example.net", "fingerprint_sha256": "AB:CD:..." },
  "zones": ["example.com."],
  "enabled": true,
  "last_seen": "2026-11-23T17:59:00Z"
}
```
- `address` — DNS-транспорт (UDP/TCP 53). `tls` — управляющий канал (mTLS). TSIG-секрет задаётся по имени и берётся из `SecretStore`, в API не передаётся.
- **Трансферы — только TCP** (AXFR/IXFR по UDP запрещён, ADR 0004 SEC-REP-001); NOTIFY — UDP с fallback на TCP.
- Secondary перед публикацией принятой зоны обязан провалидировать формат/границы, монотонность SOA serial и DNSSEC; при провале — карантин (`state=failed`, `last_error.kind=validation`), зона не публикуется и остаётся на предыдущем валидном снапшоте (ADR 0004 SEC-REP-003). API отражает это в `transfer.last_error`.
- Триггер трансфера:
```json
POST /api/v1/zones/example.com./transfer
{ "mode": "ixfr", "from_serial": 2026112301, "peer_id": "peer_ns1" }
```
Ответ `202` + job (`kind=zone_transfer`); при `mode=ixfr` и недоступной истории версий (IXFR-окно) сервер сам переходит на AXFR и сообщает `"mode_used":"axfr"` в `result`.
- Ошибки: `409 transfer-in-progress`, `409 zone-read-only` (для primary — трансфер только исходящий; входящий запрещён), `422` при `from_serial` не новее текущего.
- `POST /notify`:
```json
{ "serial": 2026112302, "peers": ["peer_ns2"] }   // peers опционально; по умолчанию все secondary зоны
```
`202` + job (`kind=notify`); при 0 получателей → `200 {"sent":0}`.
- История трансферов: `GET /transfer` →
```json
{
  "zone": "example.com.", "state": "up_to_date", "serial": 2026112301,
  "history": [ { "started_at": "...", "finished_at": "...", "mode": "ixfr",
                 "from_serial": 2026112290, "to_serial": 2026112301,
                 "rrsets": 14, "result": "success", "peer_id": "peer_ns1", "bytes": 20480 } ]
}
```
История хранится в памяти (последние 100 записей на зону) + метрики.

### 7.8. Кеш резолвера

| Метод | Путь | Scope | Idem | Примечание |
|---|---|---|---|---|
| GET | `/api/v1/resolver/cache/stats` | `cache:read` | | hit ratio, size, evictions |
| GET | `/api/v1/resolver/cache/entries` | `cache:read` | | debug-режим, выключен по умолчанию |
| POST | `/api/v1/resolver/cache/purge` | `cache:purge` | ✔ | `200` (счётчики) или `202` |
| DELETE | `/api/v1/resolver/cache` | `cache:purge` | | purge по `name`+`type` (одиночный) |

Статистика:
```json
{
  "entries": 48211, "max_entries": 200000,
  "hit_ratio_1m": 0.87, "hits_total": 918273645, "misses_total": 137264,
  "evictions_total": 1023, "expired_total": 55120,
  "negative_entries": 4112, "bogus_entries": 3,
  "by_validation": { "secure": 30122, "insecure": 18086, "bogus": 3 }
}
```
Purge:
```json
POST /api/v1/resolver/cache/purge
{ "names": ["ads.example."], "type": "A", "subtree": true, "rcode": null }
```
→ `200 {"purged": 12, "not_found": 0}` (до 10k записей) или `202` job при большем объёме / `subtree=true` на большом кеше.
`DELETE /resolver/cache?name=www.example.&type=A` → `204` (идемпотентно: отсутствие записи — тоже `204`).
Кеш — не источник правды: purge не влияет на зоны, но может привести к всплеску upstream-трафика (метрика).

### 7.9. Политики: blocklist, overrides, rules

| Метод | Путь | Scope | Idem |
|---|---|---|---|
| GET | `/api/v1/policy/rules` | `policy:read` | |
| POST | `/api/v1/policy/rules` | `policy:write` | |
| GET | `/api/v1/policy/rules/{rule_id}` | `policy:read` | |
| PUT | `/api/v1/policy/rules/{rule_id}` | `policy:write` | |
| DELETE | `/api/v1/policy/rules/{rule_id}` | `policy:write` | |
| GET | `/api/v1/policy/blocklists` | `policy:read` | |
| POST | `/api/v1/policy/blocklists` | `policy:write` | ✔ |
| GET | `/api/v1/policy/blocklists/{id}` | `policy:read` | |
| POST | `/api/v1/policy/blocklists/{id}/refresh` | `policy:write` | ✔ (202) |
| DELETE | `/api/v1/policy/blocklists/{id}` | `policy:write` | |
| GET | `/api/v1/policy/blocklists/{id}/entries` | `policy:read` | |
| GET | `/api/v1/policy/overrides` | `policy:read` | |
| PUT | `/api/v1/policy/overrides/{owner}/{type}` | `policy:write` | |
| DELETE | `/api/v1/policy/overrides/{owner}/{type}` | `policy:write` | |
| POST | `/api/v1/policy/overrides/import` | `policy:write` | ✔ (202) |

Правило:
```json
{
  "rule_id": "rule_01JCB1...",
  "priority": 100,
  "matcher": { "kind": "suffix", "values": ["ads.example.", "tracker.example."] },
  "qtypes": ["A", "AAAA"],
  "action": { "kind": "block", "rcode": "NXDOMAIN" },
  "enabled": true,
  "stats": { "hits_24h": 512 }
}
```
- `matcher.kind`: `exact` | `suffix` | `regex` | `client_group`; `regex` компилируется и ограничен по времени (1 ms) и длине (1 KiB).
- `action.kind`: `block` (rcode: `NXDOMAIN`|`REFUSED`|`NODATA`), `refuse`, `rewrite` (`rdata[]`,`ttl`), `allow`, `log_only`.
- Уникальность `priority` — `409` при конфликте? Нет: `422` с `code=priority-conflict` (валидация, не состояние). `allow` доминирует над `block` (INV-19).
- Ответ на запрос: применяется первый по `(priority, id)`; `stats` — агрегат, не в домене.

Blocklist:
```json
POST /api/v1/policy/blocklists
{ "name": "stevenblack", "source": { "type": "url", "url": "https://example.org/hosts.txt",
  "format": "hosts|domains|abp", "refresh_interval": "24h", "checksum": null },
  "enabled": true }
```
- Inline-источник: `{"type":"inline","entries":["ads.example."]}` (лимит 1M записей, тело ≤ 32 MiB).
- `201` + `Location`; загрузка выполняется job'ом (`kind=blocklist_refresh`), статус — в объекте (`state`: `pending|loading|active|failed`, `entries_count`, `last_error`).
- При ошибке загрузки сохраняется предыдущая версия списка (atomic swap), `state=failed` + `last_success_at`.
- `format` обязателен для `url`; `hosts` — парсинг `/etc/hosts`-формата (IP + имя), `domains` — по имени на строку, `abp` — подмножество ABP-синтаксиса (v1: только `||domain^`).

Overrides:
```json
PUT /api/v1/policy/overrides/printer.local./A
{ "ttl": 60, "records": ["192.168.1.50"] }
```
- Overrides имеют приоритет **выше** upstream и кеша, но **ниже** blocklist `block` (осознанно: блокировка не обходится локальным override; см. открытые вопросы).
- `POST /overrides/import` — bulk из zonefile/JSON, `202`.

### 7.10. Jobs и аудит

| Метод | Путь | Scope |
|---|---|---|
| GET | `/api/v1/jobs` | `jobs:read` |
| GET | `/api/v1/jobs/{job_id}` | `jobs:read` |
| DELETE | `/api/v1/jobs/{job_id}` | `jobs:cancel` |
| GET | `/api/v1/audit` | `audit:read` (или `admin`) |

`GET /api/v1/audit?since=&until=&principal=&action=&result=&limit=` → неизменяемый журнал управляющих операций (`principal`, `action`, `resource`, `result`, `reason`, `request_id`, `at`). Хранение: 30 дней, append-only файл; персональные данные не пишутся. Тело запросов в аудит не попадает (только хеш/размер). Аудит недоступен zone-scoped токену без `audit:read`; отказ по allowlist фиксируется как `denied_zone_out_of_scope`, даже если наружу отдан `404`.

### 7.11. Токены API

| Метод | Путь | Scope | Примечание |
|---|---|---|---|
| GET | `/api/v1/auth/tokens` | `tokens:admin` | список (без секретов, только префикс `pd_live_ab..`) |
| POST | `/api/v1/auth/tokens` | `tokens:admin` | `201`, секрет возвращается **один раз** |
| GET | `/api/v1/auth/tokens/{id}` | `tokens:admin` | метаданные, scopes, `last_used_at` |
| POST | `/api/v1/auth/tokens/{id}/rotate` | `tokens:admin` | новый секрет, старый живёт 300 с (окно перекрытия) |
| DELETE | `/api/v1/auth/tokens/{id}` | `tokens:admin` | `204`, немедленная инвалидация |

```json
POST /api/v1/auth/tokens
{ "name": "ci-deployer", "roles": ["zone-editor"], "zone_scope": ["example.com."], "expires_at": "2027-01-01T00:00:00Z" }
→ 201
{ "id": "tok_01JCC2...", "name": "ci-deployer", "roles": ["zone-editor"],
  "scopes": ["zones:read","zones:write", "..."], "token": "pd_live_9f3K...",
  "prefix": "pd_live_9f3K", "expires_at": "2027-01-01T00:00:00Z", "created_at": "..." }
```
- `token` присутствует только в ответе на создание/ротацию; повторно не выдаётся.
- Нельзя выдать роли/scopes, которых нет у вызывающего principal (иначе `403` с кодом `forbidden`) — защита от эскалации привилегий.
- Удаление/ротация собственного токена разрешены без `tokens:admin` только если это единственный токен principal'а (bootstrap-сценарий, см. §2.6).

---

## 8. Версионирование и совместимость

1. **Major — в path** (`/api/v1`). Одновременно поддерживается одна major-версия; переход — через ADR и минимум 6 месяцев параллельной работы (`/api/v1` + `/api/v2` на разных портах или с префиксами).
2. **Внутри v1 разрешены только аддитивные изменения:** новые эндпоинты, новые необязательные поля в ответах, новые enum-значения **только** с документированным поведением «неизвестное значение обрабатывать как unknown».
3. **Запрещено в v1:** удаление/переименование полей, изменение типов, изменение семантики кодов, ужесточение валидации, изменение кодов состояния для существующих кейсов.
4. **Клиенты обязаны** игнорировать неизвестные поля в ответах. Сервер **отклоняет** неизвестные поля в телах запросов (`422`, `pointer`) — это защита от опечаток; для forward-compat клиент обязан не посылать лишнего.
5. **Deprecation:** заголовки `Deprecation: @1735689600` и `Sunset: Wed, 01 Jul 2027 00:00:00 GMT` на устаревших эндпоинтах + запись в `docs/api/CHANGELOG.md`; минимум 90 дней до удаления в рамках major.
6. **Медиа-тип:** `application/json` для v1; альтернативные представления — через `Accept` и query `format`, не через новый media type.
7. **`/api/v1/openapi.json`** — машинночитаемая схема, генерируется из кода, проверяется в CI на соответствие примерам (contract-тесты).
8. Ошибки не меняют `code` в рамках major; новые коды добавляются в реестр.

---

## 9. Безопасность API (сводка требований)

- TLS 1.2+ (1.3 предпочтителен), запрещены NULL/RC4/3DES-шифры; HSTS при внешнем bind.
- По умолчанию bind `127.0.0.1` или Unix-socket; публичный bind — только явным флагом и только с TLS (ADR 0004 SEC-API-001).
- Bearer-токены: только по TLS (кроме loopback/Unix-socket); сравнение хешей — constant-time; в хранилище — SHA-256 + префикс-ID (ADR 0004 SEC-API-002/010).
- Аудит фиксирует actor по `token_id`, а не по секрету; source IP и тело запроса не попадают в `info`-логи (ADR 0004 SEC-API-007, SEC-OPS-004).
- SSRF-защита для `policy.blocklists[].source.url`, forward-upstreams и TLS-адресов peers (ADR 0004 SEC-API-010): allowlist схем (`https`, `tls`, `tcp` только для DNS-адресов), запрет редиректов на disallowed-адреса, проверка резолвнутых IP по denylist (loopback, link-local, `169.254.169.254`, RFC1918 — если не разрешены явно), лимит размера загрузки.
- Никаких секретов в URL, логах и `problem+json`.
- Заголовки ответа: `X-Content-Type-Options: nosniff`, `Cache-Control: no-store` для аутентифицированных ответов (кроме `ETag`-валидации), `Referrer-Policy: no-referrer`.
- Лимиты на размер и глубину JSON (64 уровня, 8 MiB); запрет дублирующихся ключей JSON.
- Rate limit и аудит — обязательны для всех мутаций.
- Ошибки авторизации: `401` — только невалидная/просроченная аутентификация; `403` — нет operation-scope/роли (включая глобальные endpoints), без имён зон; `404 zone_not_found` — зона вне allowlist **или** несуществующая (ответы неотличимы, ADR 0004 SEC-API-014). Коллекции фильтруются, а не отдают `403`.

---

## 10. Вне области v1

- WebSocket/SSE-подписки на события (jobs поллингом).
- GraphQL, gRPC.
- Управление DNS-транспортами DoT/DoH/DoQ (появятся как настройки позже).
- DNSCrypt (отдельный этап после v1).
- Пользовательский UI, OIDC-логин, cookie-сессии.
- Миграция зон между инстансами через API (только AXFR).
- Ресурсный RBAC по отдельным RRset (только зона целиком).

---

## 11. Открытые вопросы

1. **Хранение `Idempotency-Key` между рестартами** — in-memory (v1) достаточно? Для мутаций зон потеря ключа после рестарта может привести к дублю операции (например, повторный import в `merge`-режиме идемпотентен, а `POST /zones` — нет; конфликт поймается `zone-exists`).
2. **`GET /resolver/cache/entries`** — оставлять в v1 (утечка истории запросов) или только `stats` + точечный purge? Требуется решение по приватности.
3. **Приоритет overrides vs blocklist** — сейчас blocklist `block` выигрывает; альтернатива — overrides всегда выигрывают (нужно для «белых» локальных имён).
4. **`POST /server/shutdown`** — нужен ли в API вообще (риск DoS) или только сигнал ОС/SIGTERM?
5. **`Prefer: respond-async`** — оставляем как универсальный механизм или фиксируем список всегда-асинхронных эндпоинтов (проще для клиентов)?
6. **Мультитенантность** — если появится, `zone_scope` станет обязательным, а `principal` получит `tenant_id`; закладывать ли поле `tenant` в v1 (зарезервировать)?
7. **Коды состояния для `DELETE` primary-зоны** — требовать `confirm_origin` (предложено) или отдельный `?force=true` с аудитом?
8. **Разделение `replication:manage`** — coarse-scope соответствует ADR 0004, но не позволяет выдать «только NOTIFY» без права менять peers. Нужен ли `replication:notify` в v1.1?

Решено Оркестратором и зафиксировано в спецификации: anti-enumeration/`zone_scope` — 403 только за operation-scope, 404 `zone_not_found` для зоны вне allowlist (ADR 0004 SEC-API-014, §2.3); bootstrap-токен — env `PULSED_BOOTSTRAP_TOKEN`/`PULSERESOLVED_BOOTSTRAP_TOKEN` (§2.6), хранилища токенов у процессов раздельные; NSEC3-подпись — `501` до v1.1, валидация NSEC3 — да (§7.6); процессы — два, метрики/jobs/аудит раздельные (§1.1, §7.3); IXFR — in-memory ринг с `AxfrRequired`; state-файл сервера — JSON + `schema_version` (спецификация `docs/spec/server-state-v1.md`, M3).
