# Response Rate Limiting (RRL) резолвера

Дата: 2026-11-24. Относится к `pulseresolved` (модуль `rrl`).

## Назначение

RRL ограничивает **ответы**, а не запросы. Цель — не дать использовать
рекурсивный резолвер для reflection/amplification: подменённый source IP
получает не поток ответов, а ограниченный (или пустой) ответ.

Ограничение применяется только к UDP: TCP-сессию нельзя использовать для
амплификации с подменой адреса.

## Классы ответов

| Класс | Определение |
|---|---|
| `noerror` | `NOERROR` с данными, а также NODATA (`NOERROR`, пустой answer, SOA в authority) |
| `nxdomain` | `NXDOMAIN` |
| `referral` | `NOERROR`, пустой answer, NS в authority и нет SOA |
| `error` | `SERVFAIL`, `REFUSED`, `NOTIMP` и прочие коды |

У каждого класса свой token bucket (`qps`, `burst`), поэтому NXDOMAIN-флуд
не расходует лимит обычных ответов.

## Ключ бакета и память

Проверяются **два** бакета, и ответ ограничивается, если превышен любой:

1. `(source IP, class, FNV-1a hash(name))` — лимит класса (`qps`/`burst`
   соответствующего класса);
2. `(source IP, class)` — агрегированный лимит на источник (`source.qps` /
   `source.burst`), ловит флуд уникальных имён, который не попал бы в
   per-name бакет.

- `source IP` нормализуется: IPv4-mapped IPv6 (`::ffff:a.b.c.d`) считается
  IPv4; IPv4 и IPv6 — разные источники.
- Имя для `noerror`/`error` — QNAME, для `nxdomain`/`referral` —
  **родительское** имя: флуд по случайным поддоменам одной зоны попадает в
  один бакет (аналог zone-level группировки в RRL).
- Каждая таблица шардирована на 16 `Mutex<HashMap>`; лимит `max_entries`
  делится между шардами обеих таблиц. При переполнении сначала удаляются
  записи, простаивавшие > 300 s, затем вытесняется произвольная запись.
  Память ограничена сверху (≈ `max_entries` бакетов); коллизии/вытеснение
  могут дать ложное ограничение, но не рост памяти.

Алгоритм — token bucket: при каждом ответе бакет пополняется
`elapsed * qps` (не выше `burst`); если токенов ≥ 1, ответ разрешён.

## Действия и slip

При превышении:

- `drop` — ответ не отправляется;
- `truncate` — пустой ответ с `TC=1` (клиент повторит по TCP);
- `refused` — `REFUSED`.

`slip` управляет долей ограниченных ответов, которые всё-таки
отправляются: `slip = 0` — отбрасывать все, `1` — отправлять все,
`N` — каждый N-й (остальные `drop`). Это сохраняет видимость работы для
легитимных клиентов при флуде.

## Конфигурация

`pulseresolved` (TOML/JSON, секция `rrl`; выключен, если секции нет):

```toml
[rrl]
enabled = true
slip = 2
max_entries = 20000
action = "truncate"        # drop | truncate | refused

[rrl.noerror]
qps = 20
burst = 100

[rrl.nxdomain]
qps = 5
burst = 20

[rrl.referral]
qps = 10
burst = 40

[rrl.error]
qps = 5
burst = 20

# Агрегированный лимит на источник (все имена/классы).
[rrl.source]
qps = 50
burst = 200
```

```json
"rrl": {
  "enabled": true,
  "slip": 2,
  "max_entries": 20000,
  "action": "truncate",
  "noerror":  { "qps": 20, "burst": 100 },
  "nxdomain": { "qps": 5,  "burst": 20 },
  "referral": { "qps": 10, "burst": 40 },
  "error":    { "qps": 5,  "burst": 20 },
  "source":   { "qps": 50, "burst": 200 }
}
```

Ограничения значений: `slip` 0..=1000, `max_entries` 1..=1 000 000,
`qps` конечный > 0, `burst` > 0. Невалидная включённая секция отклоняется
при старте/`Config::validate`.

Отдельно остаётся `rate_limit` — per-source token bucket на **входящие**
запросы (защита от потока запросов с одного IP). RRL и `rate_limit`
независимы; для чистой проверки RRL `rate_limit` можно выключить.

## Порядок обработки

`ACL → decode → rate_limit (вход) → resolve → RRL (UDP) → encode`.

RRL видит уже готовый ответ, включая ответы из кеша и synthetic
blocklist/overrides, поэтому кеш не обходит ограничение.

## Метрики

`/metrics` (`pulseresolved_rrl_*`), для каждого класса `noerror`,
`nxdomain`, `referral`, `error`:

| Метрика | Смысл |
|---|---|
| `pulseresolved_rrl_limited_total{class}` | ответов ограничено |
| `pulseresolved_rrl_slipped_total{class}` | ограниченных ответов отправлено (slip) |
| `pulseresolved_rrl_dropped_total{class}` | ограниченных ответов отброшено |
| `pulseresolved_rrl_entries` | занятых записей таблицы |

`Server::rrl_stats()` отдаёт тот же снимок для встраивания.

## Тесты

- `pulseresolved` unit (`src/rrl.rs`): классификация, NXDOMAIN-флуд,
  referral-флуд с отдельным бакетом, per-source лимит на флуд уникальных
  имён, легитимные уникальные имена и другие источники, slip = 1/2/0,
  IPv4/IPv6, ограниченная таблица, валидация.
- `pulseresolved/tests/rrl.rs` (e2e UDP): NXDOMAIN-флуд → truncate,
  slip=2 → чередование drop/TC, referral-флуд → REFUSED, положительные
  ответы не ограничиваются NXDOMAIN-бакетом, `/metrics` содержит метрики
  классов, по умолчанию RRL выключен.

## Ограничения

- DNS Cookies (RFC 7873/9018) не реализованы; RRL не заменяет их.
- Группировка по родительскому имени — эвристика; возможны ложные
  ограничения при легитимном флуде уникальных имён одной зоны.
- Нет отдельной настройки для wildcard/ANY: `ANY` и трансферы отклоняются
  раньше (NOTIMP/REFUSED).
- RRL не применяется к TCP и (при появлении) DoT/DoH-входам.
