# `pulsed`: DNS + REST API в одном процессе

`pulsed` держит один `pulse-api::InMemoryZoneAdmin`: JSON-зоны загружаются в
него при старте, REST API мутирует тот же store, а DNS отвечает по снапшоту,
который перестраивается после каждой успешной мутации. Перезапуск не нужен.

## Запуск

```bash
export PULSED_API_TOKEN="$(openssl rand -hex 32)"

cargo run -p pulsed -- \
  --config examples/zones.json \
  --listen-udp 127.0.0.1:5353 \
  --listen-tcp 127.0.0.1:5353 \
  --api-listen 127.0.0.1:8080 \
  --api-scope example.com.
```

- `--api-listen` включает API; без него API выключен, даже если токен задан.
- `--api-token` или `PULSED_API_TOKEN` обязателен при включённом API.
  Предпочтителен env: токен не попадает в `ps`/историю shell.
- `--api-scope` повторяемый allowlist: точный origin (`example.com.`) или
  `*.internal.`. Без флагов токен видит все зоны.
- Без TLS API разрешён только на loopback-адресе (политика `pulse-api`).

## Пример: создать зону и получить A по DNS

```bash
API=http://127.0.0.1:8080
AUTH="Authorization: Bearer $PULSED_API_TOKEN"
JSON="Content-Type: application/json"

# 1. Зона создаётся пустой: в DNS состояние Initializing → REFUSED.
curl -sS -X PUT "$API/api/v1/zones/dynamic.test." \
  -H "$AUTH" -H 'If-None-Match: *' -H "$JSON" \
  -d '{"kind":"primary","default_ttl":3600}'

# 2. SOA в apex. Пока нет NS, зона всё ещё Initializing.
curl -sS -X PUT "$API/api/v1/zones/dynamic.test./records/@/SOA" \
  -H "$AUTH" -H "$JSON" \
  -d '{"ttl":3600,"records":["ns1.dynamic.test. hostmaster.dynamic.test. 1 3600 600 604800 300"]}'

# 3. NS в apex переводит зону в Serving.
curl -sS -X PUT "$API/api/v1/zones/dynamic.test./records/@/NS" \
  -H "$AUTH" -H "$JSON" \
  -d '{"ttl":3600,"records":["ns1.dynamic.test."]}'

# 4. A для www.dynamic.test.
curl -sS -X PUT "$API/api/v1/zones/dynamic.test./records/www.dynamic.test./A" \
  -H "$AUTH" -H "$JSON" \
  -d '{"ttl":300,"records":["192.0.2.55"]}'

dig @127.0.0.1 -p 5353 www.dynamic.test. A +norecurse
# → 192.0.2.55, AA=1
```

## Изменение и удаление

ETag читается из ответа `PUT`/`PATCH`/`GET`; для изменения существующего
ресурса `If-Match` обязателен.

```bash
ETAG=$(curl -sS -D - -o /dev/null -H "$AUTH" \
  "$API/api/v1/zones/dynamic.test./records/www.dynamic.test./A" \
  | tr -d '\r' | awk -F': ' 'tolower($1)=="etag"{print $2}')

curl -sS -X PATCH "$API/api/v1/zones/dynamic.test./records/www.dynamic.test./A" \
  -H "$AUTH" -H "If-Match: $ETAG" -H "$JSON" \
  -d '{"ttl":300,"add":["192.0.2.66"],"remove":["192.0.2.55"]}'

dig @127.0.0.1 -p 5353 www.dynamic.test. A +norecurse
# → 192.0.2.66 без рестарта
```

Удаление RRset:

```bash
ETAG=... # актуальный ETag из GET/PATCH
curl -sS -X DELETE "$API/api/v1/zones/dynamic.test./records/www.dynamic.test./A" \
  -H "$AUTH" -H "If-Match: $ETAG"

dig @127.0.0.1 -p 5353 www.dynamic.test. A +norecurse
# → NOERROR, 0 answers (NODATA): имя осталось empty node
```

Удаление зоны:

```bash
ZONE_ETAG=$(curl -sS -D - -o /dev/null -H "$AUTH" \
  "$API/api/v1/zones/dynamic.test." \
  | tr -d '\r' | awk -F': ' 'tolower($1)=="etag"{print $2}')

curl -sS -X DELETE "$API/api/v1/zones/dynamic.test." \
  -H "$AUTH" -H "If-Match: $ZONE_ETAG"

dig @127.0.0.1 -p 5353 www.dynamic.test. A +norecurse
# → REFUSED: зоны больше нет в каталоге
```

## Семантика зон

| Состояние store | DNS |
|---|---|
| зона есть, `kind=primary`, apex `SOA` (ровно один) и apex `NS` есть | `Serving`: обычные ответы |
| зона есть, но нет SOA или NS | `Initializing`: `REFUSED` |
| `kind=secondary`/`forward` | `Initializing`: `REFUSED` (трансферы вне MVP) |
| зона удалена | `REFUSED` (нет зоны, не `NXDOMAIN`) |
| RRset удалён, у имени остались другие RRset или это пустой узел | `NODATA` |
| имя никогда не существовало | `NXDOMAIN` |

`PUT /zones/{origin}` создаёт пустую зону без SOA/NS. `SOA` теперь можно
задавать через RRset API, но только в apex и ровно одной записью. `SOA` вне
apex и несколько SOA отклоняются с `422`/`invariant violation`. `CNAME` не
может сосуществовать с другими типами и не допускается в apex. TTL всех
записей одного RRset должен совпадать.

Зоны из `--config` при старте обязаны иметь apex SOA/NS (fail-fast, как и
раньше); незавершённые зоны создаются через API. Serial внутри RDATA SOA
задаётся явно пользователем; метаданные зоны ведут отдельный serial коммитов.
