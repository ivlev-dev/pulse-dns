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

## Зоны из master-файлов (.zone)

Поддерживаются RFC 1035 master-файлы через `pulse-master`: `$ORIGIN`, `$TTL`,
`$INCLUDE` (внутри каталога файла), относительные имена, `(...)`, комментарии.
Источники можно смешивать; одинаковый origin в JSON/файлах/`--zone` — ошибка
запуска. REST API правит тот же store.

Через JSON (`zones_files`):

```bash
cargo run -p pulsed -- --config examples/master-files.json
dig @127.0.0.1 -p 5353 www.example.com. A +norecurse
dig @127.0.0.1 -p 5353 missing.example.com. A +norecurse   # NXDOMAIN
```

Через CLI (`--zone` повторяемый; `empty.json` — конфиг без зон):

```bash
cargo run -p pulsed -- --config examples/empty.json \
  --zone example.com.=examples/example.com.zone
```

Файл `examples/example.com.zone` содержит SOA/NS/A/AAAA/MX/TXT/CNAME/wildcard.
`$ORIGIN` внутри файла допускается; owner'ы обязаны оставаться внутри origin
из ключа `--zone`/`zones_files`. Относительные пути считаются от текущего
каталога процесса. Ошибки парсера печатаются как `path:line:column: причина`,
процесс завершается с кодом `2`.

## Persistence (`pulse-zonefile`)

Включение файла зон:

```bash
cargo run -p pulsed -- \
  --config examples/persistent.json
# или CLI:
cargo run -p pulsed -- \
  --config examples/master-files.json \
  --data /tmp/pulse-dns.zonefile \
  --durability flush \
  --map-size 268435456
```

Первый запуск при отсутствии (или пустом) файле импортирует JSON/master-зоны
и делает `commit`. Последующие запуски читают зоны из файла; JSON/master
источники **игнорируются** — файл является источником истины. Чтобы
переимпортировать конфиг, удалите файл зон. Относительные пути (`zonefile`,
`zones_files`, `--data`) считаются от текущего каталога процесса.

Каждый успешный REST PUT/PATCH/DELETE пишется в `pulse-zonefile` и
коммитится до обновления DNS-снапшота. При shutdown выполняется `sync()`.
`durability`: `sync` (данные + meta), `flush` (по умолчанию: данные
синхронизируются, meta — нет), `memory` (без fsync). После первого `sync`
формат липко переходит в `sync`-режим для следующих коммитов.

Ограничения: один writer на файл (`LOCK_EX`; второй процесс получает `busy`),
write-through без journal/outbox, при мутации пересобирается полный
in-memory снапшот всех зон (не только изменённой), `map_size` — размер
sparse-файла и задаётся при создании (по умолчанию 4 GiB). При ошибке
`MapFull`/повреждении/несовместимой версии API возвращает `500 storage-error`,
а запуск завершается fail-closed.

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

## DNSSEC (authoritative, NSEC)

`pulsed` подписывает зону при загрузке, если для её origin заданы ключи. Ключи
читаются из BIND-пары `K*.key`/`K*.private` (роль можно вывести из SEP-бита
`.key`) или из PKCS#8 PEM/DER. Приватный файл обязан иметь режим `0600`
(каталог `0700`); более широкие права — ошибка запуска. Приватные ключи не
логируются и не отдаются через API.

JSON-конфигурация:

```json
{
  "zones_files": [{"origin": "example.com.", "path": "examples/example.com.zone"}],
  "dnssec": {
    "example.com.": {
      "keys": [
        {"role": "ksk", "path": "keys/Kexample.com.+015+12345.private"},
        {"role": "zsk", "path": "keys/Kexample.com.+015+54321.private"}
      ],
      "validity_days": 30,
      "inception_skew": 300
    }
  }
}
```

CLI (повторяемый; роль опциональна):

```bash
cargo run -p pulsed -- --config examples/empty.json \
  --zone example.com.=examples/example.com.zone \
  --dnssec-key example.com.=ksk:keys/ksk.private \
  --dnssec-key example.com.=zsk:keys/zsk.private
```

Проверка (DO=1 — RRSIG/NSEC; DO=0 — без подписей):

```bash
dig @127.0.0.1 -p 5353 www.example.com. A +dnssec +norecurse
dig @127.0.0.1 -p 5353 nope.example.com. A +dnssec +norecurse   # NXDOMAIN + NSEC
dig @127.0.0.1 -p 5353 www.example.com. AAAA +dnssec +norecurse # NODATA + NSEC
```

Публичные ключи и DS (приватные не отдаются):

```bash
curl -sS -H "Authorization: Bearer $PULSED_API_TOKEN" \
  "$API/api/v1/zones/example.com./keys"

# Переподписать после ручных изменений зоны (NSEC/RRSIG пересобираются):
curl -sS -X POST -H "Authorization: Bearer $PULSED_API_TOKEN" \
  "$API/api/v1/zones/example.com./sign"
```

Ограничения v1: только NSEC (NSEC3-подпись не генерируется); `NS` в точке
делегирования и glue ниже cut не подписываются; после изменения зоны через
REST вызовите `POST /sign`, иначе подписи/NSEC-цепочка устареют.

## Primary + secondary (AXFR/IXFR, TSIG, NOTIFY)

Пара конфигов:

```bash
cargo run -p pulsed -- --config examples/pair-primary.json
cargo run -p pulsed -- --config examples/pair-secondary.json
```

- primary слушает `127.0.0.1:5353`, отдаёт AXFR/IXFR по TCP с TSIG и шлёт
  NOTIFY на `127.0.0.1:5354`;
- secondary слушает `127.0.0.1:5354`, при старте делает AXFR, затем обновляется
  по NOTIFY и периодическому SOA-запросу, данные пишет в `secondary.pulse`;
- `tsig_key` secondary ссылается на имя из общего `tsig_keys`;
- `refresh`/`retry`/`expire` в `secondary_zones` переопределяют SOA-таймеры
  (если не заданы — берутся из SOA после первого трансфера);
- `bootstrap: false` отключает автоматический AXFR при отсутствии зоны:
  зона появится после NOTIFY от master;
- secondary read-only: REST PUT/PATCH/DELETE RRset возвращает `409`
  `zone-read-only`; данные меняются только трансфером;
- после `expire` без успешного обновления зона отвечает `SERVFAIL`, но
  остаётся в zonefile и восстанавливается следующим успешным AXFR/IXFR.

Проверка:

```bash
dig @127.0.0.1 -p 5354 example.com. SOA +norecurse
dig @127.0.0.1 -p 5354 www.example.com. A +norecurse
```

## Резолвер `pulseresolved`

`examples/resolver.json` — forward-режим на 1.1.1.1/9.9.9.9, встроенные
корневые trust anchors, blocklist `examples/resolver-blocklist.txt` и три
override-записи:

```bash
cargo run -p pulseresolved -- --config examples/resolver.json
dig @127.0.0.1 -p 5353 example.com. A
dig @127.0.0.1 -p 5353 ads.example. A    # blocklist → NXDOMAIN
dig @127.0.0.1 -p 5353 router.home. A    # override → 192.168.1.1
curl -sS http://127.0.0.1:9153/metrics
kill -HUP "$(pgrep pulseresolved)"       # перечитать blocklist
```

Другие режимы: `mode: "iterative"` (root_hints/ns_port), `blocklist.response:
"null"` (0.0.0.0/::), `blocklist.reload_secs` для периодического reload,
`trust_anchor: {"path": "root.ds"}` для собственного DS-файла (по строке
`owner. [TTL] [IN] DS <tag> <alg> <digest-type> <hex>`).
