# `pulsed`: DNS + REST API в одном процессе

`pulsed` использует `pulse-zonefile` как единственный источник истины: DNS
отвечает точечными чтениями из mmap (без полной in-memory копии зон), REST API
пишет в тот же файл и коммитит транзакцию. После коммита новый снапшот сразу
виден DNS — перезапуск не нужен.

## Запуск

```bash
export PULSED_API_TOKEN="$(openssl rand -hex 32)"

cargo run -p pulsed -- \
  --config examples/pulsed.json \
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

## Импорт зон из master-файлов (.zone)

В рантайме master-файлы не читаются: их импортирует отдельная команда
`pulsed import`. Поддерживаются RFC 1035 master-файлы через `pulse-master`:
`$ORIGIN`, `$TTL`, `$INCLUDE` (внутри каталога файла), относительные имена,
`(...)`, комментарии.

```bash
cargo run -p pulsed -- import \
  --data /tmp/pulse-dns.zonefile \
  --origin example.com. \
  examples/example.com.zone

# повторный импорт существующей зоны — только с --replace
cargo run -p pulsed -- import --replace \
  --data /tmp/pulse-dns.zonefile \
  --origin example.com. \
  examples/example.com.zone
```

Опции: `--durability sync|flush|memory`, `--map-size`, `--replace`.
`--sign` подписывает зону перед записью; ключи задаются повторяемым
`--dnssec-key <origin>=<role:path>`. Ошибки парсера печатаются как
`path:line:column: причина`, процесс завершается с кодом `2`.

Файл `examples/example.com.zone` содержит SOA/NS/A/AAAA/MX/TXT/CNAME/wildcard.
`$ORIGIN` внутри файла допускается; owner'ы обязаны оставаться внутри
`--origin`. Относительные пути считаются от текущего каталога процесса.

JSON-поля `zones`/`zones_files` больше не принимаются — запуск завершается с
инструкцией миграции.

## Zonefile (`pulse-zonefile`)

Запуск с файлом зон:

```bash
cargo run -p pulsed -- \
  --config examples/persistent.json
# или CLI:
cargo run -p pulsed -- \
  --config examples/empty.json \
  --data /tmp/pulse-dns.zonefile \
  --durability flush \
  --map-size 268435456
```

Все зоны живут в `--data`. Каждый успешный REST PUT/PATCH/DELETE коммитится
до обновления DNS-снапшота; DNS-ответы читают тот же mmap. При shutdown
выполняется `sync()`. `durability`: `sync` (данные + meta), `flush` (по
умолчанию: данные синхронизируются, meta — нет), `memory` (без fsync). После
первого `sync` формат липко переходит в `sync`-режим для следующих коммитов.

Ограничения: один writer на файл (`LOCK_EX`; второй процесс получает `busy`),
нет journal/outbox; при мутации пересобирается только список зон и пин
снапшота (данные не материализуются), `map_size` — размер sparse-файла и
задаётся при создании (по умолчанию 4 GiB). При ошибке
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

Импортированные зоны обязаны иметь apex SOA/NS (state `Serving`);
незавершённые зоны создаются через API. Serial внутри RDATA SOA задаётся явно
пользователем; метаданные зоны ведут отдельный serial коммитов.

## DNSSEC (authoritative, NSEC)

`pulsed` подписывает зону при загрузке, если для её origin заданы ключи. Ключи
читаются из BIND-пары `K*.key`/`K*.private` (роль можно вывести из SEP-бита
`.key`) или из PKCS#8 PEM/DER. Приватный файл обязан иметь режим `0600`
(каталог `0700`); более широкие права — ошибка запуска. Приватные ключи не
логируются и не отдаются через API.

Подпись при импорте:

```bash
cargo run -p pulsed -- import --sign \
  --data /tmp/pulse-dns.zonefile \
  --origin example.com. \
  --dnssec-key example.com.=ksk:keys/ksk.private \
  --dnssec-key example.com.=zsk:keys/zsk.private \
  examples/example.com.zone
```

Подпись при старте (ключи в JSON-настройках сервера; сама зона уже в zonefile):

```json
{
  "zonefile": "/tmp/pulse-dns.zonefile",
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

Подписанные DNSKEY/NSEC/RRSIG коммитятся в zonefile, а DO=1 отдаёт их из
mmap.

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

Сначала импортируйте зону в файл primary (конфиг указывает `./primary.pulse`):

```bash
cargo run -p pulsed -- import --data ./primary.pulse \
  --origin example.com. examples/example.com.zone
```

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
