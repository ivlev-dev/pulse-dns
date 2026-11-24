# `pulsed`: DNS + REST API в одном процессе

`pulsed` использует `pulse-zonefile` как единственный источник истины: DNS
отвечает точечными чтениями из mmap (без полной in-memory копии зон), REST API
пишет в тот же файл и коммитит транзакцию. После коммита новый снапшот сразу
виден DNS — перезапуск не нужен.

Основной формат конфигурации `pulsed` — TOML (`examples/*.toml`). JSON
поддерживается для обратной совместимости (`examples/*.json` — те же
эквиваленты): формат выбирается по расширению файла, CLI-overrides
применяются поверх загруженного конфига. Ошибки разбора содержат путь, строку
и колонку.

## Запуск

```bash
export PULSED_API_TOKEN="$(openssl rand -hex 32)"

cargo run -p pulsed -- \
  --config examples/pulsed.toml \
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
- Те же настройки можно задать в конфигурации (`api_listen`, `api_token`,
  `api_scope`); CLI-overrides применяются поверх файла, `PULSED_API_TOKEN`
  важнее токена из файла.
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

Поля `zones`/`zones_files` больше не принимаются (ни в TOML, ни в JSON) —
запуск завершается с инструкцией миграции.

## Zonefile (`pulse-zonefile`)

Запуск с файлом зон:

```bash
cargo run -p pulsed -- \
  --config examples/persistent.toml
# или CLI:
cargo run -p pulsed -- \
  --config examples/empty.toml \
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

## DNSSEC (authoritative, NSEC/NSEC3)

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

Подпись при старте (ключи в TOML-настройках сервера; сама зона уже в zonefile):

```toml
zonefile = "/tmp/pulse-dns.zonefile"

[dnssec."example.com."]
validity_days = 30
inception_skew = 300
denial = "nsec3"
nsec3_salt = "aabbccddeeff0011"
nsec3_iterations = 5

[[dnssec."example.com.".keys]]
role = "ksk"
path = "keys/Kexample.com.+015+12345.private"

[[dnssec."example.com.".keys]]
role = "zsk"
path = "keys/Kexample.com.+015+54321.private"
```

`denial` — `nsec` (по умолчанию) или `nsec3`. Для NSEC3 поддерживаются SHA-1
(alg 1), соль в hex (`nsec3_salt`; без неё генерируется случайная соль на
время жизни процесса) и `nsec3_iterations` в диапазоне `0..=100`; Opt-Out
всегда выключен. Смена соли при перезапуске/переподписи пересобирает
NSEC3-цепочку. Подписанные DNSKEY/NSEC или NSEC3/NSEC3PARAM/RRSIG коммитятся
в zonefile, а DO=1 отдаёт их из mmap.

Проверка (DO=1 — RRSIG/NSEC; DO=0 — без подписей):

```bash
dig @127.0.0.1 -p 5353 www.example.com. A +dnssec +norecurse
dig @127.0.0.1 -p 5353 nope.example.com. A +dnssec +norecurse   # NXDOMAIN + NSEC/NSEC3
dig @127.0.0.1 -p 5353 www.example.com. AAAA +dnssec +norecurse # NODATA + NSEC/NSEC3
dig @127.0.0.1 -p 5353 example.com. NSEC3PARAM +dnssec +norecurse # NSEC3-параметры
```

Публичные ключи и DS (приватные не отдаются):

```bash
curl -sS -H "Authorization: Bearer $PULSED_API_TOKEN" \
  "$API/api/v1/zones/example.com./keys"

# Переподписать после ручных изменений зоны (NSEC/RRSIG пересобираются):
curl -sS -X POST -H "Authorization: Bearer $PULSED_API_TOKEN" \
  "$API/api/v1/zones/example.com./sign"
```

Ограничения v1: NSEC3 Opt-Out и NSEC3 для secondary-зон не поддерживаются;
`NS` в точке делегирования и glue ниже cut не подписываются; после изменения
зоны через REST вызовите `POST /sign`, иначе подписи/denial-цепочка устареют.

## Защищённые транспорты: DoT, DoH/1.1 и DNSCrypt

`pulsed` умеет одновременно обслуживать UDP/TCP, DNS-over-TLS (RFC 7858),
DNS-over-HTTPS/1.1-2-3 (RFC 8484 + RFC 9113/9114), DNS-over-QUIC (RFC 9250)
и DNSCrypt v2 по UDP и TCP. Все они используют один и тот же путь ответа:
`decode → QueryEngine (mmap snapshot) → encode`, поэтому данные из `--data` и
REST-правки видны сразу на всех транспортах.

Пример конфигурации — `examples/transports.toml` (JSON-эквивалент —
`examples/transports.json`):

```toml
listen_udp = "127.0.0.1:5353"
listen_tcp = "127.0.0.1:5353"
zonefile = "/tmp/pulse-dns.zonefile"
dot_listen = "127.0.0.1:8853"
doh_listen = "127.0.0.1:8443"
doh_h2_listen = "127.0.0.1:8444"
doh3_listen = "127.0.0.1:8445"
doq_listen = "127.0.0.1:8854"
tls_cert = "/tmp/pulsed-tls/cert.pem"
tls_key = "/tmp/pulsed-tls/key.pem"
tls_reload_secs = 300
tls_allow_from = ["127.0.0.0/8", "::1"]
dnscrypt_listen = "127.0.0.1:5443"
dnscrypt_tcp_listen = "127.0.0.1:5444"
dnscrypt_provider_key = "/tmp/pulsed-tls/dnscrypt-provider.key"
dnscrypt_resolver_key = "/tmp/pulsed-tls/dnscrypt-resolver.key"
dnscrypt_cert = "/tmp/pulsed-tls/dnscrypt-cert.json"
dnscrypt_provider_name = "2.dnscrypt-cert.example.com."
```

`dot_listen`/`doh_listen`/`doh_h2_listen`/`doh3_listen`/`doq_listen` требуют
**оба** `tls_cert` и `tls_key`; при
`dnscrypt_listen`/`dnscrypt_tcp_listen` обязательны `dnscrypt_provider_key`,
`dnscrypt_resolver_key` и `dnscrypt_cert`. Приватные ключи должны иметь режим
`0600` (иначе запуск завершается ошибкой), секреты не попадают в логи и
`/metrics`.

DNSCrypt TCP (`dnscrypt_tcp_listen`) использует 2-байтовый length-prefix,
поддерживает несколько запросов на одном соединении и отдаёт большие ответы
без `TC`. Лимиты: `dnscrypt_tcp_max_connections` (по умолчанию 1024),
`dnscrypt_tcp_idle_timeout_ms` (10000) и `dnscrypt_tcp_max_frame` (65535).
Метрики: `dnscrypt_tcp_connections_total`, `dnscrypt_tcp_connections_rejected_total`,
`dnscrypt_tcp_active_connections`, `dnscrypt_tcp_queries_total`,
`dnscrypt_tcp_responses_total`, `dnscrypt_tcp_errors_total`.

### TLS-сертификат и hot-reload

Для локальной проверки подойдёт self-signed сертификат:

```bash
mkdir -p /tmp/pulsed-tls && chmod 700 /tmp/pulsed-tls
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout /tmp/pulsed-tls/key.pem -out /tmp/pulsed-tls/cert.pem \
  -days 365 -nodes -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
chmod 600 /tmp/pulsed-tls/key.pem
```

Сертификат перечитывается для **новых** соединений по `SIGHUP` или каждые
`tls_reload_secs` секунд; уже открытые TLS-сессии продолжают работать со старой
парой. ALPN: `dot` для DoT, `http/1.1` для DoH/1.1, `h2` для DoH/2, `h3` для
DoH/3, `doq` для DoQ. DoH/3 и DoQ применяют новый сертификат к новым
QUIC-соединениям через `endpoint.set_server_config`; 0-RTT выключен.

```bash
kill -HUP "$(pgrep pulsed)"   # перечитать cert.pem/key.pem
```

Проверка через `kdig` из knot-dnsutils:

```bash
kdig @127.0.0.1 -p 8853 +tls +tls-ca=/tmp/pulsed-tls/cert.pem \
  +tls-hostname=localhost www.example.com. A
kdig @127.0.0.1 -p 8443 +https +tls-ca=/tmp/pulsed-tls/cert.pem \
  +tls-hostname=localhost www.example.com. A
kdig @127.0.0.1 -p 8444 +https +tls-ca=/tmp/pulsed-tls/cert.pem \
  +tls-hostname=localhost www.example.com. A       # DoH/2
kdig @127.0.0.1 -p 8854 +quic +tls-ca=/tmp/pulsed-tls/cert.pem \
  +tls-hostname=localhost www.example.com. A       # DoQ
# DoH/3: нужен клиент с HTTP/3 (например, curl --http3-only)
curl -sS --http3-only --cacert /tmp/pulsed-tls/cert.pem \
  https://localhost:8445/healthz
```

DoH/1.1 также можно проверить `curl` (POST `application/dns-message`):
DoH/3 проверяется тем же запросом с `--http3-only` на порту `doh3_listen`.

```bash
# 33-байтовый запрос A www.example.com. (ID 0x1234)
python3 -c 'import sys; sys.stdout.buffer.write(bytes.fromhex("12340100000100000000000003777777076578616d706c6503636f6d0000010001"))' > /tmp/dns-query.bin
curl -sS --http1.1 --cacert /tmp/pulsed-tls/cert.pem \
  -H 'content-type: application/dns-message' \
  --data-binary @/tmp/dns-query.bin \
  https://127.0.0.1:8443/dns-query | xxd
curl -sS --http1.1 --cacert /tmp/pulsed-tls/cert.pem \
  https://127.0.0.1:8443/healthz
```

ACL `tls_allow_from` (IP/CIDR) и лимиты `dot_max_connections`/
`doh_max_connections`/`doh3_max_connections` действуют только на настроенных
адресах; у DoH/3 также есть `doh3_max_concurrent_requests` (на соединение) и
`doh3_idle_timeout_ms`.

### DNSCrypt: ключи, сертификат и TXT

Генератор создаёт provider/resolver ключи, подписанный сертификат и файл с
готовыми TXT-записями. Приватные файлы — `0600`, новый каталог — `0700`;
приватные ключи **не** печатаются:

```bash
cargo run -p pulsed -- dnscrypt-gencert \
  --out /tmp/pulsed-tls \
  --provider-name 2.dnscrypt-cert.example.com. \
  --serial 1 --validity-days 365
```

Вывод содержит `provider_public_key`, пути к файлам и TXT-записи:

- `2.pubkey.2.dnscrypt-cert.example.com. TXT "<provider-pk-hex>"`;
- `2.dnscrypt-cert.example.com. TXT "\068..."` — бинарный сертификат,
  экранированный по RFC 1035.

Публикация TXT автоматически не выполняется. Добавьте строки из
`dnscrypt-cert.txt` в master-файл зоны и переимпортируйте её (`pulsed import
--replace`), либо опубликуйте вручную в родительской зоне. Без TXT клиент
DNSCrypt не сможет получить сертификат (можно передать его вручную в
конфигурации клиента).

Проверка клиентом `pulse-dnscrypt`/dnscrypt-proxy: сервер слушает
`dnscrypt_listen` (UDP) и/или `dnscrypt_tcp_listen` (TCP), сертификат и ключи
берутся из файлов выше. UDP усекает большие ответы с `TC`; TCP отдаёт их без
усечения.

### Метрики

`GET /metrics` REST API дополнен счётчиками транспортов:

```bash
curl -sS -H "Authorization: Bearer $PULSED_API_TOKEN" \
  http://127.0.0.1:8080/metrics \
  | grep -E '^(dot|doh|dnscrypt|pulsed_tls)'
```

Префиксы: `dot_*` (connections, handshakes, queries, responses, bytes,
errors), `doh_*` (то же + `doh_http_requests_total`/`doh_http_errors_total`),
`doh_http2_*`, `doh_http3_*`, `doq_*`, `dnscrypt_*` (packets, queries,
responses, errors, dropped),
`pulsed_tls_reload_total`/`pulsed_tls_reload_errors_total`.

## Primary + secondary (AXFR/IXFR, TSIG, NOTIFY)

Сначала импортируйте зону в файл primary (конфиг указывает `./primary.pulse`):

```bash
cargo run -p pulsed -- import --data ./primary.pulse \
  --origin example.com. examples/example.com.zone
```

Пара конфигов:

```bash
cargo run -p pulsed -- --config examples/pair-primary.toml
cargo run -p pulsed -- --config examples/pair-secondary.toml
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

`examples/resolver.toml` — forward-режим на 1.1.1.1/9.9.9.9, встроенные
корневые trust anchors, blocklist `examples/resolver-blocklist.txt` и три
override-записи:

```bash
cargo run -p pulseresolved -- --config examples/resolver.toml
dig @127.0.0.1 -p 5353 example.com. A
dig @127.0.0.1 -p 5353 ads.example. A    # blocklist → NXDOMAIN
dig @127.0.0.1 -p 5353 router.home. A    # override → 192.168.1.1
curl -sS http://127.0.0.1:9153/metrics
kill -HUP "$(pgrep pulseresolved)"       # перечитать blocklist
```

`examples/resolver-control.toml` включает control-plane REST API на
`127.0.0.1:9154` (только loopback, без TLS). Токен задаётся `control_token`
или env `PULSERESOLVED_API_TOKEN` (env важнее); API не стартует без токена.

```bash
export PULSERESOLVED_API_TOKEN="$(openssl rand -hex 32)"
cargo run -p pulseresolved -- --config examples/resolver-control.toml
AUTH="Authorization: Bearer $PULSERESOLVED_API_TOKEN"
curl -sS http://127.0.0.1:9154/healthz
curl -sS -H "$AUTH" http://127.0.0.1:9154/api/v1/cache/stats
curl -sS -X POST -H "$AUTH" \
  -H 'Content-Type: application/json' \
  -d '{"name":"example.com","type":"A"}' \
  http://127.0.0.1:9154/api/v1/cache/purge
curl -sS -X POST -H "$AUTH" http://127.0.0.1:9154/api/v1/blocklist/reload
curl -sS -H "$AUTH" http://127.0.0.1:9154/api/v1/upstreams
curl -sS -H "$AUTH" http://127.0.0.1:9154/api/v1/trust-anchors
curl -sS -X PATCH -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"slip":4,"nxdomain":{"qps":2,"burst":10}}' \
  http://127.0.0.1:9154/api/v1/rrl
```

Тело запроса ограничено 1 МиБ, ошибки — RFC 9457 problem+json (401/403/404/
405/413/429), каждый ответ содержит `X-Request-Id`. `[control]` задаёт
таймауты, лимит соединений и token bucket на токен.

Основной формат конфигурации — TOML. `examples/resolver.json` — тот же
конфиг в JSON: формат определяется расширением (`.toml` или `.json`),
JSON оставлен для обратной совместимости.

Другие режимы: `mode = "iterative"` (root_hints/ns_port),
`[blocklist] response = "null"` (0.0.0.0/::), `blocklist.reload_secs` для
периодического reload, `[trust_anchor] path = "root.ds"` для собственного
DS-файла (по строке `owner. [TTL] [IN] DS <tag> <alg> <digest-type> <hex>`).

`examples/resolver-secure.json` — смешанные upstream и политика доступа:

```bash
cargo run -p pulseresolved -- --config examples/resolver-secure.json
```

- `upstreams`: URL (`udp://`, `tcp://`, `tls://host:853#servername`,
  `https://host/dns-query`) или объекты `{ "addr": "...", "tls": true,
  "server_name": "localhost", "ca": "path/to/ca.pem" }` (TOML: `{ url = "...",
  ca = "path/to/ca.pem" }`). Для self-signed upstream укажите `ca`; без `ca`
  используется webpki-roots.
- `allow_from`: IP/CIDR клиентов. Пусто — только `127.0.0.0/8` и `::1/128`,
  остальным REFUSED (`pulseresolved_refused_acl_total`).
- `rate_limit`: per-source token bucket (`qps`, `burst`, `max_entries`,
  `action` = `refused` | `drop` | `truncate`).
- Failover идёт по порядку списка; после `max_failures` ошибок upstream
  уходит в `cooldown`, затем снова пробуется.
- Для DoT/DoH клиент держит одно keep-alive-соединение на upstream; при
  обрыве переподключается. Сертификат проверяется по CN/SAN из
  `server_name`/URL.

### Серверные защищённые транспорты

`examples/resolver-secure-transports.toml` поднимает всё сразу: DoT
(`dot_listen`), DoH/1.1 (`doh_listen`), DoH/2 (`doh2_listen`), DoQ
(`doq_listen`), DNSCrypt v2 UDP/TCP (`dnscrypt_listen`,
`dnscrypt_tcp_listen`).

```bash
cargo run -p pulseresolved -- --config examples/resolver-secure-transports.toml
kdig @127.0.0.1 -p 853  +tls   +tls-ca=/etc/pulse/tls/fullchain.pem \
  +tls-hostname=dns.example example.com. A
kdig @127.0.0.1 -p 443  +https +tls-ca=/etc/pulse/tls/fullchain.pem \
  +tls-hostname=dns.example example.com. A
kdig @127.0.0.1 -p 8443 +https +tls-ca=/etc/pulse/tls/fullchain.pem \
  +tls-hostname=dns.example example.com. A
kdig @127.0.0.1 -p 8853 +quic  +tls-ca=/etc/pulse/tls/fullchain.pem \
  +tls-hostname=dns.example example.com. A
```

- `tls_cert`/`tls_key` обязательны для DoT/DoH/DoH2/DoQ; ключ — режим
  `0600` (проверяется при валидации и старте). SIGHUP перечитывает пару.
- DNSCrypt требует `dnscrypt_provider_key`, `dnscrypt_resolver_key` (hex,
  `0600`) и `dnscrypt_cert` (JSON от `pulsed dnscrypt-gencert`, либо
  hex/base64). Сертификат DNSCrypt перезапускается только рестартом.
- `tls_allow_from` — отдельный ACL TLS-транспортов; пусто — общий
  `allow_from`. Запрос вне ACL получает `REFUSED` (для DNSCrypt — в
  зашифрованном виде) до обращения к резолверу.
- `[secure]` — `max_connections`, `max_streams`, таймауты рукопожатия/
  простоя/shutdown, `max_message_size`, `worker_threads`,
  `max_requests_per_connection`, `cache_control`. `[dnscrypt]` — лимиты
  пакетов, `min_query_len`, anti-replay, усечение UDP с `TC`.
- RRL действует только на открытый UDP; на TLS/QUIC/DNSCrypt — `rate_limit`
  token bucket. Метрики: `pulseresolved_queries_total{transport="dot"|"doh"|
  "doh_http2"|"doq"|"dnscrypt_udp"|"dnscrypt_tcp"}`, а также
  `pulseresolved_{dot,doh,doh_http2,doq}_*` и
  `pulseresolved_dnscrypt_*`.

## DNSSEC: NSEC3 Opt-Out, ротация ключей и RFC 5011

### NSEC3 Opt-Out (`pulsed`)

`nsec3_opt_out = true` включает RFC 5155 Opt-Out: insecure-делегирования
(NS без DS) не получают NSEC3-запись, флаг Opt-Out устанавливается на всех
NSEC3 зоны, а DS-запрос к такому делегированию получает closest-encloser
proof + покрытие имени. Полный пример — `examples/dnssec-rotation.toml`
(JSON-эквивалент — `examples/dnssec-rotation.json`); минимальный фрагмент:

```toml
denial = "nsec3"
nsec3_salt = "aabbccddeeff0011"
nsec3_iterations = 0
nsec3_opt_out = true
```

Валидатор `pulse-dnssec` возвращает `DenialResult { opt_out: true }` для
NXDOMAIN/NODATA, которые могут скрывать insecure delegation; такие ответы
не считаются secure.

### Автоматическая ротация (`pulsed`)

Секция `rotation` включает управление ключами по RFC 7583. Сервер сам
генерирует ключи в `key_dir` (`0700`), хранит состояние в `state_path`
(атомарная запись `0600`) и проходит стадии:

1. `pre_publish` — новый DNSKEY опубликован, но не подписывает;
2. `double_sign` — старый и новый ключи подписывают;
3. `active` — новый ключ единственный подписант;
4. `retired` — старый DNSKEY ещё публикуется, затем удаляется после
   `retire_secs`.

`GET /api/v1/zones/<origin>/keys` возвращает `rotation.keys[].state` и
`next_event_at`; `POST .../sign` продвигает состояние по текущему времени.
Фоновая проверка идёт раз в `tick_secs`. Пример:
`examples/dnssec-rotation.toml`.

```bash
pulsed --config examples/dnssec-rotation.toml \
       --api-listen 127.0.0.1:8080 --api-token "$PULSED_API_TOKEN"
curl -H "Authorization: Bearer $PULSED_API_TOKEN" \
     http://127.0.0.1:8080/api/v1/zones/example.com./keys
```

### RFC 5011 в резолвере (`pulseresolved`)

`examples/resolver-rfc5011.toml`:

```toml
[trust_anchor]
path = "/etc/pulsed/root.ds"       # начальные DS (examples/root.ds)
state = "/var/lib/pulsed/trust-anchors/state.json"
add_hold_down = 2592000            # 30 дней
revoke_hold_down = 2592000
```

Каталог файла состояния должен быть `0700` (создаётся автоматически при
первой записи). Резолвер использует активные anchors из состояния, а валидированные
`DNSKEY` root-зоны передаёт в `TrustAnchorStore`: новые KSK проходят
add hold-down, KSK с REVOKE-битом — revoke hold-down; выпавший кандидат
откатывается. Состояние переживает рестарт. CLI-эквивалент:

```bash
pulseresolved --config examples/resolver-rfc5011.toml \
  --trust-anchor /etc/pulsed/root.ds \
  --trust-anchor-state /var/lib/pulsed/trust-anchors/state.json \
  --trust-anchor-hold-down 2592000
```
