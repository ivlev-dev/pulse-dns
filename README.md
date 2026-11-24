# pulse-dns

![CI](https://github.com/ivlev-dev/pulse-dns/actions/workflows/ci.yml/badge.svg)

Модульный высокопроизводительный DNS-сервер на Rust. Linux-first, edition 2024
(stable). Текущее состояние — **authoritative MVP + кеширующий резолвер**:
авторитетный сервер (`pulsed`) с UDP/TCP, REST API и `pulse-zonefile` как
единственным источником истины зон (DNS читает mmap, REST коммитит в файл), а
также резолвер (`pulseresolved`) с
forward/iterative-резолюцией, кешем, blocklist, overrides и DNSSEC-валидацией.
Это не полный продукт из ТЗ (нет DoQ, RRL и т.д.). DoT, DoH (HTTP/1.1) и
DNSCrypt v2 (авторитетный сервер) реализованы.

## Возможности

**Работает:**

- Wire-формат DNS (`pulse-dns`): RR-типы A/AAAA/NS/CNAME/SOA/PTR/MX/TXT/SRV/
  CAA/DNAME/DS/DNSKEY/RRSIG/NSEC/NSEC3/NSEC3PARAM/TLSA/SVCB/HTTPS/Unknown,
  сжатие имён, EDNS0, RFC 3597, канонизация RFC 4034, лимиты, `unsafe` запрещён.
- Авторитетный движок запросов (`pulse-server`): NXDOMAIN/NODATA/ENT, wildcard и
  closest encloser, CNAME/DNAME, делегация/glue/DS, EDNS/BADVERS, TC, ANY по
  RFC 8482, детерминированный additional.
- Рантайм (`pulse-runtime`): io_uring UDP (ring на ядро, multishot recv +
  provided buffers, IP_PKTINFO, проверка NODROP, backpressure, graceful
  shutdown, изоляция паник) + epoll-фолбэк.
- Формат зон (`pulse-zonefile`): v2 `ParallelStore` — один mmap-файл,
  lock-free аллокатор страниц, ring-головы версий A/B, chain, per-zone пулы и
  GC, in-process пины читателей, group commit (2 `fdatasync` на группу зон),
  `Flush`/`Memory`/`Sync`, recovery и `fsck`; v1-файлы читаются для
  `pulsed convert`.
- REST API (`pulse-api`): health/ready/metrics/OpenAPI, zones CRUD, RRset
  CRUD/PATCH, settings, bearer-auth + scopes + per-zone allowlist (404 вне
  allowlist), ETag/If-Match, RFC 9457 problem+json, Idempotency-Key,
  пагинация, лимиты тела/rate limit.
- Бинарник `pulsed`: UDP+TCP, зоны только в `pulse-zonefile` v2 (`--data`;
  DNS отвечает из mmap, без полной in-memory копии), импорт RFC 1035
  master-файлов командой `pulsed import` (`.zone`, `$ORIGIN`/`$TTL`/`$INCLUDE`),
  конвертация legacy v1-файлов `pulsed convert`, REST с per-zone writer'ами
  (разные зоны коммитятся параллельно; `--commit-mode per-zone|group`,
  `sync`/`flush`/`memory`), graceful shutdown, AXFR/IXFR-out по TCP с TSIG/ACL,
  IXFR-история, NOTIFY-out/in и secondary-зоны (AXFR/IXFR-in, bootstrap,
  SOA-refresh, expire → SERVFAIL), DNSSEC-подпись в zonefile, Dockerfile.
- Защищённые транспорты `pulsed`: DoT (`dot_listen`, RFC 7858), DoH/1.1
  (`doh_listen`, RFC 8484, ALPN `http/1.1`, только HTTP/1.1) и DNSCrypt v2 по
  UDP (`dnscrypt_listen`), общий путь `decode → QueryEngine (mmap) → encode`,
  TLS hot-reload по `SIGHUP`/`tls_reload_secs`, IP/CIDR ACL и лимиты,
  `pulsed dnscrypt-gencert` (ключи 0600, каталог 0700, TXT-записи), метрики
  `dot_*`/`doh_*`/`dnscrypt_*` в `/metrics`.
- Бинарник `pulseresolved`: forward/iterative-резолюция через `pulse-resolver`,
  UDP на `pulse-runtime` (N worker) и TCP с length-prefix, EDNS/TC, REFUSED
  для AXFR/IXFR, кеш, blocklist + overrides, DNSSEC-валидация (AD/SERVFAIL),
  SIGHUP/периодический reload, `GET /metrics` и `GET /healthz` на loopback,
  graceful shutdown по SIGTERM/SIGINT.

**Не реализовано (см. `STATUS.md`):** commit/allocator/GC и параллельная запись
по зонам в коде (только дизайн, ADR 0005/0006, spec parallel-writes-v2);
journal/outbox и параллельная запись в zonefile; DoQ; DNSCrypt TCP-транспорт
(только UDP); HTTP/2/3 для DoH; 0x20 echo; TLS
для API и метрик (только loopback); fuzz/Miri/loom в CI; полноценный RRL; REST —
MVP-подмножество спецификации. У резолвера нет RRL, DoT/DoH-апстримов и
RFC 5011 (trust anchors статические).

## Архитектура

| Крейт | Назначение |
|---|---|
| `pulse-dns` | Wire-формат DNS и RR-типы |
| `pulse-master` | RFC 1035 master-файлы: парсер, валидация, экспорт |
| `pulse-zonefile` | Бинарный mmap-формат зон: reader, writer/commit, fsck, compact |
| `pulse-runtime` | io_uring UDP-рантайм + epoll-фолбэк |
| `pulse-server` | Авторитетный движок запросов |
| `pulse-tls` | DNS over TLS (RFC 7858) и DNS over HTTPS/1.1 (RFC 8484) |
| `pulse-dnscrypt` | DNSCrypt v2: сертификаты, сервер, клиент |
| `pulse-api` | REST API управления зонами |
| `pulse-resolver` | Кеширующий резолвер: forward/iterative, кеш, blocklist, overrides, DNSSEC |
| `pulsed` | Бинарник сервера (UDP+TCP+DoT+DoH+DNSCrypt+REST) |
| `pulseresolved` | Бинарник резолвера (UDP+TCP+метрики) |

Спецификации и решения: `docs/adr/`, `docs/spec/`, `docs/api/rest-v1.md`,
`docs/bench/plan.md`, `docs/plan/roadmap.md`.

## Быстрый старт

Сборка:

```bash
cargo build --release
```

Импорт зоны и запуск `pulsed`:

```bash
cargo run -p pulsed -- import \
  --data /tmp/pulse-dns.zonefile \
  --origin example.com. \
  examples/example.com.zone

export PULSED_API_TOKEN="$(openssl rand -hex 32)"

cargo run -p pulsed -- \
  --config examples/pulsed.json \
  --data /tmp/pulse-dns.zonefile \
  --listen-udp 127.0.0.1:5353 \
  --listen-tcp 127.0.0.1:5353 \
  --api-listen 127.0.0.1:8080 \
  --api-scope example.com.
```

Проверка UDP/TCP:

```bash
dig @127.0.0.1 -p 5353 example.com. A +norecurse
dig @127.0.0.1 -p 5353 example.com. MX +tcp +norecurse
```

DoT/DoH/DNSCrypt (самоподписанный сертификат и генерация DNSCrypt-ключей —
подробнее в `examples/README.md`):

```bash
mkdir -p /tmp/pulsed-tls && chmod 700 /tmp/pulsed-tls
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout /tmp/pulsed-tls/key.pem -out /tmp/pulsed-tls/cert.pem \
  -days 365 -nodes -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
chmod 600 /tmp/pulsed-tls/key.pem

cargo run -p pulsed -- dnscrypt-gencert --out /tmp/pulsed-tls \
  --provider-name 2.dnscrypt-cert.example.com.

cargo run -p pulsed -- --config examples/transports.json \
  --data /tmp/pulse-dns.zonefile

kdig @127.0.0.1 -p 8853 +tls +tls-ca=/tmp/pulsed-tls/cert.pem \
  +tls-hostname=localhost www.example.com. A
kdig @127.0.0.1 -p 8443 +https +tls-ca=/tmp/pulsed-tls/cert.pem \
  +tls-hostname=localhost www.example.com. A
# DNSCrypt: клиент pulse-dnscrypt/dnscrypt-proxy, сертификат из
# /tmp/pulsed-tls/dnscrypt-cert.json, TXT — /tmp/pulsed-tls/dnscrypt-cert.txt
```

Запуск резолвера (forward на 1.1.1.1/9.9.9.9, blocklist и overrides из
`examples/resolver.json`):

```bash
cargo run -p pulseresolved -- --config examples/resolver.json
dig @127.0.0.1 -p 5353 example.com. A
dig @127.0.0.1 -p 5353 ads.example. A          # blocklist → NXDOMAIN
dig @127.0.0.1 -p 5353 router.home. A          # override → 192.168.1.1
dig @127.0.0.1 -p 5353 example.com. A +tcp     # TCP length-prefix
curl -sS http://127.0.0.1:9153/healthz
curl -sS http://127.0.0.1:9153/metrics | head
# После правки blocklist: kill -HUP <pid> (или blocklist.reload_secs > 0)
```

CLI: `--config`, `--listen-udp`, `--listen-tcp`, `--metrics-listen`,
`--forward` (repeatable), `--workers`, `--log-level`, `--blocklist`
(repeatable), `--no-dnssec`.

Зоны в `pulse-zonefile` v2:

```bash
# импорт (повторный --replace; опционально --sign с --dnssec-key)
cargo run -p pulsed -- import \
  --data /tmp/pulse-dns.zonefile \
  --origin example.com. \
  examples/example.com.zone

# legacy v1 → v2 (без потери зон/записей/настроек)
cargo run -p pulsed -- convert --from /tmp/old.v1 --to /tmp/pulse-dns.zonefile

cargo run -p pulsed -- --config examples/pulsed.json \
  --data /tmp/pulse-dns.zonefile --durability flush \
  --commit-mode per-zone --map-size 268435456
```

JSON-поля `zones`/`zones_files` больше не принимаются: конфигурация завершится
с инструкцией миграции. Все зоны живут в `--data`; REST-правки коммитятся в
тот же файл и сразу видны DNS.

Подробности — в `examples/README.md`.

Запуск с REST: API включается флагом `--api-listen` (токен обязателен,
предпочтительно через `PULSED_API_TOKEN`; без TLS только loopback). Примеры
запросов — в `examples/README.md`. Короткий пример:

```bash
API=http://127.0.0.1:8080
curl -sS -X PUT "$API/api/v1/zones/dynamic.test." \
  -H "Authorization: Bearer $PULSED_API_TOKEN" \
  -H 'If-None-Match: *' -H 'Content-Type: application/json' \
  -d '{"kind":"primary","default_ttl":3600}'
```

## Тесты

```bash
cargo test --workspace
```

Полный набор workspace-тестов (включая doctests) проходит. Также проходят
`cargo fmt --check`, `cargo clippy --workspace --all-targets -D warnings` и
rustdoc без warnings.

Проверка зависимостей:

```bash
cargo deny check
```

## Производительность

Замеры на loopback, хост был загружен — числа консервативные.

| Показатель | Значение |
|---|---|
| UDP echo, 4 worker / 4 клиента, окно 16 | 220 117 qps |
| epoll, те же условия | 230 352 qps |
| UDP echo, окно 1 | 89 036 qps, p50 35 µs, p99 182 µs |
| Zone lookup | 156–268 нс |
| RRset lookup при 1M | ~2–4.9 µs (цель 500 нс не достигнута) |
| Insert | ~10 000/s |
| Аллокации на warm lookup | 0 |

## Ограничения и roadmap

- Зоны хранятся в памяти (нет персистентности); commit/allocator и
  параллельная запись по зонам — только в дизайне.
- DoT/DoH работают синхронно (поток на соединение), DoH — только HTTP/1.1;
  DNSCrypt реализован только по UDP (TCP-порт не поднимается, большие ответы
  усекаются с `TC`); DNSCrypt TXT-запись публикуется вручную.
- REST — MVP-подмножество спецификации; API доступен только на loopback.
- Roadmap: `docs/plan/roadmap.md` (M0 выполнено, M1 в работе).

## Лицензия

MIT OR Apache-2.0. См. `LICENSE-MIT` и `LICENSE-APACHE`.
