# pulse-dns

![CI](https://github.com/ivlev-dev/pulse-dns/actions/workflows/ci.yml/badge.svg)

Модульный высокопроизводительный DNS-сервер на Rust. Linux-first, edition 2024
(stable). Текущее состояние — **authoritative MVP + кеширующий резолвер**:
авторитетный сервер (`pulsed`) с UDP/TCP, REST API и опциональной write-through
persistence в `pulse-zonefile`, а также резолвер (`pulseresolved`) с
forward/iterative-резолюцией, кешем, blocklist, overrides и DNSSEC-валидацией.
Это не полный продукт из ТЗ (нет DoT/DoH/DoQ, RRL и т.д.).

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
- Формат зон (`pulse-zonefile`): один mmap-файл, pager, superblock/meta A/B,
  CRC32C, reader table с RAII-снапшотами, recovery (durable_watermark,
  torn-мета, sticky sync_mode), B+tree (RLE-ключи, канонический компаратор,
  split, ENT), overflow-цепочки, кеш валидированных страниц, zone index.
- REST API (`pulse-api`): health/ready/metrics/OpenAPI, zones CRUD, RRset
  CRUD/PATCH, settings, bearer-auth + scopes + per-zone allowlist (404 вне
  allowlist), ETag/If-Match, RFC 9457 problem+json, Idempotency-Key,
  пагинация, лимиты тела/rate limit.
- Бинарник `pulsed`: UDP+TCP, JSON-конфиг зон и RFC 1035 master-файлы
  (`.zone`, `$ORIGIN`/`$TTL`/`$INCLUDE`), единый store с REST (правки через
  API сразу видны в DNS), write-through persistence в `pulse-zonefile`
  (`--data`, `sync`/`flush`/`memory`, один writer), graceful shutdown,
  AXFR/IXFR-out по TCP с TSIG/ACL, IXFR-история, NOTIFY-out/in и secondary-зоны
  (AXFR/IXFR-in, bootstrap, SOA-refresh, expire → SERVFAIL), Dockerfile.
- Бинарник `pulseresolved`: forward/iterative-резолюция через `pulse-resolver`,
  UDP на `pulse-runtime` (N worker) и TCP с length-prefix, EDNS/TC, REFUSED
  для AXFR/IXFR, кеш, blocklist + overrides, DNSSEC-валидация (AD/SERVFAIL),
  SIGHUP/периодический reload, `GET /metrics` и `GET /healthz` на loopback,
  graceful shutdown по SIGTERM/SIGINT.

**Не реализовано (см. `STATUS.md`):** commit/allocator/GC и параллельная запись
по зонам в коде (только дизайн, ADR 0005/0006, spec parallel-writes-v2);
journal/outbox и параллельная запись в zonefile; зоны в памяти пересобираются
полностью при мутации; DNSCrypt; DoT/DoH/DoQ; 0x20 echo; TLS
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
| `pulse-api` | REST API управления зонами |
| `pulse-resolver` | Кеширующий резолвер: forward/iterative, кеш, blocklist, overrides, DNSSEC |
| `pulsed` | Бинарник сервера (UDP+TCP+REST) |
| `pulseresolved` | Бинарник резолвера (UDP+TCP+метрики) |

Спецификации и решения: `docs/adr/`, `docs/spec/`, `docs/api/rest-v1.md`,
`docs/bench/plan.md`, `docs/plan/roadmap.md`.

## Быстрый старт

Сборка:

```bash
cargo build --release
```

Запуск `pulsed` с примером зон:

```bash
export PULSED_API_TOKEN="$(openssl rand -hex 32)"

cargo run -p pulsed -- \
  --config examples/zones.json \
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

Зона из RFC 1035 master-файла:

```bash
cargo run -p pulsed -- --config examples/master-files.json
# или: --config examples/empty.json --zone example.com.=examples/example.com.zone
```

Persistence в `pulse-zonefile`:

```bash
cargo run -p pulsed -- --config examples/master-files.json \
  --data /tmp/pulse-dns.zonefile --durability flush --map-size 268435456
```

Первый запуск импортирует JSON/master-зоны и создаёт файл; последующие
запуски читают зоны из файла, а REST-мутации коммитятся write-through.

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
- REST — MVP-подмножество спецификации; API доступен только на loopback.
- Roadmap: `docs/plan/roadmap.md` (M0 выполнено, M1 в работе).

## Лицензия

MIT OR Apache-2.0. См. `LICENSE-MIT` и `LICENSE-APACHE`.
