# pulse-dns

Модульный высокопроизводительный DNS-сервер на Rust. Linux-first, edition 2024
(stable). Текущее состояние — **authoritative MVP**: рабочий авторитетный сервер
(`pulsed`) с UDP/TCP и REST API поверх in-memory хранилища. Это не полный
продукт из ТЗ (нет рекурсии, DNSSEC-крипто, AXFR/IXFR, DoT/DoH/DoQ и т.д.).

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
- Бинарник `pulsed`: UDP+TCP, JSON-конфиг зон, единый store с REST (правки через
  API сразу видны в DNS), graceful shutdown, Dockerfile.

**Не реализовано (см. `STATUS.md`):** commit/allocator/GC и параллельная запись
по зонам в коде (только дизайн, ADR 0005/0006, spec parallel-writes-v2);
персистентность (`pulsed` не использует `pulse-zonefile`, зоны in-memory из
JSON/REST); DNSSEC-крипто (подпись/валидация) и привязка RRSIG; DNSCrypt;
рекурсивный резолвер; AXFR/IXFR/NOTIFY/secondary; DoT/DoH/DoQ; 0x20 echo; TLS
для API (только loopback); fuzz/Miri/loom в CI; полноценный RRL; REST —
MVP-подмножество спецификации.

## Архитектура

| Крейт | Назначение |
|---|---|
| `pulse-dns` | Wire-формат DNS и RR-типы |
| `pulse-zonefile` | Бинарный mmap-формат зон (reader реализован; writer/commit — в дизайне) |
| `pulse-runtime` | io_uring UDP-рантайм + epoll-фолбэк |
| `pulse-server` | Авторитетный движок запросов |
| `pulse-api` | REST API управления зонами |
| `pulsed` | Бинарник сервера (UDP+TCP+REST) |

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

В workspace 544 теста (включая doctests). Также проходят `cargo fmt --check`,
`cargo clippy --workspace --all-targets -D warnings` и rustdoc без warnings.

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
