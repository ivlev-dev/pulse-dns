# STATUS.md — состояние проекта pulse-dns

Дата: 2026-11-24. Источник правды по фактическому состоянию кода. Сроков не обещаем.

## Что закоммичено (последние коммиты)

| Хеш | Сообщение |
|---|---|
| `4685355` | docs: добавить пример конфигурации и запуска pulsed |
| `b337c5e` | docs: зафиксировать параллельную запись, durability и API |
| `452ce5d` | feat(pulsed): связать REST API и DNS через единое хранилище зон |
| `a25a556` | feat(api): реализовать REST-управление зонами с auth и ETag |
| `7ca423d` | feat(zonefile): реализовать B+tree, ключи, overflow и кеш чтения |
| `eb3f7fc` | feat(pulsed): собрать UDP/TCP DNS-сервер с JSON-зонами |
| `753e167` | feat(server): реализовать authoritative query engine |
| `d07027e` | feat(runtime): добавить io_uring UDP-рантайм с epoll-фолбэком |

## Готово

Проверено автоматически: полный набор workspace-тестов (включая doctests)
проходит; `cargo fmt --check`, `cargo clippy --workspace --all-targets
-D warnings`, rustdoc без warnings.

- `pulse-dns` — wire-формат DNS, RR-типы, сжатие имён, EDNS0, RFC 3597,
  канонизация RFC 4034, лимиты, 0 `unsafe`.
- `pulse-zonefile` — pager, superblock/meta A/B, CRC32C, reader table с
  RAII-снапшотами, recovery (durable_watermark, torn-мета, sticky sync_mode),
  B+tree (RLE-ключи, канонический компаратор, split, ENT), overflow-цепочки,
  кеш валидированных страниц, zone index, writer/commit, `compact_zone`,
  `sync`, fsck; используется `pulsed` как write-through хранилище.
- `pulse-runtime` — io_uring UDP (ring-per-core, multishot recv + provided
  buffers, IP_PKTINFO, NODROP-проверка, backpressure, graceful shutdown,
  изоляция паник) + epoll-фолбэк.
- `pulse-server` — авторитетный движок: NXDOMAIN/NODATA/ENT, wildcard/closest
  encloser, CNAME/DNAME, делегация/glue/DS, EDNS/BADVERS, TC, ANY по RFC 8482,
  детерминированный additional.
- `pulse-api` — REST MVP: health/ready/metrics/OpenAPI, zones CRUD, RRset
  CRUD/PATCH, settings, bearer-auth + scopes + per-zone allowlist (404 вне
  allowlist), ETag/If-Match, RFC 9457 problem+json, Idempotency-Key,
  пагинация, лимиты тела/rate limit.
- `pulsed` — бинарник: UDP+TCP, JSON-конфиг зон и master-файлы RFC 1035
  (`--zone`/`zones_files`, `pulse-master`), единый store с REST, write-through
  persistence в `pulse-zonefile` (`--data`, durability, single-writer),
  graceful shutdown, Dockerfile.
- `pulsed` replication: AXFR/IXFR-out по TCP (TSIG/ACL, лимиты, SOA first/last),
  ограниченная in-memory IXFR-история, NOTIFY-out с фоновой очередью,
  NOTIFY-in, secondary-зоны (bootstrap AXFR, периодический SOA-refresh,
  IXFR-in/AXFR fallback, persist в zonefile, retry/expire → SERVFAIL,
  read-only для REST).
- `pulseresolved` — бинарник резолвера: JSON-конфиг, forward/iterative,
  UDP на `pulse-runtime` (N worker) и TCP (length-prefix, idle timeout, лимит
  соединений, graceful shutdown), EDNS/TC, REFUSED для AXFR/IXFR, FORMERR на
  мусор, кеш, blocklist (несколько файлов, allowlist, NXDOMAIN/null),
  overrides A/AAAA/CNAME, DNSSEC-валидация (AD, BOGUS → SERVFAIL), SIGHUP и
  периодический reload, `GET /metrics`/`GET /healthz` на loopback.

## Проверено руками

- Реальные UDP/TCP ответы: A, AAAA, MX, NXDOMAIN+SOA, CNAME-цепочка.
- Загрузка зоны из RFC 1035 master-файла (`--zone`/`zones_files`), UDP A и
  NXDOMAIN, затем REST-правка и новый ответ без рестарта.
- Persistence: bootstrap из пустого/отсутствующего файла, REST A/TTL/DELETE,
  reopen без потери данных, удаление зоны, `Busy` второго writer'а,
  отказ на усечённом файле.
- REST-сценарий: PUT зоны → SOA/NS/A → UDP отвечает → PATCH → ответ меняется →
  DELETE → NODATA/REFUSED.
- Резолвер (`pulseresolved`): реальный прогон бинарника против mock upstream —
  forward A-ответ, повторный запрос из кеша без upstream (TTL 300 → 299),
  NXDOMAIN, blocklist → NXDOMAIN и `0.0.0.0`, override приоритетнее blocklist,
  TCP-запрос, AXFR → REFUSED, SIGHUP-reload списка, `/metrics` + `/healthz`,
  graceful shutdown по SIGTERM (exit 0). Интеграционные тесты дополнительно
  покрывают DNSSEC AD и BOGUS → SERVFAIL, TC/EDNS, periodic reload и FORMERR
  на мусор.
- Производительность (loopback, хост нагружен, числа консервативные):
  UDP echo 220 117 qps (4 worker / 4 клиента, окно 16); epoll 230 352 qps;
  окно 1 — 89 036 qps, p50 35 µs, p99 182 µs; zone lookup 156–268 нс;
  RRset lookup ~2–4.9 µs при 1M; insert ~10 000/s; 0 аллокаций на warm lookup.

## Не готово / gap’ы (с приоритетом)

**P0 (корректность/долговечность):**
- Commit/allocator/GC и параллельная запись по зонам в коде не реализованы
  (только дизайн: ADR 0005/0006, spec parallel-writes-v2).
- `pulsed` использует `pulse-zonefile` как write-through хранилище только при
  `--data`; без него зоны остаются in-memory. Нет journal/outbox и
  параллельной записи; снапшот при мутации пересобирается полностью.

**P1 (безопасность/транспорт/протокол):**
- DNSSEC-крипто (подпись/валидация) и привязка RRSIG; DNSCrypt.
- Резолвер: нет RRL, DoT/DoH/DoQ-апстримов и RFC 5011 (anchors статические).
- DoT/DoH/DoQ.
- TLS для API (только loopback).
- Полноценный RRL.
- 0x20 echo.

**P2 (качество/производительность/CI):**
- REST — MVP-подмножество спецификации.
- RRset lookup 2–4.9 µs при 1M против цели 500 нс (не достигнута).
- Fuzz/Miri/loom в CI отсутствуют.

## Как проверить за 5 минут

```bash
cargo test --workspace
cargo fmt --check
cargo clippy --workspace --all-targets -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
```

Запуск сервера и проверка:

```bash
export PULSED_API_TOKEN="$(openssl rand -hex 32)"
cargo run -p pulsed -- --config examples/zones.json \
  --listen-udp 127.0.0.1:5353 --listen-tcp 127.0.0.1:5353 \
  --api-listen 127.0.0.1:8080 --api-scope example.com.
dig @127.0.0.1 -p 5353 example.com. A +norecurse
```

## Риски и известные дефекты

- RRset lookup ~2–4.9 µs при 1M против цели 500 нс.
- Зоны в памяти: нет персистентности, потеря при рестарте.
- API доступен только на loopback, TLS отсутствует.
- Storage — single-writer: commit/allocator не реализованы, параллельная
  запись по зонам не в коде.
- Числа производительности сняты на loopback при загруженном хосте —
  консервативные оценки, не SLA.
- io_uring работает на уровне L3 только при поддержке `IORING_FEAT_NODROP`,
  иначе L2; epoll даёт сопоставимый qps, но с одной лишней копией на приём.
