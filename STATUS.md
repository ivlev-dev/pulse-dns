# STATUS.md — состояние проекта pulse-dns

Дата: 2026-11-24. Источник правды по фактическому состоянию кода. Сроков не обещаем.

## Что закоммичено (последние коммиты)

| Хеш | Сообщение |
|---|---|
| `685da3c` | fix(tls): заменить rustls-pemfile на rustls-pki-types |
| `46b3bec` | chore: добавить fuzz-таргеты, CI-hardening и fsck repair |
| `efe8927` | test(zonefile): стабилизировать проверку group commit |
| `25d3e86` | test(tls): убрать сетевой DNS-резолв из DoH-теста |
| `f935795` | feat(dnssec): добавить NSEC3-подпись и DNSCrypt TCP |
| `80e0023` | feat(resolver): добавить ACL, RRL и upstream DoT/DoH |
| `85760bd` | docs: зафиксировать параллельную запись v2 и текущий статус |
| `9a1aaa9` | feat(pulsed): перевести сервер на параллельную запись v2 |
| `f270edc` | feat(zonefile): добавить group commit и режимы durability v2 |
| `7479143` | feat(zonefile): добавить v2 PageCache и рекламацию страниц |

## Проверки (зелёные)

- `cargo test --workspace --all-features` — 1138 тестов, 0 failures.
- `cargo fmt --check`.
- `cargo clippy --workspace --all-targets -D warnings`.
- `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps`.
- `cargo deny check`.

## Готово

### Готово по крейтам (13)

| Крейт | Статус |
|---|---|
| `pulse-dns` | wire-формат DNS, RR-типы, сжатие имён, EDNS0, RFC 3597, канонизация RFC 4034, лимиты, 0 `unsafe` |
| `pulse-dnssec` | sign/validate алгоритмы 8/13/15, RRSIG при DO=1, NSEC и NSEC3 (SHA-1, salt/iterations, closest encloser, wildcard; NSEC3-подпись, NSEC3PARAM, Opt-Out), DS через API, trust anchors IANA и RFC 5011 (`TrustAnchorStore`, add/revoke hold-down, `0600`-состояние) |
| `pulse-dnscrypt` | DNSCrypt v2: сертификаты, сервер, клиент, UDP и TCP (framing, метрики) |
| `pulse-master` | парсер/сериализатор RFC 1035 master-файлов |
| `pulse-transfer` | TSIG, AXFR/IXFR, NOTIFY |
| `pulse-zonefile` | v2 `ParallelStore`: lock-free аллокатор страниц, ring-головы версий A/B, per-zone пулы/GC, in-process пины читателей, per-zone commit, group commit (2 fsync на группу), PageCache, recovery, полный `fsck --verify` и `--repair`, `compact_zone`, `sync`; v1 читается для `pulsed convert` |
| `pulse-runtime` | io_uring UDP (ring на ядро, multishot recv + provided buffers, IP_PKTINFO, NODROP-проверка, backpressure, graceful shutdown, изоляция паник) + epoll-фолбэк |
| `pulse-server` | авторитетный движок: NXDOMAIN/NODATA/ENT, wildcard/closest encloser, CNAME/DNAME, делегация/glue/DS, EDNS/BADVERS, TC, ANY по RFC 8482, детерминированный additional |
| `pulse-resolver` | library: forward/iterative, кеш + negative caching, blocklist/allowlist/overrides, DNSSEC AD/BOGUS→SERVFAIL, UDP/TCP + upstream DoT/DoH с failover/cooldown, пул keep-alive соединений (`pool_size`, default 4, in-flight лимит, reconnect backoff), смешанные upstream |
| `pulseresolved` | binary резолвер: TOML-конфиг (JSON — совместимость), UDP/TCP, серверные DoT/DoH/1.1/DoH/2/DoQ/DNSCrypt v2 (UDP+TCP), ACL клиентов (default loopback, отдельный `tls_allow_from`), per-source rate limit, полный RRL (`noerror`/`nxdomain`/`referral`/`error`, per-source + per-name, slip, refused/drop/truncate; только UDP), пул DoT/DoH, смешанные upstream (UDP/TCP/DoT/DoH), кеш, blocklist, overrides, DNSSEC, SIGHUP (blocklist + TLS-пара), `/metrics` по транспортам, `/healthz`, control-plane REST API (`control_listen`, bearer-token, cache/blocklist/upstreams/trust-anchors/RRL/config, RFC 9457 problem+json, `X-Request-Id`, rate limit на токен, graceful shutdown) |
| `pulse-tls` | DoT (RFC 7858), DoH/1.1 (RFC 8484), DoH/2 (`http2`), DoH/3 (`http3`, RFC 9114) и DoQ (`doq`) на rustls/quinn/h3: серверы и клиенты (webpki-roots/CA, ALPN, keep-alive) |
| `pulse-api` | REST MVP: health/ready/metrics/OpenAPI, zones CRUD, RRset CRUD/PATCH, settings, bearer-auth + scopes + per-zone allowlist, ETag/If-Match, RFC 9457 problem+json, Idempotency-Key, пагинация, лимиты; write-ahead journal (outbox) мутаций: CRC/seq, fsync, crash-recovery, compaction, `journal_*` метрики |
| `pulsed` | binary: TOML-конфиг (JSON — совместимость) с CLI-overrides, UDP+TCP+DoT+DoH/1.1+DoH/2+DoH/3+DoQ+DNSCrypt v2 (UDP/TCP)+REST, зоны только в `pulse-zonefile` v2 (`--data`), DNS отвечает из mmap, импорт `.zone`, `convert` v1→v2, per-zone/group commit, AXFR/IXFR-out, NOTIFY, secondary-зоны, DNSSEC-подпись NSEC/NSEC3, journal REST-мутаций с recovery на старте (`journal = true` по умолчанию), graceful shutdown, Dockerfile |

## Проверено руками

- Реальные UDP/TCP ответы: A, AAAA, MX, NXDOMAIN+SOA, CNAME-цепочка.
- Импорт RFC 1035 master-файла (`pulsed import --data ... --origin ...`), UDP
  A/AAAA/wildcard/delegation/NXDOMAIN из mmap, рестарт без импорта, затем
  REST-правка и новый ответ без рестарта.
- Persistence: import в пустой/отсутствующий файл, REST A/TTL/DELETE, reopen без
  потери данных, удаление зоны, `Busy` второго writer'а, отказ на усечённом
  файле, AXFR после импорта и после REST-правки.
- DNSSEC: подпись NSEC и NSEC3 (salt/iterations, Opt-Out) в zonefile при
  старте и `/sign`, DO=1 отдаёт RRSIG/NSEC3 из mmap, негативные и Opt-Out
  доказательства проверены `pulse-dnssec`; ротация KSK/ZSK (pre-publish →
  double-sign → active → retire) с персистентным состоянием и фоновым tick;
  `/keys` отдаёт стадии ключей; RFC 5011 add/revoke hold-down, откат
  кандидатов и `0600`-состояние; secondary AXFR-in → ответы из mmap → рестарт.
- Защищённые транспорты: реальные клиенты получают A-ответ по DoT, DoH POST/GET
  (HTTP/1.1, HTTP/2 и HTTP/3), DoQ и DNSCrypt UDP/TCP; транспорты работают
  параллельно на разных портах; неверный provider-ключ и испорченный
  сертификат отклоняются; большие ответы DoT/DoH/DoQ не усекаются, DNSCrypt
  UDP отдаёт `TC`; TLS hot-reload меняет сертификат для новых соединений
  (DoH/3 — новый QUIC `endpoint config`); graceful shutdown закрывает порты;
  DNSCrypt TCP держит несколько запросов на соединении и idle timeout;
  `dnscrypt-gencert` создаёт файлы 0600/0700, не печатает секреты и не
  перезаписывает их без `--force`; `/metrics` содержит `dot_*`/`doh_*`/
  `doh_http3_*`/`doq_*`/`dnscrypt_*`/`dnscrypt_tcp_*`.
- REST-сценарий: PUT зоны → SOA/NS/A → UDP отвечает → PATCH → ответ меняется →
  DELETE → NODATA/REFUSED.
- Резолвер (`pulseresolved`) защищённые транспорты: реальные клиенты получают
  A/AAAA/NXDOMAIN/blocklist/override по DoT (rustls), DoH/1.1 (POST/GET),
  DoH/2 (h2), DoQ (quinn) и DNSCrypt v2 UDP+TCP; ACL вне списка даёт
  зашифрованный `REFUSED` на всех транспортах до вызова резолвера,
  `tls_allow_from` изолирует TLS от открытого UDP, все транспорты работают
  одновременно, graceful shutdown закрывает порты, SIGHUP-перезагрузка
  TLS-пары меняет сертификат для новых соединений; большие ответы DoT/DoH/DoQ
  и DNSCrypt TCP не усекаются, DNSCrypt UDP отдаёт `TC`; метрики
  `queries_total{transport=...}` и `dot_*`/`doh_*`/`doh_http2_*`/`doq_*`/
  `dnscrypt_*` видны в `/metrics`.
- Резолвер (`pulseresolved`): реальный прогон бинарника против mock upstream —
  forward A-ответ, повторный запрос из кеша без upstream (TTL 300 → 299),
  NXDOMAIN, blocklist → NXDOMAIN и `0.0.0.0`, override приоритетнее blocklist,
  TCP-запрос, AXFR → REFUSED, SIGHUP-reload списка, `/metrics` + `/healthz`,
  graceful shutdown по SIGTERM (exit 0). Интеграционные тесты дополнительно
  покрывают DNSSEC AD и BOGUS → SERVFAIL, TC/EDNS, periodic reload и FORMERR
  на мусор, upstream DoT/DoH против self-signed `DotServer`/`DohServer`
  (включая keep-alive и отказ при неверном CA), failover между upstream,
  ACL (`refused_acl_total`) и rate limit с изоляцией по source IP.
  Пул DoT/DoH: 100 параллельных запросов через self-signed upstream при
  `pool_size = 4` без потерь (DoT и DoH), последовательный трафик держит одно
  соединение, обрыв → reconnect (`discards`/`reconnects`), `pool_size = 2`
  e2e через `pulseresolved`. RRL e2e: NXDOMAIN-флуд → TC по slip, referral
  → REFUSED, легитимные имена/источники не затронуты, метрики
  `rrl_limited_total{class}`/`rrl_slipped_total{class}`/`rrl_entries`.
- Control-plane API `pulseresolved` e2e: bearer-токен (401 без токена, 403 с
  неверным), `/healthz`/`/readyz`, `/metrics`, cache stats + purge по имени/типу,
  blocklist GET/reload (новый файл применяется), upstreams (тип/адрес/health/
  pool), trust anchors без приватных данных + reload, RRL stats/patch с
  валидацией, `/api/v1/config` без секретов, 404/405, 413 на тело > 1 МиБ,
  429 при исчерпании token bucket, мусорный JSON/URL и graceful shutdown.
- Пул DoT/DoH (bench, loopback, хост нагружен, 8 потоков × 10 запросов):
  `pool_size = 4` — 12.0 ms / ≈6.7k q/s; `pool_size = 1` — 25.4 ms /
  ≈3.2k q/s (ускорение ≈2.1×).
- Производительность (loopback, хост нагружен, числа консервативные):
  UDP echo 220 117 qps (4 worker / 4 клиента, окно 16); epoll 230 352 qps;
  окно 1 — 89 036 qps, p50 35 µs, p99 182 µs; zone lookup 156–268 нс;
  RRset lookup ~2–4.9 µs при 1M; insert ~10 000/s; 0 аллокаций на warm lookup.
- Параллельная запись v2 (loopback/нагрузка, числа консервативные):
  lock-free аллокатор reserve ~50M/s; per-zone commit 49k zone-commit/s на
  4 потоках (B1, tmpfs); group commit: 2 fsync на группу, ускорение 2.4× на
  btrfs и 3.36× при эмуляции дорогого fsync (2 мс); p50 6.35 ms (group) vs
  17.5 ms (per-zone) на btrfs; end-to-end baseline 88 024 q/s, при 8
  писателях в 8 зон — 72 088 q/s; PageCache: 418 нс warm single-page, полный
  lookup ~1.06 µs; зона не материализуется в RAM (RSS-anon не растёт),
  `high_water` на плато. v1-файлы читаются только через `pulsed convert
  --from … --to …`.
- Fuzz/CI: `fuzz/` (cargo-fuzz, nightly) — 5 таргетов (`dns_wire`,
  `master_zone`, `zonefile_v2_open`, `transfer_tsig`, `dnscrypt_packet`),
  seed-корпус; CI job `fuzz-smoke` на push в main; Miri на
  `pulse-dns`/`pulse-master` (nightly, continue-on-error). `cargo deny check`
  зелёный.

## Не готово / gap’ы (с приоритетом)

**P0 (корректность/долговечность):**
- Межпроцессная параллельная запись (N процессов) не реализована: в v2.0
  один процесс-писатель (`LOCK_EX`), N потоков; межпроцессная запись —
  отдельный ADR (reader table в файле, `LOCK_SH`, лидер/курсор/fencing).
- Без `--data` сервер поднимается без зон (REFUSED). WAL/journal для REST
  реализован (`docs/ops/journal.md`); WAL для внутренних write-through путей
  (`import`, secondary, DNSSEC-подпись) не реализован.

**P1 (безопасность/транспорт/протокол):**
- DNSSEC: NSEC3 для secondary-зон не генерируется; ротация ключей и RFC 5011
  реализованы (см. «Готово»), но для secondary-зон ключи не ротируются
  автоматически.
- DoH/3 реализован для `pulse-tls`/`pulsed` (`doh3_listen`, feature `http3`);
  у `pulseresolved` серверный DoH/3 и upstream HTTP/3 пока не включены
  (`doh2_listen`/`doq_listen` есть). HTTP/3 только для DoH: WebTransport,
  server push, datagrams и 0-RTT выключены.
- Резолвер: upstream DoH только HTTP/1.1; пул keep-alive соединений
  DoT/DoH (`upstream_pool.pool_size`, по умолчанию 4) с cooldown/backoff и
  лимитом in-flight; RRL резолвера по классам ответов есть (`rrl`, slip),
  DNS Cookies нет.
- TLS для REST API, control-plane API резолвера и метрик (только loopback).
- Полноценный RRL авторитетного сервера (`pulsed`).
- 0x20 echo.

**P2 (качество/производительность/CI):**
- REST — MVP-подмножество спецификации.
- RRset lookup ~2–4.9 µs при 1M против цели 500 нс (не достигнута).
- Loom отсутствует (fuzz и Miri есть).
- Полный REST-спек (OpenAPI покрывает MVP).
- File-fatal порча требует ручного разбора (repair её не «чинит»).

## Ограничения v2

- До 4096 зон; страницы 4096 байт.
- Межпроцессная запись (N процессов) — отдельный ADR.
- `map_size` задаётся при создании (по умолчанию 4 GiB), sparse-файл.
- Offline `pulsed fsck --data <file> [--repair]`: полный `--verify`
  (битсеты, обход дерева/overflow/chain/bucket/каталога, `owner_zone`,
  `page.txn ≤ version`, дизъюнктность, утечки) и `--repair` (карантин
  zone-fatal зон через `NEEDS_FSCK`, возврат утечек, идемпотентность);
  file-fatal порча требует ручного разбора.

## Как проверить за 5 минут

```bash
cargo test --workspace --all-features
cargo fmt --check
cargo clippy --workspace --all-targets -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
cargo deny check
```

Запуск сервера и проверка:

```bash
export PULSED_API_TOKEN="$(openssl rand -hex 32)"
cargo run -p pulsed -- import --data /tmp/pulse-dns.zonefile \
  --origin example.com. examples/example.com.zone
cargo run -p pulsed -- --config examples/pulsed.toml \
  --data /tmp/pulse-dns.zonefile \
  --listen-udp 127.0.0.1:5353 --listen-tcp 127.0.0.1:5353 \
  --api-listen 127.0.0.1:8080 --api-scope example.com.
dig @127.0.0.1 -p 5353 example.com. A +norecurse
```

## Риски и известные дефекты

- RRset lookup ~2–4.9 µs при 1M против цели 500 нс.
- API доступен только на loopback, TLS отсутствует.
- Storage: параллельная запись по зонам внутри одного процесса (v2); межпроцессная
  запись отсутствует (один writer на файл, `LOCK_EX`).
- v2: до 4096 зон, страницы 4096; offline `pulsed fsck [--repair]` есть,
  file-fatal порча требует ручного разбора (repair её не «чинит»).
- Числа производительности сняты на loopback при загруженном хосте —
  консервативные оценки, не SLA.
- io_uring работает на уровне L3 только при поддержке `IORING_FEAT_NODROP`,
  иначе L2; epoll даёт сопоставимый qps, но с одной лишней копией на приём.
- NSEC3 для secondary-зон не генерируется (primary-зоны: Opt-Out и ротация есть).
- Резолвер: upstream DoH только HTTP/1.1; пул keep-alive соединений DoT/DoH
  (`pool_size`, по умолчанию 4), RRL по классам ответов есть, DNS Cookies нет.
- Loom отсутствует; Miri — continue-on-error.
