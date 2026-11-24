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
| `pulse-dnssec` | sign/validate алгоритмы 8/13/15, RRSIG при DO=1, NSEC и NSEC3 (SHA-1, salt/iterations, closest encloser, wildcard; NSEC3-подпись, NSEC3PARAM; Opt-Out не реализован), DS через API, trust anchors IANA |
| `pulse-dnscrypt` | DNSCrypt v2: сертификаты, сервер, клиент, UDP и TCP (framing, метрики) |
| `pulse-master` | парсер/сериализатор RFC 1035 master-файлов |
| `pulse-transfer` | TSIG, AXFR/IXFR, NOTIFY |
| `pulse-zonefile` | v2 `ParallelStore`: lock-free аллокатор страниц, ring-головы версий A/B, per-zone пулы/GC, in-process пины читателей, per-zone commit, group commit (2 fsync на группу), PageCache, recovery, полный `fsck --verify` и `--repair`, `compact_zone`, `sync`; v1 читается для `pulsed convert` |
| `pulse-runtime` | io_uring UDP (ring на ядро, multishot recv + provided buffers, IP_PKTINFO, NODROP-проверка, backpressure, graceful shutdown, изоляция паник) + epoll-фолбэк |
| `pulse-server` | авторитетный движок: NXDOMAIN/NODATA/ENT, wildcard/closest encloser, CNAME/DNAME, делегация/glue/DS, EDNS/BADVERS, TC, ANY по RFC 8482, детерминированный additional |
| `pulse-resolver` | library: forward/iterative, кеш + negative caching, blocklist/allowlist/overrides, DNSSEC AD/BOGUS→SERVFAIL, UDP/TCP + upstream DoT/DoH с failover/cooldown/keep-alive, смешанные upstream |
| `pulseresolved` | binary резолвер: JSON-конфиг, UDP/TCP, ACL клиентов (default loopback), per-source RRL (token bucket, refused/drop/truncate), смешанные upstream (UDP/TCP/DoT/DoH), кеш, blocklist, overrides, DNSSEC, SIGHUP, `/metrics`, `/healthz`, graceful shutdown |
| `pulse-tls` | DoT (RFC 7858) и DoH/1.1 (RFC 8484) на rustls: серверы и клиенты (webpki-roots/CA, ALPN, keep-alive) |
| `pulse-api` | REST MVP: health/ready/metrics/OpenAPI, zones CRUD, RRset CRUD/PATCH, settings, bearer-auth + scopes + per-zone allowlist, ETag/If-Match, RFC 9457 problem+json, Idempotency-Key, пагинация, лимиты |
| `pulsed` | binary: UDP+TCP+DoT+DoH (HTTP/1.1)+DNSCrypt v2 (UDP/TCP)+REST, зоны только в `pulse-zonefile` v2 (`--data`), DNS отвечает из mmap, импорт `.zone`, `convert` v1→v2, per-zone/group commit, AXFR/IXFR-out, NOTIFY, secondary-зоны, DNSSEC-подпись NSEC/NSEC3, graceful shutdown, Dockerfile |

## Проверено руками

- Реальные UDP/TCP ответы: A, AAAA, MX, NXDOMAIN+SOA, CNAME-цепочка.
- Импорт RFC 1035 master-файла (`pulsed import --data ... --origin ...`), UDP
  A/AAAA/wildcard/delegation/NXDOMAIN из mmap, рестарт без импорта, затем
  REST-правка и новый ответ без рестарта.
- Persistence: import в пустой/отсутствующий файл, REST A/TTL/DELETE, reopen без
  потери данных, удаление зоны, `Busy` второго writer'а, отказ на усечённом
  файле, AXFR после импорта и после REST-правки.
- DNSSEC: подпись NSEC и NSEC3 (salt/iterations) в zonefile при старте и
  `/sign`, DO=1 отдаёт RRSIG/NSEC3 из mmap, негативные доказательства
  проверены `pulse-dnssec`; secondary AXFR-in → ответы из mmap → рестарт.
- Защищённые транспорты: реальные клиенты получают A-ответ по DoT, DoH POST/GET
  и DNSCrypt UDP/TCP; транспорты работают параллельно на разных портах;
  неверный provider-ключ и испорченный сертификат отклоняются; большие ответы
  DoT/DoH/DNSCrypt TCP не усекаются, DNSCrypt UDP отдаёт `TC`; TLS hot-reload
  меняет сертификат для новых соединений; graceful shutdown закрывает порты;
  DNSCrypt TCP держит несколько запросов на соединении и idle timeout;
  `dnscrypt-gencert` создаёт файлы 0600/0700, не печатает секреты и не
  перезаписывает их без `--force`; `/metrics` содержит `dot_*`/`doh_*`/
  `dnscrypt_*`/`dnscrypt_tcp_*`.
- REST-сценарий: PUT зоны → SOA/NS/A → UDP отвечает → PATCH → ответ меняется →
  DELETE → NODATA/REFUSED.
- Резолвер (`pulseresolved`): реальный прогон бинарника против mock upstream —
  forward A-ответ, повторный запрос из кеша без upstream (TTL 300 → 299),
  NXDOMAIN, blocklist → NXDOMAIN и `0.0.0.0`, override приоритетнее blocklist,
  TCP-запрос, AXFR → REFUSED, SIGHUP-reload списка, `/metrics` + `/healthz`,
  graceful shutdown по SIGTERM (exit 0). Интеграционные тесты дополнительно
  покрывают DNSSEC AD и BOGUS → SERVFAIL, TC/EDNS, periodic reload и FORMERR
  на мусор, upstream DoT/DoH против self-signed `DotServer`/`DohServer`
  (включая keep-alive и отказ при неверном CA), failover между upstream,
  ACL (`refused_acl_total`) и rate limit с изоляцией по source IP.
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
- Без `--data` сервер поднимается без зон (REFUSED); нет journal/outbox и
  WAL для write-through.

**P1 (безопасность/транспорт/протокол):**
- DNSSEC: NSEC3 Opt-Out не реализован; NSEC3 для secondary-зон не
  генерируется; автоматической ротации ключей нет; RFC 5011 не реализован
  (trust anchors статические).
- DoQ не реализован.
- DoH HTTP/2/3 не реализован (только HTTP/1.1).
- Резолвер: upstream DoH только HTTP/1.1, одно keep-alive соединение на
  upstream (сериализация запросов), нет полного RRL (только per-source token
  bucket).
- TLS для REST API/метрик (только loopback).
- Полноценный RRL (авторитетный сервер).
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
cargo run -p pulsed -- --config examples/pulsed.json \
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
- NSEC3 Opt-Out не реализован; автоматической ротации DNSSEC-ключей нет.
- Резолвер: upstream DoH только HTTP/1.1, одно keep-alive соединение на
  upstream (сериализация), нет полного RRL.
- Loom отсутствует; Miri — continue-on-error.
