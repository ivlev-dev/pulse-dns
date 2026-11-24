# STATUS.md — состояние проекта pulse-dns

Дата: 2026-11-25. Источник правды по фактическому состоянию кода. Сроков не обещаем.

## Что закоммичено (последние коммиты)

| Хеш | Сообщение |
|---|---|
| `ba6b251` | test(resolver): стабилизировать e2e под нагрузкой |
| `41e83c7` | feat(tls): добавить DoH HTTP/3 и интеграцию в pulsed |
| `d79cbba` | feat(api): дополнить REST до спеки jobs, transfers и audit |
| `d1114c4` | feat(pulsed): TOML, WAL, ротация и новые транспорты |
| `535c462` | feat(resolver): транспорты, control API, пул upstream и RRL |
| `a5b8456` | feat(dns): DoH2/DoQ, NSEC3 Opt-Out и ротация ключей |
| `32cc673` | feat(zonefile): межпроцессная запись v2 и исправление delete |
| `cc24abc` | docs: финальный статус и закрытые gap'ы |
| `685da3c` | fix(tls): заменить rustls-pemfile на rustls-pki-types |
| `46b3bec` | chore: добавить fuzz-таргеты, CI-hardening и fsck repair |

## Проверки (зелёные)

- `cargo test --workspace --all-features` — **1332 теста**, 0 failures.
- `cargo fmt --check`.
- `cargo clippy --workspace --all-targets -D warnings`.
- `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps`.
- `cargo deny check`.

## Готово

### Готово по крейтам (13)

| Крейт | Статус |
|---|---|
| `pulse-dns` | wire-формат DNS, RR-типы, сжатие имён, EDNS0, RFC 3597, канонизация RFC 4034, лимиты, 0 `unsafe` |
| `pulse-dnssec` | sign/validate алгоритмы 8/13/15, RRSIG при DO=1, NSEC и NSEC3 (SHA-1, salt/iterations, closest encloser, wildcard; NSEC3-подпись, NSEC3PARAM, Opt-Out), DS через API, trust anchors IANA и RFC 5011 (`TrustAnchorStore`, add/revoke hold-down, `0600`-состояние), автоматическая ротация KSK/ZSK (pre-publish/double-sign/active/retire) |
| `pulse-dnscrypt` | DNSCrypt v2: сертификаты, сервер, клиент, UDP и TCP (framing, метрики) |
| `pulse-master` | парсер/сериализатор RFC 1035 master-файлов |
| `pulse-transfer` | TSIG, AXFR/IXFR, NOTIFY |
| `pulse-zonefile` | v2 `ParallelStore`: lock-free аллокатор страниц, ring-головы версий A/B, per-zone пулы/GC, in-process пины читателей, per-zone commit, group commit (2 fsync на группу), PageCache, recovery, полный `fsck --verify` и `--repair`, `compact_zone`, `sync`; **межпроцессная запись v2** (ADR 0007): sidecar-координатор `<file>.pulsecoord`, CAS-курсор в shared mmap, `fcntl` per-zone leases + fencing (pid/starttime/generation), общая reader table, `LOCK_SH`; 4 процесса × 4 зоны, kill -9, 10k коммитов в 2 процессах; ~20k zone-commit/s; v1 читается для `pulsed convert` |
| `pulse-runtime` | io_uring UDP (ring на ядро, multishot recv + provided buffers, IP_PKTINFO, NODROP-проверка, backpressure, graceful shutdown, изоляция паник) + epoll-фолбэк |
| `pulse-server` | авторитетный движок: NXDOMAIN/NODATA/ENT, wildcard/closest encloser, CNAME/DNAME, делегация/glue/DS, EDNS/BADVERS, TC, ANY по RFC 8482, детерминированный additional |
| `pulse-resolver` | library: forward/iterative, кеш + negative caching, blocklist/allowlist/overrides, DNSSEC AD/BOGUS→SERVFAIL, UDP/TCP + upstream DoT/DoH с failover/cooldown, пул keep-alive соединений (`pool_size`, default 4, in-flight лимит, reconnect backoff), смешанные upstream |
| `pulseresolved` | binary резолвер: TOML-конфиг (JSON — совместимость), UDP/TCP, серверные DoT/DoH/1.1/DoH/2/DoH/3/DoQ/DNSCrypt v2 (UDP+TCP), ACL клиентов (default loopback, отдельный `tls_allow_from`), per-source rate limit, полный RRL (`noerror`/`nxdomain`/`referral`/`error`, per-source + per-name, slip, refused/drop/truncate; только UDP), пул DoT/DoH, смешанные upstream (UDP/TCP/DoT/DoH), кеш, blocklist, overrides, DNSSEC, SIGHUP (blocklist + TLS-пара), `/metrics` по транспортам, `/healthz`, control-plane REST API (`control_listen`, bearer-token, cache/purge, blocklist reload, upstreams, trust anchors, RRL patch, config, RFC 9457 problem+json, `X-Request-Id`, rate limit на токен, graceful shutdown) |
| `pulse-tls` | DoT (RFC 7858), DoH/1.1 (RFC 8484), DoH/2 (`http2`), DoH/3 (`http3`, RFC 9114) и DoQ (`doq`) на rustls/quinn/h3: серверы и клиенты (webpki-roots/CA, ALPN, keep-alive) |
| `pulse-api` | REST доведён: health/ready/metrics/OpenAPI, zones CRUD, RRset CRUD/PATCH, settings, serial, transfers/jobs, import, audit, confirm_origin, keys rollover/status, async `Prefer: respond-async`, bearer-auth + scopes + per-zone allowlist, ETag/If-Match, RFC 9457 problem+json, Idempotency-Key, пагинация, лимиты; write-ahead journal (outbox) мутаций: CRC/seq, fsync, crash-recovery, compaction, `journal_*` метрики |
| `pulsed` | binary: TOML-конфиг (JSON — совместимость) с CLI-overrides, UDP+TCP+DoT+DoH/1.1+DoH/2+DoH/3+DoQ+DNSCrypt v2 (UDP/TCP)+REST, зоны только в `pulse-zonefile` v2 (`--data`), DNS отвечает из mmap, импорт `.zone`, `convert` v1→v2, per-zone/group commit, AXFR/IXFR-out, NOTIFY, secondary-зоны, DNSSEC-подпись NSEC/NSEC3, автоматическая ротация ключей, journal REST-мутаций с recovery на старте (`journal = true` по умолчанию), graceful shutdown, Dockerfile |

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
  DoH/2 (h2), DoH/3 (h3), DoQ (quinn) и DNSCrypt v2 UDP+TCP; ACL вне списка даёт
  зашифрованный `REFUSED` на всех транспортов до вызова резолвера,
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
- Межпроцессная запись v2: 4 процесса × 4 зоны без потерь/дублей страниц;
  второй writer той же зоны → `ZoneBusy`, lease освобождается при смерти;
  читатель другого процесса видит согласованные версии; kill -9 писателя
  очищает lease/reader, чужие зоны целы; kill -9 в середине коммита → `DP`
  не убывает, зона на `V−1`/`V`; 10 000 коммитов в 2 процессах без
  пересечений страниц; single-process без регрессий.
- Производительность (loopback, хост нагружен, числа консервативные):
  UDP echo 220 117 qps (4 worker / 4 клиента, окно 16); epoll 230 352 qps;
  окно 1 — 89 036 qps, p50 35 µs, p99 182 µs; zone lookup 156–268 нс;
  RRset lookup ~2–4.9 µs при 1M; insert ~10 000/s; 0 аллокаций на warm lookup;
  alloc reserve ~50M/s; per-zone commit 49k zone-commit/s (4 потока, B1, tmpfs);
  group commit: 2 fsync/группу, ускорение 2.4× (btrfs), 3.36× (эмуляция fsync 2 мс);
  p50 6.35 ms (group) vs 17.5 ms (per-zone) на btrfs; end-to-end baseline 88 024 q/s,
  при 8 писателях в 8 зон — 72 088 q/s; PageCache 418 нс warm single-page,
  полный lookup ~1.06 µs; зона не материализуется в RAM (RssAnon не растёт);
  DoT ~10.4k qps; DoH h2 ~8.2k DNS/s; DoH3 ~13.6–14.9k; DoQ ~5.25k.
- Fuzz/CI: `fuzz/` (cargo-fuzz, nightly) — 5 таргетов (`dns_wire`,
  `master_zone`, `zonefile_v2_open`, `transfer_tsig`, `dnscrypt_packet`),
  seed-корпус; CI job `fuzz-smoke` на push в main; Miri на
  `pulse-dns`/`pulse-master` (nightly, continue-on-error). `cargo deny check`
  зелёный.

## Остаточные ограничения (честно)

- Multi-process: каталог (`create/delete zone`, meta) — один писатель; durable-пулы
  в multi не переиспользуются (bump-only, рекламация в quiescent/repair);
  `freeze()` локальный.
- DoH3/DoQ — серверные; upstream-клиенты у резолвера остаются HTTP/1.1/DoT
  (h2/h3 upstream нет).
- Jobs/audit в памяти (TTL 24 ч / ring 4096), import только `text/plain`.
- DNSCrypt-сертификат без hot-reload; 0-RTT выключен; нет HSM/PKCS#11.
- Один статический control-токен у резолвера; аудит-файл не персистентный.
- NSEC3 для secondary-зон не генерируется; для secondary-зон ключи не ротируются
  автоматически.
- REST — MVP-подмножество спецификации (хотя доведён по jobs/transfers/audit);
  API доступен только на loopback (без TLS).
- RRset lookup ~2–4.9 µs при 1M против цели 500 нс (не достигнута).
- Loom отсутствует (fuzz и Miri есть); Miri — continue-on-error.
- File-fatal порча требует ручного разбора (repair её не «чинит»).
- io_uring работает на уровне L3 только при поддержке `IORING_FEAT_NODROP`,
  иначе L2; epoll даёт сопоставимый qps.
- DNS Cookies нет; 0x20 echo нет; полноценный RRL авторитетного сервера
  (`pulsed`) нет.

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
- Storage: параллельная запись по зонам внутри одного процесса (v2) и
  межпроцессная (v2, ADR 0007); каталог — один writer, durable-пулы bump-only
  в multi, `freeze()` локальный.
- v2: до 4096 зон, страницы 4096; offline `pulsed fsck [--repair]` есть,
  file-fatal порча требует ручного разбора.
- Числа производительности сняты на loopback при загруженном хосте —
  консервативные оценки, не SLA.
- io_uring работает на уровне L3 только при поддержке `IORING_FEAT_NODROP`,
  иначе L2; epoll даёт сопоставимый qps, но с одной лишней копией на приём.
- NSEC3 для secondary-зон не генерируется (primary-зоны: Opt-Out и ротация есть).
- Резолвер: upstream DoH только HTTP/1.1; пул keep-alive соединений DoT/DoH
  (`pool_size`, по умолчанию 4), RRL по классам ответов есть, DNS Cookies нет.
- Loom отсутствует; Miri — continue-on-error.
- Один статический control-токен у резолвера; аудит-файл не персистентный.
