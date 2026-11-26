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

- `cargo test --workspace --all-features` — **1582 теста**, 0 failures.
- `cargo fmt --check`.
- `cargo clippy --workspace --all-targets -D warnings`.
- `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps`.
- `cargo deny check`.

## Готово

### Готово по крейтам (13)

| Крейт | Статус |
|---|---|
| `pulse-dns` | wire-формат DNS, RR-типы, сжатие имён, EDNS0, RFC 3597, канонизация RFC 4034, лимиты, 0 `unsafe`; zero-copy разбор запроса и ответ (`respond_ref_into`) |
| `pulse-dnssec` | sign/validate алгоритмы 8/13/15, RRSIG при DO=1, NSEC и NSEC3 (SHA-1, salt/iterations, closest encloser, wildcard; NSEC3-подпись, NSEC3PARAM, Opt-Out), DS через API, trust anchors IANA и RFC 5011 (`TrustAnchorStore`, add/revoke hold-down, `0600`-состояние), автоматическая ротация KSK/ZSK (pre-publish/double-sign/active/retire); NSEC/NSEC3 индексы |
| `pulse-dnscrypt` | DNSCrypt v2: сертификаты, сервер, клиент, UDP и TCP (framing, метрики) |
| `pulse-master` | парсер/сериализатор RFC 1035 master-файлов |
| `pulse-transfer` | TSIG, AXFR/IXFR, NOTIFY |
| `pulse-zonefile` | v2 `ParallelStore`: lock-free аллокатор страниц, ring-головы версий A/B, per-zone пулы/GC, in-process пины читателей, per-zone commit, group commit (2 fsync на группу), PageCache, recovery, полный `fsck --verify` и `--repair`, `compact_zone`, `sync`; **межпроцессная запись v2** (ADR 0007): sidecar-координатор `<file>.pulsecoord`, CAS-курсор в shared mmap, `fcntl` per-zone leases + fencing (pid/starttime/generation), общая reader table, `LOCK_SH`; **межпроцессный group commit** (sidecar v4, очередь `RootEntry`, лидер по commit-lease, одна пара `fdatasync` на всех, fault-tolerant ack); 2/4/8 процессов сгруппированы, kill -9 координатора в фазах 1/2, 10k коммитов в 2 процессах; ~20k zone-commit/s; group commit v4: 8 процессов 6.0× (1385 vs 231 commits/s, fsync 2 мс), p99 5.6 мс vs 34–84 мс direct; bulk-load 1M RRset за 2.5–2.8 с; order-key memcmp; каталог 1000 зон за 83 мс (исправлен self-deadlock); v1 читается для `pulsed convert` |
| `pulse-runtime` | io_uring UDP (ring на ядро, multishot recv + provided buffers, `REGISTER_FILES`, `COOP/DEFER_TASKRUN`, опции SQPOLL/`SO_BUSY_POLL`, IP_PKTINFO, NODROP-проверка, backpressure, graceful shutdown, изоляция паник) + epoll-фолбэк |
| `pulse-server` | авторитетный движок: NXDOMAIN/NODATA/ENT, wildcard/closest encloser, CNAME/DNAME, делегация/glue/DS, EDNS/BADVERS, TC, ANY по RFC 8482, детерминированный additional; zero-copy ответ (`respond_ref_into`), NSEC/NSEC3 индексы для быстрого NXDOMAIN |
| `pulse-resolver` | library: forward/iterative, кеш + negative caching, blocklist/allowlist/overrides, HTTPS blocklist-источники (стриминг, лимит 64 MiB, conditional 304, атомарный кэш 0600, SSRF-guard), DNSSEC AD/BOGUS→SERVFAIL, UDP/TCP + upstream DoT/DoH с failover/cooldown, пул keep-alive соединений (`pool_size`, default 4, in-flight лимит, reconnect backoff), смешанные upstream |
| `pulseresolved` | binary резолвер: TOML-конфиг (JSON — совместимость), UDP/TCP, серверные DoT/DoH/1.1/DoH/2/DoH/3/DoQ/DNSCrypt v2 (UDP+TCP), ACL клиентов (default loopback, отдельный `tls_allow_from`), per-source rate limit, полный RRL (`noerror`/`nxdomain`/`referral`/`error`, per-source + per-name, slip, refused/drop/truncate; только UDP), пул DoT/DoH, смешанные upstream (UDP/TCP/DoT/DoH), кеш, blocklist (файлы + HTTPS URL с периодическим обновлением/кэшем/304), overrides, DNSSEC, SIGHUP (blocklist + TLS-пара), `/metrics` по транспортам, `/healthz`, control-plane REST API (`control_listen`, bearer-token, cache/purge, blocklist reload, upstreams, trust anchors, RRL patch, config, RFC 9457 problem+json, `X-Request-Id`, rate limit на токен, graceful shutdown) |
| `pulse-tls` | DoT (RFC 7858), DoH/1.1 (RFC 8484), DoH/2 (`http2`), DoH/3 (`http3`, RFC 9114) и DoQ (`doq`) на rustls/quinn/h3: серверы и клиенты (webpki-roots/CA, ALPN, keep-alive) |
| `pulse-api` | REST доведён: health/ready/metrics/OpenAPI, zones CRUD, RRset CRUD/PATCH, settings, serial, transfers/jobs, import, audit, confirm_origin, keys rollover/status, async `Prefer: respond-async`, bearer-auth + scopes + per-zone allowlist, ETag/If-Match, RFC 9457 problem+json, Idempotency-Key, пагинация, лимиты; write-ahead journal (outbox) мутаций: CRC/seq, fsync, crash-recovery, compaction, `journal_*` метрики |
| `pulsed` | binary: TOML-конфиг (JSON — совместимость) с CLI-overrides, UDP+TCP+DoT+DoH/1.1+DoH/2+DoH/3+DoQ+DNSCrypt v2 (UDP/TCP)+REST, зоны только в `pulse-zonefile` v2 (`--data`), DNS отвечает из mmap, импорт `.zone`, `convert` v1→v2, per-zone/group commit, AXFR/IXFR-out, NOTIFY, secondary-зоны, DNSSEC-подпись NSEC/NSEC3, автоматическая ротация ключей, journal REST-мутаций с recovery на старте (`journal = true` по умолчанию), graceful shutdown, Dockerfile |

## Оптимизация горячего пути (выполнено)

- **Zero-copy ответ**: `respond_ref_into` покрывает A/AAAA/MX/TXT/SRV/CNAME/NS/SVCB/HTTPS,
  NXDOMAIN/NODATA, wildcard (unsigned), EDNS без DO; `udp-e2e` allocs/query с 52 → 0–0.01.
  **0 аллокаций** на ответ (unsigned/signed/referral/ANY/EDNS); DNAME (синтез `CNAME` в стековом буфере),
  циклы `CNAME`/`DNAME` (`SERVFAIL`), wildcard-CNAME-цепочки, `YXDOMAIN` и oversized RRset из refs —
  zero-copy.
- **NSEC/NSEC3 индексы**: NXDOMAIN p99 на 100k signed с 367 мс → 0.71 мс; 1M in-memory p99 18 µs (цель <2 мс).
  Signed NXDOMAIN: NSEC3 p99 307 µs (было 38–47 мс), NSEC p99 343 µs.
- **Bulk-load**: 1M RRset за 2.5–2.8 с (было 26 мин), пик RSS 91–103 МБ, 91 МБ на диске (было 16 ГиБ); 100k — 0.25 с.
- **Память**: v2 чтение 1M RRset RssAnon 6.3 МБ (−41%, было ~9.6), soak 600 с без роста; сервер на 1M RRset ~36 МБ RSS; PageCache 1024 страницы (~4 MiB образов); кеш резолвера 65.9 B/entry (было 113.8); фактически 74.3 МБ на 1M (было 126.4), RSS probe −36%, 0 allocs сохранены.
- **Чтение**: zone snapshot 87–92 нс; RRset warm 1M **842 нс** (было 1.57 µs), cold 1M 27.7–41.4 µs (было 83.6), 0 allocs; zone index ~113–122 нс; order-key memcmp; warm lookup 0 аллокаций; e2e A p50 **46.8 µs**. `Key::rebuild` убран.
- **io_uring**: RSS 4.7/10.2/17.5 МБ на 1/4/8 workers (было 12.7/40.6/104.9); p99 8 workers 650→440 µs; SQPOLL на этом ядре медленнее (выкл), registered files вкл.
- **Каталог 1000 зон**: исправлено зависание (выделенный lease-шард каталога); 1000 зон за 83 мс, 4096 за 651 мс. В multi каталог пишут все процессы под catalog lease (4 × 250 зон), `zone_seq` переиспользуется через общую очередь sidecar.
- **Affinity/THP**: маски DNS/API/control проверены; THP на ext4 file-backed — no-op, на RX-арене удваляет RSS без выигрыша (auto best-effort).
- **TCP/DoT/DoH/plain TCP**: tokio event-loop после горячего пути (буферы без повторного зануления, один TLS-рекорд на ответ, два таймера на запрос, ленивый буфер только после префикса): 10k idle-соединений, ~11 КБ/соединение (было 59–67 КБ); qps +16–23% против thread-per-conn, p50 0.89–0.95 мс в общем loopback-тесте (0.11 мс при изоляции server/client), p99 не хуже baseline; RSS не вырос.
- **Multi-process каталог и reclaim**: create/delete/meta из любого процесса; `high_water` стабилизируется (3636→5428 после 10k циклов); 8 процессов — 13.4k zone-commit/s.
- **Межпроцессный group commit (sidecar v4)**: писатели кладут готовые `RootEntry` в общую очередь,
  лидер (любой процесс под `fcntl`-lease) делает одну пару `fdatasync` на всех. На модели fsync 2 мс:
  8 процессов **231 → 1385 commits/s (6.0×)**, p99 5.6 мс (против 34–84 мс direct); 1 процесс — без регрессии
  (локальный путь). Смерть лидера в фазе 1/2 и с ожидающими ack не теряет версии
  (`head.version == request.version` — идемпотентный повтор), `fsck` чист.
- **Водарк-баг** `WatermarkRegression` при DELETE исправлен (порядок bucket-цепочек + DP по головам), 20/20 ролей.
- **Zero-copy fallback**: DNAME/циклы/wildcard-CNAME/single-page overflow — 0 allocs; multi-page overflow — fallback.
- **REST split**: ~381 PUT/s p50 22 мс против 62/118 мс; DNS 85–93k qps.
- **Изолированный стенд**: server/client на разных SMT-ядрах, 14 сценариев, perf stat + плоские флеймграфы; отчёт `docs/bench/isolated.md`. Хост шумный, цифры — нижняя оценка.
- **Тесты**: утечка дочерних процессов закрыта RAII-guard; 15× pulsed lib без флейков.

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
  Удалённые blocklist-источники: self-signed HTTPS mock, скачивание hosts →
  NXDOMAIN через реальный UDP (apex/поддомены/wildcard, allowlist важнее),
  периодическое обновление по `refresh_secs`, SIGHUP и
  `POST /api/v1/blocklist/reload`, перезапуск из кэша без сети, ошибка сети/
  размера/редиректа оставляет старый снимок, ETag → 304, кэш `0600`,
  метрики `blocklist_fetch_total{result=...}`, `blocklist_entries`,
  `blocklist_last_success_ts`; SSRF-guard (https-only, приватные адреса).
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
  пересечений страниц; каталог пишут все процессы без внешнего flock
  (4 × 250 = 1000 зон; update/delete/gc/recreate без потерь); 100k
  insert/delete в 2/4/8 процессах: `high_water` 50→98 / 56→152 / 68→260;
  high_water стабилизируется (3636→5428 после 10k циклов); 8 процессов — 13.4k zone-commit/s.
  Водарк-баг `WatermarkRegression` при DELETE исправлен (порядок bucket-цепочек + DP по головам), 20/20 ролей.
  single-process без регрессий.
- Производительность (loopback, окно 1, 4 клиента; хост нагружен, числа консервативные):
  A p50 68 µs, p99 141 µs; mix p50 68 µs, p99 604 µs, ~44k qps на 4 клиентах;
  10k open-loop mix p99 777 µs (было 2361); NXDOMAIN 10k qps p50 757 µs, p99 1.56 мс,
  timeouts 0 (было 260 мс/16912); NX window1 p50 235 µs.
  Signed NXDOMAIN: NSEC3 p99 307 µs (было 38–47 мс), NSEC p99 343 µs.
  NSEC/NSEC3: NXDOMAIN p99 на 100k signed 367 мс → 0.71 мс; 1M in-memory p99 18 µs.
  Zero-copy: allocs/query 52 → 0–0.01 (udp-e2e); 0 аллокаций на ответ (unsigned/signed/referral/ANY/EDNS).
  Память: v2 чтение 1M RRset RssAnon 6.3 МБ (−41%); soak 600 с без роста;
  сервер на 1M RRset ~36 МБ RSS; PageCache 1024 страницы (~4 MiB образов); кеш резолвера 65.9 B/entry (было 113.8); фактически 74.3 МБ на 1M (было 126.4), RSS probe −36%, 0 allocs.
  Чтение: zone snapshot 87–92 нс; RRset warm 1M 842 нс (было 1.57 µs), cold 1M 27.7–41.4 µs (было 83.6), 0 allocs; zone index ~113–122 нс; order-key memcmp; warm lookup 0 аллокаций.
  io_uring: RSS 4.7/10.2/17.5 МБ на 1/4/8 workers (было 12.7/40.6/104.9); p99 8 workers 650→440 µs;
  SQPOLL медленнее (выкл), registered files вкл.
  Bulk-load: 1M RRset 2.5–2.8 с (было 26 мин), пик RSS 91–103 МБ, 91 МБ на диске (было 16 ГиБ); 100k — 0.25 с.
  Каталог: 1000 зон за 83 мс, 4096 за 651 мс (исправлен self-deadlock на 256-й зоне). Multi-process: create/delete/meta из любого процесса; high_water стабилизируется (3636→5428 после 10k циклов); 8 процессов — 13.4k zone-commit/s; в multi Page/node-кеши включены (общая генерация страниц в sidecar), freeze process-local, fsck repair — quiescent.
  Multi-process read (4 процесса × 40k): hot 0.51 µs, warm 0.83 µs p50 / 0.99 p99, ~1.09M qps; было 13.4 µs warm / ~199k qps. Single-process не изменился (0.44–1.09 µs).
  Резолвер: библиотека cache hit p50 0.396 µs, p99 0.572 µs, 0 allocs, ~2.3M qps/поток (было 6–7.6 µs);
  pulseresolved hot path p50 578 нс, p99 750 нс, 0 allocs; 200k qps без таймаутов (было захлёбывался на 150k).
  REST split: ~381 PUT/s p50 22 мс против 62/118 мс; DNS 85–93k qps.
  Старые замеры (loopback, хост нагружен): UDP echo 220 117 qps (4w/4c, окно 16); epoll 230 352 qps;
  окно 1 — 89 036 qps, p50 35 µs, p99 182 µs; zone lookup 156–268 нс; insert ~10 000/s;
  alloc reserve ~50M/s; per-zone commit 49k zone-commit/s; group commit 2 fsync/группу (2.4×/3.36×);
  PageCache 418 нс warm single-page; полный lookup ~1.06 µs; DoT ~10.4k; DoH h2 ~8.2k; DoH3 ~13.6–14.9k; DoQ ~5.25k.
  TCP/DoT/DoH/plain TCP — tokio event-loop: 10k idle-соединений, ~11 КБ/соединение (было 59–67 КБ); 10k соединений там, где thread-per-conn упирался в лимиты.
  DoT async после hot-path оптимизаций (64 активных + 100/1k/10k idle, 5 пар прогонов): 52.1k/56.3k/53.9k qps, p50 0.92/0.89/0.95 мс, p99 2.85/2.86/3.05 мс; baseline thread-per-conn в том же harness — 44.9k/45.6k/44.4k qps, p50 1.18/1.14/1.17 мс, p99 3.01/3.05/3.50 мс.
  Изолированный стенд (server на CPU 0-3, client 4-7), 10 прогонов, медианы: DoT 1000 соединений/окно 1 — 39.7k qps, p50 120 µs, p99 489 µs, p999 1011 µs против thread-per-conn 26.2k qps, p50 149 µs, p99 612 µs; окно 64 — 98.9k qps, p50 1.90 мс, p99 4.81 мс против 87.4k qps, p50 1.78 мс, p99 5.98 мс.
  Plain TCP event-loop (тот же изолированный стенд): 1000 соединений/окно 1 — p50 96 µs, p99 313 µs; 100/окно 64 — 120k qps, p99 6.74 мс.
  Настройки: `tcp_workers` (0 — по CPU), `tcp_nodelay` (true), `busy_poll_us` (0), `request_timeout_ms` (10000); `SO_BUSY_POLL` применяется к listener и accepted-сокетам, ошибка опции игнорируется.
  DoT async (64 активных + 100/1k/10k idle): 48.4k/49.5k/49.0k qps, p99 2.73/2.84/3.15 мс; серверный RSS idle ~11 KiB/conn (10k соединений, 115 MiB);
  baseline thread-per-conn: 52.5k/54.5k qps при 100/1k, но 59–67 KiB/conn.
- Fuzz/CI: `fuzz/` (cargo-fuzz, nightly) — 5 таргетов (`dns_wire`,
  `master_zone`, `zonefile_v2_open`, `transfer_tsig`, `dnscrypt_packet`),
  seed-корпус; CI job `fuzz-smoke` на push в main; Miri на
  `pulse-dns`/`pulse-master` (nightly, continue-on-error). `cargo deny check`
  зелёный.

## Остаточные ограничения (честно)

- Multi-process: каталог/durable commit сериализованы; каталог (`create/delete zone`, meta) может менять любой процесс
  (catalog lease + commit-lock); durable-пулы переиспользуются под lease зоны при
  `drop_txn < min(D_z, MP всех процессов, freeze)`, `high_water` стабилизируется (3636→5428 после 10k циклов);
  в multi Page/node-кеши включены (общая генерация страниц в sidecar); `freeze()` process-local; fsck repair — quiescent.
  Sidecar v4 несовместим с v3: живые процессы старой версии получают `Busy`, без живых держателей sidecar
  пересоздаётся (данные не затрагиваются). Группа ограничена 256 зонами / 1 мс settle; режим `Memory` —
  только публикация в памяти (fsync нет). Multi кеш-ключ включает generation страницы; sidecar занимает
  +~1 МиБ на дефолтной геометрии. `fsck --repair` и возврат `[DP,cursor)` — quiescent (offline).
- DoH3/DoQ — серверные; upstream-клиенты у резолвера остаются HTTP/1.1/DoT
  (h2/h3 upstream нет).
- Jobs/audit в памяти (TTL 24 ч / ring 4096), import только `text/plain`.
- DNSCrypt-сертификат без hot-reload; 0-RTT выключен; нет HSM/PKCS#11.
- Один статический control-токен у резолвера; аудит-файл не персистентный.
- NSEC3 для secondary-зон не генерируется; для secondary-зон ключи не ротируются
  автоматически.
- REST — MVP-подмножество спецификации (хотя доведён по jobs/transfers/audit);
  API доступен только на loopback (без TLS).
- RRset warm 842 нс при 1M (было 1.57 µs); цель 500 нс не достигнута.
- Signed/DO/ANY/referral/DNAME/циклы/wildcard-CNAME/oversized — zero-copy; fallback только для multi-page `OVERFLOW`.
- Bulk-load требует отсортированный вход; `Memory` incremental не реклеймит (bulk рекомендуется).
- В режиме `all` REST под 8 UDP workers делит CPU с DNS; для разделения есть роли `--role dns|api` на одном v2-файле (multi-process, ADR 0007), см. `docs/process-roles.md`.
- Замеры на loopback + SMT: клиент и сервер делят 8 vCPU, абсолютные qps занижены.
- perf record заблокирован (paranoid=2), flamegraph не снят; call-graph (dwarf) запрещён, только плоский cycles:u.
- TCP event-loop после hot-path оптимизаций обгоняет thread-per-conn по qps (+16–23%) и p50 при меньшей памяти; выигрыш зависит от нагрузки и ядра.
- THP file-backed ограничен shmem/tmpfs; на RX-арене удваивает RSS без выигрыша (auto best-effort).
- Изолированный стенд: server/client на разных SMT-ядрах, 14 сценариев, perf stat + плоские флеймграфы; отчёт `docs/bench/isolated.md`. Хост шумный, цифры — нижняя оценка.
- Loom отсутствует (fuzz и Miri есть); Miri — continue-on-error.
- File-fatal порча требует ручного разбора (repair её не «чинит»).
- io_uring работает на уровне L3 только при поддержке `IORING_FEAT_NODROP`,
  иначе L2; epoll даёт сопоставимый qps.
- DNS Cookies нет; 0x20 echo нет; полноценный RRL авторитетного сервера
  (`pulsed`) нет.
- THP file-backed ограничен shmem/tmpfs (ext4 file-backed — no-op; на RX-арене удваивает RSS без выигрыша).
- perf call-graph (dwarf) запрещён paranoid=2; только плоский cycles:u.
- TCP event-loop после hot-path оптимизаций обгоняет thread-per-conn по qps (+16–23%) и p50 при меньшей памяти; выигрыш зависит от нагрузки и ядра.
- Loopback/SMT/шумный хост; для SLA — отдельный стенд.

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

- RRset warm 842 нс при 1M (было 1.57 µs); цель 500 нс не достигнута.
- Signed/DO/ANY/referral/DNAME/циклы/wildcard-CNAME/oversized — zero-copy; fallback только для multi-page `OVERFLOW`.
- Bulk требует отсортированный вход; `Memory` incremental не реклеймит (bulk рекомендуется).
- В режиме `all` REST под 8 UDP workers делит CPU с DNS; для разделения есть роли `--role dns|api` на одном v2-файле (multi-process, ADR 0007), см. `docs/process-roles.md`.
- Замеры на loopback + SMT: клиент и сервер делят 8 vCPU, абсолютные qps занижены.
- perf record заблокирован (paranoid=2), flamegraph не снят; call-graph (dwarf) запрещён, только плоский cycles:u.
- TCP event-loop после hot-path оптимизаций обгоняет thread-per-conn по qps (+16–23%) и p50 при меньшей памяти; выигрыш зависит от нагрузки и ядра.
- THP file-backed ограничен shmem/tmpfs; на RX-арене удваивает RSS без выигрыша (auto best-effort).
- Изолированный стенд: server/client на разных SMT-ядрах, 14 сценариев, perf stat + плоские флеймграфы; отчёт `docs/bench/isolated.md`. Хост шумный, цифры — нижняя оценка.
- API доступен только на loopback, TLS отсутствует.
- Storage: параллельная запись по зонам внутри одного процесса (v2) и
  межпроцессная (v2, ADR 0007); каталог — multi-writer под lease, durable-пулы
  рекламируются под lease, `freeze()` локальный, page-кеш в multi включён (ключ `(page_no, generation)` из sidecar).
- Водарк-баг `WatermarkRegression` при DELETE исправлен (порядок bucket-цепочек + DP по головам), 20/20 ролей.
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
