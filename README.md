# pulse-dns

![CI](https://github.com/ivlev-dev/pulse-dns/actions/workflows/ci.yml/badge.svg)

Модульный высокопроизводительный DNS-сервер на Rust. Linux-first, edition 2024
(stable). Текущее состояние — **authoritative + кеширующий резолвер**:
авторитетный сервер (`pulsed`) с UDP/TCP, REST API и `pulse-zonefile` v2 как
единственным источником истины зон (DNS читает mmap, REST коммитит в файл;
параллельная запись v2 — основная, включая межпроцессную, ADR 0007), а
также резолвер (`pulseresolved`) с
forward/iterative-резолюцией, кешем, blocklist, overrides и DNSSEC-валидацией.
DoT, DoH (HTTP/1.1, HTTP/2 и HTTP/3), DoQ и DNSCrypt v2 (UDP+TCP) реализованы
и в `pulsed`, и в `pulseresolved` (серверные транспорты); резолвер ходит в
upstream по UDP, TCP, DoT и DoH/1.1 (пул keep-alive, backoff). Остаточные
ограничения — в `STATUS.md`.

## Возможности

**Работает:**

- Wire-формат DNS (`pulse-dns`): RR-типы A/AAAA/NS/CNAME/SOA/PTR/MX/TXT/SRV/
  CAA/DNAME/DS/DNSKEY/RRSIG/NSEC/NSEC3/NSEC3PARAM/TLSA/SVCB/HTTPS/Unknown,
  сжатие имён, EDNS0, RFC 3597, канонизация RFC 4034, лимиты, `unsafe` запрещён;
  zero-copy разбор запроса и ответ (`respond_ref_into`).
- Авторитетный движок запросов (`pulse-server`): NXDOMAIN/NODATA/ENT, wildcard и
  closest encloser, CNAME/DNAME, делегация/glue/DS, EDNS/BADVERS, TC, ANY по
  RFC 8482, детерминированный additional; zero-copy ответ (`respond_ref_into`),
  0 аллокаций на ответ (unsigned/signed/referral/ANY/EDNS); NSEC/NSEC3 индексы
  для быстрого NXDOMAIN.
- Кеш готовых ответов (`response_cache`): wire-байты с `ID=0` по ключу
  `(zone_seq, zone_version, QNAME в исходном регистре, QTYPE/QCLASS, DO/CD/RD,
  EDNS payload, транспорт)`, патч ID при выдаче, авторские TTL, инвалидация по
  версии зоны (REST-правка/удаление — немедленно), шарды + приближённый LRU,
  лимиты `max_entries`/`max_bytes`, метрики hit/miss/evict; `--response-cache*`.
- Рантайм (`pulse-runtime`): io_uring UDP (ring на ядро, multishot recv +
  provided buffers, `REGISTER_FILES`, `COOP/DEFER_TASKRUN`, опции SQPOLL/
  `SO_BUSY_POLL`, IP_PKTINFO, проверка NODROP, backpressure, graceful
  shutdown, изоляция паник) + epoll-фолбэк; RSS 4.7/10.2/17.5 МБ на 1/4/8 workers.
- Формат зон (`pulse-zonefile`): v2 `ParallelStore` — один mmap-файл,
  lock-free аллокатор страниц, ring-головы версий A/B, chain, per-zone пулы и
  GC, in-process пины читателей, group commit (2 `fdatasync` на группу зон),
  `Flush`/`Memory`/`Sync`, recovery, полный `fsck --verify` и `--repair`;
  bulk-load 1M RRset за 2.5–2.8 с; order-key memcmp; каталог 1000 зон за 83 мс;
  v1-файлы читаются для `pulsed convert`.
- REST API (`pulse-api`): health/ready/metrics/OpenAPI, zones CRUD, RRset
  CRUD/PATCH, settings, serial, transfers/jobs, import, audit, confirm_origin,
  keys rollover/status, async `Prefer: respond-async`, bearer-auth + scopes +
  per-zone allowlist (404 вне allowlist), ETag/If-Match, RFC 9457
  problem+json, Idempotency-Key, пагинация, лимиты тела/rate limit;
  write-ahead journal (outbox) мутаций с CRC/seq, crash-recovery, compaction и
  метриками (`docs/ops/journal.md`).
- Бинарник `pulsed`: UDP+TCP, зоны только в `pulse-zonefile` v2 (`--data`;
  DNS отвечает из mmap, без полной in-memory копии зон), импорт RFC 1035
  master-файлов командой `pulsed import` (`.zone`, `$ORIGIN`/`$TTL`/`$INCLUDE`),
  конвертация legacy v1-файлов `pulsed convert`, REST с per-zone writer'ами
  (разные зоны коммитятся параллельно; `--commit-mode per-zone|group`,
  `sync`/`flush`/`memory`), graceful shutdown, AXFR/IXFR-out по TCP с TSIG/ACL,
  IXFR-история, NOTIFY-out/in и secondary-зоны (AXFR/IXFR-in, bootstrap,
  SOA-refresh, expire → SERVFAIL), DNSSEC-подпись в zonefile (NSEC или
  NSEC3), Dockerfile.
- DNS UPDATE (RFC 2136) на UDP/TCP/DoT/DoH/DoQ/DNSCrypt: `opcode 5`, Zone/
  Prerequisite/Update секции, prerequisites (`YXDOMAIN`/`NXRRSET`/…),
  add/delete RR, RRset и name, CNAME/apex-инварианты, атомарный writer +
  один commit, автоинкремент SOA serial (RFC 1982), NOTIFY-out после
  изменения. Политика `[update]`: выключено по умолчанию, `allow_from`
  IP/CIDR, `allow_zones`, список `tsig_keys`, обязательный TSIG, replay-кэш;
  secondary/forward → `REFUSED`, неизвестная зона → `NOTAUTH`; метрики
  `pulsed_update_*`; пример `examples/pulsed-update.toml`.
- Защищённые транспорты `pulsed`: DoT (`dot_listen`, RFC 7858), DoH/1.1
  (`doh_listen`), DoH/2 (`doh_h2_listen`), DoH/3 (`doh3_listen`, RFC 9114,
  ALPN `h3`, QUIC/TLS 1.3) и DNSCrypt v2 по UDP (`dnscrypt_listen`) и TCP
  (`dnscrypt_tcp_listen`, 2-байтовый length-prefix, несколько запросов на
  соединение), общий путь `decode → QueryEngine (mmap) → encode`, TLS
  hot-reload по `SIGHUP`/`tls_reload_secs` (DoH/3 — новый `endpoint config`),
  IP/CIDR ACL и лимиты, `pulsed dnscrypt-gencert` (ключи 0600, каталог 0700,
  TXT-записи), метрики `dot_*`/`doh_*`/`doh_http2_*`/`doh_http3_*`/`doq_*`/
  `dnscrypt_*` в `/metrics`.
- Бинарник `pulseresolved`: forward/iterative-резолюция через `pulse-resolver`,
  UDP на `pulse-runtime` (N worker) и TCP с length-prefix, EDNS/TC, REFUSED
  для AXFR/IXFR, кеш, blocklist + overrides, DNSSEC-валидация (AD/SERVFAIL),
  смешанные upstream (UDP/TCP/DoT/DoH) с failover и cooldown, пул
  keep-alive соединений для DoT/DoH (`upstream_pool.pool_size`, по умолчанию
  4), ACL клиентов (`allow_from`, по умолчанию loopback), per-source token
  bucket (`drop`/`refused`/`truncate`), полный RRL по классам ответов
  (`noerror`/`nxdomain`/`referral`/`error`, `slip`, `truncate`/`drop`/
  `refused`), метрики `refused_acl_total`, `rate_limited_total`,
  `rrl_*_total{class}` и `upstream_queries_total{transport=...}`,
  SIGHUP/периодический reload, `GET /metrics` и `GET /healthz` на loopback,
  control-plane REST API (`control_listen`, bearer-token, RFC 9457
  problem+json, rate limit на токен, `X-Request-Id`), graceful shutdown по
  SIGTERM/SIGINT.
- Серверные защищённые транспорты `pulseresolved`: DoT (`dot_listen`),
  DoH/1.1 (`doh_listen`), DoH/2 (`doh2_listen`), DoQ (`doq_listen`) и
  DNSCrypt v2 UDP/TCP (`dnscrypt_listen`, `dnscrypt_tcp_listen`) с общим
  путём `decode → resolve → encode`, ACL по всем транспортам (`REFUSED`,
  отдельный `tls_allow_from`), token bucket вместо RRL на TLS/QUIC,
  hot-reload TLS-пары по SIGHUP, метрики
  `dot_*`/`doh_*`/`doh_http2_*`/`doq_*`/`dnscrypt_*`.
- TCP/DoT/DoH/plain TCP на tokio event-loop: ~11 КБ/соединение, 10k idle-соединений
  (было 59–67 КБ); qps +16–23% против thread-per-conn, p99 не хуже, p50 0.89–0.95 мс
  в общем loopback-тесте и ~0.12 мс при изоляции клиента и сервера. Тюнинг:
  `tcp_workers`, `tcp_nodelay`, `busy_poll_us`, `request_timeout_ms`.
- Multi-process каталог/reclaim: create/delete/meta из любого процесса;
  `high_water` стабилизируется (3636→5428 после 10k циклов); 8 процессов — 13.4k zone-commit/s;
  в multi Page/node-кеши включены (общая генерация страниц в sidecar, кеш-ключ `(page_no, generation)`), `freeze()` process-local, fsck repair — quiescent.
- Zero-copy fallback: DNAME/циклы/wildcard-CNAME/single-page overflow — 0 allocs;
  multi-page overflow — fallback.
- Изолированный стенд: server/client на разных SMT-ядрах, 14 сценариев, perf stat +
  плоские флеймграфы; отчёт [`docs/bench/isolated.md`](docs/bench/isolated.md).
- CI/hardening: `fuzz/` (cargo-fuzz, nightly) — 5 таргетов, seed-корпус,
  job `fuzz-smoke` на push в main; Miri на `pulse-dns`/`pulse-master`
  (nightly, continue-on-error); `cargo deny check`.

**Остаточные ограничения (см. `STATUS.md`):** каталог/durable commit сериализованы; каталог (`create/delete zone`,
meta) — любой процесс под catalog lease + commit-lock; durable-пулы в multi
переиспользуются под lease зоны при `drop_txn < min(D_z, MP всех процессов,
freeze)`, `high_water` стабилизируется (3636→5428 после 10k циклов); в multi
Page/node-кеши включены (ключ `(page_no, generation)` из sidecar); `freeze()` process-local; fsck repair — quiescent; sidecar +~1 МиБ на дефолтной геометрии.
8 процессов — 13.4k zone-commit/s. Водарк-баг `WatermarkRegression` при DELETE
исправлен (20/20 ролей). Sidecar v4 несовместим с v3 (живые старые → `Busy`;
без живых пересоздаётся); группа ≤256 зон / 1 мс settle; `Memory` — только
публикация в памяти (fsync нет); `freeze()` в multi process-local;
`fsck --repair`/возврат `[DP,cursor)` — quiescent; multi кеш-ключ включает
generation, sidecar +~1 МиБ на дефолтной геометрии.
TCP/DoT/DoH/plain TCP — tokio event-loop: 10k idle-соединений, ~11 КБ/соединение
(было 59–67 КБ); qps +16–23% против thread-per-conn, p99 не хуже, p50
0.89–0.95 мс в общем loopback-тесте и ~0.12 мс при изоляции.
Тюнинг: `tcp_workers`, `tcp_nodelay`, `busy_poll_us`, `request_timeout_ms`.
THP на ext4 file-backed — no-op, на RX-арене удваивает RSS без выигрыша
(auto best-effort; file-backed ограничен shmem/tmpfs).
perf call-graph (dwarf) запрещён paranoid=2; только плоский cycles:u.
DoH3/DoQ — серверные транспорты; upstream-клиенты резолвера
остаются HTTP/1.1/DoT (h2/h3 upstream нет). Jobs/audit в памяти (TTL 24 ч /
ring 4096), import только `text/plain`. DNSCrypt-сертификат без hot-reload;
0-RTT выключен; нет HSM/PKCS#11. Один статический control-токен у резолвера;
аудит-файл не персистентный. NSEC3 для secondary-зон не генерируется.
REST — MVP-подмножество спецификации; API доступен только на loopback (без
TLS). DNS Cookies и полноценный RRL авторитетного сервера (`pulsed`) нет; у
резолвера RRL есть. 0x20 echo нет. Loom в CI нет (Miri — continue-on-error).
RRset warm 842 нс при 1M (было 1.57 µs); cold 27.7–41.4 µs (было 83.6); 0 allocs;
zone index ~113–122 нс; e2e A p50 46.8 µs.
Signed/DO/ANY/referral/DNAME/циклы/oversized/wildcard-CNAME/single-page overflow —
zero-copy (0 allocs); fallback остаётся для multi-page `OVERFLOW`.
Bulk требует отсортированный вход; `Memory` incremental не реклеймит (bulk рекомендуется).
Изолированный стенд: server/client на разных SMT-ядрах, 14 сценариев, perf stat + плоские
флеймграфы; отчёт [`docs/bench/isolated.md`](docs/bench/isolated.md). Хост шумный, цифры — нижняя оценка.
Замеры на loopback + SMT (8 vCPU общие), абсолютные qps занижены. REST split: ~381 PUT/s
p50 22 мс против 62/118 мс; DNS 85–93k qps. REST под 8 UDP
workers по-прежнему делит CPU с DNS в режиме `all`; для разделения есть роли
`--role dns` и `--role api` на одном v2-файле (см.
[`docs/process-roles.md`](docs/process-roles.md)). HTTP/3 используется только
для DoH: WebTransport, server push, datagrams и 0-RTT выключены.

## Архитектура

| Крейт | Назначение |
|---|---|
| `pulse-dns` | Wire-формат DNS и RR-типы |
| `pulse-dnssec` | DNSSEC: подпись/валидация alg 8/13/15, RRSIG, NSEC/NSEC3 (Opt-Out), RFC 5011 trust anchors |
| `pulse-master` | RFC 1035 master-файлы: парсер, валидация, экспорт |
| `pulse-transfer` | TSIG, AXFR/IXFR, NOTIFY |
| `pulse-zonefile` | Бинарный mmap-формат зон: reader, writer/commit, fsck, compact |
| `pulse-runtime` | io_uring UDP-рантайм + epoll-фолбэк |
| `pulse-server` | Авторитетный движок запросов и движок DNS UPDATE |
| `pulse-tls` | DNS over TLS (RFC 7858), DoH/1.1 (RFC 8484), DoH/2 (`http2`), DoH/3 (`http3`, RFC 9114) и DoQ (`doq`): серверы и клиенты для upstream |
| `pulse-dnscrypt` | DNSCrypt v2: сертификаты, сервер, клиент |
| `pulse-api` | REST API управления зонами |
| `pulse-resolver` | Кеширующий резолвер: forward/iterative, кеш, blocklist (файлы + HTTPS-источники с кэшем и 304), overrides, DNSSEC |
| `pulsed` | Бинарник сервера (UDP+TCP+DoT+DoH/1.1-2-3+DoQ+DNSCrypt+REST) |
| `pulseresolved` | Бинарник резолвера (UDP+TCP+DoT+DoH/1.1+DoH/2+DoQ+DNSCrypt+метрики+control-plane API) |

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
  --config examples/pulsed.toml \
  --data /tmp/pulse-dns.zonefile \
  --listen-udp 127.0.0.1:5353 \
  --listen-tcp 127.0.0.1:5353 \
  --api-listen 127.0.0.1:8080 \
  --api-scope example.com.
```

Основной формат конфигурации `pulsed` — TOML. JSON поддерживается для
обратной совместимости: формат выбирается по расширению `.toml` или `.json`,
поля и значения по умолчанию одинаковые. Ошибка разбора содержит путь, строку
и колонку; неизвестное расширение отклоняется с подсказкой.
`examples/*.json` — legacy-эквиваленты `examples/*.toml`.

### DNS UPDATE (RFC 2136)

UPDATE включается только явно и по умолчанию требует TSIG. Минимальный
конфиг — `examples/pulsed-update.toml`; `nsupdate`-совместимый клиент:

```bash
nsupdate -y hmac-sha256:update-key.example.:c2VjcmV0LWJhc2U2NA== <<'DNS'
server 127.0.0.1 5353
zone example.com.
update add host.example.com. 300 A 192.0.2.50
send
DNS
```

Политика: `[update] enabled`, `require_tsig`, `allow_from` (IP/CIDR),
`allow_zones`, `tsig_keys` (имена из `[[tsig_keys]]`). Без настроек сервер
отвечает `REFUSED`; неизвестная зона — `NOTAUTH`; secondary/forward —
`REFUSED`. Изменение коммитится одной транзакцией `pulse-zonefile`, serial
SOA растёт, после успеха уходит NOTIFY-out. Метрики — `pulsed_update_*`.

### DNS и REST в разных процессах

На одном `--data`-файле можно запустить два процесса (multi-process v2,
ADR 0007): DNS-транспорты и REST API не делят CPU и не мешают друг другу.

```bash
pulsed --config examples/pulsed-dns.toml      # роль dns: UDP/TCP/DoT/DoH/DoQ/DNSCrypt
PULSED_API_TOKEN='...' \
  pulsed --config examples/pulsed-api.toml    # роль api: REST + write-ahead journal
```

Роль задаётся `role = "dns" | "api" | "all"` (или `--role`). `dns` подхватывает
новые версии зон опросом (`zone_poll_ms`, по умолчанию 250 мс) без рестарта;
`api` владеет журналом и восстанавливает его при рестарте. Второй `all` на
занятом файле получает `Busy`. Подробности и ограничения —
[`docs/process-roles.md`](docs/process-roles.md).

Ядра можно разделить явно: `dns_cpu_affinity = "0-3"` и
`api_cpu_affinity = [4, 5]` (пересечение с cpuset проверяется на старте,
общие CPU у ролей запрещены). Политика THP для mmap/арен — `huge_pages =
"auto"` (по умолчанию, best-effort). Рекомендации по NUMA, измерениям
`dTLB`/RSS и ограничениям file-backed THP — в
[`docs/ops/numa-affinity.md`](docs/ops/numa-affinity.md).

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

cargo run -p pulsed -- --config examples/transports.toml \
  --data /tmp/pulse-dns.zonefile

kdig @127.0.0.1 -p 8853 +tls +tls-ca=/tmp/pulsed-tls/cert.pem \
  +tls-hostname=localhost www.example.com. A
kdig @127.0.0.1 -p 8443 +https +tls-ca=/tmp/pulsed-tls/cert.pem \
  +tls-hostname=localhost www.example.com. A
kdig @127.0.0.1 -p 8444 +https +tls-ca=/tmp/pulsed-tls/cert.pem \
  +tls-hostname=localhost www.example.com. A       # DoH/2 (ALPN h2)
# DoH/3 (ALPN h3, QUIC): curl должен быть собран с HTTP/3
curl --http3-only --cacert /tmp/pulsed-tls/cert.pem \
  https://localhost:8445/healthz
kdig @127.0.0.1 -p 8854 +quic +tls-ca=/tmp/pulsed-tls/cert.pem \
  +tls-hostname=localhost www.example.com. A       # DoQ
# DNSCrypt: клиент pulse-dnscrypt/dnscrypt-proxy, сертификат из
# /tmp/pulsed-tls/dnscrypt-cert.json, TXT — /tmp/pulsed-tls/dnscrypt-cert.txt
```

Запуск резолвера (forward на 1.1.1.1/9.9.9.9, blocklist и overrides из
`examples/resolver.toml`):

```bash
cargo run -p pulseresolved -- --config examples/resolver.toml
dig @127.0.0.1 -p 5353 example.com. A
dig @127.0.0.1 -p 5353 ads.example. A          # blocklist → NXDOMAIN
dig @127.0.0.1 -p 5353 router.home. A          # override → 192.168.1.1
dig @127.0.0.1 -p 5353 example.com. A +tcp     # TCP length-prefix
curl -sS http://127.0.0.1:9153/healthz
curl -sS http://127.0.0.1:9153/metrics | head
# После правки blocklist: kill -HUP <pid> (или blocklist.reload_secs > 0)
```

Удалённые blocklist-источники (например, StevenBlack hosts):

```toml
[blocklist]
urls = ["https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"]
refresh_secs = 86400          # 0 — только SIGHUP/API
cache_dir = "cache/blocklist" # по умолчанию $XDG_CACHE_HOME/pulseresolved/blocklist
max_bytes = 67108864          # 64 MiB, стриминговый лимит
allow_redirects = false       # true — один редирект на тот же хост
timeout_ms = 30000
retries = 2
backoff_ms = 1000
# allow_hosts = ["raw.githubusercontent.com"]  # SSRF allowlist (пусто — любой публичный хост)
# ca_file = "private-ca.pem"                   # дополнительный PEM-CA

[[blocklist.sources]]
url = "https://example.com/hosts.txt"
refresh_secs = 3600
format = "hosts"              # auto | hosts | domains
```

Загрузчик использует только HTTPS и rustls (`webpki-roots` + опциональный
CA), проверяет TLS и запрещает приватные адреса для хостов вне `allow_hosts`.
Скачивание идёт в фоне с `If-None-Match`/`If-Modified-Since` (304 не
пересобирает снимок), а тело читается потоково и обрывается при превышении
`max_bytes`. Снимок пишется атомарно в `cache_dir/<hash>.list` (0600), рядом
— метаданные `ETag`/`Last-Modified`; при старте сначала применяется кэш, затем
сеть. Ошибка сети, размера или редиректа оставляет старый снимок. SIGHUP и
`POST /api/v1/blocklist/reload` запускают немедленное обновление; метрики —
`pulseresolved_blocklist_fetch_total{result="updated|not_modified|failed"}`,
`..._fetch_bytes_total`, `..._last_success_ts`, `..._entries`. Содержимое
списков не логируется.

Control-plane API резолвера (`examples/resolver-control.toml`): отдельный
loopback-listener, bearer-token и без TLS. Токен задаётся `control_token` или,
предпочтительно, `PULSERESOLVED_API_TOKEN` (env важнее файла); без токена
`control_listen` не запускается.

```bash
export PULSERESOLVED_API_TOKEN="$(openssl rand -hex 32)"
cargo run -p pulseresolved -- --config examples/resolver-control.toml &
API=http://127.0.0.1:9154
AUTH="Authorization: Bearer $PULSERESOLVED_API_TOKEN"

curl -sS "$API/healthz"                                  # liveness
curl -sS "$API/readyz"                                   # upstreams/anchors
curl -sS -H "$AUTH" "$API/metrics" | head
curl -sS -H "$AUTH" "$API/api/v1/cache/stats"
curl -sS -X POST -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"name":"example.com","type":"A"}' "$API/api/v1/cache/purge"
curl -sS -X POST -H "$AUTH" "$API/api/v1/cache/purge"    # очистить весь кеш
curl -sS -H "$AUTH" "$API/api/v1/blocklist"
curl -sS -X POST -H "$AUTH" "$API/api/v1/blocklist/reload"
curl -sS -H "$AUTH" "$API/api/v1/upstreams"
curl -sS -H "$AUTH" "$API/api/v1/trust-anchors"
curl -sS -X POST -H "$AUTH" "$API/api/v1/trust-anchors/reload"
curl -sS -H "$AUTH" "$API/api/v1/rrl/stats"
curl -sS -X PATCH -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"slip":4,"action":"drop","nxdomain":{"qps":2,"burst":10}}' \
  "$API/api/v1/rrl"
curl -sS -H "$AUTH" "$API/api/v1/config"                 # только безопасные поля
```

Коды ошибок — RFC 9457 `application/problem+json`: 401 (нет токена),
403 (неверный токен), 404/405, 413 (тело > 1 МиБ), 429 (rate limit на токен).
Все ответы содержат `X-Request-Id`; отказы пишутся в stderr-аудит без токена.
`cache/purge` не рвёт in-flight запросы, `blocklist/reload` эквивалентен
SIGHUP, `trust-anchors/reload` перечитывает DS-файл или RFC 5011 state,
`PATCH /api/v1/rrl` валидирует лимиты до применения.

Основной формат — TOML. JSON поддерживается для обратной совместимости:
формат выбирается по расширению `.toml` или `.json`, одинаковые поля и
значения по умолчанию. `examples/resolver.json` — legacy-эквивалент
`examples/resolver.toml`.

Смешанные upstream, ACL и rate limit (`examples/resolver-secure.json`):

```bash
cargo run -p pulseresolved -- --config examples/resolver-secure.json
# или поверх конфига:
cargo run -p pulseresolved -- --config examples/resolver.toml \
  --upstream tls://dns.google:853#dns.google \
  --upstream https://cloudflare-dns.com/dns-query
```

В TOML/JSON `upstreams` принимает строки (`udp://`, `tcp://`,
`tls://host:853#name`, `https://host/dns-query`) и объекты `{ "addr": "...",
"tls": true, "server_name": "localhost", "ca": "ca.pem" }` (в TOML —
`{ url = "...", ca = "ca.pem" }`). `allow_from` — список IP/CIDR (пусто —
только loopback); `rate_limit` — `qps`, `burst`, `max_entries` и `action`
(`refused`, `drop`, `truncate`); `rrl` — классы `noerror`/`nxdomain`/
`referral`/`error` с `qps`/`burst`, `slip` и `action` (см.
`docs/spec/rrl.md`); `upstream_pool` — `pool_size` (по умолчанию 4) и
backoff переподключения (см. `docs/spec/upstream-pool.md`).

CLI: `--config` (`.toml` или `.json`), `--listen-udp`, `--listen-tcp`,
`--dot-listen`, `--doh-listen`, `--doh2-listen`, `--doq-listen`,
`--dnscrypt-listen`, `--dnscrypt-tcp-listen`, `--tls-cert`, `--tls-key`,
`--metrics-listen`, `--forward` (repeatable), `--upstream` (repeatable,
URL/схема), `--workers`, `--log-level`, `--blocklist` (repeatable),
`--no-dnssec`. CLI-overrides применяются поверх загруженного TOML.

Защищённые серверные транспорты (`examples/resolver-secure-transports.toml`):

```bash
# TLS-пара для DoT/DoH/DoH2/DoQ (ключ — 0600) и material DNSCrypt
# (provider/resolver-ключи 0600 + сертификат из `pulsed dnscrypt-gencert`)
cargo run -p pulseresolved -- --config examples/resolver-secure-transports.toml

kdig @127.0.0.1 -p 853 +tls +tls-ca=/etc/pulse/tls/fullchain.pem \
  +tls-hostname=dns.example example.com. A       # DoT
kdig @127.0.0.1 -p 443 +https +tls-ca=/etc/pulse/tls/fullchain.pem \
  +tls-hostname=dns.example example.com. A       # DoH/1.1
kdig @127.0.0.1 -p 8443 +https +tls-ca=/etc/pulse/tls/fullchain.pem \
  +tls-hostname=dns.example example.com. A       # DoH/2
kdig @127.0.0.1 -p 8853 +quic +tls-ca=/etc/pulse/tls/fullchain.pem \
  +tls-hostname=dns.example example.com. A       # DoQ
# DNSCrypt: dnscrypt-proxy/pulse-dnscrypt с сертификатом провайдера
```

Транспорты включаются независимо (`dot_listen`, `doh_listen`,
`doh2_listen`, `doq_listen`, `dnscrypt_listen`, `dnscrypt_tcp_listen`),
работают одновременно и используют общий ACL и rate limit. `tls_allow_from`
задаёт отдельный ACL для DoT/DoH/DoQ (пусто — общий `allow_from`); клиент
вне ACL получает `REFUSED` на любом транспорте. RRL применяется только к
открытому UDP, на TLS/QUIC — per-source token bucket. SIGHUP перечитывает
blocklist и TLS-пару (`tls_cert`/`tls_key`) для новых соединений. Блок
`[secure]` задаёт `max_connections`, `max_streams`, таймауты, размер
сообщения, `worker_threads` и `cache_control`; `[dnscrypt]` — лимиты
пакетов и anti-replay. Лимиты соединений/стримов и метрики по транспортам
описаны в `crates/pulseresolved/src/lib.rs`.

Зоны в `pulse-zonefile` v2:

```bash
# импорт (повторный --replace; опционально --sign с --dnssec-key)
cargo run -p pulsed -- import \
  --data /tmp/pulse-dns.zonefile \
  --origin example.com. \
  examples/example.com.zone

# legacy v1 → v2 (без потери зон/записей/настроек)
cargo run -p pulsed -- convert --from /tmp/old.v1 --to /tmp/pulse-dns.zonefile

# offline fsck: граф/пулы/утечки; --repair возвращает место и изолирует
# повреждённые зоны (подробности — docs/ops/fsck.md)
cargo run -p pulsed -- fsck --data /tmp/pulse-dns.zonefile

cargo run -p pulsed -- --config examples/pulsed.toml \
  --data /tmp/pulse-dns.zonefile --durability flush \
  --commit-mode per-zone --map-size 268435456
```

Поля `zones`/`zones_files` больше не принимаются (ни в TOML, ни в JSON):
конфигурация завершится с инструкцией миграции. Все зоны живут в `--data`;
REST-правки коммитятся в тот же файл и сразу видны DNS.

Подробности — в `examples/README.md`.

Запуск с REST: API включается флагом `--api-listen` или полями `api_listen`/
`api_token`/`api_scope` в конфигурации (CLI-overrides важнее файла; токен
обязателен, предпочтительно через `PULSED_API_TOKEN`; без TLS только
loopback). Примеры запросов — в `examples/README.md`. Короткий пример:

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

Полный набор workspace-тестов (1582 теста, включая doctests) проходит. Также проходят
`cargo fmt --check`, `cargo clippy --workspace --all-targets -D warnings` и
rustdoc без warnings.

Проверка зависимостей:

```bash
cargo deny check
```

## Производительность

Замеры на loopback (окно 1, 4 клиента); клиент и сервер делят 8 vCPU (SMT) —
абсолютные qps занижены, числа консервативные, не SLA.

| Показатель | Значение |
|---|---|
| A, окно 1, 4 клиента | p50 68 µs, p99 141 µs |
| Mix, окно 1, 4 клиента | p50 68 µs, p99 604 µs, ~44k qps |
| Mix 10k open-loop | p99 777 µs (было 2361) |
| NXDOMAIN 10k qps | p50 757 µs, p99 1.56 мс, timeouts 0 (было 260 мс/16912) |
| NXDOMAIN, окно 1 | p50 235 µs |
| NSEC/NSEC3 NXDOMAIN p99 (100k signed) | 367 мс → 0.71 мс |
| Signed NXDOMAIN (NSEC3/NSEC) | p99 307 µs / 343 µs (было 38–47 мс) |
| NSEC/NSEC3 in-memory (1M) | p99 18 µs (цель <2 мс) |
| Zero-copy ответ (allocs/query) | 52 → 0–0.01 (udp-e2e); 0 аллокаций на ответ (unsigned/signed/referral/ANY/EDNS); fallback: DNAME/циклы/wildcard-CNAME/single-page overflow — 0 allocs; multi-page overflow — fallback |
| v2 чтение 1M RRset (RssAnon) | 6.3 МБ (−41%); soak 600 с без роста |
| Сервер на 1M RRset (RSS) | ~36 МБ |
| PageCache | 1024 страницы (~4 MiB образов) |
| Zone snapshot | 87–92 нс |
| RRset warm (1M) | 842 нс (было 1.57 µs); cold 27.7–41.4 µs (было 83.6); 0 allocs; zone index ~113–122 нс |
| e2e A p50 | 46.8 µs (Key::rebuild убран) |
| Bulk-load 1M RRset | 2.5–2.8 с (было 26 мин), пик RSS 91–103 МБ, 91 МБ на диске (было 16 ГиБ); 100k — 0.25 с |
| io_uring RSS (1/4/8 workers) | 4.7/10.2/17.5 МБ (было 12.7/40.6/104.9) |
| io_uring p99 (8 workers) | 650 → 440 µs; SQPOLL медленнее (выкл), registered files вкл |
| Каталог зон | 1000 зон за 83 мс, 4096 за 651 мс |
| Кеш резолвера | 65.9 B/entry (было 113.8); фактически 74.3 МБ на 1M (было 126.4), RSS probe −36%, 0 allocs |
| Резолвер (библиотека) cache hit | p50 0.396 µs (не хуже после компактной раскладки), p99 0.572 µs, 0 allocs, ~2.3M qps/поток |
| pulseresolved hot path | p50 578 нс, p99 750 нс, 0 allocs; 200k qps без таймаутов |
| UDP echo, 4 worker / 4 клиента, окно 16 | 220 117 qps |
| epoll, те же условия | 230 352 qps |
| UDP echo, окно 1 | 89 036 qps, p50 35 µs, p99 182 µs |
| Zone lookup | 156–268 нс |
| Insert | ~10 000/s |
| Lock-free аллокатор (reserve) | ~50M/s |
| Per-zone commit (4 потока, B1, tmpfs) | 49 000 zone-commit/s |
| Group commit (fsync на группу) | 2 fsync/группу; ускорение 2.4× (btrfs), 3.36× (эмуляция fsync 2 мс) |
| PageCache warm single-page | 418 нс; полный lookup ~1.06 µs |
| DoT (qps, одно keep-alive соединение) | ~10.4k |
| DoT async, 64 активных + 100/1k/10k idle | 52.1k/56.3k/53.9k qps, p50 0.92/0.89/0.95 мс, p99 2.85/2.86/3.05 мс (thread-per-conn: 44.9k/45.6k/44.4k qps, p50 1.18/1.14/1.17 мс) |
| DoT изолированно, 1000 соединений, окно 1 | event-loop p50 120 µs / p99 489 µs / 39.7k qps; thread-per-conn p50 149 µs / p99 612 µs / 26.2k qps |
| DoT/TCP/DoH idle RSS (event-loop) | ~11 KiB/соединение (было 59–67 KiB); 10k соединений, RSS не вырос |
| DoH HTTP/2 (DNS/s) | ~8.2k |
| DoH HTTP/3 (qps) | ~13.6–14.9k |
| DoQ (qps) | ~5.25k |
| Межпроцессная запись v2 | 4 процесса × 4 зоны без потерь; 10k коммитов в 2 процессах без пересечений; create 1.9k/1.3k/0.6k зон/с (2/4/8 процессов); commit ~11–14k zone-commit/s; 8 процессов — 13.4k zone-commit/s; `high_water` стабилизируется (3636→5428 после 10k циклов); 100k insert/delete: `high_water` 50→98 / 56→152 / 68→260; group commit v4: 8 процессов 6.0× (1385 vs 231 commits/s, fsync 2 мс), p99 5.6 мс vs 34–84 мс direct |
| Роли `dns`+`api` (8 DNS + 8 REST, 8 vCPU) | DNS 85–93k qps (p99 0.53–0.66 ms), REST 359–361 PUT/s (p99 29–30 ms); `all`: 98–106k qps (p99 0.36–0.41 ms), 381–385 PUT/s (p99 27–28 ms); REST split ~381 PUT/s p50 22 мс (против 62/118 мс) |

## Ограничения и roadmap

- Зоны хранятся в одном бинарном mmap-файле (`--data`); JSON-зон нет. v2:
  параллельная запись по зонам внутри одного процесса и межпроцессная запись
  (ADR 0007: sidecar-координатор, CAS-курсор, `fcntl` per-zone leases +
  fencing, общая reader table, `LOCK_SH`); каталог (`create/delete zone`, meta)
  может менять любой процесс (catalog lease); durable-пулы переиспользуются под
  lease зоны, `high_water` стабилизируется; `freeze()` пока локальный; offline
  `pulsed fsck --data <file> [--repair]` проверяет
  граф/пулы/утечки и изолирует повреждённые зоны; `map_size` задаётся при
  создании (по умолчанию 4 GiB); до 4096 зон, страницы 4096 байт.
- DoT/DoH/1.1 и plain TCP DNS не создают поток на соединение: соединения —
  задачи общего tokio event-loop (`pulse_tls::net::TcpServer`) с лимитом
  соединений, idle/request-таймаутами, backpressure и graceful shutdown.
  DoH/2 — h2, DoH/3 и DoQ — QUIC (quinn); DoH/3 только серверный, без
  WebTransport/server push/datagrams и 0-RTT; DNSCrypt UDP усекает большие
  ответы с `TC`, DNSCrypt TCP отдаёт их без усечения; DNSCrypt TXT-запись
  публикуется вручную; DNSCrypt сертификат без hot-reload.
  AXFR/IXFR-out остаётся потоковым: после разбора запроса сокет уходит в
  `spawn_blocking`, потому что трансфер пишет серию кадров синхронно.
- REST — MVP-подмножество спецификации (jobs/transfers/audit/serial/keys
  реализованы); API доступен только на loopback (без TLS).
- DNS UPDATE: только primary-зоны в состоянии `Serving` (secondary/forward →
  `REFUSED`); авторизация — статические TSIG-ключи + IP/CIDR + allowlist зон,
  без per-name update-policy; DNSSEC-записи (`RRSIG`/`NSEC`/`NSEC3`/
  `NSEC3PARAM`/`DNSKEY`) управляются сигнатором и UPDATE не меняются;
  SIG(0) (RFC 3007) не поддерживается — авторизация только TSIG (RFC 8945);
  персистентность — общий commit `pulse-zonefile` (отдельного UPDATE-journal
  нет).
- DNSSEC: NSEC и NSEC3 (SHA-1, Opt-Out включается `nsec3_opt_out`),
  автоматическая ротация KSK/ZSK по RFC 7583 (`rotation`: pre-publish →
  double-sign → active → retire, состояние в `0600`-файле), RFC 5011 для
  резолвера (`trust_anchor = { path, state }`); NSEC3 для secondary-зон не
  генерируется; для secondary-зон ключи не ротируются автоматически.
- Резолвер: upstream DoH только HTTP/1.1; пул keep-alive DoT/DoH (по
  умолчанию 4) с backoff; RRL по классам ответов есть; DNS Cookies нет; 0x20
  echo нет. Control-plane: один статический bearer-токен; аудит-файл не
  персистентный. Jobs/audit в памяти (TTL 24 ч / ring 4096); import только
  `text/plain`. Нет HSM/PKCS#11.
- Roadmap: `docs/plan/roadmap.md` (M0–M6 выполнены; остаточные ограничения
  выше). Sidecar v4: несовместим с v3 (живые старые → `Busy`; без живых
  пересоздаётся); группа ≤256 зон / 1 мс settle; `Memory` — только публикация
  в памяти (fsync нет); `freeze()` в multi process-local; `fsck --repair`/
  возврат `[DP,cursor)` — quiescent; multi кеш-ключ включает generation,
  sidecar +~1 МиБ.

## Лицензия

MIT OR Apache-2.0. См. `LICENSE-MIT` и `LICENSE-APACHE`.
