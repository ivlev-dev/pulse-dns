# Измерительный харнесс `pulse-loadgen`

Отдельный workspace-крейт `crates/pulse-loadgen`: клиент нагрузки, генератор
зон, сэмплер памяти, аллокационный и `perf`-профиль. Production-код
(`pulsed`, `pulse-*`) не меняется; `unsafe` в крейте запрещён
(`#![forbid(unsafe_code)]`).

## Быстрый старт

```bash
cargo build --release -p pulsed -p pulse-loadgen
target/release/pulse-bench --quick          # smoke, без 1M/soak/perf
target/release/pulse-bench --reuse          # полный baseline (нужен 1M store)
```

Артефакты: `target/bench/` (zonefile, конфиги, логи, `perf.data`,
`dhat-heap.json`), отчёты — `docs/bench/baseline.md` и
`docs/bench/baseline.json`.

## Инструменты

| Бинарник | Назначение |
|---|---|
| `pulse-loadgen` | UDP open-loop/closed-loop, TCP, DoT, DoH h2; HDR p50/p99/p999/max; счётчики sent/recv/timeout/invalid/suppressed; дельта `UdpInErrors`/`UdpRcvbufErrors`; параллельный REST |
| `pulse-zonegen` | v2-zonefile `zones × rrsets` c apex SOA/NS/A и A/AAAA/MX/TXT |
| `pulse-mem` | динамика `/proc/<pid>/status`, `smaps_rollup`, `smaps`, `fincore`, fd, CPU |
| `pulse-bench` | воспроизводимый набор сценариев, 3 прогона/медиана, память, soak, `perf`, Markdown/JSON |
| `pulse-alloc` | `dhat` counting allocator: encode/decode/lookup/lookup_ref/udp-e2e, `--features alloc` |

## Метрики

- **Латентность** — клиентская, `CLOCK_MONOTONIC` (`Instant`), HDR-гистограмма
  (`hdrhistogram`, 3 значащие цифры), p50/p90/p99/p999/max/mean.
- **QPS** — клиентский (`received / измеренное время`) и серверный
  (`responses` из финального лога `pulsed` / время измерения; прогрев
  вычитается по `warmup_received` клиента).
- **Потери** — `sent − received`, `timeouts`, `invalid`, `suppressed`
  (клиент не отправил из-за лимита in-flight) и дельта namespace-счётчиков
  `UdpInErrors`/`UdpRcvbufErrors` из `/proc/net/snmp` + `nstat -az`.
  `SO_RXQ_OVFL` не используется: cmsg/`setsockopt` требуют `unsafe`, а
  крейт его запрещает. `kfree_skb` не снимается (нет bpftrace/tracefs и
  прав); потери оцениваются по `UdpRcvbufErrors`. Это ограничение отмечено
  в отчёте.
- **Память** — `VmRSS`, `RssAnon`, `RssFile`, `RssShmem`, `Pss`, `Shared_*`,
  `Private_*`, fd, CPU; `fincore RES` для page cache файла зон; `st_blocks`
  для фактического диска (v2 sparse).
- **Аллокации** — дельта `dhat::HeapStats` (`total_blocks/total_bytes`) на N
  операций; отдельно encode/decode/lookup/lookup_ref/udp-e2e.
- **Профиль** — `perf stat -p <pid>` (cycles/instructions/cache/branches/
  page-faults/context-switches) и `perf record -g` + `perf report`; при
  наличии `inferno-collapse-perf`/`inferno-flamegraph` строится
  `target/bench/flamegraph.svg`.

## Сценарии baseline

| Сценарий | Транспорт | Workers/threads | Ставка | Store |
|---|---|---|---|---|
| `udp-w1` | UDP | 1/1 | 10k open-loop | 1 зона × 100k RRset |
| `udp-w4` | UDP | 4/4 | 10k open-loop | 1 × 100k |
| `udp-w8` | UDP | 8/8 | 10k open-loop | 1 × 100k |
| `udp-closed-w8` | UDP | 8/8, окно 64 | closed-loop | 1 × 100k |
| `udp-nx-w8` | UDP | 8/8 | 10k, 100% NXDOMAIN | 1 × 100k |
| `tcp-w8` | TCP | 8/8, окно 16 | closed-loop | 1 × 100k |
| `dot-w8` | DoT | 8 соединений | closed-loop | 1 × 100k |
| `doh-h2-w8` | DoH/2 | 8 соединений × 16 stream | closed-loop | 1 × 100k |
| `udp-rest-8z` | UDP + REST | 8/8 | 10k + 80 PUT/s | 8 × 1000 |

Память: ось RRset — `1k/100k/1M` в одной зоне; ось зон — `1/100/255` зон при фиксированных `~100k` RRset суммарно
(`1×1k`, `100×1k`, `255×392`). Сценарий `1000 зон` **заблокирован дефектом
v2-writer'а**: на `zone_seq=256` процесс зависает в `futex_wait` (вероятно,
lease-шард каталога); 255 зон работают. Это отмечено в baseline. Soak 10 минут на `1M` при 20k qps.

## Ограничения и шум

- **Loopback + SMT.** Клиент и сервер делят 8 vCPU (4 физических ядра × 2).
  Абсолютные qps занижены, p99 завышен; сравнивайте прогоны между собой и с
  baseline на той же машине. В отчёте фиксируются `loadavg`, модель CPU и
  SMT siblings.
- **v2 не использует mmap для чтения.** `pulse-zonefile` v2 читает
  `pread`/`pwrite`; `mmap RSS` = 0 — это ожидаемо. Рабочий набор файла
  измеряется как page cache (`fincore`), а не как RSS процесса.
- **Page cache и RSS.** `RssFile`/`PageCache` растут при прогреве файла — это
  не утечка. Утечка — рост `RssAnon`/`VmRSS` при стабильном page cache.
- **`perf`** на этой машине: `perf stat` работает, если `perf` — parent
  сервера (обход `yama/ptrace_scope=1`). При `kernel.perf_event_paranoid=2`
  `perf record -e cycles:u` **без call-graph доступен**, а `-g` и
  `--call-graph dwarf/fp` — **нет** (`Failure to open event 'cycles:u'`).
  Harness пробует dwarf и откатывается на плоский `cycles:u`: flamegraph
  строится, но без стеков (hotspots — по символам). Для dwarf нужен
  paranoid 1 или `CAP_PERFMON`; harness не понижает sysctl сам.
- **Генерация 1M RRset** в текущем v2-writer'е стоит ~6 COW-страниц на
  RRset (allocator cursor растёт, страницы уходят в free pool). Файл
  sparse; фактическая запись ~24 GiB и ~10 минут. Это отдельный вывод о
  стоимости bulk-load, а не свойство чтения.
- **REST** измеряется с `Connection: close` на запрос; латентность включает
  TCP/TLS-подобный overhead и очередь API, а не только commit.

## Изолированный стенд (anti-loopback+SMT)

`pulse-bench --isolated` запускает сервер под `taskset -c <server>` и
пиннит каждый клиентский поток через `sched_setaffinity(0, <cpu>)`;
наборы проверяются на непересечение и вхождение в `Cpus_allowed_list`.
Сценарии `iso-*` (UDP A/mix/NX, signed с EDNS DO, TCP, DoH h2, UDP+REST
со split-ролями DNS/REST) идут в паре с `shared-*` — тем же сценарием без
пиннинга. 3 прогона, медиана, HDR; `perf stat` (cycles/instructions/cache/
TLB) и `perf record -e cycles:u` на каждый сценарий.

```bash
# авто-раскладка: целые физические ядра на сторону
target/release/pulse-bench --isolated --reuse --auto-layout

# вручную (проверит sched_getaffinity и SMT-сиблингов)
target/release/pulse-bench --isolated --reuse   --server-cpus 0-3 --client-cpus 4-7 --rest-cpus 6-7
```

Отчёты: `docs/bench/isolated.md` и `docs/bench/isolated.json`.
Раскладка `0,2,4,6` / `1,3,5,7` **не изолирует** ядро: каждая пара —
SMT-сиблинги одного физического ядра; harness предупреждает об этом.
`pulse-loadgen` принимает `--client-cpus` (и `--rest-cpus`) для ручных
прогонов; `--server-cpus` у него информационный — сервер пиннит
`pulse-bench`/`taskset`.

## Команды

```bash
# один сценарий
target/release/pulse-loadgen --server 127.0.0.1:5353 --mode udp \
  --threads 8 --qps 20000 --duration 10 --warmup 3 \
  --mix a=40,aaaa=20,mx=15,txt=10,nx=15 --zones 1 --rrsets-per-zone 100000 \
  --json-out run.json

# TCP / DoT / DoH h2
target/release/pulse-loadgen --server 127.0.0.1:5353 --mode tcp --threads 8 --window 16
target/release/pulse-loadgen --server 127.0.0.1:853 --mode dot --threads 8 \
  --ca target/bench/cert.pem
target/release/pulse-loadgen --server 127.0.0.1:8443 --mode doh-h2 --threads 8 \
  --window 16 --ca target/bench/cert.pem

# память по живому pid
target/release/pulse-mem --pid "$(pgrep -n pulsed)" --duration 600 \
  --data target/bench/z1m.v2 --zones 1 --rrsets 1000000 --json-out mem.json

# аллокации
cargo run -p pulse-loadgen --release --features alloc --bin pulse-alloc -- \
  --data target/bench/z1m.v2 --rrsets 1000000 --ops 20000 --json-out alloc.json

# commit-режимы v2
cargo bench -p pulsed --bench zone_writes
```
