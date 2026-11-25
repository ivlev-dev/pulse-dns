# Isolated: pulsed, сервер и клиент на разных физических ядрах

Автогенерировано `pulse-bench`; JSON-версия — файл из `--json`.
Все числа — **медиана трёх прогонов**, если не сказано иное. Прогрев входит в каждый прогон, но не в измерение.

Методика: `iso-*` — сервер пиннится через `taskset`, клиентские потоки — `sched_setaffinity`; `shared-*` — тот же сценарий без пиннинга (контроль loopback-общий). 3 прогона, медиана; HDR p50/p99/p999. Сервер и клиент на одной машине (loopback), поэтому абсолютные qps — нижняя оценка.

## Окружение

| Параметр | Значение |
|---|---|
| Host | `lenovo` |
| CPU | AMD Ryzen 5 3500U with Radeon Vega Mobile Gfx |
| vCPU | 8 |
| SMT siblings | `0-1` |
| Физические ядра (SMT-группы) | `0-1`, `2-3`, `4-5`, `6-7` |
| Kernel | `7.3.3-1-cachyos-bore-lto` |
| `pulsed` | pulsed 0.1.0 |
| Git | `e5b3d73dd70b5f151d5ea916f3cf6dedc2e3f607` |
| loadavg на старте | 13.60 / 13.27 / 9.83 |
| Сгенерировано (unix) | 1795623035 |

> **Изоляция.** Сценарии `iso-*` пиннятся по CPU (`taskset` для сервера, `sched_setaffinity` для клиентских потоков), `shared-*` — контроль на общем наборе CPU. Перед прогоном проверяйте `loadavg` и governor; числа на одной машине сравнимы между собой, но не с другим железом.

## Нагрузка

| Сценарий | Транспорт | Потоки | Цель qps | Клиент qps | Сервер qps | cl user% | cl sys% | srv user% | srv sys% | srv RSS MiB | srv CPUs | p50 µs | p99 µs | p999 µs | max µs | sent | recv | timeout | rcvbuf Δ | REST qps |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| shared-udp-a | udp | 8 | closed | 39400 | 39400 | 43 | 324 | 172 | 54 | 31.6 | `0-7` | 12132.35 | 31948.80 | 43581.44 | 54034.43 | 197001 | 197001 | 0 | 0 | 0.0 |
| iso-udp-a | udp | 8 | closed | 36240 | 36241 | 36 | 252 | 121 | 35 | 28.0 | `0-3` | 10452.99 | 37322.75 | 48037.89 | 56557.57 | 181394 | 181202 | 192 | 0 | 0.0 |
| shared-udp-mix | udp | 8 | closed | 23893 | 23894 | 31 | 231 | 169 | 25 | 30.8 | `0-7` | 15671.30 | 118489.09 | 161873.92 | 227672.06 | 119467 | 119467 | 0 | 0 | 0.0 |
| iso-udp-mix | udp | 8 | closed | 29177 | 29177 | 33 | 247 | 202 | 27 | 30.2 | `0-3` | 14458.88 | 58490.88 | 83689.47 | 95748.10 | 145883 | 145883 | 0 | 0 | 0.0 |
| shared-udp-nx | udp | 8 | closed | 7544 | 7545 | 47 | 369 | 218 | 8 | 22.0 | `0-7` | 57212.93 | 227803.14 | 370671.61 | 371982.34 | 37722 | 37722 | 0 | 0 | 0.0 |
| iso-udp-nx | udp | 8 | closed | 7384 | 7384 | 40 | 314 | 254 | 9 | 21.8 | `0-3` | 60063.74 | 208273.41 | 244842.49 | 327417.85 | 36920 | 36920 | 0 | 0 | 0.0 |
| shared-udp-signed | udp | 8 | closed | 35133 | 35133 | 42 | 300 | 129 | 23 | 29.6 | `0-7` | 11591.68 | 50790.40 | 75431.93 | 93847.55 | 175666 | 175666 | 0 | 0 | 0.0 |
| iso-udp-signed | udp | 8 | closed | 39543 | 39543 | 34 | 262 | 215 | 38 | 31.8 | `0-3` | 9584.64 | 57409.54 | 77463.55 | 88866.82 | 197713 | 197713 | 0 | 0 | 0.0 |
| shared-tcp | tcp | 8 | closed | 28717 | 28717 | 10 | 106 | 284 | 126 | 22.9 | `0-7` | 2205.70 | 7733.25 | 10944.51 | 16506.88 | 143584 | 143584 | 0 | 0 | 0.0 |
| iso-tcp | tcp | 8 | closed | 28360 | 28360 | 8 | 120 | 274 | 106 | 21.8 | `0-3` | 2445.31 | 7520.26 | 13803.52 | 23101.44 | 141801 | 141801 | 0 | 0 | 0.0 |
| shared-doh-h2 | doh-h2 | 8 | closed | 11110 | 11111 | 33 | 50 | 160 | 34 | 24.2 | `0-7` | 10649.60 | 19316.74 | 23609.34 | 30261.25 | 55552 | 55552 | 0 | 0 | 0.0 |
| iso-doh-h2 | doh-h2 | 8 | closed | 11082 | 11082 | 26 | 49 | 165 | 32 | 24.4 | `0-3` | 10985.47 | 17530.88 | 19791.87 | 22577.15 | 55408 | 55408 | 0 | 0 | 0.0 |
| shared-udp-rest | udp | 4 | 10000 | 9533 | 9533 | 8 | 57 | 188 | 40 | 38.8 | `0-7` | 356.86 | 7979.01 | 20594.69 | 34406.40 | 47664 | 47664 | 0 | 0 | 61.5 |
| iso-udp-rest | udp | 4 | 10000 | 9487 | 9487 | 8 | 59 | 183 | 35 | 36.7 | `0-3` | 361.21 | 3577.86 | 5558.27 | 7634.94 | 47433 | 47433 | 0 | 0 | 58.0 |

`rcvbuf Δ` — `UdpRcvbufErrors` namespace за прогон; если он > 0, сервер/ядро теряли датаграммы и qps-число отражает не только сервер. Клиентский qps — `received / время`; серверный — `responses` из финального лога `udp_stats`/`stats` минус ответы прогрева, делённые на время измерения. `cl/srv user%/sys%` — `utime/stime` процесса за прогон (100% = одно ядро; включает прогрев и старт сервера), `srv RSS` — `VmRSS` после прогона.

### shared-udp-a

UDP, A-only, closed-loop окно 64: лучший путь (positive hit). (контроль: сервер и клиент на общем наборе CPU).

| Прогон | Клиент qps | p50 µs | p99 µs | p999 µs | max µs | cl user% | cl sys% | srv user% | srv sys% | srv RSS MiB | sent | recv | timeout | invalid | suppressed | rcvbuf Δ | server qps |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| run | 45629 | 9011.20 | 32653.31 | 44040.19 | 56590.33 | 48 | 342 | 175 | 54 | 31.1 | 228143 | 228143 | 0 | 0 | 0 | 0 | 45629 |
| run | 37864 | 12173.31 | 37322.75 | 53018.62 | 68747.26 | 43 | 332 | 146 | 44 | 28.3 | 189321 | 189321 | 0 | 0 | 0 | 0 | 37864 |
| **median** | 39400 | 12132.35 | 31948.80 | 43581.44 | 54034.43 | 43 | 324 | 172 | 54 | 31.6 | 197001 | 197001 | 0 | 0 | 0 | 0 | 39400 |

- Без affinity: все потоки могут мигрировать по всем CPU.

### iso-udp-a

UDP, A-only, closed-loop окно 64: лучший путь (positive hit).

| Прогон | Клиент qps | p50 µs | p99 µs | p999 µs | max µs | cl user% | cl sys% | srv user% | srv sys% | srv RSS MiB | sent | recv | timeout | invalid | suppressed | rcvbuf Δ | server qps |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| run | 35191 | 12271.61 | 46071.81 | 61145.09 | 76808.19 | 29 | 211 | 130 | 38 | 32.7 | 175956 | 175956 | 0 | 0 | 0 | 0 | 35191 |
| **median** | 36240 | 10452.99 | 37322.75 | 48037.89 | 56557.57 | 36 | 252 | 121 | 35 | 28.0 | 181394 | 181202 | 192 | 0 | 0 | 0 | 36241 |
| run | 39804 | 8130.56 | 39223.29 | 49971.20 | 70189.05 | 31 | 242 | 134 | 38 | 32.4 | 199210 | 199018 | 192 | 0 | 0 | 0 | 39804 |

- Сервер/клиент на разных физических ядрах (см. раздел «CPU-раскладка»).

### shared-udp-mix

UDP, mix A/AAAA/MX/TXT/NXDOMAIN, closed-loop окно 64. (контроль: сервер и клиент на общем наборе CPU).

| Прогон | Клиент qps | p50 µs | p99 µs | p999 µs | max µs | cl user% | cl sys% | srv user% | srv sys% | srv RSS MiB | sent | recv | timeout | invalid | suppressed | rcvbuf Δ | server qps |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **median** | 23893 | 15671.30 | 118489.09 | 161873.92 | 227672.06 | 31 | 231 | 169 | 25 | 30.8 | 119467 | 119467 | 0 | 0 | 0 | 0 | 23894 |
| run | 21061 | 17039.36 | 71434.24 | 113311.74 | 123928.57 | 34 | 251 | 160 | 24 | 31.9 | 105494 | 105305 | 189 | 0 | 0 | 0 | 21061 |
| run | 31273 | 14581.76 | 41287.68 | 61767.68 | 80478.21 | 46 | 341 | 248 | 35 | 31.2 | 156363 | 156363 | 0 | 0 | 0 | 0 | 31273 |

- Без affinity: все потоки могут мигрировать по всем CPU.

### iso-udp-mix

UDP, mix A/AAAA/MX/TXT/NXDOMAIN, closed-loop окно 64.

| Прогон | Клиент qps | p50 µs | p99 µs | p999 µs | max µs | cl user% | cl sys% | srv user% | srv sys% | srv RSS MiB | sent | recv | timeout | invalid | suppressed | rcvbuf Δ | server qps |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| run | 30953 | 13426.69 | 55246.85 | 77660.16 | 106102.78 | 40 | 304 | 255 | 34 | 30.3 | 154766 | 154766 | 0 | 0 | 0 | 0 | 30953 |
| **median** | 29177 | 14458.88 | 58490.88 | 83689.47 | 95748.10 | 33 | 247 | 202 | 27 | 30.2 | 145883 | 145883 | 0 | 0 | 0 | 0 | 29177 |
| run | 25632 | 16482.30 | 59047.93 | 82247.68 | 94044.16 | 42 | 301 | 241 | 33 | 31.9 | 128161 | 128161 | 0 | 0 | 0 | 0 | 25632 |

### shared-udp-nx

UDP, 100% NXDOMAIN, closed-loop окно 64: худший путь перебора суффиксов. (контроль: сервер и клиент на общем наборе CPU).

| Прогон | Клиент qps | p50 µs | p99 µs | p999 µs | max µs | cl user% | cl sys% | srv user% | srv sys% | srv RSS MiB | sent | recv | timeout | invalid | suppressed | rcvbuf Δ | server qps |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| run | 7607 | 56262.65 | 220987.39 | 407633.92 | 408158.21 | 52 | 359 | 223 | 8 | 22.0 | 38033 | 38033 | 0 | 0 | 0 | 0 | 7607 |
| **median** | 7544 | 57212.93 | 227803.14 | 370671.61 | 371982.34 | 47 | 369 | 218 | 8 | 22.0 | 37722 | 37722 | 0 | 0 | 0 | 0 | 7545 |
| run | 5927 | 33882.11 | 312999.93 | 436207.61 | 436469.76 | 43 | 296 | 168 | 6 | 22.0 | 29942 | 29635 | 307 | 0 | 0 | 0 | 5927 |

- Без affinity: все потоки могут мигрировать по всем CPU.

### iso-udp-nx

UDP, 100% NXDOMAIN, closed-loop окно 64: худший путь перебора суффиксов.

| Прогон | Клиент qps | p50 µs | p99 µs | p999 µs | max µs | cl user% | cl sys% | srv user% | srv sys% | srv RSS MiB | sent | recv | timeout | invalid | suppressed | rcvbuf Δ | server qps |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **median** | 7384 | 60063.74 | 208273.41 | 244842.49 | 327417.85 | 40 | 314 | 254 | 9 | 21.8 | 36920 | 36920 | 0 | 0 | 0 | 0 | 7384 |
| run | 3766 | 107347.97 | 448528.38 | 553648.13 | 571473.92 | 32 | 228 | 173 | 6 | 21.8 | 18829 | 18829 | 0 | 0 | 0 | 0 | 3766 |
| run | 7662 | 51838.97 | 282329.09 | 361758.72 | 362807.29 | 42 | 308 | 251 | 8 | 22.0 | 38310 | 38310 | 0 | 0 | 0 | 0 | 7662 |

### shared-udp-signed

UDP, DNSSEC-подписанная зона (EDNS DO=1), mix, closed-loop окно 64. (контроль: сервер и клиент на общем наборе CPU).

| Прогон | Клиент qps | p50 µs | p99 µs | p999 µs | max µs | cl user% | cl sys% | srv user% | srv sys% | srv RSS MiB | sent | recv | timeout | invalid | suppressed | rcvbuf Δ | server qps |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **median** | 35133 | 11591.68 | 50790.40 | 75431.93 | 93847.55 | 42 | 300 | 129 | 23 | 29.6 | 175666 | 175666 | 0 | 0 | 0 | 0 | 35133 |
| run | 33895 | 9445.38 | 59670.53 | 109314.05 | 131792.89 | 38 | 300 | 171 | 32 | 31.8 | 169666 | 169474 | 192 | 0 | 0 | 0 | 33895 |
| run | 36148 | 7233.53 | 47120.38 | 148635.65 | 184942.59 | 36 | 262 | 156 | 29 | 32.0 | 180932 | 180740 | 192 | 0 | 0 | 0 | 36148 |

- Без affinity: все потоки могут мигрировать по всем CPU.

### iso-udp-signed

UDP, DNSSEC-подписанная зона (EDNS DO=1), mix, closed-loop окно 64.

| Прогон | Клиент qps | p50 µs | p99 µs | p999 µs | max µs | cl user% | cl sys% | srv user% | srv sys% | srv RSS MiB | sent | recv | timeout | invalid | suppressed | rcvbuf Δ | server qps |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| run | 43381 | 7589.89 | 58687.49 | 109641.73 | 130220.03 | 39 | 285 | 257 | 44 | 31.8 | 216905 | 216905 | 0 | 0 | 0 | 0 | 43381 |
| run | 25215 | 13680.64 | 121176.06 | 248250.37 | 336592.90 | 40 | 289 | 192 | 33 | 32.0 | 126077 | 126077 | 0 | 0 | 0 | 0 | 25216 |
| **median** | 39543 | 9584.64 | 57409.54 | 77463.55 | 88866.82 | 34 | 262 | 215 | 38 | 31.8 | 197713 | 197713 | 0 | 0 | 0 | 0 | 39543 |

- Зона `z0.bench.test.` подписывается `pulsed` при загрузке (CSK Ed25519); клиент шлёт EDNS0 с DO=1.

### shared-tcp

TCP, 8 соединений, closed-loop окно 16 (length-prefix). (контроль: сервер и клиент на общем наборе CPU).

| Прогон | Клиент qps | p50 µs | p99 µs | p999 µs | max µs | cl user% | cl sys% | srv user% | srv sys% | srv RSS MiB | sent | recv | timeout | invalid | suppressed | rcvbuf Δ | server qps |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **median** | 28717 | 2205.70 | 7733.25 | 10944.51 | 16506.88 | 10 | 106 | 284 | 126 | 22.9 | 143584 | 143584 | 0 | 0 | 0 | 0 | 28717 |
| run | 28742 | 2160.64 | 8376.32 | 11698.17 | 17498.11 | 9 | 103 | 284 | 126 | 22.7 | 143712 | 143712 | 0 | 0 | 0 | 0 | 28743 |
| run | 27709 | 2275.33 | 8273.92 | 12115.97 | 20447.23 | 10 | 102 | 277 | 123 | 22.7 | 138544 | 138544 | 0 | 0 | 0 | 0 | 27709 |

- Без affinity: все потоки могут мигрировать по всем CPU.

### iso-tcp

TCP, 8 соединений, closed-loop окно 16 (length-prefix).

| Прогон | Клиент qps | p50 µs | p99 µs | p999 µs | max µs | cl user% | cl sys% | srv user% | srv sys% | srv RSS MiB | sent | recv | timeout | invalid | suppressed | rcvbuf Δ | server qps |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| run | 29110 | 2396.16 | 7077.89 | 11894.78 | 33619.97 | 9 | 122 | 278 | 108 | 22.2 | 145552 | 145552 | 0 | 0 | 0 | 0 | 29111 |
| **median** | 28360 | 2445.31 | 7520.26 | 13803.52 | 23101.44 | 8 | 120 | 274 | 106 | 21.8 | 141801 | 141801 | 0 | 0 | 0 | 0 | 28360 |
| run | 27472 | 2521.09 | 7835.65 | 12951.55 | 25542.65 | 9 | 117 | 262 | 108 | 22.4 | 137358 | 137358 | 0 | 0 | 0 | 0 | 27472 |

### shared-doh-h2

DoH/HTTP/2, 8 соединений × 16 stream'ов, closed-loop. (контроль: сервер и клиент на общем наборе CPU).

| Прогон | Клиент qps | p50 µs | p99 µs | p999 µs | max µs | cl user% | cl sys% | srv user% | srv sys% | srv RSS MiB | sent | recv | timeout | invalid | suppressed | rcvbuf Δ | server qps |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| run | 11421 | 10477.57 | 18481.15 | 22233.09 | 30474.24 | 33 | 50 | 160 | 34 | 23.9 | 57104 | 57104 | 0 | 0 | 0 | 0 | 11421 |
| **median** | 11110 | 10649.60 | 19316.74 | 23609.34 | 30261.25 | 33 | 50 | 160 | 34 | 24.2 | 55552 | 55552 | 0 | 0 | 0 | 0 | 11111 |
| run | 10890 | 10813.44 | 20103.17 | 23461.89 | 24723.46 | 32 | 49 | 160 | 35 | 24.0 | 54448 | 54448 | 0 | 0 | 0 | 0 | 10890 |

- Без affinity: все потоки могут мигрировать по всем CPU.

### iso-doh-h2

DoH/HTTP/2, 8 соединений × 16 stream'ов, closed-loop.

| Прогон | Клиент qps | p50 µs | p99 µs | p999 µs | max µs | cl user% | cl sys% | srv user% | srv sys% | srv RSS MiB | sent | recv | timeout | invalid | suppressed | rcvbuf Δ | server qps |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| run | 11629 | 10272.77 | 17711.10 | 20496.38 | 21315.58 | 27 | 50 | 165 | 33 | 24.4 | 58144 | 58144 | 0 | 0 | 0 | 0 | 11629 |
| run | 10752 | 11255.81 | 18825.22 | 22642.69 | 25853.95 | 25 | 48 | 164 | 32 | 23.9 | 53760 | 53760 | 0 | 0 | 0 | 0 | 10752 |
| **median** | 11082 | 10985.47 | 17530.88 | 19791.87 | 22577.15 | 26 | 49 | 165 | 32 | 24.4 | 55408 | 55408 | 0 | 0 | 0 | 0 | 11082 |

### shared-udp-rest

UDP 10k qps + REST PUT в 8 зон; клиентские роли DNS/REST разведены по CPU. (контроль: сервер и клиент на общем наборе CPU).

| Прогон | Клиент qps | p50 µs | p99 µs | p999 µs | max µs | cl user% | cl sys% | srv user% | srv sys% | srv RSS MiB | sent | recv | timeout | invalid | suppressed | rcvbuf Δ | server qps |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| run | 8878 | 355.07 | 4358.14 | 11665.41 | 16875.52 | 8 | 64 | 156 | 38 | 42.4 | 44392 | 44392 | 0 | 0 | 0 | 0 | 8879 |
| run | 9770 | 355.84 | 2379.78 | 15040.51 | 23068.67 | 8 | 62 | 194 | 43 | 42.1 | 48849 | 48849 | 0 | 0 | 0 | 0 | 9770 |
| **median** | 9533 | 356.86 | 7979.01 | 20594.69 | 34406.40 | 8 | 57 | 188 | 40 | 38.8 | 47664 | 47664 | 0 | 0 | 0 | 0 | 9533 |

- Без affinity: все потоки могут мигрировать по всем CPU.

### iso-udp-rest

UDP 10k qps + REST PUT в 8 зон; клиентские роли DNS/REST разведены по CPU.

| Прогон | Клиент qps | p50 µs | p99 µs | p999 µs | max µs | cl user% | cl sys% | srv user% | srv sys% | srv RSS MiB | sent | recv | timeout | invalid | suppressed | rcvbuf Δ | server qps |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **median** | 9487 | 361.21 | 3577.86 | 5558.27 | 7634.94 | 8 | 59 | 183 | 35 | 36.7 | 47433 | 47433 | 0 | 0 | 0 | 0 | 9487 |
| run | 9638 | 368.13 | 7585.79 | 11542.53 | 14041.09 | 9 | 58 | 175 | 36 | 39.8 | 48189 | 48189 | 0 | 0 | 0 | 0 | 9638 |
| run | 9219 | 388.35 | 4608.00 | 8577.02 | 11444.22 | 8 | 57 | 136 | 37 | 44.2 | 46094 | 46094 | 0 | 0 | 0 | 0 | 9219 |

- DNS-клиент — первая половина `--client-cpus`, REST-писатели — вторая (или `--rest-cpus`). API `pulsed` живёт в том же процессе, что DNS.

## Профиль

### iso-udp-a (5s, udp)

| Счётчик | Значение |
|---|---|
| `L1-dcache-load-misses` | 213006505.000 |
| `L1-dcache-loads` | 10023054888.000 |
| `branch-misses` | 99249204.000 |
| `branches` | 6142628962.000 |
| `cache-miss-pct` | 17.086 |
| `cache-misses` | 103360718.000 |
| `cache-references` | 604930244.000 |
| `context-switches` | 0.000 |
| `cpu-migrations` | 0.000 |
| `cycles` | 21846089285.000 |
| `dTLB-load-misses` | 5978028.000 |
| `dTLB-loads` | 33106129.000 |
| `dtlb-miss-pct` | 18.057 |
| `iTLB-load-misses` | 2777523.000 |
| `instructions` | 26723238072.000 |
| `ipc` | 1.223 |
| `page-faults` | 4181.000 |
| `seconds` | 2.349 |

| Функция | % |
|---|---|
| `<pulse_zonefile::key::Key>::rebuild` | 14.68 |
| `pulse_zonefile::key::compare_raw_to_key_len` | 7.78 |
| `pulse_zonefile::key::compare_validated` | 7.26 |
| `<pulse_zonefile::node::NodeRef>::bound_by_order` | 7.00 |
| `<pulse_zonefile::key::OrderKey>::of_key` | 5.35 |
| `<pulse_zonefile::node::RawNode>::validate_leaf_items` | 4.31 |
| `memcpy` | 4.25 |
| `<pulse_zonefile::node::RawNode>::next_key` | 3.83 |
| `0x00000000001b1b62` | 2.46 |
| `crc32c::hw_x86_64::crc_u64_parallel3` | 2.32 |
| `<pulse_zonefile::cache::PageCache>::lookup_entry` | 2.03 |
| `0x00000000001b1b2e` | 1.84 |
| `0000000000000000` | 1.70 |
| `<pulse_zonefile::parallel::pagecache::PageCacheV2>::get` | 1.69 |
| `<io_uring::types::RecvMsgOut>::parse` | 1.25 |
| `<pulse_zonefile::cache::PageCache>::get::<pulse_zonefile::parallel::pageio::ReaderIo>` | 1.06 |
| `0x00000000001b240e` | 0.93 |
| `0x00000000001b1ab4` | 0.90 |
| `<pulse_zonefile::key::NameRle>::from_wire` | 0.87 |
| `0x00000000001b1af1` | 0.86 |
| `<pulse_zonefile::node::NodeRef>::upper_bound` | 0.82 |
| `0x00000000001b242e` | 0.77 |
| `0x00000000001b1b29` | 0.75 |
| `0x00000000001b2404` | 0.73 |
| `0x00000000001b1af7` | 0.66 |

Flamegraph: `target/bench/flamegraph-iso-udp-a.svg`

perf stat: perf — parent, сервер — child (ptrace_scope=1). Клиент: 27513 qps, p99 47153.2 µs. user-space cycles: paranoid=2. perf record (без call-graph (paranoid=2 запрещает dwarf/fp)): 24977 qps, p99 56852.5 µs.

### iso-udp-mix (5s, udp)

| Счётчик | Значение |
|---|---|
| `L1-dcache-load-misses` | 213733623.000 |
| `L1-dcache-loads` | 12552172907.000 |
| `branch-misses` | 49852255.000 |
| `branches` | 7549941380.000 |
| `cache-miss-pct` | 15.336 |
| `cache-misses` | 76419488.000 |
| `cache-references` | 498294511.000 |
| `context-switches` | 0.000 |
| `cpu-migrations` | 0.000 |
| `cycles` | 23126901568.000 |
| `dTLB-load-misses` | 3715698.000 |
| `dTLB-loads` | 19430419.000 |
| `dtlb-miss-pct` | 19.123 |
| `iTLB-load-misses` | 1178546.000 |
| `instructions` | 32811702767.000 |
| `ipc` | 1.419 |
| `page-faults` | 4038.000 |
| `seconds` | 1.412 |

| Функция | % |
|---|---|
| `<pulse_zonefile::key::Key>::rebuild` | 18.35 |
| `pulse_zonefile::key::compare_validated` | 12.57 |
| `memcpy` | 6.91 |
| `<pulse_zonefile::node::RawNode>::validate_leaf_items` | 4.06 |
| `pulse_zonefile::key::compare_raw_to_key_len` | 4.06 |
| `<pulse_zonefile::node::RawNode>::next_key` | 3.94 |
| `<pulse_zonefile::node::NodeRef>::bound_by_order` | 2.98 |
| `crc32c::hw_x86_64::crc_u64_parallel3` | 2.84 |
| `<pulse_zonefile::node::RawNode>::validate_branch_items` | 2.77 |
| `<pulse_zonefile::key::OrderKey>::of_key` | 2.00 |
| `0x00000000001b1b0a` | 1.87 |
| `0x00000000001b1b62` | 1.87 |
| `<pulse_zonefile::cache::PageCache>::lookup_entry` | 1.56 |
| `<pulse_zonefile::cache::PageCache>::get::<pulse_zonefile::parallel::pageio::ReaderIo>` | 1.54 |
| `0000000000000000` | 1.47 |
| `0x00000000001b1b24` | 1.41 |
| `0x00000000001b242e` | 1.10 |
| `0x00000000001b1b29` | 0.95 |
| `0x00000000001b1b6d` | 0.94 |
| `<pulse_zonefile::node::RawNode>::decode` | 0.94 |
| `0x00000000001b240e` | 0.84 |
| `0x00000000001b1b33` | 0.82 |
| `0x00000000001b2380` | 0.78 |
| `<pulse_zonefile::parallel::pagecache::PageCacheV2>::get` | 0.69 |
| `0x00000000001b1b2e` | 0.66 |

Flamegraph: `target/bench/flamegraph-iso-udp-mix.svg`

perf stat: perf — parent, сервер — child (ptrace_scope=1). Клиент: 13357 qps, p99 129171.5 µs. user-space cycles: paranoid=2. perf record (без call-graph (paranoid=2 запрещает dwarf/fp)): 14576 qps, p99 92930.0 µs.

### iso-udp-nx (5s, udp)

| Счётчик | Значение |
|---|---|
| `L1-dcache-load-misses` | 242309411.000 |
| `L1-dcache-loads` | 17265026762.000 |
| `branch-misses` | 48021501.000 |
| `branches` | 10283431647.000 |
| `cache-miss-pct` | 11.400 |
| `cache-misses` | 50935724.000 |
| `cache-references` | 446788112.000 |
| `context-switches` | 0.000 |
| `cpu-migrations` | 0.000 |
| `cycles` | 29077042816.000 |
| `dTLB-load-misses` | 1607550.000 |
| `dTLB-loads` | 6844724.000 |
| `dtlb-miss-pct` | 23.486 |
| `iTLB-load-misses` | 1268195.000 |
| `instructions` | 44417125879.000 |
| `ipc` | 1.528 |
| `page-faults` | 1563.000 |
| `seconds` | 0.585 |

| Функция | % |
|---|---|
| `<pulse_zonefile::key::Key>::rebuild` | 20.90 |
| `pulse_zonefile::key::compare_validated` | 17.63 |
| `memcpy` | 9.43 |
| `<pulse_zonefile::node::RawNode>::next_key` | 5.13 |
| `<pulse_zonefile::node::RawNode>::validate_branch_items` | 5.05 |
| `<pulse_zonefile::node::RawNode>::validate_leaf_items` | 4.19 |
| `crc32c::hw_x86_64::crc_u64_parallel3` | 2.62 |
| `0x00000000001b1b24` | 1.80 |
| `0x00000000001b242e` | 1.59 |
| `0x00000000001b1b62` | 1.44 |
| `0x00000000001b1af1` | 1.30 |
| `0x00000000001b1b6d` | 1.14 |
| `0x00000000001b1b2e` | 1.11 |
| `0x00000000001b240e` | 1.06 |
| `0x00000000001b1b0a` | 1.03 |
| `pulse_zonefile::key::prefix_cmp` | 1.02 |
| `<pulse_zonefile::node::RawNode>::decode` | 1.00 |
| `0x00000000001b1b33` | 0.91 |
| `0x00000000001b1b29` | 0.87 |
| `0x00000000001b1b45` | 0.86 |
| `0x00000000001b1b6a` | 0.85 |
| `0x00000000001b1acb` | 0.77 |
| `0x00000000001b1af7` | 0.69 |
| `0x00000000001b1b4a` | 0.69 |
| `0x00000000001b1b66` | 0.64 |

Flamegraph: `target/bench/flamegraph-iso-udp-nx.svg`

perf stat: perf — parent, сервер — child (ptrace_scope=1). Клиент: 5093 qps, p99 360185.9 µs. user-space cycles: paranoid=2. perf record (без call-graph (paranoid=2 запрещает dwarf/fp)): 5240 qps, p99 329777.2 µs.

### iso-udp-signed (5s, udp)

| Счётчик | Значение |
|---|---|
| `L1-dcache-load-misses` | 307303126.000 |
| `L1-dcache-loads` | 15325374555.000 |
| `branch-misses` | 68469346.000 |
| `branches` | 8768353759.000 |
| `cache-miss-pct` | 10.940 |
| `cache-misses` | 79243789.000 |
| `cache-references` | 724326696.000 |
| `context-switches` | 0.000 |
| `cpu-migrations` | 0.000 |
| `cycles` | 27959129046.000 |
| `dTLB-load-misses` | 3602013.000 |
| `dTLB-loads` | 28279177.000 |
| `dtlb-miss-pct` | 12.737 |
| `iTLB-load-misses` | 1901663.000 |
| `instructions` | 39327540077.000 |
| `ipc` | 1.407 |
| `page-faults` | 4564.000 |
| `seconds` | 1.994 |

| Функция | % |
|---|---|
| `<pulse_zonefile::key::Key>::rebuild` | 14.59 |
| `pulse_zonefile::key::compare_validated` | 11.15 |
| `<pulse_zonefile::node::NodeRef>::bound_by_order` | 7.30 |
| `pulse_zonefile::key::compare_raw_to_key_len` | 6.88 |
| `memcpy` | 6.61 |
| `<pulse_zonefile::node::RawNode>::next_key` | 3.18 |
| `<pulse_zonefile::node::RawNode>::validate_leaf_items` | 2.85 |
| `<pulse_zonefile::node::RawNode>::validate_branch_items` | 2.80 |
| `<pulse_dns::domain::name::NameRef>::cmp_canonical` | 2.38 |
| `<pulse_zonefile::cache::PageCache>::lookup_entry` | 1.88 |
| `crc32c::hw_x86_64::crc_u64_parallel3` | 1.63 |
| `0x00000000001b1b62` | 1.41 |
| `0x00000000001b240e` | 1.15 |
| `<pulse_zonefile::node::RawNode>::decode` | 1.07 |
| `<pulse_zonefile::cache::PageCache>::get::<pulse_zonefile::parallel::pageio::ReaderIo>` | 1.07 |
| `0x00000000001b1b24` | 1.05 |
| `<pulse_zonefile::key::NameRle>::from_wire` | 1.04 |
| `<pulse_zonefile::key::OrderKey>::of_key` | 1.02 |
| `0x00000000001b1b45` | 0.91 |
| `<pulse_zonefile::tree::ZoneTree>::lookup_cached::<pulse_zonefile::parallel::pageio::ReaderIo>` | 0.90 |
| `0x00000000001b242e` | 0.83 |
| `0x00000000001b1b33` | 0.81 |
| `0000000000000000` | 0.77 |
| `0x00000000001b1b29` | 0.77 |
| `0x00000000001b1af1` | 0.73 |

Flamegraph: `target/bench/flamegraph-iso-udp-signed.svg`

perf stat: perf — parent, сервер — child (ptrace_scope=1). Клиент: 25586 qps, p99 73662.5 µs. user-space cycles: paranoid=2. perf record (без call-graph (paranoid=2 запрещает dwarf/fp)): 33106 qps, p99 64913.4 µs.

### iso-tcp (5s, tcp)

| Счётчик | Значение |
|---|---|
| `L1-dcache-load-misses` | 414947418.000 |
| `L1-dcache-loads` | 24359839418.000 |
| `branch-misses` | 107890970.000 |
| `branches` | 14348395511.000 |
| `cache-miss-pct` | 20.925 |
| `cache-misses` | 234424777.000 |
| `cache-references` | 1120306100.000 |
| `context-switches` | 0.000 |
| `cpu-migrations` | 0.000 |
| `cycles` | 44653985625.000 |
| `dTLB-load-misses` | 6657723.000 |
| `dTLB-loads` | 44325223.000 |
| `dtlb-miss-pct` | 15.020 |
| `iTLB-load-misses` | 3422250.000 |
| `instructions` | 62836803197.000 |
| `ipc` | 1.407 |
| `page-faults` | 4214.000 |
| `seconds` | 6.608 |

| Функция | % |
|---|---|
| `<pulse_zonefile::key::Key>::rebuild` | 17.58 |
| `pulse_zonefile::key::compare_validated` | 13.30 |
| `memcpy` | 5.52 |
| `<pulse_zonefile::node::RawNode>::next_key` | 4.07 |
| `pulse_zonefile::key::compare_raw_to_key_len` | 3.82 |
| `<pulse_zonefile::node::RawNode>::validate_leaf_items` | 3.56 |
| `<pulse_zonefile::node::NodeRef>::bound_by_order` | 3.28 |
| `0x00000000001b1b62` | 3.09 |
| `crc32c::hw_x86_64::crc_u64_parallel3` | 2.84 |
| `<pulse_zonefile::node::RawNode>::validate_branch_items` | 2.37 |
| `<pulse_zonefile::key::OrderKey>::of_key` | 2.09 |
| `0x00000000001b1b24` | 1.81 |
| `0x00000000001b1af1` | 1.48 |
| `0000000000000000` | 1.41 |
| `0x00000000001b240e` | 1.13 |
| `<pulse_zonefile::cache::PageCache>::lookup_entry` | 1.07 |
| `0x00000000001b1b45` | 1.00 |
| `0x00000000001b1b2e` | 0.92 |
| `0x00000000001b242e` | 0.90 |
| `0x00000000001b1b29` | 0.82 |
| `0x00000000001b1b6d` | 0.74 |
| `0x00000000001b1b04` | 0.72 |
| `0x00000000001b2380` | 0.70 |
| `0x00000000001b2404` | 0.70 |
| `0x00000000001b1b33` | 0.68 |

Flamegraph: `target/bench/flamegraph-iso-tcp.svg`

perf stat: perf — parent, сервер — child (ptrace_scope=1). Клиент: 26832 qps, p99 7839.7 µs. user-space cycles: paranoid=2. perf record (без call-graph (paranoid=2 запрещает dwarf/fp)): 28055 qps, p99 7417.9 µs.

### iso-doh-h2 (5s, doh-h2)

| Счётчик | Значение |
|---|---|
| `L1-dcache-load-misses` | 302723344.000 |
| `L1-dcache-loads` | 14421847935.000 |
| `branch-misses` | 142259047.000 |
| `branches` | 7360602022.000 |
| `cache-miss-pct` | 40.885 |
| `cache-misses` | 562940194.000 |
| `cache-references` | 1376877692.000 |
| `context-switches` | 0.000 |
| `cpu-migrations` | 0.000 |
| `cycles` | 27849501816.000 |
| `dTLB-load-misses` | 5820934.000 |
| `dTLB-loads` | 51315412.000 |
| `dtlb-miss-pct` | 11.343 |
| `iTLB-load-misses` | 5610009.000 |
| `instructions` | 33836959527.000 |
| `ipc` | 1.215 |
| `page-faults` | 3794.000 |
| `seconds` | 2.042 |

| Функция | % |
|---|---|
| `<pulse_zonefile::key::Key>::rebuild` | 11.78 |
| `pulse_zonefile::key::compare_validated` | 9.54 |
| `memcpy` | 6.17 |
| `<pulse_zonefile::node::RawNode>::validate_leaf_items` | 3.98 |
| `<pulse_zonefile::node::RawNode>::validate_branch_items` | 2.17 |
| `0x00000000001b1b24` | 2.09 |
| `<pulse_zonefile::node::NodeRef>::bound_by_order` | 1.95 |
| `crc32c::hw_x86_64::crc_u64_parallel3` | 1.79 |
| `<pulse_zonefile::node::RawNode>::next_key` | 1.77 |
| `pulse_zonefile::key::compare_raw_to_key_len` | 1.64 |
| `0x00000000001b1b62` | 1.60 |
| `<pulse_zonefile::cache::PageCache>::lookup_entry` | 1.52 |
| `malloc` | 1.29 |
| `<pulse_zonefile::parallel::pagecache::PageCacheV2>::get` | 1.13 |
| `0x00000000001b242e` | 0.98 |
| `0x00000000001b240e` | 0.88 |
| `0000000000000000` | 0.82 |
| `0x00000000001b1b58` | 0.81 |
| `0000000000000000` | 0.78 |
| `0x00000000001b1b6a` | 0.76 |
| `0x00000000001b1b45` | 0.76 |
| `<pulse_zonefile::key::OrderKey>::of_key` | 0.75 |
| `cfree` | 0.67 |
| `0x00000000001b2404` | 0.56 |
| `0x00000000001b1af1` | 0.56 |

Flamegraph: `target/bench/flamegraph-iso-doh-h2.svg`

perf stat: perf — parent, сервер — child (ptrace_scope=1). Клиент: 10954 qps, p99 19202.0 µs. user-space cycles: paranoid=2. perf record (без call-graph (paranoid=2 запрещает dwarf/fp)): 11760 qps, p99 18546.7 µs.

### iso-udp-rest (5s, udp)

| Счётчик | Значение |
|---|---|
| `L1-dcache-load-misses` | 88035168.000 |
| `L1-dcache-loads` | 3675351595.000 |
| `branch-misses` | 27014690.000 |
| `branches` | 1981455714.000 |
| `cache-miss-pct` | 32.638 |
| `cache-misses` | 88312677.000 |
| `cache-references` | 270581452.000 |
| `context-switches` | 0.000 |
| `cpu-migrations` | 0.000 |
| `cycles` | 6592672499.000 |
| `dTLB-load-misses` | 1607572.000 |
| `dTLB-loads` | 8158277.000 |
| `dtlb-miss-pct` | 19.705 |
| `iTLB-load-misses` | 1020821.000 |
| `instructions` | 8991797618.000 |
| `ipc` | 1.364 |
| `page-faults` | 1872.000 |
| `seconds` | 1.849 |

| Функция | % |
|---|---|
| `pulse_zonefile::key::compare_validated` | 9.03 |
| `<pulse_zonefile::key::Key>::rebuild` | 7.60 |
| `<pulse_zonefile::node::NodeRef>::bound_by_order` | 6.71 |
| `memcpy` | 4.97 |
| `pulse_zonefile::key::compare_raw_to_key_len` | 4.63 |
| `<pulse_zonefile::node::RawNode>::next_key` | 4.32 |
| `<pulse_server::application::query::QueryEngine>::respond_ref_into::{closure#2}` | 4.29 |
| `0x00000000001b1b62` | 3.83 |
| `<pulse_zonefile::node::RawNode>::validate_leaf_items` | 3.46 |
| `crc32c::hw_x86_64::crc_u64_parallel3` | 2.60 |
| `malloc` | 2.30 |
| `0x00000000001b242e` | 2.24 |
| `0000000000000000` | 1.96 |
| `0x00000000001b23e8` | 1.93 |
| `<pulse_zonefile::cache::PageCache>::lookup_entry` | 1.72 |
| `0x00000000001b1b4a` | 1.70 |
| `<pulse_zonefile::parallel::store::ParallelStore>::reader` | 1.55 |
| `<pulse_zonefile::parallel::pagecache::PageCacheV2>::get` | 1.44 |
| `<pulse_zonefile::key::NameRle>::from_wire` | 1.41 |
| `0x00000000001b1b37` | 1.20 |
| `0x00000000001b2404` | 1.15 |
| `0x00000000001b1b6d` | 1.12 |
| `0x00000000001b240e` | 1.02 |
| `0x00000000001b1b2e` | 1.01 |
| `0x00000000001b1b24` | 1.00 |

Flamegraph: `target/bench/flamegraph-iso-udp-rest.svg`

perf stat: perf — parent, сервер — child (ptrace_scope=1). Клиент: 9736 qps, p99 1758.2 µs. user-space cycles: paranoid=2. perf record (без call-graph (paranoid=2 запрещает dwarf/fp)): 9618 qps, p99 1247.2 µs.

## Методика и CPU-раскладка

| Роль | CPU |
|---|---|
| Сервер (`taskset`) | `0-3` |
| Клиент DNS (`sched_setaffinity`) | `4-7` |
| REST-писатели | `6-7` |

SMT-группы (одно физическое ядро): `core0: 0-1, core1: 2-3, core2: 4-5, core3: 6-7`.

Авто-раскладка: сервер — целые физические ядра 0-3, клиент — 4-7. Каждая сторона владеет всеми SMT-сиблингами своих ядер. Раскладка вида 0,2,4,6/1,3,5,7 оставляет сиблингов в разных ролях и не изолирует ядро.; allowed: 0-7, server: 0-3, client: 4-7; topology: core0: 0-1, core1: 2-3, core2: 4-5, core3: 6-7

**Методика.** Сервер запускается как `taskset -c <server> pulsed`; каждый клиентский поток в первой инструкции вызывает `sched_setaffinity(0, <один CPU>)` (round-robin по `--client-cpus`). Наборы проверяются на непустоту, вхождение в `Cpus_allowed_list` и непересечение; фактический affinity сервера сверяется по `/proc/<pid>/status` после `exec`. В `iso-udp-rest` DNS-клиент занимает первую половину клиентских CPU, REST-писатели — вторую. 3 прогона, в таблицу идёт медиана по клиентскому qps; латентность — HDR (3 значащие цифры), клиентская, `CLOCK_MONOTONIC` вокруг send/recv. `shared-*` — тот же сценарий без affinity, запускается сразу после `iso-*`, чтобы дрейф нагрузки хоста меньше влиял на сравнение.

`perf_event_paranoid=2`: `perf stat` (cycles/instructions/cache/TLB) доступен; `perf record -e cycles:u` без call-graph тоже доступен, но `--call-graph dwarf` и `-g` при paranoid=2 **запрещены** (`Failure to open event`). Harness пробует dwarf и откатывается на плоский `cycles:u`; flamegraph тогда без стеков, hotspots — по символам. Для dwarf-стеков нужен `CAP_PERFMON` или paranoid≤1.

**SMT-сиблинги** (из `/sys/devices/system/cpu/cpu*/topology/thread_siblings_list`): все `cpuN` внутри одной группы — одно физическое ядро. Рекомендуемая раскладка — целые ядра: `server=0-3`, `client=4-7` (используется здесь). Если серверу хватает двух логических CPU, более строгий вариант — `server=0,2`, `client=4,6`, а сиблинги `1,3,5,7` оставить idle. Раскладка `0,2,4,6` / `1,3,5,7` **не является изоляцией**: каждая пара CPU — сиблинги одного ядра, и сервер конкурирует с клиентом за SMT-порты.

**Ограничения.** Один хост, loopback; 4 физических ядра / 8 SMT-потоков (Ryzen 5 3500U), SMT и turbo не отключались, governor не менялся. На хосте параллельно работали другие процессы (см. `loadavg` ниже), поэтому абсолютные qps/p99 — нижняя оценка, а сравнение `iso`/`shared` валидно только в пределах этого прогона. UDP-сценарии `iso-udp-*` — closed-loop окно 64: p50/p99 включают очередь в клиентском сокете, это метрика насыщения, а не service time.


## Isolated vs loopback-общий

| Сценарий | iso qps | shared qps | Δ qps | iso p50 µs | shared p50 µs | iso p99 µs | shared p99 µs | iso p999 µs | iso srv user/sys % | shared srv user/sys % | iso RSS MiB | shared RSS MiB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| iso-udp-a | 36240 | 39400 | -8.0% | 10452.99 | 12132.35 | 37322.75 | 31948.80 | 48037.89 | 121/35 | 172/54 | 28.0 | 31.6 |
| iso-udp-mix | 29177 | 23893 | +22.1% | 14458.88 | 15671.30 | 58490.88 | 118489.09 | 83689.47 | 202/27 | 169/25 | 30.2 | 30.8 |
| iso-udp-nx | 7384 | 7544 | -2.1% | 60063.74 | 57212.93 | 208273.41 | 227803.14 | 244842.49 | 254/9 | 218/8 | 21.8 | 22.0 |
| iso-udp-signed | 39543 | 35133 | +12.6% | 9584.64 | 11591.68 | 57409.54 | 50790.40 | 77463.55 | 215/38 | 129/23 | 31.8 | 29.6 |
| iso-tcp | 28360 | 28717 | -1.2% | 2445.31 | 2205.70 | 7520.26 | 7733.25 | 13803.52 | 274/106 | 284/126 | 21.8 | 22.9 |
| iso-doh-h2 | 11082 | 11110 | -0.3% | 10985.47 | 10649.60 | 17530.88 | 19316.74 | 19791.87 | 165/32 | 160/34 | 24.4 | 24.2 |
| iso-udp-rest | 9487 | 9533 | -0.5% | 361.21 | 356.86 | 3577.86 | 7979.01 | 5558.27 | 183/35 | 188/40 | 36.7 | 38.8 |

`shared-*` — тот же сценарий без affinity (все потоки мигрируют по 8 vCPU). Δ qps = (iso − shared) / shared; положительное значение — вклад изоляции. Оба варианта — loopback, поэтому это сравнение методики, а не абсолютный потолок. `shared-*` может выигрывать по qps: без пиннинга каждый процесс получает доступ ко всем 8 vCPU, тогда как `iso-*` ограничивает сторону 4 CPU. Изоляция убирает SMT-конкуренцию, но не увеличивает суммарное число CPU.


## Выводы и узкие места

- iso-udp-a: 36240 qps (shared 39400, -8.0%), p50 10453.0 µs, p99 37322.8 µs, p999 48037.9 µs.
- iso-udp-mix: 29177 qps (shared 23893, +22.1%), p50 14458.9 µs, p99 58490.9 µs, p999 83689.5 µs.
- iso-udp-nx: 7384 qps (shared 7544, -2.1%), p50 60063.7 µs, p99 208273.4 µs, p999 244842.5 µs.
- iso-udp-signed: 39543 qps (shared 35133, +12.6%), p50 9584.6 µs, p99 57409.5 µs, p999 77463.6 µs.
- iso-tcp: 28360 qps (shared 28717, -1.2%), p50 2445.3 µs, p99 7520.3 µs, p999 13803.5 µs.
- iso-doh-h2: 11082 qps (shared 11110, -0.3%), p50 10985.5 µs, p99 17530.9 µs, p999 19791.9 µs.
- iso-udp-rest: 9487 qps (shared 9533, -0.5%), p50 361.2 µs, p99 3577.9 µs, p999 5558.3 µs.
- Максимальный клиентский qps в прогоне — `iso-udp-signed`: 39543. Это не потолок платформы: стенд loopback на 4 серверных CPU и шумном хосте; для приёмки 100k qps нужен отдельный клиентский хост.
- NXDOMAIN против mix: p99 208273.4 µs против 58490.9 µs (3.6×). Негативный путь — главный вклад в хвост; оптимизация перебора суффиксов даёт больше, чем qps.
- Изоляция проверяется по `Cpus_allowed_list` сервера и SMT-группам: сервер и клиент не должны делить физическое ядро. Раскладка 0,2,4,6/1,3,5,7 формально не пересекается, но оставляет каждого с сиблингом на чужой стороне — это не isolated.

## Воспроизведение

```bash
cargo build --release -p pulsed -p pulse-loadgen
target/release/pulse-bench --out-dir target/bench --report docs/bench/isolated.md --json docs/bench/isolated.json
target/release/pulse-bench --isolated --reuse --auto-layout \
             --server-cpus 0-3 --client-cpus 4-7 --rest-cpus 6-7 \
             --out-dir target/bench --report docs/bench/isolated.md --json docs/bench/isolated.json
taskset -c 4-7 target/release/pulse-loadgen --server 127.0.0.1:5353 \
             --mode udp --threads 8 --window 64 --client-cpus 4-7 --json-out run.json
cargo run -p pulse-loadgen --release --features alloc --bin pulse-alloc -- \
         --data target/bench/z1m.v2 --rrsets 1000000 --ops 20000 \
         --json-out target/bench/alloc.json
cargo bench -p pulsed --bench zone_writes
```
