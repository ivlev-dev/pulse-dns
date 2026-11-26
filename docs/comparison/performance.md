# Сравнение `pulsed` / `pulseresolved` с BIND 9, Unbound и PowerDNS

Дата: 2026-11-26. Стенд: Arch Linux, AMD Ryzen 5 3500U (4 физических ядра / 8 потоков), 33 GiB RAM, kernel 7.3.3-1-cachyos-bore-lto. Без root, без Docker; всё собрано из исходников в `/tmp/opencode/compare` и установлено в `/tmp/opencode/compare/dist`.

Сырые числа: [`performance.json`](performance.json), [`raw/`](raw/), конфиги и скрипты: [`configs/`](configs/).

---

## 1. Краткое резюме

- **Authoritative, 10k qps open-loop:** все серверы держат 10 000 qps без потерь и таймаутов; достигнуто 9 963–9 990 qps. p50 ≈ 356–359 µs у всех — это **пол** пейсинга самого `pulse-loadgen`, а не latency сервера.
- **Authoritative, closed-loop окно 64:** `pulsed` с response cache — **110 065 qps** (лучший результат), PowerDNS с `cache-ttl=60` — 102 877, Unbound — 98 400, BIND — 94 769, `pulsed` без кеша — 83 156, PowerDNS без кеша (`cache-ttl=0`, gsqlite3) — 53 271.
- **Старт и память:** `pulsed` — 0.12 с и 34–45 MiB; BIND — 0.43 с и 121 MiB; Unbound — 0.72 с и 76 MiB; PowerDNS — 0.24 с (зона не грузится) и 91–105 MiB.
- **Resolver, cache-hit:** Unbound 103.7–104.4k qps, `pulseresolved` 98.4–99.8k, PowerDNS Recursor 89.6–110.8k, BIND 84.1–96.3k. Разница между лидерами — единицы процентов; `pulseresolved` при этом тратит меньше user-CPU.
- **Cold cache и NXDOMAIN:** cold-прогон (без прогрева) — 91.5–103.5k qps, p99 7.1–11.4 мс; 100% NXDOMAIN из negative cache — 88.2–108.2k qps. Все ответы валидны, потерь и таймаутов нет.
- **Корректность:** 13 запросов (A/AAAA/MX/TXT/SOA/NXDOMAIN/отсутствующее имя) на 10 серверных эндпоинтах дали одинаковые ответы и RCODE. Отличие только в policy: BIND добавляет NS зоны в AUTHORITY положительного авторитативного ответа.

---

## 2. Версии и сборка

| Компонент | Версия | Как собран |
|---|---|---|
| `pulsed` | 0.1.0 | готовый `target/release/pulsed` из репозитория |
| `pulseresolved` | 0.1.0 | готовый `target/release/pulseresolved` |
| BIND | **9.20.15** (Stable) | исходники ISC, `gcc 16.2.1`; OpenSSL 3.5.9, libuv 1.53.0, jemalloc 5.4.0, liburcu 0.15.7, json-c |
| Unbound | **1.22.0** | исходники NLnet Labs; libevent 2.1.13, OpenSSL 3.5.9, expat 2.10 |
| PowerDNS Authoritative | **4.9.20** | исходники, backend `gsqlite3`, LuaJIT, boost headers 1.92, OpenSSL 3.5.9 |
| PowerDNS Recursor | **5.2.13** | исходники, boost 1.92, libsodium, libcap, OpenSSL 3.5.9 |
| Нагрузчик | `pulse-loadgen` | штатный бинарь + локальная сборка с RD=1 (см. §7) |

BIND:

```bash
./configure --prefix=/tmp/opencode/compare/dist/bind --with-openssl=/usr \
  --disable-doh --disable-geoip --without-maxminddb --without-lmdb \
  --without-gssapi --disable-chroot --with-libxml2=no --with-json-c=detect
make -j8 && make install
```

Unbound (системный OpenSSL 4.1 не используем, линкуемся с `openssl-3` 3.5.9):

```bash
./configure --prefix=/tmp/opencode/compare/dist/unbound --with-ssl=/usr \
  --with-libevent=/usr --without-pythonmodule --without-pyunbound --without-dnstap \
  --disable-flto CPPFLAGS="-I/usr/include/openssl-3" LDFLAGS="-L/usr/lib/openssl-3"
make -j6 && make install
```

PowerDNS: системных заголовков boost в Arch нет (есть только `boost-libs`), поэтому заголовочный пакет `boost 1.92` распакован без root через `bsdtar` в `dist/boost`; конфигурация:

```bash
./configure --prefix=/tmp/opencode/compare/dist/pdns \
  --with-boost=/tmp/opencode/compare/dist/boost/usr \
  --with-modules="gsqlite3" --with-sqlite3 --without-mysql --without-pgsql --without-geoip \
  CPPFLAGS="-I/usr/include/openssl-3" LDFLAGS="-L/usr/lib/openssl-3"
```

Первая сборка была 4.9.11, но она печатает mandatory security advisory 2026-05, поэтому всё пересобрано на актуальную стабильную **4.9.20**. PowerDNS-бинарники слинкованы с OpenSSL 3.5.9, но `libcurl` тянет в процесс ещё и `libcrypto.so.4`; работает, однако это не дистрибутивная сборка (оговорка §7).

---

## 3. Одинаковая зона и проверка корректности

Сгенерированы два master-файла (`configs/genzone.py`):

| Зона | Содержимое | Размер |
|---|---|---|
| `example.com.` | SOA/NS + **100 000 A** (`host000001`…`host100000`) | 2.8 MB |
| `z0.bench.test.` | SOA/NS + **100 000 записей** `r0000000`…`r0099999`; тип циклится A/AAAA/MX/TXT по `index % 4` | 3.4 MB |

Вторая зона нужна потому, что `pulse-loadgen` жёстко строит имена `r{record:07}.z{N}.bench.test.` и циклит типы A/AAAA/MX/TXT; так mix попадает точно в существующие RRset. `example.com` — требование ТЗ и проверка A-зоны на 100k имён.

Загрузка:

- `pulsed`: `pulsed import --data run/pulsed/store.v2 --origin example.com. zones/example.com.zone`, затем то же для `z0.bench.test.` — **1.0 с** и **2.3 с** (второй импорт в тот же store), 100 003 RRset на зону; store sparse 4 GiB, реально 17 MiB.
- BIND: master-файлы в `zone`; старт до первого ответа **0.42–0.43 с** (включая разбор обеих зон), `named-checkconf -z` — 1.03 с.
- Unbound: `auth-zone` c `zonefile:`; старт **0.72 с**. Важно: встроенная local-zone `test.` перекрывает `z0.bench.test.`, поэтому в конфиге стоит `local-zone: "test." nodefault` (и `bench.test.`).
- PowerDNS: `pdnsutil load-zone` в SQLite — 0.7–0.9 с на зону, но **при старте зона не грузится**: backend отвечает SQL-запросом на каждый cache miss.

Проверка (`configs/verify.py`, 13 запросов, RD=1 для резолверов):

| Роль | Серверы | Результат |
|---|---|---|
| Authoritative | pulsed, pulsed+cache, BIND, Unbound, PowerDNS, PowerDNS+cache | все ответы и RCODE совпадают |
| Resolver | pulseresolved, Unbound, BIND, PowerDNS Recursor | все ответы и RCODE совпадают |

BIND на положительных авторитативных ответах добавляет NS зоны в AUTHORITY — это единственное наблюдённое отличие, к содержанию ответа оно не относится. Подробности: [`raw/correctness.json`](raw/correctness.json).

---

## 4. Методика

- **Изоляция:** сервер — `taskset -c 0-3`, клиент — `taskset -c 4-7`. На этом CPU SMT-пары идут подряд: `(0,1) (2,3) (4,5) (6,7)`, то есть сервер и клиент получают по 2 физических ядра и не делят сиблинги. Общие остаются L3, память, loopback и IRQ.
- **Нагрузка:** UDP, 4 клиентских потока, длительность 10 с.
  - Authoritative: open-loop `--qps 10000` и closed-loop `--window 64`.
  - Resolver: closed-loop окно 16 и 64 (cache-hit), cold-cache окно 64 (warmup 0), 100% NXDOMAIN окно 16.
  - Mix: `a=40,aaaa=20,mx=15,txt=10,nx=15`; для negative-cache — `nx=100`.
- **Повторы:** 5 прогонов на сценарий для authoritative, 3 для resolver; в таблицах медиана и min–max qps. Каждый прогон — чистый рестарт сервера.
- **Метрики:** клиентский qps (`received / 10 с`), HDR p50/p99/p999, `VmRSS` сервера после прогона, `utime/stime` сервера за прогон (100% = одно ядро), старт от `exec` до первого корректного ответа, loadavg хоста.
- **Closed-loop p50 включает очередь окна.** При окне 64 на поток держится 16 запросов в полёте, поэтому p50 отражает и время ожидания в очереди (закон Литтла), а не только стоимость обработки. Сравнивать p50 между серверами с разной пропускной способностью нужно с этой поправкой.
- **RCVBuf:** дельта `UdpRcvbufErrors` = 0 во всех валидных прогонах; `sent == received`, `timeout = errors = invalid = 0`.

---

## 5. Authoritative

Open-loop 10k — проверка «держит ли ставку», а не рейтинг latency: p50 ≈ 357 µs у всех, потому что это пол пейсинга `pulse-loadgen`. Значимее p99/p999 и отсутствие потерь.

### auth-open-10k

| Сервер | qps медиана | qps min–max | p50, µs | p99, µs | p999, µs | RSS, MiB | user % | sys % | ΣCPU % | старт, с |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Unbound 1.22.0 | 9 990 | 9 988–9 992 | 358.7 | 466.4 | 709.1 | 76.3 | 14.6 | 16.1 | 30.6 | 0.72 |
| pulsed (response cache) | 9 989 | 9 985–9 992 | 357.9 | 464.1 | 760.3 | 45.4 | 7.7 | 24.8 | 32.7 | 0.12 |
| PowerDNS 4.9.20 (cache-ttl=60) | 9 987 | 9 983–9 989 | 356.1 | 466.2 | 725.5 | 104.6 | 12.0 | 29.4 | 41.9 | 0.24 |
| BIND 9.20.15 | 9 984 | 9 979–9 985 | 357.9 | 462.1 | 741.9 | 121.4 | 31.6 | 20.5 | 51.9 | 0.42 |
| pulsed (cache off) | 9 983 | 9 978–9 988 | 357.6 | 461.6 | 768.5 | 34.1 | 25.4 | 24.0 | 51.6 | 0.12 |
| PowerDNS 4.9.20 (cache-ttl=0) | 9 963 | 9 955–9 969 | 355.6 | 477.2 | 897.5 | 90.9 | 59.1 | 52.7 | 110.4 | 0.24 |

### auth-closed-64

| Сервер | qps медиана | qps min–max | p50, µs | p99, µs | p999, µs | RSS, MiB | user % | sys % | ΣCPU % | старт, с |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| pulsed (response cache) | 110 065 | 109 084–111 408 | 37.2 | 2 689.0 | 3 428.4 | 44.6 | 22.5 | 141.4 | 163.9 | 0.12 |
| PowerDNS 4.9.20 (cache-ttl=60) | 102 877 | 95 767–104 704 | 69.6 | 2 963.5 | 3 835.9 | 100.7 | 34.3 | 156.5 | 190.8 | 0.24 |
| Unbound 1.22.0 | 98 400 | 96 493–101 273 | 39.0 | 2 650.1 | 3 348.5 | 76.4 | 75.7 | 81.7 | 157.5 | 0.72 |
| BIND 9.20.15 | 94 769 | 91 429–97 130 | 606.2 | 3 471.4 | 4 362.2 | 121.4 | 118.7 | 71.8 | 190.5 | 0.43 |
| pulsed (cache off) | 83 156 | 68 438–84 509 | 2 803.7 | 4 411.4 | 6 430.7 | 36.1 | 145.5 | 107.3 | 252.9 | 0.12 |
| PowerDNS 4.9.20 (cache-ttl=0) | 53 271 | 52 706–54 325 | 3 676.2 | 17 662.0 | 23 937.0 | 91.2 | 239.9 | 155.9 | 396.0 | 0.24 |

Комментарии:

- `pulsed` без response cache упирается в CPU: 253% суммарно, p50 2.8 мс. С кешем тот же сервер даёт 110k при 164% CPU.
- PowerDNS без кеша честно упирается в 4 ядра (396%) и SQLite: 53k. `cache-ttl=60` поднимает до 103k — это уже другой режим, показан для контекста.
- BIND и Unbound без response cache работают из памяти зоны и дают 95–98k; BIND платит большим RSS (121 MiB).
- Open-loop 10k не различает серверы: запас есть у всех, потерь нет.

---

## 6. Resolver

Upstream у всех — `pulsed` (authoritative, `127.0.0.1:5301`), конфиг без response cache; после прогрева upstream почти не нагружается. Все резолверы — forward-режим на один и тот же upstream, DNSSEC выключен (зоны не подписаны).

### res-warm-16 (cache-hit, окно 16)

| Сервер | qps медиана | qps min–max | p50, µs | p99, µs | p999, µs | RSS, MiB | user % | sys % | ΣCPU % | старт, с |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Unbound 1.22.0 | 103 704 | 99 775–104 010 | 27.6 | 2 056.2 | 2 304.0 | 35.1 | 37.1 | 99.7 | 137.2 | 0.12 |
| pulseresolved | 98 394 | 97 423–101 175 | 24.3 | 2 041.9 | 2 125.8 | 36.7 | 20.0 | 104.9 | 124.9 | 0.12 |
| PowerDNS Recursor 5.2.13 | 89 573 | 83 892–99 041 | 314.1 | 2 465.8 | 3 227.6 | 38.4 | 35.3 | 138.2 | 173.5 | 0.12 |
| BIND 9.20.15 | 84 087 | 82 635–92 807 | 191.6 | 2 381.8 | 3 076.1 | 69.6 | 100.4 | 77.1 | 177.5 | 0.12 |

### res-warm-64 (cache-hit, окно 64)

| Сервер | qps медиана | qps min–max | p50, µs | p99, µs | p999, µs | RSS, MiB | user % | sys % | ΣCPU % | старт, с |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| PowerDNS Recursor 5.2.13 | 110 785 | 110 202–110 893 | 343.8 | 3 156.0 | 3 917.8 | 41.1 | 43.8 | 172.7 | 217.2 | 0.12 |
| Unbound 1.22.0 | 104 418 | 103 302–106 874 | 27.2 | 2 053.1 | 2 371.6 | 37.8 | 38.3 | 99.3 | 137.4 | 0.12 |
| pulseresolved | 99 787 | 98 640–102 026 | 24.7 | 2 049.0 | 2 465.8 | 32.3 | 20.8 | 111.0 | 131.8 | 0.12 |
| BIND 9.20.15 | 96 339 | 94 265–96 355 | 336.4 | 3 143.7 | 3 885.1 | 72.9 | 113.5 | 81.0 | 197.7 | 0.12 |

### res-cold-64 (холодный кеш, warmup 0)

| Сервер | qps медиана | qps min–max | p50, µs | p99, µs | p999, µs | RSS, MiB | user % | sys % | ΣCPU % | старт, с |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Unbound 1.22.0 | 103 484 | 99 710–103 715 | 26.3 | 7 122.9 | 11 608.1 | 36.9 | 39.8 | 102.9 | 143.7 | 0.12 |
| PowerDNS Recursor 5.2.13 | 102 482 | 82 614–104 298 | 372.5 | 8 233.0 | 20 938.8 | 41.2 | 46.0 | 172.2 | 218.2 | 0.12 |
| pulseresolved | 91 909 | 91 004–92 863 | 23.7 | 11 419.6 | 28 491.8 | 32.3 | 23.6 | 124.0 | 147.8 | 0.12 |
| BIND 9.20.15 | 91 522 | 90 383–92 139 | 402.2 | 7 393.3 | 16 064.5 | 73.3 | 116.2 | 81.5 | 198.4 | 0.12 |

### res-nx-warm-16 (100% NXDOMAIN из negative cache)

| Сервер | qps медиана | qps min–max | p50, µs | p99, µs | p999, µs | RSS, MiB | user % | sys % | ΣCPU % | старт, с |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Unbound 1.22.0 | 108 192 | 108 053–108 910 | 26.1 | 2 038.8 | 2 067.5 | 31.3 | 37.9 | 105.8 | 143.6 | 0.12 |
| pulseresolved | 98 957 | 96 300–100 488 | 24.7 | 2 043.9 | 2 152.4 | 35.4 | 20.2 | 101.5 | 121.6 | 0.12 |
| BIND 9.20.15 | 91 904 | 88 722–95 159 | 70.7 | 2 240.5 | 2 816.0 | 68.4 | 95.9 | 87.8 | 183.8 | 0.12 |
| PowerDNS Recursor 5.2.13 | 88 196 | 87 173–105 495 | 298.2 | 2 478.1 | 3 213.3 | 39.3 | 35.1 | 135.7 | 170.9 | 0.12 |

Комментарии:

- На cache-hit Unbound стабильно впереди на 4–5% по qps; `pulseresolved` чуть позади, но с меньшим user-CPU (20% против 37–38%) и меньшим p50 (24–25 µs против 26–28 µs). При окне 64 разрыв сокращается (99.8k против 104.4k).
- PowerDNS Recursor выходит вперёд при окне 64 (110.8k), но платит вдвое большим sys-CPU и p50 344 µs.
- BIND-резолвер стабильно 84–96k, самый тяжёлый по RSS (70–73 MiB) и CPU (~180–198%).
- Cold-cache почти не роняет qps за 10 с (успевает прогреться), но p99 вырастает до 7–11 мс — это цена первых промахов. Хуже всех cold p99 у `pulseresolved` (11.4 мс), лучше у Unbound (7.1 мс).
- NXDOMAIN negative cache не создаёт проблем никому; Unbound и здесь первый.

---

## 7. Честные оговорки

1. **Loopback и один хост.** Сервер и клиент разнесены по CPU (0–3 / 4–7, по 2 физических ядра), но делят L3, память, сетевой стек ядра и IRQ. Абсолютные qps — нижняя оценка; относительные сравнения устойчивее.
2. **Нет root — нет изоляции.** Нельзя было настроить cgroups/cpuset, IRQ affinity, отключить desktop/IDE и другие агенты. Loadavg во время прогонов был 2–10; медианы и min–max показывают разброс. Authoritative-фаза из-за этого перезапускалась: первые 3 прогона (штатный loadgen) сохранены в `raw/auth-3reps-shipped-rd0.json`, итоговые 5 прогонов — в `raw/auth-5reps.json`.
3. **Разные архитектуры и storage.** `pulsed` — mmap бинарного store; BIND — in-memory rbtdb из master-файлов; Unbound — in-memory `auth-zone`; PowerDNS — `gsqlite3` без предзагрузки, SQL-запрос на каждый cache miss. Поэтому сравнение «в лоб» честно только для cache-off вариантов и с оговоркой про backend.
4. **Кеши — разные.** У `pulsed` это кеш готовых wire-ответов, у PowerDNS — packet/query cache (`cache-ttl`), у резолверов — обычный DNS-кеш. В таблицах показаны оба варианта authoritative, чтобы не сравнивать только лучший.
5. **RD-бит в нагрузчике.** Штатный `pulse-loadgen` отправляет запросы с **RD=0**. BIND, Unbound и PowerDNS Recursor на RD=0 отвечают REFUSED (проверено relay-перехватом: Unbound возвращал RCODE 5), из-за чего первый resolver-прогон дал `invalid = sent`. Для resolver-фазы (и для итоговой 5-репетиционной authoritative-серии) использована **локальная сборка того же loadgen с одной правкой: RD=1**. Код репозитория не менялся; сборка лежит в `/tmp/opencode/compare/loadgen-rd`. Авторитативные результаты, снятые штатным RD=0 инструментом, совпали в пределах шума.
6. **Open-loop p50 ≈ 357 µs** — это пол пейсинга клиента на этом хосте, а не latency сервера. Open-loop-таблица отвечает на вопрос «держим ли 10k без потерь», а не «кто быстрее».
7. **PowerDNS и OpenSSL.** Сервер собран с OpenSSL 3.5.9, но `libcurl` подгружает `libcrypto.so.4`; в процессе живут две версии OpenSSL. Функционально проверено, но это не дистрибутивная сборка. Заголовки boost 1.92 распакованы из пакета без установки в систему.
8. **DNSSEC выключен** везде: зоны не подписаны, сравнение не про валидацию.
9. **Unbound `test.`** — встроенная local-zone `test.` по умолчанию отдаёт NXDOMAIN на всю ветку; для `z0.bench.test.` она отключена (`local-zone: "test." nodefault`). Это особенность конфигурации, не производительности.
10. **Старт резолверов 0.12 с** — это время до первого корректного ответа (первый запрос уходит на upstream). Холодный кеш измеряется отдельным сценарием `res-cold-64`, а не стартом процесса.
11. **BIND AUTHORITY.** BIND добавляет NS зоны в AUTHORITY положительного ответа; в `verify.py` сравниваются RCODE и answers, различие зафиксировано отдельно.
12. **PowerDNS Recursor** запускался с `--dnssec=off`, `--allow-from=127.0.0.0/8`, 4 потоками, forward-zone на `pulsed`.

---

## 8. Выводы

1. **На 10k qps open-loop все пять серверов эквивалентны по факту приёма нагрузки**: ни потерь, ни таймаутов, ни invalid. Различия в p99 на этом уровне — шум хоста и клиентского пейсинга.
2. **В закрытом цикле `pulsed` конкурентоспособен.** С response cache он лучший (110k), без кеша — 83k, что ниже BIND/Unbound (95–98k), но выше PowerDNS с gsqlite3 без кеша (53k). Это ожидаемо: у `pulsed` в этом режиме каждый запрос идёт в zone lookup, у BIND/Unbound зона уже в памяти, а PowerDNS ещё и в SQLite.
3. **Кеш решает больше, чем «движок».** Тот же `pulsed` даёт +32% qps и вдвое меньший p50 при включённом response cache; PowerDNS +93% при `cache-ttl=60`.
4. **Старт и память — сильная сторона `pulsed`:** 0.12 с и 34–45 MiB против 0.43–0.72 с у BIND/Unbound и 121/76 MiB. Цена — отдельный шаг импорта (1.0–2.3 с) и sparse-store.
5. **В resolver-режиме разница между `pulseresolved` и Unbound — 5–11% qps** в пользу Unbound на cache-hit; `pulseresolved` компенсирует меньшим user-CPU и меньшим p50. BIND и PowerDNS Recursor в этих сценариях медленнее по p50 и тяжелее по CPU, хотя PowerDNS Recursor на окне 64 выходит на первое место по qps.
6. **Холодный кеш и NXDOMAIN** не выявляют деградации ни у одного участника; tail latency cold-старта (p99 7–11 мс) — ожидаемая цена промахов, а не ошибка.

---

## 9. Воспроизведение

Артефакты и скрипты:

```
docs/comparison/performance.md          этот отчёт
docs/comparison/performance.json        сводные числа + методика + оговорки
docs/comparison/raw/auth-5reps.json     5 прогонов authoritative (RD=1 loadgen)
docs/comparison/raw/resolver-3reps.json 3 прогона resolver (RD=1 loadgen)
docs/comparison/raw/auth-3reps-shipped-rd0.json  контроль штатным loadgen (RD=0)
docs/comparison/raw/correctness.json    результат verify.py
docs/comparison/configs/                все конфиги, генератор зоны, harness/bench/verify
```

Исходные пути на стенде: `/tmp/opencode/compare/etc/*.conf|*.toml`, зоны — `/tmp/opencode/compare/zones/`, логи — `/tmp/opencode/compare/logs/`, бинарники — `/tmp/opencode/compare/dist/{bind,unbound,pdns,pdns-recursor,boost}`.

Ключевые команды:

```bash
# зоны
python3 /tmp/opencode/compare/genzone.py /tmp/opencode/compare/zones

# authoritative: сервер на CPU 0-3, клиент на 4-7
taskset -c 0-3 target/release/pulsed --config /tmp/opencode/compare/etc/pulsed-auth.toml
taskset -c 4-7 target/release/pulse-loadgen --server 127.0.0.1:5301 --mode udp \
  --threads 4 --window 64 --duration 10 --warmup 3 \
  --mix a=40,aaaa=20,mx=15,txt=10,nx=15 --zones 1 --rrsets-per-zone 100000 \
  --client-cpus 4-7 --json-out run.json

# resolver-фаза: upstream pulsed 5301, затем резолвер и тот же loadgen с RD=1
python3 /tmp/opencode/compare/bench_res.py
```

Полный прогон: `python3 /tmp/opencode/compare/bench_auth5.py` (authoritative, 5 повторов) и `python3 /tmp/opencode/compare/bench_res.py` (resolver, 3 повтора).
