# CPU-affinity, huge pages и NUMA

Документ описывает, как `pulsed`/`pulseresolved` раскладывают worker-потоки по
ядрам, когда включаются transparent huge pages и как это проверять на bare
metal, в контейнере и под NUMA.

## 1. CPU-affinity

### 1.1. Ключи конфигурации

| Процесс | Ключ | Что пинится |
|---|---|---|
| `pulsed` | `dns_cpu_affinity` | worker'ы UDP и DNSCrypt-UDP (`pulse-runtime`) |
| `pulsed` | `api_cpu_affinity` | accept-поток REST API и потоки соединений (`pulse-api`) |
| `pulseresolved` | `control_cpu_affinity` | worker'ы UDP/TCP и потоки control-plane |

Формат — массив чисел или строка с диапазонами:

```toml
# pulsed.toml: data-plane на 0-3, control-plane на 4-5
dns_cpu_affinity = "0-3"
api_cpu_affinity = [4, 5]
```

```toml
# resolver.toml
control_cpu_affinity = "0-3"
```

CLI-эквиваленты: `--dns-cpu-affinity 0-3`, `--api-cpu-affinity 4,5`,
`--control-cpu-affinity 0-3`.

### 1.2. Правила

1. **Пересечение с маской процесса.** Любой список пересекается с
   `sched_getaffinity` (учитывает cgroup cpuset). Пустое пересечение — ошибка
   старта, а не тихий запуск без пиннинга:
   `CPU affinity error: dns_cpu_affinity: requested CPUs [8] do not intersect ...`
2. **На чужие CPU не пинимся.** Явный CPU вне маски просто не попадёт в
   пересечение; `sched_setaffinity` вызывается только с разрешёнными ядрами.
3. **DNS и API не делят ядра.** Пересечение `dns_cpu_affinity` и
   `api_cpu_affinity` — ошибка конфигурации: смысл разделения ролей
   (`docs/process-roles.md`) в том, чтобы REST не голодал под DNS-нагрузкой.
   В `role = all` наборы всё равно должны быть непересекающимися.
4. **Пустой список** — пиннинга нет, worker наследует маску процесса (поведение
   по умолчанию, регрессии нет).
5. **Переполнение.** Если worker'ов больше, чем CPU, ядра раздаются по кругу
   (`cpu[index % len]`). Лишние ядра при малом числе worker'ов не используются.

### 1.3. Контейнеры и `taskset`

`taskset -c 0-3 pulsed ...` сужает маску процесса; affinity из конфига
применяется уже внутри неё. Docker `--cpuset-cpus="0-3"`/Kubernetes
`cpuset.cpus` работают так же: ядро возвращает суженную маску, и конфиг с
`dns_cpu_affinity = "0-3"` продолжает работать, а `"6,7"` даст ошибку старта.

Проверка фактической маски:

```bash
for t in /proc/$(pgrep -n pulsed)/task/*/status; do
  grep -H -E 'Name|Cpus_allowed_list' "$t"
done
```

## 2. Huge pages

### 2.1. Политика

```toml
huge_pages = "auto"   # auto (по умолчанию) | always | never
```

* `auto` — `madvise(MADV_HUGEPAGE)` best-effort: старые ядра, `EINVAL`,
  выключенный THP и контейнер без `/sys` не мешают старту.
* `always` — подсказка обязательна. Если
  `/sys/kernel/mm/transparent_hugepage/enabled` содержит `[never]` или
  `madvise` вернул ошибку, старт завершается ошибкой (`huge_pages = always`
  имеет смысл только после проверки хоста).
* `never` — арены помечаются `MADV_NOHUGEPAGE`, файловые отображения получают
  `MADV_NOHUGEPAGE` (для tmpfs это реально выключает THP).

Где применяется:

| Регион | Модуль |
|---|---|
| RX-арена provided buffers (UDP/DNSCrypt) | `pulse-runtime`, `mem::advise` |
| mmap данных зон v1 (`FileMap`, `PROT_READ`, `MAP_SHARED`) | `pulse-zonefile`, `FileMap::map_read` |
| Reader table, sidecar координатора v2 | не применяется (маленькие регионы) |

### 2.2. Ограничение ядра

THP для **файловых** страниц `MAP_SHARED` поддерживается только для
shmem/tmpfs. На ext4/xfs `madvise(MADV_HUGEPAGE)` принимается, но страницы
остаются 4 KiB. Поэтому:

* для zone-файла на tmpfs (`/dev/shm`, `tmpfs`) THP реально работает;
* для zone-файла на диске выигрыша не будет — это ожидаемо, а не ошибка;
* v2-стор читает через page cache (`pread`), поэтому `huge_pages` влияет на
  него только через THP page cache tmpfs.

Проверка:

```bash
grep -E 'AnonHugePages|RssAnon' /proc/$(pgrep -n pulsed)/status
cat /sys/kernel/mm/transparent_hugepage/enabled
```

### 2.3. Измерения

```bash
# dTLB и IPC сервера под нагрузкой (perf_event_paranoid <= 2, свои процессы)
perf stat -e dTLB-load-misses,dTLB-store-misses,cycles,instructions \
  -p "$(pgrep -n pulsed)" -- sleep 10

# RSS и пиковый RSS
grep VmRSS /proc/$(pgrep -n pulsed)/status

# UDP-бенчмарк: сравнение политик на одном хосте
cargo run --release -p pulse-runtime --bin pulse-udp-bench -- \
  --workers 4 --clients 4 --huge-pages never --duration 10
cargo run --release -p pulse-runtime --bin pulse-udp-bench -- \
  --workers 4 --clients 4 --huge-pages always --duration 10
```

Числа зависят от хоста: на loopback dTLB-эффект виден только при большом
рабочем наборе (много worker'ов × большая RX-арена); на tmpfs zone-файле —
на cold-чтении после `echo 3 > /proc/sys/vm/drop_caches`.

### 2.4. Эталонные числа (tmpfs, THP=always, 8 CPU)

Замеры на Linux 6.x, `/tmp` — tmpfs, `shmem_enabled = advise`:

```text
# pulse-udp-bench, 2 worker'а, 2 клиента, rx-buffers=16384 (~140 MiB арен)
huge_pages=never:  RSS 76.8 MB, AnonHugePages 0,       dTLB-load-misses/1k instr 0.975
huge_pages=always: RSS 148.4 MB, AnonHugePages 137216 kB, dTLB-load-misses/1k instr 0.958
                   qps 44.4k -> 41.9k, p99 97 -> 120 us (в пределах шума loopback)
```

Выводы:

* THP **применяется** к RX-арене (`AnonHugePages` 0 → 137216 kB), но loopback-UDP
  не упирается в TLB: выигрыша в qps/p99 нет, а RSS на лениво заполненной арене
  растёт почти вдвое (huge page зануляется целиком при первом касании).
  Поэтому дефолт — `auto`, а `always` — осознанный выбор под конкретный профиль.
* Для mmap зоны v1 `always` даёт `THPeligible=1` на регионе (проверяется
  `/proc/<pid>/smaps`), но уже записанные через `pwrite` 4 KiB страницы page
  cache не перекладываются в huge pages: `ShmemPmdMapped` остаётся 0, пока
  khugepaged не сложит их. Это ограничение ядра, а не ошибка конфигурации.
* `never` — детерминированный способ выключить THP и держать предсказуемый RSS.

## 3. NUMA

Отдельного `mbind`/`set_mempolicy` в коде нет: first-touch уже размещает
арены и mmap на узле того потока, который первым к ним обратился. Рекомендация:

```bash
# Один NUMA-узел на процесс: CPU и память с одного узла.
numactl --cpunodebind=0 --membind=0 pulsed --config pulsed.toml

# Проверить топологию и что процесс не «разъехался» по узлам.
numactl --hardware
numastat -p "$(pgrep -n pulsed)"
```

`numactl --physcpubind=0-3` совместим с `dns_cpu_affinity = "0-3"`: внешняя
маска сужается первой, конфиг лишь подтверждает те же CPU. Если нужен
per-zone NUMA-локальный кэш — это отдельная задача; текущая модель
(thread-per-core + first-touch) не требует `mbind` для корректности.

## 4. Ограничения

* DoT/DoH/DoQ/DNSCrypt-TCP работают на потоках `tokio`/thread-per-connection
  внутри `pulse-tls`; affinity к ним не применяется (только UDP/DNSCrypt-UDP
  worker'ы, TCP- и control-потоки `pulseresolved`). Для полной изоляции
  используйте `taskset`/cpuset на процесс.
* `dns_cpu_affinity` не ограничивает число worker'ов: это делают `workers`/
  `dns_workers`.
* Ошибка `sched_setaffinity` в отдельном соединении не фатальна (пишется
  предупреждение в `stderr`); старт уже проверяет пересечение с маской.
