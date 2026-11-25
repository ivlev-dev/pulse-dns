# pulse-runtime

Thread-per-core UDP-рантайм для `pulse-dns`: io_uring (multishot recvmsg +
provided buffers) с опциональным epoll-фолбэком. Без tokio и async:
синхронный обработчик датаграммы и собственный completion loop.

## Быстрый старт

```rust
use std::net::SocketAddr;
use pulse_runtime::{Reply, UdpServer};

let server = UdpServer::bind(
    "0.0.0.0:5353".parse().unwrap(),
    |request: &[u8], _peer: SocketAddr, out: &mut [u8]| {
        let len = request.len().min(out.len());
        out[..len].copy_from_slice(&request[..len]);
        Reply::Send(len)
    },
    4, // worker-потоков
)
.unwrap();

server.run().unwrap(); // блокируется; shutdown() из другого потока
```

Обработчик получает запрос, адрес пира и provided-буфер ответа
(`Reply::Send(len)` — без лишней копии; `Reply::Owned(Vec<u8>)` и
`owned(|req, peer| Option<Vec<u8>>)` — вариант с аллокацией). `len` больше
буфера — датаграмма не отправляется и учитывается в `responses_dropped`.

## Бэкенды

| `BackendPreference` | Поведение |
|---|---|
| `Auto` (по умолчанию) | Пробует io_uring; при недоступности и включённой feature `epoll-fallback` переключается на epoll и пишет одно предупреждение в `stderr`. Без feature — `RuntimeError::IoUringUnavailable` с подсказкой. |
| `Uring` | Fail-fast, без фолбэка. |
| `Epoll` | Требует feature `epoll-fallback`, иначе `RuntimeError::EpollUnsupported`. |

Фактический бэкенд и уровень возможностей всегда видны в
`UdpServer::backend()` / `Runtime::capabilities()` и печатаются
`pulse-udp-bench`. Уровень L3 выставляется только при поддержке
`IORING_FEAT_NODROP`; иначе — L2.

## Возможности

- ring на каждый worker-поток, `SO_REUSEPORT` на сокет, пробуждение через
  `eventfd`, опциональная привязка к разрешённым `sched_getaffinity` ядрам
  (явный список CPU пересекается с cpuset, чужие CPU не пинятся);
- `IORING_OP_RECVMSG` + `RECV_MULTISHOT` + `IORING_REGISTER_PBUF_RING`;
  при отказе регистрации — автоматический батч одиночных `recvmsg` (L1);
- L3-флаги `SINGLE_ISSUER | DEFER_TASKRUN` с послойным откатом (и
  опциональным `COOP_TASKRUN`);
- `IORING_REGISTER_FILES` для сокета и `eventfd` (по умолчанию, `SQE.fd =
  Fixed`); при отказе — обычный `Fd`;
- опциональный `IORING_SETUP_SQPOLL` + `SQ_AFF` (`with_sqpoll`,
  `with_sqpoll_cpu`); без прав автоматически выключается, фактическое
  состояние — в `Capabilities::sqpoll`;
- `SO_BUSY_POLL` / `SO_PREFER_BUSY_POLL` / `SO_BUSY_POLL_BUDGET`
  (`with_busy_poll`); ошибки `EPERM`/`ENOPROTOOPT` не ломают bind;
- `sendmsg`-SQE батчами, TX-слоты и backpressure (буферы не возвращаются
  ядру при нехватке слотов), счётчики `tx_pressure` / `pbuf_starve`;
- `IP_PKTINFO` / `IPV6_RECVPKTINFO`: wildcard-bind отвечает с того же
  локального адреса, на который пришёл запрос (ответ уходит с cmsg;
  при отсутствии cmsg — поведение ядра по умолчанию);
- `MSG_TRUNC`: датаграмма больше RX-буфера учитывается в
  `oversize_received` и не передаётся обработчику;
- graceful shutdown: `eventfd` + `IORING_REGISTER_SYNC_CANCEL` + дренаж CQE;
- паника обработчика изолируется (`handler_panics`), worker не падает, а
  глобальный panic-hook подавляет stderr на время обработчика;
- статистика: пакеты/байты RX/TX, ошибки, дропы, oversize, давление,
  паники, `cq_overflow_total`; в io_uring-бэкенде счётчики копятся локально
  и публикуются раз за проход completion-loop (без атомика на пакет).

## Тюнинг

Все параметры — поля/билдеры `RuntimeConfig`, API обработчика не меняется.

| Параметр | По умолчанию | Комментарий |
|---|---|---|
| `thread_stack_size` | 512 КиБ | стек worker'а; `0` — по умолчанию ОС |
| `cqe_batch` | 256 | CQE за проход; больше — меньше возвратов в `submit` |
| `rx_buffers` | 1024 | provided-буферы на worker (степень двойки) |
| `tx_slots` | 256 | TX-слоты на worker; при нехватке — backpressure |
| `cpu_affinity` | пусто | пересечение с `sched_getaffinity`/cpuset |
| `register_files` | `true` | `IORING_REGISTER_FILES` для сокета и `eventfd` |
| `coop_taskrun` | `false` | опциональный `IORING_SETUP_COOP_TASKRUN` |
| `sqpoll_idle` / `sqpoll_cpu` | `None` | SQPOLL выключен; требует отдельного CPU |
| `busy_poll_us` | `None` | `SO_BUSY_POLL`; на loopback выигрыша нет |

Арена provided-буферов выровнена по 64 байта (шаг буфера и начало арены):
соседние буферы не делят cache line. Для DNS-профиля (запрос ≤512 Б)
разумны `rx_buffer_size = 512`, `tx_slot_size = 1232..4096`,
`rx_buffers = 1024`, `tx_slots = 256`.

## Надёжность и shutdown

- **CQ overflow.** Инвариант `rx_buffers + tx_slots + 2 <= cq_entries`
  проверяется в конфигурации; `cq.overflow() > 0` — fail-fast worker'а и
  счётчик `cq_overflow_total` (потеря CQE не игнорируется).
- **Отмена без UAF.** `shutdown` отменяет операции с дедлайном
  `shutdown_timeout` (EINTR ретраится) и ждёт опустошения CQ. Если CQ не
  опустел, arena/pbuf/TX/RX-слоты **намеренно утекают** (`mem::forget`):
  освобождать память, на которую может ссылаться ядро, нельзя. Ошибка
  `unregister_buf_ring` обрабатывается так же.
- **Смерть worker'а.** Ошибка любого worker'а выставляет общий abort, будит
  всех (включая worker'ов других серверов того же `Runtime`) и возвращается
  из `run()`; `join` ограничен дедлайном и не висит бесконечно.
- **Частичный старт.** Если `start()` одного сервера упал, уже запущенные
  worker'ы останавливаются до возврата ошибки из `Runtime::run`.
- **`Reply::Send(len)`** с `len > out.len()` отбрасывается: слот не
  отправляет хвост прошлого ответа (префикс слота обнуляется при
  переиспользовании).

## Ограничения MVP

1. **Обработчик — синхронный**, ответ пишется в provided-буфер
   (`Reply::Send`). Варианта «внешний буфер без копирования» нет.
2. **Worker-пулы per-server.** Два `UdpServer` на одном `Runtime` создают
   по пулу на сервер. Общий пул / несколько fd в одном ring'е — после M3.
3. **`Auto`-фолбэк на epoll разрешён**, но не молчаливый: предупреждение в
   `stderr`, фактический бэкенд в `capabilities()/backend()`. Явный `Epoll`
   без feature — `EpollUnsupported`, без подмены.
4. **Oversize-датаграммы — count+drop (финально).** `IP_PKTINFO` и
   `IPV6_V6ONLY` реализованы; dual-stack (`IPV6_V6ONLY=0`) по-прежнему нет.
5. **SQPOLL и `SO_BUSY_POLL` — опции, по умолчанию выключены.** SQPOLL
   требует отдельного ядра и (на старых ядрах) привилегий; busy-poll жжёт
   CPU и на loopback бесполезен. `IORING_REGISTER_FILES` включён по
   умолчанию и деградирует к обычному `Fd` при отказе.
6. **TCP и таймеры** — следующая итерация M3.
7. epoll-бэкенд (`EPOLLET`) вычитывает сокет до `EAGAIN`, отправляет
   `sendmmsg` с ретраем частичной отправки/EINTR и дропает остаток при
   `EAGAIN`; TX-очереди, как в uring, нет. Одна лишняя копия на приём.
8. **`SO_REUSEPORT` — не изоляция.** Другой процесс того же uid может
   привязаться к тому же порту с `SO_REUSEPORT` и получать часть трафика;
   это свойство механизма, а не баг. Для изоляции нужен отдельный uid/netns.

## Бенчмарк

`pulse-udp-bench` — echo-сервер в процессе + N клиентов. По умолчанию:
прогрев 1 с, замер 5 с, 3 прогона и медиана. RTT считается по
HDR-подобной гистограмме с фиксированными бакетами (латентности не хранятся
в `Vec`), ответ проверяется побайтно (echo + seq), корректность — `corrupt=0`.

Машина: AMD Ryzen 5 3500U (4 ядра / 8 потоков, 3.7 ГГц), kernel
7.3.3-1-cachyos-bore-lto, rustc 1.99.1, io_uring L3
(multishot + pbuf + `DEFER_TASKRUN` + `NODROP`), `performance`. Замеры — при
фоновой нагрузке хоста ≈ 4–5; потерь и ошибок не было.

| Конфигурация | qps (медиана) | p50 | p99 | p999 |
|---|---:|---:|---:|---:|
| uring, 4 / 4, окно 1, 64 B | 89 036 | 35 µs | 182 µs | 750–1060 µs |
| uring, 4 / 4, окно 16, 64 B | 220 117 | 230–310 µs | 1 260 µs | 2 300–2 600 µs |
| epoll, 4 / 4, окно 16, 64 B | 230 352 | 240 µs | 1 070 µs | 2 200–2 500 µs |
| uring, 4 / 4, окно 16, 512 B | 207 568 | 220–330 µs | 1 380 µs | 2 200–3 400 µs |

При окне >1 перцентили включают очередь клиента (throughput-режим); строка с
окном 1 — честный RTT. epoll и uring на этом профиле практически равны;
запас по qps ограничен клиентом на тех же 8 логических CPU. Хост — рабочая
машина: при повторном прогоне под нагрузкой ~10 тот же конфиг uring 4/4/16
дал 136 100 qps / p99 2.4 мс, поэтому цифры выше — верхняя оценка, а не
гарантированный SLA.

### Тюнинг 2026-11-25

Профиль: 4 клиента, окно 16, 64 B, 3×3 с, медиана. «До» — старый профиль
(`rx_buffer=4096`, `tx_slots=workers×256`, стек ОС); «после» — DNS-профиль
(`rx_buffer=512`, `tx_slots=256`, стек 512 КиБ, `REGISTER_FILES`).

| Workers | До, qps | После, qps | До, p99 | После, p99 | До sys CPU | После sys CPU | До RSS | После RSS |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 142 449 | 140 157 | 660 µs | 840 µs | 32.9 s | 30.5 s | 12.7 MB | 4.7 MB |
| 4 | 284 998 | 224 118 | 560 µs | 520 µs | 68.1 s | 58.5 s | 40.6 MB | 10.2 MB |
| 8 | 276 130 | 229 474 | 650 µs | 440 µs | 70.9 s | 72.1 s | 104.9 MB | 17.5 MB |

Окно 1 (честный RTT, 4 worker'а): до p50 33 µs / p99 63 µs, после p50 33 µs /
p99 60 µs. 512 B payload: 210 867 → 264 275 qps (в пределах разброса хоста).

**Осторожно с выводами по qps:** хост общий, во время части прогонов
сторонняя нагрузка поднимала load average до 10–20. В одинаковых условиях
(тот же `rx`/`tx`, изолированный user-scope `CPUWeight=10000`) 4/4 и 8/8
дают одинаковый qps в пределах ±10 %, а sys CPU на 4 worker'ах ниже на
~5–14 %. RSS и перцентили устойчивы; абсолютный qps — верхняя оценка.

Эффект опций (4/4, тот же профиль, медианы/лучшие серии):

| Опция | Наблюдение | Рекомендация |
|---|---|---|
| `register_files=true` | qps в пределах шума (208k on vs 199k off) | оставить `true` |
| `sqpoll=1000` | 152–172k qps, p99 1.8–2.3 мс: kernel-поток занимает 4 CPU и отключает `DEFER_TASKRUN` (L2) | off; включать только при `workers < CPU/2` и на реальном NIC |
| `busy_poll=50` | 221k vs 224k на loopback, p99 без выигрыша | off на loopback; на NIC — мерить отдельно |
| `coop_taskrun=true` | без выигрыша, p99 хуже (1.5–2.3 мс) | off по умолчанию |
| `cqe_batch=512` | в пределах шума | 256 по умолчанию |
| `pin_to_cpu` | 216k vs 188k в одной серии, 165k в другой | off по умолчанию; пинить только worker'ов ≤ доступных CPU |

Для DNS-нагрузки (запросы ≤512 B, ответы ≤1232–4096 B): `rx_buffer=512`,
`tx_slot_size=1232..4096`, `tx_slots=256`, `rx_buffers=1024`, SQPOLL и
busy-poll выключены, `register_files=true`. На 8+ физических ядрах с NIC
имеет смысл отдельно измерить SQPOLL с выделенным CPU и `SO_BUSY_POLL`.

```text
cargo run --release -p pulse-runtime --features epoll-fallback --bin pulse-udp-bench -- \
    --workers 4 --clients 4 --window 16 --duration 5 --warmup 1 --runs 3 --payload 64
```

## Проверки

```text
cargo fmt --check -p pulse-runtime
cargo clippy -p pulse-runtime --all-targets --all-features -- -D warnings
cargo test -p pulse-runtime --all-features
RUSTDOCFLAGS="-D warnings" cargo doc -p pulse-runtime --no-deps --all-features
```

Тесты на реальных localhost-сокетах: echo, несколько worker'ов,
`SO_REUSEPORT`, wildcard-bind с `IP_PKTINFO` (multishot/batch/epoll), пустая и
усечённая датаграмма, перегрузка, shutdown под флудом (< 500 мс), частичный
старт, паника обработчика (100 подряд без flood в stderr), невалидный
`Reply::Send(len)`, батчевый L1-режим, epoll-бэкенд, IPv6.
