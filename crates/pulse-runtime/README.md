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
  `eventfd`, опциональная привязка к разрешённым `sched_getaffinity` ядрам;
- `IORING_OP_RECVMSG` + `RECV_MULTISHOT` + `IORING_REGISTER_PBUF_RING`;
  при отказе регистрации — автоматический батч одиночных `recvmsg` (L1);
- L3-флаги `SINGLE_ISSUER | DEFER_TASKRUN` с откатом на базовые;
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
  паники, `cq_overflow_total`.

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
5. **`IORING_REGISTER_FILES` и `SO_BUSY_POLL` не используются** —
   запланированы после MVP. `SQPOLL` настраивается, но по умолчанию выключен
   и требует привилегий.
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
