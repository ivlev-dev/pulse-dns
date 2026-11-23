# Спецификация I/O-рантайма pulse (`pulse-runtime` v1)

- **Крейт:** `pulse-runtime` (leaf-крейт, без знаний о DNS; ADR 0001 §4.1)
- **Платформа:** Linux, kernel ≥ 6.0 (целевой 7.x), 8 ядер; fallback `epoll` для не-Linux/старых ядер
- **Статус:** проект, на утверждение
- **Связанные:** `docs/adr/0003-zonefile-format.md`, `docs/spec/zonefile-v1.md` (§20), `docs/bench/plan.md`, `docs/spec/domain-model.md` (§5.8 `Timer`/`Spawner`)

---

## 1. Цели и не-цели

**Цели.**

| ID | Цель | Метрика |
|---|---|---|
| G1 | Обслуживать ≥ 100k qps UDP на 8 ядрах с p99 < 1 мс в LAN | §plan, M1/M3 |
| G2 | Ноль блокирующих syscall и ноль аллокаций на горячем пути | `strace -c` в тесте, счётчики аллокатора |
| G3 | Отсутствие общих блокировок между ядрами на пути запроса | нет `Mutex`/`RwLock` в hot-path (проверка линтом + ревью) |
| G4 | Graceful degradation: `epoll`-бэкенд с тем же API | один и тот же код сервера на обоих бэкендах |
| G5 | Устойчивость к медленным/вредоносным клиентам | лимиты соединений, in-flight, таймауты |
| G6 | Наблюдаемость без блокировок | per-core счётчики, агрегация раз в секунду |

**Не-цели.** DoT/DoH (M6), TLS, DNSCrypt, кроссплатформенность (только Linux + fallback), zero-copy transmit (`SEND_ZC`) в v1, `io_uring`-based файловый I/O для зон (зоны читаются через `mmap`, а не через ring).

---

## 2. Топология: поток на ядро, кольцо на поток

### 2.1. Решение

**Одно `io_uring` на рабочий поток, поток закреплён за ядром (`sched_setaffinity`), без work-stealing.**

```
core 0 ─ worker 0 ─ ring 0 ─ sockets(SO_REUSEPORT) ─ per-core arena, conn shard, timer wheel
core 1 ─ worker 1 ─ ring 1 ─ sockets(SO_REUSEPORT) ─ ...
...
core 7 ─ worker 7 ─ ring 7 ─ sockets(SO_REUSEPORT) ─ ...
         (отдельный поток) zone-writer: коммиты зон, fsync, публикация снапшота
         (отдельный поток) admin/API: REST, метрики, health
```

### 2.2. Сравнение моделей

| Модель | Плюсы | Минусы | Вердикт |
|---|---|---|---|
| **Ring per core** (выбрано) | нет конкуренции за SQ/CQ; нет атомарных RMW на submission; предсказуемая латентность; per-core кеши, arenas, таймеры; естественный шардинг по `SO_REUSEPORT` | N колец = N × (SQ+CQ+registered buffers) памяти; балансировка соединений — на ядре (reuseport hash); нельзя «украсть» работу у простаивающего ядра | **принято** |
| Один общий ring + N потоков submit | проще, один набор registered buffers | конкуренция за `SQ tail` (атомарный CAS), false sharing на головах, сериализация submit, непредсказуемый p99 | отклонено |
| Ring per core + shared SQ (IORING_SETUP_SQPOLL с общим ring) | меньше syscall'ов | тот же false sharing + SQPOLL жжёт ядро + привилегии | отклонено как дефолт, SQPOLL — опция (§5) |
| sharded rings по типу I/O (UDP-ring, TCP-ring, timer-ring) | изоляция классов трафика | удвоение колец и буферов, межкольцевая передача соединений | отклонено |

Обоснование при 8 ядрах и цели 100k qps: 12.5k qps/ядро — это ~80 µs бюджета на запрос, ring-конкуренция не является узким местом, но её вклад в p999 заметен (CAS на `SQ tail` под нагрузкой даёт «хвосты»). Изоляция колец даёт самый предсказуемый хвост при равных затратах памяти.

### 2.3. Правила потока

1. Worker никогда не выполняет блокирующих операций: ни `fsync`, ни `read`, ни `open`, ни `malloc` (см. §13).
2. Всё, что блокирует (коммит зоны, запись логов, DNS-ключи), — на выделенных потоках; общение через `mpsc`/`arc-swap`.
3. Потоки не мигрируют: `pthread_setaffinity_np` + `SCHED_FIFO` для worker'ов (опционально, требует `CAP_SYS_NICE`; по умолчанию `SCHED_OTHER` + `nice -5`).
4. Каждый worker владеет своими сокетами (свои `SO_REUSEPORT`-сокеты на тот же порт), своей таблицей соединений (шард по `hash(4-tuple) % n`), своим таймерным колесом.

---

## 3. Выбор рантайма: собственный мини-исполнитель

### 3.1. Ключевое наблюдение

**Обработка одного DNS-запроса не является асинхронной.** Получив датаграмму, сервер выполняет синхронную функцию:

```
handle(zone_snapshot, request_bytes, response_buf) -> Action   // чистая, ≤ 2 µs
```

Асинхронность нужна только для: (а) приёма следующей пачки, (б) отправки, (в) состояния TCP-соединения, (г) таймеров. То есть поверхность «future-машинерии» мала: конечный автомат на соединение + очередь готовых событий.

### 3.2. Сравнение

| Вариант | Что даёт | Цена | Вердикт |
|---|---|---|---|
| **Tokio** | зрелость, экосистема, `spawn_blocking` | reactor на epoll (io_uring — только через `tokio-uring`, не поддерживается официально); нет доступа к multishot/provided buffers/SQE-батчингу; work-stealing ломает per-core инварианты; аллокация на каждый `spawn`; `hyper` тянет целый мир | отклонено для data-plane, допустимо для control-plane (REST) |
| **monoio** | thread-per-core, io_uring, zero-copy буферы | сторонний проект, свой buffer-модель и свой `AsyncRead/AsyncWrite`; нет epoll-fallback; привязка к одному мейнтейнеру (риск для 5-летнего проекта) | отклонено |
| **glommio** | thread-per-core, io_uring, хорошие буферы | Linux-only без fallback, тяжёлые зависимости, свои примитивы синхронизации; навязывает модель задач | отклонено |
| **`tokio-uring`** | знакомый API | не развивается, требует `Rc`, не даёт multishot, нет контроля над SQ/CQ | отклонено |
| **Собственный мини-исполнитель** (выбрано) | полный контроль над SQE/CQE, батчингом, registered buffers, multishot; один code path для uring/epoll; ноль аллокаций; ~2–3k LOC | надо написать и протестировать `Future`/`Waker`/таймеры; нет экосистемы; выше требования к дисциплине | **принято** |

### 3.3. Объём собственного рантайма

| Компонент | LOC (оценка) | Ответственность |
|---|---|---|
| `reactor::uring` | 700 | setup/probe, submit, CQE-батч, регистрация buffers/files, cancel |
| `reactor::epoll` | 350 | тот же trait, `recvmmsg`/`sendmmsg`, timerfd |
| `executor` | 400 | per-core task queue, `Waker`, `spawn_local`, `block_on`, park/unpark |
| `timer` | 200 | колесо таймеров, дедлайны, `Sleep` |
| `net::{udp,tcp}` | 500 | сокеты, framing, лимиты |
| `buf` | 300 | pbuf-ринги, slab'ы, арены |
| **Итого** | **~2.5k** | |

Риск «изобретаем futures» ограничен: нам нужны только `Waker` + `poll` + очередь готовых задач; никаких generic-тред-пулов, никакого `Send`-апкастинга.

### 3.4. Границы API (эскиз, без реализации)

```rust
// Инициализация
pub struct Runtime { /* N workers */ }
impl Runtime {
    pub fn new(cfg: RuntimeConfig) -> Result<Self, RuntimeError>;
    pub fn backend(&self) -> BackendKind;            // Uring { level } | Epoll
    /// Запускает N worker-потоков и возвращает handle'ы.
    pub fn start<F>(self, per_core: F) -> Result<RuntimeHandle, RuntimeError>
        where F: Fn(WorkerCtx) -> WorkerInit + Send + Sync + 'static;
    pub fn shutdown(self, timeout: Duration) -> ShutdownReport;
}

// WorkerCtx: per-core, !Send
impl WorkerCtx {
    pub fn core_id(&self) -> usize;
    pub fn spawn_local<F: Future<Output = ()> + 'static>(&self, f: F);
    pub fn udp_bind(&self, addr: SocketAddr, opts: UdpOpts) -> Result<UdpSocket, RuntimeError>;
    pub fn tcp_listen(&self, addr: SocketAddr, opts: TcpOpts) -> Result<TcpListener, RuntimeError>;
    pub fn now_mono(&self) -> Mono;                  // без syscall (vDSO/кеш)
    pub fn sleep(&self, d: Duration) -> Sleep;       // таймер на колесе
}

// Порты для application-слоя (domain-model §5.8)
pub trait Spawner { fn spawn(&self, f: Pin<Box<dyn Future<Output = ()> + Send>>); }
pub trait Timer { fn sleep(&self, d: Duration) -> Pin<Box<dyn Future<Output = ()> + Send>>; }
```

Контракт:

- `spawn_local` не требует `Send` и не аллоцирует, если задача помещается в slab-слот.
- Все future, создаваемые транспортом, **не** должны блокировать: `poll` возвращает `Poll::Pending` после постановки SQE.
- `block_on` используется только для control-plane и тестов.
- Один `Future` не может быть опрошен на двух ядрах (нет work-stealing) — это осознанно.

---

## 4. Конфигурация `io_uring`

### 4.1. Параметры ring'а

| Параметр | Значение | Обоснование |
|---|---|---|
| `entries` (SQ) | 1024 | хватает на батч 32 recv + 512 send + accept/timers; больше — растёт латентность submit |
| `cq_entries` | 4096 (4×SQ) | multishot recv генерирует CQE на каждую датаграмму; запас против overflow |
| `flags` | `SINGLE_ISSUER` \| `DEFER_TASKRUN` \| `CLAMP` (+ `COOP_TASKRUN` на 6.0–6.3) | минимум syscall'ов и минимум kernel-side работы |
| `NODROP` | включён при kernel ≥ 6.5 | overflow CQ виден как `-ENOBUFS` на submit, а не тихая потеря CQE |
| `SQPOLL` | выключен (опция, §5) | требует привилегий и отдельного ядра |
| `IORING_SETUP_R_DISABLED` | нет | не нужен |
| `IORING_REGISTER_RESTRICTIONS` | опционально | доступ только к нужным opcode (defense in depth) |

### 4.2. Уровни возможностей (capability levels)

| Уровень | Требование | Что доступно | Поведение |
|---|---|---|---|
| L0 | нет io_uring (`ENOSYS`, seccomp, контейнер) | epoll + `recvmmsg`/`sendmmsg` | полная функциональность, выше CPU |
| L1 | `io_uring_setup` + базовые opcode | recv/send/accept/timeout | без multishot, без pbuf |
| L2 | kernel ≥ 6.0 + `RECV_MULTISHOT` + `PROVIDE_BUFFERS` + `ACCEPT_MULTISHOT` | multishot recv/accept, pbuf-ринги | целевой режим |
| L3 | kernel ≥ 6.5 + `NODROP` + `SINGLE_ISSUER`/`DEFER_TASKRUN` | минимум syscall'ов, детект overflow | рекомендуемый |

Проба при старте:

```
1. io_uring_setup(8, params) → errno? → L0
2. IORING_REGISTER_PROBE → битовая карта opcode
3. проверить наличие: SENDMSG, RECVMSG, ACCEPT, TIMEOUT, ASYNC_CANCEL, LINK_TIMEOUT
4. проверить IORING_RECV_MULTISHOT (recvmsg flags) и IORING_REGISTER_PBUF_RING
5. проверить поддержку флагов (по errno от setup)
6. выставить level = максимальный полностью поддержанный
```

`--io-backend={auto,uring,epoll}` принудительно переопределяет выбор (для тестов и отладки). Уровень и причина деградации логируются один раз при старте и отдаются в `/health` и метрике `runtime_backend_info{kind,level}`.

### 4.3. `user_data` — единый тег

8 байт, чтобы не аллоцировать контекст:

```
bits 0..7    op_kind     (1=RECV, 2=SEND, 3=ACCEPT, 4=TIMEOUT, 5=CANCEL, 6=CONNECT, 7=CLOSE)
bits 8..31   slot        (24 бита: индекс в per-core таблице сокетов/соединений)
bits 32..55  generation  (24 бита: защита от use-after-free при переиспользовании слота)
bits 56..63  flags       (0x01=multishot, 0x02=linked, 0x04=incremental)
```

CQE с неизвестным/устаревшим `generation` → отбрасывается со счётчиком `stale_cqe_total` (не паника).

---

## 5. SQPOLL

| Аспект | Решение |
|---|---|
| По умолчанию | **выключен** |
| Включение | `--io-sqpoll[=idle_ms]`, требует `CAP_SYS_NICE` (или `IORING_SETUP_SQ_AFF` + привилегии) |
| Выигрыш | минус один `io_uring_enter` на батч (~0.3–0.8 µs) на очень высокой нагрузке (> 200k qps/ядро) |
| Цена | поток ядра жжёт целое ядро (busy-poll) или просыпается по `idle_ms` (латентность); +1 ядро к бюджету |
| Рекомендация | только при ≥ 12 ядрах и профиле «чистый UDP ≥ 300k qps»; на 8 ядрах — не включать |

При `SQPOLL` обязательны: `IORING_SETUP_SQ_AFF` с `sq_thread_cpu`, `IORING_SETUP_SQPOLL` + `CQ size ≥ 2×SQ`, мониторинг `sq_thread_idle` и `sq_full` (SQ overflow → `-EBUSY`, обрабатывается как backpressure).

---

## 6. Registered buffers и files

### 6.1. Приём (UDP): provided buffer ring

| Параметр | Значение |
|---|---|
| Размер буфера | 2048 байт (типичный запрос ≤ 512; EDNS-запросы до 1232 влезают) |
| Число буферов | 4096 на ядро (8 МиБ) |
| Механизм | `IORING_REGISTER_PBUF_RING` + `IOSQE_BUFFER_SELECT` |
| Режим | `IOU_PBUF_RING_MMAP` (кольцо в общем mmap) или user-memory ring |
| Политика при `-ENOBUFS` | дослать буферы, пере-вооружить multishot recv, счётчик `pbuf_starve_total` |

Датаграмма больше 2048 байт: `recvmsg` с `MSG_TRUNC` возвращает реальную длину; такие пакеты **считаются и отбрасываются** (`udp_oversize_total`), ответ не формируется (запрос > 2048 байт аномален для DNS: с EDNS клиент обязан укладываться в advertised size; защита от amplification).

### 6.2. Отправка

- **Без `SEND_ZC` в v1.** Ответ копируется один раз из mmap-срезов в TX-слот (неизбежно: нужно вставить ID, флаги, сжать имена). Стоимость ~100–400 нс на 200 байт — приемлемо.
- TX-слоты: slab фиксированного размера 4096 байт × 1024 слота на ядро (4 МиБ), выровнены на 64 байта.
- Слот живёт до CQE отправки; учёт — freelist с `generation` (см. §4.3). Исчерпание слотов → backpressure (§8.3).
- `IORING_REGISTER_FILES` на сокеты worker'а; при `accept` — `IORING_REGISTER_FILES_UPDATE` батчами по 32 (не на каждое соединение).
- `MSG_ZEROCOPY`/`SEND_ZC` — зарезервировано как оптимизация v1.1 (требует учёта двух CQE и удержания буфера).

### 6.3. Регистрация буферов: правила

```
на старте:   register pbuf ring (RX), register files (listen socket)
на accept:   files_update(add fd) батчем
на close:    files_update(remove fd) батчем (или лениво, при накоплении 32)
на shutdown: unregister buffers → ring exit
```

Все регистрации — с `mmap(MAP_LOCKED|MAP_POPULATE)` для исключения page fault в рантайме (`RLIMIT_MEMLOCK` поднимается в systemd unit, §16).

---

## 7. Multishot

| Операция | Механизм | Правило пере-вооружения |
|---|---|---|
| UDP recv | `IORING_OP_RECVMSG` + `IORING_RECV_MULTISHOT` + pbuf | CQE приходит на каждую датаграмму; при `-ENOBUFS` — дослать буферы и выставить SQE снова; при `-ECANCELED` — не вооружать |
| TCP accept | `IORING_OP_ACCEPT` + `IORING_ACCEPT_MULTISHOT` | один SQE на listen-сокет; CQE на каждое соединение; `-EMFILE` → стоп accept на 100 мс (backpressure) |
| TCP recv | **не multishot** | `IORING_OP_RECV` на соединение: нужен точный контроль in-flight и отмены при таймауте |
| TCP send | обычный `IORING_OP_SENDMSG` | одно отправление на ответ; очередь пишется последовательно |

Почему TCP recv не multishot: для соединения нужен строгий учёт «один recv в полёте», иначе невозможно корректно отменить операцию по idle-timeout и посчитать backpressure. Для UDP цена ошибки нулевая (датаграммы независимы), для TCP — утечка SQE.

---

## 8. Event loop, батчинг, backpressure

### 8.1. Основной цикл

```
loop:
  # 1. Дренаж завершений: забрать всё, что есть (без syscall, если CQ не пуст)
  n = cq_peek_batch(&mut cqes[0..MAX_BATCH])       # MAX_BATCH = 256
  for cqe in cqes[0..n]:
      dispatch(cqe)                                # sync, без аллокаций
  # 2. Продвинуть таймеры (только если ближайший дедлайн наступил)
  timers.advance(now_mono())
  # 3. Подготовить исходящие SQEs (recv пере-вооружение, send, accept)
  sqe_prepare_all()
  # 4. Один submit + ожидание
  if sq_ready > 0 or need_wait:
      io_uring_submit_and_wait(ring, min_inflight)  # 1 syscall
  else:
      park_until_woken()                            # futex/eventfd, без io_uring_enter
```

Правила батчинга:

| Правило | Значение | Почему |
|---|---|---|
| Дренаж CQ до submit | всегда | один `io_uring_enter` на цикл |
| Максимум CQE за цикл | 256 | ограничивает хвост латентности одного запроса |
| Максимум SQE за submit | 512 | не раздувать латентность submit |
| Порог «пустого» цикла | `min_inflight = 1` | не жечь CPU при простое |
| Приоритет | recv > send > accept > timers | свежие запросы не ждут отправки старых |

### 8.2. UDP-батч

Один CQE на датаграмму (multishot), но обработка группируется:

```
on_cqe_recv(buf_id, len, src, dst, cmsg):
   slot = tx_alloc()                     # если нет — drop + counter
   action = handle(snapshot, &rx[buf_id][..len], &mut tx[slot])
   rxbuf_return(buf_id)
   if action == Reply: sendmsg_prepare(slot, src, dst)
   if action == Drop:  tx_free(slot)
```

`sendmsg` подготавливается с `msg_name = src` (для wildcard-bind обязателен `IP_PKTINFO`/`IPV6_RECVPKTINFO`; ответ уходит с того же адреса, на который пришёл запрос).

### 8.3. Backpressure (обязателен, не «best effort»)

| Ресурс | Порог | Действие |
|---|---|---|
| TX-слоты | < 5% свободных | перестать вооружать multishot recv (backpressure на уровне ядра: датаграммы копятся в `SO_RCVBUF`, затем дропаются ядром); счётчик `tx_pressure_total` |
| SQ ring | `sq_ready > SQ-64` | сначала дренаж CQ, затем submit |
| CQ overflow (`-ENOBUFS` при NODROP) | любой | немедленно дренаж CQ; если повторно — стоп recv на 1 мс, `cq_overflow_total` |
| Accept | `conns_total > 0.9 * max` | приостановить multishot accept |
| Files/depth на соединение | `inflight > max_inflight` | не читать дальше (TCP flow control) |

Принцип: **лучше дропнуть на входе (UDP) или притормозить чтение (TCP), чем накапливать очередь и получать p999 в секунды.**

---

## 9. Таймеры и отмена

### 9.1. Таймерное колесо

- Одно колесо на worker, гранулярность 1 мс, 512 слотов (диапазон 512 мс) + overflow-список для длинных дедлайнов.
- Источник времени: `clock_gettime(CLOCK_MONOTONIC)` через vDSO, кешируется на цикл (`now_mono` в `WorkerCtx`).
- Пробуждение: один `IORING_OP_TIMEOUT` (или `TIMEOUT_UPDATE` при L2+), взведённый на ближайший дедлайн, с `min = 1 мс`. В epoll-бэкенде — `timerfd` или таймаут `epoll_wait`.
- Стоимость: O(1) вставка/удаление, O(k) на тик.

### 9.2. Что таймеризуется

| Объект | Значение по умолчанию | Действие по истечении |
|---|---|---|
| TCP idle (нет данных) | 30 с | закрыть |
| TCP slow-reader (частичный кадр) | 10 с | закрыть, `tcp_slowloris_total` |
| TCP in-flight запрос | 5 с | закрыть соединение (клиент не читает ответы) |
| TCP write-queue stall | 30 с | закрыть |
| rate-limit bucket refill | 100 мс | пересчёт (см. API-слой) |
| zone snapshot republish | по событию | не таймер |
| DNS cookie secret rotation | 1 ч | ротация (M3+) |

### 9.3. Отмена

- `IORING_OP_ASYNC_CANCEL` с `user_data`-тегом, `IORING_ASYNC_CANCEL_ALL` при закрытии соединения.
- После `cancel` всегда дожидаемся CQE (`-ECANCELED`) прежде чем освобождать слот/буфер; иначе use-after-free в kernel'е.
- Таймаут на операцию: `IORING_OP_LINK_TIMEOUT` — **не используется** (плодит SQE на каждую операцию); вместо этого — колесо + cancel по дедлайну.
- Флаг `generation` в `user_data` защищает от «позднего» CQE после переиспользования слота.

---

## 10. UDP-путь

### 10.1. Сокеты

| Параметр | Значение | Комментарий |
|---|---|---|
| `SO_REUSEPORT` | включён, один сокет на worker | ядро хеширует 4-tuple, трафик распределяется без локов |
| `SO_RCVBUF` / `SO_SNDBUF` | 4 МиБ / 4 МиБ (поднимать `net.core.rmem_max`) | против дропов при всплесках |
| `IP_PKTINFO` / `IPV6_RECVPKTINFO` | включены | корректный source address на wildcard-bind |
| `SO_BUSY_POLL` | опционально (0..50 µs) | снижает latency при низкой нагрузке, жжёт CPU; по умолчанию off |
| `SO_INCOMING_CPU` | проверяется в отладке | контроль, что reuseport не «перекидывает» пакеты между ядрами |
| `UDP_GRO` | выключен | не нужен: каждая датаграмма — отдельный запрос |
| IPv6 | dual-stack сокет `IPV6_V6ONLY=0` | один сокет на оба семейства, addr хранится в `sockaddr_storage` |

### 10.2. Приём

- L2+: один `IORING_OP_RECVMSG` с multishot + pbuf-ринг на сокет.
- L1/L0: `recvmmsg` батчами 32 (epoll edge-triggered), `MSG_DONTWAIT`.
- `MSG_TRUNC` проверяется всегда: усечённый запрос не парсится.

### 10.3. EDNS и усечение

```
max_response(no OPT)                  = 512
max_response(OPT, udpsize)            = clamp(udpsize, 512, 4096)
max_response(OPT, udpsize < 512)      = 512
```

Правила:

1. Более одного OPT, OPT не в additional или его owner ≠ root → `FORMERR`.
2. `EDNS version > 0` → `BADVERS` с пустым ответом и OPT с нашей версией.
3. Ответ не влезает → установить `TC=1`, **обрезать по границам RRset** (никогда не разрывать RRset), оставить вопрос; в additional — OPT (если запрос его содержал).
4. Без EDNS и ответ > 512 → `TC=1`, тело = только вопрос (минимальный ответ; клиент повторит по TCP).
5. `DO`-бит пробрасывается в домен; DNSSEC-записи включаются только при `DO` (RFC 4035 §3.2.1).
6. EDNS padding (RFC 7830) не применяется к plain UDP; зарезервирован для DoT/DoH.

### 10.4. Стоимость пути (цель)

| Шаг | Время (тёплый кеш) |
|---|---|
| CQE dispatch | ~30 нс |
| парсинг заголовка+вопроса | ~80 нс |
| нормализация имени в RLE | ~60 нс |
| поиск зоны + RRset (§zonefile 20) | 150–500 нс |
| сборка ответа (1 копия) | 150–350 нс |
| подготовка SQE + submit (амортизировано) | ~100 нс |
| **Итого** | **~0.6–1.2 µs** |

При 12.5k qps/ядро бюджет 80 µs — запас 60–100×, которого хватает на всплески и на DNSSEC-подпись/валидацию на отдельных путях.

---

## 11. TCP-путь

### 11.1. Framing

- Length-prefixed: `u16` длина сообщения, big-endian (RFC 1035 §4.2.2), затем сообщение. Длина 0 недопустима; максимум 65535.
- Один `read` может содержать несколько сообщений (pipelining) и часть следующего → парсер работает по буферу с сохранением состояния.
- Ответы могут уходить не в порядке запросов, но `ID` обязан совпадать с запросом (RFC 7766 §6.2.1.1).

### 11.2. Состояние соединения

```
Conn {
  fd, gen,
  rx: { buf: [u8; 4096] или pooled до 64K, len, want },   // want = ожидаемая длина кадра
  inflight: smallvec<[{ id: u16, deadline: Mono }]>,       // ≤ max_inflight
  tx: ring-буфер исходящих ответов (слоты из slab),
  state: Reading | Writing | Draining | Closing,
}
```

Правила:

| Параметр | Значение | Обоснование |
|---|---|---|
| `max_inflight` на соединение | 16 (configurable 1..64) | защита от amplification через pipelining |
| `max_message` | 65535 | предел протокола |
| начальный rx-буфер | 4096 (из пула) | типичный запрос ≤ 512 |
| рост rx-буфера | до 64 KiB, только при валидном префиксе длины | против «мусорного» роста |
| `TCP_NODELAY` | включён | ответ должен уходить сразу |
| `max_conns_total` | `ulimit -n` × 0.8 (по умолчанию 64k) | запас на zone file, API, метрики |
| `max_conns_per_ip` | 256 (хеш-счётчик на ядро) | защита от одного клиента |
| accept-бюджет за цикл | 64 | не голодать recv |

### 11.3. Защита от медленных клиентов

| Атака | Механизм |
|---|---|
| Slowloris (медленная отправка кадра) | нет прогресса `want` за 10 с → `close`, `tcp_slowloris_total` |
| Pipelining-флуд (много запросов без чтения ответов) | `max_inflight` + write-queue cap 64 KiB → перестаём читать (TCP flow control) |
| Медленное чтение ответов | `inflight.deadline` 5 с → `close` |
| Полуоткрытые соединения | `max_conns_total`, `SYN`-очередь ядра (`somaxconn`, syncookies), accept-throttling |
| Мелкие кадры (1 байт) | префикс читается только целиком; буфер не растёт без валидной длины |
| Долгие AXFR (легитимные) | отдельный лимит: AXFR-соединение не считается idle, но имеет бюджет `max_axfr_duration` (по умолчанию 10 мин) |

### 11.4. AXFR/IXFR

- Потоковая отдача: `enumerate` зоны (канонический порядок) → сериализация в TX-слоты → sendmsg по мере освобождения слотов.
- Backpressure: если TX-слоты кончились — приостановить итератор (не материализовать зону в память). Итератор зоны держит снапшот, поэтому writer не переиспользует страницы (§zonefile 14).
- Размер сообщения ≤ 65535; разбиение по RRset-границам.
- `IXFR`: при отсутствии истории (v1) — деградация до AXFR с корректным SOA-сравнением (решение домена).

---

## 12. Fallback: `epoll` и абстракция

### 12.1. Трейты (внутренние для `pulse-runtime`)

```rust
pub trait Reactor {
    fn submit(&mut self, ops: &mut OpBatch) -> Result<usize, IoError>;
    fn wait(&mut self, timeout: Option<Duration>) -> Result<CompletionBatch, IoError>;
    fn register_buffers(&mut self, bufs: &BufferRing) -> Result<(), IoError>;
    fn register_files(&mut self, fds: &[RawFd]) -> Result<(), IoError>;
    fn cancel(&mut self, tag: Tag) -> Result<(), IoError>;
    fn capabilities(&self) -> Caps;
}

pub struct Caps {
    pub backend: BackendKind,          // Uring{level} | Epoll
    pub multishot_recv: bool,
    pub provided_buffers: bool,
    pub registered_files: bool,
    pub sqpoll: bool,
    pub op_batching: u16,              // макс. SQE за submit
}
```

`OpBatch`/`CompletionBatch` — фиксированные массивы на стеке (или в per-core структуре), без `Vec` на hot-path.

### 12.2. epoll-бэкенд

| Аспект | Реализация |
|---|---|
| Регистрация | `epoll_ctl(ADD, EPOLLET | EPOLLIN | EPOLLOUT)` на сокет |
| UDP приём | `recvmmsg(..., 32, MSG_DONTWAIT)` в цикле до `EAGAIN` |
| UDP отправка | `sendmmsg(..., 32)` |
| TCP accept | `accept4(SOCK_NONBLOCK)` в цикле до `EAGAIN`, бюджет 64 |
| TCP recv/send | `read`/`write` в неблокирующем режиме |
| Таймеры | `timerfd` + `epoll` (или таймаут `epoll_wait`, взведённый на ближайший дедлайн) |
| Отмена | нет аналога: операция либо завершилась, либо не начиналась (все операции неблокирующие) — упрощает модель |
| Стоимость | +1 syscall на пачку (epoll_wait) + 1 syscall на recvmmsg-батч |

Эквивалентность семантики:

| Возможность | uring L3 | epoll |
|---|---|---|
| «Fire and forget» отправка | CQE | `sendmmsg` возвращает число отправленных; очередь досылается на `EPOLLOUT` |
| Отмена по таймауту | `ASYNC_CANCEL` | закрытие сокета / удаление из очереди |
| Batching | SQ/CQ | `recvmmsg`/`sendmmsg` |
| Zero-copy RX | pbuf ring | буферы из slab, копирование из MSG-буфера невозможно → **+1 копия** |

**Единственное реальное расхождение:** epoll-бэкенд делает одну лишнюю копию на приём (нет provided buffers). Это документируется в отчёте бенчмарка; целевые метрики M1 формулируются для uring-L3, epoll — «не хуже 70% qps».

### 12.3. Тестирование паритета

- Все интеграционные тесты транспорта гоняются дважды: `PULSE_IO_BACKEND=uring` и `=epoll` (CI-матрица).
- Тест «одинаковый ответ»: один и тот же набор запросов через оба бэкенда → байт-в-байт идентичные ответы (кроме порядка).

---

## 13. Правила «неблокирующего» пути

### 13.1. Запрещено на горячем пути

| Запрет | Почему | Как проверяется |
|---|---|---|
| любой syscall, кроме `io_uring_enter`/`epoll_wait` | 0.5–2 µs каждый | `strace -c -f` в нагрузочном тесте: счётчик syscall'ов ≈ числу submit'ов |
| `malloc`/`free` | до 200 нс + деградация под многопоточностью | счётчик аллокатора в тесте (`0 allocs/query`) |
| `Mutex`, `RwLock` (на запись) | блокировки и priority inversion | линт + `perf lock` |
| `open`, `stat`, `read` файлов | блокирующий I/O | статический анализ + ревью |
| `println!`, `tracing` с I/O | блокировка на write | логи только в ring-буфер (§15) |
| `mmap`/`munmap`/`mremap` | TLB shootdown | карта создаётся один раз |
| `gettimeofday` без vDSO | syscall | проверка `clock_gettime` через vDSO (`perf` не показывает syscall) |
| Паника в обработчике | падение worker'а | `catch_unwind` на границе задачи + счётчик |

### 13.2. Разрешено

| Примитив | Где | Порядок памяти |
|---|---|---|
| `AtomicU64::load` | снапшот зоны, счётчики чтения | `Acquire` для указателя, `Relaxed` для счётчиков |
| `AtomicU64::store` | reader-slot `active_txn`, публикация снапшота | `Release` |
| `AtomicU64::fetch_add` | per-core счётчики (только свой core) | `Relaxed` (или plain `u64`, если не читаются извне) |
| `arc-swap` load | конфиг, ключи DNSSEC, снапшот | `Acquire` (внутри) |
| `checked_*` арифметика | парсинг | — |
| `prefetch` | страницы зоны по пути спуска | — |

### 13.3. Где допустимы блокировки

| Объект | Примитив | Почему безопасно |
|---|---|---|
| Публикация снапшота зоны | `arc-swap` (lock-free) | читатель никогда не блокируется |
| Таблица читателей | атомарные `u64` | требуется только writer'у |
| Менеджер соединений (admin) | `Mutex` | вне hot-path |
| Коммит зоны | `Mutex` внутри `Writer` | выделенный поток, не hot-path |
| REST API | обычные `Mutex`/`RwLock` | отдельный пул потоков |
| Метрики | per-core atomics + агрегатор | нет общих счётчиков на hot-path |

### 13.4. Per-core структуры (обязательно)

| Структура | Причина |
|---|---|
| таблица соединений (шард) | нет CAS на общем счётчике, нет false sharing |
| TX/RX slab'ы и арены | нет общего аллокатора |
| таймерное колесо | нет глобального лока |
| счётчики | `#[repr(align(128))]` на каждый счётчик (защита от false sharing) |
| кеш `now_mono` | один vDSO-вызов на цикл |
| буфер нормализации имени | на стеке (256 байт) |

Общее (read-only или очень редкая запись): mmap зон, конфиг (`arc-swap`), ключи DNSSEC (`arc-swap`), статистика (append-only per-core).

---

## 14. Память

| Назначение | Механизм | Размер (на ядро) |
|---|---|---|
| RX provided buffers (UDP) | pbuf ring, 4096 × 2048 | 8 МиБ |
| TX-слоты ответов | slab 1024 × 4096 | 4 МиБ |
| rx-буферы TCP | пул 4096 × 4096 (рост до 64K) | до 16 МиБ |
| conn-таблица | slab 8192 × ~256 байт | 2 МиБ |
| транзиентные аллокации запроса | bump-арена 64 КиБ, сброс на батч | 64 КиБ |
| логи | ring-буфер 1 МиБ, дренаж отдельным потоком | 1 МиБ |
| **Итого** | | **~31 МиБ/ядро → ~250 МиБ на 8 ядер** |

Правила:

- Все буферы выделяются один раз; `Vec::with_capacity` — только на старте.
- `MAP_POPULATE | MAP_LOCKED` для сетевых буферов (нет page fault в рантайме).
- Арена сбрасывается на каждый батч: «мусор» не накапливается, размер ограничен.
- `mlock` зонного файла — опционально (`--mlock-zones`), иначе полагаемся на page cache; `MADV_WILLNEED` при открытии.
- Утечки в рантайме невозможны по построению (нет динамических контейнеров), но проверяются счётчиками `slots_in_use`.

---

## 15. Наблюдаемость

| Метрика | Тип | Где считается |
|---|---|---|
| `queries_total{proto,rcode}` | counter | per-core, агрегация 1 c |
| `udp_oversize_total`, `udp_truncated_total` | counter | hot-path (relaxed) |
| `pbuf_starve_total`, `tx_pressure_total`, `cq_overflow_total` | counter | hot-path |
| `tcp_conns{state}` | gauge | per-core |
| `tcp_slowloris_total`, `tcp_idle_close_total` | counter | таймер |
| `runtime_backend_info{kind,level}` | gauge | старт |
| `latency_us` (histogram, HDR) | histogram | per-core, агрегация |
| `zone_snapshot_txn`, `zoneindex_rebuild_ms` | gauge | application |

Логирование: только в per-core ring-буфер (lock-free, SPSC), дренаж — отдельным потоком. На hot-path `tracing` запрещён.

Профилирование: счётчики `io_uring` через `io_uring_register`/`IORING_REGISTER_PBUF_STATUS` не используются; при отладке — `bpftrace` uprobe на обработчик.

---

## 16. Системная конфигурация

| Параметр | Значение | Где |
|---|---|---|
| `net.core.rmem_max`, `wmem_max` | 16 МиБ | sysctl |
| `net.core.somaxconn` | 8192 | sysctl |
| `net.ipv4.tcp_max_syn_backlog` | 8192 | sysctl |
| `net.ipv4.tcp_syncookies` | 1 | sysctl |
| `net.ipv4.ip_local_port_range` | 10240 65535 | sysctl (для исходящих AXFR/NOTIFY) |
| `fs.file-max`, `LimitNOFILE` | 262144 | systemd |
| `LimitMEMLOCK` | infinity (для `MAP_LOCKED`, io_uring buffers) | systemd |
| `kernel.io_uring_disabled` | 0 (проверяется при старте) | sysctl |
| NIC: очереди RX | ≥ 8, IRQ affinity по ядрам | ethtool |
| CPU governor | `performance` | cpufreq |
| Transparent Huge Pages | `madvise` (не `always`) | sysfs |
| TLS | не используется | — |

Проверки при старте (fail-fast или warning в зависимости от критичности) — в `/health` и в отчёте `pulsed --diagnose`.

---

## 17. Открытые вопросы

1. **Языковой рантайм для control-plane (REST).** Свой исполнитель или `tokio` в отдельном пуле потоков? Предлагаю `tokio` только для `pulse-api` (отдельный пул), чтобы не тащить его в data-plane. Требует подтверждения Оркестратора.
2. **`SEND_ZC`** в v1.1: нужен ли он при цели 100k qps? Оценка выигрыша — 100–200 нс на ответ, но +сложность учёта буферов. Предлагаю отложить.
3. **`io_uring` в контейнерах.** Часть окружений блокирует `io_uring` через seccomp (Docker default до 24.x). Нужно ли гарантировать «не хуже 70% qps» на epoll в M1 или это цель M3?
4. **`max_inflight` TCP** = 16: подтвердить, исходя из профиля (рекурсивные резолверы шлют пачки; authoritative — обычно 1).
5. **`SO_BUSY_POLL`**: включать ли по умолчанию при `latency-critical` профиле (жжёт CPU, требует `CAP_NET_ADMIN`)?
6. **Мульти-очередь NIC ↔ `SO_REUSEPORT`**: нужен ли eBPF `SO_ATTACH_REUSEPORT_EBPF` для стабильного хеширования или достаточно встроенного?
7. **Границы `Handler`:** где именно живёт `handle()` — синхронная функция в `pulse-server` (application вызывает домен), а транспорт даёт буферы. Нужно синхронизировать сигнатуры с DDD-архитектором (§20.3 zonefile-спеки).
8. **`SCHED_FIFO` для worker'ов** по умолчанию или нет? Влияет на другие процессы на хосте; предлагаю off по умолчанию, флаг `--realtime`.
