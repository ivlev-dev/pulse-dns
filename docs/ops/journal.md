# Write-ahead journal (outbox) REST-мутаций

`pulsed` пишет журнал намерений для каждой REST-мутации (`PUT`/`PATCH`/`DELETE`
зон, RRset и настроек). Журнал закрывает окно между применением правки к
`pulse-zonefile` и подтверждением клиенту: `2xx` отдаётся только после
zonefile-коммита и записи `committed` в журнал.

## Файл

По умолчанию журнал лежит рядом с zonefile: `<data>.journal`
(например, `/var/lib/pulse/zones.v2.journal`). Путь и порог задаются в
конфигурации:

```toml
journal = true                 # по умолчанию true
journal_path = "/var/lib/pulse/zones.journal"  # по умолчанию <data>.journal
journal_max_bytes = 8388608    # порог compaction, минимум 4096
journal_fsync = true           # fsync intent/committed/aborted
```

Журнал — append-only. Запись открывается с `O_APPEND`; при `journal_fsync =
true` каждая запись синхронизируется `fdatasync`.

### Формат (версия 1)

Заголовок (16 байт):

| Смещение | Размер | Поле |
|---|---|---|
| 0 | 8 | magic `PULSEJNL` |
| 8 | 4 | версия формата (`u32 LE`, сейчас `1`) |
| 12 | 4 | CRC32 заголовка (`magic + version`) |

Кадр:

| Размер | Поле |
|---|---|
| 4 | длина payload (`u32 LE`) |
| 4 | CRC32 payload (IEEE, `u32 LE`) |
| N | payload: JSON-запись |

Записи:

```json
{"record":"intent","seq":1,"intent":{
  "op_id":"…","timestamp_unix_ns":…,"method":"PUT",
  "path":"/api/v1/zones/example.com.",
  "body_sha256":"…","expected_etag":"z1-v3-t7",
  "expected_version":3,"if_none_match":null,
  "operation":{"op":"put_rrset","origin":"example.com.",
    "owner":"www.example.com.","rr_type":"A","ttl":300,
    "records":["192.0.2.10"]}}}
{"record":"committed","seq":2,"op_id":"…","version":8,
  "response":{"status":201,"headers":[["ETag","\"rr_…\""]],
              "body_b64":"…"}}
{"record":"aborted","seq":3,"op_id":"…","reason":"zone-busy",
  "response":{…}}
```

`seq` монотонно растёт. Секреты (заголовок `Authorization`, тело запроса) в
журнал не попадают: хранятся только метод/путь, SHA-256 тела, ожидаемый
`ETag`/версия и нормализованная операция. Тело ответа хранится для точного
идемпотентного replay.

## Жизненный цикл

1. Запрос проходит аутентификацию, scope, rate limit и in-memory
   `Idempotency-Key`.
2. `intent` пишется и синхронизируется **до** применения.
3. `ZoneAdmin` применяет операцию и коммитит zonefile.
4. `committed` фиксирует версию и HTTP-ответ.
5. Только после шага 4 клиент получает `2xx`.

При ошибке коммита zonefile или записи `committed` API отвечает `500`, а
`intent` остаётся. Повтор с тем же `Idempotency-Key` идемпотентен: операция
либо уже применена (проверка целевого состояния), либо применяется один раз.

Клиентские ошибки (`4xx`) пишутся как `aborted`, чтобы recovery не повторял
заведомо невалидную операцию. Исключение — retryable-ошибки (`zone-busy`
409, `precondition-failed` 412, `precondition-required` 428): они помечаются
`retryable` и не блокируют повтор с тем же `Idempotency-Key` (новая запись
`intent` вместо replay).

## Идемпотентность

`op_id` детерминированно выводится из `(token, method, path, Idempotency-Key)`.
Без заголовка `op_id` уникален для запроса; crash-recovery всё равно применит
намерение ровно один раз.

После рестарта повтор с тем же `Idempotency-Key`:

- возвращает сохранённый HTTP-ответ, если `committed` успел записаться;
- иначе (crash между zonefile-коммитом и `committed`) — проверяет, что
  операция уже применена по состоянию, дописывает `committed` без ответа и
  отдаёт текущее состояние ресурса (`200` вместо `201` в этом узком окне);
- иначе применяет операцию один раз.

## Recovery

На старте, до запуска транспортов, сервер читает журнал:

1. Проверяет заголовок. Несовместимая версия → отказ старта с сообщением
   `journal ... uses format version N, but this binary supports only version 1`.
2. Сканирует кадры. Первый невалидный кадр (обрыв длины, CRC, JSON) считается
   повреждённым хвостом: файл обрезается до последнего валидного кадра,
   предыдущие операции сохраняются.
3. Для каждого `intent` без `committed`/`aborted`:
   - если целевое состояние уже достигнуто — `committed` без повторного
     применения;
   - иначе операция применяется и пишется `committed`;
   - клиентская ошибка → `aborted`;
   - ошибка хранилища → старт прерывается, `intent` остаётся для следующей
     попытки.

Recovery выполняется до открытия API, поэтому после рестарта не бывает
«полуприменённых» подтверждённых операций.

## Compaction

При достижении `journal_max_bytes` журнал атомарно переписывается во временный
файл (`<path>.compact`, `fsync`, `rename`, `fsync` каталога). Сохраняются:

- **все** незавершённые `intent`;
- последние `1024` завершённых записей (для идемпотентных повторов).

Старый файл не изменяется до успешного `rename`. Ошибка compaction не ломает
запись: журнал продолжает расти, счётчик `journal_errors_total` увеличивается.

## Метрики

`GET /metrics`:

```
journal_intents_total
journal_replays_total
journal_compactions_total
journal_errors_total
```

`journal_replays_total` учитывает recovery-применения и HTTP-replay из
журнала. `journal_errors_total` — I/O, повреждение/обрезка хвоста, ошибки
compaction и тестовые инъекции.

## Тестовые хуки

Только debug-сборки; в release игнорируются:

- `PULSED_JOURNAL_CRASH=after_intent|after_apply|after_committed` — процесс
  убивает себя `kill -9` в указанной фазе (`after_apply` — после
  zonefile-коммита, до `committed`);
- `PULSED_JOURNAL_FAULT=commit` — однократная ошибка записи `committed`
  (API отвечает `500`, intent сохраняется).

Интеграционные тесты: `crates/pulsed/tests/journal.rs`. Unit-тесты формата,
повреждённого хвоста и compaction: `crates/pulse-api/src/journal.rs`.

## Ограничения

- Один процесс-писатель (как и `pulse-zonefile` v2); межпроцессная запись не
  поддерживается.
- `journal_fsync = false` отключает durability журнала: crash может потерять
  `intent`, но не повреждает zonefile.
- `POST /zones/{origin}/sign` не журналируется (переподпись идемпотентна по
  данным и не является операцией из scope zone/rrset/settings).
- Recovery использует эвристику «целевое состояние уже достигнуто» для
  узкого окна crash между zonefile-коммитом и `committed`; для `PUT`/`PATCH`
  это сравнение TTL/набора RDATA, для настроек — сравнение полей.
- Журнал не заменяет `fsck` zonefile: после crash рекомендуется
  `pulsed fsck --data <file>`.
- При офлайн-замене zonefile (`pulsed import`, `pulsed convert`, ручная
  подмена файла) удалите старый `<data>.journal` или задайте новый
  `journal_path`: журнал не привязан к inode файла. Для обычного
  рестарта/краха этого делать не нужно.
