# Пул keep-alive соединений DoT/DoH upstream

Дата: 2026-11-24. Относится к `pulse-resolver` (клиент) и `pulseresolved`
(конфигурация/метрики), реализация — `pulse-tls::pool`.

## Зачем

До изменений каждый DoT/DoH upstream держал **одно** соединение под общим
`Mutex`: параллельные запросы к защищённому upstream сериализовались, а
падение единственного соединения давало паузу всем запросам. Пул из N
keep-alive соединений снимает сериализацию и даёт явный лимит in-flight.

## Конфигурация

`ResolverConfig::pool` (`UpstreamPoolConfig`):

| Поле | По умолчанию | Смысл |
|---|---|---|
| `size` | `4` | число соединений = лимит одновременных запросов к одному upstream (1..=64) |
| `reconnect_backoff` | `100 ms` | начальная задержка после неудачного connect |
| `max_reconnect_backoff` | `5 s` | потолок экспоненциального backoff |

`pulseresolved` (TOML/JSON):

```toml
[upstream_pool]
pool_size = 4                  # alias: size
reconnect_backoff_ms = 100
max_reconnect_backoff_ms = 5000
```

```json
"upstream_pool": {
  "pool_size": 4,
  "reconnect_backoff_ms": 100,
  "max_reconnect_backoff_ms": 5000
}
```

UDP/TCP upstream не используют пул (у них один сокет/соединение на запрос).

## Алгоритм

- Слоты пула: `Empty`, `Busy`, `Idle(conn)`. Пул **ленивый**: сначала
  сканируются idle-слоты (последовательный трафик переиспользует одно
  соединение), затем пустые — в них открывается новое; если все слоты `Busy`,
  запрос ждёт свободный слот с шагом 1 ms до общего дедлайна и получает
  таймаут.
- Каждое соединение используется одним запросом за раз (без pipelining):
  DoT — length-prefixed DNS, DoH — HTTP/1.1 `POST /dns-query`
  (`Connection: keep-alive`, `Content-Length`).
- Ошибка обмена (закрытие, reset, таймаут I/O) выбрасывает соединение
  (`discard`) и повторяет запрос **один раз** с новым соединением. Ошибки
  проверки сертификата и cooldown не повторяются.
- Health/cooldown: неудачный `connect` увеличивает счётчик отказов, пул
  уходит в cooldown до `min(initial * 2^(n-1), max)`; успешный connect
  сбрасывает счётчик. Cooldown блокирует только **создание** соединений —
  открытые idle-соединения продолжают обслуживать запросы.
- Forwarder-уровень (`max_failures`/`cooldown` в `ForwardConfig`) продолжает
  работать поверх пула и отвечает за failover на другой upstream.

## Метрики

В `/metrics` (`pulseresolved_upstream_pool_*`) и в `pulse_resolver::UpstreamStats.pool`:

| Метрика | Смысл |
|---|---|
| `..._pool_opens_total` | открыто соединений |
| `..._pool_reuses_total` | выдач уже открытого соединения |
| `..._pool_waits_total` | запросов, ждавших свободный слот |
| `..._pool_discards_total` | сброшено сломанных соединений |
| `..._pool_connect_failures_total` | неудачных connect |
| `..._pool_cooldowns_total` | отказов из-за активного cooldown |

## Тесты

- `pulse-tls` unit: последовательное переиспользование, параллельное
  заполнение слотов, `discard`, cooldown/backoff, таймаут занятого пула.
- `pulse-tls/tests/client.rs`: 32 параллельных запроса через DoT и DoH —
  сервер видит ≤ 4 соединений, все ответы совпадают с запросами; обрыв
  соединения → `reconnects = 1`, `discards = 1`.
- `pulse-resolver/tests/upstream_pool.rs`: **100** параллельных запросов
  через self-signed `DotServer`/`DohServer` (`pool_size = 4`), проверка
  отсутствия потерь/гонок, переиспользования и переподключения после обрыва.
- `cargo bench -p pulse-resolver --bench resolver` — группа `resolver/pool`
  (8 потоков × 10 запросов через DoT-пул).

### Числа (loopback, self-signed DoT, rustls, хост под нагрузкой)

| Сценарий | Время на 80 запросов | Throughput |
|---|---|---|
| `pool_size = 4`, 8 потоков × 10 | 12.0 ms (11.0–13.1 ms) | ≈ 6.7k q/s |
| `pool_size = 1`, 8 потоков × 10 | 25.4 ms (24.5–26.4 ms) | ≈ 3.2k q/s |

Пул из 4 соединений даёт ≈ 2.1× на этом профиле; числа консервативные
(loopback, загруженный хост, полный TLS-record на каждый запрос).

## Ограничения

- DoH upstream — только HTTP/1.1 (HTTP/2 upstream не реализован; клиент h2
  требует async-рантайма и вне текущего объёма).
- Пул не ограничивает число upstream: лимит действует на каждый upstream.
- Порядок выдачи соединений не гарантирует fair-share между потоками.
