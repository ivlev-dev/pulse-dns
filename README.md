# pulse-dns

Модульный высокопроизводительный DNS-сервер на Rust: авторитетный (authoritative) и рекурсивный резолвер. io_uring, mmap, REST API.

## Структура репозитория

| Крейт | Назначение | Статус |
|---|---|---|
| `pulse-zonefile` | Парсинг/сериализация zonefile | планируется |
| `pulse-dns` | Wire-формат DNS | планируется |
| `pulse-runtime` | Общее время выполнения / io_uring | планируется |
| `pulse-server` | Авторитетный сервер (UDP/TCP, primary/secondary) | планируется |
| `pulse-resolver` | Рекурсивный резолвер | планируется |
| `pulse-api` | REST API | планируется |
| `pulsed` | Бинарник авторитетного сервера | планируется |
| `pulseresolved` | Бинарник рекурсивного резолвера | планируется |

## Статус

M0 — проектирование.

## Требования

- Linux
- Rust stable (1.99+)

## Быстрый старт

```bash
cargo build
```

## Лицензия

MIT OR Apache-2.0. См. `LICENSE-MIT` и `LICENSE-APACHE`.
