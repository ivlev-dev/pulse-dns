# Offline `fsck` для pulse-zonefile v2

`pulsed fsck` проверяет durable-состояние файла зон **до** запуска сервера
(offline). Сервер не должен держать writer-lock: режим проверки (без
`--repair`) открывает файл read-only без блокировки, `--repair` берёт `LOCK_EX` и отказывает, если файл
занят живым writer'ом.

```bash
# только проверка (exit 0 — чисто, 1 — есть замечания/порча)
pulsed fsck --data /var/lib/pulse/zones.v2

# вернуть безопасные утечки в free-пул и изолировать повреждённые зоны
pulsed fsck --data /var/lib/pulse/zones.v2 --repair
```

## Что проверяет проверка (без `--repair`)

- достижимость деревьев всех зон (leaf/branch/overflow), chain-страниц,
  bucket-страниц и каталога зон;
- `page.txn ≤ version` и `owner_zone` каждой прочитанной страницы;
- `root_page`/`meta_root`/`free_head`/`prev_record` внутри
  `page_limit_at_commit`, а лимит — внутри `DP`;
- `DP = reachable ∪ pools ∪ leaked`: утечки не ошибка (крах/aborted), но
  считаются и показываются;
- дизъюнктность `tree`/`chain`/`bucket`/`free` (пересечение — file-fatal);
- `fsck_lite`: `LayoutHead` A/B, `ALLOC_RECORD` A/B, watermark'и, ring-цепочки.

Множества страниц хранятся битсетом (`DP / 8` байт на набор), поэтому проверка
больших файлов не раздувает RSS.

## Классы повреждений

| Класс | Поведение |
|---|---|
| file-fatal (`owner_zone`, `page.txn > version`, пересечение множеств, регрессия `DP`/`DT`) | проверка завершается с ошибкой; запись в файл запрещена; `--repair` отказывает |
| zone-fatal (CRC/`page_no`/`payload_len`/уровень дерева/overflow/chain/пул зоны) | зона попадает в `damaged_zones`; остальные зоны проверяются |
| утечка `[data_first, DP)` | не ошибка; `--repair` возвращает безопасные страницы в пул |

## `--repair`

1. Помечает каждую zone-fatal зону `NEEDS_FSCK` в durable-записи корня
   (`RootFlags::NEEDS_FSCK`). Пишутся только две копии `RootEntry`; дерево,
   overflow, chain и пулы **не изменяются**.
2. Возвращает утёкшие страницы в bucket-пул каталога (`owner_zone = 0`).
   Страницы ниже `page_limit_at_commit` повреждённой зоны **не** возвращаются:
   они могут принадлежать её недоступному дереву. Они показываются как
   `deferred_leaks` и остаются в отчёте.
3. Идемпотентен: повторный запуск на чистом/изолированном файле возвращает
   `repaired_pages = 0` и не создаёт новых версий.

Отчёт содержит `repaired_pages`, `remaining_leaks`, `deferred_leaks`,
`quarantined_zones`, `ok` и диагностические `issues`. `ok = true` означает:
file-fatal нет, все безопасные утечки возвращены, повреждённые зоны
изолированы.

## Восстановление после падения

Если проверка показала file-fatal, файл нужно разобрать вручную: `--repair`
намеренно не «чинит» пересечения/чужого владельца/`page.txn > version`.
Сохраните копию файла перед любыми ручными правками. После устранения причины
повторите:

```bash
pulsed fsck --data zones.v2 --repair
pulsed fsck --data zones.v2
```
