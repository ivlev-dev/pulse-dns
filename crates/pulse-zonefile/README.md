# pulse-zonefile

Формат файла зон pulse v1: page-based COW B+tree, двойная meta, MVCC-читатели,
freelist и offline `fsck`. Спецификация — `docs/spec/zonefile-v1.md`.

## Известные ограничения (v1)

- **Freelist пересобирается целиком на каждом коммите.** Цепочка bucket-страниц
  строится заново из групп `free_txn` (порядок и COW сохранены, пустых bucket'ов
  нет), но это временное решение: стоимость коммита —
  `O(свободные страницы / ёмкость bucket + bucket-страницы)`, а не строго
  `O(depth)`/0–1 COW-образ. Ориентир — инкрементальные образы только
  затронутых bucket'ов по §11.7. Особенно заметно в режимах `Flush`/`Memory` без
  `sync()`: freelist монотонно растёт, и коммит дорожает.
- Group commit между транзакциями не реализован: один `fdatasync` на коммит
  покрывает все dirty-страницы этого коммита.
- `compact_zone` переписывает дерево зоны, но не уменьшает файл; offline
  `compact --in/--out` и `fsck --repair` не входят в v1.
- Публичный API — минимальный writer (`create_zone`, `upsert_rrset`,
  `delete_*`, `compact_zone`, `commit`); доменный `apply(Edit)`/`ZoneStore` —
  отдельная задача.
