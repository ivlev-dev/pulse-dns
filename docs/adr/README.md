# ADR — индекс

| № | Название | Статус |
|---|---|---|
| 0001 | [ADR 0001. DDD-архитектура pulse-dns: контексты, слои, зависимости](0001-ddd-architecture.md) | Proposed |
| 0002 | [ADR 0002. Карта крейтов и защита от циклов зависимостей](0002-crate-map.md) | Proposed |
| 0003 | [ADR 0003. Формат файла зон: page-based COW B+tree с двойным meta-заголовком](0003-zonefile-format.md) | Proposed |
| 0004 | [ADR-0004: Модель безопасности (принятые меры)](0004-security-model.md) | Proposed |
| 0005 | [ADR 0005. Параллельная запись в один файл: деревья и корни на зону](0005-parallel-writers.md) | Proposed |
| 0006 | [ADR-0006: Безопасность параллельной записи в один mmap-файл зон](0006-parallel-writers-safety.md) | Proposed (блокирует ADR-0005) |
| 0007 | [ADR 0007. Межпроцессная параллельная запись в один файл (M3)](0007-multiprocess-writers.md) | Accepted |

## Спецификации

- [docs/spec/crypto-inventory.md](../spec/crypto-inventory.md)
- [docs/spec/domain-model.md](../spec/domain-model.md)
- [docs/spec/io-uring-runtime.md](../spec/io-uring-runtime.md)
- [docs/spec/threat-model.md](../spec/threat-model.md)
- [docs/spec/zonefile-v1.md](../spec/zonefile-v1.md)

## API

- [docs/api/rest-v1.md](../api/rest-v1.md)

## Бенчмарки

- [docs/bench/plan.md](../bench/plan.md)
