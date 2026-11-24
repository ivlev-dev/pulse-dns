# Roadmap

| Этап | Описание | Статус |
|---|---|---|
| M0 | Фундамент и спецификации | ✅ выполнено |
| M1 | `pulse-zonefile`: спецификация + прототип (v2: аллокатор, публикация корней, пины, GC, group commit, PageCache, recovery, полный `fsck --verify` и `--repair`) | ✅ выполнено |
| M2 | `pulse-dns`: wire-формат | ✅ выполнено |
| M3 | `pulsed`: авторитетный сервер (UDP/TCP, primary/secondary, REST, транспорты DoT/DoH/DNSCrypt) | ✅ выполнено |
| M4 | `pulseresolved`: рекурсия, кеш, ad-block, overrides (базовый сервис) | ✅ выполнено |
| M5 | DNSSEC (sign/validate), затем DNSCrypt | 🟡 частично: NSEC и NSEC3-подпись (SHA-1, salt/iterations, NSEC3PARAM, RRSIG, негативные доказательства, конфиг `dnssec.<zone>.denial=nsec3`), DNSCrypt UDP/TCP, NSEC3 Opt-Out, автоматическая ротация KSK/ZSK (RFC 7583) и RFC 5011 реализованы; NSEC3 для secondary-зон не генерируется |
| M6 | DoT/DoH, observability, нагрузочные тесты | 🟡 частично: DoT и DoH (HTTP/1.1) реализованы; DoQ и HTTP/2/3 нет. Fuzz (5 таргетов, CI `fuzz-smoke`), Miri (nightly, continue-on-error) и `cargo deny check` зелёные; полный `fsck --verify`/`--repair` реализован |

Примечание: v1 = релиз после M0–M6; DNSSEC входит в v1 (реализация — M5, готовность формата — M1); DNSCrypt — после DNSSEC. Межпроцессная параллельная запись (N процессов) вынесена в отдельный ADR (M3-продолжение) и не блокирует M1. Осталось: межпроцессная запись N процессов (reader table в файле, `LOCK_SH`, лидер/курсор/fencing), DoH HTTP/2/3 и DoQ, NSEC3 для secondary-зон, WAL/journal для write-through, REST — полный спек (сейчас MVP), полноценный RRL авторитетного сервера, 0x20 echo, TLS для API/метрик (сейчас loopback), лoom в CI. Резолвер: upstream DoH только HTTP/1.1, одно keep-alive соединение на upstream (сериализация), RRL ограничен per-source token bucket.
