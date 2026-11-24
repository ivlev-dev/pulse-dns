# Roadmap

| Этап | Описание | Статус |
|---|---|---|
| M0 | Фундамент и спецификации | ✅ выполнено |
| M1 | `pulse-zonefile`: спецификация + прототип (v2: аллокатор, публикация корней, пины, GC, group commit, PageCache, recovery, fsck) | ✅ выполнено |
| M2 | `pulse-dns`: wire-формат | ✅ выполнено |
| M3 | `pulsed`: авторитетный сервер (UDP/TCP, primary/secondary, REST, транспорты DoT/DoH/DNSCrypt) | ✅ выполнено |
| M4 | `pulseresolved`: рекурсия, кеш, ad-block, overrides (базовый сервис) | ✅ выполнено |
| M5 | DNSSEC (sign/validate), затем DNSCrypt | 🟡 частично: DNSSEC sign/validate реализованы; DNSCrypt реализован |
| M6 | DoT/DoH, observability, нагрузочные тесты | 🟡 частично: DoT и DoH (HTTP/1.1) реализованы; DoQ нет |

Примечание: v1 = релиз после M0–M6; DNSSEC входит в v1 (реализация — M5, готовность формата — M1); DNSCrypt — после DNSSEC. Межпроцессная параллельная запись (N процессов) вынесена в отдельный ADR (M3-продолжение) и не блокирует M1.