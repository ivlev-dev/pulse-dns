# Roadmap

| Этап | Описание | Статус |
|---|---|---|
| M0 | Фундамент и спецификации | ✅ выполнено |
| M1 | `pulse-zonefile`: спецификация + прототип (v2: аллокатор, публикация корней, пины, GC, group commit, PageCache, recovery, полный `fsck --verify` и `--repair`) | ✅ выполнено |
| M2 | `pulse-dns`: wire-формат | ✅ выполнено |
| M3 | `pulsed`: авторитетный сервер (UDP/TCP, primary/secondary, REST, транспорты DoT/DoH/DNSCrypt) + межпроцессная запись v2 (ADR 0007) | ✅ выполнено |
| M4 | `pulseresolved`: рекурсия, кеш, ad-block, overrides (базовый сервис) | ✅ выполнено |
| M5 | DNSSEC (sign/validate), затем DNSCrypt | ✅ выполнено: NSEC и NSEC3-подпись (SHA-1, salt/iterations, NSEC3PARAM, RRSIG, негативные доказательства, Opt-Out), DNSCrypt UDP/TCP, автоматическая ротация KSK/ZSK (RFC 7583), RFC 5011 в резолвере. Residual: NSEC3 для secondary-зон не генерируется; ключи secondary-зон не ротируются автоматически |
| M6 | DoT/DoH, observability, нагрузочные тесты | ✅ выполнено: DoT, DoH (HTTP/1.1, HTTP/2, HTTP/3), DoQ, DNSCrypt UDP/TCP в `pulsed` и `pulseresolved`; ACL/RRL/метрики на всех транспортах; fuzz (5 таргетов), Miri, `cargo deny`; control API резолвера. Residual: upstream h2/h3 у резолвера нет (HTTP/1.1/DoT); 0-RTT выключен |

## Остаточные ограничения (не блокируют v1)

- Multi-process: каталог (`create/delete zone`, meta) — один писатель; durable-пулы в multi не переиспользуются (bump-only, рекламация в quiescent/repair); `freeze()` локальный.
- DoH3/DoQ — серверные транспорты; upstream-клиенты резолвера остаются HTTP/1.1/DoT.
- Jobs/audit в памяти (TTL 24 ч / ring 4096); import только `text/plain`.
- DNSCrypt-сертификат без hot-reload; 0-RTT выключен; нет HSM/PKCS#11.
- Один статический control-токен у резолвера; аудит-файл не персистентный.
- NSEC3 для secondary-зон не генерируется; ключи secondary-зон не ротируются автоматически.
- REST — MVP-подмножество спецификации; API доступен только на loopback (без TLS).
- DNS Cookies и полноценный RRL авторитетного сервера (`pulsed`) нет; 0x20 echo нет.
- RRset lookup ~2–4.9 µs при 1M против цели 500 нс (не достигнута).
- Loom в CI нет (Miri — continue-on-error); file-fatal порча требует ручного разбора.

Примечание: v1 = релиз после M0–M6. Межпроцессная параллельная запись (N процессов) реализована (ADR 0007) и не блокирует M1/M3. Производительность и тесты: 1332 теста, alloc 50M/s, commit 49k/s (4 потока), group commit 2.4×/3.36×, end-to-end 88k q/s baseline / 72k при 8 писателях; DoT ~10.4k qps, DoH h2 ~8.2k DNS/s, DoH3 ~13.6–14.9k, DoQ ~5.25k.
