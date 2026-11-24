# `pulse-transfer`

TSIG (RFC 8945), AXFR (RFC 5936), IXFR (RFC 1995) и NOTIFY (RFC 1996)
поверх [`pulse-dns`](../pulse-dns).

## TSIG algorithms

Поддерживаются только HMAC-SHA1/224/256/384/512 (по умолчанию — SHA-256).
Все HMAC считаются через `aws-lc-rs`; собственных крипто-реализаций в крейте
нет.

HMAC-MD5 и любые неизвестные алгоритмы **не поддерживаются**: запись с таким
алгоритмом отвергается типизированной ошибкой
`TsigError::UnsupportedAlgorithm`, сервер отвечает отказом без разбора зоны.
Legacy-совместимость — только SHA1+ (SHA1 допустим RFC 8945, но не
рекомендуется).

## Транспорт

`AxfrClient`/`AxfrServer`/`IxfrClient`/`IxfrServer` работают поверх любых
синхронных `std::io::Read + std::io::Write` (TCP или in-memory pipe), без
`unsafe` и без async.

## Пример

```bash
cargo run -p pulse-transfer --example axfr_session
```

```text
server: 4 messages, 24 records, 1079 bytes
client: origin=example.com., serial=2026112401, records=22
round-trip OK
```
