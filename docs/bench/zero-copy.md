# Zero-copy горячий путь DNS-ответа

Замеры на локальном стенде (8 vCPU, loopback, сервер и клиент на одном хосте).
Перед замерами прогреваются `PageCache`, `PageCacheV2`, node cache и scratch
энкодера.

## Аллокации (`dhat`, `pulse-alloc`)

| Операция | До | После | Комментарий |
|---|---:|---:|---|
| `decode` | 10.0000 allocs/op | 5.0000 allocs/op | `Name::from_wire` без `Vec<Vec<u8>>`; `MessageRef` на горячем пути не декодирует `Message` |
| `lookup` | 12.5660 allocs/op | 2.0000 allocs/op | материализация RRset остаётся только на холодных путях |
| `lookup_ref` | 7.6454 allocs/op | 0.0000 allocs/op | `NameRef`/inline `PageArena` без `HashMap` на типичный обход |
| `udp-e2e` | 52.0156 allocs/op, 5040.62 B/op | 0.0005 allocs/op, 0.01 B/op | `MessageRef` → snapshot → `respond_ref_into` → TX-слот |

До — `docs/bench/baseline.md`; после — фикстурa `z1k-alloc.v2`
(`gen_fixture`, 1000 A-записей), `--ops 10000`.
Интеграционный тест `crates/pulsed/tests/ref_alloc.rs` на 1000 UDP-обменов даёт
`0.0020 allocs/op` и `50.0 bytes/op` (2 аллокации — прогрев/служебные).

## Задержки и пропускная способность (UDP, A)

`pulse-loadgen`, 4 клиентских потока, ставка 10k qps, 10 с:

| Метрика | До (baseline) | После |
|---|---:|---:|
| client qps | 9767 (median) | 9970 |
| p50 | 753.15 µs | 356.35 µs |
| p99 | 778.8 µs | 409.34 µs |
| timeout/invalid | 0 / 0 | 0 / 0 |

Насыщение (8 потоков, окно 32, 10 с): `126 730 qps`, p50 `334.33 µs`,
p99 `10 829.82 µs`; клиент и сервер делят 8 vCPU, поэтому p99 включает
конкуренцию планировщика.

## Что изменено

- `pulse-dns`: `NameRef`, аллокационно-свободные `Name::is_subdomain_of` /
  `cmp_canonical` / `Name::from_wire`, zero-copy `MessageRef`, `Encoder::
  write_question_wire` / `write_rr_raw` / `write_rr_wire_name`.
- `pulse-server`: `RrsetRef`/`RdataRef`/`LookupOutcomeRef`, `ZoneSnapshot`
  (пин на время ответа), `ZoneView::with_snapshot/lookup_ref/soa_ref/ns_ref/
  records_ref/lookup_all_ref`, `QueryEngine::respond_ref_into`.
- `pulsed`: `MessageRef::decode_simple` в UDP-пути с откатом на полный декодер;
  `FileZoneView` отдаёт `FileZoneSnapshot` с одним `ZoneReader` на запрос;
  проверка opcode в `handle_notify_in` до полного decode.
- `pulse-zonefile`: inline-слоты `PageArena` (16 страниц) вместо `HashMap` на
  каждый `ZoneReader`.

## Ограничения

- Быстрый путь обслуживает один вопрос без EDNS, `QTYPE = A/AAAA`, точное
  совпадение, зону `Serving`, без `DO`; остальное (CNAME/DNAME-цепочки,
  wildcard, referral, NXDOMAIN/NODATA, DNSSEC, EDNS, TCP-ошибки) идёт прежним
  путём без изменения поведения.
- `records_ref`/`lookup_all_ref` для v2 пока не покрывают полный обход типов и
  `RRSIG`-подтипы; горячий путь их не использует.
- `lookup_ref` для v2 отдаёт только inline-payload; overflow-наборы
  материализуются прежним путём.

## Воспроизведение

```bash
cargo run -p pulse-loadgen --release --example gen_fixture -- target/bench/z1k-alloc.v2 1000
cargo run -p pulse-loadgen --release --features alloc --bin pulse-alloc -- \
  --data target/bench/z1k-alloc.v2 --rrsets 1000 --ops 10000
cargo test -p pulsed --test ref_alloc -- --nocapture
```
