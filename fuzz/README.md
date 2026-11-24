# Fuzzing (`cargo-fuzz`)

Отдельный nightly-workspace: таргеты не входят в `cargo test --workspace` и не
ломают стабильную сборку.

## Требования

- Rust nightly (`rustup toolchain install nightly`);
- `cargo install cargo-fuzz --locked`.

## Цели

| Target | Что проверяет | Лимит входа |
|---|---|---|
| `dns_wire` | `pulse_dns::Message::decode` | 65 535 Б |
| `master_zone` | `pulse_master::parse_zone` | 64 КиБ |
| `zonefile_v2_open` | `ParallelStore::open` + `fsck`/чтение мутированного v2-файла | 2 МиБ |
| `transfer_tsig` | `parse_tsig` + AXFR length-prefixed сообщения | 65 535 Б |
| `dnscrypt_packet` | `DnscryptServer::handle_udp` на мусоре/мутациях | 65 535 Б |

## Seed corpus

Seed-файлы лежат в `seeds/<target>/` (отслеживаются git). `corpus/` и
`artifacts/` — рабочие каталоги и игнорируются.

```bash
# пересоздать seeds (детерминированно)
cargo +nightly run --manifest-path fuzz/Cargo.toml --bin gen_seeds

# копия seeds в рабочий corpus (libFuzzer дописывает туда мутации)
mkdir -p fuzz/corpus/dns_wire
cp fuzz/seeds/dns_wire/* fuzz/corpus/dns_wire/

cargo +nightly fuzz run dns_wire fuzz/corpus/dns_wire -- -max_total_time=45
```

CI (`fuzz-smoke`) собирает таргеты и гоняет каждый по 30–60 с только на push
в `main`; упавшие артефакты (`fuzz/artifacts/**`, `fuzz/corpus/**`) загружаются
как GitHub Artifact. Для длинного локального прогона:

```bash
cargo +nightly fuzz run zonefile_v2_open fuzz/corpus/zonefile_v2_open -- \
  -max_total_time=3600 -rss_limit_mb=4096
```
