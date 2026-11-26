# Функциональное сравнение pulse-dns с BIND 9, Unbound и PowerDNS

Сравниваются авторитетный сервер `pulsed` и рекурсивный резолвер `pulseresolved` как один продукт **pulse-dns** с четырьмя чужими продуктами: BIND 9.20, Unbound 1.22, PowerDNS Authoritative 5.1 и PowerDNS Recursor 5.5.

Документ отвечает на вопрос **«что умеет и чего не умеет каждый»**, а не «кто быстрее». Сырые цифры производительности сюда сознательно не включены — для них отдельный отчёт.

## 0. Методика и версии

| Параметр | Значение |
|---|---|
| Дата среза | 2026-11-26 |
| pulse-dns | рабочее дерево на 2026-11-26, **включая незакоммиченные правки** (`STATUS.md`, `README.md`, код); git не изменялся |
| BIND | 9.20.15 ARM (стабильная ветка 9.20) |
| Unbound | 1.22.0 (man-страница тега `release-1.22.0`; в 2026 актуальны 1.25/1.26, но сравнение привязано к 1.22) |
| PowerDNS Authoritative | 5.1.7 (docs `doc.powerdns.com/authoritative`) |
| PowerDNS Recursor | 5.5.0 (docs `doc.powerdns.com/recursor`) |

Статусы: ✅ да, ⚠️ частично, ❌ нет, — н/п (роль не применима), ❓ не удалось подтвердить. «Частично» означает: функция есть в ограниченном виде, включена не по умолчанию, доступна только части транспортов/типов зон или требует внешнего компонента. Пометка «в рабочем дереве» в пояснениях означает, что код есть, но не входит в последний коммит.

Каждая ячейка матрицы раскрыта в разделах 4–5: статус + короткое пояснение + ссылка (для чужих — официальная документация, для наших — файл кода).

> **Важно.** Разделы 2–5 — это *стандартные* функции DNS. Наши архитектурные отличия (mmap-файл, многопроцессная запись, Rust, io_uring, zero-copy, group commit) вынесены в раздел 6 и не выдаются за «стандарт». Чего у нас нет — в разделе 7 без смягчений.

## 1. Краткая сводка

- **Стандартное ядро** (primary/secondary, DNSSEC-подпись NSEC/NSEC3, AXFR/IXFR/NOTIFY/TSIG, RFC 2136, рекурсия, кеш, DNSSEC-валидация, ACL, RRL, DoT/DoH/DoQ) у pulse-dns закрыто; по числу встроенных транспортов (DoT + DoH 1.1/2/3 + DoQ + DNSCrypt) мы шире BIND 9.20 и PowerDNS.

- **Крупные функциональные пробелы**: нет catalog zones (RFC 9432), views/split-horizon, stub-зон, per-zone query ACL, непрерывного inline-signing, HSM/PKCS#11, SQL-backend'ов и DNS Cookies. У авторитетного сервера нет RRL; у резолвера — prefetch, serve-stale, RPZ и персистентности кеша.

- **BIND 9.20** — самый полный по авторитетной части (views, catalog consumer, per-zone allow-query, update-policy, SIG(0), inline-signing, RRL), но без DoQ/DoH3/DNSCrypt и без REST API.

- **Unbound 1.22** — сильнейший резолвер по политикам (RPZ, views, cookies, serve-stale, prefetch), с DoT/DoH/DoQ/DNSCrypt на входе; авторитетная часть ограничена auth-zone (AXFR/IXFR-in, без AXFR-out).

- **PowerDNS Auth 5.1** — сильнейший по backends/catalog/views и REST+OpenAPI, но **не отдаёт IXFR**, не имеет встроенных шифрованных транспортов и требует dnsdist для DoT/DoH/DoQ.

- **PowerDNS Recursor 5.5** — полный набор резолверных политик (RPZ, serve-stale, qname-min, cookies исходящие, REST+Prometheus), но без встроенных шифрованных листенеров, без RRL и без RFC 5011.

- **Наши реальные преимущества** — не «ещё один DNS», а модель хранения и записи: один mmap-файл, многопроцессная запись с fencing и общим group commit, io_uring, zero-copy, отсутствие GC и внешней БД.

- **Расхождение в наших доках**: README/STATUS называют SIG(0) и per-name update-policy отсутствующими, но в коде они реализованы (см. §8). Матрица следует коду.

## 2. Матрица: авторитетный сервер

### 2.1. Зоны и ACL

| Функция | pulse-dns | BIND 9.20 | Unbound 1.22 | PowerDNS Auth 5.1 | PowerDNS Recursor 5.5 |
|---|---|---|---|---|---|
| Primary-зоны | ✅ | ✅ | ⚠️ | ✅ | ⚠️ |
| Secondary-зоны (AXFR/IXFR-in, refresh/expire) | ✅ | ✅ | ⚠️ | ✅ | ❌ |
| Reverse-зоны (in-addr.arpa / ip6.arpa) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Forward-зоны | ⚠️ | ✅ | ✅ | ❌ | ✅ |
| Stub / static-stub зоны | ❌ | ✅ | ✅ | ❌ | ❌ |
| Catalog zones (RFC 9432) | ❌ | ⚠️ | ❌ | ✅ | ❌ |
| Views / split-horizon | ❌ | ✅ | ✅ | ✅ | ❌ |
| Per-zone ACL (allow-query) | ⚠️ | ✅ | ⚠️ | ⚠️ | ❌ |

### 2.2. DNSSEC

| Функция | pulse-dns | BIND 9.20 | Unbound 1.22 | PowerDNS Auth 5.1 | PowerDNS Recursor 5.5 |
|---|---|---|---|---|---|
| Подпись зон | ✅ | ✅ | ❌ | ✅ | ❌ |
| Алгоритмы подписи (RSA/ECDSA/Ed25519/Ed448) | ⚠️ | ✅ | ❌ | ✅ | ❌ |
| NSEC / NSEC3 / opt-out | ✅ | ✅ | ❌ | ✅ | ❌ |
| Key rollover | ✅ | ✅ | ❌ | ✅ | ❌ |
| Inline signing | ⚠️ | ✅ | ❌ | ✅ | ❌ |
| DNSSEC-валидация (в составе продукта) | ✅ | ✅ | ✅ | ❌ | ✅ |

### 2.3. Трансферы

| Функция | pulse-dns | BIND 9.20 | Unbound 1.22 | PowerDNS Auth 5.1 | PowerDNS Recursor 5.5 |
|---|---|---|---|---|---|
| AXFR (out/in) | ✅ | ✅ | ⚠️ | ✅ | ❌ |
| IXFR (out/in) | ✅ | ✅ | ⚠️ | ⚠️ | ❌ |
| TSIG и алгоритмы | ✅ | ✅ | ❌ | ✅ | ❌ |
| NOTIFY (in/out) | ✅ | ✅ | ⚠️ | ✅ | ❌ |
| IXFR-from-differences | ✅ | ✅ | ❌ | ❌ | ❌ |

### 2.4. RFC 2136 UPDATE

| Функция | pulse-dns | BIND 9.20 | Unbound 1.22 | PowerDNS Auth 5.1 | PowerDNS Recursor 5.5 |
|---|---|---|---|---|---|
| RFC 2136 UPDATE | ✅ | ✅ | ❌ | ✅ | ❌ |
| Prerequisites | ✅ | ✅ | ❌ | ✅ | ❌ |
| Policy per-name | ✅ | ✅ | ❌ | ⚠️ | ❌ |
| SIG(0) | ✅ | ✅ | ❌ | ❌ | ❌ |
| TSIG для UPDATE | ✅ | ✅ | ❌ | ✅ | ❌ |

### 2.5. Транспорты

| Функция | pulse-dns | BIND 9.20 | Unbound 1.22 | PowerDNS Auth 5.1 | PowerDNS Recursor 5.5 |
|---|---|---|---|---|---|
| UDP/TCP | ✅ | ✅ | ✅ | ✅ | ✅ |
| DoT | ✅ | ✅ | ✅ | ❌ | ❌ |
| DoH 1.1 / 2 | ✅ | ⚠️ | ⚠️ | ❌ | ❌ |
| DoH 3 | ✅ | ❌ | ❌ | ❌ | ❌ |
| DoQ | ✅ | ❌ | ✅ | ❌ | ❌ |
| DNSCrypt | ✅ | ❌ | ✅ | ❌ | ❌ |

### 2.6. API и управление

| Функция | pulse-dns | BIND 9.20 | Unbound 1.22 | PowerDNS Auth 5.1 | PowerDNS Recursor 5.5 |
|---|---|---|---|---|---|
| REST API | ✅ | ❌ | ❌ | ✅ | ✅ |
| OpenAPI | ✅ | ❌ | ❌ | ✅ | ❓ |
| Аутентификация API и scopes | ✅ | ⚠️ | ⚠️ | ⚠️ | ⚠️ |
| Jobs | ✅ | ❌ | ❌ | ❌ | ❌ |
| Audit | ✅ | ❌ | ❌ | ❌ | ❌ |
| Metrics | ✅ | ⚠️ | ⚠️ | ✅ | ✅ |

### 2.7. Хранилище

| Функция | pulse-dns | BIND 9.20 | Unbound 1.22 | PowerDNS Auth 5.1 | PowerDNS Recursor 5.5 |
|---|---|---|---|---|---|
| mmap single-file | ✅ | ❌ | ❌ | ⚠️ | ❌ |
| Multi-writer | ✅ | ❌ | ❌ | ⚠️ | ❌ |
| SQL/backends | ❌ | ⚠️ | ⚠️ | ✅ | ❌ |
| Hot reload | ⚠️ | ✅ | ✅ | ✅ | ✅ |
| Bulk-load | ✅ | ✅ | ⚠️ | ✅ | — |

### 2.8. Производительность-фичи

| Функция | pulse-dns | BIND 9.20 | Unbound 1.22 | PowerDNS Auth 5.1 | PowerDNS Recursor 5.5 |
|---|---|---|---|---|---|
| io_uring | ✅ | ❌ | ❌ | ❌ | ❌ |
| Zero-copy ответа | ✅ | ❌ | ❌ | ❌ | ❌ |
| Response cache | ✅ | ❌ | ❌ | ✅ | ✅ |
| Group commit | ✅ | ❌ | ❌ | ❌ | ❌ |

## 3. Матрица: рекурсивный резолвер

### 3.1. Рекурсия и forward

| Функция | pulse-dns | BIND 9.20 | Unbound 1.22 | PowerDNS Auth 5.1 | PowerDNS Recursor 5.5 |
|---|---|---|---|---|---|
| Итеративная рекурсия | ✅ | ✅ | ✅ | ❌ | ✅ |
| Forward | ✅ | ✅ | ✅ | ❌ | ✅ |
| Stub-зоны | ❌ | ✅ | ✅ | ❌ | ❌ |
| QNAME minimization | ✅ | ✅ | ✅ | ❌ | ✅ |
| 0x20-рандомизация | ✅ | ❌ | ✅ | ❌ | ❌ |
| Prefetch | ❌ | ✅ | ✅ | ❌ | ⚠️ |
| Serve-stale | ❌ | ✅ | ✅ | ❌ | ✅ |

### 3.2. Кеш

| Функция | pulse-dns | BIND 9.20 | Unbound 1.22 | PowerDNS Auth 5.1 | PowerDNS Recursor 5.5 |
|---|---|---|---|---|---|
| Positive/negative cache + TTL | ✅ | ✅ | ✅ | ❌ | ✅ |
| Персистентность кеша | ❌ | ❌ | ⚠️ | ❌ | ❌ |

### 3.3. DNSSEC

| Функция | pulse-dns | BIND 9.20 | Unbound 1.22 | PowerDNS Auth 5.1 | PowerDNS Recursor 5.5 |
|---|---|---|---|---|---|
| DNSSEC-валидация и алгоритмы | ✅ | ✅ | ✅ | ❌ | ✅ |
| NSEC3-валидация | ✅ | ✅ | ✅ | ❌ | ✅ |
| Root trust anchor | ✅ | ✅ | ✅ | ❌ | ✅ |
| RFC 5011 | ✅ | ✅ | ✅ | ❌ | ❌ |

### 3.4. Политики и защита

| Функция | pulse-dns | BIND 9.20 | Unbound 1.22 | PowerDNS Auth 5.1 | PowerDNS Recursor 5.5 |
|---|---|---|---|---|---|
| RPZ / adblock / blocklist | ⚠️ | ✅ | ✅ | ❌ | ✅ |
| Overrides / local zones | ⚠️ | ✅ | ✅ | ❌ | ✅ |
| RRL / rate limit | ✅ | ✅ | ⚠️ | ❌ | ❌ |
| ACL клиентов | ✅ | ✅ | ✅ | ❌ | ✅ |
| DNS Cookies | ❌ | ✅ | ✅ | ❌ | ⚠️ |

### 3.5. Транспорты

| Функция | pulse-dns | BIND 9.20 | Unbound 1.22 | PowerDNS Auth 5.1 | PowerDNS Recursor 5.5 |
|---|---|---|---|---|---|
| Транспорты вниз (клиент→резолвер) | ✅ | ✅ | ✅ | ❌ | ❌ |
| Транспорты вверх (резолвер→upstream) | ⚠️ | ⚠️ | ⚠️ | ❌ | ⚠️ |

### 3.6. API и управление

| Функция | pulse-dns | BIND 9.20 | Unbound 1.22 | PowerDNS Auth 5.1 | PowerDNS Recursor 5.5 |
|---|---|---|---|---|---|
| API / метрики | ✅ | ⚠️ | ⚠️ | ❌ | ✅ |

## 4. Детали: авторитетный сервер

### 4.1. Зоны и ACL

#### A.1. Primary-зоны

- **pulse-dns** — да. Зона хранится в v2-файле, состояние Serving, DNS отвечает из mmap. `crates/pulsed/src/store.rs`
- **BIND 9.20** — да. type primary; штатный авторитетный режим. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/reference.html#namedconf-statement-type)
- **Unbound 1.22** — частично. auth-zone отдаёт локальные данные вниз и вверх, но это не полноценное ведение primary-зоны. [Unbound 1.22 manual](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html#authority-zone-options)
- **PowerDNS Auth 5.1** — да. Режимы native и primary; зона ведётся в backend. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/modes-of-operation.html)
- **PowerDNS Recursor 5.5** — частично. auth-zones — локальная авторитетная копия для резолвера, без ведения зоны. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/settings.html)

#### A.2. Secondary-зоны (AXFR/IXFR-in, refresh/expire)

- **pulse-dns** — да. secondary_zones: bootstrap, SOA-refresh, expire → SERVFAIL, AXFR/IXFR-in, TSIG. `crates/pulsed/src/secondary.rs`
- **BIND 9.20** — да. type secondary, primaries, журнал, NOTIFY. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/reference.html#namedconf-statement-type)
- **Unbound 1.22** — частично. auth-zone обновляется через AXFR/IXFR/SOA-таймеры, но исходящий NOTIFY не шлёт. [Unbound 1.22 manual](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html#authority-zone-options)
- **PowerDNS Auth 5.1** — да. Secondary-режим, autoprimary, IXFR-in; IXFR-out не отдаёт. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/modes-of-operation.html)
- **PowerDNS Recursor 5.5** — нет. Рекурсор не является secondary. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/settings.html)

#### A.3. Reverse-зоны (in-addr.arpa / ip6.arpa)

- **pulse-dns** — да. Обычная зона с reverse-именем; отдельной синхронизации PTR нет. `crates/pulse-zonefile/src/zonefile.rs`
- **BIND 9.20** — да. Обычные зоны; reverse — это просто имя зоны. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/reference.html#namedconf-statement-type)
- **Unbound 1.22** — да. Обычные auth-zone/local-zone с reverse-именем. [Unbound 1.22 manual](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html#authority-zone-options)
- **PowerDNS Auth 5.1** — да. Обычная зона в backend. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/modes-of-operation.html)
- **PowerDNS Recursor 5.5** — да. Разрешает reverse-имена как резолвер; auth-zones тоже возможны. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/settings.html)

#### A.4. Forward-зоны

- **pulse-dns** — частично. kind=forward есть в модели/API и формате, но forward_upstreams не используются в пути ответа. `crates/pulse-zonefile/src/zone_meta.rs`
- **BIND 9.20** — да. type forward с forwarders, в т.ч. per-zone. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/reference.html#namedconf-statement-type)
- **Unbound 1.22** — да. forward-zone с forward-addr/host и TLS-апстримом. [Unbound 1.22 manual](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html#forward-zone-options)
- **PowerDNS Auth 5.1** — нет. Такого типа зоны нет; forwarding — задача резолвера/dnsdist. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/modes-of-operation.html)
- **PowerDNS Recursor 5.5** — да. forward-zones — штатный режим (в т.ч. per-zone). [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/settings.html#forward-zones)

#### A.5. Stub / static-stub зоны

- **pulse-dns** — нет. Нет stub-зон. `STATUS.md`
- **BIND 9.20** — да. type stub и static-stub. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/reference.html#namedconf-statement-type)
- **Unbound 1.22** — да. stub-zone (stub-addr/stub-host, TLS/TCP). [Unbound 1.22 manual](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html#stub-zone-options)
- **PowerDNS Auth 5.1** — нет. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/modes-of-operation.html)
- **PowerDNS Recursor 5.5** — нет. Нет stub-зон, только forward-zones. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/settings.html#forward-zones)

#### A.6. Catalog zones (RFC 9432)

- **pulse-dns** — нет. Нет; внутренний каталог зон в zonefile — не RFC 9432. `crates/pulse-zonefile/src/zonefile.rs`
- **BIND 9.20** — частично. Только consumer: schema v1/v2, custom properties, coo; producer в ARM 9.20 не описан. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/chapter6.html#catalog-zones)
- **Unbound 1.22** — нет. В unbound.conf 1.22 опций catalog нет. [Unbound 1.22 manual](https://github.com/NLnetLabs/unbound/blob/release-1.22.0/doc/unbound.conf.5.in)
- **PowerDNS Auth 5.1** — да. Producer и consumer v2; v1 — только consumer; требует поддержки backend. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/catalog.html#supported-catalog-versions)
- **PowerDNS Recursor 5.5** — нет. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/settings.html)

#### A.7. Views / split-horizon

- **pulse-dns** — нет. Нет views; один набор зон для всех клиентов. `crates/pulsed/src/config.rs`
- **BIND 9.20** — да. view-блоки, отдельные зоны/forwarders/ACL. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/reference.html#namedconf-statement-view)
- **Unbound 1.22** — да. view: + access-control-view/interface-view. [Unbound 1.22 manual](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html#unbound-conf-view)
- **PowerDNS Auth 5.1** — да. Views с 5.0, экспериментально; нужен zone cache и LMDB/Postgres. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/views.html#requirements)
- **PowerDNS Recursor 5.5** — нет. Нет views. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/settings.html)

#### A.8. Per-zone ACL (allow-query)

- **pulse-dns** — частично. Есть allow_zones для transfer/update и общий TLS-ACL; per-zone query ACL для UDP/TCP нет. `crates/pulsed/src/config.rs`
- **BIND 9.20** — да. allow-query в zone/view переопределяет глобальный. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/reference.html#namedconf-statement-allow-query)
- **Unbound 1.22** — частично. access-control — по клиенту, не по зоне; per-zone allow-query нет. [Unbound 1.22 manual](https://github.com/NLnetLabs/unbound/blob/release-1.22.0/doc/unbound.conf.5.in)
- **PowerDNS Auth 5.1** — частично. ALLOW-AXFR-FROM / ALLOW-DNSUPDATE-FROM / TSIG-метаданные; ACL на обычные запросы нет. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/domainmetadata.html#allow-axfr-from)
- **PowerDNS Recursor 5.5** — нет. Только глобальный allow-from по клиенту; per-zone ACL нет. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/settings.html#allow-from)


### 4.2. DNSSEC

#### A.9. Подпись зон

- **pulse-dns** — да. Подпись при старте, по job/API и после ротации ключей; NSEC/NSEC3. `crates/pulsed/src/store.rs`
- **BIND 9.20** — да. KASP/dnssec-policy, автоматическое сопровождение. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/chapter5.html#fully-automated-key-and-signing-policy)
- **Unbound 1.22** — нет. Unbound только валидирует, не подписывает. [Unbound 1.22 manual](https://github.com/NLnetLabs/unbound/blob/release-1.22.0/doc/unbound.conf.5.in)
- **PowerDNS Auth 5.1** — да. Online signing и pre-signed зоны. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/dnssec/index.html)
- **PowerDNS Recursor 5.5** — нет. Рекурсор не подписывает. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/dnssec.html)

#### A.10. Алгоритмы подписи (RSA/ECDSA/Ed25519/Ed448)

- **pulse-dns** — частично. Подпись: 8/13/15. Валидация: 8/10/13/14/15 (+legacy 5/7 opt-in); Ed448 и подпись 10/14 нет. `crates/pulse-dnssec/src/algorithm.rs`
- **BIND 9.20** — да. RSASHA1/256/512, ECDSA P-256/P-384, Ed25519, Ed448 (по crypto-lib). [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/reference.html#namedconf-statement-keys)
- **Unbound 1.22** — нет. Подписи нет; валидация — RSA/ECDSA/Ed25519/Ed448. [Unbound 1.22 manual](https://github.com/NLnetLabs/unbound/blob/release-1.22.0/doc/unbound.conf.5.in)
- **PowerDNS Auth 5.1** — да. 5/7/8/10/13/14/15/16 (зависит от сборки). [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/dnssec/profile.html)
- **PowerDNS Recursor 5.5** — нет. Подписи нет. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/dnssec.html)

#### A.11. NSEC / NSEC3 / opt-out

- **pulse-dns** — да. NSEC и NSEC3 (salt/iterations, closest encloser, wildcard, opt-out); для secondary NSEC3 не генерируется. `crates/pulse-dnssec/src/denial/mod.rs`
- **BIND 9.20** — да. NSEC/NSEC3, nsec3param, opt-out, narrow. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/reference.html#namedconf-statement-nsec3param)
- **Unbound 1.22** — нет. Только валидация denial-доказательств. [Unbound 1.22 manual](https://github.com/NLnetLabs/unbound/blob/release-1.22.0/doc/unbound.conf.5.in)
- **PowerDNS Auth 5.1** — да. NSEC/NSEC3, NSEC3PARAM, NSEC3NARROW, opt-out. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/domainmetadata.html#nsec3narrow)
- **PowerDNS Recursor 5.5** — нет. Только валидация. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/dnssec.html)

#### A.12. Key rollover

- **pulse-dns** — да. Автоматическая ротация KSK/ZSK: pre-publish → double-sign → active → retire, состояние на диске. `crates/pulsed/src/rotation.rs`
- **BIND 9.20** — да. KASP: ZSK автоматически, KSK с checkds/parental-agents. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/chapter5.html#fully-automated-key-and-signing-policy)
- **Unbound 1.22** — нет. Нет управления ключами. [Unbound 1.22 manual](https://github.com/NLnetLabs/unbound/blob/release-1.22.0/doc/unbound.conf.5.in)
- **PowerDNS Auth 5.1** — да. Signature rollover и key maintenance управляются PowerDNS. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/dnssec/index.html)
- **PowerDNS Recursor 5.5** — нет. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/dnssec.html)

#### A.13. Inline signing

- **pulse-dns** — частично. Подпись при старте/по job/после ротации; непрерывного re-sign при изменениях и истечении подписей нет. `crates/pulsed/src/store.rs`
- **BIND 9.20** — да. inline-signing включён по умолчанию для dnssec-policy. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/reference.html#namedconf-statement-inline-signing)
- **Unbound 1.22** — нет. [Unbound 1.22 manual](https://github.com/NLnetLabs/unbound/blob/release-1.22.0/doc/unbound.conf.5.in)
- **PowerDNS Auth 5.1** — да. Online signing: подписи генерируются при ответе/изменении. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/dnssec/index.html)
- **PowerDNS Recursor 5.5** — нет. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/dnssec.html)

#### A.14. DNSSEC-валидация (в составе продукта)

- **pulse-dns** — да. Валидирует pulseresolved (AD/BOGUS→SERVFAIL); сам pulsed — нет. `crates/pulse-resolver/src/dnssec.rs`
- **BIND 9.20** — да. Встроенный резолвер валидирует по умолчанию. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/chapter5.html#dnssec-validation)
- **Unbound 1.22** — да. Validator по умолчанию. [Unbound 1.22 manual](https://github.com/NLnetLabs/unbound/blob/release-1.22.0/doc/unbound.conf.5.in)
- **PowerDNS Auth 5.1** — нет. Валидации нет (только подпись/serving). [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/dnssec/index.html)
- **PowerDNS Recursor 5.5** — да. Валидирует как резолвер (режимы process/validate); авторитетного режима нет. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/dnssec.html)


### 4.3. Трансферы

#### A.15. AXFR (out/in)

- **pulse-dns** — да. AXFR-out по TCP с TSIG/ACL; AXFR-in для secondary. `crates/pulse-transfer/src/lib.rs`
- **BIND 9.20** — да. AXFR-out и AXFR-in. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/chapter6.html#incremental-zone-transfers-ixfr)
- **Unbound 1.22** — частично. AXFR-in через auth-zone; AXFR-out не отдаёт (мануал прямо это оговаривает). [Unbound 1.22 manual](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html#authority-zone-options)
- **PowerDNS Auth 5.1** — да. AXFR-out; AXFR-in для secondary. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/modes-of-operation.html)
- **PowerDNS Recursor 5.5** — нет. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/settings.html)

#### A.16. IXFR (out/in)

- **pulse-dns** — да. IXFR-out из истории коммитов (history_deltas) и IXFR-in для secondary. `crates/pulsed/src/transfer.rs`
- **BIND 9.20** — да. IXFR-out/in, max-ixfr-ratio, request-ixfr. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/chapter6.html#incremental-zone-transfers-ixfr)
- **Unbound 1.22** — частично. IXFR-in через auth-zone; IXFR-out не отдаёт. [Unbound 1.22 manual](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html#authority-zone-options)
- **PowerDNS Auth 5.1** — частично. IXFR только получает; «cannot serve IXFR updates» (официально). [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/modes-of-operation.html#ixfr-incremental-zone-transfers)
- **PowerDNS Recursor 5.5** — нет. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/settings.html)

#### A.17. TSIG и алгоритмы

- **pulse-dns** — да. hmac-sha1/224/256/384/512, replay-защита, подпись каждого N-го сообщения. `crates/pulse-transfer/src/tsig.rs`
- **BIND 9.20** — да. hmac-md5/sha1/224/256/384/512. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/chapter7.html#tsig)
- **Unbound 1.22** — нет. TSIG в unbound.conf 1.22 отсутствует. [Unbound 1.22 manual](https://github.com/NLnetLabs/unbound/blob/release-1.22.0/doc/unbound.conf.5.in)
- **PowerDNS Auth 5.1** — да. hmac-md5/sha1/224/256/384/512 + GSS-TSIG. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/tsig.html)
- **PowerDNS Recursor 5.5** — нет. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/settings.html)

#### A.18. NOTIFY (in/out)

- **pulse-dns** — да. NOTIFY-out после изменений, NOTIFY-in для secondary, TSIG/ACL/retry. `crates/pulsed/src/transfer.rs`
- **BIND 9.20** — да. notify/also-notify, приём NOTIFY. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/chapter6.html#notify)
- **Unbound 1.22** — частично. allow-notify для auth-zone; исходящий NOTIFY не отправляет. [Unbound 1.22 manual](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html#authority-zone-options)
- **PowerDNS Auth 5.1** — да. NOTIFY in/out, also-notify, autoprimary. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/modes-of-operation.html)
- **PowerDNS Recursor 5.5** — нет. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/settings.html)

#### A.19. IXFR-from-differences

- **pulse-dns** — да. Аналог: дельты строятся из истории коммитов зоны, без внешнего diff-файла. `crates/pulse-zonefile/src/zonefile.rs`
- **BIND 9.20** — да. ixfr-from-differences (yes/primary/secondary). [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/reference.html#namedconf-statement-ixfr-from-differences)
- **Unbound 1.22** — нет. [Unbound 1.22 manual](https://github.com/NLnetLabs/unbound/blob/release-1.22.0/doc/unbound.conf.5.in)
- **PowerDNS Auth 5.1** — нет. Нет; IXFR-out вообще не поддерживается. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/modes-of-operation.html#ixfr-incremental-zone-transfers)
- **PowerDNS Recursor 5.5** — нет. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/settings.html)


### 4.4. RFC 2136 UPDATE

#### A.20. RFC 2136 UPDATE

- **pulse-dns** — да. opcode 5 на UDP/TCP/DoT/DoH/DoQ/DNSCrypt, атомарный commit, SOA serial RFC 1982. `crates/pulse-server/src/update.rs`
- **BIND 9.20** — да. allow-update/update-policy, journal. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/chapter6.html#dynamic-update)
- **Unbound 1.22** — нет. Динамических обновлений нет. [Unbound 1.22 manual](https://github.com/NLnetLabs/unbound/blob/release-1.22.0/doc/unbound.conf.5.in)
- **PowerDNS Auth 5.1** — да. dnsupdate=yes, backend-операции, SOA-EDIT-DNSUPDATE. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/dnsupdate.html)
- **PowerDNS Recursor 5.5** — нет. Рекурсор UPDATE не принимает. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/settings.html)

#### A.21. Prerequisites

- **pulse-dns** — да. YXDOMAIN/NXRRSET/YXRRSET/NXDOMAIN, проверка на одном снапшоте до записи. `crates/pulse-server/src/update.rs`
- **BIND 9.20** — да. Полный набор prerequisites RFC 2136. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/chapter6.html#dynamic-update)
- **Unbound 1.22** — нет. Нет UPDATE. [Unbound 1.22 manual](https://github.com/NLnetLabs/unbound/blob/release-1.22.0/doc/unbound.conf.5.in)
- **PowerDNS Auth 5.1** — да. Prerequisites поддерживаются (RFC 2136). [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/dnsupdate.html)
- **PowerDNS Recursor 5.5** — нет. Нет UPDATE. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/settings.html)

#### A.22. Policy per-name

- **pulse-dns** — да. update.policy: zone/name (exact/suffix/wildcard) + types + principal (TSIG/SIG0/subnet/any); первое совпадение, default deny. В рабочем дереве, не в последнем коммите. `crates/pulsed/src/update.rs`
- **BIND 9.20** — да. update-policy: grant/deny по name/type/principal. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/reference.html#dynamic-update-policies)
- **Unbound 1.22** — нет. Нет UPDATE. [Unbound 1.22 manual](https://github.com/NLnetLabs/unbound/blob/release-1.22.0/doc/unbound.conf.5.in)
- **PowerDNS Auth 5.1** — частично. Статически — только IP/TSIG на зону; произвольная политика — Lua-скрипт updatepolicy. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/dnsupdate.html)
- **PowerDNS Recursor 5.5** — нет. Нет UPDATE. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/settings.html)

#### A.23. SIG(0)

- **pulse-dns** — да. Проверка SIG(0) (RFC 2931/3007), доверенные ключи, replay-кэш, подпись ответа. В рабочем дереве, не в последнем коммите. `crates/pulse-dnssec/src/sig0.rs`
- **BIND 9.20** — да. SIG(0)-подписанные запросы, квоты проверок. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/chapter7.html#sig-0)
- **Unbound 1.22** — нет. [Unbound 1.22 manual](https://github.com/NLnetLabs/unbound/blob/release-1.22.0/doc/unbound.conf.5.in)
- **PowerDNS Auth 5.1** — нет. Нет; только TSIG/GSS-TSIG. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/tsig.html)
- **PowerDNS Recursor 5.5** — нет. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/settings.html)

#### A.24. TSIG для UPDATE

- **pulse-dns** — да. TSIG обязателен по умолчанию, replay-кэш, allow_from/allow_zones. `crates/pulsed/src/update.rs`
- **BIND 9.20** — да. TSIG-подпись обновлений. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/chapter7.html#tsig)
- **Unbound 1.22** — нет. [Unbound 1.22 manual](https://github.com/NLnetLabs/unbound/blob/release-1.22.0/doc/unbound.conf.5.in)
- **PowerDNS Auth 5.1** — да. TSIG-ALLOW-DNSUPDATE, dnsupdate-require-tsig, GSS-TSIG. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/domainmetadata.html#allow-dnsupdate-from-forward-dnsupdate-notify-dnsupdate-soa-edit-dnsupdate)
- **PowerDNS Recursor 5.5** — нет. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/settings.html)


### 4.5. Транспорты

#### A.25. UDP/TCP

- **pulse-dns** — да. UDP на io_uring, TCP на tokio event-loop, EDNS/TC. `crates/pulsed/src/dns.rs`
- **BIND 9.20** — да. UDP/TCP. [BIND ARM 9.20](https://kb.isc.org/docs/proxyv2-support-in-bind-9)
- **Unbound 1.22** — да. UDP/TCP. [Unbound 1.22 manual](https://github.com/NLnetLabs/unbound/blob/release-1.22.0/doc/unbound.conf.5.in)
- **PowerDNS Auth 5.1** — да. UDP/TCP. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/settings.html)
- **PowerDNS Recursor 5.5** — да. UDP/TCP. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/settings.html)

#### A.26. DoT

- **pulse-dns** — да. Серверный DoT (RFC 7858), TLS hot-reload. `crates/pulse-tls/src/dot.rs`
- **BIND 9.20** — да. tls-port + tls-блок. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/reference.html#namedconf-statement-tls-port)
- **Unbound 1.22** — да. tls-port + tls-service-key/pem. [Unbound 1.22 manual](https://github.com/NLnetLabs/unbound/blob/release-1.22.0/doc/unbound.conf.5.in)
- **PowerDNS Auth 5.1** — нет. Встроенного DoT нет; ставится dnsdist. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/settings.html)
- **PowerDNS Recursor 5.5** — нет. Встроенного DoT-листенера нет; ставится dnsdist. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/settings.html)

#### A.27. DoH 1.1 / 2

- **pulse-dns** — да. DoH/1.1 и DoH/2 (h2), GET/POST. `crates/pulse-tls/src/doh.rs`
- **BIND 9.20** — частично. DoH через https-port/http-*; в ARM заявлен HTTP/2, HTTP/1.1 не заявлен. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/reference.html#namedconf-statement-https-port)
- **Unbound 1.22** — частично. DoH только HTTP/2 (сборка с libnghttp2); HTTP/1.1 в manual не заявлен. [Unbound 1.22 manual](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html#unbound-conf-https-port)
- **PowerDNS Auth 5.1** — нет. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/settings.html)
- **PowerDNS Recursor 5.5** — нет. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/settings.html)

#### A.28. DoH 3

- **pulse-dns** — да. DoH/3 на quinn/h3, отдельный листенер. `crates/pulse-tls/src/doh3.rs`
- **BIND 9.20** — нет. В 9.20 нет; транспорты BIND — Do53/DoT/DoH. [BIND ARM 9.20](https://kb.isc.org/docs/proxyv2-support-in-bind-9)
- **Unbound 1.22** — нет. DoH только HTTP/2 (libnghttp2). [Unbound 1.22 manual](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html#unbound-conf-https-port)
- **PowerDNS Auth 5.1** — нет. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/settings.html)
- **PowerDNS Recursor 5.5** — нет. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/settings.html)

#### A.29. DoQ

- **pulse-dns** — да. DoQ (RFC 9250) на quinn. `crates/pulse-tls/src/doq.rs`
- **BIND 9.20** — нет. DoQ в 9.20 не реализован (Do53/DoT/DoH). [BIND ARM 9.20](https://kb.isc.org/docs/proxyv2-support-in-bind-9)
- **Unbound 1.22** — да. quic-port/quic-size с 1.22.0 (сборка с libngtcp2). [Unbound 1.22 manual](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html#unbound-conf-quic-port)
- **PowerDNS Auth 5.1** — нет. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/settings.html)
- **PowerDNS Recursor 5.5** — нет. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/settings.html)

#### A.30. DNSCrypt

- **pulse-dns** — да. DNSCrypt v2 UDP+TCP: сертификаты, сервер, клиент, метрики. `crates/pulse-dnscrypt/src/lib.rs`
- **BIND 9.20** — нет. [BIND ARM 9.20](https://kb.isc.org/docs/proxyv2-support-in-bind-9)
- **Unbound 1.22** — да. dnscrypt:-блок (опциональная сборка). [Unbound 1.22 manual](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html#unbound-conf-dnscrypt)
- **PowerDNS Auth 5.1** — нет. Нет; DNSCrypt — отдельный wrapper/dnsdist-сосед. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/settings.html)
- **PowerDNS Recursor 5.5** — нет. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/settings.html)


### 4.6. API и управление

#### A.31. REST API

- **pulse-dns** — да. Zones/RRset CRUD, transfers, jobs, keys, import, audit, settings. `crates/pulse-api/src/handler.rs`
- **BIND 9.20** — нет. Только rndc (TSIG-канал) и statistics-channels. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/manpages.html#rndc)
- **Unbound 1.22** — нет. Только unbound-control (TLS-канал). [Unbound 1.22 manual](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound-control.html)
- **PowerDNS Auth 5.1** — да. REST /api/v1, зоны/метаданные/трансферы. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/http-api/index.html)
- **PowerDNS Recursor 5.5** — да. REST /api/v1 (зоны, статистика, кеш, RPZ, трассировка). [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/http-api/index.html)

#### A.32. OpenAPI

- **pulse-dns** — да. OpenAPI 3.1, статическая схема + /api/v1/openapi.json. `crates/pulse-api/src/openapi.rs`
- **BIND 9.20** — нет. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/reference.html#bind-9-statistics)
- **Unbound 1.22** — нет. [Unbound 1.22 manual](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound-control.html)
- **PowerDNS Auth 5.1** — да. OpenAPI 3.1, доступен с работающего сервера. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/http-api/index.html)
- **PowerDNS Recursor 5.5** — не удалось подтвердить. В документации API OpenAPI-спека не найдена; отсутствие не подтверждено. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/http-api/index.html)

#### A.33. Аутентификация API и scopes

- **pulse-dns** — да. Bearer-токены, scopes (admin/group:*/точечные), per-zone allowlist, Idempotency-Key. `crates/pulse-api/src/auth.rs`
- **BIND 9.20** — частично. rndc-key/ACL, без HTTP API и scopes. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/manpages.html#rndc)
- **Unbound 1.22** — частично. TLS-ключи unbound-control, без scopes. [Unbound 1.22 manual](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound-control.html)
- **PowerDNS Auth 5.1** — частично. Статический X-API-Key, без scopes/ролей. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/settings.html#api-key)
- **PowerDNS Recursor 5.5** — частично. API key/password, без scopes; allow_from. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/settings.html#api-key)

#### A.34. Jobs

- **pulse-dns** — да. Асинхронные операции, Prefer: respond-async, TTL 24 ч, в памяти. `crates/pulse-api/src/jobs.rs`
- **BIND 9.20** — нет. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/manpages.html#rndc)
- **Unbound 1.22** — нет. [Unbound 1.22 manual](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound-control.html)
- **PowerDNS Auth 5.1** — нет. Нет API-задач. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/http-api/index.html)
- **PowerDNS Recursor 5.5** — нет. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/http-api/index.html)

#### A.35. Audit

- **pulse-dns** — да. Аудит мутаций, ring 4096, в памяти (не персистентный). `crates/pulse-api/src/audit.rs`
- **BIND 9.20** — нет. Нет отдельного audit API (только логи). [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/reference.html#bind-9-statistics)
- **Unbound 1.22** — нет. [Unbound 1.22 manual](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound-control.html)
- **PowerDNS Auth 5.1** — нет. Нет audit API. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/http-api/index.html)
- **PowerDNS Recursor 5.5** — нет. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/http-api/index.html)

#### A.36. Metrics

- **pulse-dns** — да. Prometheus /metrics: DNS, transports, cache, journal, jobs. `crates/pulse-api/src/metrics.rs`
- **BIND 9.20** — частично. statistics-channels (JSON/XML), Prometheus-экспорттера нет. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/reference.html#bind-9-statistics)
- **Unbound 1.22** — частично. stats через unbound-control/SNMP, HTTP-Prometheus нет. [Unbound 1.22 manual](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound-control.html)
- **PowerDNS Auth 5.1** — да. Prometheus /metrics + Carbon. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/performance.html)
- **PowerDNS Recursor 5.5** — да. Prometheus /metrics (pdns_recursor_*). [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/metrics.html)


### 4.7. Хранилище

#### A.37. mmap single-file

- **pulse-dns** — да. Один mmap-файл, версии/транзакции, PageCache; зоны не копируются в heap. `crates/pulse-zonefile/src/zonefile.rs`
- **BIND 9.20** — нет. NZD/LMDB (mmap) хранит только конфигурацию зон rndc addzone; данные зон — zone file + journal. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/reference.html#namedconf-statement-lmdb-mapsize)
- **Unbound 1.22** — нет. Zonefile/AXFR/Redis-cache; единого mmap-хранилища нет. [Unbound 1.22 manual](https://github.com/NLnetLabs/unbound/blob/release-1.22.0/doc/unbound.conf.5.in)
- **PowerDNS Auth 5.1** — частично. LMDB-backend — mmap B+tree, но это один из backend'ов и с одним writer'ом. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/backends/index.html)
- **PowerDNS Recursor 5.5** — нет. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/settings.html)

#### A.38. Multi-writer

- **pulse-dns** — да. Несколько процессов пишут разные зоны в один файл: sidecar-координатор, leases, fencing, общий group commit. `docs/adr/0007-multiprocess-writers.md`
- **BIND 9.20** — нет. Один named-процесс; изменения через rndc. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/manpages.html#rndc)
- **Unbound 1.22** — нет. Один процесс (плюс unbound-control). [Unbound 1.22 manual](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound-control.html)
- **PowerDNS Auth 5.1** — частично. Несколько инстансов могут работать с общей SQL-БД (native replication), но файлового multi-writer нет. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/modes-of-operation.html)
- **PowerDNS Recursor 5.5** — нет. Один процесс, многопоточность внутри. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/settings.html)

#### A.39. SQL/backends

- **pulse-dns** — нет. Только встроенный v2-файл; SQL/внешних backend'ов нет. `crates/pulse-zonefile/src/lib.rs`
- **BIND 9.20** — частично. DLZ/DynDB существуют, но DLZ не рекомендуется и не для нагрузки. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/chapter6.html#dynamically-loadable-zones-dlz)
- **Unbound 1.22** — частично. cachedb Redis — кеш, не хранилище зон. [Unbound 1.22 manual](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html#unbound-conf-cachedb)
- **PowerDNS Auth 5.1** — да. gmysql/gpgsql/gsqlite3/godbc/lmdb/bind/pipe/remote и др. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/backends/index.html)
- **PowerDNS Recursor 5.5** — нет. Нет хранилища зон. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/settings.html)

#### A.40. Hot reload

- **pulse-dns** — частично. REST-правки видны сразу (новая версия mmap); SIGHUP — TLS/blocklist; смена конфига — рестарт. `STATUS.md`
- **BIND 9.20** — да. rndc reload/reconfig, dynamic zones. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/manpages.html#rndc)
- **Unbound 1.22** — да. SIGHUP перечитывает конфиг (интерфейсы — рестарт). [Unbound 1.22 manual](https://github.com/NLnetLabs/unbound/blob/release-1.22.0/doc/unbound.conf.5.in)
- **PowerDNS Auth 5.1** — да. pdns_control reload, API, zone cache. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/settings.html)
- **PowerDNS Recursor 5.5** — да. SIGHUP, reload-zones, wipe-cache. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/settings.html)

#### A.41. Bulk-load

- **pulse-dns** — да. pulsed import: master-файлы, bulk-запись, отсортированный вход. `crates/pulsed/src/master.rs`
- **BIND 9.20** — да. Загрузка zone-файлов, named-compilezone. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/reference.html#namedconf-statement-type)
- **Unbound 1.22** — частично. auth-zone из zonefile/URL; отдельного bulk-инструмента нет. [Unbound 1.22 manual](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html#authority-zone-options)
- **PowerDNS Auth 5.1** — да. pdnsutil zone load, SQL-bulk, backend-импорт. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/backends/index.html)
- **PowerDNS Recursor 5.5** — н/п. Рекурсор не хранит зоны. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/settings.html)


### 4.8. Производительность-фичи

#### A.42. io_uring

- **pulse-dns** — да. UDP-рантайм: ring на ядро, multishot recv, provided buffers, REGISTER_FILES, SQPOLL-опция, epoll-фолбэк. `crates/pulse-runtime/src/backend`
- **BIND 9.20** — нет. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/reference.html#bind-9-statistics)
- **Unbound 1.22** — нет. [Unbound 1.22 manual](https://github.com/NLnetLabs/unbound/blob/release-1.22.0/doc/unbound.conf.5.in)
- **PowerDNS Auth 5.1** — нет. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/performance.html)
- **PowerDNS Recursor 5.5** — нет. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/settings.html)

#### A.43. Zero-copy ответа

- **pulse-dns** — да. respond_ref_into: ответ из заимствованных RRset прямо в TX-буфер, 0 аллокаций на горячем пути. `crates/pulse-server/src/lib.rs`
- **BIND 9.20** — нет. Не заявлено. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/reference.html#bind-9-statistics)
- **Unbound 1.22** — нет. Не заявлено. [Unbound 1.22 manual](https://github.com/NLnetLabs/unbound/blob/release-1.22.0/doc/unbound.conf.5.in)
- **PowerDNS Auth 5.1** — нет. Не заявлено. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/performance.html)
- **PowerDNS Recursor 5.5** — нет. Не заявлено. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/metrics.html)

#### A.44. Response cache

- **pulse-dns** — да. Кеш готовых wire-ответов, ключ по версии зоны/регистру QNAME/DO/CD/RD/EDNS/транспорту; в памяти, без decrement TTL. `crates/pulse-server/src/application/cache.rs`
- **BIND 9.20** — нет. У авторитетного BIND кеша ответов нет. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/reference.html#bind-9-statistics)
- **Unbound 1.22** — нет. У auth-zone своего response-кеша нет. [Unbound 1.22 manual](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html#authority-zone-options)
- **PowerDNS Auth 5.1** — да. Packet cache + query cache. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/performance.html#packet-cache)
- **PowerDNS Recursor 5.5** — да. Record cache + packet cache (резолвер). [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/metrics.html)

#### A.45. Group commit

- **pulse-dns** — да. 2 fsync на группу зон; межпроцессный лидер по commit-lease, одна пара fdatasync на всех. `crates/pulse-zonefile/src/parallel/store.rs`
- **BIND 9.20** — нет. Нет (журнал/файлы, fsync по мере записи). [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/chapter6.html#dynamic-update)
- **Unbound 1.22** — нет. [Unbound 1.22 manual](https://github.com/NLnetLabs/unbound/blob/release-1.22.0/doc/unbound.conf.5.in)
- **PowerDNS Auth 5.1** — нет. Нет; durability — на стороне SQL-backend. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/backends/index.html)
- **PowerDNS Recursor 5.5** — нет. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/settings.html)


## 5. Детали: рекурсивный резолвер

### 5.1. Рекурсия и forward

#### R.1. Итеративная рекурсия

- **pulse-dns** — да. От root hints: делегирования, bailiwick, glue, CNAME-цепочки, лимиты глубины/бюджета. `crates/pulse-resolver/src/iterative.rs`
- **BIND 9.20** — да. Полный рекурсор (BIND 9 может быть resolver). [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/chapter3.html#resolver-caching-name-servers)
- **Unbound 1.22** — да. Основной режим Unbound. [Unbound 1.22 manual](https://github.com/NLnetLabs/unbound/blob/release-1.22.0/doc/unbound.conf.5.in)
- **PowerDNS Auth 5.1** — нет. Не резолвер. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/modes-of-operation.html)
- **PowerDNS Recursor 5.5** — да. Основной режим Recursor. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/settings.html)

#### R.2. Forward

- **pulse-dns** — да. Глобальный forward-режим со смешанными upstream и failover; per-zone forward нет. `crates/pulse-resolver/src/forward.rs`
- **BIND 9.20** — да. forwarders, forward only/first, per-zone. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/reference.html#namedconf-statement-forwarders)
- **Unbound 1.22** — да. forward-zone (per-zone). [Unbound 1.22 manual](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html#forward-zone-options)
- **PowerDNS Auth 5.1** — нет. Не резолвер. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/modes-of-operation.html)
- **PowerDNS Recursor 5.5** — да. forward-zones (per-zone). [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/settings.html#forward-zones)

#### R.3. Stub-зоны

- **pulse-dns** — нет. Нет: только forward-режим целиком. `crates/pulse-resolver/src/config.rs`
- **BIND 9.20** — да. stub/static-stub зоны. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/reference.html#namedconf-statement-type)
- **Unbound 1.22** — да. stub-zone. [Unbound 1.22 manual](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html#stub-zone-options)
- **PowerDNS Auth 5.1** — нет. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/modes-of-operation.html)
- **PowerDNS Recursor 5.5** — нет. Нет stub-зон. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/settings.html#forward-zones)

#### R.4. QNAME minimization

- **pulse-dns** — да. Реализована, но по умолчанию выключена (qname_minimization=false). `crates/pulse-resolver/src/config.rs`
- **BIND 9.20** — да. По умолчанию relaxed (RFC 9156/7816). [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/reference.html#namedconf-statement-qname-minimization)
- **Unbound 1.22** — да. По умолчанию включена; есть strict-режим. [Unbound 1.22 manual](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html#unbound-conf-qname-minimisation)
- **PowerDNS Auth 5.1** — нет. Не резолвер. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/modes-of-operation.html)
- **PowerDNS Recursor 5.5** — да. По умолчанию включена, relaxed RFC 9156. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/settings.html#qname-minimization)

#### R.5. 0x20-рандомизация

- **pulse-dns** — да. Для UDP-upstream включена по умолчанию (use_0x20=true); эхо регистра клиенту на авторитетном сервере — нет. `crates/pulse-resolver/src/config.rs`
- **BIND 9.20** — нет. BIND 0x20 не реализует. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/reference.html#namedconf-statement-qname-minimization)
- **Unbound 1.22** — да. use-caps-for-id, по умолчанию выключена. [Unbound 1.22 manual](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html#unbound-conf-use-caps-for-id)
- **PowerDNS Auth 5.1** — нет. Не резолвер. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/modes-of-operation.html)
- **PowerDNS Recursor 5.5** — нет. Опции 0x20 в 5.5 нет. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/settings.html)

#### R.6. Prefetch

- **pulse-dns** — нет. Нет prefetch по TTL. `crates/pulse-resolver/src/cache.rs`
- **BIND 9.20** — да. prefetch с trigger TTL (по умолчанию 2 с). [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/reference.html#namedconf-statement-prefetch)
- **Unbound 1.22** — да. prefetch (по умолчанию off). [Unbound 1.22 manual](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html#unbound-conf-prefetch)
- **PowerDNS Auth 5.1** — нет. Не резолвер. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/modes-of-operation.html)
- **PowerDNS Recursor 5.5** — частично. refresh-on-ttl-perc — обновление по остатку TTL, не классический prefetch. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/settings.html)

#### R.7. Serve-stale

- **pulse-dns** — нет. `crates/pulse-resolver/src/cache.rs`
- **BIND 9.20** — да. stale-answer-enable/stale-answer-ttl. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/reference.html#namedconf-statement-stale-answer-enable)
- **Unbound 1.22** — да. serve-expired (TTL, client-timeout, EDE). [Unbound 1.22 manual](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html#unbound-conf-serve-expired)
- **PowerDNS Auth 5.1** — нет. Не резолвер. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/modes-of-operation.html)
- **PowerDNS Recursor 5.5** — да. serve-stale-extensions (с 4.8). [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/settings.html#serve-stale-extensions)


### 5.2. Кеш

#### R.8. Positive/negative cache + TTL

- **pulse-dns** — да. Шардированный кеш, TTL как absolute deadline, RFC 2308 negative caching, лимиты записей/памяти. `crates/pulse-resolver/src/cache.rs`
- **BIND 9.20** — да. RRset/message cache, negative TTL, min/max кеш-TTL. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/reference.html#namedconf-statement-max-cache-size)
- **Unbound 1.22** — да. msg/rrset/neg caches, TTL-границы. [Unbound 1.22 manual](https://github.com/NLnetLabs/unbound/blob/release-1.22.0/doc/unbound.conf.5.in)
- **PowerDNS Auth 5.1** — нет. Не резолвер. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/modes-of-operation.html)
- **PowerDNS Recursor 5.5** — да. Record cache + negative cache, TTL-границы. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/metrics.html)

#### R.9. Персистентность кеша

- **pulse-dns** — нет. Кеш только в памяти, после рестарта пуст. `crates/pulse-resolver/src/cache.rs`
- **BIND 9.20** — нет. Только rndc dumpdb для диагностики; автозагрузки кеша нет. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/reference.html#namedconf-statement-dump-file)
- **Unbound 1.22** — частично. cachedb (Redis) или dump_cache/load_cache вручную. [Unbound 1.22 manual](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html#unbound-conf-cachedb)
- **PowerDNS Auth 5.1** — нет. Не резолвер. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/modes-of-operation.html)
- **PowerDNS Recursor 5.5** — нет. Кеш не персистится (кроме save-parent-ns-set). [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/settings.html)


### 5.3. DNSSEC

#### R.10. DNSSEC-валидация и алгоритмы

- **pulse-dns** — да. Цепочка DS→DNSKEY→RRSIG, AD/BOGUS→SERVFAIL; 8/10/13/14/15, legacy 5/7 opt-in, Ed448 нет. `crates/pulse-resolver/src/dnssec.rs`
- **BIND 9.20** — да. Валидация по умолчанию, широкий набор алгоритмов. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/chapter5.html#dnssec-validation)
- **Unbound 1.22** — да. Validator, RSA/ECDSA/Ed25519/Ed448. [Unbound 1.22 manual](https://github.com/NLnetLabs/unbound/blob/release-1.22.0/doc/unbound.conf.5.in)
- **PowerDNS Auth 5.1** — нет. Не резолвер. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/dnssec/index.html)
- **PowerDNS Recursor 5.5** — да. Валидация (process/validate), алгоритмы зависят от crypto-lib. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/dnssec.html)

#### R.11. NSEC3-валидация

- **pulse-dns** — да. NSEC/NSEC3 (SHA-1, salt/iterations), closest encloser, wildcard, opt-out. `crates/pulse-dnssec/src/denial/nsec3.rs`
- **BIND 9.20** — да. NSEC/NSEC3. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/reference.html#namedconf-statement-nsec3param)
- **Unbound 1.22** — да. NSEC/NSEC3. [Unbound 1.22 manual](https://github.com/NLnetLabs/unbound/blob/release-1.22.0/doc/unbound.conf.5.in)
- **PowerDNS Auth 5.1** — нет. Не резолвер. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/dnssec/index.html)
- **PowerDNS Recursor 5.5** — да. NSEC/NSEC3, лимиты итераций/хешей. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/dnssec.html)

#### R.12. Root trust anchor

- **pulse-dns** — да. Встроенные IANA-anchors + конфигурируемые DS/ключа. `crates/pulse-dnssec/src/trust_anchor.rs`
- **BIND 9.20** — да. Встроенный root TA, обновляется. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/chapter5.html#dnssec-validation)
- **Unbound 1.22** — да. root.key/auto-trust-anchor-file. [Unbound 1.22 manual](https://github.com/NLnetLabs/unbound/blob/release-1.22.0/doc/unbound.conf.5.in)
- **PowerDNS Auth 5.1** — нет. Не резолвер. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/dnssec/index.html)
- **PowerDNS Recursor 5.5** — да. trustanchors/trustanchorfile. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/dnssec.html)

#### R.13. RFC 5011

- **pulse-dns** — да. TrustAnchorStore: add/revoke hold-down, кандидаты, состояние 0600. `crates/pulse-dnssec/src/trust_update.rs`
- **BIND 9.20** — да. Dynamic Trust Anchor Management. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/chapter5.html#dynamic-trust-anchor-management)
- **Unbound 1.22** — да. auto-trust-anchor-file (RFC 5011). [Unbound 1.22 manual](https://github.com/NLnetLabs/unbound/blob/release-1.22.0/doc/unbound.conf.5.in)
- **PowerDNS Auth 5.1** — нет. Не резолвер. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/dnssec/index.html)
- **PowerDNS Recursor 5.5** — нет. Официально: RFC 5011 не поддерживается, изменённый root TA не персистится. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/dnssec.html)


### 5.4. Политики и защита

#### R.14. RPZ / adblock / blocklist

- **pulse-dns** — частично. Blocklist/allowlist (файлы + HTTPS-фиды, NXDOMAIN/null-IP) вместо RPZ; триггеров по IP/NS нет. `crates/pulse-resolver/src/blocklist.rs`
- **BIND 9.20** — да. RPZ (QNAME/IP/NSIP/NSDNAME, 6 действий), до 64 зон. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/chapter6.html#dns-firewalls-and-response-policy-zones)
- **Unbound 1.22** — да. RPZ через respip-модуль (QNAME/IP/nsdname/nsip/clientip). [Unbound 1.22 manual](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html#unbound-conf-rpz)
- **PowerDNS Auth 5.1** — нет. Не резолвер. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/modes-of-operation.html)
- **PowerDNS Recursor 5.5** — да. RPZ через Lua-конфиг. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/lua-config/rpz.html)

#### R.15. Overrides / local zones

- **pulse-dns** — частично. Overrides A/AAAA/CNAME (приоритетнее blocklist/upstream); полноценных local-zone нет. `crates/pulse-resolver/src/overrides.rs`
- **BIND 9.20** — да. local-zones/local-data, RPZ. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/reference.html#namedconf-statement-response-policy)
- **Unbound 1.22** — да. local-zone/local-data. [Unbound 1.22 manual](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html#unbound-conf-local-zone)
- **PowerDNS Auth 5.1** — нет. Не резолвер. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/modes-of-operation.html)
- **PowerDNS Recursor 5.5** — да. auth-zones + Lua-хуки. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/settings.html)

#### R.16. RRL / rate limit

- **pulse-dns** — да. RRL по классам noerror/nxdomain/referral/error, per-source + per-name, slip/drop/refused/truncate; только UDP + token bucket на TLS. `crates/pulseresolved/src/rrl.rs`
- **BIND 9.20** — да. rate-limit (RRL) с credit/token bucket. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/reference.html#rrl)
- **Unbound 1.22** — частично. ip-ratelimit по клиенту; RRL по именам нет. [Unbound 1.22 manual](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html#unbound-conf-ip-ratelimit)
- **PowerDNS Auth 5.1** — нет. Не резолвер. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/modes-of-operation.html)
- **PowerDNS Recursor 5.5** — нет. RRL нет; обычно dnsdist. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/settings.html)

#### R.17. ACL клиентов

- **pulse-dns** — да. allow_from, по умолчанию loopback; отдельный tls_allow_from. `crates/pulseresolved/src/secure.rs`
- **BIND 9.20** — да. allow-query/allow-recursion/allow-query-cache. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/reference.html#namedconf-statement-allow-query)
- **Unbound 1.22** — да. access-control allow/deny/refuse. [Unbound 1.22 manual](https://github.com/NLnetLabs/unbound/blob/release-1.22.0/doc/unbound.conf.5.in)
- **PowerDNS Auth 5.1** — нет. Не резолвер. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/modes-of-operation.html)
- **PowerDNS Recursor 5.5** — да. allow-from/allow-from-file. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/settings.html#allow-from)

#### R.18. DNS Cookies

- **pulse-dns** — нет. Нет ни серверных, ни клиентских cookies. `STATUS.md`
- **BIND 9.20** — да. answer-cookie, require-cookie. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/reference.html#namedconf-statement-answer-cookie)
- **Unbound 1.22** — да. answer-cookie + cookie-secret, ip-ratelimit-cookie. [Unbound 1.22 manual](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html#unbound-conf-answer-cookie)
- **PowerDNS Auth 5.1** — нет. Не резолвер. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/modes-of-operation.html)
- **PowerDNS Recursor 5.5** — частично. Только исходящие cookies с 5.4; входящие в документации не заявлены. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/settings.html#outgoing-cookies)


### 5.5. Транспорты

#### R.19. Транспорты вниз (клиент→резолвер)

- **pulse-dns** — да. UDP/TCP/DoT/DoH1.1/DoH2/DoQ/DNSCrypt v2; DoH3 нет. `crates/pulseresolved/src/lib.rs`
- **BIND 9.20** — да. Do53/DoT/DoH (HTTP/2); DoQ/DNSCrypt/DoH3 нет. [BIND ARM 9.20](https://kb.isc.org/docs/proxyv2-support-in-bind-9)
- **Unbound 1.22** — да. UDP/TCP/DoT/DoH/DoQ/DNSCrypt (сборка). [Unbound 1.22 manual](https://github.com/NLnetLabs/unbound/blob/release-1.22.0/doc/unbound.conf.5.in)
- **PowerDNS Auth 5.1** — нет. Не резолвер. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/modes-of-operation.html)
- **PowerDNS Recursor 5.5** — нет. Встроенных DoT/DoH/DoQ-листенеров нет; ставится dnsdist. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/settings.html)

#### R.20. Транспорты вверх (резолвер→upstream)

- **pulse-dns** — частично. UDP/TCP/DoT/DoH1.1 с failover/cooldown/пулом; DoH2/3 и DoQ-апстрима нет. `crates/pulse-resolver/src/upstream.rs`
- **BIND 9.20** — частично. DoT к forwarders/primaries; DoH/DoQ-апстрима нет. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/reference.html#namedconf-statement-forwarders)
- **Unbound 1.22** — частично. DoT (forward/stub-tls-upstream); DoH/DoQ-апстрима нет. [Unbound 1.22 manual](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html#unbound-conf-tls-upstream)
- **PowerDNS Auth 5.1** — нет. Не резолвер. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/modes-of-operation.html)
- **PowerDNS Recursor 5.5** — частично. DoT (dot-to-auth-names, tls_configurations); DoH/DoQ-апстрима нет. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/settings.html#dot-to-auth-names)


### 5.6. API и управление

#### R.21. API / метрики

- **pulse-dns** — да. Prometheus /metrics, /healthz, control REST на loopback с bearer-токеном. `crates/pulseresolved/src/control.rs`
- **BIND 9.20** — частично. rndc/statistics-channels, HTTP REST API нет. [BIND ARM 9.20](https://bind9.readthedocs.io/en/v9.20.15/reference.html#bind-9-statistics)
- **Unbound 1.22** — частично. unbound-control + stats; HTTP API нет. [Unbound 1.22 manual](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound-control.html)
- **PowerDNS Auth 5.1** — нет. Не резолвер. [PowerDNS Auth docs](https://doc.powerdns.com/authoritative/modes-of-operation.html)
- **PowerDNS Recursor 5.5** — да. REST API + Prometheus /metrics. [PowerDNS Recursor docs](https://doc.powerdns.com/recursor/http-api/index.html)


## 6. Наши отличия (это не «стандартные функции»)

Перечисленное ниже — архитектурные решения pulse-dns, которых нет у сравниваемых продуктов
в таком виде. Это не преимущества «вообще», а свойства, которые надо проверять под свою задачу.

| Отличие | В чём суть | Где |
|---|---|---|
| **Один mmap-файл на все зоны** | Зоны, каталог, версии и IXFR-история лежат в одном v2-файле; DNS-потоки читают из mmap без полной heap-копии зон и без GC-пауз. | `crates/pulse-zonefile/src/zonefile.rs`, `docs/adr/0003-zonefile-format.md` |
| **Многопроцессная запись** | Несколько процессов (`--role dns` / `--role api`) пишут разные зоны в один файл: sidecar-координатор, `fcntl`-leases, fencing по pid/starttime/generation, общая reader table. | `docs/adr/0007-multiprocess-writers.md` |
| **Межпроцессный group commit** | Одна пара `fdatasync` на группу коммитов от всех процессов; лидер выбирается по commit-lease и переживает kill -9 без потери версий. | `crates/pulse-zonefile/src/parallel/store.rs` |
| **Rust без GC и без `unsafe` в wire-крейте** | Предсказуемые задержки, `pulse-dns` с `#![forbid(unsafe_code)]`; нет сборщика мусора и «мировых стопов». | `crates/pulse-dns/src/lib.rs` |
| **io_uring UDP-рантайм** | Ring на ядро, multishot recv + provided buffers, `REGISTER_FILES`, COOP/DEFER_TASKRUN, опции SQPOLL/SO_BUSY_POLL, IP_PKTINFO; epoll-фолбэк. | `crates/pulse-runtime/src/backend` |
| **Zero-copy ответ** | `respond_ref_into` собирает ответ из заимствованных RRset прямо в TX-буфер; на горячем пути 0 аллокаций (включая signed/referral/ANY/EDNS). | `crates/pulse-server/src/lib.rs` |
| **Встроенные DNSCrypt v2, DoQ и DoH/3** | И у `pulsed`, и у `pulseresolved`; у BIND/PowerDNS этого нет, у Unbound DNSCrypt/DoQ есть, DoH3 — нет. | `crates/pulse-dnscrypt`, `crates/pulse-tls/src/doq.rs`, `crates/pulse-tls/src/doh3.rs` |
| **Декларативная per-name/type UPDATE-политика + SIG(0)** | `update.policy`: зона/имя (exact/suffix/wildcard)/тип/principal (TSIG/SIG0/subnet/any), первое совпадение, default deny; SIG(0) с replay-кэшем. | `crates/pulsed/src/config.rs`, `crates/pulsed/src/update.rs` |
| **REST уровня «взрослого» API** | OpenAPI 3.1, scopes + per-zone allowlist, ETag/If-Match, Idempotency-Key, RFC 9457 problem+json, async jobs, WAL-outbox мутаций. | `crates/pulse-api`, `docs/api/rest-v1.md` |
| **IXFR-out из истории коммитов** | Дельты строятся из версий зоны; PowerDNS Auth IXFR-out не умеет вообще, Unbound — не отдаёт AXFR/IXFR. | `crates/pulsed/src/transfer.rs` |
| **Нет внешней БД и отдельного демона для TLS** | Один бинарник + файл; нет SQL/Redis/keystore-зависимости для базового режима. | `Cargo.toml`, `crates/*` |

## 7. Чего у нас нет (без смягчений)

### 7.1. Авторитетный сервер

- **Catalog zones (RFC 9432)** — ни producer, ни consumer; авто-провижининг зон из каталога невозможен.
- **Views / split-horizon** — один набор зон для всех клиентов; нельзя отдать разный ответ internal/external.
- **Stub-зоны** — нет. **Forward-зоны** — только `kind=forward` в модели/API и поле upstreams в формате; фактического резолвинга через upstream в `pulsed` нет.
- **Per-zone query ACL** — нет `allow-query` на зону. Есть только: общий `tls_allow_from` для DoT/DoH/DoQ, `transfer.allow_zones` и `update.allow_zones`.
- **ACL на обычные UDP/TCP-запросы** — нет вообще: plain DNS принимает запросы от любого источника.
- **NSEC3 для secondary-зон** и **автоматическая ротация ключей secondary** — не генерируются/не выполняются.
- **Непрерывный inline-signing** — подпись при старте, по job/API и после ротации; автоматической переподписи при изменении данных/истечении подписей нет.
- **Алгоритмы**: нет подписи Ed448, RSA/SHA-512 (10), ECDSA P-384 (14); SHA-1 (5/7) — только legacy-валидация по opt-in. Ed448 не валидируется.
- **HSM/PKCS#11** — нет; ключи только файлами.
- **TSIG на обычных запросах** — нет (только transfer/update). **GSS-TSIG/Kerberos** — нет.
- **DNS Cookies** (server, BADCOOKIE) — нет. **Эхо 0x20** для клиента — нет (имена канонизируются).
- **RRL авторитетного сервера** — нет; RRL есть только у резолвера и только на UDP.
- **SQL/внешние backends** — нет; только один v2-файл, до 4096 зон.
- **REST поверх TLS / mTLS / удалённый bind** — API только на loopback и без TLS; у резолвера один статический control-токен.
- **Мультитенантность, GeoIP, Lua-записи** — нет.
- **Персистентность response-кеша** — кеш только в памяти и сбрасывается при рестарте.
- **Каталог/durable-commit сериализованы** между процессами (осознанный компромисс ADR 0007).

### 7.2. Резолвер

- **Prefetch** — нет.
- **Serve-stale** — нет.
- **Персистентность кеша** — нет; после рестарта кеш пуст.
- **RPZ** — нет; есть blocklist/allowlist/HTTPS-фиды и overrides. Триггеров по IP/NS/NSDNAME и действий RPZ нет.
- **Local zones** — только overrides A/AAAA/CNAME; полноценных local-zone/local-data нет.
- **Stub-зоны и per-zone forward** — нет; forward-режим глобальный.
- **DoH/DoQ-апстрим** — нет; только UDP/TCP/DoT/DoH 1.1.
- **DoH/3 вниз** — нет.
- **DNS Cookies** (входящие и исходящие) — нет.
- **Эхо 0x20 клиенту** — нет (0x20 работает только на upstream-UDP).
- **Ed448** — не валидируется; SHA-1 (5/7) по умолчанию запрещён.
- **RRL на TLS/QUIC** — вместо RRL работает per-source token bucket (слабее по семантике).
- **Views по клиенту** — нет.

## 8. Расхождения и оговорки (важно для честности)

1. На момент среза в рабочем дереве есть **незакоммиченные** изменения (последний коммит — `7e33e5e`): новые
   `crates/pulse-dnssec/src/sig0.rs` и `crates/pulsed/src/tsigkeys.rs`, правки `crates/pulsed/src/{update,config,store,transfer}.rs`,
   тесты и `examples/pulsed-update.toml`. Именно они добавляют **SIG(0)**, **per-name update-policy** и управляемые TSIG-ключи.
   `README.md` (строки ~565, ~567) и `STATUS.md` (строка ~210) этого ещё не отражают и говорят «нет».
   Матрица описывает **рабочее дерево**; при сравнении с релизом эти пункты надо считать «есть в разработке», а не отгруженными.
2. `STATUS.md`/`README.md` пишут «0x20 echo нет». Это верно для **авторитетного** сервера (регистр QNAME не сохраняется),
   но у **резолвера** 0x20-рандомизация upstream-UDP включена по умолчанию (`use_0x20: true`). В матрице это разделено.
3. Дерево активно меняется (одновременно правятся `pulse-api`, `pulse-dnssec`, `pulsed`), поэтому срез зафиксирован датой
   и не является утверждением о содержимом какого-либо тега.
4. Unbound в 2026 имеет версии 1.25/1.26; здесь по требованию зафиксирована **1.22.0**. Часть возможностей
   (например, DoQ) появилась именно в 1.22.0, поэтому переносить выводы на более старые 1.21 нельзя.
5. BIND 9.20 — актуальная стабильная ветка, но **DoQ в ней нет**; не путать с планами/патчами.

## 9. Источники

### 9.1. Официальная документация

| Продукт | Версия | Ссылки |
|---|---|---|
| BIND 9 | 9.20.15 | [ARM: index](https://bind9.readthedocs.io/en/v9.20.15/), [гл. 5 DNSSEC](https://bind9.readthedocs.io/en/v9.20.15/chapter5.html), [гл. 6 advanced](https://bind9.readthedocs.io/en/v9.20.15/chapter6.html), [гл. 7 security](https://bind9.readthedocs.io/en/v9.20.15/chapter7.html), [reference](https://bind9.readthedocs.io/en/v9.20.15/reference.html), [manpages/rndc](https://bind9.readthedocs.io/en/v9.20.15/manpages.html#rndc), [ISC KB: транспорты BIND](https://kb.isc.org/docs/proxyv2-support-in-bind-9) |
| Unbound | 1.22.0 | [unbound.conf(5), тег 1.22.0](https://github.com/NLnetLabs/unbound/blob/release-1.22.0/doc/unbound.conf.5.in), [Changelog 1.22.0](https://github.com/NLnetLabs/unbound/blob/release-1.22.0/doc/Changelog), [актуальный manual](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html), [unbound-control](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound-control.html) |
| PowerDNS Authoritative | 5.1.7 | [docs](https://doc.powerdns.com/authoritative/), [modes](https://doc.powerdns.com/authoritative/modes-of-operation.html), [DNSSEC profile](https://doc.powerdns.com/authoritative/dnssec/profile.html), [catalog](https://doc.powerdns.com/authoritative/catalog.html), [views](https://doc.powerdns.com/authoritative/views.html), [domain metadata](https://doc.powerdns.com/authoritative/domainmetadata.html), [DNS update](https://doc.powerdns.com/authoritative/dnsupdate.html), [TSIG](https://doc.powerdns.com/authoritative/tsig.html), [HTTP API](https://doc.powerdns.com/authoritative/http-api/index.html), [settings](https://doc.powerdns.com/authoritative/settings.html), [performance](https://doc.powerdns.com/authoritative/performance.html), [backends](https://doc.powerdns.com/authoritative/backends/index.html) |
| PowerDNS Recursor | 5.5.0 | [docs](https://doc.powerdns.com/recursor/), [settings](https://doc.powerdns.com/recursor/settings.html), [YAML settings](https://doc.powerdns.com/recursor/yamlsettings.html), [DNSSEC](https://doc.powerdns.com/recursor/dnssec.html), [RPZ](https://doc.powerdns.com/recursor/lua-config/rpz.html), [HTTP API](https://doc.powerdns.com/recursor/http-api/index.html), [metrics](https://doc.powerdns.com/recursor/metrics.html), [changelog](https://doc.powerdns.com/recursor/changelog/index.html) |

### 9.2. RFC

RFC 1035 (wire/master), 1995 (IXFR), 1996 (NOTIFY), 2136 (UPDATE), 2308 (negative caching), 2845/8945 (TSIG),
2931/3007 (SIG(0)), 4034/4035 (DNSSEC), 5011 (trust anchor rollover), 5155 (NSEC3), 6891 (EDNS0),
7858 (DoT), 7873/9018 (Cookies), 8482 (ANY), 8484 (DoH), 9250 (DoQ), 9432 (catalog zones).
RRL не стандартизован RFC: это `draft-vixie-dns-rrl`, реализован в BIND и в нашем резолвере.

### 9.3. Наши артефакты

- `STATUS.md`, `README.md` — фактическое состояние и ограничения.
- `docs/adr/0003-zonefile-format.md`, `docs/adr/0007-multiprocess-writers.md`, `docs/process-roles.md`.
- `docs/api/rest-v1.md`, `crates/pulse-api/src/openapi.rs`.
- Код: `crates/pulse-server/src/{lib.rs,update.rs}`, `crates/pulsed/src/{config.rs,update.rs,transfer.rs,secondary.rs,rotation.rs,store.rs}`,
  `crates/pulse-dnssec/src/{algorithm.rs,sig0.rs,trust_update.rs}`, `crates/pulse-transfer/src/tsig.rs`,
  `crates/pulse-zonefile/src/parallel/store.rs`, `crates/pulse-runtime/src/backend`,
  `crates/pulse-resolver/src/{config.rs,iterative.rs,cache.rs,dnssec.rs,blocklist.rs,overrides.rs}`,
  `crates/pulseresolved/src/{rrl.rs,control.rs}`.

## 10. Машиночитаемые файлы

- `functional.json` — те же данные: `meta`, `features[]`, у каждой ячейки `status`/`note`/`ref`.
- `functional.csv` — плоская таблица для Excel/Sheets (по строке на функцию, по 3 колонки на продукт).
- JSON и CSV содержат те же данные, что и таблицы; при расхождении источником истины считать `functional.json` (срез на 2026-11-26).

