//! Горячий путь `pulseresolved`: wire-эквивалентность старому Message-пути,
//! EDNS/TC, ACL до резолва и конкурентные запросы через реальные UDP/TCP.

mod support;

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use pulse_dns::{DecodeLimits, EncodeOptions, Message, Record, Rtype, Ttl};
use pulse_resolver::Resolver;
use pulseresolved::config::{Config, RateLimitAction, RateLimitSetting};
use pulseresolved::server::Server;

use support::e2e::{SOCKET_TIMEOUT, retry};
use support::{
    MockUpstream, a_record, make_query, positive_response, tcp_query_retry, udp_query_retry,
};

const NAME: &str = "hotpath.test";

/// Сколько раз повторять UDP-запрос, прежде чем считать его потерянным.
const UDP_ATTEMPTS: u32 = 5;

/// Таймаут одного UDP-обмена (щедрый: debug-сборка под нагрузкой).
const UDP_TIMEOUT: Duration = Duration::from_secs(5);

/// Бюджет проверки согласованности: повторы и все клиентские потоки.
const CONSISTENCY_DEADLINE: Duration = Duration::from_secs(30);

/// Клиентских потоков в конкурентном тесте.
const CONCURRENT_CLIENTS: usize = 4;

/// Запросов на поток (если позволяет дедлайн).
const QUERIES_PER_CLIENT: usize = 100;

/// Начальная и максимальная пауза между повторами UDP-запроса.
const RETRY_BACKOFF_START: Duration = Duration::from_millis(50);
const RETRY_BACKOFF_MAX: Duration = Duration::from_secs(1);

/// Источник ID для повторов: каждая попытка получает новый ID, поэтому
/// запоздавший ответ прошлой попытки не принимается за ответ текущей.
static NEXT_ID: AtomicU16 = AtomicU16::new(0x1000);

fn next_id() -> u16 {
    NEXT_ID.fetch_add(1, Ordering::Relaxed)
}

fn upstream() -> MockUpstream {
    MockUpstream::start(|request| {
        Some(positive_response(
            request,
            a_record(NAME, [192, 0, 2, 77], 300),
        ))
    })
}

fn udp_raw(server: SocketAddr, request: &[u8]) -> Vec<u8> {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind udp client");
    socket
        .set_read_timeout(Some(SOCKET_TIMEOUT))
        .expect("udp timeout");
    socket.send_to(request, server).expect("send udp");
    let mut buffer = [0_u8; 4096];
    loop {
        match socket.recv_from(&mut buffer) {
            Ok((length, _)) => return buffer[..length].to_vec(),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => panic!("recv udp: {error}"),
        }
    }
}

fn tcp_raw(server: SocketAddr, request: &[u8]) -> Vec<u8> {
    let mut stream = retry(
        "tcp raw connect",
        || format!("tcp {server}"),
        || TcpStream::connect(server).map_err(|error| error.to_string()),
    );
    stream
        .set_read_timeout(Some(SOCKET_TIMEOUT))
        .expect("tcp timeout");
    let length = u16::try_from(request.len()).expect("query fits u16");
    stream
        .write_all(&length.to_be_bytes())
        .expect("write length");
    stream.write_all(request).expect("write query");
    stream.flush().expect("flush");
    let mut prefix = [0_u8; 2];
    stream.read_exact(&mut prefix).expect("read length");
    let mut response = vec![0_u8; usize::from(u16::from_be_bytes(prefix))];
    stream.read_exact(&mut response).expect("read response");
    response
}

fn normalize(mut bytes: Vec<u8>) -> Vec<u8> {
    assert!(bytes.len() >= 2, "short response");
    bytes[..2].fill(0);
    bytes
}

/// Обнуляет TTL обычных RR, не трогая `OPT` (у него это поле несёт флаги EDNS).
///
/// Кеш отдаёт уменьшающийся остаток TTL, поэтому побайтовое сравнение через
/// секунду после прогрева законно различается. Всё остальное в wire-форме
/// (сжатие имён, порядок записей, флаги `OPT`) остаётся под сравнением.
fn mask_rr_ttls(bytes: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    let Some(counts) = out.get(4..12) else {
        return out;
    };
    let questions = usize::from(u16::from_be_bytes([counts[0], counts[1]]));
    let answers = usize::from(u16::from_be_bytes([counts[2], counts[3]]));
    let authority = usize::from(u16::from_be_bytes([counts[4], counts[5]]));
    let additional = usize::from(u16::from_be_bytes([counts[6], counts[7]]));
    let mut pos = 12;
    for _ in 0..questions {
        pos = skip_wire_name(&out, pos).saturating_add(4);
    }
    for _ in 0..(answers + authority + additional) {
        pos = skip_wire_name(&out, pos);
        let Some(kind) = out.get(pos..pos.saturating_add(2)) else {
            return out;
        };
        let rr_type = u16::from_be_bytes([kind[0], kind[1]]);
        pos = pos.saturating_add(4); // type + class
        if rr_type != 41
            && let Some(ttl) = out.get_mut(pos..pos.saturating_add(4))
        {
            ttl.fill(0);
        }
        pos = pos.saturating_add(4); // TTL
        let Some(length) = out.get(pos..pos.saturating_add(2)) else {
            return out;
        };
        let rdata_len = usize::from(u16::from_be_bytes([length[0], length[1]]));
        pos = pos.saturating_add(2).saturating_add(rdata_len);
    }
    out
}

fn skip_wire_name(bytes: &[u8], mut pos: usize) -> usize {
    loop {
        let Some(&length) = bytes.get(pos) else {
            return bytes.len();
        };
        if length == 0 {
            return pos.saturating_add(1);
        }
        if length & 0xC0 == 0xC0 {
            return pos.saturating_add(2);
        }
        pos = pos.saturating_add(1).saturating_add(usize::from(length));
    }
}

#[test]
fn ttl_mask_keeps_wire_shape_and_edns_flags() {
    let request = make_query(NAME, Rtype::A, None);
    let mut older = Message::response(&request);
    older.add_answer(a_record(NAME, [192, 0, 2, 77], 299));
    let mut newer = Message::response(&request);
    newer.add_answer(a_record(NAME, [192, 0, 2, 77], 300));

    let older_wire = older.encode(&EncodeOptions::default()).expect("encode");
    let newer_wire = newer.encode(&EncodeOptions::default()).expect("encode");
    assert_ne!(older_wire, newer_wire, "TTL должен различать wire-формы");
    let masked = mask_rr_ttls(&older_wire);
    assert_eq!(masked.len(), older_wire.len(), "маска не меняет длину");
    assert_eq!(masked, mask_rr_ttls(&newer_wire), "TTL замаскирован");
    assert!(
        masked.windows(4).any(|window| window == [192, 0, 2, 77]),
        "RDATA не должна попасть под маску"
    );

    // Поле TTL у OPT несёт флаги EDNS: его маскировать нельзя.
    let mut plain = older.clone();
    plain.set_edns(Some(pulse_dns::Edns::new(4096)));
    let mut with_do = older;
    with_do.set_edns(Some(pulse_dns::Edns::new(4096).with_dnssec_ok(true)));
    let plain_wire = plain.encode(&EncodeOptions::default()).expect("encode");
    let do_wire = with_do.encode(&EncodeOptions::default()).expect("encode");
    assert_ne!(plain_wire, do_wire);
    assert_ne!(
        mask_rr_ttls(&plain_wire),
        mask_rr_ttls(&do_wire),
        "DO-флаг в OPT должен остаться под сравнением"
    );
}

/// Последняя транспортная ошибка: попадает в диагностику при падении.
#[derive(Default)]
struct LastError {
    inner: Mutex<Option<String>>,
}

impl LastError {
    fn record(&self, message: String) {
        *self.inner.lock().expect("last error lock") = Some(message);
    }

    fn get(&self) -> String {
        self.inner
            .lock()
            .expect("last error lock")
            .clone()
            .unwrap_or_else(|| "ошибок не было".to_owned())
    }
}

/// Снимок счётчиков сервера и резолвера для сообщения о падении.
fn server_diagnostics(server: &Server) -> String {
    format!(
        "stats={:?}; udp={:?}; resolver={:?}",
        server.stats(),
        server.udp_stats(),
        server.resolver_stats()
    )
}

/// Представление ответа без ID и TTL.
///
/// Кеш отдаёт уменьшающийся остаток TTL, поэтому побайтовое сравнение через
/// секунду после прогрева законно различается. Инвариант согласованности —
/// совпадение RCODE, флагов, вопроса и данных всех секций.
fn semantic_view(bytes: &[u8], label: &str) -> Message {
    let message = Message::decode(bytes, &DecodeLimits::default())
        .unwrap_or_else(|error| panic!("{label}: декодирование ответа: {error}"));
    let mut view = Message::new(0, message.flags());
    view.set_edns(message.edns().cloned());
    for question in message.questions() {
        view.add_question(question.clone());
    }
    for record in message.answers() {
        view.add_answer(with_zero_ttl(record));
    }
    for record in message.authority() {
        view.add_authority(with_zero_ttl(record));
    }
    for record in message.additional() {
        view.add_additional(with_zero_ttl(record));
    }
    view
}

fn with_zero_ttl(record: &Record) -> Record {
    Record::new(
        record.owner().clone(),
        record.rr_type(),
        record.class(),
        Ttl::ZERO,
        record.rdata().clone(),
    )
    .expect("record with zero TTL")
}

/// Один UDP-обмен: отправляет запрос с заданным ID и ждёт ответ именно на него.
fn udp_exchange(
    socket: &UdpSocket,
    server: SocketAddr,
    wire: &[u8],
    id: u16,
    timeout: Duration,
) -> std::io::Result<Vec<u8>> {
    let mut datagram = wire.to_vec();
    datagram[..2].copy_from_slice(&id.to_be_bytes());
    support::e2e::send_to(socket, &datagram, server)?;
    let deadline = Instant::now() + timeout;
    let mut buffer = [0_u8; 4096];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                ErrorKind::TimedOut,
                format!("нет ответа на id={id:#06x} за {timeout:?}"),
            ));
        }
        socket.set_read_timeout(Some(remaining))?;
        let (length, _) = support::e2e::recv_from(socket, &mut buffer)?;
        let bytes = buffer.get(..length).unwrap_or_default();
        // Ответ на запрос прошлой попытки игнорируем и ждём текущий ID.
        if bytes.len() >= 2 && u16::from_be_bytes([bytes[0], bytes[1]]) == id {
            return Ok(bytes.to_vec());
        }
    }
}

/// UDP-запрос с повторами (новый ID, экспоненциальная пауза) до `deadline`.
///
/// Сокет один на все попытки, поэтому запоздавший ответ отсекается по ID.
fn udp_exchange_retry(
    server: SocketAddr,
    wire: &[u8],
    label: &str,
    deadline: Instant,
) -> Result<Vec<u8>, String> {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .map_err(|error| format!("{label}: bind UDP-клиента: {error} ({:?})", error.kind()))?;
    let mut backoff = RETRY_BACKOFF_START;
    let mut last = "попыток не было".to_owned();
    for attempt in 1..=UDP_ATTEMPTS {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            last = format!("дедлайн истёк до попытки {attempt}");
            break;
        }
        let id = next_id();
        match udp_exchange(&socket, server, wire, id, UDP_TIMEOUT.min(remaining)) {
            Ok(response) => return Ok(response),
            Err(error) => {
                last = format!(
                    "попытка {attempt}/{UDP_ATTEMPTS}, id={id:#06x}: {error} ({:?})",
                    error.kind()
                );
            }
        }
        if attempt < UDP_ATTEMPTS {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            std::thread::sleep(backoff.min(remaining));
            backoff = backoff.saturating_mul(2).min(RETRY_BACKOFF_MAX);
        }
    }
    Err(format!(
        "{label}: UDP-ответ не получен за {UDP_ATTEMPTS} попыток; последняя ошибка: {last}"
    ))
}

fn reference_bytes(config: &Config, request: &Message) -> Vec<u8> {
    let resolver = Resolver::new(config.resolver_config().expect("resolver config"))
        .expect("reference resolver");
    // Прогрев: сравнение должно идти по cache hit, а не по ответу upstream.
    // Под нагрузкой первый запрос к mock upstream может не уложиться в
    // per-query таймаут, поэтому SERVFAIL повторяем до дедлайна.
    retry(
        "reference warmup",
        || "эталонный резолвер".to_owned(),
        || {
            let response = resolver.resolve(request);
            if response.rcode() == pulse_dns::Rcode::NOERROR {
                Ok(())
            } else {
                Err(format!("эталонный ответ: rcode={:?}", response.rcode()))
            }
        },
    );
    let mut out = [0_u8; 4096];
    let cached = resolver.resolve(request);
    assert_eq!(
        cached.rcode(),
        pulse_dns::Rcode::NOERROR,
        "эталонный cache hit должен быть положительным"
    );
    let length = cached.encode_into(&mut out).expect("encode reference");
    out[..length].to_vec()
}

#[test]
fn udp_and_tcp_match_legacy_message_path_bytes() {
    let upstream = upstream();
    let config = support::base_config(upstream.address());
    let server = Server::start(&config).expect("server");
    let udp = server.udp_addr().expect("udp");
    let tcp = server.tcp_addr().expect("tcp");
    let request = make_query(NAME, Rtype::A, None);
    let wire = request.encode(&EncodeOptions::default()).expect("encode");
    let expected = mask_rr_ttls(&normalize(reference_bytes(&config, &request)));

    // Первый запрос прогревает кеш сервера.
    let _ = udp_query_retry(udp, &request, "warmup UDP");
    assert_eq!(
        mask_rr_ttls(&normalize(udp_raw(udp, &wire))),
        expected,
        "UDP"
    );
    assert_eq!(
        mask_rr_ttls(&normalize(tcp_raw(tcp, &wire))),
        expected,
        "TCP"
    );

    let stats = server.stats();
    assert!(stats.fast_path >= 1, "wire fast path must be used");
    assert!(
        stats.zero_alloc_responses >= 1,
        "cache hit must be zero-alloc"
    );
    assert!(server.resolver_stats().cache.hits >= 1);
}

#[test]
fn edns_payload_and_do_survive_fast_path() {
    let upstream = upstream();
    let config = support::base_config(upstream.address());
    let server = Server::start(&config).expect("server");
    let udp = server.udp_addr().expect("udp");
    let mut request = make_query(NAME, Rtype::A, Some(4096));
    request.set_edns(Some(pulse_dns::Edns::new(4096).with_dnssec_ok(true)));
    let wire = request.encode(&EncodeOptions::default()).expect("encode");
    let _ = udp_query_retry(udp, &request, "warmup EDNS");
    let expected = mask_rr_ttls(&normalize(reference_bytes(&config, &request)));
    let response = normalize(udp_raw(udp, &wire));
    assert_eq!(mask_rr_ttls(&response), expected);
    let decoded = Message::decode(&response, &DecodeLimits::default()).expect("decode");
    let edns = decoded.edns().expect("OPT echoed");
    assert_eq!(edns.udp_payload_size(), 1232);
    assert!(edns.dnssec_ok());
    assert!(!decoded.flags().tc());
}

#[test]
fn tc_is_set_when_full_response_exceeds_client_payload() {
    let upstream = MockUpstream::start(|request| {
        let mut response = Message::response(request);
        for index in 0..30_u8 {
            let text = format!("{index:02}-{}", "x".repeat(100));
            response.add_answer(
                pulse_dns::Record::new(
                    pulse_dns::Name::parse("big.hotpath.test").expect("name"),
                    Rtype::TXT,
                    pulse_dns::Rclass::IN,
                    pulse_dns::Ttl::new(300).expect("ttl"),
                    pulse_dns::Rdata::Txt(
                        pulse_dns::TxtData::new([text.into_bytes()]).expect("txt"),
                    ),
                )
                .expect("record"),
            );
        }
        Some(response)
    });
    let config = support::base_config(upstream.address());
    let server = Server::start(&config).expect("server");
    let udp = server.udp_addr().expect("udp");
    let mut request = make_query("big.hotpath.test", Rtype::TXT, Some(4096));
    request.set_edns(Some(pulse_dns::Edns::new(4096)));
    let wire = request.encode(&EncodeOptions::default()).expect("encode");

    let full = udp_raw(udp, &wire);
    let full = Message::decode(&full, &DecodeLimits::default()).expect("full");
    assert!(!full.flags().tc());
    assert_eq!(full.answers().len(), 30);

    // Второй ответ — cache hit с payload 512 из нового запроса.
    let small = make_query("big.hotpath.test", Rtype::TXT, Some(512));
    let small_wire = small.encode(&EncodeOptions::default()).expect("encode");
    let truncated = udp_raw(udp, &small_wire);
    let truncated = Message::decode(&truncated, &DecodeLimits::default()).expect("truncated");
    assert!(truncated.flags().tc());
    assert_eq!(truncated.answers().len(), 0);
    assert!(server.stats().truncated >= 1);
}

#[test]
fn acl_is_checked_before_resolver() {
    let upstream = upstream();
    let mut config = support::base_config(upstream.address());
    config.allow_from = vec!["192.0.2.0/24".to_owned()];
    let server = Server::start(&config).expect("server");
    let udp = server.udp_addr().expect("udp");
    let request = make_query(NAME, Rtype::A, None);
    let wire = request.encode(&EncodeOptions::default()).expect("encode");
    let response = udp_raw(udp, &wire);
    let response = Message::decode(&response, &DecodeLimits::default()).expect("decode");
    assert_eq!(response.rcode(), pulse_dns::Rcode::REFUSED);
    assert_eq!(server.resolver_stats().queries, 0, "ACL before resolver");
    assert!(server.stats().refused_acl >= 1);
}

#[test]
fn concurrent_udp_queries_are_consistent() {
    let upstream = upstream();
    let config = support::base_config(upstream.address());
    let server = Server::start(&config).expect("server");
    let udp = server.udp_addr().expect("udp");
    let request = make_query(NAME, Rtype::A, None);
    let wire = request.encode(&EncodeOptions::default()).expect("encode");
    let expected = semantic_view(&reference_bytes(&config, &request), "эталон");
    let diagnostics = || server_diagnostics(&server);
    let last_error = LastError::default();

    // Прогрев: под нагрузкой первый ответ upstream может не уложиться в
    // per-query таймаут, поэтому ждём положительный ответ, а не любой.
    let warmup_deadline = Instant::now() + CONSISTENCY_DEADLINE;
    retry(
        "warmup concurrent",
        || server_diagnostics(&server),
        || {
            let response = udp_exchange_retry(udp, &wire, "warmup concurrent", warmup_deadline)
                .inspect_err(|error| last_error.record(error.clone()))?;
            let actual = semantic_view(&response, "warmup");
            if actual == expected {
                Ok(())
            } else {
                let message = format!("прогрев вернул неожиданный ответ: {actual:?}");
                last_error.record(message.clone());
                Err(message)
            }
        },
    );

    // Число доставленных ответов не фиксировано: UDP под нагрузкой может
    // теряться. Проверяем инвариант — все успешные ответы согласованы.
    let deadline = Instant::now() + CONSISTENCY_DEADLINE;
    let successes = AtomicU64::new(0);
    let failed = AtomicBool::new(false);
    std::thread::scope(|scope| {
        for worker in 0..CONCURRENT_CLIENTS {
            let wire = wire.as_slice();
            let expected = &expected;
            let last_error = &last_error;
            let successes = &successes;
            let failed = &failed;
            scope.spawn(move || {
                for round in 0..QUERIES_PER_CLIENT {
                    if Instant::now() >= deadline {
                        break;
                    }
                    let response = match udp_exchange_retry(udp, wire, "concurrent UDP", deadline) {
                        Ok(response) => response,
                        // Потеря под нагрузкой не ломает инвариант:
                        // запрос не учитывается, поток завершает работу.
                        Err(error) => {
                            last_error.record(error);
                            break;
                        }
                    };
                    let actual = semantic_view(&response, "concurrent");
                    if actual != *expected {
                        last_error.record(format!(
                            "worker {worker}, round {round}: ответ отличается от эталона: \
                             {actual:?}"
                        ));
                        failed.store(true, Ordering::Relaxed);
                        return;
                    }
                    successes.fetch_add(1, Ordering::Relaxed);
                }
            });
        }
    });

    let successes = successes.load(Ordering::Relaxed);
    assert!(
        !failed.load(Ordering::Relaxed),
        "конкурентная проверка прервана: {}; диагностика: {}",
        last_error.get(),
        diagnostics()
    );
    assert!(
        successes >= 1,
        "за {CONSISTENCY_DEADLINE:?} не получено ни одного UDP-ответа; \
         последняя ошибка: {}; диагностика: {}",
        last_error.get(),
        diagnostics()
    );
    let resolver = server.resolver_stats();
    assert!(
        resolver.cache.hits >= successes,
        "каждый успешный ответ должен обслуживаться кешем: hits={}, успехов={successes}; \
         последняя ошибка: {}; диагностика: {}",
        resolver.cache.hits,
        last_error.get(),
        diagnostics()
    );
}

#[test]
fn rate_limit_runs_before_resolve_and_keeps_action() {
    let upstream = upstream();
    let mut config = support::base_config(upstream.address());
    config.rate_limit = Some(RateLimitSetting {
        burst: 1,
        qps: 0.001,
        max_entries: 16,
        action: RateLimitAction::Truncate,
        ..RateLimitSetting::default()
    });
    let server = Server::start(&config).expect("server");
    let udp = server.udp_addr().expect("udp");
    let request = make_query(NAME, Rtype::A, None);
    let wire = request.encode(&EncodeOptions::default()).expect("encode");

    let first = udp_query_retry(udp, &request, "first rate limit query");
    assert!(!first.flags().tc());
    let before = server.resolver_stats().queries;
    let limited = udp_raw(udp, &wire);
    let limited = Message::decode(&limited, &DecodeLimits::default()).expect("decode");
    assert!(limited.flags().tc());
    assert_eq!(
        server.resolver_stats().queries,
        before,
        "rate limit must run before the resolver"
    );
    assert!(server.stats().rate_limit_truncated >= 1);
}

#[test]
fn tcp_keeps_large_cache_hit_untruncated() {
    let upstream = MockUpstream::start(|request| {
        let mut response = Message::response(request);
        for index in 0..20_u8 {
            let text = format!("{index:02}-{}", "y".repeat(100));
            response.add_answer(
                pulse_dns::Record::new(
                    pulse_dns::Name::parse("big.tcp.test").expect("name"),
                    Rtype::TXT,
                    pulse_dns::Rclass::IN,
                    pulse_dns::Ttl::new(300).expect("ttl"),
                    pulse_dns::Rdata::Txt(
                        pulse_dns::TxtData::new([text.into_bytes()]).expect("txt"),
                    ),
                )
                .expect("record"),
            );
        }
        Some(response)
    });
    let config = support::base_config(upstream.address());
    let server = Server::start(&config).expect("server");
    let tcp = server.tcp_addr().expect("tcp");
    let request = make_query("big.tcp.test", Rtype::TXT, None);
    let first = tcp_query_retry(tcp, &request, "first TCP big");
    assert_eq!(first.answers().len(), 20);
    let second = tcp_query_retry(tcp, &request, "cached TCP big");
    assert_eq!(second.answers().len(), 20);
    assert!(!second.flags().tc());
}
