//! UDP/TCP upstream-клиент с EDNS0, ретраями и строгим матчингом ответа.
//!
//! Каждый запрос получает свежие TXID и source port из CSPRNG (`getrandom`).
//! Для UDP включена 0x20-рандомизация регистра QNAME: ответ обязан побайтово
//! повторить регистр вопроса. Если upstream регистр не сохраняет, клиент
//! автоматически повторяет запрос без 0x20 (совместимость с middlebox) и
//! учитывает это в метрике `zero_x_fallbacks`. Авто-отключение действует на
//! текущий запрос; persistent-состояние на upstream не ведётся (см.
//! ограничения крейта).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pulse_dns::{DecodeLimits, Edns, Flags, Message, Question, Rcode};

use crate::error::ResolverError;

/// Параметры upstream-клиента.
#[derive(Debug, Clone, Copy)]
pub(crate) struct UpstreamOptions {
    pub(crate) edns_payload: u16,
    pub(crate) use_0x20: bool,
    pub(crate) retries: u8,
    pub(crate) per_query: Duration,
    pub(crate) tcp_timeout: Duration,
    pub(crate) max_response_bytes: usize,
}

/// Ответ upstream.
#[derive(Debug)]
pub(crate) struct UpstreamResponse {
    pub(crate) message: Message,
}

/// Счётчики транспорта.
#[derive(Debug, Default)]
pub(crate) struct UpstreamCounters {
    pub(crate) udp_queries: AtomicU64,
    pub(crate) tcp_queries: AtomicU64,
    pub(crate) tls_queries: AtomicU64,
    pub(crate) https_queries: AtomicU64,
    pub(crate) retries: AtomicU64,
    pub(crate) timeouts: AtomicU64,
    pub(crate) mismatches: AtomicU64,
    pub(crate) zero_x_fallbacks: AtomicU64,
    pub(crate) failovers: AtomicU64,
}

/// Снимок счётчиков транспорта.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UpstreamStats {
    /// Отправленные UDP-запросы.
    pub udp_queries: u64,
    /// TCP-запросы (включая TC-fallback).
    pub tcp_queries: u64,
    /// DNS-over-TLS-запросы.
    pub tls_queries: u64,
    /// DNS-over-HTTPS-запросы.
    pub https_queries: u64,
    /// Повторы.
    pub retries: u64,
    /// Таймауты.
    pub timeouts: u64,
    /// Ответы, не прошедшие матчинг.
    pub mismatches: u64,
    /// Случаи авто-отключения 0x20.
    pub zero_x_fallbacks: u64,
    /// Переключения на следующий upstream после ошибки.
    pub failovers: u64,
}

impl UpstreamCounters {
    pub(crate) fn snapshot(&self) -> UpstreamStats {
        UpstreamStats {
            udp_queries: self.udp_queries.load(Ordering::Relaxed),
            tcp_queries: self.tcp_queries.load(Ordering::Relaxed),
            tls_queries: self.tls_queries.load(Ordering::Relaxed),
            https_queries: self.https_queries.load(Ordering::Relaxed),
            retries: self.retries.load(Ordering::Relaxed),
            timeouts: self.timeouts.load(Ordering::Relaxed),
            mismatches: self.mismatches.load(Ordering::Relaxed),
            zero_x_fallbacks: self.zero_x_fallbacks.load(Ordering::Relaxed),
            failovers: self.failovers.load(Ordering::Relaxed),
        }
    }
}

/// Предпочтительный транспорт для UDP/TCP-клиента.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UpstreamTransport {
    /// UDP с автоматическим TCP-fallback при TC.
    Udp,
    /// Только TCP (RFC 7766).
    Tcp,
}

/// Потокобезопасный upstream-клиент.
#[derive(Debug)]
pub(crate) struct UpstreamClient {
    options: UpstreamOptions,
    counters: Arc<UpstreamCounters>,
}

impl UpstreamClient {
    pub(crate) fn new(options: UpstreamOptions) -> Self {
        Self {
            options,
            counters: Arc::new(UpstreamCounters::default()),
        }
    }

    pub(crate) fn counters(&self) -> Arc<UpstreamCounters> {
        Arc::clone(&self.counters)
    }

    pub(crate) fn options(&self) -> UpstreamOptions {
        self.options
    }

    pub(crate) fn query(
        &self,
        server: SocketAddr,
        question: &Question,
        recursion_desired: bool,
        dnssec_ok: bool,
        deadline: Instant,
        cancel: Option<&Arc<AtomicBool>>,
    ) -> Result<UpstreamResponse, ResolverError> {
        self.query_over(
            server,
            UpstreamTransport::Udp,
            question,
            recursion_desired,
            dnssec_ok,
            deadline,
            cancel,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn query_over(
        &self,
        server: SocketAddr,
        transport: UpstreamTransport,
        question: &Question,
        recursion_desired: bool,
        dnssec_ok: bool,
        deadline: Instant,
        cancel: Option<&Arc<AtomicBool>>,
    ) -> Result<UpstreamResponse, ResolverError> {
        let mut last_error = ResolverError::Timeout;
        let mut use_0x20 = self.options.use_0x20 && transport == UpstreamTransport::Udp;
        let mut attempt = 0_u8;

        while attempt <= self.options.retries {
            check_deadline(deadline, cancel)?;
            if attempt > 0 {
                self.counters.retries.fetch_add(1, Ordering::Relaxed);
            }
            let prepared = prepare(
                question,
                recursion_desired,
                dnssec_ok,
                self.options.edns_payload,
                use_0x20,
            )?;
            match self.exchange(server, transport, &prepared, deadline, cancel) {
                Ok(response) => {
                    return Ok(response);
                }
                Err(error) => {
                    if matches!(error, ResolverError::Mismatch { .. }) {
                        self.counters.mismatches.fetch_add(1, Ordering::Relaxed);
                        if use_0x20 {
                            // Upstream не сохраняет регистр: повторяем без 0x20,
                            // не тратя попытку ретрая.
                            use_0x20 = false;
                            self.counters
                                .zero_x_fallbacks
                                .fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                    }
                    if matches!(error, ResolverError::Timeout) {
                        self.counters.timeouts.fetch_add(1, Ordering::Relaxed);
                    }
                    last_error = error;
                    attempt = attempt.saturating_add(1);
                }
            }
        }
        Err(last_error)
    }

    fn exchange(
        &self,
        server: SocketAddr,
        transport: UpstreamTransport,
        prepared: &PreparedQuery,
        deadline: Instant,
        cancel: Option<&Arc<AtomicBool>>,
    ) -> Result<UpstreamResponse, ResolverError> {
        match transport {
            UpstreamTransport::Udp => {
                self.counters.udp_queries.fetch_add(1, Ordering::Relaxed);
                let message = self.query_udp(server, prepared, deadline, cancel)?;
                if message.flags().tc() {
                    self.counters.tcp_queries.fetch_add(1, Ordering::Relaxed);
                    let message = self.query_tcp(server, prepared, deadline, cancel)?;
                    Ok(UpstreamResponse { message })
                } else {
                    Ok(UpstreamResponse { message })
                }
            }
            UpstreamTransport::Tcp => {
                self.counters.tcp_queries.fetch_add(1, Ordering::Relaxed);
                let message = self.query_tcp(server, prepared, deadline, cancel)?;
                Ok(UpstreamResponse { message })
            }
        }
    }

    fn query_udp(
        &self,
        server: SocketAddr,
        prepared: &PreparedQuery,
        deadline: Instant,
        cancel: Option<&Arc<AtomicBool>>,
    ) -> Result<Message, ResolverError> {
        let socket = bind_udp(server)?;
        let timeout = remaining(deadline).min(self.options.per_query);
        socket.set_read_timeout(Some(timeout))?;
        socket.send_to(&prepared.bytes, server)?;

        let mut buffer = vec![0_u8; self.options.max_response_bytes.clamp(512, 65_535)];
        loop {
            check_deadline(deadline, cancel)?;
            match socket.recv_from(&mut buffer) {
                Ok((length, peer)) => {
                    if peer != server {
                        continue;
                    }
                    let Some(bytes) = buffer.get(..length) else {
                        continue;
                    };
                    let message = Message::decode(bytes, &DecodeLimits::default())?;
                    verify_response(&message, bytes, prepared)?;
                    return Ok(message);
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Err(ResolverError::Timeout);
                }
                Err(error) => return Err(ResolverError::Io(error)),
            }
        }
    }

    fn query_tcp(
        &self,
        server: SocketAddr,
        prepared: &PreparedQuery,
        deadline: Instant,
        cancel: Option<&Arc<AtomicBool>>,
    ) -> Result<Message, ResolverError> {
        check_deadline(deadline, cancel)?;
        let timeout = remaining(deadline).min(self.options.tcp_timeout);
        let mut stream = TcpStream::connect_timeout(&server, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;

        let length = u16::try_from(prepared.bytes.len()).map_err(|_| ResolverError::Internal {
            reason: "query too long",
        })?;
        let mut framed = Vec::with_capacity(prepared.bytes.len() + 2);
        framed.extend_from_slice(&length.to_be_bytes());
        framed.extend_from_slice(&prepared.bytes);
        use std::io::{Read, Write};
        stream.write_all(&framed)?;
        stream.flush()?;

        let mut size_bytes = [0_u8; 2];
        stream.read_exact(&mut size_bytes)?;
        let size = usize::from(u16::from_be_bytes(size_bytes));
        if size < 12 {
            return Err(ResolverError::Mismatch {
                reason: "invalid tcp response length",
            });
        }
        let mut bytes = vec![0_u8; size];
        stream.read_exact(&mut bytes)?;
        let message = Message::decode(&bytes, &DecodeLimits::default())?;
        verify_response(&message, &bytes, prepared)?;
        Ok(message)
    }
}

pub(crate) struct PreparedQuery {
    pub(crate) bytes: Vec<u8>,
    qname_wire: Vec<u8>,
    pub(crate) id: u16,
    pub(crate) question: Question,
    pub(crate) recursion_desired: bool,
    pub(crate) use_0x20: bool,
}

pub(crate) fn prepare(
    question: &Question,
    recursion_desired: bool,
    dnssec_ok: bool,
    edns_payload: u16,
    use_0x20: bool,
) -> Result<PreparedQuery, ResolverError> {
    let id = random_u16();
    let mut message = Message::query(id, question.clone());
    message.set_flags(Flags::new().with_rd(recursion_desired));
    message.set_edns(Some(Edns::new(edns_payload).with_dnssec_ok(dnssec_ok)));
    let mut bytes = message.encode(&pulse_dns::EncodeOptions::default())?;
    let qname_wire = if use_0x20 {
        randomize_question_case(&mut bytes)?
    } else {
        question.qname().as_wire().to_vec()
    };
    Ok(PreparedQuery {
        bytes,
        qname_wire,
        id,
        question: question.clone(),
        recursion_desired,
        use_0x20,
    })
}

pub(crate) fn verify_response(
    message: &Message,
    bytes: &[u8],
    prepared: &PreparedQuery,
) -> Result<(), ResolverError> {
    if message.id() != prepared.id {
        return Err(ResolverError::Mismatch {
            reason: "transaction id",
        });
    }
    if !message.flags().qr() {
        return Err(ResolverError::Mismatch {
            reason: "response flag",
        });
    }
    if message.flags().opcode() != pulse_dns::Opcode::QUERY {
        return Err(ResolverError::Mismatch { reason: "opcode" });
    }
    if message.flags().rd() != prepared.recursion_desired {
        return Err(ResolverError::Mismatch { reason: "rd flag" });
    }
    let Some(question) = message.questions().first() else {
        return Err(ResolverError::Mismatch {
            reason: "empty question",
        });
    };
    if message.questions().len() != 1
        || question.qname() != prepared.question.qname()
        || question.qtype() != prepared.question.qtype()
        || question.qclass() != prepared.question.qclass()
    {
        return Err(ResolverError::Mismatch { reason: "question" });
    }
    if prepared.use_0x20 {
        let Some(raw) = question_wire(bytes) else {
            return Err(ResolverError::Mismatch {
                reason: "question encoding",
            });
        };
        if raw != prepared.qname_wire.as_slice() {
            return Err(ResolverError::Mismatch {
                reason: "0x20 case",
            });
        }
    }
    Ok(())
}

/// Возвращает несжатую wire-форму QNAME из начала вопроса.
fn question_wire(bytes: &[u8]) -> Option<&[u8]> {
    let mut position = 12_usize;
    loop {
        let length = *bytes.get(position)?;
        match length {
            0 => {
                let end = position.checked_add(1)?;
                return bytes.get(12..end);
            }
            1..=63 => {
                position = position.checked_add(1 + usize::from(length))?;
                if position >= bytes.len() {
                    return None;
                }
            }
            _ => return None,
        }
    }
}

/// Рандомизирует регистр ASCII-букв QNAME в уже закодированном запросе.
fn randomize_question_case(bytes: &mut [u8]) -> Result<Vec<u8>, ResolverError> {
    let Some(range) = question_range(bytes) else {
        return Err(ResolverError::Internal {
            reason: "question range",
        });
    };
    let (start, end) = range;
    let mut random = vec![0_u8; end.saturating_sub(start)];
    if getrandom::fill(&mut random).is_err() {
        return Ok(bytes.get(start..end).unwrap_or(&[]).to_vec());
    }
    for (offset, random_byte) in random.iter().enumerate() {
        let Some(index) = start.checked_add(offset) else {
            break;
        };
        let Some(byte) = bytes.get_mut(index) else {
            break;
        };
        if byte.is_ascii_lowercase() && random_byte & 1 == 1 {
            *byte = byte.to_ascii_uppercase();
        }
    }
    Ok(bytes.get(start..end).unwrap_or(&[]).to_vec())
}

fn question_range(bytes: &[u8]) -> Option<(usize, usize)> {
    let mut position = 12_usize;
    loop {
        let length = *bytes.get(position)?;
        if length == 0 {
            return Some((12, position.checked_add(1)?));
        }
        if length > 63 {
            return None;
        }
        position = position.checked_add(1 + usize::from(length))?;
        if position >= bytes.len() {
            return None;
        }
    }
}

fn bind_udp(server: SocketAddr) -> std::io::Result<UdpSocket> {
    let unspecified = match server.ip() {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    for _ in 0..8 {
        let port = random_u16();
        if port < 1024 {
            continue;
        }
        let address = SocketAddr::new(unspecified, port);
        if let Ok(socket) = UdpSocket::bind(address) {
            return Ok(socket);
        }
    }
    UdpSocket::bind(SocketAddr::new(unspecified, 0))
}

fn check_deadline(
    deadline: Instant,
    cancel: Option<&Arc<AtomicBool>>,
) -> Result<(), ResolverError> {
    if cancel.is_some_and(|token| token.load(Ordering::Relaxed)) {
        return Err(ResolverError::Cancelled);
    }
    if Instant::now() >= deadline {
        return Err(ResolverError::Timeout);
    }
    Ok(())
}

fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

fn random_u16() -> u16 {
    let mut bytes = [0_u8; 2];
    if getrandom::fill(&mut bytes).is_ok() {
        return u16::from_ne_bytes(bytes);
    }
    fallback_random()
}

fn fallback_random() -> u16 {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
        });
    let mixed = nanos ^ counter.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    u16::try_from(mixed & u64::from(u16::MAX)).unwrap_or(1)
}

/// Проверяет, что RCODE не требует retry на другом сервере.
#[must_use]
pub(crate) fn is_retryable_rcode(rcode: Rcode) -> bool {
    matches!(rcode, Rcode::SERVFAIL | Rcode::REFUSED | Rcode::NOTIMP)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn question_wire_extracts_qname() {
        let name = pulse_dns::Name::parse("www.example.com").unwrap();
        let question = Question::new(name.clone(), pulse_dns::Rtype::A, pulse_dns::Rclass::IN);
        let prepared = prepare(&question, false, false, 1232, false).unwrap();
        assert_eq!(question_wire(&prepared.bytes), Some(name.as_wire()));
        assert_eq!(prepared.qname_wire.len(), name.wire_len());
    }

    #[test]
    fn prepare_sets_edns_and_do() {
        let name = pulse_dns::Name::parse("example.com").unwrap();
        let question = Question::new(name, pulse_dns::Rtype::A, pulse_dns::Rclass::IN);
        let prepared = prepare(&question, true, true, 1232, false).unwrap();
        let message = Message::decode(&prepared.bytes, &DecodeLimits::default()).unwrap();
        let edns = message.edns().unwrap();
        assert_eq!(edns.udp_payload_size(), 1232);
        assert!(edns.dnssec_ok());
        assert!(message.flags().rd());
    }

    #[test]
    fn randomize_keeps_length() {
        let name = pulse_dns::Name::parse("example.com").unwrap();
        let question = Question::new(name, pulse_dns::Rtype::A, pulse_dns::Rclass::IN);
        let mut prepared = prepare(&question, false, false, 1232, false).unwrap();
        let original = prepared.bytes.len();
        let randomized = randomize_question_case(&mut prepared.bytes).unwrap();
        assert_eq!(prepared.bytes.len(), original);
        assert_eq!(randomized.len(), prepared.qname_wire.len());
    }
}
