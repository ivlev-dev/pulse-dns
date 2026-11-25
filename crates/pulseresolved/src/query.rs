//! Обработка одного DNS-запроса: decode → resolve → encode с усечением.

use std::cell::RefCell;
use std::net::IpAddr;
use std::sync::Arc;

use pulse_dns::{
    DecodeLimits, EDNS_DEFAULT_PAYLOAD, EDNS_MAX_PAYLOAD, Edns, EncodeError, EncodeOptions, Flags,
    MAX_MESSAGE_LEN, MAX_UDP_PAYLOAD, Message, MessageRef, Opcode, Rcode, Rtype,
};
use pulse_resolver::{ResolvedResponse, Resolver, ResponseMeta};
use pulse_tls::{Acl, RateLimiter};

use crate::config::RateLimitAction;
use crate::rrl::{Rrl, RrlOutcome};
use crate::stats::Stats;

/// Транспорт, по которому пришёл запрос.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Transport {
    Udp,
    Tcp,
    Dot,
    Doh,
    Doh2,
    Doq,
    DnscryptUdp,
    DnscryptTcp,
}

impl Transport {
    /// Транспорт из семейства TLS/QUIC (действует `tls_allow_from`).
    const fn is_tls(self) -> bool {
        matches!(self, Self::Dot | Self::Doh | Self::Doh2 | Self::Doq)
    }

    /// Лимит сырого ответа для FORMERR/REFUSED без разобранного запроса.
    const fn raw_limit(self) -> usize {
        match self {
            Self::Udp => MAX_UDP_PAYLOAD,
            _ => MAX_MESSAGE_LEN,
        }
    }

    fn count_query(self, stats: &Stats) {
        match self {
            Self::Udp => stats.udp_query(),
            Self::Tcp => stats.tcp_query(),
            Self::Dot => stats.dot_query(),
            Self::Doh => stats.doh_query(),
            Self::Doh2 => stats.doh_http2_query(),
            Self::Doq => stats.doq_query(),
            Self::DnscryptUdp => stats.dnscrypt_udp_query(),
            Self::DnscryptTcp => stats.dnscrypt_tcp_query(),
        }
    }

    fn count_response(self, stats: &Stats) {
        match self {
            Self::Udp => stats.udp_response(),
            Self::Tcp => stats.tcp_response(),
            Self::Dot => stats.dot_response(),
            Self::Doh => stats.doh_response(),
            Self::Doh2 => stats.doh_http2_response(),
            Self::Doq => stats.doq_response(),
            Self::DnscryptUdp => stats.dnscrypt_udp_response(),
            Self::DnscryptTcp => stats.dnscrypt_tcp_response(),
        }
    }
}

/// Политика доступа к сервису: ACL клиентов и per-source rate limit.
pub(crate) struct AccessPolicy {
    acl: Acl,
    tls_acl: Option<Acl>,
    limiter: Option<RateLimiter>,
    action: RateLimitAction,
}

impl AccessPolicy {
    pub(crate) fn new(
        acl: Acl,
        tls_acl: Option<Acl>,
        limiter: Option<RateLimiter>,
        action: RateLimitAction,
    ) -> Self {
        Self {
            acl,
            tls_acl,
            limiter,
            action,
        }
    }

    fn allows(&self, transport: Transport, peer: IpAddr) -> bool {
        let peer = normalize_ip(peer);
        if transport.is_tls() {
            self.tls_acl.as_ref().unwrap_or(&self.acl).allows(peer)
        } else {
            self.acl.allows(peer)
        }
    }

    fn rate_allows(&self, peer: IpAddr) -> bool {
        match &self.limiter {
            Some(limiter) => limiter.allow(normalize_ip(peer)),
            None => true,
        }
    }

    const fn action(&self) -> RateLimitAction {
        self.action
    }
}

/// Сводит IPv4-mapped IPv6 (`::ffff:a.b.c.d`) к IPv4 для ACL/RRL.
fn normalize_ip(peer: IpAddr) -> IpAddr {
    match peer {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map_or(IpAddr::V6(address), IpAddr::V4),
        IpAddr::V4(_) => peer,
    }
}

/// Общий обработчик UDP и TCP.
pub(crate) struct Processor {
    resolver: Resolver,
    stats: Arc<Stats>,
    policy: AccessPolicy,
    rrl: Option<Arc<Rrl>>,
}

impl Processor {
    pub(crate) fn new(
        resolver: Resolver,
        stats: Arc<Stats>,
        acl: Acl,
        tls_acl: Option<Acl>,
        limiter: Option<RateLimiter>,
        action: RateLimitAction,
        rrl: Option<Arc<Rrl>>,
    ) -> Self {
        Self {
            resolver,
            stats,
            policy: AccessPolicy::new(acl, tls_acl, limiter, action),
            rrl,
        }
    }

    /// Обрабатывает пакет и возвращает wire-ответ (или `None`, если отвечать
    /// не нужно/невозможно).
    ///
    /// Владеющий `Vec` нужен транспортам с API `Fn(...) -> Option<Vec<u8>>`
    /// (TLS/QUIC/DNSCrypt). UDP и TCP используют [`Processor::handle_into`]
    /// и не аллоцируют ответ.
    pub(crate) fn handle(
        &self,
        request: &[u8],
        transport: Transport,
        peer: std::net::SocketAddr,
    ) -> Option<Vec<u8>> {
        RESPONSE_BUFFER.with_borrow_mut(|buffer| {
            let len = self.handle_into(request, transport, peer, buffer)?;
            Some(buffer.get(..len)?.to_vec())
        })
    }

    /// Обрабатывает пакет и пишет ответ в `out`, возвращая его длину.
    ///
    /// Горячий путь простого запроса:
    /// `MessageRef::decode_simple_edns` → ACL → rate limit →
    /// [`Resolver::resolve_ref_into_limited`] → RRL по метаданным. На
    /// попадании в кеш нет ни `Message`, ни `Name`, ни аллокаций.
    pub(crate) fn handle_into(
        &self,
        request: &[u8],
        transport: Transport,
        peer: std::net::SocketAddr,
        out: &mut [u8],
    ) -> Option<usize> {
        transport.count_query(&self.stats);
        if !self.policy.allows(transport, peer.ip()) {
            self.stats.refused_acl();
            self.stats.refused();
            self.stats.rcode(Rcode::REFUSED);
            return self.raw_error_into(
                request,
                Rcode::REFUSED,
                transport.raw_limit(),
                out,
                transport,
            );
        }
        if let Some(request) = MessageRef::decode_simple_edns(request) {
            self.stats.fast_path();
            return self.handle_fast(&request, transport, peer, out);
        }
        self.stats.full_decode();
        self.handle_slow(request, transport, peer, out)
    }

    fn handle_fast(
        &self,
        request: &MessageRef<'_>,
        transport: Transport,
        peer: std::net::SocketAddr,
        out: &mut [u8],
    ) -> Option<usize> {
        let qname = request.qname()?;
        let limit = match transport {
            Transport::Udp => udp_limit_ref(request),
            _ => MAX_MESSAGE_LEN,
        };
        if !self.policy.rate_allows(peer.ip()) {
            self.stats.rate_limited();
            return match self.policy.action() {
                RateLimitAction::Drop => {
                    self.stats.rate_limit_dropped();
                    None
                }
                RateLimitAction::Refused => {
                    self.stats.rate_limit_refused();
                    self.stats.refused();
                    self.stats.rcode(Rcode::REFUSED);
                    self.write_ref_response(request, out, limit, Rcode::REFUSED, false, transport)
                }
                RateLimitAction::Truncate => {
                    self.stats.rate_limit_truncated();
                    self.write_ref_response(request, out, limit, Rcode::NOERROR, true, transport)
                }
            };
        }
        let axfr = matches!(request.qtype(), Rtype::AXFR | Rtype::IXFR);
        let report = if axfr {
            self.stats.refused();
            self.stats.rcode(Rcode::REFUSED);
            let len =
                self.write_ref_response(request, out, limit, Rcode::REFUSED, false, transport)?;
            ResolvedResponse {
                len,
                meta: ResponseMeta {
                    rcode: Rcode::REFUSED,
                    answers: 0,
                    authority_ns: false,
                    authority_soa: false,
                    cache_hit: false,
                    secure: false,
                },
                truncated: false,
            }
        } else if let Ok(report) = self.resolver.resolve_ref_into_limited(request, out, limit) {
            report
        } else {
            self.stats.encode_error();
            return None;
        };
        if !axfr {
            self.stats.rcode(report.meta.rcode);
            match report.meta.rcode {
                Rcode::REFUSED => self.stats.refused(),
                Rcode::FORMERR => self.stats.formerr(),
                _ => {}
            }
        }
        if report.truncated {
            self.stats.truncated();
        }
        if report.meta.cache_hit {
            self.stats.zero_alloc_response();
        }
        let mut len = report.len;
        if transport == Transport::Udp
            && let Some(rrl) = &self.rrl
        {
            let class = classify_meta(report.meta);
            match rrl.check_class(peer.ip(), qname.as_wire(), class) {
                RrlOutcome::Allow => {}
                RrlOutcome::Drop => return None,
                RrlOutcome::Respond(action) => {
                    len = match action {
                        RateLimitAction::Drop => return None,
                        RateLimitAction::Refused => {
                            self.stats.refused();
                            self.stats.rcode(Rcode::REFUSED);
                            self.write_ref_response(
                                request,
                                out,
                                limit,
                                Rcode::REFUSED,
                                false,
                                transport,
                            )?
                        }
                        RateLimitAction::Truncate => self.write_ref_response(
                            request,
                            out,
                            limit,
                            Rcode::NOERROR,
                            true,
                            transport,
                        )?,
                    };
                }
            }
        }
        transport.count_response(&self.stats);
        Some(len)
    }

    fn handle_slow(
        &self,
        raw: &[u8],
        transport: Transport,
        peer: std::net::SocketAddr,
        out: &mut [u8],
    ) -> Option<usize> {
        let raw_limit = transport.raw_limit();
        let Ok(request) = Message::decode(raw, &DecodeLimits::default()) else {
            self.stats.decode_error();
            return self.raw_error_into(raw, Rcode::FORMERR, raw_limit, out, transport);
        };
        if request.flags().qr() {
            self.stats.dropped();
            return None;
        }
        let limit = match transport {
            Transport::Udp => udp_limit(&request),
            _ => MAX_MESSAGE_LEN,
        };
        if !self.policy.rate_allows(peer.ip()) {
            self.stats.rate_limited();
            return match self.policy.action() {
                RateLimitAction::Drop => {
                    self.stats.rate_limit_dropped();
                    None
                }
                RateLimitAction::Refused => {
                    self.stats.rate_limit_refused();
                    self.stats.refused();
                    self.stats.rcode(Rcode::REFUSED);
                    self.encode_response_into(
                        &error_response(&request, Rcode::REFUSED),
                        limit,
                        transport,
                        out,
                    )
                }
                RateLimitAction::Truncate => {
                    self.stats.rate_limit_truncated();
                    self.encode_response_into(&truncated_response(&request), limit, transport, out)
                }
            };
        }
        let axfr = request
            .questions()
            .iter()
            .any(|question| matches!(question.qtype(), Rtype::AXFR | Rtype::IXFR));
        let response = if axfr {
            error_response(&request, Rcode::REFUSED)
        } else {
            self.resolver.resolve(&request)
        };
        self.stats.rcode(response.rcode());
        match response.rcode() {
            Rcode::FORMERR => self.stats.formerr(),
            Rcode::REFUSED => self.stats.refused(),
            _ => {}
        }
        if transport == Transport::Udp
            && let Some(rrl) = &self.rrl
        {
            match rrl.check(peer.ip(), &response) {
                RrlOutcome::Allow => {}
                RrlOutcome::Drop => return None,
                RrlOutcome::Respond(action) => {
                    let limited = match action {
                        RateLimitAction::Drop => return None,
                        RateLimitAction::Refused => {
                            self.stats.refused();
                            self.stats.rcode(Rcode::REFUSED);
                            error_response(&request, Rcode::REFUSED)
                        }
                        RateLimitAction::Truncate => truncated_response(&request),
                    };
                    return self.encode_response_into(&limited, limit, transport, out);
                }
            }
        }
        self.encode_response_into(&response, limit, transport, out)
    }

    fn encode_response_into(
        &self,
        response: &Message,
        limit: usize,
        transport: Transport,
        out: &mut [u8],
    ) -> Option<usize> {
        let Ok((len, truncated)) = encode_limited_into(response, out, limit) else {
            self.stats.encode_error();
            return None;
        };
        if truncated {
            self.stats.truncated();
        }
        transport.count_response(&self.stats);
        Some(len)
    }

    fn write_ref_response(
        &self,
        request: &MessageRef<'_>,
        out: &mut [u8],
        limit: usize,
        rcode: Rcode,
        tc: bool,
        transport: Transport,
    ) -> Option<usize> {
        let Ok(len) = write_minimal(request, out, limit, rcode, tc) else {
            self.stats.encode_error();
            return None;
        };
        transport.count_response(&self.stats);
        Some(len)
    }

    fn raw_error_into(
        &self,
        raw: &[u8],
        rcode: Rcode,
        limit: usize,
        out: &mut [u8],
        transport: Transport,
    ) -> Option<usize> {
        if raw.len() < 12 {
            self.stats.dropped();
            return None;
        }
        let id = u16::from_be_bytes([*raw.first()?, *raw.get(1)?]);
        let opcode = raw.get(2).map_or(0, |byte| byte >> 3) & 0x0F;
        let flags = Flags::new()
            .with_qr(true)
            .with_ra(true)
            .with_opcode(Opcode::from_u8(opcode))
            .with_rcode_bits(rcode.header_bits());
        let limit = limit.min(out.len());
        if limit < 12 {
            self.stats.encode_error();
            return None;
        }
        let slot = out.get_mut(..12)?;
        slot.get_mut(..2)?.copy_from_slice(&id.to_be_bytes());
        slot.get_mut(2..4)?
            .copy_from_slice(&flags.bits().to_be_bytes());
        // QDCOUNT=ANCOUNT=NSCOUNT=ARCOUNT=0.
        if let Some(tail) = slot.get_mut(4..12) {
            tail.fill(0);
        }
        if rcode == Rcode::FORMERR {
            self.stats.formerr();
            self.stats.rcode(Rcode::FORMERR);
        }
        transport.count_response(&self.stats);
        Some(12)
    }
}

thread_local! {
    /// Буфер для транспортов, чей API возвращает `Vec<u8>`.
    static RESPONSE_BUFFER: RefCell<Vec<u8>> = RefCell::new(vec![0_u8; MAX_MESSAGE_LEN]);
}

/// Классифицирует ответ по метаданным резолвера (семантика `Message`-пути).
fn classify_meta(meta: ResponseMeta) -> crate::rrl::ResponseClass {
    use crate::rrl::ResponseClass;
    match meta.rcode {
        Rcode::NOERROR => {
            if meta.answers == 0 && meta.authority_ns && !meta.authority_soa {
                ResponseClass::Referral
            } else {
                ResponseClass::NoError
            }
        }
        Rcode::NXDOMAIN => ResponseClass::NxDomain,
        _ => ResponseClass::Error,
    }
}

/// Лимит UDP-ответа из EDNS-запроса.
fn udp_limit_ref(request: &MessageRef<'_>) -> usize {
    request.edns().map_or(MAX_UDP_PAYLOAD, |edns| {
        usize::from(edns.udp_payload_size().clamp(512, EDNS_MAX_PAYLOAD))
    })
}

/// Пишет минимальный ответ (заголовок + вопрос + OPT) для простого запроса.
fn write_minimal(
    request: &MessageRef<'_>,
    out: &mut [u8],
    limit: usize,
    rcode: Rcode,
    tc: bool,
) -> Result<usize, EncodeError> {
    let limit = limit.min(out.len());
    let qname = request.qname().ok_or(EncodeError::Internal {
        reason: "MessageRef without qname",
    })?;
    let qname = qname.as_wire();
    let flags = Flags::new()
        .with_qr(true)
        .with_rd(request.flags().rd())
        .with_cd(request.flags().cd())
        .with_ra(true)
        .with_ad(false)
        .with_tc(tc)
        .with_rcode_bits(rcode.header_bits());
    let question_len = qname.len().saturating_add(4);
    let edns_len = usize::from(request.edns().is_some()) * 11;
    let base = 12_usize.saturating_add(edns_len);
    let with_question = base.saturating_add(question_len) <= limit;
    let needed = if with_question {
        base.saturating_add(question_len)
    } else {
        base
    };
    if needed > limit {
        return Err(EncodeError::BufferTooSmall {
            capacity: out.len(),
            needed,
        });
    }
    let Some(slot) = out.get_mut(..needed) else {
        return Err(EncodeError::BufferTooSmall {
            capacity: out.len(),
            needed,
        });
    };
    slot.get_mut(..2)
        .ok_or(EncodeError::Internal {
            reason: "truncated response header",
        })?
        .copy_from_slice(&request.id().to_be_bytes());
    slot.get_mut(2..4)
        .ok_or(EncodeError::Internal {
            reason: "truncated response flags",
        })?
        .copy_from_slice(&flags.bits().to_be_bytes());
    let counts = [
        u16::from(with_question),
        0_u16,
        0_u16,
        u16::from(request.edns().is_some()),
    ];
    let mut position = 4_usize;
    for count in counts {
        slot.get_mut(position..position.saturating_add(2))
            .ok_or(EncodeError::Internal {
                reason: "truncated response counts",
            })?
            .copy_from_slice(&count.to_be_bytes());
        position = position.saturating_add(2);
    }
    if with_question {
        slot.get_mut(position..position.saturating_add(qname.len()))
            .ok_or(EncodeError::Internal {
                reason: "truncated response question",
            })?
            .copy_from_slice(qname);
        position = position.saturating_add(qname.len());
        for value in [
            request.qtype().as_u16().to_be_bytes(),
            request.qclass().as_u16().to_be_bytes(),
        ] {
            slot.get_mut(position..position.saturating_add(2))
                .ok_or(EncodeError::Internal {
                    reason: "truncated response question tail",
                })?
                .copy_from_slice(&value);
            position = position.saturating_add(2);
        }
    }
    if let Some(edns) = request.edns() {
        let payload = edns.udp_payload_size().clamp(512, EDNS_DEFAULT_PAYLOAD);
        let do_bit: u32 = if edns.dnssec_ok() { 0x8000 } else { 0 };
        let ttl = (u32::from(rcode.extended_bits()) << 24) | do_bit;
        let [type_hi, type_lo] = Rtype::OPT.as_u16().to_be_bytes();
        let [payload_hi, payload_lo] = payload.to_be_bytes();
        let [ttl_a, ttl_b, ttl_c, ttl_d] = ttl.to_be_bytes();
        let opt = [
            0_u8, type_hi, type_lo, payload_hi, payload_lo, ttl_a, ttl_b, ttl_c, ttl_d, 0, 0,
        ];
        slot.get_mut(position..position.saturating_add(opt.len()))
            .ok_or(EncodeError::Internal {
                reason: "truncated response OPT",
            })?
            .copy_from_slice(&opt);
    }
    Ok(needed)
}

/// Пишет ответ в `out[..limit]`, при переполнении — минимальный TC-ответ.
fn encode_limited_into(
    response: &Message,
    out: &mut [u8],
    limit: usize,
) -> Result<(usize, bool), EncodeError> {
    let capacity = limit.min(out.len());
    let Some(target) = out.get_mut(..capacity) else {
        return Err(EncodeError::BufferTooSmall {
            capacity: out.len(),
            needed: capacity,
        });
    };
    match response.encode_into(target) {
        Ok(len) => return Ok((len, false)),
        Err(EncodeError::BufferTooSmall { .. }) => {}
        Err(error) => return Err(error),
    }
    for (answers, authority, questions) in [
        (true, true, true),
        (true, false, true),
        (false, false, true),
        (false, false, false),
    ] {
        let candidate = rebuild(response, answers, authority, questions);
        let encoded = candidate.encode(&EncodeOptions::default())?;
        if encoded.len() <= capacity {
            out.get_mut(..encoded.len())
                .ok_or(EncodeError::Internal {
                    reason: "truncated candidate buffer",
                })?
                .copy_from_slice(&encoded);
            return Ok((encoded.len(), true));
        }
    }
    // Минимальный заголовок (12 байт) всегда укладывается в limit ≥ 512.
    let encoded = rebuild(response, false, false, false).encode(&EncodeOptions::default())?;
    if encoded.len() > capacity {
        return Err(EncodeError::BufferTooSmall {
            capacity: out.len(),
            needed: encoded.len(),
        });
    }
    out.get_mut(..encoded.len())
        .ok_or(EncodeError::Internal {
            reason: "minimal buffer",
        })?
        .copy_from_slice(&encoded);
    Ok((encoded.len(), true))
}

/// Пустой ответ с TC: клиент повторит запрос по TCP.
fn truncated_response(request: &Message) -> Message {
    let mut response = Message::response(request);
    response.set_flags(response.flags().with_ra(true).with_tc(true).with_qr(true));
    if let Some(edns) = request.edns() {
        let payload = edns.udp_payload_size().clamp(512, EDNS_DEFAULT_PAYLOAD);
        response.set_edns(Some(Edns::new(payload).with_dnssec_ok(edns.dnssec_ok())));
    }
    response
}

fn udp_limit(request: &Message) -> usize {
    request.edns().map_or(MAX_UDP_PAYLOAD, |edns| {
        usize::from(edns.udp_payload_size().clamp(512, EDNS_MAX_PAYLOAD))
    })
}

fn error_response(request: &Message, rcode: Rcode) -> Message {
    let mut response = Message::response(request);
    response.set_flags(response.flags().with_ra(true));
    if let Some(edns) = request.edns() {
        let payload = edns.udp_payload_size().clamp(512, EDNS_DEFAULT_PAYLOAD);
        response.set_edns(Some(Edns::new(payload).with_dnssec_ok(edns.dnssec_ok())));
    }
    response.set_rcode(rcode);
    response
}

/// Кодирует ответ; если он больше лимита, отбрасывает секции и ставит TC.
#[cfg(test)]
fn encode_limited(response: &Message, limit: usize) -> Result<(Vec<u8>, bool), EncodeError> {
    let options = EncodeOptions::default();
    let encoded = response.encode(&options)?;
    if encoded.len() <= limit {
        return Ok((encoded, false));
    }
    for (answers, authority, questions) in [
        (true, true, true),
        (true, false, true),
        (false, false, true),
        (false, false, false),
    ] {
        let candidate = rebuild(response, answers, authority, questions);
        let encoded = candidate.encode(&options)?;
        if encoded.len() <= limit {
            return Ok((encoded, true));
        }
    }
    // Минимальный заголовок (12 байт) всегда укладывается в limit ≥ 512.
    let encoded = rebuild(response, false, false, false).encode(&options)?;
    Ok((encoded, true))
}

fn rebuild(response: &Message, answers: bool, authority: bool, questions: bool) -> Message {
    let mut out = Message::new(response.id(), response.flags().with_qr(true).with_tc(true));
    if questions {
        for question in response.questions() {
            out.add_question(question.clone());
        }
    }
    out.set_rcode(response.rcode());
    if let Some(edns) = response.edns() {
        out.set_edns(Some(edns.clone()));
    }
    if answers {
        for record in response.answers() {
            out.add_answer(record.clone());
        }
    }
    if authority {
        for record in response.authority() {
            out.add_authority(record.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::net::UdpSocket;
    use std::sync::atomic::AtomicBool;
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    use pulse_dns::{Name, Question, Rclass, Rdata, Record, Ttl};
    use pulse_resolver::ResolverConfig;

    use super::*;

    #[global_allocator]
    static ALLOC: dhat::Alloc = dhat::Alloc;

    struct MockUpstream {
        addr: std::net::SocketAddr,
        shutdown: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
    }

    impl MockUpstream {
        fn start() -> Self {
            let socket = UdpSocket::bind("127.0.0.1:0").expect("bind mock upstream");
            socket
                .set_read_timeout(Some(Duration::from_millis(20)))
                .expect("timeout");
            let addr = socket.local_addr().expect("addr");
            let shutdown = Arc::new(AtomicBool::new(false));
            let flag = Arc::clone(&shutdown);
            let thread = thread::spawn(move || {
                let mut buffer = [0_u8; 4096];
                while !flag.load(std::sync::atomic::Ordering::Relaxed) {
                    let Ok((length, peer)) = socket.recv_from(&mut buffer) else {
                        continue;
                    };
                    let Ok(request) = Message::decode(&buffer[..length], &DecodeLimits::default())
                    else {
                        continue;
                    };
                    let Some(question) = request.questions().first() else {
                        continue;
                    };
                    let mut response = Message::response(&request);
                    response.set_rcode(Rcode::NOERROR);
                    let record = Record::new(
                        question.qname().clone(),
                        Rtype::A,
                        Rclass::IN,
                        Ttl::new(3600).expect("ttl"),
                        Rdata::A([192, 0, 2, 99].into()),
                    )
                    .expect("record");
                    response.add_answer(record);
                    let Ok(bytes) = response.encode(&EncodeOptions::default()) else {
                        continue;
                    };
                    let _ = socket.send_to(&bytes, peer);
                }
            });
            Self {
                addr,
                shutdown,
                thread: Some(thread),
            }
        }
    }

    impl Drop for MockUpstream {
        fn drop(&mut self) {
            self.shutdown
                .store(true, std::sync::atomic::Ordering::Relaxed);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    fn processor(upstream: std::net::SocketAddr) -> Processor {
        let mut config = ResolverConfig::forward(vec![upstream]);
        config.retries = 1;
        config.use_0x20 = false;
        config.timeouts.per_query = Duration::from_millis(500);
        config.timeouts.tcp = Duration::from_millis(700);
        config.timeouts.total = Duration::from_secs(3);
        let resolver = pulse_resolver::Resolver::new(config).expect("resolver");
        Processor::new(
            resolver,
            Arc::new(Stats::new()),
            Acl::allow_all(),
            None,
            None,
            RateLimitAction::Refused,
            None,
        )
    }

    fn query_wire() -> Vec<u8> {
        Message::query(
            0x1234,
            Question::new(
                Name::parse("hot.example").expect("name"),
                Rtype::A,
                Rclass::IN,
            ),
        )
        .encode(&EncodeOptions::default())
        .expect("encode")
    }

    fn percentile(samples: &mut [u64], numerator: usize, denominator: usize) -> u64 {
        if samples.is_empty() {
            return 0;
        }
        samples.sort_unstable();
        let rank = samples
            .len()
            .saturating_mul(numerator)
            .saturating_div(denominator)
            .saturating_sub(1);
        samples.get(rank).copied().unwrap_or(0)
    }

    #[test]
    #[ignore = "allocation probe: run explicitly with --test-threads=1"]
    fn hot_path_cache_hit_allocates_nothing() {
        let upstream = MockUpstream::start();
        let processor = processor(upstream.addr);
        let wire = query_wire();
        let peer: std::net::SocketAddr = "127.0.0.1:5353".parse().expect("peer");
        let mut out = [0_u8; 4096];
        let warm = processor
            .handle_into(&wire, Transport::Udp, peer, &mut out)
            .expect("warm");
        assert!(warm > 12);
        // Второй вызов обязан попасть в кеш.
        let hit = processor
            .handle_into(&wire, Transport::Udp, peer, &mut out)
            .expect("hit");
        assert!(hit > 12);

        let _profiler = dhat::Profiler::builder()
            .testing()
            .trim_backtraces(Some(4))
            .build();
        let before = dhat::HeapStats::get();
        for _ in 0..10_000 {
            let length = processor
                .handle_into(&wire, Transport::Udp, peer, &mut out)
                .expect("hit");
            std::hint::black_box(length);
        }
        let after = dhat::HeapStats::get();
        let allocations = after.total_blocks.saturating_sub(before.total_blocks);
        eprintln!(
            "hot_path allocs={allocations} allocs/op={:.3}",
            allocations as f64 / 10_000.0
        );
        assert_eq!(allocations, 0, "cache hit must not allocate");
    }

    #[test]
    #[ignore = "latency probe: run explicitly with --nocapture"]
    fn hot_path_latency_old_vs_new() {
        const BATCH: usize = 64;
        const BATCHES: usize = 2_000;
        let upstream = MockUpstream::start();
        let processor = processor(upstream.addr);
        let wire = query_wire();
        let peer: std::net::SocketAddr = "127.0.0.1:5353".parse().expect("peer");
        let mut out = [0_u8; 4096];
        processor
            .handle_into(&wire, Transport::Udp, peer, &mut out)
            .expect("warm");
        let resolver = processor.resolver.clone();

        let mut legacy = Vec::with_capacity(BATCHES);
        for _ in 0..BATCHES {
            let started = Instant::now();
            for _ in 0..BATCH {
                let request = Message::decode(&wire, &DecodeLimits::default()).expect("decode");
                let response = resolver.resolve(&request);
                let (bytes, _) = encode_limited(&response, 512).expect("encode");
                std::hint::black_box(bytes.len());
            }
            legacy.push(
                u64::try_from(started.elapsed().as_nanos() / BATCH as u128).unwrap_or(u64::MAX),
            );
        }

        let mut fresh = Vec::with_capacity(BATCHES);
        for _ in 0..BATCHES {
            let started = Instant::now();
            for _ in 0..BATCH {
                let length = processor
                    .handle_into(&wire, Transport::Udp, peer, &mut out)
                    .expect("hit");
                std::hint::black_box(length);
            }
            fresh.push(
                u64::try_from(started.elapsed().as_nanos() / BATCH as u128).unwrap_or(u64::MAX),
            );
        }

        let legacy_p50 = percentile(&mut legacy, 50, 100);
        let legacy_p99 = percentile(&mut legacy, 99, 100);
        let fresh_p50 = percentile(&mut fresh, 50, 100);
        let fresh_p99 = percentile(&mut fresh, 99, 100);
        eprintln!("legacy Message path: p50={legacy_p50} ns p99={legacy_p99} ns");
        eprintln!("wire fast path:       p50={fresh_p50} ns p99={fresh_p99} ns");
        eprintln!(
            "delta: p50={} ns p99={} ns",
            i128::from(legacy_p50) - i128::from(fresh_p50),
            i128::from(legacy_p99) - i128::from(fresh_p99)
        );
    }

    fn response_with_txt(count: usize) -> Message {
        let name = Name::parse("big.test").unwrap();
        let mut response = Message::query(7, Question::new(name.clone(), Rtype::TXT, Rclass::IN));
        response = Message::response(&response);
        for index in 0..count {
            let text = format!("{index:04}-{}", "x".repeat(100));
            let record = Record::new(
                name.clone(),
                Rtype::TXT,
                Rclass::IN,
                Ttl::new(60).unwrap(),
                Rdata::Txt(pulse_dns::TxtData::new([text.as_bytes().to_vec()]).unwrap()),
            )
            .unwrap();
            response.add_answer(record);
        }
        response
    }

    #[test]
    fn small_response_is_not_truncated() {
        let response = response_with_txt(1);
        let (bytes, truncated) = encode_limited(&response, 512).unwrap();
        assert!(!truncated);
        assert!(bytes.len() <= 512);
        assert!(
            !Message::decode(&bytes, &DecodeLimits::default())
                .unwrap()
                .flags()
                .tc()
        );
    }

    #[test]
    fn oversized_response_sets_tc_and_fits() {
        let response = response_with_txt(20);
        let (bytes, truncated) = encode_limited(&response, 512).unwrap();
        assert!(truncated);
        assert!(bytes.len() <= 512);
        let decoded = Message::decode(&bytes, &DecodeLimits::default()).unwrap();
        assert!(decoded.flags().tc());
        assert_eq!(decoded.questions().len(), 1);
        assert_eq!(decoded.answers().len(), 0);
    }

    #[test]
    fn huge_edns_payload_keeps_answer() {
        let response = response_with_txt(20);
        let (bytes, truncated) = encode_limited(&response, 4096).unwrap();
        assert!(!truncated);
        let decoded = Message::decode(&bytes, &DecodeLimits::default()).unwrap();
        assert_eq!(decoded.answers().len(), 20);
    }
}
