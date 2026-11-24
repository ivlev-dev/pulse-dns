//! Обработка одного DNS-запроса: decode → resolve → encode с усечением.

use std::net::IpAddr;
use std::sync::Arc;

use pulse_dns::{
    DecodeLimits, EDNS_DEFAULT_PAYLOAD, EDNS_MAX_PAYLOAD, Edns, EncodeError, EncodeOptions, Flags,
    MAX_MESSAGE_LEN, MAX_UDP_PAYLOAD, Message, Opcode, Rcode, Rtype,
};
use pulse_resolver::Resolver;
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
    pub(crate) fn handle(
        &self,
        request: &[u8],
        transport: Transport,
        peer: std::net::SocketAddr,
    ) -> Option<Vec<u8>> {
        transport.count_query(&self.stats);
        let raw_limit = transport.raw_limit();
        if !self.policy.allows(transport, peer.ip()) {
            self.stats.refused_acl();
            self.stats.refused();
            return self.raw_error(request, Rcode::REFUSED, raw_limit, transport);
        }
        let Ok(request) = Message::decode(request, &DecodeLimits::default()) else {
            self.stats.decode_error();
            return self.raw_error(request, Rcode::FORMERR, raw_limit, transport);
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
                    self.encode_response(
                        &error_response(&request, Rcode::REFUSED),
                        limit,
                        transport,
                    )
                }
                RateLimitAction::Truncate => {
                    self.stats.rate_limit_truncated();
                    self.encode_response(&truncated_response(&request), limit, transport)
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
                            error_response(&request, Rcode::REFUSED)
                        }
                        RateLimitAction::Truncate => truncated_response(&request),
                    };
                    return self.encode_response(&limited, limit, transport);
                }
            }
        }
        self.encode_response(&response, limit, transport)
    }

    fn encode_response(
        &self,
        response: &Message,
        limit: usize,
        transport: Transport,
    ) -> Option<Vec<u8>> {
        let Ok((bytes, truncated)) = encode_limited(response, limit) else {
            self.stats.encode_error();
            return None;
        };
        if truncated {
            self.stats.truncated();
        }
        transport.count_response(&self.stats);
        Some(bytes)
    }

    fn raw_error(
        &self,
        raw: &[u8],
        rcode: Rcode,
        limit: usize,
        transport: Transport,
    ) -> Option<Vec<u8>> {
        if raw.len() < 12 {
            self.stats.dropped();
            return None;
        }
        let id = u16::from_be_bytes([*raw.first()?, *raw.get(1)?]);
        let opcode = raw.get(2).map_or(0, |byte| byte >> 3) & 0x0F;
        let mut response = Message::new(
            id,
            Flags::new()
                .with_qr(true)
                .with_ra(true)
                .with_opcode(Opcode::from_u8(opcode)),
        );
        response.set_rcode(rcode);
        if rcode == Rcode::FORMERR {
            self.stats.formerr();
        }
        let Ok((bytes, _)) = encode_limited(&response, limit) else {
            self.stats.encode_error();
            return None;
        };
        transport.count_response(&self.stats);
        Some(bytes)
    }
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
    use pulse_dns::{Name, Question, Rclass, Rdata, Record, Ttl};

    use super::*;

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
