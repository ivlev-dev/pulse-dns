//! Движок авторитетных запросов: разбор вопроса, композиция ответа, EDNS, усечение.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use pulse_dns::{
    Edns, EncodeError, EncodeOptions, Flags, MAX_MESSAGE_LEN, MAX_NAME_WIRE_LEN, Message, Name,
    Opcode, Rclass, Rcode, Rdata, RdataError, Record, RecordError, Rrset, RrsetError, Rtype, Ttl,
    TtlError,
};
use pulse_dnssec::{DenialLimits, Nsec3Params};
use thiserror::Error;

use super::port::ZoneView;
use super::stats::QueryStats;
use crate::domain::{DenialKind, LookupOutcome, ZoneState};

/// UDP payload без EDNS0 (RFC 1035 §4.2.1).
pub const UDP_PAYLOAD_WITHOUT_EDNS: u16 = 512;
/// Рекомендуемый EDNS0 payload сервера (SEC-DNS-001).
pub const EDNS_DEFAULT_PAYLOAD: u16 = 1232;
/// Верхняя граница EDNS0 payload, которую использует сервер в v1 (SEC-DNS-001).
pub const MAX_UDP_PAYLOAD: u16 = 1232;
/// Лимит цепочки `CNAME`/`DNAME` (SEC-RES-006).
pub const MAX_CNAME_CHAIN: usize = 16;
/// Верхняя граница TTL негативного ответа (INV-14, RFC 2308 §5).
pub const NEGATIVE_TTL_CAP: u32 = 10_800;
/// TTL синтезированного `HINFO` для `QTYPE=ANY` по умолчанию.
pub const DEFAULT_ANY_HINFO_TTL: Ttl = Ttl::from_wire(3600);

/// Тип `HINFO` (RFC 1035 §3.3.2), не входящий в известные типы `pulse-dns`.
const HINFO_TYPE: Rtype = Rtype::from_u16(13);
/// RDATA синтезированного `HINFO`: CPU `"RFC8482"`, пустой OS (RFC 8482 §4.1).
const HINFO_RFC8482: [u8; 9] = [8, b'R', b'F', b'C', b'8', b'4', b'8', b'2', 0];

/// Настройки движка.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineConfig {
    /// TTL синтезированного `HINFO` для `QTYPE=ANY` (RFC 8482 §4.2).
    pub any_hinfo_ttl: Ttl,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            any_hinfo_ttl: DEFAULT_ANY_HINFO_TTL,
        }
    }
}

/// Транспорт, для которого формируется ответ.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    /// UDP: ответ ограничен 512 октетами без EDNS0 либо согласованным payload.
    Udp,
    /// TCP: ответ ограничен 65535 октетами, `TC` не выставляется.
    Tcp,
}

/// Ошибка построения ответа.
///
/// Протокольные ошибки (`FORMERR`, `NOTIMP`, `REFUSED`, `NXDOMAIN`, …) не
/// являются `Err`: они возвращаются как обычный [`Message`]. `Err` означает
/// невозможность собрать корректный ответ (испорченные данные зоны,
/// превышение wire-лимитов); [`QueryEngine::respond`] превращает его в
/// `SERVFAIL` и инкрементирует счётчик.
#[derive(Debug, Error)]
pub enum QueryError {
    /// Некорректный RRset, полученный от порта зоны.
    #[error("invalid rrset from zone: {0}")]
    Rrset(#[from] RrsetError),
    /// Не удалось собрать запись для wire-формы.
    #[error("invalid record while assembling response: {0}")]
    Record(#[from] RecordError),
    /// Ошибка wire-кодирования при проверке размера ответа.
    #[error("wire encoding failed: {0}")]
    Encode(#[from] EncodeError),
    /// Некорректный TTL при построении негативного ответа.
    #[error("invalid ttl: {0}")]
    Ttl(#[from] TtlError),
    /// Не удалось собрать синтезированные RDATA (`HINFO` для ANY).
    #[error("invalid synthesized rdata: {0}")]
    Rdata(#[from] RdataError),
    /// `Serving`-зона не содержит `SOA` — нарушение INV-4.
    #[error("zone {zone} is serving but has no SOA")]
    MissingSoa {
        /// Origin зоны.
        zone: Name,
    },
    /// Порт зоны вернул данные, противоречащие контракту.
    #[error("zone {zone} returned inconsistent data for {name} ({rtype})")]
    InconsistentZone {
        /// Origin зоны.
        zone: Name,
        /// Имя запроса.
        name: Name,
        /// Тип запроса.
        rtype: Rtype,
    },
    /// Обнаружен цикл `CNAME`/`DNAME` (BIND-совместимый `SERVFAIL`).
    #[error("cname/dname loop detected at {name}")]
    ChainLoop {
        /// Имя, на котором замыкается цепочка.
        name: Name,
    },
    /// Минимальный ответ (заголовок + вопрос + OPT) не помещается в лимит.
    #[error("empty response base exceeds {limit} octets")]
    BaseTooLarge {
        /// Лимит транспорта.
        limit: u16,
    },
}

/// Авторитетный движок запросов.
///
/// Держит набор зон (longest-suffix выбор через индекс по именам) и общие
/// атомарные счётчики. Движок не делает ввода-вывода и не блокируется:
/// каждый вызов [`QueryEngine::respond`] независим.
pub struct QueryEngine {
    zones: Vec<Arc<dyn ZoneView>>,
    zone_index: HashMap<Name, usize>,
    stats: Arc<QueryStats>,
    config: EngineConfig,
}

impl QueryEngine {
    /// Создаёт движок над набором зон с новыми счётчиками и дефолтной
    /// конфигурацией.
    #[must_use]
    pub fn new(zones: Vec<Arc<dyn ZoneView>>) -> Self {
        Self::build(zones, Arc::new(QueryStats::new()), EngineConfig::default())
    }

    /// Создаёт движок с разделяемыми счётчиками и дефолтной конфигурацией.
    #[must_use]
    pub fn with_stats(zones: Vec<Arc<dyn ZoneView>>, stats: Arc<QueryStats>) -> Self {
        Self::build(zones, stats, EngineConfig::default())
    }

    /// Создаёт движок с явной конфигурацией и новыми счётчиками.
    #[must_use]
    pub fn with_config(zones: Vec<Arc<dyn ZoneView>>, config: EngineConfig) -> Self {
        Self::build(zones, Arc::new(QueryStats::new()), config)
    }

    /// Создаёт движок с явной конфигурацией и разделяемыми счётчиками.
    #[must_use]
    pub fn with_config_and_stats(
        zones: Vec<Arc<dyn ZoneView>>,
        config: EngineConfig,
        stats: Arc<QueryStats>,
    ) -> Self {
        Self::build(zones, stats, config)
    }

    fn build(zones: Vec<Arc<dyn ZoneView>>, stats: Arc<QueryStats>, config: EngineConfig) -> Self {
        let mut zone_index = HashMap::with_capacity(zones.len());
        for (position, zone) in zones.iter().enumerate() {
            zone_index.insert(zone.origin().clone(), position);
        }
        Self {
            zones,
            zone_index,
            stats,
            config,
        }
    }

    /// Конфигурация движка.
    #[must_use]
    pub const fn config(&self) -> EngineConfig {
        self.config
    }

    /// Счётчики движка.
    #[must_use]
    pub fn stats(&self) -> &QueryStats {
        &self.stats
    }

    /// Обрабатывает запрос и всегда возвращает ответ (при внутренней ошибке —
    /// `SERVFAIL`).
    #[must_use]
    pub fn respond(&self, request: &Message, transport: Transport) -> Message {
        if let Ok(response) = self.try_respond(request, transport) {
            response
        } else {
            self.stats.record_servfail();
            Self::error_response(request, Rcode::SERVFAIL)
        }
    }

    /// Обрабатывает запрос, возвращая ошибку построения ответа.
    ///
    /// # Errors
    ///
    /// [`QueryError`], если данные зоны некорректны или ответ не кодируется в
    /// wire-формат.
    pub fn try_respond(
        &self,
        request: &Message,
        transport: Transport,
    ) -> Result<Message, QueryError> {
        self.stats.record_query();

        if request.flags().qr() {
            self.stats.record_formerr();
            return Ok(Self::error_response(request, Rcode::FORMERR));
        }
        if request.opcode() != Opcode::QUERY {
            self.stats.record_notimp();
            return Ok(Self::error_response(request, Rcode::NOTIMP));
        }
        let Some(question) = request.questions().first() else {
            self.stats.record_formerr();
            return Ok(Self::error_response(request, Rcode::FORMERR));
        };
        if request.questions().len() != 1 {
            self.stats.record_formerr();
            return Ok(Self::error_response(request, Rcode::FORMERR));
        }
        if request.edns().is_some_and(|edns| edns.version() != 0) {
            self.stats.record_badvers();
            return Ok(Self::badvers_response(request));
        }
        if is_transfer_meta_qtype(question.qtype()) {
            self.stats.record_notimp();
            return Ok(Self::error_response(request, Rcode::NOTIMP));
        }

        let qname = question.qname();
        let qtype = question.qtype();
        let Some(zone) = self.find_zone(qname) else {
            self.stats.record_refused();
            return Ok(Self::error_response(request, Rcode::REFUSED));
        };
        if zone.state() == ZoneState::Expired {
            self.stats.record_servfail();
            return Ok(Self::error_response(request, Rcode::SERVFAIL));
        }
        if zone.state() != ZoneState::Serving {
            self.stats.record_refused();
            return Ok(Self::error_response(request, Rcode::REFUSED));
        }
        let qclass = question.qclass();
        if qclass != zone.class() && qclass != Rclass::ANY {
            self.stats.record_refused();
            return Ok(Self::error_response(request, Rcode::REFUSED));
        }

        let do_bit = request.edns().is_some_and(Edns::dnssec_ok);
        let resolution = self.resolve(zone, qname, qtype, do_bit)?;
        match resolution.status {
            Status::NxDomain => self.stats.record_nxdomain(),
            Status::NoData => self.stats.record_nodata(),
            Status::Answer | Status::Referral | Status::YxDomain => {}
        }

        let mut message = Message::response(request);
        let flags = message
            .flags()
            .with_aa(resolution.aa)
            .with_ra(false)
            .with_ad(false)
            .with_tc(false);
        message.set_flags(flags);
        if let Some(edns) = request.edns() {
            message.set_edns(Some(response_edns(edns)));
        }
        message.set_rcode(status_rcode(resolution.status));
        Self::append_answer(&mut message, zone, &resolution, do_bit)?;

        match transport {
            Transport::Udp => {
                let limit = request
                    .edns()
                    .map_or(UDP_PAYLOAD_WITHOUT_EDNS, negotiated_payload);
                let (message, truncated) = truncate_to(&message, limit)?;
                if truncated {
                    self.stats.record_truncated();
                }
                Ok(message)
            }
            Transport::Tcp => {
                let encoded = message.encode(&EncodeOptions::compressed())?;
                if encoded.len() > MAX_MESSAGE_LEN {
                    return Err(QueryError::Encode(EncodeError::MessageTooLong {
                        len: encoded.len(),
                    }));
                }
                Ok(message)
            }
        }
    }

    fn find_zone(&self, qname: &Name) -> Option<&dyn ZoneView> {
        let mut current = Some(qname.clone());
        while let Some(candidate) = current {
            if let Some(&position) = self.zone_index.get(&candidate)
                && let Some(zone) = self.zones.get(position)
            {
                return Some(zone.as_ref());
            }
            current = candidate.parent();
        }
        None
    }

    fn resolve(
        &self,
        zone: &dyn ZoneView,
        qname: &Name,
        qtype: Rtype,
        do_bit: bool,
    ) -> Result<Resolution, QueryError> {
        if let Some(mut referral) = referral_for(zone, qname, qtype, do_bit)? {
            if matches!(referral.status, Status::NoData | Status::NxDomain) {
                append_negative_soa(zone, &mut referral)?;
            }
            if do_bit && zone.signed() {
                append_denial_proofs(zone, qname, &mut referral);
            }
            return Ok(referral);
        }
        let mut resolution = Resolution::empty();
        let mut visited = Vec::new();
        self.resolve_name(zone, qname, qtype, 0, &mut visited, &mut resolution)?;
        if matches!(resolution.status, Status::NoData | Status::NxDomain) {
            append_negative_soa(zone, &mut resolution)?;
        }
        if do_bit && zone.signed() {
            append_denial_proofs(zone, qname, &mut resolution);
        }
        Ok(resolution)
    }

    fn should_chase(
        zone: &dyn ZoneView,
        qname: &Name,
        target: &Name,
        depth: usize,
        visited: &[Name],
    ) -> Result<bool, QueryError> {
        if target == qname || visited.contains(target) {
            return Err(QueryError::ChainLoop {
                name: target.clone(),
            });
        }
        if depth + 1 >= MAX_CNAME_CHAIN {
            return Ok(false);
        }
        if !target.is_subdomain_of(zone.origin()) || find_delegation(zone, target).is_some() {
            return Ok(false);
        }
        Ok(true)
    }

    fn resolve_name(
        &self,
        zone: &dyn ZoneView,
        qname: &Name,
        qtype: Rtype,
        depth: usize,
        visited: &mut Vec<Name>,
        resolution: &mut Resolution,
    ) -> Result<(), QueryError> {
        if let Some((dname, target_suffix)) = dname_redirect(zone, qname)? {
            resolution.answers.push(dname.clone());
            resolution.aa = true;
            resolution.status = Status::Answer;
            let Some(target) = substitute_suffix(qname, dname.owner(), &target_suffix) else {
                resolution.status = Status::YxDomain;
                return Ok(());
            };
            let cname = Rrset::new(
                qname.clone(),
                Rtype::CNAME,
                zone.class(),
                dname.ttl(),
                [Rdata::Cname(target.clone())],
            )?;
            resolution.answers.push(cname);
            if Self::should_chase(zone, qname, &target, depth, visited)? {
                visited.push(qname.clone());
                self.resolve_name(zone, &target, qtype, depth + 1, visited, resolution)?;
            }
            return Ok(());
        }

        if qtype == Rtype::ANY {
            return self.resolve_any(zone, qname, resolution);
        }

        match zone.lookup(qname, qtype) {
            LookupOutcome::Answer(rrset) => {
                resolution.answers.push(rrset);
                resolution.status = Status::Answer;
                resolution.aa = true;
            }
            LookupOutcome::Cname(rrset, target) => {
                resolution.answers.push(rrset);
                resolution.status = Status::Answer;
                resolution.aa = true;
                if Self::should_chase(zone, qname, &target, depth, visited)? {
                    visited.push(qname.clone());
                    self.resolve_name(zone, &target, qtype, depth + 1, visited, resolution)?;
                }
            }
            LookupOutcome::NoData => {
                resolution.status = Status::NoData;
                resolution.aa = true;
            }
            LookupOutcome::NxDomain => {
                self.resolve_wildcard(zone, qname, qtype, depth, visited, resolution)?;
            }
            LookupOutcome::Delegation { ns, .. } => {
                resolution.status = Status::Referral;
                resolution.aa = false;
                resolution.authority.push(ns);
            }
            LookupOutcome::Referral | LookupOutcome::ZoneNotFound => {
                return Err(QueryError::InconsistentZone {
                    zone: zone.origin().clone(),
                    name: qname.clone(),
                    rtype: qtype,
                });
            }
        }
        Ok(())
    }

    fn resolve_wildcard(
        &self,
        zone: &dyn ZoneView,
        qname: &Name,
        qtype: Rtype,
        depth: usize,
        visited: &mut Vec<Name>,
        resolution: &mut Resolution,
    ) -> Result<(), QueryError> {
        let Some(wildcard) = wildcard_for(zone, qname) else {
            resolution.status = Status::NxDomain;
            resolution.aa = true;
            return Ok(());
        };
        resolution.wildcard = Some(wildcard.clone());
        match zone.lookup(&wildcard, qtype) {
            LookupOutcome::Answer(rrset) => {
                resolution
                    .signature_sources
                    .insert((qname.clone(), rrset.rr_type()), wildcard.clone());
                resolution.answers.push(reowner(&rrset, qname)?);
                resolution.status = Status::Answer;
                resolution.aa = true;
            }
            LookupOutcome::Cname(rrset, target) => {
                resolution
                    .signature_sources
                    .insert((qname.clone(), rrset.rr_type()), wildcard.clone());
                resolution.answers.push(reowner(&rrset, qname)?);
                resolution.status = Status::Answer;
                resolution.aa = true;
                if Self::should_chase(zone, qname, &target, depth, visited)? {
                    visited.push(qname.clone());
                    self.resolve_name(zone, &target, qtype, depth + 1, visited, resolution)?;
                }
            }
            LookupOutcome::NoData => {
                resolution.status = Status::NoData;
                resolution.aa = true;
            }
            LookupOutcome::NxDomain => {
                resolution.status = Status::NxDomain;
                resolution.aa = true;
            }
            LookupOutcome::Delegation { ns, .. } => {
                resolution.status = Status::Referral;
                resolution.aa = false;
                resolution.authority.push(ns);
            }
            LookupOutcome::Referral | LookupOutcome::ZoneNotFound => {
                return Err(QueryError::InconsistentZone {
                    zone: zone.origin().clone(),
                    name: qname.clone(),
                    rtype: qtype,
                });
            }
        }
        Ok(())
    }

    fn resolve_any(
        &self,
        zone: &dyn ZoneView,
        qname: &Name,
        resolution: &mut Resolution,
    ) -> Result<(), QueryError> {
        match zone.lookup(qname, Rtype::CNAME) {
            LookupOutcome::Answer(cname) => {
                resolution.answers.push(cname);
                resolution.status = Status::Answer;
                resolution.aa = true;
                return Ok(());
            }
            LookupOutcome::NoData | LookupOutcome::NxDomain => {}
            LookupOutcome::Cname(..)
            | LookupOutcome::Delegation { .. }
            | LookupOutcome::Referral
            | LookupOutcome::ZoneNotFound => {
                return Err(QueryError::InconsistentZone {
                    zone: zone.origin().clone(),
                    name: qname.clone(),
                    rtype: Rtype::CNAME,
                });
            }
        }

        if zone.node_exists(qname) {
            return synthesize_hinfo(zone, qname, self.config.any_hinfo_ttl, resolution);
        }

        let Some(wildcard) = wildcard_for(zone, qname) else {
            resolution.status = Status::NxDomain;
            resolution.aa = true;
            return Ok(());
        };
        match zone.lookup(&wildcard, Rtype::CNAME) {
            LookupOutcome::Answer(cname) => {
                resolution.answers.push(reowner(&cname, qname)?);
                resolution.status = Status::Answer;
                resolution.aa = true;
                return Ok(());
            }
            LookupOutcome::NoData | LookupOutcome::NxDomain => {}
            LookupOutcome::Cname(..)
            | LookupOutcome::Delegation { .. }
            | LookupOutcome::Referral
            | LookupOutcome::ZoneNotFound => {
                return Err(QueryError::InconsistentZone {
                    zone: zone.origin().clone(),
                    name: wildcard,
                    rtype: Rtype::CNAME,
                });
            }
        }
        if zone.node_exists(&wildcard) {
            return synthesize_hinfo(zone, qname, self.config.any_hinfo_ttl, resolution);
        }
        resolution.status = Status::NxDomain;
        resolution.aa = true;
        Ok(())
    }

    fn append_answer(
        message: &mut Message,
        zone: &dyn ZoneView,
        resolution: &Resolution,
        do_bit: bool,
    ) -> Result<(), QueryError> {
        let signed = do_bit && zone.signed();
        let mut signatures: HashSet<(Name, Rdata)> = HashSet::new();

        for rrset in &resolution.answers {
            let source = resolution
                .signature_sources
                .get(&(rrset.owner().clone(), rrset.rr_type()))
                .unwrap_or(rrset.owner());
            append_rrset(
                message,
                zone,
                rrset,
                Section::Answer,
                signed,
                Some(source),
                &mut signatures,
            )?;
        }
        for rrset in &resolution.authority {
            append_rrset(
                message,
                zone,
                rrset,
                Section::Authority,
                signed,
                None,
                &mut signatures,
            )?;
        }

        let mut seen: HashSet<(Name, Rtype)> = resolution
            .answers
            .iter()
            .chain(resolution.authority.iter())
            .map(|rrset| (rrset.owner().clone(), rrset.rr_type()))
            .collect();

        let mut targets: Vec<Name> = Vec::new();
        for rrset in &resolution.answers {
            collect_targets(rrset, &mut targets);
        }
        targets.retain(|target| {
            target.is_subdomain_of(zone.origin()) && find_delegation(zone, target).is_none()
        });

        // Referral: glue допустим только для имён внутри этого же cut
        // (bailiwick). Цель ниже другого cut — не наши данные.
        let mut referral_targets: Vec<Name> = Vec::new();
        for rrset in &resolution.authority {
            if rrset.rr_type() != Rtype::NS {
                continue;
            }
            let cut = rrset.owner();
            let mut candidates = Vec::new();
            collect_targets(rrset, &mut candidates);
            for target in candidates {
                if !target.is_subdomain_of(zone.origin()) {
                    continue;
                }
                match find_delegation(zone, &target) {
                    None => referral_targets.push(target),
                    Some(delegation) if delegation == *cut => referral_targets.push(target),
                    Some(_) => {}
                }
            }
        }
        targets.extend(referral_targets);
        targets.sort_by(Name::cmp_canonical);
        targets.dedup();

        for target in targets {
            for glue in zone.glue(&target) {
                let key = (glue.owner().clone(), glue.rr_type());
                if !seen.insert(key) {
                    continue;
                }
                append_rrset(
                    message,
                    zone,
                    &glue,
                    Section::Additional,
                    signed,
                    None,
                    &mut signatures,
                )?;
            }
        }
        Ok(())
    }

    fn error_response(request: &Message, rcode: Rcode) -> Message {
        let mut message = Message::new(
            request.id(),
            Flags::new()
                .with_qr(true)
                .with_opcode(request.opcode())
                .with_rd(request.flags().rd())
                .with_cd(request.flags().cd())
                .with_ra(false)
                .with_aa(false)
                .with_tc(false),
        );
        if let Some(question) = request.questions().first() {
            message.add_question(question.clone());
        }
        if let Some(edns) = request.edns() {
            message.set_edns(Some(response_edns(edns)));
        }
        message.set_rcode(rcode);
        message
    }

    fn badvers_response(request: &Message) -> Message {
        let mut message = Message::response(request);
        let flags = message.flags().with_aa(false).with_ra(false).with_tc(false);
        message.set_flags(flags);
        let edns = request
            .edns()
            .map_or_else(|| Edns::new(EDNS_DEFAULT_PAYLOAD), response_edns);
        message.set_edns(Some(edns));
        message.set_rcode(Rcode::BADVERS);
        message
    }
}

/// Секция DNS-сообщения, в которую добавляется RRset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    Answer,
    Authority,
    Additional,
}

impl Section {
    fn add(self, message: &mut Message, record: Record) {
        match self {
            Self::Answer => message.add_answer(record),
            Self::Authority => message.add_authority(record),
            Self::Additional => message.add_additional(record),
        }
    }
}

/// Добавляет RRset и (при `DO = 1`) его `RRSIG`.
///
/// `signature_owner` задаёт имя, под которым подписи хранятся в зоне; для
/// wildcard-развёрнутого ответа это `*.closest-encloser`, а записи
/// переименовываются в QNAME (RFC 4035 §5.3.2).
fn append_rrset(
    message: &mut Message,
    zone: &dyn ZoneView,
    rrset: &Rrset,
    section: Section,
    signed: bool,
    signature_owner: Option<&Name>,
    signatures: &mut HashSet<(Name, Rdata)>,
) -> Result<(), QueryError> {
    for record in rrset_records(rrset)? {
        section.add(message, record);
    }
    if !signed || rrset.rr_type() == Rtype::RRSIG {
        return Ok(());
    }
    let source = signature_owner.unwrap_or_else(|| rrset.owner());
    for signatures_rrset in zone.lookup_all_rrsig(source, rrset.rr_type()) {
        let signatures_rrset = if source == rrset.owner() {
            signatures_rrset
        } else {
            reowner(&signatures_rrset, rrset.owner())?
        };
        for record in rrset_records(&signatures_rrset)? {
            let key = (record.owner().clone(), record.rdata().clone());
            if signatures.insert(key) {
                section.add(message, record);
            }
        }
    }
    Ok(())
}

/// Добавляет denial-доказательство к негативному или wildcard-ответу.
fn append_denial_proofs(zone: &dyn ZoneView, qname: &Name, resolution: &mut Resolution) {
    match zone.denial() {
        DenialKind::Nsec => append_nsec_proofs(zone, qname, resolution),
        DenialKind::Nsec3 => append_nsec3_proofs(zone, qname, resolution),
    }
}

/// Добавляет NSEC3-доказательство к негативному или wildcard-ответу.
///
/// Наборы подбираются только по hash-пространству из `NSEC3PARAM`: closest
/// encloser, next closer и wildcard. Каждый proof получает RRSIG через
/// обычный [`append_rrset`] (owner NSEC3 — hashed-имя).
fn append_nsec3_proofs(zone: &dyn ZoneView, qname: &Name, resolution: &mut Resolution) {
    let Some(params) = nsec3_params(zone) else {
        return;
    };
    let mut proofs: Vec<Rrset> = Vec::new();
    match resolution.status {
        Status::NxDomain => {
            let closest = closest_encloser(zone, qname);
            push_nsec3_exact(zone, &params, &closest, &mut proofs);
            if let Some(next) = next_closer_name(qname, &closest) {
                push_nsec3_cover(zone, &params, &next, &mut proofs);
            }
            if let Some(wildcard) = wildcard_name(&closest) {
                push_nsec3_cover(zone, &params, &wildcard, &mut proofs);
            }
        }
        Status::NoData => {
            if let Some(wildcard) = &resolution.wildcard {
                if let Some(closest) = wildcard.parent() {
                    push_nsec3_exact(zone, &params, &closest, &mut proofs);
                    if let Some(next) = next_closer_name(qname, &closest) {
                        push_nsec3_cover(zone, &params, &next, &mut proofs);
                    }
                }
                push_nsec3_exact(zone, &params, wildcard, &mut proofs);
            } else {
                push_nsec3_exact(zone, &params, qname, &mut proofs);
            }
        }
        Status::Answer => {
            if let Some(wildcard) = &resolution.wildcard
                && let Some(closest) = wildcard.parent()
            {
                push_nsec3_exact(zone, &params, &closest, &mut proofs);
                if let Some(next) = next_closer_name(qname, &closest) {
                    push_nsec3_cover(zone, &params, &next, &mut proofs);
                }
            }
        }
        Status::Referral | Status::YxDomain => {}
    }
    resolution.authority.append(&mut proofs);
}

fn push_nsec3_exact(
    zone: &dyn ZoneView,
    params: &Nsec3Params,
    name: &Name,
    proofs: &mut Vec<Rrset>,
) {
    if let Some(exact) = zone.nsec3_at(&params.hash(name)) {
        push_proof(proofs, exact);
    }
}

fn push_nsec3_cover(
    zone: &dyn ZoneView,
    params: &Nsec3Params,
    name: &Name,
    proofs: &mut Vec<Rrset>,
) {
    if let Some(cover) = zone.nsec3_cover(&params.hash(name)) {
        push_proof(proofs, cover);
    }
}

/// Denial-запись, доказывающая отсутствие `DS` в точке делегирования.
fn denial_at(zone: &dyn ZoneView, name: &Name) -> Option<Rrset> {
    match zone.denial() {
        DenialKind::Nsec => zone.nsec_at(name),
        DenialKind::Nsec3 => {
            let params = nsec3_params(zone)?;
            zone.nsec3_at(&params.hash(name))
        }
    }
}

fn nsec3_params(zone: &dyn ZoneView) -> Option<Nsec3Params> {
    let param = zone.nsec3_param()?;
    let data = param.rdatas().iter().find_map(|rdata| match rdata {
        Rdata::Nsec3Param(data) => Some(data),
        _ => None,
    })?;
    Nsec3Params::from_nsec3param(data, DenialLimits::new()).ok()
}

/// Добавляет NSEC-доказательство к негативному или wildcard-ответу.
fn append_nsec_proofs(zone: &dyn ZoneView, qname: &Name, resolution: &mut Resolution) {
    let mut proofs: Vec<Rrset> = Vec::new();
    match resolution.status {
        Status::NxDomain => {
            if let Some(cover) = zone.nsec_cover(qname) {
                push_proof(&mut proofs, cover);
            }
            let closest = closest_encloser(zone, qname);
            if let Some(wildcard) = wildcard_name(&closest) {
                if let Some(exact) = zone.nsec_at(&wildcard) {
                    push_proof(&mut proofs, exact);
                } else if let Some(cover) = zone.nsec_cover(&wildcard) {
                    push_proof(&mut proofs, cover);
                }
            }
        }
        Status::NoData => {
            if let Some(wildcard) = &resolution.wildcard {
                if let Some(exact) = zone.nsec_at(wildcard) {
                    push_proof(&mut proofs, exact);
                }
                if let Some(cover) = zone.nsec_cover(qname) {
                    push_proof(&mut proofs, cover);
                }
            } else if let Some(exact) = zone.nsec_at(qname) {
                push_proof(&mut proofs, exact);
            }
        }
        Status::Answer => {
            if let Some(wildcard) = &resolution.wildcard
                && let Some(closest) = wildcard.parent()
                && let Some(next) = next_closer_name(qname, &closest)
                && let Some(cover) = zone.nsec_cover(&next)
            {
                push_proof(&mut proofs, cover);
            }
        }
        Status::Referral | Status::YxDomain => {}
    }
    resolution.authority.append(&mut proofs);
}

fn push_proof(proofs: &mut Vec<Rrset>, rrset: Rrset) {
    if proofs
        .iter()
        .any(|existing| existing.owner() == rrset.owner() && existing.rr_type() == rrset.rr_type())
    {
        return;
    }
    proofs.push(rrset);
}

/// Самый длинный существующий предок QNAME (включая apex).
fn closest_encloser(zone: &dyn ZoneView, qname: &Name) -> Name {
    let mut current = qname.parent();
    while let Some(name) = current {
        if zone.node_exists(&name) {
            return name;
        }
        if name == *zone.origin() {
            return name;
        }
        current = name.parent();
    }
    zone.origin().clone()
}

fn wildcard_name(parent: &Name) -> Option<Name> {
    let mut wire = Vec::with_capacity(parent.wire_len().saturating_add(2));
    wire.push(1);
    wire.push(b'*');
    wire.extend_from_slice(parent.as_wire());
    Name::from_wire(&wire).ok()
}

fn next_closer_name(qname: &Name, closest_encloser: &Name) -> Option<Name> {
    if !qname.is_subdomain_of(closest_encloser) || qname == closest_encloser {
        return None;
    }
    let mut current = qname.clone();
    while let Some(parent) = current.parent() {
        if parent == *closest_encloser {
            return Some(current);
        }
        current = parent;
    }
    None
}

/// Итог разбора внутри зоны.
#[derive(Debug)]
struct Resolution {
    status: Status,
    aa: bool,
    answers: Vec<Rrset>,
    authority: Vec<Rrset>,
    /// Wildcard-владелец, через который получен ответ/NODATA (для denial proof).
    wildcard: Option<Name>,
    /// Для ответа, развёрнутого из wildcard: подписи хранятся под wildcard
    /// владельцем, а отдаются под QNAME. Ключ — `(owner, type)` ответа.
    signature_sources: HashMap<(Name, Rtype), Name>,
}

impl Resolution {
    fn empty() -> Self {
        Self {
            status: Status::Answer,
            aa: true,
            answers: Vec::new(),
            authority: Vec::new(),
            wildcard: None,
            signature_sources: HashMap::new(),
        }
    }

    fn answer(rrset: Rrset) -> Self {
        Self {
            status: Status::Answer,
            aa: true,
            answers: vec![rrset],
            authority: Vec::new(),
            wildcard: None,
            signature_sources: HashMap::new(),
        }
    }

    fn no_data() -> Self {
        Self {
            status: Status::NoData,
            aa: true,
            answers: Vec::new(),
            authority: Vec::new(),
            wildcard: None,
            signature_sources: HashMap::new(),
        }
    }

    fn referral(ns: Rrset) -> Self {
        Self {
            status: Status::Referral,
            aa: false,
            answers: Vec::new(),
            authority: vec![ns],
            wildcard: None,
            signature_sources: HashMap::new(),
        }
    }
}

/// Терминальное состояние разбора.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Answer,
    NoData,
    NxDomain,
    Referral,
    YxDomain,
}

const fn status_rcode(status: Status) -> Rcode {
    match status {
        Status::Answer | Status::NoData | Status::Referral => Rcode::NOERROR,
        Status::NxDomain => Rcode::NXDOMAIN,
        Status::YxDomain => Rcode::YXDOMAIN,
    }
}

fn is_transfer_meta_qtype(qtype: Rtype) -> bool {
    matches!(
        qtype,
        Rtype::AXFR | Rtype::IXFR | Rtype::TKEY | Rtype::TSIG | Rtype::OPT
    )
}

fn referral_for(
    zone: &dyn ZoneView,
    qname: &Name,
    qtype: Rtype,
    do_bit: bool,
) -> Result<Option<Resolution>, QueryError> {
    let Some(cut) = find_delegation(zone, qname) else {
        return Ok(None);
    };
    if cut == *qname && qtype == Rtype::DS {
        return match zone.lookup(qname, Rtype::DS) {
            LookupOutcome::Answer(ds) => Ok(Some(Resolution::answer(ds))),
            LookupOutcome::NoData => Ok(Some(Resolution::no_data())),
            LookupOutcome::Cname(..)
            | LookupOutcome::NxDomain
            | LookupOutcome::Delegation { .. }
            | LookupOutcome::Referral
            | LookupOutcome::ZoneNotFound => Err(QueryError::InconsistentZone {
                zone: zone.origin().clone(),
                name: qname.clone(),
                rtype: Rtype::DS,
            }),
        };
    }
    match zone.lookup(&cut, Rtype::NS) {
        LookupOutcome::Delegation { ns, ds } => {
            let mut resolution = Resolution::referral(ns);
            if do_bit {
                if let Some(ds) = ds {
                    resolution.authority.push(ds);
                } else if zone.signed()
                    && let Some(proof) = denial_at(zone, &cut)
                {
                    // Insecure delegation: denial record at the cut proves
                    // DS absence (NSEC or NSEC3 depending on the zone).
                    resolution.authority.push(proof);
                }
            }
            Ok(Some(resolution))
        }
        LookupOutcome::Answer(_)
        | LookupOutcome::Cname(..)
        | LookupOutcome::NoData
        | LookupOutcome::NxDomain
        | LookupOutcome::Referral
        | LookupOutcome::ZoneNotFound => Err(QueryError::InconsistentZone {
            zone: zone.origin().clone(),
            name: cut,
            rtype: Rtype::NS,
        }),
    }
}

fn find_delegation(zone: &dyn ZoneView, name: &Name) -> Option<Name> {
    let mut current = Some(name.clone());
    while let Some(candidate) = current {
        if candidate == *zone.origin() {
            break;
        }
        if zone.is_delegation(&candidate) {
            return Some(candidate);
        }
        current = candidate.parent();
    }
    None
}

fn dname_redirect(zone: &dyn ZoneView, qname: &Name) -> Result<Option<(Rrset, Name)>, QueryError> {
    let mut current = qname.parent();
    while let Some(ancestor) = current {
        // INV-6 (`domain-model.md`): DNAME в apex запрещён, поэтому apex не
        // проверяется; `InMemoryZone` отвергает такую вставку. Имена выше
        // origin также не принадлежат зоне.
        if ancestor == *zone.origin() || !ancestor.is_subdomain_of(zone.origin()) {
            break;
        }
        match zone.lookup(&ancestor, Rtype::DNAME) {
            LookupOutcome::Answer(dname) => {
                let target = dname.rdatas().iter().find_map(|rdata| match rdata {
                    Rdata::Dname(name) => Some(name.clone()),
                    _ => None,
                });
                let Some(target) = target else {
                    return Err(QueryError::InconsistentZone {
                        zone: zone.origin().clone(),
                        name: ancestor,
                        rtype: Rtype::DNAME,
                    });
                };
                return Ok(Some((dname, target)));
            }
            LookupOutcome::NoData | LookupOutcome::NxDomain | LookupOutcome::Cname(..) => {}
            LookupOutcome::Delegation { .. }
            | LookupOutcome::Referral
            | LookupOutcome::ZoneNotFound => {
                return Err(QueryError::InconsistentZone {
                    zone: zone.origin().clone(),
                    name: ancestor,
                    rtype: Rtype::DNAME,
                });
            }
        }
        current = ancestor.parent();
    }
    Ok(None)
}

fn synthesize_hinfo(
    zone: &dyn ZoneView,
    qname: &Name,
    ttl: Ttl,
    resolution: &mut Resolution,
) -> Result<(), QueryError> {
    let rdata = Rdata::unknown(HINFO_TYPE, HINFO_RFC8482.to_vec())?;
    let hinfo = Rrset::new(qname.clone(), HINFO_TYPE, zone.class(), ttl, [rdata])?;
    resolution.answers.push(hinfo);
    resolution.status = Status::Answer;
    resolution.aa = true;
    Ok(())
}

fn wildcard_for(zone: &dyn ZoneView, qname: &Name) -> Option<Name> {
    let mut closest = None;
    let mut current = qname.parent();
    while let Some(candidate) = current {
        if zone.node_exists(&candidate) {
            closest = Some(candidate);
            break;
        }
        if candidate == *zone.origin() {
            break;
        }
        current = candidate.parent();
    }
    let closest = closest.or_else(|| {
        if zone.node_exists(zone.origin()) {
            Some(zone.origin().clone())
        } else {
            None
        }
    })?;
    let mut wire = Vec::with_capacity(closest.wire_len().saturating_add(2));
    wire.push(1);
    wire.push(b'*');
    wire.extend_from_slice(closest.as_wire());
    if wire.len() > MAX_NAME_WIRE_LEN {
        return None;
    }
    Name::from_wire(&wire).ok()
}

fn substitute_suffix(qname: &Name, owner: &Name, target: &Name) -> Option<Name> {
    let prefix_len = qname.label_count().checked_sub(owner.label_count())?;
    let mut wire = Vec::new();
    for (index, label) in qname.labels().enumerate() {
        if index >= prefix_len {
            break;
        }
        let length = u8::try_from(label.len()).ok()?;
        wire.push(length);
        wire.extend_from_slice(label);
    }
    wire.extend_from_slice(target.as_wire());
    if wire.len() > MAX_NAME_WIRE_LEN {
        return None;
    }
    Name::from_wire(&wire).ok()
}

fn reowner(rrset: &Rrset, owner: &Name) -> Result<Rrset, QueryError> {
    Ok(Rrset::new(
        owner.clone(),
        rrset.rr_type(),
        rrset.class(),
        rrset.ttl(),
        rrset.rdatas().iter().cloned(),
    )?)
}

fn append_negative_soa(zone: &dyn ZoneView, resolution: &mut Resolution) -> Result<(), QueryError> {
    let origin = zone.origin().clone();
    let soa = zone.soa().ok_or_else(|| QueryError::MissingSoa {
        zone: origin.clone(),
    })?;
    let minimum = soa.rdatas().iter().find_map(|rdata| match rdata {
        Rdata::Soa(data) => Some(data.minimum),
        _ => None,
    });
    let Some(minimum) = minimum else {
        return Err(QueryError::InconsistentZone {
            zone: origin,
            name: soa.owner().clone(),
            rtype: Rtype::SOA,
        });
    };
    let ttl = Ttl::new(soa.ttl().as_u32().min(minimum).min(NEGATIVE_TTL_CAP))?;
    let negative = Rrset::new(
        soa.owner().clone(),
        Rtype::SOA,
        soa.class(),
        ttl,
        soa.rdatas().iter().cloned(),
    )?;
    resolution.authority.push(negative);
    Ok(())
}

fn rrset_records(rrset: &Rrset) -> Result<Vec<Record>, QueryError> {
    let mut records = Vec::with_capacity(rrset.len());
    for rdata in rrset.rdatas() {
        records.push(Record::new(
            rrset.owner().clone(),
            rrset.rr_type(),
            rrset.class(),
            rrset.ttl(),
            rdata.clone(),
        )?);
    }
    Ok(records)
}

fn collect_targets(rrset: &Rrset, targets: &mut Vec<Name>) {
    match rrset.rr_type() {
        Rtype::NS => {
            for rdata in rrset.rdatas() {
                if let Rdata::Ns(name) = rdata {
                    targets.push(name.clone());
                }
            }
        }
        Rtype::MX => {
            for rdata in rrset.rdatas() {
                if let Rdata::Mx { exchange, .. } = rdata {
                    targets.push(exchange.clone());
                }
            }
        }
        Rtype::SRV => {
            for rdata in rrset.rdatas() {
                if let Rdata::Srv { target, .. } = rdata {
                    targets.push(target.clone());
                }
            }
        }
        Rtype::SVCB => {
            for rdata in rrset.rdatas() {
                if let Rdata::Svcb(data) = rdata {
                    targets.push(data.target().clone());
                }
            }
        }
        Rtype::HTTPS => {
            for rdata in rrset.rdatas() {
                if let Rdata::Https(data) = rdata {
                    targets.push(data.target().clone());
                }
            }
        }
        _ => {}
    }
}

fn negotiated_payload(edns: &Edns) -> u16 {
    edns.udp_payload_size()
        .clamp(UDP_PAYLOAD_WITHOUT_EDNS, MAX_UDP_PAYLOAD)
}

fn response_edns(request: &Edns) -> Edns {
    Edns::new(negotiated_payload(request))
        .with_version(0)
        .with_dnssec_ok(request.dnssec_ok())
}

fn truncate_to(message: &Message, limit: u16) -> Result<(Message, bool), QueryError> {
    let mut truncated = Message::new(message.id(), message.flags().with_tc(false));
    for question in message.questions() {
        truncated.add_question(question.clone());
    }
    truncated.set_edns(message.edns().cloned());
    if !fits(&truncated, limit)? {
        return Err(QueryError::BaseTooLarge { limit });
    }

    let mut overflow = false;
    for record in message.answers() {
        let mut candidate = truncated.clone();
        candidate.add_answer(record.clone());
        if fits(&candidate, limit)? {
            truncated = candidate;
        } else {
            overflow = true;
            break;
        }
    }
    if !overflow {
        for record in message.authority() {
            let mut candidate = truncated.clone();
            candidate.add_authority(record.clone());
            if fits(&candidate, limit)? {
                truncated = candidate;
            } else {
                overflow = true;
                break;
            }
        }
    }
    if !overflow {
        for group in additional_groups(message.additional()) {
            let mut candidate = truncated.clone();
            for record in group {
                candidate.add_additional(record);
            }
            if fits(&candidate, limit)? {
                truncated = candidate;
            } else {
                break;
            }
        }
    }
    if overflow {
        truncated.set_flags(truncated.flags().with_tc(true));
    }
    Ok((truncated, overflow))
}

/// Делит flat additional-секцию на последовательные RRset-группы.
fn additional_groups(records: &[Record]) -> Vec<Vec<Record>> {
    let mut groups: Vec<Vec<Record>> = Vec::new();
    for record in records {
        match groups.last_mut() {
            Some(group)
                if group.first().is_some_and(|first| {
                    first.owner() == record.owner() && first.rr_type() == record.rr_type()
                }) =>
            {
                group.push(record.clone());
            }
            _ => groups.push(vec![record.clone()]),
        }
    }
    groups
}

fn fits(message: &Message, limit: u16) -> Result<bool, QueryError> {
    match message.encode(&EncodeOptions::compressed()) {
        Ok(encoded) => Ok(encoded.len() <= usize::from(limit)),
        Err(EncodeError::MessageTooLong { .. }) => Ok(false),
        Err(error) => Err(QueryError::Encode(error)),
    }
}
