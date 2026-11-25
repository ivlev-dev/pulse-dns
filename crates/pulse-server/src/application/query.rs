//! Движок авторитетных запросов: разбор вопроса, композиция ответа, EDNS, усечение.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use pulse_dns::{
    Checkpoint, Edns, EncodeError, EncodeOptions, EncodeScratch, Encoder, Flags, HeaderCounts,
    MAX_MESSAGE_LEN, MAX_NAME_WIRE_LEN, Message, MessageRef, Name, Opcode, Rclass, Rcode, Rdata,
    RdataError, Record, RecordError, Rrset, RrsetError, Rtype, Ttl, TtlError, edns_wire_len,
};
use pulse_dnssec::{DenialLimits, Nsec3Params};
use thiserror::Error;

use super::port::ZoneView;
use super::stats::QueryStats;
use crate::domain::{DenialKind, LookupOutcome, LookupOutcomeRef, RdataRef, RrsetRef, ZoneState};

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

/// Переиспользуемое состояние построения ответа на поток.
///
/// Держите один экземпляр на worker-поток и передавайте его в
/// [`QueryEngine::respond_into`]: таблица компрессии и вспомогательные
/// коллекции (`visited`, `targets`, `seen`, `signatures`) не аллоцируются
/// заново на каждый запрос.
#[derive(Default)]
pub struct Scratch {
    encode: EncodeScratch,
    visited: Vec<Name>,
    targets: Vec<Name>,
    seen: HashSet<(Name, Rtype)>,
    signatures: HashSet<(Name, Rdata)>,
}

impl Scratch {
    /// Создаёт пустое состояние.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Сбрасывает состояние перед новым ответом.
    pub fn clear(&mut self) {
        self.encode.clear();
        self.visited.clear();
        self.targets.clear();
        self.seen.clear();
        self.signatures.clear();
    }
}

impl core::fmt::Debug for Scratch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Scratch")
            .field("visited", &self.visited.len())
            .field("targets", &self.targets.len())
            .finish_non_exhaustive()
    }
}

/// Результат потокового кодирования ответа.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodedResponse {
    /// Длина записанного сообщения в октетах.
    pub len: usize,
    /// Был ли ответ усечён по лимиту транспорта (`TC = 1`).
    pub truncated: bool,
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
    /// Индекс origin'ов по несжатой wire-форме имени: поиск зоны идёт по
    /// суффиксам QNAME без клонирования `Name`.
    zone_index: HashMap<Vec<u8>, usize>,
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
            zone_index.insert(zone.origin().as_wire().to_vec(), position);
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
                // Точная длина вместо полного кодирования в `Vec`: тот же
                // контракт (`MessageTooLong` при >65535), но без аллокации.
                message.encoded_len()?;
                Ok(message)
            }
        }
    }

    /// Полностью собирает и кодирует ответ прямо в `out`, без промежуточных
    /// [`Message`] и `Vec`.
    ///
    /// Внутренняя ошибка превращается в `SERVFAIL`, как и в
    /// [`QueryEngine::respond`].
    ///
    /// # Errors
    ///
    /// [`QueryError`], если не удалось записать даже `SERVFAIL` в `out`.
    pub fn respond_into(
        &self,
        request: &Message,
        transport: Transport,
        out: &mut [u8],
        scratch: &mut Scratch,
    ) -> Result<usize, QueryError> {
        if let Ok(response) = self.try_respond_into(request, transport, out, scratch) {
            return Ok(response.len);
        }
        self.stats.record_servfail();
        Self::error_into(request, Rcode::SERVFAIL, out, &mut scratch.encode).map(|r| r.len)
    }

    /// Zero-copy ответ на простой запрос [`MessageRef`].
    ///
    /// Обслуживает только горячий случай: один вопрос, без EDNS, `QTYPE =
    /// A/AAAA`, зона `Serving`, точное совпадение с RRset. Ответ кодируется
    /// прямо в `out` из заимствованных [`RrsetRef`] без `Message` и без
    /// материализации RRset. `None` означает «случай не горячий» — вызывающий
    /// обязан обработать пакет обычным путём через [`Message::decode`].
    #[must_use]
    pub fn respond_ref_into(
        &self,
        request: &MessageRef<'_>,
        transport: Transport,
        out: &mut [u8],
        scratch: &mut Scratch,
    ) -> Option<usize> {
        let qname = request.qname()?;
        let qtype = request.qtype();
        if !matches!(qtype, Rtype::A | Rtype::AAAA) {
            return None;
        }
        if request.qclass() != Rclass::IN {
            return None;
        }
        let zone = self.find_zone_wire(qname.as_wire())?;
        if zone.state() != ZoneState::Serving || zone.class() != Rclass::IN {
            return None;
        }
        if !qname.is_subdomain_of_name(zone.origin()) {
            return None;
        }

        let mut encoded = None;
        let snapshot_available = zone.with_snapshot(&mut |snapshot| {
            if let LookupOutcomeRef::Answer(rrset) = snapshot.lookup_ref(qname, qtype) {
                encoded = self.encode_ref_answer(request, rrset, transport, out, scratch);
            }
        });
        if !snapshot_available {
            return None;
        }
        if encoded.is_some() {
            self.stats.record_query();
        }
        encoded
    }

    /// Кодирует точный ответ из заимствованного RRset.
    fn encode_ref_answer(
        &self,
        request: &MessageRef<'_>,
        rrset: RrsetRef<'_>,
        transport: Transport,
        out: &mut [u8],
        scratch: &mut Scratch,
    ) -> Option<usize> {
        let qname = request.qname()?;
        let limit = match transport {
            Transport::Udp => usize::from(UDP_PAYLOAD_WITHOUT_EDNS),
            Transport::Tcp => MAX_MESSAGE_LEN,
        };
        let capacity = out.len().min(limit);
        let buffer = out.get_mut(..capacity)?;
        let flags = Flags::new()
            .with_qr(true)
            .with_opcode(Opcode::QUERY)
            .with_rd(request.flags().rd())
            .with_cd(request.flags().cd())
            .with_aa(true)
            .with_ra(false)
            .with_ad(false)
            .with_tc(false);
        let mut encoder = Encoder::new(buffer, EncodeOptions::compressed(), &mut scratch.encode);
        encoder.begin_message(request.id()).ok()?;
        encoder
            .write_question_wire(qname.as_wire(), request.qtype(), request.qclass())
            .ok()?;

        let owner = rrset.owner();
        let mut answers = 0_u16;
        let mut truncated = false;
        for rdata in rrset.records() {
            let checkpoint = encoder.checkpoint();
            let result = match rdata {
                RdataRef::Domain(rdata) => encoder.write_rr_wire_name(
                    owner.as_wire(),
                    rrset.rr_type(),
                    rrset.class(),
                    rrset.ttl(),
                    rdata,
                ),
                RdataRef::Wire { bytes, .. } => encoder.write_rr_raw(
                    owner.as_wire(),
                    rrset.rr_type(),
                    rrset.class(),
                    rrset.ttl(),
                    bytes,
                ),
            };
            match result {
                Ok(()) => answers = answers.saturating_add(1),
                Err(EncodeError::BufferTooSmall { .. }) if transport == Transport::Udp => {
                    encoder.rollback(checkpoint);
                    truncated = true;
                    break;
                }
                Err(_) => return None,
            }
        }
        let len = encoder
            .finish(
                flags.with_tc(truncated),
                HeaderCounts {
                    question: 1,
                    answer: answers,
                    authority: 0,
                    additional: 0,
                },
            )
            .ok()?;
        if truncated {
            self.stats.record_truncated();
        }
        Some(len)
    }

    /// Потоковая версия [`QueryEngine::try_respond`].
    ///
    /// Заголовок резервируется первым, записи пишутся в `out` по мере обхода
    /// секций; при усечении (UDP) непоместившаяся запись откатывается вместе
    /// со своими суффиксами компрессии. Для UDP `out` может быть равен
    /// согласованному payload, для TCP — до [`MAX_MESSAGE_LEN`].
    ///
    /// # Errors
    ///
    /// [`QueryError`], если данные зоны некорректны или ответ не кодируется.
    #[allow(clippy::too_many_lines)]
    pub fn try_respond_into(
        &self,
        request: &Message,
        transport: Transport,
        out: &mut [u8],
        scratch: &mut Scratch,
    ) -> Result<EncodedResponse, QueryError> {
        self.stats.record_query();

        if request.flags().qr() {
            self.stats.record_formerr();
            return Self::error_into(request, Rcode::FORMERR, out, &mut scratch.encode);
        }
        if request.opcode() != Opcode::QUERY {
            self.stats.record_notimp();
            return Self::error_into(request, Rcode::NOTIMP, out, &mut scratch.encode);
        }
        let Some(question) = request.questions().first() else {
            self.stats.record_formerr();
            return Self::error_into(request, Rcode::FORMERR, out, &mut scratch.encode);
        };
        if request.questions().len() != 1 {
            self.stats.record_formerr();
            return Self::error_into(request, Rcode::FORMERR, out, &mut scratch.encode);
        }
        if request.edns().is_some_and(|edns| edns.version() != 0) {
            self.stats.record_badvers();
            return Self::error_into(request, Rcode::BADVERS, out, &mut scratch.encode);
        }
        if is_transfer_meta_qtype(question.qtype()) {
            self.stats.record_notimp();
            return Self::error_into(request, Rcode::NOTIMP, out, &mut scratch.encode);
        }

        let qname = question.qname();
        let qtype = question.qtype();
        let Some(zone) = self.find_zone(qname) else {
            self.stats.record_refused();
            return Self::error_into(request, Rcode::REFUSED, out, &mut scratch.encode);
        };
        if zone.state() == ZoneState::Expired {
            self.stats.record_servfail();
            return Self::error_into(request, Rcode::SERVFAIL, out, &mut scratch.encode);
        }
        if zone.state() != ZoneState::Serving {
            self.stats.record_refused();
            return Self::error_into(request, Rcode::REFUSED, out, &mut scratch.encode);
        }
        let qclass = question.qclass();
        if qclass != zone.class() && qclass != Rclass::ANY {
            self.stats.record_refused();
            return Self::error_into(request, Rcode::REFUSED, out, &mut scratch.encode);
        }

        let do_bit = request.edns().is_some_and(Edns::dnssec_ok);
        let resolution = self.resolve_with(zone, qname, qtype, do_bit, &mut scratch.visited)?;
        match resolution.status {
            Status::NxDomain => self.stats.record_nxdomain(),
            Status::NoData => self.stats.record_nodata(),
            Status::Answer | Status::Referral | Status::YxDomain => {}
        }

        let rcode = status_rcode(resolution.status);
        let flags = Flags::new()
            .with_qr(true)
            .with_opcode(request.opcode())
            .with_rd(request.flags().rd())
            .with_cd(request.flags().cd())
            .with_aa(resolution.aa)
            .with_ra(false)
            .with_ad(false)
            .with_tc(false)
            .with_rcode_bits(rcode.header_bits());
        let response_edns = request.edns().map(response_edns);
        let opt_len = match &response_edns {
            Some(edns) => edns_wire_len(edns)?,
            None => 0,
        };
        let limit = match transport {
            Transport::Udp => usize::from(
                request
                    .edns()
                    .map_or(UDP_PAYLOAD_WITHOUT_EDNS, negotiated_payload),
            ),
            Transport::Tcp => MAX_MESSAGE_LEN,
        };
        let capacity = out.len().min(limit);
        let question_count = u16::try_from(request.questions().len()).unwrap_or(u16::MAX);
        let Some(buffer) = out.get_mut(..capacity) else {
            return Err(QueryError::Encode(EncodeError::Internal {
                reason: "response buffer range",
            }));
        };
        let mut encoder = Encoder::new(buffer, EncodeOptions::compressed(), &mut scratch.encode);
        encoder.begin_message(request.id())?;
        for question in request.questions() {
            encoder.write_question(question)?;
        }
        if encoder.len().saturating_add(opt_len) > capacity {
            return Err(QueryError::BaseTooLarge {
                limit: u16::try_from(capacity).unwrap_or(u16::MAX),
            });
        }
        let budget = match transport {
            Transport::Udp => capacity.saturating_sub(opt_len),
            Transport::Tcp => capacity,
        };

        let mut sink = WireSink::new(encoder, transport, budget);
        walk_response(
            zone,
            &resolution,
            do_bit,
            &mut sink,
            &mut scratch.targets,
            &mut scratch.seen,
            &mut scratch.signatures,
        )?;
        let truncated = sink.truncated;
        let answer_count = sink.answer_count;
        let authority_count = sink.authority_count;
        let additional_count = sink.additional_count;
        let mut encoder = sink.into_encoder();
        if let Some(edns) = &response_edns {
            encoder.write_edns(edns)?;
        }
        let additional = additional_count.saturating_add(u16::from(response_edns.is_some()));
        let len = encoder.finish(
            flags.with_tc(truncated),
            HeaderCounts {
                question: question_count,
                answer: answer_count,
                authority: authority_count,
                additional,
            },
        )?;
        if truncated {
            self.stats.record_truncated();
        }
        Ok(EncodedResponse { len, truncated })
    }

    fn error_into(
        request: &Message,
        rcode: Rcode,
        out: &mut [u8],
        scratch: &mut EncodeScratch,
    ) -> Result<EncodedResponse, QueryError> {
        let flags = Flags::new()
            .with_qr(true)
            .with_opcode(request.opcode())
            .with_rd(request.flags().rd())
            .with_cd(request.flags().cd())
            .with_ra(false)
            .with_aa(false)
            .with_tc(false)
            .with_rcode_bits(rcode.header_bits());
        let edns = request
            .edns()
            .map(|edns| response_edns(edns).with_extended_rcode(rcode.extended_bits()));
        let question_count = u16::from(!request.questions().is_empty());
        let additional = u16::from(edns.is_some());
        let mut encoder = Encoder::new(out, EncodeOptions::compressed(), scratch);
        encoder.begin_message(request.id())?;
        if let Some(question) = request.questions().first() {
            encoder.write_question(question)?;
        }
        if let Some(edns) = &edns {
            encoder.write_edns(edns)?;
        }
        let len = encoder.finish(
            flags,
            HeaderCounts {
                question: question_count,
                answer: 0,
                authority: 0,
                additional,
            },
        )?;
        Ok(EncodedResponse {
            len,
            truncated: false,
        })
    }

    fn find_zone(&self, qname: &Name) -> Option<&dyn ZoneView> {
        self.find_zone_wire(qname.as_wire())
    }

    fn find_zone_wire(&self, wire: &[u8]) -> Option<&dyn ZoneView> {
        let mut position = 0_usize;
        loop {
            let suffix = wire.get(position..)?;
            if let Some(&index) = self.zone_index.get(suffix) {
                return self.zones.get(index).map(AsRef::as_ref);
            }
            let length = *suffix.first()?;
            if length == 0 {
                return None;
            }
            position = position.checked_add(1 + usize::from(length))?;
        }
    }

    fn resolve(
        &self,
        zone: &dyn ZoneView,
        qname: &Name,
        qtype: Rtype,
        do_bit: bool,
    ) -> Result<Resolution, QueryError> {
        let mut visited = Vec::new();
        self.resolve_with(zone, qname, qtype, do_bit, &mut visited)
    }

    fn resolve_with(
        &self,
        zone: &dyn ZoneView,
        qname: &Name,
        qtype: Rtype,
        do_bit: bool,
        visited: &mut Vec<Name>,
    ) -> Result<Resolution, QueryError> {
        visited.clear();
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
        self.resolve_name(zone, qname, qtype, 0, visited, &mut resolution)?;
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
        let mut targets = Vec::new();
        let mut seen = HashSet::new();
        let mut signatures = HashSet::new();
        let mut sink = MessageSink { message };
        walk_response(
            zone,
            resolution,
            do_bit,
            &mut sink,
            &mut targets,
            &mut seen,
            &mut signatures,
        )
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

/// Продолжать ли обход после текущей записи.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flow {
    Continue,
    Stop,
}

/// Приёмник записей ответа: либо в [`Message`], либо сразу в wire-буфер.
trait RecordSink {
    fn push(
        &mut self,
        section: Section,
        owner: &Name,
        rr_type: Rtype,
        class: Rclass,
        ttl: Ttl,
        rdata: &Rdata,
    ) -> Result<Flow, QueryError>;
}

/// Приёмник для прежнего API [`QueryEngine::respond`] (собирает [`Message`]).
struct MessageSink<'a> {
    message: &'a mut Message,
}

impl RecordSink for MessageSink<'_> {
    fn push(
        &mut self,
        section: Section,
        owner: &Name,
        rr_type: Rtype,
        class: Rclass,
        ttl: Ttl,
        rdata: &Rdata,
    ) -> Result<Flow, QueryError> {
        let record = Record::new(owner.clone(), rr_type, class, ttl, rdata.clone())?;
        section.add(self.message, record);
        Ok(Flow::Continue)
    }
}

/// Приёмник для [`QueryEngine::respond_into`]: пишет прямо в буфер и
/// откатывает записи, не поместившиеся в лимит UDP.
struct WireSink<'a> {
    encoder: Encoder<'a>,
    transport: Transport,
    budget: usize,
    truncated: bool,
    group_start: Checkpoint,
    group_key: Option<(Name, Rtype)>,
    answer_count: u16,
    authority_count: u16,
    additional_count: u16,
}

impl<'a> WireSink<'a> {
    fn new(encoder: Encoder<'a>, transport: Transport, budget: usize) -> Self {
        let group_start = encoder.checkpoint();
        Self {
            encoder,
            transport,
            budget,
            truncated: false,
            group_start,
            group_key: None,
            answer_count: 0,
            authority_count: 0,
            additional_count: 0,
        }
    }

    fn into_encoder(self) -> Encoder<'a> {
        self.encoder
    }
}

impl RecordSink for WireSink<'_> {
    fn push(
        &mut self,
        section: Section,
        owner: &Name,
        rr_type: Rtype,
        class: Rclass,
        ttl: Ttl,
        rdata: &Rdata,
    ) -> Result<Flow, QueryError> {
        let checkpoint = self.encoder.checkpoint();
        if section == Section::Additional {
            // Усечение additional — по группам `(owner, type)`.
            let same_group = self
                .group_key
                .as_ref()
                .is_some_and(|(name, ty)| name == owner && *ty == rr_type);
            if !same_group {
                self.group_key = Some((owner.clone(), rr_type));
                self.group_start = checkpoint;
            }
        }
        let rollback_to = if section == Section::Additional {
            self.group_start
        } else {
            checkpoint
        };
        match self.encoder.write_rr(owner, rr_type, class, ttl, rdata) {
            Ok(()) => {}
            Err(EncodeError::BufferTooSmall { .. }) if self.transport == Transport::Udp => {
                self.encoder.rollback(rollback_to);
                if section != Section::Additional {
                    self.truncated = true;
                }
                return Ok(Flow::Stop);
            }
            Err(error) => return Err(QueryError::Encode(error)),
        }
        if self.transport == Transport::Udp && self.encoder.len() > self.budget {
            self.encoder.rollback(rollback_to);
            if section != Section::Additional {
                self.truncated = true;
            }
            return Ok(Flow::Stop);
        }
        match section {
            Section::Answer => self.answer_count = self.answer_count.saturating_add(1),
            Section::Authority => {
                self.authority_count = self.authority_count.saturating_add(1);
            }
            Section::Additional => {
                self.additional_count = self.additional_count.saturating_add(1);
            }
        }
        Ok(Flow::Continue)
    }
}

/// Обходит секции ответа в wire-порядке: answer, authority, additional/glue.
///
/// Логика композиции (RRSIG, dedup, сортировка glue) общая для [`Message`] и
/// потокового энкодера; различается только приёмник записей.
fn walk_response(
    zone: &dyn ZoneView,
    resolution: &Resolution,
    do_bit: bool,
    sink: &mut dyn RecordSink,
    targets: &mut Vec<Name>,
    seen: &mut HashSet<(Name, Rtype)>,
    signatures: &mut HashSet<(Name, Rdata)>,
) -> Result<(), QueryError> {
    let signed = do_bit && zone.signed();
    signatures.clear();
    targets.clear();
    seen.clear();

    for rrset in &resolution.answers {
        let source = resolution
            .signature_sources
            .get(&(rrset.owner().clone(), rrset.rr_type()))
            .unwrap_or(rrset.owner());
        if append_rrset(
            sink,
            zone,
            rrset,
            Section::Answer,
            signed,
            Some(source),
            signatures,
        )? == Flow::Stop
        {
            return Ok(());
        }
    }
    for rrset in &resolution.authority {
        if append_rrset(
            sink,
            zone,
            rrset,
            Section::Authority,
            signed,
            None,
            signatures,
        )? == Flow::Stop
        {
            return Ok(());
        }
    }

    for rrset in &resolution.answers {
        collect_targets(rrset, targets);
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

    for rrset in resolution.answers.iter().chain(resolution.authority.iter()) {
        seen.insert((rrset.owner().clone(), rrset.rr_type()));
    }

    for target in targets.iter() {
        for glue in zone.glue(target) {
            let key = (glue.owner().clone(), glue.rr_type());
            if !seen.insert(key) {
                continue;
            }
            if append_rrset(
                sink,
                zone,
                &glue,
                Section::Additional,
                signed,
                None,
                signatures,
            )? == Flow::Stop
            {
                return Ok(());
            }
        }
    }
    Ok(())
}

/// Добавляет RRset и (при `DO = 1`) его `RRSIG`.
///
/// `signature_owner` задаёт имя, под которым подписи хранятся в зоне; для
/// wildcard-развёрнутого ответа это `*.closest-encloser`, а записи
/// переименовываются в QNAME (RFC 4035 §5.3.2).
fn append_rrset(
    sink: &mut dyn RecordSink,
    zone: &dyn ZoneView,
    rrset: &Rrset,
    section: Section,
    signed: bool,
    signature_owner: Option<&Name>,
    signatures: &mut HashSet<(Name, Rdata)>,
) -> Result<Flow, QueryError> {
    for rdata in rrset.rdatas() {
        if sink.push(
            section,
            rrset.owner(),
            rrset.rr_type(),
            rrset.class(),
            rrset.ttl(),
            rdata,
        )? == Flow::Stop
        {
            return Ok(Flow::Stop);
        }
    }
    if !signed || rrset.rr_type() == Rtype::RRSIG {
        return Ok(Flow::Continue);
    }
    let source = signature_owner.unwrap_or_else(|| rrset.owner());
    for signatures_rrset in zone.lookup_all_rrsig(source, rrset.rr_type()) {
        let signatures_rrset = if source == rrset.owner() {
            signatures_rrset
        } else {
            reowner(&signatures_rrset, rrset.owner())?
        };
        for rdata in signatures_rrset.rdatas() {
            let key = (signatures_rrset.owner().clone(), rdata.clone());
            if signatures.insert(key)
                && sink.push(
                    section,
                    signatures_rrset.owner(),
                    signatures_rrset.rr_type(),
                    signatures_rrset.class(),
                    signatures_rrset.ttl(),
                    rdata,
                )? == Flow::Stop
            {
                return Ok(Flow::Stop);
            }
        }
    }
    Ok(Flow::Continue)
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
                if proofs.is_empty() {
                    // Opt-Out: DS-NODATA в insecure-делегировании не имеет
                    // точного NSEC3; доказываем CE + покрытием имени.
                    let closest = closest_encloser(zone, qname);
                    push_nsec3_exact(zone, &params, &closest, &mut proofs);
                    push_nsec3_cover(zone, &params, qname, &mut proofs);
                }
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
        Status::Referral | Status::YxDomain => {
            if resolution.status == Status::Referral
                && let Some(cut) = resolution
                    .authority
                    .iter()
                    .find(|rrset| rrset.rr_type() == Rtype::NS)
                    .map(Rrset::owner)
            {
                // Opt-Out: у insecure-делегирования нет точного NSEC3.
                // Доказываем отсутствие DS closest-encloser + покрытием cut.
                let closest = closest_encloser(zone, cut);
                push_nsec3_exact(zone, &params, &closest, &mut proofs);
                push_nsec3_cover(zone, &params, cut, &mut proofs);
            }
        }
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
    // Точная длина без записи байтов: усечение больше не аллоцирует `Vec`
    // на каждую пробную запись.
    match message.encoded_len() {
        Ok(len) => Ok(len <= usize::from(limit)),
        Err(EncodeError::MessageTooLong { .. }) => Ok(false),
        Err(error) => Err(QueryError::Encode(error)),
    }
}
