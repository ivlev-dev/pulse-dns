//! Движок авторитетных запросов: разбор вопроса, композиция ответа, EDNS, усечение.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use pulse_dns::{
    Checkpoint, Edns, EncodeError, EncodeOptions, EncodeScratch, Encoder, Flags, HeaderCounts,
    MAX_LABELS, MAX_MESSAGE_LEN, MAX_NAME_WIRE_LEN, Message, MessageRef, Name, NameRef, Opcode,
    Rclass, Rcode, Rdata, RdataError, Record, RecordError, Rrset, RrsetError, Rtype, Ttl, TtlError,
    edns_wire_len,
};
use pulse_dnssec::rdata_util::{NSEC3_SHA1_LEN, nsec3_hash_into};
use pulse_dnssec::{DenialLimits, Nsec3Params};
use thiserror::Error;

use super::port::{ZoneSnapshot, ZoneView};
use super::stats::QueryStats;
use crate::domain::{
    DenialKind, LookupOutcome, LookupOutcomeRef, RdataRef, RefLookup, RrsetRef, ZoneState,
};

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
    /// Обслуживает горячий путь авторитетного ответа без `Message`, без
    /// материализации RRset и без аллокаций:
    ///
    /// * точное совпадение `A`/`AAAA`/`MX`/`TXT`/`SRV`/`CNAME`/`NS` и других
    ///   типов (включая additional-glue для `MX`/`SRV`/`NS`/`SVCB`/`HTTPS`);
    /// * `CNAME`-цепочка в зоне до [`MAX_CNAME_CHAIN`] звеньев;
    /// * `NXDOMAIN`/`NODATA` с `SOA` и negative TTL из заимствованных данных;
    /// * wildcard-развёртывание, включая wildcard `CNAME`;
    /// * подписанные ответы (`DO = 1`): `RRSIG` из refs, `NSEC`/`NSEC3`
    ///   denial-доказательства из индексов зоны;
    /// * referral: `NS`/`DS`/`NSEC3` Opt-Out и glue в bailiwick, `AA = 0`;
    /// * `QTYPE = ANY`: `HINFO`-синтез по RFC 8482 и `CNAME` владельца;
    /// * EDNS0 (версия 0): OPT повторяется (включая `DO`), payload
    ///   ограничивает ответ, `TC` выставляется по тем же правилам, что и в
    ///   полном пути.
    ///
    /// `DNAME` выше `QNAME` (синтез `CNAME` и продолжение цепочки), циклы
    /// `CNAME`/`DNAME` (SERVFAIL) и `YXDOMAIN` обслуживаются здесь же.
    /// Неподдерживаемые представления данных (например, `OVERFLOW`-payload
    /// зоны v2, требующий материализации нескольких страниц) и прочие
    /// не-горячие случаи остаются на полном пути. `None` означает «случай не
    /// горячий» — вызывающий обязан обработать пакет обычным путём.
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
        if is_transfer_meta_qtype(qtype) {
            return None;
        }
        if request.qclass() != Rclass::IN {
            return None;
        }
        let request_edns = request.edns();
        if request_edns.is_some_and(|edns| edns.version() != 0) {
            return None;
        }
        let zone = self.find_zone_wire(qname.as_wire())?;
        if zone.state() != ZoneState::Serving || zone.class() != Rclass::IN {
            return None;
        }
        if !qname.is_subdomain_of_name(zone.origin()) {
            return None;
        }
        let response_edns = request_edns.map(|edns| {
            Edns::new(negotiated_payload_size(edns.udp_payload_size()))
                .with_version(0)
                .with_dnssec_ok(edns.dnssec_ok())
        });

        let mut encoded = None;
        let available = zone.with_snapshot(&mut |snapshot| {
            encoded = Self::encode_fast(
                request,
                snapshot,
                transport,
                out,
                scratch,
                response_edns.as_ref(),
                self.config.any_hinfo_ttl,
            );
        });
        if !available {
            return None;
        }
        let response = encoded?;
        self.stats.record_query();
        match response.status {
            FastStatus::NxDomain => self.stats.record_nxdomain(),
            FastStatus::NoData => self.stats.record_nodata(),
            FastStatus::ServFail => self.stats.record_servfail(),
            FastStatus::Answer | FastStatus::Referral | FastStatus::YxDomain => {}
        }
        if response.truncated {
            self.stats.record_truncated();
        }
        Some(response.len)
    }

    /// Собирает и кодирует ответ по заимствованному снимку зоны.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn encode_fast<'a>(
        request: &'a MessageRef<'_>,
        snapshot: &'a dyn ZoneSnapshot,
        transport: Transport,
        out: &'a mut [u8],
        scratch: &'a mut Scratch,
        response_edns: Option<&Edns>,
        hinfo_ttl: Ttl,
    ) -> Option<FastResponse> {
        let qname = request.qname()?;
        let qtype = request.qtype();
        let origin = snapshot.origin_ref();
        if !qname.is_subdomain_of(origin) {
            return None;
        }
        let do_bit = response_edns.is_some_and(Edns::dnssec_ok);
        let signed = do_bit && snapshot.signed_ref();

        let mut wildcard_wire = [0_u8; MAX_NAME_WIRE_LEN];
        let mut synth_storage = [[0_u8; MAX_NAME_WIRE_LEN]; MAX_CNAME_CHAIN];
        let mut synth_pool = NameBufferPool::new(&mut synth_storage);
        let mut plan = FastPlan::new();
        match resolve_fast(
            snapshot,
            qname,
            qtype,
            origin,
            &mut wildcard_wire,
            &mut synth_pool,
            hinfo_ttl,
            &mut plan,
        )? {
            ResolveOutcome::Done => {}
            ResolveOutcome::ServFail => {
                return Self::encode_fast_error(
                    request,
                    qname,
                    qtype,
                    transport,
                    out,
                    scratch,
                    response_edns,
                    Rcode::SERVFAIL,
                );
            }
        }

        let mut targets = NameSlots::new();
        for entry in plan.answers.iter().take(plan.answer_len).flatten() {
            if let FastAnswerData::Ref(rrset) = entry.data {
                add_targets(rrset, &mut targets)?;
            }
        }
        let mut glue_targets = NameSlots::new();
        for index in 0..targets.len {
            let &target = targets.items.get(index)?;
            if target.is_subdomain_of(origin)
                && !delegation_above(snapshot, target, origin)
                && !glue_targets.push(target)
            {
                return None;
            }
        }
        if let Some(referral) = plan.referral {
            let mut referral_targets = NameSlots::new();
            add_targets(referral.ns, &mut referral_targets)?;
            for index in 0..referral_targets.len {
                let &target = referral_targets.items.get(index)?;
                if !target.is_subdomain_of(origin) {
                    continue;
                }
                // Bailiwick: glue допустим для имён вне cut или в этом же cut.
                let in_bailiwick = match find_delegation_ref(snapshot, target, origin) {
                    None => true,
                    Some(found) => found.as_wire() == referral.cut.as_wire(),
                };
                if in_bailiwick && !glue_targets.push(target) {
                    return None;
                }
            }
        }
        glue_targets.sort_dedup();

        let limit = match transport {
            Transport::Udp => {
                usize::from(response_edns.map_or(UDP_PAYLOAD_WITHOUT_EDNS, negotiated_payload))
            }
            Transport::Tcp => MAX_MESSAGE_LEN,
        };
        let capacity = out.len().min(limit);
        let opt_len = match response_edns {
            Some(edns) => edns_wire_len(edns).ok()?,
            None => 0,
        };
        let buffer = out.get_mut(..capacity)?;
        let rcode = match plan.status {
            FastStatus::NxDomain => Rcode::NXDOMAIN,
            FastStatus::YxDomain => Rcode::YXDOMAIN,
            FastStatus::Answer | FastStatus::NoData | FastStatus::Referral => Rcode::NOERROR,
            FastStatus::ServFail => Rcode::SERVFAIL,
        };
        let flags = Flags::new()
            .with_qr(true)
            .with_opcode(Opcode::QUERY)
            .with_rd(request.flags().rd())
            .with_cd(request.flags().cd())
            .with_aa(plan.aa)
            .with_ra(false)
            .with_ad(false)
            .with_tc(false)
            .with_rcode_bits(rcode.header_bits());
        let mut encoder = Encoder::new(buffer, EncodeOptions::compressed(), &mut scratch.encode);
        encoder.begin_message(request.id()).ok()?;
        encoder
            .write_question_wire(qname.as_wire(), qtype, request.qclass())
            .ok()?;
        if encoder.len().saturating_add(opt_len) > capacity {
            return None;
        }
        let budget = match transport {
            Transport::Udp => capacity.saturating_sub(opt_len),
            Transport::Tcp => capacity,
        };
        let mut counts = FastCounts::default();
        let mut truncated = false;
        let mut stopped = false;

        for entry in plan.answers.iter().take(plan.answer_len).flatten() {
            if stopped {
                break;
            }
            let flow = match entry.data {
                FastAnswerData::Ref(rrset) => write_fast_group(
                    &mut encoder,
                    transport,
                    budget,
                    &mut truncated,
                    Section::Answer,
                    entry.owner,
                    rrset,
                    None,
                    None,
                    &mut counts,
                ),
                FastAnswerData::DnameCname { dname } => write_fast_dname_cname(
                    &mut encoder,
                    transport,
                    budget,
                    &mut truncated,
                    entry.owner,
                    dname,
                    snapshot.class_ref(),
                    &mut counts,
                ),
                FastAnswerData::Hinfo { ttl } => write_fast_hinfo(
                    &mut encoder,
                    transport,
                    budget,
                    &mut truncated,
                    entry.owner,
                    ttl,
                    &mut counts,
                ),
            }
            .ok()?;
            if flow == Flow::Stop {
                stopped = true;
                break;
            }
            if signed {
                let source = entry.sig_source.unwrap_or(entry.owner);
                let flow = write_signature_fast(
                    snapshot,
                    &mut encoder,
                    transport,
                    budget,
                    &mut truncated,
                    Section::Answer,
                    entry.owner,
                    entry.rr_type(),
                    source,
                    &mut counts,
                )?;
                if flow == Flow::Stop {
                    stopped = true;
                }
            }
        }
        if !stopped {
            stopped = write_authority_fast(
                snapshot,
                &mut encoder,
                transport,
                budget,
                &mut truncated,
                &mut counts,
                &plan,
                signed,
                do_bit,
                qname,
                origin,
            )? == Flow::Stop;
        }
        if !stopped {
            'glue: for target in glue_targets.iter() {
                for rr_type in [Rtype::A, Rtype::AAAA] {
                    let rrset = match snapshot.glue_at_ref(target, rr_type) {
                        RefLookup::Found(rrset) => rrset,
                        RefLookup::Absent => continue,
                        RefLookup::Unsupported => return None,
                    };
                    let already = plan.answers.iter().take(plan.answer_len).flatten().any(
                        |entry| match entry.data {
                            FastAnswerData::Ref(answer) => {
                                answer.owner().as_wire() == rrset.owner().as_wire()
                                    && answer.rr_type() == rrset.rr_type()
                            }
                            FastAnswerData::DnameCname { .. } | FastAnswerData::Hinfo { .. } => {
                                false
                            }
                        },
                    );
                    if already {
                        continue;
                    }
                    let flow = write_fast_group(
                        &mut encoder,
                        transport,
                        budget,
                        &mut truncated,
                        Section::Additional,
                        rrset.owner(),
                        rrset,
                        None,
                        None,
                        &mut counts,
                    )
                    .ok()?;
                    if flow == Flow::Stop {
                        break 'glue;
                    }
                    if signed {
                        let flow = write_signature_fast(
                            snapshot,
                            &mut encoder,
                            transport,
                            budget,
                            &mut truncated,
                            Section::Additional,
                            rrset.owner(),
                            rrset.rr_type(),
                            rrset.owner(),
                            &mut counts,
                        )?;
                        if flow == Flow::Stop {
                            break 'glue;
                        }
                    }
                }
            }
        }

        if let Some(edns) = response_edns {
            encoder.write_edns(edns).ok()?;
        }
        let additional = counts
            .additional
            .saturating_add(u16::from(response_edns.is_some()));
        let len = encoder
            .finish(
                flags.with_tc(truncated),
                HeaderCounts {
                    question: 1,
                    answer: counts.answer,
                    authority: counts.authority,
                    additional,
                },
            )
            .ok()?;
        Some(FastResponse {
            len,
            status: plan.status,
            truncated,
        })
    }

    /// Кодирует ошибочный ответ (`SERVFAIL`) в том же виде, что и полный путь.
    ///
    /// Используется для цикла `CNAME`/`DNAME`: ответ не содержит answer, но
    /// содержит вопрос и эхо `OPT`, поэтому байты совпадают с `error_into`.
    #[allow(clippy::too_many_arguments)]
    fn encode_fast_error(
        request: &MessageRef<'_>,
        qname: NameRef<'_>,
        qtype: Rtype,
        transport: Transport,
        out: &mut [u8],
        scratch: &mut Scratch,
        response_edns: Option<&Edns>,
        rcode: Rcode,
    ) -> Option<FastResponse> {
        let limit = match transport {
            Transport::Udp => {
                usize::from(response_edns.map_or(UDP_PAYLOAD_WITHOUT_EDNS, negotiated_payload))
            }
            Transport::Tcp => MAX_MESSAGE_LEN,
        };
        let capacity = out.len().min(limit);
        let buffer = out.get_mut(..capacity)?;
        let flags = Flags::new()
            .with_qr(true)
            .with_opcode(Opcode::QUERY)
            .with_rd(request.flags().rd())
            .with_cd(request.flags().cd())
            .with_aa(false)
            .with_ra(false)
            .with_ad(false)
            .with_tc(false)
            .with_rcode_bits(rcode.header_bits());
        let mut encoder = Encoder::new(buffer, EncodeOptions::compressed(), &mut scratch.encode);
        encoder.begin_message(request.id()).ok()?;
        encoder
            .write_question_wire(qname.as_wire(), qtype, request.qclass())
            .ok()?;
        if let Some(edns) = response_edns {
            encoder.write_edns(edns).ok()?;
        }
        let len = encoder
            .finish(
                flags,
                HeaderCounts {
                    question: 1,
                    answer: 0,
                    authority: 0,
                    additional: u16::from(response_edns.is_some()),
                },
            )
            .ok()?;
        Some(FastResponse {
            len,
            status: FastStatus::ServFail,
            truncated: false,
        })
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

/// Максимум записей ответа в быстром пути: цепочка `CNAME`/`DNAME` + финальный
/// RRset. Шаг `DNAME` добавляет две записи (`DNAME` и синтезированный `CNAME`).
const FAST_ANSWER_SLOTS: usize = 2 * MAX_CNAME_CHAIN + 1;
/// Максимум целей additional, обрабатываемых без аллокаций.
const FAST_TARGET_SLOTS: usize = 16;
/// Максимум proof-владельцев, запоминаемых для dedup в быстром пути.
const FAST_PROOF_SLOTS: usize = 4;
/// Корневое имя как значение-заглушка для стековых массивов [`NameRef`].
const ROOT_NAME: NameRef<'static> = NameRef::from_validated(&[0]);

/// Итог быстрого разбора.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FastStatus {
    Answer,
    NoData,
    NxDomain,
    YxDomain,
    Referral,
    /// Цикл `CNAME`/`DNAME`: ответ `SERVFAIL` без answer.
    ServFail,
}

/// Источник записей ответа в быстром пути.
#[derive(Debug, Clone, Copy)]
enum FastAnswerData<'a> {
    /// Заимствованный RRset зоны.
    Ref(RrsetRef<'a>),
    /// `CNAME`, синтезированный из `DNAME` (RFC 6672). Цель строится из
    /// `owner` и RDATA `DNAME` при кодировании, без материализации RRset.
    DnameCname {
        /// `DNAME`-набор, из которого синтезируется `CNAME`.
        dname: RrsetRef<'a>,
    },
    /// Синтезированный `HINFO` для `QTYPE = ANY` (RFC 8482).
    Hinfo {
        /// TTL синтезированной записи.
        ttl: Ttl,
    },
}

impl FastAnswerData<'_> {
    const fn rr_type(self) -> Rtype {
        match self {
            Self::Ref(rrset) => rrset.rr_type(),
            Self::DnameCname { .. } => Rtype::CNAME,
            Self::Hinfo { .. } => HINFO_TYPE,
        }
    }
}

/// Запись ответа с возможным переименованием владельца (wildcard).
#[derive(Debug, Clone, Copy)]
struct FastAnswer<'a> {
    owner: NameRef<'a>,
    data: FastAnswerData<'a>,
    /// Имя, под которым хранятся подписи: wildcard-владелец для
    /// развёрнутого ответа. `None` — подписи под владельцем набора.
    sig_source: Option<NameRef<'a>>,
}

impl FastAnswer<'_> {
    const fn rr_type(self) -> Rtype {
        self.data.rr_type()
    }
}

/// Referral-план: `NS`/`DS` и точка cut из refs.
#[derive(Debug, Clone, Copy)]
struct FastReferral<'a> {
    cut: NameRef<'a>,
    ns: RrsetRef<'a>,
    ds: Option<RrsetRef<'a>>,
}

/// Собранный план быстрого ответа.
struct FastPlan<'a> {
    answers: [Option<FastAnswer<'a>>; FAST_ANSWER_SLOTS],
    answer_len: usize,
    status: FastStatus,
    aa: bool,
    needs_soa: bool,
    referral: Option<FastReferral<'a>>,
    /// Wildcard-владелец для denial-доказательств.
    wildcard: Option<NameRef<'a>>,
}

impl<'a> FastPlan<'a> {
    const fn new() -> Self {
        Self {
            answers: [None; FAST_ANSWER_SLOTS],
            answer_len: 0,
            status: FastStatus::Answer,
            aa: true,
            needs_soa: false,
            referral: None,
            wildcard: None,
        }
    }

    /// Добавляет запись ответа; `None` — переполнение (полный путь).
    fn push(&mut self, answer: FastAnswer<'a>) -> Option<()> {
        *self.answers.get_mut(self.answer_len)? = Some(answer);
        self.answer_len = self.answer_len.checked_add(1)?;
        Some(())
    }
}

/// Результат кодирования быстрого пути.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FastResponse {
    len: usize,
    status: FastStatus,
    truncated: bool,
}

/// Счётчики записанных записей по секциям.
#[derive(Debug, Clone, Copy, Default)]
struct FastCounts {
    answer: u16,
    authority: u16,
    additional: u16,
}

/// Стековый dedup proof-владельцев по wire-форме (имя или NSEC3-hash).
struct FastSeen {
    owners: [[u8; MAX_NAME_WIRE_LEN]; FAST_PROOF_SLOTS],
    lens: [usize; FAST_PROOF_SLOTS],
    len: usize,
}

impl FastSeen {
    const fn new() -> Self {
        Self {
            owners: [[0_u8; MAX_NAME_WIRE_LEN]; FAST_PROOF_SLOTS],
            lens: [0_usize; FAST_PROOF_SLOTS],
            len: 0,
        }
    }

    fn contains(&self, wire: &[u8]) -> bool {
        self.lens
            .iter()
            .zip(self.owners.iter())
            .take(self.len)
            .any(|(&len, owner)| owner.get(..len) == Some(wire))
    }

    /// Запоминает владельца; `false` — переполнение (полный путь).
    fn insert(&mut self, wire: &[u8]) -> bool {
        let Some(slot) = self.owners.get_mut(self.len) else {
            return false;
        };
        let Some(target) = slot.get_mut(..wire.len()) else {
            return false;
        };
        target.copy_from_slice(wire);
        if let Some(len) = self.lens.get_mut(self.len) {
            *len = wire.len();
        }
        self.len = self.len.saturating_add(1);
        true
    }
}

/// Стековый пул буферов имён для синтеза `DNAME`-`CNAME`.
///
/// Каждый шаг цепочки получает отдельный слот: имена синтезированных
/// `CNAME` живут до конца кодирования ответа.
struct NameBufferPool<'a> {
    slots: core::slice::IterMut<'a, [u8; MAX_NAME_WIRE_LEN]>,
}

impl<'a> NameBufferPool<'a> {
    fn new(storage: &'a mut [[u8; MAX_NAME_WIRE_LEN]; MAX_CNAME_CHAIN]) -> Self {
        Self {
            slots: storage.iter_mut(),
        }
    }

    fn next(&mut self) -> Option<&'a mut [u8; MAX_NAME_WIRE_LEN]> {
        self.slots.next()
    }
}

/// Стековый список имён без аллокаций.
#[derive(Debug, Clone, Copy)]
struct NameSlots<'a> {
    items: [NameRef<'a>; FAST_TARGET_SLOTS],
    len: usize,
}

impl<'a> NameSlots<'a> {
    const fn new() -> Self {
        Self {
            items: [ROOT_NAME; FAST_TARGET_SLOTS],
            len: 0,
        }
    }

    /// Добавляет имя; `false` — переполнение (нужен полный путь).
    fn push(&mut self, name: NameRef<'a>) -> bool {
        let Some(slot) = self.items.get_mut(self.len) else {
            return false;
        };
        *slot = name;
        self.len = self.len.saturating_add(1);
        true
    }

    /// Сортирует по каноническому порядку и убирает дубликаты.
    fn sort_dedup(&mut self) {
        for index in 1..self.len {
            let mut position = index;
            while position > 0 {
                let (Some(previous), Some(current)) = (
                    self.items.get(position - 1).copied(),
                    self.items.get(position).copied(),
                ) else {
                    break;
                };
                if previous.cmp_canonical(current) != core::cmp::Ordering::Greater {
                    break;
                }
                self.items.swap(position - 1, position);
                position -= 1;
            }
        }
        let mut unique = 0_usize;
        for index in 0..self.len {
            let Some(&candidate) = self.items.get(index) else {
                break;
            };
            let duplicate = index > 0
                && self
                    .items
                    .get(unique.saturating_sub(1))
                    .is_some_and(|last| last.as_wire() == candidate.as_wire());
            if duplicate {
                continue;
            }
            if let Some(slot) = self.items.get_mut(unique) {
                *slot = candidate;
                unique = unique.saturating_add(1);
            }
        }
        self.len = unique;
    }

    fn iter(&self) -> impl Iterator<Item = NameRef<'a>> + '_ {
        self.items.iter().take(self.len).copied()
    }
}

/// Итог поиска по wildcard.
#[derive(Debug, Clone, Copy)]
enum WildcardOutcome<'a> {
    /// Ответ из wildcard; владелец набора — `*.<closest>`.
    Answer {
        rrset: RrsetRef<'a>,
        wildcard: NameRef<'a>,
    },
    /// `CNAME` из wildcard и его каноническая цель.
    Cname {
        rrset: RrsetRef<'a>,
        target: NameRef<'a>,
        wildcard: NameRef<'a>,
    },
    /// Wildcard существует, но типа в нём нет.
    NoData { wildcard: NameRef<'a> },
    /// Wildcard не найден.
    NxDomain,
    /// Не представимо заимствованно (полный путь).
    Unsupported,
}

/// Строит `*.<closest encloser>` в caller-provided буфере (RFC 4592).
///
/// `None` — у имени нет существующего предка внутри зоны либо имя не
/// помещается в буфер.
fn wildcard_owner_ref<'a>(
    snapshot: &dyn ZoneSnapshot,
    name: NameRef<'a>,
    origin: NameRef<'_>,
    buffer: &'a mut [u8; MAX_NAME_WIRE_LEN],
) -> Option<NameRef<'a>> {
    let mut closest = None;
    let mut candidate = name.parent();
    while let Some(current) = candidate {
        // Origin обслуживающей зоны существует всегда (SOA/NS), поэтому его
        // не нужно проверять отдельным спуском в дерево.
        if current.as_wire() == origin.as_wire() || snapshot.node_exists_ref(current) {
            closest = Some(current);
            break;
        }
        candidate = current.parent();
    }
    let closest = match closest {
        Some(closest) => closest,
        None => {
            if snapshot.node_exists_ref(origin) {
                origin
            } else {
                return None;
            }
        }
    };
    let length = closest.wire_len().checked_add(2)?;
    let slot = buffer.get_mut(..length)?;
    let (header, rest) = slot.split_first_mut()?;
    *header = 1;
    let (marker, tail) = rest.split_first_mut()?;
    *marker = b'*';
    tail.copy_from_slice(closest.as_wire());
    let wire = buffer.get(..length)?;
    Some(NameRef::from_validated(wire))
}

/// Ищет wildcard-ответ для несуществующего имени (RFC 4592).
fn wildcard_lookup<'a>(
    snapshot: &'a dyn ZoneSnapshot,
    name: NameRef<'a>,
    qtype: Rtype,
    origin: NameRef<'a>,
    buffer: &'a mut [u8; MAX_NAME_WIRE_LEN],
) -> WildcardOutcome<'a> {
    let Some(wildcard) = wildcard_owner_ref(snapshot, name, origin, buffer) else {
        return WildcardOutcome::NxDomain;
    };
    // Wildcard-владелец, которого нет в зоне, даёт NxDomain без полного
    // поиска: это заметно дешевле на больших зонах (нет проверки
    // делегирования и RRset).
    if !snapshot.node_exists_ref(wildcard) {
        return WildcardOutcome::NxDomain;
    }
    match snapshot.lookup_ref(wildcard, qtype) {
        LookupOutcomeRef::Answer(rrset) => WildcardOutcome::Answer { rrset, wildcard },
        LookupOutcomeRef::Cname(rrset, target) => WildcardOutcome::Cname {
            rrset,
            target,
            wildcard,
        },
        LookupOutcomeRef::NoData => WildcardOutcome::NoData { wildcard },
        LookupOutcomeRef::NxDomain => WildcardOutcome::NxDomain,
        LookupOutcomeRef::Delegation { .. }
        | LookupOutcomeRef::Referral
        | LookupOutcomeRef::ZoneNotFound
        | LookupOutcomeRef::Unsupported => WildcardOutcome::Unsupported,
    }
}

/// Точка делегирования для имени (deepest cut ниже origin).
fn find_delegation_ref<'a>(
    snapshot: &dyn ZoneSnapshot,
    name: NameRef<'a>,
    origin: NameRef<'_>,
) -> Option<NameRef<'a>> {
    let mut current = Some(name);
    while let Some(candidate) = current {
        if candidate.as_wire() == origin.as_wire() || !candidate.is_subdomain_of(origin) {
            return None;
        }
        if snapshot.is_delegation_ref(candidate) {
            return Some(candidate);
        }
        current = candidate.parent();
    }
    None
}

/// Итог разбора быстрым путём.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResolveOutcome {
    /// Ответ собран в плане.
    Done,
    /// Обнаружен цикл `CNAME`/`DNAME`; нужен `SERVFAIL`.
    ServFail,
}

/// Найденный `DNAME` на предке имени.
#[derive(Debug, Clone, Copy)]
struct DnameRedirect<'a> {
    owner: NameRef<'a>,
    rrset: RrsetRef<'a>,
    target: NameRef<'a>,
}

/// Результат поиска `DNAME` на предках.
#[derive(Debug, Clone, Copy)]
enum DnameLookup<'a> {
    /// `DNAME` на предке нет.
    Absent,
    /// Найден `DNAME` и его цель.
    Redirect(DnameRedirect<'a>),
    /// Заимствованное представление недоступно (полный путь).
    Unsupported,
}

/// Решение о продолжении цепочки `CNAME`/`DNAME`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChaseDecision {
    /// Продолжать цепочку.
    Chase,
    /// Остановиться на уже собранном ответе.
    Stop,
    /// Цикл: ответ `SERVFAIL`.
    ServFail,
}

/// Можно ли продолжать `CNAME`/`DNAME`-цепочку и не замыкается ли она.
fn chase_allowed<'a>(
    snapshot: &dyn ZoneSnapshot,
    current: NameRef<'a>,
    target: NameRef<'a>,
    origin: NameRef<'_>,
    visited: &[NameRef<'a>],
) -> ChaseDecision {
    if target.as_wire() == current.as_wire()
        || visited
            .iter()
            .any(|name| name.as_wire() == target.as_wire())
    {
        return ChaseDecision::ServFail;
    }
    if visited.len().saturating_add(1) >= MAX_CNAME_CHAIN
        || !target.is_subdomain_of(origin)
        || delegation_above(snapshot, target, origin)
    {
        return ChaseDecision::Stop;
    }
    ChaseDecision::Chase
}

/// Разбирает ответ по заимствованному снимку: referral, `ANY` или цепочка.
#[allow(clippy::too_many_lines)]
#[allow(clippy::too_many_arguments)]
fn resolve_fast<'s: 'b, 'b, 'r: 'b>(
    snapshot: &'s dyn ZoneSnapshot,
    qname: NameRef<'r>,
    qtype: Rtype,
    origin: NameRef<'s>,
    wildcard_wire: &'b mut [u8; MAX_NAME_WIRE_LEN],
    synth_pool: &mut NameBufferPool<'b>,
    hinfo_ttl: Ttl,
    plan: &mut FastPlan<'b>,
) -> Option<ResolveOutcome> {
    if let Some(cut) = find_delegation_ref(snapshot, qname, origin) {
        if cut.as_wire() == qname.as_wire() && qtype == Rtype::DS {
            return match snapshot.lookup_ref(qname, Rtype::DS) {
                LookupOutcomeRef::Answer(ds) => plan
                    .push(FastAnswer {
                        owner: qname,
                        data: FastAnswerData::Ref(ds),
                        sig_source: None,
                    })
                    .map(|()| ResolveOutcome::Done),
                LookupOutcomeRef::NoData => {
                    plan.status = FastStatus::NoData;
                    plan.needs_soa = true;
                    Some(ResolveOutcome::Done)
                }
                _ => None,
            };
        }
        let LookupOutcomeRef::Delegation { ns, ds } = snapshot.lookup_ref(cut, Rtype::NS) else {
            return None;
        };
        plan.status = FastStatus::Referral;
        plan.aa = false;
        plan.referral = Some(FastReferral { cut, ns, ds });
        return Some(ResolveOutcome::Done);
    }

    let mut visited = [ROOT_NAME; MAX_CNAME_CHAIN];
    let mut visited_len = 0_usize;
    let mut current: NameRef<'b> = qname;
    loop {
        // `DNAME` на предке перекрывает и точное совпадение, и `NXDOMAIN`:
        // синтезируем `CNAME` и продолжаем разбор цели (RFC 6672).
        match dname_redirect_ref(snapshot, current, origin) {
            DnameLookup::Absent => {}
            DnameLookup::Unsupported => return None,
            DnameLookup::Redirect(redirect) => {
                plan.push(FastAnswer {
                    owner: redirect.owner,
                    data: FastAnswerData::Ref(redirect.rrset),
                    sig_source: None,
                })?;
                plan.status = FastStatus::Answer;
                plan.aa = true;
                let synth = synth_pool.next()?;
                let Some(target) =
                    substitute_suffix_ref(current, redirect.owner, redirect.target, synth)
                else {
                    // Переполнение имени при синтезе (RFC 6672 §2.2).
                    plan.status = FastStatus::YxDomain;
                    return Some(ResolveOutcome::Done);
                };
                plan.push(FastAnswer {
                    owner: current,
                    data: FastAnswerData::DnameCname {
                        dname: redirect.rrset,
                    },
                    sig_source: None,
                })?;
                match chase_allowed(
                    snapshot,
                    current,
                    target,
                    origin,
                    visited.get(..visited_len)?,
                ) {
                    ChaseDecision::ServFail => return Some(ResolveOutcome::ServFail),
                    ChaseDecision::Stop => return Some(ResolveOutcome::Done),
                    ChaseDecision::Chase => {}
                }
                *visited.get_mut(visited_len)? = current;
                visited_len = visited_len.checked_add(1)?;
                current = target;
                continue;
            }
        }

        if qtype == Rtype::ANY {
            resolve_any_fast(snapshot, current, origin, wildcard_wire, hinfo_ttl, plan)?;
            return Some(ResolveOutcome::Done);
        }

        match snapshot.lookup_ref(current, qtype) {
            LookupOutcomeRef::Answer(rrset) => {
                plan.push(FastAnswer {
                    owner: current,
                    data: FastAnswerData::Ref(rrset),
                    sig_source: None,
                })?;
                plan.status = FastStatus::Answer;
                return Some(ResolveOutcome::Done);
            }
            LookupOutcomeRef::Cname(rrset, target) => {
                plan.push(FastAnswer {
                    owner: current,
                    data: FastAnswerData::Ref(rrset),
                    sig_source: None,
                })?;
                match chase_allowed(
                    snapshot,
                    current,
                    target,
                    origin,
                    visited.get(..visited_len)?,
                ) {
                    ChaseDecision::ServFail => return Some(ResolveOutcome::ServFail),
                    ChaseDecision::Stop => return Some(ResolveOutcome::Done),
                    ChaseDecision::Chase => {}
                }
                *visited.get_mut(visited_len)? = current;
                visited_len = visited_len.checked_add(1)?;
                current = target;
            }
            LookupOutcomeRef::NoData => {
                plan.status = FastStatus::NoData;
                plan.aa = true;
                plan.needs_soa = true;
                return Some(ResolveOutcome::Done);
            }
            LookupOutcomeRef::NxDomain => {
                match wildcard_lookup(snapshot, current, qtype, origin, wildcard_wire) {
                    WildcardOutcome::Answer { rrset, wildcard } => {
                        plan.push(FastAnswer {
                            owner: current,
                            data: FastAnswerData::Ref(rrset),
                            sig_source: Some(wildcard),
                        })?;
                        plan.status = FastStatus::Answer;
                        plan.wildcard = Some(wildcard);
                        return Some(ResolveOutcome::Done);
                    }
                    WildcardOutcome::Cname {
                        rrset,
                        target,
                        wildcard,
                    } => {
                        plan.push(FastAnswer {
                            owner: current,
                            data: FastAnswerData::Ref(rrset),
                            sig_source: Some(wildcard),
                        })?;
                        plan.status = FastStatus::Answer;
                        plan.wildcard = Some(wildcard);
                        match chase_allowed(
                            snapshot,
                            current,
                            target,
                            origin,
                            visited.get(..visited_len)?,
                        ) {
                            ChaseDecision::ServFail => {
                                return Some(ResolveOutcome::ServFail);
                            }
                            ChaseDecision::Stop => return Some(ResolveOutcome::Done),
                            ChaseDecision::Chase => {}
                        }
                        *visited.get_mut(visited_len)? = current;
                        visited_len = visited_len.checked_add(1)?;
                        // После wildcard-CNAME цепочка продолжается только
                        // точными данными и `DNAME`: повторный wildcard-поиск
                        // (и связанный с ним второй буфер имени) остаётся
                        // полному пути.
                        return chase_exact_fast(
                            snapshot,
                            target,
                            qtype,
                            origin,
                            &mut visited,
                            &mut visited_len,
                            synth_pool,
                            plan,
                        );
                    }
                    WildcardOutcome::NoData { wildcard } => {
                        plan.status = FastStatus::NoData;
                        plan.aa = true;
                        plan.needs_soa = true;
                        plan.wildcard = Some(wildcard);
                        return Some(ResolveOutcome::Done);
                    }
                    WildcardOutcome::NxDomain => {
                        plan.status = FastStatus::NxDomain;
                        plan.aa = true;
                        plan.needs_soa = true;
                        return Some(ResolveOutcome::Done);
                    }
                    WildcardOutcome::Unsupported => return None,
                }
            }
            LookupOutcomeRef::Unsupported => return None,
            LookupOutcomeRef::Delegation { .. }
            | LookupOutcomeRef::Referral
            | LookupOutcomeRef::ZoneNotFound => {
                // Делегирование в цепочке — штатная остановка; в начале —
                // не горячий случай.
                return if plan.answer_len == 0 {
                    None
                } else {
                    Some(ResolveOutcome::Done)
                };
            }
        }
    }
}

/// Продолжает цепочку после wildcard-`CNAME`: точные данные и `DNAME`.
#[allow(clippy::too_many_arguments)]
fn chase_exact_fast<'s: 'b, 'b>(
    snapshot: &'s dyn ZoneSnapshot,
    mut current: NameRef<'b>,
    qtype: Rtype,
    origin: NameRef<'s>,
    visited: &mut [NameRef<'b>; MAX_CNAME_CHAIN],
    visited_len: &mut usize,
    synth_pool: &mut NameBufferPool<'b>,
    plan: &mut FastPlan<'b>,
) -> Option<ResolveOutcome> {
    loop {
        match dname_redirect_ref(snapshot, current, origin) {
            DnameLookup::Absent => {}
            DnameLookup::Unsupported => return None,
            DnameLookup::Redirect(redirect) => {
                plan.push(FastAnswer {
                    owner: redirect.owner,
                    data: FastAnswerData::Ref(redirect.rrset),
                    sig_source: None,
                })?;
                plan.status = FastStatus::Answer;
                plan.aa = true;
                let synth = synth_pool.next()?;
                let Some(target) =
                    substitute_suffix_ref(current, redirect.owner, redirect.target, synth)
                else {
                    plan.status = FastStatus::YxDomain;
                    return Some(ResolveOutcome::Done);
                };
                plan.push(FastAnswer {
                    owner: current,
                    data: FastAnswerData::DnameCname {
                        dname: redirect.rrset,
                    },
                    sig_source: None,
                })?;
                match chase_allowed(
                    snapshot,
                    current,
                    target,
                    origin,
                    visited.get(..*visited_len)?,
                ) {
                    ChaseDecision::ServFail => return Some(ResolveOutcome::ServFail),
                    ChaseDecision::Stop => return Some(ResolveOutcome::Done),
                    ChaseDecision::Chase => {}
                }
                *visited.get_mut(*visited_len)? = current;
                *visited_len = visited_len.checked_add(1)?;
                current = target;
                continue;
            }
        }

        match snapshot.lookup_ref(current, qtype) {
            LookupOutcomeRef::Answer(rrset) => {
                plan.push(FastAnswer {
                    owner: current,
                    data: FastAnswerData::Ref(rrset),
                    sig_source: None,
                })?;
                plan.status = FastStatus::Answer;
                return Some(ResolveOutcome::Done);
            }
            LookupOutcomeRef::Cname(rrset, target) => {
                plan.push(FastAnswer {
                    owner: current,
                    data: FastAnswerData::Ref(rrset),
                    sig_source: None,
                })?;
                match chase_allowed(
                    snapshot,
                    current,
                    target,
                    origin,
                    visited.get(..*visited_len)?,
                ) {
                    ChaseDecision::ServFail => return Some(ResolveOutcome::ServFail),
                    ChaseDecision::Stop => return Some(ResolveOutcome::Done),
                    ChaseDecision::Chase => {}
                }
                *visited.get_mut(*visited_len)? = current;
                *visited_len = visited_len.checked_add(1)?;
                current = target;
            }
            LookupOutcomeRef::NoData => {
                // Wildcard-владелец остаётся в плане: NODATA-доказательство
                // строится по нему, как в полном пути.
                plan.status = FastStatus::NoData;
                plan.aa = true;
                plan.needs_soa = true;
                return Some(ResolveOutcome::Done);
            }
            // `NXDOMAIN` после wildcard-CNAME требует второго wildcard-поиска
            // с отдельным буфером имени — это полный путь.
            LookupOutcomeRef::NxDomain | LookupOutcomeRef::Unsupported => return None,
            LookupOutcomeRef::Delegation { .. }
            | LookupOutcomeRef::Referral
            | LookupOutcomeRef::ZoneNotFound => {
                return if plan.answer_len == 0 {
                    None
                } else {
                    Some(ResolveOutcome::Done)
                };
            }
        }
    }
}

/// `QTYPE = ANY`: `CNAME` владельца либо `HINFO`-синтез (RFC 8482).
fn resolve_any_fast<'a>(
    snapshot: &'a dyn ZoneSnapshot,
    qname: NameRef<'a>,
    origin: NameRef<'a>,
    wildcard_wire: &'a mut [u8; MAX_NAME_WIRE_LEN],
    hinfo_ttl: Ttl,
    plan: &mut FastPlan<'a>,
) -> Option<()> {
    match snapshot.lookup_ref(qname, Rtype::CNAME) {
        LookupOutcomeRef::Answer(cname) => {
            plan.push(FastAnswer {
                owner: qname,
                data: FastAnswerData::Ref(cname),
                sig_source: None,
            })?;
            plan.status = FastStatus::Answer;
            return Some(());
        }
        LookupOutcomeRef::NoData | LookupOutcomeRef::NxDomain => {}
        _ => return None,
    }
    if snapshot.node_exists_ref(qname) {
        plan.push(FastAnswer {
            owner: qname,
            data: FastAnswerData::Hinfo { ttl: hinfo_ttl },
            sig_source: None,
        })?;
        plan.status = FastStatus::Answer;
        return Some(());
    }
    let Some(wildcard) = wildcard_owner_ref(snapshot, qname, origin, wildcard_wire) else {
        plan.status = FastStatus::NxDomain;
        plan.needs_soa = true;
        return Some(());
    };
    match snapshot.lookup_ref(wildcard, Rtype::CNAME) {
        LookupOutcomeRef::Answer(cname) => {
            // Полный путь переименовывает CNAME в QNAME и не помечает
            // источник подписи: подпись ищется у QNAME.
            plan.push(FastAnswer {
                owner: qname,
                data: FastAnswerData::Ref(cname),
                sig_source: None,
            })?;
            plan.status = FastStatus::Answer;
        }
        LookupOutcomeRef::NoData | LookupOutcomeRef::NxDomain => {
            if snapshot.node_exists_ref(wildcard) {
                plan.push(FastAnswer {
                    owner: qname,
                    data: FastAnswerData::Hinfo { ttl: hinfo_ttl },
                    sig_source: None,
                })?;
                plan.status = FastStatus::Answer;
            } else {
                plan.status = FastStatus::NxDomain;
                plan.needs_soa = true;
            }
        }
        _ => return None,
    }
    Some(())
}

/// Запрос denial-доказательства: точный владелец либо покрытие.
#[derive(Debug, Clone, Copy)]
enum ProofQuery<'a> {
    Exact(NameRef<'a>),
    Cover(NameRef<'a>),
}

impl<'a> ProofQuery<'a> {
    const fn name(self) -> NameRef<'a> {
        match self {
            Self::Exact(name) | Self::Cover(name) => name,
        }
    }
}

/// Повод для denial-доказательств (`NSEC`/`NSEC3`).
#[derive(Debug, Clone, Copy)]
enum ProofReason<'a> {
    NxDomain,
    NoData { wildcard: Option<NameRef<'a>> },
    WildcardAnswer { wildcard: NameRef<'a> },
    Referral { cut: NameRef<'a> },
}

/// Параметры NSEC3-цепочки из `NSEC3PARAM` для hash-пространства.
#[derive(Debug, Clone, Copy)]
struct FastNsec3Params<'a> {
    iterations: u16,
    salt: &'a [u8],
}

/// Итог чтения параметров NSEC3.
#[derive(Debug, Clone, Copy)]
enum FastParams<'a> {
    Params(FastNsec3Params<'a>),
    /// Параметров нет или они невалидны: полный путь тоже не даёт proof.
    Absent,
    /// Заимствованное представление недоступно (полный путь).
    Unsupported,
}

/// Читает и валидирует `NSEC3PARAM` так же, как `Nsec3Params::from_nsec3param`.
fn fast_nsec3_params(snapshot: &dyn ZoneSnapshot) -> FastParams<'_> {
    let rrset = match snapshot.nsec3_param_ref() {
        RefLookup::Found(rrset) => rrset,
        RefLookup::Absent => return FastParams::Absent,
        RefLookup::Unsupported => return FastParams::Unsupported,
    };
    let parsed = match rrset.first_record() {
        Some(RdataRef::Domain(Rdata::Nsec3Param(param))) => Some((
            param.hash_algorithm(),
            param.flags(),
            param.iterations(),
            param.salt(),
        )),
        Some(RdataRef::Domain(_)) | None => None,
        Some(RdataRef::Wire { bytes, .. }) => parse_nsec3param_wire(bytes),
    };
    let Some((algorithm, flags, iterations, salt)) = parsed else {
        return FastParams::Absent;
    };
    if flags != 0
        || algorithm != Nsec3Params::HASH_SHA1
        || iterations > DenialLimits::new().max_nsec3_iterations
    {
        return FastParams::Absent;
    }
    FastParams::Params(FastNsec3Params { iterations, salt })
}

/// Разбирает wire-форму `NSEC3PARAM`.
fn parse_nsec3param_wire(bytes: &[u8]) -> Option<(u8, u8, u16, &[u8])> {
    let algorithm = *bytes.first()?;
    let flags = *bytes.get(1)?;
    let iterations: [u8; 2] = bytes.get(2..4)?.try_into().ok()?;
    let salt_len = usize::from(*bytes.get(4)?);
    let start = 5_usize;
    let end = start.checked_add(salt_len)?;
    let salt = bytes.get(start..end)?;
    if end != bytes.len() {
        return None;
    }
    Some((algorithm, flags, u16::from_be_bytes(iterations), salt))
}

/// Самый длинный существующий предок `qname` (включая apex).
fn closest_encloser_ref<'a>(
    snapshot: &dyn ZoneSnapshot,
    qname: NameRef<'a>,
    origin: NameRef<'a>,
) -> NameRef<'a> {
    let mut current = qname.parent();
    while let Some(name) = current {
        if snapshot.node_exists_ref(name) || name.as_wire() == origin.as_wire() {
            return name;
        }
        current = name.parent();
    }
    origin
}

/// Ближайшее к `qname` имя ниже `closest_encloser` (суффикс `qname`).
fn next_closer_ref<'a>(qname: NameRef<'a>, closest_encloser: NameRef<'a>) -> Option<NameRef<'a>> {
    if qname.as_wire() == closest_encloser.as_wire() || !qname.is_subdomain_of(closest_encloser) {
        return None;
    }
    let mut current = qname;
    while let Some(parent) = current.parent() {
        if parent.as_wire() == closest_encloser.as_wire() {
            return Some(current);
        }
        current = parent;
    }
    None
}

/// Строит `*.<parent>` в caller-provided буфере.
fn wildcard_name_ref<'a>(
    parent: NameRef<'_>,
    buffer: &'a mut [u8; MAX_NAME_WIRE_LEN],
) -> Option<NameRef<'a>> {
    let length = parent.wire_len().checked_add(2)?;
    let slot = buffer.get_mut(..length)?;
    let (header, rest) = slot.split_first_mut()?;
    *header = 1;
    let (marker, tail) = rest.split_first_mut()?;
    *marker = b'*';
    tail.copy_from_slice(parent.as_wire());
    let wire = buffer.get(..length)?;
    Some(NameRef::from_validated(wire))
}

/// Нужны ли denial-доказательства для собранного плана.
fn proof_reason<'a>(plan: &FastPlan<'a>) -> Option<ProofReason<'a>> {
    match plan.status {
        FastStatus::NxDomain => Some(ProofReason::NxDomain),
        FastStatus::NoData => Some(ProofReason::NoData {
            wildcard: plan.wildcard,
        }),
        FastStatus::Answer => plan
            .wildcard
            .map(|wildcard| ProofReason::WildcardAnswer { wildcard }),
        FastStatus::Referral => plan
            .referral
            .map(|referral| ProofReason::Referral { cut: referral.cut }),
        FastStatus::YxDomain | FastStatus::ServFail => None,
    }
}

/// Пишет authority-секцию: `NS`/`DS`/`SOA` и denial-доказательства.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn write_authority_fast<'a>(
    snapshot: &'a dyn ZoneSnapshot,
    encoder: &mut Encoder<'_>,
    transport: Transport,
    budget: usize,
    truncated: &mut bool,
    counts: &mut FastCounts,
    plan: &FastPlan<'a>,
    signed: bool,
    do_bit: bool,
    qname: NameRef<'a>,
    origin: NameRef<'a>,
) -> Option<Flow> {
    if let Some(referral) = plan.referral {
        let flow = write_fast_group(
            encoder,
            transport,
            budget,
            truncated,
            Section::Authority,
            referral.ns.owner(),
            referral.ns,
            None,
            None,
            counts,
        )
        .ok()?;
        if flow == Flow::Stop {
            return Some(Flow::Stop);
        }
        if signed {
            let flow = write_signature_fast(
                snapshot,
                encoder,
                transport,
                budget,
                truncated,
                Section::Authority,
                referral.ns.owner(),
                Rtype::NS,
                referral.ns.owner(),
                counts,
            )?;
            if flow == Flow::Stop {
                return Some(Flow::Stop);
            }
        }
        if do_bit {
            if let Some(ds) = referral.ds {
                let flow = write_fast_group(
                    encoder,
                    transport,
                    budget,
                    truncated,
                    Section::Authority,
                    ds.owner(),
                    ds,
                    None,
                    None,
                    counts,
                )
                .ok()?;
                if flow == Flow::Stop {
                    return Some(Flow::Stop);
                }
                if signed {
                    let flow = write_signature_fast(
                        snapshot,
                        encoder,
                        transport,
                        budget,
                        truncated,
                        Section::Authority,
                        ds.owner(),
                        Rtype::DS,
                        ds.owner(),
                        counts,
                    )?;
                    if flow == Flow::Stop {
                        return Some(Flow::Stop);
                    }
                }
            } else if signed {
                let flow = write_denial_at_fast(
                    snapshot,
                    encoder,
                    transport,
                    budget,
                    truncated,
                    counts,
                    referral.cut,
                )?;
                if flow == Flow::Stop {
                    return Some(Flow::Stop);
                }
            }
        }
    } else if plan.needs_soa {
        let soa = snapshot.soa_ref()?;
        let ttl = negative_ttl(soa)?;
        let flow = write_fast_group(
            encoder,
            transport,
            budget,
            truncated,
            Section::Authority,
            soa.owner(),
            soa,
            Some(ttl),
            None,
            counts,
        )
        .ok()?;
        if flow == Flow::Stop {
            return Some(Flow::Stop);
        }
        if signed {
            let flow = write_signature_fast(
                snapshot,
                encoder,
                transport,
                budget,
                truncated,
                Section::Authority,
                soa.owner(),
                Rtype::SOA,
                soa.owner(),
                counts,
            )?;
            if flow == Flow::Stop {
                return Some(Flow::Stop);
            }
        }
    }
    if signed && let Some(reason) = proof_reason(plan) {
        let flow = write_denial_fast(
            snapshot, encoder, transport, budget, truncated, counts, qname, origin, reason,
        )?;
        if flow == Flow::Stop {
            return Some(Flow::Stop);
        }
    }
    Some(Flow::Continue)
}

/// Пишет denial-доказательства выбранного зоной механизма.
#[allow(clippy::too_many_arguments)]
fn write_denial_fast<'a>(
    snapshot: &'a dyn ZoneSnapshot,
    encoder: &mut Encoder<'_>,
    transport: Transport,
    budget: usize,
    truncated: &mut bool,
    counts: &mut FastCounts,
    qname: NameRef<'a>,
    origin: NameRef<'a>,
    reason: ProofReason<'a>,
) -> Option<Flow> {
    match snapshot.denial_ref() {
        DenialKind::Nsec => write_nsec_denial(
            snapshot, encoder, transport, budget, truncated, counts, qname, origin, reason,
        ),
        DenialKind::Nsec3 => write_nsec3_denial(
            snapshot, encoder, transport, budget, truncated, counts, qname, origin, reason,
        ),
    }
}

/// Пишет `NSEC`-доказательства в том же порядке, что и полный путь.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn write_nsec_denial<'a>(
    snapshot: &'a dyn ZoneSnapshot,
    encoder: &mut Encoder<'_>,
    transport: Transport,
    budget: usize,
    truncated: &mut bool,
    counts: &mut FastCounts,
    qname: NameRef<'a>,
    origin: NameRef<'a>,
    reason: ProofReason<'a>,
) -> Option<Flow> {
    let mut seen = FastSeen::new();
    let mut owner_wire = [0_u8; MAX_NAME_WIRE_LEN];
    let mut name_wire = [0_u8; MAX_NAME_WIRE_LEN];
    match reason {
        ProofReason::NxDomain => {
            step_nsec(
                snapshot,
                encoder,
                transport,
                budget,
                truncated,
                counts,
                ProofQuery::Cover(qname),
                &mut seen,
                &mut owner_wire,
            )?;
            let closest = closest_encloser_ref(snapshot, qname, origin);
            let Some(wildcard) = wildcard_name_ref(closest, &mut name_wire) else {
                return Some(Flow::Continue);
            };
            let flow = step_nsec(
                snapshot,
                encoder,
                transport,
                budget,
                truncated,
                counts,
                ProofQuery::Exact(wildcard),
                &mut seen,
                &mut owner_wire,
            )?;
            if flow.0 == Flow::Stop {
                return Some(Flow::Stop);
            }
            if !flow.1 {
                let (flow, _) = step_nsec(
                    snapshot,
                    encoder,
                    transport,
                    budget,
                    truncated,
                    counts,
                    ProofQuery::Cover(wildcard),
                    &mut seen,
                    &mut owner_wire,
                )?;
                if flow == Flow::Stop {
                    return Some(Flow::Stop);
                }
            }
        }
        ProofReason::NoData { wildcard } => {
            if let Some(wildcard) = wildcard {
                let (flow, _) = step_nsec(
                    snapshot,
                    encoder,
                    transport,
                    budget,
                    truncated,
                    counts,
                    ProofQuery::Exact(wildcard),
                    &mut seen,
                    &mut owner_wire,
                )?;
                if flow == Flow::Stop {
                    return Some(Flow::Stop);
                }
                let (flow, _) = step_nsec(
                    snapshot,
                    encoder,
                    transport,
                    budget,
                    truncated,
                    counts,
                    ProofQuery::Cover(qname),
                    &mut seen,
                    &mut owner_wire,
                )?;
                if flow == Flow::Stop {
                    return Some(Flow::Stop);
                }
            } else {
                let (flow, _) = step_nsec(
                    snapshot,
                    encoder,
                    transport,
                    budget,
                    truncated,
                    counts,
                    ProofQuery::Exact(qname),
                    &mut seen,
                    &mut owner_wire,
                )?;
                if flow == Flow::Stop {
                    return Some(Flow::Stop);
                }
            }
        }
        ProofReason::WildcardAnswer { wildcard } => {
            let Some(closest) = wildcard.parent() else {
                return Some(Flow::Continue);
            };
            let Some(next) = next_closer_ref(qname, closest) else {
                return Some(Flow::Continue);
            };
            let (flow, _) = step_nsec(
                snapshot,
                encoder,
                transport,
                budget,
                truncated,
                counts,
                ProofQuery::Cover(next),
                &mut seen,
                &mut owner_wire,
            )?;
            if flow == Flow::Stop {
                return Some(Flow::Stop);
            }
        }
        ProofReason::Referral { .. } => {}
    }
    Some(Flow::Continue)
}

/// Один шаг `NSEC`-доказательства: выделение, dedup и запись.
#[allow(clippy::too_many_arguments)]
fn step_nsec<'s: 'b, 'b>(
    snapshot: &'s dyn ZoneSnapshot,
    encoder: &mut Encoder<'_>,
    transport: Transport,
    budget: usize,
    truncated: &mut bool,
    counts: &mut FastCounts,
    query: ProofQuery<'b>,
    seen: &mut FastSeen,
    owner_wire: &'b mut [u8; MAX_NAME_WIRE_LEN],
) -> Option<(Flow, bool)> {
    let lookup = match query {
        ProofQuery::Exact(name) => snapshot.nsec_at_ref(name),
        ProofQuery::Cover(name) => snapshot.nsec_cover_ref(name, owner_wire),
    };
    let rrset = match lookup {
        RefLookup::Found(rrset) => rrset,
        RefLookup::Absent => return Some((Flow::Continue, false)),
        RefLookup::Unsupported => return None,
    };
    if seen.contains(rrset.owner().as_wire()) {
        return Some((Flow::Continue, true));
    }
    if !seen.insert(rrset.owner().as_wire()) {
        return None;
    }
    let flow = write_found_proof(
        snapshot, encoder, transport, budget, truncated, counts, rrset,
    )?;
    Some((flow, true))
}

/// Пишет `NSEC3`-доказательства в том же порядке, что и полный путь.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn write_nsec3_denial<'a>(
    snapshot: &'a dyn ZoneSnapshot,
    encoder: &mut Encoder<'_>,
    transport: Transport,
    budget: usize,
    truncated: &mut bool,
    counts: &mut FastCounts,
    qname: NameRef<'a>,
    origin: NameRef<'a>,
    reason: ProofReason<'a>,
) -> Option<Flow> {
    let params = match fast_nsec3_params(snapshot) {
        FastParams::Params(params) => params,
        FastParams::Absent => return Some(Flow::Continue),
        FastParams::Unsupported => return None,
    };
    let mut seen = FastSeen::new();
    let mut owner_wire = [0_u8; MAX_NAME_WIRE_LEN];
    let mut name_wire = [0_u8; MAX_NAME_WIRE_LEN];
    match reason {
        ProofReason::NxDomain => {
            let closest = closest_encloser_ref(snapshot, qname, origin);
            let (flow, _) = step_nsec3(
                snapshot,
                encoder,
                transport,
                budget,
                truncated,
                counts,
                &params,
                ProofQuery::Exact(closest),
                &mut seen,
                &mut owner_wire,
            )?;
            if flow == Flow::Stop {
                return Some(Flow::Stop);
            }
            if let Some(next) = next_closer_ref(qname, closest) {
                let (flow, _) = step_nsec3(
                    snapshot,
                    encoder,
                    transport,
                    budget,
                    truncated,
                    counts,
                    &params,
                    ProofQuery::Cover(next),
                    &mut seen,
                    &mut owner_wire,
                )?;
                if flow == Flow::Stop {
                    return Some(Flow::Stop);
                }
            }
            if let Some(wildcard) = wildcard_name_ref(closest, &mut name_wire) {
                let (flow, _) = step_nsec3(
                    snapshot,
                    encoder,
                    transport,
                    budget,
                    truncated,
                    counts,
                    &params,
                    ProofQuery::Cover(wildcard),
                    &mut seen,
                    &mut owner_wire,
                )?;
                if flow == Flow::Stop {
                    return Some(Flow::Stop);
                }
            }
        }
        ProofReason::NoData { wildcard } => {
            if let Some(wildcard) = wildcard {
                let Some(closest) = wildcard.parent() else {
                    return Some(Flow::Continue);
                };
                let (flow, _) = step_nsec3(
                    snapshot,
                    encoder,
                    transport,
                    budget,
                    truncated,
                    counts,
                    &params,
                    ProofQuery::Exact(closest),
                    &mut seen,
                    &mut owner_wire,
                )?;
                if flow == Flow::Stop {
                    return Some(Flow::Stop);
                }
                if let Some(next) = next_closer_ref(qname, closest) {
                    let (flow, _) = step_nsec3(
                        snapshot,
                        encoder,
                        transport,
                        budget,
                        truncated,
                        counts,
                        &params,
                        ProofQuery::Cover(next),
                        &mut seen,
                        &mut owner_wire,
                    )?;
                    if flow == Flow::Stop {
                        return Some(Flow::Stop);
                    }
                }
                let (flow, _) = step_nsec3(
                    snapshot,
                    encoder,
                    transport,
                    budget,
                    truncated,
                    counts,
                    &params,
                    ProofQuery::Exact(wildcard),
                    &mut seen,
                    &mut owner_wire,
                )?;
                if flow == Flow::Stop {
                    return Some(Flow::Stop);
                }
            } else {
                let (flow, found) = step_nsec3(
                    snapshot,
                    encoder,
                    transport,
                    budget,
                    truncated,
                    counts,
                    &params,
                    ProofQuery::Exact(qname),
                    &mut seen,
                    &mut owner_wire,
                )?;
                if flow == Flow::Stop {
                    return Some(Flow::Stop);
                }
                if !found {
                    // Opt-Out: у insecure-делегирования нет точного NSEC3.
                    let closest = closest_encloser_ref(snapshot, qname, origin);
                    let (flow, _) = step_nsec3(
                        snapshot,
                        encoder,
                        transport,
                        budget,
                        truncated,
                        counts,
                        &params,
                        ProofQuery::Exact(closest),
                        &mut seen,
                        &mut owner_wire,
                    )?;
                    if flow == Flow::Stop {
                        return Some(Flow::Stop);
                    }
                    let (flow, _) = step_nsec3(
                        snapshot,
                        encoder,
                        transport,
                        budget,
                        truncated,
                        counts,
                        &params,
                        ProofQuery::Cover(qname),
                        &mut seen,
                        &mut owner_wire,
                    )?;
                    if flow == Flow::Stop {
                        return Some(Flow::Stop);
                    }
                }
            }
        }
        ProofReason::WildcardAnswer { wildcard } => {
            let Some(closest) = wildcard.parent() else {
                return Some(Flow::Continue);
            };
            let (flow, _) = step_nsec3(
                snapshot,
                encoder,
                transport,
                budget,
                truncated,
                counts,
                &params,
                ProofQuery::Exact(closest),
                &mut seen,
                &mut owner_wire,
            )?;
            if flow == Flow::Stop {
                return Some(Flow::Stop);
            }
            if let Some(next) = next_closer_ref(qname, closest) {
                let (flow, _) = step_nsec3(
                    snapshot,
                    encoder,
                    transport,
                    budget,
                    truncated,
                    counts,
                    &params,
                    ProofQuery::Cover(next),
                    &mut seen,
                    &mut owner_wire,
                )?;
                if flow == Flow::Stop {
                    return Some(Flow::Stop);
                }
            }
        }
        ProofReason::Referral { cut } => {
            let closest = closest_encloser_ref(snapshot, cut, origin);
            let (flow, _) = step_nsec3(
                snapshot,
                encoder,
                transport,
                budget,
                truncated,
                counts,
                &params,
                ProofQuery::Exact(closest),
                &mut seen,
                &mut owner_wire,
            )?;
            if flow == Flow::Stop {
                return Some(Flow::Stop);
            }
            let (flow, _) = step_nsec3(
                snapshot,
                encoder,
                transport,
                budget,
                truncated,
                counts,
                &params,
                ProofQuery::Cover(cut),
                &mut seen,
                &mut owner_wire,
            )?;
            if flow == Flow::Stop {
                return Some(Flow::Stop);
            }
        }
    }
    Some(Flow::Continue)
}

/// Один шаг `NSEC3`-доказательства: hash, выделение, dedup и запись.
#[allow(clippy::too_many_arguments)]
fn step_nsec3<'s: 'b, 'b>(
    snapshot: &'s dyn ZoneSnapshot,
    encoder: &mut Encoder<'_>,
    transport: Transport,
    budget: usize,
    truncated: &mut bool,
    counts: &mut FastCounts,
    params: &FastNsec3Params<'_>,
    query: ProofQuery<'b>,
    seen: &mut FastSeen,
    owner_wire: &'b mut [u8; MAX_NAME_WIRE_LEN],
) -> Option<(Flow, bool)> {
    let mut hash = [0_u8; NSEC3_SHA1_LEN];
    let hash_bytes = nsec3_hash_into(
        query.name().as_wire(),
        params.salt,
        params.iterations,
        &mut hash,
    );
    let lookup = match query {
        ProofQuery::Exact(_) => snapshot.nsec3_at_ref(hash_bytes, owner_wire),
        ProofQuery::Cover(_) => snapshot.nsec3_cover_ref(hash_bytes, owner_wire),
    };
    let rrset = match lookup {
        RefLookup::Found(rrset) => rrset,
        RefLookup::Absent => return Some((Flow::Continue, false)),
        RefLookup::Unsupported => return None,
    };
    // Dedup по владельцу proof-записи, как в полном пути: разные hash-входы
    // могут покрываться одной и той же NSEC3.
    if seen.contains(rrset.owner().as_wire()) {
        return Some((Flow::Continue, true));
    }
    if !seen.insert(rrset.owner().as_wire()) {
        return None;
    }
    let flow = write_found_proof(
        snapshot, encoder, transport, budget, truncated, counts, rrset,
    )?;
    Some((flow, true))
}

/// Пишет denial-запись, доказывающую отсутствие `DS` в точке cut.
#[allow(clippy::too_many_arguments)]
fn write_denial_at_fast<'a>(
    snapshot: &'a dyn ZoneSnapshot,
    encoder: &mut Encoder<'_>,
    transport: Transport,
    budget: usize,
    truncated: &mut bool,
    counts: &mut FastCounts,
    cut: NameRef<'a>,
) -> Option<Flow> {
    match snapshot.denial_ref() {
        DenialKind::Nsec => match snapshot.nsec_at_ref(cut) {
            RefLookup::Found(rrset) => write_found_proof(
                snapshot, encoder, transport, budget, truncated, counts, rrset,
            ),
            RefLookup::Absent => Some(Flow::Continue),
            RefLookup::Unsupported => None,
        },
        DenialKind::Nsec3 => {
            let params = match fast_nsec3_params(snapshot) {
                FastParams::Params(params) => params,
                FastParams::Absent => return Some(Flow::Continue),
                FastParams::Unsupported => return None,
            };
            let mut hash = [0_u8; NSEC3_SHA1_LEN];
            let hash_bytes =
                nsec3_hash_into(cut.as_wire(), params.salt, params.iterations, &mut hash);
            let mut owner_wire = [0_u8; MAX_NAME_WIRE_LEN];
            match snapshot.nsec3_at_ref(hash_bytes, &mut owner_wire) {
                RefLookup::Found(rrset) => write_found_proof(
                    snapshot, encoder, transport, budget, truncated, counts, rrset,
                ),
                RefLookup::Absent => Some(Flow::Continue),
                RefLookup::Unsupported => None,
            }
        }
    }
}

/// Пишет denial-набор и его `RRSIG` в authority.
#[allow(clippy::too_many_arguments)]
fn write_found_proof<'s: 'b, 'b>(
    snapshot: &'s dyn ZoneSnapshot,
    encoder: &mut Encoder<'_>,
    transport: Transport,
    budget: usize,
    truncated: &mut bool,
    counts: &mut FastCounts,
    rrset: RrsetRef<'b>,
) -> Option<Flow> {
    let flow = write_fast_group(
        encoder,
        transport,
        budget,
        truncated,
        Section::Authority,
        rrset.owner(),
        rrset,
        None,
        None,
        counts,
    )
    .ok()?;
    if flow == Flow::Stop {
        return Some(Flow::Stop);
    }
    write_signature_fast(
        snapshot,
        encoder,
        transport,
        budget,
        truncated,
        Section::Authority,
        rrset.owner(),
        rrset.rr_type(),
        rrset.owner(),
        counts,
    )
}

/// Ищет `DNAME` на предках имени (исключая origin) — RFC 6672 §2.2.
///
/// Цель берётся из RDATA `DNAME` заимствованно; материализации RRset нет.
fn dname_redirect_ref<'a>(
    snapshot: &'a dyn ZoneSnapshot,
    name: NameRef<'a>,
    origin: NameRef<'a>,
) -> DnameLookup<'a> {
    let mut current = name.parent();
    while let Some(candidate) = current {
        // INV-6: DNAME в apex запрещён; имена выше origin не принадлежат зоне.
        if candidate.as_wire() == origin.as_wire() || !candidate.is_subdomain_of(origin) {
            break;
        }
        match snapshot.lookup_ref(candidate, Rtype::DNAME) {
            LookupOutcomeRef::Answer(rrset) => {
                let Some(target) = dname_target_ref(rrset) else {
                    return DnameLookup::Unsupported;
                };
                return DnameLookup::Redirect(DnameRedirect {
                    owner: rrset.owner(),
                    rrset,
                    target,
                });
            }
            LookupOutcomeRef::NoData | LookupOutcomeRef::NxDomain | LookupOutcomeRef::Cname(..) => {
            }
            LookupOutcomeRef::Delegation { .. }
            | LookupOutcomeRef::Referral
            | LookupOutcomeRef::ZoneNotFound
            | LookupOutcomeRef::Unsupported => return DnameLookup::Unsupported,
        }
        current = candidate.parent();
    }
    DnameLookup::Absent
}

/// Цель `DNAME`-RDATA как заимствованное имя.
fn dname_target_ref(rrset: RrsetRef<'_>) -> Option<NameRef<'_>> {
    match rrset.first_record()? {
        RdataRef::Domain(Rdata::Dname(name)) => Some(NameRef::from_name(name)),
        RdataRef::Domain(_) => None,
        RdataRef::Wire { bytes, .. } => NameRef::from_wire(bytes).ok(),
    }
}

/// Синтезирует имя из `qname` и цели `DNAME` в caller-provided буфере.
///
/// `None` — `qname` не под `owner` либо результат длиннее 255 октетов
/// (`YXDOMAIN`).
fn substitute_suffix_ref<'b>(
    qname: NameRef<'_>,
    owner: NameRef<'_>,
    target: NameRef<'_>,
    buffer: &'b mut [u8; MAX_NAME_WIRE_LEN],
) -> Option<NameRef<'b>> {
    let prefix_labels = qname.label_count().checked_sub(owner.label_count())?;
    let mut out = 0_usize;
    let mut cursor = 0_usize;
    for _ in 0..prefix_labels {
        let length = usize::from(*qname.as_wire().get(cursor)?);
        if length == 0 {
            return None;
        }
        let end = cursor.checked_add(1)?.checked_add(length)?;
        let label = qname.as_wire().get(cursor..end)?;
        let slot = buffer.get_mut(out..out.checked_add(label.len())?)?;
        slot.copy_from_slice(label);
        out = out.checked_add(label.len())?;
        cursor = end;
    }
    let target_wire = target.as_wire();
    let end = out.checked_add(target_wire.len())?;
    buffer.get_mut(out..end)?.copy_from_slice(target_wire);
    NameRef::from_wire(buffer.get(..end)?).ok()
}

/// Находится ли имя в делегированной зоне (включая саму точку cut).
fn delegation_above(snapshot: &dyn ZoneSnapshot, name: NameRef<'_>, origin: NameRef<'_>) -> bool {
    let mut current = Some(name);
    while let Some(candidate) = current {
        if candidate.as_wire() == origin.as_wire() || !candidate.is_subdomain_of(origin) {
            return false;
        }
        if snapshot.is_delegation_ref(candidate) {
            return true;
        }
        current = candidate.parent();
    }
    false
}

/// Собирает цели additional из ответа так же, как полный путь.
fn add_targets<'a>(rrset: RrsetRef<'a>, slots: &mut NameSlots<'a>) -> Option<()> {
    let offset = match rrset.rr_type() {
        Rtype::NS => 0,
        Rtype::MX | Rtype::SVCB | Rtype::HTTPS => 2,
        Rtype::SRV => 6,
        _ => return Some(()),
    };
    for rdata in rrset.records() {
        let target = match rdata {
            RdataRef::Domain(Rdata::Ns(name)) => NameRef::from_name(name),
            RdataRef::Domain(Rdata::Mx { exchange, .. }) => NameRef::from_name(exchange),
            RdataRef::Domain(Rdata::Srv { target, .. }) => NameRef::from_name(target),
            RdataRef::Domain(Rdata::Svcb(data) | Rdata::Https(data)) => {
                NameRef::from_name(data.target())
            }
            RdataRef::Domain(_) => continue,
            RdataRef::Wire { bytes, .. } => name_at(bytes, offset)?,
        };
        if !slots.push(target) {
            return None;
        }
    }
    Some(())
}

/// Разбирает несжатое имя из начала `bytes[offset..]`.
fn name_at(bytes: &[u8], offset: usize) -> Option<NameRef<'_>> {
    let mut end = offset;
    let mut labels = 0_usize;
    loop {
        let length = *bytes.get(end)?;
        if length == 0 {
            end = end.checked_add(1)?;
            break;
        }
        if length & 0xC0 != 0 {
            return None;
        }
        labels = labels.saturating_add(1);
        if labels > MAX_LABELS {
            return None;
        }
        end = end.checked_add(1 + usize::from(length))?;
        if end > bytes.len() {
            return None;
        }
    }
    NameRef::from_wire(bytes.get(offset..end)?).ok()
}

/// TTL негативного ответа: `min(SOA.ttl, SOA.minimum, NEGATIVE_TTL_CAP)`.
fn negative_ttl(soa: RrsetRef<'_>) -> Option<Ttl> {
    let minimum = match soa.first_record()? {
        RdataRef::Domain(Rdata::Soa(data)) => data.minimum,
        RdataRef::Domain(_) => return None,
        RdataRef::Wire { bytes, .. } => {
            let start = bytes.len().checked_sub(4)?;
            u32::from_be_bytes(bytes.get(start..)?.try_into().ok()?)
        }
    };
    let ttl = soa.ttl().as_u32().min(minimum).min(NEGATIVE_TTL_CAP);
    Ttl::new(ttl).ok()
}

/// Есть ли в RRSIG-RDATA поле `Type Covered`, равное `covered`.
fn rdata_covers(rdata: RdataRef<'_>, covered: Rtype) -> bool {
    rdata.type_covered() == Some(covered)
}

/// Записывает `CNAME`, синтезированный из `DNAME`, без материализации RRset.
///
/// Владелец — `owner` (QNAME текущего шага), TTL и класс — как у `DNAME`.
#[allow(clippy::too_many_arguments)]
fn write_fast_dname_cname(
    encoder: &mut Encoder<'_>,
    transport: Transport,
    budget: usize,
    truncated: &mut bool,
    owner: NameRef<'_>,
    dname: RrsetRef<'_>,
    class: Rclass,
    counts: &mut FastCounts,
) -> Result<Flow, ()> {
    let target = dname_target_ref(dname).ok_or(())?;
    let mut name_wire = [0_u8; MAX_NAME_WIRE_LEN];
    let target = substitute_suffix_ref(owner, dname.owner(), target, &mut name_wire).ok_or(())?;
    let length = target.as_wire().len();
    let mut payload = [0_u8; MAX_NAME_WIRE_LEN + 2];
    let slot = payload
        .get_mut(..length.checked_add(2).ok_or(())?)
        .ok_or(())?;
    let (prefix, rest) = slot.split_at_mut(2);
    prefix.copy_from_slice(&u16::try_from(length).map_err(|_| ())?.to_be_bytes());
    rest.copy_from_slice(target.as_wire());
    let payload = payload.get(..length.checked_add(2).ok_or(())?).ok_or(())?;
    let rrset = RrsetRef::from_wire(owner, Rtype::CNAME, class, dname.ttl(), payload);
    write_fast_group(
        encoder,
        transport,
        budget,
        truncated,
        Section::Answer,
        owner,
        rrset,
        None,
        None,
        counts,
    )
}

/// Записывает RRset в секцию с теми же правилами усечения, что у `WireSink`.
///
/// `covered` фильтрует записи `RRSIG` по полю `Type Covered`: в in-memory
/// зоне подписи всех типов владельца лежат одним набором, тогда как полный
/// путь отдаёт только покрывающие `covered`.
#[allow(clippy::too_many_arguments)]
fn write_fast_group(
    encoder: &mut Encoder<'_>,
    transport: Transport,
    budget: usize,
    truncated: &mut bool,
    section: Section,
    owner: NameRef<'_>,
    rrset: RrsetRef<'_>,
    ttl_override: Option<Ttl>,
    covered: Option<Rtype>,
    counts: &mut FastCounts,
) -> Result<Flow, ()> {
    let group_start = encoder.checkpoint();
    let ttl = ttl_override.unwrap_or_else(|| rrset.ttl());
    for rdata in rrset.records() {
        if let Some(covered) = covered
            && !rdata_covers(rdata, covered)
        {
            continue;
        }
        let checkpoint = encoder.checkpoint();
        let result = match rdata {
            RdataRef::Domain(rdata) => encoder.write_rr_wire_name(
                owner.as_wire(),
                rrset.rr_type(),
                rrset.class(),
                ttl,
                rdata,
            ),
            RdataRef::Wire { bytes, .. } => encoder.write_rr_zone_raw(
                owner.as_wire(),
                rrset.rr_type(),
                rrset.class(),
                ttl,
                bytes,
            ),
        };
        let mut stop = false;
        match result {
            Ok(()) => {}
            Err(EncodeError::BufferTooSmall { .. }) if transport == Transport::Udp => {
                let rollback = if section == Section::Additional {
                    group_start
                } else {
                    checkpoint
                };
                encoder.rollback(rollback);
                if section != Section::Additional {
                    *truncated = true;
                }
                stop = true;
            }
            Err(_) => return Err(()),
        }
        if !stop && transport == Transport::Udp && encoder.len() > budget {
            let rollback = if section == Section::Additional {
                group_start
            } else {
                checkpoint
            };
            encoder.rollback(rollback);
            if section != Section::Additional {
                *truncated = true;
            }
            stop = true;
        }
        if stop {
            return Ok(Flow::Stop);
        }
        match section {
            Section::Answer => counts.answer = counts.answer.saturating_add(1),
            Section::Authority => counts.authority = counts.authority.saturating_add(1),
            Section::Additional => counts.additional = counts.additional.saturating_add(1),
        }
    }
    Ok(Flow::Continue)
}

/// Записывает синтезированный `HINFO` (RFC 8482 §4.1) в answer.
fn write_fast_hinfo(
    encoder: &mut Encoder<'_>,
    transport: Transport,
    budget: usize,
    truncated: &mut bool,
    owner: NameRef<'_>,
    ttl: Ttl,
    counts: &mut FastCounts,
) -> Result<Flow, ()> {
    let checkpoint = encoder.checkpoint();
    let result = encoder.write_rr_raw(owner.as_wire(), HINFO_TYPE, Rclass::IN, ttl, &HINFO_RFC8482);
    let mut stop = false;
    match result {
        Ok(()) => {}
        Err(EncodeError::BufferTooSmall { .. }) if transport == Transport::Udp => {
            encoder.rollback(checkpoint);
            *truncated = true;
            stop = true;
        }
        Err(_) => return Err(()),
    }
    if !stop && transport == Transport::Udp && encoder.len() > budget {
        encoder.rollback(checkpoint);
        *truncated = true;
        stop = true;
    }
    if stop {
        return Ok(Flow::Stop);
    }
    counts.answer = counts.answer.saturating_add(1);
    Ok(Flow::Continue)
}

/// Прикладывает `RRSIG`, покрывающие `covered`, к записям `owner`.
///
/// `source` — имя, под которым подписи хранятся в зоне (wildcard-владелец
/// для развёрнутого ответа). `None` — полный путь (refs недоступны).
#[allow(clippy::too_many_arguments)]
fn write_signature_fast<'s: 'b, 'b>(
    snapshot: &'s dyn ZoneSnapshot,
    encoder: &mut Encoder<'_>,
    transport: Transport,
    budget: usize,
    truncated: &mut bool,
    section: Section,
    owner: NameRef<'b>,
    covered: Rtype,
    source: NameRef<'b>,
    counts: &mut FastCounts,
) -> Option<Flow> {
    match snapshot.rrsig_ref(source, covered) {
        RefLookup::Absent => Some(Flow::Continue),
        RefLookup::Unsupported => None,
        RefLookup::Found(rrset) => write_fast_group(
            encoder,
            transport,
            budget,
            truncated,
            section,
            owner,
            rrset,
            None,
            Some(covered),
            counts,
        )
        .ok(),
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
    negotiated_payload_size(edns.udp_payload_size())
}

fn negotiated_payload_size(payload: u16) -> u16 {
    payload.clamp(UDP_PAYLOAD_WITHOUT_EDNS, MAX_UDP_PAYLOAD)
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
