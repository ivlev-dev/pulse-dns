//! DNS UPDATE (RFC 2136): разбор запроса, валидация секций и ответ.
//!
//! Секции UPDATE переопределяют смысл секций обычного сообщения:
//!
//! - **Zone** (question) — ровно одна запись `ZNAME/ZCLASS` с `ZTYPE = SOA`;
//! - **Prerequisite** (answer) — условия на текущее состояние зоны;
//! - **Update** (authority) — операции добавления/удаления;
//! - **Additional** — `TSIG`/`OPT` и прочие данные, не входящие в транзакцию.
//!
//! Модуль отвечает только за **формат**: проверки формата выполняются здесь
//! (`FORMERR`, `NOTZONE`), а проверки состояния зоны (prerequisites, права,
//! авторитетность) — движком `pulse-server::update` и вызывающим сервером.
//!
//! Классы `ANY`/`NONE` и пустая `RDATA` — метазначения UPDATE, поэтому
//! [`Prerequisite`] и [`UpdateOp`] хранят уже разобранную семантику, а не
//! сырые [`Record`].
//!
//! # Пример
//!
//! ```
//! use pulse_dns::domain::{Flags, Message, Name, Opcode, Question, Rclass, Rtype};
//! use pulse_dns::update::UpdateRequest;
//!
//! let zone = Name::parse("example.com").unwrap();
//! let mut message = Message::new(7, Flags::new().with_opcode(Opcode::UPDATE));
//! message.add_question(Question::new(zone.clone(), Rtype::SOA, Rclass::IN));
//! let request = UpdateRequest::from_message(&message).unwrap();
//! assert_eq!(request.zone(), &zone);
//! assert!(request.prerequisites().is_empty());
//! assert!(request.updates().is_empty());
//! ```

use std::collections::BTreeSet;

use thiserror::Error;

use crate::domain::{
    Flags, Message, Name, Opcode, Question, Rclass, Rcode, Rdata, Record, Rtype, Ttl,
};

/// Максимальное число записей в одной секции UPDATE.
///
/// Лимит защищает от раздутого prerequisite-набора: каждая запись — это
/// отдельная проверка, а размер сообщения всё равно ограничен 65535 октетами.
pub const MAX_UPDATE_RECORDS: usize = 16_384;

/// Ошибка разбора или исполнения UPDATE.
///
/// [`UpdateError::rcode`] даёт код ответа по RFC 2136 §3.8; движок использует
/// тот же тип, чтобы не терять код между слоями.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum UpdateError {
    /// Некорректный формат секции (`FORMERR`).
    #[error("malformed update: {reason}")]
    Format {
        /// Причина.
        reason: &'static str,
    },
    /// Имя вне зоны из Zone-секции (`NOTZONE`).
    #[error("name {name} is outside zone {zone}")]
    NotZone {
        /// Имя из запроса.
        name: String,
        /// Зона.
        zone: String,
    },
    /// Сервер не авторитетен для зоны (`NOTAUTH`).
    #[error("not authoritative for zone {zone}")]
    NotAuthoritative {
        /// Зона.
        zone: String,
    },
    /// Операция запрещена политикой (`REFUSED`).
    #[error("update refused: {reason}")]
    Refused {
        /// Причина.
        reason: &'static str,
    },
    /// Внутренняя ошибка хранилища (`SERVFAIL`).
    #[error("update failed: {reason}")]
    ServFail {
        /// Причина.
        reason: String,
    },
    /// Требуемое имя отсутствует (`NXDOMAIN`).
    #[error("required name does not exist: {name}")]
    NameRequired {
        /// Имя.
        name: String,
    },
    /// Имя должно отсутствовать, но существует (`YXDOMAIN`).
    #[error("name must not exist: {name}")]
    NameExists {
        /// Имя.
        name: String,
    },
    /// Требуемый RRset отсутствует (`NXRRSET`).
    #[error("required rrset does not exist: {name}/{rr_type}")]
    RrsetRequired {
        /// Владелец.
        name: String,
        /// Тип.
        rr_type: Rtype,
    },
    /// RRset должен отсутствовать, но существует (`YXRRSET`).
    #[error("rrset must not exist: {name}/{rr_type}")]
    RrsetExists {
        /// Владелец.
        name: String,
        /// Тип.
        rr_type: Rtype,
    },
    /// RRset не совпал по составу RDATA (`NXRRSET`).
    #[error("rrset does not match prerequisite: {name}/{rr_type}")]
    RrsetMismatch {
        /// Владелец.
        name: String,
        /// Тип.
        rr_type: Rtype,
    },
}

impl UpdateError {
    /// Код ответа DNS для этой ошибки (RFC 2136 §3.8).
    #[must_use]
    pub const fn rcode(&self) -> Rcode {
        match self {
            Self::Format { .. } => Rcode::FORMERR,
            Self::NotZone { .. } => Rcode::NOTZONE,
            Self::NotAuthoritative { .. } => Rcode::NOTAUTH,
            Self::Refused { .. } => Rcode::REFUSED,
            Self::ServFail { .. } => Rcode::SERVFAIL,
            Self::NameRequired { .. } => Rcode::NXDOMAIN,
            Self::NameExists { .. } => Rcode::YXDOMAIN,
            Self::RrsetRequired { .. } | Self::RrsetMismatch { .. } => Rcode::NXRRSET,
            Self::RrsetExists { .. } => Rcode::YXRRSET,
        }
    }
}

/// Условие Prerequisite-секции (RFC 2136 §2.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Prerequisite {
    /// Имя владеет хотя бы одной записью (`CLASS=ANY`, `TYPE=ANY`).
    NameInUse {
        /// Имя.
        name: Name,
    },
    /// Имя не владеет ни одной записью (`CLASS=NONE`, `TYPE=ANY`).
    NameNotInUse {
        /// Имя.
        name: Name,
    },
    /// RRset существует, значение не важно (`CLASS=ANY`, `TYPE=rrset`).
    RrsetExists {
        /// Имя.
        name: Name,
        /// Тип.
        rr_type: Rtype,
    },
    /// RRset не существует (`CLASS=NONE`, `TYPE=rrset`).
    RrsetDoesNotExist {
        /// Имя.
        name: Name,
        /// Тип.
        rr_type: Rtype,
    },
    /// RRset существует и совпадает по составу RDATA (`CLASS=ZCLASS`).
    RrsetEquals {
        /// Имя.
        name: Name,
        /// Тип.
        rr_type: Rtype,
        /// Требуемые RDATA (TTL игнорируется).
        rdatas: Vec<Rdata>,
    },
}

/// Операция Update-секции (RFC 2136 §2.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateOp {
    /// Добавить RR(s) в RRset (`CLASS=ZCLASS`).
    Add {
        /// Владелец.
        name: Name,
        /// Тип.
        rr_type: Rtype,
        /// TTL новых записей; для существующего RRset сохраняется старый.
        ttl: Ttl,
        /// Добавляемые RDATA.
        rdatas: Vec<Rdata>,
    },
    /// Удалить RRset (`CLASS=ANY`, конкретный тип).
    DeleteRrset {
        /// Владелец.
        name: Name,
        /// Тип.
        rr_type: Rtype,
    },
    /// Удалить все RRset имени (`CLASS=ANY`, `TYPE=ANY`).
    DeleteName {
        /// Владелец.
        name: Name,
    },
    /// Удалить конкретные RR из RRset (`CLASS=NONE`).
    DeleteRecord {
        /// Владелец.
        name: Name,
        /// Тип.
        rr_type: Rtype,
        /// Удаляемые RDATA.
        rdatas: Vec<Rdata>,
    },
}

/// Разобранный UPDATE-запрос.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateRequest {
    id: u16,
    zone: Name,
    zone_class: Rclass,
    prerequisites: Vec<Prerequisite>,
    updates: Vec<UpdateOp>,
}

impl UpdateRequest {
    /// Разбирает и валидирует UPDATE-сообщение.
    ///
    /// # Errors
    ///
    /// [`UpdateError::Format`] при нарушении формата секций,
    /// [`UpdateError::NotZone`], если имя секции вне зоны.
    pub fn from_message(message: &Message) -> Result<Self, UpdateError> {
        if message.flags().qr() {
            return Err(format_error("UPDATE request has QR=1"));
        }
        if message.opcode() != Opcode::UPDATE {
            return Err(format_error("message is not UPDATE"));
        }
        if message.questions().len() != 1 {
            return Err(format_error("zone section must contain exactly one record"));
        }
        let zone_question = message
            .questions()
            .first()
            .ok_or_else(|| format_error("missing zone section"))?;
        if zone_question.qtype() != Rtype::SOA {
            return Err(format_error("zone ZTYPE must be SOA"));
        }
        if is_meta_class(zone_question.qclass()) {
            return Err(format_error("zone ZCLASS must not be ANY or NONE"));
        }
        let zone = zone_question.qname().clone();
        let zone_class = zone_question.qclass();

        let prerequisites = parse_prerequisites(&zone, zone_class, message.answers())?;
        let updates = parse_updates(&zone, zone_class, message.authority())?;
        Ok(Self {
            id: message.id(),
            zone,
            zone_class,
            prerequisites,
            updates,
        })
    }

    /// ID запроса.
    #[must_use]
    pub const fn id(&self) -> u16 {
        self.id
    }

    /// Зона (ZNAME).
    #[must_use]
    pub const fn zone(&self) -> &Name {
        &self.zone
    }

    /// Класс зоны (ZCLASS).
    #[must_use]
    pub const fn zone_class(&self) -> Rclass {
        self.zone_class
    }

    /// Prerequisite-секция.
    #[must_use]
    pub fn prerequisites(&self) -> &[Prerequisite] {
        &self.prerequisites
    }

    /// Update-секция.
    #[must_use]
    pub fn updates(&self) -> &[UpdateOp] {
        &self.updates
    }

    /// Строит ответ с эхом Zone-секции и заданным RCODE.
    ///
    /// `AA` не выставляется: RFC 2136 §3.8 определяет только QR/Opcode и
    /// RCODE; эхо вопроса упрощает сопоставление клиенту.
    #[must_use]
    pub fn response(&self, rcode: Rcode) -> Message {
        let flags = Flags::new().with_qr(true).with_opcode(Opcode::UPDATE);
        let mut message = Message::new(self.id, flags);
        message.add_question(Question::new(
            self.zone.clone(),
            Rtype::SOA,
            self.zone_class,
        ));
        message.set_rcode(rcode);
        message
    }
}

fn parse_prerequisites(
    zone: &Name,
    zone_class: Rclass,
    records: &[Record],
) -> Result<Vec<Prerequisite>, UpdateError> {
    if records.len() > MAX_UPDATE_RECORDS {
        return Err(format_error("too many prerequisite records"));
    }
    // value-dependent prerequisites объединяются по (NAME, TYPE).
    let mut value_sets: Vec<(Name, Rtype, BTreeSet<Rdata>)> = Vec::new();
    let mut prerequisites = Vec::new();
    for record in records {
        ensure_in_zone(zone, record.owner())?;
        if record.ttl() != Ttl::ZERO {
            return Err(format_error("prerequisite TTL must be zero"));
        }
        let name = record.owner().clone();
        let rr_type = record.rr_type();
        match record.class() {
            Rclass::ANY => {
                ensure_empty_rdata(record)?;
                if rr_type == Rtype::ANY {
                    prerequisites.push(Prerequisite::NameInUse { name });
                } else {
                    ensure_update_type(rr_type)?;
                    prerequisites.push(Prerequisite::RrsetExists { name, rr_type });
                }
            }
            Rclass::NONE => {
                ensure_empty_rdata(record)?;
                if rr_type == Rtype::ANY {
                    prerequisites.push(Prerequisite::NameNotInUse { name });
                } else {
                    ensure_update_type(rr_type)?;
                    prerequisites.push(Prerequisite::RrsetDoesNotExist { name, rr_type });
                }
            }
            class if class == zone_class => {
                if rr_type == Rtype::ANY {
                    return Err(format_error(
                        "value-dependent prerequisite TYPE must not be ANY",
                    ));
                }
                ensure_update_type(rr_type)?;
                if let Some((_, _, rdatas)) = value_sets
                    .iter_mut()
                    .find(|(owner, kind, _)| owner == &name && *kind == rr_type)
                {
                    rdatas.insert(record.rdata().clone());
                } else {
                    value_sets.push((name, rr_type, BTreeSet::from([record.rdata().clone()])));
                }
            }
            _ => return Err(format_error("invalid prerequisite CLASS")),
        }
    }
    for (name, rr_type, rdatas) in value_sets {
        prerequisites.push(Prerequisite::RrsetEquals {
            name,
            rr_type,
            rdatas: rdatas.into_iter().collect(),
        });
    }
    Ok(prerequisites)
}

fn parse_updates(
    zone: &Name,
    zone_class: Rclass,
    records: &[Record],
) -> Result<Vec<UpdateOp>, UpdateError> {
    if records.len() > MAX_UPDATE_RECORDS {
        return Err(format_error("too many update records"));
    }
    let mut updates = Vec::with_capacity(records.len());
    for record in records {
        ensure_in_zone(zone, record.owner())?;
        let name = record.owner().clone();
        let rr_type = record.rr_type();
        match record.class() {
            class if class == zone_class => {
                if rr_type == Rtype::ANY {
                    return Err(format_error("add TYPE must not be ANY"));
                }
                ensure_update_type(rr_type)?;
                updates.push(UpdateOp::Add {
                    name,
                    rr_type,
                    ttl: record.ttl(),
                    rdatas: vec![record.rdata().clone()],
                });
            }
            Rclass::ANY => {
                if record.ttl() != Ttl::ZERO {
                    return Err(format_error("delete TTL must be zero"));
                }
                ensure_empty_rdata(record)?;
                if rr_type == Rtype::ANY {
                    updates.push(UpdateOp::DeleteName { name });
                } else {
                    ensure_update_type(rr_type)?;
                    updates.push(UpdateOp::DeleteRrset { name, rr_type });
                }
            }
            Rclass::NONE => {
                if record.ttl() != Ttl::ZERO {
                    return Err(format_error("delete TTL must be zero"));
                }
                if rr_type == Rtype::ANY {
                    return Err(format_error("delete TYPE must not be ANY"));
                }
                ensure_update_type(rr_type)?;
                updates.push(UpdateOp::DeleteRecord {
                    name,
                    rr_type,
                    rdatas: vec![record.rdata().clone()],
                });
            }
            _ => return Err(format_error("invalid update CLASS")),
        }
    }
    Ok(updates)
}

fn ensure_in_zone(zone: &Name, name: &Name) -> Result<(), UpdateError> {
    if name.is_subdomain_of(zone) {
        Ok(())
    } else {
        Err(UpdateError::NotZone {
            name: name.to_string(),
            zone: zone.to_string(),
        })
    }
}

fn ensure_empty_rdata(record: &Record) -> Result<(), UpdateError> {
    if record.rdata().wire_len() == 0 {
        Ok(())
    } else {
        Err(format_error("delete/prerequisite RDATA must be empty"))
    }
}

fn ensure_update_type(rr_type: Rtype) -> Result<(), UpdateError> {
    if is_query_meta_type(rr_type) {
        Err(format_error("TYPE is a query/metatype"))
    } else {
        Ok(())
    }
}

/// `true` для типов, которые нельзя использовать в Prerequisite/Update.
#[must_use]
pub const fn is_query_meta_type(rr_type: Rtype) -> bool {
    matches!(
        rr_type.as_u16(),
        0 | 41 | 249 | 250 | 251 | 252 | 253 | 254 | 255
    )
}

const fn is_meta_class(class: Rclass) -> bool {
    matches!(class.as_u16(), 0 | 254 | 255)
}

const fn format_error(reason: &'static str) -> UpdateError {
    UpdateError::Format { reason }
}

/// Ответ на UPDATE с эхом Zone-секции (RFC 2136 §3.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateResponse {
    id: u16,
    zone: Option<Question>,
    rcode: Rcode,
}

impl UpdateResponse {
    /// Создаёт ответ на разобранный запрос.
    #[must_use]
    pub fn for_request(request: &UpdateRequest, rcode: Rcode) -> Self {
        Self {
            id: request.id,
            zone: Some(Question::new(
                request.zone.clone(),
                Rtype::SOA,
                request.zone_class,
            )),
            rcode,
        }
    }

    /// Создаёт ответ на сообщение, которое не удалось разобрать как UPDATE:
    /// первый вопрос (если он есть) эхируется как Zone-секция.
    #[must_use]
    pub fn for_message(message: &Message, rcode: Rcode) -> Self {
        Self {
            id: message.id(),
            zone: message.questions().first().cloned(),
            rcode,
        }
    }

    /// ID ответа.
    #[must_use]
    pub const fn id(&self) -> u16 {
        self.id
    }

    /// RCODE.
    #[must_use]
    pub const fn rcode(&self) -> Rcode {
        self.rcode
    }

    /// Эхо Zone-секции, если запрос её содержал.
    #[must_use]
    pub const fn zone(&self) -> Option<&Question> {
        self.zone.as_ref()
    }

    /// Строит DNS-сообщение ответа.
    #[must_use]
    pub fn to_message(&self) -> Message {
        let flags = Flags::new().with_qr(true).with_opcode(Opcode::UPDATE);
        let mut message = Message::new(self.id, flags);
        if let Some(zone) = &self.zone {
            message.add_question(zone.clone());
        }
        message.set_rcode(self.rcode);
        message
    }

    /// Кодирует ответ в wire-формат.
    ///
    /// # Errors
    ///
    /// [`crate::wire::EncodeError`] при ошибке кодирования.
    pub fn encode(&self) -> Result<Vec<u8>, crate::wire::EncodeError> {
        self.to_message()
            .encode(&crate::wire::EncodeOptions::compressed())
    }
}

/// Строит `FORMERR`-ответ на сообщение, которое не удалось разобрать как
/// UPDATE, сохраняя ID и opcode.
///
/// Используется транспортом, когда [`UpdateRequest::from_message`] вернул
/// ошибку: ответ должен уйти клиенту даже при частично разобранном запросе.
#[must_use]
pub fn error_response(message: &Message, rcode: Rcode) -> Message {
    let mut response = Message::response(message);
    response.set_opcode(Opcode::UPDATE);
    response.set_rcode(rcode);
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Record, SoaData};

    fn zone() -> Name {
        Name::parse("example.com").unwrap()
    }

    fn base() -> Message {
        let mut message = Message::new(0x4242, Flags::new().with_opcode(Opcode::UPDATE));
        message.add_question(Question::new(zone(), Rtype::SOA, Rclass::IN));
        message
    }

    fn record(name: &str, rr_type: Rtype, class: Rclass, ttl: u32, rdata: Rdata) -> Record {
        Record::new(
            Name::parse(name).unwrap(),
            rr_type,
            class,
            Ttl::new(ttl).unwrap(),
            rdata,
        )
        .unwrap()
    }

    fn empty(name: &str, rr_type: Rtype, class: Rclass) -> Record {
        Record::update_metavalue(Name::parse(name).unwrap(), rr_type, class)
    }

    #[test]
    fn parses_add_and_delete_semantics() {
        let mut message = base();
        message.add_authority(record(
            "www.example.com",
            Rtype::A,
            Rclass::IN,
            300,
            Rdata::A("192.0.2.1".parse().unwrap()),
        ));
        message.add_authority(empty("old.example.com", Rtype::A, Rclass::ANY));
        message.add_authority(empty("gone.example.com", Rtype::ANY, Rclass::ANY));
        message.add_authority(record(
            "www.example.com",
            Rtype::A,
            Rclass::NONE,
            0,
            Rdata::A("192.0.2.2".parse().unwrap()),
        ));
        let request = UpdateRequest::from_message(&message).unwrap();
        assert_eq!(request.updates().len(), 4);
        assert!(matches!(request.updates()[0], UpdateOp::Add { .. }));
        assert!(matches!(request.updates()[1], UpdateOp::DeleteRrset { .. }));
        assert!(matches!(request.updates()[2], UpdateOp::DeleteName { .. }));
        assert!(matches!(
            request.updates()[3],
            UpdateOp::DeleteRecord { .. }
        ));
    }

    #[test]
    fn parses_value_dependent_prerequisite_as_one_set() {
        let mut message = base();
        for address in ["192.0.2.1", "192.0.2.2"] {
            message.add_answer(record(
                "www.example.com",
                Rtype::A,
                Rclass::IN,
                0,
                Rdata::A(address.parse().unwrap()),
            ));
        }
        let request = UpdateRequest::from_message(&message).unwrap();
        assert_eq!(request.prerequisites().len(), 1);
        let Prerequisite::RrsetEquals { rdatas, .. } = &request.prerequisites()[0] else {
            panic!("expected value-dependent prerequisite");
        };
        assert_eq!(rdatas.len(), 2);
    }

    #[test]
    fn rejects_bad_zone_section() {
        let mut message = Message::new(1, Flags::new().with_opcode(Opcode::UPDATE));
        message.add_question(Question::new(zone(), Rtype::SOA, Rclass::IN));
        message.add_question(Question::new(zone(), Rtype::SOA, Rclass::IN));
        assert_eq!(
            UpdateRequest::from_message(&message).unwrap_err().rcode(),
            Rcode::FORMERR
        );

        let mut wrong_type = Message::new(1, Flags::new().with_opcode(Opcode::UPDATE));
        wrong_type.add_question(Question::new(zone(), Rtype::A, Rclass::IN));
        assert_eq!(
            UpdateRequest::from_message(&wrong_type)
                .unwrap_err()
                .rcode(),
            Rcode::FORMERR
        );
    }

    #[test]
    fn rejects_ttl_and_nonempty_delete() {
        let mut message = base();
        message.add_authority(empty("old.example.com", Rtype::A, Rclass::ANY));
        let mut record = message.authority()[0].clone();
        // TTL delete должен быть нулевым; Record неизменяем, поэтому собираем
        // сообщение заново с ненулевым TTL.
        // TTL delete должен быть нулевым; Record неизменяем, поэтому собираем
        // сообщение заново с ненулевым TTL.
        message = base();
        record = Record::from_parts_unchecked(
            record.owner().clone(),
            Rtype::A,
            Rclass::ANY,
            Ttl::new(60).unwrap(),
            Rdata::empty_metavalue(Rtype::A),
        );
        message.add_authority(record);
        assert_eq!(
            UpdateRequest::from_message(&message).unwrap_err().rcode(),
            Rcode::FORMERR
        );
    }

    #[test]
    fn out_of_zone_name_is_notzone() {
        let mut message = base();
        message.add_authority(record(
            "www.other.test",
            Rtype::A,
            Rclass::IN,
            300,
            Rdata::A("192.0.2.1".parse().unwrap()),
        ));
        assert_eq!(
            UpdateRequest::from_message(&message).unwrap_err().rcode(),
            Rcode::NOTZONE
        );
    }

    #[test]
    fn rejects_query_metatypes() {
        let mut message = base();
        message.add_authority(empty("www.example.com", Rtype::AXFR, Rclass::ANY));
        assert_eq!(
            UpdateRequest::from_message(&message).unwrap_err().rcode(),
            Rcode::FORMERR
        );
    }

    #[test]
    fn response_echoes_zone_and_rcode() {
        let request = UpdateRequest::from_message(&base()).unwrap();
        let response = request.response(Rcode::NXRRSET);
        assert_eq!(response.id(), 0x4242);
        assert_eq!(response.opcode(), Opcode::UPDATE);
        assert_eq!(response.rcode(), Rcode::NXRRSET);
        assert_eq!(response.questions().len(), 1);
        assert_eq!(response.questions()[0].qname(), &zone());
        assert_eq!(response.questions()[0].qtype(), Rtype::SOA);
    }

    #[test]
    fn accepts_unknown_rdata_and_aaaa() {
        let mut message = base();
        message.add_authority(record(
            "v6.example.com",
            Rtype::AAAA,
            Rclass::IN,
            60,
            Rdata::Aaaa("2001:db8::1".parse().unwrap()),
        ));
        message.add_authority(record(
            "x.example.com",
            Rtype::from_u16(65280),
            Rclass::IN,
            60,
            Rdata::unknown(Rtype::from_u16(65280), vec![1, 2, 3]).unwrap(),
        ));
        let request = UpdateRequest::from_message(&message).unwrap();
        assert_eq!(request.updates().len(), 2);
    }

    #[test]
    fn soa_add_is_accepted_at_apex() {
        let mut message = base();
        message.add_authority(record(
            "example.com",
            Rtype::SOA,
            Rclass::IN,
            3600,
            Rdata::Soa(SoaData::new(
                Name::parse("ns1.example.com").unwrap(),
                Name::parse("hostmaster.example.com").unwrap(),
                crate::domain::Serial::new(2),
                3600,
                600,
                86_400,
                300,
            )),
        ));
        let request = UpdateRequest::from_message(&message).unwrap();
        assert_eq!(request.updates().len(), 1);
    }
}
