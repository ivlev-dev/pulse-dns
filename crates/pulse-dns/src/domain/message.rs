//! DNS-сообщение, заголовок и EDNS0 (`domain-model.md` §2, RFC 1035/6891).

use std::io::Write;

use thiserror::Error;

use super::question::Question;
use super::record::Record;
use super::rr::{Opcode, Rcode};
use crate::wire::{DecodeError, DecodeLimits, EncodeError, EncodeOptions};

/// Ошибка конструирования EDNS0-опции.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EdnsError {
    /// Данные опции длиннее 65535.
    #[error("edns option data is {len} octets long (max 65535)")]
    TooLong {
        /// Фактическая длина.
        len: usize,
    },
    /// Слишком много опций (не более 65535 / 4).
    #[error("too many edns options: {count}")]
    TooManyOptions {
        /// Количество опций.
        count: usize,
    },
}

/// Флаги заголовка DNS (биты 0…15, RFC 1035 §4.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Flags(u16);

impl Flags {
    /// Пустой набор флагов.
    #[must_use]
    pub const fn new() -> Self {
        Self(0)
    }

    /// Создаёт флаги из сырых битов.
    #[must_use]
    pub const fn from_bits(bits: u16) -> Self {
        Self(bits)
    }

    /// Сырые биты.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// QR: это ответ.
    #[must_use]
    pub const fn qr(self) -> bool {
        self.0 & 0x8000 != 0
    }

    /// Opcode.
    #[must_use]
    pub const fn opcode(self) -> Opcode {
        let [_, high] = self.0.to_le_bytes();
        Opcode::from_u8((high >> 3) & 0x0F)
    }

    /// AA: authoritative answer.
    #[must_use]
    pub const fn aa(self) -> bool {
        self.0 & 0x0400 != 0
    }

    /// TC: truncated.
    #[must_use]
    pub const fn tc(self) -> bool {
        self.0 & 0x0200 != 0
    }

    /// RD: recursion desired.
    #[must_use]
    pub const fn rd(self) -> bool {
        self.0 & 0x0100 != 0
    }

    /// RA: recursion available.
    #[must_use]
    pub const fn ra(self) -> bool {
        self.0 & 0x0080 != 0
    }

    /// Z: зарезервированный бит.
    #[must_use]
    pub const fn z(self) -> bool {
        self.0 & 0x0040 != 0
    }

    /// AD: authenticated data.
    #[must_use]
    pub const fn ad(self) -> bool {
        self.0 & 0x0020 != 0
    }

    /// CD: checking disabled.
    #[must_use]
    pub const fn cd(self) -> bool {
        self.0 & 0x0010 != 0
    }

    /// Младшие 4 бита RCODE из заголовка.
    #[must_use]
    pub const fn rcode_bits(self) -> u8 {
        let [low, _] = self.0.to_le_bytes();
        low & 0x0F
    }

    /// Устанавливает QR.
    #[must_use]
    pub const fn with_qr(mut self, value: bool) -> Self {
        self.set_bit(0x8000, value);
        self
    }

    /// Устанавливает Opcode.
    #[must_use]
    pub fn with_opcode(mut self, opcode: Opcode) -> Self {
        self.0 = (self.0 & !0x7800) | (u16::from(opcode.as_u8() & 0x0F) << 11);
        self
    }

    /// Устанавливает AA.
    #[must_use]
    pub const fn with_aa(mut self, value: bool) -> Self {
        self.set_bit(0x0400, value);
        self
    }

    /// Устанавливает TC.
    #[must_use]
    pub const fn with_tc(mut self, value: bool) -> Self {
        self.set_bit(0x0200, value);
        self
    }

    /// Устанавливает RD.
    #[must_use]
    pub const fn with_rd(mut self, value: bool) -> Self {
        self.set_bit(0x0100, value);
        self
    }

    /// Устанавливает RA.
    #[must_use]
    pub const fn with_ra(mut self, value: bool) -> Self {
        self.set_bit(0x0080, value);
        self
    }

    /// Устанавливает AD.
    #[must_use]
    pub const fn with_ad(mut self, value: bool) -> Self {
        self.set_bit(0x0020, value);
        self
    }

    /// Устанавливает CD.
    #[must_use]
    pub const fn with_cd(mut self, value: bool) -> Self {
        self.set_bit(0x0010, value);
        self
    }

    /// Устанавливает младшие 4 бита RCODE.
    #[must_use]
    pub fn with_rcode_bits(mut self, value: u8) -> Self {
        self.set_rcode_low(value);
        self
    }

    /// Устанавливает младшие 4 бита RCODE.
    pub(crate) fn set_rcode_low(&mut self, value: u8) {
        self.0 = (self.0 & !0x000F) | u16::from(value & 0x0F);
    }

    const fn set_bit(&mut self, mask: u16, value: bool) {
        if value {
            self.0 |= mask;
        } else {
            self.0 &= !mask;
        }
    }
}

/// Заголовок DNS-сообщения (RFC 1035 §4.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Header {
    id: u16,
    flags: Flags,
    question_count: u16,
    answer_count: u16,
    authority_count: u16,
    additional_count: u16,
}

impl Header {
    /// Создаёт заголовок из полей.
    #[must_use]
    pub const fn new(
        id: u16,
        flags: Flags,
        question_count: u16,
        answer_count: u16,
        authority_count: u16,
        additional_count: u16,
    ) -> Self {
        Self {
            id,
            flags,
            question_count,
            answer_count,
            authority_count,
            additional_count,
        }
    }

    /// ID сообщения.
    #[must_use]
    pub const fn id(&self) -> u16 {
        self.id
    }

    /// Флаги.
    #[must_use]
    pub const fn flags(&self) -> Flags {
        self.flags
    }

    /// QDCOUNT.
    #[must_use]
    pub const fn question_count(&self) -> u16 {
        self.question_count
    }

    /// ANCOUNT.
    #[must_use]
    pub const fn answer_count(&self) -> u16 {
        self.answer_count
    }

    /// NSCOUNT.
    #[must_use]
    pub const fn authority_count(&self) -> u16 {
        self.authority_count
    }

    /// ARCOUNT.
    #[must_use]
    pub const fn additional_count(&self) -> u16 {
        self.additional_count
    }
}

/// EDNS0-опция (RFC 6891 §6.1.2), значение непрозрачно.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EdnsOption {
    code: u16,
    data: Vec<u8>,
}

impl EdnsOption {
    /// Создаёт опцию.
    ///
    /// # Errors
    ///
    /// [`EdnsError::TooLong`], если данные больше 65535.
    pub fn new(code: u16, data: impl Into<Vec<u8>>) -> Result<Self, EdnsError> {
        let data = data.into();
        if data.len() > usize::from(u16::MAX) {
            return Err(EdnsError::TooLong { len: data.len() });
        }
        Ok(Self { code, data })
    }

    /// Код опции.
    #[must_use]
    pub const fn code(&self) -> u16 {
        self.code
    }

    /// Данные опции.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

/// EDNS0 (OPT pseudo-record, RFC 6891).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Edns {
    udp_payload_size: u16,
    extended_rcode: u8,
    version: u8,
    flags: u16,
    options: Vec<EdnsOption>,
}

impl Edns {
    /// Создаёт EDNS с указанным UDP payload size и без опций.
    #[must_use]
    pub const fn new(udp_payload_size: u16) -> Self {
        Self {
            udp_payload_size,
            extended_rcode: 0,
            version: 0,
            flags: 0,
            options: Vec::new(),
        }
    }

    /// UDP payload size (поле CLASS).
    #[must_use]
    pub const fn udp_payload_size(&self) -> u16 {
        self.udp_payload_size
    }

    /// Расширенный RCODE (старшие 8 бит).
    #[must_use]
    pub const fn extended_rcode(&self) -> u8 {
        self.extended_rcode
    }

    /// EDNS version.
    #[must_use]
    pub const fn version(&self) -> u8 {
        self.version
    }

    /// Сырые флаги EDNS.
    #[must_use]
    pub const fn flags(&self) -> u16 {
        self.flags
    }

    /// DO-бит.
    #[must_use]
    pub const fn dnssec_ok(&self) -> bool {
        self.flags & 0x8000 != 0
    }

    /// Опции в порядке wire-формата.
    #[must_use]
    pub fn options(&self) -> &[EdnsOption] {
        &self.options
    }

    /// Устанавливает UDP payload size.
    #[must_use]
    pub const fn with_udp_payload_size(mut self, size: u16) -> Self {
        self.udp_payload_size = size;
        self
    }

    /// Устанавливает DO-бит.
    #[must_use]
    pub const fn with_dnssec_ok(mut self, value: bool) -> Self {
        if value {
            self.flags |= 0x8000;
        } else {
            self.flags &= !0x8000;
        }
        self
    }

    /// Устанавливает расширенный RCODE.
    #[must_use]
    pub const fn with_extended_rcode(mut self, value: u8) -> Self {
        self.extended_rcode = value;
        self
    }

    /// Устанавливает версию EDNS.
    #[must_use]
    pub const fn with_version(mut self, value: u8) -> Self {
        self.version = value;
        self
    }

    /// Устанавливает сырые флаги EDNS (DO-бит — 0x8000).
    #[must_use]
    pub const fn with_flags(mut self, value: u16) -> Self {
        self.flags = value;
        self
    }

    /// Добавляет опцию.
    ///
    /// # Errors
    ///
    /// [`EdnsError::TooManyOptions`] при переполнении счётчика.
    pub fn push_option(&mut self, option: EdnsOption) -> Result<(), EdnsError> {
        if self.options.len() >= usize::from(u16::MAX) / 4 {
            return Err(EdnsError::TooManyOptions {
                count: self.options.len() + 1,
            });
        }
        self.options.push(option);
        Ok(())
    }
}

/// DNS-сообщение.
///
/// Секция additional не содержит OPT: EDNS0 представлен отдельным полем
/// [`Message::edns`] и кодируется/декодируется прозрачно.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    id: u16,
    flags: Flags,
    questions: Vec<Question>,
    answers: Vec<Record>,
    authority: Vec<Record>,
    additional: Vec<Record>,
    edns: Option<Edns>,
}

impl Message {
    /// Создаёт пустое сообщение.
    #[must_use]
    pub const fn new(id: u16, flags: Flags) -> Self {
        Self {
            id,
            flags,
            questions: Vec::new(),
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
            edns: None,
        }
    }

    /// Создаёт запрос с одним вопросом и без флагов.
    #[must_use]
    pub fn query(id: u16, question: Question) -> Self {
        let mut message = Self::new(id, Flags::new());
        message.questions.push(question);
        message
    }

    /// Создаёт ответ-заготовку на запрос: копирует ID, вопрос, opcode,
    /// RD и CD; выставляет QR.
    #[must_use]
    pub fn response(request: &Self) -> Self {
        let flags = Flags::new()
            .with_qr(true)
            .with_opcode(request.flags.opcode())
            .with_rd(request.flags.rd())
            .with_cd(request.flags.cd());
        let mut message = Self::new(request.id, flags);
        message.questions.clone_from(&request.questions);
        message
    }

    /// ID.
    #[must_use]
    pub const fn id(&self) -> u16 {
        self.id
    }

    /// Устанавливает ID.
    pub const fn set_id(&mut self, id: u16) {
        self.id = id;
    }

    /// Флаги.
    #[must_use]
    pub const fn flags(&self) -> Flags {
        self.flags
    }

    /// Устанавливает флаги целиком.
    pub const fn set_flags(&mut self, flags: Flags) {
        self.flags = flags;
    }

    /// Opcode.
    #[must_use]
    pub const fn opcode(&self) -> Opcode {
        self.flags.opcode()
    }

    /// Устанавливает opcode.
    pub fn set_opcode(&mut self, opcode: Opcode) {
        self.flags = self.flags.with_opcode(opcode);
    }

    /// Полный RCODE (заголовок + extended bits EDNS0).
    #[must_use]
    pub fn rcode(&self) -> Rcode {
        let low = u16::from(self.flags.rcode_bits());
        let extended = self
            .edns
            .as_ref()
            .map_or(0, |edns| u16::from(edns.extended_rcode) << 4);
        Rcode::from_u16(extended | low)
    }

    /// Устанавливает RCODE; для значений >15 автоматически включает/правит
    /// OPT (с payload 1232, если OPT ещё не было).
    pub fn set_rcode(&mut self, rcode: Rcode) {
        self.flags.set_rcode_low(rcode.header_bits());
        let extended = rcode.extended_bits();
        if extended == 0 {
            if let Some(edns) = &mut self.edns {
                edns.extended_rcode = 0;
            }
            return;
        }
        if let Some(edns) = &mut self.edns {
            edns.extended_rcode = extended;
        } else {
            let mut edns = Edns::new(1232);
            edns.extended_rcode = extended;
            self.edns = Some(edns);
        }
    }

    /// EDNS0, если присутствует.
    #[must_use]
    pub const fn edns(&self) -> Option<&Edns> {
        self.edns.as_ref()
    }

    /// Устанавливает/удаляет EDNS0.
    pub fn set_edns(&mut self, edns: Option<Edns>) {
        self.edns = edns;
    }

    /// Вопросы.
    #[must_use]
    pub fn questions(&self) -> &[Question] {
        &self.questions
    }

    /// Ответы.
    #[must_use]
    pub fn answers(&self) -> &[Record] {
        &self.answers
    }

    /// Authority.
    #[must_use]
    pub fn authority(&self) -> &[Record] {
        &self.authority
    }

    /// Additional (без OPT).
    #[must_use]
    pub fn additional(&self) -> &[Record] {
        &self.additional
    }

    /// Добавляет вопрос.
    pub fn add_question(&mut self, question: Question) {
        self.questions.push(question);
    }

    /// Добавляет ответ.
    pub fn add_answer(&mut self, record: Record) {
        self.answers.push(record);
    }

    /// Добавляет запись в authority.
    pub fn add_authority(&mut self, record: Record) {
        self.authority.push(record);
    }

    /// Добавляет запись в additional.
    pub fn add_additional(&mut self, record: Record) {
        self.additional.push(record);
    }

    /// Заголовок с актуальными счётчиками секций.
    #[must_use]
    pub fn header(&self) -> Header {
        Header::new(
            self.id,
            self.flags,
            count_u16(self.questions.len()),
            count_u16(self.answers.len()),
            count_u16(self.authority.len()),
            count_u16(self.additional.len() + usize::from(self.edns.is_some())),
        )
    }

    /// Кодирует сообщение в wire-формат.
    ///
    /// # Errors
    ///
    /// [`EncodeError`] при превышении лимитов или ошибке записи.
    pub fn encode(&self, options: &EncodeOptions) -> Result<Vec<u8>, EncodeError> {
        crate::wire::encode::encode_message(self, *options)
    }

    /// Кодирует сообщение прямо в переданный срез (компрессия включена).
    ///
    /// Не аллоцирует память: таблица компрессии создаётся на стеке.
    /// Возвращает длину записанного сообщения.
    ///
    /// # Errors
    ///
    /// [`EncodeError::BufferTooSmall`], если `out` меньше сообщения;
    /// [`EncodeError::MessageTooLong`], если сообщение длиннее 65535 октетов;
    /// прочие [`EncodeError`] при некорректных данных.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, EncodeError> {
        self.encode_into_with(out, &EncodeOptions::compressed())
    }

    /// То же, что [`Message::encode_into`], с явными опциями кодирования.
    ///
    /// # Errors
    ///
    /// См. [`Message::encode_into`].
    pub fn encode_into_with(
        &self,
        out: &mut [u8],
        options: &EncodeOptions,
    ) -> Result<usize, EncodeError> {
        let mut scratch = crate::wire::EncodeScratch::new();
        crate::wire::encode::encode_message_into(self, *options, out, &mut scratch)
    }

    /// Точная длина wire-формы без записи байтов (компрессия включена).
    ///
    /// # Errors
    ///
    /// [`EncodeError`] при превышении лимитов или некорректных данных.
    pub fn encoded_len(&self) -> Result<usize, EncodeError> {
        self.encoded_len_with(&EncodeOptions::compressed())
    }

    /// То же, что [`Message::encoded_len`], с явными опциями кодирования.
    ///
    /// # Errors
    ///
    /// См. [`Message::encoded_len`].
    pub fn encoded_len_with(&self, options: &EncodeOptions) -> Result<usize, EncodeError> {
        let mut scratch = crate::wire::EncodeScratch::new();
        crate::wire::encode::encoded_message_len(self, *options, &mut scratch)
    }

    /// Кодирует сообщение и записывает его в `out`.
    ///
    /// # Errors
    ///
    /// [`EncodeError`] при превышении лимитов или ошибке записи.
    pub fn encode_to(
        &self,
        out: &mut impl Write,
        options: &EncodeOptions,
    ) -> Result<usize, EncodeError> {
        let bytes = self.encode(options)?;
        out.write_all(&bytes)?;
        Ok(bytes.len())
    }

    /// Разбирает сообщение из wire-формата.
    ///
    /// # Errors
    ///
    /// [`DecodeError`] при любом нарушении формата.
    pub fn decode(bytes: &[u8], limits: &DecodeLimits) -> Result<Self, DecodeError> {
        crate::wire::decode::decode_message(bytes, *limits)
    }
}

fn count_u16(value: usize) -> u16 {
    u16::try_from(value).unwrap_or(u16::MAX)
}
