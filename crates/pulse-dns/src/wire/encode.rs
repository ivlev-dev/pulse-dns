//! Энкодер wire-формата: запись в caller-provided срез без аллокаций.
//!
//! Компрессия имён (RFC 1035 §4.1.4) использует маленькую линейную таблицу
//! суффиксов вместо `HashMap`: таблица и арена байтов живут в
//! [`EncodeScratch`], который переиспользуется между сообщениями. Таблица
//! ограничена; при переполнении новые суффиксы не регистрируются, поэтому
//! сообщение остаётся корректным, но может быть сжато слабее.
//!
//! [`Message::encode`](crate::Message::encode) сохраняет прежний контракт
//! (`Vec<u8>`), а [`Message::encode_into`](crate::Message::encode_into) пишет
//! сразу в буфер без промежуточного `Vec`.

use crate::domain::{Edns, Flags, Message, Name, Question, Rclass, Rdata, Record, Rtype, Ttl};
use crate::wire::{EncodeError, EncodeOptions, MAX_MESSAGE_LEN, MAX_RECORDS};

use super::rdata::{RdataOut, write_rdata};

/// Максимум суффиксов, отслеживаемых для компрессии в одном сообщении.
const COMPRESSION_ENTRIES: usize = 128;
/// Размер арены байтов для суффиксов компрессии.
const COMPRESSION_ARENA: usize = 4096;

/// Переиспользуемое состояние энкодера (таблица компрессии).
///
/// Держите один экземпляр на поток и передавайте его в
/// [`Encoder`] и [`Message::encode_into`](crate::Message::encode_into), чтобы
/// не аллоцировать на каждый ответ.
#[derive(Clone)]
pub struct EncodeScratch {
    table: CompressionTable,
}

impl EncodeScratch {
    /// Создаёт пустое состояние.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            table: CompressionTable::new(),
        }
    }

    /// Сбрасывает состояние перед новым сообщением.
    pub fn clear(&mut self) {
        self.table.clear();
    }
}

impl Default for EncodeScratch {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for EncodeScratch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EncodeScratch")
            .field("entries", &self.table.len)
            .field("arena_used", &self.table.used)
            .finish()
    }
}

/// Сохранённая позиция энкодера для отката частично записанной записи.
///
/// Используется вместе с [`Encoder::rollback`] для усечения ответа: запись,
/// которая не поместилась в лимит транспорта, откатывается вместе со своими
/// суффиксами компрессии.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checkpoint {
    len: usize,
    table_len: usize,
    arena_used: usize,
}

/// Счётчики секций для заголовка DNS-сообщения.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HeaderCounts {
    /// `QDCOUNT`.
    pub question: u16,
    /// `ANCOUNT`.
    pub answer: u16,
    /// `NSCOUNT`.
    pub authority: u16,
    /// `ARCOUNT` (включая OPT).
    pub additional: u16,
}

impl HeaderCounts {
    /// Считает секции сообщения, проверяя лимиты wire-формата.
    ///
    /// # Errors
    ///
    /// [`EncodeError::SectionTooLarge`], если секция или общее число записей
    /// превышают лимиты.
    pub fn from_message(message: &Message) -> Result<Self, EncodeError> {
        let question = count_u16("question", message.questions().len())?;
        let answer = count_u16("answer", message.answers().len())?;
        let authority = count_u16("authority", message.authority().len())?;
        let additional = count_u16(
            "additional",
            message
                .additional()
                .len()
                .saturating_add(usize::from(message.edns().is_some())),
        )?;
        let counts = Self {
            question,
            answer,
            authority,
            additional,
        };
        counts.validate()?;
        Ok(counts)
    }

    /// Проверяет лимиты `MAX_RECORDS`.
    ///
    /// # Errors
    ///
    /// [`EncodeError::SectionTooLarge`] при превышении лимита записей.
    pub fn validate(&self) -> Result<(), EncodeError> {
        let record_total = usize::from(self.answer)
            .saturating_add(usize::from(self.authority))
            .saturating_add(usize::from(self.additional));
        if record_total > MAX_RECORDS {
            return Err(EncodeError::SectionTooLarge {
                section: "records",
                count: record_total,
                max: MAX_RECORDS,
            });
        }
        if usize::from(self.question) > MAX_RECORDS {
            return Err(EncodeError::SectionTooLarge {
                section: "question",
                count: usize::from(self.question),
                max: MAX_RECORDS,
            });
        }
        Ok(())
    }
}

/// Куда пишет [`Encoder`].
enum Target<'a> {
    Slice { out: &'a mut [u8], pos: usize },
    Vec(Vec<u8>),
    Count { pos: usize },
}

/// Потоковый wire-энкодер.
///
/// Позволяет собрать сообщение по частям (вопрос, записи, OPT) прямо в
/// переданный срез, без `Vec<u8>` и без `HashMap`. Заголовок резервируется
/// [`Encoder::begin_message`] и заполняется [`Encoder::finish`], поэтому
/// счётчики и флаг `TC` можно выставить после усечения.
///
/// ```
/// use pulse_dns::{EncodeScratch, Flags, HeaderCounts, Message, Name, Question, Rclass, Rtype};
/// use pulse_dns::wire::Encoder;
///
/// let mut scratch = EncodeScratch::new();
/// let mut out = [0_u8; 64];
/// let mut encoder = Encoder::new(&mut out, pulse_dns::EncodeOptions::compressed(), &mut scratch);
/// encoder.begin_message(7).unwrap();
/// encoder
///     .write_question(&Question::new(
///         Name::parse("example.com").unwrap(),
///         Rtype::A,
///         Rclass::IN,
///     ))
///     .unwrap();
/// let len = encoder
///     .finish(Flags::new().with_qr(true), HeaderCounts { question: 1, ..HeaderCounts::default() })
///     .unwrap();
/// assert_eq!(len, 12 + 13 + 4);
/// ```
pub struct Encoder<'a> {
    target: Target<'a>,
    scratch: &'a mut EncodeScratch,
    compress: bool,
    overflowed: bool,
    required: usize,
}

impl<'a> Encoder<'a> {
    /// Создаёт энкодер, пишущий в `out`.
    ///
    /// Состояние компрессии в `scratch` сбрасывается: один экземпляр
    /// соответствует одному сообщению.
    pub fn new(out: &'a mut [u8], options: EncodeOptions, scratch: &'a mut EncodeScratch) -> Self {
        scratch.clear();
        Self {
            target: Target::Slice { out, pos: 0 },
            scratch,
            compress: options.compress_names,
            overflowed: false,
            required: 0,
        }
    }

    /// Создаёт энкодер, который только считает длину сообщения.
    ///
    /// Полезен для предварительной проверки лимита без записи байтов.
    pub fn counting(options: EncodeOptions, scratch: &'a mut EncodeScratch) -> Self {
        scratch.clear();
        Self {
            target: Target::Count { pos: 0 },
            scratch,
            compress: options.compress_names,
            overflowed: false,
            required: 0,
        }
    }

    /// Создаёт энкодер во владеющий `Vec` (используется [`Message::encode`]).
    pub fn to_vec(options: EncodeOptions, scratch: &'a mut EncodeScratch) -> Self {
        scratch.clear();
        Self {
            target: Target::Vec(Vec::with_capacity(512)),
            scratch,
            compress: options.compress_names,
            overflowed: false,
            required: 0,
        }
    }

    /// Текущая длина записанного сообщения.
    #[must_use]
    pub fn len(&self) -> usize {
        match &self.target {
            Target::Slice { pos, .. } | Target::Count { pos } => *pos,
            Target::Vec(out) => out.len(),
        }
    }

    /// Пустое ли сообщение (до записи заголовка).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Резервирует 12-байтовый заголовок с указанным ID.
    ///
    /// # Errors
    ///
    /// [`EncodeError::BufferTooSmall`], если в буфере нет 12 байт.
    pub fn begin_message(&mut self, id: u16) -> Result<(), EncodeError> {
        self.push(&id.to_be_bytes());
        self.push(&[0_u8; 10]);
        self.check_overflow()
    }

    /// Записывает вопрос.
    ///
    /// # Errors
    ///
    /// [`EncodeError::BufferTooSmall`] или [`EncodeError::MessageTooLong`].
    pub fn write_question(&mut self, question: &Question) -> Result<(), EncodeError> {
        self.write_question_wire(
            question.qname().as_wire(),
            question.qtype(),
            question.qclass(),
        )
    }

    /// Записывает вопрос из несжатой wire-формы имени.
    ///
    /// `qname` должен быть канонической wire-формой (нижний регистр,
    /// терминальный ноль) и проходить [`crate::NameRef::from_wire`] или
    /// [`crate::NameRef::from_name`].
    ///
    /// # Errors
    ///
    /// [`EncodeError::BufferTooSmall`] или [`EncodeError::MessageTooLong`].
    pub fn write_question_wire(
        &mut self,
        qname: &[u8],
        qtype: Rtype,
        qclass: Rclass,
    ) -> Result<(), EncodeError> {
        self.write_name_wire(qname, true);
        self.push(&qtype.as_u16().to_be_bytes());
        self.push(&qclass.as_u16().to_be_bytes());
        self.check_overflow()?;
        self.check_size()
    }

    /// Записывает полную запись, проверяя согласованность типа и RDATA.
    ///
    /// # Errors
    ///
    /// [`EncodeError`] при несоответствии типа, невалидной RDATA,
    /// превышении `RDLENGTH` или нехватке места в буфере.
    pub fn write_record(&mut self, record: &Record) -> Result<(), EncodeError> {
        self.write_rr(
            record.owner(),
            record.rr_type(),
            record.class(),
            record.ttl(),
            record.rdata(),
        )
    }

    /// Записывает RR без промежуточного [`Record`].
    ///
    /// # Errors
    ///
    /// [`EncodeError`] при несоответствии типа, невалидной RDATA,
    /// превышении `RDLENGTH` или нехватке места в буфере.
    pub fn write_rr(
        &mut self,
        owner: &Name,
        rr_type: Rtype,
        class: Rclass,
        ttl: Ttl,
        rdata: &Rdata,
    ) -> Result<(), EncodeError> {
        self.write_rr_wire_name(owner.as_wire(), rr_type, class, ttl, rdata)
    }

    /// Записывает RR с владельцем в несжатой wire-форме.
    ///
    /// `owner` должен быть канонической wire-формой; RDATA валидируется.
    ///
    /// # Errors
    ///
    /// [`EncodeError`] при несоответствии типа, невалидной RDATA,
    /// превышении `RDLENGTH` или нехватке места в буфере.
    pub fn write_rr_wire_name(
        &mut self,
        owner: &[u8],
        rr_type: Rtype,
        class: Rclass,
        ttl: Ttl,
        rdata: &Rdata,
    ) -> Result<(), EncodeError> {
        if rdata.rr_type() != rr_type {
            return Err(EncodeError::RecordTypeMismatch {
                declared: rr_type,
                actual: rdata.rr_type(),
            });
        }
        if let Err(source) = rdata.validate() {
            return Err(EncodeError::InvalidRdata { rr_type, source });
        }
        if self.overflowed {
            return Err(self.overflow_error());
        }
        self.write_name_wire(owner, true);
        self.push(&rr_type.as_u16().to_be_bytes());
        self.push(&class.as_u16().to_be_bytes());
        self.push(&ttl.as_u32().to_be_bytes());
        let length_position = self.len();
        self.push(&[0, 0]);
        let rdata_start = self.len();
        write_rdata(rdata, self);
        self.finish_rr(rr_type, length_position, rdata_start)
    }

    /// Записывает RR из уже сериализованной RDATA (zero-copy).
    ///
    /// Вызывающий гарантирует, что `rdata` — валидная wire-форма для
    /// `rr_type` (обычно это проверенные данные зоны). Имена внутри RDATA
    /// пишутся без компрессии; это корректная, но чуть менее компактная
    /// форма.
    ///
    /// # Errors
    ///
    /// [`EncodeError::RdataTooLong`] или [`EncodeError::BufferTooSmall`].
    pub fn write_rr_raw(
        &mut self,
        owner: &[u8],
        rr_type: Rtype,
        class: Rclass,
        ttl: Ttl,
        rdata: &[u8],
    ) -> Result<(), EncodeError> {
        if self.overflowed {
            return Err(self.overflow_error());
        }
        let Ok(length) = u16::try_from(rdata.len()) else {
            return Err(EncodeError::RdataTooLong {
                rr_type,
                len: rdata.len(),
            });
        };
        self.write_name_wire(owner, true);
        self.push(&rr_type.as_u16().to_be_bytes());
        self.push(&class.as_u16().to_be_bytes());
        self.push(&ttl.as_u32().to_be_bytes());
        self.push(&length.to_be_bytes());
        self.push(rdata);
        self.check_size()
    }

    fn finish_rr(
        &mut self,
        rr_type: Rtype,
        length_position: usize,
        rdata_start: usize,
    ) -> Result<(), EncodeError> {
        if self.overflowed {
            return Err(self.overflow_error());
        }
        let rdata_length = self.len().saturating_sub(rdata_start);
        let Ok(length) = u16::try_from(rdata_length) else {
            return Err(EncodeError::RdataTooLong {
                rr_type,
                len: rdata_length,
            });
        };
        self.patch_u16(length_position, length)?;
        self.check_size()
    }

    /// Записывает OPT-псевдозапись EDNS0.
    ///
    /// # Errors
    ///
    /// [`EncodeError::SectionTooLarge`] для слишком длинной опции,
    /// [`EncodeError::BufferTooSmall`] при нехватке места.
    pub fn write_edns(&mut self, edns: &Edns) -> Result<(), EncodeError> {
        if self.overflowed {
            return Err(self.overflow_error());
        }
        self.push(&[0]);
        self.push(&Rtype::OPT.as_u16().to_be_bytes());
        self.push(&edns.udp_payload_size().to_be_bytes());
        let ttl = (u32::from(edns.extended_rcode()) << 24)
            | (u32::from(edns.version()) << 16)
            | u32::from(edns.flags());
        self.push(&ttl.to_be_bytes());
        let length_position = self.len();
        self.push(&[0, 0]);
        let rdata_start = self.len();
        for option in edns.options() {
            self.push(&option.code().to_be_bytes());
            let length =
                u16::try_from(option.data().len()).map_err(|_| EncodeError::SectionTooLarge {
                    section: "edns option",
                    count: option.data().len(),
                    max: usize::from(u16::MAX),
                })?;
            self.push(&length.to_be_bytes());
            self.push(option.data());
            if self.overflowed {
                return Err(self.overflow_error());
            }
            self.check_size()?;
        }
        let rdata_length = self.len().saturating_sub(rdata_start);
        let Ok(length) = u16::try_from(rdata_length) else {
            return Err(EncodeError::SectionTooLarge {
                section: "edns options",
                count: rdata_length,
                max: usize::from(u16::MAX),
            });
        };
        self.patch_u16(length_position, length)?;
        self.check_size()
    }

    /// Сохраняет текущую позицию для возможного отката.
    #[must_use]
    pub fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            len: self.len(),
            table_len: self.scratch.table.len,
            arena_used: self.scratch.table.used,
        }
    }

    /// Откатывает энкодер к сохранённой позиции.
    ///
    /// Байты за новой длиной остаются в буфере, но считаются свободными;
    /// суффиксы компрессии, зарегистрированные после точки сохранения,
    /// отбрасываются.
    pub fn rollback(&mut self, checkpoint: Checkpoint) {
        match &mut self.target {
            Target::Slice { pos, .. } | Target::Count { pos } => {
                *pos = checkpoint.len.min(*pos);
            }
            Target::Vec(out) => {
                out.truncate(checkpoint.len);
            }
        }
        self.scratch.table.len = checkpoint.table_len.min(self.scratch.table.len);
        self.scratch.table.used = checkpoint.arena_used.min(self.scratch.table.used);
        self.overflowed = false;
    }

    /// Завершает сообщение: проверяет лимиты и записывает флаги и счётчики.
    ///
    /// Возвращает длину сообщения в байтах.
    ///
    /// # Errors
    ///
    /// [`EncodeError::SectionTooLarge`] при превышении числа записей,
    /// [`EncodeError::MessageTooLong`] при длине больше 65535,
    /// [`EncodeError::BufferTooSmall`] при нехватке места в буфере.
    pub fn finish(&mut self, flags: Flags, counts: HeaderCounts) -> Result<usize, EncodeError> {
        self.check_overflow()?;
        counts.validate()?;
        self.patch(2, flags.bits().to_be_bytes())?;
        self.patch(4, counts.question.to_be_bytes())?;
        self.patch(6, counts.answer.to_be_bytes())?;
        self.patch(8, counts.authority.to_be_bytes())?;
        self.patch(10, counts.additional.to_be_bytes())?;
        self.check_size()?;
        Ok(self.len())
    }

    /// Возвращает собранный `Vec` (только для [`Encoder::to_vec`]).
    ///
    /// # Errors
    ///
    /// [`EncodeError::Internal`], если энкодер писал не в `Vec`.
    pub fn into_vec(self) -> Result<Vec<u8>, EncodeError> {
        match self.target {
            Target::Vec(out) => Ok(out),
            _ => Err(EncodeError::Internal {
                reason: "into_vec on non-vec encoder",
            }),
        }
    }

    fn push(&mut self, bytes: &[u8]) {
        if self.overflowed {
            return;
        }
        match &mut self.target {
            Target::Slice { out, pos } => {
                let end = pos.saturating_add(bytes.len());
                if let Some(slot) = out.get_mut(*pos..end) {
                    slot.copy_from_slice(bytes);
                    *pos = end;
                } else {
                    self.overflowed = true;
                    self.required = end.max(*pos);
                }
            }
            Target::Vec(out) => out.extend_from_slice(bytes),
            Target::Count { pos } => *pos = pos.saturating_add(bytes.len()),
        }
    }

    fn patch(&mut self, at: usize, bytes: [u8; 2]) -> Result<(), EncodeError> {
        if self.overflowed {
            return Err(self.overflow_error());
        }
        self.patch_u16(at, u16::from_be_bytes(bytes))
    }

    fn patch_u16(&mut self, at: usize, value: u16) -> Result<(), EncodeError> {
        let end = at.saturating_add(2);
        match &mut self.target {
            Target::Slice { out, pos } => {
                let Some(slot) = out.get_mut(at..end) else {
                    self.overflowed = true;
                    self.required = end.max(*pos);
                    return Err(self.overflow_error());
                };
                slot.copy_from_slice(&value.to_be_bytes());
            }
            Target::Vec(out) => {
                let Some(slot) = out.get_mut(at..end) else {
                    return Err(EncodeError::Internal {
                        reason: "header patch outside buffer",
                    });
                };
                slot.copy_from_slice(&value.to_be_bytes());
            }
            Target::Count { pos } => {
                if end > *pos {
                    return Err(EncodeError::Internal {
                        reason: "header patch outside counted message",
                    });
                }
            }
        }
        Ok(())
    }

    fn check_overflow(&self) -> Result<(), EncodeError> {
        if self.overflowed {
            return Err(self.overflow_error());
        }
        Ok(())
    }

    fn overflow_error(&self) -> EncodeError {
        match &self.target {
            Target::Slice { out, .. } => EncodeError::BufferTooSmall {
                capacity: out.len(),
                needed: self.required,
            },
            _ => EncodeError::Internal {
                reason: "encoder overflow without slice target",
            },
        }
    }

    fn check_size(&self) -> Result<(), EncodeError> {
        if self.len() > MAX_MESSAGE_LEN {
            return Err(EncodeError::MessageTooLong { len: self.len() });
        }
        Ok(())
    }

    fn write_name(&mut self, name: &Name, compressible: bool) {
        self.write_name_wire(name.as_wire(), compressible);
    }

    fn write_name_wire(&mut self, wire: &[u8], compressible: bool) {
        if self.overflowed {
            return;
        }
        if !self.compress || !compressible {
            self.push(wire);
            return;
        }

        // Ищем самый длинный суффикс, уже встречавшийся в сообщении.
        let mut chosen: Option<(usize, u16)> = None;
        let mut position = 0_usize;
        while let Some(&length) = wire.get(position) {
            if length == 0 {
                break;
            }
            let Some(suffix) = wire.get(position..) else {
                break;
            };
            if let Some(target) = self.scratch.table.find(suffix) {
                chosen = Some((position, target));
                break;
            }
            position = position.saturating_add(1 + usize::from(length));
        }

        let output_start = self.len();
        let prefix_end = chosen.map_or(wire.len(), |(offset, _)| offset);
        if output_start < 0x4000 {
            let mut offset = 0_usize;
            while offset < prefix_end {
                let Some(&length) = wire.get(offset) else {
                    break;
                };
                if length == 0 {
                    break;
                }
                if let Some(suffix) = wire.get(offset..) {
                    self.scratch
                        .table
                        .register(suffix, output_start.saturating_add(offset));
                }
                offset = offset.saturating_add(1 + usize::from(length));
            }
        }

        if let Some(prefix) = wire.get(..prefix_end) {
            self.push(prefix);
        } else {
            self.push(wire);
        }
        if let Some((_, target)) = chosen {
            self.push(&(0xC000_u16 | target).to_be_bytes());
        }
    }
}

impl RdataOut for Encoder<'_> {
    fn bytes(&mut self, value: &[u8]) {
        self.push(value);
    }

    fn name(&mut self, name: &Name, compressible: bool) {
        self.write_name(name, compressible);
    }
}

/// Таблица суффиксов для компрессии: линейный поиск, без хешей и аллокаций.
#[derive(Clone)]
struct CompressionTable {
    entries: [Entry; COMPRESSION_ENTRIES],
    len: usize,
    arena: [u8; COMPRESSION_ARENA],
    used: usize,
}

#[derive(Clone, Copy)]
struct Entry {
    /// Абсолютное смещение суффикса в выходном сообщении.
    out: u16,
    /// Начало суффикса в арене.
    start: u16,
    /// Длина суффикса в арене.
    len: u8,
}

const EMPTY_ENTRY: Entry = Entry {
    out: 0,
    start: 0,
    len: 0,
};

impl CompressionTable {
    const fn new() -> Self {
        Self {
            entries: [EMPTY_ENTRY; COMPRESSION_ENTRIES],
            len: 0,
            arena: [0_u8; COMPRESSION_ARENA],
            used: 0,
        }
    }

    fn clear(&mut self) {
        self.len = 0;
        self.used = 0;
    }

    fn find(&self, suffix: &[u8]) -> Option<u16> {
        for entry in self.entries.iter().take(self.len) {
            let start = usize::from(entry.start);
            let end = start.saturating_add(usize::from(entry.len));
            if self.arena.get(start..end) == Some(suffix) {
                return Some(entry.out);
            }
        }
        None
    }

    fn register(&mut self, suffix: &[u8], absolute: usize) {
        if absolute >= 0x4000 || self.len >= COMPRESSION_ENTRIES {
            return;
        }
        let Ok(out) = u16::try_from(absolute) else {
            return;
        };
        let Ok(len) = u8::try_from(suffix.len()) else {
            return;
        };
        let Some(end) = self.used.checked_add(suffix.len()) else {
            return;
        };
        if end > COMPRESSION_ARENA {
            return;
        }
        let Some(slot) = self.arena.get_mut(self.used..end) else {
            return;
        };
        slot.copy_from_slice(suffix);
        let Ok(start) = u16::try_from(self.used) else {
            return;
        };
        if let Some(entry) = self.entries.get_mut(self.len) {
            *entry = Entry { out, start, len };
            self.len += 1;
            self.used = end;
        }
    }
}

/// Кодирует сообщение в новый `Vec<u8>` (прежний контракт [`Message::encode`]).
pub(crate) fn encode_message(
    message: &Message,
    options: EncodeOptions,
) -> Result<Vec<u8>, EncodeError> {
    let counts = HeaderCounts::from_message(message)?;
    let mut scratch = EncodeScratch::new();
    let mut encoder = Encoder::to_vec(options, &mut scratch);
    encode_body(&mut encoder, message, counts)?;
    encoder.into_vec()
}

/// Кодирует сообщение в caller-provided срез без аллокаций.
pub(crate) fn encode_message_into(
    message: &Message,
    options: EncodeOptions,
    out: &mut [u8],
    scratch: &mut EncodeScratch,
) -> Result<usize, EncodeError> {
    let counts = HeaderCounts::from_message(message)?;
    let mut encoder = Encoder::new(out, options, scratch);
    encode_body(&mut encoder, message, counts)
}

/// Считает длину wire-формы без записи байтов.
pub(crate) fn encoded_message_len(
    message: &Message,
    options: EncodeOptions,
    scratch: &mut EncodeScratch,
) -> Result<usize, EncodeError> {
    let counts = HeaderCounts::from_message(message)?;
    let mut encoder = Encoder::counting(options, scratch);
    encode_body(&mut encoder, message, counts)
}

fn encode_body(
    encoder: &mut Encoder<'_>,
    message: &Message,
    counts: HeaderCounts,
) -> Result<usize, EncodeError> {
    encoder.begin_message(message.id())?;
    for question in message.questions() {
        encoder.write_question(question)?;
    }
    for record in message.answers() {
        encoder.write_record(record)?;
    }
    for record in message.authority() {
        encoder.write_record(record)?;
    }
    for record in message.additional() {
        encoder.write_record(record)?;
    }
    if let Some(edns) = message.edns() {
        encoder.write_edns(edns)?;
    }
    encoder.finish(message.flags(), counts)
}

/// Длина OPT-записи в wire-форме (без компрессии имени — оно корневое).
///
/// # Errors
///
/// [`EncodeError::SectionTooLarge`], если опция или суммарная RDATA не
/// помещаются в 16 бит.
pub fn edns_wire_len(edns: &Edns) -> Result<usize, EncodeError> {
    const FIXED: usize = 1 + 2 + 2 + 4 + 2;
    let mut total = FIXED;
    for option in edns.options() {
        let length =
            u16::try_from(option.data().len()).map_err(|_| EncodeError::SectionTooLarge {
                section: "edns option",
                count: option.data().len(),
                max: usize::from(u16::MAX),
            })?;
        total = total
            .checked_add(4)
            .and_then(|value| value.checked_add(usize::from(length)))
            .ok_or(EncodeError::SectionTooLarge {
                section: "edns options",
                count: usize::MAX,
                max: usize::from(u16::MAX),
            })?;
    }
    let rdata_length = total.saturating_sub(FIXED);
    if rdata_length > usize::from(u16::MAX) {
        return Err(EncodeError::SectionTooLarge {
            section: "edns options",
            count: rdata_length,
            max: usize::from(u16::MAX),
        });
    }
    Ok(total)
}

fn count_u16(section: &'static str, count: usize) -> Result<u16, EncodeError> {
    u16::try_from(count).map_err(|_| EncodeError::SectionTooLarge {
        section,
        count,
        max: usize::from(u16::MAX),
    })
}

#[cfg(test)]
mod tests {
    use super::{EncodeScratch, Encoder, HeaderCounts, edns_wire_len};
    use crate::domain::{Edns, EdnsOption, Flags, Name, Rclass, Rdata, Rtype};
    use crate::wire::EncodeOptions;

    #[test]
    fn compression_offsets_are_14_bit() {
        let mut scratch = EncodeScratch::new();
        scratch.table.register(b"\x01a\x00", 0x3FFF);
        assert_eq!(scratch.table.find(b"\x01a\x00"), Some(0x3FFF));

        scratch.table.register(b"\x01b\x00", 0x4000);
        assert_eq!(scratch.table.find(b"\x01b\x00"), None);
    }

    #[test]
    fn table_overflow_degrades_but_keeps_entries() {
        let mut scratch = EncodeScratch::new();
        for index in 0..(super::COMPRESSION_ENTRIES + 8) {
            let name = [1, u8::try_from(index % 200).unwrap_or(0), 0];
            scratch.table.register(&name, index);
        }
        assert_eq!(scratch.table.len, super::COMPRESSION_ENTRIES);
    }

    #[test]
    fn edns_length_matches_encoder() {
        let mut edns = Edns::new(1232).with_dnssec_ok(true);
        edns.push_option(EdnsOption::new(10, vec![1, 2, 3]).unwrap())
            .unwrap();
        edns.push_option(EdnsOption::new(12, vec![4]).unwrap())
            .unwrap();
        let expected = edns_wire_len(&edns).unwrap();
        let mut scratch = EncodeScratch::new();
        let mut out = [0_u8; 128];
        let mut encoder = Encoder::new(&mut out, EncodeOptions::compressed(), &mut scratch);
        encoder.begin_message(0).unwrap();
        encoder.write_edns(&edns).unwrap();
        let len = encoder
            .finish(Flags::new(), HeaderCounts::default())
            .unwrap();
        assert_eq!(len, 12 + expected);
    }

    #[test]
    fn rollback_restores_position_and_table() {
        let mut scratch = EncodeScratch::new();
        let mut out = [0_u8; 128];
        let mut encoder = Encoder::new(&mut out, EncodeOptions::compressed(), &mut scratch);
        encoder.begin_message(1).unwrap();
        let checkpoint = encoder.checkpoint();
        encoder
            .write_rr(
                &Name::parse("example.com").unwrap(),
                Rtype::A,
                Rclass::IN,
                crate::domain::Ttl::new(300).unwrap(),
                &Rdata::A([192, 0, 2, 1].into()),
            )
            .unwrap();
        assert!(encoder.len() > checkpoint.len);
        encoder.rollback(checkpoint);
        assert_eq!(encoder.len(), checkpoint.len);
        assert_eq!(scratch.table.len, checkpoint.table_len);
    }
}
