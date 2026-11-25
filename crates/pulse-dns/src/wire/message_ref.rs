//! Zero-copy представление простого DNS-запроса.
//!
//! [`MessageRef`] разбирает заголовок и единственный вопрос **без аллокаций**
//! и без `Vec`: `QNAME` копируется в стековый буфер и канонизируется, а
//! `QTYPE`/`QCLASS` возвращаются как value-типы. Это горячий путь UDP:
//! полноценный [`crate::Message`] нужен только для запросов, которые не
//! помещаются в простое представление (несколько вопросов, сжатый `QNAME`,
//! записи в секциях ответа). Один OPT в additional разбирается
//! [`MessageRef::decode_simple_edns`].
//!
//! `MessageRef` намеренно не является универсальным декодером: `None` из
//! [`MessageRef::decode_simple`] означает «разберите пакет полным
//! [`crate::Message::decode`]». Такая граница гарантирует, что быстрый путь не
//! принимает пакет, который полноценный декодер отверг бы.

use crate::domain::{Flags, MAX_LABELS, MAX_NAME_WIRE_LEN, NameRef, Opcode, Rclass, Rtype};

/// Заимствованное представление EDNS0-запроса (RFC 6891).
///
/// Хранит только поля, нужные для ответа: payload, версию, DO-бит и
/// расширенный RCODE. Опции не копируются: быстрый путь их не отражает
/// (сервер отвечает пустым OPT, как и полный путь).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EdnsRef {
    payload: u16,
    extended_rcode: u8,
    version: u8,
    flags: u16,
}

impl EdnsRef {
    /// UDP payload size (поле CLASS OPT-записи).
    #[must_use]
    pub const fn udp_payload_size(self) -> u16 {
        self.payload
    }

    /// Расширенный RCODE (старшие 8 бит).
    #[must_use]
    pub const fn extended_rcode(self) -> u8 {
        self.extended_rcode
    }

    /// Версия EDNS.
    #[must_use]
    pub const fn version(self) -> u8 {
        self.version
    }

    /// DO-бит.
    #[must_use]
    pub const fn dnssec_ok(self) -> bool {
        self.flags & 0x8000 != 0
    }
}

/// Разобранный простой запрос (один вопрос).
#[derive(Clone, Copy)]
pub struct MessageRef<'a> {
    source: &'a [u8],
    id: u16,
    flags: Flags,
    /// Канонический `QNAME` в несжатой wire-форме.
    qname: [u8; MAX_NAME_WIRE_LEN],
    qname_len: usize,
    qtype: Rtype,
    qclass: Rclass,
    edns: Option<EdnsRef>,
}

impl core::fmt::Debug for MessageRef<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MessageRef")
            .field("id", &self.id)
            .field("qname", &self.qname())
            .field("qtype", &self.qtype)
            .field("qclass", &self.qclass)
            .field("edns", &self.edns)
            .finish_non_exhaustive()
    }
}

impl<'a> MessageRef<'a> {
    /// Разбирает простой запрос без аллокаций.
    ///
    /// Возвращает `None`, если пакет не является одиночным запросом с
    /// несжатым `QNAME`: тогда вызывающий обязан использовать полный
    /// [`crate::Message::decode`]. `None` также возвращается для любого
    /// повреждённого пакета — быстрый путь не подменяет валидацию.
    #[must_use]
    pub fn decode_simple(source: &'a [u8]) -> Option<Self> {
        Self::parse(source, false)
    }

    /// Разбирает простой запрос вместе с одним OPT в additional.
    ///
    /// Принимает те же пакеты, что и [`MessageRef::decode_simple`], плюс
    /// `ARCOUNT = 1`, где единственная запись — корректная OPT-псевдозапись в
    /// корневом владельце. Структура опций валидируется (длины и отсутствие
    /// сжатия в имени), но сами опции не сохраняются: быстрый путь отвечает
    /// пустым OPT, как и полный путь.
    #[must_use]
    pub fn decode_simple_edns(source: &'a [u8]) -> Option<Self> {
        Self::parse(source, true)
    }

    fn parse(source: &'a [u8], allow_edns: bool) -> Option<Self> {
        if source.len() < 12 || source.len() > crate::wire::MAX_MESSAGE_LEN {
            return None;
        }
        let id = read_u16(source, 0)?;
        let flags = Flags::from_bits(read_u16(source, 2)?);
        if flags.qr() || flags.opcode() != Opcode::QUERY {
            return None;
        }
        let additional_count = read_u16(source, 10)?;
        if read_u16(source, 4)? != 1
            || read_u16(source, 6)? != 0
            || read_u16(source, 8)? != 0
            || additional_count > 1
            || (additional_count == 1 && !allow_edns)
        {
            return None;
        }

        let mut qname = [0_u8; MAX_NAME_WIRE_LEN];
        let mut position = 12_usize;
        let mut written = 0_usize;
        let mut labels = 0_usize;
        loop {
            let octet = *source.get(position)?;
            position = position.saturating_add(1);
            if octet == 0 {
                let slot = qname.get_mut(written)?;
                *slot = 0;
                written = written.saturating_add(1);
                break;
            }
            // Сжатый QNAME: горячий путь его не обслуживает, отдаём полному
            // декодеру.
            if octet & 0xC0 != 0 {
                return None;
            }
            labels = labels.saturating_add(1);
            if labels > MAX_LABELS {
                return None;
            }
            let length = usize::from(octet);
            let end = position.checked_add(length)?;
            let label = source.get(position..end)?;
            let slot = qname.get_mut(written)?;
            *slot = octet;
            written = written.saturating_add(1);
            let dst = qname.get_mut(written..written + length)?;
            for (dst, src) in dst.iter_mut().zip(label) {
                *dst = src.to_ascii_lowercase();
            }
            written = written.saturating_add(length);
            if written > MAX_NAME_WIRE_LEN {
                return None;
            }
            position = end;
        }

        let qtype = Rtype::from_u16(read_u16(source, position)?);
        let qclass = Rclass::from_u16(read_u16(source, position.saturating_add(2))?);
        position = position.saturating_add(4);
        let edns = if additional_count == 1 {
            let (edns, next) = parse_opt(source, position)?;
            position = next;
            Some(edns)
        } else {
            None
        };
        if position != source.len() {
            return None;
        }
        Some(Self {
            source,
            id,
            flags,
            qname,
            qname_len: written,
            qtype,
            qclass,
            edns,
        })
    }

    /// Исходный пакет.
    #[must_use]
    pub const fn as_bytes(self) -> &'a [u8] {
        self.source
    }

    /// ID запроса.
    #[must_use]
    pub const fn id(self) -> u16 {
        self.id
    }

    /// Флаги заголовка.
    #[must_use]
    pub const fn flags(self) -> Flags {
        self.flags
    }

    /// Канонический `QNAME`.
    #[must_use]
    pub fn qname(&self) -> Option<NameRef<'_>> {
        self.qname
            .get(..self.qname_len)
            .map(NameRef::from_validated)
    }

    /// Тип вопроса.
    #[must_use]
    pub const fn qtype(self) -> Rtype {
        self.qtype
    }

    /// Класс вопроса.
    #[must_use]
    pub const fn qclass(self) -> Rclass {
        self.qclass
    }

    /// EDNS0-запрос, если он был в additional.
    #[must_use]
    pub const fn edns(self) -> Option<EdnsRef> {
        self.edns
    }
}

/// Разбирает единственную OPT-псевдозапись и возвращает позицию за ней.
fn parse_opt(source: &[u8], start: usize) -> Option<(EdnsRef, usize)> {
    // Владелец OPT — корень (RFC 6891 §6.1.1).
    if *source.get(start)? != 0 {
        return None;
    }
    let mut position = start.checked_add(1)?;
    let rr_type = read_u16(source, position)?;
    if rr_type != Rtype::OPT.as_u16() {
        return None;
    }
    position = position.checked_add(2)?;
    let payload = read_u16(source, position)?;
    position = position.checked_add(2)?;
    let ttl = u32::from_be_bytes(read_bytes::<4>(source, position)?);
    position = position.checked_add(4)?;
    let rdata_len = usize::from(read_u16(source, position)?);
    position = position.checked_add(2)?;
    let end = position.checked_add(rdata_len)?;
    source.get(position..end)?;

    let mut cursor = position;
    while cursor < end {
        let _code = read_u16(source, cursor)?;
        cursor = cursor.checked_add(2)?;
        let length = usize::from(read_u16(source, cursor)?);
        cursor = cursor.checked_add(2)?;
        cursor = cursor.checked_add(length)?;
        if cursor > end {
            return None;
        }
    }
    if cursor != end {
        return None;
    }

    let edns = EdnsRef {
        payload,
        extended_rcode: u8::try_from(ttl >> 24).ok()?,
        version: u8::try_from((ttl >> 16) & 0xFF).ok()?,
        flags: u16::try_from(ttl & 0xFFFF).ok()?,
    };
    Some((edns, end))
}

fn read_bytes<const N: usize>(bytes: &[u8], offset: usize) -> Option<[u8; N]> {
    let end = offset.checked_add(N)?;
    bytes.get(offset..end)?.try_into().ok()
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let value: [u8; 2] = bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?;
    Some(u16::from_be_bytes(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EncodeOptions;
    use crate::domain::{Message, Name, Question};

    fn query_bytes(name: &str, qtype: Rtype) -> Vec<u8> {
        Message::query(
            0x1234,
            Question::new(Name::parse(name).unwrap(), qtype, Rclass::IN),
        )
        .encode(&EncodeOptions::compressed())
        .unwrap()
    }

    #[test]
    fn decodes_uncompressed_query_without_allocations() {
        let bytes = query_bytes("WWW.Example.COM", Rtype::A);
        let parsed = MessageRef::decode_simple(&bytes).unwrap();
        assert_eq!(parsed.id(), 0x1234);
        assert_eq!(parsed.qtype(), Rtype::A);
        assert_eq!(parsed.qclass(), Rclass::IN);
        assert_eq!(
            parsed.qname().unwrap().as_wire(),
            b"\x03www\x07example\x03com\x00"
        );
    }

    #[test]
    fn rejects_compressed_qname() {
        let mut bytes = query_bytes("www.example.com", Rtype::A);
        // Указатель в заголовок: полный декодер тоже отвергнет.
        bytes[12] = 0xC0;
        bytes[13] = 0x0C;
        assert!(MessageRef::decode_simple(&bytes).is_none());
    }

    #[test]
    fn rejects_edns_and_extra_sections() {
        let mut bytes = query_bytes("www.example.com", Rtype::A);
        bytes[10] = 0;
        bytes[11] = 1;
        assert!(MessageRef::decode_simple(&bytes).is_none());
    }

    #[test]
    fn parses_single_opt() {
        let mut message = Message::query(
            0x2222,
            Question::new(
                Name::parse("www.example.com").unwrap(),
                Rtype::A,
                Rclass::IN,
            ),
        );
        message.set_edns(Some(
            crate::domain::Edns::new(1400)
                .with_version(0)
                .with_dnssec_ok(false),
        ));
        let bytes = message.encode(&EncodeOptions::compressed()).unwrap();
        let parsed = MessageRef::decode_simple_edns(&bytes).unwrap();
        let edns = parsed.edns().expect("edns");
        assert_eq!(edns.udp_payload_size(), 1400);
        assert_eq!(edns.version(), 0);
        assert!(!edns.dnssec_ok());
    }

    #[test]
    fn rejects_malformed_opt_option() {
        let mut message = Message::query(
            0x3333,
            Question::new(
                Name::parse("www.example.com").unwrap(),
                Rtype::A,
                Rclass::IN,
            ),
        );
        message.set_edns(Some(crate::domain::Edns::new(1232)));
        let mut bytes = message.encode(&EncodeOptions::compressed()).unwrap();
        // RDATA OPT пуст; объявляем опцию длиной 4 без данных.
        bytes.extend_from_slice(&[0, 10, 0, 4]);
        let last = bytes.len() - 4;
        bytes[last - 2] = 0;
        bytes[last - 1] = 4;
        assert!(MessageRef::decode_simple_edns(&bytes).is_none());
    }

    #[test]
    fn rejects_second_opt() {
        let mut message = Message::query(
            0x4444,
            Question::new(
                Name::parse("www.example.com").unwrap(),
                Rtype::A,
                Rclass::IN,
            ),
        );
        message.set_edns(Some(crate::domain::Edns::new(1232)));
        let mut bytes = message.encode(&EncodeOptions::compressed()).unwrap();
        bytes[11] = 2;
        assert!(MessageRef::decode_simple_edns(&bytes).is_none());
    }

    #[test]
    fn rejects_response() {
        let mut bytes = query_bytes("www.example.com", Rtype::A);
        bytes[2] |= 0x80;
        assert!(MessageRef::decode_simple(&bytes).is_none());
    }
}
