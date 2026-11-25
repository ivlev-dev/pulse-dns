//! Zero-copy представление простого DNS-запроса.
//!
//! [`MessageRef`] разбирает заголовок и единственный вопрос **без аллокаций**
//! и без `Vec`: `QNAME` копируется в стековый буфер и канонизируется, а
//! `QTYPE`/`QCLASS` возвращаются как value-типы. Это горячий путь UDP:
//! полноценный [`crate::Message`] нужен только для запросов, которые не
//! помещаются в простое представление (EDNS, несколько вопросов, сжатый
//! `QNAME`, секции ответа).
//!
//! `MessageRef` намеренно не является универсальным декодером: `None` из
//! [`MessageRef::decode_simple`] означает «разберите пакет полным
//! [`crate::Message::decode`]». Такая граница гарантирует, что быстрый путь не
//! принимает пакет, который полноценный декодер отверг бы.

use crate::domain::{Flags, MAX_LABELS, MAX_NAME_WIRE_LEN, NameRef, Opcode, Rclass, Rtype};

/// Разобранный простой запрос (один вопрос, без дополнительных секций).
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
}

impl core::fmt::Debug for MessageRef<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MessageRef")
            .field("id", &self.id)
            .field("qname", &self.qname())
            .field("qtype", &self.qtype)
            .field("qclass", &self.qclass)
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
        if source.len() < 12 || source.len() > crate::wire::MAX_MESSAGE_LEN {
            return None;
        }
        let id = read_u16(source, 0)?;
        let flags = Flags::from_bits(read_u16(source, 2)?);
        if flags.qr() || flags.opcode() != Opcode::QUERY {
            return None;
        }
        if read_u16(source, 4)? != 1
            || read_u16(source, 6)? != 0
            || read_u16(source, 8)? != 0
            || read_u16(source, 10)? != 0
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
        if position.saturating_add(4) != source.len() {
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
    fn rejects_response() {
        let mut bytes = query_bytes("www.example.com", Rtype::A);
        bytes[2] |= 0x80;
        assert!(MessageRef::decode_simple(&bytes).is_none());
    }
}
