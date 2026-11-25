//! Заимствованные представления RRset/RDATA для горячего пути ответа.
//!
//! [`RrsetRef`] либо ссылается на владеющий [`Rrset`] (in-memory/testkit),
//! либо держит сырой `[u16 length][rdata]…` payload из зоны v2. Оба варианта
//! позволяют кодировать ответ без материализации `Rrset` и без `Vec`.

use std::collections::btree_set;

use pulse_dns::{NameRef, Rclass, Rdata, Rrset, Rtype, Ttl};

/// Заимствованная RDATA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RdataRef<'a> {
    /// Доменная RDATA (валидированный [`Rdata`]).
    Domain(&'a Rdata),
    /// Сырая wire-форма RDATA из зоны.
    Wire {
        /// Тип записи (для интерпретации полей).
        rr_type: Rtype,
        /// Байты RDATA без `RDLENGTH`.
        bytes: &'a [u8],
    },
}

impl<'a> RdataRef<'a> {
    /// Тип RDATA.
    #[must_use]
    pub const fn rr_type(self) -> Rtype {
        match self {
            Self::Domain(rdata) => rdata.rr_type(),
            Self::Wire { rr_type, .. } => rr_type,
        }
    }

    /// Доменная RDATA, если она материализована.
    #[must_use]
    pub const fn as_domain(self) -> Option<&'a Rdata> {
        match self {
            Self::Domain(rdata) => Some(rdata),
            Self::Wire { .. } => None,
        }
    }

    /// Сырые байты RDATA, если представление wire-based.
    #[must_use]
    pub const fn as_wire(self) -> Option<&'a [u8]> {
        match self {
            Self::Domain(_) => None,
            Self::Wire { bytes, .. } => Some(bytes),
        }
    }

    /// Поле `Type Covered` для `RRSIG`-RDATA.
    ///
    /// `None` — RDATA другого типа или повреждённая wire-форма.
    #[must_use]
    pub fn type_covered(self) -> Option<Rtype> {
        match self {
            Self::Domain(Rdata::Rrsig(signature)) => Some(signature.type_covered()),
            Self::Wire { rr_type, bytes } if rr_type == Rtype::RRSIG => {
                let raw: [u8; 2] = bytes.get(..2)?.try_into().ok()?;
                Some(Rtype::from_u16(u16::from_be_bytes(raw)))
            }
            Self::Domain(_) | Self::Wire { .. } => None,
        }
    }
}

/// Источник RDATA RRset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RrsetSource<'a> {
    /// Владеющий набор.
    Owned(&'a Rrset),
    /// Payload `[u16 length][rdata]…` из зоны v2.
    Wire(&'a [u8]),
}

/// Заимствованный RRset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RrsetRef<'a> {
    owner: NameRef<'a>,
    rr_type: Rtype,
    class: Rclass,
    ttl: Ttl,
    source: RrsetSource<'a>,
}

impl<'a> RrsetRef<'a> {
    /// Представление владеющего набора.
    #[must_use]
    pub fn from_owned(rrset: &'a Rrset) -> Self {
        Self {
            owner: NameRef::from_name(rrset.owner()),
            rr_type: rrset.rr_type(),
            class: rrset.class(),
            ttl: rrset.ttl(),
            source: RrsetSource::Owned(rrset),
        }
    }

    /// Представление payload'а зоны v2.
    ///
    /// `payload` — последовательность `[u16 length][rdata]…` в каноническом
    /// порядке (как хранит `pulse-zonefile`).
    #[must_use]
    pub const fn from_wire(
        owner: NameRef<'a>,
        rr_type: Rtype,
        class: Rclass,
        ttl: Ttl,
        payload: &'a [u8],
    ) -> Self {
        Self {
            owner,
            rr_type,
            class,
            ttl,
            source: RrsetSource::Wire(payload),
        }
    }

    /// Владелец.
    #[must_use]
    pub const fn owner(self) -> NameRef<'a> {
        self.owner
    }

    /// Тип набора.
    #[must_use]
    pub const fn rr_type(self) -> Rtype {
        self.rr_type
    }

    /// Класс набора.
    #[must_use]
    pub const fn class(self) -> Rclass {
        self.class
    }

    /// TTL набора.
    #[must_use]
    pub const fn ttl(self) -> Ttl {
        self.ttl
    }

    /// Число записей.
    #[must_use]
    pub fn len(self) -> usize {
        match self.source {
            RrsetSource::Owned(rrset) => rrset.len(),
            RrsetSource::Wire(payload) => Rdatas::wire_len(payload),
        }
    }

    /// Пуст ли набор (для симметрии с [`RrsetRef::len`]).
    #[must_use]
    pub fn is_empty(self) -> bool {
        self.len() == 0
    }

    /// Итератор RDATA в каноническом порядке.
    #[must_use]
    pub fn records(self) -> Rdatas<'a> {
        match self.source {
            RrsetSource::Owned(rrset) => Rdatas::Owned(rrset.rdatas().iter()),
            RrsetSource::Wire(payload) => Rdatas::Wire {
                rr_type: self.rr_type,
                payload,
                offset: 0,
            },
        }
    }

    /// Первая RDATA (для CNAME-цели в горячем пути).
    #[must_use]
    pub fn first_record(self) -> Option<RdataRef<'a>> {
        self.records().next()
    }

    /// Есть ли в наборе `RRSIG`, покрывающая `covered`.
    ///
    /// Для наборов других типов всегда `false`.
    #[must_use]
    pub fn covers(self, covered: Rtype) -> bool {
        self.rr_type() == Rtype::RRSIG
            && self
                .records()
                .any(|rdata| rdata.type_covered() == Some(covered))
    }
}

/// Итератор заимствованных RDATA.
#[derive(Debug)]
pub enum Rdatas<'a> {
    /// Итератор владеющего набора.
    Owned(btree_set::Iter<'a, Rdata>),
    /// Последовательность wire-форм.
    Wire {
        /// Тип записей.
        rr_type: Rtype,
        /// Payload `[u16 length][rdata]…`.
        payload: &'a [u8],
        /// Текущее смещение.
        offset: usize,
    },
}

impl Rdatas<'_> {
    fn wire_len(payload: &[u8]) -> usize {
        let mut offset = 0_usize;
        let mut count = 0_usize;
        while let Some(length) = read_length(payload, offset) {
            let Some(end) = offset.saturating_add(2).checked_add(usize::from(length)) else {
                break;
            };
            if end > payload.len() {
                break;
            }
            offset = end;
            count = count.saturating_add(1);
        }
        count
    }
}

impl<'a> Iterator for Rdatas<'a> {
    type Item = RdataRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Owned(records) => records.next().map(RdataRef::Domain),
            Self::Wire {
                rr_type,
                payload,
                offset,
            } => {
                let length = read_length(payload, *offset)?;
                let start = offset.checked_add(2)?;
                let end = start.checked_add(usize::from(length))?;
                let bytes = payload.get(start..end)?;
                *offset = end;
                Some(RdataRef::Wire {
                    rr_type: *rr_type,
                    bytes,
                })
            }
        }
    }
}

fn read_length(payload: &[u8], offset: usize) -> Option<u16> {
    let bytes: [u8; 2] = payload
        .get(offset..offset.checked_add(2)?)?
        .try_into()
        .ok()?;
    Some(u16::from_be_bytes(bytes))
}

/// Заимствованный результат точного поиска.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupOutcomeRef<'a> {
    /// Точное совпадение.
    Answer(RrsetRef<'a>),
    /// `CNAME` и его каноническая цель.
    Cname(RrsetRef<'a>, NameRef<'a>),
    /// Имя существует, записей типа нет.
    NoData,
    /// Имени нет.
    NxDomain,
    /// Точка делегирования.
    Delegation {
        /// `NS`-набор.
        ns: RrsetRef<'a>,
        /// `DS`-набор, если опубликован.
        ds: Option<RrsetRef<'a>>,
    },
    /// Имя ниже zone cut.
    Referral,
    /// Имя вне зоны.
    ZoneNotFound,
    /// Заимствованное представление данных невозможно (нужен полный путь).
    Unsupported,
}

/// Результат заимствованного поиска необязательного набора.
///
/// Отличает «набора нет» от «набор есть, но без материализации его нельзя
/// отдать»: во втором случае горячий путь обязан уступить полному, чтобы не
/// потерять записи (например, `OVERFLOW`-цепочка зоны v2 из нескольких
/// страниц). Одно-страничный `OVERFLOW` отдаётся как [`RrsetRef::from_wire`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefLookup<'a> {
    /// Набор найден.
    Found(RrsetRef<'a>),
    /// Набора нет.
    Absent,
    /// Набор существует, но заимствованное представление невозможно.
    Unsupported,
}
