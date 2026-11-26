//! Полная DNS-запись (`domain-model.md` §2.4).

use thiserror::Error;

use super::name::Name;
use super::rdata::Rdata;
use super::rr::{Rclass, Rtype};
use super::ttl::Ttl;

/// Ошибка создания или валидации [`Record`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RecordError {
    /// Тип RDATA не совпадает с типом записи.
    #[error("rdata type {actual} does not match record type {declared}")]
    TypeMismatch {
        /// Тип из заголовка RR.
        declared: Rtype,
        /// Тип, определяемый вариантом RDATA.
        actual: Rtype,
    },
    /// Класс не поддерживается в v1 (INV-10).
    #[error("unsupported class {class}; only IN is allowed in v1")]
    UnsupportedClass {
        /// Класс записи.
        class: Rclass,
    },
    /// RDATA не проходит валидацию.
    #[error(transparent)]
    Rdata(#[from] super::rdata::RdataError),
    /// RDATA длиннее 65535 октетов (не помещается в RDLENGTH).
    #[error("rdata is {len} octets long (max 65535)")]
    RdataTooLong {
        /// Длина RDATA.
        len: usize,
    },
}

/// DNS-ресурсная запись.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Record {
    owner: Name,
    rr_type: Rtype,
    class: Rclass,
    ttl: Ttl,
    rdata: Rdata,
}

impl Record {
    /// Создаёт запись, проверяя согласованность типа и RDATA.
    ///
    /// # Errors
    ///
    /// [`RecordError::TypeMismatch`], если `rr_type != rdata.rr_type()`.
    pub fn new(
        owner: Name,
        rr_type: Rtype,
        class: Rclass,
        ttl: Ttl,
        rdata: Rdata,
    ) -> Result<Self, RecordError> {
        if rr_type != rdata.rr_type() {
            return Err(RecordError::TypeMismatch {
                declared: rr_type,
                actual: rdata.rr_type(),
            });
        }
        rdata.validate()?;
        let rdata_len = rdata.wire_len();
        if rdata_len > usize::from(u16::MAX) {
            return Err(RecordError::RdataTooLong { len: rdata_len });
        }
        Ok(Self {
            owner,
            rr_type,
            class,
            ttl,
            rdata,
        })
    }

    /// Создаёт метазапись DNS UPDATE с пустой RDATA (RFC 2136 §2.4/§2.5).
    ///
    /// Используется в Prerequisite/Update секциях с классом `ANY`/`NONE`
    /// (удаление, проверки существования). TTL всегда `0`; такая запись не
    /// предназначена для хранения в зоне и не проходит [`Record::validate`].
    #[must_use]
    pub fn update_metavalue(owner: Name, rr_type: Rtype, class: Rclass) -> Self {
        Self::from_parts_unchecked(
            owner,
            rr_type,
            class,
            Ttl::ZERO,
            Rdata::empty_metavalue(rr_type),
        )
    }

    /// Создаёт запись без проверки типа, для wire-декодера.
    ///
    /// Декодер сам гарантирует соответствие через диспетчеризацию по типу.
    pub(crate) fn from_parts_unchecked(
        owner: Name,
        rr_type: Rtype,
        class: Rclass,
        ttl: Ttl,
        rdata: Rdata,
    ) -> Self {
        Self {
            owner,
            rr_type,
            class,
            ttl,
            rdata,
        }
    }

    /// Владелец записи.
    #[must_use]
    pub const fn owner(&self) -> &Name {
        &self.owner
    }

    /// Тип записи.
    #[must_use]
    pub const fn rr_type(&self) -> Rtype {
        self.rr_type
    }

    /// Класс записи.
    #[must_use]
    pub const fn class(&self) -> Rclass {
        self.class
    }

    /// TTL.
    #[must_use]
    pub const fn ttl(&self) -> Ttl {
        self.ttl
    }

    /// RDATA.
    #[must_use]
    pub const fn rdata(&self) -> &Rdata {
        &self.rdata
    }

    /// Проверяет доменные инварианты записи (INV-10).
    ///
    /// # Errors
    ///
    /// [`RecordError::TypeMismatch`] или [`RecordError::UnsupportedClass`].
    pub fn validate(&self) -> Result<(), RecordError> {
        if self.rr_type != self.rdata.rr_type() {
            return Err(RecordError::TypeMismatch {
                declared: self.rr_type,
                actual: self.rdata.rr_type(),
            });
        }
        if self.class != Rclass::IN {
            return Err(RecordError::UnsupportedClass { class: self.class });
        }
        self.rdata.validate()?;
        Ok(())
    }

    /// Каноническая wire-форма RR (RFC 4034 §6.2): имя в нижнем регистре,
    /// без компрессии.
    ///
    /// # Errors
    ///
    /// [`RecordError`], если тип/RDATA несогласованы или RDATA не помещается
    /// в RDLENGTH; в этом случае байты не возвращаются.
    pub fn to_canonical_wire(&self) -> Result<Vec<u8>, RecordError> {
        let mut out = Vec::new();
        self.write_canonical_wire(&mut out)?;
        Ok(out)
    }

    /// Записывает каноническую wire-форму RR в `out`.
    ///
    /// # Errors
    ///
    /// [`RecordError`] при некорректной RDATA; `out` в этом случае не
    /// получает частичную запись.
    pub fn write_canonical_wire(&self, out: &mut Vec<u8>) -> Result<(), RecordError> {
        if self.rr_type != self.rdata.rr_type() {
            return Err(RecordError::TypeMismatch {
                declared: self.rr_type,
                actual: self.rdata.rr_type(),
            });
        }
        self.rdata.validate()?;
        let rdata = self.rdata.to_canonical_wire();
        let Ok(length) = u16::try_from(rdata.len()) else {
            return Err(RecordError::RdataTooLong { len: rdata.len() });
        };
        out.extend_from_slice(self.owner.as_wire());
        out.extend_from_slice(&self.rr_type.as_u16().to_be_bytes());
        out.extend_from_slice(&self.class.as_u16().to_be_bytes());
        out.extend_from_slice(&self.ttl.as_u32().to_be_bytes());
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&rdata);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{DsData, Rclass, Rdata, Rtype, Ttl};

    #[test]
    fn canonical_wire_rejects_oversized_rdata_without_partial_output() {
        let rdata = Rdata::Ds(DsData::new(1, 1, 99, vec![0; 65_535]).unwrap());
        let record = Record::from_parts_unchecked(
            Name::parse("example.com").unwrap(),
            Rtype::DS,
            Rclass::IN,
            Ttl::new(300).unwrap(),
            rdata,
        );
        let mut out = Vec::new();
        assert!(matches!(
            record.write_canonical_wire(&mut out),
            Err(RecordError::RdataTooLong { len: 65_539 })
        ));
        assert_eq!(out.len(), 0);
        assert!(matches!(
            record.to_canonical_wire(),
            Err(RecordError::RdataTooLong { len: 65_539 })
        ));
    }
}
