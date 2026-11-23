//! RRset: атомарный набор записей одного `(owner, type, class, ttl)`.

use std::collections::BTreeSet;

use thiserror::Error;

use super::name::{Name, NameError};
use super::rdata::{Rdata, RdataError};
use super::record::Record;
use super::rr::{Rclass, Rtype};
use super::ttl::Ttl;

/// Максимальное число RR в одном RRset (ADR 0004 SEC-DNS-003).
pub const MAX_RRSET_RECORDS: usize = 4096;

/// Ошибка нарушения инвариантов [`Rrset`] (INV-1, INV-2, INV-10).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RrsetError {
    /// Пустой RRset не существует.
    #[error("rrset must contain at least one record")]
    Empty,
    /// Разные TTL в одном наборе (INV-1, policy `Transaction`).
    #[error("ttl mismatch: existing {existing}, incoming {incoming}")]
    TtlMismatch {
        /// TTL набора.
        existing: Ttl,
        /// TTL входящей записи.
        incoming: Ttl,
    },
    /// Разные владельцы.
    #[error("owner mismatch: existing {existing}, incoming {incoming}")]
    OwnerMismatch {
        /// Владелец набора.
        existing: String,
        /// Владелец входящей записи.
        incoming: String,
    },
    /// Разные типы.
    #[error("type mismatch: existing {existing}, incoming {incoming}")]
    TypeMismatch {
        /// Тип набора.
        existing: Rtype,
        /// Тип входящей записи.
        incoming: Rtype,
    },
    /// Разные классы.
    #[error("class mismatch: existing {existing}, incoming {incoming}")]
    ClassMismatch {
        /// Класс набора.
        existing: Rclass,
        /// Класс входящей записи.
        incoming: Rclass,
    },
    /// Класс не IN (INV-10).
    #[error("unsupported class {class}; only IN is allowed in v1")]
    UnsupportedClass {
        /// Класс.
        class: Rclass,
    },
    /// RDATA не соответствует типу набора.
    #[error("rdata type {actual} does not match rrset type {expected}")]
    RdataTypeMismatch {
        /// Тип набора.
        expected: Rtype,
        /// Тип RDATA.
        actual: Rtype,
    },
    /// Превышен лимит RR в наборе.
    #[error("rrset has {count} records (max {MAX_RRSET_RECORDS})")]
    TooManyRecords {
        /// Количество записей.
        count: usize,
    },
    /// RDATA не проходит валидацию.
    #[error(transparent)]
    Rdata(#[from] RdataError),
    /// RDATA длиннее 65535 октетов (не помещается в RDLENGTH).
    #[error("rdata is {len} octets long (max 65535)")]
    RdataTooLong {
        /// Длина RDATA.
        len: usize,
    },
    /// Владелец не является корректным владельцем зоны (INV-11).
    #[error(transparent)]
    Owner(#[from] NameError),
}

/// Набор ресурсных записей с одним owner/type/class/ttl.
///
/// RDATA хранятся в [`BTreeSet`], то есть дедуплицированы и упорядочены по
/// канонической wire-форме (INV-2). Пустой набор невозможен.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rrset {
    owner: Name,
    rr_type: Rtype,
    class: Rclass,
    ttl: Ttl,
    rdata: BTreeSet<Rdata>,
}

impl Rrset {
    /// Создаёт RRset.
    ///
    /// # Errors
    ///
    /// [`RrsetError`] при пустом наборе, не-IN классе, несоответствии типа,
    /// превышении лимита или невалидной RDATA.
    pub fn new(
        owner: Name,
        rr_type: Rtype,
        class: Rclass,
        ttl: Ttl,
        rdatas: impl IntoIterator<Item = Rdata>,
    ) -> Result<Self, RrsetError> {
        owner.validate_zone_owner()?;
        if class != Rclass::IN {
            return Err(RrsetError::UnsupportedClass { class });
        }
        let mut set = BTreeSet::new();
        for rdata in rdatas {
            rdata.validate()?;
            let rdata_len = rdata.wire_len();
            if rdata_len > usize::from(u16::MAX) {
                return Err(RrsetError::RdataTooLong { len: rdata_len });
            }
            if rdata.rr_type() != rr_type {
                return Err(RrsetError::RdataTypeMismatch {
                    expected: rr_type,
                    actual: rdata.rr_type(),
                });
            }
            set.insert(rdata);
            if set.len() > MAX_RRSET_RECORDS {
                return Err(RrsetError::TooManyRecords { count: set.len() });
            }
        }
        if set.is_empty() {
            return Err(RrsetError::Empty);
        }
        Ok(Self {
            owner,
            rr_type,
            class,
            ttl,
            rdata: set,
        })
    }

    /// Строит RRset из готовых записей с политикой `WriteIntent::Transaction`:
    /// разный TTL — ошибка, а не молчаливый `min` (`domain-model.md` §2.5).
    ///
    /// # Errors
    ///
    /// [`RrsetError`] при нарушении однородности набора.
    pub fn from_records(records: impl IntoIterator<Item = Record>) -> Result<Self, RrsetError> {
        let mut iterator = records.into_iter();
        let first = iterator.next().ok_or(RrsetError::Empty)?;
        let owner = first.owner().clone();
        let rr_type = first.rr_type();
        let class = first.class();
        let ttl = first.ttl();
        let mut rdatas = vec![first.rdata().clone()];
        for record in iterator {
            if record.owner() != &owner {
                return Err(RrsetError::OwnerMismatch {
                    existing: owner.to_string(),
                    incoming: record.owner().to_string(),
                });
            }
            if record.rr_type() != rr_type {
                return Err(RrsetError::TypeMismatch {
                    existing: rr_type,
                    incoming: record.rr_type(),
                });
            }
            if record.class() != class {
                return Err(RrsetError::ClassMismatch {
                    existing: class,
                    incoming: record.class(),
                });
            }
            if record.ttl() != ttl {
                return Err(RrsetError::TtlMismatch {
                    existing: ttl,
                    incoming: record.ttl(),
                });
            }
            rdatas.push(record.rdata().clone());
        }
        Self::new(owner, rr_type, class, ttl, rdatas)
    }

    /// Владелец набора.
    #[must_use]
    pub const fn owner(&self) -> &Name {
        &self.owner
    }

    /// Тип набора.
    #[must_use]
    pub const fn rr_type(&self) -> Rtype {
        self.rr_type
    }

    /// Класс набора.
    #[must_use]
    pub const fn class(&self) -> Rclass {
        self.class
    }

    /// TTL всего набора (RFC 2181 §5.2).
    #[must_use]
    pub const fn ttl(&self) -> Ttl {
        self.ttl
    }

    /// RDATA в каноническом порядке.
    #[must_use]
    pub fn rdatas(&self) -> &BTreeSet<Rdata> {
        &self.rdata
    }

    /// Количество записей в наборе.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rdata.len()
    }

    /// Набор всегда непуст; метод существует для симметрии с `is_empty`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rdata.is_empty()
    }

    /// Содержит ли набор указанную RDATA.
    #[must_use]
    pub fn contains(&self, rdata: &Rdata) -> bool {
        self.rdata.contains(rdata)
    }

    /// Объединение наборов с проверкой инвариантов.
    ///
    /// # Errors
    ///
    /// [`RrsetError`] при несовпадении owner/type/class/TTL.
    pub fn merge(&self, other: &Self) -> Result<Self, RrsetError> {
        self.check_compatible(other)?;
        if self.ttl != other.ttl {
            return Err(RrsetError::TtlMismatch {
                existing: self.ttl,
                incoming: other.ttl,
            });
        }
        let mut rdatas = self.rdata.clone();
        rdatas.extend(other.rdata.iter().cloned());
        if rdatas.len() > MAX_RRSET_RECORDS {
            return Err(RrsetError::TooManyRecords {
                count: rdatas.len(),
            });
        }
        Ok(Self {
            owner: self.owner.clone(),
            rr_type: self.rr_type,
            class: self.class,
            ttl: self.ttl,
            rdata: rdatas,
        })
    }

    /// Вычитание наборов. `None` означает, что набор стал пустым и должен
    /// быть удалён вызывающим (`domain-model.md` §2.5).
    ///
    /// # Errors
    ///
    /// [`RrsetError`] при несовпадении owner/type/class.
    pub fn subtract(&self, other: &Self) -> Result<Option<Self>, RrsetError> {
        self.check_compatible(other)?;
        let rdata: BTreeSet<Rdata> = self
            .rdata
            .iter()
            .filter(|candidate| !other.rdata.contains(*candidate))
            .cloned()
            .collect();
        if rdata.is_empty() {
            return Ok(None);
        }
        Ok(Some(Self {
            owner: self.owner.clone(),
            rr_type: self.rr_type,
            class: self.class,
            ttl: self.ttl,
            rdata,
        }))
    }

    /// Конкатенация канонических RR, отсортированных по RDATA (RFC 4034 §6.3).
    ///
    /// # Errors
    ///
    /// [`RrsetError`], если какая-то RDATA не проходит валидацию или не
    /// помещается в RDLENGTH.
    pub fn to_canonical_wire(&self) -> Result<Vec<u8>, RrsetError> {
        let mut out = Vec::new();
        self.write_canonical_wire(&mut out)?;
        Ok(out)
    }

    /// Записывает каноническую wire-форму RRset в `out`.
    ///
    /// # Errors
    ///
    /// [`RrsetError`]; при ошибке `out` не получает частичную запись.
    pub fn write_canonical_wire(&self, out: &mut Vec<u8>) -> Result<(), RrsetError> {
        let mut encoded = Vec::new();
        for rdata in &self.rdata {
            rdata.validate()?;
            let canonical = rdata.to_canonical_wire();
            let Ok(length) = u16::try_from(canonical.len()) else {
                return Err(RrsetError::RdataTooLong {
                    len: canonical.len(),
                });
            };
            encoded.extend_from_slice(self.owner.as_wire());
            encoded.extend_from_slice(&self.rr_type.as_u16().to_be_bytes());
            encoded.extend_from_slice(&self.class.as_u16().to_be_bytes());
            encoded.extend_from_slice(&self.ttl.as_u32().to_be_bytes());
            encoded.extend_from_slice(&length.to_be_bytes());
            encoded.extend_from_slice(&canonical);
        }
        out.extend_from_slice(&encoded);
        Ok(())
    }

    fn check_compatible(&self, other: &Self) -> Result<(), RrsetError> {
        if self.owner != other.owner {
            return Err(RrsetError::OwnerMismatch {
                existing: self.owner.to_string(),
                incoming: other.owner.to_string(),
            });
        }
        if self.rr_type != other.rr_type {
            return Err(RrsetError::TypeMismatch {
                existing: self.rr_type,
                incoming: other.rr_type,
            });
        }
        if self.class != other.class {
            return Err(RrsetError::ClassMismatch {
                existing: self.class,
                incoming: other.class,
            });
        }
        Ok(())
    }
}
