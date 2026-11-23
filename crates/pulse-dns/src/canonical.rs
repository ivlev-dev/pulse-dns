//! Каноническая форма для DNSSEC (RFC 4034 §6).
//!
//! Каноническая wire-форма RRset:
//!
//! - owner и все имена RDATA — в нижнем регистре, без компрессии;
//! - RR внутри набора отсортированы по канонической RDATA (лексикографически,
//!   как последовательность октетов);
//! - TTL, type и class берутся из RRset.
//!
//! Порядок имён (`name_cmp`) — RFC 4034 §6.1.
//!
//! # Пример
//!
//! ```
//! use pulse_dns::canonical;
//! use pulse_dns::domain::Name;
//!
//! let apex = Name::parse("example.com").unwrap();
//! let child = Name::parse("a.example.com").unwrap();
//! assert_eq!(canonical::compare_names(&apex, &child), std::cmp::Ordering::Less);
//! ```

use crate::domain::{Name, Record, RecordError, Rrset, RrsetError, name_cmp};

/// Сравнение имён по RFC 4034 §6.1.
#[must_use]
pub fn compare_names(left: &Name, right: &Name) -> std::cmp::Ordering {
    name_cmp(left, right)
}

/// Каноническая wire-форма одной RR.
///
/// # Errors
///
/// [`RecordError`] при некорректной/слишком длинной RDATA.
pub fn record_wire(record: &Record) -> Result<Vec<u8>, RecordError> {
    record.to_canonical_wire()
}

/// Каноническая wire-форма RRset с сортировкой RR по RDATA.
///
/// # Errors
///
/// [`RrsetError`] при некорректной/слишком длинной RDATA.
pub fn rrset_wire(rrset: &Rrset) -> Result<Vec<u8>, RrsetError> {
    rrset.to_canonical_wire()
}
