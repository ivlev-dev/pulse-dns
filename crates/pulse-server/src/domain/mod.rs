//! Доменные типы авторитетного ответа.

mod refs;
mod resolve;

pub use refs::{LookupOutcomeRef, RdataRef, Rdatas, RefLookup, RrsetRef};
pub use resolve::{DenialKind, LookupOutcome, ZoneState};
