//! Denial-of-existence: проверка NSEC/NSEC3 proof-наборов.
//!
//! Модуль не доверяет порядку записей и не паникует на произвольных
//! именах: все сравнения идут в каноническом (NSEC) или hash-порядке
//! (NSEC3), лимиты проверяются до вычислений.

pub mod base32hex;
mod nsec;
mod nsec3;

pub use nsec::{
    NsecProof, bitmap_contains, nsec_nodata, nsec_nxdomain, nsec_wildcard_answer,
    nsec_wildcard_nodata,
};
pub use nsec3::{
    Nsec3Params, Nsec3Proof, nsec3_ds_nodata, nsec3_nodata, nsec3_nxdomain, nsec3_wildcard_answer,
    nsec3_wildcard_nodata,
};

use crate::error::DenialError;

/// Лимит итераций NSEC3 по умолчанию (RFC 9276 рекомендует 0; валидатор
/// обязан ограничивать, SEC-RES-006).
pub const MAX_NSEC3_ITERATIONS: u16 = 100;

/// Лимит числа proof-записей в ответе.
pub const MAX_DENIAL_RECORDS: usize = 32;

/// Лимиты denial-валидации.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DenialLimits {
    /// Максимум итераций NSEC3.
    pub max_nsec3_iterations: u16,
    /// Максимум proof-записей.
    pub max_records: usize,
}

impl DenialLimits {
    /// Лимиты по умолчанию.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_nsec3_iterations: MAX_NSEC3_ITERATIONS,
            max_records: MAX_DENIAL_RECORDS,
        }
    }

    /// Заменяет лимит итераций.
    #[must_use]
    pub const fn with_max_iterations(mut self, iterations: u16) -> Self {
        self.max_nsec3_iterations = iterations;
        self
    }
}

impl Default for DenialLimits {
    fn default() -> Self {
        Self::new()
    }
}

/// Что именно доказано denial-записями.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenialOutcome {
    /// Имени не существует (NXDOMAIN).
    NxDomain,
    /// Имя существует, но типа нет (NODATA).
    NoData,
    /// Wildcard существует, но типа в нём нет.
    WildcardNoData,
    /// Wildcard-развёртывание подтверждено.
    WildcardExpansion,
}

/// Результат проверки denial proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DenialResult {
    /// Доказанный факт.
    pub outcome: DenialOutcome,
    /// Использован Opt-Out (ответ считается insecure для делегирования).
    pub opt_out: bool,
}

impl DenialResult {
    /// Создаёт результат.
    #[must_use]
    pub const fn new(outcome: DenialOutcome, opt_out: bool) -> Self {
        Self { outcome, opt_out }
    }

    /// Доказательство secure (без Opt-Out).
    #[must_use]
    pub const fn is_secure(self) -> bool {
        !self.opt_out
    }
}

pub(crate) fn check_record_limit(count: usize, limits: DenialLimits) -> Result<(), DenialError> {
    if count == 0 {
        return Err(DenialError::EmptyProof);
    }
    if count > limits.max_records {
        return Err(DenialError::TooManyRecords {
            count,
            max: limits.max_records,
        });
    }
    Ok(())
}
