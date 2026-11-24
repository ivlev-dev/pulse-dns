//! Зона, лимиты и общие параметры трансфера.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use pulse_dns::{DecodeLimits, Name, Rclass, Rdata, Record, Rtype, Serial};

use crate::error::{LimitKind, TransferError};

/// Лимиты клиентского и серверного трансфера (ADR 0004 SEC-REP-004).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferLimits {
    /// Максимальное число записей во всём трансфере.
    pub max_records: usize,
    /// Максимальный суммарный объём wire-сообщений.
    pub max_bytes: u64,
    /// Максимальное число сообщений.
    pub max_messages: usize,
    /// Таймаут на весь трансфер (проверяется между операциями).
    pub timeout: Option<Duration>,
    /// Лимиты декодера одного сообщения.
    pub decode: DecodeLimits,
}

impl Default for TransferLimits {
    fn default() -> Self {
        Self {
            max_records: 1_000_000,
            max_bytes: 64 * 1024 * 1024,
            max_messages: 100_000,
            timeout: None,
            decode: DecodeLimits::default(),
        }
    }
}

/// Параметры AXFR/IXFR-сервера и клиента.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferConfig {
    /// Лимиты.
    pub limits: TransferLimits,
    /// Целевой размер сообщения в байтах.
    pub message_bytes: usize,
    /// Подписывать каждое N-е сообщение (1 — каждое).
    pub tsig_every: usize,
    /// Требовать TSIG на сервере.
    pub require_tsig: bool,
    /// Разрешать fallback IXFR → AXFR.
    pub allow_axfr_fallback: bool,
}

impl Default for TransferConfig {
    fn default() -> Self {
        Self {
            limits: TransferLimits::default(),
            message_bytes: 16 * 1024,
            tsig_every: 1,
            require_tsig: true,
            allow_axfr_fallback: true,
        }
    }
}

impl TransferConfig {
    /// Проверяет параметры конфигурации.
    ///
    /// # Errors
    ///
    /// [`TransferError::Protocol`], если `tsig_every == 0` или
    /// `message_bytes` слишком мал.
    pub fn validate(&self) -> Result<(), TransferError> {
        if self.tsig_every == 0 {
            return Err(TransferError::protocol("tsig_every must be at least 1"));
        }
        if self.message_bytes < 256 {
            return Err(TransferError::protocol(
                "message_bytes must be at least 256",
            ));
        }
        if self.tsig_every > 100 {
            return Err(TransferError::protocol(
                "tsig_every must not exceed 100 (at most 99 unsigned messages)",
            ));
        }
        if self.limits.max_records == 0
            || self.limits.max_bytes == 0
            || self.limits.max_messages == 0
        {
            return Err(TransferError::protocol("transfer limits must be non-zero"));
        }
        Ok(())
    }
}

/// Дедлайн, проверяемый между операциями.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Deadline {
    timeout: Option<Duration>,
    start: Instant,
}

impl Deadline {
    pub(crate) fn new(limits: &TransferLimits) -> Self {
        Self {
            timeout: limits.timeout,
            start: Instant::now(),
        }
    }

    pub(crate) fn check(&self) -> Result<(), TransferError> {
        if let Some(timeout) = self.timeout
            && self.start.elapsed() > timeout
        {
            return Err(TransferError::Timeout);
        }
        Ok(())
    }
}

/// Снапшот зоны для AXFR/IXFR-сервера.
///
/// Содержит ровно одну SOA в apex; остальные записи хранятся в стабильном
/// каноническом порядке и без дублей.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneSnapshot {
    origin: Name,
    soa: Record,
    records: Vec<Record>,
}

impl ZoneSnapshot {
    /// Создаёт снапшот из origin и записей.
    ///
    /// # Errors
    ///
    /// [`TransferError::Zone`], если SOA не одна, SOA не в apex, запись вне
    /// зоны, класс не IN или запись невалидна.
    pub fn new(
        origin: Name,
        records: impl IntoIterator<Item = Record>,
    ) -> Result<Self, TransferError> {
        let mut keyed: Vec<(Vec<u8>, Record)> = Vec::new();
        for record in records {
            record.validate()?;
            if record.class() != Rclass::IN {
                return Err(TransferError::zone("only class IN is supported"));
            }
            if !record.owner().is_subdomain_of(&origin) {
                return Err(TransferError::zone("record owner is outside the zone"));
            }
            let key = record.to_canonical_wire()?;
            keyed.push((key, record));
        }
        keyed.sort_by(|left, right| left.0.cmp(&right.0));
        keyed.dedup_by(|left, right| left.0 == right.0);

        let mut soa: Option<Record> = None;
        let mut other_soa = false;
        let mut body = Vec::with_capacity(keyed.len());
        for (_, record) in keyed {
            if record.rr_type() == Rtype::SOA {
                if record.owner() == &origin {
                    if soa.is_some() {
                        return Err(TransferError::zone("zone has more than one SOA"));
                    }
                    soa = Some(record);
                } else {
                    other_soa = true;
                }
            } else {
                body.push(record);
            }
        }
        if other_soa {
            return Err(TransferError::zone("SOA is only allowed at the zone apex"));
        }
        let soa = soa.ok_or(TransferError::zone("zone has no SOA at apex"))?;
        Ok(Self {
            origin,
            soa,
            records: body,
        })
    }

    /// Origin зоны.
    #[must_use]
    pub const fn origin(&self) -> &Name {
        &self.origin
    }

    /// SOA зоны.
    #[must_use]
    pub const fn soa(&self) -> &Record {
        &self.soa
    }

    /// Serial зоны.
    #[must_use]
    pub fn serial(&self) -> Serial {
        soa_serial(&self.soa).unwrap_or(Serial::ZERO)
    }

    /// Записи зоны без apex SOA.
    #[must_use]
    pub fn records(&self) -> &[Record] {
        &self.records
    }

    /// Записи зоны вместе с SOA.
    #[must_use]
    pub fn records_with_soa(&self) -> Vec<Record> {
        let mut records = Vec::with_capacity(self.records.len() + 1);
        records.push(self.soa.clone());
        records.extend(self.records.iter().cloned());
        records
    }

    /// Суммарная каноническая длина всех записей.
    ///
    /// # Errors
    ///
    /// [`TransferError::Record`] при некорректной записи.
    pub fn encoded_len(&self) -> Result<usize, TransferError> {
        let mut total = self.soa.to_canonical_wire()?.len();
        for record in &self.records {
            total = total.saturating_add(record.to_canonical_wire()?.len());
        }
        Ok(total)
    }
}

/// Serial из SOA-записи.
#[must_use]
pub fn soa_serial(record: &Record) -> Option<Serial> {
    if record.rr_type() != Rtype::SOA {
        return None;
    }
    match record.rdata() {
        Rdata::Soa(soa) => Some(soa.serial),
        _ => None,
    }
}

/// Проверяет лимит числа записей.
pub(crate) fn check_record_limit(
    limits: &TransferLimits,
    count: usize,
) -> Result<(), TransferError> {
    if count > limits.max_records {
        return Err(TransferError::limit(
            LimitKind::Records,
            count as u64,
            limits.max_records as u64,
        ));
    }
    Ok(())
}

/// Проверяет лимит числа байтов.
pub(crate) fn check_byte_limit(limits: &TransferLimits, count: u64) -> Result<(), TransferError> {
    if count > limits.max_bytes {
        return Err(TransferError::limit(
            LimitKind::Bytes,
            count,
            limits.max_bytes,
        ));
    }
    Ok(())
}

/// Проверяет лимит числа сообщений.
pub(crate) fn check_message_limit(
    limits: &TransferLimits,
    count: usize,
) -> Result<(), TransferError> {
    if count > limits.max_messages {
        return Err(TransferError::limit(
            LimitKind::Messages,
            count as u64,
            limits.max_messages as u64,
        ));
    }
    Ok(())
}

/// Применяет дельты IXFR к снапшоту.
///
/// # Errors
///
/// [`TransferError::Serial`], если serial не сходится, или
/// [`TransferError::Protocol`], если удаляется отсутствующая запись.
pub fn apply_deltas(
    base: &ZoneSnapshot,
    deltas: &[crate::ixfr::ZoneDelta],
) -> Result<ZoneSnapshot, TransferError> {
    let mut records: HashSet<Record> = base.records.iter().cloned().collect();
    let mut serial = base.serial();
    let mut soa = base.soa.clone();
    for delta in deltas {
        if delta.old_soa().owner() != base.origin() || delta.new_soa().owner() != base.origin() {
            return Err(TransferError::serial(
                "delta SOA owner does not match the zone origin",
            ));
        }
        if delta.from() != serial {
            return Err(TransferError::serial(
                "delta does not start at the current zone serial",
            ));
        }
        for record in delta.deletions() {
            if !records.remove(record) {
                return Err(TransferError::protocol(
                    "delta deletes a record that is not present",
                ));
            }
        }
        for record in delta.additions() {
            records.insert(record.clone());
        }
        soa = delta.new_soa().clone();
        serial = delta.to();
    }
    if soa_serial(&soa) != Some(serial) {
        return Err(TransferError::serial("final SOA serial mismatch"));
    }
    let mut all = Vec::with_capacity(records.len() + 1);
    all.push(soa);
    all.extend(records);
    ZoneSnapshot::new(base.origin.clone(), all)
}
