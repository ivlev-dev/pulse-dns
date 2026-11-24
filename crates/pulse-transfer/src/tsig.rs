//! TSIG: подпись и проверка DNS-транзакций (RFC 8945).
//!
//! MAC считается по сообщению ровно в том виде, в каком оно было отправлено
//! (до добавления TSIG), плюс TSIG variables (RFC 8945 §4.3.3). Для ответов
//! дополнительно включается request MAC; для второго и последующих сообщений
//! multi-message ответа — prior MAC и только таймеры (RFC 8945 §5.3.1).
//!
//! # Политика
//!
//! - HMAC-SHA256 — алгоритм по умолчанию; SHA-1/224/384/512 поддерживаются.
//! - HMAC-MD5 и прочие неизвестные алгоритмы не поддерживаются: узел с таким
//!   TSIG отвергается с [`TsigError::UnsupportedAlgorithm`].
//! - MAC сравнивается constant-time (`subtle`), секрет zeroize-ится, `Debug`
//!   не печатает секрет.
//! - Время проверяется по `Time Signed ± Fudge`; fudge ограничивается
//!   локальным максимумом (по умолчанию 300 с).
//! - `TsigReplayCache` отбрасывает сообщения с неувеличившимся `Time Signed`.

use std::collections::HashMap;
use std::fmt;

use aws_lc_rs::hmac;
use pulse_dns::{
    DecodeLimits, EncodeOptions, Message, Name, Rclass, Rcode, Rdata, Record, Rtype, Ttl,
};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{TsigError, TsigErrorCode};
use crate::raw;

/// Алгоритм HMAC для TSIG (RFC 8945 §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TsigAlgorithm {
    /// `hmac-sha1`.
    HmacSha1,
    /// `hmac-sha224`.
    HmacSha224,
    /// `hmac-sha256` (по умолчанию).
    HmacSha256,
    /// `hmac-sha384`.
    HmacSha384,
    /// `hmac-sha512`.
    HmacSha512,
}

impl TsigAlgorithm {
    /// Алгоритм по умолчанию (HMAC-SHA256).
    pub const DEFAULT: Self = Self::HmacSha256;

    /// Все поддерживаемые алгоритмы.
    pub const ALL: [Self; 5] = [
        Self::HmacSha1,
        Self::HmacSha224,
        Self::HmacSha256,
        Self::HmacSha384,
        Self::HmacSha512,
    ];

    /// Текстовое имя алгоритма без завершающей точки.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::HmacSha1 => "hmac-sha1",
            Self::HmacSha224 => "hmac-sha224",
            Self::HmacSha256 => "hmac-sha256",
            Self::HmacSha384 => "hmac-sha384",
            Self::HmacSha512 => "hmac-sha512",
        }
    }

    /// Каноническая wire-форма имени алгоритма.
    #[must_use]
    pub const fn name_wire(self) -> &'static [u8] {
        match self {
            Self::HmacSha1 => b"\x09hmac-sha1\0",
            Self::HmacSha224 => b"\x0bhmac-sha224\0",
            Self::HmacSha256 => b"\x0bhmac-sha256\0",
            Self::HmacSha384 => b"\x0bhmac-sha384\0",
            Self::HmacSha512 => b"\x0bhmac-sha512\0",
        }
    }

    /// Распознаёт алгоритм по имени.
    ///
    /// # Errors
    ///
    /// [`TsigError::UnsupportedAlgorithm`], если имя не входит в
    /// поддерживаемый набор.
    pub fn from_name(name: &Name) -> Result<Self, TsigError> {
        Self::ALL
            .into_iter()
            .find(|algorithm| name.as_wire() == algorithm.name_wire())
            .ok_or_else(|| TsigError::UnsupportedAlgorithm {
                name: name.to_string(),
            })
    }

    /// Длина полного MAC.
    #[must_use]
    pub const fn output_len(self) -> usize {
        match self {
            Self::HmacSha1 => 20,
            Self::HmacSha224 => 28,
            Self::HmacSha256 => 32,
            Self::HmacSha384 => 48,
            Self::HmacSha512 => 64,
        }
    }

    /// Минимально допустимая длина MAC (RFC 8945 §5.2.2.1).
    #[must_use]
    pub const fn min_mac_len(self) -> usize {
        let half = self.output_len() / 2;
        if half > 10 { half } else { 10 }
    }

    const fn aws(self) -> hmac::Algorithm {
        match self {
            Self::HmacSha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            Self::HmacSha224 => hmac::HMAC_SHA224,
            Self::HmacSha256 => hmac::HMAC_SHA256,
            Self::HmacSha384 => hmac::HMAC_SHA384,
            Self::HmacSha512 => hmac::HMAC_SHA512,
        }
    }
}

impl fmt::Display for TsigAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Политика TSIG-ключа.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TsigKeyPolicy {
    /// Fudge, используемый при подписи, секунды.
    pub fudge: u16,
    /// Максимальный принимаемый fudge, секунды.
    pub max_fudge: u16,
    /// Разрешить несовпадение `Original ID` и ID запроса (forwarding).
    pub allow_original_id_mismatch: bool,
}

impl Default for TsigKeyPolicy {
    fn default() -> Self {
        Self {
            fudge: 300,
            max_fudge: 300,
            allow_original_id_mismatch: false,
        }
    }
}

/// Секрет ключа с затиранием памяти.
#[derive(Zeroize, ZeroizeOnDrop)]
struct SecretBytes(Vec<u8>);

impl SecretBytes {
    fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

/// TSIG-ключ.
///
/// Секрет не печатается в [`fmt::Debug`] и затирается при уничтожении ключа.
pub struct TsigKey {
    name: Name,
    algorithm: TsigAlgorithm,
    algorithm_name: Name,
    secret: SecretBytes,
    policy: TsigKeyPolicy,
}

impl TsigKey {
    /// Создаёт ключ с политикой по умолчанию.
    ///
    /// # Errors
    ///
    /// [`TsigError::EmptySecret`] или ошибка имени алгоритма.
    pub fn new(
        name: Name,
        algorithm: TsigAlgorithm,
        secret: impl Into<Vec<u8>>,
    ) -> Result<Self, TsigError> {
        Self::new_with_policy(name, algorithm, secret, TsigKeyPolicy::default())
    }

    /// Создаёт ключ с явной политикой.
    ///
    /// # Errors
    ///
    /// [`TsigError::EmptySecret`] или ошибка имени алгоритма.
    pub fn new_with_policy(
        name: Name,
        algorithm: TsigAlgorithm,
        secret: impl Into<Vec<u8>>,
        policy: TsigKeyPolicy,
    ) -> Result<Self, TsigError> {
        let secret = secret.into();
        if secret.is_empty() {
            return Err(TsigError::EmptySecret);
        }
        let algorithm_name = Name::from_wire(algorithm.name_wire())?;
        Ok(Self {
            name,
            algorithm,
            algorithm_name,
            secret: SecretBytes::new(secret),
            policy,
        })
    }

    /// Имя ключа.
    #[must_use]
    pub const fn name(&self) -> &Name {
        &self.name
    }

    /// Алгоритм.
    #[must_use]
    pub const fn algorithm(&self) -> TsigAlgorithm {
        self.algorithm
    }

    /// Имя алгоритма в wire-форме.
    #[must_use]
    pub const fn algorithm_name(&self) -> &Name {
        &self.algorithm_name
    }

    /// Политика ключа.
    #[must_use]
    pub const fn policy(&self) -> TsigKeyPolicy {
        self.policy
    }

    /// Fudge, используемый при подписи.
    #[must_use]
    pub const fn fudge(&self) -> u16 {
        self.policy.fudge
    }

    /// Подписывает запрос.
    ///
    /// `message` — wire-сообщение без TSIG. ID в MAC-входе нормализуется к
    /// `original_id`.
    ///
    /// # Errors
    ///
    /// [`TsigError`] при некорректных параметрах.
    pub fn sign_request(
        &self,
        message: &[u8],
        original_id: u16,
        time_signed: u64,
    ) -> Result<TsigRecord, TsigError> {
        let params = TsigSignParams::new(original_id, time_signed, self.policy.fudge);
        self.sign_with_variables(message, None, &params)
    }

    /// Подписывает запрос с произвольными TSIG-полями.
    ///
    /// # Errors
    ///
    /// [`TsigError`] при некорректных параметрах.
    pub fn sign_request_with(
        &self,
        message: &[u8],
        params: &TsigSignParams,
    ) -> Result<TsigRecord, TsigError> {
        self.sign_with_variables(message, None, params)
    }

    /// Подписывает ответ на подписанный запрос.
    ///
    /// # Errors
    ///
    /// [`TsigError`] при некорректных параметрах.
    pub fn sign_response(
        &self,
        message: &[u8],
        request_mac: &[u8],
        original_id: u16,
        time_signed: u64,
    ) -> Result<TsigRecord, TsigError> {
        let params = TsigSignParams::new(original_id, time_signed, self.policy.fudge);
        self.sign_with_variables(message, Some(request_mac), &params)
    }

    /// Подписывает ответ с произвольными TSIG-полями (BADTIME и т. п.).
    ///
    /// # Errors
    ///
    /// [`TsigError`] при некорректных параметрах.
    pub fn sign_response_with(
        &self,
        message: &[u8],
        request_mac: Option<&[u8]>,
        params: &TsigSignParams,
    ) -> Result<TsigRecord, TsigError> {
        self.sign_with_variables(message, request_mac, params)
    }

    /// Подписывает сообщение в multi-message цепочке (RFC 8945 §5.3.1).
    ///
    /// `messages` — все сообщения после последнего TSIG, включая текущее,
    /// без TSIG. Используются только таймеры, без полного набора TSIG
    /// variables.
    ///
    /// # Errors
    ///
    /// [`TsigError`] при некорректных параметрах.
    pub fn sign_chain(
        &self,
        prior_mac: &[u8],
        messages: &[&[u8]],
        original_id: u16,
        time_signed: u64,
        fudge: u16,
    ) -> Result<TsigRecord, TsigError> {
        let mut record = TsigRecord::new(
            self.name.clone(),
            self.algorithm_name.clone(),
            time_signed,
            fudge,
            Vec::new(),
            original_id,
            TsigErrorCode::NONE,
            Vec::new(),
        )?;
        let normalized: Vec<Vec<u8>> = messages
            .iter()
            .map(|message| normalize_id(message, original_id))
            .collect::<Result<_, _>>()?;
        let parts: Vec<&[u8]> = normalized.iter().map(Vec::as_slice).collect();
        let full = self.compute_chain_mac(prior_mac, &parts, &record)?;
        record.mac = full;
        Ok(record)
    }

    fn sign_with_variables(
        &self,
        message: &[u8],
        prior_mac: Option<&[u8]>,
        params: &TsigSignParams,
    ) -> Result<TsigRecord, TsigError> {
        let data = normalize_id(message, params.original_id)?;
        let mut record = TsigRecord::new(
            self.name.clone(),
            self.algorithm_name.clone(),
            params.time_signed,
            params.fudge,
            Vec::new(),
            params.original_id,
            params.error,
            params.other_data.clone(),
        )?;
        let full = self.compute_full_mac(&data, prior_mac, &record)?;
        record.mac = self.truncate_mac(full, params.truncate)?;
        Ok(record)
    }

    fn truncate_mac(&self, full: Vec<u8>, truncate: Option<usize>) -> Result<Vec<u8>, TsigError> {
        let Some(length) = truncate else {
            return Ok(full);
        };
        let minimum = self.algorithm.min_mac_len();
        let maximum = full.len();
        if length < minimum || length > maximum {
            return Err(TsigError::InvalidTruncation {
                len: length,
                minimum,
                maximum,
            });
        }
        full.get(..length)
            .map(<[u8]>::to_vec)
            .ok_or(TsigError::InvalidTruncation {
                len: length,
                minimum,
                maximum,
            })
    }

    fn compute_full_mac(
        &self,
        message: &[u8],
        prior_mac: Option<&[u8]>,
        record: &TsigRecord,
    ) -> Result<Vec<u8>, TsigError> {
        let mut prior_length = [0u8; 2];
        if let Some(prior) = prior_mac {
            let length = u16::try_from(prior.len()).map_err(|_| TsigError::Malformed {
                reason: "request MAC is longer than 65535 octets",
            })?;
            prior_length = length.to_be_bytes();
        }
        let class = Rclass::ANY.as_u16().to_be_bytes();
        let ttl = 0_u32.to_be_bytes();
        let time = encode_u48(record.time_signed)?;
        let fudge = record.fudge.to_be_bytes();
        let error = record.error.as_u16().to_be_bytes();
        let other_len =
            u16::try_from(record.other_data.len()).map_err(|_| TsigError::Malformed {
                reason: "TSIG other data is longer than 65535 octets",
            })?;
        let other_len = other_len.to_be_bytes();

        let mut parts: Vec<&[u8]> = Vec::with_capacity(18);
        if let Some(prior) = prior_mac {
            parts.push(&prior_length[..]);
            parts.push(prior);
        }
        parts.push(message);
        parts.push(record.key_name.as_wire());
        parts.push(&class[..]);
        parts.push(&ttl[..]);
        parts.push(record.algorithm_name.as_wire());
        parts.push(&time[..]);
        parts.push(&fudge[..]);
        parts.push(&error[..]);
        parts.push(&other_len[..]);
        parts.push(record.other_data.as_slice());
        self.mac_parts(&parts)
    }

    fn compute_chain_mac(
        &self,
        prior_mac: &[u8],
        messages: &[&[u8]],
        record: &TsigRecord,
    ) -> Result<Vec<u8>, TsigError> {
        let length = u16::try_from(prior_mac.len()).map_err(|_| TsigError::Malformed {
            reason: "prior MAC is longer than 65535 octets",
        })?;
        let prior_length = length.to_be_bytes();
        let time = encode_u48(record.time_signed)?;
        let fudge = record.fudge.to_be_bytes();
        let mut parts: Vec<&[u8]> = Vec::with_capacity(messages.len() + 4);
        parts.push(&prior_length[..]);
        parts.push(prior_mac);
        parts.extend_from_slice(messages);
        parts.push(&time[..]);
        parts.push(&fudge[..]);
        self.mac_parts(&parts)
    }

    fn mac_parts(&self, parts: &[&[u8]]) -> Result<Vec<u8>, TsigError> {
        let key = hmac::Key::new(self.algorithm.aws(), self.secret.as_slice());
        let mut context = hmac::Context::with_key(&key);
        for part in parts {
            context.update(part);
        }
        Ok(context.sign().as_ref().to_vec())
    }

    fn check_key(&self, record: &TsigRecord) -> Result<(), TsigError> {
        if record.key_name != self.name {
            return Err(TsigError::KeyNameMismatch {
                expected: self.name.to_string(),
                actual: record.key_name.to_string(),
            });
        }
        if record.algorithm != self.algorithm || record.algorithm_name != self.algorithm_name {
            return Err(TsigError::AlgorithmMismatch {
                expected: self.algorithm.name().to_owned(),
                actual: record.algorithm_name.to_string(),
            });
        }
        Ok(())
    }

    fn check_fudge(&self, record: &TsigRecord) -> Result<(), TsigError> {
        if record.fudge > self.policy.max_fudge {
            return Err(TsigError::FudgeTooLarge {
                received: record.fudge,
                maximum: self.policy.max_fudge,
            });
        }
        Ok(())
    }

    fn check_time(record: &TsigRecord, now: u64) -> Result<(), TsigError> {
        let skew = now.abs_diff(record.time_signed);
        if skew > u64::from(record.fudge) {
            return Err(TsigError::TimeSkew {
                now,
                signed: record.time_signed,
                fudge: record.fudge,
            });
        }
        Ok(())
    }

    fn compare_mac(&self, expected: &[u8], received: &[u8]) -> Result<(), TsigError> {
        if received.is_empty() {
            return Err(TsigError::Unsigned);
        }
        if received.len() > expected.len() {
            return Err(TsigError::MacTooLong {
                len: received.len(),
                maximum: expected.len(),
            });
        }
        let minimum = self.algorithm.min_mac_len();
        if received.len() < minimum {
            return Err(TsigError::MacTooShort {
                len: received.len(),
                minimum,
            });
        }
        let truncated = expected
            .get(..received.len())
            .ok_or(TsigError::MacTooLong {
                len: received.len(),
                maximum: expected.len(),
            })?;
        if bool::from(truncated.ct_eq(received)) {
            Ok(())
        } else {
            Err(TsigError::BadSig)
        }
    }

    fn verify_full_mac(
        &self,
        message: &[u8],
        prior_mac: Option<&[u8]>,
        record: &TsigRecord,
    ) -> Result<(), TsigError> {
        let expected = self.compute_full_mac(message, prior_mac, record)?;
        self.compare_mac(&expected, &record.mac)
    }

    fn verify_chain_mac(
        &self,
        prior_mac: &[u8],
        messages: &[&[u8]],
        record: &TsigRecord,
    ) -> Result<(), TsigError> {
        let expected = self.compute_chain_mac(prior_mac, messages, record)?;
        self.compare_mac(&expected, &record.mac)
    }

    /// Разбирает и проверяет TSIG запроса.
    ///
    /// # Errors
    ///
    /// [`TsigError::Missing`] или любая ошибка проверки TSIG.
    pub fn verify_request(&self, raw: &[u8], now: u64) -> Result<VerifiedTsig, TsigError> {
        let envelope = parse_tsig(raw)?.ok_or(TsigError::Missing)?;
        self.verify_request_envelope(&envelope, now)
    }

    /// Проверяет разобранный TSIG запроса.
    ///
    /// # Errors
    ///
    /// Любая ошибка имени ключа, MAC, времени или `Original ID`.
    pub fn verify_request_envelope(
        &self,
        envelope: &TsigEnvelope,
        now: u64,
    ) -> Result<VerifiedTsig, TsigError> {
        let record = envelope.record();
        self.check_key(record)?;
        if !self.policy.allow_original_id_mismatch && record.original_id != envelope.wire_id() {
            return Err(TsigError::OriginalIdMismatch {
                expected: envelope.wire_id(),
                actual: record.original_id,
            });
        }
        if record.error != TsigErrorCode::NONE {
            return Err(TsigError::Malformed {
                reason: "TSIG request error field must be zero",
            });
        }
        self.verify_full_mac(envelope.message(), None, record)?;
        self.check_fudge(record)?;
        Self::check_time(record, now)?;
        Ok(VerifiedTsig::new(record.clone()))
    }

    /// Проверяет запрос и учитывает его в replay-кэше.
    ///
    /// # Errors
    ///
    /// [`TsigError::Replay`] или любая ошибка проверки TSIG.
    pub fn verify_request_with_replay(
        &self,
        raw: &[u8],
        now: u64,
        cache: &mut TsigReplayCache,
    ) -> Result<VerifiedTsig, TsigError> {
        let verified = self.verify_request(raw, now)?;
        cache.check_and_record(
            verified.record().key_name(),
            verified.record().time_signed(),
        )?;
        Ok(verified)
    }

    /// Разбирает и проверяет TSIG ответа.
    ///
    /// # Errors
    ///
    /// [`TsigError::Missing`] или любая ошибка проверки TSIG.
    pub fn verify_response(
        &self,
        raw: &[u8],
        request_mac: &[u8],
        expected_id: u16,
        now: u64,
    ) -> Result<VerifiedTsig, TsigError> {
        let envelope = parse_tsig(raw)?.ok_or(TsigError::Missing)?;
        self.verify_response_envelope(&envelope, request_mac, expected_id, now)
    }

    /// Проверяет разобранный TSIG ответа.
    ///
    /// # Errors
    ///
    /// Любая ошибка имени ключа, MAC, времени или `Original ID`.
    pub fn verify_response_envelope(
        &self,
        envelope: &TsigEnvelope,
        request_mac: &[u8],
        expected_id: u16,
        now: u64,
    ) -> Result<VerifiedTsig, TsigError> {
        let record = envelope.record();
        self.check_key(record)?;
        if record.original_id != expected_id {
            return Err(TsigError::OriginalIdMismatch {
                expected: expected_id,
                actual: record.original_id,
            });
        }
        self.verify_full_mac(envelope.message(), Some(request_mac), record)?;
        self.check_fudge(record)?;
        if record.error == TsigErrorCode::BADTIME {
            if record.other_data.len() != 6 {
                return Err(TsigError::Malformed {
                    reason: "BADTIME response must carry 6 octets of server time",
                });
            }
        } else {
            Self::check_time(record, now)?;
        }
        Ok(VerifiedTsig::new(record.clone()))
    }

    /// Проверяет TSIG в цепочке multi-message ответа.
    ///
    /// `messages` — сообщения после последнего TSIG, включая текущее.
    ///
    /// # Errors
    ///
    /// Любая ошибка имени ключа, MAC или времени.
    pub fn verify_chain(
        &self,
        prior_mac: &[u8],
        messages: &[&[u8]],
        record: &TsigRecord,
        now: u64,
    ) -> Result<VerifiedTsig, TsigError> {
        self.check_key(record)?;
        if record.error != TsigErrorCode::NONE {
            return Err(TsigError::Malformed {
                reason: "chained TSIG error field must be zero",
            });
        }
        self.verify_chain_mac(prior_mac, messages, record)?;
        self.check_fudge(record)?;
        Self::check_time(record, now)?;
        Ok(VerifiedTsig::new(record.clone()))
    }
}

impl fmt::Debug for TsigKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TsigKey")
            .field("name", &self.name)
            .field("algorithm", &self.algorithm)
            .field("secret", &"<redacted>")
            .field("fudge", &self.policy.fudge)
            .finish_non_exhaustive()
    }
}

/// Параметры подписи TSIG.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsigSignParams {
    /// `Original ID`.
    pub original_id: u16,
    /// `Time Signed` (48 бит).
    pub time_signed: u64,
    /// `Fudge`.
    pub fudge: u16,
    /// Поле `Error`.
    pub error: TsigErrorCode,
    /// `Other Data`.
    pub other_data: Vec<u8>,
    /// Усечь MAC до указанной длины.
    pub truncate: Option<usize>,
}

impl TsigSignParams {
    /// Создаёт параметры с пустыми `Error`/`Other Data`.
    #[must_use]
    pub const fn new(original_id: u16, time_signed: u64, fudge: u16) -> Self {
        Self {
            original_id,
            time_signed,
            fudge,
            error: TsigErrorCode::NONE,
            other_data: Vec::new(),
            truncate: None,
        }
    }
}

/// TSIG RR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsigRecord {
    key_name: Name,
    algorithm_name: Name,
    algorithm: TsigAlgorithm,
    time_signed: u64,
    fudge: u16,
    mac: Vec<u8>,
    original_id: u16,
    error: TsigErrorCode,
    other_data: Vec<u8>,
}

impl TsigRecord {
    /// Создаёт TSIG RR.
    ///
    /// # Errors
    ///
    /// [`TsigError::InvalidTime`] или [`TsigError::Malformed`] при
    /// переполнении полей.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        key_name: Name,
        algorithm_name: Name,
        time_signed: u64,
        fudge: u16,
        mac: Vec<u8>,
        original_id: u16,
        error: TsigErrorCode,
        other_data: Vec<u8>,
    ) -> Result<Self, TsigError> {
        if time_signed > 0xFFFF_FFFF_FFFF {
            return Err(TsigError::InvalidTime { value: time_signed });
        }
        if mac.len() > usize::from(u16::MAX) {
            return Err(TsigError::Malformed {
                reason: "TSIG MAC is longer than 65535 octets",
            });
        }
        if other_data.len() > usize::from(u16::MAX) {
            return Err(TsigError::Malformed {
                reason: "TSIG other data is longer than 65535 octets",
            });
        }
        let algorithm = TsigAlgorithm::from_name(&algorithm_name)?;
        Ok(Self {
            key_name,
            algorithm_name,
            algorithm,
            time_signed,
            fudge,
            mac,
            original_id,
            error,
            other_data,
        })
    }

    /// Создаёт незаполненный TSIG RR для error-ответа (MAC пуст).
    ///
    /// # Errors
    ///
    /// [`TsigError::InvalidTime`].
    pub fn unsigned_error(
        request: &Self,
        code: TsigErrorCode,
        now: u64,
    ) -> Result<Self, TsigError> {
        Self::new(
            request.key_name.clone(),
            request.algorithm_name.clone(),
            now,
            request.fudge,
            Vec::new(),
            request.original_id,
            code,
            Vec::new(),
        )
    }

    /// Разбирает TSIG из [`Record`].
    ///
    /// # Errors
    ///
    /// [`TsigError::Malformed`], если запись не является корректным TSIG RR.
    pub fn from_record(record: &Record) -> Result<Self, TsigError> {
        if record.rr_type() != Rtype::TSIG {
            return Err(TsigError::Malformed {
                reason: "record is not TSIG",
            });
        }
        if record.class() != Rclass::ANY {
            return Err(TsigError::Malformed {
                reason: "TSIG class must be ANY",
            });
        }
        if record.ttl() != Ttl::ZERO {
            return Err(TsigError::Malformed {
                reason: "TSIG TTL must be zero",
            });
        }
        let Rdata::Unknown { rdata, .. } = record.rdata() else {
            return Err(TsigError::Malformed {
                reason: "TSIG RDATA must be opaque",
            });
        };
        let name_end = raw::skip_name(rdata, 0).ok_or(TsigError::Malformed {
            reason: "truncated TSIG algorithm name",
        })?;
        let algorithm_name =
            Name::from_wire(rdata.get(..name_end).ok_or(TsigError::Malformed {
                reason: "invalid TSIG algorithm name",
            })?)?;
        let time_signed = raw::read_u48(rdata, name_end).ok_or(TsigError::Malformed {
            reason: "truncated TSIG time",
        })?;
        let fudge = raw::read_u16(rdata, name_end + 6).ok_or(TsigError::Malformed {
            reason: "truncated TSIG fudge",
        })?;
        let mac_len = usize::from(raw::read_u16(rdata, name_end + 8).ok_or(
            TsigError::Malformed {
                reason: "truncated TSIG MAC size",
            },
        )?);
        let mac_start = name_end + 10;
        let mac_end = mac_start.checked_add(mac_len).ok_or(TsigError::Malformed {
            reason: "TSIG MAC size overflow",
        })?;
        let mac = rdata
            .get(mac_start..mac_end)
            .ok_or(TsigError::Malformed {
                reason: "truncated TSIG MAC",
            })?
            .to_vec();
        let original_id = raw::read_u16(rdata, mac_end).ok_or(TsigError::Malformed {
            reason: "truncated TSIG original ID",
        })?;
        let error = raw::read_u16(rdata, mac_end + 2).ok_or(TsigError::Malformed {
            reason: "truncated TSIG error",
        })?;
        let other_len = usize::from(raw::read_u16(rdata, mac_end + 4).ok_or(
            TsigError::Malformed {
                reason: "truncated TSIG other length",
            },
        )?);
        let other_start = mac_end + 6;
        let other_end = other_start
            .checked_add(other_len)
            .ok_or(TsigError::Malformed {
                reason: "TSIG other data size overflow",
            })?;
        let other_data = rdata
            .get(other_start..other_end)
            .ok_or(TsigError::Malformed {
                reason: "truncated TSIG other data",
            })?
            .to_vec();
        if other_end != rdata.len() {
            return Err(TsigError::Malformed {
                reason: "trailing bytes after TSIG RDATA",
            });
        }
        Self::new(
            record.owner().clone(),
            algorithm_name,
            time_signed,
            fudge,
            mac,
            original_id,
            TsigErrorCode::from_u16(error),
            other_data,
        )
    }

    /// Имя ключа.
    #[must_use]
    pub const fn key_name(&self) -> &Name {
        &self.key_name
    }

    /// Имя алгоритма.
    #[must_use]
    pub const fn algorithm_name(&self) -> &Name {
        &self.algorithm_name
    }

    /// Алгоритм.
    #[must_use]
    pub const fn algorithm(&self) -> TsigAlgorithm {
        self.algorithm
    }

    /// Время подписи (48 бит).
    #[must_use]
    pub const fn time_signed(&self) -> u64 {
        self.time_signed
    }

    /// Fudge.
    #[must_use]
    pub const fn fudge(&self) -> u16 {
        self.fudge
    }

    /// MAC.
    #[must_use]
    pub fn mac(&self) -> &[u8] {
        &self.mac
    }

    /// `Original ID`.
    #[must_use]
    pub const fn original_id(&self) -> u16 {
        self.original_id
    }

    /// Поле `Error`.
    #[must_use]
    pub const fn error(&self) -> TsigErrorCode {
        self.error
    }

    /// `Other Data`.
    #[must_use]
    pub fn other_data(&self) -> &[u8] {
        &self.other_data
    }

    /// RDATA TSIG (RFC 8945 §4.2).
    ///
    /// # Errors
    ///
    /// [`TsigError`] при переполнении полей длины.
    pub fn rdata(&self) -> Result<Vec<u8>, TsigError> {
        let mut out = Vec::new();
        out.extend_from_slice(self.algorithm_name.as_wire());
        out.extend_from_slice(&encode_u48(self.time_signed)?);
        out.extend_from_slice(&self.fudge.to_be_bytes());
        let mac_len = u16::try_from(self.mac.len()).map_err(|_| TsigError::Malformed {
            reason: "TSIG MAC is longer than 65535 octets",
        })?;
        out.extend_from_slice(&mac_len.to_be_bytes());
        out.extend_from_slice(&self.mac);
        out.extend_from_slice(&self.original_id.to_be_bytes());
        out.extend_from_slice(&self.error.as_u16().to_be_bytes());
        let other_len = u16::try_from(self.other_data.len()).map_err(|_| TsigError::Malformed {
            reason: "TSIG other data is longer than 65535 octets",
        })?;
        out.extend_from_slice(&other_len.to_be_bytes());
        out.extend_from_slice(&self.other_data);
        Ok(out)
    }

    /// Собирает [`Record`] типа TSIG.
    ///
    /// # Errors
    ///
    /// [`TsigError`] при некорректной RDATA.
    pub fn to_record(&self) -> Result<Record, TsigError> {
        let rdata = self.rdata()?;
        let rdata = Rdata::unknown(Rtype::TSIG, rdata)?;
        Ok(Record::new(
            self.key_name.clone(),
            Rtype::TSIG,
            Rclass::ANY,
            Ttl::ZERO,
            rdata,
        )?)
    }

    /// Кодирует RR в канонической wire-форме без компрессии.
    ///
    /// # Errors
    ///
    /// [`TsigError`] при некорректной RDATA.
    pub fn encode_rr(&self) -> Result<Vec<u8>, TsigError> {
        Ok(self.to_record()?.to_canonical_wire()?)
    }
}

/// Разобранный TSIG и сообщение без него.
#[derive(Debug, Clone)]
pub struct TsigEnvelope {
    record: TsigRecord,
    message: Vec<u8>,
    wire_id: u16,
}

impl TsigEnvelope {
    /// TSIG RR.
    #[must_use]
    pub const fn record(&self) -> &TsigRecord {
        &self.record
    }

    /// Сообщение без TSIG с ID, нормализованным по `Original ID`.
    #[must_use]
    pub fn message(&self) -> &[u8] {
        &self.message
    }

    /// ID из исходного заголовка.
    #[must_use]
    pub const fn wire_id(&self) -> u16 {
        self.wire_id
    }

    /// MAC пуст (unsigned error).
    #[must_use]
    pub fn is_unsigned(&self) -> bool {
        self.record.mac.is_empty()
    }
}

/// Успешно проверенный TSIG.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTsig {
    record: TsigRecord,
}

impl VerifiedTsig {
    fn new(record: TsigRecord) -> Self {
        Self { record }
    }

    /// TSIG RR.
    #[must_use]
    pub const fn record(&self) -> &TsigRecord {
        &self.record
    }

    /// Проверенный MAC (как передан; может быть усечён).
    #[must_use]
    pub fn mac(&self) -> &[u8] {
        self.record.mac()
    }

    /// Время подписи.
    #[must_use]
    pub const fn time_signed(&self) -> u64 {
        self.record.time_signed()
    }
}

/// Разбирает TSIG из сообщения и вырезает его, сохраняя остальные байты.
///
/// # Errors
///
/// [`TsigError::Malformed`], если TSIG расположен не последним, встречается
/// более одного раза или сообщение некорректно.
pub fn parse_tsig(raw: &[u8]) -> Result<Option<TsigEnvelope>, TsigError> {
    let message = Message::decode(raw, &DecodeLimits::default())?;
    for section in [message.answers(), message.authority()] {
        if section.iter().any(|record| record.rr_type() == Rtype::TSIG) {
            return Err(TsigError::Malformed {
                reason: "TSIG record outside additional section",
            });
        }
    }
    let additional = message.additional();
    let mut tsig_records = additional
        .iter()
        .filter(|record| record.rr_type() == Rtype::TSIG);
    let Some(record) = tsig_records.next() else {
        return Ok(None);
    };
    if tsig_records.next().is_some() {
        return Err(TsigError::Malformed {
            reason: "multiple TSIG records",
        });
    }
    let Some(last) = additional.last() else {
        return Err(TsigError::Malformed {
            reason: "TSIG is not the last additional record",
        });
    };
    if last.rr_type() != Rtype::TSIG {
        return Err(TsigError::Malformed {
            reason: "TSIG is not the last additional record",
        });
    }
    let record = TsigRecord::from_record(record)?;
    let stripped = raw::strip_tsig(raw)?.ok_or(TsigError::Malformed {
        reason: "TSIG disappeared during extraction",
    })?;
    let mut message = stripped.bytes;
    let id = record.original_id.to_be_bytes();
    message
        .get_mut(0..2)
        .ok_or(TsigError::Malformed {
            reason: "missing message ID",
        })?
        .copy_from_slice(&id);
    Ok(Some(TsigEnvelope {
        record,
        message,
        wire_id: stripped.wire_id,
    }))
}

/// Добавляет TSIG RR в конец сообщения и увеличивает ARCOUNT.
///
/// # Errors
///
/// [`TsigError::MessageTooLarge`] или ошибка кодирования TSIG.
pub fn append_tsig(mut message: Vec<u8>, record: &TsigRecord) -> Result<Vec<u8>, TsigError> {
    let rr = record.encode_rr()?;
    let total = message.len().saturating_add(rr.len());
    if total > usize::from(u16::MAX) {
        return Err(TsigError::MessageTooLarge { len: total });
    }
    let arcount = raw::read_u16(&message, 10).ok_or(TsigError::Malformed {
        reason: "missing ARCOUNT",
    })?;
    let arcount = arcount.checked_add(1).ok_or(TsigError::Malformed {
        reason: "ARCOUNT overflow",
    })?;
    message
        .get_mut(10..12)
        .ok_or(TsigError::Malformed {
            reason: "missing ARCOUNT",
        })?
        .copy_from_slice(&arcount.to_be_bytes());
    message.extend_from_slice(&rr);
    Ok(message)
}

/// Собирает error-ответ TSIG (RFC 8945 §5.3.2).
///
/// Для `BADKEY`/`BADSIG`/`BADTRUNC` ответ unsigned; для `BADTIME` — подписан
/// тем же ключом, с временем клиента и временем сервера в `Other Data`.
///
/// # Errors
///
/// [`TsigError`] при кодировании ответа.
pub fn build_tsig_error_response(
    request: &Message,
    request_tsig: Option<&TsigRecord>,
    key: Option<&TsigKey>,
    request_mac: Option<&[u8]>,
    code: TsigErrorCode,
    now: u64,
) -> Result<Vec<u8>, TsigError> {
    let mut response = Message::response(request);
    response.set_rcode(Rcode::NOTAUTH);
    let base = response.encode(&EncodeOptions::default())?;
    let Some(tsig) = request_tsig else {
        return Ok(base);
    };
    let record = if code == TsigErrorCode::BADTIME {
        let key = key.ok_or(TsigError::Missing)?;
        let other = encode_u48(now)?.to_vec();
        let params = TsigSignParams {
            original_id: tsig.original_id,
            time_signed: tsig.time_signed,
            fudge: tsig.fudge,
            error: code,
            other_data: other,
            truncate: None,
        };
        key.sign_response_with(&base, request_mac, &params)?
    } else {
        TsigRecord::unsigned_error(tsig, code, now)?
    };
    append_tsig(base, &record)
}

/// Кэш для защиты от replay (RFC 8945 §5.2.3).
///
/// Хранит максимальный принятый `Time Signed` для каждого имени ключа и
/// отвергает сообщения с неувеличившимся временем.
#[derive(Debug)]
pub struct TsigReplayCache {
    seen: HashMap<Name, u64>,
    max_entries: usize,
}

impl TsigReplayCache {
    /// Создаёт кэш с ограничением на число ключей.
    #[must_use]
    pub fn new(max_entries: usize) -> Self {
        Self {
            seen: HashMap::new(),
            max_entries: max_entries.max(1),
        }
    }

    /// Проверяет и запоминает время для ключа.
    ///
    /// # Errors
    ///
    /// [`TsigError::Replay`], если `time` не больше ранее принятого.
    pub fn check_and_record(&mut self, key: &Name, time: u64) -> Result<(), TsigError> {
        if let Some(previous) = self.seen.get(key)
            && time <= *previous
        {
            return Err(TsigError::Replay {
                key: key.to_string(),
                time,
                previous: *previous,
            });
        }
        if self.seen.len() >= self.max_entries
            && !self.seen.contains_key(key)
            && let Some(oldest) = self
                .seen
                .iter()
                .min_by_key(|(_, value)| **value)
                .map(|(name, _)| name.clone())
        {
            self.seen.remove(&oldest);
        }
        self.seen.insert(key.clone(), time);
        Ok(())
    }
}

impl Default for TsigReplayCache {
    fn default() -> Self {
        Self::new(1024)
    }
}

/// Верификатор цепочки TSIG для multi-message ответа (AXFR/IXFR).
///
/// Первое сообщение обязано быть подписано; далее допускается до 99
/// промежуточных сообщений без TSIG (RFC 8945 §5.3.1).
pub struct TsigStreamVerifier<'a> {
    key: &'a TsigKey,
    expected_id: u16,
    request_mac: Vec<u8>,
    prior_mac: Option<Vec<u8>>,
    pending: Vec<u8>,
    unsigned_since: usize,
    first: bool,
    last_time: u64,
    original_id: u16,
}

impl<'a> TsigStreamVerifier<'a> {
    /// Создаёт верификатор для ответа на запрос с MAC `request_mac`.
    #[must_use]
    pub fn new(key: &'a TsigKey, request_mac: Vec<u8>, expected_id: u16) -> Self {
        Self {
            key,
            expected_id,
            request_mac,
            prior_mac: None,
            pending: Vec::new(),
            unsigned_since: 0,
            first: true,
            last_time: 0,
            original_id: expected_id,
        }
    }

    /// Проверяет очередное сообщение потока.
    ///
    /// Возвращает разобранный TSIG и сообщение без него, если оно было
    /// подписано.
    ///
    /// # Errors
    ///
    /// [`TsigError`] при нарушении цепочки, MAC или времени.
    pub fn verify_message(
        &mut self,
        raw: &[u8],
        now: u64,
    ) -> Result<Option<TsigEnvelope>, TsigError> {
        let envelope = parse_tsig(raw)?;
        if let Some(envelope) = &envelope
            && envelope.is_unsigned()
            && envelope.record().error().is_error()
        {
            // Unsigned error response (BADKEY/BADSIG/BADTRUNC): MAC проверять
            // нечем, но вызывающий должен увидеть код ошибки, а не
            // «unsigned» вместо серверного отказа.
            return Ok(Some(envelope.clone()));
        }
        if let Some(envelope) = envelope {
            let record = envelope.record();
            if self.first {
                self.key.verify_response_envelope(
                    &envelope,
                    &self.request_mac,
                    self.expected_id,
                    now,
                )?;
            } else {
                let prior = self.prior_mac.as_deref().ok_or(TsigError::Missing)?;
                let mut messages: Vec<&[u8]> = Vec::with_capacity(2);
                if !self.pending.is_empty() {
                    messages.push(&self.pending);
                }
                messages.push(envelope.message());
                self.key.verify_chain(prior, &messages, record, now)?;
            }
            if !self.first && record.time_signed() < self.last_time {
                return Err(TsigError::Malformed {
                    reason: "TSIG time went backwards in a transfer stream",
                });
            }
            if self.first {
                self.original_id = record.original_id();
            }
            self.prior_mac = Some(record.mac().to_vec());
            self.pending.clear();
            self.unsigned_since = 0;
            self.last_time = record.time_signed();
            self.first = false;
            Ok(Some(envelope))
        } else {
            if self.first {
                return Err(TsigError::Missing);
            }
            self.unsigned_since = self.unsigned_since.saturating_add(1);
            if self.unsigned_since > 99 {
                return Err(TsigError::Malformed {
                    reason: "more than 99 consecutive unsigned messages",
                });
            }
            let normalized = normalize_id(raw, self.original_id)?;
            self.pending.extend_from_slice(&normalized);
            self.first = false;
            Ok(None)
        }
    }
}

fn normalize_id(message: &[u8], original_id: u16) -> Result<Vec<u8>, TsigError> {
    let mut data = message.to_vec();
    data.get_mut(0..2)
        .ok_or(TsigError::Malformed {
            reason: "message shorter than DNS header",
        })?
        .copy_from_slice(&original_id.to_be_bytes());
    Ok(data)
}

/// Кодирует 48-битное значение.
///
/// # Errors
///
/// [`TsigError::InvalidTime`], если значение не помещается в 48 бит.
pub fn encode_u48(value: u64) -> Result<[u8; 6], TsigError> {
    if value > 0xFFFF_FFFF_FFFF {
        return Err(TsigError::InvalidTime { value });
    }
    let bytes = value.to_be_bytes();
    let mut out = [0u8; 6];
    let slice = bytes.get(2..8).ok_or(TsigError::InvalidTime { value })?;
    out.copy_from_slice(slice);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_key(algorithm: TsigAlgorithm) -> TsigKey {
        let name = Name::parse("key.example.com").unwrap();
        TsigKey::new(name, algorithm, vec![0x0b; 20]).unwrap()
    }

    #[test]
    fn hmac_sha1_rfc2202() {
        let key = make_key(TsigAlgorithm::HmacSha1);
        let mac = key.mac_parts(&[b"Hi There"]).unwrap();
        assert_eq!(hex::encode(mac), "b617318655057264e28bc0b6fb378c8ef146be00");
    }

    #[test]
    fn hmac_sha2_rfc4231_case1() {
        let key = make_key(TsigAlgorithm::HmacSha224);
        assert_eq!(
            hex::encode(key.mac_parts(&[b"Hi There"]).unwrap()),
            "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22"
        );
        let key = make_key(TsigAlgorithm::HmacSha256);
        assert_eq!(
            hex::encode(key.mac_parts(&[b"Hi There"]).unwrap()),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        let key = make_key(TsigAlgorithm::HmacSha384);
        assert_eq!(
            hex::encode(key.mac_parts(&[b"Hi There"]).unwrap()),
            "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6"
        );
        let key = make_key(TsigAlgorithm::HmacSha512);
        assert_eq!(
            hex::encode(key.mac_parts(&[b"Hi There"]).unwrap()),
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
        );
    }

    #[test]
    fn debug_does_not_leak_secret() {
        let key = make_key(TsigAlgorithm::HmacSha256);
        let debug = format!("{key:?}");
        assert!(!debug.contains("0b0b"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn replay_cache_rejects_non_increasing_time() {
        let name = Name::parse("key.example.com").unwrap();
        let mut cache = TsigReplayCache::new(4);
        cache.check_and_record(&name, 100).unwrap();
        assert!(matches!(
            cache.check_and_record(&name, 100),
            Err(TsigError::Replay { .. })
        ));
        assert!(matches!(
            cache.check_and_record(&name, 99),
            Err(TsigError::Replay { .. })
        ));
        cache.check_and_record(&name, 101).unwrap();
    }
}
