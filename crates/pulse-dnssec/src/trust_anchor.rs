//! Trust anchors: встроенный корневой KSK IANA и обновление из файла.
//!
//! В поставку включены **актуальные** root KSK: 20326 (KSK-2017) и 38696
//! (KSK-2024). Статический набор обновляется с релизами ПО
//! (ADR-0004 SEC-CR-007); автоматическое обновление по RFC 5011 реализовано
//! в [`crate::trust_update`] (см. [`RFC_5011_SUPPORTED`]).

use std::path::Path;
use std::str::FromStr;

use pulse_dns::{DnskeyData, DsData, Name};

use crate::ds::{DsPolicy, ds_matches};
use crate::error::TrustAnchorError;

/// RFC 5011 (trust anchor update) поддерживается через
/// [`crate::trust_update::TrustAnchorStore`].
pub const RFC_5011_SUPPORTED: bool = true;

const KSK_20326_DIGEST: [u8; 32] = [
    0xE0, 0x6D, 0x44, 0xB8, 0x0B, 0x8F, 0x1D, 0x39, 0xA9, 0x5C, 0x0B, 0x0D, 0x7C, 0x65, 0xD0, 0x84,
    0x58, 0xE8, 0x80, 0x40, 0x9B, 0xBC, 0x68, 0x34, 0x57, 0x10, 0x42, 0x37, 0xC7, 0xF8, 0xEC, 0x8D,
];
const KSK_38696_DIGEST: [u8; 32] = [
    0x68, 0x3D, 0x2D, 0x0A, 0xCB, 0x8C, 0x9B, 0x71, 0x2A, 0x19, 0x48, 0xB2, 0x7F, 0x74, 0x12, 0x19,
    0x29, 0x8D, 0x0A, 0x45, 0x0D, 0x61, 0x2C, 0x48, 0x3A, 0xF4, 0x44, 0xA4, 0xC0, 0xFB, 0x2B, 0x16,
];
const KSK_20326_VALID_FROM: u32 = 1_485_993_600;
const KSK_38696_VALID_FROM: u32 = 1_721_260_800;

/// Один trust anchor (DS-подобный digest DNSKEY).
#[derive(Clone, PartialEq, Eq)]
pub struct TrustAnchor {
    key_tag: u16,
    algorithm: u8,
    digest_type: u8,
    digest: Vec<u8>,
    valid_from: Option<u32>,
    valid_until: Option<u32>,
}

impl std::fmt::Debug for TrustAnchor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustAnchor")
            .field("key_tag", &self.key_tag)
            .field("algorithm", &self.algorithm)
            .field("digest_type", &self.digest_type)
            .field("digest_len", &self.digest.len())
            .field("valid_from", &self.valid_from)
            .field("valid_until", &self.valid_until)
            .finish()
    }
}

impl TrustAnchor {
    /// Создаёт anchor.
    ///
    /// # Errors
    ///
    /// [`TrustAnchorError::DigestLength`] при неверной длине digest.
    pub fn new(
        key_tag: u16,
        algorithm: u8,
        digest_type: u8,
        digest: Vec<u8>,
        valid_from: Option<u32>,
        valid_until: Option<u32>,
    ) -> Result<Self, TrustAnchorError> {
        validate_digest(digest_type, digest.len())?;
        Ok(Self {
            key_tag,
            algorithm,
            digest_type,
            digest,
            valid_from,
            valid_until,
        })
    }

    /// Key tag.
    #[must_use]
    pub const fn key_tag(&self) -> u16 {
        self.key_tag
    }

    /// Алгоритм DNSKEY.
    #[must_use]
    pub const fn algorithm(&self) -> u8 {
        self.algorithm
    }

    /// Digest type.
    #[must_use]
    pub const fn digest_type(&self) -> u8 {
        self.digest_type
    }

    /// Digest.
    #[must_use]
    pub fn digest(&self) -> &[u8] {
        &self.digest
    }

    /// Начало действия.
    #[must_use]
    pub const fn valid_from(&self) -> Option<u32> {
        self.valid_from
    }

    /// Конец действия.
    #[must_use]
    pub const fn valid_until(&self) -> Option<u32> {
        self.valid_until
    }

    /// Активен ли anchor в момент `now`.
    #[must_use]
    pub fn is_active_at(&self, now: u32) -> bool {
        let started = self.valid_from.is_none_or(|from| now >= from);
        let not_finished = self.valid_until.is_none_or(|until| now < until);
        started && not_finished
    }

    /// Создаёт anchor из DS-записи (например, из файла доверенных DS).
    ///
    /// # Errors
    ///
    /// [`TrustAnchorError::DigestLength`] при неверной длине digest.
    pub fn from_ds(
        ds: &DsData,
        valid_from: Option<u32>,
        valid_until: Option<u32>,
    ) -> Result<Self, TrustAnchorError> {
        Self::new(
            ds.key_tag(),
            ds.algorithm(),
            ds.digest_type(),
            ds.digest().to_vec(),
            valid_from,
            valid_until,
        )
    }

    /// Преобразует anchor в DS (если digest type поддерживается).
    ///
    /// # Errors
    ///
    /// [`TrustAnchorError::DigestType`] для неподдерживаемого digest type,
    /// [`TrustAnchorError::DigestLength`] при неверной длине.
    pub fn to_ds(&self) -> Result<DsData, TrustAnchorError> {
        let expected = match self.digest_type {
            1 => 20,
            2 => 32,
            4 => 48,
            other => return Err(TrustAnchorError::DigestType { digest_type: other }),
        };
        if self.digest.len() != expected {
            return Err(TrustAnchorError::DigestLength {
                digest_type: self.digest_type,
                actual: self.digest.len(),
            });
        }
        DsData::new(
            self.key_tag,
            self.algorithm,
            self.digest_type,
            self.digest.clone(),
        )
        .map_err(|_| TrustAnchorError::DigestLength {
            digest_type: self.digest_type,
            actual: self.digest.len(),
        })
    }
}

fn validate_digest(digest_type: u8, length: usize) -> Result<(), TrustAnchorError> {
    let expected = match digest_type {
        1 => 20,
        2 => 32,
        4 => 48,
        other => return Err(TrustAnchorError::DigestType { digest_type: other }),
    };
    if length == expected {
        Ok(())
    } else {
        Err(TrustAnchorError::DigestLength {
            digest_type,
            actual: length,
        })
    }
}

/// Встроенные root KSK IANA (актуальные).
///
/// # Panics
///
/// Не паникует.
#[must_use]
pub fn builtin_root_anchors() -> Vec<TrustAnchor> {
    vec![
        TrustAnchor {
            key_tag: 20326,
            algorithm: 8,
            digest_type: 2,
            digest: KSK_20326_DIGEST.to_vec(),
            valid_from: Some(KSK_20326_VALID_FROM),
            valid_until: None,
        },
        TrustAnchor {
            key_tag: 38696,
            algorithm: 8,
            digest_type: 2,
            digest: KSK_38696_DIGEST.to_vec(),
            valid_from: Some(KSK_38696_VALID_FROM),
            valid_until: None,
        },
    ]
}

/// Набор trust anchors.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustAnchorSet {
    anchors: Vec<TrustAnchor>,
}

impl TrustAnchorSet {
    /// Пустой набор.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Встроенный набор IANA.
    #[must_use]
    pub fn iana_root() -> Self {
        Self {
            anchors: builtin_root_anchors(),
        }
    }

    /// Набор из готовых anchors.
    #[must_use]
    pub fn from_anchors(anchors: Vec<TrustAnchor>) -> Self {
        Self { anchors }
    }

    /// Добавляет anchor.
    pub fn add(&mut self, anchor: TrustAnchor) {
        if !self.anchors.contains(&anchor) {
            self.anchors.push(anchor);
        }
    }

    /// Удаляет anchor по key tag и digest type; возвращает число удалённых.
    pub fn remove(&mut self, key_tag: u16, digest_type: u8) -> usize {
        let before = self.anchors.len();
        self.anchors
            .retain(|anchor| anchor.key_tag != key_tag || anchor.digest_type != digest_type);
        before - self.anchors.len()
    }

    /// Все anchors.
    #[must_use]
    pub fn anchors(&self) -> &[TrustAnchor] {
        &self.anchors
    }

    /// Количество anchors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.anchors.len()
    }

    /// Пуст ли набор.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }

    /// Активные anchors на момент `now`.
    pub fn active_at(&self, now: u32) -> impl Iterator<Item = &TrustAnchor> {
        self.anchors
            .iter()
            .filter(move |anchor| anchor.is_active_at(now))
    }

    /// Преобразует активные anchors в DS-набор.
    ///
    /// Anchors с digest type, запрещённым политикой (SHA-1 без opt-in),
    /// пропускаются; неподдерживаемые типы — ошибка.
    ///
    /// # Errors
    ///
    /// [`TrustAnchorError`] при некорректном digest type/длине.
    pub fn to_ds_set(&self, now: u32, policy: DsPolicy) -> Result<Vec<DsData>, TrustAnchorError> {
        let mut result = Vec::new();
        for anchor in self.active_at(now) {
            if anchor.digest_type == 1 && !policy.allow_legacy_sha1 {
                continue;
            }
            result.push(anchor.to_ds()?);
        }
        Ok(result)
    }

    /// Проверяет DNSKEY против активных anchors (DS-семантика).
    ///
    /// # Errors
    ///
    /// [`TrustAnchorError`] для некорректных anchors; ошибки DS-политики
    /// не возвращаются (неподходящий digest type просто не совпадает).
    pub fn matches_dnskey(
        &self,
        owner: &Name,
        dnskey: &DnskeyData,
        now: u32,
        policy: DsPolicy,
    ) -> Result<bool, TrustAnchorError> {
        for anchor in self.active_at(now) {
            if anchor.digest_type == 1 && !policy.allow_legacy_sha1 {
                continue;
            }
            let ds = anchor.to_ds()?;
            if matches!(ds_matches(owner, dnskey, &ds, policy), Ok(true)) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Разбирает IANA `root-anchors.xml`.
    ///
    /// Поддерживаются элементы `KeyDigest` с `KeyTag`, `Algorithm`,
    /// `DigestType`, `Digest` и атрибутами `validFrom`/`validUntil`.
    ///
    /// # Errors
    ///
    /// [`TrustAnchorError::Parse`] при структурных ошибках.
    pub fn from_xml(xml: &str) -> Result<Self, TrustAnchorError> {
        let mut anchors = Vec::new();
        let mut rest = xml;
        while let Some(start) = rest.find("<KeyDigest") {
            let after = rest.get(start..).unwrap_or("");
            let Some(end) = after.find("</KeyDigest>") else {
                return Err(TrustAnchorError::Parse {
                    reason: "unterminated KeyDigest element",
                });
            };
            let block = after.get(..end).unwrap_or("");
            let opening_end = block.find('>').ok_or(TrustAnchorError::Parse {
                reason: "KeyDigest without attributes end",
            })?;
            let opening = block.get(..opening_end).unwrap_or("");
            let body = block.get(opening_end + 1..).unwrap_or("");
            let key_tag = parse_u16_element(body, "KeyTag")?;
            let algorithm = parse_u8_element(body, "Algorithm")?;
            let digest_type = parse_u8_element(body, "DigestType")?;
            let digest_text = element_text(body, "Digest").ok_or(TrustAnchorError::Parse {
                reason: "missing Digest",
            })?;
            let digest = decode_hex(digest_text.trim()).ok_or(TrustAnchorError::Parse {
                reason: "invalid hex digest",
            })?;
            let valid_from = parse_optional_timestamp(attribute(opening, "validFrom"))?;
            let valid_until = parse_optional_timestamp(attribute(opening, "validUntil"))?;
            validate_digest(digest_type, digest.len())?;
            anchors.push(TrustAnchor {
                key_tag,
                algorithm,
                digest_type,
                digest,
                valid_from,
                valid_until,
            });
            rest = after.get(end + "</KeyDigest>".len()..).unwrap_or("");
        }
        if anchors.is_empty() {
            return Err(TrustAnchorError::Parse {
                reason: "no KeyDigest elements",
            });
        }
        Ok(Self { anchors })
    }

    /// Загружает anchors из файла (IANA XML).
    ///
    /// # Errors
    ///
    /// [`TrustAnchorError::Io`] и ошибки [`TrustAnchorSet::from_xml`].
    pub fn from_file(path: &Path) -> Result<Self, TrustAnchorError> {
        let text = std::fs::read_to_string(path)?;
        Self::from_xml(&text)
    }
}

fn element_text<'a>(body: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = body.find(&open)? + open.len();
    let tail = body.get(start..)?;
    let end = tail.find(&close)?;
    tail.get(..end)
}

fn parse_u16_element(body: &str, tag: &str) -> Result<u16, TrustAnchorError> {
    let text = element_text(body, tag).ok_or(TrustAnchorError::Parse {
        reason: "missing numeric element",
    })?;
    u16::from_str(text.trim()).map_err(|_| TrustAnchorError::Parse {
        reason: "invalid numeric element",
    })
}

fn parse_u8_element(body: &str, tag: &str) -> Result<u8, TrustAnchorError> {
    let text = element_text(body, tag).ok_or(TrustAnchorError::Parse {
        reason: "missing numeric element",
    })?;
    u8::from_str(text.trim()).map_err(|_| TrustAnchorError::Parse {
        reason: "invalid numeric element",
    })
}

fn attribute<'a>(opening: &'a str, name: &str) -> Option<&'a str> {
    let needle = format!("{name}=\"");
    let start = opening.find(&needle)? + needle.len();
    let tail = opening.get(start..)?;
    let end = tail.find('"')?;
    tail.get(..end)
}

fn parse_optional_timestamp(value: Option<&str>) -> Result<Option<u32>, TrustAnchorError> {
    match value {
        None => Ok(None),
        Some(text) => parse_timestamp(text).map(Some),
    }
}

/// Разбирает `YYYY-MM-DDTHH:MM:SS(Z|±HH:MM)` в секунды UNIX.
fn parse_timestamp(value: &str) -> Result<u32, TrustAnchorError> {
    let error = || TrustAnchorError::Timestamp {
        value: value.to_owned(),
    };
    let (date, rest) = value.split_once('T').ok_or_else(error)?;
    let mut date_parts = date.split('-');
    let year: i64 = date_parts
        .next()
        .ok_or_else(error)?
        .parse()
        .map_err(|_| error())?;
    let month: i64 = date_parts
        .next()
        .ok_or_else(error)?
        .parse()
        .map_err(|_| error())?;
    let day: i64 = date_parts
        .next()
        .ok_or_else(error)?
        .parse()
        .map_err(|_| error())?;
    if date_parts.next().is_some() {
        return Err(error());
    }

    let (time, offset_seconds) = if let Some(stripped) = rest.strip_suffix('Z') {
        (stripped, 0_i64)
    } else {
        let plus = rest.find('+');
        let minus = rest.find('-');
        let (time, sign, offset) = match (plus, minus) {
            (Some(position), _) => (
                rest.get(..position).unwrap_or(""),
                1_i64,
                rest.get(position + 1..).unwrap_or(""),
            ),
            (None, Some(position)) => (
                rest.get(..position).unwrap_or(""),
                -1_i64,
                rest.get(position + 1..).unwrap_or(""),
            ),
            (None, None) => return Err(error()),
        };
        let mut offset_parts = offset.split(':');
        let hours: i64 = offset_parts
            .next()
            .ok_or_else(error)?
            .parse()
            .map_err(|_| error())?;
        let minutes: i64 = offset_parts
            .next()
            .ok_or_else(error)?
            .parse()
            .map_err(|_| error())?;
        (time, sign * (hours * 3600 + minutes * 60))
    };

    let mut time_parts = time.split(':');
    let hour: i64 = time_parts
        .next()
        .ok_or_else(error)?
        .parse()
        .map_err(|_| error())?;
    let minute: i64 = time_parts
        .next()
        .ok_or_else(error)?
        .parse()
        .map_err(|_| error())?;
    let second: i64 = time_parts
        .next()
        .ok_or_else(error)?
        .parse()
        .map_err(|_| error())?;
    if time_parts.next().is_some()
        || !(0..24).contains(&hour)
        || !(0..60).contains(&minute)
        || !(0..61).contains(&second)
    {
        return Err(error());
    }
    let days = days_from_civil(year, month, day);
    let seconds = days
        .checked_mul(86_400)
        .and_then(|value| value.checked_add(hour * 3600 + minute * 60 + second - offset_seconds))
        .ok_or_else(error)?;
    u32::try_from(seconds).map_err(|_| error())
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let shifted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    let bytes = text.as_bytes();
    let mut index = 0_usize;
    while index < bytes.len() {
        let high = hex_value(*bytes.get(index)?)?;
        let low = hex_value(*bytes.get(index + 1)?)?;
        out.push((high << 4) | low);
        index += 2;
    }
    Some(out)
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_anchors_are_active() {
        let set = TrustAnchorSet::iana_root();
        // 2026-01-01
        let now = 1_767_225_600;
        let tags: Vec<u16> = set.active_at(now).map(TrustAnchor::key_tag).collect();
        assert!(tags.contains(&20326));
        assert!(tags.contains(&38696));
        let ds = set.to_ds_set(now, DsPolicy::strict()).unwrap();
        assert_eq!(ds.len(), 2);
        assert!(ds.iter().all(|ds| ds.digest_type() == 2));
    }

    #[test]
    fn buildin_anchor_timestamps() {
        let set = TrustAnchorSet::iana_root();
        // KSK-2024 ещё не опубликован в 2024-06-01.
        let early = 1_717_200_000;
        let tags: Vec<u16> = set.active_at(early).map(TrustAnchor::key_tag).collect();
        assert!(tags.contains(&20326));
        assert!(!tags.contains(&38696));
    }

    #[test]
    fn xml_roundtrip() {
        let xml = r#"
<TrustAnchor>
  <KeyDigest id="x" validFrom="2017-02-02T00:00:00+00:00">
    <KeyTag>20326</KeyTag>
    <Algorithm>8</Algorithm>
    <DigestType>2</DigestType>
    <Digest>E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D</Digest>
  </KeyDigest>
</TrustAnchor>"#;
        let set = TrustAnchorSet::from_xml(xml).unwrap();
        assert_eq!(set.len(), 1);
        let anchor = set.anchors().first().unwrap();
        assert_eq!(anchor.key_tag(), 20326);
        assert_eq!(anchor.valid_from(), Some(1_485_993_600));
        assert!(anchor.is_active_at(1_767_225_600));
    }

    #[test]
    fn loads_from_file() {
        let xml = r#"<TrustAnchor><KeyDigest validFrom="2017-02-02T00:00:00+00:00">
            <KeyTag>20326</KeyTag><Algorithm>8</Algorithm><DigestType>2</DigestType>
            <Digest>E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D</Digest>
            </KeyDigest></TrustAnchor>"#;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("root-anchors.xml");
        std::fs::write(&path, xml).unwrap();
        let set = TrustAnchorSet::from_file(&path).unwrap();
        assert_eq!(set.len(), 1);
        assert_eq!(set.anchors().first().unwrap().key_tag(), 20326);
    }

    #[test]
    fn timestamp_parse() {
        assert_eq!(parse_timestamp("1970-01-01T00:00:00Z").unwrap(), 0);
        assert_eq!(
            parse_timestamp("2017-02-02T00:00:00+00:00").unwrap(),
            1_485_993_600
        );
        assert!(parse_timestamp("not-a-date").is_err());
    }
}
