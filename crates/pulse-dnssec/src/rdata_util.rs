//! Кодирование DNSSEC-структур для подписи/валидации.
//!
//! - RRSIG RDATA без поля signature (RFC 4034 §3.1.8.1);
//! - каноническая wire-форма RRset с подменой TTL на Original TTL;
//! - key tag (RFC 4034 Appendix B);
//! - DNSKEY public key для RSA (RFC 3110), ECDSA (X||Y) и Ed25519.

use aws_lc_rs::digest::{SHA256, digest};
use pulse_dns::{DnskeyData, Name, Rclass, Rdata, RrsigData, Rtype, TypeBitmap};

use crate::error::VerifyError;

/// DNSKEY RDATA в wire-форме (RFC 4034 §2.1).
#[must_use]
pub fn dnskey_rdata(dnskey: &DnskeyData) -> Vec<u8> {
    let mut out = Vec::with_capacity(dnskey.public_key().len() + 4);
    out.extend_from_slice(&dnskey.flags().to_be_bytes());
    out.push(dnskey.protocol());
    out.push(dnskey.algorithm());
    out.extend_from_slice(dnskey.public_key());
    out
}

/// Key tag DNSKEY (RFC 4034 Appendix B).
///
/// Для algorithm 1 применяется историческое правило (старшие 16 из
/// младших 24 бит модуля); сам RSAMD5 в крейте запрещён, но key tag
/// вычисляется корректно для тестовых векторов.
#[must_use]
pub fn key_tag(dnskey: &DnskeyData) -> u16 {
    if dnskey.algorithm() == 1 {
        return rsamd5_key_tag(dnskey.public_key());
    }
    let rdata = dnskey_rdata(dnskey);
    let mut accumulator: u32 = 0;
    for (index, byte) in rdata.iter().enumerate() {
        if index % 2 == 0 {
            accumulator += u32::from(*byte) << 8;
        } else {
            accumulator += u32::from(*byte);
        }
    }
    accumulator += (accumulator >> 16) & 0xFFFF;
    u16::try_from(accumulator & 0xFFFF).unwrap_or(0)
}

fn rsamd5_key_tag(public_key: &[u8]) -> u16 {
    let Some((&first, _rest)) = public_key.split_first() else {
        return 0;
    };
    let (header, exponent_len) = if first == 0 {
        let Some(prefix) = public_key.get(1..3) else {
            return 0;
        };
        let Some(high) = prefix.first() else {
            return 0;
        };
        let Some(low) = prefix.get(1) else {
            return 0;
        };
        (3_usize, usize::from(u16::from_be_bytes([*high, *low])))
    } else {
        (1_usize, usize::from(first))
    };
    let Some(modulus) = public_key.get(header.saturating_add(exponent_len)..) else {
        return 0;
    };
    if modulus.len() < 3 {
        return 0;
    }
    let start = modulus.len() - 3;
    let Some(bytes) = modulus.get(start..start + 2) else {
        return 0;
    };
    u16::from_be_bytes([
        bytes.first().copied().unwrap_or(0),
        bytes.get(1).copied().unwrap_or(0),
    ])
}

/// RRSIG RDATA без поля signature (вход подписи, RFC 4034 §3.1.8.1).
#[must_use]
pub fn rrsig_signed_prefix(rrsig: &RrsigData) -> Vec<u8> {
    let mut out = Vec::with_capacity(18 + rrsig.signer_name().wire_len() + 2);
    out.extend_from_slice(&rrsig.type_covered().as_u16().to_be_bytes());
    out.push(rrsig.algorithm());
    out.push(rrsig.labels());
    out.extend_from_slice(&rrsig.original_ttl().to_be_bytes());
    out.extend_from_slice(&rrsig.signature_expiration().to_be_bytes());
    out.extend_from_slice(&rrsig.signature_inception().to_be_bytes());
    out.extend_from_slice(&rrsig.key_tag().to_be_bytes());
    out.extend_from_slice(rrsig.signer_name().as_wire());
    out
}

/// Каноническая wire-форма RRset с заданным TTL (RFC 4034 §6.2).
///
/// RR сортируются лексикографически по канонической RDATA. TTL берётся
/// из аргумента (для подписи/валидации — Original TTL), поэтому полный
/// `u32` допустим без clamp.
///
/// # Errors
///
/// [`VerifyError::Rrset`], если RDATA не валидна или не помещается в
/// `RDLENGTH`.
pub fn canonical_rrset_wire(
    owner: &Name,
    rr_type: Rtype,
    class: Rclass,
    ttl: u32,
    rdatas: &[Rdata],
) -> Result<Vec<u8>, VerifyError> {
    let mut encoded_rdatas = Vec::with_capacity(rdatas.len());
    for rdata in rdatas {
        encoded_rdatas.push(rdata.to_canonical_wire());
    }
    encoded_rdatas.sort_unstable();
    let mut out = Vec::new();
    for rdata in encoded_rdatas {
        let Ok(length) = u16::try_from(rdata.len()) else {
            return Err(VerifyError::Rrset(pulse_dns::RrsetError::RdataTooLong {
                len: rdata.len(),
            }));
        };
        out.extend_from_slice(owner.as_wire());
        out.extend_from_slice(&rr_type.as_u16().to_be_bytes());
        out.extend_from_slice(&class.as_u16().to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&rdata);
    }
    Ok(out)
}

/// Полный вход подписи: RRSIG RDATA без signature + канонический RRset.
///
/// # Errors
///
/// Ошибки кодирования RRset.
pub fn signed_data(
    owner: &Name,
    rr_type: Rtype,
    class: Rclass,
    rdatas: &[Rdata],
    rrsig: &RrsigData,
) -> Result<Vec<u8>, VerifyError> {
    let mut out = rrsig_signed_prefix(rrsig);
    out.extend_from_slice(&canonical_rrset_wire(
        owner,
        rr_type,
        class,
        rrsig.original_ttl(),
        rdatas,
    )?);
    Ok(out)
}

/// Число меток владельца для поля Labels, с учётом wildcard.
///
/// Для `*.example.com` возвращается 2 (звёздочка не считается).
#[must_use]
pub fn rrsig_labels(owner: &Name) -> usize {
    let count = owner.label_count();
    if owner.is_wildcard_owner() {
        count.saturating_sub(1)
    } else {
        count
    }
}

/// Имя, которое использовалось при подписи (RFC 4035 §5.3.2).
///
/// Если `labels` меньше числа меток владельца ровно на одну, имя
/// восстанавливается как wildcard: `*.` + правые метки. Разница больше
/// одной метки — ошибка.
///
/// # Errors
///
/// [`VerifyError::LabelsExceedOwner`] и
/// [`VerifyError::WildcardLabelsMismatch`].
pub fn signing_owner_name(owner: &Name, labels: u8) -> Result<Name, VerifyError> {
    let owner_labels = owner.label_count();
    let labels = usize::from(labels);
    if labels > owner_labels {
        return Err(VerifyError::LabelsExceedOwner {
            labels: u8::try_from(labels).unwrap_or(u8::MAX),
            owner_labels,
        });
    }
    if owner.is_wildcard_owner() {
        // RRSIG для wildcard-владельца, запрошенного напрямую: имя при
        // подписи — сам wildcard, а не результат развёртывания.
        return Ok(owner.clone());
    }
    if labels == owner_labels {
        return Ok(owner.clone());
    }
    let mut wire = Vec::new();
    wire.push(1_u8);
    wire.push(b'*');
    let skip = owner_labels.saturating_sub(labels);
    for label in owner.labels().skip(skip) {
        let Ok(length) = u8::try_from(label.len()) else {
            return Err(VerifyError::WildcardLabelsMismatch {
                labels: u8::try_from(labels).unwrap_or(u8::MAX),
                owner_labels,
            });
        };
        wire.push(length);
        wire.extend_from_slice(label);
    }
    wire.push(0);
    Name::from_wire(&wire).map_err(|_| VerifyError::WildcardLabelsMismatch {
        labels: u8::try_from(labels).unwrap_or(u8::MAX),
        owner_labels,
    })
}

/// Кодирует RSA public key для DNSKEY (RFC 3110).
#[must_use]
pub fn encode_rsa_dnskey_key(exponent: &[u8], modulus: &[u8]) -> Vec<u8> {
    let exponent = trim_leading_zeros(exponent);
    let mut out = Vec::with_capacity(exponent.len() + modulus.len() + 3);
    let short_length = u8::try_from(exponent.len()).unwrap_or(0);
    if short_length != 0 {
        out.push(short_length);
    }
    if out.is_empty() || exponent.len() > usize::from(u8::MAX) {
        out.clear();
        out.push(0);
        let Ok(length) = u16::try_from(exponent.len()) else {
            return Vec::new();
        };
        out.extend_from_slice(&length.to_be_bytes());
    }
    out.extend_from_slice(exponent);
    out.extend_from_slice(trim_leading_zeros(modulus));
    out
}

/// Разбирает RSA public key из DNSKEY (RFC 3110).
///
/// Возвращает `(exponent, modulus)`.
///
/// # Errors
///
/// [`VerifyError::BadPublicKey`] при некорректной структуре.
pub fn parse_rsa_dnskey_key(public_key: &[u8]) -> Result<(&[u8], &[u8]), VerifyError> {
    let (&first, rest) = public_key.split_first().ok_or(VerifyError::BadPublicKey {
        reason: "empty RSA public key",
    })?;
    let (exponent_length, rest) = if first == 0 {
        let prefix = rest.get(..2).ok_or(VerifyError::BadPublicKey {
            reason: "truncated exponent length",
        })?;
        let high = prefix.first().copied().ok_or(VerifyError::BadPublicKey {
            reason: "truncated exponent length",
        })?;
        let low = prefix.get(1).copied().ok_or(VerifyError::BadPublicKey {
            reason: "truncated exponent length",
        })?;
        let length = usize::from(u16::from_be_bytes([high, low]));
        (length, rest.get(2..).unwrap_or(&[]))
    } else {
        (usize::from(first), rest)
    };
    if exponent_length == 0 {
        return Err(VerifyError::BadPublicKey {
            reason: "empty RSA exponent",
        });
    }
    let (exponent, modulus) =
        rest.split_at_checked(exponent_length)
            .ok_or(VerifyError::BadPublicKey {
                reason: "truncated RSA exponent",
            })?;
    if modulus.is_empty() {
        return Err(VerifyError::BadPublicKey {
            reason: "empty RSA modulus",
        });
    }
    Ok((trim_leading_zeros(exponent), trim_leading_zeros(modulus)))
}

fn trim_leading_zeros(bytes: &[u8]) -> &[u8] {
    let mut index = 0_usize;
    while let Some(&byte) = bytes.get(index) {
        if byte != 0 {
            break;
        }
        index += 1;
    }
    bytes.get(index..).unwrap_or(&[])
}

/// Длина NSEC3 hash для algorithm 1 (SHA-1, RFC 5155 §5).
pub const NSEC3_SHA1_LEN: usize = 20;

/// NSEC3 hash (RFC 5155 §5): `IH(salt, name, iterations)` на SHA-1.
///
/// SHA-1 здесь предписан протоколом (hash algorithm 1), а не выбран для
/// подписи; число итераций ограничивается вызывающим кодом.
/// Возвращает 20 байт.
#[must_use]
pub fn nsec3_hash(name: &Name, salt: &[u8], iterations: u16) -> Vec<u8> {
    let mut value = [0_u8; NSEC3_SHA1_LEN];
    nsec3_hash_into(name.as_wire(), salt, iterations, &mut value).to_vec()
}

/// NSEC3 hash в caller-provided буфер, без промежуточных `Vec`.
///
/// Возвращает ровно [`NSEC3_SHA1_LEN`] байт — столько же, сколько
/// [`nsec3_hash`]; горячий путь ответа использует вариант без аллокаций.
///
/// # Panics
///
/// Не паникует: размер результата фиксирован типом буфера.
#[must_use]
pub fn nsec3_hash_into<'a>(
    name_wire: &[u8],
    salt: &[u8],
    iterations: u16,
    out: &'a mut [u8; NSEC3_SHA1_LEN],
) -> &'a [u8] {
    use aws_lc_rs::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY};

    let mut context = Context::new(&SHA1_FOR_LEGACY_USE_ONLY);
    context.update(name_wire);
    context.update(salt);
    out.copy_from_slice(context.finish().as_ref());
    for _ in 0..iterations {
        let mut context = Context::new(&SHA1_FOR_LEGACY_USE_ONLY);
        context.update(out);
        context.update(salt);
        out.copy_from_slice(context.finish().as_ref());
    }
    out
}

/// SHA-256 digest (для тестов/DS).
#[must_use]
pub fn sha256(data: &[u8]) -> Vec<u8> {
    digest(&SHA256, data).as_ref().to_vec()
}

/// NSEC-запись в доменном виде.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NsecEntry {
    /// Владелец NSEC.
    pub owner: Name,
    /// Next Domain Name.
    pub next: Name,
    /// Type bitmap.
    pub types: TypeBitmap,
}

impl NsecEntry {
    /// Извлекает NSEC из [`pulse_dns::Record`].
    ///
    /// # Errors
    ///
    /// [`crate::DenialError::NotNsec`], если запись не NSEC.
    pub fn from_record(record: &pulse_dns::Record) -> Result<Self, crate::DenialError> {
        match record.rdata() {
            Rdata::Nsec(nsec) => Ok(Self {
                owner: record.owner().clone(),
                next: nsec.next_domain().clone(),
                types: nsec.type_bitmap().clone(),
            }),
            _ => Err(crate::DenialError::NotNsec),
        }
    }

    /// Содержит ли интервал имя (строго внутри, RFC 4034 §4.1.2).
    #[must_use]
    pub fn covers(&self, name: &Name) -> bool {
        use std::cmp::Ordering;

        if name == &self.owner {
            return false;
        }
        match self.owner.cmp_canonical(&self.next) {
            Ordering::Less => {
                self.owner.cmp_canonical(name) == Ordering::Less
                    && name.cmp_canonical(&self.next) == Ordering::Less
            }
            Ordering::Greater | Ordering::Equal => {
                self.owner.cmp_canonical(name) == Ordering::Less
                    || name.cmp_canonical(&self.next) == Ordering::Less
            }
        }
    }

    /// Совпадает ли владелец с именем.
    #[must_use]
    pub fn matches(&self, name: &Name) -> bool {
        &self.owner == name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_tag_rfc4034_appendix_b() {
        let public_key = base64_decode(
            "AQOeiiR0GOMYkDshWoSKz9XzfwJr1AYtsmx3TGkJaNXVbfi/2pHm822aJ5iI9BMzNXxeYCmZ\
             DRD99WYwYqUSdjMmmAphXdvxegXd/M5+X7OrzKBaMbCVdFLUUh6DhweJBjEVv5f2wwjM9Xzc\
             nOf+EPbtG9DMBmADjFDc2w/rljwvFw==",
        );
        let dnskey = DnskeyData::new(256, 3, 5, public_key).unwrap();
        assert_eq!(key_tag(&dnskey), 60485);
    }
    #[test]
    fn rsa_dnskey_roundtrip() {
        let exponent = [0x01, 0x00, 0x01];
        let modulus = [0x00, 0xC1, 0x02, 0x03];
        let encoded = encode_rsa_dnskey_key(&exponent, &modulus);
        let (parsed_exponent, parsed_modulus) = parse_rsa_dnskey_key(&encoded).unwrap();
        assert_eq!(parsed_exponent, exponent);
        assert_eq!(parsed_modulus, [0xC1, 0x02, 0x03]);
    }

    #[test]
    fn long_exponent_uses_three_byte_prefix() {
        let exponent = vec![0x01; 300];
        let encoded = encode_rsa_dnskey_key(&exponent, &[0x80]);
        assert_eq!(encoded.first(), Some(&0));
        assert_eq!(encoded.get(1..3), Some([0x01, 0x2C].as_slice()));
        let (parsed, _) = parse_rsa_dnskey_key(&encoded).unwrap();
        assert_eq!(parsed.len(), 300);
    }

    #[test]
    fn wildcard_owner_reconstruction() {
        let owner = Name::parse("a.b.example.com").unwrap();
        let reconstructed = signing_owner_name(&owner, 2).unwrap();
        assert_eq!(reconstructed, Name::parse("*.example.com").unwrap());
        assert_eq!(
            signing_owner_name(&owner, 0).unwrap(),
            Name::parse("*").unwrap()
        );
        assert!(matches!(
            signing_owner_name(&owner, 9),
            Err(VerifyError::LabelsExceedOwner { .. })
        ));
    }

    fn base64_decode(input: &str) -> Vec<u8> {
        use base64::Engine as _;
        let cleaned: String = input.chars().filter(|c| !c.is_whitespace()).collect();
        base64::engine::general_purpose::STANDARD
            .decode(cleaned)
            .unwrap()
    }
}
