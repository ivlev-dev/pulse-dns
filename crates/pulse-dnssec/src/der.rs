//! Минимальный DER-кодек для PKCS#8/PKCS#1/SEC1 ключевых структур.
//!
//! Это не криптография, а разбор ASN.1-оболочки: сами ключи проверяет
//! `aws-lc-rs`. Поддерживаются только нужные теги и definite-length.
//! Любая структурная ошибка возвращается как [`KeyError::Der`], паника
//! невозможна.

use crate::error::KeyError;

const TAG_INTEGER: u8 = 0x02;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_OID: u8 = 0x06;
const TAG_SEQUENCE: u8 = 0x30;

/// OID `id-ecPublicKey` (1.2.840.10045.2.1).
pub const OID_EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
/// OID `prime256v1` (1.2.840.10045.3.1.7).
pub const OID_PRIME256V1: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
/// OID `id-Ed25519` (1.3.101.112).
pub const OID_ED25519: &[u8] = &[0x2B, 0x65, 0x70];

fn der_error(reason: &'static str) -> KeyError {
    KeyError::Der { reason }
}

/// Курсор по DER-структуре с обязательным исчерпанием.
pub struct DerReader<'a> {
    input: &'a [u8],
}

impl<'a> DerReader<'a> {
    /// Создаёт читатель.
    #[must_use]
    pub const fn new(input: &'a [u8]) -> Self {
        Self { input }
    }

    /// Читает TLV с ожидаемым тегом и возвращает содержимое.
    ///
    /// # Errors
    ///
    /// [`KeyError::Der`] при неверном теге/длине/усечении.
    pub fn read(&mut self, expected_tag: u8) -> Result<&'a [u8], KeyError> {
        let (tag, value) = self.take()?;
        if tag != expected_tag {
            return Err(der_error("unexpected tag"));
        }
        Ok(value)
    }

    /// Читает произвольный TLV и возвращает тег и содержимое.
    ///
    /// # Errors
    ///
    /// [`KeyError::Der`] при структурной ошибке.
    pub fn take(&mut self) -> Result<(u8, &'a [u8]), KeyError> {
        let (tag, rest) = self
            .input
            .split_first()
            .ok_or_else(|| der_error("truncated tag"))?;
        let (&first_length, rest) = rest
            .split_first()
            .ok_or_else(|| der_error("truncated length"))?;
        let (length, rest) = if first_length & 0x80 == 0 {
            (usize::from(first_length), rest)
        } else {
            let count = usize::from(first_length & 0x7F);
            if count == 0 || count > 3 {
                return Err(der_error("unsupported length encoding"));
            }
            let (length_bytes, rest) = rest
                .split_at_checked(count)
                .ok_or_else(|| der_error("truncated length bytes"))?;
            let mut length = 0_usize;
            for byte in length_bytes {
                length = (length << 8) | usize::from(*byte);
            }
            if length < 0x80 {
                return Err(der_error("non-minimal length encoding"));
            }
            (length, rest)
        };
        let (value, rest) = rest
            .split_at_checked(length)
            .ok_or_else(|| der_error("truncated value"))?;
        self.input = rest;
        Ok((*tag, value))
    }

    /// Читает SEQUENCE и возвращает вложенный читатель.
    ///
    /// # Errors
    ///
    /// [`KeyError::Der`] при структурной ошибке.
    pub fn sequence(&mut self) -> Result<DerReader<'a>, KeyError> {
        Ok(DerReader::new(self.read(TAG_SEQUENCE)?))
    }

    /// Читает INTEGER без ведущих нулей (неотрицательное число).
    ///
    /// # Errors
    ///
    /// [`KeyError::Der`] при пустом или отрицательном значении.
    pub fn integer(&mut self) -> Result<&'a [u8], KeyError> {
        let value = self.read(TAG_INTEGER)?;
        if value.is_empty() {
            return Err(der_error("empty integer"));
        }
        if value.first().is_some_and(|byte| byte & 0x80 != 0) {
            return Err(der_error("negative integer"));
        }
        let trimmed = trim_leading_zeros(value);
        if trimmed.is_empty() {
            return Err(der_error("zero integer"));
        }
        Ok(trimmed)
    }

    /// Читает INTEGER и проверяет точное значение (version-поля).
    ///
    /// # Errors
    ///
    /// [`KeyError::Der`] при другом значении.
    pub fn expect_integer(&mut self, expected: u8) -> Result<(), KeyError> {
        if expected == 0 {
            if self.read(TAG_INTEGER)? != [0] {
                return Err(der_error("unexpected integer value"));
            }
            return Ok(());
        }
        let value = self.integer()?;
        if value != [expected] {
            return Err(der_error("unexpected integer value"));
        }
        Ok(())
    }

    /// Читает OCTET STRING.
    ///
    /// # Errors
    ///
    /// [`KeyError::Der`] при структурной ошибке.
    pub fn octet_string(&mut self) -> Result<&'a [u8], KeyError> {
        self.read(TAG_OCTET_STRING)
    }

    /// Читает BIT STRING и требует нулевой unused-bits октет.
    ///
    /// # Errors
    ///
    /// [`KeyError::Der`] при ненулевом unused-bits.
    pub fn bit_string(&mut self) -> Result<&'a [u8], KeyError> {
        let value = self.read(TAG_BIT_STRING)?;
        let (unused, payload) = value
            .split_first()
            .ok_or_else(|| der_error("empty bit string"))?;
        if *unused != 0 {
            return Err(der_error("unsupported bit string padding"));
        }
        Ok(payload)
    }

    /// Читает OID и сравнивает с ожидаемым.
    ///
    /// # Errors
    ///
    /// [`KeyError::Der`] при несовпадении.
    pub fn expect_oid(&mut self, expected: &[u8]) -> Result<(), KeyError> {
        if self.read(TAG_OID)? != expected {
            return Err(der_error("unexpected OID"));
        }
        Ok(())
    }

    /// Требует исчерпания входа.
    ///
    /// # Errors
    ///
    /// [`KeyError::Der`], если остались байты.
    pub fn finish(self) -> Result<(), KeyError> {
        if self.input.is_empty() {
            Ok(())
        } else {
            Err(der_error("trailing bytes"))
        }
    }
}

/// Убирает ведущие нули (DER INTEGER).
#[must_use]
pub fn trim_leading_zeros(bytes: &[u8]) -> &[u8] {
    let mut index = 0_usize;
    while let Some(&byte) = bytes.get(index) {
        if byte != 0 {
            break;
        }
        index += 1;
    }
    bytes.get(index..).unwrap_or(&[])
}

/// Кодирует TLV.
#[must_use]
pub fn encode_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len() + 6);
    out.push(tag);
    encode_length(value.len(), &mut out);
    out.extend_from_slice(value);
    out
}

fn encode_length(length: usize, out: &mut Vec<u8>) {
    if length < 0x80 {
        out.push(u8::try_from(length).unwrap_or(0x7F));
        return;
    }
    let bytes = length.to_be_bytes();
    let trimmed = trim_leading_zeros(&bytes);
    out.push(0x80 | u8::try_from(trimmed.len()).unwrap_or(0));
    out.extend_from_slice(trimmed);
}

/// Кодирует DER INTEGER из неотрицательного big-endian числа.
#[must_use]
pub fn encode_integer(bytes: &[u8]) -> Vec<u8> {
    let trimmed = trim_leading_zeros(bytes);
    let mut value = Vec::with_capacity(trimmed.len() + 1);
    if trimmed.is_empty() {
        value.push(0);
    } else {
        if trimmed.first().is_some_and(|byte| byte & 0x80 != 0) {
            value.push(0);
        }
        value.extend_from_slice(trimmed);
    }
    encode_tlv(TAG_INTEGER, &value)
}

/// Кодирует OCTET STRING.
#[must_use]
pub fn encode_octet_string(bytes: &[u8]) -> Vec<u8> {
    encode_tlv(TAG_OCTET_STRING, bytes)
}

/// Кодирует SEQUENCE из уже закодированных элементов.
#[must_use]
pub fn encode_sequence(elements: &[Vec<u8>]) -> Vec<u8> {
    let total: usize = elements.iter().map(Vec::len).sum();
    let mut value = Vec::with_capacity(total);
    for element in elements {
        value.extend_from_slice(element);
    }
    encode_tlv(TAG_SEQUENCE, &value)
}

/// Кодирует PKCS#1 `RSAPrivateKey` из компонентов.
///
/// `version = 0`, далее n, e, d, p, q, dP, dQ, qInv — все big-endian без
/// ведущих нулей.
#[must_use]
pub fn encode_rsa_private_key(components: &[&[u8]; 8]) -> Vec<u8> {
    let mut elements = Vec::with_capacity(9);
    elements.push(encode_integer(&[0]));
    for component in components {
        elements.push(encode_integer(component));
    }
    encode_sequence(&elements)
}

/// Кодирует PKCS#1 `RSAPublicKey` (n, e).
#[must_use]
pub fn encode_rsa_public_key(modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
    encode_sequence(&[encode_integer(modulus), encode_integer(exponent)])
}

/// Разбирает PKCS#1 `RSAPublicKey` (n, e).
///
/// # Errors
///
/// [`KeyError::Der`] при структурной ошибке.
pub fn parse_rsa_public_key(der: &[u8]) -> Result<(&[u8], &[u8]), KeyError> {
    let mut outer = DerReader::new(der);
    let mut sequence = outer.sequence()?;
    let modulus = sequence.integer()?;
    let exponent = sequence.integer()?;
    sequence.finish()?;
    outer.finish()?;
    Ok((modulus, exponent))
}

/// Разбирает PKCS#1 `RSAPrivateKey` и возвращает девять INTEGER-полей
/// (version, n, e, d, p, q, dP, dQ, qInv).
///
/// # Errors
///
/// [`KeyError::Der`] при структурной ошибке; version обязана быть 0.
pub fn parse_rsa_private_key(der: &[u8]) -> Result<[&[u8]; 8], KeyError> {
    let mut outer = DerReader::new(der);
    let mut sequence = outer.sequence()?;
    sequence.expect_integer(0)?;
    let mut fields: [&[u8]; 8] = [&[]; 8];
    for slot in &mut fields {
        *slot = sequence.integer()?;
    }
    sequence.finish()?;
    outer.finish()?;
    Ok(fields)
}

/// Разбирает PKCS#8 `PrivateKeyInfo` и возвращает inner OCTET STRING.
///
/// # Errors
///
/// [`KeyError::Der`] при структурной ошибке.
pub fn parse_pkcs8_private_key_info(der: &[u8]) -> Result<&[u8], KeyError> {
    let mut outer = DerReader::new(der);
    let mut sequence = outer.sequence()?;
    sequence.expect_integer(0)?;
    let mut algorithm = sequence.sequence()?;
    let _oid = algorithm.read(TAG_OID)?;
    // Параметры алгоритма (OID/SEQUENCE/NULL) могут присутствовать; просто
    // дочитываем остаток algorithm identifier без интерпретации.
    let mut rest = algorithm;
    while !rest.input.is_empty() {
        rest.skip_tlv()?;
    }
    let inner = sequence.octet_string()?;
    let mut trailing = sequence;
    while !trailing.input.is_empty() {
        trailing.skip_tlv()?;
    }
    outer.finish()?;
    Ok(inner)
}

impl DerReader<'_> {
    /// Пропускает один TLV без интерпретации.
    ///
    /// # Errors
    ///
    /// [`KeyError::Der`] при структурной ошибке.
    pub fn skip_tlv(&mut self) -> Result<(), KeyError> {
        self.take().map(|_| ())
    }
}

/// Кодирует SEC1 `ECPrivateKey` (RFC 5915) для P-256.
///
/// Публичный ключ не включается: `aws-lc-rs` выводит его из приватного
/// скаляра при импорте.
#[must_use]
pub fn encode_sec1_p256_private_key(scalar: &[u8]) -> Vec<u8> {
    let mut elements = Vec::with_capacity(3);
    elements.push(encode_integer(&[1]));
    elements.push(encode_octet_string(scalar));
    // [0] EXPLICIT ECParameters { namedCurve prime256v1 }
    let mut parameters = Vec::new();
    parameters.push(0xA0);
    let oid = encode_tlv(TAG_OID, OID_PRIME256V1);
    encode_length(oid.len(), &mut parameters);
    parameters.extend_from_slice(&oid);
    elements.push(parameters);
    encode_sequence(&elements)
}

/// Кодирует PKCS#8 v1 для Ed25519 из 32-байтного seed.
#[must_use]
pub fn encode_ed25519_pkcs8(seed: &[u8]) -> Vec<u8> {
    let algorithm = encode_sequence(&[encode_tlv(TAG_OID, OID_ED25519)]);
    let private_key = encode_octet_string(&encode_octet_string(seed));
    encode_sequence(&[encode_integer(&[0]), algorithm, private_key])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_roundtrip() {
        let encoded = encode_integer(&[0x00, 0x80, 0x01]);
        let mut reader = DerReader::new(&encoded);
        assert_eq!(reader.integer().unwrap(), [0x80, 0x01]);
        reader.finish().unwrap();
    }

    #[test]
    fn rsa_public_key_roundtrip() {
        let der = encode_rsa_public_key(&[0x00, 0xC1, 0x02], &[0x01, 0x00, 0x01]);
        let (modulus, exponent) = parse_rsa_public_key(&der).unwrap();
        assert_eq!(modulus, [0xC1, 0x02]);
        assert_eq!(exponent, [0x01, 0x00, 0x01]);
    }

    #[test]
    fn rsa_private_key_roundtrip() {
        let der = encode_rsa_private_key(&[&[1], &[3], &[5], &[7], &[9], &[11], &[13], &[15]]);
        let parsed = parse_rsa_private_key(&der).unwrap();
        assert_eq!(parsed[0], [1]);
        assert_eq!(parsed[7], [15]);
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut der = encode_integer(&[1]);
        der.push(0);
        let mut reader = DerReader::new(&der);
        assert!(reader.integer().is_ok());
        assert!(reader.finish().is_err());
    }

    #[test]
    fn rejects_indefinite_length() {
        let mut reader = DerReader::new(&[TAG_INTEGER, 0x80]);
        assert!(reader.integer().is_err());
    }
}
