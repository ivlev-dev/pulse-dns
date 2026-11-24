//! Загрузка trust anchors из текстового файла DS-записей.
//!
//! Формат строки — обычная presentation-форма DS:
//! `example. 300 IN DS 12345 15 2 <hex-digest>`, где TTL и класс
//! необязательны. Строки с `;` или `#` считаются комментариями. Пустой файл
//! допустим только когда DNSSEC-валидация выключена.

use std::path::Path;

use pulse_dns::{DsData, Name};
use pulse_resolver::TrustAnchorConfig;

use crate::error::ConfigError;

/// Читает DS-файл и преобразует его в anchors резолвера.
pub(crate) fn load(path: &Path) -> Result<Vec<TrustAnchorConfig>, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    parse(&text, path)
}

fn parse(text: &str, path: &Path) -> Result<Vec<TrustAnchorConfig>, ConfigError> {
    let mut anchors = Vec::new();
    for (index, raw_line) in text.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.split([';', '#']).next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let anchor = parse_line(line).map_err(|reason| {
            ConfigError::invalid(format!(
                "trust_anchor {}:{line_number}: {reason}",
                path.display()
            ))
        })?;
        anchors.push(anchor);
    }
    Ok(anchors)
}

fn parse_line(line: &str) -> Result<TrustAnchorConfig, String> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let ds_index = tokens
        .iter()
        .position(|token| token.eq_ignore_ascii_case("DS"))
        .ok_or_else(|| "missing DS record".to_owned())?;
    let owner = tokens
        .first()
        .ok_or_else(|| "missing owner name".to_owned())?;
    let zone = Name::parse(owner).map_err(|error| format!("invalid owner {owner:?}: {error}"))?;
    let fields = tokens.get(ds_index + 1..).unwrap_or(&[]);
    let [key_tag, algorithm, digest_type, digest] = fields else {
        return Err("DS record expects: <key-tag> <algorithm> <digest-type> <hex>".to_owned());
    };
    let key_tag: u16 = key_tag
        .parse()
        .map_err(|error| format!("invalid key tag {key_tag:?}: {error}"))?;
    let algorithm: u8 = algorithm
        .parse()
        .map_err(|error| format!("invalid algorithm {algorithm:?}: {error}"))?;
    let digest_type: u8 = digest_type
        .parse()
        .map_err(|error| format!("invalid digest type {digest_type:?}: {error}"))?;
    let digest = decode_hex(digest)
        .ok_or_else(|| format!("digest {digest:?} is not an even-length hex string"))?;
    let ds = DsData::new(key_tag, algorithm, digest_type, digest)
        .map_err(|error| format!("invalid DS data: {error}"))?;
    Ok(TrustAnchorConfig::new(zone, ds))
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if text.is_empty() || !text.len().is_multiple_of(2) {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut index = 0;
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
    use std::path::PathBuf;

    use super::*;

    const DIGEST: &str = "e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d";

    #[test]
    fn parses_default_and_root_anchor_lines() {
        let text = format!(
            "; root anchor\n. 172800 IN DS 20326 8 2 {DIGEST}\n\
             example.test. DS 12345 15 2 {DIGEST}\n"
        );
        let anchors = parse(&text, &PathBuf::from("<test>")).unwrap();
        assert_eq!(anchors.len(), 2);
        assert_eq!(anchors[0].zone, Name::root());
        assert_eq!(anchors[0].ds.key_tag(), 20326);
        assert_eq!(anchors[1].zone, Name::parse("example.test").unwrap());
        assert_eq!(anchors[1].ds.algorithm(), 15);
    }

    #[test]
    fn rejects_malformed_lines() {
        assert!(parse("example.test. DS 1 8\n", &PathBuf::from("x")).is_err());
        assert!(parse("example.test. 1 8 2 zz\n", &PathBuf::from("x")).is_err());
        assert!(parse("example.test. DS 1 8 2 abc\n", &PathBuf::from("x")).is_err());
    }
}
