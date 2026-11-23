//! Разбор path и query-строки.

use crate::codec::percent_decode;

/// Декодирует path в сегменты (без ведущего `/`).
pub(crate) fn decode_path_segments(path: &str) -> Option<Vec<String>> {
    let rest = path.strip_prefix('/')?;
    if rest.is_empty() {
        return Some(Vec::new());
    }
    let mut segments = Vec::new();
    for raw in rest.split('/') {
        let decoded = percent_decode(raw, false)?;
        if decoded.contains('/') || decoded.contains('\u{0}') {
            return None;
        }
        segments.push(decoded);
    }
    Some(segments)
}

/// Разобранная query-строка.
#[derive(Debug, Clone, Default)]
pub(crate) struct Query {
    pairs: Vec<(String, String)>,
}

impl Query {
    /// Разбирает query.
    pub(crate) fn parse(query: &str) -> Option<Self> {
        if query.is_empty() {
            return Some(Self::default());
        }
        if query.len() > 8192 {
            return None;
        }
        let mut pairs = Vec::new();
        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let key = percent_decode(key, true)?;
            let value = percent_decode(value, true)?;
            pairs.push((key, value));
        }
        Some(Self { pairs })
    }

    /// Первое значение параметра.
    pub(crate) fn get(&self, name: &str) -> Option<&str> {
        self.pairs
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// Все значения параметра.
    pub(crate) fn get_all(&self, name: &str) -> Vec<&str> {
        self.pairs
            .iter()
            .filter(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
            .collect()
    }
}

/// Разбирает `limit` (1..=500, по умолчанию 50).
pub(crate) fn parse_limit(query: &Query) -> Result<u32, &'static str> {
    match query.get("limit") {
        None => Ok(50),
        Some(value) => {
            let limit = value.parse::<u32>().map_err(|_| "invalid limit")?;
            if (1..=500).contains(&limit) {
                Ok(limit)
            } else {
                Err("limit must be in 1..=500")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_segments() {
        assert_eq!(
            decode_path_segments("/api/v1/zones/example.com."),
            Some(vec![
                "api".to_owned(),
                "v1".to_owned(),
                "zones".to_owned(),
                "example.com.".to_owned()
            ])
        );
        assert_eq!(
            decode_path_segments("/zones/example%2Ecom."),
            Some(vec!["zones".to_owned(), "example.com.".to_owned()])
        );
        assert_eq!(decode_path_segments("/zones/%2F"), None);
        assert_eq!(decode_path_segments("/zones/%ZZ"), None);
        assert_eq!(decode_path_segments("relative"), None);
    }

    #[test]
    fn query_parsing() {
        let query = Query::parse("limit=10&cursor=abc&limit=20&x=a+b").unwrap();
        assert_eq!(query.get("limit"), Some("10"));
        assert_eq!(query.get_all("limit"), vec!["10", "20"]);
        assert_eq!(query.get("x"), Some("a b"));
        assert!(Query::parse("%ZZ").is_none());
    }

    #[test]
    fn limit_validation() {
        assert_eq!(parse_limit(&Query::default()), Ok(50));
        assert_eq!(parse_limit(&Query::parse("limit=1").unwrap()), Ok(1));
        assert_eq!(parse_limit(&Query::parse("limit=500").unwrap()), Ok(500));
        assert!(parse_limit(&Query::parse("limit=0").unwrap()).is_err());
        assert!(parse_limit(&Query::parse("limit=501").unwrap()).is_err());
        assert!(parse_limit(&Query::parse("limit=x").unwrap()).is_err());
    }
}
