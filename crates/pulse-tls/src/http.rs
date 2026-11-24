//! Разбор HTTP/1.1 и сериализация ответов для DoH (RFC 8484).
//!
//! HTTP/2 сознательно не поддерживается: ALPN DoH-сервера — только
//! `http/1.1`.

use std::fmt::Write as _;

use pulse_dns::Message;
use pulse_dns::wire::DecodeLimits;

const MAX_HEADERS: usize = 64;

/// Метод запроса.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Method {
    Get,
    Post,
    Other,
}

/// Ошибка разбора заголовков запроса.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParseError {
    /// Синтаксическая ошибка.
    Malformed,
    /// HTTP/2 preface или версия выше 1.1.
    UnsupportedVersion,
}

/// Заголовки запроса в исходном виде.
#[derive(Debug, Default)]
pub(crate) struct Headers {
    entries: Vec<(String, Vec<u8>)>,
}

impl Headers {
    fn from_httparse(headers: &[httparse::Header<'_>]) -> Self {
        let entries = headers
            .iter()
            .map(|header| (header.name.to_owned(), header.value.to_vec()))
            .collect();
        Self { entries }
    }

    fn values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a [u8]> + 'a {
        self.entries
            .iter()
            .filter(move |(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_slice())
    }

    pub(crate) fn first<'a>(&'a self, name: &'a str) -> Option<&'a [u8]> {
        self.values(name).next()
    }

    /// Content-Length; `Err(())` при конфликтующих или некорректных значениях.
    pub(crate) fn content_length(&self) -> Result<Option<usize>, ()> {
        let mut parsed: Option<usize> = None;
        for value in self.values("content-length") {
            let text = std::str::from_utf8(value).map_err(|_| ())?;
            let length = text.trim().parse::<u64>().map_err(|_| ())?;
            let length = usize::try_from(length).map_err(|_| ())?;
            match parsed {
                Some(existing) if existing != length => return Err(()),
                _ => parsed = Some(length),
            }
        }
        Ok(parsed)
    }

    pub(crate) fn has_transfer_encoding(&self) -> bool {
        self.values("transfer-encoding").any(|value| {
            std::str::from_utf8(value)
                .map_or(true, |text| !text.trim().eq_ignore_ascii_case("identity"))
        })
    }

    pub(crate) fn content_type_is(&self, expected: &str) -> bool {
        self.first("content-type").is_some_and(|value| {
            std::str::from_utf8(value).is_ok_and(|text| {
                text.split(';')
                    .next()
                    .map(str::trim)
                    .is_some_and(|media| media.eq_ignore_ascii_case(expected))
            })
        })
    }

    pub(crate) fn keep_alive(&self, version: u8) -> bool {
        let close = self
            .values("connection")
            .any(|value| contains_token(value, "close"));
        if close {
            return false;
        }
        if version == 0 {
            return self
                .values("connection")
                .any(|value| contains_token(value, "keep-alive"));
        }
        true
    }
}

fn contains_token(value: &[u8], token: &str) -> bool {
    std::str::from_utf8(value).is_ok_and(|text| {
        text.split(',')
            .any(|part| part.trim().eq_ignore_ascii_case(token))
    })
}

/// Разобранная строка запроса и заголовки.
#[derive(Debug)]
pub(crate) struct RequestHead {
    pub(crate) method: Method,
    pub(crate) target: String,
    pub(crate) version: u8,
    pub(crate) headers: Headers,
}

impl RequestHead {
    pub(crate) fn into_parts(self) -> (Method, String, u8, Headers) {
        (self.method, self.target, self.version, self.headers)
    }
}

/// Разбирает заголовок запроса (включая завершающие `\r\n\r\n`).
pub(crate) fn parse_head(buffer: &[u8]) -> Result<RequestHead, ParseError> {
    if buffer.starts_with(b"PRI * HTTP/2.0\r\n") {
        return Err(ParseError::UnsupportedVersion);
    }
    let mut header_slots = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut request = httparse::Request::new(&mut header_slots);
    match request.parse(buffer) {
        Ok(httparse::Status::Complete(_)) => {}
        Ok(httparse::Status::Partial) | Err(_) => return Err(ParseError::Malformed),
    }
    let version = request.version.ok_or(ParseError::Malformed)?;
    if version > 1 {
        return Err(ParseError::UnsupportedVersion);
    }
    let method = match request.method.ok_or(ParseError::Malformed)? {
        "GET" => Method::Get,
        "POST" => Method::Post,
        _ => Method::Other,
    };
    let target = request.path.ok_or(ParseError::Malformed)?.to_owned();
    let headers = Headers::from_httparse(request.headers);
    Ok(RequestHead {
        method,
        target,
        version,
        headers,
    })
}

/// Ищет `name` в query-string и percent-декодирует значение.
pub(crate) fn query_param(target: &str, name: &str) -> Option<Vec<u8>> {
    let query = target.split_once('?')?.1;
    for pair in query.split('&') {
        let (key, value) = match pair.split_once('=') {
            Some((key, value)) => (key, value),
            None => (pair, ""),
        };
        if key == name {
            return percent_decode(value);
        }
    }
    None
}

fn percent_decode(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = *bytes.get(index)?;
        if byte == b'%' {
            let high = hex_value(*bytes.get(index + 1)?)?;
            let low = hex_value(*bytes.get(index + 2)?)?;
            decoded.push(high << 4 | low);
            index += 3;
        } else if byte == b'+' {
            decoded.push(b' ');
            index += 1;
        } else {
            decoded.push(byte);
            index += 1;
        }
    }
    Some(decoded)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => byte.checked_sub(b'0'),
        b'a'..=b'f' => byte.checked_sub(b'a').map(|value| value + 10),
        b'A'..=b'F' => byte.checked_sub(b'A').map(|value| value + 10),
        _ => None,
    }
}

/// Позиция конца заголовка (`\r\n\r\n`).
pub(crate) fn find_head_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

/// HTTP-ответ.
#[derive(Debug)]
pub(crate) struct HttpResponse {
    pub(crate) status: u16,
    pub(crate) content_type: &'static str,
    pub(crate) body: Vec<u8>,
    pub(crate) cache_max_age: Option<u32>,
    pub(crate) close: bool,
    pub(crate) allow: Option<&'static str>,
}

const DNS_MEDIA_TYPE: &str = "application/dns-message";
const TEXT_MEDIA_TYPE: &str = "text/plain; charset=utf-8";

impl HttpResponse {
    pub(crate) fn dns(body: Vec<u8>, cache_max_age: Option<u32>, close: bool) -> Self {
        Self {
            status: 200,
            content_type: DNS_MEDIA_TYPE,
            body,
            cache_max_age,
            close,
            allow: None,
        }
    }

    pub(crate) fn text(status: u16, body: impl Into<Vec<u8>>, close: bool) -> Self {
        Self {
            status,
            content_type: TEXT_MEDIA_TYPE,
            body: body.into(),
            cache_max_age: None,
            close,
            allow: None,
        }
    }

    pub(crate) fn error(status: u16, message: &str, close: bool) -> Self {
        Self::text(status, format!("{message}\n"), close)
    }

    pub(crate) fn method_not_allowed(close: bool) -> Self {
        let mut response = Self::error(405, "method not allowed", close);
        response.allow = Some("GET, POST");
        response
    }

    /// Сериализует ответ в HTTP/1.1.
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let reason = reason(self.status);
        let mut head = format!("HTTP/1.1 {} {}\r\n", self.status, reason);
        let _ = write!(head, "content-length: {}\r\n", self.body.len());
        let _ = write!(head, "content-type: {}\r\n", self.content_type);
        if let Some(max_age) = self.cache_max_age {
            let _ = write!(head, "cache-control: max-age={max_age}\r\n");
        }
        if let Some(allow) = self.allow {
            let _ = write!(head, "allow: {allow}\r\n");
        }
        head.push_str("server: pulse-tls\r\n");
        head.push_str(if self.close {
            "connection: close\r\n\r\n"
        } else {
            "connection: keep-alive\r\n\r\n"
        });
        let mut bytes = head.into_bytes();
        bytes.extend_from_slice(&self.body);
        bytes
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        505 => "HTTP Version Not Supported",
        _ => "Error",
    }
}

/// Минимальный TTL в ответе для `Cache-Control: max-age`.
pub(crate) fn response_max_age(response: &[u8]) -> Option<u32> {
    let message = Message::decode(response, &DecodeLimits::default()).ok()?;
    message
        .answers()
        .iter()
        .chain(message.authority())
        .map(|record| record.ttl().as_u32())
        .min()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_get_and_keep_alive() {
        let head = b"GET /dns-query?dns=AAEC HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n";
        let parsed = parse_head(head).expect("head");
        assert_eq!(parsed.method, Method::Get);
        assert_eq!(parsed.target, "/dns-query?dns=AAEC");
        assert_eq!(parsed.version, 1);
        assert!(parsed.headers.keep_alive(parsed.version));
        assert_eq!(query_param(&parsed.target, "dns"), Some(b"AAEC".to_vec()));
    }

    #[test]
    fn parses_post_content_length() {
        let head = b"POST /dns-query HTTP/1.1\r\nContent-Type: application/dns-message\r\nContent-Length: 17\r\n\r\n";
        let parsed = parse_head(head).expect("head");
        assert_eq!(parsed.method, Method::Post);
        assert_eq!(parsed.headers.content_length(), Ok(Some(17)));
        assert!(parsed.headers.content_type_is("application/dns-message"));
    }

    #[test]
    fn rejects_http2_preface_and_garbage() {
        assert!(matches!(
            parse_head(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
            Err(ParseError::UnsupportedVersion)
        ));
        assert!(matches!(
            parse_head(b"garbage\r\n\r\n"),
            Err(ParseError::Malformed)
        ));
    }

    #[test]
    fn percent_and_base64_query() {
        assert_eq!(
            query_param("/dns-query?dns=AA%45C", "dns"),
            Some(b"AAEC".to_vec())
        );
        assert_eq!(query_param("/dns-query?other=1", "dns"), None);
        assert_eq!(query_param("/dns-query?dns=%zz", "dns"), None);
    }

    #[test]
    fn serializes_response() {
        let response = HttpResponse::dns(vec![1, 2, 3], Some(60), false);
        let bytes = response.to_bytes();
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.contains("content-length: 3\r\n"));
        assert!(text.contains("content-type: application/dns-message\r\n"));
        assert!(text.contains("cache-control: max-age=60\r\n"));
        assert!(text.ends_with("\r\n\r\n\u{1}\u{2}\u{3}"));
    }

    #[test]
    fn finds_head_end() {
        assert_eq!(find_head_end(b"abc\r\n\r\nrest"), Some(7));
        assert_eq!(find_head_end(b"abc"), None);
    }
}
