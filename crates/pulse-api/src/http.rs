//! Минимальный синхронный HTTP/1.1 транспорт с жёсткими лимитами.
//!
//! `tiny_http` не позволяет управлять таймаутом чтения принятого сокета,
//! поэтому транспорт реализован поверх `std::net::TcpStream`: одно соединение
//! — один запрос, `Connection: close`, лимиты заголовков/тела, общий дедлайн
//! чтения и защита от request smuggling (TE+CL, obs-fold, неизвестный TE).

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use serde_json::Value;

const MAX_REQUEST_LINE_BYTES: usize = 8192;
const MAX_HEADER_BYTES: usize = 32 * 1024;
const MAX_HEADERS: usize = 100;
const MAX_CHUNK_LINE_BYTES: usize = 1024;
const MAX_TRAILER_BYTES: usize = 4096;

/// Метод HTTP-запроса.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Method {
    /// GET.
    Get,
    /// PUT.
    Put,
    /// PATCH.
    Patch,
    /// DELETE.
    Delete,
    /// POST.
    Post,
    /// OPTIONS.
    Options,
    /// HEAD.
    Head,
    /// Иной метод (обрабатывается как 405).
    Other(String),
}

impl Method {
    /// Каноническое имя метода.
    pub(crate) fn as_str(&self) -> &str {
        match self {
            Self::Get => "GET",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
            Self::Post => "POST",
            Self::Options => "OPTIONS",
            Self::Head => "HEAD",
            Self::Other(value) => value,
        }
    }

    fn parse(value: &str) -> Self {
        match value {
            "GET" => Self::Get,
            "PUT" => Self::Put,
            "PATCH" => Self::Patch,
            "DELETE" => Self::Delete,
            "POST" => Self::Post,
            "OPTIONS" => Self::Options,
            "HEAD" => Self::Head,
            other => Self::Other(other.to_owned()),
        }
    }
}

/// Заголовки запроса (имена в нижнем регистре).
#[derive(Debug, Clone, Default)]
pub(crate) struct HeaderMap {
    entries: Vec<(String, String)>,
}

impl HeaderMap {
    /// Первое значение заголовка.
    pub(crate) fn get(&self, name: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// Все значения заголовка.
    pub(crate) fn get_all(&self, name: &str) -> Vec<&str> {
        self.entries
            .iter()
            .filter(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
            .collect()
    }

    /// Добавляет заголовок.
    fn push(&mut self, name: String, value: String) {
        self.entries.push((name, value));
    }
}

/// Разобранный HTTP-запрос.
#[derive(Debug, Clone)]
pub(crate) struct HttpRequest {
    /// Метод.
    pub(crate) method: Method,
    /// Сырой path без query (до percent-decoding).
    pub(crate) path: String,
    /// Сырая query-строка без `?`.
    pub(crate) query_string: String,
    /// Заголовки.
    pub(crate) headers: HeaderMap,
    /// Тело запроса.
    pub(crate) body: Vec<u8>,
}

impl HttpRequest {
    /// Заголовок как `&str`.
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name)
    }
}

/// HTTP-ответ.
#[derive(Debug, Clone)]
pub(crate) struct HttpResponse {
    /// Статус.
    pub(crate) status: u16,
    /// Заголовки (без `Content-Length`, `Date`, `Connection`).
    pub(crate) headers: Vec<(String, String)>,
    /// Тело.
    pub(crate) body: Vec<u8>,
}

impl HttpResponse {
    /// JSON-ответ.
    pub(crate) fn json(status: u16, value: Value) -> Self {
        let body = serde_json::to_vec(&value).unwrap_or_else(|_| b"{}".to_vec());
        let mut response = Self {
            status,
            headers: Vec::new(),
            body,
        };
        response.set_header("Content-Type", "application/json; charset=utf-8");
        response
    }

    /// Текстовый ответ.
    pub(crate) fn text(status: u16, content_type: &str, body: impl Into<String>) -> Self {
        let mut response = Self {
            status,
            headers: Vec::new(),
            body: body.into().into_bytes(),
        };
        response.set_header("Content-Type", content_type);
        response
    }

    /// Ответ без тела.
    pub(crate) fn empty(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// Устанавливает (или заменяет) заголовок.
    pub(crate) fn set_header(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let name = name.into();
        let value = value.into();
        if let Some(existing) = self
            .headers
            .iter_mut()
            .find(|(existing, _)| existing.eq_ignore_ascii_case(&name))
        {
            existing.1 = value;
        } else {
            self.headers.push((name, value));
        }
    }

    /// Значение заголовка.
    #[cfg(test)]
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// Лимиты транспорта.
#[derive(Debug, Clone, Copy)]
pub(crate) struct HttpLimits {
    /// Максимум тела.
    pub(crate) max_body_bytes: usize,
    /// Дедлайн чтения.
    pub(crate) request_timeout: Duration,
    /// Таймаут записи.
    pub(crate) write_timeout: Duration,
}

/// Ошибка чтения запроса.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RequestError {
    /// HTTP-статус.
    pub(crate) status: u16,
    /// Код проблемы.
    pub(crate) code: &'static str,
    /// Деталь.
    pub(crate) detail: &'static str,
}

impl RequestError {
    fn malformed(detail: &'static str) -> Self {
        Self {
            status: 400,
            code: "bad-request",
            detail,
        }
    }

    fn too_large() -> Self {
        Self {
            status: 413,
            code: "payload-too-large",
            detail: "Request body exceeds the configured limit.",
        }
    }

    fn timeout() -> Self {
        Self {
            status: 408,
            code: "bad-request",
            detail: "Request read timed out.",
        }
    }

    fn io() -> Self {
        Self {
            status: 400,
            code: "bad-request",
            detail: "Malformed or truncated HTTP request.",
        }
    }
}

/// Читает один HTTP-запрос.
pub(crate) fn read_request(
    stream: &mut TcpStream,
    limits: &HttpLimits,
) -> Result<HttpRequest, RequestError> {
    let deadline = Instant::now() + limits.request_timeout;
    let mut reader = ConnReader {
        stream,
        buffer: Vec::new(),
        deadline,
    };
    loop {
        if find_header_end(&reader.buffer).is_some() {
            break;
        }
        if reader.buffer.len() >= MAX_HEADER_BYTES {
            return Err(RequestError::too_large());
        }
        reader.fill()?;
    }
    let header_end = find_header_end(&reader.buffer).ok_or_else(RequestError::io)?;
    let header_bytes = reader
        .buffer
        .get(..header_end)
        .ok_or_else(RequestError::io)?
        .to_vec();
    let rest = reader
        .buffer
        .get(header_end + 4..)
        .ok_or_else(RequestError::io)?
        .to_vec();
    reader.buffer = rest;
    if header_bytes.len() > MAX_HEADER_BYTES {
        return Err(RequestError::too_large());
    }
    let header_text = std::str::from_utf8(&header_bytes)
        .map_err(|_| RequestError::malformed("Header block is not valid ASCII/UTF-8."))?;
    let mut lines = header_text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| RequestError::malformed("Missing request line."))?;
    if request_line.len() > MAX_REQUEST_LINE_BYTES {
        return Err(RequestError::malformed("Request line is too long."));
    }
    let mut parts = request_line.split(' ');
    let method_text = parts
        .next()
        .ok_or_else(|| RequestError::malformed("Missing method."))?;
    let target = parts
        .next()
        .ok_or_else(|| RequestError::malformed("Missing request target."))?;
    let version = parts
        .next()
        .ok_or_else(|| RequestError::malformed("Missing HTTP version."))?;
    if parts.next().is_some() {
        return Err(RequestError::malformed("Malformed request line."));
    }
    if !is_token(method_text.as_bytes()) || method_text.is_empty() {
        return Err(RequestError::malformed("Invalid method token."));
    }
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(RequestError {
            status: 505,
            code: "bad-request",
            detail: "Only HTTP/1.0 and HTTP/1.1 are supported.",
        });
    }
    let (path, query_string) = split_target(target)?;
    let mut headers = HeaderMap::default();
    let mut count = 0_usize;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(RequestError::malformed(
                "Obsolete header folding is not allowed.",
            ));
        }
        count += 1;
        if count > MAX_HEADERS {
            return Err(RequestError::malformed("Too many headers."));
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| RequestError::malformed("Malformed header line."))?;
        if !is_token(name.as_bytes()) || name.is_empty() {
            return Err(RequestError::malformed("Invalid header name."));
        }
        let value = value.trim_matches([' ', '\t']);
        if value
            .bytes()
            .any(|byte| byte != b'\t' && !(0x20..=0x7E).contains(&byte))
        {
            return Err(RequestError::malformed("Invalid header value."));
        }
        headers.push(name.to_ascii_lowercase(), value.to_owned());
    }

    let content_lengths = headers.get_all("content-length");
    if content_lengths.len() > 1 {
        return Err(RequestError::malformed("Duplicate Content-Length."));
    }
    let content_length = match content_lengths.first() {
        Some(value) => Some(
            value
                .parse::<usize>()
                .map_err(|_| RequestError::malformed("Invalid Content-Length."))?,
        ),
        None => None,
    };
    let transfer_encodings = headers.get_all("transfer-encoding");
    let chunked = !transfer_encodings.is_empty();
    if chunked && content_length.is_some() {
        return Err(RequestError::malformed(
            "Both Transfer-Encoding and Content-Length are present.",
        ));
    }
    if chunked {
        for (index, value) in transfer_encodings.iter().enumerate() {
            let tokens: Vec<&str> = value
                .split(',')
                .map(str::trim)
                .filter(|token| !token.is_empty())
                .collect();
            if tokens.is_empty() {
                return Err(RequestError::malformed("Empty Transfer-Encoding."));
            }
            for (position, token) in tokens.iter().enumerate() {
                if !token.eq_ignore_ascii_case("chunked") {
                    return Err(RequestError::malformed("Unsupported Transfer-Encoding."));
                }
                if index + 1 != transfer_encodings.len() || position + 1 != tokens.len() {
                    return Err(RequestError::malformed(
                        "chunked must be the final Transfer-Encoding.",
                    ));
                }
            }
        }
    }
    if let Some(length) = content_length {
        if length > limits.max_body_bytes {
            return Err(RequestError::too_large());
        }
    }
    if let Some(expect) = headers.get("expect") {
        if expect.eq_ignore_ascii_case("100-continue") {
            reader.send_continue()?;
        } else {
            return Err(RequestError::malformed("Unsupported Expect header."));
        }
    }

    let body = if chunked {
        read_chunked(&mut reader, limits.max_body_bytes)?
    } else if let Some(length) = content_length {
        reader.take_exact(length)?
    } else {
        Vec::new()
    };

    Ok(HttpRequest {
        method: Method::parse(method_text),
        path,
        query_string,
        headers,
        body,
    })
}

fn split_target(target: &str) -> Result<(String, String), RequestError> {
    if target.len() > MAX_REQUEST_LINE_BYTES {
        return Err(RequestError::malformed("Request target is too long."));
    }
    let origin_form = if target.starts_with('/') {
        target
    } else if let Some(rest) = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))
    {
        let slash = rest.find('/').unwrap_or(rest.len());
        rest.get(slash..).unwrap_or("/")
    } else {
        return Err(RequestError::malformed(
            "Request target must be origin-form.",
        ));
    };
    let (path, query) = origin_form
        .split_once('?')
        .map_or((origin_form, ""), |(path, query)| (path, query));
    if path.is_empty() {
        return Err(RequestError::malformed("Empty request path."));
    }
    Ok((path.to_owned(), query.to_owned()))
}

fn read_chunked(reader: &mut ConnReader<'_>, max_body: usize) -> Result<Vec<u8>, RequestError> {
    let mut body = Vec::new();
    loop {
        let line = reader.read_line(MAX_CHUNK_LINE_BYTES)?;
        let size_text = line.split(';').next().unwrap_or("").trim();
        if size_text.is_empty() || size_text.len() > 16 {
            return Err(RequestError::malformed("Invalid chunk size."));
        }
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| RequestError::malformed("Invalid chunk size."))?;
        if size == 0 {
            let mut trailer_bytes = 0_usize;
            loop {
                let trailer = reader.read_line(MAX_CHUNK_LINE_BYTES)?;
                trailer_bytes += trailer.len() + 2;
                if trailer_bytes > MAX_TRAILER_BYTES {
                    return Err(RequestError::malformed("Trailer section is too large."));
                }
                if trailer.is_empty() {
                    break;
                }
            }
            break;
        }
        if body.len().saturating_add(size) > max_body {
            return Err(RequestError::too_large());
        }
        let framed = reader.take_exact(size.saturating_add(2))?;
        let data = framed.get(..size).ok_or_else(RequestError::io)?;
        let terminator = framed.get(size..).ok_or_else(RequestError::io)?;
        if terminator != b"\r\n" {
            return Err(RequestError::malformed("Chunk is not terminated by CRLF."));
        }
        body.extend_from_slice(data);
    }
    Ok(body)
}

/// Проверяет, является ли значение HTTP-token.
fn is_token(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes.iter().all(|byte| {
            matches!(
                byte,
                b'!' | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'.'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'|'
                    | b'~'
            ) || byte.is_ascii_alphanumeric()
        })
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

struct ConnReader<'a> {
    stream: &'a mut TcpStream,
    buffer: Vec<u8>,
    deadline: Instant,
}

impl ConnReader<'_> {
    fn send_continue(&mut self) -> Result<(), RequestError> {
        self.stream
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .map_err(|_| RequestError::io())?;
        self.stream.flush().map_err(|_| RequestError::io())
    }

    fn fill(&mut self) -> Result<(), RequestError> {
        let mut chunk = [0_u8; 4096];
        let timeout = self.deadline.saturating_duration_since(Instant::now());
        if timeout.is_zero() {
            return Err(RequestError::timeout());
        }
        self.stream
            .set_read_timeout(Some(timeout))
            .map_err(|_| RequestError::io())?;
        match self.stream.read(&mut chunk) {
            Ok(0) => Err(RequestError::io()),
            Ok(read) => {
                let data = chunk.get(..read).ok_or_else(RequestError::io)?;
                self.buffer.extend_from_slice(data);
                Ok(())
            }
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.kind() == io::ErrorKind::TimedOut =>
            {
                Err(RequestError::timeout())
            }
            Err(_) => Err(RequestError::io()),
        }
    }

    fn take_exact(&mut self, length: usize) -> Result<Vec<u8>, RequestError> {
        while self.buffer.len() < length {
            self.fill()?;
        }
        let data = self
            .buffer
            .get(..length)
            .ok_or_else(RequestError::io)?
            .to_vec();
        self.buffer.drain(..length);
        Ok(data)
    }

    fn read_line(&mut self, max: usize) -> Result<String, RequestError> {
        loop {
            if let Some(position) = self.buffer.windows(2).position(|window| window == b"\r\n") {
                if position > max {
                    return Err(RequestError::malformed("HTTP line is too long."));
                }
                let line = self
                    .buffer
                    .get(..position)
                    .ok_or_else(RequestError::io)?
                    .to_vec();
                self.buffer.drain(..position + 2);
                return String::from_utf8(line)
                    .map_err(|_| RequestError::malformed("HTTP line is not valid UTF-8."));
            }
            if self.buffer.len() > max {
                return Err(RequestError::malformed("HTTP line is too long."));
            }
            self.fill()?;
        }
    }
}

/// Записывает ответ и закрывает соединение.
pub(crate) fn write_response(
    stream: &mut TcpStream,
    response: &HttpResponse,
    limits: &HttpLimits,
) -> io::Result<()> {
    let mut head = String::with_capacity(256);
    head.push_str("HTTP/1.1 ");
    head.push_str(&response.status.to_string());
    head.push(' ');
    head.push_str(reason_phrase(response.status));
    head.push_str("\r\nDate: ");
    head.push_str(&crate::timefmt::http_date(std::time::SystemTime::now()));
    head.push_str("\r\nServer: pulse-api/0.1\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\nContent-Length: ");
    head.push_str(&response.body.len().to_string());
    head.push_str("\r\n");
    for (name, value) in &response.headers {
        if name.bytes().any(|byte| byte == b'\r' || byte == b'\n')
            || value.bytes().any(|byte| byte == b'\r' || byte == b'\n')
        {
            continue;
        }
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    stream
        .set_write_timeout(Some(limits.write_timeout))
        .map_err(io::Error::other)?;
    stream.write_all(head.as_bytes())?;
    if !response.body.is_empty() {
        stream.write_all(&response.body)?;
    }
    stream.flush()?;
    let _ = stream.shutdown(std::net::Shutdown::Write);
    Ok(())
}

/// Стандартная причина статуса.
fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        408 => "Request Timeout",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        422 => "Unprocessable Content",
        428 => "Precondition Required",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_validation() {
        assert!(is_token(b"Content-Type"));
        assert!(is_token(b"x_1"));
        assert!(!is_token(b""));
        assert!(!is_token(b"bad header"));
        assert!(!is_token(b"bad:header"));
    }

    #[test]
    fn target_parsing() {
        assert_eq!(
            split_target("/api/v1/zones?limit=1").unwrap(),
            ("/api/v1/zones".to_owned(), "limit=1".to_owned())
        );
        assert_eq!(
            split_target("http://localhost:8080/healthz").unwrap(),
            ("/healthz".to_owned(), String::new())
        );
        assert!(split_target("relative").is_err());
    }

    #[test]
    fn header_end_detection() {
        assert_eq!(find_header_end(b"GET / HTTP/1.1\r\n\r\nrest"), Some(14));
        assert_eq!(find_header_end(b"GET / HTTP/1.1\r\n"), None);
    }

    #[test]
    fn response_headers_do_not_inject() {
        let mut response = HttpResponse::text(200, "text/plain", "ok");
        response.set_header("X-Test", "value");
        response.set_header("Content-Type", "application/json");
        assert_eq!(response.header("content-type"), Some("application/json"));
        response.set_header("X-Test", "other");
    }
}
