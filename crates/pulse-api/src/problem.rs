//! RFC 9457 `application/problem+json` и реестр кодов.

use serde_json::json;

use crate::error::{AdminError, Conflict, NotFound};
use crate::http::HttpResponse;

/// Проблемный HTTP-ответ.
#[derive(Debug, Clone)]
pub(crate) struct Problem {
    status: u16,
    code: &'static str,
    title: &'static str,
    detail: String,
    instance: String,
    request_id: String,
    retryable: bool,
    errors: Vec<crate::error::FieldIssue>,
    current_etag: Option<String>,
    current_version: Option<u64>,
    headers: Vec<(String, String)>,
}

impl Problem {
    /// Создаёт проблему.
    pub(crate) fn new(
        status: u16,
        code: &'static str,
        detail: impl Into<String>,
        instance: impl Into<String>,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            status,
            code,
            title: title_for(code),
            detail: detail.into(),
            instance: instance.into(),
            request_id: request_id.into(),
            retryable: status == 429 || status >= 500,
            errors: Vec::new(),
            current_etag: None,
            current_version: None,
            headers: Vec::new(),
        }
    }

    /// Добавляет field-level ошибки.
    pub(crate) fn with_errors(mut self, errors: Vec<crate::error::FieldIssue>) -> Self {
        self.errors = errors;
        self
    }

    /// Добавляет заголовок.
    pub(crate) fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Отмечает ответ как повторяемый.
    pub(crate) fn retryable(mut self, retryable: bool) -> Self {
        self.retryable = retryable;
        self
    }

    /// Код проблемы.
    pub(crate) fn code(&self) -> &'static str {
        self.code
    }

    /// Создаёт problem+json ответ.
    pub(crate) fn into_response(self) -> HttpResponse {
        let mut body = json!({
            "type": problem_type(self.code),
            "title": self.title,
            "status": self.status,
            "detail": self.detail,
            "instance": self.instance,
            "code": self.code,
            "request_id": self.request_id,
            "retryable": self.retryable,
            "errors": self
                .errors
                .iter()
                .map(|issue| json!({
                    "pointer": issue.pointer,
                    "code": issue.code,
                    "detail": issue.detail,
                }))
                .collect::<Vec<_>>(),
        });
        if let (Some(etag), Some(version)) = (&self.current_etag, self.current_version) {
            if let Some(object) = body.as_object_mut() {
                object.insert("current_etag".to_owned(), json!(etag));
                object.insert("current_version".to_owned(), json!(version));
            }
        }
        let mut response = HttpResponse::json(self.status, body);
        response.set_header("Content-Type", "application/problem+json");
        for (name, value) in self.headers {
            response.set_header(name, value);
        }
        if self.status == 401 {
            response.set_header("WWW-Authenticate", "Bearer");
        }
        response
    }

    /// Маппинг типизированной ошибки порта.
    pub(crate) fn from_admin(error: AdminError, instance: &str, request_id: &str) -> Self {
        match error {
            AdminError::NotFound(NotFound::Zone) => Self::new(
                404,
                "zone_not_found",
                "Zone is not served by this instance.",
                instance,
                request_id,
            ),
            AdminError::NotFound(NotFound::Rrset) => Self::new(
                404,
                "rrset-not-found",
                "The RRset does not exist.",
                instance,
                request_id,
            ),
            AdminError::Conflict(Conflict::ZoneExists) => Self::new(
                409,
                "zone-exists",
                "The zone already exists.",
                instance,
                request_id,
            ),
            AdminError::Conflict(Conflict::RrsetExists) => Self::new(
                409,
                "rrset-exists",
                "The RRset already exists.",
                instance,
                request_id,
            ),
            AdminError::Conflict(Conflict::ZoneBusy) | AdminError::Busy => Self::new(
                409,
                "zone-busy",
                "The zone is busy; retry the request.",
                instance,
                request_id,
            )
            .with_header("Retry-After", "0"),
            AdminError::Conflict(Conflict::ZoneReadOnly) => Self::new(
                409,
                "zone-read-only",
                "The zone is read-only.",
                instance,
                request_id,
            ),
            AdminError::PreconditionFailed {
                current_etag,
                current_version,
            } => Self {
                status: 412,
                code: "precondition-failed",
                title: title_for("precondition-failed"),
                detail: "The resource was modified; re-read it and retry.".to_owned(),
                instance: instance.to_owned(),
                request_id: request_id.to_owned(),
                retryable: false,
                errors: Vec::new(),
                current_etag,
                current_version,
                headers: Vec::new(),
            },
            AdminError::PreconditionRequired => Self::new(
                428,
                "precondition-required",
                "This operation requires an If-Match header.",
                instance,
                request_id,
            ),
            AdminError::InvariantViolation(violation) => Self::new(
                422,
                "validation-failed",
                "The request violates zone invariants.",
                instance,
                request_id,
            )
            .with_errors(violation.issues),
            AdminError::InvalidCursor => Self::new(
                400,
                "bad-request",
                "The pagination cursor is invalid.",
                instance,
                request_id,
            ),
            AdminError::Internal => Self::new(
                500,
                "internal-error",
                "An internal error occurred.",
                instance,
                request_id,
            ),
        }
    }
}

/// Стабильный URI типа проблемы.
pub(crate) fn problem_type(code: &str) -> String {
    format!("https://pulse-dns.dev/problems/{}", code.replace('_', "-"))
}

/// Заголовок проблемы.
pub(crate) fn title_for(code: &str) -> &'static str {
    match code {
        "bad-request" => "Bad request",
        "validation-failed" => "Validation failed",
        "unauthenticated" => "Unauthenticated",
        "forbidden" => "Forbidden",
        "zone_not_found" => "Zone not found",
        "rrset-not-found" => "RRset not found",
        "zone-exists" => "Zone already exists",
        "rrset-exists" => "RRset already exists",
        "zone-busy" => "Zone is busy",
        "zone-read-only" => "Zone is read-only",
        "precondition-failed" => "ETag mismatch",
        "precondition-required" => "Precondition required",
        "payload-too-large" => "Payload too large",
        "unsupported-media-type" => "Unsupported media type",
        "rate-limited" => "Rate limited",
        "internal-error" => "Internal error",
        "unavailable" => "Unavailable",
        "idempotency-key-reuse" => "Idempotency key reuse",
        "idempotency-in-progress" => "Idempotency request in progress",
        "method-not-allowed" => "Method not allowed",
        "not-found" => "Not found",
        "serial-managed" => "Serial is managed",
        "apex-ns-required" => "Apex NS is required",
        _ => "Request failed",
    }
}
