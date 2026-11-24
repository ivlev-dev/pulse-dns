//! HTTP-маршрутизация и обработка запросов.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use pulse_dns::{Name, Rdata, Rtype, Ttl};
use pulse_dnssec::{DIGEST_SHA256, DNSKEY_FLAG_SEP, DsPolicy, ds_from_dnskey, key_tag};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::audit::{AuditLog, AuditQuery};
use crate::auth::{Authenticator, Principal};
use crate::codec::{hex_lower, parse_rtype};
use crate::config::{ApiConfig, MAX_IMPORT_BYTES};
use crate::error::{AdminError, Conflict, FieldIssue, NotFound};
use crate::etag::{header_matches, normalize_tag};
use crate::http::{HttpRequest, HttpResponse, Method};
use crate::idempotency::{Begin, IdempotencyStore};
use crate::jobs::{CancelOutcome, JobFailure, JobQuery, JobRecord, JobRegistry, JobState};
use crate::journal::{
    Begin as JournalBegin, Journal, JournalOp, body_hash_hex, crash_point, intent as journal_intent,
};
use crate::metrics::Metrics;
use crate::port::{
    AllowAll, Denial, ImportMode, KeyRotationView, ListRrsets, ListZones, Precondition,
    Preconditions, RolloverRequest, RrsetInput, RrsetPatch, RrsetPatchOutcome, SerialUpdate,
    TransferKind, TransferRequest, ZoneAdmin, ZoneAllow, ZoneKind, ZoneMetaInput,
    ZoneSettingsPatch, ZoneView,
};
use crate::problem::Problem;
use crate::query::{Query, decode_path_segments, parse_limit};
use crate::ratelimit::{Decision, RateLimiter};
use crate::rdata_text::{format_rdata, parse_rdata};
use crate::timefmt::rfc3339;

/// Контекст одной мутации: стабильный `op_id` и хеш тела.
struct MutationContext {
    op_id: String,
    body_sha256: String,
}

/// Обработчик API.
pub(crate) struct Api {
    store: Arc<dyn ZoneAdmin>,
    auth: Authenticator,
    metrics: Metrics,
    extra_metrics: Option<crate::server::MetricsProvider>,
    limiter: RateLimiter,
    idempotency: IdempotencyStore,
    journal: Option<Arc<Journal>>,
    jobs: Arc<JobRegistry>,
    audit_log: Arc<AuditLog>,
    max_body_bytes: usize,
    request_counter: AtomicU64,
    op_counter: AtomicU64,
}

impl Api {
    /// Создаёт обработчик из валидированной конфигурации.
    pub(crate) fn new(
        config: &ApiConfig,
        store: Arc<dyn ZoneAdmin>,
        auth: Authenticator,
        extra_metrics: Option<crate::server::MetricsProvider>,
        journal: Option<Arc<Journal>>,
    ) -> Self {
        Self {
            store,
            auth,
            metrics: Metrics::default(),
            extra_metrics,
            limiter: RateLimiter::new(config.rate_limit_per_sec),
            idempotency: IdempotencyStore::new(config.idempotency_ttl, config.idempotency_capacity),
            journal,
            jobs: Arc::new(JobRegistry::new(Duration::from_hours(24), 4096)),
            audit_log: Arc::new(AuditLog::new(4096)),
            max_body_bytes: config.max_body_bytes,
            request_counter: AtomicU64::new(1),
            op_counter: AtomicU64::new(1),
        }
    }

    /// Обрабатывает один запрос.
    pub(crate) fn handle(&self, request: &HttpRequest, peer: SocketAddr) -> HttpResponse {
        let request_id = self.request_id(request);
        let method = request.method.as_str().to_owned();
        let route_label = route_label(&request.path);
        let result = self.handle_inner(request, peer, &request_id);
        let (mut response, error_code) = match result {
            Ok(response) => (response, None),
            Err(problem) => {
                let code = problem.code();
                (problem.into_response(), Some(code))
            }
        };
        response.set_header("X-Request-Id", request_id);
        self.metrics
            .record_request(&method, route_label, response.status);
        if let Some(code) = error_code {
            self.metrics.record_error(code);
        }
        response
    }

    fn handle_inner(
        &self,
        request: &HttpRequest,
        peer: SocketAddr,
        request_id: &str,
    ) -> Result<HttpResponse, Problem> {
        let instance = request.path.as_str();
        if let Some(response) = self.public_route(request, request_id) {
            return Ok(response);
        }
        if !request.path.starts_with("/api/v1/") {
            return Err(Problem::new(
                404,
                "not-found",
                "The requested resource does not exist.",
                instance,
                request_id,
            ));
        }
        let principal = self.authenticate(request, peer, request_id, instance)?;
        let route = parse_route(request, instance, request_id)?;
        let decision = self.limiter.check(&principal.token_id);
        if !decision.allowed {
            self.metrics.rate_limited();
            let retry = decision.retry_after.unwrap_or(1);
            let problem = Problem::new(
                429,
                "rate-limited",
                "Too many requests for this token.",
                instance,
                request_id,
            )
            .with_header("Retry-After", retry.to_string());
            return Err(with_rate_headers(problem, decision));
        }
        if let Some(origin) = route.origin() {
            if !principal.zone_allowed(origin) {
                self.metrics.denied_zone_out_of_scope();
                self.audit(
                    request_id,
                    &principal.token_id,
                    "zone.access",
                    &origin.to_string(),
                    "denied",
                    Some("denied_zone_out_of_scope"),
                    peer,
                );
                return Err(with_rate_headers(
                    Problem::new(
                        404,
                        "zone_not_found",
                        "Zone is not served by this instance.",
                        instance,
                        request_id,
                    ),
                    decision,
                ));
            }
        }
        let allowed = route.allowed_methods();
        if !allowed.contains(&request.method.as_str()) {
            return Err(with_rate_headers(
                method_not_allowed(allowed, instance, request_id),
                decision,
            ));
        }
        if let Some(scope) = required_scope(&route, &request.method) {
            if !principal.has_scope(scope) {
                self.audit(
                    request_id,
                    &principal.token_id,
                    "scope.check",
                    &route.target(),
                    "denied",
                    Some("denied_scope"),
                    peer,
                );
                return Err(with_rate_headers(
                    Problem::new(
                        403,
                        "forbidden",
                        "The token does not grant the required operation scope.",
                        instance,
                        request_id,
                    ),
                    decision,
                ));
            }
        }
        let idempotency_key = self.idempotency_key(request, &principal, instance, request_id)?;
        if let Some(key) = &idempotency_key {
            match self.idempotency.begin(key, sha256(&request.body)) {
                Begin::New => {}
                Begin::Replay(mut response) => {
                    apply_rate_headers(&mut response, decision);
                    return Ok(response);
                }
                Begin::Conflict => {
                    return Err(with_rate_headers(
                        Problem::new(
                            409,
                            "idempotency-key-reuse",
                            "The Idempotency-Key was already used with a different request body.",
                            instance,
                            request_id,
                        ),
                        decision,
                    ));
                }
                Begin::InProgress => {
                    return Err(with_rate_headers(
                        Problem::new(
                            409,
                            "idempotency-in-progress",
                            "A request with this Idempotency-Key is already in progress.",
                            instance,
                            request_id,
                        ),
                        decision,
                    ));
                }
            }
        }
        let mutation = self.mutation_context(request, request_id, idempotency_key.as_deref());
        let result = self.dispatch(request, &route, &principal, request_id, instance, &mutation);
        if let Some(key) = &idempotency_key {
            match &result {
                Ok(response) if (200..300).contains(&response.status) => {
                    self.idempotency.complete(key, response);
                }
                _ => self.idempotency.abort(key),
            }
        }
        let is_mutation = matches!(
            request.method,
            Method::Put | Method::Patch | Method::Delete | Method::Post
        );
        match result {
            Ok(mut response) => {
                if is_mutation {
                    self.audit(
                        request_id,
                        &principal.token_id,
                        route.action(&request.method),
                        &audit_target(&route, instance),
                        "success",
                        None,
                        peer,
                    );
                }
                apply_rate_headers(&mut response, decision);
                Ok(response)
            }
            Err(problem) => {
                if is_mutation {
                    self.audit(
                        request_id,
                        &principal.token_id,
                        route.action(&request.method),
                        &audit_target(&route, instance),
                        "failed",
                        Some(problem.code()),
                        peer,
                    );
                }
                Err(with_rate_headers(problem, decision))
            }
        }
    }

    fn public_route(&self, request: &HttpRequest, request_id: &str) -> Option<HttpResponse> {
        let instance = request.path.as_str();
        match instance {
            "/healthz" => {
                if request.method == Method::Get {
                    Some(HttpResponse::json(200, json!({ "status": "ok" })))
                } else {
                    Some(method_not_allowed(&["GET"], instance, request_id).into_response())
                }
            }
            "/readyz" => {
                if request.method == Method::Get {
                    if self.store.ready() {
                        Some(HttpResponse::json(200, json!({ "status": "ready" })))
                    } else {
                        Some(
                            Problem::new(
                                503,
                                "unavailable",
                                "The service is not ready.",
                                instance,
                                request_id,
                            )
                            .retryable(true)
                            .with_header("Retry-After", "1")
                            .into_response(),
                        )
                    }
                } else {
                    Some(method_not_allowed(&["GET"], instance, request_id).into_response())
                }
            }
            "/metrics" => {
                if request.method == Method::Get {
                    let mut body = self.metrics.render_with(self.store.zonefile_metrics());
                    if let Some(journal) = &self.journal {
                        body.push_str(&journal.metrics().render());
                    }
                    if let Some(extra) = &self.extra_metrics {
                        body.push_str(&extra());
                    }
                    Some(HttpResponse::text(
                        200,
                        "text/plain; version=0.0.4; charset=utf-8",
                        body,
                    ))
                } else {
                    Some(method_not_allowed(&["GET"], instance, request_id).into_response())
                }
            }
            _ => None,
        }
    }

    fn authenticate(
        &self,
        request: &HttpRequest,
        peer: SocketAddr,
        request_id: &str,
        instance: &str,
    ) -> Result<Principal, Problem> {
        let header = request.header("authorization");
        let principal = header.and_then(|value| self.auth.authenticate(value));
        principal.ok_or_else(|| {
            self.metrics.auth_failed();
            self.audit(
                request_id,
                "-",
                "auth",
                instance,
                "denied",
                Some("auth_failed"),
                peer,
            );
            Problem::new(
                401,
                "unauthenticated",
                "A valid bearer token is required.",
                instance,
                request_id,
            )
        })
    }

    fn idempotency_key(
        &self,
        request: &HttpRequest,
        principal: &Principal,
        instance: &str,
        request_id: &str,
    ) -> Result<Option<String>, Problem> {
        if !matches!(
            request.method,
            Method::Put | Method::Patch | Method::Delete | Method::Post
        ) {
            return Ok(None);
        }
        let Some(value) = request.header("idempotency-key") else {
            return Ok(None);
        };
        if !valid_idempotency_key(value) {
            return Err(Problem::new(
                400,
                "bad-request",
                "Idempotency-Key must be 8..=128 characters of [A-Za-z0-9._-].",
                instance,
                request_id,
            ));
        }
        let mut hasher = Sha256::new();
        hasher.update(principal.token_id.as_bytes());
        hasher.update([0x1F]);
        hasher.update(request.method.as_str().as_bytes());
        hasher.update([0x1F]);
        hasher.update(instance.as_bytes());
        hasher.update([0x1F]);
        hasher.update(value.as_bytes());
        Ok(Some(hex_lower(&hasher.finalize())))
    }

    fn mutation_context(
        &self,
        request: &HttpRequest,
        request_id: &str,
        idempotency_key: Option<&str>,
    ) -> MutationContext {
        let body_sha256 = body_hash_hex(&request.body);
        let op_id = if let Some(key) = idempotency_key {
            let mut hasher = Sha256::new();
            hasher.update(b"pulse-op\0");
            hasher.update(key.as_bytes());
            hex_lower(&hasher.finalize())
        } else {
            let counter = self.op_counter.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos());
            let mut hasher = Sha256::new();
            hasher.update(b"pulse-op\0");
            hasher.update(nanos.to_le_bytes());
            hasher.update(counter.to_le_bytes());
            hasher.update(std::process::id().to_le_bytes());
            hasher.update(request.method.as_str().as_bytes());
            hasher.update(request.path.as_bytes());
            hasher.update(body_sha256.as_bytes());
            hasher.update(request_id.as_bytes());
            hex_lower(&hasher.finalize())
        };
        MutationContext { op_id, body_sha256 }
    }

    #[allow(clippy::too_many_arguments)]
    fn journaled<F, R>(
        &self,
        ctx: &MutationContext,
        request: &HttpRequest,
        instance: &str,
        request_id: &str,
        preconditions: &Preconditions,
        operation: JournalOp,
        apply: F,
        replay: R,
    ) -> Result<HttpResponse, Problem>
    where
        F: FnOnce(&dyn ZoneAdmin) -> Result<(HttpResponse, u64), Problem>,
        R: FnOnce(&dyn ZoneAdmin) -> Result<HttpResponse, Problem>,
    {
        let Some(journal) = &self.journal else {
            let (response, _) = apply(&*self.store)?;
            return Ok(response);
        };
        let intent = journal_intent(
            &ctx.op_id,
            request.method.as_str(),
            &request.path,
            &ctx.body_sha256,
            preconditions,
            operation.clone(),
        );
        let begin = journal
            .begin(intent)
            .inspect_err(|_| journal.record_error())
            .map_err(|error| journal_failure(instance, request_id, &error))?;
        crash_point("after_intent");
        let mut replay_response = None;
        match begin {
            JournalBegin::New => {}
            JournalBegin::Conflict => {
                return Err(Problem::new(
                    409,
                    "idempotency-key-reuse",
                    "The Idempotency-Key was already used with a different request body.",
                    instance,
                    request_id,
                ));
            }
            JournalBegin::Pending => match operation.already_applied(&*self.store) {
                Ok(Some(version)) => {
                    journal
                        .commit(&ctx.op_id, version, None)
                        .inspect_err(|_| journal.record_error())
                        .map_err(|error| journal_failure(instance, request_id, &error))?;
                    journal.note_replay();
                    replay_response = Some(replay(&*self.store)?);
                }
                Ok(None) => {}
                Err(error) => return Err(Problem::from_admin(error, instance, request_id)),
            },
            JournalBegin::Response(stored) => {
                journal.note_replay();
                return Ok(stored.into_http());
            }
            JournalBegin::Committed { version } => {
                let _ = version;
                journal.note_replay();
                return Ok(with_replay_header(replay(&*self.store)?));
            }
            JournalBegin::Aborted { reason } => {
                return Err(Problem::new(
                    409,
                    "idempotency-key-reuse",
                    format!(
                        "The operation was previously rejected ({reason}); use a new Idempotency-Key."
                    ),
                    instance,
                    request_id,
                ));
            }
        }
        if let Some(mut response) = replay_response {
            response.set_header("Idempotent-Replay", "true");
            return Ok(response);
        }
        match apply(&*self.store) {
            Ok((response, version)) => {
                crash_point("after_apply");
                journal
                    .commit(&ctx.op_id, version, Some(&response))
                    .inspect_err(|_| journal.record_error())
                    .map_err(|error| journal_failure(instance, request_id, &error))?;
                crash_point("after_committed");
                Ok(response)
            }
            Err(problem) if problem.status() >= 500 => Err(problem),
            Err(problem) => {
                let retryable = matches!(
                    problem.code(),
                    "zone-busy" | "precondition-failed" | "precondition-required"
                );
                let response = problem.clone().into_response();
                if journal
                    .abort(&ctx.op_id, problem.code(), retryable, Some(&response))
                    .is_err()
                {
                    journal.record_error();
                }
                Err(problem)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn dispatch(
        &self,
        request: &HttpRequest,
        route: &Route,
        principal: &Principal,
        request_id: &str,
        instance: &str,
        mutation: &MutationContext,
    ) -> Result<HttpResponse, Problem> {
        match route {
            Route::Health | Route::Ready | Route::Metrics => Err(internal(instance, request_id)),
            Route::OpenApi => Ok(HttpResponse::json(200, crate::openapi::document())),
            Route::Zones => match request.method {
                Method::Get => self.list_zones(request, principal, request_id, instance),
                Method::Post => self.create_zone(request, principal, request_id, instance),
                _ => Err(internal(instance, request_id)),
            },
            Route::Zone(origin) => match request.method {
                Method::Get => self.get_zone(request, origin, request_id, instance),
                Method::Put => self.put_zone(request, origin, request_id, instance, mutation),
                Method::Delete => self.delete_zone(request, origin, request_id, instance, mutation),
                _ => Err(internal(instance, request_id)),
            },
            Route::ZoneSerial(origin) => match request.method {
                Method::Get => self.get_serial(origin, request_id, instance),
                Method::Post => self.update_serial(request, origin, request_id, instance),
                _ => Err(internal(instance, request_id)),
            },
            Route::ZoneTransfers(origin) => match request.method {
                Method::Get => {
                    self.list_transfers(request, origin, principal, request_id, instance)
                }
                Method::Post => {
                    self.trigger_transfer(request, origin, principal, request_id, instance)
                }
                _ => Err(internal(instance, request_id)),
            },
            Route::ZoneImport(origin) => match request.method {
                Method::Post => self.import_zone(request, origin, request_id, instance),
                _ => Err(internal(instance, request_id)),
            },
            Route::ZoneSettings(origin) => match request.method {
                Method::Get => self.get_settings(origin, request_id, instance),
                Method::Patch => {
                    self.patch_settings(request, origin, request_id, instance, mutation)
                }
                _ => Err(internal(instance, request_id)),
            },
            Route::ZoneKeys(origin) => self.get_zone_keys(origin, request_id, instance),
            Route::ZoneKeysStatus(origin) => self.get_keys_status(origin, request_id, instance),
            Route::ZoneRollover(origin) => {
                self.rollover_keys(request, origin, request_id, instance)
            }
            Route::ZoneSign(origin) => self.sign_zone(request, origin, request_id, instance),
            Route::Jobs => self.list_jobs(request, principal, request_id, instance),
            Route::Job(job_id) => match request.method {
                Method::Get => self.get_job(job_id, principal, request_id, instance),
                Method::Delete => self.cancel_job(job_id, principal, request_id, instance, false),
                _ => Err(internal(instance, request_id)),
            },
            Route::TransferJob(job_id) => match request.method {
                Method::Get => self.get_job(job_id, principal, request_id, instance),
                Method::Delete => self.cancel_job(job_id, principal, request_id, instance, true),
                _ => Err(internal(instance, request_id)),
            },
            Route::Audit => self.list_audit(request, request_id, instance),
            Route::RrsetList(origin) => self.list_rrsets(request, origin, request_id, instance),
            Route::Rrset {
                origin,
                owner,
                rr_type,
            } => match request.method {
                Method::Get => {
                    self.get_rrset(request, origin, owner, *rr_type, request_id, instance)
                }
                Method::Put => self.put_rrset(
                    request, origin, owner, *rr_type, request_id, instance, mutation,
                ),
                Method::Patch => self.patch_rrset(
                    request, origin, owner, *rr_type, request_id, instance, mutation,
                ),
                Method::Delete => self.delete_rrset(
                    request, origin, owner, *rr_type, request_id, instance, mutation,
                ),
                _ => Err(internal(instance, request_id)),
            },
        }
    }

    fn get_zone_keys(
        &self,
        origin: &Name,
        request_id: &str,
        instance: &str,
    ) -> Result<HttpResponse, Problem> {
        let zone = self
            .store
            .get_zone(origin)
            .map_err(|error| Problem::from_admin(error, instance, request_id))?;
        let rrset = match self.store.get_rrset(origin, origin, Rtype::DNSKEY) {
            Ok(rrset) => rrset,
            Err(AdminError::NotFound(NotFound::Rrset)) => {
                return Err(Problem::new(
                    404,
                    "dnssec_not_configured",
                    "Zone has no DNSSEC keys.",
                    instance,
                    request_id,
                ));
            }
            Err(error) => return Err(Problem::from_admin(error, instance, request_id)),
        };
        let dnskeys: Vec<pulse_dns::DnskeyData> = rrset
            .rdata
            .iter()
            .filter_map(|rdata| match rdata {
                Rdata::Dnskey(key) => Some(key.clone()),
                _ => None,
            })
            .collect();
        if dnskeys.is_empty() {
            return Err(Problem::new(
                404,
                "dnssec_not_configured",
                "Zone has no DNSSEC keys.",
                instance,
                request_id,
            ));
        }
        let has_sep = dnskeys.iter().any(|key| key.flags() & DNSKEY_FLAG_SEP != 0);
        let mut keys = Vec::with_capacity(dnskeys.len());
        let mut ds = Vec::new();
        for key in &dnskeys {
            keys.push(json!({
                "flags": key.flags(),
                "protocol": key.protocol(),
                "algorithm": key.algorithm(),
                "key_tag": key_tag(key),
                "role": if key.flags() & DNSKEY_FLAG_SEP != 0 { "ksk" } else { "zsk" },
                "public_key": base64::engine::general_purpose::STANDARD.encode(key.public_key()),
            }));
            let is_ds_candidate = !has_sep || key.flags() & DNSKEY_FLAG_SEP != 0;
            if is_ds_candidate {
                let record = ds_from_dnskey(origin, key, DIGEST_SHA256, DsPolicy::strict())
                    .map_err(|_| internal(instance, request_id))?;
                ds.push(json!({
                    "key_tag": record.key_tag(),
                    "algorithm": record.algorithm(),
                    "digest_type": record.digest_type(),
                    "digest": hex_lower(record.digest()),
                }));
            }
        }
        let rotation = self
            .store
            .key_rotation(origin)
            .map_err(|error| Problem::from_admin(error, instance, request_id))?;
        let rotation_json = rotation.map_or(Value::Null, |rotation| {
            json!({
                "next_event_at": rotation.next_event_at,
                "keys": rotation
                    .keys
                    .iter()
                    .map(|key| {
                        json!({
                            "key_tag": key.key_tag,
                            "role": key.role,
                            "state": key.state,
                            "created_at": key.created_at,
                            "next_transition": key.next_transition,
                        })
                    })
                    .collect::<Vec<_>>(),
            })
        });
        Ok(HttpResponse::json(
            200,
            json!({
                "zone": origin.to_string(),
                "denial": zone.denial.as_str(),
                "keys": keys,
                "ds": ds,
                "rotation": rotation_json,
            }),
        ))
    }

    fn sign_zone(
        &self,
        request: &HttpRequest,
        origin: &Name,
        request_id: &str,
        instance: &str,
    ) -> Result<HttpResponse, Problem> {
        self.store
            .get_zone(origin)
            .map_err(|error| Problem::from_admin(error, instance, request_id))?;
        if prefers_async(request) {
            let job_id = self.jobs.create(
                "zone_sign",
                &zone_resource(origin),
                Some(origin.to_string()),
                false,
            );
            self.jobs.start(&job_id);
            let jobs = Arc::clone(&self.jobs);
            let store = Arc::clone(&self.store);
            let origin = origin.clone();
            let job = job_id.clone();
            let spawn = std::thread::Builder::new()
                .name("pulse-job-sign".to_owned())
                .spawn(move || {
                    let outcome = store.sign_zone(&origin).map_or_else(
                        |error| Err(admin_failure(error)),
                        |zone| Ok(zone_json(&zone)),
                    );
                    jobs.finish(&job, outcome);
                });
            if spawn.is_err() {
                self.jobs.finish(
                    &job_id,
                    Err(JobFailure::new(
                        "internal-error",
                        "cannot start background job",
                        true,
                    )),
                );
            }
            return Ok(self.accepted_job(&job_id, instance));
        }
        let zone = self
            .store
            .sign_zone(origin)
            .map_err(|error| Problem::from_admin(error, instance, request_id))?;
        let mut response = HttpResponse::json(200, zone_json(&zone));
        response.set_header("ETag", zone.etag);
        Ok(response)
    }

    fn create_zone(
        &self,
        request: &HttpRequest,
        principal: &Principal,
        request_id: &str,
        instance: &str,
    ) -> Result<HttpResponse, Problem> {
        let value = self.json_body(request, instance, request_id)?;
        let body: ZoneWriteBody = deserialize(value, instance, request_id)?;
        let origin_text = body.origin.ok_or_else(|| {
            validation(
                instance,
                request_id,
                "/origin",
                "required",
                "origin is required",
            )
        })?;
        let origin = Name::parse(origin_text.trim()).map_err(|_| {
            validation(
                instance,
                request_id,
                "/origin",
                "invalid-name",
                "origin must be a valid DNS name",
            )
        })?;
        if origin == Name::root() || origin.labels().any(|label| label == b"*") {
            return Err(validation(
                instance,
                request_id,
                "/origin",
                "invalid-origin",
                "zone origin must be a non-root name without wildcards",
            ));
        }
        if !principal.zone_allowed(&origin) {
            return Err(Problem::new(
                403,
                "forbidden",
                "The token does not allow this zone.",
                instance,
                request_id,
            ));
        }
        let kind = match body.kind.as_deref() {
            None => ZoneKind::Primary,
            Some(value) => ZoneKind::parse(value).ok_or_else(|| {
                validation(
                    instance,
                    request_id,
                    "/kind",
                    "invalid-kind",
                    "kind must be primary, secondary or forward",
                )
            })?,
        };
        let default_ttl = match body.default_ttl {
            None => Ttl::new(3600).map_err(|_| internal(instance, request_id))?,
            Some(value) => Ttl::new(value).map_err(|_| {
                validation(
                    instance,
                    request_id,
                    "/default_ttl",
                    "ttl-out-of-range",
                    "ttl must be in 0..=2147483647",
                )
            })?,
        };
        let denial = match body.denial.as_deref() {
            None => Denial::Nsec,
            Some(value) => Denial::parse(value).ok_or_else(|| {
                validation(
                    instance,
                    request_id,
                    "/denial",
                    "invalid-denial",
                    "denial must be nsec or nsec3",
                )
            })?,
        };
        let meta = ZoneMetaInput {
            kind,
            default_ttl,
            denial,
        };
        let zone = self
            .store
            .create_zone(&origin, &meta)
            .map_err(|error| Problem::from_admin(error, instance, request_id))?;
        let mut response = HttpResponse::json(201, zone_json(&zone));
        response.set_header("ETag", zone.etag.clone());
        response.set_header("Location", zone_resource(&origin));
        Ok(response)
    }

    fn get_serial(
        &self,
        origin: &Name,
        request_id: &str,
        instance: &str,
    ) -> Result<HttpResponse, Problem> {
        let state = self
            .store
            .get_serial(origin)
            .map_err(|error| Problem::from_admin(error, instance, request_id))?;
        let mut response = HttpResponse::json(
            200,
            json!({
                "zone": state.zone.to_string(),
                "serial": state.serial.as_u32(),
                "version": state.version,
                "updated_at": rfc3339(state.updated_at),
            }),
        );
        response.set_header("ETag", state.etag);
        Ok(response)
    }

    fn update_serial(
        &self,
        request: &HttpRequest,
        origin: &Name,
        request_id: &str,
        instance: &str,
    ) -> Result<HttpResponse, Problem> {
        let value = self.json_body(request, instance, request_id)?;
        let body: SerialBody = deserialize(value, instance, request_id)?;
        let mode = body.mode.ok_or_else(|| {
            validation(
                instance,
                request_id,
                "/mode",
                "required",
                "mode is required",
            )
        })?;
        let update = match mode.as_str() {
            "increment" => {
                if body.value.is_some() {
                    return Err(validation(
                        instance,
                        request_id,
                        "/value",
                        "unexpected-field",
                        "value is not allowed with mode=increment",
                    ));
                }
                SerialUpdate::Increment
            }
            "set" => SerialUpdate::Set(body.value.ok_or_else(|| {
                validation(
                    instance,
                    request_id,
                    "/value",
                    "required",
                    "value is required with mode=set",
                )
            })?),
            _ => {
                return Err(validation(
                    instance,
                    request_id,
                    "/mode",
                    "invalid-mode",
                    "mode must be increment or set",
                ));
            }
        };
        let preconditions = preconditions(request, instance, request_id)?;
        let result = self
            .store
            .update_serial(origin, update, &preconditions)
            .map_err(|error| Problem::from_admin(error, instance, request_id))?;
        let mut response = HttpResponse::json(
            200,
            json!({
                "zone": result.zone.to_string(),
                "old_serial": result.old_serial.as_u32(),
                "new_serial": result.new_serial.as_u32(),
                "commit_id": format!("c_{}", result.version),
                "version": result.version,
                "updated_at": rfc3339(result.updated_at),
            }),
        );
        response.set_header("ETag", result.etag);
        Ok(response)
    }

    fn list_transfers(
        &self,
        request: &HttpRequest,
        origin: &Name,
        principal: &Principal,
        request_id: &str,
        instance: &str,
    ) -> Result<HttpResponse, Problem> {
        let zone = self
            .store
            .get_zone(origin)
            .map_err(|error| Problem::from_admin(error, instance, request_id))?;
        let query = Query::parse(&request.query_string)
            .ok_or_else(|| bad_request("The query string is malformed.", instance, request_id))?;
        let limit = parse_limit(&query)
            .map_err(|detail| Problem::new(400, "bad-request", detail, instance, request_id))?;
        let state = match query.get("state") {
            Some(value) => Some(parse_job_state(value).ok_or_else(|| {
                Problem::new(
                    400,
                    "bad-request",
                    "Unknown job state.",
                    instance,
                    request_id,
                )
            })?),
            None => None,
        };
        if let Some(cursor) = query.get("cursor")
            && !valid_seq_cursor(cursor)
        {
            return Err(bad_request(
                "The pagination cursor is invalid.",
                instance,
                request_id,
            ));
        }
        let page = self.jobs.list(&JobQuery {
            limit,
            cursor: query.get("cursor").map(str::to_owned),
            state,
            kind: Some("zone_transfer".to_owned()),
            zone: Some(origin.to_string()),
        });
        let items: Vec<Value> = page.items.iter().map(job_json).collect();
        let _ = principal;
        Ok(HttpResponse::json(
            200,
            json!({
                "zone": zone.origin.to_string(),
                "kind": zone.kind.as_str(),
                "serial": zone.serial.as_u32(),
                "items": items,
                "history": page.items.iter().map(job_json).collect::<Vec<_>>(),
                "next_cursor": page.next_cursor,
                "has_more": page.has_more,
            }),
        ))
    }

    fn trigger_transfer(
        &self,
        request: &HttpRequest,
        origin: &Name,
        principal: &Principal,
        request_id: &str,
        instance: &str,
    ) -> Result<HttpResponse, Problem> {
        let zone = self
            .store
            .get_zone(origin)
            .map_err(|error| Problem::from_admin(error, instance, request_id))?;
        if zone.kind == ZoneKind::Forward {
            return Err(Problem::new(
                409,
                "zone-read-only",
                "Forward zones do not support transfers.",
                instance,
                request_id,
            ));
        }
        let value = self.json_body(request, instance, request_id)?;
        let body: TransferBody = deserialize(value, instance, request_id)?;
        let kind = body
            .kind
            .as_deref()
            .and_then(TransferKind::parse)
            .ok_or_else(|| {
                validation(
                    instance,
                    request_id,
                    "/kind",
                    "invalid-kind",
                    "kind must be axfr or ixfr",
                )
            })?;
        let transfer = TransferRequest {
            kind,
            peer: body.peer,
            tsig_key: body.tsig_key,
            from_serial: body.from_serial,
        };
        let _ = principal;
        if zone.kind == ZoneKind::Primary {
            let result = self
                .store
                .trigger_transfer(origin, &transfer)
                .map_err(|error| Problem::from_admin(error, instance, request_id))?;
            return Ok(HttpResponse::json(200, transfer_json(&result)));
        }
        let job_id = self.jobs.create(
            "zone_transfer",
            &zone_resource(origin),
            Some(origin.to_string()),
            true,
        );
        self.jobs.start(&job_id);
        let jobs = Arc::clone(&self.jobs);
        let store = Arc::clone(&self.store);
        let origin = origin.clone();
        let job = job_id.clone();
        let spawn = std::thread::Builder::new()
            .name("pulse-job-transfer".to_owned())
            .spawn(move || {
                let outcome = store.trigger_transfer(&origin, &transfer).map_or_else(
                    |error| Err(admin_failure(error)),
                    |result| Ok(transfer_json(&result)),
                );
                jobs.finish(&job, outcome);
            });
        if spawn.is_err() {
            self.jobs.finish(
                &job_id,
                Err(JobFailure::new(
                    "internal-error",
                    "cannot start background job",
                    true,
                )),
            );
        }
        Ok(self.accepted_job(&job_id, instance))
    }

    fn import_zone(
        &self,
        request: &HttpRequest,
        origin: &Name,
        request_id: &str,
        instance: &str,
    ) -> Result<HttpResponse, Problem> {
        let zone = self
            .store
            .get_zone(origin)
            .map_err(|error| Problem::from_admin(error, instance, request_id))?;
        if zone.kind != ZoneKind::Primary {
            return Err(Problem::new(
                409,
                "zone-read-only",
                "Only primary zones can be imported.",
                instance,
                request_id,
            ));
        }
        let content_type = request.header("content-type").unwrap_or("");
        let media_type = content_type.split(';').next().unwrap_or("").trim();
        if !media_type.eq_ignore_ascii_case("text/plain")
            && !media_type.eq_ignore_ascii_case("text/dns")
        {
            return Err(Problem::new(
                415,
                "unsupported-media-type",
                "Content-Type must be text/plain.",
                instance,
                request_id,
            ));
        }
        let limit = MAX_IMPORT_BYTES;
        if request.body.len() > limit {
            return Err(Problem::new(
                413,
                "payload-too-large",
                "Import body exceeds the configured limit.",
                instance,
                request_id,
            ));
        }
        if request.body.is_empty() {
            return Err(validation(
                instance,
                request_id,
                "/body",
                "required",
                "zone text is required",
            ));
        }
        let text = std::str::from_utf8(&request.body)
            .map_err(|_| bad_request("Import body must be valid UTF-8.", instance, request_id))?;
        let query = Query::parse(&request.query_string)
            .ok_or_else(|| bad_request("The query string is malformed.", instance, request_id))?;
        let mode = match query.get("mode") {
            None => ImportMode::Replace,
            Some(value) => ImportMode::parse(value).ok_or_else(|| {
                Problem::new(
                    400,
                    "bad-request",
                    "mode must be replace, merge or check.",
                    instance,
                    request_id,
                )
            })?,
        };
        let job_id = self.jobs.create(
            "zone_import",
            &zone_resource(origin),
            Some(origin.to_string()),
            true,
        );
        self.jobs.start(&job_id);
        let jobs = Arc::clone(&self.jobs);
        let store = Arc::clone(&self.store);
        let origin = origin.clone();
        let job = job_id.clone();
        let text = text.to_owned();
        let spawn = std::thread::Builder::new()
            .name("pulse-job-import".to_owned())
            .spawn(move || {
                let outcome = store.import_zone(&origin, &text, mode).map_or_else(
                    |error| Err(admin_failure(error)),
                    |report| Ok(import_json(&report)),
                );
                jobs.finish(&job, outcome);
            });
        if spawn.is_err() {
            self.jobs.finish(
                &job_id,
                Err(JobFailure::new(
                    "internal-error",
                    "cannot start background job",
                    true,
                )),
            );
        }
        Ok(self.accepted_job(&job_id, instance))
    }

    fn get_keys_status(
        &self,
        origin: &Name,
        request_id: &str,
        instance: &str,
    ) -> Result<HttpResponse, Problem> {
        let zone = self
            .store
            .get_zone(origin)
            .map_err(|error| Problem::from_admin(error, instance, request_id))?;
        let rotation = self
            .store
            .key_rotation(origin)
            .map_err(|error| Problem::from_admin(error, instance, request_id))?;
        let dnskeys = self.store.get_rrset(origin, origin, Rtype::DNSKEY).ok();
        let mut ksk = 0_u32;
        let mut zsk = 0_u32;
        if let Some(rrset) = &dnskeys {
            for rdata in &rrset.rdata {
                if let Rdata::Dnskey(key) = rdata {
                    if key.flags() & DNSKEY_FLAG_SEP != 0 {
                        ksk = ksk.saturating_add(1);
                    } else {
                        zsk = zsk.saturating_add(1);
                    }
                }
            }
        }
        let rotation_json = rotation.as_ref().map_or(Value::Null, rotation_json);
        Ok(HttpResponse::json(
            200,
            json!({
                "zone": zone.origin.to_string(),
                "signed": dnskeys.is_some(),
                "denial": zone.denial.as_str(),
                "keys": { "ksk": ksk, "zsk": zsk, "csk": 0 },
                "rotation": rotation_json,
                "next_event_at": rotation.as_ref().and_then(|rotation| rotation.next_event_at),
                "next_event": rotation
                    .as_ref()
                    .and_then(|rotation| rotation.next_event_at)
                    .map(|seconds| rfc3339(unix_time(seconds))),
                "signature_valid_until": Value::Null,
                "last_signed_at": Value::Null,
                "issues": [],
            }),
        ))
    }

    fn rollover_keys(
        &self,
        request: &HttpRequest,
        origin: &Name,
        request_id: &str,
        instance: &str,
    ) -> Result<HttpResponse, Problem> {
        self.store
            .get_zone(origin)
            .map_err(|error| Problem::from_admin(error, instance, request_id))?;
        let value = self.json_body(request, instance, request_id)?;
        let body: RolloverBody = deserialize(value, instance, request_id)?;
        let role = body.role.ok_or_else(|| {
            validation(
                instance,
                request_id,
                "/role",
                "required",
                "role is required",
            )
        })?;
        if !matches!(role.as_str(), "ksk" | "zsk") {
            return Err(validation(
                instance,
                request_id,
                "/role",
                "invalid-role",
                "role must be ksk or zsk",
            ));
        }
        let scheme = body.scheme.unwrap_or_else(|| "pre_publish".to_owned());
        if !matches!(scheme.as_str(), "pre_publish" | "double_sign") {
            return Err(validation(
                instance,
                request_id,
                "/scheme",
                "invalid-scheme",
                "scheme must be pre_publish or double_sign",
            ));
        }
        let overlap = match body.overlap.as_ref() {
            None => 7 * 86_400,
            Some(value) => duration_from_value(value).ok_or_else(|| {
                validation(
                    instance,
                    request_id,
                    "/overlap",
                    "invalid-duration",
                    "overlap must be seconds or a duration like 7d",
                )
            })?,
        };
        let retire_after = match body.retire_after.as_ref() {
            None => None,
            Some(value) => Some(duration_from_value(value).ok_or_else(|| {
                validation(
                    instance,
                    request_id,
                    "/retire_after",
                    "invalid-duration",
                    "retire_after must be seconds or a duration like 30d",
                )
            })?),
        };
        let rollover = RolloverRequest {
            role,
            scheme,
            overlap,
            retire_after,
        };
        let rotation = self
            .store
            .rollover_keys(origin, &rollover)
            .map_err(|error| Problem::from_admin(error, instance, request_id))?;
        let job_id = self.jobs.create(
            "key_rollover",
            &zone_resource(origin),
            Some(origin.to_string()),
            false,
        );
        self.jobs.start(&job_id);
        self.jobs.finish(&job_id, Ok(rotation_json(&rotation)));
        Ok(self.accepted_job(&job_id, instance))
    }

    fn list_jobs(
        &self,
        request: &HttpRequest,
        principal: &Principal,
        request_id: &str,
        instance: &str,
    ) -> Result<HttpResponse, Problem> {
        let query = Query::parse(&request.query_string)
            .ok_or_else(|| bad_request("The query string is malformed.", instance, request_id))?;
        let limit = parse_limit(&query)
            .map_err(|detail| Problem::new(400, "bad-request", detail, instance, request_id))?;
        let state = match query.get("state") {
            Some(value) => Some(parse_job_state(value).ok_or_else(|| {
                Problem::new(
                    400,
                    "bad-request",
                    "Unknown job state.",
                    instance,
                    request_id,
                )
            })?),
            None => None,
        };
        if let Some(cursor) = query.get("cursor")
            && !valid_seq_cursor(cursor)
        {
            return Err(bad_request(
                "The pagination cursor is invalid.",
                instance,
                request_id,
            ));
        }
        let page = self.jobs.list(&JobQuery {
            limit,
            cursor: query.get("cursor").map(str::to_owned),
            state,
            kind: query.get("kind").map(str::to_owned),
            zone: None,
        });
        let items: Vec<Value> = page
            .items
            .iter()
            .filter(|job| job_visible(job, principal))
            .map(job_json)
            .collect();
        Ok(HttpResponse::json(
            200,
            json!({
                "items": items,
                "next_cursor": page.next_cursor,
                "has_more": page.has_more,
            }),
        ))
    }

    fn get_job(
        &self,
        job_id: &str,
        principal: &Principal,
        request_id: &str,
        instance: &str,
    ) -> Result<HttpResponse, Problem> {
        let Some(job) = self.jobs.get(job_id) else {
            return Err(job_not_found(instance, request_id));
        };
        if !job_visible(&job, principal) {
            return Err(job_not_found(instance, request_id));
        }
        Ok(HttpResponse::json(200, job_json(&job)))
    }

    fn cancel_job(
        &self,
        job_id: &str,
        principal: &Principal,
        request_id: &str,
        instance: &str,
        transfer_only: bool,
    ) -> Result<HttpResponse, Problem> {
        let Some(job) = self.jobs.get(job_id) else {
            return Err(job_not_found(instance, request_id));
        };
        if !job_visible(&job, principal) || (transfer_only && job.kind != "zone_transfer") {
            return Err(job_not_found(instance, request_id));
        }
        match self.jobs.cancel(job_id) {
            CancelOutcome::Accepted(job) => {
                let mut response = HttpResponse::json(202, job_json(&job));
                response.set_header("Location", format!("/api/v1/jobs/{}", job.id));
                response.set_header("Retry-After", "1");
                Ok(response)
            }
            CancelOutcome::Terminal(job) => Ok(HttpResponse::json(200, job_json(&job))),
            CancelOutcome::NotFound => Err(job_not_found(instance, request_id)),
        }
    }

    fn list_audit(
        &self,
        request: &HttpRequest,
        request_id: &str,
        instance: &str,
    ) -> Result<HttpResponse, Problem> {
        let query = Query::parse(&request.query_string)
            .ok_or_else(|| bad_request("The query string is malformed.", instance, request_id))?;
        let limit = parse_limit(&query)
            .map_err(|detail| Problem::new(400, "bad-request", detail, instance, request_id))?;
        if let Some(cursor) = query.get("cursor")
            && !valid_seq_cursor(cursor)
        {
            return Err(bad_request(
                "The pagination cursor is invalid.",
                instance,
                request_id,
            ));
        }
        let page = self.audit_log.list(&AuditQuery {
            limit,
            cursor: query.get("cursor").map(str::to_owned),
            principal: query.get("principal").map(str::to_owned),
            action: query.get("action").map(str::to_owned),
            result: query.get("result").map(str::to_owned),
        });
        let items: Vec<Value> = page
            .items
            .iter()
            .map(|entry| {
                json!({
                    "at": rfc3339(entry.at),
                    "principal": entry.principal,
                    "action": entry.action,
                    "resource": entry.resource,
                    "result": entry.result,
                    "reason": entry.reason,
                    "request_id": entry.request_id,
                })
            })
            .collect();
        Ok(HttpResponse::json(
            200,
            json!({
                "items": items,
                "next_cursor": page.next_cursor,
                "has_more": page.has_more,
            }),
        ))
    }

    fn accepted_job(&self, job_id: &str, instance: &str) -> HttpResponse {
        let record = self.jobs.get(job_id);
        let mut response = record.as_ref().map_or_else(
            || {
                HttpResponse::json(
                    202,
                    json!({ "job_id": job_id, "state": "pending", "resource": instance }),
                )
            },
            |job| HttpResponse::json(202, job_json(job)),
        );
        response.set_header("Location", format!("/api/v1/jobs/{job_id}"));
        response.set_header("Retry-After", "1");
        response
    }

    fn list_zones(
        &self,
        request: &HttpRequest,
        principal: &Principal,
        request_id: &str,
        instance: &str,
    ) -> Result<HttpResponse, Problem> {
        let query = Query::parse(&request.query_string)
            .ok_or_else(|| bad_request("The query string is malformed.", instance, request_id))?;
        let limit = parse_limit(&query)
            .map_err(|detail| Problem::new(400, "bad-request", detail, instance, request_id))?;
        let kind = match query.get("kind") {
            Some(value) => Some(ZoneKind::parse(value).ok_or_else(|| {
                Problem::new(
                    400,
                    "bad-request",
                    "Unknown zone kind.",
                    instance,
                    request_id,
                )
            })?),
            None => None,
        };
        let list = ListZones {
            limit,
            cursor: query.get("cursor").map(str::to_owned),
            kind,
        };
        let allow_all = AllowAll;
        let scope_ref: &dyn ZoneAllow = match &principal.zone_scope {
            Some(scope) => scope,
            None => &allow_all,
        };
        let page = self
            .store
            .list_zones(&list, scope_ref)
            .map_err(|error| Problem::from_admin(error, instance, request_id))?;
        let items: Vec<Value> = page.items.iter().map(zone_json).collect();
        Ok(HttpResponse::json(
            200,
            json!({
                "items": items,
                "next_cursor": page.next_cursor,
                "has_more": page.has_more,
            }),
        ))
    }

    fn get_zone(
        &self,
        request: &HttpRequest,
        origin: &Name,
        request_id: &str,
        instance: &str,
    ) -> Result<HttpResponse, Problem> {
        let zone = self
            .store
            .get_zone(origin)
            .map_err(|error| Problem::from_admin(error, instance, request_id))?;
        if let Some(header) = request.header("if-none-match") {
            if header_matches(&zone.etag, header) {
                let mut response = HttpResponse::empty(304);
                response.set_header("ETag", zone.etag.clone());
                return Ok(response);
            }
        }
        let mut response = HttpResponse::json(200, zone_json(&zone));
        response.set_header("ETag", zone.etag.clone());
        Ok(response)
    }

    fn put_zone(
        &self,
        request: &HttpRequest,
        origin: &Name,
        request_id: &str,
        instance: &str,
        mutation: &MutationContext,
    ) -> Result<HttpResponse, Problem> {
        let value = self.json_body(request, instance, request_id)?;
        let body: ZoneWriteBody = deserialize(value, instance, request_id)?;
        if let Some(text) = &body.origin {
            let provided = Name::parse(text).map_err(|_| {
                validation(
                    instance,
                    request_id,
                    "/origin",
                    "invalid-name",
                    "origin must be a valid DNS name",
                )
            })?;
            if &provided != origin {
                return Err(validation(
                    instance,
                    request_id,
                    "/origin",
                    "origin-mismatch",
                    "body origin does not match the path",
                ));
            }
        }
        let kind = match body.kind.as_deref() {
            None => ZoneKind::Primary,
            Some(value) => ZoneKind::parse(value).ok_or_else(|| {
                validation(
                    instance,
                    request_id,
                    "/kind",
                    "invalid-kind",
                    "kind must be primary, secondary or forward",
                )
            })?,
        };
        let default_ttl = match body.default_ttl {
            None => Ttl::new(3600).map_err(|_| internal(instance, request_id))?,
            Some(value) => Ttl::new(value).map_err(|_| {
                validation(
                    instance,
                    request_id,
                    "/default_ttl",
                    "ttl-out-of-range",
                    "ttl must be in 0..=2147483647",
                )
            })?,
        };
        let denial = match body.denial.as_deref() {
            None => Denial::Nsec,
            Some(value) => Denial::parse(value).ok_or_else(|| {
                validation(
                    instance,
                    request_id,
                    "/denial",
                    "invalid-denial",
                    "denial must be nsec or nsec3",
                )
            })?,
        };
        let meta = ZoneMetaInput {
            kind,
            default_ttl,
            denial,
        };
        let preconditions = preconditions(request, instance, request_id)?;
        let operation = JournalOp::PutZone {
            origin: origin.to_string(),
            kind: kind.as_str().to_owned(),
            default_ttl: default_ttl.as_u32(),
            denial: denial.as_str().to_owned(),
        };
        self.journaled(
            mutation,
            request,
            instance,
            request_id,
            &preconditions,
            operation,
            |store| {
                let outcome = store
                    .put_zone(origin, &meta, &preconditions)
                    .map_err(|error| Problem::from_admin(error, instance, request_id))?;
                let created = outcome.is_created();
                let zone = outcome.value();
                let mut response =
                    HttpResponse::json(if created { 201 } else { 200 }, zone_json(zone));
                response.set_header("ETag", zone.etag.clone());
                if created {
                    response.set_header(
                        "Location",
                        format!("/api/v1/zones/{}", encode_segment(&origin.to_string())),
                    );
                }
                Ok((response, zone.version))
            },
            |store| {
                let zone = store
                    .get_zone(origin)
                    .map_err(|error| Problem::from_admin(error, instance, request_id))?;
                let mut response = HttpResponse::json(200, zone_json(&zone));
                response.set_header("ETag", zone.etag.clone());
                Ok(response)
            },
        )
    }

    fn delete_zone(
        &self,
        request: &HttpRequest,
        origin: &Name,
        request_id: &str,
        instance: &str,
        mutation: &MutationContext,
    ) -> Result<HttpResponse, Problem> {
        let zone = self
            .store
            .get_zone(origin)
            .map_err(|error| Problem::from_admin(error, instance, request_id))?;
        if let Some(value) = request.header("if-match") {
            if value.trim() != "*" && !header_matches(&zone.etag, value) {
                return Err(Problem::from_admin(
                    AdminError::PreconditionFailed {
                        current_etag: Some(zone.etag.clone()),
                        current_version: Some(zone.version),
                    },
                    instance,
                    request_id,
                ));
            }
        }
        if zone.kind == ZoneKind::Primary {
            let query = Query::parse(&request.query_string).ok_or_else(|| {
                bad_request("The query string is malformed.", instance, request_id)
            })?;
            let confirm = query
                .get("confirm_origin")
                .map(str::to_owned)
                .or_else(|| confirm_origin_from_body(&request.body));
            match confirm {
                Some(value) if Name::parse(value.trim()).as_ref() == Ok(origin) => {}
                Some(_) => {
                    return Err(validation(
                        instance,
                        request_id,
                        "/confirm_origin",
                        "origin-mismatch",
                        "confirm_origin does not match the zone origin",
                    ));
                }
                None => {
                    return Err(validation(
                        instance,
                        request_id,
                        "/confirm_origin",
                        "required",
                        "deleting a primary zone requires confirm_origin",
                    ));
                }
            }
        }
        let preconditions = preconditions(request, instance, request_id)?;
        let operation = JournalOp::DeleteZone {
            origin: origin.to_string(),
        };
        self.journaled(
            mutation,
            request,
            instance,
            request_id,
            &preconditions,
            operation,
            |store| {
                store
                    .delete_zone(origin, &preconditions)
                    .map_err(|error| Problem::from_admin(error, instance, request_id))?;
                Ok((HttpResponse::empty(204), 0))
            },
            |_store| Ok(HttpResponse::empty(204)),
        )
    }

    fn get_settings(
        &self,
        origin: &Name,
        request_id: &str,
        instance: &str,
    ) -> Result<HttpResponse, Problem> {
        let settings = self
            .store
            .get_settings(origin)
            .map_err(|error| Problem::from_admin(error, instance, request_id))?;
        let mut response = HttpResponse::json(200, settings_json(&settings));
        response.set_header("ETag", settings.etag.clone());
        Ok(response)
    }

    fn patch_settings(
        &self,
        request: &HttpRequest,
        origin: &Name,
        request_id: &str,
        instance: &str,
        mutation: &MutationContext,
    ) -> Result<HttpResponse, Problem> {
        let value = self.json_body(request, instance, request_id)?;
        let body: SettingsPatchBody = deserialize(value, instance, request_id)?;
        if body.default_ttl.is_none() && body.denial.is_none() {
            return Err(validation(
                instance,
                request_id,
                "/",
                "empty-patch",
                "at least one setting must be provided",
            ));
        }
        let default_ttl = match body.default_ttl {
            Some(value) => Some(Ttl::new(value).map_err(|_| {
                validation(
                    instance,
                    request_id,
                    "/default_ttl",
                    "ttl-out-of-range",
                    "ttl must be in 0..=2147483647",
                )
            })?),
            None => None,
        };
        let denial = match body.denial.as_deref() {
            Some(value) => Some(Denial::parse(value).ok_or_else(|| {
                validation(
                    instance,
                    request_id,
                    "/denial",
                    "invalid-denial",
                    "denial must be nsec or nsec3",
                )
            })?),
            None => None,
        };
        let patch = ZoneSettingsPatch {
            default_ttl,
            denial,
        };
        let preconditions = preconditions(request, instance, request_id)?;
        let operation = JournalOp::PatchSettings {
            origin: origin.to_string(),
            default_ttl: default_ttl.map(Ttl::as_u32),
            denial: denial.map(Denial::as_str).map(str::to_owned),
        };
        self.journaled(
            mutation,
            request,
            instance,
            request_id,
            &preconditions,
            operation,
            |store| {
                let settings = store
                    .patch_settings(origin, &patch, &preconditions)
                    .map_err(|error| Problem::from_admin(error, instance, request_id))?;
                let mut response = HttpResponse::json(200, settings_json(&settings));
                response.set_header("ETag", settings.etag.clone());
                Ok((response, settings.version))
            },
            |store| {
                let settings = store
                    .get_settings(origin)
                    .map_err(|error| Problem::from_admin(error, instance, request_id))?;
                let mut response = HttpResponse::json(200, settings_json(&settings));
                response.set_header("ETag", settings.etag.clone());
                Ok(response)
            },
        )
    }

    fn get_rrset(
        &self,
        request: &HttpRequest,
        origin: &Name,
        owner: &Name,
        rr_type: Rtype,
        request_id: &str,
        instance: &str,
    ) -> Result<HttpResponse, Problem> {
        let rrset = self
            .store
            .get_rrset(origin, owner, rr_type)
            .map_err(|error| Problem::from_admin(error, instance, request_id))?;
        if let Some(header) = request.header("if-none-match") {
            if header_matches(&rrset.etag, header) {
                let mut response = HttpResponse::empty(304);
                response.set_header("ETag", rrset.etag.clone());
                return Ok(response);
            }
        }
        let mut response = HttpResponse::json(200, rrset_json(&rrset));
        response.set_header("ETag", rrset.etag.clone());
        Ok(response)
    }

    #[allow(clippy::too_many_arguments)]
    fn put_rrset(
        &self,
        request: &HttpRequest,
        origin: &Name,
        owner: &Name,
        rr_type: Rtype,
        request_id: &str,
        instance: &str,
        mutation: &MutationContext,
    ) -> Result<HttpResponse, Problem> {
        let value = self.json_body(request, instance, request_id)?;
        let body: RrsetWriteBody = deserialize(value, instance, request_id)?;
        validate_class(body.class.as_deref(), instance, request_id)?;
        let ttl_value = body.ttl.ok_or_else(|| {
            validation(instance, request_id, "/ttl", "required", "ttl is required")
        })?;
        let ttl = Ttl::new(ttl_value).map_err(|_| {
            validation(
                instance,
                request_id,
                "/ttl",
                "ttl-out-of-range",
                "ttl must be in 0..=2147483647",
            )
        })?;
        let records = body.records.ok_or_else(|| {
            validation(
                instance,
                request_id,
                "/records",
                "required",
                "records is required",
            )
        })?;
        let rdata = parse_records(&records, rr_type, instance, request_id)?;
        let input = RrsetInput { ttl, rdata };
        let preconditions = preconditions(request, instance, request_id)?;
        let operation = JournalOp::PutRrset {
            origin: origin.to_string(),
            owner: owner.to_string(),
            rr_type: rr_type.to_string(),
            ttl: ttl.as_u32(),
            records,
        };
        self.journaled(
            mutation,
            request,
            instance,
            request_id,
            &preconditions,
            operation,
            |store| {
                let outcome = store
                    .put_rrset(origin, owner, rr_type, &input, &preconditions)
                    .map_err(|error| Problem::from_admin(error, instance, request_id))?;
                let created = outcome.is_created();
                let rrset = outcome.value();
                let mut response =
                    HttpResponse::json(if created { 201 } else { 200 }, rrset_json(rrset));
                response.set_header("ETag", rrset.etag.clone());
                if created {
                    response.set_header(
                        "Location",
                        format!(
                            "/api/v1/zones/{}/records/{}/{}",
                            encode_segment(&origin.to_string()),
                            encode_segment(&owner.to_string()),
                            rr_type
                        ),
                    );
                }
                let version = store
                    .get_zone(origin)
                    .map_err(|error| Problem::from_admin(error, instance, request_id))?
                    .version;
                Ok((response, version))
            },
            |store| {
                let rrset = store
                    .get_rrset(origin, owner, rr_type)
                    .map_err(|error| Problem::from_admin(error, instance, request_id))?;
                let mut response = HttpResponse::json(200, rrset_json(&rrset));
                response.set_header("ETag", rrset.etag.clone());
                Ok(response)
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn patch_rrset(
        &self,
        request: &HttpRequest,
        origin: &Name,
        owner: &Name,
        rr_type: Rtype,
        request_id: &str,
        instance: &str,
        mutation: &MutationContext,
    ) -> Result<HttpResponse, Problem> {
        let value = self.json_body(request, instance, request_id)?;
        let body: RrsetPatchBody = deserialize(value, instance, request_id)?;
        let add_present = body.add.as_ref().is_some_and(|records| !records.is_empty());
        let remove_present = body
            .remove
            .as_ref()
            .is_some_and(|records| !records.is_empty());
        if body.ttl.is_none() && !add_present && !remove_present {
            return Err(validation(
                instance,
                request_id,
                "/",
                "empty-patch",
                "at least one of ttl, add, remove must be provided",
            ));
        }
        let ttl = match body.ttl {
            Some(value) => Some(Ttl::new(value).map_err(|_| {
                validation(
                    instance,
                    request_id,
                    "/ttl",
                    "ttl-out-of-range",
                    "ttl must be in 0..=2147483647",
                )
            })?),
            None => None,
        };
        let add_text = match &body.add {
            Some(records) if !records.is_empty() => records.clone(),
            _ => Vec::new(),
        };
        let remove_text = match &body.remove {
            Some(records) if !records.is_empty() => records.clone(),
            _ => Vec::new(),
        };
        let add = if add_text.is_empty() {
            Vec::new()
        } else {
            parse_records(&add_text, rr_type, instance, request_id)?
        };
        let remove = if remove_text.is_empty() {
            Vec::new()
        } else {
            parse_records(&remove_text, rr_type, instance, request_id)?
        };
        let patch = RrsetPatch { ttl, add, remove };
        let preconditions = preconditions(request, instance, request_id)?;
        let operation = JournalOp::PatchRrset {
            origin: origin.to_string(),
            owner: owner.to_string(),
            rr_type: rr_type.to_string(),
            ttl: ttl.map(Ttl::as_u32),
            add: add_text,
            remove: remove_text,
        };
        self.journaled(
            mutation,
            request,
            instance,
            request_id,
            &preconditions,
            operation,
            |store| {
                let outcome = store
                    .patch_rrset(origin, owner, rr_type, &patch, &preconditions)
                    .map_err(|error| Problem::from_admin(error, instance, request_id))?;
                let version = store
                    .get_zone(origin)
                    .map_err(|error| Problem::from_admin(error, instance, request_id))?
                    .version;
                let response = match outcome {
                    RrsetPatchOutcome::Updated {
                        rrset,
                        added,
                        removed,
                    } => {
                        let mut response = HttpResponse::json(
                            200,
                            json!({
                                "rrset": rrset_json(&rrset),
                                "added": added,
                                "removed": removed,
                            }),
                        );
                        response.set_header("ETag", rrset.etag.clone());
                        response
                    }
                    RrsetPatchOutcome::Deleted { removed } => {
                        HttpResponse::json(200, json!({ "deleted": true, "removed": removed }))
                    }
                };
                Ok((response, version))
            },
            |store| match store.get_rrset(origin, owner, rr_type) {
                Ok(rrset) => {
                    let mut response = HttpResponse::json(200, rrset_json(&rrset));
                    response.set_header("ETag", rrset.etag.clone());
                    Ok(response)
                }
                Err(AdminError::NotFound(NotFound::Rrset)) => Ok(HttpResponse::json(
                    200,
                    json!({ "deleted": true, "removed": 0 }),
                )),
                Err(error) => Err(Problem::from_admin(error, instance, request_id)),
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn delete_rrset(
        &self,
        request: &HttpRequest,
        origin: &Name,
        owner: &Name,
        rr_type: Rtype,
        request_id: &str,
        instance: &str,
        mutation: &MutationContext,
    ) -> Result<HttpResponse, Problem> {
        let preconditions = preconditions(request, instance, request_id)?;
        let operation = JournalOp::DeleteRrset {
            origin: origin.to_string(),
            owner: owner.to_string(),
            rr_type: rr_type.to_string(),
        };
        self.journaled(
            mutation,
            request,
            instance,
            request_id,
            &preconditions,
            operation,
            |store| {
                store
                    .delete_rrset(origin, owner, rr_type, &preconditions)
                    .map_err(|error| Problem::from_admin(error, instance, request_id))?;
                let version = store
                    .get_zone(origin)
                    .map_err(|error| Problem::from_admin(error, instance, request_id))?
                    .version;
                Ok((HttpResponse::empty(204), version))
            },
            |_store| Ok(HttpResponse::empty(204)),
        )
    }

    fn list_rrsets(
        &self,
        request: &HttpRequest,
        origin: &Name,
        request_id: &str,
        instance: &str,
    ) -> Result<HttpResponse, Problem> {
        let query = Query::parse(&request.query_string)
            .ok_or_else(|| bad_request("The query string is malformed.", instance, request_id))?;
        let limit = parse_limit(&query)
            .map_err(|detail| Problem::new(400, "bad-request", detail, instance, request_id))?;
        let owner = match query.get("owner") {
            Some("@") => Some(origin.clone()),
            Some(value) => Some(
                Name::parse(value)
                    .map_err(|_| bad_request("Invalid owner filter.", instance, request_id))?,
            ),
            None => None,
        };
        let owner_suffix =
            match query.get("owner_suffix") {
                Some(value) => Some(Name::parse(value).map_err(|_| {
                    bad_request("Invalid owner_suffix filter.", instance, request_id)
                })?),
                None => None,
            };
        let mut types = Vec::new();
        for value in query.get_all("type") {
            for item in value.split(',') {
                if item.is_empty() {
                    continue;
                }
                let rr_type = parse_rtype(item)
                    .ok_or_else(|| bad_request("Invalid type filter.", instance, request_id))?;
                types.push(rr_type);
            }
        }
        let list = ListRrsets {
            limit,
            cursor: query.get("cursor").map(str::to_owned),
            owner,
            owner_suffix,
            types,
        };
        let page = self
            .store
            .list_rrsets(origin, &list)
            .map_err(|error| Problem::from_admin(error, instance, request_id))?;
        let items: Vec<Value> = page.items.iter().map(rrset_json).collect();
        Ok(HttpResponse::json(
            200,
            json!({
                "items": items,
                "next_cursor": page.next_cursor,
                "has_more": page.has_more,
            }),
        ))
    }

    fn json_body(
        &self,
        request: &HttpRequest,
        instance: &str,
        request_id: &str,
    ) -> Result<Value, Problem> {
        if request.body.len() > self.max_body_bytes {
            return Err(Problem::new(
                413,
                "payload-too-large",
                "Request body exceeds the configured limit.",
                instance,
                request_id,
            ));
        }
        if request.body.is_empty() {
            return Err(bad_request(
                "A JSON request body is required.",
                instance,
                request_id,
            ));
        }
        let content_type = request.header("content-type").unwrap_or("");
        let media_type = content_type.split(';').next().unwrap_or("").trim();
        if !media_type.eq_ignore_ascii_case("application/json") {
            return Err(Problem::new(
                415,
                "unsupported-media-type",
                "Content-Type must be application/json.",
                instance,
                request_id,
            ));
        }
        let value: Value = serde_json::from_slice(&request.body).map_err(|_| {
            bad_request("The request body is not valid JSON.", instance, request_id)
        })?;
        if !value.is_object() {
            return Err(bad_request(
                "The JSON request body must be an object.",
                instance,
                request_id,
            ));
        }
        Ok(value)
    }

    fn request_id(&self, request: &HttpRequest) -> String {
        if let Some(value) = request.header("x-request-id") {
            if valid_request_id(value) {
                return value.to_owned();
            }
        }
        let counter = self.request_counter.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let mut hasher = Sha256::new();
        hasher.update(nanos.to_le_bytes());
        hasher.update(counter.to_le_bytes());
        hasher.update(std::process::id().to_le_bytes());
        let digest = hasher.finalize();
        format!("req_{}", hex_lower(digest.get(..13).unwrap_or(&digest)))
    }

    #[allow(clippy::too_many_arguments)]
    fn audit(
        &self,
        request_id: &str,
        token_id: &str,
        action: &str,
        target: &str,
        result: &str,
        code: Option<&str>,
        peer: SocketAddr,
    ) {
        let timestamp = rfc3339(SystemTime::now());
        let code = code.unwrap_or("-");
        self.audit_log.record(
            token_id,
            action,
            target,
            result,
            (code != "-").then_some(code),
            request_id,
        );
        eprintln!(
            "audit ts={} request_id={} token={} action={} target={} result={} code={} peer={}",
            audit_value(&timestamp),
            audit_value(request_id),
            audit_value(token_id),
            audit_value(action),
            audit_value(target),
            audit_value(result),
            audit_value(code),
            peer.ip()
        );
    }
}

fn zone_json(zone: &ZoneView) -> Value {
    json!({
        "id": zone.id.as_u32(),
        "origin": zone.origin.to_string(),
        "kind": zone.kind.as_str(),
        "serial": zone.serial.as_u32(),
        "version": zone.version,
        "default_ttl": zone.default_ttl.as_u32(),
        "denial": zone.denial.as_str(),
        "rrsets": zone.rrset_count,
        "dnssec": Value::Null,
        "transfer": Value::Null,
        "forward": Value::Null,
        "created_at": rfc3339(zone.created_at),
        "updated_at": rfc3339(zone.updated_at),
    })
}

fn rrset_json(rrset: &crate::port::RrsetView) -> Value {
    json!({
        "zone": rrset.zone.to_string(),
        "owner": rrset.owner.to_string(),
        "type": rrset.rr_type.to_string(),
        "class": "IN",
        "ttl": rrset.ttl.as_u32(),
        "records": rrset.rdata.iter().map(format_rdata).collect::<Vec<_>>(),
        "etag": rrset.etag,
        "updated_at": rfc3339(rrset.updated_at),
    })
}

fn settings_json(settings: &crate::port::ZoneSettingsView) -> Value {
    json!({
        "zone": settings.zone.to_string(),
        "default_ttl": settings.settings.default_ttl.as_u32(),
        "denial": settings.settings.denial.as_str(),
        "version": settings.version,
        "updated_at": rfc3339(settings.updated_at),
    })
}

fn deserialize<T: DeserializeOwned>(
    value: Value,
    instance: &str,
    request_id: &str,
) -> Result<T, Problem> {
    serde_json::from_value(value).map_err(|_| {
        validation(
            instance,
            request_id,
            "/",
            "validation-failed",
            "The request body has invalid or missing fields.",
        )
    })
}

fn parse_records(
    records: &[String],
    rr_type: Rtype,
    instance: &str,
    request_id: &str,
) -> Result<Vec<Rdata>, Problem> {
    if records.is_empty() {
        return Err(validation(
            instance,
            request_id,
            "/records",
            "empty-rrset",
            "records must contain at least one entry",
        ));
    }
    if records.len() > 4096 {
        return Err(validation(
            instance,
            request_id,
            "/records",
            "too-many-records",
            "too many records in rrset",
        ));
    }
    records
        .iter()
        .enumerate()
        .map(|(index, text)| {
            parse_rdata(rr_type, text).map_err(|error| {
                validation(
                    instance,
                    request_id,
                    &format!("/records/{index}"),
                    error.code(),
                    &error.to_string(),
                )
            })
        })
        .collect()
}

fn validate_class(class: Option<&str>, instance: &str, request_id: &str) -> Result<(), Problem> {
    match class {
        None => Ok(()),
        Some(value) if value.eq_ignore_ascii_case("IN") => Ok(()),
        Some(_) => Err(validation(
            instance,
            request_id,
            "/class",
            "unsupported-class",
            "only class IN is supported",
        )),
    }
}

fn preconditions(
    request: &HttpRequest,
    instance: &str,
    request_id: &str,
) -> Result<Preconditions, Problem> {
    let if_match = match request.header("if-match") {
        Some(value) => Some(parse_condition(value, instance, request_id)?),
        None => None,
    };
    let if_none_match = match request.header("if-none-match") {
        Some(value) => Some(parse_condition(value, instance, request_id)?),
        None => None,
    };
    Ok(Preconditions {
        if_match,
        if_none_match,
    })
}

fn parse_condition(value: &str, instance: &str, request_id: &str) -> Result<Precondition, Problem> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(bad_request(
            "Empty conditional header.",
            instance,
            request_id,
        ));
    }
    if trimmed.split(',').any(|part| part.trim() == "*") {
        return Ok(Precondition::Any);
    }
    let tags: Vec<String> = trimmed
        .split(',')
        .filter_map(normalize_tag)
        .filter(|tag| tag != "*")
        .collect();
    match tags.len() {
        0 => Err(bad_request(
            "Malformed ETag condition.",
            instance,
            request_id,
        )),
        1 => Ok(Precondition::Tag(tags.first().cloned().unwrap_or_default())),
        _ => Ok(Precondition::Tags(tags)),
    }
}

fn valid_idempotency_key(value: &str) -> bool {
    (8..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_request_id(value: &str) -> bool {
    (1..=128).contains(&value.len()) && value.bytes().all(|byte| (0x21..=0x7E).contains(&byte))
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut output = [0_u8; 32];
    for (target, source) in output.iter_mut().zip(digest.iter()) {
        *target = *source;
    }
    output
}

fn with_rate_headers(problem: Problem, decision: Decision) -> Problem {
    problem
        .with_header("RateLimit-Limit", decision.limit.to_string())
        .with_header("RateLimit-Remaining", decision.remaining.to_string())
        .with_header("RateLimit-Reset", decision.reset_seconds.to_string())
        .with_header("RateLimit-Policy", format!("{};w=1", decision.limit))
}

fn apply_rate_headers(response: &mut HttpResponse, decision: Decision) {
    response.set_header("RateLimit-Limit", decision.limit.to_string());
    response.set_header("RateLimit-Remaining", decision.remaining.to_string());
    response.set_header("RateLimit-Reset", decision.reset_seconds.to_string());
    response.set_header("RateLimit-Policy", format!("{};w=1", decision.limit));
}

fn bad_request(detail: &str, instance: &str, request_id: &str) -> Problem {
    Problem::new(400, "bad-request", detail, instance, request_id)
}

fn validation(
    instance: &str,
    request_id: &str,
    pointer: &str,
    code: &str,
    detail: &str,
) -> Problem {
    Problem::new(
        422,
        "validation-failed",
        "The request violates validation rules.",
        instance,
        request_id,
    )
    .with_errors(vec![FieldIssue::new(pointer, code, detail)])
}

fn internal(instance: &str, request_id: &str) -> Problem {
    Problem::new(
        500,
        "internal-error",
        "An internal error occurred.",
        instance,
        request_id,
    )
}

fn method_not_allowed(allowed: &[&str], instance: &str, request_id: &str) -> Problem {
    Problem::new(
        405,
        "method-not-allowed",
        "The method is not allowed for this resource.",
        instance,
        request_id,
    )
    .with_header("Allow", allowed.join(", "))
}

fn encode_segment(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn audit_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len().min(160));
    for character in value.chars().take(160) {
        if character.is_whitespace() || character.is_control() {
            out.push('_');
        } else {
            out.push(character);
        }
    }
    out
}

#[derive(Debug, Clone)]
enum Route {
    Health,
    Ready,
    Metrics,
    OpenApi,
    Zones,
    Zone(Name),
    ZoneSerial(Name),
    ZoneTransfers(Name),
    ZoneImport(Name),
    ZoneSettings(Name),
    ZoneKeys(Name),
    ZoneKeysStatus(Name),
    ZoneRollover(Name),
    ZoneSign(Name),
    Jobs,
    Job(String),
    TransferJob(String),
    Audit,
    RrsetList(Name),
    Rrset {
        origin: Name,
        owner: Name,
        rr_type: Rtype,
    },
}

impl Route {
    fn label(&self) -> &'static str {
        match self {
            Self::Health => "/healthz",
            Self::Ready => "/readyz",
            Self::Metrics => "/metrics",
            Self::OpenApi => "/api/v1/openapi.json",
            Self::Zones => "/api/v1/zones",
            Self::Zone(_) => "/api/v1/zones/{origin}",
            Self::ZoneSerial(_) => "/api/v1/zones/{origin}/serial",
            Self::ZoneTransfers(_) => "/api/v1/zones/{origin}/transfers",
            Self::ZoneImport(_) => "/api/v1/zones/{origin}/import",
            Self::ZoneSettings(_) => "/api/v1/zones/{origin}/settings",
            Self::ZoneKeys(_) => "/api/v1/zones/{origin}/keys",
            Self::ZoneKeysStatus(_) => "/api/v1/zones/{origin}/keys/status",
            Self::ZoneRollover(_) => "/api/v1/zones/{origin}/keys/rollover",
            Self::ZoneSign(_) => "/api/v1/zones/{origin}/sign",
            Self::Jobs => "/api/v1/jobs",
            Self::Job(_) => "/api/v1/jobs/{job_id}",
            Self::TransferJob(_) => "/api/v1/transfers/{job_id}",
            Self::Audit => "/api/v1/audit",
            Self::RrsetList(_) => "/api/v1/zones/{origin}/rrsets",
            Self::Rrset { .. } => "/api/v1/zones/{origin}/records/{name}/{type}",
        }
    }

    fn origin(&self) -> Option<&Name> {
        match self {
            Self::Zone(origin)
            | Self::ZoneSerial(origin)
            | Self::ZoneTransfers(origin)
            | Self::ZoneImport(origin)
            | Self::ZoneSettings(origin)
            | Self::ZoneKeys(origin)
            | Self::ZoneKeysStatus(origin)
            | Self::ZoneRollover(origin)
            | Self::ZoneSign(origin)
            | Self::RrsetList(origin) => Some(origin),
            Self::Rrset { origin, .. } => Some(origin),
            _ => None,
        }
    }

    fn allowed_methods(&self) -> &'static [&'static str] {
        match self {
            Self::Health | Self::Ready | Self::Metrics | Self::OpenApi => &["GET"],
            Self::Zones => &["GET", "POST"],
            Self::Zone(_) => &["GET", "PUT", "DELETE"],
            Self::ZoneSerial(_) => &["GET", "POST"],
            Self::ZoneTransfers(_) => &["GET", "POST"],
            Self::ZoneImport(_) => &["POST"],
            Self::ZoneSettings(_) => &["GET", "PATCH"],
            Self::ZoneKeys(_) | Self::ZoneKeysStatus(_) => &["GET"],
            Self::ZoneRollover(_) | Self::ZoneSign(_) => &["POST"],
            Self::Jobs | Self::Audit => &["GET"],
            Self::Job(_) | Self::TransferJob(_) => &["GET", "DELETE"],
            Self::Rrset { .. } => &["GET", "PUT", "PATCH", "DELETE"],
            Self::RrsetList(_) => &["GET"],
        }
    }

    fn target(&self) -> String {
        match self {
            Self::Zone(origin)
            | Self::ZoneSerial(origin)
            | Self::ZoneTransfers(origin)
            | Self::ZoneImport(origin)
            | Self::ZoneSettings(origin)
            | Self::ZoneKeys(origin)
            | Self::ZoneKeysStatus(origin)
            | Self::ZoneRollover(origin)
            | Self::ZoneSign(origin)
            | Self::RrsetList(origin) => origin.to_string(),
            Self::Rrset { origin, .. } => origin.to_string(),
            Self::Job(job_id) | Self::TransferJob(job_id) => job_id.clone(),
            _ => "-".to_owned(),
        }
    }

    fn action(&self, method: &Method) -> &'static str {
        match (self, method) {
            (Self::Zones, Method::Post) => "zone.create",
            (Self::Zone(_), Method::Put) => "zone.put",
            (Self::Zone(_), Method::Delete) => "zone.delete",
            (Self::ZoneSerial(_), Method::Post) => "zone.serial.set",
            (Self::ZoneTransfers(_), Method::Post) => "zone.transfer.start",
            (Self::ZoneImport(_), Method::Post) => "zone.import",
            (Self::ZoneSettings(_), Method::Patch) => "zone.settings.patch",
            (Self::ZoneKeysStatus(_), _) => "zone.keys.status",
            (Self::ZoneRollover(_), Method::Post) => "zone.keys.rollover",
            (Self::ZoneSign(_), Method::Post) => "zone.sign",
            (Self::Job(_) | Self::TransferJob(_), Method::Delete) => "job.cancel",
            (Self::Rrset { .. }, Method::Put) => "rrset.put",
            (Self::Rrset { .. }, Method::Patch) => "rrset.patch",
            (Self::Rrset { .. }, Method::Delete) => "rrset.delete",
            _ => "api.request",
        }
    }
}

fn parse_route(request: &HttpRequest, instance: &str, request_id: &str) -> Result<Route, Problem> {
    let segments = decode_path_segments(&request.path)
        .ok_or_else(|| bad_request("The request path is malformed.", instance, request_id))?;
    match segments.as_slice() {
        [health] if health == "healthz" => Ok(Route::Health),
        [ready] if ready == "readyz" => Ok(Route::Ready),
        [metrics] if metrics == "metrics" => Ok(Route::Metrics),
        [api, version, openapi] if api == "api" && version == "v1" && openapi == "openapi.json" => {
            Ok(Route::OpenApi)
        }
        [api, version, zones] if api == "api" && version == "v1" && zones == "zones" => {
            Ok(Route::Zones)
        }
        [api, version, zones, origin] if api == "api" && version == "v1" && zones == "zones" => {
            Ok(Route::Zone(parse_origin(origin, instance, request_id)?))
        }
        [api, version, zones, origin, serial]
            if api == "api" && version == "v1" && zones == "zones" && serial == "serial" =>
        {
            Ok(Route::ZoneSerial(parse_origin(
                origin, instance, request_id,
            )?))
        }
        [api, version, zones, origin, transfers]
            if api == "api" && version == "v1" && zones == "zones" && transfers == "transfers" =>
        {
            Ok(Route::ZoneTransfers(parse_origin(
                origin, instance, request_id,
            )?))
        }
        [api, version, zones, origin, import]
            if api == "api" && version == "v1" && zones == "zones" && import == "import" =>
        {
            Ok(Route::ZoneImport(parse_origin(
                origin, instance, request_id,
            )?))
        }
        [api, version, zones, origin, keys, status]
            if api == "api"
                && version == "v1"
                && zones == "zones"
                && keys == "keys"
                && status == "status" =>
        {
            Ok(Route::ZoneKeysStatus(parse_origin(
                origin, instance, request_id,
            )?))
        }
        [api, version, zones, origin, keys, rollover]
            if api == "api"
                && version == "v1"
                && zones == "zones"
                && keys == "keys"
                && rollover == "rollover" =>
        {
            Ok(Route::ZoneRollover(parse_origin(
                origin, instance, request_id,
            )?))
        }
        [api, version, jobs] if api == "api" && version == "v1" && jobs == "jobs" => {
            Ok(Route::Jobs)
        }
        [api, version, jobs, job_id] if api == "api" && version == "v1" && jobs == "jobs" => {
            Ok(Route::Job(job_id.clone()))
        }
        [api, version, transfers, job_id]
            if api == "api" && version == "v1" && transfers == "transfers" =>
        {
            Ok(Route::TransferJob(job_id.clone()))
        }
        [api, version, audit] if api == "api" && version == "v1" && audit == "audit" => {
            Ok(Route::Audit)
        }
        [api, version, zones, origin, settings]
            if api == "api" && version == "v1" && zones == "zones" && settings == "settings" =>
        {
            Ok(Route::ZoneSettings(parse_name(
                origin, instance, request_id,
            )?))
        }
        [api, version, zones, origin, collection]
            if api == "api" && version == "v1" && zones == "zones" && collection == "keys" =>
        {
            Ok(Route::ZoneKeys(parse_origin(origin, instance, request_id)?))
        }
        [api, version, zones, origin, collection]
            if api == "api" && version == "v1" && zones == "zones" && collection == "sign" =>
        {
            Ok(Route::ZoneSign(parse_origin(origin, instance, request_id)?))
        }
        [api, version, zones, origin, collection]
            if api == "api" && version == "v1" && zones == "zones" && collection == "rrsets" =>
        {
            Ok(Route::RrsetList(parse_origin(
                origin, instance, request_id,
            )?))
        }
        [api, version, zones, origin, collection, owner, rr_type]
            if api == "api"
                && version == "v1"
                && zones == "zones"
                && (collection == "records" || collection == "rrsets") =>
        {
            let origin = parse_origin(origin, instance, request_id)?;
            let owner = if owner == "@" {
                origin.clone()
            } else {
                parse_name(owner, instance, request_id)?
            };
            let rr_type = parse_rtype(rr_type)
                .ok_or_else(|| bad_request("Invalid record type.", instance, request_id))?;
            Ok(Route::Rrset {
                origin,
                owner,
                rr_type,
            })
        }
        _ => Err(Problem::new(
            404,
            "not-found",
            "The requested resource does not exist.",
            instance,
            request_id,
        )),
    }
}

fn parse_name(value: &str, instance: &str, request_id: &str) -> Result<Name, Problem> {
    Name::parse(value).map_err(|_| bad_request("Invalid DNS name.", instance, request_id))
}

fn parse_origin(value: &str, instance: &str, request_id: &str) -> Result<Name, Problem> {
    let name = parse_name(value, instance, request_id)?;
    if name == Name::root() || name.labels().any(|label| label == b"*") {
        return Err(bad_request(
            "A zone origin must be a non-root name without wildcards.",
            instance,
            request_id,
        ));
    }
    Ok(name)
}

fn required_scope(route: &Route, method: &Method) -> Option<&'static str> {
    match (route, method) {
        (Route::OpenApi, _) => None,
        (Route::Zones, Method::Post) => Some("zones:write"),
        (Route::Zones, _)
        | (Route::Zone(_), Method::Get)
        | (Route::ZoneSerial(_), Method::Get)
        | (Route::ZoneSettings(_), Method::Get) => Some("zones:read"),
        (Route::ZoneKeys(_), _) | (Route::ZoneKeysStatus(_), _) => Some("keys:read"),
        (Route::Zone(_), Method::Delete) => Some("zones:delete"),
        (Route::Zone(_), Method::Put)
        | (Route::ZoneSerial(_), Method::Post)
        | (Route::ZoneImport(_), _)
        | (Route::ZoneSettings(_), Method::Patch)
        | (Route::ZoneSign(_), _) => Some("zones:write"),
        (Route::ZoneTransfers(_), Method::Get) => Some("replication:read"),
        (Route::ZoneTransfers(_), _) => Some("replication:manage"),
        (Route::ZoneRollover(_), _) => Some("keys:write"),
        (Route::Jobs, _) | (Route::Job(_), Method::Get) | (Route::TransferJob(_), Method::Get) => {
            Some("jobs:read")
        }
        (Route::Job(_), _) | (Route::TransferJob(_), _) => Some("jobs:cancel"),
        (Route::Audit, _) => Some("audit:read"),
        (Route::RrsetList(_), _) | (Route::Rrset { .. }, Method::Get) => Some("zones:read"),
        (Route::Rrset { .. }, _) => Some("zones:write"),
        _ => None,
    }
}

fn route_label(path: &str) -> &'static str {
    let Some(segments) = decode_path_segments(path) else {
        return "invalid";
    };
    match segments.as_slice() {
        [health] if health == "healthz" => Route::Health.label(),
        [ready] if ready == "readyz" => Route::Ready.label(),
        [metrics] if metrics == "metrics" => Route::Metrics.label(),
        [api, version, openapi] if api == "api" && version == "v1" && openapi == "openapi.json" => {
            Route::OpenApi.label()
        }
        [api, version, zones] if api == "api" && version == "v1" && zones == "zones" => {
            Route::Zones.label()
        }
        [api, version, zones, _] if api == "api" && version == "v1" && zones == "zones" => {
            "/api/v1/zones/{origin}"
        }
        [api, version, jobs] if api == "api" && version == "v1" && jobs == "jobs" => "/api/v1/jobs",
        [api, version, jobs, _] if api == "api" && version == "v1" && jobs == "jobs" => {
            "/api/v1/jobs/{job_id}"
        }
        [api, version, transfers, _]
            if api == "api" && version == "v1" && transfers == "transfers" =>
        {
            "/api/v1/transfers/{job_id}"
        }
        [api, version, audit] if api == "api" && version == "v1" && audit == "audit" => {
            "/api/v1/audit"
        }
        [api, version, zones, _, collection]
            if api == "api" && version == "v1" && zones == "zones" && collection == "serial" =>
        {
            "/api/v1/zones/{origin}/serial"
        }
        [api, version, zones, _, collection]
            if api == "api" && version == "v1" && zones == "zones" && collection == "transfers" =>
        {
            "/api/v1/zones/{origin}/transfers"
        }
        [api, version, zones, _, collection]
            if api == "api" && version == "v1" && zones == "zones" && collection == "import" =>
        {
            "/api/v1/zones/{origin}/import"
        }
        [api, version, zones, _, collection, sub]
            if api == "api"
                && version == "v1"
                && zones == "zones"
                && collection == "keys"
                && sub == "status" =>
        {
            "/api/v1/zones/{origin}/keys/status"
        }
        [api, version, zones, _, collection, sub]
            if api == "api"
                && version == "v1"
                && zones == "zones"
                && collection == "keys"
                && sub == "rollover" =>
        {
            "/api/v1/zones/{origin}/keys/rollover"
        }
        [api, version, zones, _, settings]
            if api == "api" && version == "v1" && zones == "zones" && settings == "settings" =>
        {
            "/api/v1/zones/{origin}/settings"
        }
        [api, version, zones, _, collection]
            if api == "api" && version == "v1" && zones == "zones" && collection == "keys" =>
        {
            "/api/v1/zones/{origin}/keys"
        }
        [api, version, zones, _, collection]
            if api == "api" && version == "v1" && zones == "zones" && collection == "sign" =>
        {
            "/api/v1/zones/{origin}/sign"
        }
        [api, version, zones, _, collection]
            if api == "api" && version == "v1" && zones == "zones" && collection == "rrsets" =>
        {
            "/api/v1/zones/{origin}/rrsets"
        }
        [api, version, zones, _, collection, _, _]
            if api == "api" && version == "v1" && zones == "zones" && collection == "records" =>
        {
            "/api/v1/zones/{origin}/records/{name}/{type}"
        }
        [api, version, zones, _, collection, _, _]
            if api == "api" && version == "v1" && zones == "zones" && collection == "rrsets" =>
        {
            "/api/v1/zones/{origin}/rrsets/{owner}/{type}"
        }
        _ => "not-found",
    }
}

#[derive(Debug, Deserialize)]
struct ZoneWriteBody {
    origin: Option<String>,
    kind: Option<String>,
    default_ttl: Option<u32>,
    denial: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RrsetWriteBody {
    ttl: Option<u32>,
    records: Option<Vec<String>>,
    class: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RrsetPatchBody {
    ttl: Option<u32>,
    add: Option<Vec<String>>,
    remove: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct SettingsPatchBody {
    default_ttl: Option<u32>,
    denial: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SerialBody {
    mode: Option<String>,
    value: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct TransferBody {
    kind: Option<String>,
    peer: Option<String>,
    tsig_key: Option<String>,
    from_serial: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct RolloverBody {
    role: Option<String>,
    scheme: Option<String>,
    overlap: Option<Value>,
    retire_after: Option<Value>,
}

fn with_replay_header(mut response: HttpResponse) -> HttpResponse {
    response.set_header("Idempotent-Replay", "true");
    response
}

fn audit_target(route: &Route, instance: &str) -> String {
    let target = route.target();
    if target == "-" {
        instance.to_owned()
    } else {
        target
    }
}

fn zone_resource(origin: &Name) -> String {
    format!("/api/v1/zones/{}", encode_segment(&origin.to_string()))
}

fn prefers_async(request: &HttpRequest) -> bool {
    request.header("prefer").is_some_and(|value| {
        value.split(',').any(|token| {
            token
                .trim()
                .split(';')
                .next()
                .is_some_and(|kind| kind.trim().eq_ignore_ascii_case("respond-async"))
        })
    })
}

fn confirm_origin_from_body(body: &[u8]) -> Option<String> {
    if body.is_empty() {
        return None;
    }
    let value: Value = serde_json::from_slice(body).ok()?;
    value
        .get("confirm_origin")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn parse_duration(value: &str) -> Option<u32> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let (digits, multiplier) = match trimmed.as_bytes().last().copied() {
        Some(b's') => (trimmed.get(..trimmed.len().saturating_sub(1))?, 1_u64),
        Some(b'm') => (trimmed.get(..trimmed.len().saturating_sub(1))?, 60),
        Some(b'h') => (trimmed.get(..trimmed.len().saturating_sub(1))?, 3_600),
        Some(b'd') => (trimmed.get(..trimmed.len().saturating_sub(1))?, 86_400),
        _ => (trimmed, 1),
    };
    let number = digits.parse::<u64>().ok()?;
    u32::try_from(number.saturating_mul(multiplier)).ok()
}

fn duration_from_value(value: &Value) -> Option<u32> {
    match value {
        Value::String(text) => parse_duration(text),
        Value::Number(number) => number
            .as_u64()
            .and_then(|seconds| u32::try_from(seconds).ok()),
        _ => None,
    }
}

fn valid_seq_cursor(cursor: &str) -> bool {
    crate::base64url::decode(cursor)
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|text| text.parse::<u64>().ok())
        .is_some()
}

fn parse_job_state(value: &str) -> Option<JobState> {
    match value {
        "pending" | "queued" => Some(JobState::Pending),
        "running" => Some(JobState::Running),
        "done" | "succeeded" => Some(JobState::Done),
        "failed" => Some(JobState::Failed),
        "cancelled" | "canceled" => Some(JobState::Cancelled),
        _ => None,
    }
}

fn unix_time(seconds: u32) -> SystemTime {
    UNIX_EPOCH
        .checked_add(Duration::from_secs(u64::from(seconds)))
        .unwrap_or(UNIX_EPOCH)
}

fn job_json(job: &JobRecord) -> Value {
    json!({
        "job_id": job.id,
        "kind": job.kind,
        "state": job.state.as_str(),
        "status": job.state.as_str(),
        "resource": job.resource,
        "zone": job.zone,
        "progress": Value::Null,
        "result": job.result,
        "error": job.error.as_ref().map(|error| json!({
            "kind": error.kind,
            "detail": error.detail,
            "retryable": error.retryable,
        })),
        "created_at": rfc3339(job.created_at),
        "started_at": job.started_at.map(rfc3339),
        "finished_at": job.finished_at.map(rfc3339),
        "cancellable": job.cancellable,
        "expires_at": job.expires_at.map(rfc3339),
    })
}

fn job_visible(job: &JobRecord, principal: &Principal) -> bool {
    match &job.zone {
        Some(zone) => Name::parse(zone).is_ok_and(|name| principal.zone_allowed(&name)),
        None => true,
    }
}

fn job_not_found(instance: &str, request_id: &str) -> Problem {
    Problem::new(
        404,
        "job-not-found",
        "The job does not exist or has expired.",
        instance,
        request_id,
    )
}

fn admin_failure(error: AdminError) -> JobFailure {
    let (kind, retryable) = match &error {
        AdminError::NotFound(_) => ("not-found", false),
        AdminError::Conflict(Conflict::ZoneExists) => ("zone-exists", false),
        AdminError::Conflict(Conflict::RrsetExists) => ("rrset-exists", false),
        AdminError::Conflict(Conflict::ZoneBusy) | AdminError::Busy => ("zone-busy", true),
        AdminError::Conflict(Conflict::ZoneReadOnly) => ("zone-read-only", false),
        AdminError::Conflict(Conflict::SerialNotNewer) => ("serial-not-newer", false),
        AdminError::Conflict(Conflict::SerialAmbiguous) => ("serial-ambiguous", false),
        AdminError::Conflict(Conflict::TransferInProgress) => ("transfer-in-progress", true),
        AdminError::Conflict(Conflict::InvalidZoneState) => ("invalid-zone-state", false),
        AdminError::PreconditionFailed { .. } => ("precondition-failed", false),
        AdminError::PreconditionRequired => ("precondition-required", false),
        AdminError::InvariantViolation(_) => ("validation-failed", false),
        AdminError::InvalidCursor => ("bad-request", false),
        AdminError::Internal | AdminError::Storage(_) => ("internal-error", true),
    };
    JobFailure::new(kind, "The background operation failed.", retryable)
}

fn transfer_json(result: &crate::port::TransferResult) -> Value {
    json!({
        "zone": result.zone.to_string(),
        "kind": result.kind.as_str(),
        "mode": result.mode_used.as_str(),
        "mode_used": result.mode_used.as_str(),
        "serial": result.serial.map(pulse_dns::Serial::as_u32),
        "rrsets": result.rrsets,
        "bytes": result.bytes,
        "peer": result.peer,
        "outgoing": result.outgoing,
    })
}

fn import_json(report: &crate::port::ImportReport) -> Value {
    json!({
        "zone": report.zone.to_string(),
        "mode": report.mode.as_str(),
        "rrsets": report.rrsets,
        "serial": report.serial.map(pulse_dns::Serial::as_u32),
        "warnings": report.warnings,
        "applied": report.applied,
    })
}

fn rotation_json(rotation: &KeyRotationView) -> Value {
    json!({
        "next_event_at": rotation.next_event_at,
        "keys": rotation
            .keys
            .iter()
            .map(|key| json!({
                "key_tag": key.key_tag,
                "role": key.role,
                "state": key.state,
                "created_at": key.created_at,
                "next_transition": key.next_transition,
            }))
            .collect::<Vec<_>>(),
    })
}

fn journal_failure(
    instance: &str,
    request_id: &str,
    error: &crate::journal::JournalError,
) -> Problem {
    Problem::new(
        500,
        "storage-error",
        format!("Write-ahead journal failed: {error}"),
        instance,
        request_id,
    )
}
