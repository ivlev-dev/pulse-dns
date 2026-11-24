//! HTTP-маршрутизация и обработка запросов.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use pulse_dns::{Name, Rdata, Rtype, Ttl};
use pulse_dnssec::{DIGEST_SHA256, DNSKEY_FLAG_SEP, DsPolicy, ds_from_dnskey, key_tag};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::auth::{Authenticator, Principal};
use crate::codec::{hex_lower, parse_rtype};
use crate::config::ApiConfig;
use crate::error::{AdminError, FieldIssue, NotFound};
use crate::etag::{header_matches, normalize_tag};
use crate::http::{HttpRequest, HttpResponse, Method};
use crate::idempotency::{Begin, IdempotencyStore};
use crate::metrics::Metrics;
use crate::port::{
    AllowAll, Denial, ListRrsets, ListZones, Precondition, Preconditions, RrsetInput, RrsetPatch,
    RrsetPatchOutcome, ZoneAdmin, ZoneAllow, ZoneKind, ZoneMetaInput, ZoneSettingsPatch, ZoneView,
};
use crate::problem::Problem;
use crate::query::{Query, decode_path_segments, parse_limit};
use crate::ratelimit::{Decision, RateLimiter};
use crate::rdata_text::{format_rdata, parse_rdata};
use crate::timefmt::rfc3339;

/// Обработчик API.
pub(crate) struct Api {
    store: Arc<dyn ZoneAdmin>,
    auth: Authenticator,
    metrics: Metrics,
    limiter: RateLimiter,
    idempotency: IdempotencyStore,
    max_body_bytes: usize,
    request_counter: AtomicU64,
}

impl Api {
    /// Создаёт обработчик из валидированной конфигурации.
    pub(crate) fn new(config: &ApiConfig, store: Arc<dyn ZoneAdmin>, auth: Authenticator) -> Self {
        Self {
            store,
            auth,
            metrics: Metrics::default(),
            limiter: RateLimiter::new(config.rate_limit_per_sec),
            idempotency: IdempotencyStore::new(config.idempotency_ttl, config.idempotency_capacity),
            max_body_bytes: config.max_body_bytes,
            request_counter: AtomicU64::new(1),
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
        let result = self.dispatch(request, &route, &principal, request_id, instance);
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
                        &route.target(),
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
                        &route.target(),
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
                    Some(HttpResponse::text(
                        200,
                        "text/plain; version=0.0.4; charset=utf-8",
                        self.metrics.render_with(self.store.zonefile_metrics()),
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
        if !matches!(request.method, Method::Put | Method::Patch | Method::Delete) {
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
        Ok(Some(hex_lower(&hasher.finalize())))
    }

    fn dispatch(
        &self,
        request: &HttpRequest,
        route: &Route,
        principal: &Principal,
        request_id: &str,
        instance: &str,
    ) -> Result<HttpResponse, Problem> {
        match route {
            Route::Health | Route::Ready | Route::Metrics => Err(internal(instance, request_id)),
            Route::OpenApi => Ok(HttpResponse::json(200, crate::openapi::document())),
            Route::Zones => self.list_zones(request, principal, request_id, instance),
            Route::Zone(origin) => match request.method {
                Method::Get => self.get_zone(request, origin, request_id, instance),
                Method::Put => self.put_zone(request, origin, request_id, instance),
                Method::Delete => self.delete_zone(request, origin, request_id, instance),
                _ => Err(internal(instance, request_id)),
            },
            Route::ZoneSettings(origin) => match request.method {
                Method::Get => self.get_settings(origin, request_id, instance),
                Method::Patch => self.patch_settings(request, origin, request_id, instance),
                _ => Err(internal(instance, request_id)),
            },
            Route::ZoneKeys(origin) => self.get_zone_keys(origin, request_id, instance),
            Route::ZoneSign(origin) => self.sign_zone(origin, request_id, instance),
            Route::RrsetList(origin) => self.list_rrsets(request, origin, request_id, instance),
            Route::Rrset {
                origin,
                owner,
                rr_type,
            } => match request.method {
                Method::Get => {
                    self.get_rrset(request, origin, owner, *rr_type, request_id, instance)
                }
                Method::Put => {
                    self.put_rrset(request, origin, owner, *rr_type, request_id, instance)
                }
                Method::Patch => {
                    self.patch_rrset(request, origin, owner, *rr_type, request_id, instance)
                }
                Method::Delete => {
                    self.delete_rrset(request, origin, owner, *rr_type, request_id, instance)
                }
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
        self.store
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
        Ok(HttpResponse::json(
            200,
            json!({
                "zone": origin.to_string(),
                "denial": "nsec",
                "keys": keys,
                "ds": ds,
            }),
        ))
    }

    fn sign_zone(
        &self,
        origin: &Name,
        request_id: &str,
        instance: &str,
    ) -> Result<HttpResponse, Problem> {
        let zone = self
            .store
            .sign_zone(origin)
            .map_err(|error| Problem::from_admin(error, instance, request_id))?;
        let mut response = HttpResponse::json(200, zone_json(&zone));
        response.set_header("ETag", zone.etag);
        Ok(response)
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
        let outcome = self
            .store
            .put_zone(origin, &meta, &preconditions)
            .map_err(|error| Problem::from_admin(error, instance, request_id))?;
        let created = outcome.is_created();
        let zone = outcome.value();
        let mut response = HttpResponse::json(if created { 201 } else { 200 }, zone_json(zone));
        response.set_header("ETag", zone.etag.clone());
        if created {
            response.set_header(
                "Location",
                format!("/api/v1/zones/{}", encode_segment(&origin.to_string())),
            );
        }
        Ok(response)
    }

    fn delete_zone(
        &self,
        request: &HttpRequest,
        origin: &Name,
        request_id: &str,
        instance: &str,
    ) -> Result<HttpResponse, Problem> {
        let preconditions = preconditions(request, instance, request_id)?;
        self.store
            .delete_zone(origin, &preconditions)
            .map_err(|error| Problem::from_admin(error, instance, request_id))?;
        Ok(HttpResponse::empty(204))
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
        let settings = self
            .store
            .patch_settings(origin, &patch, &preconditions)
            .map_err(|error| Problem::from_admin(error, instance, request_id))?;
        let mut response = HttpResponse::json(200, settings_json(&settings));
        response.set_header("ETag", settings.etag.clone());
        Ok(response)
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

    fn put_rrset(
        &self,
        request: &HttpRequest,
        origin: &Name,
        owner: &Name,
        rr_type: Rtype,
        request_id: &str,
        instance: &str,
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
        let outcome = self
            .store
            .put_rrset(origin, owner, rr_type, &input, &preconditions)
            .map_err(|error| Problem::from_admin(error, instance, request_id))?;
        let created = outcome.is_created();
        let rrset = outcome.value();
        let mut response = HttpResponse::json(if created { 201 } else { 200 }, rrset_json(rrset));
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
        Ok(response)
    }

    fn patch_rrset(
        &self,
        request: &HttpRequest,
        origin: &Name,
        owner: &Name,
        rr_type: Rtype,
        request_id: &str,
        instance: &str,
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
        let add = match body.add {
            Some(records) if !records.is_empty() => {
                parse_records(&records, rr_type, instance, request_id)?
            }
            _ => Vec::new(),
        };
        let remove = match body.remove {
            Some(records) if !records.is_empty() => {
                parse_records(&records, rr_type, instance, request_id)?
            }
            _ => Vec::new(),
        };
        let patch = RrsetPatch { ttl, add, remove };
        let preconditions = preconditions(request, instance, request_id)?;
        let outcome = self
            .store
            .patch_rrset(origin, owner, rr_type, &patch, &preconditions)
            .map_err(|error| Problem::from_admin(error, instance, request_id))?;
        match outcome {
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
                Ok(response)
            }
            RrsetPatchOutcome::Deleted { removed } => Ok(HttpResponse::json(
                200,
                json!({ "deleted": true, "removed": removed }),
            )),
        }
    }

    fn delete_rrset(
        &self,
        request: &HttpRequest,
        origin: &Name,
        owner: &Name,
        rr_type: Rtype,
        request_id: &str,
        instance: &str,
    ) -> Result<HttpResponse, Problem> {
        let preconditions = preconditions(request, instance, request_id)?;
        self.store
            .delete_rrset(origin, owner, rr_type, &preconditions)
            .map_err(|error| Problem::from_admin(error, instance, request_id))?;
        Ok(HttpResponse::empty(204))
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
    ZoneSettings(Name),
    ZoneKeys(Name),
    ZoneSign(Name),
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
            Self::ZoneSettings(_) => "/api/v1/zones/{origin}/settings",
            Self::ZoneKeys(_) => "/api/v1/zones/{origin}/keys",
            Self::ZoneSign(_) => "/api/v1/zones/{origin}/sign",
            Self::RrsetList(_) => "/api/v1/zones/{origin}/rrsets",
            Self::Rrset { .. } => "/api/v1/zones/{origin}/records/{name}/{type}",
        }
    }

    fn origin(&self) -> Option<&Name> {
        match self {
            Self::Zone(origin)
            | Self::ZoneSettings(origin)
            | Self::ZoneKeys(origin)
            | Self::ZoneSign(origin)
            | Self::RrsetList(origin) => Some(origin),
            Self::Rrset { origin, .. } => Some(origin),
            _ => None,
        }
    }

    fn allowed_methods(&self) -> &'static [&'static str] {
        match self {
            Self::Health | Self::Ready | Self::Metrics | Self::OpenApi | Self::Zones => &["GET"],
            Self::Zone(_) => &["GET", "PUT", "DELETE"],
            Self::ZoneSettings(_) => &["GET", "PATCH"],
            Self::ZoneKeys(_) => &["GET"],
            Self::ZoneSign(_) => &["POST"],
            Self::Rrset { .. } => &["GET", "PUT", "PATCH", "DELETE"],
            Self::RrsetList(_) => &["GET"],
        }
    }

    fn target(&self) -> String {
        match self {
            Self::Zone(origin)
            | Self::ZoneSettings(origin)
            | Self::ZoneKeys(origin)
            | Self::ZoneSign(origin)
            | Self::RrsetList(origin) => origin.to_string(),
            Self::Rrset { origin, .. } => origin.to_string(),
            _ => "-".to_owned(),
        }
    }

    fn action(&self, method: &Method) -> &'static str {
        match (self, method) {
            (Self::Zone(_), Method::Put) => "zone.put",
            (Self::Zone(_), Method::Delete) => "zone.delete",
            (Self::ZoneSettings(_), Method::Patch) => "zone.settings.patch",
            (Self::ZoneSign(_), Method::Post) => "zone.sign",
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
        (Route::Zones, _)
        | (Route::Zone(_), Method::Get)
        | (Route::ZoneSettings(_), Method::Get)
        | (Route::ZoneKeys(_), _) => Some("zones:read"),
        (Route::Zone(_), Method::Delete) => Some("zones:delete"),
        (Route::Zone(_), Method::Put)
        | (Route::ZoneSettings(_), Method::Patch)
        | (Route::ZoneSign(_), _) => Some("zones:write"),
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
