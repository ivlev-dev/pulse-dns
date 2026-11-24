//! Control-plane REST API (`v1` subset) для `pulse-dns`.
//!
//! Крейт реализует синхронный HTTP-сервер управления зонами: health/readiness,
//! список и CRUD зон, RRset (upsert/patch/delete), настройки зоны, публичные
//! DNSSEC-ключи/DS и переподпись зоны, ETag / `If-Match`, идемпотентность,
//! bearer-аутентификацию со scope-проверками, ошибки RFC 9457
//! (`application/problem+json`) и метрики Prometheus.
//!
//! # Состав
//!
//! - [`port`] — порт [`port::ZoneAdmin`] и его DTO.
//! - [`memory`] — in-memory реализация порта для `pulsed` и тестов.
//! - [`auth`] — конфигурация токенов, scopes и per-zone allowlist.
//! - [`config`] — конфигурация сервера.
//! - [`server`] — запуск HTTP-сервера с graceful shutdown.
//! - [`error`] — типизированные ошибки порта.
//!
//! # Безопасность
//!
//! - Bind по умолчанию — `127.0.0.1`; публичный bind без TLS отклоняется
//!   ([`config::ApiConfig::validate`]).
//! - Токены сравниваются в constant-time (`subtle`).
//! - Зона вне allowlist токена неотличима от несуществующей (`404
//!   zone_not_found`), в лог пишется событие `denied_zone_out_of_scope`.
//! - Тело запроса ограничено, заголовки и время чтения лимитированы,
//!   паники на недоверенном вводе отсутствуют.
//!
//! # Пример
//!
//! ```
//! use std::sync::Arc;
//! use pulse_api::auth::TokenConfig;
//! use pulse_api::config::ApiConfig;
//! use pulse_api::memory::InMemoryZoneAdmin;
//! use pulse_api::server::serve;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let tokens = vec![TokenConfig {
//!     id: "tok_admin".to_owned(),
//!     token: "pd_live_example_token_value".to_owned(),
//!     scopes: vec!["admin".to_owned()],
//!     zone_scope: None,
//! }];
//! let config = ApiConfig::new(tokens);
//! let store = Arc::new(InMemoryZoneAdmin::new());
//! let server = serve(config, store)?;
//! println!("listening on {}", server.addr());
//! server.shutdown();
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::map_unwrap_or)]
#![allow(clippy::option_if_let_else)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::significant_drop_tightening)]
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::single_match_else)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::float_cmp)]
#![allow(clippy::similar_names)]
#![allow(clippy::result_large_err)]
#![allow(clippy::type_complexity)]
#![allow(clippy::unused_self)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::format_push_string)]
#![allow(clippy::unnested_or_patterns)]

pub mod auth;
pub mod config;
pub mod error;
pub mod memory;
pub mod port;
pub mod server;

mod base64url;
mod codec;
mod etag;
mod handler;
mod http;
mod idempotency;
mod metrics;
mod openapi;
mod problem;
mod query;
mod ratelimit;
mod rdata_text;
mod timefmt;

pub use auth::{AuthConfigError, Authenticator, Principal, ScopeSet, TokenConfig, ZoneScope};
pub use config::{ApiConfig, ApiConfigError};
pub use error::{AdminError, Conflict, FieldIssue, InvariantViolation, NotFound};
pub use memory::{InMemoryZoneAdmin, StoreSnapshot, ZoneSnapshot};
pub use port::{
    Denial, ListRrsets, ListZones, Precondition, Preconditions, RrsetInput, RrsetPage, RrsetPatch,
    RrsetPatchOutcome, RrsetView, WriteOutcome, ZoneAdmin, ZoneAllow, ZoneFileMetrics, ZoneId,
    ZoneKind, ZoneMetaInput, ZonePage, ZoneSettings, ZoneSettingsPatch, ZoneSettingsView, ZoneView,
};
pub use server::{ApiServerError, RunningServer, serve};
