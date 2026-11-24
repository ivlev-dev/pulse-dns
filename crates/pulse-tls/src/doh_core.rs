//! Протокол-независимое ядро DoH (RFC 8484).
//!
//! HTTP/1.1 (`doh`) и HTTP/2 (`doh2`) используют один и тот же разбор
//! `GET /dns-query?dns=…` / `POST /dns-query`, одни и те же коды ответов,
//! лимиты и `Cache-Control`. Транспорт отвечает только за чтение запроса и
//! сериализацию ответа.

use std::net::SocketAddr;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};

use crate::dot::DnsHandler;
use crate::error::Error;
use crate::http::{HttpResponse, Method, content_type_is, query_param, response_max_age};
use crate::ratelimit::{RateLimitConfig, RateLimiter};
use crate::stats::Stats;

pub(crate) const DNS_PATH: &str = "/dns-query";
pub(crate) const HEALTH_PATH: &str = "/healthz";
pub(crate) const DNS_MEDIA_TYPE: &str = "application/dns-message";

/// Общие настройки и обработчик DoH для любого HTTP-транспорта.
pub(crate) struct DohCore {
    pub(crate) max_body_size: usize,
    cache_control: bool,
    handler: DnsHandler,
    limiter: Option<RateLimiter>,
    stats: Arc<Stats>,
}

impl DohCore {
    pub(crate) fn new(
        max_body_size: usize,
        cache_control: bool,
        handler: DnsHandler,
        rate_limit: Option<RateLimitConfig>,
        stats: Arc<Stats>,
    ) -> Result<Self, Error> {
        let limiter = match rate_limit {
            Some(rate_limit) => Some(RateLimiter::new(rate_limit)?),
            None => None,
        };
        Ok(Self {
            max_body_size,
            cache_control,
            handler,
            limiter,
            stats,
        })
    }

    /// Проверяет rate limit и учитывает отказ в счётчиках.
    pub(crate) fn allow_rate(&self, peer: SocketAddr) -> bool {
        match &self.limiter {
            Some(limiter) if !limiter.allow(peer.ip()) => {
                self.stats.rate_limited();
                self.stats.http_error();
                false
            }
            _ => true,
        }
    }

    /// Маршрутизирует запрос и возвращает готовый HTTP-ответ.
    ///
    /// `target` — path + query (`/dns-query?dns=…`), `content_type` — сырое
    /// значение заголовка `Content-Type`, `body` — уже прочитанное тело.
    pub(crate) fn route(
        &self,
        peer: SocketAddr,
        method: Method,
        target: &str,
        content_type: Option<&[u8]>,
        body: &[u8],
    ) -> HttpResponse {
        let path = target.split('?').next().unwrap_or(target);
        if path == HEALTH_PATH {
            return if method == Method::Get {
                HttpResponse::text(200, "ok\n", false)
            } else {
                let mut response = HttpResponse::method_not_allowed(false);
                response.allow = Some("GET");
                response
            };
        }
        if path != DNS_PATH {
            return HttpResponse::error(404, "not found", false);
        }
        match method {
            Method::Get => {
                let Some(encoded) = query_param(target, "dns") else {
                    return HttpResponse::error(400, "missing dns query parameter", false);
                };
                let Some(query) = decode_dns(&encoded) else {
                    return HttpResponse::error(400, "invalid base64url dns parameter", false);
                };
                if query.is_empty() {
                    return HttpResponse::error(400, "empty dns message", false);
                }
                if query.len() > self.max_body_size {
                    return HttpResponse::error(413, "dns message too large", false);
                }
                self.invoke(peer, &query)
            }
            Method::Post => {
                if !content_type_is(content_type, DNS_MEDIA_TYPE) {
                    return HttpResponse::error(
                        415,
                        "Content-Type must be application/dns-message",
                        false,
                    );
                }
                if body.is_empty() {
                    return HttpResponse::error(400, "empty dns message", false);
                }
                if body.len() > self.max_body_size {
                    return HttpResponse::error(413, "dns message too large", false);
                }
                self.invoke(peer, body)
            }
            Method::Other => HttpResponse::method_not_allowed(false),
        }
    }

    fn invoke(&self, peer: SocketAddr, query: &[u8]) -> HttpResponse {
        self.stats.query();
        let outcome = catch_unwind(AssertUnwindSafe(|| (self.handler)(query, peer)));
        let response = match outcome {
            Ok(Some(response)) => response,
            Ok(None) | Err(_) => {
                return HttpResponse::error(500, "DNS handler failed", false);
            }
        };
        if response.is_empty() {
            return HttpResponse::error(500, "DNS handler returned an empty response", false);
        }
        if response.len() > self.max_body_size {
            return HttpResponse::error(500, "DNS response too large", false);
        }
        let cache = if self.cache_control {
            response_max_age(&response)
        } else {
            None
        };
        HttpResponse::dns(response, cache, false)
    }
}

fn decode_dns(encoded: &[u8]) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(encoded)
        .or_else(|_| URL_SAFE.decode(encoded))
        .ok()
}
