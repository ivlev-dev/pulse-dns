//! Application-слой авторитетного сервиса: порт зоны, движок запросов, метрики.

mod cache;
mod port;
mod query;
mod stats;

pub use cache::{
    CachedOutcome, DEFAULT_MAX_BYTES, DEFAULT_MAX_ENTRIES, DEFAULT_SHARDS, MAX_SHARDS,
    ResponseCache, ResponseCacheConfig, ResponseCacheKey, ResponseCacheMetrics, ZoneIdentity,
};
pub use port::{ZoneSnapshot, ZoneView};
pub use query::{
    DEFAULT_ANY_HINFO_TTL, EDNS_DEFAULT_PAYLOAD, EncodedResponse, EngineConfig, MAX_CNAME_CHAIN,
    MAX_UDP_PAYLOAD, NEGATIVE_TTL_CAP, QueryEngine, QueryError, Scratch, Transport,
    UDP_PAYLOAD_WITHOUT_EDNS,
};
pub use stats::{QueryStats, StatsSnapshot};
