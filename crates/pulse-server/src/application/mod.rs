//! Application-слой авторитетного сервиса: порт зоны, движок запросов, метрики.

mod port;
mod query;
mod stats;

pub use port::ZoneView;
pub use query::{
    DEFAULT_ANY_HINFO_TTL, EDNS_DEFAULT_PAYLOAD, EngineConfig, MAX_CNAME_CHAIN, MAX_UDP_PAYLOAD,
    NEGATIVE_TTL_CAP, QueryEngine, QueryError, Transport, UDP_PAYLOAD_WITHOUT_EDNS,
};
pub use stats::{QueryStats, StatsSnapshot};
