//! Доменные value objects и сущности shared kernel.

mod message;
mod name;
mod rdata;
mod record;
mod rr;
mod rrset;
mod serial;
mod ttl;

pub mod question;

pub use message::{Edns, EdnsError, EdnsOption, Flags, Header, Message};
pub use name::{
    MAX_LABEL_LEN, MAX_LABELS, MAX_NAME_TEXT_LEN, MAX_NAME_WIRE_LEN, Name, NameError, NameRef,
    name_cmp,
};
pub use question::Question;
pub use rdata::{
    CaaTag, DnskeyData, DsData, Nsec3Data, Nsec3ParamData, NsecData, Rdata, RdataError, RrsigData,
    SoaData, SvcParam, SvcbData, TlsaData, TxtData, TypeBitmap,
};
pub use record::{Record, RecordError};
pub use rr::{Opcode, Rclass, Rcode, Rtype};
pub use rrset::{MAX_RRSET_RECORDS, Rrset, RrsetError};
pub use serial::Serial;
pub use ttl::{TTL_MAX, Ttl, TtlError};

/// Совместимые с `domain-model.md` имена: `RrType` — это [`Rtype`].
pub type RrType = Rtype;
/// Совместимое с `domain-model.md` имя: `Class` — это [`Rclass`].
pub type Class = Rclass;
