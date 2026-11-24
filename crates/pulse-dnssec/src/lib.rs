//! DNSSEC: подпись и валидация (RFC 4033/4034/4035/5155/5702/6605).
//!
//! Крейт реализует криптографическую часть DNSSEC поверх `pulse-dns`
//! (wire-форматы, канонизация) и `aws-lc-rs` (единственный крипто-бэкенд,
//! ADR-0004 SEC-CR-001).
//!
//! # Возможности
//!
//! - **Ключи**: генерация/импорт/экспорт Ed25519 (15), ECDSA P-256 (13),
//!   RSA/SHA-256 (8, 2048/4096); PKCS#8 DER/PEM; BIND `K*.key`/`.private`;
//!   [`SecretRef`] с zeroize и безопасным `Debug`.
//! - **Подпись**: [`sign_rrset`] с канонизацией RRSIG RDATA + RRset,
//!   выбором inception/expiration, Original TTL, Labels и key tag.
//! - **Валидация**: [`verify_rrsig`] с проверкой signer/времени/TTL/типа/
//!   класса/алгоритма/key tag и wildcard-развёртывания.
//! - **DS**: [`ds_from_dnskey`], [`ds_matches`], цепочка
//!   [`chain::validate_dnskey_rrset`] / [`chain::validate_rrset_in_chain`].
//! - **Denial**: NSEC и NSEC3 (SHA-1, salt, лимит итераций, closest
//!   encloser, wildcard, Opt-Out).
//! - **Trust anchors**: встроенные root KSK IANA (20326, 38696), загрузка
//!   `root-anchors.xml`; RFC 5011 — [`trust_update::TrustAnchorStore`]
//!   (add/revoke hold-down, персистентное состояние `0600`).
//! - **Файлы ключей**: атомарная запись `0600` в каталог `0700`,
//!   аудит-хук без записи секретов.
//!
//! # Политика алгоритмов
//!
//! Подпись разрешена для 8/13/15. Валидация — для 8/10/13/14/15; SHA-1
//! (5/7) — только при явном [`AlgorithmPolicy::with_legacy_sha1`].
//! MD5/DSA/GOST/Ed448 отвергаются как [`VerifyError::AlgorithmNotAllowed`].
//!
//! # Пример (без выполнения)
//!
//! ```no_run
//! use std::net::Ipv4Addr;
//!
//! use pulse_dns::{Name, Rclass, Rdata, Rrset, Rtype, Ttl, DnskeyData};
//! use pulse_dnssec::{Algorithm, PrivateKey, SignOptions, sign_rrset};
//!
//! let key = PrivateKey::generate(Algorithm::ED25519)?;
//! let dnskey: DnskeyData = key.dnskey(256)?;
//! let owner = Name::parse("example.com")?;
//! let rrset = Rrset::new(
//!     owner.clone(),
//!     Rtype::A,
//!     Rclass::IN,
//!     Ttl::new(300)?,
//!     vec![Rdata::A(Ipv4Addr::new(192, 0, 2, 1))],
//! )?;
//! let options = SignOptions::new(owner, 1_700_000_000, 86_400);
//! let rrsig = sign_rrset(&key, &rrset, &options)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Лимиты
//!
//! NSEC3 iterations ≤ [`denial::MAX_NSEC3_ITERATIONS`], число proof-записей
//! ≤ [`denial::MAX_DENIAL_RECORDS`]; RSA < 2048 бит отвергается. Все
//! операции возвращают типизированные ошибки и не паникуют.

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
#![allow(
    clippy::module_name_repetitions,
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::too_many_lines,
    clippy::similar_names,
    clippy::needless_pass_by_value,
    clippy::items_after_statements,
    clippy::return_self_not_must_use
)]

pub mod algorithm;
pub mod bind;
pub mod chain;
pub mod denial;
pub mod der;
pub mod ds;
mod error;
pub mod key;
pub mod keyfile;
pub mod rdata_util;
pub mod secret;
pub mod sign;
pub mod trust_anchor;
pub mod trust_update;
pub mod verify;

pub use algorithm::{Algorithm, AlgorithmPolicy};
pub use chain::{ValidatedDnskeySet, validate_dnskey_rrset, validate_rrset_in_chain};
pub use denial::{DenialLimits, DenialOutcome, DenialResult, Nsec3Params, Nsec3Proof, NsecProof};
pub use ds::{DIGEST_SHA1, DIGEST_SHA256, DIGEST_SHA384, DsPolicy, ds_from_dnskey, ds_matches};
pub use error::{
    ChainError, DenialError, DsError, Error, KeyError, KeyFileError, SignError, TrustAnchorError,
    VerifyError,
};
pub use key::{DNSKEY_FLAG_SEP, DNSKEY_FLAG_ZONE_KEY, MIN_RSA_BITS, PrivateKey, RsaKeySize};
pub use keyfile::{
    KeyAudit, KeyAuditEvent, KeyFilePaths, KeyOperation, NoopAudit, ensure_private_directory,
    read_private_key_file, write_key_pair, write_secret_file,
};
pub use rdata_util::key_tag;
pub use secret::SecretRef;
pub use sign::{SignOptions, sign_rrset};
pub use trust_anchor::{RFC_5011_SUPPORTED, TrustAnchor, TrustAnchorSet, builtin_root_anchors};
pub use trust_update::{
    AnchorStatus, SharedTrustAnchors, TrustAnchorPolicy, TrustAnchorProvider, TrustAnchorSnapshot,
    TrustAnchorStore, TrustUpdateError, UpdateReport,
};
pub use verify::{VerifyOptions, verify_rrset_with_dnskeys, verify_rrsig};

/// Псевдоним RRSIG RDATA в терминах RFC.
pub type Rrsig = pulse_dns::RrsigData;
