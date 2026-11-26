//! Единый писатель RDATA для wire-кодера и канонической формы.

use crate::domain::{Name, Rdata};

/// Приёмник RDATA-полей.
pub(crate) trait RdataOut {
    /// Записывает сырые байты.
    fn bytes(&mut self, value: &[u8]);

    /// Записывает доменное имя.
    ///
    /// `compressible` — разрешена ли компрессия для данного поля (RFC 1035,
    /// RFC 2782, RFC 4034, RFC 6672, RFC 9460).
    fn name(&mut self, name: &Name, compressible: bool);

    /// Записывает `u8`.
    fn u8(&mut self, value: u8) {
        self.bytes(&[value]);
    }

    /// Записывает `u16` big-endian.
    fn u16(&mut self, value: u16) {
        self.bytes(&value.to_be_bytes());
    }

    /// Записывает `u32` big-endian.
    fn u32(&mut self, value: u32) {
        self.bytes(&value.to_be_bytes());
    }
}

/// Пишет RDATA в `out` без учёта RDLENGTH (его добавляет вызывающий).
#[allow(clippy::too_many_lines)]
pub(crate) fn write_rdata<O: RdataOut + ?Sized>(rdata: &Rdata, out: &mut O) {
    match rdata {
        Rdata::A(address) => out.bytes(&address.octets()),
        Rdata::Aaaa(address) => out.bytes(&address.octets()),
        Rdata::Ns(name) | Rdata::Cname(name) | Rdata::Ptr(name) => out.name(name, true),
        Rdata::Dname(name) => out.name(name, false),
        Rdata::Soa(soa) => {
            out.name(&soa.mname, true);
            out.name(&soa.rname, true);
            out.u32(soa.serial.as_u32());
            out.u32(soa.refresh);
            out.u32(soa.retry);
            out.u32(soa.expire);
            out.u32(soa.minimum);
        }
        Rdata::Mx {
            preference,
            exchange,
        } => {
            out.u16(*preference);
            out.name(exchange, true);
        }
        Rdata::Txt(text) => {
            for segment in text.segments() {
                out.u8(u8::try_from(segment.len()).unwrap_or(u8::MAX));
                out.bytes(segment);
            }
        }
        Rdata::Srv {
            priority,
            weight,
            port,
            target,
        } => {
            out.u16(*priority);
            out.u16(*weight);
            out.u16(*port);
            // RFC 2782 §2: имя цели не сжимается.
            out.name(target, false);
        }
        Rdata::Caa { flags, tag, value } => {
            out.u8(*flags);
            out.u8(u8::try_from(tag.as_bytes().len()).unwrap_or(u8::MAX));
            out.bytes(tag.as_bytes());
            out.bytes(value);
        }
        Rdata::Ds(ds) => {
            out.u16(ds.key_tag());
            out.u8(ds.algorithm());
            out.u8(ds.digest_type());
            out.bytes(ds.digest());
        }
        Rdata::Dnskey(key) => {
            out.u16(key.flags());
            out.u8(key.protocol());
            out.u8(key.algorithm());
            out.bytes(key.public_key());
        }
        Rdata::Rrsig(signature) => {
            out.u16(signature.type_covered().as_u16());
            out.u8(signature.algorithm());
            out.u8(signature.labels());
            out.u32(signature.original_ttl());
            out.u32(signature.signature_expiration());
            out.u32(signature.signature_inception());
            out.u16(signature.key_tag());
            // RFC 4034 §3.1.7: Signer's Name не сжимается.
            out.name(signature.signer_name(), false);
            out.bytes(signature.signature());
        }
        Rdata::Nsec(nsec) => {
            // RFC 4034 §4.1.1: Next Domain Name не сжимается.
            out.name(nsec.next_domain(), false);
            out.bytes(nsec.type_bitmap().as_bytes());
        }
        Rdata::Nsec3(nsec3) => {
            out.u8(nsec3.hash_algorithm());
            out.u8(nsec3.flags());
            out.u16(nsec3.iterations());
            out.u8(u8::try_from(nsec3.salt().len()).unwrap_or(u8::MAX));
            out.bytes(nsec3.salt());
            out.u8(u8::try_from(nsec3.next_hashed_owner().len()).unwrap_or(u8::MAX));
            out.bytes(nsec3.next_hashed_owner());
            out.bytes(nsec3.type_bitmap().as_bytes());
        }
        Rdata::Nsec3Param(param) => {
            out.u8(param.hash_algorithm());
            out.u8(param.flags());
            out.u16(param.iterations());
            out.u8(u8::try_from(param.salt().len()).unwrap_or(u8::MAX));
            out.bytes(param.salt());
        }
        Rdata::Tlsa(tlsa) => {
            out.u8(tlsa.usage());
            out.u8(tlsa.selector());
            out.u8(tlsa.matching());
            out.bytes(tlsa.certificate_association_data());
        }
        Rdata::Svcb(svcb) | Rdata::Https(svcb) => {
            out.u16(svcb.priority());
            // RFC 9460 §2.2: TargetName не сжимается.
            out.name(svcb.target(), false);
            for param in svcb.params() {
                out.u16(param.key());
                out.u16(u16::try_from(param.value().len()).unwrap_or(u16::MAX));
                out.bytes(param.value());
            }
        }
        Rdata::Unknown { rdata, .. } => out.bytes(rdata),
        Rdata::Empty(_) => {}
    }
}
