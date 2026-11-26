//! Декодер wire-формата с защитой от враждебного ввода.

use std::cell::RefCell;
use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::domain::{
    CaaTag, DnskeyData, DsData, Edns, EdnsOption, Flags, MAX_LABELS, MAX_NAME_WIRE_LEN, Message,
    Name, Nsec3Data, Nsec3ParamData, NsecData, Question, Rclass, Rdata, RdataError, Record,
    RrsigData, Rtype, SoaData, SvcParam, SvcbData, TlsaData, Ttl, TxtData, TypeBitmap,
};
use crate::wire::{
    DecodeError, DecodeLimits, MAX_COMPRESSION_POINTERS, MAX_MESSAGE_LEN, MAX_RECORDS,
};

/// Декодирует сообщение.
pub(crate) fn decode_message(bytes: &[u8], limits: DecodeLimits) -> Result<Message, DecodeError> {
    if bytes.len() > MAX_MESSAGE_LEN {
        return Err(DecodeError::MessageTooLong { len: bytes.len() });
    }
    let limits = DecodeLimits {
        max_records: limits.max_records.min(MAX_RECORDS),
    };
    let decoder = Decoder {
        buf: bytes,
        allow_compression: true,
        limits,
        valid_starts: RefCell::new(HashSet::new()),
    };
    decoder.parse_message()
}

/// Декодирует RDATA без сжатия (самостоятельный вызов).
pub(crate) fn decode_standalone_rdata(rr_type: Rtype, bytes: &[u8]) -> Result<Rdata, DecodeError> {
    if rr_type == Rtype::OPT {
        return Err(DecodeError::OptAsRdata);
    }
    if bytes.len() > usize::from(u16::MAX) {
        return Err(DecodeError::RdataTooLong { len: bytes.len() });
    }
    let decoder = Decoder {
        buf: bytes,
        allow_compression: false,
        limits: DecodeLimits::default_limits(),
        valid_starts: RefCell::new(HashSet::new()),
    };
    decoder.parse_rdata(rr_type, 0, bytes.len())
}

struct Decoder<'a> {
    buf: &'a [u8],
    allow_compression: bool,
    limits: DecodeLimits,
    /// Позиции, являющиеся началом метки или сжатого имени; только на них
    /// разрешено указывать compression pointer.
    valid_starts: RefCell<HashSet<usize>>,
}

impl<'a> Decoder<'a> {
    #[allow(clippy::too_many_lines)]
    fn parse_message(&self) -> Result<Message, DecodeError> {
        let id = self.u16_at(0, "id")?;
        let flags = Flags::from_bits(self.u16_at(2, "flags")?);
        let question_count = usize::from(self.u16_at(4, "qdcount")?);
        let answer_count = usize::from(self.u16_at(6, "ancount")?);
        let authority_count = usize::from(self.u16_at(8, "nscount")?);
        let additional_count = usize::from(self.u16_at(10, "arcount")?);

        let record_total = answer_count
            .saturating_add(authority_count)
            .saturating_add(additional_count);
        if record_total > self.limits.max_records {
            return Err(DecodeError::RecordLimitExceeded {
                section: "records",
                count: record_total,
                limit: self.limits.max_records,
            });
        }
        if question_count > self.limits.max_records {
            return Err(DecodeError::RecordLimitExceeded {
                section: "question",
                count: question_count,
                limit: self.limits.max_records,
            });
        }

        let mut position = 12_usize;
        let mut questions = Vec::with_capacity(question_count);
        for _ in 0..question_count {
            let (qname, next) = self.name_at(position, true)?;
            position = next;
            let qtype = Rtype::from_u16(self.u16_at(position, "qtype")?);
            position = position.saturating_add(2);
            let qclass = Rclass::from_u16(self.u16_at(position, "qclass")?);
            position = position.saturating_add(2);
            questions.push(Question::new(qname, qtype, qclass));
        }

        let mut answers = Vec::new();
        let mut authority = Vec::new();
        let mut additional = Vec::new();
        let mut edns = None;

        for (index, count) in [answer_count, authority_count, additional_count]
            .into_iter()
            .enumerate()
        {
            let additional_section = index == 2;
            for _ in 0..count {
                let (owner, next) = self.name_at(position, true)?;
                position = next;
                let rr_type = Rtype::from_u16(self.u16_at(position, "type")?);
                position = position.saturating_add(2);
                let class = Rclass::from_u16(self.u16_at(position, "class")?);
                position = position.saturating_add(2);
                let ttl_raw = self.u32_at(position, "ttl")?;
                position = position.saturating_add(4);
                let rdlength = usize::from(self.u16_at(position, "rdlength")?);
                position = position.saturating_add(2);
                let rdata_end =
                    position
                        .checked_add(rdlength)
                        .ok_or(DecodeError::RdataOutOfBounds {
                            offset: position,
                            len: rdlength,
                            remaining: self.buf.len().saturating_sub(position),
                        })?;
                if rdata_end > self.buf.len() {
                    return Err(DecodeError::RdataOutOfBounds {
                        offset: position,
                        len: rdlength,
                        remaining: self.buf.len().saturating_sub(position),
                    });
                }

                if rr_type == Rtype::OPT {
                    if !additional_section {
                        return Err(DecodeError::OptOutsideAdditional);
                    }
                    if owner.wire_len() != 1 {
                        return Err(DecodeError::OptOwnerNotRoot);
                    }
                    if edns.is_some() {
                        return Err(DecodeError::DuplicateOpt);
                    }
                    edns = Some(self.parse_opt(class, ttl_raw, position, rdata_end)?);
                } else {
                    // DNS UPDATE (RFC 2136 §2.4/§2.5): в Prerequisite/Update
                    // секциях классы ANY/NONE с RDLENGTH=0 несут метазначение,
                    // а не RDATA конкретного типа. Обычный парсер отверг бы
                    // пустую RDATA для A/NS/SOA и т.п., поэтому запись
                    // сохраняется как пустой `Unknown` без разбора полей.
                    let rdata = if rdlength == 0 && matches!(class, Rclass::ANY | Rclass::NONE) {
                        Rdata::empty_metavalue(rr_type)
                    } else {
                        self.parse_rdata(rr_type, position, rdata_end)?
                    };
                    let record = Record::from_parts_unchecked(
                        owner,
                        rr_type,
                        class,
                        Ttl::from_wire(ttl_raw),
                        rdata,
                    );
                    match index {
                        0 => answers.push(record),
                        1 => authority.push(record),
                        _ => additional.push(record),
                    }
                }
                position = rdata_end;
            }
        }

        if position > self.buf.len() {
            return Err(DecodeError::Truncated {
                offset: position,
                field: "message",
            });
        }
        if position != self.buf.len() {
            return Err(DecodeError::TrailingBytes { offset: position });
        }

        let mut message = Message::new(id, flags);
        for question in questions {
            message.add_question(question);
        }
        for record in answers {
            message.add_answer(record);
        }
        for record in authority {
            message.add_authority(record);
        }
        for record in additional {
            message.add_additional(record);
        }
        message.set_edns(edns);
        Ok(message)
    }

    fn parse_opt(
        &self,
        class: Rclass,
        ttl_raw: u32,
        start: usize,
        end: usize,
    ) -> Result<Edns, DecodeError> {
        let [extended, version, high, low] = ttl_raw.to_be_bytes();
        let flags = u16::from_be_bytes([high, low]);
        let mut edns = Edns::new(class.as_u16())
            .with_extended_rcode(extended)
            .with_version(version)
            .with_flags(flags);

        let mut position = start;
        while position < end {
            let code = self.u16_at(position, "edns option code")?;
            position = position.saturating_add(2);
            let length = usize::from(self.u16_at(position, "edns option length")?);
            position = position.saturating_add(2);
            let data_end = position
                .checked_add(length)
                .ok_or(DecodeError::OptTruncated { offset: position })?;
            if data_end > end {
                return Err(DecodeError::OptTruncated { offset: position });
            }
            let data = self
                .buf
                .get(position..data_end)
                .ok_or(DecodeError::OptTruncated { offset: position })?;
            let option = EdnsOption::new(code, data).map_err(|_| DecodeError::InvalidOpt {
                reason: "option data too long",
            })?;
            edns.push_option(option)
                .map_err(|_| DecodeError::InvalidOpt {
                    reason: "too many options",
                })?;
            position = data_end;
        }
        Ok(edns)
    }

    fn parse_rdata(&self, rr_type: Rtype, start: usize, end: usize) -> Result<Rdata, DecodeError> {
        let mut reader = RdataReader {
            decoder: self,
            position: start,
            end,
            rr_type,
        };
        let rdata = reader.parse_fields()?;
        reader.finish()?;
        Ok(rdata)
    }

    fn u16_at(&self, offset: usize, field: &'static str) -> Result<u16, DecodeError> {
        let bytes = self.slice_at(offset, 2, field)?;
        let Ok(array) = <[u8; 2]>::try_from(bytes) else {
            return Err(DecodeError::Truncated { offset, field });
        };
        Ok(u16::from_be_bytes(array))
    }

    fn u32_at(&self, offset: usize, field: &'static str) -> Result<u32, DecodeError> {
        let bytes = self.slice_at(offset, 4, field)?;
        let Ok(array) = <[u8; 4]>::try_from(bytes) else {
            return Err(DecodeError::Truncated { offset, field });
        };
        Ok(u32::from_be_bytes(array))
    }

    fn slice_at(
        &self,
        offset: usize,
        length: usize,
        field: &'static str,
    ) -> Result<&'a [u8], DecodeError> {
        let end = offset
            .checked_add(length)
            .ok_or(DecodeError::Truncated { offset, field })?;
        self.buf
            .get(offset..end)
            .ok_or(DecodeError::Truncated { offset, field })
    }

    /// Читает имя, начиная с `start`; возвращает имя и позицию после него.
    ///
    /// `allow_compression == false` запрещает указатели (для RDATA-полей,
    /// где RFC 1035/2782/4034/9460 их не допускают).
    ///
    /// Указатель обязан:
    /// - идти строго назад и не в заголовок (`target >= 12`);
    /// - указывать на уже встреченное начало метки, терминатор или начало
    ///   сжатого имени (позиция указателя). Так отвергаются указатели в
    ///   середину метки; pointer-to-pointer допускается, потому что это
    ///   начало сжатого имени.
    #[allow(clippy::too_many_lines)]
    fn name_at(&self, start: usize, allow_compression: bool) -> Result<(Name, usize), DecodeError> {
        let mut position = start;
        let mut wire = [0_u8; MAX_NAME_WIRE_LEN];
        let mut written = 0_usize;
        let mut end_of_name: Option<usize> = None;
        let mut jumps = 0_usize;
        let mut labels = 0_usize;
        self.valid_starts.borrow_mut().insert(start);

        loop {
            let Some(&octet) = self.buf.get(position) else {
                return Err(DecodeError::Truncated {
                    offset: position,
                    field: "name",
                });
            };
            if octet == 0 {
                self.valid_starts.borrow_mut().insert(position);
                position = position.saturating_add(1);
                if let Some(slot) = wire.get_mut(written) {
                    *slot = 0;
                    written = written.saturating_add(1);
                }
                break;
            }
            if octet & 0xC0 == 0xC0 {
                if !allow_compression || !self.allow_compression {
                    return Err(DecodeError::BadLabelType {
                        offset: position,
                        value: octet,
                    });
                }
                let Some(&low) = self.buf.get(position + 1) else {
                    return Err(DecodeError::Truncated {
                        offset: position,
                        field: "compression pointer",
                    });
                };
                let target = (usize::from(octet & 0x3F) << 8) | usize::from(low);
                if target >= position {
                    return Err(DecodeError::ForwardPointer {
                        offset: position,
                        target,
                    });
                }
                if target < 12 {
                    return Err(DecodeError::PointerIntoHeader {
                        offset: position,
                        target,
                    });
                }
                if !self.valid_starts.borrow().contains(&target) {
                    return Err(DecodeError::PointerNotLabelStart {
                        offset: position,
                        target,
                    });
                }
                // Указатель сам является началом сжатого имени: на него можно
                // ссылаться из последующих имён (pointer-to-pointer).
                self.valid_starts.borrow_mut().insert(position);
                if end_of_name.is_none() {
                    end_of_name = Some(position.saturating_add(2));
                }
                jumps = jumps.saturating_add(1);
                if jumps > MAX_COMPRESSION_POINTERS {
                    return Err(DecodeError::TooManyPointers {
                        offset: position,
                        limit: MAX_COMPRESSION_POINTERS,
                    });
                }
                position = target;
                continue;
            }
            if octet & 0xC0 != 0 {
                return Err(DecodeError::BadLabelType {
                    offset: position,
                    value: octet,
                });
            }
            self.valid_starts.borrow_mut().insert(position);
            let length = usize::from(octet);
            let label_start = position.saturating_add(1);
            let label_end = label_start.saturating_add(length);
            let Some(label) = self.buf.get(label_start..label_end) else {
                return Err(DecodeError::Truncated {
                    offset: label_start,
                    field: "label",
                });
            };
            labels = labels.saturating_add(1);
            if labels > MAX_LABELS {
                return Err(DecodeError::NameTooLong {
                    offset: start,
                    max: MAX_NAME_WIRE_LEN,
                });
            }
            let Some(slot) = wire.get_mut(written) else {
                return Err(DecodeError::NameTooLong {
                    offset: start,
                    max: MAX_NAME_WIRE_LEN,
                });
            };
            *slot = u8::try_from(length).map_err(|_| DecodeError::NameTooLong {
                offset: start,
                max: MAX_NAME_WIRE_LEN,
            })?;
            written = written.saturating_add(1);
            let Some(dst) = wire.get_mut(written..written + length) else {
                return Err(DecodeError::NameTooLong {
                    offset: start,
                    max: MAX_NAME_WIRE_LEN,
                });
            };
            for (dst, src) in dst.iter_mut().zip(label) {
                *dst = src.to_ascii_lowercase();
            }
            written = written.saturating_add(length);
            position = label_end;
        }

        let end = end_of_name.unwrap_or(position);
        let Some(raw) = wire.get(..written) else {
            return Err(DecodeError::NameTooLong {
                offset: start,
                max: MAX_NAME_WIRE_LEN,
            });
        };
        let name = Name::from_wire(raw).map_err(|source| DecodeError::InvalidName {
            offset: start,
            source,
        })?;
        Ok((name, end))
    }
}

struct RdataReader<'a, 'b> {
    decoder: &'a Decoder<'b>,
    position: usize,
    end: usize,
    rr_type: Rtype,
}

#[allow(clippy::elidable_lifetime_names)]
impl<'a, 'b> RdataReader<'a, 'b> {
    #[allow(clippy::too_many_lines)]
    fn parse_fields(&mut self) -> Result<Rdata, DecodeError> {
        match self.rr_type {
            Rtype::A => {
                let octets = self.take_array::<4>("A address")?;
                Ok(Rdata::A(Ipv4Addr::from(octets)))
            }
            Rtype::AAAA => {
                let octets = self.take_array::<16>("AAAA address")?;
                Ok(Rdata::Aaaa(Ipv6Addr::from(octets)))
            }
            Rtype::NS => Ok(Rdata::Ns(self.name(true)?)),
            Rtype::CNAME => Ok(Rdata::Cname(self.name(true)?)),
            Rtype::PTR => Ok(Rdata::Ptr(self.name(true)?)),
            Rtype::DNAME => Ok(Rdata::Dname(self.name(false)?)),
            Rtype::SOA => {
                let mname = self.name(true)?;
                let rname = self.name(true)?;
                let serial = crate::domain::Serial::from_wire(self.u32("serial")?);
                let refresh = self.u32("refresh")?;
                let retry = self.u32("retry")?;
                let expire = self.u32("expire")?;
                let minimum = self.u32("minimum")?;
                Ok(Rdata::Soa(SoaData::new(
                    mname, rname, serial, refresh, retry, expire, minimum,
                )))
            }
            Rtype::MX => {
                let preference = self.u16("preference")?;
                let exchange = self.name(true)?;
                Ok(Rdata::Mx {
                    preference,
                    exchange,
                })
            }
            Rtype::TXT => {
                let mut segments = Vec::new();
                while self.remaining() > 0 {
                    let length = usize::from(self.u8("txt length")?);
                    segments.push(self.take(length, "txt segment")?.to_vec());
                }
                let text = TxtData::new(segments).map_err(|source| self.invalid(source))?;
                Ok(Rdata::Txt(text))
            }
            Rtype::SRV => {
                let priority = self.u16("priority")?;
                let weight = self.u16("weight")?;
                let port = self.u16("port")?;
                let target = self.name(false)?;
                Ok(Rdata::Srv {
                    priority,
                    weight,
                    port,
                    target,
                })
            }
            Rtype::CAA => {
                let flags = self.u8("flags")?;
                let tag_length = usize::from(self.u8("tag length")?);
                let tag = CaaTag::new(self.take(tag_length, "tag")?)
                    .map_err(|source| self.invalid(source))?;
                let value = self.rest().to_vec();
                Ok(Rdata::Caa { flags, tag, value })
            }
            Rtype::DS => {
                let key_tag = self.u16("key tag")?;
                let algorithm = self.u8("algorithm")?;
                let digest_type = self.u8("digest type")?;
                let digest = self.rest().to_vec();
                let ds = DsData::new(key_tag, algorithm, digest_type, digest)
                    .map_err(|source| self.invalid(source))?;
                Ok(Rdata::Ds(ds))
            }
            Rtype::DNSKEY => {
                let flags = self.u16("flags")?;
                let protocol = self.u8("protocol")?;
                let algorithm = self.u8("algorithm")?;
                let public_key = self.rest().to_vec();
                let key = DnskeyData::new(flags, protocol, algorithm, public_key)
                    .map_err(|source| self.invalid(source))?;
                Ok(Rdata::Dnskey(key))
            }
            Rtype::RRSIG => {
                let type_covered = Rtype::from_u16(self.u16("type covered")?);
                let algorithm = self.u8("algorithm")?;
                let labels = self.u8("labels")?;
                let original_ttl = self.u32("original ttl")?;
                let expiration = self.u32("signature expiration")?;
                let inception = self.u32("signature inception")?;
                let key_tag = self.u16("key tag")?;
                let signer_name = self.name(false)?;
                let signature = self.rest().to_vec();
                let rrsig = RrsigData::new(
                    type_covered,
                    algorithm,
                    labels,
                    original_ttl,
                    expiration,
                    inception,
                    key_tag,
                    signer_name,
                    signature,
                )
                .map_err(|source| self.invalid(source))?;
                Ok(Rdata::Rrsig(rrsig))
            }
            Rtype::NSEC => {
                let next_domain = self.name(false)?;
                let bitmap = TypeBitmap::new(self.rest()).map_err(|source| self.invalid(source))?;
                let nsec =
                    NsecData::new(next_domain, bitmap).map_err(|source| self.invalid(source))?;
                Ok(Rdata::Nsec(nsec))
            }
            Rtype::NSEC3 => {
                let hash_algorithm = self.u8("hash algorithm")?;
                let nsec_flags = self.u8("flags")?;
                let iterations = self.u16("iterations")?;
                let salt_length = usize::from(self.u8("salt length")?);
                let salt = self.take(salt_length, "salt")?.to_vec();
                let hash_length = usize::from(self.u8("hash length")?);
                let next_hashed_owner = self.take(hash_length, "next hashed owner")?.to_vec();
                let bitmap = TypeBitmap::new_allow_empty(self.rest())
                    .map_err(|source| self.invalid(source))?;
                let nsec3 = Nsec3Data::new(
                    hash_algorithm,
                    nsec_flags,
                    iterations,
                    salt,
                    next_hashed_owner,
                    bitmap,
                )
                .map_err(|source| self.invalid(source))?;
                Ok(Rdata::Nsec3(nsec3))
            }
            Rtype::NSEC3PARAM => {
                let hash_algorithm = self.u8("hash algorithm")?;
                let nsec_flags = self.u8("flags")?;
                let iterations = self.u16("iterations")?;
                let salt_length = usize::from(self.u8("salt length")?);
                let salt = self.take(salt_length, "salt")?.to_vec();
                let param = Nsec3ParamData::new(hash_algorithm, nsec_flags, iterations, salt)
                    .map_err(|source| self.invalid(source))?;
                Ok(Rdata::Nsec3Param(param))
            }
            Rtype::TLSA => {
                let usage = self.u8("usage")?;
                let selector = self.u8("selector")?;
                let matching = self.u8("matching")?;
                let data = self.rest().to_vec();
                let tlsa = TlsaData::new(usage, selector, matching, data)
                    .map_err(|source| self.invalid(source))?;
                Ok(Rdata::Tlsa(tlsa))
            }
            Rtype::SVCB | Rtype::HTTPS => {
                let priority = self.u16("priority")?;
                let target = self.name(false)?;
                let mut params = Vec::new();
                while self.remaining() > 0 {
                    let key = self.u16("svcparam key")?;
                    let length = usize::from(self.u16("svcparam length")?);
                    let value = self.take(length, "svcparam value")?.to_vec();
                    let param = SvcParam::new(key, value).map_err(|source| self.invalid(source))?;
                    params.push(param);
                }
                let svcb = SvcbData::new(priority, target, params)
                    .map_err(|source| self.invalid(source))?;
                if self.rr_type == Rtype::SVCB {
                    Ok(Rdata::Svcb(svcb))
                } else {
                    Ok(Rdata::Https(svcb))
                }
            }
            Rtype::OPT => Err(DecodeError::OptAsRdata),
            other => {
                let bytes = self.rest().to_vec();
                Ok(Rdata::Unknown {
                    rr_type: other,
                    rdata: bytes,
                })
            }
        }
    }

    fn finish(&self) -> Result<(), DecodeError> {
        if self.position != self.end {
            return Err(DecodeError::RdataTrailing {
                rr_type: self.rr_type,
                offset: self.position,
            });
        }
        Ok(())
    }

    fn remaining(&self) -> usize {
        self.end.saturating_sub(self.position)
    }

    fn take(&mut self, length: usize, field: &'static str) -> Result<&'b [u8], DecodeError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(DecodeError::RdataTruncated {
                rr_type: self.rr_type,
                field,
            })?;
        if end > self.end {
            return Err(DecodeError::RdataTruncated {
                rr_type: self.rr_type,
                field,
            });
        }
        let bytes =
            self.decoder
                .buf
                .get(self.position..end)
                .ok_or(DecodeError::RdataTruncated {
                    rr_type: self.rr_type,
                    field,
                })?;
        self.position = end;
        Ok(bytes)
    }

    fn rest(&mut self) -> &'b [u8] {
        let start = self.position;
        let end = self.end;
        self.position = end;
        self.decoder.buf.get(start..end).unwrap_or(&[])
    }

    fn take_array<const N: usize>(&mut self, field: &'static str) -> Result<[u8; N], DecodeError> {
        let bytes = self.take(N, field)?;
        <[u8; N]>::try_from(bytes).map_err(|_| DecodeError::RdataTruncated {
            rr_type: self.rr_type,
            field,
        })
    }

    fn u8(&mut self, field: &'static str) -> Result<u8, DecodeError> {
        let bytes = self.take(1, field)?;
        bytes.first().copied().ok_or(DecodeError::RdataTruncated {
            rr_type: self.rr_type,
            field,
        })
    }

    fn u16(&mut self, field: &'static str) -> Result<u16, DecodeError> {
        Ok(u16::from_be_bytes(self.take_array::<2>(field)?))
    }

    fn u32(&mut self, field: &'static str) -> Result<u32, DecodeError> {
        Ok(u32::from_be_bytes(self.take_array::<4>(field)?))
    }

    fn name(&mut self, allow_compression: bool) -> Result<Name, DecodeError> {
        let (name, next) = self.decoder.name_at(self.position, allow_compression)?;
        if next > self.end {
            return Err(DecodeError::RdataTruncated {
                rr_type: self.rr_type,
                field: "name",
            });
        }
        self.position = next;
        Ok(name)
    }

    fn invalid(&self, source: RdataError) -> DecodeError {
        DecodeError::RdataInvalid {
            rr_type: self.rr_type,
            source,
        }
    }
}
