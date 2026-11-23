//! Энкодер wire-формата с опциональной компрессией имён.

use std::collections::HashMap;

use crate::domain::{Edns, Message, Name, Record};
use crate::wire::{EncodeError, EncodeOptions, MAX_MESSAGE_LEN, MAX_RECORDS};

use super::rdata::{RdataOut, write_rdata};

pub(crate) fn encode_message(
    message: &Message,
    options: EncodeOptions,
) -> Result<Vec<u8>, EncodeError> {
    let question_count = message.questions().len();
    let answer_count = message.answers().len();
    let authority_count = message.authority().len();
    let additional_records = message.additional().len();
    let additional_count = additional_records.saturating_add(usize::from(message.edns().is_some()));

    for (section, count) in [
        ("question", question_count),
        ("answer", answer_count),
        ("authority", authority_count),
        ("additional", additional_count),
    ] {
        if count > usize::from(u16::MAX) {
            return Err(EncodeError::SectionTooLarge {
                section,
                count,
                max: usize::from(u16::MAX),
            });
        }
    }
    let record_total = answer_count
        .saturating_add(authority_count)
        .saturating_add(additional_count);
    if record_total > MAX_RECORDS {
        return Err(EncodeError::SectionTooLarge {
            section: "records",
            count: record_total,
            max: MAX_RECORDS,
        });
    }
    if question_count > MAX_RECORDS {
        return Err(EncodeError::SectionTooLarge {
            section: "question",
            count: question_count,
            max: MAX_RECORDS,
        });
    }

    let mut writer = Writer {
        out: Vec::with_capacity(512),
        compress: options.compress_names,
        names: HashMap::new(),
    };

    writer.out.extend_from_slice(&message.id().to_be_bytes());
    writer
        .out
        .extend_from_slice(&message.flags().bits().to_be_bytes());
    writer
        .out
        .extend_from_slice(&count_u16(question_count).to_be_bytes());
    writer
        .out
        .extend_from_slice(&count_u16(answer_count).to_be_bytes());
    writer
        .out
        .extend_from_slice(&count_u16(authority_count).to_be_bytes());
    writer
        .out
        .extend_from_slice(&count_u16(additional_count).to_be_bytes());

    for question in message.questions() {
        writer.write_name(question.qname(), true);
        writer
            .out
            .extend_from_slice(&question.qtype().as_u16().to_be_bytes());
        writer
            .out
            .extend_from_slice(&question.qclass().as_u16().to_be_bytes());
        writer.check_size()?;
    }

    for record in message.answers() {
        writer.write_record(record)?;
    }
    for record in message.authority() {
        writer.write_record(record)?;
    }
    for record in message.additional() {
        writer.write_record(record)?;
    }
    if let Some(edns) = message.edns() {
        writer.write_opt(edns)?;
    }

    writer.check_size()?;
    Ok(writer.out)
}

struct Writer {
    out: Vec<u8>,
    compress: bool,
    names: HashMap<Vec<u8>, u16>,
}

impl Writer {
    fn write_record(&mut self, record: &Record) -> Result<(), EncodeError> {
        if record.rdata().rr_type() != record.rr_type() {
            return Err(EncodeError::RecordTypeMismatch {
                declared: record.rr_type(),
                actual: record.rdata().rr_type(),
            });
        }
        if let Err(source) = record.rdata().validate() {
            return Err(EncodeError::InvalidRdata {
                rr_type: record.rr_type(),
                source,
            });
        }
        self.write_name(record.owner(), true);
        self.out
            .extend_from_slice(&record.rr_type().as_u16().to_be_bytes());
        self.out
            .extend_from_slice(&record.class().as_u16().to_be_bytes());
        self.out
            .extend_from_slice(&record.ttl().as_u32().to_be_bytes());
        let length_position = self.out.len();
        self.out.extend_from_slice(&[0, 0]);
        let rdata_start = self.out.len();
        write_rdata(record.rdata(), self);
        let rdata_length = self.out.len().saturating_sub(rdata_start);
        let Ok(length) = u16::try_from(rdata_length) else {
            return Err(EncodeError::RdataTooLong {
                rr_type: record.rr_type(),
                len: rdata_length,
            });
        };
        let length_end = length_position.saturating_add(2);
        let Some(slot) = self.out.get_mut(length_position..length_end) else {
            return Err(EncodeError::Internal {
                reason: "rdlength placeholder",
            });
        };
        slot.copy_from_slice(&length.to_be_bytes());
        self.check_size()
    }

    fn write_opt(&mut self, edns: &Edns) -> Result<(), EncodeError> {
        self.out.push(0);
        self.out
            .extend_from_slice(&crate::domain::Rtype::OPT.as_u16().to_be_bytes());
        self.out
            .extend_from_slice(&edns.udp_payload_size().to_be_bytes());
        let ttl = (u32::from(edns.extended_rcode()) << 24)
            | (u32::from(edns.version()) << 16)
            | u32::from(edns.flags());
        self.out.extend_from_slice(&ttl.to_be_bytes());
        let length_position = self.out.len();
        self.out.extend_from_slice(&[0, 0]);
        let rdata_start = self.out.len();
        for option in edns.options() {
            self.out.extend_from_slice(&option.code().to_be_bytes());
            let length =
                u16::try_from(option.data().len()).map_err(|_| EncodeError::SectionTooLarge {
                    section: "edns option",
                    count: option.data().len(),
                    max: usize::from(u16::MAX),
                })?;
            self.out.extend_from_slice(&length.to_be_bytes());
            self.out.extend_from_slice(option.data());
            self.check_size()?;
        }
        let rdata_length = self.out.len().saturating_sub(rdata_start);
        let Ok(length) = u16::try_from(rdata_length) else {
            return Err(EncodeError::SectionTooLarge {
                section: "edns options",
                count: rdata_length,
                max: usize::from(u16::MAX),
            });
        };
        let length_end = length_position.saturating_add(2);
        let Some(slot) = self.out.get_mut(length_position..length_end) else {
            return Err(EncodeError::Internal {
                reason: "opt rdlength placeholder",
            });
        };
        slot.copy_from_slice(&length.to_be_bytes());
        self.check_size()
    }

    fn write_name(&mut self, name: &Name, compressible: bool) {
        let wire = name.as_wire();
        if !self.compress || !compressible {
            self.out.extend_from_slice(wire);
            return;
        }

        let mut offsets = Vec::new();
        let mut position = 0_usize;
        while let Some(&length) = wire.get(position) {
            if length == 0 {
                break;
            }
            offsets.push(position);
            position = position.saturating_add(1 + usize::from(length));
        }

        let mut chosen: Option<(usize, u16)> = None;
        for (index, &offset) in offsets.iter().enumerate() {
            let Some(suffix) = wire.get(offset..) else {
                continue;
            };
            if let Some(&target) = self.names.get(suffix) {
                chosen = Some((index, target));
                break;
            }
        }

        let output_start = self.out.len();
        let written_labels = chosen.map_or(offsets.len(), |(index, _)| index);
        for &offset in offsets.iter().take(written_labels) {
            self.register(wire, offset, output_start);
        }

        let prefix_end = chosen
            .and_then(|(index, _)| offsets.get(index).copied())
            .unwrap_or(wire.len());
        match wire.get(..prefix_end) {
            Some(prefix) => self.out.extend_from_slice(prefix),
            None => self.out.extend_from_slice(wire),
        }
        if let Some((_, target)) = chosen {
            self.out
                .extend_from_slice(&(0xC000_u16 | target).to_be_bytes());
        }
    }

    fn register(&mut self, wire: &[u8], offset: usize, output_start: usize) {
        let absolute = output_start.saturating_add(offset);
        let Ok(absolute) = u16::try_from(absolute) else {
            return;
        };
        if absolute >= 0x4000 {
            return;
        }
        if let Some(suffix) = wire.get(offset..) {
            self.names.entry(suffix.to_vec()).or_insert(absolute);
        }
    }

    fn check_size(&self) -> Result<(), EncodeError> {
        if self.out.len() > MAX_MESSAGE_LEN {
            return Err(EncodeError::MessageTooLong {
                len: self.out.len(),
            });
        }
        Ok(())
    }
}

impl RdataOut for Writer {
    fn bytes(&mut self, value: &[u8]) {
        self.out.extend_from_slice(value);
    }

    fn name(&mut self, name: &Name, compressible: bool) {
        self.write_name(name, compressible);
    }
}

fn count_u16(value: usize) -> u16 {
    u16::try_from(value).unwrap_or(u16::MAX)
}

#[cfg(test)]
mod tests {
    use super::Writer;
    use std::collections::HashMap;

    fn writer() -> Writer {
        Writer {
            out: Vec::new(),
            compress: true,
            names: HashMap::new(),
        }
    }

    #[test]
    fn compression_offsets_are_14_bit() {
        let wire = b"\x01a\x00";
        let mut accepted = writer();
        accepted.register(wire, 0, 0x3FFF);
        assert_eq!(accepted.names.get(wire.as_slice()), Some(&0x3FFF));

        let mut rejected = writer();
        rejected.register(wire, 0, 0x4000);
        assert!(rejected.names.is_empty());
    }
}
