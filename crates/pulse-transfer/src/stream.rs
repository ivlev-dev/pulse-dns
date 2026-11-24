//! Чтение и проверка потока ответов AXFR/IXFR.

use std::io::Read;

use pulse_dns::{Message, Opcode};

use crate::error::TransferError;
use crate::net::read_message;
use crate::tsig::{TsigEnvelope, TsigKey, TsigRecord, TsigStreamVerifier};
use crate::zone::{Deadline, TransferLimits, check_byte_limit, check_message_limit};

pub(crate) struct ResponseMessage {
    pub(crate) message: Message,
    pub(crate) tsig: Option<TsigRecord>,
}

pub(crate) struct ResponseReader<'a, S> {
    stream: &'a mut S,
    limits: TransferLimits,
    verifier: Option<TsigStreamVerifier<'a>>,
    key_present: bool,
    expected_id: u16,
    deadline: Deadline,
    messages: usize,
    bytes: u64,
}

impl<'a, S: Read> ResponseReader<'a, S> {
    pub(crate) fn new(
        stream: &'a mut S,
        limits: TransferLimits,
        key: Option<&'a TsigKey>,
        request_mac: Option<Vec<u8>>,
        expected_id: u16,
    ) -> Self {
        let verifier = match (key, request_mac) {
            (Some(key), Some(mac)) => Some(TsigStreamVerifier::new(key, mac, expected_id)),
            _ => None,
        };
        Self {
            stream,
            limits,
            verifier,
            key_present: key.is_some(),
            expected_id,
            deadline: Deadline::new(&limits),
            messages: 0,
            bytes: 0,
        }
    }

    pub(crate) fn next(&mut self, now: u64) -> Result<ResponseMessage, TransferError> {
        self.deadline.check()?;
        check_message_limit(&self.limits, self.messages.saturating_add(1))?;
        let raw = read_message(self.stream)?;
        self.messages = self.messages.saturating_add(1);
        self.bytes = self.bytes.saturating_add(raw.len() as u64);
        check_byte_limit(&self.limits, self.bytes)?;

        let envelope: Option<TsigEnvelope> = if self.key_present {
            self.verifier
                .as_mut()
                .ok_or_else(|| TransferError::protocol("TSIG verifier is not initialized"))?
                .verify_message(&raw, now)?
        } else {
            if crate::tsig::parse_tsig(&raw)?.is_some() {
                return Err(TransferError::Tsig(crate::error::TsigError::Unexpected));
            }
            None
        };

        let (message, tsig) = if let Some(envelope) = envelope {
            let message = Message::decode(envelope.message(), &self.limits.decode)?;
            (message, Some(envelope.record().clone()))
        } else {
            let message = Message::decode(&raw, &self.limits.decode)?;
            (message, None)
        };

        if message.id() != self.expected_id {
            return Err(TransferError::protocol(
                "response ID does not match query ID",
            ));
        }
        if !message.flags().qr() {
            return Err(TransferError::protocol("response has QR=0"));
        }
        if message.opcode() != Opcode::QUERY {
            return Err(TransferError::protocol("response has non-QUERY opcode"));
        }
        Ok(ResponseMessage { message, tsig })
    }
}
