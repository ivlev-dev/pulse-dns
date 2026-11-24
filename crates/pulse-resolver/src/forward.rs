//! Forward-режим: пересылка на рекурсивные серверы с health/failover.

use pulse_dns::{Name, Question, Rclass, Rtype};

use crate::error::ResolverError;
use crate::resolver::{Resolution, ResolveContext, Resolver};
use crate::upstream::is_retryable_rcode;

pub(crate) fn resolve(
    resolver: &Resolver,
    qname: &Name,
    qtype: Rtype,
    dnssec_ok: bool,
    ctx: &ResolveContext,
) -> Result<Resolution, ResolverError> {
    let candidates = resolver.forwarder_order();
    if candidates.is_empty() {
        return Err(ResolverError::NoUpstream);
    }
    let question = Question::new(qname.clone(), qtype, Rclass::IN);
    let mut last_error: Option<ResolverError> = None;
    let mut position = 0_usize;

    for index in candidates {
        if position > 0 {
            resolver.note_failover();
        }
        position = position.saturating_add(1);
        match resolver.query_forwarder(index, &question, dnssec_ok, ctx) {
            Ok(response) => {
                let rcode = response.message.rcode();
                if is_retryable_rcode(rcode) {
                    resolver.forwarder_failure(index);
                    last_error = Some(ResolverError::UpstreamRcode {
                        server: resolver
                            .forwarder_config(index)
                            .map_or_else(|| "upstream".to_owned(), ToString::to_string),
                        rcode,
                    });
                    continue;
                }
                resolver.forwarder_success(index);
                let message = response.message;
                return Ok(Resolution {
                    rcode,
                    answers: message.answers().to_vec(),
                    authority: message.authority().to_vec(),
                    additional: message.additional().to_vec(),
                    zone: Name::root(),
                });
            }
            Err(error) => {
                resolver.forwarder_failure(index);
                if matches!(error, ResolverError::Cancelled) {
                    return Err(error);
                }
                last_error = Some(error);
            }
        }
    }

    Err(last_error.unwrap_or(ResolverError::NoUpstream))
}
