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
    let deadline = ctx.deadline();
    let question = Question::new(qname.clone(), qtype, Rclass::IN);
    let mut last_error: Option<ResolverError> = None;

    for (index, address) in candidates {
        match resolver
            .upstream()
            .query(address, &question, true, dnssec_ok, deadline, ctx.cancel())
        {
            Ok(response) => {
                let rcode = response.message.rcode();
                if is_retryable_rcode(rcode) {
                    resolver.forwarder_failure(index);
                    last_error = Some(ResolverError::UpstreamRcode {
                        server: address.to_string(),
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
                if matches!(error, ResolverError::Cancelled | ResolverError::Timeout) {
                    resolver.forwarder_failure(index);
                    if matches!(error, ResolverError::Cancelled) {
                        return Err(error);
                    }
                } else {
                    resolver.forwarder_failure(index);
                }
                last_error = Some(error);
            }
        }
    }

    Err(last_error.unwrap_or(ResolverError::NoUpstream))
}
