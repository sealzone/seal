use seal_crypto::TicketKey;
use seal_proto::identity::{ProofContext, ProofPurpose};
use seal_proto::{TenantId, TrustedTime};

use crate::AuthzError;

/// The context names `tenant`, this enclave's `tls_spki_sha256`, exactly `purpose`,
/// and carries a ticket that `ticket_key` issued for `tenant` and has not expired.
pub(crate) fn check_context(
    ctx: &ProofContext,
    tenant: &TenantId,
    tls_spki_sha256: &[u8; 32],
    purpose: &ProofPurpose,
    ticket_key: &TicketKey,
    time: &TrustedTime,
) -> Result<(), AuthzError> {
    if &ctx.tenant != tenant {
        return Err(AuthzError::not_allowed("proof context names another tenant"));
    }
    if &ctx.tls_spki_sha256 != tls_spki_sha256 {
        return Err(AuthzError::not_allowed("proof context names another enclave key"));
    }
    if &ctx.purpose != purpose {
        return Err(AuthzError::not_allowed("proof context is for another request"));
    }
    ticket_key.verify(tenant, &ctx.ticket, time).map_err(|_| AuthzError::not_allowed("proof ticket invalid or expired"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{acme, other_tenant, service_keys, T};
    use seal_proto::ErrorCode;

    fn purpose(b: u8) -> ProofPurpose {
        ProofPurpose::Session { request_digest: [b; 32] }
    }

    #[test]
    fn every_field_is_checked() {
        let keys = service_keys();
        let spki = keys.tls.spki_sha256();
        let now = TrustedTime::exact(T);
        let ticket = keys.ticket.issue(&acme(), &now, &mut seal_crypto::UnwrapErr(seal_crypto::SysRng));
        let ctx = ProofContext { tenant: acme(), purpose: purpose(1), tls_spki_sha256: spki, ticket: ticket.clone() };
        let check = |ctx: &ProofContext, tenant: &TenantId, spki: &[u8; 32], p: &ProofPurpose, time: &TrustedTime| {
            check_context(ctx, tenant, spki, p, &keys.ticket, time)
        };
        check(&ctx, &acme(), &spki, &purpose(1), &now).unwrap();

        let denied = |r: Result<(), AuthzError>| assert_eq!(r.unwrap_err().code(), ErrorCode::NotAllowed);
        // Another tenant: in the context, or the enclave's.
        denied(check(&ProofContext { tenant: other_tenant(), ..ctx.clone() }, &acme(), &spki, &purpose(1), &now));
        denied(check(&ctx, &other_tenant(), &spki, &purpose(1), &now));
        // Another enclave's TLS key.
        denied(check(&ProofContext { tls_spki_sha256: [9; 32], ..ctx.clone() }, &acme(), &spki, &purpose(1), &now));
        // Another request, or another kind of request with the same digest.
        denied(check(&ctx, &acme(), &spki, &purpose(2), &now));
        denied(check(&ctx, &acme(), &spki, &ProofPurpose::Seal { request_digest: [1; 32] }, &now));
        // Expired ticket (latest end of the interval), forged ticket.
        denied(check(&ctx, &acme(), &spki, &purpose(1), &TrustedTime::exact(ticket.expires_at)));
        denied(check(&ctx, &acme(), &spki, &purpose(1), &TrustedTime { now: ticket.expires_at - 5, radius: 5 }));
        let mut forged = ctx.clone();
        forged.ticket.mac[0] ^= 1;
        denied(check(&forged, &acme(), &spki, &purpose(1), &now));
        let mut stretched = ctx.clone();
        stretched.ticket.expires_at += 3600;
        denied(check(&stretched, &acme(), &spki, &purpose(1), &now));
        // A ticket issued for another tenant under the same key.
        let foreign = keys.ticket.issue(&other_tenant(), &now, &mut seal_crypto::UnwrapErr(seal_crypto::SysRng));
        denied(check(&ProofContext { ticket: foreign, ..ctx.clone() }, &acme(), &spki, &purpose(1), &now));
    }
}
