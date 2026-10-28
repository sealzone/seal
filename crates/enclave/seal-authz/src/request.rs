//! One owner checks expected request purpose, ticket, enclave identity and provider proof.
use crate::context::check_context;
use crate::identity::{IdentityVerifier, ProofVerifier};
use crate::{AuthenticatedCaller, AuthzError};
use seal_proto::{
    api::{ExtendRequest, SessionRequest, SignalRequest},
    identity::{IdentityMatcher, IdentityProof, ProofContext, ProofPurpose},
    ErrorCode, TrustedTime,
};
use seal_verify::VerifiedTenant;
use std::sync::Arc;

pub struct AuthenticatedRequest<T> {
    request: T,
    caller: AuthenticatedCaller,
}
impl<T> AuthenticatedRequest<T> {
    pub(crate) fn new(request: T, caller: AuthenticatedCaller) -> Self {
        Self { request, caller }
    }
    pub fn request(&self) -> &T {
        &self.request
    }
    pub fn caller(&self) -> &AuthenticatedCaller {
        &self.caller
    }
}

/// Checks a request's proof context against the enclave's tenant (`tenant.state().tenant`),
/// TLS key and ticket key with the purpose computed from the request, then its identity proof
/// against the tenant's app matchers.
pub struct RequestAuthenticator {
    verifier: Box<dyn IdentityVerifier>,
    ticket_key: Arc<seal_crypto::TicketKey>,
    tls_spki_sha256: [u8; 32],
}
impl RequestAuthenticator {
    pub fn new(
        https: Arc<seal_net::HttpsClient>,
        ticket_key: Arc<seal_crypto::TicketKey>,
        tls_spki_sha256: [u8; 32],
    ) -> Self {
        Self::with_verifier(Box::new(ProofVerifier::new(https)), ticket_key, tls_spki_sha256)
    }

    pub(crate) fn with_verifier(
        verifier: Box<dyn IdentityVerifier>,
        ticket_key: Arc<seal_crypto::TicketKey>,
        tls_spki_sha256: [u8; 32],
    ) -> Self {
        Self { verifier, ticket_key, tls_spki_sha256 }
    }

    async fn authenticate<T>(
        &self,
        request: T,
        parts: impl Fn(&T) -> (&ProofContext, &IdentityProof, ProofPurpose),
        tenant: &VerifiedTenant,
        time: &TrustedTime,
    ) -> Result<AuthenticatedRequest<T>, AuthzError> {
        let (ctx, proof, purpose) = parts(&request);
        let state = tenant.state();
        check_context(ctx, &state.tenant, &self.tls_spki_sha256, &purpose, &self.ticket_key, time)?;
        let mut candidates: Vec<IdentityMatcher> = state.apps.values().flatten().cloned().collect();
        candidates.sort();
        candidates.dedup();
        let caller = self.verifier.verify(proof, ctx, &candidates, time).await?;
        Ok(AuthenticatedRequest::new(request, caller))
    }

    /// Every method checks request.expected_purpose(); callers never supply the expected digest.
    /// App-key proofs bind this request; OIDC proofs retain their bearer/channel limitations.
    pub async fn session(
        &self,
        request: SessionRequest,
        tenant: &VerifiedTenant,
        time: &TrustedTime,
    ) -> Result<AuthenticatedRequest<SessionRequest>, AuthzError> {
        self.authenticate(request, |r| (&r.context, &r.proof, r.expected_purpose()), tenant, time).await
    }
    pub async fn extend(
        &self,
        request: ExtendRequest,
        tenant: &VerifiedTenant,
        time: &TrustedTime,
    ) -> Result<AuthenticatedRequest<ExtendRequest>, AuthzError> {
        self.authenticate(request, |r| (&r.context, &r.proof, r.expected_purpose()), tenant, time).await
    }
    pub async fn signal(
        &self,
        request: SignalRequest,
        tenant: &VerifiedTenant,
        time: &TrustedTime,
    ) -> Result<AuthenticatedRequest<SignalRequest>, AuthzError> {
        // The self credential arrives as a pair; the external credential never reaches here.
        if request.context.is_none() || request.proof.is_none() {
            return Err(AuthzError::denied(ErrorCode::BadRequest, "a self-signal needs its proof"));
        }
        self.authenticate(
            request,
            |r| (r.context.as_ref().expect("checked"), r.proof.as_ref().expect("checked"), r.expected_purpose()),
            tenant,
            time,
        )
        .await
    }
}
