//! Who may do what inside the enclave.
//!
//! - `RequestAuthenticator` checks a request's proof context (tenant, this enclave's TLS key,
//!   the purpose it computes from the request itself, the ticket) and its identity proof
//!   together, and returns an `AuthenticatedRequest`.
//! - `TenantAuthorizer` decides over one verified tenant snapshot, keeping the original
//!   authentication scope, and returns a permit the enclave acts on.
//! - `DeploymentVerifier` checks the enclave deployment's own identity before any key request.
//! - `StateCache` keeps the newest verified state of the enclave's one tenant and never goes back.

#![forbid(unsafe_code)]

pub mod cache;
mod context;
pub mod decide;
mod identity;
pub mod request;

pub use cache::StateCache;
pub use decide::{ExtendPermit, SealPermit, SessionDecision, SessionPermit, SignalPermit, TenantAuthorizer};
pub use identity::{AuthenticatedCaller, DeploymentProof, DeploymentVerifier, MAX_OIDC_TOKEN_AGE_SECS};
pub use request::{AuthenticatedRequest, RequestAuthenticator};

#[cfg(test)]
mod testing;

#[derive(Debug, thiserror::Error)]
pub enum AuthzError {
    /// `reason` is the refusal's fixed sentence; `context`, the values behind it where the
    /// decision has them. Both reach the tenant's telemetry (`RefusalReason`), never the caller.
    #[error("denied: {code:?}: {reason}")]
    Denied {
        code: seal_proto::ErrorCode,
        reason: &'static str,
        context: Option<Box<seal_proto::telemetry::RefusalContext>>,
    },
    #[error("stale state")]
    Stale,
    #[error("identity proof rejected: {0}")]
    BadProof(&'static str),
    /// A service the decision needed did not answer; the text is for the log only.
    #[error("unavailable: {1}")]
    Unavailable(seal_proto::telemetry::Dependency, String),
    /// The endpoint report failed the app's artifact rule. Carries the `artifact-mismatch`
    /// signal (severity `High`, source `Sdk`, the blob's id) for the caller, which the enclave
    /// signs, records and applies.
    #[error("endpoint report fails the artifact rule")]
    ArtifactMismatch(Box<seal_proto::integrity::IntegritySignal>),
}

impl AuthzError {
    pub(crate) fn denied(code: seal_proto::ErrorCode, reason: &'static str) -> Self {
        AuthzError::Denied { code, reason, context: None }
    }
    /// The same denial, with the values that explain it.
    pub(crate) fn with(self, context: seal_proto::telemetry::RefusalContext) -> Self {
        match self {
            AuthzError::Denied { code, reason, .. } => {
                AuthzError::Denied { code, reason, context: Some(Box::new(context)) }
            }
            other => other,
        }
    }

    /// Why, for the tenant's telemetry. A denial carries its own context; a malformed request
    /// or a proof that does not verify says which, in its fixed sentence.
    pub fn context(&self) -> Option<seal_proto::telemetry::RefusalContext> {
        use seal_proto::telemetry::RefusalContext;
        match self {
            AuthzError::Denied { context: Some(context), .. } => Some((**context).clone()),
            AuthzError::Denied { code: seal_proto::ErrorCode::BadRequest, reason, .. } => {
                Some(RefusalContext::Malformed { what: (*reason).into() })
            }
            AuthzError::Denied { .. } => None,
            AuthzError::BadProof(what) => Some(RefusalContext::BadProof { what: (*what).into() }),
            AuthzError::Stale => Some(RefusalContext::StaleState { fresh_until: None }),
            AuthzError::Unavailable(service, _) => Some(RefusalContext::Unavailable { service: *service }),
            AuthzError::ArtifactMismatch(_) => Some(RefusalContext::ArtifactMismatch),
        }
    }

    pub(crate) fn not_allowed(reason: &'static str) -> Self {
        Self::denied(seal_proto::ErrorCode::NotAllowed, reason)
    }

    /// The public code (`Stale` → `Unavailable`, `BadProof` → `NotAllowed`,
    /// `ArtifactMismatch` → `IntegrityFailed`).
    pub fn code(&self) -> seal_proto::ErrorCode {
        use seal_proto::ErrorCode;
        match self {
            AuthzError::Denied { code, .. } => *code,
            AuthzError::Stale | AuthzError::Unavailable(..) => ErrorCode::Unavailable,
            AuthzError::BadProof(_) => ErrorCode::NotAllowed,
            AuthzError::ArtifactMismatch(_) => ErrorCode::IntegrityFailed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seal_proto::ErrorCode;

    #[test]
    fn public_codes() {
        assert_eq!(AuthzError::denied(ErrorCode::TierTooLow, "x").code(), ErrorCode::TierTooLow);
        assert_eq!(AuthzError::Stale.code(), ErrorCode::Unavailable);
        assert_eq!(AuthzError::BadProof("x").code(), ErrorCode::NotAllowed);
        assert_eq!(
            AuthzError::Unavailable(seal_proto::telemetry::Dependency::Sts, "x".into()).code(),
            ErrorCode::Unavailable
        );
        let signal = seal_proto::integrity::IntegritySignal {
            tenant: seal_proto::TenantId::new("acme").unwrap(),
            identity: seal_proto::identity::WorkloadIdentity::AppKey { key_id: seal_proto::KeyId([1; 32]) },
            source: seal_proto::integrity::SignalSource::Sdk,
            code: seal_proto::integrity::CODE_ARTIFACT_MISMATCH.into(),
            severity: seal_proto::integrity::Severity::High,
            observed_at: 1,
            blob_id: None,
        };
        assert_eq!(AuthzError::ArtifactMismatch(Box::new(signal)).code(), ErrorCode::IntegrityFailed);
    }
}
