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
    #[error("denied: {code:?}: {reason}")]
    Denied { code: seal_proto::ErrorCode, reason: &'static str },
    #[error("stale state")]
    Stale,
    #[error("identity proof rejected: {0}")]
    BadProof(&'static str),
    #[error("unavailable: {0}")]
    Unavailable(String),
    /// The endpoint report failed the app's artifact rule. Carries the `artifact-mismatch`
    /// signal (severity `High`, source `Sdk`, the blob's id) for the caller, which the enclave
    /// signs, records and applies.
    #[error("endpoint report fails the artifact rule")]
    ArtifactMismatch(Box<seal_proto::integrity::IntegritySignal>),
}

impl AuthzError {
    pub(crate) fn denied(code: seal_proto::ErrorCode, reason: &'static str) -> Self {
        AuthzError::Denied { code, reason }
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
            AuthzError::Stale | AuthzError::Unavailable(_) => ErrorCode::Unavailable,
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
        assert_eq!(AuthzError::Unavailable("x".into()).code(), ErrorCode::Unavailable);
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
