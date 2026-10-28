use serde::{Deserialize, Serialize};

/// The public error vocabulary. SDK exceptions, HTTP status codes and the
/// `seal_error` field in upstream-facing error bodies all map from this.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Blob past its `expires_at`, or its tenant key version is retired (below
    /// `oldest_accepted`). SDK: `seal.Expired`.
    Expired,
    /// Caller identity is not in the blob's `apps`, or is from another tenant; or it connects
    /// from outside its app's networks (`TenantState::app_networks`). SDK: `seal.NotAllowed`.
    NotAllowed,
    /// Session would be weaker than the caller's `min_tier`. SDK: `seal.TierTooLow`.
    TierTooLow,
    /// The endpoint failed an integrity check, or its identity is suspended. Not retryable;
    /// clears when an admin clears the identity or a timed suspension ends. SDK: `seal.IntegrityFailed`.
    IntegrityFailed,
    /// Seal or a dependency it needs could not be reached. Retryable. SDK: `seal.Unavailable`.
    Unavailable,
    /// A request in a session falls outside the blob's policy. HTTP 403.
    PolicyDenied,
    /// Budget or rate limit exhausted. HTTP 429.
    BudgetExceeded,
    /// Session token expired; the SDK refreshes transparently.
    SessionExpired,
    /// The session was ended before its token expired (`SessionEnd`): by its client, or by the
    /// enclave on an integrity action. Not retryable: start a new session.
    SessionEnded,
    /// The SDK could not verify the enclave (evidence, release, binding or TLS pin).
    /// Never retried silently: it may mean an attack. SDK: `seal.VerificationFailed`.
    VerificationFailed,
    /// The request is malformed. A bug in the caller, never retryable.
    BadRequest,
    /// Seal itself failed. Details go to telemetry, never to the caller.
    Internal,
    /// The blob has no DEK wrap for this enclave's platform: it was sealed before the tenant
    /// enabled the platform. Not retryable here; seal the secret again (or use the blob on a
    /// platform it was sealed for). SDK: `seal.ResealRequired`.
    ResealRequired,
}

impl ErrorCode {
    pub fn http_status(self) -> u16 {
        match self {
            ErrorCode::Expired => 410,
            ErrorCode::NotAllowed => 403,
            ErrorCode::TierTooLow => 403,
            ErrorCode::IntegrityFailed => 403,
            ErrorCode::Unavailable => 503,
            ErrorCode::PolicyDenied => 403,
            ErrorCode::BudgetExceeded => 429,
            ErrorCode::SessionExpired => 401,
            ErrorCode::SessionEnded => 401,
            ErrorCode::VerificationFailed => 495,
            ErrorCode::BadRequest => 400,
            ErrorCode::Internal => 500,
            ErrorCode::ResealRequired => 409,
        }
    }

    pub fn retryable(self) -> bool {
        matches!(self, ErrorCode::Unavailable | ErrorCode::SessionExpired)
    }

    /// The wire name, as serde writes it (`"session_ended"`), for errors written without serde
    /// (Redis `-ERR seal <code>: …`, Postgres error text).
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::Expired => "expired",
            ErrorCode::NotAllowed => "not_allowed",
            ErrorCode::TierTooLow => "tier_too_low",
            ErrorCode::IntegrityFailed => "integrity_failed",
            ErrorCode::Unavailable => "unavailable",
            ErrorCode::PolicyDenied => "policy_denied",
            ErrorCode::BudgetExceeded => "budget_exceeded",
            ErrorCode::SessionExpired => "session_expired",
            ErrorCode::SessionEnded => "session_ended",
            ErrorCode::VerificationFailed => "verification_failed",
            ErrorCode::BadRequest => "bad_request",
            ErrorCode::Internal => "internal",
            ErrorCode::ResealRequired => "reseal_required",
        }
    }
}

/// Errors from parsing or validating wire data.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProtoError {
    #[error("malformed: {0}")]
    Malformed(String),
    #[error("invalid {field}: {reason}")]
    Invalid { field: &'static str, reason: String },
    #[error("unsupported: {0}")]
    Unsupported(String),
}

impl ProtoError {
    pub fn invalid(field: &'static str, reason: impl Into<String>) -> Self {
        ProtoError::Invalid { field, reason: reason.into() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as_str_is_the_serde_name() {
        use ErrorCode::*;
        let all = [
            Expired,
            NotAllowed,
            TierTooLow,
            IntegrityFailed,
            Unavailable,
            PolicyDenied,
            BudgetExceeded,
            SessionExpired,
            SessionEnded,
            VerificationFailed,
            BadRequest,
            Internal,
            ResealRequired,
        ];
        // No wildcard: a new variant fails to compile here until it is added to `all`.
        let position = |code: ErrorCode| match code {
            Expired => 0,
            NotAllowed => 1,
            TierTooLow => 2,
            IntegrityFailed => 3,
            Unavailable => 4,
            PolicyDenied => 5,
            BudgetExceeded => 6,
            SessionExpired => 7,
            SessionEnded => 8,
            VerificationFailed => 9,
            BadRequest => 10,
            Internal => 11,
            ResealRequired => 12,
        };
        for (i, code) in all.into_iter().enumerate() {
            assert_eq!(position(code), i);
            assert_eq!(serde_json::to_string(&code).unwrap(), format!("\"{}\"", code.as_str()));
            assert_eq!(serde_json::from_str::<ErrorCode>(&format!("\"{}\"", code.as_str())).unwrap(), code);
        }
    }
}
