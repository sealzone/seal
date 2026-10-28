//! The Seal SDK: use secrets without holding them.
//!
//! ```no_run
//! # async fn demo(secret: &[u8]) -> Result<(), seal::ClientError> {
//! let seal = seal::Client::from_env().await?;
//!
//! // Seal: required arguments positional, options chained, then `.await`.
//! let blob = seal.seal(secret, "https://api.openai.com/v1", ["checkout"])
//!     .header("x-api-key")
//!     .await?;
//!
//! // Use it: the app gets a stand-in key, the enclave injects the real one.
//! let s = seal.session(&blob).http().await?;
//! let (url, key) = (s.url(), s.key());
//! # let _ = (url, key);
//! s.close().await?;
//! # Ok(()) }
//! ```
//!
//! One client does everything a workload may do. Whether it may seal (producer grant) or
//! start sessions (app grant) is decided by the enclave on every call, from the tenant's
//! signed grants, never by the SDK. Admin tools live in `admin`.
//!
//! The SDK core. Language bindings (Python, Node/TypeScript, Go) are thin wrappers over this
//! crate; none re-implements attestation, proofs or tunnels.
//!
//! # Features
//!
//! - `aws`: AWS workload identity (`identity::AwsIdentity`); off by default, a large tree.
//! - `sim`: **insecure, for tests and local development only.** The client then accepts
//!   simulator attestation evidence, which is signed by a public development key and proves
//!   nothing, and reads its trust from `SEAL_TRUST`. Never enable it in anything that handles
//!   real secrets.
//!
//! The release trust enclaves are verified against is compiled in: Seal's production trust,
//! shipped with this crate (`ClientBuilder::trust` to use another).
//!
//! Every connection to the enclave goes through `verify` first: evidence checked against
//! the vendor root, measurement checked against a published release (M-of-N signatures +
//! log inclusion), the TLS key and ingest key checked against the evidence's report data,
//! and those keys checked against the guardian's certificate, which proves the guardian
//! released them. The TLS connection is then pinned to that key, so a misissued
//! certificate cannot intercept.

pub mod admin;
mod client;
pub mod identity;
pub mod integrity;
pub mod receipts;
mod session;
mod transport;
mod tunnel;
pub mod verify;
mod wake;

pub use client::{built_in_trust, Client, ClientBuilder, SealBuilder};
pub use identity::{detect_identity, IdentityProvider};
pub use receipts::TelemetryReceipt;
pub use session::{DatabaseSession, HttpSession, Session, SessionBuilder};
pub use wake::WAKE_WAIT_SECS;

// Everything a caller touches, so no one needs `seal_proto` directly.
pub use seal_proto::integrity::Severity;
pub use seal_proto::policy::Protocol;
pub use seal_proto::session::{ConsumerTier, PlatformTier, SessionInfo};
pub use seal_proto::{ErrorCode, TenantId, TenantRootId, UnixTime};
pub use seal_verify::{Trust, TrustError};

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// `ErrorCode` from the enclave (Expired, NotAllowed, TierTooLow, SessionEnded, ...).
    #[error("{code:?}: {message}")]
    Seal { code: ErrorCode, message: String },
    /// The enclave could not be verified. Never retried silently.
    #[error("enclave verification failed: {0}")]
    Verification(String),
    #[error("no workload identity found: {0}")]
    NoIdentity(String),
    /// A bad argument, e.g. an invalid `to`, app name, header or pin. Raised at `.await`.
    #[error("invalid argument: {0}")]
    Invalid(String),
    #[error("network: {0}")]
    Network(String),
}

impl ClientError {
    /// The public code (`Verification` → `VerificationFailed`, `Network` → `Unavailable`,
    /// `Invalid` → `BadRequest`, `NoIdentity` → `NotAllowed`).
    pub fn code(&self) -> ErrorCode {
        match self {
            ClientError::Seal { code, .. } => *code,
            ClientError::Verification(_) => ErrorCode::VerificationFailed,
            ClientError::NoIdentity(_) => ErrorCode::NotAllowed,
            ClientError::Invalid(_) => ErrorCode::BadRequest,
            ClientError::Network(_) => ErrorCode::Unavailable,
        }
    }
}

impl From<seal_verify::TrustError> for ClientError {
    fn from(e: seal_verify::TrustError) -> Self {
        ClientError::Invalid(e.to_string())
    }
}

impl From<seal_proto::ProtoError> for ClientError {
    fn from(e: seal_proto::ProtoError) -> Self {
        ClientError::Invalid(e.to_string())
    }
}

pub(crate) type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;
