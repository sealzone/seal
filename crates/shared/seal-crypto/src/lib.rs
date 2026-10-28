//! Seal's cryptography, as pure functions over `seal-proto` types.
//!
//! Boundary rules:
//! - No IO, no clocks, no globals. Randomness comes in as `&mut impl CryptoRng`.
//! - Every secret type zeroizes on drop and has a redacting `Debug`; none
//!   implements `Serialize`, `Display` or `Clone` except where noted.
//! - Every signature signs `codec::labeled_digest(label, msg)`; labels live in `seal-proto`.
//!
//! Key hierarchy (HKDF-SHA256, `ikm` = platform master key, labels in `kdf`; the
//! master key is bound to one platform, so every derived key is too). Below the guardian's
//! own keys, every key belongs to one tenant root (tenant name + `TenantRootId`):
//! ```text
//! PlatformMasterKey (one per platform, only inside that platform's guardian)
//!  ├─ guardian key            → Ed25519: signs ServiceKeyCertificates and TenantWrapKeys
//!  ├─ challenge key           → HMAC key for stateless GuardianChallenges
//!  └─ per tenant root t:
//!      ├─ TenantWrappingKey (t, tenant key version)  → X25519: DEK wraps are HPKE to its public half
//!      └─ per service key version v:
//!          ├─ token seed(t, v)   → session tokens (per-token HKDF salt)
//!          ├─ ingest seed(t, v)  → X25519 pair, HPKE target for seal()
//!          ├─ telemetry seed(t, v)   → Ed25519 pair: telemetry, integrity signals, session ends
//!          ├─ tls seed(t, v)     → P-256 handshake and CA keys + deterministic CA and leaf certs, same on the tenant's replicas
//!          └─ ticket seed(t, v)  → HMAC key for stateless proof tickets
//! ```
//!
//! Seeds are 32 bytes; the X25519 keys use a seed as the scalar, the Ed25519 keys as the
//! RFC 8032 secret key, the HMAC keys as the key. The TLS scalar derives from its seed
//! (`TlsKey`).

#![forbid(unsafe_code)]

/// The OS generator, for callers at the IO edge. `SysRng` can fail; `UnwrapErr` turns it
/// into the infallible `CryptoRng` every function here takes.
pub use rand::rand_core::UnwrapErr;
pub use rand::rngs::SysRng;
pub use rand::CryptoRng;

pub mod blob;
mod cert;
pub mod hpke;
pub mod jws;
pub mod kdf;
pub mod keys;
pub mod sign;
pub mod telemetry;
pub mod ticket;
pub mod token;

pub use keys::{
    ChallengeKey, EphemeralKey, IngestKey, Key32, PlatformMasterKey, SecretBytes, ServiceKeyScope, ServiceKeys,
    TelemetryKey, TenantWrappingKey, TenantWrappingKeyScope, TicketKey, TlsKey, TokenKey,
};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    /// AEAD or HPKE open failed. Deliberately carries no detail.
    #[error("decryption failed")]
    Decrypt,
    #[error("bad signature")]
    BadSignature,
    #[error("need {need} valid signatures from distinct known keys, have {have}")]
    Threshold { have: usize, need: usize },
    #[error("proof ticket invalid or expired")]
    InvalidTicket,
    #[error("no DEK wrap for this platform")]
    NoWrapForPlatform,
    #[error("malformed: {0}")]
    Malformed(String),
}

impl CryptoError {
    /// The public code. Decryption and ticket failures say nothing more specific.
    pub fn code(&self) -> seal_proto::ErrorCode {
        use seal_proto::ErrorCode;
        match self {
            CryptoError::Decrypt | CryptoError::Malformed(_) => ErrorCode::BadRequest,
            CryptoError::NoWrapForPlatform => ErrorCode::ResealRequired,
            CryptoError::BadSignature | CryptoError::Threshold { .. } => ErrorCode::VerificationFailed,
            CryptoError::InvalidTicket => ErrorCode::NotAllowed,
        }
    }
}
