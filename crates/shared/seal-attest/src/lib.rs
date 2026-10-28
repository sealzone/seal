//! Checking TEE evidence. Pure and sync: no IO, no clock (`time` is when hardware
//! certificates must be valid; endorsements signed by a cloud are checked at their own signed
//! time), no configuration. Every vendor root is baked in and outlives any release, so a
//! guardian that never changes can use it: AMD's ARK per chip family, AWS's Nitro root
//! (30-year lifetime), Google's Confidential Space PKI-token root (rotated every 10 years).
//! Debug-mode TEEs are always refused. One implementation, shared by the SDK, the guardians
//! and the enclave.
//!
//! The set of platforms is closed, so dispatch is a `match` on `seal_proto::Evidence`: adding
//! a platform fails to compile until it is verified here.
#![forbid(unsafe_code)]

use seal_proto::{Evidence, Measurement, PlatformId, TrustedTime};

pub mod azure;
pub mod gcp;
pub mod nitro;
#[cfg(feature = "sim")]
pub mod sim;
mod x509;

#[derive(Debug, thiserror::Error)]
pub enum AttestError {
    #[error("evidence rejected: {0}")]
    Rejected(String),
    #[error("debug-mode TEE refused")]
    DebugMode,
    #[error("platform {0:?} not accepted by this build")]
    Unsupported(PlatformId),
}

impl AttestError {
    /// The public code: evidence that does not check out.
    pub fn code(&self) -> seal_proto::ErrorCode {
        seal_proto::ErrorCode::VerificationFailed
    }
}

/// Evidence after verification: what code runs, on what firmware, and what it committed to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedEvidence {
    pub platform: PlatformId,
    pub measurement: Measurement,
    /// Platform TCB as named components, checked against `ReleaseConstraints::min_tcb` with
    /// `Tcb::meets` (components per platform: `seal_proto::release::Tcb`).
    pub tcb: seal_proto::release::Tcb,
    /// The 32 bytes the TEE committed to (an `AttestationBinding`, `KeyRequestBinding` or
    /// guardian identity digest).
    pub report_data: [u8; 32],
    /// The deployment identity the evidence itself attests (Confidential Space: project and
    /// service account). `None` where the platform does not attest one.
    pub deployment: Option<seal_proto::identity::WorkloadIdentity>,
}

/// Verifies `evidence` against its platform's baked vendor roots. `Unsupported` for
/// simulator evidence unless built with `sim`, and for any platform without a verifier.
pub fn verify(evidence: &Evidence, time: &TrustedTime) -> Result<VerifiedEvidence, AttestError> {
    match evidence {
        Evidence::AzureSnpAci { report, vcek_der, uvm_endorsement } => {
            azure::verify(report, vcek_der, uvm_endorsement, time)
        }
        Evidence::AwsNitro { document } => nitro::verify(document, time),
        Evidence::GcpConfidentialSpace { token } => gcp::verify(token, time),
        #[cfg(feature = "sim")]
        Evidence::Sim { document } => sim::verify(document),
        #[cfg(not(feature = "sim"))]
        Evidence::Sim { .. } => Err(AttestError::Unsupported(PlatformId::Sim)),
    }
}
