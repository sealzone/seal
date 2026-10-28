//! GCP Confidential Space: the pin from the `tee-env-SEAL_TENANT` override, the deployment
//! identity from the enclave's own attestation (verified with `seal_attest::verify`, then
//! `VerifiedEvidence::deployment`), Roughtime for the clock, TCP egress through Cloud NAT.
//!
//! The launcher passes each `tee-env-<NAME>` metadata value to the container as the
//! environment variable `<NAME>`, so the pin is read from `SEAL_TENANT`. The image's launch
//! policy (`tee.launch_policy.allow_env_override=SEAL_TENANT`) makes it the only variable an
//! operator can set.

use std::sync::Arc;

use seal_attest::VerifiedEvidence;
use seal_authz::DeploymentProof;
use seal_proto::{Evidence, TenantPin, TrustedTime};
use seal_tee::gcp::ConfidentialSpaceAttestor;
use seal_tee::roughtime::{default_servers, RoughtimeClock, DEFAULT_MIN_AGREEING};
use seal_tee::{Attestor, Clock};

use crate::CloudError;

/// The report data of the token the replica attests its own deployment with. The token stays
/// in the process, so it commits to nothing.
const DEPLOYMENT_REPORT_DATA: [u8; 32] = [0; 32];

/// A Confidential Space VM.
pub struct ConfidentialSpace {
    pub(crate) attestor: Attestor,
    pub(crate) clock: Clock,
    pub(crate) pin: TenantPin,
    pub(crate) dialer: Arc<dyn seal_net::Dialer>,
}

impl ConfidentialSpace {
    /// Around the attestor `Attestor::detect` chose: the pin from `SEAL_TENANT`, Roughtime
    /// over UDP with the production servers, plain TCP.
    pub(crate) fn from_env(attestor: ConfidentialSpaceAttestor) -> Result<Self, CloudError> {
        let pin = crate::tenant_pin(std::env::var(crate::TENANT_VAR).ok())?;
        let clock = RoughtimeClock::new(default_servers(), DEFAULT_MIN_AGREEING, Arc::new(seal_net::UdpDatagrams));
        Ok(Self {
            attestor: Attestor::GcpConfidentialSpace(attestor),
            clock: Clock::Roughtime(clock),
            pin,
            dialer: Arc::new(seal_net::TcpDialer),
        })
    }

    /// A fresh token of our own, verified at the trusted time; its project and service account.
    pub(crate) async fn deployment(&self) -> Result<DeploymentProof, CloudError> {
        let evidence = self.attestor.attest(DEPLOYMENT_REPORT_DATA).await?;
        let time = self.clock.now().await?;
        deployment_of(&evidence, &time)
    }
}

/// The attested deployment identity of `evidence`, verified at `time`.
pub(crate) fn deployment_of(evidence: &Evidence, time: &TrustedTime) -> Result<DeploymentProof, CloudError> {
    let verified: VerifiedEvidence = seal_attest::verify(evidence, time)
        .map_err(|e| CloudError::Deployment(format!("own attestation does not verify: {e}")))?;
    let identity = verified
        .deployment
        .ok_or_else(|| CloudError::Deployment("own attestation carries no deployment identity".into()))?;
    Ok(DeploymentProof::Attested(identity))
}

#[cfg(test)]
mod tests {
    use seal_proto::identity::WorkloadIdentity;

    use super::*;

    /// Recorded on a live TDX VM (`seal-attest/tests/data/gcp`, sources in its README).
    const TDX: &str = include_str!("../../../shared/seal-attest/tests/data/gcp/tdx.jwt");
    const TDX_DEBUG: &str = include_str!("../../../shared/seal-attest/tests/data/gcp/tdx-debug.jwt");
    /// While both recordings are valid.
    const NOW: TrustedTime = TrustedTime { now: 1_793_080_400, radius: 1 };

    #[test]
    fn deployment_is_the_attested_project_and_service_account() {
        let evidence = Evidence::GcpConfidentialSpace { token: TDX.to_owned() };
        match deployment_of(&evidence, &NOW).unwrap() {
            DeploymentProof::Attested(identity) => assert_eq!(
                identity,
                WorkloadIdentity::ConfidentialSpace {
                    project_number: 118_699_070_563,
                    service_account: "seal-dev-gcp@seal-512903.iam.gserviceaccount.com".into(),
                }
            ),
            DeploymentProof::Proof(_) => panic!("not attested"),
        }
        // Our own evidence must verify: not after it expires, never from the debug image.
        let late = TrustedTime { now: 1_793_090_000, radius: 1 };
        assert!(matches!(deployment_of(&evidence, &late), Err(CloudError::Deployment(_))));
        let debug = Evidence::GcpConfidentialSpace { token: TDX_DEBUG.to_owned() };
        assert!(matches!(deployment_of(&debug, &NOW), Err(CloudError::Deployment(_))));
    }
}
