//! A booted guardian's `GET /v1/identity`, checked: the guardian key is published only from
//! here, since the evidence attests it (the root ceremony's printout is not evidence).
//!
//! The evidence must verify (`seal_attest::verify`) at the given time, measure the expected
//! guardian release, and commit to `labeled_digest(GUARDIAN_IDENTITY_LABEL, (challenge,
//! platform, guardian_key))` for the challenge sent.

use anyhow::{bail, Context as _};
use serde::Deserialize;

use seal_proto::codec::labeled_digest;
use seal_proto::release::GUARDIAN_IDENTITY_LABEL;
use seal_proto::{Evidence, Measurement, PlatformId, PublicKey, TrustedTime};

/// `GET /v1/identity`'s answer.
#[derive(Debug, Deserialize)]
pub struct Identity {
    pub platform: PlatformId,
    pub runs_on: PlatformId,
    pub guardian_key: PublicKey,
    pub evidence: Evidence,
}

/// The identity's guardian key, once the evidence checks out.
pub fn check(
    identity: &Identity,
    challenge: [u8; 32],
    measurement: &Measurement,
    time: &TrustedTime,
) -> anyhow::Result<PublicKey> {
    let verified = seal_attest::verify(&identity.evidence, time).context("the guardian's evidence")?;
    if verified.platform != identity.runs_on {
        bail!("the evidence is from {:?}, the guardian says it runs on {:?}", verified.platform, identity.runs_on);
    }
    if verified.measurement != *measurement {
        bail!("the guardian measures {}, not the release's {measurement}", verified.measurement);
    }
    let expected = labeled_digest(GUARDIAN_IDENTITY_LABEL, &(challenge, identity.platform, identity.guardian_key));
    if verified.report_data != expected {
        bail!("the evidence does not commit to this challenge, platform and guardian key");
    }
    Ok(identity.guardian_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_that_does_not_verify_is_refused() {
        let identity = Identity {
            platform: PlatformId::GcpConfidentialSpace,
            runs_on: PlatformId::GcpConfidentialSpace,
            guardian_key: PublicKey([1; 32]),
            evidence: Evidence::GcpConfidentialSpace { token: "e30.e30.e30".into() },
        };
        assert!(check(&identity, [0; 32], &Measurement([0; 48]), &TrustedTime::exact(1_793_080_400)).is_err());
    }
}
