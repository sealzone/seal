//! The cloud an enclave replica runs on. Everything that differs between clouds for an
//! enclave lives here, behind one enum, so the runtime (`seal-enclave`) reads the same on
//! every cloud: detect the cloud, read the pin, prove the deployment, dial.
//!
//! | Cloud | Tenant pin | Deployment identity | Network |
//! |-------|------------|---------------------|---------|
//! | Azure ACI | `SEAL_TENANT`, allowed by an anchored re2 rule in the container policy | the group's managed-identity token (IMDS) | TCP and UDP; NAT gateway |
//! | AWS Nitro (designed, not built: `Cloud::detect` refuses it) | the first message the parent sends over vsock | `GetCallerIdentity` presigned by the parent with its instance role | vsock to the parent's egress proxy (`CONNECT host:port`); time from the hypervisor (`NitroClock`) |
//! | GCP Confidential Space | `tee-env-SEAL_TENANT`, the only override the launch policy allows | project and service account in the enclave's own attestation | TCP and UDP; Cloud NAT |
//!
//! The pin is unattested on every cloud; it can only narrow what the enclave serves.
#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::sync::Arc;

use seal_authz::DeploymentProof;
use seal_proto::identity::IdentityMatcher;
use seal_proto::TenantPin;
use seal_tee::{Attestor, Clock};

pub mod azure;
pub mod gcp;
#[cfg(feature = "sim")]
pub mod sim;

#[derive(Debug, thiserror::Error)]
pub enum CloudError {
    #[error("tee: {0}")]
    Tee(#[from] seal_tee::TeeError),
    #[error("tenant pin: {0}")]
    Pin(String),
    #[error("deployment identity unavailable: {0}")]
    Deployment(String),
    #[error("{0} is not supported by this build")]
    Unsupported(&'static str),
}

impl CloudError {
    /// The public code: the cloud could not supply what the enclave needs.
    pub fn code(&self) -> seal_proto::ErrorCode {
        seal_proto::ErrorCode::Unavailable
    }
}

// One per process; every variant holds an attestor, a clock and a dialer.
#[allow(clippy::large_enum_variant)]
pub enum Cloud {
    AzureSnpAci(azure::Aci),
    GcpConfidentialSpace(gcp::ConfidentialSpace),
    #[cfg(feature = "sim")]
    Sim(sim::Sim),
}

impl Cloud {
    /// From `Attestor::detect`: the cloud whose TEE device is present, `NotInTee` (as
    /// `CloudError::Tee`) when none is, `Unsupported` on AWS Nitro. A `sim` build with
    /// `SEAL_SIM=1` gets the simulator cloud, configured from the environment (`sim` module).
    pub fn detect() -> Result<Self, CloudError> {
        match Attestor::detect()? {
            Attestor::AzureSnpAci(attestor) => Ok(Cloud::AzureSnpAci(azure::Aci::from_env(attestor)?)),
            Attestor::AwsNitro(_) => Err(CloudError::Unsupported("AWS Nitro Enclaves")),
            Attestor::GcpConfidentialSpace(attestor) => {
                Ok(Cloud::GcpConfidentialSpace(gcp::ConfidentialSpace::from_env(attestor)?))
            }
            #[cfg(feature = "sim")]
            Attestor::Sim(attestor) => Ok(Cloud::Sim(sim::Sim::from_env(attestor)?)),
        }
    }
    pub fn attestor(&self) -> &Attestor {
        match self {
            Cloud::AzureSnpAci(a) => &a.attestor,
            Cloud::GcpConfidentialSpace(c) => &c.attestor,
            #[cfg(feature = "sim")]
            Cloud::Sim(s) => &s.attestor,
        }
    }
    pub fn clock(&self) -> &Clock {
        match self {
            Cloud::AzureSnpAci(a) => &a.clock,
            Cloud::GcpConfidentialSpace(c) => &c.clock,
            #[cfg(feature = "sim")]
            Cloud::Sim(s) => &s.clock,
        }
    }
    /// Where every outbound stream starts (upstreams, guardian, control plane, OIDC, STS).
    pub fn dialer(&self) -> Arc<dyn seal_net::Dialer> {
        match self {
            Cloud::AzureSnpAci(a) => a.dialer.clone(),
            Cloud::GcpConfidentialSpace(c) => c.dialer.clone(),
            #[cfg(feature = "sim")]
            Cloud::Sim(s) => s.dialer.clone(),
        }
    }
    /// `<tenant>@<root id>`, read from `SEAL_TENANT` by `detect`.
    pub fn tenant_pin(&self) -> &TenantPin {
        match self {
            Cloud::AzureSnpAci(a) => &a.pin,
            Cloud::GcpConfidentialSpace(c) => &c.pin,
            #[cfg(feature = "sim")]
            Cloud::Sim(s) => &s.pin,
        }
    }
    /// Who deployed this replica, checked against `deployments` (the verified `TenantState::deployments`) before
    /// any key request (`seal_authz::DeploymentVerifier`). Azure takes its token audience from them.
    pub async fn deployment(&self, deployments: &BTreeSet<IdentityMatcher>) -> Result<DeploymentProof, CloudError> {
        match self {
            Cloud::AzureSnpAci(a) => a.deployment(deployments).await,
            Cloud::GcpConfidentialSpace(c) => c.deployment().await,
            #[cfg(feature = "sim")]
            Cloud::Sim(s) => Ok(s.deployment()),
        }
    }
}

/// The environment variable every cloud delivers the tenant pin in.
const TENANT_VAR: &str = "SEAL_TENANT";

/// `SEAL_TENANT`'s value as a pin.
fn tenant_pin(value: Option<String>) -> Result<TenantPin, CloudError> {
    value
        .ok_or_else(|| CloudError::Pin(format!("{TENANT_VAR} is not set")))?
        .parse()
        .map_err(|e| CloudError::Pin(format!("{TENANT_VAR}: {e}")))
}

#[cfg(test)]
#[test]
fn the_pin_is_seal_tenant() {
    let pin = format!("acme@{}", "ab".repeat(32));
    assert_eq!(tenant_pin(Some(pin.clone())).unwrap(), pin.parse().unwrap());
    assert!(matches!(tenant_pin(None), Err(CloudError::Pin(e)) if e.contains("not set")));
    for bad in ["acme", "acme@xyz", "", "ACME@abab"] {
        assert!(matches!(tenant_pin(Some(bad.into())), Err(CloudError::Pin(_))), "{bad}");
    }
}

#[cfg(all(test, feature = "sim"))]
mod tests;
