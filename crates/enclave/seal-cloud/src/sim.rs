//! Simulator cloud (feature `sim`): the sim attestor and system clock, TCP, and a pin and
//! deployment proof given at construction.
//!
//! `Cloud::detect` builds one when `seal_tee::Attestor::detect` picks the simulator
//! (`SEAL_SIM=1` in a `sim` build), from the environment:
//!
//! | Variable | Meaning |
//! | --- | --- |
//! | `SEAL_TENANT` | the tenant pin, `<tenant>@<root id>` (required) |
//! | `SEAL_SIM_DEPLOYMENT` | the deployment identity, a `WorkloadIdentity` as JSON, returned as `DeploymentProof::Attested` (required) |
//! | `SEAL_SIM_CLOCK_OFFSET` | seconds added to the system clock, may be negative (default 0) |

use std::sync::Arc;

use seal_authz::DeploymentProof;
use seal_proto::identity::{IdentityProof, WorkloadIdentity};
use seal_proto::TenantPin;
use seal_tee::{Attestor, Clock};

use crate::CloudError;

pub struct Sim {
    pub(crate) attestor: Attestor,
    pub(crate) clock: Clock,
    pub(crate) pin: TenantPin,
    deployment: DeploymentProof,
    pub(crate) dialer: Arc<dyn seal_net::Dialer>,
}

impl Sim {
    pub fn new(
        attestor: seal_tee::sim::SimAttestor,
        clock: seal_tee::sim::SystemClock,
        pin: TenantPin,
        deployment: DeploymentProof,
    ) -> Self {
        Self {
            attestor: Attestor::Sim(attestor),
            clock: Clock::System(clock),
            pin,
            deployment,
            dialer: Arc::new(seal_net::TcpDialer),
        }
    }

    /// From the environment (module docs), around the attestor `Attestor::detect` chose.
    pub(crate) fn from_env(attestor: seal_tee::sim::SimAttestor) -> Result<Self, CloudError> {
        Self::from_vars(attestor, |name| std::env::var(name).ok())
    }

    pub(crate) fn from_vars(
        attestor: seal_tee::sim::SimAttestor,
        var: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, CloudError> {
        let pin = crate::tenant_pin(var(crate::TENANT_VAR))?;
        let identity: WorkloadIdentity = serde_json::from_str(
            &var("SEAL_SIM_DEPLOYMENT")
                .ok_or_else(|| CloudError::Deployment("SEAL_SIM_DEPLOYMENT is not set".into()))?,
        )
        .map_err(|e| CloudError::Deployment(format!("SEAL_SIM_DEPLOYMENT: {e}")))?;
        let offset = match var("SEAL_SIM_CLOCK_OFFSET") {
            None => 0,
            Some(s) => s
                .parse::<i64>()
                .map_err(|e| CloudError::Tee(seal_tee::TeeError::Unavailable(format!("SEAL_SIM_CLOCK_OFFSET: {e}"))))?,
        };
        Ok(Self::new(attestor, seal_tee::sim::SystemClock::new(offset), pin, DeploymentProof::Attested(identity)))
    }

    /// A copy of the proof given at construction.
    pub(crate) fn deployment(&self) -> DeploymentProof {
        match &self.deployment {
            DeploymentProof::Attested(identity) => DeploymentProof::Attested(identity.clone()),
            DeploymentProof::Proof(proof) => DeploymentProof::Proof(match proof {
                IdentityProof::Oidc { provider, jwt } => {
                    IdentityProof::Oidc { provider: *provider, jwt: jwt.duplicate() }
                }
                IdentityProof::AwsSigV4 { method, url, headers, body } => IdentityProof::AwsSigV4 {
                    method: method.clone(),
                    url: url.clone(),
                    headers: headers.iter().map(|(name, value)| (name.clone(), value.duplicate())).collect(),
                    body: body.clone(),
                },
                IdentityProof::AppKey { key_id, signature } => {
                    IdentityProof::AppKey { key_id: *key_id, signature: signature.clone() }
                }
            }),
        }
    }
}
