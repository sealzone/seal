//! `TenantStore` and `ReleaseStore` over the control plane (`seal_control::client::ControlClient`),
//! the control-plane source of what a key request carries (`ControlKeyRequestSource`), and the
//! credential the replica reads its tenant's bundle with (`EnclaveCredential`).
//!
//! The control plane is untrusted storage: whatever it serves is verified by the runtime (or,
//! for key requests, by the guardian) before use, and it can only withhold. So every failure
//! here, including a refusal of something this enclave posts, is `Unavailable` to callers;
//! the status stays in `detail`.

use seal_proto::telemetry::{Dependency, RefusalContext};
use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use seal_control::client::{signed_authorization, ControlClient, ControlError, Credential, Target};
use seal_proto::codec::{b64url, labeled_digest};
use seal_proto::control::{AttestedControlRequest, ATTESTED_SCHEME, CONTROL_REQUEST_LABEL};
use seal_proto::integrity::SignedSignal;
use seal_proto::release::{ReleaseEvidence, SignedServiceKeyCertificate};
use seal_proto::session::SignedSessionEnd;
use seal_proto::state::TenantBundle;
use seal_proto::{ErrorCode, Measurement, PlatformId, TenantId, TenantRootId};

use super::guardian::KeyRequestInputs;
use crate::{fail, host_now, ReleaseStore, ServiceError, TelemetrySigner, TenantStore};

fn unavailable(what: &str, e: ControlError) -> ServiceError {
    fail(ErrorCode::Unavailable, format!("control plane, {what}: {e}"))
        .with(RefusalContext::Unavailable { service: Dependency::ControlPlane })
}

/// How this replica's reads of its tenant's bundle are authorized (`seal_proto::control`):
/// attested until the guardian released its keys, then signed with its telemetry key, which
/// `Telemetry::start` hands over (`ControlTelemetry::with_credential`). The control plane admits
/// an attested read from a released enclave build pinned to `<tenant>@<root id>`, and a signed
/// one under a telemetry key the guardian certified for the chain.
pub struct EnclaveCredential {
    root_id: TenantRootId,
    attestor: Arc<seal_tee::Attestor>,
    signer: OnceLock<TelemetrySigner>,
}

impl EnclaveCredential {
    /// `root_id` is the pin's; `attestor` this enclave's own.
    pub fn new(root_id: TenantRootId, attestor: Arc<seal_tee::Attestor>) -> Self {
        Self { root_id, attestor, signer: OnceLock::new() }
    }

    /// Signs every later request with `signer`'s telemetry key.
    pub(crate) fn sign_with(&self, signer: TelemetrySigner) {
        let _ = self.signer.set(signer);
    }
}

#[async_trait]
impl Credential for EnclaveCredential {
    async fn authorization(&self, target: &Target<'_>) -> Result<String, ControlError> {
        let request = target.request(self.root_id, host_now());
        if let Some(signer) = self.signer.get() {
            return Ok(signed_authorization(&signer.sign_control_request(request)));
        }
        let evidence = self
            .attestor
            .attest(labeled_digest(CONTROL_REQUEST_LABEL, &request))
            .await
            .map_err(|e| ControlError::Credential(format!("attest control request: {e}")))?;
        let json = serde_json::to_vec(&AttestedControlRequest { request, evidence })
            .map_err(|e| ControlError::Credential(e.to_string()))?;
        Ok(format!("{ATTESTED_SCHEME} {}", b64url(&json)))
    }
}

/// The deployment's one tenant (`Cloud::tenant_pin`) on the control plane.
pub struct ControlTenantStore {
    client: Arc<ControlClient>,
    tenant: TenantId,
}

impl ControlTenantStore {
    pub fn new(client: Arc<ControlClient>, tenant: TenantId) -> Self {
        Self { client, tenant }
    }
}

#[async_trait]
impl TenantStore for ControlTenantStore {
    /// `GET /v1/tenants/{tenant}/bundle`, with the client's credential (`EnclaveCredential`).
    async fn load(&self) -> Result<TenantBundle, ServiceError> {
        self.client.get_bundle(&self.tenant).await.map_err(|e| unavailable("get bundle", e))
    }

    /// `POST /v1/tenants/{tenant}/signals`.
    async fn publish_signal(&self, signal: &SignedSignal) -> Result<(), ServiceError> {
        self.client.post_signal(&self.tenant, signal).await.map_err(|e| unavailable("post signal", e))
    }

    /// `POST /v1/tenants/{tenant}/session-ends`.
    async fn publish_session_end(&self, end: &SignedSessionEnd) -> Result<(), ServiceError> {
        self.client.post_session_end(&self.tenant, end).await.map_err(|e| unavailable("post session end", e))
    }

    /// `POST /v1/tenants/{tenant}/service-key-certificates`: the guardian's certificate over this
    /// enclave's service keys, posted at boot. The control plane accepts this enclave's signals,
    /// session ends and telemetry batches only once it holds the certificate naming their key,
    /// so boot posts it before `Telemetry::start`.
    async fn publish_service_key_certificate(&self, cert: &SignedServiceKeyCertificate) -> Result<(), ServiceError> {
        self.client
            .post_service_key_certificate(&self.tenant, cert)
            .await
            .map_err(|e| unavailable("post service key certificate", e))
    }
}

/// This release's evidence (`GET /v1/releases/{platform}/{measurement}`) with the control
/// plane's latest checkpoint (`GET /v1/checkpoint`) as its `fresh` checkpoint. The stored one
/// is as old as the upload, and every verifier refuses it once it is `FRESH_CHECKPOINT_SECS`
/// old. The latest replaces it only when it covers at least as many entries; when it cannot be
/// fetched, the stored evidence is returned as it is. The runtime, the guardian and SDKs verify
/// the result either way, so a checkpoint whose policy revokes the release is refused there.
async fn current_release(
    client: &ControlClient,
    platform: PlatformId,
    measurement: &Measurement,
) -> Result<ReleaseEvidence, ServiceError> {
    let mut evidence = client.get_release(platform, measurement).await.map_err(|e| unavailable("get release", e))?;
    match client.get_checkpoint().await {
        Ok(latest) if latest.checkpoint.size >= evidence.fresh.checkpoint.size => evidence.fresh = latest,
        Ok(_) => {}
        Err(e) => tracing::warn!(error = %e, "control plane, get checkpoint: serving the stored fresh checkpoint"),
    }
    Ok(evidence)
}

/// Release evidence from the control plane, with its latest checkpoint (`current_release`).
pub struct ControlReleaseStore {
    client: Arc<ControlClient>,
}

impl ControlReleaseStore {
    pub fn new(client: Arc<ControlClient>) -> Self {
        Self { client }
    }
}

#[async_trait]
impl ReleaseStore for ControlReleaseStore {
    async fn load(&self, platform: PlatformId, measurement: &Measurement) -> Result<ReleaseEvidence, ServiceError> {
        current_release(&self.client, platform, measurement).await
    }
}

/// Fetches, for every key request, this release's evidence (`current_release`), the tenant's
/// current bundle and, when the bundle's latest root has `cosign_releases`, the tenant's
/// co-signature of this measurement (`GET /v1/tenants/{tenant}/release-cosigns/{measurement}`). The guardian
/// verifies all three itself; a missing co-signature makes it refuse.
pub struct ControlKeyRequestSource {
    client: Arc<ControlClient>,
    tenant: TenantId,
}

impl ControlKeyRequestSource {
    pub fn new(client: Arc<ControlClient>, tenant: TenantId) -> Self {
        Self { client, tenant }
    }
}

impl ControlKeyRequestSource {
    /// This release's evidence for `platform` and `measurement`, the bundle and the co-signature.
    pub(super) async fn inputs(
        &self,
        platform: PlatformId,
        measurement: &Measurement,
    ) -> Result<KeyRequestInputs, ServiceError> {
        let release = current_release(&self.client, platform, measurement).await?;
        let bundle = self.client.get_bundle(&self.tenant).await.map_err(|e| unavailable("get bundle", e))?;
        let cosign_releases = bundle.root_chain.last().is_some_and(|r| r.root.body.cosign_releases);
        let cosign = if cosign_releases {
            let cosign = self
                .client
                .get_release_cosign(&self.tenant, measurement)
                .await
                .map_err(|e| unavailable("get release co-signature", e))?;
            Some(cosign)
        } else {
            None
        };
        Ok(KeyRequestInputs { release, bundle, cosign })
    }
}
