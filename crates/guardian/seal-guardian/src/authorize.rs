//! The guardian's whole decision, as one pure function.

use seal_proto::codec::labeled_digest;
use seal_proto::release::{
    Component, KeyPurpose, KeyRequest, GUARDIAN_PROTOCOL_VERSION, KEY_REQUEST_BINDING_LABEL, RELEASE_COSIGN_LABEL,
};
use seal_verify::{ReleaseVerifier, TenantVerifier};

use crate::{GuardianConfig, RequestFacts};

/// Why a key request was refused. Logged by the guardian; the requester gets only "denied".
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Denial {
    #[error("unsupported protocol version")]
    ProtocolVersion,
    #[error("challenge invalid or expired")]
    Challenge,
    #[error("evidence is for another platform")]
    WrongPlatform,
    #[error("evidence report data does not commit to this request")]
    Binding,
    #[error("manifest is not for the enclave component on this platform")]
    WrongComponent,
    #[error("evidence measurement differs from the manifest")]
    MeasurementMismatch,
    #[error("release: {0}")]
    Release(#[from] seal_verify::VerifyError),
    #[error("tenant bundle invalid, not fresh, or for another tenant or root")]
    Tenant,
    #[error("requested tenant key versions outside [oldest_accepted, current]")]
    TenantKeyVersionOutOfRange,
    #[error("tenant requires its own co-signature on this release")]
    TenantCosign,
}

/// In order: protocol version; challenge; platform == manifest.platform, which is
/// config.platform for enclave purposes and config.runs_on for `Succession`;
/// binding (`report_data == labeled_digest(KEY_REQUEST_BINDING_LABEL, binding)`);
/// component == Enclave, or for `Succession` component == Guardian with
/// `manifest.serves == Some(config.platform)`; measurement == manifest;
/// `seal_verify::ReleaseVerifier::verify` with `time.earliest()` and `time.latest()`
/// (revocations included); `check_tcb(&evidence.tcb)`. A successor passes exactly the rules
/// an enclave release passes, nothing more and nothing less, and needs no tenant bundle.
/// Then, for both tenant-scoped purposes: `TenantVerifier::verify` of the bundle at `time` for the named
/// tenant (so it must be fresh; anchors of this guardian's own key count, so the state in force is
/// the one the enclave that sent the same bundle works out), its root id == the purpose's `root_id`, and if
/// `cosign_releases`, a tenant co-signature (`verify_admin_signed`, `RELEASE_COSIGN_LABEL`)
/// over this measurement; for tenant keys also the versions within `[oldest_accepted, current]`.
pub struct KeyReleaseAuthorizer<'a> {
    config: &'a GuardianConfig,
    /// This guardian's own key, whose anchors count even when `trust.guardians` does not name
    /// it: a guardian is built before its key exists, so its configuration often cannot.
    own_key: seal_proto::PublicKey,
}
pub struct KeyReleasePermit<'a> {
    request: &'a KeyRequest,
}
impl<'a> KeyReleaseAuthorizer<'a> {
    /// For the guardian with `config` whose guardian key is `own_key`.
    pub fn new(config: &'a GuardianConfig, own_key: seal_proto::PublicKey) -> Self {
        Self { config, own_key }
    }

    pub fn authorize<'r>(&self, req: &'r KeyRequest, facts: &RequestFacts) -> Result<KeyReleasePermit<'r>, Denial> {
        let config = self.config;
        let binding = &req.binding;
        let manifest = &req.release.manifest.body;
        let evidence = &facts.evidence;

        if req.protocol_version != GUARDIAN_PROTOCOL_VERSION || binding.protocol_version != GUARDIAN_PROTOCOL_VERSION {
            return Err(Denial::ProtocolVersion);
        }
        if !facts.challenge_ok {
            return Err(Denial::Challenge);
        }
        let succession = matches!(binding.purpose, KeyPurpose::Succession);
        let platform = if succession { config.runs_on } else { config.platform };
        if evidence.platform != platform || manifest.platform != platform {
            return Err(Denial::WrongPlatform);
        }
        if evidence.report_data != labeled_digest(KEY_REQUEST_BINDING_LABEL, binding) {
            return Err(Denial::Binding);
        }
        let component_ok = if succession {
            manifest.component == Component::Guardian && manifest.serves == Some(config.platform)
        } else {
            manifest.component == Component::Enclave
        };
        if !component_ok {
            return Err(Denial::WrongComponent);
        }
        if evidence.measurement != manifest.measurement {
            return Err(Denial::MeasurementMismatch);
        }
        let release = ReleaseVerifier::new(config.trust.releases.clone()).verify(&req.release, &facts.time)?;
        ReleaseVerifier::check_tcb(release.constraints(), evidence.platform, &evidence.tcb)?;

        let (tenant, root_id) = match &binding.purpose {
            KeyPurpose::Succession => return Ok(KeyReleasePermit { request: req }),
            KeyPurpose::Service { tenant, root_id } | KeyPurpose::Tenant { tenant, root_id, .. } => (tenant, root_id),
        };
        let bundle = req.tenant.as_ref().ok_or(Denial::Tenant)?;
        // Signals and session ends do not concern the guardian, so no telemetry keys.
        let mut own_anchors: Vec<_> = config.trust.guardians.get(&config.platform).into_iter().copied().collect();
        if !own_anchors.contains(&self.own_key) {
            own_anchors.push(self.own_key);
        }
        let verified = TenantVerifier::new(config.trust.tenants.clone(), Vec::new())
            .with_anchor_keys(own_anchors)
            .verify(tenant, bundle, &facts.time)
            .map_err(|_| Denial::Tenant)?;
        if verified.root_id() != root_id {
            return Err(Denial::Tenant);
        }
        if verified.root().cosign_releases {
            let cosign = req.tenant_cosign.as_ref().ok_or(Denial::TenantCosign)?;
            if &cosign.body.tenant != tenant || cosign.body.measurement != manifest.measurement {
                return Err(Denial::TenantCosign);
            }
            TenantVerifier::verify_admin_signed(verified.root(), RELEASE_COSIGN_LABEL, cosign)
                .map_err(|_| Denial::TenantCosign)?;
        }
        if let KeyPurpose::Tenant { tenant_key_versions, .. } = &binding.purpose {
            let window = verified.state().tenant_key_versions;
            if !tenant_key_versions.iter().all(|v| (window.oldest_accepted..=window.current).contains(v)) {
                return Err(Denial::TenantKeyVersionOutOfRange);
            }
        }
        Ok(KeyReleasePermit { request: req })
    }
}
impl KeyReleasePermit<'_> {
    pub fn request(&self) -> &KeyRequest {
        self.request
    }
}
