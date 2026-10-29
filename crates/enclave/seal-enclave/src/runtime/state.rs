//! The tenant state: verifying bundles, the reload, wrap keys, and applying what this
//! replica signs itself.

use std::collections::BTreeMap;

use seal_proto::integrity::SignedSignal;
use seal_proto::release::{TenantWrapKey, TENANT_WRAP_KEY_LABEL};
use seal_proto::session::SignedSessionEnd;
use seal_proto::state::TenantBundle;
use seal_proto::{ErrorCode, PlatformId, PublicKey, TenantKeyVersion, TenantPin, TrustedTime};
use seal_verify::{TenantVerifier, Trust, VerifiedTenant};

use super::{fail, live, lock, Runtime};
use crate::ServiceError;

/// `bundle` verified for the pinned tenant at `time`, signals and session ends checked against
/// `telemetry_keys`, starting from anchors of `platform`'s guardian (the one the enclave's key
/// requests go to, which works out the same state in force from the same bundle), and its
/// chain the pin's root id (`NotAllowed` otherwise).
pub(super) fn verify_bundle(
    trust: &Trust,
    platform: PlatformId,
    pin: &TenantPin,
    bundle: &TenantBundle,
    telemetry_keys: Vec<PublicKey>,
    time: &TrustedTime,
) -> Result<VerifiedTenant, ServiceError> {
    let anchor_keys = trust.guardians.get(&platform).into_iter().copied().collect();
    let verified = TenantVerifier::new(trust.tenants.clone(), telemetry_keys)
        .with_anchor_keys(anchor_keys)
        .verify(&pin.tenant, bundle, time)
        .map_err(|e| fail(e.code(), format!("tenant bundle: {e}")))?;
    if verified.root_id() != &pin.root_id {
        return Err(fail(ErrorCode::NotAllowed, "the tenant bundle is for another root chain than the pin's"));
    }
    Ok(verified)
}

/// The bundle's wrap keys for the pinned tenant and root that their platform's guardian key
/// (`Trust::guardians`) certified; the others are dropped.
pub(super) fn wrap_keys(
    trust: &Trust,
    pin: &TenantPin,
    bundle: &TenantBundle,
) -> BTreeMap<(PlatformId, TenantKeyVersion), TenantWrapKey> {
    bundle
        .wrap_keys
        .iter()
        .filter(|signed| {
            let key = &signed.body;
            key.tenant == pin.tenant
                && key.root_id == pin.root_id
                && trust.guardians.get(&key.platform).is_some_and(|guardian| {
                    seal_crypto::sign::verify_threshold(
                        std::slice::from_ref(guardian),
                        1,
                        TENANT_WRAP_KEY_LABEL,
                        *signed,
                    )
                    .is_ok()
                })
        })
        .map(|signed| ((signed.body.platform, signed.body.tenant_key_version), signed.body.clone()))
        .collect()
}

/// Something this replica signed and applies before anyone else sees it.
pub(crate) enum Local {
    Signal(SignedSignal),
    End(SignedSessionEnd),
}

impl Runtime {
    /// The telemetry keys of this replica's certificate that the release policy has not
    /// retired: signals and session ends signed by an older version's key below the platform's
    /// `min_service_key_version` count for nothing.
    fn telemetry_keys(&self) -> Vec<PublicKey> {
        let policy = lock(&self.release).fresh.checkpoint.policy.clone();
        seal_verify::telemetry_keys_in_force(&self.service.certificate.body, Some(&policy))
    }

    /// Loads, verifies and caches the tenant's newest bundle. A change wakes the live-session
    /// monitor, which rechecks every live session.
    pub(crate) async fn reload(&self) -> Result<(), ServiceError> {
        let bundle = self.tenants.load().await?;
        let time = self.now().await?;
        let verified = verify_bundle(&self.trust, self.platform, &self.pin, &bundle, self.telemetry_keys(), &time)?;
        let mut held = lock(&self.bundle);
        self.state.update(verified)?;
        lock(&self.wrap_keys).extend(wrap_keys(&self.trust, &self.pin, &bundle));
        *held = bundle;
        Ok(())
    }

    /// Applies `item` at once: the latest bundle with it added is verified again and merged into
    /// the cache (which keeps it across later reloads), then every live session is rechecked.
    pub(crate) fn apply_local(&self, item: Local) {
        let time = self.time.estimate();
        {
            let held = lock(&self.bundle);
            let mut bundle = held.clone();
            match item {
                Local::Signal(signal) => bundle.signals.push(signal),
                Local::End(end) => bundle.ended_sessions.push(end),
            }
            let applied = verify_bundle(&self.trust, self.platform, &self.pin, &bundle, self.telemetry_keys(), &time)
                .and_then(|verified| self.state.update(verified).map_err(ServiceError::from));
            if let Err(e) = applied {
                tracing::warn!(error = %e, "could not apply a locally signed signal or session end");
            }
        }
        live::recheck_all(self);
    }
}
