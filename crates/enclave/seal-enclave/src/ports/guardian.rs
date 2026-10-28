//! `KeyProvider` backed by the key guardian (`seal_guardian::client::GuardianClient`).
//!
//! One key request per call (tenant wrapping keys are cached, see below):
//!
//! 1. `ControlKeyRequestSource::inputs`: this release's evidence, the tenant's bundle and the
//!    tenant's co-signature of this release when its root requires one;
//! 2. `GuardianClient::challenge`;
//! 3. a fresh `EphemeralKey`, and a `KeyRequestBinding` naming it, the challenge and the purpose
//!    (`KeyPurpose::Service { tenant, root_id }` or `KeyPurpose::Tenant { tenant, root_id,
//!    tenant_key_versions: [v] }`);
//! 4. evidence from this enclave's attestor with report data
//!    `labeled_digest(KEY_REQUEST_BINDING_LABEL, binding)`;
//! 5. `GuardianClient::keys`, which accepts only a response the configured guardian key signed
//!    for exactly this binding, then `open_response` with the ephemeral key;
//! 6. the released keys must have exactly the requested scope (platform, tenant, root and
//!    version), or they are dropped and the call fails with `Internal`.
//!
//! The ephemeral key lives only for the call. Tenant wrapping keys are kept for
//! `TENANT_KEY_CACHE_SECS` after they were fetched and then requested again, so a revoked
//! customer-managed key stops working for new sessions within that time.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use seal_crypto::{EphemeralKey, ServiceKeyScope, ServiceKeys, TenantWrappingKey, TenantWrappingKeyScope};
use seal_guardian::client::{open_response, GuardianClient};
use seal_guardian::GuardianError;
use seal_proto::codec::labeled_digest;
use seal_proto::release::{
    KeyPurpose, KeyRequest, KeyRequestBinding, ReleaseCosign, ReleaseEvidence, ReleasedKeys, GUARDIAN_PROTOCOL_VERSION,
    KEY_REQUEST_BINDING_LABEL,
};
use seal_proto::signed::Signed;
use seal_proto::state::TenantBundle;
use seal_proto::{ErrorCode, PlatformId, SecretVec};
use tokio::time::Instant;

use super::control::ControlKeyRequestSource;
use crate::{fail, lock, rng, KeyProvider, ServiceError, TENANT_KEY_CACHE_SECS};

/// What a `KeyRequest` carries besides its binding and evidence. Unverified here: the guardian
/// verifies each part before releasing anything.
pub(crate) struct KeyRequestInputs {
    /// For the attestor's own platform and measurement.
    pub release: ReleaseEvidence,
    /// The deployment's tenant, with current freshness statements.
    pub bundle: TenantBundle,
    /// Required by the guardian when the bundle's latest root has `cosign_releases`.
    pub cosign: Option<Signed<ReleaseCosign>>,
}

/// The guardian-backed `KeyProvider`. `attestor` is this enclave's own (`seal_tee::Attestor`,
/// the one `Cloud` uses); scopes for any other platform are refused before anything is sent.
pub struct GuardianKeyProvider {
    client: GuardianClient,
    attestor: Arc<seal_tee::Attestor>,
    /// Where the inputs come from, once per request so the guardian sees the newest bundle.
    inputs: ControlKeyRequestSource,
    tenant_keys: Mutex<TenantKeyCache>,
}

impl GuardianKeyProvider {
    pub fn new(client: GuardianClient, attestor: Arc<seal_tee::Attestor>, inputs: ControlKeyRequestSource) -> Self {
        Self {
            client,
            attestor,
            inputs,
            tenant_keys: Mutex::new(TenantKeyCache::new(Duration::from_secs(TENANT_KEY_CACHE_SECS))),
        }
    }

    /// Steps 1 to 5 of the module docs for `purpose`; the caller checks the scope.
    async fn request(&self, platform: PlatformId, purpose: KeyPurpose) -> Result<ReleasedKeys, ServiceError> {
        if platform != self.attestor.platform() {
            return Err(fail(
                ErrorCode::Internal,
                format!("keys requested for {platform:?}, this enclave runs on {:?}", self.attestor.platform()),
            ));
        }
        let measurement = self.attestor.measurement();
        let KeyRequestInputs { release, bundle, cosign } = self.inputs.inputs(platform, &measurement).await?;
        let challenge = self.client.challenge().await.map_err(guardian_error)?;
        let ephemeral = EphemeralKey::generate(&mut rng());
        let binding = KeyRequestBinding {
            protocol_version: GUARDIAN_PROTOCOL_VERSION,
            challenge,
            ephemeral_public_key: ephemeral.public_key(),
            purpose,
        };
        let evidence = self
            .attestor
            .attest(labeled_digest(KEY_REQUEST_BINDING_LABEL, &binding))
            .await
            .map_err(|e| fail(e.code(), format!("attest key request: {e}")))?;
        let request = KeyRequest {
            protocol_version: GUARDIAN_PROTOCOL_VERSION,
            evidence,
            binding,
            release,
            tenant: Some(bundle),
            tenant_cosign: cosign,
        };
        let response = self.client.keys(&request).await.map_err(guardian_error)?;
        open_response(&ephemeral, &request.binding, &response).map_err(guardian_error)
    }
}

fn guardian_error(e: GuardianError) -> ServiceError {
    fail(e.code(), format!("guardian: {e}"))
}

fn scope_mismatch(what: &str) -> ServiceError {
    tracing::error!("the guardian released {what} for another scope than requested");
    fail(ErrorCode::Internal, format!("released {what} are for another scope than requested"))
}

#[async_trait]
impl KeyProvider for GuardianKeyProvider {
    async fn service_keys(&self, scope: &ServiceKeyScope) -> Result<ServiceKeys, ServiceError> {
        let purpose = KeyPurpose::Service { tenant: scope.tenant.clone(), root_id: scope.root_id };
        let released = self.request(scope.platform, purpose).await?;
        let keys = ServiceKeys::from_released(scope.platform, &released)
            .map_err(|e| fail(ErrorCode::Internal, format!("released service keys: {e}")))?;
        if keys.scope != *scope {
            return Err(scope_mismatch("service keys"));
        }
        Ok(keys)
    }

    async fn tenant_wrapping_key(&self, scope: &TenantWrappingKeyScope) -> Result<TenantWrappingKey, ServiceError> {
        let cached = lock(&self.tenant_keys).get(scope, Instant::now());
        if let Some(seed) = cached {
            return wrapping_key(scope, seed);
        }
        let purpose = KeyPurpose::Tenant {
            tenant: scope.tenant.clone(),
            root_id: scope.root_id,
            tenant_key_versions: vec![scope.tenant_key_version],
        };
        let released = self.request(scope.platform, purpose).await?;
        let ReleasedKeys::Tenant { tenant, root_id, mut keys } = released else {
            return Err(scope_mismatch("tenant wrapping keys"));
        };
        if tenant != scope.tenant
            || root_id != scope.root_id
            || keys.len() != 1
            || keys[0].0 != scope.tenant_key_version
        {
            return Err(scope_mismatch("tenant wrapping keys"));
        }
        let (_, seed) = keys.remove(0);
        let key = wrapping_key(scope, seed.duplicate())?;
        lock(&self.tenant_keys).insert(scope.clone(), seed, Instant::now());
        Ok(key)
    }
}

/// The wrapping key of `scope` from its released seed; `Internal` unless it has exactly `scope`.
fn wrapping_key(scope: &TenantWrappingKeyScope, seed: SecretVec) -> Result<TenantWrappingKey, ServiceError> {
    let released = ReleasedKeys::Tenant {
        tenant: scope.tenant.clone(),
        root_id: scope.root_id,
        keys: vec![(scope.tenant_key_version, seed)],
    };
    let mut keys = TenantWrappingKey::from_released(scope.platform, &released)
        .map_err(|e| fail(ErrorCode::Internal, format!("released tenant wrapping key: {e}")))?;
    match (keys.pop(), keys.is_empty()) {
        (Some(key), true) if key.scope() == scope => Ok(key),
        _ => Err(scope_mismatch("tenant wrapping keys")),
    }
}

/// Released tenant wrapping-key seeds by scope, each kept for `ttl` after it was fetched.
/// Seeds are `SecretVec`s and zeroize when evicted.
struct TenantKeyCache {
    ttl: Duration,
    entries: Vec<(TenantWrappingKeyScope, SecretVec, Instant)>,
}

impl TenantKeyCache {
    fn new(ttl: Duration) -> Self {
        Self { ttl, entries: Vec::new() }
    }

    /// A copy of the seed for `scope` if it was fetched less than `ttl` before `now`. Drops
    /// every expired entry.
    fn get(&mut self, scope: &TenantWrappingKeyScope, now: Instant) -> Option<SecretVec> {
        let ttl = self.ttl;
        self.entries.retain(|(_, _, at)| now.saturating_duration_since(*at) < ttl);
        self.entries.iter().find(|(s, _, _)| s == scope).map(|(_, seed, _)| seed.duplicate())
    }

    fn insert(&mut self, scope: TenantWrappingKeyScope, seed: SecretVec, now: Instant) {
        self.entries.retain(|(s, _, _)| *s != scope);
        self.entries.push((scope, seed, now));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seal_proto::{TenantId, TenantKeyVersion, TenantRootId};

    fn scope(version: u32) -> TenantWrappingKeyScope {
        TenantWrappingKeyScope {
            platform: PlatformId::Sim,
            tenant: TenantId::new("acme").unwrap(),
            root_id: TenantRootId([1; 32]),
            tenant_key_version: TenantKeyVersion(version),
        }
    }

    #[test]
    fn cache_keeps_seeds_for_the_ttl_only() {
        let start = Instant::now();
        let mut cache = TenantKeyCache::new(Duration::from_secs(TENANT_KEY_CACHE_SECS));
        cache.insert(scope(1), SecretVec::new(vec![7; 32]), start);
        cache.insert(scope(2), SecretVec::new(vec![8; 32]), start + Duration::from_secs(100));

        let almost = start + Duration::from_secs(TENANT_KEY_CACHE_SECS - 1);
        assert_eq!(cache.get(&scope(1), almost).unwrap().expose(), &[7; 32]);
        assert!(cache.get(&scope(3), almost).is_none());

        let expired = start + Duration::from_secs(TENANT_KEY_CACHE_SECS);
        assert!(cache.get(&scope(1), expired).is_none());
        assert_eq!(cache.entries.len(), 1, "expired entries are dropped");
        assert_eq!(cache.get(&scope(2), expired).unwrap().expose(), &[8; 32]);
    }

    #[test]
    fn a_refetch_replaces_the_entry() {
        let start = Instant::now();
        let mut cache = TenantKeyCache::new(Duration::from_secs(10));
        cache.insert(scope(1), SecretVec::new(vec![7; 32]), start);
        cache.insert(scope(1), SecretVec::new(vec![9; 32]), start + Duration::from_secs(9));
        assert_eq!(cache.entries.len(), 1);
        assert_eq!(cache.get(&scope(1), start + Duration::from_secs(15)).unwrap().expose(), &[9; 32]);
    }

    #[test]
    fn wrapping_keys_carry_the_requested_scope() {
        let key = wrapping_key(&scope(2), SecretVec::new(vec![3; 32])).unwrap();
        assert_eq!(key.scope(), &scope(2));
        assert_eq!(wrapping_key(&scope(2), SecretVec::new(vec![3; 31])).unwrap_err().code, ErrorCode::Internal);
    }
}
