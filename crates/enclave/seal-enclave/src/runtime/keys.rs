//! Tenant wrapping keys: fetched from the `KeyProvider` per tenant key version, checked for
//! exactly the requested scope, cached for `TENANT_KEY_CACHE_SECS`, and used to open blobs.

use seal_proto::telemetry::RefusalContext;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use seal_crypto::blob::{BlobCipher, OpenedBlob};
use seal_crypto::{TenantWrappingKey, TenantWrappingKeyScope};
use seal_proto::blob::Blob;
use seal_proto::{ErrorCode, TenantKeyVersion};
use seal_verify::VerifiedTenant;

use super::{fail, lock, Runtime};
use crate::{ServiceError, TENANT_KEY_CACHE_SECS};

#[derive(Default)]
pub(super) struct TenantKeyCache {
    keys: Mutex<HashMap<TenantKeyVersion, (Arc<TenantWrappingKey>, Instant)>>,
}

impl Runtime {
    /// The wrapping key of `version` on this platform, refetched once it is
    /// `TENANT_KEY_CACHE_SECS` old: a revoked customer-managed key stops new sessions then.
    async fn tenant_key(&self, version: TenantKeyVersion) -> Result<Arc<TenantWrappingKey>, ServiceError> {
        if let Some((key, fetched)) = lock(&self.tenant_keys.keys).get(&version) {
            if fetched.elapsed() < Duration::from_secs(TENANT_KEY_CACHE_SECS) {
                return Ok(key.clone());
            }
        }
        let scope = TenantWrappingKeyScope {
            platform: self.platform,
            tenant: self.pin.tenant.clone(),
            root_id: self.pin.root_id,
            tenant_key_version: version,
        };
        let key = self.keys.tenant_wrapping_key(&scope).await?;
        if key.scope() != &scope {
            return Err(fail(ErrorCode::VerificationFailed, "tenant wrapping key for another scope"));
        }
        let key = Arc::new(key);
        lock(&self.tenant_keys.keys).insert(version, (key.clone(), Instant::now()));
        Ok(key)
    }

    /// Opens `blob` (not yet authorized: callers take a permit or recheck the claims). Only
    /// blobs of the pinned tenant and root within `tenant`'s accepted key versions get as far
    /// as a key request.
    pub(crate) async fn open(&self, blob: &Blob, tenant: &VerifiedTenant) -> Result<OpenedBlob, ServiceError> {
        let header = &blob.header;
        if header.tenant != self.pin.tenant || header.root_id != self.pin.root_id {
            return Err(fail(ErrorCode::NotAllowed, "blob of another tenant")
                .with(RefusalContext::OtherTenant { tenant: header.tenant.clone() }));
        }
        let versions = tenant.state().tenant_key_versions;
        if header.tenant_key_version < versions.oldest_accepted {
            return Err(fail(ErrorCode::Expired, "blob tenant key version retired").with(
                RefusalContext::KeyVersionRetired {
                    version: header.tenant_key_version,
                    oldest_accepted: versions.oldest_accepted,
                },
            ));
        }
        if header.tenant_key_version > versions.current {
            return Err(fail(ErrorCode::Unavailable, "blob sealed under a newer tenant state")
                .with(RefusalContext::NewerState { version: header.tenant_key_version }));
        }
        if !blob.wraps.iter().any(|w| w.platform() == self.platform) {
            // Sealed before the tenant enabled this platform, unless its policy keeps it off
            // this platform: then resealing would not help.
            if blob.policy.min_platform().is_some_and(|min| self.platform.tier() < min) {
                return Err(fail(ErrorCode::NotAllowed, "the blob's min_platform excludes this platform")
                    .with(RefusalContext::PlatformExcluded { platform: self.platform }));
            }
            return Err(fail(ErrorCode::ResealRequired, "the blob has no wrap for this platform")
                .with(RefusalContext::NotSealedForPlatform { platform: self.platform }));
        }
        let key = self.tenant_key(header.tenant_key_version).await?;
        BlobCipher::new(&key).open(blob).map_err(|e| fail(e.code(), format!("blob: {e}")))
    }
}
