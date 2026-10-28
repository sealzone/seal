//! Blob crypto owns headers, digests, IDs and nonces. Callers supply intent only.
//!
//! Sealing needs only public keys: the DEK is HPKE-wrapped (`DekWrap::Hpke`) to each
//! platform's guardian-certified `TenantWrapKey`, so an enclave on one platform seals for
//! every platform the tenant enables. Opening needs that platform's private wrap key.
//!
//! The DEK is a random AES-256-GCM key; each wrap is HPKE with
//! `info = DEK_WRAP_INFO || platform` (`kdf::platform_bytes`) and `aad = canonical(header)`;
//! the secret is AES-256-GCM under the DEK with a random 12-byte nonce and the same `aad`.
use std::collections::BTreeSet;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};

use crate::{CryptoError, Key32, SecretBytes, TenantWrappingKey};
use seal_proto::blob::{BlobHeader, DekWrap, DEK_WRAP_INFO, POLICY_LABEL};
use seal_proto::codec::{canonical, labeled_digest};
use seal_proto::{
    blob::Blob, identity::WorkloadIdentity, policy::SecretPolicy, release::TenantWrapKey, BlobId, PlatformId, UnixTime,
};

/// `DEK_WRAP_INFO || platform`.
fn wrap_info(platform: PlatformId) -> Vec<u8> {
    [DEK_WRAP_INFO, crate::kdf::platform_bytes(platform)].concat()
}

/// Seals for one tenant key version across platforms.
pub struct BlobSealer<'k> {
    recipients: &'k [TenantWrapKey],
}
impl<'k> BlobSealer<'k> {
    /// `recipients` must already be verified against `Trust::guardians` and all name the same
    /// tenant, root and tenant key version, one per platform (`Malformed` otherwise, and when
    /// empty).
    pub fn new(recipients: &'k [TenantWrapKey]) -> Result<Self, CryptoError> {
        let Some(first) = recipients.first() else {
            return Err(CryptoError::Malformed("no DEK wrap recipients".into()));
        };
        let mut platforms = BTreeSet::new();
        for r in recipients {
            if r.tenant != first.tenant
                || r.root_id != first.root_id
                || r.tenant_key_version != first.tenant_key_version
            {
                return Err(CryptoError::Malformed("DEK wrap recipients name different tenant keys".into()));
            }
            if !platforms.insert(r.platform) {
                return Err(CryptoError::Malformed("two DEK wrap recipients for one platform".into()));
            }
        }
        Ok(Self { recipients })
    }
    /// Generates the header (tenant, root, version from the recipients), the DEK, one wrap per
    /// recipient and all nonces internally. No caller nonces. `Malformed` when the policy is
    /// invalid, when a recipient's platform is below the policy's `min_platform`, or when a
    /// recipient key is unusable.
    pub fn seal(
        &self,
        secret: &[u8],
        policy: SecretPolicy,
        producer: WorkloadIdentity,
        now: UnixTime,
        rng: &mut impl rand::CryptoRng,
    ) -> Result<Blob, CryptoError> {
        policy.validate().map_err(|e| CryptoError::Malformed(e.to_string()))?;
        if let Some(min) = policy.min_platform() {
            if self.recipients.iter().any(|r| r.platform.tier() < min) {
                return Err(CryptoError::Malformed("a DEK wrap recipient is below the policy's min_platform".into()));
            }
        }
        let first = &self.recipients[0];
        let mut blob_id = [0u8; 8];
        rng.fill_bytes(&mut blob_id);
        let header = BlobHeader {
            version: 1,
            tenant: first.tenant.clone(),
            root_id: first.root_id,
            tenant_key_version: first.tenant_key_version,
            blob_id: BlobId(blob_id),
            producer,
            policy_digest: labeled_digest(POLICY_LABEL, &policy),
            created_at: now,
        };
        let aad = canonical(&header);
        let dek = Key32::generate(rng);
        let wraps = self
            .recipients
            .iter()
            .map(|r| {
                let (enc, wrapped_dek) =
                    crate::hpke::seal(&r.public_key, &wrap_info(r.platform), &aad, dek.expose(), rng)?;
                Ok(DekWrap::Hpke { platform: r.platform, enc, wrapped_dek })
            })
            .collect::<Result<Vec<_>, CryptoError>>()?;
        let mut nonce = [0u8; 12];
        rng.fill_bytes(&mut nonce);
        let ciphertext = Aes256Gcm::new(dek.expose().into())
            .encrypt(&Nonce::from(nonce), Payload { msg: secret, aad: &aad })
            .map_err(|_| CryptoError::Malformed("secret too long".into()))?;
        let blob = Blob { header, policy, wraps, nonce, ciphertext };
        blob.check_structure().map_err(|e| CryptoError::Malformed(e.to_string()))?;
        Ok(blob)
    }
}

/// Opens blobs with one platform's private wrap key.
pub struct BlobCipher<'k> {
    key: &'k TenantWrappingKey,
}
impl<'k> BlobCipher<'k> {
    pub fn new(key: &'k TenantWrappingKey) -> Self {
        Self { key }
    }
    pub fn scope(&self) -> &crate::TenantWrappingKeyScope {
        self.key.scope()
    }
    /// Checks tenant/root/tenant key version against the key's scope (`Malformed`), takes the
    /// wrap for the key's platform (`NoWrapForPlatform` if none, `Malformed` if several), checks
    /// structure (`Blob::check_structure`, including the policy digest; `Malformed`) and AEAD
    /// (`Decrypt`); does not authorize application use.
    pub fn open(&self, blob: &Blob) -> Result<OpenedBlob, CryptoError> {
        let scope = self.key.scope();
        let h = &blob.header;
        if h.tenant != scope.tenant || h.root_id != scope.root_id || h.tenant_key_version != scope.tenant_key_version {
            return Err(CryptoError::Malformed("blob was sealed for another tenant key".into()));
        }
        let mut wraps = blob.wraps.iter().filter(|w| w.platform() == scope.platform);
        let Some(DekWrap::Hpke { enc, wrapped_dek, .. }) = wraps.next() else {
            return Err(CryptoError::NoWrapForPlatform);
        };
        if wraps.next().is_some() {
            return Err(CryptoError::Malformed("blob has two DEK wraps for one platform".into()));
        }
        blob.check_structure().map_err(|e| CryptoError::Malformed(e.to_string()))?;
        let aad = canonical(&blob.header);
        let dek = crate::hpke::open_wrap(self.key, enc, wrapped_dek, &wrap_info(scope.platform), &aad)?;
        let dek: &[u8; 32] = dek.expose().try_into().map_err(|_| CryptoError::Decrypt)?;
        let secret = Aes256Gcm::new(dek.into())
            .decrypt(&Nonce::from(blob.nonce), Payload { msg: &blob.ciphertext, aad: &aad })
            .map_err(|_| CryptoError::Decrypt)?;
        Ok(OpenedBlob { blob: blob.clone(), secret: SecretBytes::new(secret) })
    }
}

/// Exact authenticated envelope plus its plaintext. No unchecked constructor.
pub struct OpenedBlob {
    blob: Blob,
    secret: SecretBytes,
}
impl OpenedBlob {
    pub fn blob(&self) -> &Blob {
        &self.blob
    }
    pub fn secret(&self) -> &[u8] {
        self.secret.expose()
    }
}

impl std::fmt::Debug for OpenedBlob {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("OpenedBlob").field("blob", &self.blob.header.blob_id).field("secret", &self.secret).finish()
    }
}
