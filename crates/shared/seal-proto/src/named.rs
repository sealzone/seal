//! Named secrets: blobs a tenant's admins publish under a name (`openai`), so apps start
//! sessions on the name and pick up a new version without a redeploy.
//!
//! The control plane stores them; it is untrusted, so each version is its own document signed
//! by the threshold of the tenant's latest root (`NAMED_SECRET_LABEL`). They are not part of
//! signed tenant state: publishing has no pending window and is not logged. An app reaches a
//! name only through its enclave (`POST /v1/secrets/resolve`), which fetches the newest version
//! from the control plane, checks the signatures against the latest root, that the blob is the
//! one signed for, and that the caller is granted one of the blob's apps.
//!
//! A version points at a blob by id and SHA-256 of its text, or at nothing: a deletion. The
//! blob itself is the sealed secret it always was, so storing it reveals nothing, and a name
//! is no kill switch: whoever holds an older blob's text can still use it while it is valid.

use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::blob::Blob;
use crate::signed::Signed;
use crate::{codec, BlobId, ProtoError, SecretName, TenantId, TenantRootId, UnixTime};

/// What admins sign for one version of a name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamedSecret {
    pub tenant: TenantId,
    /// The chain the version was published under. Its admin keys are the latest root's.
    pub root_id: TenantRootId,
    pub name: SecretName,
    /// 1 for a name's first version, one more for each after it, deletions included.
    pub version: u64,
    /// The blob this version points at; `None` deletes the name.
    pub blob: Option<BlobRef>,
    /// When the admin published it, by their own clock. Shown, never relied on.
    pub published_at: UnixTime,
}

/// The signatures cover `labeled_digest(NAMED_SECRET_LABEL, &NamedSecret)`.
pub const NAMED_SECRET_LABEL: &str = "seal/named-secret/v1";

pub type SignedNamedSecret = Signed<NamedSecret>;

/// One blob, by its id and the SHA-256 of its text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobRef {
    pub blob_id: BlobId,
    #[serde(with = "codec::array_b64")]
    pub sha256: [u8; 32],
}

impl BlobRef {
    /// The reference to a blob's text. Refuses text that is not a blob.
    pub fn of(text: &str) -> Result<Self, ProtoError> {
        let blob = Blob::from_str(text)?;
        Ok(Self { blob_id: blob.header.blob_id, sha256: Sha256::digest(text.as_bytes()).into() })
    }
}

/// One version as the control plane stores and serves it: the signed entry and, unless it is a
/// deletion, the blob's text.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamedSecretVersion {
    pub entry: SignedNamedSecret,
    pub blob: Option<String>,
}

impl NamedSecretVersion {
    /// The blob is the one the entry names (and both are absent for a deletion), and it is the
    /// entry's tenant and chain's. Signatures are checked separately, against the latest root.
    pub fn check(&self) -> Result<(), ProtoError> {
        let entry = &self.entry.body;
        match (&entry.blob, self.blob.as_deref()) {
            (None, None) => Ok(()),
            (Some(named), Some(text)) => {
                if BlobRef::of(text)? != *named {
                    return Err(ProtoError::invalid("blob", "not the blob the entry names"));
                }
                let blob = Blob::from_str(text)?;
                if blob.header.tenant != entry.tenant || blob.header.root_id != entry.root_id {
                    return Err(ProtoError::invalid("blob", "sealed for another tenant or root chain"));
                }
                Ok(())
            }
            (Some(_), None) => Err(ProtoError::invalid("blob", "missing")),
            (None, Some(_)) => Err(ProtoError::invalid("blob", "a deletion carries no blob")),
        }
    }

    /// The blob's text, unless this version deletes the name.
    pub fn text(&self) -> Option<&str> {
        self.blob.as_deref()
    }
}

/// Names one tenant may have, deletions excluded.
pub const MAX_NAMED_SECRETS: usize = 256;
/// Versions of each name the control plane keeps, newest first.
pub const NAMED_SECRET_VERSIONS_KEPT: usize = 10;
/// Largest blob text a name may point at.
pub const MAX_NAMED_BLOB_BYTES: usize = 256 << 10;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob::{BlobHeader, DekWrap, BLOB_VERSION, POLICY_LABEL};
    use crate::policy::SecretPolicy;
    use crate::{AppName, PlatformId, TenantKeyVersion};

    fn blob(tenant: &str, root: u8, id: u8) -> String {
        let policy = SecretPolicy::new("https://api.example.com/v1", [AppName::new("checkout").unwrap()]).unwrap();
        Blob {
            header: BlobHeader {
                version: BLOB_VERSION,
                tenant: TenantId::new(tenant).unwrap(),
                root_id: TenantRootId([root; 32]),
                tenant_key_version: TenantKeyVersion(1),
                blob_id: BlobId([id; 8]),
                policy_digest: codec::labeled_digest(POLICY_LABEL, &policy),
                created_at: 1,
            },
            policy,
            wraps: vec![DekWrap::Hpke { platform: PlatformId::Sim, enc: vec![1; 32], wrapped_dek: vec![2; 48] }],
            nonce: [3; 12],
            ciphertext: vec![4; 40],
        }
        .to_string()
    }

    fn version(text: Option<String>, named: Option<&str>) -> NamedSecretVersion {
        NamedSecretVersion {
            entry: Signed {
                body: NamedSecret {
                    tenant: TenantId::new("acme").unwrap(),
                    root_id: TenantRootId([6; 32]),
                    name: SecretName::new("openai").unwrap(),
                    version: 1,
                    blob: named.map(|t| BlobRef::of(t).unwrap()),
                    published_at: 1,
                },
                signatures: vec![],
            },
            blob: text,
        }
    }

    #[test]
    fn a_version_carries_exactly_the_blob_it_names() {
        let ours = blob("acme", 6, 1);
        assert!(version(Some(ours.clone()), Some(&ours)).check().is_ok());
        assert!(version(None, None).check().is_ok());
        assert!(version(Some(blob("acme", 6, 2)), Some(&ours)).check().is_err());
        assert!(version(None, Some(&ours)).check().is_err());
        assert!(version(Some(ours.clone()), None).check().is_err());
        let foreign = blob("acme", 7, 1);
        assert!(version(Some(foreign.clone()), Some(&foreign)).check().is_err());
    }

    #[test]
    fn names_are_never_blobs() {
        assert!(SecretName::new("openai").is_ok());
        assert!(SecretName::new(blob("acme", 6, 1)).is_err());
        assert!(SecretName::new("open.ai").is_err());
    }
}
