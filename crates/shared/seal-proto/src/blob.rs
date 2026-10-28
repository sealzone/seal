//! The blob: a sealed secret plus its policy, safe to store anywhere.
//!
//! Text form: `seal1.<tenant>.<tenant_key_version>.<blob_id>.<base64url(canonical(Blob))>`.
//! The dotted prefix repeats header fields for humans and logs; parsing
//! rejects a prefix that disagrees with the body.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::policy::SecretPolicy;
use crate::{codec, BlobId, PlatformId, ProtoError, TenantId, TenantKeyVersion, TenantRootId, UnixTime};

pub const BLOB_PREFIX: &str = "seal1";
/// `BlobHeader::version`.
pub const BLOB_VERSION: u8 = 2;
pub const POLICY_LABEL: &str = "seal/policy/v1";

/// Authenticated, unencrypted header. `codec::canonical(&BlobHeader)` is the
/// associated data of the secret's AEAD, so editing any field breaks the blob.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobHeader {
    pub version: u8,
    pub tenant: TenantId,
    /// The tenant root chain the blob was sealed under. Its wrapping key derives from it.
    pub root_id: TenantRootId,
    pub tenant_key_version: TenantKeyVersion,
    pub blob_id: BlobId,
    /// `codec::labeled_digest(POLICY_LABEL, &policy)`. The policy travels in clear text next
    /// to the header; this digest, inside the AEAD's associated data, makes it tamper-evident.
    #[serde(with = "codec::array_b64")]
    pub policy_digest: [u8; 32],
    pub created_at: UnixTime,
}

/// The secret's DEK, wrapped for one platform.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DekWrap {
    /// HPKE (ingest suite) to the platform's `TenantWrapKey` for (tenant, root_id,
    /// tenant_key_version), `info = DEK_WRAP_INFO || platform`, `aad = canonical(header)`.
    /// Wrapping needs only the guardian-certified public key, so an enclave on one platform
    /// wraps for every platform the tenant enables; opening needs the private key, which only
    /// that platform's guardian releases, to that platform's enclaves.
    Hpke {
        platform: PlatformId,
        #[serde(with = "codec::bytes_b64")]
        enc: Vec<u8>,
        #[serde(with = "codec::bytes_b64")]
        wrapped_dek: Vec<u8>,
    },
}
pub const DEK_WRAP_INFO: &[u8] = b"seal/dek-wrap/v1";

impl DekWrap {
    pub fn platform(&self) -> PlatformId {
        match self {
            DekWrap::Hpke { platform, .. } => *platform,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Blob {
    pub header: BlobHeader,
    pub policy: SecretPolicy,
    /// One wrap per platform the tenant enabled at seal time (at or above the policy's
    /// `min_platform`). Any listed platform can open the blob.
    pub wraps: Vec<DekWrap>,
    #[serde(with = "codec::array_b64")]
    pub nonce: [u8; 12],
    /// AES-256-GCM(dek, secret), AAD = canonical(header).
    #[serde(with = "codec::bytes_b64")]
    pub ciphertext: Vec<u8>,
}

impl Blob {
    /// Structural checks only; cryptographic checks live in `seal-crypto`.
    pub fn check_structure(&self) -> Result<(), ProtoError> {
        if self.header.version != BLOB_VERSION {
            return Err(ProtoError::Unsupported(format!("blob version {}", self.header.version)));
        }
        if codec::labeled_digest(POLICY_LABEL, &self.policy) != self.header.policy_digest {
            return Err(ProtoError::invalid("blob", "policy does not match the sealed policy digest"));
        }
        self.policy.validate()?;
        if self.wraps.is_empty() {
            return Err(ProtoError::invalid("blob", "no DEK wraps"));
        }
        Ok(())
    }
}

impl fmt::Display for Blob {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let h = &self.header;
        write!(
            f,
            "{BLOB_PREFIX}.{}.{}.{}.{}",
            h.tenant,
            h.tenant_key_version,
            h.blob_id,
            codec::b64url(&codec::canonical(self))
        )
    }
}

impl FromStr for Blob {
    type Err = ProtoError;
    fn from_str(s: &str) -> Result<Self, ProtoError> {
        let s = s.trim();
        let mut parts = s.splitn(5, '.');
        let (Some(prefix), Some(tenant), Some(tenant_key_version), Some(blob_id), Some(body)) =
            (parts.next(), parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(ProtoError::Malformed("blob: expected seal1.<tenant>.<tenant_key_version>.<id>.<body>".into()));
        };
        if prefix != BLOB_PREFIX {
            return Err(ProtoError::Unsupported(format!("blob prefix `{prefix}`")));
        }
        let blob: Blob = codec::from_canonical(&codec::from_b64url(body)?)?;
        let h = &blob.header;
        if h.tenant.as_str() != tenant
            || h.tenant_key_version.0.to_string() != tenant_key_version
            || h.blob_id.to_string() != blob_id
        {
            return Err(ProtoError::invalid("blob", "text prefix disagrees with the sealed header"));
        }
        blob.check_structure()?;
        Ok(blob)
    }
}
