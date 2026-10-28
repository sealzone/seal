use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::ProtoError;

/// Seconds since the Unix epoch. All Seal timestamps use this.
pub type UnixTime = u64;

fn validate_name(field: &'static str, s: &str) -> Result<(), ProtoError> {
    let ok = (1..=32).contains(&s.len())
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !s.starts_with('-')
        && !s.ends_with('-');
    if ok {
        Ok(())
    } else {
        Err(ProtoError::invalid(field, "1-32 chars of [a-z0-9-], not starting or ending with '-'"))
    }
}

macro_rules! name_type {
    ($(#[$m:meta])* $name:ident, $field:literal) => {
        $(#[$m])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            pub fn new(s: impl Into<String>) -> Result<Self, ProtoError> {
                let s = s.into();
                validate_name($field, &s)?;
                Ok(Self(s))
            }
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
        impl TryFrom<String> for $name {
            type Error = ProtoError;
            fn try_from(s: String) -> Result<Self, ProtoError> {
                Self::new(s)
            }
        }
        impl From<$name> for String {
            fn from(v: $name) -> String {
                v.0
            }
        }
        impl FromStr for $name {
            type Err = ProtoError;
            fn from_str(s: &str) -> Result<Self, ProtoError> {
                Self::new(s)
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

name_type!(
    /// One Seal customer account (e.g. `acme`).
    TenantId,
    "tenant"
);
name_type!(
    /// A named app in a tenant (e.g. `checkout`): a set of workload identities.
    AppName,
    "app"
);

macro_rules! bytes_type {
    ($(#[$m:meta])* $name:ident, $n:literal) => {
        $(#[$m])*
        /// JSON and other human-readable formats: lowercase hex (same as `Display`). CBOR: bytes.
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub [u8; $n]);

        impl Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                if s.is_human_readable() { s.serialize_str(&hex::encode(self.0)) } else { s.serialize_bytes(&self.0) }
            }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                struct V;
                impl<'de> serde::de::Visitor<'de> for V {
                    type Value = $name;
                    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str(concat!($n, " bytes or hex")) }
                    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<$name, E> { v.parse().map_err(E::custom) }
                    fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<$name, E> {
                        v.try_into().map($name).map_err(|_| E::custom(concat!("expected ", $n, " bytes")))
                    }
                }
                d.deserialize_any(V)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), hex::encode(self.0))
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str(&hex::encode(self.0))
            }
        }
        impl FromStr for $name {
            type Err = ProtoError;
            fn from_str(s: &str) -> Result<Self, ProtoError> {
                let v = hex::decode(s).map_err(|e| ProtoError::invalid(stringify!($name), e.to_string()))?;
                let a: [u8; $n] = v
                    .try_into()
                    .map_err(|_| ProtoError::invalid(stringify!($name), concat!("expected ", $n, " bytes")))?;
                Ok(Self(a))
            }
        }
    };
}

bytes_type!(
    /// Random id of one sealed secret version. Unique within a tenant.
    BlobId,
    8
);
bytes_type!(
    /// The platform-neutral fingerprint of "what code runs" in a TEE, always
    /// `SHA-384(platform label || platform value)`:
    /// - Azure confidential ACI: value = SNP `host_data`, the SHA-256 of the
    ///   confidential-container security policy, which pins every image digest
    ///   and forbids exec. NOT the launch measurement: that is Microsoft's
    ///   utility VM, which changes when Microsoft updates it; it is checked
    ///   separately against Microsoft's signed UVM endorsement and the
    ///   checkpoint's minimum TCB. Key Vault's release policy pins the same host_data.
    /// - AWS Nitro: value = PCR0 || PCR1 || PCR2 of the enclave image (EIF), built from the
    ///   release's container image by `nitro-cli build-enclave` with a pinned boot blob set
    ///   (`bzImage`, `cmdline`, `init`, `nsm.ko`, `linuxkit`, by SHA-256; the nitro-cli
    ///   version does not matter). PCR1 depends only on the blobs; PCR2 only on the image's
    ///   filesystem, CMD and ENV. The EIF's metadata section is not attested, so nothing may
    ///   depend on it.
    /// - GCP Confidential Space: value = the container image digest. The image's launch-policy
    ///   labels (which env overrides, log redirection and restart policies the operator may
    ///   set) are part of the image, so the digest covers them.
    /// - Sim: SHA-384 of the binary.
    /// One release builds one container image for all three clouds, so a release has three
    /// measurements and three manifests.
    Measurement,
    48
);
bytes_type!(
    /// A 32-byte public key: Ed25519 for signing keys, X25519 for HPKE recipients
    /// (the ingest key, a guardian requester's ephemeral key).
    PublicKey,
    32
);
bytes_type!(
    /// SHA-256 of a public key's canonical bytes; names signing keys in
    /// manifests, checkpoints and signed state.
    KeyId,
    32
);
bytes_type!(
    /// Which tenant, beyond its name: `labeled_digest(TENANT_ROOT_ID_LABEL, root v1)`
    /// (`state::root_id`). Every tenant key derives from it and every blob header carries it,
    /// so a competing root v1 for the same name gets unrelated keys and opens none of the
    /// tenant's blobs. Deployments pin it next to the tenant name (`SEAL_TENANT=<tenant>@<root id>`).
    TenantRootId,
    32
);

/// The tenant an enclave deployment serves, and its root chain. Text form
/// `<tenant>@<root id hex>`, e.g. `acme@3f9c…`, as `SEAL_TENANT` and the CLI write it.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TenantPin {
    pub tenant: TenantId,
    pub root_id: TenantRootId,
}

impl FromStr for TenantPin {
    type Err = ProtoError;
    fn from_str(s: &str) -> Result<Self, ProtoError> {
        let (tenant, root_id) =
            s.split_once('@').ok_or_else(|| ProtoError::invalid("tenant pin", "expected <tenant>@<root id>"))?;
        Ok(Self { tenant: tenant.parse()?, root_id: root_id.parse()? })
    }
}
impl TenantPin {
    /// A tenant written with or without its root id, as SDK options and `SEAL_TENANT` take it:
    /// `acme`, or `acme@<root id hex>` (a `TenantPin`). Surrounding whitespace is ignored.
    pub fn parse_partial(text: &str) -> Result<(TenantId, Option<TenantRootId>), ProtoError> {
        let text = text.trim();
        if text.contains('@') {
            let pin: TenantPin = text.parse()?;
            Ok((pin.tenant, Some(pin.root_id)))
        } else {
            Ok((TenantId::new(text)?, None))
        }
    }
}
impl fmt::Display for TenantPin {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}@{}", self.tenant, self.root_id)
    }
}
impl TryFrom<String> for TenantPin {
    type Error = ProtoError;
    fn try_from(s: String) -> Result<Self, ProtoError> {
        s.parse()
    }
}
impl From<TenantPin> for String {
    fn from(p: TenantPin) -> String {
        p.to_string()
    }
}

/// Version of Seal's service keys (token, ingest, telemetry, TLS, ticket),
/// carried in every release manifest. Raising the log's minimum service key version
/// retires every older release at once.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ServiceKeyVersion(pub u32);

impl fmt::Display for ServiceKeyVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "v{}", self.0)
    }
}

/// Version of a tenant wrapping key. New blobs use the current version.
/// Older versions remain accepted until the tenant raises its oldest accepted version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TenantKeyVersion(pub u32);

impl fmt::Display for TenantKeyVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Which TEE family an enclave (or a DEK wrap) belongs to. Each platform has
/// its own platform master key, so a blob carries one DEK wrap per platform it may open on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformId {
    /// Azure confidential containers on ACI (AMD SEV-SNP).
    AzureSnpAci,
    /// AWS Nitro Enclaves on an EC2 parent instance.
    AwsNitro,
    /// GCP Confidential Space on AMD SEV-SNP or Intel TDX (plain SEV, without memory
    /// integrity, is refused).
    GcpConfidentialSpace,
    /// Local simulator for development and tests. Never accepted in production builds.
    Sim,
}

impl PlatformId {
    /// The platform tier a session on this platform gets.
    pub fn tier(self) -> crate::session::PlatformTier {
        use crate::session::PlatformTier;
        match self {
            PlatformId::AzureSnpAci | PlatformId::AwsNitro | PlatformId::GcpConfidentialSpace => PlatformTier::Sealed,
            PlatformId::Sim => PlatformTier::Sim,
        }
    }
}
