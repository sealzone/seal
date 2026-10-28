//! Where a guardian's platform root comes from. Guardians only: no enclave image contains
//! code that can unseal a platform root. Each cloud source releases the root only to the
//! guardian's measurement. Every source returns the root itself, never a value derived from
//! it, so a root handed to a successor and stored in its vaults boots it to the same platform
//! master key: Cloud KMS and Key Vault `RSA-HSM` keys unwrap a stored wrapped root (a Managed
//! HSM `oct-HSM` key's bytes would be the root; not implemented). A predecessor hands over the
//! root only to a guardian release that passes its rules.
//!
//! Designed, not built: AWS KMS `Decrypt` of the wrapped root with `Recipient` = a Nitro
//! attestation document, under a key policy whose `kms:RecipientAttestation:PCR0/1/2`
//! conditions pin the guardian's image. The AWS account owner can always change that policy
//! (or recover the key through AWS Support), so it suits only a customer who trusts their own
//! account administrators; it joins `KeySource` with the Nitro platform.

use seal_crypto::{EphemeralKey, Key32, SysRng, UnwrapErr};
use seal_proto::codec::labeled_digest;
use seal_proto::release::{
    KeyPurpose, KeyRequest, KeyRequestBinding, ReleaseEvidence, ReleasedKeys, GUARDIAN_PROTOCOL_VERSION,
    KEY_REQUEST_BINDING_LABEL,
};
use seal_tee::Attestor;

use crate::client::{open_response, GuardianClient};
use crate::GuardianError;

mod azure;
mod gcp;

pub use azure::{
    check_release_policy, release_policy, KeyVault, KeyVaultKeySource, VaultCredentials, VaultKey, VaultKeyName,
};
pub use gcp::{root_aad, AttestationTokens, GcpKms, GcpKmsKeySource, KmsWrappedRoot, LauncherTokens, WorkloadIdentity};

pub enum KeySource {
    /// Seal's guardians, and self-hosted guardians on Azure.
    KeyVault(KeyVaultKeySource),
    /// Self-hosted guardians on Confidential Space (degraded: see `GcpKmsKeySource`).
    GcpKms(GcpKmsKeySource),
    /// A successor's first boot: the root from the guardian it succeeds (`KeyPurpose::Succession`),
    /// which it then stores with its own key service (`KeyVault::store`, `GcpKms::store`) and
    /// boots from thereafter.
    Predecessor(PredecessorKeySource),
    #[cfg(feature = "sim")]
    File(FileKeySource),
}

/// Asks the guardian this one succeeds for its root, attesting with this guardian's own
/// evidence and release. The release's manifest names the platform this guardian serves
/// (`serves`); a root handed over for any other platform is refused.
pub struct PredecessorKeySource {
    predecessor: GuardianClient,
    /// Boxed: release evidence is large, and the other key sources are small.
    release: Box<ReleaseEvidence>,
}

impl PredecessorKeySource {
    pub fn new(predecessor: GuardianClient, release: ReleaseEvidence) -> Self {
        Self { predecessor, release: Box::new(release) }
    }

    /// A challenge from the predecessor, a fresh ephemeral key, evidence over the
    /// `KeyPurpose::Succession` binding, `POST /v1/keys`, then the opened `ReleasedKeys::Root`.
    async fn root_secret(&self, attestor: &Attestor) -> Result<Key32, GuardianError> {
        let root_err = |e: GuardianError| GuardianError::Root(format!("predecessor: {e}"));
        let challenge = self.predecessor.challenge().await.map_err(root_err)?;
        let ephemeral = EphemeralKey::generate(&mut UnwrapErr(SysRng));
        let binding = KeyRequestBinding {
            protocol_version: GUARDIAN_PROTOCOL_VERSION,
            challenge,
            ephemeral_public_key: ephemeral.public_key(),
            purpose: KeyPurpose::Succession,
        };
        let evidence = attestor.attest(labeled_digest(KEY_REQUEST_BINDING_LABEL, &binding)).await?;
        let req = KeyRequest {
            protocol_version: GUARDIAN_PROTOCOL_VERSION,
            evidence,
            binding,
            release: (*self.release).clone(),
            tenant: None,
            tenant_cosign: None,
        };
        let resp = self.predecessor.keys(&req).await.map_err(root_err)?;
        match open_response(&ephemeral, &req.binding, &resp).map_err(root_err)? {
            ReleasedKeys::Root { platform, root } if Some(platform) == self.release.manifest.body.serves => {
                Key32::from_secret_vec(&root).map_err(|_| GuardianError::Root("predecessor: malformed root".into()))
            }
            _ => Err(GuardianError::Root("predecessor: not a root for the platform this guardian serves".into())),
        }
    }
}

impl KeySource {
    /// Attests as the guardian (`attestor`) to the key service and returns the root.
    /// `GuardianError::Root` if the service refuses or cannot be reached.
    pub async fn root_secret(&self, attestor: &Attestor) -> Result<Key32, GuardianError> {
        match self {
            KeySource::KeyVault(source) => source.root_secret(attestor).await,
            KeySource::GcpKms(source) => source.root_secret(attestor).await,
            KeySource::Predecessor(source) => source.root_secret(attestor).await,
            #[cfg(feature = "sim")]
            KeySource::File(source) => source.root_secret(attestor),
        }
    }
}

/// Simulator: the root is the content of a 32-byte file, created with random bytes (mode
/// 0600) if absent, and released only to an attestor whose measurement is `allowed` (mimics a
/// release policy).
#[cfg(feature = "sim")]
pub struct FileKeySource {
    path: std::path::PathBuf,
    allowed: seal_proto::Measurement,
}

#[cfg(feature = "sim")]
impl FileKeySource {
    pub fn new(path: std::path::PathBuf, allowed: seal_proto::Measurement) -> Self {
        Self { path, allowed }
    }

    fn root_secret(&self, attestor: &Attestor) -> Result<Key32, GuardianError> {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;

        if attestor.measurement() != self.allowed {
            return Err(GuardianError::Root("file key source: measurement not allowed".into()));
        }
        let err = |e: std::io::Error| GuardianError::Root(format!("{}: {e}", self.path.display()));
        match std::fs::read(&self.path) {
            Ok(bytes) => {
                return Key32::from_secret_vec(&seal_proto::SecretVec::new(bytes))
                    .map_err(|_| GuardianError::Root(format!("{}: not exactly 32 bytes", self.path.display())));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(err(e)),
        }
        let root = Key32::generate(&mut UnwrapErr(SysRng));
        let mut file =
            std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&self.path).map_err(err)?;
        file.write_all(root.expose()).map_err(err)?;
        file.sync_all().map_err(err)?;
        Ok(root)
    }
}
