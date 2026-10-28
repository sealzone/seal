//! Release manifests: built from a measurement, signed with M of the N release keys, appended
//! to the log, and published to the control plane as `ReleaseEvidence` (the inclusion proof
//! and a fresh checkpoint), which is what enclaves load at boot and guardians check.

use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, bail, Context as _};
use seal_crypto::sign::SigningKey;
use seal_proto::release::{Component, LogEntry, ReleaseEvidence, ReleaseManifest, RELEASE_LABEL};
use seal_proto::signed::Signed;
use seal_proto::{Measurement, PlatformId, ServiceKeyVersion};

/// A release key file as `seal key create` writes it: the Ed25519 seed as 64 hex digits.
pub fn read_key(path: &Path) -> anyhow::Result<SigningKey> {
    let text = std::fs::read_to_string(path).with_context(|| format!("{}", path.display()))?;
    let text = text.trim();
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("{}: expected 64 hex digits", path.display());
    }
    let mut seed = [0u8; 32];
    for (i, byte) in seed.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16)?;
    }
    Ok(SigningKey::from_seed(&seed))
}

/// What a release names besides its measurement.
#[derive(Clone, Debug)]
pub struct Release {
    pub component: Component,
    /// Where it runs.
    pub platform: PlatformId,
    pub measurement: Measurement,
    /// Guardians only: the enclave platform it serves.
    pub serves: Option<PlatformId>,
    pub service_key_version: ServiceKeyVersion,
    pub version: String,
    pub source_commit: String,
}

impl Release {
    pub fn manifest(&self) -> anyhow::Result<ReleaseManifest> {
        match (self.component, self.serves) {
            (Component::Enclave, Some(_)) => bail!("an enclave release serves no other platform"),
            (Component::Guardian, None) => bail!("a guardian release names the platform it serves"),
            _ => {}
        }
        if self.source_commit.is_empty() || self.version.is_empty() {
            bail!("a release names its version and source commit");
        }
        Ok(ReleaseManifest {
            component: self.component,
            platform: self.platform,
            measurement: self.measurement,
            service_key_version: self.service_key_version,
            version: self.version.clone(),
            source_commit: self.source_commit.clone(),
            serves: self.serves,
        })
    }
}

/// `manifest` cosigned by every key (each a distinct release key; the threshold is the
/// verifier's to check).
pub fn sign(manifest: ReleaseManifest, keys: &[SigningKey]) -> anyhow::Result<Signed<ReleaseManifest>> {
    let mut ids: Vec<_> = keys.iter().map(SigningKey::key_id).collect();
    ids.sort();
    ids.dedup();
    if ids.len() != keys.len() || keys.is_empty() {
        bail!("sign with distinct release keys, at least one");
    }
    let mut signed = Signed { body: manifest, signatures: vec![] };
    for key in keys {
        key.cosign(RELEASE_LABEL, &mut signed);
    }
    Ok(signed)
}

/// Appends the manifest to the log and returns its evidence: the inclusion proof and the
/// log's checkpoint after it. Verifies both against `tlog` before returning.
pub async fn log(
    log: &seal::admin::LogClient,
    tlog: &seal_tlog::TlogTrust,
    manifest: Signed<ReleaseManifest>,
) -> anyhow::Result<ReleaseEvidence> {
    let entry = LogEntry::Release(manifest.body.clone());
    let index = log.append(&entry).await.context("append the release to the log")?;
    let included = log.prove(index).await.context("the inclusion proof")?;
    let fresh = log.checkpoint().await.context("a fresh checkpoint")?;
    let verifier = seal_tlog::LogVerifier::new(tlog.clone());
    verifier.inclusion(&entry, &included).map_err(|e| anyhow!("the log's inclusion proof does not verify: {e}"))?;
    verifier.checkpoint(&fresh).map_err(|e| anyhow!("the log's checkpoint does not verify: {e}"))?;
    Ok(ReleaseEvidence { manifest, included, fresh, auditor: None })
}

/// PUTs the evidence to the control plane (`PUT /v1/releases/{platform}/{measurement}`).
pub async fn publish(control: &seal::admin::ControlClient, evidence: &ReleaseEvidence) -> anyhow::Result<()> {
    let manifest = &evidence.manifest.body;
    let mut attempt = 0;
    loop {
        match control.put_release(manifest.platform, &manifest.measurement, evidence).await {
            Ok(()) => return Ok(()),
            Err(e) if attempt < 3 => {
                eprintln!("seal-release: publishing the release: {e}; retrying");
                attempt += 1;
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            Err(e) => return Err(e).context("publish the release to the control plane"),
        }
    }
}

#[cfg(test)]
mod tests {
    use seal_crypto::{SysRng, UnwrapErr};

    use super::*;

    fn release() -> Release {
        Release {
            component: Component::Enclave,
            platform: PlatformId::GcpConfidentialSpace,
            measurement: Measurement([7; 48]),
            serves: None,
            service_key_version: ServiceKeyVersion(1),
            version: "0.1.0".into(),
            source_commit: "abc".into(),
        }
    }

    #[test]
    fn manifests_name_what_they_serve() {
        assert!(release().manifest().unwrap().serves.is_none());
        assert!(Release { serves: Some(PlatformId::AzureSnpAci), ..release() }.manifest().is_err());
        assert!(Release { component: Component::Guardian, ..release() }.manifest().is_err());
        let guardian = Release { component: Component::Guardian, serves: Some(PlatformId::AzureSnpAci), ..release() };
        assert_eq!(guardian.manifest().unwrap().serves, Some(PlatformId::AzureSnpAci));
        assert!(Release { source_commit: String::new(), ..release() }.manifest().is_err());
    }

    #[test]
    fn signatures_meet_the_threshold() {
        let keys: Vec<SigningKey> = (0..3).map(|_| SigningKey::generate(&mut UnwrapErr(SysRng))).collect();
        let signed = sign(release().manifest().unwrap(), &keys[..2]).unwrap();
        let public: Vec<_> = keys.iter().map(SigningKey::public_key).collect();
        seal_crypto::sign::verify_threshold(&public, 2, RELEASE_LABEL, &signed).unwrap();
        assert!(seal_crypto::sign::verify_threshold(&public, 3, RELEASE_LABEL, &signed).is_err());
        let twice = [SigningKey::from_seed(&keys[0].to_seed()), SigningKey::from_seed(&keys[0].to_seed())];
        assert!(sign(release().manifest().unwrap(), &twice).is_err());
        assert!(sign(release().manifest().unwrap(), &[]).is_err());
    }

    #[test]
    fn key_files_are_hex_seeds() {
        let dir = std::env::temp_dir().join(format!("seal-release-key-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = SigningKey::generate(&mut UnwrapErr(SysRng));
        let seed: String = key.to_seed().iter().map(|b| format!("{b:02x}")).collect();
        std::fs::write(dir.join("k"), format!("{seed}\n")).unwrap();
        assert_eq!(read_key(&dir.join("k")).unwrap().public_key(), key.public_key());
        std::fs::write(dir.join("bad"), "zz").unwrap();
        assert!(read_key(&dir.join("bad")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
