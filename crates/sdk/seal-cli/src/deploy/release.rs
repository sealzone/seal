//! Which release to deploy: every Azure enclave release the control plane lists, verified with
//! `seal_verify::ReleaseVerifier` (signatures, log inclusion, the time lock, the log's
//! revocations), newest by log position. The control plane can withhold releases, never forge
//! one; a release that does not verify is reported and skipped.

use anyhow::bail;

use seal_proto::release::{Component, ReleaseEvidence, SignedCheckpoint};
use seal_proto::{Measurement, PlatformId, TrustedTime};
use seal_verify::{ReleaseVerifier, VerifiedRelease};

/// A verified release and its position in the log.
#[derive(Clone, Debug)]
pub struct Candidate {
    pub release: VerifiedRelease,
    pub leaf_index: u64,
}

impl Candidate {
    pub fn measurement(&self) -> Measurement {
        self.release.manifest().measurement
    }
}

/// The verified Azure enclave releases among `listed`, oldest first, and one line for each
/// that did not verify. `latest` (the control plane's checkpoint) replaces a stored evidence's
/// `fresh` checkpoint when it covers at least as many entries, as the enclave does.
pub fn verify_all(
    verifier: &ReleaseVerifier,
    listed: Vec<ReleaseEvidence>,
    latest: Option<&SignedCheckpoint>,
    time: &TrustedTime,
) -> (Vec<Candidate>, Vec<String>) {
    let mut verified = Vec::new();
    let mut refused = Vec::new();
    for mut evidence in listed {
        let manifest = &evidence.manifest.body;
        if manifest.component != Component::Enclave || manifest.platform != PlatformId::AzureSnpAci {
            continue;
        }
        if let Some(latest) = latest.filter(|l| l.checkpoint.size >= evidence.fresh.checkpoint.size) {
            evidence.fresh = latest.clone();
        }
        let leaf_index = evidence.included.leaf_index;
        match verifier.verify(&evidence, time) {
            Ok(release) => verified.push(Candidate { release, leaf_index }),
            Err(e) => refused.push(format!("release {} ({}): {e}", manifest.version, manifest.measurement)),
        }
    }
    verified.sort_by_key(|c| c.leaf_index);
    (verified, refused)
}

/// `wanted`, or the newest.
pub fn pick(verified: &[Candidate], wanted: Option<&Measurement>) -> anyhow::Result<Candidate> {
    let found = match wanted {
        Some(m) => verified.iter().find(|c| &c.measurement() == m),
        None => verified.last(),
    };
    match (found, wanted) {
        (Some(c), _) => Ok(c.clone()),
        (None, Some(m)) => bail!("release {m} is not a verified Azure enclave release"),
        (None, None) => bail!("the control plane lists no Azure enclave release that verifies"),
    }
}

#[cfg(test)]
mod tests {
    use seal_crypto::sign::SigningKey;
    use seal_proto::release::{LogEntry, ReleaseManifest, RELEASE_LABEL};
    use seal_proto::signed::Signed;
    use seal_proto::ServiceKeyVersion;
    use seal_tlog::dev::DevLog;
    use seal_verify::{ReleaseTrust, VerifyError};

    use super::*;

    fn key(n: u8) -> SigningKey {
        SigningKey::from_seed(&[n; 32])
    }

    struct Log {
        log: DevLog,
        _dir: std::path::PathBuf,
    }

    impl Log {
        fn new(name: &str) -> Self {
            let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
            let dir = std::env::temp_dir().join(format!("seal-cli-release-{name}-{}-{nanos}", std::process::id()));
            Self { log: DevLog::open(&dir, [0x42; 32], 3, 2).unwrap(), _dir: dir }
        }

        fn release(&mut self, m: u8, platform: PlatformId, signers: &[u8]) -> ReleaseEvidence {
            let manifest = ReleaseManifest {
                component: Component::Enclave,
                platform,
                measurement: Measurement([m; 48]),
                service_key_version: ServiceKeyVersion(1),
                version: format!("0.{m}.0"),
                source_commit: "abc".into(),
                serves: None,
            };
            let mut signed = Signed { body: manifest, signatures: vec![] };
            for &n in signers {
                key(n).cosign(RELEASE_LABEL, &mut signed);
            }
            let index = self.log.append(LogEntry::Release(signed.body.clone())).unwrap();
            ReleaseEvidence {
                manifest: signed,
                included: self.log.prove(index),
                fresh: self.log.checkpoint(),
                auditor: None,
            }
        }

        fn verifier(&self, time_lock_secs: u64) -> ReleaseVerifier {
            ReleaseVerifier::new(ReleaseTrust {
                tlog: self.log.trust(),
                release_keys: vec![key(1).public_key(), key(2).public_key(), key(3).public_key()],
                release_threshold: 2,
                required_auditor: None,
                time_lock_secs,
            })
        }
    }

    impl Drop for Log {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self._dir);
        }
    }

    fn now() -> TrustedTime {
        TrustedTime::exact(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs())
    }

    #[test]
    fn the_newest_verified_azure_enclave_release_is_picked() {
        let mut log = Log::new("newest");
        let old = log.release(1, PlatformId::AzureSnpAci, &[1, 2]);
        let new = log.release(2, PlatformId::AzureSnpAci, &[2, 3]);
        let unsigned = log.release(3, PlatformId::AzureSnpAci, &[1]);
        let gcp = log.release(4, PlatformId::GcpConfidentialSpace, &[1, 2]);
        let latest = log.log.checkpoint();
        let listed = vec![new, unsigned, old, gcp];
        let (verified, refused) = verify_all(&log.verifier(0), listed, Some(&latest), &now());
        let ms: Vec<_> = verified.iter().map(Candidate::measurement).collect();
        assert_eq!(ms, [Measurement([1; 48]), Measurement([2; 48])], "oldest first, GCP skipped");
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert!(refused[0].contains("0.3.0") && refused[0].contains("signatures"), "{refused:?}");
        assert_eq!(pick(&verified, None).unwrap().measurement(), Measurement([2; 48]));
        assert_eq!(pick(&verified, Some(&Measurement([1; 48]))).unwrap().measurement(), Measurement([1; 48]));
        assert!(pick(&verified, Some(&Measurement([3; 48]))).is_err(), "an unverified release is never picked");
        assert!(pick(&[], None).is_err());
    }

    #[test]
    fn the_time_lock_holds_releases_back() {
        let mut log = Log::new("time-lock");
        let evidence = log.release(1, PlatformId::AzureSnpAci, &[1, 2]);
        let (verified, refused) = verify_all(&log.verifier(3600), vec![evidence.clone()], None, &now());
        assert!(verified.is_empty());
        assert!(refused[0].contains("time lock"), "{refused:?}");
        assert!(matches!(log.verifier(3600).verify(&evidence, &now()), Err(VerifyError::TimeLock { .. })));
    }

    #[test]
    fn a_stale_stored_checkpoint_is_replaced_by_the_latest() {
        let mut log = Log::new("stale");
        let evidence = log.release(1, PlatformId::AzureSnpAci, &[1, 2]);
        let mut stale = evidence.clone();
        stale.fresh.cosignatures.clear();
        let (verified, _) = verify_all(&log.verifier(0), vec![stale.clone()], None, &now());
        assert!(verified.is_empty(), "the stored checkpoint does not verify");
        log.release(2, PlatformId::AzureSnpAci, &[1, 2]);
        let latest = log.log.checkpoint();
        let (verified, _) = verify_all(&log.verifier(0), vec![stale.clone()], Some(&latest), &now());
        assert_eq!(verified.len(), 1, "replaced by the latest");
        // A checkpoint smaller than the stored one is not used.
        let smaller = evidence.included.checkpoint.clone();
        let mut newer = evidence;
        newer.fresh = latest;
        newer.fresh.cosignatures.clear();
        let (verified, _) = verify_all(&log.verifier(0), vec![newer], Some(&smaller), &now());
        assert!(verified.is_empty(), "the stored one stays");
    }
}
