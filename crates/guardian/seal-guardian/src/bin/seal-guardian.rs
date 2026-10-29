//! The guardian binary: boots one `Guardian` and serves it over plain HTTP (TLS is terminated
//! by a proxy in front of it).
//!
//! Production builds compile their rules in (`compiled`): one build per (served platform,
//! platform it runs on), with the trust, listen address and key service fixed at its freeze.
//! The build reads them from the JSON file `SEAL_RELEASE_GUARDIAN_CONFIG` names (`build.rs`;
//! e.g. `deploy/example/guardian-azure.json`); a production binary built without it refuses to
//! start. It names the served platform, the platform the guardian runs on, its key service and
//! the trust (shaped as in the sim file below); it listens on `0.0.0.0:7400` and its clock is
//! Roughtime. A guardian on ACI names its Key Vault keys (`KeySource::KeyVault`), one on
//! Confidential Space its Cloud KMS keys (`KeySource::GcpKms`):
//!
//! ```json
//! {
//!   "platform": "azure_snp_aci",
//!   "runs_on": "azure_snp_aci",
//!   "key_vault": {"maa_endpoint": "https://sharedeus.eus.attest.azure.net",
//!                 "keys": [{"vault_url": "https://<vault>.vault.azure.net", "key_name": "<key>"}]},
//!   "trust": {...}
//! }
//! {
//!   "platform": "gcp_confidential_space",
//!   "runs_on": "gcp_confidential_space",
//!   "gcp_kms": {"provider": "projects/<number>/locations/global/workloadIdentityPools/<pool>/providers/<provider>",
//!               "service_account": null, "keys": ["projects/<project>/locations/<location>/keyRings/<ring>/cryptoKeys/<key>"]},
//!   "trust": {...}
//! }
//! ```
//!
//! The wrapped roots are not secret and cannot be part of the image that produced them (nor,
//! on ACI, can the key version, whose release policy pins the image's `host_data`): they come
//! from `SEAL_GUARDIAN_WRAPPED_ROOTS`, comma-separated, one per compiled key in order, each
//! standard base64 (Cloud KMS) or `<key version>:<standard base64>` (Key Vault). The clock is
//! Roughtime.
//!
//! The root ceremony is the same binary with `SEAL_GUARDIAN_CEREMONY=1`: it generates a root
//! in the TEE, stores it under every key (`GcpKms::store`; `KeyVault::store`, which takes each
//! key's current version and refuses one whose release policy is not immutable and pinned to
//! this guardian), prints one JSON line to stdout, `{"platform", "guardian_key",
//! "wrapped_roots": [...]}` (the entries of `SEAL_GUARDIAN_WRAPPED_ROOTS`), and exits without
//! serving. Publish the guardian key only from a booted guardian's `GET /v1/identity`, whose
//! evidence attests it. A repeated ceremony only makes another root nobody trusts.
//!
//! Succession is the same binary with `SEAL_GUARDIAN_SUCCEED_FROM=<https URL of the guardian
//! it succeeds>` and `SEAL_GUARDIAN_RELEASES=<https URL of the control plane>`: it fetches its
//! own release evidence (`GET /v1/releases/{runs_on}/{measurement}`, with the latest
//! checkpoint as `fresh`), asks the predecessor for its root (`KeyPurpose::Succession`; the
//! predecessor checks this build's evidence and release as it would an enclave's), refuses a
//! root that does not derive the guardian key compiled into `trust.guardians` for the served
//! platform, then stores and prints it as the ceremony does. The guardian key does not change,
//! so no client's trust and no blob does. Run it while the predecessor still serves.
//!
//! These variables are therefore operator-settable without changing the measurement. On ACI the
//! guardian's container policy allows them by anchored re2 rules (`seal-release aci-policy
//! --component guardian`) and the group sets them as environment variables; the ceremony's
//! output and refusal reasons are read from the container's logs. The Confidential Space image carries
//! the launch policy labels
//! `tee.launch_policy.allow_env_override=SEAL_GUARDIAN_WRAPPED_ROOTS,SEAL_GUARDIAN_CEREMONY,SEAL_GUARDIAN_SUCCEED_FROM,SEAL_GUARDIAN_RELEASES`
//! and `tee.launch_policy.log_redirect=always` (the guardian logs no secret), and the VM sets
//! them as `tee-env-<name>` in its metadata.
//!
//! Sim builds (`--features sim`) are the simulator's guardian: platform `Sim`, running on
//! `Sim` (`Attestor::detect`, so `SEAL_SIM=1` must be set), the root in a `FileKeySource`
//! released to this binary's own measurement, the system clock. They read their rules from the
//! JSON file named by `SEAL_GUARDIAN_CONFIG`:
//!
//! ```json
//! {
//!   "listen": "127.0.0.1:7400",
//!   "root_file": "/var/lib/seal/guardian-root",
//!   "trust": {
//!     "releases": {
//!       "tlog": {"origin": "...", "log_key": "<hex>", "witness_keys": ["<hex>"], "witness_quorum": 1},
//!       "release_keys": ["<hex>"], "release_threshold": 1, "required_auditor": null, "time_lock_secs": 0
//!     },
//!     "tenants": {"tlog": {...}, "registrar_keys": ["<hex>"], "registrar_threshold": 1},
//!     "guardians": {"sim": "<hex>"}
//!   }
//! }
//! ```
//!
//! Logs go to stderr, `info` and above (`SEAL_LOG=debug` for more).
#![forbid(unsafe_code)]

#[tokio::main]
async fn main() {
    log::init();
    #[cfg(feature = "sim")]
    let result = sim::run().await;
    #[cfg(not(feature = "sim"))]
    let result = production::run().await;
    if let Err(e) = result {
        tracing::error!("{e}");
        std::process::exit(1);
    }
}

/// What every guardian's boot shares; all but `boot_and_serve` only in production builds.
mod boot {
    use std::sync::Arc;

    use seal_guardian::{GuardianComponents, GuardianConfig};
    #[cfg(not(feature = "sim"))]
    use seal_tee::roughtime::{default_servers, RoughtimeClock, DEFAULT_MIN_AGREEING};
    #[cfg(not(feature = "sim"))]
    use seal_tee::Clock;

    /// `SEAL_GUARDIAN_CEREMONY=1`.
    #[cfg(not(feature = "sim"))]
    pub fn ceremony_requested() -> bool {
        std::env::var_os("SEAL_GUARDIAN_CEREMONY").is_some_and(|v| v == "1")
    }

    /// `SEAL_GUARDIAN_SUCCEED_FROM` and `SEAL_GUARDIAN_RELEASES`, when this run is a succession.
    #[cfg(not(feature = "sim"))]
    pub fn succession_requested() -> Result<Option<crate::succession::Succession>, String> {
        let Some(from) = std::env::var("SEAL_GUARDIAN_SUCCEED_FROM").ok().filter(|v| !v.is_empty()) else {
            return Ok(None);
        };
        if ceremony_requested() {
            return Err(
                "SEAL_GUARDIAN_CEREMONY and SEAL_GUARDIAN_SUCCEED_FROM are both set: a run is one or the other".into(),
            );
        }
        let releases = std::env::var("SEAL_GUARDIAN_RELEASES")
            .map_err(|_| "SEAL_GUARDIAN_SUCCEED_FROM is set but SEAL_GUARDIAN_RELEASES is not".to_owned())?;
        crate::succession::Succession::new(&from, &releases).map(Some)
    }

    /// `SEAL_GUARDIAN_WRAPPED_ROOTS`, split at commas.
    #[cfg(not(feature = "sim"))]
    pub fn wrapped_roots_env() -> Result<Vec<String>, String> {
        let wrapped = std::env::var("SEAL_GUARDIAN_WRAPPED_ROOTS")
            .map_err(|_| "SEAL_GUARDIAN_WRAPPED_ROOTS is not set".to_owned())?;
        Ok(wrapped.split(',').map(str::to_owned).collect())
    }

    /// The ceremony's one line on stdout.
    #[cfg(not(feature = "sim"))]
    pub fn print_ceremony(platform: seal_proto::PlatformId, root: &seal_crypto::Key32, wrapped_roots: &[String]) {
        let guardian_key = seal_crypto::PlatformMasterKey::from_root_secret(platform, root).guardian_key().public_key();
        let line =
            serde_json::json!({"platform": platform, "guardian_key": guardian_key, "wrapped_roots": wrapped_roots});
        println!("{line}");
        tracing::info!(platform = ?platform, guardian_key = %guardian_key, copies = wrapped_roots.len(), "root ceremony done");
    }

    #[cfg(not(feature = "sim"))]
    pub fn roughtime() -> Clock {
        Clock::Roughtime(RoughtimeClock::new(default_servers(), DEFAULT_MIN_AGREEING, Arc::new(seal_net::UdpDatagrams)))
    }

    /// Boots and serves on `listen` until the listener fails.
    pub async fn boot_and_serve(
        config: GuardianConfig,
        components: GuardianComponents,
        listen: &str,
    ) -> Result<(), String> {
        let guardian = seal_guardian::Guardian::boot(config, components).await.map_err(|e| format!("boot: {e}"))?;
        let listener = tokio::net::TcpListener::bind(listen).await.map_err(|e| format!("listen on {listen}: {e}"))?;
        tracing::info!(listen = %listen, "serving");
        seal_guardian::server::serve(Arc::new(guardian), listener).await.map_err(|e| format!("serve: {e}"))
    }
}

/// A GCP guardian's root (Cloud KMS).
#[cfg(not(feature = "sim"))]
mod gcp {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use seal_crypto::{Key32, SysRng, UnwrapErr};
    use seal_guardian::keysource::{GcpKms, GcpKmsKeySource, KmsWrappedRoot};
    use seal_guardian::KeySource;
    use seal_proto::PlatformId;
    use seal_tee::Attestor;

    /// A new root from the TEE's randomness, stored under every key; the result goes to stdout.
    pub async fn ceremony(
        kms: &GcpKms,
        keys: &[String],
        attestor: &Attestor,
        platform: PlatformId,
    ) -> Result<(), String> {
        store(kms, keys, attestor, platform, &Key32::generate(&mut UnwrapErr(SysRng))).await
    }

    /// `root` stored under every key; the result goes to stdout. A ceremony's or a succession's.
    pub async fn store(
        kms: &GcpKms,
        keys: &[String],
        attestor: &Attestor,
        platform: PlatformId,
        root: &Key32,
    ) -> Result<(), String> {
        let copies = kms.store(root, keys, attestor).await.map_err(|e| format!("store the root: {e}"))?;
        let wrapped: Vec<String> = copies.iter().map(|c| STANDARD.encode(&c.wrapped_root)).collect();
        crate::boot::print_ceremony(platform, root, &wrapped);
        Ok(())
    }

    /// `keys[i]` with `wrapped_roots[i]` (standard base64); the counts must match.
    pub fn copies(keys: &[String], wrapped_roots: &[String]) -> Result<Vec<KmsWrappedRoot>, String> {
        if wrapped_roots.len() != keys.len() {
            return Err(format!("{} wrapped roots for {} Cloud KMS keys", wrapped_roots.len(), keys.len()));
        }
        keys.iter()
            .zip(wrapped_roots)
            .map(|(key_name, b64)| {
                let wrapped_root =
                    STANDARD.decode(b64.trim()).map_err(|e| format!("wrapped root for {key_name}: {e}"))?;
                Ok(KmsWrappedRoot { key_name: key_name.clone(), wrapped_root })
            })
            .collect()
    }

    pub fn key_source(kms: GcpKms, copies: Vec<KmsWrappedRoot>) -> Result<KeySource, String> {
        Ok(KeySource::GcpKms(GcpKmsKeySource::new(kms, copies).map_err(|e| e.to_string())?))
    }
}

/// An Azure guardian's root (Key Vault).
#[cfg(not(feature = "sim"))]
mod azure {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use seal_crypto::{Key32, SysRng, UnwrapErr};
    use seal_guardian::keysource::{KeyVault, KeyVaultKeySource, VaultKey, VaultKeyName};
    use seal_guardian::KeySource;
    use seal_proto::PlatformId;
    use seal_tee::Attestor;

    /// A new root from the TEE's randomness, wrapped under the current version of every key
    /// and released back to check; the result goes to stdout, one `<key version>:<base64>` per key.
    pub async fn ceremony(
        vault: &KeyVault,
        keys: &[VaultKeyName],
        attestor: &Attestor,
        platform: PlatformId,
    ) -> Result<(), String> {
        store(vault, keys, attestor, platform, &Key32::generate(&mut UnwrapErr(SysRng))).await
    }

    /// `root` wrapped under the current version of every key and released back to check; the
    /// result goes to stdout. A ceremony's or a succession's.
    pub async fn store(
        vault: &KeyVault,
        keys: &[VaultKeyName],
        attestor: &Attestor,
        platform: PlatformId,
        root: &Key32,
    ) -> Result<(), String> {
        let copies = vault.store(root, keys, attestor).await.map_err(|e| format!("store the root: {e}"))?;
        let wrapped: Vec<String> = copies
            .iter()
            .map(|c| format!("{}:{}", c.key_version, STANDARD.encode(c.wrapped_root.as_deref().unwrap_or_default())))
            .collect();
        crate::boot::print_ceremony(platform, root, &wrapped);
        Ok(())
    }

    /// `keys[i]` with `wrapped_roots[i]` (`<key version>:<standard base64>`); the counts must match.
    pub fn copies(keys: &[VaultKeyName], wrapped_roots: &[String]) -> Result<Vec<VaultKey>, String> {
        if wrapped_roots.len() != keys.len() {
            return Err(format!("{} wrapped roots for {} Key Vault keys", wrapped_roots.len(), keys.len()));
        }
        keys.iter()
            .zip(wrapped_roots)
            .map(|(key, copy)| {
                let what = format!("{}/keys/{}", key.vault_url, key.key_name);
                let (version, b64) = copy
                    .trim()
                    .split_once(':')
                    .ok_or_else(|| format!("wrapped root for {what}: not <version>:<base64>"))?;
                let wrapped_root = STANDARD.decode(b64).map_err(|e| format!("wrapped root for {what}: {e}"))?;
                Ok(VaultKey {
                    vault_url: key.vault_url.clone(),
                    key_name: key.key_name.clone(),
                    key_version: version.to_owned(),
                    wrapped_root: Some(wrapped_root),
                })
            })
            .collect()
    }

    pub fn key_source(vault: KeyVault, copies: Vec<VaultKey>) -> Result<KeySource, String> {
        Ok(KeySource::KeyVault(KeyVaultKeySource::new(vault, copies).map_err(|e| e.to_string())?))
    }
}

/// A successor's first run: the root from the guardian it succeeds (the tests exercise
/// `PredecessorKeySource` directly).
#[cfg(not(feature = "sim"))]
mod succession {
    use std::sync::Arc;

    use seal_crypto::{Key32, PlatformMasterKey};
    use seal_guardian::client::GuardianClient;
    use seal_guardian::keysource::PredecessorKeySource;
    use seal_guardian::{GuardianConfig, KeySource};
    use seal_net::HttpsClient;
    use seal_proto::release::{ReleaseEvidence, SignedCheckpoint};
    use seal_tee::Attestor;

    pub struct Succession {
        from: url::Url,
        releases: url::Url,
    }

    impl Succession {
        /// Both must be `https://`.
        pub fn new(from: &str, releases: &str) -> Result<Self, String> {
            let parse = |name: &str, v: &str| -> Result<url::Url, String> {
                let u = url::Url::parse(v.trim()).map_err(|e| format!("{name}: {e}"))?;
                if u.scheme() != "https" {
                    return Err(format!("{name}: must be https://"));
                }
                Ok(u)
            };
            Ok(Self {
                from: parse("SEAL_GUARDIAN_SUCCEED_FROM", from)?,
                releases: parse("SEAL_GUARDIAN_RELEASES", releases)?,
            })
        }

        /// The predecessor's root, checked to derive the guardian key `config.trust.guardians`
        /// names for the served platform: the key every client already trusts.
        pub async fn root(
            &self,
            config: &GuardianConfig,
            attestor: &Attestor,
            https: Arc<HttpsClient>,
        ) -> Result<Key32, String> {
            let guardian_key = *config.trust.guardians.get(&config.platform).ok_or_else(|| {
                format!(
                    "succession: trust.guardians has no key for {:?} (compile in the predecessor's)",
                    config.platform
                )
            })?;
            let release = self.own_release(config, attestor, &https).await?;
            let predecessor = GuardianClient::new(self.from.clone(), https, guardian_key);
            let root = KeySource::Predecessor(PredecessorKeySource::new(predecessor, release))
                .root_secret(attestor)
                .await
                .map_err(|e| format!("succession: {e}"))?;
            if PlatformMasterKey::from_root_secret(config.platform, &root).guardian_key().public_key() != guardian_key {
                return Err("succession: the root handed over does not derive the trusted guardian key".into());
            }
            tracing::info!(guardian_key = %guardian_key, "succession: root received");
            Ok(root)
        }

        /// This build's release evidence, with the control plane's latest checkpoint as `fresh`
        /// when it covers at least as much of the log.
        async fn own_release(
            &self,
            config: &GuardianConfig,
            attestor: &Attestor,
            https: &HttpsClient,
        ) -> Result<ReleaseEvidence, String> {
            let platform = match serde_json::to_value(config.runs_on) {
                Ok(serde_json::Value::String(name)) => name,
                _ => return Err("succession: platform name".into()),
            };
            let base = self.releases.as_str().trim_end_matches('/');
            let get = |path: String| async move {
                let (status, body) = https.get(&path, &[]).await.map_err(|e| format!("succession: GET {path}: {e}"))?;
                if status != 200 {
                    return Err(format!("succession: GET {path}: HTTP {status}"));
                }
                Ok(body)
            };
            let body = get(format!("{base}/v1/releases/{platform}/{}", attestor.measurement())).await?;
            let mut evidence: ReleaseEvidence =
                serde_json::from_slice(&body).map_err(|e| format!("succession: release evidence: {e}"))?;
            match get(format!("{base}/v1/checkpoint")).await.and_then(|b| {
                serde_json::from_slice::<SignedCheckpoint>(&b).map_err(|e| format!("succession: checkpoint: {e}"))
            }) {
                Ok(latest) if latest.checkpoint.size >= evidence.fresh.checkpoint.size => evidence.fresh = latest,
                Ok(_) => {}
                Err(e) => tracing::warn!("{e}: sending the stored fresh checkpoint"),
            }
            Ok(evidence)
        }
    }
}

/// The rules this build is frozen with: the release configuration `build.rs` compiled in.
#[cfg(not(feature = "sim"))]
mod compiled {
    use seal_guardian::keysource::VaultKeyName;
    use seal_proto::PlatformId;
    use serde::Deserialize;

    pub const LISTEN: &str = "0.0.0.0:7400";

    /// The release configuration (empty when the build was given none).
    pub const RELEASE_CONFIG: &str = include_str!(concat!(env!("OUT_DIR"), "/release-config.json"));

    /// The compiled-in rules; `Release::parse` guarantees the key service of `runs_on`.
    pub fn release() -> Result<Release, String> {
        if RELEASE_CONFIG.trim().is_empty() {
            return Err("this build has no release configuration (build with SEAL_RELEASE_GUARDIAN_CONFIG)".into());
        }
        Release::parse(RELEASE_CONFIG.as_bytes())
    }

    /// A production build's compiled-in rules.
    pub struct Release {
        pub platform: PlatformId,
        pub runs_on: PlatformId,
        /// On Confidential Space: the workload identity provider (and service account, if any)
        /// and the Cloud KMS keys holding the root, in the order `SEAL_GUARDIAN_WRAPPED_ROOTS`
        /// lists them.
        pub gcp_kms: Option<(seal_guardian::keysource::WorkloadIdentity, Vec<String>)>,
        /// On ACI: the attestation endpoint and the Key Vault keys holding the root, in the
        /// order `SEAL_GUARDIAN_WRAPPED_ROOTS` lists them.
        pub key_vault: Option<(String, Vec<VaultKeyName>)>,
        pub trust: seal_verify::Trust,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ReleaseFile {
        platform: PlatformId,
        runs_on: PlatformId,
        #[serde(default)]
        gcp_kms: Option<GcpKms>,
        #[serde(default)]
        key_vault: Option<KeyVault>,
        trust: crate::file::Trust,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct GcpKms {
        provider: String,
        #[serde(default)]
        service_account: Option<String>,
        keys: Vec<String>,
    }

    /// A guardian on ACI: Key Vault Secure Key Release, attested by `maa_endpoint`.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct KeyVault {
        pub maa_endpoint: String,
        pub keys: Vec<VaultKeyName>,
    }

    impl Release {
        pub fn parse(text: &[u8]) -> Result<Self, String> {
            let file: ReleaseFile =
                serde_json::from_slice(text).map_err(|e| format!("guardian release config: {e}"))?;
            let gcp_kms = match (file.runs_on, file.gcp_kms) {
                (PlatformId::GcpConfidentialSpace, Some(kms)) if !kms.keys.is_empty() => Some((
                    seal_guardian::keysource::WorkloadIdentity {
                        provider: kms.provider,
                        service_account: kms.service_account,
                    },
                    kms.keys,
                )),
                (PlatformId::GcpConfidentialSpace, _) => {
                    return Err("guardian release config: a guardian on Confidential Space needs gcp_kms keys".into())
                }
                (_, Some(_)) => {
                    return Err("guardian release config: gcp_kms is for guardians on Confidential Space".into())
                }
                (_, None) => None,
            };
            let key_vault = match (file.runs_on, file.key_vault) {
                (PlatformId::AzureSnpAci, Some(kv)) if !kv.keys.is_empty() => Some((kv.maa_endpoint, kv.keys)),
                (PlatformId::AzureSnpAci, _) => {
                    return Err("guardian release config: a guardian on ACI needs key_vault keys".into())
                }
                (_, Some(_)) => return Err("guardian release config: key_vault is for guardians on ACI".into()),
                (_, None) => None,
            };
            Ok(Self { platform: file.platform, runs_on: file.runs_on, gcp_kms, key_vault, trust: file.trust.into() })
        }
    }
}

/// The trust as both builds' JSON spells it (module docs).
mod file {
    use std::collections::BTreeMap;

    use seal_proto::{PlatformId, PublicKey};
    use serde::Deserialize;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Trust {
        releases: ReleaseTrust,
        tenants: TenantTrust,
        #[serde(default)]
        guardians: BTreeMap<PlatformId, PublicKey>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct TlogTrust {
        origin: String,
        log_key: PublicKey,
        witness_keys: Vec<PublicKey>,
        witness_quorum: usize,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ReleaseTrust {
        tlog: TlogTrust,
        release_keys: Vec<PublicKey>,
        release_threshold: usize,
        #[serde(default)]
        required_auditor: Option<PublicKey>,
        time_lock_secs: u64,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct TenantTrust {
        tlog: TlogTrust,
        registrar_keys: Vec<PublicKey>,
        registrar_threshold: usize,
    }

    impl From<TlogTrust> for seal_tlog::TlogTrust {
        fn from(t: TlogTrust) -> Self {
            Self {
                origin: t.origin,
                log_key: t.log_key,
                witness_keys: t.witness_keys,
                witness_quorum: t.witness_quorum,
            }
        }
    }

    impl From<Trust> for seal_verify::Trust {
        fn from(t: Trust) -> Self {
            Self {
                releases: seal_verify::ReleaseTrust {
                    tlog: t.releases.tlog.into(),
                    release_keys: t.releases.release_keys,
                    release_threshold: t.releases.release_threshold,
                    required_auditor: t.releases.required_auditor,
                    time_lock_secs: t.releases.time_lock_secs,
                },
                tenants: seal_verify::TenantTrust {
                    tlog: t.tenants.tlog.into(),
                    registrar_keys: t.tenants.registrar_keys,
                    registrar_threshold: t.tenants.registrar_threshold,
                },
                guardians: t.guardians,
            }
        }
    }
}

#[cfg(not(feature = "sim"))]
mod production {
    use std::sync::Arc;

    use seal_guardian::keysource::{GcpKms, KeyVault};
    use seal_guardian::{GuardianComponents, GuardianConfig};
    use seal_net::{BakedRootsConnector, HttpsClient, TcpDialer};
    use seal_tee::Attestor;

    use crate::{azure, boot, compiled, gcp};

    pub async fn run() -> Result<(), String> {
        let release = compiled::release()?;
        let config = GuardianConfig { platform: release.platform, runs_on: release.runs_on, trust: release.trust };
        let attestor = Attestor::detect().map_err(|e| format!("attestor: {e}"))?;
        if attestor.platform() != config.runs_on {
            return Err(format!("this build runs on {:?}, not {:?}", config.runs_on, attestor.platform()));
        }
        // A first trusted reading: every certificate below, ceremony and succession included, is
        // checked at trusted time.
        let clock = boot::roughtime();
        clock.now().await.map_err(|e| format!("clock: {e}"))?;
        let connector = BakedRootsConnector::new(Arc::new(TcpDialer)).with_time(seal_tee::tls_time());
        let https = Arc::new(HttpsClient::new(Arc::new(connector)));
        let key_source = match (release.gcp_kms, release.key_vault) {
            (Some((identity, keys)), _) => {
                let kms = GcpKms::new(config.platform, identity, https.clone()).map_err(|e| e.to_string())?;
                if let Some(succession) = boot::succession_requested()? {
                    let root = succession.root(&config, &attestor, https).await?;
                    return gcp::store(&kms, &keys, &attestor, config.platform, &root).await;
                }
                if boot::ceremony_requested() {
                    return gcp::ceremony(&kms, &keys, &attestor, config.platform).await;
                }
                gcp::key_source(kms, gcp::copies(&keys, &boot::wrapped_roots_env()?)?)?
            }
            (None, Some((maa_endpoint, keys))) => {
                let vault = KeyVault::new(config.platform, maa_endpoint, https.clone()).map_err(|e| e.to_string())?;
                if let Some(succession) = boot::succession_requested()? {
                    let root = succession.root(&config, &attestor, https).await?;
                    return azure::store(&vault, &keys, &attestor, config.platform, &root).await;
                }
                if boot::ceremony_requested() {
                    return azure::ceremony(&vault, &keys, &attestor, config.platform).await;
                }
                azure::key_source(vault, azure::copies(&keys, &boot::wrapped_roots_env()?)?)?
            }
            (None, None) => return Err(format!("this build has no key source for a guardian on {:?}", config.runs_on)),
        };
        let components = GuardianComponents { key_source, attestor, clock };
        boot::boot_and_serve(config, components, compiled::LISTEN).await
    }
}

#[cfg(feature = "sim")]
mod sim {
    use std::path::PathBuf;

    use seal_guardian::keysource::FileKeySource;
    use seal_guardian::{GuardianComponents, GuardianConfig, KeySource};
    use seal_proto::PlatformId;
    use seal_tee::{sim::SystemClock, Attestor, Clock};
    use serde::Deserialize;

    use crate::{boot, file};

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Config {
        listen: String,
        root_file: PathBuf,
        trust: file::Trust,
    }

    pub async fn run() -> Result<(), String> {
        let path = std::env::var_os("SEAL_GUARDIAN_CONFIG").ok_or("SEAL_GUARDIAN_CONFIG is not set")?;
        let text = std::fs::read(&path).map_err(|e| format!("{}: {e}", PathBuf::from(&path).display()))?;
        let config: Config = serde_json::from_slice(&text).map_err(|e| format!("guardian config: {e}"))?;
        let attestor = Attestor::detect().map_err(|e| format!("attestor: {e} (set SEAL_SIM=1)"))?;
        let key_source = KeySource::File(FileKeySource::new(config.root_file, attestor.measurement()));
        let components = GuardianComponents { key_source, attestor, clock: Clock::System(SystemClock::new(0)) };
        let guardian_config =
            GuardianConfig { platform: PlatformId::Sim, runs_on: PlatformId::Sim, trust: config.trust.into() };
        boot::boot_and_serve(guardian_config, components, &config.listen).await
    }
}

/// A minimal stderr logger: one line per event, `LEVEL target: message key=value…`. Spans are
/// not tracked. Small on purpose: the guardian's dependency set never changes.
mod log {
    use std::fmt::Write as _;

    use tracing::field::{Field, Visit};
    use tracing::span::{Attributes, Id, Record};
    use tracing::{Event, Level, Metadata};

    struct Stderr {
        max: Level,
    }

    pub fn init() {
        let max = match std::env::var("SEAL_LOG").as_deref() {
            Ok("trace") => Level::TRACE,
            Ok("debug") => Level::DEBUG,
            Ok("warn") => Level::WARN,
            Ok("error") => Level::ERROR,
            _ => Level::INFO,
        };
        // Fails only if a logger is already installed, which then stays.
        let _ = tracing::subscriber::set_global_default(Stderr { max });
    }

    struct Line(String);

    impl Visit for Line {
        fn record_str(&mut self, field: &Field, value: &str) {
            if field.name() == "message" {
                let _ = write!(self.0, " {value}");
            } else {
                let _ = write!(self.0, " {}={value}", field.name());
            }
        }
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                let _ = write!(self.0, " {value:?}");
            } else {
                let _ = write!(self.0, " {}={value:?}", field.name());
            }
        }
    }

    impl tracing::Subscriber for Stderr {
        fn enabled(&self, metadata: &Metadata<'_>) -> bool {
            *metadata.level() <= self.max
        }
        fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
            Some(self.max.into())
        }
        fn new_span(&self, _: &Attributes<'_>) -> Id {
            Id::from_u64(1)
        }
        fn record(&self, _: &Id, _: &Record<'_>) {}
        fn record_follows_from(&self, _: &Id, _: &Id) {}
        fn event(&self, event: &Event<'_>) {
            let metadata = event.metadata();
            let mut line = Line(format!("{} {}:", metadata.level(), metadata.target()));
            event.record(&mut line);
            eprintln!("{}", line.0);
        }
        fn enter(&self, _: &Id) {}
        fn exit(&self, _: &Id) {}
    }
}

#[cfg(all(test, not(feature = "sim")))]
mod tests {
    use seal_proto::PlatformId;

    use crate::compiled::Release;

    /// The example guardians' release configurations committed in `deploy/example`.
    const GCP: &str = include_str!("../../../../../deploy/example/guardian-gcp.json");
    const AZURE: &str = include_str!("../../../../../deploy/example/guardian-azure.json");

    #[test]
    fn example_release_configs_parse() {
        let gcp = Release::parse(GCP.as_bytes()).unwrap();
        assert_eq!((gcp.platform, gcp.runs_on), (PlatformId::GcpConfidentialSpace, PlatformId::GcpConfidentialSpace));
        let (identity, keys) = gcp.gcp_kms.as_ref().unwrap();
        assert!(identity.provider.contains("/workloadIdentityPools/"), "{}", identity.provider);
        assert!(!keys.is_empty() && gcp.key_vault.is_none());

        let azure = Release::parse(AZURE.as_bytes()).unwrap();
        assert_eq!((azure.platform, azure.runs_on), (PlatformId::AzureSnpAci, PlatformId::AzureSnpAci));
        let (maa, keys) = azure.key_vault.as_ref().unwrap();
        assert_eq!(maa, "https://sharedeus.eus.attest.azure.net");
        assert!(!keys.is_empty() && azure.gcp_kms.is_none());
        // The binary builds its key source from these without complaint.
        let https = std::sync::Arc::new(seal_net::HttpsClient::new(std::sync::Arc::new(
            seal_net::BakedRootsConnector::new(std::sync::Arc::new(seal_net::TcpDialer)),
        )));
        let vault = seal_guardian::keysource::KeyVault::new(azure.platform, maa.clone(), https).unwrap();
        let copies = crate::azure::copies(keys, &[format!("{}:AAAA", "0".repeat(32))]).unwrap();
        crate::azure::key_source(vault, copies).unwrap();

        for release in [gcp, azure] {
            assert!(release.trust.releases.release_threshold >= 2);
        }
    }

    #[test]
    fn key_vault_copies_name_their_version() {
        let keys: Vec<seal_guardian::keysource::VaultKeyName> = serde_json::from_value(
            serde_json::json!([{"vault_url": "https://seal-a.vault.azure.net", "key_name": "root"}]),
        )
        .unwrap();
        let version = "0123456789abcdef0123456789abcdef";
        let copies = crate::azure::copies(&keys, &[format!("{version}:AAEC")]).unwrap();
        assert_eq!(copies[0].key_version, version);
        assert_eq!(copies[0].wrapped_root.as_deref(), Some(&[0u8, 1, 2][..]));
        assert!(crate::azure::copies(&keys, &["AAEC".into()]).is_err(), "no version");
        assert!(crate::azure::copies(&keys, &[format!("{version}:!!")]).is_err());
        assert!(crate::azure::copies(&keys, &[]).is_err());
    }

    #[test]
    fn release_configs_refuse_sim_settings_and_missing_keys() {
        let example: serde_json::Value = serde_json::from_str(GCP).unwrap();
        for (field, value) in [
            ("root_file", serde_json::json!("/var/lib/root")),
            ("extra_roots", serde_json::json!("/etc/ca.pem")),
            ("clock", serde_json::json!("system")),
            ("listen", serde_json::json!("0.0.0.0:1")),
        ] {
            let mut v = example.clone();
            v[field] = value;
            assert!(Release::parse(v.to_string().as_bytes()).is_err(), "{field}");
        }
        let mut v = example.clone();
        v["gcp_kms"]["wrapped_roots"] = serde_json::json!(["AAAA"]);
        assert!(Release::parse(v.to_string().as_bytes()).is_err(), "wrapped roots are boot inputs");
        let mut v = example.clone();
        v["gcp_kms"]["keys"] = serde_json::json!([]);
        assert!(Release::parse(v.to_string().as_bytes()).is_err());
        let mut v = example.clone();
        v.as_object_mut().unwrap().remove("gcp_kms");
        assert!(Release::parse(v.to_string().as_bytes()).is_err());
        let mut v = example;
        v["runs_on"] = serde_json::json!("azure_snp_aci");
        assert!(Release::parse(v.to_string().as_bytes()).is_err(), "gcp_kms on another platform");

        let example: serde_json::Value = serde_json::from_str(AZURE).unwrap();
        let mut v = example.clone();
        v["key_vault"]["wrapped_roots"] = serde_json::json!(["AAAA"]);
        assert!(Release::parse(v.to_string().as_bytes()).is_err(), "wrapped roots are boot inputs");
        let mut v = example.clone();
        v["key_vault"]["keys"][0]["key_version"] = serde_json::json!("0".repeat(32));
        assert!(Release::parse(v.to_string().as_bytes()).is_err(), "key versions are boot inputs");
        let mut v = example.clone();
        v["key_vault"]["keys"] = serde_json::json!([]);
        assert!(Release::parse(v.to_string().as_bytes()).is_err());
        let mut v = example.clone();
        v.as_object_mut().unwrap().remove("key_vault");
        assert!(Release::parse(v.to_string().as_bytes()).is_err());
        let mut v = example;
        v["runs_on"] = serde_json::json!("gcp_confidential_space");
        assert!(Release::parse(v.to_string().as_bytes()).is_err(), "key_vault on another platform");
    }

    /// The configuration this build compiled in, when it has one, is one the binary accepts.
    #[test]
    fn compiled_release_config_parses() {
        if !crate::compiled::RELEASE_CONFIG.trim().is_empty() {
            crate::compiled::release().unwrap();
        }
    }
}
