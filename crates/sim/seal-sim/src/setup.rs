//! Writes a complete simulator environment into one directory: dev release keys and a dev log
//! holding the enclave release they approved, a registrar key, a guardian root and the trust
//! that goes with them, a test CA for every local TLS server, and the configuration files of
//! the guardian, the control plane, the enclave and the `seal` CLI.
//!
//! ```text
//! <dir>/sim.json                  `Sim`: ports, keys and paths, read back by the other commands
//! <dir>/trust.json                `seal_verify::Trust` as JSON (guardian, enclave, SDK, CLI)
//! <dir>/log/                      the dev log (`seal-tlog-dev --dir`), with the release logged
//! <dir>/release.json              the release's `ReleaseEvidence`, PUT to the control plane
//! <dir>/release-keys/{1,2,3}.key  dev release keys (2 of 3 sign)
//! <dir>/registrar.key             the dev registrar key (`seal dev init --registrar-key`)
//! <dir>/stranger.key              a `SEAL_APP_KEY` no grant names (it may seal, as anyone may)
//! <dir>/ca.pem                    the test CA, trusted as `extra_roots` everywhere
//! <dir>/tls-chain.pem, tls-key.pem  a `localhost` certificate and key under it
//! <dir>/guardian-root, guardian.json   the guardian's root file and `SEAL_GUARDIAN_CONFIG`
//! <dir>/control.json, control/    the control plane's configuration and data directory
//! <dir>/enclave.json              `SEAL_ENCLAVE_CONFIG`
//! <dir>/admin/config.json         `SEAL_HOME` of the admin CLI: URLs and extra roots
//! ```
//!
//! The release is logged before the log server starts (the dev log is a directory), so the
//! log server must not be running on `<dir>/log` during setup.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context as _};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha384};

use seal_crypto::sign::SigningKey;
use seal_crypto::{Key32, PlatformMasterKey, ServiceKeys, SysRng, UnwrapErr};
use seal_proto::identity::WorkloadIdentity;
use seal_proto::release::{Component, LogEntry, ReleaseEvidence, ReleaseManifest, RELEASE_LABEL};
use seal_proto::signed::Signed;
use seal_proto::{Measurement, PlatformId, PublicKey, ServiceKeyVersion, TenantId, TenantRootId};
use seal_tlog::dev::DevLog;

/// The host name every local TLS server presents and every URL uses.
pub const HOST: &str = "localhost";
/// Witnesses of the dev log, and how many must cosign.
const WITNESSES: usize = 3;
const QUORUM: usize = 2;
const RELEASE_KEYS: usize = 3;
const RELEASE_THRESHOLD: usize = 2;
/// The release's (and the enclave's) service key version.
pub const SERVICE_KEY_VERSION: ServiceKeyVersion = ServiceKeyVersion(1);

/// Local ports, all on 127.0.0.1.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Ports {
    pub log: u16,
    /// The guardian itself (plain HTTP; the control plane reaches it here).
    pub guardian: u16,
    /// The TLS proxy in front of the guardian (the enclave reaches it here).
    pub guardian_tls: u16,
    pub control: u16,
    /// The enclave's one port: its API and the SDK tunnels.
    pub api: u16,
    pub upstream: u16,
}

impl Ports {
    /// Consecutive ports from `base`.
    pub fn from_base(base: u16) -> Self {
        Self {
            log: base,
            guardian: base + 1,
            guardian_tls: base + 2,
            control: base + 3,
            api: base + 4,
            upstream: base + 5,
        }
    }

    /// Ports that were free a moment ago (bound to port 0, then released).
    pub fn free() -> anyhow::Result<Self> {
        let take = || -> anyhow::Result<u16> { Ok(std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?.port()) };
        let listeners: Vec<u16> = (0..6).map(|_| take()).collect::<anyhow::Result<_>>()?;
        let [log, guardian, guardian_tls, control, api, upstream] = listeners[..] else { unreachable!("six ports") };
        Ok(Self { log, guardian, guardian_tls, control, api, upstream })
    }
}

/// Everything later steps need, saved as `<dir>/sim.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Sim {
    pub dir: PathBuf,
    pub ports: Ports,
    /// The dev log's seed (`seal-tlog-dev --seed`).
    pub log_seed: String,
    pub write_token: String,
    pub measurement: Measurement,
    pub guardian_key: PublicKey,
    /// What `SEAL_SIM_DEPLOYMENT` holds and `seal grant enclave sim` grants.
    pub deployment: WorkloadIdentity,
}

impl Sim {
    pub fn load(dir: &Path) -> anyhow::Result<Self> {
        let path = dir.join("sim.json");
        let text = std::fs::read(&path).with_context(|| format!("{}: run `seal-sim setup` first", path.display()))?;
        serde_json::from_slice(&text).with_context(|| format!("{}", path.display()))
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }
    pub fn log_url(&self) -> String {
        format!("http://127.0.0.1:{}/", self.ports.log)
    }
    pub fn control_url(&self) -> String {
        format!("https://{HOST}:{}/", self.ports.control)
    }
    /// `SEAL_ENDPOINT`.
    pub fn endpoint(&self) -> String {
        format!("https://{HOST}:{}", self.ports.api)
    }
    /// The test upstream's base URL, what blobs are sealed to.
    pub fn upstream_url(&self) -> String {
        format!("https://{HOST}:{}/v1", self.ports.upstream)
    }
    /// `SEAL_SIM_DEPLOYMENT` as JSON.
    pub fn deployment_json(&self) -> String {
        serde_json::to_string(&self.deployment).expect("an identity serializes")
    }
    /// The stranger's `SEAL_APP_KEY`.
    pub fn stranger_key(&self) -> anyhow::Result<String> {
        let path = self.path("stranger.key");
        Ok(std::fs::read_to_string(&path).with_context(|| format!("{}", path.display()))?.trim().to_string())
    }
    /// The test CA (PEM).
    pub fn ca_pem(&self) -> anyhow::Result<Vec<u8>> {
        let path = self.path("ca.pem");
        std::fs::read(&path).with_context(|| format!("{}", path.display()))
    }
    /// `<dir>/trust.json` as a `seal_verify::Trust`, for in-process SDK clients.
    pub fn trust(&self) -> anyhow::Result<seal_verify::Trust> {
        #[derive(Deserialize)]
        struct Tlog {
            origin: String,
            log_key: PublicKey,
            witness_keys: Vec<PublicKey>,
            witness_quorum: usize,
        }
        #[derive(Deserialize)]
        struct Releases {
            tlog: Tlog,
            release_keys: Vec<PublicKey>,
            release_threshold: usize,
            required_auditor: Option<PublicKey>,
            time_lock_secs: u64,
        }
        #[derive(Deserialize)]
        struct Tenants {
            tlog: Tlog,
            registrar_keys: Vec<PublicKey>,
            registrar_threshold: usize,
        }
        #[derive(Deserialize)]
        struct Trust {
            releases: Releases,
            tenants: Tenants,
            guardians: std::collections::BTreeMap<PlatformId, PublicKey>,
        }
        let tlog = |t: Tlog| seal_tlog::TlogTrust {
            origin: t.origin,
            log_key: t.log_key,
            witness_keys: t.witness_keys,
            witness_quorum: t.witness_quorum,
        };
        let t: Trust = serde_json::from_slice(&std::fs::read(self.path("trust.json"))?)?;
        Ok(seal_verify::Trust {
            releases: seal_verify::ReleaseTrust {
                tlog: tlog(t.releases.tlog),
                release_keys: t.releases.release_keys,
                release_threshold: t.releases.release_threshold,
                required_auditor: t.releases.required_auditor,
                time_lock_secs: t.releases.time_lock_secs,
            },
            tenants: seal_verify::TenantTrust {
                tlog: tlog(t.tenants.tlog),
                registrar_keys: t.tenants.registrar_keys,
                registrar_threshold: t.tenants.registrar_threshold,
            },
            guardians: t.guardians,
        })
    }
}

fn rng() -> UnwrapErr<SysRng> {
    UnwrapErr(SysRng)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn pem(label: &str, der: &[u8]) -> String {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let lines: Vec<&str> =
        b64.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).expect("base64 is ASCII")).collect();
    format!("-----BEGIN {label}-----\n{}\n-----END {label}-----\n", lines.join("\n"))
}

/// Writes `bytes` with mode 0600 (keys, tokens).
fn write_private(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("{}", path.display()))?;
    file.write_all(bytes).with_context(|| format!("{}", path.display()))
}

fn write_json(path: &Path, value: &serde_json::Value) -> anyhow::Result<()> {
    let mut text = serde_json::to_vec_pretty(value)?;
    text.push(b'\n');
    std::fs::write(path, text).with_context(|| format!("{}", path.display()))
}

/// A new Ed25519 key, saved as the CLI's key files are (the seed as 64 hex digits).
fn new_key(path: &Path) -> anyhow::Result<SigningKey> {
    let key = SigningKey::generate(&mut rng());
    write_private(path, format!("{}\n", hex(&key.to_seed()[..])).as_bytes())?;
    Ok(key)
}

/// SHA-384 of the file: a sim attestor's measurement of that binary.
pub fn measure(binary: &Path) -> anyhow::Result<Measurement> {
    let bytes = std::fs::read(binary).with_context(|| format!("{}", binary.display()))?;
    let digest = Sha384::digest(&bytes);
    Ok(Measurement(std::array::from_fn(|i| digest[i])))
}

/// The test CA and a `localhost` leaf under it: a name-constrained `TlsKey` chain, the same
/// construction enclaves use for their own certificates, from a random seed.
fn test_pki(dir: &Path) -> anyhow::Result<()> {
    let master = PlatformMasterKey::from_root_secret(PlatformId::Sim, &Key32::generate(&mut rng()));
    let released = master.release_service(&TenantId::new("sim-ca")?, &TenantRootId([0; 32]), ServiceKeyVersion(1));
    let tls = ServiceKeys::from_released(PlatformId::Sim, &released)?.tls;
    let names = vec![HOST.to_string()];
    let ca = pem("CERTIFICATE", &tls.ca_certificate_der(&names)?);
    let leaf = pem("CERTIFICATE", &tls.leaf_certificate_der(&names)?);
    std::fs::write(dir.join("ca.pem"), &ca)?;
    std::fs::write(dir.join("tls-chain.pem"), format!("{leaf}{ca}"))?;
    write_private(&dir.join("tls-key.pem"), pem("PRIVATE KEY", &tls.private_key_pkcs8_der()).as_bytes())
}

/// Signs the enclave release with `RELEASE_THRESHOLD` of the dev release keys, logs it and
/// returns its evidence: the inclusion proof and a fresh checkpoint, both cosigned `age`
/// seconds ago by the witnesses' clocks.
fn log_release(log: &mut DevLog, keys: &[SigningKey], measurement: Measurement, age: u64) -> ReleaseEvidence {
    let manifest = ReleaseManifest {
        component: Component::Enclave,
        platform: PlatformId::Sim,
        measurement,
        service_key_version: SERVICE_KEY_VERSION,
        version: env!("CARGO_PKG_VERSION").into(),
        source_commit: "sim".into(),
        serves: None,
    };
    let mut signed = Signed { body: manifest, signatures: vec![] };
    for key in &keys[..RELEASE_THRESHOLD] {
        key.cosign(RELEASE_LABEL, &mut signed);
    }
    let index = log.append(LogEntry::Release(signed.body.clone())).expect("the dev log appends releases");
    log.set_clock_offset(-i64::try_from(age).unwrap_or(i64::MAX));
    let included = log.prove(index);
    let fresh = log.checkpoint();
    log.set_clock_offset(0);
    ReleaseEvidence { manifest: signed, included, fresh, auditor: None }
}

/// Choices `setup` takes beyond the ports; the defaults behave like a release.
#[derive(Clone, Copy, Debug, Default)]
pub struct Options {
    /// The release's evidence is cosigned this many seconds ago: tests make its fresh
    /// checkpoint run out (`FRESH_CHECKPOINT_SECS`) while the system runs.
    pub release_age: u64,
    /// Replicas reload tenant state every second and the control plane reuses a log
    /// checkpoint for one second, instead of `STATE_RELOAD_SECS` and `CHECKPOINT_CACHE_SECS`,
    /// so tests see admin changes at once.
    pub fast_reload: bool,
}

/// Creates `dir` (which must not exist or be empty) and everything listed in the module docs.
/// `enclave_binary` is the `seal-enclave` the release approves.
pub fn setup(dir: &Path, enclave_binary: &Path, ports: Ports) -> anyhow::Result<Sim> {
    setup_with(dir, enclave_binary, ports, Options::default())
}

/// As `setup`, with `options`.
pub fn setup_with(dir: &Path, enclave_binary: &Path, ports: Ports, options: Options) -> anyhow::Result<Sim> {
    let Options { release_age, fast_reload } = options;
    if dir.exists() && std::fs::read_dir(dir)?.next().is_some() {
        bail!("{} is not empty", dir.display());
    }
    std::fs::create_dir_all(dir.join("release-keys"))?;
    std::fs::create_dir_all(dir.join("admin"))?;
    let dir = dir.canonicalize()?;
    let measurement = measure(enclave_binary)?;

    // The release: dev release keys, logged in the dev log.
    let release_keys: Vec<SigningKey> = (1..=RELEASE_KEYS)
        .map(|n| new_key(&dir.join(format!("release-keys/{n}.key"))))
        .collect::<anyhow::Result<_>>()?;
    let log_seed = Key32::generate(&mut rng());
    let mut log = DevLog::open(&dir.join("log"), *log_seed.expose(), WITNESSES, QUORUM)?;
    let tlog = log.trust();
    let evidence = log_release(&mut log, &release_keys, measurement, release_age);
    drop(log);
    std::fs::write(dir.join("release.json"), serde_json::to_vec_pretty(&evidence)?)?;

    // The guardian's root, and the guardian key derived from it.
    let root = Key32::generate(&mut rng());
    write_private(&dir.join("guardian-root"), root.expose())?;
    let guardian_key = PlatformMasterKey::from_root_secret(PlatformId::Sim, &root).guardian_key().public_key();

    let registrar = new_key(&dir.join("registrar.key"))?;
    let stranger = SigningKey::generate(&mut rng());
    let stranger_text = format!("sealak_{}\n", seal_proto::codec::b64url(&stranger.to_seed()[..]));
    write_private(&dir.join("stranger.key"), stranger_text.as_bytes())?;
    test_pki(&dir)?;
    let write_token = hex(Key32::generate(&mut rng()).expose());

    let tlog_json = json!({
        "origin": tlog.origin,
        "log_key": tlog.log_key,
        "witness_keys": tlog.witness_keys,
        "witness_quorum": tlog.witness_quorum,
    });
    let trust = json!({
        "releases": {
            "tlog": tlog_json,
            "release_keys": release_keys.iter().map(SigningKey::public_key).collect::<Vec<_>>(),
            "release_threshold": RELEASE_THRESHOLD,
            "required_auditor": null,
            "time_lock_secs": 0,
        },
        "tenants": {"tlog": tlog_json, "registrar_keys": [registrar.public_key()], "registrar_threshold": 1},
        "guardians": {"sim": guardian_key},
    });
    write_json(&dir.join("trust.json"), &trust)?;
    let path = |name: &str| dir.join(name).display().to_string();

    write_json(
        &dir.join("guardian.json"),
        &json!({
            "listen": format!("127.0.0.1:{}", ports.guardian),
            "root_file": path("guardian-root"),
            "trust": trust,
        }),
    )?;
    write_json(
        &dir.join("control.json"),
        &json!({
            "listen": format!("127.0.0.1:{}", ports.control),
            "data_dir": path("control"),
            "write_token": write_token,
            "tls": {"cert_chain": path("tls-chain.pem"), "private_key": path("tls-key.pem")},
            "log": {
                "url": format!("http://127.0.0.1:{}/", ports.log),
                "origin": tlog.origin,
                "log_key": tlog.log_key,
                "witness_keys": tlog.witness_keys,
                "witness_quorum": tlog.witness_quorum,
            },
            "registrar": {"keys": [registrar.public_key()], "threshold": 1},
            "guardians": {"sim": {"url": format!("http://127.0.0.1:{}/", ports.guardian), "key": guardian_key}},
            "releases": {
                "release_keys": release_keys.iter().map(SigningKey::public_key).collect::<Vec<_>>(),
                "release_threshold": RELEASE_THRESHOLD,
                "required_auditor": null,
                "time_lock_secs": 0,
            },
            "sim": if fast_reload {
                json!({"extra_roots": path("ca.pem"), "checkpoint_cache_secs": 1})
            } else {
                json!({"extra_roots": path("ca.pem")})
            },
        }),
    )?;
    let mut enclave = json!({
            "guardian": format!("https://{HOST}:{}/", ports.guardian_tls),
            "control_plane": format!("https://{HOST}:{}/", ports.control),
            "listen": format!("127.0.0.1:{}", ports.api),
            "service_key_version": SERVICE_KEY_VERSION,
            "extra_roots": path("ca.pem"),
            "trust": trust,
    });
    if fast_reload {
        enclave["state_reload_secs"] = 1.into();
    }
    write_json(&dir.join("enclave.json"), &enclave)?;
    let admin_config = json!({
        "log_url": format!("http://127.0.0.1:{}/", ports.log),
        "control_url": format!("https://{HOST}:{}/", ports.control),
        "sim": {"extra_roots": path("ca.pem")},
    });
    write_private(&dir.join("admin/config.json"), &serde_json::to_vec_pretty(&admin_config)?)?;

    let sim = Sim {
        dir: dir.clone(),
        ports,
        log_seed: hex(log_seed.expose()),
        write_token,
        measurement,
        guardian_key,
        deployment: WorkloadIdentity::ConfidentialSpace {
            project_number: 1,
            service_account: "enclave@sim.seal.zone".into(),
        },
    };
    write_json(&dir.join("sim.json"), &serde_json::to_value(&sim)?)?;
    Ok(sim)
}

/// PUTs `<dir>/release.json` to the control plane (`PUT /v1/releases/sim/{measurement}`).
pub async fn publish_release(sim: &Sim) -> anyhow::Result<()> {
    let evidence: ReleaseEvidence = serde_json::from_slice(&std::fs::read(sim.path("release.json"))?)?;
    let https = seal::admin::https_with_extra_roots(&sim.ca_pem()?)?;
    let control =
        seal::admin::ControlClient::new(url::Url::parse(&sim.control_url())?, https, Some(sim.write_token.clone()));
    control.put_release(PlatformId::Sim, &sim.measurement, &evidence).await?;
    Ok(())
}
