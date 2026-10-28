//! `$SEAL_HOME` (default `~/.config/seal/`): `config.json`, which `seal use` writes. It names
//! the tenant and where to reach it, never a credential or a key:
//!
//! ```json
//! {
//!   "tenant": "acme",
//!   "root_id": "<64 hex>",
//!   "workspace": "acme-corp",
//!   "console_url": "https://console.seal.zone/",
//!   "control_url": "https://control.seal.zone/",
//!   "log_url": "https://log.seal.zone/",
//!   "sim": {"extra_roots": "/path/test-ca.pem"}
//! }
//! ```
//!
//! Every field is optional; the URLs default to Seal's (`DEFAULT_*`) and are written only when
//! `--console-url`, `--control-url` or `--log-url` named others. `sim.extra_roots` (sim builds
//! only) adds a test CA for the console, the control plane and the log.
//!
//! The trust tenants are verified with is the one compiled into this build
//! (`seal::built_in_trust`), or a `trust.json` named by `--trust` / `SEAL_TRUST`
//! (`TrustFile`: `releases` and `guardians` may be left out).
//!
//! Key files are the user's: the CLI reads the ones named on the command line and writes one
//! only where asked (`seal key create --out`, `--generate --out`). Admin and freshness key
//! files hold one Ed25519 seed as 64 hex digits, telemetry reader key files one X25519 seed
//! the same way, app keys the `SEAL_APP_KEY` format, `sealak_<base64url(seed)>`; each is
//! created with mode 0600 and never overwritten.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context as _};
use serde::{Deserialize, Serialize};

use seal_crypto::sign::SigningKey;
use seal_crypto::telemetry::TelemetryReaderKey;
use seal_crypto::SecretBytes;
use seal_proto::{PlatformId, PublicKey, TenantId, TenantRootId};

pub const DEFAULT_CONSOLE_URL: &str = "https://console.seal.zone/";
pub const DEFAULT_CONTROL_URL: &str = "https://control.seal.zone/";
pub const DEFAULT_LOG_URL: &str = "https://log.seal.zone/";

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<TenantId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_id: Option<TenantRootId>,
    /// The console workspace the tenant is in (its slug), for console links.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub console_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sim: Option<SimConfig>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra_roots: Option<PathBuf>,
}

/// A `trust.json` as `--trust` reads it: `seal_verify::Trust`, with `releases` and
/// `guardians` optional (tenant commands need only `tenants`).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustFile {
    pub tenants: TenantTrustFile,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub releases: Option<ReleaseTrustFile>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub guardians: BTreeMap<PlatformId, PublicKey>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlogTrustFile {
    pub origin: String,
    pub log_key: PublicKey,
    pub witness_keys: Vec<PublicKey>,
    pub witness_quorum: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantTrustFile {
    pub tlog: TlogTrustFile,
    pub registrar_keys: Vec<PublicKey>,
    pub registrar_threshold: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseTrustFile {
    pub tlog: TlogTrustFile,
    pub release_keys: Vec<PublicKey>,
    pub release_threshold: usize,
    #[serde(default)]
    pub required_auditor: Option<PublicKey>,
    pub time_lock_secs: u64,
}

impl From<&TlogTrustFile> for seal::admin::TlogTrust {
    fn from(t: &TlogTrustFile) -> Self {
        Self {
            origin: t.origin.clone(),
            log_key: t.log_key,
            witness_keys: t.witness_keys.clone(),
            witness_quorum: t.witness_quorum,
        }
    }
}

/// What commands verify with: the tenant trust always; the release trust and guardian keys
/// when the trust names them.
#[derive(Clone, Debug)]
pub struct Trusted {
    pub tenants: seal_verify::TenantTrust,
    /// The full trust: `seal secret seal` passes it to the SDK; deploying verifies releases.
    pub full: Option<seal_verify::Trust>,
    pub guardians: BTreeMap<PlatformId, PublicKey>,
}

impl From<seal_verify::Trust> for Trusted {
    fn from(t: seal_verify::Trust) -> Self {
        Self { tenants: t.tenants.clone(), guardians: t.guardians.clone(), full: Some(t) }
    }
}

impl From<&TrustFile> for Trusted {
    fn from(t: &TrustFile) -> Self {
        let tenants = seal_verify::TenantTrust {
            tlog: (&t.tenants.tlog).into(),
            registrar_keys: t.tenants.registrar_keys.clone(),
            registrar_threshold: t.tenants.registrar_threshold,
        };
        let full = t.releases.as_ref().map(|r| seal_verify::Trust {
            releases: seal_verify::ReleaseTrust {
                tlog: (&r.tlog).into(),
                release_keys: r.release_keys.clone(),
                release_threshold: r.release_threshold,
                required_auditor: r.required_auditor,
                time_lock_secs: r.time_lock_secs,
            },
            tenants: tenants.clone(),
            guardians: t.guardians.clone(),
        });
        Self { tenants, full, guardians: t.guardians.clone() }
    }
}

/// The trust in `path` (`--trust`).
pub fn read_trust(path: &Path) -> anyhow::Result<Trusted> {
    let text = std::fs::read(path).with_context(|| format!("{}", path.display()))?;
    let file: TrustFile = serde_json::from_slice(&text).with_context(|| format!("{}", path.display()))?;
    Ok((&file).into())
}

/// The `$SEAL_HOME` directory.
pub struct Home(pub PathBuf);

impl Home {
    /// `explicit` (`--home` / `SEAL_HOME`), else `~/.config/seal`.
    pub fn locate(explicit: Option<PathBuf>) -> anyhow::Result<Self> {
        if let Some(dir) = explicit {
            return Ok(Self(dir));
        }
        let home = std::env::var_os("HOME").ok_or_else(|| anyhow!("HOME is not set: pass --home or set SEAL_HOME"))?;
        Ok(Self(PathBuf::from(home).join(".config").join("seal")))
    }

    pub fn config_path(&self) -> PathBuf {
        self.0.join("config.json")
    }

    /// The configuration; empty when there is no file yet.
    pub fn load(&self) -> anyhow::Result<Config> {
        let path = self.config_path();
        match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).with_context(|| format!("{}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(e).with_context(|| format!("{}", path.display())),
        }
    }

    pub fn save(&self, config: &Config) -> anyhow::Result<()> {
        let path = self.config_path();
        let tmp = self.0.join("config.json.tmp");
        let _ = std::fs::remove_file(&tmp);
        let mut text = serde_json::to_vec_pretty(config)?;
        text.push(b'\n');
        write_private(&tmp, &text)?;
        std::fs::rename(&tmp, &path).with_context(|| format!("{}", path.display()))
    }
}

/// Creates `path` (and its directory, mode 0700) with mode 0600; refuses to overwrite.
pub fn write_private(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder.create(dir).with_context(|| format!("{}", dir.display()))?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(path).with_context(|| format!("{}", path.display()))?;
    file.write_all(bytes).with_context(|| format!("{}", path.display()))?;
    file.sync_all().with_context(|| format!("{}", path.display()))
}

/// Refuses `path` when something is there already: key files are never replaced.
pub fn check_new(path: &Path) -> anyhow::Result<()> {
    if path.exists() {
        bail!("{} exists: key files are never replaced", path.display());
    }
    Ok(())
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(s: &str) -> anyhow::Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        bail!("expected hex digits");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| anyhow!("expected hex digits")))
        .collect()
}

/// The key `from_seed` makes of the 32-byte seed in the key file `path` (64 hex digits);
/// `kind` names the key in errors.
fn read_seed<K>(path: &Path, kind: &str, from_seed: impl FnOnce(&[u8; 32]) -> K) -> anyhow::Result<K> {
    let text = SecretBytes::new(std::fs::read(path).with_context(|| format!("{}", path.display()))?);
    let text = std::str::from_utf8(text.expose()).map_err(|_| anyhow!("{}: not a key file", path.display()))?;
    let seed = SecretBytes::new(unhex(text.trim()).map_err(|_| anyhow!("{}: not a key file", path.display()))?);
    let seed: &[u8; 32] =
        seed.expose().try_into().map_err(|_| anyhow!("{}: expected a 32-byte {kind} seed", path.display()))?;
    Ok(from_seed(seed))
}

/// `seed` as a key file's text: 64 hex digits and a newline.
pub fn seed_text(seed: &[u8; 32]) -> SecretBytes {
    let mut text = hex(seed);
    text.push('\n');
    SecretBytes::new(text.into_bytes())
}

/// The Ed25519 key in `path` (64 hex digits of its seed).
pub fn read_key(path: &Path) -> anyhow::Result<SigningKey> {
    read_seed(path, "Ed25519", SigningKey::from_seed)
}

/// A new Ed25519 key.
pub fn generate_key() -> SigningKey {
    SigningKey::generate(&mut seal_crypto::UnwrapErr(seal_crypto::SysRng))
}

/// A new Ed25519 key, written to `path` (which must not exist) with mode 0600.
pub fn create_key(path: &Path) -> anyhow::Result<SigningKey> {
    let key = generate_key();
    write_private(path, seed_text(&key.to_seed()).expose())?;
    Ok(key)
}

/// The telemetry reader key in `path` (64 hex digits of its X25519 seed).
pub fn read_reader_key(path: &Path) -> anyhow::Result<TelemetryReaderKey> {
    read_seed(path, "X25519", TelemetryReaderKey::from_seed)
}

/// `key` in the `SEAL_APP_KEY` format, and a newline.
pub fn app_key_text(key: &SigningKey) -> SecretBytes {
    SecretBytes::new(format!("sealak_{}\n", seal_proto::codec::b64url(&key.to_seed()[..])).into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        std::env::temp_dir().join(format!("seal-cli-{name}-{}-{nanos}", std::process::id()))
    }

    #[test]
    fn key_files_round_trip_privately_and_never_overwrite() {
        let dir = scratch("keys");
        let path = dir.join("admin.key");
        let key = create_key(&path).unwrap();
        assert_eq!(read_key(&path).unwrap().public_key(), key.public_key());
        assert!(create_key(&path).is_err(), "an existing key is never replaced");
        assert!(check_new(&path).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn reader_key_files_round_trip_privately_and_never_overwrite() {
        let dir = scratch("reader-keys");
        let path = dir.join("reader.key");
        let key = TelemetryReaderKey::generate(&mut seal_crypto::UnwrapErr(seal_crypto::SysRng));
        write_private(&path, seed_text(&key.to_seed()).expose()).unwrap();
        assert_eq!(read_reader_key(&path).unwrap().public_key(), key.public_key());
        assert!(write_private(&path, b"x").is_err(), "an existing key is never replaced");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        std::fs::write(dir.join("short.key"), "abcd\n").unwrap();
        let err = read_reader_key(&dir.join("short.key")).unwrap_err().to_string();
        assert!(err.contains("expected a 32-byte X25519 seed"), "{err}");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn config_round_trips_and_holds_no_credential() {
        let home = Home(scratch("config"));
        assert!(home.load().unwrap().tenant.is_none());
        let config = Config {
            tenant: Some(TenantId::new("acme").unwrap()),
            root_id: Some(TenantRootId([3; 32])),
            workspace: Some("acme-corp".into()),
            ..Config::default()
        };
        home.save(&config).unwrap();
        home.save(&config).unwrap();
        let back = home.load().unwrap();
        assert_eq!(back.tenant, config.tenant);
        assert_eq!(back.root_id, config.root_id);
        assert_eq!(back.workspace.as_deref(), Some("acme-corp"));
        std::fs::write(home.config_path(), r#"{"control_token": "t"}"#).unwrap();
        assert!(home.load().is_err(), "a write token is never read from the configuration");
        std::fs::remove_dir_all(&home.0).unwrap();
    }

    #[test]
    fn a_partial_trust_file_verifies_tenants_only() {
        let key = PublicKey([1; 32]);
        let file: TrustFile = serde_json::from_value(serde_json::json!({
            "tenants": {"tlog": {"origin": "o", "log_key": key, "witness_keys": [], "witness_quorum": 0},
                        "registrar_keys": [key], "registrar_threshold": 1}
        }))
        .unwrap();
        let trusted = Trusted::from(&file);
        assert!(trusted.full.is_none() && trusted.guardians.is_empty());
        assert_eq!(trusted.tenants.registrar_keys, [key]);
    }
}
