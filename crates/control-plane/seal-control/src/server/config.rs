//! The deployment's configuration: one JSON file (`seal-control --config FILE`).
//!
//! ```json
//! {
//!   "listen": "0.0.0.0:8443",
//!   "data_dir": "/var/lib/seal-control",
//!   "write_token": "...",
//!   "tls": { "cert_chain": "/etc/seal-control/chain.pem", "private_key": "/etc/seal-control/key.pem" },
//!   "log": {
//!     "url": "https://log.seal.zone",
//!     "origin": "log.seal.zone/v1",
//!     "log_key": "<hex>",
//!     "witness_keys": ["<hex>"],
//!     "witness_quorum": 1
//!   },
//!   "registrar": { "keys": ["<hex>"], "threshold": 1 },
//!   "guardians": { "azure_snp_aci": { "url": "https://guardian-aci.seal.zone", "key": "<hex>" } },
//!   "releases": { "release_keys": ["<hex>"], "release_threshold": 2, "required_auditor": null, "time_lock_secs": 0 },
//!   "console": { "origin": "https://console.seal.zone", "keys": ["<hex>"] },
//!   "sim": { "extra_roots": "/tmp/sim-ca.pem" }
//! }
//! ```
//!
//! - `write_token`: the bearer token admin writes need; `SEAL_CONTROL_WRITE_TOKEN` in the
//!   environment takes precedence. At least 16 characters.
//! - `tls`: PEM files the server presents, reread when they change (`tls::ReloadingCert`), so a
//!   certificate renewed next to the server takes over without a restart. Without it the
//!   server speaks plain HTTP, for a TLS-terminating proxy in front.
//! - `log`: where freshness statements and checkpoints come from, and the `TlogTrust` that
//!   checks them and the root chains' inclusion proofs.
//! - `registrar`: optional; when set, a root version 1 must carry the registrar threshold.
//! - `guardians`: per platform, where wrap keys come from and the guardian key that certifies
//!   them and enclaves' service key certificates.
//! - `releases`: the release trust (with the log's) that an enclave's attested boot read must
//!   pass (`auth`). Without it, attested reads are refused.
//! - `console`: the web UI's origin, the only one CORS admits, and the console's Ed25519
//!   public keys (several while it rotates) that control tokens are checked with.
//! - `sim` (sim builds only): `extra_roots` is a PEM file of roots trusted for the log and the
//!   guardians next to the baked ones, and `http://` URLs on loopback are allowed for them.
//!   `checkpoint_cache_secs` shortens how long a log checkpoint is reused, so a local run need
//!   not wait out `CHECKPOINT_CACHE_SECS` to see what it just logged.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use seal_proto::{PlatformId, PublicKey};

pub const WRITE_TOKEN_ENV: &str = "SEAL_CONTROL_WRITE_TOKEN";
const MIN_WRITE_TOKEN_LEN: usize = 16;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: SocketAddr,
    pub data_dir: PathBuf,
    #[serde(default)]
    pub write_token: Option<String>,
    #[serde(default)]
    pub tls: Option<TlsFiles>,
    pub log: LogConfig,
    #[serde(default)]
    pub registrar: Option<RegistrarConfig>,
    #[serde(default)]
    pub guardians: BTreeMap<PlatformId, GuardianConfig>,
    #[serde(default)]
    pub releases: Option<ReleaseConfig>,
    #[serde(default)]
    pub console: Option<ConsoleConfig>,
    #[serde(default)]
    pub sim: Option<SimConfig>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseConfig {
    pub release_keys: Vec<PublicKey>,
    pub release_threshold: usize,
    #[serde(default)]
    pub required_auditor: Option<PublicKey>,
    pub time_lock_secs: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsoleConfig {
    /// Scheme and host exactly as browsers send `Origin` (`https://console.seal.zone`).
    pub origin: String,
    pub keys: Vec<PublicKey>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsFiles {
    pub cert_chain: PathBuf,
    pub private_key: PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    #[serde(deserialize_with = "url_from_str")]
    pub url: url::Url,
    pub origin: String,
    pub log_key: PublicKey,
    pub witness_keys: Vec<PublicKey>,
    pub witness_quorum: usize,
}

impl LogConfig {
    pub fn trust(&self) -> seal_tlog::TlogTrust {
        seal_tlog::TlogTrust {
            origin: self.origin.clone(),
            log_key: self.log_key,
            witness_keys: self.witness_keys.clone(),
            witness_quorum: self.witness_quorum,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrarConfig {
    pub keys: Vec<PublicKey>,
    pub threshold: usize,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardianConfig {
    #[serde(deserialize_with = "url_from_str")]
    pub url: url::Url,
    pub key: PublicKey,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimConfig {
    // Read only by sim builds; other builds refuse a config with "sim" at all.
    #[cfg_attr(not(feature = "sim"), allow(dead_code))]
    #[serde(default)]
    pub extra_roots: Option<PathBuf>,
    #[serde(default)]
    pub checkpoint_cache_secs: Option<u64>,
}

fn url_from_str<'de, D: serde::Deserializer<'de>>(d: D) -> Result<url::Url, D::Error> {
    let s = String::deserialize(d)?;
    url::Url::parse(&s).map_err(serde::de::Error::custom)
}

fn upstream_url(what: &str, url: &url::Url, sim: bool) -> Result<(), String> {
    match url.scheme() {
        "https" => Ok(()),
        "http" if sim && is_loopback(url) => Ok(()),
        "http" if sim => Err(format!("{what}: plain http:// is allowed on loopback only")),
        _ => Err(format!("{what}: needs an https:// URL")),
    }
}

/// `localhost` or a loopback IP.
pub fn is_loopback(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        let bytes = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let mut config: Config = serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display()))?;
        if let Ok(token) = std::env::var(WRITE_TOKEN_ENV) {
            config.write_token = Some(token);
        }
        config.validate()?;
        Ok(config)
    }

    /// Checks everything that does not need IO.
    pub fn validate(&self) -> Result<(), String> {
        let sim = self.sim.is_some();
        if sim && !cfg!(feature = "sim") {
            return Err("\"sim\" needs a build with the sim feature".into());
        }
        match &self.write_token {
            Some(t) if t.len() >= MIN_WRITE_TOKEN_LEN => {}
            Some(_) => return Err(format!("the write token needs at least {MIN_WRITE_TOKEN_LEN} characters")),
            None => return Err(format!("no write token: set \"write_token\" or {WRITE_TOKEN_ENV}")),
        }
        upstream_url("log.url", &self.log.url, sim)?;
        if self.log.witness_quorum == 0 || self.log.witness_quorum > self.log.witness_keys.len() {
            return Err("log.witness_quorum must be between 1 and the number of witness keys".into());
        }
        if let Some(r) = &self.registrar {
            if r.threshold == 0 || r.threshold > r.keys.len() {
                return Err("registrar.threshold must be between 1 and the number of keys".into());
            }
        }
        if let Some(r) = &self.releases {
            if r.release_threshold == 0 || r.release_threshold > r.release_keys.len() {
                return Err("releases.release_threshold must be between 1 and the number of keys".into());
            }
        }
        if let Some(c) = &self.console {
            let origin = url::Url::parse(&c.origin).map_err(|e| format!("console.origin: {e}"))?;
            let bare = origin.path() == "/" && origin.query().is_none() && origin.fragment().is_none();
            let local = matches!(origin.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
            let scheme_ok = origin.scheme() == "https" || (sim && local && origin.scheme() == "http");
            if !scheme_ok || !bare || c.origin.ends_with('/') || origin.username() != "" {
                return Err("console.origin must be https://host[:port] (sim mode also takes http://localhost[:port]), as browsers send Origin".into());
            }
            if c.keys.is_empty() {
                return Err("console.keys names no key".into());
            }
        }
        for (platform, guardian) in &self.guardians {
            if *platform == PlatformId::Sim && !sim {
                return Err("a guardian for the sim platform needs sim mode".into());
            }
            upstream_url(&format!("guardians.{platform:?}.url"), &guardian.url, sim)?;
        }
        Ok(())
    }

    /// The release trust attested reads are checked with, over the configured log.
    pub fn release_trust(&self) -> Option<seal_verify::ReleaseTrust> {
        let r = self.releases.as_ref()?;
        Some(seal_verify::ReleaseTrust {
            tlog: self.log.trust(),
            release_keys: r.release_keys.clone(),
            release_threshold: r.release_threshold,
            required_auditor: r.required_auditor,
            time_lock_secs: r.time_lock_secs,
        })
    }

    pub fn write_token(&self) -> &str {
        self.write_token.as_deref().unwrap_or_default()
    }

    /// `sim.checkpoint_cache_secs`, else `CHECKPOINT_CACHE_SECS` ("sim" is refused outside
    /// sim builds, so release builds always get the constant).
    pub fn checkpoint_cache_secs(&self) -> u64 {
        self.sim.as_ref().and_then(|s| s.checkpoint_cache_secs).unwrap_or(super::CHECKPOINT_CACHE_SECS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: &str) -> Result<Config, String> {
        let config: Config = serde_json::from_str(json).map_err(|e| e.to_string())?;
        config.validate().map(|()| config)
    }

    const KEY: &str = "0101010101010101010101010101010101010101010101010101010101010101";

    fn config(extra: &str) -> String {
        format!(
            r#"{{"listen":"127.0.0.1:0","data_dir":"/tmp/x","write_token":"0123456789abcdef",
            "log":{{"url":"https://log.example","origin":"o","log_key":"{KEY}","witness_keys":["{KEY}"],"witness_quorum":1}}{extra}}}"#
        )
    }

    #[test]
    fn a_minimal_config_loads() {
        let c = parse(&config("")).unwrap();
        assert_eq!(c.write_token(), "0123456789abcdef");
        assert!(c.guardians.is_empty());
    }

    #[test]
    fn guardians_are_keyed_by_platform() {
        let c =
            parse(&config(&format!(r#","guardians":{{"azure_snp_aci":{{"url":"https://g.example","key":"{KEY}"}}}}"#)))
                .unwrap();
        assert!(c.guardians.contains_key(&PlatformId::AzureSnpAci));
    }

    #[test]
    fn junk_is_refused() {
        assert!(parse(&config(r#","unknown":1"#)).is_err());
        let short = config("").replace("0123456789abcdef", "short");
        assert!(parse(&short).is_err());
        let plain = config("").replace("https://log.example", "http://log.example");
        assert!(parse(&plain).is_err());
        let quorum = config("").replace(r#""witness_quorum":1"#, r#""witness_quorum":2"#);
        assert!(parse(&quorum).is_err());
        let sim_guardian = config(&format!(r#","guardians":{{"sim":{{"url":"https://g.example","key":"{KEY}"}}}}"#));
        assert!(parse(&sim_guardian).is_err());
    }

    #[test]
    fn console_and_releases_are_checked() {
        let console = |origin: &str| config(&format!(r#","console":{{"origin":"{origin}","keys":["{KEY}"]}}"#));
        assert!(parse(&console("https://console.seal.zone")).is_ok());
        assert!(parse(&console("https://console.seal.zone/")).is_err(), "browsers send no trailing slash");
        assert!(parse(&console("http://console.seal.zone")).is_err());
        assert!(parse(&console("http://localhost:3000")).is_err(), "plain http only in sim mode");
        assert!(parse(&console("https://console.seal.zone/api")).is_err());
        assert!(parse(&config(r#","console":{"origin":"https://console.seal.zone","keys":[]}"#)).is_err());
        let releases = |threshold: u8| {
            config(&format!(
                r#","releases":{{"release_keys":["{KEY}"],"release_threshold":{threshold},"time_lock_secs":0}}"#
            ))
        };
        assert!(parse(&releases(1)).unwrap().release_trust().is_some());
        assert!(parse(&releases(2)).is_err());
        assert!(parse(&config("")).unwrap().release_trust().is_none());
    }

    #[test]
    fn sim_mode_needs_the_feature_and_allows_loopback_http() {
        let local = config(r#","sim":{}"#).replace("https://log.example", "http://127.0.0.1:7300");
        assert_eq!(parse(&local).is_ok(), cfg!(feature = "sim"));
        let remote = config(r#","sim":{}"#).replace("https://log.example", "http://log.example");
        assert!(parse(&remote).is_err());
        let origin = |o: &str| config(&format!(r#","sim":{{}},"console":{{"origin":"{o}","keys":["{KEY}"]}}"#));
        assert_eq!(parse(&origin("http://localhost:3000")).is_ok(), cfg!(feature = "sim"));
        assert!(parse(&origin("http://console.example")).is_err(), "plain http to localhost only");
    }

    #[test]
    fn only_sim_mode_shortens_the_checkpoint_cache() {
        assert_eq!(parse(&config("")).unwrap().checkpoint_cache_secs(), super::super::CHECKPOINT_CACHE_SECS);
        let short = parse(&config(r#","sim":{"checkpoint_cache_secs":1}"#)).map(|c| c.checkpoint_cache_secs());
        // Release builds refuse "sim" at all.
        assert_eq!(short.ok(), cfg!(feature = "sim").then_some(1));
    }
}
