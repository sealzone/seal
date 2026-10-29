//! The enclave binary: detects its cloud, builds the runtime's `Components` over the guardian and
//! the control plane, boots `SealService` and serves its one port: the API and the SDK tunnels
//! (`seal_enclave::api::serve`). On SIGTERM or Ctrl-C, or
//! when a Seal-hosted replica has been idle for `HOSTED_IDLE_SECS` (`SealService::idle_exit`),
//! it stops accepting, lets open API requests finish (up to `API_DRAIN`), ships telemetry's
//! final batch (`ControlTelemetry::shutdown`) and exits with status 0: a Confidential Space VM
//! with restart policy `Never` then stops.
//!
//! Configuration (`Config`) is compiled in for production: the guardian and control-plane
//! URLs, the trust and the listen address are part of the release and so of its measurement, and the
//! tenant pin from the cloud is the only setting a deployer gives. The build reads it from the
//! JSON file `SEAL_RELEASE_ENCLAVE_CONFIG` names (`build.rs`; e.g.
//! `deploy/example/enclave.json`); a production binary built without it refuses to start.
//! The guardian key is the trust's `guardians` entry for the platform the enclave runs on.
//! Sim builds (`--features sim`, run with `SEAL_SIM=1`) read the same JSON from the file
//! named by `SEAL_ENCLAVE_CONFIG` at run time instead; only they may set `extra_roots` (PEM),
//! which adds CAs trusted for every outbound connection, `hosted_idle_secs`, which replaces
//! `HOSTED_IDLE_SECS`, and `state_reload_secs` (1 to `STATE_RELOAD_SECS`), which shortens the
//! tenant-state reload so tests need not wait it out:
//!
//! ```json
//! {
//!   "guardian": "https://guardian.local:7443/",
//!   "control_plane": "https://control.local:7500/",
//!   "listen": "127.0.0.1:7000",
//!   "service_key_version": 1,
//!   "extra_roots": "/etc/seal/test-ca.pem",
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
//! One image serves every platform, and each platform has its own guardian: `guardian` may
//! instead map platforms to URLs (`{"gcp_confidential_space": ..., "azure_snp_aci": ...}`), and
//! the enclave takes the entry for the platform it detects. Clients reach a replica at whatever
//! address their `SEAL_ENDPOINT` names and pin its attested key, so no name or address of the
//! replica's own is configured.
//!
//! The cloud's environment (`SEAL_TENANT`, `SEAL_SIM_DEPLOYMENT`, `SEAL_SIM_CLOCK_OFFSET` in sim)
//! is read by `seal_cloud::Cloud::detect`. Logs go to stderr, `info` and above (`SEAL_LOG=debug`
//! for more).
#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use seal_adapter_http::HttpAdapter;
use seal_adapter_pg::PostgresAdapter;
use seal_adapter_redis::RedisAdapter;
use seal_cloud::Cloud;
use seal_control::client::ControlClient;
use seal_enclave::ports::control::{
    ControlKeyRequestSource, ControlReleaseStore, ControlTenantStore, EnclaveCredential,
};
use seal_enclave::ports::guardian::GuardianKeyProvider;
use seal_enclave::ports::telemetry::ControlTelemetry;
use seal_enclave::{api, Components, SealService, ServiceConfig};
use seal_guardian::client::GuardianClient;
use seal_net::{BakedRootsConnector, HttpsClient};
use seal_proto::ServiceKeyVersion;
use tokio::net::TcpListener;
use tokio::sync::watch;

/// How long open API requests may take to finish after a shutdown signal.
const API_DRAIN: Duration = Duration::from_secs(10);

/// Everything the enclave is configured with besides its cloud.
struct Config {
    guardian: file::PerPlatform<url::Url>,
    control_plane: url::Url,
    /// The one port: the API and the tunnels.
    listen: SocketAddr,
    service_key_version: ServiceKeyVersion,
    trust: seal_verify::Trust,
    /// Sim only: extra PEM roots for outbound TLS.
    extra_roots: Option<Vec<u8>>,
    /// How long a hosted replica stays up idle: `HOSTED_IDLE_SECS`, or the sim file's.
    hosted_idle: Duration,
    /// How often the tenant's bundle is reloaded: `STATE_RELOAD_SECS`, or the sim file's.
    state_reload: Duration,
}

#[tokio::main]
async fn main() {
    log::init();
    if let Err(e) = run().await {
        tracing::error!("{e}");
        std::process::exit(1);
    }
}

/// The release configuration `build.rs` compiled in (empty when none was given).
#[cfg(not(feature = "sim"))]
const RELEASE_CONFIG: &str = include_str!(concat!(env!("OUT_DIR"), "/release-config.json"));

#[cfg(not(feature = "sim"))]
fn config() -> Result<Config, String> {
    if RELEASE_CONFIG.trim().is_empty() {
        return Err("this build has no release configuration (build with SEAL_RELEASE_ENCLAVE_CONFIG)".into());
    }
    file::parse(RELEASE_CONFIG.as_bytes(), file::SimSettings::Refuse)
}

#[cfg(feature = "sim")]
fn config() -> Result<Config, String> {
    sim::config()
}

async fn run() -> Result<(), String> {
    let config = config()?;
    let cloud = Cloud::detect().map_err(|e| format!("cloud: {e}"))?;
    let pin = cloud.tenant_pin().clone();
    let platform = cloud.attestor().platform();
    let guardian_url =
        config.guardian.get(platform).ok_or_else(|| format!("the configuration names no guardian for {platform:?}"))?;
    let guardian_key = *config
        .trust
        .guardians
        .get(&platform)
        .ok_or_else(|| format!("the trust names no guardian key for {platform:?}"))?;

    // The key provider and the control-plane credential attest with their own handle on this
    // TEE: `Cloud` moves into the runtime.
    let attestor = seal_tee::Attestor::detect().map_err(|e| format!("attestor: {e}"))?;
    if attestor.platform() != platform || attestor.measurement() != cloud.attestor().measurement() {
        return Err("the key provider's attestor is not the cloud's".into());
    }

    let attestor = Arc::new(attestor);

    let connector = Arc::new(connector(&config, cloud.dialer())?);
    let https = Arc::new(HttpsClient::new(connector.clone()));
    let credential = Arc::new(EnclaveCredential::new(pin.root_id, attestor.clone()));
    let control = Arc::new(
        ControlClient::new(config.control_plane.clone(), https.clone(), None).with_credential(credential.clone()),
    );
    let guardian = GuardianClient::new(guardian_url, https, guardian_key);
    let inputs = ControlKeyRequestSource::new(control.clone(), pin.tenant.clone());
    let telemetry = Arc::new(ControlTelemetry::new(control.clone(), pin.tenant.clone()).with_credential(credential));
    let components = Components {
        keys: Arc::new(GuardianKeyProvider::new(guardian, attestor, inputs)),
        tenants: Arc::new(ControlTenantStore::new(control.clone(), pin.tenant.clone())),
        releases: Arc::new(ControlReleaseStore::new(control)),
        cloud,
        upstream: connector,
        telemetry: telemetry.clone(),
        adapters: vec![Arc::new(HttpAdapter), Arc::new(PostgresAdapter::default()), Arc::new(RedisAdapter)],
        detectors: vec![],
        evidence_checks: vec![],
    };
    let service_config = ServiceConfig {
        service_key_version: config.service_key_version,
        trust: config.trust,
        state_reload: config.state_reload,
    };
    let service = Arc::new(SealService::boot(service_config, components).await.map_err(|e| format!("boot: {e}"))?);
    tracing::info!(tenant = %pin, "booted");

    let tls = service.tls_config();
    let listener = bind(config.listen).await?;
    let (stop, stopping) = watch::channel(false);
    let api_task = tokio::spawn(api::serve(service.clone(), listener, tls, stopped(stopping)));
    tracing::info!(listen = %config.listen, "serving the API and tunnels");

    tokio::select! {
        _ = shutdown_signal() => tracing::info!("shutting down"),
        _ = service.idle_exit(config.hosted_idle) => {
            tracing::info!(secs = config.hosted_idle.as_secs(), "hosted replica idle: shutting down")
        }
    }
    let _ = stop.send(true);
    match tokio::time::timeout(API_DRAIN, api_task).await {
        Ok(Ok(Err(e))) => tracing::warn!(error = %e, "API server"),
        Err(_) => tracing::warn!("API requests still open after the drain period"),
        _ => {}
    }
    if let Err(e) = telemetry.shutdown().await {
        tracing::error!(error = %e, "telemetry");
    }
    Ok(())
}

/// Outbound TLS for the guardian, the control plane and upstreams, through the cloud's dialer, with
/// certificates checked at trusted time (`seal_tee::tls_time`, first read by `SealService::boot`).
fn connector(config: &Config, dialer: Arc<dyn seal_net::Dialer>) -> Result<BakedRootsConnector, String> {
    #[cfg(feature = "sim")]
    if let Some(pem) = &config.extra_roots {
        return BakedRootsConnector::with_extra_roots(dialer, pem)
            .map(|c| c.with_time(seal_tee::tls_time()))
            .map_err(|e| format!("extra roots: {e}"));
    }
    if config.extra_roots.is_some() {
        return Err("extra roots are for sim builds only".into());
    }
    Ok(BakedRootsConnector::new(dialer).with_time(seal_tee::tls_time()))
}

async fn bind(addr: SocketAddr) -> Result<TcpListener, String> {
    TcpListener::bind(addr).await.map_err(|e| format!("listen on {addr}: {e}"))
}

/// Resolves once `stopping` turns true (or its sender is gone).
async fn stopped(mut stopping: watch::Receiver<bool>) {
    loop {
        let stop = *stopping.borrow_and_update();
        if stop || stopping.changed().await.is_err() {
            return;
        }
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}

/// The configuration's JSON (module docs), shared by the compiled-in release configuration
/// and the sim file.
mod file {
    use std::collections::BTreeMap;
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::time::Duration;

    use seal_enclave::{HOSTED_IDLE_SECS, STATE_RELOAD_SECS};
    use seal_proto::{PlatformId, PublicKey, ServiceKeyVersion};
    use serde::Deserialize;

    use super::Config;

    /// One value for every platform, or one per platform.
    #[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
    #[serde(untagged)]
    pub enum PerPlatform<T> {
        All(T),
        Each(BTreeMap<PlatformId, T>),
    }

    impl<T: Clone> PerPlatform<T> {
        pub fn get(&self, platform: PlatformId) -> Option<T> {
            match self {
                PerPlatform::All(value) => Some(value.clone()),
                PerPlatform::Each(values) => values.get(&platform).cloned(),
            }
        }

        fn try_map<U>(self, f: impl Fn(T) -> Result<U, String>) -> Result<PerPlatform<U>, String> {
            Ok(match self {
                PerPlatform::All(value) => PerPlatform::All(f(value)?),
                PerPlatform::Each(values) => {
                    PerPlatform::Each(values.into_iter().map(|(p, v)| Ok((p, f(v)?))).collect::<Result<_, String>>()?)
                }
            })
        }
    }

    /// Whether the sim-only settings (`extra_roots`, `hosted_idle_secs`, `state_reload_secs`)
    /// are taken (sim builds) or refused (release builds).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SimSettings {
        #[cfg_attr(not(feature = "sim"), allow(dead_code))]
        Allow,
        #[cfg_attr(feature = "sim", allow(dead_code))]
        Refuse,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct File {
        guardian: PerPlatform<String>,
        control_plane: String,
        listen: SocketAddr,
        service_key_version: ServiceKeyVersion,
        #[serde(default)]
        extra_roots: Option<PathBuf>,
        #[serde(default)]
        hosted_idle_secs: Option<u64>,
        #[serde(default)]
        state_reload_secs: Option<u64>,
        trust: Trust,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Trust {
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

    pub fn parse(text: &[u8], sim_settings: SimSettings) -> Result<Config, String> {
        let file: File = serde_json::from_slice(text).map_err(|e| format!("enclave config: {e}"))?;
        let extra_roots = match (&file.extra_roots, sim_settings) {
            (None, _) => None,
            (Some(_), SimSettings::Refuse) => return Err("enclave config: extra_roots are for sim builds only".into()),
            (Some(pem), SimSettings::Allow) => Some(std::fs::read(pem).map_err(|e| format!("{}: {e}", pem.display()))?),
        };
        let hosted_idle_secs = match (file.hosted_idle_secs, sim_settings) {
            (None, _) => HOSTED_IDLE_SECS,
            (Some(_), SimSettings::Refuse) => {
                return Err("enclave config: hosted_idle_secs is for sim builds only".into())
            }
            (Some(secs), SimSettings::Allow) => secs,
        };
        let state_reload_secs = match (file.state_reload_secs, sim_settings) {
            (None, _) => STATE_RELOAD_SECS,
            (Some(_), SimSettings::Refuse) => {
                return Err("enclave config: state_reload_secs is for sim builds only".into())
            }
            (Some(secs), SimSettings::Allow) if (1..=STATE_RELOAD_SECS).contains(&secs) => secs,
            (Some(_), SimSettings::Allow) => {
                return Err(format!("enclave config: state_reload_secs must be 1..={STATE_RELOAD_SECS}"))
            }
        };
        let url = |name: &str, s: &str| url::Url::parse(s).map_err(|e| format!("enclave config: {name}: {e}"));
        Ok(Config {
            guardian: file.guardian.try_map(|s| url("guardian", &s))?,
            control_plane: url("control_plane", &file.control_plane)?,
            listen: file.listen,
            service_key_version: file.service_key_version,
            trust: file.trust.into(),
            extra_roots,
            hosted_idle: Duration::from_secs(hosted_idle_secs),
            state_reload: Duration::from_secs(state_reload_secs),
        })
    }
}

#[cfg(feature = "sim")]
mod sim {
    use std::path::PathBuf;

    use super::{file, Config};

    pub fn config() -> Result<Config, String> {
        let path = PathBuf::from(std::env::var_os("SEAL_ENCLAVE_CONFIG").ok_or("SEAL_ENCLAVE_CONFIG is not set")?);
        let text = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        file::parse(&text, file::SimSettings::Allow)
    }
}

/// A minimal stderr logger: one line per event, `LEVEL target: message key=value…`. Spans are
/// not tracked; the TEE's dependency set stays as it is.
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

#[cfg(test)]
mod tests {
    use seal_enclave::HOSTED_IDLE_SECS;
    use seal_proto::PlatformId;

    use super::file::{self, PerPlatform, SimSettings};

    /// The example release configuration committed in `deploy/example`.
    const EXAMPLE: &str = include_str!("../../../../../deploy/example/enclave.json");

    fn parse(value: &serde_json::Value) -> Result<super::Config, String> {
        file::parse(value.to_string().as_bytes(), SimSettings::Refuse)
    }

    #[test]
    fn example_release_config_parses() {
        let config = file::parse(EXAMPLE.as_bytes(), SimSettings::Refuse).unwrap();
        for platform in [PlatformId::GcpConfidentialSpace, PlatformId::AzureSnpAci] {
            assert!(config.guardian.get(platform).is_some(), "{platform:?}: guardian");
            assert!(config.trust.guardians.contains_key(&platform), "{platform:?}: guardian key");
        }
        // Each platform has its own guardian; the simulator has none in a release.
        assert_ne!(config.guardian.get(PlatformId::GcpConfidentialSpace), config.guardian.get(PlatformId::AzureSnpAci));
        assert_eq!(config.guardian.get(PlatformId::Sim), None);
        assert!(config.extra_roots.is_none());
        assert_eq!(config.hosted_idle.as_secs(), HOSTED_IDLE_SECS);
    }

    #[test]
    fn release_builds_refuse_extra_roots_and_unknown_fields() {
        let mut value: serde_json::Value = serde_json::from_str(EXAMPLE).unwrap();
        value["extra_roots"] = "/etc/ca.pem".into();
        let err = parse(&value).err().unwrap();
        assert!(err.contains("sim builds only"), "{err}");
        let mut value: serde_json::Value = serde_json::from_str(EXAMPLE).unwrap();
        value["hosted_idle_secs"] = 5.into();
        let err = parse(&value).err().unwrap();
        assert!(err.contains("sim builds only"), "{err}");
        let mut value: serde_json::Value = serde_json::from_str(EXAMPLE).unwrap();
        value["state_reload_secs"] = 1.into();
        let err = parse(&value).err().unwrap();
        assert!(err.contains("sim builds only"), "{err}");
        let mut value: serde_json::Value = serde_json::from_str(EXAMPLE).unwrap();
        value["debug"] = true.into();
        assert!(parse(&value).is_err());
    }

    #[test]
    fn one_value_serves_every_platform() {
        let mut value: serde_json::Value = serde_json::from_str(EXAMPLE).unwrap();
        value["guardian"] = "https://guardian.example/".into();
        let config = parse(&value).unwrap();
        for platform in [PlatformId::Sim, PlatformId::AwsNitro, PlatformId::GcpConfidentialSpace] {
            assert_eq!(config.guardian.get(platform).unwrap().as_str(), "https://guardian.example/");
        }
        assert!(matches!(config.guardian, PerPlatform::All(_)));
        value["guardian"] = "not a url".into();
        assert!(parse(&value).is_err());
        value["guardian"] = serde_json::json!({"gcp_confidential_space": "not a url"});
        assert!(parse(&value).is_err());
    }

    /// The configuration this build compiled in, when it has one, is one the binary accepts.
    #[cfg(not(feature = "sim"))]
    #[test]
    fn compiled_release_config_parses() {
        if !super::RELEASE_CONFIG.trim().is_empty() {
            file::parse(super::RELEASE_CONFIG.as_bytes(), SimSettings::Refuse).unwrap();
        }
    }
}
