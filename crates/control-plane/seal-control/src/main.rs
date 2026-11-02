//! The control plane server. The API is documented on the library (`seal_control`).
//!
//! ```text
//! seal-control --config FILE
//! seal-control --config FILE import-telemetry
//! ```
//!
//! `import-telemetry` reads the batch files under `data_dir` into the telemetry database, once;
//! running it again changes nothing.
//!
//! The configuration is described in `server::config`.

#![forbid(unsafe_code)]

mod server;

use std::sync::Arc;

use seal_net::{BakedRootsConnector, HttpsClient, TcpDialer, UpstreamConnector};

use server::config::Config;

fn connector(config: &Config) -> Result<Arc<dyn UpstreamConnector>, String> {
    let dialer = Arc::new(TcpDialer);
    #[cfg(feature = "sim")]
    if let Some(path) = config.sim.as_ref().and_then(|s| s.extra_roots.as_ref()) {
        let pem = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let connector = BakedRootsConnector::with_extra_roots(dialer, &pem).map_err(|e| e.to_string())?;
        return Ok(Arc::new(connector));
    }
    let _ = config;
    Ok(Arc::new(BakedRootsConnector::new(dialer)))
}

async fn telemetry_db(config: &Config) -> Result<Option<server::telemetry_db::TelemetryDb>, String> {
    let Ok(url) = std::env::var(server::config::DATABASE_URL_ENV) else { return Ok(None) };
    let entra = match std::env::var(server::config::DATABASE_AUTH_ENV).as_deref() {
        Ok("entra") => true,
        Err(_) => false,
        Ok(other) => return Err(format!("{}: unknown value {other}", server::config::DATABASE_AUTH_ENV)),
    };
    let db = server::telemetry_db::TelemetryDb::connect(&url, config.telemetry_retention_days, entra)
        .await
        .map_err(|e| format!("telemetry database: {e}"))?;
    Ok(Some(db))
}

async fn import_telemetry(config: Config) -> Result<(), String> {
    let db = telemetry_db(&config).await?.ok_or_else(|| format!("set {}", server::config::DATABASE_URL_ENV))?;
    let (new, failed) = db.import_files(&config.data_dir).await.map_err(|e| format!("telemetry database: {e}"))?;
    println!("{new} batches imported, {failed} files could not be read");
    Ok(())
}

async fn run(config: Config) -> Result<(), String> {
    let https = Arc::new(HttpsClient::new(connector(&config)?));
    let upstreams = server::upstream::HttpUpstreams::new(
        https,
        &config.log.url,
        config.guardians.iter().map(|(p, g)| (*p, g.url.clone())).collect(),
    );
    let settings = server::Settings {
        write_token: config.write_token().to_string(),
        log: config.log.trust(),
        registrar: config.registrar.as_ref().map(|r| (r.keys.clone(), r.threshold)),
        guardians: config.guardians.iter().map(|(p, g)| (*p, g.key)).collect(),
        releases: config.release_trust(),
        console_keys: config.console.as_ref().map(|c| c.keys.clone()).unwrap_or_default(),
        console_origin: config.console.as_ref().map(|c| c.origin.clone()),
        checkpoint_cache_secs: config.checkpoint_cache_secs(),
    };
    let store = server::store::Store::open(&config.data_dir)
        .map_err(|e| format!("cannot open {}: {e}", config.data_dir.display()))?;
    let clock = server::system_clock();
    let mut app = server::App::new(settings, store, Arc::new(upstreams), clock.clone())?;
    if let Some(db) = telemetry_db(&config).await? {
        let db = Arc::new(db);
        db.maintain(clock()).await.map_err(|e| format!("telemetry database: {e}"))?;
        app = app.with_telemetry_db(db.clone());
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(3_600)).await;
                if let Err(e) = db.maintain(clock()).await {
                    tracing::warn!(error = %e, "telemetry database upkeep");
                }
            }
        });
    }
    let app = Arc::new(app);
    let tls = match &config.tls {
        Some(files) => {
            let cert = server::tls::ReloadingCert::load(&files.cert_chain, &files.private_key)?;
            cert.watch();
            Some(cert.server_config()?)
        }
        None => None,
    };
    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .map_err(|e| format!("cannot listen on {}: {e}", config.listen))?;
    eprintln!(
        "seal-control: listening on {} ({})",
        config.listen,
        if tls.is_some() { "TLS" } else { "plain HTTP, expects a TLS-terminating proxy" }
    );
    server::serve(listener, app, tls).await.map_err(|e| e.to_string())
}

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let (path, import) = match (args.next().as_deref(), args.next(), args.next().as_deref(), args.next()) {
        (Some("--config"), Some(path), None, None) => (path, false),
        (Some("--config"), Some(path), Some("import-telemetry"), None) => (path, true),
        _ => {
            eprintln!("usage: seal-control --config FILE [import-telemetry]");
            std::process::exit(2);
        }
    };
    let config = Config::load(std::path::Path::new(&path)).unwrap_or_else(|e| {
        eprintln!("seal-control: {e}");
        std::process::exit(2);
    });
    let result = if import { import_telemetry(config).await } else { run(config).await };
    if let Err(e) = result {
        eprintln!("seal-control: {e}");
        std::process::exit(1);
    }
}
