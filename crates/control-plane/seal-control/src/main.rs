//! The control plane server. The API is documented on the library (`seal_control`).
//!
//! ```text
//! seal-control --config FILE
//! ```
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
    let app = Arc::new(server::App::new(settings, store, Arc::new(upstreams), server::system_clock())?);
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
    let path = match (args.next().as_deref(), args.next(), args.next()) {
        (Some("--config"), Some(path), None) => path,
        _ => {
            eprintln!("usage: seal-control --config FILE");
            std::process::exit(2);
        }
    };
    let config = Config::load(std::path::Path::new(&path)).unwrap_or_else(|e| {
        eprintln!("seal-control: {e}");
        std::process::exit(2);
    });
    if let Err(e) = run(config).await {
        eprintln!("seal-control: {e}");
        std::process::exit(1);
    }
}
