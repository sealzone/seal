//! `seal-registrar`, configured from the environment:
//!
//! | Variable | Meaning |
//! | --- | --- |
//! | `SEAL_REGISTRAR_LISTEN` | Address to serve on, default `127.0.0.1:8444` |
//! | `SEAL_REGISTRAR_DATA` | Directory for the ledger (`ledger.jsonl`) |
//! | `SEAL_REGISTRAR_SEED` | The signing key's 32-byte seed, 64 hex digits |
//! | `SEAL_REGISTRAR_API_TOKEN` | What the console sends as `Authorization: Bearer`, at least 16 characters |
//! | `SEAL_REGISTRAR_LOG_URL` | The transparency log |
//! | `SEAL_REGISTRAR_CONTROL_URL` | The control plane |
//! | `SEAL_REGISTRAR_CONTROL_WRITE_TOKEN` | The control plane's write token |
//! | `SEAL_PASSKEY_RP_ID` | RP ID passkey admin keys must use, default `seal.zone` |
//! | `SEAL_REGISTRAR_EXTRA_ROOTS` | Sim builds only: a PEM file of test CAs also trusted for the log and control plane |
//!
//! It prints its public key at start: the control plane's `registrar.keys`.
#![forbid(unsafe_code)]

use std::sync::Arc;

use seal_crypto::sign::SigningKey;
use seal_net::{BakedRootsConnector, HttpsClient, TcpDialer};
use seal_registrar::http::{check_url, HttpUpstreams};
use seal_registrar::ledger::Ledger;
use seal_registrar::server::{router, App};
use seal_registrar::{Policy, Registrar};

fn var(k: &str) -> Result<String, String> {
    std::env::var(k).ok().filter(|v| !v.is_empty()).ok_or_else(|| format!("{k} is required"))
}

async fn run() -> Result<(), String> {
    let listen = std::env::var("SEAL_REGISTRAR_LISTEN").unwrap_or_else(|_| "127.0.0.1:8444".into());
    let data = std::path::PathBuf::from(var("SEAL_REGISTRAR_DATA")?);
    let seed: [u8; 32] = hex::decode(var("SEAL_REGISTRAR_SEED")?)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or("SEAL_REGISTRAR_SEED: 64 hex digits")?;
    let api_token = var("SEAL_REGISTRAR_API_TOKEN")?;
    if api_token.len() < 16 {
        return Err("SEAL_REGISTRAR_API_TOKEN: at least 16 characters".into());
    }
    let parse = |k: &str| -> Result<url::Url, String> {
        let u = url::Url::parse(&var(k)?).map_err(|e| format!("{k}: {e}"))?;
        check_url(k, &u)?;
        Ok(u)
    };
    let log = parse("SEAL_REGISTRAR_LOG_URL")?;
    let control = parse("SEAL_REGISTRAR_CONTROL_URL")?;
    let control_write_token = var("SEAL_REGISTRAR_CONTROL_WRITE_TOKEN")?;
    let passkey_rp_id = std::env::var("SEAL_PASSKEY_RP_ID").unwrap_or_else(|_| "seal.zone".into());

    std::fs::create_dir_all(&data).map_err(|e| format!("{}: {e}", data.display()))?;
    let ledger = Ledger::open(&data.join("ledger.jsonl")).map_err(|e| format!("ledger: {e}"))?;
    let connector = match std::env::var_os("SEAL_REGISTRAR_EXTRA_ROOTS") {
        #[cfg(feature = "sim")]
        Some(path) => {
            let pem = std::fs::read(&path).map_err(|e| format!("SEAL_REGISTRAR_EXTRA_ROOTS: {e}"))?;
            BakedRootsConnector::with_extra_roots(Arc::new(TcpDialer), &pem)
                .map_err(|e| format!("SEAL_REGISTRAR_EXTRA_ROOTS: {e}"))?
        }
        #[cfg(not(feature = "sim"))]
        Some(_) => return Err("SEAL_REGISTRAR_EXTRA_ROOTS needs a build with the sim feature".into()),
        None => BakedRootsConnector::new(Arc::new(TcpDialer)),
    };
    let https = Arc::new(HttpsClient::new(Arc::new(connector)));
    let upstreams = HttpUpstreams::new(https, &log, &control, control_write_token);
    let key = SigningKey::from_seed(&seed);
    let registrar = Registrar::new(key, Policy { passkey_rp_id }, Box::new(upstreams), ledger);
    println!("seal-registrar: public key {}", registrar.public_key());
    let app = Arc::new(App::new(registrar, &api_token));
    let listener = tokio::net::TcpListener::bind(&listen).await.map_err(|e| format!("{listen}: {e}"))?;
    println!("seal-registrar: listening on {listen}");
    axum::serve(listener, router(app)).await.map_err(|e| e.to_string())
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout()))
        .init();
    if let Err(e) = run().await {
        eprintln!("seal-registrar: {e}");
        std::process::exit(1);
    }
}
