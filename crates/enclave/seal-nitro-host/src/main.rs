//! `seal-nitro-host`: the network of one Nitro enclave replica, run on its parent EC2 instance
//! (crate docs). Logs go to stderr (`SEAL_LOG`, a `tracing` filter, default `info`).
//!
//! ```text
//! seal-nitro-host --tenant <tenant>@<root id> [--enclave-cid 16] [--listen 0.0.0.0:8443]
//!                 [--enclave-port 8443] [--sts-region REGION]
//!                 [--max-connections 1024] [--max-tunnels 4096]
//! ```
#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;
use seal_nitro_host::{imds, sigv4, Config};
use seal_proto::TenantPin;

#[derive(Parser)]
#[command(name = "seal-nitro-host", version, about = "The parent instance's side of a Seal enclave on AWS Nitro")]
struct Cli {
    /// The replica's tenant pin, `<tenant>@<root id>`
    #[arg(long, env = "SEAL_TENANT")]
    tenant: TenantPin,
    /// The enclave's CID (`nitro-cli run-enclave --enclave-cid`); only it is served
    #[arg(long, default_value_t = seal_nitro_host::DEFAULT_ENCLAVE_CID)]
    enclave_cid: u32,
    /// Where clients reach the enclave on this instance
    #[arg(long, default_value_t = SocketAddr::from(([0, 0, 0, 0], seal_nitro_host::DEFAULT_PORT)))]
    listen: SocketAddr,
    /// The enclave's vsock port: the release's `listen` port
    #[arg(long, default_value_t = u32::from(seal_nitro_host::DEFAULT_PORT))]
    enclave_port: u32,
    /// Presign for this region's STS endpoint instead of the global `sts.amazonaws.com` (needed
    /// outside the `aws` partition, and where the global endpoint is turned off)
    #[arg(long)]
    sts_region: Option<String>,
    /// Inbound connections at once
    #[arg(long, default_value_t = seal_nitro_host::DEFAULT_MAX_CONNECTIONS)]
    max_connections: usize,
    /// Egress tunnels at once
    #[arg(long, default_value_t = seal_nitro_host::DEFAULT_MAX_TUNNELS)]
    max_tunnels: usize,
}

#[tokio::main]
async fn main() {
    let filter = tracing_subscriber::EnvFilter::try_from_env("SEAL_LOG").unwrap_or_else(|_| "info".into());
    tracing_subscriber::fmt().with_env_filter(filter).with_writer(std::io::stderr).init();
    let cli = Cli::parse();
    let sts = match cli.sts_region.as_deref().map(sigv4::Sts::regional) {
        None => sigv4::Sts::global(),
        Some(Ok(sts)) => sts,
        Some(Err(e)) => {
            tracing::error!("--sts-region: {e}");
            std::process::exit(2);
        }
    };
    let config = Config {
        tenant: cli.tenant,
        enclave_cid: cli.enclave_cid,
        enclave_port: cli.enclave_port,
        listen: cli.listen,
        sts,
        max_connections: cli.max_connections,
        max_tunnels: cli.max_tunnels,
    };
    let served = tokio::select! {
        served = seal_nitro_host::run(config, Arc::new(imds::Imds::default())) => served,
        _ = shutdown_signal() => Ok(()),
    };
    if let Err(e) = served {
        tracing::error!("{e:#}");
        std::process::exit(1);
    }
}

async fn shutdown_signal() {
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
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate => {}
    }
}
