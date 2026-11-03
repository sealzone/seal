//! `seal-nitro-host`: the network of one Nitro enclave replica, run on its parent EC2 instance
//! (crate docs). Logs go to stderr (`SEAL_LOG`, a `tracing` filter, default `info`).
//!
//! ```text
//! seal-nitro-host --tenant <tenant>@<root id> [--enclave-cid 16] [--listen 0.0.0.0:8443]
//!                 [--enclave-port 8443] [--sts-region REGION]
//!                 [--max-connections 1024] [--max-connections-per-source 512]
//!                 [--idle-timeout 350] [--max-tunnels 4096]
//! ```
#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;
use seal_nitro_host::{imds, ingress, sigv4, Config};
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
    #[arg(long, default_value_t = ingress::Limits::default().connections)]
    max_connections: usize,
    /// Inbound connections from one source (an IPv4 address or an IPv6 /64) at once
    #[arg(long, default_value_t = ingress::Limits::default().per_source)]
    max_connections_per_source: usize,
    /// Seconds an inbound connection may go with no byte moving either way
    #[arg(long, default_value_t = ingress::Limits::default().idle.as_secs())]
    idle_timeout: u64,
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
        inbound: ingress::Limits {
            connections: cli.max_connections,
            per_source: cli.max_connections_per_source,
            idle: std::time::Duration::from_secs(cli.idle_timeout),
        },
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
