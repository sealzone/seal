//! The parent instance's side of a Nitro enclave replica: the enclave has no network
//! interface, so this process, on the EC2 instance that runs it, is its network
//! (`seal_proto::nitro` has the protocol):
//!
//! | Serves | On | What |
//! | --- | --- | --- |
//! | `parent` | vsock `PARENT_PORT` | one `ParentMessage` per connection: the tenant pin and a fresh deployment proof, a `GetCallerIdentity` presigned with the instance role (IMDSv2) |
//! | `egress` | vsock `EGRESS_PORT` | `CONNECT host:port` to anything a NAT gateway would reach, except the instance's own addresses |
//! | `ingress` | TCP `listen` (`0.0.0.0:8443`) | each client relayed to the enclave's vsock port, after a PROXY v2 header naming it |
//!
//! Only connections from the enclave's CID are served on the vsock ports.
//!
//! The parent is untrusted, like any host, and nothing here is trusted by the enclave: the pin
//! only narrows what the enclave serves, the proof counts once STS answers it, every stream is
//! the enclave's own TLS (verified at the NSM's time, which the parent cannot set), and the
//! client addresses it names are what the network would show on any other cloud. What it can
//! do is what any host can: refuse service, or run the enclave for another tenant, which then
//! holds no keys unless that tenant lists the instance role as a deployment.
#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use seal_net::vsock::{VsockListener, CID_ANY};
use seal_proto::nitro::{EGRESS_PORT, PARENT_PORT};
use seal_proto::TenantPin;

pub mod egress;
pub mod imds;
pub mod ingress;
pub mod parent;
pub mod sigv4;

#[cfg(test)]
mod tests;

/// The enclave CID `seal deploy aws` runs enclaves with (`nitro-cli run-enclave --enclave-cid`).
pub const DEFAULT_ENCLAVE_CID: u32 = 16;
/// The release's `listen` port.
pub const DEFAULT_PORT: u16 = 8443;
/// Egress tunnels at once.
pub const DEFAULT_MAX_TUNNELS: usize = 4096;

/// Everything the host serves with.
pub struct Config {
    pub tenant: TenantPin,
    pub enclave_cid: u32,
    /// The enclave's vsock port: the release's `listen` port.
    pub enclave_port: u32,
    /// Where clients reach the enclave on the instance.
    pub listen: SocketAddr,
    pub sts: sigv4::Sts,
    pub inbound: ingress::Limits,
    pub max_tunnels: usize,
}

/// Binds every port (failing at once if one cannot be had), then serves until one server
/// stops, which none does on its own.
pub async fn run(config: Config, credentials: Arc<dyn parent::CredentialSource>) -> anyhow::Result<()> {
    let message_port =
        VsockListener::bind(CID_ANY, PARENT_PORT).with_context(|| format!("vsock port {PARENT_PORT}"))?;
    let egress_port = VsockListener::bind(CID_ANY, EGRESS_PORT).with_context(|| format!("vsock port {EGRESS_PORT}"))?;
    let inbound = tokio::net::TcpListener::bind(config.listen).await.with_context(|| format!("{}", config.listen))?;
    tracing::info!(
        tenant = %config.tenant,
        enclave_cid = config.enclave_cid,
        listen = %config.listen,
        enclave_port = config.enclave_port,
        sts = %config.sts.host,
        "serving the enclave"
    );
    let messages = Arc::new(parent::Messages { tenant: config.tenant, sts: config.sts, credentials });
    tokio::select! {
        _ = parent::serve(message_port, config.enclave_cid, messages) => {}
        _ = egress::serve(egress_port, config.enclave_cid, config.max_tunnels, egress::Policy::default()) => {}
        _ = ingress::serve(inbound, config.enclave_cid, config.enclave_port, config.inbound) => {}
    }
    anyhow::bail!("a server stopped")
}
