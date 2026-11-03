//! The cloud an enclave replica runs on. Everything that differs between clouds for an
//! enclave lives here, behind one enum, so the runtime (`seal-enclave`) reads the same on
//! every cloud: detect the cloud, read the pin, prove the deployment, dial, listen.
//!
//! | Cloud | Tenant pin | Deployment identity | Network |
//! |-------|------------|---------------------|---------|
//! | Azure ACI | `SEAL_TENANT`, allowed by an anchored re2 rule in the container policy | the group's managed-identity token (IMDS) | TCP and UDP; NAT gateway |
//! | AWS Nitro | the first message the parent sends over vsock (`seal_proto::nitro::ParentMessage`) | `GetCallerIdentity` presigned by the parent with its instance role, in a fresh message | vsock to the parent's egress proxy (`CONNECT host:port`), and the parent forwards the enclave's port in over vsock; time from the hypervisor (`NitroClock`) |
//! | GCP Confidential Space | `tee-env-SEAL_TENANT`, the only override the launch policy allows | project and service account in the enclave's own attestation | TCP and UDP; Cloud NAT |
//!
//! The pin is unattested on every cloud; it can only narrow what the enclave serves.
#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;

use seal_authz::DeploymentProof;
use seal_proto::identity::IdentityMatcher;
use seal_proto::TenantPin;
use seal_tee::{Attestor, Clock};

pub mod azure;
pub mod gcp;
pub mod nitro;
#[cfg(feature = "sim")]
pub mod sim;

#[derive(Debug, thiserror::Error)]
pub enum CloudError {
    #[error("tee: {0}")]
    Tee(#[from] seal_tee::TeeError),
    #[error("tenant pin: {0}")]
    Pin(String),
    #[error("deployment identity unavailable: {0}")]
    Deployment(String),
}

impl CloudError {
    /// The public code: the cloud could not supply what the enclave needs.
    pub fn code(&self) -> seal_proto::ErrorCode {
        seal_proto::ErrorCode::Unavailable
    }
}

// One per process; every variant holds an attestor, a clock and a dialer.
#[allow(clippy::large_enum_variant)]
pub enum Cloud {
    AzureSnpAci(azure::Aci),
    AwsNitro(nitro::Nitro),
    GcpConfidentialSpace(gcp::ConfidentialSpace),
    #[cfg(feature = "sim")]
    Sim(sim::Sim),
}

impl Cloud {
    /// From `Attestor::detect`: the cloud whose TEE device is present, `NotInTee` (as
    /// `CloudError::Tee`) when none is. On AWS Nitro it waits for the parent's first message
    /// (`nitro::PARENT_WAIT`). A `sim` build with `SEAL_SIM=1` gets the simulator cloud,
    /// configured from the environment (`sim` module).
    pub async fn detect() -> Result<Self, CloudError> {
        match Attestor::detect()? {
            Attestor::AzureSnpAci(attestor) => Ok(Cloud::AzureSnpAci(azure::Aci::from_env(attestor)?)),
            Attestor::AwsNitro(attestor) => Ok(Cloud::AwsNitro(nitro::Nitro::from_parent(attestor).await?)),
            Attestor::GcpConfidentialSpace(attestor) => {
                Ok(Cloud::GcpConfidentialSpace(gcp::ConfidentialSpace::from_env(attestor)?))
            }
            #[cfg(feature = "sim")]
            Attestor::Sim(attestor) => Ok(Cloud::Sim(sim::Sim::from_env(attestor)?)),
        }
    }
    pub fn attestor(&self) -> &Attestor {
        match self {
            Cloud::AzureSnpAci(a) => &a.attestor,
            Cloud::AwsNitro(n) => &n.attestor,
            Cloud::GcpConfidentialSpace(c) => &c.attestor,
            #[cfg(feature = "sim")]
            Cloud::Sim(s) => &s.attestor,
        }
    }
    pub fn clock(&self) -> &Clock {
        match self {
            Cloud::AzureSnpAci(a) => &a.clock,
            Cloud::AwsNitro(n) => &n.clock,
            Cloud::GcpConfidentialSpace(c) => &c.clock,
            #[cfg(feature = "sim")]
            Cloud::Sim(s) => &s.clock,
        }
    }
    /// Where every outbound stream starts (upstreams, guardian, control plane, OIDC, STS).
    pub fn dialer(&self) -> Arc<dyn seal_net::Dialer> {
        match self {
            Cloud::AzureSnpAci(a) => a.dialer.clone(),
            Cloud::AwsNitro(n) => n.dialer.clone(),
            Cloud::GcpConfidentialSpace(c) => c.dialer.clone(),
            #[cfg(feature = "sim")]
            Cloud::Sim(s) => s.dialer.clone(),
        }
    }
    /// `<tenant>@<root id>`, read by `detect`: from `SEAL_TENANT`, or on Nitro from the
    /// parent's first message.
    pub fn tenant_pin(&self) -> &TenantPin {
        match self {
            Cloud::AzureSnpAci(a) => &a.pin,
            Cloud::AwsNitro(n) => &n.pin,
            Cloud::GcpConfidentialSpace(c) => &c.pin,
            #[cfg(feature = "sim")]
            Cloud::Sim(s) => &s.pin,
        }
    }
    /// Who deployed this replica, checked against `deployments` (the verified `TenantState::deployments`) before
    /// any key request (`seal_authz::DeploymentVerifier`). Azure takes its token audience from them; Nitro asks
    /// its parent only when they name an AWS role.
    pub async fn deployment(&self, deployments: &BTreeSet<IdentityMatcher>) -> Result<DeploymentProof, CloudError> {
        match self {
            Cloud::AzureSnpAci(a) => a.deployment(deployments).await,
            Cloud::AwsNitro(n) => n.deployment(deployments).await,
            Cloud::GcpConfidentialSpace(c) => c.deployment().await,
            #[cfg(feature = "sim")]
            Cloud::Sim(s) => Ok(s.deployment()),
        }
    }
    /// Where the enclave's one port listens, for the release's `listen` address: that TCP address,
    /// or on Nitro a vsock port of the same number, which the parent forwards the instance's
    /// port to.
    pub fn listen(&self, listen: SocketAddr) -> Listen {
        match self {
            Cloud::AwsNitro(_) => Listen::Parent { port: u32::from(listen.port()) },
            _ => Listen::Tcp(listen),
        }
    }
}

/// Where the enclave's one port listens (`Cloud::listen`). Taken before the cloud moves into
/// the runtime, bound once it has booted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Listen {
    Tcp(SocketAddr),
    /// A vsock port, for connections from the Nitro parent (`seal_proto::nitro::PARENT_CID`).
    Parent {
        port: u32,
    },
}

impl std::fmt::Display for Listen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Listen::Tcp(addr) => write!(f, "{addr}"),
            Listen::Parent { port } => write!(f, "vsock port {port}"),
        }
    }
}

impl Listen {
    pub async fn bind(self) -> std::io::Result<Listener> {
        match self {
            Listen::Tcp(addr) => Ok(Listener::Tcp(tokio::net::TcpListener::bind(addr).await?)),
            Listen::Parent { port } => {
                Ok(Listener::Parent(seal_net::vsock::VsockListener::bind(seal_net::vsock::CID_ANY, port)?))
            }
        }
    }
}

/// The enclave's one port, bound.
pub enum Listener {
    Tcp(tokio::net::TcpListener),
    /// vsock, accepting the Nitro parent only. Its connections are vsock streams handed to
    /// tokio as `TcpStream`s (`seal_net::vsock`).
    Parent(seal_net::vsock::VsockListener),
    /// Feature `testing`: TCP connections taken as the Nitro parent's (`names_clients`).
    #[cfg(feature = "testing")]
    Forwarded(tokio::net::TcpListener),
}

impl From<tokio::net::TcpListener> for Listener {
    fn from(listener: tokio::net::TcpListener) -> Self {
        Listener::Tcp(listener)
    }
}

/// The address a vsock connection stands for until its PROXY header names the client.
pub const NO_ADDRESS: SocketAddr = SocketAddr::V4(std::net::SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0));

impl Listener {
    /// The next connection and its address: the TCP peer's, or for the parent `NO_ADDRESS`.
    /// A vsock connection from any CID but the parent's is closed and the next one taken.
    pub async fn accept(&self) -> std::io::Result<(tokio::net::TcpStream, SocketAddr)> {
        match self {
            Listener::Tcp(listener) => listener.accept().await,
            Listener::Parent(listener) => loop {
                let (stream, cid) = listener.accept().await?;
                if cid == seal_proto::nitro::PARENT_CID {
                    return Ok((stream, NO_ADDRESS));
                }
                tracing::debug!(cid, "connection refused: not from the parent");
            },
            #[cfg(feature = "testing")]
            Listener::Forwarded(listener) => Ok((listener.accept().await?.0, NO_ADDRESS)),
        }
    }

    /// The TCP address listened on, or `NO_ADDRESS` for vsock.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        match self {
            Listener::Tcp(listener) => listener.local_addr(),
            Listener::Parent(_) => Ok(NO_ADDRESS),
            #[cfg(feature = "testing")]
            Listener::Forwarded(listener) => listener.local_addr(),
        }
    }

    /// Whether every connection starts with a PROXY v2 header naming its client, which then
    /// stands for the connection's address: the Nitro parent's forwarder writes one, since the
    /// enclave would otherwise see only the parent. The parent is the network there, as the
    /// host is on every cloud; a connection without a header is refused.
    pub fn names_clients(&self) -> bool {
        match self {
            Listener::Tcp(_) => false,
            Listener::Parent(_) => true,
            #[cfg(feature = "testing")]
            Listener::Forwarded(_) => true,
        }
    }

    /// For logs: the TCP address, or the vsock port.
    pub fn local(&self) -> String {
        match self {
            Listener::Parent(listener) => format!("vsock port {}", listener.port()),
            _ => self.local_addr().map_or_else(|e| e.to_string(), |a| a.to_string()),
        }
    }
}

/// The environment variable every cloud delivers the tenant pin in.
const TENANT_VAR: &str = "SEAL_TENANT";

/// `SEAL_TENANT`'s value as a pin.
fn tenant_pin(value: Option<String>) -> Result<TenantPin, CloudError> {
    value
        .ok_or_else(|| CloudError::Pin(format!("{TENANT_VAR} is not set")))?
        .parse()
        .map_err(|e| CloudError::Pin(format!("{TENANT_VAR}: {e}")))
}

#[cfg(test)]
#[test]
fn the_pin_is_seal_tenant() {
    let pin = format!("acme@{}", "ab".repeat(32));
    assert_eq!(tenant_pin(Some(pin.clone())).unwrap(), pin.parse().unwrap());
    assert!(matches!(tenant_pin(None), Err(CloudError::Pin(e)) if e.contains("not set")));
    for bad in ["acme", "acme@xyz", "", "ACME@abab"] {
        assert!(matches!(tenant_pin(Some(bad.into())), Err(CloudError::Pin(_))), "{bad}");
    }
}

#[cfg(all(test, feature = "sim"))]
mod tests;
