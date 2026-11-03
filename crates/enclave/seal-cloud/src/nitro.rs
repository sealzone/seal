//! AWS Nitro Enclaves: everything goes through the parent instance over vsock
//! (`seal_proto::nitro` has the ports), and time comes from the hypervisor.
//!
//! - **Tenant pin**: the `tenant` of the first `ParentMessage` the parent sends
//!   (`PARENT_CID`:`PARENT_PORT`). `Cloud::detect` waits up to `PARENT_WAIT` for the parent to
//!   answer, since the parent's host proxy may start after the enclave. The pin is unattested,
//!   as on every cloud, and only narrows what the enclave serves.
//! - **Deployment proof**: the `deployment` of a fresh `ParentMessage`: an STS
//!   `GetCallerIdentity` the parent presigned with its instance role (`IdentityProof::AwsSigV4`),
//!   which `seal_authz::DeploymentVerifier` replays to STS. Asked for only when the tenant's
//!   deployments name an AWS role, and refused if the message names another tenant than the
//!   pin, or carries another kind of proof.
//! - **Network**: no interface. `ParentDialer` opens a vsock stream to the parent's egress
//!   port and asks for `CONNECT host:port`; past the parent's `200`, the stream is the
//!   destination's (TLS verified above, as on every cloud). The parent resolves names. The
//!   enclave's one port is a vsock listener on the `listen` port number (`crate::Listen`), and
//!   the parent names each client in a PROXY v2 header.
//! - **Clock**: `seal_tee::nitro::NitroClock`, the NSM's signed timestamp. No Roughtime, no UDP.

use std::collections::BTreeSet;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use seal_authz::DeploymentProof;
use seal_net::{BoxStream, Dialer, NetError};
use seal_proto::identity::{IdentityMatcher, IdentityProof};
use seal_proto::nitro::{ParentMessage, EGRESS_PORT, MAX_CONNECT_HEAD, MAX_PARENT_MESSAGE, PARENT_CID, PARENT_PORT};
use seal_proto::TenantPin;
use seal_tee::{Attestor, Clock};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::CloudError;

#[cfg(test)]
mod tests;

/// How long `Cloud::detect` waits for the parent's first message.
pub const PARENT_WAIT: Duration = Duration::from_secs(60);
/// Between tries while waiting.
const PARENT_RETRY: Duration = Duration::from_secs(1);
/// One vsock connection to the parent.
const VSOCK_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Reading one `ParentMessage` (the parent asks IMDS for credentials and presigns).
const MESSAGE_TIMEOUT: Duration = Duration::from_secs(10);
/// A whole dial: the vsock connection, the request, and the parent's own connection (10 s).
const DIAL_TIMEOUT: Duration = Duration::from_secs(15);

/// How the enclave reaches its parent: vsock to `PARENT_CID` (`Vsock`). A trait so tests can
/// carry the same bytes over something else.
#[async_trait]
pub trait ParentLink: Send + Sync {
    /// A stream to the parent's `port`.
    async fn open(&self, port: u32) -> io::Result<BoxStream>;
}

/// vsock to the parent instance.
pub struct Vsock;

#[async_trait]
impl ParentLink for Vsock {
    async fn open(&self, port: u32) -> io::Result<BoxStream> {
        let stream = seal_net::vsock::connect(PARENT_CID, port, VSOCK_CONNECT_TIMEOUT).await?;
        Ok(Box::new(stream))
    }
}

/// A Nitro enclave.
pub struct Nitro {
    pub(crate) attestor: Attestor,
    pub(crate) clock: Clock,
    pub(crate) pin: TenantPin,
    pub(crate) dialer: Arc<dyn Dialer>,
    parent: Arc<dyn ParentLink>,
}

impl Nitro {
    /// Around the attestor `Attestor::detect` chose: `NitroClock`, vsock to the parent, the pin
    /// from its first message.
    pub(crate) async fn from_parent(attestor: seal_tee::nitro::NitroAttestor) -> Result<Self, CloudError> {
        let clock = seal_tee::nitro::NitroClock::new()?;
        Self::with(Attestor::AwsNitro(attestor), Clock::Nitro(clock), Arc::new(Vsock), PARENT_WAIT).await
    }

    /// With the parent behind `parent`, waiting up to `wait` for its first message.
    pub async fn with(
        attestor: Attestor,
        clock: Clock,
        parent: Arc<dyn ParentLink>,
        wait: Duration,
    ) -> Result<Self, CloudError> {
        let first = first_message(&*parent, wait).await?;
        Ok(Self { attestor, clock, pin: first.tenant, dialer: Arc::new(ParentDialer::new(parent.clone())), parent })
    }

    /// A fresh proof from the parent (module docs).
    pub(crate) async fn deployment(
        &self,
        deployments: &BTreeSet<IdentityMatcher>,
    ) -> Result<DeploymentProof, CloudError> {
        if !deployments.iter().any(|m| matches!(m, IdentityMatcher::AwsRole { .. })) {
            return Err(CloudError::Deployment("the tenant's deployments name no AWS role".into()));
        }
        let message = message(&*self.parent).await.map_err(CloudError::Deployment)?;
        if message.tenant != self.pin {
            return Err(CloudError::Deployment(format!(
                "the parent now names tenant {}, not the pin {}",
                message.tenant, self.pin
            )));
        }
        match message.deployment {
            proof @ IdentityProof::AwsSigV4 { .. } => Ok(DeploymentProof::Proof(proof)),
            _ => Err(CloudError::Deployment("the parent's proof is not a presigned STS request".into())),
        }
    }
}

/// The parent's first message, tried every `PARENT_RETRY` for up to `wait`.
pub(crate) async fn first_message(parent: &dyn ParentLink, wait: Duration) -> Result<ParentMessage, CloudError> {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        match message(parent).await {
            Ok(message) => return Ok(message),
            Err(e) if tokio::time::Instant::now() + PARENT_RETRY > deadline => {
                return Err(CloudError::Pin(format!("no message from the parent within {} s: {e}", wait.as_secs())))
            }
            Err(e) => tracing::debug!(error = %e, "no message from the parent yet; retrying"),
        }
        tokio::time::sleep(PARENT_RETRY).await;
    }
}

/// One `ParentMessage`: a connection to `PARENT_PORT`, read to its end.
pub(crate) async fn message(parent: &dyn ParentLink) -> Result<ParentMessage, String> {
    let read = async {
        let stream = parent.open(PARENT_PORT).await.map_err(|e| format!("connect to the parent: {e}"))?;
        let mut text = Vec::new();
        stream
            .take(MAX_PARENT_MESSAGE as u64 + 1)
            .read_to_end(&mut text)
            .await
            .map_err(|e| format!("read the parent's message: {e}"))?;
        if text.len() > MAX_PARENT_MESSAGE {
            return Err("the parent's message is too long".to_string());
        }
        serde_json::from_slice::<ParentMessage>(&text).map_err(|e| format!("the parent's message: {e}"))
    };
    tokio::time::timeout(MESSAGE_TIMEOUT, read).await.map_err(|_| "the parent's message timed out".to_string())?
}

/// Every outbound stream: `CONNECT host:port` through the parent's egress port.
pub struct ParentDialer {
    parent: Arc<dyn ParentLink>,
}

impl ParentDialer {
    pub fn new(parent: Arc<dyn ParentLink>) -> Self {
        Self { parent }
    }
}

#[async_trait]
impl Dialer for ParentDialer {
    async fn dial(&self, host: &str, port: u16) -> Result<BoxStream, NetError> {
        let err = |reason: String| NetError::Connect { host: host.to_string(), port, reason };
        let request = connect_request(host, port).map_err(err)?;
        let dial = async {
            let mut stream = self.parent.open(EGRESS_PORT).await.map_err(|e| format!("the parent's proxy: {e}"))?;
            stream.write_all(request.as_bytes()).await.map_err(|e| format!("the parent's proxy: {e}"))?;
            read_connect_response(&mut stream).await?;
            Ok::<_, String>(stream)
        };
        tokio::time::timeout(DIAL_TIMEOUT, dial)
            .await
            .map_err(|_| err(format!("timed out after {} s", DIAL_TIMEOUT.as_secs())))?
            .map_err(err)
    }
}

/// `CONNECT host:port HTTP/1.1` with its `Host`, for a host name or IP address (IPv6 with or
/// without brackets). Anything that is not one (spaces, line breaks, `@`, `/`) is refused before
/// the parent sees it.
pub(crate) fn connect_request(host: &str, port: u16) -> Result<String, String> {
    let authority = authority(host, port).ok_or_else(|| "not a host name or address".to_string())?;
    Ok(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n"))
}

/// `host:port`, or `[v6]:port`.
pub(crate) fn authority(host: &str, port: u16) -> Option<String> {
    if port == 0 {
        return None;
    }
    let bare = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    if let Ok(v6) = bare.parse::<std::net::Ipv6Addr>() {
        return Some(format!("[{v6}]:{port}"));
    }
    let name_char = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_');
    let ok = !host.is_empty() && host.len() <= 253 && host.bytes().all(name_char);
    ok.then(|| format!("{host}:{port}"))
}

/// Reads the parent's answer to `CONNECT` up to its blank line, exactly, so the stream is left
/// at the destination's first byte: `Ok` for a 2xx, the status otherwise.
pub(crate) async fn read_connect_response<S: AsyncRead + AsyncWrite + Unpin + ?Sized>(
    stream: &mut S,
) -> Result<(), String> {
    let mut head = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_CONNECT_HEAD {
            return Err("the parent's proxy answered with too long a header".into());
        }
        match stream.read(&mut byte).await {
            Ok(0) => return Err("the parent's proxy closed the connection".into()),
            Ok(_) => head.push(byte[0]),
            Err(e) => return Err(format!("the parent's proxy: {e}")),
        }
    }
    let status_line = head.split(|b| *b == b'\r').next().unwrap_or_default();
    let status_line = std::str::from_utf8(status_line).map_err(|_| "the parent's proxy answered garbage")?;
    let mut parts = status_line.splitn(3, ' ');
    match (parts.next(), parts.next()) {
        (Some("HTTP/1.1" | "HTTP/1.0"), Some(code)) if code.len() == 3 && code.bytes().all(|b| b.is_ascii_digit()) => {
            if code.starts_with('2') {
                Ok(())
            } else {
                Err(format!("the parent's proxy answered {code}"))
            }
        }
        _ => Err("the parent's proxy answered garbage".into()),
    }
}
