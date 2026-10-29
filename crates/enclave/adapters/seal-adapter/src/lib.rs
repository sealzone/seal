//! The adapter contract.
//!
//! The enclave core owns: listening, inbound TLS (with the attested key), the tunnel
//! preamble, token crypto, session lifetime, identity, integrity and telemetry. An adapter
//! owns exactly one wire protocol, spoken by the app through its SDK tunnel:
//!
//! 1. find the app's local key in its protocol's credential slot (HTTP header, Postgres
//!    password, Redis AUTH/HELLO, ClickHouse Hello password) with
//!    `seal_proto::tunnel::find_local_key`;
//! 2. `ctx.resolver.resolve(credential, &meta)` → `Session`, or an `ErrorCode`
//!    reported in the protocol's own error format;
//! 3. `ctx.upstream.connect(policy.destination(), policy.pins())` (TLS only, by type)
//!    and authenticate with `session.secret()` exactly as the policy says, as the
//!    destination's user and database: whatever the client asked for in its own startup or
//!    handshake is replaced, never forwarded;
//! 4. relay traffic, enforcing per-request policy where the protocol allows,
//!    passing each request to `session.observe` and obeying its `Verdict`,
//!    reporting how it ended with `session.complete`,
//!    and stop when `session.ended()` fires;
//! 5. never let the secret reach the client (`scrub`), never log it, never
//!    put upstream text into a `Completion` or an error.
//!
//! What adapters cannot do: stop a session from using everything the credential allows,
//! including minting a credential of its own (`ALTER ROLE … PASSWORD`, `ACL SETUSER` inside
//! `EVAL`, an API's key-creation endpoint). Command filters are best effort against dynamic
//! SQL and scripts. The control is least privilege at the upstream, plus `HttpRules` for HTTP.
//!
//! Adapters depend on this crate, `seal-net` and `seal-integrity` (re-exported) and `seal-proto`
//! only: never on the enclave, crypto, authz or platform crates.
#![forbid(unsafe_code)]

use std::sync::Arc;

use async_trait::async_trait;
use seal_proto::policy::{Protocol, SecretPolicy};
use seal_proto::tunnel::TunnelConnect;
use seal_proto::{AppName, BlobId, ErrorCode, TenantId, UnixTime};

pub use seal_integrity::{Completion, Observation, Outcome, UpstreamErrorKind, Verdict};
pub use seal_net::{BoxStream, UpstreamConnector, UpstreamStream};

pub mod policy;
pub mod scrub;
#[cfg(feature = "testing")]
pub mod testing;

/// Read-only adapter view. Implementations and the resolver are trusted enclave components.
/// The private runtime implementation owns claims and decides when a session ends.
#[async_trait]
pub trait Session: Send + Sync {
    fn tenant(&self) -> &TenantId;
    fn app(&self) -> &AppName;
    fn blob_id(&self) -> BlobId;
    fn policy(&self) -> &SecretPolicy;
    /// Current expiry. Moves forward when the SDK extends the session (`TunnelPreamble::Extend`).
    fn expires_at(&self) -> UnixTime;
    /// Only for upstream authentication and response scrubbing.
    fn secret(&self) -> &[u8];
    /// One request, before it is forwarded, for the integrity detectors. The adapter must obey the verdict.
    /// The runtime attributes the observation to this session's identity.
    fn observe(&self, observation: &seal_integrity::Observation<'_>) -> seal_integrity::Verdict;
    /// How the request ended. The runtime turns it into the telemetry entry (adding time,
    /// identity, app, blob and connection) and runs completion detectors.
    fn complete(&self, completion: Completion);
    /// Resolves with the reason once this session must end: `expires_at` reached, the caller
    /// no longer granted, the tenant key version retired, the caller suspended,
    /// or the session ended early (`SessionEnd`, on any replica). The runtime rechecks live
    /// sessions whenever the tenant's verified state changes, so this also ends connections
    /// that are already established.
    async fn ended(&self) -> ErrorCode;
}

/// Facts about an inbound connection, established by the core before the adapter runs.
#[derive(Debug)]
pub struct ConnMeta {
    pub connection_id: u64,
    pub protocol: Protocol,
    /// The TCP peer. Host-asserted: the host controls the network, so it authorizes nothing
    /// on its own; it is checked only against the apps' network rules
    /// (`TenantState::app_networks`), which guard against credentials used from elsewhere,
    /// not against the host.
    pub peer: Option<std::net::SocketAddr>,
    /// The tunnel's `Connect` preamble.
    pub tunnel: TunnelConnect,
}

#[async_trait]
pub trait SessionResolver: Send + Sync {
    /// Local key (as found by `find_local_key`) → session: `SHA-256(credential)` must equal
    /// `meta.tunnel.local_key_sha256`, and the preamble's token is then redeemed. Then checks expiry, tenant key version, service key version, and that the caller is
    /// still granted. Errors are safe to show the client.
    async fn resolve(&self, credential: &str, meta: &ConnMeta) -> Result<Arc<dyn Session>, ErrorCode>;
}

#[derive(Clone)]
pub struct AdapterCtx {
    pub resolver: Arc<dyn SessionResolver>,
    pub upstream: Arc<dyn UpstreamConnector>,
}

#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    #[error("client protocol error: {0}")]
    Client(&'static str),
    #[error("upstream: {0:?}")]
    Upstream(UpstreamErrorKind),
    #[error("denied: {0:?}")]
    Denied(ErrorCode),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl AdapterError {
    /// The public code (`Client` → `BadRequest`, `Upstream` and `Io` → `Unavailable`).
    pub fn code(&self) -> ErrorCode {
        match self {
            AdapterError::Client(_) => ErrorCode::BadRequest,
            AdapterError::Upstream(_) | AdapterError::Io(_) => ErrorCode::Unavailable,
            AdapterError::Denied(code) => *code,
        }
    }
}

/// One wire protocol. `serve` handles one inbound connection (already TLS-
/// terminated, preamble already consumed by the core, and the preamble's session already
/// rechecked: live, granted, from inside the app's networks) until either side closes.
#[async_trait]
pub trait Adapter: Send + Sync {
    fn protocol(&self) -> Protocol;
    async fn serve(&self, inbound: BoxStream, meta: ConnMeta, ctx: AdapterCtx) -> Result<(), AdapterError>;
}
