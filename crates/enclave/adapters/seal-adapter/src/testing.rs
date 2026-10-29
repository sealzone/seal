//! Test doubles for adapter crates (feature `testing`).
//!
//! - `FixedResolver`: maps credential strings to sessions you build with `claims()`.
//! - `TestUpstream`: "connects" by dialing a local plain-TCP address you register
//!   per destination host, and wraps it as an `UpstreamStream` (no TLS in unit tests).
//!
//! Test sessions answer every observation with the resolver's verdict (`Forward` unless
//! `FixedResolver::set_verdict` says otherwise) and keep observations and completions for
//! `FixedResolver::take_observations` and `FixedResolver::take_completions`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use seal_net::{NetError, UpstreamConnector, UpstreamStream};
use seal_proto::policy::{Destination, Protocol, SecretPolicy};
use seal_proto::{AppName, BlobId, ErrorCode, SecretVec, TenantId, UnixTime};
use tokio::sync::Notify;

use crate::{Completion, ConnMeta, Session, SessionResolver};
use seal_integrity::{Observation, Verdict};

/// The adapter's view of a test session, with the secret in clear. (Real session claims
/// carry the blob still sealed; only the runtime opens it.)
pub struct TestClaims {
    pub tenant: TenantId,
    pub app: AppName,
    pub blob_id: BlobId,
    pub policy: SecretPolicy,
    pub secret: SecretVec,
    pub expires_at: UnixTime,
    /// The preamble token of the session's tunnels (`Session::same_session`).
    pub tunnel_token: String,
}

/// The preamble token `claims` gives a session's tunnels.
pub const TUNNEL_TOKEN: &str = "sealtok_preamble";

/// Claims for tests: tenant `acme`, app `checkout`, the given destination and secret.
pub fn claims(destination: Destination, secret: &[u8]) -> TestClaims {
    let app = AppName::new("checkout").unwrap();
    TestClaims {
        tenant: TenantId::new("acme").unwrap(),
        app: app.clone(),
        blob_id: BlobId([0xb7, 0xf2, 0, 0, 0, 0, 0, 1]),
        policy: SecretPolicy::new(&destination.to_string(), [app]).unwrap(),
        secret: SecretVec::new(secret.to_vec()),
        expires_at: u64::MAX,
        tunnel_token: TUNNEL_TOKEN.into(),
    }
}

#[derive(Default)]
pub struct FixedResolver {
    sessions: Mutex<HashMap<String, Arc<dyn Session>>>,
    ended: Arc<Notify>,
    end_reason: Arc<Mutex<Option<ErrorCode>>>,
    completions: Arc<Mutex<Vec<Completion>>>,
    verdict: Arc<Mutex<Option<Verdict>>>,
    observations: Arc<Mutex<Vec<Observed>>>,
}

/// One `Session::observe` call, copied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observed {
    pub protocol: Protocol,
    pub action: String,
    pub content: Vec<u8>,
}

impl FixedResolver {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    pub fn insert(&self, credential: &str, claims: TestClaims) {
        self.sessions.lock().unwrap().insert(
            credential.to_string(),
            Arc::new(TestSession {
                claims,
                ended: self.ended.clone(),
                end_reason: self.end_reason.clone(),
                completions: self.completions.clone(),
                verdict: self.verdict.clone(),
                observations: self.observations.clone(),
            }),
        );
    }
    /// What every session's `observe` returns from now on.
    pub fn set_verdict(&self, verdict: Verdict) {
        *self.verdict.lock().unwrap() = Some(verdict);
    }
    /// Observations every session received so far, oldest first.
    pub fn take_observations(&self) -> Vec<Observed> {
        std::mem::take(&mut self.observations.lock().unwrap())
    }
    /// Ends every session with `reason` (simulates expiry or a grant removal).
    pub fn end_all(&self, reason: ErrorCode) {
        *self.end_reason.lock().unwrap() = Some(reason);
        self.ended.notify_waiters();
    }
    /// Completions every session reported so far, oldest first.
    pub fn take_completions(&self) -> Vec<Completion> {
        std::mem::take(&mut self.completions.lock().unwrap())
    }
}

#[async_trait]
impl SessionResolver for FixedResolver {
    async fn resolve(&self, credential: &str, _meta: &ConnMeta) -> Result<Arc<dyn Session>, ErrorCode> {
        if let Some(reason) = *self.end_reason.lock().unwrap() {
            return Err(reason);
        }
        self.sessions.lock().unwrap().get(credential).cloned().ok_or(ErrorCode::NotAllowed)
    }
}

#[derive(Default)]
pub struct TestUpstream {
    routes: Mutex<HashMap<String, SocketAddr>>,
}

impl TestUpstream {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    /// Connections to `host` (any port) go to `addr` over plain TCP.
    pub fn route(&self, host: &str, addr: SocketAddr) {
        self.routes.lock().unwrap().insert(host.to_string(), addr);
    }
}

#[async_trait]
impl UpstreamConnector for TestUpstream {
    async fn connect(
        &self,
        dest: &Destination,
        pins: &std::collections::BTreeSet<seal_proto::policy::SpkiPin>,
    ) -> Result<UpstreamStream, NetError> {
        let _ = pins;
        let addr = self.routes.lock().unwrap().get(dest.host()).copied().ok_or_else(|| NetError::Connect {
            host: dest.host().to_string(),
            port: dest.port(),
            reason: "no test route".into(),
        })?;
        let s = tokio::net::TcpStream::connect(addr).await.map_err(|e| NetError::Connect {
            host: dest.host().to_string(),
            port: dest.port(),
            reason: e.to_string(),
        })?;
        Ok(UpstreamStream::from_test_stream(Box::new(s)))
    }
}

struct TestSession {
    claims: TestClaims,
    ended: Arc<Notify>,
    end_reason: Arc<Mutex<Option<ErrorCode>>>,
    completions: Arc<Mutex<Vec<Completion>>>,
    verdict: Arc<Mutex<Option<Verdict>>>,
    observations: Arc<Mutex<Vec<Observed>>>,
}
#[async_trait]
impl Session for TestSession {
    fn tenant(&self) -> &TenantId {
        &self.claims.tenant
    }
    fn app(&self) -> &AppName {
        &self.claims.app
    }
    fn blob_id(&self) -> BlobId {
        self.claims.blob_id
    }
    fn policy(&self) -> &SecretPolicy {
        &self.claims.policy
    }
    fn expires_at(&self) -> UnixTime {
        self.claims.expires_at
    }
    fn secret(&self) -> &[u8] {
        self.claims.secret.expose()
    }
    fn same_session(&self, tunnel: &seal_proto::tunnel::TunnelConnect) -> bool {
        tunnel.token.expose() == self.claims.tunnel_token
    }
    /// Records the observation and returns the resolver's verdict (`Forward` by default).
    fn observe(&self, observation: &Observation<'_>) -> Verdict {
        self.observations.lock().unwrap().push(Observed {
            protocol: observation.protocol,
            action: observation.action.to_string(),
            content: observation.content.to_vec(),
        });
        self.verdict.lock().unwrap().unwrap_or(Verdict::Forward)
    }
    fn complete(&self, completion: Completion) {
        self.completions.lock().unwrap().push(completion);
    }
    async fn ended(&self) -> ErrorCode {
        loop {
            let notified = self.ended.notified();
            let reason = *self.end_reason.lock().unwrap();
            if let Some(reason) = reason {
                return reason;
            }
            notified.await;
        }
    }
}
