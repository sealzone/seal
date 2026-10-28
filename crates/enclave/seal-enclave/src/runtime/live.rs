//! Live sessions: the runtime's `seal_adapter::Session`, one per resolved connection
//! credential, the registry of them by `session_id`, the resolver adapters use, and the
//! monitor that rechecks every live session when the tenant state changes.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};

use async_trait::async_trait;
use seal_adapter::{Completion, ConnMeta, Observation, Session, SessionResolver, Verdict};
use seal_authz::TenantAuthorizer;
use seal_crypto::blob::OpenedBlob;
use seal_proto::identity::WorkloadIdentity;
use seal_proto::integrity::SignalSource;
use seal_proto::policy::SecretPolicy;
use seal_proto::session::SessionClaims;
use seal_proto::telemetry::TelemetryEvent;
use seal_proto::tunnel::LOCAL_KEY_PREFIX;
use seal_proto::{AppName, BlobId, ErrorCode, TenantId, TrustedTime, UnixTime};
use seal_verify::VerifiedTenant;
use sha2::{Digest, Sha256};
use tokio::sync::watch;

use super::integrity::{stricter, verdict};
use super::{fail, lock, Runtime};
use crate::ServiceError;

/// Live sessions by `session_id`; one entry per connection that resolved a credential.
#[derive(Default)]
pub(crate) struct Registry {
    sessions: Mutex<HashMap<[u8; 16], Vec<Weak<LiveSession>>>>,
}

impl Registry {
    fn insert(&self, session: &Arc<LiveSession>) {
        lock(&self.sessions).entry(session.session_id).or_default().push(Arc::downgrade(session));
    }

    /// The live sessions of `session_id`.
    pub(crate) fn of(&self, session_id: &[u8; 16]) -> Vec<Arc<LiveSession>> {
        let mut sessions = lock(&self.sessions);
        let Some(list) = sessions.get_mut(session_id) else { return Vec::new() };
        list.retain(|w| w.strong_count() > 0);
        let live = list.iter().filter_map(Weak::upgrade).collect();
        if list.is_empty() {
            sessions.remove(session_id);
        }
        live
    }

    /// Every live session; drops the entries of connections that are gone.
    pub(super) fn all(&self) -> Vec<Arc<LiveSession>> {
        let mut sessions = lock(&self.sessions);
        sessions.retain(|_, list| {
            list.retain(|w| w.strong_count() > 0);
            !list.is_empty()
        });
        sessions.values().flatten().filter_map(Weak::upgrade).collect()
    }

    /// Ends every live connection of `session_id` with `reason`.
    pub(crate) fn end(&self, session_id: &[u8; 16], reason: ErrorCode) {
        for session in self.of(session_id) {
            session.end(reason);
        }
    }
}

/// One connection's session. Its claims start as the token's; an `Extend` preamble moves
/// their expiry (and authentication scope) forward. It ends, with the reason `ended`
/// returns, when its expiry passes, when a recheck against the tenant state fails (grant or
/// producer removed, key version retired, suspension, `SessionEnd` from any replica, a stale
/// state, this replica no longer listed), or when this replica ends the
/// session.
pub(crate) struct LiveSession {
    runtime: Arc<Runtime>,
    tenant: TenantId,
    app: AppName,
    session_id: [u8; 16],
    caller: WorkloadIdentity,
    claims: RwLock<SessionClaims>,
    opened: OpenedBlob,
    connection_id: u64,
    expires_at: AtomicU64,
    end: watch::Sender<Option<ErrorCode>>,
}

impl LiveSession {
    fn new(runtime: Arc<Runtime>, claims: SessionClaims, opened: OpenedBlob, connection_id: u64) -> Self {
        Self {
            runtime,
            tenant: claims.tenant.clone(),
            app: claims.app.clone(),
            session_id: claims.session_id,
            caller: claims.caller.clone(),
            expires_at: AtomicU64::new(claims.expires_at),
            claims: RwLock::new(claims),
            opened,
            connection_id,
            end: watch::Sender::new(None),
        }
    }

    /// Ends this connection's session with `reason`; the first reason stays.
    pub(crate) fn end(&self, reason: ErrorCode) {
        self.end.send_if_modified(|current| {
            if current.is_some() {
                return false;
            }
            *current = Some(reason);
            true
        });
    }

    fn ended_with(&self) -> Option<ErrorCode> {
        *self.end.borrow()
    }

    /// Takes the expiry and authentication of `newer`, a token for the same session, caller,
    /// app and blob that expires later. Returns whether it did.
    pub(crate) fn extend(&self, newer: &SessionClaims) -> bool {
        let mut claims = self.claims.write().unwrap_or_else(|e| e.into_inner());
        let same = newer.session_id == claims.session_id
            && newer.caller == claims.caller
            && newer.app == claims.app
            && newer.blob == claims.blob;
        if !same || newer.expires_at <= claims.expires_at || self.ended_with().is_some() {
            return false;
        }
        claims.expires_at = newer.expires_at;
        claims.issued_at = newer.issued_at;
        claims.authentication = newer.authentication.clone();
        self.expires_at.store(newer.expires_at, Ordering::Relaxed);
        drop(claims);
        // Wakes `ended`, which waits for the new expiry from now on.
        self.end.send_modify(|_| {});
        true
    }

    /// The session against `tenant`: the replica still serves sessions, and the claims pass
    /// `TenantAuthorizer::recheck`.
    fn recheck(&self, tenant: &VerifiedTenant, time: &TrustedTime) -> Result<(), ErrorCode> {
        self.runtime.serving(tenant).map_err(|e| e.code)?;
        let claims = self.claims.read().unwrap_or_else(|e| e.into_inner());
        TenantAuthorizer::new(tenant).recheck(&claims, time).map_err(|e| e.code())
    }

    /// What the tenant's policy makes of a detector's finding about this session's caller.
    fn act(&self, detector: &str, finding: seal_integrity::Finding, time: &TrustedTime) -> Verdict {
        let source = SignalSource::Enclave { detector: detector.into() };
        match self.runtime.finding_signal(&self.caller, source, finding, Some(self.blob_id()), time) {
            Some(signal) => verdict(self.runtime.raise_detached(signal, time)),
            None => Verdict::Forward,
        }
    }
}

impl Drop for LiveSession {
    /// The connection ended: the idle exit counts from here.
    fn drop(&mut self) {
        self.runtime.activity.touch();
    }
}

#[async_trait]
impl Session for LiveSession {
    fn tenant(&self) -> &TenantId {
        &self.tenant
    }
    fn app(&self) -> &AppName {
        &self.app
    }
    fn blob_id(&self) -> BlobId {
        self.opened.blob().header.blob_id
    }
    fn policy(&self) -> &SecretPolicy {
        &self.opened.blob().policy
    }
    fn expires_at(&self) -> UnixTime {
        self.expires_at.load(Ordering::Relaxed)
    }
    fn secret(&self) -> &[u8] {
        self.opened.secret()
    }

    /// Rechecks the session against the current state (a failure ends it and refuses the
    /// request), then runs the detectors for the request's protocol; the strictest action
    /// their findings map to wins. `End` also ends the session on every replica.
    fn observe(&self, observation: &Observation<'_>) -> Verdict {
        if let Some(reason) = self.ended_with() {
            return Verdict::Refuse(reason);
        }
        let time = self.runtime.time.estimate();
        let checked = match self.runtime.state.get() {
            Some(tenant) => self.recheck(&tenant, &time),
            None => Err(ErrorCode::Unavailable),
        };
        if let Err(reason) = checked {
            self.end(reason);
            return Verdict::Refuse(reason);
        }
        let mut result = Verdict::Forward;
        for detector in self.runtime.detectors.iter().filter(|d| d.protocols().contains(&observation.protocol)) {
            if let Some(finding) = detector.observe(observation) {
                result = stricter(result, self.act(detector.name(), finding, &time));
            }
        }
        if let Verdict::End(reason) = result {
            self.runtime.close_session_detached(self.session_id, reason, &self.caller, &time);
        }
        result
    }

    /// One `Request` telemetry entry, then the completion detectors (their findings affect
    /// later requests; `Suspend` ends the session).
    fn complete(&self, completion: Completion) {
        let time = self.runtime.time.estimate();
        let mut end = false;
        for detector in self.runtime.detectors.iter().filter(|d| d.protocols().contains(&completion.protocol)) {
            if let Some(finding) = detector.complete(&completion) {
                end |= matches!(self.act(detector.name(), finding, &time), Verdict::End(_));
            }
        }
        self.runtime.record(
            Some(self.caller.clone()),
            TelemetryEvent::Request {
                session_id: self.session_id,
                app: self.app.clone(),
                blob_id: self.blob_id(),
                connection_id: self.connection_id,
                completion,
            },
        );
        if end {
            self.runtime.close_session_detached(self.session_id, ErrorCode::IntegrityFailed, &self.caller, &time);
        }
    }

    async fn ended(&self) -> ErrorCode {
        let mut changes = self.end.subscribe();
        loop {
            if let Some(reason) = *changes.borrow_and_update() {
                return reason;
            }
            let expires_at = self.expires_at.load(Ordering::Relaxed);
            if self.runtime.time.estimate().latest() >= expires_at {
                self.end(ErrorCode::SessionExpired);
                continue;
            }
            let deadline = self.runtime.time.instant_at(expires_at);
            tokio::select! {
                _ = tokio::time::sleep_until(deadline.into()) => {}
                changed = changes.changed() => {
                    if changed.is_err() {
                        // The sender lives as long as `self`; never reached.
                        std::future::pending::<()>().await;
                    }
                }
            }
        }
    }
}

/// Ends every live session that no longer passes `TenantAuthorizer::recheck` against the
/// newest state (all of them, with `Unavailable`, once it is stale).
pub(crate) fn recheck_all(runtime: &Runtime) {
    let sessions = runtime.live.all();
    if sessions.is_empty() {
        return;
    }
    let time = runtime.time.estimate();
    let tenant = runtime.state.get();
    for session in sessions.iter().filter(|s| s.ended_with().is_none()) {
        let checked = match &tenant {
            Some(tenant) => session.recheck(tenant, &time),
            None => Err(ErrorCode::Unavailable),
        };
        if let Err(reason) = checked {
            session.end(reason);
        }
    }
}

/// Rechecks every live session on each tenant state change, when the state's `fresh_until`
/// passes, and at least every `state_reload` (`STATE_RELOAD_SECS` in release builds).
pub(super) async fn monitor(runtime: Arc<Runtime>) {
    let mut changes = runtime.state.subscribe();
    loop {
        let stale_at = runtime
            .state
            .get()
            .map(|t| t.fresh_until())
            .filter(|until| runtime.time.estimate().latest() < *until)
            .map(|until| runtime.time.instant_at(until));
        let stale = async {
            match stale_at {
                Some(at) => tokio::time::sleep_until(at.into()).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            changed = changes.changed() => {
                if changed.is_err() {
                    return;
                }
            }
            _ = stale => {}
            _ = tokio::time::sleep(runtime.state_reload) => {}
        }
        recheck_all(&runtime);
    }
}

/// The resolver adapters get: credential → live session.
pub(super) struct Resolver {
    pub(super) runtime: Arc<Runtime>,
}

#[async_trait]
impl SessionResolver for Resolver {
    async fn resolve(&self, credential: &str, meta: &ConnMeta) -> Result<Arc<dyn Session>, ErrorCode> {
        match self.runtime.resolve(credential, meta).await {
            Ok(session) => Ok(session),
            Err(e) => {
                tracing::debug!(error = %e, "credential refused");
                Err(e.code)
            }
        }
    }
}

impl Runtime {
    /// A local key only through its tunnel (`SHA-256(local key) == local_key_sha256`), redeeming
    /// the preamble's token. The claims then pass `TenantAuthorizer::recheck` and the blob is
    /// opened.
    async fn resolve(self: &Arc<Self>, credential: &str, meta: &ConnMeta) -> Result<Arc<LiveSession>, ServiceError> {
        let (time, tenant) = self.serving_now().await?;
        if !credential.starts_with(LOCAL_KEY_PREFIX) {
            return Err(fail(ErrorCode::NotAllowed, "not a Seal credential"));
        }
        let digest: [u8; 32] = Sha256::digest(credential.as_bytes()).into();
        if digest != meta.tunnel.local_key_sha256 {
            return Err(fail(ErrorCode::NotAllowed, "the local key is not this tunnel's"));
        }
        let claims = self.redeem(meta.tunnel.token.expose())?;
        // Every data connection is held to the app's network rule.
        TenantAuthorizer::new(&tenant)
            .with_source(meta.peer.map(|p| p.ip()))
            .recheck(&claims, &time)
            .map_err(ServiceError::from)?;
        // Running work from here until the session is live, which then keeps the replica up.
        let _busy = self.activity.begin()?;
        let opened = self.open(&claims.blob, &tenant).await?;
        let session = Arc::new(LiveSession::new(self.clone(), claims, opened, meta.connection_id));
        self.live.insert(&session);
        Ok(session)
    }
}
