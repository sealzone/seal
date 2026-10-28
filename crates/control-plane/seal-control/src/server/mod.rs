//! The control plane server: the routes of the API table in the library docs, over a
//! file-backed `Store`. It authorizes reads and writes as the library docs' tables say
//! (`auth`) and rejects junk; it is untrusted, so nothing it serves is believed without
//! verification.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use seal_control::client::{Documents, Proposal, Proposed, Submitted};
use seal_crypto::sign::{admin_key_id, key_id, verify, verify_admin, verify_threshold};
use seal_proto::codec::labeled_digest;
use seal_proto::integrity::{validate_code, SignalSource, SignedSignal, SIGNAL_LABEL};
use seal_proto::release::{
    LogEntry, ReleaseCosign, ReleaseEvidence, SignedCheckpoint, SignedServiceKeyCertificate, SignedTenantWrapKey,
    TenantStateLeaf, TlogProof, RELEASE_COSIGN_LABEL, TENANT_WRAP_KEY_LABEL,
};
use seal_proto::session::{SignedSessionEnd, SESSION_END_LABEL};
use seal_proto::signed::Signed;
use seal_proto::state::{
    root_id, LoggedRoot, LoggedState, SignedStateFreshness, SignedTenantAnchor, SignedTenantState, TenantBundle,
    TenantRoot, TenantState, STATE_FRESHNESS_LABEL, TENANT_ANCHOR_LABEL, TENANT_ROOT_LABEL, TENANT_STATE_LABEL,
};
use seal_proto::telemetry::{SignedTelemetryBatch, TelemetryEntries, TELEMETRY_BATCH_LABEL};
use seal_proto::{
    ErrorCode, Measurement, PlatformId, PublicKey, TenantId, TenantKeyVersion, TenantRootId, TrustedTime, UnixTime,
};
use seal_tlog::{LogVerifier, TlogTrust};
use seal_verify::{ReleaseTrust, TenantVerifier};

pub mod auth;
pub mod config;
pub mod cors;
pub mod store;
#[cfg(test)]
mod tests;
pub mod tls;
pub mod token;
pub mod upstream;

use auth::{Asked, Chain, Rule};
use store::{Freshness, Store, TenantDocs, TenantEntry};
use token::ConsoleKeys;
use upstream::{Appended, Upstreams};

/// The log's statement in the bundle is refetched once it is this old.
pub const LOG_FRESHNESS_REFRESH_SECS: u64 = 3_600;
/// A guardian's anchor in the bundle is renewed once it is this old, so bundles carry about
/// `MAX_PENDING_WINDOW_SECS` plus this much of a tenant's states.
pub const ANCHOR_REFRESH_SECS: u64 = 3_600;
/// `GET /v1/checkpoint` serves one fetched checkpoint for this long.
pub const CHECKPOINT_CACHE_SECS: u64 = 60;
/// A wrap key a guardian did not deliver is asked for again after this long.
pub const WRAP_KEY_RETRY_SECS: u64 = 60;
/// Statements dated further ahead of the server's clock than this are refused.
pub const MAX_CLOCK_SKEW_SECS: u64 = 300;
/// Tenant-run freshness statements kept for the latest state (the newest).
pub const TENANT_STATEMENTS_KEPT: usize = 8;
/// Open proposals a tenant may have at once.
pub const MAX_PROPOSALS: usize = 32;
/// Signatures one proposal may collect.
pub const MAX_PROPOSAL_SIGNATURES: usize = 64;
/// How far back from the log's end a document already logged is looked for, when the log
/// refuses to append it again (a submit retried after its first attempt was logged).
pub const LOG_LOOKBACK_ENTRIES: u64 = 1_024;

/// Seconds since the Unix epoch, from wherever the server takes its time.
pub type Clock = Arc<dyn Fn() -> UnixTime + Send + Sync>;

pub fn system_clock() -> Clock {
    Arc::new(|| std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs()))
}

/// A refusal: its status and a short reason, sent as `{"error": reason}`.
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub message: String,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self { status, message: message.into() }
    }
    fn bad(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }
    fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "this write needs the write token")
    }
    fn unauthenticated(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, message)
    }
    fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, message)
    }
    fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }
    fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, message)
    }
    fn bad_gateway(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_GATEWAY, message)
    }
    fn unavailable(message: impl Into<String>) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, message)
    }
}

impl From<std::io::Error> for ApiError {
    fn from(e: std::io::Error) -> Self {
        tracing::error!(error = %e, "storage");
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "storage error")
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(serde_json::json!({ "error": self.message }))).into_response()
    }
}

type ApiResult<T> = Result<T, ApiError>;

/// What the server trusts and requires, from `config::Config`.
pub struct Settings {
    pub write_token: String,
    pub log: TlogTrust,
    /// Registrar keys and threshold a root version 1 must carry, when set.
    pub registrar: Option<(Vec<PublicKey>, usize)>,
    /// Each platform's guardian key.
    pub guardians: BTreeMap<PlatformId, PublicKey>,
    /// What an enclave's attested boot read must pass; none refuses attested reads.
    pub releases: Option<ReleaseTrust>,
    /// The console's control-token keys; none refuses control tokens.
    pub console_keys: Vec<PublicKey>,
    /// The web UI's origin, the only one CORS admits.
    pub console_origin: Option<String>,
    /// How long a fetched log checkpoint is reused: `CHECKPOINT_CACHE_SECS`, or less in sim
    /// builds (`sim.checkpoint_cache_secs`).
    pub checkpoint_cache_secs: u64,
}

type WrapKeyId = (PlatformId, TenantId, TenantRootId, TenantKeyVersion);

pub struct App {
    store: Store,
    upstreams: Arc<dyn Upstreams>,
    /// SHA-256 of the write token, so the comparison is constant-time over equal lengths.
    write_token: [u8; 32],
    log: TlogTrust,
    registrar: Option<(Vec<PublicKey>, usize)>,
    guardians: BTreeMap<PlatformId, PublicKey>,
    releases: Option<ReleaseTrust>,
    console: Option<ConsoleKeys>,
    console_origin: Option<Arc<str>>,
    clock: Clock,
    checkpoint_cache_secs: u64,
    checkpoint: Mutex<Option<(UnixTime, SignedCheckpoint)>>,
    /// When each wrap key was last asked for and not delivered.
    wrap_key_misses: Mutex<HashMap<WrapKeyId, UnixTime>>,
}

impl App {
    /// Refuses a console key that is not an Ed25519 public key.
    pub fn new(settings: Settings, store: Store, upstreams: Arc<dyn Upstreams>, clock: Clock) -> Result<Self, String> {
        let console = match settings.console_keys.as_slice() {
            [] => None,
            keys => Some(ConsoleKeys::new(keys)?),
        };
        Ok(Self {
            store,
            upstreams,
            write_token: Sha256::digest(settings.write_token.as_bytes()).into(),
            log: settings.log,
            registrar: settings.registrar,
            guardians: settings.guardians,
            releases: settings.releases,
            console,
            console_origin: settings.console_origin.map(Arc::from),
            clock,
            checkpoint_cache_secs: settings.checkpoint_cache_secs,
            checkpoint: Mutex::new(None),
            wrap_key_misses: Mutex::new(HashMap::new()),
        })
    }

    fn now(&self) -> UnixTime {
        (self.clock)()
    }

    fn require_write_token(&self, asked: &Asked) -> ApiResult<()> {
        let presented = asked
            .authorization
            .as_deref()
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or_else(ApiError::unauthorized)?;
        self.check_write_token(presented)
    }

    fn check_write_token(&self, presented: &str) -> ApiResult<()> {
        let digest: [u8; 32] = Sha256::digest(presented.as_bytes()).into();
        if bool::from(digest.ct_eq(&self.write_token)) {
            Ok(())
        } else {
            Err(ApiError::unauthorized())
        }
    }

    /// The guardian keys of `platforms` (those configured): whose anchors bundles carry.
    fn anchor_keys(&self, platforms: &std::collections::BTreeSet<PlatformId>) -> Vec<PublicKey> {
        platforms.iter().filter_map(|p| self.guardians.get(p)).copied().collect()
    }

    /// The run of consecutive versions of `stored` that ends with the bundle's state, from where
    /// every verifier trusting one of `keys` finds an anchor (`seal_verify::anchor_index`).
    fn served_states(
        &self,
        stored: Vec<LoggedState>,
        bundle: &TenantBundle,
        keys: &[PublicKey],
        time: &TrustedTime,
    ) -> Vec<LoggedState> {
        if stored.last().is_none_or(|last| last.state != bundle.state) {
            return Vec::new();
        }
        let run = stored
            .windows(2)
            .rposition(|w| w[0].state.body.version + 1 != w[1].state.body.version)
            .map_or(0, |i| i + 1);
        let states = &stored[run..];
        let (roots, anchors, checkpoint) = (&bundle.root_chain, &bundle.anchors, bundle.checkpoint.as_ref());
        let from = seal_verify::anchor_index(&self.log, keys, roots, states, anchors, checkpoint, time);
        states[from..].to_vec()
    }

    /// Asks each of `keys`' guardians for a new anchor for `bundle` when the one it has is
    /// missing or older than `ANCHOR_REFRESH_SECS`, keeping one per guardian (signed by it, for
    /// this tenant and chain). Whether any changed.
    async fn refresh_anchors(
        &self,
        tenant: &TenantId,
        root_id: TenantRootId,
        keys: &[PublicKey],
        bundle: &mut TenantBundle,
        now: UnixTime,
    ) -> bool {
        let valid = |a: &SignedTenantAnchor, key: &PublicKey| {
            signed_by_any(&[*key], TENANT_ANCHOR_LABEL, a) && &a.body.tenant == tenant && a.body.root_id == root_id
        };
        let mut changed = false;
        for (platform, key) in self.guardians.iter().filter(|(_, k)| keys.contains(k)) {
            let current = bundle.anchors.iter().filter(|a| valid(a, key)).max_by_key(|a| a.body.at);
            if current.is_some_and(|a| now < a.body.at.saturating_add(ANCHOR_REFRESH_SECS)) {
                continue;
            }
            match self.upstreams.anchor(*platform, tenant, &root_id, bundle).await {
                Ok(Some(anchor)) if valid(&anchor, key) => {
                    bundle.anchors.retain(|a| !signed_by_any(&[*key], TENANT_ANCHOR_LABEL, a));
                    bundle.anchors.push(anchor);
                    changed = true;
                }
                Ok(Some(_)) => tracing::warn!(%tenant, ?platform, "the guardian's anchor does not verify"),
                Ok(None) => tracing::warn!(%tenant, ?platform, "the guardian refused an anchor"),
                Err(e) => tracing::warn!(%tenant, ?platform, error = %e, "cannot reach the guardian for an anchor"),
            }
        }
        changed
    }

    /// The log's latest checkpoint, verified; fetched at most every `checkpoint_cache_secs`.
    async fn latest_checkpoint(&self) -> ApiResult<SignedCheckpoint> {
        let now = self.now();
        {
            let cached = self.checkpoint.lock().unwrap_or_else(|p| p.into_inner());
            if let Some((at, checkpoint)) = cached.as_ref() {
                if now < at.saturating_add(self.checkpoint_cache_secs) {
                    return Ok(checkpoint.clone());
                }
            }
        }
        let checkpoint = self
            .upstreams
            .log_checkpoint()
            .await
            .map_err(|e| ApiError::unavailable(format!("the log is unreachable: {e}")))?;
        LogVerifier::new(self.log.clone())
            .checkpoint(&checkpoint)
            .map_err(|e| ApiError::bad_gateway(format!("the log's checkpoint does not verify: {e}")))?;
        *self.checkpoint.lock().unwrap_or_else(|p| p.into_inner()) = Some((now, checkpoint.clone()));
        Ok(checkpoint)
    }

    /// Signed by the log key and not dated ahead of the server's clock.
    fn log_statement_valid(&self, statement: &SignedStateFreshness) -> bool {
        signed_by_any(&[self.log.log_key], STATE_FRESHNESS_LABEL, statement)
            && statement.body.signed_at <= self.now().saturating_add(MAX_CLOCK_SKEW_SECS)
    }

    /// The log's statement for the tenant's latest logged state, checked against the log key.
    async fn log_freshness(&self, tenant: &TenantId) -> ApiResult<Option<SignedStateFreshness>> {
        let statement = self
            .upstreams
            .log_freshness(tenant)
            .await
            .map_err(|e| ApiError::unavailable(format!("the log is unreachable: {e}")))?;
        match statement {
            Some(s) if !self.log_statement_valid(&s) || s.body.tenant != *tenant => {
                Err(ApiError::bad_gateway("the log's freshness statement does not verify"))
            }
            other => Ok(other),
        }
    }

    fn wrap_key_valid(&self, key: &SignedTenantWrapKey, id: &WrapKeyId) -> bool {
        let (platform, tenant, root_id, version) = id;
        let body = &key.body;
        body.platform == *platform
            && body.tenant == *tenant
            && body.root_id == *root_id
            && body.tenant_key_version == *version
            && self
                .guardians
                .get(platform)
                .is_some_and(|guardian| signed_by_any(std::slice::from_ref(guardian), TENANT_WRAP_KEY_LABEL, key))
    }

    /// Fetches `id` from its guardian unless it failed within `WRAP_KEY_RETRY_SECS`.
    async fn fetch_wrap_key(&self, id: &WrapKeyId) -> Option<SignedTenantWrapKey> {
        let now = self.now();
        {
            let misses = self.wrap_key_misses.lock().unwrap_or_else(|p| p.into_inner());
            if misses.get(id).is_some_and(|&at| now < at.saturating_add(WRAP_KEY_RETRY_SECS)) {
                return None;
            }
        }
        let (platform, tenant, root_id, version) = id;
        let result = self.upstreams.wrap_key(*platform, tenant, root_id, *version).await;
        let mut misses = self.wrap_key_misses.lock().unwrap_or_else(|p| p.into_inner());
        match result {
            Ok(Some(key)) if self.wrap_key_valid(&key, id) => {
                misses.remove(id);
                Some(key)
            }
            Ok(Some(_)) => {
                tracing::warn!(?platform, %tenant, %version, "guardian wrap key does not verify");
                misses.insert(id.clone(), now);
                None
            }
            Ok(None) => {
                tracing::warn!(?platform, %tenant, %version, "guardian has no wrap key");
                misses.insert(id.clone(), now);
                None
            }
            Err(e) => {
                tracing::warn!(?platform, %tenant, %version, error = %e, "guardian unreachable");
                misses.insert(id.clone(), now);
                None
            }
        }
    }
}

pub fn router(app: Arc<App>) -> Router {
    let origin = app.console_origin.clone();
    Router::new()
        .route("/v1/tenants/{tenant}/bundle", get(get_bundle))
        .route("/v1/tenants/{tenant}/documents", get(get_documents))
        .route("/v1/tenants/{tenant}/root", put(put_root))
        .route("/v1/tenants/{tenant}/state", put(put_state))
        .route("/v1/tenants/{tenant}/proposals", get(get_proposals))
        .route("/v1/tenants/{tenant}/proposals/{id}", put(put_proposal).delete(delete_proposal))
        .route("/v1/tenants/{tenant}/proposals/{id}/submit", post(post_proposal_submit))
        .route("/v1/tenants/{tenant}/freshness", post(post_freshness))
        .route("/v1/tenants/{tenant}/signals", post(post_signal))
        .route("/v1/tenants/{tenant}/session-ends", post(post_session_end))
        .route(
            "/v1/tenants/{tenant}/service-key-certificates",
            get(get_service_key_certificates).post(post_service_key_certificate),
        )
        .route("/v1/tenants/{tenant}/telemetry", get(get_telemetry).post(post_telemetry))
        .route("/v1/tenants/{tenant}/release-cosigns/{measurement}", get(get_release_cosign).put(put_release_cosign))
        .route("/v1/releases/{platform}", get(get_releases))
        .route("/v1/releases/{platform}/{measurement}", get(get_release).put(put_release))
        .route("/v1/releases/{platform}/{measurement}/template", get(get_release_template).put(put_release_template))
        .route("/v1/checkpoint", get(get_checkpoint))
        .with_state(app)
        .layer(axum::middleware::from_fn_with_state(origin, cors::cors))
}

fn parse<T: DeserializeOwned>(body: &[u8]) -> ApiResult<T> {
    serde_json::from_slice(body).map_err(|e| ApiError::bad(format!("malformed body: {e}")))
}

/// Some signature of `signed` verifies under one of `keys` (Ed25519).
fn signed_by_any<T: serde::Serialize>(keys: &[PublicKey], label: &str, signed: &Signed<T>) -> bool {
    signed.signatures.iter().any(|sig| {
        keys.iter().find(|k| key_id(k) == sig.signer).is_some_and(|k| verify(k, label, &signed.body, sig).is_ok())
    })
}

/// A statement for exactly `state` (tenant, version, digest).
fn for_state(statement: &SignedStateFreshness, state: &TenantState) -> bool {
    let s = &statement.body;
    s.tenant == state.tenant && s.version == state.version && s.digest == labeled_digest(TENANT_STATE_LABEL, state)
}

fn chain_root_id(docs: &TenantDocs) -> Option<TenantRootId> {
    docs.roots.first().map(|link| root_id(&link.root.body))
}

/// The telemetry public keys of the certificates posted for the tenant's root chain.
fn telemetry_keys(docs: &TenantDocs) -> Vec<PublicKey> {
    let Some(root_id) = chain_root_id(docs) else {
        return Vec::new();
    };
    let mut keys: Vec<PublicKey> = docs
        .certificates
        .iter()
        .filter(|c| c.body.root_id == root_id)
        .flat_map(|c| c.body.telemetry_public_keys.iter().map(|(_, k)| *k))
        .collect();
    keys.sort_unstable();
    keys.dedup();
    keys
}

fn same_tenant(path: &TenantId, body: &TenantId) -> ApiResult<()> {
    if path == body {
        Ok(())
    } else {
        Err(ApiError::bad("the document is for another tenant"))
    }
}

async fn get_bundle(
    State(app): State<Arc<App>>,
    Path(tenant): Path<TenantId>,
    asked: Asked,
) -> ApiResult<Json<TenantBundle>> {
    let entry = app.store.tenant(&tenant)?;
    let docs = entry.lock().await.docs.clone();
    app.authorize(&Chain::of(&tenant, &docs), &docs, &asked, &[], Rule::Bundle).await?;
    let (Some(state), Some(root_id)) = (docs.state.clone(), chain_root_id(&docs)) else {
        return Err(ApiError::not_found("no root chain and state for this tenant"));
    };
    let now = app.now();

    // The log's statement: refetched when missing or an hour old; the cached one stays in
    // use while the log is unreachable.
    let mut log_statement = docs.freshness.log.clone().filter(|s| for_state(s, &state.body));
    let due = log_statement.as_ref().is_none_or(|s| now >= s.body.signed_at.saturating_add(LOG_FRESHNESS_REFRESH_SECS));
    if due {
        match app.log_freshness(&tenant).await {
            Ok(Some(fresh)) if for_state(&fresh, &state.body) => {
                let newer = log_statement.as_ref().is_none_or(|old| fresh.body.signed_at > old.body.signed_at);
                if newer {
                    let mut e = entry.lock().await;
                    if e.docs.state.as_ref() == Some(&state) {
                        let freshness = Freshness { log: Some(fresh.clone()), tenant: e.docs.freshness.tenant.clone() };
                        if let Err(err) = e.set_freshness(freshness) {
                            tracing::error!(error = %err, "storing the log's freshness statement");
                        }
                    }
                    log_statement = Some(fresh);
                }
            }
            Ok(_) => {
                tracing::warn!(%tenant, version = state.body.version, "the log's latest state is not the stored one")
            }
            Err(e) => tracing::warn!(%tenant, error = %e.message, "cannot refresh the log's freshness statement"),
        }
    }

    // Wrap keys of every platform and accepted tenant key version, fetched once and cached.
    let versions = &state.body.tenant_key_versions;
    let mut wrap_keys = Vec::new();
    let mut fetched = Vec::new();
    for platform in &state.body.platforms {
        for v in versions.oldest_accepted.0..=versions.current.0 {
            let id: WrapKeyId = (*platform, tenant.clone(), root_id, TenantKeyVersion(v));
            if let Some(key) = docs.wrap_keys.iter().find(|k| app.wrap_key_valid(k, &id)) {
                wrap_keys.push(key.clone());
            } else if let Some(key) = app.fetch_wrap_key(&id).await {
                wrap_keys.push(key.clone());
                fetched.push(key);
            }
        }
    }
    if !fetched.is_empty() {
        let mut e = entry.lock().await;
        let mut all = e.docs.wrap_keys.clone();
        for key in fetched {
            if !all.contains(&key) {
                all.push(key);
            }
        }
        if let Err(err) = e.set_wrap_keys(all) {
            tracing::error!(error = %err, "caching wrap keys");
        }
    }

    let time = TrustedTime::exact(now);
    let mut freshness: Vec<SignedStateFreshness> = log_statement.into_iter().collect();
    // The newest tenant-run statement already in force (one dated ahead never counts).
    let tenant_statement = docs
        .freshness
        .tenant
        .iter()
        .filter(|s| for_state(s, &state.body) && s.body.signed_at <= now)
        .max_by_key(|s| s.body.signed_at);
    freshness.extend(tenant_statement.cloned());
    let checkpoint = match app.latest_checkpoint().await {
        Ok(checkpoint) => Some(checkpoint),
        Err(e) => {
            tracing::warn!(%tenant, error = %e.message, "bundle served without the log's latest checkpoint");
            None
        }
    };
    let keys = app.anchor_keys(&state.body.platforms);
    let mut bundle = TenantBundle {
        root_chain: docs.roots.clone(),
        signals: docs.signals.into_iter().filter(|s| state.body.integrity.is_live(&s.body, &time)).collect(),
        ended_sessions: docs.session_ends.into_iter().filter(|e| e.body.is_live(&time)).collect(),
        state,
        freshness,
        wrap_keys,
        states: Vec::new(),
        checkpoint,
        anchors: docs.anchors.clone(),
    };
    let from = oldest_anchored(&keys, &bundle.anchors);
    let stored = entry.lock().await.logged_states(from)?;
    bundle.states = app.served_states(stored.clone(), &bundle, &keys, &time);
    if app.refresh_anchors(&tenant, root_id, &keys, &mut bundle, now).await {
        let mut e = entry.lock().await;
        if let Err(err) = e.set_anchors(bundle.anchors.clone()) {
            tracing::error!(error = %err, "storing anchors");
        }
        drop(e);
        bundle.states = app.served_states(stored, &bundle, &keys, &time);
    }
    Ok(Json(bundle))
}

/// The version before the oldest of `anchors` signed by `keys`, when each key signed one: the
/// stored states a bundle can need start after it.
fn oldest_anchored(keys: &[PublicKey], anchors: &[SignedTenantAnchor]) -> Option<u64> {
    keys.iter()
        .map(|k| anchors.iter().filter(|a| signed_by_any(&[*k], TENANT_ANCHOR_LABEL, a)).map(|a| a.body.version).max())
        .collect::<Option<Vec<u64>>>()?
        .into_iter()
        .min()
        .map(|v| v.saturating_sub(1))
}

/// A state's log leaf on the chain `root_id`.
fn state_leaf(root_id: TenantRootId, state: &TenantState) -> LogEntry {
    LogEntry::TenantState(TenantStateLeaf {
        tenant: state.tenant.clone(),
        root_id,
        version: state.version,
        digest: labeled_digest(TENANT_STATE_LABEL, state),
    })
}

impl App {
    /// Appends `link` to the stored chain: it must be the next version, carry the registrar's
    /// signatures (version 1, when a registrar is configured) or the threshold of the version
    /// before it, and be included in the log. Storing the same link again changes nothing.
    fn store_root(&self, e: &mut TenantEntry, link: LoggedRoot) -> ApiResult<()> {
        let root = &link.root.body;
        let have = e.docs.roots.len() as u64;
        if let Some(index) = root.version.checked_sub(1).filter(|&i| i < have) {
            return if e.docs.roots[index as usize].root == link.root {
                Ok(())
            } else {
                Err(ApiError::conflict(format!("version {} is already in the chain", root.version)))
            };
        }
        if root.version != have + 1 {
            return Err(ApiError::conflict(format!("the chain has {have} versions; the next must be {}", have + 1)));
        }
        match e.docs.roots.last() {
            None => {
                if let Some((keys, threshold)) = &self.registrar {
                    verify_threshold(keys, *threshold, TENANT_ROOT_LABEL, &link.root)
                        .map_err(|_| ApiError::bad("version 1 lacks the registrar's signatures"))?;
                }
            }
            Some(previous) => {
                TenantVerifier::verify_admin_signed(&previous.root.body, TENANT_ROOT_LABEL, &link.root)
                    .map_err(|_| ApiError::bad(format!("not signed by the threshold of version {have}")))?;
            }
        }
        LogVerifier::new(self.log.clone())
            .inclusion(&LogEntry::TenantRoot(root.clone()), &link.proof)
            .map_err(|err| ApiError::bad(format!("log inclusion: {err}")))?;
        let mut roots = e.docs.roots.clone();
        roots.push(link);
        e.set_roots(roots)?;
        Ok(())
    }

    /// Whether `state` may follow the stored one: for the latest root version, signed by its
    /// threshold, with a higher version. `true` when it is exactly the current one.
    fn check_state(&self, e: &TenantEntry, state: &SignedTenantState) -> ApiResult<bool> {
        let latest = &e.docs.roots.last().ok_or_else(|| ApiError::conflict("the tenant has no root chain"))?.root.body;
        if state.body.root_version != latest.version {
            return Err(ApiError::conflict(format!(
                "signed for root version {}, the latest is {}",
                state.body.root_version, latest.version
            )));
        }
        TenantVerifier::verify_admin_signed(latest, TENANT_STATE_LABEL, state)
            .map_err(|_| ApiError::bad("not signed by the threshold of the latest root"))?;
        if let Some(current) = &e.docs.state {
            if current == state {
                return Ok(true);
            }
            if state.body.version <= current.body.version {
                return Err(ApiError::conflict(format!(
                    "version {} does not increase on {}",
                    state.body.version, current.body.version
                )));
            }
        }
        Ok(false)
    }

    /// Appends `entry` (the outcome of the append is `append`), or finds it among the log's
    /// last `LOG_LOOKBACK_ENTRIES` when the log refuses it because it is already there;
    /// returns its inclusion proof, checked.
    async fn log(&self, entry: &LogEntry, append: Result<Appended, upstream::UpstreamError>) -> ApiResult<TlogProof> {
        let index = match append.map_err(log_unreachable)? {
            Appended::At(index) => index,
            Appended::Refused(reason) => match self.find_logged(entry).await? {
                Some(index) => index,
                None => return Err(ApiError::conflict(format!("the log refused it: {reason}"))),
            },
        };
        let proof = self.upstreams.log_proof(index).await.map_err(log_unreachable)?;
        if proof.leaf_index != index {
            return Err(ApiError::bad_gateway(format!("the log proved entry {} for {index}", proof.leaf_index)));
        }
        LogVerifier::new(self.log.clone())
            .inclusion(entry, &proof)
            .map_err(|e| ApiError::bad_gateway(format!("the log's inclusion proof does not verify: {e}")))?;
        Ok(proof)
    }

    async fn find_logged(&self, entry: &LogEntry) -> ApiResult<Option<u64>> {
        let checkpoint = self.upstreams.log_checkpoint().await.map_err(log_unreachable)?;
        let size = LogVerifier::new(self.log.clone())
            .checkpoint(&checkpoint)
            .map_err(|e| ApiError::bad_gateway(format!("the log's checkpoint does not verify: {e}")))?
            .checkpoint()
            .size;
        for index in (size.saturating_sub(LOG_LOOKBACK_ENTRIES)..size).rev() {
            if self.upstreams.log_entry(index).await.map_err(log_unreachable)?.as_ref() == Some(entry) {
                return Ok(Some(index));
            }
        }
        Ok(None)
    }

    /// Logs `state` (unless `proof` shows it is logged) after `check_state`, and stores it as
    /// the tenant's current state once the log names it as the tenant's latest. The stored one
    /// when `state` is already current.
    async fn submit_state(
        &self,
        tenant: &TenantId,
        e: &mut TenantEntry,
        state: SignedTenantState,
        proof: Option<TlogProof>,
    ) -> ApiResult<Option<LoggedState>> {
        if self.check_state(e, &state)? {
            return Ok(e.logged_state(state.body.version)?);
        }
        let root_id = chain_root_id(&e.docs).ok_or_else(|| ApiError::conflict("the tenant has no root chain"))?;
        let leaf = state_leaf(root_id, &state.body);
        let proof = match proof {
            Some(proof) => {
                LogVerifier::new(self.log.clone())
                    .inclusion(&leaf, &proof)
                    .map_err(|err| ApiError::bad(format!("log inclusion: {err}")))?;
                proof
            }
            None => self.log(&leaf, self.upstreams.log_append_state(tenant, &state).await).await?,
        };
        let statement = self
            .log_freshness(tenant)
            .await?
            .ok_or_else(|| ApiError::conflict("the log has no state for this tenant"))?;
        if !for_state(&statement, &state.body) {
            return Err(ApiError::conflict(format!(
                "the log has not recorded this state as the tenant's latest (its latest is version {})",
                statement.body.version
            )));
        }
        let logged = LoggedState { state, proof };
        e.put_logged_state(&logged)?;
        e.set_state(logged.state.clone())?;
        e.set_freshness(Freshness { log: Some(statement), tenant: Vec::new() })?;
        Ok(Some(logged))
    }
}

fn log_unreachable(e: upstream::UpstreamError) -> ApiError {
    ApiError::unavailable(format!("the log is unreachable: {e}"))
}

async fn put_root(
    State(app): State<Arc<App>>,
    Path(tenant): Path<TenantId>,
    asked: Asked,
    body: Bytes,
) -> ApiResult<StatusCode> {
    let link: LoggedRoot = parse(&body)?;
    same_tenant(&tenant, &link.root.body.tenant)?;
    let entry = app.store.tenant(&tenant)?;
    let mut e = entry.lock().await;
    let docs = e.docs.clone();
    // Root version 1 names its own chain and first admins.
    let chain = if docs.roots.is_empty() && link.root.body.version == 1 {
        Chain { tenant: &tenant, root_id: Some(root_id(&link.root.body)), admins: Some(&link.root.body) }
    } else {
        Chain::of(&tenant, &docs)
    };
    app.authorize(&chain, &docs, &asked, &body, Rule::Submit).await?;
    app.store_root(&mut e, link)?;
    Ok(StatusCode::NO_CONTENT)
}

/// `PUT /state` takes a state its caller logged, with the proof, or one the control plane
/// logs itself.
#[allow(clippy::large_enum_variant)]
#[derive(Deserialize)]
#[serde(untagged)]
enum StateBody {
    Logged(LoggedState),
    Unlogged(SignedTenantState),
}

async fn put_state(
    State(app): State<Arc<App>>,
    Path(tenant): Path<TenantId>,
    asked: Asked,
    body: Bytes,
) -> ApiResult<StatusCode> {
    let (state, proof) = match parse(&body)? {
        StateBody::Logged(l) => (l.state, Some(l.proof)),
        StateBody::Unlogged(s) => (s, None),
    };
    same_tenant(&tenant, &state.body.tenant)?;
    let entry = app.store.tenant(&tenant)?;
    let mut e = entry.lock().await;
    let docs = e.docs.clone();
    app.authorize(&Chain::of(&tenant, &docs), &docs, &asked, &body, Rule::Submit).await?;
    app.submit_state(&tenant, &mut e, state, proof).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn post_freshness(
    State(app): State<Arc<App>>,
    Path(tenant): Path<TenantId>,
    body: Bytes,
) -> ApiResult<StatusCode> {
    let statement: SignedStateFreshness = parse(&body)?;
    same_tenant(&tenant, &statement.body.tenant)?;
    let entry = app.store.tenant(&tenant)?;
    let mut e = entry.lock().await;
    let state = &e.docs.state.as_ref().ok_or_else(|| ApiError::conflict("the tenant has no state"))?.body;
    let keys: Vec<PublicKey> = state.freshness_keys.iter().copied().collect();
    if !signed_by_any(&keys, STATE_FRESHNESS_LABEL, &statement) {
        return Err(ApiError::forbidden("not signed by a freshness key of the latest state"));
    }
    if !for_state(&statement, state) {
        return Err(ApiError::conflict("not a statement for the latest state"));
    }
    if statement.body.signed_at > app.now().saturating_add(MAX_CLOCK_SKEW_SECS) {
        return Err(ApiError::bad("dated in the future"));
    }
    if e.docs.freshness.tenant.contains(&statement) {
        return Ok(StatusCode::NO_CONTENT);
    }
    let mut freshness = e.docs.freshness.clone();
    freshness.tenant.push(statement);
    freshness.tenant.sort_by_key(|s| s.body.signed_at);
    let excess = freshness.tenant.len().saturating_sub(TENANT_STATEMENTS_KEPT);
    freshness.tenant.drain(..excess);
    e.set_freshness(freshness)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn post_signal(State(app): State<Arc<App>>, Path(tenant): Path<TenantId>, body: Bytes) -> ApiResult<StatusCode> {
    let signal: SignedSignal = parse(&body)?;
    same_tenant(&tenant, &signal.body.tenant)?;
    validate_code(&signal.body.code).map_err(|e| ApiError::bad(e.to_string()))?;
    let entry = app.store.tenant(&tenant)?;
    let mut e = entry.lock().await;
    match &signal.body.source {
        SignalSource::Enclave { .. } | SignalSource::Sdk => {
            if !signed_by_any(&telemetry_keys(&e.docs), SIGNAL_LABEL, &signal) {
                return Err(ApiError::forbidden("not signed by a certified telemetry key of this tenant"));
            }
        }
        SignalSource::External { source } => {
            let key = e
                .docs
                .state
                .as_ref()
                .and_then(|s| s.body.integrity.sources.get(source))
                .ok_or_else(|| ApiError::forbidden("not a source of the latest state"))?;
            if !signed_by_any(std::slice::from_ref(key), SIGNAL_LABEL, &signal) {
                return Err(ApiError::forbidden("not signed by the source's key"));
            }
        }
    }
    if e.docs.signals.iter().any(|s| s.body == signal.body) {
        return Ok(StatusCode::NO_CONTENT);
    }
    let mut signals = e.docs.signals.clone();
    signals.push(signal);
    e.set_signals(signals)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn post_session_end(
    State(app): State<Arc<App>>,
    Path(tenant): Path<TenantId>,
    body: Bytes,
) -> ApiResult<StatusCode> {
    let end: SignedSessionEnd = parse(&body)?;
    same_tenant(&tenant, &end.body.tenant)?;
    if !matches!(end.body.reason, ErrorCode::SessionEnded | ErrorCode::IntegrityFailed) {
        return Err(ApiError::bad("a session ends with session_ended or integrity_failed"));
    }
    let entry = app.store.tenant(&tenant)?;
    let mut e = entry.lock().await;
    if !signed_by_any(&telemetry_keys(&e.docs), SESSION_END_LABEL, &end) {
        return Err(ApiError::forbidden("not signed by a certified telemetry key of this tenant"));
    }
    let time = TrustedTime::exact(app.now());
    let live: Vec<SignedSessionEnd> = e.docs.session_ends.iter().filter(|x| x.body.is_live(&time)).cloned().collect();
    let known = live.iter().any(|x| x.body.session_id == end.body.session_id);
    if known && live.len() == e.docs.session_ends.len() {
        return Ok(StatusCode::NO_CONTENT);
    }
    let mut ends = live;
    if !known && end.body.is_live(&time) {
        ends.push(end);
    }
    e.set_session_ends(ends)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn post_service_key_certificate(
    State(app): State<Arc<App>>,
    Path(tenant): Path<TenantId>,
    body: Bytes,
) -> ApiResult<StatusCode> {
    let certificate: SignedServiceKeyCertificate = parse(&body)?;
    same_tenant(&tenant, &certificate.body.tenant)?;
    seal_verify::verify_service_certificate(&app.guardians, &certificate)
        .map_err(|e| ApiError::forbidden(e.to_string()))?;
    let entry = app.store.tenant(&tenant)?;
    let mut e = entry.lock().await;
    let root_id = chain_root_id(&e.docs).ok_or_else(|| ApiError::conflict("the tenant has no root chain"))?;
    if certificate.body.root_id != root_id {
        return Err(ApiError::conflict("the certificate is for another root chain"));
    }
    if e.docs.certificates.contains(&certificate) {
        return Ok(StatusCode::NO_CONTENT);
    }
    let mut certificates = e.docs.certificates.clone();
    certificates.push(certificate);
    e.set_certificates(certificates)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Public: certificates name public keys, which every enclave also
/// serves in its attestation.
async fn get_service_key_certificates(
    State(app): State<Arc<App>>,
    Path(tenant): Path<TenantId>,
) -> ApiResult<Json<Vec<SignedServiceKeyCertificate>>> {
    let entry = app.store.tenant(&tenant)?;
    let certificates = entry.lock().await.docs.certificates.clone();
    Ok(Json(certificates))
}

/// Shape checks a batch must pass before its signature is looked at.
fn check_batch(tenant: &TenantId, batch: &SignedTelemetryBatch) -> ApiResult<()> {
    let b = &batch.body;
    same_tenant(tenant, &b.tenant)?;
    if b.from > b.to {
        return Err(ApiError::bad("from is after to"));
    }
    match &b.entries {
        TelemetryEntries::Clear { entries } => {
            if entries.len() != b.count as usize {
                return Err(ApiError::bad("count does not match the entries"));
            }
            if entries.iter().any(|x| x.tenant != *tenant || x.at < b.from || x.at > b.to) {
                return Err(ApiError::bad("an entry is for another tenant or outside from..to"));
            }
        }
        TelemetryEntries::Sealed { readers, .. } => {
            if readers.is_empty() {
                return Err(ApiError::bad("sealed entries without readers"));
            }
        }
    }
    Ok(())
}

async fn post_telemetry(
    State(app): State<Arc<App>>,
    Path(tenant): Path<TenantId>,
    body: Bytes,
) -> ApiResult<StatusCode> {
    let batch: SignedTelemetryBatch = parse(&body)?;
    check_batch(&tenant, &batch)?;
    let entry = app.store.tenant(&tenant)?;
    let e = entry.lock().await;
    if !signed_by_any(&telemetry_keys(&e.docs), TELEMETRY_BATCH_LABEL, &batch) {
        return Err(ApiError::forbidden("not signed by a certified telemetry key of this tenant"));
    }
    match e.telemetry_batch(&batch.body.stream, batch.body.sequence)? {
        Some(stored) if stored == batch => Ok(StatusCode::NO_CONTENT),
        Some(_) => Err(ApiError::conflict("another batch has this stream and sequence")),
        None => {
            e.put_telemetry_batch(&batch)?;
            Ok(StatusCode::NO_CONTENT)
        }
    }
}

#[derive(Deserialize)]
struct TelemetryQuery {
    since: Option<UnixTime>,
    /// The last batch of the previous page, `<stream hex>-<sequence>`.
    after: Option<String>,
    limit: Option<usize>,
}

/// Batches per telemetry page by default and at most.
pub const TELEMETRY_PAGE_BATCHES: usize = 1_000;
/// A page stops before its JSON grows past this, after at least one batch: readers' HTTPS
/// clients cap a response at 1 MiB.
pub const TELEMETRY_PAGE_BYTES: usize = 768 * 1024;

/// `<32 hex digits>-<sequence>`.
fn parse_cursor(cursor: &str) -> ApiResult<([u8; 16], u64)> {
    let bad = || ApiError::bad("after is <stream hex>-<sequence>");
    let (stream, sequence) = cursor.split_once('-').ok_or_else(bad)?;
    let bytes: Vec<u8> = (0..stream.len())
        .step_by(2)
        .map(|i| stream.get(i..i + 2).and_then(|h| u8::from_str_radix(h, 16).ok()))
        .collect::<Option<_>>()
        .ok_or_else(bad)?;
    Ok((bytes.try_into().map_err(|_| bad())?, sequence.parse().map_err(|_| bad())?))
}

/// One page of batches with entries at or after `since`, by stream and sequence, after the
/// `after` cursor. A page ends at `limit` batches or `TELEMETRY_PAGE_BYTES`; readers ask again
/// from its last batch until a page comes back empty.
async fn get_telemetry(
    State(app): State<Arc<App>>,
    Path(tenant): Path<TenantId>,
    Query(query): Query<TelemetryQuery>,
    asked: Asked,
) -> ApiResult<Json<Vec<SignedTelemetryBatch>>> {
    let since = query.since.unwrap_or(0);
    let after = query.after.as_deref().map(parse_cursor).transpose()?;
    let limit = query.limit.unwrap_or(TELEMETRY_PAGE_BATCHES).clamp(1, TELEMETRY_PAGE_BATCHES);
    let entry = app.store.tenant(&tenant)?;
    let docs = entry.lock().await.docs.clone();
    app.authorize(&Chain::of(&tenant, &docs), &docs, &asked, &[], Rule::Members).await?;
    let mut batches: Vec<_> = entry
        .lock()
        .await
        .telemetry()?
        .into_iter()
        .filter(|b| b.body.to >= since && after.is_none_or(|a| (b.body.stream, b.body.sequence) > a))
        .collect();
    batches.sort_by_key(|b| (b.body.stream, b.body.sequence));
    let mut page = Vec::new();
    let mut bytes = 0;
    for batch in batches.into_iter().take(limit) {
        bytes += serde_json::to_vec(&batch).map_or(0, |b| b.len() + 1);
        if !page.is_empty() && bytes > TELEMETRY_PAGE_BYTES {
            break;
        }
        page.push(batch);
    }
    Ok(Json(page))
}

/// Public: a co-signature names a public release, and an enclave's key requests carry it
/// before the enclave holds keys.
async fn get_release_cosign(
    State(app): State<Arc<App>>,
    Path((tenant, measurement)): Path<(TenantId, Measurement)>,
) -> ApiResult<Json<Signed<ReleaseCosign>>> {
    let entry = app.store.tenant(&tenant)?;
    let cosign = entry.lock().await.release_cosign(&measurement)?;
    cosign.map(Json).ok_or_else(|| ApiError::not_found("no co-signature for this release"))
}

async fn put_release_cosign(
    State(app): State<Arc<App>>,
    Path((tenant, measurement)): Path<(TenantId, Measurement)>,
    asked: Asked,
    body: Bytes,
) -> ApiResult<StatusCode> {
    let cosign: Signed<ReleaseCosign> = parse(&body)?;
    same_tenant(&tenant, &cosign.body.tenant)?;
    if cosign.body.measurement != measurement {
        return Err(ApiError::bad("the co-signature is for another measurement"));
    }
    let entry = app.store.tenant(&tenant)?;
    let e = entry.lock().await;
    app.authorize(&Chain::of(&tenant, &e.docs), &e.docs, &asked, &body, Rule::Submit).await?;
    let latest = &e.docs.roots.last().ok_or_else(|| ApiError::conflict("the tenant has no root chain"))?.root.body;
    TenantVerifier::verify_admin_signed(latest, RELEASE_COSIGN_LABEL, &cosign)
        .map_err(|_| ApiError::bad("not signed by the threshold of the latest root"))?;
    e.put_release_cosign(&measurement, &cosign)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_release(
    State(app): State<Arc<App>>,
    Path((platform, measurement)): Path<(PlatformId, Measurement)>,
) -> ApiResult<Json<ReleaseEvidence>> {
    app.store
        .release(platform, &measurement)?
        .map(Json)
        .ok_or_else(|| ApiError::not_found("no evidence for this release"))
}

async fn put_release(
    State(app): State<Arc<App>>,
    Path((platform, measurement)): Path<(PlatformId, Measurement)>,
    asked: Asked,
    body: Bytes,
) -> ApiResult<StatusCode> {
    app.require_write_token(&asked)?;
    let evidence: ReleaseEvidence = parse(&body)?;
    let manifest = &evidence.manifest.body;
    if manifest.platform != platform || manifest.measurement != measurement {
        return Err(ApiError::bad("the evidence is for another release"));
    }
    let log = LogVerifier::new(app.log.clone());
    log.inclusion(&LogEntry::Release(manifest.clone()), &evidence.included)
        .map_err(|e| ApiError::bad(format!("log inclusion: {e}")))?;
    log.checkpoint(&evidence.fresh).map_err(|e| ApiError::bad(format!("fresh checkpoint: {e}")))?;
    app.store.put_release(platform, &measurement, &evidence)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_releases(
    State(app): State<Arc<App>>,
    Path(platform): Path<PlatformId>,
) -> ApiResult<Json<Vec<ReleaseEvidence>>> {
    let mut releases = app.store.releases(platform)?;
    releases.sort_by_key(|e| e.included.leaf_index);
    Ok(Json(releases))
}

async fn get_release_template(
    State(app): State<Arc<App>>,
    Path((platform, measurement)): Path<(PlatformId, Measurement)>,
) -> ApiResult<Json<serde_json::Value>> {
    app.store
        .release_template(platform, &measurement)?
        .map(Json)
        .ok_or_else(|| ApiError::not_found("no template for this release"))
}

async fn put_release_template(
    State(app): State<Arc<App>>,
    Path((platform, measurement)): Path<(PlatformId, Measurement)>,
    asked: Asked,
    body: Bytes,
) -> ApiResult<StatusCode> {
    app.require_write_token(&asked)?;
    let template: serde_json::Value = parse(&body)?;
    if !template.is_object() {
        return Err(ApiError::bad("a template is a JSON object"));
    }
    if app.store.release(platform, &measurement)?.is_none() {
        return Err(ApiError::conflict("publish the release's evidence first"));
    }
    app.store.put_release_template(platform, &measurement, &template)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_checkpoint(State(app): State<Arc<App>>) -> ApiResult<Json<SignedCheckpoint>> {
    app.latest_checkpoint().await.map(Json)
}

#[derive(Deserialize)]
struct SinceVersion {
    since_version: Option<u64>,
}

async fn get_documents(
    State(app): State<Arc<App>>,
    Path(tenant): Path<TenantId>,
    Query(query): Query<SinceVersion>,
    asked: Asked,
) -> ApiResult<Json<Documents>> {
    let entry = app.store.tenant(&tenant)?;
    let docs = entry.lock().await.docs.clone();
    app.authorize(&Chain::of(&tenant, &docs), &docs, &asked, &[], Rule::Members).await?;
    let states = entry.lock().await.logged_states(query.since_version)?;
    let checkpoint = match app.latest_checkpoint().await {
        Ok(checkpoint) => Some(checkpoint),
        Err(e) => {
            tracing::warn!(error = %e.message, "documents served without the latest checkpoint");
            None
        }
    };
    Ok(Json(Documents { roots: docs.roots, states, checkpoint }))
}

/// A proposal id: 64 lowercase hex digits.
fn check_proposal_id(id: &str) -> ApiResult<()> {
    if id.len() == 64 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        Ok(())
    } else {
        Err(ApiError::bad("a proposal id is 64 lowercase hex digits"))
    }
}

/// Whether a proposal can still be submitted: a root above the chain, or a state above the
/// current one signed for the latest root or the next.
fn still_open(docs: &TenantDocs, proposal: &Proposal) -> bool {
    let latest = docs.roots.last().map_or(0, |link| link.root.body.version);
    match &proposal.document {
        Proposed::Root(root) => root.body.version > latest,
        Proposed::State(state) => {
            state.body.root_version >= latest && docs.state.as_ref().is_none_or(|c| state.body.version > c.body.version)
        }
    }
}

/// The open proposals, oldest first; the rest are deleted.
fn open_proposals(e: &TenantEntry) -> ApiResult<Vec<Proposal>> {
    let mut open = Vec::new();
    for proposal in e.proposals()? {
        if still_open(&e.docs, &proposal) {
            open.push(proposal);
        } else {
            e.delete_proposal(&proposal.id)?;
        }
    }
    open.sort_by(|a, b| (a.created_at, &a.id).cmp(&(b.created_at, &b.id)));
    Ok(open)
}

async fn get_proposals(
    State(app): State<Arc<App>>,
    Path(tenant): Path<TenantId>,
    asked: Asked,
) -> ApiResult<Json<Vec<Proposal>>> {
    let entry = app.store.tenant(&tenant)?;
    let e = entry.lock().await;
    app.authorize(&Chain::of(&tenant, &e.docs), &e.docs, &asked, &[], Rule::Members).await?;
    open_proposals(&e).map(Json)
}

/// The signed state or root in `body` whose digest `id` is.
fn proposed(id: &str, body: &[u8]) -> ApiResult<Proposed> {
    let state = serde_json::from_slice::<SignedTenantState>(body).ok().map(Proposed::State);
    let root = serde_json::from_slice::<Signed<TenantRoot>>(body).ok().map(Proposed::Root);
    state
        .into_iter()
        .chain(root)
        .find(|document| document.id() == id)
        .ok_or_else(|| ApiError::bad("the body is not a signed state or root whose digest is the proposal id"))
}

/// The roots whose admin keys may sign `document`: the latest root, for a root proposal and a
/// state signed for it; the open root proposals of the next version, for a state signed for
/// that one. Refuses a document that cannot follow the stored chain and state.
fn signing_roots(
    docs: &TenantDocs,
    open: &[Proposal],
    document: &Proposed,
    tenant: &TenantId,
) -> ApiResult<Vec<TenantRoot>> {
    let latest = &docs
        .roots
        .last()
        .ok_or_else(|| ApiError::conflict("the tenant has no root chain; version 1 is the registrar's"))?
        .root
        .body;
    match document {
        Proposed::Root(root) => {
            same_tenant(tenant, &root.body.tenant)?;
            if root.body.version != latest.version + 1 {
                return Err(ApiError::conflict(format!("the next root is version {}", latest.version + 1)));
            }
            if root.body.threshold == 0 || usize::from(root.body.threshold) > root.body.admin_keys.len() {
                return Err(ApiError::bad("the threshold does not fit the admin keys"));
            }
            Ok(vec![latest.clone()])
        }
        Proposed::State(state) => {
            same_tenant(tenant, &state.body.tenant)?;
            if let Some(current) = &docs.state {
                if state.body.version <= current.body.version {
                    return Err(ApiError::conflict(format!(
                        "the next state is above version {}",
                        current.body.version
                    )));
                }
            }
            if state.body.root_version == latest.version {
                return Ok(vec![latest.clone()]);
            }
            if state.body.root_version != latest.version + 1 {
                return Err(ApiError::conflict(format!(
                    "signed for root version {}, the latest is {}",
                    state.body.root_version, latest.version
                )));
            }
            Ok(open
                .iter()
                .filter_map(|p| match &p.document {
                    Proposed::Root(root) if root.body.version == state.body.root_version => Some(root.body.clone()),
                    _ => None,
                })
                .collect())
        }
    }
}

/// Every signature of `signed` is by an admin key of one of `roots`, and verifies.
fn signatures_verify<T: serde::Serialize>(roots: &[TenantRoot], label: &str, signed: &Signed<T>) -> bool {
    signed.signatures.iter().all(|sig| {
        roots
            .iter()
            .flat_map(|r| &r.admin_keys)
            .any(|key| admin_key_id(key) == sig.signer && verify_admin(key, label, &signed.body, sig).is_ok())
    })
}

async fn put_proposal(
    State(app): State<Arc<App>>,
    Path((tenant, id)): Path<(TenantId, String)>,
    asked: Asked,
    body: Bytes,
) -> ApiResult<Json<Proposal>> {
    check_proposal_id(&id)?;
    let document = proposed(&id, &body)?;
    let entry = app.store.tenant(&tenant)?;
    let e = entry.lock().await;
    app.authorize(&Chain::of(&tenant, &e.docs), &e.docs, &asked, &body, Rule::Propose).await?;
    let open = open_proposals(&e)?;
    let roots = signing_roots(&e.docs, &open, &document, &tenant)?;
    let verified = match &document {
        Proposed::State(s) => signatures_verify(&roots, TENANT_STATE_LABEL, s),
        Proposed::Root(r) => signatures_verify(&roots, TENANT_ROOT_LABEL, r),
    };
    if !verified {
        return Err(ApiError::forbidden("a signature is not an admin signature of this document"));
    }
    let now = app.now();
    let existing = open.into_iter().find(|p| p.id == id);
    if existing.is_none() && e.proposals()?.len() >= MAX_PROPOSALS {
        return Err(ApiError::conflict(format!("the tenant has {MAX_PROPOSALS} open proposals")));
    }
    let mut proposal = existing.unwrap_or_else(|| Proposal {
        id: id.clone(),
        document: match &document {
            Proposed::State(s) => Proposed::State(Signed { body: s.body.clone(), signatures: Vec::new() }),
            Proposed::Root(r) => Proposed::Root(Signed { body: r.body.clone(), signatures: Vec::new() }),
        },
        created_at: now,
        updated_at: now,
    });
    let (signatures, new) = match (&mut proposal.document, document) {
        (Proposed::State(have), Proposed::State(add)) => (&mut have.signatures, add.signatures),
        (Proposed::Root(have), Proposed::Root(add)) => (&mut have.signatures, add.signatures),
        _ => return Err(ApiError::conflict("the proposal id names another kind of document")),
    };
    for sig in new {
        if !signatures.iter().any(|s| s.signer == sig.signer) {
            signatures.push(sig);
        }
    }
    if signatures.len() > MAX_PROPOSAL_SIGNATURES {
        return Err(ApiError::conflict(format!("a proposal holds at most {MAX_PROPOSAL_SIGNATURES} signatures")));
    }
    proposal.updated_at = now;
    e.put_proposal(&proposal)?;
    Ok(Json(proposal))
}

async fn delete_proposal(
    State(app): State<Arc<App>>,
    Path((tenant, id)): Path<(TenantId, String)>,
    asked: Asked,
) -> ApiResult<StatusCode> {
    check_proposal_id(&id)?;
    let entry = app.store.tenant(&tenant)?;
    let e = entry.lock().await;
    app.authorize(&Chain::of(&tenant, &e.docs), &e.docs, &asked, &[], Rule::Propose).await?;
    if e.delete_proposal(&id)? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::not_found("no such proposal"))
    }
}

/// Logs the proposal's document and stores it as the tenant's next root or state, if it holds
/// the latest root's threshold of signatures; the proposal is then gone.
async fn post_proposal_submit(
    State(app): State<Arc<App>>,
    Path((tenant, id)): Path<(TenantId, String)>,
    asked: Asked,
    body: Bytes,
) -> ApiResult<Json<Submitted>> {
    check_proposal_id(&id)?;
    let entry = app.store.tenant(&tenant)?;
    let mut e = entry.lock().await;
    let docs = e.docs.clone();
    app.authorize(&Chain::of(&tenant, &docs), &docs, &asked, &body, Rule::Propose).await?;
    let proposal = e.proposal(&id)?.ok_or_else(|| ApiError::not_found("no such proposal"))?;
    let submitted = match proposal.document {
        Proposed::State(state) => {
            let latest =
                &docs.roots.last().ok_or_else(|| ApiError::conflict("the tenant has no root chain"))?.root.body;
            if state.body.root_version == latest.version {
                TenantVerifier::verify_admin_signed(latest, TENANT_STATE_LABEL, &state).map_err(|_| {
                    ApiError::conflict(format!("not yet signed by the threshold of root version {}", latest.version))
                })?;
            }
            let logged = app
                .submit_state(&tenant, &mut e, state, None)
                .await?
                .ok_or_else(|| ApiError::conflict("this state is already current"))?;
            Submitted::State(logged)
        }
        Proposed::Root(root) => {
            let latest =
                &docs.roots.last().ok_or_else(|| ApiError::conflict("the tenant has no root chain"))?.root.body;
            if root.body.version != latest.version + 1 {
                return Err(ApiError::conflict(format!("the next root is version {}", latest.version + 1)));
            }
            TenantVerifier::verify_admin_signed(latest, TENANT_ROOT_LABEL, &root).map_err(|_| {
                ApiError::conflict(format!("not yet signed by the threshold of version {}", latest.version))
            })?;
            let leaf = LogEntry::TenantRoot(root.body.clone());
            let proof = app.log(&leaf, app.upstreams.log_append_root(&leaf).await).await?;
            let link = LoggedRoot { root, proof };
            app.store_root(&mut e, link.clone())?;
            Submitted::Root(link)
        }
    };
    e.delete_proposal(&id)?;
    Ok(Json(submitted))
}

/// Serves `router(app)` on `listener` until ctrl-c: over TLS when `tls` is set, plain HTTP
/// otherwise (behind a TLS-terminating proxy).
pub async fn serve(
    listener: tokio::net::TcpListener,
    app: Arc<App>,
    tls: Option<Arc<rustls::ServerConfig>>,
) -> std::io::Result<()> {
    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    match tls {
        Some(config) => {
            let listener = tls::TlsListener::new(listener, config)?;
            axum::serve(listener, router(app)).with_graceful_shutdown(shutdown).await
        }
        None => axum::serve(listener, router(app)).with_graceful_shutdown(shutdown).await,
    }
}
