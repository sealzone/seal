//! In-process servers for admin tests: the dev log (`seal_tlog::dev::DevLog`) over plain HTTP
//! on loopback with the `seal-tlog-dev` routes, and a fake control plane behind a TLS proxy
//! whose CA the clients trust (sim builds only). Release evidence and templates are served as
//! stored (`Stored::releases`, `Stored::templates`). The fake checks no credentials on reads;
//! it logs a submitted proposal like the real one. The same server answers as the console for
//! `seal login`, `seal use` and control tokens (`console_router`), for one user in one
//! workspace holding tenant `acme`.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::{Path as UrlPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use base64::Engine as _;
use serde::Serialize;

use seal_client::admin::{Admin, ControlClient, HttpsClient, LogClient, Proposal, Proposed, Submitted};
use seal_crypto::sign::SigningKey;
use seal_crypto::{Key32, PlatformMasterKey, ServiceKeys};
use seal_proto::release::{LogEntry, ReleaseCosign, ReleaseEvidence, SignedServiceKeyCertificate};
use seal_proto::signed::Signed;
use seal_proto::state::{LoggedRoot, LoggedState, SignedStateFreshness, SignedTenantState, TenantBundle, TenantRoot};
use seal_proto::telemetry::SignedTelemetryBatch;
use seal_proto::{PlatformId, ServiceKeyVersion, TenantId, TenantRootId, TrustedTime};
use seal_tlog::dev::DevLog;
use seal_tlog::TlogTrust;
use seal_verify::TenantTrust;

pub const TOKEN: &str = "test-write-token";
/// The CLI token the fake console issues, and the control token it hands out for it.
pub const CLI_TOKEN: &str = "sealcli_test";
pub const CONTROL_TOKEN: &str = "sealct_test";
pub const WORKSPACE: &str = "acme-corp";
pub const REGISTRAR: [u8; 32] = [0x21; 32];
/// The seed of the admin key `write_home` writes.
pub const ADMIN: [u8; 32] = [0x22; 32];

/// What `Servers::write_home` wrote.
pub struct HomeFiles {
    pub registrar: PathBuf,
    /// The admin key file (`--key-file`).
    pub key: PathBuf,
    /// The trust (`SEAL_TRUST`).
    pub trust: PathBuf,
    /// Where sim builds keep the console login (`SEAL_SIM_TOKEN_FILE`).
    pub token: PathBuf,
}

/// `seal` with the home's trust and token file, and nothing from this process's environment.
pub fn seal_command(home: &Path) -> tokio::process::Command {
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_seal"));
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("SEAL_") {
            command.env_remove(name);
        }
    }
    command
        .arg("--home")
        .arg(home)
        .env("SEAL_TRUST", home.join("trust.json"))
        .env("SEAL_SIM_TOKEN_FILE", home.join("cli-token"))
        .env("SEAL_CONTROL_TOKEN", TOKEN)
        .env("NO_COLOR", "1")
        .stdin(std::process::Stdio::null());
    command
}

pub fn acme() -> TenantId {
    TenantId::new("acme").unwrap()
}

pub fn now() -> TrustedTime {
    TrustedTime::exact(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs())
}

pub fn registrar() -> SigningKey {
    SigningKey::from_seed(&REGISTRAR)
}

pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(name: &str) -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir =
            PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("seal-cli-{name}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

type Log = Arc<Mutex<DevLog>>;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn refuse(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, msg.into()).into_response()
}

#[derive(Serialize)]
struct Index {
    index: u64,
}

#[derive(Clone)]
struct LogServer {
    log: Log,
}

fn log_router(server: LogServer) -> Router {
    async fn append(State(s): State<LogServer>, Json(entry): Json<LogEntry>) -> Response {
        match lock(&s.log).append(entry) {
            Ok(index) => Json(Index { index }).into_response(),
            Err(e) => refuse(StatusCode::BAD_REQUEST, e.to_string()),
        }
    }
    async fn entry(State(s): State<LogServer>, UrlPath(index): UrlPath<u64>) -> Response {
        match lock(&s.log).entry(index) {
            Some(entry) => Json(entry).into_response(),
            None => refuse(StatusCode::NOT_FOUND, "no such entry"),
        }
    }
    async fn proof(State(s): State<LogServer>, UrlPath(index): UrlPath<u64>) -> Response {
        let mut log = lock(&s.log);
        if index >= log.size() {
            return refuse(StatusCode::NOT_FOUND, "no such entry");
        }
        Json(log.prove(index)).into_response()
    }
    async fn checkpoint(State(s): State<LogServer>) -> Response {
        Json(lock(&s.log).checkpoint()).into_response()
    }
    async fn state(
        State(s): State<LogServer>,
        UrlPath(tenant): UrlPath<TenantId>,
        Json(state): Json<SignedTenantState>,
    ) -> Response {
        if state.body.tenant != tenant {
            return refuse(StatusCode::BAD_REQUEST, "the state is for another tenant");
        }
        match lock(&s.log).append_state(&state) {
            Ok(index) => Json(Index { index }).into_response(),
            Err(e) => refuse(StatusCode::CONFLICT, e),
        }
    }
    async fn freshness(State(s): State<LogServer>, UrlPath(tenant): UrlPath<TenantId>) -> Response {
        match lock(&s.log).freshness(&tenant) {
            Some(statement) => Json(statement).into_response(),
            None => refuse(StatusCode::NOT_FOUND, "no logged state for this tenant"),
        }
    }
    Router::new()
        .route("/v1/entries", post(append))
        .route("/v1/entries/{index}", get(entry))
        .route("/v1/proof/{index}", get(proof))
        .route("/v1/checkpoint", get(checkpoint))
        .route("/v1/tenants/{tenant}/states", post(state))
        .route("/v1/tenants/{tenant}/freshness", get(freshness))
        .with_state(server)
}

/// What the fake control plane stores for one tenant.
#[derive(Default)]
pub struct Stored {
    pub roots: Vec<LoggedRoot>,
    pub state: Option<SignedTenantState>,
    /// Every state submitted, with its proof, oldest first.
    pub states: Vec<LoggedState>,
    /// The log's statement fetched when the state was PUT, as the real control plane keeps it.
    pub log_freshness: Option<SignedStateFreshness>,
    pub tenant_freshness: Vec<SignedStateFreshness>,
    pub cosigns: BTreeMap<String, Signed<ReleaseCosign>>,
    pub telemetry: Vec<SignedTelemetryBatch>,
    pub certificates: Vec<SignedServiceKeyCertificate>,
    pub releases: Vec<ReleaseEvidence>,
    /// Release templates by measurement (hex).
    pub templates: BTreeMap<String, serde_json::Value>,
    pub proposals: BTreeMap<String, Proposal>,
    /// Polls of the fake console's device code so far.
    pub device_polls: u32,
    /// CLI tokens revoked by `seal logout`.
    pub revoked: Vec<String>,
    /// Control tokens issued, by scope.
    pub control_tokens: Vec<String>,
}

#[derive(Clone)]
struct Control {
    log: Log,
    stored: Arc<Mutex<Stored>>,
}

/// The write token, a console control token, or a signed request (whose signature the fake
/// does not check).
fn authorized(headers: &HeaderMap) -> bool {
    let value = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or_default();
    value == format!("Bearer {TOKEN}") || value == format!("Bearer {CONTROL_TOKEN}") || value.starts_with("SealSigned ")
}

fn signed_in(headers: &HeaderMap) -> bool {
    headers.get("authorization").and_then(|v| v.to_str().ok()) == Some(&format!("Bearer {CLI_TOKEN}"))
}

fn console_router(control: Control) -> Router {
    use serde_json::json;
    fn unauthenticated() -> Response {
        (StatusCode::UNAUTHORIZED, Json(json!({"code": "unauthenticated", "message": "sign in"}))).into_response()
    }
    fn seal_tenant(c: &Control) -> Option<String> {
        let s = lock(&c.stored);
        s.roots.first().map(|r| format!("acme@{}", seal_proto::state::root_id(&r.root.body)))
    }
    async fn device(Json(body): Json<serde_json::Value>) -> Response {
        if !body["client"].as_str().is_some_and(|c| c.starts_with("seal ")) {
            return (StatusCode::BAD_REQUEST, Json(json!({"code": "bad_request", "message": "client"})))
                .into_response();
        }
        Json(json!({"device_code": "device-secret", "user_code": "ABCD-EFGH",
                    "verification_url": "https://console.test/cli?code=ABCD-EFGH", "interval": 1, "expires_in": 600}))
        .into_response()
    }
    async fn token(State(c): State<Control>, Json(body): Json<serde_json::Value>) -> Response {
        if body["device_code"] != "device-secret" {
            return (StatusCode::GONE, Json(json!({"error": "expired_token"}))).into_response();
        }
        let mut s = lock(&c.stored);
        s.device_polls += 1;
        match s.device_polls {
            1 => (StatusCode::BAD_REQUEST, Json(json!({"error": "authorization_pending"}))).into_response(),
            _ => {
                Json(json!({"token": CLI_TOKEN, "user": {"email": "admin@acme.test"}, "expires_at": 1_900_000_000u64}))
                    .into_response()
            }
        }
    }
    async fn logout(State(c): State<Control>, headers: HeaderMap) -> Response {
        if !signed_in(&headers) {
            return unauthenticated();
        }
        lock(&c.stored).revoked.push(CLI_TOKEN.into());
        StatusCode::NO_CONTENT.into_response()
    }
    async fn me(headers: HeaderMap) -> Response {
        if !signed_in(&headers) {
            return unauthenticated();
        }
        Json(json!({"user": {"id": "u1", "email": "admin@acme.test", "name": "Ada"},
                    "workspaces": [{"slug": WORKSPACE, "name": "Acme", "role": "owner"}],
                    "identities": [], "sessions": []}))
        .into_response()
    }
    async fn tenants(State(c): State<Control>, headers: HeaderMap, UrlPath(w): UrlPath<String>) -> Response {
        if !signed_in(&headers) {
            return unauthenticated();
        }
        let list: Vec<serde_json::Value> = match (w.as_str(), seal_tenant(&c)) {
            (WORKSPACE, Some(pin)) => {
                vec![json!({"id": "acme", "plan": "developer", "status": "active", "seal_tenant": pin})]
            }
            _ => vec![],
        };
        Json(list).into_response()
    }
    async fn tenant(State(c): State<Control>, headers: HeaderMap, UrlPath(t): UrlPath<String>) -> Response {
        if !signed_in(&headers) {
            return unauthenticated();
        }
        match (t.as_str(), seal_tenant(&c)) {
            ("acme", Some(pin)) => {
                Json(json!({"id": "acme", "plan": "developer", "status": "active", "seal_tenant": pin,
                                              "workspace": WORKSPACE, "pending_changes": 0}))
                .into_response()
            }
            _ => (StatusCode::NOT_FOUND, Json(json!({"code": "not_found", "message": "tenant not found"})))
                .into_response(),
        }
    }
    async fn control_token(
        State(c): State<Control>,
        headers: HeaderMap,
        Json(body): Json<serde_json::Value>,
    ) -> Response {
        if !signed_in(&headers) {
            return unauthenticated();
        }
        lock(&c.stored).control_tokens.push(body["scope"].as_str().unwrap_or_default().to_string());
        let exp = now().now + 300;
        Json(json!({"token": CONTROL_TOKEN, "expires_at": exp, "control_url": "https://control.test"})).into_response()
    }
    Router::new()
        .route("/api/v1/cli/device", post(device))
        .route("/api/v1/cli/token", post(token))
        .route("/api/v1/cli/logout", post(logout))
        .route("/api/v1/me", get(me))
        .route("/api/v1/workspaces/{w}/tenants", get(tenants))
        .route("/api/v1/tenants/{t}", get(tenant))
        .route("/api/v1/tenants/{t}/control-token", post(control_token))
        .with_state(control)
}

fn control_router(control: Control) -> Router {
    async fn bundle(State(c): State<Control>, UrlPath(_tenant): UrlPath<TenantId>) -> Response {
        let s = lock(&c.stored);
        let Some(state) = s.state.clone() else { return refuse(StatusCode::NOT_FOUND, "no such tenant") };
        let mut freshness: Vec<_> = s.log_freshness.iter().cloned().collect();
        freshness.extend(s.tenant_freshness.iter().filter(|f| f.body.version == state.body.version).cloned());
        Json(TenantBundle {
            root_chain: s.roots.clone(),
            state,
            signals: vec![],
            ended_sessions: vec![],
            freshness,
            wrap_keys: vec![],
            states: s.states.clone(),
            checkpoint: Some(lock(&c.log).checkpoint()),
            anchors: Vec::new(),
        })
        .into_response()
    }
    async fn root(State(c): State<Control>, headers: HeaderMap, body: Bytes) -> Response {
        if !authorized(&headers) {
            return refuse(StatusCode::UNAUTHORIZED, "write token");
        }
        let link: LoggedRoot = match serde_json::from_slice(&body) {
            Ok(link) => link,
            Err(e) => return refuse(StatusCode::BAD_REQUEST, e.to_string()),
        };
        let mut s = lock(&c.stored);
        // As the real control plane: a version already in the chain is accepted again unchanged.
        if s.roots.iter().any(|r| r.root == link.root) {
            return StatusCode::NO_CONTENT.into_response();
        }
        if link.root.body.version != s.roots.len() as u64 + 1 {
            return refuse(StatusCode::CONFLICT, "not the next version");
        }
        s.roots.push(link);
        StatusCode::NO_CONTENT.into_response()
    }
    async fn state(
        State(c): State<Control>,
        UrlPath(tenant): UrlPath<TenantId>,
        headers: HeaderMap,
        body: Bytes,
    ) -> Response {
        if !authorized(&headers) {
            return refuse(StatusCode::UNAUTHORIZED, "write token");
        }
        let state: SignedTenantState = match serde_json::from_slice(&body) {
            Ok(state) => state,
            Err(e) => return refuse(StatusCode::BAD_REQUEST, e.to_string()),
        };
        let Some(statement) = lock(&c.log).freshness(&tenant) else {
            return refuse(StatusCode::CONFLICT, "the log has no state for this tenant");
        };
        let mut s = lock(&c.stored);
        if s.state.as_ref() == Some(&state) {
            return StatusCode::NO_CONTENT.into_response();
        }
        if s.state.as_ref().is_some_and(|old| old.body.version >= state.body.version) {
            return refuse(StatusCode::CONFLICT, "version does not increase");
        }
        if statement.body.version != state.body.version {
            return refuse(StatusCode::CONFLICT, "the log has not recorded this state as the latest");
        }
        s.state = Some(state);
        s.log_freshness = Some(statement);
        StatusCode::NO_CONTENT.into_response()
    }
    async fn freshness(State(c): State<Control>, body: Bytes) -> Response {
        match serde_json::from_slice::<SignedStateFreshness>(&body) {
            Ok(statement) => {
                lock(&c.stored).tenant_freshness.push(statement);
                StatusCode::NO_CONTENT.into_response()
            }
            Err(e) => refuse(StatusCode::BAD_REQUEST, e.to_string()),
        }
    }
    async fn cosign(
        State(c): State<Control>,
        UrlPath((_tenant, measurement)): UrlPath<(TenantId, String)>,
        headers: HeaderMap,
        body: Bytes,
    ) -> Response {
        if !authorized(&headers) {
            return refuse(StatusCode::UNAUTHORIZED, "write token");
        }
        match serde_json::from_slice(&body) {
            Ok(cosign) => {
                lock(&c.stored).cosigns.insert(measurement, cosign);
                StatusCode::NO_CONTENT.into_response()
            }
            Err(e) => refuse(StatusCode::BAD_REQUEST, e.to_string()),
        }
    }
    async fn get_cosign(
        State(c): State<Control>,
        UrlPath((_tenant, measurement)): UrlPath<(TenantId, String)>,
    ) -> Response {
        match lock(&c.stored).cosigns.get(&measurement).cloned() {
            Some(cosign) => Json(cosign).into_response(),
            None => refuse(StatusCode::NOT_FOUND, "no co-signature for this release"),
        }
    }
    async fn proposals(State(c): State<Control>) -> Response {
        Json(lock(&c.stored).proposals.values().cloned().collect::<Vec<_>>()).into_response()
    }
    /// Merges the body's signatures into the proposal its id names; checks nothing else.
    async fn put_proposal(
        State(c): State<Control>,
        UrlPath((_tenant, id)): UrlPath<(TenantId, String)>,
        body: Bytes,
    ) -> Response {
        let state = serde_json::from_slice::<SignedTenantState>(&body).ok().map(Proposed::State);
        let root = serde_json::from_slice::<Signed<TenantRoot>>(&body).ok().map(Proposed::Root);
        let Some(document) = state.into_iter().chain(root).find(|d| d.id() == id) else {
            return refuse(StatusCode::BAD_REQUEST, "not the document the id names");
        };
        let mut s = lock(&c.stored);
        let proposal = s.proposals.entry(id.clone()).or_insert(Proposal {
            id,
            document: document.clone(),
            created_at: 0,
            updated_at: 0,
        });
        let (have, add) = match (&mut proposal.document, document) {
            (Proposed::State(have), Proposed::State(add)) => (&mut have.signatures, add.signatures),
            (Proposed::Root(have), Proposed::Root(add)) => (&mut have.signatures, add.signatures),
            _ => return refuse(StatusCode::CONFLICT, "another kind"),
        };
        for sig in add {
            if !have.contains(&sig) {
                have.push(sig);
            }
        }
        Json(proposal.clone()).into_response()
    }
    async fn delete_proposal(
        State(c): State<Control>,
        UrlPath((_tenant, id)): UrlPath<(TenantId, String)>,
    ) -> Response {
        match lock(&c.stored).proposals.remove(&id) {
            Some(_) => StatusCode::NO_CONTENT.into_response(),
            None => refuse(StatusCode::NOT_FOUND, "no such proposal"),
        }
    }
    /// Logs the proposal's document (the dev log checks a state's signatures) and stores it.
    async fn submit(State(c): State<Control>, UrlPath((tenant, id)): UrlPath<(TenantId, String)>) -> Response {
        let Some(proposal) = lock(&c.stored).proposals.remove(&id) else {
            return refuse(StatusCode::NOT_FOUND, "no such proposal");
        };
        let mut log = lock(&c.log);
        let submitted = match proposal.document {
            Proposed::State(state) => {
                // As the real control plane: a state the log already holds is found there.
                let digest = seal_proto::codec::labeled_digest(seal_proto::state::TENANT_STATE_LABEL, &state.body);
                let logged = (0..log.size())
                    .find(|&i| matches!(log.entry(i), Some(LogEntry::TenantState(leaf)) if leaf.digest == digest));
                let index = match logged.map(Ok).unwrap_or_else(|| log.append_state(&state)) {
                    Ok(index) => index,
                    Err(e) => return refuse(StatusCode::CONFLICT, e),
                };
                let mut s = lock(&c.stored);
                s.log_freshness = log.freshness(&tenant);
                s.state = Some(state.clone());
                let logged = LoggedState { state, proof: log.prove(index) };
                s.states.push(logged.clone());
                Submitted::State(logged)
            }
            Proposed::Root(root) => {
                let index = log.append(LogEntry::TenantRoot(root.body.clone())).unwrap();
                let link = LoggedRoot { root, proof: log.prove(index) };
                lock(&c.stored).roots.push(link.clone());
                Submitted::Root(link)
            }
        };
        Json(submitted).into_response()
    }
    async fn telemetry(State(c): State<Control>) -> Response {
        Json(lock(&c.stored).telemetry.clone()).into_response()
    }
    async fn certificates(State(c): State<Control>) -> Response {
        Json(lock(&c.stored).certificates.clone()).into_response()
    }
    async fn releases(State(c): State<Control>) -> Response {
        Json(lock(&c.stored).releases.clone()).into_response()
    }
    async fn release(State(c): State<Control>, UrlPath((_platform, m)): UrlPath<(String, String)>) -> Response {
        let found = lock(&c.stored).releases.iter().find(|e| e.manifest.body.measurement.to_string() == m).cloned();
        match found {
            Some(evidence) => Json(evidence).into_response(),
            None => refuse(StatusCode::NOT_FOUND, "no evidence for this release"),
        }
    }
    async fn template(State(c): State<Control>, UrlPath((_platform, m)): UrlPath<(String, String)>) -> Response {
        match lock(&c.stored).templates.get(&m).cloned() {
            Some(template) => Json(template).into_response(),
            None => refuse(StatusCode::NOT_FOUND, "no template for this release"),
        }
    }
    async fn checkpoint(State(c): State<Control>) -> Response {
        Json(lock(&c.log).checkpoint()).into_response()
    }
    Router::new()
        .route("/v1/releases/{platform}", get(releases))
        .route("/v1/releases/{platform}/{measurement}", get(release))
        .route("/v1/releases/{platform}/{measurement}/template", get(template))
        .route("/v1/checkpoint", get(checkpoint))
        .route("/v1/tenants/{tenant}/bundle", get(bundle))
        .route("/v1/tenants/{tenant}/root", put(root))
        .route("/v1/tenants/{tenant}/state", put(state))
        .route("/v1/tenants/{tenant}/freshness", post(freshness))
        .route("/v1/tenants/{tenant}/release-cosigns/{measurement}", get(get_cosign).put(cosign))
        .route("/v1/tenants/{tenant}/telemetry", get(telemetry))
        .route("/v1/tenants/{tenant}/proposals", get(proposals))
        .route("/v1/tenants/{tenant}/proposals/{id}", put(put_proposal).delete(delete_proposal))
        .route("/v1/tenants/{tenant}/proposals/{id}/submit", post(submit))
        .route("/v1/tenants/{tenant}/service-key-certificates", get(certificates))
        .with_state(control.clone())
        .merge(console_router(control))
}

/// The fake control plane's TLS identity: a deterministic CA and a leaf for `localhost`.
fn tls() -> seal_crypto::TlsKey {
    let master = PlatformMasterKey::from_root_secret(PlatformId::Sim, &Key32::from_bytes([0x77; 32]));
    let keys = master.release_service(&TenantId::new("control").unwrap(), &TenantRootId([0; 32]), ServiceKeyVersion(1));
    ServiceKeys::from_released(PlatformId::Sim, &keys).unwrap().tls
}

fn names() -> Vec<String> {
    vec!["localhost".to_string()]
}

pub fn ca_pem() -> String {
    let der = tls().ca_certificate_der(&names()).unwrap();
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let lines: Vec<&str> = b64.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap()).collect();
    format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", lines.join("\n"))
}

async fn serve_plain(router: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await });
    addr
}

/// A TLS-terminating proxy in front of `backend`; returns its address.
async fn tls_proxy(backend: SocketAddr) -> SocketAddr {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    let tls = tls();
    let chain = vec![
        CertificateDer::from(tls.leaf_certificate_der(&names()).unwrap()),
        CertificateDer::from(tls.ca_certificate_der(&names()).unwrap()),
    ];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(tls.private_key_pkcs8_der().to_vec()));
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { continue };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else { return };
                let Ok(mut upstream) = tokio::net::TcpStream::connect(backend).await else { return };
                let _ = tokio::io::copy_bidirectional(&mut tls, &mut upstream).await;
            });
        }
    });
    addr
}

/// A dev log and a fake control plane, both in process.
pub struct Servers {
    pub log: Log,
    pub stored: Arc<Mutex<Stored>>,
    pub log_url: url::Url,
    pub control_url: url::Url,
    pub dir: TempDir,
}

impl Servers {
    pub async fn start(name: &str) -> Self {
        let dir = TempDir::new(name);
        let log = Arc::new(Mutex::new(DevLog::open(&dir.0.join("log"), [0x42; 32], 3, 2).unwrap()));
        let stored = Arc::new(Mutex::new(Stored::default()));
        let log_addr = serve_plain(log_router(LogServer { log: log.clone() })).await;
        let control = serve_plain(control_router(Control { log: log.clone(), stored: stored.clone() })).await;
        let proxy = tls_proxy(control).await;
        Self {
            log,
            stored,
            log_url: url::Url::parse(&format!("http://127.0.0.1:{}/", log_addr.port())).unwrap(),
            control_url: url::Url::parse(&format!("https://localhost:{}/", proxy.port())).unwrap(),
            dir,
        }
    }

    pub fn tlog_trust(&self) -> TlogTrust {
        lock(&self.log).trust()
    }

    pub fn tenant_trust(&self) -> TenantTrust {
        TenantTrust { tlog: self.tlog_trust(), registrar_keys: vec![registrar().public_key()], registrar_threshold: 1 }
    }

    pub fn https(&self) -> Arc<HttpsClient> {
        seal_client::admin::https_with_extra_roots(ca_pem().as_bytes()).unwrap()
    }

    pub fn admin(&self, root_id: Option<TenantRootId>) -> Admin {
        let https = self.https();
        Admin::new(
            acme(),
            root_id,
            self.tenant_trust(),
            ControlClient::new(self.control_url.clone(), https.clone(), Some(TOKEN.into())),
            LogClient::with_https(self.log_url.clone(), https),
        )
    }

    /// The bundle as stored, verified like any reader would.
    pub fn verified(&self) -> seal_verify::VerifiedTenant {
        self.verify_at(now()).unwrap()
    }

    /// Moves the log's clock (its witnesses and freshness statements) `secs` ahead and renews
    /// the stored statement, as time passing does; returns the new time.
    pub fn advance(&self, secs: u64) -> TrustedTime {
        let at = now().now + secs;
        let mut log = lock(&self.log);
        log.set_clock_offset(secs as i64);
        lock(&self.stored).log_freshness = log.freshness(&acme());
        TrustedTime::exact(at)
    }

    /// The bundle as stored, verified at `time`.
    pub fn verify_at(&self, time: TrustedTime) -> Result<seal_verify::VerifiedTenant, seal_verify::VerifyError> {
        let bundle = {
            let s = lock(&self.stored);
            let state = s.state.clone().unwrap();
            let mut freshness: Vec<_> = s.log_freshness.iter().cloned().collect();
            freshness.extend(s.tenant_freshness.iter().cloned());
            TenantBundle {
                root_chain: s.roots.clone(),
                state,
                signals: vec![],
                ended_sessions: vec![],
                freshness,
                wrap_keys: vec![],
                states: s.states.clone(),
                checkpoint: Some(lock(&self.log).checkpoint()),
                anchors: Vec::new(),
            }
        };
        seal_verify::TenantVerifier::new(self.tenant_trust(), vec![]).verify(&acme(), &bundle, &time)
    }

    /// Writes into `home` a `seal` configuration pointing at these servers, the trust
    /// (`trust.json`, tenants only), the registrar key and an admin key.
    pub fn write_home(&self, home: &Path) -> HomeFiles {
        std::fs::create_dir_all(home).unwrap();
        let ca = home.join("ca.pem");
        std::fs::write(&ca, ca_pem()).unwrap();
        let t = self.tlog_trust();
        let tlog = serde_json::json!({
            "origin": t.origin,
            "log_key": t.log_key,
            "witness_keys": t.witness_keys,
            "witness_quorum": t.witness_quorum,
        });
        let config = serde_json::json!({
            "log_url": self.log_url.as_str(),
            "control_url": self.control_url.as_str(),
            "console_url": self.control_url.as_str(),
            "sim": {"extra_roots": ca},
        });
        std::fs::write(home.join("config.json"), serde_json::to_vec_pretty(&config).unwrap()).unwrap();
        let trust = home.join("trust.json");
        let tenants = serde_json::json!({"tenants": {"tlog": tlog, "registrar_keys": [registrar().public_key()], "registrar_threshold": 1}});
        std::fs::write(&trust, serde_json::to_vec_pretty(&tenants).unwrap()).unwrap();
        let hex = |seed: &[u8; 32]| seed.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let registrar_file = home.join("registrar.key");
        std::fs::write(&registrar_file, hex(&REGISTRAR)).unwrap();
        let key = home.join("admin.key");
        std::fs::write(&key, hex(&ADMIN)).unwrap();
        HomeFiles { registrar: registrar_file, key, trust, token: home.join("cli-token") }
    }
}
