//! Separate administration surface: manages signed tenant roots and grants.
//! Admin signatures alone do not authorize runtime app operations.
//! Storage write credentials are not tenant-admin signing authority.
//!
//! Admin-side clients for the CLI: the control plane (`seal_control::client`) and the
//! transparency log (`LogClient`), and `Admin`, the workflow every admin command follows:
//! fetch the bundle, verify it (`TenantVerifier::verify`, the expected root id, and the log's
//! own freshness statement, so a control plane serving an older state is caught), apply an
//! edit to the state in force, show the diff and its classification (`seal_verify::change`:
//! narrowing applies at once, widening waits the pending window), sign the next `TenantState`
//! (the latest version + 1) with the admin keys, and
//! hand it to the control plane as a proposal (`PUT /proposals/{id}`), the same endpoints the
//! console uses. With the root's threshold of signatures it is submitted at once (the control
//! plane logs and stores it, and the returned inclusion proof is checked); with fewer, it waits
//! for other admins to add theirs from their own machines (`sign_proposal`), then `submit`.
//! Everything fetched is verified with `seal-verify` before it is shown or
//! re-signed, so a malicious control service cannot get an admin to sign an injected grant.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Display;
use std::sync::Arc;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use seal_crypto::sign::{admin_key_id, verify, SigningKey};
use seal_proto::codec::labeled_digest;
use seal_proto::identity::{GitHubScope, IdentityMatcher};
use seal_proto::release::{
    LogEntry, ReleaseCosign, SignedCheckpoint, TenantStateLeaf, TlogProof, RELEASE_COSIGN_LABEL,
};
use seal_proto::signed::Signed;
use seal_proto::state::{
    root_id, AdminKey, LoggedRoot, LoggedState, SignedStateFreshness, SignedTenantState, StateFreshness, TenantBundle,
    TenantKeyVersions, TenantRoot, TenantState, STATE_FRESHNESS_LABEL, TENANT_ROOT_LABEL, TENANT_STATE_LABEL,
};
use seal_proto::{ErrorCode, KeyId, Measurement, PlatformId, TenantId, TenantKeyVersion, TenantRootId, TrustedTime};
use seal_tlog::LogVerifier;
use seal_verify::change::{self, Change, Difference};
use seal_verify::{TenantTrust, TenantVerifier, VerifiedTenant, VerifyError};

use crate::ClientError;

/// The control plane client, shared with the enclave, and what its proposal endpoints carry.
pub use seal_control::client::{
    ControlClient, ControlError, Credential, Proposal, Proposed, SigningKeyCredential, Submitted, Target,
};
/// The HTTPS client both clients run on (baked roots, no pins).
pub use seal_net::HttpsClient;
/// The log trust `TenantTrust` carries, for callers building one.
pub use seal_tlog::TlogTrust;

/// An `HttpsClient` over TCP that trusts `seal_net::baked_roots()` only.
pub fn https() -> Arc<HttpsClient> {
    let connector = seal_net::BakedRootsConnector::new(Arc::new(seal_net::TcpDialer));
    Arc::new(HttpsClient::new(Arc::new(connector)))
}

/// Sim builds: an `HttpsClient` that also trusts the PEM certificates in `pem` (a local test CA).
#[cfg(feature = "sim")]
pub fn https_with_extra_roots(pem: &[u8]) -> Result<Arc<HttpsClient>, ClientError> {
    let connector = seal_net::BakedRootsConnector::with_extra_roots(Arc::new(seal_net::TcpDialer), pem)
        .map_err(|e| ClientError::Invalid(format!("extra roots: {e}")))?;
    Ok(Arc::new(HttpsClient::new(Arc::new(connector))))
}

fn control_error(e: ControlError) -> ClientError {
    match e {
        ControlError::Net(e) => ClientError::Network(format!("control plane: {e}")),
        other => ClientError::Seal { code: other.code(), message: format!("control plane: {other}") },
    }
}

fn verification(what: &str, e: impl Display) -> ClientError {
    ClientError::Verification(format!("{what}: {e}"))
}

/// At most 200 printable characters of an untrusted response body, for error messages.
fn excerpt(body: &[u8]) -> String {
    String::from_utf8_lossy(body).chars().filter(|c| !c.is_control()).take(200).collect()
}

#[derive(Clone, Copy)]
enum Method {
    Get,
    Post,
}

#[derive(Deserialize)]
struct Index {
    index: u64,
}

/// HTTP client for the transparency log (`seal-tlog-dev` API in dev): `POST /v1/entries`,
/// `GET /v1/proof/{index}`, `GET /v1/checkpoint`, `GET /v1/entries/{index}`,
/// `POST /v1/tenants/{tenant}/states`, `GET /v1/tenants/{tenant}/freshness`. The base URL
/// must be `https://`; sim builds also reach plain `http://` on loopback (the dev log serves
/// plain HTTP). What it returns is unverified: callers check proofs and signatures against
/// their `TlogTrust`.
pub struct LogClient {
    /// The base URL without a trailing slash.
    base: String,
    https: Arc<HttpsClient>,
}

impl LogClient {
    /// Over `https()` (baked roots).
    pub fn new(base: url::Url) -> Self {
        Self::with_https(base, https())
    }

    pub fn with_https(base: url::Url, https: Arc<HttpsClient>) -> Self {
        Self { base: base.as_str().trim_end_matches('/').to_string(), https }
    }

    async fn request(&self, method: Method, path: &str, body: Option<&[u8]>) -> Result<(u16, Vec<u8>), ClientError> {
        let url = format!("{}{path}", self.base);
        #[cfg(feature = "sim")]
        if url.starts_with("http://") {
            return plain::request(method, &url, body).await;
        }
        let headers = [("accept", "application/json")];
        let result = match method {
            Method::Get => self.https.get(&url, &headers).await,
            Method::Post => self.https.post(&url, &headers, body.unwrap_or_default()).await,
        };
        result.map_err(|e| ClientError::Network(format!("log: {e}")))
    }

    async fn json<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<T, ClientError> {
        let (status, body) = self.request(method, path, body).await?;
        if !(200..300).contains(&status) {
            let code = if (400..500).contains(&status) { ErrorCode::BadRequest } else { ErrorCode::Unavailable };
            return Err(ClientError::Seal { code, message: format!("log answered {status}: {}", excerpt(&body)) });
        }
        serde_json::from_slice(&body).map_err(|e| ClientError::Network(format!("log: malformed response: {e}")))
    }

    async fn post_json<B: Serialize, T: DeserializeOwned>(&self, path: &str, body: &B) -> Result<T, ClientError> {
        let body = serde_json::to_vec(body).map_err(|e| ClientError::Invalid(e.to_string()))?;
        self.json(Method::Post, path, Some(&body)).await
    }

    pub async fn append(&self, entry: &LogEntry) -> Result<u64, ClientError> {
        let index: Index = self.post_json("/v1/entries", entry).await?;
        Ok(index.index)
    }

    pub async fn prove(&self, index: u64) -> Result<TlogProof, ClientError> {
        self.json(Method::Get, &format!("/v1/proof/{index}"), None).await
    }

    /// The log's latest checkpoint.
    pub async fn checkpoint(&self) -> Result<SignedCheckpoint, ClientError> {
        self.json(Method::Get, "/v1/checkpoint", None).await
    }

    /// The entry at `index` (`GET /v1/entries/{index}`), for scanning the log. Check it with
    /// `prove(index)`: the log could return anything.
    pub async fn entry(&self, index: u64) -> Result<LogEntry, ClientError> {
        self.json(Method::Get, &format!("/v1/entries/{index}"), None).await
    }

    /// Logs a newly signed state (the log checks the admin signatures and the version). The
    /// control plane logs the states proposals submit; a state logged here goes to it with its
    /// proof (`ControlClient::put_state`).
    pub async fn append_state(&self, tenant: &TenantId, state: &SignedTenantState) -> Result<u64, ClientError> {
        let index: Index = self.post_json(&format!("/v1/tenants/{tenant}/states"), state).await?;
        Ok(index.index)
    }

    /// The log's freshness statement for the tenant's latest state. Admin commands compare
    /// it with the bundle they fetched, so a control plane serving an older state is caught.
    pub async fn freshness(&self, tenant: &TenantId) -> Result<SignedStateFreshness, ClientError> {
        self.json(Method::Get, &format!("/v1/tenants/{tenant}/freshness"), None).await
    }
}

/// Sim builds: one plain HTTP/1.1 request to a loopback address (the dev log serves plain HTTP).
#[cfg(feature = "sim")]
mod plain {
    use http_body_util::{BodyExt, Full, Limited};
    use hyper::body::Bytes;
    use hyper_util::rt::TokioIo;

    use super::Method;
    use crate::ClientError;

    const MAX_BODY: usize = 1 << 20;
    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

    fn is_loopback(url: &url::Url) -> bool {
        match url.host() {
            Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            None => false,
        }
    }

    pub(super) async fn request(method: Method, url: &str, body: Option<&[u8]>) -> Result<(u16, Vec<u8>), ClientError> {
        let err = |e: &dyn std::fmt::Display| ClientError::Network(format!("log {url}: {e}"));
        let parsed = url::Url::parse(url).map_err(|e| err(&e))?;
        if !is_loopback(&parsed) {
            return Err(ClientError::Invalid(format!("{url}: plain HTTP is allowed only on loopback")));
        }
        let host = parsed.host_str().ok_or_else(|| err(&"no host"))?.to_string();
        let port = parsed.port_or_known_default().unwrap_or(80);
        let path = match parsed.query() {
            Some(q) => format!("{}?{q}", parsed.path()),
            None => parsed.path().to_string(),
        };
        let exchange = async {
            let addr = host.trim_start_matches('[').trim_end_matches(']').to_string();
            let stream = tokio::net::TcpStream::connect((addr.as_str(), port)).await.map_err(|e| err(&e))?;
            let (mut sender, conn) =
                hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.map_err(|e| err(&e))?;
            let conn = tokio::spawn(conn);
            let method = match method {
                Method::Get => hyper::Method::GET,
                Method::Post => hyper::Method::POST,
            };
            let mut req = hyper::Request::builder()
                .method(method)
                .uri(path)
                .header(hyper::header::HOST, format!("{host}:{port}"))
                .header(hyper::header::ACCEPT, "application/json");
            if body.is_some() {
                req = req.header(hyper::header::CONTENT_TYPE, "application/json");
            }
            let req = req.body(Full::new(Bytes::copy_from_slice(body.unwrap_or_default()))).map_err(|e| err(&e))?;
            let resp = sender.send_request(req).await.map_err(|e| err(&e))?;
            let status = resp.status().as_u16();
            let body = Limited::new(resp.into_body(), MAX_BODY).collect().await.map_err(|e| err(&e))?;
            conn.abort();
            Ok((status, body.to_bytes().to_vec()))
        };
        tokio::time::timeout(TIMEOUT, exchange).await.map_err(|_| err(&"timed out"))?
    }
}

/// A verified tenant as an admin command sees it: the bundle as fetched and what verification
/// returned. Only `tenant` is to be trusted; `bundle` is kept for its proofs.
pub struct Current {
    pub bundle: TenantBundle,
    pub tenant: VerifiedTenant,
}

/// A signed-to-be state and how it differs from the one in force, for the admin to confirm.
pub struct Draft {
    /// The state in force.
    pub old: TenantState,
    pub new: TenantState,
    /// `diff(old, new)`.
    pub changes: Vec<String>,
    /// `change::diff_states(old, new)`.
    pub differences: Vec<Difference>,
    /// Narrowing applies at once; widening once public for `old`'s pending window.
    pub change: Change,
    /// The pending states it supersedes when it applies at once: they never take effect.
    pub supersedes: Vec<u64>,
}

/// What `Admin::init` created or, resuming, found.
pub struct Initialized {
    pub root_id: TenantRootId,
    pub root: LoggedRoot,
    pub state: SignedTenantState,
    /// What an earlier run had already done, one line each (empty for a fresh tenant).
    pub resumed: Vec<String>,
}

/// What `Admin::verify_roots` found. Every finding is evidence against the log or the
/// registrar; none is expected.
pub struct RootScan {
    /// Log entries scanned; `None` when the log does not serve entries (`GET /v1/entries/{index}`),
    /// in which case only the chain and freshness checks ran.
    pub scanned: Option<u64>,
    pub findings: Vec<String>,
}

/// The admin workflow for one tenant (module docs). Holds no keys: callers pass the admin
/// keys to each signing step.
pub struct Admin {
    tenant: TenantId,
    root_id: Option<TenantRootId>,
    trust: TenantTrust,
    /// Guardian keys whose `TenantAnchor`s bundles may start from.
    anchor_keys: Vec<seal_proto::PublicKey>,
    control: ControlClient,
    log: LogClient,
}

fn not_signed(what: &str, root: &TenantRoot, keys: &[SigningKey]) -> ClientError {
    let have =
        keys.iter().filter(|k| root.admin_keys.contains(&AdminKey::Ed25519 { public_key: k.public_key() })).count();
    ClientError::Invalid(format!(
        "{what} needs {} signatures from admin keys of root version {}; {have} of the given keys are among them",
        root.threshold, root.version
    ))
}

/// `body` signed by every key in `keys` that is an admin key of `root`, checked to meet its threshold.
fn admin_sign<T: Serialize>(
    what: &str,
    root: &TenantRoot,
    label: &str,
    body: T,
    keys: &[SigningKey],
) -> Result<Signed<T>, ClientError> {
    let signed = cosign(root, label, Signed { body, signatures: Vec::new() }, keys);
    TenantVerifier::verify_admin_signed(root, label, &signed).map_err(|_| not_signed(what, root, keys))?;
    Ok(signed)
}

/// `signed` with the signatures of every key in `keys` that is an admin key of `root` and has
/// not signed it yet.
pub fn cosign<T: Serialize>(root: &TenantRoot, label: &str, mut signed: Signed<T>, keys: &[SigningKey]) -> Signed<T> {
    for key in keys {
        let admin = root.admin_keys.contains(&AdminKey::Ed25519 { public_key: key.public_key() });
        if admin && !signed.signatures.iter().any(|s| s.signer == key.key_id()) {
            key.cosign(label, &mut signed);
        }
    }
    signed
}

/// Whether `signed` carries `root`'s threshold of valid admin signatures.
pub fn meets_threshold<T: Serialize>(root: &TenantRoot, label: &str, signed: &Signed<T>) -> bool {
    TenantVerifier::verify_admin_signed(root, label, signed).is_ok()
}

/// The log's statement must be signed by its key and name exactly `state`.
/// The consecutive run of `states` (by version) that ends with `latest`; empty when none does.
fn consecutive_to(states: &[LoggedState], latest: &SignedTenantState) -> Vec<LoggedState> {
    let Some(end) = states.iter().position(|s| s.state.body == latest.body) else { return Vec::new() };
    let start = states[..=end]
        .windows(2)
        .rposition(|w| w[0].state.body.version + 1 != w[1].state.body.version)
        .map_or(0, |i| i + 1);
    states[start..=end].to_vec()
}

fn check_log_statement(
    log_key: &seal_proto::PublicKey,
    state: &TenantState,
    statement: &SignedStateFreshness,
) -> Result<(), ClientError> {
    let signed =
        statement.signatures.iter().any(|sig| verify(log_key, STATE_FRESHNESS_LABEL, &statement.body, sig).is_ok());
    if !signed {
        return Err(ClientError::Verification("the log's freshness statement is not signed by the log key".into()));
    }
    let body = &statement.body;
    if body.tenant != state.tenant {
        return Err(ClientError::Verification("the log's freshness statement is for another tenant".into()));
    }
    if body.version != state.version || body.digest != labeled_digest(TENANT_STATE_LABEL, state) {
        return Err(ClientError::Verification(format!(
            "the control plane serves state version {}, but the log's latest is version {}: refusing to build on it",
            state.version, body.version
        )));
    }
    Ok(())
}

impl Admin {
    /// `root_id`: the chain this admin expects (`None` only before `init`). `trust`: the log
    /// and registrar keys bundles are verified with.
    pub fn new(
        tenant: TenantId,
        root_id: Option<TenantRootId>,
        trust: TenantTrust,
        control: ControlClient,
        log: LogClient,
    ) -> Self {
        Self { tenant, root_id, trust, anchor_keys: Vec::new(), control, log }
    }

    /// Also start bundles from `TenantAnchor`s these guardian keys signed (`Trust::guardians`).
    /// Without them a bundle that starts from an anchor is completed from `/documents`.
    pub fn with_anchor_keys(mut self, keys: Vec<seal_proto::PublicKey>) -> Self {
        self.anchor_keys = keys;
        self
    }

    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }
    pub fn log(&self) -> &LogClient {
        &self.log
    }
    pub fn control(&self) -> &ControlClient {
        &self.control
    }

    /// Fetches a log proof for `index` and checks it includes `entry`.
    async fn prove(&self, entry: &LogEntry, index: u64) -> Result<TlogProof, ClientError> {
        let proof = self.log.prove(index).await?;
        if proof.leaf_index != index {
            return Err(ClientError::Verification(format!(
                "the log proved entry {} instead of {index}",
                proof.leaf_index
            )));
        }
        LogVerifier::new(self.trust.tlog.clone())
            .inclusion(entry, &proof)
            .map_err(|e| verification("log inclusion", e))?;
        Ok(proof)
    }

    /// Creates the tenant: root version 1 (`admin` the only admin key, threshold 1) signed by
    /// `registrar`, logged and PUT, then state version 1 (tenant key version 1, `platforms`,
    /// nothing else) signed by `admin`, logged and PUT. The root id is `state::root_id(v1)`.
    ///
    /// Resumable: run again with the same keys and options after a failure, it continues where
    /// the first run stopped. Root version 1 already in the log is reused (the root is
    /// deterministic: Ed25519 signatures over the same body), and refused when the tenant's
    /// first logged version 1 is another root. PUTs of what the control plane holds already
    /// succeed. Once the control plane holds a state the tenant exists, and `init` verifies
    /// and returns it without signing anything. A state the log recorded but the control
    /// plane never received is superseded by the next version, signed now.
    pub async fn init(
        &self,
        admin: &SigningKey,
        registrar: &[SigningKey],
        cosign_releases: bool,
        platforms: BTreeSet<PlatformId>,
        pending_window_secs: u64,
        time: &TrustedTime,
    ) -> Result<Initialized, ClientError> {
        let root = TenantRoot {
            tenant: self.tenant.clone(),
            version: 1,
            admin_keys: [AdminKey::Ed25519 { public_key: admin.public_key() }].into(),
            threshold: 1,
            cosign_releases,
        };
        let mut signed_root = Signed { body: root, signatures: Vec::new() };
        for key in registrar {
            key.cosign(TENANT_ROOT_LABEL, &mut signed_root);
        }
        seal_crypto::sign::verify_threshold(
            &self.trust.registrar_keys,
            self.trust.registrar_threshold,
            TENANT_ROOT_LABEL,
            &signed_root,
        )
        .map_err(|e| ClientError::Invalid(format!("root version 1 needs the registrar's signatures: {e}")))?;
        let root_id = root_id(&signed_root.body);
        let mut resumed = Vec::new();

        let link = match self.first_root_v1().await? {
            Some((index, root)) if root == signed_root.body => {
                resumed.push(format!("root version 1 is already log entry {index}"));
                let proof = self.prove(&LogEntry::TenantRoot(root), index).await?;
                LoggedRoot { root: signed_root, proof }
            }
            Some((index, root)) => {
                return Err(ClientError::Invalid(format!(
                    "the log already holds root version 1 of {} as entry {index} (root id {}), not this one: \
                     resume with the admin key, registrar keys and options of that run, or pick another tenant name",
                    self.tenant,
                    seal_proto::state::root_id(&root)
                )))
            }
            None => self.log_root(signed_root).await?,
        };
        // From here on the control plane knows the chain, and `admin` signs for it.
        let credential = SigningKeyCredential::new(SigningKey::from_seed(&admin.to_seed()), root_id);
        self.control.set_credential(Arc::new(credential));
        self.control.put_root(&self.tenant, &link).await.map_err(control_error)?;

        match self.control.get_bundle(&self.tenant).await {
            Ok(bundle) => {
                let current = self.verify_bundle(bundle, time).await?;
                if current.tenant.root_id() != &root_id {
                    return Err(ClientError::Verification(format!(
                        "the control plane serves root chain {}, not {root_id}",
                        current.tenant.root_id()
                    )));
                }
                let state = current.bundle.state;
                resumed.push(format!("the control plane already holds state version {}", state.body.version));
                return Ok(Initialized { root_id, root: link, state, resumed });
            }
            Err(ControlError::Rejected { status: 404 }) => {}
            Err(e) => return Err(control_error(e)),
        }
        // The log refuses a version it already holds, so a state it recorded for a run that
        // failed before the PUT is superseded rather than signed again.
        let version = match self.log.freshness(&self.tenant).await {
            Ok(statement) => {
                let by_log = statement
                    .signatures
                    .iter()
                    .any(|sig| verify(&self.trust.tlog.log_key, STATE_FRESHNESS_LABEL, &statement.body, sig).is_ok());
                if !by_log || statement.body.tenant != self.tenant {
                    return Err(ClientError::Verification("the log's freshness statement does not verify".into()));
                }
                // A run that stopped after proposing its state left the signed state there:
                // submitting it again stores it (the control plane finds it in the log). Only a
                // state nobody holds any more is superseded, and then verifiers, which cannot
                // compare the new state with a first state they never see, accept the new one
                // once it has been public for `MAX_PENDING_WINDOW_SECS`.
                let open = self.control.get_proposals(&self.tenant).await.map_err(control_error)?;
                let held = open.into_iter().find_map(|p| match p.document {
                    Proposed::State(s)
                        if s.body.version == statement.body.version
                            && labeled_digest(TENANT_STATE_LABEL, &s.body) == statement.body.digest =>
                    {
                        Some(s)
                    }
                    _ => None,
                });
                if let Some(state) = held {
                    resumed.push(format!("state version {} was proposed and is submitted again", state.body.version));
                    self.submit_state(&root_id, &state).await?;
                    return Ok(Initialized { root_id, root: link, state, resumed });
                }
                resumed.push(format!(
                    "the log already holds state version {}, which the control plane never received; the next \
                     version supersedes it and is in force once public for {} s",
                    statement.body.version,
                    seal_proto::state::MAX_PENDING_WINDOW_SECS
                ));
                statement.body.version + 1
            }
            Err(ClientError::Seal { code: ErrorCode::BadRequest, .. }) => 1,
            Err(e) => return Err(e),
        };

        let state = TenantState {
            tenant: self.tenant.clone(),
            version,
            root_version: 1,
            apps: BTreeMap::new(),
            tenant_key_versions: TenantKeyVersions {
                current: TenantKeyVersion(1),
                oldest_accepted: TenantKeyVersion(1),
            },
            platforms,
            integrity: Default::default(),
            deployments: BTreeSet::new(),
            freshness_keys: BTreeSet::new(),
            telemetry_readers: BTreeSet::new(),
            issued_at: time.now,
            pending_window_secs,
            app_networks: Default::default(),
        };
        let state = admin_sign(
            &format!("state version {version}"),
            &link.root.body,
            TENANT_STATE_LABEL,
            state,
            std::slice::from_ref(admin),
        )?;
        self.submit_state(&root_id, &state).await?;
        Ok(Initialized { root_id, root: link, state, resumed })
    }

    /// The tenant's first root version 1 in the log, with its index; `None` when there is none
    /// or the log does not serve entries. Unverified: `init` proves the one it reuses.
    async fn first_root_v1(&self) -> Result<Option<(u64, TenantRoot)>, ClientError> {
        let checkpoint = self.log.checkpoint().await?;
        let size = LogVerifier::new(self.trust.tlog.clone())
            .checkpoint(&checkpoint)
            .map_err(|e| verification("log checkpoint", e))?
            .checkpoint()
            .size;
        for index in 0..size {
            match self.log.entry(index).await {
                Ok(LogEntry::TenantRoot(root)) if root.tenant == self.tenant && root.version == 1 => {
                    return Ok(Some((index, root)))
                }
                Ok(_) => {}
                Err(ClientError::Seal { code: ErrorCode::BadRequest, .. }) if index == 0 => return Ok(None),
                Err(e) => return Err(e),
            }
        }
        Ok(None)
    }

    async fn log_root(&self, root: Signed<TenantRoot>) -> Result<LoggedRoot, ClientError> {
        let entry = LogEntry::TenantRoot(root.body.clone());
        let index = self.log.append(&entry).await?;
        let proof = self.prove(&entry, index).await?;
        Ok(LoggedRoot { root, proof })
    }

    /// The tenant's bundle, verified: chain and state (`TenantVerifier::verify`, no telemetry
    /// keys, so signals and session ends are dropped), the expected root id, and the log's
    /// current statement naming exactly this state.
    pub async fn fetch(&self, time: &TrustedTime) -> Result<Current, ClientError> {
        let bundle = self.control.get_bundle(&self.tenant).await.map_err(control_error)?;
        self.verify_bundle(bundle, time).await
    }

    /// The tenant's logged documents, verified (`TenantVerifier::verify_documents`): the root
    /// chain and the states above it, each with its inclusion proof, and the expected root id.
    /// Unlike `fetch` it needs no state in force, so it serves a tenant whose first state is
    /// not signed yet; it says nothing about freshness or what is in force.
    pub async fn documents(&self) -> Result<seal_verify::VerifiedDocuments, ClientError> {
        let docs = self.control.get_documents(&self.tenant, None).await.map_err(control_error)?;
        let verified = TenantVerifier::new(self.trust.clone(), Vec::new())
            .with_anchor_keys(self.anchor_keys.clone())
            .verify_documents(&self.tenant, &docs.roots, &docs.states, docs.checkpoint.as_ref())
            .map_err(|e| verification("tenant documents", e))?;
        if let Some(expected) = &self.root_id {
            if &verified.root_id != expected {
                return Err(ClientError::Verification(format!(
                    "the control plane serves root chain {}, not {expected}",
                    verified.root_id
                )));
            }
        }
        Ok(verified)
    }

    /// As `fetch`, for a tenant-run freshness signer about to sign: the bundle is verified as
    /// if it carried `signer`'s statement for its state, so a state whose last tenant statement
    /// ran out can still be signed for. `signer` must be one of the state's `freshness_keys`.
    pub async fn fetch_as_freshness_signer(
        &self,
        signer: &SigningKey,
        time: &TrustedTime,
    ) -> Result<Current, ClientError> {
        let mut bundle = self.control.get_bundle(&self.tenant).await.map_err(control_error)?;
        let state = &bundle.state.body;
        if !state.freshness_keys.contains(&signer.public_key()) {
            return Err(ClientError::Invalid(format!(
                "{} is not a freshness key of state version {}",
                signer.public_key(),
                state.version
            )));
        }
        let candidate = freshness_statement(signer, state, time);
        bundle.freshness.push(candidate);
        let mut current = self.verify_bundle(bundle, time).await?;
        current.bundle.freshness.pop();
        Ok(current)
    }

    async fn verify_bundle(&self, mut bundle: TenantBundle, time: &TrustedTime) -> Result<Current, ClientError> {
        let verifier = TenantVerifier::new(self.trust.clone(), Vec::new()).with_anchor_keys(self.anchor_keys.clone());
        let mut verified = verifier.verify(&self.tenant, &bundle, time);
        if matches!(verified, Err(VerifyError::State(_))) && !bundle.states.is_empty() {
            // The bundle starts from a guardian anchor this admin does not trust: every state.
            let documents = self.control.get_documents(&self.tenant, None).await.map_err(control_error)?;
            bundle.states = consecutive_to(&documents.states, &bundle.state);
            verified = verifier.verify(&self.tenant, &bundle, time);
        }
        let tenant = verified.map_err(|e| match e {
            VerifyError::StateNotFresh if !bundle.state.body.freshness_keys.is_empty() => ClientError::Verification(
                "no current freshness statement for the tenant's state; it names freshness keys, so one of them \
                 must sign for it (`seal settings freshness sign`)"
                    .into(),
            ),
            e => verification("tenant bundle", e),
        })?;
        if let Some(expected) = &self.root_id {
            if tenant.root_id() != expected {
                return Err(ClientError::Verification(format!(
                    "the control plane serves root chain {}, not {expected}",
                    tenant.root_id()
                )));
            }
        }
        let statement = self.log.freshness(&self.tenant).await?;
        check_log_statement(&self.trust.tlog.log_key, tenant.latest_state(), &statement)?;
        Ok(Current { bundle, tenant })
    }

    /// The next state: the one in force, edited, with the latest version + 1, the latest root
    /// version and `issued_at` now. Refused when the edit changes nothing. It builds on the
    /// state in force, not on a pending one, so when it narrows it applies at once and the
    /// pending states never take effect (`Draft::supersedes`).
    pub fn draft(
        current: &Current,
        time: &TrustedTime,
        edit: impl FnOnce(&mut TenantState) -> Result<(), ClientError>,
    ) -> Result<Draft, ClientError> {
        let tenant = &current.tenant;
        let old = tenant.state().clone();
        let mut new = old.clone();
        edit(&mut new)?;
        let mut unchanged = new.clone();
        unchanged.issued_at = old.issued_at;
        if unchanged == old {
            return Err(ClientError::Invalid("nothing to change".into()));
        }
        let latest = tenant.latest_state().version;
        new.version = latest.checked_add(1).ok_or_else(|| ClientError::Invalid("state version overflow".into()))?;
        new.root_version = tenant.latest_root().version;
        new.issued_at = time.now;
        new.tenant = old.tenant.clone();
        let changes = diff(&old, &new);
        let differences = change::diff_states(&old, &new);
        let mut change = change::classify(&differences);
        if new.root_version > old.root_version {
            change = change.max(change::classify_root(tenant.root(), tenant.latest_root()));
        }
        let supersedes = match change {
            Change::Narrowing => tenant.pending().iter().map(|p| p.version).collect(),
            Change::Widening => Vec::new(),
        };
        Ok(Draft { old, new, changes, differences, change, supersedes })
    }

    /// `state` signed by every key in `keys` that is an admin key of `root` (the latest root:
    /// states are signed under it); refused unless that meets `root.threshold`.
    pub fn sign_state(
        root: &TenantRoot,
        state: TenantState,
        keys: &[SigningKey],
    ) -> Result<SignedTenantState, ClientError> {
        let what = format!("state version {}", state.version);
        admin_sign(&what, root, TENANT_STATE_LABEL, state, keys)
    }

    /// Submits `state`, which carries the latest root's threshold of signatures, through a
    /// proposal: the control plane logs and stores it. Returns its log index.
    pub async fn publish(&self, state: &SignedTenantState) -> Result<u64, ClientError> {
        let root_id = self.root_id.ok_or_else(|| ClientError::Invalid("no root id for this tenant".into()))?;
        self.submit_state(&root_id, state).await
    }

    async fn submit_state(&self, root_id: &TenantRootId, state: &SignedTenantState) -> Result<u64, ClientError> {
        let document = Proposed::State(state.clone());
        self.control.put_proposal(&self.tenant, &document).await.map_err(control_error)?;
        match self.submit_checked(root_id, &document.id(), &document).await? {
            Submitted::State(logged) => Ok(logged.proof.leaf_index),
            Submitted::Root(_) => {
                Err(ClientError::Verification("the control plane submitted a root for a state".into()))
            }
        }
    }

    /// Creates the proposal of `document`, or adds its signatures to it.
    pub async fn propose_document(&self, document: &Proposed) -> Result<Proposal, ClientError> {
        self.control.put_proposal(&self.tenant, document).await.map_err(control_error)
    }

    /// The open proposals, unverified: callers check each against a verified `Current`.
    pub async fn proposals(&self) -> Result<Vec<Proposal>, ClientError> {
        self.control.get_proposals(&self.tenant).await.map_err(control_error)
    }

    pub async fn withdraw(&self, id: &str) -> Result<(), ClientError> {
        self.control.delete_proposal(&self.tenant, id).await.map_err(control_error)
    }

    /// Submits the proposal `id` holding `document`; checks that what the control plane stored
    /// is exactly `document`, included in the log.
    pub async fn submit(&self, document: &Proposed) -> Result<Submitted, ClientError> {
        let root_id = self.root_id.ok_or_else(|| ClientError::Invalid("no root id for this tenant".into()))?;
        self.submit_checked(&root_id, &document.id(), document).await
    }

    async fn submit_checked(
        &self,
        root_id: &TenantRootId,
        id: &str,
        document: &Proposed,
    ) -> Result<Submitted, ClientError> {
        let submitted = self.control.post_proposal_submit(&self.tenant, id).await.map_err(control_error)?;
        let log = LogVerifier::new(self.trust.tlog.clone());
        match (&submitted, document) {
            (Submitted::State(logged), Proposed::State(state)) if logged.state.body == state.body => {
                let leaf = LogEntry::TenantState(TenantStateLeaf {
                    tenant: self.tenant.clone(),
                    root_id: *root_id,
                    version: state.body.version,
                    digest: labeled_digest(TENANT_STATE_LABEL, &state.body),
                });
                log.inclusion(&leaf, &logged.proof).map_err(|e| verification("log inclusion", e))?;
            }
            (Submitted::Root(link), Proposed::Root(root)) if link.root.body == root.body => {
                log.inclusion(&LogEntry::TenantRoot(root.body.clone()), &link.proof)
                    .map_err(|e| verification("log inclusion", e))?;
            }
            _ => return Err(ClientError::Verification("the control plane submitted another document".into())),
        }
        Ok(submitted)
    }

    /// Signs a tenant-run freshness statement for `state` now and posts it to the control plane.
    pub async fn post_freshness(
        &self,
        signer: &SigningKey,
        state: &TenantState,
        time: &TrustedTime,
    ) -> Result<SignedStateFreshness, ClientError> {
        let statement = freshness_statement(signer, state, time);
        self.control.post_freshness(&self.tenant, &statement).await.map_err(control_error)?;
        Ok(statement)
    }

    /// Rotates the root: `next` (the next version) signed by the latest root's threshold of
    /// `keys`, and the latest state re-signed under it (version + 1, `root_version` the new
    /// one) by its threshold of `keys`, since a state applies only under its own root (a
    /// rotation that widens the root in force waits the pending window of the state in force).
    /// Both signatures are checked before anything is sent; then both are proposed, and the root
    /// submitted before the state.
    pub async fn rotate_root(
        &self,
        current: &Current,
        next: TenantRoot,
        keys: &[SigningKey],
        time: &TrustedTime,
    ) -> Result<(LoggedRoot, SignedTenantState), ClientError> {
        let root = current.tenant.latest_root();
        if next.tenant != root.tenant || Some(next.version) != root.version.checked_add(1) {
            return Err(ClientError::Invalid(format!(
                "the next root must be version {} of {}",
                root.version + 1,
                root.tenant
            )));
        }
        if next.threshold == 0 || usize::from(next.threshold) > next.admin_keys.len() {
            return Err(ClientError::Invalid(format!(
                "threshold {} with {} admin keys",
                next.threshold,
                next.admin_keys.len()
            )));
        }
        let what = format!("root version {}", next.version);
        let signed_root = admin_sign(&what, root, TENANT_ROOT_LABEL, next, keys)?;
        let mut state = current.tenant.latest_state().clone();
        state.version += 1;
        state.root_version = signed_root.body.version;
        state.issued_at = time.now;
        let state = Self::sign_state(&signed_root.body, state, keys)?;

        let (root, state) = (Proposed::Root(signed_root), Proposed::State(state));
        self.propose_document(&root).await?;
        self.propose_document(&state).await?;
        let Submitted::Root(link) = self.submit(&root).await? else { unreachable!("checked by submit") };
        let Submitted::State(logged) = self.submit(&state).await? else { unreachable!("checked by submit") };
        Ok((link, logged.state))
    }

    /// A tenant co-signature for releases measuring `measurement` (for `cosign_releases`
    /// tenants), signed by the latest root's threshold of `keys` and PUT on the control plane.
    pub async fn approve_release(
        &self,
        current: &Current,
        measurement: Measurement,
        keys: &[SigningKey],
    ) -> Result<Signed<ReleaseCosign>, ClientError> {
        let body = ReleaseCosign { tenant: self.tenant.clone(), measurement };
        let cosign = admin_sign("a release co-signature", current.tenant.root(), RELEASE_COSIGN_LABEL, body, keys)?;
        self.control.put_release_cosign(&self.tenant, &measurement, &cosign).await.map_err(control_error)?;
        Ok(cosign)
    }

    /// Scans the log for this tenant's documents: root versions not in the verified chain
    /// (a competing root version 1 the registrar signed, or a later version nobody showed
    /// us), states logged under another root id, and a log freshness statement for an older
    /// version than one the log holds (a signed, provable lie). Every scanned entry is
    /// checked against the log's inclusion proof.
    pub async fn verify_roots(&self, time: &TrustedTime) -> Result<RootScan, ClientError> {
        let current = self.fetch(time).await?;
        let chain: Vec<&TenantRoot> = current.bundle.root_chain.iter().map(|l| &l.root.body).collect();
        let ours = *current.tenant.root_id();
        let log = LogVerifier::new(self.trust.tlog.clone());
        let checkpoint = self.log.checkpoint().await?;
        let size = log.checkpoint(&checkpoint).map_err(|e| verification("log checkpoint", e))?.checkpoint().size;

        let mut findings = Vec::new();
        let mut highest: Option<u64> = None;
        let mut scanned = Some(0);
        for index in 0..size {
            let entry = match self.log.entry(index).await {
                Ok(entry) => entry,
                Err(ClientError::Seal { code: ErrorCode::BadRequest, .. }) if index == 0 => {
                    scanned = None;
                    break;
                }
                Err(e) => return Err(e),
            };
            if let Err(e) = self.prove(&entry, index).await {
                findings.push(format!("log entry {index} does not match the log's proof: {e}"));
                continue;
            }
            scanned = Some(index + 1);
            match &entry {
                LogEntry::TenantRoot(root) if root.tenant == self.tenant && !chain.contains(&root) => {
                    if root.version == 1 {
                        findings.push(format!(
                            "log entry {index}: a competing root version 1 for {} (root id {})",
                            self.tenant,
                            root_id(root)
                        ));
                    } else {
                        findings.push(format!("log entry {index}: root version {} is not in our chain", root.version));
                    }
                }
                LogEntry::TenantState(leaf) if leaf.tenant == self.tenant => {
                    if leaf.root_id != ours {
                        findings.push(format!(
                            "log entry {index}: state version {} logged under another root chain ({})",
                            leaf.version, leaf.root_id
                        ));
                    } else {
                        highest = highest.max(Some(leaf.version));
                    }
                }
                _ => {}
            }
        }
        let statement = self.log.freshness(&self.tenant).await?;
        let mut statements: Vec<&SignedStateFreshness> = current.bundle.freshness.iter().collect();
        statements.push(&statement);
        let highest = highest.unwrap_or(0).max(current.tenant.latest_state().version);
        for s in statements {
            let by_log = s
                .signatures
                .iter()
                .any(|sig| verify(&self.trust.tlog.log_key, STATE_FRESHNESS_LABEL, &s.body, sig).is_ok());
            if by_log && s.body.tenant == self.tenant && s.body.version < highest {
                findings.push(format!(
                    "the log signed freshness for state version {} at {} while version {highest} is logged",
                    s.body.version, s.body.signed_at
                ));
            }
        }
        Ok(RootScan { scanned, findings })
    }
}

fn freshness_statement(signer: &SigningKey, state: &TenantState, time: &TrustedTime) -> SignedStateFreshness {
    let statement = StateFreshness {
        tenant: state.tenant.clone(),
        version: state.version,
        digest: labeled_digest(TENANT_STATE_LABEL, state),
        signed_at: time.now,
    };
    signer.sign_into(STATE_FRESHNESS_LABEL, statement)
}

/// The next root after `root`: `add` admin keys added, keys whose `admin_key_id` is in
/// `remove` dropped, `threshold` when given (else unchanged). Refused when a removed key is
/// not there or the threshold does not fit the keys.
pub fn next_root(
    root: &TenantRoot,
    add: impl IntoIterator<Item = AdminKey>,
    remove: &[KeyId],
    threshold: Option<u8>,
) -> Result<TenantRoot, ClientError> {
    let mut next = root.clone();
    next.version = root.version.checked_add(1).ok_or_else(|| ClientError::Invalid("root version overflow".into()))?;
    for id in remove {
        let before = next.admin_keys.len();
        next.admin_keys.retain(|k| admin_key_id(k) != *id);
        if next.admin_keys.len() == before {
            return Err(ClientError::Invalid(format!("{id} is not an admin key of root version {}", root.version)));
        }
    }
    next.admin_keys.extend(add);
    if let Some(threshold) = threshold {
        next.threshold = threshold;
    }
    if next.threshold == 0 || usize::from(next.threshold) > next.admin_keys.len() {
        return Err(ClientError::Invalid(format!(
            "threshold {} does not fit {} admin keys",
            next.threshold,
            next.admin_keys.len()
        )));
    }
    if next == (TenantRoot { version: next.version, ..root.clone() }) {
        return Err(ClientError::Invalid("nothing to change".into()));
    }
    Ok(next)
}

/// The wire name of a platform (`azure_snp_aci`, `sim`, ...).
pub fn platform_name(platform: PlatformId) -> String {
    match serde_json::to_value(platform) {
        Ok(serde_json::Value::String(name)) => name,
        _ => format!("{platform:?}"),
    }
}

/// One line for an identity matcher, with its immutable ids.
pub fn describe(matcher: &IdentityMatcher) -> String {
    match matcher {
        IdentityMatcher::Azure { entra_tenant, object_id, audience, hosted } => match hosted {
            None => format!("Azure managed identity {object_id} (Entra tenant {entra_tenant}, audience {audience})"),
            Some(_) => format!(
                "Seal-hosted replicas (managed identity {object_id}, Entra tenant {entra_tenant}, audience {audience})"
            ),
        },
        IdentityMatcher::AwsRole { role_arn, role_id } => format!("AWS role {role_arn} ({role_id})"),
        IdentityMatcher::Kubernetes { issuer, namespace, service_account, service_account_uid } => {
            format!("Kubernetes {namespace}/{service_account} ({service_account_uid}) at {issuer}")
        }
        IdentityMatcher::Gcp { email, unique_id } => format!("GCP {email} ({unique_id})"),
        IdentityMatcher::GitHub { repository, repository_id, repository_owner_id, scope } => {
            let scope = match scope {
                GitHubScope::Environment(e) => format!("environment {e}"),
                GitHubScope::Ref(r) => format!("ref {r}"),
            };
            format!("GitHub {repository} ({repository_owner_id}/{repository_id}), {scope}")
        }
        IdentityMatcher::AppKey { key_id, public_key } => format!("app key {public_key} (key id {key_id})"),
        IdentityMatcher::ConfidentialSpace { project_number, service_account, hosted } => match hosted {
            None => format!("Confidential Space project {project_number}, {service_account}"),
            Some(_) => format!("Seal-hosted replicas (project {project_number}, {service_account})"),
        },
    }
}

fn set_changes<T: Ord>(
    out: &mut Vec<String>,
    what: &str,
    old: &BTreeSet<T>,
    new: &BTreeSet<T>,
    show: impl Fn(&T) -> String,
) {
    for item in old.difference(new) {
        out.push(format!("- {what}: {}", show(item)));
    }
    for item in new.difference(old) {
        out.push(format!("+ {what}: {}", show(item)));
    }
}

fn map_changes<K: Ord + Display, V: PartialEq>(
    out: &mut Vec<String>,
    what: &str,
    old: &BTreeMap<K, V>,
    new: &BTreeMap<K, V>,
    show: impl Fn(&V) -> String,
) {
    for (key, value) in old {
        match new.get(key) {
            None => out.push(format!("- {what} {key}: {}", show(value))),
            Some(v) if v != value => out.push(format!("~ {what} {key}: {} -> {}", show(value), show(v))),
            Some(_) => {}
        }
    }
    for (key, value) in new {
        if !old.contains_key(key) {
            out.push(format!("+ {what} {key}: {}", show(value)));
        }
    }
}

/// The changes from `old` to `new`, one line each: `+` added, `-` removed, `~` changed.
/// Identities show their immutable ids.
pub fn diff(old: &TenantState, new: &TenantState) -> Vec<String> {
    let mut out = Vec::new();
    for (app, matchers) in &old.apps {
        if !new.apps.contains_key(app) {
            out.push(format!("- app {app} ({} identities)", matchers.len()));
        }
    }
    for (app, matchers) in &new.apps {
        let before = old.apps.get(app);
        if before.is_none() {
            out.push(format!("+ app {app}"));
        }
        set_changes(&mut out, &format!("app {app}"), before.unwrap_or(&BTreeSet::new()), matchers, describe);
    }
    for (app, matchers) in &old.apps {
        if !new.apps.contains_key(app) {
            set_changes(&mut out, &format!("app {app}"), matchers, &BTreeSet::new(), describe);
        }
    }
    set_changes(&mut out, "deployment", &old.deployments, &new.deployments, describe);
    set_changes(&mut out, "platform", &old.platforms, &new.platforms, |p| platform_name(*p));
    let (o, n) = (old.tenant_key_versions, new.tenant_key_versions);
    if o.current != n.current {
        out.push(format!("~ tenant key version: {} -> {}", o.current, n.current));
    }
    if o.oldest_accepted != n.oldest_accepted {
        out.push(format!("~ oldest accepted tenant key version: {} -> {}", o.oldest_accepted, n.oldest_accepted));
    }
    set_changes(&mut out, "freshness key", &old.freshness_keys, &new.freshness_keys, |k| k.to_string());
    set_changes(&mut out, "telemetry reader", &old.telemetry_readers, &new.telemetry_readers, |k| k.to_string());
    if old.pending_window_secs != new.pending_window_secs {
        out.push(format!("~ pending window: {}s -> {}s", old.pending_window_secs, new.pending_window_secs));
    }
    let (oi, ni) = (&old.integrity, &new.integrity);
    let empty = BTreeSet::new();
    let apps: BTreeSet<_> = oi.artifacts.keys().chain(ni.artifacts.keys()).collect();
    for app in apps {
        set_changes(
            &mut out,
            &format!("allowed artifact for {app}"),
            oi.artifacts.get(app).unwrap_or(&empty),
            ni.artifacts.get(app).unwrap_or(&empty),
            |a| format!("{}={}", a.name, hex(&a.sha256)),
        );
    }
    map_changes(&mut out, "integrity source", &oi.sources, &ni.sources, |k| k.to_string());
    let actions = |m: &BTreeMap<seal_proto::integrity::Severity, seal_proto::integrity::IntegrityAction>| {
        m.iter().map(|(s, a)| (format!("{s:?}").to_lowercase(), *a)).collect::<BTreeMap<_, _>>()
    };
    map_changes(&mut out, "integrity action from", &actions(&oi.actions), &actions(&ni.actions), |a| format!("{a:?}"));
    set_changes(&mut out, "clearance", &oi.cleared, &ni.cleared, |c| {
        format!("{} before {}", serde_json::to_string(&c.identity).unwrap_or_default(), c.before)
    });
    if old.root_version != new.root_version {
        out.push(format!("~ signed under root version: {} -> {}", old.root_version, new.root_version));
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use seal_proto::PublicKey;

    fn state() -> TenantState {
        TenantState {
            tenant: TenantId::new("acme").unwrap(),
            version: 1,
            root_version: 1,
            apps: BTreeMap::new(),
            tenant_key_versions: TenantKeyVersions {
                current: TenantKeyVersion(1),
                oldest_accepted: TenantKeyVersion(1),
            },
            platforms: BTreeSet::new(),
            integrity: Default::default(),
            deployments: BTreeSet::new(),
            freshness_keys: BTreeSet::new(),
            telemetry_readers: BTreeSet::new(),
            issued_at: 0,
            pending_window_secs: 0,
            app_networks: Default::default(),
        }
    }

    #[test]
    fn diff_lists_every_change() {
        let old = state();
        let mut new = old.clone();
        let app = seal_proto::AppName::new("checkout").unwrap();
        let key = PublicKey([7; 32]);
        new.apps
            .insert(app, [IdentityMatcher::AppKey { key_id: seal_crypto::sign::key_id(&key), public_key: key }].into());
        new.platforms.insert(PlatformId::Sim);
        new.tenant_key_versions.current = TenantKeyVersion(2);
        let lines = diff(&old, &new);
        assert_eq!(lines.len(), 4, "{lines:?}");
        assert_eq!(lines[0], "+ app checkout");
        assert!(lines[1].starts_with("+ app checkout: app key "), "{lines:?}");
        assert_eq!(lines[2], "+ platform: sim");
        assert_eq!(lines[3], "~ tenant key version: 1 -> 2");
        assert!(diff(&new, &old).iter().any(|l| l == "- app checkout (1 identities)"));
    }

    #[test]
    fn next_root_checks_keys_and_threshold() {
        let a = SigningKey::from_seed(&[1; 32]);
        let b = SigningKey::from_seed(&[2; 32]);
        let ka = AdminKey::Ed25519 { public_key: a.public_key() };
        let kb = AdminKey::Ed25519 { public_key: b.public_key() };
        let root = TenantRoot {
            tenant: TenantId::new("acme").unwrap(),
            version: 1,
            admin_keys: [ka.clone()].into(),
            threshold: 1,
            cosign_releases: false,
        };
        let next = next_root(&root, [kb.clone()], &[], Some(2)).unwrap();
        assert_eq!((next.version, next.threshold, next.admin_keys.len()), (2, 2, 2));
        assert!(next_root(&root, [], &[a.key_id()], None).is_err(), "no keys left");
        assert!(next_root(&root, [kb], &[b.key_id()], None).is_err(), "b is not in v1");
        assert!(next_root(&root, [], &[], None).is_err(), "nothing changes");
        assert!(next_root(&root, [], &[], Some(2)).is_err(), "threshold above the keys");
    }

    #[test]
    fn signing_needs_the_threshold() {
        let a = SigningKey::from_seed(&[1; 32]);
        let b = SigningKey::from_seed(&[2; 32]);
        let root = TenantRoot {
            tenant: TenantId::new("acme").unwrap(),
            version: 1,
            admin_keys: [
                AdminKey::Ed25519 { public_key: a.public_key() },
                AdminKey::Ed25519 { public_key: b.public_key() },
            ]
            .into(),
            threshold: 2,
            cosign_releases: false,
        };
        let err = Admin::sign_state(&root, state(), std::slice::from_ref(&a)).unwrap_err();
        assert!(err.to_string().contains("needs 2 signatures"), "{err}");
        let signed = Admin::sign_state(&root, state(), &[a, b]).unwrap();
        assert_eq!(signed.signatures.len(), 2);
    }
}
