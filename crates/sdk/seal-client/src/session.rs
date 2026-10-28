//! Sessions: use a blob through the enclave without receiving its plaintext.

use std::future::{Future, IntoFuture};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use seal_proto::api::{EndRequest, ExtendRequest, ExtendResponse, SessionRequest, SessionResponse, TelemetryReceipt};
use seal_proto::blob::Blob;
use seal_proto::policy::{Destination, Protocol};
use seal_proto::session::{ConsumerTier, SessionInfo, SESSION_EXTEND_SECS};
use seal_proto::tunnel::LOCAL_KEY_PREFIX;
use seal_proto::{Bearer, ErrorCode};
use sha2::{Digest, Sha256};

use crate::client::{now, placeholder};
use crate::verify::VerifiedEnclave;
use crate::{integrity, tunnel, BoxFuture, Client, ClientError};

type Reload = Arc<dyn Fn() -> BoxFuture<'static, Result<String, ClientError>> + Send + Sync>;
type OnReseal = Arc<dyn Fn(String) -> BoxFuture<'static, ()> + Send + Sync>;

/// `Client::session(blob)`: chain options, then end with `.http()` or `.database()` for a
/// typed session, or `.await` for a `Session` of whichever kind the blob is.
#[must_use = "a session does nothing until you .await it"]
pub struct SessionBuilder<'a> {
    client: &'a Client,
    blob: String,
    min_tier: Option<ConsumerTier>,
    reload: Option<Reload>,
    on_reseal: Option<OnReseal>,
    endpoint: Option<Arc<dyn integrity::EndpointReporter>>,
}

impl<'a> SessionBuilder<'a> {
    pub(crate) fn new(client: &'a Client, blob: String) -> Self {
        Self { client, blob, min_tier: None, reload: None, on_reseal: None, endpoint: None }
    }
    /// Refuse to start unless the session is at least this strong.
    pub fn min_tier(mut self, tier: ConsumerTier) -> Self {
        self.min_tier = Some(tier);
        self
    }
    /// Where to get the blob again when it comes back `Expired` (e.g. after a rotation
    /// wrote a new one): the session restarts with what this returns.
    pub fn reload_with<F, Fut>(mut self, reload: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<String, ClientError>> + Send + 'static,
    {
        self.reload = Some(Arc::new(move || Box::pin(reload())));
        self
    }
    /// Called with the same secret resealed under the tenant's current key version, when the
    /// blob's version is decrypt-only. Store it to replace the old blob.
    pub fn on_reseal<F, Fut>(mut self, on_reseal: F) -> Self
    where
        F: Fn(String) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.on_reseal = Some(Arc::new(move |blob| Box::pin(on_reseal(blob))));
        self
    }
    /// Start a session on an HTTP blob. A blob for another protocol fails with
    /// `ClientError::Invalid` before anything is sent: the policy is readable in the blob.
    // The signature states `Send`, which bindings rely on.
    #[allow(clippy::manual_async_fn)]
    pub fn http(self) -> impl Future<Output = Result<HttpSession, ClientError>> + Send + 'a {
        async move {
            expect_kind(&self.blob, Kind::Http)?;
            match self.await? {
                Session::Http(s) => Ok(s),
                Session::Database(_) => unreachable!("checked before starting"),
            }
        }
    }
    /// Start a session on a Postgres, Redis or ClickHouse blob. Any other blob fails with
    /// `ClientError::Invalid` before anything is sent.
    #[allow(clippy::manual_async_fn)]
    pub fn database(self) -> impl Future<Output = Result<DatabaseSession, ClientError>> + Send + 'a {
        async move {
            expect_kind(&self.blob, Kind::Database)?;
            match self.await? {
                Session::Database(s) => Ok(s),
                Session::Http(_) => unreachable!("checked before starting"),
            }
        }
    }
    /// What to report about this endpoint at start and every extend.
    /// Default `integrity::ExecutableHash`.
    pub fn endpoint_reporter(mut self, reporter: Arc<dyn integrity::EndpointReporter>) -> Self {
        self.endpoint = Some(reporter);
        self
    }
}

impl<'a> IntoFuture for SessionBuilder<'a> {
    type Output = Result<Session, ClientError>;
    type IntoFuture = BoxFuture<'a, Self::Output>;

    /// `POST /v1/sessions` with a fresh identity proof and endpoint report, then starts the
    /// local tunnel. The kind follows the blob's destination.
    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move {
            Blob::from_str(&self.blob)?;
            self.client.warn_if_env_app_key_and_blob(&self.blob).await;
            let live = Arc::new(Live {
                client: self.client.clone(),
                min_tier: self.min_tier,
                reporter: self.endpoint.unwrap_or_else(|| Arc::new(integrity::ExecutableHash)),
                reload: self.reload,
                on_reseal: self.on_reseal,
                blob: Mutex::new(self.blob),
                token: Arc::new(Mutex::new(Bearer::new(String::new()))),
                expires_at: AtomicU64::new(0),
                tunnel: Mutex::new(None),
                serial: tokio::sync::Mutex::new(()),
                ended: AtomicBool::new(false),
                receipts: Mutex::new(Vec::new()),
            });
            let (response, _) = live.start().await?;
            Core::open(live, response).await
        })
    }
}

/// Reads the blob's clear-text policy, so a wrong kind fails before anything is sent.
fn expect_kind(blob: &str, kind: Kind) -> Result<(), ClientError> {
    let blob = Blob::from_str(blob)?;
    let destination = blob.policy.destination();
    if Kind::of(destination.protocol()) == kind {
        Ok(())
    } else {
        Err(ClientError::Invalid(format!("blob is for {destination}, not {}", kind.name())))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Http,
    Database,
}
impl Kind {
    fn of(protocol: Protocol) -> Self {
        match protocol {
            Protocol::Http => Kind::Http,
            Protocol::Postgres | Protocol::Redis | Protocol::ClickHouse => Kind::Database,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Kind::Http => "https",
            Kind::Database => "a database (postgres, rediss, clickhouse)",
        }
    }
}

/// A session of whichever kind the blob is, for code that handles any blob. Apps that know
/// what they hold use `SessionBuilder::http` or `database` instead.
pub enum Session {
    Http(HttpSession),
    Database(DatabaseSession),
}

/// A session on an HTTP blob: point the app's client at `url()` with `key()` where the real
/// key would go (the sealed header).
pub struct HttpSession {
    core: Core,
    url: url::Url,
    key: seal_proto::Bearer,
}

/// A session on a Postgres, Redis or ClickHouse blob: connect with `dsn()`.
pub struct DatabaseSession {
    core: Core,
    protocol: Protocol,
    dsn: seal_proto::Bearer,
}

impl HttpSession {
    /// `s.url`: the local tunnel. The path continues the sealed destination's.
    pub fn url(&self) -> &str {
        self.url.as_str()
    }
    /// `s.key`: a local key worthless outside this tunnel.
    pub fn key(&self) -> &str {
        self.key.expose()
    }
}

impl DatabaseSession {
    /// `s.dsn`: a complete connection string for the app's driver.
    pub fn dsn(&self) -> &str {
        self.dsn.expose()
    }
    /// `Postgres`, `Redis` or `ClickHouse`.
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }
}

/// The same lifecycle on every session type.
macro_rules! lifecycle {
    ($($ty:ty),*) => {$(
        impl $ty {
            /// `s.info`: session id, tiers, tenant, app, blob id, expiry. `expires_at` moves
            /// with every `extend` called here; the tunnel's automatic extends keep the session
            /// alive without changing it, and a restart after `Expired` replaces it.
            pub fn info(&self) -> &SessionInfo {
                &self.core().info
            }
            /// Where telemetry recorded this session's start, then each restart (after `Expired`
            /// or an expired token, also those the tunnel makes by itself), oldest first. Keep
            /// them (`receipts::append`) for `seal telemetry --receipts`.
            pub fn receipts(&self) -> Vec<TelemetryReceipt> {
                self.core().live.receipts.lock().unwrap_or_else(|e| e.into_inner()).clone()
            }
            /// Extend the session now with a fresh identity proof and endpoint report
            /// (`/v1/sessions/extend`), then send `TunnelPreamble::Extend` to every replica
            /// holding one of its tunnel connections. The tunnel does this by itself before
            /// every expiry; calling it moves `info().expires_at`.
            pub async fn extend(&mut self) -> Result<(), ClientError> {
                if let Some(restarted) = self.core_mut().extend().await? {
                    self.core_mut().restarted(restarted);
                }
                Ok(())
            }
            /// Ends the session on the server (`/v1/sessions/end`): every replica refuses its
            /// tokens from then on. The
            /// first call also stops extending and closes the tunnel, whatever the answer.
            /// An error means the end may not have reached every replica (the one that
            /// answered may have ended it only locally, e.g. while the control plane is down):
            /// call `close` again to resend it. Once it succeeds, further calls do nothing.
            pub async fn close(&self) -> Result<(), ClientError> {
                self.core().close().await
            }
        }
    )*};
}
lifecycle!(HttpSession, DatabaseSession, Session);

impl HttpSession {
    fn core(&self) -> &Core {
        &self.core
    }
    fn core_mut(&mut self) -> &mut Core {
        &mut self.core
    }
}
impl DatabaseSession {
    fn core(&self) -> &Core {
        &self.core
    }
    fn core_mut(&mut self) -> &mut Core {
        &mut self.core
    }
}
impl Session {
    fn core(&self) -> &Core {
        match self {
            Session::Http(s) => &s.core,
            Session::Database(s) => &s.core,
        }
    }
    fn core_mut(&mut self) -> &mut Core {
        match self {
            Session::Http(s) => &mut s.core,
            Session::Database(s) => &mut s.core,
        }
    }
}

/// What a session shares with its tunnel's background extender.
struct Live {
    client: Client,
    min_tier: Option<ConsumerTier>,
    reporter: Arc<dyn integrity::EndpointReporter>,
    reload: Option<Reload>,
    on_reseal: Option<OnReseal>,
    /// The blob the current session runs on.
    blob: Mutex<String>,
    token: Arc<tunnel::TokenCell>,
    expires_at: AtomicU64,
    /// Set once the tunnel runs.
    tunnel: Mutex<Option<Arc<tunnel::Shared>>>,
    /// One extend or restart at a time.
    serial: tokio::sync::Mutex<()>,
    /// The server ended the session, or `close` did; it is never extended or restarted again.
    ended: AtomicBool,
    /// The telemetry receipts of every start, oldest first.
    receipts: Mutex<Vec<TelemetryReceipt>>,
}

/// What an extend did besides moving the expiry.
enum Renewal {
    Extended,
    /// The session was started again (after `Expired` with `reload_with`, or an expired token).
    Restarted(Box<SessionResponse>),
}

impl Live {
    fn blob(&self) -> String {
        self.blob.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
    fn token(&self) -> Bearer {
        self.token.lock().unwrap_or_else(|e| e.into_inner()).duplicate()
    }
    fn set_token(&self, token: &Bearer, expires_at: seal_proto::UnixTime) {
        *self.token.lock().unwrap_or_else(|e| e.into_inner()) = token.duplicate();
        self.expires_at.store(expires_at, Ordering::Relaxed);
    }
    fn tunnel(&self) -> Option<Arc<tunnel::Shared>> {
        self.tunnel.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Starts a session on the current blob; on `Expired` with `reload_with`, once more on
    /// the blob it returns. Hands a resealed blob to `on_reseal`.
    async fn start(&self) -> Result<(SessionResponse, Arc<VerifiedEnclave>), ClientError> {
        let (response, enclave) = match self.start_once(&self.blob()).await {
            Err(ClientError::Seal { code: ErrorCode::Expired, .. }) if self.reload.is_some() => {
                let reload = self.reload.as_ref().expect("checked");
                let blob = reload().await?;
                let started = self.start_once(&blob).await?;
                *self.blob.lock().unwrap_or_else(|e| e.into_inner()) = blob;
                started
            }
            other => other?,
        };
        self.set_token(&response.token, response.info.expires_at);
        self.receipts.lock().unwrap_or_else(|e| e.into_inner()).push(response.telemetry);
        if let (Some(resealed), Some(on_reseal)) = (&response.resealed, &self.on_reseal) {
            on_reseal(resealed.clone()).await;
        }
        Ok((response, enclave))
    }

    async fn start_once(&self, blob: &str) -> Result<(SessionResponse, Arc<VerifiedEnclave>), ClientError> {
        let parsed = Blob::from_str(blob)?;
        let client = &self.client;
        let enclave = client.enclave().await?;
        if &parsed.header.tenant != enclave.tenant() || &parsed.header.root_id != enclave.root_id() {
            return Err(ClientError::Verification(format!(
                "the blob is for {}@{}, the enclave serves {}@{}",
                parsed.header.tenant,
                parsed.header.root_id,
                enclave.tenant(),
                enclave.root_id()
            )));
        }
        let (context, proof) = placeholder(client.tenant());
        let mut request =
            SessionRequest { blob: blob.to_owned(), context, proof, min_tier: self.min_tier, endpoint: None };
        let endpoint = Some(self.reporter.report(request.evidence_challenge()).await?);
        request.endpoint = endpoint;
        (request.context, request.proof) = client.prove(&enclave, request.expected_purpose()).await?;
        let response: SessionResponse = client.call(&enclave, "/v1/sessions", &request).await?;
        if self.min_tier.is_some_and(|min| response.info.tier < min) {
            let _ = self.end_token(&enclave, response.token.duplicate()).await;
            return Err(ClientError::Seal { code: ErrorCode::TierTooLow, message: "session below min_tier".into() });
        }
        Ok((response, enclave))
    }

    /// Extends with a fresh proof and report, then the tunnel's live connections. A session
    /// whose blob is `Expired` restarts through `reload_with`; one whose token already expired
    /// restarts on the same blob. `SessionEnded` and `IntegrityFailed` stop the tunnel.
    async fn extend(&self) -> Result<Renewal, ClientError> {
        let _one = self.serial.lock().await;
        if self.ended.load(Ordering::Relaxed) {
            return Err(ClientError::Seal { code: ErrorCode::SessionEnded, message: "the session was ended".into() });
        }
        let client = &self.client;
        let enclave = client.enclave().await?;
        let (context, proof) = placeholder(client.tenant());
        let mut request = ExtendRequest { token: self.token(), endpoint: None, context, proof };
        let endpoint = Some(self.reporter.report(request.evidence_challenge()).await?);
        request.endpoint = endpoint;
        (request.context, request.proof) = client.prove(&enclave, request.expected_purpose()).await?;
        match client.call::<_, ExtendResponse>(&enclave, "/v1/sessions/extend", &request).await {
            Ok(extended) => {
                self.set_token(&extended.token, extended.expires_at);
                if let Some(tunnel) = self.tunnel() {
                    tunnel.push_extend(&extended.token).await;
                }
                Ok(Renewal::Extended)
            }
            Err(ClientError::Seal { code: ErrorCode::SessionExpired, .. }) => {
                let (response, _) = self.start().await?;
                Ok(Renewal::Restarted(Box::new(response)))
            }
            Err(ClientError::Seal { code: ErrorCode::Expired, .. }) if self.reload.is_some() => {
                let reload = self.reload.as_ref().expect("checked");
                *self.blob.lock().unwrap_or_else(|e| e.into_inner()) = reload().await?;
                let (response, _) = self.start().await?;
                Ok(Renewal::Restarted(Box::new(response)))
            }
            Err(e @ ClientError::Seal { code: ErrorCode::SessionEnded | ErrorCode::IntegrityFailed, .. }) => {
                self.ended.store(true, Ordering::Relaxed);
                if let Some(tunnel) = self.tunnel() {
                    tunnel.stop();
                }
                Err(e)
            }
            Err(e) => Err(e),
        }
    }

    async fn end_token(&self, enclave: &Arc<VerifiedEnclave>, token: Bearer) -> Result<(), ClientError> {
        match self.client.call_empty(enclave, "/v1/sessions/end", &EndRequest { token }).await {
            Err(ClientError::Seal { code: ErrorCode::SessionEnded, .. }) => Ok(()),
            other => other,
        }
    }

    /// `POST /v1/sessions/end` with the current token; a session already ended counts as ended.
    async fn end(&self) -> Result<(), ClientError> {
        let enclave = self.client.enclave().await?;
        self.end_token(&enclave, self.token()).await
    }
}

/// The tunnel extends this long before expiry: half the token's remaining life, at most
/// `SESSION_EXTEND_SECS` and at least a second.
fn next_extend(expires_at: seal_proto::UnixTime, now: seal_proto::UnixTime) -> Duration {
    let half = expires_at.saturating_sub(now) / 2;
    Duration::from_secs(half.clamp(1, SESSION_EXTEND_SECS))
}

/// Extends the tunnel's session before each expiry until it ends. Transient failures are
/// retried at the same pace while the token lives; an ended session stops the loop.
async fn auto_extend(live: Arc<Live>) {
    loop {
        tokio::time::sleep(next_extend(live.expires_at.load(Ordering::Relaxed), now())).await;
        match live.extend().await {
            Ok(_) => {}
            Err(e @ ClientError::Seal { code: ErrorCode::SessionEnded | ErrorCode::IntegrityFailed, .. }) => {
                tracing::warn!(error = %e, "tunnel: the server ended the session; tunnel stopped");
                return;
            }
            Err(e) => tracing::warn!(error = %e, "tunnel: extending the session failed; retrying"),
        }
    }
}

/// What every session owns, whatever its kind.
struct Core {
    live: Arc<Live>,
    tunnel: tunnel::Tunnel,
    info: SessionInfo,
    destination: Destination,
    /// The app's local key (`LOCAL_KEY_PREFIX…`).
    local_key: Bearer,
    /// The automatic extender, until `close`.
    extender: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// `close` closed the tunnel.
    closed: AtomicBool,
    /// The server answered an end: nothing is left to send.
    ended: AtomicBool,
}

impl Core {
    /// The session's tunnel for a fresh `SessionResponse`, and the typed session.
    async fn open(live: Arc<Live>, response: SessionResponse) -> Result<Session, ClientError> {
        let protocol = response.destination.protocol();
        let local_key = Bearer::new(format!(
            "{LOCAL_KEY_PREFIX}{}",
            seal_proto::codec::b64url(
                seal_crypto::Key32::generate(&mut seal_crypto::UnwrapErr(seal_crypto::SysRng)).expose()
            )
        ));
        let local_key_sha256: [u8; 32] = Sha256::digest(local_key.expose().as_bytes()).into();
        let mut replicas: Vec<(String, u16)> = Vec::new();
        for endpoint in live.client.endpoints_from_current() {
            let replica = crate::verify::host_port(&endpoint)?;
            if !replicas.contains(&replica) {
                replicas.push(replica);
            }
        }
        let tunnel = tunnel::Tunnel::start(live.client.clone(), live.token.clone(), local_key_sha256, replicas).await?;
        *live.tunnel.lock().unwrap_or_else(|e| e.into_inner()) = Some(tunnel.shared());
        let extender = Some(tokio::spawn(auto_extend(live.clone())));
        let core = Core {
            live,
            tunnel,
            info: response.info,
            destination: response.destination,
            local_key,
            extender: Mutex::new(extender),
            closed: AtomicBool::new(false),
            ended: AtomicBool::new(false),
        };
        Ok(match Kind::of(protocol) {
            Kind::Http => Session::Http(HttpSession { url: core.http_url(), key: core.credential(), core }),
            Kind::Database => Session::Database(DatabaseSession { protocol, dsn: core.dsn(), core }),
        })
    }

    async fn extend(&mut self) -> Result<Option<SessionResponse>, ClientError> {
        match self.live.extend().await? {
            Renewal::Extended => {
                self.info.expires_at = self.live.expires_at.load(Ordering::Relaxed);
                Ok(None)
            }
            Renewal::Restarted(response) => Ok(Some(*response)),
        }
    }

    /// Adopts a restarted session's info.
    fn restarted(&mut self, response: SessionResponse) {
        self.info = response.info;
        self.destination = response.destination;
    }

    /// Sends the end unless the server already answered one; stops the extender and the tunnel
    /// on the first call.
    async fn close(&self) -> Result<(), ClientError> {
        if self.ended.load(Ordering::Relaxed) {
            return Ok(());
        }
        self.live.ended.store(true, Ordering::Relaxed);
        if let Some(extender) = self.extender.lock().unwrap_or_else(|e| e.into_inner()).take() {
            extender.abort();
        }
        let ended = self.live.end().await;
        if ended.is_ok() {
            self.ended.store(true, Ordering::Relaxed);
        }
        if !self.closed.swap(true, Ordering::Relaxed) {
            self.tunnel.close().await;
        }
        ended
    }

    /// What the app presents: the tunnel's local key.
    fn credential(&self) -> Bearer {
        self.local_key.duplicate()
    }

    /// Where the app sends HTTP: the tunnel, plain HTTP on loopback.
    fn http_url(&self) -> url::Url {
        let path = match &self.destination {
            Destination::Https { path_prefix, .. } => path_prefix.as_str(),
            _ => "/",
        };
        url::Url::parse(&format!("http://{}{path}", self.tunnel.local_addr()))
            .expect("a host, a port and a validated path prefix form a URL")
    }

    /// A complete connection string for the destination's driver, through the tunnel.
    fn dsn(&self) -> Bearer {
        Bearer::new(dsn(&self.destination, &self.tunnel.local_addr().to_string(), self.local_key.expose()))
    }
}

impl Drop for Core {
    /// A session not closed successfully ends in the background: the tunnel stops at once and
    /// the end request is sent (once more, after a failed `close`) when a runtime is there to send it.
    fn drop(&mut self) {
        if *self.ended.get_mut() {
            return;
        }
        if let Some(extender) = self.extender.get_mut().unwrap_or_else(|e| e.into_inner()).take() {
            extender.abort();
        }
        if let Some(tunnel) = self.live.tunnel() {
            tunnel.stop();
        }
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let live = self.live.clone();
            runtime.spawn(async move {
                if let Err(e) = live.end().await {
                    tracing::debug!(error = %e, "ending a dropped session failed");
                }
            });
        }
    }
}

/// The connection string for `destination` at `host_port` (the tunnel, on loopback, so in
/// plaintext) with `credential` as password.
fn dsn(destination: &Destination, host_port: &str, credential: &str) -> String {
    let (scheme, user, path) = match destination {
        Destination::Postgres { user, database, .. } => ("postgres", user.as_str(), database.clone()),
        Destination::Redis { user, db, .. } => ("redis", user.as_deref().unwrap_or("default"), db.to_string()),
        Destination::ClickHouse { user, database, .. } => {
            ("clickhouse", user.as_str(), database.clone().unwrap_or_else(|| "default".into()))
        }
        Destination::Https { .. } => ("https", "", String::new()),
    };
    let mut url = url::Url::parse(&format!("{scheme}://{host_port}/")).expect("a host and port form a URL");
    let _ = url.set_username(user);
    let _ = url.set_password(Some(credential));
    url.path_segments_mut().expect("hierarchical URL").pop_if_empty().push(&path);
    if let Destination::Postgres { .. } = destination {
        url.query_pairs_mut().append_pair("sslmode", "disable");
    }
    url.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use seal_proto::blob::{BlobHeader, DekWrap};
    use seal_proto::codec::labeled_digest;

    use seal_proto::policy::SecretPolicy;
    use seal_proto::{AppName, BlobId, PlatformId, TenantId, TenantKeyVersion, TenantRootId};

    fn blob(to: &str) -> String {
        let policy = SecretPolicy::new(to, [AppName::new("checkout").unwrap()]).unwrap();
        Blob {
            header: BlobHeader {
                version: seal_proto::blob::BLOB_VERSION,
                tenant: TenantId::new("acme").unwrap(),
                root_id: TenantRootId([6; 32]),
                tenant_key_version: TenantKeyVersion(1),
                blob_id: BlobId([1; 8]),
                policy_digest: labeled_digest(seal_proto::blob::POLICY_LABEL, &policy),
                created_at: 1,
            },
            policy,
            wraps: vec![DekWrap::Hpke { platform: PlatformId::Sim, enc: vec![1; 32], wrapped_dek: vec![2; 48] }],
            nonce: [3; 12],
            ciphertext: vec![4; 40],
        }
        .to_string()
    }

    #[test]
    fn wrong_kind_fails_before_anything_is_sent() {
        let pg = blob("postgres://app@db.example.com/orders");
        let http = blob("https://api.example.com/v1");
        let err = expect_kind(&pg, Kind::Http).unwrap_err();
        assert!(err.to_string().contains("postgres://app@db.example.com"), "{err}");
        assert!(expect_kind(&pg, Kind::Database).is_ok());
        assert!(expect_kind(&http, Kind::Http).is_ok());
        assert!(expect_kind(&http, Kind::Database).is_err());
        assert!(expect_kind("not a blob", Kind::Http).is_err());
    }

    #[test]
    fn dsns() {
        let dest = |to: &str| Destination::parse(to).unwrap();
        let pg = dest("postgres://app@db.example.com/orders");
        assert_eq!(
            dsn(&pg, "127.0.0.1:5000", "seallk_ab"),
            "postgres://app:seallk_ab@127.0.0.1:5000/orders?sslmode=disable"
        );
        let redis = dest("rediss://cache.example.com:6380/2");
        assert_eq!(dsn(&redis, "127.0.0.1:5001", "seallk_ab"), "redis://default:seallk_ab@127.0.0.1:5001/2");
        let ch = dest("clickhouse://reader@ch.example.com");
        assert_eq!(dsn(&ch, "127.0.0.1:5002", "seallk_ab"), "clickhouse://reader:seallk_ab@127.0.0.1:5002/default");
    }

    #[test]
    fn extends_at_half_life() {
        assert_eq!(next_extend(1_600, 1_000), Duration::from_secs(SESSION_EXTEND_SECS));
        assert_eq!(next_extend(1_010, 1_000), Duration::from_secs(5));
        assert_eq!(next_extend(1_000, 1_000), Duration::from_secs(1));
        assert_eq!(next_extend(10, 1_000), Duration::from_secs(1));
    }
}
