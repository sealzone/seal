//! The enclave API (`seal_proto::api` has the table) as an axum `Router` over `SealService`,
//! and its HTTPS listener.
//!
//! - Bodies are JSON, read whole up to `MAX_REQUEST_BYTES` (`/v1/blobs`, `/v1/sessions`) or
//!   `MAX_SMALL_REQUEST_BYTES` (extend, end, signals); `/v1/tickets` reads none. An oversized,
//!   unreadable or malformed body is `BadRequest`.
//! - Success: `200` with the JSON response, or `204` for `/v1/sessions/end` and `/v1/signals`.
//! - Errors: `ErrorCode::http_status()` with an `ApiError` body whose message is fixed per code.
//!   `ServiceError::detail` is logged at debug level and never sent. Unknown paths and methods
//!   are `BadRequest`.
//! - `GET /v1/attestation?nonce=<b64url of 32 bytes>` (the only parameter; anything else is
//!   `BadRequest`) answers the challenge for the connection it arrives on, whose TLS 1.3
//!   exporter the listener records (`Source`); a TLS 1.2 connection is `BadRequest`. The
//!   answer is one signature over the latest periodic evidence, so it needs no rate limit.
//! - `POST /v1/tickets` and `POST /v1/blobs`, which anyone may call, are rate limited per
//!   connection source (the peer's IPv4 address, or its IPv6 /64): a bucket of `TICKET_BURST`
//!   tickets refilled at `TICKETS_PER_SEC`, and one of `SEAL_BURST` seals refilled at
//!   `SEALS_PER_SEC`. Over the limit is `BudgetExceeded`. Each limiter tracks at most
//!   `SOURCES` sources; when every one is mid-burst, a new source displaces the fullest
//!   bucket, so sources cycled in never refill anyone else's.
//!
//! The port holds at most `MAX_CONNECTIONS` connections at once, API and tunnels together,
//! and `MAX_CONNECTIONS_PER_SOURCE` from one source (keyed as the rate limits are); a
//! connection past either is closed before its TLS handshake. A connection holds its slot
//! from the accept until it closes: the PROXY header and handshake within `HANDSHAKE_TIMEOUT`,
//! then a tunnel until it ends, or an API connection until it goes `API_IDLE_TIMEOUT` with no
//! byte moving either way.
//!
//! `serve` terminates TLS itself with the enclave's TLS key (`SealService::tls_config`), the
//! same key the attestation binds, so clients pin it before sending anything. The port is the
//! enclave's only one: a connection whose ClientHello offers the tunnel's ALPN
//! (`seal_proto::tunnel::ALPN`) is a data-plane tunnel, admitted or dropped before the
//! handshake (`SealService::admits_tunnel`) and then served by `SealService::serve_tunnel`;
//! every other connection is the API.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Bytes;
use axum::extract::connect_info::{ConnectInfo, Connected};
use axum::extract::{DefaultBodyLimit, FromRequest, RawQuery, Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::serve::{IncomingStream, Listener};
use axum::{Extension, Json, Router};
use seal_proto::api::{
    ApiError, AttestationResponse, ChallengedAttestation, EndRequest, ExtendRequest, ExtendResponse, SealRequest,
    SealResponse, SessionRequest, SessionResponse, SignalRequest,
};
use seal_proto::freshness::ProofTicket;
use seal_proto::tunnel::ALPN;
use seal_proto::ErrorCode;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{Instant, Sleep};
use tokio_rustls::server::TlsStream;

use crate::{SealService, ServiceError};

/// Largest body of `/v1/blobs` and `/v1/sessions` (a sealed secret, or a blob and a proof).
pub const MAX_REQUEST_BYTES: usize = 1 << 20;
/// Largest body of `/v1/sessions/extend`, `/v1/sessions/end` and `/v1/signals`.
pub const MAX_SMALL_REQUEST_BYTES: usize = 64 << 10;
/// Tickets one connection source may take at once.
pub const TICKET_BURST: u32 = 20;
/// Rate at which a source's ticket bucket refills.
pub const TICKETS_PER_SEC: u32 = 5;
/// Seals one connection source may make at once.
pub const SEAL_BURST: u32 = 20;
/// Rate at which a source's seal bucket refills.
pub const SEALS_PER_SEC: u32 = 2;

/// Connections the port holds at once, API and tunnels together: with a 1 MiB request body
/// buffered on each, about 1 GiB, half the container.
pub const MAX_CONNECTIONS: usize = 1024;
/// Connections one source (an IPv4 address or an IPv6 /64) may hold at once. Callers behind
/// one translated address share it.
pub const MAX_CONNECTIONS_PER_SOURCE: usize = MAX_CONNECTIONS / 2;

/// Sources a limiter tracks at most; past it, sources whose bucket has refilled are forgotten,
/// or else the fullest (`RateLimiter::allow`).
const SOURCES: usize = 10_000;
/// Time from an accepted connection to a finished TLS handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Time an API connection may go with no byte moving either way, between requests or within
/// one. Well past any request's own work (each outbound call has 10 s).
const API_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// The operations the router calls: `SealService`'s, as a seam the router's tests implement.
#[async_trait]
trait Api: Send + Sync + 'static {
    async fn attestation(&self) -> Result<AttestationResponse, ServiceError>;
    async fn challenged_attestation(
        &self,
        nonce: [u8; 32],
        tls_exporter: [u8; 32],
    ) -> Result<ChallengedAttestation, ServiceError>;
    async fn ticket(&self) -> Result<ProofTicket, ServiceError>;
    async fn seal(&self, request: SealRequest) -> Result<SealResponse, ServiceError>;
    // `source`: the connection's peer address, for the apps' network rules.
    async fn session(
        &self,
        request: SessionRequest,
        source: Option<SocketAddr>,
    ) -> Result<SessionResponse, ServiceError>;
    async fn extend(&self, request: ExtendRequest, source: Option<SocketAddr>) -> Result<ExtendResponse, ServiceError>;
    async fn end(&self, request: EndRequest) -> Result<(), ServiceError>;
    async fn signal(&self, request: SignalRequest) -> Result<(), ServiceError>;
}

#[async_trait]
impl Api for SealService {
    async fn attestation(&self) -> Result<AttestationResponse, ServiceError> {
        SealService::attestation(self).await
    }
    async fn challenged_attestation(
        &self,
        nonce: [u8; 32],
        tls_exporter: [u8; 32],
    ) -> Result<ChallengedAttestation, ServiceError> {
        SealService::challenged_attestation(self, nonce, tls_exporter).await
    }
    async fn ticket(&self) -> Result<ProofTicket, ServiceError> {
        SealService::ticket(self).await
    }
    async fn seal(&self, request: SealRequest) -> Result<SealResponse, ServiceError> {
        SealService::seal(self, request).await
    }
    async fn session(
        &self,
        request: SessionRequest,
        source: Option<SocketAddr>,
    ) -> Result<SessionResponse, ServiceError> {
        SealService::session(self, request, source).await
    }
    async fn extend(&self, request: ExtendRequest, source: Option<SocketAddr>) -> Result<ExtendResponse, ServiceError> {
        SealService::extend(self, request, source).await
    }
    async fn end(&self, request: EndRequest) -> Result<(), ServiceError> {
        SealService::end(self, request).await
    }
    async fn signal(&self, request: SignalRequest) -> Result<(), ServiceError> {
        SealService::signal(self, request).await
    }
}

/// Serves the API routes over `service` (module docs) and the service's tunnels on `listener`, terminating TLS with `tls`
/// (`SealService::tls_config`), until `shutdown` resolves; then waits for open requests to
/// finish. Tunnels are not waited for.
pub async fn serve(
    service: Arc<SealService>,
    listener: TcpListener,
    tls: Arc<rustls::ServerConfig>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> io::Result<()> {
    let tunnels: Arc<dyn Tunnels> = service.clone();
    serve_router(routes(service), listener, tls, tunnels, PortLimits::default(), shutdown).await
}

async fn serve_router(
    router: Router,
    listener: TcpListener,
    tls: Arc<rustls::ServerConfig>,
    tunnels: Arc<dyn Tunnels>,
    limits: PortLimits,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> io::Result<()> {
    let listener = TlsListener::new(listener, tls, tunnels, limits)?;
    axum::serve(listener, router.into_make_service_with_connect_info::<Source>()).with_graceful_shutdown(shutdown).await
}

struct AppState<S> {
    service: Arc<S>,
    limits: Limits,
}

impl<S> Clone for AppState<S> {
    fn clone(&self) -> Self {
        Self { service: self.service.clone(), limits: self.limits.clone() }
    }
}

/// The per-source limits of the open calls.
#[derive(Clone)]
struct Limits {
    tickets: Arc<RateLimiter>,
    seals: Arc<RateLimiter>,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            tickets: Arc::new(RateLimiter::new(TICKET_BURST, TICKETS_PER_SEC)),
            seals: Arc::new(RateLimiter::new(SEAL_BURST, SEALS_PER_SEC)),
        }
    }
}

fn routes<S: Api>(service: Arc<S>) -> Router {
    routes_with(service, Limits::default())
}

fn routes_with<S: Api>(service: Arc<S>, limits: Limits) -> Router {
    let state = AppState { service, limits };
    let large = DefaultBodyLimit::max(MAX_REQUEST_BYTES);
    let small = DefaultBodyLimit::max(MAX_SMALL_REQUEST_BYTES);
    Router::new()
        .route("/v1/attestation", get(attestation::<S>))
        .route("/v1/tickets", post(ticket::<S>))
        .route("/v1/blobs", post(seal::<S>).layer(large))
        .route("/v1/sessions", post(session::<S>).layer(large))
        .route("/v1/sessions/extend", post(extend::<S>).layer(small))
        .route("/v1/sessions/end", post(end::<S>).layer(small))
        .route("/v1/signals", post(signal::<S>).layer(small))
        .fallback(unknown)
        .method_not_allowed_fallback(unknown)
        .with_state(state)
}

/// A failed request: `code` reaches the caller with a fixed message, `detail` only the log.
struct Failure(ServiceError);

impl From<ServiceError> for Failure {
    fn from(e: ServiceError) -> Self {
        Self(e)
    }
}

fn bad_request(detail: String) -> Failure {
    Failure(crate::fail(ErrorCode::BadRequest, detail))
}

/// What a caller is told for `code`: safe to show, the same for every failure with that code.
fn message(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::Expired => "the blob has expired or its tenant key version is retired",
        ErrorCode::NotAllowed => "not allowed",
        ErrorCode::TierTooLow => "the session would be below the requested tier",
        ErrorCode::IntegrityFailed => "the endpoint failed an integrity check or its identity is suspended",
        ErrorCode::Unavailable => "temporarily unavailable, retry",
        ErrorCode::PolicyDenied => "denied by the secret's policy",
        ErrorCode::BudgetExceeded => "rate or budget limit exceeded",
        ErrorCode::SessionExpired => "the session token has expired",
        ErrorCode::SessionEnded => "the session has ended",
        ErrorCode::VerificationFailed => "verification failed",
        ErrorCode::BadRequest => "malformed request",
        ErrorCode::Internal => "internal error",
        ErrorCode::ResealRequired => "the blob was not sealed for this enclave's platform; reseal it",
    }
}

impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        let code = self.0.code;
        tracing::debug!(?code, detail = %self.0.detail, "API request failed");
        let status = StatusCode::from_u16(code.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (status, Json(ApiError { code, message: message(code).to_string() })).into_response()
    }
}

/// A JSON request body, within the route's `DefaultBodyLimit`; `BadRequest` otherwise.
struct JsonBody<T>(T);

impl<T: DeserializeOwned, S: Send + Sync> FromRequest<S> for JsonBody<T> {
    type Rejection = Failure;

    async fn from_request(req: Request, state: &S) -> Result<Self, Failure> {
        let body = Bytes::from_request(req, state).await.map_err(|e| bad_request(format!("request body: {e}")))?;
        // serde_json's message can quote a value (a token, a JWT), so only where it failed is kept.
        serde_json::from_slice(&body).map(JsonBody).map_err(|e| {
            bad_request(format!("request body: {:?} error at line {}, column {}", e.classify(), e.line(), e.column()))
        })
    }
}

async fn unknown() -> Failure {
    bad_request("no such route".into())
}

/// The periodic attestation, or with `nonce=` the answer to that challenge for this connection.
async fn attestation<S: Api>(
    State(state): State<AppState<S>>,
    source: Option<Extension<ConnectInfo<Source>>>,
    RawQuery(query): RawQuery,
) -> Result<Response, Failure> {
    let Some(query) = query else {
        return Ok(Json(state.service.attestation().await?).into_response());
    };
    let nonce = query
        .strip_prefix("nonce=")
        .and_then(|value| seal_proto::codec::from_b64url(value).ok())
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| bad_request("attestation query: not nonce=<32 bytes, base64url>".into()))?;
    let tls_exporter = source
        .and_then(|Extension(ConnectInfo(Source(_, exporter)))| exporter)
        .ok_or_else(|| bad_request("an attestation challenge needs a TLS 1.3 connection".into()))?;
    Ok(Json(state.service.challenged_attestation(nonce, tls_exporter).await?).into_response())
}

async fn ticket<S: Api>(
    State(state): State<AppState<S>>,
    source: Option<Extension<ConnectInfo<Source>>>,
) -> Result<Json<ProofTicket>, Failure> {
    limited(&state.limits.tickets, "ticket", source)?;
    Ok(Json(state.service.ticket().await?))
}

async fn seal<S: Api>(
    State(state): State<AppState<S>>,
    source: Option<Extension<ConnectInfo<Source>>>,
    JsonBody(request): JsonBody<SealRequest>,
) -> Result<Json<SealResponse>, Failure> {
    limited(&state.limits.seals, "seal", source)?;
    Ok(Json(state.service.seal(request).await?))
}

/// `BudgetExceeded` once the connection's source is over `limiter`'s rate.
fn limited(limiter: &RateLimiter, what: &str, source: Option<Extension<ConnectInfo<Source>>>) -> Result<(), Failure> {
    let source = source.map(|Extension(ConnectInfo(Source(addr, _)))| bucket_key(addr.ip()));
    match limiter.allow(source, Instant::now()) {
        true => Ok(()),
        false => Err(Failure(crate::fail(ErrorCode::BudgetExceeded, format!("{what} rate limit for {source:?}")))),
    }
}

async fn session<S: Api>(
    State(state): State<AppState<S>>,
    source: Option<Extension<ConnectInfo<Source>>>,
    JsonBody(request): JsonBody<SessionRequest>,
) -> Result<Json<SessionResponse>, Failure> {
    Ok(Json(state.service.session(request, peer(source)).await?))
}

async fn extend<S: Api>(
    State(state): State<AppState<S>>,
    source: Option<Extension<ConnectInfo<Source>>>,
    JsonBody(request): JsonBody<ExtendRequest>,
) -> Result<Json<ExtendResponse>, Failure> {
    Ok(Json(state.service.extend(request, peer(source)).await?))
}

/// The connection's peer address and port, if the listener recorded one.
fn peer(source: Option<Extension<ConnectInfo<Source>>>) -> Option<SocketAddr> {
    source.map(|Extension(ConnectInfo(Source(addr, _)))| addr)
}

async fn end<S: Api>(
    State(state): State<AppState<S>>,
    JsonBody(request): JsonBody<EndRequest>,
) -> Result<StatusCode, Failure> {
    state.service.end(request).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// One body, two credentials — the payload says which (see `SignalRequest`).
async fn signal<S: Api>(
    State(state): State<AppState<S>>,
    JsonBody(request): JsonBody<SignalRequest>,
) -> Result<StatusCode, Failure> {
    state.service.signal(request).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// IPv4 addresses (including IPv4-mapped IPv6) as they are, IPv6 by /64: one host usually
/// holds a whole /64.
fn bucket_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let s = v6.segments();
                IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
            }
        },
    }
}

/// Token buckets by source (`None`: requests served without a known source).
struct RateLimiter {
    burst: f64,
    per_sec: f64,
    buckets: Mutex<HashMap<Option<IpAddr>, (f64, Instant)>>,
}

impl RateLimiter {
    fn new(burst: u32, per_sec: u32) -> Self {
        Self { burst: f64::from(burst), per_sec: f64::from(per_sec), buckets: Mutex::new(HashMap::new()) }
    }

    fn refilled(&self, (tokens, at): (f64, Instant), now: Instant) -> f64 {
        (tokens + now.saturating_duration_since(at).as_secs_f64() * self.per_sec).min(self.burst)
    }

    /// Takes one token from `source`'s bucket at `now`, if it has one.
    fn allow(&self, source: Option<IpAddr>, now: Instant) -> bool {
        let mut buckets = crate::lock(&self.buckets);
        if buckets.len() >= SOURCES && !buckets.contains_key(&source) {
            buckets.retain(|_, bucket| self.refilled(*bucket, now) < self.burst);
            if buckets.len() >= SOURCES {
                // Every tracked source is mid-burst: forget the fullest, which gains the least
                // by starting over. A drained bucket goes only once every other one is as
                // drained, which costs whoever cycles sources a burst each. (The scan is cheap
                // next to the TLS handshake every new source costs.)
                let fullest = buckets
                    .iter()
                    .map(|(source, bucket)| (*source, self.refilled(*bucket, now)))
                    .max_by(|a, b| a.1.total_cmp(&b.1))
                    .map(|(source, _)| source);
                if let Some(fullest) = fullest {
                    buckets.remove(&fullest);
                }
            }
        }
        let bucket = buckets.entry(source).or_insert((self.burst, now));
        let tokens = self.refilled(*bucket, now);
        if tokens >= 1.0 {
            *bucket = (tokens - 1.0, now);
            true
        } else {
            *bucket = (tokens, now);
            false
        }
    }
}

/// The peer of an API connection and, for TLS 1.3, the connection's exporter for attestation
/// challenges (`seal_proto::api::ATTESTATION_EXPORTER_LABEL`), as `ConnectInfo`.
#[derive(Clone, Copy, Debug)]
struct Source(SocketAddr, Option<[u8; 32]>);

impl Connected<IncomingStream<'_, TlsListener>> for Source {
    fn connect_info(stream: IncomingStream<'_, TlsListener>) -> Self {
        Source(*stream.remote_addr(), crate::runtime::conn::tls_exporter(stream.io().tls.get_ref().1))
    }
}

/// Where the port's tunnel connections go: `SealService` (a seam for the listener's tests).
#[async_trait]
trait Tunnels: Send + Sync + 'static {
    /// Whether a tunnel may connect: asked before its TLS handshake.
    fn admit(&self) -> bool;
    /// Whether a PROXY header's client address is trusted (`SealService::behind_front_door`).
    fn behind_front_door(&self) -> bool;
    async fn serve(&self, stream: TlsStream<TcpStream>, peer: SocketAddr);
}

#[async_trait]
impl Tunnels for SealService {
    fn admit(&self) -> bool {
        self.admits_tunnel().map_err(|e| tracing::debug!(error = %e, "tunnel refused before its handshake")).is_ok()
    }
    fn behind_front_door(&self) -> bool {
        SealService::behind_front_door(self)
    }
    async fn serve(&self, stream: TlsStream<TcpStream>, peer: SocketAddr) {
        let exporter = crate::runtime::conn::tls_exporter(stream.get_ref().1);
        if let Err(e) = self.serve_tunnel(Box::new(stream), Some(peer), exporter).await {
            tracing::debug!(%peer, error = %e, "tunnel connection ended");
        }
    }
}

/// The port's connection limits: `MAX_CONNECTIONS`, `MAX_CONNECTIONS_PER_SOURCE` and
/// `API_IDLE_TIMEOUT` (smaller in tests).
#[derive(Clone, Copy, Debug)]
struct PortLimits {
    connections: usize,
    per_source: usize,
    idle: Duration,
}

impl Default for PortLimits {
    fn default() -> Self {
        Self { connections: MAX_CONNECTIONS, per_source: MAX_CONNECTIONS_PER_SOURCE, idle: API_IDLE_TIMEOUT }
    }
}

/// The connections the port holds: a permit each, and a count per source (`bucket_key`).
struct Slots {
    all: Arc<Semaphore>,
    per_source: usize,
    held: Mutex<HashMap<IpAddr, usize>>,
}

impl Slots {
    fn new(limits: &PortLimits) -> Arc<Self> {
        Arc::new(Self {
            all: Arc::new(Semaphore::new(limits.connections)),
            per_source: limits.per_source,
            held: Mutex::new(HashMap::new()),
        })
    }

    /// The slot of a connection holding `permit` from `ip`, unless its source holds its share.
    fn take(self: &Arc<Self>, permit: OwnedSemaphorePermit, ip: IpAddr) -> Option<Slot> {
        let source = bucket_key(ip);
        let mut held = crate::lock(&self.held);
        let count = held.get(&source).copied().unwrap_or(0);
        if count >= self.per_source {
            return None;
        }
        held.insert(source, count + 1);
        Some(Slot { slots: self.clone(), source, _permit: permit })
    }
}

/// One connection's place in `Slots`, given back when dropped.
struct Slot {
    slots: Arc<Slots>,
    source: IpAddr,
    _permit: OwnedSemaphorePermit,
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut held = crate::lock(&self.slots.held);
        if let Some(count) = held.get_mut(&self.source) {
            *count -= 1;
            if *count == 0 {
                held.remove(&self.source);
            }
        }
    }
}

/// An API connection: its TLS stream, which fails once no byte has moved either way for
/// `idle`, and its slot.
struct ApiStream {
    tls: TlsStream<TcpStream>,
    idle: Duration,
    deadline: Pin<Box<Sleep>>,
    _slot: Slot,
}

impl ApiStream {
    fn new(tls: TlsStream<TcpStream>, idle: Duration, slot: Slot) -> Self {
        Self { tls, idle, deadline: Box::pin(tokio::time::sleep(idle)), _slot: slot }
    }

    /// `poll` of the stream, which moves the deadline when it is ready and fails once the
    /// deadline passes while it is not.
    fn poll_io<T>(&mut self, cx: &mut Context<'_>, poll: Poll<io::Result<T>>) -> Poll<io::Result<T>> {
        match poll {
            Poll::Ready(result) => {
                self.deadline.as_mut().reset(Instant::now() + self.idle);
                Poll::Ready(result)
            }
            Poll::Pending => match self.deadline.as_mut().poll(cx) {
                Poll::Ready(()) => Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, "API connection idle"))),
                Poll::Pending => Poll::Pending,
            },
        }
    }
}

impl AsyncRead for ApiStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.tls).poll_read(cx, buf);
        this.poll_io(cx, poll)
    }
}

impl AsyncWrite for ApiStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.tls).poll_write(cx, buf);
        this.poll_io(cx, poll)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.tls).poll_write_vectored(cx, bufs);
        this.poll_io(cx, poll)
    }

    fn is_write_vectored(&self) -> bool {
        self.tls.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.tls).poll_flush(cx);
        this.poll_io(cx, poll)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().tls).poll_shutdown(cx)
    }
}

/// Accepts TCP connections within `PortLimits` (past them, a connection is closed at once) and
/// completes their TLS handshakes in the background (each within `HANDSHAKE_TIMEOUT`), so a
/// slow client never holds up the others; tunnels go to `tunnels`, the rest to the API. Stops
/// accepting once dropped.
struct TlsListener {
    rx: tokio::sync::mpsc::Receiver<(ApiStream, SocketAddr)>,
    local: SocketAddr,
}

impl TlsListener {
    fn new(
        listener: TcpListener,
        config: Arc<rustls::ServerConfig>,
        tunnels: Arc<dyn Tunnels>,
        limits: PortLimits,
    ) -> io::Result<Self> {
        let local = listener.local_addr()?;
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        let slots = Slots::new(&limits);
        tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    _ = tx.closed() => return,
                    accepted = listener.accept() => accepted,
                };
                let (mut tcp, socket_peer) = match accepted {
                    Ok(conn) => conn,
                    Err(e) => {
                        tracing::warn!(error = %e, "API accept failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let Ok(permit) = slots.all.clone().try_acquire_owned() else {
                    tracing::debug!(peer = %socket_peer, "connection refused: the port is full");
                    continue;
                };
                // Small writes (TLS handshakes, preambles, requests) go out at once.
                let _ = tcp.set_nodelay(true);
                let (config, tunnels, tx, slots) = (config.clone(), tunnels.clone(), tx.clone(), slots.clone());
                tokio::spawn(async move {
                    // A PROXY header first, if the connection starts with one: its client
                    // address stands for the socket's only on a replica behind the front door.
                    let accepting = async {
                        let named = crate::proxy::read(&mut tcp).await?;
                        let peer = named.filter(|_| tunnels.behind_front_door()).unwrap_or(socket_peer);
                        let Some(slot) = slots.take(permit, peer.ip()) else {
                            tracing::debug!(%peer, "connection refused: its source holds its share of the port");
                            return Ok(None);
                        };
                        let accepted = handshake(tcp, config, &*tunnels).await?;
                        Ok::<_, io::Error>(accepted.map(|accepted| (accepted, peer, slot)))
                    };
                    let peer = socket_peer;
                    let ((tls, tunnel), peer, slot) = match tokio::time::timeout(HANDSHAKE_TIMEOUT, accepting).await {
                        Ok(Ok(Some(accepted))) => accepted,
                        Ok(Ok(None)) => return,
                        Ok(Err(e)) => return tracing::debug!(%peer, error = %e, "TLS handshake failed"),
                        Err(_) => return tracing::debug!(%peer, "TLS handshake timed out"),
                    };
                    if tunnel {
                        tunnels.serve(tls, peer).await;
                        drop(slot);
                    } else {
                        let _ = tx.send((ApiStream::new(tls, limits.idle, slot), peer)).await;
                    }
                });
            }
        });
        Ok(Self { rx, local })
    }
}

/// The TLS handshake, and whether the connection is a tunnel. `None` for a tunnel refused
/// before its handshake (dropped: the tunnel tries its next replica).
async fn handshake(
    tcp: TcpStream,
    config: Arc<rustls::ServerConfig>,
    tunnels: &dyn Tunnels,
) -> io::Result<Option<(TlsStream<TcpStream>, bool)>> {
    let start = tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), tcp).await?;
    let tunnel = start.client_hello().alpn().is_some_and(|mut offered| offered.any(|p| p == ALPN));
    if tunnel && !tunnels.admit() {
        return Ok(None);
    }
    let tls = start.into_stream(config).await?;
    if tunnel && tls.get_ref().1.alpn_protocol() != Some(ALPN) {
        return Ok(None);
    }
    Ok(Some((tls, tunnel)))
}

impl Listener for TlsListener {
    type Io = ApiStream;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.rx.recv().await {
            Some(conn) => conn,
            // The accept task has ended: no connection will come again.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        Ok(self.local)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use base64::Engine as _;
    use seal_net::{BakedRootsConnector, BoxStream, Dialer, HttpsClient, NetError};
    use seal_proto::api::TelemetryReceipt;
    use seal_proto::freshness::ProofTicket;
    use seal_proto::identity::{IdentityProof, ProofContext, ProofPurpose};
    use seal_proto::{Bearer, BlobId, KeyId, PlatformId, ServiceKeyVersion, TenantId, TenantRootId};

    use super::*;

    pub(crate) const HOST: &str = "enclave.test";

    /// Canned answers; records what reached it.
    #[derive(Default)]
    struct Fake {
        calls: Mutex<Vec<String>>,
        /// The TLS exporter the last challenge came with.
        exporter: Mutex<Option<[u8; 32]>>,
    }

    impl Fake {
        fn called(&self, what: impl Into<String>) {
            self.calls.lock().unwrap().push(what.into());
        }
    }

    fn fail(code: ErrorCode) -> ServiceError {
        crate::fail(code, "upstream db.internal:5432 refused user svc_admin")
    }

    #[async_trait]
    impl Api for Fake {
        async fn attestation(&self) -> Result<AttestationResponse, ServiceError> {
            self.called("attestation");
            Err(fail(ErrorCode::Internal))
        }
        async fn challenged_attestation(
            &self,
            nonce: [u8; 32],
            tls_exporter: [u8; 32],
        ) -> Result<ChallengedAttestation, ServiceError> {
            self.called(format!("challenge {}", nonce[0]));
            *self.exporter.lock().unwrap() = Some(tls_exporter);
            Err(fail(ErrorCode::Unavailable))
        }
        async fn ticket(&self) -> Result<ProofTicket, ServiceError> {
            self.called("ticket");
            Ok(ProofTicket { value: [1; 32], expires_at: 99, mac: [2; 32] })
        }
        async fn seal(&self, request: SealRequest) -> Result<SealResponse, ServiceError> {
            self.called(format!("seal {} bytes", request.sealed_payload.len()));
            Ok(SealResponse {
                blob: "seal1.test".into(),
                blob_id: BlobId([3; 8]),
                telemetry: TelemetryReceipt { stream: [4; 16], entry: 7 },
            })
        }
        async fn session(
            &self,
            _request: SessionRequest,
            _source: Option<SocketAddr>,
        ) -> Result<SessionResponse, ServiceError> {
            self.called("session");
            Err(fail(ErrorCode::NotAllowed))
        }
        async fn extend(
            &self,
            request: ExtendRequest,
            _source: Option<SocketAddr>,
        ) -> Result<ExtendResponse, ServiceError> {
            self.called(format!("extend {}", request.token.expose()));
            Ok(ExtendResponse { token: Bearer::new("sealtok_new".into()), expires_at: 1_000 })
        }
        async fn end(&self, request: EndRequest) -> Result<(), ServiceError> {
            self.called(format!("end {}", request.token.expose()));
            Ok(())
        }
        async fn signal(&self, request: SignalRequest) -> Result<(), ServiceError> {
            if request.signatures.is_empty() {
                self.called(format!("signal {}", request.code));
                Err(fail(ErrorCode::VerificationFailed))
            } else {
                self.called(format!("signal+signed {}", request.code));
                Ok(())
            }
        }
    }

    fn tls_key() -> seal_crypto::TlsKey {
        let master =
            seal_crypto::PlatformMasterKey::from_root_secret(PlatformId::Sim, &seal_crypto::Key32::from_bytes([9; 32]));
        let released =
            master.release_service(&TenantId::new("acme").unwrap(), &TenantRootId([1; 32]), ServiceKeyVersion(1));
        seal_crypto::ServiceKeys::from_released(PlatformId::Sim, &released).unwrap().tls
    }

    /// Dials one address whatever the host.
    struct FixedDialer(SocketAddr);

    #[async_trait]
    impl Dialer for FixedDialer {
        async fn dial(&self, _host: &str, _port: u16) -> Result<BoxStream, NetError> {
            let stream = TcpStream::connect(self.0).await.map_err(|e| NetError::Connect {
                host: self.0.to_string(),
                port: self.0.port(),
                reason: e.to_string(),
            })?;
            Ok(Box::new(stream))
        }
    }

    /// Serves the routes over `fake` with the test TLS key; an HTTPS client trusting its CA.
    async fn serve_fake(fake: Arc<Fake>) -> HttpsClient {
        serve_fake_with(fake, Limits::default()).await
    }

    async fn serve_fake_with(fake: Arc<Fake>, limits: Limits) -> HttpsClient {
        serve_tls(routes_with(fake, limits)).await
    }

    /// A test identity for `HOST` (the runtime builds the real one: `SealService::tls_config`).
    fn tls_config(key: &seal_crypto::TlsKey, names: &[String]) -> Arc<rustls::ServerConfig> {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

        let chain = vec![
            CertificateDer::from(key.leaf_certificate_der(names).unwrap()),
            CertificateDer::from(key.ca_certificate_der(names).unwrap()),
        ];
        let private = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.private_key_pkcs8_der().to_vec()));
        let mut config =
            rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(chain, private)
                .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec(), ALPN.to_vec()];
        Arc::new(config)
    }

    /// Tunnels admitted while `admit` holds; each served one gets `served` written back.
    struct FakeTunnels {
        admit: std::sync::atomic::AtomicBool,
    }

    #[async_trait]
    impl Tunnels for FakeTunnels {
        fn admit(&self) -> bool {
            self.admit.load(std::sync::atomic::Ordering::Relaxed)
        }
        fn behind_front_door(&self) -> bool {
            false
        }
        async fn serve(&self, mut stream: TlsStream<TcpStream>, _: SocketAddr) {
            use tokio::io::AsyncWriteExt;
            let _ = stream.write_all(b"served").await;
            let _ = stream.shutdown().await;
        }
    }

    #[tokio::test]
    async fn one_port_serves_the_api_and_tunnels_by_alpn() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let key = tls_key();
        let names = vec![HOST.to_string()];
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let tunnels = Arc::new(FakeTunnels { admit: true.into() });
        let router = routes_with(Arc::new(Fake::default()), Limits::default());
        let served = tunnels.clone() as Arc<dyn Tunnels>;
        let limits = PortLimits::default();
        tokio::spawn(serve_router(router, listener, tls_config(&key, &names), served, limits, std::future::pending()));
        let mut roots = rustls::RootCertStore::empty();
        roots.add(rustls::pki_types::CertificateDer::from(key.ca_certificate_der(&names).unwrap())).unwrap();
        let connect = |alpn: &[u8]| {
            let mut config =
                rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .with_root_certificates(roots.clone())
                    .with_no_client_auth();
            config.alpn_protocols = vec![alpn.to_vec()];
            async move {
                let tcp = TcpStream::connect(addr).await.unwrap();
                let name = rustls::pki_types::ServerName::try_from(HOST).unwrap();
                tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, tcp).await
            }
        };
        // A tunnel reaches the tunnel handler.
        let mut tls = connect(ALPN).await.unwrap();
        let mut got = Vec::new();
        tls.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"served");
        // A replica that admits none drops it before the handshake completes.
        tunnels.admit.store(false, std::sync::atomic::Ordering::Relaxed);
        assert!(connect(ALPN).await.is_err());
        // The API on the same port, still answering.
        let mut tls = connect(b"http/1.1").await.unwrap();
        tls.write_all(b"GET /v1/nothing HTTP/1.1\r\nhost: enclave.test\r\nconnection: close\r\n\r\n").await.unwrap();
        let mut got = Vec::new();
        tls.read_to_end(&mut got).await.unwrap();
        assert!(got.starts_with(b"HTTP/1.1 400"), "{}", String::from_utf8_lossy(&got));
    }

    /// Serves the routes over a `Fake`, and tunnels that are admitted, on a local port within
    /// `limits`.
    async fn serve_port(limits: PortLimits) -> SocketAddr {
        let key = tls_key();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let tunnels = Arc::new(FakeTunnels { admit: true.into() });
        let router = routes_with(Arc::new(Fake::default()), Limits::default());
        let config = tls_config(&key, &[HOST.to_string()]);
        tokio::spawn(serve_router(router, listener, config, tunnels, limits, std::future::pending()));
        addr
    }

    /// A TLS connection to `addr` from the loopback address `from`, offering `alpn`.
    async fn dial(
        addr: SocketAddr,
        from: [u8; 4],
        alpn: &[u8],
    ) -> io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let mut roots = rustls::RootCertStore::empty();
        let ca = tls_key().ca_certificate_der(&[HOST.to_string()]).unwrap();
        roots.add(rustls::pki_types::CertificateDer::from(ca)).unwrap();
        let mut config =
            rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
        config.alpn_protocols = vec![alpn.to_vec()];
        let socket = tokio::net::TcpSocket::new_v4()?;
        socket.bind(SocketAddr::from((from, 0)))?;
        let tcp = socket.connect(addr).await?;
        let name = rustls::pki_types::ServerName::try_from(HOST).unwrap();
        tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, tcp).await
    }

    /// Dials until a connection is accepted (a closed one frees its slot soon after), within 5 s.
    async fn dial_until_accepted(
        addr: SocketAddr,
        from: [u8; 4],
        alpn: &[u8],
    ) -> tokio_rustls::client::TlsStream<TcpStream> {
        let accepted = async {
            loop {
                if let Ok(tls) = dial(addr, from, alpn).await {
                    return tls;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        };
        tokio::time::timeout(Duration::from_secs(5), accepted).await.expect("a slot was freed")
    }

    #[tokio::test]
    async fn connections_are_capped_in_all_and_per_source_and_freed_when_they_end() {
        use tokio::io::AsyncReadExt;

        let limits = PortLimits { connections: 2, per_source: 1, ..PortLimits::default() };
        let addr = serve_port(limits).await;
        let (a, b, c) = ([127, 0, 0, 1], [127, 0, 0, 2], [127, 0, 0, 3]);
        let held = dial(addr, a, b"http/1.1").await.unwrap();
        assert!(dial(addr, a, b"http/1.1").await.is_err(), "a source holds at most its share");
        let other = dial(addr, b, b"http/1.1").await.unwrap();
        assert!(dial(addr, c, b"http/1.1").await.is_err(), "the port holds at most its connections");
        assert!(dial(addr, c, ALPN).await.is_err(), "tunnels count too");
        // A closed API connection gives its slot back, in all and for its source.
        drop(held);
        let _held = dial_until_accepted(addr, a, b"http/1.1").await;
        drop(other);
        // So does a tunnel once it ends.
        let mut tunnel = dial_until_accepted(addr, c, ALPN).await;
        let mut got = Vec::new();
        tunnel.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"served");
        dial_until_accepted(addr, b, b"http/1.1").await;
    }

    #[tokio::test]
    async fn an_idle_api_connection_is_closed() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let idle = Duration::from_millis(300);
        let addr = serve_port(PortLimits { idle, ..PortLimits::default() }).await;
        let mut tls = dial(addr, [127, 0, 0, 1], b"http/1.1").await.unwrap();
        // Kept alive after a request, it closes once nothing has moved for `idle`.
        tls.write_all(b"GET /v1/nothing HTTP/1.1\r\nhost: enclave.test\r\n\r\n").await.unwrap();
        let mut first = [0u8; 12];
        tls.read_exact(&mut first).await.unwrap();
        assert_eq!(&first, b"HTTP/1.1 400");
        let start = Instant::now();
        let mut rest = Vec::new();
        let closed = tokio::time::timeout(Duration::from_secs(5), tls.read_to_end(&mut rest)).await;
        assert!(closed.is_ok(), "closed when idle");
        assert!(start.elapsed() >= idle - Duration::from_millis(100), "{:?}", start.elapsed());
    }

    #[tokio::test]
    async fn a_challenge_reaches_the_service_with_its_connections_tls_exporter() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let fake = Arc::new(Fake::default());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let tunnels = Arc::new(FakeTunnels { admit: false.into() });
        let router = routes_with(fake.clone(), Limits::default());
        let config = tls_config(&tls_key(), &[HOST.to_string()]);
        tokio::spawn(serve_router(router, listener, config, tunnels, PortLimits::default(), std::future::pending()));
        // `GET path` on a new connection with `versions`: the response and the connection's exporter.
        let get = |path: String, versions: &'static [&'static rustls::SupportedProtocolVersion]| async move {
            let mut roots = rustls::RootCertStore::empty();
            let ca = tls_key().ca_certificate_der(&[HOST.to_string()]).unwrap();
            roots.add(rustls::pki_types::CertificateDer::from(ca)).unwrap();
            let config =
                rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                    .with_protocol_versions(versions)
                    .unwrap()
                    .with_root_certificates(roots)
                    .with_no_client_auth();
            let tcp = TcpStream::connect(addr).await.unwrap();
            let name = rustls::pki_types::ServerName::try_from(HOST).unwrap();
            let mut tls = tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, tcp).await.unwrap();
            let label = seal_proto::api::ATTESTATION_EXPORTER_LABEL;
            let exporter = tls.get_ref().1.export_keying_material([0u8; 32], label, None).unwrap();
            let request = format!("GET {path} HTTP/1.1\r\nhost: {HOST}\r\nconnection: close\r\n\r\n");
            tls.write_all(request.as_bytes()).await.unwrap();
            let mut got = Vec::new();
            tls.read_to_end(&mut got).await.unwrap();
            (String::from_utf8_lossy(&got).into_owned(), exporter)
        };
        static TLS13: [&rustls::SupportedProtocolVersion; 1] = [&rustls::version::TLS13];
        static TLS12: [&rustls::SupportedProtocolVersion; 1] = [&rustls::version::TLS12];
        let (tls13, tls12) = (&TLS13[..], &TLS12[..]);
        let status = |code: ErrorCode| format!("HTTP/1.1 {}", code.http_status());

        let nonce = seal_proto::codec::b64url(&[7; 32]);
        let (response, exporter) = get(format!("/v1/attestation?nonce={nonce}"), tls13).await;
        assert!(response.starts_with(&status(ErrorCode::Unavailable)), "{response}");
        assert_eq!(*fake.exporter.lock().unwrap(), Some(exporter), "the exporter of the connection that asked");
        let (_, other) = get(format!("/v1/attestation?nonce={nonce}"), tls13).await;
        assert_ne!(other, exporter, "every connection has its own");
        assert_eq!(*fake.exporter.lock().unwrap(), Some(other));

        for query in ["nonce=AAAA", "nonce=", "other=1", &format!("nonce={nonce}&x=1"), &format!("x=1&nonce={nonce}")] {
            let (response, _) = get(format!("/v1/attestation?{query}"), tls13).await;
            assert!(response.starts_with(&status(ErrorCode::BadRequest)), "{query}: {response}");
        }
        // TLS 1.2 has no exporter it may use.
        let (response, _) = get(format!("/v1/attestation?nonce={nonce}"), tls12).await;
        assert!(response.starts_with(&status(ErrorCode::BadRequest)), "{response}");
        assert_eq!(*fake.calls.lock().unwrap(), ["challenge 7", "challenge 7"]);
    }

    /// Serves `router` over HTTPS (`serve_router`) for `HOST` on a local port; an HTTPS client
    /// that reaches it for any host and trusts its CA.
    pub(crate) async fn serve_tls(router: Router) -> HttpsClient {
        let key = tls_key();
        let names = vec![HOST.to_string()];
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let tunnels = Arc::new(FakeTunnels { admit: false.into() });
        let limits = PortLimits::default();
        tokio::spawn(serve_router(router, listener, tls_config(&key, &names), tunnels, limits, std::future::pending()));
        let b64 = base64::engine::general_purpose::STANDARD.encode(key.ca_certificate_der(&names).unwrap());
        let pem = format!("-----BEGIN CERTIFICATE-----\n{b64}\n-----END CERTIFICATE-----\n");
        let connector = BakedRootsConnector::with_extra_roots(Arc::new(FixedDialer(addr)), pem.as_bytes()).unwrap();
        HttpsClient::new(Arc::new(connector))
    }

    fn url(path: &str) -> String {
        format!("https://{HOST}{path}")
    }

    fn api_error(body: &[u8]) -> ApiError {
        serde_json::from_slice(body).unwrap()
    }

    fn context() -> ProofContext {
        ProofContext {
            tenant: TenantId::new("acme").unwrap(),
            purpose: ProofPurpose::Session { request_digest: [5; 32] },
            tls_spki_sha256: [6; 32],
            ticket: ProofTicket { value: [1; 32], expires_at: 99, mac: [2; 32] },
        }
    }

    fn proof() -> IdentityProof {
        IdentityProof::AppKey { key_id: KeyId([7; 32]), signature: vec![8; 64] }
    }

    fn seal_request(payload: usize) -> Vec<u8> {
        serde_json::to_vec(&SealRequest {
            service_key_version: ServiceKeyVersion(1),
            hpke_enc: vec![1; 32],
            sealed_payload: vec![2; payload],
        })
        .unwrap()
    }

    #[tokio::test]
    async fn every_route_answers_json_or_its_error_code() {
        let fake = Arc::new(Fake::default());
        let client = serve_fake(fake.clone()).await;

        let (status, body) = client.get(&url("/v1/attestation"), &[]).await.unwrap();
        assert_eq!(status, 500);
        assert_eq!(api_error(&body), ApiError { code: ErrorCode::Internal, message: "internal error".into() });
        assert!(!String::from_utf8_lossy(&body).contains("svc_admin"), "detail never reaches the caller");

        let (status, body) = client.post(&url("/v1/tickets"), &[], b"").await.unwrap();
        assert_eq!(status, 200);
        let ticket: ProofTicket = serde_json::from_slice(&body).unwrap();
        assert_eq!(ticket.expires_at, 99);

        let (status, body) = client.post(&url("/v1/blobs"), &[], &seal_request(10)).await.unwrap();
        assert_eq!(status, 200);
        let sealed: SealResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!((sealed.blob.as_str(), sealed.telemetry.entry), ("seal1.test", 7));

        let session = serde_json::json!({
            "blob": "seal1.test", "context": context(), "proof": proof(),
            "min_tier": null, "endpoint": null,
        });
        let (status, body) = client.post(&url("/v1/sessions"), &[], session.to_string().as_bytes()).await.unwrap();
        assert_eq!((status, api_error(&body).code), (403, ErrorCode::NotAllowed));

        let extend =
            serde_json::json!({ "token": "sealtok_old", "endpoint": null, "context": context(), "proof": proof() });
        let (status, body) =
            client.post(&url("/v1/sessions/extend"), &[], extend.to_string().as_bytes()).await.unwrap();
        assert_eq!(status, 200);
        let extended: ExtendResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!((extended.token.expose(), extended.expires_at), ("sealtok_new", 1_000));

        let (status, body) = client.post(&url("/v1/sessions/end"), &[], br#"{"token":"sealtok_old"}"#).await.unwrap();
        assert_eq!((status, body.len()), (204, 0));

        let signal =
            serde_json::json!({ "code": "edr-high", "severity": "high", "context": context(), "proof": proof() });
        let (status, body) = client.post(&url("/v1/signals"), &[], signal.to_string().as_bytes()).await.unwrap();
        assert_eq!((status, api_error(&body).code), (495, ErrorCode::VerificationFailed));

        // The same body carries an external finding: the sender's fields only (the
        // tenant and source are derived at the replica), serialized for real.
        let external = SignalRequest {
            code: "reverse-shell".into(),
            severity: seal_proto::integrity::Severity::Critical,
            context: None,
            proof: None,
            identity: Some(seal_proto::identity::WorkloadIdentity::AppKey { key_id: seal_proto::KeyId([3; 32]) }),
            observed_at: Some(0),
            blob_id: None,
            signatures: vec![seal_proto::signed::Signature {
                signer: seal_proto::KeyId([4; 32]),
                alg: seal_proto::signed::SigAlg::Ed25519 { sig: vec![0; 64] },
            }],
        };
        let body = serde_json::to_vec(&external).unwrap();
        let (status, body) = client.post(&url("/v1/signals"), &[], &body).await.unwrap();
        assert_eq!((status, body.len()), (204, 0), "{}", String::from_utf8_lossy(&body));

        assert_eq!(
            *fake.calls.lock().unwrap(),
            [
                "attestation",
                "ticket",
                "seal 10 bytes",
                "session",
                "extend sealtok_old",
                "end sealtok_old",
                "signal edr-high",
                "signal+signed reverse-shell"
            ]
        );
    }

    #[tokio::test]
    async fn malformed_bodies_and_unknown_routes_are_bad_requests() {
        let fake = Arc::new(Fake::default());
        let client = serve_fake(fake.clone()).await;
        for (status, body) in [
            client.post(&url("/v1/blobs"), &[], b"{").await.unwrap(),
            client.post(&url("/v1/sessions/end"), &[], br#"{"token": 5}"#).await.unwrap(),
            client.get(&url("/v1/blobs"), &[]).await.unwrap(),
            client.get(&url("/v1/keys"), &[]).await.unwrap(),
        ] {
            assert_eq!((status, api_error(&body).code), (400, ErrorCode::BadRequest));
        }
        assert!(fake.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn bodies_are_limited_per_route() {
        let fake = Arc::new(Fake::default());
        let client = serve_fake(fake.clone()).await;

        // Base64 grows the payload by 4/3: about 0.9 MiB of JSON fits, 1.1 MiB does not.
        let (status, _) = client.post(&url("/v1/blobs"), &[], &seal_request(700 << 10)).await.unwrap();
        assert_eq!(status, 200);
        let big = seal_request(800 << 10);
        assert!(big.len() > MAX_REQUEST_BYTES);
        let (status, body) = client.post(&url("/v1/blobs"), &[], &big).await.unwrap();
        assert_eq!((status, api_error(&body).code), (400, ErrorCode::BadRequest));

        let token = "x".repeat(MAX_SMALL_REQUEST_BYTES);
        let end = serde_json::to_vec(&serde_json::json!({ "token": token })).unwrap();
        let (status, body) = client.post(&url("/v1/sessions/end"), &[], &end).await.unwrap();
        assert_eq!((status, api_error(&body).code), (400, ErrorCode::BadRequest));
        assert_eq!(fake.calls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn tickets_and_seals_are_rate_limited_per_source() {
        let fake = Arc::new(Fake::default());
        // No refill, so a slow machine cannot earn the burst another call (refill: below).
        let limits = Limits { tickets: Arc::new(RateLimiter::new(3, 0)), seals: Arc::new(RateLimiter::new(2, 0)) };
        let client = serve_fake_with(fake.clone(), limits.clone()).await;
        for _ in 0..3 {
            assert_eq!(client.post(&url("/v1/tickets"), &[], b"").await.unwrap().0, 200);
        }
        let (status, body) = client.post(&url("/v1/tickets"), &[], b"").await.unwrap();
        assert_eq!((status, api_error(&body).code), (429, ErrorCode::BudgetExceeded));
        let seal = seal_request(10);
        for _ in 0..2 {
            assert_eq!(client.post(&url("/v1/blobs"), &[], &seal).await.unwrap().0, 200);
        }
        let (status, body) = client.post(&url("/v1/blobs"), &[], &seal).await.unwrap();
        assert_eq!((status, api_error(&body).code), (429, ErrorCode::BudgetExceeded));
        assert_eq!(fake.calls.lock().unwrap().len(), 5);
        // Each request was counted against its connection's source.
        for limiter in [&limits.tickets, &limits.seals] {
            let sources: Vec<_> = limiter.buckets.lock().unwrap().keys().copied().collect();
            assert_eq!(sources, [Some(IpAddr::from([127, 0, 0, 1]))]);
        }
    }

    #[test]
    fn buckets_refill_and_are_kept_per_source() {
        let limiter = RateLimiter::new(2, 1);
        let start = Instant::now();
        let a = Some("10.0.0.1".parse().unwrap());
        let b = Some("10.0.0.2".parse().unwrap());
        assert!(limiter.allow(a, start));
        assert!(limiter.allow(a, start));
        assert!(!limiter.allow(a, start));
        assert!(limiter.allow(b, start), "another source has its own bucket");
        assert!(!limiter.allow(a, start + Duration::from_millis(500)));
        assert!(limiter.allow(a, start + Duration::from_millis(1_100)));
        assert!(!limiter.allow(a, start + Duration::from_millis(1_200)));
        // Refills never exceed the burst.
        let later = start + Duration::from_secs(60);
        assert!(limiter.allow(a, later) && limiter.allow(a, later) && !limiter.allow(a, later));
    }

    #[test]
    fn sources_cycled_in_never_refill_a_drained_bucket() {
        let limiter = RateLimiter::new(2, 0);
        let now = Instant::now();
        let honest = Some("10.0.0.1".parse().unwrap());
        assert!(limiter.allow(honest, now) && limiter.allow(honest, now) && !limiter.allow(honest, now));
        // Every other tracked source mid-burst, then more of them than the limiter tracks.
        for n in 0..SOURCES as u32 + 100 {
            assert!(limiter.allow(Some(IpAddr::from((0x0b00_0000 + n).to_be_bytes())), now));
        }
        assert_eq!(limiter.buckets.lock().unwrap().len(), SOURCES);
        assert!(!limiter.allow(honest, now), "the drained bucket was kept");
    }

    #[test]
    fn ipv6_sources_share_their_64() {
        let key = |s: &str| bucket_key(s.parse().unwrap());
        assert_eq!(key("2001:db8:1:2:aaaa::1"), key("2001:db8:1:2:bbbb::2"));
        assert_ne!(key("2001:db8:1:2::1"), key("2001:db8:1:3::1"));
        assert_eq!(key("::ffff:10.0.0.1"), key("10.0.0.1"));
    }
}
