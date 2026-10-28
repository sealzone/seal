//! Postgres: client cleartext-password auth (the Seal credential), upstream SCRAM-SHA-256 over
//! verified TLS, then relay.
//!
//! **Client side.** The app's driver speaks to the SDK tunnel on loopback, and the core has
//! terminated the tunnel's TLS, so an `SSLRequest` or `GSSENCRequest` is answered `N` and the
//! client continues in clear inside the tunnel. The `StartupMessage` must be protocol 3.0; a client asking for a newer 3.x minor or for
//! `_pq_.` options gets `NegotiateProtocolVersion` (3.0, none supported), and any other major
//! version is refused. A `CancelRequest` is served as `cancel` describes, and a startup asking
//! for `replication` is refused. The adapter then asks for a cleartext password, which carries the
//! tunnel's local key (`seal_proto::tunnel::find_local_key`), and resolves it into the session;
//! the session's destination must be Postgres. The client's `user`, `database`, `options` and
//! every other startup parameter are dropped, except the allowlist in
//! `client::FORWARDED_PARAMS` (per-session settings any role may `SET` anyway).
//!
//! **Upstream.** `UpstreamConnector::connect` (`SSLRequest`, then TLS verified against the
//! baked roots and the policy's pins), then a startup message with the destination's `user`
//! and `database`, `client_encoding=UTF8` and the allowlisted parameters, then SCRAM-SHA-256
//! with the secret as password, as SCRAM-SHA-256-PLUS bound to the upstream's TLS connection
//! (`tls-server-end-point`) whenever the server offers it; when it offers only SCRAM-SHA-256,
//! the client-first message says `y`, so a stripped PLUS offer fails. The server is also
//! authenticated by the verified TLS chain and its SCRAM signature. Any other authentication method (cleartext, MD5, GSS, none at all) is
//! refused: the secret is sent only through SCRAM, and only to a server that proves it knows
//! the verifier. The client receives `AuthenticationOk` only once the upstream is ready, then
//! the upstream's `ParameterStatus` messages, a `BackendKeyData` of the adapter's own (a
//! random process ID and key, `cancel`), and `ReadyForQuery`.
//!
//! **Relay.** Each client message is framed. `Query` and `Parse` (at most `MAX_SQL_BODY`) are
//! passed to `Session::observe` (action `QUERY` or `PARSE`, content the SQL text) before they are
//! forwarded; SQL is never parsed or rewritten, so what a statement may do is up to the
//! upstream role's privileges. `FunctionCall` is refused (it runs functions by OID, past
//! observation). A refused request gets an `ERROR` and the connection stays when nothing is in
//! flight and the upstream is idle outside a transaction; otherwise, and for `Verdict::End`,
//! the connection closes with `FATAL`, which also rolls back the upstream transaction. Every
//! upstream message body passes through a `Scrubber` (needle: the secret), released at each
//! message boundary; large messages stream. One `Session::complete` per simple query or
//! extended-protocol cycle (up to its `Sync`), when its `ReadyForQuery` arrives: action
//! `QUERY`, `PARSE` (a cycle with a `Parse`), `EXECUTE` (one without) or `FUNCTION_CALL`,
//! outcome `Allowed`, `UpstreamError(Sqlstate)` with the SQLSTATE of the cycle's first
//! `ErrorResponse` (SQL errors included), or `Denied`, and bytes each way including framing. A cycle cut by the client going away or the session
//! ending is `Aborted`; one cut by the upstream is `UpstreamError`. A connection that fails
//! after the session resolved but before relaying reports one `CONNECT` completion.
//!
//! **Errors** reach the client as `ErrorResponse`s with the adapter's own fixed text
//! (prefixed `seal:`, with the `ErrorCode` where there is one), never upstream text for a
//! failed upstream login. When `Session::ended` fires the connection closes with `FATAL`
//! `57P01` and `serve` returns `Denied` with the reason.
#![forbid(unsafe_code)]

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use seal_adapter::scrub::Scrubber;
use seal_adapter::{
    Adapter, AdapterCtx, AdapterError, BoxStream, Completion, ConnMeta, Outcome, Session, UpstreamErrorKind,
    UpstreamStream,
};
use seal_proto::policy::{Destination, Protocol};
use seal_proto::ErrorCode;
use tokio::io::{AsyncWrite, BufReader, BufWriter};
use zeroize::Zeroizing;

mod cancel;
mod client;
mod relay;
mod upstream;
mod wire;

pub use cancel::CANCEL;
pub use relay::MAX_SQL_BODY;

/// Time a client has from connecting to sending its password.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
/// Time the upstream has from an open TLS connection to its first `ReadyForQuery`.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(30);
/// `Completion::action` of a connection that failed before relaying.
pub const CONNECT: &str = "CONNECT";

/// One per enclave: it knows the keys of the connections it relays, for cancel requests.
#[derive(Debug, Default)]
pub struct PostgresAdapter {
    cancels: Arc<cancel::Cancels>,
}

#[async_trait]
impl Adapter for PostgresAdapter {
    fn protocol(&self) -> Protocol {
        Protocol::Postgres
    }

    /// Serves one connection until either side closes (`Ok`) or the session ends (`Denied`
    /// with the reason). A refused credential is `Denied` with the resolver's code.
    async fn serve(&self, inbound: BoxStream, meta: ConnMeta, ctx: AdapterCtx) -> Result<(), AdapterError> {
        let (client_r, client_w) = tokio::io::split(inbound);
        let mut client_r = BufReader::new(client_r);
        let mut out = relay::ClientOut::new(client_w);

        let login = match tokio::time::timeout(STARTUP_TIMEOUT, client::login(&mut client_r, &mut out)).await {
            Err(_) => return Err(AdapterError::Client("startup timed out")),
            Ok(login) => match login? {
                Some(client::Start::Login(login)) => login,
                Some(client::Start::Cancel { pid, key }) => {
                    return self.cancels.cancel(pid, key, &*ctx.upstream).await;
                }
                None => return Ok(()),
            },
        };
        let session = match ctx.resolver.resolve(&login.credential, &meta).await {
            Ok(session) => session,
            Err(code) => {
                let text = refusal_text("the Seal credential was refused", code);
                return Err(out.refuse(b"28P01", &text, AdapterError::Denied(code)).await);
            }
        };
        drop(login.credential);

        let policy = session.policy();
        let Destination::Postgres { user, database, .. } = policy.destination() else {
            let code = ErrorCode::PolicyDenied;
            connect_failed(&*session, Outcome::Denied(code));
            let text = refusal_text("the blob is not for a Postgres destination", code);
            return Err(out.refuse(b"28000", &text, AdapterError::Denied(code)).await);
        };
        let stream = match ctx.upstream.connect(policy.destination(), policy.pins()).await {
            Ok(stream) => stream,
            Err(e) => {
                let code = e.code();
                // TLS, missing TLS and pin failures are the policy-denied ones.
                let kind =
                    if code == ErrorCode::PolicyDenied { UpstreamErrorKind::Tls } else { UpstreamErrorKind::Connect };
                connect_failed(&*session, Outcome::UpstreamError(kind));
                let text = refusal_text("the upstream could not be reached", code);
                return Err(out.refuse(b"08001", &text, AdapterError::Upstream(kind)).await);
            }
        };
        let binding = channel_binding(&stream);
        let (upstream_r, upstream_w) = tokio::io::split(stream);
        let mut upstream_r = BufReader::new(upstream_r);
        let mut upstream_w = BufWriter::new(upstream_w);

        let mut params: Vec<(&str, &str)> = vec![("user", user), ("database", database), ("client_encoding", "UTF8")];
        params.extend(login.params.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        let handshake = upstream::handshake(&mut upstream_r, &mut upstream_w, &params, session.secret(), binding);
        let ready = match tokio::time::timeout(UPSTREAM_TIMEOUT, handshake).await {
            Ok(Ok(ready)) => ready,
            Ok(Err(failure)) => return Err(upstream_failed(&*session, &mut out, failure).await),
            Err(_) => {
                connect_failed(&*session, Outcome::UpstreamError(UpstreamErrorKind::Timeout));
                let text = refusal_text("the upstream did not answer in time", ErrorCode::Unavailable);
                return Err(out.refuse(b"08001", &text, AdapterError::Upstream(UpstreamErrorKind::Timeout)).await);
            }
        };

        let registration = self.cancels.register(session.clone(), ready.pid, ready.key);
        let client_key = (registration.pid, registration.key);
        if greet(&*session, &mut out, &ready, client_key).await.is_err() {
            // The client went away before the relay started.
            return Ok(());
        }
        let relay = relay::Relay::new(&*session, out, ready.status, client_key);
        let result = relay.run(&mut client_r, &mut upstream_r, &mut upstream_w).await;
        drop(registration);
        result
    }
}

/// The `tls-server-end-point` channel-binding data of the upstream's TLS connection: the hash
/// of its leaf certificate (RFC 5929), when its signature algorithm defines one.
fn channel_binding(stream: &UpstreamStream) -> Option<Vec<u8>> {
    stream.tls_server_end_point.clone()
}

/// `AuthenticationOk`, the upstream's parameters and notices (scrubbed), the client's own
/// `BackendKeyData` and `ReadyForQuery`.
async fn greet<W: AsyncWrite + Unpin>(
    session: &dyn Session,
    out: &mut relay::ClientOut<W>,
    ready: &upstream::Ready,
    (pid, key): (i32, i32),
) -> std::io::Result<()> {
    let mut scrubber = Scrubber::new(vec![Zeroizing::new(session.secret().to_vec())]);
    out.send(&wire::auth_ok()).await?;
    for message in &ready.messages {
        let (header, body) = message.split_at(5);
        let mut scrubbed = scrubber.push(body);
        scrubbed.extend(scrubber.flush());
        out.send(header).await?;
        out.send(&scrubbed).await?;
    }
    out.send(&wire::backend_key_data(pid, key)).await?;
    out.send(&wire::ready_for_query(ready.status)).await?;
    out.flush().await
}

async fn upstream_failed<W: AsyncWrite + Unpin>(
    session: &dyn Session,
    out: &mut relay::ClientOut<W>,
    failure: upstream::Failure,
) -> AdapterError {
    use upstream::Failure;
    let (outcome, sqlstate, text, err) = match failure {
        Failure::Method => (
            Outcome::Denied(ErrorCode::PolicyDenied),
            *b"08004",
            refusal_text("the upstream asked for authentication other than SCRAM-SHA-256", ErrorCode::PolicyDenied),
            AdapterError::Denied(ErrorCode::PolicyDenied),
        ),
        Failure::Rejected(state) => (
            Outcome::UpstreamError(UpstreamErrorKind::AuthRejected),
            // Only the SQLSTATE of the upstream's refusal reaches the client; never its text.
            state.filter(|s| !s.starts_with(b"28")).unwrap_or(*b"08004"),
            refusal_text("the upstream refused the connection", ErrorCode::Unavailable),
            AdapterError::Upstream(UpstreamErrorKind::AuthRejected),
        ),
        Failure::Scram => (
            Outcome::UpstreamError(UpstreamErrorKind::AuthRejected),
            *b"08004",
            refusal_text("the upstream failed SCRAM authentication", ErrorCode::Unavailable),
            AdapterError::Upstream(UpstreamErrorKind::AuthRejected),
        ),
        Failure::Protocol => (
            Outcome::UpstreamError(UpstreamErrorKind::Protocol),
            *b"08P01",
            refusal_text("the upstream sent an invalid message", ErrorCode::Unavailable),
            AdapterError::Upstream(UpstreamErrorKind::Protocol),
        ),
        Failure::Io => (
            Outcome::UpstreamError(UpstreamErrorKind::Closed),
            *b"08006",
            refusal_text("the upstream closed the connection", ErrorCode::Unavailable),
            AdapterError::Upstream(UpstreamErrorKind::Closed),
        ),
    };
    connect_failed(session, outcome);
    out.refuse(&sqlstate, &text, err).await
}

fn connect_failed(session: &dyn Session, outcome: Outcome) {
    let action = CONNECT.to_string();
    session.complete(Completion { protocol: Protocol::Postgres, action, outcome, bytes_up: 0, bytes_down: 0 });
}

/// `seal: <text> (<error code>)`.
pub(crate) fn refusal_text(text: &str, code: ErrorCode) -> String {
    format!("seal: {text} ({})", code.as_str())
}

/// SQLSTATE for a refused request in a live session.
pub(crate) fn sqlstate_for(code: ErrorCode) -> [u8; 5] {
    match code {
        ErrorCode::PolicyDenied | ErrorCode::IntegrityFailed | ErrorCode::NotAllowed | ErrorCode::TierTooLow => {
            *b"42501"
        }
        ErrorCode::BudgetExceeded => *b"53400",
        ErrorCode::Unavailable => *b"08006",
        ErrorCode::BadRequest => *b"08P01",
        ErrorCode::Expired | ErrorCode::SessionExpired | ErrorCode::SessionEnded | ErrorCode::ResealRequired => {
            *b"28000"
        }
        ErrorCode::VerificationFailed => *b"28000",
        ErrorCode::Internal => *b"XX000",
    }
}
