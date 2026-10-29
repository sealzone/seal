//! HTTP/1.1 and SSE: header injection per policy, path/method policy, response scrubbing.
//!
//! The secret goes only to the sealed destination:
//! - requests must be origin-form (`/path?query`); absolute-form, authority-form and
//!   `CONNECT` are refused (`PolicyDenied`);
//! - the upstream request's `Host` is the destination's host and port, whatever the client sent;
//! - redirects are relayed to the client as responses, never followed, so a `3xx` cannot
//!   carry the injected header to another origin;
//! - `Upgrade` (WebSocket, h2c) is refused, and so is a header that some servers read as the
//!   real method or path (`OVERRIDE_HEADERS`), since the policy checks the request line;
//! - so is a `_method` query parameter, which frameworks (Laravel, Symfony, Rails, Express's
//!   `method-override`) also take as the method. When the policy restricts methods, a
//!   `multipart/form-data` body is refused, and an `application/x-www-form-urlencoded` one
//!   (or a body without a `Content-Type`, which Rack parses as a form) is read whole, up to
//!   `FORM_MAX_BYTES`, and refused if it has a `_method` field. So is a body Laravel reads as
//!   JSON (a `Content-Type` containing `/json` or `+json`), refused if its top-level object has
//!   a `_method` key or if it does not parse; other bodies stream;
//! - the upstream request's `Accept-Encoding` is `identity`, whatever the client sent, so
//!   responses reach the scrubber uncompressed; a response that is encoded anyway is refused;
//! - `Range` and `If-Range` are dropped, so an echo of the secret comes back whole, never in
//!   slices the scrubber cannot match.
//!
//! One inbound connection is one keep-alive HTTP/1.1 server. Its first request must carry a
//! local key (`seal_proto::tunnel::find_local_key`, searched in every header value; at most
//! one per request), which is resolved into the connection's session. Every later request must
//! carry the same one; another is refused and the connection closes. The header carrying it is removed, every value of
//! the policy's injection header is replaced with `Injection::render(secret)`, and hop-by-hop
//! headers are dropped. The request is then checked (`HttpPath`, `HttpPolicy`), passed to
//! `Session::observe`, and forwarded over one upstream connection, opened on first use with
//! `UpstreamConnector::connect` and reopened when the upstream closes it.
//!
//! Responses stream back without buffering (chunked and SSE included): header values,
//! body and trailers pass through a `Scrubber` whose needles are the secret and the rendered
//! header value, and a header or trailer whose name carries a needle in any ASCII case (hyper
//! lowercases names) is dropped; the upstream's reason phrase is never relayed. Each request ends with one
//! `Session::complete`: its outcome and the request and response body byte counts; a response
//! cut before its end (the client went away, the session ended) is `Outcome::Aborted`.
//!
//! Refusals are JSON, `{"seal_error": <ErrorCode>, "message": <fixed text>}`, with
//! `ErrorCode::http_status`. Refusals about the credential and `Verdict::End` also close the
//! connection; other refusals keep it, after reading and discarding the rest of the request
//! body (closing instead when that is over `DRAIN_MAX_BYTES` or `DRAIN_TIMEOUT`). When
//! `Session::ended` fires, in-flight upstream exchanges are cut and the connection closes.
#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{ready, Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::client::conn::http1::SendRequest;
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::{Method, Request, Response, StatusCode, Uri, Version};
use hyper_util::rt::{TokioIo, TokioTimer};
use seal_adapter::policy::HttpPolicy;
use seal_adapter::scrub::Scrubber;
use seal_adapter::{
    Adapter, AdapterCtx, AdapterError, BoxStream, Completion, ConnMeta, Observation, Outcome, Session,
    UpstreamErrorKind, Verdict,
};
use seal_proto::policy::{HttpPath, Protocol};
use seal_proto::tunnel::find_local_key;
use seal_proto::ErrorCode;
use tokio::sync::watch;
use zeroize::Zeroizing;

/// Time a client has to send a request's headers, and how long an idle keep-alive
/// connection stays open.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);
/// After the session ends, how long an error response already being written may take.
const END_GRACE: Duration = Duration::from_secs(1);
/// A refused request's body is read and discarded up to this size, within `DRAIN_TIMEOUT`,
/// to keep the connection; a longer or slower one closes it.
const DRAIN_MAX_BYTES: usize = 1 << 20;
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
/// A response body whose upstream sends nothing for this long gets the scrubber's held-back
/// window (`Scrubber::release`), so a stream (SSE) is never stuck behind it. When that happens
/// depends on arrival times alone, never on the bytes.
const QUIET_RELEASE: Duration = Duration::from_millis(100);
/// `Completion::action` keeps at most this many bytes of the path.
const ACTION_PATH_MAX: usize = 128;
/// Headers some servers and frameworks take as the request's method (`methods` policy) or
/// path (prefix policy) in place of the request line's. A request carrying one is refused.
const OVERRIDE_HEADERS: [&str; 5] =
    ["x-http-method-override", "x-http-method", "x-method-override", "x-original-url", "x-rewrite-url"];
/// Under method rules, a form or JSON body is read whole up to this size to look for a
/// `_method` field before it goes upstream; a longer one is refused.
const FORM_MAX_BYTES: usize = 1 << 20;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type RespBody = BoxBody<Bytes, BoxError>;

#[derive(Debug, Default)]
pub struct HttpAdapter;

#[async_trait]
impl Adapter for HttpAdapter {
    fn protocol(&self) -> Protocol {
        Protocol::Http
    }

    /// Serves until the client or the server closes the connection (`Ok`), or the session
    /// ends (`Denied` with the reason from `Session::ended`). A malformed request is `Client`.
    async fn serve(&self, inbound: BoxStream, meta: ConnMeta, ctx: AdapterCtx) -> Result<(), AdapterError> {
        let (session_tx, mut session_rx) = watch::channel(None);
        let conn = Arc::new(Conn {
            ctx,
            meta,
            bound: tokio::sync::Mutex::new(None),
            session_tx,
            ended: Mutex::new(None),
            upstream_tasks: Mutex::new(Vec::new()),
        });
        let _abort = AbortOnDrop(conn.clone());

        let service_conn = conn.clone();
        let service = hyper::service::service_fn(move |req| {
            let conn = service_conn.clone();
            async move { Ok::<_, Infallible>(conn.handle(req).await) }
        });
        let server = hyper::server::conn::http1::Builder::new()
            .timer(TokioTimer::new())
            .header_read_timeout(HEADER_READ_TIMEOUT)
            .keep_alive(true)
            .serve_connection(TokioIo::new(inbound), service);
        tokio::pin!(server);

        // The session's end, once a request has bound one.
        let ended = async {
            loop {
                let current = session_rx.borrow_and_update().clone();
                match current {
                    None => {
                        if session_rx.changed().await.is_err() {
                            std::future::pending::<()>().await;
                        }
                    }
                    Some(session) => tokio::select! {
                        code = session.ended() => break code,
                        switched = session_rx.changed() => {
                            if switched.is_err() {
                                break session.ended().await;
                            }
                        }
                    },
                }
            }
        };

        tokio::select! {
            result = server.as_mut() => server_result(result),
            code = ended => {
                conn.end(code);
                server.as_mut().graceful_shutdown();
                let _ = tokio::time::timeout(END_GRACE, server.as_mut()).await;
                Err(AdapterError::Denied(code))
            }
        }
    }
}

fn server_result(result: Result<(), hyper::Error>) -> Result<(), AdapterError> {
    match result {
        Ok(()) => Ok(()),
        Err(e) if e.is_parse() || e.is_parse_too_large() || e.is_parse_status() => {
            Err(AdapterError::Client("malformed HTTP request"))
        }
        Err(e) if e.is_incomplete_message() || e.is_canceled() || e.is_closed() || e.is_timeout() => Ok(()),
        Err(e) => Err(AdapterError::Io(std::io::Error::other(e))),
    }
}

/// One inbound connection.
struct Conn {
    ctx: AdapterCtx,
    meta: ConnMeta,
    /// Requests are served one at a time; the lock also serializes upstream use.
    bound: tokio::sync::Mutex<Option<Bound>>,
    /// Announces the session once the first credential resolves, so `serve` can wait on `ended`.
    session_tx: watch::Sender<Option<Arc<dyn Session>>>,
    ended: Mutex<Option<ErrorCode>>,
    upstream_tasks: Mutex<Vec<tokio::task::AbortHandle>>,
}

/// The connection's session, the credential it was resolved from, and the upstream.
struct Bound {
    credential: Zeroizing<String>,
    session: Arc<dyn Session>,
    upstream: Option<SendRequest<UpBody>>,
}

struct AbortOnDrop(Arc<Conn>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort_upstream();
    }
}

/// A refusal: code, fixed message, whether the connection closes after it.
struct Refusal {
    code: ErrorCode,
    message: &'static str,
    close: bool,
}

impl Refusal {
    fn keep(code: ErrorCode, message: &'static str) -> Self {
        Self { code, message, close: false }
    }
    fn close(code: ErrorCode, message: &'static str) -> Self {
        Self { code, message, close: true }
    }
    /// The response after reading what is left of the request body, so the connection can
    /// serve the next request; closes it instead when the rest is too long or too slow.
    async fn after(mut self, body: ReqBody) -> Response<RespBody> {
        if !self.close && !body.is_end_stream() {
            self.close = !drain(body).await;
        }
        self.response()
    }

    fn response(&self) -> Response<RespBody> {
        let body = serde_json::json!({ "seal_error": self.code, "message": self.message }).to_string();
        let mut response = Response::new(Full::new(Bytes::from(body)).map_err(|never| match never {}).boxed());
        *response.status_mut() =
            StatusCode::from_u16(self.code.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
        if self.close {
            response.headers_mut().insert(header::CONNECTION, HeaderValue::from_static("close"));
        }
        response
    }
}

impl Conn {
    fn end(&self, code: ErrorCode) {
        *self.ended.lock().unwrap_or_else(|e| e.into_inner()) = Some(code);
        self.abort_upstream();
    }

    fn abort_upstream(&self) {
        for task in self.upstream_tasks.lock().unwrap_or_else(|e| e.into_inner()).drain(..) {
            task.abort();
        }
    }

    async fn handle(self: Arc<Self>, req: Request<Incoming>) -> Response<RespBody> {
        let req = req.map(ReqBody::Stream);
        let action = action(req.method(), req.uri());
        if let Some(code) = *self.ended.lock().unwrap_or_else(|e| e.into_inner()) {
            return Refusal::close(code, "the session has ended").response();
        }
        let mut bound = self.bound.lock().await;

        let credential_header = match self.authenticate(&mut bound, req.headers()).await {
            Ok(name) => name,
            Err(refusal) => {
                if let Some(b) = bound.as_ref() {
                    complete(&*b.session, &action, Outcome::Denied(refusal.code), 0, 0);
                }
                return refusal.response();
            }
        };
        let Some(b) = bound.as_mut() else {
            return Refusal::close(ErrorCode::Internal, "no session").response();
        };
        let session = b.session.clone();

        if let Err(code) = check_request(&*session, &req) {
            complete(&*session, &action, Outcome::Denied(code), 0, 0);
            return Refusal::keep(code, "the request is outside the blob's policy").after(req.into_body()).await;
        }
        let req = match read_form(&*session, req).await {
            Ok(req) => req,
            Err(refusal) => {
                complete(&*session, &action, Outcome::Denied(refusal.code), 0, 0);
                return refusal.response();
            }
        };

        let target = req.uri().path_and_query().map_or("/", |pq| pq.as_str()).to_string();
        let content = format!("{} {target}", req.method());
        let verdict =
            session.observe(&Observation { protocol: Protocol::Http, action: &action, content: content.as_bytes() });
        match verdict {
            Verdict::Forward => {}
            Verdict::Refuse(code) => {
                complete(&*session, &action, Outcome::Denied(code), 0, 0);
                return Refusal::keep(code, "the request was refused by the tenant's integrity policy")
                    .after(req.into_body())
                    .await;
            }
            Verdict::End(code) => {
                complete(&*session, &action, Outcome::Denied(code), 0, 0);
                drop(bound);
                self.end(code);
                return Refusal::close(code, "the session was ended by the tenant's integrity policy").response();
            }
        }

        let sender = match self.upstream(b).await {
            Ok(sender) => sender,
            Err((kind, code)) => {
                complete(&*session, &action, Outcome::UpstreamError(kind), 0, 0);
                return Refusal::keep(code, "the upstream could not be reached").after(req.into_body()).await;
            }
        };
        let bytes_up = Arc::new(AtomicU64::new(0));
        let upstream_req = match upstream_request(&*session, req, credential_header, &target, bytes_up.clone()) {
            Ok(r) => r,
            Err(code) => {
                complete(&*session, &action, Outcome::Denied(code), 0, 0);
                return Refusal::close(code, "the request could not be prepared").response();
            }
        };
        let response = match sender.send_request(upstream_req).await {
            Ok(response) => response,
            Err(e) => {
                b.upstream = None;
                let up = bytes_up.load(Ordering::Relaxed);
                // The session ending cuts the upstream exchange; say why.
                if let Some(code) = *self.ended.lock().unwrap_or_else(|e| e.into_inner()) {
                    complete(&*session, &action, Outcome::Aborted, up, 0);
                    return Refusal::close(code, "the session has ended").response();
                }
                complete(&*session, &action, Outcome::UpstreamError(send_error_kind(&e)), up, 0);
                return Refusal::keep(ErrorCode::Unavailable, "the upstream request failed").response();
            }
        };

        if encoded(response.headers()) {
            // The unread body leaves the upstream connection unusable.
            b.upstream = None;
            let up = bytes_up.load(Ordering::Relaxed);
            complete(&*session, &action, Outcome::UpstreamError(UpstreamErrorKind::Protocol), up, 0);
            return Refusal::keep(
                ErrorCode::PolicyDenied,
                "the upstream sent an encoded response, which cannot be scrubbed",
            )
            .response();
        }
        drop(bound);

        let status = response.status();
        let outcome = if status.as_u16() >= 400 {
            Outcome::UpstreamError(UpstreamErrorKind::HttpStatus(status.as_u16()))
        } else {
            Outcome::Allowed
        };
        let (mut parts, body) = response.into_parts();
        // Extensions carry the upstream's reason phrase, which is upstream text.
        parts.extensions = Default::default();
        parts.version = Version::HTTP_11;
        strip_hop_by_hop(&mut parts.headers);
        let (mut scrubber, mut names) = scrubbers(&*session);
        scrub_headers(&mut parts.headers, &mut scrubber, &mut names);
        let body = DownBody {
            inner: body,
            scrubber,
            names,
            pending: VecDeque::new(),
            inner_done: false,
            pushed: 0,
            sent: 0,
            quiet: Box::pin(tokio::time::sleep(QUIET_RELEASE)),
            report: Some(Report { session, action, outcome, bytes_up, conn: self.clone() }),
        };
        Response::from_parts(parts, body.boxed())
    }

    /// Binds the connection to a session on its first credential; a later one must be the same.
    /// Returns the header that carried it.
    async fn authenticate(&self, bound: &mut Option<Bound>, headers: &HeaderMap) -> Result<HeaderName, Refusal> {
        let Ok(found) = request_credential(headers) else {
            return Err(Refusal::close(ErrorCode::BadRequest, "more than one Seal credential in the request"));
        };
        let Some((name, credential)) = found else {
            return Err(Refusal::close(ErrorCode::NotAllowed, "the request carries no Seal credential"));
        };
        match bound {
            Some(b) if seal_proto::secret::ct_eq(b.credential.as_bytes(), credential.as_bytes()) => Ok(name),
            Some(_) => Err(Refusal::close(ErrorCode::NotAllowed, "the Seal credential is not this connection's")),
            None => {
                let session = self
                    .ctx
                    .resolver
                    .resolve(&credential, &self.meta)
                    .await
                    .map_err(|code| Refusal::close(code, "the Seal credential was refused"))?;
                if session.policy().injection().is_none() {
                    return Err(Refusal::close(ErrorCode::PolicyDenied, "the blob is not for an HTTP destination"));
                }
                self.session_tx.send_replace(Some(session.clone()));
                *bound = Some(Bound { credential, session, upstream: None });
                Ok(name)
            }
        }
    }

    /// The upstream connection, opened (or reopened after the upstream closed it) as needed.
    async fn upstream<'a>(
        &self,
        b: &'a mut Bound,
    ) -> Result<&'a mut SendRequest<UpBody>, (UpstreamErrorKind, ErrorCode)> {
        if let Some(sender) = b.upstream.as_mut() {
            if !sender.is_closed() && sender.ready().await.is_ok() {
                return Ok(b.upstream.as_mut().expect("checked above"));
            }
        }
        b.upstream = None;
        let policy = b.session.policy();
        let stream = self.ctx.upstream.connect(policy.destination(), policy.pins()).await.map_err(|e| {
            // TLS, missing TLS and pin failures are the policy-denied ones.
            let code = e.code();
            let kind =
                if code == ErrorCode::PolicyDenied { UpstreamErrorKind::Tls } else { UpstreamErrorKind::Connect };
            (kind, code)
        })?;
        let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|_| (UpstreamErrorKind::Protocol, ErrorCode::Unavailable))?;
        let task = tokio::spawn(async move {
            let _ = connection.await;
        });
        let mut tasks = self.upstream_tasks.lock().unwrap_or_else(|e| e.into_inner());
        tasks.retain(|t| !t.is_finished());
        tasks.push(task.abort_handle());
        drop(tasks);
        Ok(b.upstream.insert(sender))
    }
}

/// Reads and discards a refused request's body: true if it ended within the limits.
async fn drain(mut body: ReqBody) -> bool {
    let read = async {
        let mut left = DRAIN_MAX_BYTES;
        while let Some(frame) = body.frame().await {
            let Ok(frame) = frame else { return false };
            if let Some(data) = frame.data_ref() {
                let Some(rest) = left.checked_sub(data.len()) else { return false };
                left = rest;
            }
        }
        true
    };
    tokio::time::timeout(DRAIN_TIMEOUT, read).await.unwrap_or(false)
}

/// `METHOD /path` with the path cut to `ACTION_PATH_MAX` bytes and the query dropped; just
/// `METHOD` when the target has no path (authority-form, asterisk-form).
fn action(method: &Method, uri: &Uri) -> String {
    let path = uri.path();
    if !path.starts_with('/') {
        return method.to_string();
    }
    let mut end = path.len().min(ACTION_PATH_MAX);
    while !path.is_char_boundary(end) {
        end -= 1;
    }
    format!("{method} {}", &path[..end])
}

/// The one Seal credential among the header values: `Ok(None)` without one, `Err` with more.
fn request_credential(headers: &HeaderMap) -> Result<Option<(HeaderName, Zeroizing<String>)>, ()> {
    let mut found = None;
    for (name, value) in headers {
        let text = String::from_utf8_lossy(value.as_bytes());
        if let Some(c) = find_local_key(&text) {
            if found.is_some() {
                return Err(());
            }
            found = Some((name.clone(), Zeroizing::new(c.to_string())));
        }
    }
    Ok(found)
}

/// Request form, `Upgrade`, override headers and parameters, path syntax and the blob's HTTP
/// policy. A multipart body under method rules is refused here; `read_form` checks the others.
fn check_request(session: &dyn Session, req: &Request<ReqBody>) -> Result<(), ErrorCode> {
    let uri = req.uri();
    if req.method() == Method::CONNECT || uri.scheme().is_some() || uri.authority().is_some() {
        return Err(ErrorCode::PolicyDenied);
    }
    let upgrade = req.headers().contains_key(header::UPGRADE)
        || header_tokens(req.headers(), &header::CONNECTION).any(|t| t.eq_ignore_ascii_case("upgrade"));
    if upgrade || OVERRIDE_HEADERS.iter().any(|h| req.headers().contains_key(*h)) {
        return Err(ErrorCode::PolicyDenied);
    }
    if uri.query().is_some_and(|q| has_method_field(q.as_bytes())) {
        return Err(ErrorCode::PolicyDenied);
    }
    if methods_restricted(session) && form_kind(req) == Some(Form::Multipart) {
        return Err(ErrorCode::PolicyDenied);
    }
    let path = HttpPath::parse(uri.path()).map_err(|_| ErrorCode::PolicyDenied)?;
    HttpPolicy::check(session.policy(), req.method().as_str(), &path)
}

fn methods_restricted(session: &dyn Session) -> bool {
    session.policy().http().is_some_and(|r| !r.methods.is_empty())
}

#[derive(Debug, PartialEq, Eq)]
enum Form {
    UrlEncoded,
    Multipart,
}

/// How a server may parse the body as form fields: by its `Content-Type`, or as URL-encoded
/// when a body comes without one (Rack does that for `POST`). `None` for other bodies.
fn form_kind(req: &Request<ReqBody>) -> Option<Form> {
    let mut types = req.headers().get_all(header::CONTENT_TYPE).iter().peekable();
    if types.peek().is_none() {
        return (!req.body().is_end_stream()).then_some(Form::UrlEncoded);
    }
    let mut kind = None;
    for value in types {
        let Ok(text) = value.to_str() else { return Some(Form::UrlEncoded) };
        let media = text.split(';').next().unwrap_or("").trim();
        if media.eq_ignore_ascii_case("multipart/form-data") {
            return Some(Form::Multipart);
        }
        if media.eq_ignore_ascii_case("application/x-www-form-urlencoded") {
            kind = Some(Form::UrlEncoded);
        }
    }
    kind
}

/// Under method rules, reads a URL-encoded or JSON body whole and refuses it if it has a
/// `_method` field (`has_method_field`, `json_has_method`); any other request passes through
/// still streaming.
async fn read_form(session: &dyn Session, req: Request<ReqBody>) -> Result<Request<ReqBody>, Refusal> {
    let (form, json) = (form_kind(&req) == Some(Form::UrlEncoded), json_body(&req));
    if !methods_restricted(session) || !(form || json) || req.body().is_end_stream() {
        return Ok(req);
    }
    let (parts, mut body) = req.into_parts();
    let mut buf = Vec::new();
    while let Some(frame) = body.frame().await {
        let Ok(frame) = frame else {
            return Err(Refusal::close(ErrorCode::BadRequest, "the request body could not be read"));
        };
        if let Some(data) = frame.data_ref() {
            if buf.len() + data.len() > FORM_MAX_BYTES {
                return Err(Refusal::close(ErrorCode::PolicyDenied, "the request body is too large to check"));
            }
            buf.extend_from_slice(data);
        }
    }
    if (form && has_method_field(&buf)) || (json && json_has_method(&buf)) {
        return Err(Refusal::keep(ErrorCode::PolicyDenied, "the request is outside the blob's policy"));
    }
    Ok(Request::from_parts(parts, ReqBody::Buffered(Some(Bytes::from(buf)))))
}

/// Whether Laravel reads the body as JSON (`Request::isJson`): a `Content-Type` that contains
/// `/json` or `+json` anywhere, parameters included (in any case here).
fn json_body(req: &Request<ReqBody>) -> bool {
    req.headers().get_all(header::CONTENT_TYPE).iter().any(|value| {
        let text = value.as_bytes().to_ascii_lowercase();
        text.windows(5).any(|w| w == b"/json" || w == b"+json")
    })
}

/// Whether a JSON body has a `_method` key (any ASCII case) at the top level of an object,
/// the only place Laravel looks. A body serde_json cannot parse counts as having one: PHP's
/// parser takes some that serde_json refuses (nesting past 128 levels, numbers out of `f64`
/// range), and such a body is not let past a check that could not read it. A blank body has
/// none: PHP reads no fields from it.
fn json_has_method(body: &[u8]) -> bool {
    if body.iter().all(u8::is_ascii_whitespace) {
        return false;
    }
    match serde_json::from_slice::<serde_json::Value>(body) {
        Ok(serde_json::Value::Object(fields)) => fields.keys().any(|k| k.eq_ignore_ascii_case("_method")),
        Ok(_) => false,
        Err(_) => true,
    }
}

/// Whether URL-encoded `fields` (a query string or a form body) name a `_method` field, as
/// any common parser would read the name: `+` and `%XX` decoded, ASCII case ignored, PHP's
/// rewriting of leading spaces, ` ` and `.` (to `_`) and `[...]` suffixes applied. `&` and
/// `;` both separate fields.
fn has_method_field(fields: &[u8]) -> bool {
    fields.split(|&b| b == b'&' || b == b';').any(|field| {
        let raw = field.split(|&b| b == b'=').next().unwrap_or_default();
        let mut name = percent_decode(raw);
        name.make_ascii_lowercase();
        let start = name.iter().position(|&b| b != b' ').unwrap_or(name.len());
        let name = &name[start..];
        let name = &name[..name.iter().position(|&b| b == b'[').unwrap_or(name.len())];
        name.len() == 7 && name.iter().zip(b"_method").all(|(&a, &b)| a == b || (b == b'_' && (a == b' ' || a == b'.')))
    })
}

/// `+` as a space and `%XX` as its byte; a `%` without two hex digits stays as it is.
fn percent_decode(raw: &[u8]) -> Vec<u8> {
    let hex = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        let decoded = match (raw[i], raw.get(i + 1).copied().and_then(hex), raw.get(i + 2).copied().and_then(hex)) {
            (b'%', Some(hi), Some(lo)) => {
                i += 2;
                hi << 4 | lo
            }
            (b'+', ..) => b' ',
            (b, ..) => b,
        };
        out.push(decoded);
        i += 1;
    }
    out
}

/// The request as the destination receives it.
fn upstream_request(
    session: &dyn Session,
    req: Request<ReqBody>,
    credential_header: HeaderName,
    target: &str,
    bytes_up: Arc<AtomicU64>,
) -> Result<Request<UpBody>, ErrorCode> {
    let policy = session.policy();
    let injection = policy.injection().ok_or(ErrorCode::PolicyDenied)?;
    let injection_header = HeaderName::from_bytes(injection.header.as_bytes()).map_err(|_| ErrorCode::Internal)?;
    let mut value = HeaderValue::from_bytes(&injection.render(session.secret())).map_err(|_| ErrorCode::Internal)?;
    value.set_sensitive(true);
    let destination = policy.destination();
    let host = HeaderValue::from_str(&format!("{}:{}", destination.host(), destination.port()))
        .map_err(|_| ErrorCode::Internal)?;
    let uri: Uri = target.parse().map_err(|_| ErrorCode::BadRequest)?;

    let (parts, body) = req.into_parts();
    let mut headers = parts.headers;
    strip_hop_by_hop(&mut headers);
    headers.remove(&credential_header);
    headers.remove(&injection_header);
    headers.remove(header::EXPECT);
    headers.remove(header::RANGE);
    headers.remove(header::IF_RANGE);
    headers.insert(injection_header, value);
    headers.insert(header::HOST, host);
    headers.insert(header::ACCEPT_ENCODING, HeaderValue::from_static("identity"));

    let mut upstream = Request::new(UpBody { inner: body, count: bytes_up });
    *upstream.method_mut() = parts.method;
    *upstream.uri_mut() = uri;
    *upstream.version_mut() = Version::HTTP_11;
    *upstream.headers_mut() = headers;
    Ok(upstream)
}

fn header_tokens<'a>(headers: &'a HeaderMap, name: &HeaderName) -> impl Iterator<Item = &'a str> {
    headers.get_all(name).iter().flat_map(|v| v.to_str().unwrap_or("\u{0}").split(',')).map(str::trim)
}

/// Drops the connection-level headers and those the `Connection` header names.
fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let listed: Vec<HeaderName> =
        header_tokens(headers, &header::CONNECTION).filter_map(|t| HeaderName::from_bytes(t.as_bytes()).ok()).collect();
    for name in listed {
        headers.remove(name);
    }
    for name in [
        header::CONNECTION,
        HeaderName::from_static("keep-alive"),
        HeaderName::from_static("proxy-connection"),
        header::PROXY_AUTHENTICATE,
        header::PROXY_AUTHORIZATION,
        header::TE,
        header::TRAILER,
        header::TRANSFER_ENCODING,
        header::UPGRADE,
    ] {
        headers.remove(name);
    }
}

/// Any content coding other than `identity`, or a transfer coding other than `chunked`.
fn encoded(headers: &HeaderMap) -> bool {
    let plain = |t: &str, chunked_ok: bool| {
        t.is_empty() || t.eq_ignore_ascii_case("identity") || (chunked_ok && t.eq_ignore_ascii_case("chunked"))
    };
    header_tokens(headers, &header::CONTENT_ENCODING).any(|t| !plain(t, false))
        || header_tokens(headers, &header::TRANSFER_ENCODING).any(|t| !plain(t, true))
}

/// The response's scrubber, whose needles are the secret and the rendered header value, and
/// the same needles in any ASCII case, for header names.
fn scrubbers(session: &dyn Session) -> (Scrubber, Scrubber) {
    let secret = session.secret();
    let mut needles = vec![Zeroizing::new(secret.to_vec())];
    if let Some(injection) = session.policy().injection() {
        needles.push(injection.render(secret));
    }
    (Scrubber::new(needles.clone()), Scrubber::ignoring_ascii_case(needles))
}

/// Drops every header whose name carries a needle in any of its forms (`names`, which ignores
/// ASCII case: hyper lowercases names, so a name keeps no case to match exactly), then masks
/// every value on its own. Dropped, not masked: `*` is a valid name character, but masked
/// names can collide with each other or with a real header, and no client needs a name made
/// of the secret; refusing instead would not work for trailers, which come after the response
/// has started. Only a whole occurrence matches, as in values. Both scrubbers must hold
/// nothing back when called.
fn scrub_headers(headers: &mut HeaderMap, scrubber: &mut Scrubber, names: &mut Scrubber) {
    let carrying: Vec<HeaderName> = headers
        .keys()
        .filter(|name| {
            let name = name.as_str().as_bytes();
            let mut out = names.push(name);
            out.extend(names.flush());
            out != name
        })
        .cloned()
        .collect();
    for name in carrying {
        headers.remove(name);
    }
    for value in headers.values_mut() {
        let mut out = scrubber.push(value.as_bytes());
        out.extend(scrubber.flush());
        if out != value.as_bytes() {
            // Masking only writes `*`, so the value stays valid.
            *value = HeaderValue::from_bytes(&out).unwrap_or_else(|_| HeaderValue::from_static(""));
        }
    }
}

fn send_error_kind(e: &hyper::Error) -> UpstreamErrorKind {
    if e.is_timeout() {
        UpstreamErrorKind::Timeout
    } else if e.is_parse() || e.is_parse_too_large() || e.is_parse_status() {
        UpstreamErrorKind::Protocol
    } else {
        UpstreamErrorKind::Closed
    }
}

fn complete(session: &dyn Session, action: &str, outcome: Outcome, bytes_up: u64, bytes_down: u64) {
    session.complete(Completion {
        protocol: Protocol::Http,
        action: action.to_string(),
        outcome,
        bytes_up,
        bytes_down,
    });
}

/// A client's request body: streaming, or already read whole (`read_form`).
enum ReqBody {
    Stream(Incoming),
    Buffered(Option<Bytes>),
}

impl Body for ReqBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        match self.get_mut() {
            ReqBody::Stream(inner) => Pin::new(inner).poll_frame(cx),
            ReqBody::Buffered(data) => Poll::Ready(data.take().map(|d| Ok(Frame::data(d)))),
        }
    }
    fn is_end_stream(&self) -> bool {
        match self {
            ReqBody::Stream(inner) => inner.is_end_stream(),
            ReqBody::Buffered(data) => data.is_none(),
        }
    }
    fn size_hint(&self) -> SizeHint {
        match self {
            ReqBody::Stream(inner) => inner.size_hint(),
            ReqBody::Buffered(data) => SizeHint::with_exact(data.as_ref().map_or(0, |d| d.len() as u64)),
        }
    }
}

/// The client's request body on its way upstream, counted.
struct UpBody {
    inner: ReqBody,
    count: Arc<AtomicU64>,
}

impl Body for UpBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        let frame = ready!(Pin::new(&mut self.inner).poll_frame(cx));
        if let Some(Ok(data)) = &frame {
            if let Some(data) = data.data_ref() {
                self.count.fetch_add(data.len() as u64, Ordering::Relaxed);
            }
        }
        Poll::Ready(frame)
    }
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// What `DownBody` reports once, at the end of the body or when it is dropped.
struct Report {
    session: Arc<dyn Session>,
    action: String,
    outcome: Outcome,
    bytes_up: Arc<AtomicU64>,
    /// Tells a cut caused by the session ending (aborted) from an upstream failure.
    conn: Arc<Conn>,
}

/// The upstream's response body on its way to the client, scrubbed as it streams.
struct DownBody {
    inner: Incoming,
    scrubber: Scrubber,
    /// Header names in any ASCII case, for the trailers (`scrub_headers`).
    names: Scrubber,
    /// Scrubbed frames not yet returned.
    pending: VecDeque<Frame<Bytes>>,
    inner_done: bool,
    /// Body bytes taken from upstream.
    pushed: u64,
    /// Body bytes returned to the client.
    sent: u64,
    /// `QUIET_RELEASE` after the upstream's latest data.
    quiet: Pin<Box<tokio::time::Sleep>>,
    report: Option<Report>,
}

impl DownBody {
    /// `outcome` replaces the response's own (`Allowed` or an HTTP status error) when the
    /// body did not finish.
    fn report(&mut self, cut: Option<Outcome>) {
        if let Some(report) = self.report.take() {
            let outcome = cut.unwrap_or(report.outcome);
            let up = report.bytes_up.load(Ordering::Relaxed);
            complete(&*report.session, &report.action, outcome, up, self.sent);
        }
    }
    fn queue(&mut self, data: Vec<u8>) {
        if !data.is_empty() {
            self.pending.push_back(Frame::data(Bytes::from(data)));
        }
    }
}

impl Body for DownBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = &mut *self;
        loop {
            if let Some(frame) = this.pending.pop_front() {
                if let Some(data) = frame.data_ref() {
                    this.sent += data.len() as u64;
                }
                if this.inner_done && this.pending.is_empty() {
                    this.report(None);
                }
                return Poll::Ready(Some(Ok(frame)));
            }
            if this.inner_done {
                this.report(None);
                return Poll::Ready(None);
            }
            let polled = Pin::new(&mut this.inner).poll_frame(cx);
            if polled.is_pending() {
                if this.scrubber.holding() && this.quiet.as_mut().poll(cx).is_ready() {
                    let out = this.scrubber.release();
                    this.queue(out);
                    continue;
                }
                return Poll::Pending;
            }
            match ready!(polled) {
                Some(Ok(frame)) => match frame.into_data() {
                    Ok(data) => {
                        this.pushed += data.len() as u64;
                        this.quiet.as_mut().reset(tokio::time::Instant::now() + QUIET_RELEASE);
                        let out = this.scrubber.push(&data);
                        this.queue(out);
                    }
                    Err(frame) => {
                        // Trailers end the body: release the held-back tail first.
                        let tail = this.scrubber.finish();
                        this.queue(tail);
                        if let Ok(mut trailers) = frame.into_trailers() {
                            scrub_headers(&mut trailers, &mut this.scrubber, &mut this.names);
                            this.pending.push_back(Frame::trailers(trailers));
                        }
                    }
                },
                Some(Err(e)) => {
                    this.inner_done = true;
                    this.pending.clear();
                    let ended = this
                        .report
                        .as_ref()
                        .is_some_and(|r| r.conn.ended.lock().unwrap_or_else(|e| e.into_inner()).is_some());
                    let kind = if e.is_timeout() { UpstreamErrorKind::Timeout } else { UpstreamErrorKind::Closed };
                    this.report(Some(if ended { Outcome::Aborted } else { Outcome::UpstreamError(kind) }));
                    return Poll::Ready(Some(Err(Box::new(e))));
                }
                None => {
                    this.inner_done = true;
                    let tail = this.scrubber.finish();
                    this.queue(tail);
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.pending.is_empty() && (self.inner_done || (self.inner.is_end_stream() && self.pushed == self.sent))
    }

    /// Scrubbing keeps lengths, so the upstream's hint plus what is held back stays exact.
    fn size_hint(&self) -> SizeHint {
        let held = self.pushed - self.sent;
        let inner = if self.inner_done { SizeHint::with_exact(0) } else { self.inner.size_hint() };
        let mut hint = SizeHint::new();
        hint.set_lower(inner.lower() + held);
        if let Some(upper) = inner.upper() {
            hint.set_upper(upper + held);
        }
        hint
    }
}

impl Drop for DownBody {
    /// hyper drops a body once `is_end_stream` says it is done; dropped before that, the client
    /// went away or the session ended mid-body: report what was sent, as aborted.
    fn drop(&mut self) {
        let cut = (!self.is_end_stream()).then_some(Outcome::Aborted);
        self.report(cut);
    }
}
