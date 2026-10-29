//! End to end: a client on an in-memory pipe, the adapter, and a plain local upstream
//! reached through `TestUpstream`.

use std::collections::BTreeSet;
use std::convert::Infallible;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame, Incoming};
use hyper::header::HeaderMap;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use seal_adapter::testing::{claims, FixedResolver, TestClaims, TestUpstream};
use seal_adapter::{Adapter, AdapterCtx, AdapterError, ConnMeta, Outcome, UpstreamErrorKind, Verdict};
use seal_adapter_http::HttpAdapter;
use seal_proto::policy::{Destination, HttpRules, Injection, Protocol, SecretPolicy};
use seal_proto::ErrorCode;
use tokio::sync::{mpsc, Notify};
use tokio::task::JoinHandle;

const SECRET: &str = "sk-test-123";
const TOKEN: &str = "seallk_abc";
const HOST: &str = "api.example.com";

/// What the upstream received.
#[derive(Clone, Debug)]
struct Seen {
    method: String,
    target: String,
    headers: HeaderMap,
    body: Vec<u8>,
}

/// A response body fed from a channel, so tests control chunk boundaries and timing.
struct ChannelBody(mpsc::Receiver<Bytes>);
impl Body for ChannelBody {
    type Data = Bytes;
    type Error = Infallible;
    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        self.0.poll_recv(cx).map(|c| c.map(|b| Ok(Frame::data(b))))
    }
}

type UpBody = http_body_util::combinators::BoxBody<Bytes, Infallible>;

fn full(body: impl Into<Bytes>) -> UpBody {
    Full::new(body.into()).boxed()
}

/// Sends `chunks` as separate frames, each after a short pause; waits on `gate` before the last.
fn chunked(chunks: Vec<&'static str>, gate: Option<Arc<Notify>>) -> UpBody {
    let (tx, rx) = mpsc::channel(1);
    tokio::spawn(async move {
        let last = chunks.len().saturating_sub(1);
        for (i, c) in chunks.into_iter().enumerate() {
            if i == last {
                if let Some(gate) = &gate {
                    gate.notified().await;
                }
            }
            if tx.send(Bytes::from(c)).await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    });
    ChannelBody(rx).boxed()
}

struct Upstream {
    seen: Arc<Mutex<Vec<Seen>>>,
    /// Released by the SSE test once it has read the first events.
    gate: Arc<Notify>,
}

async fn route(req: Request<Incoming>, seen: Arc<Mutex<Vec<Seen>>>, gate: Arc<Notify>) -> Response<UpBody> {
    let method = req.method().to_string();
    let target = req.uri().to_string();
    let headers = req.headers().clone();
    let body = req.into_body().collect().await.map(|b| b.to_bytes().to_vec()).unwrap_or_default();
    seen.lock().unwrap().push(Seen { method, target: target.clone(), headers, body });
    let path = target.split('?').next().unwrap().to_string();
    let mut response = match path.as_str() {
        "/v1/redirect" => Response::builder()
            .status(StatusCode::FOUND)
            .header("location", "https://evil.example/steal")
            .body(full(""))
            .unwrap(),
        "/v1/gzip" => Response::builder().header("content-encoding", "gzip").body(full(&b"\x1f\x8b"[..])).unwrap(),
        "/v1/te-gzip" => Response::builder().header("transfer-encoding", "gzip, chunked").body(full("x")).unwrap(),
        "/v1/leak" => Response::builder()
            .header("x-debug", format!("key={SECRET}"))
            .body(full(format!("{{\"error\":\"invalid key {SECRET}\",\"auth\":\"Bearer {SECRET}\"}}")))
            .unwrap(),
        "/v1/leak-split" => Response::new(chunked(vec!["error: key sk-te", "st-1", "23 is invalid"], None)),
        "/v1/sse" => Response::builder()
            .header("content-type", "text/event-stream")
            .body(chunked(
                vec!["data: {\"n\":1}\n\n", "data: Bearer sk-t", "est-123\n\n", "data: [DONE]\n\n"],
                Some(gate),
            ))
            .unwrap(),
        "/v1/hang" => Response::new(chunked(vec!["first\n", "never"], Some(gate))),
        "/v1/fail" => Response::builder().status(500).body(full("boom")).unwrap(),
        _ => Response::new(full("ok")),
    };
    response.headers_mut().insert("x-upstream", "1".parse().unwrap());
    response
}

async fn start_upstream() -> (Upstream, std::net::SocketAddr) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let gate = Arc::new(Notify::new());
    let (s, g) = (seen.clone(), gate.clone());
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let (s, g) = (s.clone(), g.clone());
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |req| {
                    let (s, g) = (s.clone(), g.clone());
                    async move { Ok::<_, Infallible>(route(req, s, g).await) }
                });
                let _ =
                    hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), service).await;
            });
        }
    });
    (Upstream { seen, gate }, addr)
}

struct Harness {
    resolver: Arc<FixedResolver>,
    upstream: Upstream,
    ctx: AdapterCtx,
}

impl Harness {
    async fn new(claims: TestClaims) -> Self {
        let (upstream, addr) = start_upstream().await;
        let connector = TestUpstream::new();
        connector.route(HOST, addr);
        let resolver = FixedResolver::new();
        resolver.insert(TOKEN, claims);
        let ctx = AdapterCtx { resolver: resolver.clone(), upstream: connector };
        Self { resolver, upstream, ctx }
    }

    async fn default() -> Self {
        Self::new(default_claims()).await
    }

    fn seen(&self) -> Vec<Seen> {
        self.upstream.seen.lock().unwrap().clone()
    }

    /// One inbound connection: the adapter's task and a client over the pipe.
    async fn connect(&self) -> Client {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let ctx = self.ctx.clone();
        let meta = ConnMeta {
            connection_id: 7,
            protocol: Protocol::Http,
            peer: None,
            tunnel: seal_proto::tunnel::TunnelConnect {
                token: seal_proto::Bearer::new("seallk_preamble".into()),
                local_key_sha256: [0; 32],
            },
        };
        let served = tokio::spawn(async move { HttpAdapter.serve(Box::new(server_io), meta, ctx).await });
        let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(client_io)).await.unwrap();
        let driver = tokio::spawn(async move {
            let _ = conn.await;
        });
        Client { sender, served, driver }
    }
}

fn default_claims() -> TestClaims {
    claims(Destination::parse(&format!("https://{HOST}/v1")).unwrap(), SECRET.as_bytes())
}

fn claims_with(injection: Injection, rules: HttpRules) -> TestClaims {
    let mut c = default_claims();
    c.policy =
        SecretPolicy::new(&format!("https://{HOST}/v1"), [c.app.clone()]).unwrap().with_http(injection, rules).unwrap();
    c
}

struct Client {
    sender: hyper::client::conn::http1::SendRequest<Full<Bytes>>,
    served: JoinHandle<Result<(), AdapterError>>,
    driver: JoinHandle<()>,
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Reply {
    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap()
    }
    fn seal_error(&self) -> String {
        self.json()["seal_error"].as_str().unwrap().to_string()
    }
}

fn get(target: &str) -> hyper::http::request::Builder {
    Request::builder().uri(target).header("host", "localhost").header("authorization", format!("Bearer {TOKEN}"))
}

impl Client {
    async fn send(&mut self, req: Request<Full<Bytes>>) -> Response<Incoming> {
        self.sender.ready().await.unwrap();
        self.sender.send_request(req).await.unwrap()
    }
    async fn request(&mut self, req: Request<Full<Bytes>>) -> Reply {
        let response = self.send(req).await;
        let (parts, body) = response.into_parts();
        let body = body.collect().await.unwrap().to_bytes().to_vec();
        Reply { status: parts.status, headers: parts.headers, body }
    }
    async fn get(&mut self, target: &str) -> Reply {
        self.request(get(target).body(Full::default()).unwrap()).await
    }
    /// The adapter closed the connection.
    async fn closed(self) -> Result<(), AdapterError> {
        tokio::time::timeout(Duration::from_secs(5), self.driver).await.expect("connection closes").unwrap();
        tokio::time::timeout(Duration::from_secs(5), self.served).await.expect("serve returns").unwrap()
    }
}

fn header<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    h.get(name).map(|v| v.to_str().unwrap())
}

#[tokio::test]
async fn injects_secret_in_place_of_the_credential() {
    let h = Harness::default().await;
    let mut c = h.connect().await;
    let reply = c
        .request(
            get("/v1/chat/completions?stream=true")
                .method("POST")
                .header("accept-encoding", "gzip, br")
                .header("x-trace", "t1")
                .header("connection", "keep-alive, x-hop")
                .header("x-hop", "drop me")
                .body(Full::new(Bytes::from_static(b"{\"model\":\"m\"}")))
                .unwrap(),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.body, b"ok");
    assert_eq!(header(&reply.headers, "x-upstream"), Some("1"));

    let seen = h.seen();
    assert_eq!(seen.len(), 1);
    let up = &seen[0];
    assert_eq!(up.method, "POST");
    assert_eq!(up.target, "/v1/chat/completions?stream=true");
    assert_eq!(header(&up.headers, "authorization"), Some("Bearer sk-test-123"));
    assert_eq!(up.headers.get_all("authorization").iter().count(), 1);
    assert_eq!(header(&up.headers, "host"), Some("api.example.com:443"));
    assert_eq!(header(&up.headers, "accept-encoding"), Some("identity"));
    assert_eq!(header(&up.headers, "x-trace"), Some("t1"));
    assert!(up.headers.get("x-hop").is_none(), "headers named by Connection are hop-by-hop");
    assert!(up.headers.get("connection").is_none());
    assert_eq!(up.body, b"{\"model\":\"m\"}");
    for (_, v) in &up.headers {
        assert!(!v.to_str().unwrap().contains("seallk_"), "the credential never reaches upstream");
    }

    let observed = h.resolver.take_observations();
    assert_eq!(observed.len(), 1);
    assert_eq!(observed[0].protocol, Protocol::Http);
    assert_eq!(observed[0].action, "POST /v1/chat/completions");
    assert_eq!(observed[0].content, b"POST /v1/chat/completions?stream=true");

    let completions = h.resolver.take_completions();
    assert_eq!(completions.len(), 1);
    let done = &completions[0];
    assert_eq!(done.protocol, Protocol::Http);
    assert_eq!(done.action, "POST /v1/chat/completions");
    assert_eq!(done.outcome, Outcome::Allowed);
    assert_eq!(done.bytes_up, 13);
    assert_eq!(done.bytes_down, 2);
}

#[tokio::test]
async fn custom_injection_header_replaces_client_values() {
    let h = Harness::new(claims_with(Injection::new("X-Api-Key", None).unwrap(), HttpRules::default())).await;
    let mut c = h.connect().await;
    let reply = c.request(get("/v1/models").header("x-api-key", "client-value").body(Full::default()).unwrap()).await;
    assert_eq!(reply.status, StatusCode::OK);
    let up = &h.seen()[0];
    assert_eq!(header(&up.headers, "x-api-key"), Some(SECRET));
    assert_eq!(up.headers.get_all("x-api-key").iter().count(), 1);
    assert!(up.headers.get("authorization").is_none(), "the credential's header is removed");
}

#[tokio::test]
async fn credential_in_another_header_is_found_and_removed() {
    let h = Harness::default().await;
    let mut c = h.connect().await;
    let req = Request::builder().uri("/v1/models").header("x-seal", TOKEN).body(Full::default()).unwrap();
    assert_eq!(c.request(req).await.status, StatusCode::OK);
    let up = &h.seen()[0];
    assert!(up.headers.get("x-seal").is_none());
    assert_eq!(header(&up.headers, "authorization"), Some("Bearer sk-test-123"));
}

#[tokio::test]
async fn keep_alive_serves_many_requests_on_one_connection() {
    let h = Harness::default().await;
    let mut c = h.connect().await;
    for _ in 0..3 {
        assert_eq!(c.get("/v1/models").await.status, StatusCode::OK);
    }
    assert_eq!(h.seen().len(), 3);
    assert_eq!(h.resolver.take_completions().len(), 3);
}

#[tokio::test]
async fn missing_credential_is_refused_and_closes() {
    let h = Harness::default().await;
    let mut c = h.connect().await;
    let reply = c.request(Request::builder().uri("/v1/models").body(Full::default()).unwrap()).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(reply.seal_error(), "not_allowed");
    assert!(reply.json()["message"].is_string());
    assert_eq!(header(&reply.headers, "content-type"), Some("application/json"));
    assert!(h.seen().is_empty());
    c.closed().await.unwrap();
}

#[tokio::test]
async fn wrong_credential_is_refused() {
    let h = Harness::default().await;
    let mut c = h.connect().await;
    let req = Request::builder()
        .uri("/v1/models")
        .header("authorization", "Bearer seallk_wrong")
        .body(Full::default())
        .unwrap();
    let reply = c.request(req).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(reply.seal_error(), "not_allowed");
    assert!(h.seen().is_empty());
    c.closed().await.unwrap();
}

#[tokio::test]
async fn two_credentials_are_refused() {
    let h = Harness::default().await;
    let mut c = h.connect().await;
    let reply = c.request(get("/v1/models").header("x-other", "seallk_x").body(Full::default()).unwrap()).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(reply.seal_error(), "bad_request");
    assert!(h.seen().is_empty());
}

#[tokio::test]
async fn another_credential_is_refused_and_closes() {
    let h = Harness::default().await;
    // Even one for the same session: a tunnel's local key never changes.
    h.resolver.insert("seallk_other", default_claims());
    let mut c = h.connect().await;
    assert_eq!(c.get("/v1/models").await.status, StatusCode::OK);
    let req = Request::builder()
        .uri("/v1/models")
        .header("authorization", "Bearer seallk_other")
        .body(Full::default())
        .unwrap();
    let reply = c.request(req).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(reply.seal_error(), "not_allowed");
    assert_eq!(h.seen().len(), 1);
    let completions = h.resolver.take_completions();
    assert_eq!(completions[1].outcome, Outcome::Denied(ErrorCode::NotAllowed));
    c.closed().await.unwrap();
}

#[tokio::test]
async fn later_request_without_credential_is_refused() {
    let h = Harness::default().await;
    let mut c = h.connect().await;
    assert_eq!(c.get("/v1/models").await.status, StatusCode::OK);
    let reply = c.request(Request::builder().uri("/v1/models").body(Full::default()).unwrap()).await;
    assert_eq!(reply.seal_error(), "not_allowed");
    assert_eq!(h.seen().len(), 1);
}

#[tokio::test]
async fn path_method_and_deny_rules() {
    let rules = HttpRules {
        methods: ["GET".to_string(), "POST".to_string()].into_iter().collect::<BTreeSet<_>>(),
        deny_path_prefixes: ["/v1/keys".to_string()].into_iter().collect(),
    };
    let h = Harness::new(claims_with(Injection::default(), rules)).await;
    let mut c = h.connect().await;
    for (method, target) in [
        ("GET", "/v2/models"),
        ("GET", "/v10"),
        ("GET", "/"),
        ("DELETE", "/v1/models"),
        ("POST", "/v1/keys"),
        ("GET", "/v1/keys/1"),
        ("GET", "/v1/%6Beys"),
        ("GET", "/v1/../keys"),
        ("GET", "/v1//keys"),
    ] {
        let reply = c.request(get(target).method(method).body(Full::default()).unwrap()).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{method} {target}");
        assert_eq!(reply.seal_error(), "policy_denied", "{method} {target}");
    }
    // The connection survives policy refusals.
    assert_eq!(c.get("/v1/models?q=%2F").await.status, StatusCode::OK);
    let seen = h.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].target, "/v1/models?q=%2F", "the query is forwarded as sent");
    let completions = h.resolver.take_completions();
    assert_eq!(completions.len(), 10);
    assert_eq!(completions[0].outcome, Outcome::Denied(ErrorCode::PolicyDenied));
    assert_eq!(completions[0].action, "GET /v2/models");
    assert!(h.resolver.take_observations().len() == 1, "only requests that pass policy are observed");
}

#[tokio::test]
async fn path_tricks_against_deny_rules_are_refused() {
    let rules = HttpRules { methods: BTreeSet::new(), deny_path_prefixes: ["/v1/keys".to_string()].into() };
    let h = Harness::new(claims_with(Injection::default(), rules)).await;
    let mut c = h.connect().await;
    for target in ["/v1/KEYS", "/v1/Keys/1", "/v1/keys;x", "/v1/models/..;/keys", "/v1/models;v=1"] {
        let reply = c.get(target).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{target}");
        assert_eq!(reply.seal_error(), "policy_denied", "{target}");
    }
    assert_eq!(c.get("/v1/models").await.status, StatusCode::OK);
    assert_eq!(h.seen().len(), 1);
}

#[tokio::test]
async fn method_and_url_override_headers_are_refused() {
    let rules = HttpRules { methods: ["GET".to_string()].into(), deny_path_prefixes: ["/v1/keys".to_string()].into() };
    let h = Harness::new(claims_with(Injection::default(), rules)).await;
    let mut c = h.connect().await;
    for (name, value) in [
        ("x-http-method-override", "DELETE"),
        ("X-HTTP-Method", "DELETE"),
        ("x-method-override", "DELETE"),
        ("x-original-url", "/v1/keys"),
        ("X-Rewrite-URL", "/v1/keys"),
    ] {
        let reply = c.request(get("/v1/models").header(name, value).body(Full::default()).unwrap()).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{name}");
        assert_eq!(reply.seal_error(), "policy_denied", "{name}");
    }
    assert_eq!(c.get("/v1/models").await.status, StatusCode::OK, "the connection survives");
    assert_eq!(h.seen().len(), 1);
}

#[tokio::test]
async fn method_override_parameters_are_refused() {
    let rules = HttpRules { methods: ["GET".to_string(), "POST".to_string()].into(), deny_path_prefixes: [].into() };
    let h = Harness::new(claims_with(Injection::default(), rules)).await;
    let mut c = h.connect().await;
    for target in [
        "/v1/models?_method=DELETE",
        "/v1/models?a=1&_METHOD=DELETE",
        "/v1/models?%5Fmethod=DELETE",
        "/v1/models?x;.method=PUT",
    ] {
        let reply = c.request(get(target).method("POST").body(Full::default()).unwrap()).await;
        assert_eq!(reply.seal_error(), "policy_denied", "{target}");
    }
    let form = |body: &'static str, content_type: Option<&str>| {
        let mut req = get("/v1/models").method("POST");
        if let Some(t) = content_type {
            req = req.header("content-type", t);
        }
        req.body(Full::new(Bytes::from(body))).unwrap()
    };
    let urlencoded = Some("application/x-www-form-urlencoded; charset=utf-8");
    for (body, content_type) in [
        ("a=1&_method=DELETE", urlencoded),
        ("_Method=DELETE", Some("Application/X-WWW-Form-URLEncoded")),
        ("a=1&%5f%6Dethod=DELETE", urlencoded),
        ("%2Emethod=DELETE", urlencoded),
        ("_method[]=DELETE", urlencoded),
        ("_method=DELETE", None),
        (
            "--b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--b--\r\n",
            Some("multipart/form-data; boundary=b"),
        ),
    ] {
        let reply = c.request(form(body, content_type)).await;
        assert_eq!(reply.seal_error(), "policy_denied", "{body}");
    }
    let reply = c.request(form("amount=1&payment_method=pm_1&method_x=1", urlencoded)).await;
    assert_eq!(reply.status, StatusCode::OK, "the connection survives, other fields pass");
    let reply = c.request(form("{\"_method\":\"x\"}", Some("application/json"))).await;
    assert_eq!(reply.status, StatusCode::OK, "only form bodies are read");
    let seen = h.seen();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].body, b"amount=1&payment_method=pm_1&method_x=1");
    let allowed: Vec<u64> =
        h.resolver.take_completions().iter().filter(|c| c.outcome == Outcome::Allowed).map(|c| c.bytes_up).collect();
    assert_eq!(allowed, [39, 15], "a read form body is counted as sent");

    let reply = c.request(form("_method=DELETE&", urlencoded)).await;
    assert_eq!(reply.seal_error(), "policy_denied");
    let big = Bytes::from(vec![b'a'; (1 << 20) + 1]);
    let reply = c
        .request(
            get("/v1/models")
                .method("POST")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Full::new(big))
                .unwrap(),
        )
        .await;
    assert_eq!(reply.seal_error(), "policy_denied", "too large to check");
    c.closed().await.unwrap();
}

#[tokio::test]
async fn form_bodies_stream_without_method_rules() {
    let h = Harness::default().await;
    let mut c = h.connect().await;
    let req = get("/v1/upload").method("POST").header("content-type", "multipart/form-data; boundary=b");
    let reply = c.request(req.body(Full::new(Bytes::from("--b--\r\n"))).unwrap()).await;
    assert_eq!(reply.status, StatusCode::OK);
    let req = get("/v1/upload").method("POST").header("content-type", "application/x-www-form-urlencoded");
    assert_eq!(c.request(req.body(Full::new(Bytes::from("_method=PUT"))).unwrap()).await.status, StatusCode::OK);
    let reply = c.get("/v1/models?_method=DELETE").await;
    assert_eq!(reply.seal_error(), "policy_denied", "the query parameter is refused under any policy");
}

#[tokio::test]
async fn range_headers_are_dropped() {
    let h = Harness::default().await;
    let mut c = h.connect().await;
    let req = get("/v1/models").header("range", "bytes=0-3").header("if-range", "\"etag\"").body(Full::default());
    assert_eq!(c.request(req.unwrap()).await.status, StatusCode::OK);
    let up = &h.seen()[0];
    assert!(up.headers.get("range").is_none(), "a ranged echo could slice the secret past the scrubber");
    assert!(up.headers.get("if-range").is_none());
}

#[tokio::test]
async fn refused_request_with_body_is_answered() {
    let h = Harness::default().await;
    let mut c = h.connect().await;
    let body = Bytes::from(vec![b'x'; 100_000]);
    let reply = c.request(get("/v2/upload").method("POST").body(Full::new(body.clone())).unwrap()).await;
    assert_eq!(reply.seal_error(), "policy_denied");
    let reply = c.request(get("/v1/upload").method("POST").body(Full::new(body)).unwrap()).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(h.seen()[0].body.len(), 100_000);
    assert_eq!(h.resolver.take_completions()[1].bytes_up, 100_000);
}

#[tokio::test]
async fn absolute_form_is_refused() {
    let h = Harness::default().await;
    let mut c = h.connect().await;
    let reply = c.get(&format!("http://{HOST}/v1/models")).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(reply.seal_error(), "policy_denied");
    let reply = c.get("https://evil.example/v1/models").await;
    assert_eq!(reply.seal_error(), "policy_denied");
    assert!(h.seen().is_empty());
}

#[tokio::test]
async fn connect_is_refused() {
    let h = Harness::default().await;
    let mut c = h.connect().await;
    let reply = c.request(get("evil.example:443").method("CONNECT").body(Full::default()).unwrap()).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(reply.seal_error(), "policy_denied");
    assert!(h.seen().is_empty());
}

#[tokio::test]
async fn upgrade_is_refused() {
    let h = Harness::default().await;
    let mut c = h.connect().await;
    let req = get("/v1/realtime")
        .header("connection", "Upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .header("sec-websocket-version", "13")
        .body(Full::default())
        .unwrap();
    let reply = c.request(req).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(reply.seal_error(), "policy_denied");
    let reply = c.request(get("/v1/x").header("upgrade", "h2c").body(Full::default()).unwrap()).await;
    assert_eq!(reply.seal_error(), "policy_denied");
    assert!(h.seen().is_empty());
}

#[tokio::test]
async fn redirect_is_relayed_not_followed() {
    let h = Harness::default().await;
    let mut c = h.connect().await;
    let reply = c.get("/v1/redirect").await;
    assert_eq!(reply.status, StatusCode::FOUND);
    assert_eq!(header(&reply.headers, "location"), Some("https://evil.example/steal"));
    assert_eq!(h.seen().len(), 1);
}

#[tokio::test]
async fn encoded_response_is_refused() {
    let h = Harness::default().await;
    let mut c = h.connect().await;
    for target in ["/v1/gzip", "/v1/te-gzip"] {
        let reply = c.get(target).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{target}");
        assert_eq!(reply.seal_error(), "policy_denied");
    }
    let completions = h.resolver.take_completions();
    assert_eq!(completions[0].outcome, Outcome::UpstreamError(UpstreamErrorKind::Protocol));
    // The upstream connection is replaced and the client's connection kept.
    assert_eq!(c.get("/v1/models").await.status, StatusCode::OK);
}

#[tokio::test]
async fn echoed_secret_is_masked_in_body_and_headers() {
    let h = Harness::default().await;
    let mut c = h.connect().await;
    let reply = c.get("/v1/leak").await;
    let body = String::from_utf8(reply.body.clone()).unwrap();
    assert!(!body.contains(SECRET), "{body}");
    assert_eq!(body, "{\"error\":\"invalid key ***********\",\"auth\":\"******************\"}");
    assert_eq!(header(&reply.headers, "x-debug"), Some("key=***********"));
}

#[tokio::test]
async fn secret_split_across_chunks_is_masked() {
    let h = Harness::default().await;
    let mut c = h.connect().await;
    let reply = c.get("/v1/leak-split").await;
    assert_eq!(String::from_utf8(reply.body).unwrap(), "error: key *********** is invalid");
    let done = &h.resolver.take_completions()[0];
    assert_eq!(done.bytes_down, 33);
}

#[tokio::test]
async fn sse_streams_and_is_masked() {
    let h = Harness::default().await;
    let mut c = h.connect().await;
    let response = c.send(get("/v1/sse").body(Full::default()).unwrap()).await;
    assert_eq!(header(response.headers(), "content-type"), Some("text/event-stream"));
    let mut body = response.into_body();
    let mut got = Vec::new();
    // The first two events arrive while the upstream is still holding the last one back.
    while String::from_utf8_lossy(&got).matches("\n\n").count() < 2 {
        let frame =
            tokio::time::timeout(Duration::from_secs(5), body.frame()).await.expect("streams").unwrap().unwrap();
        if let Ok(data) = frame.into_data() {
            got.extend_from_slice(&data);
        }
    }
    h.upstream.gate.notify_one();
    while let Some(frame) = body.frame().await {
        if let Ok(data) = frame.unwrap().into_data() {
            got.extend_from_slice(&data);
        }
    }
    let text = String::from_utf8(got).unwrap();
    assert_eq!(text, "data: {\"n\":1}\n\ndata: ******************\n\ndata: [DONE]\n\n");
}

#[tokio::test]
async fn upstream_error_status_is_relayed_and_recorded() {
    let h = Harness::default().await;
    let mut c = h.connect().await;
    let reply = c.get("/v1/fail").await;
    assert_eq!(reply.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(reply.body, b"boom");
    let done = &h.resolver.take_completions()[0];
    assert_eq!(done.outcome, Outcome::UpstreamError(UpstreamErrorKind::HttpStatus(500)));
}

#[tokio::test]
async fn unreachable_upstream_is_unavailable() {
    let connector = TestUpstream::new();
    let resolver = FixedResolver::new();
    resolver.insert(TOKEN, default_claims());
    let h = Harness {
        resolver: resolver.clone(),
        upstream: Upstream { seen: Default::default(), gate: Default::default() },
        ctx: AdapterCtx { resolver, upstream: connector },
    };
    let mut c = h.connect().await;
    let reply = c.get("/v1/models").await;
    assert_eq!(reply.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(reply.seal_error(), "unavailable");
    assert_eq!(h.resolver.take_completions()[0].outcome, Outcome::UpstreamError(UpstreamErrorKind::Connect));
}

#[tokio::test]
async fn verdict_refuse_keeps_the_connection() {
    let h = Harness::default().await;
    let mut c = h.connect().await;
    h.resolver.set_verdict(Verdict::Refuse(ErrorCode::BudgetExceeded));
    let reply = c.get("/v1/models").await;
    assert_eq!(reply.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(reply.seal_error(), "budget_exceeded");
    assert!(h.seen().is_empty());
    h.resolver.set_verdict(Verdict::Forward);
    assert_eq!(c.get("/v1/models").await.status, StatusCode::OK);
    let completions = h.resolver.take_completions();
    assert_eq!(completions[0].outcome, Outcome::Denied(ErrorCode::BudgetExceeded));
    assert_eq!(completions[1].outcome, Outcome::Allowed);
}

#[tokio::test]
async fn verdict_end_refuses_and_closes() {
    let h = Harness::default().await;
    let mut c = h.connect().await;
    h.resolver.set_verdict(Verdict::End(ErrorCode::IntegrityFailed));
    let reply = c.get("/v1/models").await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(reply.seal_error(), "integrity_failed");
    assert!(h.seen().is_empty());
    assert_eq!(h.resolver.take_completions()[0].outcome, Outcome::Denied(ErrorCode::IntegrityFailed));
    c.closed().await.unwrap();
}

#[tokio::test]
async fn session_end_closes_the_connection() {
    let h = Harness::default().await;
    let mut c = h.connect().await;
    assert_eq!(c.get("/v1/models").await.status, StatusCode::OK);
    h.resolver.end_all(ErrorCode::SessionEnded);
    let result = c.closed().await;
    assert!(matches!(result, Err(AdapterError::Denied(ErrorCode::SessionEnded))), "{result:?}");
}

#[tokio::test]
async fn session_end_cuts_a_streaming_response() {
    let h = Harness::default().await;
    let mut c = h.connect().await;
    let response = c.send(get("/v1/hang").body(Full::default()).unwrap()).await;
    let mut body = response.into_body();
    let first = body.frame().await.unwrap().unwrap().into_data().unwrap();
    assert_eq!(&first[..], b"first\n");
    h.resolver.end_all(ErrorCode::SessionEnded);
    let rest = tokio::time::timeout(Duration::from_secs(5), body.collect()).await.expect("the stream is cut");
    assert!(rest.is_err(), "the body ends with an error, not a clean end");
    let result = c.closed().await;
    assert!(matches!(result, Err(AdapterError::Denied(ErrorCode::SessionEnded))), "{result:?}");
    let done = &h.resolver.take_completions()[0];
    assert_eq!(done.bytes_down, 6);
    assert_eq!(done.outcome, Outcome::Aborted);
}
