//! Sessions: `seal::Session` behind a JavaScript object, and the app callbacks a session runs.
//!
//! The session's URL, key or DSN and info are kept in a view that reads never wait on, so
//! property access is synchronous. The SDK's tunnel extends the session by itself; an
//! `extend` called here refreshes the view's info.

use std::sync::{Arc, Mutex};

use napi::bindgen_prelude::{Promise, PromiseRaw, ToNapiValue};
use napi::threadsafe_function::ThreadsafeFunction;
use napi::{Env, Error, Status};
use napi_derive::napi;
use seal::{ClientError, ConsumerTier, ErrorCode};
use seal_proto::integrity::{ArtifactHash, EndpointEvidence, EndpointReport};
use seal_proto::Bearer;
use serde::de::DeserializeOwned;
use serde::Deserialize;

use crate::types::{SessionInfo, TelemetryReceipt};
use crate::{parse, wire_name};

/// `SessionBuilder::http` or `database`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Http,
    Database,
}

/// A JavaScript callback as `index.js` wraps it: called with `A`, it resolves to the JSON
/// `reply` reads and never throws. Weak: a session's callbacks never keep Node running.
pub(crate) type Callback<A> = ThreadsafeFunction<A, Promise<String>, A, Status, false, true>;

/// The session options a JavaScript call passed.
pub(crate) struct Options {
    pub(crate) kind: Option<Kind>,
    pub(crate) min_tier: Option<ConsumerTier>,
    pub(crate) reload_with: Option<Arc<Callback<()>>>,
    pub(crate) on_reseal: Option<Arc<Callback<String>>>,
    pub(crate) endpoint_reporter: Option<Reporter>,
}

/// What reports a session's endpoint: a JavaScript function, or one of the SDK's own
/// reporters (`HostAgentReporter`), which never crosses into JavaScript.
pub(crate) enum Reporter {
    Js(Arc<Callback<String>>),
    Native(Arc<dyn seal::integrity::EndpointReporter>),
}

impl Options {
    pub(crate) fn new(kind: Option<&str>, min_tier: Option<&str>) -> Result<Self, ClientError> {
        let kind = match kind {
            None => None,
            Some("http") => Some(Kind::Http),
            Some("database") => Some(Kind::Database),
            Some(other) => {
                return Err(ClientError::Invalid(format!("kind must be \"http\" or \"database\", not {other:?}")))
            }
        };
        let min_tier = min_tier.map(parse).transpose()?;
        Ok(Self { kind, min_tier, reload_with: None, on_reseal: None, endpoint_reporter: None })
    }

    pub(crate) async fn start(self, client: seal::Client, blob: String) -> Result<Session, ClientError> {
        let mut builder = client.session(&blob);
        if let Some(tier) = self.min_tier {
            builder = builder.min_tier(tier);
        }
        if let Some(reload) = self.reload_with {
            builder = builder.reload_with(move || {
                let reload = reload.clone();
                async move {
                    call(&reload, "reloadWith", ())
                        .await?
                        .ok_or_else(|| ClientError::Invalid("reloadWith returned no blob".into()))
                }
            });
        }
        if let Some(on_reseal) = self.on_reseal {
            builder = builder.on_reseal(move |blob| {
                let on_reseal = on_reseal.clone();
                async move {
                    // Nothing to return the error to: `index.js` reports it as a warning.
                    let _ = call::<(), _>(&on_reseal, "onReseal", blob).await;
                }
            });
        }
        match self.endpoint_reporter {
            Some(Reporter::Js(callback)) => builder = builder.endpoint_reporter(Arc::new(JsReporter(callback))),
            Some(Reporter::Native(reporter)) => builder = builder.endpoint_reporter(reporter),
            None => {}
        }
        let session = match self.kind {
            Some(Kind::Http) => builder.http().await.map(seal::Session::Http)?,
            Some(Kind::Database) => builder.database().await.map(seal::Session::Database)?,
            None => builder.await?,
        };
        Ok(Session::new(session))
    }
}

/// What a wrapped callback resolves to: `{"value": …}`, or `{"error": {"code", "message"}}`
/// when the app's function threw (`code` is a `SealError`'s, else null).
#[derive(Deserialize)]
struct Reply<T> {
    #[serde(default = "Option::default")]
    value: Option<T>,
    error: Option<ReplyError>,
}

#[derive(Deserialize)]
struct ReplyError {
    code: Option<String>,
    message: String,
}

/// A callback's reply as an SDK result: an error keeps a `SealError`'s code and is
/// `BadRequest` otherwise, as seal-py does.
fn reply<T: DeserializeOwned>(what: &str, text: &str) -> Result<Option<T>, ClientError> {
    let reply: Reply<T> =
        serde_json::from_str(text).map_err(|e| ClientError::Invalid(format!("{what} returned a bad value: {e}")))?;
    match reply.error {
        None => Ok(reply.value),
        Some(ReplyError { code, message }) => match code.as_deref().map(parse::<ErrorCode>) {
            Some(Ok(code)) => Err(ClientError::Seal { code, message: format!("{what}: {message}") }),
            _ => Err(ClientError::Invalid(format!("{what}: {message}"))),
        },
    }
}

/// Calls a wrapped callback on the JavaScript thread and waits for its reply.
async fn call<T: DeserializeOwned, A: 'static + ToNapiValue>(
    callback: &Callback<A>,
    what: &str,
    arg: A,
) -> Result<Option<T>, ClientError> {
    let failed = |e: Error| ClientError::Invalid(format!("{what}: {}", e.reason));
    let promise = callback.call_async_catch(arg).await.map_err(failed)?;
    let text = promise.await.map_err(failed)?;
    reply(what, &text)
}

/// An `endpointReporter` as `index.js` encodes its answer: hex for the bytes.
#[derive(Deserialize)]
struct Report {
    artifact: Option<Artifact>,
    #[serde(default)]
    evidence: Vec<Evidence>,
}

#[derive(Deserialize)]
struct Artifact {
    name: String,
    sha256: String,
}

#[derive(Deserialize)]
struct Evidence {
    provider: String,
    bytes: String,
}

impl Report {
    fn report(self) -> Result<EndpointReport, ClientError> {
        let bad = |what: &str| ClientError::Invalid(format!("endpointReporter: {what}"));
        let artifact = match self.artifact {
            Some(a) => {
                let sha256 = hex::decode(&a.sha256).ok().and_then(|h| <[u8; 32]>::try_from(h).ok());
                Some(ArtifactHash {
                    name: a.name,
                    sha256: sha256.ok_or_else(|| bad("artifact sha256 must be 32 bytes"))?,
                })
            }
            None => None,
        };
        let evidence = self
            .evidence
            .into_iter()
            .map(|e| {
                Ok(EndpointEvidence { provider: e.provider, bytes: hex::decode(&e.bytes).map_err(|_| bad("bytes"))? })
            })
            .collect::<Result<_, ClientError>>()?;
        Ok(EndpointReport { artifact, evidence })
    }
}

/// An `endpointReporter` function returning an `EndpointReport` (or a Promise of one). It is
/// called with the request's 32-byte challenge (hex here; `index.js` hands it over as a
/// Buffer), which signed evidence must cover so it cannot be replayed.
struct JsReporter(Arc<Callback<String>>);

#[async_trait::async_trait]
impl seal::integrity::EndpointReporter for JsReporter {
    async fn report(&self, challenge: [u8; 32]) -> Result<EndpointReport, ClientError> {
        call::<Report, _>(&self.0, "endpointReporter", hex::encode(challenge))
            .await?
            .ok_or_else(|| ClientError::Invalid("endpointReporter returned no report".into()))?
            .report()
    }
}

/// What reads of a session see, refreshed after every extend made here.
struct View {
    kind: Kind,
    url: Option<String>,
    /// The key (HTTP) or the DSN (database).
    credential: Bearer,
    protocol: Option<seal::Protocol>,
    info: seal::SessionInfo,
}

impl View {
    fn of(session: &seal::Session) -> Self {
        let (kind, url, credential, protocol) = match session {
            seal::Session::Http(s) => (Kind::Http, Some(s.url().to_owned()), Bearer::new(s.key().to_owned()), None),
            seal::Session::Database(s) => (Kind::Database, None, Bearer::new(s.dsn().to_owned()), Some(s.protocol())),
        };
        Self { kind, url, credential, protocol, info: session.info().clone() }
    }
}

/// What the JavaScript object and the futures it starts share.
struct Shared {
    session: tokio::sync::Mutex<Option<seal::Session>>,
    view: Mutex<View>,
    /// The runtime the session started on, where a drop ends it.
    runtime: tokio::runtime::Handle,
}

impl Shared {
    fn view<T>(&self, read: impl FnOnce(&View) -> T) -> T {
        read(&self.view.lock().unwrap_or_else(|e| e.into_inner()))
    }

    async fn extend(&self) -> Result<(), ClientError> {
        let mut session = self.session.lock().await;
        let Some(session) = session.as_mut() else {
            return Ok(());
        };
        session.extend().await?;
        *self.view.lock().unwrap_or_else(|e| e.into_inner()) = View::of(session);
        Ok(())
    }

    async fn close(&self) -> Result<(), ClientError> {
        match self.session.lock().await.as_ref() {
            Some(session) => session.close().await,
            None => Ok(()),
        }
    }

    async fn receipts(&self) -> Vec<seal::TelemetryReceipt> {
        self.session.lock().await.as_ref().map(|s| s.receipts()).unwrap_or_default()
    }
}

impl Drop for Shared {
    /// The SDK ends a session dropped without a successful close in the background, on the
    /// runtime it finds; this is the one. A garbage-collected session lands here on the
    /// JavaScript thread, outside any runtime.
    fn drop(&mut self) {
        let session = self.session.get_mut().take();
        let _runtime = self.runtime.enter();
        drop(session);
    }
}

/// A session on a blob (`HttpSession` or `DatabaseSession` in `index.js` wrap it).
#[napi]
pub struct Session {
    shared: Arc<Shared>,
}

impl Session {
    /// Made on the runtime: a drop ends the session there.
    fn new(session: seal::Session) -> Self {
        let view = View::of(&session);
        let shared = Arc::new(Shared {
            session: tokio::sync::Mutex::new(Some(session)),
            view: Mutex::new(view),
            runtime: tokio::runtime::Handle::current(),
        });
        Self { shared }
    }
}

#[napi]
impl Session {
    /// `"http"` or `"database"`.
    #[napi(getter)]
    pub fn kind(&self) -> &'static str {
        match self.shared.view(|v| v.kind) {
            Kind::Http => "http",
            Kind::Database => "database",
        }
    }
    /// HTTP sessions: the local tunnel.
    #[napi(getter)]
    pub fn url(&self) -> Option<String> {
        self.shared.view(|v| v.url.clone())
    }
    /// HTTP sessions: the stand-in key, worthless outside this tunnel.
    #[napi(getter)]
    pub fn key(&self) -> Option<String> {
        self.shared.view(|v| (v.kind == Kind::Http).then(|| v.credential.expose().to_owned()))
    }
    /// Database sessions: a complete connection string.
    #[napi(getter)]
    pub fn dsn(&self) -> Option<String> {
        self.shared.view(|v| (v.kind == Kind::Database).then(|| v.credential.expose().to_owned()))
    }
    /// Database sessions: `postgres`, `redis` or `click_house`.
    #[napi(getter)]
    pub fn protocol(&self) -> Option<String> {
        self.shared.view(|v| v.protocol.as_ref().map(wire_name))
    }
    #[napi(getter)]
    pub fn info(&self) -> SessionInfo {
        self.shared.view(|v| SessionInfo::from(&v.info))
    }

    /// Where telemetry recorded the start and every restart, oldest first.
    #[napi(ts_return_type = "Promise<TelemetryReceipt[]>")]
    pub fn receipts<'env>(&self, env: &'env Env) -> napi::Result<PromiseRaw<'env, Vec<TelemetryReceipt>>> {
        let shared = self.shared.clone();
        env.spawn_future(async move { Ok(shared.receipts().await.into_iter().map(TelemetryReceipt::from).collect()) })
    }

    #[napi(ts_return_type = "Promise<void>")]
    pub fn extend<'env>(&self, env: &'env Env) -> napi::Result<PromiseRaw<'env, ()>> {
        let shared = self.shared.clone();
        env.spawn_future(async move { shared.extend().await.map_err(crate::error) })
    }

    /// Ends the session on the server; the first call also stops extending and closes the
    /// tunnel. An error means the end may not have reached every replica: call it again.
    #[napi(ts_return_type = "Promise<void>")]
    pub fn close<'env>(&self, env: &'env Env) -> napi::Result<PromiseRaw<'env, ()>> {
        let shared = self.shared.clone();
        env.spawn_future(async move { shared.close().await.map_err(crate::error) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callback_replies() {
        assert_eq!(reply::<String>("reloadWith", r#"{"value":"seal1.x"}"#).unwrap().as_deref(), Some("seal1.x"));
        assert_eq!(reply::<()>("onReseal", r#"{"value":null}"#).unwrap(), None);
        let e = reply::<String>("reloadWith", r#"{"error":{"code":"expired","message":"gone"}}"#).unwrap_err();
        assert!(
            matches!(e, ClientError::Seal { code: ErrorCode::Expired, ref message } if message == "reloadWith: gone")
        );
        let e = reply::<String>("reloadWith", r#"{"error":{"code":null,"message":"boom"}}"#).unwrap_err();
        assert!(matches!(e, ClientError::Invalid(ref m) if m == "reloadWith: boom"));
        assert!(matches!(reply::<String>("reloadWith", "nope"), Err(ClientError::Invalid(_))));
    }

    #[test]
    fn reports_decode() {
        let report: Report = serde_json::from_str(&format!(
            r#"{{"artifact":{{"name":"app","sha256":"{}"}},"evidence":[{{"provider":"edr","bytes":"0102"}}]}}"#,
            "ab".repeat(32)
        ))
        .unwrap();
        let report = report.report().unwrap();
        assert_eq!(report.artifact.unwrap().sha256, [0xab; 32]);
        assert_eq!(report.evidence[0].bytes, [1, 2]);
        let short: Report = serde_json::from_str(r#"{"artifact":{"name":"app","sha256":"ab"}}"#).unwrap();
        assert!(short.report().is_err());
    }
}
