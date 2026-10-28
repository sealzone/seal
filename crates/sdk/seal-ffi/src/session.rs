//! Sessions: `seal::Session` behind a handle, as `seal-py` holds it.
//!
//! The session's URL, key or DSN and info are kept in a view that reads never wait on. The
//! SDK's tunnel extends the session by itself; an extend called here refreshes the view's info.

use std::ffi::c_char;
use std::sync::{Arc, Mutex};

use seal::{ClientError, ConsumerTier};
use serde::{Deserialize, Serialize};

use crate::client::{live, SealClient};
use crate::{
    block_on, guard, invalid, json_arg, parse, put, put_json, required, runtime, wire_name, SealCancel, SealError,
};

/// `SessionBuilder::http` or `database`.
#[derive(Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Kind {
    Http,
    Database,
}

/// The `options_json` of `seal_client_session`.
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Options {
    kind: Option<Kind>,
    /// `"base"` or `"hardened"`.
    min_tier: Option<String>,
    /// Report through the seal host agent (App Integrity add-on) instead of the executable's
    /// hash: `{}` from the environment (`SEAL_AGENT_SOCKET`, `SEAL_APP_KEY`), or
    /// `{"socket", "app_key"}`.
    host_agent: Option<HostAgent>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HostAgent {
    socket: Option<String>,
    app_key: Option<String>,
}

impl HostAgent {
    fn reporter(self) -> Result<seal::integrity::HostAgentReporter, ClientError> {
        match (self.socket, self.app_key) {
            (None, None) => Ok(seal::integrity::HostAgentReporter::new()),
            (Some(socket), Some(key)) => {
                let key = zeroize::Zeroizing::new(key);
                let key_id = seal::identity::AppKeyIdentity::parse(&key)?.key_id();
                Ok(seal::integrity::HostAgentReporter::with_socket_and_key(socket, key_id))
            }
            _ => Err(ClientError::Invalid("host_agent takes both socket and app_key, or neither".into())),
        }
    }
}

impl Options {
    async fn start(self, client: &seal::Client, blob: &str) -> Result<seal::Session, ClientError> {
        let mut builder = client.session(blob);
        if let Some(agent) = self.host_agent {
            builder = builder.endpoint_reporter(Arc::new(agent.reporter()?));
        }
        if let Some(tier) = &self.min_tier {
            builder = builder.min_tier(parse::<ConsumerTier>(tier)?);
        }
        match self.kind {
            Some(Kind::Http) => builder.http().await.map(seal::Session::Http),
            Some(Kind::Database) => builder.database().await.map(seal::Session::Database),
            None => builder.await,
        }
    }
}

/// What `seal_session_view` returns, refreshed after every extend made here. The credential
/// (the HTTP key or the DSN) is not part of it: `seal_session_credential` returns it alone,
/// and it is wiped when the view is replaced.
#[derive(Serialize)]
struct View {
    kind: Kind,
    url: Option<String>,
    #[serde(skip)]
    credential: seal_proto::Bearer,
    /// `postgres`, `redis` or `click_house`.
    protocol: Option<String>,
    info: Info,
}

#[derive(Serialize)]
struct Info {
    /// base64url, as telemetry shows it.
    session_id: String,
    platform: String,
    tier: String,
    tenant: String,
    app: String,
    blob_id: String,
    /// Unix seconds.
    expires_at: u64,
}

impl View {
    fn of(session: &seal::Session) -> Self {
        let (kind, url, credential, protocol) = match session {
            seal::Session::Http(s) => (Kind::Http, Some(s.url().to_owned()), s.key(), None),
            seal::Session::Database(s) => (Kind::Database, None, s.dsn(), Some(wire_name(&s.protocol()))),
        };
        let credential = seal_proto::Bearer::new(credential.to_owned());
        let i = session.info();
        let info = Info {
            session_id: seal_proto::codec::b64url(&i.session_id),
            platform: wire_name(&i.platform),
            tier: wire_name(&i.tier),
            tenant: i.tenant.to_string(),
            app: i.app.to_string(),
            blob_id: i.blob_id.to_string(),
            expires_at: i.expires_at,
        };
        Self { kind, url, credential, protocol, info }
    }
}

/// What the handle and the futures it starts share.
struct Shared {
    session: tokio::sync::Mutex<Option<seal::Session>>,
    view: Mutex<View>,
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
    /// runtime it finds; this is the one.
    fn drop(&mut self) {
        let session = self.session.get_mut().take();
        let _runtime = runtime().enter();
        drop(session);
    }
}

/// `seal_session`: a session on a blob.
pub struct SealSession {
    shared: Arc<Shared>,
}

impl SealSession {
    fn new(session: seal::Session) -> Self {
        let view = View::of(&session);
        let shared = Arc::new(Shared { session: tokio::sync::Mutex::new(Some(session)), view: Mutex::new(view) });
        Self { shared }
    }
}

/// The session behind a handle.
///
/// # Safety
/// `session` NULL or live.
unsafe fn session<'a>(session: *const SealSession) -> Result<&'a SealSession, crate::Failure> {
    // SAFETY: the caller promises NULL or a live session.
    unsafe { session.as_ref() }.ok_or_else(|| invalid("session is NULL"))
}

/// Starts a session on `blob`, in `*out`. `options_json` (NULL for the defaults):
/// `{"kind": "http" | "database", "min_tier": "base" | "hardened", "host_agent": {...}}`.
/// `kind` fails with `"bad_request"` before anything is sent when the blob is of the other
/// kind. The SDK runs a local tunnel to the enclave and extends the session before every expiry.
///
/// # Safety
/// `client` live; strings NUL-terminated; `cancel` NULL or live; `out` writable.
#[no_mangle]
pub unsafe extern "C" fn seal_client_session(
    client: *const SealClient,
    blob: *const c_char,
    options_json: *const c_char,
    cancel: *const SealCancel,
    out: *mut *mut SealSession,
) -> *mut SealError {
    guard(|| {
        // SAFETY: the caller's promises, per argument.
        let (client, blob, options, cancel) = unsafe {
            (live(client)?, required(blob, "blob")?, json_arg::<Options>(options_json, "options")?, cancel.as_ref())
        };
        if out.is_null() {
            return Err(invalid("an out-parameter is NULL"));
        }
        let started = block_on(cancel, options.start(client, blob))?;
        // SAFETY: the caller promises `out` is writable.
        unsafe { put(out, || Box::into_raw(Box::new(SealSession::new(started)))) }
    })
}

/// The session as JSON, in `*out`: `{"kind": "http" | "database", "url", "protocol", "info":
/// {"session_id", "platform", "tier", "tenant", "app", "blob_id", "expires_at"}}`. Fields of
/// the other kind are null. Never waits on the network. The key or DSN is not in it: see
/// `seal_session_credential`.
///
/// # Safety
/// `session` live; `out` writable.
#[no_mangle]
pub unsafe extern "C" fn seal_session_view(session: *const SealSession, out: *mut *mut c_char) -> *mut SealError {
    guard(|| {
        // SAFETY: the caller promises a live session.
        let session = unsafe { self::session(session) }?;
        let text = session.shared.view(serde_json::to_string).map_err(|e| invalid(format!("encoding JSON: {e}")))?;
        // SAFETY: the caller promises `out` is writable.
        unsafe { put(out, || crate::c_string(text)) }
    })
}

/// The session's credential in `*out`: the key to send (HTTP) or the DSN (database), both for
/// the local tunnel; it never changes for the life of the session. Free it with
/// `seal_string_free`, which wipes it.
///
/// # Safety
/// `session` live; `out` writable.
#[no_mangle]
pub unsafe extern "C" fn seal_session_credential(session: *const SealSession, out: *mut *mut c_char) -> *mut SealError {
    guard(|| {
        // SAFETY: the caller promises a live session.
        let session = unsafe { self::session(session) }?;
        if out.is_null() {
            return Err(invalid("an out-parameter is NULL"));
        }
        let text = session.shared.view(|v| v.credential.expose().to_owned());
        // SAFETY: the caller promises `out` is writable.
        unsafe { put(out, || crate::c_string(text)) }
    })
}

/// Where telemetry recorded the start and every restart, oldest first, as a JSON array of
/// `{"stream": "<base64url>", "entry": n}`, in `*out`.
///
/// # Safety
/// `session` live; `out` writable.
#[no_mangle]
pub unsafe extern "C" fn seal_session_receipts(session: *const SealSession, out: *mut *mut c_char) -> *mut SealError {
    guard(|| {
        // SAFETY: the caller promises a live session.
        let shared = unsafe { self::session(session) }?.shared.clone();
        let receipts = block_on(None, async move { Ok(shared.receipts().await) })?;
        // SAFETY: the caller promises `out` is writable.
        unsafe { put_json(out, &receipts) }
    })
}

/// Extends the session now with a fresh identity proof and moves the view's `expires_at`. The
/// tunnel also extends by itself before every expiry.
///
/// # Safety
/// `session` live; `cancel` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn seal_session_extend(session: *const SealSession, cancel: *const SealCancel) -> *mut SealError {
    guard(|| {
        // SAFETY: the caller's promises, per argument.
        let (session, cancel) = unsafe { (self::session(session)?, cancel.as_ref()) };
        block_on(cancel, session.shared.extend())
    })
}

/// Ends the session on the server; the first call also stops extending and closes the
/// tunnel. An error means the end may not have reached every replica: call it again.
///
/// # Safety
/// `session` live; `cancel` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn seal_session_close(session: *const SealSession, cancel: *const SealCancel) -> *mut SealError {
    guard(|| {
        // SAFETY: the caller's promises, per argument.
        let (session, cancel) = unsafe { (self::session(session)?, cancel.as_ref()) };
        block_on(cancel, session.shared.close())
    })
}

/// Frees a session. One not closed successfully is ended in the background. NULL does nothing.
///
/// # Safety
/// `session` NULL or from `seal_client_session`, freed once, with no call still using it.
#[no_mangle]
pub unsafe extern "C" fn seal_session_free(session: *mut SealSession) {
    if !session.is_null() {
        // SAFETY: from Box::into_raw in seal_client_session, freed once (the caller's promise).
        drop(unsafe { Box::from_raw(session) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{take, text};

    #[test]
    fn options_default_and_refuse_unknown_fields() {
        let options: Options = serde_json::from_str("{}").unwrap();
        assert!(options.kind.is_none() && options.min_tier.is_none() && options.host_agent.is_none());
        let options: Options = serde_json::from_str(r#"{"kind": "database"}"#).unwrap();
        assert!(options.kind == Some(Kind::Database));
        assert!(serde_json::from_str::<Options>(r#"{"timeout": 5}"#).is_err());
        assert!(serde_json::from_str::<Options>(r#"{"kind": "grpc"}"#).is_err());
    }

    #[test]
    fn the_host_agent_takes_both_settings_or_neither() {
        let agent = |json: &str| serde_json::from_str::<Options>(json).unwrap().host_agent.unwrap().reporter();
        assert!(agent(r#"{"host_agent": {}}"#).is_ok());
        assert!(matches!(agent(r#"{"host_agent": {"socket": "/s"}}"#), Err(ClientError::Invalid(_))));
        assert!(matches!(
            agent(r#"{"host_agent": {"socket": "/s", "app_key": "nope"}}"#),
            Err(ClientError::Invalid(_))
        ));
        assert!(serde_json::from_str::<Options>(r#"{"host_agent": {"port": 1}}"#).is_err());
    }

    #[test]
    fn null_sessions_are_bad_requests() {
        let mut out = std::ptr::null_mut();
        let blob = text("seal1.x");
        // SAFETY: NULL handles are checked.
        unsafe {
            assert_eq!(take(seal_session_view(std::ptr::null(), &mut out)).unwrap().0, "bad_request");
            assert_eq!(take(seal_session_extend(std::ptr::null(), std::ptr::null())).unwrap().0, "bad_request");
            assert_eq!(take(seal_session_close(std::ptr::null(), std::ptr::null())).unwrap().0, "bad_request");
            let mut session = std::ptr::null_mut();
            let error =
                seal_client_session(std::ptr::null(), blob.as_ptr(), std::ptr::null(), std::ptr::null(), &mut session);
            assert_eq!(take(error).unwrap().0, "bad_request");
            seal_session_free(std::ptr::null_mut());
        }
    }
}
