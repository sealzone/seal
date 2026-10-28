//! Sessions: `seal::Session` behind a Python object, and the app callbacks a session runs.
//!
//! The session's URL, key or DSN and info are kept in a view that reads never wait on, so
//! attribute access never blocks on the network. The SDK's tunnel extends the session by
//! itself; an `extend` called here refreshes the view's info.

use std::sync::{Arc, Mutex};

use pyo3::prelude::*;
use seal::{ClientError, ConsumerTier};
use seal_proto::Bearer;

use crate::types::{EndpointReport, SessionInfo, TelemetryReceipt};
use crate::{awaitable, from_python, runtime, wait, wire_name};

/// `SessionBuilder::http` or `database`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Http,
    Database,
}

/// A Python callable, shared with the SDK's callbacks.
type Callback = Arc<Py<PyAny>>;

/// The session options a Python call passed.
pub(crate) struct Options {
    pub(crate) kind: Option<Kind>,
    pub(crate) min_tier: Option<ConsumerTier>,
    pub(crate) reload_with: Option<Callback>,
    pub(crate) on_reseal: Option<Callback>,
    pub(crate) endpoint_reporter: Option<Reporter>,
}

/// What reports a session's endpoint: a Python callable, or one of the SDK's own reporters
/// (`seal.HostAgentReporter`), which never crosses into Python.
pub(crate) enum Reporter {
    Python(Callback),
    Native(Arc<dyn seal::integrity::EndpointReporter>),
}

impl Options {
    pub(crate) async fn start(self, client: seal::Client, blob: String) -> Result<seal::Session, ClientError> {
        let mut builder = client.session(&blob);
        if let Some(tier) = self.min_tier {
            builder = builder.min_tier(tier);
        }
        if let Some(reload) = self.reload_with {
            builder = builder.reload_with(move || {
                call(reload.clone(), "reload_with", Arg::None, false, |_, blob| blob.extract::<String>())
            });
        }
        if let Some(on_reseal) = self.on_reseal {
            builder = builder.on_reseal(move |blob| {
                let on_reseal = on_reseal.clone();
                async move {
                    // Nothing to return the error to: Python's hook reports it.
                    let _ = call(on_reseal, "on_reseal", Arg::Text(blob), true, |_, _| Ok(())).await;
                }
            });
        }
        match self.endpoint_reporter {
            Some(Reporter::Python(callable)) => builder = builder.endpoint_reporter(Arc::new(PyReporter(callable))),
            Some(Reporter::Native(reporter)) => builder = builder.endpoint_reporter(reporter),
            None => {}
        }
        match self.kind {
            Some(Kind::Http) => builder.http().await.map(seal::Session::Http),
            Some(Kind::Database) => builder.database().await.map(seal::Session::Database),
            None => builder.await,
        }
    }
}

/// What a callback is called with.
enum Arg {
    None,
    Text(String),
    Bytes(Vec<u8>),
}

/// Calls `callback` (with `arg`, if any) on a blocking thread holding the GIL. An exception is
/// returned as an SDK error, and with `unraisable` also reported through
/// `sys.unraisablehook` (for callbacks whose errors reach no caller).
async fn call<T: Send + 'static>(
    callback: Callback,
    what: &'static str,
    arg: Arg,
    unraisable: bool,
    extract: fn(Python<'_>, Bound<'_, PyAny>) -> PyResult<T>,
) -> Result<T, ClientError> {
    let called = tokio::task::spawn_blocking(move || {
        Python::attach(|py| {
            let callback = callback.bind(py);
            let result = match arg {
                Arg::None => callback.call0(),
                Arg::Text(text) => callback.call1((text,)),
                Arg::Bytes(bytes) => callback.call1((pyo3::types::PyBytes::new(py, &bytes),)),
            };
            result.and_then(|value| extract(py, value)).map_err(|e| {
                let error = from_python(py, what, e.clone_ref(py));
                if unraisable {
                    e.write_unraisable(py, Some(callback));
                }
                error
            })
        })
    });
    called.await.map_err(|e| ClientError::Invalid(format!("{what}: {e}")))?
}

/// An `endpoint_reporter` callable returning a `seal.EndpointReport`. It is called with the
/// request's 32-byte challenge, which signed evidence must cover so it cannot be replayed.
struct PyReporter(Callback);

#[async_trait::async_trait]
impl seal::integrity::EndpointReporter for PyReporter {
    async fn report(&self, challenge: [u8; 32]) -> Result<seal_proto::integrity::EndpointReport, ClientError> {
        call(self.0.clone(), "endpoint_reporter", Arg::Bytes(challenge.to_vec()), false, |_, report| {
            Ok(report.cast::<EndpointReport>()?.get().report())
        })
        .await
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

/// What the Python object and the futures it starts share.
struct Shared {
    session: tokio::sync::Mutex<Option<seal::Session>>,
    view: Mutex<View>,
    /// The process that started the session.
    pid: u32,
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
    /// runtime it finds; this is the one. A forked child's copy is forgotten instead: the
    /// session is its parent's.
    fn drop(&mut self) {
        let session = self.session.get_mut().take();
        if self.pid != std::process::id() {
            std::mem::forget(session);
            return;
        }
        let _runtime = runtime().enter();
        drop(session);
    }
}

/// A session on a blob (`seal.HttpSession` or `seal.DatabaseSession` wrap it).
#[pyclass(frozen, module = "seal._seal")]
pub struct Session {
    shared: Arc<Shared>,
}

impl Session {
    pub(crate) fn new(session: seal::Session) -> Self {
        let view = View::of(&session);
        let shared = Arc::new(Shared {
            session: tokio::sync::Mutex::new(Some(session)),
            view: Mutex::new(view),
            pid: std::process::id(),
        });
        Self { shared }
    }

    /// The shared state, refused in a process forked after the session started.
    fn live(&self) -> PyResult<&Arc<Shared>> {
        crate::same_process(self.shared.pid, "session")?;
        Ok(&self.shared)
    }
}

#[pymethods]
impl Session {
    /// `"http"` or `"database"`.
    #[getter]
    fn kind(&self) -> PyResult<&'static str> {
        Ok(match self.live()?.view(|v| v.kind) {
            Kind::Http => "http",
            Kind::Database => "database",
        })
    }
    /// HTTP sessions: the local tunnel.
    #[getter]
    fn url(&self) -> PyResult<Option<String>> {
        Ok(self.live()?.view(|v| v.url.clone()))
    }
    /// HTTP sessions: the stand-in key, worthless outside this tunnel.
    #[getter]
    fn key(&self) -> PyResult<Option<String>> {
        Ok(self.live()?.view(|v| (v.kind == Kind::Http).then(|| v.credential.expose().to_owned())))
    }
    /// Database sessions: a complete connection string.
    #[getter]
    fn dsn(&self) -> PyResult<Option<String>> {
        Ok(self.live()?.view(|v| (v.kind == Kind::Database).then(|| v.credential.expose().to_owned())))
    }
    /// Database sessions: `postgres`, `redis` or `click_house`.
    #[getter]
    fn protocol(&self) -> PyResult<Option<String>> {
        Ok(self.live()?.view(|v| v.protocol.as_ref().map(wire_name)))
    }
    #[getter]
    fn info(&self) -> PyResult<SessionInfo> {
        Ok(self.live()?.view(|v| SessionInfo::from(&v.info)))
    }

    /// Where telemetry recorded the start and every restart, oldest first.
    fn receipts(&self, py: Python<'_>) -> PyResult<Vec<TelemetryReceipt>> {
        let shared = self.live()?.clone();
        let receipts = wait(py, async move { Ok(shared.receipts().await) })?;
        Ok(receipts.into_iter().map(TelemetryReceipt::from).collect())
    }

    fn extend(&self, py: Python<'_>) -> PyResult<()> {
        let shared = self.live()?.clone();
        wait(py, async move { shared.extend().await })
    }

    fn extend_async<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let shared = self.live()?.clone();
        awaitable(py, async move { shared.extend().await }, |py, ()| Ok(py.None()))
    }

    /// Ends the session on the server; the first call also stops extending and closes the
    /// tunnel. An error means the end may not have reached every replica: call it again.
    fn close(&self, py: Python<'_>) -> PyResult<()> {
        let shared = self.live()?.clone();
        wait(py, async move { shared.close().await })
    }

    fn close_async<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let shared = self.live()?.clone();
        awaitable(py, async move { shared.close().await }, |py, ()| Ok(py.None()))
    }
}
