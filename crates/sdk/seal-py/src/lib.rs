//! pyo3 bindings over the Rust SDK (`seal::Client`), as the native module `seal._seal`. The
//! Python surface (`seal.Client`, `seal.AsyncClient`, `seal.seal`, `seal.session`, the
//! exceptions) is in `python/seal/` and calls into this module.
//!
//! One background tokio runtime runs every SDK future. Blocking calls wait for theirs with the
//! GIL released, checking for signals (Ctrl-C) while they wait; `*_async` calls return an
//! asyncio future resolved from the runtime. Errors become the exceptions of
//! `seal._errors`, one per `ErrorCode`.

extern crate seal_client as seal;

use std::future::Future;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use seal::{ClientError, ErrorCode};
use serde::de::DeserializeOwned;
use serde::Serialize;

mod client;
mod session;
mod types;

/// One process's runtime.
struct Slot {
    pid: u32,
    runtime: tokio::runtime::Runtime,
}

/// The runtime every SDK future and tunnel runs on, started on first use in each process. A
/// forked child (a prefork server's worker) has none of its parent's runtime threads, so it
/// starts its own; the parent's is leaked there, never dropped. Lock-free, so a fork can never
/// copy it mid-update into a state the child waits on.
pub(crate) fn runtime() -> &'static tokio::runtime::Runtime {
    static SLOT: AtomicPtr<Slot> = AtomicPtr::new(std::ptr::null_mut());
    let pid = std::process::id();
    loop {
        let current = SLOT.load(Ordering::Acquire);
        // SAFETY: slots are leaked once published, never freed.
        if let Some(slot) = unsafe { current.as_ref() } {
            if slot.pid == pid {
                return &slot.runtime;
            }
        }
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("seal")
            .build()
            .expect("starting the seal runtime");
        let fresh = Box::into_raw(Box::new(Slot { pid, runtime }));
        match SLOT.compare_exchange(current, fresh, Ordering::AcqRel, Ordering::Acquire) {
            // SAFETY: just published; never freed.
            Ok(_) => return unsafe { &(*fresh).runtime },
            Err(_) => {
                // SAFETY: never published, so this thread owns it.
                let lost = unsafe { Box::from_raw(fresh) };
                lost.runtime.shutdown_background();
            }
        }
    }
}

/// Refuses an object the binding made in another process. A forked child inherits copies of
/// the parent's clients and sessions with their locks, connection pools and tunnels in
/// whatever state the parent's runtime threads left them at the fork, and those threads do not
/// exist in the child; using them could wait forever. The child builds its own instead.
pub(crate) fn same_process(created_in: u32, what: &str) -> PyResult<()> {
    if created_in == std::process::id() {
        return Ok(());
    }
    Err(PyRuntimeError::new_err(format!(
        "this {what} was created in process {created_in}, before a fork: create a new one in this process \
         (seal.seal, seal.session and seal.signal build their own client after a fork)"
    )))
}

/// How often a blocking call wakes up to check for signals.
const SIGNAL_POLL: Duration = Duration::from_millis(100);

/// Runs `future` on the runtime and waits for it with the GIL released. A signal handler that
/// raises (Ctrl-C) cancels it.
pub(crate) fn wait<T, F>(py: Python<'_>, future: F) -> PyResult<T>
where
    F: Future<Output = Result<T, ClientError>> + Send + 'static,
    T: Send + 'static,
{
    let (tx, mut rx) = mpsc::channel();
    let task = runtime().spawn(async move {
        let _ = tx.send(future.await);
    });
    loop {
        // The receiver moves into the detached closure and back: it is `Send`, not `Sync`.
        let received;
        (received, rx) = py.detach(move || (rx.recv_timeout(SIGNAL_POLL), rx));
        match received {
            Ok(result) => return result.map_err(|e| error(py, e)),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if let Err(e) = py.check_signals() {
                    task.abort();
                    return Err(e);
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(PyRuntimeError::new_err("the seal runtime dropped the call"))
            }
        }
    }
}

/// Runs `future` on the runtime and returns an asyncio future of the running loop, resolved
/// with `convert` of its output. Cancelling the asyncio future cancels `future`.
pub(crate) fn awaitable<'py, T, F, C>(py: Python<'py>, future: F, convert: C) -> PyResult<Bound<'py, PyAny>>
where
    F: Future<Output = Result<T, ClientError>> + Send + 'static,
    T: Send + 'static,
    C: for<'a> FnOnce(Python<'a>, T) -> PyResult<Py<PyAny>> + Send + 'static,
{
    let event_loop = py.import("asyncio")?.call_method0("get_running_loop")?;
    let result = event_loop.call_method0("create_future")?;
    let (loop_ref, result_ref) = (event_loop.unbind(), result.clone().unbind());
    let task = runtime().spawn(async move {
        let output = future.await;
        Python::attach(|py| -> PyResult<()> {
            let (error_value, value) = match output.map_err(|e| error(py, e)).and_then(|v| convert(py, v)) {
                Ok(value) => (py.None(), value),
                Err(e) => (e.into_value(py).into_any(), py.None()),
            };
            let resolve = py.import("seal._aio")?.getattr("resolve")?;
            loop_ref
                .bind(py)
                .call_method1("call_soon_threadsafe", (resolve, result_ref.bind(py), error_value, value))?;
            Ok(())
        })
        // The loop is closed: nobody awaits the result any more.
        .ok();
    });
    result.call_method1("add_done_callback", (types::CancelTask(task.abort_handle()),))?;
    Ok(result)
}

/// The exception of `seal._errors` for `e`'s `ErrorCode`.
pub(crate) fn error(py: Python<'_>, e: ClientError) -> PyErr {
    let code = e.code();
    let message = match e {
        ClientError::Seal { message, .. } => message,
        other => other.to_string(),
    };
    match py.import("seal._errors").and_then(|m| m.call_method1("from_code", (code.as_str(), message))) {
        Ok(exception) => PyErr::from_value(exception),
        Err(e) => e,
    }
}

/// A Python exception raised by an app callback, as an SDK error: a `seal.SealError` keeps its
/// code, anything else is `Invalid`.
pub(crate) fn from_python(py: Python<'_>, what: &str, e: PyErr) -> ClientError {
    let code = e
        .value(py)
        .getattr("code")
        .and_then(|c| c.getattr("value"))
        .ok()
        .and_then(|c| c.extract::<String>().ok())
        .and_then(|c| parse::<ErrorCode>(&c).ok());
    match code {
        Some(code) => ClientError::Seal { code, message: format!("{what}: {}", e.value(py)) },
        None => ClientError::Invalid(format!("{what}: {e}")),
    }
}

/// A serde enum from its wire name (`"high"`, `"hardened"`).
pub(crate) fn parse<T: DeserializeOwned>(text: &str) -> Result<T, ClientError> {
    serde_json::from_value(serde_json::Value::String(text.to_owned()))
        .map_err(|_| ClientError::Invalid(format!("unknown value {text:?}")))
}

/// A serde enum's wire name.
pub(crate) fn wire_name<T: Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(s)) => s,
        _ => String::new(),
    }
}

#[pymodule]
fn _seal(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<client::Client>()?;
    m.add_class::<client::IdentityProvider>()?;
    m.add_class::<client::AppKeyIdentity>()?;
    m.add_class::<client::AzureManagedIdentity>()?;
    m.add_class::<client::KubernetesIdentity>()?;
    m.add_class::<client::GcpIdentity>()?;
    m.add_class::<client::GitHubActionsIdentity>()?;
    #[cfg(feature = "aws")]
    m.add_class::<client::AwsIdentity>()?;
    m.add_class::<session::Session>()?;
    m.add_class::<types::SessionInfo>()?;
    m.add_class::<types::TelemetryReceipt>()?;
    m.add_class::<types::EndpointReport>()?;
    m.add_class::<client::HostAgentReporter>()?;
    m.add_function(wrap_pyfunction!(types::append_receipts, m)?)?;
    m.add("SIM", cfg!(feature = "sim"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_names_round_trip() {
        assert_eq!(wire_name(&seal::Severity::High), "high");
        assert_eq!(parse::<seal::Severity>("critical").unwrap(), seal::Severity::Critical);
        assert_eq!(parse::<seal::ConsumerTier>("hardened").unwrap(), seal::ConsumerTier::Hardened);
        assert_eq!(parse::<ErrorCode>("session_ended").unwrap(), ErrorCode::SessionEnded);
        assert!(matches!(parse::<seal::Severity>("High"), Err(ClientError::Invalid(_))));
        assert_eq!(wire_name(&seal::Protocol::ClickHouse), "click_house");
    }
}
