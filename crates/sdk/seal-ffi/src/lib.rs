//! A C ABI over the Rust SDK (`seal::Client`), declared in `seal.h`, for the Go SDK
//! (`seal.zone/go`, in `crates/sdk/seal-go`). Other languages with a C FFI can use it too.
//!
//! The conventions, the same for every function (`seal.h` says them again for C readers):
//!
//! - Every fallible function returns a `seal_error *`: NULL on success, otherwise an error with
//!   `code` (an `ErrorCode` wire name, `"bad_request"`, `"unavailable"`, ..., or `"canceled"`
//!   when its `seal_cancel` fired) and `message`. Free it with `seal_error_free`. Results come
//!   back through out-parameters, written only on success.
//! - Strings in are NUL-terminated UTF-8, borrowed for the call. Strings out are allocated
//!   here; free them with `seal_string_free`. Structured values cross as JSON text.
//! - Clients, sessions, identities and cancel tokens are opaque handles, freed with their
//!   `*_free` function. Handles are safe to use from several threads at once; a free must not
//!   race a call on the same handle.
//! - Calls that reach the network block the calling thread. They run on one process-wide tokio
//!   runtime, which also runs the tunnels of live sessions. A call given a `seal_cancel`
//!   returns `"canceled"` as soon as the token is cancelled, dropping what it was doing.
//! - A panic never unwinds into the caller: it becomes an `"internal"` error.

extern crate seal_client as seal;

use std::ffi::{c_char, CStr, CString};
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use seal::ClientError;
use serde::de::DeserializeOwned;
use serde::Serialize;

mod client;
mod session;

pub use client::*;
pub use session::*;

/// The runtime every SDK future and tunnel runs on, started on first use. Never shut down:
/// tunnels of live sessions run on it until the process exits.
pub(crate) fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("seal")
            .build()
            .expect("starting the seal runtime")
    })
}

/// `seal_error`: what every fallible function returns, NULL on success.
#[repr(C)]
pub struct SealError {
    /// An `ErrorCode` wire name, or `"canceled"`.
    pub code: *mut c_char,
    pub message: *mut c_char,
}

/// Why a call failed.
#[derive(Debug)]
pub(crate) enum Failure {
    Client(ClientError),
    /// The call's `seal_cancel` fired.
    Canceled,
}

impl From<ClientError> for Failure {
    fn from(e: ClientError) -> Self {
        Failure::Client(e)
    }
}

/// The code `Failure::Canceled` reports.
pub const CANCELED: &str = "canceled";

impl Failure {
    /// The code and message, mapped as `seal-py` maps them: an enclave error keeps its message,
    /// the SDK's own errors their display text.
    pub(crate) fn parts(self) -> (String, String) {
        match self {
            Failure::Client(e) => {
                let code = e.code().as_str().to_owned();
                let message = match e {
                    ClientError::Seal { message, .. } => message,
                    other => other.to_string(),
                };
                (code, message)
            }
            Failure::Canceled => (CANCELED.to_owned(), "the call was canceled".to_owned()),
        }
    }

    fn into_raw(self) -> *mut SealError {
        let (code, message) = self.parts();
        Box::into_raw(Box::new(SealError { code: c_string(code), message: c_string(message) }))
    }
}

pub(crate) fn invalid(message: impl Into<String>) -> Failure {
    Failure::Client(ClientError::Invalid(message.into()))
}

/// Runs an exported function's body: its error, or a panic, as a `seal_error`.
pub(crate) fn guard(body: impl FnOnce() -> Result<(), Failure>) -> *mut SealError {
    match std::panic::catch_unwind(AssertUnwindSafe(body)) {
        Ok(Ok(())) => std::ptr::null_mut(),
        Ok(Err(e)) => e.into_raw(),
        Err(_) => {
            Failure::Client(ClientError::Seal { code: seal::ErrorCode::Internal, message: "seal-ffi panicked".into() })
                .into_raw()
        }
    }
}

/// Runs `future` on the runtime, blocking this thread until it finishes or `cancel` fires.
pub(crate) fn block_on<T>(
    cancel: Option<&SealCancel>,
    future: impl Future<Output = Result<T, ClientError>>,
) -> Result<T, Failure> {
    runtime().block_on(async move {
        match cancel {
            None => future.await.map_err(Failure::Client),
            Some(cancel) => tokio::select! {
                result = future => result.map_err(Failure::Client),
                () = cancel.cancelled() => Err(Failure::Canceled),
            },
        }
    })
}

/// An owned C string; NULs (which no SDK string holds) become U+FFFD.
pub(crate) fn c_string(text: String) -> *mut c_char {
    let text = match text.contains('\0') {
        true => text.replace('\0', "\u{fffd}"),
        false => text,
    };
    CString::new(text).expect("no NUL left").into_raw()
}

/// A borrowed string argument; NULL is `None`.
///
/// # Safety
/// `text` is NULL or a NUL-terminated string valid for `'a`.
pub(crate) unsafe fn str_arg<'a>(text: *const c_char, what: &str) -> Result<Option<&'a str>, Failure> {
    if text.is_null() {
        return Ok(None);
    }
    // SAFETY: non-null, and the caller promises a NUL-terminated string valid for 'a.
    let text = unsafe { CStr::from_ptr(text) };
    text.to_str().map(Some).map_err(|_| invalid(format!("{what} is not UTF-8")))
}

/// A required string argument.
///
/// # Safety
/// As `str_arg`.
pub(crate) unsafe fn required<'a>(text: *const c_char, what: &str) -> Result<&'a str, Failure> {
    // SAFETY: forwarded from the caller.
    unsafe { str_arg(text, what) }?.ok_or_else(|| invalid(format!("{what} is NULL")))
}

/// Options given as JSON text; NULL or empty is every default.
///
/// # Safety
/// As `str_arg`.
pub(crate) unsafe fn json_arg<T: DeserializeOwned + Default>(text: *const c_char, what: &str) -> Result<T, Failure> {
    // SAFETY: forwarded from the caller.
    match unsafe { str_arg(text, what) }? {
        None => Ok(T::default()),
        Some(text) if text.trim().is_empty() => Ok(T::default()),
        Some(text) => serde_json::from_str(text).map_err(|e| invalid(format!("{what}: {e}"))),
    }
}

/// Writes `value()` to an out-parameter. `value` runs only once `out` is known to be non-NULL,
/// so a handle or string it allocates is never left without an owner.
///
/// # Safety
/// `out` is NULL or valid for a write of `T`.
pub(crate) unsafe fn put<T>(out: *mut T, value: impl FnOnce() -> T) -> Result<(), Failure> {
    if out.is_null() {
        return Err(invalid("an out-parameter is NULL"));
    }
    // SAFETY: non-null, and the caller promises it is valid for a write.
    unsafe { out.write(value()) };
    Ok(())
}

/// `value` as JSON text in an out-parameter.
///
/// # Safety
/// As `put`.
pub(crate) unsafe fn put_json<T: Serialize>(out: *mut *mut c_char, value: &T) -> Result<(), Failure> {
    let text = serde_json::to_string(value).map_err(|e| invalid(format!("encoding JSON: {e}")))?;
    // SAFETY: forwarded from the caller.
    unsafe { put(out, || c_string(text)) }
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

/// `seal_cancel`: cancels the calls it is passed to, once and for good.
#[derive(Default)]
pub struct SealCancel {
    fired: AtomicBool,
    notify: tokio::sync::Notify,
}

impl SealCancel {
    async fn cancelled(&self) {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.fired.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
}

/// A new cancel token. Free it with `seal_cancel_free` once no call uses it.
#[no_mangle]
pub extern "C" fn seal_cancel_new() -> *mut SealCancel {
    Box::into_raw(Box::default())
}

/// Cancels every call given `cancel`, now and later. NULL does nothing.
///
/// # Safety
/// `cancel` is NULL or from `seal_cancel_new`, not yet freed.
#[no_mangle]
pub unsafe extern "C" fn seal_cancel_cancel(cancel: *const SealCancel) {
    // SAFETY: the caller promises a live token or NULL.
    if let Some(cancel) = unsafe { cancel.as_ref() } {
        cancel.fired.store(true, Ordering::Release);
        cancel.notify.notify_waiters();
    }
}

/// Frees a cancel token. NULL does nothing.
///
/// # Safety
/// `cancel` is NULL or from `seal_cancel_new`, freed once, with no call still using it.
#[no_mangle]
pub unsafe extern "C" fn seal_cancel_free(cancel: *mut SealCancel) {
    if !cancel.is_null() {
        // SAFETY: from Box::into_raw in seal_cancel_new, freed once (the caller's promise).
        drop(unsafe { Box::from_raw(cancel) });
    }
}

/// Frees a string this library returned. NULL does nothing.
///
/// # Safety
/// `text` is NULL or a string this library returned, freed once.
#[no_mangle]
pub unsafe extern "C" fn seal_string_free(text: *mut c_char) {
    if !text.is_null() {
        // SAFETY: from CString::into_raw in c_string, freed once (the caller's promise).
        let mut bytes = unsafe { CString::from_raw(text) }.into_bytes_with_nul();
        // Some strings carry a session token (seal_session_credential): wipe them all.
        zeroize::Zeroize::zeroize(&mut bytes);
    }
}

/// Frees an error and its strings. NULL does nothing.
///
/// # Safety
/// `error` is NULL or an error this library returned, freed once.
#[no_mangle]
pub unsafe extern "C" fn seal_error_free(error: *mut SealError) {
    if error.is_null() {
        return;
    }
    // SAFETY: from Box::into_raw in Failure::into_raw, freed once (the caller's promise).
    let error = unsafe { Box::from_raw(error) };
    // SAFETY: both strings come from c_string and are owned by the error.
    unsafe {
        seal_string_free(error.code);
        seal_string_free(error.message);
    }
}

/// Appends receipts (a JSON array of `{"stream": "<base64url>", "entry": n}`, as
/// `seal_client_seal` and `seal_session_receipts` give them) to the file at `path` as JSON
/// lines, the format `seal telemetry --receipts` reads; creates the file when missing.
///
/// # Safety
/// `path` and `receipts_json` are NUL-terminated strings.
#[no_mangle]
pub unsafe extern "C" fn seal_append_receipts(path: *const c_char, receipts_json: *const c_char) -> *mut SealError {
    guard(|| {
        // SAFETY: the caller promises NUL-terminated strings.
        let path = unsafe { required(path, "path") }?;
        // SAFETY: as above.
        let receipts: Vec<seal::TelemetryReceipt> = unsafe { json_arg(receipts_json, "receipts") }?;
        seal::receipts::append(path, &receipts)
            .map_err(|e| Failure::Client(ClientError::Invalid(format!("appending receipts to {path}: {e}"))))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use seal::ErrorCode;

    /// The code and message of a returned error, freeing it.
    pub(crate) fn take(error: *mut SealError) -> Option<(String, String)> {
        if error.is_null() {
            return None;
        }
        // SAFETY: a live error from this library.
        let parts = unsafe {
            let e = &*error;
            (
                CStr::from_ptr(e.code).to_str().unwrap().to_owned(),
                CStr::from_ptr(e.message).to_str().unwrap().to_owned(),
            )
        };
        // SAFETY: freed once.
        unsafe { seal_error_free(error) };
        Some(parts)
    }

    pub(crate) fn text(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    /// Takes a returned string, freeing it.
    pub(crate) fn take_string(s: *mut c_char) -> String {
        // SAFETY: a live string from this library, freed once.
        unsafe {
            let owned = CStr::from_ptr(s).to_str().unwrap().to_owned();
            seal_string_free(s);
            owned
        }
    }

    #[test]
    fn errors_map_as_seal_py_maps_them() {
        let cases = [
            (
                ClientError::Seal { code: ErrorCode::NotAllowed, message: "not yours".into() },
                "not_allowed",
                "not yours",
            ),
            (
                ClientError::Verification("bad quote".into()),
                "verification_failed",
                "enclave verification failed: bad quote",
            ),
            (ClientError::NoIdentity("none".into()), "not_allowed", "no workload identity found: none"),
            (ClientError::Invalid("bad".into()), "bad_request", "invalid argument: bad"),
            (ClientError::Network("down".into()), "unavailable", "network: down"),
        ];
        for (error, code, message) in cases {
            let raw = guard(|| Err(error.into()));
            assert_eq!(take(raw), Some((code.to_owned(), message.to_owned())));
        }
        assert_eq!(take(guard(|| Err(Failure::Canceled))).unwrap().0, CANCELED);
        assert_eq!(take(guard(|| Ok(()))), None);
    }

    #[test]
    fn every_code_is_its_wire_name() {
        use ErrorCode::*;
        for code in [
            Expired,
            NotAllowed,
            TierTooLow,
            IntegrityFailed,
            Unavailable,
            PolicyDenied,
            BudgetExceeded,
            SessionExpired,
            SessionEnded,
            VerificationFailed,
            BadRequest,
            Internal,
            ResealRequired,
        ] {
            let (got, _) = Failure::Client(ClientError::Seal { code, message: String::new() }).parts();
            assert_eq!(got, wire_name(&code));
        }
    }

    #[test]
    fn a_panic_is_an_internal_error() {
        let raw = guard(|| panic!("boom"));
        assert_eq!(take(raw), Some(("internal".to_owned(), "seal-ffi panicked".to_owned())));
    }

    #[test]
    fn nul_bytes_never_cut_a_string() {
        assert_eq!(take_string(c_string("a\0b".into())), "a\u{fffd}b");
    }

    #[test]
    fn freeing_null_does_nothing() {
        // SAFETY: NULL is allowed for every free.
        unsafe {
            seal_string_free(std::ptr::null_mut());
            seal_error_free(std::ptr::null_mut());
            seal_cancel_free(std::ptr::null_mut());
            seal_cancel_cancel(std::ptr::null());
        }
    }

    #[test]
    fn a_cancelled_call_returns_at_once() {
        let cancel = seal_cancel_new();
        // SAFETY: a live token, freed once after its last use.
        unsafe {
            seal_cancel_cancel(cancel);
            let result = block_on(cancel.as_ref(), std::future::pending::<Result<(), ClientError>>());
            assert!(matches!(result, Err(Failure::Canceled)));
            seal_cancel_free(cancel);
        }
        // Without a token, it runs to the end.
        assert_eq!(block_on(None, async { Ok::<_, ClientError>(7) }).unwrap(), 7);
    }

    #[test]
    fn a_cancel_from_another_thread_ends_a_waiting_call() {
        struct Token(*mut SealCancel);
        // SAFETY: the token is Sync; the pointer outlives both threads.
        unsafe impl Send for Token {}
        let token = Token(seal_cancel_new());
        let raw = token.0 as usize;
        let canceller = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(50));
            // SAFETY: live until the join below.
            unsafe { seal_cancel_cancel(raw as *const SealCancel) };
        });
        // SAFETY: live until freed below, after the join.
        let result = block_on(unsafe { token.0.as_ref() }, std::future::pending::<Result<(), ClientError>>());
        canceller.join().unwrap();
        assert!(matches!(result, Err(Failure::Canceled)));
        // SAFETY: freed once, no call uses it any more.
        unsafe { seal_cancel_free(token.0) };
    }

    #[test]
    fn receipts_append_as_json_lines() {
        let path = std::env::temp_dir().join(format!("seal-ffi-receipts-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let receipts = [seal::TelemetryReceipt { stream: [7; 16], entry: 3 }];
        let json = text(&serde_json::to_string(&receipts).unwrap());
        let c_path = text(path.to_str().unwrap());
        // SAFETY: NUL-terminated strings.
        assert_eq!(take(unsafe { seal_append_receipts(c_path.as_ptr(), json.as_ptr()) }), None);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("{}\n", serde_json::to_string(&receipts[0]).unwrap())
        );
        // A malformed array is a bad request, and writes nothing.
        let bad = text(r#"[{"stream": "short", "entry": 1}]"#);
        // SAFETY: as above.
        assert_eq!(take(unsafe { seal_append_receipts(c_path.as_ptr(), bad.as_ptr()) }).unwrap().0, "bad_request");
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 1);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn the_header_declares_every_exported_function() {
        let header = include_str!("../seal.h");
        let sources = [include_str!("lib.rs"), include_str!("client.rs"), include_str!("session.rs")];
        let mut exported = 0;
        for source in sources {
            for line in source.lines() {
                let Some(rest) = line.trim().strip_prefix("pub ") else {
                    continue;
                };
                let rest = rest.strip_prefix("unsafe ").unwrap_or(rest);
                let Some(rest) = rest.strip_prefix("extern \"C\" fn ") else {
                    continue;
                };
                let name = &rest[..rest.find('(').unwrap()];
                let declared = header.contains(&format!(" {name}(")) || header.contains(&format!("*{name}("));
                assert!(declared, "seal.h does not declare {name}");
                exported += 1;
            }
        }
        assert!(exported > 20, "found {exported} exported functions");
    }
}
