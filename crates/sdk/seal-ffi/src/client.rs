//! Clients, the workload identities they act as, sealing and signals.

use std::ffi::c_char;
use std::str::FromStr;
use std::sync::Arc;

use seal::identity as id;
use seal::{ClientError, TenantId, TenantRootId};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::{
    block_on, guard, invalid, json_arg, parse, put, put_json, required, str_arg, Failure, SealCancel, SealError,
};

/// `seal_client`: a verified connection to the tenant's enclaves, acting as one identity.
pub struct SealClient(pub(crate) seal::Client);

/// `seal_identity`: a workload identity a client proves itself with.
pub struct SealIdentity(Arc<dyn seal::IdentityProvider>);

/// The `options_json` of `seal_client_connect`. Unset fields come from the environment.
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Connect {
    endpoints: Vec<String>,
    /// `<tenant>` or `<tenant>@<root id>`.
    tenant: Option<String>,
    root_id: Option<String>,
}

impl Connect {
    /// The builder for these options, as `seal-py` builds it.
    fn builder(
        self,
        identity: Option<&SealIdentity>,
        trust: Option<&[u8]>,
    ) -> Result<seal::ClientBuilder, ClientError> {
        let mut builder = seal::Client::builder();
        builder = builder.endpoints(self.endpoints);
        if let Some(tenant) = self.tenant {
            builder = builder.tenant(tenant);
        }
        if let Some(root_id) = self.root_id {
            builder = builder.root_id(TenantRootId::from_str(root_id.trim())?);
        }
        if let Some(identity) = identity {
            builder = builder.identity(identity.0.clone());
        }
        if let Some(trust) = trust {
            builder = builder.trust(seal::Trust::from_json(trust)?);
        }
        Ok(builder)
    }
}

/// Verifies the enclave and returns a client in `*out`. `options_json` (NULL for none):
/// `{"endpoints": [...], "tenant": "acme[@root]", "root_id": "..."}`; anything unset comes from
/// the environment (`SEAL_ENDPOINT`, `SEAL_TENANT`). `identity` NULL: the first workload
/// identity found. `trust` NULL: the release trust this build ships; otherwise `trust.json`'s
/// bytes.
///
/// # Safety
/// Strings NUL-terminated; `identity` NULL or live; `trust` NULL or `trust_len` readable bytes;
/// `cancel` NULL or live; `out` writable.
#[no_mangle]
pub unsafe extern "C" fn seal_client_connect(
    options_json: *const c_char,
    identity: *const SealIdentity,
    trust: *const u8,
    trust_len: usize,
    cancel: *const SealCancel,
    out: *mut *mut SealClient,
) -> *mut SealError {
    guard(|| {
        // SAFETY: the caller's promises, per argument.
        let (options, identity, cancel) =
            unsafe { (json_arg::<Connect>(options_json, "options")?, identity.as_ref(), cancel.as_ref()) };
        // SAFETY: the caller promises `trust_len` readable bytes at a non-null `trust`.
        if out.is_null() {
            return Err(invalid("an out-parameter is NULL"));
        }
        // A non-NULL `trust` is used even when empty (and then refused), never replaced by the
        // default trust.
        let trust = (!trust.is_null()).then(|| unsafe { std::slice::from_raw_parts(trust, trust_len) });
        let builder = options.builder(identity, trust)?;
        let client = block_on(cancel, builder.connect())?;
        // SAFETY: the caller promises `out` is writable.
        unsafe { put(out, || Box::into_raw(Box::new(SealClient(client)))) }
    })
}

/// Frees a client. Sessions it started keep working. NULL does nothing.
///
/// # Safety
/// `client` NULL or from `seal_client_connect`, freed once, with no call still using it.
#[no_mangle]
pub unsafe extern "C" fn seal_client_free(client: *mut SealClient) {
    if !client.is_null() {
        let _runtime = crate::runtime().enter();
        // SAFETY: from Box::into_raw in seal_client_connect, freed once (the caller's promise).
        drop(unsafe { Box::from_raw(client) });
    }
}

/// The tenant this client serves, in `*out`.
///
/// # Safety
/// `client` live; `out` writable.
#[no_mangle]
pub unsafe extern "C" fn seal_client_tenant(client: *const SealClient, out: *mut *mut c_char) -> *mut SealError {
    guard(|| {
        // SAFETY: the caller promises a live client.
        let client = unsafe { live(client) }?;
        // SAFETY: the caller promises `out` is writable.
        unsafe { put(out, || crate::c_string(client.tenant().to_string())) }
    })
}

/// The `options_json` of `seal_client_seal`.
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Seal {
    to: String,
    apps: Vec<String>,
    header: Option<String>,
    format: Option<String>,
    pins: Vec<String>,
    /// Unix seconds.
    expires: Option<u64>,
    methods: Vec<String>,
    deny: Vec<String>,
    sealed_only: bool,
    hardened_only: bool,
}

impl Seal {
    async fn send(self, client: &seal::Client, secret: &[u8]) -> Result<(String, seal::TelemetryReceipt), ClientError> {
        let mut builder = client.seal(secret, &self.to, &self.apps);
        if let Some(header) = &self.header {
            builder = builder.header(header);
        }
        if let Some(format) = &self.format {
            builder = builder.format(format);
        }
        for pin in &self.pins {
            builder = builder.pin(pin);
        }
        if let Some(at) = self.expires {
            builder = builder.expires(at);
        }
        if !self.methods.is_empty() {
            builder = builder.methods(&self.methods);
        }
        for prefix in &self.deny {
            builder = builder.deny(prefix);
        }
        if self.sealed_only {
            builder = builder.sealed_only();
        }
        if self.hardened_only {
            builder = builder.hardened_only();
        }
        builder.with_receipt().await
    }
}

/// Seals `secret` so only the named apps can use it, and only with `to`: the blob text in
/// `*blob_out`, and where telemetry recorded the seal (`{"stream": "<base64url>", "entry": n}`)
/// in `*receipt_out` unless it is NULL. `options_json`: `{"to": "https://...", "apps": [...],
/// "header", "format", "pins": [...], "expires": <unix seconds>, "methods": [...], "deny": [...],
/// "sealed_only": bool, "hardened_only": bool}`; `to` and `apps` are required.
///
/// # Safety
/// `client` live; `secret` `secret_len` readable bytes (or NULL with 0); strings
/// NUL-terminated; `cancel` NULL or live; `blob_out` writable; `receipt_out` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn seal_client_seal(
    client: *const SealClient,
    secret: *const u8,
    secret_len: usize,
    options_json: *const c_char,
    cancel: *const SealCancel,
    blob_out: *mut *mut c_char,
    receipt_out: *mut *mut c_char,
) -> *mut SealError {
    guard(|| {
        if secret.is_null() && secret_len != 0 {
            return Err(invalid("secret is NULL with a non-zero length"));
        }
        // SAFETY: the caller's promises, per argument.
        let (client, options, cancel) =
            unsafe { (live(client)?, json_arg::<Seal>(options_json, "options")?, cancel.as_ref()) };
        let secret = match secret.is_null() {
            true => Zeroizing::new(Vec::new()),
            // SAFETY: the caller promises `secret_len` readable bytes.
            false => Zeroizing::new(unsafe { std::slice::from_raw_parts(secret, secret_len) }.to_vec()),
        };
        if blob_out.is_null() {
            return Err(invalid("blob_out is NULL"));
        }
        let (blob, receipt) = block_on(cancel, options.send(client, &secret))?;
        if !receipt_out.is_null() {
            // SAFETY: non-null, and the caller promises it is writable.
            unsafe { put_json(receipt_out, &receipt) }?;
        }
        // SAFETY: the caller promises `blob_out` is writable.
        unsafe { put(blob_out, || crate::c_string(blob)) }
    })
}

/// Signals that this workload's own endpoint may be compromised. `severity`: `"low"`,
/// `"medium"`, `"high"` or `"critical"`.
///
/// # Safety
/// `client` live; strings NUL-terminated; `cancel` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn seal_client_signal(
    client: *const SealClient,
    code: *const c_char,
    severity: *const c_char,
    cancel: *const SealCancel,
) -> *mut SealError {
    guard(|| {
        // SAFETY: the caller's promises, per argument.
        let (client, code, severity, cancel) =
            unsafe { (live(client)?, required(code, "code")?, required(severity, "severity")?, cancel.as_ref()) };
        let severity: seal::Severity = parse(severity)?;
        block_on(cancel, client.signal(code, severity))
    })
}

/// The client behind a handle.
///
/// # Safety
/// `client` NULL or live.
pub(crate) unsafe fn live<'a>(client: *const SealClient) -> Result<&'a seal::Client, Failure> {
    // SAFETY: the caller promises NULL or a live client.
    unsafe { client.as_ref() }.map(|c| &c.0).ok_or_else(|| invalid("client is NULL"))
}

/// Returns a new identity handle.
///
/// # Safety
/// `out` writable.
unsafe fn identity_out(
    out: *mut *mut SealIdentity,
    identity: impl seal::IdentityProvider + 'static,
) -> Result<(), Failure> {
    // SAFETY: the caller promises `out` is writable.
    unsafe { put(out, || Box::into_raw(Box::new(SealIdentity(Arc::new(identity))))) }
}

/// An app key, `sealak_…` (what `SEAL_APP_KEY` holds).
///
/// # Safety
/// `key` NUL-terminated; `out` writable.
#[no_mangle]
pub unsafe extern "C" fn seal_identity_app_key(key: *const c_char, out: *mut *mut SealIdentity) -> *mut SealError {
    guard(|| {
        // SAFETY: the caller promises a NUL-terminated string.
        let key = unsafe { required(key, "key") }?;
        let identity = id::AppKeyIdentity::parse(key)?;
        // SAFETY: the caller promises `out` is writable.
        unsafe { identity_out(out, identity) }
    })
}

/// An Azure managed identity's token for `audience`, the Entra app ID URI the tenant
/// registered; `client_id` (NULL for the system-assigned identity) picks a user-assigned one.
///
/// # Safety
/// Strings NULL (`client_id` only) or NUL-terminated; `out` writable.
#[no_mangle]
pub unsafe extern "C" fn seal_identity_azure(
    audience: *const c_char,
    client_id: *const c_char,
    out: *mut *mut SealIdentity,
) -> *mut SealError {
    guard(|| {
        // SAFETY: the caller promises NUL-terminated strings.
        let (audience, client_id) = unsafe { (required(audience, "audience")?, str_arg(client_id, "client_id")?) };
        let mut identity = id::AzureManagedIdentity::new(audience);
        if let Some(client_id) = client_id {
            identity = identity.client_id(client_id);
        }
        // SAFETY: the caller promises `out` is writable.
        unsafe { identity_out(out, identity) }
    })
}

/// A Kubernetes projected service account token (audience `seal:<tenant>`), re-read for every
/// proof, from `path` (NULL for the default path).
///
/// # Safety
/// `path` NULL or NUL-terminated; `out` writable.
#[no_mangle]
pub unsafe extern "C" fn seal_identity_kubernetes(path: *const c_char, out: *mut *mut SealIdentity) -> *mut SealError {
    guard(|| {
        // SAFETY: the caller promises NULL or a NUL-terminated string.
        let path = unsafe { str_arg(path, "path") }?.unwrap_or(id::KubernetesIdentity::DEFAULT_PATH);
        // SAFETY: the caller promises `out` is writable.
        unsafe { identity_out(out, id::KubernetesIdentity::new(path)) }
    })
}

/// A GCP service account's identity token from the metadata server, audience `seal:<tenant>`.
///
/// # Safety
/// `tenant` NUL-terminated; `out` writable.
#[no_mangle]
pub unsafe extern "C" fn seal_identity_gcp(tenant: *const c_char, out: *mut *mut SealIdentity) -> *mut SealError {
    guard(|| {
        // SAFETY: the caller promises a NUL-terminated string.
        let tenant = TenantId::new(unsafe { required(tenant, "tenant") }?).map_err(ClientError::from)?;
        // SAFETY: the caller promises `out` is writable.
        unsafe { identity_out(out, id::GcpIdentity::new(tenant)) }
    })
}

/// GitHub Actions OIDC (`permissions: id-token: write`): a fresh token for audience
/// `seal:<tenant>` on every proof.
///
/// # Safety
/// `tenant` NUL-terminated; `out` writable.
#[no_mangle]
pub unsafe extern "C" fn seal_identity_github_actions(
    tenant: *const c_char,
    out: *mut *mut SealIdentity,
) -> *mut SealError {
    guard(|| {
        // SAFETY: the caller promises a NUL-terminated string.
        let tenant = TenantId::new(unsafe { required(tenant, "tenant") }?).map_err(ClientError::from)?;
        let identity = id::GitHubActionsIdentity::from_env(tenant)?;
        // SAFETY: the caller promises `out` is writable.
        unsafe { identity_out(out, identity) }
    })
}

/// An IAM role from the default AWS credential chain, proven by a presigned STS
/// `GetCallerIdentity`. Builds without the `aws` feature return `"bad_request"`.
///
/// # Safety
/// `cancel` NULL or live; `out` writable.
#[no_mangle]
pub unsafe extern "C" fn seal_identity_aws(cancel: *const SealCancel, out: *mut *mut SealIdentity) -> *mut SealError {
    guard(|| {
        #[cfg(feature = "aws")]
        {
            // SAFETY: the caller promises NULL or a live token.
            let identity = block_on(unsafe { cancel.as_ref() }, async { Ok(id::AwsIdentity::from_env().await) })?;
            // SAFETY: the caller promises `out` is writable.
            unsafe { identity_out(out, identity) }
        }
        #[cfg(not(feature = "aws"))]
        {
            let _ = (cancel, out);
            Err(invalid("this build of seal-ffi has no AWS identity (the `aws` feature)"))
        }
    })
}

/// The identity's short name for logs and errors (`app-key`, `azure`, ...), in `*out`.
///
/// # Safety
/// `identity` live; `out` writable.
#[no_mangle]
pub unsafe extern "C" fn seal_identity_kind(identity: *const SealIdentity, out: *mut *mut c_char) -> *mut SealError {
    guard(|| {
        // SAFETY: the caller promises NULL or a live identity.
        let identity = unsafe { identity.as_ref() }.ok_or_else(|| invalid("identity is NULL"))?;
        // SAFETY: the caller promises `out` is writable.
        unsafe { put(out, || crate::c_string(identity.0.kind().to_owned())) }
    })
}

/// Frees an identity; clients connected with it keep their own reference. NULL does nothing.
///
/// # Safety
/// `identity` NULL or from a `seal_identity_*` constructor, freed once, with no call still
/// using it.
#[no_mangle]
pub unsafe extern "C" fn seal_identity_free(identity: *mut SealIdentity) {
    if !identity.is_null() {
        let _runtime = crate::runtime().enter();
        // SAFETY: from Box::into_raw in identity_out, freed once (the caller's promise).
        drop(unsafe { Box::from_raw(identity) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{take, take_string, text};

    #[test]
    fn a_bad_app_key_is_a_bad_request() {
        let key = text("not-a-key");
        let mut identity = std::ptr::null_mut();
        // SAFETY: valid arguments.
        let (code, _) = take(unsafe { seal_identity_app_key(key.as_ptr(), &mut identity) }).unwrap();
        assert_eq!(code, "bad_request");
        assert!(identity.is_null(), "nothing is written on failure");
    }

    #[test]
    fn identities_report_their_kind() {
        let audience = text("api://seal");
        let tenant = text("acme");
        let mut kinds = Vec::new();
        for make in [
            &(|out| unsafe { seal_identity_azure(audience.as_ptr(), std::ptr::null(), out) })
                as &dyn Fn(*mut *mut SealIdentity) -> *mut SealError,
            &|out| unsafe { seal_identity_kubernetes(std::ptr::null(), out) },
            &|out| unsafe { seal_identity_gcp(tenant.as_ptr(), out) },
        ] {
            let mut identity = std::ptr::null_mut();
            assert_eq!(take(make(&mut identity)), None);
            let mut kind = std::ptr::null_mut();
            // SAFETY: a live identity, freed once.
            unsafe {
                assert_eq!(take(seal_identity_kind(identity, &mut kind)), None);
                seal_identity_free(identity);
            }
            kinds.push(take_string(kind));
        }
        assert_eq!(kinds.len(), 3);
        assert!(kinds.iter().all(|k| !k.is_empty()), "{kinds:?}");
    }

    #[test]
    fn a_bad_tenant_is_a_bad_request() {
        let tenant = text("Not A Tenant!");
        let mut identity = std::ptr::null_mut();
        // SAFETY: valid arguments.
        let (code, _) = take(unsafe { seal_identity_gcp(tenant.as_ptr(), &mut identity) }).unwrap();
        assert_eq!(code, "bad_request");
    }

    #[test]
    fn connect_refuses_bad_options_before_the_network() {
        for options in [r#"{"endpoint": "x"}"#, r#"{"endpoints": ["not a url"]}"#, r#"{"tenant": "a@b"}"#, "[1"] {
            let options = text(options);
            let mut client = std::ptr::null_mut();
            // SAFETY: valid arguments.
            let error = unsafe {
                seal_client_connect(
                    options.as_ptr(),
                    std::ptr::null(),
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    &mut client,
                )
            };
            assert_eq!(take(error).unwrap().0, "bad_request");
            assert!(client.is_null());
        }
        // Malformed trust JSON, too.
        let options = text(r#"{"endpoints": ["https://localhost:1"], "tenant": "acme"}"#);
        let trust = b"{not json";
        let mut client = std::ptr::null_mut();
        // SAFETY: valid arguments.
        let error = unsafe {
            seal_client_connect(
                options.as_ptr(),
                std::ptr::null(),
                trust.as_ptr(),
                trust.len(),
                std::ptr::null(),
                &mut client,
            )
        };
        assert_eq!(take(error).unwrap().0, "bad_request");

        // An empty but given trust is refused, never replaced by the default one; and nothing
        // is done for a NULL out-parameter.
        for (trust, out) in [(b"".as_ptr(), &mut client as *mut _), (trust.as_ptr(), std::ptr::null_mut())] {
            // SAFETY: valid arguments; a NULL `out` is checked.
            let error =
                unsafe { seal_client_connect(options.as_ptr(), std::ptr::null(), trust, 0, std::ptr::null(), out) };
            assert_eq!(take(error).unwrap().0, "bad_request");
        }
    }

    #[test]
    fn a_null_secret_needs_a_zero_length() {
        let options = text(r#"{"to": "https://x.example", "apps": ["a"]}"#);
        let (mut blob, mut receipt) = (std::ptr::null_mut(), std::ptr::null_mut());
        // SAFETY: the secret is checked before anything else, the client included.
        let error = unsafe {
            seal_client_seal(
                std::ptr::null(),
                std::ptr::null(),
                5,
                options.as_ptr(),
                std::ptr::null(),
                &mut blob,
                &mut receipt,
            )
        };
        let (code, message) = take(error).unwrap();
        assert_eq!(code, "bad_request");
        assert!(message.contains("secret"), "{message}");
        assert!(blob.is_null());
    }

    #[test]
    fn null_handles_are_bad_requests() {
        let mut out = std::ptr::null_mut();
        // SAFETY: NULL handles are checked.
        unsafe {
            assert_eq!(take(seal_client_tenant(std::ptr::null(), &mut out)).unwrap().0, "bad_request");
            assert_eq!(take(seal_identity_kind(std::ptr::null(), &mut out)).unwrap().0, "bad_request");
        }
    }

    #[cfg(not(feature = "aws"))]
    #[test]
    fn aws_needs_the_feature() {
        let mut identity = std::ptr::null_mut();
        // SAFETY: valid arguments.
        let (code, message) = take(unsafe { seal_identity_aws(std::ptr::null(), &mut identity) }).unwrap();
        assert_eq!(code, "bad_request");
        assert!(message.contains("aws"), "{message}");
    }
}
