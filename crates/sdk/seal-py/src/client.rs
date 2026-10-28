//! `seal::Client` and the workload identities a client can be built with.

use std::str::FromStr;
use std::sync::Arc;

use pyo3::prelude::*;
use pyo3::IntoPyObjectExt;
use seal::identity as id;
use seal::{ClientError, TenantId, TenantRootId};
use zeroize::Zeroizing;

use crate::session::{self, Kind, Options, Reporter};
use crate::types::TelemetryReceipt;
use crate::{awaitable, parse, wait};

/// A verified connection to the tenant's enclaves, acting as one workload identity.
#[pyclass(frozen, module = "seal._seal")]
pub struct Client {
    inner: seal::Client,
    /// The process that connected it.
    pid: u32,
}

impl Client {
    fn new(inner: seal::Client) -> Self {
        Self { inner, pid: std::process::id() }
    }
    /// The client, refused in a process forked after it was made.
    fn client(&self) -> PyResult<seal::Client> {
        crate::same_process(self.pid, "seal.Client")?;
        Ok(self.inner.clone())
    }
}

/// What `Client::seal` takes besides the client.
struct Seal {
    secret: Zeroizing<Vec<u8>>,
    to: String,
    apps: Vec<String>,
    header: Option<String>,
    format: Option<String>,
    pins: Vec<String>,
    expires: Option<u64>,
    methods: Vec<String>,
    deny: Vec<String>,
    sealed_only: bool,
    hardened_only: bool,
}

impl Seal {
    async fn send(self, client: seal::Client) -> Result<(String, seal::TelemetryReceipt), ClientError> {
        let mut builder = client.seal(&self.secret, &self.to, &self.apps);
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

/// `blob`, or `(blob, receipt)` when asked for.
fn sealed(
    py: Python<'_>,
    (blob, receipt): (String, seal::TelemetryReceipt),
    with_receipt: bool,
) -> PyResult<Py<PyAny>> {
    if with_receipt {
        (blob, TelemetryReceipt::from(receipt)).into_py_any(py)
    } else {
        blob.into_py_any(py)
    }
}

/// The builder for these arguments; anything unset comes from the environment at `connect`.
fn builder(
    endpoints: Option<Vec<String>>,
    tenant: Option<String>,
    root_id: Option<String>,
    identity: Option<PyRef<'_, IdentityProvider>>,
    trust: Option<Vec<u8>>,
) -> Result<seal::ClientBuilder, ClientError> {
    let mut builder = seal::Client::builder();
    if let Some(endpoints) = endpoints {
        builder = builder.endpoints(endpoints);
    }
    if let Some(tenant) = tenant {
        builder = builder.tenant(tenant);
    }
    if let Some(root_id) = root_id {
        builder = builder.root_id(TenantRootId::from_str(root_id.trim())?);
    }
    if let Some(identity) = identity {
        builder = builder.identity(identity.inner.clone());
    }
    if let Some(trust) = trust {
        builder = builder.trust(seal::Trust::from_json(&trust)?);
    }
    Ok(builder)
}

#[pymethods]
impl Client {
    /// Verifies the enclave and returns a client. Unset arguments come from the environment:
    /// `SEAL_ENDPOINT`, `SEAL_TENANT`, the first workload identity found; `trust` (the release
    /// trust's JSON, `seal::Trust::from_json`) defaults to the one the build ships.
    #[staticmethod]
    #[pyo3(signature = (*, endpoints=None, tenant=None, root_id=None, identity=None, trust=None))]
    fn connect(
        py: Python<'_>,
        endpoints: Option<Vec<String>>,
        tenant: Option<String>,
        root_id: Option<String>,
        identity: Option<PyRef<'_, IdentityProvider>>,
        trust: Option<Vec<u8>>,
    ) -> PyResult<Self> {
        if let Some(identity) = &identity {
            crate::same_process(identity.pid, "identity")?;
        }
        let builder = builder(endpoints, tenant, root_id, identity, trust).map_err(|e| crate::error(py, e))?;
        wait(py, builder.connect()).map(Self::new)
    }

    /// `connect`, as an asyncio future.
    #[staticmethod]
    #[pyo3(signature = (*, endpoints=None, tenant=None, root_id=None, identity=None, trust=None))]
    fn connect_async<'py>(
        py: Python<'py>,
        endpoints: Option<Vec<String>>,
        tenant: Option<String>,
        root_id: Option<String>,
        identity: Option<PyRef<'_, IdentityProvider>>,
        trust: Option<Vec<u8>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        if let Some(identity) = &identity {
            crate::same_process(identity.pid, "identity")?;
        }
        let builder = builder(endpoints, tenant, root_id, identity, trust).map_err(|e| crate::error(py, e))?;
        awaitable(py, builder.connect(), |py, inner| Self::new(inner).into_py_any(py))
    }

    /// The tenant this client serves.
    #[getter]
    fn tenant(&self) -> PyResult<String> {
        Ok(self.client()?.tenant().to_string())
    }

    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (secret, to, apps, *, header=None, format=None, pins=Vec::new(), expires=None,
                        methods=Vec::new(), deny=Vec::new(), sealed_only=false, hardened_only=false,
                        with_receipt=false))]
    fn seal(
        &self,
        py: Python<'_>,
        secret: Vec<u8>,
        to: String,
        apps: Vec<String>,
        header: Option<String>,
        format: Option<String>,
        pins: Vec<String>,
        expires: Option<u64>,
        methods: Vec<String>,
        deny: Vec<String>,
        sealed_only: bool,
        hardened_only: bool,
        with_receipt: bool,
    ) -> PyResult<Py<PyAny>> {
        let args = Seal {
            secret: Zeroizing::new(secret),
            to,
            apps,
            header,
            format,
            pins,
            expires,
            methods,
            deny,
            sealed_only,
            hardened_only,
        };
        let output = wait(py, args.send(self.client()?))?;
        sealed(py, output, with_receipt)
    }

    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (secret, to, apps, *, header=None, format=None, pins=Vec::new(), expires=None,
                        methods=Vec::new(), deny=Vec::new(), sealed_only=false, hardened_only=false,
                        with_receipt=false))]
    fn seal_async<'py>(
        &self,
        py: Python<'py>,
        secret: Vec<u8>,
        to: String,
        apps: Vec<String>,
        header: Option<String>,
        format: Option<String>,
        pins: Vec<String>,
        expires: Option<u64>,
        methods: Vec<String>,
        deny: Vec<String>,
        sealed_only: bool,
        hardened_only: bool,
        with_receipt: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        let args = Seal {
            secret: Zeroizing::new(secret),
            to,
            apps,
            header,
            format,
            pins,
            expires,
            methods,
            deny,
            sealed_only,
            hardened_only,
        };
        awaitable(py, args.send(self.client()?), move |py, output| sealed(py, output, with_receipt))
    }

    /// Starts a session on `blob`. `kind` (`"http"` or `"database"`) fails before anything is
    /// sent when the blob is of the other kind.
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (blob, *, kind=None, min_tier=None, reload_with=None, on_reseal=None, endpoint_reporter=None))]
    fn session(
        &self,
        py: Python<'_>,
        blob: String,
        kind: Option<String>,
        min_tier: Option<String>,
        reload_with: Option<Py<PyAny>>,
        on_reseal: Option<Py<PyAny>>,
        endpoint_reporter: Option<Py<PyAny>>,
    ) -> PyResult<session::Session> {
        let options = options(py, kind, min_tier, reload_with, on_reseal, endpoint_reporter)?;
        let started = wait(py, options.start(self.client()?, blob))?;
        Ok(session::Session::new(started))
    }

    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (blob, *, kind=None, min_tier=None, reload_with=None, on_reseal=None, endpoint_reporter=None))]
    fn session_async<'py>(
        &self,
        py: Python<'py>,
        blob: String,
        kind: Option<String>,
        min_tier: Option<String>,
        reload_with: Option<Py<PyAny>>,
        on_reseal: Option<Py<PyAny>>,
        endpoint_reporter: Option<Py<PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let options = options(py, kind, min_tier, reload_with, on_reseal, endpoint_reporter)?;
        awaitable(py, options.start(self.client()?, blob), |py, started| session::Session::new(started).into_py_any(py))
    }

    /// Signals that this workload's own endpoint may be compromised.
    fn signal(&self, py: Python<'_>, code: String, severity: String) -> PyResult<()> {
        let client = self.client()?;
        let severity = parse(&severity).map_err(|e| crate::error(py, e))?;
        wait(py, async move { client.signal(&code, severity).await })
    }

    fn signal_async<'py>(&self, py: Python<'py>, code: String, severity: String) -> PyResult<Bound<'py, PyAny>> {
        let client = self.client()?;
        let severity = parse(&severity).map_err(|e| crate::error(py, e))?;
        awaitable(py, async move { client.signal(&code, severity).await }, |py, ()| Ok(py.None()))
    }
}

fn options(
    py: Python<'_>,
    kind: Option<String>,
    min_tier: Option<String>,
    reload_with: Option<Py<PyAny>>,
    on_reseal: Option<Py<PyAny>>,
    endpoint_reporter: Option<Py<PyAny>>,
) -> PyResult<Options> {
    let to_py = |e| crate::error(py, e);
    let kind = match kind.as_deref() {
        None => None,
        Some("http") => Some(Kind::Http),
        Some("database") => Some(Kind::Database),
        Some(other) => {
            return Err(to_py(ClientError::Invalid(format!("kind must be \"http\" or \"database\", not {other:?}"))))
        }
    };
    let min_tier = min_tier.as_deref().map(parse).transpose().map_err(to_py)?;
    Ok(Options {
        kind,
        min_tier,
        reload_with: reload_with.map(Arc::new),
        on_reseal: on_reseal.map(Arc::new),
        endpoint_reporter: endpoint_reporter.map(|reporter| match reporter.bind(py).cast::<HostAgentReporter>() {
            Ok(native) => Reporter::Native(native.get().inner.clone()),
            Err(_) => Reporter::Python(Arc::new(reporter)),
        }),
    })
}

/// The seal host agent (App Integrity add-on) as a session's `endpoint_reporter`: the
/// artifact the agent hashed outside this process, and its evidence signed over the request's
/// challenge. Without arguments it reads `SEAL_AGENT_SOCKET` (default `/run/seal/agent.sock`)
/// and the app key from `SEAL_APP_KEY`; with them, both must be given. When the agent does not
/// answer it falls back to hashing this executable.
#[pyclass(frozen, module = "seal._seal")]
pub struct HostAgentReporter {
    inner: Arc<seal::integrity::HostAgentReporter>,
}

#[pymethods]
impl HostAgentReporter {
    #[new]
    #[pyo3(signature = (*, socket=None, app_key=None))]
    fn new(py: Python<'_>, socket: Option<String>, app_key: Option<String>) -> PyResult<Self> {
        let reporter = match (socket, app_key) {
            (None, None) => seal::integrity::HostAgentReporter::new(),
            (Some(socket), Some(key)) => {
                let key_id = id::AppKeyIdentity::parse(&key).map_err(|e| crate::error(py, e))?.key_id();
                seal::integrity::HostAgentReporter::with_socket_and_key(socket, key_id)
            }
            _ => {
                let e = ClientError::Invalid("HostAgentReporter takes both socket and app_key, or neither".into());
                return Err(crate::error(py, e));
            }
        };
        Ok(Self { inner: Arc::new(reporter) })
    }
}

/// A workload identity a client proves itself with. Without one, a client uses the first
/// identity the environment provides.
#[pyclass(subclass, frozen, module = "seal._seal")]
pub struct IdentityProvider {
    inner: Arc<dyn seal::IdentityProvider>,
    /// The process that made it: identities fetching tokens hold connection pools.
    pid: u32,
}

impl IdentityProvider {
    fn init(inner: impl seal::IdentityProvider + 'static) -> PyClassInitializer<Self> {
        PyClassInitializer::from(Self { inner: Arc::new(inner), pid: std::process::id() })
    }
}

#[pymethods]
impl IdentityProvider {
    /// Short name for logs and errors, e.g. `app-key`.
    #[getter]
    fn kind(&self) -> &'static str {
        self.inner.kind()
    }
    fn __repr__(&self) -> String {
        format!("IdentityProvider(kind={:?})", self.inner.kind())
    }
}

/// An app key, `sealak_…` (what `SEAL_APP_KEY` holds).
#[pyclass(extends = IdentityProvider, frozen, module = "seal._seal")]
pub struct AppKeyIdentity;

#[pymethods]
impl AppKeyIdentity {
    #[new]
    fn new(py: Python<'_>, key: &str) -> PyResult<PyClassInitializer<Self>> {
        let identity = id::AppKeyIdentity::parse(key).map_err(|e| crate::error(py, e))?;
        Ok(IdentityProvider::init(identity).add_subclass(Self))
    }
}

/// An Azure managed identity's token for `audience`, the Entra app ID URI the tenant
/// registered; `client_id` picks a user-assigned identity.
#[pyclass(extends = IdentityProvider, frozen, module = "seal._seal")]
pub struct AzureManagedIdentity;

#[pymethods]
impl AzureManagedIdentity {
    #[new]
    #[pyo3(signature = (audience, *, client_id=None))]
    fn new(audience: String, client_id: Option<String>) -> PyClassInitializer<Self> {
        let mut identity = id::AzureManagedIdentity::new(audience);
        if let Some(client_id) = client_id {
            identity = identity.client_id(client_id);
        }
        IdentityProvider::init(identity).add_subclass(Self)
    }
}

/// A Kubernetes projected service account token (audience `seal:<tenant>`,
/// `expirationSeconds: 600`), re-read for every proof.
#[pyclass(extends = IdentityProvider, frozen, module = "seal._seal")]
pub struct KubernetesIdentity;

#[pymethods]
impl KubernetesIdentity {
    #[new]
    #[pyo3(signature = (path=id::KubernetesIdentity::DEFAULT_PATH.into()))]
    fn new(path: std::path::PathBuf) -> PyClassInitializer<Self> {
        IdentityProvider::init(id::KubernetesIdentity::new(path)).add_subclass(Self)
    }
}

/// A GCP service account's identity token from the metadata server, audience `seal:<tenant>`.
#[pyclass(extends = IdentityProvider, frozen, module = "seal._seal")]
pub struct GcpIdentity;

#[pymethods]
impl GcpIdentity {
    #[new]
    fn new(py: Python<'_>, tenant: &str) -> PyResult<PyClassInitializer<Self>> {
        let tenant = TenantId::new(tenant).map_err(|e| crate::error(py, e.into()))?;
        Ok(IdentityProvider::init(id::GcpIdentity::new(tenant)).add_subclass(Self))
    }
}

/// GitHub Actions OIDC (`permissions: id-token: write`): a fresh token for audience
/// `seal:<tenant>` on every proof.
#[pyclass(extends = IdentityProvider, frozen, module = "seal._seal")]
pub struct GitHubActionsIdentity;

#[pymethods]
impl GitHubActionsIdentity {
    #[new]
    fn new(py: Python<'_>, tenant: &str) -> PyResult<PyClassInitializer<Self>> {
        let tenant = TenantId::new(tenant).map_err(|e| crate::error(py, e.into()))?;
        let identity = id::GitHubActionsIdentity::from_env(tenant).map_err(|e| crate::error(py, e))?;
        Ok(IdentityProvider::init(identity).add_subclass(Self))
    }
}

/// An IAM role from the default AWS credential chain, proven by a presigned STS
/// `GetCallerIdentity`.
#[cfg(feature = "aws")]
#[pyclass(extends = IdentityProvider, frozen, module = "seal._seal")]
pub struct AwsIdentity;

#[cfg(feature = "aws")]
#[pymethods]
impl AwsIdentity {
    #[new]
    fn new(py: Python<'_>) -> PyResult<PyClassInitializer<Self>> {
        let identity = wait(py, async { Ok(id::AwsIdentity::from_env().await) })?;
        Ok(IdentityProvider::init(identity).add_subclass(Self))
    }
}
