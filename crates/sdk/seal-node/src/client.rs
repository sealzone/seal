//! `seal::Client` and the workload identities a client can be built with.

use std::str::FromStr;
use std::sync::Arc;

use napi::bindgen_prelude::{Buffer, PromiseRaw};
use napi::Env;
use napi_derive::napi;
use seal::identity as id;
use seal::{ClientError, TenantId, TenantRootId};
use zeroize::Zeroizing;

use crate::session::{Callback, Options, Reporter, Session};
use crate::types::TelemetryReceipt;
use crate::{error, parse};

/// A verified connection to the tenant's enclaves, acting as one workload identity.
#[napi]
pub struct Client {
    inner: seal::Client,
}

/// What `Client.connect` takes; anything unset comes from the environment at connect.
#[napi(object, object_to_js = false)]
pub struct ConnectOptions {
    pub endpoints: Option<Vec<String>>,
    /// `<tenant>` or `<tenant>@<root id>`.
    pub tenant: Option<String>,
    pub root_id: Option<String>,
    /// The release trust's JSON (`seal::Trust::from_json`).
    pub trust: Option<Buffer>,
}

/// The builder for these options.
fn builder(options: ConnectOptions, identity: Option<&Identity>) -> Result<seal::ClientBuilder, ClientError> {
    let mut builder = seal::Client::builder();
    if let Some(endpoints) = options.endpoints {
        let endpoints = endpoints
            .iter()
            .map(|e| url::Url::parse(e.trim()).map_err(|err| ClientError::Invalid(format!("endpoint {e}: {err}"))))
            .collect::<Result<Vec<_>, _>>()?;
        builder = builder.endpoints(endpoints);
    }
    if let Some(tenant) = options.tenant {
        let (tenant, root_id) = seal_proto::TenantPin::parse_partial(&tenant)?;
        builder = builder.tenant(tenant);
        if let Some(root_id) = root_id {
            builder = builder.root_id(root_id);
        }
    }
    if let Some(root_id) = options.root_id {
        builder = builder.root_id(TenantRootId::from_str(root_id.trim())?);
    }
    if let Some(identity) = identity {
        builder = builder.identity(identity.inner.clone());
    }
    if let Some(trust) = options.trust {
        builder = builder.trust(seal::Trust::from_json(&trust)?);
    }
    Ok(builder)
}

/// What `Client.seal` takes besides secret, `to` and apps.
#[napi(object, object_to_js = false)]
pub struct SealOptions {
    pub header: Option<String>,
    pub format: Option<String>,
    pub pins: Option<Vec<String>>,
    /// Unix seconds.
    pub expires: Option<i64>,
    pub methods: Option<Vec<String>>,
    pub deny: Option<Vec<String>>,
    pub sealed_only: Option<bool>,
    pub hardened_only: Option<bool>,
}

/// The blob text and where telemetry recorded the seal.
#[napi(object)]
pub struct Sealed {
    pub blob: String,
    pub receipt: TelemetryReceipt,
}

/// One seal: the secret (wiped once sent) and the options.
struct Seal {
    secret: Zeroizing<Vec<u8>>,
    to: String,
    apps: Vec<String>,
    options: SealOptions,
}

impl Seal {
    async fn send(self, client: seal::Client) -> Result<Sealed, ClientError> {
        let o = &self.options;
        let mut builder = client.seal(&self.secret, &self.to, &self.apps);
        if let Some(header) = &o.header {
            builder = builder.header(header);
        }
        if let Some(format) = &o.format {
            builder = builder.format(format);
        }
        for pin in o.pins.iter().flatten() {
            builder = builder.pin(pin);
        }
        if let Some(at) = o.expires {
            let at = u64::try_from(at).map_err(|_| ClientError::Invalid("expires must be after 1970".into()))?;
            builder = builder.expires(at);
        }
        if let Some(methods) = o.methods.as_ref().filter(|m| !m.is_empty()) {
            builder = builder.methods(methods);
        }
        for prefix in o.deny.iter().flatten() {
            builder = builder.deny(prefix);
        }
        if o.sealed_only == Some(true) {
            builder = builder.sealed_only();
        }
        if o.hardened_only == Some(true) {
            builder = builder.hardened_only();
        }
        let (blob, receipt) = builder.with_receipt().await?;
        Ok(Sealed { blob, receipt: receipt.into() })
    }
}

/// What `Client.session` takes besides the blob and the callbacks.
#[napi(object, object_to_js = false)]
pub struct SessionOptions {
    /// `http` or `database`.
    pub kind: Option<String>,
    /// `base` or `hardened`.
    pub min_tier: Option<String>,
}

#[napi]
impl Client {
    /// Verifies the enclave and resolves to a client. Unset options come from the
    /// environment: `SEAL_ENDPOINT`, `SEAL_TENANT`, the first workload identity found; `trust`
    /// defaults to the one the build ships.
    #[napi(ts_return_type = "Promise<Client>")]
    pub fn connect<'env>(
        env: &'env Env,
        options: ConnectOptions,
        identity: Option<&Identity>,
    ) -> napi::Result<PromiseRaw<'env, Client>> {
        let builder = builder(options, identity).map_err(error)?;
        env.spawn_future(async move { builder.connect().await.map(|inner| Client { inner }).map_err(error) })
    }

    /// The tenant this client serves.
    #[napi(getter)]
    pub fn tenant(&self) -> String {
        self.inner.tenant().to_string()
    }

    #[napi(ts_return_type = "Promise<Sealed>")]
    pub fn seal<'env>(
        &self,
        env: &'env Env,
        secret: Buffer,
        to: String,
        apps: Vec<String>,
        options: SealOptions,
    ) -> napi::Result<PromiseRaw<'env, Sealed>> {
        let seal = Seal { secret: Zeroizing::new(secret.to_vec()), to, apps, options };
        let client = self.inner.clone();
        env.spawn_future(async move { seal.send(client).await.map_err(error) })
    }

    /// Starts a session on `blob`. `kind` (`"http"` or `"database"`) fails before anything is
    /// sent when the blob is of the other kind. The callbacks are `index.js`'s wrappers.
    #[napi(ts_return_type = "Promise<Session>")]
    #[allow(clippy::too_many_arguments)]
    pub fn session<'env>(
        &self,
        env: &'env Env,
        blob: String,
        options: SessionOptions,
        reload_with: Option<Callback<()>>,
        on_reseal: Option<Callback<String>>,
        endpoint_reporter: Option<Callback<String>>,
        host_agent: Option<&HostAgentReporter>,
    ) -> napi::Result<PromiseRaw<'env, Session>> {
        let mut start = Options::new(options.kind.as_deref(), options.min_tier.as_deref()).map_err(error)?;
        start.reload_with = reload_with.map(Arc::new);
        start.on_reseal = on_reseal.map(Arc::new);
        start.endpoint_reporter = match host_agent {
            Some(native) => Some(Reporter::Native(native.inner.clone())),
            None => endpoint_reporter.map(|callback| Reporter::Js(Arc::new(callback))),
        };
        let client = self.inner.clone();
        env.spawn_future(async move { start.start(client, blob).await.map_err(error) })
    }

    /// Signals that this workload's own endpoint may be compromised.
    #[napi(ts_return_type = "Promise<void>")]
    pub fn signal<'env>(&self, env: &'env Env, code: String, severity: String) -> napi::Result<PromiseRaw<'env, ()>> {
        let severity = parse(&severity).map_err(error)?;
        let client = self.inner.clone();
        env.spawn_future(async move { client.signal(&code, severity).await.map_err(error) })
    }
}

/// The seal host agent (App Integrity add-on) as a session's `endpointReporter`: the artifact
/// the agent hashed outside this process, and its evidence signed over the request's
/// challenge. Falls back to hashing this executable when the agent does not answer.
#[napi]
pub struct HostAgentReporter {
    inner: Arc<seal::integrity::HostAgentReporter>,
}

#[napi]
impl HostAgentReporter {
    /// From the environment: `SEAL_AGENT_SOCKET` (default `/run/seal/agent.sock`) and the app
    /// key in `SEAL_APP_KEY`.
    #[napi(factory)]
    pub fn from_env() -> Self {
        Self { inner: Arc::new(seal::integrity::HostAgentReporter::new()) }
    }

    /// The agent at `socket`, reporting for the app key `appKey`.
    #[napi(factory)]
    pub fn with_socket_and_key(socket: String, app_key: String) -> napi::Result<Self> {
        let key_id = id::AppKeyIdentity::parse(&Zeroizing::new(app_key)).map_err(error)?.key_id();
        Ok(Self { inner: Arc::new(seal::integrity::HostAgentReporter::with_socket_and_key(socket, key_id)) })
    }
}

/// A workload identity a client proves itself with. Without one, a client uses the first
/// identity the environment provides.
#[napi]
pub struct Identity {
    inner: Arc<dyn seal::IdentityProvider>,
}

impl Identity {
    fn new(inner: impl seal::IdentityProvider + 'static) -> Self {
        Self { inner: Arc::new(inner) }
    }
}

#[napi]
impl Identity {
    /// Short name for logs and errors, e.g. `app-key`.
    #[napi(getter)]
    pub fn kind(&self) -> &'static str {
        self.inner.kind()
    }

    /// An app key, `sealak_…` (what `SEAL_APP_KEY` holds).
    #[napi(factory)]
    pub fn app_key(key: String) -> napi::Result<Self> {
        let key = Zeroizing::new(key);
        id::AppKeyIdentity::parse(&key).map(Self::new).map_err(error)
    }

    /// An Azure managed identity's token for `audience`, the Entra app ID URI the tenant
    /// registered; `clientId` picks a user-assigned identity.
    #[napi(factory)]
    pub fn azure_managed(audience: String, client_id: Option<String>) -> Self {
        let mut identity = id::AzureManagedIdentity::new(audience);
        if let Some(client_id) = client_id {
            identity = identity.client_id(client_id);
        }
        Self::new(identity)
    }

    /// A Kubernetes projected service account token (audience `seal:<tenant>`,
    /// `expirationSeconds: 600`), re-read for every proof.
    #[napi(factory)]
    pub fn kubernetes(path: Option<String>) -> Self {
        Self::new(id::KubernetesIdentity::new(path.unwrap_or_else(|| id::KubernetesIdentity::DEFAULT_PATH.into())))
    }

    /// A GCP service account's identity token from the metadata server, audience
    /// `seal:<tenant>`.
    #[napi(factory)]
    pub fn gcp(tenant: String) -> napi::Result<Self> {
        let tenant = TenantId::new(&tenant).map_err(|e| error(e.into()))?;
        Ok(Self::new(id::GcpIdentity::new(tenant)))
    }

    /// GitHub Actions OIDC (`permissions: id-token: write`): a fresh token for audience
    /// `seal:<tenant>` on every proof.
    #[napi(factory)]
    pub fn github_actions(tenant: String) -> napi::Result<Self> {
        let tenant = TenantId::new(&tenant).map_err(|e| error(e.into()))?;
        id::GitHubActionsIdentity::from_env(tenant).map(Self::new).map_err(error)
    }
}

/// An IAM role from the default AWS credential chain, proven by a presigned STS
/// `GetCallerIdentity`. Only in builds with the `aws` feature (`AWS` is true).
#[cfg(feature = "aws")]
#[napi(ts_return_type = "Promise<Identity>")]
#[cfg_attr(test, allow(dead_code))]
pub fn aws_identity(env: &Env) -> napi::Result<PromiseRaw<'_, Identity>> {
    env.spawn_future(async { Ok(Identity::new(id::AwsIdentity::from_env().await)) })
}
