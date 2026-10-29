//! The `seal` command.
//!
//! ```text
//! Everyday
//!   seal login | logout | whoami            console account (device code approved in the browser)
//!   seal use [TENANT]                       pick a tenant; its root chain and state verified here
//!   seal status [--log]                     the tenant at a glance; --log scans the transparency log
//!   seal secret --to URL --app NAME [..]    seal a secret read from the terminal or stdin; prints the blob
//!                                           (anyone may: --tenant T@ROOT --endpoint URL, no login)
//! Who may do what (sealing is open to anyone)
//!   seal grant  app NAME KIND .. | enclave KIND .. [--hosted] | network APP CIDR ..
//!   seal revoke app NAME [KIND ..] | enclave KIND .. | network APP CIDR ..
//!   seal changes [--watch] | show|sign|submit|cancel ID
//! Tenant settings
//!   seal settings admins|window|platforms|integrity|telemetry-readers|freshness|tenant-key ..
//!   seal deploy azure .. | upgrade ..       enclave replicas in your Azure subscription
//!   seal key create [--out F] | public F    admin key files (the CLI stores none)
//!   seal telemetry [..]                     verified telemetry
//!   seal release approve MEASUREMENT        tenant co-signature of a release
//!   seal completion SHELL
//! ```
//! KIND is azure, aws, k8s, gcp, github or key (apps), or azure, aws or confidential-space
//! (enclaves), each with its own id flags.
//!
//! A change is built on the verified state in force, shown as classified differences, then
//! proposed on the control plane and signed by the admins' passkeys in the console, which the
//! CLI opens and follows until the change is logged; `--key-file` signs here instead (`sign`).
//! The CLI keeps no admin key and no credential in `$SEAL_HOME` (`config`): the console login
//! is in the OS keychain (`console`). Exit status: 0 done, 1 error, 2 usage, 3 `changes --watch
//! --once` found something pending, 130 stopped waiting (the proposal stays).

#![forbid(unsafe_code)]

extern crate seal_client as seal;

mod config;
mod console;
mod deploy;
mod grants;
mod identity;
#[cfg(feature = "passkey")]
mod passkey;
mod settings;
mod sign;
mod status;
mod telemetry;
mod ui;
mod watch;

use std::io::{IsTerminal as _, Read as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use anyhow::{anyhow, bail, Context as _};
use clap::builder::FalseyValueParser;
use clap::{Args, CommandFactory as _, FromArgMatches as _, Parser, Subcommand};

use seal::admin::{Admin, ControlClient, Credential, HttpsClient, LogClient, SigningKeyCredential};
use seal_crypto::sign::SigningKey;
use seal_crypto::SecretBytes;
use seal_proto::state::TenantState;
use seal_proto::{TenantId, TenantRootId, TrustedTime, UnixTime};

use config::{Config, Home, Trusted};
use console::{Console, ConsoleCredential};

#[derive(Parser, Debug)]
#[command(
    name = "seal",
    version,
    about = "Use secrets without holding them: seal them for your apps, and run your Seal tenant."
)]
struct Cli {
    #[command(flatten)]
    global: Global,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Args, Debug, Clone)]
struct Global {
    /// Config directory (default ~/.config/seal)
    #[arg(long, env = "SEAL_HOME", value_name = "DIR", global = true, help_heading = "Global options")]
    home: Option<PathBuf>,
    /// The console (default console.seal.zone)
    #[arg(long, env = "SEAL_CONSOLE_URL", value_name = "URL", global = true, help_heading = "Global options")]
    console_url: Option<url::Url>,
    /// The control plane (default control.seal.zone)
    #[arg(long, env = "SEAL_CONTROL_URL", value_name = "URL", global = true, help_heading = "Global options")]
    control_url: Option<url::Url>,
    /// The transparency log (default log.seal.zone)
    #[arg(long, env = "SEAL_LOG_URL", value_name = "URL", global = true, help_heading = "Global options")]
    log_url: Option<url::Url>,
    /// Verify with this trust.json, not the built-in trust
    #[arg(long, env = "SEAL_TRUST", value_name = "FILE", global = true, help_heading = "Global options")]
    trust: Option<PathBuf>,
    /// Plain output, no color (also NO_COLOR=1)
    #[arg(long, global = true, help_heading = "Global options")]
    no_color: bool,
    /// The control plane's write token: development control planes, for `seal dev init`
    #[arg(long, env = "SEAL_CONTROL_TOKEN", value_name = "TOKEN", global = true, hide = true, hide_env_values = true)]
    control_token: Option<String>,
}

/// Admin key files to sign with: the only keys the CLI ever uses, read where they are.
#[derive(Args, Debug, Clone, Default)]
struct KeyFiles {
    /// Sign with this admin key file, not in the console; repeat for M-of-N
    #[arg(long = "key-file", value_name = "FILE", global = true, help_heading = "Signing")]
    key_files: Vec<PathBuf>,
}

#[derive(Args, Debug, Clone, Default)]
struct SignArgs {
    #[command(flatten)]
    keys: KeyFiles,
    /// Freshness key file to sign new states with
    #[arg(long, env = "SEAL_FRESHNESS_KEY", value_name = "FILE", global = true, help_heading = "Signing")]
    freshness_key: Option<PathBuf>,
    /// Sign or propose without asking
    #[arg(long, short = 'y', global = true, help_heading = "Signing")]
    yes: bool,
    /// Print the console link, don't open a browser
    #[arg(long, env = "SEAL_NO_BROWSER", value_parser = FalseyValueParser::new(), global = true, help_heading = "Signing")]
    no_browser: bool,
    /// Propose and exit; don't wait for the signatures
    #[arg(long, global = true, help_heading = "Signing")]
    no_wait: bool,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Sign in to the console (a code you approve in the browser)
    Login {
        /// Print the link instead of opening a browser
        #[arg(long, env = "SEAL_NO_BROWSER", value_parser = FalseyValueParser::new())]
        no_browser: bool,
    },
    /// Sign out: revoke this machine's console login
    Logout,
    /// Who you are signed in as, and your workspaces
    Whoami {
        /// JSON instead of text
        #[arg(long)]
        json: bool,
    },
    /// Pick the tenant the other commands work on, from your workspaces; verifies it
    Use {
        /// The tenant's id; without it, a list to pick from
        tenant: Option<TenantId>,
    },
    /// The tenant at a glance: root, admin keys, state in force, grants, pending changes
    Status {
        #[command(flatten)]
        keys: KeyFiles,
        #[command(flatten)]
        args: status::StatusArgs,
    },
    /// Seal a secret (read from the terminal, or stdin) for apps; prints the blob
    Secret(SecretArgs),
    /// Let an app start sessions, or an enclave serve the tenant
    Grant {
        #[command(flatten)]
        sign: SignArgs,
        #[command(subcommand)]
        cmd: grants::GrantCmd,
    },
    /// Take a grant back
    Revoke {
        #[command(flatten)]
        sign: SignArgs,
        #[command(subcommand)]
        cmd: grants::RevokeCmd,
    },
    /// Proposals waiting for signatures, and logged changes not yet in force
    Changes {
        #[command(flatten)]
        args: sign::ChangesArgs,
        #[command(flatten)]
        sign: SignArgs,
    },
    /// Admin keys, the pending window, platforms, integrity, telemetry readers, freshness
    Settings {
        #[command(flatten)]
        sign: SignArgs,
        #[command(subcommand)]
        cmd: settings::SettingsCmd,
    },
    /// Run enclave replicas in your cloud account, or upgrade them
    Deploy {
        #[command(flatten)]
        sign: SignArgs,
        #[command(subcommand)]
        cmd: deploy::DeployCmd,
    },
    /// Make admin key files (the CLI keeps none)
    #[command(subcommand)]
    Key(KeyCmd),
    /// The tenant's telemetry, verified: gaps, cut-off streams, receipts with no entry
    Telemetry {
        #[command(flatten)]
        keys: KeyFiles,
        #[command(flatten)]
        args: TelemetryArgs,
    },
    /// Co-sign enclave releases (tenants whose root requires it)
    Release {
        /// Co-sign with this admin key file; repeat for the root's threshold
        #[arg(long = "key-file", value_name = "FILE", global = true, help_heading = "Signing")]
        key_files: Vec<PathBuf>,
        /// Sign without asking
        #[arg(long, short = 'y', global = true, help_heading = "Signing")]
        yes: bool,
        #[command(subcommand)]
        cmd: settings::ReleaseCmd,
    },
    /// Shell completions: `seal completion zsh > ~/.zfunc/_seal`
    Completion {
        /// bash, zsh, fish, elvish or powershell
        shell: clap_complete::Shell,
    },
    /// Development logs and registrars
    #[command(subcommand, hide = true)]
    Dev(settings::DevCmd),
}

#[derive(Args, Debug)]
struct SecretArgs {
    /// Where the secret may be used (https://, postgres://, rediss://, clickhouse://)
    #[arg(long, value_name = "URL")]
    to: String,
    /// An app that may use it; repeat, or separate with commas
    #[arg(long = "app", value_name = "NAME", value_delimiter = ',', required = true)]
    apps: Vec<String>,
    /// Append the seal's telemetry receipt to this file (JSON lines, read by `seal telemetry --receipts`)
    #[arg(long, value_name = "FILE")]
    receipt_file: Option<PathBuf>,
    /// `<tenant>@<root id>` as `seal status` prints it, or `<tenant>` for any root chain of
    /// that name (default: the `seal use` tenant)
    #[arg(long, value_name = "TENANT[@ROOT]", env = "SEAL_TENANT", value_parser = parse_tenant_pin, help_heading = "Enclave")]
    tenant: Option<(TenantId, Option<TenantRootId>)>,
    /// An enclave replica of the tenant, as `seal deploy` prints it; repeat, or separate with
    /// commas (default: the replicas Seal runs for the tenant)
    #[arg(
        long = "endpoint",
        value_name = "URL",
        env = "SEAL_ENDPOINT",
        value_delimiter = ',',
        help_heading = "Enclave"
    )]
    endpoints: Vec<url::Url>,
    /// The header that carries the secret (default authorization)
    #[arg(long, help_heading = "HTTP")]
    header: Option<String>,
    /// The header value, with {key} where the secret goes
    #[arg(long, help_heading = "HTTP")]
    format: Option<String>,
    /// Allowed methods (default any)
    #[arg(long, value_name = "M,..", value_delimiter = ',', help_heading = "HTTP")]
    methods: Vec<String>,
    /// Refuse paths under this prefix (e.g. an API's key-management paths)
    #[arg(long = "deny", value_name = "PATH", help_heading = "HTTP")]
    deny: Vec<String>,
    /// The blob stops working at this time (RFC 3339, YYYY-MM-DD in UTC, or Unix seconds)
    #[arg(long, value_name = "DATE", value_parser = parse_time, help_heading = "Limits")]
    expires: Option<UnixTime>,
    /// Require this upstream key in the certificate chain; up to 4
    #[arg(long = "pin", value_name = "sha256/B64", help_heading = "Limits")]
    pins: Vec<String>,
    /// Only enclaves on the sealed platform tier may open the blob
    #[arg(long, help_heading = "Limits")]
    sealed_only: bool,
    /// Only hardened sessions may use the blob: the SDK's channel plus verified endpoint
    /// evidence at every start and extend
    #[arg(long, help_heading = "Limits")]
    hardened_only: bool,
}

#[derive(Subcommand, Debug)]
enum KeyCmd {
    /// A new Ed25519 admin key; its public key goes to stderr
    Create {
        /// Write the private key to FILE (mode 0600, never overwritten); without it, the key
        /// goes to stdout, which must not be a terminal
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
    },
    /// The public key of a key file
    Public {
        /// The key file
        file: PathBuf,
    },
}

#[derive(Args, Debug)]
struct TelemetryArgs {
    /// Entries at or after (RFC 3339, YYYY-MM-DD, Unix seconds, or a duration ago such as 2h)
    #[arg(long, value_name = "TIME", value_parser = parse_since)]
    since: Option<UnixTime>,
    /// `SignedServiceKeyCertificate`s (JSON, one or an array) whose telemetry keys verify
    /// batches, instead of the ones the control plane serves
    #[arg(long, value_name = "FILE")]
    certificates: Option<PathBuf>,
    /// Receipts kept by clients (JSON lines, as `seal secret --receipt-file` writes them);
    /// reported when no batch holds them
    #[arg(long, value_name = "FILE")]
    receipts: Option<PathBuf>,
    /// A telemetry reader key file, to decrypt sealed batches
    #[arg(long, value_name = "FILE")]
    reader_key: Option<PathBuf>,
    /// One JSON object per entry, then one per finding
    #[arg(long)]
    json: bool,
}

/// `<tenant>` or `<tenant>@<root id>`, as `SEAL_TENANT` takes it.
fn parse_tenant_pin(s: &str) -> Result<(TenantId, Option<TenantRootId>), String> {
    seal_proto::TenantPin::parse_partial(s).map_err(|e| e.to_string())
}

/// RFC 3339, `YYYY-MM-DD` (midnight UTC) or Unix seconds.
fn parse_time(s: &str) -> Result<UnixTime, String> {
    if let Ok(secs) = s.parse::<u64>() {
        return Ok(secs);
    }
    let ts = match s.parse::<jiff::Timestamp>() {
        Ok(ts) => ts,
        Err(_) => s
            .parse::<jiff::civil::Date>()
            .and_then(|d| d.to_zoned(jiff::tz::TimeZone::UTC))
            .map(|z| z.timestamp())
            .map_err(|_| format!("{s}: expected RFC 3339 (2026-12-31T00:00:00Z), YYYY-MM-DD or Unix seconds"))?,
    };
    u64::try_from(ts.as_second()).map_err(|_| format!("{s}: before 1970"))
}

/// Whole seconds, or a duration such as `90s`, `30m`, `1h` or `1d`.
fn parse_duration(s: &str) -> Result<u64, String> {
    if let Ok(secs) = s.parse::<u64>() {
        return Ok(secs);
    }
    let span: jiff::Span = s.parse().map_err(|_| format!("{s}: expected seconds or a duration such as 1h"))?;
    let duration = span.to_duration(jiff::SpanRelativeTo::days_are_24_hours()).map_err(|e| format!("{s}: {e}"))?;
    u64::try_from(duration.as_secs()).map_err(|_| format!("{s}: a negative duration"))
}

/// As `parse_time`, or a duration before now (`2h`, `30m`, `1d`).
fn parse_since(s: &str) -> Result<UnixTime, String> {
    if let Ok(t) = parse_time(s) {
        return Ok(t);
    }
    let span: jiff::Span = s.parse().map_err(|_| format!("{s}: expected a time or a duration such as 2h"))?;
    let ago = span.to_duration(jiff::SpanRelativeTo::days_are_24_hours()).map_err(|e| format!("{s}: {e}"))?;
    let secs = u64::try_from(ago.as_secs()).map_err(|_| format!("{s}: a duration before now"))?;
    Ok(now().saturating_sub(secs))
}

fn now() -> UnixTime {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn time() -> TrustedTime {
    TrustedTime::exact(now())
}

/// What a control-plane request is for: the console grants `read` or `submit` control tokens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    Read,
    Submit,
}

/// The control plane, for error hints.
static CONTROL_URL: OnceLock<String> = OnceLock::new();

/// Everything a command needs from the flags and the configuration.
pub struct Env {
    home: Home,
    config: Config,
    global: Global,
    sign: SignArgs,
    token: tokio::sync::OnceCell<Option<String>>,
}

fn url_of(flag: &Option<url::Url>, saved: &Option<String>, default: &str) -> anyhow::Result<url::Url> {
    match (flag, saved) {
        (Some(url), _) => Ok(url.clone()),
        (None, Some(saved)) => url::Url::parse(saved).with_context(|| format!("{saved} in the configuration")),
        (None, None) => Ok(url::Url::parse(default).expect("a valid default URL")),
    }
}

impl Env {
    fn https(&self) -> anyhow::Result<Arc<HttpsClient>> {
        #[cfg(feature = "sim")]
        if let Some(path) = self.config.sim.as_ref().and_then(|s| s.extra_roots.as_ref()) {
            let pem = std::fs::read(path).with_context(|| format!("{}", path.display()))?;
            return Ok(seal::admin::https_with_extra_roots(&pem)?);
        }
        Ok(seal::admin::https())
    }

    fn console_url(&self) -> anyhow::Result<url::Url> {
        url_of(&self.global.console_url, &self.config.console_url, config::DEFAULT_CONSOLE_URL)
    }
    fn control_url(&self) -> anyhow::Result<url::Url> {
        url_of(&self.global.control_url, &self.config.control_url, config::DEFAULT_CONTROL_URL)
    }
    fn log_url(&self) -> anyhow::Result<url::Url> {
        url_of(&self.global.log_url, &self.config.log_url, config::DEFAULT_LOG_URL)
    }

    /// Keeps the URLs the flags named in the configuration, so later commands need none.
    fn remember_urls(&mut self) {
        let keep = |flag: &Option<url::Url>, saved: &mut Option<String>| {
            if let Some(url) = flag {
                *saved = Some(url.to_string());
            }
        };
        keep(&self.global.console_url, &mut self.config.console_url);
        keep(&self.global.control_url, &mut self.config.control_url);
        keep(&self.global.log_url, &mut self.config.log_url);
    }

    /// The console, with the stored login (or `SEAL_CONSOLE_TOKEN`).
    async fn console(&self) -> anyhow::Result<Console> {
        let url = self.console_url()?;
        let origin = console::origin(&url);
        let token = self
            .token
            .get_or_try_init(|| async {
                match std::env::var("SEAL_CONSOLE_TOKEN").ok().filter(|t| !t.is_empty()) {
                    Some(token) => anyhow::Ok(Some(token)),
                    None => console::load_token(&origin, &self.home.0).await,
                }
            })
            .await?
            .clone();
        Ok(Console::new(&url, self.https()?, token))
    }

    fn trust(&self) -> anyhow::Result<Trusted> {
        if let Some(path) = &self.global.trust {
            return config::read_trust(path);
        }
        match seal::built_in_trust() {
            Some(trust) => Ok(trust?.into()),
            None => bail!("this build has no built-in trust: pass --trust FILE (or SEAL_TRUST)"),
        }
    }

    fn tenant(&self) -> anyhow::Result<TenantId> {
        self.config.tenant.clone().ok_or_else(|| anyhow!("no tenant selected: run `seal use <tenant>`"))
    }

    /// The `--key-file` keys, with their paths.
    fn keys(&self) -> anyhow::Result<Vec<(PathBuf, SigningKey)>> {
        self.sign.keys.key_files.iter().map(|p| Ok((p.clone(), config::read_key(p)?))).collect()
    }

    /// The admin workflow for `tenant`, its requests authorized by `credential` (or the write
    /// token alone).
    fn admin_with(
        &self,
        tenant: &TenantId,
        root_id: Option<TenantRootId>,
        credential: Option<Arc<dyn Credential>>,
    ) -> anyhow::Result<Admin> {
        let https = self.https()?;
        let control_url = self.control_url()?;
        let _ = CONTROL_URL.set(control_url.to_string());
        let mut control = ControlClient::new(control_url, https.clone(), self.global.control_token.clone());
        if let Some(credential) = credential {
            control = control.with_credential(credential);
        }
        let trust = self.trust()?;
        let log = LogClient::with_https(self.log_url()?, https);
        Ok(Admin::new(tenant.clone(), root_id, trust.tenants, control, log)
            .with_anchor_keys(trust.guardians.values().copied().collect()))
    }

    /// Before the tenant exists: the write token only (`seal dev init`).
    fn admin_for(&self, tenant: &TenantId, root_id: Option<TenantRootId>) -> anyhow::Result<Admin> {
        self.admin_with(tenant, root_id, None)
    }

    /// The selected tenant's workflow, its requests signed with `key`.
    fn admin_signed_by(&self, key: SigningKey) -> anyhow::Result<Admin> {
        let tenant = self.tenant()?;
        let root_id = self.config.root_id.ok_or_else(|| anyhow!("no root id: run `seal use <tenant>`"))?;
        self.admin_with(&tenant, Some(root_id), Some(Arc::new(SigningKeyCredential::new(key, root_id))))
    }

    /// The selected tenant's workflow: requests signed by the first `--key-file` key, else
    /// authorized by console control tokens of `scope`.
    async fn admin(&self, scope: Scope) -> anyhow::Result<Admin> {
        let tenant = self.tenant()?;
        if let Some((_, key)) = self.keys()?.into_iter().next() {
            return self.admin_signed_by(key);
        }
        let console = self.console().await?;
        if !console.signed_in() {
            bail!("not logged in: run `seal login` (or sign with --key-file FILE)");
        }
        let scope = match scope {
            Scope::Read => "read",
            Scope::Submit => "submit",
        };
        let credential = ConsoleCredential::new(console, tenant.clone(), scope);
        self.admin_with(&tenant, self.config.root_id, Some(Arc::new(credential)))
    }

    fn console_link(&self, path: &str, id: Option<&str>) -> String {
        let origin = self.console_url().map(|u| console::origin(&u)).unwrap_or_default();
        let mut query = Vec::new();
        if let Some(w) = &self.config.workspace {
            query.push(format!("w={w}"));
        }
        if let Some(t) = &self.config.tenant {
            query.push(format!("t={t}"));
        }
        if let Some(id) = id {
            query.push(format!("id={id}"));
        }
        format!("{origin}{path}?{}", query.join("&"))
    }

    /// The console page where admins sign proposal `id`.
    fn change_url(&self, id: &str) -> String {
        self.console_link("/tenant/change", Some(id))
    }

    /// The tenant's console page.
    fn tenant_url(&self) -> String {
        self.console_link("/tenant", None)
    }

    fn save(&self) -> anyhow::Result<()> {
        self.home.save(&self.config)
    }
}

/// An edit of the next state, as `Admin::draft` takes it.
type Edit = Box<dyn FnOnce(&mut TenantState) -> Result<(), seal::ClientError>>;

fn invalid(message: impl Into<String>) -> seal::ClientError {
    seal::ClientError::Invalid(message.into())
}

/// The secret: from the terminal without echo, or all of stdin minus one trailing newline.
fn read_secret() -> anyhow::Result<SecretBytes> {
    let mut bytes = if std::io::stdin().is_terminal() {
        rpassword::prompt_password("Secret: ").context("reading the secret")?.into_bytes()
    } else {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf).context("reading the secret from stdin")?;
        buf
    };
    if bytes.ends_with(b"\n") {
        bytes.pop();
        if bytes.ends_with(b"\r") {
            bytes.pop();
        }
    }
    let secret = SecretBytes::new(bytes);
    if secret.expose().is_empty() {
        bail!("empty secret");
    }
    Ok(secret)
}

async fn seal_secret(env: &Env, args: SecretArgs) -> anyhow::Result<()> {
    ui::reserve_stdout();
    // A named tenant keeps the root `seal use` verified when it is the same one.
    let (tenant, root_id) = match args.tenant {
        Some((tenant, root_id)) => {
            let saved = env.config.root_id.filter(|_| env.config.tenant.as_ref() == Some(&tenant));
            (tenant, root_id.or(saved))
        }
        None => match &env.config.tenant {
            Some(tenant) => (tenant.clone(), env.config.root_id),
            None => bail!("name the tenant: --tenant <tenant>@<root id> (its admins' `seal status` prints it), or `seal use <tenant>`"),
        },
    };
    // No endpoint named: the replicas Seal runs for the tenant, as the console lists them.
    let endpoints = if args.endpoints.is_empty() {
        let console = env.console().await?;
        if !console.signed_in() {
            bail!(
                "name an enclave replica of the tenant: --endpoint https://HOST:PORT (or SEAL_ENDPOINT), or `seal login` to use the replicas Seal runs for it"
            );
        }
        let endpoints = console.tenant(&tenant).await?.serving_endpoints()?;
        if endpoints.is_empty() {
            bail!(
                "Seal runs no enclave for {tenant}: enable one in the console (Deployments), or name your own with --endpoint (`seal deploy` prints it)"
            );
        }
        endpoints
    } else {
        args.endpoints
    };
    let mut builder = seal::Client::builder().endpoints(endpoints).tenant(tenant.clone());
    if let Some(root_id) = root_id {
        builder = builder.root_id(root_id);
    }
    if env.global.trust.is_some() {
        if let Some(trust) = env.trust()?.full {
            builder = builder.trust(trust);
        }
    }
    // Verify the enclave before asking for the secret, so a wrong endpoint or tenant fails first.
    let client = {
        let _spinner = ui::Spinner::start("verifying the enclave");
        builder.connect().await?
    };
    let secret = read_secret()?;
    let mut seal = client.seal(secret.expose(), &args.to, &args.apps);
    if let Some(header) = &args.header {
        seal = seal.header(header);
    }
    if let Some(format) = &args.format {
        seal = seal.format(format);
    }
    for pin in &args.pins {
        seal = seal.pin(pin);
    }
    if let Some(at) = args.expires {
        seal = seal.expires(at);
    }
    if !args.methods.is_empty() {
        seal = seal.methods(&args.methods);
    }
    for path in &args.deny {
        seal = seal.deny(path);
    }
    if args.sealed_only {
        seal = seal.sealed_only();
    }
    if args.hardened_only {
        seal = seal.hardened_only();
    }
    let (blob, receipt) = seal.with_receipt().await?;
    if let Some(path) = &args.receipt_file {
        seal::receipts::append(path, &[receipt]).with_context(|| format!("{}", path.display()))?;
    }
    println!("{blob}");
    Ok(())
}

fn key(cmd: KeyCmd) -> anyhow::Result<()> {
    match cmd {
        KeyCmd::Create { out } => {
            let key = match &out {
                Some(path) => config::create_key(path)?,
                None if std::io::stdout().is_terminal() => {
                    bail!("pass --out FILE: a private key is never printed to a terminal (or redirect stdout)")
                }
                None => {
                    use std::io::Write as _;
                    let key = config::generate_key();
                    std::io::stdout().write_all(config::seed_text(&key.to_seed()).expose())?;
                    key
                }
            };
            if let Some(path) = &out {
                eprintln!("{}", ui::ok(&format!("new admin key in {} (mode 0600)", path.display())));
            }
            eprintln!("public key {}", key.public_key());
            eprintln!("key id {}", key.key_id());
            eprintln!(
                "{}",
                ui::dim(&format!(
                    "make it an admin key with `seal settings admins add {}`, or on the console's Admins page",
                    key.public_key()
                ))
            );
            Ok(())
        }
        KeyCmd::Public { file } => {
            println!("{}", config::read_key(&file)?.public_key());
            Ok(())
        }
    }
}

/// A JSON file of `T`s: one, an array, or a sequence of them (JSON lines), arrays in it flattened.
fn read_json_list<T: serde::de::DeserializeOwned>(path: &Path) -> anyhow::Result<Vec<T>> {
    let text = std::fs::read(path).with_context(|| format!("{}", path.display()))?;
    parse_json_list(&text).with_context(|| format!("{}", path.display()))
}

fn parse_json_list<T: serde::de::DeserializeOwned>(text: &[u8]) -> anyhow::Result<Vec<T>> {
    let mut items = Vec::new();
    for value in serde_json::Deserializer::from_slice(text).into_iter::<serde_json::Value>() {
        match value? {
            serde_json::Value::Array(more) => items.extend(more),
            one => items.push(one),
        }
    }
    Ok(items.into_iter().map(serde_json::from_value).collect::<Result<_, _>>()?)
}

async fn show_telemetry(env: &Env, args: TelemetryArgs) -> anyhow::Result<()> {
    let tenant = env.tenant()?;
    let root_id = env.config.root_id.ok_or_else(|| anyhow!("no root id: run `seal use <tenant>`"))?;
    let reader = args.reader_key.as_deref().map(config::read_reader_key).transpose()?;
    let admin = env.admin(Scope::Read).await?;
    let certificates = match &args.certificates {
        Some(path) => read_json_list(path)?,
        None => {
            admin.control().get_service_key_certificates(&tenant).await.map_err(|e| anyhow!("control plane: {e}"))?
        }
    };
    let (keys, mut findings) = telemetry::certified_keys(&env.trust()?.guardians, &tenant, &root_id, &certificates);
    if keys.is_empty() {
        bail!("no certificate verified under the trust's guardian keys");
    }
    let receipts = match &args.receipts {
        Some(path) => read_json_list(path)?,
        None => Vec::new(),
    };
    let since = args.since.unwrap_or(0);
    let batches = admin.control().get_telemetry(&tenant, since).await.map_err(|e| anyhow!("control plane: {e}"))?;
    let analysis = telemetry::analyze(&tenant, &keys, &batches, since, &receipts, reader.as_ref());
    findings.extend(analysis.findings);
    if args.json {
        for (stream, number, entry) in &analysis.entries {
            println!("{}", serde_json::json!({ "stream": config::hex(stream), "entry": number, "telemetry": entry }));
        }
        for (stream, sequence, count) in &analysis.sealed {
            println!(
                "{}",
                serde_json::json!({ "sealed": { "stream": config::hex(stream), "batch": sequence, "entries": count } })
            );
        }
        for finding in &findings {
            println!("{}", serde_json::json!({ "finding": finding }));
        }
        return Ok(());
    }
    for (stream, number, entry) in &analysis.entries {
        let event = serde_json::to_string(&entry.event).unwrap_or_default();
        say!(
            "{}  {}#{number}  {}  {event}",
            watch::time(entry.at),
            &config::hex(stream)[..8],
            telemetry::who(entry.identity.as_ref())
        );
    }
    for (stream, sequence, count) in &analysis.sealed {
        say!("sealed batch: stream {} batch {sequence}, {count} entries", config::hex(stream));
    }
    if !analysis.sealed.is_empty() && reader.is_none() {
        say!("note: pass --reader-key FILE with a telemetry reader key to decrypt sealed batches");
    }
    for finding in &findings {
        say!("{}", ui::accent(&format!("FOUND: {finding}")));
    }
    Ok(())
}

/// `seal use`: the tenant from the console, verified against the trust and the log, then saved.
async fn use_tenant(env: &mut Env, tenant: Option<TenantId>) -> anyhow::Result<()> {
    let console = env.console().await?;
    if !console.signed_in() {
        bail!("not logged in: run `seal login` first");
    }
    let tenant = match tenant {
        Some(t) => t,
        None => {
            let all = console::tenants(&console, None).await?;
            // Active tenants first; any other status (closed) leads its row, in red.
            let mut choices: Vec<(bool, String, String)> = all
                .iter()
                .flat_map(|(w, ts)| {
                    ts.iter().map(move |t| {
                        let about = format!("{w} · {}", t.plan);
                        if t.status == "active" {
                            (true, t.id.clone(), about)
                        } else {
                            (
                                false,
                                t.id.clone(),
                                format!("{} {}", ui::accent(&t.status), ui::dim(&format!("· {about}"))),
                            )
                        }
                    })
                })
                .collect();
            choices.sort_by_key(|(active, _, _)| !active);
            let choices: Vec<(String, String)> = choices.into_iter().map(|(_, id, about)| (id, about)).collect();
            if choices.is_empty() {
                bail!("your workspaces hold no tenant yet: create one in the console");
            }
            if !ui::interactive() {
                for (id, about) in &choices {
                    println!("{id}  {about}");
                }
                bail!("name the tenant: seal use <tenant>");
            }
            let refs: Vec<(&str, String)> = choices.iter().map(|(id, about)| (id.as_str(), about.clone())).collect();
            ui::pick("Which tenant?", &refs)?.parse()?
        }
    };
    let found = console::find(&console, &tenant).await?;
    let credential = ConsoleCredential::new(console, tenant.clone(), "read");
    let admin = env.admin_with(&tenant, Some(found.pin.root_id), Some(Arc::new(credential)))?;
    let spinner = ui::Spinner::start(&format!("verifying {tenant}"));
    let current = admin.fetch(&time()).await;
    // No bundle yet: a tenant whose first state isn't signed still has a root chain to verify.
    let unsigned = match &current {
        Err(_) => match admin.documents().await {
            Ok(docs) if docs.states.is_empty() => Some(docs),
            _ => None,
        },
        Ok(_) => None,
    };
    drop(spinner);
    let current = match (current, &unsigned) {
        (Ok(current), _) => Some(current),
        (Err(_), Some(_)) => None,
        (Err(e), None) => return Err(e.into()),
    };
    env.config.tenant = Some(tenant.clone());
    env.config.root_id = Some(found.pin.root_id);
    env.config.workspace = Some(found.workspace.clone());
    env.remember_urls();
    env.save()?;
    say!("{}", ui::ok(&format!("using {} (workspace {})", found.pin, found.workspace)));
    match (current, unsigned) {
        (Some(current), _) => {
            let t = &current.tenant;
            say!(
                "  {}",
                ui::dim(&format!(
                    "root version {} and state version {} verified against the trust and the log",
                    t.latest_root().version,
                    t.state().version
                ))
            );
        }
        (None, Some(docs)) => {
            say!(
                "  {}",
                ui::dim(&format!(
                    "root version {} verified against the trust and the log; no state is signed yet",
                    docs.roots.len()
                ))
            );
            say!(
                "  next: finish setup in the console ({}/workspace/new-tenant?w={}&t={tenant})",
                env.console_url()?.as_str().trim_end_matches('/'),
                found.workspace
            );
        }
        (None, None) => unreachable!("handled above"),
    }
    Ok(())
}

/// `seal` alone: the mark and the command groups.
fn overview() {
    if let Some(mark) = ui::mark(&ui::bold("seal")) {
        println!("{mark}\n");
    }
    println!("Use secrets without holding them.\n");
    for (title, names) in SECTIONS {
        let names: Vec<String> = names.iter().map(|n| ui::accent(n)).collect();
        // Padded by the plain title: the bold's escape codes would count toward a `{:<18}`.
        println!("{}{}{}", ui::bold(title), " ".repeat(18usize.saturating_sub(title.len())), names.join(" · "));
    }
    println!("\nStart with `seal login`, then `seal use <tenant>`. `seal --help` lists every command.");
}

async fn dispatch(cli: Cli) -> anyhow::Result<()> {
    let home = Home::locate(cli.global.home.clone())?;
    let config = home.load()?;
    let mut env = Env { home, config, global: cli.global, sign: SignArgs::default(), token: Default::default() };
    let Some(command) = cli.command else {
        overview();
        return Ok(());
    };
    match command {
        Command::Login { no_browser } => {
            let console = env.console().await?;
            console::login(console, &env.home.0, !console::browser_wanted(no_browser)).await?;
            if env.global.console_url.is_some() {
                env.remember_urls();
                env.save()?;
            }
        }
        Command::Logout => console::logout(&env.console().await?, &env.home.0).await?,
        Command::Whoami { json } => {
            let tenant = env.config.tenant.as_ref().map(|t| match env.config.root_id {
                Some(r) => format!("{t}@{r}"),
                None => t.to_string(),
            });
            console::whoami(&env.console().await?, tenant, json).await?;
        }
        Command::Use { tenant } => use_tenant(&mut env, tenant).await?,
        Command::Status { keys, args } => {
            env.sign.keys = keys;
            status::run(&env, args).await?;
        }
        Command::Secret(args) => seal_secret(&env, args).await?,
        Command::Grant { sign, cmd } => {
            env.sign = sign;
            grants::run_grant(&env, cmd).await?;
        }
        Command::Revoke { sign, cmd } => {
            env.sign = sign;
            grants::run_revoke(&env, cmd).await?;
        }
        Command::Changes { sign, args } => {
            env.sign = sign;
            sign::run(&env, args).await?;
        }
        Command::Settings { sign, cmd } => {
            env.sign = sign;
            settings::run(&env, cmd).await?;
        }
        Command::Deploy { sign, cmd } => {
            env.sign = sign;
            deploy::run(&env, cmd).await?;
        }
        Command::Key(cmd) => key(cmd)?,
        Command::Telemetry { keys, args } => {
            env.sign.keys = keys;
            show_telemetry(&env, args).await?;
        }
        Command::Release { key_files, yes, cmd } => {
            env.sign = SignArgs { keys: KeyFiles { key_files }, yes, ..SignArgs::default() };
            settings::release(&env, cmd).await?;
        }
        Command::Completion { shell } => {
            // The untidied tree: completions offer the global options under every command.
            clap_complete::generate(shell, &mut Cli::command(), "seal", &mut std::io::stdout());
        }
        Command::Dev(settings::DevCmd::Init(args)) => settings::init(&mut env, args).await?,
    }
    Ok(())
}

/// The command groups of the help and the overview.
const SECTIONS: [(&str, &[&str]); 3] = [
    ("Everyday", &["login", "logout", "whoami", "use", "status", "secret"]),
    ("Who may do what", &["grant", "revoke", "changes"]),
    ("Tenant settings", &["settings", "deploy", "key", "telemetry", "release", "completion"]),
];

fn styles() -> clap::builder::Styles {
    use anstyle::Style;
    clap::builder::Styles::styled()
        .header(Style::new().bold())
        .usage(Style::new().bold())
        .literal(ui::red().bold())
        .placeholder(Style::new().italic())
        .valid(ui::red())
        .invalid(Style::new().bold())
}

/// Help wraps at the terminal's width, but no wider: long lines are hard to follow.
const MAX_WIDTH: usize = 100;

/// The command tree, its top-level help grouped by `SECTIONS`. The global options are listed
/// there only: every other help ends with their names instead (`tidy`).
fn command() -> clap::Command {
    let mut command = Cli::command();
    let globals: Vec<clap::Arg> = command.get_arguments().filter(|a| a.is_global_set()).cloned().collect();
    let names: Vec<String> =
        globals.iter().filter(|a| !a.is_hide_set()).filter_map(|a| a.get_long()).map(|l| format!("--{l}")).collect();
    let footer = ui::dim(&format!("Global options: {} (`seal --help`)", names.join(", ")));
    for name in command.get_subcommands().map(|s| s.get_name().to_owned()).collect::<Vec<_>>() {
        // A subcommand that already has an argument is not given the global one (clap skips
        // it), so hidden copies keep the globals working without listing them.
        command = command.mut_subcommand(name, |sub| {
            tidy(globals.iter().fold(sub, |sub, a| sub.arg(a.clone().hide(true))), &footer)
        });
    }
    let mut groups = String::new();
    for (title, names) in SECTIONS {
        groups.push_str(&format!("{}\n", ui::bold(&format!("{title}:"))));
        for name in names {
            let about =
                command.find_subcommand(name).and_then(|s| s.get_about()).map(|a| a.to_string()).unwrap_or_default();
            groups.push_str(&format!(
                "  {}{}  {about}\n",
                ui::accent(name),
                " ".repeat(12usize.saturating_sub(name.len()))
            ));
        }
        groups.push('\n');
    }
    let color = if ui::color() { clap::ColorChoice::Auto } else { clap::ColorChoice::Never };
    command
        .max_term_width(MAX_WIDTH)
        .styles(styles())
        .color(color)
        .help_template(format!(
            "{{about-with-newline}}\n{{usage-heading}} {{usage}}\n\n{groups}{}\n{{options}}{{after-help}}",
            ui::bold("Global options:")
        ))
        .after_help("Start with `seal login`, then `seal use <tenant>`.\n`seal COMMAND --help` explains each command.")
}

/// `sub` and the commands under it: the global options' footer, and no `help` subcommand
/// (`--help` does the same).
fn tidy(sub: clap::Command, footer: &str) -> clap::Command {
    let names: Vec<String> = sub.get_subcommands().map(|s| s.get_name().to_owned()).collect();
    let sub = sub.after_help(footer.to_owned()).disable_help_subcommand(true).max_term_width(MAX_WIDTH);
    names.into_iter().fold(sub, |sub, name| sub.mut_subcommand(name, |s| tidy(s, footer)))
}

fn parse(args: Vec<std::ffi::OsString>) -> Cli {
    let no_color = args.iter().any(|a| a == "--no-color");
    ui::init(no_color);
    let matches = command().get_matches_from(args);
    Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit())
}

/// The next step for errors that have an obvious one.
fn hint(e: &anyhow::Error) -> Option<String> {
    let control = CONTROL_URL.get().map_or("the configured URL", String::as_str);
    match e.downcast_ref::<seal::ClientError>()? {
        seal::ClientError::Network(m) if m.starts_with("control plane") => {
            Some(format!("the control plane is unreachable at {control}: check --control-url or your network"))
        }
        seal::ClientError::Network(_) => {
            Some("a network request failed: check the URLs (`seal --help`) or your network".into())
        }
        seal::ClientError::Seal { code: seal::ErrorCode::NotAllowed, message }
            if message.starts_with("control plane") =>
        {
            Some("the control plane refused the credential: run `seal login`, or pass an admin --key-file".into())
        }
        _ => None,
    }
}

/// The `seal` command run on `args` (the program name first), as the `seal` binary and
/// `pip install sealzone`'s `seal` script do. Returns the exit status; usage errors and
/// `--help` exit the process themselves, as clap does.
pub fn run<I, T>(args: I) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString>,
{
    let cli = parse(args.into_iter().map(Into::into).collect());
    let filter = tracing_subscriber::EnvFilter::try_from_env("SEAL_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    // A second run in one process (a Python caller) keeps the first subscriber.
    let _ = tracing_subscriber::fmt().with_env_filter(filter).with_writer(std::io::stderr).try_init();
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("seal: {e}");
            return 1;
        }
    };
    let Err(e) = runtime.block_on(dispatch(cli)) else { return 0 };
    if let Some(Exit(code)) = e.downcast_ref::<Exit>() {
        return *code;
    }
    eprintln!("{} {e:#}", ui::accent("seal:"));
    if let Some(hint) = hint(&e) {
        eprintln!("{}", ui::dim(&format!("  {hint}")));
    }
    1
}

/// An exit status a command chose, with nothing more to report on stderr.
#[derive(Debug)]
pub struct Exit(pub i32);

impl std::fmt::Display for Exit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "exit status {}", self.0)
    }
}

impl std::error::Error for Exit {}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        let matches = command().try_get_matches_from(std::iter::once("seal").chain(args.iter().copied()))?;
        Cli::from_arg_matches(&matches)
    }

    #[test]
    fn the_command_tree_is_consistent() {
        command().debug_assert();
    }

    #[test]
    fn every_section_names_a_command_and_every_command_is_in_a_section() {
        let command = command();
        let listed: Vec<&str> = SECTIONS.iter().flat_map(|(_, names)| names.iter().copied()).collect();
        for name in &listed {
            assert!(command.find_subcommand(name).is_some(), "{name}");
        }
        for sub in command.get_subcommands().filter(|s| !s.is_hide_set() && s.get_name() != "help") {
            assert!(listed.contains(&sub.get_name()), "{} is in no section", sub.get_name());
        }
    }

    #[test]
    fn global_options_work_everywhere_and_are_listed_once() {
        let cli =
            parse(&["grant", "app", "checkout", "key", "--generate", "--trust", "t.json", "--home", "h"]).unwrap();
        assert_eq!((cli.global.trust.unwrap(), cli.global.home.unwrap()), ("t.json".into(), "h".into()));
        let help = command().find_subcommand_mut("grant").unwrap().render_help().to_string();
        assert!(!help.contains("SEAL_TRUST") && help.contains("Global options: --home,"), "{help}");
        assert!(command().render_help().to_string().contains("SEAL_TRUST"));
    }

    #[test]
    fn every_argument_has_help() {
        fn check(command: &clap::Command, path: &str) {
            for arg in command.get_arguments() {
                let id = arg.get_id().as_str();
                if id != "help" && id != "version" && !arg.is_hide_set() {
                    assert!(arg.get_help().is_some(), "{path} {id} has no help");
                }
            }
            for sub in command.get_subcommands() {
                assert!(
                    sub.get_about().is_some() || sub.get_name() == "help",
                    "{path} {} has no about",
                    sub.get_name()
                );
                check(sub, &format!("{path} {}", sub.get_name()));
            }
        }
        check(&command(), "seal");
    }

    #[test]
    fn the_console_quotes_these_commands() {
        let key = "11".repeat(32);
        for args in [
            &["key", "create", "--out", "admin.key"][..],
            &["key", "create", "--out", "freshness.key"],
            &["key", "public", "admin.key"],
            &["grant", "app", "checkout", "key", "--generate", "--out", "checkout.key"],
            &["secret", "--to", "https://api.openai.com/v1", "--app", "checkout", "--header", "authorization"],
            &["settings", "telemetry-readers", "add", "--generate", "reader.key"],
            &["settings", "freshness", "sign"],
            &["changes", "sign", "abcdef", "--key-file", "admin.key"],
            &["changes", "--watch"],
            &["telemetry"],
            &["status", "--log"],
            &["settings", "admins", "add", &key],
        ] {
            parse(args).unwrap_or_else(|e| panic!("{args:?}: {e}"));
        }
    }

    #[test]
    fn secrets_take_every_seal_option() {
        let cli = parse(&[
            "secret",
            "--to",
            "https://api.example.com/v1",
            "--app",
            "a,b",
            "--app",
            "c",
            "--header",
            "x-api-key",
            "--pin",
            "sha256/AAAA",
            "--pin",
            "sha256/BBBB",
            "--methods",
            "GET,POST",
            "--deny",
            "/v1/keys",
            "--sealed-only",
            "--hardened-only",
            "--expires",
            "2030-01-01",
        ])
        .unwrap();
        let Some(Command::Secret(s)) = cli.command else { panic!() };
        assert_eq!(s.apps, ["a", "b", "c"]);
        assert_eq!(s.pins.len(), 2);
        assert_eq!(s.methods, ["GET", "POST"]);
        assert_eq!(s.expires, Some(1_893_456_000));
        assert!(s.sealed_only && s.hardened_only);
        assert!(s.tenant.is_none() && s.endpoints.is_empty(), "both default to `seal use` and SEAL_ENDPOINT");

        let root = "ab".repeat(32);
        let pin = format!("acme@{root}");
        let cli = parse(&[
            "secret",
            "--to",
            "https://x",
            "--app",
            "a",
            "--tenant",
            &pin,
            "--endpoint",
            "https://10.0.1.4:8443,https://10.0.1.5:8443",
        ])
        .unwrap();
        let Some(Command::Secret(s)) = cli.command else { panic!() };
        let (tenant, root_id) = s.tenant.unwrap();
        assert_eq!((tenant.as_str(), root_id.map(|r| r.to_string())), ("acme", Some(root)));
        assert_eq!(s.endpoints.len(), 2);
        assert!(
            parse(&["secret", "--to", "https://x", "--app", "a", "--tenant", "Acme"]).is_err(),
            "tenant ids are checked"
        );
        assert!(parse(&["secret", "--app", "a"]).is_err(), "--to is required");
        assert!(parse(&["secret", "--to", "https://x"]).is_err(), "--app is required");
    }

    #[test]
    fn signing_options_go_anywhere_in_their_group() {
        let cli =
            parse(&["grant", "--key-file", "a.key", "app", "checkout", "key", "--public", &"11".repeat(32), "--yes"])
                .unwrap();
        let Some(Command::Grant { sign, .. }) = cli.command else { panic!() };
        assert!(sign.yes && sign.keys.key_files.len() == 1);
        assert!(parse(&["--home", "h", "settings", "platforms", "add", "azure", "--key-file", "a", "--key-file", "b"])
            .is_ok());
        assert!(parse(&["key", "create", "--yes"]).is_err(), "key commands sign nothing");
        assert!(parse(&["settings", "platforms", "add", "mars"]).is_err());
    }

    #[test]
    fn settings_parse() {
        let digest = "ab".repeat(32);
        let key = "22".repeat(32);
        for args in [
            &["settings", "admins"][..],
            &["settings", "admins", "--json"],
            &["settings", "admins", "rm", &key, "--threshold", "1"],
            &["settings", "admins", "threshold", "2"],
            &["settings", "window"],
            &["settings", "window", "24h"],
            &["settings", "platforms", "rm", "gcp"],
            &["settings", "integrity", "allow", "checkout", &format!("image={digest}")],
            &["settings", "integrity", "on", "high", "suspend=600"],
            &["settings", "integrity", "source", "add", "edr", "--public-key", &key],
            &["settings", "integrity", "clear", "{}"],
            &["settings", "telemetry-readers", "add", &key],
            &["settings", "telemetry-readers", "rm", &key],
            &["settings", "freshness", "key", "add", "--file", "f.key"],
            &["settings", "freshness", "key", "rm", &key],
            &["settings", "tenant-key", "bump", "--retire-older"],
            &["release", "approve", &"cd".repeat(48)],
            &["changes", "--watch", "--once", "--json"],
            &["changes", "show", "abc", "--json"],
            &[
                "dev",
                "init",
                "--tenant",
                "acme",
                "--key-file",
                "a.key",
                "--registrar-key",
                "r.key",
                "--platform",
                "azure",
            ],
            &["deploy", "azure"],
            &["deploy", "azure", "--vnet", "app-vnet", "--dry-run"],
            &["deploy", "azure", "-g", "rg", "--subnet", "app/seal", "--audience", "api://x"],
            &["deploy", "upgrade", "-g", "rg", "--release", &"cd".repeat(48), "--dry-run"],
            &["completion", "zsh"],
        ] {
            parse(args).unwrap_or_else(|e| panic!("{args:?}: {e}"));
        }
        for args in [
            &["settings", "integrity", "allow", "checkout", "image=xyz"][..],
            &["settings", "integrity", "on", "high", "explode"],
            &["settings", "telemetry-readers", "add"],
            &["settings", "telemetry-readers", "add", &key, "--generate", "r.key"],
            &["settings", "freshness", "key", "add"],
            &["release", "approve", "cd"],
            &["changes", "--once"],
            &["dev", "init", "--tenant", "Not Valid", "--key-file", "a", "--registrar-key", "r"],
            &["deploy", "azure", "--vnet"],
            &["deploy", "azure", "--vnet", "app-vnet", "--create-audience"],
        ] {
            assert!(parse(args).is_err(), "{args:?}");
        }
    }

    #[test]
    fn json_lists() {
        let parse = |text: &str| parse_json_list::<u32>(text.as_bytes()).unwrap();
        assert_eq!(parse("7"), [7]);
        assert_eq!(parse("[1, 2]"), [1, 2]);
        assert_eq!(parse("1\n2\n[3]\n"), [1, 2, 3]);
        assert!(parse("").is_empty());
        assert!(parse_json_list::<u32>(b"1\n{").is_err());
        assert!(parse_json_list::<u32>(b"\"x\"").is_err());
    }

    #[test]
    fn times_parse() {
        assert_eq!(parse_time("0").unwrap(), 0);
        assert_eq!(parse_time("2026-10-26").unwrap(), 1_792_972_800);
        assert_eq!(parse_time("2026-10-26T00:00:00+02:00").unwrap(), 1_792_965_600);
        assert!(parse_time("tomorrow").is_err());
        let ago = parse_since("1h").unwrap();
        assert!(now() - ago >= 3600 && now() - ago < 3700);
    }
}
