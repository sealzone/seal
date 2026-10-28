//! The console: signing in (`seal login`, a device code approved in the browser), the account
//! (`seal whoami`, `seal logout`), picking a tenant (`seal use`), and control tokens.
//!
//! ```text
//! POST /api/v1/cli/device   {"client"}       → {"device_code", "user_code", "verification_url", "interval", "expires_in"}
//! POST /api/v1/cli/token    {"device_code"}  → 400 authorization_pending | slow_down, 403 access_denied,
//!                                              410 expired_token, 200 {"token", "user": {"email"}, "expires_at"}
//! POST /api/v1/cli/logout                     revokes the token
//! GET  /api/v1/me, /api/v1/workspaces/{w}/tenants, /api/v1/tenants/{t}
//! POST /api/v1/tenants/{t}/control-token {"scope": "read" | "submit"} → {"token", "expires_at", "control_url"}
//! ```
//!
//! The CLI token (`sealcli_…`) is a bearer token for these requests. It lives in the OS
//! keychain (macOS Keychain, the Secret Service on Linux, Windows Credential Manager), service
//! `seal`, account `console:<console origin>`, never in `config.json`; `SEAL_CONSOLE_TOKEN`
//! passes one instead (CI). It reads and proposes as the user and signs nothing: a control
//! token (`sealct_…`, five minutes, one tenant) is what the control plane accepts, and every
//! document still needs its admin signatures.

use std::io::IsTerminal as _;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context as _};
use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use seal::admin::{ControlError, Credential, HttpsClient, Target};
use seal_proto::{TenantId, TenantPin};

/// The keychain service CLI tokens are stored under.
const KEYCHAIN_SERVICE: &str = "seal";
/// A control token is fetched again this long before it expires.
const RENEW_SECS: u64 = 30;

/// The console's API for one origin, with the CLI token when there is one.
#[derive(Clone)]
pub struct Console {
    /// `scheme://host[:port]`, no trailing slash.
    origin: String,
    https: Arc<HttpsClient>,
    token: Option<String>,
}

#[derive(Deserialize)]
pub struct DeviceCode {
    pub device_code: String,
    pub user_code: String,
    pub verification_url: String,
    pub interval: u64,
    pub expires_in: u64,
}

#[derive(Deserialize)]
struct Issued {
    token: String,
    user: User,
}

#[derive(Deserialize)]
pub struct User {
    pub email: String,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Deserialize)]
pub struct Me {
    pub user: User,
    #[serde(default)]
    pub workspaces: Vec<WorkspaceRole>,
}

#[derive(Deserialize)]
pub struct WorkspaceRole {
    pub slug: String,
    pub name: String,
    pub role: String,
}

#[derive(Deserialize)]
pub struct TenantSummary {
    pub id: String,
    pub plan: String,
    pub status: String,
}

#[derive(Deserialize)]
pub struct TenantDetail {
    pub seal_tenant: String,
    /// The workspace's slug.
    #[serde(default)]
    pub workspace: Option<String>,
}

#[derive(Serialize)]
struct ScopeRequest<'a> {
    scope: &'a str,
}

#[derive(Deserialize)]
struct ControlToken {
    token: String,
    expires_at: u64,
}

/// The console's error body, `{"code", "message"}`, or an OAuth-style `{"error"}`.
#[derive(Deserialize, Default)]
struct ApiError {
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

/// `url`'s `scheme://host[:port]`.
pub fn origin(url: &url::Url) -> String {
    url.origin().ascii_serialization()
}

impl Console {
    pub fn new(url: &url::Url, https: Arc<HttpsClient>, token: Option<String>) -> Self {
        Self { origin: origin(url), https, token }
    }

    pub fn origin(&self) -> &str {
        &self.origin
    }

    pub fn signed_in(&self) -> bool {
        self.token.is_some()
    }

    async fn exchange(&self, post: Option<&[u8]>, path: &str) -> anyhow::Result<(u16, Vec<u8>)> {
        let url = format!("{}/api/v1{path}", self.origin);
        let bearer = self.token.as_ref().map(|t| format!("Bearer {t}"));
        let mut headers = vec![("accept", "application/json")];
        if let Some(bearer) = &bearer {
            headers.push(("authorization", bearer.as_str()));
        }
        let response = match post {
            Some(body) => self.https.post(&url, &headers, body).await,
            None => self.https.get(&url, &headers).await,
        };
        response.map_err(|e| anyhow!("console {}: {e}", self.origin))
    }

    /// The JSON answer of a request that must succeed.
    async fn call<T: DeserializeOwned>(&self, post: Option<&[u8]>, path: &str) -> anyhow::Result<T> {
        if self.token.is_none() {
            bail!("not signed in to {}: run `seal login`", self.origin);
        }
        let (status, body) = self.exchange(post, path).await?;
        if status == 401 {
            bail!("the console no longer accepts this login (expired or revoked): run `seal login`");
        }
        if !(200..300).contains(&status) {
            let error: ApiError = serde_json::from_slice(&body).unwrap_or_default();
            let message = error.message.or(error.error).unwrap_or_else(|| format!("answered {status}"));
            bail!("console: {message}");
        }
        serde_json::from_slice(&body).with_context(|| format!("console {path}: unexpected answer"))
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> anyhow::Result<T> {
        self.call(None, path).await
    }

    async fn post<B: Serialize, T: DeserializeOwned>(&self, path: &str, body: &B) -> anyhow::Result<T> {
        self.call(Some(&serde_json::to_vec(body)?), path).await
    }

    pub async fn me(&self) -> anyhow::Result<Me> {
        self.get("/me").await
    }

    pub async fn tenants(&self, workspace: &str) -> anyhow::Result<Vec<TenantSummary>> {
        self.get(&format!("/workspaces/{workspace}/tenants")).await
    }

    pub async fn tenant(&self, tenant: &TenantId) -> anyhow::Result<TenantDetail> {
        self.get(&format!("/tenants/{tenant}")).await
    }

    /// A control token for `tenant`: `read`, or `submit` (proposing and submitting).
    async fn control_token(&self, tenant: &TenantId, scope: &str) -> anyhow::Result<ControlToken> {
        self.post(&format!("/tenants/{tenant}/control-token"), &ScopeRequest { scope }).await
    }

    async fn device(&self, client: &str) -> anyhow::Result<DeviceCode> {
        let body = serde_json::to_vec(&serde_json::json!({ "client": client }))?;
        let (status, body) = self.exchange(Some(&body), "/cli/device").await?;
        if status != 200 {
            let error: ApiError = serde_json::from_slice(&body).unwrap_or_default();
            bail!("console: {}", error.message.or(error.error).unwrap_or_else(|| format!("answered {status}")));
        }
        serde_json::from_slice(&body).context("console /cli/device: unexpected answer")
    }

    async fn poll(&self, device_code: &str) -> anyhow::Result<Poll> {
        let body = serde_json::to_vec(&serde_json::json!({ "device_code": device_code }))?;
        let (status, body) = self.exchange(Some(&body), "/cli/token").await?;
        if status == 200 {
            let issued: Issued = serde_json::from_slice(&body).context("console /cli/token: unexpected answer")?;
            return Ok(Poll::Done(issued.token, issued.user));
        }
        let error: ApiError = serde_json::from_slice(&body).unwrap_or_default();
        Ok(match (status, error.error.as_deref()) {
            (400, Some("authorization_pending")) => Poll::Pending,
            (400, Some("slow_down")) => Poll::SlowDown,
            (403, _) => Poll::Denied,
            (410, _) => Poll::Expired,
            _ => bail!("console: {}", error.message.or(error.error).unwrap_or_else(|| format!("answered {status}"))),
        })
    }
}

enum Poll {
    Pending,
    SlowDown,
    Denied,
    Expired,
    Done(String, User),
}

/// Requests authorized by console control tokens for one tenant, fetched with the CLI token
/// and renewed shortly before each expires.
pub struct ConsoleCredential {
    console: Console,
    tenant: TenantId,
    scope: &'static str,
    cached: tokio::sync::Mutex<Option<(String, u64)>>,
}

impl ConsoleCredential {
    pub fn new(console: Console, tenant: TenantId, scope: &'static str) -> Self {
        Self { console, tenant, scope, cached: tokio::sync::Mutex::new(None) }
    }
}

#[async_trait]
impl Credential for ConsoleCredential {
    async fn authorization(&self, _target: &Target<'_>) -> Result<String, ControlError> {
        let mut cached = self.cached.lock().await;
        let now = crate::now();
        if let Some((token, expires_at)) = cached.as_ref() {
            if now + RENEW_SECS < *expires_at {
                return Ok(format!("Bearer {token}"));
            }
        }
        let issued = self
            .console
            .control_token(&self.tenant, self.scope)
            .await
            .map_err(|e| ControlError::Credential(format!("{e:#}")))?;
        let bearer = format!("Bearer {}", issued.token);
        *cached = Some((issued.token, issued.expires_at));
        Ok(bearer)
    }
}

// ---- the stored token ------------------------------------------------------------------------

fn keychain_account(origin: &str) -> String {
    format!("console:{origin}")
}

/// Sim builds: `SEAL_SIM_TOKEN_FILE` keeps the token in that file instead of the keychain.
#[cfg(feature = "sim")]
fn sim_file() -> Option<std::path::PathBuf> {
    std::env::var_os("SEAL_SIM_TOKEN_FILE").map(Into::into)
}
#[cfg(not(feature = "sim"))]
fn sim_file() -> Option<std::path::PathBuf> {
    None
}

/// Where the CLI token is kept: the OS keychain when the host has one, else a file in
/// `$SEAL_HOME` readable only by its owner (a headless host: servers, containers, SSH). The
/// token reads and proposes as the user and never signs; admin keys are never stored at all.
enum Store {
    Keychain(String),
    File(std::path::PathBuf),
}

fn store(origin: &str, home: &std::path::Path) -> Store {
    if let Some(path) = sim_file() {
        return Store::File(path);
    }
    if keyring::Entry::store_status().is_ok() {
        return Store::Keychain(keychain_account(origin));
    }
    let host: String = origin
        .split("://")
        .last()
        .unwrap_or(origin)
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' })
        .collect();
    Store::File(home.join("logins").join(host))
}

/// The stored CLI token for `origin`, if any.
pub async fn load_token(origin: &str, home: &std::path::Path) -> anyhow::Result<Option<String>> {
    match store(origin, home) {
        Store::File(path) => match std::fs::read_to_string(&path) {
            Ok(text) => Ok(Some(text.trim().to_string()).filter(|t| !t.is_empty())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("{}", path.display())),
        },
        Store::Keychain(account) => {
            let found = tokio::task::spawn_blocking(move || {
                keyring::Entry::new(KEYCHAIN_SERVICE, &account).and_then(|entry| entry.get_password())
            })
            .await?;
            match found {
                Ok(token) => Ok(Some(token)),
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(e) => Err(anyhow!("the OS keychain: {e}")),
            }
        }
    }
}

async fn save_token(origin: &str, home: &std::path::Path, token: &str) -> anyhow::Result<()> {
    match store(origin, home) {
        Store::File(path) => {
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir).with_context(|| format!("{}", dir.display()))?;
            }
            let _ = std::fs::remove_file(&path);
            crate::config::write_private(&path, token.as_bytes())
        }
        Store::Keychain(account) => {
            let token = token.to_string();
            tokio::task::spawn_blocking(move || {
                keyring::Entry::new(KEYCHAIN_SERVICE, &account).and_then(|entry| entry.set_password(&token))
            })
            .await?
            .map_err(|e| anyhow!("the OS keychain could not store the login: {e}"))
        }
    }
}

async fn delete_token(origin: &str, home: &std::path::Path) -> anyhow::Result<()> {
    match store(origin, home) {
        Store::File(path) => match std::fs::remove_file(&path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e).with_context(|| format!("{}", path.display())),
            _ => Ok(()),
        },
        Store::Keychain(account) => {
            match tokio::task::spawn_blocking(move || {
                keyring::Entry::new(KEYCHAIN_SERVICE, &account).and_then(|entry| entry.delete_credential())
            })
            .await?
            {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(e) => Err(anyhow!("the OS keychain: {e}")),
            }
        }
    }
}

// ---- commands ----------------------------------------------------------------------------------

/// "seal 0.1.0 on HOST", what the approval page shows.
fn client_name() -> String {
    let host = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .ok()
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
        .or_else(|| {
            std::process::Command::new("hostname")
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .filter(|h| !h.is_empty())
        })
        .unwrap_or_else(|| "this host".into());
    let host: String = host.chars().filter(|c| !c.is_control()).take(60).collect();
    format!("seal {} on {host}", env!("CARGO_PKG_VERSION"))
}

/// `seal login`: a device code, approved in the browser; the token goes to the keychain.
pub async fn login(console: Console, home: &std::path::Path, no_browser: bool) -> anyhow::Result<()> {
    let anonymous = Console { token: None, ..console };
    // Decided before the console issues anything, so an approval is never wasted.
    if let Store::File(path) = store(anonymous.origin(), home) {
        if sim_file().is_none() {
            eprintln!(
                "{}",
                crate::ui::dim(&format!(
                    "no OS keychain on this host: the login will be kept in {} (readable only by you)",
                    path.display()
                ))
            );
        }
    }
    let code = anonymous.device(&client_name()).await?;
    eprintln!(
        "To sign in, open {} and check that it shows the code {}",
        crate::ui::accent(&code.verification_url),
        crate::ui::bold(&code.user_code)
    );
    if !no_browser {
        crate::ui::open_browser(&code.verification_url);
    }
    let started = std::time::Instant::now();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(code.expires_in.max(1));
    let mut interval = code.interval.max(1);
    loop {
        let spinner = crate::ui::Spinner::start_since("waiting for you to approve the code in the browser", started);
        tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
        drop(spinner);
        if std::time::Instant::now() > deadline {
            bail!("the code expired: run `seal login` again");
        }
        match anonymous.poll(&code.device_code).await {
            Ok(Poll::Pending) => {}
            Ok(Poll::SlowDown) => interval += 5,
            Ok(Poll::Denied) => bail!("the sign-in was denied in the browser"),
            Ok(Poll::Expired) => bail!("the code expired: run `seal login` again"),
            Ok(Poll::Done(token, user)) => {
                save_token(anonymous.origin(), home, &token).await?;
                let done = format!("Signed in as {} {}", crate::ui::bold(&user.email), crate::ui::green("✓"));
                match crate::ui::mark(&done) {
                    Some(mark) => println!("{mark}"),
                    None => println!("signed in to {} as {}", anonymous.origin(), user.email),
                }
                println!("{}", crate::ui::dim("next: `seal use <tenant>`"));
                return Ok(());
            }
            Err(e) => eprintln!("seal: {e:#} (retrying)"),
        }
    }
}

/// `seal logout`: revokes the token on the console and forgets it here.
pub async fn logout(console: &Console, home: &std::path::Path) -> anyhow::Result<()> {
    if !console.signed_in() {
        println!("not signed in to {}", console.origin());
        return Ok(());
    }
    let revoked: anyhow::Result<serde_json::Value> = async {
        let (status, _) = console.exchange(Some(b"{}"), "/cli/logout").await?;
        match status {
            200..=299 | 401 => Ok(serde_json::Value::Null),
            _ => bail!("the console answered {status}"),
        }
    }
    .await;
    delete_token(console.origin(), home).await?;
    match revoked {
        Ok(_) => println!("signed out of {}", console.origin()),
        Err(e) => {
            println!("signed out here; the console did not revoke the token ({e:#}): revoke it on your account page")
        }
    }
    Ok(())
}

/// `seal whoami`.
pub async fn whoami(console: &Console, tenant: Option<String>, json: bool) -> anyhow::Result<()> {
    if !console.signed_in() {
        if json {
            println!("{}", serde_json::json!({ "console": console.origin(), "signed_in": false, "tenant": tenant }));
            return Ok(());
        }
        bail!("not logged in to {}: run `seal login`", console.origin());
    }
    let me = console.me().await?;
    if json {
        let workspaces: Vec<serde_json::Value> = me
            .workspaces
            .iter()
            .map(|w| serde_json::json!({ "slug": w.slug, "name": w.name, "role": w.role }))
            .collect();
        println!(
            "{}",
            serde_json::json!({ "console": console.origin(), "signed_in": true, "email": me.user.email,
                                "name": me.user.name, "workspaces": workspaces, "tenant": tenant })
        );
        return Ok(());
    }
    match &me.user.name {
        Some(name) => println!("{name} <{}> on {}", me.user.email, console.origin()),
        None => println!("{} on {}", me.user.email, console.origin()),
    }
    let rows: Vec<Vec<String>> = me
        .workspaces
        .iter()
        .map(|w| vec![format!("  {}", crate::ui::bold(&w.slug)), w.name.clone(), crate::ui::dim(&w.role)])
        .collect();
    for line in crate::ui::table(&rows) {
        println!("{line}");
    }
    match tenant {
        Some(tenant) => println!("using tenant {tenant}"),
        None => println!("{}", crate::ui::dim("no tenant selected: `seal use <tenant>`")),
    }
    Ok(())
}

/// A tenant the user can reach, and the workspace it is in.
pub struct Found {
    pub workspace: String,
    pub pin: TenantPin,
}

/// Every tenant of the user's workspaces (of `workspace` alone when given), by workspace.
pub async fn tenants(console: &Console, workspace: Option<&str>) -> anyhow::Result<Vec<(String, Vec<TenantSummary>)>> {
    let slugs: Vec<String> = match workspace {
        Some(w) => vec![w.to_string()],
        None => console.me().await?.workspaces.into_iter().map(|w| w.slug).collect(),
    };
    let mut all = Vec::new();
    for slug in slugs {
        let tenants = console.tenants(&slug).await?;
        all.push((slug, tenants));
    }
    Ok(all)
}

/// The tenant `tenant`, with its root id and workspace as the console names them.
pub async fn find(console: &Console, tenant: &TenantId) -> anyhow::Result<Found> {
    let detail = match console.tenant(tenant).await {
        Ok(detail) => detail,
        Err(e) => {
            let known: Vec<String> = match tenants(console, None).await {
                Ok(all) => all.into_iter().flat_map(|(_, ts)| ts.into_iter().map(|t| t.id)).collect(),
                Err(_) => return Err(e),
            };
            if known.is_empty() {
                bail!("no tenant {tenant} in your workspaces, which hold none yet: create one in the console");
            }
            bail!("no tenant {tenant} in your workspaces ({e:#}); yours: {}", known.join(", "));
        }
    };
    let pin: TenantPin =
        detail.seal_tenant.parse().with_context(|| format!("the console's seal_tenant {}", detail.seal_tenant))?;
    if &pin.tenant != tenant {
        bail!("the console named tenant {} for {tenant}", pin.tenant);
    }
    let workspace = match detail.workspace {
        Some(w) => w,
        None => tenants(console, None)
            .await?
            .into_iter()
            .find(|(_, ts)| ts.iter().any(|t| t.id == tenant.as_str()))
            .map(|(w, _)| w)
            .ok_or_else(|| anyhow!("the console names no workspace for {tenant}"))?,
    };
    Ok(Found { workspace, pin })
}

/// Whether to open a browser: asked for, and someone is at a terminal to see it.
pub fn browser_wanted(no_browser: bool) -> bool {
    !no_browser && std::io::stderr().is_terminal()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins_drop_the_path_and_keep_the_port() {
        let url = url::Url::parse("https://console.example.test:8443/some/path/").unwrap();
        assert_eq!(origin(&url), "https://console.example.test:8443");
        assert_eq!(keychain_account(&origin(&url)), "console:https://console.example.test:8443");
    }

    #[test]
    fn the_client_name_is_short_and_printable() {
        let name = client_name();
        assert!(name.starts_with("seal ") && name.contains(" on "), "{name}");
        assert!(name.chars().count() <= 100 && !name.chars().any(char::is_control));
    }
}
