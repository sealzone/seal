//! `seal settings`: the tenant's rarer settings. Each one shows its current value without a
//! subcommand (`--json` for scripts), and changes it through the usual signed change
//! (`sign`): admin keys and threshold (a new root), the pending window, platforms, the
//! integrity policy, telemetry readers, freshness signers and the tenant key version. Also
//! `seal release approve` and the development `seal dev init`.

use std::path::PathBuf;

use anyhow::{anyhow, bail, Context as _};
use clap::{Args, Subcommand};
use serde_json::json;

use seal::admin::{cosign, meets_threshold, Admin, Current, Proposed};
use seal_proto::integrity::{ArtifactHash, Clearance, IntegrityAction, Severity};
use seal_proto::signed::Signed;
use seal_proto::state::{
    AdminKey, MAX_PENDING_WINDOW_SECS, MIN_STATE_FRESHNESS_SECS, STATE_FRESHNESS_SECS, TENANT_ROOT_LABEL,
    TENANT_STATE_LABEL,
};
use seal_proto::{AppName, KeyId, Measurement, PlatformId, PublicKey, TenantId, TenantKeyVersion};

use crate::sign::{confirm, edit_state, follow, root_changes, sign_freshness_if_held};
use crate::{config, invalid, parse_duration, say, time, ui, watch, Env, Scope};

#[derive(Subcommand, Debug)]
pub enum SettingsCmd {
    /// The admin keys that sign the tenant's changes, and how many must sign
    Admins(AdminsArgs),
    /// How long a change that widens access waits in public before it takes effect
    Window {
        /// The new window: seconds, or a duration such as 1h or 24h (shortening it waits the
        /// current window); without it, the window in force
        #[arg(value_parser = parse_duration)]
        duration: Option<u64>,
        /// JSON instead of text
        #[arg(long)]
        json: bool,
    },
    /// The platforms new blobs are wrapped for
    Platforms(PlatformsArgs),
    /// The integrity policy: allowed endpoint artifacts, signal sources and responses
    Integrity(IntegrityArgs),
    /// The X25519 keys telemetry is encrypted to (none: telemetry is kept in the clear)
    TelemetryReaders(ReadersArgs),
    /// Tenant-run freshness signers (none: the log alone vouches for the latest state), and
    /// how long a freshness statement keeps the state usable
    Freshness(FreshnessArgs),
    /// The tenant key version new blobs are sealed under
    TenantKey(TenantKeyArgs),
}

#[derive(Args, Debug)]
#[command(args_conflicts_with_subcommands = true)]
pub struct AdminsArgs {
    #[command(subcommand)]
    cmd: Option<AdminsCmd>,
    /// JSON instead of text
    #[arg(long)]
    json: bool,
}

#[derive(Subcommand, Debug)]
pub enum AdminsCmd {
    /// Add admin keys: Ed25519 public keys (hex) from `seal key create` (passkeys are added in
    /// the console)
    Add {
        /// The public keys to add
        #[arg(required = true, value_name = "PUBLIC KEY")]
        keys: Vec<PublicKey>,
        /// The new threshold, if it changes
        #[arg(long, value_name = "N")]
        threshold: Option<u8>,
    },
    /// Remove admin keys, by public key or key id (hex)
    Rm {
        /// The keys to remove
        #[arg(required = true, value_name = "KEY")]
        keys: Vec<KeyId>,
        /// The new threshold, if it changes
        #[arg(long, value_name = "N")]
        threshold: Option<u8>,
    },
    /// How many admin keys must sign each change
    Threshold {
        /// Signatures needed, 1 up to the number of admin keys
        n: u8,
    },
}

#[derive(Args, Debug)]
#[command(args_conflicts_with_subcommands = true)]
pub struct PlatformsArgs {
    #[command(subcommand)]
    cmd: Option<PlatformsCmd>,
    /// JSON instead of text
    #[arg(long)]
    json: bool,
}

#[derive(Subcommand, Debug)]
pub enum PlatformsCmd {
    /// Wrap new blobs for a platform too
    Add {
        /// azure, aws or gcp (sim in sim builds)
        #[arg(value_parser = parse_platform)]
        platform: PlatformId,
    },
    /// Stop wrapping new blobs for a platform
    Rm {
        /// azure, aws or gcp (sim in sim builds)
        #[arg(value_parser = parse_platform)]
        platform: PlatformId,
    },
}

#[derive(Args, Debug)]
#[command(args_conflicts_with_subcommands = true)]
pub struct IntegrityArgs {
    #[command(subcommand)]
    cmd: Option<IntegrityCmd>,
    /// JSON instead of text
    #[arg(long)]
    json: bool,
}

#[derive(Subcommand, Debug)]
pub enum IntegrityCmd {
    /// Allow an endpoint artifact for an app: its sessions then need a matching endpoint report
    Allow {
        /// The app
        app: AppName,
        /// The artifact's name and SHA-256 (64 hex digits)
        #[arg(value_name = "NAME=SHA256", value_parser = parse_artifact)]
        artifact: ArtifactHash,
        /// Remove it instead
        #[arg(long)]
        remove: bool,
    },
    /// External signal sources (an EDR relay)
    #[command(subcommand)]
    Source(SourceCmd),
    /// The response to signals from a severity upward
    On {
        /// low, medium, high or critical
        #[arg(value_parser = parse_severity)]
        severity: Severity,
        /// log-only, deny, suspend, suspend=SECS, or none (remove the rule)
        #[arg(value_parser = parse_action)]
        action: ActionArg,
    },
    /// Ignore an identity's signals up to now (lifts a suspension)
    Clear {
        /// The identity, a `WorkloadIdentity` as JSON
        identity: String,
    },
}

/// The Seal host agent (App Integrity add-on) as an integrity source, and its root: Seal's CA, the
/// same key for every tenant. The release pipeline's CA signs each agent release's leaf, the agent
/// carries leaf and proof, and the enclave checks the proof against the key the tenant enrolled.
const HOST_AGENT: &str = "host-agent";
const HOST_AGENT_CA: &str = "42623498da78de07c9a3d3ef25ce3975eec0093c476fc9852956e8506670b4bd";

fn host_agent_ca() -> PublicKey {
    HOST_AGENT_CA.parse().expect("HOST_AGENT_CA is 64 hex digits")
}

#[derive(Subcommand, Debug)]
pub enum SourceCmd {
    /// Trust signals signed by this source
    Add {
        /// The source's name: 1-64 of [a-z0-9-.]
        name: String,
        /// Its Ed25519 public key (hex); for host-agent, Seal's CA unless given
        #[arg(long, value_name = "HEX")]
        public_key: Option<PublicKey>,
    },
    /// Stop trusting a source
    Rm {
        /// The source's name
        name: String,
    },
}

#[derive(Args, Debug)]
#[command(args_conflicts_with_subcommands = true)]
pub struct ReadersArgs {
    #[command(subcommand)]
    cmd: Option<ReadersCmd>,
    /// JSON instead of text
    #[arg(long)]
    json: bool,
}

#[derive(Subcommand, Debug)]
pub enum ReadersCmd {
    /// Encrypt telemetry to a reader: by public key, or a new reader key file
    Add {
        /// The reader's X25519 public key (hex)
        #[arg(required_unless_present = "generate", conflicts_with = "generate", value_name = "PUBLIC KEY")]
        key: Option<PublicKey>,
        /// Generate a reader key into FILE (mode 0600, never overwritten) and add its public key
        #[arg(long, value_name = "FILE")]
        generate: Option<PathBuf>,
    },
    /// Stop encrypting telemetry to a reader
    Rm {
        /// The reader's X25519 public key (hex)
        #[arg(value_name = "PUBLIC KEY")]
        key: PublicKey,
    },
}

#[derive(Args, Debug)]
#[command(args_conflicts_with_subcommands = true)]
pub struct FreshnessArgs {
    #[command(subcommand)]
    cmd: Option<FreshnessCmd>,
    /// JSON instead of text
    #[arg(long)]
    json: bool,
}

#[derive(Subcommand, Debug)]
pub enum FreshnessCmd {
    /// Freshness signer keys
    #[command(subcommand)]
    Key(FreshnessKeyCmd),
    /// Sign one statement that the latest state is current, with --freshness-key; run it from
    /// cron, well within the freshness window (daily by default)
    Sign,
    /// How long a freshness statement keeps the latest state usable, which bounds how long a
    /// replayed older state works and how long an unreachable log is survived
    Window {
        /// The new window: seconds or a duration from 5m up to 24h, or `default` (24h);
        /// shortening it applies at once, lengthening it waits the pending window; without
        /// it, the window in force
        #[arg(value_parser = parse_freshness_window)]
        window: Option<FreshnessWindow>,
        /// JSON instead of text
        #[arg(long)]
        json: bool,
    },
}

/// A freshness window as given: a duration, or the 24-hour default.
#[derive(Clone, Copy, Debug)]
pub enum FreshnessWindow {
    Default,
    Secs(u64),
}

/// `default`, or a duration within `MIN_STATE_FRESHNESS_SECS..=STATE_FRESHNESS_SECS` (the
/// longest is the default).
fn parse_freshness_window(s: &str) -> Result<FreshnessWindow, String> {
    if s == "default" {
        return Ok(FreshnessWindow::Default);
    }
    let secs = parse_duration(s)?;
    if !(MIN_STATE_FRESHNESS_SECS..=STATE_FRESHNESS_SECS).contains(&secs) {
        return Err(format!(
            "{s}: the freshness window is {} to {}",
            watch::span(MIN_STATE_FRESHNESS_SECS),
            watch::span(STATE_FRESHNESS_SECS)
        ));
    }
    Ok(if secs == STATE_FRESHNESS_SECS { FreshnessWindow::Default } else { FreshnessWindow::Secs(secs) })
}

#[derive(Subcommand, Debug)]
pub enum FreshnessKeyCmd {
    /// Add a freshness signer: by public key, or the key in a key file (`seal key create`)
    Add {
        /// The signer's Ed25519 public key (hex)
        #[arg(required_unless_present = "file", conflicts_with = "file", value_name = "PUBLIC KEY")]
        key: Option<PublicKey>,
        /// The key file whose public key to add
        #[arg(long, value_name = "FILE")]
        file: Option<PathBuf>,
    },
    /// Remove a freshness signer
    Rm {
        /// The signer's Ed25519 public key (hex)
        #[arg(value_name = "PUBLIC KEY")]
        key: PublicKey,
    },
}

#[derive(Args, Debug)]
#[command(args_conflicts_with_subcommands = true)]
pub struct TenantKeyArgs {
    #[command(subcommand)]
    cmd: Option<TenantKeyCmd>,
    /// JSON instead of text
    #[arg(long)]
    json: bool,
}

#[derive(Subcommand, Debug)]
pub enum TenantKeyCmd {
    /// New blobs use the next tenant key version
    Bump {
        /// Also stop accepting older versions: their blobs stop working
        #[arg(long)]
        retire_older: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum ReleaseCmd {
    /// Co-sign enclave releases measuring MEASUREMENT (for tenants whose root requires it);
    /// signs with --key-file
    Approve {
        /// The release measurement (hex)
        measurement: Measurement,
    },
}

#[derive(Subcommand, Debug)]
pub enum DevCmd {
    /// Create a tenant on a log whose registrar key you hold (Seal's tenants are created in
    /// the console); prints the root id
    Init(InitArgs),
}

#[derive(Args, Debug)]
pub struct InitArgs {
    /// The new tenant's id
    #[arg(long)]
    tenant: TenantId,
    /// The first admin key: a key file from `seal key create`
    #[arg(long, value_name = "FILE")]
    key_file: PathBuf,
    /// A registrar key file to sign root version 1 with (repeat for a threshold)
    #[arg(long = "registrar-key", value_name = "FILE", required = true)]
    registrar_keys: Vec<PathBuf>,
    /// Platforms of state version 1 (azure, aws, gcp; sim in sim builds)
    #[arg(long = "platform", value_name = "P", value_parser = parse_platform)]
    platforms: Vec<PlatformId>,
    /// Tenant keys go only to releases this tenant's admins co-signed
    #[arg(long)]
    cosign_releases: bool,
    /// How long changes that widen access wait in public before they take effect (default 0)
    #[arg(long, value_name = "DURATION", value_parser = parse_duration)]
    pending_window: Option<u64>,
    /// Sign without asking
    #[arg(long, short = 'y')]
    yes: bool,
}

#[derive(Clone, Copy, Debug)]
pub enum ActionArg {
    Set(IntegrityAction),
    Unset,
}

pub fn parse_platform(s: &str) -> Result<PlatformId, String> {
    match s {
        "azure" => Ok(PlatformId::AzureSnpAci),
        "aws" => Ok(PlatformId::AwsNitro),
        "gcp" => Ok(PlatformId::GcpConfidentialSpace),
        #[cfg(feature = "sim")]
        "sim" => Ok(PlatformId::Sim),
        _ => Err("expected azure, aws or gcp".into()),
    }
}

fn parse_severity(s: &str) -> Result<Severity, String> {
    serde_json::from_value(serde_json::Value::String(s.to_ascii_lowercase()))
        .map_err(|_| "expected low, medium, high or critical".into())
}

fn parse_action(s: &str) -> Result<ActionArg, String> {
    Ok(match s {
        "log-only" => ActionArg::Set(IntegrityAction::LogOnly),
        "deny" => ActionArg::Set(IntegrityAction::Deny),
        "suspend" => ActionArg::Set(IntegrityAction::Suspend { secs: None }),
        "none" => ActionArg::Unset,
        _ => match s.strip_prefix("suspend=") {
            Some(secs) => ActionArg::Set(IntegrityAction::Suspend {
                secs: Some(secs.parse().map_err(|_| "suspend=SECS takes whole seconds")?),
            }),
            None => return Err("expected log-only, deny, suspend, suspend=SECS or none".into()),
        },
    })
}

fn parse_artifact(s: &str) -> Result<ArtifactHash, String> {
    let (name, digest) = s.split_once('=').ok_or("expected NAME=SHA256")?;
    let bytes = config::unhex(digest).map_err(|_| "the SHA-256 is 64 hex digits")?;
    let sha256: [u8; 32] = bytes.try_into().map_err(|_| "the SHA-256 is 64 hex digits")?;
    if name.is_empty() {
        return Err("expected NAME=SHA256".into());
    }
    Ok(ArtifactHash { name: name.to_string(), sha256 })
}

/// The verified tenant, read with the login (or `--key-file`).
pub async fn current(env: &Env) -> anyhow::Result<(Admin, Current)> {
    let admin = env.admin(Scope::Read).await?;
    let current = admin.fetch(&time()).await?;
    Ok((admin, current))
}

fn changed(changed: bool) -> Result<(), seal::ClientError> {
    changed.then_some(()).ok_or_else(|| invalid("nothing to change"))
}

/// One line per item, or `none`.
fn list(title: &str, items: Vec<String>) {
    say!("{}", ui::bold(title));
    if items.is_empty() {
        say!("  {}", ui::dim("none"));
    }
    for item in items {
        say!("  {item}");
    }
}

pub async fn run(env: &Env, cmd: SettingsCmd) -> anyhow::Result<()> {
    match cmd {
        SettingsCmd::Admins(AdminsArgs { cmd: None, json }) => show_admins(env, json).await,
        SettingsCmd::Admins(AdminsArgs { cmd: Some(cmd), .. }) => {
            let (add, remove, threshold) = match cmd {
                AdminsCmd::Add { keys, threshold } => (keys, Vec::new(), threshold),
                AdminsCmd::Rm { keys, threshold } => (Vec::new(), keys, threshold),
                AdminsCmd::Threshold { n } => (Vec::new(), Vec::new(), Some(n)),
            };
            rotate_root(env, add, remove, threshold).await
        }
        SettingsCmd::Window { duration: None, json } => {
            let (_, current) = current(env).await?;
            let window = current.tenant.state().pending_window_secs;
            if json {
                println!("{}", json!({ "pending_window_secs": window }));
            } else {
                say!("pending window {}: changes that widen access wait this long in public", watch::span(window));
            }
            Ok(())
        }
        SettingsCmd::Window { duration: Some(duration), .. } => {
            if duration > MAX_PENDING_WINDOW_SECS {
                bail!("the longest pending window is {}", watch::span(MAX_PENDING_WINDOW_SECS));
            }
            edit_state(env, |s| {
                s.pending_window_secs = duration;
                Ok(())
            })
            .await
            .map(|_| ())
        }
        SettingsCmd::Platforms(PlatformsArgs { cmd: None, json }) => {
            let (_, current) = current(env).await?;
            let names: Vec<String> =
                current.tenant.state().platforms.iter().map(|p| seal::admin::platform_name(*p)).collect();
            if json {
                println!("{}", json!({ "platforms": names }));
            } else {
                list("Platforms new blobs are wrapped for", names);
            }
            Ok(())
        }
        SettingsCmd::Platforms(PlatformsArgs { cmd: Some(cmd), .. }) => edit_state(env, |s| {
            changed(match cmd {
                PlatformsCmd::Add { platform } => s.platforms.insert(platform),
                PlatformsCmd::Rm { platform } => s.platforms.remove(&platform),
            })
        })
        .await
        .map(|_| ()),
        SettingsCmd::Integrity(IntegrityArgs { cmd: None, json }) => {
            let (_, current) = current(env).await?;
            let policy = &current.tenant.state().integrity;
            if json {
                println!("{}", serde_json::to_string(policy)?);
                return Ok(());
            }
            list(
                "Allowed endpoint artifacts",
                policy
                    .artifacts
                    .iter()
                    .flat_map(|(app, set)| {
                        set.iter().map(move |a| format!("{app}: {} {}", a.name, config::hex(&a.sha256)))
                    })
                    .collect(),
            );
            list("Signal sources", policy.sources.iter().map(|(name, key)| format!("{name}: {key}")).collect());
            list(
                "Responses",
                policy
                    .actions
                    .iter()
                    .map(|(severity, action)| format!("{} and up: {action:?}", format!("{severity:?}").to_lowercase()))
                    .collect(),
            );
            list(
                "Clearances",
                policy
                    .cleared
                    .iter()
                    .map(|c| {
                        format!(
                            "{} before {}",
                            serde_json::to_string(&c.identity).unwrap_or_default(),
                            watch::at(c.before)
                        )
                    })
                    .collect(),
            );
            Ok(())
        }
        SettingsCmd::Integrity(IntegrityArgs { cmd: Some(cmd), .. }) => integrity(env, cmd).await,
        SettingsCmd::TelemetryReaders(ReadersArgs { cmd: None, json }) => {
            let (_, current) = current(env).await?;
            let keys: Vec<String> = current.tenant.state().telemetry_readers.iter().map(ToString::to_string).collect();
            if json {
                println!("{}", json!({ "telemetry_readers": keys }));
            } else {
                list("Telemetry readers (telemetry is encrypted to these keys)", keys);
            }
            Ok(())
        }
        SettingsCmd::TelemetryReaders(ReadersArgs { cmd: Some(cmd), .. }) => {
            let (key, add, generate) = match cmd {
                ReadersCmd::Add { key: Some(key), .. } => (key, true, None),
                ReadersCmd::Add { key: None, generate: Some(path) } => {
                    config::check_new(&path)?;
                    let reader = seal_crypto::telemetry::TelemetryReaderKey::generate(&mut seal_crypto::UnwrapErr(
                        seal_crypto::SysRng,
                    ));
                    (reader.public_key(), true, Some((path, reader)))
                }
                ReadersCmd::Add { key: None, generate: None } => bail!("name a key, or --generate FILE"),
                ReadersCmd::Rm { key } => (key, false, None),
            };
            crate::sign::change_state(
                env,
                |s| changed(if add { s.telemetry_readers.insert(key) } else { s.telemetry_readers.remove(&key) }),
                || {
                    if let Some((path, reader)) = &generate {
                        config::write_private(path, config::seed_text(&reader.to_seed()).expose())?;
                        say!(
                            "{}",
                            ui::ok(&format!(
                                "telemetry reader key in {} (mode 0600), public key {key}",
                                path.display()
                            ))
                        );
                    }
                    Ok(())
                },
            )
            .await
            .map(|_| ())
        }
        SettingsCmd::Freshness(FreshnessArgs { cmd: None, json }) => {
            let (_, current) = current(env).await?;
            let state = current.tenant.state();
            let keys: Vec<String> = state.freshness_keys.iter().map(ToString::to_string).collect();
            if json {
                println!("{}", json!({ "freshness_keys": keys, "freshness_secs": state.freshness_window() }));
            } else {
                list("Freshness signers (none: the log alone vouches for the latest state)", keys);
                say!("freshness window {}", watch::span(state.freshness_window()));
            }
            Ok(())
        }
        SettingsCmd::Freshness(FreshnessArgs { cmd: Some(cmd), .. }) => freshness(env, cmd).await,
        SettingsCmd::TenantKey(TenantKeyArgs { cmd: None, json }) => {
            let (_, current) = current(env).await?;
            let v = &current.tenant.state().tenant_key_versions;
            if json {
                println!("{}", json!({ "current": v.current.0, "oldest_accepted": v.oldest_accepted.0 }));
            } else {
                say!("tenant key version {} (blobs of version {} and later open)", v.current.0, v.oldest_accepted.0);
            }
            Ok(())
        }
        SettingsCmd::TenantKey(TenantKeyArgs { cmd: Some(TenantKeyCmd::Bump { retire_older }), .. }) => {
            edit_state(env, |s| {
                let v = &mut s.tenant_key_versions;
                v.current = TenantKeyVersion(v.current.0.checked_add(1).ok_or_else(|| invalid("version overflow"))?);
                if retire_older {
                    v.oldest_accepted = v.current;
                }
                Ok(())
            })
            .await
            .map(|_| ())
        }
    }
}

async fn show_admins(env: &Env, json: bool) -> anyhow::Result<()> {
    let (_, current) = current(env).await?;
    let root = current.tenant.latest_root();
    let yours: Vec<PublicKey> = env.keys()?.iter().map(|(_, k)| k.public_key()).collect();
    if json {
        let keys: Vec<serde_json::Value> = root.admin_keys.iter().map(admin_key_json).collect();
        println!(
            "{}",
            json!({ "root_version": root.version, "threshold": root.threshold, "cosign_releases": root.cosign_releases, "admin_keys": keys })
        );
        return Ok(());
    }
    say!("{}", ui::bold(&format!("Admin keys of root version {}", root.version)));
    let mut rows = vec![vec![ui::dim("KIND"), ui::dim("KEY ID"), ui::dim("KEY")]];
    for key in &root.admin_keys {
        let id = seal_crypto::sign::admin_key_id(key).to_string();
        let (kind, shown) = match key {
            AdminKey::Ed25519 { public_key } => {
                let mine =
                    if yours.contains(public_key) { format!(" {}", ui::green("(--key-file)")) } else { String::new() };
                ("ed25519", format!("{public_key}{mine}"))
            }
            AdminKey::WebAuthnEs256 { rp_id, .. } => ("passkey", format!("for {rp_id}")),
        };
        rows.push(vec![kind.to_string(), id, shown]);
    }
    for line in ui::table(&rows) {
        say!("  {line}");
    }
    say!("{} of {} must sign each change", root.threshold, root.admin_keys.len());
    if root.admin_keys.len() == 1 {
        say!(
            "{}",
            ui::yellow("only one admin key: add a backup (`seal key create --out backup.key`, then `seal settings admins add KEY`)")
        );
    }
    Ok(())
}

pub fn admin_key_json(key: &AdminKey) -> serde_json::Value {
    let id = seal_crypto::sign::admin_key_id(key).to_string();
    match key {
        AdminKey::Ed25519 { public_key } => json!({ "kind": "ed25519", "key_id": id, "public_key": public_key }),
        AdminKey::WebAuthnEs256 { rp_id, .. } => json!({ "kind": "passkey", "key_id": id, "rp_id": rp_id }),
    }
}

/// The next root: keys added or removed, a new threshold; the state re-signed under it.
async fn rotate_root(env: &Env, add: Vec<PublicKey>, remove: Vec<KeyId>, threshold: Option<u8>) -> anyhow::Result<()> {
    let admin = env.admin(Scope::Submit).await?;
    let time = time();
    let current = admin.fetch(&time).await?;
    let root = current.tenant.latest_root();
    // A public key given to rm names its key id.
    let remove: Vec<KeyId> = remove
        .into_iter()
        .map(|k| {
            let as_key = AdminKey::Ed25519 { public_key: PublicKey(k.0) };
            if root.admin_keys.contains(&as_key) {
                seal_crypto::sign::admin_key_id(&as_key)
            } else {
                k
            }
        })
        .collect();
    let next = seal::admin::next_root(
        root,
        add.into_iter().map(|public_key| AdminKey::Ed25519 { public_key }),
        &remove,
        threshold,
    )?;
    let keys: Vec<_> = env.keys()?.into_iter().map(|(_, k)| k).collect();
    let mut changes = root_changes(root, &next);
    changes.push(format!(
        "~ state version {} re-signed under root version {}",
        current.tenant.latest_state().version + 1,
        next.version
    ));
    let signed_root = cosign(root, TENANT_ROOT_LABEL, Signed { body: next.clone(), signatures: Vec::new() }, &keys);
    let mut state = current.tenant.latest_state().clone();
    state.version += 1;
    state.root_version = next.version;
    state.issued_at = time.now;
    let signed_state = cosign(&next, TENANT_STATE_LABEL, Signed { body: state, signatures: Vec::new() }, &keys);
    let meets = meets_threshold(root, TENANT_ROOT_LABEL, &signed_root)
        && meets_threshold(&next, TENANT_STATE_LABEL, &signed_state);
    if !keys.is_empty() && signed_root.signatures.is_empty() {
        bail!(
            "none of the --key-file keys is an admin key of root version {}: `seal settings admins` lists them",
            root.version
        );
    }
    let verb = match (keys.is_empty(), meets) {
        (true, _) => "Propose this change",
        (false, true) => "Sign and publish",
        (false, false) => "Sign and propose",
    };
    let title = format!("{}: root version {} → {}", admin.tenant(), root.version, next.version);
    confirm(env, &title, &changes, verb)?;
    if meets {
        let (link, state) = admin.rotate_root(&current, next, &keys, &time).await?;
        say!(
            "{}",
            ui::ok(&format!(
                "published root version {} and state version {}",
                link.root.body.version, state.body.version
            ))
        );
        return sign_freshness_if_held(env, &admin, &state.body, &time).await;
    }
    let root_proposal = admin.propose_document(&Proposed::Root(signed_root)).await?;
    let state_proposal = admin.propose_document(&Proposed::State(signed_state)).await?;
    let window = current.tenant.state().pending_window_secs;
    let change = seal_verify::change::classify_root(root, &next);
    follow(env, &admin, vec![root_proposal, state_proposal], change, window).await.map(|_| ())
}

async fn integrity(env: &Env, cmd: IntegrityCmd) -> anyhow::Result<()> {
    let edit: crate::Edit = match cmd {
        IntegrityCmd::Allow { app, artifact, remove } => Box::new(move |s| {
            let set = s.integrity.artifacts.entry(app.clone()).or_default();
            let done = if remove { set.remove(&artifact) } else { set.insert(artifact) };
            if set.is_empty() {
                s.integrity.artifacts.remove(&app);
            }
            changed(done)
        }),
        IntegrityCmd::Source(SourceCmd::Add { name, public_key }) => Box::new(move |s| {
            seal_proto::integrity::validate_code(&name)
                .map_err(|_| invalid("a source name is 1-64 chars of [a-z0-9-.]"))?;
            let public_key = match public_key {
                Some(key) => key,
                None if name == HOST_AGENT => host_agent_ca(),
                None => return Err(invalid(format!("name the key {name} signs with: --public-key HEX"))),
            };
            s.integrity.sources.insert(name, public_key);
            Ok(())
        }),
        IntegrityCmd::Source(SourceCmd::Rm { name }) => Box::new(move |s| {
            s.integrity.sources.remove(&name).map(|_| ()).ok_or_else(|| invalid(format!("no source {name}")))
        }),
        IntegrityCmd::On { severity, action } => Box::new(move |s| {
            match action {
                ActionArg::Set(action) => {
                    s.integrity.actions.insert(severity, action);
                }
                ActionArg::Unset => {
                    s.integrity.actions.remove(&severity);
                }
            }
            Ok(())
        }),
        IntegrityCmd::Clear { identity } => {
            let identity = serde_json::from_str(&identity).context("the identity is a WorkloadIdentity as JSON")?;
            let before = crate::now();
            Box::new(move |s| {
                s.integrity.cleared.insert(Clearance { identity, before });
                Ok(())
            })
        }
    };
    edit_state(env, edit).await.map(|_| ())
}

async fn freshness(env: &Env, cmd: FreshnessCmd) -> anyhow::Result<()> {
    match cmd {
        FreshnessCmd::Key(FreshnessKeyCmd::Add { key, file }) => {
            let key = match (key, &file) {
                (Some(k), _) => k,
                (None, Some(path)) => config::read_key(path)?.public_key(),
                (None, None) => bail!("name a key, or --file FILE"),
            };
            edit_state(env, |s| changed(s.freshness_keys.insert(key))).await.map(|_| ())
        }
        FreshnessCmd::Key(FreshnessKeyCmd::Rm { key }) => {
            edit_state(env, |s| changed(s.freshness_keys.remove(&key))).await.map(|_| ())
        }
        FreshnessCmd::Window { window: None, json } => {
            let (_, current) = current(env).await?;
            let window = current.tenant.state().freshness_window();
            if json {
                println!("{}", json!({ "freshness_secs": window }));
            } else {
                say!(
                    "freshness window {}: a replayed older state works this long at most, and the tenant survives \
                     an unreachable log this long",
                    watch::span(window)
                );
            }
            Ok(())
        }
        FreshnessCmd::Window { window: Some(window), .. } => {
            let secs = match window {
                FreshnessWindow::Default => None,
                FreshnessWindow::Secs(secs) => Some(secs),
            };
            edit_state(env, |s| changed(std::mem::replace(&mut s.freshness_secs, secs) != secs)).await.map(|_| ())
        }
        FreshnessCmd::Sign => {
            let path = env
                .sign
                .freshness_key
                .as_ref()
                .ok_or_else(|| anyhow!("name the freshness key: --freshness-key FILE (or SEAL_FRESHNESS_KEY)"))?;
            let key = config::read_key(path)?;
            // A freshness signer reads the state it signs for with its own key.
            let admin = env.admin_signed_by(seal_crypto::sign::SigningKey::from_seed(&key.to_seed()))?;
            let time = time();
            let current = admin.fetch_as_freshness_signer(&key, &time).await?;
            let state = current.tenant.latest_state();
            admin.post_freshness(&key, state, &time).await?;
            say!(
                "{}",
                ui::ok(&format!("signed freshness for state version {} at {}", state.version, watch::at(time.now)))
            );
            Ok(())
        }
    }
}

/// `seal release approve`: a co-signature by the threshold of `--key-file` keys.
pub async fn release(env: &Env, cmd: ReleaseCmd) -> anyhow::Result<()> {
    let ReleaseCmd::Approve { measurement } = cmd;
    let keys: Vec<_> = env.keys()?.into_iter().map(|(_, k)| k).collect();
    if keys.is_empty() {
        bail!("a release co-signature is signed here: pass --key-file with the threshold of admin keys");
    }
    let admin = env.admin(Scope::Submit).await?;
    let current = admin.fetch(&time()).await?;
    if !current.tenant.root().cosign_releases {
        say!("note: this tenant's root does not require co-signed releases");
    }
    confirm(env, &format!("{}: co-sign releases measuring", admin.tenant()), &[format!("+ {measurement}")], "Sign")?;
    admin.approve_release(&current, measurement, &keys).await?;
    say!("{}", ui::ok(&format!("co-signed {measurement}")));
    Ok(())
}

/// `seal dev init`: root version 1 signed by the registrar keys, logged and stored with the
/// write token, then state version 1; writes the configuration. Resumable (`Admin::init`).
pub async fn init(env: &mut Env, args: InitArgs) -> anyhow::Result<()> {
    let InitArgs { tenant, key_file, registrar_keys, platforms, cosign_releases, pending_window, yes } = args;
    let pending_window = pending_window.unwrap_or(0);
    if pending_window > MAX_PENDING_WINDOW_SECS {
        bail!("the longest pending window is {}", watch::span(MAX_PENDING_WINDOW_SECS));
    }
    if env.config.tenant.as_ref().is_some_and(|t| t != &tenant) {
        bail!(
            "{} uses tenant {}: pass another --home",
            env.home.config_path().display(),
            env.config.tenant.as_ref().map_or("", |t| t.as_str())
        );
    }
    let key = config::read_key(&key_file)?;
    let registrar = registrar_keys.iter().map(|p| config::read_key(p)).collect::<anyhow::Result<Vec<_>>>()?;
    env.sign.yes = yes;
    let names: Vec<String> = platforms.iter().map(|p| seal::admin::platform_name(*p)).collect();
    let lines = vec![
        format!("+ root version 1: admin key {} (threshold 1)", key.key_id()),
        format!("+ state version 1: platforms {}", if names.is_empty() { "none".into() } else { names.join(", ") }),
    ];
    confirm(env, &format!("create tenant {tenant}"), &lines, "Sign")?;
    let admin = env.admin_for(&tenant, None)?;
    let init =
        admin.init(&key, &registrar, cosign_releases, platforms.into_iter().collect(), pending_window, &time()).await?;
    for line in &init.resumed {
        say!("resumed: {line}");
    }
    env.config.tenant = Some(tenant.clone());
    env.config.root_id = Some(init.root_id);
    env.remember_urls();
    env.save()?;
    say!("{}", ui::ok(&format!("created tenant {tenant}, root id {}", init.root_id)));
    println!("SEAL_TENANT={tenant}@{}", init.root_id);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_host_agent_ca_is_a_public_key() {
        assert_eq!(host_agent_ca().to_string(), HOST_AGENT_CA);
    }
}
