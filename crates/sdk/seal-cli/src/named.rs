//! Named blobs: `seal secret --name` publishes the blob it seals, `seal blobs` lists the
//! tenant's names and deletes one. Apps start sessions on a name (`seal.session("openai")`) and
//! follow its newest version.
//!
//! Each version is signed here by the root in force's threshold of admin keys: the
//! `--key-file` keys, or with `--passkey` an admin passkey on a security key. The control
//! plane stores it; every enclave checks the signatures again before handing the blob out.

use anyhow::{bail, Context as _};
use clap::Subcommand;

use seal::admin::{cosign, Admin, Current};
use seal_proto::named::{NamedBlobVersion, NAMED_BLOB_LABEL};
use seal_proto::BlobName;

use crate::sign::confirm;
use crate::{now, say, time, ui, Env, Scope};

#[derive(Subcommand, Debug)]
pub enum BlobsCmd {
    /// Every name, its version, where it may be sent and which apps may use it (the default)
    List {
        /// JSON instead of text
        #[arg(long)]
        json: bool,
    },
    /// Approve a name's current blob again as its next version: for a version the admins in
    /// force no longer cover (an admin removed, a higher threshold), which enclaves refuse
    Approve {
        /// The name to approve again
        name: BlobName,
        /// Approve with an admin passkey on a security key, not a --key-file
        #[arg(long)]
        passkey: bool,
    },
    /// Delete a name: apps can no longer start sessions on it. Blobs already handed out keep
    /// working until they expire; rotate the credential upstream to end them
    Delete {
        /// The name to delete
        name: BlobName,
        /// Delete with an admin passkey on a security key, not a --key-file
        #[arg(long)]
        passkey: bool,
    },
}

/// Signs `version` with the `--key-file` keys, or the security key with `passkey`.
async fn sign(env: &Env, current: &Current, version: &mut NamedBlobVersion, passkey: bool) -> anyhow::Result<()> {
    let root = current.tenant.root();
    if passkey {
        return sign_with_passkey(root, version).await;
    }
    let keys: Vec<_> = env.keys()?.into_iter().map(|(_, k)| k).collect();
    if keys.is_empty() {
        bail!(
            "a named blob is signed here: pass --key-file (the root's threshold of admin keys) or --passkey, or publish it in the console"
        );
    }
    version.entry = cosign(root, NAMED_BLOB_LABEL, version.entry.clone(), &keys);
    Ok(())
}

#[cfg(feature = "passkey")]
async fn sign_with_passkey(root: &seal_proto::state::TenantRoot, version: &mut NamedBlobVersion) -> anyhow::Result<()> {
    crate::passkey::cosign(root, NAMED_BLOB_LABEL, &mut version.entry).await
}

#[cfg(not(feature = "passkey"))]
async fn sign_with_passkey(_: &seal_proto::state::TenantRoot, _: &mut NamedBlobVersion) -> anyhow::Result<()> {
    bail!("this seal was built without passkey support (the `passkey` feature): sign with --key-file")
}

/// Checks before the secret is asked for that a version could be signed and stored: the
/// tenant is the one `seal use` selected, and there is something to sign with.
pub fn check_publishable(env: &Env, tenant: &seal_proto::TenantId, passkey: bool) -> anyhow::Result<()> {
    if env.config.tenant.as_ref() != Some(tenant) {
        bail!("--name publishes for the tenant `seal use` selected: run `seal use {tenant}` first");
    }
    if !passkey && env.sign.keys.key_files.is_empty() {
        bail!("--name needs the root's threshold of admin keys: pass --key-file (repeat for M-of-N) or --passkey");
    }
    Ok(())
}

/// Publishes `blob` as `name`'s next version.
pub async fn publish(env: &Env, name: &BlobName, blob: &str, passkey: bool) -> anyhow::Result<u64> {
    let admin = env.admin(Scope::Submit).await?;
    let current = admin.fetch(&time()).await?;
    let mut version = admin.draft_blob(&current, name, Some(blob), now()).await?;
    sign(env, &current, &mut version, passkey).await?;
    admin.publish_blob(&current, &version).await.with_context(|| format!("publishing {name}"))?;
    Ok(version.entry.body.version)
}

pub async fn run(env: &Env, cmd: Option<BlobsCmd>) -> anyhow::Result<()> {
    match cmd.unwrap_or(BlobsCmd::List { json: false }) {
        BlobsCmd::List { json } => list(env, json).await,
        BlobsCmd::Delete { name, passkey } => delete(env, &name, passkey).await,
        BlobsCmd::Approve { name, passkey } => approve(env, &name, passkey).await,
    }
}

async fn list(env: &Env, json: bool) -> anyhow::Result<()> {
    let admin = env.admin(Scope::Read).await?;
    let current = admin.fetch(&time()).await?;
    let names = admin.named_blobs().await?;
    if json {
        let rows: Vec<_> = names.iter().map(|v| row_json(&admin, &current, v)).collect();
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(());
    }
    if names.is_empty() {
        say!("{} has no named blobs: `seal secret --name NAME` publishes one", admin.tenant());
        return Ok(());
    }
    let mut rows = vec![["NAME", "VERSION", "DESTINATION", "APPS", "PUBLISHED"].map(ui::dim).to_vec()];
    for version in &names {
        let entry = &version.entry.body;
        let (destination, apps) = describe(version);
        let mut name = entry.name.to_string();
        if !admin.named_signed(&current, version) {
            name = format!("{name} {}", ui::yellow("(needs signing again)"));
        }
        let published = format!("{} ago", crate::watch::span(now().saturating_sub(entry.published_at)));
        rows.push(vec![name, format!("v{}", entry.version), destination, apps, published]);
    }
    for line in ui::table(&rows) {
        println!("{line}");
    }
    Ok(())
}

/// The destination and apps a version's blob names, from its clear-text policy.
fn describe(version: &NamedBlobVersion) -> (String, String) {
    match version.text().and_then(|t| t.parse::<seal_proto::blob::Blob>().ok()) {
        Some(blob) => {
            let apps: Vec<String> = blob.policy.apps().iter().map(ToString::to_string).collect();
            (blob.policy.destination().to_string(), apps.join(","))
        }
        None => ("-".into(), "-".into()),
    }
}

fn row_json(admin: &Admin, current: &Current, version: &NamedBlobVersion) -> serde_json::Value {
    let entry = &version.entry.body;
    let (destination, apps) = describe(version);
    serde_json::json!({
        "name": entry.name,
        "version": entry.version,
        "destination": destination,
        "apps": apps.split(',').filter(|a| !a.is_empty()).collect::<Vec<_>>(),
        "published_at": entry.published_at,
        "signed": admin.named_signed(current, version),
        "blob": version.blob,
    })
}

async fn approve(env: &Env, name: &BlobName, passkey: bool) -> anyhow::Result<()> {
    let admin = env.admin(Scope::Submit).await?;
    let current = admin.fetch(&time()).await?;
    let latest = admin.named_blobs().await?.into_iter().find(|v| &v.entry.body.name == name);
    let Some(blob) = latest.as_ref().and_then(|v| v.blob.clone()) else {
        bail!("{} has no named blob {name}", admin.tenant());
    };
    let mut version = admin.draft_blob(&current, name, Some(&blob), now()).await?;
    let (destination, apps) = describe(&version);
    confirm(
        env,
        &format!("{}: approve the named blob again", admin.tenant()),
        &[format!("~ {name} version {}: {destination} for {apps}", version.entry.body.version)],
        "Sign",
    )?;
    sign(env, &current, &mut version, passkey).await?;
    admin.publish_blob(&current, &version).await.with_context(|| format!("approving {name}"))?;
    say!("{}", ui::ok(&format!("approved {name} as version {}", version.entry.body.version)));
    Ok(())
}

async fn delete(env: &Env, name: &BlobName, passkey: bool) -> anyhow::Result<()> {
    let admin = env.admin(Scope::Submit).await?;
    let current = admin.fetch(&time()).await?;
    let mut version = admin.draft_blob(&current, name, None, now()).await?;
    confirm(
        env,
        &format!("{}: delete the named blob", admin.tenant()),
        &[format!("- {name} (apps can no longer start sessions on it)")],
        "Delete",
    )?;
    sign(env, &current, &mut version, passkey).await?;
    admin.publish_blob(&current, &version).await.with_context(|| format!("deleting {name}"))?;
    say!("{}", ui::ok(&format!("deleted {name}")));
    Ok(())
}
