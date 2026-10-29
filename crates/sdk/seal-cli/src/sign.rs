//! How a change reaches the tenant, and `seal changes`.
//!
//! Every change is built here on the verified state in force (`Admin::draft`), shown as its
//! classified differences, and then:
//!
//! - signed here with the `--key-file` keys (or, in `seal changes sign --passkey`, an admin
//!   passkey on a security key: `crate::passkey`) and published when they meet the root's
//!   threshold;
//! - otherwise proposed on the control plane (with whatever signatures the keys gave), its
//!   console page opened for the admins' passkeys, and followed until it is logged: the CLI
//!   submits it itself once the threshold of signatures is there. Ctrl-C leaves it pending.
//!
//! The CLI holds no admin key of its own: without `--key-file` or `--passkey` it signs nothing.

use std::io::IsTerminal as _;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail};
use clap::{Args, Subcommand};
use serde::Serialize;

use seal::admin::{cosign, meets_threshold, Admin, Current, Proposal, Proposed, Submitted};
use seal_proto::signed::Signed;
use seal_proto::state::{TenantRoot, TenantState, TENANT_ROOT_LABEL, TENANT_STATE_LABEL};
use seal_proto::TrustedTime;
use seal_verify::change::Change;

use crate::{say, time, ui, watch, Env, Exit, Scope};

/// How often a followed proposal is checked.
const POLL: Duration = Duration::from_secs(2);

/// Where a change ended up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delivered {
    /// Logged: in force, or waiting out the pending window.
    Logged,
    /// A proposal, still waiting for signatures.
    Pending,
}

/// Prints `title` and `lines`, then asks to `verb`, unless `--yes`.
pub fn confirm(env: &Env, title: &str, lines: &[String], verb: &str) -> anyhow::Result<()> {
    say!("{}", ui::bold(title));
    for line in lines {
        say!("  {}", ui::diff_line(line));
    }
    if env.sign.yes {
        return Ok(());
    }
    if !ui::interactive() {
        bail!("stdin is not a terminal: pass --yes to {} without asking", verb.to_lowercase());
    }
    if ui::confirm(&format!("{verb}?"))? {
        Ok(())
    } else {
        bail!("cancelled; nothing was signed or proposed")
    }
}

/// `draft`'s changes, then in plain words when it applies, and what it supersedes.
pub fn classified(current: &Current, draft: &seal::admin::Draft) -> Vec<String> {
    let mut lines = draft.changes.clone();
    let window = draft.old.pending_window_secs;
    lines.push(match draft.change {
        Change::Narrowing => "this narrows access: it applies as soon as it is logged".to_string(),
        Change::Widening if window == 0 => {
            "this widens access: with no pending window it applies as soon as it is logged".into()
        }
        Change::Widening => format!(
            "this widens access: it takes effect {} after it is logged (the pending window), unless an admin cancels it",
            watch::span(window)
        ),
    });
    if !draft.supersedes.is_empty() {
        let versions: Vec<String> = draft.supersedes.iter().map(u64::to_string).collect();
        lines.push(format!("pending state versions {} never take effect", versions.join(", ")));
    } else if let Some(p) = current.tenant.pending().first() {
        lines.push(format!("note: pending state version {} may take effect before this one", p.version));
    }
    lines
}

/// The verb to confirm: what happens next with these keys.
fn verb(keys: usize, meets: bool) -> &'static str {
    match (keys, meets) {
        (0, _) => "Propose this change",
        (_, true) => "Sign and publish",
        (_, false) => "Sign and propose",
    }
}

/// The admin keys `--key-file` gave that `root` lists.
fn admin_keys_given(env: &Env, root: &TenantRoot) -> anyhow::Result<Vec<seal_crypto::sign::SigningKey>> {
    let keys = env.keys()?;
    if keys.is_empty() {
        return Ok(Vec::new());
    }
    let admins: Vec<_> = keys
        .into_iter()
        .filter(|(_, k)| root.admin_keys.contains(&seal_proto::state::AdminKey::Ed25519 { public_key: k.public_key() }))
        .map(|(_, k)| k)
        .collect();
    if admins.is_empty() {
        bail!(
            "none of the --key-file keys is an admin key of root version {}: `seal settings admins` lists them",
            root.version
        );
    }
    Ok(admins)
}

/// A change to the state: built, verified, shown, then signed or proposed (module docs).
pub async fn edit_state(
    env: &Env,
    edit: impl FnOnce(&mut TenantState) -> Result<(), seal::ClientError>,
) -> anyhow::Result<Delivered> {
    change_state(env, edit, || Ok(())).await
}

/// As `edit_state`; `stored` runs once the change is on the control plane (logged or
/// proposed), before any waiting: a key the change grants is written then.
pub async fn change_state(
    env: &Env,
    edit: impl FnOnce(&mut TenantState) -> Result<(), seal::ClientError>,
    stored: impl FnOnce() -> anyhow::Result<()>,
) -> anyhow::Result<Delivered> {
    let admin = env.admin(Scope::Submit).await?;
    let time = time();
    let current = admin.fetch(&time).await?;
    let draft = Admin::draft(&current, &time, edit)?;
    let root = current.tenant.latest_root().clone();
    let keys = admin_keys_given(env, &root)?;
    let lines = classified(&current, &draft);
    let (change, window) = (draft.change, draft.old.pending_window_secs);
    let signed = cosign(&root, TENANT_STATE_LABEL, Signed { body: draft.new, signatures: Vec::new() }, &keys);
    let meets = meets_threshold(&root, TENANT_STATE_LABEL, &signed);
    let (from, to) = (draft.old.version, signed.body.version);
    let title = format!("{}: state version {from} (in force) → {to}", admin.tenant());
    confirm(env, &title, &lines, verb(keys.len(), meets))?;
    if meets {
        let index = admin.publish(&signed).await?;
        stored()?;
        published(&signed.body, index, change, window);
        sign_freshness_if_held(env, &admin, &signed.body, &time).await?;
        return Ok(Delivered::Logged);
    }
    if !keys.is_empty() {
        say!(
            "this change needs {} signatures of root version {}; you gave {}",
            root.threshold,
            root.version,
            keys.len()
        );
    }
    let proposal = admin.propose_document(&Proposed::State(signed)).await?;
    stored()?;
    follow(env, &admin, vec![proposal], change, window).await
}

fn published(state: &TenantState, index: u64, change: Change, window: u64) {
    say!("{}", ui::ok(&format!("published state version {} (log entry {index})", state.version)));
    if change == Change::Widening && window > 0 {
        let at = crate::now() + window;
        say!(
            "  it takes effect in {}, at {}, unless an admin cancels it; follow it with `seal changes --watch`",
            watch::span(window),
            watch::at(at)
        );
    }
}

/// The security key's signature on `document` (`crate::passkey`).
#[cfg(feature = "passkey")]
async fn sign_with_passkey(root: &TenantRoot, document: &mut Proposed) -> anyhow::Result<()> {
    match document {
        Proposed::State(s) => crate::passkey::cosign(root, TENANT_STATE_LABEL, s).await,
        Proposed::Root(r) => crate::passkey::cosign(root, TENANT_ROOT_LABEL, r).await,
    }
}

#[cfg(not(feature = "passkey"))]
async fn sign_with_passkey(_: &TenantRoot, _: &mut Proposed) -> anyhow::Result<()> {
    bail!("this seal was built without passkey support (the `passkey` feature): sign with --key-file or in the console")
}

fn signature_count(document: &Proposed) -> usize {
    match document {
        Proposed::State(s) => s.signatures.len(),
        Proposed::Root(r) => r.signatures.len(),
    }
}

fn what(document: &Proposed) -> String {
    match document {
        Proposed::State(s) => format!("state version {}", s.body.version),
        Proposed::Root(r) => format!("root version {}", r.body.version),
    }
}

/// The first 12 hex digits of a proposal id: enough to name it (`find` takes a prefix).
pub fn short(id: &str) -> &str {
    &id[..id.len().min(12)]
}

/// Follows `proposals` (a root first, when one is among them) until every one is logged:
/// opens the console page of the first, submits each once it has its signatures, and reports.
pub async fn follow(
    env: &Env,
    admin: &Admin,
    proposals: Vec<Proposal>,
    change: Change,
    window: u64,
) -> anyhow::Result<Delivered> {
    let first = proposals.first().ok_or_else(|| anyhow!("nothing proposed"))?.id.clone();
    let url = env.change_url(&first);
    for p in &proposals {
        say!("proposed {} as {}", what(&p.document), ui::bold(short(&p.id)));
    }
    say!("sign it in the console: {}", ui::accent(&url));
    say!("{}", ui::dim(&format!("  or here: seal changes sign {} --key-file FILE", short(&first))));
    if crate::console::browser_wanted(env.sign.no_browser) {
        ui::open_browser(&url);
    }
    if env.sign.no_wait {
        say!("it stays pending: `seal changes` lists it");
        return Ok(Delivered::Pending);
    }
    if !std::io::stderr().is_terminal() {
        eprintln!("waiting for the admins' signatures (Ctrl-C stops waiting; the proposal stays)");
    }
    let started = Instant::now();
    let mut waiting: Vec<Proposed> = proposals.into_iter().map(|p| p.document).collect();
    let mut last = None;
    loop {
        let spinner = ui::Spinner::start_since("waiting for the admins' signatures", started);
        let interrupted = tokio::select! {
            _ = tokio::signal::ctrl_c() => true,
            () = tokio::time::sleep(POLL) => false,
        };
        drop(spinner);
        if interrupted {
            eprintln!(
                "stopped waiting; {} stays pending: sign it at {url} or with `seal changes sign {}`",
                what(&waiting[0]),
                short(&first)
            );
            return Err(Exit(130).into());
        }
        match step(admin, &mut waiting).await {
            Ok(Some(state)) => {
                say!(
                    "{}",
                    ui::ok(&format!(
                        "{} is logged",
                        what(&Proposed::State(Signed { body: state.clone(), signatures: vec![] }))
                    ))
                );
                if change == Change::Widening && window > 0 {
                    say!(
                        "  it takes effect in {}, unless an admin cancels it; follow it with `seal changes --watch`",
                        watch::span(window)
                    );
                }
                sign_freshness_if_held(env, admin, &state, &time()).await?;
                return Ok(Delivered::Logged);
            }
            Ok(None) => last = None,
            Err(StepError::Fatal(e)) => return Err(anyhow!("{e}")),
            Err(StepError::Retry(e)) => {
                if last.as_ref() != Some(&e) {
                    eprintln!("seal: {e} (retrying)");
                }
                last = Some(e);
            }
        }
    }
}

/// Why a check of followed proposals failed: for good, or for now.
enum StepError {
    Fatal(String),
    Retry(String),
}

/// One check of the followed documents: submits those with their signatures, drops those
/// logged. Returns the last state once nothing is left.
async fn step(admin: &Admin, waiting: &mut Vec<Proposed>) -> Result<Option<TenantState>, StepError> {
    let retry = |e: seal::ClientError| match e {
        seal::ClientError::Verification(_) => StepError::Fatal(e.to_string()),
        e => StepError::Retry(e.to_string()),
    };
    let open = admin.proposals().await.map_err(retry)?;
    let current = admin.fetch(&time()).await.map_err(retry)?;
    let mut last_state = None;
    let mut i = 0;
    while i < waiting.len() {
        let document = waiting[i].clone();
        let id = document.id();
        let latest = current.tenant.latest_root();
        if let Some(p) = open.iter().find(|p| p.id == id) {
            let ready = match &p.document {
                Proposed::Root(r) => meets_threshold(latest, TENANT_ROOT_LABEL, r),
                Proposed::State(s) => {
                    s.body.root_version == latest.version && meets_threshold(latest, TENANT_STATE_LABEL, s)
                }
            };
            if !ready {
                i += 1;
                continue;
            }
            match admin.submit(&p.document).await {
                Ok(Submitted::Root(link)) => {
                    say!("{}", ui::ok(&format!("published root version {}", link.root.body.version)))
                }
                Ok(Submitted::State(logged)) => {
                    say!(
                        "{}",
                        ui::ok(&format!(
                            "published state version {} (log entry {})",
                            logged.state.body.version, logged.proof.leaf_index
                        ))
                    );
                    last_state = Some(logged.state.body.clone());
                }
                // Someone else submitted it first: the next check finds it logged.
                Err(seal::ClientError::Seal { .. }) => {
                    i += 1;
                    continue;
                }
                Err(e) => return Err(retry(e)),
            }
            waiting.remove(i);
            // A root just logged: the state under it is checked against it next time.
            return Ok(if waiting.is_empty() { last_state } else { None });
        }
        let logged = match &document {
            Proposed::Root(r) => current.bundle.root_chain.iter().any(|l| l.root.body == r.body),
            Proposed::State(s) => {
                current.tenant.latest_state() == &s.body || current.bundle.states.iter().any(|l| l.state.body == s.body)
            }
        };
        if !logged {
            return Err(StepError::Fatal(format!("proposal {} was cancelled before it was logged", short(&id))));
        }
        if let Proposed::State(s) = &document {
            say!("{}", ui::ok(&format!("state version {} was submitted and logged", s.body.version)));
            last_state = Some(s.body.clone());
        } else {
            say!("{}", ui::ok(&format!("{} was submitted and logged", what(&document))));
        }
        waiting.remove(i);
    }
    Ok(if waiting.is_empty() { last_state.or_else(|| Some(current.tenant.latest_state().clone())) } else { None })
}

/// Signs a freshness statement for `state` when it names freshness keys and `--freshness-key`
/// holds one of them; otherwise says it waits for one.
pub async fn sign_freshness_if_held(
    env: &Env,
    admin: &Admin,
    state: &TenantState,
    time: &TrustedTime,
) -> anyhow::Result<()> {
    if state.freshness_keys.is_empty() {
        return Ok(());
    }
    if let Some(path) = &env.sign.freshness_key {
        let key = crate::config::read_key(path)?;
        if state.freshness_keys.contains(&key.public_key()) {
            admin.post_freshness(&key, state, time).await?;
            say!(
                "{}",
                ui::ok(&format!("signed freshness for state version {} with {}", state.version, path.display()))
            );
            return Ok(());
        }
    }
    say!(
        "note: state version {} names freshness keys; it is not used until one of them signs for it \
         (`seal settings freshness sign --freshness-key FILE`)",
        state.version
    );
    Ok(())
}

// ---- seal changes ----------------------------------------------------------------------------

#[derive(Args, Debug)]
#[command(args_conflicts_with_subcommands = true)]
pub struct ChangesArgs {
    #[command(subcommand)]
    pub cmd: Option<ChangesCmd>,
    /// Follow pending changes as they are logged, take effect or are superseded
    #[arg(long, help_heading = "Watch")]
    pub watch: bool,
    /// Print the state in force and every pending change, then exit: 0 when nothing is
    /// pending, 3 when something is
    #[arg(long, requires = "watch", help_heading = "Watch")]
    pub once: bool,
    /// How often to check (seconds, or a duration such as 5m)
    #[arg(long, value_name = "DURATION", value_parser = crate::parse_duration, default_value = "60", requires = "watch", help_heading = "Watch")]
    pub interval: u64,
    /// JSON instead of text (with --watch: one object per pending state)
    #[arg(long)]
    pub json: bool,
}

#[derive(Subcommand, Debug)]
pub enum ChangesCmd {
    /// One proposal: its differences from the state in force, and its signatures
    Show {
        /// The proposal id, or enough of its start to name it
        id: String,
        /// JSON instead of text
        #[arg(long)]
        json: bool,
    },
    /// Add your signatures: with --key-file or --passkey here, else in the console
    Sign {
        /// The proposal id, or enough of its start to name it
        id: String,
        /// Sign with your admin passkey on a security key plugged in over USB
        #[arg(long)]
        passkey: bool,
    },
    /// Submit a proposal that has its signatures (a root goes with the state proposed under it)
    Submit {
        /// The proposal id, or enough of its start to name it
        id: String,
    },
    /// Delete a proposal
    Cancel {
        /// The proposal id, or enough of its start to name it
        id: String,
    },
}

/// A proposal as `--json` prints it.
#[derive(Serialize)]
struct ProposalJson<'a> {
    id: &'a str,
    kind: &'static str,
    version: u64,
    signatures: usize,
    threshold: u8,
    root_version: u64,
    changes: Vec<String>,
}

/// The changes from `old` to `new`, one line each.
pub fn root_changes(old: &TenantRoot, new: &TenantRoot) -> Vec<String> {
    let mut changes = Vec::new();
    for k in old.admin_keys.difference(&new.admin_keys) {
        changes.push(format!("- admin key {}", seal_crypto::sign::admin_key_id(k)));
    }
    for k in new.admin_keys.difference(&old.admin_keys) {
        changes.push(format!("+ admin key {}", seal_crypto::sign::admin_key_id(k)));
    }
    if new.threshold != old.threshold {
        changes.push(format!("~ threshold: {} -> {}", old.threshold, new.threshold));
    }
    if new.cosign_releases != old.cosign_releases {
        changes.push(format!("~ co-sign releases: {} -> {}", old.cosign_releases, new.cosign_releases));
    }
    changes
}

/// How `proposal` differs from the verified state, and the root its signatures count under:
/// the latest one, or for a state signed for the next root, the root proposed among `open`.
/// Refuses a proposal that cannot follow the verified state.
pub fn check_proposal(
    current: &Current,
    open: &[Proposal],
    proposal: &Proposal,
) -> anyhow::Result<(Vec<String>, TenantRoot)> {
    let (root, state) = (current.tenant.latest_root(), current.tenant.latest_state());
    match &proposal.document {
        Proposed::Root(next) => {
            let next = &next.body;
            if next.tenant != root.tenant || next.version != root.version + 1 {
                bail!("proposal {} is not the next root of {}", short(&proposal.id), root.tenant);
            }
            Ok((root_changes(root, next), root.clone()))
        }
        Proposed::State(new) => {
            let new = &new.body;
            if new.tenant != state.tenant || new.version <= state.version {
                bail!("proposal {} does not follow state version {}", short(&proposal.id), state.version);
            }
            // Shown against the state in force, with each difference's classification.
            let in_force = current.tenant.state();
            let mut changes: Vec<String> =
                seal_verify::change::diff_states(in_force, new).iter().map(watch::line).collect();
            let signing = if new.root_version == root.version {
                root.clone()
            } else {
                let proposed = open.iter().find_map(|p| match &p.document {
                    Proposed::Root(r) if r.body.version == new.root_version && r.body.version == root.version + 1 => {
                        Some(r.body.clone())
                    }
                    _ => None,
                });
                proposed
                    .ok_or_else(|| anyhow!("proposal {} is signed for a root nobody proposed", short(&proposal.id)))?
            };
            if new.version != state.version + 1 {
                changes.push(format!("~ version: {} -> {}", state.version, new.version));
            }
            Ok((changes, signing))
        }
    }
}

/// The open proposal whose id is or starts with `id`.
fn find<'a>(open: &'a [Proposal], id: &str) -> anyhow::Result<&'a Proposal> {
    let matches: Vec<&Proposal> = open.iter().filter(|p| p.id.starts_with(id)).collect();
    match matches.as_slice() {
        [one] => Ok(one),
        [] => bail!("no open proposal {id}: `seal changes` lists them"),
        _ => bail!("{id} names {} proposals: give more of the id", matches.len()),
    }
}

pub async fn run(env: &Env, args: ChangesArgs) -> anyhow::Result<()> {
    if args.watch {
        let admin = env.admin(Scope::Read).await?;
        if args.once {
            return match watch::once(&admin, &time(), args.json).await? {
                watch::Found::Nothing => Ok(()),
                watch::Found::Pending => Err(Exit(3).into()),
            };
        }
        return watch::follow(&admin, Duration::from_secs(args.interval.max(1)), args.json, time).await;
    }
    match args.cmd {
        None => list(env, args.json).await,
        Some(ChangesCmd::Show { id, json }) => show(env, &id, json).await,
        Some(ChangesCmd::Sign { id, passkey }) => sign(env, &id, passkey).await,
        Some(ChangesCmd::Submit { id }) => submit(env, &id).await,
        Some(ChangesCmd::Cancel { id }) => {
            let admin = env.admin(Scope::Submit).await?;
            let open = admin.proposals().await?;
            let proposal = find(&open, &id)?;
            admin.withdraw(&proposal.id).await?;
            say!("{}", ui::ok(&format!("cancelled proposal {}", short(&proposal.id))));
            Ok(())
        }
    }
}

async fn list(env: &Env, json: bool) -> anyhow::Result<()> {
    let admin = env.admin(Scope::Read).await?;
    let current = admin.fetch(&time()).await?;
    let open = admin.proposals().await?;
    let pending = current.tenant.pending();
    if json {
        let proposals: Vec<ProposalJson> = open.iter().map(|p| proposal_json(&current, &open, p)).collect();
        let pending: Vec<serde_json::Value> = pending
            .iter()
            .map(|p| {
                let mut v = serde_json::to_value(p).unwrap_or_default();
                v["differences"] = serde_json::to_value(current.tenant.differences(p.version)).unwrap_or_default();
                v
            })
            .collect();
        println!("{}", serde_json::json!({ "proposals": proposals, "pending": pending }));
        return Ok(());
    }
    if open.is_empty() && pending.is_empty() {
        say!("nothing pending: state version {} is in force, and no proposal is open", current.tenant.state().version);
        return Ok(());
    }
    if !open.is_empty() {
        say!("{}", ui::bold("Proposals (waiting for signatures)"));
        let mut rows = vec![vec![ui::dim("ID"), ui::dim("WHAT"), ui::dim("SIGNED"), ui::dim("CHANGES")]];
        for p in &open {
            let (signed, changes) = match check_proposal(&current, &open, p) {
                Ok((changes, root)) => (format!("{} of {}", signature_count(&p.document), root.threshold), changes),
                Err(e) => ("-".into(), vec![format!("! {e}")]),
            };
            let first = changes.first().cloned().unwrap_or_default();
            rows.push(vec![short(&p.id).to_string(), what(&p.document), signed, ui::diff_line(&first)]);
            for more in changes.iter().skip(1) {
                rows.push(vec![String::new(), String::new(), String::new(), ui::diff_line(more)]);
            }
        }
        for line in ui::table(&rows) {
            say!("  {line}");
        }
    }
    if !pending.is_empty() {
        say!("{}", ui::bold("Logged, not yet in force"));
        let now = current.tenant.checked_at();
        for p in &pending {
            say!("  state version {}: {}", p.version, watch::when(p, now));
            for d in current.tenant.differences(p.version).unwrap_or_default() {
                say!("    {}", ui::diff_line(&watch::line(&d)));
            }
        }
    }
    Ok(())
}

fn proposal_json<'a>(current: &Current, open: &[Proposal], p: &'a Proposal) -> ProposalJson<'a> {
    let (changes, threshold, root_version) = match check_proposal(current, open, p) {
        Ok((changes, root)) => (changes, root.threshold, root.version),
        Err(e) => (vec![format!("! {e}")], 0, 0),
    };
    let (kind, version) = match &p.document {
        Proposed::State(s) => ("state", s.body.version),
        Proposed::Root(r) => ("root", r.body.version),
    };
    ProposalJson {
        id: &p.id,
        kind,
        version,
        signatures: signature_count(&p.document),
        threshold,
        root_version,
        changes,
    }
}

async fn show(env: &Env, id: &str, json: bool) -> anyhow::Result<()> {
    let admin = env.admin(Scope::Read).await?;
    let current = admin.fetch(&time()).await?;
    let open = admin.proposals().await?;
    let proposal = find(&open, id)?;
    if json {
        println!("{}", serde_json::to_string(&proposal_json(&current, &open, proposal))?);
        return Ok(());
    }
    let (changes, root) = check_proposal(&current, &open, proposal)?;
    say!("{} {}", ui::bold(&what(&proposal.document)), ui::dim(&proposal.id));
    say!(
        "  {} of the {} signatures root version {} needs",
        signature_count(&proposal.document),
        root.threshold,
        root.version
    );
    let signers: Vec<String> = match &proposal.document {
        Proposed::State(s) => s.signatures.iter().map(|s| s.signer.to_string()).collect(),
        Proposed::Root(r) => r.signatures.iter().map(|s| s.signer.to_string()).collect(),
    };
    if !signers.is_empty() {
        say!("  signed by {}", signers.join(", "));
    }
    for line in &changes {
        say!("  {}", ui::diff_line(line));
    }
    say!("  sign it: {}", ui::accent(&env.change_url(&proposal.id)));
    Ok(())
}

/// `seal changes sign ID`: with `--key-file`, adds those signatures (and submits a state that
/// reaches the threshold); without, follows it while the admins sign in the console.
async fn sign(env: &Env, id: &str, passkey: bool) -> anyhow::Result<()> {
    let admin = env.admin(Scope::Submit).await?;
    let time = time();
    let current = admin.fetch(&time).await?;
    let open = admin.proposals().await?;
    let proposal = find(&open, id)?.clone();
    let (changes, root) = check_proposal(&current, &open, &proposal)?;
    let window = current.tenant.state().pending_window_secs;
    let change = match &proposal.document {
        Proposed::State(s) => {
            seal_verify::change::classify(&seal_verify::change::diff_states(current.tenant.state(), &s.body))
        }
        Proposed::Root(_) => Change::Widening,
    };
    let keys = env.keys()?;
    if keys.is_empty() && !passkey {
        say!("{}", ui::bold(&format!("{}: {}", admin.tenant(), what(&proposal.document))));
        for line in &changes {
            say!("  {}", ui::diff_line(line));
        }
        follow(env, &admin, vec![proposal], change, window).await?;
        return Ok(());
    }
    let keys = admin_keys_given(env, &root)?;
    let (mut document, title) = match &proposal.document {
        Proposed::State(s) => (
            Proposed::State(cosign(&root, TENANT_STATE_LABEL, s.clone(), &keys)),
            format!("{}: state version {} → {}", admin.tenant(), current.tenant.state().version, s.body.version),
        ),
        Proposed::Root(r) => (
            Proposed::Root(cosign(&root, TENANT_ROOT_LABEL, r.clone(), &keys)),
            format!("{}: root version {} → {}", admin.tenant(), root.version, r.body.version),
        ),
    };
    if !passkey && signature_count(&document) == signature_count(&proposal.document) {
        bail!("your keys have signed proposal {} already", short(&proposal.id));
    }
    confirm(env, &title, &changes, "Sign")?;
    if passkey {
        sign_with_passkey(&root, &mut document).await?;
    }
    let stored = admin.propose_document(&document).await?;
    match &stored.document {
        Proposed::State(s) if s.body.root_version == root.version && meets_threshold(&root, TENANT_STATE_LABEL, s) => {
            let index = admin.publish(s).await?;
            published(&s.body, index, change, window);
            sign_freshness_if_held(env, &admin, &s.body, &time).await?;
        }
        Proposed::Root(r) if meets_threshold(&root, TENANT_ROOT_LABEL, r) => {
            say!(
                "root version {} has its signatures: `seal changes submit {}` once its state is signed",
                r.body.version,
                short(&stored.id)
            );
        }
        _ => say!(
            "proposal {}: {} of the {} signatures root version {} needs",
            short(&stored.id),
            signature_count(&stored.document),
            root.threshold,
            root.version
        ),
    }
    Ok(())
}

/// Submits a proposal. A root goes only together with a state proposed under it that the new
/// root's threshold signed, since verifiers accept only a state signed by the latest root; the
/// root is submitted first.
async fn submit(env: &Env, id: &str) -> anyhow::Result<()> {
    let admin = env.admin(Scope::Submit).await?;
    let time = time();
    let current = admin.fetch(&time).await?;
    let open = admin.proposals().await?;
    let proposal = find(&open, id)?;
    let (_, root) = check_proposal(&current, &open, proposal)?;
    let state = match &proposal.document {
        Proposed::State(s) => {
            if !meets_threshold(&root, TENANT_STATE_LABEL, s) {
                bail!(
                    "this change needs {} signatures of root version {}; it has {}",
                    root.threshold,
                    root.version,
                    s.signatures.len()
                );
            }
            s.clone()
        }
        Proposed::Root(r) => {
            let state = open
                .iter()
                .find_map(|p| match &p.document {
                    Proposed::State(s)
                        if s.body.root_version == r.body.version && meets_threshold(&r.body, TENANT_STATE_LABEL, s) =>
                    {
                        Some(s.clone())
                    }
                    _ => None,
                })
                .ok_or_else(|| {
                    anyhow!("no state proposed under root version {} has its signatures yet", r.body.version)
                })?;
            let Submitted::Root(link) = admin.submit(&proposal.document).await? else {
                unreachable!("checked by submit")
            };
            say!("{}", ui::ok(&format!("published root version {}", link.root.body.version)));
            state
        }
    };
    let Submitted::State(logged) = admin.submit(&Proposed::State(state)).await? else {
        unreachable!("checked by submit")
    };
    say!(
        "{}",
        ui::ok(&format!(
            "published state version {} (log entry {})",
            logged.state.body.version, logged.proof.leaf_index
        ))
    );
    sign_freshness_if_held(env, &admin, &logged.state.body, &time).await
}
