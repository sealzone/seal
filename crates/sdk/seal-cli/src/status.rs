//! `seal status`, the home screen: the tenant as verified here (its root chain against the
//! trust, its state against the log), its admin keys, grants, pending changes and open
//! proposals. `--log` also scans the transparency log for roots of the tenant outside this
//! chain and for stale freshness statements.

use clap::Args;
use serde_json::json;

use seal_proto::state::TenantState;

use crate::settings::admin_key_json;
use crate::{say, time, ui, watch, Env, Exit, Scope};

#[derive(Args, Debug)]
pub struct StatusArgs {
    /// Also scan the transparency log for roots of this tenant outside its chain, and for
    /// freshness statements older than a logged state (exits 1 when it finds any)
    #[arg(long)]
    pub log: bool,
    /// JSON instead of text
    #[arg(long)]
    pub json: bool,
}

/// `1 app`, `2 apps`.
fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

fn grants(state: &TenantState) -> String {
    let identities: usize = state.apps.values().map(|s| s.len()).sum();
    format!(
        "{} ({}) · {}",
        plural(state.apps.len(), "app", "apps"),
        plural(identities, "identity", "identities"),
        plural(state.deployments.len(), "enclave", "enclaves"),
    ) + &networks(state)
}

/// `; checkout only from 203.0.113.0/24`: each app's network rule, when it has one.
fn networks(state: &TenantState) -> String {
    state
        .app_networks
        .iter()
        .map(|(app, nets)| {
            let nets: Vec<String> = nets.iter().map(ToString::to_string).collect();
            if nets.is_empty() {
                format!("; {app} from no address")
            } else {
                format!("; {app} only from {}", nets.join(", "))
            }
        })
        .collect()
}

pub async fn run(env: &Env, args: StatusArgs) -> anyhow::Result<()> {
    let admin = env.admin(Scope::Read).await?;
    let time = time();
    let current = match admin.fetch(&time).await {
        Ok(current) => current,
        // No bundle yet: show the verified root, and where to sign the first state.
        Err(e) => match admin.documents().await {
            Ok(docs) if docs.states.is_empty() => return unsigned(env, &admin, &docs, args.json).await,
            _ => return Err(e.into()),
        },
    };
    let open = admin.proposals().await.unwrap_or_default();
    let t = &current.tenant;
    let (root, state) = (t.latest_root(), t.state());
    let pending = t.pending();
    let pin = format!("{}@{}", admin.tenant(), t.root_id());
    let platforms: Vec<String> = state.platforms.iter().map(|p| seal::admin::platform_name(*p)).collect();
    let scan = if args.log { Some(admin.verify_roots(&time).await?) } else { None };
    if args.json {
        let keys: Vec<serde_json::Value> = root.admin_keys.iter().map(admin_key_json).collect();
        let mut out = json!({
            "tenant": admin.tenant(),
            "root_id": t.root_id(),
            "workspace": env.config.workspace,
            "root": {"version": root.version, "threshold": root.threshold, "cosign_releases": root.cosign_releases, "admin_keys": keys},
            "state": {"version": state.version, "in_force_since": t.in_force_since(), "pending_window_secs": state.pending_window_secs,
                      "platforms": platforms, "apps": state.apps.len(), "enclaves": state.deployments.len()},
            "latest_state": t.latest_state().version,
            "pending": pending,
            "proposals": open.iter().map(|p| &p.id).collect::<Vec<_>>(),
        });
        if let Some(scan) = &scan {
            out["log"] = json!({ "scanned": scan.scanned, "findings": scan.findings });
        }
        println!("{out}");
        return finish(scan.as_ref());
    }
    let beside = match &env.config.workspace {
        Some(w) => format!("{} {}", ui::bold(admin.tenant().as_str()), ui::dim(&format!("· workspace {w}"))),
        None => ui::bold(admin.tenant().as_str()),
    };
    if let Some(mark) = ui::mark(&beside) {
        say!("{mark}\n");
    }
    let now = t.checked_at();
    let mut rows = vec![
        vec![ui::dim("tenant"), pin],
        vec![
            ui::dim("root"),
            format!(
                "version {} · {}, {} must sign",
                root.version,
                plural(root.admin_keys.len(), "admin key", "admin keys"),
                root.threshold
            ),
        ],
        vec![
            ui::dim("state"),
            format!(
                "version {} in force since {} · pending window {}",
                state.version,
                watch::at(t.in_force_since()),
                watch::span(state.pending_window_secs)
            ),
        ],
        vec![ui::dim("grants"), grants(state)],
        vec![ui::dim("platforms"), if platforms.is_empty() { "none".into() } else { platforms.join(", ") }],
    ];
    if pending.is_empty() {
        rows.push(vec![ui::dim("pending"), ui::dim("nothing")]);
    }
    for (i, p) in pending.iter().enumerate() {
        let label = if i == 0 { ui::dim("pending") } else { String::new() };
        rows.push(vec![label, ui::yellow(&format!("state version {}: {}", p.version, watch::when(p, now)))]);
    }
    rows.push(vec![
        ui::dim("proposals"),
        match open.len() {
            0 => ui::dim("none open"),
            n => format!("{n} waiting for signatures: `seal changes`"),
        },
    ]);
    if env.config.workspace.is_some() {
        rows.push(vec![ui::dim("console"), ui::accent(&env.tenant_url())]);
    }
    for line in ui::table(&rows) {
        say!("{line}");
    }
    say!("{}", ui::dim("verified here: the root chain against the trust, the state against the log"));
    if root.admin_keys.len() == 1 {
        say!("{}", ui::yellow("only one admin key: add a backup key (`seal settings admins`)"));
    }
    if let Some(scan) = &scan {
        match scan.scanned {
            Some(n) => say!("scanned {n} log entries"),
            None => say!("the log does not serve entries: checked the chain and freshness only"),
        }
        if scan.findings.is_empty() {
            say!("{}", ui::ok("no roots outside our chain, no stale freshness statements"));
        }
        for finding in &scan.findings {
            say!("{}", ui::accent(&format!("FOUND: {finding}")));
        }
    }
    finish(scan.as_ref())
}

/// A tenant whose first state isn't signed yet: its verified root and admin keys.
async fn unsigned(
    env: &Env,
    admin: &seal::admin::Admin,
    docs: &seal_verify::VerifiedDocuments,
    json: bool,
) -> anyhow::Result<()> {
    let root = docs.roots.last().expect("a verified chain is not empty").body();
    let open = admin.proposals().await.unwrap_or_default();
    let setup = format!(
        "{}/workspace/new-tenant?w={}&t={}",
        env.console_url()?.as_str().trim_end_matches('/'),
        env.config.workspace.as_deref().unwrap_or_default(),
        admin.tenant()
    );
    if json {
        let keys: Vec<serde_json::Value> = root.admin_keys.iter().map(admin_key_json).collect();
        println!(
            "{}",
            json!({
                "tenant": admin.tenant(),
                "root_id": docs.root_id,
                "workspace": env.config.workspace,
                "root": {"version": root.version, "threshold": root.threshold, "cosign_releases": root.cosign_releases, "admin_keys": keys},
                "state": null,
                "proposals": open.iter().map(|p| &p.id).collect::<Vec<_>>(),
                "setup": setup,
            })
        );
        return Ok(());
    }
    if let Some(mark) = ui::mark(&ui::bold(admin.tenant().as_str())) {
        say!("{mark}\n");
    }
    let rows = vec![
        vec![ui::dim("tenant"), format!("{}@{}", admin.tenant(), docs.root_id)],
        vec![
            ui::dim("root"),
            format!(
                "version {} · {}, {} must sign",
                root.version,
                plural(root.admin_keys.len(), "admin key", "admin keys"),
                root.threshold
            ),
        ],
        vec![ui::dim("state"), "none signed yet: nothing serves this tenant".to_string()],
        vec![
            ui::dim("proposals"),
            if open.is_empty() { "none open".to_string() } else { plural(open.len(), "open", "open") },
        ],
    ];
    for line in ui::table(&rows) {
        say!("{line}");
    }
    say!("{}", ui::dim("verified here: the root chain against the trust and the log"));
    say!("next: sign the first state in the console: {setup}");
    Ok(())
}

fn finish(scan: Option<&seal::admin::RootScan>) -> anyhow::Result<()> {
    match scan {
        Some(scan) if !scan.findings.is_empty() => Err(Exit(1).into()),
        _ => Ok(()),
    }
}
