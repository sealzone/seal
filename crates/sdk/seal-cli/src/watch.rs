//! `seal changes --watch`: the tenant's pending roots and states, from the log and the control
//! plane, verified here (`Admin::fetch`), so a tenant can follow changes without trusting
//! Seal's console. Each pending state is shown with its diff against the state in force, its
//! classification and when it takes effect.

use std::collections::BTreeMap;
use std::time::Duration;

use seal::admin::{describe, platform_name, Admin, Current};
use seal_proto::identity::HostedMode;
use seal_proto::{TrustedTime, UnixTime};
use seal_verify::change::{Change, Difference, Item};
use seal_verify::Pending;
use serde::Serialize;

use crate::say;

/// What `--once` found: its exit status.
pub enum Found {
    /// Nothing pending: exit 0.
    Nothing,
    /// One or more pending states: exit 2.
    Pending,
}

/// A pending state as `--json` prints it, one per line.
#[derive(Serialize)]
struct PendingJson<'a> {
    tenant: &'a str,
    in_force: u64,
    #[serde(flatten)]
    pending: &'a Pending,
    differences: Vec<Difference>,
}

/// RFC 3339.
pub fn time(t: UnixTime) -> String {
    jiff::Timestamp::from_second(i64::try_from(t).unwrap_or(i64::MAX)).map_or_else(|_| t.to_string(), |t| t.to_string())
}

/// For people: `2026-10-27 14:00 UTC`.
pub fn at(t: UnixTime) -> String {
    jiff::Timestamp::from_second(i64::try_from(t).unwrap_or(i64::MAX))
        .map_or_else(|_| t.to_string(), |t| t.strftime("%Y-%m-%d %H:%M UTC").to_string())
}

/// `90` → `1m 30s`, `86400` → `1d`.
pub fn span(secs: u64) -> String {
    if secs == 0 {
        return "0s".into();
    }
    let parts = [(86_400, "d"), (3_600, "h"), (60, "m"), (1, "s")];
    let mut rest = secs;
    let mut out = Vec::new();
    for (unit, name) in parts {
        if rest >= unit {
            out.push(format!("{}{name}", rest / unit));
            rest %= unit;
        }
    }
    out.join(" ")
}

fn tag(change: Change) -> &'static str {
    match change {
        Change::Narrowing => "narrowing",
        Change::Widening => "widening",
    }
}

/// One line for a difference: `+`/`-`/`~`, what, and its classification.
pub fn line(d: &Difference) -> String {
    let what = match &d.item {
        Item::Tenant { old, new } => format!("~ tenant: {old} -> {new}"),
        Item::AppAdded { app } => format!("+ app {app}"),
        Item::AppRemoved { app } => format!("- app {app}"),
        Item::IdentityAdded { app, identity } => format!("+ app {app}: {}", describe(identity)),
        Item::IdentityRemoved { app, identity } => format!("- app {app}: {}", describe(identity)),
        Item::ProducerAdded { identity } => format!("+ producer: {}", describe(identity)),
        Item::ProducerRemoved { identity } => format!("- producer: {}", describe(identity)),
        Item::DeploymentAdded { identity } => format!("+ deployment: {}", describe(identity)),
        Item::DeploymentRemoved { identity } => format!("- deployment: {}", describe(identity)),
        Item::DeploymentMode { identity, old, new } => {
            let whose = |m: &Option<HostedMode>| if m.is_some() { "Seal-hosted" } else { "your own" };
            format!("~ deployment {}: {} -> {}", describe(identity), whose(old), whose(new))
        }
        Item::PlatformAdded { platform } => format!("+ platform: {}", platform_name(*platform)),
        Item::PlatformRemoved { platform } => format!("- platform: {}", platform_name(*platform)),
        Item::OldestAccepted { old, new } => format!("~ oldest accepted tenant key version: {old} -> {new}"),
        Item::CurrentKeyVersion { old, new } => format!("~ tenant key version: {old} -> {new}"),
        Item::ArtifactAdded { app, artifact } => format!("+ allowed artifact for {app}: {}", artifact.name),
        Item::ArtifactRemoved { app, artifact } => format!("- allowed artifact for {app}: {}", artifact.name),
        Item::ArtifactRuleAdded { app } => format!("+ artifact check for {app}"),
        Item::ArtifactRuleRemoved { app } => format!("- artifact check for {app}"),
        Item::NetworkRuleAdded { app, networks } => format!(
            "+ network rule for {app}: sessions only from {}",
            networks.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
        ),
        Item::NetworkRuleRemoved { app } => format!("- network rule for {app}: sessions from any address"),
        Item::NetworkAdded { app, network } => format!("+ network for {app}: {network}"),
        Item::NetworkRemoved { app, network } => format!("- network for {app}: {network}"),
        Item::SourceAdded { source, key } => format!("+ integrity source {source}: {key}"),
        Item::SourceRemoved { source, key } => format!("- integrity source {source}: {key}"),
        Item::SourceRekeyed { source, old, new } => format!("~ integrity source {source}: {old} -> {new}"),
        Item::Action { severity, old, new } => {
            format!("~ integrity action at {}: {old:?} -> {new:?}", format!("{severity:?}").to_lowercase())
        }
        Item::ClearanceAdded { clearance } => {
            format!(
                "+ clearance: {} before {}",
                serde_json::to_string(&clearance.identity).unwrap_or_default(),
                clearance.before
            )
        }
        Item::ClearanceRemoved { clearance } => {
            format!(
                "- clearance: {} before {}",
                serde_json::to_string(&clearance.identity).unwrap_or_default(),
                clearance.before
            )
        }
        Item::FreshnessKeyAdded { key } => format!("+ freshness key: {key}"),
        Item::FreshnessKeyRemoved { key } => format!("- freshness key: {key}"),
        Item::TelemetryReaderAdded { key } => format!("+ telemetry reader: {key}"),
        Item::TelemetryReaderRemoved { key } => format!("- telemetry reader: {key}"),
        Item::PendingWindow { old, new } => format!("~ pending window: {} -> {}", span(*old), span(*new)),
        Item::AdminKeyAdded { key } => format!("+ admin key {}", seal_crypto::sign::admin_key_id(key)),
        Item::AdminKeyRemoved { key } => format!("- admin key {}", seal_crypto::sign::admin_key_id(key)),
        Item::Threshold { old, new } => format!("~ threshold: {old} -> {new}"),
        Item::CosignReleases { old, new } => format!("~ co-signed releases: {old} -> {new}"),
    };
    format!("{what} ({})", tag(d.change))
}

/// When `pending` takes effect, for people.
pub fn when(pending: &Pending, now: UnixTime) -> String {
    match pending.effective_at {
        None => "never: signed under an older root than the one in force".into(),
        Some(t) if pending.change == Change::Narrowing => format!("applies at once (from {})", at(t)),
        Some(t) if t <= now => format!("takes effect now ({})", at(t)),
        Some(t) => format!("takes effect in {}, at {}, unless an admin cancels it", span(t - now), at(t)),
    }
}

fn print_status(current: &Current) {
    let t = &current.tenant;
    say!(
        "{}: state version {} in force (root version {}, since {}), pending window {}; latest logged state {}",
        t.state().tenant,
        t.state().version,
        t.root().version,
        at(t.in_force_since()),
        span(t.state().pending_window_secs),
        t.latest_state().version
    );
}

fn print_pending(current: &Current, pending: &Pending, json: bool) {
    let t = &current.tenant;
    let Some(differences) = t.differences(pending.version) else { return };
    if json {
        let line = PendingJson { tenant: t.state().tenant.as_str(), in_force: t.state().version, pending, differences };
        println!("{}", serde_json::to_string(&line).unwrap_or_default());
        return;
    }
    say!(
        "pending state version {} (root version {}), public since {}, {}: {}",
        pending.version,
        pending.root_version,
        at(pending.public_since),
        tag(pending.change),
        crate::ui::yellow(&when(pending, t.checked_at()))
    );
    if differences.is_empty() {
        say!("  (no change from the state in force)");
    }
    for d in &differences {
        say!("  {}", crate::ui::diff_line(&line(d)));
    }
}

/// `--once`: the status and every pending state.
pub async fn once(admin: &Admin, time: &TrustedTime, json: bool) -> anyhow::Result<Found> {
    let current = admin.fetch(time).await?;
    let pending = current.tenant.pending();
    if !json {
        print_status(&current);
    }
    for p in &pending {
        print_pending(&current, p, json);
    }
    Ok(if pending.is_empty() { Found::Nothing } else { Found::Pending })
}

/// Follows the tenant every `interval`: prints each newly pending state once, and when it
/// takes effect or is superseded. Network errors are reported and retried; a bundle that
/// does not verify ends the watch with an error.
pub async fn follow(
    admin: &Admin,
    interval: Duration,
    json: bool,
    now: impl Fn() -> TrustedTime,
) -> anyhow::Result<()> {
    let mut seen: BTreeMap<u64, Pending> = BTreeMap::new();
    let mut in_force = None;
    loop {
        match admin.fetch(&now()).await {
            Ok(current) => {
                let t = &current.tenant;
                let version = t.state().version;
                if in_force != Some(version) {
                    if !json {
                        print_status(&current);
                    }
                    in_force = Some(version);
                }
                let pending = t.pending();
                for p in &pending {
                    if let std::collections::btree_map::Entry::Vacant(e) = seen.entry(p.version) {
                        print_pending(&current, p, json);
                        e.insert(p.clone());
                    }
                }
                let gone: Vec<u64> =
                    seen.keys().copied().filter(|v| !pending.iter().any(|p| p.version == *v)).collect();
                for v in gone {
                    seen.remove(&v);
                    if json {
                        continue;
                    }
                    if v == version {
                        say!("{}", crate::ui::ok(&format!("state version {v} took effect")));
                    } else {
                        say!("state version {v} never takes effect: state version {version} is in force");
                    }
                }
            }
            Err(e @ seal::ClientError::Verification(_)) => return Err(e.into()),
            Err(e) => eprintln!("seal: {e} (retrying)"),
        }
        tokio::time::sleep(interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spans_read_naturally() {
        assert_eq!(span(0), "0s");
        assert_eq!(span(90), "1m 30s");
        assert_eq!(span(86_400), "1d");
        assert_eq!(span(90_061), "1d 1h 1m 1s");
    }

    #[test]
    fn lines_say_their_classification() {
        let d = Difference { change: Change::Widening, item: Item::PendingWindow { old: 3_600, new: 0 } };
        assert_eq!(line(&d), "~ pending window: 1h -> 0s (widening)");
        let pending = Pending {
            version: 4,
            root_version: 1,
            change: Change::Widening,
            public_since: 100,
            effective_at: Some(3_700),
        };
        assert!(when(&pending, 100).starts_with("takes effect in 1h, at 1970-01-01 01:01 UTC"));
        assert!(when(&pending, 4_000).starts_with("takes effect now"));
        let never = Pending { effective_at: None, ..pending };
        assert!(when(&never, 100).starts_with("never"));
    }
}
