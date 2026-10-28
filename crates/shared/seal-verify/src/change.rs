//! What a newer tenant document changes, and whether that narrows or widens access.
//!
//! The pending window rests on this classification: a document that narrows the one in force
//! applies at once; one that widens it waits in public for the window first. Both functions
//! are pure functions of the two documents. A difference is narrowing only when it provably
//! removes access; everything else, including any change this module does not know, is
//! widening.
//!
//! | Field | Narrowing | Widening |
//! | --- | --- | --- |
//! | `apps` | removing an app or an identity | adding an app or an identity |
//! | `producers`, `deployments` | removing one | adding one |
//! | a deployment's `hosted` mark (Azure or Confidential Space) | setting it (the replica becomes Seal's, which idles out) | clearing it |
//! | `platforms` | removing one | adding one |
//! | `tenant_key_versions` | raising `oldest_accepted` (retiring); raising `current` | lowering either |
//! | `integrity.artifacts` | removing an allowed artifact; listing a new app | adding an artifact; unlisting an app |
//! | `integrity.sources` | | adding, removing or rekeying a source (removing one lifts its suspensions) |
//! | `integrity.actions` | a harder action for some severity | a softer one |
//! | `integrity.cleared` | removing a clearance | adding a clearance (it lifts suspensions) |
//! | `freshness_keys` | adding one | removing one |
//! | `telemetry_readers` | removing one while others remain | adding one; removing the last |
//! | `pending_window_secs` | lengthening | shortening |
//! | root `admin_keys` | | adding or removing a key |
//! | root `threshold` | raising | lowering |
//! | root `cosign_releases` | turning it on | turning it off |
//!
//! `version`, `root_version` and `issued_at` are not changes of access. A document for
//! another tenant is widening.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use seal_proto::identity::{HostedMode, IdentityMatcher};
use seal_proto::integrity::{ArtifactHash, Clearance, IntegrityAction, Severity};
use seal_proto::net::Cidr;
use seal_proto::state::{AdminKey, TenantRoot, TenantState};
use seal_proto::{AppName, PlatformId, PublicKey, TenantId, TenantKeyVersion};

/// How a newer document compares with the one in force.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Change {
    /// Removes access or changes nothing: applies at once.
    Narrowing,
    /// Adds access, or cannot be shown not to: waits the pending window.
    Widening,
}

/// One difference between two documents and its classification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Difference {
    pub change: Change,
    pub item: Item,
}

/// What changed. Serialized with a `kind` tag.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Item {
    Tenant {
        old: TenantId,
        new: TenantId,
    },
    AppAdded {
        app: AppName,
    },
    AppRemoved {
        app: AppName,
    },
    IdentityAdded {
        app: AppName,
        identity: IdentityMatcher,
    },
    IdentityRemoved {
        app: AppName,
        identity: IdentityMatcher,
    },
    ProducerAdded {
        identity: IdentityMatcher,
    },
    ProducerRemoved {
        identity: IdentityMatcher,
    },
    DeploymentAdded {
        identity: IdentityMatcher,
    },
    DeploymentRemoved {
        identity: IdentityMatcher,
    },
    /// The same deployment identity with its `hosted` mark set or cleared (`identity` shows the
    /// new entry).
    DeploymentMode {
        identity: IdentityMatcher,
        old: Option<HostedMode>,
        new: Option<HostedMode>,
    },
    PlatformAdded {
        platform: PlatformId,
    },
    PlatformRemoved {
        platform: PlatformId,
    },
    OldestAccepted {
        old: TenantKeyVersion,
        new: TenantKeyVersion,
    },
    CurrentKeyVersion {
        old: TenantKeyVersion,
        new: TenantKeyVersion,
    },
    ArtifactAdded {
        app: AppName,
        artifact: ArtifactHash,
    },
    ArtifactRemoved {
        app: AppName,
        artifact: ArtifactHash,
    },
    /// The app is now checked against its allowed artifacts.
    ArtifactRuleAdded {
        app: AppName,
    },
    /// The app is no longer checked against allowed artifacts.
    ArtifactRuleRemoved {
        app: AppName,
    },
    /// The app now starts sessions only from these networks (`TenantState::app_networks`).
    NetworkRuleAdded {
        app: AppName,
        networks: BTreeSet<Cidr>,
    },
    /// The app may start sessions from any address again.
    NetworkRuleRemoved {
        app: AppName,
    },
    NetworkAdded {
        app: AppName,
        network: Cidr,
    },
    NetworkRemoved {
        app: AppName,
        network: Cidr,
    },
    SourceAdded {
        source: String,
        key: PublicKey,
    },
    SourceRemoved {
        source: String,
        key: PublicKey,
    },
    SourceRekeyed {
        source: String,
        old: PublicKey,
        new: PublicKey,
    },
    /// The action for this severity (`IntegrityPolicy::action_for`).
    Action {
        severity: Severity,
        old: IntegrityAction,
        new: IntegrityAction,
    },
    ClearanceAdded {
        clearance: Clearance,
    },
    ClearanceRemoved {
        clearance: Clearance,
    },
    FreshnessKeyAdded {
        key: PublicKey,
    },
    FreshnessKeyRemoved {
        key: PublicKey,
    },
    TelemetryReaderAdded {
        key: PublicKey,
    },
    TelemetryReaderRemoved {
        key: PublicKey,
    },
    /// `TenantState::pending_window` (seconds).
    PendingWindow {
        old: u64,
        new: u64,
    },
    AdminKeyAdded {
        key: AdminKey,
    },
    AdminKeyRemoved {
        key: AdminKey,
    },
    Threshold {
        old: u8,
        new: u8,
    },
    CosignReleases {
        old: bool,
        new: bool,
    },
}

/// `Widening` when any difference widens, else `Narrowing` (including no difference).
pub fn classify(differences: &[Difference]) -> Change {
    if differences.iter().any(|d| d.change == Change::Widening) {
        Change::Widening
    } else {
        Change::Narrowing
    }
}

/// How `new` changes access relative to `old` (the state in force).
pub fn classify_state(old: &TenantState, new: &TenantState) -> Change {
    classify(&diff_states(old, new))
}

/// How `new` changes access relative to `old` (the root in force).
pub fn classify_root(old: &TenantRoot, new: &TenantRoot) -> Change {
    classify(&diff_roots(old, new))
}

const SEVERITIES: [Severity; 4] = [Severity::Low, Severity::Medium, Severity::High, Severity::Critical];

struct Diff(Vec<Difference>);

impl Diff {
    fn push(&mut self, change: Change, item: Item) {
        self.0.push(Difference { change, item });
    }
    fn when(&mut self, widening: bool, item: Item) {
        self.push(if widening { Change::Widening } else { Change::Narrowing }, item);
    }
    /// Added members widen, removed ones narrow (or the reverse with `added_narrows`).
    fn sets<T: Ord + Clone>(
        &mut self,
        old: &BTreeSet<T>,
        new: &BTreeSet<T>,
        added_narrows: bool,
        added: impl Fn(T) -> Item,
        removed: impl Fn(T) -> Item,
    ) {
        for x in new.difference(old) {
            self.when(!added_narrows, added(x.clone()));
        }
        for x in old.difference(new) {
            self.when(added_narrows, removed(x.clone()));
        }
    }
}

/// Every difference from `old` to `new`, in field order.
pub fn diff_states(old: &TenantState, new: &TenantState) -> Vec<Difference> {
    let mut d = Diff(Vec::new());
    if old.tenant != new.tenant {
        d.push(Change::Widening, Item::Tenant { old: old.tenant.clone(), new: new.tenant.clone() });
    }

    let empty = BTreeSet::new();
    for (app, identities) in &new.apps {
        if !old.apps.contains_key(app) {
            d.push(Change::Widening, Item::AppAdded { app: app.clone() });
        }
        let before = old.apps.get(app).unwrap_or(&empty);
        for identity in identities.difference(before) {
            d.push(Change::Widening, Item::IdentityAdded { app: app.clone(), identity: identity.clone() });
        }
    }
    for (app, identities) in &old.apps {
        let after = new.apps.get(app).unwrap_or(&empty);
        for identity in identities.difference(after) {
            d.push(Change::Narrowing, Item::IdentityRemoved { app: app.clone(), identity: identity.clone() });
        }
        if !new.apps.contains_key(app) {
            d.push(Change::Narrowing, Item::AppRemoved { app: app.clone() });
        }
    }

    d.sets(
        &old.producers,
        &new.producers,
        false,
        |identity| Item::ProducerAdded { identity },
        |identity| Item::ProducerRemoved { identity },
    );
    deployments(&mut d, &old.deployments, &new.deployments);
    d.sets(
        &old.platforms,
        &new.platforms,
        false,
        |platform| Item::PlatformAdded { platform },
        |platform| Item::PlatformRemoved { platform },
    );

    let (ov, nv) = (old.tenant_key_versions, new.tenant_key_versions);
    if ov.oldest_accepted != nv.oldest_accepted {
        d.when(
            nv.oldest_accepted < ov.oldest_accepted,
            Item::OldestAccepted { old: ov.oldest_accepted, new: nv.oldest_accepted },
        );
    }
    if ov.current != nv.current {
        d.when(nv.current < ov.current, Item::CurrentKeyVersion { old: ov.current, new: nv.current });
    }

    let (oi, ni) = (&old.integrity, &new.integrity);
    for (app, allowed) in &ni.artifacts {
        match oi.artifacts.get(app) {
            None => d.push(Change::Narrowing, Item::ArtifactRuleAdded { app: app.clone() }),
            Some(before) => {
                for artifact in allowed.difference(before) {
                    d.push(Change::Widening, Item::ArtifactAdded { app: app.clone(), artifact: artifact.clone() });
                }
                for artifact in before.difference(allowed) {
                    d.push(Change::Narrowing, Item::ArtifactRemoved { app: app.clone(), artifact: artifact.clone() });
                }
            }
        }
    }
    for app in oi.artifacts.keys().filter(|app| !ni.artifacts.contains_key(*app)) {
        d.push(Change::Widening, Item::ArtifactRuleRemoved { app: app.clone() });
    }

    // Networks, like artifact rules: a first rule narrows, a further network widens, removing a
    // network narrows, removing the rule (any address again) widens.
    for (app, networks) in &new.app_networks {
        match old.app_networks.get(app) {
            None => d.push(Change::Narrowing, Item::NetworkRuleAdded { app: app.clone(), networks: networks.clone() }),
            Some(before) => {
                for network in networks.difference(before) {
                    d.push(Change::Widening, Item::NetworkAdded { app: app.clone(), network: *network });
                }
                for network in before.difference(networks) {
                    d.push(Change::Narrowing, Item::NetworkRemoved { app: app.clone(), network: *network });
                }
            }
        }
    }
    for app in old.app_networks.keys().filter(|app| !new.app_networks.contains_key(*app)) {
        d.push(Change::Widening, Item::NetworkRuleRemoved { app: app.clone() });
    }

    sources(&mut d, &oi.sources, &ni.sources);

    for severity in SEVERITIES {
        let (o, n) = (oi.action_for(severity), ni.action_for(severity));
        if o != n {
            d.when(strictness(n) < strictness(o), Item::Action { severity, old: o, new: n });
        }
    }

    d.sets(
        &oi.cleared,
        &ni.cleared,
        false,
        |clearance| Item::ClearanceAdded { clearance },
        |clearance| Item::ClearanceRemoved { clearance },
    );
    d.sets(
        &old.freshness_keys,
        &new.freshness_keys,
        true,
        |key| Item::FreshnessKeyAdded { key },
        |key| Item::FreshnessKeyRemoved { key },
    );

    for key in new.telemetry_readers.difference(&old.telemetry_readers) {
        d.push(Change::Widening, Item::TelemetryReaderAdded { key: *key });
    }
    for key in old.telemetry_readers.difference(&new.telemetry_readers) {
        // Removing the last reader sends telemetry in clear.
        d.when(new.telemetry_readers.is_empty(), Item::TelemetryReaderRemoved { key: *key });
    }

    let (ow, nw) = (old.pending_window_secs, new.pending_window_secs);
    if ow != nw {
        d.when(nw < ow, Item::PendingWindow { old: ow, new: nw });
    }
    d.0
}

/// `matcher` without its hosted mark: the deployment identity it names.
fn identity_of(matcher: &IdentityMatcher) -> IdentityMatcher {
    match matcher {
        IdentityMatcher::Azure { entra_tenant, object_id, audience, .. } => IdentityMatcher::Azure {
            entra_tenant: entra_tenant.clone(),
            object_id: object_id.clone(),
            audience: audience.clone(),
            hosted: None,
        },
        IdentityMatcher::ConfidentialSpace { project_number, service_account, .. } => {
            IdentityMatcher::ConfidentialSpace {
                project_number: *project_number,
                service_account: service_account.clone(),
                hosted: None,
            }
        }
        other => other.clone(),
    }
}

/// Added deployments widen and removed ones narrow, except that an entry whose identity is
/// also removed is a change of its hosted mark: setting it narrows (the replicas become Seal's,
/// which idle out), clearing it widens.
fn deployments(d: &mut Diff, old: &BTreeSet<IdentityMatcher>, new: &BTreeSet<IdentityMatcher>) {
    let removed: Vec<&IdentityMatcher> = old.difference(new).collect();
    let mut paired = BTreeSet::new();
    for added in new.difference(old) {
        let before = removed.iter().find(|r| !paired.contains(**r) && identity_of(r) == identity_of(added));
        match before {
            Some(before) => {
                paired.insert((*before).clone());
                let (o, n) = (before.hosted(), added.hosted());
                d.when(o.is_some() && n.is_none(), Item::DeploymentMode { identity: added.clone(), old: o, new: n });
            }
            None => d.push(Change::Widening, Item::DeploymentAdded { identity: added.clone() }),
        }
    }
    for identity in removed.into_iter().filter(|r| !paired.contains(*r)) {
        d.push(Change::Narrowing, Item::DeploymentRemoved { identity: identity.clone() });
    }
}

fn sources(d: &mut Diff, old: &BTreeMap<String, PublicKey>, new: &BTreeMap<String, PublicKey>) {
    for (source, key) in new {
        match old.get(source) {
            None => d.push(Change::Widening, Item::SourceAdded { source: source.clone(), key: *key }),
            Some(before) if before != key => {
                d.push(Change::Widening, Item::SourceRekeyed { source: source.clone(), old: *before, new: *key })
            }
            Some(_) => {}
        }
    }
    for (source, key) in old.iter().filter(|(s, _)| !new.contains_key(*s)) {
        d.push(Change::Widening, Item::SourceRemoved { source: source.clone(), key: *key });
    }
}

/// How hard an action is: log only < deny < suspend for longer < suspend until cleared.
fn strictness(action: IntegrityAction) -> (u8, u64) {
    match action {
        IntegrityAction::LogOnly => (0, 0),
        IntegrityAction::Deny => (1, 0),
        IntegrityAction::Suspend { secs: Some(secs) } => (2, secs),
        IntegrityAction::Suspend { secs: None } => (3, 0),
    }
}

/// Every difference from `old` to `new` (roots), in field order.
pub fn diff_roots(old: &TenantRoot, new: &TenantRoot) -> Vec<Difference> {
    let mut d = Diff(Vec::new());
    if old.tenant != new.tenant {
        d.push(Change::Widening, Item::Tenant { old: old.tenant.clone(), new: new.tenant.clone() });
    }
    // Removing an admin key also removes someone who could veto a pending change.
    for key in new.admin_keys.difference(&old.admin_keys) {
        d.push(Change::Widening, Item::AdminKeyAdded { key: key.clone() });
    }
    for key in old.admin_keys.difference(&new.admin_keys) {
        d.push(Change::Widening, Item::AdminKeyRemoved { key: key.clone() });
    }
    if old.threshold != new.threshold {
        d.when(new.threshold < old.threshold, Item::Threshold { old: old.threshold, new: new.threshold });
    }
    if old.cosign_releases != new.cosign_releases {
        d.when(!new.cosign_releases, Item::CosignReleases { old: old.cosign_releases, new: new.cosign_releases });
    }
    d.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use seal_proto::identity::WorkloadIdentity;
    use seal_proto::integrity::IntegrityPolicy;
    use seal_proto::state::TenantKeyVersions;
    use seal_proto::KeyId;

    fn app(name: &str) -> AppName {
        AppName::new(name).unwrap()
    }
    fn id(n: u8) -> IdentityMatcher {
        IdentityMatcher::AppKey { key_id: KeyId([n; 32]), public_key: PublicKey([n; 32]) }
    }
    fn artifact(n: u8) -> ArtifactHash {
        ArtifactHash { name: "image".into(), sha256: [n; 32] }
    }
    fn net(s: &str) -> Cidr {
        s.parse().unwrap()
    }
    fn clearance(n: u8) -> Clearance {
        Clearance { identity: WorkloadIdentity::AppKey { key_id: KeyId([n; 32]) }, before: 100 }
    }

    /// Every field set, so each test can add to or take from it.
    fn base() -> TenantState {
        TenantState {
            tenant: TenantId::new("acme").unwrap(),
            version: 1,
            root_version: 1,
            apps: [(app("checkout"), [id(1), id(2)].into())].into(),
            producers: [id(3), id(4)].into(),
            tenant_key_versions: TenantKeyVersions {
                current: TenantKeyVersion(3),
                oldest_accepted: TenantKeyVersion(2),
            },
            platforms: [PlatformId::Sim, PlatformId::AzureSnpAci].into(),
            integrity: IntegrityPolicy {
                artifacts: [(app("checkout"), [artifact(1), artifact(2)].into())].into(),
                sources: [("edr".to_string(), PublicKey([9; 32]))].into(),
                actions: [(Severity::High, IntegrityAction::Suspend { secs: Some(60) })].into(),
                cleared: [clearance(1), clearance(2)].into(),
            },
            deployments: [id(5), id(6)].into(),
            freshness_keys: [PublicKey([7; 32])].into(),
            telemetry_readers: [PublicKey([8; 32]), PublicKey([10; 32])].into(),
            issued_at: 1,
            pending_window_secs: 3600,
            app_networks: [(app("checkout"), [net("203.0.113.0/24"), net("198.51.100.7/32")].into())].into(),
        }
    }

    /// The classification of `edit` applied to `base()`, and its one difference.
    fn one(edit: impl FnOnce(&mut TenantState)) -> (Change, Item) {
        let old = base();
        let mut new = old.clone();
        edit(&mut new);
        let d = diff_states(&old, &new);
        assert_eq!(d.len(), 1, "{d:?}");
        assert_eq!(classify_state(&old, &new), d[0].change);
        (d[0].change, d[0].item.clone())
    }
    fn narrows(edit: impl FnOnce(&mut TenantState)) -> Item {
        let (change, item) = one(edit);
        assert_eq!(change, Change::Narrowing, "{item:?}");
        item
    }
    fn widens(edit: impl FnOnce(&mut TenantState)) -> Item {
        let (change, item) = one(edit);
        assert_eq!(change, Change::Widening, "{item:?}");
        item
    }

    #[test]
    fn metadata_and_no_change_narrow() {
        let old = base();
        let mut new = old.clone();
        new.version = 9;
        new.root_version = 4;
        new.issued_at = 99;
        assert!(diff_states(&old, &new).is_empty());
        assert_eq!(classify_state(&old, &new), Change::Narrowing);
    }

    #[test]
    fn another_tenant_widens() {
        widens(|s| s.tenant = TenantId::new("other").unwrap());
    }

    #[test]
    fn apps() {
        let checkout = app("checkout");
        let item = narrows(|s| {
            s.apps.get_mut(&checkout).unwrap().remove(&id(1));
        });
        assert_eq!(item, Item::IdentityRemoved { app: checkout.clone(), identity: id(1) });
        let item = widens(|s| {
            s.apps.get_mut(&checkout).unwrap().insert(id(9));
        });
        assert_eq!(item, Item::IdentityAdded { app: checkout.clone(), identity: id(9) });
        // Adding an app, even with no identity yet.
        let item = widens(|s| {
            s.apps.insert(app("billing"), BTreeSet::new());
        });
        assert_eq!(item, Item::AppAdded { app: app("billing") });
        // Removing an app removes its identities too: all narrowing.
        let old = base();
        let mut new = old.clone();
        new.apps.clear();
        let d = diff_states(&old, &new);
        assert_eq!(d.len(), 3);
        assert_eq!(classify(&d), Change::Narrowing);
        assert!(d.contains(&Difference { change: Change::Narrowing, item: Item::AppRemoved { app: checkout.clone() } }));
        // Adding an app with an identity: both widen.
        let mut added = old.clone();
        added.apps.insert(app("billing"), [id(9)].into());
        assert_eq!(classify_state(&old, &added), Change::Widening);
        assert_eq!(diff_states(&old, &added).len(), 2);
        // Moving an identity to another app widens.
        let mut moved = old.clone();
        moved.apps.get_mut(&checkout).unwrap().remove(&id(1));
        moved.apps.insert(app("billing"), [id(1)].into());
        assert_eq!(classify_state(&old, &moved), Change::Widening);
    }

    #[test]
    fn producers_deployments_platforms() {
        let item = narrows(|s| {
            s.producers.remove(&id(3));
        });
        assert_eq!(item, Item::ProducerRemoved { identity: id(3) });
        let item = widens(|s| {
            s.producers.insert(id(9));
        });
        assert_eq!(item, Item::ProducerAdded { identity: id(9) });
        let item = narrows(|s| {
            s.deployments.remove(&id(5));
        });
        assert_eq!(item, Item::DeploymentRemoved { identity: id(5) });
        let item = widens(|s| {
            s.deployments.insert(id(9));
        });
        assert_eq!(item, Item::DeploymentAdded { identity: id(9) });
        let item = narrows(|s| {
            s.platforms.remove(&PlatformId::Sim);
        });
        assert_eq!(item, Item::PlatformRemoved { platform: PlatformId::Sim });
        let item = widens(|s| {
            s.platforms.insert(PlatformId::AwsNitro);
        });
        assert_eq!(item, Item::PlatformAdded { platform: PlatformId::AwsNitro });
    }

    #[test]
    fn hosted_marks() {
        hosted_marks_of(|mode| IdentityMatcher::ConfidentialSpace {
            project_number: 7,
            service_account: "acme@seal".into(),
            hosted: mode,
        });
        hosted_marks_of(|mode| IdentityMatcher::Azure {
            entra_tenant: "tid".into(),
            object_id: "oid".into(),
            audience: "api://seal-hosted".into(),
            hosted: mode,
        });
    }

    /// The same rules for each kind of hosted identity, `hosted(mode)`.
    fn hosted_marks_of(hosted: fn(Option<HostedMode>) -> IdentityMatcher) {
        let sessions = Some(HostedMode::Sessions);
        let with = |mode| {
            let mut s = base();
            s.deployments.insert(hosted(mode));
            s
        };
        let change = |from, to| {
            let d = diff_states(&with(from), &with(to));
            assert_eq!(d.len(), 1, "{d:?}");
            assert_eq!(d[0].item, Item::DeploymentMode { identity: hosted(to), old: from, new: to });
            d[0].change
        };
        assert_eq!(change(None, sessions), Change::Narrowing);
        assert_eq!(change(sessions, None), Change::Widening);
        // Removing the hosted entry narrows; adding one widens.
        assert_eq!(classify_state(&with(sessions), &base()), Change::Narrowing);
        assert_eq!(classify_state(&base(), &with(sessions)), Change::Widening);
        // Another identity is not a change of mark.
        let mut other = base();
        other.deployments.insert(match hosted(sessions) {
            IdentityMatcher::Azure { entra_tenant, audience, hosted, .. } => {
                IdentityMatcher::Azure { entra_tenant, object_id: "another".into(), audience, hosted }
            }
            _ => IdentityMatcher::ConfidentialSpace {
                project_number: 8,
                service_account: "acme@seal".into(),
                hosted: sessions,
            },
        });
        let d = diff_states(&with(sessions), &other);
        assert_eq!(d.len(), 2);
        assert_eq!(classify(&d), Change::Widening);
    }

    #[test]
    fn tenant_key_versions() {
        let (v1, v2, v3, v4) = (TenantKeyVersion(1), TenantKeyVersion(2), TenantKeyVersion(3), TenantKeyVersion(4));
        assert_eq!(narrows(|s| s.tenant_key_versions.oldest_accepted = v3), Item::OldestAccepted { old: v2, new: v3 });
        assert_eq!(widens(|s| s.tenant_key_versions.oldest_accepted = v1), Item::OldestAccepted { old: v2, new: v1 });
        assert_eq!(narrows(|s| s.tenant_key_versions.current = v4), Item::CurrentKeyVersion { old: v3, new: v4 });
        assert_eq!(widens(|s| s.tenant_key_versions.current = v2), Item::CurrentKeyVersion { old: v3, new: v2 });
    }

    #[test]
    fn artifacts() {
        let checkout = app("checkout");
        let item = narrows(|s| {
            s.integrity.artifacts.get_mut(&checkout).unwrap().remove(&artifact(1));
        });
        assert_eq!(item, Item::ArtifactRemoved { app: checkout.clone(), artifact: artifact(1) });
        let item = widens(|s| {
            s.integrity.artifacts.get_mut(&checkout).unwrap().insert(artifact(9));
        });
        assert_eq!(item, Item::ArtifactAdded { app: checkout.clone(), artifact: artifact(9) });
        let item = narrows(|s| {
            s.integrity.artifacts.insert(app("billing"), [artifact(3)].into());
        });
        assert_eq!(item, Item::ArtifactRuleAdded { app: app("billing") });
        let item = widens(|s| {
            s.integrity.artifacts.remove(&checkout);
        });
        assert_eq!(item, Item::ArtifactRuleRemoved { app: checkout });
    }

    #[test]
    fn networks() {
        let checkout = app("checkout");
        let item = narrows(|s| {
            s.app_networks.get_mut(&checkout).unwrap().remove(&net("198.51.100.7/32"));
        });
        assert_eq!(item, Item::NetworkRemoved { app: checkout.clone(), network: net("198.51.100.7/32") });
        let item = widens(|s| {
            s.app_networks.get_mut(&checkout).unwrap().insert(net("2001:db8::/32"));
        });
        assert_eq!(item, Item::NetworkAdded { app: checkout.clone(), network: net("2001:db8::/32") });
        let item = narrows(|s| {
            s.app_networks.insert(app("billing"), [net("10.0.0.0/8")].into());
        });
        assert_eq!(item, Item::NetworkRuleAdded { app: app("billing"), networks: [net("10.0.0.0/8")].into() });
        let item = widens(|s| {
            s.app_networks.remove(&checkout);
        });
        assert_eq!(item, Item::NetworkRuleRemoved { app: checkout.clone() });
        // Emptying the rule keeps it: the app may then connect from nowhere.
        let (old, mut new) = (base(), base());
        new.app_networks.insert(checkout.clone(), BTreeSet::new());
        assert_eq!(classify_state(&old, &new), Change::Narrowing);
    }

    #[test]
    fn sources() {
        let (key, other, rekey) = (PublicKey([9; 32]), PublicKey([11; 32]), PublicKey([12; 32]));
        let item = widens(|s| {
            s.integrity.sources.insert("siem".into(), other);
        });
        assert_eq!(item, Item::SourceAdded { source: "siem".into(), key: other });
        // Removing a source voids its signals and lifts their suspensions.
        let item = widens(|s| {
            s.integrity.sources.remove("edr");
        });
        assert_eq!(item, Item::SourceRemoved { source: "edr".into(), key });
        let item = widens(|s| {
            s.integrity.sources.insert("edr".into(), rekey);
        });
        assert_eq!(item, Item::SourceRekeyed { source: "edr".into(), old: key, new: rekey });
    }

    #[test]
    fn actions_compare_per_severity() {
        let suspend = |secs| IntegrityAction::Suspend { secs };
        // Base: Low and Medium log only, High and Critical suspend 60 s.
        let old = base();
        let with = |actions: &[(Severity, IntegrityAction)]| {
            let mut new = old.clone();
            new.integrity.actions = actions.iter().copied().collect();
            classify_state(&old, &new)
        };
        assert_eq!(with(&[(Severity::High, suspend(Some(61)))]), Change::Narrowing, "longer");
        assert_eq!(with(&[(Severity::High, suspend(None))]), Change::Narrowing, "until cleared");
        assert_eq!(
            with(&[(Severity::Low, IntegrityAction::Deny), (Severity::High, suspend(Some(60)))]),
            Change::Narrowing
        );
        assert_eq!(with(&[(Severity::High, suspend(Some(59)))]), Change::Widening, "shorter");
        assert_eq!(with(&[(Severity::High, IntegrityAction::Deny)]), Change::Widening);
        assert_eq!(with(&[]), Change::Widening, "empty = log only");
        assert_eq!(with(&[(Severity::Critical, suspend(Some(60)))]), Change::Widening, "High now logs only");
        assert_eq!(with(&[(Severity::Medium, suspend(Some(60)))]), Change::Narrowing, "from Medium up");
        // The same actions written differently are no change.
        let mut same = old.clone();
        same.integrity.actions.insert(Severity::Critical, suspend(Some(60)));
        assert!(diff_states(&old, &same).is_empty());
        let item = narrows(|s| {
            s.integrity.actions.insert(Severity::Medium, IntegrityAction::Deny);
        });
        let (log_only, deny) = (IntegrityAction::LogOnly, IntegrityAction::Deny);
        assert_eq!(item, Item::Action { severity: Severity::Medium, old: log_only, new: deny });
    }

    #[test]
    fn clearances() {
        let item = widens(|s| {
            s.integrity.cleared.insert(clearance(3));
        });
        assert_eq!(item, Item::ClearanceAdded { clearance: clearance(3) });
        let item = narrows(|s| {
            s.integrity.cleared.remove(&clearance(1));
        });
        assert_eq!(item, Item::ClearanceRemoved { clearance: clearance(1) });
    }

    #[test]
    fn freshness_keys() {
        let item = narrows(|s| {
            s.freshness_keys.insert(PublicKey([11; 32]));
        });
        assert_eq!(item, Item::FreshnessKeyAdded { key: PublicKey([11; 32]) });
        assert_eq!(widens(|s| s.freshness_keys.clear()), Item::FreshnessKeyRemoved { key: PublicKey([7; 32]) });
    }

    #[test]
    fn telemetry_readers() {
        let item = narrows(|s| {
            s.telemetry_readers.remove(&PublicKey([8; 32]));
        });
        assert_eq!(item, Item::TelemetryReaderRemoved { key: PublicKey([8; 32]) });
        let item = widens(|s| {
            s.telemetry_readers.insert(PublicKey([11; 32]));
        });
        assert_eq!(item, Item::TelemetryReaderAdded { key: PublicKey([11; 32]) });
        // Emptying the set sends telemetry in clear.
        let old = base();
        let mut new = old.clone();
        new.telemetry_readers.clear();
        let d = diff_states(&old, &new);
        assert_eq!(d.len(), 2);
        assert!(d.iter().all(|d| d.change == Change::Widening));
        // A first reader is still a new reader.
        let mut none = old.clone();
        none.telemetry_readers.clear();
        let mut first = none.clone();
        first.telemetry_readers.insert(PublicKey([11; 32]));
        assert_eq!(classify_state(&none, &first), Change::Widening);
    }

    #[test]
    fn pending_window() {
        assert_eq!(narrows(|s| s.pending_window_secs = 7200), Item::PendingWindow { old: 3600, new: 7200 });
        assert_eq!(widens(|s| s.pending_window_secs = 60), Item::PendingWindow { old: 3600, new: 60 });
        assert_eq!(widens(|s| s.pending_window_secs = 0), Item::PendingWindow { old: 3600, new: 0 });
    }

    #[test]
    fn a_mix_with_one_widening_widens() {
        let old = base();
        let mut new = old.clone();
        new.producers.clear();
        new.deployments.clear();
        new.deployments.insert(id(9));
        assert_eq!(classify_state(&old, &new), Change::Widening);
    }

    fn root() -> TenantRoot {
        let keys = [PublicKey([1; 32]), PublicKey([2; 32])];
        TenantRoot {
            tenant: TenantId::new("acme").unwrap(),
            version: 1,
            admin_keys: keys.iter().map(|&public_key| AdminKey::Ed25519 { public_key }).collect(),
            threshold: 1,
            cosign_releases: false,
        }
    }
    fn root_change(edit: impl FnOnce(&mut TenantRoot)) -> (Change, Vec<Difference>) {
        let old = root();
        let mut new = old.clone();
        edit(&mut new);
        (classify_root(&old, &new), diff_roots(&old, &new))
    }

    #[test]
    fn roots() {
        let (change, d) = root_change(|r| r.version = 2);
        assert_eq!((change, d.len()), (Change::Narrowing, 0));
        let passkey = AdminKey::WebAuthnEs256 { sec1: vec![4; 65], rp_id: "seal.zone".into() };
        let (change, d) = root_change(|r| {
            r.admin_keys.insert(passkey.clone());
        });
        assert_eq!(change, Change::Widening);
        assert_eq!(d[0].item, Item::AdminKeyAdded { key: passkey });
        // Removing a key removes someone who could veto: widening.
        let (change, d) = root_change(|r| {
            r.admin_keys.pop_first();
        });
        assert_eq!(change, Change::Widening);
        assert!(matches!(d[0].item, Item::AdminKeyRemoved { .. }));
        assert_eq!(root_change(|r| r.threshold = 2).0, Change::Narrowing);
        assert_eq!(root_change(|r| r.threshold = 0).0, Change::Widening);
        assert_eq!(root_change(|r| r.cosign_releases = true).0, Change::Narrowing);
        let mut on = root();
        on.cosign_releases = true;
        assert_eq!(classify_root(&on, &root()), Change::Widening);
        assert_eq!(root_change(|r| r.tenant = TenantId::new("other").unwrap()).0, Change::Widening);
        // Raising the threshold while adding a key still widens.
        let (change, d) = root_change(|r| {
            r.threshold = 2;
            r.admin_keys.insert(AdminKey::Ed25519 { public_key: PublicKey([3; 32]) });
        });
        assert_eq!((change, d.len()), (Change::Widening, 2));
    }
}
