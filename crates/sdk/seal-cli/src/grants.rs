//! `seal grant` and `seal revoke`: who may start sessions (apps), from which networks, seal
//! (producers) and serve the tenant (enclaves). On a terminal, a grant without an identity kind asks for one and
//! for its ids; scripts name it (`seal grant app checkout azure --object-id …`).

use std::collections::BTreeSet;
use std::io::IsTerminal as _;

use anyhow::{anyhow, bail};
use clap::{CommandFactory as _, FromArgMatches, Subcommand};

use seal_crypto::sign::SigningKey;
use seal_proto::identity::IdentityMatcher;
use seal_proto::net::Cidr;
use seal_proto::state::TenantState;
use seal_proto::AppName;

use crate::identity::{Deployment, DeploymentRef, Workload, WorkloadRef};
use crate::sign::{change_state, edit_state};
use crate::{config, invalid, say, ui, Env};

#[derive(Subcommand, Debug)]
pub enum GrantCmd {
    /// Let an app start sessions: an identity it runs as (the app is created with the first one)
    App {
        /// The app's name, as blobs name it (`seal secret --app NAME`)
        name: AppName,
        #[command(subcommand)]
        identity: Option<Workload>,
    },
    /// Let a workload seal secrets for the tenant's apps
    Producer {
        #[command(subcommand)]
        identity: Option<Workload>,
    },
    /// Let an enclave deployment serve the tenant (get its keys)
    Enclave {
        #[command(subcommand)]
        identity: Option<Deployment>,
    },
    /// Let an app start sessions only from these networks; its first turns the rule on
    Network {
        /// The app's name
        app: AppName,
        /// Networks in CIDR form: 203.0.113.0/24, 2001:db8::/32, one address as 198.51.100.7/32
        #[arg(required = true)]
        networks: Vec<Cidr>,
    },
}

#[derive(Subcommand, Debug)]
pub enum RevokeCmd {
    /// Remove one identity of an app, or the whole app when none is named
    App {
        /// The app's name
        name: AppName,
        #[command(subcommand)]
        identity: Option<WorkloadRef>,
    },
    /// Remove a producer
    Producer {
        #[command(subcommand)]
        identity: Option<WorkloadRef>,
    },
    /// Remove an enclave deployment: it gets no keys from the next state on
    Enclave {
        #[command(subcommand)]
        identity: Option<DeploymentRef>,
    },
    /// Remove networks from an app's rule; with none named, the rule (any address again)
    Network {
        /// The app's name
        app: AppName,
        /// Networks to remove, as `seal status` lists them
        networks: Vec<Cidr>,
    },
}

/// A wrapper so a kind enum parses on its own.
#[derive(clap::Parser, Debug)]
#[command(name = "identity", subcommand_required = true)]
struct Kind<T: Subcommand> {
    #[command(subcommand)]
    kind: T,
}

/// Asks for an identity kind and its ids on the terminal; parses them as the command line would.
fn prompt<T: Subcommand + std::fmt::Debug>(what: &str, usage: &str) -> anyhow::Result<T> {
    if !ui::interactive() {
        bail!("name the identity: {usage} (see --help)");
    }
    let command = Kind::<T>::command();
    let kinds: Vec<(&str, String)> = command
        .get_subcommands()
        .filter(|s| !s.is_hide_set())
        .map(|s| (s.get_name(), s.get_about().map(|a| a.to_string()).unwrap_or_default()))
        .collect();
    let kind = ui::pick(&format!("Which kind of identity {what}?"), &kinds)?.to_string();
    let sub = command.find_subcommand(&kind).ok_or_else(|| anyhow!("no kind {kind}"))?;
    let mut argv = vec!["identity".to_string(), kind.clone()];
    for arg in sub.get_arguments().filter(|a| a.get_id() != "help" && !a.is_hide_set()) {
        let help = arg.get_help().map(|h| h.to_string()).unwrap_or_default();
        let name = match arg.get_long() {
            Some(long) => format!("--{long}"),
            None => arg
                .get_value_names()
                .and_then(|v| v.first())
                .map_or_else(|| arg.get_id().to_string(), |v| v.to_string()),
        };
        eprintln!("{}", ui::dim(&help));
        if !arg.get_action().takes_values() {
            if ui::confirm(&format!("  {}", ui::bold(&name)))? {
                argv.push(name);
            }
            continue;
        }
        let required = arg.is_required_set() || arg.is_positional();
        loop {
            let optional = if required { String::new() } else { ui::dim(" (optional: Enter skips)") };
            let value = ui::ask(&format!("  {}{optional}: ", ui::bold(&name)))?;
            if value.is_empty() && required {
                continue;
            }
            if !value.is_empty() {
                if arg.is_positional() {
                    argv.push(value);
                } else {
                    argv.extend([name.clone(), value]);
                }
            }
            break;
        }
    }
    eprintln!("{}", ui::dim(&format!("  (as flags: {})", argv[1..].join(" "))));
    let matches = command.try_get_matches_from(&argv)?;
    Ok(Kind::<T>::from_arg_matches(&matches)?.kind)
}

fn grant(set: &mut BTreeSet<IdentityMatcher>, what: &str, matcher: IdentityMatcher) -> Result<(), seal::ClientError> {
    if set.contains(&matcher) {
        return Err(invalid(format!("{what} already has that identity")));
    }
    set.insert(matcher);
    Ok(())
}

fn revoke(
    set: &mut BTreeSet<IdentityMatcher>,
    what: &str,
    mut selects: impl FnMut(&IdentityMatcher) -> bool,
) -> Result<(), seal::ClientError> {
    let before = set.len();
    set.retain(|m| !selects(m));
    if set.len() == before {
        return Err(invalid(format!("{what} has no such identity")));
    }
    Ok(())
}

/// A key `key --generate` makes, and where it goes; checked before anything is signed.
struct NewKey {
    key: SigningKey,
    out: Option<std::path::PathBuf>,
}

impl NewKey {
    fn of(identity: &Workload) -> anyhow::Result<Option<Self>> {
        let Some(out) = identity.generates() else { return Ok(None) };
        match out {
            Some(path) => config::check_new(path)?,
            None if std::io::stdout().is_terminal() => {
                bail!("pass --out FILE: a new key is never printed to a terminal (or redirect stdout)")
            }
            None => ui::reserve_stdout(),
        }
        Ok(Some(Self { key: config::generate_key(), out: out.cloned() }))
    }

    /// Writes the key once its grant is on the control plane, and says which key it is.
    fn store(&self, what: &str) -> anyhow::Result<()> {
        let text = config::app_key_text(&self.key);
        match &self.out {
            Some(path) => {
                config::write_private(path, text.expose())?;
                say!("{}", ui::ok(&format!("app key for {what} in {} (SEAL_APP_KEY; mode 0600)", path.display())));
            }
            None => {
                use std::io::Write as _;
                std::io::stdout().write_all(text.expose())?;
                say!("{}", ui::ok(&format!("app key for {what} written to stdout (SEAL_APP_KEY)")));
            }
        }
        let public_key = self.key.public_key();
        say!("  public key {public_key}");
        say!("  key id {}", seal_crypto::sign::key_id(&public_key));
        Ok(())
    }
}

/// Grants `identity` in the set `pick` chooses.
async fn grant_workload(
    env: &Env,
    what: String,
    identity: Workload,
    pick: impl FnOnce(&mut TenantState) -> &mut BTreeSet<IdentityMatcher>,
) -> anyhow::Result<()> {
    let new = NewKey::of(&identity)?;
    let matcher = identity.matcher(new.as_ref().map(|n| n.key.public_key()))?;
    let label = what.clone();
    change_state(env, move |s| grant(pick(s), &label, matcher), || new.as_ref().map_or(Ok(()), |n| n.store(&what)))
        .await
        .map(|_| ())
}

pub async fn run_grant(env: &Env, cmd: GrantCmd) -> anyhow::Result<()> {
    match cmd {
        GrantCmd::App { name, identity } => {
            let identity = match identity {
                Some(i) => i,
                None => prompt(
                    &format!("does app {name} run as"),
                    &format!("seal grant app {name} azure|aws|k8s|gcp|github|key …"),
                )?,
            };
            let app = name.clone();
            grant_workload(env, format!("app {name}"), identity, move |s| s.apps.entry(app).or_default()).await
        }
        GrantCmd::Producer { identity } => {
            let identity = match identity {
                Some(i) => i,
                None => prompt("may seal", "seal grant producer azure|aws|k8s|gcp|github|key …")?,
            };
            grant_workload(env, "producer".into(), identity, |s| &mut s.producers).await
        }
        GrantCmd::Enclave { identity } => {
            let identity = match identity {
                Some(i) => i,
                None => prompt("does the enclave run as", "seal grant enclave azure|aws|confidential-space …")?,
            };
            let matcher = identity.matcher()?;
            let selector = identity.as_ref();
            edit_state(env, move |s| {
                if s.deployments.contains(&matcher) {
                    return Err(invalid("the tenant already allows that enclave"));
                }
                // One entry per deployment: granting it again with or without `--hosted` replaces it.
                let mut error = None;
                s.deployments.retain(|m| match selector.selects(m) {
                    Ok(selected) => !selected,
                    Err(e) => {
                        error = Some(e);
                        true
                    }
                });
                if let Some(e) = error {
                    return Err(invalid(e.to_string()));
                }
                s.deployments.insert(matcher);
                Ok(())
            })
            .await
            .map(|_| ())
        }
        GrantCmd::Network { app, networks } => edit_state(env, move |s| {
            if !s.apps.contains_key(&app) {
                return Err(invalid(format!("no app {app}: grant it an identity first (seal grant app {app} …)")));
            }
            let set = s.app_networks.entry(app.clone()).or_default();
            let before = set.len();
            set.extend(networks);
            if set.len() == before {
                return Err(invalid(format!("app {app} already has those networks")));
            }
            Ok(())
        })
        .await
        .map(|_| ()),
    }
}

pub async fn run_revoke(env: &Env, cmd: RevokeCmd) -> anyhow::Result<()> {
    match cmd {
        RevokeCmd::App { name, identity: None } => {
            edit_state(env, move |s| s.apps.remove(&name).map(|_| ()).ok_or_else(|| invalid(format!("no app {name}"))))
                .await
                .map(|_| ())
        }
        RevokeCmd::App { name, identity: Some(identity) } => edit_state(env, move |s| {
            let set = s.apps.get_mut(&name).ok_or_else(|| invalid(format!("no app {name}")))?;
            revoke(set, &format!("app {name}"), |m| identity.selects(m))?;
            if set.is_empty() {
                s.apps.remove(&name);
            }
            Ok(())
        })
        .await
        .map(|_| ()),
        RevokeCmd::Producer { identity } => {
            let identity: WorkloadRef = match identity {
                Some(i) => i,
                None => prompt("may no longer seal", "seal revoke producer azure|aws|k8s|gcp|github|key …")?,
            };
            edit_state(env, move |s| revoke(&mut s.producers, "the tenant's producers", |m| identity.selects(m)))
                .await
                .map(|_| ())
        }
        RevokeCmd::Enclave { identity } => {
            let identity: DeploymentRef = match identity {
                Some(i) => i,
                None => prompt("may no longer serve", "seal revoke enclave azure|aws|confidential-space …")?,
            };
            edit_state(env, move |s| {
                let mut error = None;
                revoke(&mut s.deployments, "the tenant's enclaves", |m| {
                    identity.selects(m).unwrap_or_else(|e| {
                        error = Some(e.to_string());
                        false
                    })
                })?;
                error.map_or(Ok(()), |e| Err(invalid(e)))
            })
            .await
            .map(|_| ())
        }
        RevokeCmd::Network { app, networks } => edit_state(env, move |s| {
            if networks.is_empty() {
                return s
                    .app_networks
                    .remove(&app)
                    .map(|_| ())
                    .ok_or_else(|| invalid(format!("app {app} has no network rule")));
            }
            let set = s.app_networks.get_mut(&app).ok_or_else(|| invalid(format!("app {app} has no network rule")))?;
            for network in &networks {
                if !set.remove(network) {
                    return Err(invalid(format!("{network} is not in app {app}'s networks")));
                }
            }
            if set.is_empty() {
                return Err(invalid(format!(
                    "that would leave app {app} with no network at all, so no address could connect: \
                     remove the rule instead (seal revoke network {app}), or add another network first"
                )));
            }
            Ok(())
        })
        .await
        .map(|_| ()),
    }
}
