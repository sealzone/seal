//! `seal deploy azure` and `seal deploy upgrade`: enclave replicas in the customer's Azure
//! subscription, pinned to this home's tenant.
//!
//! Both pick a release the same way (`release`): every Azure enclave release the control plane
//! lists (or the one `--release` or `--template` names), verified with `ReleaseVerifier` under
//! the configured release trust, newest by log position; then the release template (control
//! plane, or `--template`), refused unless its policy's measurement is that release's (`aci`);
//! then, for tenants with `cosign_releases`, the admins' co-signature. Only then is anything
//! rendered or run. The deployed ARM template is rendered here (`aci::render`), never taken
//! from the template's source.
//!
//! `azure` needs only the VNet the apps run in (`--vnet`, or chosen from `az network vnet
//! list` at a terminal). It works out the network first (`network::plan`): the subnet `seal`,
//! reused when delegated to container groups, else created in the first free /27; its NAT
//! gateway, the only egress ACI supports in a VNet: the subnet's own, one another subnet of
//! the VNet uses, else a new `seal-nat` with a static public IP. `--subnet` names a prepared
//! subnet instead, used only when it is delegated and has a NAT gateway. Then come the
//! tenant's audience (`--audience`, else the one its own Azure deployments use, else an Entra
//! application `seal-TENANT` registered now), the network, the user-assigned managed identity
//! (created when missing), its entry in `TenantState::deployments` (the usual signed state
//! change; `--skip-grant` prints the command for an admin instead), and the group, in the
//! VNet's resource group and location unless `-g` and `--location` say otherwise. `upgrade`
//! reads a running group back and redeploys it with the new release, keeping its name,
//! location, identity, subnet and pin; it refuses a group pinned to another tenant and a
//! release older than the running one. `--dry-run` reads Azure as a run would, prints the
//! template (stdout) and the commands that would change something (stderr), and runs none.

pub mod aci;
pub mod cli;
pub mod gcp;
pub mod network;
pub mod release;
pub mod steps;

use std::collections::BTreeSet;
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context as _};
use clap::{Args, Subcommand};
use serde_json::{json, Value};

use seal::admin::{Admin, Current};
use seal_crypto::SecretBytes;
use seal_proto::identity::IdentityMatcher;
use seal_proto::release::RELEASE_COSIGN_LABEL;
use seal_proto::{Measurement, PlatformId, TenantPin, TrustedTime};
use seal_verify::{ReleaseVerifier, TenantVerifier};

use crate::sign::edit_state;
use crate::{invalid, say, ui, Env, Scope};
use aci::{Deployed, Placement, ReleaseTemplate};
use cli::{Cli, Scratch, AZ};
use network::{leaf, Nat, Plan, Subnet, Vnet, SUBNET};
use release::Candidate;
use steps::Steps;

const DELEGATION: &str = "Microsoft.ContainerInstance/containerGroups";
const IDENTITY_TYPE: &str = "Microsoft.ManagedIdentity/userAssignedIdentities";
const REGISTRY_PASSWORD: &str = "SEAL_REGISTRY_PASSWORD";
const NAT: &str = "seal-nat";
const NAT_IP: &str = "seal-nat-ip";

#[derive(Subcommand, Debug)]
pub enum DeployCmd {
    /// A replica in your Azure subscription, in the VNet your apps run in: its subnet, NAT
    /// gateway, identity and audience are made when missing
    Azure(AzureArgs),
    /// Not available in this build
    #[command(hide = true)]
    Aws(Passthrough),
    /// A replica in your Google Cloud project, in the VPC your apps run in: a Confidential Space
    /// VM, with its service account, Cloud NAT and firewall rule made when missing
    Gcp(gcp::GcpArgs),
    /// Move an Azure replica to the newest verified release, keeping its identity, network and pin
    Upgrade(UpgradeArgs),
}

#[derive(Args, Debug)]
pub struct Passthrough {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, hide = true)]
    args: Vec<String>,
}

#[derive(Args, Debug)]
pub struct ReleaseArgs {
    /// Deploy this release (its measurement, hex) instead of the newest verified one
    #[arg(long, value_name = "MEASUREMENT", help_heading = "Release")]
    release: Option<Measurement>,
    /// Read the release template from FILE instead of the control plane (`seal-release aci-policy`
    /// writes it); its release must still verify
    #[arg(long, value_name = "FILE", help_heading = "Release")]
    template: Option<PathBuf>,
    /// Pull the image as this registry user, with the password in SEAL_REGISTRY_PASSWORD
    #[arg(long, value_name = "USER", help_heading = "Release")]
    registry_user: Option<String>,
    /// Verify the release, print the ARM template (stdout) and the commands (stderr); change nothing
    #[arg(long)]
    dry_run: bool,
}

#[derive(Args, Debug)]
pub struct AzureArgs {
    /// The VNet your apps run in, by name or resource id (asked at a terminal); it gets a subnet
    /// `seal` and a NAT gateway when it has none
    #[arg(long, value_name = "NAME|ID", help_heading = "Placement")]
    vnet: Option<String>,
    /// A prepared subnet instead: SUBNET in --vnet, VNET/SUBNET or a subnet resource id,
    /// delegated to Microsoft.ContainerInstance/containerGroups, with a NAT gateway
    #[arg(long, value_name = "SUBNET|ID", help_heading = "Placement")]
    subnet: Option<String>,
    /// The resource group for the identity, the group and a new NAT gateway (default: the VNet's)
    #[arg(long, short = 'g', value_name = "RG", help_heading = "Placement")]
    resource_group: Option<String>,
    /// The container group (default seal-TENANT); one per replica
    #[arg(long, help_heading = "Replica")]
    name: Option<String>,
    /// The user-assigned managed identity in the resource group, created when missing (default
    /// seal-TENANT); replicas may share it
    #[arg(long, value_name = "NAME", help_heading = "Replica")]
    identity: Option<String>,
    /// The Azure region (default: the VNet's)
    #[arg(long, help_heading = "Placement")]
    location: Option<String>,
    /// The Entra app ID URI the replica's token is for (default: the one the tenant's Azure
    /// deployments use, else an Entra application seal-TENANT, registered now)
    #[arg(long, value_name = "URI", help_heading = "Replica")]
    audience: Option<String>,
    /// Do not sign the deployment grant; print the `seal grant enclave` command for an admin
    #[arg(long, help_heading = "Replica")]
    skip_grant: bool,
    #[command(flatten)]
    release: ReleaseArgs,
}

#[derive(Args, Debug)]
pub struct UpgradeArgs {
    /// The replica's resource group
    #[arg(long, short = 'g', value_name = "RG")]
    resource_group: String,
    /// The container group (default seal-TENANT)
    #[arg(long)]
    name: Option<String>,
    #[command(flatten)]
    release: ReleaseArgs,
}

pub async fn run(env: &Env, cmd: DeployCmd) -> anyhow::Result<()> {
    match cmd {
        DeployCmd::Aws(_) => bail!("`seal deploy aws` is not available in this build"),
        DeployCmd::Gcp(args) => gcp::deploy(env, args).await,
        DeployCmd::Azure(args) => azure(env, args).await,
        DeployCmd::Upgrade(args) => upgrade(env, args).await,
    }
}

/// The verified tenant and the pin its replicas carry.
async fn tenant(env: &Env, time: &TrustedTime) -> anyhow::Result<(Admin, Current, TenantPin)> {
    let admin = env.admin(Scope::Submit).await?;
    let current = admin.fetch(time).await?;
    let pin = TenantPin { tenant: admin.tenant().clone(), root_id: *current.tenant.root_id() };
    Ok((admin, current, pin))
}

fn control<T>(r: Result<T, seal::admin::ControlError>) -> anyhow::Result<T> {
    r.map_err(|e| anyhow!("control plane: {e}"))
}

/// The release to deploy on `platform`, checked as the module docs say: verified, the one
/// `wanted` names or the newest, and for tenants with `cosign_releases` co-signed by its admins.
async fn choose(
    env: &Env,
    admin: &Admin,
    current: &Current,
    wanted: Option<Measurement>,
    time: &TrustedTime,
    platform: PlatformId,
) -> anyhow::Result<Candidate> {
    let trust = env.trust()?.full.ok_or_else(|| {
        anyhow!("the trust names no release trust (`releases` in --trust FILE): deploying verifies releases with it")
    })?;
    let verifier = ReleaseVerifier::new(trust.releases);
    let control_plane = admin.control();
    let listed = match &wanted {
        Some(m) => vec![control(control_plane.get_release(platform, m).await)?],
        None => control(control_plane.get_releases(platform).await)?,
    };
    let latest = match control_plane.get_checkpoint().await {
        Ok(checkpoint) => Some(checkpoint),
        Err(e) => {
            eprintln!("note: no latest checkpoint from the control plane ({e}); using the stored ones");
            None
        }
    };
    let (verified, refused) = release::verify_all(&verifier, listed, latest.as_ref(), time, platform);
    for line in &refused {
        eprintln!("not verified: {line}");
    }
    let candidate = release::pick(&verified, wanted.as_ref(), platform)?;
    let m = candidate.measurement();
    let root = current.tenant.root();
    if root.cosign_releases {
        let cosigned = match control_plane.get_release_cosign(admin.tenant(), &m).await {
            Ok(c) => {
                c.body.tenant == *admin.tenant()
                    && c.body.measurement == m
                    && TenantVerifier::verify_admin_signed(root, RELEASE_COSIGN_LABEL, &c).is_ok()
            }
            Err(_) => false,
        };
        if !cosigned {
            bail!("this tenant's keys go only to releases its admins co-signed: run `seal release approve {m}` first");
        }
    }
    let manifest = candidate.release.manifest();
    eprintln!(
        "release {} (commit {}), measurement {m}: verified (public since {}, log entry {})",
        manifest.version,
        manifest.source_commit,
        candidate.release.public_since(),
        candidate.leaf_index
    );
    Ok(candidate)
}

/// The Azure release to deploy and its ACI template (`--template`, else the control plane's),
/// refused unless the template's policy measures that release.
async fn choose_azure(
    env: &Env,
    admin: &Admin,
    current: &Current,
    args: &ReleaseArgs,
    time: &TrustedTime,
) -> anyhow::Result<(Candidate, ReleaseTemplate)> {
    let from_file = args.template.as_deref().map(read_template).transpose()?;
    let wanted = match (&from_file, args.release) {
        (Some(t), Some(m)) if t.measurement != m => {
            bail!("the template's policy measures {}, not --release {m}", t.measurement)
        }
        (Some(t), _) => Some(t.measurement),
        (None, m) => m,
    };
    let candidate = choose(env, admin, current, wanted, time, PlatformId::AzureSnpAci).await?;
    let m = candidate.measurement();
    let template = match from_file {
        Some(t) => t,
        None => {
            let value = control(admin.control().get_release_template(PlatformId::AzureSnpAci, &m).await)
                .context("the release template")?;
            ReleaseTemplate::parse(&value).context("the release template")?
        }
    };
    if template.measurement != m {
        bail!("the release template's policy measures {}, not release {m}: refusing it", template.measurement);
    }
    eprintln!("  its ACI policy's host_data {}", crate::config::hex(&template.host_data));
    Ok((candidate, template))
}

fn read_template(path: &std::path::Path) -> anyhow::Result<ReleaseTemplate> {
    let text = std::fs::read(path).with_context(|| format!("{}", path.display()))?;
    let value: Value = serde_json::from_slice(&text).with_context(|| format!("{}", path.display()))?;
    ReleaseTemplate::parse(&value).with_context(|| format!("{}", path.display()))
}

/// The registry password, when a registry user is named.
fn registry_password(args: &ReleaseArgs) -> anyhow::Result<Option<SecretBytes>> {
    if args.registry_user.is_none() {
        return Ok(None);
    }
    let password = std::env::var(REGISTRY_PASSWORD)
        .map_err(|_| anyhow!("--registry-user needs the registry password in {REGISTRY_PASSWORD}"))?;
    Ok(Some(SecretBytes::new(password.into_bytes())))
}

/// The tenant's audience for a new deployment entry: `--audience`, else the one its own Azure
/// deployments use (a Seal-hosted replica's entry names Seal's audience, never the tenant's);
/// `None`: none yet, so one is registered.
fn audience(args: &AzureArgs, current: &Current) -> anyhow::Result<Option<String>> {
    if let Some(a) = &args.audience {
        return Ok(Some(a.clone()));
    }
    own_audience(&current.tenant.state().deployments)
}

fn own_audience(deployments: &BTreeSet<IdentityMatcher>) -> anyhow::Result<Option<String>> {
    let used: BTreeSet<&str> = deployments
        .iter()
        .filter_map(|m| match m {
            IdentityMatcher::Azure { audience, hosted: None, .. } => Some(audience.as_str()),
            _ => None,
        })
        .collect();
    match used.into_iter().collect::<Vec<_>>().as_slice() {
        [] => Ok(None),
        [one] => Ok(Some((*one).to_owned())),
        several => {
            bail!("the tenant's Azure deployments use several audiences ({}): pass --audience", several.join(", "))
        }
    }
}

/// From `az ad app list --display-name`: the first application's app id, and whether it
/// already has the identifier URI `api://APP_ID`.
fn registered_app(apps: &Value) -> Option<(String, bool)> {
    let app = apps.as_array()?.iter().find(|a| a["appId"].is_string())?;
    let id = app["appId"].as_str()?.to_owned();
    let uri = format!("api://{id}");
    let has_uri = app["identifierUris"].as_array().is_some_and(|us| us.iter().any(|u| *u == *uri));
    Some((id, has_uri))
}

/// The subnet's resource id, once it has the supported shape.
fn checked_subnet(subnet: &Value) -> anyhow::Result<String> {
    let id = subnet["id"].as_str().ok_or_else(|| anyhow!("the subnet has no id"))?;
    if !network::delegated(subnet) {
        bail!(
            "{id} is not delegated to container groups: \
             az network vnet subnet update --ids {id} --delegations {DELEGATION}"
        );
    }
    if subnet["natGateway"]["id"].as_str().is_none() {
        bail!(
            "{id} has no NAT gateway, the only egress ACI supports in a VNet (the replica reaches its guardian, \
             the control plane, the log and Roughtime through it): \
             az network vnet subnet update --ids {id} --nat-gateway NAT_GATEWAY"
        );
    }
    Ok(id.to_owned())
}

fn text<'a>(v: &'a Value, what: &str) -> anyhow::Result<&'a str> {
    v.as_str().ok_or_else(|| anyhow!("az returned no {what}"))
}

/// Writes the template (and parameters, with the registry password) and runs
/// `az deployment group create`.
async fn deploy(
    az: &Cli,
    resource_group: &str,
    name: &str,
    template: &Value,
    password: Option<&SecretBytes>,
) -> anyhow::Result<()> {
    let scratch = Scratch::new()?;
    let file = scratch.write("template.json", &serde_json::to_vec_pretty(template)?)?;
    let file = file.to_str().ok_or_else(|| anyhow!("the temporary directory is not UTF-8"))?.to_owned();
    let mut args = vec!["deployment", "group", "create", "-g", resource_group, "-n", name, "--template-file", &file];
    let parameters;
    if let Some(password) = password {
        let password =
            std::str::from_utf8(password.expose()).map_err(|_| anyhow!("{REGISTRY_PASSWORD} is not UTF-8"))?;
        let body = SecretBytes::new(serde_json::to_vec(&json!({
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
            "contentVersion": "1.0.0.0",
            "parameters": {"registryPassword": {"value": password}},
        }))?);
        let path = scratch.write("parameters.json", body.expose())?;
        parameters = format!("@{}", path.to_str().ok_or_else(|| anyhow!("the temporary directory is not UTF-8"))?);
        args.extend(["--parameters", &parameters]);
    }
    eprintln!("deploying {name} (az deployment group create; this takes a few minutes)");
    az.json(&args).await?;
    Ok(())
}

/// The commands `deploy` runs, for `--dry-run`.
fn deploy_lines(resource_group: &str, name: &str, registry: bool) -> Vec<String> {
    let mut args =
        vec!["deployment", "group", "create", "-g", resource_group, "-n", name, "--template-file", "TEMPLATE"];
    if registry {
        args.extend(["--parameters", "@PARAMETERS"]);
    }
    vec![AZ.line(&args)]
}

/// Where the SDK reaches a deployed replica.
async fn report(az: &Cli, resource_group: &str, name: &str, template: &ReleaseTemplate) -> anyhow::Result<()> {
    let show = az.show(&["container", "show", "-g", resource_group, "-n", name]).await?;
    let ip = show.as_ref().and_then(|s| Deployed::parse(s).ok()).and_then(|d| d.ip);
    match ip {
        Some(ip) => {
            let endpoint = format!("https://{ip}:{}", template.container.ports[0]);
            say!("{}", ui::ok(&format!("replica {name} at {ip} — set SEAL_ENDPOINT={endpoint}")));
        }
        None => say!("replica {name} deployed; its address is not assigned yet (az container show -g {resource_group} -n {name})"),
    }
    Ok(())
}

/// How long a replica may take from `az deployment group create` returning to serving.
const READY_SECS: u64 = 600;

/// Waits until the replica serves: the group running and the enclave saying so in its log
/// (the address is private, so this reads Azure's view of it). An enclave that cannot boot
/// says why (most often a deployment grant not yet in force) and ACI restarts it; that reason
/// is reported once and the wait goes on, until `READY_SECS`.
async fn wait_azure(az: &Cli, rg: &str, name: &str) -> anyhow::Result<()> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(READY_SECS);
    let mut said = String::new();
    loop {
        let logs = az.text(&["container", "logs", "-g", rg, "-n", name]).await.unwrap_or_default();
        if logs.contains("serving the API") {
            say!("{} {name}: serving", ui::dim("·"));
            return Ok(());
        }
        if let Some(reason) = boot_failure(&logs).filter(|r| *r != said) {
            say!("{} {name} has not booted yet: {reason}", ui::dim("·"));
            said = reason;
        }
        if std::time::Instant::now() > deadline {
            bail!(
                "{name} is not serving after {} min{}; its log: az container logs -g {rg} -n {name}",
                READY_SECS / 60,
                if said.is_empty() { String::new() } else { format!(" ({said})") }
            );
        }
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    }
}

/// The reason in an enclave's log that it could not boot, if it says one.
fn boot_failure(logs: &str) -> Option<String> {
    let line = logs.lines().rev().find(|l| l.contains("ERROR") && l.contains("boot"))?;
    Some(line.split_once("boot:").map_or(line, |(_, why)| why).trim().to_owned())
}

fn print_plan(title: &str, lines: &[String], template: &Value) -> anyhow::Result<()> {
    eprintln!("{title}");
    for l in lines {
        eprintln!("  {l}");
    }
    println!("{}", serde_json::to_string_pretty(template)?);
    Ok(())
}

/// The replica's subnet: a prepared one (`--subnet`, checked), or what `network::plan` found.
enum Network {
    Prepared { id: String, nat: String },
    Plan(Plan),
}

/// The VNet `wanted` names (a resource id, or a name in the subscription), else the one chosen
/// at the terminal.
async fn find_vnet(env: &Env, az: &Cli, wanted: Option<&str>) -> anyhow::Result<Vnet> {
    if let Some(id) = wanted.filter(|w| w.starts_with("/subscriptions/")) {
        let vnet = az.show(&["network", "vnet", "show", "--ids", id]).await?.ok_or_else(|| anyhow!("no VNet {id}"))?;
        return Vnet::parse(&vnet);
    }
    let listed = az.json(&["network", "vnet", "list"]).await?;
    let mut vnets: Vec<Vnet> = listed.as_array().into_iter().flatten().filter_map(|v| Vnet::parse(v).ok()).collect();
    if let Some(name) = wanted {
        return network::named(vnets, name);
    }
    if vnets.is_empty() {
        bail!(
            "the subscription has no VNet: deploy into the VNet your apps run in (`az account set -s` switches \
             to the subscription that has it)"
        );
    }
    if env.sign.yes || !ui::interactive() {
        let names: Vec<&str> = vnets.iter().map(|v| v.name.as_str()).collect();
        bail!("pass --vnet NAME|ID, the VNet your apps run in ({})", names.join(", "));
    }
    let subscription = az.json(&["account", "show"]).await.ok().and_then(|a| a["name"].as_str().map(str::to_owned));
    let of = subscription.map(|s| format!(" (subscription {s})")).unwrap_or_default();
    if vnets.len() == 1 {
        let only = vnets.remove(0);
        say!("{} VNet {} ({}): the only one in the subscription{of}", ui::dim("·"), only.name, only.about());
        return Ok(only);
    }
    let labels: Vec<String> = vnets
        .iter()
        .map(|v| {
            let alike = vnets.iter().filter(|w| w.name.eq_ignore_ascii_case(&v.name)).count();
            if alike > 1 {
                format!("{}/{}", v.resource_group, v.name)
            } else {
                v.name.clone()
            }
        })
        .collect();
    let choices: Vec<(&str, String)> = labels.iter().zip(&vnets).map(|(l, v)| (l.as_str(), v.about())).collect();
    let chosen = ui::pick(&format!("Which VNet do your apps run in?{of}"), &choices)?;
    let at = labels.iter().position(|l| l == chosen).ok_or_else(|| anyhow!("no VNet {chosen}"))?;
    Ok(vnets.swap_remove(at))
}

/// The tenant's Entra application `seal-TENANT`, registered (or finished, when a run began
/// it): its app ID URI, api://APP_ID, is the audience.
async fn register_audience(steps: &mut Steps<'_>, tenant: &str) -> anyhow::Result<String> {
    let display = format!("seal-{tenant}");
    let refused = || {
        format!(
            "registering the Entra application {display} failed: ask an Entra admin to register it (application ID \
             URI api://APP_ID, with a service principal), then pass --audience api://APP_ID"
        )
    };
    let apps = steps.cli.json(&["ad", "app", "list", "--display-name", &display]).await.with_context(refused)?;
    let found = registered_app(&apps);
    let (app_id, has_uri) = match &found {
        Some(found) => found.clone(),
        None => {
            steps.note(format!("audience: registering the Entra application {display}"));
            match steps.change(&["ad", "app", "create", "--display-name", &display]).await.with_context(refused)? {
                Some(app) => (text(&app["appId"], "appId")?.to_owned(), false),
                None => ("APP_ID".to_owned(), false),
            }
        }
    };
    let uri = format!("api://{app_id}");
    if !has_uri {
        steps
            .change(&["ad", "app", "update", "--id", &app_id, "--identifier-uris", &uri])
            .await
            .with_context(refused)?;
    }
    let principals = match (&found, steps.dry) {
        (None, true) => Value::Null,
        _ => {
            let filter = format!("appId eq '{app_id}'");
            steps.cli.json(&["ad", "sp", "list", "--filter", &filter]).await.with_context(refused)?
        }
    };
    if !principals.as_array().is_some_and(|p| !p.is_empty()) {
        steps.change(&["ad", "sp", "create", "--id", &app_id]).await.with_context(refused)?;
    }
    steps.note(format!("audience {uri}: registered (Entra application {display})"));
    Ok(uri)
}

/// `seal-nat` in `rg`: the one an earlier run made, else a new one with a static public IP.
async fn nat_gateway(steps: &mut Steps<'_>, rg: &str, location: &str, tags: &str) -> anyhow::Result<String> {
    let show = ["network", "nat", "gateway", "show", "-g", rg, "-n", NAT];
    if let Some(nat) = steps.cli.show(&show).await? {
        steps.note(format!("NAT gateway: using {NAT}"));
        return Ok(text(&nat["id"], "NAT gateway id")?.to_owned());
    }
    steps.note(format!("NAT gateway: creating {NAT} with a static public IP (about $32/month)"));
    let ip = ["network", "public-ip", "create", "-g", rg, "-n", NAT_IP, "-l", location];
    steps.change(&[&ip[..], &["--sku", "Standard", "--allocation-method", "Static", "--tags", tags]].concat()).await?;
    let nat = ["network", "nat", "gateway", "create", "-g", rg, "-n", NAT, "-l", location];
    steps.change(&[&nat[..], &["--public-ip-addresses", NAT_IP, "--tags", tags]].concat()).await?;
    if steps.dry {
        return Ok("NAT_GATEWAY_ID".to_owned());
    }
    let nat = steps.cli.show(&show).await?.ok_or_else(|| anyhow!("{NAT} was created but az does not show it"))?;
    Ok(text(&nat["id"], "NAT gateway id")?.to_owned())
}

/// Makes `plan` so: the subnet (created, or given the NAT gateway it lacks) and its NAT
/// gateway (shared or created). Returns the subnet's id.
async fn prepare(
    steps: &mut Steps<'_>,
    vnet: &Vnet,
    plan: Plan,
    rg: &str,
    location: &str,
    tags: &str,
) -> anyhow::Result<String> {
    let id = match &plan.subnet {
        Subnet::Existing(id) => {
            steps.note(format!("subnet {} in {}: delegated to container groups, using it", leaf(id), vnet.name));
            id.clone()
        }
        Subnet::Create(prefix) => {
            steps.note(format!("subnet {SUBNET} {prefix} in {}: creating, delegated to container groups", vnet.name));
            format!("{}/subnets/{SUBNET}", vnet.id)
        }
    };
    let nat = match plan.nat {
        Nat::Attached(nat) => {
            steps.note(format!("NAT gateway: using {}", leaf(&nat)));
            None
        }
        Nat::Shared(nat) => {
            steps.note(format!("NAT gateway: using {}, as other subnets of {} do", leaf(&nat), vnet.name));
            Some(nat)
        }
        Nat::Create => Some(nat_gateway(steps, rg, location, tags).await?),
    };
    match plan.subnet {
        Subnet::Existing(_) => {
            if let Some(nat) = &nat {
                steps.change(&["network", "vnet", "subnet", "update", "--ids", &id, "--nat-gateway", nat]).await?;
            }
        }
        Subnet::Create(prefix) => {
            let prefix = prefix.to_string();
            let mut args =
                vec!["network", "vnet", "subnet", "create", "-g", &vnet.resource_group, "--vnet-name", &vnet.name];
            args.extend(["-n", SUBNET, "--address-prefixes", &prefix, "--delegations", DELEGATION]);
            if let Some(nat) = &nat {
                args.extend(["--nat-gateway", nat]);
            }
            steps.change(&args).await?;
        }
    }
    Ok(id)
}

async fn azure(env: &Env, args: AzureArgs) -> anyhow::Result<()> {
    AZ.preflight().await?;
    let mut steps = Steps::new(&AZ, args.release.dry_run);
    let result = azure_steps(env, args, &mut steps).await;
    if result.is_err() {
        steps.explain_failure("seal deploy azure (with the same arguments)");
    }
    result
}

async fn azure_steps(env: &Env, args: AzureArgs, steps: &mut Steps<'_>) -> anyhow::Result<()> {
    let time = crate::time();
    let (admin, current, pin) = tenant(env, &time).await?;
    let (candidate, release) = choose_azure(env, &admin, &current, &args.release, &time).await?;
    let version = candidate.release.manifest().version.clone();
    let password = registry_password(&args.release)?;
    let audience = audience(&args, &current)?;
    if !current.tenant.state().platforms.contains(&PlatformId::AzureSnpAci) {
        eprintln!(
            "note: the tenant does not enable azure, so new blobs are not wrapped for this replica: \
             `seal settings platforms add azure`"
        );
    }
    let tenant = &pin.tenant;
    let az = &AZ;
    let wanted = network::wanted(args.vnet.as_deref(), args.subnet.as_deref())?;
    let vnet = find_vnet(env, az, wanted.vnet.as_deref()).await?;
    let network = match &wanted.subnet {
        Some(s) => {
            let subnet = vnet.subnet(s).ok_or_else(|| anyhow!("{} has no subnet {s}", vnet.name))?;
            let id = checked_subnet(subnet)?;
            Network::Prepared { id, nat: subnet["natGateway"]["id"].as_str().map(leaf).unwrap_or_default().to_owned() }
        }
        None => Network::Plan(network::plan(&vnet)?),
    };
    let rg = args.resource_group.clone().unwrap_or_else(|| vnet.resource_group.clone());
    let location = args.location.clone().unwrap_or_else(|| vnet.location.clone());
    let name = args.name.clone().unwrap_or_else(|| format!("seal-{tenant}"));
    let identity = args.identity.clone().unwrap_or_else(|| format!("seal-{tenant}"));
    let tags = format!("seal-tenant={tenant}");

    let audience = match audience {
        Some(a) => {
            let own = if args.audience.is_some() { "" } else { ": the tenant's own" };
            steps.note(format!("audience {a}{own}"));
            a
        }
        None => register_audience(steps, tenant.as_ref()).await?,
    };
    let subnet = match network {
        Network::Prepared { id, nat } => {
            steps.note(format!("subnet {} in {}: delegated, NAT gateway {nat}", leaf(&id), vnet.name));
            id
        }
        Network::Plan(plan) => prepare(steps, &vnet, plan, &rg, &location, &tags).await?,
    };
    if !steps.dry {
        let shown = az.show(&["network", "vnet", "subnet", "show", "--ids", &subnet]).await?;
        checked_subnet(&shown.ok_or_else(|| anyhow!("no subnet {subnet}"))?)?;
    }
    let mi = match az.show(&["identity", "show", "-g", &rg, "-n", &identity]).await? {
        Some(mi) => {
            steps.note(format!("identity {identity}: using it"));
            Some(mi)
        }
        None => {
            steps.note(format!("identity {identity}: creating"));
            steps.change(&["identity", "create", "-g", &rg, "-n", &identity, "-l", &location, "--tags", &tags]).await?
        }
    };
    let (mi_id, object_id, entra_tenant) = match &mi {
        Some(mi) => (
            text(&mi["id"], "identity id")?.to_owned(),
            text(&mi["principalId"], "principalId")?.to_owned(),
            text(&mi["tenantId"], "tenantId")?.to_owned(),
        ),
        None => (aci::resource_id(IDENTITY_TYPE, &[&identity]), "PRINCIPAL_ID".to_owned(), "TENANT_ID".to_owned()),
    };
    let matcher = IdentityMatcher::Azure {
        entra_tenant: entra_tenant.clone(),
        object_id: object_id.clone(),
        audience: audience.clone(),
        hosted: None,
    };
    let grant =
        format!("seal grant enclave azure --object-id {object_id} --entra-tenant {entra_tenant} --audience {audience}");
    if current.tenant.state().deployments.contains(&matcher) {
        steps.note(format!("grant: {} is already a deployment of {tenant}", seal::admin::describe(&matcher)));
    } else if args.skip_grant {
        steps.note(format!("grant: an admin must allow the replica before it gets keys:\n    {grant}"));
    } else if steps.dry {
        steps.note(format!("grant: {grant}  (signed with --key-file, else proposed and signed in the console)"));
    } else {
        edit_state(env, move |s| s.deployments.insert(matcher).then_some(()).ok_or_else(|| invalid("already listed")))
            .await?;
        say!(
            "note: with a pending window, the replica gets keys once this state is in force; ACI restarts it until then"
        );
    }
    let placement = Placement {
        name: name.clone(),
        location: location.clone(),
        identity: mi_id,
        subnet,
        pin: pin.clone(),
        registry_user: args.release.registry_user.clone(),
    };
    let template = aci::render(&release, &version, &placement);
    if steps.dry {
        steps.lines.push(format!("replica {name}: deploying"));
        steps.lines.extend(deploy_lines(&rg, &name, password.is_some()).into_iter().map(|l| format!("  {l}")));
        let title = format!("dry run: {name} in {rg} ({location}), pinned to {pin}; nothing is changed");
        return print_plan(&title, &steps.lines, &template);
    }
    deploy(az, &rg, &name, &template, password.as_ref()).await?;
    steps.made(&format!("container group {name}"), &["container", "delete", "-g", &rg, "-n", &name, "--yes"]);
    wait_azure(az, &rg, &name).await?;
    report(az, &rg, &name, &release).await
}

async fn upgrade(env: &Env, args: UpgradeArgs) -> anyhow::Result<()> {
    let time = crate::time();
    let (admin, current, pin) = tenant(env, &time).await?;
    AZ.preflight().await?;
    let rg = args.resource_group.as_str();
    let name = args.name.clone().unwrap_or_else(|| format!("seal-{}", pin.tenant));
    let az = &AZ;
    let show = az
        .show(&["container", "show", "-g", rg, "-n", &name])
        .await?
        .ok_or_else(|| anyhow!("no container group {name} in {rg}"))?;
    let deployed = Deployed::parse(&show).with_context(|| format!("container group {name}"))?;
    if deployed.pin != pin.to_string() {
        bail!("{name} is pinned to {}, not this home's tenant {pin}", deployed.pin);
    }
    let (candidate, release) = choose_azure(env, &admin, &current, &args.release, &time).await?;
    let m = candidate.measurement();
    let version = candidate.release.manifest().version.clone();
    match deployed.measurement {
        Some(running) if running == m => {
            say!("{name} already runs release {version} ({m})");
            return Ok(());
        }
        Some(running) => {
            let newer = match admin.control().get_release(PlatformId::AzureSnpAci, &running).await {
                Ok(evidence) => {
                    let trust = env.trust()?.full.ok_or_else(|| anyhow!("no release trust"))?;
                    let verifier = ReleaseVerifier::new(trust.releases);
                    let latest = admin.control().get_checkpoint().await.ok();
                    let (verified, _) =
                        release::verify_all(&verifier, vec![evidence], latest.as_ref(), &time, PlatformId::AzureSnpAci);
                    verified.first().filter(|c| c.leaf_index > candidate.leaf_index).cloned()
                }
                Err(_) => None,
            };
            if let Some(newer) = newer {
                bail!(
                    "{name} runs release {} ({running}), newer than {version}: refusing to go back",
                    newer.release.manifest().version
                );
            }
        }
        None => eprintln!("note: the group's description has no ccePolicy; its current release is unknown"),
    }
    let listed = deployed.principal_id.as_ref().is_some_and(|oid| {
        current
            .tenant
            .state()
            .deployments
            .iter()
            .any(|d| matches!(d, IdentityMatcher::Azure { object_id, .. } if object_id == oid))
    });
    if !listed {
        eprintln!(
            "note: {name}'s managed identity ({}) is not among the tenant's deployments; it gets no keys until an \
             admin runs `seal grant enclave azure --object-id OBJECT_ID --entra-tenant TENANT_ID --audience URI`",
            deployed.principal_id.as_deref().unwrap_or("principal id not shown")
        );
    }
    let password = registry_password(&args.release)?;
    let placement = Placement {
        name: name.clone(),
        location: deployed.location.clone(),
        identity: deployed.identity.clone(),
        subnet: deployed.subnet.clone(),
        pin: pin.clone(),
        registry_user: args.release.registry_user.clone(),
    };
    let template = aci::render(&release, &version, &placement);
    let from = deployed.measurement.map_or_else(|| "an unknown release".to_owned(), |m| m.to_string());
    if args.release.dry_run {
        let lines = deploy_lines(rg, &name, password.is_some());
        return print_plan(&format!("dry run: {name} in {rg} from {from} to {version} ({m})"), &lines, &template);
    }
    deploy(az, rg, &name, &template, password.as_ref()).await.with_context(|| {
        format!(
            "if Azure refuses to update the group in place, delete it (az container delete -g {rg} -n {name}) and \
             run `seal deploy azure` with -g {rg} --name {name}, the same --identity and --subnet {}",
            deployed.subnet
        )
    })?;
    wait_azure(az, rg, &name).await?;
    say!("upgraded {name} from {from} to release {version} ({m})");
    report(az, rg, &name, &release).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use seal_proto::identity::HostedMode;

    #[test]
    fn the_default_audience_is_the_tenants_own() {
        let azure = |audience: &str, hosted| IdentityMatcher::Azure {
            entra_tenant: "t".into(),
            object_id: "o".into(),
            audience: audience.into(),
            hosted,
        };
        let seal = azure("api://seal-hosted", Some(HostedMode::Sessions));
        assert_eq!(own_audience(&BTreeSet::from([seal.clone()])).unwrap(), None, "registered when the tenant has none");
        let acme = azure("api://acme", None);
        assert_eq!(own_audience(&BTreeSet::from([seal, acme.clone()])).unwrap().as_deref(), Some("api://acme"));
        let mut other = acme.clone();
        if let IdentityMatcher::Azure { audience, object_id, .. } = &mut other {
            (*audience, *object_id) = ("api://other".into(), "o2".into());
        }
        assert!(own_audience(&BTreeSet::from([acme, other])).unwrap_err().to_string().contains("--audience"));
    }

    #[test]
    fn a_registered_app_is_reused() {
        assert_eq!(registered_app(&json!([])), None);
        assert_eq!(registered_app(&json!([{"appId": "a1", "identifierUris": []}])), Some(("a1".into(), false)));
        assert_eq!(
            registered_app(&json!([{"displayName": "x"}, {"appId": "a1", "identifierUris": ["api://a1"]}])),
            Some(("a1".into(), true))
        );
    }

    #[test]
    fn a_boot_failure_is_read_from_the_log() {
        let log = "INFO seal_enclave: starting\nERROR seal_enclave: boot: Unavailable: guardian: unavailable: guardian answered HTTP 504\n";
        assert_eq!(
            boot_failure(log).as_deref(),
            Some("Unavailable: guardian: unavailable: guardian answered HTTP 504")
        );
        assert_eq!(boot_failure("INFO seal_enclave: serving the API and tunnels"), None);
    }

    #[test]
    fn only_a_delegated_subnet_with_a_nat_gateway_is_used() {
        let good = json!({
            "id": "/s/subnets/seal",
            "delegations": [{"serviceName": DELEGATION}],
            "natGateway": {"id": "/s/natGateways/nat"},
        });
        assert_eq!(checked_subnet(&good).unwrap(), "/s/subnets/seal");
        let mut undelegated = good.clone();
        undelegated["delegations"] = json!([]);
        assert!(checked_subnet(&undelegated).unwrap_err().to_string().contains("--delegations"));
        let mut no_nat = good.clone();
        no_nat.as_object_mut().unwrap().remove("natGateway");
        assert!(checked_subnet(&no_nat).unwrap_err().to_string().contains("NAT gateway"));
    }
}
