//! `seal deploy gcp`: a replica in the customer's Google Cloud project, a Confidential Space VM
//! (Intel TDX, `c3-*`) pinned to this home's tenant, in the VPC the apps run in.
//!
//! The release is picked as on Azure (`super::choose`): the newest verified GCP enclave release,
//! or `--release`. Its template on the control plane names the image (`{"image":
//! "REPO@sha256:…", "port": 8443}`), refused unless the image digest measures to that release
//! (`seal_attest::gcp::measurement`); nothing else is taken from it. The VM gets that image,
//! the pin as `tee-env-SEAL_TENANT` (the only variable its launch policy lets an operator set),
//! the Confidential Space image (`confidential-space` from `confidential-space-images`), no
//! external address, and a service account of its own: its deployment identity, project number
//! and email, which the tenant's state must list (the usual signed change; `--skip-grant`
//! prints the command instead).
//!
//! The network is made so when it is not (each step looks first): the APIs, Cloud NAT on a
//! router in the VM's region (the replica reaches its guardian, the control plane, the log,
//! Google's attestation service and Roughtime through it), and a firewall rule letting the
//! VPC's own ranges reach the replica's port. Running it again on an existing VM moves it to
//! the chosen release (new image, then a reset), keeping its identity, network and pin, and
//! never goes back to an older release.

use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context as _};
use clap::Args;
use serde_json::Value;

use seal_proto::identity::IdentityMatcher;
use seal_proto::{Measurement, PlatformId, TenantPin};

use super::cli::GCLOUD;
use super::steps::Steps;
use super::{choose, control, tenant, ReleaseArgs};
use crate::sign::edit_state;
use crate::{invalid, say, ui, Env};

/// Confidential Space's VM image.
const IMAGE_PROJECT: &str = "confidential-space-images";
const IMAGE_FAMILY: &str = "confidential-space";
/// The smallest machine type with Intel TDX, which Confidential Space attests.
const MACHINE_TYPE: &str = "c3-standard-4";
/// The role that lets the VM's service account get Confidential Space attestation tokens.
const WORKLOAD_ROLE: &str = "roles/confidentialcomputing.workloadUser";
const ROUTER: &str = "seal-nat-router";
const NAT: &str = "seal-nat";
/// How long a VM may take from created to serving.
const READY_SECS: u64 = 600;

#[derive(Args, Debug)]
pub struct GcpArgs {
    /// The project (default: gcloud's `core/project`)
    #[arg(long, help_heading = "Placement")]
    project: Option<String>,
    /// The VPC network your apps run in (default: the project's only one, else asked at a terminal)
    #[arg(long, value_name = "NAME", help_heading = "Placement")]
    network: Option<String>,
    /// The zone (default: gcloud's `compute/zone`); it needs C3 machines with Intel TDX
    #[arg(long, help_heading = "Placement")]
    zone: Option<String>,
    /// The subnet in the zone's region (default: the network's subnet there)
    #[arg(long, help_heading = "Placement")]
    subnet: Option<String>,
    /// The VM (default seal-TENANT); one per replica
    #[arg(long, help_heading = "Replica")]
    name: Option<String>,
    /// The VM's service account, created when missing (default seal-TENANT@PROJECT.iam.gserviceaccount.com)
    #[arg(long, value_name = "EMAIL", help_heading = "Replica")]
    service_account: Option<String>,
    /// The machine type (default c3-standard-4)
    #[arg(long, help_heading = "Replica")]
    machine_type: Option<String>,
    /// Do not sign the deployment grant; print the `seal grant enclave` command for an admin
    #[arg(long, help_heading = "Replica")]
    skip_grant: bool,
    #[command(flatten)]
    release: ReleaseArgs,
}

/// A GCP release template: the image, by digest, and the port it serves on.
#[derive(Debug, PartialEq)]
pub struct ImageTemplate {
    pub image: String,
    pub digest: String,
    pub port: u16,
}

impl ImageTemplate {
    /// Parsed and checked against `release`: the digest must measure to it.
    pub fn parse(value: &Value, release: &Measurement) -> anyhow::Result<Self> {
        let image = value["image"].as_str().ok_or_else(|| anyhow!("the GCP release template names no image"))?;
        let (_, digest) =
            image.rsplit_once('@').ok_or_else(|| anyhow!("the GCP release template's image {image} has no digest"))?;
        let measured = seal_attest::gcp::measurement(digest).map_err(|e| anyhow!("{image}: {e}"))?;
        if &measured != release {
            bail!("the GCP release template's image measures {measured}, not release {release}: refusing it");
        }
        let port = value["port"].as_u64().unwrap_or(8443);
        let port = u16::try_from(port).map_err(|_| anyhow!("the GCP release template's port {port} is not a port"))?;
        Ok(Self { image: image.to_owned(), digest: digest.to_owned(), port })
    }
}

pub async fn deploy(env: &Env, args: GcpArgs) -> anyhow::Result<()> {
    GCLOUD.preflight().await?;
    let mut steps = Steps::new(&GCLOUD, args.release.dry_run);
    let result = run(env, args, &mut steps).await;
    if result.is_err() {
        steps.explain_failure("seal deploy gcp (with the same arguments)");
    }
    result
}

fn text<'a>(v: &'a Value, what: &str) -> anyhow::Result<&'a str> {
    v.as_str().ok_or_else(|| anyhow!("gcloud returned no {what}"))
}

/// `us-central1-a` → `us-central1`.
pub fn region_of(zone: &str) -> anyhow::Result<&str> {
    zone.rsplit_once('-').map(|(r, _)| r).filter(|r| r.contains('-')).ok_or_else(|| anyhow!("{zone} is not a zone"))
}

/// gcloud's configured value for `key`, if any.
async fn configured(key: &str) -> Option<String> {
    GCLOUD
        .json(&["config", "get-value", key])
        .await
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .filter(|v| !v.is_empty())
}

async fn run(env: &Env, args: GcpArgs, steps: &mut Steps<'_>) -> anyhow::Result<()> {
    let gc = &GCLOUD;
    if args.release.registry_user.is_some() || args.release.template.is_some() {
        bail!("--registry-user and --template are for Azure; GCP releases name a public image");
    }
    let time = crate::time();
    let (admin, current, pin) = tenant(env, &time).await?;
    let candidate =
        choose(env, &admin, &current, args.release.release, &time, PlatformId::GcpConfidentialSpace).await?;
    let m = candidate.measurement();
    let version = candidate.release.manifest().version.clone();
    let value = control(admin.control().get_release_template(PlatformId::GcpConfidentialSpace, &m).await)
        .context("the GCP release template")?;
    let image = ImageTemplate::parse(&value, &m)?;
    if !current.tenant.state().platforms.contains(&PlatformId::GcpConfidentialSpace) {
        eprintln!(
            "note: the tenant does not enable gcp, so new blobs are not wrapped for this replica: \
             `seal settings platforms add gcp`"
        );
    }

    let project = match &args.project {
        Some(p) => p.clone(),
        None => {
            configured("core/project").await.ok_or_else(|| anyhow!("pass --project (gcloud has no core/project)"))?
        }
    };
    let described = gc
        .show(&["projects", "describe", &project])
        .await?
        .ok_or_else(|| anyhow!("no project {project}, or no access to it"))?;
    let project_number: u64 = text(&described["projectNumber"], "projectNumber")?.parse().context("projectNumber")?;
    let zone = match &args.zone {
        Some(z) => z.clone(),
        None => configured("compute/zone").await.ok_or_else(|| anyhow!("pass --zone (gcloud has no compute/zone)"))?,
    };
    let region = region_of(&zone)?.to_owned();
    let tenant = pin.tenant.to_string();
    let name = args.name.clone().unwrap_or_else(|| format!("seal-{tenant}"));
    let email =
        args.service_account.clone().unwrap_or_else(|| format!("seal-{tenant}@{project}.iam.gserviceaccount.com"));
    let machine = args.machine_type.clone().unwrap_or_else(|| MACHINE_TYPE.to_owned());
    let p = ["--project", project.as_str()];

    // APIs: enabling an enabled one is a no-op.
    steps.note("APIs: compute and confidentialcomputing".into());
    steps
        .change(
            &[&["services", "enable", "compute.googleapis.com", "confidentialcomputing.googleapis.com"][..], &p]
                .concat(),
        )
        .await?;

    let network = pick_network(env, &project, args.network.as_deref()).await?;
    let subnet = subnet(&project, &network, &region, args.subnet.as_deref()).await?;
    steps.note(format!("subnet {} in {network} ({region}), {}", subnet.name, subnet.range));
    nat(steps, &project, &network, &region).await?;
    firewall(steps, &project, &network, &tenant, image.port).await?;
    let sa = service_account(steps, &project, &email, &tenant).await?;

    let matcher = IdentityMatcher::ConfidentialSpace { project_number, service_account: sa.clone(), hosted: None };
    let grant =
        format!("seal grant enclave confidential-space --project-number {project_number} --service-account {sa}");
    if current.tenant.state().deployments.contains(&matcher) {
        steps.note(format!("grant: {} is already a deployment of {tenant}", seal::admin::describe(&matcher)));
    } else if args.skip_grant {
        steps.note(format!("grant: an admin must allow the replica before it gets keys:\n    {grant}"));
    } else if steps.dry {
        steps.note(format!("grant: {grant}  (signed with --key-file, else proposed and signed in the console)"));
    } else {
        edit_state(env, move |s| s.deployments.insert(matcher).then_some(()).ok_or_else(|| invalid("already listed")))
            .await?;
        say!("note: with a pending window, the replica gets keys once this state is in force; the VM restarts it until then");
    }

    let at = Vm { project: &project, zone: &zone, name: &name };
    match gc.show(&at.args(&["describe"])).await? {
        Some(vm) => update(steps, env, &admin, &at, &vm, &pin, &image, &candidate, &version).await?,
        None => {
            create(steps, &at, &machine, &sa, &subnet.name, &tenant, &image, &pin).await?;
        }
    }
    if steps.dry {
        let title =
            format!("dry run: {name} in {project} ({zone}), release {version}, pinned to {pin}; nothing is changed");
        eprintln!("{title}");
        for l in &steps.lines {
            eprintln!("  {l}");
        }
        return Ok(());
    }
    let ip = wait(&at).await?;
    say!(
        "{}",
        ui::ok(&format!("replica {name} at {ip}, release {version} — set SEAL_ENDPOINT=https://{ip}:{}", image.port))
    );
    Ok(())
}

/// The network the apps run in: `wanted`, else the project's only one, else asked.
async fn pick_network(env: &Env, project: &str, wanted: Option<&str>) -> anyhow::Result<String> {
    if let Some(n) = wanted {
        GCLOUD
            .show(&["compute", "networks", "describe", n, "--project", project])
            .await?
            .ok_or_else(|| anyhow!("{project} has no network {n}"))?;
        return Ok(n.to_owned());
    }
    let listed = GCLOUD.json(&["compute", "networks", "list", "--project", project]).await?;
    let names: Vec<String> =
        listed.as_array().into_iter().flatten().filter_map(|n| n["name"].as_str().map(str::to_owned)).collect();
    match names.as_slice() {
        [] => bail!("{project} has no VPC network: deploy into the one your apps run in"),
        [one] => {
            say!("{} network {one}: the only one in {project}", ui::dim("·"));
            Ok(one.clone())
        }
        _ if env.sign.yes || !ui::interactive() => {
            bail!("pass --network NAME, the network your apps run in ({})", names.join(", "))
        }
        _ => {
            let choices: Vec<(&str, String)> = names.iter().map(|n| (n.as_str(), String::new())).collect();
            Ok(ui::pick(&format!("Which network do your apps run in? (project {project})"), &choices)?.to_owned())
        }
    }
}

pub struct Subnet {
    pub name: String,
    pub range: String,
}

/// The subnet the VM goes in: `wanted`, else the network's only one in `region`.
async fn subnet(project: &str, network: &str, region: &str, wanted: Option<&str>) -> anyhow::Result<Subnet> {
    let filter = format!("network~/{network}$");
    let listed = GCLOUD
        .json(&[
            "compute",
            "networks",
            "subnets",
            "list",
            "--project",
            project,
            "--regions",
            region,
            "--filter",
            &filter,
        ])
        .await?;
    let found: Vec<Subnet> = listed
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|s| {
            Some(Subnet { name: s["name"].as_str()?.to_owned(), range: s["ipCidrRange"].as_str()?.to_owned() })
        })
        .collect();
    let names = || found.iter().map(|s| s.name.as_str()).collect::<Vec<_>>().join(", ");
    match wanted {
        Some(w) => {
            found.into_iter().find(|s| s.name == w).ok_or_else(|| anyhow!("{network} has no subnet {w} in {region}"))
        }
        None => match found.len() {
            0 => bail!("{network} has no subnet in {region}: pass a --zone in a region it has, or create one there"),
            1 => Ok(found.into_iter().next().expect("one")),
            _ => bail!("{network} has several subnets in {region} ({}): pass --subnet", names()),
        },
    }
}

/// Cloud NAT for the region: any NAT on a router of the network there, else `seal-nat` on a
/// router `seal-nat-router` made now.
async fn nat(steps: &mut Steps<'_>, project: &str, network: &str, region: &str) -> anyhow::Result<()> {
    let filter = format!("network~/{network}$");
    let routers = GCLOUD
        .json(&["compute", "routers", "list", "--project", project, "--regions", region, "--filter", &filter])
        .await?;
    let with_nat =
        routers.as_array().into_iter().flatten().find(|r| r["nats"].as_array().is_some_and(|n| !n.is_empty()));
    if let Some(r) = with_nat {
        steps.note(format!("Cloud NAT: using the one on router {}", r["name"].as_str().unwrap_or("?")));
        return Ok(());
    }
    let p = ["--project", project, "--region", region];
    steps
        .ensure(
            &format!("router {ROUTER} in {region}"),
            &[&["compute", "routers", "describe", ROUTER][..], &p].concat(),
            &[&["compute", "routers", "create", ROUTER, "--network", network][..], &p].concat(),
            &[&["compute", "routers", "delete", ROUTER][..], &p].concat(),
        )
        .await?;
    steps.note(format!("Cloud NAT {NAT} on {ROUTER}: creating (about $32/month plus traffic)"));
    let create = [
        &["compute", "routers", "nats", "create", NAT, "--router", ROUTER][..],
        &p,
        &["--auto-allocate-nat-external-ips", "--nat-all-subnet-ip-ranges"],
    ]
    .concat();
    match steps.change(&create).await {
        Ok(_) => steps.made(
            &format!("Cloud NAT {NAT}"),
            &[&["compute", "routers", "nats", "delete", NAT, "--router", ROUTER][..], &p].concat(),
        ),
        Err(e) if GCLOUD.already_exists(&e) => {}
        Err(e) => return Err(e),
    }
    Ok(())
}

/// The VPC's own ranges may reach the replica's port; nothing from outside may.
async fn firewall(steps: &mut Steps<'_>, project: &str, network: &str, tenant: &str, port: u16) -> anyhow::Result<()> {
    let rule = format!("seal-{tenant}-ingress");
    let allow = format!("tcp:{port}");
    let tag = format!("seal-{tenant}");
    let filter = format!("network~/{network}$");
    let subnets =
        GCLOUD.json(&["compute", "networks", "subnets", "list", "--project", project, "--filter", &filter]).await?;
    let ranges: Vec<&str> =
        subnets.as_array().into_iter().flatten().filter_map(|s| s["ipCidrRange"].as_str()).collect();
    if ranges.is_empty() {
        bail!("{network} has no subnets to allow the replica's port from");
    }
    let sources = ranges.join(",");
    let p = ["--project", project];
    steps
        .ensure(
            &format!("firewall rule {rule} ({allow} from {network}'s ranges)"),
            &[&["compute", "firewall-rules", "describe", &rule][..], &p].concat(),
            &[
                &["compute", "firewall-rules", "create", &rule, "--network", network, "--direction", "INGRESS"][..],
                &["--allow", &allow, "--source-ranges", &sources, "--target-tags", &tag],
                &p,
            ]
            .concat(),
            &[&["compute", "firewall-rules", "delete", &rule][..], &p].concat(),
        )
        .await?;
    Ok(())
}

/// The VM's service account, with the role that gets it attestation tokens. Its email.
async fn service_account(steps: &mut Steps<'_>, project: &str, email: &str, tenant: &str) -> anyhow::Result<String> {
    let account = email.split('@').next().unwrap_or(email);
    let p = ["--project", project];
    let display = format!("Seal enclave for {tenant}");
    let made = steps
        .ensure(
            &format!("service account {email}"),
            &[&["iam", "service-accounts", "describe", email][..], &p].concat(),
            &[&["iam", "service-accounts", "create", account, "--display-name", &display][..], &p].concat(),
            &[&["iam", "service-accounts", "delete", email][..], &p].concat(),
        )
        .await?;
    let email = match made {
        Some(sa) => text(&sa["email"], "service account email")?.to_owned(),
        None => email.to_owned(),
    };
    let member = format!("serviceAccount:{email}");
    // Adding a binding that exists is a no-op.
    steps.note(format!("{email}: {WORKLOAD_ROLE}"));
    steps
        .change(&[
            "projects",
            "add-iam-policy-binding",
            project,
            "--member",
            &member,
            "--role",
            WORKLOAD_ROLE,
            "--condition=None",
        ])
        .await?;
    Ok(email)
}

/// One VM's place, for `gcloud compute instances …` calls.
struct Vm<'a> {
    project: &'a str,
    zone: &'a str,
    name: &'a str,
}

impl Vm<'_> {
    fn args<'s>(&'s self, verb: &[&'s str]) -> Vec<&'s str> {
        let mut a = vec!["compute", "instances"];
        a.extend_from_slice(verb);
        a.extend([self.name, "--project", self.project, "--zone", self.zone]);
        a
    }
}

/// The VM's metadata, keyed.
fn metadata(vm: &Value) -> std::collections::BTreeMap<String, String> {
    vm["metadata"]["items"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|i| Some((i["key"].as_str()?.to_owned(), i["value"].as_str()?.to_owned())))
        .collect()
}

/// The `--metadata` value for the image and the pin. `^~^` makes `~` the separator, since the
/// pin has none and image references have no `~`.
fn launch_metadata(image: &ImageTemplate, pin: &TenantPin) -> String {
    format!("^~^tee-image-reference={}~tee-env-SEAL_TENANT={pin}~tee-restart-policy=Always", image.image)
}

#[allow(clippy::too_many_arguments)]
async fn create(
    steps: &mut Steps<'_>,
    at: &Vm<'_>,
    machine: &str,
    sa: &str,
    subnet: &str,
    tenant: &str,
    image: &ImageTemplate,
    pin: &TenantPin,
) -> anyhow::Result<()> {
    let tag = format!("seal-{tenant}");
    let labels = format!("seal-tenant={tenant}");
    let meta = launch_metadata(image, pin);
    let mut args = at.args(&["create"]);
    args.extend([
        "--machine-type",
        machine,
        "--confidential-compute-type=TDX",
        "--maintenance-policy=TERMINATE",
        "--shielded-secure-boot",
        "--image-project",
        IMAGE_PROJECT,
        "--image-family",
        IMAGE_FAMILY,
        "--service-account",
        sa,
        "--scopes=cloud-platform",
        "--subnet",
        subnet,
        "--no-address",
        "--tags",
        &tag,
        "--labels",
        &labels,
        "--metadata",
        &meta,
    ]);
    steps.note(format!("VM {} ({machine}, Intel TDX, Confidential Space): creating", at.name));
    match steps.change(&args).await {
        Ok(_) => steps.made(&format!("VM {}", at.name), &at.args(&["delete"])),
        Err(e) if GCLOUD.already_exists(&e) => {}
        Err(e) => return Err(e),
    }
    Ok(())
}

/// An existing VM: refused unless it is this tenant's; left alone on the same release; moved to
/// a newer one (new image, then a reset); never moved back.
#[allow(clippy::too_many_arguments)]
async fn update(
    steps: &mut Steps<'_>,
    env: &Env,
    admin: &seal::admin::Admin,
    at: &Vm<'_>,
    vm: &Value,
    pin: &TenantPin,
    image: &ImageTemplate,
    candidate: &super::release::Candidate,
    version: &str,
) -> anyhow::Result<()> {
    let meta = metadata(vm);
    match meta.get("tee-env-SEAL_TENANT") {
        Some(p) if *p == pin.to_string() => {}
        Some(p) => bail!("{} is pinned to {p}, not this home's tenant {pin}", at.name),
        None => bail!("{} is not a Seal replica (no tee-env-SEAL_TENANT): pass another --name", at.name),
    }
    let running = meta.get("tee-image-reference").cloned().unwrap_or_default();
    if running == image.image {
        steps.note(format!("VM {}: already runs release {version}", at.name));
        if vm["status"].as_str() != Some("RUNNING") {
            steps.note(format!("VM {}: starting it", at.name));
            steps.change(&at.args(&["start"])).await?;
        }
        return Ok(());
    }
    if let Some((_, digest)) = running.rsplit_once('@') {
        if let Ok(old) = seal_attest::gcp::measurement(digest) {
            let newer = match admin.control().get_release(PlatformId::GcpConfidentialSpace, &old).await {
                Ok(evidence) => {
                    let trust = env.trust()?.full.ok_or_else(|| anyhow!("no release trust"))?;
                    let verifier = seal_verify::ReleaseVerifier::new(trust.releases);
                    let latest = admin.control().get_checkpoint().await.ok();
                    let (verified, _) = super::release::verify_all(
                        &verifier,
                        vec![evidence],
                        latest.as_ref(),
                        &crate::time(),
                        PlatformId::GcpConfidentialSpace,
                    );
                    verified.first().filter(|c| c.leaf_index > candidate.leaf_index).cloned()
                }
                Err(_) => None,
            };
            if let Some(newer) = newer {
                bail!(
                    "{} runs release {}, newer than {version}: refusing to go back",
                    at.name,
                    newer.release.manifest().version
                );
            }
        }
    }
    steps.note(format!("VM {}: moving to release {version} (new image, then a reset)", at.name));
    let meta = launch_metadata(image, pin);
    let mut add = at.args(&["add-metadata"]);
    add.extend(["--metadata", &meta]);
    steps.change(&add).await?;
    steps.change(&at.args(&["reset"])).await?;
    Ok(())
}

/// Waits until the VM runs and its launcher started the workload, then returns its internal
/// address. Confidential Space keeps the container's log in the VM (`log_redirect` is never),
/// so this reads the VM's state and the launcher's own lines on the serial console.
async fn wait(at: &Vm<'_>) -> anyhow::Result<String> {
    let deadline = Instant::now() + Duration::from_secs(READY_SECS);
    let mut said = String::new();
    loop {
        let vm = GCLOUD.show(&at.args(&["describe"])).await?.ok_or_else(|| anyhow!("VM {} is gone", at.name))?;
        let status = vm["status"].as_str().unwrap_or("?").to_owned();
        let ip = vm["networkInterfaces"][0]["networkIP"].as_str().map(str::to_owned);
        if status == "RUNNING" {
            let serial = GCLOUD.text(&at.args(&["get-serial-port-output"])).await.unwrap_or_default();
            match launcher(&serial) {
                Launch::Running => {
                    let ip = ip.ok_or_else(|| anyhow!("VM {} has no internal address", at.name))?;
                    say!("{} {}: serving", ui::dim("·"), at.name);
                    return Ok(ip);
                }
                Launch::Failed(why) => bail!(
                    "{}'s workload failed to launch: {why}\n  its console: gcloud compute instances get-serial-port-output {} --zone {} --project {}",
                    at.name,
                    at.name,
                    at.zone,
                    at.project
                ),
                Launch::Starting(state) if state != said => {
                    say!("{} {}: {state}", ui::dim("·"), at.name);
                    said = state;
                }
                Launch::Starting(_) => {}
            }
        } else if status != said {
            say!("{} {}: {}", ui::dim("·"), at.name, status.to_lowercase());
            said = status;
        }
        if Instant::now() > deadline {
            bail!("{} is not serving after {} min (last: {said})", at.name, READY_SECS / 60);
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

#[derive(Debug, PartialEq)]
enum Launch {
    Starting(String),
    Running,
    Failed(String),
}

/// What the Confidential Space launcher's serial lines say: the workload started, failed (its
/// error), or neither yet.
fn launcher(serial: &str) -> Launch {
    let lines: Vec<&str> =
        serial.lines().filter(|l| l.contains("confidential-space-launcher") || l.contains("Launcher")).collect();
    if let Some(failed) = lines.iter().rev().find(|l| {
        let l = l.to_ascii_lowercase();
        l.contains("error") || l.contains("failed")
    }) {
        return Launch::Failed(failed.split_once("]: ").map_or(*failed, |(_, m)| m).trim().to_owned());
    }
    if lines.iter().any(|l| l.contains("workload task started") || l.contains("Workload running")) {
        return Launch::Running;
    }
    Launch::Starting(if lines.is_empty() { "booting".into() } else { "pulling the image".into() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_template_is_taken_only_for_its_release() {
        let digest = format!("sha256:{}", "ab".repeat(32));
        let m = seal_attest::gcp::measurement(&digest).unwrap();
        let value = serde_json::json!({ "image": format!("ghcr.io/sealzone/seal-enclave@{digest}") });
        let t = ImageTemplate::parse(&value, &m).unwrap();
        assert_eq!((t.digest.as_str(), t.port), (digest.as_str(), 8443));
        assert!(ImageTemplate::parse(&value, &Measurement([0; 48])).unwrap_err().to_string().contains("refusing"));
        let tagged = serde_json::json!({ "image": "ghcr.io/sealzone/seal-enclave:latest" });
        assert!(ImageTemplate::parse(&tagged, &m).unwrap_err().to_string().contains("no digest"));
    }

    #[test]
    fn zones_name_their_region() {
        assert_eq!(region_of("us-central1-a").unwrap(), "us-central1");
        assert_eq!(region_of("europe-west4-c").unwrap(), "europe-west4");
        assert!(region_of("central").is_err());
    }

    #[test]
    fn the_pin_and_image_go_in_one_metadata_value() {
        let pin: TenantPin = format!("acme@{}", "11".repeat(32)).parse().unwrap();
        let image = ImageTemplate { image: "ghcr.io/x@sha256:ab".into(), digest: "sha256:ab".into(), port: 8443 };
        let meta = launch_metadata(&image, &pin);
        assert!(meta.starts_with("^~^tee-image-reference=ghcr.io/x@sha256:ab~"));
        assert!(meta.contains(&format!("~tee-env-SEAL_TENANT={pin}~")));
        assert!(!pin.to_string().contains('~'), "the separator never occurs in a pin");
    }

    #[test]
    fn the_launcher_says_how_far_it_got() {
        assert_eq!(launcher(""), Launch::Starting("booting".into()));
        let started = "x confidential-space-launcher[1]: pulling image\nx confidential-space-launcher[1]: workload task started\n";
        assert_eq!(launcher(started), Launch::Running);
        let failed = "x confidential-space-launcher[1]: Error: failed to pull image: denied\n";
        assert!(matches!(launcher(failed), Launch::Failed(why) if why.contains("denied")));
    }
}
