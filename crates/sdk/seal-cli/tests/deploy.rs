//! `seal deploy azure` and `seal deploy upgrade` end to end against the in-process dev log and
//! fake control plane, with releases built from the example template and policy, and a fake
//! `az` on PATH that answers like the Azure CLI and keeps what it was asked to deploy. Nothing
//! reaches Azure.
#![cfg(all(feature = "sim", unix))]

mod common;

use std::path::{Path, PathBuf};

use base64::Engine as _;
use serde_json::{json, Value};

use common::Servers;
use seal_crypto::sign::SigningKey;
use seal_proto::identity::IdentityMatcher;
use seal_proto::release::{Component, LogEntry, ReleaseEvidence, ReleaseManifest, RELEASE_LABEL};
use seal_proto::signed::Signed;
use seal_proto::{Measurement, PlatformId, ServiceKeyVersion, TenantPin};

const TEMPLATE: &str = include_str!("../../../../deploy/example/aci.template.json");
const POLICY: &str = include_str!("../../../../deploy/example/aci-policy.rego");
const RELEASE_KEYS: [u8; 3] = [0x31, 0x32, 0x33];

const FAKE_AZ: &str = r#"#!/bin/sh
echo "$*" >> "$FAKE_AZ/log"
not_found() { echo "ERROR: (ResourceNotFound) The resource was not found." >&2; exit 3; }
arg() {
    flag="$1"; shift
    while [ $# -gt 0 ]; do [ "$1" = "$flag" ] && { echo "$2"; return; }; shift; done
}
VNET=/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/app-vnet
vnet() {
    seal=""; [ -f "$FAKE_AZ/subnet.json" ] && seal=", $(cat "$FAKE_AZ/subnet.json")"
    echo "{\"id\": \"$VNET\", \"name\": \"app-vnet\", \"resourceGroup\": \"rg\", \"location\": \"eastus\",
           \"addressSpace\": {\"addressPrefixes\": [\"10.20.0.0/16\"]},
           \"subnets\": [{\"id\": \"$VNET/subnets/apps\", \"name\": \"apps\", \"addressPrefix\": \"10.20.0.0/24\",
                          \"delegations\": []}$seal]}"
}
case "$*" in
"network vnet list "*) echo "[$(vnet)]" ;;
"network vnet show "*) vnet ;;
"network vnet subnet show "*)
    [ -f "$FAKE_AZ/subnet.json" ] || not_found
    cat "$FAKE_AZ/subnet.json" ;;
"network vnet subnet create "*)
    echo "{\"id\": \"$VNET/subnets/$(arg -n "$@")\", \"name\": \"$(arg -n "$@")\",
           \"addressPrefix\": \"$(arg --address-prefixes "$@")\",
           \"delegations\": [{\"serviceName\": \"$(arg --delegations "$@")\"}],
           \"natGateway\": {\"id\": \"$(arg --nat-gateway "$@")\"}}" > "$FAKE_AZ/subnet.json"
    cat "$FAKE_AZ/subnet.json" ;;
"network nat gateway show "*)
    [ -f "$FAKE_AZ/nat.json" ] || not_found
    cat "$FAKE_AZ/nat.json" ;;
"network nat gateway create "*)
    echo "{\"id\": \"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/natGateways/$(arg -n "$@")\"}" \
        > "$FAKE_AZ/nat.json"
    cat "$FAKE_AZ/nat.json" ;;
"network public-ip create "*) echo '{"publicIp": {"ipAddress": "203.0.113.7"}}' ;;
"ad app list "*)
    if [ -f "$FAKE_AZ/app.json" ]; then echo "[$(cat "$FAKE_AZ/app.json")]"; else echo '[]'; fi ;;
"ad app create "*)
    echo '{"appId": "app-1", "identifierUris": []}' > "$FAKE_AZ/app.json"
    cat "$FAKE_AZ/app.json" ;;
"ad app update "*) echo '{"appId": "app-1", "identifierUris": ["api://app-1"]}' > "$FAKE_AZ/app.json" ;;
"ad sp list "*)
    if [ -f "$FAKE_AZ/sp" ]; then echo '[{"appId": "app-1"}]'; else echo '[]'; fi ;;
"ad sp create "*)
    touch "$FAKE_AZ/sp"
    echo '{"appId": "app-1"}' ;;
"identity show "*)
    [ -f "$FAKE_AZ/identity.json" ] || not_found
    cat "$FAKE_AZ/identity.json" ;;
"identity create "*)
    echo '{"id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/seal-acme",
           "principalId": "oid-1", "tenantId": "tid-1", "clientId": "cid-1"}' > "$FAKE_AZ/identity.json"
    cat "$FAKE_AZ/identity.json" ;;
"deployment group create "*)
    while [ $# -gt 0 ]; do
        [ "$1" = "--template-file" ] && cp "$2" "$FAKE_AZ/deployed.json"
        [ "$1" = "--parameters" ] && cp "${2#@}" "$FAKE_AZ/parameters.json"
        shift
    done
    echo '{}' ;;
"container show "*)
    [ -f "$FAKE_AZ/show.json" ] || not_found
    cat "$FAKE_AZ/show.json" ;;
*) echo "fake az: unexpected $*" >&2; exit 1 ;;
esac
"#;

const SUBNET_ID: &str =
    "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/app-vnet/subnets/seal";

/// A directory with the fake `az` in `bin/`.
fn fake_az(dir: &Path) -> PathBuf {
    std::fs::create_dir_all(dir.join("bin")).unwrap();
    let script = dir.join("bin").join("az");
    std::fs::write(&script, FAKE_AZ).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    dir.to_owned()
}

fn release_key(n: u8) -> SigningKey {
    SigningKey::from_seed(&[n; 32])
}

/// The example template with `policy` as its `ccePolicy`.
fn release_template(policy: &str) -> Value {
    let mut template: Value = serde_json::from_str(TEMPLATE).unwrap();
    template["resources"][0]["properties"]["confidentialComputeProperties"]["ccePolicy"] =
        json!(base64::engine::general_purpose::STANDARD.encode(policy));
    template
}

fn measure(policy: &str) -> Measurement {
    use sha2::Digest as _;
    seal_attest::azure::measurement(&sha2::Sha256::digest(policy.as_bytes()).into())
}

/// Signs, logs and stores an Azure enclave release for `policy`, with `template` as its template.
fn publish(servers: &Servers, version: &str, policy: &str, template: Value) -> Measurement {
    let measurement = measure(policy);
    let manifest = ReleaseManifest {
        component: Component::Enclave,
        platform: PlatformId::AzureSnpAci,
        measurement,
        service_key_version: ServiceKeyVersion(1),
        version: version.into(),
        source_commit: "abc".into(),
        serves: None,
    };
    let mut signed = Signed { body: manifest, signatures: vec![] };
    for n in &RELEASE_KEYS[..2] {
        release_key(*n).cosign(RELEASE_LABEL, &mut signed);
    }
    let evidence = {
        let mut log = servers.log.lock().unwrap();
        let index = log.append(LogEntry::Release(signed.body.clone())).unwrap();
        ReleaseEvidence { manifest: signed, included: log.prove(index), fresh: log.checkpoint(), auditor: None }
    };
    let mut stored = servers.stored.lock().unwrap();
    stored.releases.push(evidence);
    stored.templates.insert(measurement.to_string(), template);
    measurement
}

/// Adds release trust (two of `RELEASE_KEYS`, no time lock) to the home's trust.
fn trust_releases(servers: &Servers, home: &Path) {
    let path = home.join("trust.json");
    let mut config: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let t = servers.tlog_trust();
    config["releases"] = json!({
        "tlog": {"origin": t.origin, "log_key": t.log_key, "witness_keys": t.witness_keys, "witness_quorum": t.witness_quorum},
        "release_keys": RELEASE_KEYS.iter().map(|&n| release_key(n).public_key()).collect::<Vec<_>>(),
        "release_threshold": 2,
        "time_lock_secs": 0,
    });
    std::fs::write(&path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
}

struct Run {
    home: PathBuf,
    fake: PathBuf,
}

/// `dev init` for acme with the home's admin key and `extra` options.
fn init_args(files: &common::HomeFiles, extra: &[&'static str]) -> Vec<String> {
    let mut args: Vec<String> =
        ["dev", "init", "--tenant", "acme", "--yes", "--key-file"].iter().map(|s| s.to_string()).collect();
    args.push(files.key.to_str().unwrap().into());
    args.push("--registrar-key".into());
    args.push(files.registrar.to_str().unwrap().into());
    args.extend(extra.iter().map(|s| s.to_string()));
    args
}

impl Run {
    /// `seal --home HOME args...` with the fake `az` first on PATH, signing with the home's
    /// admin key; (success, stdout, stderr).
    async fn seal(&self, args: &[&str]) -> (bool, String, String) {
        let path = format!("{}:{}", self.fake.join("bin").display(), std::env::var("PATH").unwrap_or_default());
        let mut command = common::seal_command(&self.home);
        command.args(args);
        if matches!(args.first(), Some(&"deploy") | Some(&"release")) {
            command.arg("--key-file").arg(self.home.join("admin.key"));
        }
        let out = command
            .env("PATH", path)
            .env("FAKE_AZ", &self.fake)
            .env("SEAL_REGISTRY_PASSWORD", "registry-secret")
            .output()
            .await
            .unwrap();
        let (stdout, stderr) =
            (String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned());
        (out.status.success(), stdout, stderr)
    }

    async fn ok(&self, args: &[&str]) -> (String, String) {
        let (success, stdout, stderr) = self.seal(args).await;
        assert!(success, "seal {args:?} failed:\n{stdout}\n{stderr}");
        (stdout, stderr)
    }

    async fn fails(&self, args: &[&str]) -> String {
        let (success, stdout, stderr) = self.seal(args).await;
        assert!(!success, "seal {args:?} succeeded:\n{stdout}\n{stderr}");
        stderr
    }

    fn az_log(&self) -> String {
        std::fs::read_to_string(self.fake.join("log")).unwrap_or_default()
    }

    fn deployed(&self) -> Value {
        serde_json::from_slice(&std::fs::read(self.fake.join("deployed.json")).unwrap()).unwrap()
    }

    /// What `az container show` answers for the group last deployed, at `ip`.
    fn show_deployed(&self, ip: &str) {
        let g = self.deployed()["resources"][0].clone();
        let mut show = g["properties"].clone();
        show["ipAddress"]["ip"] = json!(ip);
        show["name"] = g["name"].clone();
        show["location"] = json!("eastus");
        let id = g["identity"]["userAssignedIdentities"].as_object().unwrap().keys().next().unwrap().clone();
        show["identity"] = json!({"type": "UserAssigned", "userAssignedIdentities": {id: {"principalId": "oid-1", "clientId": "cid-1"}}});
        std::fs::write(self.fake.join("show.json"), serde_json::to_vec(&show).unwrap()).unwrap();
    }
}

fn policy_of(template: &Value) -> String {
    let b64 = template["resources"][0]["properties"]["confidentialComputeProperties"]["ccePolicy"].as_str().unwrap();
    String::from_utf8(base64::engine::general_purpose::STANDARD.decode(b64).unwrap()).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn deploy_and_upgrade_azure_replicas() {
    let servers = Servers::start("deploy").await;
    let home = servers.dir.0.join("home");
    let files = servers.write_home(&home);
    let fake = fake_az(&servers.dir.0.join("az"));
    let run = Run { home: home.clone(), fake: fake.clone() };
    let init = init_args(&files, &[]);
    let (out, _) = run.ok(&init.iter().map(String::as_str).collect::<Vec<_>>()).await;
    let pin: TenantPin = out.lines().find_map(|l| l.strip_prefix("SEAL_TENANT=")).unwrap().parse().unwrap();

    let azure = ["deploy", "azure", "--vnet", "app-vnet"];
    let err = run.fails(&[&azure[..], &["--dry-run"]].concat()).await;
    assert!(err.contains("names no release trust"), "{err}");
    trust_releases(&servers, &home);
    let err = run.fails(&[&azure[..], &["--dry-run"]].concat()).await;
    assert!(err.contains("no Azure enclave release"), "{err}");

    let v1 = publish(&servers, "0.1.0", POLICY, release_template(POLICY));

    // A dry run verifies the release, reads the VNet and prints what it would make and the
    // template; it changes nothing.
    let (out, err) = run.ok(&[&azure[..], &["--dry-run"]].concat()).await;
    let log = run.az_log();
    assert!(!log.contains("create") && !log.contains("update"), "a dry run changes nothing: {log}");
    assert!(err.contains(&format!("measurement {v1}")) && err.contains("verified"), "{err}");
    for planned in [
        "az ad app create --display-name seal-acme",
        "subnet seal 10.20.1.0/27 in app-vnet: creating",
        "az network nat gateway create -g rg -n seal-nat",
        "--address-prefixes 10.20.1.0/27 --delegations Microsoft.ContainerInstance/containerGroups",
        "az identity create -g rg -n seal-acme",
        "seal grant enclave azure --object-id PRINCIPAL_ID",
        "az deployment group create -g rg -n seal-acme",
    ] {
        assert!(err.contains(planned), "{planned}: {err}");
    }
    let template: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(policy_of(&template), POLICY);
    let g = &template["resources"][0];
    assert_eq!(g["properties"]["subnetIds"][0]["id"], SUBNET_ID);
    assert_eq!(g["location"], "eastus", "the VNet's location");
    let container = &g["properties"]["containers"][0]["properties"];
    assert_eq!(container["environmentVariables"], json!([{"name": "SEAL_TENANT", "value": pin.to_string()}]));
    // Without a terminal, the VNet is named.
    let err = run.fails(&["deploy", "azure", "--dry-run"]).await;
    assert!(err.contains("pass --vnet") && err.contains("app-vnet"), "{err}");
    // A prepared subnet is used only as it is.
    let err = run.fails(&["deploy", "azure", "--subnet", "app-vnet/apps", "--dry-run"]).await;
    assert!(err.contains("not delegated to container groups"), "{err}");

    // The deployment: audience registered, subnet and NAT gateway made, identity created,
    // granted, then the group.
    std::fs::remove_file(fake.join("log")).unwrap();
    let (out, _) = run.ok(&[&azure[..], &["--registry-user", "puller", "--yes"]].concat()).await;
    let log = run.az_log();
    for step in [
        "ad app create --display-name seal-acme",
        "ad app update --id app-1 --identifier-uris api://app-1",
        "ad sp create --id app-1",
        "network public-ip create -g rg -n seal-nat-ip -l eastus --sku Standard --allocation-method Static",
        "network nat gateway create -g rg -n seal-nat -l eastus --public-ip-addresses seal-nat-ip",
        "network vnet subnet create -g rg --vnet-name app-vnet -n seal --address-prefixes 10.20.1.0/27",
        "network vnet subnet show --ids",
        "identity create",
        "deployment group create",
    ] {
        assert!(log.contains(step), "{step}: {log}");
    }
    assert!(!log.contains("registry-secret"), "the password is never an argument");
    let parameters = std::fs::read_to_string(fake.join("parameters.json")).unwrap();
    assert!(parameters.contains("registry-secret"));
    let deployed = run.deployed();
    assert_eq!(policy_of(&deployed), POLICY);
    let g = &deployed["resources"][0];
    assert!(g["identity"]["userAssignedIdentities"]
        .get("/subscriptions/s/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/seal-acme")
        .is_some());
    assert_eq!(g["properties"]["subnetIds"][0]["id"], SUBNET_ID);
    assert!(out.contains("audience api://app-1: registered"), "{out}");
    assert!(out.contains("+ deployment") && out.contains("published state version"), "{out}");
    let state = servers.verified().state().clone();
    let granted = IdentityMatcher::Azure {
        entra_tenant: "tid-1".into(),
        object_id: "oid-1".into(),
        audience: "api://app-1".into(),
        hosted: None,
    };
    assert!(state.deployments.contains(&granted));

    // A second replica reuses the subnet, its NAT gateway, the identity and the tenant's
    // audience; nothing is made or signed again.
    std::fs::remove_file(fake.join("log")).unwrap();
    let version = state.version;
    let (out, _) = run.ok(&[&azure[..], &["--name", "seal-acme-2"]].concat()).await;
    assert!(out.contains("audience api://app-1") && out.contains("NAT gateway: using seal-nat"), "{out}");
    assert!(out.contains("already a deployment"), "{out}");
    let log = run.az_log();
    assert_eq!(log.matches("create").count(), 1, "only the group is deployed: {log}");
    assert!(!log.contains("ad app"), "{log}");
    assert_eq!(servers.verified().state().version, version);

    // Upgrade: nothing newer yet.
    run.show_deployed("10.0.2.4");
    let (out, _) = run.ok(&["deploy", "upgrade", "-g", "rg"]).await;
    assert!(out.contains("already runs release 0.1.0"), "{out}");

    // A newer release: the group is redeployed with it, keeping identity, subnet and pin.
    let policy2 = format!("{POLICY}\n");
    let v2 = publish(&servers, "0.2.0", &policy2, release_template(&policy2));
    let before = run.deployed();
    let (out, _) = run.ok(&["deploy", "upgrade", "-g", "rg"]).await;
    assert!(out.contains(&format!("from {v1} to release 0.2.0 ({v2})")), "{out}");
    assert!(out.contains("SEAL_ENDPOINT=https://10.0.2.4:8443"), "{out}");
    let after = run.deployed();
    assert_eq!(policy_of(&after), policy2);
    assert_eq!(after["resources"][0]["identity"], before["resources"][0]["identity"]);
    assert_eq!(after["resources"][0]["properties"]["subnetIds"], before["resources"][0]["properties"]["subnetIds"]);
    assert_eq!(after["resources"][0]["location"], "eastus", "the group's own location");
    assert_eq!(
        after["resources"][0]["properties"]["containers"][0]["properties"]["environmentVariables"],
        json!([{"name": "SEAL_TENANT", "value": pin.to_string()}])
    );

    // Never back to an older release.
    run.show_deployed("10.0.2.4");
    let err = run.fails(&["deploy", "upgrade", "-g", "rg", "--release", &v1.to_string()]).await;
    assert!(err.contains("refusing to go back"), "{err}");

    // A group pinned to another tenant is not touched.
    let mut show: Value = serde_json::from_slice(&std::fs::read(fake.join("show.json")).unwrap()).unwrap();
    show["containers"][0]["properties"]["environmentVariables"][0]["value"] =
        json!(format!("other@{}", "cd".repeat(32)));
    std::fs::write(fake.join("show.json"), serde_json::to_vec(&show).unwrap()).unwrap();
    let err = run.fails(&["deploy", "upgrade", "-g", "rg"]).await;
    assert!(err.contains("pinned to other@"), "{err}");

    // A template whose policy is not its release's is refused, whoever serves it.
    let policy3 = format!("{POLICY}\n\n");
    let v3 = publish(&servers, "0.3.0", &policy3, release_template(POLICY));
    let err = run.fails(&[&azure[..], &["--dry-run"]].concat()).await;
    assert!(err.contains(&format!("not release {v3}")), "{err}");
    // From a file, it must still be a verified release.
    let file = servers.dir.0.join("unreleased.json");
    std::fs::write(&file, serde_json::to_vec(&release_template(&format!("{POLICY}\n\n\n"))).unwrap()).unwrap();
    let err = run.fails(&[&azure[..], &["--dry-run", "--template", file.to_str().unwrap()]].concat()).await;
    assert!(err.contains("404") || err.contains("control plane"), "{err}");
    let file2 = servers.dir.0.join("v2.json");
    std::fs::write(&file2, serde_json::to_vec(&release_template(&policy2)).unwrap()).unwrap();
    let (out, _) = run.ok(&[&azure[..], &["--dry-run", "--template", file2.to_str().unwrap()]].concat()).await;
    assert_eq!(policy_of(&serde_json::from_str(&out).unwrap()), policy2);

    let (success, _, stderr) = run.seal(&["deploy", "gcp"]).await;
    assert!(!success && stderr.contains("not available in this build"), "{stderr}");
}

#[tokio::test(flavor = "multi_thread")]
async fn cosigning_tenants_deploy_only_releases_they_approved() {
    let servers = Servers::start("deploy-cosign").await;
    let home = servers.dir.0.join("home");
    let files = servers.write_home(&home);
    let run = Run { home: home.clone(), fake: fake_az(&servers.dir.0.join("az")) };
    let init = init_args(&files, &["--cosign-releases"]);
    run.ok(&init.iter().map(String::as_str).collect::<Vec<_>>()).await;
    trust_releases(&servers, &home);
    let m = publish(&servers, "0.1.0", POLICY, release_template(POLICY));
    let dry_run = ["deploy", "azure", "--vnet", "app-vnet", "--audience", "api://seal-acme", "--dry-run"];
    let err = run.fails(&dry_run).await;
    assert!(err.contains(&format!("seal release approve {m}")), "{err}");
    run.ok(&["release", "approve", &m.to_string(), "--yes"]).await;
    let (out, _) = run.ok(&dry_run).await;
    assert_eq!(policy_of(&serde_json::from_str(&out).unwrap()), POLICY);
}
