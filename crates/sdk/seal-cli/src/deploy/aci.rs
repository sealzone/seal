//! Azure release templates and the ARM template `seal deploy` renders from them.
//!
//! A release template is what `seal-release aci-policy` writes: an ARM template with one
//! confidential container group whose `ccePolicy` is the base64 of the release's container
//! policy. It comes from the control plane or a file and is not trusted: `ReleaseTemplate::parse`
//! takes only the policy and Seal's container (image, command, ports, resources) from it, and
//! the caller deploys it only when the policy's measurement (`seal_attest::azure::measurement`
//! of its SHA-256, `host_data`) is a verified release's. Everything else in the deployed
//! template is rendered here, in the one supported shape: a user-assigned managed identity, a
//! subnet delegated to container groups (egress through its NAT gateway), a private address,
//! `SEAL_TENANT` as the only variable, and the policy as given, so a template served by an
//! untrusted party can add no resource, role or container to the customer's subscription.

use std::collections::BTreeSet;

use anyhow::{anyhow, bail, Context as _};
use base64::Engine as _;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use seal_proto::{Measurement, TenantPin};

pub const GROUP_TYPE: &str = "Microsoft.ContainerInstance/containerGroups";
const API_VERSION: &str = "2023-05-01";
const TENANT_VAR: &str = "SEAL_TENANT";
/// Containers a release policy lists besides Seal's: the generator's pause container and ACI's own.
const NOT_SEALS: [&str; 4] = ["pause-container", "atlas-mount-resolv-conf", "msi-atlas-adapter", "atlas-netstats"];
/// What Seal's container in a release template may set; anything else would be dropped here
/// and the container would no longer match its policy, so it is refused instead.
const CONTAINER_PROPERTIES: [&str; 5] = ["image", "command", "environmentVariables", "ports", "resources"];

/// Seal's container in a release template.
#[derive(Clone, Debug, PartialEq)]
pub struct Container {
    pub name: String,
    pub image: String,
    pub command: Option<Value>,
    /// TCP ports, the enclave API first.
    pub ports: Vec<u16>,
    pub resources: Value,
}

/// What a release template contributes to a deployment.
#[derive(Clone, Debug)]
pub struct ReleaseTemplate {
    pub policy: String,
    pub host_data: [u8; 32],
    pub measurement: Measurement,
    pub container: Container,
}

/// The base64 policy text in a group's `confidentialComputeProperties.ccePolicy`.
fn decode_policy(b64: &str) -> anyhow::Result<String> {
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64.trim()).context("ccePolicy is not base64")?;
    String::from_utf8(bytes).map_err(|_| anyhow!("the policy is not UTF-8"))
}

/// The policy's measurement: `seal_attest::azure::measurement` of its SHA-256.
pub fn measure(policy: &str) -> ([u8; 32], Measurement) {
    let host_data: [u8; 32] = Sha256::digest(policy.as_bytes()).into();
    (host_data, seal_attest::azure::measurement(&host_data))
}

/// The JSON value of the policy's one `<name> := ` line.
fn policy_value(policy: &str, name: &str) -> anyhow::Result<Value> {
    let prefix = format!("{name} := ");
    let mut lines = policy.split('\n').filter_map(|l| l.strip_prefix(prefix.as_str()));
    match (lines.next(), lines.next()) {
        (Some(line), None) => serde_json::from_str(line).with_context(|| format!("the policy's `{name}`")),
        _ => bail!("the policy has no single one-line `{name} :=`"),
    }
}

/// Seal's container in the policy: its name and image.
fn policy_container(policy: &str) -> anyhow::Result<(String, String)> {
    if policy_value(policy, "fragments")? != json!([]) {
        bail!("the policy includes fragments, which would let containers join without changing host_data");
    }
    let containers = policy_value(policy, "containers")?;
    let ours: Vec<&Value> = containers
        .as_array()
        .ok_or_else(|| anyhow!("the policy's containers are not a list"))?
        .iter()
        .filter(|c| !NOT_SEALS.contains(&c["name"].as_str().unwrap_or_default()))
        .collect();
    let [ours] = ours.as_slice() else { bail!("the policy lists {} containers besides ACI's, not one", ours.len()) };
    let field =
        |f: &str| ours[f].as_str().map(str::to_owned).ok_or_else(|| anyhow!("the policy's container has no {f}"));
    Ok((field("name")?, field("id")?))
}

/// The one container group of an ARM template.
pub fn group(template: &Value) -> anyhow::Result<&Value> {
    let groups: Vec<&Value> = template["resources"]
        .as_array()
        .ok_or_else(|| anyhow!("the template has no resources"))?
        .iter()
        .filter(|r| r["type"] == GROUP_TYPE)
        .collect();
    match groups.as_slice() {
        [one] => Ok(one),
        other => bail!("the template has {} container groups, not one", other.len()),
    }
}

fn ports(value: &Value) -> anyhow::Result<Vec<u16>> {
    let list = value.as_array().ok_or_else(|| anyhow!("no ports"))?;
    let mut ports = Vec::new();
    for p in list {
        if p.get("protocol").and_then(Value::as_str).is_some_and(|proto| !proto.eq_ignore_ascii_case("TCP")) {
            bail!("only TCP ports are deployed");
        }
        let port = p["port"].as_u64().and_then(|n| u16::try_from(n).ok()).filter(|&n| n != 0);
        ports.push(port.ok_or_else(|| anyhow!("a port is not a TCP port number"))?);
    }
    if ports.is_empty() || ports.iter().collect::<BTreeSet<_>>().len() != ports.len() {
        bail!("the ports are empty or repeated");
    }
    Ok(ports)
}

impl ReleaseTemplate {
    /// Takes the policy and Seal's container from `template`, refusing anything this command
    /// could not deploy faithfully: other containers, other variables, mounts or settings on
    /// Seal's container, or a policy whose container is not the template's image.
    pub fn parse(template: &Value) -> anyhow::Result<Self> {
        let group = group(template)?;
        let props = &group["properties"];
        if props["sku"] != "Confidential" {
            bail!("the container group is not confidential");
        }
        let policy = props["confidentialComputeProperties"]["ccePolicy"]
            .as_str()
            .filter(|p| !p.is_empty())
            .ok_or_else(|| anyhow!("the container group has no ccePolicy"))?;
        let policy = decode_policy(policy)?;
        let containers = props["containers"].as_array().ok_or_else(|| anyhow!("the group has no containers"))?;
        let [container] = containers.as_slice() else {
            bail!("the group has {} containers, not Seal's alone", containers.len())
        };
        let name = container["name"].as_str().ok_or_else(|| anyhow!("the container has no name"))?;
        let c = container["properties"].as_object().ok_or_else(|| anyhow!("the container has no properties"))?;
        if let Some(extra) = c.keys().find(|k| !CONTAINER_PROPERTIES.contains(&k.as_str())) {
            bail!("the container sets {extra}, which `seal deploy` does not deploy");
        }
        let vars: Vec<&str> = c
            .get("environmentVariables")
            .and_then(Value::as_array)
            .map(|vars| vars.iter().map(|v| v["name"].as_str().unwrap_or_default()).collect())
            .unwrap_or_default();
        if vars != [TENANT_VAR] {
            bail!("the container's variables are {vars:?}; the release passes {TENANT_VAR} alone");
        }
        let image = c.get("image").and_then(Value::as_str).ok_or_else(|| anyhow!("the container has no image"))?;
        if !image.contains("@sha256:") {
            bail!("the image {image} is not named by digest");
        }
        let (policy_name, policy_image) = policy_container(&policy)?;
        if policy_name != name || policy_image != image {
            bail!("the policy is for container {policy_name} ({policy_image}), the template runs {name} ({image})");
        }
        let resources = c.get("resources").cloned().ok_or_else(|| anyhow!("the container has no resources"))?;
        let requests = &resources["requests"];
        if !(requests["cpu"].is_number() && requests["memoryInGB"].is_number()) {
            bail!("the container's resources are not cpu and memoryInGB requests");
        }
        let (host_data, measurement) = measure(&policy);
        Ok(Self {
            policy,
            host_data,
            measurement,
            container: Container {
                name: name.to_owned(),
                image: image.to_owned(),
                command: c.get("command").cloned(),
                ports: ports(c.get("ports").unwrap_or(&Value::Null))?,
                resources,
            },
        })
    }

    /// The registry host of the image (before its first `/`).
    pub fn registry(&self) -> &str {
        self.container.image.split('/').next().unwrap_or_default()
    }
}

/// Where and as whom a replica runs. `identity`, `subnet` and `location` are resource ids or
/// ARM expressions.
#[derive(Clone, Debug)]
pub struct Placement {
    pub name: String,
    pub location: String,
    pub identity: String,
    pub subnet: String,
    pub pin: TenantPin,
    /// A registry user; the password is the template's `registryPassword` parameter.
    pub registry_user: Option<String>,
}

/// The ARM expression for a resource in the deployment's resource group.
pub fn resource_id(kind: &str, names: &[&str]) -> String {
    let names: Vec<String> = names.iter().map(|n| format!("'{}'", n.replace('\'', "''"))).collect();
    format!("[resourceId('{kind}', {})]", names.join(", "))
}

/// The deployed ARM template: one confidential container group, nothing else.
pub fn render(release: &ReleaseTemplate, version: &str, at: &Placement) -> Value {
    let c = &release.container;
    let ports: Vec<Value> = c.ports.iter().map(|p| json!({"protocol": "TCP", "port": p})).collect();
    let mut container = json!({
        "image": c.image,
        "environmentVariables": [{"name": TENANT_VAR, "value": at.pin.to_string()}],
        "ports": ports,
        "resources": c.resources,
    });
    if let Some(command) = &c.command {
        container["command"] = command.clone();
    }
    let mut properties = json!({
        "sku": "Confidential",
        "confidentialComputeProperties": {
            "ccePolicy": base64::engine::general_purpose::STANDARD.encode(&release.policy)
        },
        "osType": "Linux",
        "restartPolicy": "Always",
        "subnetIds": [{"id": at.subnet}],
        "ipAddress": {"type": "Private", "ports": ports},
        "containers": [{"name": c.name, "properties": container}],
    });
    let mut parameters = json!({});
    if let Some(user) = &at.registry_user {
        properties["imageRegistryCredentials"] =
            json!([{"server": release.registry(), "username": user, "password": "[parameters('registryPassword')]"}]);
        parameters = json!({"registryPassword": {"type": "securestring"}});
    }
    json!({
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "parameters": parameters,
        "resources": [{
            "type": GROUP_TYPE,
            "apiVersion": API_VERSION,
            "name": at.name,
            "location": at.location,
            "tags": {"seal-tenant": at.pin.tenant.to_string(), "seal-release": version},
            "identity": {"type": "UserAssigned", "userAssignedIdentities": {at.identity.clone(): {}}},
            "properties": properties,
        }],
    })
}

/// A running group as `az container show` describes it (flattened, or ARM's `properties`).
#[derive(Clone, Debug, PartialEq)]
pub struct Deployed {
    pub location: String,
    /// The managed identity's resource id, and its object (principal) id when shown.
    pub identity: String,
    pub principal_id: Option<String>,
    pub subnet: String,
    /// `SEAL_TENANT` of Seal's container.
    pub pin: String,
    /// The measurement of its policy, when the description includes it.
    pub measurement: Option<Measurement>,
    pub ip: Option<String>,
}

impl Deployed {
    pub fn parse(show: &Value) -> anyhow::Result<Self> {
        let props = show.get("properties").unwrap_or(show);
        if props["sku"] != "Confidential" {
            bail!("the container group is not confidential");
        }
        let identities = show["identity"]["userAssignedIdentities"]
            .as_object()
            .ok_or_else(|| anyhow!("the group has no user-assigned managed identity"))?;
        let mut ids = identities.iter();
        let (identity, details) = match (ids.next(), ids.next()) {
            (Some(one), None) => one,
            _ => bail!("the group has {} managed identities, not one", identities.len()),
        };
        let subnets = props["subnetIds"].as_array().map(Vec::as_slice).unwrap_or_default();
        let [subnet] = subnets else { bail!("the group is in {} subnets, not one", subnets.len()) };
        let pins: Vec<&str> = props["containers"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .flat_map(|c| {
                let c = c.get("properties").unwrap_or(c);
                c["environmentVariables"].as_array().map(Vec::as_slice).unwrap_or_default()
            })
            .filter(|v| v["name"] == TENANT_VAR)
            .filter_map(|v| v["value"].as_str())
            .collect();
        let [pin] = pins.as_slice() else { bail!("the group sets {TENANT_VAR} {} times, not once", pins.len()) };
        let measurement = match props["confidentialComputeProperties"]["ccePolicy"].as_str() {
            Some(p) if !p.is_empty() => Some(measure(&decode_policy(p)?).1),
            _ => None,
        };
        let text =
            |v: &Value, what: &str| v.as_str().map(str::to_owned).ok_or_else(|| anyhow!("the group has no {what}"));
        Ok(Self {
            location: text(&show["location"], "location")?,
            identity: identity.clone(),
            principal_id: details["principalId"].as_str().map(str::to_owned),
            subnet: text(&subnet["id"], "subnet id")?,
            pin: (*pin).to_owned(),
            measurement,
            ip: props["ipAddress"]["ip"].as_str().map(str::to_owned),
        })
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    const TEMPLATE: &str = include_str!("../../../../../deploy/example/aci.template.json");
    const POLICY: &str = include_str!("../../../../../deploy/example/aci-policy.rego");

    /// The example release template: the template the policy was generated from, with its `ccePolicy`.
    pub fn example() -> Value {
        let mut template: Value = serde_json::from_str(TEMPLATE).unwrap();
        template["resources"][0]["properties"]["confidentialComputeProperties"]["ccePolicy"] =
            json!(base64::engine::general_purpose::STANDARD.encode(POLICY));
        template
    }

    pub fn pin() -> TenantPin {
        format!("acme@{}", "ab".repeat(32)).parse().unwrap()
    }

    pub fn placement() -> Placement {
        Placement {
            name: "seal-acme".into(),
            location: "[resourceGroup().location]".into(),
            identity: resource_id("Microsoft.ManagedIdentity/userAssignedIdentities", &["seal-acme"]),
            subnet: resource_id("Microsoft.Network/virtualNetworks/subnets", &["app", "seal"]),
            pin: pin(),
            registry_user: None,
        }
    }

    fn container(template: &mut Value) -> &mut Value {
        &mut template["resources"][0]["properties"]["containers"][0]["properties"]
    }

    #[test]
    fn the_example_release_template_parses_to_its_policy() {
        let release = ReleaseTemplate::parse(&example()).unwrap();
        assert_eq!(release.policy, POLICY);
        let hex: String = release.host_data.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "293733f9e01278d2fd7657f77ec76dd192e6587de1c6a9630ff8fbafbd6160c6", "sha256sum of the file");
        assert_eq!(release.measurement, seal_attest::azure::measurement(&release.host_data));
        assert_eq!(release.container.name, "seal-enclave");
        assert_eq!(release.container.ports, [8443]);
        assert!(release
            .container
            .image
            .ends_with("@sha256:6b872135476028dba6075a89086b47c87fbe74a3893e8a14b091e1b97cd1bffe"));
        assert_eq!(release.registry(), "sealexample.azurecr.io");
    }

    #[test]
    fn templates_the_release_cannot_vouch_for_are_refused() {
        let refused = |edit: &dyn Fn(&mut Value)| {
            let mut t = example();
            edit(&mut t);
            ReleaseTemplate::parse(&t).unwrap_err().to_string()
        };
        assert!(refused(&|t| { container(t)["image"] = json!("evil.example/enclave@sha256:00") })
            .contains("the policy is for"));
        assert!(
            refused(&|t| { container(t)["image"] = json!("sealexample.azurecr.io/enclave:latest") }).contains("digest")
        );
        assert!(refused(&|t| {
            container(t)["environmentVariables"]
                .as_array_mut()
                .unwrap()
                .push(json!({"name": "RUST_LOG", "value": "debug"}))
        })
        .contains("variables"));
        assert!(refused(&|t| { container(t)["volumeMounts"] = json!([]) }).contains("volumeMounts"));
        assert!(refused(&|t| {
            let c = t["resources"][0]["properties"]["containers"][0].clone();
            t["resources"][0]["properties"]["containers"].as_array_mut().unwrap().push(c);
        })
        .contains("2 containers"));
        assert!(
            refused(&|t| { t["resources"][0]["properties"]["sku"] = json!("Standard") }).contains("not confidential")
        );
        assert!(refused(&|t| {
            let g = t["resources"][0].clone();
            t["resources"].as_array_mut().unwrap().push(g);
        })
        .contains("2 container groups"));
        let with_fragments = POLICY.replacen("fragments := []", r#"fragments := [{"feed": "x"}]"#, 1);
        assert!(refused(&|t| {
            t["resources"][0]["properties"]["confidentialComputeProperties"]["ccePolicy"] =
                json!(base64::engine::general_purpose::STANDARD.encode(&with_fragments))
        })
        .contains("fragments"));
    }

    #[test]
    fn the_rendered_template_is_the_supported_shape() {
        let release = ReleaseTemplate::parse(&example()).unwrap();
        let out = render(&release, "0.1.0", &placement());
        let resources = out["resources"].as_array().unwrap();
        assert_eq!(resources.len(), 1, "a container group and nothing else");
        // The rendered template is itself a release template for the same measurement.
        assert_eq!(ReleaseTemplate::parse(&out).unwrap().measurement, release.measurement);
        let g = &resources[0];
        assert_eq!(g["name"], "seal-acme");
        assert_eq!(g["identity"]["type"], "UserAssigned");
        assert!(g["identity"]["userAssignedIdentities"]
            .get("[resourceId('Microsoft.ManagedIdentity/userAssignedIdentities', 'seal-acme')]")
            .is_some());
        let p = &g["properties"];
        assert_eq!(p["ipAddress"]["type"], "Private", "no public address");
        assert_eq!(p["subnetIds"][0]["id"], "[resourceId('Microsoft.Network/virtualNetworks/subnets', 'app', 'seal')]");
        assert!(p.get("imageRegistryCredentials").is_none());
        let env = &p["containers"][0]["properties"]["environmentVariables"];
        assert_eq!(env, &json!([{"name": "SEAL_TENANT", "value": pin().to_string()}]));
        assert_eq!(g["tags"]["seal-release"], "0.1.0");

        let out = render(&release, "0.1.0", &Placement { registry_user: Some("puller".into()), ..placement() });
        let creds = &out["resources"][0]["properties"]["imageRegistryCredentials"];
        assert_eq!(
            creds,
            &json!([{"server": "sealexample.azurecr.io", "username": "puller", "password": "[parameters('registryPassword')]"}])
        );
        assert_eq!(out["parameters"]["registryPassword"]["type"], "securestring", "no password in the template");
        assert_eq!(resource_id("K", &["it's"]), "[resourceId('K', 'it''s')]");
    }

    /// `az container show` of a group deployed from `template`.
    pub fn shown(template: &Value, ip: &str) -> Value {
        let g = &template["resources"][0];
        let identity = g["identity"]["userAssignedIdentities"].as_object().unwrap().keys().next().unwrap().clone();
        let mut p = g["properties"].clone();
        p["ipAddress"]["ip"] = json!(ip);
        p["subnetIds"] = json!([{"id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/app/subnets/seal"}]);
        let mut show = json!({
            "name": g["name"],
            "location": "eastus",
            "identity": {"type": "UserAssigned", "userAssignedIdentities": {identity: {"principalId": "oid-1", "clientId": "c-1"}}},
        });
        for (k, v) in p.as_object().unwrap() {
            show[k] = v.clone();
        }
        show
    }

    #[test]
    fn a_running_group_is_read_back() {
        let release = ReleaseTemplate::parse(&example()).unwrap();
        let show = shown(&render(&release, "0.1.0", &placement()), "10.0.2.4");
        let d = Deployed::parse(&show).unwrap();
        assert_eq!(d.measurement, Some(release.measurement));
        assert_eq!(d.pin, pin().to_string());
        assert_eq!(d.principal_id.as_deref(), Some("oid-1"));
        assert_eq!(d.ip.as_deref(), Some("10.0.2.4"));
        assert_eq!(d.location, "eastus");
        assert!(d.subnet.ends_with("/subnets/seal"));
        // ARM's own shape, with `properties`, reads the same.
        let arm = json!({"location": "eastus", "identity": show["identity"], "properties": show});
        assert_eq!(Deployed::parse(&arm).unwrap(), d);
        let mut two = show.clone();
        two["identity"]["userAssignedIdentities"]["/other"] = json!({});
        assert!(Deployed::parse(&two).is_err());
    }
}
