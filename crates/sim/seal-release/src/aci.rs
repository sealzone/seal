//! The Azure release policy: what `az confcom acipolicygen` generates for the release's ARM
//! template, rewritten to the rules of the release (ARCHITECTURE.md, the Azure row):
//!
//! - `fragments := []`: no infra fragment, which would let containers join the group without
//!   changing `host_data`. ACI's own containers are listed instead (`AciContainers`:
//!   `atlas-mount-resolv-conf`, `msi-atlas-adapter`, `atlas-netstats`, copied from Microsoft's
//!   infra fragment), replacing any of the same name.
//! - Seal's container: not elevated, no exec processes, and its operator-set variables allowed
//!   only by anchored re2 rules (`Component::Enclave`: the tenant pin, `TENANT_RULE`, required;
//!   `Component::Guardian`: `CEREMONY_RULE`, `WRAPPED_ROOTS_RULE`, `SUCCEED_FROM_RULE` and
//!   `RELEASES_RULE`, optional), in place of
//!   every rule the generator wrote for them (from the template's placeholder values). Every
//!   variable ACI injects (`INJECTED`) has a rule, since dropping variables is not allowed.
//! - No containers but Seal's, the generator's `pause-container` and ACI's three.
//! - `allow_dump_stacks`, `allow_runtime_logging`, `allow_environment_variable_dropping` and
//!   `allow_unencrypted_scratch` false.
//! - Nothing outside the framework's skeleton: `package policy`, the two `future.keywords`
//!   imports, `api_version` and `framework_version`, `containers`, `fragments`, the six known
//!   flags, each of `FRAMEWORK_RULES` bound to the framework's rule of the same name, and
//!   `reason`, each exactly once, and empty lines. A policy with any other line (a rule of
//!   its own, a comment, a rule bound to another) is refused, not rewritten.
//!
//! The policy text is otherwise kept byte for byte: `containers` and `fragments` are compact
//! JSON with sorted keys, as the generator writes them, so rewriting a conforming policy
//! returns it unchanged. `host_data` is the SHA-256 of the policy text (what ACI is given
//! base64-encoded), and the measurement is `seal_attest::azure::measurement(host_data)`.
//!
//! The Key Vault release policy a guardian's root key is created with, which pins the guardian
//! group's `host_data`, is the guardian's own `seal_guardian::keysource::release_policy`: the
//! one its `check_release_policy` accepts.

use anyhow::{anyhow, bail, Context as _};
use seal_proto::release::Component;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Allows exactly `<tenant>@<root id>`: a tenant name (`seal_proto::TenantId`) and 64
/// lowercase hex digits.
const TENANT_RULE: &str = "^SEAL_TENANT=[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?@[0-9a-f]{64}$";

/// The guardian's root ceremony switch (`1` runs it).
const CEREMONY_RULE: &str = "^SEAL_GUARDIAN_CEREMONY=[01]?$";

/// The guardian's wrapped roots, `<Key Vault key version>:<standard base64>` comma-separated,
/// or none (the ceremony; ACI passes a variable set to `""` as its bare name). Only the
/// characters: the guardian parses the value, and the policy's regexp engine (Go's RE2) refuses
/// counted repetitions above 1000, which a wrapped root's base64 needs.
const WRAPPED_ROOTS_RULE: &str = "^SEAL_GUARDIAN_WRAPPED_ROOTS(=[0-9A-Za-z+/=:,]*)?$";

/// The guardian a successor takes its root from, an `https://` origin, or none. Any origin is
/// safe to allow: the successor accepts only a response signed by its compiled guardian key.
const SUCCEED_FROM_RULE: &str = "^SEAL_GUARDIAN_SUCCEED_FROM(=(https://[0-9A-Za-z.-]+(:[0-9]+)?/?)?)?$";

/// The control plane a successor fetches its release evidence from, an `https://` origin, or
/// none. The predecessor verifies the evidence, so its source does not matter.
const RELEASES_RULE: &str = "^SEAL_GUARDIAN_RELEASES(=(https://[0-9A-Za-z.-]+(:[0-9]+)?/?)?)?$";

/// The pinned attestation authority of Seal's guardians' release policies: Microsoft Azure
/// Attestation's shared endpoint in East US.
pub const MAA_EASTUS: &str = "https://sharedeus.eus.attest.azure.net";

/// The operator-set variables of `component`'s container: name, rule, required.
fn operator_rules(component: Component) -> &'static [(&'static str, &'static str, bool)] {
    match component {
        Component::Enclave => &[("SEAL_TENANT", TENANT_RULE, true)],
        Component::Guardian => &[
            ("SEAL_GUARDIAN_CEREMONY", CEREMONY_RULE, false),
            ("SEAL_GUARDIAN_WRAPPED_ROOTS", WRAPPED_ROOTS_RULE, false),
            ("SEAL_GUARDIAN_SUCCEED_FROM", SUCCEED_FROM_RULE, false),
            ("SEAL_GUARDIAN_RELEASES", RELEASES_RULE, false),
        ],
    }
}

/// Variables ACI injects into every container of a group with a managed identity. With
/// environment variable dropping off, a container whose policy lacks a rule for one of them
/// does not start.
const INJECTED: [&str; 8] = [
    "IDENTITY_API_VERSION",
    "IDENTITY_HEADER",
    "IDENTITY_SERVER_THUMBPRINT",
    "APP_IDENTITY_ENDPOINT",
    "IDENTITY_ENDPOINT",
    "MSI_ENDPOINT",
    "MSI_SECRET",
    "IMDS_ENDPOINT",
];

/// The names of ACI's own containers, in the order the policy lists them.
const ACI_CONTAINERS: [&str; 3] = ["atlas-mount-resolv-conf", "msi-atlas-adapter", "atlas-netstats"];

const PAUSE: &str = "pause-container";

/// Flags that must be `false`.
const OFF: [&str; 4] =
    ["allow_dump_stacks", "allow_runtime_logging", "allow_environment_variable_dropping", "allow_unencrypted_scratch"];

/// Flags that may be either.
const EITHER: [&str; 2] = ["allow_properties_access", "allow_capability_dropping"];

/// The framework's rules a policy binds, each as `<rule> := data.framework.<rule>`.
const FRAMEWORK_RULES: [&str; 18] = [
    "mount_device",
    "unmount_device",
    "mount_overlay",
    "unmount_overlay",
    "create_container",
    "exec_in_container",
    "exec_external",
    "shutdown_container",
    "signal_container_process",
    "plan9_mount",
    "plan9_unmount",
    "get_properties",
    "dump_stacks",
    "runtime_logging",
    "load_fragment",
    "scratch_mount",
    "scratch_unmount",
    "rw_mount_device",
];

/// The skeleton's fixed lines.
const FIXED: [&str; 5] = [
    "package policy",
    "import future.keywords.every",
    "import future.keywords.in",
    "fragments := []",
    r#"reason := {"errors": data.framework.errors}"#,
];

/// A quoted version: dot-separated decimal numbers.
fn is_version(value: &str) -> bool {
    value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .is_some_and(|v| v.split('.').all(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())))
}

/// Refuses a policy with anything outside the framework skeleton (module docs). Runs on the
/// rewritten lines, where `containers` and `fragments` are one line each.
fn skeleton(lines: &[String]) -> anyhow::Result<()> {
    let mut seen = std::collections::BTreeSet::new();
    for line in lines.iter().filter(|l| !l.trim().is_empty()) {
        let key = match line.split_once(" := ") {
            _ if FIXED.contains(&line.as_str()) => line.as_str(),
            Some((name, value))
                if match name {
                    "api_version" | "framework_version" => is_version(value),
                    "containers" => value.starts_with('['),
                    _ if OFF.contains(&name) => value == "false",
                    _ if EITHER.contains(&name) => value == "true" || value == "false",
                    _ => FRAMEWORK_RULES.contains(&name) && value.strip_prefix("data.framework.") == Some(name),
                } =>
            {
                name
            }
            _ => bail!("the policy has a line outside the framework skeleton: {line:?}"),
        };
        if !seen.insert(key) {
            bail!("the policy repeats {line:?}");
        }
    }
    let expected = FIXED.len() + 3 + OFF.len() + EITHER.len() + FRAMEWORK_RULES.len();
    if seen.len() != expected {
        bail!("the policy lacks part of the framework skeleton ({} of its {expected} lines)", seen.len());
    }
    Ok(())
}

/// ACI's three containers as the infra fragment defines them (a JSON array of policy
/// container objects, `deploy/azure/aci-containers.json`).
pub struct AciContainers(Vec<Value>);

impl AciContainers {
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let containers: Vec<Value> = serde_json::from_str(text).context("ACI containers")?;
        let names: Vec<&str> = containers.iter().map(|c| c["name"].as_str().unwrap_or_default()).collect();
        if names != ACI_CONTAINERS {
            bail!("ACI containers: expected {ACI_CONTAINERS:?}, got {names:?}");
        }
        Ok(Self(containers))
    }
}

/// The line holding `<name> := `, which must be the only one.
fn assignment(lines: &[String], name: &str) -> anyhow::Result<usize> {
    let prefix = format!("{name} := ");
    let mut found = lines.iter().enumerate().filter(|(_, l)| l.starts_with(prefix.as_str())).map(|(i, _)| i);
    match (found.next(), found.next()) {
        (Some(one), None) => Ok(one),
        (None, _) => Err(anyhow!("the policy has no `{name} :=` line")),
        (Some(_), Some(_)) => Err(anyhow!("the policy has more than one `{name} :=` line")),
    }
}

/// Replaces the JSON value of `<name> := <value>` (on one line, or pretty-printed over several
/// as the generator writes `fragments`) with `f` of it, as one compact line.
fn replace_json(
    lines: &mut Vec<String>,
    name: &str,
    f: impl FnOnce(Value) -> anyhow::Result<Value>,
) -> anyhow::Result<()> {
    let start = assignment(lines, name)?;
    let prefix = format!("{name} := ");
    let mut text = lines[start][prefix.len()..].to_owned();
    let mut end = start + 1;
    let value = loop {
        if let Ok(value) = serde_json::from_str::<Value>(&text) {
            break value;
        }
        let next = lines.get(end).ok_or_else(|| anyhow!("the policy's `{name}` is not JSON"))?;
        text.push('\n');
        text.push_str(next);
        end += 1;
    };
    let line = format!("{prefix}{}", serde_json::to_string(&f(value)?)?);
    lines.splice(start..end, [line]);
    Ok(())
}

/// The variable an env rule's pattern names: its leading `[A-Za-z0-9_]` run, after any `^`.
fn env_name_of(pattern: &str) -> &str {
    let pattern = pattern.trim_start_matches('^');
    let end = pattern.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).unwrap_or(pattern.len());
    &pattern[..end]
}

/// Seal's container as the release rules want it (module docs).
fn seal_container(container: &mut Value, seal: &str, component: Component) -> anyhow::Result<()> {
    container["allow_elevated"] = json!(false);
    container["exec_processes"] = json!([]);
    let rules = container["env_rules"].as_array_mut().ok_or_else(|| anyhow!("{seal}: no env_rules"))?;
    for (name, rule, required) in operator_rules(component) {
        let is_it = |r: &Value| env_name_of(r["pattern"].as_str().unwrap_or_default()) == *name;
        let at = rules.iter().position(is_it).unwrap_or(rules.len());
        rules.retain(|r| !is_it(r));
        rules.insert(at.min(rules.len()), json!({"pattern": rule, "required": required, "strategy": "re2"}));
    }
    for var in INJECTED {
        if !rules.iter().any(|r| env_name_of(r["pattern"].as_str().unwrap_or_default()) == var) {
            rules.push(json!({"pattern": format!("{var}=.*"), "required": false, "strategy": "re2"}));
        }
    }
    Ok(())
}

/// Rewrites the generated `policy` (rego text) as the module docs say; `seal` names Seal's
/// container (the template's container name), which runs `component`.
pub fn rewrite(policy: &str, seal: &str, aci: &AciContainers, component: Component) -> anyhow::Result<String> {
    let mut lines: Vec<String> = policy.split('\n').map(str::to_owned).collect();
    replace_json(&mut lines, "containers", |containers| {
        let mut containers: Vec<Value> = serde_json::from_value(containers).context("the policy's containers")?;
        containers.retain(|c| !ACI_CONTAINERS.contains(&c["name"].as_str().unwrap_or_default()));
        let mut ours = 0;
        for container in &mut containers {
            let name = container["name"].as_str().unwrap_or_default().to_owned();
            if name == PAUSE {
                continue;
            }
            if name != seal {
                bail!("the policy has a container {name:?} besides Seal's {seal:?}, the pause container and ACI's");
            }
            ours += 1;
            seal_container(container, seal, component)?;
        }
        if ours != 1 {
            bail!("the policy has {ours} containers named {seal:?}, not one");
        }
        containers.extend(aci.0.iter().cloned());
        Ok(Value::Array(containers))
    })?;
    replace_json(&mut lines, "fragments", |_| Ok(json!([])))?;
    for flag in OFF {
        let i = assignment(&lines, flag)?;
        lines[i] = format!("{flag} := false");
    }
    skeleton(&lines)?;
    Ok(lines.join("\n"))
}

/// The policy's `host_data`: SHA-256 of its text.
pub fn host_data(policy: &str) -> [u8; 32] {
    Sha256::digest(policy.as_bytes()).into()
}

/// `template` (an ARM template with one confidential container group) with `ccePolicy` set to
/// the base64 of `policy`.
pub fn with_policy(template: &Value, policy: &str) -> anyhow::Result<Value> {
    use base64::Engine as _;
    let mut template = template.clone();
    let groups: Vec<&mut Value> = template["resources"]
        .as_array_mut()
        .ok_or_else(|| anyhow!("the template has no resources"))?
        .iter_mut()
        .filter(|r| r["type"] == "Microsoft.ContainerInstance/containerGroups")
        .collect();
    let [group] = <[&mut Value; 1]>::try_from(groups).map_err(|g| anyhow!("{} container groups, not one", g.len()))?;
    group["properties"]["confidentialComputeProperties"]["ccePolicy"] =
        json!(base64::engine::general_purpose::STANDARD.encode(policy));
    Ok(template)
}

/// The policy text in `template`'s one container group (`ccePolicy`, base64).
pub fn policy_of(template: &Value) -> anyhow::Result<String> {
    use base64::Engine as _;
    let groups: Vec<&Value> = template["resources"]
        .as_array()
        .ok_or_else(|| anyhow!("the template has no resources"))?
        .iter()
        .filter(|r| r["type"] == "Microsoft.ContainerInstance/containerGroups")
        .collect();
    let [group] = groups.as_slice() else { bail!("{} container groups, not one", groups.len()) };
    let b64 = group["properties"]["confidentialComputeProperties"]["ccePolicy"]
        .as_str()
        .filter(|p| !p.is_empty())
        .ok_or_else(|| anyhow!("the container group has no ccePolicy"))?;
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64).context("ccePolicy is not base64")?;
    String::from_utf8(bytes).map_err(|_| anyhow!("the policy is not UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A conforming policy captured on a live group (its SHA-256 is the report's `host_data`);
    /// its own container is named `main`.
    const CAPTURED: &str = include_str!("../../../shared/seal-attest/tests/data/aci-genoa/security-policy-base64");
    const ACI: &str = include_str!("../../../../deploy/azure/aci-containers.json");
    /// The infra fragment as `az confcom acipolicygen` 2.4.1 writes it, even with
    /// `--exclude-default-fragments`.
    const FRAGMENTS: &str = r#"fragments := [
  {
    "feed": "mcr.microsoft.com/aci/aci-cc-infra-fragment",
    "includes": [
      "containers",
      "fragments"
    ],
    "issuer": "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3.6.1.4.1.311.76.59.1.3",
    "minimum_svn": "4"
  }
]"#;
    /// The capture's `host_data`.
    const CAPTURED_HOST_DATA: &str = "202896786ffa17822b3af330287de59f1aa4af02dd5742c298fbd0fcac96382f";

    fn captured() -> String {
        use base64::Engine as _;
        let bytes = base64::engine::general_purpose::STANDARD.decode(CAPTURED.trim()).unwrap();
        String::from_utf8(bytes).unwrap()
    }

    fn aci() -> AciContainers {
        AciContainers::parse(ACI).unwrap()
    }

    fn containers(policy: &str) -> Vec<Value> {
        let line = policy.split('\n').find_map(|l| l.strip_prefix("containers := ")).unwrap();
        serde_json::from_str(line).unwrap()
    }

    /// What the generator writes before the rewrite: a string rule for the template's
    /// placeholder, the infra fragment, no ACI containers, debugging flags on.
    fn generated() -> String {
        let policy = captured();
        let mut cs = containers(&policy);
        cs.retain(|c| !ACI_CONTAINERS.contains(&c["name"].as_str().unwrap()));
        let main = &mut cs[0];
        main["allow_elevated"] = json!(true);
        main["exec_processes"] = json!([{"command": ["/bin/sh"], "signals": []}]);
        let rules = main["env_rules"].as_array_mut().unwrap();
        rules.retain(|r| {
            let name = env_name_of(r["pattern"].as_str().unwrap());
            name != "SEAL_TENANT" && name != "APP_IDENTITY_ENDPOINT" && name != "IMDS_ENDPOINT"
        });
        rules.push(json!({"pattern": "SEAL_TENANT=placeholder", "required": false, "strategy": "string"}));
        let lines: Vec<String> = policy
            .split('\n')
            .map(|l| {
                if l.starts_with("containers := ") {
                    format!("containers := {}", serde_json::to_string(&cs).unwrap())
                } else if l.starts_with("fragments := ") {
                    // Pretty-printed over several lines, as az confcom 2.4 writes it.
                    FRAGMENTS.into()
                } else if l == "allow_dump_stacks := false" {
                    "allow_dump_stacks := true".into()
                } else if l == "allow_environment_variable_dropping := false" {
                    "allow_environment_variable_dropping := true".into()
                } else {
                    l.to_owned()
                }
            })
            .collect();
        lines.join("\n")
    }

    #[test]
    fn aci_containers_are_the_live_ones() {
        // The committed copy is exactly what the captured policy lists.
        let live: Vec<Value> = containers(&captured())
            .into_iter()
            .filter(|c| ACI_CONTAINERS.contains(&c["name"].as_str().unwrap()))
            .collect();
        assert_eq!(serde_json::to_string(&live).unwrap(), serde_json::to_string(&aci().0).unwrap());
        let aci = aci();
        let privileged: Vec<&str> =
            aci.0.iter().filter(|c| c["allow_elevated"] == json!(true)).map(|c| c["name"].as_str().unwrap()).collect();
        assert_eq!(privileged, ["atlas-mount-resolv-conf", "msi-atlas-adapter"]);
        assert!(AciContainers::parse("[]").is_err());
    }

    #[test]
    fn a_conforming_policy_is_unchanged() {
        let policy = captured();
        assert_eq!(hex(&host_data(&policy)), CAPTURED_HOST_DATA);
        let rewritten = rewrite(&policy, "main", &aci(), Component::Enclave).unwrap();
        assert_eq!(rewritten, policy);
        assert_eq!(rewrite(&rewritten, "main", &aci(), Component::Enclave).unwrap(), policy);
        // So is the example's, as `seal-release aci-policy` wrote it from acipolicygen 2.4 output.
        let example = include_str!("../../../../deploy/example/aci-policy.rego");
        assert_eq!(rewrite(example, "seal-enclave", &aci(), Component::Enclave).unwrap(), example);
    }

    #[test]
    fn a_generated_policy_is_rewritten_to_the_release_rules() {
        let generated = generated();
        assert_ne!(generated, captured());
        let rewritten = rewrite(&generated, "main", &aci(), Component::Enclave).unwrap();
        assert!(rewritten.contains("\nfragments := []\n"));
        for flag in OFF {
            assert!(rewritten.contains(&format!("\n{flag} := false\n")), "{flag}");
        }
        let cs = containers(&rewritten);
        let names: Vec<&str> = cs.iter().map(|c| c["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["main", PAUSE, "atlas-mount-resolv-conf", "msi-atlas-adapter", "atlas-netstats"]);
        let main = &cs[0];
        assert_eq!(main["allow_elevated"], json!(false));
        assert_eq!(main["exec_processes"], json!([]));
        let rules = main["env_rules"].as_array().unwrap();
        let tenant: Vec<&Value> =
            rules.iter().filter(|r| env_name_of(r["pattern"].as_str().unwrap()) == "SEAL_TENANT").collect();
        assert_eq!(tenant, [&json!({"pattern": TENANT_RULE, "required": true, "strategy": "re2"})]);
        for var in INJECTED {
            assert!(rules.iter().any(|r| env_name_of(r["pattern"].as_str().unwrap()) == var), "{var}");
        }
        // Rewriting again changes nothing.
        assert_eq!(rewrite(&rewritten, "main", &aci(), Component::Enclave).unwrap(), rewritten);
    }

    #[test]
    fn a_guardian_policy_allows_the_ceremony_and_the_wrapped_roots() {
        // The generator's string rules for the template's placeholders, as for a guardian.
        let generated = generated().replace(
            r#"{"pattern":"SEAL_TENANT=placeholder","required":false,"strategy":"string"}"#,
            r#"{"pattern":"SEAL_GUARDIAN_CEREMONY=0","required":false,"strategy":"string"},{"pattern":"SEAL_GUARDIAN_WRAPPED_ROOTS=","required":false,"strategy":"string"}"#,
        );
        let rewritten = rewrite(&generated, "main", &aci(), Component::Guardian).unwrap();
        let rules = containers(&rewritten)[0]["env_rules"].as_array().unwrap().clone();
        let named = |name: &str| -> Vec<Value> {
            rules.iter().filter(|r| env_name_of(r["pattern"].as_str().unwrap()) == name).cloned().collect()
        };
        assert!(named("SEAL_TENANT").is_empty(), "a guardian has no tenant pin");
        assert_eq!(
            named("SEAL_GUARDIAN_CEREMONY"),
            [json!({"pattern": CEREMONY_RULE, "required": false, "strategy": "re2"})]
        );
        assert_eq!(
            named("SEAL_GUARDIAN_WRAPPED_ROOTS"),
            [json!({"pattern": WRAPPED_ROOTS_RULE, "required": false, "strategy": "re2"})]
        );
        // The succession variables have rules though the template set neither.
        assert_eq!(
            named("SEAL_GUARDIAN_SUCCEED_FROM"),
            [json!({"pattern": SUCCEED_FROM_RULE, "required": false, "strategy": "re2"})]
        );
        assert_eq!(
            named("SEAL_GUARDIAN_RELEASES"),
            [json!({"pattern": RELEASES_RULE, "required": false, "strategy": "re2"})]
        );
        assert_eq!(rewrite(&rewritten, "main", &aci(), Component::Guardian).unwrap(), rewritten);
    }

    #[test]
    fn the_succession_rules_allow_an_https_origin_only() {
        let matches = |rule: &str, s: &str| regex::Regex::new(rule).unwrap().is_match(s);
        for ok in [
            "SEAL_GUARDIAN_SUCCEED_FROM",
            "SEAL_GUARDIAN_SUCCEED_FROM=",
            "SEAL_GUARDIAN_SUCCEED_FROM=https://guardian.seal.zone/",
            "SEAL_GUARDIAN_SUCCEED_FROM=https://10.60.1.5:7400",
        ] {
            assert!(matches(SUCCEED_FROM_RULE, ok), "{ok}");
        }
        for bad in [
            "SEAL_GUARDIAN_SUCCEED_FROM=http://guardian.seal.zone/",
            "SEAL_GUARDIAN_SUCCEED_FROM=https://guardian.seal.zone/v1/keys",
            "SEAL_GUARDIAN_SUCCEED_FROM=https://a\nSEAL_TENANT=x",
            "SEAL_GUARDIAN_SUCCEED_FROMX=https://a",
        ] {
            assert!(!matches(SUCCEED_FROM_RULE, bad), "{bad}");
        }
        assert!(matches(RELEASES_RULE, "SEAL_GUARDIAN_RELEASES=https://control.seal.zone"));
        assert!(!matches(RELEASES_RULE, "SEAL_GUARDIAN_RELEASES=file:///etc"));
    }

    #[test]
    fn other_containers_are_refused() {
        let policy = captured();
        assert!(
            rewrite(&policy, "seal-enclave", &aci(), Component::Enclave).is_err(),
            "Seal's container must be there"
        );
        let mut cs = containers(&policy);
        let mut extra = cs[0].clone();
        extra["name"] = json!("sidecar");
        cs.push(extra);
        let with_sidecar = policy.replacen(
            &format!("containers := {}", serde_json::to_string(&containers(&policy)).unwrap()),
            &format!("containers := {}", serde_json::to_string(&cs).unwrap()),
            1,
        );
        assert!(rewrite(&with_sidecar, "main", &aci(), Component::Enclave)
            .unwrap_err()
            .to_string()
            .contains("sidecar"));
        assert!(rewrite("package policy\n", "main", &aci(), Component::Enclave).is_err());
    }

    #[test]
    fn lines_outside_the_skeleton_are_refused() {
        let policy = captured();
        let refused = |edited: String, why: &str| {
            assert_ne!(edited, policy, "{why}: the edit must apply");
            let err = rewrite(&edited, "main", &aci(), Component::Enclave).expect_err(why).to_string();
            assert!(["skeleton", "repeats", "more than one"].iter().any(|m| err.contains(m)), "{why}: {err}");
        };
        let before_reason = |extra: &str| policy.replacen("\nreason := ", &format!("\n{extra}\nreason := "), 1);
        refused(before_reason("create_container := true"), "a rule shadowing the framework's");
        refused(before_reason("exec_external := data.framework.exec_external"), "a repeated binding");
        refused(before_reason("allow_anything := true"), "an unknown flag");
        refused(before_reason("debug { true }"), "a rule with a body");
        refused(before_reason("# generated"), "a comment");
        refused(before_reason("import data.other"), "another import");
        refused(before_reason("fragments := []"), "a second fragments line");
        refused(
            policy.replacen("allow_capability_dropping := true", "allow_capability_dropping := input.drop", 1),
            "a computed flag",
        );
        refused(
            policy.replacen(
                "exec_external := data.framework.exec_external",
                "exec_external := data.framework.create_container",
                1,
            ),
            "a rule bound to another",
        );
        refused(policy.replacen(r#"api_version := "0.11.0""#, "api_version := data.x", 1), "a computed version");
        refused(
            policy.replacen(r#"reason := {"errors": data.framework.errors}"#, r#"reason := {"errors": []}"#, 1),
            "a changed reason",
        );
        refused(policy.replacen("\nmount_device := data.framework.mount_device\n", "\n", 1), "a missing binding");
        refused(policy.replacen("\nget_properties := ", "\n  get_properties := ", 1), "an indented binding");
    }

    #[test]
    fn the_template_gets_the_policy() {
        let template = json!({"resources": [
            {"type": "Microsoft.ManagedIdentity/userAssignedIdentities"},
            {"type": "Microsoft.ContainerInstance/containerGroups", "properties": {"confidentialComputeProperties": {"ccePolicy": ""}}}
        ]});
        let out = with_policy(&template, "package policy").unwrap();
        assert_eq!(
            out["resources"][1]["properties"]["confidentialComputeProperties"]["ccePolicy"],
            json!("cGFja2FnZSBwb2xpY3k=")
        );
        assert_eq!(policy_of(&out).unwrap(), "package policy");
        assert!(policy_of(&template).is_err(), "an empty ccePolicy is no policy");
        assert!(with_policy(&json!({"resources": []}), "p").is_err());
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
