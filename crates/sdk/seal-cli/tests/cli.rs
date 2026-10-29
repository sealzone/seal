//! The `seal` binary end to end against the in-process dev log and fake control plane (which
//! also answers as the console): `dev init`, grants, settings and `status`, the stored bundle
//! verified with `TenantVerifier`; `login`, `use` and a change proposed with the console login
//! and followed until another admin signs it; key files; telemetry with a generated reader key.
#![cfg(feature = "sim")]

mod common;

use std::path::Path;

use common::{acme, seal_command, HomeFiles, Servers, CLI_TOKEN, WORKSPACE};
use seal_crypto::{Key32, PlatformMasterKey, ServiceKeys};
use seal_proto::identity::{IdentityMatcher, WorkloadIdentity};
use seal_proto::telemetry::{Operation, TelemetryBatch, TelemetryEntry, TelemetryEvent, TELEMETRY_BATCH_LABEL};
use seal_proto::{AppName, ErrorCode, PlatformId, PublicKey, ServiceKeyVersion, TenantPin};

/// Runs `seal --home HOME args...` with stdin closed; returns (success, stdout, stderr).
async fn seal(home: &Path, args: &[&str]) -> (bool, String, String) {
    let out = seal_command(home).args(args).output().await.unwrap();
    let (stdout, stderr) =
        (String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned());
    (out.status.success(), stdout, stderr)
}

/// `seal --home HOME args...`'s exit code and stdout.
async fn status(home: &Path, args: &[&str]) -> (Option<i32>, String) {
    let out = seal_command(home).args(args).output().await.unwrap();
    (out.status.code(), String::from_utf8_lossy(&out.stdout).into_owned())
}

async fn ok(home: &Path, args: &[&str]) -> String {
    let (success, stdout, stderr) = seal(home, args).await;
    assert!(success, "seal {args:?} failed:\n{stdout}\n{stderr}");
    stdout
}

/// `seal dev init` for acme with the home's admin key; returns its pin.
async fn init(home: &Path, files: &HomeFiles, extra: &[&str]) -> TenantPin {
    let (key, registrar) = (files.key.to_str().unwrap(), files.registrar.to_str().unwrap());
    let args =
        [&["dev", "init", "--tenant", "acme", "--key-file", key, "--registrar-key", registrar, "--yes"][..], extra]
            .concat();
    let out = ok(home, &args).await;
    out.lines().find_map(|l| l.strip_prefix("SEAL_TENANT=")).expect("prints SEAL_TENANT").parse().unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn widening_changes_wait_the_window_and_watch_shows_them() {
    let servers = Servers::start("window").await;
    let home = servers.dir.0.join("home");
    let files = servers.write_home(&home);
    let key = files.key.to_str().unwrap();
    init(&home, &files, &["--pending-window", "1h"]).await;
    assert_eq!(servers.verified().state().pending_window_secs, 3_600);
    let (code, out) = status(&home, &["changes", "--watch", "--once", "--key-file", key]).await;
    assert_eq!(code, Some(0), "{out}");
    assert!(out.contains("state version 1 in force") && out.contains("pending window 1h"), "{out}");

    // Allowing an enclave widens: it waits, and says so.
    let deployment = r#"{"kind":"confidential_space","project_number":7,"service_account":"ci@seal.test"}"#;
    let out = ok(&home, &["grant", "enclave", "sim", deployment, "--key-file", key, "--yes"]).await;
    assert!(out.contains("this widens access") && out.contains("takes effect in 1h"), "{out}");
    let verified = servers.verified();
    assert_eq!((verified.state().version, verified.latest_state().version), (1, 2));
    let (code, out) = status(&home, &["changes", "--watch", "--once", "--key-file", key]).await;
    assert_eq!(code, Some(3), "{out}");
    assert!(out.contains("pending state version 2") && out.contains("widening: takes effect in"), "{out}");
    assert!(out.contains("+ deployment: Confidential Space project 7, ci@seal.test (widening)"), "{out}");
    let (code, out) = status(&home, &["changes", "--watch", "--once", "--json", "--key-file", key]).await;
    assert_eq!(code, Some(3));
    let line: serde_json::Value = serde_json::from_str(out.lines().next().unwrap()).unwrap();
    assert_eq!(line["version"], 2);
    assert_eq!(line["change"], "widening");
    assert_eq!(line["differences"][0]["item"]["kind"], "deployment_added");
    let out = ok(&home, &["changes", "--key-file", key]).await;
    assert!(out.contains("Logged, not yet in force") && out.contains("state version 2: takes effect in"), "{out}");

    // Lengthening the window narrows: it applies at once, built on the state in force, and so
    // supersedes the pending deployment.
    let out = ok(&home, &["settings", "window", "2h", "--yes", "--key-file", key]).await;
    assert!(out.contains("this narrows access") && out.contains("pending state versions 2 never take effect"), "{out}");
    let verified = servers.verified();
    assert_eq!(verified.state().version, 3);
    assert!(verified.state().deployments.is_empty(), "the cancelled deployment never took effect");
    let (code, out) = status(&home, &["changes", "--watch", "--once", "--key-file", key]).await;
    assert_eq!(code, Some(0), "{out}");
    let out = ok(&home, &["settings", "window", "--key-file", key]).await;
    assert!(out.contains("pending window 2h"), "{out}");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_freshness_window_narrows_at_once_and_widens_after_the_pending_window() {
    let servers = Servers::start("freshness-window").await;
    let home = servers.dir.0.join("home");
    let files = servers.write_home(&home);
    let key = files.key.to_str().unwrap();
    init(&home, &files, &["--pending-window", "1h"]).await;
    let out = ok(&home, &["settings", "freshness", "window", "--key-file", key]).await;
    assert!(out.contains("freshness window 1d"), "{out}");
    let (success, _, stderr) = seal(&home, &["settings", "freshness", "window", "1m", "--key-file", key]).await;
    assert!(!success && stderr.contains("the freshness window is 5m to 1d"), "{stderr}");

    let out = ok(&home, &["settings", "freshness", "window", "10m", "--yes", "--key-file", key]).await;
    assert!(out.contains("this narrows access") && out.contains("~ freshness window: 86400s -> 600s"), "{out}");
    let verified = servers.verified();
    assert_eq!((verified.state().version, verified.state().freshness_secs), (2, Some(600)));
    let out = ok(&home, &["settings", "freshness", "--json", "--key-file", key]).await;
    assert!(out.contains(r#""freshness_secs":600"#), "{out}");

    // Back to the default lengthens it: it waits the pending window.
    let out = ok(&home, &["settings", "freshness", "window", "default", "--yes", "--key-file", key]).await;
    assert!(out.contains("this widens access") && out.contains("takes effect in 1h"), "{out}");
    let verified = servers.verified();
    assert_eq!((verified.state().version, verified.latest_state().freshness_secs), (2, None));
}

#[tokio::test(flavor = "multi_thread")]
async fn init_grants_settings_and_status_end_to_end() {
    let servers = Servers::start("e2e").await;
    let home = servers.dir.0.join("home");
    let files = servers.write_home(&home);
    let key = files.key.to_str().unwrap();
    let pin = init(&home, &files, &[]).await;
    let config = std::fs::read_to_string(home.join("config.json")).unwrap();
    assert!(!config.contains("token") && !config.contains("trust"), "no credential in the configuration: {config}");

    // Without --yes and without a terminal, nothing is signed.
    let (success, stdout, stderr) = seal(&home, &["settings", "platforms", "add", "sim", "--key-file", key]).await;
    assert!(!success && stderr.contains("pass --yes"), "{stderr}");
    assert!(stdout.contains("+ platform: sim"), "the diff is shown first: {stdout}");
    // Without a key file or a login, nothing is proposed either.
    let (success, _, stderr) = seal(&home, &["settings", "platforms", "add", "sim", "--yes"]).await;
    assert!(!success && stderr.contains("run `seal login`"), "{stderr}");

    let app_key = servers.dir.0.join("checkout.key");
    let out = ok(
        &home,
        &[
            "grant",
            "app",
            "checkout",
            "key",
            "--generate",
            "--out",
            app_key.to_str().unwrap(),
            "--key-file",
            key,
            "--yes",
        ],
    )
    .await;
    assert!(out.contains("+ app checkout: app key "), "{out}");
    let app_key = std::fs::read_to_string(&app_key).unwrap();
    let seed = seal_proto::codec::from_b64url(app_key.trim().strip_prefix("sealak_").unwrap()).unwrap();
    let app_public = seal_crypto::sign::SigningKey::from_seed(&seed.try_into().unwrap()).public_key();
    assert!(!out.contains(app_key.trim()), "the app key is written to its file, not printed");
    assert!(out.contains(&format!("public key {app_public}")), "{out}");
    assert!(out.contains(&format!("+ app checkout: app key {app_public} (key id ")), "{out}");
    let (success, _, stderr) = seal(
        &home,
        &[
            "grant",
            "app",
            "checkout",
            "key",
            "--generate",
            "--out",
            files.key.to_str().unwrap(),
            "--key-file",
            key,
            "--yes",
        ],
    )
    .await;
    assert!(!success && stderr.contains("never replaced"), "{stderr}");

    // An app key to stdout: the key alone there, everything else on stderr.
    let out = seal_command(&home)
        .args(["grant", "app", "billing", "key", "--generate", "--key-file", key, "--yes"])
        .output()
        .await
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let billing_key = String::from_utf8(out.stdout).unwrap();
    assert!(billing_key.starts_with("sealak_") && billing_key.lines().count() == 1, "{billing_key}");
    let seed = seal_proto::codec::from_b64url(billing_key.trim().strip_prefix("sealak_").unwrap()).unwrap();
    let billing_public = seal_crypto::sign::SigningKey::from_seed(&seed.try_into().unwrap()).public_key();
    assert!(String::from_utf8_lossy(&out.stderr).contains(&format!("public key {billing_public}")));

    let deployment = r#"{"kind":"confidential_space","project_number":7,"service_account":"sim@seal.test"}"#;
    ok(&home, &["grant", "enclave", "sim", deployment, "--key-file", key, "--yes"]).await;
    ok(&home, &["settings", "platforms", "add", "sim", "--key-file", key, "--yes"]).await;
    let (success, _, stderr) = seal(&home, &["settings", "platforms", "add", "sim", "--key-file", key, "--yes"]).await;
    assert!(!success && stderr.contains("nothing to change"), "{stderr}");

    let verified = servers.verified();
    assert_eq!(verified.root_id(), &pin.root_id);
    let state = verified.state();
    assert_eq!(state.version, 5);
    assert!(state.apps[&AppName::new("checkout").unwrap()]
        .iter()
        .any(|m| matches!(m, IdentityMatcher::AppKey { public_key, .. } if *public_key == app_public)));
    let identity: WorkloadIdentity = serde_json::from_str(deployment).unwrap();
    assert!(state.deployments.iter().any(|m| m.matches(&identity)));
    assert!(state.apps[&AppName::new("billing").unwrap()]
        .iter()
        .any(|m| matches!(m, IdentityMatcher::AppKey { public_key, .. } if *public_key == billing_public)));
    assert_eq!(state.platforms, [PlatformId::Sim].into());

    let out = ok(&home, &["status", "--log", "--key-file", key]).await;
    assert!(out.contains(&pin.to_string()) && out.contains("version 5 in force"), "{out}");
    assert!(out.contains("2 apps (2 identities) · 1 enclave"), "{out}");
    assert!(out.contains("only one admin key"), "{out}");
    assert!(out.contains("scanned 6 log entries") && out.contains("no roots outside our chain"), "{out}");
    let out = ok(&home, &["status", "--json", "--key-file", key]).await;
    let json: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!((json["state"]["version"].as_u64(), json["root"]["threshold"].as_u64()), (Some(5), Some(1)));
    let out = ok(&home, &["settings", "admins", "--key-file", key]).await;
    assert!(out.contains("ed25519") && out.contains("(--key-file)") && out.contains("1 of 1 must sign"), "{out}");

    // Revoking takes the identity by its primary id; an app without one goes whole.
    ok(
        &home,
        &["revoke", "app", "billing", "key", "--public", &billing_public.to_string(), "--key-file", key, "--yes"],
    )
    .await;
    ok(&home, &["revoke", "app", "checkout", "--key-file", key, "--yes"]).await;
    let state = servers.verified().state().clone();
    assert!(state.apps.is_empty());

    let (success, _, stderr) = seal(&home, &["deploy", "aws"]).await;
    assert!(!success && stderr.contains("not available in this build"), "{stderr}");
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_keys_are_files_the_cli_never_prints_to_a_terminal() {
    let servers = Servers::start("keys").await;
    let home = servers.dir.0.join("home");
    servers.write_home(&home);
    let file = servers.dir.0.join("new.key");
    let out = seal_command(&home).args(["key", "create", "--out", file.to_str().unwrap()]).output().await.unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success() && out.stdout.is_empty(), "{stderr}");
    let public = ok(&home, &["key", "public", file.to_str().unwrap()]).await;
    assert!(
        stderr.contains(&format!("public key {}", public.trim())) && stderr.contains("seal settings admins add"),
        "{stderr}"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
    }
    let (success, _, stderr) = seal(&home, &["key", "create", "--out", file.to_str().unwrap()]).await;
    assert!(!success && stderr.contains("new.key"), "a key file is never replaced: {stderr}");
    let piped = ok(&home, &["key", "create"]).await;
    assert_eq!(piped.trim().len(), 64, "the seed, to a pipe: {piped}");
    let mut keys: Vec<String> = std::fs::read_dir(&home)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".key"))
        .collect();
    keys.sort();
    assert_eq!(keys, ["admin.key", "registrar.key"], "nothing written to the home");
}

#[tokio::test(flavor = "multi_thread")]
async fn login_use_and_changes_signed_by_another_admin() {
    let servers = Servers::start("console").await;
    let home = servers.dir.0.join("home");
    let files = servers.write_home(&home);
    let key = files.key.to_str().unwrap();
    init(&home, &files, &[]).await;

    let (success, _, stderr) = seal(&home, &["whoami"]).await;
    assert!(!success && stderr.contains("run `seal login`"), "{stderr}");
    let (success, stdout, stderr) = seal(&home, &["login", "--no-browser"]).await;
    assert!(success, "{stdout}\n{stderr}");
    assert!(stderr.contains("ABCD-EFGH") && stdout.contains("admin@acme.test"), "{stdout}\n{stderr}");
    assert_eq!(std::fs::read_to_string(&files.token).unwrap(), CLI_TOKEN);
    let out = ok(&home, &["whoami", "--json"]).await;
    let me: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(
        (me["email"].as_str(), me["workspaces"][0]["slug"].as_str()),
        (Some("admin@acme.test"), Some(WORKSPACE))
    );

    let (success, _, stderr) = seal(&home, &["use", "other"]).await;
    assert!(!success && stderr.contains("no tenant other") && stderr.contains("yours: acme"), "{stderr}");
    let out = ok(&home, &["use", "acme"]).await;
    assert!(out.contains(&format!("workspace {WORKSPACE}")) && out.contains("verified"), "{out}");
    let config: serde_json::Value = serde_json::from_slice(&std::fs::read(home.join("config.json")).unwrap()).unwrap();
    assert_eq!(config["workspace"], WORKSPACE);

    // Read with the login alone.
    let out = ok(&home, &["status"]).await;
    assert!(out.contains("version 1 in force") && out.contains(&format!("/tenant?w={WORKSPACE}&t=acme")), "{out}");

    // Proposed with the login, not waited for: the console link names it.
    let out = ok(&home, &["settings", "platforms", "add", "sim", "--yes", "--no-wait", "--no-browser"]).await;
    let id = servers.stored.lock().unwrap().proposals.keys().next().cloned().expect("a proposal");
    assert!(
        out.contains(&format!("/tenant/change?w={WORKSPACE}&t=acme&id={id}")) && out.contains("stays pending"),
        "{out}"
    );
    let out = ok(&home, &["changes"]).await;
    assert!(out.contains(&id[..12]) && out.contains("0 of 1") && out.contains("+ platform: sim"), "{out}");
    let out = ok(&home, &["changes", "show", &id[..8]]).await;
    assert!(out.contains(&id) && out.contains("0 of the 1 signatures"), "{out}");
    ok(&home, &["changes", "cancel", &id[..8]]).await;
    assert!(servers.stored.lock().unwrap().proposals.is_empty());
    assert!(servers.stored.lock().unwrap().control_tokens.iter().any(|s| s == "submit"));

    // Proposed and followed: once another admin signs it, it is submitted and logged.
    let follow = seal_command(&home)
        .args(["settings", "platforms", "add", "sim", "--yes", "--no-browser"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let id = loop {
        if let Some(id) = servers.stored.lock().unwrap().proposals.keys().next().cloned() {
            break id;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    };
    let out = ok(&home, &["changes", "sign", &id[..12], "--key-file", key, "--yes"]).await;
    assert!(out.contains("published state version 2"), "{out}");
    let followed =
        tokio::time::timeout(std::time::Duration::from_secs(30), follow.wait_with_output()).await.unwrap().unwrap();
    let stdout = String::from_utf8_lossy(&followed.stdout);
    assert!(followed.status.success(), "{stdout}\n{}", String::from_utf8_lossy(&followed.stderr));
    assert!(stdout.contains("state version 2 was submitted and logged"), "{stdout}");
    assert_eq!(servers.verified().state().platforms, [PlatformId::Sim].into());

    let out = ok(&home, &["logout"]).await;
    assert!(out.contains("signed out"), "{out}");
    assert!(!files.token.exists());
    assert_eq!(servers.stored.lock().unwrap().revoked, [CLI_TOKEN]);
}

#[tokio::test(flavor = "multi_thread")]
async fn telemetry_reader_keys_are_generated_and_open_sealed_batches() {
    let servers = Servers::start("telemetry").await;
    let home = servers.dir.0.join("home");
    let files = servers.write_home(&home);
    let key = files.key.to_str().unwrap();
    let pin = init(&home, &files, &[]).await;

    // The guardian that certifies this tenant's enclave, in the trust.
    let guardian = PlatformMasterKey::from_root_secret(PlatformId::Sim, &Key32::from_bytes([0x31; 32]));
    let mut trust: serde_json::Value = serde_json::from_slice(&std::fs::read(&files.trust).unwrap()).unwrap();
    trust["guardians"] = serde_json::json!({"sim": guardian.guardian_key().public_key()});
    std::fs::write(&files.trust, serde_json::to_vec_pretty(&trust).unwrap()).unwrap();

    let key_file = home.join("reader.key");
    let key_path = key_file.to_str().unwrap();
    let out =
        ok(&home, &["settings", "telemetry-readers", "add", "--generate", key_path, "--key-file", key, "--yes"]).await;
    let reader: PublicKey = out
        .lines()
        .find_map(|l| l.split_once("public key ").map(|(_, k)| k.trim().to_string()))
        .expect("prints the public key")
        .parse()
        .unwrap();
    assert!(!out.contains(std::fs::read_to_string(&key_file).unwrap().trim()), "the key is never printed");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&key_file).unwrap().permissions().mode() & 0o777, 0o600);
    }
    assert_eq!(servers.verified().state().telemetry_readers, [reader].into());
    let (success, _, stderr) =
        seal(&home, &["settings", "telemetry-readers", "add", "--generate", key_path, "--key-file", key, "--yes"])
            .await;
    assert!(!success && stderr.contains("reader.key"), "an existing key file is never replaced: {stderr}");

    // The enclave's certificate (posted at boot) and one batch sealed to the reader.
    let released = guardian.release_service(&acme(), &pin.root_id, ServiceKeyVersion(1));
    let keys = ServiceKeys::from_released(PlatformId::Sim, &released).unwrap();
    let entry = TelemetryEntry {
        at: 1_900_000_000,
        tenant: acme(),
        identity: None,
        event: TelemetryEvent::Refused {
            operation: Operation::Seal,
            code: ErrorCode::NotAllowed,
            context: Some(seal_proto::telemetry::RefusalContext::DeploymentNotListed),
        },
    };
    let mut rng = seal_crypto::UnwrapErr(seal_crypto::SysRng);
    let entries = std::slice::from_ref(&entry);
    let entries = seal_crypto::telemetry::seal_entries(&acme(), [7; 16], 0, 0, entries, &[reader], &mut rng).unwrap();
    let batch = TelemetryBatch {
        tenant: acme(),
        stream: [7; 16],
        sequence: 0,
        first_entry: 0,
        count: 1,
        from: entry.at,
        to: entry.at,
        entries,
        last: true,
    };
    {
        let mut stored = servers.stored.lock().unwrap();
        stored.certificates.push(keys.certificate.clone());
        stored.telemetry.push(keys.telemetry.signer().sign_into(TELEMETRY_BATCH_LABEL, batch));
    }

    let out = ok(&home, &["telemetry", "--reader-key", key_path, "--key-file", key]).await;
    assert!(out.contains(r#"07070707#0  enclave  {"kind":"refused""#), "{out}");
    assert!(out.contains(r#""context":{"kind":"deployment_not_listed"}"#), "{out}");
    assert!(!out.contains("FOUND") && !out.contains("sealed batch"), "{out}");
    let out = ok(&home, &["telemetry", "--reader-key", key_path, "--json", "--key-file", key]).await;
    let line: serde_json::Value = serde_json::from_str(out.lines().next().unwrap()).unwrap();
    assert_eq!(line["telemetry"]["event"]["kind"], "refused");

    let out = ok(&home, &["telemetry", "--key-file", key]).await;
    assert!(out.contains("sealed batch: stream 07070707") && out.contains("pass --reader-key"), "{out}");

    // Certificates from a file instead: one the trusted guardian did not sign verifies nothing.
    let stranger = PlatformMasterKey::from_root_secret(PlatformId::Sim, &Key32::from_bytes([0x32; 32]));
    let forged = stranger.release_service(&acme(), &pin.root_id, ServiceKeyVersion(1));
    let forged = ServiceKeys::from_released(PlatformId::Sim, &forged).unwrap().certificate;
    let certificates = home.join("certificates.json");
    std::fs::write(&certificates, serde_json::to_vec(&[forged]).unwrap()).unwrap();
    let (success, _, stderr) =
        seal(&home, &["telemetry", "--certificates", certificates.to_str().unwrap(), "--key-file", key]).await;
    assert!(!success && stderr.contains("no certificate verified"), "{stderr}");
}
