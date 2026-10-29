//! `seal-release`: release steps as commands (crate docs).
//!
//! ```text
//! seal-release trust --log-info F --release-key F... --threshold M --registrar-key F
//!                    [--time-lock SECS] [--guardian PLATFORM=HEX]...           trust.json to stdout
//! seal-release measure gcp sha256:<digest>                                     the GCP measurement
//! seal-release aci-policy --template T --container NAME --aci-containers F --out-dir D [--policy F]
//!                         [--component enclave|guardian]                       generate (az confcom) or read the policy,
//!                                                                              rewrite it; writes policy.rego and
//!                                                                              template.json (ccePolicy set) to D and
//!                                                                              prints host_data and the measurement
//! seal-release kv-release-policy --host-data HEX [--maa URL]                   the Key Vault release policy for a
//!                                                                              guardian's root key (JSON to stdout)
//! seal-release publish --component enclave|guardian --platform P [--serves P] --measurement HEX
//!                      [--version V] --commit C [--service-key-version N] --key F... --trust F
//!                      --log URL --control URL [--evidence-out F] [--template F]
//!                                                                              sign, log, PUT to the control plane
//!                                                                              (write token: SEAL_CONTROL_TOKEN);
//!                                                                              --template: an Azure enclave release's
//!                                                                              aci-policy template.json, checked to
//!                                                                              measure HEX, PUT after the evidence
//!                                                                              for `seal deploy`
//! seal-release policy FILE [--log URL]                                        check a checkpoint policy (JSON
//!                                                                              `ReleaseConstraints`) against the
//!                                                                              platforms' TCB components and the
//!                                                                              log's current policy; prints it
//!                                                                              for the log's `PUT /v1/policy`
//! seal-release guardian-identity --url URL --measurement HEX                 a booted guardian's attested key (https, or
//!                                                                              http straight to the guardian: the
//!                                                                              evidence authenticates the answer)
//! seal-release app http --trust F --blob-file F                                a session on an HTTP blob
//! seal-release app signal CODE SEVERITY --trust F                              the app signals about itself
//! ```
//!
//! Platforms are `gcp`, `azure` and `aws`. `app` is a production SDK client:
//! `SEAL_ENDPOINT`, `SEAL_TENANT` and `SEAL_APP_KEY` from the environment, the trust from `--trust`.
#![forbid(unsafe_code)]

extern crate seal_client as seal;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command as Process;

use anyhow::{anyhow, bail, Context as _};
use clap::{Parser, Subcommand};

use seal_proto::release::Component;
use seal_proto::{Measurement, PlatformId, PublicKey, ServiceKeyVersion};
use seal_release::{aci, policy, release, trust};

#[derive(Parser)]
#[command(name = "seal-release", about = "Seal release tooling (development)")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

// Parsed once per run.
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
enum Command {
    /// Write trust.json to stdout
    Trust {
        /// What seal-tlog-dev printed on start
        #[arg(long)]
        log_info: PathBuf,
        #[arg(long = "release-key", required = true)]
        release_keys: Vec<PathBuf>,
        #[arg(long)]
        threshold: usize,
        #[arg(long = "registrar-key", required = true)]
        registrar_keys: Vec<PathBuf>,
        #[arg(long, default_value_t = 0)]
        time_lock: u64,
        /// PLATFORM=HEX, a guardian key
        #[arg(long = "guardian", value_parser = parse_guardian)]
        guardians: Vec<(PlatformId, PublicKey)>,
    },
    /// Measurements
    #[command(subcommand)]
    Measure(MeasureCmd),
    /// The Azure container policy for an ARM template
    AciPolicy {
        #[arg(long)]
        template: PathBuf,
        /// Seal's container in the template
        #[arg(long)]
        container: String,
        #[arg(long)]
        aci_containers: PathBuf,
        #[arg(long)]
        out_dir: PathBuf,
        /// A generated policy to rewrite instead of running `az confcom acipolicygen`
        #[arg(long)]
        policy: Option<PathBuf>,
        /// What Seal's container runs: its operator-set variables differ
        #[arg(long, value_parser = parse_component, default_value = "enclave")]
        component: Component,
    },
    /// The Key Vault release policy a guardian's root key is created with
    KvReleasePolicy {
        /// The guardian group's host_data (aci-policy prints it)
        #[arg(long)]
        host_data: String,
        /// The pinned attestation authority
        #[arg(long, default_value = aci::MAA_EASTUS)]
        maa: String,
    },
    /// Sign a release, log it and publish its evidence
    Publish {
        #[arg(long, value_parser = parse_component)]
        component: Component,
        #[arg(long, value_parser = parse_platform)]
        platform: PlatformId,
        #[arg(long, value_parser = parse_platform)]
        serves: Option<PlatformId>,
        #[arg(long)]
        measurement: Measurement,
        #[arg(long, default_value = env!("CARGO_PKG_VERSION"))]
        version: String,
        #[arg(long)]
        commit: String,
        #[arg(long, default_value_t = 1)]
        service_key_version: u32,
        #[arg(long = "key", required = true)]
        keys: Vec<PathBuf>,
        /// trust.json: the signatures must meet its release threshold, and the log its tlog
        #[arg(long = "trust")]
        trust_path: PathBuf,
        #[arg(long)]
        log: url::Url,
        #[arg(long)]
        control: url::Url,
        #[arg(long)]
        evidence_out: Option<PathBuf>,
        /// Azure enclave releases: the deployable template (`aci-policy` output) `seal deploy` uses
        #[arg(long)]
        template: Option<PathBuf>,
    },
    /// Check a checkpoint policy before it is set on the log
    Policy {
        /// `ReleaseConstraints` as JSON
        file: PathBuf,
        /// The log: the policy must not loosen its current checkpoint's
        #[arg(long)]
        log: Option<url::Url>,
    },
    /// A booted guardian's key, from its attested `GET /v1/identity`
    GuardianIdentity {
        #[arg(long)]
        url: url::Url,
        /// The guardian release's measurement
        #[arg(long)]
        measurement: Measurement,
    },
    /// The app
    #[command(subcommand)]
    App(AppCmd),
}

#[derive(Subcommand)]
enum MeasureCmd {
    Gcp { digest: String },
}

#[derive(Subcommand)]
enum AppCmd {
    Http {
        #[arg(long)]
        trust: PathBuf,
        #[arg(long)]
        blob_file: PathBuf,
    },
    Signal {
        code: String,
        severity: String,
        #[arg(long)]
        trust: PathBuf,
    },
}

fn parse_platform(s: &str) -> Result<PlatformId, String> {
    match s {
        "gcp" | "gcp_confidential_space" => Ok(PlatformId::GcpConfidentialSpace),
        "azure" | "azure_snp_aci" => Ok(PlatformId::AzureSnpAci),
        "aws" | "aws_nitro" => Ok(PlatformId::AwsNitro),
        _ => Err("expected gcp, azure or aws".into()),
    }
}

fn parse_component(s: &str) -> Result<Component, String> {
    match s {
        "enclave" => Ok(Component::Enclave),
        "guardian" => Ok(Component::Guardian),
        _ => Err("expected enclave or guardian".into()),
    }
}

fn parse_guardian(s: &str) -> Result<(PlatformId, PublicKey), String> {
    let (platform, key) = s.split_once('=').ok_or("expected PLATFORM=HEX")?;
    Ok((parse_platform(platform)?, key.parse().map_err(|e| format!("{e}"))?))
}

fn read(path: &Path) -> anyhow::Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("{}", path.display()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `az confcom acipolicygen` on `template`: the policy text, no default fragments.
fn generate_policy(template: &Path) -> anyhow::Result<String> {
    let output = Process::new("az")
        .args(["confcom", "acipolicygen", "--only-show-errors", "--exclude-default-fragments", "--outraw", "-a"])
        .arg(template)
        .output()
        .context("run az confcom acipolicygen")?;
    if !output.status.success() {
        bail!("az confcom acipolicygen: {}", String::from_utf8_lossy(&output.stderr).trim());
    }
    let text = String::from_utf8(output.stdout).context("the policy is not UTF-8")?;
    Ok(text.trim_end().to_owned())
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Command::Trust { log_info, release_keys, threshold, registrar_keys, time_lock, guardians } => {
            let log = trust::LogInfo::parse(&read(&log_info)?)?;
            let public = |paths: &[PathBuf]| -> anyhow::Result<Vec<PublicKey>> {
                paths.iter().map(|p| Ok(release::read_key(p)?.public_key())).collect()
            };
            let guardians: BTreeMap<_, _> = guardians.into_iter().collect();
            let value = trust::build(
                &log,
                &public(&release_keys)?,
                threshold,
                &public(&registrar_keys)?,
                time_lock,
                &guardians,
            )?;
            println!("{}", serde_json::to_string_pretty(&value)?);
        }
        Command::Measure(MeasureCmd::Gcp { digest }) => {
            println!("{}", seal_attest::gcp::measurement(&digest)?);
        }
        Command::AciPolicy { template, container, aci_containers, out_dir, policy, component } => {
            let generated = match policy {
                Some(path) => read(&path)?,
                None => generate_policy(&template)?,
            };
            let containers = aci::AciContainers::parse(&read(&aci_containers)?)?;
            let policy = aci::rewrite(&generated, &container, &containers, component)?;
            let template: serde_json::Value = serde_json::from_str(&read(&template)?).context("the template")?;
            let deployable = aci::with_policy(&template, &policy)?;
            std::fs::create_dir_all(&out_dir)?;
            std::fs::write(out_dir.join("policy.rego"), &policy)?;
            std::fs::write(out_dir.join("template.json"), serde_json::to_string_pretty(&deployable)? + "\n")?;
            let host_data = aci::host_data(&policy);
            println!("policy {}", out_dir.join("policy.rego").display());
            println!("template {}", out_dir.join("template.json").display());
            println!("host_data {}", hex(&host_data));
            println!("measurement {}", seal_attest::azure::measurement(&host_data));
        }
        Command::KvReleasePolicy { host_data, maa } => {
            let bytes: Vec<u8> = (0..host_data.len())
                .step_by(2)
                .map(|i| host_data.get(i..i + 2).and_then(|b| u8::from_str_radix(b, 16).ok()))
                .collect::<Option<_>>()
                .ok_or_else(|| anyhow!("--host-data: not hex"))?;
            let host_data: [u8; 32] = bytes.try_into().map_err(|_| anyhow!("--host-data: not 32 bytes"))?;
            if !maa.starts_with("https://") || !maa.trim_end_matches('/').ends_with(".attest.azure.net") {
                bail!("--maa: not an attestation endpoint: {maa}");
            }
            println!("{}", serde_json::to_string(&seal_guardian::keysource::release_policy(&host_data, &maa))?);
        }
        Command::Policy { file, log } => {
            let policy: seal_proto::release::ReleaseConstraints =
                serde_json::from_str(&read(&file)?).with_context(|| format!("{}", file.display()))?;
            let current = match log {
                None => None,
                Some(log) => {
                    let log = seal::admin::LogClient::with_https(log, seal::admin::https());
                    Some(log.checkpoint().await.context("the log's checkpoint")?.checkpoint.policy)
                }
            };
            policy::check(&policy, current.as_ref())?;
            println!("{}", serde_json::to_string(&policy)?);
        }
        Command::Publish {
            component,
            platform,
            serves,
            measurement,
            version,
            commit,
            service_key_version,
            keys,
            trust_path,
            log,
            control,
            evidence_out,
            template,
        } => {
            let template = match template {
                None => None,
                Some(path) => {
                    if component != Component::Enclave || platform != PlatformId::AzureSnpAci {
                        bail!("--template is for Azure enclave releases");
                    }
                    let template: serde_json::Value =
                        serde_json::from_str(&read(&path)?).with_context(|| format!("{}", path.display()))?;
                    let host_data = aci::host_data(&aci::policy_of(&template)?);
                    if seal_attest::azure::measurement(&host_data) != measurement {
                        bail!("{}: its policy does not measure {measurement}", path.display());
                    }
                    Some(template)
                }
            };
            let manifest = release::Release {
                component,
                platform,
                measurement,
                serves,
                service_key_version: ServiceKeyVersion(service_key_version),
                version,
                source_commit: commit,
            }
            .manifest()?;
            let keys: Vec<_> = keys.iter().map(|p| release::read_key(p)).collect::<anyhow::Result<_>>()?;
            let signed = release::sign(manifest, &keys)?;
            let trust = trust::parse(read(&trust_path)?.as_bytes())?;
            seal_crypto::sign::verify_threshold(
                &trust.releases.release_keys,
                trust.releases.release_threshold,
                seal_proto::release::RELEASE_LABEL,
                &signed,
            )
            .map_err(|e| anyhow!("the signatures do not meet the trust's release threshold: {e}"))?;
            let token = std::env::var("SEAL_CONTROL_TOKEN").map_err(|_| anyhow!("SEAL_CONTROL_TOKEN is not set"))?;
            let https = seal::admin::https();
            let log_client = seal::admin::LogClient::with_https(log, https.clone());
            let evidence = release::log(&log_client, &trust.releases.tlog, signed).await?;
            let control = seal::admin::ControlClient::new(control, https, Some(token));
            release::publish(&control, &evidence).await?;
            if let Some(template) = &template {
                control
                    .put_release_template(platform, &measurement, template)
                    .await
                    .context("publish the release template to the control plane")?;
            }
            if let Some(path) = evidence_out {
                std::fs::write(&path, serde_json::to_vec_pretty(&evidence)?)
                    .with_context(|| format!("{}", path.display()))?;
            }
            println!(
                "release {measurement} ({component:?} on {platform:?}) logged at {}",
                evidence.included.leaf_index
            );
        }
        Command::GuardianIdentity { url, measurement } => {
            let challenge = *seal_crypto::Key32::generate(&mut seal_crypto::UnwrapErr(seal_crypto::SysRng)).expose();
            let url = url.join(&format!("v1/identity?challenge={}", seal_proto::codec::b64url(&challenge)))?;
            let (status, body) = match url.scheme() {
                "http" => plain_get(&url).await?,
                _ => seal::admin::https().get(url.as_str(), &[]).await?,
            };
            if status != 200 {
                bail!("{url}: HTTP {status}");
            }
            let identity: seal_release::identity::Identity = serde_json::from_slice(&body).context("the identity")?;
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
            let key = seal_release::identity::check(
                &identity,
                challenge,
                &measurement,
                &seal_proto::TrustedTime { now, radius: 5 },
            )?;
            println!(
                "guardian {:?} on {:?}: key {key} (attested, measurement {measurement})",
                identity.platform, identity.runs_on
            );
        }
        Command::App(cmd) => {
            let trust_path = match &cmd {
                AppCmd::Http { trust, .. } | AppCmd::Signal { trust, .. } => trust.clone(),
            };
            let trust = trust::parse(read(&trust_path)?.as_bytes())?;
            let client = seal::Client::builder().trust(trust).connect().await.context("connect to the enclave")?;
            let enclave = client.enclave().await?;
            println!(
                "app: verified enclave {} (release {}, tenant {}@{})",
                enclave.measurement(),
                enclave.release_version(),
                enclave.tenant(),
                enclave.root_id()
            );
            match cmd {
                AppCmd::Http { blob_file, .. } => {
                    let blob = read(&blob_file)?;
                    let report = seal_sim::app::http_flow(&client, blob.trim()).await?;
                    println!("app: sessions {:?}; tunnel closed {}", report.session_ids, report.tunnel_closed);
                    if !report.tunnel_closed {
                        bail!("a closed session still worked");
                    }
                }
                AppCmd::Signal { code, severity, .. } => {
                    let severity: seal::Severity = serde_json::from_value(serde_json::Value::String(severity))
                        .context("severity: low, medium, high or critical")?;
                    client.signal(&code, severity).await?;
                    println!("app: signalled {code} ({severity:?})");
                }
            }
        }
    }
    Ok(())
}

/// One plain-HTTP `GET`: the status and the body.
async fn plain_get(url: &url::Url) -> anyhow::Result<(u16, Vec<u8>)> {
    use http_body_util::{BodyExt as _, Empty};
    let host = url.host_str().ok_or_else(|| anyhow!("{url}: no host"))?;
    let port = url.port_or_known_default().unwrap_or(80);
    let stream =
        tokio::net::TcpStream::connect((host, port)).await.with_context(|| format!("connect to {host}:{port}"))?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream)).await?;
    let conn = tokio::spawn(conn);
    let path = &url[url::Position::BeforePath..];
    let request =
        hyper::Request::get(path).header(hyper::header::HOST, host).body(Empty::<hyper::body::Bytes>::new())?;
    let response = sender.send_request(request).await?;
    let status = response.status().as_u16();
    let body = response.into_body().collect().await?.to_bytes().to_vec();
    conn.abort();
    Ok((status, body))
}

#[tokio::main]
async fn main() {
    if let Err(e) = run(Cli::parse()).await {
        eprintln!("seal-release: {e:#}");
        std::process::exit(1);
    }
}
