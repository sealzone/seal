//! `seal-sim`: the simulator harness's pieces as commands, for `scripts/sim-demo.sh` and the
//! end-to-end tests (`tests/e2e/world.py`).
//!
//! ```text
//! seal-sim setup --dir D --enclave-bin PATH [--port-base N]   write the environment (seal_sim::setup);
//!     [--fast-reload] [--release-stale-in SECS]               tests: 1 s reloads; release evidence aging out
//! seal-sim publish-release --dir D                            PUT the release evidence to the control plane
//! seal-sim proxy --dir D                                      TLS proxy in front of the guardian (runs until killed)
//! seal-sim upstream --dir D [--record F]                      the HTTPS test upstream (runs until killed);
//!                                                             appends each request it sees to F as JSON
//! seal-sim postgres|redis --dir D                             start Postgres or Redis in Docker or Podman; the
//!                                                             password is read from stdin; prints the runtime,
//!                                                             the container id and the destination
//! seal-sim app http --blob-file F                             the app: a session on an HTTP blob
//! seal-sim app pg --blob-file F                               the app: one query through a database session
//! ```
//!
//! `app` is a plain SDK client: `Client::from_env` (`SEAL_ENDPOINT`, `SEAL_TENANT`,
//! `SEAL_APP_KEY`, `SEAL_TRUST`).
#![forbid(unsafe_code)]

extern crate seal_client as seal;

use std::io::Read as _;
use std::path::PathBuf;

use anyhow::Context as _;
use clap::{Parser, Subcommand};

use seal_proto::release::FRESH_CHECKPOINT_SECS;
use seal_sim::container::Container;
use seal_sim::setup::{self, Ports, Sim};
use seal_sim::{app, net, postgres, redis};

#[derive(Parser)]
#[command(name = "seal-sim", about = "Seal's local simulator harness")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Write a fresh simulator environment into DIR
    Setup {
        #[arg(long)]
        dir: PathBuf,
        /// The seal-enclave binary the release approves (its SHA-384 is the measurement)
        #[arg(long)]
        enclave_bin: PathBuf,
        /// First of nine consecutive local ports
        #[arg(long, default_value_t = 47300)]
        port_base: u16,
        /// Reload tenant state and log checkpoints every second (tests)
        #[arg(long)]
        fast_reload: bool,
        /// The release evidence's fresh checkpoint runs out this many seconds after setup
        #[arg(long)]
        release_stale_in: Option<u64>,
    },
    /// PUT the release evidence to the control plane
    PublishRelease {
        #[arg(long)]
        dir: PathBuf,
    },
    /// The TLS-terminating proxy in front of the guardian
    Proxy {
        #[arg(long)]
        dir: PathBuf,
    },
    /// The HTTPS test upstream
    Upstream {
        #[arg(long)]
        dir: PathBuf,
        /// Append each request seen to this file, one JSON object per line
        #[arg(long)]
        record: Option<PathBuf>,
    },
    /// Start a Postgres upstream in Docker or Podman with the password read from stdin
    Postgres {
        #[arg(long)]
        dir: PathBuf,
    },
    /// Start a Redis upstream in Docker or Podman with the password read from stdin
    Redis {
        #[arg(long)]
        dir: PathBuf,
    },
    /// The app
    #[command(subcommand)]
    App(AppCmd),
}

#[derive(Subcommand)]
enum AppCmd {
    Http {
        #[arg(long)]
        blob_file: PathBuf,
    },
    Pg {
        #[arg(long)]
        blob_file: PathBuf,
    },
}

/// Prints what the caller needs and leaves the container running: the caller removes it
/// (`<runtime> rm -f <container>`).
fn print_container(container: Container, destination: &str) {
    println!("runtime {}", container.runtime);
    println!("container {}", container.id);
    println!("destination {destination}");
    std::mem::forget(container);
}

fn blob(path: &PathBuf) -> anyhow::Result<String> {
    Ok(std::fs::read_to_string(path).with_context(|| format!("{}", path.display()))?.trim().to_string())
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Command::Setup { dir, enclave_bin, port_base, fast_reload, release_stale_in } => {
            let release_age = match release_stale_in {
                Some(secs) => FRESH_CHECKPOINT_SECS.checked_sub(secs).context("--release-stale-in is too long")?,
                None => 0,
            };
            let options = setup::Options { release_age, fast_reload };
            let sim = setup::setup_with(&dir, &enclave_bin, Ports::from_base(port_base), options)?;
            println!("environment in {}", sim.dir.display());
            println!("enclave measurement {}", sim.measurement);
            println!("guardian key {}", sim.guardian_key);
            println!("producer key {}", sim.producer_public_key);
            println!("deployment identity {}", sim.deployment_json());
            println!("log seed {}", sim.log_seed);
        }
        Command::PublishRelease { dir } => {
            let sim = Sim::load(&dir)?;
            setup::publish_release(&sim).await?;
            println!("release {} published to {}", sim.measurement, sim.control_url());
        }
        Command::Proxy { dir } => {
            let sim = Sim::load(&dir)?;
            let listener = tokio::net::TcpListener::bind(("127.0.0.1", sim.ports.guardian_tls)).await?;
            let backend = std::net::SocketAddr::from(([127, 0, 0, 1], sim.ports.guardian));
            println!("proxy: TLS on {} -> guardian on {backend}", sim.ports.guardian_tls);
            net::proxy(listener, backend, net::server_config(&sim, &[])?).await;
        }
        Command::Upstream { dir, record } => {
            let sim = Sim::load(&dir)?;
            let listener = tokio::net::TcpListener::bind(("127.0.0.1", sim.ports.upstream)).await?;
            println!("upstream: {}", sim.upstream_url());
            let record = std::sync::Arc::new(match record {
                Some(path) => net::Upstream::recording_to(&path)?,
                None => net::Upstream::default(),
            });
            net::upstream(listener, net::server_config(&sim, &[b"http/1.1"])?, record, true).await;
        }
        Command::Postgres { dir } => {
            let sim = Sim::load(&dir)?;
            let mut password = String::new();
            std::io::stdin().read_to_string(&mut password)?;
            let pg = postgres::start(&sim, password.trim()).await?;
            let destination = pg.destination();
            print_container(pg.0, &destination);
        }
        Command::Redis { dir } => {
            let sim = Sim::load(&dir)?;
            let mut password = String::new();
            std::io::stdin().read_to_string(&mut password)?;
            let redis = redis::start(&sim, password.trim()).await?;
            let destination = redis.destination();
            print_container(redis.0, &destination);
        }
        Command::App(cmd) => {
            let client = seal::Client::from_env().await.context("connect to the enclave")?;
            let enclave = client.enclave().await?;
            println!(
                "app: verified enclave {} (release {}, tenant {}@{})",
                enclave.measurement(),
                enclave.release_version(),
                enclave.tenant(),
                enclave.root_id()
            );
            match cmd {
                AppCmd::Http { blob_file } => {
                    app::http_flow(&client, &blob(&blob_file)?).await?;
                }
                AppCmd::Pg { blob_file } => {
                    app::pg_flow(&client, &blob(&blob_file)?).await?;
                }
            }
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    if let Err(e) = run(Cli::parse()).await {
        eprintln!("seal-sim: {e:#}");
        std::process::exit(1);
    }
}
