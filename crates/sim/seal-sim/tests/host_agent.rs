//! The seal host agent (App Integrity add-on) against the whole system on the simulator: Seal's
//! own binaries as processes on localhost, as in the end-to-end tests (`tests/e2e/` at the
//! repository root, which cover everything else). This one stays in Rust because it uses the
//! SDK's `HostAgentReporter`, which the Python SDK does not expose yet.
//!
//! Ignored by default: it needs the sim binaries (`scripts/sim-env.sh` builds them, as
//! `scripts/e2e.sh` does) and `SEAL_AGENT_BIN`, a `seal-agent` built with its `sim` feature from
//! the private add-on repo:
//!
//! ```text
//! SEAL_AGENT_BIN=... cargo test -p seal-sim --features sim --test host_agent -- --ignored --nocapture
//! ```
//!
//! `SEAL_SIM_BIN_DIR` names another directory for the binaries.

extern crate seal_client as seal;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use seal::identity::AppKeyIdentity;
use seal::{Client, ErrorCode};
use seal_sim::net::{self, Upstream};
use seal_sim::setup::{self, Ports, Sim};

const TENANT: &str = "acme";
const SECRET: &str = "sk-live-e2e-5be1c0de";
/// Longer than `STATE_RELOAD_SECS`, so every replica has loaded a new state.
const RELOAD_WAIT: Duration = Duration::from_secs(45);

/// A running binary, its output in `<dir>/logs/<name>.log`; killed on drop.
struct Proc {
    child: Child,
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct World {
    sim: Sim,
    bins: PathBuf,
    upstream: Arc<Upstream>,
    procs: Vec<Proc>,
    pin: String,
    trust: seal_verify::Trust,
}

impl Drop for World {
    fn drop(&mut self) {
        // Newest first, so the enclave can still reach the control plane.
        while let Some(p) = self.procs.pop() {
            drop(p);
        }
        if std::thread::panicking() {
            for entry in std::fs::read_dir(self.sim.path("logs")).into_iter().flatten().flatten() {
                let text = std::fs::read_to_string(entry.path()).unwrap_or_default();
                let tail: Vec<&str> = text.lines().rev().take(25).collect();
                eprintln!("--- {}", entry.path().display());
                for line in tail.into_iter().rev() {
                    eprintln!("{line}");
                }
            }
        } else {
            let _ = std::fs::remove_dir_all(&self.sim.dir);
        }
    }
}

/// The binaries' directory: `SEAL_SIM_BIN_DIR`, else the one holding this package's binary.
fn bin_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("SEAL_SIM_BIN_DIR") {
        return PathBuf::from(dir);
    }
    Path::new(env!("CARGO_BIN_EXE_seal-sim")).parent().unwrap().to_path_buf()
}

/// A command with no inherited `SEAL_*` variables.
fn command(bin: &Path) -> Command {
    let mut cmd = Command::new(bin);
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("SEAL_") {
            cmd.env_remove(name);
        }
    }
    cmd
}

impl World {
    fn spawn(&mut self, name: &'static str, mut cmd: Command) {
        let log = std::fs::File::create(self.sim.path(&format!("logs/{name}.log"))).unwrap();
        cmd.stdout(log.try_clone().unwrap()).stderr(log).stdin(Stdio::null());
        let child = cmd.spawn().unwrap_or_else(|e| panic!("start {name}: {e}"));
        self.procs.push(Proc { child });
    }

    fn log_of(&self, name: &str) -> String {
        std::fs::read_to_string(self.sim.path(&format!("logs/{name}.log"))).unwrap_or_default()
    }

    async fn wait_for_log(&self, name: &str, needle: &str) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while !self.log_of(name).contains(needle) {
            assert!(Instant::now() < deadline, "{name} did not log {needle:?}");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Runs the `seal` CLI with this world's admin home and trust, signing changes with its
    /// admin key file; returns stdout, panics on failure.
    fn seal(&self, args: &[&str], stdin: Option<&str>, env: &[(&str, &str)]) -> String {
        let mut cmd = command(&self.bins.join("seal"));
        cmd.env("SEAL_HOME", self.sim.path("admin")).env("SEAL_TRUST", self.sim.path("trust.json")).args(args);
        if matches!(args.first(), Some(&"grant") | Some(&"settings")) {
            cmd.arg("--key-file").arg(self.sim.path("admin.key"));
        }
        cmd.envs(env.iter().copied());
        cmd.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() });
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = cmd.spawn().expect("run seal");
        if let Some(text) = stdin {
            use std::io::Write as _;
            child.stdin.take().unwrap().write_all(text.as_bytes()).unwrap();
        }
        let out = child.wait_with_output().unwrap();
        let (stdout, stderr) = (String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        println!("$ seal {}\n{stdout}{stderr}", args.join(" "));
        assert!(out.status.success(), "seal {args:?} failed: {stderr}");
        stdout.into_owned()
    }

    /// Seals with the CLI as the producer.
    fn seal_secret(&self, secret: &str, to: &str, extra: &[&str]) -> String {
        let producer = self.sim.producer_key().unwrap();
        let mut args = vec!["secret", "--to", to, "--app", "checkout"];
        args.extend_from_slice(extra);
        let endpoint = self.sim.endpoint();
        let env = [("SEAL_APP_KEY", producer.as_str()), ("SEAL_ENDPOINT", &endpoint), ("SEAL_TENANT", &self.pin)];
        self.seal(&args, Some(secret), &env).trim().to_string()
    }

    /// An in-process SDK client acting as `app_key`, for the replica.
    async fn client(&self, app_key: &str) -> Client {
        let (tenant, root) = self.pin.split_once('@').unwrap();
        Client::builder()
            .endpoints([url::Url::parse(&self.sim.endpoint()).unwrap()])
            .tenant(seal::TenantId::new(tenant).unwrap())
            .root_id(root.parse().unwrap())
            .identity(Arc::new(AppKeyIdentity::parse(app_key).unwrap()))
            .trust(self.trust.clone())
            .connect()
            .await
            .expect("the app verifies the enclave")
    }

    fn app_key(&self) -> String {
        std::fs::read_to_string(self.sim.path("checkout.key")).unwrap().trim().to_string()
    }
}

/// The system up, with the tenant created and one replica serving; its files under a
/// directory named after `test`.
async fn boot(test: &str) -> World {
    let bins = bin_dir();
    for bin in ["seal-tlog-dev", "seal-guardian", "seal-control", "seal-enclave", "seal"] {
        assert!(bins.join(bin).exists(), "{} is missing: build the sim binaries first", bins.join(bin).display());
    }
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("seal-sim-{test}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let sim = setup::setup(&dir, &bins.join("seal-enclave"), Ports::free().unwrap()).unwrap();
    std::fs::create_dir_all(sim.path("logs")).unwrap();
    let trust = sim.trust().unwrap();
    let mut world = World { sim, bins, upstream: Arc::default(), procs: Vec::new(), pin: String::new(), trust };
    let (sim, bins) = (world.sim.clone(), world.bins.clone());
    let ports = sim.ports;

    let mut log = command(&bins.join("seal-tlog-dev"));
    log.args(["--dir", &sim.path("log").display().to_string(), "--seed", &sim.log_seed]);
    log.args(["--listen", &format!("127.0.0.1:{}", ports.log)]);
    world.spawn("log", log);
    let mut guardian = command(&bins.join("seal-guardian"));
    guardian.env("SEAL_SIM", "1").env("SEAL_GUARDIAN_CONFIG", sim.path("guardian.json"));
    world.spawn("guardian", guardian);
    let mut control = command(&bins.join("seal-control"));
    control.args(["--config", &sim.path("control.json").display().to_string()]);
    world.spawn("control", control);

    let proxy = tokio::net::TcpListener::bind(("127.0.0.1", ports.guardian_tls)).await.unwrap();
    let tls = net::server_config(&sim, &[]).unwrap();
    tokio::spawn(net::proxy(proxy, ([127, 0, 0, 1], ports.guardian).into(), tls));
    let upstream = tokio::net::TcpListener::bind(("127.0.0.1", ports.upstream)).await.unwrap();
    let tls = net::server_config(&sim, &[b"http/1.1"]).unwrap();
    tokio::spawn(net::upstream(upstream, tls, world.upstream.clone(), false));

    for port in [ports.log, ports.guardian, ports.control] {
        net::wait_for_port(port, Duration::from_secs(30)).await.unwrap();
    }
    setup::publish_release(&sim).await.expect("the control plane takes the release evidence");

    // The tenant, with the CLI.
    let registrar = sim.path("registrar.key").display().to_string();
    let admin_key = sim.path("admin.key").display().to_string();
    world.seal(&["key", "create", "--out", &admin_key], None, &[]);
    let init_args =
        ["dev", "init", "--tenant", TENANT, "--key-file", &admin_key, "--registrar-key", &registrar, "--yes"];
    let init = world.seal(&init_args, None, &[("SEAL_CONTROL_TOKEN", &sim.write_token)]);
    world.pin = init.lines().find_map(|l| l.strip_prefix("SEAL_TENANT=")).expect("init prints the pin").to_string();
    let app_key_out = sim.path("checkout.key").display().to_string();
    world.seal(&["grant", "app", "checkout", "key", "--generate", "--out", &app_key_out, "--yes"], None, &[]);
    let producer = sim.producer_public_key.to_string();
    world.seal(&["grant", "producer", "key", "--public", &producer, "--yes"], None, &[]);
    world.seal(&["grant", "enclave", "sim", &sim.deployment_json(), "--yes"], None, &[]);
    world.seal(&["settings", "platforms", "add", "sim", "--yes"], None, &[]);

    // The enclave: release, bundle and deployment verified, keys from the guardian.
    let mut enclave = command(&bins.join("seal-enclave"));
    enclave.env("SEAL_SIM", "1").env("SEAL_TENANT", &world.pin);
    enclave.env("SEAL_SIM_DEPLOYMENT", sim.deployment_json()).env("SEAL_ENCLAVE_CONFIG", sim.path("enclave.json"));
    world.spawn("enclave", enclave);
    world.wait_for_log("enclave", "serving the API").await;
    world
}

/// `GET <base>/models` with the key; the status, or 0 when the connection fails.
async fn status(base: &str, key: &str, at: Option<std::net::SocketAddr>, roots: Option<&[u8]>) -> u16 {
    let auth = format!("Bearer {key}");
    match net::get_at(at, &format!("{base}/models"), &[("authorization", &auth)], roots).await {
        Ok((status, _)) => status,
        Err(_) => 0,
    }
}

/// Polls `check` every second until it holds, for at most `RELOAD_WAIT`.
async fn eventually<F: std::future::Future<Output = bool>>(what: &str, mut check: impl FnMut() -> F) {
    let deadline = Instant::now() + RELOAD_WAIT;
    while !check().await {
        assert!(Instant::now() < deadline, "{what} within {RELOAD_WAIT:?}");
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// The seal host agent (App Integrity add-on), end to end: the agent runs as a real process
/// posting signed findings straight to the replica (`POST /v1/agent-signals`, pinned CA),
/// which verifies them against the enrolled source and applies the suspension at once; the SDK's
/// `HostAgentReporter` enrolls this very test process through the report socket (its
/// evidence rides `EndpointReport`, and would be verified by the add-on's in-enclave check);
/// a reverse-shell child of the enrolled process is detected, published, and every replica
/// applies the tenant's suspension within `STATE_RELOAD_SECS` — the identity's next session
/// start fails `IntegrityFailed` and its live session stops working.
///
/// Needs `SEAL_AGENT_BIN` and skips without it: the binary lives in the private add-on
/// repo, not this workspace.
#[tokio::test]
#[ignore]
async fn the_host_agent_detects_a_reverse_shell_and_suspends_the_endpoint() {
    let Some(agent_bin) = std::env::var_os("SEAL_AGENT_BIN").filter(|v| !v.is_empty()) else {
        eprintln!("skipping: SEAL_AGENT_BIN is not set");
        return;
    };
    let agent_bin = PathBuf::from(agent_bin);
    let mut world = boot("agent").await;
    let blob = world.seal_secret(SECRET, &format!("{}/v1", world.sim.upstream_url()), &[]);

    // The agent's key as a trusted external source; Critical findings suspend for an hour.
    let key_path = world.sim.path("agent.key").display().to_string();
    let keygen = command(&agent_bin)
        .args(["keygen", "--key", &key_path])
        .stdin(Stdio::null())
        .output()
        .expect("seal-agent keygen runs");
    assert!(keygen.status.success(), "{}", String::from_utf8_lossy(&keygen.stderr));
    let public = String::from_utf8_lossy(&keygen.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("public_key: "))
        .expect("keygen prints the public key")
        .to_string();
    world.seal(&["settings", "integrity", "source", "add", "host-agent", "--public-key", &public, "--yes"], None, &[]);
    world.seal(&["settings", "integrity", "on", "critical", "suspend=3600", "--yes"], None, &[]);

    // The agent: one process, posting findings straight to the replica under its CA.
    let socket = world.sim.path("agent.sock").display().to_string();
    let run_dir = world.sim.path("agent-run").display().to_string();
    let config = world.sim.path("agent.toml").display().to_string();
    std::fs::write(
        &config,
        format!(
            "tenant = \"{TENANT}\"\nendpoints = [\"{}\"]\nca_pem = \"\"\nsocket_path = \"{socket}\"\nkey_path = \"{key_path}\"\nrun_dir = \"{run_dir}\"\npoll_ms = 200\n",
            world.sim.endpoint(),
        ),
    )
    .unwrap();
    let mut agent = command(&agent_bin);
    agent.args(["run", "--config", &config]);
    world.spawn("agent", agent);
    let deadline = Instant::now() + Duration::from_secs(20);
    while !Path::new(&socket).exists() {
        assert!(Instant::now() < deadline, "the agent socket never appeared:\n{}", world.log_of("agent"));
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // A session whose reports come from the agent: the handshake enrolls this process.
    let app_key = world.app_key();
    let client = world.client(&app_key).await;
    let key_id = AppKeyIdentity::parse(&app_key).unwrap().key_id();
    let reporter = Arc::new(seal::integrity::HostAgentReporter::with_socket_and_key(&socket, key_id));
    let session = client.session(&blob).endpoint_reporter(reporter.clone()).http().await.expect("the session starts");
    eventually("the agent watches the caller", || async {
        agent_health(&socket).map(|h| h.get("en").and_then(|v| v.as_u64()) == Some(1)).unwrap_or(false)
    })
    .await;
    let (url, key) = (session.url().to_string(), session.key().to_string());
    assert_eq!(status(&format!("{url}/models"), &key, None, None).await, 200);

    // The trigger: an interactive shell as a child of the enrolled process, exactly the
    // shape the agent flags (`reverse-shell`, Critical). Its stdin is a pipe we hold, so it
    // stays alive for more than one watch tick.
    let mut shell = Command::new("bash")
        .arg("-i")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("bash runs");

    // The suspension reaches the replica within STATE_RELOAD_SECS: new starts fail
    // IntegrityFailed, and the live session stops working.
    let deadline = Instant::now() + RELOAD_WAIT + Duration::from_secs(15);
    let mut suspended = false;
    while Instant::now() < deadline {
        let started = client.session(&blob).endpoint_reporter(reporter.clone()).http().await;
        match started {
            Err(seal::ClientError::Seal { code: ErrorCode::IntegrityFailed, .. }) => {
                suspended = true;
                break;
            }
            Err(e) => panic!("unexpected session error: {e:?}"),
            Ok(s) => {
                let _ = s.close().await;
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    assert!(
        suspended,
        "the reverse shell was never applied:\nagent log:\n{}\nhealth: {:?}\nenclave log:\n{}\ncontrol log:\n{}",
        world.log_of("agent"),
        agent_health(&socket),
        world.log_of("enclave"),
        world.log_of("control")
    );
    eventually("the live session is cut off", || async {
        status(&format!("{url}/models"), &key, None, None).await != 200
    })
    .await;

    // Cleanup order matters: kill the shell, then the watchdog (it would resurrect the
    // agent when World's Drop kills it), then let Drop take the agent itself.
    drop(shell.stdin.take());
    let _ = shell.wait();
    let wd = std::fs::read_to_string(format!("{run_dir}/wd.pid")).unwrap_or_default().trim().to_string();
    if !wd.is_empty() {
        let _ = Command::new("kill").args(["-9", &wd]).status();
    }
    let log = world.log_of("agent");
    assert!(!log.contains("ERROR"), "agent:\n{log}");
}

/// One health request to the agent socket.
fn agent_health(socket: &str) -> Option<serde_json::Value> {
    use std::io::{BufRead, BufReader, Write};
    let mut stream = std::os::unix::net::UnixStream::connect(socket).ok()?;
    stream.write_all(b"{\"v\":1,\"t\":\"h\"}\n").ok()?;
    let line = BufReader::new(stream).lines().next()?.ok()?;
    serde_json::from_str(&line).ok()
}
