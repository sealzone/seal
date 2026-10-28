//! Upstreams in containers (Docker or Podman), for the Postgres and Redis upstreams.

use std::process::Command;

use anyhow::{anyhow, bail, Context as _};

/// A running container, removed on drop.
pub struct Container {
    pub id: String,
    /// The host port its service port is published on (127.0.0.1).
    pub port: u16,
    /// `docker` or `podman`, whichever started it.
    pub runtime: String,
}

impl Drop for Container {
    fn drop(&mut self) {
        let _ = Command::new(&self.runtime).args(["rm", "-f", &self.id]).output();
    }
}

/// The container runtime: `SEAL_CONTAINER_RUNTIME` if set, else `docker` or `podman`,
/// whichever answers first.
pub fn runtime() -> anyhow::Result<String> {
    let answers = |cmd: &str| Command::new(cmd).arg("info").output().is_ok_and(|o| o.status.success());
    if let Some(cmd) = std::env::var("SEAL_CONTAINER_RUNTIME").ok().filter(|c| !c.is_empty()) {
        return if answers(&cmd) {
            Ok(cmd)
        } else {
            bail!("SEAL_CONTAINER_RUNTIME={cmd} does not answer `{cmd} info`")
        };
    }
    ["docker", "podman"]
        .into_iter()
        .find(|cmd| answers(cmd))
        .map(str::to_string)
        .ok_or_else(|| anyhow!("Docker or Podman is required (neither answers `info`)"))
}

/// Starts `image` detached with `env`, running `script` under `shell`, and publishes
/// `service_port` on a free port of 127.0.0.1.
pub fn start(
    image: &str,
    env: &[(&str, &str)],
    shell: &str,
    script: &str,
    service_port: u16,
) -> anyhow::Result<Container> {
    let runtime = runtime()?;
    let mut cmd = Command::new(&runtime);
    cmd.args(["run", "-d", "-p", &format!("127.0.0.1::{service_port}")]);
    for (name, value) in env {
        cmd.args(["-e", &format!("{name}={value}")]);
    }
    let out =
        cmd.args(["--entrypoint", shell, image, "-c", script]).output().with_context(|| format!("{runtime} run"))?;
    if !out.status.success() {
        bail!("{runtime} run: {}", String::from_utf8_lossy(&out.stderr));
    }
    let id = String::from_utf8(out.stdout)?.trim().to_string();
    let mapped = Command::new(&runtime).args(["port", &id, &format!("{service_port}/tcp")]).output();
    let mapped = String::from_utf8(mapped.context("container port")?.stdout)?;
    let port = mapped.lines().next().and_then(|l| l.trim().rsplit(':').next()).and_then(|p| p.parse().ok());
    let Some(port) = port else {
        drop(Container { id, port: 0, runtime: runtime.clone() });
        bail!("{runtime} port: {mapped}");
    };
    Ok(Container { id, port, runtime })
}
