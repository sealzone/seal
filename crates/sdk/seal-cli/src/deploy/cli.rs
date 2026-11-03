//! The cloud CLIs `seal deploy` drives (`az`, `gcloud`, `aws`), run as child processes with
//! JSON output. They bring the customer's login, project or subscription and MFA, so this build
//! carries no cloud SDK and no token handling. No secret is ever an argument: a registry
//! password goes in a file only the user can read.
//!
//! Each run is checked before anything changes (`preflight`: the CLI is installed and logged
//! in), and a call that fails the way a busy or flaky cloud fails (throttling, a timeout, a 5xx)
//! is tried again with backoff. Reads and the existence checks are safe to repeat; a create that
//! timed out may have happened, which is why every step looks first (`Steps::ensure` treats
//! "already exists" as done).

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, bail, Context as _};
use serde_json::Value;

/// One cloud CLI: how to run it and how to read its failures.
pub struct Cli {
    pub program: &'static str,
    /// Appended to every call: JSON output, no prompts.
    output: &'static [&'static str],
    /// Failure text that means the resource does not exist.
    not_found: &'static [&'static str],
    /// Failure text that means a create found the resource there already.
    exists: &'static [&'static str],
    /// Failure text worth trying again.
    transient: &'static [&'static str],
    /// The command that fails unless the user is logged in, and what to run then.
    whoami: &'static [&'static str],
    login: &'static str,
}

pub const AZ: Cli = Cli {
    program: "az",
    output: &["-o", "json", "--only-show-errors"],
    // Not a bare "NotFound": SubscriptionNotFound is a login problem, not a missing resource.
    not_found: &["ResourceNotFound", "could not be found", "was not found"],
    exists: &["already exists", "AlreadyExists", "Conflict"],
    transient: &[
        "TooManyRequests",
        "(429)",
        "RetryableError",
        "ServiceUnavailable",
        "InternalServerError",
        "GatewayTimeout",
        "AnotherOperationInProgress",
        "Connection aborted",
        "Connection reset",
        "timed out",
    ],
    whoami: &["account", "show"],
    login: "az login",
};

pub const GCLOUD: Cli = Cli {
    program: "gcloud",
    output: &["--format=json", "--quiet"],
    not_found: &["was not found", "notFound", "NOT_FOUND", "does not exist"],
    exists: &["already exists", "alreadyExists", "ALREADY_EXISTS"],
    transient: &[
        "rateLimitExceeded",
        "RATE_LIMIT_EXCEEDED",
        "backendError",
        "UNAVAILABLE",
        "Internal error",
        "INTERNAL",
        "resourceNotReady",
        "is not ready",
        "currently in use by another operation",
        "Connection reset",
        "timed out",
        "HTTP 503",
        "HTTP 502",
    ],
    whoami: &["auth", "print-access-token"],
    login: "gcloud auth login",
};

// For `seal deploy aws`, which arrives with the Nitro platform.
#[allow(dead_code)]
pub const AWS: Cli = Cli {
    program: "aws",
    output: &["--output", "json", "--no-cli-pager"],
    not_found: &["NotFound", "does not exist", "NoSuchEntity", "InvalidGroup.NotFound"],
    exists: &["AlreadyExists", "already exists", "EntityAlreadyExists", "InvalidPermission.Duplicate"],
    transient: &[
        "Throttling",
        "RequestLimitExceeded",
        "ServiceUnavailable",
        "InternalError",
        "RequestTimeout",
        "Connection reset",
        "timed out",
    ],
    whoami: &["sts", "get-caller-identity"],
    login: "aws configure (or aws sso login)",
};

/// One argument as a shell would need it, for printing commands.
fn quoted(arg: &str) -> String {
    let plain = !arg.is_empty() && arg.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_./:=@,+%".contains(&b));
    if plain {
        arg.to_owned()
    } else {
        format!("'{}'", arg.replace('\'', r"'\''"))
    }
}

/// `PROGRAM ARGS` as a command line.
pub fn line(program: &str, args: &[&str]) -> String {
    std::iter::once(program.to_owned()).chain(args.iter().map(|a| quoted(a))).collect::<Vec<_>>().join(" ")
}

/// The first lines of an error a CLI wrote, for messages.
fn excerpt(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).take(4).collect();
    lines.join(" | ")
}

/// How long to wait before attempt `n` (from 1): 2 s, 4 s, 8 s.
pub const ATTEMPTS: u32 = 4;
fn backoff(n: u32) -> Duration {
    Duration::from_secs(1 << n.min(4))
}

/// A failed call: the command, what it wrote, and whether it is worth trying again.
#[derive(Debug)]
pub struct Failed {
    pub command: String,
    pub stderr: String,
}

impl std::fmt::Display for Failed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} failed: {}", self.command, excerpt(self.stderr.as_bytes()))
    }
}

impl std::error::Error for Failed {}

impl Cli {
    pub fn line(&self, args: &[&str]) -> String {
        line(self.program, args)
    }

    fn matches(text: &str, markers: &[&str]) -> bool {
        markers.iter().any(|m| text.contains(m))
    }

    async fn output(&self, args: &[&str]) -> anyhow::Result<std::process::Output> {
        tokio::process::Command::new(self.program)
            .args(args)
            .args(self.output)
            .stdin(std::process::Stdio::null())
            .output()
            .await
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => anyhow!("{} is not installed or not on PATH", self.program),
                _ => anyhow!("run {}: {e}", self.program),
            })
    }

    /// Runs `args`, trying a transient failure again; the last output either way.
    async fn run(&self, args: &[&str]) -> anyhow::Result<std::process::Output> {
        let mut n = 1;
        loop {
            let out = self.output(args).await?;
            let stderr = String::from_utf8_lossy(&out.stderr);
            if out.status.success() || n >= ATTEMPTS || !Self::matches(&stderr, self.transient) {
                return Ok(out);
            }
            let wait = backoff(n);
            eprintln!("  {} answered {}; trying again in {} s", self.program, excerpt(&out.stderr), wait.as_secs());
            tokio::time::sleep(wait).await;
            n += 1;
        }
    }

    fn parse(&self, args: &[&str], stdout: &[u8]) -> anyhow::Result<Value> {
        if stdout.iter().all(u8::is_ascii_whitespace) {
            return Ok(Value::Null);
        }
        serde_json::from_slice(stdout).with_context(|| format!("{}: output is not JSON", self.line(args)))
    }

    /// `PROGRAM ARGS`, its JSON output parsed (`null` when it printed nothing).
    pub async fn json(&self, args: &[&str]) -> anyhow::Result<Value> {
        let out = self.run(args).await?;
        if !out.status.success() {
            return Err(Failed { command: self.line(args), stderr: String::from_utf8_lossy(&out.stderr).into() }.into());
        }
        self.parse(args, &out.stdout)
    }

    /// As `json` for a read of one resource: `None` when it does not exist.
    pub async fn show(&self, args: &[&str]) -> anyhow::Result<Option<Value>> {
        let out = self.run(args).await?;
        if out.status.success() {
            return self.parse(args, &out.stdout).map(Some);
        }
        let stderr = String::from_utf8_lossy(&out.stderr);
        if Self::matches(&stderr, self.not_found) {
            return Ok(None);
        }
        Err(Failed { command: self.line(args), stderr: stderr.into() }.into())
    }

    /// `PROGRAM ARGS`'s plain output (logs, a serial console), without the JSON flags.
    pub async fn text(&self, args: &[&str]) -> anyhow::Result<String> {
        let out = tokio::process::Command::new(self.program)
            .args(args)
            .stdin(std::process::Stdio::null())
            .output()
            .await
            .map_err(|e| anyhow!("run {}: {e}", self.program))?;
        if !out.status.success() {
            return Err(Failed { command: self.line(args), stderr: String::from_utf8_lossy(&out.stderr).into() }.into());
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// Whether `err` is a create finding its resource already there.
    pub fn already_exists(&self, err: &anyhow::Error) -> bool {
        err.downcast_ref::<Failed>().is_some_and(|f| Self::matches(&f.stderr, self.exists))
    }

    /// The CLI is installed and logged in; checked before anything is read or changed.
    pub async fn preflight(&self) -> anyhow::Result<()> {
        let out = self.output(self.whoami).await?;
        if !out.status.success() {
            bail!("{} is not logged in ({}): run `{}` first", self.program, excerpt(&out.stderr), self.login);
        }
        Ok(())
    }
}

/// A private directory (mode 0700) for templates and parameter files, removed on drop.
pub struct Scratch(pub PathBuf);

impl Scratch {
    pub fn new() -> anyhow::Result<Self> {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos());
        let dir = std::env::temp_dir().join(format!("seal-deploy-{}-{nanos}", std::process::id()));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder.create(&dir).with_context(|| format!("{}", dir.display()))?;
        Ok(Self(dir))
    }

    /// Writes `bytes` to a new file `name` here (mode 0600).
    pub fn write(&self, name: &str, bytes: &[u8]) -> anyhow::Result<PathBuf> {
        let path = self.0.join(name);
        crate::config::write_private(&path, bytes)?;
        Ok(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_print_as_a_shell_reads_them() {
        assert_eq!(
            AZ.line(&["identity", "create", "-g", "rg", "-n", "seal acme", "--tags", "it's"]),
            r"az identity create -g rg -n 'seal acme' --tags 'it'\''s'"
        );
        assert_eq!(
            AZ.line(&["ad", "app", "update", "--identifier-uris", "api://x"]),
            "az ad app update --identifier-uris api://x"
        );
        assert_eq!(GCLOUD.line(&["compute", "instances", "list"]), "gcloud compute instances list");
        assert_eq!(AZ.line(&["x", ""]), "az x ''");
    }

    #[test]
    fn failures_are_read_per_cli() {
        let failed = |stderr: &str| anyhow::Error::from(Failed { command: "x".into(), stderr: stderr.into() });
        assert!(GCLOUD.already_exists(&failed("ERROR: (gcloud.iam.service-accounts.create) Resource in projects [p] is the subject of a conflict: Service account seal-acme already exists within project")));
        assert!(AZ.already_exists(&failed("(Conflict) The resource already exists")));
        assert!(!AZ.already_exists(&failed("(AuthorizationFailed) no")));
        assert!(Cli::matches(
            "ERROR: (gcloud.compute.instances.create) Could not fetch resource: - rateLimitExceeded",
            GCLOUD.transient
        ));
        assert!(!Cli::matches("ERROR: PERMISSION_DENIED", GCLOUD.transient));
        assert!(Cli::matches("(TooManyRequests) slow down", AZ.transient));
        assert_eq!(backoff(1), Duration::from_secs(2));
        assert_eq!(backoff(3), Duration::from_secs(8));
    }

    #[test]
    fn scratch_files_are_private_and_removed() {
        let scratch = Scratch::new().unwrap();
        let path = scratch.write("p.json", b"{}").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&scratch.0).unwrap().permissions().mode() & 0o777, 0o700);
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let dir = scratch.0.clone();
        drop(scratch);
        assert!(!dir.exists());
    }
}
