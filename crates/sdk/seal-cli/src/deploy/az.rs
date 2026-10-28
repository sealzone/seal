//! The Azure CLI, run as a child process with `-o json`. It brings the customer's login,
//! subscription and MFA, so this build carries no Azure SDK and no token handling. No secret is
//! ever an argument: the registry password goes in a parameters file only the user can read.

use std::path::PathBuf;

use anyhow::{anyhow, bail, Context as _};
use serde_json::Value;

pub struct Az;

/// One argument as a shell would need it, for printing commands.
fn quoted(arg: &str) -> String {
    let plain = !arg.is_empty() && arg.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_./:=@,+%".contains(&b));
    if plain {
        arg.to_owned()
    } else {
        format!("'{}'", arg.replace('\'', r"'\''"))
    }
}

/// `az ARGS` as a command line.
pub fn line(args: &[&str]) -> String {
    std::iter::once("az".to_owned()).chain(args.iter().map(|a| quoted(a))).collect::<Vec<_>>().join(" ")
}

/// The first lines of an error az wrote, for messages.
fn excerpt(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).take(4).collect();
    lines.join(" | ")
}

impl Az {
    async fn output(&self, args: &[&str]) -> anyhow::Result<std::process::Output> {
        tokio::process::Command::new("az")
            .args(args)
            .args(["-o", "json", "--only-show-errors"])
            .stdin(std::process::Stdio::null())
            .output()
            .await
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => anyhow!("the Azure CLI (az) is not installed or not on PATH"),
                _ => anyhow!("run az: {e}"),
            })
    }

    /// `az ARGS -o json`, its output parsed (`null` when it printed nothing).
    pub async fn json(&self, args: &[&str]) -> anyhow::Result<Value> {
        let out = self.output(args).await?;
        if !out.status.success() {
            bail!("{} failed: {}", line(args), excerpt(&out.stderr));
        }
        if out.stdout.iter().all(u8::is_ascii_whitespace) {
            return Ok(Value::Null);
        }
        serde_json::from_slice(&out.stdout).with_context(|| format!("{}: output is not JSON", line(args)))
    }

    /// As `json` for a `show`, `None` when the resource does not exist.
    pub async fn show(&self, args: &[&str]) -> anyhow::Result<Option<Value>> {
        let out = self.output(args).await?;
        if out.status.success() {
            return Ok(Some(
                serde_json::from_slice(&out.stdout).with_context(|| format!("{}: output is not JSON", line(args)))?,
            ));
        }
        let stderr = String::from_utf8_lossy(&out.stderr);
        if stderr.contains("ResourceNotFound")
            || stderr.contains("could not be found")
            || stderr.contains("was not found")
        {
            return Ok(None);
        }
        bail!("{} failed: {}", line(args), excerpt(&out.stderr))
    }
}

/// A private directory (mode 0700) for the template and parameters files, removed on drop.
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
            line(&["identity", "create", "-g", "rg", "-n", "seal acme", "--tags", "it's"]),
            r"az identity create -g rg -n 'seal acme' --tags 'it'\''s'"
        );
        assert_eq!(
            line(&["ad", "app", "update", "--identifier-uris", "api://x"]),
            "az ad app update --identifier-uris api://x"
        );
        assert_eq!(line(&["x", ""]), "az x ''");
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
