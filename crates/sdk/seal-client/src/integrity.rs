//! Integrity on the SDK side: the endpoint report sent with every session start and extend,
//! and signals about itself (`Client::signal`). The SDK sends only
//! signals; telemetry is written by the enclave. Reporters are pluggable, so a host agent or an
//! EDR integration can supply the report; Seal treats its evidence as opaque.

use std::sync::OnceLock;

use async_trait::async_trait;
use seal_proto::integrity::{ArtifactHash, EndpointReport};
use seal_proto::KeyId;
use sha2::{Digest, Sha256};

use crate::identity::AppKeyIdentity;
use crate::ClientError;

/// Supplies the `EndpointReport` sent at every session start and extend.
#[async_trait]
pub trait EndpointReporter: Send + Sync {
    /// `challenge` is the `evidence_challenge()` of the request this report will travel
    /// in. Reporters that sign evidence (see `HostAgentReporter`) bind it into the signed
    /// bytes so the enclave can refuse replays; simple reporters ignore it.
    async fn report(&self, challenge: [u8; 32]) -> Result<EndpointReport, ClientError>;
}

/// Reports what the seal host agent (App Integrity add-on) says about this process: the
/// artifact the agent itself hashed outside the process, plus opaque `host-agent` evidence
/// bound to the challenge, so the enclave can hold the report to a signature the app
/// cannot forge and refuse evidence replayed from another request.
///
/// Falls back to `ExecutableHash` whenever the agent is absent (no `SEAL_APP_KEY`, no
/// socket, timeout, bad answer), so hosts without the add-on keep passing the Phase 1
/// artifact check. Protocol `host-agent/v1`: one JSON line per connection.
pub struct HostAgentReporter {
    socket: String,
    key_id: Option<KeyId>,
}

impl Default for HostAgentReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl HostAgentReporter {
    /// Socket: `SEAL_AGENT_SOCKET`, else `/run/seal/agent.sock`. App key id: parsed from
    /// `SEAL_APP_KEY` (the same env `AppKeyIdentity` reads); without one the agent cannot
    /// attribute reports, so the reporter falls back.
    pub fn new() -> Self {
        let socket = std::env::var("SEAL_AGENT_SOCKET")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "/run/seal/agent.sock".to_owned());
        let key_id =
            std::env::var("SEAL_APP_KEY").ok().and_then(|key| AppKeyIdentity::parse(&key).ok().map(|id| id.key_id()));
        Self { socket, key_id }
    }

    /// Fully specified (tests, configured setups).
    pub fn with_socket_and_key(socket: impl Into<String>, key_id: KeyId) -> Self {
        Self { socket: socket.into(), key_id: Some(key_id) }
    }

    async fn fallback(&self, challenge: [u8; 32]) -> Result<EndpointReport, ClientError> {
        ExecutableHash.report(challenge).await
    }

    /// One ask, one answer, two seconds.
    async fn ask(&self, key_id: KeyId, challenge: [u8; 32]) -> Result<EndpointReport, ClientError> {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let bad = || ClientError::Invalid("the host agent answered nonsense".into());
        let mut stream = tokio::net::UnixStream::connect(&self.socket)
            .await
            .map_err(|_| ClientError::Invalid("the host agent is not answering".into()))?;
        let request = serde_json::json!({
            "v": 1, "t": "r",
            "pid": std::process::id(),
            "k": hex::encode(key_id.0),
            "c": hex::encode(challenge),
        });
        let ask = async {
            stream.write_all((request.to_string() + "\n").as_bytes()).await?;
            let (reader, _writer) = stream.split();
            let mut line = Vec::new();
            let mut reader = BufReader::new(reader);
            reader.read_until(b'\n', &mut line).await?;
            Ok::<_, std::io::Error>(line)
        };
        let line = tokio::time::timeout(std::time::Duration::from_secs(2), ask)
            .await
            .map_err(|_| ClientError::Invalid("the host agent timed out".into()))?
            .map_err(|_| ClientError::Invalid("the host agent is not answering".into()))?;
        let answer: serde_json::Value = serde_json::from_slice(&line).map_err(|_| bad())?;
        if answer.get("ok").and_then(|v| v.as_bool()) != Some(true) {
            return Err(ClientError::Invalid("the host agent refused the report".into()));
        }
        let name = answer.get("an").and_then(|v| v.as_str()).ok_or_else(bad)?.to_owned();
        let sha = answer.get("as").and_then(|v| v.as_str()).ok_or_else(bad)?;
        let sha: [u8; 32] = hex::decode(sha).map_err(|_| bad())?.as_slice().try_into().map_err(|_| bad())?;
        let evidence = answer.get("e").and_then(|v| v.as_str()).ok_or_else(bad)?;
        let evidence = hex::decode(evidence).map_err(|_| bad())?;
        Ok(EndpointReport {
            artifact: Some(ArtifactHash { name, sha256: sha }),
            evidence: vec![seal_proto::integrity::EndpointEvidence { provider: "host-agent".into(), bytes: evidence }],
        })
    }
}

#[async_trait]
impl EndpointReporter for HostAgentReporter {
    async fn report(&self, challenge: [u8; 32]) -> Result<EndpointReport, ClientError> {
        match self.key_id {
            Some(key_id) => match self.ask(key_id, challenge).await {
                Ok(report) => Ok(report),
                // An absent or wedged agent must not break the session: fall back.
                Err(_) => self.fallback(challenge).await,
            },
            None => self.fallback(challenge).await,
        }
    }
}

/// Default: `artifact = ("executable", SHA-256 of the running executable)`, computed once
/// per process. Interpreted apps (Python) should supply a reporter that hashes the app
/// bundle or reports the container image digest instead.
pub struct ExecutableHash;

/// The running executable's hash, once per process.
static EXECUTABLE_SHA256: OnceLock<[u8; 32]> = OnceLock::new();

/// SHA-256 of the file at `path`, read in chunks.
fn file_sha256(path: &std::path::Path) -> std::io::Result<[u8; 32]> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            return Ok(hash.finalize().into());
        }
        hash.update(&buf[..n]);
    }
}

#[async_trait]
impl EndpointReporter for ExecutableHash {
    async fn report(&self, _challenge: [u8; 32]) -> Result<EndpointReport, ClientError> {
        let sha256 = match EXECUTABLE_SHA256.get() {
            Some(h) => *h,
            None => {
                let hashing = |e: String| ClientError::Invalid(format!("hashing the executable: {e}"));
                let hash = tokio::task::spawn_blocking(|| std::env::current_exe().and_then(|p| file_sha256(&p)))
                    .await
                    .map_err(|e| hashing(e.to_string()))?
                    .map_err(|e| hashing(e.to_string()))?;
                *EXECUTABLE_SHA256.get_or_init(|| hash)
            }
        };
        Ok(EndpointReport { artifact: Some(ArtifactHash { name: "executable".into(), sha256 }), evidence: Vec::new() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reports_the_running_executable() {
        let report = ExecutableHash.report([0; 32]).await.unwrap();
        let artifact = report.artifact.unwrap();
        assert_eq!(artifact.name, "executable");
        let expected = file_sha256(&std::env::current_exe().unwrap()).unwrap();
        assert_eq!(artifact.sha256, expected);
        assert!(report.evidence.is_empty());
        assert_eq!(ExecutableHash.report([0; 32]).await.unwrap().artifact.unwrap().sha256, expected);
    }

    #[tokio::test]
    async fn host_agent_reporter_binds_the_challenge_and_parses_the_answer() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut line = Vec::new();
            BufReader::new(reader).read_until(b'\n', &mut line).await.unwrap();
            let answer = format!(
                "{{\"v\":1,\"ok\":true,\"an\":\"executable\",\"as\":\"{}\",\"e\":\"{}\",\"n\":1}}\n",
                hex::encode([7u8; 32]),
                hex::encode([1, 2, 3, 4]),
            );
            writer.write_all(answer.as_bytes()).await.unwrap();
        });

        let reporter = HostAgentReporter::with_socket_and_key(path.to_str().unwrap(), seal_proto::KeyId([9; 32]));
        let challenge = [5u8; 32];
        let report = reporter.report(challenge).await.unwrap();
        let artifact = report.artifact.unwrap();
        assert_eq!(artifact.name, "executable");
        assert_eq!(artifact.sha256, [7; 32]);
        assert_eq!(report.evidence.len(), 1);
        assert_eq!(report.evidence[0].provider, "host-agent");
        assert_eq!(report.evidence[0].bytes, vec![1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn host_agent_reporter_falls_back_when_the_agent_is_absent() {
        let reporter =
            HostAgentReporter::with_socket_and_key("/nonexistent/seal/agent.sock", seal_proto::KeyId([9; 32]));
        let report = reporter.report([1; 32]).await.unwrap();
        // The executable hash, and no evidence: the Phase 1 check keeps working.
        assert_eq!(report.artifact.unwrap().name, "executable");
        assert!(report.evidence.is_empty());
    }
}
