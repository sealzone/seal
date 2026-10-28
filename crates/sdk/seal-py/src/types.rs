//! The SDK's data as Python values: session info, receipts, endpoint reports.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use seal_proto::integrity::{ArtifactHash, EndpointEvidence};

use crate::wire_name;

/// `s.info`: the session's id, tiers, tenant, app, blob id and expiry.
#[pyclass(frozen, module = "seal._seal")]
pub struct SessionInfo {
    /// base64url, as telemetry shows it.
    #[pyo3(get)]
    session_id: String,
    /// `sim` or `sealed`.
    #[pyo3(get)]
    platform: String,
    /// `base` or `hardened`.
    #[pyo3(get)]
    tier: String,
    #[pyo3(get)]
    tenant: String,
    #[pyo3(get)]
    app: String,
    #[pyo3(get)]
    blob_id: String,
    /// Unix seconds.
    #[pyo3(get)]
    expires_at: u64,
}

impl From<&seal::SessionInfo> for SessionInfo {
    fn from(info: &seal::SessionInfo) -> Self {
        Self {
            session_id: seal_proto::codec::b64url(&info.session_id),
            platform: wire_name(&info.platform),
            tier: wire_name(&info.tier),
            tenant: info.tenant.to_string(),
            app: info.app.to_string(),
            blob_id: info.blob_id.to_string(),
            expires_at: info.expires_at,
        }
    }
}

#[pymethods]
impl SessionInfo {
    fn __repr__(&self) -> String {
        format!(
            "SessionInfo(session_id={:?}, platform={:?}, tier={:?}, tenant={:?}, app={:?}, blob_id={:?}, expires_at={})",
            self.session_id, self.platform, self.tier, self.tenant, self.app, self.blob_id, self.expires_at
        )
    }
}

/// Where telemetry recorded a seal or a session start. Keep receipts
/// (`seal.receipts.append`) for `seal telemetry --receipts`.
#[pyclass(frozen, eq, hash, module = "seal._seal")]
#[derive(PartialEq, Eq, Hash)]
pub struct TelemetryReceipt {
    stream: [u8; 16],
    #[pyo3(get)]
    entry: u64,
}

impl From<seal::TelemetryReceipt> for TelemetryReceipt {
    fn from(r: seal::TelemetryReceipt) -> Self {
        Self { stream: r.stream, entry: r.entry }
    }
}

impl TelemetryReceipt {
    fn receipt(&self) -> seal::TelemetryReceipt {
        seal::TelemetryReceipt { stream: self.stream, entry: self.entry }
    }
}

#[pymethods]
impl TelemetryReceipt {
    /// The telemetry stream (16 bytes).
    #[getter]
    fn stream<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.stream)
    }
    /// One JSON line of the receipts file.
    fn to_json(&self) -> String {
        serde_json::to_string(&self.receipt()).expect("a receipt serializes")
    }
    fn __repr__(&self) -> String {
        format!("TelemetryReceipt(stream={}, entry={})", hex::encode(self.stream), self.entry)
    }
}

/// Appends `receipts` to `path` as JSON lines, the format `seal telemetry --receipts` reads.
#[pyfunction]
pub fn append_receipts(
    py: Python<'_>,
    path: std::path::PathBuf,
    receipts: Vec<PyRef<'_, TelemetryReceipt>>,
) -> PyResult<()> {
    let receipts: Vec<seal::TelemetryReceipt> = receipts.iter().map(|r| r.receipt()).collect();
    py.detach(|| seal::receipts::append(&path, &receipts)).map_err(PyErr::from)
}

/// What an `endpoint_reporter` returns: the endpoint's artifact (`(name, sha256)`, checked
/// against the tenant's integrity policy) and opaque provider evidence (`(provider, bytes)`).
#[pyclass(frozen, module = "seal._seal")]
pub struct EndpointReport {
    artifact: Option<ArtifactHash>,
    evidence: Vec<EndpointEvidence>,
}

impl EndpointReport {
    pub(crate) fn report(&self) -> seal_proto::integrity::EndpointReport {
        seal_proto::integrity::EndpointReport { artifact: self.artifact.clone(), evidence: self.evidence.clone() }
    }
}

#[pymethods]
impl EndpointReport {
    #[new]
    #[pyo3(signature = (*, artifact=None, evidence=Vec::new()))]
    fn new(artifact: Option<(String, Vec<u8>)>, evidence: Vec<(String, Vec<u8>)>) -> PyResult<Self> {
        let artifact = match artifact {
            Some((name, sha256)) => {
                let sha256: [u8; 32] =
                    sha256.try_into().map_err(|_| PyValueError::new_err("artifact sha256 must be 32 bytes"))?;
                Some(ArtifactHash { name, sha256 })
            }
            None => None,
        };
        let evidence = evidence.into_iter().map(|(provider, bytes)| EndpointEvidence { provider, bytes }).collect();
        Ok(Self { artifact, evidence })
    }
    fn __repr__(&self) -> String {
        match &self.artifact {
            Some(a) => format!("EndpointReport(artifact=({:?}, {}))", a.name, hex::encode(a.sha256)),
            None => "EndpointReport(artifact=None)".into(),
        }
    }
}

/// Done callback of an asyncio future: cancelling the future aborts its SDK task.
#[pyclass(frozen, module = "seal._seal")]
pub struct CancelTask(pub tokio::task::AbortHandle);

#[pymethods]
impl CancelTask {
    fn __call__(&self, future: &Bound<'_, PyAny>) -> PyResult<()> {
        if future.call_method0("cancelled")?.extract::<bool>()? {
            self.0.abort();
        }
        Ok(())
    }
}
