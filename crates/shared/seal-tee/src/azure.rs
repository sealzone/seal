//! Azure confidential containers on ACI (AMD SEV-SNP).
//!
//! `Evidence::AzureSnpAci` holds exactly what `seal_attest::azure` verifies:
//! - **report**: the raw ATTESTATION_REPORT from `/dev/sev-guest` (`SNP_GET_REPORT` through `sev`, VMPL 0), with
//!   the 32-byte report data in bytes 0..32 of REPORT_DATA and zeros after. ACI's utility VM gives every
//!   container of a confidential group the device, unprivileged; there is no attestation sidecar to go through.
//! - **VCEK**: `vcekCert` of the security context's `host-amd-cert-base64` (THIM's answer, which the host writes
//!   at launch), used while its `tcbm` equals the report's REPORTED_TCB. For any other TCB the VCEK for the
//!   report's CHIP_ID and TCB comes from `global.acccache.azure.net`, then `kdsintf.amd.com`, and is kept for
//!   later reports at that TCB. ACI does not serve IMDS THIM (404). The VCEK is public and the verifier binds it
//!   to the report, so where it comes from adds no trust.
//! - **UVM endorsement**: `reference-info-base64`, as the platform wrote it.
//!
//! The security context directory is `UVM_SECURITY_CONTEXT_DIR` (ACI sets it), else the one
//! `/security-context-*` directory. Its `security-policy-base64` must hash to the report's `host_data`, from
//! which `measurement` is computed. Time on Azure is Roughtime (`crate::roughtime`).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use seal_proto::{Evidence, Measurement};
use sha2::{Digest, Sha256};

use crate::TeeError;

/// Names the security context directory.
const SECURITY_CONTEXT_ENV: &str = "UVM_SECURITY_CONTEXT_DIR";
const SEV_GUEST: &str = "/dev/sev-guest";
const HOST_AMD_CERT: &str = "host-amd-cert-base64";
const REFERENCE_INFO: &str = "reference-info-base64";
const SECURITY_POLICY: &str = "security-policy-base64";

const ACCCACHE: &str = "https://global.acccache.azure.net/SevSnpVM/certificates";
const KDS: &str = "https://kdsintf.amd.com/vcek/v1";
/// Each VCEK fetch, whole exchange.
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// The security context directory: `UVM_SECURITY_CONTEXT_DIR`, else the one `/security-context-*` directory.
/// `None` when neither names exactly one directory.
pub(crate) fn security_context_dir() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os(SECURITY_CONTEXT_ENV).filter(|v| !v.is_empty()) {
        let dir = PathBuf::from(dir);
        return dir.is_dir().then_some(dir);
    }
    let mut dirs = std::fs::read_dir("/")
        .ok()?
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().starts_with("security-context-") && e.path().is_dir())
        .map(|e| e.path());
    match (dirs.next(), dirs.next()) {
        (Some(dir), None) => Some(dir),
        _ => None,
    }
}

/// Produces `Evidence::AzureSnpAci` (module docs).
pub struct SnpAciAttestor {
    device: ReportSource,
    context: SecurityContext,
    host_data: [u8; 32],
    vceks: VcekFetcher,
}

impl SnpAciAttestor {
    /// Reads the security context and takes one report for `host_data`. `Unavailable` when the device or the
    /// context is missing, or they disagree.
    pub fn new() -> Result<Self, TeeError> {
        let dir =
            security_context_dir().ok_or_else(|| TeeError::Unavailable("no ACI security context directory".into()))?;
        let vceks = VcekFetcher::new(Arc::new(seal_net::TcpDialer));
        Self::from_parts(ReportSource::Device, SecurityContext::load(&dir)?, vceks)
    }

    fn from_parts(device: ReportSource, context: SecurityContext, vceks: VcekFetcher) -> Result<Self, TeeError> {
        let report = Report::new(device.report([0; 64])?)?;
        let host_data = report.host_data();
        if host_data != context.policy_sha256 {
            return Err(TeeError::Unavailable(
                "the security context's policy does not hash to the report's host_data".into(),
            ));
        }
        Ok(Self { device, context, host_data, vceks })
    }

    /// This group's `host_data`: SHA-256 of its container policy.
    pub fn host_data(&self) -> [u8; 32] {
        self.host_data
    }

    /// `seal_attest::azure::measurement` of this group's `host_data`.
    pub fn measurement(&self) -> Measurement {
        seal_attest::azure::measurement(&self.host_data)
    }

    /// A fresh report committing to `report_data`, its VCEK and the UVM endorsement.
    pub(crate) async fn attest(&self, report_data: [u8; 32]) -> Result<Evidence, TeeError> {
        let mut data = [0u8; 64];
        data[..32].copy_from_slice(&report_data);
        let device = self.device.clone();
        let raw = tokio::task::spawn_blocking(move || device.report(data))
            .await
            .map_err(|e| TeeError::Unavailable(format!("report task: {e}")))??;
        let report = Report::new(raw)?;
        if report.report_data() != data {
            return Err(TeeError::Unavailable("the report does not carry the requested report data".into()));
        }
        if report.host_data() != self.host_data {
            return Err(TeeError::Unavailable("the report's host_data changed".into()));
        }
        let vcek_der = if report.reported_tcb() == self.context.host_vcek.tcbm {
            self.context.host_vcek.der.clone()
        } else {
            self.vceks.fetch(&report).await?
        };
        Ok(Evidence::AzureSnpAci { report: report.0, vcek_der, uvm_endorsement: self.context.endorsement.clone() })
    }
}

/// Where reports come from.
#[derive(Clone)]
enum ReportSource {
    /// `/dev/sev-guest`, opened per report.
    Device,
    /// A recorded report, whatever is asked (tests).
    #[cfg(test)]
    Recorded(Vec<u8>),
}

impl ReportSource {
    fn report(&self, data: [u8; 64]) -> Result<Vec<u8>, TeeError> {
        match self {
            ReportSource::Device => {
                let mut device = sev::firmware::guest::Firmware::open()
                    .map_err(|e| TeeError::Unavailable(format!("{SEV_GUEST}: {e}")))?;
                device
                    .get_report(None, Some(data), Some(0))
                    .map_err(|e| TeeError::Unavailable(format!("SNP_GET_REPORT: {e}")))
            }
            #[cfg(test)]
            ReportSource::Recorded(report) => {
                let _ = data;
                Ok(report.clone())
            }
        }
    }
}

/// The ATTESTATION_REPORT fields the attestor reads (AMD publication 56860); the verifier checks the rest.
struct Report(Vec<u8>);

impl Report {
    const LEN: usize = 0x4A0;

    fn new(raw: Vec<u8>) -> Result<Self, TeeError> {
        if raw.len() != Self::LEN {
            return Err(TeeError::Unavailable(format!("report is {} bytes, expected {}", raw.len(), Self::LEN)));
        }
        Ok(Self(raw))
    }
    fn version(&self) -> u32 {
        u32::from_le_bytes(self.0[0..4].try_into().expect("4 bytes"))
    }
    fn report_data(&self) -> [u8; 64] {
        self.0[0x50..0x90].try_into().expect("64 bytes")
    }
    fn host_data(&self) -> [u8; 32] {
        self.0[0xC0..0xE0].try_into().expect("32 bytes")
    }
    fn reported_tcb(&self) -> u64 {
        u64::from_le_bytes(self.0[0x180..0x188].try_into().expect("8 bytes"))
    }
    fn chip_id(&self) -> &[u8] {
        &self.0[0x1A0..0x1E0]
    }
    /// KDS's product name, from CPUID (report version 3 and later).
    fn product(&self) -> Option<Product> {
        if self.version() < 3 {
            return None;
        }
        match (self.0[0x188], self.0[0x189]) {
            (0x19, 0x00..=0x0F) => Some(Product::Milan),
            (0x19, 0x10..=0x1F | 0xA0..=0xAF) => Some(Product::Genoa),
            (0x1A, 0x00..=0x11) => Some(Product::Turin),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Product {
    Milan,
    Genoa,
    Turin,
}

impl Product {
    /// `<product>/<hwID>?<SPLs>` (AMD publication 57230). Turin's hwID is the first 8 bytes of CHIP_ID and its
    /// TCB starts with an FMC byte.
    fn kds_path(self, report: &Report) -> String {
        let b = report.reported_tcb().to_le_bytes();
        match self {
            Product::Milan | Product::Genoa => format!(
                "{self:?}/{}?blSPL={}&teeSPL={}&snpSPL={}&ucodeSPL={}",
                hex(report.chip_id()),
                b[0],
                b[1],
                b[6],
                b[7]
            ),
            Product::Turin => format!(
                "Turin/{}?fmcSPL={}&blSPL={}&teeSPL={}&snpSPL={}&ucodeSPL={}",
                hex(&report.chip_id()[..8]),
                b[0],
                b[1],
                b[2],
                b[3],
                b[7]
            ),
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The security context files the attestor reads.
struct SecurityContext {
    host_vcek: HostVcek,
    /// `reference-info-base64`, trimmed.
    endorsement: String,
    /// SHA-256 of the decoded `security-policy-base64`: the `host_data` ACI launched the group with.
    policy_sha256: [u8; 32],
}

impl SecurityContext {
    fn load(dir: &Path) -> Result<Self, TeeError> {
        let read = |name: &str| {
            std::fs::read_to_string(dir.join(name))
                .map_err(|e| TeeError::Unavailable(format!("security context {name}: {e}")))
        };
        let decode = |name: &str, text: &str| {
            base64::engine::general_purpose::STANDARD
                .decode(text.trim())
                .map_err(|_| TeeError::Unavailable(format!("security context {name} is not base64")))
        };
        let host_vcek = HostVcek::from_json(&decode(HOST_AMD_CERT, &read(HOST_AMD_CERT)?)?)
            .map_err(|e| TeeError::Unavailable(format!("security context {HOST_AMD_CERT}: {e}")))?;
        let endorsement = read(REFERENCE_INFO)?.trim().to_owned();
        decode(REFERENCE_INFO, &endorsement)?;
        let policy = decode(SECURITY_POLICY, &read(SECURITY_POLICY)?)?;
        Ok(Self { host_vcek, endorsement, policy_sha256: Sha256::digest(&policy).into() })
    }
}

/// A VCEK and the TCB it certifies, as THIM and Azure's certificate cache answer
/// (`{"vcekCert": PEM, "tcbm": hex, "certificateChain": PEM, ...}`).
struct HostVcek {
    der: Vec<u8>,
    tcbm: u64,
}

impl HostVcek {
    fn from_json(json: &[u8]) -> Result<Self, String> {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Answer {
            vcek_cert: String,
            tcbm: String,
        }
        let answer: Answer = serde_json::from_slice(json).map_err(|e| format!("not a VCEK answer: {e}"))?;
        let tcbm = u64::from_str_radix(answer.tcbm.trim(), 16).map_err(|_| "tcbm is not hex".to_owned())?;
        Ok(Self { der: first_pem_certificate(&answer.vcek_cert)?, tcbm })
    }
}

/// The DER of the first `CERTIFICATE` block of `pem`.
fn first_pem_certificate(pem: &str) -> Result<Vec<u8>, String> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let body = pem
        .split_once(BEGIN)
        .and_then(|(_, rest)| rest.split_once(END))
        .map(|(body, _)| body)
        .ok_or("no PEM certificate")?;
    let b64: String = body.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    base64::engine::general_purpose::STANDARD.decode(b64).map_err(|_| "PEM certificate is not base64".to_owned())
}

/// VCEKs for TCBs the security context does not cover.
struct VcekFetcher {
    https: seal_net::HttpsClient,
    /// The last fetched VCEK, by REPORTED_TCB.
    cached: Mutex<Option<(u64, Vec<u8>)>>,
}

impl VcekFetcher {
    fn new(dialer: Arc<dyn seal_net::Dialer>) -> Self {
        let connector = Arc::new(seal_net::BakedRootsConnector::new(dialer).with_time(crate::tls_time()));
        Self { https: seal_net::HttpsClient::new(connector), cached: Mutex::new(None) }
    }

    async fn fetch(&self, report: &Report) -> Result<Vec<u8>, TeeError> {
        let tcb = report.reported_tcb();
        if let Some((cached_tcb, der)) = self.cached.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
            if *cached_tcb == tcb {
                return Ok(der.clone());
            }
        }
        let der = match self.acccache(report).await {
            Ok(der) => der,
            Err(cache) => self.kds(report).await.map_err(|kds| {
                TeeError::Unavailable(format!("no VCEK for REPORTED_TCB {tcb:016x}: acccache: {cache}; KDS: {kds}"))
            })?,
        };
        *self.cached.lock().unwrap_or_else(|e| e.into_inner()) = Some((tcb, der.clone()));
        Ok(der)
    }

    /// The VCEK (DER) for the report's chip and TCB from Azure's certificate cache, which answers the PEM chain
    /// VCEK, ASK, ARK (`application/x-pem-file`, the TCB in a `TCBm` header).
    async fn acccache(&self, report: &Report) -> Result<Vec<u8>, String> {
        let chip = hex(report.chip_id());
        let url = format!("{ACCCACHE}/{chip}/{:x}?api-version=2020-10-15-preview", report.reported_tcb());
        let pem = String::from_utf8(self.get(&url).await?).map_err(|_| "answer is not PEM".to_owned())?;
        first_pem_certificate(&pem)
    }

    /// The VCEK (DER) for exactly the report's chip and TCB from AMD.
    async fn kds(&self, report: &Report) -> Result<Vec<u8>, String> {
        let product = report.product().ok_or("the report names no known product")?;
        self.get(&format!("{KDS}/{}", product.kds_path(report))).await
    }

    async fn get(&self, url: &str) -> Result<Vec<u8>, String> {
        let (status, body) = tokio::time::timeout(FETCH_TIMEOUT, self.https.get(url, &[]))
            .await
            .map_err(|_| "timed out".to_owned())?
            .map_err(|e| e.to_string())?;
        if status != 200 {
            return Err(format!("HTTP {status}"));
        }
        Ok(body)
    }
}

#[cfg(test)]
mod tests;
