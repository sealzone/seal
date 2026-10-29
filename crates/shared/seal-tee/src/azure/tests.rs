use seal_proto::TrustedTime;

use super::*;

/// 2026-10-26T07:33:20Z, as in seal-attest's vectors: every VCEK below is valid.
const NOW: TrustedTime = TrustedTime { now: 1_793_000_000, radius: 10 };

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// A security context directory under the temp dir, removed on drop.
struct ContextDir(PathBuf);

impl ContextDir {
    fn new(files: &[(&str, &str)]) -> Self {
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("seal-tee-security-context-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for (name, content) in files {
            std::fs::write(dir.join(name), content).unwrap();
        }
        Self(dir)
    }
}

impl Drop for ContextDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// One group's report and security context files (base64 text, as ACI writes them).
struct Sample {
    report: Vec<u8>,
    host_amd_cert: String,
    reference_info: String,
    security_policy: String,
    report_data: [u8; 32],
}

impl Sample {
    /// microsoft/confidential-sidecar-containers' production ACI sample (seal-attest's `tests/data/aci`).
    fn sidecar() -> Self {
        let data = |name: &str| format!("{}/../seal-attest/tests/data/aci/{name}", env!("CARGO_MANIFEST_DIR"));
        let read = |name: &str| std::fs::read(data(name)).unwrap();
        Self {
            report: read("snp_report.bin"),
            host_amd_cert: b64(&read("uvm_host_amd_certificate.json")),
            reference_info: b64(&read("body.uvm_reference_info.bin")),
            security_policy: String::from_utf8(read("uvm_security_policy.base64")).unwrap(),
            report_data: Report::new(read("snp_report.bin")).unwrap().report_data()[..32].try_into().unwrap(),
        }
    }

    /// Seal's own capture from a confidential container group in eastus (Genoa), the security context files
    /// byte for byte (seal-attest's `tests/data/aci-genoa`).
    fn genoa() -> Self {
        let data = |name: &str| format!("{}/../seal-attest/tests/data/aci-genoa/{name}", env!("CARGO_MANIFEST_DIR"));
        let text = |name: &str| std::fs::read_to_string(data(name)).unwrap();
        Self {
            report: std::fs::read(data("snp_report.bin")).unwrap(),
            host_amd_cert: text(HOST_AMD_CERT),
            reference_info: text(REFERENCE_INFO),
            security_policy: text(SECURITY_POLICY),
            report_data: capture_report_data(),
        }
    }

    fn dir(&self) -> ContextDir {
        ContextDir::new(&[
            (HOST_AMD_CERT, &self.host_amd_cert),
            (REFERENCE_INFO, &self.reference_info),
            (SECURITY_POLICY, &self.security_policy),
        ])
    }

    fn attestor(&self, dialer: Arc<dyn seal_net::Dialer>) -> Result<SnpAciAttestor, TeeError> {
        let context = SecurityContext::load(&self.dir().0)?;
        SnpAciAttestor::from_parts(ReportSource::Recorded(self.report.clone()), context, VcekFetcher::new(dialer))
    }

    fn policy_sha256(&self) -> [u8; 32] {
        let policy = base64::engine::general_purpose::STANDARD.decode(self.security_policy.trim()).unwrap();
        Sha256::digest(policy).into()
    }
}

/// Refuses every connection and records what was dialed.
#[derive(Default)]
struct RefusingDialer(Mutex<Vec<String>>);

#[async_trait::async_trait]
impl seal_net::Dialer for RefusingDialer {
    async fn dial(&self, host: &str, port: u16) -> Result<seal_net::BoxStream, seal_net::NetError> {
        self.0.lock().unwrap().push(format!("{host}:{port}"));
        Err(seal_net::NetError::Connect { host: host.into(), port, reason: "refused".into() })
    }
}

fn offline() -> Arc<RefusingDialer> {
    Arc::new(RefusingDialer::default())
}

#[track_caller]
fn assert_unavailable<T>(result: Result<T, TeeError>, needle: &str) {
    match result {
        Err(TeeError::Unavailable(e)) => assert!(e.contains(needle), "{e:?} does not mention {needle:?}"),
        Err(e) => panic!("expected Unavailable mentioning {needle:?}, got {e}"),
        Ok(_) => panic!("expected Unavailable mentioning {needle:?}"),
    }
}

#[tokio::test]
async fn sidecar_sample_assembles_verifiable_evidence() {
    let sample = Sample::sidecar();
    let dialer = offline();
    let attestor = sample.attestor(dialer.clone()).unwrap();
    assert_eq!(attestor.measurement(), seal_attest::azure::measurement(&sample.policy_sha256()));

    let evidence = attestor.attest(sample.report_data).await.unwrap();
    let Evidence::AzureSnpAci { report, vcek_der, uvm_endorsement } = &evidence else { panic!("not Azure evidence") };
    assert_eq!(report, &sample.report);
    assert_eq!(uvm_endorsement, &sample.reference_info);
    assert_eq!(vcek_der[0], 0x30, "DER");
    let verified = seal_attest::verify(&evidence, &NOW).unwrap();
    assert_eq!(verified.platform, seal_proto::PlatformId::AzureSnpAci);
    assert_eq!(verified.measurement, attestor.measurement());
    assert_eq!(verified.report_data, sample.report_data);
    assert!(dialer.0.lock().unwrap().is_empty(), "the security context's VCEK matches: no fetch");
}

/// When the Genoa capture was taken (2026-10-27T05:43:04Z).
const CAPTURED_AT: TrustedTime = TrustedTime { now: 1_793_079_784, radius: 10 };

#[tokio::test]
async fn genoa_capture_assembles_verifiable_evidence() {
    let sample = Sample::genoa();
    let dialer = offline();
    let attestor = sample.attestor(dialer.clone()).unwrap();
    // host_data is SHA-256 of the policy ACI was given: the release's measurement is fixed by its policy.
    assert_eq!(hex(&attestor.host_data), "202896786ffa17822b3af330287de59f1aa4af02dd5742c298fbd0fcac96382f");
    assert_eq!(attestor.host_data, sample.policy_sha256());
    assert_eq!(
        attestor.measurement().to_string(),
        "12535fb627f062c16aa7e8d9f4568ffd90eb1eba61b11115c1cb0412664d129a59f11bbb9ed911810ab059d3d3cb9038"
    );

    let evidence = attestor.attest(sample.report_data).await.unwrap();
    let verified = seal_attest::verify(&evidence, &CAPTURED_AT).unwrap();
    assert_eq!(verified.measurement, attestor.measurement());
    assert_eq!(verified.report_data, capture_report_data());
    let tcb =
        [("genoa.bootloader", 10), ("genoa.tee", 0), ("genoa.snp", 23), ("genoa.microcode", 84), ("uvm_svn", 104)];
    assert_eq!(verified.tcb.0, tcb.into_iter().map(|(k, v)| (k.to_owned(), v)).collect());
    assert!(dialer.0.lock().unwrap().is_empty());

    // The VCEK KDS issued for the same chip and TCB (the fallback's last source) verifies as well.
    let Evidence::AzureSnpAci { report, uvm_endorsement, .. } = evidence else { panic!("not Azure evidence") };
    let kds_vcek =
        std::fs::read(format!("{}/../seal-attest/tests/data/aci-genoa/kds_vcek.der", env!("CARGO_MANIFEST_DIR")))
            .unwrap();
    let from_kds = Evidence::AzureSnpAci { report, vcek_der: kds_vcek, uvm_endorsement };
    assert_eq!(seal_attest::verify(&from_kds, &CAPTURED_AT).unwrap(), verified);
}

#[test]
fn genoa_capture_names_its_kds_vcek() {
    let report = Report::new(Sample::genoa().report).unwrap();
    assert_eq!(report.product(), Some(Product::Genoa));
    assert_eq!(
        Product::Genoa.kds_path(&report),
        "Genoa/e9643dd07596742d8279a90e51708add785d0c047cbf69448f3d1a47b62936ad39dad2d9b56bf7ee1a1d3159d5a265c6\
         5dddd9735e45e61540af9241c9c06eb8?blSPL=10&teeSPL=0&snpSPL=23&ucodeSPL=84"
    );
}

#[tokio::test]
async fn report_without_the_requested_data_is_refused() {
    let attestor = Sample::sidecar().attestor(offline()).unwrap();
    assert_unavailable(attestor.attest([0; 32]).await, "requested report data");
}

#[test]
fn policy_must_hash_to_host_data() {
    let mut sample = Sample::sidecar();
    sample.security_policy = b64(b"package policy\n");
    assert_unavailable(sample.attestor(offline()), "does not hash to the report's host_data");
}

#[test]
fn report_must_have_the_abi_length() {
    let mut sample = Sample::sidecar();
    sample.report.truncate(0x2A0);
    assert_unavailable(sample.attestor(offline()), "expected 1184");
}

#[test]
fn security_context_files_are_checked() {
    let sample = Sample::sidecar();
    for missing in [HOST_AMD_CERT, REFERENCE_INFO, SECURITY_POLICY] {
        let dir = sample.dir();
        std::fs::remove_file(dir.0.join(missing)).unwrap();
        assert_unavailable(SecurityContext::load(&dir.0), missing);
    }
    for (file, content, needle) in [
        (HOST_AMD_CERT, "not base64!", "is not base64"),
        (REFERENCE_INFO, "not base64!", "is not base64"),
        (SECURITY_POLICY, "not base64!", "is not base64"),
        (HOST_AMD_CERT, &b64(b"{}"), "not a VCEK answer"),
        (HOST_AMD_CERT, &b64(br#"{"vcekCert":"x","tcbm":"zz"}"#), "tcbm is not hex"),
        (HOST_AMD_CERT, &b64(br#"{"vcekCert":"x","tcbm":"00"}"#), "no PEM certificate"),
    ] {
        let dir = sample.dir();
        std::fs::write(dir.0.join(file), content).unwrap();
        assert_unavailable(SecurityContext::load(&dir.0), needle);
    }
}

#[tokio::test]
async fn other_tcb_fetches_the_vcek_from_the_cache_then_kds() {
    let sample = Sample::sidecar();
    let dialer = offline();
    let mut attestor = sample.attestor(dialer.clone()).unwrap();
    attestor.context.host_vcek.tcbm ^= 1;
    assert_unavailable(attestor.attest(sample.report_data).await, "no VCEK for REPORTED_TCB 7308000000000003");
    assert_eq!(*dialer.0.lock().unwrap(), ["global.acccache.azure.net:443"], "a version-2 report names no KDS product");

    // A cached VCEK for the report's TCB is used without a fetch.
    let der = attestor.context.host_vcek.der.clone();
    *attestor.vceks.cached.lock().unwrap() = Some((0x7308000000000003, der));
    seal_attest::verify(&attestor.attest(sample.report_data).await.unwrap(), &NOW).unwrap();
    assert_eq!(dialer.0.lock().unwrap().len(), 1);
}

#[test]
fn kds_paths_per_product() {
    // CCF's version-2 Milan report: the URL its VCEK in seal-attest's `tests/data/kds` was fetched from.
    let report = |name: &str| {
        let path = format!("{}/../seal-attest/tests/data/ccf/{name}", env!("CARGO_MANIFEST_DIR"));
        Report::new(std::fs::read(path).unwrap()).unwrap()
    };
    let v2 = report("v2_format_milan_attestation.bin");
    assert_eq!(v2.product(), None);
    assert_eq!(
        Product::Milan.kds_path(&v2),
        "Milan/dc7e37cc9b95b4d072ec4c6ebcabeaf98a6655b2e692768f9eb79e0fe1fa9d6c70b1d0a251757dcd48b360d660f89bbf\
         228ef9f99003014c6d534a681473ea07?blSPL=3&teeSPL=0&snpSPL=8&ucodeSPL=115"
    );
    assert_eq!(report("milan_attestation.bin").product(), Some(Product::Milan));
    assert_eq!(report("genoa_attestation.bin").product(), Some(Product::Genoa));
    let turin = report("turin_attestation.bin");
    assert_eq!(turin.product(), Some(Product::Turin));
    let path = Product::Turin.kds_path(&turin);
    let (hwid, spls) = path.strip_prefix("Turin/").unwrap().split_once('?').unwrap();
    assert_eq!(hwid, hex(&turin.chip_id()[..8]));
    assert!(spls.starts_with("fmcSPL="), "{spls}");
}

#[test]
fn first_pem_certificate_of_a_chain() {
    let pem = |body: &str| format!("-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n");
    let chain = format!("{}{}", pem("AQID"), pem("BAUG"));
    assert_eq!(first_pem_certificate(&chain).unwrap(), [1, 2, 3]);
    assert!(first_pem_certificate(&pem("AQ\nID")).is_ok(), "line breaks inside the body");
    assert!(first_pem_certificate("AQID").is_err());
    assert!(first_pem_certificate(&pem("!!")).is_err());
}

/// Report data of the live capture: SHA-256 of `seal-dev-azure capture`.
fn capture_report_data() -> [u8; 32] {
    Sha256::digest(b"seal-dev-azure capture").into()
}

/// Runs inside an ACI confidential container group (`--ignored live_capture --nocapture`): prints the security
/// context, the evidence for `capture_report_data` and what each VCEK source answers, one JSON object per line.
#[tokio::test]
#[ignore = "needs an ACI confidential container group"]
async fn live_capture() {
    let dir = security_context_dir().expect("security context");
    for entry in std::fs::read_dir(&dir).unwrap() {
        let entry = entry.unwrap();
        let text = std::fs::read_to_string(entry.path()).unwrap();
        let file = serde_json::json!({ "file": entry.file_name().to_string_lossy(), "content": text.trim() });
        println!("CAPTURE {file}");
    }
    let attestor = SnpAciAttestor::new().unwrap();
    let evidence = attestor.attest(capture_report_data()).await.unwrap();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let verified = seal_attest::verify(&evidence, &seal_proto::TrustedTime { now, radius: 300 });
    let summary = serde_json::json!({
        "host_data": hex(&attestor.host_data),
        "measurement": attestor.measurement().to_string(),
        "captured_at": now,
        "verified": format!("{verified:?}"),
    });
    println!("CAPTURE {summary}");
    println!("CAPTURE {}", serde_json::json!({ "evidence": evidence }));

    let Evidence::AzureSnpAci { report, .. } = &evidence else { panic!("not Azure evidence") };
    let report = Report::new(report.clone()).unwrap();
    let time = seal_proto::TrustedTime { now, radius: 300 };
    let with_vcek = |vcek_der: Vec<u8>| {
        let Evidence::AzureSnpAci { report, uvm_endorsement, .. } = evidence.clone() else { unreachable!() };
        let encoded = base64_der(&vcek_der);
        let verified = seal_attest::verify(&Evidence::AzureSnpAci { report, vcek_der, uvm_endorsement }, &time);
        (encoded, verified.is_ok())
    };
    let cache = attestor.vceks.acccache(&report).await.map(with_vcek);
    let kds = attestor.vceks.kds(&report).await.map(with_vcek);
    let sources = serde_json::json!({
        "acccache": format!("{cache:?}"),
        "kds": format!("{kds:?}"),
        "kds_path": report.product().map(|p| p.kds_path(&report)),
    });
    println!("CAPTURE {sources}");
}

fn base64_der(der: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(der)
}
