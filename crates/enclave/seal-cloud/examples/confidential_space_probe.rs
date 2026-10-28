//! Runs the GCP cloud inside a live Confidential Space container and prints what it finds, for
//! recording test vectors (`seal-attest/tests/data/gcp/README.md`). Never part of an image
//! Seal ships. Each line starts with `SEAL_PROBE`; the token is printed in 1000-character
//! lines, since container log lines are split at 16 KiB.
//!
//! The report data is the bytes 0, 1, …, 31, so the token's nonce is
//! `000102…1f`.

use seal_cloud::Cloud;
use seal_proto::TrustedTime;
use seal_tee::Attestor;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::main]
async fn main() {
    println!("SEAL_PROBE SEAL_TENANT={:?}", std::env::var("SEAL_TENANT"));
    let attestor = match Attestor::detect() {
        Ok(a) => a,
        Err(e) => {
            println!("SEAL_PROBE detect failed: {e}");
            return;
        }
    };
    println!("SEAL_PROBE platform {:?} measurement {}", attestor.platform(), hex(&attestor.measurement().0));
    let report_data: [u8; 32] = std::array::from_fn(|i| i as u8);
    match attestor.attest(report_data).await {
        Ok(evidence) => {
            if let seal_proto::Evidence::GcpConfidentialSpace { token } = &evidence {
                println!("SEAL_PROBE token length {}", token.len());
                for (i, line) in token.as_bytes().chunks(1000).enumerate() {
                    println!("SEAL_PROBE token {} {}", i + 1, String::from_utf8_lossy(line));
                }
                println!("SEAL_PROBE token end");
            }
            let system = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
            match seal_attest::verify(&evidence, &TrustedTime { now: system, radius: 5 }) {
                Ok(v) => println!(
                    "SEAL_PROBE verified at system time: measurement {} report_data {} tcb {:?} deployment {:?}",
                    hex(&v.measurement.0),
                    hex(&v.report_data),
                    v.tcb,
                    v.deployment
                ),
                Err(e) => println!("SEAL_PROBE verify at system time: {e}"),
            }
        }
        Err(e) => println!("SEAL_PROBE attest failed: {e}"),
    }
    let cloud = match Cloud::detect() {
        Ok(c) => c,
        Err(e) => {
            println!("SEAL_PROBE Cloud::detect failed: {e}");
            return;
        }
    };
    println!("SEAL_PROBE tenant pin {}", cloud.tenant_pin());
    match cloud.clock().now().await {
        Ok(t) => println!("SEAL_PROBE roughtime {} ± {}", t.now, t.radius),
        Err(e) => println!("SEAL_PROBE roughtime: {e}"),
    }
    match cloud.deployment(&Default::default()).await {
        Ok(seal_authz::DeploymentProof::Attested(id)) => println!("SEAL_PROBE deployment {id:?}"),
        Ok(seal_authz::DeploymentProof::Proof(_)) => println!("SEAL_PROBE deployment: a proof, not attested"),
        Err(e) => println!("SEAL_PROBE deployment: {e}"),
    }
}
