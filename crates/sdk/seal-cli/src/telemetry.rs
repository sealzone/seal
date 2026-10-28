//! `seal telemetry`: verifies batches against telemetry keys from guardian-certified
//! `ServiceKeyCertificate`s, opens sealed ones with a reader key, and reports what the control
//! plane may have withheld (`seal_verify::telemetry`, which the web UI runs too), one line per
//! finding.

use std::collections::BTreeMap;

use seal_crypto::telemetry::TelemetryReaderKey;
use seal_proto::api::TelemetryReceipt;
use seal_proto::identity::WorkloadIdentity;
use seal_proto::release::SignedServiceKeyCertificate;
use seal_proto::telemetry::{SignedTelemetryBatch, TelemetryEntry};
use seal_proto::{PlatformId, PublicKey, TenantId, TenantRootId, UnixTime};
use seal_verify::telemetry::Finding;

use crate::config::hex;

/// The telemetry public keys of every certificate that verifies under `guardians` and is for
/// `tenant` and `root_id`; the rest are listed in the returned findings.
pub fn certified_keys(
    guardians: &BTreeMap<PlatformId, PublicKey>,
    tenant: &TenantId,
    root_id: &TenantRootId,
    certificates: &[SignedServiceKeyCertificate],
) -> (Vec<PublicKey>, Vec<String>) {
    let (keys, findings) = seal_verify::telemetry::certified_keys(guardians, tenant, root_id, certificates);
    (keys, findings.iter().map(line).collect())
}

/// What `analyze` found.
#[derive(Debug, Default)]
pub struct Analysis {
    /// Verified entries, clear or opened, in stream and entry order: (stream, entry number, entry).
    pub entries: Vec<([u8; 16], u64, TelemetryEntry)>,
    /// Verified sealed batches not opened: (stream, sequence, entry count).
    pub sealed: Vec<([u8; 16], u64, u32)>,
    pub findings: Vec<String>,
}

/// `seal_verify::telemetry::analyze`, with each finding as one line.
pub fn analyze(
    tenant: &TenantId,
    keys: &[PublicKey],
    batches: &[SignedTelemetryBatch],
    since: UnixTime,
    receipts: &[TelemetryReceipt],
    reader: Option<&TelemetryReaderKey>,
) -> Analysis {
    let a = seal_verify::telemetry::analyze(tenant, keys, batches, since, receipts, reader);
    Analysis {
        entries: a.entries.into_iter().map(|e| (e.stream, e.number, e.entry)).collect(),
        sealed: a.sealed.into_iter().map(|s| (s.stream, s.sequence, s.count)).collect(),
        findings: a.findings.iter().map(line).collect(),
    }
}

/// One line for a finding.
fn line(finding: &Finding) -> String {
    match finding {
        Finding::CertificateIgnored { index, reason } => format!("certificate {index}: {reason}: ignored"),
        Finding::OtherTenant { stream, sequence } => {
            format!("stream {} batch {sequence}: for another tenant, dropped", hex(stream))
        }
        Finding::NotCertified { stream, sequence } => {
            format!("stream {} batch {sequence}: not signed by a certified telemetry key, dropped", hex(stream))
        }
        Finding::Equivocation { stream, sequence } => {
            format!("stream {} batch {sequence}: two different signed batches with this sequence", hex(stream))
        }
        Finding::MissingBatches { stream, from, to } => format!("stream {}: batches {from}..{to} missing", hex(stream)),
        Finding::EntryGap { stream, sequence, first_entry, expected } => {
            format!("stream {}: batch {sequence} starts at entry {first_entry}, expected {expected}", hex(stream))
        }
        Finding::Unopened { stream, sequence, error } => {
            format!("stream {} batch {sequence}: sealed entries do not open: {error}", hex(stream))
        }
        Finding::NoLast { stream } => format!(
            "stream {}: no last batch (still running, or its replica died and lost up to one buffer)",
            hex(stream)
        ),
        Finding::ReceiptNotHeld { stream, entry } => format!(
            "receipt for stream {} entry {entry}: no verified batch holds it (withheld, or before --since)",
            hex(stream)
        ),
    }
}

/// A short form of an identity for one telemetry line.
pub fn who(identity: Option<&WorkloadIdentity>) -> String {
    match identity {
        None => "enclave".into(),
        Some(WorkloadIdentity::Azure { object_id, .. }) => format!("azure:{object_id}"),
        Some(WorkloadIdentity::AwsRole { role_arn, .. }) => format!("aws:{role_arn}"),
        Some(WorkloadIdentity::Kubernetes { namespace, service_account, .. }) => {
            format!("k8s:{namespace}/{service_account}")
        }
        Some(WorkloadIdentity::Gcp { email, .. }) => format!("gcp:{email}"),
        Some(WorkloadIdentity::GitHub { repository, environment, git_ref, .. }) => match environment {
            Some(e) => format!("github:{repository}@environment:{e}"),
            None => format!("github:{repository}@ref:{git_ref}"),
        },
        Some(WorkloadIdentity::AppKey { key_id }) => format!("app-key:{key_id}"),
        Some(WorkloadIdentity::ConfidentialSpace { project_number, service_account }) => {
            format!("confidential-space:{project_number}/{service_account}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seal_crypto::sign::SigningKey;
    use seal_proto::telemetry::{TelemetryBatch, TelemetryEntries, TelemetryEvent, TELEMETRY_BATCH_LABEL};

    fn acme() -> TenantId {
        TenantId::new("acme").unwrap()
    }

    fn batch(
        key: &SigningKey,
        stream: u8,
        sequence: u64,
        first_entry: u64,
        count: u32,
        last: bool,
    ) -> SignedTelemetryBatch {
        let entries = (0..count)
            .map(|_| TelemetryEntry {
                at: 100,
                tenant: acme(),
                identity: None,
                event: TelemetryEvent::Dropped { requests: 1, other: 0 },
            })
            .collect();
        key.sign_into(
            TELEMETRY_BATCH_LABEL,
            TelemetryBatch {
                tenant: acme(),
                stream: [stream; 16],
                sequence,
                first_entry,
                count,
                from: 100,
                to: 100,
                entries: TelemetryEntries::Clear { entries },
                last,
            },
        )
    }

    #[test]
    fn complete_streams_have_no_findings() {
        let key = SigningKey::from_seed(&[1; 32]);
        let batches = [batch(&key, 1, 0, 0, 2, false), batch(&key, 1, 1, 2, 1, true)];
        let receipts = [TelemetryReceipt { stream: [1; 16], entry: 2 }];
        let a = analyze(&acme(), &[key.public_key()], &batches, 0, &receipts, None);
        assert!(a.findings.is_empty(), "{:?}", a.findings);
        assert_eq!(a.entries.iter().map(|e| e.1).collect::<Vec<_>>(), [0, 1, 2]);
    }

    #[test]
    fn gaps_cut_streams_forgeries_and_withheld_receipts_are_reported() {
        let key = SigningKey::from_seed(&[1; 32]);
        let forger = SigningKey::from_seed(&[2; 32]);
        let batches = [
            batch(&key, 1, 0, 0, 1, false),
            batch(&key, 1, 2, 5, 1, true),
            batch(&key, 2, 1, 3, 1, false),
            batch(&forger, 3, 0, 0, 1, true),
        ];
        let receipts = [TelemetryReceipt { stream: [1; 16], entry: 2 }, TelemetryReceipt { stream: [9; 16], entry: 0 }];
        let a = analyze(&acme(), &[key.public_key()], &batches, 0, &receipts, None);
        let f = a.findings.join("\n");
        assert!(f.contains("batch 0: not signed by a certified telemetry key"), "{f}");
        assert!(f.contains(&format!("stream {}: batches 1..2 missing", hex(&[1; 16]))), "{f}");
        assert!(f.contains(&format!("stream {}: batches 0..1 missing", hex(&[2; 16]))), "{f}");
        assert!(f.contains(&format!("stream {}: no last batch", hex(&[2; 16]))), "{f}");
        assert!(f.contains(&format!("receipt for stream {} entry 2", hex(&[1; 16]))), "{f}");
        assert!(f.contains(&format!("receipt for stream {} entry 0", hex(&[9; 16]))), "{f}");
        assert_eq!(a.findings.len(), 6, "{f}");
    }

    /// `batch` with its entries sealed to `readers`, signed by `key`.
    fn sealed(key: &SigningKey, sequence: u64, first_entry: u64, readers: &[PublicKey]) -> SignedTelemetryBatch {
        let mut body = batch(key, 1, sequence, first_entry, 2, sequence == 1).body;
        let TelemetryEntries::Clear { entries } = &body.entries else { unreachable!() };
        let mut rng = seal_crypto::UnwrapErr(seal_crypto::SysRng);
        let stream = body.stream;
        body.entries =
            seal_crypto::telemetry::seal_entries(&acme(), stream, sequence, first_entry, entries, readers, &mut rng)
                .unwrap();
        key.sign_into(TELEMETRY_BATCH_LABEL, body)
    }

    #[test]
    fn sealed_batches_open_with_the_reader_key() {
        let key = SigningKey::from_seed(&[1; 32]);
        let reader = TelemetryReaderKey::from_seed(&[3; 32]);
        let other = TelemetryReaderKey::from_seed(&[4; 32]);
        let batches = [sealed(&key, 0, 0, &[reader.public_key()]), sealed(&key, 1, 2, &[other.public_key()])];

        let a = analyze(&acme(), &[key.public_key()], &batches, 0, &[], Some(&reader));
        assert!(a.findings.is_empty(), "{:?}", a.findings);
        assert_eq!(a.entries.iter().map(|e| e.1).collect::<Vec<_>>(), [0, 1]);
        assert_eq!(a.sealed, [([1; 16], 1, 2)], "not sealed to this reader");

        let a = analyze(&acme(), &[key.public_key()], &batches, 0, &[], None);
        assert!(a.entries.is_empty());
        assert_eq!(a.sealed.len(), 2);

        // Sealed to the reader, but the ciphertext was altered before signing.
        let mut broken = sealed(&key, 0, 0, &[reader.public_key()]).body;
        let TelemetryEntries::Sealed { ciphertext, .. } = &mut broken.entries else { unreachable!() };
        ciphertext[0] ^= 1;
        let broken = key.sign_into(TELEMETRY_BATCH_LABEL, broken);
        let a = analyze(&acme(), &[key.public_key()], &[broken], 0, &[], Some(&reader));
        assert!(a.findings.iter().any(|f| f.contains("batch 0: sealed entries do not open")), "{:?}", a.findings);
        assert_eq!(a.sealed.len(), 1);
    }

    #[test]
    fn a_later_since_does_not_flag_the_start() {
        let key = SigningKey::from_seed(&[1; 32]);
        let a = analyze(&acme(), &[key.public_key()], &[batch(&key, 1, 4, 9, 1, true)], 50, &[], None);
        assert!(a.findings.is_empty(), "{:?}", a.findings);
    }
}
