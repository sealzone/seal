//! Telemetry as a reader checks it (`seal telemetry`, the web UI): batches verified against
//! the telemetry keys of guardian-certified `ServiceKeyCertificate`s, sealed ones opened with a
//! reader key, and everything the control plane may have withheld reported.

use std::collections::BTreeMap;

use serde::Serialize;

use seal_crypto::sign::{key_id, verify};
use seal_crypto::telemetry::{open_entries, TelemetryReaderKey};
use seal_proto::api::TelemetryReceipt;
use seal_proto::codec;
use seal_proto::release::{ReleaseConstraints, SignedServiceKeyCertificate};
use seal_proto::telemetry::{
    SignedTelemetryBatch, TelemetryBatch, TelemetryEntries, TelemetryEntry, TELEMETRY_BATCH_LABEL,
};
use seal_proto::{PlatformId, PublicKey, TenantId, TenantRootId, UnixTime};

/// Something a reader should know about the telemetry it was shown. Streams serialize as
/// base64url, like `TelemetryBatch::stream`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Finding {
    /// Certificate `index` was not used: another tenant or chain, or it did not verify.
    CertificateIgnored { index: usize, reason: String },
    /// A batch for another tenant, dropped.
    OtherTenant {
        #[serde(with = "codec::array_b64")]
        stream: [u8; 16],
        sequence: u64,
    },
    /// A batch no certified telemetry key signed, dropped.
    NotCertified {
        #[serde(with = "codec::array_b64")]
        stream: [u8; 16],
        sequence: u64,
    },
    /// Two different signed batches with one sequence.
    Equivocation {
        #[serde(with = "codec::array_b64")]
        stream: [u8; 16],
        sequence: u64,
    },
    /// Batches `from..to` of the stream are missing.
    MissingBatches {
        #[serde(with = "codec::array_b64")]
        stream: [u8; 16],
        from: u64,
        to: u64,
    },
    /// The batch's entry numbers do not follow on from the batch before.
    EntryGap {
        #[serde(with = "codec::array_b64")]
        stream: [u8; 16],
        sequence: u64,
        first_entry: u64,
        expected: u64,
    },
    /// A batch sealed to the reader whose entries do not open.
    Unopened {
        #[serde(with = "codec::array_b64")]
        stream: [u8; 16],
        sequence: u64,
        error: String,
    },
    /// No `last` batch: the replica is still running, or died and lost up to one buffer.
    NoLast {
        #[serde(with = "codec::array_b64")]
        stream: [u8; 16],
    },
    /// A kept receipt whose entry no verified batch holds: withheld, or before `since`.
    ReceiptNotHeld {
        #[serde(with = "codec::array_b64")]
        stream: [u8; 16],
        entry: u64,
    },
}

/// A verified entry, clear or opened.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Entry {
    #[serde(with = "codec::array_b64")]
    pub stream: [u8; 16],
    /// Its number in the stream.
    pub number: u64,
    pub entry: TelemetryEntry,
}

/// A verified sealed batch that was not opened.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Sealed {
    #[serde(with = "codec::array_b64")]
    pub stream: [u8; 16],
    pub sequence: u64,
    pub count: u32,
}

/// What `analyze` found.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Analysis {
    /// In stream and entry order.
    pub entries: Vec<Entry>,
    pub sealed: Vec<Sealed>,
    pub findings: Vec<Finding>,
}

/// The telemetry public keys still in force (`telemetry_keys_in_force` under `policy`, the
/// release constraints of a checkpoint the caller verified) of every certificate that verifies
/// under `guardians` (`verify_service_certificate`) and is for `tenant` and `root_id`; the
/// others, and certificates of a retired service key version, are findings. Batches signed by
/// a retired version's key are then refused whenever they are dated: nothing records when the
/// version was retired, and a batch's dates are its signer's own. Without a policy, each
/// certificate counts only its own version's key.
pub fn certified_keys(
    guardians: &BTreeMap<PlatformId, PublicKey>,
    tenant: &TenantId,
    root_id: &TenantRootId,
    certificates: &[SignedServiceKeyCertificate],
    policy: Option<&ReleaseConstraints>,
) -> (Vec<PublicKey>, Vec<Finding>) {
    let mut keys = Vec::new();
    let mut findings = Vec::new();
    for (index, cert) in certificates.iter().enumerate() {
        match crate::verify_service_certificate(guardians, cert) {
            Ok(body) if &body.tenant == tenant && &body.root_id == root_id => {
                let floor = crate::telemetry_floor(body, policy);
                if body.service_key_version < floor {
                    let reason =
                        format!("service key version {} is retired (below {})", body.service_key_version.0, floor.0);
                    findings.push(Finding::CertificateIgnored { index, reason });
                    continue;
                }
                for key in crate::telemetry_keys_in_force(body, policy) {
                    if !keys.contains(&key) {
                        keys.push(key);
                    }
                }
            }
            Ok(_) => {
                findings.push(Finding::CertificateIgnored { index, reason: "for another tenant or root chain".into() })
            }
            Err(e) => findings.push(Finding::CertificateIgnored { index, reason: e.to_string() }),
        }
    }
    (keys, findings)
}

fn signed_by(keys: &[PublicKey], batch: &SignedTelemetryBatch) -> bool {
    batch.signatures.iter().any(|sig| {
        keys.iter()
            .find(|k| key_id(k) == sig.signer)
            .is_some_and(|k| verify(k, TELEMETRY_BATCH_LABEL, &batch.body, sig).is_ok())
    })
}

/// Verifies `batches` with `keys` and reports, per stream: sequence gaps (and a missing start
/// when `since` is 0), batches whose entry numbers do not follow on, two different batches
/// with one sequence, and a stream without a `last` batch; also receipts naming an entry no
/// verified batch holds. Batches that do not verify or are for another tenant are dropped and
/// reported. Sealed batches are opened with `reader` when they are sealed to it; one that is
/// but does not open is reported.
pub fn analyze(
    tenant: &TenantId,
    keys: &[PublicKey],
    batches: &[SignedTelemetryBatch],
    since: UnixTime,
    receipts: &[TelemetryReceipt],
    reader: Option<&TelemetryReaderKey>,
) -> Analysis {
    let mut out = Analysis::default();
    let mut streams: BTreeMap<[u8; 16], BTreeMap<u64, &TelemetryBatch>> = BTreeMap::new();
    for batch in batches {
        let body = &batch.body;
        let (stream, sequence) = (body.stream, body.sequence);
        if &body.tenant != tenant {
            out.findings.push(Finding::OtherTenant { stream, sequence });
            continue;
        }
        if !signed_by(keys, batch) {
            out.findings.push(Finding::NotCertified { stream, sequence });
            continue;
        }
        let seen = streams.entry(stream).or_default();
        match seen.get(&sequence) {
            Some(existing) if *existing != body => out.findings.push(Finding::Equivocation { stream, sequence }),
            Some(_) => {}
            None => {
                seen.insert(sequence, body);
            }
        }
    }
    for (&stream, batches) in &streams {
        let mut previous: Option<&TelemetryBatch> = None;
        for batch in batches.values() {
            match previous {
                None if since == 0 && batch.sequence != 0 => {
                    out.findings.push(Finding::MissingBatches { stream, from: 0, to: batch.sequence });
                }
                Some(p) if batch.sequence != p.sequence + 1 => {
                    out.findings.push(Finding::MissingBatches { stream, from: p.sequence + 1, to: batch.sequence });
                }
                Some(p) if batch.first_entry != p.first_entry + u64::from(p.count) => {
                    out.findings.push(Finding::EntryGap {
                        stream,
                        sequence: batch.sequence,
                        first_entry: batch.first_entry,
                        expected: p.first_entry + u64::from(p.count),
                    });
                }
                _ => {}
            }
            let number = |i: usize| batch.first_entry + i as u64;
            match &batch.entries {
                TelemetryEntries::Clear { entries } => {
                    for (i, entry) in entries.iter().enumerate() {
                        out.entries.push(Entry { stream, number: number(i), entry: entry.clone() });
                    }
                }
                TelemetryEntries::Sealed { readers, .. } => {
                    let reader = reader.filter(|r| readers.iter().any(|slot| slot.reader == r.public_key()));
                    let sealed = Sealed { stream, sequence: batch.sequence, count: batch.count };
                    match reader.map(|r| open_entries(r, batch)) {
                        Some(Ok(entries)) => {
                            for (i, entry) in entries.into_iter().enumerate() {
                                out.entries.push(Entry { stream, number: number(i), entry });
                            }
                        }
                        Some(Err(e)) => {
                            let sequence = batch.sequence;
                            out.findings.push(Finding::Unopened { stream, sequence, error: e.to_string() });
                            out.sealed.push(sealed);
                        }
                        None => out.sealed.push(sealed),
                    }
                }
            }
            previous = Some(batch);
        }
        if !batches.values().any(|b| b.last) {
            out.findings.push(Finding::NoLast { stream });
        }
    }
    for receipt in receipts {
        let held = streams.get(&receipt.stream).is_some_and(|batches| {
            batches.values().any(|b| (b.first_entry..b.first_entry + u64::from(b.count)).contains(&receipt.entry))
        });
        if !held {
            out.findings.push(Finding::ReceiptNotHeld { stream: receipt.stream, entry: receipt.entry });
        }
    }
    out
}
