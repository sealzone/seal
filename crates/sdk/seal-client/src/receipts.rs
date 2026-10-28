//! Telemetry receipts kept by clients, in the file format `seal telemetry --receipts` reads.
//!
//! `SealBuilder::with_receipt` and `Session::receipts` hand them out; a client that keeps them
//! can prove the control plane withheld their entries, even a whole stream.

use std::io::Write as _;
use std::path::Path;

pub use seal_proto::api::TelemetryReceipt;

/// Appends `receipts` to `path` as JSON lines, one `TelemetryReceipt` each, creating the file
/// when it is missing. One write per call, so processes appending to one file keep whole lines.
pub fn append(path: impl AsRef<Path>, receipts: &[TelemetryReceipt]) -> std::io::Result<()> {
    let mut lines = Vec::new();
    for receipt in receipts {
        serde_json::to_writer(&mut lines, receipt)?;
        lines.push(b'\n');
    }
    if lines.is_empty() {
        return Ok(());
    }
    std::fs::OpenOptions::new().create(true).append(true).open(path)?.write_all(&lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appends_json_lines() {
        let path = std::env::temp_dir().join(format!("seal-receipts-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let a = TelemetryReceipt { stream: [1; 16], entry: 2 };
        let b = TelemetryReceipt { stream: [3; 16], entry: 4 };
        append(&path, &[a]).unwrap();
        append(&path, &[]).unwrap();
        append(&path, &[b, a]).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let read: Vec<TelemetryReceipt> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(read, [a, b, a]);
        std::fs::remove_file(&path).unwrap();
    }
}
