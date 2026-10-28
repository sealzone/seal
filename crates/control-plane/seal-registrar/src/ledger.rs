//! The registrar's own record of every root version 1 it signed: an append-only JSON-lines
//! file, replayed at start. The last line for a tenant wins (the same root, later with its log
//! index). It is what makes "one root version 1 per tenant" hold even if the control plane
//! loses data.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

use seal_proto::signed::Signed;
use seal_proto::state::TenantRoot;
use seal_proto::TenantId;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Record {
    pub tenant: TenantId,
    pub root: Signed<TenantRoot>,
    /// Set once the root is in the log.
    pub log_index: Option<u64>,
}

pub struct Ledger {
    file: File,
    records: BTreeMap<TenantId, Record>,
}

impl Ledger {
    /// Opens (or creates) `path` and replays it. Every record is written as one line ending in
    /// `\n`, so bytes after the last `\n` are a torn write (a crash mid-append): they are cut
    /// off, so the next record starts on a line of its own. Any complete line that does not
    /// parse is an error.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let text = match std::fs::read(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e),
        };
        let complete = text.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
        let mut records = BTreeMap::new();
        for (i, line) in text[..complete].split_inclusive(|&b| b == b'\n').enumerate() {
            let rec: Record = serde_json::from_slice(line)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("line {}: {e}", i + 1)))?;
            records.insert(rec.tenant.clone(), rec);
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        if complete < text.len() {
            tracing::warn!("cutting off a torn last ledger line");
            file.set_len(complete as u64)?;
            file.sync_data()?;
        }
        Ok(Self { file, records })
    }

    pub fn get(&self, tenant: &TenantId) -> Option<&Record> {
        self.records.get(tenant)
    }

    /// Appends and syncs before returning.
    pub fn record(
        &mut self,
        tenant: &TenantId,
        root: &Signed<TenantRoot>,
        log_index: Option<u64>,
    ) -> std::io::Result<()> {
        let rec = Record { tenant: tenant.clone(), root: root.clone(), log_index };
        let mut line = serde_json::to_vec(&rec)?;
        line.push(b'\n');
        self.file.write_all(&line)?;
        self.file.sync_data()?;
        self.records.insert(tenant.clone(), rec);
        Ok(())
    }
}
