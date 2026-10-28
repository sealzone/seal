//! `trust.json`: the `seal_verify::Trust` of a release environment as JSON, the same shape the
//! enclave and guardian release configurations embed and `seal --trust` reads.

use std::collections::BTreeMap;

use anyhow::{anyhow, bail, Context as _};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use seal_proto::{PlatformId, PublicKey};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TlogTrust {
    origin: String,
    log_key: PublicKey,
    witness_keys: Vec<PublicKey>,
    witness_quorum: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseTrust {
    tlog: TlogTrust,
    release_keys: Vec<PublicKey>,
    release_threshold: usize,
    #[serde(default)]
    required_auditor: Option<PublicKey>,
    time_lock_secs: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantTrust {
    tlog: TlogTrust,
    registrar_keys: Vec<PublicKey>,
    registrar_threshold: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Trust {
    releases: ReleaseTrust,
    tenants: TenantTrust,
    #[serde(default)]
    guardians: BTreeMap<PlatformId, PublicKey>,
}

fn tlog(t: TlogTrust) -> seal_tlog::TlogTrust {
    seal_tlog::TlogTrust {
        origin: t.origin,
        log_key: t.log_key,
        witness_keys: t.witness_keys,
        witness_quorum: t.witness_quorum,
    }
}

/// Parses `trust.json`.
pub fn parse(text: &[u8]) -> anyhow::Result<seal_verify::Trust> {
    let t: Trust = serde_json::from_slice(text).context("trust")?;
    Ok(seal_verify::Trust {
        releases: seal_verify::ReleaseTrust {
            tlog: tlog(t.releases.tlog),
            release_keys: t.releases.release_keys,
            release_threshold: t.releases.release_threshold,
            required_auditor: t.releases.required_auditor,
            time_lock_secs: t.releases.time_lock_secs,
        },
        tenants: seal_verify::TenantTrust {
            tlog: tlog(t.tenants.tlog),
            registrar_keys: t.tenants.registrar_keys,
            registrar_threshold: t.tenants.registrar_threshold,
        },
        guardians: t.guardians,
    })
}

/// The log as `seal-tlog-dev` prints it on start (`origin`, `log key`, `witness key` lines,
/// `witness quorum`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LogInfo {
    pub origin: String,
    pub log_key: PublicKey,
    pub witness_keys: Vec<PublicKey>,
    pub witness_quorum: usize,
}

impl LogInfo {
    pub fn parse(printed: &str) -> anyhow::Result<Self> {
        let (mut origin, mut log_key, mut witness_keys, mut quorum) = (None, None, Vec::new(), None);
        for line in printed.lines() {
            let key = |s: &str| s.trim().parse::<PublicKey>().map_err(|e| anyhow!("{line:?}: {e}"));
            if let Some(v) = line.strip_prefix("origin ") {
                origin = Some(v.trim().to_owned());
            } else if let Some(v) = line.strip_prefix("log key ") {
                log_key = Some(key(v)?);
            } else if let Some(v) = line.strip_prefix("witness key ") {
                witness_keys.push(key(v)?);
            } else if let Some(v) = line.strip_prefix("witness quorum ") {
                quorum = Some(v.trim().parse().with_context(|| format!("{line:?}"))?);
            }
        }
        let info = Self {
            origin: origin.ok_or_else(|| anyhow!("no origin line"))?,
            log_key: log_key.ok_or_else(|| anyhow!("no log key line"))?,
            witness_keys,
            witness_quorum: quorum.ok_or_else(|| anyhow!("no witness quorum line"))?,
        };
        if info.witness_quorum == 0 || info.witness_quorum > info.witness_keys.len() {
            bail!("witness quorum {} of {} witnesses", info.witness_quorum, info.witness_keys.len());
        }
        Ok(info)
    }
}

/// `trust.json` for one log serving both releases and tenants.
pub fn build(
    log: &LogInfo,
    release_keys: &[PublicKey],
    release_threshold: usize,
    registrar_keys: &[PublicKey],
    time_lock_secs: u64,
    guardians: &BTreeMap<PlatformId, PublicKey>,
) -> anyhow::Result<Value> {
    if release_threshold == 0 || release_threshold > release_keys.len() {
        bail!("release threshold {release_threshold} of {} keys", release_keys.len());
    }
    if registrar_keys.is_empty() {
        bail!("no registrar key");
    }
    let tlog = serde_json::to_value(log)?;
    let value = json!({
        "releases": {
            "tlog": tlog,
            "release_keys": release_keys,
            "release_threshold": release_threshold,
            "required_auditor": null,
            "time_lock_secs": time_lock_secs,
        },
        "tenants": {"tlog": tlog, "registrar_keys": registrar_keys, "registrar_threshold": 1},
        "guardians": guardians,
    });
    parse(value.to_string().as_bytes())?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRINTED: &str = "origin dev.log.seal.zone/v1\nlog key 0101010101010101010101010101010101010101010101010101010101010101\n\
        witness key 0202020202020202020202020202020202020202020202020202020202020202\n\
        witness key 0303030303030303030303030303030303030303030303030303030303030303\nwitness quorum 2\nlistening on 0.0.0.0:7300\n";

    #[test]
    fn trust_from_the_log_and_keys() {
        let log = LogInfo::parse(PRINTED).unwrap();
        assert_eq!(log.witness_keys.len(), 2);
        let k = |b: u8| PublicKey([b; 32]);
        let guardians = BTreeMap::from([(PlatformId::GcpConfidentialSpace, k(9))]);
        let value = build(&log, &[k(4), k(5), k(6)], 2, &[k(7)], 60, &guardians).unwrap();
        let trust = parse(value.to_string().as_bytes()).unwrap();
        assert_eq!(trust.releases.release_threshold, 2);
        assert_eq!(trust.releases.time_lock_secs, 60);
        assert_eq!(trust.tenants.tlog.origin, "dev.log.seal.zone/v1");
        assert_eq!(trust.guardians[&PlatformId::GcpConfidentialSpace], k(9));
        assert!(build(&log, &[k(4)], 2, &[k(7)], 0, &guardians).is_err());
        assert!(LogInfo::parse("origin x\nwitness quorum 1\n").is_err());
    }

    /// Every release configuration in `deploy/example` embeds `trust.json`. The guardians'
    /// own configurations predate their keys (the root ceremony runs their image), so only the
    /// enclave's names them.
    #[test]
    fn example_configs_share_one_trust() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../deploy/example");
        let read = |file: &str| -> Value {
            serde_json::from_str(&std::fs::read_to_string(format!("{dir}/{file}")).unwrap()).unwrap()
        };
        let trust = read("trust.json");
        parse(trust.to_string().as_bytes()).unwrap();
        assert_eq!(read("enclave.json")["trust"], trust);
        for file in ["guardian-gcp.json", "guardian-azure.json"] {
            let config = read(file);
            assert_eq!(config["trust"]["releases"], trust["releases"], "{file}");
            assert_eq!(config["trust"]["tenants"], trust["tenants"], "{file}");
        }
    }
}
