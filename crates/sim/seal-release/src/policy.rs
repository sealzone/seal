//! The log's checkpoint policy (`ReleaseConstraints`, `PUT /v1/policy` on the log), checked
//! before it is set. Floors only rise and witnesses refuse anything looser, so a mistake in
//! one lasts: every `min_tcb` component must be one its platform's evidence carries
//! (`seal_attest::check_floor`; Azure hardware components are per chip family, `milan.snp`),
//! and the policy must not loosen the log's current one.
//!
//! Service keys depend on the platform, tenant, root and service key version, never on the
//! build or the hardware that received them. So revoking a measurement or raising a platform's
//! `min_tcb` stops new releases of keys but not use of keys already released: a revocation
//! there must also raise the platform's `min_service_key_version` (to a version a release
//! already serves past its time lock), unless the operator says no released key is suspect
//! (`keep_service_keys`).

use anyhow::{anyhow, bail};
use seal_proto::release::ReleaseConstraints;

/// `policy` names only components its platforms' evidence carries and, given the log's
/// current policy, does not loosen it, and retires the service keys of every platform whose
/// measurements it revokes or whose floor it raises, unless `keep_service_keys`.
pub fn check(
    policy: &ReleaseConstraints,
    current: Option<&ReleaseConstraints>,
    keep_service_keys: bool,
) -> anyhow::Result<()> {
    for (platform, floor) in &policy.min_tcb {
        seal_attest::check_floor(*platform, floor).map_err(|e| anyhow!("min_tcb: {e}"))?;
    }
    let Some(current) = current else { return Ok(()) };
    if !seal_tlog::policy_not_loosened(current, policy) {
        bail!("the policy loosens the log's current one");
    }
    if keep_service_keys {
        return Ok(());
    }
    for platform in revoking(current, policy) {
        if policy.min_service_key_version.get(&platform) <= current.min_service_key_version.get(&platform) {
            bail!(
                "the policy revokes measurements or raises min_tcb on {platform:?} but keeps its service keys: \
                 raise min_service_key_version too, or pass --keep-service-keys if no released key is suspect"
            );
        }
    }
    Ok(())
}

/// Platforms on which `policy` revokes a measurement or raises the TCB floor.
fn revoking(current: &ReleaseConstraints, policy: &ReleaseConstraints) -> Vec<seal_proto::PlatformId> {
    let mut platforms: Vec<_> = policy
        .revoked_measurements
        .iter()
        .filter(|(p, ms)| current.revoked_measurements.get(p).is_none_or(|was| !ms.is_subset(was)))
        .map(|(p, _)| *p)
        .chain(policy.min_tcb.iter().filter(|(p, floor)| current.min_tcb.get(p) != Some(floor)).map(|(p, _)| *p))
        .collect();
    platforms.sort();
    platforms.dedup();
    platforms
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(json: &str) -> ReleaseConstraints {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn family_floors_check_out() {
        let p = policy(
            r#"{"min_service_key_version": {}, "min_tcb": {"azure_snp_aci":
                {"milan.snp": 24, "genoa.snp": 23, "turin.fmc": 1, "uvm_svn": 100},
                "gcp_confidential_space": {"cs_stable": 1}}}"#,
        );
        check(&p, None, false).unwrap();
        check(&p, Some(&ReleaseConstraints::default()), true).unwrap();
        check(&ReleaseConstraints::default(), Some(&ReleaseConstraints::default()), false).unwrap();
    }

    #[test]
    fn unknown_components_and_loosening_are_refused() {
        let bare = policy(r#"{"min_service_key_version": {}, "min_tcb": {"azure_snp_aci": {"snp": 24}}}"#);
        assert!(check(&bare, None, false).unwrap_err().to_string().contains("snp"));
        let nitro = policy(r#"{"min_service_key_version": {}, "min_tcb": {"aws_nitro": {"uvm_svn": 1}}}"#);
        assert!(check(&nitro, None, false).is_err());
        let set = policy(r#"{"min_service_key_version": {}, "min_tcb": {"azure_snp_aci": {"milan.snp": 24}}}"#);
        let lower = policy(r#"{"min_service_key_version": {}, "min_tcb": {"azure_snp_aci": {"milan.snp": 23}}}"#);
        assert!(check(&lower, Some(&set), true).unwrap_err().to_string().contains("loosens"));
    }

    #[test]
    fn revoking_needs_a_service_key_version_bump() {
        let none = ReleaseConstraints::default();
        let floor = policy(r#"{"min_service_key_version": {}, "min_tcb": {"azure_snp_aci": {"genoa.snp": 23}}}"#);
        assert!(check(&floor, Some(&none), false).unwrap_err().to_string().contains("--keep-service-keys"));
        check(&floor, Some(&none), true).unwrap();
        let bumped = policy(
            r#"{"min_service_key_version": {"azure_snp_aci": 2}, "min_tcb": {"azure_snp_aci": {"genoa.snp": 23}}}"#,
        );
        check(&bumped, Some(&none), false).unwrap();
        // Unchanged floors and revocations already in force need nothing more.
        check(&floor, Some(&floor), false).unwrap();
        let mut revoked = none.clone();
        revoked
            .revoked_measurements
            .entry(seal_proto::PlatformId::AzureSnpAci)
            .or_default()
            .insert(seal_proto::Measurement([7; 48]));
        assert!(check(&revoked, Some(&none), false).is_err());
        check(&revoked, Some(&revoked), false).unwrap();
    }
}
