//! The log's checkpoint policy (`ReleaseConstraints`, `PUT /v1/policy` on the log), checked
//! before it is set. Floors only rise and witnesses refuse anything looser, so a mistake in
//! one lasts: every `min_tcb` component must be one its platform's evidence carries
//! (`seal_attest::check_floor`; Azure hardware components are per chip family, `milan.snp`),
//! and the policy must not loosen the log's current one.

use anyhow::{anyhow, bail};
use seal_proto::release::ReleaseConstraints;

/// `policy` names only components its platforms' evidence carries and, given the log's
/// current policy, does not loosen it.
pub fn check(policy: &ReleaseConstraints, current: Option<&ReleaseConstraints>) -> anyhow::Result<()> {
    for (platform, floor) in &policy.min_tcb {
        seal_attest::check_floor(*platform, floor).map_err(|e| anyhow!("min_tcb: {e}"))?;
    }
    if current.is_some_and(|current| !seal_tlog::policy_not_loosened(current, policy)) {
        bail!("the policy loosens the log's current one");
    }
    Ok(())
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
        check(&p, None).unwrap();
        check(&p, Some(&ReleaseConstraints::default())).unwrap();
        check(&ReleaseConstraints::default(), Some(&ReleaseConstraints::default())).unwrap();
    }

    #[test]
    fn unknown_components_and_loosening_are_refused() {
        let bare = policy(r#"{"min_service_key_version": {}, "min_tcb": {"azure_snp_aci": {"snp": 24}}}"#);
        assert!(check(&bare, None).unwrap_err().to_string().contains("snp"));
        let nitro = policy(r#"{"min_service_key_version": {}, "min_tcb": {"aws_nitro": {"uvm_svn": 1}}}"#);
        assert!(check(&nitro, None).is_err());
        let set = policy(r#"{"min_service_key_version": {}, "min_tcb": {"azure_snp_aci": {"milan.snp": 24}}}"#);
        let lower = policy(r#"{"min_service_key_version": {}, "min_tcb": {"azure_snp_aci": {"milan.snp": 23}}}"#);
        assert!(check(&lower, Some(&set)).unwrap_err().to_string().contains("loosens"));
    }
}
