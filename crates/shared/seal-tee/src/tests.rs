use crate::detect::{choose, Device, Probe};
use crate::TeeError;

#[test]
fn no_device_is_not_in_tee() {
    assert!(matches!(choose(&Probe::default()), Err(TeeError::NotInTee)));
    // The SNP device alone is not ACI: Confidential Space on SNP has it too.
    let snp_only = Probe { sev_guest: true, ..Probe::default() };
    assert!(matches!(choose(&snp_only), Err(TeeError::NotInTee)));
}

#[test]
fn devices_in_documented_order() {
    let all = Probe { sim: false, sev_guest: true, aci_security_context: true, nsm: true, launcher_socket: true };
    assert_eq!(choose(&all).unwrap(), Device::SevGuestAci);
    assert_eq!(choose(&Probe { aci_security_context: false, ..all }).unwrap(), Device::Nsm);
    let gcp_on_snp = Probe { sev_guest: true, launcher_socket: true, ..Probe::default() };
    assert_eq!(choose(&gcp_on_snp).unwrap(), Device::LauncherSocket);
    assert_eq!(choose(&Probe { sim: true, ..all }).unwrap(), Device::Sim);
}

#[test]
fn detect_on_this_host_does_not_panic() {
    // Test hosts have no TEE device; `SEAL_SIM` is unset unless a sim build selects it.
    match crate::Attestor::detect() {
        Err(TeeError::NotInTee) => {}
        #[cfg(feature = "sim")]
        Ok(a) => assert_eq!(a.platform(), seal_proto::PlatformId::Sim),
        #[cfg(not(feature = "sim"))]
        Ok(_) => panic!("a TEE attestor on a test host"),
        Err(e) => panic!("unexpected: {e}"),
    }
}

#[cfg(feature = "sim")]
mod sim {
    use seal_proto::{Evidence, Measurement, TrustedTime};

    use crate::sim::{SimAttestor, SystemClock};
    use crate::{Attestor, Clock};

    #[tokio::test]
    async fn sim_evidence_verifies() {
        let measurement = Measurement([7; 48]);
        let attestor = Attestor::Sim(SimAttestor::new(measurement));
        assert_eq!(attestor.platform(), seal_proto::PlatformId::Sim);
        assert_eq!(attestor.measurement(), measurement);
        let evidence = attestor.attest([9; 32]).await.unwrap();
        let verified = seal_attest::verify(&evidence, &TrustedTime::exact(0)).unwrap();
        assert_eq!(verified.platform, seal_proto::PlatformId::Sim);
        assert_eq!(verified.measurement, measurement);
        assert_eq!(verified.report_data, [9; 32]);
        assert!(verified.tcb.0.is_empty());
        assert_eq!(verified.deployment, None);

        let Evidence::Sim { mut document } = evidence else { panic!("not sim evidence") };
        let last = document.len() - 1;
        document[last] ^= 1;
        assert!(seal_attest::verify(&Evidence::Sim { document }, &TrustedTime::exact(0)).is_err());
    }

    #[test]
    fn running_binary_measurement() {
        let a = SimAttestor::of_running_binary().unwrap();
        assert_eq!(a.measurement(), SimAttestor::of_running_binary().unwrap().measurement());
        assert_ne!(a.measurement(), Measurement([0; 48]));
    }

    #[tokio::test]
    async fn clock_offset() {
        let system = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let base = Clock::System(SystemClock::new(0)).now().await.unwrap();
        assert_eq!(base.radius, 0);
        assert!(base.now.abs_diff(system) <= 1);
        let ahead = Clock::System(SystemClock::new(86_400)).now().await.unwrap();
        assert!(ahead.now.abs_diff(system + 86_400) <= 1);
        let behind = Clock::System(SystemClock::new(-3_600)).now().await.unwrap();
        assert!(behind.now.abs_diff(system - 3_600) <= 1);
        assert!(Clock::System(SystemClock::new(i64::MIN)).now().await.is_err());
    }
}
