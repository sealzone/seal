//! Being a TEE: producing evidence about this process (`Attestor`) and time the host cannot
//! rewind (`Clock`). Used by the enclave and the guardian, never by the SDK; checking
//! evidence is `seal-attest`.
//!
//! One enclave image runs on every cloud, so every attestor is compiled in and
//! `Attestor::detect` picks the one whose TEE device is present. Each refuses to start
//! outside its TEE. The set is closed: dispatch is a `match`, not a trait object.
//!
//! The SNP guest-device ioctl goes through `sev` (`/dev/sev-guest`), so this crate has no
//! `unsafe` of its own.
#![forbid(unsafe_code)]

use seal_proto::{Evidence, Measurement, PlatformId, TrustedTime};

pub mod azure;
pub mod gcp;
pub mod nitro;
pub mod roughtime;
#[cfg(feature = "sim")]
pub mod sim;

#[derive(Debug, thiserror::Error)]
pub enum TeeError {
    /// No supported TEE device is present.
    #[error("not running in a supported TEE")]
    NotInTee,
    #[error("unavailable: {0}")]
    Unavailable(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl TeeError {
    /// The public code: the TEE or a service it needs could not be reached.
    pub fn code(&self) -> seal_proto::ErrorCode {
        seal_proto::ErrorCode::Unavailable
    }
}

/// Produces evidence for the TEE this process runs in.
pub enum Attestor {
    AzureSnpAci(azure::SnpAciAttestor),
    AwsNitro(nitro::NitroAttestor),
    GcpConfidentialSpace(gcp::ConfidentialSpaceAttestor),
    #[cfg(feature = "sim")]
    Sim(sim::SimAttestor),
}

impl Attestor {
    /// By device, in this order: `/dev/sev-guest` with the ACI security context
    /// (`UVM_SECURITY_CONTEXT_DIR`, else exactly one `/security-context-*` directory) (Azure),
    /// `/dev/nsm` (Nitro, which this build refuses with `Unavailable`), the Confidential Space
    /// launcher socket `/run/container_launcher/teeserver.sock` (GCP). `NotInTee` when none is
    /// present.
    ///
    /// A `sim` build with `SEAL_SIM=1` set returns the simulator instead, measuring the
    /// running binary (see `sim`). Other builds ignore the variable.
    pub fn detect() -> Result<Self, TeeError> {
        match detect::choose(&detect::Probe::host())? {
            detect::Device::SevGuestAci => Ok(Attestor::AzureSnpAci(azure::SnpAciAttestor::new()?)),
            detect::Device::Nsm => Ok(Attestor::AwsNitro(nitro::NitroAttestor::new()?)),
            detect::Device::LauncherSocket => {
                Ok(Attestor::GcpConfidentialSpace(gcp::ConfidentialSpaceAttestor::new()?))
            }
            #[cfg(feature = "sim")]
            detect::Device::Sim => Ok(Attestor::Sim(sim::SimAttestor::of_running_binary()?)),
            #[cfg(not(feature = "sim"))]
            detect::Device::Sim => Err(TeeError::NotInTee),
        }
    }
    pub fn platform(&self) -> PlatformId {
        match self {
            Attestor::AzureSnpAci(_) => PlatformId::AzureSnpAci,
            Attestor::AwsNitro(_) => PlatformId::AwsNitro,
            Attestor::GcpConfidentialSpace(_) => PlatformId::GcpConfidentialSpace,
            #[cfg(feature = "sim")]
            Attestor::Sim(_) => PlatformId::Sim,
        }
    }
    /// This TEE's own measurement, as `seal_attest::verify` computes it.
    pub fn measurement(&self) -> Measurement {
        match self {
            Attestor::AzureSnpAci(a) => a.measurement(),
            Attestor::AwsNitro(a) => a.measurement(),
            Attestor::GcpConfidentialSpace(a) => a.measurement(),
            #[cfg(feature = "sim")]
            Attestor::Sim(a) => a.measurement(),
        }
    }
    /// Evidence committing to `report_data`.
    pub async fn attest(&self, report_data: [u8; 32]) -> Result<Evidence, TeeError> {
        match self {
            Attestor::AzureSnpAci(a) => a.attest(report_data).await,
            Attestor::AwsNitro(a) => a.attest(report_data).await,
            Attestor::GcpConfidentialSpace(a) => a.attest(report_data).await,
            #[cfg(feature = "sim")]
            Attestor::Sim(a) => Ok(a.attest(report_data)),
        }
    }
}

/// Time the host cannot rewind. See `TrustedTime` for which end each check uses.
pub enum Clock {
    /// Azure, GCP and every guardian.
    Roughtime(roughtime::RoughtimeClock),
    /// AWS Nitro: the hypervisor's signed attestation timestamp, no network.
    Nitro(nitro::NitroClock),
    #[cfg(feature = "sim")]
    System(sim::SystemClock),
}

impl Clock {
    pub async fn now(&self) -> Result<TrustedTime, TeeError> {
        match self {
            Clock::Roughtime(c) => c.now().await,
            Clock::Nitro(clock) => clock.now().await,
            #[cfg(feature = "sim")]
            Clock::System(c) => c.now(),
        }
    }
}

mod detect {
    use std::path::Path;

    use crate::TeeError;

    /// What `choose` found, in probing order.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Device {
        Sim,
        SevGuestAci,
        Nsm,
        LauncherSocket,
    }

    /// What `Attestor::detect` looks at on the host.
    #[derive(Clone, Copy, Debug, Default)]
    pub(crate) struct Probe {
        /// A `sim` build with `SEAL_SIM=1`.
        pub sim: bool,
        pub sev_guest: bool,
        pub aci_security_context: bool,
        pub nsm: bool,
        pub launcher_socket: bool,
    }

    impl Probe {
        pub fn host() -> Self {
            Self {
                sim: cfg!(feature = "sim") && std::env::var_os("SEAL_SIM").is_some_and(|v| v == "1"),
                sev_guest: Path::new("/dev/sev-guest").exists(),
                aci_security_context: crate::azure::security_context_dir().is_some(),
                nsm: Path::new("/dev/nsm").exists(),
                launcher_socket: Path::new(crate::gcp::TEESERVER_SOCKET).exists(),
            }
        }
    }

    pub(crate) fn choose(probe: &Probe) -> Result<Device, TeeError> {
        if probe.sim {
            Ok(Device::Sim)
        } else if probe.sev_guest && probe.aci_security_context {
            Ok(Device::SevGuestAci)
        } else if probe.nsm {
            Ok(Device::Nsm)
        } else if probe.launcher_socket {
            Ok(Device::LauncherSocket)
        } else {
            Err(TeeError::NotInTee)
        }
    }
}

#[cfg(test)]
mod tests;
