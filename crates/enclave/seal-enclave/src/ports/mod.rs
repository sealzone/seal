//! Production implementations of the runtime ports, over the two Seal services an enclave
//! talks to:
//!
//! | Port | Implementation | Service |
//! | --- | --- | --- |
//! | `KeyProvider` | `guardian::GuardianKeyProvider` | `seal_guardian::client::GuardianClient` |
//! | `TenantStore` | `control::ControlTenantStore` | `seal_control::client::ControlClient` |
//! | `ReleaseStore` | `control::ControlReleaseStore` | `seal_control::client::ControlClient` |
//! | `Telemetry` | `telemetry::ControlTelemetry` | `seal_control::client::ControlClient` |
//!
//! Both services are reached over `seal_net::HttpsClient` through the cloud's dialer. Everything
//! they return is untrusted: the runtime verifies documents with `seal-verify`, and key
//! responses are accepted only when the guardian key signed them for the exact request
//! and they carry exactly the requested scope.

pub mod control;
pub mod guardian;
pub mod telemetry;
