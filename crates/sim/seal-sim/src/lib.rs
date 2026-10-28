//! The local simulator harness (feature `sim`; without it only the app and its HTTP client).
//!
//! Seal's own binaries run unchanged as processes on localhost; this crate supplies what a
//! real deployment gets from elsewhere: dev release keys and a dev log holding the release
//! they approved, a guardian root, a test CA, every configuration file (`setup`), the
//! untrusted TLS proxy in front of the guardian and an HTTPS test upstream (`net`), Postgres
//! and Redis upstreams in containers (`postgres`, `redis`), and the app that uses a blob through the enclave
//! (`app`). The `seal-sim` binary exposes each piece for `scripts/sim-demo.sh` and the
//! end-to-end tests (`tests/e2e/` at the repository root); `tests/host_agent.rs` drives them
//! in-process. The app and the HTTP client it uses (`app`, `net` without its servers) build
//! without the feature too, so `seal-release` runs the same flows over a production SDK client
//! against a live deployment.
#![forbid(unsafe_code)]

extern crate seal_client as seal;

pub mod app;
#[cfg(feature = "sim")]
pub mod container;
pub mod net;
#[cfg(feature = "sim")]
pub mod postgres;
#[cfg(feature = "sim")]
pub mod redis;
#[cfg(feature = "sim")]
pub mod setup;
