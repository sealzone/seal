//! Seal wire types.
//!
//! This crate is the contract between every Seal component. It holds data
//! only: no IO, no crypto, no async. Every type that is hashed or signed has a
//! single canonical encoding, `codec::canonical` (deterministic CBOR), so two
//! components can never disagree on the bytes behind a signature.
//!
//! Rule for all types here: maps are `BTreeMap`/`BTreeSet`, never `HashMap`,
//! and struct field order is part of the format.

#![forbid(unsafe_code)]

pub mod api;
pub mod blob;
pub mod codec;
pub mod control;
pub mod error;
pub mod evidence;
pub mod freshness;
pub mod identity;
pub mod ids;
pub mod integrity;
pub mod net;
pub mod policy;
pub mod release;
pub mod secret;
pub mod session;
pub mod signed;
pub mod state;
pub mod telemetry;
pub mod time;
pub mod tunnel;

pub use error::{ErrorCode, ProtoError};
pub use evidence::Evidence;
pub use ids::{
    AppName, BlobId, KeyId, Measurement, PlatformId, PublicKey, ServiceKeyVersion, TenantId, TenantKeyVersion,
    TenantPin, TenantRootId, UnixTime,
};
pub use secret::{Bearer, SecretVec};
pub use time::TrustedTime;
