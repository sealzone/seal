//! napi-rs bindings over the Rust SDK (`seal::Client`), as the native addon of the npm package
//! `@sealzone/sdk`. The JavaScript surface (`Client`, the sessions, the identities, the
//! errors) is in `index.js` and calls into this addon.
//!
//! Every SDK future runs on napi's tokio runtime and comes back as a Promise. Errors reject
//! with `[seal:<code>] <message>`, which `errors.js` turns into the `SealError` subclass for
//! that `ErrorCode`; callbacks the app passes (`reloadWith`, `onReseal`, `endpointReporter`)
//! answer in the same vocabulary, as JSON (`session::reply`).

extern crate seal_client as seal;

use napi::{Error, Status};
use napi_derive::napi;
use seal::ClientError;
use serde::de::DeserializeOwned;
use serde::Serialize;

mod client;
mod session;
mod types;

/// Where `[seal:<code>]` starts an error message from this addon.
const TAG: &str = "[seal:";

/// The JavaScript error for `e`: its wire code and message, read back by `errors.js`.
pub(crate) fn error(e: ClientError) -> Error {
    let code = e.code();
    let message = match e {
        ClientError::Seal { message, .. } => message,
        other => other.to_string(),
    };
    Error::new(Status::GenericFailure, format!("{TAG}{}] {message}", code.as_str()))
}

/// A serde enum from its wire name (`"high"`, `"hardened"`).
pub(crate) fn parse<T: DeserializeOwned>(text: &str) -> Result<T, ClientError> {
    serde_json::from_value(serde_json::Value::String(text.to_owned()))
        .map_err(|_| ClientError::Invalid(format!("unknown value {text:?}")))
}

/// A serde enum's wire name.
pub(crate) fn wire_name<T: Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(s)) => s,
        _ => String::new(),
    }
}

/// Whether this build talks to the simulator (`--features sim`).
#[napi]
pub const SIM: bool = cfg!(feature = "sim");

/// Whether this build has AWS workload identity (`--features aws`).
#[napi]
pub const AWS: bool = cfg!(feature = "aws");

#[cfg(test)]
mod tests {
    use super::*;
    use seal::ErrorCode;

    #[test]
    fn wire_names_round_trip() {
        assert_eq!(wire_name(&seal::Severity::High), "high");
        assert_eq!(parse::<seal::Severity>("critical").unwrap(), seal::Severity::Critical);
        assert_eq!(parse::<seal::ConsumerTier>("hardened").unwrap(), seal::ConsumerTier::Hardened);
        assert_eq!(parse::<ErrorCode>("session_ended").unwrap(), ErrorCode::SessionEnded);
        assert!(matches!(parse::<seal::Severity>("High"), Err(ClientError::Invalid(_))));
        assert_eq!(wire_name(&seal::Protocol::ClickHouse), "click_house");
    }

    #[test]
    fn errors_carry_their_code() {
        let e = error(ClientError::Seal { code: ErrorCode::NotAllowed, message: "not in apps".into() });
        assert_eq!(e.reason, "[seal:not_allowed] not in apps");
        let e = error(ClientError::Network("refused".into()));
        assert_eq!(e.reason, "[seal:unavailable] network: refused");
    }
}
