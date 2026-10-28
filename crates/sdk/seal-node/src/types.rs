//! The SDK's data as JavaScript values: session info and receipts. Plain objects;
//! `index.js` gives them their classes.

use napi::bindgen_prelude::spawn_blocking;
use napi::Error;
use napi_derive::napi;
use seal::ClientError;
use seal_proto::codec;

use crate::wire_name;

/// `session.info`: the session's id, tiers, tenant, app, blob id and expiry.
#[napi(object)]
pub struct SessionInfo {
    /// base64url, as telemetry shows it.
    pub session_id: String,
    /// `sim` or `sealed`.
    pub platform: String,
    /// `base` or `hardened`.
    pub tier: String,
    pub tenant: String,
    pub app: String,
    pub blob_id: String,
    /// Unix seconds.
    pub expires_at: i64,
}

impl From<&seal::SessionInfo> for SessionInfo {
    fn from(info: &seal::SessionInfo) -> Self {
        Self {
            session_id: codec::b64url(&info.session_id),
            platform: wire_name(&info.platform),
            tier: wire_name(&info.tier),
            tenant: info.tenant.to_string(),
            app: info.app.to_string(),
            blob_id: info.blob_id.to_string(),
            expires_at: i64::try_from(info.expires_at).unwrap_or(i64::MAX),
        }
    }
}

/// Where telemetry recorded a seal or a session start: the stream (16 bytes, base64url, as
/// the receipts file writes it) and the entry.
#[napi(object)]
pub struct TelemetryReceipt {
    pub stream: String,
    pub entry: i64,
}

impl From<seal::TelemetryReceipt> for TelemetryReceipt {
    fn from(r: seal::TelemetryReceipt) -> Self {
        Self { stream: codec::b64url(&r.stream), entry: i64::try_from(r.entry).unwrap_or(i64::MAX) }
    }
}

impl TelemetryReceipt {
    fn receipt(&self) -> Result<seal::TelemetryReceipt, ClientError> {
        let bad = || ClientError::Invalid("a receipt's stream is 16 bytes".into());
        let stream = codec::from_b64url(&self.stream).map_err(|_| bad())?;
        let entry = u64::try_from(self.entry).map_err(|_| ClientError::Invalid("a receipt's entry is >= 0".into()))?;
        Ok(seal::TelemetryReceipt { stream: stream.try_into().map_err(|_| bad())?, entry })
    }
}

/// Appends `receipts` to `path` as JSON lines, the format `seal telemetry --receipts` reads.
#[napi]
// Only JavaScript calls it: napi registers exports outside test builds.
#[cfg_attr(test, allow(dead_code))]
pub async fn append_receipts(path: String, receipts: Vec<TelemetryReceipt>) -> napi::Result<()> {
    let receipts =
        receipts.iter().map(TelemetryReceipt::receipt).collect::<Result<Vec<_>, _>>().map_err(crate::error)?;
    spawn_blocking(move || seal::receipts::append(&path, &receipts).map_err(|e| format!("{path}: {e}")))
        .await
        .map_err(|e| Error::from_reason(e.to_string()))?
        .map_err(Error::from_reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipts_round_trip() {
        let receipt = seal::TelemetryReceipt { stream: [7; 16], entry: 42 };
        let js = TelemetryReceipt::from(receipt);
        assert_eq!(js.stream, codec::b64url(&[7; 16]));
        assert_eq!(js.receipt().unwrap(), receipt);
        let short = TelemetryReceipt { stream: codec::b64url(&[7; 15]), entry: 1 };
        assert!(matches!(short.receipt(), Err(ClientError::Invalid(_))));
        let negative = TelemetryReceipt { stream: js.stream.clone(), entry: -1 };
        assert!(matches!(negative.receipt(), Err(ClientError::Invalid(_))));
    }
}
