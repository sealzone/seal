//! Compile with: cargo check -p sealzone --example contract
//! The client-facing contract in one place.
use std::sync::Arc;

use seal::identity::AppKeyIdentity;
use seal::{Client, ClientError, Session, Severity, TelemetryReceipt};

#[allow(dead_code)]
async fn use_secret(secret: &[u8]) -> Result<(), ClientError> {
    let seal = Client::from_env().await?;

    let blob =
        seal.seal(secret, "https://api.example.com/v1", ["checkout"]).header("x-api-key").deny("/v1/keys").await?;

    let s = seal.session(&blob).http().await?;
    let (_url, _key): (&str, &str) = (s.url(), s.key());
    // A failed close may have ended the session on one replica only: closing again resends the end.
    if s.close().await.is_err() {
        s.close().await?;
    }

    match seal.session(&blob).await? {
        Session::Http(s) => s.close().await?,
        Session::Database(db) => {
            let _dsn: &str = db.dsn();
            db.close().await?
        }
    }

    // Extend now rather than at the tunnel's next automatic extend; the key stays the same.
    let mut d = seal.session(&blob).http().await?;
    d.extend().await?;
    let (_url, _key): (&str, &str) = (d.url(), d.key());
    d.close().await?;

    // Telemetry receipts, kept for `seal telemetry --receipts receipts.jsonl`.
    let (_blob, receipt): (String, TelemetryReceipt) =
        seal.seal(secret, "https://api.example.com/v1", ["checkout"]).with_receipt().await?;
    let _starts: Vec<TelemetryReceipt> = d.receipts();
    seal::receipts::append("receipts.jsonl", &[receipt]).map_err(|e| ClientError::Invalid(e.to_string()))?;

    seal.signal("edr-alert", Severity::High).await
}

#[allow(dead_code)]
async fn explicit(trust: seal_verify::Trust) -> Result<Client, ClientError> {
    Client::builder()
        .endpoints(["https://10.0.1.4:8443"])
        .tenant("acme")
        .identity(Arc::new(AppKeyIdentity::from_env()?))
        .trust(trust)
        .connect()
        .await
}

fn main() {}
