# sealzone: the Seal SDK for Rust

Seal lets apps use secrets they never hold, because an attested enclave injects each secret
into the app's upstream traffic.

## Install

```toml
[dependencies]
seal = { package = "sealzone", version = "0.2" }
```

## Example

```rust,no_run
async fn demo(secret: &[u8]) -> Result<(), seal::ClientError> {
    // Reads SEAL_ENDPOINT, SEAL_TENANT and the workload's identity.
    let seal = seal::Client::from_env().await?;

    // Seal the secret. Anyone may seal; it needs no identity or grant.
    let blob = seal.seal(secret, "https://api.openai.com/v1", ["checkout"]).header("x-api-key").await?;

    // Use it. This needs an app grant. The app gets a stand-in key, and the enclave injects the real one.
    let s = seal.session(&blob).http().await?;
    let (url, key) = (s.url(), s.key());
    println!("send requests to {url} with key {key}");
    s.close().await?;
    Ok(())
}
```

Anyone can seal a secret for named apps. One of those apps then starts a session on the
sealed blob and gets a stand-in. The enclave injects the real secret on the way to the
upstream. The app, its host and Seal's control plane never see the secret.

## Verification

Every client verifies the enclave before it sends anything. It checks three things:

- the enclave's attestation, against the vendor's root
- its measurement, against a release signed by M of N release keys and logged in a
  transparency log
- its keys, against the guardian's certificate

Seal's production release trust ships with this crate. `ClientBuilder::trust` takes another.

## Reference

- **Sessions.** `.http()` gives a URL and a stand-in key. `.database()` gives a DSN
  (Postgres, Redis, ClickHouse). Both point at a local tunnel that the SDK runs. The tunnel
  reaches the enclave over TLS pinned to the enclave's attested key, so the app never holds
  a real credential. Sessions extend themselves, and `close()` ends them on every replica.
- **Identity.** A client proves who it is with an app key (`SEAL_APP_KEY`) or with the
  workload's own cloud identity: Azure managed identity, Kubernetes, GCP, GitHub Actions, or
  AWS (feature `aws`).
- **Errors.** `ClientError::Seal { code, .. }` carries an `ErrorCode` (`NotAllowed`,
  `Unavailable`, ...). The Python, Node and Go SDKs use the same codes.

The `sim` feature is **insecure**. It makes the client accept simulator evidence, which is
signed by a public development key. It exists for tests and local development. Never enable
it in anything that handles real secrets.

Documentation: <https://docs.rs/sealzone>. Source, the other SDKs and the protocol:
<https://github.com/sealzone/seal>. Licensed under Apache-2.0.
