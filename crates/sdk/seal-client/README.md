# sealzone: the Seal SDK for Rust

Use secrets without holding them. Anyone seals a secret for named apps; one of those apps starts a
session on the sealed blob and gets a stand-in, while an attested enclave injects the real
secret on the way to the upstream. The app, its host and Seal's control plane never see it.

```toml
[dependencies]
seal = { package = "sealzone", version = "0.2" }
```

```rust,no_run
# async fn demo(secret: &[u8]) -> Result<(), seal::ClientError> {
let seal = seal::Client::from_env().await?;   // SEAL_ENDPOINT, SEAL_TENANT, the workload's identity

// Seal (anyone may: no identity or grant needed).
let blob = seal.seal(secret, "https://api.openai.com/v1", ["checkout"]).header("x-api-key").await?;

// Use it (needs an app grant): the app gets a stand-in key, the enclave injects the real one.
let s = seal.session(&blob).http().await?;
let (url, key) = (s.url(), s.key());
# let _ = (url, key);
s.close().await?;
# Ok(()) }
```

Before it sends anything, every client verifies the enclave: its attestation against the
vendor's root, its measurement against a release signed by M of N release keys and logged in a
transparency log, and its keys against the guardian's certificate. Seal's production release
trust ships with this crate; `ClientBuilder::trust` takes another.

- **Sessions**: `.http()` gives a URL and a stand-in key; `.database()` a DSN (Postgres,
  Redis, ClickHouse). Both point at a local tunnel the SDK runs, which reaches the enclave over TLS
  pinned to its attested key; the app never holds a real credential. Sessions extend
  themselves; `close()` ends them on every replica.
- **Identity**: an app key (`SEAL_APP_KEY`), or the workload's own cloud identity: Azure
  managed identity, Kubernetes, GCP, GitHub Actions, AWS (feature `aws`).
- **Errors**: `ClientError::Seal { code, .. }` carries an `ErrorCode` (`NotAllowed`,
  `Unavailable`, ...), the same codes as the Python, Node and Go SDKs.

The `sim` feature is **insecure**: it makes the client accept simulator evidence, signed by a
public development key. It exists for tests and local development; never enable it in
anything that handles real secrets.

Documentation: <https://docs.rs/sealzone>. Source, the other SDKs and the protocol:
<https://github.com/sealzone/seal>. Licensed under Apache-2.0.
