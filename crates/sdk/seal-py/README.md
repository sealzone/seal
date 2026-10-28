# sealzone: the Seal SDK for Python

Use secrets without holding them. Anyone seals a secret for named apps; one of those apps starts a
session on the sealed blob and gets a stand-in, while the enclave injects the real secret on
the way to the upstream.

```sh
pip install sealzone   # the SDK, and the `seal` command
```

```python
import seal

# Seal: required arguments as keywords, options as keywords.
blob = seal.seal(secret, to="https://api.openai.com/v1", apps=["checkout"], header="x-api-key")

# Use it: the app gets a stand-in key, the enclave injects the real one.
with seal.session(blob) as s:                 # leaving the block ends the session everywhere
    client = OpenAI(base_url=s.url, api_key=s.key)
```

The same flow in Rust is `seal.seal(secret, to, apps).header(..).await?`, then
`seal.session(&blob).http().await?` and `s.close().await?`; both SDKs use the same names.

The module-level `seal.seal`, `seal.session` and `seal.signal` use a client built from the
environment on first use: `SEAL_ENDPOINT` (the tenant's enclave replicas, comma-separated),
`SEAL_TENANT` (`<tenant>` or `<tenant>@<root id>`) and the first workload identity found
(`SEAL_APP_KEY`, Azure managed identity with `SEAL_AZURE_AUDIENCE`, a Kubernetes projected
token, GCP, GitHub Actions). Every client verifies the enclave before it sends anything,
against the release trust the wheel ships, or the one it is given:
`seal.Client(trust="trust.json")` (a path, or the JSON as bytes). Whether this workload may
seal or start sessions is decided by the enclave from the tenant's grants.

## Sessions

`seal.session(blob)` returns an `HttpSession` (`url`, `key`) or a `DatabaseSession` (`dsn`,
`protocol`), whichever the blob is; `kind="http"` or `kind="database"` asks for one and fails
with `seal.BadRequest` before anything is sent if the blob is the other kind. Every session
has `info`, `receipts()`, `extend()` and `close()`, and closes on leaving a `with` (or
`async with`) block.

```python
with seal.session(db_blob, kind="database") as db:
    conn = psycopg.connect(db.dsn)
```

- **The tunnel**: `url` and `dsn` point at a local proxy on `127.0.0.1` that the SDK runs to
  the enclave; `key` (and the DSN's password) is a stand-in worthless outside this process's
  tunnel. None of them change for the life of the session. The SDK extends the session before
  every expiry with a fresh identity proof; `extend()` does it now.
- **`close()`** ends the session on the server: every replica refuses its tokens from then
  on. If it raises, the end may not have reached every replica; call it again. A session
  dropped without a close is ended in the background.

Options: `min_tier`, `reload_with` (returns the blob again when it comes back `Expired`),
`on_reseal` (receives the secret resealed under the tenant's current key), and
`endpoint_reporter` (called with the request's 32-byte challenge, returns the
`seal.EndpointReport` sent at start and every extend, with any signed evidence covering the
challenge; the default reports the hash of the running executable, which for Python is the
interpreter, so apps whose tenant checks artifacts report their own bundle or image digest;
`seal.HostAgentReporter()` reports what the seal host agent says about this process).

## Explicit configuration, asyncio, receipts, signals

```python
client = seal.Client(endpoints=["https://10.0.1.4:8443"], tenant="acme",
                     identity=seal.AppKeyIdentity(app_key))

async def main():
    client = await seal.AsyncClient.connect()
    async with client.session(blob) as s:
        ...

blob, receipt = seal.seal(secret, to=..., apps=[...], with_receipt=True)
seal.receipts.append("receipts.jsonl", [receipt, *s.receipts()])   # for `seal telemetry --receipts`

seal.signal("edr-alert", severity="high")
```

Blocking calls release the GIL while they wait on the network, and Ctrl-C interrupts them.
Callbacks run on a worker thread and may be coroutine functions.

Prefork servers (gunicorn, Celery): a forked worker gets its own default client from
`seal.seal` / `seal.session` / `seal.signal`. Clients, sessions and identities made before
the fork raise `RuntimeError` in the worker; make new ones there.

## Errors

Every error is a `seal.SealError` with `code` (a `seal.ErrorCode`) and `retryable`, raised as
the subclass named after its code: `Expired`, `NotAllowed`, `TierTooLow`, `IntegrityFailed`,
`Unavailable`, `PolicyDenied`, `BudgetExceeded`, `SessionExpired`, `SessionEnded`,
`VerificationFailed`, `BadRequest` (also a `ValueError`), `Internal` and `ResealRequired`.
`VerificationFailed` means the enclave could not be verified; it is never retried silently.

## Building and testing

Wheels are abi3 (CPython 3.9 and later), built with maturin from this directory:
`maturin build --release`. `--features aws` adds AWS workload identity (`seal.AwsIdentity`).

`scripts/py-test.sh` (from the repository root) builds the simulator and a `sim` wheel into a
virtualenv and runs the tests in `tests/` against the simulator.
