# sealzone: the Seal SDK for Python

Seal lets apps use secrets they never hold, because an attested enclave injects each secret
into the app's upstream traffic.

## Install

```sh
pip install sealzone   # the SDK, and the `seal` command
```

## Example

```python
import os

import seal
from openai import OpenAI

# Seal the secret. Required arguments and options are both keywords.
blob = seal.seal(os.environ["OPENAI_API_KEY"], to="https://api.openai.com/v1", apps=["checkout"], header="x-api-key")

# Use it. The app gets a stand-in key, and the enclave injects the real one.
with seal.session(blob) as s:                 # leaving the block ends the session everywhere
    client = OpenAI(base_url=s.url, api_key=s.key)
```

Anyone can seal a secret for named apps. One of those apps then starts a session on the
sealed blob and gets a stand-in. The enclave injects the real secret on the way to the
upstream.

The same flow in Rust is `seal.seal(secret, to, apps).header(..).await?`, then
`seal.session(&blob).http().await?` and `s.close().await?`. Both SDKs use the same names.

## Configuration

The module-level `seal.seal`, `seal.session` and `seal.signal` build a client from the
environment on first use. It reads:

- `SEAL_ENDPOINT`, the tenant's enclave replicas, comma-separated
- `SEAL_TENANT`, as `<tenant>` or `<tenant>@<root id>`
- the first workload identity it finds: `SEAL_APP_KEY`, Azure managed identity with
  `SEAL_AZURE_AUDIENCE`, a Kubernetes projected token, GCP, or GitHub Actions

Every client verifies the enclave before it sends anything. By default it uses the release
trust the wheel ships. To use another, pass `seal.Client(trust="trust.json")`, which takes a
path or the JSON as bytes.

Anyone may seal. The enclave decides from the tenant's grants whether this workload may start
sessions.

## Sessions

`seal.session(blob)` returns an `HttpSession` (`url`, `key`) or a `DatabaseSession` (`dsn`,
`protocol`), whichever the blob is. `kind="http"` or `kind="database"` asks for one kind. If
the blob is the other kind, the call fails with `seal.BadRequest` before anything is sent.
Every session has `info`, `receipts()`, `extend()` and `close()`. A session also closes on
leaving a `with` or `async with` block.

```python
with seal.session(db_blob, kind="database") as db:
    conn = psycopg.connect(db.dsn)
```

- **The tunnel.** `url` and `dsn` point at a local proxy on `127.0.0.1` that the SDK runs to
  the enclave. `key`, and the DSN's password, is a stand-in that is worthless outside this
  process's tunnel. None of them change for the life of the session. The SDK extends the
  session with a fresh identity proof before every expiry. `extend()` does it now.
- **`close()`** ends the session on the server, and from then on every replica refuses its
  tokens. If `close()` raises, the end may not have reached every replica, so call it again.
  A session dropped without a close is ended in the background.

Session options:

- `min_tier` refuses weaker sessions.
- `reload_with` returns the blob again when it comes back `Expired`.
- `on_reseal` receives the secret resealed under the tenant's current key.
- `endpoint_reporter` is called with the request's 32-byte challenge. It returns the
  `seal.EndpointReport` sent at start and at every extend, with any signed evidence covering
  the challenge. `seal.HostAgentReporter()` reports what the seal host agent says about this
  process.

By default a session reports the hash of the running executable. For Python that is the
interpreter, so an app whose tenant checks artifacts should report its own bundle or image
digest.

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

Prefork servers such as gunicorn and Celery are supported. A forked worker gets its own
default client from `seal.seal`, `seal.session` and `seal.signal`. Clients, sessions and
identities made before the fork raise `RuntimeError` in the worker, so make new ones there.

## Errors

Every error is a `seal.SealError` with `code` (a `seal.ErrorCode`) and `retryable`. Each
error is raised as the subclass named after its code:

`Expired`, `NotAllowed`, `TierTooLow`, `IntegrityFailed`, `Unavailable`, `PolicyDenied`,
`BudgetExceeded`, `SessionExpired`, `SessionEnded`, `VerificationFailed`, `BadRequest` (also
a `ValueError`), `Internal`, `ResealRequired`.

`VerificationFailed` means the enclave could not be verified. The SDK never retries it
silently.

## Building and testing

Wheels are abi3 (CPython 3.9 and later). Build them with maturin from this directory:
`maturin build --release`. `--features aws` adds AWS workload identity (`seal.AwsIdentity`).

From the repository root, `scripts/py-test.sh` builds the simulator and a `sim` wheel into a
virtualenv. It then runs the tests in `tests/` against the simulator.
