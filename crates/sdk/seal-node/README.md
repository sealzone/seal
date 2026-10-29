# @sealzone/sdk: the Seal SDK for Node.js

Seal lets apps use secrets they never hold, because an attested enclave injects each secret
into the app's upstream traffic.

## Install

```sh
npm install @sealzone/sdk
```

## Example

```js
import { Client } from "@sealzone/sdk";
import OpenAI from "openai";

const seal = await Client.fromEnv();

// Seal the secret. The destination and the apps are options.
const blob = await seal.seal(process.env.OPENAI_API_KEY, { to: "https://api.openai.com/v1", apps: ["checkout"], header: "x-api-key" });

// Use it. The app gets a stand-in key, and the enclave injects the real one.
const s = await seal.session(blob, { kind: "http" });
try {
  const openai = new OpenAI({ baseURL: s.url, apiKey: s.key });
} finally {
  await s.close(); // ends the session everywhere
}
```

Anyone can seal a secret for named apps. One of those apps then starts a session on the
sealed blob and gets a stand-in. The enclave injects the real secret on the way to the
upstream.

The same flow in Python is `seal.seal(secret, to=..., apps=[...])` and `seal.session(blob)`.
In Rust it is `seal.seal(secret, to, apps).header(..).await?`. Every SDK uses the same names,
in each language's case.

## Configuration

`Client.fromEnv()` builds a client from the environment:

- `SEAL_ENDPOINT`, the tenant's enclave replicas, comma-separated
- `SEAL_TENANT`, as `<tenant>@<root id>` (the console's Connect page shows it). Sealing
  needs the root id; sessions also work with `<tenant>` alone, since a blob names its root
- the first workload identity it finds: `SEAL_APP_KEY`, Azure managed identity with
  `SEAL_AZURE_AUDIENCE`, a Kubernetes projected token, GCP, or GitHub Actions

`Client.connect({ endpoints, tenant, rootId, identity, trust })` sets any of them, and the
rest still come from the environment.

Every client verifies the enclave before it sends anything. By default it uses the release
trust the package ships. To use another, pass `trust: "trust.json"`, which takes a path or
the JSON as a string or Buffer.

Anyone may seal. The enclave decides from the tenant's grants whether this workload may start
sessions. Every operation returns a Promise.

## Sessions

`client.session(blob)` resolves to an `HttpSession` (`url`, `key`) or a `DatabaseSession`
(`dsn`, `protocol`), whichever the blob is. `kind: "http"` or `kind: "database"` asks for one
kind and types the result. If the blob is the other kind, the call fails with `BadRequest`
before anything is sent. Every session has `info`, `receipts()`, `extend()` and `close()`.
A session also closes on leaving an `await using` block (Node 24+, TypeScript 5.2+).

```js
await using db = await seal.session(dbBlob, { kind: "database" });
const conn = new pg.Client({ connectionString: db.dsn });
```

- **The tunnel.** `url` and `dsn` point at a local proxy on `127.0.0.1` that the SDK runs to
  the enclave. `key`, and the DSN's password, is a stand-in that is worthless outside this
  process's tunnel. None of them change for the life of the session. The SDK extends the
  session with a fresh identity proof before every expiry. `extend()` does it now.
- **`close()`** ends the session on the server, and from then on every replica refuses its
  tokens. If `close()` rejects, the end may not have reached every replica, so call it again.
  A session that is garbage-collected without a close is ended in the background.

Session options:

- `minTier` refuses weaker sessions.
- `reloadWith` returns the blob again when it comes back `Expired`.
- `onReseal` receives the secret resealed under the tenant's current key. Its errors become
  process warnings.
- `endpointReporter` is called with the request's 32-byte challenge as a Buffer. It returns
  the `EndpointReport` sent at start and at every extend, shaped
  `{ artifact: { name, sha256 }, evidence: [{ provider, bytes }] }`, with any signed evidence
  covering the challenge. Pass `new HostAgentReporter()` instead to report what the seal host
  agent says about this process.

By default a session reports the hash of the running executable. For Node that is the `node`
binary, so an app whose tenant checks artifacts should report its own bundle or image digest.
Callbacks may be async and run on the JavaScript thread. They never keep Node running by
themselves.

## Identities, receipts, signals

```js
import { AppKeyIdentity, Client, receipts } from "@sealzone/sdk";

const client = await Client.connect({ endpoints: ["https://10.0.1.4:8443"], tenant: "acme",
                                      identity: new AppKeyIdentity(appKey) });

const { blob, receipt } = await client.seal(secret, { to, apps: ["checkout"], withReceipt: true });
await receipts.append("receipts.jsonl", [receipt, ...(await s.receipts())]); // for `seal telemetry --receipts`

await client.signal("edr-alert", "high");
```

The identities are `AppKeyIdentity(key)`, `AzureManagedIdentity(audience, { clientId })`,
`KubernetesIdentity(path?)`, `GcpIdentity(tenant)`, `GitHubActionsIdentity(tenant)`, and
`await AwsIdentity.fromEnv()` in builds with AWS support.

## Errors

Every error is a `SealError` with `code` and `retryable`. `code` is an `ErrorCode` value such
as `"not_allowed"`. Each error is thrown as the subclass named after its code:

`Expired`, `NotAllowed`, `TierTooLow`, `IntegrityFailed`, `Unavailable`, `PolicyDenied`,
`BudgetExceeded`, `SessionExpired`, `SessionEnded`, `VerificationFailed`, `BadRequest`,
`Internal`, `ResealRequired`.

`VerificationFailed` means the enclave could not be verified. The SDK never retries it
silently. Arguments of the wrong type throw a `TypeError`.

## Building and testing

The package is a napi-rs addon over the Rust SDK (`src/`, crate `seal-node`), plus a thin
JavaScript layer (`index.js`, `index.d.ts`, `errors.js`). `build.sh` (or `npm run build`)
builds the addon for this machine as `seal.<platform>.node`, and `native.js` loads that file
first. When published, each platform's addon is its own package
(`@sealzone/sdk-linux-x64-gnu`, ...), listed as an optional dependency in the napi-rs layout.
`build.sh` takes these flags:

- `--release` builds what ships.
- `--aws` adds `AwsIdentity`.
- `--sim` targets the simulator.

`build.sh --test` runs the unit tests in `test/` with `node --test`, without a simulator.
From the repository root, `scripts/e2e.sh -k node` runs `examples/e2e.mjs` against a whole
simulated system (`tests/e2e/test_node_sdk.py`). It covers a session through the tunnel and
sealing as anyone.
