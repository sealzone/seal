# @sealzone/sdk: the Seal SDK for Node.js

Use secrets without holding them. Anyone seals a secret for named apps; one of those apps starts a
session on the sealed blob and gets a stand-in, while the enclave injects the real secret on
the way to the upstream.

```sh
npm install @sealzone/sdk
```

```js
import { Client } from "@sealzone/sdk";

const seal = await Client.fromEnv();

// Seal: the destination and the apps as options.
const blob = await seal.seal(secret, { to: "https://api.openai.com/v1", apps: ["checkout"], header: "x-api-key" });

// Use it: the app gets a stand-in key, the enclave injects the real one.
const s = await seal.session(blob, { kind: "http" });
try {
  const openai = new OpenAI({ baseURL: s.url, apiKey: s.key });
} finally {
  await s.close(); // ends the session everywhere
}
```

The same flow in Python is `seal.seal(secret, to=..., apps=[...])` and `seal.session(blob)`,
and in Rust `seal.seal(secret, to, apps).header(..).await?`; every SDK uses the same names,
in each language's case.

`Client.fromEnv()` builds a client from the environment: `SEAL_ENDPOINT` (the tenant's
enclave replicas, comma-separated), `SEAL_TENANT` (`<tenant>` or `<tenant>@<root id>`) and
the first workload identity found (`SEAL_APP_KEY`, Azure managed identity with
`SEAL_AZURE_AUDIENCE`, a Kubernetes projected token, GCP, GitHub Actions).
`Client.connect({ endpoints, tenant, rootId, identity, trust })` sets any of them; the rest
still come from the environment. Every client verifies the enclave before it sends anything,
against the release trust the package ships, or the one it is given: `trust: "trust.json"`
(a path, or the JSON as a string or Buffer). Anyone may seal; whether this workload may start
sessions is decided by the enclave from the tenant's grants. Every operation returns a Promise.

## Sessions

`client.session(blob)` resolves to an `HttpSession` (`url`, `key`) or a `DatabaseSession`
(`dsn`, `protocol`), whichever the blob is; `kind: "http"` or `kind: "database"` asks for one
(and types it) and fails with `BadRequest` before anything is sent if the blob is the other
kind. Every session has `info`, `receipts()`, `extend()` and `close()`, and closes on leaving
an `await using` block (Node 24+, TypeScript 5.2+).

```js
await using db = await seal.session(dbBlob, { kind: "database" });
const conn = new pg.Client({ connectionString: db.dsn });
```

- **The tunnel**: `url` and `dsn` point at a local proxy on `127.0.0.1` that the SDK runs to
  the enclave; `key` (and the DSN's password) is a stand-in worthless outside this process's
  tunnel. None of them change for the life of the session. The SDK extends the session before
  every expiry with a fresh identity proof; `extend()` does it now.
- **`close()`** ends the session on the server: every replica refuses its tokens from then
  on. If it rejects, the end may not have reached every replica; call it again. A session
  garbage-collected without a close is ended in the background.

Options: `minTier`, `reloadWith` (returns the blob again when it comes back `Expired`),
`onReseal` (receives the secret resealed under the tenant's current key; its errors become
process warnings), and `endpointReporter` (called with the request's 32-byte challenge as a
Buffer, returns the `EndpointReport` sent at start and every extend,
`{ artifact: { name, sha256 }, evidence: [{ provider, bytes }] }`, with any signed evidence
covering the challenge; `new HostAgentReporter()` reports what the seal host agent says about
this process instead; the default
reports the hash of the running executable, which for Node is the `node` binary, so apps
whose tenant checks artifacts report their own bundle or image digest). Callbacks may be
async and run on the JavaScript thread; they never keep Node running by themselves.

## Identities, receipts, signals

```js
import { AppKeyIdentity, Client, receipts } from "@sealzone/sdk";

const client = await Client.connect({ endpoints: ["https://10.0.1.4:8443"], tenant: "acme",
                                      identity: new AppKeyIdentity(appKey) });

const { blob, receipt } = await client.seal(secret, { to, apps: ["checkout"], withReceipt: true });
await receipts.append("receipts.jsonl", [receipt, ...(await s.receipts())]); // for `seal telemetry --receipts`

await client.signal("edr-alert", "high");
```

Identities: `AppKeyIdentity(key)`, `AzureManagedIdentity(audience, { clientId })`,
`KubernetesIdentity(path?)`, `GcpIdentity(tenant)`, `GitHubActionsIdentity(tenant)`, and
`await AwsIdentity.fromEnv()` in builds with AWS support.

## Errors

Every error is a `SealError` with `code` (an `ErrorCode` value: `"not_allowed"`, ...) and
`retryable`, thrown as the subclass named after its code: `Expired`, `NotAllowed`,
`TierTooLow`, `IntegrityFailed`, `Unavailable`, `PolicyDenied`, `BudgetExceeded`,
`SessionExpired`, `SessionEnded`, `VerificationFailed`, `BadRequest`,
`Internal` and `ResealRequired`. `VerificationFailed` means the enclave could not be
verified; it is never retried silently. Arguments of the wrong type throw a `TypeError`.

## Building and testing

The package is a napi-rs addon over the Rust SDK (`src/`, crate `seal-node`) and a thin
JavaScript layer (`index.js`, `index.d.ts`, `errors.js`). `build.sh` (or `npm run build`)
builds the addon for this machine as `seal.<platform>.node`, which `native.js` loads first;
published, each platform's addon is its own package (`@sealzone/sdk-linux-x64-gnu`, ...)
listed as an optional dependency, as napi-rs lays them out. `--release` builds what ships,
`--aws` adds `AwsIdentity`, `--sim` targets the simulator.

`build.sh --test` runs the unit tests in `test/` (`node --test`, no simulator).
`scripts/e2e.sh -k node` (from the repository root) runs `examples/e2e.mjs` against a whole
simulated system: a session through the tunnel, sealing as anyone
(`tests/e2e/test_node_sdk.py`).
