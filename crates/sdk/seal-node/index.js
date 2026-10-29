"use strict";
// Seal: use secrets without holding them.
//
//   const { Client } = require("@sealzone/sdk");   // or: import { Client } from "@sealzone/sdk"
//
//   const seal = await Client.fromEnv();
//   const blob = await seal.seal(secret, { to: "https://api.openai.com/v1", apps: ["checkout"] });
//
//   await using s = await seal.session(blob, { kind: "http" });  // or: try { ... } finally { await s.close() }
//   const openai = new OpenAI({ baseURL: s.url, apiKey: s.key });
//
// Over the native addon (src/, `native.js` finds it): every operation is a Promise, errors are
// `SealError`s named after their `ErrorCode` (errors.js).

const fs = require("node:fs");
const { fileURLToPath } = require("node:url");

const native = require("./native.js").load();

const {
  ErrorCode,
  SealError,
  Expired,
  NotAllowed,
  TierTooLow,
  IntegrityFailed,
  Unavailable,
  PolicyDenied,
  BudgetExceeded,
  SessionExpired,
  SessionEnded,
  VerificationFailed,
  BadRequest,
  Internal,
  ResealRequired,
  fromNative,
} = require("./errors.js");

// Where wrappers keep their native object; not part of the API.
const NATIVE = Symbol("seal.native");
// Lets only this module construct clients and sessions.
const TOKEN = Symbol("seal.token");

/** `fn()`, with native errors as `SealError`s. */
function sync(fn) {
  try {
    return fn();
  } catch (e) {
    throw fromNative(e);
  }
}

/** `await promise`, with native errors as `SealError`s. */
async function settle(promise) {
  try {
    return await promise;
  } catch (e) {
    throw fromNative(e);
  }
}

function strings(value, name) {
  if (value === undefined || value === null) {
    return undefined;
  }
  const list = typeof value === "string" ? [value] : value;
  if (!Array.isArray(list) || !list.every((s) => typeof s === "string")) {
    throw new TypeError(`${name} must be a string or an array of strings`);
  }
  return list;
}

function optionalString(value, name) {
  if (value !== undefined && value !== null && typeof value !== "string") {
    throw new TypeError(`${name} must be a string`);
  }
  return value ?? undefined;
}

function bytes(value, name) {
  if (typeof value === "string") {
    return Buffer.from(value, "utf8");
  }
  if (value instanceof Uint8Array) {
    return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  }
  throw new TypeError(`${name} must be a string, a Buffer or a Uint8Array`);
}

/** A release trust's JSON: a Buffer or a string of JSON as given, a path's contents. */
function trustJson(trust) {
  if (trust === undefined || trust === null) {
    return undefined;
  }
  if (trust instanceof URL) {
    return fs.readFileSync(fileURLToPath(trust));
  }
  if (typeof trust === "string") {
    return trust.trimStart().startsWith("{") ? Buffer.from(trust, "utf8") : fs.readFileSync(trust);
  }
  return bytes(trust, "trust");
}

function unixSeconds(expires) {
  if (expires === undefined || expires === null) {
    return undefined;
  }
  if (expires instanceof Date) {
    return Math.floor(expires.getTime() / 1000);
  }
  if (Number.isInteger(expires)) {
    return expires;
  }
  throw new TypeError("expires must be a Date or Unix seconds");
}

function callable(fn, name) {
  if (fn !== undefined && fn !== null && typeof fn !== "function") {
    throw new TypeError(`${name} must be a function`);
  }
  return fn ?? undefined;
}

/** An app callback as the addon calls it (src/session.rs `reply`): a function that never
 * throws and resolves to `{"value": …}` or `{"error": {"code", "message"}}` as JSON. */
function reply(fn, encode) {
  return async (arg) => {
    try {
      return JSON.stringify({ value: encode(await fn(arg)) });
    } catch (e) {
      const code = e instanceof SealError ? e.code : null;
      return JSON.stringify({ error: { code, message: String(e?.message ?? e) } });
    }
  };
}

function encodeBlob(blob) {
  if (typeof blob !== "string") {
    throw new TypeError("reloadWith must return the blob text");
  }
  return blob;
}

function hex(value, name) {
  if (typeof value === "string") {
    return value;
  }
  if (value instanceof Uint8Array) {
    return Buffer.from(value).toString("hex");
  }
  throw new TypeError(`${name} must be a Buffer, a Uint8Array or a hex string`);
}

function encodeReport(report) {
  if (report === null || typeof report !== "object") {
    throw new TypeError("endpointReporter must return an EndpointReport");
  }
  const artifact = report.artifact
    ? { name: String(report.artifact.name), sha256: hex(report.artifact.sha256, "artifact.sha256") }
    : null;
  const evidence = (report.evidence ?? []).map((e) => ({
    provider: String(e.provider),
    bytes: Buffer.from(bytes(e.bytes, "evidence.bytes")).toString("hex"),
  }));
  return { artifact, evidence };
}

/** `onReseal` has no caller to report to: its errors become process warnings. */
function resealed(fn) {
  return async (blob) => {
    try {
      await fn(blob);
    } catch (e) {
      process.emitWarning(`onReseal failed: ${e?.message ?? e}`, { type: "SealWarning" });
    }
    return JSON.stringify({ value: null });
  };
}

// ---- data ---------------------------------------------------------------------------------

/** Where telemetry recorded a seal or a session start. Keep receipts (`receipts.append`) for
 * `seal telemetry --receipts`. */
class TelemetryReceipt {
  constructor(stream, entry) {
    this.stream = Buffer.from(stream);
    this.entry = entry;
    if (this.stream.length !== 16) {
      throw new TypeError("a receipt's stream is 16 bytes");
    }
    Object.freeze(this);
  }

  /** One line of the receipts file: `JSON.stringify(receipt)`. */
  toJSON() {
    return { stream: this.stream.toString("base64url"), entry: this.entry };
  }

  static fromNative({ stream, entry }) {
    return new TelemetryReceipt(Buffer.from(stream, "base64url"), entry);
  }
}

const receipts = {
  /** Appends `receipts` to `path` as JSON lines, creating the file when it is missing. One
   * write per call, so processes appending to one file keep whole lines. */
  async append(path, list) {
    const file = path instanceof URL ? fileURLToPath(path) : path;
    if (typeof file !== "string") {
      throw new TypeError("path must be a string or a file URL");
    }
    const items = Array.from(list, (r) => {
      if (!(r instanceof TelemetryReceipt)) {
        throw new TypeError("receipts must be TelemetryReceipts");
      }
      return r.toJSON();
    });
    await settle(native.appendReceipts(file, items));
  },
};

// ---- the host agent --------------------------------------------------------------------------

/** The seal host agent (App Integrity add-on) as a session's `endpointReporter`: the artifact
 * the agent hashed outside this process, and its evidence signed over the request's
 * challenge. Without options it reads `SEAL_AGENT_SOCKET` (default `/run/seal/agent.sock`)
 * and the app key from `SEAL_APP_KEY`; with them, give both `socket` and `appKey`. Falls back
 * to hashing this executable when the agent does not answer. */
class HostAgentReporter {
  constructor(options) {
    const { socket, appKey } = options ?? {};
    let handle;
    if (socket === undefined && appKey === undefined) {
      handle = native.HostAgentReporter.fromEnv();
    } else if (typeof socket === "string" && typeof appKey === "string") {
      handle = sync(() => native.HostAgentReporter.withSocketAndKey(socket, appKey));
    } else {
      throw new BadRequest("HostAgentReporter takes both socket and appKey, or neither");
    }
    Object.defineProperty(this, NATIVE, { value: handle });
  }
}

// ---- identities ---------------------------------------------------------------------------

/** A workload identity a client proves itself with. Without one, a client uses the first
 * identity the environment provides. */
class IdentityProvider {
  constructor(handle) {
    if (!(handle instanceof native.Identity)) {
      throw new TypeError("use AppKeyIdentity, AzureManagedIdentity, KubernetesIdentity, ...");
    }
    Object.defineProperty(this, NATIVE, { value: handle });
  }

  /** Short name for logs and errors, e.g. `app-key`. */
  get kind() {
    return this[NATIVE].kind;
  }
}

/** An app key, `sealak_…` (what `SEAL_APP_KEY` holds). */
class AppKeyIdentity extends IdentityProvider {
  constructor(key) {
    if (typeof key !== "string") {
      throw new TypeError("key must be a string");
    }
    super(sync(() => native.Identity.appKey(key)));
  }
}

/** An Azure managed identity's token for `audience`, the Entra app ID URI the tenant
 * registered; `clientId` picks a user-assigned identity. */
class AzureManagedIdentity extends IdentityProvider {
  constructor(audience, { clientId } = {}) {
    super(sync(() => native.Identity.azureManaged(audience, optionalString(clientId, "clientId"))));
  }
}

/** A Kubernetes projected service account token (audience `seal:<tenant>`,
 * `expirationSeconds: 600`), re-read for every proof. */
class KubernetesIdentity extends IdentityProvider {
  constructor(path = undefined) {
    super(sync(() => native.Identity.kubernetes(optionalString(path, "path"))));
  }
}

/** A GCP service account's identity token from the metadata server, audience `seal:<tenant>`. */
class GcpIdentity extends IdentityProvider {
  constructor(tenant) {
    super(sync(() => native.Identity.gcp(tenant)));
  }
}

/** GitHub Actions OIDC (`permissions: id-token: write`): a fresh token for audience
 * `seal:<tenant>` on every proof. */
class GitHubActionsIdentity extends IdentityProvider {
  constructor(tenant) {
    super(sync(() => native.Identity.githubActions(tenant)));
  }
}

/** An IAM role from the default AWS credential chain, proven by a presigned STS
 * `GetCallerIdentity`. Only in builds with AWS support (`build.sh --aws`). */
class AwsIdentity extends IdentityProvider {
  static async fromEnv() {
    if (!native.AWS) {
      throw new Error("this build of @sealzone/sdk has no AWS support (build.sh --aws)");
    }
    return new AwsIdentity(await settle(native.awsIdentity()));
  }
}

// ---- sessions -----------------------------------------------------------------------------

/** What every session has: `info`, `receipts()`, `extend()`, `close()`, and
 * `await using`, which closes it. */
class Session {
  constructor(token, handle) {
    if (token !== TOKEN) {
      throw new TypeError("sessions come from client.session(blob)");
    }
    Object.defineProperty(this, NATIVE, { value: handle });
  }

  /** `"http"` or `"database"`. */
  get kind() {
    return this[NATIVE].kind;
  }

  /** Session id, tiers, tenant, app, blob id, expiry (`expiresAt`, Unix seconds). */
  get info() {
    return Object.freeze(this[NATIVE].info);
  }

  /** Where telemetry recorded the start and every restart, oldest first. */
  async receipts() {
    return (await settle(this[NATIVE].receipts())).map(TelemetryReceipt.fromNative);
  }

  /** Extend now with a fresh identity proof and move `info.expiresAt`. The tunnel extends the
   * session by itself before every expiry; `url`, `key` and `dsn` never change. */
  async extend() {
    await settle(this[NATIVE].extend());
  }

  /** End the session on the server (every replica refuses its tokens from then on) and close
   * the tunnel. On an error the end may not have reached every replica: call it again to
   * resend it. Once it succeeds, further calls do nothing. */
  async close() {
    await settle(this[NATIVE].close());
  }
}

if (typeof Symbol.asyncDispose === "symbol") {
  /** `await using s = await client.session(blob)`: closes on leaving the block, resending
   * the end once if the first attempt fails. */
  Session.prototype[Symbol.asyncDispose] = async function dispose() {
    try {
      await this.close();
    } catch (e) {
      if (!(e instanceof SealError)) {
        throw e;
      }
      await this.close();
    }
  };
}

/** A session on an HTTP blob: point the app's client at `url` with `key` where the real key
 * would go. */
class HttpSession extends Session {
  /** The local tunnel (`http://127.0.0.1:…`). The path continues the sealed destination's. */
  get url() {
    return this[NATIVE].url;
  }

  /** A stand-in key worthless outside this tunnel. */
  get key() {
    return this[NATIVE].key;
  }
}

/** A session on a Postgres, Redis or ClickHouse blob: connect with `dsn`. */
class DatabaseSession extends Session {
  /** A complete connection string for the app's driver, through the local tunnel. */
  get dsn() {
    return this[NATIVE].dsn;
  }

  /** `"postgres"`, `"redis"` or `"click_house"`. */
  get protocol() {
    return this[NATIVE].protocol;
  }
}

// ---- the client ---------------------------------------------------------------------------

const KINDS = new Set(["http", "database"]);
const SEVERITIES = new Set(["low", "medium", "high", "critical"]);

/** A verified connection to the tenant's enclaves, acting as one workload identity. */
class Client {
  constructor(token, handle) {
    if (token !== TOKEN) {
      throw new TypeError("use Client.connect() or Client.fromEnv()");
    }
    Object.defineProperty(this, NATIVE, { value: handle });
  }

  /** Verifies the enclave and resolves to a client. Options not given come from the
   * environment: `SEAL_ENDPOINT` (the enclave replicas, comma-separated), `SEAL_TENANT`
   * (`<tenant>@<root id>`; `<tenant>` alone cannot seal) and the first workload identity found
   * (`SEAL_APP_KEY`, Azure, Kubernetes, GCP, GitHub Actions). `trust` is the release trust
   * (`trust.json`): a path, or its JSON as a Buffer or string; by default the one this
   * build ships. */
  static async connect({ endpoints, tenant, rootId, identity, trust } = {}) {
    if (identity !== undefined && identity !== null && !(identity instanceof IdentityProvider)) {
      throw new TypeError("identity must be an IdentityProvider (e.g. new AppKeyIdentity(key))");
    }
    const options = {
      endpoints: strings(endpoints, "endpoints"),
      tenant: optionalString(tenant, "tenant"),
      rootId: optionalString(rootId, "rootId"),
      trust: trustJson(trust),
    };
    const handle = await settle(sync(() => native.Client.connect(options, identity?.[NATIVE])));
    return new Client(TOKEN, handle);
  }

  /** Everything from the environment: `Client.connect()`. */
  static fromEnv() {
    return Client.connect();
  }

  /** The tenant this client serves. */
  get tenant() {
    return this[NATIVE].tenant;
  }

  /** Seal `secret` so only the named `apps` can use it, and only with `to`. Resolves to the
   * portable blob text (`seal1.…`), safe to store anywhere; with `withReceipt: true`,
   * `{ blob, receipt }`. Anyone may seal: it needs no identity or grant.
   *
   * `to` is the destination URL (`https://`, `postgres://`, `clickhouse://`, `rediss://`).
   * HTTP options: `header` (default `authorization`), `format` (`{key}` where the secret
   * goes; default `Bearer {key}` for `authorization`), `methods`, `deny` (path prefixes).
   * `pin`: upstream keys (`sha256/<base64>`, up to 4) required in its certificate chain.
   * `expires`: when every copy stops working. `sealedOnly`: only sealed-tier enclaves.
   * `hardenedOnly`: only hardened sessions. */
  async seal(secret, options) {
    const { to, apps, header, format, pin, expires, methods, deny, sealedOnly, hardenedOnly, withReceipt } =
      options ?? {};
    if (typeof to !== "string") {
      throw new TypeError("to must be the destination URL");
    }
    const appList = strings(apps, "apps");
    if (appList === undefined) {
      throw new TypeError("apps must name the apps that may use the secret");
    }
    const sealOptions = {
      header: optionalString(header, "header"),
      format: optionalString(format, "format"),
      pins: strings(pin, "pin"),
      expires: unixSeconds(expires),
      methods: strings(methods, "methods"),
      deny: strings(deny, "deny"),
      sealedOnly: Boolean(sealedOnly),
      hardenedOnly: Boolean(hardenedOnly),
    };
    const secretBytes = bytes(secret, "secret");
    const sealed = await settle(sync(() => this[NATIVE].seal(secretBytes, to, appList, sealOptions)));
    if (withReceipt) {
      return { blob: sealed.blob, receipt: TelemetryReceipt.fromNative(sealed.receipt) };
    }
    return sealed.blob;
  }

  /** Start a session on `blob`: the enclave opens it and the app gets a stand-in. Needs an
   * app grant listed in the blob's policy. Resolves to an `HttpSession` or a
   * `DatabaseSession`, whichever the blob is; `kind: "http"` or `"database"` asks for one and
   * fails with `BadRequest` before anything is sent if the blob is the other kind.
   *
   * The SDK runs a local tunnel to the enclave and extends the session before every expiry.
   * `minTier`: refuse a weaker session. `reloadWith()`: returns the blob
   * again when it comes back `Expired` (e.g. after a rotation). `onReseal(blob)`: receives
   * the secret resealed under the tenant's current key version. `endpointReporter(challenge)`:
   * returns the `EndpointReport` sent at start and every extend, with any signed evidence
   * covering the 32-byte `challenge` Buffer (default: the running executable's hash); or a
   * `HostAgentReporter` for the seal host agent. Callbacks may be async. */
  async session(blob, options = {}) {
    const { kind, minTier, reloadWith, onReseal, endpointReporter } = options ?? {};
    if (typeof blob !== "string") {
      throw new TypeError("blob must be the blob text");
    }
    if (kind !== undefined && kind !== null && !KINDS.has(kind)) {
      throw new BadRequest(`kind must be "http" or "database", not ${JSON.stringify(kind)}`);
    }
    const reload = callable(reloadWith, "reloadWith");
    const reseal = callable(onReseal, "onReseal");
    const hostAgent = endpointReporter instanceof HostAgentReporter ? endpointReporter[NATIVE] : undefined;
    const reporter = hostAgent ? undefined : callable(endpointReporter, "endpointReporter");
    const sessionOptions = {
      kind: kind ?? undefined,
      minTier: optionalString(minTier, "minTier"),
    };
    const handle = await settle(
      sync(() =>
        this[NATIVE].session(
          blob,
          sessionOptions,
          reload && reply(reload, encodeBlob),
          reseal && resealed(reseal),
          reporter && reply((challenge) => reporter(Buffer.from(challenge, "hex")), encodeReport),
          hostAgent,
        ),
      ),
    );
    return handle.kind === "http" ? new HttpSession(TOKEN, handle) : new DatabaseSession(TOKEN, handle);
  }

  /** Signal that this workload's own endpoint may be compromised. Names only this identity;
   * under the tenant's integrity policy it may suspend the identity at once. `code` is opaque
   * to Seal (`[a-z0-9-.]`, 1 to 64 characters); `severity` is `low`, `medium`, `high` or
   * `critical`. */
  async signal(code, severity) {
    if (typeof code !== "string") {
      throw new TypeError("code must be a string");
    }
    if (!SEVERITIES.has(severity)) {
      throw new BadRequest(`severity must be low, medium, high or critical, not ${JSON.stringify(severity)}`);
    }
    await settle(sync(() => this[NATIVE].signal(code, severity)));
  }
}

module.exports = {
  Client,
  Session,
  HttpSession,
  DatabaseSession,
  TelemetryReceipt,
  HostAgentReporter,
  IdentityProvider,
  AppKeyIdentity,
  AzureManagedIdentity,
  KubernetesIdentity,
  GcpIdentity,
  GitHubActionsIdentity,
  AwsIdentity,
  receipts,
  ErrorCode,
  SealError,
  Expired,
  NotAllowed,
  TierTooLow,
  IntegrityFailed,
  Unavailable,
  PolicyDenied,
  BudgetExceeded,
  SessionExpired,
  SessionEnded,
  VerificationFailed,
  BadRequest,
  Internal,
  ResealRequired,
};
