// Seal: use secrets without holding them. Types for `@sealzone/sdk` (index.js).

/// <reference types="node" />

export type Secret = string | Uint8Array;
export type Strings = string | readonly string[];
export type Severity = "low" | "medium" | "high" | "critical";
export type Tier = "base" | "hardened";
/** A release trust (`trust.json`): a path, a file URL, or its JSON as a string or bytes. */
export type Trust = string | URL | Uint8Array;

export interface ConnectOptions {
  /** The tenant's enclave replicas, e.g. `https://10.0.1.4:8443`. Default: `SEAL_ENDPOINT`. */
  endpoints?: Strings;
  /** `<tenant>` or `<tenant>@<root id>`. Default: `SEAL_TENANT`. */
  tenant?: string;
  /** The tenant's root chain; enclaves serving another root are refused. Sealing needs it, here or in `tenant`. */
  rootId?: string;
  /** Default: the first workload identity the environment provides. */
  identity?: IdentityProvider;
  /** Default: the release trust this build ships. */
  trust?: Trust;
}

export interface SealOptions {
  /** The destination URL (`https://`, `postgres://`, `clickhouse://`, `rediss://`). */
  to: string;
  /** The apps that may use the secret. */
  apps: Strings;
  /** HTTP: the header that carries the secret. Default `authorization`. */
  header?: string;
  /** HTTP: the header value, `{key}` where the secret goes. Default `Bearer {key}` for
   * `authorization`, `{key}` otherwise. */
  format?: string;
  /** Upstream keys (`sha256/<base64>`, up to 4) required in its certificate chain. */
  pin?: Strings;
  /** When every copy stops working: a Date, or Unix seconds. */
  expires?: Date | number;
  /** HTTP: allowed methods. Default: any. */
  methods?: Strings;
  /** HTTP: refused path prefixes, even inside `to`. */
  deny?: Strings;
  /** Only enclaves on the sealed platform tier may open the blob. */
  sealedOnly?: boolean;
  /** Only hardened sessions may use the blob. */
  hardenedOnly?: boolean;
  /** Resolve to `{ blob, receipt }` instead of the blob. */
  withReceipt?: boolean;
}

/** What an `endpointReporter` returns: the endpoint's artifact (checked against the tenant's
 * integrity policy) and opaque provider evidence. */
export interface EndpointReport {
  artifact?: { name: string; sha256: Uint8Array | string } | null;
  evidence?: ReadonlyArray<{ provider: string; bytes: Uint8Array | string }>;
}

export interface SessionOptions {
  /** Ask for this kind; a blob of the other kind fails with `BadRequest` before anything is sent. */
  kind?: "http" | "database";
  /** Refuse a weaker session. */
  minTier?: Tier;
  /** Returns the blob again when it comes back `Expired` (e.g. after a rotation). */
  reloadWith?: () => string | Promise<string>;
  /** Receives the secret resealed under the tenant's current key version. Errors become
   * process warnings. */
  onReseal?: (blob: string) => void | Promise<void>;
  /** Returns the report sent at start and every extend, with any signed evidence covering the
   * request's 32-byte `challenge`; or a `HostAgentReporter`. Default: the running executable's hash. */
  endpointReporter?: ((challenge: Buffer) => EndpointReport | Promise<EndpointReport>) | HostAgentReporter;
}

/** `session.info`. */
export interface SessionInfo {
  /** base64url, as telemetry shows it. */
  readonly sessionId: string;
  readonly platform: "sim" | "sealed";
  readonly tier: Tier;
  readonly tenant: string;
  readonly app: string;
  readonly blobId: string;
  /** Unix seconds. */
  readonly expiresAt: number;
}

/** Where telemetry recorded a seal or a session start. */
export declare class TelemetryReceipt {
  constructor(stream: Uint8Array, entry: number);
  /** The telemetry stream (16 bytes). */
  readonly stream: Buffer;
  readonly entry: number;
  /** One line of the receipts file: `JSON.stringify(receipt)`. */
  toJSON(): { stream: string; entry: number };
}

/** Telemetry receipts, in the file format `seal telemetry --receipts` reads. */
export declare const receipts: {
  /** Appends `receipts` to `path` as JSON lines, creating the file when it is missing. */
  append(path: string | URL, receipts: Iterable<TelemetryReceipt>): Promise<void>;
};

/** What every session has. `await using` closes it. */
export declare abstract class Session {
  protected constructor();
  readonly kind: "http" | "database";
  readonly info: SessionInfo;
  /** Where telemetry recorded the start and every restart, oldest first. */
  receipts(): Promise<TelemetryReceipt[]>;
  /** Extend now with a fresh identity proof. The tunnel also extends by itself before every expiry. */
  extend(): Promise<void>;
  /** End the session on the server and close the tunnel. On an error, call it again. */
  close(): Promise<void>;
  [Symbol.asyncDispose](): Promise<void>;
}

/** A session on an HTTP blob: point the app's client at `url` with `key`. */
export declare class HttpSession extends Session {
  readonly kind: "http";
  /** The local tunnel (`http://127.0.0.1:…`). */
  readonly url: string;
  /** A stand-in key worthless outside this tunnel. */
  readonly key: string;
}

/** A session on a Postgres, Redis or ClickHouse blob: connect with `dsn`. */
export declare class DatabaseSession extends Session {
  readonly kind: "database";
  /** A complete connection string for the app's driver. */
  readonly dsn: string;
  readonly protocol: "postgres" | "redis" | "click_house";
}

/** The seal host agent (App Integrity add-on) as an `endpointReporter`: from the environment
 * (`SEAL_AGENT_SOCKET`, `SEAL_APP_KEY`), or with both `socket` and `appKey`. */
export declare class HostAgentReporter {
  constructor(options?: { socket: string; appKey: string });
}

/** A workload identity a client proves itself with. */
export declare abstract class IdentityProvider {
  protected constructor();
  /** Short name for logs and errors, e.g. `app-key`. */
  readonly kind: string;
}

/** An app key, `sealak_…` (what `SEAL_APP_KEY` holds). */
export declare class AppKeyIdentity extends IdentityProvider {
  constructor(key: string);
}

/** An Azure managed identity's token for `audience`; `clientId` picks a user-assigned identity. */
export declare class AzureManagedIdentity extends IdentityProvider {
  constructor(audience: string, options?: { clientId?: string });
}

/** A Kubernetes projected service account token, re-read for every proof. */
export declare class KubernetesIdentity extends IdentityProvider {
  constructor(path?: string);
}

/** A GCP service account's identity token from the metadata server, audience `seal:<tenant>`. */
export declare class GcpIdentity extends IdentityProvider {
  constructor(tenant: string);
}

/** GitHub Actions OIDC (`permissions: id-token: write`), audience `seal:<tenant>`. */
export declare class GitHubActionsIdentity extends IdentityProvider {
  constructor(tenant: string);
}

/** An IAM role from the default AWS credential chain. Only in builds with AWS support. */
export declare class AwsIdentity extends IdentityProvider {
  static fromEnv(): Promise<AwsIdentity>;
}

/** A verified connection to the tenant's enclaves, acting as one workload identity. */
export declare class Client {
  private constructor();
  /** Verifies the enclave; options not given come from the environment. */
  static connect(options?: ConnectOptions): Promise<Client>;
  /** Everything from the environment. */
  static fromEnv(): Promise<Client>;
  /** The tenant this client serves. */
  readonly tenant: string;
  /** Seal `secret` so only `apps` can use it, and only with `to`. Anyone may seal. */
  seal(secret: Secret, options: SealOptions & { withReceipt?: false }): Promise<string>;
  seal(secret: Secret, options: SealOptions & { withReceipt: true }): Promise<{ blob: string; receipt: TelemetryReceipt }>;
  /** Start a session on `blob`. Needs an app grant listed in the blob's policy. */
  session(blob: string, options: SessionOptions & { kind: "http" }): Promise<HttpSession>;
  session(blob: string, options: SessionOptions & { kind: "database" }): Promise<DatabaseSession>;
  session(blob: string, options?: SessionOptions): Promise<HttpSession | DatabaseSession>;
  /** Signal that this workload's own endpoint may be compromised. */
  signal(code: string, severity: Severity): Promise<void>;
}

/** The public error vocabulary; values are the wire names. */
export declare const ErrorCode: {
  readonly Expired: "expired";
  readonly NotAllowed: "not_allowed";
  readonly TierTooLow: "tier_too_low";
  readonly IntegrityFailed: "integrity_failed";
  readonly Unavailable: "unavailable";
  readonly PolicyDenied: "policy_denied";
  readonly BudgetExceeded: "budget_exceeded";
  readonly SessionExpired: "session_expired";
  readonly SessionEnded: "session_ended";
  readonly VerificationFailed: "verification_failed";
  readonly BadRequest: "bad_request";
  readonly Internal: "internal";
  readonly ResealRequired: "reseal_required";
};
export type ErrorCode = (typeof ErrorCode)[keyof typeof ErrorCode];

/** Base of every Seal error. */
export declare class SealError extends Error {
  constructor(message?: string, code?: ErrorCode);
  static readonly code: ErrorCode;
  readonly code: ErrorCode;
  /** `unavailable` and `session_expired`: trying again later may succeed. */
  readonly retryable: boolean;
}
/** The blob is past its `expires`, or its tenant key version is retired. */
export declare class Expired extends SealError {}
/** This identity may not do this, or no workload identity was found. */
export declare class NotAllowed extends SealError {}
/** The session would be weaker than `minTier`. */
export declare class TierTooLow extends SealError {}
/** The endpoint failed an integrity check, or its identity is suspended. */
export declare class IntegrityFailed extends SealError {}
/** Seal, or something it needs, could not be reached. Retryable. */
export declare class Unavailable extends SealError {}
/** A request falls outside the blob's policy. */
export declare class PolicyDenied extends SealError {}
/** A budget or rate limit is exhausted. */
export declare class BudgetExceeded extends SealError {}
/** The session token expired; the SDK restarts the session by itself. */
export declare class SessionExpired extends SealError {}
/** The session was ended. Start a new one. */
export declare class SessionEnded extends SealError {}
/** The enclave could not be verified. Never retried silently. */
export declare class VerificationFailed extends SealError {}
/** A bad argument (an invalid `to`, app name, header or pin, a malformed blob). */
export declare class BadRequest extends SealError {}
/** Seal itself failed. */
export declare class Internal extends SealError {}
/** The blob was sealed before the enclave's platform was enabled: seal the secret again. */
export declare class ResealRequired extends SealError {}
