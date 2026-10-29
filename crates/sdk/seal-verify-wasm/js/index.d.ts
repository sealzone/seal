// @sealzone/verify. Protocol documents (TenantBundle, TenantState, TenantRoot, Signed<…>,
// AdminKey, SignedTelemetryBatch, …) are seal-proto's serde JSON and pass through as `Json`.

export type Json = any

/** Loads the WebAssembly module (`seal_verify_wasm_bg.wasm` next to this file unless given). Call once. */
export function init(module?: {
  module_or_path: RequestInfo | URL | Response | BufferSource | WebAssembly.Module
}): Promise<unknown>
/** Loads the module from bytes already at hand (Node, tests). */
export function initSync(module: { module: BufferSource | WebAssembly.Module }): unknown

/** The labels admin keys sign under. */
export const LABELS: {
  readonly tenantState: "seal/tenant-state/v1"
  readonly tenantRoot: "seal/tenant-root/v1"
  readonly releaseCosign: "seal/release-cosign/v1"
}

export interface TlogTrust {
  origin: string
  log_key: string
  witness_keys: string[]
  witness_quorum: number
}

/**
 * The trust file (`trust.json`): `tenants` verifies documents, `guardians` telemetry
 * certificates, `releases` the log's checkpoints and releases (`verifyCheckpoint`,
 * `verifyInclusion`, `releaseSigners`, `verifyRelease`, which take the whole file).
 */
export interface Trust {
  tenants: {
    tlog: TlogTrust
    registrar_keys: string[]
    registrar_threshold: number
  }
  releases?: {
    tlog: TlogTrust
    release_keys: string[]
    release_threshold: number
    required_auditor?: string | null
    time_lock_secs: number
  }
  guardians?: Record<string, string>
  [other: string]: unknown
}

export type Change = "narrowing" | "widening"

/** One difference: `item.kind` names it (`deployment_added`, `pending_window`, `admin_key_added`, …). */
export interface Difference {
  change: Change
  item: { kind: string; [field: string]: Json }
}

/** A logged document and the witnessed time it was public by (Unix seconds). */
export interface Public {
  signed: Json
  public_since: number
}

export interface Pending {
  version: number
  root_version: number
  change: Change
  public_since: number
  /** When it takes effect unless a newer state does first; null: never. */
  effective_at: number | null
  differences: Difference[]
}

export interface VerifiedTenant {
  root_id: string
  /** In force: what enclaves obey. */
  root: Json
  state: Json
  in_force_since: number
  latest_root: Json
  latest_state: Json
  /** The time windows were measured at: the browser's clock bounded by the log's witnessed time. */
  checked_at: number
  fresh_until: number
  pending: Pending[]
  roots: Public[]
  states: Public[]
  signals: Json[]
  ended_sessions: Json[]
}

export interface VerifiedDocuments {
  root_id: string
  roots: Public[]
  states: Public[]
  witnessed_at: number
}

export function verifyTenant(
  trust: Trust,
  tenant: string,
  bundle: Json,
  options?: { now?: number; telemetryKeys?: string[]; documents?: Documents },
): VerifiedTenant
/** What `GET /v1/tenants/{t}/documents` serves. */
export interface Documents {
  roots: Json[]
  states?: Json[]
  checkpoint?: Json | null
}

export function verifyDocuments(trust: Trust, tenant: string, documents: Documents): VerifiedDocuments

export function classifyState(old: Json, next: Json): Change
export function diffStates(old: Json, next: Json): Difference[]
export function classifyRoot(old: Json, next: Json): Change
export function diffRoots(old: Json, next: Json): Difference[]

/** `labeled_digest(label, document)`: the 32 bytes a passkey signs (the WebAuthn challenge). */
export function labeledDigest(label: string, document: Json): Uint8Array
type Bytes = ArrayBuffer | ArrayBufferView | string
/** The protocol Signature for a passkey's assertion over `labeledDigest(label, document)`, checked first. */
export function webauthnSignature(
  adminKey: Json,
  label: string,
  document: Json,
  assertion: { authenticatorData: Bytes; clientDataJSON: Bytes; signature: Bytes },
): Json
/** Key ids (hex) of the root's admin keys with a valid signature on `signed`. */
export function signers(root: Json, label: string, signed: Json): string[]
export function adminKeyId(adminKey: Json): string
export function rootId(rootV1: Json): string

export interface Finding {
  kind:
    | "certificate_ignored"
    | "other_tenant"
    | "not_certified"
    | "equivocation"
    | "missing_batches"
    | "entry_gap"
    | "unopened"
    | "no_last"
    | "receipt_not_held"
  [field: string]: Json
}
export interface Analysis {
  entries: { stream: string; number: number; entry: Json }[]
  sealed: { stream: string; sequence: number; count: number }[]
  findings: Finding[]
}
export function certifiedTelemetryKeys(
  trust: Trust,
  tenant: string,
  rootId: string,
  certificates: Json[],
): { keys: string[]; findings: Finding[] }
export function analyzeTelemetry(
  tenant: string,
  keys: string[],
  batches: Json[],
  options?: { since?: number; receipts?: Json[]; readerSeed?: string | Uint8Array },
): Analysis
export function telemetryReaderPublicKey(readerSeed: string | Uint8Array): string

/** A checkpoint whose log signature and witness quorum verify (`releases.tlog`). */
export interface VerifiedCheckpoint {
  origin: string
  size: number
  /** Hex. */
  root_hash: string
  /** The checkpoint's `ReleaseConstraints`. */
  policy: Json
  /** The earliest time a quorum had seen it. */
  public_since: number
  /** The latest time a quorum vouched for it. */
  fresh_at: number
  quorum: number
  /** Each trusted witness; `cosigned_at` is null unless its cosignature is valid and not revoked. */
  witnesses: { key_id: string; cosigned_at: number | null }[]
}
export function verifyCheckpoint(trust: Trust, checkpoint: Json): VerifiedCheckpoint

/** `entry` (a `LogEntry`) is the leaf at `leaf_index` of the proof's verified checkpoint. */
export interface VerifiedInclusion {
  leaf_index: number
  size: number
  root_hash: string
  public_since: number
}
export function verifyInclusion(trust: Trust, entry: Json, proof: Json): VerifiedInclusion

/** Key ids (hex) of the trust's release keys with a valid signature on a `Signed<ReleaseManifest>`. */
export function releaseSigners(trust: Trust, manifest: Json): string[]

/** A release the guardian would accept: signatures, inclusion, time lock, freshness, revocations. */
export interface VerifiedRelease {
  manifest: Json
  public_since: number
  /** `public_since` plus the trust's time lock. */
  unlocked_at: number
  policy: Json
}
/** `fresh` replaces the evidence's own fresh checkpoint with a recent one. */
export function verifyRelease(
  trust: Trust,
  evidence: Json,
  options?: { fresh?: Json; now?: number },
): VerifiedRelease
