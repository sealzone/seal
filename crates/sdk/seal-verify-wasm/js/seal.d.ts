// @sealzone/verify/seal: sealing in the browser. Protocol documents pass through as `Json`.

import type { Json, Trust } from "./index.js"

/** Loads the sealing module (`seal/seal_wasm_bg.wasm` next to this file unless given). Call once. */
export function init(module?: {
  module_or_path: RequestInfo | URL | Response | BufferSource | WebAssembly.Module
}): Promise<unknown>
/** Loads the module from bytes already at hand (Node, tests). */
export function initSync(module: { module: BufferSource | WebAssembly.Module }): unknown

/** The enclave a seal would go to, from its verified `GET /v1/attestation`. */
export interface VerifiedEnclave {
  platform: string
  release: string
  measurement: string
  attested_at: number
  service_key_version: number
  tenant: string
  root_id: string
}

/** `seal seal`'s options: where the secret may be sent, which apps may use it, and how. */
export interface SealOptions {
  to: string
  apps: string[]
  header?: string
  format?: string
  methods?: string[]
  deny?: string[]
  pins?: string[]
  /** Unix seconds. */
  expires?: number
  sealed_only?: boolean
  hardened_only?: boolean
}

/** Checks an enclave's attestation (evidence, release, guardian certificate) for `tenant` and `rootId`. */
export function verifyEnclave(
  trust: Trust,
  tenant: string,
  rootId: string,
  attestation: Json,
  now: number
): VerifiedEnclave
/** The `IdentityMatcher` a producer key (`sealak_…`) is granted as. */
export function producerIdentity(producerKey: string): {
  kind: "app_key"
  key_id: string
  public_key: string
}
/**
 * `POST /v1/blobs`'s body: `secret` HPKE-sealed to the verified enclave's ingest key, proven by
 * `producerKey` over `ticket`. Relays see only ciphertext; this page sees the secret.
 */
export function sealRequest(
  trust: Trust,
  tenant: string,
  rootId: string,
  attestation: Json,
  ticket: Json,
  producerKey: string,
  secret: Uint8Array,
  options: SealOptions,
  now: number
): { request: Json; policy: Json }
/** The seal response, checked: the blob names `tenant` and `rootId` and carries exactly `policy`. */
export function checkSealed(
  response: Json,
  tenant: string,
  rootId: string,
  policy: Json
): { blob: string; blob_id: string; telemetry: { stream: string; entry: number } }
