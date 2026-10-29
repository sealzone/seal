// @sealzone/verify: seal-verify in the browser. Documents go in and come out as the protocol's
// JSON (seal-proto's serde form), exactly as the control plane serves them. Call `init()` (or
// `initSync`) once before anything else. Every function throws an Error when verification
// fails or an argument does not parse.

import init, {
  initSync,
  verifyTenant as wasmVerifyTenant,
  verifyDocuments as wasmVerifyDocuments,
  classifyState as wasmClassifyState,
  diffStates as wasmDiffStates,
  classifyRoot as wasmClassifyRoot,
  diffRoots as wasmDiffRoots,
  labeledDigest as wasmLabeledDigest,
  webauthnSignature as wasmWebauthnSignature,
  signers as wasmSigners,
  adminKeyId as wasmAdminKeyId,
  rootId as wasmRootId,
  certifiedTelemetryKeys as wasmCertifiedTelemetryKeys,
  analyzeTelemetry as wasmAnalyzeTelemetry,
  telemetryReaderPublicKey as wasmTelemetryReaderPublicKey,
  verifyCheckpoint as wasmVerifyCheckpoint,
  verifyInclusion as wasmVerifyInclusion,
  releaseSigners as wasmReleaseSigners,
  verifyRelease as wasmVerifyRelease,
} from "./seal_verify_wasm.js"

export { init, initSync }

// The labels admin keys sign documents under.
export const LABELS = Object.freeze({
  tenantState: "seal/tenant-state/v1",
  tenantRoot: "seal/tenant-root/v1",
  releaseCosign: "seal/release-cosign/v1",
})

const json = (value) => JSON.stringify(value)
const parse = (text) => JSON.parse(text)
const nowSecs = () => Math.floor(Date.now() / 1000)

// base64url without padding, from an ArrayBuffer, a typed array or a base64url string.
function b64url(value) {
  if (typeof value === "string") return value
  const bytes = value instanceof ArrayBuffer ? new Uint8Array(value) : new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
  let s = ""
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

function hex(value) {
  if (typeof value === "string") return value
  return Array.from(value instanceof ArrayBuffer ? new Uint8Array(value) : value, (b) => b.toString(16).padStart(2, "0")).join("")
}

export function verifyTenant(trust, tenant, bundle, { now = nowSecs(), telemetryKeys = [], documents } = {}) {
  const docs = documents === undefined ? "" : json(documents)
  return parse(wasmVerifyTenant(json(trust), tenant, json(bundle), now, json(telemetryKeys), docs))
}

export function verifyDocuments(trust, tenant, documents) {
  return parse(wasmVerifyDocuments(json(trust), tenant, json(documents)))
}

export function classifyState(old, next) {
  return parse(wasmClassifyState(json(old), json(next)))
}

export function diffStates(old, next) {
  return parse(wasmDiffStates(json(old), json(next)))
}

export function classifyRoot(old, next) {
  return parse(wasmClassifyRoot(json(old), json(next)))
}

export function diffRoots(old, next) {
  return parse(wasmDiffRoots(json(old), json(next)))
}

export function labeledDigest(label, document) {
  return wasmLabeledDigest(label, json(document))
}

export function webauthnSignature(adminKey, label, document, assertion) {
  const parts = {
    authenticator_data: b64url(assertion.authenticatorData),
    client_data_json: b64url(assertion.clientDataJSON),
    signature: b64url(assertion.signature),
  }
  return parse(wasmWebauthnSignature(json(adminKey), label, json(document), json(parts)))
}

export function signers(root, label, signed) {
  return parse(wasmSigners(json(root), label, json(signed)))
}

export function adminKeyId(adminKey) {
  return wasmAdminKeyId(json(adminKey))
}

export function rootId(rootV1) {
  return wasmRootId(json(rootV1))
}

export function certifiedTelemetryKeys(trust, tenant, rootId, certificates, checkpoint) {
  const cp = checkpoint === undefined ? "" : json(checkpoint)
  return parse(wasmCertifiedTelemetryKeys(json(trust), tenant, rootId, json(certificates), cp))
}

export function analyzeTelemetry(tenant, keys, batches, { since = 0, receipts = [], readerSeed } = {}) {
  const seed = readerSeed === undefined ? "" : hex(readerSeed)
  return parse(wasmAnalyzeTelemetry(tenant, json(keys), json(batches), since, json(receipts), seed))
}

export function telemetryReaderPublicKey(readerSeed) {
  return wasmTelemetryReaderPublicKey(hex(readerSeed))
}

export function verifyCheckpoint(trust, checkpoint) {
  return parse(wasmVerifyCheckpoint(json(trust), json(checkpoint)))
}

export function verifyInclusion(trust, entry, proof) {
  return parse(wasmVerifyInclusion(json(trust), json(entry), json(proof)))
}

export function releaseSigners(trust, manifest) {
  return parse(wasmReleaseSigners(json(trust), json(manifest)))
}

export function verifyRelease(trust, evidence, { fresh, now = nowSecs() } = {}) {
  return parse(wasmVerifyRelease(json(trust), json(evidence), fresh === undefined ? "" : json(fresh), now))
}
