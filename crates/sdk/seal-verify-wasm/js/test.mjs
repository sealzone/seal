// The WebAssembly build against tests/vectors.json, the same vectors the Rust API meets
// (tests/vectors.rs). Run by `build.sh --test`; SEAL_VERIFY_PKG names the built package.
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"
import { test } from "node:test"
import { fileURLToPath } from "node:url"

const here = fileURLToPath(new URL(".", import.meta.url))
const pkg = process.env.SEAL_VERIFY_PKG ?? join(here, "..", "pkg")
const seal = await import(join(pkg, "index.js"))
seal.initSync({ module: readFileSync(join(pkg, "seal_verify_wasm_bg.wasm")) })
const v = JSON.parse(readFileSync(join(here, "..", "tests", "vectors.json"), "utf8"))

const kinds = (differences) => differences.map((d) => d.item.kind).sort()

test("the state in force and the pending ones", () => {
  for (const c of v.tenant_cases) {
    const out = seal.verifyTenant(v.trust, v.tenant, c.bundle, { now: c.now, documents: c.documents })
    assert.equal(out.state.version, c.in_force, c.name)
    assert.equal(out.latest_state.version, c.latest, c.name)
    assert.deepEqual(
      out.pending.map((p) => ({ version: p.version, change: p.change, effective_at: p.effective_at })),
      c.pending,
      c.name,
    )
  }
  const pending = seal.verifyTenant(v.trust, v.tenant, v.tenant_cases[0].bundle, { now: v.tenant_cases[0].now })
  assert.deepEqual(kinds(pending.pending[0].differences), ["deployment_added"])
  // Older states left out: nothing shows what was in force before.
  const stale = structuredClone(v.tenant_cases[0].bundle)
  stale.states.shift()
  assert.throws(() => seal.verifyTenant(v.trust, v.tenant, stale, { now: v.tenant_cases[0].now }), /cannot tell which state is in force/)
  // A forged signature on the latest state.
  const forged = structuredClone(v.tenant_cases[0].bundle)
  forged.state.body.deployments = []
  assert.throws(() => seal.verifyTenant(v.trust, v.tenant, forged, { now: v.tenant_cases[0].now }))
})

test("documents with when each became public", () => {
  const out = seal.verifyDocuments(v.trust, v.tenant, v.documents.documents)
  assert.deepEqual(out.states.map((s) => s.public_since), v.documents.public_since)
})

test("classification and differences", () => {
  for (const c of v.classify) {
    assert.equal(seal.classifyState(c.old, c.new), c.change)
    assert.deepEqual(kinds(seal.diffStates(c.old, c.new)), c.kinds)
  }
  for (const c of v.classify_roots) {
    assert.equal(seal.classifyRoot(c.old, c.new), c.change)
    assert.deepEqual(kinds(seal.diffRoots(c.old, c.new)), c.kinds)
  }
})

test("passkey signing", () => {
  const g = v.signing
  const digest = seal.labeledDigest(g.label, g.document)
  assert.equal(Buffer.from(digest).toString("hex"), g.digest)
  assert.equal(g.label, seal.LABELS.tenantState)
  assert.throws(() => seal.labeledDigest("seal/other/v1", g.document))
  const fromBytes = (b64) => new Uint8Array(Buffer.from(b64, "base64url"))
  const assertion = {
    authenticatorData: fromBytes(g.assertion.authenticator_data).buffer,
    clientDataJSON: fromBytes(g.assertion.client_data_json),
    signature: g.assertion.signature,
  }
  assert.deepEqual(seal.webauthnSignature(g.admin_key, g.label, g.document, assertion), g.signature)
  assert.throws(() => seal.webauthnSignature(g.admin_key, g.label, { ...g.document, version: 5 }, assertion), /does not verify/)
  assert.equal(seal.adminKeyId(g.admin_key), g.admin_key_id)
  assert.deepEqual(seal.signers(g.root, g.label, g.signed).sort(), [...g.signers].sort())
  assert.equal(seal.rootId(g.root_v1), g.root_id)
})

test("telemetry", () => {
  const t = v.telemetry
  const certified = seal.certifiedTelemetryKeys(v.trust, v.tenant, t.root_id, t.certificates)
  assert.deepEqual(certified.keys, t.keys)
  assert.deepEqual(certified.findings.map((f) => f.kind), t.certificate_findings)
  assert.equal(seal.telemetryReaderPublicKey(t.reader_seed), t.reader_public_key)
  const opened = seal.analyzeTelemetry(v.tenant, certified.keys, t.batches, { receipts: t.receipts, readerSeed: t.reader_seed })
  assert.equal(opened.entries.length, t.entries)
  assert.deepEqual(opened.findings.map((f) => f.kind).sort(), t.findings)
  const seed = new Uint8Array(Buffer.from(t.reader_seed, "hex"))
  assert.equal(seal.analyzeTelemetry(v.tenant, certified.keys, t.batches, { readerSeed: seed }).sealed.length, 0)
  const closed = seal.analyzeTelemetry(v.tenant, certified.keys, t.batches, { receipts: t.receipts })
  assert.equal(closed.sealed.length, t.sealed_without_reader)
})

// The sealing module. A real seal needs a live attested enclave (the console's e2e covers it);
// here, what holds without one.
const sealing = await import(join(pkg, "seal.js"))
sealing.initSync({ module: readFileSync(join(pkg, "seal", "seal_wasm_bg.wasm")) })

test("sealing: refusals before any network", () => {
  const root = "11".repeat(32)
  assert.throws(() => sealing.verifyEnclave(v.trust, v.tenant, root, {}, 0), /attestation/)
  assert.throws(() => sealing.checkSealed({ blob: "seal1.x", blob_id: "0", telemetry: {} }, v.tenant, root, {}), /./)
})
