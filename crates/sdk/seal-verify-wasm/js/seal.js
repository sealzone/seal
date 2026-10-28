// @sealzone/verify/seal: sealing a secret in the browser, as `seal secret` does. A module of its
// own: checking an enclave's attestation brings in RSA, P-384 and X.509, which pages that only
// verify documents should not load. Call `init()` (or `initSync`) once before anything else.
//
// The page verifies the enclave (`verifyEnclave`), HPKE-seals the secret to its attested ingest
// key (`sealRequest`), and checks the blob (`checkSealed`); whatever relays the calls sees only
// ciphertext. Sealing is open: no key is needed. The page itself sees the secret.

import init, {
  initSync,
  verifyEnclave as wasmVerifyEnclave,
  sealRequest as wasmSealRequest,
  checkSealed as wasmCheckSealed,
} from "./seal/seal_wasm.js"

export { init, initSync }

const json = (value) => JSON.stringify(value)
const parse = (text) => JSON.parse(text)

export function verifyEnclave(trust, tenant, rootId, attestation, now) {
  return parse(wasmVerifyEnclave(json(trust), tenant, rootId, json(attestation), now))
}

export function sealRequest(trust, tenant, rootId, attestation, secret, options, now) {
  return parse(wasmSealRequest(json(trust), tenant, rootId, json(attestation), secret, json(options), now))
}

export function checkSealed(response, tenant, rootId, policy) {
  return parse(wasmCheckSealed(json(response), tenant, rootId, json(policy)))
}
