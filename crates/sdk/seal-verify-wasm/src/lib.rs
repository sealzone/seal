//! `seal-verify` for the browser: the web UI checks tenant documents, the pending window,
//! passkey signatures and telemetry with the same code the enclave, the guardian and the CLI
//! run. `api` holds the functions (JSON in and out); built for `wasm32-unknown-unknown`, they
//! are exported to JavaScript, and `js/index.js` wraps them (`build.sh` makes the npm package
//! `@sealzone/verify`).
//!
//! Browser verification protects against the control plane and storage, not against the page
//! that loads it: the trust it is given comes from wherever the page does.

#![deny(unsafe_code)]

pub mod api;

#[cfg(target_arch = "wasm32")]
mod js {
    // `#[wasm_bindgen]` expands to the unsafe glue that crosses into JavaScript.
    #![allow(unsafe_code)]

    use wasm_bindgen::prelude::*;

    use crate::api;

    fn js(r: api::Result<String>) -> Result<String, JsError> {
        r.map_err(|e| JsError::new(&e))
    }

    #[wasm_bindgen(js_name = verifyTenant)]
    pub fn verify_tenant(
        trust: &str,
        tenant: &str,
        bundle: &str,
        now: f64,
        telemetry_keys: &str,
        documents: &str,
    ) -> Result<String, JsError> {
        js(api::verify_tenant(trust, tenant, bundle, now as u64, telemetry_keys, documents))
    }

    #[wasm_bindgen(js_name = verifyDocuments)]
    pub fn verify_documents(trust: &str, tenant: &str, documents: &str) -> Result<String, JsError> {
        js(api::verify_documents(trust, tenant, documents))
    }

    #[wasm_bindgen(js_name = classifyState)]
    pub fn classify_state(old: &str, new: &str) -> Result<String, JsError> {
        js(api::classify_state(old, new))
    }

    #[wasm_bindgen(js_name = diffStates)]
    pub fn diff_states(old: &str, new: &str) -> Result<String, JsError> {
        js(api::diff_states(old, new))
    }

    #[wasm_bindgen(js_name = classifyRoot)]
    pub fn classify_root(old: &str, new: &str) -> Result<String, JsError> {
        js(api::classify_root(old, new))
    }

    #[wasm_bindgen(js_name = diffRoots)]
    pub fn diff_roots(old: &str, new: &str) -> Result<String, JsError> {
        js(api::diff_roots(old, new))
    }

    #[wasm_bindgen(js_name = labeledDigest)]
    pub fn labeled_digest(label: &str, document: &str) -> Result<Vec<u8>, JsError> {
        api::labeled_digest_of(label, document).map(|d| d.to_vec()).map_err(|e| JsError::new(&e))
    }

    #[wasm_bindgen(js_name = webauthnSignature)]
    pub fn webauthn_signature(
        admin_key: &str,
        label: &str,
        document: &str,
        assertion: &str,
    ) -> Result<String, JsError> {
        js(api::webauthn_signature(admin_key, label, document, assertion))
    }

    #[wasm_bindgen]
    pub fn signers(root: &str, label: &str, signed: &str) -> Result<String, JsError> {
        js(api::signers(root, label, signed))
    }

    #[wasm_bindgen(js_name = adminKeyId)]
    pub fn admin_key_id(admin_key: &str) -> Result<String, JsError> {
        js(api::admin_key_id_of(admin_key))
    }

    #[wasm_bindgen(js_name = rootId)]
    pub fn root_id(root_v1: &str) -> Result<String, JsError> {
        js(api::root_id_of(root_v1))
    }

    #[wasm_bindgen(js_name = certifiedTelemetryKeys)]
    pub fn certified_telemetry_keys(
        trust: &str,
        tenant: &str,
        root_id: &str,
        certificates: &str,
    ) -> Result<String, JsError> {
        js(api::certified_telemetry_keys(trust, tenant, root_id, certificates))
    }

    #[wasm_bindgen(js_name = analyzeTelemetry)]
    pub fn analyze_telemetry(
        tenant: &str,
        keys: &str,
        batches: &str,
        since: f64,
        receipts: &str,
        reader_seed: &str,
    ) -> Result<String, JsError> {
        js(api::analyze_telemetry(tenant, keys, batches, since as u64, receipts, reader_seed))
    }

    #[wasm_bindgen(js_name = telemetryReaderPublicKey)]
    pub fn telemetry_reader_public_key(reader_seed: &str) -> Result<String, JsError> {
        js(api::telemetry_reader_public_key(reader_seed))
    }
}
