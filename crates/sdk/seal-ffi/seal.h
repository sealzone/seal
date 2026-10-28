/*
 * seal.h: the C ABI of seal-ffi, over the Seal SDK core (crates/sdk/seal-client).
 * The Go SDK (seal.zone/go) is built on it. Hand-written; src/lib.rs's tests check that it
 * declares every exported function.
 *
 * Conventions:
 *
 * - Every fallible function returns a seal_error *: NULL on success, otherwise an error with
 *   `code` (an ErrorCode wire name: "expired", "not_allowed", "tier_too_low",
 *   "integrity_failed", "unavailable", "policy_denied", "budget_exceeded", "session_expired",
 *   "session_ended", "verification_failed", "bad_request", "internal",
 *   "reseal_required"; or "canceled" when the call's seal_cancel fired) and `message`.
 *   Free it with seal_error_free. Results come back through out-parameters, written only on
 *   success.
 * - Strings in are NUL-terminated UTF-8, borrowed for the call. Strings out are allocated by
 *   the library: free them with seal_string_free. Structured values cross as JSON text.
 * - seal_client, seal_session, seal_identity and seal_cancel are opaque handles, freed with
 *   their *_free function. Handles may be used from several threads at once; a free must not
 *   race a call on the same handle.
 * - Calls that reach the network block the calling thread. They run on one process-wide
 *   runtime inside the library, which also runs live sessions' tunnels. A call given a
 *   seal_cancel returns "canceled" as soon as the token is cancelled, abandoning its work.
 */

#ifndef SEAL_H
#define SEAL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct seal_error {
    char *code;
    char *message;
} seal_error;

typedef struct seal_client seal_client;
typedef struct seal_session seal_session;
typedef struct seal_identity seal_identity;
typedef struct seal_cancel seal_cancel;

/* ---- memory ---------------------------------------------------------------------------- */

void seal_error_free(seal_error *error);
/* Wipes the string before freeing it: some carry a session token (seal_session_credential). */
void seal_string_free(char *text);

/* ---- cancellation ---------------------------------------------------------------------- */

/* A token that cancels the calls it is passed to. Free it once no call uses it. */
seal_cancel *seal_cancel_new(void);
/* Cancels every call given `cancel`, now and later. */
void seal_cancel_cancel(const seal_cancel *cancel);
void seal_cancel_free(seal_cancel *cancel);

/* ---- identities ------------------------------------------------------------------------ */

/* An app key, sealak_... (what SEAL_APP_KEY holds). */
seal_error *seal_identity_app_key(const char *key, seal_identity **out);
/* An Azure managed identity's token for `audience`; `client_id` NULL: system-assigned. */
seal_error *seal_identity_azure(const char *audience, const char *client_id, seal_identity **out);
/* A Kubernetes projected service account token at `path` (NULL: the default path). */
seal_error *seal_identity_kubernetes(const char *path, seal_identity **out);
/* A GCP service account's identity token from the metadata server. */
seal_error *seal_identity_gcp(const char *tenant, seal_identity **out);
/* GitHub Actions OIDC (permissions: id-token: write). */
seal_error *seal_identity_github_actions(const char *tenant, seal_identity **out);
/* An IAM role from the default AWS credential chain; "bad_request" without the `aws` feature. */
seal_error *seal_identity_aws(const seal_cancel *cancel, seal_identity **out);
/* The identity's short name: "app-key", ... */
seal_error *seal_identity_kind(const seal_identity *identity, char **out);
void seal_identity_free(seal_identity *identity);

/* ---- clients --------------------------------------------------------------------------- */

/*
 * Verifies the enclave and returns a client. options_json (NULL for none):
 * {"endpoints": ["https://..."], "tenant": "acme" or "acme@<root id>", "root_id": "..."};
 * unset fields come from the environment (SEAL_ENDPOINT, SEAL_TENANT). identity NULL: the
 * first workload identity found. trust NULL: the release trust the build ships; otherwise
 * trust.json's bytes (a non-NULL trust is never replaced by the default: empty is refused).
 */
seal_error *seal_client_connect(const char *options_json, const seal_identity *identity,
                                const uint8_t *trust, size_t trust_len,
                                const seal_cancel *cancel, seal_client **out);
/* The tenant the client serves. */
seal_error *seal_client_tenant(const seal_client *client, char **out);
/*
 * Seals `secret` for the named apps. options_json: {"to": "https://...", "apps": [...],
 * "header", "format", "pins": [...], "expires": <unix seconds>, "methods": [...],
 * "deny": [...], "sealed_only": bool, "hardened_only": bool}; `to` and `apps` required.
 * The blob text in *blob_out; the telemetry receipt {"stream": "<base64url>", "entry": n}
 * in *receipt_out unless receipt_out is NULL. secret may be NULL only with secret_len 0.
 */
seal_error *seal_client_seal(const seal_client *client, const uint8_t *secret, size_t secret_len,
                             const char *options_json, const seal_cancel *cancel,
                             char **blob_out, char **receipt_out);
/* Signals that this workload's endpoint may be compromised. severity: low|medium|high|critical. */
seal_error *seal_client_signal(const seal_client *client, const char *code, const char *severity,
                               const seal_cancel *cancel);
/* Sessions the client started keep working. */
void seal_client_free(seal_client *client);

/* ---- sessions -------------------------------------------------------------------------- */

/*
 * Starts a session on `blob`, through a local tunnel the library runs to the enclave and
 * extends before every expiry. options_json (NULL for the defaults):
 * {"kind": "http" | "database", "min_tier": "base" | "hardened",
 *  "host_agent": {} (the seal host agent reports for this process, from SEAL_AGENT_SOCKET and
 *  SEAL_APP_KEY) | {"socket": "...", "app_key": "sealak_..."}}.
 */
seal_error *seal_client_session(const seal_client *client, const char *blob, const char *options_json,
                                const seal_cancel *cancel, seal_session **out);
/*
 * The session as JSON: {"kind", "url", "protocol", "info": {"session_id", "platform",
 * "tier", "tenant", "app", "blob_id", "expires_at"}}. Never waits on the network. Carries no
 * credential: see seal_session_credential.
 */
seal_error *seal_session_view(const seal_session *session, char **out);
/*
 * The key to send (HTTP) or the DSN (database), both for the local tunnel; it never changes
 * for the life of the session. Free it with seal_string_free, which wipes it.
 */
seal_error *seal_session_credential(const seal_session *session, char **out);
/* The telemetry receipts of the start and every restart, a JSON array, oldest first. */
seal_error *seal_session_receipts(const seal_session *session, char **out);
/* Extends the session now with a fresh identity proof (the tunnel also does by itself). */
seal_error *seal_session_extend(const seal_session *session, const seal_cancel *cancel);
/* Ends the session on the server; an error means it may not have reached every replica. */
seal_error *seal_session_close(const seal_session *session, const seal_cancel *cancel);
/* A session not closed successfully is ended in the background. */
void seal_session_free(seal_session *session);

/* ---- receipts -------------------------------------------------------------------------- */

/* Appends a JSON array of receipts to `path` as JSON lines (`seal telemetry --receipts`). */
seal_error *seal_append_receipts(const char *path, const char *receipts_json);

#ifdef __cplusplus
}
#endif

#endif /* SEAL_H */
