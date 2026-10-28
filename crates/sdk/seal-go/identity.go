package seal

/*
#include <stdlib.h>
#include "seal.h"
*/
import "C"

import (
	"context"
	"runtime"
)

// Identity is a workload identity a client proves itself with. Without one, a client uses the
// first identity the environment provides (SEAL_APP_KEY, Azure, Kubernetes, GCP, GitHub
// Actions).
type Identity struct {
	ptr *C.seal_identity
}

func newIdentity(ptr *C.seal_identity) *Identity {
	id := &Identity{ptr: ptr}
	runtime.SetFinalizer(id, func(id *Identity) { C.seal_identity_free(id.ptr) })
	return id
}

// Kind is the identity's short name for logs and errors, e.g. "app-key".
func (id *Identity) Kind() string {
	defer runtime.KeepAlive(id)
	var out *C.char
	if err := check(C.seal_identity_kind(id.ptr, &out)); err != nil {
		return ""
	}
	return takeString(out)
}

// AppKeyIdentity is an app key, "sealak_…" (what SEAL_APP_KEY holds).
func AppKeyIdentity(key string) (*Identity, error) {
	if err := noNUL("key", key); err != nil {
		return nil, err
	}
	k := cString(key, false)
	defer free(k)
	var out *C.seal_identity
	if err := check(C.seal_identity_app_key(k, &out)); err != nil {
		return nil, err
	}
	return newIdentity(out), nil
}

// AzureManagedIdentity is an Azure managed identity's token for audience, the Entra app ID
// URI the tenant registered; clientID picks a user-assigned identity ("" for the
// system-assigned one).
func AzureManagedIdentity(audience, clientID string) (*Identity, error) {
	if err := noNUL("audience or clientID", audience, clientID); err != nil {
		return nil, err
	}
	a, c := cString(audience, false), cString(clientID, true)
	defer free(a)
	defer free(c)
	var out *C.seal_identity
	if err := check(C.seal_identity_azure(a, c, &out)); err != nil {
		return nil, err
	}
	return newIdentity(out), nil
}

// KubernetesIdentity is a Kubernetes projected service account token (audience
// "seal:<tenant>", expirationSeconds: 600) at path ("" for the default path), re-read for
// every proof.
func KubernetesIdentity(path string) (*Identity, error) {
	if err := noNUL("path", path); err != nil {
		return nil, err
	}
	p := cString(path, true)
	defer free(p)
	var out *C.seal_identity
	if err := check(C.seal_identity_kubernetes(p, &out)); err != nil {
		return nil, err
	}
	return newIdentity(out), nil
}

// GCPIdentity is a GCP service account's identity token from the metadata server, audience
// "seal:<tenant>".
func GCPIdentity(tenant string) (*Identity, error) {
	if err := noNUL("tenant", tenant); err != nil {
		return nil, err
	}
	t := cString(tenant, false)
	defer free(t)
	var out *C.seal_identity
	if err := check(C.seal_identity_gcp(t, &out)); err != nil {
		return nil, err
	}
	return newIdentity(out), nil
}

// GitHubActionsIdentity is GitHub Actions OIDC (permissions: id-token: write): a fresh token
// for audience "seal:<tenant>" on every proof.
func GitHubActionsIdentity(tenant string) (*Identity, error) {
	if err := noNUL("tenant", tenant); err != nil {
		return nil, err
	}
	t := cString(tenant, false)
	defer free(t)
	var out *C.seal_identity
	if err := check(C.seal_identity_github_actions(t, &out)); err != nil {
		return nil, err
	}
	return newIdentity(out), nil
}

// AWSIdentity is an IAM role from the default AWS credential chain, proven by a presigned STS
// GetCallerIdentity. Only libraries built with the `aws` feature (build.sh --aws) have it;
// others return ErrBadRequest.
func AWSIdentity(ctx context.Context) (*Identity, error) {
	var out *C.seal_identity
	err := call(ctx, func(cancel *C.seal_cancel) *C.seal_error {
		return C.seal_identity_aws(cancel, &out)
	})
	if err != nil {
		return nil, err
	}
	return newIdentity(out), nil
}
