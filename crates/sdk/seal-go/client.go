package seal

/*
#include <stdlib.h>
#include "seal.h"
*/
import "C"

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"time"
)

// Client is a verified connection to the tenant's enclaves, acting as one workload identity.
// Safe for concurrent use; one per process is enough.
type Client struct {
	ptr *C.seal_client
}

// Options configures Connect. Anything unset comes from the environment, as FromEnv.
type Options struct {
	// Endpoints are the tenant's enclave replicas, e.g. "https://10.0.1.4:8443". Default:
	// SEAL_ENDPOINT (comma-separated).
	Endpoints []string
	// Tenant is "<tenant>" or "<tenant>@<root id>". Default: SEAL_TENANT.
	Tenant string
	// RootID is the tenant's root chain; enclaves serving another root are refused.
	RootID string
	// Identity is what the client proves itself as. Default: the first workload identity the
	// environment provides.
	Identity *Identity
	// Trust is the release trust (trust.json). Default: the one the library was built with.
	Trust *Trust
}

// Trust is a release trust: TrustFile or TrustJSON.
type Trust struct {
	path string
	json []byte
}

// TrustFile is the release trust in the JSON file at path, read at Connect.
func TrustFile(path string) *Trust { return &Trust{path: path} }

// TrustJSON is the release trust's JSON.
func TrustJSON(b []byte) *Trust { return &Trust{json: b} }

func (t *Trust) bytes() ([]byte, error) {
	if t.path == "" {
		return t.json, nil
	}
	b, err := os.ReadFile(t.path)
	if err != nil {
		return nil, fmt.Errorf("seal: reading the release trust: %w", err)
	}
	return b, nil
}

// FromEnv verifies the enclave and returns a client configured from the environment:
// SEAL_ENDPOINT (the tenant's enclave replicas, comma-separated), SEAL_TENANT ("<tenant>" or
// "<tenant>@<root id>") and the first workload identity found (SEAL_APP_KEY, Azure managed
// identity with SEAL_AZURE_AUDIENCE, a Kubernetes projected token, GCP, GitHub Actions).
func FromEnv(ctx context.Context) (*Client, error) {
	return Connect(ctx, Options{})
}

// Connect verifies the enclave and returns a client. Every client verifies the enclave before
// it sends anything. Anyone may seal; whether this workload may start sessions is decided by
// the enclave from the tenant's grants.
func Connect(ctx context.Context, opts Options) (*Client, error) {
	options, err := json.Marshal(struct {
		Endpoints []string `json:"endpoints,omitempty"`
		Tenant    string   `json:"tenant,omitempty"`
		RootID    string   `json:"root_id,omitempty"`
	}{opts.Endpoints, opts.Tenant, opts.RootID})
	if err != nil {
		return nil, err
	}
	var trust []byte
	if opts.Trust != nil {
		if trust, err = opts.Trust.bytes(); err != nil {
			return nil, err
		}
		if len(trust) == 0 {
			return nil, &Error{Code: CodeBadRequest, Message: "trust is empty"}
		}
	}
	var identity *C.seal_identity
	if opts.Identity != nil {
		identity = opts.Identity.ptr
		defer runtime.KeepAlive(opts.Identity)
	}
	o := cString(string(options), false)
	defer free(o)
	var out *C.seal_client
	err = call(ctx, func(cancel *C.seal_cancel) *C.seal_error {
		t, n := bytesArg(trust)
		return C.seal_client_connect(o, identity, t, n, cancel, &out)
	})
	if err != nil {
		return nil, err
	}
	c := &Client{ptr: out}
	runtime.SetFinalizer(c, func(c *Client) { C.seal_client_free(c.ptr) })
	return c, nil
}

// Tenant is the tenant this client serves.
func (c *Client) Tenant() string {
	defer runtime.KeepAlive(c)
	var out *C.char
	if err := check(C.seal_client_tenant(c.ptr, &out)); err != nil {
		return ""
	}
	return takeString(out)
}

// SealOption configures Client.Seal.
type SealOption func(*sealOptions)

type sealOptions struct {
	To           string   `json:"to"`
	Apps         []string `json:"apps"`
	Header       string   `json:"header,omitempty"`
	Format       string   `json:"format,omitempty"`
	Pins         []string `json:"pins,omitempty"`
	Expires      int64    `json:"expires,omitempty"`
	Methods      []string `json:"methods,omitempty"`
	Deny         []string `json:"deny,omitempty"`
	SealedOnly   bool     `json:"sealed_only,omitempty"`
	HardenedOnly bool     `json:"hardened_only,omitempty"`
}

// WithHeader is the HTTP header that carries the secret. Default "authorization".
func WithHeader(header string) SealOption { return func(o *sealOptions) { o.Header = header } }

// WithFormat is the HTTP header value, with "{key}" where the secret goes. Default
// "Bearer {key}" for authorization, "{key}" otherwise.
func WithFormat(format string) SealOption { return func(o *sealOptions) { o.Format = format } }

// WithPin requires this upstream key ("sha256/<base64>") in the upstream's certificate chain.
// Give it up to 4 times, e.g. for the current and the next key.
func WithPin(pin string) SealOption { return func(o *sealOptions) { o.Pins = append(o.Pins, pin) } }

// WithExpiry makes the blob stop working at t, on every copy.
func WithExpiry(t time.Time) SealOption { return func(o *sealOptions) { o.Expires = t.Unix() } }

// WithMethods allows only these HTTP methods. Default: any.
func WithMethods(methods ...string) SealOption {
	return func(o *sealOptions) { o.Methods = append(o.Methods, methods...) }
}

// WithDeny refuses HTTP paths under this prefix, even inside to (e.g. key-management
// endpoints). Give it once per prefix.
func WithDeny(pathPrefix string) SealOption {
	return func(o *sealOptions) { o.Deny = append(o.Deny, pathPrefix) }
}

// WithSealedOnly lets only enclaves on the sealed platform tier open the blob.
func WithSealedOnly() SealOption { return func(o *sealOptions) { o.SealedOnly = true } }

// WithHardenedOnly lets only hardened sessions use the blob: the endpoint presents verified
// integrity evidence at every start and extend.
func WithHardenedOnly() SealOption { return func(o *sealOptions) { o.HardenedOnly = true } }

// Seal seals secret so only the named apps can use it, and only with to (https://,
// postgres://, clickhouse://, rediss://). It returns the portable blob text ("seal1.…"),
// safe to store anywhere. Anyone may seal: it needs no identity or grant.
func (c *Client) Seal(ctx context.Context, secret []byte, to string, apps []string, opts ...SealOption) (string, error) {
	blob, _, err := c.seal(ctx, secret, to, apps, opts, false)
	return blob, err
}

// SealWithReceipt is Seal, also returning where telemetry recorded the seal. Keep receipts
// (AppendReceipts) for `seal telemetry --receipts`.
func (c *Client) SealWithReceipt(ctx context.Context, secret []byte, to string, apps []string, opts ...SealOption) (string, TelemetryReceipt, error) {
	return c.seal(ctx, secret, to, apps, opts, true)
}

func (c *Client) seal(ctx context.Context, secret []byte, to string, apps []string, opts []SealOption, withReceipt bool) (string, TelemetryReceipt, error) {
	defer runtime.KeepAlive(c)
	o := sealOptions{To: to, Apps: apps}
	if o.Apps == nil {
		o.Apps = []string{}
	}
	for _, opt := range opts {
		opt(&o)
	}
	options, err := json.Marshal(o)
	if err != nil {
		return "", TelemetryReceipt{}, err
	}
	co := cString(string(options), false)
	defer free(co)
	var blob, receipt *C.char
	defer func() { C.seal_string_free(blob); C.seal_string_free(receipt) }()
	err = call(ctx, func(cancel *C.seal_cancel) *C.seal_error {
		s, n := bytesArg(secret)
		receiptOut := &receipt
		if !withReceipt {
			receiptOut = nil
		}
		return C.seal_client_seal(c.ptr, s, n, co, cancel, &blob, receiptOut)
	})
	if err != nil {
		return "", TelemetryReceipt{}, err
	}
	var r TelemetryReceipt
	if withReceipt {
		if err := json.Unmarshal([]byte(C.GoString(receipt)), &r); err != nil {
			return "", TelemetryReceipt{}, fmt.Errorf("seal: reading the receipt: %w", err)
		}
	}
	return C.GoString(blob), r, nil
}

// Severity is how bad a Signal is.
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Signal signals that this workload's own endpoint may be compromised. It names only this
// identity; under the tenant's integrity policy it may suspend the identity at once. code is
// opaque to Seal ([a-z0-9-.], 1 to 64 characters).
func (c *Client) Signal(ctx context.Context, code string, severity Severity) error {
	if err := noNUL("code or severity", code, string(severity)); err != nil {
		return err
	}
	defer runtime.KeepAlive(c)
	cc, cs := cString(code, false), cString(string(severity), false)
	defer free(cc)
	defer free(cs)
	return call(ctx, func(cancel *C.seal_cancel) *C.seal_error {
		return C.seal_client_signal(c.ptr, cc, cs, cancel)
	})
}
