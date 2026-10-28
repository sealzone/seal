package seal

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These tests need the library (build.sh) but no simulator: they stop before the network.

func TestErrorsMatchTheirSentinel(t *testing.T) {
	err := error(&Error{Code: CodeNotAllowed, Message: "not yours"})
	if !errors.Is(err, ErrNotAllowed) || errors.Is(err, ErrExpired) {
		t.Fatalf("errors.Is by code: %v", err)
	}
	var e *Error
	if !errors.As(err, &e) || e.Message != "not yours" || e.Retryable() {
		t.Fatalf("errors.As: %#v", e)
	}
	if !ErrUnavailable.Retryable() || !ErrSessionExpired.Retryable() {
		t.Fatal("unavailable and session_expired are retryable")
	}
	if got := err.Error(); got != "seal: not_allowed: not yours" {
		t.Fatalf("Error(): %q", got)
	}
}

func TestABadAppKeyIsABadRequest(t *testing.T) {
	_, err := AppKeyIdentity("not-a-key")
	if !errors.Is(err, ErrBadRequest) {
		t.Fatalf("got %v", err)
	}
}

func TestIdentitiesReportTheirKind(t *testing.T) {
	azure, err := AzureManagedIdentity("api://seal", "")
	if err != nil {
		t.Fatal(err)
	}
	k8s, err := KubernetesIdentity("")
	if err != nil {
		t.Fatal(err)
	}
	gcp, err := GCPIdentity("acme")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []*Identity{azure, k8s, gcp} {
		if id.Kind() == "" {
			t.Fatal("an identity without a kind")
		}
	}
	if _, err := GCPIdentity("Not A Tenant!"); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("a bad tenant: %v", err)
	}
}

func TestConnectRefusesBadOptionsBeforeTheNetwork(t *testing.T) {
	ctx := context.Background()
	if _, err := Connect(ctx, Options{Endpoints: []string{"not a url"}, Tenant: "acme"}); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("a bad endpoint: %v", err)
	}
	if _, err := Connect(ctx, Options{Endpoints: []string{"https://localhost:1"}, Tenant: "acme@x"}); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("a bad pin: %v", err)
	}
	trust := TrustJSON([]byte("{not json"))
	if _, err := Connect(ctx, Options{Endpoints: []string{"https://localhost:1"}, Tenant: "acme", Trust: trust}); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("bad trust: %v", err)
	}
	if _, err := Connect(ctx, Options{Trust: TrustFile(filepath.Join(t.TempDir(), "missing.json"))}); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a missing trust file: %v", err)
	}
	// An empty trust is refused, never replaced by the default one.
	for _, empty := range []*Trust{TrustJSON(nil), TrustJSON([]byte{}), TrustFile(os.DevNull)} {
		if _, err := Connect(ctx, Options{Endpoints: []string{"https://localhost:1"}, Tenant: "acme", Trust: empty}); !errors.Is(err, ErrBadRequest) {
			t.Fatalf("an empty trust: %v", err)
		}
	}
}

func TestStringsWithNULAreRefusedNotCut(t *testing.T) {
	if _, err := AppKeyIdentity("sealak_x\x00junk"); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("an app key with a NUL: %v", err)
	}
	if err := AppendReceipts(filepath.Join(t.TempDir(), "r.jsonl\x00.bak"), nil); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("a path with a NUL: %v", err)
	}
}

func TestFromEnvNeedsAnEndpoint(t *testing.T) {
	t.Setenv("SEAL_ENDPOINT", "")
	os.Unsetenv("SEAL_ENDPOINT")
	if _, err := FromEnv(context.Background()); !errors.Is(err, ErrBadRequest) || !strings.Contains(err.Error(), "SEAL_ENDPOINT") {
		t.Fatalf("got %v", err)
	}
}

func TestADoneContextReturnsItsError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := FromEnv(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}

func TestReceiptsAreTheCoresJSONLines(t *testing.T) {
	r := TelemetryReceipt{Entry: 3}
	for i := range r.Stream {
		r.Stream[i] = 0xfb
	}
	line, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(line) != `{"stream":"-_v7-_v7-_v7-_v7-_v7-w","entry":3}` {
		t.Fatalf("got %s", line)
	}
	var back TelemetryReceipt
	if err := json.Unmarshal(line, &back); err != nil || back != r {
		t.Fatalf("round trip: %v %v", back, err)
	}
	if err := json.Unmarshal([]byte(`{"stream":"AAAA","entry":1}`), &back); err == nil {
		t.Fatal("a short stream is refused")
	}

	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	if err := AppendReceipts(path, []TelemetryReceipt{r}); err != nil {
		t.Fatal(err)
	}
	if err := AppendReceipts(path, nil); err != nil {
		t.Fatal(err)
	}
	if err := AppendReceipts(path, []TelemetryReceipt{{Entry: 4}, r}); err != nil {
		t.Fatal(err)
	}
	text, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(text), "\n"), "\n")
	if len(lines) != 3 || lines[0] != string(line) || lines[2] != string(line) {
		t.Fatalf("got %q", text)
	}
}

func TestSessionOptionsEncodeAsTheABIReadsThem(t *testing.T) {
	var o sessionOptions
	if b, _ := json.Marshal(o); string(b) != `{}` {
		t.Fatalf("got %s", b)
	}
	for _, opt := range []SessionOption{WithKind(KindHTTP), WithMinTier(TierHardened)} {
		opt(&o)
	}
	b, _ := json.Marshal(o)
	if string(b) != `{"kind":"http","min_tier":"hardened"}` {
		t.Fatalf("got %s", b)
	}
	WithHostAgent()(&o)
	if b, _ = json.Marshal(o); !strings.HasSuffix(string(b), `"host_agent":{}}`) {
		t.Fatalf("got %s", b)
	}
	WithHostAgentAt("/run/agent.sock", "sealak_k")(&o)
	if b, _ = json.Marshal(o); !strings.HasSuffix(string(b), `"host_agent":{"socket":"/run/agent.sock","app_key":"sealak_k"}}`) {
		t.Fatalf("got %s", b)
	}
	s := sealOptions{To: "https://x", Apps: []string{"a"}}
	for _, opt := range []SealOption{WithHeader("x-api-key"), WithPin("p1"), WithPin("p2"), WithExpiry(time.Unix(42, 0)),
		WithMethods("GET"), WithDeny("/admin"), WithSealedOnly(), WithHardenedOnly()} {
		opt(&s)
	}
	b, _ = json.Marshal(s)
	want := `{"to":"https://x","apps":["a"],"header":"x-api-key","pins":["p1","p2"],"expires":42,"methods":["GET"],` +
		`"deny":["/admin"],"sealed_only":true,"hardened_only":true}`
	if string(b) != want {
		t.Fatalf("got %s", b)
	}
}
