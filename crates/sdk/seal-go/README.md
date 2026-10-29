# seal.zone/go: the Seal SDK for Go

Seal lets apps use secrets they never hold, because an attested enclave injects each secret
into the app's upstream traffic.

## Install

```sh
go get seal.zone/go
```

## Example

```go
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	seal "seal.zone/go"
)

func main() {
	ctx := context.Background()
	client, err := seal.FromEnv(ctx)
	if err != nil {
		log.Fatal(err)
	}

	// Seal the secret. Required arguments are positional, options come after.
	blob, err := client.Seal(ctx, []byte(os.Getenv("OPENAI_API_KEY")), "https://api.openai.com/v1",
		[]string{"checkout"}, seal.WithHeader("x-api-key"))
	if err != nil {
		log.Fatal(err)
	}

	// Use it. The app gets a stand-in key, and the enclave injects the real one.
	s, err := client.Session(ctx, blob, seal.WithKind(seal.KindHTTP))
	if err != nil {
		log.Fatal(err)
	}
	defer s.Close(ctx) // ends the session everywhere

	// Point the app's HTTP client at s.URL(), with s.Key() where the real key would go.
	fmt.Println(s.URL(), s.Key())
}
```

Anyone can seal a secret for named apps. One of those apps then starts a session on the
sealed blob and gets a stand-in. The enclave injects the real secret on the way to the
upstream.

The same flow in Python is `seal.seal(secret, to=..., apps=[...])` and `seal.session(blob)`.
Every SDK uses the same names and error codes.

## Configuration

`seal.FromEnv` reads three things from the environment:

- `SEAL_ENDPOINT`, the tenant's enclave replicas, comma-separated
- `SEAL_TENANT`, as `<tenant>@<root id>` (the console's Connect page shows it). Sealing
  needs the root id; sessions also work with `<tenant>` alone, since a blob names its root
- the first workload identity it finds: `SEAL_APP_KEY`, Azure managed identity with
  `SEAL_AZURE_AUDIENCE`, a Kubernetes projected token, GCP, or GitHub Actions

`seal.Connect(ctx, seal.Options{...})` sets any of them explicitly. The fields are:

- `Endpoints`
- `Tenant`
- `RootID`
- `Identity`: `seal.AppKeyIdentity`, `seal.AzureManagedIdentity`, `seal.KubernetesIdentity`,
  `seal.GCPIdentity`, `seal.GitHubActionsIdentity`, or `seal.AWSIdentity` in `--aws` builds
- `Trust`: `seal.TrustFile("trust.json")` or `seal.TrustJSON(b)`

Every client verifies the enclave before it sends anything. Anyone may seal. The enclave
decides from the tenant's grants whether this workload may start sessions.

## Sessions

`client.Session(ctx, blob, opts...)` returns a session of whichever kind the blob is. An HTTP
session has `URL` and `Key`. A database session has `DSN` and `Protocol`. To ask for one
kind, pass `seal.WithKind(seal.KindHTTP)` or `seal.KindDatabase`. If the blob is the other
kind, the call fails with `seal.ErrBadRequest` before anything is sent. Every session has
`Info`, `Receipts`, `Extend` and `Close`.

- **The tunnel.** `URL` and `DSN` point at a local proxy on `127.0.0.1` that the SDK runs to
  the enclave. `Key`, and the DSN's password, is a stand-in that is worthless outside this
  process's tunnel. None of them change for the life of the session. The SDK extends the
  session with a fresh identity proof before every expiry. `Extend` does it now.
- **`Close`** ends the session on the server, and from then on every replica refuses its
  tokens. If `Close` fails, the end may not have reached every replica, so call it again. A
  session that is garbage-collected without a successful close is ended in the background.

`seal.WithMinTier(seal.TierHardened)` refuses weaker sessions.

## Seal options, receipts, signals

```go
blob, receipt, err := client.SealWithReceipt(ctx, secret, to, apps,
    seal.WithFormat("Bearer {key}"), seal.WithMethods("GET", "POST"), seal.WithDeny("/v1/admin"),
    seal.WithPin("sha256/..."), seal.WithExpiry(time.Now().Add(90*24*time.Hour)),
    seal.WithSealedOnly(), seal.WithHardenedOnly())

receipts, err := s.Receipts()
seal.AppendReceipts("receipts.jsonl", append(receipts, receipt)) // for `seal telemetry --receipts`

client.Signal(ctx, "edr-alert", seal.SeverityHigh)
```

## Errors and contexts

Every Seal error is a `*seal.Error` with a `Code` and a `Message`. `Code` is a
`seal.ErrorCode`, with the same wire names as the other SDKs. `errors.Is(err,
seal.ErrNotAllowed)` matches by code. There is one sentinel per code:

`ErrExpired`, `ErrNotAllowed`, `ErrTierTooLow`, `ErrIntegrityFailed`, `ErrUnavailable`,
`ErrPolicyDenied`, `ErrBudgetExceeded`, `ErrSessionExpired`, `ErrSessionEnded`,
`ErrVerificationFailed`, `ErrBadRequest`, `ErrInternal`, `ErrResealRequired`.

`ErrVerificationFailed` means the enclave could not be verified. The SDK never retries it
silently.

Calls block their goroutine. A context cancels its call. The call returns `ctx.Err()` at
once, and the core drops what it was doing. If it was starting a session, that session is
ended in the background.

This version does not have the session callbacks of the other SDKs (`reload_with`,
`on_reseal`, `endpoint_reporter`). By default a session reports the hash of the running
executable. With `seal.WithHostAgent()` or `seal.WithHostAgentAt(socket, appKey)`, it reports
what the seal host agent says about this process instead.

## How it is built

The package is a cgo binding over the Rust SDK core, through `seal-ffi` (`crates/sdk/seal-ffi`,
with its C ABI in `seal.h`). Attestation, identity proofs and tunnels all run in the core.
cgo links the static library `lib/<GOOS>_<GOARCH>/libseal_ffi.a` with the header
`lib/seal.h`. In this repository, `build.sh` builds them, and they are not committed. The
published module carries them prebuilt.

```sh
crates/sdk/seal-go/build.sh               # release build for the host
crates/sdk/seal-go/build.sh --sim --debug # against the simulator, quick to build
cd crates/sdk/seal-go && go vet ./... && go test ./...
```

`go test` needs no simulator. `scripts/e2e.sh -k go_sdk` runs `examples/e2e` against a
simulated system (`tests/e2e/test_go_sdk.py`).
