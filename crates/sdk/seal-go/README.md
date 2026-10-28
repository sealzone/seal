# seal.zone/go: the Seal SDK for Go

Use secrets without holding them. Anyone seals a secret for named apps; one of those apps starts a
session on the sealed blob and gets a stand-in, while the enclave injects the real secret on
the way to the upstream.

```sh
go get seal.zone/go
```

```go
import seal "seal.zone/go"

client, err := seal.FromEnv(ctx)

// Seal: required arguments positional, options after.
blob, err := client.Seal(ctx, secret, "https://api.openai.com/v1", []string{"checkout"},
    seal.WithHeader("x-api-key"))

// Use it: the app gets a stand-in key, the enclave injects the real one.
s, err := client.Session(ctx, blob, seal.WithKind(seal.KindHTTP))
defer s.Close(ctx)                       // ends the session everywhere
// point the app's HTTP client at s.URL(), with s.Key() where the real key would go
```

The same flow in Python is `seal.seal(secret, to=..., apps=[...])` and `seal.session(blob)`;
every SDK uses the same names and error codes.

`seal.FromEnv` reads `SEAL_ENDPOINT` (the tenant's enclave replicas, comma-separated),
`SEAL_TENANT` (`<tenant>` or `<tenant>@<root id>`) and the first workload identity found
(`SEAL_APP_KEY`, Azure managed identity with `SEAL_AZURE_AUDIENCE`, a Kubernetes projected
token, GCP, GitHub Actions). `seal.Connect(ctx, seal.Options{...})` sets any of them
explicitly: `Endpoints`, `Tenant`, `RootID`, `Identity` (`seal.AppKeyIdentity`,
`seal.AzureManagedIdentity`, `seal.KubernetesIdentity`, `seal.GCPIdentity`,
`seal.GitHubActionsIdentity`, `seal.AWSIdentity` in `--aws` builds) and `Trust`
(`seal.TrustFile("trust.json")` or `seal.TrustJSON(b)`). Every client verifies the enclave
before it sends anything. Anyone may seal; whether this workload may start sessions is decided
by the enclave from the tenant's grants.

## Sessions

`client.Session(ctx, blob, opts...)` returns a session of whichever kind the blob is: HTTP
(`URL`, `Key`) or database (`DSN`, `Protocol`). `seal.WithKind(seal.KindHTTP)` or
`seal.KindDatabase` asks for one and fails with `seal.ErrBadRequest` before anything is sent
if the blob is the other kind. Every session has `Info`, `Receipts`, `Extend` and `Close`.

- **The tunnel**: `URL` and `DSN` point at a local proxy on `127.0.0.1` that the SDK runs to
  the enclave; `Key` (and the DSN's password) is a stand-in worthless outside this process's
  tunnel. None of them change for the life of the session. The SDK extends the session before
  every expiry with a fresh identity proof; `Extend` does it now.
- **`Close`** ends the session on the server: every replica refuses its tokens from then on.
  If it fails, the end may not have reached every replica; call it again. A session
  garbage-collected without a successful close is ended in the background.

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

Every Seal error is a `*seal.Error` with `Code` (a `seal.ErrorCode`, the same wire names as
the other SDKs) and `Message`; `errors.Is(err, seal.ErrNotAllowed)` matches by code, with one
sentinel per code: `ErrExpired`, `ErrNotAllowed`, `ErrTierTooLow`, `ErrIntegrityFailed`,
`ErrUnavailable`, `ErrPolicyDenied`, `ErrBudgetExceeded`, `ErrSessionExpired`,
`ErrSessionEnded`, `ErrVerificationFailed`, `ErrBadRequest`, `ErrInternal`,
`ErrResealRequired`. `ErrVerificationFailed` means the enclave could not be verified; it is
never retried silently.

Calls block their goroutine. A context cancels its call: the call returns `ctx.Err()` at once
and the core drops what it was doing (a session it was starting is ended in the background).

Not in this version: the session callbacks of the other SDKs (`reload_with`, `on_reseal`,
`endpoint_reporter`). Sessions report the hash of the running executable, the core's default,
or what the seal host agent says about this process with `seal.WithHostAgent()` (or
`seal.WithHostAgentAt(socket, appKey)`).

## How it is built

The package is a cgo binding over the Rust SDK core through `seal-ffi`
(`crates/sdk/seal-ffi`, its C ABI in `seal.h`); attestation, identity proofs and tunnels are
the core's. cgo links the static library from `lib/<GOOS>_<GOARCH>/libseal_ffi.a` with the
header `lib/seal.h`. In this repository `build.sh` builds them (they are not committed); the
published module carries them prebuilt.

```sh
crates/sdk/seal-go/build.sh               # release build for the host
crates/sdk/seal-go/build.sh --sim --debug # against the simulator, quick to build
cd crates/sdk/seal-go && go vet ./... && go test ./...
```

`go test` needs no simulator. `scripts/e2e.sh -k go_sdk` runs `examples/e2e` against a
simulated system (`tests/e2e/test_go_sdk.py`).
