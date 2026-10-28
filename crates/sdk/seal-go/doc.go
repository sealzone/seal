// Package seal is the Seal SDK for Go: use secrets without holding them.
//
//	client, err := seal.FromEnv(ctx)
//
//	// Seal (anyone may): required arguments positional, options after.
//	blob, err := client.Seal(ctx, secret, "https://api.openai.com/v1", []string{"checkout"},
//		seal.WithHeader("x-api-key"))
//
//	// Use it (needs an app grant): the app gets a stand-in key, the enclave injects the real one.
//	s, err := client.Session(ctx, blob, seal.WithKind(seal.KindHTTP))
//	defer s.Close(ctx)
//	req.Header.Set("x-api-key", s.Key()) // requests go to s.URL()
//
//	client.Signal(ctx, "edr-alert", seal.SeverityHigh)
//
// FromEnv reads SEAL_ENDPOINT, SEAL_TENANT and the first workload identity found; Connect
// takes explicit Options. Every client verifies the enclave before it sends anything.
// Anyone may seal; whether this workload may start sessions is decided by the enclave from
// the tenant's grants, never by the SDK.
//
// Errors are *Error values with a Code; errors.Is(err, seal.ErrNotAllowed) and the other
// sentinels match by code.
//
// The package is a cgo binding over the Rust SDK core (libseal_ffi, crates/sdk/seal-ffi):
// attestation, identity proofs and tunnels are the core's. Calls block their goroutine. A
// context passed to a call cancels it: the call returns ctx.Err() at once and the core drops
// what it was doing (a session it was starting is ended in the background). Live sessions'
// tunnels run on the core's own threads, not on goroutines.
package seal
