package seal

/*
#include <stdlib.h>
#include "seal.h"
*/
import "C"

import (
	"context"
	"encoding/json"
	"runtime"
	"time"
)

// Kind is what a blob is for: HTTP or a database.
type Kind string

const (
	KindHTTP     Kind = "http"
	KindDatabase Kind = "database"
)

// Tier is how sure Seal is about who is calling; each tier implies the ones below it.
type Tier string

const (
	TierBase     Tier = "base"
	TierHardened Tier = "hardened"
)

// Protocol is a database session's wire protocol.
type Protocol string

const (
	ProtocolPostgres   Protocol = "postgres"
	ProtocolRedis      Protocol = "redis"
	ProtocolClickHouse Protocol = "click_house"
)

// SessionOption configures Client.Session.
type SessionOption func(*sessionOptions)

type sessionOptions struct {
	Kind      Kind       `json:"kind,omitempty"`
	MinTier   Tier       `json:"min_tier,omitempty"`
	HostAgent *hostAgent `json:"host_agent,omitempty"`
}

type hostAgent struct {
	Socket string `json:"socket,omitempty"`
	AppKey string `json:"app_key,omitempty"`
}

// WithKind asks for a session of this kind; a blob of the other kind fails with ErrBadRequest
// before anything is sent.
func WithKind(kind Kind) SessionOption { return func(o *sessionOptions) { o.Kind = kind } }

// WithMinTier refuses to start unless the session is at least this strong.
func WithMinTier(tier Tier) SessionOption { return func(o *sessionOptions) { o.MinTier = tier } }

// WithHostAgent reports through the seal host agent (App Integrity add-on) at every start and
// extend instead of the executable's hash: the artifact the agent hashed outside this process,
// and its evidence signed over the request's challenge. It reads SEAL_AGENT_SOCKET (default
// /run/seal/agent.sock) and the app key from SEAL_APP_KEY, and falls back to the executable's
// hash when the agent does not answer.
func WithHostAgent() SessionOption {
	return func(o *sessionOptions) { o.HostAgent = &hostAgent{} }
}

// WithHostAgentAt is WithHostAgent with the agent's socket and the app key given.
func WithHostAgentAt(socket, appKey string) SessionOption {
	return func(o *sessionOptions) { o.HostAgent = &hostAgent{Socket: socket, AppKey: appKey} }
}

// Session is a session on a blob: an HTTP session (URL, Key) or a database session (DSN,
// Protocol), whichever the blob is. Safe for concurrent use. Close it when done; a session
// garbage-collected without a successful Close is ended in the background.
//
// URL and DSN point at a local proxy on 127.0.0.1 that the SDK runs to the enclave, and Key
// (and the DSN's password) is a stand-in worthless outside this process's tunnel. None of them
// change for the life of the session; the SDK extends the session before every expiry.
type Session struct {
	ptr *C.seal_session
}

// Session starts a session on blob: the enclave opens it and the app gets a stand-in. Needs
// an app grant listed in the blob's policy.
func (c *Client) Session(ctx context.Context, blob string, opts ...SessionOption) (*Session, error) {
	if err := noNUL("blob", blob); err != nil {
		return nil, err
	}
	defer runtime.KeepAlive(c)
	var o sessionOptions
	for _, opt := range opts {
		opt(&o)
	}
	options, err := json.Marshal(o)
	if err != nil {
		return nil, err
	}
	cb, co := cString(blob, false), cString(string(options), false)
	defer free(cb)
	defer free(co)
	var out *C.seal_session
	err = call(ctx, func(cancel *C.seal_cancel) *C.seal_error {
		return C.seal_client_session(c.ptr, cb, co, cancel, &out)
	})
	if err != nil {
		return nil, err
	}
	s := &Session{ptr: out}
	runtime.SetFinalizer(s, func(s *Session) { C.seal_session_free(s.ptr) })
	return s, nil
}

// SessionInfo is a session's id, tiers, tenant, app, blob id and expiry.
type SessionInfo struct {
	// SessionID is base64url, as telemetry shows it.
	SessionID string
	// Platform is "sim" or "sealed".
	Platform string
	Tier     Tier
	Tenant   string
	App      string
	BlobID   string
	// ExpiresAt moves with every Extend; a tunnel's own extends keep the session alive
	// without changing it.
	ExpiresAt time.Time
}

// view is seal_session_view's JSON.
type view struct {
	Kind     Kind     `json:"kind"`
	URL      string   `json:"url"`
	Protocol Protocol `json:"protocol"`
	Info     struct {
		SessionID string `json:"session_id"`
		Platform  string `json:"platform"`
		Tier      Tier   `json:"tier"`
		Tenant    string `json:"tenant"`
		App       string `json:"app"`
		BlobID    string `json:"blob_id"`
		ExpiresAt int64  `json:"expires_at"`
	} `json:"info"`
}

// view reads the session's current state; it never waits on the network.
func (s *Session) view() view {
	defer runtime.KeepAlive(s)
	var out *C.char
	var v view
	if err := check(C.seal_session_view(s.ptr, &out)); err != nil {
		return v
	}
	_ = json.Unmarshal([]byte(takeString(out)), &v)
	return v
}

// Kind is KindHTTP or KindDatabase.
func (s *Session) Kind() Kind { return s.view().Kind }

// URL is, for HTTP sessions, the local tunnel (http://127.0.0.1:port); its path continues the
// sealed destination's. Empty for database sessions.
func (s *Session) URL() string { return s.view().URL }

// Key is, for HTTP sessions, the stand-in key to send where the real key would go (the
// sealed header). Empty for database sessions.
func (s *Session) Key() string {
	if s.Kind() != KindHTTP {
		return ""
	}
	return s.credential()
}

// DSN is, for database sessions, a complete connection string for the app's driver, through
// the local tunnel. Empty for HTTP sessions.
func (s *Session) DSN() string {
	if s.Kind() != KindDatabase {
		return ""
	}
	return s.credential()
}

// credential is the key (HTTP) or the DSN (database), read on its own so it is copied only
// when asked for.
func (s *Session) credential() string {
	defer runtime.KeepAlive(s)
	var out *C.char
	if err := check(C.seal_session_credential(s.ptr, &out)); err != nil {
		return ""
	}
	return takeString(out)
}

// Protocol is, for database sessions, ProtocolPostgres, ProtocolRedis or ProtocolClickHouse.
func (s *Session) Protocol() Protocol { return s.view().Protocol }

// Info is the session's id, tiers, tenant, app, blob id and expiry.
func (s *Session) Info() SessionInfo {
	i := s.view().Info
	return SessionInfo{
		SessionID: i.SessionID,
		Platform:  i.Platform,
		Tier:      i.Tier,
		Tenant:    i.Tenant,
		App:       i.App,
		BlobID:    i.BlobID,
		ExpiresAt: time.Unix(i.ExpiresAt, 0),
	}
}

// Receipts is where telemetry recorded the session's start and every restart, oldest first.
// Keep them (AppendReceipts) for `seal telemetry --receipts`.
func (s *Session) Receipts() ([]TelemetryReceipt, error) {
	defer runtime.KeepAlive(s)
	var out *C.char
	if err := check(C.seal_session_receipts(s.ptr, &out)); err != nil {
		return nil, err
	}
	var receipts []TelemetryReceipt
	if err := json.Unmarshal([]byte(takeString(out)), &receipts); err != nil {
		return nil, err
	}
	return receipts, nil
}

// Extend extends the session now with a fresh identity proof and moves Info().ExpiresAt. The
// tunnel also extends the session by itself before every expiry.
func (s *Session) Extend(ctx context.Context) error {
	defer runtime.KeepAlive(s)
	return call(ctx, func(cancel *C.seal_cancel) *C.seal_error {
		return C.seal_session_extend(s.ptr, cancel)
	})
}

// Close ends the session on the server: every replica refuses its tokens from then on. The
// first call stops extending, and the tunnel closes once the end request is answered,
// whatever the answer. An error means the end may not have reached every replica: call Close
// again. If ctx ends first, the tunnel stays open until Close is called again (or the
// session is collected). Once Close succeeds, further calls do nothing.
func (s *Session) Close(ctx context.Context) error {
	defer runtime.KeepAlive(s)
	return call(ctx, func(cancel *C.seal_cancel) *C.seal_error {
		return C.seal_session_close(s.ptr, cancel)
	})
}
