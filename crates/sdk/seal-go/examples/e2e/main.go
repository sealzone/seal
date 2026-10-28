// The Go SDK end to end, driven by tests/e2e/test_go_sdk.py against a simulated system. The
// environment configures the client, as it would an app (SEAL_ENDPOINT, SEAL_TENANT,
// SEAL_APP_KEY; SEAL_TRUST for a sim build). Prints one JSON object.
//
//	e2e seal <to> <receipts file>   as anyone: seal stdin for app checkout
//	e2e app <blob>                  as the app: a session on the blob, through the tunnel
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	seal "seal.zone/go"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var out any
	var err error
	switch {
	case len(os.Args) == 4 && os.Args[1] == "seal":
		out, err = stranger(ctx, os.Args[2], os.Args[3])
	case len(os.Args) == 3 && os.Args[1] == "app":
		out, err = app(ctx, os.Args[2])
	default:
		err = errors.New("usage: e2e seal <to> <receipts file> | e2e app <blob>")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	json.NewEncoder(os.Stdout).Encode(out)
}

// stranger seals stdin, as anyone may, and keeps the receipt.
func stranger(ctx context.Context, to, receipts string) (any, error) {
	secret, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, err
	}
	client, err := seal.FromEnv(ctx)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	blob, receipt, err := client.SealWithReceipt(ctx, secret, to, []string{"checkout"},
		seal.WithFormat("Bearer {key}"), seal.WithMethods("GET"), seal.WithDeny("/v1/admin"))
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	if err := seal.AppendReceipts(receipts, []seal.TelemetryReceipt{receipt}); err != nil {
		return nil, err
	}
	// Anyone may seal; only the blob's apps may use it.
	_, err = client.Session(ctx, blob)
	return map[string]any{
		"tenant":             client.Tenant(),
		"blob":               blob,
		"receipt":            receipt,
		"stranger_session":   code(err),
		"is_not_allowed":     errors.Is(err, seal.ErrNotAllowed),
		"bad_seal":           code(sealBad(ctx, client, secret, to)),
		"bad_signal_code":    code(client.Signal(ctx, "Not Valid!", seal.SeverityHigh)),
		"bad_signal_level":   code(client.Signal(ctx, "edr-alert", "severe")),
		"trust_file_missing": trustMissing(ctx),
	}, nil
}

func sealBad(ctx context.Context, client *seal.Client, secret []byte, to string) error {
	_, err := client.Seal(ctx, secret, to, []string{"Not An App!"})
	return err
}

func trustMissing(ctx context.Context) bool {
	_, err := seal.Connect(ctx, seal.Options{Trust: seal.TrustFile("/nonexistent/trust.json")})
	return errors.Is(err, os.ErrNotExist)
}

// call is one request's outcome.
type call struct {
	Status int    `json:"status"`
	Body   string `json:"body"`
	Error  string `json:"error,omitempty"`
}

// get is `GET <url>/models` with `Authorization: Bearer <key>`.
func get(client *http.Client, url, key string) call {
	req, err := http.NewRequest("GET", strings.TrimRight(url, "/")+"/models", nil)
	if err != nil {
		return call{Error: err.Error()}
	}
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := client.Do(req)
	if err != nil {
		return call{Error: err.Error()}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return call{Status: resp.StatusCode, Body: string(body)}
}

// app uses the blob through a session's local tunnel.
func app(ctx context.Context, blob string) (any, error) {
	client, err := seal.FromEnv(ctx)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	out := map[string]any{"tenant": client.Tenant()}

	// The wrong kind fails before anything is sent.
	_, err = client.Session(ctx, blob, seal.WithKind(seal.KindDatabase))
	out["wrong_kind"] = code(err)

	s, err := client.Session(ctx, blob, seal.WithKind(seal.KindHTTP))
	if err != nil {
		return nil, fmt.Errorf("session: %w", err)
	}
	http := &http.Client{}
	key := s.Key()
	first := get(http, s.URL(), key)
	if err := s.Extend(ctx); err != nil {
		return nil, fmt.Errorf("extend: %w", err)
	}
	second := get(http, s.URL(), s.Key())
	receipts, err := s.Receipts()
	if err != nil {
		return nil, err
	}
	info := s.Info()
	url, lastKey := s.URL(), s.Key()
	if err := s.Close(ctx); err != nil {
		return nil, fmt.Errorf("close: %w", err)
	}
	http.CloseIdleConnections()
	out["tunnel"] = map[string]any{
		"kind":         s.Kind(),
		"url":          url,
		"keys":         []string{key, lastKey},
		"calls":        []call{first, second},
		"after_close":  get(http, url, lastKey),
		"receipts":     len(receipts),
		"tier":         info.Tier,
		"app":          info.App,
		"expires_in":   int(time.Until(info.ExpiresAt).Seconds()),
		"extend_after": code(s.Extend(ctx)),
	}

	// A cancelled call returns at once: connect to a listener that never answers.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
		}
	}()
	short, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = seal.Connect(short, seal.Options{Endpoints: []string{"https://" + listener.Addr().String()}})
	out["canceled"] = map[string]any{
		"deadline_exceeded": errors.Is(err, context.DeadlineExceeded),
		"error":             fmt.Sprint(err),
		"ms":                time.Since(start).Milliseconds(),
	}
	return out, nil
}

// code is an error's seal code, "" for nil, or its text for another error.
func code(err error) string {
	var e *seal.Error
	switch {
	case err == nil:
		return ""
	case errors.As(err, &e):
		return string(e.Code)
	default:
		return err.Error()
	}
}
