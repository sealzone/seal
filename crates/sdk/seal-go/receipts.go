package seal

/*
#include <stdlib.h>
#include "seal.h"
*/
import "C"

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// TelemetryReceipt is where telemetry recorded a seal or a session start. A client that keeps
// its receipts can prove the control plane withheld their entries, even a whole stream.
type TelemetryReceipt struct {
	// Stream is the telemetry stream.
	Stream [16]byte
	Entry  uint64
}

type receiptJSON struct {
	Stream string `json:"stream"`
	Entry  uint64 `json:"entry"`
}

// MarshalJSON is one line of a receipts file: {"stream":"<base64url>","entry":n}.
func (r TelemetryReceipt) MarshalJSON() ([]byte, error) {
	return json.Marshal(receiptJSON{Stream: base64.RawURLEncoding.EncodeToString(r.Stream[:]), Entry: r.Entry})
}

func (r *TelemetryReceipt) UnmarshalJSON(b []byte) error {
	var j receiptJSON
	if err := json.Unmarshal(b, &j); err != nil {
		return err
	}
	stream, err := base64.RawURLEncoding.DecodeString(j.Stream)
	if err != nil || len(stream) != len(r.Stream) {
		return fmt.Errorf("seal: a receipt's stream must be 16 bytes of base64url, not %q", j.Stream)
	}
	copy(r.Stream[:], stream)
	r.Entry = j.Entry
	return nil
}

func (r TelemetryReceipt) String() string {
	return fmt.Sprintf("TelemetryReceipt(stream=%x, entry=%d)", r.Stream, r.Entry)
}

// AppendReceipts appends receipts to the file at path as JSON lines, the format
// `seal telemetry --receipts` reads, creating the file when missing. One write per call, so
// processes appending to one file keep whole lines.
func AppendReceipts(path string, receipts []TelemetryReceipt) error {
	if err := noNUL("path", path); err != nil {
		return err
	}
	if receipts == nil {
		receipts = []TelemetryReceipt{}
	}
	text, err := json.Marshal(receipts)
	if err != nil {
		return err
	}
	cp, ct := cString(path, false), cString(string(text), false)
	defer free(cp)
	defer free(ct)
	return check(C.seal_append_receipts(cp, ct))
}
