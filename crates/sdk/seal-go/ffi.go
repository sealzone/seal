package seal

// The cgo side: linking seal-ffi (crates/sdk/seal-ffi), and running its calls.
//
// build.sh builds the static library and puts it, with seal.h, where these directives look:
// lib/seal.h and lib/<GOOS>_<GOARCH>/libseal_ffi.a. The system libraries are what
// `rustc --print native-static-libs` lists for the library.

/*
#cgo CFLAGS: -I${SRCDIR}/lib
#cgo linux,amd64 LDFLAGS: -L${SRCDIR}/lib/linux_amd64
#cgo linux,arm64 LDFLAGS: -L${SRCDIR}/lib/linux_arm64
#cgo darwin,amd64 LDFLAGS: -L${SRCDIR}/lib/darwin_amd64
#cgo darwin,arm64 LDFLAGS: -L${SRCDIR}/lib/darwin_arm64
#cgo LDFLAGS: -lseal_ffi
#cgo linux LDFLAGS: -lgcc_s -lutil -lrt -lpthread -lm -ldl -lc
#cgo darwin LDFLAGS: -framework Security -framework CoreFoundation -liconv -lm -lc
#include <stdlib.h>
#include "seal.h"
*/
import "C"

import (
	"context"
	"strings"
	"unsafe"
)

// codeCanceled is what seal-ffi reports when a call's cancel token fired.
const codeCanceled = "canceled"

// call runs one blocking seal-ffi call, cancelling it when ctx is done. A call cancelled that
// way returns ctx.Err(); the work it was doing is dropped in the library (a session it was
// starting is ended in the background).
func call(ctx context.Context, f func(cancel *C.seal_cancel) *C.seal_error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var cancel *C.seal_cancel
	if ctx.Done() != nil {
		cancel = C.seal_cancel_new()
		done, stopped := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(stopped)
			select {
			case <-ctx.Done():
				C.seal_cancel_cancel(cancel)
			case <-done:
			}
		}()
		// The watcher must be gone before the token is freed.
		defer func() {
			close(done)
			<-stopped
			C.seal_cancel_free(cancel)
		}()
	}
	err := takeError(f(cancel))
	if err != nil && err.Code == codeCanceled && ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		return err
	}
	return nil
}

// takeError converts and frees an error from seal-ffi; nil stays nil.
func takeError(e *C.seal_error) *Error {
	if e == nil {
		return nil
	}
	defer C.seal_error_free(e)
	return &Error{Code: ErrorCode(C.GoString(e.code)), Message: C.GoString(e.message)}
}

// check is takeError as an error, keeping a nil interface nil.
func check(e *C.seal_error) error {
	if err := takeError(e); err != nil {
		return err
	}
	return nil
}

// takeString copies and frees a string from seal-ffi.
func takeString(s *C.char) string {
	if s == nil {
		return ""
	}
	defer C.seal_string_free(s)
	return C.GoString(s)
}

// noNUL is a bad_request error when a string argument holds a NUL byte, which C would
// silently cut it at.
func noNUL(what string, values ...string) error {
	for _, v := range values {
		if strings.IndexByte(v, 0) >= 0 {
			return &Error{Code: CodeBadRequest, Message: what + " contains a NUL byte"}
		}
	}
	return nil
}

// cString is a C copy of s; free it with C.free. "" is NULL when optional.
func cString(s string, optional bool) *C.char {
	if optional && s == "" {
		return nil
	}
	return C.CString(s)
}

func free(s *C.char) {
	if s != nil {
		C.free(unsafe.Pointer(s))
	}
}

// bytesArg points at b's bytes for the duration of a call (cgo allows Go memory without Go
// pointers in it); NULL for an empty slice.
func bytesArg(b []byte) (*C.uint8_t, C.size_t) {
	if len(b) == 0 {
		return nil, 0
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0])), C.size_t(len(b))
}
