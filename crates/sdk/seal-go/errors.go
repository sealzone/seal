package seal

// ErrorCode is the public error vocabulary; values are the wire names, as in every Seal SDK.
type ErrorCode string

const (
	// CodeExpired: the blob is past its expiry, or its tenant key version is retired.
	CodeExpired ErrorCode = "expired"
	// CodeNotAllowed: this identity may not do this (not in the blob's apps), or no workload
	// identity was found.
	CodeNotAllowed ErrorCode = "not_allowed"
	// CodeTierTooLow: the session would be weaker than WithMinTier.
	CodeTierTooLow ErrorCode = "tier_too_low"
	// CodeIntegrityFailed: the endpoint failed an integrity check, or its identity is suspended.
	CodeIntegrityFailed ErrorCode = "integrity_failed"
	// CodeUnavailable: Seal, or something it needs, could not be reached. Retryable.
	CodeUnavailable ErrorCode = "unavailable"
	// CodePolicyDenied: a request falls outside the blob's policy.
	CodePolicyDenied ErrorCode = "policy_denied"
	// CodeBudgetExceeded: a budget or rate limit is exhausted.
	CodeBudgetExceeded ErrorCode = "budget_exceeded"
	// CodeSessionExpired: the session token expired; the SDK restarts the session by itself.
	CodeSessionExpired ErrorCode = "session_expired"
	// CodeSessionEnded: the session was ended (closed, or by the enclave on an integrity
	// action). Start a new one.
	CodeSessionEnded ErrorCode = "session_ended"
	// CodeVerificationFailed: the enclave could not be verified. Never retried silently: it
	// may mean an attack.
	CodeVerificationFailed ErrorCode = "verification_failed"
	// CodeBadRequest: a bad argument (an invalid to, app name, header or pin, a malformed blob).
	CodeBadRequest ErrorCode = "bad_request"
	// CodeInternal: Seal itself failed.
	CodeInternal ErrorCode = "internal"
	// CodeResealRequired: the blob was sealed before the enclave's platform was enabled: seal
	// the secret again.
	CodeResealRequired ErrorCode = "reseal_required"
)

// Retryable reports whether trying again later may succeed.
func (c ErrorCode) Retryable() bool {
	return c == CodeUnavailable || c == CodeSessionExpired
}

// Error is every error from Seal: Code says what happened, Message the details. Compare with
// the sentinels: errors.Is(err, seal.ErrNotAllowed).
type Error struct {
	Code    ErrorCode
	Message string
}

func (e *Error) Error() string {
	if e.Message == "" {
		return "seal: " + string(e.Code)
	}
	return "seal: " + string(e.Code) + ": " + e.Message
}

// Is matches a sentinel (an Error without a message) of the same code.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Code == e.Code && (t.Message == "" || t.Message == e.Message)
}

// Retryable reports whether trying again later may succeed.
func (e *Error) Retryable() bool {
	return e.Code.Retryable()
}

// Sentinels, one per ErrorCode, for errors.Is.
var (
	ErrExpired            = &Error{Code: CodeExpired}
	ErrNotAllowed         = &Error{Code: CodeNotAllowed}
	ErrTierTooLow         = &Error{Code: CodeTierTooLow}
	ErrIntegrityFailed    = &Error{Code: CodeIntegrityFailed}
	ErrUnavailable        = &Error{Code: CodeUnavailable}
	ErrPolicyDenied       = &Error{Code: CodePolicyDenied}
	ErrBudgetExceeded     = &Error{Code: CodeBudgetExceeded}
	ErrSessionExpired     = &Error{Code: CodeSessionExpired}
	ErrSessionEnded       = &Error{Code: CodeSessionEnded}
	ErrVerificationFailed = &Error{Code: CodeVerificationFailed}
	ErrBadRequest         = &Error{Code: CodeBadRequest}
	ErrInternal           = &Error{Code: CodeInternal}
	ErrResealRequired     = &Error{Code: CodeResealRequired}
)
