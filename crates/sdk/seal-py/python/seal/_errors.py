"""Exceptions: one per `ErrorCode`, all `SealError`s carrying the code."""

from __future__ import annotations

import enum
from typing import Dict, Optional, Type


class ErrorCode(str, enum.Enum):
    """The public error vocabulary; values are the wire names."""

    Expired = "expired"
    NotAllowed = "not_allowed"
    TierTooLow = "tier_too_low"
    IntegrityFailed = "integrity_failed"
    Unavailable = "unavailable"
    PolicyDenied = "policy_denied"
    BudgetExceeded = "budget_exceeded"
    SessionExpired = "session_expired"
    SessionEnded = "session_ended"
    VerificationFailed = "verification_failed"
    BadRequest = "bad_request"
    Internal = "internal"
    ResealRequired = "reseal_required"

    @property
    def retryable(self) -> bool:
        return self in (ErrorCode.Unavailable, ErrorCode.SessionExpired)


class SealError(Exception):
    """Base of every Seal exception: `code` is the `ErrorCode`, `message` the text."""

    code: ErrorCode = ErrorCode.Internal

    def __init__(self, message: str = "", code: Optional[ErrorCode] = None) -> None:
        super().__init__(message)
        self.message = message
        if code is not None:
            self.code = code

    @property
    def retryable(self) -> bool:
        return self.code.retryable


class Expired(SealError):
    """The blob is past its `expires`, or its tenant key version is retired."""

    code = ErrorCode.Expired


class NotAllowed(SealError):
    """This identity may not do this (not in the blob's apps, no producer grant), or no
    workload identity was found."""

    code = ErrorCode.NotAllowed


class TierTooLow(SealError):
    """The session would be weaker than `min_tier`."""

    code = ErrorCode.TierTooLow


class IntegrityFailed(SealError):
    """The endpoint failed an integrity check, or its identity is suspended."""

    code = ErrorCode.IntegrityFailed


class Unavailable(SealError):
    """Seal, or something it needs, could not be reached. Retryable."""

    code = ErrorCode.Unavailable


class PolicyDenied(SealError):
    """A request falls outside the blob's policy."""

    code = ErrorCode.PolicyDenied


class BudgetExceeded(SealError):
    """A budget or rate limit is exhausted."""

    code = ErrorCode.BudgetExceeded


class SessionExpired(SealError):
    """The session token expired; the SDK restarts the session by itself."""

    code = ErrorCode.SessionExpired


class SessionEnded(SealError):
    """The session was ended (closed, or by the enclave on an integrity action). Start a new one."""

    code = ErrorCode.SessionEnded


class VerificationFailed(SealError):
    """The enclave could not be verified. Never retried silently: it may mean an attack."""

    code = ErrorCode.VerificationFailed


class BadRequest(SealError, ValueError):
    """A bad argument (an invalid `to`, app name, header or pin, a malformed blob)."""

    code = ErrorCode.BadRequest


class Internal(SealError):
    """Seal itself failed."""

    code = ErrorCode.Internal


class ResealRequired(SealError):
    """The blob was sealed before the enclave's platform was enabled: seal the secret again."""

    code = ErrorCode.ResealRequired


_BY_CODE: Dict[ErrorCode, Type[SealError]] = {
    cls.code: cls
    for cls in (
        Expired,
        NotAllowed,
        TierTooLow,
        IntegrityFailed,
        Unavailable,
        PolicyDenied,
        BudgetExceeded,
        SessionExpired,
        SessionEnded,
        VerificationFailed,
        BadRequest,
        Internal,
        ResealRequired,
    )
}


def from_code(code: str, message: str) -> SealError:
    """The exception for a wire code (the native module raises these)."""
    try:
        error_code = ErrorCode(code)
    except ValueError:
        return SealError(f"{code}: {message}")
    return _BY_CODE[error_code](message)
