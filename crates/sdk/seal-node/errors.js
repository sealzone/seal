"use strict";
// Errors: one class per `ErrorCode`, all `SealError`s carrying the code.

/** The public error vocabulary; values are the wire names. */
const ErrorCode = Object.freeze({
  Expired: "expired",
  NotAllowed: "not_allowed",
  TierTooLow: "tier_too_low",
  IntegrityFailed: "integrity_failed",
  Unavailable: "unavailable",
  PolicyDenied: "policy_denied",
  BudgetExceeded: "budget_exceeded",
  SessionExpired: "session_expired",
  SessionEnded: "session_ended",
  VerificationFailed: "verification_failed",
  BadRequest: "bad_request",
  Internal: "internal",
  ResealRequired: "reseal_required",
});

const RETRYABLE = new Set([ErrorCode.Unavailable, ErrorCode.SessionExpired]);

/** Base of every Seal error: `code` is the `ErrorCode`, `message` the text. */
class SealError extends Error {
  static code = ErrorCode.Internal;

  constructor(message = "", code = undefined) {
    super(message);
    this.name = new.target.name;
    this.code = code ?? new.target.code;
  }

  /** Whether trying again later may succeed (`unavailable`, `session_expired`). */
  get retryable() {
    return RETRYABLE.has(this.code);
  }
}

/** The blob is past its `expires`, or its tenant key version is retired. */
class Expired extends SealError {
  static code = ErrorCode.Expired;
}

/** This identity may not do this (not in the blob's apps), or no workload identity was found. */
class NotAllowed extends SealError {
  static code = ErrorCode.NotAllowed;
}

/** The session would be weaker than `minTier`. */
class TierTooLow extends SealError {
  static code = ErrorCode.TierTooLow;
}

/** The endpoint failed an integrity check, or its identity is suspended. */
class IntegrityFailed extends SealError {
  static code = ErrorCode.IntegrityFailed;
}

/** Seal, or something it needs, could not be reached. Retryable. */
class Unavailable extends SealError {
  static code = ErrorCode.Unavailable;
}

/** A request falls outside the blob's policy. */
class PolicyDenied extends SealError {
  static code = ErrorCode.PolicyDenied;
}

/** A budget or rate limit is exhausted. */
class BudgetExceeded extends SealError {
  static code = ErrorCode.BudgetExceeded;
}

/** The session token expired; the SDK restarts the session by itself. */
class SessionExpired extends SealError {
  static code = ErrorCode.SessionExpired;
}

/** The session was ended (closed, or by the enclave on an integrity action). Start a new one. */
class SessionEnded extends SealError {
  static code = ErrorCode.SessionEnded;
}

/** The enclave could not be verified. Never retried silently: it may mean an attack. */
class VerificationFailed extends SealError {
  static code = ErrorCode.VerificationFailed;
}

/** A bad argument (an invalid `to`, app name, header or pin, a malformed blob). */
class BadRequest extends SealError {
  static code = ErrorCode.BadRequest;
}

/** Seal itself failed. */
class Internal extends SealError {
  static code = ErrorCode.Internal;
}

/** The blob was sealed before the enclave's platform was enabled: seal the secret again. */
class ResealRequired extends SealError {
  static code = ErrorCode.ResealRequired;
}

const BY_CODE = new Map(
  [
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
  ].map((cls) => [cls.code, cls]),
);

/** The error for a wire code. An unknown code gives a plain `SealError` (`internal`). */
function fromCode(code, message) {
  const cls = BY_CODE.get(code);
  return cls ? new cls(message) : new SealError(`${code}: ${message}`);
}

// The native addon rejects with `[seal:<code>] <message>` (src/lib.rs `error`).
const TAGGED = /^\[seal:([a-z_]+)\] ([\s\S]*)$/;

/** A native error as its `SealError`; anything else (a TypeError from argument conversion,
 * an I/O error) unchanged. */
function fromNative(error) {
  const match = error instanceof Error ? TAGGED.exec(error.message) : null;
  return match ? fromCode(match[1], match[2]) : error;
}

module.exports = {
  ErrorCode,
  SealError,
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
  fromCode,
  fromNative,
};
