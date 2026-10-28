// Unit tests: no simulator. `build.sh --test` (or `npm test` after a build) runs them.

import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, describe, test } from "node:test";

import * as seal from "../index.js";
import {
  AppKeyIdentity,
  AzureManagedIdentity,
  BadRequest,
  Client,
  ErrorCode,
  GcpIdentity,
  GitHubActionsIdentity,
  IdentityProvider,
  KubernetesIdentity,
  NotAllowed,
  SealError,
  Session,
  TelemetryReceipt,
  Unavailable,
  VerificationFailed,
  receipts,
} from "../index.js";
import errors from "../errors.js";

// Every test sets what it needs; nothing comes from the machine's environment.
for (const name of Object.keys(process.env)) {
  if (name.startsWith("SEAL_") || name.startsWith("ACTIONS_ID_TOKEN_")) {
    delete process.env[name];
  }
}

const APP_KEY = "sealak_" + Buffer.alloc(32, 7).toString("base64url");

describe("errors", () => {
  // The codes seal-py's `ErrorCode` has, and its class names.
  const CODES = {
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
  };

  test("one class per code, as Python names them", () => {
    assert.deepEqual({ ...ErrorCode }, CODES);
    for (const [name, code] of Object.entries(CODES)) {
      const cls = seal[name];
      assert.equal(cls.code, code, name);
      const e = errors.fromCode(code, "why");
      assert.ok(e instanceof cls && e instanceof SealError && e instanceof Error, name);
      assert.equal(e.name, name);
      assert.equal(e.code, code);
      assert.equal(e.message, "why");
      assert.equal(e.retryable, code === "unavailable" || code === "session_expired", name);
    }
  });

  test("an unknown code is a plain SealError", () => {
    const e = errors.fromCode("brand_new", "why");
    assert.equal(e.constructor, SealError);
    assert.equal(e.code, "internal");
    assert.equal(e.message, "brand_new: why");
  });

  test("native errors are read back; others pass through", () => {
    const e = errors.fromNative(new Error("[seal:unavailable] network: refused\nsecond line"));
    assert.ok(e instanceof Unavailable);
    assert.equal(e.message, "network: refused\nsecond line");
    const other = new TypeError("Failed to convert");
    assert.equal(errors.fromNative(other), other);
    assert.equal(errors.fromNative("not an error"), "not an error");
  });

  test("a SealError can be made with a code", () => {
    assert.equal(new SealError("x", "expired").code, "expired");
    assert.equal(new SealError("x").code, "internal");
  });
});

describe("native errors map to their class", () => {
  test("a malformed app key is BadRequest, without repeating the key", () => {
    assert.throws(
      () => new AppKeyIdentity("sealak_not-a-key"),
      (e) => e instanceof BadRequest && e.code === "bad_request" && !e.message.includes("not-a-key"),
    );
  });

  test("a bad endpoint, tenant or trust is BadRequest", async () => {
    const identity = new AppKeyIdentity(APP_KEY);
    await assert.rejects(Client.connect({ endpoints: "nope", tenant: "acme", identity }), BadRequest);
    await assert.rejects(Client.connect({ endpoints: "https://127.0.0.1:1", tenant: "Not A Tenant" }), BadRequest);
    await assert.rejects(
      Client.connect({ endpoints: "https://127.0.0.1:1", tenant: "acme", identity, trust: "{ not json" }),
      BadRequest,
    );
  });

  test("missing environment: no endpoint is BadRequest, no identity NotAllowed", async () => {
    await assert.rejects(Client.fromEnv(), (e) => e instanceof BadRequest && /SEAL_ENDPOINT/.test(e.message));
    assert.throws(() => new GitHubActionsIdentity("acme"), NotAllowed);
  });

  test("no release trust is VerificationFailed", async () => {
    // This build ships none, and SEAL_TRUST is unset.
    const identity = new AppKeyIdentity(APP_KEY);
    await assert.rejects(
      Client.connect({ endpoints: ["https://127.0.0.1:1"], tenant: "acme", identity }),
      (e) => e instanceof VerificationFailed && !e.retryable,
    );
  });
});

describe("argument validation", () => {
  test("clients and sessions are not constructed directly", () => {
    assert.throws(() => new Client(), TypeError);
    assert.throws(() => new Session(), TypeError);
    assert.throws(() => new IdentityProvider({}), TypeError);
  });

  test("connect checks its options' types", async () => {
    await assert.rejects(Client.connect({ identity: APP_KEY }), TypeError);
    await assert.rejects(Client.connect({ endpoints: [1] }), TypeError);
    await assert.rejects(Client.connect({ trust: 5 }), TypeError);
    await assert.rejects(Client.connect({ tenant: 5 }), TypeError);
  });

  // Validation runs before the client's native half is touched, so a bare object stands in.
  const bare = {};

  test("seal needs to, apps and a secret", async () => {
    const seal = (secret, options) => Client.prototype.seal.call(bare, secret, options);
    await assert.rejects(seal("s", { apps: ["checkout"] }), /to must be/);
    await assert.rejects(seal("s", { to: "https://x" }), /apps must/);
    await assert.rejects(seal("s", { to: "https://x", apps: [1] }), TypeError);
    await assert.rejects(seal(42, { to: "https://x", apps: "checkout" }), /secret must/);
    await assert.rejects(seal("s", { to: "https://x", apps: "a", expires: "tomorrow" }), /expires/);
    await assert.rejects(seal("s", { to: "https://x", apps: "a", pin: 3 }), TypeError);
  });

  test("session checks kind and callbacks", async () => {
    const session = (blob, options) => Client.prototype.session.call(bare, blob, options);
    await assert.rejects(session(42), TypeError);
    await assert.rejects(session("seal1.x", { kind: "ftp" }), BadRequest);
    await assert.rejects(session("seal1.x", { reloadWith: "seal1.y" }), /reloadWith must be a function/);
  });

  test("signal checks the severity", async () => {
    await assert.rejects(Client.prototype.signal.call(bare, "edr", "severe"), BadRequest);
    await assert.rejects(Client.prototype.signal.call(bare, 1, "high"), TypeError);
  });
});

describe("identities", () => {
  test("each kind is built", () => {
    assert.equal(new AppKeyIdentity(APP_KEY).kind, "app-key");
    assert.ok(new AppKeyIdentity(APP_KEY) instanceof IdentityProvider);
    assert.equal(new AzureManagedIdentity("api://seal", { clientId: "id" }).kind, "azure-managed-identity");
    assert.equal(new KubernetesIdentity().kind, "kubernetes");
    assert.equal(new GcpIdentity("acme").kind, "gcp-service-account");
    assert.throws(() => new GcpIdentity("Not A Tenant"), BadRequest);
  });
});

describe("receipts", () => {
  const dir = mkdtempSync(join(tmpdir(), "seal-node-test-"));
  after(() => rmSync(dir, { recursive: true, force: true }));

  test("append writes the JSON lines `seal telemetry --receipts` reads", async () => {
    const path = join(dir, "receipts.jsonl");
    const a = new TelemetryReceipt(Buffer.alloc(16, 1), 2);
    const b = new TelemetryReceipt(new Uint8Array(16).fill(3), 4);
    await receipts.append(path, [a]);
    await receipts.append(path, []);
    await receipts.append(path, new Set([b, a]));
    const lines = readFileSync(path, "utf8").split("\n");
    assert.deepEqual(lines, [JSON.stringify(a), JSON.stringify(b), JSON.stringify(a), ""]);
    // The Rust SDK's format: stream as unpadded base64url.
    assert.equal(lines[0], '{"stream":"AQEBAQEBAQEBAQEBAQEBAQ","entry":2}');
  });

  test("only receipts, and only whole ones", async () => {
    await assert.rejects(receipts.append(join(dir, "x"), [{ stream: "AQ", entry: 1 }]), TypeError);
    assert.throws(() => new TelemetryReceipt(Buffer.alloc(15), 1), TypeError);
  });
});

describe("HostAgentReporter", () => {
  test("from the environment, or with both socket and appKey", () => {
    new seal.HostAgentReporter();
    assert.throws(() => new seal.HostAgentReporter({ socket: "/run/seal/agent.sock" }), seal.BadRequest);
    assert.throws(
      () => new seal.HostAgentReporter({ socket: "/run/seal/agent.sock", appKey: "not an app key" }),
      seal.BadRequest,
    );
  });
});
