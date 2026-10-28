// The end-to-end scenario tests/e2e/test_node_sdk.py drives, against a `build.sh --sim`
// addon. The environment is the app's (`SEAL_ENDPOINT`, `SEAL_TENANT`, `SEAL_TRUST`,
// `SEAL_APP_KEY`); prints one JSON object, which never holds a secret.
//
//   node e2e.mjs sessions <blob>     a session through the local tunnel on an HTTP blob
//   node e2e.mjs seal <to> <receipts file>
//                                    seal SEAL_E2E_SECRET as anyone (SEAL_E2E_STRANGER_KEY, an app
//                                    key no grant names)

import http from "node:http";

import { AppKeyIdentity, Client, HttpSession, receipts } from "../index.js";
import native from "../native.js";

/** `GET <url>/models` with `Authorization: Bearer <key>`: `{ status, body }`, status 0 when the
 * connection fails. */
function get(url, key, agent) {
  const target = new URL(url.replace(/\/$/, "") + "/models");
  return new Promise((resolve) => {
    const request = http.get(target, { agent, headers: { authorization: `Bearer ${key}` }, timeout: 10_000 }, (response) => {
      const chunks = [];
      response.on("data", (c) => chunks.push(c));
      response.on("end", () => resolve({ status: response.statusCode, body: Buffer.concat(chunks).toString() }));
      response.on("error", (e) => resolve({ status: 0, body: String(e) }));
    });
    request.on("timeout", () => request.destroy(new Error("timeout")));
    request.on("error", (e) => resolve({ status: 0, body: String(e) }));
  });
}

/** The error's class name and code, or "none". */
async function failure(promise) {
  try {
    await promise;
    return "none";
  } catch (e) {
    return `${e.constructor.name}:${e.code}`;
  }
}

async function sessions(blob) {
  const app = await Client.fromEnv();
  const out = { tenant: app.tenant, statuses: [], bodies: [], keys: [] };

  // Two calls on one kept-alive connection with an extend in between, then close.
  const agent = new http.Agent({ keepAlive: true, maxSockets: 1 });
  // An async endpoint reporter: called (on the JavaScript thread) at start and every extend.
  let reports = 0;
  const challenges = new Set();
  const endpointReporter = async (challenge) => {
    reports += 1;
    if (Buffer.isBuffer(challenge) && challenge.length === 32) challenges.add(challenge.toString("hex"));
    return { artifact: { name: "e2e.mjs", sha256: Buffer.alloc(32, 1) } };
  };
  const s = await app.session(blob, { kind: "http", endpointReporter });
  out.tunnel = { isHttp: s instanceof HttpSession, info: s.info, loopback: s.url.startsWith("http://127.0.0.1:") };
  out.keys.push(s.key);
  for (let i = 0; i < 2; i++) {
    const { status, body } = await get(s.url, s.key, agent);
    out.statuses.push(status);
    out.bodies.push(body);
    if (i === 0) {
      const [url, key, expiresAt] = [s.url, s.key, s.info.expiresAt];
      await s.extend();
      // The local URL and key never change; the expiry moves.
      out.tunnel.unchanged = s.url === url && s.key === key && s.info.expiresAt >= expiresAt;
    }
  }
  out.tunnel.receipts = (await s.receipts()).length;
  out.tunnel.reports = reports;
  out.tunnel.challenges = challenges.size;
  const [url, key] = [s.url, s.key];
  await s.close();
  await s.close(); // a second close does nothing
  out.tunnel.afterClose = (await get(url, key, agent)).status;
  agent.destroy();

  // Errors come back as their classes: the wrong kind before anything is sent.
  out.wrongKind = await failure(app.session(blob, { kind: "database" }));
  return out;
}

async function seal(to, receiptsFile) {
  const stranger = await Client.connect({ identity: new AppKeyIdentity(process.env.SEAL_E2E_STRANGER_KEY) });
  const { blob, receipt } = await stranger.seal(process.env.SEAL_E2E_SECRET, {
    to,
    apps: "checkout",
    format: "Bearer {key}",
    withReceipt: true,
  });
  await receipts.append(receiptsFile, [receipt]);
  // Anyone may seal; only the blob's apps may use it.
  const notAllowed = await failure(stranger.session(blob));
  const badPin = await failure(stranger.seal("x", { to, apps: ["checkout"], pin: "sha256/nope" }));

  // `await using` closes the session on leaving the block (Node 24+); otherwise close it here.
  const app = await Client.fromEnv();
  const s = await app.session(blob, { kind: "http" });
  let status;
  try {
    status = (await get(s.url, s.key)).status;
  } finally {
    await s[Symbol.asyncDispose]();
  }
  return { blob, entry: receipt.entry, notAllowed, badPin, status };
}

if (!native.load().SIM) {
  throw new Error("build the addon with build.sh --sim");
}
const [mode, ...args] = process.argv.slice(2);
const out = mode === "seal" ? await seal(...args) : await sessions(...args);
process.stdout.write(JSON.stringify(out) + "\n");
