import assert from "node:assert/strict";
import {webcrypto} from "node:crypto";
import {createUcrFirstPartyCallEntry} from "./src/canonical_first_party_call_entry.ts";
import {createUcrFirstPartyHttpHost, encodeUcrFirstPartyEnrollmentProof} from "./src/first_party_browser_http.ts";
import {
  createUcrBrowserProtectedDeviceVault,
  type UcrLocalSignerRecord,
  type UcrLocalSignerRecordStore,
} from "./src/canonical_device_seed_vault.ts";

if (!globalThis.crypto) Object.defineProperty(globalThis, "crypto", {value: webcrypto});
Object.defineProperty(globalThis, "location", {
  configurable: true, value: {origin: "http://localhost:18080"},
});

const binding = {
  tenantId: "tenant-one", namespaceId: null,
  participantId: "identity-one", deviceId: "device-one",
};
const second = {...binding, deviceId: "device-two"};
const origin = "http://localhost:18080";
function encode(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function reply(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status, headers: {"Content-Type": "application/json; charset=utf-8"},
  });
}
function deferred<T>() {
  let release!: (value: T) => void;
  const promise = new Promise<T>(resolve => {release = resolve;});
  return {promise, release};
}
function store() {
  const records = new Map<string, UcrLocalSignerRecord>();
  const backing: UcrLocalSignerRecordStore = {
    async get(key) {return records.get(key) ?? null;},
    async addIfAbsent(key, data) {
      if (records.has(key)) return false;
      records.set(key, data); return true;
    },
  };
  return {backing, records};
}
function sessionHost(overrides: {
  session?: typeof binding | null;
  missingSession?: boolean;
  corruptChallenge?: boolean;
  foreignIssuer?: boolean;
  rejectApproval?: boolean;
  mutateSessionAfterChallenge?: boolean;
} = {}) {
  const trace: string[] = [];
  const http: Array<{url: string; init: RequestInit}> = [];
  const local = store();
  const vault = createUcrBrowserProtectedDeviceVault(local.backing);
  let trust: {deviceActive: boolean; deviceRevoked: boolean; activeKey:
    {keyId: string; publicKeyBase64Url: string} | null} = {
    deviceActive: false, deviceRevoked: false, activeKey: null,
  };
  let activeSession = overrides.session === undefined ? binding : overrides.session;
  let requestedKey: {keyId: string; publicKeyBase64Url: string} | null = null;
  const challenge = webcrypto.getRandomValues(new Uint8Array(48));
  let challengeUsed = false;
  let approvals = 0, issuances = 0;
  let challengeId = "once-only-challenge";
  const transport: typeof fetch = async (url, init) => {
    const resolved = new URL(String(url));
    const path = resolved.pathname;
    http.push({url: resolved.href, init: init ?? {}});
    assert.equal(resolved.origin, origin, "never contact an outside origin");
    assert.equal(init?.redirect, "error");
    assert.equal(init?.credentials, "same-origin");
    assert.equal(init?.cache, "no-store");
    assert.equal(init?.referrerPolicy, "no-referrer");
    assert.equal(init?.mode, "same-origin");
    assert.equal((init?.headers as Record<string,string>)?.Authorization, undefined);
    assert.equal((init?.headers as Record<string,string>)?.["X-UCR-First-Party-Request"],
      init?.method === "POST" ? "v1" : undefined);
    trace.push(path);
    const body = init?.body ? JSON.parse(String(init.body)) : null;
    if (path === "/v1/first-party/session") {
      if (overrides.missingSession) return reply({error:"unauthenticated"}, 401);
      return reply(activeSession);
    }
    if (path === "/v1/first-party/device/inspect") {
      assert.equal(body.tenantId, binding.tenantId);
      assert.equal(body.participantId, binding.participantId);
      return reply(trust);
    }
    if (path === "/v1/first-party/device/challenge") {
      assert.equal(body.deviceId, binding.deviceId, "bind challenge to authenticated Device");
      requestedKey = {keyId: body.keyId, publicKeyBase64Url: body.publicKeyBase64Url};
      if (overrides.mutateSessionAfterChallenge) activeSession = second;
      return reply({
        challengeId,
        challengeBytesBase64Url: overrides.corruptChallenge ? "?" : encode(challenge),
      });
    }
    if (path === "/v1/first-party/device/approve") {
      assert.equal(challengeUsed, false, "must not reuse server challenge");
      assert.deepEqual(body.binding, binding);
      assert.equal(body.challengeId, challengeId);
      assert.equal(body.keyId, requestedKey?.keyId);
      assert.equal(body.publicKeyBase64Url, requestedKey?.publicKeyBase64Url);
      const key = await webcrypto.subtle.importKey(
        "raw", Uint8Array.from(atob(body.publicKeyBase64Url.replace(/-/g, "+").replace(/_/g, "/")),
          char => char.charCodeAt(0)),
        {name: "Ed25519"}, false, ["verify"],
      );
      const signature = Uint8Array.from(
        atob(body.signatureBase64Url.replace(/-/g, "+").replace(/_/g, "/")),
        char => char.charCodeAt(0),
      );
      const proofMessage = encodeUcrFirstPartyEnrollmentProof(binding, {
        keyId: body.keyId,
        publicKey: Uint8Array.from(
          atob(body.publicKeyBase64Url.replace(/-/g, "+").replace(/_/g, "/")),
          char => char.charCodeAt(0),
        ),
      }, challengeId, challenge);
      assert.equal(await webcrypto.subtle.verify("Ed25519", key,
        signature, proofMessage), true, "Device enrollment proof must be domain-scoped");
      assert.equal(await webcrypto.subtle.verify("Ed25519", key,
        signature, challenge), false, "Device cannot be tricked into signing raw server bytes");
      if (overrides.rejectApproval) return reply({error:"forbidden"}, 403);
      challengeUsed = true;
      approvals++;
      trust = {deviceActive:true, deviceRevoked:false, activeKey: requestedKey};
      return reply({approved:true});
    }
    if (path === "/v1/first-party/call/join") {
      assert.equal(trust.deviceActive, true);
      assert.equal(trust.deviceRevoked, false);
      assert.deepEqual(body, binding);
      issuances++;
      const signed = "#ucr_join=" + encode(new TextEncoder().encode("fake-claims")) +
        "." + encode(new TextEncoder().encode("fake-signature"));
      return reply({
        ...binding, deviceId: overrides.foreignIssuer ? "stolen-device" : binding.deviceId,
        callId: "call-one", sessionId: "session-one", joinFragment: signed,
      });
    }
    return reply({error:"route_not_found"}, 404);
  };
  const host = createUcrFirstPartyHttpHost(vault, {origin, fetchImpl: transport});
  const enter = createUcrFirstPartyCallEntry(host, vault);
  return {trace, http, local, vault, host, enter, get approvals() {return approvals;},
    get issuances() {return issuances;},
    get trust() {return trust;},
    revoke() {trust = {...trust, deviceRevoked:true, deviceActive:false};},
    switchUser() {activeSession = second;},
  };
}

// First visit: separately authenticated session -> local private signer ->
// server-generated, one-time challenge -> canonical trusted-key approval ->
// independently issued signed Join -> final inspection-only recheck.
const first = sessionHost();
const a = await first.enter();
assert.equal(a.deviceId, binding.deviceId);
assert.equal(a.callId, "call-one");
assert.equal(first.approvals, 1);
assert.equal(first.issuances, 1);
assert.equal(first.local.records.size, 1);
const challengeIndex = first.trace.indexOf("/v1/first-party/device/challenge");
const approveIndex = first.trace.indexOf("/v1/first-party/device/approve");
const joinIndex = first.trace.indexOf("/v1/first-party/call/join");
assert.ok(challengeIndex !== -1 && challengeIndex < approveIndex && approveIndex < joinIndex);
assert.equal(first.trace[0], "/v1/first-party/session");
assert.equal(first.trace.at(-1), "/v1/first-party/device/inspect");
assert.ok(!first.http.some(({url}) => /ucr_join|client_secret|authorization/i.test(url)));

// Repeat login and a simulated browser restart share the same protected signer.
const signer = await first.vault.load(binding);
const b = await first.enter();
assert.equal(b.deviceId, binding.deviceId);
assert.equal(first.approvals, 1, "never re-enroll already trusted Device");
assert.equal(first.issuances, 2);
const restored = createUcrBrowserProtectedDeviceVault(first.local.backing);
assert.equal((await restored.load(binding))?.keyId, signer?.keyId);
assert.equal(first.local.records.size, 1, "no second signing key");

// A revoked signer must fail before another Join is issued.
first.revoke();
await assert.rejects(first.enter(), /revoked|trust unavailable/);
assert.equal(first.issuances, 2);

// Browser cannot invent its own authenticated session by presenting a grant.
const missing = sessionHost({missingSession:true});
await assert.rejects(missing.enter(), /HTTP 401/);
assert.equal(missing.local.records.size, 0);
assert.equal(missing.issuances, 0);

// An invalid server-provided challenge cannot reach enrollment/Join.
const malformed = sessionHost({corruptChallenge:true});
await assert.rejects(malformed.enter(), /binary descriptor/);
assert.equal(malformed.approvals, 0);
assert.equal(malformed.issuances, 0);

// Authenticated user swap between signing steps rejects the proof.
const changed = sessionHost({mutateSessionAfterChallenge:true});
await assert.rejects(changed.enter(), /session changed/);
assert.equal(changed.approvals, 0);
assert.equal(changed.issuances, 0);

// Trust approval is not implicit: explicit server denial is terminal.
const denied = sessionHost({rejectApproval:true});
await assert.rejects(denied.enter(), /HTTP 403/);
assert.equal(denied.issuances, 0);

// A mismatched issuer cannot hand back another Device's signed grant.
const foreign = sessionHost({foreignIssuer:true});
await assert.rejects(foreign.enter(), /foreign Device|differs from prepared Device/);
assert.equal(foreign.issuances, 1);

// Reject insecure HTTP on LAN, cross-origin hosts, embedded URL credentials
// and pages lacking a validated origin, BEFORE any network access.
for (const address of [
  "http://192.168.1.60:18080", "https://evil.example",
  "http://localhost:18080/path", "http://user:pass@localhost:18080",
  "file://localhost",
]) {
  assert.throws(
    () => createUcrFirstPartyHttpHost(first.vault, {origin:address, fetchImpl:transportNotUsed}),
    /origin|HTTPS/,
    address,
  );
}
function transportNotUsed(): Promise<Response> {
  throw new Error("network must never be reached");
}

// No trust or signed join can be derived from a 200 HTML response or redirect.
const bad = createUcrFirstPartyHttpHost(first.vault, {
  origin,
  fetchImpl: async () => new Response("<html>login</html>", {
    status:200, headers:{"Content-Type":"text/html"},
  }),
});
await assert.rejects(bad.resumeAuthenticatedDevice(), /unexpected content type/);
const huge = createUcrFirstPartyHttpHost(first.vault, {
  origin,
  fetchImpl: async () => reply({payload:"x".repeat(20000)}),
});
await assert.rejects(huge.resumeAuthenticatedDevice(), /exceeds limit/);

// Strong session correlation still applies when two requests are in flight.
const guard = deferred<Response>();
let inflight = false;
const stalled = createUcrFirstPartyHttpHost(first.vault, {
  origin,
  fetchImpl: async () => {
    inflight = true;
    return guard.promise;
  },
});
const waiting = stalled.resumeAuthenticatedDevice();
assert.equal(inflight, true);
guard.release(reply(binding));
assert.deepEqual(await waiting, binding);

console.log("RT0 first-party HTTP authenticated Device -> possession -> signed Join conformance passed");
