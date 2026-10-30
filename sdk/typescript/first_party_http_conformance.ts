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
      assert.deepEqual(body, {binding}, "Rust BoundRequest requires exactly one binding field");
      return reply(trust);
    }
    if (path === "/v1/first-party/device/challenge") {
      assert.deepEqual(body.binding, binding, "bind challenge to authenticated Device and scope");
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
      throw new Error("unscoped Device Join must never reach first-party HTTP transport");
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

// First visit: the same browser must authenticate and prove possession of
// its protected Device signer, but CAN NEVER receive an unscoped Call Join.
// A mocked 200 from /call/join formerly gave a false green result that was
// impossible against the canonical Rust BFF (which always returns 403).
const first = sessionHost();
await assert.rejects(first.enter(), /unscoped Device Join forbidden/);
assert.equal(first.approvals,1);
assert.equal(first.issuances,0);
assert.equal(first.local.records.size,1);
const challengeIndex = first.trace.indexOf("/v1/first-party/device/challenge");
const approveIndex = first.trace.indexOf("/v1/first-party/device/approve");
assert.ok(challengeIndex !== -1 && challengeIndex < approveIndex);
assert.equal(first.trace[0],"/v1/first-party/session");
assert.ok(!first.trace.includes("/v1/first-party/call/join"));
assert.ok(!first.http.some(({url}) => /ucr_join|client_secret|authorization/i.test(url)));

// A browser restart reuses the protected signer; no duplicate registration
// and no unauthorized standalone Join are possible.
const signer = await first.vault.load(binding);
await assert.rejects(first.enter(), /unscoped Device Join forbidden/);
assert.equal(first.approvals,1);
assert.equal(first.issuances,0);
const restored = createUcrBrowserProtectedDeviceVault(first.local.backing);
assert.equal((await restored.load(binding))?.keyId,signer?.keyId);
assert.equal(first.local.records.size,1);

// Fail closed on revoked, missing or swapped Identity/Device, corrupt challenge
// and explicit denial of canonical signer proof.
first.revoke();
await assert.rejects(first.enter(), /revoked|trust unavailable/);
const missing = sessionHost({missingSession:true});
await assert.rejects(missing.enter(), /HTTP 401/);
assert.equal(missing.local.records.size,0);
const malformed = sessionHost({corruptChallenge:true});
await assert.rejects(malformed.enter(), /binary descriptor/);
assert.equal(malformed.approvals,0);
const changed = sessionHost({mutateSessionAfterChallenge:true});
await assert.rejects(changed.enter(), /session changed/);
assert.equal(changed.approvals,0);
const denied = sessionHost({rejectApproval:true});
await assert.rejects(denied.enter(), /HTTP 403/);
assert.equal(denied.issuances,0);

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

// Actual first-party Rust BFF requires a recipient-accepted Call before Join.
// Mocking a successful bare /call/join response above tests a legacy SDK seam,
// NOT a route that exists on the real server. Verify the live BFF's direct Call
// request envelopes and fail-closed unscoped-Join contract independently.
const direct = {
  ...binding, callId:"fp-v-call-token-42", callerIdentityId:binding.participantId,
  calleeIdentityId:"peer-other", media:"video" as const,
  state:"active" as const, revision:7,
};
const authenticatedRoutes: string[] = [];
const canonicalHttp = createUcrFirstPartyHttpHost(first.vault, {
  origin,
  fetchImpl: async (url, init) => {
    const path = new URL(String(url)).pathname;
    authenticatedRoutes.push(path);
    if (path === "/v1/first-party/session") return reply(binding);
    if (path === "/v1/first-party/call/join") return reply({error:"forbidden"},403);
    const body = JSON.parse(String(init?.body));
    assert.deepEqual(body.binding, binding, "live Rust BFF checks session-scoped binding");
    if (path === "/v1/first-party/device/inspect") {
      assert.deepEqual(Object.keys(body), ["binding"], "no naked Device JSON");
      return reply(first.trust);
    }
    if (path === "/v1/first-party/call/start") {
      assert.deepEqual(body.intent, {
        peerIdentityId: "peer-other", media:"video", idempotencyKey:"call-token-42",
      });
      return reply({...direct, state:"inviting"});
    }
    if (path === "/v1/first-party/call/get") {
      assert.equal(body.callId, direct.callId);
      return reply(direct);
    }
    if (path === "/v1/first-party/call/incoming") {
      assert.deepEqual(Object.keys(body), ["binding"]);
      return reply([]);
    }
    if (path === "/v1/first-party/call/signal") {
      assert.deepEqual({
        callId:body.callId, expectedRevision:body.expectedRevision, action:body.action,
      }, {callId:direct.callId,expectedRevision:7,action:"hangup"});
      return reply({...direct,state:"terminated",revision:8});
    }
    if (path === "/v1/first-party/call/join-accepted") {
      assert.equal(body.callId,direct.callId);
      assert.equal(body.expectedRevision,7);
      return reply({
        ...binding,callId:direct.callId,sessionId:"session-42",
        joinFragment:"#ucr_join="+encode(new TextEncoder().encode("fake-claims"))+
          "."+encode(new TextEncoder().encode("fake-signature")),
      });
    }
    return reply({error:"unknown canonical route"},404);
  },
});
assert.deepEqual(await canonicalHttp.resumeAuthenticatedDevice(),binding);
await canonicalHttp.inspect(binding);
const started = await canonicalHttp.startDirectCall(binding,{
  peerIdentityId:"peer-other",media:"video",idempotencyKey:"call-token-42",
});
assert.equal(started.state,"inviting");
assert.equal((await canonicalHttp.getDirectCall(binding,direct.callId)).revision,7);
assert.deepEqual(await canonicalHttp.listIncomingDirectCalls(binding),[]);
assert.equal((await canonicalHttp.signalDirectCall(binding,{
  callId:direct.callId,expectedRevision:7,action:"hangup",
})).state,"terminated");
assert.equal((await canonicalHttp.issueSignedJoinForAcceptedCall(binding,{
  callId:direct.callId,expectedRevision:7,
})).sessionId,"session-42");
await assert.rejects(canonicalHttp.issueSignedDeviceJoin(binding),/unscoped Device Join forbidden/);
for (const route of [
  "device/inspect","call/start","call/get","call/incoming",
  "call/signal","call/join-accepted",
]) {
  assert.ok(authenticatedRoutes.includes("/v1/first-party/"+route),route);
}

assert.ok(!authenticatedRoutes.includes("/v1/first-party/call/join"));
// A signed Join or MLS descriptor issued to the previous Device is stale when
// the browser switches Identity/Device before the HTTP response completes.
// A matching binding inside the delayed response alone is not sufficient.
async function expectLateDeviceResponseRefused(
  route: string,
  payload: unknown,
  invoke: (host: ReturnType<typeof createUcrFirstPartyHttpHost>) => Promise<unknown>,
): Promise<void> {
  let active = binding;
  const requested = deferred<void>();
  const delayed = deferred<Response>();
  const host = createUcrFirstPartyHttpHost(first.vault, {
    origin,
    fetchImpl: async (url) => {
      const path = new URL(String(url)).pathname;
      if (path === "/v1/first-party/session") return reply(active);
      if (path === "/v1/first-party/call/mls-descriptor" && path !== route) {
        return reply(acceptedMlsDescriptor);
      }
      if (path === route) {
        requested.release(undefined);
        return delayed.promise;
      }
      throw new Error("unexpected first-party route: " + path);
    },
  });
  const pending = invoke(host);
  await requested.promise;
  active = second;
  delayed.release(reply(payload));
  await assert.rejects(pending, new RegExp("account or Device changed during MLS/Join operation"));
}

const acceptedMlsDescriptor = {
  callId: direct.callId, expectedRevision: 7,
  groupRevision: null, expectedPeerDeviceId: null, cryptoEpoch: null, cryptoStateRef: null,
  mediaCallId: "fp-m-call-42", groupId: "fp-mg-group-42",
  conversationId: "fp-mc-conversation-42",
  creatorPrincipalId: binding.participantId, peerPrincipalId: "peer-other",
  deviceId: binding.deviceId, cryptoCapability: "ucr.group-mls.v1",
  requiresEndpointOwnedCommit: true,
};
// The Group's CAS revision is independent of the direct Call revision.
// The descriptor must distinguish absence from the real initial revision 0,
// and reject a partially initialized or downgraded crypto-state projection.
let groupDescriptor: unknown = acceptedMlsDescriptor;
const descriptorHost = createUcrFirstPartyHttpHost(first.vault, {
  origin,
  fetchImpl: async url => {
    const path = new URL(String(url)).pathname;
    if (path === "/v1/first-party/session") return reply(binding);
    if (path === "/v1/first-party/call/mls-descriptor") return reply(groupDescriptor);
    throw new Error("unexpected descriptor route: " + path);
  },
});
const descriptorRequest = {callId: direct.callId, expectedRevision: 7};
assert.equal((await descriptorHost.describeAcceptedCallMls(binding, descriptorRequest)).groupRevision, null);
groupDescriptor = {...acceptedMlsDescriptor, groupRevision: 0, cryptoEpoch: 0,
  cryptoStateRef: "local-epoch-zero"};
const initialGroup = await descriptorHost.describeAcceptedCallMls(binding, descriptorRequest);
assert.equal(initialGroup.groupRevision, 0);
assert.equal(initialGroup.cryptoEpoch, 0);
assert.equal(initialGroup.cryptoStateRef, "local-epoch-zero");
groupDescriptor = {...acceptedMlsDescriptor, groupRevision: 1, cryptoEpoch: 1,
  cryptoStateRef: "endpoint-committed-epoch-one", expectedPeerDeviceId: "peer-device"};
const admittedGroup = await descriptorHost.describeAcceptedCallMls(binding, descriptorRequest);
assert.equal(admittedGroup.groupRevision, 1);
assert.equal(admittedGroup.expectedPeerDeviceId, "peer-device");
for (const invalid of [
  {...acceptedMlsDescriptor, groupRevision: 1, cryptoEpoch: 1,
    cryptoStateRef: "state", expectedPeerDeviceId: null},
  {...acceptedMlsDescriptor, groupRevision: 1, cryptoEpoch: 1,
    cryptoStateRef: "state", expectedPeerDeviceId: binding.deviceId},
  {...acceptedMlsDescriptor, groupRevision: 1, cryptoEpoch: 1,
    cryptoStateRef: "state", expectedPeerDeviceId: "peer device"},
]) {
  groupDescriptor = invalid;
  await assert.rejects(
    descriptorHost.describeAcceptedCallMls(binding, descriptorRequest),
    /missing or untrusted committed MLS peer Device/,
  );
}
for (const invalid of [
  {...acceptedMlsDescriptor, groupRevision: 0},
  {...acceptedMlsDescriptor, groupRevision: 0, cryptoEpoch: 0, cryptoStateRef: null},
  {...acceptedMlsDescriptor, groupRevision: -1, cryptoEpoch: 0, cryptoStateRef: "state"},
  {...acceptedMlsDescriptor, groupRevision: 0, cryptoEpoch: -1, cryptoStateRef: "state"},
  {...acceptedMlsDescriptor, groupRevision: 0, cryptoEpoch: 0, cryptoStateRef: ""},
  {...acceptedMlsDescriptor, groupRevision: Number.MAX_SAFE_INTEGER + 1,
    cryptoEpoch: 0, cryptoStateRef: "state"},
]) {
  groupDescriptor = invalid;
  await assert.rejects(
    descriptorHost.describeAcceptedCallMls(binding, descriptorRequest),
    /inconsistent canonical MLS Group revision or crypto epoch/,
  );
}

await expectLateDeviceResponseRefused(
  "/v1/first-party/call/mls-descriptor", acceptedMlsDescriptor,
  host => host.describeAcceptedCallMls(binding, {callId: direct.callId, expectedRevision: 7}),
);
await expectLateDeviceResponseRefused(
  "/v1/first-party/call/join-accepted", {
    ...binding, callId: direct.callId, sessionId: "session-42",
    joinFragment: "#ucr_join=" + encode(new TextEncoder().encode("fake-claims")) +
      "." + encode(new TextEncoder().encode("fake-signature")),
  },
  host => host.issueSignedJoinForAcceptedCall(binding, {
    callId: direct.callId, expectedRevision: 7,
  }),
);

await expectLateDeviceResponseRefused(
  "/v1/first-party/call/mls-offers", {
    callId: direct.callId, groupId: acceptedMlsDescriptor.groupId, offers: [],
  },
  host => host.listEndpointMlsOffers(binding, {callId: direct.callId, expectedRevision: 7}),
);
await expectLateDeviceResponseRefused(
  "/v1/first-party/call/mls-bootstrap", {
    callId: direct.callId, groupId: acceptedMlsDescriptor.groupId,
    deviceId: binding.deviceId, admissionEventId: "event-42",
    welcomeBase64Url: encode(new Uint8Array([1])), welcomeEpoch: 1,
    welcomeStateRef: "state-42", commits: [], cryptoEpoch: 1,
    cryptoStateRef: "state-42",
  },
  host => host.fetchEndpointMlsBootstrap(binding, {callId: direct.callId, expectedRevision: 7}),
);

console.log("RT0 HTTP: existing Device proof, canonical Call routes, and unscoped Join denial passed");
