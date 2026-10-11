import assert from "node:assert/strict";
import {createUcrFirstPartyCallEntry} from "./src/canonical_first_party_call_entry.ts";
import {webcrypto} from "node:crypto";

import {
  createUcrBrowserProtectedDeviceVault,
  type UcrLocalSignerRecord,
  type UcrLocalSignerRecordStore,
} from "./src/canonical_device_seed_vault.ts";

if (!globalThis.crypto) {
  Object.defineProperty(globalThis, "crypto", {value: webcrypto});
}
const state = new Map<string, UcrLocalSignerRecord>();
let writes = 0;
const durableStore: UcrLocalSignerRecordStore = {
  async get(key) { return state.get(key) ?? null; },
  async addIfAbsent(key, value) {
    if (state.has(key)) return false;
    writes++;
    state.set(key, value);
    return true;
  },
};
const device = {tenantId:"tenant", namespaceId:null, deviceId:"device"};
const first = createUcrBrowserProtectedDeviceVault(durableStore);
assert.equal(await first.load(device), null);
const original = await first.stageNew(device);
assert.equal(original.publicKey.length, 32);
assert.match(original.keyId, /^ucr-ed25519-[0-9a-f]{64}$/);
assert.equal(state.size, 1, "must reuse EXISTING persistence owner");
assert.equal(writes, 1);
const saved = [...state.values()][0];
assert.equal(saved.wrappingKey.extractable, false, "never persist plaintext AES key");
assert.equal(saved.encryptedSeed.length, 48);
const challenge = webcrypto.getRandomValues(new Uint8Array(64));
const signature = await first.signChallenge(device, challenge);
const verifier = await webcrypto.subtle.importKey(
  "raw", original.publicKey as Uint8Array<ArrayBuffer>,
  {name:"Ed25519"}, false, ["verify"],
);
assert.equal(await webcrypto.subtle.verify(
  "Ed25519", verifier, signature as Uint8Array<ArrayBuffer>, challenge,
), true, "private signer possession must verify against canonical public descriptor");

// Simulate a full page/process restart with the SAME durable local store.
const restored = createUcrBrowserProtectedDeviceVault(durableStore);
const repeated = await restored.stageNew(device);
assert.equal(repeated.keyId, original.keyId);
assert.deepEqual(repeated.publicKey, original.publicKey);
assert.equal(writes, 1, "repeat login cannot create new permanent signing key");
const resumedSignature = await restored.signChallenge(device, challenge);
assert.deepEqual(resumedSignature, signature, "same Ed25519 Device signer after restart");
const forOtherCall = await restored.stageNew(device);
assert.equal(forOtherCall.keyId, original.keyId, "Call does not participate in vault scope");

// One real canonical Device may have multiple calls but each OTHER Device
// must have its own key, without becoming a contact or phone-number table.
const second = await restored.stageNew({...device, deviceId:"second-device"});
assert.notEqual(second.keyId, original.keyId);
assert.equal(state.size, 2);

// A transient seed must be erased immediately after the media callback.
let seedView: Uint8Array | undefined;
await restored.withAuthorizedSeed(device, async () => true, async seed => {
  seedView = seed;
  assert.equal(seed.length, 32);
  assert.ok(seed.some(byte => byte !== 0), "WASM signer seed must be live in callback");
}, () => {throw new Error("successful seed use must never roll back");});
assert.ok(seedView?.every(byte => byte === 0), "media callback seed zeroized");
await assert.rejects(
  restored.withAuthorizedSeed(device, async () => false, async () => {}, () => {}),
  /independent canonical Device media trust and revoke hook required/,
);
let count = 0;
await assert.rejects(
  restored.withAuthorizedSeed(device, async () => ++count === 1, async () => {}, () => {}),
  /canonical Device media trust revoked/,
);

// A revoked Device must tear down a partially-installed media bridge,
// not merely reject the promise and leave the bridge active in WASM.
let authChecks = 0, mediaActive = false, rollbackCalls = 0;
await assert.rejects(
  restored.withAuthorizedSeed(
    device,
    async () => ++authChecks <= 2,
    async () => {mediaActive = true; return "installed media bridge";},
    async () => {mediaActive = false; rollbackCalls++;},
  ),
  /canonical Device media trust revoked/,
);
assert.equal(mediaActive, false, "revoked Device must not leave active media side effect");
assert.equal(rollbackCalls, 1, "revoked Device must tear down installed media bridge");
let threwRollback = 0;
await assert.rejects(
  restored.withAuthorizedSeed(
    device, async () => true,
    async () => {mediaActive = true; throw new Error("bridge construction failed");},
    () => {mediaActive = false; threwRollback++;},
  ),
  /bridge construction failed/,
);
assert.equal(mediaActive, false);
assert.equal(threwRollback, 1);
await assert.rejects(
  (restored.withAuthorizedSeed as any)(device, async () => true,
    async () => {mediaActive = true;}),
  /revoke hook required/,
);
assert.equal(mediaActive, false, "no side effects when mandatory rollback is absent");

// A corrupted encrypted record must NOT silently regenerate or reauthorize.
const key = [...state.keys()].find(k => k.includes('"device"'));
assert.ok(key);
const stored = state.get(key)!;
state.set(key, {...stored, encryptedSeed: stored.encryptedSeed.map(() => 0)});
await assert.rejects(restored.signChallenge(device, challenge));
assert.equal(writes, 2, "corruption cannot create replacement key");

// Independent user authorization MUST happen BEFORE signer staging, which
// MUST happen BEFORE the server signs a device-bound Call/Session join grant.
const canonicalScope = {tenantId:"first-party",namespaceId:null,deviceId:"owned-device",
  participantId:"authenticated-person"};
let active = false, revoked = false, firstEntryAuth = 0, grants = 0;
let registered: {keyId:string;publicKey:Uint8Array} | null = null;
let revokeDuringGrant = false, mismatchDevice = false;
let deleteTrustDuringGrant = false, approvalCalls = 0;
let mutateGrantAtRecheck = false;
let latestIssuedGrant: {deviceId:string;joinFragment:string} | null = null;
const host = {
  async resumeAuthenticatedDevice() {
    firstEntryAuth++;
    return {...canonicalScope};
  },
  async inspect(binding: {callId?: string; sessionId?: string}) {
    // Only mutate the *newly issued* grant at its post-issuance trust check.
    // The first inspect belongs to the previous login/Device preflight and
    // must not consume this adversarial race injection.
    if (mutateGrantAtRecheck && binding.callId === "call" &&
        binding.sessionId === "session" && latestIssuedGrant) {
      latestIssuedGrant.deviceId = "mutated-after-issue";
      latestIssuedGrant.joinFragment = "#ucr_join=unchecked-mutable-replacement";
      mutateGrantAtRecheck = false;
    }
    return {deviceActive:active, deviceRevoked:revoked,
      activeKey:active && registered ? {...registered,publicKey:registered.publicKey.slice()} : null};
  },
  async approveNewDevice(_binding: unknown, key: {keyId:string;publicKey:Uint8Array}) {
    approvalCalls++;
    registered = {keyId:key.keyId,publicKey:key.publicKey.slice()};
    active = true;
  },
  async issueSignedDeviceJoin(binding: typeof canonicalScope) {
    assert.equal(binding.deviceId, canonicalScope.deviceId);
    assert.ok(active && registered && !revoked, "server may not issue for untrusted Device");
    grants++;
    if (revokeDuringGrant)revoked = true;
    if (deleteTrustDuringGrant) {active = false; registered = null;}
    const issued = {...binding,deviceId:mismatchDevice?"other-device":binding.deviceId,
      callId:"call",sessionId:"session",joinFragment:"#ucr_join=server-signed-opaque"};
    latestIssuedGrant = issued;
    return issued;
  },
};
const launch = createUcrFirstPartyCallEntry(host, createUcrBrowserProtectedDeviceVault(durableStore));
const [firstGrant, duplicate] = await Promise.all([launch(), launch()]);
assert.equal(firstGrant.joinFragment, "#ucr_join=server-signed-opaque");
assert.deepEqual(firstGrant, duplicate);
assert.equal(grants, 1, "two clicks cannot issue duplicate parallel joins");
assert.equal(firstEntryAuth, 1);
mutateGrantAtRecheck = true;
const returning = await launch();
assert.equal(returning.deviceId, canonicalScope.deviceId);
assert.equal(returning.joinFragment, "#ucr_join=server-signed-opaque",
  "grant must remain exactly what was validated before async trust recheck");
assert.equal(grants, 2, "repeat login preserves signing identity but issues fresh grant");
assert.equal(latestIssuedGrant?.deviceId, "mutated-after-issue",
  "test must actually mutate the host-owned grant object");
const identityAfter = await createUcrBrowserProtectedDeviceVault(durableStore).load(canonicalScope);
assert.equal(identityAfter?.keyId, registered?.keyId);
revokeDuringGrant = true;
await assert.rejects(launch(), /Device revoked or trust unavailable/);
assert.equal(grants, 3, "grant may be issued but must never be consumed after revocation");
revoked = false;
revokeDuringGrant = false;
mismatchDevice = true;
await assert.rejects(launch(), /join grant differs from prepared Device/);
mismatchDevice = false;

// A trust record deleted after issuance MUST NOT be recreated by the
// post-grant check. The local signer still exists, but registration is
// forbidden at this stage even for a previously approved Device.
const approvalsBeforeDeletion = approvalCalls;
const grantsBeforeDeletion = grants;
deleteTrustDuringGrant = true;
await assert.rejects(launch(), /canonical Device revoked or trust unavailable/);
assert.equal(grants, grantsBeforeDeletion + 1,
  "test must simulate loss of trust after the canonical grant was issued");
assert.equal(active, false);
assert.equal(registered, null);
assert.equal(approvalCalls, approvalsBeforeDeletion,
  "a deleted canonical trust entry must never be silently re-enrolled");
deleteTrustDuringGrant = false;
console.log("UCR_FIRST_PARTY_DEVICE_TO_GRANT_SEQUENCE_OK");

console.log("UCR_CANONICAL_DEVICE_SEED_VAULT_CONFORMANCE_OK");
