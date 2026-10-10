import assert from "node:assert/strict";
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
});
assert.ok(seedView?.every(byte => byte === 0), "media callback seed zeroized");
await assert.rejects(
  restored.withAuthorizedSeed(device, async () => false, async () => {}),
  /independent canonical Device media trust required/,
);
let count = 0;
await assert.rejects(
  restored.withAuthorizedSeed(device, async () => ++count === 1, async () => {}),
  /canonical Device media trust revoked/,
);

// A corrupted encrypted record must NOT silently regenerate or reauthorize.
const key = [...state.keys()].find(k => k.includes('"device"'));
assert.ok(key);
const stored = state.get(key)!;
state.set(key, {...stored, encryptedSeed: stored.encryptedSeed.map(() => 0)});
await assert.rejects(restored.signChallenge(device, challenge));
assert.equal(writes, 2, "corruption cannot create replacement key");
console.log("UCR_CANONICAL_DEVICE_SEED_VAULT_CONFORMANCE_OK");
