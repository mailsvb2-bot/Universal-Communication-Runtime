import assert from "node:assert/strict";
import {
  createUcrCanonicalBrowserMediaFactory,
  type UcrCanonicalBrowserMediaAdmission,
} from "./src/canonical_browser_media_factory.ts";
import type { UcrAuthorizedMediaBootstrap } from "./src/authorized_browser_media.ts";

const verifyingKey = new Uint8Array(32).fill(7);
const directGroup = "fp-mg-canonical-test";
const claims = Object.freeze({
  tenantId: "tenant", namespaceId: null, callId: "fp-m-call",
  deviceId: "alice-device", participantId: "alice", participantKind: "person",
  sessionId: "session-a",
});
const binding = Object.freeze({
  tenantId: claims.tenantId, namespaceId: claims.namespaceId,
  callId: claims.callId, groupId: directGroup,
  cryptoEpoch: 1n, negotiationRef: "negotiation-a",
  negotiationGeneration: 1n,
});
function scenario(options: {
  peer?: string;
  rosterAvailable?: boolean;
  rosterReject?: boolean;
  revokeDuringRoster?: boolean;
  groupId?: string;
} = {}) {
  let live = true;
  let rosterChecks = 0;
  let bridges = 0;
  let revoked = 0;
  const state = {
    crypto_epoch: () => 1n,
    ...(options.rosterAvailable === false ? {} : {
      authorize_direct_call_roster(peer: string) {
        rosterChecks++;
        if (options.rosterReject || peer !== "bob-device") {
          throw new Error("MLS roster has foreign or missing leaf");
        }
        if (options.revokeDuringRoster) live = false;
      },
    }),
    media_bridge() {
      bridges++;
      return {
        local_verifying_key: () => verifyingKey.slice(),
        revoke: () => { revoked++; },
        seal_wire: () => new Uint8Array(),
        open_wire: () => new Uint8Array(),
      };
    },
  };
  const groupId = options.groupId ?? directGroup;
  const bootstrap: UcrAuthorizedMediaBootstrap = {
    state, claims, groupId, loadWasm: async () => ({}),
  };
  const admission: UcrCanonicalBrowserMediaAdmission = {
    sessionId: claims.sessionId,
    deviceId: claims.deviceId,
    participantId: claims.participantId,
    principalKindCode: 1,
    binding: {...binding, groupId},
    signingKeyId: "trusted-key",
    signingSeed: new Uint8Array(32).fill(8),
    trustedLocalVerifyingKey: verifyingKey.slice(),
    ...(options.peer === undefined ? {} : {expectedPeerDeviceId: options.peer}),
    trustedKeys: {resolve: () => verifyingKey.slice()},
    audioContext: {} as AudioContext,
    isCurrent: () => live,
    authorizeFrame: () => live,
    authorizePublish: () => live,
  };
  return {
    run: () => createUcrCanonicalBrowserMediaFactory(async () => admission)(bootstrap),
    counts: () => ({rosterChecks, bridges, revoked}),
  };
}

{
  const test = scenario();
  await assert.rejects(test.run(), /peer Device\/MLS roster authority unavailable/);
  assert.deepEqual(test.counts(), {rosterChecks: 0, bridges: 0, revoked: 0});
}
{
  const test = scenario({peer: "alice-device"});
  await assert.rejects(test.run(), /peer Device\/MLS roster authority unavailable/);
  assert.deepEqual(test.counts(), {rosterChecks: 0, bridges: 0, revoked: 0});
}
{
  const test = scenario({peer: "bob-device", rosterAvailable: false});
  await assert.rejects(test.run(), /peer Device\/MLS roster authority unavailable/);
  assert.deepEqual(test.counts(), {rosterChecks: 0, bridges: 0, revoked: 0});
}
{
  const test = scenario({peer: "bob-device", rosterReject: true});
  await assert.rejects(test.run(), /MLS roster has foreign or missing leaf/);
  assert.deepEqual(test.counts(), {rosterChecks: 1, bridges: 0, revoked: 0});
}
{
  const test = scenario({peer: "bob-device", revokeDuringRoster: true});
  await assert.rejects(test.run(), /revoked during MLS roster validation/);
  assert.deepEqual(test.counts(), {rosterChecks: 1, bridges: 0, revoked: 0});
}
{
  const test = scenario({peer: "bob-device"});
  const result = await test.run();
  assert.ok(result.bridge);
  assert.deepEqual(test.counts(), {rosterChecks: 1, bridges: 1, revoked: 0});
}
{
  // Multi-party Conference MLS must not accidentally inherit the two-leaf
  // direct-call restriction. Its existing canonical membership guard applies.
  const test = scenario({groupId: "conference-mls-group"});
  const result = await test.run();
  assert.ok(result.bridge);
  assert.deepEqual(test.counts(), {rosterChecks: 0, bridges: 1, revoked: 0});
}
console.log("canonical direct-call endpoint MLS roster conformance: PASS");
