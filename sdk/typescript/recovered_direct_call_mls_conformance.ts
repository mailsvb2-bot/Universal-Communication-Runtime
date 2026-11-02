/** Contract-only recovery flow: NOT proof of physical WebRTC video or relay blindness. */
import assert from "node:assert/strict";
import {establishRecoveredDirectCall, type UcrRecoveredCallEndpoint} from "./src/recovered_direct_call_mls.ts";
import type {UcrManagedFirstPartyHost, UcrEndpointMlsCallDescriptor} from "./src/first_party_browser_http.ts";
import type {UcrAuthenticatedFirstEntry} from "./src/canonical_first_party_call_entry.ts";
import type {UcrDirectCall} from "./src/contact_call_journey.ts";

const alice:UcrAuthenticatedFirstEntry={tenantId:"t",namespaceId:null,participantId:"alice",deviceId:"a"};
const bob:UcrAuthenticatedFirstEntry={tenantId:"t",namespaceId:null,participantId:"bob",deviceId:"b"};
const call:UcrDirectCall={tenantId:"t",namespaceId:null,callId:"call-new",callerIdentityId:"alice",calleeIdentityId:"bob",media:"video",state:"active",revision:2};
const oldCall:UcrDirectCall={...call,callId:"call-old",state:"terminated",revision:3};
let epoch:number|null=null, joins=0, published=false, committed=false;
const descriptor=(auth:UcrAuthenticatedFirstEntry):UcrEndpointMlsCallDescriptor=>({
  callId:call.callId,expectedRevision:2,groupRevision:published?(committed?4:3):null,
  expectedPeerDeviceId:committed?(auth.deviceId==="a"?"b":"a"):null,
  cryptoEpoch:epoch,cryptoStateRef:epoch===null?null:epoch===0?"epoch-zero":"epoch-one",
  mediaCallId:"fp-m-call-new",groupId:"fp-mg-call-new",conversationId:"fp-mc-call-new",
  creatorPrincipalId:"alice",peerPrincipalId:auth.deviceId==="a"?"bob":"alice",
  deviceId:auth.deviceId,
  cryptoCapability:"ucr.group.mls",requiresEndpointOwnedCommit:true,
});
const host:UcrManagedFirstPartyHost={
  async getDirectCall(_auth,id){return id==="call-old"?oldCall:call;},
  async describeAcceptedCallMls(auth){return descriptor(auth);},
  async publishEndpointMlsGroup(){assert.equal(published,false);published=true;epoch=0;},
  async publishEndpointMlsOffer(_auth,input){assert.deepEqual([...input.keyPackage],[1,2,3]);},
  async listEndpointMlsOffers(){return [{
    recipientDeviceId:"b",recipientSignerKeyId:"bob-key",
    recipientKeyPackageBase64Url:"AQID",recipientSignatureBase64Url:"signed",
  }];},
  async addEndpointMlsPeer(_auth,input){
    assert.equal(input.groupRevision,3);assert.equal(input.cryptoEpoch,1);
    assert.equal(input.recipientDeviceId,"b");
    committed=true;epoch=1;
  },
  async fetchEndpointMlsBootstrap(){assert.equal(committed,true);return {
    groupId:"fp-mg-call-new",admissionEventId:"event",
    welcome:new Uint8Array([8]),welcomeEpoch:1,welcomeStateRef:"epoch-one",
    commits:[],cryptoEpoch:1,cryptoStateRef:"epoch-one",
  };},
  async issueSignedJoinForAcceptedCall(auth){
    assert.equal(committed,true);joins++;
    return {...auth,callId:call.callId,sessionId:"session-"+auth.deviceId,
      joinFragment:"#ucr_join=signed"};
  },
} as UcrManagedFirstPartyHost;
const own=(id:string):UcrRecoveredCallEndpoint=>({
  async createGroup(group){assert.equal(id,"a");assert.equal(group,"fp-mg-call-new");return {cryptoStateRef:"epoch-zero"};},
  async createKeyPackage(){assert.equal(id,"b");return new Uint8Array([1,2,3]);},
  async addPeer(_group,pack){assert.equal(id,"a");assert.deepEqual([...pack],[1,2,3]);return {
    commit:new Uint8Array([7]),welcome:new Uint8Array([8]),
    cryptoEpoch:1,cryptoStateRef:"epoch-one",
  };},
  async applyWelcome(_group,welcome){assert.equal(id,"b");assert.deepEqual([...welcome],[8]);return {
    cryptoEpoch:1,cryptoStateRef:"epoch-one",
  };},
  async verifyRoster(_group,our,peer){
    assert.equal(our,id);assert.equal(peer,id==="a"?"b":"a");return true;
  },
});
await assert.rejects(establishRecoveredDirectCall("call-new",call,
  {host,endpoint:own("a"),auth:alice},{host,endpoint:own("b"),auth:bob}),/independent/);
// The Call object is not an authority for tenant/namespace selection.
// Reject cross-scope recovery before either endpoint can create MLS state.
for (const foreignCall of [
  {...call,tenantId:"foreign-tenant"},
  {...call,namespaceId:"foreign-namespace"},
]) {
  await assert.rejects(establishRecoveredDirectCall("call-old",foreignCall,
    {host,endpoint:own("a"),auth:alice},{host,endpoint:own("b"),auth:bob}),/independent/);
  assert.equal(published,false,"cross-scope Call must not publish MLS state");
}
// A new Call must not start endpoint MLS recovery while the compromised
// Call remains live, even if the caller's browser claims it was terminated.
const liveOldHost={...host,
  async getDirectCall(_auth:UcrAuthenticatedFirstEntry,id:string) {
    return id==="call-old" ? {...oldCall,state:"active" as const} : call;
  },
} as UcrManagedFirstPartyHost;
await assert.rejects(establishRecoveredDirectCall("call-old",call,
  {host:liveOldHost,endpoint:own("a"),auth:alice},
  {host:liveOldHost,endpoint:own("b"),auth:bob}),/prior Call is not canonically terminated/);
assert.equal(published,false,"live compromised Group must not initiate recovery");

// A different old-Call revision on the recipient is not the same canonical
// terminal snapshot. Do not publish MLS state before the two views converge.
const skewOldHost={...host,
  async getDirectCall(auth:UcrAuthenticatedFirstEntry,id:string) {
    return id==="call-old" && auth.deviceId==="b"
      ? {...oldCall,revision:oldCall.revision+1}
      : id==="call-old" ? oldCall : call;
  },
} as UcrManagedFirstPartyHost;
await assert.rejects(establishRecoveredDirectCall("call-old",call,
  {host:skewOldHost,endpoint:own("a"),auth:alice},
  {host:skewOldHost,endpoint:own("b"),auth:bob}),/prior Call is not canonically terminated/);
assert.equal(published,false,"divergent old-Call snapshots must fail closed");

// A host response for another Device must not create even a local MLS Group.
const foreignDeviceHost={...host,
  async describeAcceptedCallMls(auth:UcrAuthenticatedFirstEntry) {
    return {...descriptor(auth),deviceId:"foreign-device"};
  },
} as UcrManagedFirstPartyHost;
await assert.rejects(establishRecoveredDirectCall("call-old",call,
  {host:foreignDeviceHost,endpoint:own("a"),auth:alice},
  {host:foreignDeviceHost,endpoint:own("b"),auth:bob}),/fresh and Call-bound/);
assert.equal(published,false);

// A valid signed Commit is not enough when the canonical BFF reports a
// different recipient Device for the committed epoch. No Join may be issued.
const wrongPeerHost={...host,
  async describeAcceptedCallMls(auth:UcrAuthenticatedFirstEntry) {
    const state=descriptor(auth);
    return committed && auth.deviceId==="a"
      ? {...state,expectedPeerDeviceId:"foreign-device"} : state;
  },
} as UcrManagedFirstPartyHost;
await assert.rejects(establishRecoveredDirectCall("call-old",call,
  {host:wrongPeerHost,endpoint:own("a"),auth:alice},
  {host:wrongPeerHost,endpoint:own("b"),auth:bob}),/committed MLS peer Device/);
assert.equal(joins,0);
epoch=null;published=false;committed=false;

// Both independently authenticated Group snapshots must report the same
// committed CAS revision, advanced beyond the pre-Commit Group revision.
// A matching MLS epoch/state digest alone is not sufficient for signed Join.
for (const skew of [1, -1]) {
  const divergentGroupHost={...host,
    async describeAcceptedCallMls(auth:UcrAuthenticatedFirstEntry) {
      const state=descriptor(auth);
      return committed && auth.deviceId==="b"
        ? {...state,groupRevision:state.groupRevision!+skew} : state;
    },
  } as UcrManagedFirstPartyHost;
  await assert.rejects(establishRecoveredDirectCall("call-old",call,
    {host:divergentGroupHost,endpoint:own("a"),auth:alice},
    {host:divergentGroupHost,endpoint:own("b"),auth:bob}),/canonical committed MLS peer Device or epoch mismatch/);
  assert.equal(joins,0,"divergent Group revision cannot issue Join");
  epoch=null;published=false;committed=false;
}
const unadvancedGroupHost={...host,
  async describeAcceptedCallMls(auth:UcrAuthenticatedFirstEntry) {
    const state=descriptor(auth);
    return committed ? {...state,groupRevision:3} : state;
  },
} as UcrManagedFirstPartyHost;
await assert.rejects(establishRecoveredDirectCall("call-old",call,
  {host:unadvancedGroupHost,endpoint:own("a"),auth:alice},
  {host:unadvancedGroupHost,endpoint:own("b"),auth:bob}),/canonical committed MLS peer Device or epoch mismatch/);
assert.equal(joins,0,"unadvanced Group revision cannot issue Join");
epoch=null;published=false;committed=false;

// A Welcome for a different epoch must be refused before endpoint import.
const wrongWelcomeHost={...host,
  async fetchEndpointMlsBootstrap(auth:UcrAuthenticatedFirstEntry,
    input:{callId:string;expectedRevision:number}) {
    const bootstrap=await host.fetchEndpointMlsBootstrap(auth,input);
    return {...bootstrap,welcomeEpoch:bootstrap.welcomeEpoch+1};
  },
} as UcrManagedFirstPartyHost;
await assert.rejects(establishRecoveredDirectCall("call-old",call,
  {host:wrongWelcomeHost,endpoint:own("a"),auth:alice},
  {host:wrongWelcomeHost,endpoint:own("b"),auth:bob}),/recipient MLS bootstrap/);
assert.equal(joins,0);
epoch=null;published=false;committed=false;

// The recovered Join must bind the exact independently authenticated Identity,
// not merely a matching Device string returned by the same HTTP host.
const foreignJoinHost={...host,
  async issueSignedJoinForAcceptedCall(auth:UcrAuthenticatedFirstEntry) {
    const grant=await host.issueSignedJoinForAcceptedCall(auth,{callId:call.callId,expectedRevision:call.revision});
    return auth.deviceId==="a" ? {...grant,participantId:"foreign-identity"} : grant;
  },
} as UcrManagedFirstPartyHost;
await assert.rejects(establishRecoveredDirectCall("call-old",call,
  {host:foreignJoinHost,endpoint:own("a"),auth:alice},
  {host:foreignJoinHost,endpoint:own("b"),auth:bob}),/authenticated endpoint Identity\/Device/);
assert.equal(joins,2);
epoch=null;published=false;committed=false;joins=0;

// A stale but correctly Device-labelled KeyPackage cannot be committed:
// Bob has sealed the private provider for AQID, not the offered AQIE.
// Reject before accepting an irreversible canonical MLS epoch transition.
const staleOfferHost={...host,
  async listEndpointMlsOffers(auth:UcrAuthenticatedFirstEntry,
    input:{callId:string;expectedRevision:number}) {
    const offers=await host.listEndpointMlsOffers(auth,input);
    return offers.map(offer=>({...offer,recipientKeyPackageBase64Url:"AQIE"}));
  },
} as UcrManagedFirstPartyHost;
await assert.rejects(establishRecoveredDirectCall("call-old",call,
  {host:staleOfferHost,endpoint:own("a"),auth:alice},
  {host:staleOfferHost,endpoint:own("b"),auth:bob}),/KeyPackage changed between publish and Commit/);
assert.equal(committed,false);
assert.equal(joins,0);
epoch=null;published=false;committed=false;joins=0;

const result=await establishRecoveredDirectCall("call-old",call,
  {host,endpoint:own("a"),auth:alice},{host,endpoint:own("b"),auth:bob});
assert.equal(result.groupId,"fp-mg-call-new");
assert.equal(result.mediaCallId,"fp-m-call-new");
assert.equal(result.callerJoin.deviceId,"a");
assert.equal(result.recipientJoin.deviceId,"b");
assert.equal(joins,2);
// Hangup concurrent with final issuance must deny the recovered handoff.
epoch=null;published=false;committed=false;joins=0;
let inspection=0;
const hungUpHost={...host,
  async getDirectCall(_auth,id){if(id==="call-old")return oldCall;inspection++;return inspection===2
    ? {...call,state:"terminated" as const,revision:3} : call;},
} as UcrManagedFirstPartyHost;
await assert.rejects(establishRecoveredDirectCall("call-old",call,
  {host:hungUpHost,endpoint:own("a"),auth:alice},
  {host:hungUpHost,endpoint:own("b"),auth:bob}),/changed after MLS Join issuance/);
assert.equal(inspection,2);
assert.equal(joins,2);
// A still-active Call at a NEW revision is not the same accepted snapshot.
// A concurrent signal/re-negotiation after Join issuance must also fail closed.
epoch=null;published=false;committed=false;joins=0;
const revisedHost={...host,
  async getDirectCall(_auth,id){return id==="call-old"?oldCall:{...call,revision:call.revision+1};},
} as UcrManagedFirstPartyHost;
await assert.rejects(establishRecoveredDirectCall("call-old",call,
  {host:revisedHost,endpoint:own("a"),auth:alice},
  {host:revisedHost,endpoint:own("b"),auth:bob}),/changed after MLS Join issuance/);
assert.equal(joins,2);
console.log("contract-only recovered endpoint MLS + canonical Join orchestration (NOT live media)");
