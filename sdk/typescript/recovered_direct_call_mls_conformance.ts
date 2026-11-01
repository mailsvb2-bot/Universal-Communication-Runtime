/** Contract-only recovery flow: NOT proof of physical WebRTC video or relay blindness. */
import assert from "node:assert/strict";
import {establishRecoveredDirectCall, type UcrRecoveredCallEndpoint} from "./src/recovered_direct_call_mls.ts";
import type {UcrManagedFirstPartyHost, UcrEndpointMlsCallDescriptor} from "./src/first_party_browser_http.ts";
import type {UcrAuthenticatedFirstEntry} from "./src/canonical_first_party_call_entry.ts";
import type {UcrDirectCall} from "./src/contact_call_journey.ts";

const alice:UcrAuthenticatedFirstEntry={tenantId:"t",namespaceId:null,participantId:"alice",deviceId:"a"};
const bob:UcrAuthenticatedFirstEntry={tenantId:"t",namespaceId:null,participantId:"bob",deviceId:"b"};
const call:UcrDirectCall={tenantId:"t",namespaceId:null,callId:"call-new",callerIdentityId:"alice",calleeIdentityId:"bob",media:"video",state:"active",revision:2};
let epoch:number|null=null, joins=0, published=false, committed=false;
const descriptor=(auth:UcrAuthenticatedFirstEntry):UcrEndpointMlsCallDescriptor=>({
  callId:call.callId,expectedRevision:2,groupRevision:published?(committed?4:3):null,
  expectedPeerDeviceId:committed?(auth.deviceId==="a"?"b":"a"):null,
  cryptoEpoch:epoch,cryptoStateRef:epoch===null?null:epoch===0?"epoch-zero":"epoch-one",
  mediaCallId:"fp-m-call-new",groupId:"fp-mg-call-new",conversationId:"fp-mc-call-new",
  creatorPrincipalId:"alice",peerPrincipalId:"bob",deviceId:auth.deviceId,
  cryptoCapability:"group_mls",requiresEndpointOwnedCommit:true,
});
const host:UcrManagedFirstPartyHost={
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

const result=await establishRecoveredDirectCall("call-old",call,
  {host,endpoint:own("a"),auth:alice},{host,endpoint:own("b"),auth:bob});
assert.equal(result.groupId,"fp-mg-call-new");
assert.equal(result.mediaCallId,"fp-m-call-new");
assert.equal(result.callerJoin.deviceId,"a");
assert.equal(result.recipientJoin.deviceId,"b");
assert.equal(joins,2);
console.log("contract-only recovered endpoint MLS + canonical Join orchestration (NOT live media)");
