/**
 * CONTRACT-ONLY security regression tests. The host here is in memory.
 * These tests DO NOT prove a real server, SFU, WebRTC or MLS media path.
 */
import assert from "node:assert/strict";
import {webcrypto} from "node:crypto";
import {createUcrContactCallJourney, type UcrDirectCall, type UcrDirectCallHost} from "./src/contact_call_journey.ts";
import {createUcrBrowserProtectedDeviceVault, type UcrLocalSignerRecordStore, type UcrLocalSignerRecord} from "./src/canonical_device_seed_vault.ts";
import type {UcrPrivateContactsStorage} from "./src/private_contacts.ts";

if (!globalThis.crypto) Object.defineProperty(globalThis,"crypto",{value:webcrypto});
function storage(): UcrPrivateContactsStorage {
  const keys=new Map<string,CryptoKey>(),records=new Map<string,any>();
  return {
    async getKey(k) {
      let key=keys.get(k);
      if (!key) {key=await crypto.subtle.generateKey({name:"AES-GCM",length:256},false,["encrypt","decrypt"]); keys.set(k,key);}
      return key;
    },
    async read(k) {return records.get(k)??null;},
    async compareAndSwap(k,expected,value) {
      if ((records.get(k)?.revision??null)!==expected)return false;
      records.set(k,value);return true;
    },
  };
}
function vault() {
  const records=new Map<string,UcrLocalSignerRecord>();
  const backing:UcrLocalSignerRecordStore={
    async get(k){return records.get(k)??null;},
    async addIfAbsent(k,v){if(records.has(k))return false;records.set(k,v);return true;},
  };
  return createUcrBrowserProtectedDeviceVault(backing);
}
const alice={tenantId:"tenant",namespaceId:null,participantId:"alice",deviceId:"device-a"};
const bob={...alice,participantId:"bob",deviceId:"device-b"};
let current=alice, revoked=false;
let idempotentStarts=0, issuanceCount=0;
let call:UcrDirectCall|null=null;
const seen=new Map<string,UcrDirectCall>();
const keyByDevice=new Map<string,{keyId:string;publicKey:Uint8Array}>();
const host:UcrDirectCallHost={
  async resumeAuthenticatedDevice(){return current;},
  async inspect(binding){
    const key=keyByDevice.get(binding.deviceId);
    return {deviceActive:!!key&&!revoked,deviceRevoked:revoked,
      activeKey:key?{keyId:key.keyId,publicKey:key.publicKey}:null};
  },
  async approveNewDevice(binding,signer){
    if(revoked)throw Error("revoked");
    keyByDevice.set(binding.deviceId,{keyId:signer.keyId,publicKey:signer.publicKey.slice()});
  },
  async issueSignedDeviceJoin(){throw Error("unscoped join must not be used");},
  async startDirectCall(binding,intent){
    if(binding.participantId!=="alice"||intent.peerIdentityId!=="bob")throw Error("unauthorized");
    const existing=seen.get(intent.idempotencyKey);
    if(existing)return existing;
    idempotentStarts++;
    call={tenantId:"tenant",namespaceId:null,callId:"call-1",
      callerIdentityId:"alice",calleeIdentityId:"bob",media:intent.media,
      state:"ringing",revision:1};
    seen.set(intent.idempotencyKey,call);
    return call;
  },
  async getDirectCall(_auth,callId){if(callId!=="call-1"||!call)throw Error("not found");return call;},
  async listIncomingDirectCalls(auth){
    return auth.participantId==="bob"&&call&&call.state==="ringing"?[call]:[];
  },
  async signalDirectCall(auth,request){
    if(!call||request.callId!==call.callId||request.expectedRevision!==call.revision)throw Error("revision conflict");
    const next=request.action==="accept"?"active":"terminated";
    call={...call,state:next,revision:call.revision+1};
    return call;
  },
  async issueSignedJoinForAcceptedCall(auth,request){
    if(!call||call.state!=="active"||call.callId!==request.callId||
      request.expectedRevision!==call.revision)throw Error("call not accepted");
    issuanceCount++;
    return {...auth,callId:call.callId,sessionId:"session-1",joinFragment:"#ucr_join=server-issued-placeholder"};
  },
};
const a=createUcrContactCallJourney(host,vault(),storage());
const ac=await a.addContact("Bob","bob");
assert.equal((await a.contacts())[0].peerIdentityId,"bob");
await assert.rejects(a.addContact("Self","alice"),/self/);
await assert.rejects(a.start("deleted","audio","retry-1"),/no longer exists/);
const first=await a.start(ac.id,"audio","retry-1");
assert.equal(first.state,"ringing");
assert.equal(idempotentStarts,1);
assert.equal((await a.start(ac.id,"audio","retry-1")).callId,first.callId);
assert.equal(idempotentStarts,1,"network retry cannot duplicate canonical StartCall");
await assert.rejects(a.join(first.callId),/not accepted/,"must not issue early Join");
assert.equal(issuanceCount,0);
await assert.rejects(a.signal(first.callId,"accept"),/only the invited recipient/);
current=bob;
const b=createUcrContactCallJourney(host,vault(),storage());
assert.equal((await b.incoming()).length,1);
const accepted=await b.signal(first.callId,"accept");
assert.equal(accepted.state,"active");
assert.equal((await b.incoming()).length,0);
const joinB=await b.join(first.callId);
assert.equal(joinB.deviceId,"device-b");
assert.equal(joinB.callId,"call-1");
current=alice;
const joinA=await a.join(first.callId);
assert.equal(joinA.deviceId,"device-a");
assert.notEqual(joinA.deviceId,joinB.deviceId);
assert.equal(issuanceCount,2);
current=bob;
assert.equal((await b.signal(first.callId,"hangup")).state,"terminated");
current=alice;
await assert.rejects(a.join(first.callId),/not accepted/);
assert.equal(issuanceCount,2,"closed Call must not issue a new Join");
revoked=true;
await assert.rejects(a.start(ac.id,"audio","new-call"),/revoked/);
assert.equal(idempotentStarts,1,"revoked Device cannot initiate");
revoked=false;
host.getDirectCall=async ()=>({...first,callerIdentityId:"mallory",calleeIdentityId:"eve"});
await assert.rejects(a.inspect("call-1"),/participants|identity|mismatch/);
host.getDirectCall=async ()=>call!;
current=bob;
host.listIncomingDirectCalls=async ()=>[{...first,state:"active"}];
await assert.rejects(b.incoming(),/foreign or invalid incoming/);
console.log("contract-only contact/call journey: verified state checks and fail-closed gating (NOT live E2E)");
