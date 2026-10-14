/**
 * Cross-layer first-call CONTRACT test, not a live SFU/MLS/ICE proof.
 *
 * Exercises the actual browser HTTP adapter + protected device preparation
 * + encrypted contacts + Call coordinator for TWO separate authenticated
 * Devices against one deliberately strict emulated canonical BFF.
 * The Rust BFF owns the real Identity/Device/Call/Conference state.
 */
import assert from "node:assert/strict";
import {webcrypto} from "node:crypto";
import {createUcrBrowserProtectedDeviceVault, type UcrLocalSignerRecord, type UcrLocalSignerRecordStore} from "./src/canonical_device_seed_vault.ts";
import {createUcrFirstPartyHttpHost} from "./src/first_party_browser_http.ts";
import {createUcrContactCallJourney, type UcrDirectCall} from "./src/contact_call_journey.ts";
import type {UcrPrivateContactsStorage} from "./src/private_contacts.ts";

if (!globalThis.crypto) Object.defineProperty(globalThis,"crypto",{value:webcrypto});
Object.defineProperty(globalThis,"location",{
  configurable:true,value:{origin:"http://localhost:18080"},
});
const origin="http://localhost:18080";
const alice={tenantId:"tenant",namespaceId:null,participantId:"alice",deviceId:"device-a"};
const bob={...alice,participantId:"bob",deviceId:"device-b"};
type Binding=typeof alice;
const allCalls=new Map<string,UcrDirectCall>();
const starts=new Map<string,string>();
const requests:string[]=[];
let approved=0, signedJoins=0, bareJoinAttempts=0, revokedBob=false;
function response(value:unknown,status=200):Response {
  return new Response(JSON.stringify(value),{status,headers:{"Content-Type":"application/json"}});
}
function contactStorage():UcrPrivateContactsStorage {
  const keys=new Map<string,CryptoKey>();
  const rows=new Map<string,any>();
  return {
    async getKey(key) {
      let value=keys.get(key);
      if(!value) {
        value=await crypto.subtle.generateKey({name:"AES-GCM",length:256},false,["encrypt","decrypt"]);
        keys.set(key,value);
      }
      return value;
    },
    async read(key){return rows.get(key)??null;},
    async compareAndSwap(key,revision,value){
      if((rows.get(key)?.revision??null)!==revision)return false;
      rows.set(key,value);return true;
    },
  };
}
function protectedVault() {
  const rows=new Map<string,UcrLocalSignerRecord>();
  const storage:UcrLocalSignerRecordStore={
    async get(key){return rows.get(key)??null;},
    async addIfAbsent(key,value){if(rows.has(key))return false;rows.set(key,value);return true;},
  };
  return createUcrBrowserProtectedDeviceVault(storage);
}
const vaultA=protectedVault(),vaultB=protectedVault();
const signerA=await vaultA.stageNew(alice);
const signerB=await vaultB.stageNew(bob);
function base64url(raw:Uint8Array) {
  return btoa(String.fromCharCode(...raw)).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
}
const trust=new Map([[alice.deviceId,signerA],[bob.deviceId,signerB]]);
function authenticatedFetch(actor:Binding):typeof fetch {
  return async (input,init) => {
    const path=new URL(String(input)).pathname;
    requests.push(actor.participantId+":"+path);
    assert.equal(new URL(String(input)).origin,origin);
    assert.equal(init?.credentials,"same-origin");
    assert.equal(init?.redirect,"error");
    assert.equal(init?.cache,"no-store");
    assert.equal(init?.mode,"same-origin");
    if(actor.participantId==="bob"&&revokedBob)return response({error:"device_revoked"},401);
    if(path==="/v1/first-party/session") {
      assert.equal(init?.method,"GET");
      return response(actor);
    }
    assert.equal(init?.method,"POST");
    const headers=init?.headers as Record<string,string>;
    assert.equal(headers["X-UCR-First-Party-Request"],"v1");
    assert.equal(headers["Content-Type"],"application/json");
    const data=JSON.parse(String(init?.body));
    assert.deepEqual(data.binding,actor,"server independently correlates cookie and binding");
    const signer=trust.get(actor.deviceId);
    if(!signer)return response({error:"untrusted"},401);
    if(path==="/v1/first-party/device/inspect") {
      assert.deepEqual(Object.keys(data),["binding"]);
      return response({deviceActive:true,deviceRevoked:false,activeKey:{
        keyId:signer.keyId,publicKeyBase64Url:base64url(signer.publicKey),
      }});
    }
    if(path==="/v1/first-party/device/challenge"||
       path==="/v1/first-party/device/approve") {
      approved++;
      return response({error:"existing signer must not be reprovisioned"},403);
    }
    if(path==="/v1/first-party/call/join") {
      bareJoinAttempts++;
      return response({error:"Call-free Join forbidden"},403);
    }
    if(path==="/v1/first-party/call/start") {
      if(actor.participantId!=="alice"||
         data.intent.peerIdentityId!=="bob"||
         !["audio","video"].includes(data.intent.media))return response({error:"forbidden"},403);
      const key=actor.participantId+":"+data.intent.idempotencyKey;
      const known=starts.get(key);
      if(known)return response(allCalls.get(known));
      const id="fp-"+(data.intent.media==="video"?"v":"a")+"-"+data.intent.idempotencyKey;
      const call:UcrDirectCall={
        tenantId:"tenant",namespaceId:null,callId:id,
        callerIdentityId:"alice",calleeIdentityId:"bob",
        media:data.intent.media,state:"ringing",revision:1,
      };
      starts.set(key,id);allCalls.set(id,call);return response(call);
    }
    if(path==="/v1/first-party/call/incoming") {
      assert.deepEqual(Object.keys(data),["binding"]);
      return response([...allCalls.values()].filter(c=>
        c.calleeIdentityId===actor.participantId&&
        (c.state==="ringing"||c.state==="inviting")));
    }
    const call=allCalls.get(data.callId);
    if(!call||![call.callerIdentityId,call.calleeIdentityId].includes(actor.participantId)) {
      return response({error:"not_found"},404);
    }
    if(path==="/v1/first-party/call/get")return response(call);
    if(path==="/v1/first-party/call/join-accepted") {
      if(call.state!=="active"||call.revision!==data.expectedRevision)return response({error:"forbidden"},403);
      signedJoins++;
      return response({...actor,callId:call.callId,
        sessionId:"session-"+actor.participantId+"-"+signedJoins,
        joinFragment:"#ucr_join=Y2FsbA.c2lnbmF0dXJl",
      });
    }
    if(path==="/v1/first-party/call/signal") {
      if(data.expectedRevision!==call.revision)return response({error:"revision_conflict"},409);
      const allowed=(data.action==="accept"||data.action==="reject"||data.action==="busy")
        ? actor.participantId===call.calleeIdentityId&&call.state==="ringing"
        : data.action==="cancel"
          ? actor.participantId===call.callerIdentityId&&call.state==="ringing"
          : data.action==="hangup"&&call.state==="active";
      if(!allowed)return response({error:"forbidden"},403);
      const next:UcrDirectCall={...call,
        state:data.action==="accept"?"active":"terminated",revision:call.revision+1};
      allCalls.set(call.callId,next);return response(next);
    }
    return response({error:"unknown_route"},404);
  };
}
const hostA=createUcrFirstPartyHttpHost(vaultA,{origin,fetchImpl:authenticatedFetch(alice)});
const hostB=createUcrFirstPartyHttpHost(vaultB,{origin,fetchImpl:authenticatedFetch(bob)});
const contactsA=contactStorage(),contactsB=contactStorage();
const appA=createUcrContactCallJourney(hostA,vaultA,contactsA);
const appB=createUcrContactCallJourney(hostB,vaultB,contactsB);

// Contact -> one StartCall, retry is the same canonical Call, never a second call.
const contact=await appA.addContact("Bob","bob");
const first=await appA.start(contact.id,"video","first-call-1");
assert.equal(first.state,"ringing");
assert.equal((await appA.start(contact.id,"video","first-call-1")).callId,first.callId);
assert.equal(allCalls.size,1);
assert.equal((await appA.contacts()).length,1);
assert.equal((await appB.contacts()).length,0,"encrypted local contacts are not shared");
assert.equal((await appA.incoming()).length,0);
assert.equal((await appB.incoming()).length,1);
await assert.rejects(appA.join(first.callId),/not accepted/);
await assert.rejects(appB.join(first.callId),/not accepted/);
assert.equal(signedJoins,0);

// Independently authenticated B accepts. Both Devices get their own Join
// only for the accepted Call/revision (not from a Device-only shortcut).
const accepted=await appB.signal(first.callId,"accept");
assert.equal(accepted.state,"active");
assert.equal((await appB.incoming()).length,0);
const grantB=await appB.join(first.callId);
const grantA=await appA.join(first.callId);
assert.equal(grantA.callId,grantB.callId);
assert.notEqual(grantA.deviceId,grantB.deviceId);
assert.notEqual(grantA.sessionId,grantB.sessionId);
assert.equal(signedJoins,2);
assert.equal(approved,0,"trusted signers must not be enrolled again");
await assert.rejects(hostA.issueSignedDeviceJoin(alice),/unscoped Device Join forbidden/);
await assert.rejects(hostB.issueSignedDeviceJoin(bob),/unscoped Device Join forbidden/);
assert.equal(bareJoinAttempts,0,"legacy route must never be transmitted");

// Stale revision and foreign session bindings cannot advance the call.
await assert.rejects(hostA.signalDirectCall(alice,{
  callId:first.callId,expectedRevision:1,action:"hangup",
}),/HTTP 409/);
await assert.rejects(hostA.getDirectCall(bob,first.callId),/account changed/);

// Server-confirmed termination survives a new browser coordinator instance,
// then both old Device grants are unusable as a means to rejoin.
assert.equal((await appB.signal(first.callId,"hangup")).state,"terminated");
const afterRestart=createUcrContactCallJourney(hostA,vaultA,contactsA);
assert.equal((await afterRestart.inspect(first.callId)).state,"terminated");
assert.equal((await afterRestart.contacts()).length,1);
await assert.rejects(afterRestart.join(first.callId),/not accepted/);
await assert.rejects(appB.join(first.callId),/not accepted/);
assert.equal(signedJoins,2);

// Device revocation must invalidate B's independently authenticated session,
// even when a previously issued Join fragment exists.
revokedBob=true;
await assert.rejects(appB.incoming(),/HTTP 401/);
await assert.rejects(appB.inspect(first.callId),/HTTP 401/);
assert.ok(requests.includes("alice:/v1/first-party/call/start"));
assert.ok(requests.includes("bob:/v1/first-party/call/incoming"));
assert.ok(requests.includes("bob:/v1/first-party/call/signal"));
assert.ok(requests.includes("alice:/v1/first-party/call/join-accepted"));
assert.ok(requests.includes("bob:/v1/first-party/call/join-accepted"));
console.log("RT0 two-device HTTP contract: contact -> start -> incoming -> accept -> distinct Join -> hangup -> restart/revoke, no standalone Join (NOT live media)");
