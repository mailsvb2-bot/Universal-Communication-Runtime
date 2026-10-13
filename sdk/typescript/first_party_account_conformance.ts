/** Two independent pseudonymous users, recovered second Devices, signout and
 * restart login. Contract-only: Rust SQLite durability is tested separately. */
import assert from "node:assert/strict";
import {webcrypto} from "node:crypto";
import {
  registerUcrFirstPartyUser,recoverUcrFirstPartyDevice,
  authenticateUcrFirstPartyDevice,createUcrFirstPartyHttpHost,
} from "./src/first_party_browser_http.ts";
import {
  createUcrBrowserProtectedDeviceVault,
  type UcrLocalSignerRecord,type UcrLocalSignerRecordStore,
} from "./src/canonical_device_seed_vault.ts";
if(!globalThis.crypto)Object.defineProperty(globalThis,"crypto",{value:webcrypto});
Object.defineProperty(globalThis,"location",{
  configurable:true,value:{origin:"http://localhost:18080"},
});
const origin="http://localhost:18080";
function encode(v:Uint8Array){
  return btoa(String.fromCharCode(...v)).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
}
function decode(v:string){
  return Uint8Array.from(atob(v.replace(/-/g,"+").replace(/_/g,"/")),c=>c.charCodeAt(0));
}
function reply(v:unknown,status=200){
  return new Response(JSON.stringify(v),{status,headers:{"Content-Type":"application/json"}});
}
function vault(){
  const rows=new Map<string,UcrLocalSignerRecord>();
  const storage:UcrLocalSignerRecordStore={
    async get(k){return rows.get(k)??null;},
    async addIfAbsent(k,v){if(rows.has(k))return false;rows.set(k,v);return true;},
  };
  return {instance:createUcrBrowserProtectedDeviceVault(storage),storage};
}
type Binding={tenantId:string;namespaceId:null;participantId:string;deviceId:string};
type Account={devices:Map<string,{keyId:string;publicKeyBase64Url:string;revoked:boolean}>;code:string};
type Challenge={binding:Binding;nonce:string;kind:string};
const accounts=new Map<string,Account>();
const challenges=new Map<string,Challenge>();
let number=0,challengeSequence=0;
function transport(){
  let session:Binding|null=null;
  const fetchImpl:typeof fetch=async(url,init)=>{
    const path=new URL(String(url)).pathname;
    assert.equal(new URL(String(url)).origin,origin);
    assert.equal(init?.redirect,"error");
    assert.equal(init?.credentials,"same-origin");
    if(path==="/v1/first-party/bootstrap"){
      return reply({tenantId:"public-self-service",namespaceId:null});
    }
    if(path==="/v1/first-party/session"){
      return session?reply(session):reply({error:"unauthorized"},401);
    }
    const data=JSON.parse(String(init?.body));
    assert.equal((init?.headers as Record<string,string>)["X-UCR-First-Party-Request"],"v1");
    function challenge(binding:Binding,kind:string){
      const challengeId="challenge-"+(++challengeSequence);
      const nonce=encode(webcrypto.getRandomValues(new Uint8Array(32)));
      challenges.set(challengeId,{binding,nonce,kind});
      return {challengeId,challengeBytesBase64Url:nonce};
    }
    if(path==="/v1/first-party/signup/begin"){
      assert.deepEqual(data,{});
      const id=++number;
      const binding:Binding={tenantId:"public-self-service",namespaceId:null,
        participantId:"identity-"+id,deviceId:"device-"+id};
      return reply({...challenge(binding,"signup"),binding});
    }
    if(path==="/v1/first-party/recover/begin"){
      return reply(challenge(data,"recover"));
    }
    if(path.endsWith("/finish")){
      const kind=path.includes("/signup/")?"signup":"recover";
      const pending=challenges.get(data.challengeId);
      if(!pending||pending.kind!==kind||
          JSON.stringify(pending.binding)!==JSON.stringify(data.binding)){
        return reply({error:"replay_or_scope"},403);
      }
      challenges.delete(data.challengeId);
      const proof=new TextEncoder().encode(
        "ucr-first-party-"+kind+".v1\u0000"+
        JSON.stringify([
          data.binding.tenantId,data.binding.namespaceId,
          data.binding.participantId,data.binding.deviceId,
          data.keyId,data.publicKeyBase64Url,
          data.challengeId,pending.nonce,
        ]),
      );
      const key=await webcrypto.subtle.importKey(
        "raw",decode(data.publicKeyBase64Url),{name:"Ed25519"},false,["verify"]);
      if(!await webcrypto.subtle.verify("Ed25519",key,decode(data.signatureBase64Url),proof)){
        return reply({error:"invalid_signature"},403);
      }
      let account=accounts.get(data.binding.participantId);
      if(kind==="signup"){
        if(account||data.recoveryCode!==undefined)return reply({error:"conflict"},409);
        account={devices:new Map(),code:""};
        accounts.set(data.binding.participantId,account);
      }else if(!account||account.code!==data.recoveryCode||
          account.devices.has(data.binding.deviceId)){
        return reply({error:"recovery_denied"},403);
      }
      account!.devices.set(data.binding.deviceId,{
        keyId:data.keyId,publicKeyBase64Url:data.publicKeyBase64Url,revoked:false});
      account!.code=encode(webcrypto.getRandomValues(new Uint8Array(32)));
      session=data.binding;
      return reply({binding:session,recoveryCode:account!.code});
    }
    if(path==="/v1/first-party/login/challenge"){
      return reply(challenge(data,"login"));
    }
    if(path==="/v1/first-party/login/verify"){
      const pending=challenges.get(data.challengeId);
      const trusted=accounts.get(data.binding.participantId)?.devices.get(data.binding.deviceId);
      if(!pending||pending.kind!=="login"||!trusted||trusted.revoked)return reply({error:"unauthorized"},401);
      challenges.delete(data.challengeId);
      const proof=new TextEncoder().encode("ucr-first-party-device-login.v1\u0000"+
        JSON.stringify([
          data.binding.tenantId,data.binding.namespaceId,data.binding.participantId,
          data.binding.deviceId,data.challengeId,pending.nonce,
        ]));
      const key=await webcrypto.subtle.importKey(
        "raw",decode(trusted.publicKeyBase64Url),{name:"Ed25519"},false,["verify"]);
      if(!await webcrypto.subtle.verify("Ed25519",key,decode(data.signatureBase64Url),proof)){
        return reply({error:"unauthorized"},401);
      }
      session=data.binding;
      return reply(session);
    }
    if(!session||JSON.stringify(session)!==JSON.stringify(data.binding)){
      return reply({error:"unauthorized"},401);
    }
    const account=accounts.get(session.participantId)!;
    if(path==="/v1/first-party/device/inspect"){
      const signer=account.devices.get(session.deviceId);
      if(!signer||signer.revoked)return reply({error:"revoked"},401);
      return reply({deviceActive:true,deviceRevoked:false,
        activeKey:{keyId:signer.keyId,publicKeyBase64Url:signer.publicKeyBase64Url}});
    }
    if(path==="/v1/first-party/device/list"){
      return reply([...account.devices].map(([deviceId,value])=>({
        deviceId,state:value.revoked?"revoked":"active",
      })));
    }
    if(path==="/v1/first-party/device/rotate-recovery"){
      account.code=encode(webcrypto.getRandomValues(new Uint8Array(32)));
      return reply({recoveryCode:account.code});
    }
    if(path==="/v1/first-party/device/revoke"){
      const signer=account.devices.get(data.deviceId);
      if(!signer)return reply({error:"not_found"},404);
      signer.revoked=true;
      if(data.deviceId===session.deviceId)session=null;
      return reply({revoked:true});
    }
    if(path==="/v1/first-party/logout"){
      session=null;return reply({signedOut:true});
    }
    return reply({error:"not_found"},404);
  };
  return {fetchImpl,get session(){return session;}};
}
const a=transport(),b=transport();
const av=vault(),bv=vault();
const userA=await registerUcrFirstPartyUser(av.instance,{origin,fetchImpl:a.fetchImpl});
const userB=await registerUcrFirstPartyUser(bv.instance,{origin,fetchImpl:b.fetchImpl});
assert.notEqual(userA.binding.participantId,userB.binding.participantId);
assert.notEqual(userA.recoveryCode,userB.recoveryCode);
const hA=createUcrFirstPartyHttpHost(av.instance,{origin,fetchImpl:a.fetchImpl});
const hB=createUcrFirstPartyHttpHost(bv.instance,{origin,fetchImpl:b.fetchImpl});
assert.equal((await hA.listDevices()).length,1);
assert.equal((await hB.listDevices()).length,1);
await hA.logout();
await assert.rejects(hA.resumeAuthenticatedDevice(),/HTTP 401/);
// A persisted browser signer allows fully independent signed login after restart.
const avRestored=createUcrBrowserProtectedDeviceVault(av.storage);
const confirmed=await authenticateUcrFirstPartyDevice(
  avRestored,{origin,fetchImpl:a.fetchImpl},userA.binding);
assert.deepEqual(confirmed,userA.binding);
// Recover a SECOND trusted Device for each new user with their own code.
const a2=transport(),b2=transport();
const a2v=vault(),b2v=vault();
const nextA=await recoverUcrFirstPartyDevice(a2v.instance,
  {origin,fetchImpl:a2.fetchImpl},userA.binding.participantId,userA.recoveryCode);
const nextB=await recoverUcrFirstPartyDevice(b2v.instance,
  {origin,fetchImpl:b2.fetchImpl},userB.binding.participantId,userB.recoveryCode);
assert.notEqual(nextA.binding.deviceId,userA.binding.deviceId);
assert.notEqual(nextB.binding.deviceId,userB.binding.deviceId);
assert.equal((await hA.listDevices()).length,2);
const hA2=createUcrFirstPartyHttpHost(a2v.instance,{origin,fetchImpl:a2.fetchImpl});
assert.equal((await hA2.listDevices()).length,2);
// Old one-time recovery tokens cannot be used for a third Device.
await assert.rejects(recoverUcrFirstPartyDevice(vault().instance,
  {origin,fetchImpl:transport().fetchImpl},
  userA.binding.participantId,userA.recoveryCode),/HTTP 403/);
// Rotation invalidates the second code as well.
const rotated=await hA2.rotateRecoveryCode();
assert.notEqual(rotated,nextA.recoveryCode);
await hA.revokeDevice(nextA.binding.deviceId);
await assert.rejects(hA2.resumeAuthenticatedDevice(),/HTTP 401|revoked/);
assert.equal((await hA.listDevices()).find(x=>x.deviceId===nextA.binding.deviceId)?.state,"revoked");
console.log("RT0 first-party self-service contracts: 2 users, 4 independently signed Devices, restart, logout, single-use recovery, rotate/revoke (NOT live HTTPS)");
