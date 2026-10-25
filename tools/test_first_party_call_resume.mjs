#!/usr/bin/env node
// Executable same-tab Call-resume regression. No server or fake E2EE evidence.
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {runInNewContext} from "node:vm";

const source=readFileSync("crates/ucr-realtime-web/static/start.js","utf8");
const begin=source.indexOf("function principalScope(user) {");
const end=source.indexOf("function message(value) {",begin);
assert.ok(begin>=0 && end>begin,"first-party Call resume implementation missing");
const snippet=source.slice(begin,end);
const dialBegin=source.indexOf("async function dial(contact,media) {");
const dialEnd=source.indexOf("function renderIncoming(items)",dialBegin);
assert.ok(dialBegin>=0 && dialEnd>dialBegin,"first-party dialing implementation missing");
const dialSnippet=source.slice(dialBegin,dialEnd);
const user={tenantId:"tenant-a",namespaceId:null,participantId:"alice",deviceId:"device-a"};
const call={callId:"call-123",callerIdentityId:"alice",calleeIdentityId:"bob",state:"ringing"};
const scope=JSON.stringify([user.tenantId,user.namespaceId,user.participantId,user.deviceId]);
const values=new Map();
const storage={
  getItem:key=>values.get(key)??null,
  setItem:(key,value)=>values.set(key,value),
  removeItem:key=>values.delete(key),
};
const hintKey="ucr.first-party.active-call.v1";
let inspections=0,rendered=0;
const context={
  accountScope:scope,active:null,sessionStorage:storage,
  idempotency:new Map(),crypto:{randomUUID:()=>"retry-id"},
  restoreSession:async()=>user,message(){},
  calls:{async inspect(id){inspections++;assert.equal(id,call.callId);return call;}},
  authHttpCode:error=>Number(String(error.message).match(/HTTP (\d+)/)?.[1]??0),
  showActive(){rendered++;},
};
runInNewContext(
  'const ACTIVE_CALL_HINT_KEY="ucr.first-party.active-call.v1";\n'+snippet+
  "\n"+dialSnippet+
  "\nthis.ops={rememberActiveCall,forgetActiveCall,restoreActiveCall,dial};",
  context,
);
const {rememberActiveCall,forgetActiveCall,restoreActiveCall,dial}=context.ops;
rememberActiveCall(call,"alice");
assert.equal(JSON.parse(values.get(hintKey)).callId,call.callId);
context.active=null; // Reload, not a new Call or a new identity owner.
await restoreActiveCall(user);
assert.equal(context.active.call,call);
assert.equal(inspections,1);
assert.equal(rendered,1);

context.active=null;
values.set(hintKey,JSON.stringify({scope:"another-device",callId:call.callId}));
await restoreActiveCall(user);
assert.equal(context.active,null);
assert.equal(values.has(hintKey),false);
assert.equal(inspections,1,"foreign Device hint must never reach canonical Call inspection");

values.set(hintKey,JSON.stringify({scope,callId:"../foreign"}));
await restoreActiveCall(user);
assert.equal(values.has(hintKey),false);
assert.equal(inspections,1,"invalid Call hint must fail before transport");

rememberActiveCall(call,"mallory");
assert.equal(values.has(hintKey),false,"foreign participant cannot save a Call hint");

rememberActiveCall(call,"alice");
context.calls.inspect=async()=>({...call,state:"terminated"});
await restoreActiveCall(user);
assert.equal(values.has(hintKey),false);
assert.equal(context.active,null);

rememberActiveCall(call,"alice");
context.calls.inspect=async()=>{throw new Error("HTTP 403: Call denied");};
await assert.rejects(restoreActiveCall(user),/HTTP 403/);
assert.equal(values.has(hintKey),false,"denied Call must not remain resumable");

rememberActiveCall(call,"alice");
context.calls.inspect=async()=>{throw new Error("HTTP 503: temporary outage");};
await assert.rejects(restoreActiveCall(user),/HTTP 503/);
assert.equal(values.has(hintKey),true,"transient failure must not erase durable Call locator");

let release;
context.calls.inspect=()=>new Promise(resolve=>{release=resolve;});
const pending=restoreActiveCall(user);
context.accountScope="switched-device";
release(call);
await pending;
assert.equal(context.active,null,"late Call inspection must not restore after Device switch");
assert.equal(values.has(hintKey),false);
context.accountScope=scope;
rememberActiveCall(call,"alice");
forgetActiveCall();
assert.equal(values.has(hintKey),false);

// A late canonical inspect must not overwrite a newer Call or its locator.
let resolveOld;
context.active=null;
rememberActiveCall(call,"alice");
context.calls.inspect=()=>new Promise(resolve=>{resolveOld=resolve;});
const stale=restoreActiveCall(user);
const newer={...call,callId:"call-new"};
context.active={call:newer,identity:"alice"};
rememberActiveCall(newer,"alice");
resolveOld(call);
await stale;
assert.equal(context.active.call.callId,newer.callId);
assert.equal(JSON.parse(values.get(hintKey)).callId,newer.callId);

// Even a late canonical denial must not delete the replacement locator.
let rejectOld;
context.active=null;
forgetActiveCall();
rememberActiveCall(call,"alice");
context.calls.inspect=()=>new Promise((_resolve,reject)=>{rejectOld=reject;});
const staleDenied=restoreActiveCall(user);
rememberActiveCall(newer,"alice");
rejectOld(new Error("HTTP 403: previous Call denied"));
await assert.rejects(staleDenied,/HTTP 403/);
assert.equal(JSON.parse(values.get(hintKey)).callId,newer.callId);

// Locator replacement alone fences restoration, even if no active Call exists.
let resolveReplaced;
context.active=null;
forgetActiveCall();
rememberActiveCall(call,"alice");
context.calls.inspect=()=>new Promise(resolve=>{resolveReplaced=resolve;});
const replaced=restoreActiveCall(user);
rememberActiveCall(newer,"alice");
resolveReplaced(call);
await replaced;
assert.equal(context.active,null);
assert.equal(JSON.parse(values.get(hintKey)).callId,newer.callId);

// A transiently unverified pending Call must block a second irreversible start.
let starts=0;
context.calls.start=async()=>{starts++;return newer;};
context.active=null;
forgetActiveCall();
rememberActiveCall(call,"alice");
await assert.rejects(dial({id:"contact-b"},"video"),/незавершённый вызов/);
assert.equal(starts,0,"unresolved Call locator must block duplicate dialing");
forgetActiveCall();
await dial({id:"contact-b"},"video");
assert.equal(starts,1);
assert.equal(context.active.call.callId,newer.callId);
assert.equal(JSON.parse(values.get(hintKey)).callId,newer.callId);
assert.match(source,/if \(activeCallLocator\(\) !== null\) throw Error\("сначала дождитесь проверки незавершённого вызова"\);/);

assert.match(source,/const call = await calls\.start\(contact\.id,media,requestId\);[\s\S]*?rememberActiveCall\(call,session\.participantId\);/);
assert.match(source,/const result = await calls\.signal\(call\.callId,"accept"\);[\s\S]*?rememberActiveCall\(result,session\.participantId\);/);
assert.match(source,/if \(!active\) await restoreActiveCall\(user\);/);
assert.match(source,/if \(fresh\.state === "terminated"\) \{\s*forgetActiveCall\(\);/);
assert.match(source,/await host\.logout\(\);\s*forgetBinding\(\);\s*forgetActiveCall\(\);/);
assert.doesNotMatch(snippet,/calls\.join\(/,"untrusted locator cannot mint a Join");
console.log("PASS: canonical Call resume is scope-fenced, inspected, and cleared on terminal/denied state");
