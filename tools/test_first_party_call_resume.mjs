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
  calls:{async inspect(id){inspections++;assert.equal(id,call.callId);return call;}},
  authHttpCode:error=>Number(String(error.message).match(/HTTP (\d+)/)?.[1]??0),
  showActive(){rendered++;},
};
runInNewContext(
  'const ACTIVE_CALL_HINT_KEY="ucr.first-party.active-call.v1";\n'+snippet+
  "\nthis.ops={rememberActiveCall,forgetActiveCall,restoreActiveCall};",
  context,
);
const {rememberActiveCall,forgetActiveCall,restoreActiveCall}=context.ops;
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

assert.match(source,/const call = await calls\.start\(contact\.id,media,requestId\);[\s\S]*?rememberActiveCall\(call,session\.participantId\);/);
assert.match(source,/const result = await calls\.signal\(call\.callId,"accept"\);[\s\S]*?rememberActiveCall\(result,session\.participantId\);/);
assert.match(source,/if \(!active\) await restoreActiveCall\(user\);/);
assert.match(source,/if \(fresh\.state === "terminated"\) \{\s*forgetActiveCall\(\);/);
assert.match(source,/await host\.logout\(\);\s*forgetBinding\(\);\s*forgetActiveCall\(\);/);
assert.doesNotMatch(snippet,/calls\.join\(/,"untrusted locator cannot mint a Join");
console.log("PASS: canonical Call resume is scope-fenced, inspected, and cleared on terminal/denied state");
