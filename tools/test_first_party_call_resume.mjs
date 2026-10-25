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
const refreshBegin=source.indexOf("async function refresh() {");
const refreshEnd=source.indexOf("async function initialize() {",refreshBegin);
assert.ok(refreshBegin>=0 && refreshEnd>refreshBegin,"first-party refresh implementation missing");
const refreshSnippet=source.slice(refreshBegin,refreshEnd);
const mediaBegin=source.indexOf("async function beginMedia(callId) {");
const mediaEnd=source.indexOf("async function dial(contact,media) {",mediaBegin);
assert.ok(mediaBegin>=0 && mediaEnd>mediaBegin,"first-party accepted-Join implementation missing");
const mediaSnippet=source.slice(mediaBegin,mediaEnd);
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
let inspections=0,rendered=0,incomingRendered=0,navigatedTo=null;
const context={
  accountScope:scope,active:null,sessionStorage:storage,
  idempotency:new Map(),crypto:{randomUUID:()=>"retry-id"},
  restoreSession:async()=>user,message(){},
  refreshing:false,navigating:false,timer:null,knownContacts:[],
  clearInterval(){},renderContacts(){},renderIncoming(){incomingRendered++;},
  authTrace:async(_stage,operation)=>operation(),clearRetryKey(){},
  setCallStage(){},URL,location:{origin:"https://localhost",replace(url){navigatedTo=url;}},
  calls:{async inspect(id){inspections++;assert.equal(id,call.callId);return call;},
    async incoming(){return [];}} ,
  authHttpCode:error=>Number(String(error.message).match(/HTTP (\d+)/)?.[1]??0),
  showActive(){rendered++;},
};
runInNewContext(
  'const ACTIVE_CALL_HINT_KEY="ucr.first-party.active-call.v1";\n'+snippet+
  "\n"+dialSnippet+"\n"+refreshSnippet+"\n"+mediaSnippet+
  "\nthis.ops={rememberActiveCall,forgetActiveCall,restoreActiveCall,dial,refresh,beginMedia};",
  context,
);
const {rememberActiveCall,forgetActiveCall,restoreActiveCall,dial,refresh,beginMedia}=context.ops;
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

// A periodic inspect begun for an old Call must not overwrite a newly dialed Call.
context.active={call,identity:"alice"};
forgetActiveCall();
rememberActiveCall(call,"alice");
let releaseRefresh,signalRefresh;
const refreshStarted=new Promise(resolve=>{signalRefresh=resolve;});
context.calls.inspect=()=>new Promise(resolve=>{releaseRefresh=resolve;signalRefresh();});
const oldRefresh=refresh();
await refreshStarted;
context.active={call:newer,identity:"alice"};
rememberActiveCall(newer,"alice");
releaseRefresh({...call,state:"terminated"});
await oldRefresh;
assert.equal(context.active.call.callId,newer.callId,"stale refresh must not replace newer Call");
assert.equal(JSON.parse(values.get(hintKey)).callId,newer.callId,
  "stale terminal refresh must not delete newer Call locator");

// A delayed accepted-Call Join cannot navigate to an ended/replaced Call.
const accepted={...call,state:"active"};
context.active={call:accepted,identity:"alice"};
forgetActiveCall();
rememberActiveCall(accepted,"alice");
let releaseJoin,signalJoin;
const joinStarted=new Promise(resolve=>{signalJoin=resolve;});
context.calls.join=()=>new Promise(resolve=>{releaseJoin=resolve;signalJoin();});
const pendingJoin=beginMedia(accepted.callId);
await joinStarted;
context.active={call:newer,identity:"alice"};
rememberActiveCall(newer,"alice");
releaseJoin({callId:accepted.callId,joinFragment:"#signed"});
await pendingJoin;
assert.equal(context.navigating,false,"stale accepted Join must not navigate");
assert.equal(navigatedTo,null,"stale Join must not replace location");
assert.equal(context.active.call.callId,newer.callId);
assert.equal(JSON.parse(values.get(hintKey)).callId,newer.callId);

// The SAME accepted Call may be refreshed while Join is pending: do not
// starve real slow-network connections by comparing mutable UI object identity.
context.active={call:accepted,identity:"alice"};
forgetActiveCall();
rememberActiveCall(accepted,"alice");
let resolveValidJoin,signalValidJoin;
const validJoinStarted=new Promise(resolve=>{signalValidJoin=resolve;});
context.calls.join=()=>new Promise(resolve=>{resolveValidJoin=resolve;signalValidJoin();});
const validJoin=beginMedia(accepted.callId);
await validJoinStarted;
context.active={...context.active,call:{...accepted}};
resolveValidJoin({callId:accepted.callId,joinFragment:"#signed"});
await validJoin;
assert.equal(context.navigating,true,"same active Call refresh must not block Join");
assert.match(navigatedTo,/\/client\.html#signed$/);
assert.equal(values.get("ucrFirstPartyDirectCall"),accepted.callId);
context.navigating=false;
navigatedTo=null;

// A pending incoming-list response cannot repaint a former Device's Calls.
context.active=null;
context.accountScope=scope;
let releaseIncoming,signalIncoming;
const incomingStarted=new Promise(resolve=>{signalIncoming=resolve;});
context.calls.incoming=()=>new Promise(resolve=>{releaseIncoming=resolve;signalIncoming();});
const previousIncomingCount=incomingRendered;
const staleIncoming=refresh();
await incomingStarted;
context.accountScope="logged-out";
releaseIncoming([call]);
await staleIncoming;
assert.equal(incomingRendered,previousIncomingCount,
  "late incoming list must not display after logout or Device switch");
context.accountScope=scope;

assert.match(source,/const call = await calls\.start\(contact\.id,media,requestId\);[\s\S]*?rememberActiveCall\(call,session\.participantId\);/);
assert.match(source,/const result = await calls\.signal\(call\.callId,"accept"\);[\s\S]*?rememberActiveCall\(result,session\.participantId\);/);
assert.match(source,/if \(!active\) await restoreActiveCall\(user\);/);
assert.match(source,/if \(fresh\.state === "terminated"\) \{\s*forgetActiveCall\(inspectedLocator\);/);
assert.match(source,/await host\.logout\(\);\s*forgetBinding\(\);\s*forgetActiveCall\(\);/);
assert.doesNotMatch(snippet,/calls\.join\(/,"untrusted locator cannot mint a Join");
console.log("PASS: canonical Call resume is scope-fenced, inspected, and cleared on terminal/denied state");
