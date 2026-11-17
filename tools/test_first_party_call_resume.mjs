#!/usr/bin/env node
// Executable same-tab Call-resume regression. No server or fake E2EE evidence.
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {runInNewContext} from "node:vm";

const source=readFileSync("crates/ucr-realtime-web/static/start.js","utf8");
const mediaPage=readFileSync("crates/ucr-realtime-web/static/client.html","utf8");
assert.match(source,/ucr-e2ee-state:fp-v1:/,"pre-Join MLS must use a scoped sealed snapshot");
assert.match(mediaPage,/ucr-e2ee-state:fp-v1:/,"media page must restore the SAME scoped MLS snapshot");
assert.match(mediaPage,/function endpointAdapterPersistenceStorageKey\(/,
  "media transport state must have an independent record name, not an independent authority");
assert.match(mediaPage,/key\+":media-adapter-v1"/,
  "opaque media adapter persistence must never overwrite the OpenMLS provider");
assert.match(source,/navigator\.locks\.request\("ucr-first-party-mls:"\+key/,
  "pre-Join cross-tab OpenMLS state must be serialized");
assert.match(mediaPage,/navigator\.locks\.request\("ucr-first-party-mls:"\+key/,
  "post-Join state must share the same cross-tab lock");
assert.match(source,/state\.authorize_direct_call_roster\(committed\.expectedPeerDeviceId\)/,
  "signed Join must require the exact locally verified two-Device MLS roster");
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
const terminationBegin=source.indexOf("async function terminateActiveCall() {");
const terminationEnd=source.indexOf('el("cancel").addEventListener',terminationBegin);
assert.ok(terminationBegin>=0 && terminationEnd>terminationBegin,
  "first-party pending hangup guard missing");
const terminationSnippet=source.slice(terminationBegin,terminationEnd);
const cancelListenerEnd=source.indexOf('el("signup").addEventListener',terminationEnd);
assert.ok(cancelListenerEnd>terminationEnd,"hangup click listener missing");
const cancelListenerSnippet=source.slice(terminationEnd,cancelListenerEnd);
let cancelClick=null;
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
  accountScope:scope,active:null,uiAuthGeneration:0,sessionStorage:storage,
  idempotency:new Map(),crypto:{randomUUID:()=>"retry-id"},
  restoreSession:async()=>user,message(){},
  refreshing:false,navigating:false,timer:null,knownContacts:[],
  mlsPreparation:null,
  // This isolated regression executes Call code without the page diagnostics.
  // Diagnostics are observation-only; they do not own media or grant authority.
  authDiagnostic(){},
  rememberCallInfo(){},
  mlsHint(){return "MLS/Join temporarily unavailable";},
  sessionCallInfo:{mlsPhase:null},
  callRoleOf(snapshot){
    if(snapshot?.identity===snapshot?.call?.callerIdentityId)return "caller";
    if(snapshot?.identity===snapshot?.call?.calleeIdentityId)return "callee";
    return null;
  },
  prepareFirstPartyEndpointMls:async()=>true,
  clearInterval(){},renderContacts(){},renderIncoming(){incomingRendered++;},
  authTrace:async(_stage,operation)=>operation(),clearRetryKey(){},
  setCallStage(){},URL,location:{origin:"https://localhost",replace(url){navigatedTo=url;}},
  calls:{async inspect(id){inspections++;assert.equal(id,call.callId);return call;},
    async incoming(){return [];}} ,
  authHttpCode:error=>Number(String(error.message).match(/HTTP (\d+)/)?.[1]??0),
  showActive(){rendered++;},
  el(id){
    assert.equal(id,"cancel");
    return {addEventListener(type,listener){
      assert.equal(type,"click");
      cancelClick=listener;
    }};
  },
  run(){throw Error("hangup must not pass through the busy UI action gate");},
};
runInNewContext(
  'const ACTIVE_CALL_HINT_KEY="ucr.first-party.active-call.v1";\n'+snippet+
  "\n"+dialSnippet+"\n"+refreshSnippet+"\n"+mediaSnippet+"\n"+terminationSnippet+"\n"+cancelListenerSnippet+
  "\nthis.ops={rememberActiveCall,forgetActiveCall,restoreActiveCall,dial,refresh,beginMedia,terminateActiveCall};",
  context,
);
const {rememberActiveCall,forgetActiveCall,restoreActiveCall,dial,refresh,beginMedia,terminateActiveCall}=context.ops;
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

// Same Identity/Device after logout is still a NEW authentication generation.
// The old in-flight inspection must not restore its previous Call.
context.active=null;
forgetActiveCall();
rememberActiveCall(call,"alice");
let releaseOldGeneration;
context.calls.inspect=()=>new Promise(resolve=>{releaseOldGeneration=resolve;});
const oldGenerationResume=restoreActiveCall(user);
context.uiAuthGeneration++;
releaseOldGeneration(call);
await oldGenerationResume;
assert.equal(context.active,null,"old auth generation cannot restore a Call");
assert.equal(values.has(hintKey),false);
context.uiAuthGeneration=0;

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

// A Call creation that finishes after a Device session change may exist on
// the canonical owner, but must not be painted under the replacement login.
context.active=null;
forgetActiveCall();
let finishStaleDial,signalStaleDial;
const staleDialStarted=new Promise(resolve=>{signalStaleDial=resolve;});
context.calls.start=()=>new Promise(resolve=>{finishStaleDial=resolve;signalStaleDial();});
const staleDial=dial({id:"contact-b"},"audio");
await staleDialStarted;
context.uiAuthGeneration++;
finishStaleDial(newer);
await assert.rejects(staleDial,/Device changed during Call creation/);
assert.equal(context.active,null,"late Call creation must not repaint another Device");
assert.equal(values.has(hintKey),false);
assert.match(source,/if \(locator !== null\) throw Error\("сначала дождитесь проверки незавершённого вызова"\);/);

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

// MLS is a mandatory pre-Join gate, not an optional optimization.
const acceptedForMls={...call,state:"active"};
context.active={call:acceptedForMls,identity:"alice"};
forgetActiveCall();
rememberActiveCall(acceptedForMls,"alice");
let preflightJoinAttempts=0;
context.calls.join=async()=>{preflightJoinAttempts++;return {callId:call.callId,joinFragment:"#signed"};};
context.prepareFirstPartyEndpointMls=async()=>false;
await beginMedia(call.callId);
assert.equal(preflightJoinAttempts,0,"no Join before the independently admitted MLS pair");
assert.equal(context.navigating,false);
let finishMls,signalMls;
const mlsStarted=new Promise(resolve=>{signalMls=resolve;});
context.prepareFirstPartyEndpointMls=()=>new Promise(resolve=>{finishMls=resolve;signalMls();});
const pendingMls=beginMedia(call.callId);
await mlsStarted;
context.active.terminating=true; // Hangup while KeyPackage/Welcome is still pending.
finishMls(true);
await pendingMls;
assert.equal(preflightJoinAttempts,0,"a late successful MLS preflight cannot bypass Hangup");
context.active.terminating=false;
context.prepareFirstPartyEndpointMls=async()=>true;

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

// A Join from a previous authentication generation must not navigate even if
// the same Identity/Device and same Call locator were re-established.
context.active={call:accepted,identity:"alice"};
forgetActiveCall();
rememberActiveCall(accepted,"alice");
let finishOldGenerationJoin,signalOldGenerationJoin;
const oldGenerationJoinStarted=new Promise(resolve=>{signalOldGenerationJoin=resolve;});
context.calls.join=()=>new Promise(resolve=>{finishOldGenerationJoin=resolve;signalOldGenerationJoin();});
const staleGenerationJoin=beginMedia(accepted.callId);
await oldGenerationJoinStarted;
context.uiAuthGeneration++;
finishOldGenerationJoin({callId:accepted.callId,joinFragment:"#signed"});
await staleGenerationJoin;
assert.equal(context.navigating,false,"prior login generation must never navigate");
assert.equal(navigatedTo,null,"old signed Join must not navigate after reauthentication");

// A pending incoming-list response cannot repaint a former Device's Calls.
forgetActiveCall();
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

// A delayed 401 from the PREVIOUS authentication generation must not erase
// a fresh login. This is distinct from a current-generation 401, which must
// still fail closed. A transient 503 must preserve the visible session.
let denyOldSession, signalOldSession;
const oldSessionStarted=new Promise(resolve=>{signalOldSession=resolve;});
context.restoreSession=()=>new Promise((_resolve,reject)=>{
  denyOldSession=reject;
  signalOldSession();
});
let authViewResets=0;
context.plClearAuthenticatedView=()=>{
  authViewResets++;
  context.accountScope=null;
  context.uiAuthGeneration++;
};
const oldAuthRefresh=refresh();
await oldSessionStarted;
context.uiAuthGeneration++; // another tab or explicit reauthentication won
denyOldSession(new Error("HTTP 401: retired browser session"));
await oldAuthRefresh;
assert.equal(authViewResets,0,"old 401 cannot clear newly authenticated Device");
assert.equal(context.accountScope,scope,"new authenticated scope must survive old denial");

context.restoreSession=async()=>{throw Error("HTTP 401: current session revoked");};
await assert.rejects(refresh(),/HTTP 401/);
assert.equal(authViewResets,1,"current-generation 401 must clear revoked Device");

context.accountScope=scope;
context.restoreSession=async()=>{throw Error("HTTP 503: temporary outage");};
await assert.rejects(refresh(),/HTTP 503/);
assert.equal(authViewResets,1,"transient network outage must not clear authenticated Device");
context.restoreSession=async()=>user;
context.accountScope=scope;
context.uiAuthGeneration=0;

// A user-requested hangup must fence BOTH a fresh Join and a Join already
// waiting on the canonical server, even when a periodic inspect races.
const acceptedCall={...call,state:"active"};
context.accountScope=scope;
context.active={call:acceptedCall,identity:"alice"};
forgetActiveCall();
rememberActiveCall(acceptedCall,"alice");
context.calls.incoming=async()=>[];
context.calls.inspect=async()=>acceptedCall;
let completeHangup;
context.calls.signal=()=>new Promise(resolve=>{completeHangup=resolve;});
let joinAttempts=0;
context.calls.join=async()=>{joinAttempts++;return {callId:call.callId,joinFragment:"#signed"};};
const pendingHangup=terminateActiveCall();
assert.equal(context.active.terminating,true,"hangup must fence media synchronously");
await refresh();
await beginMedia(acceptedCall.callId);
assert.equal(joinAttempts,0,"no Join during pending hangup");
assert.equal(context.navigating,false);
completeHangup({...acceptedCall,state:"terminated"});
await pendingHangup;
assert.equal(context.active.call.state,"terminated");
assert.equal(values.has(hintKey),false,"confirmed hangup clears only its locator");

// A Join requested BEFORE hangup must be discarded when its response arrives.
context.active={call:acceptedCall,identity:"alice"};
rememberActiveCall(acceptedCall,"alice");
let finishJoin,signalJoinPending;
const joinPending=new Promise(resolve=>{signalJoinPending=resolve;});
context.calls.join=()=>new Promise(resolve=>{finishJoin=resolve;signalJoinPending();});
const inFlightJoin=beginMedia(acceptedCall.callId);
await joinPending;
const secondHangup=terminateActiveCall();
finishJoin({callId:acceptedCall.callId,joinFragment:"#signed"});
await inFlightJoin;
assert.equal(context.navigating,false,"late Join must not navigate during hangup");
assert.equal(navigatedTo,null);
completeHangup({...acceptedCall,state:"terminated"});
await secondHangup;

// A failed termination unblocks a deliberate retry; a late response for a
// replaced Call cannot erase the new Call's locator or UI state.
context.active={call:acceptedCall,identity:"alice"};
rememberActiveCall(acceptedCall,"alice");
context.calls.signal=async()=>{throw Error("HTTP 503: temporary outage");};
await assert.rejects(terminateActiveCall(),/HTTP 503/);
assert.equal(context.active.terminating,true,
  "unknown hangup outcome must keep signed Join and media blocked");
assert.equal(context.active.terminationInFlight,false,
  "unknown hangup outcome must allow an explicit retry");
assert.equal(JSON.parse(values.get(hintKey)).stopRequested,true,
  "same-tab Call locator must retain stop intent without becoming an authority");
await beginMedia(acceptedCall.callId);
assert.equal(context.navigating,false,"failed hangup must not resume signed Join");

// Reload must not erase the user's stop intent after an ambiguous network reply.
context.active=null;
context.calls.inspect=async()=>acceptedCall;
await restoreActiveCall(user);
assert.equal(context.active.terminating,true,
  "reload must restore the stop fence only after canonical Call inspection");
await beginMedia(acceptedCall.callId);
assert.equal(context.navigating,false,"reloaded Call must not auto-enter E2EE media");

// Even a nonterminal canonical reply cannot override the user's stop intent.
// The owner may have raced an acceptance or rejected a stale revision.
context.calls.signal=async()=>({...acceptedCall,state:"active"});
await terminateActiveCall();
assert.equal(context.active.terminating,true,
  "nonterminal hangup reply must preserve fail-closed media fence");
assert.equal(context.active.terminationInFlight,false,
  "nonterminal reply must leave Hangup available for retry");
await beginMedia(acceptedCall.callId);
assert.equal(context.navigating,false,"nonterminal reply must not navigate to media");

let completeOld;
context.calls.signal=()=>new Promise(resolve=>{completeOld=resolve;});
const oldHangup=terminateActiveCall();
context.active={call:newer,identity:"alice"};
rememberActiveCall(newer,"alice");
completeOld({...acceptedCall,state:"terminated"});
await oldHangup;
assert.equal(context.active.call.callId,newer.callId);
assert.equal(JSON.parse(values.get(hintKey)).callId,newer.callId);

// The accepted incoming-Call handler awaits Join under the ordinary busy lock.
// Its visible Hangup button must still fence the pending Join synchronously.
context.active={call:acceptedCall,identity:"alice"};
rememberActiveCall(acceptedCall,"alice");
let finishBusyHangup;
context.calls.signal=()=>new Promise(resolve=>{finishBusyHangup=resolve;});
context.busy=true;
assert.equal(typeof cancelClick,"function","real Hangup click handler must be wired");
cancelClick();
assert.equal(context.active.terminating,true,
  "Hangup click must fence media even while another UI action is busy");
finishBusyHangup({...acceptedCall,state:"terminated"});
await new Promise(resolve=>setImmediate(resolve));
assert.equal(context.active.call.state,"terminated");
context.busy=false;

// Execute the REAL incoming-accept handler with delayed canonical responses.
// A cross-tab logout or same-Device reauthentication must fence the callback
// both after acceptance and after the separate session verification.
const incomingBegin=source.indexOf("function renderIncoming(items) {");
const incomingEnd=source.indexOf("async function refresh() {",incomingBegin);
assert.ok(incomingBegin>=0 && incomingEnd>incomingBegin);
const handlers=new Map();
const incomingCall={...call,callerIdentityId:"bob",calleeIdentityId:"alice"};
let incomingLocator=null,safeAcceptedHints=0;
const incomingContext={
  accountScope:scope,uiAuthGeneration:0,active:null,plOwnIdentity:"alice",
  document:{createElement:()=>({append(){},textContent:"",className:""})},
  el:id=>{assert.equal(id,"incoming");return {replaceChildren(){},append(){}};},
  nameFor:id=>id,
  btn:(label,callback)=>{handlers.set(label,callback);return {label};},
  activeCallLocator:()=>incomingLocator,
  calls:{},
  host:{},
  principalScope:user=>JSON.stringify([user.tenantId,user.namespaceId,user.participantId,user.deviceId]),
  rememberActiveCall(result,identity){
    assert.equal(identity,"alice");assert.equal(result.callId,incomingCall.callId);
    safeAcceptedHints++;incomingLocator="scoped-call-hint";
  },
  showActive(){throw Error("stale accept cannot paint Call");},
  beginMedia(){throw Error("stale accept cannot join media");},
  refresh(){},
};
runInNewContext(source.slice(incomingBegin,incomingEnd)+
  "\nthis.renderIncoming=renderIncoming;",incomingContext);
incomingContext.renderIncoming([incomingCall]);
const acceptIncoming=handlers.get("Принять");
assert.equal(typeof acceptIncoming,"function");
let finishOldAccept;
incomingContext.calls.signal=()=>new Promise(resolve=>{finishOldAccept=resolve;});
incomingContext.host.resumeAuthenticatedDevice=async()=>user;
const staleAccept=acceptIncoming();
incomingContext.uiAuthGeneration++;
incomingLocator=null; // explicit Logout clears the untrusted pending locator
finishOldAccept({...incomingCall,state:"active"});
await staleAccept;
assert.equal(incomingContext.active,null,"old generation must not paint accepted Call");

let finishOldSession;
incomingContext.calls.signal=async()=>({...incomingCall,state:"active"});
incomingContext.host.resumeAuthenticatedDevice=()=>new Promise(resolve=>{finishOldSession=resolve;});
const staleSessionAccept=acceptIncoming();
// Flush the separate VM context's promise jobs before checking the verifier.
await new Promise(resolve=>setImmediate(resolve));
assert.equal(typeof finishOldSession,"function","accept must verify canonical Device");
incomingContext.uiAuthGeneration++;
// Logout clears only the local recovery locator; old callback cannot restore it.
incomingLocator=null;
finishOldSession(user);
await staleSessionAccept;
assert.equal(incomingContext.active,null,"late Device verification must not paint Call");

let savedAccepts=0,mediaAccepts=0;
incomingContext.host.resumeAuthenticatedDevice=async()=>user;
incomingContext.rememberActiveCall=(result,identity)=>{
  assert.equal(result.callId,incomingCall.callId);
  assert.equal(identity,"alice");
  incomingLocator="scoped-call-hint";savedAccepts++;
};
incomingContext.showActive=()=>{};
incomingContext.beginMedia=async()=>{mediaAccepts++;};
await acceptIncoming();
assert.equal(incomingContext.active.call.callId,call.callId);
assert.equal(savedAccepts,3,"pending intent and committed acceptance remain scoped across Device recheck");
assert.equal(mediaAccepts,1,"fresh accepted Call must still enter canonical media");

incomingContext.active=null;
incomingLocator=null;
incomingContext.host.resumeAuthenticatedDevice=async()=>({...user,deviceId:"other-device"});
await assert.rejects(acceptIncoming(),/Device changed during Call acceptance/);
assert.equal(incomingContext.active,null,"wrong Device must not adopt accepted Call");

// A pending cookie check must not perform a fresh Device reauthentication
// after explicit logout or a same-Device session replacement.
const authBegin=source.indexOf("async function restoreSession() {");
const authEnd=source.indexOf("function clearRetryKey(call) {",authBegin);
assert.ok(authBegin>=0 && authEnd>authBegin);
let reauthCount=0;
const authContext={
  uiAuthGeneration:0,
  SessionSuperseded:class SessionSuperseded extends Error{
    constructor(){super("Device session changed during authentication");}
  },
  host:{},vault:{},location:{origin:"https://localhost"},
  authTrace:async(_stage,op)=>op(),lastBinding:()=>user,
  authHttpCode:error=>Number(String(error.message).match(/HTTP (\d+)/)?.[1]??0),
  authDiagnostic(){},forgetBinding(){},
  principalScope:identity=>JSON.stringify([
    identity.tenantId,identity.namespaceId,identity.participantId,identity.deviceId]),
  authenticateUcrFirstPartyDevice:async()=>{reauthCount++;return user;},
};
runInNewContext(source.slice(authBegin,authEnd)+"\nthis.restoreSession=restoreSession;",authContext);
let rejectPendingCookie;
authContext.host.resumeAuthenticatedDevice=()=>new Promise((_resolve,reject)=>{
  rejectPendingCookie=reject;
});
const staleCookie=authContext.restoreSession();
authContext.uiAuthGeneration++;
rejectPendingCookie(new Error("HTTP 401: old session expired"));
await assert.rejects(staleCookie,/Device session changed during authentication/);
assert.equal(reauthCount,0,"logout must block late automatic Device reauthentication");

// Reauthentication itself may already be in flight when logout happens.
let finishReauthentication;
authContext.uiAuthGeneration=0;
authContext.host.resumeAuthenticatedDevice=async()=>{throw Error("HTTP 401: expired");};
authContext.authenticateUcrFirstPartyDevice=()=>{
  reauthCount++;
  return new Promise(resolve=>{finishReauthentication=resolve;});
};
const staleReauthentication=authContext.restoreSession();
await new Promise(resolve=>setImmediate(resolve));
assert.equal(typeof finishReauthentication,"function");
authContext.uiAuthGeneration++;
finishReauthentication(user);
await assert.rejects(staleReauthentication,/Device session changed during authentication/);
assert.equal(reauthCount,1);

// An unavailable session endpoint is not proof of an expired cookie. It must
// NEVER initiate a new login/Set-Cookie behind the user's back. Only 401 may
// invoke the protected existing-Device possession flow.
authContext.uiAuthGeneration=0;
for (const error of [
  new Error("HTTP 503: session endpoint unavailable"),
  new Error("HTTP 429: rate limited"),
  new Error("HTTP 403: trust denied"),
  new TypeError("network offline"),
]) {
  authContext.host.resumeAuthenticatedDevice=async()=>{throw error;};
  await assert.rejects(authContext.restoreSession(),rejected=>rejected===error);
  assert.equal(reauthCount,1,"non-401 session failure must not mint another cookie");
}

// The current generation must still recover with its original protected signer.
authContext.host.resumeAuthenticatedDevice=async()=>{throw Error("HTTP 401: expired");};
authContext.uiAuthGeneration=0;
authContext.authenticateUcrFirstPartyDevice=async()=>{reauthCount++;return user;};
assert.equal((await authContext.restoreSession()).deviceId,user.deviceId);
assert.equal(reauthCount,2);

// Logout must bypass the ordinary busy lock. In particular, a pending Call
// acceptance or signed Join must never make the user-facing Logout a no-op.
// Execute the actual listener with an intentionally delayed server response.
const logoutBegin=source.indexOf('el("logout").addEventListener("click"');
const logoutEnd=source.indexOf("// Mobile tabs become hidden",logoutBegin);
assert.ok(logoutBegin>=0 && logoutEnd>logoutBegin);
let logoutClick,completeLogout,forgotBinding=0,forgotCall=0,serverLogoutCalls=0;
let logoutMessage="";
const who={textContent:""};
const logoutContext={
  busy:true,navigating:false,uiAuthGeneration:0,accountScope:scope,
  active:{call:acceptedCall},
  el:id=>id==="logout"?{addEventListener:(_event,handler)=>{logoutClick=handler;}}:who,
  run:()=>{throw Error("security Logout must bypass the busy UI action gate");},
  forgetBinding:()=>{forgotBinding++;},
  forgetActiveCall:()=>{forgotCall++;},
  plClearAuthenticatedView:()=>{
    logoutContext.uiAuthGeneration++;
    logoutContext.accountScope=null;
    logoutContext.active=null;
  },
  host:{logout:()=>{
    serverLogoutCalls++;
    assert.equal(logoutContext.active,null,"local Call must stop before HTTP logout");
    assert.equal(logoutContext.uiAuthGeneration,1,"pending Join must be fenced");
    return new Promise(resolve=>{completeLogout=resolve;});
  }},
  message:value=>{logoutMessage=value;},
};
runInNewContext(source.slice(source.indexOf("let logoutInFlight=false;",logoutBegin-200),logoutEnd)+
  "\nthis.logoutState=()=>logoutInFlight;",logoutContext);
assert.equal(typeof logoutClick,"function");
logoutClick(); // A busy action MUST NOT swallow Logout.
assert.equal(forgotBinding,1);
assert.equal(forgotCall,1);
assert.equal(logoutContext.active,null);
assert.equal(logoutContext.accountScope,null);
assert.equal(logoutContext.uiAuthGeneration,1);
assert.equal(serverLogoutCalls,1);
assert.equal(logoutContext.logoutState(),true);
logoutClick(); // Repeated clicks cannot issue duplicate concurrent Logout.
assert.equal(serverLogoutCalls,1);
completeLogout();
await new Promise(resolve=>setImmediate(resolve));
assert.match(who.textContent,/вышли/);
assert.equal(logoutContext.logoutState(),false);

// An ambiguous server failure cannot be presented as a completed sign-out:
// the HttpOnly cookie may still exist even though local Call admission stopped.
logoutContext.accountScope=scope;
logoutContext.active={call:acceptedCall};
let rejectLogout;
logoutContext.host.logout=()=>new Promise((_resolve,reject)=>{rejectLogout=reject;});
logoutClick();
assert.equal(logoutContext.active,null);
rejectLogout(new Error("HTTP 503: unavailable"));
await new Promise(resolve=>setImmediate(resolve));
assert.match(logoutMessage,/выход на сервере не подтверждён/);
assert.equal(logoutContext.logoutState(),false);

assert.match(source,/const call = await calls\.start\(contact\.id,media,requestId\);[\s\S]*?rememberActiveCall\(call,session\.participantId\);/);
assert.match(source,/const result = await calls\.signal\(call\.callId,"accept"\);[\s\S]*?rememberActiveCall\(result,session\.participantId\);/);
assert.match(source,/if \(!active\) await restoreActiveCall\(user\);/);
assert.match(source,/if \(fresh\.state === "terminated"\) \{\s*forgetActiveCall\(inspectedLocator\);/);
assert.match(source,/forgetBinding\(\);\s*forgetActiveCall\(\);\s*plClearAuthenticatedView\(\);/);
assert.doesNotMatch(snippet,/calls\.join\(/,"untrusted locator cannot mint a Join");
// A stale same-tab Direct Call marker plus a separately signed grant must
// NEVER trigger automatic camera/microphone capture. Match the exact derived
// media Call through the canonical authenticated BFF before join().
const handoffStart=mediaPage.indexOf("async function verifyFirstPartyAutoJoinHandoff(");
const handoffBoundary=/\r?\ntry\{\r?\n  const params=new URLSearchParams\(location\.hash\.slice\(1\)\);/.exec(mediaPage.slice(handoffStart));
const handoffEnd=handoffBoundary?handoffStart+handoffBoundary.index:-1;
assert.ok(handoffStart>=0&&handoffEnd>handoffStart,"canonical pre-auto-Join binding gate missing");
const handoffCode=mediaPage.slice(handoffStart,handoffEnd);
const grant={call_id:"fp-m-matched",tenant_id:"tenant-a",namespace_id:null,
  participant_id:"alice",device_id:"device-a",expires:Date.now()+60000};
let descriptorCalls=0,hostCalls=0;
let canonicalMediaMode="video";
const canonicalHandoffHost={
  async resumeAuthenticatedDevice(){hostCalls++;return user;},
  async getDirectCall(auth,id){
    assert.equal(auth.participantId,"alice");assert.equal(id,"fp-v-12345678-1234-1234-1234-1234567890ab");
    return {state:"active",revision:2,media:canonicalMediaMode};
  },
  async describeAcceptedCallMls(auth,request){
    descriptorCalls++;
    assert.equal(auth.deviceId,"device-a");
    assert.equal(request.callId,"fp-v-12345678-1234-1234-1234-1234567890ab");
    assert.equal(request.expectedRevision,2);
    return {mediaCallId:"fp-m-matched",deviceId:"device-a"};
  },
};
let hint="fp-v-12345678-1234-1234-1234-1234567890ab";
const handoffContext={
  claims:grant,signedGrantRetired:false,firstPartyAcceptedMediaKind:null,
  sessionStorage:{getItem:()=>hint},
  firstPartyCanonicalHttpHost:null,
  installFirstPartyDeviceAuthority:async()=>{
    handoffContext.firstPartyCanonicalHttpHost=canonicalHandoffHost;
  },
  Date,
};
runInNewContext(handoffCode+"\nthis.verifyHandoff=verifyFirstPartyAutoJoinHandoff;",handoffContext);
await handoffContext.verifyHandoff("fp-v-12345678-1234-1234-1234-1234567890ab",grant);
assert.equal(descriptorCalls,1);
assert.equal(hostCalls,1);
assert.equal(handoffContext.firstPartyAcceptedMediaKind,"video");
canonicalMediaMode="audio";
handoffContext.firstPartyAcceptedMediaKind=null;
await handoffContext.verifyHandoff("fp-v-12345678-1234-1234-1234-1234567890ab",grant);
assert.equal(handoffContext.firstPartyAcceptedMediaKind,"audio",
  "verified audio Call must not inherit video permission from browser settings");
canonicalMediaMode="invalid";
handoffContext.firstPartyAcceptedMediaKind=null;
await assert.rejects(handoffContext.verifyHandoff(
  "fp-v-12345678-1234-1234-1234-1234567890ab",grant),/media kind unavailable/);
assert.equal(handoffContext.firstPartyAcceptedMediaKind,null);
canonicalMediaMode="video";
await assert.rejects(handoffContext.verifyHandoff("fp-v-12345678-1234-1234-1234-1234567890ab",
  {...grant,call_id:"fp-m-unrelated"}),/binding mismatch/);
hint="fp-v-other";
await assert.rejects(handoffContext.verifyHandoff("fp-v-12345678-1234-1234-1234-1234567890ab",grant),/binding mismatch/);
hint="fp-v-12345678-1234-1234-1234-1234567890ab";
handoffContext.signedGrantRetired=true;
await assert.rejects(handoffContext.verifyHandoff("fp-v-12345678-1234-1234-1234-1234567890ab",grant),/binding mismatch/);
assert.match(mediaPage,/verifyFirstPartyAutoJoinHandoff\(directCall,handoffClaims\)\.then\(\(\)=>\{/);
const policyStart=mediaPage.indexOf("function policyAllows(kind){");
const policyEnd=mediaPage.indexOf("function screenShareSupported(){",policyStart);
assert.ok(policyStart>=0&&policyEnd>policyStart);
const policyScope={
  claims:grant,firstPartyAcceptedMediaKind:null,
  mediaPolicy:{publish_audio_allowed:true,publish_camera_allowed:true,screen_share_allowed:true},
};
runInNewContext(mediaPage.slice(policyStart,policyEnd)+"\nthis.isAllowed=policyAllows;",policyScope);
assert.equal(policyScope.isAllowed("camera"),false,"no verified Call => camera must stay off");
policyScope.firstPartyAcceptedMediaKind="audio";
assert.equal(policyScope.isAllowed("camera"),false,"audio Call must never capture camera");
assert.equal(policyScope.isAllowed("audio"),true,"audio Call still permits canonical microphone");
policyScope.firstPartyAcceptedMediaKind="video";
assert.equal(policyScope.isAllowed("camera"),true,"only canonically verified video permits camera");
policyScope.mediaPolicy.publish_camera_allowed=false;
assert.equal(policyScope.isAllowed("camera"),false,"canonical media policy still overrides video");
policyScope.claims={...grant,call_id:"room-grant"};
assert.equal(policyScope.isAllowed("audio"),true,"non-first-party room policy remains unchanged");
assert.match(mediaPage,/const requestAudio=audioAllowed&&preferred.mic,requestCamera=cameraAllowed&&preferred.video/);
assert.match(mediaPage,/ui.cameraToggle.disabled=!sessionActive\|\|!cameraAllowed/);
// Only an explicitly missing/expired cookie (401) may trigger the existing
// trusted-Device possession proof. Network/5xx, rate limits and revocation
// must fail closed without issuing a replacement session.
const authorityBegin=mediaPage.indexOf("async function installFirstPartyDeviceAuthority(){");
const authorityFinish=mediaPage.indexOf("function requireCanonicalMediaHostReady(){",authorityBegin);
assert.ok(authorityBegin>=0&&authorityFinish>authorityBegin);
const authorityImpl=mediaPage.slice(authorityBegin,authorityFinish)
  .replace('await import("./endpoint-media/reference_browser_media_installer.js")',
    "await installerStub");
async function authorityCase(error){
  let retries=0,inspections=0;
  const signer={keyId:"own-key",publicKey:new Uint8Array(32)};
  const host={
    resumeAuthenticatedDevice:async()=>{throw error;},
    inspect:async()=>{inspections++;return {
      deviceActive:true,deviceRevoked:false,activeKey:signer
    };},
  };
  const context={
    claims:{call_id:"fp-m-target",tenant_id:user.tenantId,namespace_id:null,
      participant_id:user.participantId,device_id:user.deviceId},
    sessionStorage:{getItem:()=>null},
    location:{origin:"https://app.petrellink.ru"},
    window:{},Uint8Array,
    installerStub:{
      createUcrBrowserProtectedDeviceVault:()=>({load:async()=>signer}),
      createUcrFirstPartyHttpHost:()=>host,
      authenticateUcrFirstPartyDevice:async()=>{
        retries++;return user;
      },
    },
    createEndpointAdmissionResolver:()=>()=>{},
  };
  runInNewContext("let firstPartyDeviceAuthorityPromise=null,firstPartyCanonicalHttpHost=null;\n"+
    authorityImpl+"\nthis.install=installFirstPartyDeviceAuthority;",context);
  let thrown=null;
  try{await context.install();}catch(e){thrown=e;}
  return {retries,inspections,thrown,context};
}
for(const failure of [
  new Error("first-party canonical authority rejected request: HTTP 503"),
  new Error("first-party canonical authority rejected request: HTTP 403"),
  new Error("first-party canonical authority rejected request: HTTP 429"),
  new TypeError("network offline"),
]){
  const result=await authorityCase(failure);
  assert.equal(result.thrown,failure);
  assert.equal(result.retries,0,"non-401 cannot silently reauthenticate media Device");
  assert.equal(result.inspections,0);
}
const expiredAuthority=await authorityCase(
  new Error("first-party canonical authority rejected request: HTTP 401"));
assert.equal(expiredAuthority.thrown,null);
assert.equal(expiredAuthority.retries,1);
assert.equal(expiredAuthority.inspections,1);
console.log("PASS: canonical Call resume, pre-auto-Join binding and 401-only media reauthentication");

// Exercise consumed-grant recovery from this existing required Windows CI entry.
await import("./test_first_party_media_recovery.mjs");
await import("./test_first_party_peer_join_race.mjs");
