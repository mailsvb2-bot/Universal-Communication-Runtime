#!/usr/bin/env node
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import vm from "node:vm";

const html=readFileSync("crates/ucr-realtime-web/static/client.html","utf8");
const start=html.indexOf("function ucrShowFreshFirstPartyAdmission(){");
const end=html.indexOf("const UCR_CANDIDATE_TYPES",start);
assert.ok(start>=0&&end>start,"canonical fresh-grant action is missing");
const action=html.slice(start,end);
const status={children:[],replaceChildren(...items){this.children=items;}};
const join={disabled:false},state={textContent:""};
const dom={
 createElement(kind){
  assert.equal(kind,"a");
  return {href:"",textContent:""};
 },
 createTextNode(text){return {textContent:text};},
};
const ctx={document:dom,ui:{join,state,status}};
vm.runInNewContext(action+"\nthis.recover=ucrShowFreshFirstPartyAdmission;",ctx);
ctx.recover();
assert.equal(join.disabled,true,"an already-consumed Join grant must not be retried");
assert.equal(state.textContent,"Требуется новый допуск");
assert.equal(status.children.length,2);
assert.equal(status.children[1].href,"/start",
  "retry must return to the canonical authenticated Direct Call owner");
assert.doesNotMatch(action,/fetch\(|calls\.start|localStorage/,
  "a fresh session is obtained only by the authenticated canonical /start path");

// Client-side capture/Join must not start before confirmed media authorization.
// Failed accepted first-party Join is cleaned up without hanging up its parent
// Call, and its old signed grant cannot be reused (the observed HTTP 401).
const joinStart=html.indexOf("async function join(){");
const joinEnd=html.indexOf("function scheduleEntryRetry(){",joinStart);
assert.ok(joinStart>=0&&joinEnd>joinStart);
const joinLogic=html.slice(joinStart,joinEnd);
assert.match(joinLogic,/const needsFreshFirstPartyGrant=firstPartyMediaGrant&&\s*\(sessionActive\|\|\(ucrMediaActivationStage==="REALTIME_JOIN"&&\[401,403,404\]\.includes\(e\?\.status\)\)\)/);
assert.match(joinLogic,/if\(sessionActive\)\{\s*try\{await leave\(\{retireGrant:false\}\)/);
assert.match(joinLogic,/if\(needsFreshFirstPartyGrant\)\{\s*[\s\S]*?signedGrantRetired=true;\s*ucrShowFreshFirstPartyAdmission\(\);\s*return;/);
assert.match(joinLogic,/ui\.join\.disabled=signedGrantRetired\|\|grantExpired/);
assert.match(html,/mediaActivationStage:ucrMediaActivationStage/);
// Losing accepted first-party access is terminal for the old grant and
// must expose the canonical fresh-admission link instead of a disabled dead end.
const endStart=html.indexOf("async function endUnverifiedMedia(generation,message){");
const endEnd=html.indexOf("async function hangupFirstPartyDirectCall(",endStart);
assert.ok(endStart>=0&&endEnd>endStart);
const endLogic=html.slice(endStart,endEnd);
assert.match(endLogic,/const cleanup=leave\(\{retireGrant:true\}\)/);
assert.match(endLogic,/const firstPartyMediaGrant=claims\?\.call_id\?\.startsWith\("fp-m-"\)===true;/);
assert.match(endLogic,/if\(firstPartyMediaGrant\)\{[\s\S]*?signedGrantRetired=true;\s*ucrShowFreshFirstPartyAdmission\(\);\s*return;/);
async function runEnd(firstParty){
 const ui={state:{textContent:""},status:{textContent:"",replaceChildren(...items){this.children=items;}},join:{disabled:false}};
 const c={ui,claims:{call_id:firstParty?"fp-m-call":"conf-call",expires:Date.now()+60000},
  sessionActive:true,sessionLifecycleGeneration:7,signedGrantRetired:false,Date,document:dom};
 c.leave=async({retireGrant})=>{c.sessionActive=false;c.sessionLifecycleGeneration++;if(retireGrant)c.signedGrantRetired=true;};
 vm.runInNewContext(action+endLogic+"\nthis.end=endUnverifiedMedia;",c);
 await c.end(7,"Network unavailable");
 return {ui,c};
}
const fpEnd=await runEnd(true);
assert.equal(fpEnd.ui.join.disabled,true);
assert.equal(fpEnd.c.signedGrantRetired,true);
assert.equal(fpEnd.ui.state.textContent,"Требуется новый допуск");
assert.equal(fpEnd.ui.status.children?.[1]?.href,"/start");
const confEnd=await runEnd(false);
assert.equal(confEnd.ui.state.textContent,"Access ended");
assert.equal(confEnd.ui.join.disabled,true);
for(const stage of ["PREFLIGHT","REALTIME_JOIN","MLS_RESTORE","WEBRTC_START","WEBRTC_OFFER","SDP_ICE_NEGOTIATION"]){
 assert.ok(html.includes('ucrMediaActivationStage="'+stage+'"'),"missing safe media stage "+stage);
}
console.log("PASS: accepted first-party Join failure retires only the old media grant, offers canonical /start recovery, and records precise safe stage");

// A rejected first-party /webrtc/start is not recoverable by endlessly
// reusing the same consumed signed grant. Stop physical capture, then route
// through /start for a fresh canonical Device-bound media admission.
const reconnectStart=html.indexOf("async function restartWebRtc(forceMedia){");
const reconnectEnd=html.indexOf("function scheduleWebRtcRetryAfterRestart(){",reconnectStart);
assert.ok(reconnectStart>=0&&reconnectEnd>reconnectStart);
const reconnect=html.slice(reconnectStart,reconnectEnd);
assert.match(reconnect,/claims\?\.call_id\?\.startsWith\("fp-m-"\)&&\[401,403\]\.includes\(e\?\.status\)/);
assert.match(reconnect,/await retireRejectedFirstPartyMedia\(generation\)/);
assert.match(reconnect,/return scheduleWebRtcRetryAfterRestart\(\)/,
  "retry must remain for transient non-authorization transport failures");
const activationStart=html.indexOf("async function activateAdmittedMedia(){");
const activationEnd=html.indexOf("async function applyAdmissionState(state){",activationStart);
assert.ok(activationStart>=0&&activationEnd>activationStart);
const activation=html.slice(activationStart,activationEnd);
assert.match(activation,/claims\?\.call_id\?\.startsWith\("fp-m-"\)&&\[401,403\]\.includes\(e\?\.status\)/);
assert.match(activation,/await retireRejectedFirstPartyMedia\(generation\)/);
assert.match(html,/localMediaPolicy:\{[\s\S]*?acceptedCallMedia:[\s\S]*?microphoneAllowed:policyAllows\("audio"\),[\s\S]*?cameraAllowed:policyAllows\("camera"\),/);
console.log("PASS: terminal first-party media 401/403 retires grant, while transient transport retry and canonical video consent stay guarded");

// Regression: a refused media grant must NOT terminate the live parent Call.
// Explicit user Hangup is the only path that can stop that Direct Call here.
const rejectedStart=html.indexOf("async function retireRejectedFirstPartyMedia(generation){");
const rejectedEnd=html.indexOf("async function hangupFirstPartyDirectCall(callId){",rejectedStart);
assert.ok(rejectedStart>=0&&rejectedEnd>rejectedStart);
const rejected=html.slice(rejectedStart,rejectedEnd);
assert.match(rejected,/await leave\(\{retireGrant:false\}\)/);
assert.doesNotMatch(rejected,/hangupFirstPartyDirectCall\(/);
let stopCount=0,hangupCount=0,recoveryCount=0;
const rejectedContext={
 sessionActive:true,sessionLifecycleGeneration:12,signedGrantRetired:false,
 leave:async({retireGrant})=>{
   assert.equal(retireGrant,false,"media rejection must preserve parent Call");
   rejectedContext.sessionActive=false;
   rejectedContext.sessionLifecycleGeneration++;
   stopCount++;
 },
 ucrShowFreshFirstPartyAdmission:()=>{recoveryCount++},
 hangupFirstPartyDirectCall:()=>{hangupCount++},
};
vm.runInNewContext(rejected+"\nthis.retire=retireRejectedFirstPartyMedia;",rejectedContext);
await rejectedContext.retire(12);
assert.equal(stopCount,1);
assert.equal(hangupCount,0);
assert.equal(recoveryCount,1);
assert.equal(rejectedContext.signedGrantRetired,true);
await rejectedContext.retire(12);
assert.equal(stopCount,1,"old generation cannot end a new Call");
console.log("PASS: rejected WebRTC media retires one-time grant without hanging up parent Call");

// Production latency diagnosis: the per-device export must expose timestamped
// MLS completion, ICE connection and E2EE activation. No key or SDP is logged.
assert.match(html,/ucrRecordDiagnostic\("MLS admission ready","lifecycle"\)/);
assert.match(html,/ucrRecordDiagnostic\("WebRTC ICE connected","webrtc"\)/);
assert.equal((html.match(/ucrRecordDiagnostic\("Endpoint E2EE transport active","lifecycle"\)/g)||[]).length,2,
  "initial E2EE activation and authorized reconnection both emit timing marks");
console.log("PASS: safe timestamped MLS/ICE/E2EE milestones support call-start latency diagnosis");

// Distinguish slow server offer/permission/candidate exchange from ICE itself.
// A server health 200 and "WebRTC ICE connected" alone cannot locate 10+ s.
for(const event of [
  "WebRTC server offer received",
  "Local capture ready for WebRTC",
  "WebRTC remote SDP accepted"
])assert.ok(html.includes('ucrRecordDiagnostic("'+event+'","webrtc")'),
  "missing per-stage WebRTC timing marker: "+event);
console.log("PASS: timestamped offer/capture/SDP milestones locate ICE startup delay");


// First-pixel latency: once permitted capture has returned, UI device
// enumeration must not block the server offer/SDP. After E2EE opens, a
// bounded first-frame recovery retries only canonical authorized subscription
// reads and stops as soon as a real authenticated frame was drawn.
const localCaptureStart=html.indexOf("async function captureLocalMedia(force){");
const localCaptureEnd=html.indexOf("async function ensureLocalTrack(kind){",localCaptureStart);
assert.ok(localCaptureStart>=0&&localCaptureEnd>localCaptureStart);
const localCapture=html.slice(localCaptureStart,localCaptureEnd);
assert.match(localCapture,/void refreshDevices\(\)\.catch\(\(\)=>\{\}\)/);
assert.doesNotMatch(localCapture,/await refreshDevices\(\)/,
  "enumerating device labels must not delay the first WebRTC SDP");
const firstFrameRecoveryStart=html.indexOf("function startInitialVideoRecovery(){");
const firstFrameRecoveryEnd=html.indexOf("async function syncReceiveSubscriptions(){",firstFrameRecoveryStart);
assert.ok(firstFrameRecoveryStart>=0&&firstFrameRecoveryEnd>firstFrameRecoveryStart);
const firstFrameRecovery=html.slice(firstFrameRecoveryStart,firstFrameRecoveryEnd);
assert.match(firstFrameRecovery,/deadline=Date\.now\(\)\+12000/);
assert.match(firstFrameRecovery,/window\.__ucrVideoCounters\?\.firstRenderedAt/);
assert.match(firstFrameRecovery,/syncReceiveSubscriptions\(\)/);
assert.doesNotMatch(firstFrameRecovery,/\/v1\/realtime\/media\/publish|\.seal_wire\(/);
assert.match(html,/window\.ucrFirstAuthenticatedVideoRendered=\(\)=>\{[\s\S]*?stopInitialVideoRecovery\(\)/);
const firstFrameActivations=(html.match(/startInitialVideoRecovery\(\);/g)||[]).length;
assert.equal(firstFrameActivations,2,
  "initial and reconnected E2EE must each recover first-video subscriptions");
console.log("PASS: capture does not wait for device enumeration; first-frame recovery is bounded, authenticated and stops on actual canvas rendering");


// Exercise the actual canonical receive-roster handler: one new admitted peer
// may ask the *local* encoder for a fresh reference frame; ordinary polling
// of an unchanged roster must not create a keyframe storm.
const rosterStart=html.indexOf("async function syncReceiveSubscriptions(){");
const rosterEnd=html.indexOf("function updateReceiveActiveSpeaker(",rosterStart);
assert.ok(rosterStart>=0&&rosterEnd>rosterStart,"canonical roster handler missing");
const rosterCode=html.slice(rosterStart,rosterEnd);
let refreshes=0,subscriptions=0;
const mediaSession={};
const channel={readyState:"open"};
const rosterCtx={
  sessionActive:true,mediaActive:true,e2eeAdapterReady:true,receiveRosterInFlight:false,
  receiveRosterGeneration:7,claims:mediaSession,e2eeChannel:channel,
  receiveRosterSources:[],receiveSpeakerId:null,
  body:()=>({}),api:async()=>({json:async()=>({ok:true,sources:[
    {source_id:"authenticated-peer",source_kind:1},
  ]})}),
  validReceiveRoster:result=>result.sources,
  applyReceiveSubscriptions:async()=>{subscriptions++},
  e2eeAdapter:()=>({requestPublishedVideoKeyframes:()=>{refreshes++}}),
};
vm.runInNewContext(rosterCode+"\nthis.sync=syncReceiveSubscriptions;",rosterCtx);
await rosterCtx.sync();
assert.equal(refreshes,1,"first admitted peer must request a local encoder keyframe");
assert.equal(subscriptions,1);
await rosterCtx.sync();
assert.equal(refreshes,1,"identical roster must not regenerate reference frames");
assert.equal(subscriptions,2);
rosterCtx.e2eeChannel={readyState:"closed"};
await rosterCtx.sync();
assert.equal(refreshes,1,"retired channel cannot request new frames");
console.log("PASS: only a newly admitted canonical peer requests one local encoder keyframe; stale channels and repeated polls do not");
