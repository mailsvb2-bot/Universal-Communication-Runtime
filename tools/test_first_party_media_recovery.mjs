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
assert.match(reconnect,/await endUnverifiedMedia\(generation,"Protected Call media authorization rejected\."\)/);
assert.match(reconnect,/return scheduleWebRtcRetryAfterRestart\(\)/,
  "retry must remain for transient non-authorization transport failures");
const activationStart=html.indexOf("async function activateAdmittedMedia(){");
const activationEnd=html.indexOf("async function applyAdmissionState(state){",activationStart);
assert.ok(activationStart>=0&&activationEnd>activationStart);
const activation=html.slice(activationStart,activationEnd);
assert.match(activation,/claims\?\.call_id\?\.startsWith\("fp-m-"\)&&\[401,403\]\.includes\(e\?\.status\)/);
assert.match(activation,/await endUnverifiedMedia\(generation,"Protected Call media authorization rejected\."\)/);
assert.match(html,/localMediaPolicy:\{[\s\S]*?acceptedCallMedia:[\s\S]*?microphoneAllowed:policyAllows\("audio"\),[\s\S]*?cameraAllowed:policyAllows\("camera"\),/);
console.log("PASS: terminal first-party media 401/403 retires grant, while transient transport retry and canonical video consent stay guarded");
