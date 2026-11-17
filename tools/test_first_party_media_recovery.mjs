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
assert.match(joinLogic,/const needsFreshFirstPartyGrant=firstPartyMediaGrant&&\s*\(sessionActive\|\|\(ucrMediaActivationStage==="REALTIME_JOIN"&&e\?\.status===401\)\)/);
assert.match(joinLogic,/if\(sessionActive\)\{\s*try\{await leave\(\{retireGrant:false\}\)/);
assert.match(joinLogic,/if\(needsFreshFirstPartyGrant\)\{\s*[\s\S]*?signedGrantRetired=true;\s*ucrShowFreshFirstPartyAdmission\(\);\s*return;/);
assert.match(joinLogic,/ui\.join\.disabled=signedGrantRetired\|\|grantExpired/);
assert.match(html,/mediaActivationStage:ucrMediaActivationStage/);
for(const stage of ["PREFLIGHT","REALTIME_JOIN","MLS_RESTORE","WEBRTC_START","WEBRTC_OFFER","SDP_ICE_NEGOTIATION"]){
 assert.ok(html.includes('ucrMediaActivationStage="'+stage+'"'),"missing safe media stage "+stage);
}
console.log("PASS: accepted first-party Join failure retires only the old media grant, offers canonical /start recovery, and records precise safe stage");
