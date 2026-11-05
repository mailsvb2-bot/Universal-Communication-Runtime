#!/usr/bin/env node
// Behavioral contract for phone↔PC media survival without weakening E2EE.
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {runInNewContext} from "node:vm";
const browser=readFileSync("crates/ucr-realtime-web/static/client.html","utf8");
const start=readFileSync("crates/ucr-realtime-web/static/start.js","utf8");
assert.match(browser,/function detachE2eeChannel\(\)\{/);
assert.match(browser,/teardownPeer\(\{keepAdapter:true\}\)/);
assert.match(browser,/e2eeAdapterStarted&&e2eeAdapter\(\)/);
assert.match(browser,/MEDIA_REPLAY_REJECTED/);
assert.match(browser,/lastRxAudio:window\.__ucrMediaStageMetrics\.lastRxAudio/);
assert.match(browser,/ucrConferenceMediaActive/);
assert.match(start,/Защищённый звонок уже открыт на экране конференции/);
assert.doesNotMatch(browser,/if\(event\.startsWith\("event: media"\)\)\{packetCount\+\+/);
const attachSnippet=browser.slice(browser.indexOf("function attachE2eeDataChannel(channel){"),browser.indexOf("function scheduleStreamRetry(){"));
assert.ok(attachSnippet.includes("detachE2eeChannel();e2eeChannel=channel"));
assert.ok(attachSnippet.includes("if(e2eeChannel!==channel)return;"));
assert.ok(!/recoverTerminalEncryptedChannel[\s\S]*closeE2eeTransport\(\);/.test(attachSnippet),
  "terminal DataChannel recovery must not revoke live epoch signer");
let detached=0,opened=0;
const channel={label:"ucr.e2ee.media.v1",readyState:"open",binaryType:"",close(){},onopen:null,onmessage:null,onclose:null,onerror:null};
const ctx={
 E2EE_CHANNEL_LABEL:"ucr.e2ee.media.v1",e2eeChannel:null,e2eePending:null,
 e2eeAdapterReady:false,e2eeAdapterStarted:true,packetCount:0,sessionActive:true,mediaActive:true,
 webrtcNeedsPeerRebuild:false,
 ui:{packets:{textContent:""},status:{textContent:""},webrtcState:{textContent:""},state:{textContent:""}},
 detachE2eeChannel(){detached++;ctx.e2eeChannel=null;},
 closeE2eeTransport(){throw new Error("reconnect must not revoke signer");},
 receiveE2eeChunk:wire=>wire,
 e2eeAdapter(){return {onEnvelope:async wire=>{opened++;if(wire[0]===9)throw new Error("replayed endpoint media frame");}};},
 requireCompatibleE2eeAdapter:value=>value,
 activateE2eeAdapter:async()=>{ctx.e2eeAdapterReady=true;},
 ucrDiagnosticReason:message=>/replayed/.test(String(message||""))?"MEDIA_REPLAY_REJECTED":"OTHER",
 ucrRecordDiagnostic(){},scheduleWebRtcRetry(){},endUnverifiedMedia(){throw new Error("replay must not end call");}
};
runInNewContext(attachSnippet+"\nthis.attach = attachE2eeDataChannel;",ctx);
ctx.attach(channel);
assert.equal(detached,1);
channel.onmessage({data:new Uint8Array([1])});
channel.onmessage({data:new Uint8Array([9])});
await Promise.resolve();await Promise.resolve();
assert.equal(opened,2);
assert.equal(ctx.ui.status.textContent,"","replay must not overwrite status");
assert.equal(ctx.packetCount,2);
const begin=start.slice(start.indexOf("async function beginMedia(callId) {"),start.indexOf("async function dial("));
const messages=[];
const beginCtx={
 navigating:false,active:{terminating:false,call:{callId:"fp-v-1",state:"active"}},
 accountScope:"scope",uiAuthGeneration:1,mlsPreparation:null,sessionCallInfo:{mlsPhase:"wait_welcome"},
 sessionStorage:{getItem:key=>key==="ucrConferenceMediaActive"?"1":null},
 authDiagnostic(){},callRoleOf:()=>"callee",activeCallLocator:()=>"loc",
 prepareFirstPartyEndpointMls:async()=>false,message:text=>messages.push(text),
 MLS_PHASES:new Set(["wait_welcome","ready"])
};
runInNewContext(begin+"\nthis.beginMedia = beginMedia;",beginCtx);
await beginCtx.beginMedia("fp-v-1");
assert.equal(messages[0],"Защищённый звонок уже открыт на экране конференции.");
console.log("PASS: encrypted media survival keeps signer, anti-replay, and /start conference flag");
