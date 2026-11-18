#!/usr/bin/env node
// Execute the real canonical browser prefetch & activation owners: early ICE
// offer allocation is allowed after signed Join, but E2EE media never starts
// without finished MLS, and cancelled/stale offers must close by their own ID.
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {runInNewContext} from "node:vm";

const html=readFileSync(new URL("../crates/ucr-realtime-web/static/client.html",import.meta.url),"utf8");
const extract=(start,end)=>{
  const from=html.indexOf(start),to=html.indexOf(end,from);
  assert.ok(from>=0&&to>from,`missing browser owner: ${start}`);
  return html.slice(from,to);
};
const prefetchCode=extract("function prefetchFirstPartyWebRtcOffer()","// Serialize complete offer ownership");
const activateCode=extract("async function activateAdmittedMedia()","async function applyAdmissionState(");
const offerId="a".repeat(43);
const controls={disabled:true,textContent:""};
let apiCalls=[],closed=[],events=[];
let offerResolve;
const offerGate=new Promise(resolve=>{offerResolve=resolve;});
const ctx={
  sessionActive:true,mediaActive:false,sessionLifecycleGeneration:7,mediaCaptureGeneration:4,
  claims:{call_id:"fp-m-call-7",expires:Date.now()+60_000},
  token:"signed-original",body:()=>({session:"one",call:"call-7"}),
  requireCanonicalMediaHostReady(){},
  api:async (path,body,_signal,_unused,token)=>{
    apiCalls.push({path,body,token});
    await offerGate;
    return {json:async()=>({offer_id:offerId,sdp_type:"offer",sdp:"test"})};
  },
  closeServerPeer:async (_skip,id,owner,token)=>{closed.push({id,owner,token});},
  ucrRecordDiagnostic:(safe)=>events.push(safe),
  ui:{
    privacyMode:{value:"secure"},status:controls,state:controls,handToggle:{disabled:true},
    reactionSend:{disabled:true},chatInput:{disabled:true},chatSend:{disabled:true}
  },
  earlyLocalCapture:false,ensureLocalMedia:async()=>{},
  ensureEndpointMlsReady:async()=>{},
  startRoomViewingCopy(){},startRoomRoster(){},refreshLocalMediaControls(){},
  reactionTimer:null,chatTimer:null,setInterval:()=>1,pollReactions:async()=>{},
  pollChat:async()=>{},policyAllows:()=>false,openStream:Object.assign(async()=>{}, {missing:false}),
  startWebRtc:async()=>{},startActiveSpeakerMonitoring:async()=>{},
  signedGrantRetired:false,appliedAdaptiveQuality:null,
  Date,Promise,
};
runInNewContext(prefetchCode+"\nthis.prefetch=prefetchFirstPartyWebRtcOffer;this.retire=retirePrefetchedWebRtcOffer;",ctx);
const prefetch=ctx.prefetch();
assert.ok(prefetch,"accepted first-party Join begins early server ICE offer");
assert.equal(apiCalls.length,1);
assert.equal(apiCalls[0].path,"/v1/realtime/webrtc/start");
assert.equal(apiCalls[0].token,"signed-original");
assert.equal(apiCalls[0].body.session,"one");
ctx.token="signed-replacement";
ctx.body=()=>({session:"replacement",call:"call-8"});
offerResolve();
const offer=await prefetch.promise;
assert.equal(offer.ok,true);
await ctx.retire(prefetch);
assert.equal(closed.length,1);
assert.deepEqual(closed[0],{id:offerId,owner:prefetch.owner.claims,token:"signed-original"},
  "never retire an old server peer using the replacement Device grant");
ctx.claims={call_id:"general-room",expires:Date.now()+60_000};
assert.equal(ctx.prefetch(),null,"never prefetch for a non-first-party call");
assert.equal(apiCalls.length,1);

const activationEvents=[];
let releaseMls;const mlsGate=new Promise(resolve=>{releaseMls=resolve;});
const accepted={...ctx,claims:{call_id:"fp-m-call-7",expires:Date.now()+60_000},
  token:"signed-original",body:()=>({session:"one",call:"call-7"}),
  sessionLifecycleGeneration:8,mediaActive:false,ensureEndpointMlsReady:async()=>{
    activationEvents.push("mls-start");await mlsGate;activationEvents.push("mls-ready");
  },
  prefetchFirstPartyWebRtcOffer:()=>{activationEvents.push("offer-prefetch");return {tag:"offer"};},
  startWebRtc:async (_force,prefetched)=>{activationEvents.push("webrtc-start");assert.equal(prefetched.tag,"offer");},
  ucrRecordDiagnostic:safe=>activationEvents.push(safe),
  openStream:Object.assign(async()=>{}, {missing:false}),
  ui:{...ctx.ui,privacyMode:{value:"secure"},status:{textContent:""},state:{textContent:""},
      handToggle:{disabled:true},reactionSend:{disabled:true},chatInput:{disabled:true},chatSend:{disabled:true}},
};
runInNewContext(activateCode+"\nthis.activate=activateAdmittedMedia;",accepted);
const activation=accepted.activate();
await Promise.resolve();
assert.deepEqual(activationEvents.slice(0,2),["offer-prefetch","mls-start"],
  "ICE offer must start concurrently with MLS without starting WebRTC media");
assert.equal(accepted.mediaActive,false,"MLS is still the media authorization barrier");
releaseMls();
await activation;
assert.ok(activationEvents.indexOf("webrtc-start")>activationEvents.indexOf("mls-ready"),
  "WebRTC media must not start before MLS admission is ready");
assert.equal(accepted.mediaActive,true);
console.log("PASS first-party ICE offer prefetch overlaps MLS, fences ownership and preserves E2EE activation");
