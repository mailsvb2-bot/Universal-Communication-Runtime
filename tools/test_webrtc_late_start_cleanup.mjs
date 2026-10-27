#!/usr/bin/env node
// Execute the actual browser functions with deferred HTTP responses. A model
// server is used only for transport timing: this is NOT a live E2EE A/B call.
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {runInNewContext} from "node:vm";

const source=readFileSync("crates/ucr-realtime-web/static/client.html","utf8");
function section(begin,end){
  const from=source.indexOf(begin),to=source.indexOf(end,from+begin.length);
  assert.ok(from>=0&&to>from,`Missing actual browser function: ${begin}`);
  return source.slice(from,to);
}
const functions=[
  section("async function api(","function endpointStateKey("),
  section("async function closeServerPeer(","function scheduleWebRtcRetry("),
  section("async function startWebRtcOnce(","async function restartIce(")
].join("\n");

async function exercise({withdraw=false,replace=false,permissionDenied=false,peerConstructorDenied=false}={}){
  const oldOffer="a".repeat(43),newOffer="b".repeat(43);
  const calls=[];
  let resolveStart,localMediaRequests=0,peerConstructors=0;
  const pendingStart=new Promise(resolve=>{resolveStart=resolve;});
  const oldClaims={tenant_id:"t",namespace_id:null,call_id:"old-call",session_id:"old-session"};
  const newClaims={tenant_id:"t",namespace_id:null,call_id:"new-call",session_id:"new-session"};
  const context={
    sessionActive:true,mediaActive:true,mediaCaptureGeneration:7,
    navigator:{onLine:true},claims:{expires:Date.now()+60000},
    ui:{privacyMode:{value:"secure"}},
    token:"old-grant",startWebRtc:{offerId:replace?newOffer:null},peer:null,
    ucrDiagnosticAllowedPaths:new Set(),ucrRecordDiagnostic:()=>{},
    body:()=>context.token==="old-grant"?oldClaims:newClaims,
    requireCanonicalMediaHostReady:()=>{},
    rtcNetworkConfiguration:()=>({}),
    ensureLocalMedia:async()=>{
      localMediaRequests++;
      if(permissionDenied)throw Error("media permission denied");
    },
    RTCPeerConnection:class {
      constructor(){
        peerConstructors++;
        if(peerConstructorDenied)throw Error("peer creation denied");
      }
    },
    fetch:async(path,options)=>{
      calls.push({path,auth:options.headers.Authorization,payload:JSON.parse(options.body)});
      if(path==="/v1/realtime/webrtc/start")return pendingStart;
      if(path==="/v1/realtime/webrtc/close")return {ok:true};
      throw Error("Unexpected HTTP route: "+path);
    }
  };
  runInNewContext(functions+"\nglobalThis.runLateStart=startWebRtcOnce;",context);
  const started=context.runLateStart();
  await Promise.resolve();
  assert.equal(calls.length,1);
  assert.equal(calls[0].auth,"Bearer old-grant");
  if(withdraw){context.sessionActive=false;context.mediaActive=false;}
  if(replace){
    context.token="replacement-grant";
    context.mediaCaptureGeneration=8;
  }
  resolveStart({ok:true,json:async()=>({offer_id:oldOffer,ice_servers:[]})});
  await assert.rejects(started,withdraw||replace
    ?/WebRTC start cancelled/
    :permissionDenied?/media permission denied/:/peer creation denied/);
  const closes=calls.filter(x=>x.path==="/v1/realtime/webrtc/close");
  assert.equal(closes.length,1,"Every allocated offer must receive an offer-scoped close");
  assert.equal(closes[0].payload.offer_id,oldOffer);
  assert.equal(closes[0].payload.call_id,oldClaims.call_id);
  assert.equal(closes[0].payload.session_id,oldClaims.session_id);
  assert.equal(closes[0].auth,"Bearer old-grant","Cleanup must not borrow a replacement grant");
  assert.equal(context.startWebRtc.offerId,replace?newOffer:null,
    "Late start must not install its stale offer over a replacement");
  if(withdraw||replace){
    assert.equal(localMediaRequests,0,"Revoked start must not request media");
    assert.equal(peerConstructors,0,"Revoked start must not allocate a peer");
  }
}

await exercise({withdraw:true});
await exercise({replace:true});
await exercise({permissionDenied:true});
await exercise({peerConstructorDenied:true});
console.log("PASS: late WebRTC start response after Leave/replace and failed media/peer setup closes exact retired offer with original grant (MOCK HTTP, NOT live media)");
