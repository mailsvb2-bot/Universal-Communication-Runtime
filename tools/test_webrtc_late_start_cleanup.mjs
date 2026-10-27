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
  section("async function startWebRtcOnce(","async function restartIce("),
  section("async function restartIce(","async function recoverWebRtc(")
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

// The same real browser function must clean up a server offer if any later
// SDP/ICE step fails. A new grant must never inherit the retired offer's
// remote-description or ICE messages, even when token rotation races setup.
async function exerciseNegotiation({failAt=null,replace=false,rotateToken=false}={}){
  const oldOffer="c".repeat(43),newOffer="d".repeat(43);
  const oldClaims={tenant_id:"t",namespace_id:null,call_id:"call-a",session_id:"session-a"};
  const newClaims={tenant_id:"t",namespace_id:null,call_id:"call-b",session_id:"session-b"};
  const calls=[];
  let createdPeer=null,closed=0,teardowns=0;
  const context={
    sessionActive:true,mediaActive:true,mediaCaptureGeneration:7,
    navigator:{onLine:true},claims:{expires:Date.now()+60000},
    ui:{privacyMode:{value:"secure"},remoteVideo:{srcObject:null},
      webrtcState:{textContent:""},state:{textContent:""},status:{textContent:""}},
    token:"original-grant",startWebRtc:{offerId:null},peer:null,
    ucrDiagnosticAllowedPaths:new Set(),ucrRecordDiagnostic:()=>{},
    body:()=>context.token==="original-grant"?oldClaims:newClaims,
    requireCanonicalMediaHostReady:()=>{},
    rtcNetworkConfiguration:()=>({}),
    ensureLocalMedia:async()=>{},
    MediaStream:class {},
    ucrDiagnosticReason:message=>message,
    teardownPeer:()=>{
      teardowns++;
      context.peer.close();
      context.peer=null;
      context.mediaCaptureGeneration++;
    },
    RTCPeerConnection:class {
      constructor(){this.connectionState="connecting";createdPeer=this;}
      async setRemoteDescription(){
        if(replace){
          context.token="replacement-grant";
          context.mediaCaptureGeneration++;
          context.peer={connectionState:"connected"};
          context.startWebRtc.offerId=newOffer;
        }
        if(failAt==="remote")throw Error("remote SDP failed");
      }
      async createAnswer(){
        if(failAt==="answer")throw Error("answer failed");
        return {type:"answer",sdp:"answer"};
      }
      async setLocalDescription(answer){
        if(failAt==="local")throw Error("local SDP failed");
        this.localDescription=answer;
        if(rotateToken)context.token="replacement-grant";
        this.onicecandidate({candidate:{
          candidate:"candidate:1",sdpMid:"0",sdpMLineIndex:0
        }});
      }
      close(){this.connectionState="closed";closed++;}
    },
    fetch:async(path,options)=>{
      calls.push({path,auth:options.headers.Authorization,
        payload:JSON.parse(options.body)});
      if(path==="/v1/realtime/webrtc/start")
        return {ok:true,json:async()=>({
          offer_id:oldOffer,ice_servers:[],sdp_type:"offer",sdp:"offer"
        })};
      if(path==="/v1/realtime/webrtc/close")return {ok:true};
      if(path==="/v1/realtime/webrtc/remote-description"){
        if(failAt==="submit")throw Error("remote description HTTP failed");
        return {ok:true};
      }
      if(path==="/v1/realtime/webrtc/ice"){
        if(failAt==="ice")throw Error("ICE HTTP failed");
        return {ok:true};
      }
      throw Error("Unexpected HTTP route: "+path);
    }
  };
  runInNewContext(functions+"\nglobalThis.runNegotiation=startWebRtcOnce;",context);
  if(failAt||replace){
    await assert.rejects(context.runNegotiation(),
      replace?/WebRTC start cancelled/:new RegExp(
        failAt==="remote"?"remote SDP failed":
        failAt==="answer"?"answer failed":
        failAt==="local"?"local SDP failed":
        failAt==="submit"?"remote description HTTP failed":"ICE HTTP failed"));
  }else{
    await context.runNegotiation();
  }
  const closes=calls.filter(x=>x.path==="/v1/realtime/webrtc/close");
  const signals=calls.filter(x=>x.path==="/v1/realtime/webrtc/remote-description"||
    x.path==="/v1/realtime/webrtc/ice");
  for(const item of signals){
    assert.equal(item.auth,"Bearer original-grant",
      "SDP and ICE must use the grant that allocated this exact offer");
    assert.equal(item.payload.call_id,oldClaims.call_id);
    assert.equal(item.payload.session_id,oldClaims.session_id);
    assert.equal(item.payload.offer_id,oldOffer);
  }
  if(failAt||replace){
    assert.equal(closes.length,1,"Failed SDP/ICE must retire its exact server offer");
    assert.equal(closes[0].auth,"Bearer original-grant");
    assert.equal(closes[0].payload.call_id,oldClaims.call_id);
    assert.equal(closes[0].payload.session_id,oldClaims.session_id);
    assert.equal(closes[0].payload.offer_id,oldOffer);
    assert.equal(closed,1,"Failed negotiation must close its local RTCPeerConnection");
    assert.equal(teardowns,replace?0:1,
      "Stale negotiation must not tear down a replacement peer");
    assert.equal(context.startWebRtc.offerId,replace?newOffer:null,
      "Failed old offer cannot clear a replacement offer");
  }else{
    assert.equal(closes.length,0);
    assert.equal(closed,0);
    assert.equal(signals.length,2,"Successful SDP must submit one answer and ICE candidate");
    assert.equal(context.startWebRtc.offerId,oldOffer);
  }
}
for(const failAt of ["remote","answer","local","submit","ice"]){
  await exerciseNegotiation({failAt});
}
await exerciseNegotiation({replace:true});
await exerciseNegotiation({rotateToken:true});
console.log("PASS: SDP/ICE failure retires exact original offer, closes old peer, preserves replacement, and never borrows renewed grant (MOCK HTTP, NOT live media)");


// ICE restart and ordinary Leave cleanup must never borrow a newer bearer
// grant for the old offer. This executes the actual browser functions with
// delayed restart responses and independently mutable Call/Join state.
async function exerciseIceOwnership({replace=false,mismatchedOffer=false}={}){
  const oldOffer="e".repeat(43),newOffer="f".repeat(43);
  const oldClaims={tenant_id:"t",namespace_id:null,call_id:"call-old",session_id:"session-old"};
  const newClaims={tenant_id:"t",namespace_id:null,call_id:"call-new",session_id:"session-new"};
  const oldOwner=Object.freeze({offerId:oldOffer,claims:oldClaims,token:"old-grant"});
  const newOwner=Object.freeze({offerId:newOffer,claims:newClaims,token:"new-grant"});
  let resolveRestart,configured=0,remoteDescriptions=0;
  const pendingRestart=new Promise(resolve=>{resolveRestart=resolve;});
  const calls=[];
  const pc={
    connectionState:"connected",localDescription:null,
    setConfiguration(){configured++;},
    async setRemoteDescription(){remoteDescriptions++;},
    async createAnswer(){return {type:"answer",sdp:"answer"};},
    async setLocalDescription(value){this.localDescription=value;}
  };
  const context={
    sessionActive:true,mediaActive:true,restarting:false,
    navigator:{onLine:true},mediaCaptureGeneration:7,peer:pc,
    startWebRtc:{offerId:oldOffer,offerOwner:oldOwner},
    token:"old-grant",webrtcRetryTimer:null,
    ui:{webrtcState:{textContent:""},status:{textContent:""},privacyMode:{value:"secure"}},
    body:()=>context.token==="old-grant"?oldClaims:newClaims,
    rtcNetworkConfiguration:()=>({}),
    ucrDiagnosticAllowedPaths:new Set(),ucrRecordDiagnostic:()=>{},
    fetch:async(path,options)=>{
      calls.push({path,auth:options.headers.Authorization,payload:JSON.parse(options.body)});
      if(path==="/v1/realtime/webrtc/restart")return pendingRestart;
      if(path==="/v1/realtime/webrtc/remote-description"||
         path==="/v1/realtime/webrtc/close")return {ok:true};
      throw Error("Unexpected HTTP route: "+path);
    }
  };
  runInNewContext(functions+
    "\nglobalThis.runIce=restartIce;globalThis.runClose=closeServerPeer;",context);
  const restarted=context.runIce();
  await Promise.resolve();
  assert.equal(calls.length,1);
  // Change the mutable global grant while the network response is delayed.
  context.token="new-grant";
  if(replace){
    context.startWebRtc.offerOwner=newOwner;
    context.startWebRtc.offerId=newOffer;
  }
  resolveRestart({ok:true,json:async()=>({
    offer_id:mismatchedOffer?newOffer:oldOffer,
    ice_servers:[],sdp_type:"offer",sdp:"offer"
  })});
  if(replace||mismatchedOffer){
    await assert.rejects(restarted,
      replace?/ICE restart cancelled/:/immutable WebRTC transport offer identity/);
    assert.equal(configured,0,"Stale or substituted ICE offer must not reconfigure the peer");
    assert.equal(remoteDescriptions,0,"Stale ICE response must not reach SDP");
  }else{
    assert.equal(await restarted,true);
    assert.equal(configured,1);
    assert.equal(remoteDescriptions,1);
  }
  const signals=calls.filter(item=>item.path.endsWith("/restart")||
    item.path.endsWith("/remote-description"));
  for(const item of signals){
    assert.equal(item.auth,"Bearer old-grant",
      "ICE restart must use the original offer's grant after global token renewal");
    assert.equal(item.payload.call_id,oldClaims.call_id);
    assert.equal(item.payload.session_id,oldClaims.session_id);
    if(item.path.endsWith("/remote-description"))
      assert.equal(item.payload.offer_id,oldOffer);
  }
  if(!replace){
    // The same original authority is required when Leave closes this offer.
    await context.runClose();
    const close=calls.find(item=>item.path.endsWith("/close"));
    assert.ok(close,"Server-side WebRTC close must be attempted");
    assert.equal(close.auth,"Bearer old-grant");
    assert.equal(close.payload.call_id,oldClaims.call_id);
    assert.equal(close.payload.offer_id,oldOffer);
    assert.equal(context.startWebRtc.offerId,null);
    assert.equal(context.startWebRtc.offerOwner,null);
  }else{
    // Explicit stale-offer cleanup cannot clear a replacement's authority.
    await context.runClose(false,oldOffer,oldClaims,"old-grant");
    assert.equal(context.startWebRtc.offerId,newOffer);
    assert.equal(context.startWebRtc.offerOwner,newOwner);
  }
}
await exerciseIceOwnership();
await exerciseIceOwnership({replace:true});
await exerciseIceOwnership({mismatchedOffer:true});
console.log("PASS: ICE restart and Leave close bind to original offer owner despite token rotation, replacement and substituted SDP (MOCK HTTP, NOT live media)");
