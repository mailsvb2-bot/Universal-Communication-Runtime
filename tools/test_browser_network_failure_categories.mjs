#!/usr/bin/env node
// Fail-closed diagnostic classification: specific stages need explicit evidence.
// Generic WebRTC connection failures must not be reported as TURN auth failures.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";
const html=readFileSync("crates/ucr-realtime-web/static/client.html","utf8");
const begin=html.indexOf("function ucrDiagnosticReason(value){");
const end=html.indexOf("// Receive failures from the actual codec/MLS media owner.",begin);
assert.ok(begin>=0&&end>begin);
const context={};
vm.createContext(context);
vm.runInContext(html.slice(begin,end),context);
const classify=context.ucrDiagnosticReason;
assert.equal(classify("TURN authentication failed: stale nonce 438"),"TURN_AUTHENTICATION_FAILURE");
assert.equal(classify("TURN TLS certificate verify failed"),"TURN_TLS_FAILURE");
assert.equal(classify("DTLS handshake failed"),"DTLS_HANDSHAKE_FAILURE");
assert.equal(classify("Invalid SDP answer"),"WEBRTC_SDP_NEGOTIATION_FAILURE");
assert.equal(classify("ICE gathering timeout"),"WEBRTC_ICE_FAILURE");
assert.equal(classify("WebRTC connection failure"),"WEBRTC_CONNECTION_FAILURE");
assert.notEqual(classify("WebRTC connection failure"),"TURN_AUTHENTICATION_FAILURE");
assert.equal(classify("MLS epoch mismatch"),"MLS_EPOCH_MISMATCH");
// A real failed call was incorrectly marked WEBRTC_CONNECTION_FAILURE
// because the substring "ice" appears in the word "device".
assert.equal(classify("device-bound MLS admission context rejected"),"MLS_ADMISSION_UNAVAILABLE");
assert.equal(classify("mls_context_rejected"),"MLS_ADMISSION_UNAVAILABLE");
assert.equal(classify("device authorization failed"),"MEDIA_ACTIVATION_FAILURE");
assert.equal(classify("peer waiting for MLS welcome"),"MLS_ADMISSION_UNAVAILABLE");
assert.equal(classify("ICE candidate connection failed"),"WEBRTC_ICE_FAILURE");
assert.equal(classify("Peer connection is closed"),"WEBRTC_CONNECTION_FAILURE");
assert.equal(classify("Failed to execute 'addTransceiver' on 'RTCPeerConnection': The RTCPeerConnection's signalingState is 'closed'."),"WEBRTC_CONNECTION_FAILURE");
assert.equal(classify("iceConnectionState failed"),"WEBRTC_ICE_FAILURE");
assert.equal(classify("iceGatheringState timeout"),"WEBRTC_ICE_FAILURE");
assert.equal(classify("Device signer is no longer trusted"),"DEVICE_TRUST_REJECTED");
assert.equal(classify("microphone notallowed"),"DEVICE_PERMISSION_DENIED");

assert.equal(classify("UCR_MEDIA_CODEC_PRODUCER_FAILURE"),"MEDIA_CODEC_PRODUCER_FAILURE");
assert.equal(classify("UCR_MEDIA_CODEC_CONSUMER_FAILURE"),"MEDIA_CODEC_CONSUMER_FAILURE");
assert.equal(classify("UCR_MEDIA_OUTBOUND_DATACHANNEL_SEND"),"MEDIA_OUTBOUND_DATACHANNEL_SEND",
  "sender failures must not collapse into ambiguous MEDIA_ACTIVATION_FAILURE");

console.log("PASS: protocol-stage failures distinguished without inferring relay path");

const server=readFileSync("crates/ucr-realtime-web/src/main.rs","utf8");
const routesStart=html.indexOf("const ucrDiagnosticAllowedPaths=new Set([");
const routesEnd=html.indexOf("]);",routesStart);
assert.ok(routesStart>=0&&routesEnd>routesStart,"diagnostic routes must be declared");
const routesText=html.slice(routesStart,routesEnd);
const paths=[...routesText.matchAll(/"(\/v1\/realtime\/[a-z/-]+)"/g)].map(match=>match[1]);
assert.equal(new Set(paths).size,paths.length,"diagnostic route list must not duplicate endpoints");
for(const path of paths){
 assert.ok(server.includes('"'+path+'"'),
   "HTTP diagnostic route is not implemented by the canonical Rust gateway: "+path);
}
for(const required of [
 "/v1/realtime/mls-context",
 "/v1/realtime/webrtc/start",
 "/v1/realtime/webrtc/remote-description",
 "/v1/realtime/webrtc/ice",
 "/v1/realtime/webrtc/restart",
]){
 assert.ok(paths.includes(required),"actual media setup failures must be observable: "+required);
}
for(const obsolete of ["/v1/realtime/webrtc/offer","/v1/realtime/webrtc/answer"]){
 assert.ok(!paths.includes(obsolete),"obsolete route must never displace canonical diagnostics");
}
console.log("PASS: browser diagnostics agree with implemented canonical Rust realtime HTTP routes");
