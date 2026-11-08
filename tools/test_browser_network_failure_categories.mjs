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
assert.equal(classify("microphone notallowed"),"DEVICE_PERMISSION_DENIED");
console.log("PASS: protocol-stage failures distinguished without inferring relay path");
