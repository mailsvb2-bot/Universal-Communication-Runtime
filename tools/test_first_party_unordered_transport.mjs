#!/usr/bin/env node
// Source-executable contracts for Rust-offered optional unordered v2 ciphertext.
// No second crypto owner: both v1 and v2 go through the SAME adapter.onEnvelope.
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import vm from "node:vm";

const html=readFileSync("crates/ucr-realtime-web/static/client.html","utf8");
const start=html.indexOf("function readAscii(bytes,start,length){");
const end=html.indexOf("// Aggregate encrypted transport pressure only:",start);
assert.ok(start>=0&&end>start,"v2 must be in canonical browser transport owner");
const receiver=html.slice(start,end);
const constants={
  E2EE_CHUNK_MAGIC:"UCRCHK01",E2EE_CHUNK_HEADER_BYTES:24,
  E2EE_DATA_MESSAGE_BYTES:16000,E2EE_CHUNK_PAYLOAD_BYTES:15976,
  E2EE_MAX_WIRE_BYTES:2*1024*1024+8192,
  E2EE_V2_CHUNK_MAGIC:"UCRCHK02",E2EE_V2_HEADER_BYTES:25,
  E2EE_V2_PAYLOAD_BYTES:15975,E2EE_V2_PENDING_LIMIT:4,
  e2eeV2Pending:new Map(),e2eeV2Delivered:null,e2eePending:null,
  e2eeChannelV2:null,e2eeChannel:null,
  Uint8Array,TextEncoder,DataView,BigInt,Map,Set,Math,Number,
};
const receiveCtx={...constants};
vm.runInNewContext(receiver+"\nthis.receiveV2=receiveE2eeChunkV2;this.receiveV1=receiveE2eeChunk;",receiveCtx);
const v2Chunk=(seq,part,index,count,total,keyframe=true)=>{
  const bytes=new Uint8Array(25+part.length);bytes.set(new TextEncoder().encode("UCRCHK02"));
  const view=new DataView(bytes.buffer);
  view.setBigUint64(8,BigInt(seq),false);view.setUint16(16,index,false);
  view.setUint16(18,count,false);view.setUint32(20,total,false);
  view.setUint8(24,keyframe?1:0);bytes.set(part,25);
  return bytes;
};
const payload=Uint8Array.from({length:17000},(_,i)=>i%251);
const chunks=[
  v2Chunk(1,payload.subarray(0,15975),0,2,payload.length),
  v2Chunk(1,payload.subarray(15975),1,2,payload.length),
];
assert.equal(receiveCtx.receiveV2(chunks[1]),null,"last fragment can arrive first");
const out=receiveCtx.receiveV2(chunks[0]);
assert.deepEqual([...out],[...payload],"unordered chunks reconstruct EXACT encrypted envelope");
assert.equal(receiveCtx.receiveV2(chunks[1]),null,"late duplicate cannot replay ciphertext");
// Bad version/size cannot be reinterpreted as the older ordered wire protocol.
assert.throws(()=>receiveCtx.receiveV2(Uint8Array.of(1,2,3)),/Invalid/);
assert.throws(()=>receiveCtx.receiveV2(
  Uint8Array.from([85,67,82,67,72,75,48,49,...new Array(30).fill(0)])),/protocol/);
// Lost intermediate envelope must NOT create a forever growing reassembly queue.
const partial=v2Chunk(2,Uint8Array.from({length:15975},()=>8),0,2,17000);
assert.equal(receiveCtx.receiveV2(partial),null);
for(let id=3;id<=8;id++) {
  const b=v2Chunk(id,Uint8Array.of(id),0,1,1,false);
  assert.deepEqual([...receiveCtx.receiveV2(b)],[id]);
}
assert.equal(receiveCtx.receiveV2(v2Chunk(2,Uint8Array.of(1),0,1,1)),null);
assert.ok(receiveCtx.e2eeV2Pending.size<=4);

const sendStart=html.indexOf("function ucrTransportError(code,message){");
const sendEnd=html.indexOf("function endpointMediaSources(){",sendStart);
assert.ok(sendStart>=0&&sendEnd>sendStart);
const sentV1=[],sentV2=[];
const sendCtx={
  ...constants,
  e2eeChannel:{readyState:"open",bufferedAmount:0,send:bytes=>sentV1.push(bytes)},
  e2eeChannelV2:{readyState:"open",bufferedAmount:0,send:bytes=>sentV2.push(bytes)},
  e2eeMessageId:1,e2eeV2Selected:false,packetCount:0,
  window:{__ucrAudioCounters:{transportQueued:0}},
  ui:{packets:{textContent:""}},
};
vm.runInNewContext(html.slice(sendStart,sendEnd)+
  "\nthis.publish=sendE2eeEnvelope;",sendCtx);
sendCtx.publish(Uint8Array.of(10,20,30),"video",true);
assert.equal(sentV1.length,0,"v2 transport must not duplicate encrypted frame on v1");
assert.equal(sentV2.length,1);
assert.equal(new DataView(sentV2[0].buffer).getUint8(24),1,
  "verified video keyframe metadata must survive as v2 recovery flag");
assert.equal(sendCtx.e2eeV2Selected,true);
// Plain browser with no Rust v2 offer stays on exact v1 envelope contract.
sendCtx.e2eeChannelV2=null;
sendCtx.publish(Uint8Array.of(1,2),"audio",false);
assert.equal(sentV1.length,1);
assert.equal(String.fromCharCode(...sentV1[0].slice(0,8)),"UCRCHK01");
assert.equal(sendCtx.window.__ucrAudioCounters.transportQueued,1);
// The v2 receiver routes only complete ciphertext to the existing adapter,
// never creates a second key bridge.
assert.match(receiver,/adapter\.onEnvelope\(wire\)/);
assert.doesNotMatch(receiver,/seal_wire|open_wire|derive_secret|new .*CryptoBridge/);
assert.ok(html.includes("channel.label===E2EE_UNORDERED_CHANNEL_LABEL"),
  "v2 offered channel must reach the same authenticated media owner");

const bindStart=html.indexOf("function attachE2eeDataChannel(channel){");
const bindEnd=html.indexOf("function scheduleStreamRetry(){",bindStart);
assert.ok(bindStart>=0&&bindEnd>bindStart);
const earlyV2={label:"ucr.e2ee.media.v2",readyState:"open"};
const bindCtx={
  E2EE_CHANNEL_LABEL:"ucr.e2ee.media.v1",
  E2EE_UNORDERED_CHANNEL_LABEL:"ucr.e2ee.media.v2",
  e2eeChannel:null,e2eeChannelV2:earlyV2,
  detachE2eeChannel(){throw new Error("initial v1 must not erase early v2 offer");},
  attachUnorderedE2eeDataChannel(){throw new Error("not a v2 event");},
  ui:{},console,
};
vm.runInNewContext(html.slice(bindStart,bindEnd)+"\nthis.bind=attachE2eeDataChannel;",bindCtx);
const reliable={label:"ucr.e2ee.media.v1",readyState:"connecting"};
bindCtx.bind(reliable);
assert.equal(bindCtx.e2eeChannel,reliable);
assert.equal(bindCtx.e2eeChannelV2,earlyV2,
  "server may announce v2 before v1; order must not discard optional channel");
console.log("PASS: v2 loss/reorder/replay bounds, keyframe metadata, v1 fallback and one E2EE owner");
