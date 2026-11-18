#!/usr/bin/env node
// Executable regression of the real WebRTC offer-scoped pending ICE drain.
// Pending candidates must not be sent serially or outlive peer teardown.
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import vm from "node:vm";

const html=readFileSync("crates/ucr-realtime-web/static/client.html","utf8");
const begin=html.indexOf("    const initialCandidates=pendingCandidates.splice(0);");
const end=html.indexOf("    // SDP completion must not overwrite",begin);
assert.ok(begin>=0&&end>begin,"canonical WebRTC ICE drain unavailable");
const block=html.slice(begin,end);
assert.match(block,/Promise\.allSettled\(/);
assert.match(block,/initialCandidates\.slice\(offset,offset\+4\)/);
assert.match(block,/ensureOwnedPeer\(\)/);
assert.ok(block.indexOf("const settled=await Promise.allSettled")<
  block.indexOf("const rejected=settled.find"),
  "close/revocation must await all candidate writes before cleanup");
const load=(scope)=>{
  vm.runInNewContext("async function drain(){\n"+block+"\n}\nthis.drain=drain;",scope);
  return scope.drain();
};
let active=0,maximum=0,finished=[];
await load({
  pendingCandidates:[1,2,3,4,5,6,7],
  ensureOwnedPeer(){},
  async sendCandidate(candidate){
    active++;maximum=Math.max(maximum,active);
    await Promise.resolve();
    finished.push(candidate);
    active--;
  },
});
assert.equal(maximum,4,"ICE calls must be bounded by four concurrent requests");
assert.deepEqual(finished,[1,2,3,4,5,6,7]);
let finishedAfterFailure=[];
await assert.rejects(load({
  pendingCandidates:[1,2,3,4,5],
  ensureOwnedPeer(){},
  async sendCandidate(candidate){
    await Promise.resolve();
    finishedAfterFailure.push(candidate);
    if(candidate===2)throw Error("rejected ICE offer candidate");
  },
}),/rejected ICE offer candidate/);
assert.deepEqual(finishedAfterFailure,[1,2,3,4],
  "all first-batch requests settle before the offer can be retired");
console.log("PASS: offer-scoped ICE dispatch is bounded, concurrent, and settles before cleanup");
