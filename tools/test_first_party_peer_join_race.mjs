#!/usr/bin/env node
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {runInNewContext} from "node:vm";

const src=readFileSync("crates/ucr-realtime-web/static/client.html","utf8");
const first=src.indexOf("async function fetchEndpointMlsContext(signal){");
const last=src.indexOf("async function fetchEndpointMlsBootstrap(signal){",first);
assert.ok(first>=0 && last>first,"canonical MLS rendezvous retry is missing");
const implementation=src.slice(first,last);
assert.match(src,/acceptedFirstPartyHandoff/,"accepted Device-bound calls autojoin");
assert.match(src,/claims\.call_id\.startsWith\("fp-m-"\)/,"autojoin is scoped to signed first-party media Calls");
assert.match(src,/sessionStorage\.getItem\("ucrFirstPartyDirectCall"\)/,"autojoin requires handoff from authenticated /start");

async function runScenario({responses,firstParty=true,aborted=false,advanceMs=0,grantTtlMs=120000,advanceByDelay=false}) {
 let requests=0,virtualNow=Date.now();
 const startedAt=virtualNow;
 const context={
  claims:{call_id:firstParty?"fp-m-test-call":"conference-call",expires:virtualNow+grantTtlMs},
  sessionStorage:{getItem:()=>firstParty?"fp-v-test-call":null},
  ui:{status:{textContent:""}},
  Date:{now:()=>virtualNow},Math,DOMException,Error,
  setTimeout:(fn,ms)=>{virtualNow+=advanceByDelay?ms:advanceMs;return setTimeout(fn,0);},
  body:()=>({call_id:"test"}),
  async api(){
   const entry=responses[Math.min(requests,responses.length-1)];
   requests++;
   if(entry!==200)throw Object.assign(new Error("rejected"),{status:entry});
   return {json:async()=>({ok:true,group_id:"fp-mg-test",endpoint_state_mode:"restore"})};
  }
 };
 runInNewContext(implementation+"\nthis.fetchContext=fetchEndpointMlsContext;",context);
 let value=null,error=null;
 try{value=await context.fetchContext({aborted});}catch(e){error=e;}
 return {value,error,requests,elapsedMs:virtualNow-startedAt};
}
const pending=await runScenario({responses:[503,503,503,200]});
assert.equal(pending.requests,4);
assert.equal(pending.value?.endpoint_state_mode,"restore");
assert.equal(pending.error,null);
// The real 2026-11-17 call failed after ~8 seconds: the peer began joining
// only after the old 7-second deadline. Simulate 12 seconds of elapsed time,
// without sleeping in CI, and verify the first grant stays in its admitted
// canonical rendezvous instead of being needlessly retired.
const delayedPeer=await runScenario({
 responses:[503,503,503,503,503,503,503,503,503,503,503,503,200],
 advanceMs:1000,
});
assert.equal(delayedPeer.error,null,"recipient arrival after 7 seconds must succeed");
assert.equal(delayedPeer.requests,13);
assert.equal(delayedPeer.value?.endpoint_state_mode,"restore");
// Never turn the bounded wait into unbounded 503 polling, or extend an
// expired signed grant. Other HTTP errors still fail immediately.
const expiredWindow=await runScenario({
 responses:Array(80).fill(503),advanceMs:1000,grantTtlMs:30000,
});
assert.equal(expiredWindow.error?.status,503);
assert.ok(expiredWindow.requests<=31,"signed grant expiry must cap waiting");
const boundedWindow=await runScenario({
 responses:Array(80).fill(503),advanceMs:1000,grantTtlMs:120000,
});
assert.equal(boundedWindow.error?.status,503);
assert.ok(boundedWindow.requests<=61,"rendezvous must stop within 60 seconds");
// The 60-second rendezvous stays on a sub-second poll. A 2 s backoff hid a
// peer who had already joined (call 44 waited through 2.1 s gaps). The cap is
// the request count of a 450 ms poll across the same 60 s deadline.
const backoff=await runScenario({responses:Array(400).fill(503),advanceByDelay:true});
assert.equal(backoff.error?.status,503);
assert.ok(backoff.requests<=140,"sub-second MLS poll must still stop at 60s; requests="+backoff.requests);
assert.ok(backoff.elapsedMs<=60000&&backoff.elapsedMs>=59000,"keep 60s deadline");
const lateRecipient=await runScenario({responses:[...Array(30).fill(503),200],advanceByDelay:true});
assert.equal(lateRecipient.error,null,"late recipient must still join");
assert.ok(lateRecipient.elapsedMs<60000);
for(const code of [401,403,502]){
 const denied=await runScenario({responses:[code,200]});
 assert.equal(denied.requests,1,"must never retry terminal authorization or integrity denial");
 assert.equal(denied.error?.status,code);
}
const other=await runScenario({responses:[503,200],firstParty:false});
assert.equal(other.requests,1,"conference calls must not enter direct-Call retry policy");
assert.equal(other.error?.status,503);
const cancelled=await runScenario({responses:[503,200],aborted:true});
assert.equal(cancelled.requests,0,"revoked local admission must stop before network");
console.log("PASS: first-party MLS pending-peer rendezvous retries only 503; terminal denies, non-first-party grants, and cancellation fail closed");
