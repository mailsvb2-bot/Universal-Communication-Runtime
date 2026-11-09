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

async function runScenario({responses,firstParty=true,aborted=false}) {
 let requests=0;
 const context={
  claims:{call_id:firstParty?"fp-m-test-call":"conference-call",expires:Date.now()+60000},
  sessionStorage:{getItem:()=>firstParty?"fp-v-test-call":null},
  ui:{status:{textContent:""}},
  Date,Math,DOMException,Error,
  setTimeout:(fn)=>setTimeout(fn,0),
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
 return {value,error,requests};
}
const pending=await runScenario({responses:[503,503,503,200]});
assert.equal(pending.requests,4);
assert.equal(pending.value?.endpoint_state_mode,"restore");
assert.equal(pending.error,null);
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
