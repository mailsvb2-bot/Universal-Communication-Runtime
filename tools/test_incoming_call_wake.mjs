#!/usr/bin/env node
// Item C6: the optional incoming-call wake loop must (a) stop on 404 (flag
// off) leaving periodic polling, (b) call refresh() only on a real change,
// (c) never put a query string on /v1/first-party/* (edge proxy denies it),
// (d) stop when the auth generation changes (logout).
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {runInNewContext} from "node:vm";

const source=readFileSync("crates/ucr-realtime-web/static/start.js","utf8");
const start=source.indexOf("let incomingWakeGeneration");
const end=source.indexOf('el("device-login")',start);
assert.ok(start>0&&end>start,"wake loop present");
const code=source.slice(start,end);
assert.doesNotMatch(code,/\?since=/,"no query strings through the edge proxy");
assert.match(source,/startIncomingCallWake\(\);\n\}/,"started after periodic poller");

async function run(responses,{logoutAfter=Infinity}={}){
  const urls=[];let refreshes=0;
  const ctx={uiAuthGeneration:1,busy:false,navigating:false,encodeURIComponent,
    setTimeout:(f)=>f(),authDiagnostic(){},
    refresh:async()=>{refreshes+=1;},
    fetch:async(url)=>{urls.push(url);if(urls.length>=logoutAfter)ctx.uiAuthGeneration+=1;
      const r=responses.shift();if(!r)return {status:404,ok:false};
      if(r==="throw")throw new Error("net");
      return {status:r.status??200,ok:(r.status??200)===200,json:async()=>r.body};}};
  runInNewContext(code+";startIncomingCallWake();",ctx);
  for(let i=0;i<50;i+=1)await new Promise(r=>setImmediate(r));
  return {urls,refreshes};
}

let r=await run([{status:404}]);
assert.deepEqual(r.urls,["/v1/first-party/call/wait"]);assert.equal(r.refreshes,0);

r=await run([{body:{revision:"5",changed:false}},{body:{revision:"5",changed:false}},{body:{revision:"9",changed:true}}]);
assert.deepEqual(r.urls.slice(0,3),["/v1/first-party/call/wait","/v1/first-party/call/wait/5","/v1/first-party/call/wait/5"]);
assert.equal(r.refreshes,1,"refresh only on change");

r=await run(["throw","throw","throw",{body:{revision:"1",changed:false}}]);
assert.equal(r.urls.length,3,"stops after repeated failures");

r=await run([{body:{revision:"bad",changed:true}}]);
assert.equal(r.urls.length,1,"rejects malformed revision");

r=await run([{body:{revision:"1",changed:false}},{body:{revision:"2",changed:true}}],{logoutAfter:1});
assert.equal(r.urls.length,1);assert.equal(r.refreshes,0,"logout stops loop");
console.log("incoming-call wake loop: ok");
