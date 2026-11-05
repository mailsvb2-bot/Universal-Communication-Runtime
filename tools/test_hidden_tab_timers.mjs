#!/usr/bin/env node
// Item C8: UI-only polling must pause in a hidden tab, while call-critical
// timers (heartbeat, presence, membership refresh, adaptive media) must not.
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {runInNewContext} from "node:vm";

const source=readFileSync("crates/ucr-realtime-web/static/client.html","utf8");
const helper=source.slice(source.indexOf("function ucrBackgroundIdle("),source.indexOf("\n",source.indexOf("function ucrBackgroundIdle(")));
for(const hidden of [true,false]){
  const ctx={document:{hidden}};
  runInNewContext(helper,ctx);
  assert.equal(runInNewContext("ucrBackgroundIdle()",ctx),hidden);
}
assert.equal(runInNewContext(helper+";ucrBackgroundIdle()",{}),false,"no document = never idle");

for(const poller of ["pollReactions()","pollChat()","pollActiveSpeaker()","refreshRoomRoster()"]){
  const re=new RegExp(`setInterval\\(\\(\\)=>\\{if\\(ucrBackgroundIdle\\(\\)\\)return;${poller.replace(/[()]/g,"\\$&")}`);
  assert.match(source,re,`${poller} interval must skip hidden tabs`);
}
for(const critical of ["holdRoomPresence","reportAdaptiveMedia","reportLocalAudioLevel"]){
  const at=source.indexOf(critical+"",source.indexOf("setInterval("));
  assert.ok(at>0,critical);
}
assert.doesNotMatch(source,/setInterval\(holdRoomPresence[^)]*ucrBackgroundIdle/,"presence must keep running");
assert.doesNotMatch(source,/heartbeatTimer=setInterval\(\(\)=>\{if\(ucrBackgroundIdle/,"heartbeat must keep running");
const vis=source.slice(source.indexOf('addEventListener("visibilitychange"'));
for(const f of ["pollChat()","pollReactions()","pollActiveSpeaker()","refreshRoomRoster()"])assert.ok(vis.slice(0,600).includes(f),`catch-up ${f}`);
console.log("hidden-tab timer policy: ok");
