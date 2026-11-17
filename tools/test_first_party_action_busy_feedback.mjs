#!/usr/bin/env node
// Regression: locked authenticated actions must acknowledge the user without
// triggering duplicate operations. No UI credentials, browser or network needed.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const js = readFileSync("crates/ucr-realtime-web/static/start.js", "utf8");
const start = js.indexOf("async function run(action) {");
const end = js.indexOf("function renderContacts(", start);
assert.ok(start >= 0 && end > start, "canonical run() must exist");
const source = js.slice(start, end);
const notices = [];
let executed = 0;
const ctx = {
  busy: true,
  navigating: false,
  logoutInFlight: false,
  accountScope: "tenant-account-a",
  uiAuthGeneration: 4,
  SessionSuperseded: class SessionSuperseded extends Error {},
  message: text => notices.push(text),
  handleMlsIntegrityError: () => false,
  Error,
};
vm.createContext(ctx);
vm.runInContext(source, ctx);
const op = () => { executed++; };
await vm.runInContext("run",ctx)(op);
assert.equal(executed,0);
assert.match(notices.at(-1),/Предыдущее действие/);
ctx.busy=false;
ctx.navigating=true;
await vm.runInContext("run",ctx)(op);
assert.equal(executed,0);
assert.match(notices.at(-1),/Открывается защищённая конференция/);
ctx.navigating=false;
// Logout owns the current HttpOnly cookie until the canonical server request
// settles. A new login/signup/call MUST NOT be allowed to race that request.
ctx.logoutInFlight=true;
await vm.runInContext("run",ctx)(op);
assert.equal(executed,0);
assert.match(notices.at(-1),/Завершается выход/);
ctx.logoutInFlight=false;
await vm.runInContext("run",ctx)(op);
assert.equal(executed,1);
assert.equal(ctx.busy,false);
// A delayed request rejected after explicit Logout is no longer allowed to
// paint the old account's diagnostic error into the new or anonymous UI.
let rejectOld;
const pending=vm.runInContext("run",ctx)(()=>new Promise((_resolve,reject)=>{
  rejectOld=reject;
}));
assert.equal(ctx.busy,true);
const noticesBeforeLogout=notices.length;
ctx.accountScope=null;
ctx.uiAuthGeneration++;
rejectOld(new Error("HTTP 503: previous account"));
await pending;
assert.equal(ctx.busy,false);
assert.equal(notices.length,noticesBeforeLogout,
  "late old-account failure must not repaint after Logout");
console.log("PASS: blocked actions acknowledged, no duplicates or stale post-Logout errors");
