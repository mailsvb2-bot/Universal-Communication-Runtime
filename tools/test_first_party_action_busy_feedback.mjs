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
await vm.runInContext("run",ctx)(op);
assert.equal(executed,1);
assert.equal(ctx.busy,false);
console.log("PASS: blocked actions acknowledged and never executed twice");
