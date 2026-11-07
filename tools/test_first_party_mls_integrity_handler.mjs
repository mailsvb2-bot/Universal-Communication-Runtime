#!/usr/bin/env node
// Exercise the production /start.js integrity-failure handler, not a duplicate
// implementation. Isolated UI regression: NOT a live two-device E2EE proof.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";

const source = readFileSync("crates/ucr-realtime-web/static/start.js", "utf8");
const begin = source.indexOf("function handleMlsIntegrityError(error) {");
const end = source.indexOf("async function run(action)", begin);
assert.ok(begin !== -1 && end > begin, "production integrity handler missing");
const handler = source.slice(begin, end);
const events = [];
const state = {
  active: { call: { callId: "call-a" } },
  MlsIntegrityError: class MlsIntegrityError extends Error {},
  markCallCompromised: id => events.push(["compromised", id]),
  message: text => events.push(["message", text]),
  showActive: () => events.push(["render"]),
};
runInNewContext(handler + "\nthis.handle = handleMlsIntegrityError;", state);
assert.equal(state.handle(new Error("HTTP 503")), false,
  "ordinary network failure must not compromise the current Call");
assert.equal(events.length, 0, "network failure must leave UI and state untouched");
assert.equal(state.handle(new state.MlsIntegrityError("bad commit")), true);
assert.deepEqual(events.map(([kind]) => kind),
  ["compromised", "message", "render"],
  "integrity failure must quarantine the exact call and re-render its recovery UI");
assert.equal(events[0][1], "call-a");
assert.match(events[1][1], /новый защищённый звонок/i);
state.active = null;
events.length = 0;
assert.equal(state.handle(new state.MlsIntegrityError("stale previous call")), false,
  "late integrity errors must not quarantine an unrelated or absent Call");
assert.equal(events.length, 0, "late error must cause no UI side effects");
console.log("PASS: actual first-party MLS integrity handler fail-closed and scoped");
