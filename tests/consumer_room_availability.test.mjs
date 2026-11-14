import assert from "node:assert/strict";
import test from "node:test";
import {readFileSync} from "node:fs";

const root=readFileSync("crates/ucr-realtime-web/src/main.rs","utf8");
const client=readFileSync("crates/ucr-realtime-web/static/client.html","utf8");
const start=readFileSync("crates/ucr-realtime-web/static/start.html","utf8");
const roomAnchor='function beginLocalRoomLobby(){';
const begin=client.indexOf(roomAnchor);
const end=client.indexOf('async function submitLocalRoom(',begin);
assert.ok(begin>0 && end>begin);
const room=client.slice(begin,end);

test("room availability is separate from the general gateway readyz",()=>{
 assert.match(root,/path == "\/v1\/room\/status"/);
 assert.match(root,/read_room_proxy\(state\.room_api, "\/v1\/room\/capabilities"/);\n assert.match(root,/canonical-ucr-runtime/);\n assert.match(root,/production-room-enrollment-v1/);
 assert.match(root,/StatusCode::SERVICE_UNAVAILABLE/);
 assert.match(root,/room_backend_unavailable/);
 assert.match(root,/transport":"canonical-room-ready/);
});
test("room lobby does not offer capture or enrollment before room preflight",()=>{
 const disabled=room.indexOf('roomSubmit.disabled=true;');
 const preflight=room.indexOf('fetch("/v1/room/status"');
 const handler=room.indexOf('lobby.addEventListener("submit"');
 assert.ok(disabled>=0 && disabled<preflight && preflight<handler);
 assert.match(room,/if\(!response\.ok\)throw/);
 assert.match(room,/if\(result\.ok!==true\|\|result\.transport!=="canonical-room-ready"\)/);
 assert.match(room,/roomSubmit\.disabled=false/);
 assert.match(room,/Эфир временно недоступен/);
});
test("public live navigation still targets the existing same-origin room page",()=>{
 assert.match(start,/<a href="\/room" id="pl-entry-broadcast"/);
 assert.match(client,/const configured = "%%UCR_ROOM_API%%"/);
 assert.match(root,/fn room_page\(\) -> String/);
 assert.doesNotMatch(room,/\bwindow\.location\s*=/);
});
