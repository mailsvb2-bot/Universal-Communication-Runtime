import assert from "node:assert/strict";
import test from "node:test";
import {readFileSync} from "node:fs";
import {URL} from "node:url";

const html=readFileSync("crates/ucr-realtime-web/static/start.html","utf8");
const script=readFileSync("crates/ucr-realtime-web/static/start.js","utf8");
const server=readFileSync("crates/ucr-realtime-web/src/main.rs","utf8");
const origin="https://app.petrellink.ru";

test("first-party /start has a visible, keyboard-usable Live link",()=>{
 const anchor=html.match(/<a\s+[^>]*id="pl-entry-broadcast"[^>]*>Эфир<\/a>/);
 assert.ok(anchor,"visible Эфир link must exist in the entry navigation");
 assert.match(html,/<nav id="pl-entry-nav" aria-label="Разделы PetrelLink">/);
 assert.doesNotMatch(anchor[0],/hidden|disabled|target="_blank"/);
 const href=anchor[0].match(/href="([^"]+)"/)?.[1];
 assert.equal(href,"/room");
 assert.equal(new URL(href,origin).origin,origin,"route remains same-origin");
});

test("broadcast link reaches the existing room enrollment handler, not grant-only conference",()=>{
 assert.match(server,/"\/"\s*\|\s*"\/join"\s*\|\s*"\/conference"\s*\|\s*"\/client.html"/);
 assert.match(server,/return Ok\(html_response\(StatusCode::OK, CLIENT_HTML\)\);/);
 assert.match(html,/<a href="\/start" aria-current="page" data-pl-ui="calls">Звонки<\/a>/);
 assert.match(script,/ru:\{calls:'Звонки',broadcast:'Эфир'/);
 assert.match(script,/en:\{calls:'Calls',broadcast:'Live'/);
});

test("Live route never embeds a signed grant, token or account ID",()=>{
 const live=html.match(/<a\s+[^>]*id="pl-entry-broadcast"[^>]*>/)?.[0];
 assert.ok(live);
 assert.doesNotMatch(live,/\?|#|token|credential|identity|grant|session/i);
});
