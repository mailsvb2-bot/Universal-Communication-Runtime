#!/usr/bin/env node
// Behavioral regression: both invitations respond even while a background
// authenticated action holds the generic run() lock, and blocked browser
// clipboard/share APIs expose a selectable contact locator.
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import vm from "node:vm";
import {sharePublicInvite} from "../crates/ucr-realtime-web/static/consumer-actions.js";
const js=readFileSync("crates/ucr-realtime-web/static/start.js","utf8");
const start=js.indexOf("function plInviteUrl(){");
const end=js.indexOf("function authHttpCode(error){",start);
assert.ok(start>=0&&end>start,"invitation handler must remain first-party");
const listeners=new Map(), elements=new Map(),messages=[];
function el(id){
  if((id==="pl-invite-manual"||id==="pl-invite-manual-url")&&!elements.has(id))return null;
  if(!elements.has(id)){
    const obj={id,children:[],hidden:false,style:{},dataset:{},append(...v){this.children.push(...v);for(const x of v)if(x.id)elements.set(x.id,x)},addEventListener(event,fn){listeners.set(id+":"+event,fn)},focus(){this.focused=true},select(){this.selected=true},setAttribute(){},value:"",textContent:""};
    elements.set(id,obj);
  }
  return elements.get(id);
}
const clipboard=[];
const ctx={plOwnIdentity:"known-peer",accountScope:"known-peer-session",location:{origin:"https://example.test"},navigator:{clipboard:{writeText:async url=>{clipboard.push(url);}}},
document:{createElement:tag=>({tag,children:[],style:{},append(...v){this.children.push(...v);for(const x of v)if(x.id)elements.set(x.id,x)},setAttribute(){},focus(){this.focused=true},select(){this.selected=true}})},
el,message:v=>messages.push(v),busy:true,navigating:true,
sharePublicInvite,resetPhonebook(){},run:()=>{throw Error("invitation must not be gated on run()")},URL};
vm.runInNewContext(js.slice(start,end),ctx);
listeners.get("pl-copy-invite:click")();
await new Promise(resolve=>setImmediate(resolve));
assert.deepEqual(clipboard,["https://example.test/start?contact=known-peer"]);
assert.ok(messages.at(-1).includes("скопировано"));
ctx.navigator.clipboard.writeText=async()=>{throw Error("blocked")};
listeners.get("pl-copy-invite:click")();
await new Promise(resolve=>setImmediate(resolve));
assert.equal(el("pl-invite-manual-url").value,"https://example.test/start?contact=known-peer");
assert.equal(el("pl-invite-manual-url").selected,true);
ctx.navigator.share=async()=>{throw Error("share aborted")};
listeners.get("pl-share-invite:click")();
await new Promise(resolve=>setImmediate(resolve));
assert.equal(el("pl-invite-manual-url").value,"https://example.test/start?contact=known-peer");
ctx.navigator.share=undefined;ctx.navigator.clipboard.writeText=async url=>clipboard.push(url);
listeners.get("pl-share-invite:click")();
await new Promise(resolve=>setImmediate(resolve));
assert.equal(clipboard.length,2);
// Account switches must not re-expose the old public contact locator.
const accountStart=js.indexOf("function plSetSignedIn(identity){");
const accountEnd=js.indexOf("// One fail-closed UI reset",accountStart);
assert.ok(accountStart>=0&&accountEnd>accountStart);
ctx.document.getElementById=id=>elements.get(id)||null;
ctx.localize=value=>value;
vm.runInNewContext(js.slice(accountStart,accountEnd),ctx);
vm.runInNewContext('plSetSignedIn("another-peer")',ctx);
assert.equal(el("pl-invite-manual").hidden,true);
assert.equal(el("pl-invite-manual-url").value,"");
ctx.plOwnIdentity=null;
listeners.get("pl-copy-invite:click")();
await new Promise(resolve=>setImmediate(resolve));
assert.ok(messages.at(-1).includes("Сначала подтвердите профиль"));
console.log("PASS: invite copy/share work under busy lock, denied clipboard/share, missing identity");
// This existing CI entrypoint also runs the real consumer contact/phonebook contract.
await import("../tests/consumer_phonebook.test.mjs");
