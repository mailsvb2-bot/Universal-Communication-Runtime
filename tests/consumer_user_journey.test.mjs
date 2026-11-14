import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import vm from "node:vm";
import test from "node:test";

const js=readFileSync("crates/ucr-realtime-web/static/start.js","utf8");
function section(from,to){
 const first=js.indexOf(from),last=js.indexOf(to,first);
 assert.ok(first>=0&&last>first,`missing journey section: ${from}`);
 return js.slice(first,last);
}

test("signup and recovery make the one-time secret visible in collapsed advanced panel",()=>{
 const output={hidden:true,scrollIntoView(options){this.scroll=options;}};
 const field={value:""};
 const advanced={open:false};
 const messages=[];
 const elements={"recovery-output":output,"recovery-code":field,"pl-advanced":advanced};
 const scope={el:id=>{assert.ok(elements[id],id);return elements[id]},message:x=>messages.push(x)};
 vm.runInNewContext(section("function showRecovery(code) {","async function updateDevices()"),scope);
 vm.runInNewContext('showRecovery("fresh-once-only-secret")',scope);
 assert.equal(output.hidden,false);
 assert.equal(advanced.open,true);
 assert.equal(field.value,"fresh-once-only-secret");
 assert.equal(output.scroll.block,"nearest");
 assert.ok(messages.some(x=>x.includes("повторно он не показывается")));
});

test("the signed-in CTA gives an actionable invite when contacts are empty",()=>{
 const source=section('el("pl-quick-action").addEventListener("click",()=>{','const plUiObserver=');
 const contacts={hidden:false,scrollIntoView(){},querySelector(){return null}};
 let invoked=0,registered;
 const scope={
  knownContacts:[],
  el:(id)=>{assert.equal(id,"pl-quick-action");return {addEventListener:(event,cb)=>{assert.equal(event,"click");registered=cb}}},
  plUiSave:()=>{},
  document:{body:{classList:{contains:()=>true}}},
  plUI:(id)=>id==="pl-contacts"?contacts:null,
  plShareInvite:()=>{invoked++;return Promise.resolve();}
 };
 vm.runInNewContext(source,scope);
 assert.equal(typeof registered,"function");
 registered();
 assert.equal(invoked,1,"first-time invite must run directly under user gesture");
});

test("CTA selects contact rather than inviting when the phonebook has entries",()=>{
 const source=section('el("pl-quick-action").addEventListener("click",()=>{','const plUiObserver=');
 let invited=0,focused=0,registered;
 const contacts={hidden:false,scrollIntoView(){},querySelector:()=>({})};
 const scope={
  knownContacts:[{id:'one'}],
  el:()=>({addEventListener:(_event,cb)=>{registered=cb}}),
  plUiSave:()=>{},
  document:{body:{classList:{contains:()=>true}}},
  plUI:(id)=>id==="pl-contacts"?contacts:id==="pl-contacts-filter"?{focus(){focused++}}:null,
  plShareInvite:()=>{invited++;return Promise.resolve()},
  renderContacts:()=>{}
 };
 vm.runInNewContext(source,scope);
 registered();
 assert.equal(invited,0);
 assert.equal(focused,1);
});

test("consumer CTA label distinguishes no contacts from populated contact list",()=>{
 const source=section("function plUiSync(){","const plSavedUi=");
 const catalog=section("const plUiText={","function plUiSync(){");
 const labels={};
 let populated=false;
 const classes={toggle(){},contains:x=>x==="pl-signed-in"};
 const quickName={placeholder:""},quickAction={textContent:""},quickHint={textContent:""};
 const scope={
  knownContacts:[],
  document:{body:{classList:classes},documentElement:{lang:"ru"},querySelectorAll:()=>[],querySelector:()=>populated?{}:null},
  plQuickName:quickName,plQuickAction:quickAction,plQuickHint:quickHint,
  plQuickPanel:{classList:{toggle(){}}},plUiPreferredButtons:()=>{},
  Object
 };
 vm.runInNewContext(catalog+source+"\nthis.sync=plUiSync;",scope);
 scope.sync();
 assert.equal(quickAction.textContent,"Пригласить друга");
 populated=true;scope.knownContacts=[{id:'one'}];scope.sync();
 assert.equal(quickAction.textContent,"Выбрать, кому позвонить");
});

test("pending share result cannot reveal the previous account invitation after logout",async()=>{
 const code=section("function plInviteStillCurrent(","el(\"pl-copy-invite\").addEventListener");
 let resolveShare;const pending=new Promise(resolve=>{resolveShare=resolve;});
 let shown=0,copied=0;
 const scope={
  plOwnIdentity:"identity-one",accountScope:"scope-one",
  plInviteUrl:()=>scope.plOwnIdentity?"https://example.invalid/start?contact="+scope.plOwnIdentity:null,
  location:{origin:"https://example.invalid"},navigator:{clipboard:{writeText:async()=>{copied++;}}},
  sharePublicInvite:async()=>pending,
  plShowInviteForManualCopy:()=>{shown++;},message:()=>{}
 };
 vm.runInNewContext(code+"\nthis.share=plShareInvite;",scope);
 const attempt=scope.share();
 scope.plOwnIdentity=null;scope.accountScope=null;
 resolveShare("manual");
 await attempt;
 assert.equal(shown,0,"stale invite fallback must not be visible after logout");
 assert.equal(copied,0);
});

test("a failed pending clipboard operation cannot restore a previous account invite",async()=>{
 const code=section("function plInviteStillCurrent(","el(\"pl-copy-invite\").addEventListener");
 let rejectCopy;const pending=new Promise((_,reject)=>{rejectCopy=reject;});
 let shown=0;
 const scope={
  plOwnIdentity:"identity-one",accountScope:"scope-one",
  plInviteUrl:()=>scope.plOwnIdentity?"https://example.invalid/start?contact="+scope.plOwnIdentity:null,
  navigator:{clipboard:{writeText:()=>pending}},plShowInviteForManualCopy:()=>{shown++;},message:()=>{}
 };
 vm.runInNewContext(code+"\nthis.copy=plCopyInvite;",scope);
 const attempt=scope.copy();
 scope.plOwnIdentity="identity-two";scope.accountScope="scope-two";
 rejectCopy(new Error("clipboard denied"));
 await attempt;
 assert.equal(shown,0);
});

test("filtered-to-zero search still navigates to real contacts, not invite",()=>{
 const source=section('el("pl-quick-action").addEventListener("click",()=>{','const plUiObserver=');
 let callback,invited=0,rendered=0,focused=0;
 const search={value:"missing friend",focus(){focused++;}};
 const scope={
  knownContacts:[{id:"existing"}],
  el:()=>({addEventListener:(_event,cb)=>{callback=cb}}),
  plUiSave:()=>{},
  document:{body:{classList:{contains:()=>true}}},
  plUI:id=>id==="pl-contacts"?{hidden:false,scrollIntoView(){}}:id==="pl-contacts-filter"?search:null,
  plShareInvite:()=>{invited++;return Promise.resolve()},
  renderContacts:items=>{assert.equal(items.length,1);rendered++;}
 };
 vm.runInNewContext(source,scope);
 callback();
 assert.equal(invited,0);
 assert.equal(rendered,1);
 assert.equal(search.value,"");
 assert.equal(focused,1);
});
