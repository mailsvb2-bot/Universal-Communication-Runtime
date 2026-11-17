import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import vm from "node:vm";
import test from "node:test";

const source=readFileSync("crates/ucr-realtime-web/static/start.js","utf8");
function extract(start,end) {
  const a=source.indexOf(start),b=source.indexOf(end,a);
  assert.ok(a>=0 && b>a,`missing session lifecycle boundary ${start}`);
  return source.slice(a,b);
}

test("repeated device initialization has one foreground listener, not one per login",()=>{
  const init=extract("async function initialize() {","// Item C6:");
  assert.doesNotMatch(init,/addEventListener\(["']visibilitychange["']/);
  assert.equal((source.match(/document\.addEventListener\(["']visibilitychange["']/g)||[]).length,1);
  assert.match(init,/requireCurrent\(\);\s*try \{await authTrace\("list_devices"/);
});

test("logout during contact load cannot restore old account widgets or start polling",async()=>{
  const init=extract("async function initialize() {","// Item C6:");
  let resolveContacts;
  const pendingContacts=new Promise(resolve=>{resolveContacts=resolve});
  const elements={who:{textContent:""},devices:{replaceChildren(){}}};
  let contactsRendered=0,startedWake=0,startedTimers=0,displayed=[];
  const scope={
    uiAuthGeneration:1,accountScope:null,active:null,knownContacts:[],
    idempotency:new Map(),timer:null,authDiagnostic(){},clearInterval(){},
    message:text=>displayed.push(text),restoreSession:async()=>({
      tenantId:"tenant",namespaceId:null,participantId:"alice",deviceId:"device",
    }),
    rememberBinding(){},forgetActiveCall(){},plSetSignedIn(){},showActive(){},
    renderIncoming(){},renderContacts(){contactsRendered++},
    el:id=>elements[id]||{replaceChildren(){}},
    principalScope:u=>JSON.stringify([u.tenantId,u.namespaceId,u.participantId,u.deviceId]),
    authTrace:async(_name,action)=>action(),
    updateContacts:()=>pendingContacts,
    updateDevices:async()=>{},
    refresh:async()=>{},
    handleMlsIntegrityError:()=>false,
    setInterval(){startedTimers++;return 1;},
    startIncomingCallWake(){startedWake++;},
    document:{hidden:false},
    navigating:false,busy:false,
    SessionSuperseded:class SessionSuperseded extends Error{constructor(){super("Device session changed");}},
  };
  vm.runInNewContext(init+"\nthis.initialize=initialize;",scope);
  const running=scope.initialize();
  for(let i=0;i<15 && !scope.accountScope;i++)await Promise.resolve();
  assert.ok(scope.accountScope,"initialization must reach authenticated account");
  const before=contactsRendered;
  scope.accountScope=null;
  scope.uiAuthGeneration++;
  resolveContacts([]);
  await assert.rejects(running,/Device session changed/);
  assert.equal(contactsRendered,before,"late contacts failure must not repaint logged-out account");
  assert.equal(startedTimers,0,"late initialization must not restart call polling");
  assert.equal(startedWake,0,"late initialization must not restart incoming wake");
  assert.ok(!displayed.some(text=>text.includes("Входящие звонки проверяются")));
});

test("late foreground network error is scoped to the authenticated generation",async()=>{
  const listener=extract('document.addEventListener("visibilitychange",()=>{','window.addEventListener("pagehide"');
  let cb;
  let rejectRefresh;
  let reports=0,messages=0;
  const promise=new Promise((_,reject)=>{rejectRefresh=reject;});
  const scope={
    accountScope:"scope-one",uiAuthGeneration:1,navigating:false,busy:false,
    document:{hidden:false,addEventListener:(event,fn)=>{assert.equal(event,"visibilitychange");cb=fn}},
    refresh:()=>promise,authDiagnostic:()=>{reports++},handleMlsIntegrityError:()=>false,
    message:()=>{messages++},
  };
  vm.runInNewContext(listener,scope);
  cb();
  scope.accountScope=null;scope.uiAuthGeneration=2;
  rejectRefresh(new Error("previous account network request"));
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(messages,0);
  assert.equal(reports,0);
});

test("accepted incoming call survives transient Device recheck failure without granting media",async()=>{
  const code=extract("function renderIncoming(items) {","async function refresh() {");
  const actions={};
  let locator=null,mediaStarted=0,confirmedIdentity=null;
  const accepted={
    callId:"accepted-call",callerIdentityId:"peer-alice",calleeIdentityId:"peer-bob",
    media:"video",state:"active"
  };
  const element=()=>({
    hidden:false,textContent:"",className:"",append(){},replaceChildren(){},
    setAttribute(){},
  });
  const incoming=element();
  const scope={
    accountScope:"signed-in-scope",uiAuthGeneration:7,plOwnIdentity:"peer-bob",
    active:null,navigating:false,
    activeCallLocator:()=>locator,
    rememberActiveCall:(call,identity)=>{
      assert.equal(call.callId,accepted.callId);
      confirmedIdentity=identity;
      locator="scoped-canonical-call-locator";
    },
    host:{resumeAuthenticatedDevice:async()=>{throw new Error("transient 503");}},
    calls:{signal:async(id,action)=>{
      assert.equal(id,accepted.callId);assert.equal(action,"accept");return accepted;
    }},
    document:{title:"PetrelLink",querySelector:()=>({hidden:true}),createElement:element},
    ordinaryPageTitle:"PetrelLink",
    el:id=>id==="incoming"?incoming:element(),
    btn:(name,callback)=>{actions[name]=callback;return element()},
    nameFor:identity=>identity,
    beginMedia:async()=>{mediaStarted++;},
    principalScope:()=> "signed-in-scope",
    showActive(){},
    message(){},
    mlsHint:e=>String(e),
  };
  vm.runInNewContext(code+"\nthis.renderIncoming=renderIncoming;",scope);
  scope.renderIncoming([accepted]);
  await assert.rejects(actions["Принять"](),/transient 503/);
  assert.equal(confirmedIdentity,"peer-bob");
  assert.equal(locator,"scoped-canonical-call-locator",
    "committed canonical acceptance must be recoverable after transient recheck error");
  assert.equal(scope.active,null,"no authenticated Device proof means no media");
  assert.equal(mediaStarted,0);
});

test("ambiguous recipient acceptance remains untrusted until canonical active inspection",async()=>{
  const sourceCode=extract("function principalScope(user) {","function message(value) {");
  const user={tenantId:"tenant",namespaceId:null,participantId:"bob",deviceId:"device"};
  const scopeKey=JSON.stringify([user.tenantId,user.namespaceId,user.participantId,user.deviceId]);
  let state="ringing",painted=0;
  const hints=new Map(),hintKey="ucr.first-party.active-call.v1";
  const call={
    callId:"incoming-call",callerIdentityId:"alice",calleeIdentityId:"bob",media:"video",state
  };
  const ctx={
    accountScope:scopeKey,uiAuthGeneration:2,active:null,knownContacts:[],
    sessionStorage:{getItem:k=>hints.get(k)??null,setItem:(k,v)=>hints.set(k,v),removeItem:k=>hints.delete(k)},
    calls:{inspect:async id=>{assert.equal(id,call.callId);return {...call,state};}},
    showActive:()=>painted++,authHttpCode:()=>0,
  };
  vm.runInNewContext('const ACTIVE_CALL_HINT_KEY="ucr.first-party.active-call.v1";\n'+
    sourceCode+'\nthis.ops={rememberActiveCall,restoreActiveCall};',ctx);
  ctx.ops.rememberActiveCall(call,"bob",{acceptPending:true});
  assert.equal(JSON.parse(hints.get(hintKey)).acceptPending,true);
  await ctx.ops.restoreActiveCall(user);
  assert.equal(ctx.active,null,"ringing alone is not evidence of accepted media");
  assert.equal(painted,0);
  assert.equal(hints.has(hintKey),true,"briefly retain ambiguous acceptance for late commit");
  state="active";
  await ctx.ops.restoreActiveCall(user);
  assert.equal(ctx.active.call.state,"active");
  assert.equal(painted,1);
  assert.equal(JSON.parse(hints.get(hintKey)).acceptPending,undefined,
    "canonical confirmation clears pending-only marker");
  ctx.active=null;state="ringing";
  ctx.ops.rememberActiveCall(call,"bob",{acceptPending:true});
  const expired=JSON.parse(hints.get(hintKey));
  expired.acceptPendingAt=Date.now()-20000;
  hints.set(hintKey,JSON.stringify(expired));
  await ctx.ops.restoreActiveCall(user);
  assert.equal(ctx.active,null);
  assert.equal(hints.has(hintKey),false,
    "an unconfirmed ringing call must not lock the UI indefinitely");
});

test("logout completion cannot repaint a newer session, and server logout is awaited",async()=>{
  const code=extract("let logoutInFlight=false;","// Mobile tabs become hidden");
  let handler=null,finishLogout,rejectLogout;
  const request=new Promise((resolve,reject)=>{finishLogout=resolve;rejectLogout=reject});
  const messages=[],who={textContent:""};
  const scope={
    accountScope:"old-session",uiAuthGeneration:5,
    el:id=>id==="logout"?{addEventListener:(name,cb)=>{
      assert.equal(name,"click");handler=cb;
    }}:id==="who"?who:assert.fail(id),
    forgetBinding(){},forgetActiveCall(){},
    plClearAuthenticatedView(){scope.accountScope=null;scope.uiAuthGeneration++},
    host:{logout:()=>request},message:x=>messages.push(x),
  };
  vm.runInNewContext(code+"\nthis.logoutBusy=()=>logoutInFlight;",scope);
  handler();
  assert.equal(scope.logoutBusy(),true);
  assert.equal(scope.accountScope,null);
  // A new login in a different tab or another UI generation must win.
  scope.accountScope="new-session";scope.uiAuthGeneration++;
  finishLogout();
  for(let i=0;i<8;i++)await Promise.resolve();
  assert.equal(scope.logoutBusy(),false);
  assert.notEqual(who.textContent,"Вы вышли из учётной записи.");
  assert.equal(messages.length,0,"old logout completion must not repaint new identity");
});

test("long-poll incoming wake is cancelled on logout, pagehide and a replacement Device",async()=>{
  const code=extract("let incomingWakeGeneration = 0, incomingWakeController = null;",
                     'el("device-login").addEventListener');
  const signals=[],requests=[];
  const ctx={
    accountScope:"account-one",uiAuthGeneration:3,busy:false,navigating:false,
    AbortController,
    fetch:(_url,options)=>{
      requests.push(_url);signals.push(options.signal);
      return new Promise((resolve,reject)=>{
        options.signal.addEventListener("abort",()=>reject(
          Object.assign(new Error("aborted"),{name:"AbortError"})),{once:true});
      });
    },
    refresh:async()=>{},
    authDiagnostic(){},
    setTimeout:()=>assert.fail("aborted long poll must not start retry timer"),
  };
  vm.runInNewContext(code+"\nthis.start=startIncomingCallWake;this.stop=stopIncomingCallWake;",ctx);
  ctx.start();
  assert.equal(requests.length,1);
  assert.equal(signals[0].aborted,false);
  ctx.start();
  assert.equal(signals[0].aborted,true,"new Device wake must retire previous fetch");
  assert.equal(requests.length,2);
  ctx.accountScope=null;ctx.uiAuthGeneration++;
  ctx.stop();
  assert.equal(signals[1].aborted,true,"logout must promptly cancel pending fetch");
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(requests.length,2,"aborted wake cannot restart a prior Device poll");
  assert.match(source,/function plClearAuthenticatedView\([^)]*\)\{[\s\S]*?stopIncomingCallWake\(\);/);
  assert.match(source,/window\.addEventListener\("pagehide", \(\) => \{[\s\S]*?stopIncomingCallWake\(\);/);
});

test("BFCache restore restarts canonical Device monitoring once, not on fresh pages",async()=>{
  const code=extract('window.addEventListener("pagehide", () => {','function explainEntryFailure(error) {');
  const listeners={};
  let polls=0,initializations=0,aborts=0;
  const ctx={
    window:{addEventListener:(name,fn)=>{listeners[name]=fn}},
    clearInterval:()=>{polls++},stopIncomingCallWake:()=>{aborts++},
    timer:42,accountScope:"verified-device",navigating:false,busy:false,logoutInFlight:false,
    initialize:async()=>{initializations++;ctx.timer=99},
    authDiagnostic:()=>assert.fail("unexpected restore failure"),
    message:()=>assert.fail("unexpected restore failure"),
    SessionSuperseded:class extends Error {},
  };
  vm.runInNewContext(code,ctx);
  listeners.pageshow({persisted:false});
  assert.equal(initializations,0);
  listeners.pagehide();
  assert.equal(ctx.timer,null);
  assert.equal(polls,1);
  assert.equal(aborts,1);
  listeners.pageshow({persisted:true});
  listeners.pageshow({persisted:true});
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(initializations,1,"BFCache duplicate pageshow must not launch two monitors");
  assert.equal(ctx.timer,99);
  assert.equal(ctx.busy,false);
  listeners.pageshow({persisted:true});
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(initializations,1,"already active timer must not be replaced");
  ctx.accountScope=null;ctx.timer=null;
  listeners.pageshow({persisted:true});
  assert.equal(initializations,1,"logged-out page must not monitor old account");
});
