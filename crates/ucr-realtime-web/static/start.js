// Report a missing generated browser bundle instead of hanging at login.
let media;
try {
  media = await import("/endpoint-media/reference_browser_media_installer.js");
} catch (error) {
  const who = document.getElementById("who");
  if (who) who.textContent = "Вход недоступен: браузерный пакет не установлен.";
  const status = document.getElementById("status");
  if (status) status.textContent = "Не загружен браузерный пакет: " +
    (error instanceof Error ? error.message : String(error));
  throw error;
}
const {
  createUcrBrowserProtectedDeviceVault,
  createUcrFirstPartyHttpHost,
  authenticateUcrFirstPartyDevice,
  registerUcrFirstPartyUser,
  recoverUcrFirstPartyDevice,
  createUcrContactCallJourney,
} = media;

const el = (id) => document.getElementById(id);
const status = el("status");
const vault = createUcrBrowserProtectedDeviceVault();
const host = createUcrFirstPartyHttpHost(vault, {origin:location.origin});
const calls = createUcrContactCallJourney(host,vault);
let active = null, busy = false, navigating = false, refreshing = false, timer = null;
let knownContacts = [];
let accountScope = null;
// Fence delayed authenticated reads across logout, revoke and same-Identity re-login.
let uiAuthGeneration = 0;
const idempotency = new Map();
const HINT_KEY = "ucr.first-party.last-device.v1";
const ACTIVE_CALL_HINT_KEY = "ucr.first-party.active-call.v1";
const authDiagnostics=[];
let plOwnIdentity=null;
function plSetSignedIn(identity){
  plOwnIdentity=identity||null;
  const logged=Boolean(plOwnIdentity);
  el("pl-new-user").hidden=logged;
  el("pl-user-cabinet").hidden=!logged;
  for(const id of ["pl-contacts","pl-incoming","pl-current-call"])el(id).hidden=!logged;
  if(logged){
    el("pl-friendly-identity").textContent="Профиль активен. Пригласите знакомого или выберите контакт для звонка.";
    const invited=el("contact-peer").dataset.invitedContact==="true";
    if(invited) {
      el("pl-invite-help").hidden=false;
      // The invite is only a locator, not authority to authenticate its sender.
      el("pl-contacts").scrollIntoView({behavior:"smooth",block:"start"});
      el("contact-name").focus({preventScroll:true});
    }
  }
}
// One fail-closed UI reset for logout, revoked sessions and cross-tab account changes.
// It clears previously authenticated contact, Device, Call and recovery views.
function plClearAuthenticatedView(preserveRecoveryCode=false){
  uiAuthGeneration++;
  clearInterval(timer);
  accountScope=null;
  active=null;
  knownContacts=[];
  idempotency.clear();
  renderContacts([]);
  renderIncoming([]);
  el("devices").replaceChildren();
  showActive();
  plSetSignedIn(null);
  el("who").textContent="Нет подтверждённой сессии.";
  el("new-contact").reset();
  el("pl-invite-help").hidden=true;
  // An account signup/recovery may have committed before session issuance.
  // Never destroy the one-time rotated recovery code on a failed first login.
  if(!preserveRecoveryCode){
    el("recovery-output").hidden=true;
    el("recovery-code").value="";
  }
}
function plInviteUrl(){
  if(!plOwnIdentity)return null;
  const url=new URL("/start",location.origin);
  url.searchParams.set("contact",plOwnIdentity);
  return url.href;
}
el("pl-copy-invite").addEventListener("click",()=>void run(async()=>{
  const url=plInviteUrl();if(!url)return;
  await navigator.clipboard.writeText(url);
  message("Приглашение скопировано. Попросите знакомого сверить код с вами.");
}));
el("pl-share-invite").addEventListener("click",()=>void run(async()=>{
  const url=plInviteUrl();if(!url)return;
  if(navigator.share){await navigator.share({title:"PetrelLink — контакт",url});}
  else{await navigator.clipboard.writeText(url);message("Приглашение скопировано.");}
}));
function authHttpCode(error){
  const match=String(error instanceof Error?error.message:"").match(/HTTP (401|403|404|409|429|500|502|503)/);
  return match?Number(match[1]):null;
}
function authFailureCategory(error){
  const code=authHttpCode(error);
  if(code===401)return "HTTP_401_AUTHORITY_REJECTED";
  if(code===403)return "HTTP_403_ACCESS_DENIED";
  if(code===409)return "HTTP_409_STATE_CONFLICT";
  if(code===503)return "HTTP_503_AUTHORITY_UNAVAILABLE";
  return code?"HTTP_"+code:"CLIENT_OR_NETWORK_ERROR";
}
function authDiagnostic(stage,outcome,error){
  // Explicit allowlist: do not include arbitrary error messages or IDs.
  const allowed=new Set(["resume_session","device_reauthentication","device_scope_verification","list_devices","list_contacts","incoming_calls","inspect_call","initialization","periodic_refresh"]);
  if(!allowed.has(stage))return;
  authDiagnostics.push({timestamp:new Date().toISOString(),stage,outcome,
    reason:error?authFailureCategory(error):null,httpStatus:error?authHttpCode(error):null});
  if(authDiagnostics.length>60)authDiagnostics.shift();
  authRenderDiagnostics();
}
function authRenderDiagnostics(){
  const panel=el("auth-diagnostics-report");
  if(!panel)return;
  panel.textContent=JSON.stringify({schema:"ucr-auth-diagnostics-v1",
    generatedAt:new Date().toISOString(),events:authDiagnostics},null,2);
}
el("auth-diagnostics-copy").addEventListener("click",async()=>{
  try{await navigator.clipboard.writeText(el("auth-diagnostics-report").textContent);}
  catch{message("Буфер обмена недоступен. Используйте «Сохранить JSON».");}
});
el("auth-diagnostics-save").addEventListener("click",()=>{
  const blob=new Blob([el("auth-diagnostics-report").textContent],{type:"application/json"});
  const url=URL.createObjectURL(blob);const link=document.createElement("a");
  link.href=url;link.download="ucr-auth-diagnostics.json";link.click();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
});
authRenderDiagnostics();
async function authTrace(stage,operation){
  try{const result=await operation();authDiagnostic(stage,"ok");return result;}
  catch(error){authDiagnostic(stage,"failed",error);throw error;}
}

// A convenience hint only: never a login credential, authorization grant,
// private Device signer, recovery code or second Identity database.
function rememberBinding(binding) {
  const publicHint={
    tenantId:binding.tenantId,namespaceId:binding.namespaceId,
    participantId:binding.participantId,deviceId:binding.deviceId,
  };
  try {localStorage.setItem(HINT_KEY,JSON.stringify(publicHint));} catch {}
}
function forgetBinding() {
  try {localStorage.removeItem(HINT_KEY);} catch {}
}
function lastBinding() {
  try {
    const hint=JSON.parse(localStorage.getItem(HINT_KEY)??"null");
    if(!hint||typeof hint!=="object"||
        !["tenantId","participantId","deviceId"].every(
          key=>typeof hint[key]==="string"&&hint[key].length>0&&hint[key].length<=120) ||
        !(hint.namespaceId===null||
          (typeof hint.namespaceId==="string"&&hint.namespaceId.length>0))){
      return null;
    }
    return hint;
  } catch {return null;}
}
// Keep the public identity fields visible for an existing trusted Device.
// The localStorage hint cannot authorize anything without the IndexedDB signer
// and fresh server challenge. This never registers or trusts a new Device.
{
  const saved = lastBinding();
  if (saved) {
    el("login-tenant").value = saved.tenantId;
    el("login-namespace").value = saved.namespaceId ?? "";
    el("login-identity").value = saved.participantId;
    el("login-device").value = saved.deviceId;
  }
}
async function restoreSession() {
  // Logout/revoke must fence an in-flight cookie check before it can
  // silently reauthenticate and issue a new browser session.
  const generation=uiAuthGeneration;
  try {
    const resumed=await authTrace("resume_session",()=>host.resumeAuthenticatedDevice());
    if(generation!==uiAuthGeneration)throw Error("Device session changed during authentication");
    return resumed;
  } catch(error) {
    if(generation!==uiAuthGeneration)throw Error("Device session changed during authentication");
    // Only an expired/absent cookie (401) authorizes a fresh possession proof.
    // A transient network/5xx failure, rate limit or 403 must not silently
    // issue another session or turn a failed status check into a login attempt.
    if(authHttpCode(error)!==401)throw error;
    const hint=lastBinding();
    if(!hint){
      authDiagnostic("device_reauthentication","unavailable");
      // A missing public binding cannot authorize a replacement identity.
      // Preserve the existing protected signer and require explicit re-login.
      throw new Error("HTTP 401: session expired; no saved Device binding. Enter your existing Tenant, Identity and Device IDs to sign in with the original protected key. If that key is unavailable, use account recovery.");
    }
    // Only a real protected, previously registered signer may re-login.
    // If the server revoked this Device, do not turn the hint into trust.
    const verified=await authTrace("device_reauthentication",()=>authenticateUcrFirstPartyDevice(
      vault,{origin:location.origin},hint));
    if(generation!==uiAuthGeneration)throw Error("Device session changed during authentication");
    if(principalScope(verified)!==principalScope(hint)){
      authDiagnostic("device_scope_verification","failed");
      forgetBinding();
      throw Error("восстановленная учётная запись или Device не совпадает");
    }
    return verified;
  }
}


function clearRetryKey(call) {
  // A terminal Call is not a retry of a previous button press. A fresh
  // click must start a new canonical Call with a new idempotency key.
  const contact = knownContacts.find(c => c.peerIdentityId === call.calleeIdentityId);
  if (contact) idempotency.delete(contact.id + ":" + call.media);
}
function principalScope(user) {
  return JSON.stringify([user.tenantId,user.namespaceId,user.participantId,user.deviceId]);
}

// Session storage is only a same-tab locator, never a Call or Identity owner.
// Every restored Call must be inspected under a fresh canonical Device session.
function rememberActiveCall(call,identity) {
  if (!accountScope || ![call.callerIdentityId,call.calleeIdentityId].includes(identity) ||
      typeof call.callId !== "string" || !/^[A-Za-z0-9_.:@-]{1,128}$/.test(call.callId)) return;
  try {sessionStorage.setItem(ACTIVE_CALL_HINT_KEY,JSON.stringify({
    scope:accountScope,callId:call.callId,
  }));} catch {}
}
function activeCallLocator() {
  try {return sessionStorage.getItem(ACTIVE_CALL_HINT_KEY);} catch {return null;}
}
// This same-tab locator is not a Call authority. Persist only the user's
// stop intent so a reload after an ambiguous Hangup response cannot silently
// re-enter media before the canonical Call owner confirms termination.
function rememberStopIntent(callId) {
  const locator = activeCallLocator();
  if (locator === null) return null;
  try {
    const hint = JSON.parse(locator);
    if (hint?.scope !== accountScope || hint?.callId !== callId) return locator;
    const stopped = JSON.stringify({...hint,stopRequested:true});
    sessionStorage.setItem(ACTIVE_CALL_HINT_KEY,stopped);
    return stopped;
  } catch {return locator;}
}
function forgetActiveCall(expectedLocator) {
  try {
    // A stale inspection must not delete a newer Call's locator.
    if (expectedLocator === undefined ||
        sessionStorage.getItem(ACTIVE_CALL_HINT_KEY) === expectedLocator) {
      sessionStorage.removeItem(ACTIVE_CALL_HINT_KEY);
    }
  } catch {}
}
async function restoreActiveCall(user) {
  // Snapshot the exact locator: the Call owner, not sessionStorage, supplies state.
  const locator = activeCallLocator();
  if (locator === null) return;
  let hint;
  try {hint=JSON.parse(locator);}
  catch {forgetActiveCall(locator);return;}
  const scope=principalScope(user);
  const generation=uiAuthGeneration;
  if (!hint || typeof hint!=="object" || hint.scope!==scope ||
      accountScope!==scope || typeof hint.callId!=="string" ||
      !/^[A-Za-z0-9_.:@-]{1,128}$/.test(hint.callId)) {
    forgetActiveCall(locator);return;
  }
  try {
    const call=await calls.inspect(hint.callId);
    // Inspect checks current canonical participant, Device and Call membership.
    // A delayed response cannot restore a Call after account/Device switch.
    if (accountScope!==scope || generation!==uiAuthGeneration) {
      forgetActiveCall(locator);return;
    }
    // A new Call (or a newer locator) wins over this in-flight inspection.
    if (active || activeCallLocator()!==locator) return;
    if (call.state==="terminated") {forgetActiveCall(locator);return;}
    active={call,identity:user.participantId,terminating:hint.stopRequested===true};
    showActive();
  } catch(error) {
    // A stale denial must not delete a newer Call's locator.
    if ([403,404].includes(authHttpCode(error))) forgetActiveCall(locator);
    throw error;
  }
}

function message(value) { status.textContent = value; }
function setCallStage(step, guide) {
  for (const [index, name] of ["device","contact","accepted","media"].entries()) {
    const element = el("stage-" + name);
    if (index === step) element.setAttribute("aria-current","step");
    else element.removeAttribute("aria-current");
  }
  el("video-guide").textContent = guide;
}
function showRecovery(code) {
  const element = el("recovery-output");
  element.hidden = false;
  el("recovery-code").value = code;
  message("Новый одноразовый код создан. Сохраните его отдельно: повторно он не показывается.");
}
async function updateDevices() {
  const scope=accountScope, generation=uiAuthGeneration;
  const records = await host.listDevices();
  if(!scope || scope!==accountScope || generation!==uiAuthGeneration)return;
  const list = el("devices");
  list.replaceChildren();
  for (const record of records) {
    const li=document.createElement("li");
    const name=document.createElement("strong");
    name.textContent=record.deviceId;
    const state=document.createElement("div");
    state.className="identity";state.textContent=record.state;
    li.append(name,state);
    if(record.state==="active"){
      const actions=document.createElement("div");
      actions.className="actions";
      actions.append(btn("Отозвать устройство",async()=>{
        if(!window.confirm("Отзыв устройства необратим. Подтвердить?"))return;
        const own=record.deviceId===(await host.resumeAuthenticatedDevice()).deviceId;
        await host.revokeDevice(record.deviceId);
        if(own){
          forgetBinding();forgetActiveCall();
          plClearAuthenticatedView();
          message("Это устройство отозвано. Повторный вход с ним невозможен.");
        }else{await updateDevices();}
      },"secondary"));
      li.append(actions);
    }
    list.append(li);
  }
}

function textNode(value) {return document.createTextNode(value);}
function btn(text, callback, style = "") {
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = text;
  if (style) button.className = style;
  button.addEventListener("click", () => void run(callback));
  return button;
}
async function run(action) {
  if (busy || navigating) return;
  busy = true;
  try {await action();}
  catch(error) { message("Действие не подтверждено: " + (error instanceof Error ? error.message : String(error)));}
  finally {busy = false;}
}
function renderContacts(contacts) {
  knownContacts = contacts.slice();
  const list = el("contacts");
  list.replaceChildren();
  for (const contact of contacts) {
    const li = document.createElement("li");
    const title = document.createElement("strong");
    title.append(textNode(contact.displayName));
    const identity = document.createElement("div");
    identity.className = "identity";
    identity.textContent = contact.peerIdentityId;
    const actions = document.createElement("div");
    actions.className = "actions";
    actions.append(
      btn("Аудиозвонок", () => dial(contact,"audio")),
      btn("Видеозвонок", () => dial(contact,"video")),
      btn("Удалить", async () => {
        await calls.removeContact(contact.id);
        await updateContacts();
      },"secondary"),
    );
    li.append(title,identity,actions);
    list.append(li);
  }
  if (!contacts.length) {
    const li = document.createElement("li");
    li.textContent = "Контактов пока нет. Пригласите знакомого по ссылке или добавьте его код.";
    list.append(li);
  }
}
async function updateContacts() {
  const scope=accountScope, generation=uiAuthGeneration;
  const contacts=await calls.contacts();
  if(!scope || scope!==accountScope || generation!==uiAuthGeneration)return;
  renderContacts(contacts);
}
function nameFor(identity) {
  return knownContacts.find(c => c.peerIdentityId === identity)?.displayName ?? identity;
}
function showActive() {
  const state = el("call-state");
  if (!active) {
    state.textContent = "Нет активного вызова.";
    el("cancel").hidden = true;
    setCallStage(accountScope ? 1 : 0, accountScope ? "Выберите контакт и нажмите «Видеозвонок»." : "Зарегистрируйте первое доверенное устройство.");
    return;
  }
  const remote = active.call.callerIdentityId === active.identity
    ? active.call.calleeIdentityId : active.call.callerIdentityId;
  state.textContent = nameFor(remote) + " — " + active.call.state
    + " (" + (active.call.media === "video" ? "видео" : "аудио") + ")";
  el("cancel").hidden = active.call.state === "terminated";
  if (active.call.state === "active") setCallStage(3, active.call.media === "video" ? "Вызов принят. Проверяем криптографический допуск и открываем видеоэкран…" : "Аудиовызов принят. Проверяем криптографический допуск и открываем экран аудиосвязи…");
  else if (active.call.state === "terminated") setCallStage(1, "Вызов завершён. Выберите контакт для нового звонка.");
  else setCallStage(2, active.call.media === "video" ? "Видеовызов отправлен. Ожидается принятие вторым участником; камера пока выключена." : "Аудиовызов отправлен. Ожидается принятие вторым участником; микрофон пока выключен.");
}
// The first-party /start page is the only owner of PRE-Join MLS creation.
// The existing canonical BFF authorizes every mutation; the browser keeps
// OpenMLS private state in the SAME encrypted IndexedDB store as client.html.
// A Join is never requested until both authenticated endpoints have converged.
const MLS_DB="ucr-endpoint-state-v1",MLS_DB_VERSION=2;
const MLS_SNAPSHOTS="sealed-snapshots",MLS_WRAPPING="wrapping-key-vault";
const MLS_AAD="UCR-ENDPOINT-WRAPPING-KEY-V1\0";
const MLS_MAX_SNAPSHOT=4*1024*1024;
let mlsPreparation=null,mlsModulePromise=null;
function mlsStateKey(user,descriptor){
  const key="ucr-e2ee-state:fp-v1:"+JSON.stringify([
    user.tenantId,user.namespaceId,descriptor.mediaCallId,
    user.participantId,user.deviceId
  ]);
  if(key.length>512)throw Error("Endpoint MLS storage scope too large");
  return key;
}
function mlsDb(){
  return new Promise((resolve,reject)=>{
    const req=indexedDB.open(MLS_DB,MLS_DB_VERSION);
    let settled=false;
    req.onupgradeneeded=()=>{
      if(settled){try{req.transaction?.abort();}catch{}return;}
      if(!req.result.objectStoreNames.contains(MLS_SNAPSHOTS))
        req.result.createObjectStore(MLS_SNAPSHOTS);
      if(!req.result.objectStoreNames.contains(MLS_WRAPPING))
        req.result.createObjectStore(MLS_WRAPPING);
    };
    req.onsuccess=()=>{if(settled){req.result.close();return;}settled=true;resolve(req.result);};
    req.onerror=()=>{if(!settled){settled=true;reject(req.error||Error("MLS IndexedDB open failed"));}};
    req.onblocked=()=>{if(!settled){settled=true;reject(Error("MLS IndexedDB upgrade blocked"));}};
  });
}
async function mlsRecord(store,key,write,record,insertOnly=false){
  const db=await mlsDb();
  try{
    return await new Promise((resolve,reject)=>{
      const tx=db.transaction(store,write?"readwrite":"readonly");
      const object=tx.objectStore(store);
      const req=write?(insertOnly?object.add(record,key):object.put(record,key)):object.get(key);
      let result;
      req.onsuccess=()=>{result=req.result;};
      req.onerror=()=>reject(req.error||Error("MLS IndexedDB request failed"));
      tx.oncomplete=()=>resolve(write?undefined:result??null);
      tx.onerror=()=>reject(req.error||tx.error||Error("MLS IndexedDB transaction failed"));
      tx.onabort=()=>reject(req.error||tx.error||Error("MLS IndexedDB transaction aborted"));
    });
  }finally{db.close();}
}
function mlsBytes(bytes){
  const value=bytes instanceof Uint8Array?bytes:new Uint8Array(bytes);
  if(!value.length||value.length>MLS_MAX_SNAPSHOT)throw Error("Invalid sealed MLS snapshot");
  return value;
}
async function mlsSnapshot(key){
  const record=await mlsRecord(MLS_SNAPSHOTS,key,false);
  return record===null?null:mlsBytes(record).slice();
}
async function mlsSave(key,bytes,first=false){
  await mlsRecord(MLS_SNAPSHOTS,key,true,Array.from(mlsBytes(bytes)),first);
}
// A write-ahead transition record uses the existing sealed-snapshots store.
// No private MLS key is stored in plaintext: the next-epoch snapshot is sealed
// by the same Device-held wrapping key and never sent to the BFF.
async function mlsTransition(key,record){
  const journalKey=key+":pending-commit-v1";
  if(record===undefined)return mlsRecord(MLS_SNAPSHOTS,journalKey,false);
  if(record===null)return mlsRecord(MLS_SNAPSHOTS,journalKey,true,null);
  return mlsRecord(MLS_SNAPSHOTS,journalKey,true,record);
}
function checkedMlsTransition(journal,descriptor){
  if(!journal||journal.version!==1||journal.groupId!==descriptor.groupId||
     !Number.isSafeInteger(journal.epoch)||journal.epoch!==1||
     !Number.isSafeInteger(journal.groupRevision)||journal.groupRevision!==0||
     typeof journal.ref!=="string"||!journal.ref||
     typeof journal.baseRef!=="string"||!journal.baseRef||
     typeof journal.eventId!=="string"||!journal.eventId||
     typeof journal.recipientDeviceId!=="string"||
     typeof journal.recipientSignerKeyId!=="string"||
     typeof journal.recipientKeyPackageBase64Url!=="string"||
     typeof journal.recipientSignatureBase64Url!=="string"||
     !Array.isArray(journal.commit)||!Array.isArray(journal.welcome)||
     !Array.isArray(journal.sealed))
    throw Error("Corrupt pending MLS Commit journal");
  const bounded=(value,max)=>{
    if(value.length===0||value.length>max||
       value.some(byte=>!Number.isInteger(byte)||byte<0||byte>255))
      throw Error("Invalid pending MLS Commit journal bytes");
    return new Uint8Array(value);
  };
  return {
    ...journal,commit:bounded(journal.commit,8192),
    welcome:bounded(journal.welcome,8192),
    sealed:bounded(journal.sealed,MLS_MAX_SNAPSHOT)
  };
}
function mlsWrappingRecord(record){
  if(!record||record.version!==1||record.kek?.type!=="secret"||
     record.kek.extractable!==false||record.kek.algorithm?.name!=="AES-GCM")
    throw Error("Invalid MLS wrapping-key record");
  const iv=new Uint8Array(record.iv),wrapped=new Uint8Array(record.wrapped);
  if(iv.length!==12||wrapped.length<=32)throw Error("Invalid MLS wrapping-key ciphertext");
  return {...record,iv,wrapped};
}
async function mlsWrappingKey(key,{requireExisting=false}={}){
  let record=await mlsRecord(MLS_WRAPPING,key,false);
  if(record===null){
    if(requireExisting)throw Error("Existing MLS snapshot has no wrapping key");
    const kek=await crypto.subtle.generateKey({name:"AES-GCM",length:256},false,["encrypt","decrypt"]);
    const candidate=crypto.getRandomValues(new Uint8Array(32));
    const iv=crypto.getRandomValues(new Uint8Array(12));
    try{
      const wrapped=new Uint8Array(await crypto.subtle.encrypt({
        name:"AES-GCM",iv,additionalData:new TextEncoder().encode(MLS_AAD+key)
      },kek,candidate));
      try{
        await mlsRecord(MLS_WRAPPING,key,true,{
          version:1,kek,iv:Array.from(iv),wrapped:Array.from(wrapped)
        },true);
        return candidate.slice();
      }catch(error){
        if(error?.name!=="ConstraintError")throw error;
      }
    }finally{candidate.fill(0);}
    record=await mlsRecord(MLS_WRAPPING,key,false);
    if(record===null)throw Error("Concurrent MLS key creation lost committed winner");
  }
  const saved=mlsWrappingRecord(record);
  const result=new Uint8Array(await crypto.subtle.decrypt({
    name:"AES-GCM",iv:saved.iv,additionalData:new TextEncoder().encode(MLS_AAD+key)
  },saved.kek,saved.wrapped));
  if(result.length!==32||result.every(byte=>byte===0))
    throw Error("Invalid recovered MLS wrapping key");
  return result;
}
async function mlsWasm(){
  if(!mlsModulePromise)mlsModulePromise=(async()=>{
    const module=await import("/endpoint-wasm/ucr_endpoint_wasm.js");
    if(typeof module.default!=="function"||
       typeof module.EndpointMlsState!=="function"||
       typeof module.endpoint_wasm_contract_version!=="function")
      throw Error("Endpoint-owned OpenMLS WASM package unavailable");
    await module.default();
    if(module.endpoint_wasm_contract_version()!=="ucr.endpoint-wasm.v1")
      throw Error("Endpoint-owned OpenMLS WASM contract unavailable");
    return module;
  })().catch(error=>{mlsModulePromise=null;throw error;});
  return mlsModulePromise;
}
async function prepareFirstPartyEndpointMls(callId,selectedScope,locator){
  const selected=active;
  const check=async()=>{
    if(navigating||accountScope!==selectedScope||!active||
       active.terminating||active.call.callId!==callId||
       active.call.state!=="active"||activeCallLocator()!==locator)
      throw Error("MLS preparation cancelled by Call withdrawal");
    const user=await host.resumeAuthenticatedDevice();
    if(principalScope(user)!==selectedScope)
      throw Error("MLS preparation cancelled by Device change");
    const call=await calls.inspect(callId);
    if(call.state!=="active"||call.callId!==callId)
      throw Error("MLS preparation cancelled by canonical Call");
    return {user,call};
  };
  const initial=await check();
  const user=initial.user,call=initial.call;
  const request={callId,expectedRevision:call.revision};
  const descriptor=await host.describeAcceptedCallMls(user,request);
  await check();
  if(descriptor.callId!==callId||descriptor.deviceId!==user.deviceId||
     descriptor.requiresEndpointOwnedCommit!==true)
    throw Error("Untrusted first-party MLS descriptor");
  const creator=descriptor.creatorPrincipalId===user.participantId;
  const key=mlsStateKey(user,descriptor);
  const operation=async()=>{
    const module=await mlsWasm();
    let state=null;
    let sealed=await mlsSnapshot(key);
    let wrapping=null;
    try{
      wrapping=await mlsWrappingKey(key,{requireExisting:sealed!==null});
      await check();
      if(creator){
        // Recover the exact already-staged wire after uncertain server ACK,
        // crash, or failed local promotion. Never stage a second random Commit.
        const rawJournal=await mlsTransition(key);
        if(rawJournal!==null){
          const journal=checkedMlsTransition(rawJournal,descriptor);
          if(descriptor.cryptoEpoch===0 &&
             descriptor.groupRevision===journal.groupRevision &&
             descriptor.cryptoStateRef===journal.baseRef){
            await check();
            await host.addEndpointMlsPeer(user,{
              ...request,groupRevision:journal.groupRevision,
              eventId:journal.eventId,cryptoEpoch:journal.epoch,
              cryptoStateRef:journal.ref,
              recipientDeviceId:journal.recipientDeviceId,
              recipientSignerKeyId:journal.recipientSignerKeyId,
              recipientKeyPackageBase64Url:journal.recipientKeyPackageBase64Url,
              recipientSignatureBase64Url:journal.recipientSignatureBase64Url,
              commit:journal.commit,welcome:journal.welcome
            });
            await check();
          }else if(descriptor.cryptoEpoch!==journal.epoch ||
                   descriptor.cryptoStateRef!==journal.ref){
            throw Error("Canonical MLS epoch conflicts with pending Commit; media fenced");
          }
          const canonical=await host.describeAcceptedCallMls(user,request);
          await check();
          if(canonical.cryptoEpoch!==journal.epoch||
             canonical.cryptoStateRef!==journal.ref||
             canonical.expectedPeerDeviceId!==journal.recipientDeviceId)
            throw Error("Pending MLS Commit not canonically confirmed; media fenced");
          // Validate sealed new epoch locally before replacing the old snapshot.
          state=module.EndpointMlsState.restore(user.tenantId,user.namespaceId??undefined,
            descriptor.groupId,user.deviceId,wrapping,journal.sealed,
            BigInt(journal.epoch),journal.ref);
          state.authorize_direct_call_roster(journal.recipientDeviceId);
          await mlsSave(key,journal.sealed);
          await mlsTransition(key,null);
          sealed=journal.sealed;
          return true;
        }
        if(descriptor.cryptoEpoch===null){
          if(sealed===null){
            state=new module.EndpointMlsState(user.tenantId,user.namespaceId??undefined,
              descriptor.groupId,user.deviceId);
            state.create_endpoint_group();
            // Seal the creator's epoch-zero Group in a distinct AAD domain
            // BEFORE publishing. A lost HTTP acknowledgement must not mint
            // another MLS identity or permanently strand the first Group.
            await mlsSave(key,state.seal_unpublished_group(wrapping),true);
          }else{
            state=module.EndpointMlsState.restore_unpublished_group(
              user.tenantId,user.namespaceId??undefined,descriptor.groupId,
              user.deviceId,wrapping,sealed);
          }
          await check();
          await host.publishEndpointMlsGroup(user,{
            ...request,cryptoStateRef:state.crypto_state_ref()
          });
          await check();
          // A recipient's independently signed offer may arrive later.
          return false;
        }
        if(sealed===null)throw Error("Initiator's private OpenMLS snapshot is missing");
        if(descriptor.cryptoEpoch===0){
          // An accepted epoch-zero publication may have lost its HTTP reply
          // or crashed before local promotion. Recover the SAME sealed Group,
          // verify the canonical digest, then atomically promote the snapshot.
          let unpublished=false;
          try{
            state=module.EndpointMlsState.restore(user.tenantId,user.namespaceId??undefined,
              descriptor.groupId,user.deviceId,wrapping,sealed,
              0n,descriptor.cryptoStateRef);
          }catch{
            state=module.EndpointMlsState.restore_unpublished_group(
              user.tenantId,user.namespaceId??undefined,descriptor.groupId,
              user.deviceId,wrapping,sealed);
            unpublished=true;
          }
          if(state.crypto_state_ref()!==descriptor.cryptoStateRef)
            throw Error("Published MLS epoch-zero digest differs from local Group");
          if(unpublished){
            await mlsSave(key,state.seal_snapshot(wrapping));
            await check();
          }
        }else{
          state=module.EndpointMlsState.restore(user.tenantId,user.namespaceId??undefined,
            descriptor.groupId,user.deviceId,wrapping,sealed,
            BigInt(descriptor.cryptoEpoch),descriptor.cryptoStateRef);
        }
        if(descriptor.cryptoEpoch===0){
          const offers=await host.listEndpointMlsOffers(user,request);
          await check();
          if(offers.length===0)return false;
          if(offers.length!==1||offers[0].recipientDeviceId===user.deviceId)
            throw Error("Ambiguous authenticated MLS recipient offer");
          const offer=offers[0];
          const packageBytes=Uint8Array.from(atob(
            offer.recipientKeyPackageBase64Url.replace(/-/g,"+").replace(/_/g,"/")+
            "=".repeat((4-offer.recipientKeyPackageBase64Url.length%4)%4)
          ),ch=>ch.charCodeAt(0));
          const commit=state.stage_add_device(offer.recipientDeviceId,packageBytes);
          const epoch=Number(state.pending_epoch()),stateRef=state.pending_state_ref();
          const welcome=state.pending_welcome();
          // Merge locally only to prepare a sealed next-epoch checkpoint.
          // Media remains fenced until the canonical server CAS is verified.
          state.merge_endpoint_transition(BigInt(epoch),stateRef);
          const journal=checkedMlsTransition({
            version:1,groupId:descriptor.groupId,groupRevision:descriptor.groupRevision,
            baseRef:descriptor.cryptoStateRef,eventId:crypto.randomUUID(),epoch,ref:stateRef,
            recipientDeviceId:offer.recipientDeviceId,
            recipientSignerKeyId:offer.recipientSignerKeyId,
            recipientKeyPackageBase64Url:offer.recipientKeyPackageBase64Url,
            recipientSignatureBase64Url:offer.recipientSignatureBase64Url,
            commit:Array.from(commit),welcome:Array.from(welcome),
            sealed:Array.from(state.seal_snapshot(wrapping))
          },descriptor);
          // Durable journal FIRST. If this fails, nothing is sent to server.
          await mlsTransition(key,{...journal,
            commit:Array.from(journal.commit),welcome:Array.from(journal.welcome),
            sealed:Array.from(journal.sealed)});
          await check();
          await host.addEndpointMlsPeer(user,{
            ...request,groupRevision:journal.groupRevision,
            eventId:journal.eventId,cryptoEpoch:journal.epoch,cryptoStateRef:journal.ref,
            recipientDeviceId:journal.recipientDeviceId,
            recipientSignerKeyId:journal.recipientSignerKeyId,
            recipientKeyPackageBase64Url:journal.recipientKeyPackageBase64Url,
            recipientSignatureBase64Url:journal.recipientSignatureBase64Url,
            commit:journal.commit,welcome:journal.welcome
          });
          const canonical=await host.describeAcceptedCallMls(user,request);
          await check();
          if(canonical.cryptoEpoch!==epoch||canonical.cryptoStateRef!==stateRef||
             canonical.expectedPeerDeviceId!==offer.recipientDeviceId)
            throw Error("Server did not confirm the staged MLS Commit");
          await mlsSave(key,journal.sealed);
          await mlsTransition(key,null);
          await check();
        }
      }else{
        // The durable public offer has a foreign key to the canonical Group:
        // never publish before the initiator's signed epoch-zero creation.
        if(descriptor.cryptoEpoch===null)return false;
        if(sealed===null){
          if(descriptor.cryptoEpoch!==0)
            throw Error("Recipient KeyPackage missing after canonical MLS admission");
          state=new module.EndpointMlsState(user.tenantId,user.namespaceId??undefined,
            descriptor.groupId,user.deviceId);
          await mlsSave(key,state.seal_unjoined_key_package(wrapping),true);
          sealed=await mlsSnapshot(key);
          await check();
        }
        if(descriptor.cryptoEpoch===0){
          if(!state)state=module.EndpointMlsState.restore_unjoined_key_package(
            user.tenantId,user.namespaceId??undefined,descriptor.groupId,
            user.deviceId,wrapping,sealed);
          // Idempotent retry of the EXACT SAME signed KeyPackage. A failed
          // first HTTP response must not strand a durable pending offer.
          await host.publishEndpointMlsOffer(user,{
            ...request,keyPackage:new Uint8Array(state.key_package())
          });
          await check();
          return false;
        }
        try{
          state=module.EndpointMlsState.restore(user.tenantId,user.namespaceId??undefined,
            descriptor.groupId,user.deviceId,wrapping,sealed,
            BigInt(descriptor.cryptoEpoch),descriptor.cryptoStateRef);
        }catch{
          state=module.EndpointMlsState.restore_unjoined_key_package(
            user.tenantId,user.namespaceId??undefined,descriptor.groupId,
            user.deviceId,wrapping,sealed);
          const bootstrap=await host.fetchEndpointMlsBootstrap(user,request);
          await check();
          if(bootstrap.groupId!==descriptor.groupId||
             bootstrap.cryptoEpoch!==descriptor.cryptoEpoch||
             bootstrap.cryptoStateRef!==descriptor.cryptoStateRef)
            throw Error("Canonical MLS Welcome does not match accepted Call");
          state.join_from_welcome(bootstrap.welcome,BigInt(bootstrap.welcomeEpoch),
            bootstrap.welcomeStateRef);
          for(const item of bootstrap.commits)
            state.process_commit(item.commit,BigInt(item.cryptoEpoch),item.cryptoStateRef);
          if(Number(state.crypto_epoch())!==descriptor.cryptoEpoch||
             state.crypto_state_ref()!==descriptor.cryptoStateRef)
            throw Error("Recipient OpenMLS epoch differs from canonical admission");
          await mlsSave(key,state.seal_snapshot(wrapping));
          await check();
        }
      }
      const committed=await host.describeAcceptedCallMls(user,request);
      await check();
      if(committed.cryptoEpoch===null||committed.cryptoEpoch<1||
         !committed.expectedPeerDeviceId||
         committed.expectedPeerDeviceId===user.deviceId||
         committed.groupId!==descriptor.groupId||
         committed.cryptoEpoch!==Number(state.crypto_epoch())||
         committed.cryptoStateRef!==state.crypto_state_ref())
        return false;
      state.authorize_direct_call_roster(committed.expectedPeerDeviceId);
      return true;
    }finally{
      if(wrapping)wrapping.fill(0);
      if(state&&typeof state.free==="function")state.free();
    }
  };
  // Serialize competing same-origin tabs. No second Call, Identity or key
  // authority: this lock only fences local encrypted MLS snapshot updates.
  if(!navigator.locks?.request)
    throw Error("Cross-tab MLS persistence lock unavailable; refusing unsafe Join");
  return navigator.locks.request("ucr-first-party-mls:"+key,{mode:"exclusive"},operation);
}

async function beginMedia(callId) {
  if (navigating) return;
  // A signed Join is valid only for the still-selected accepted Call/Device.
  // A late grant must never navigate away from a newer or ended Call.
  const selected = active;
  if (!selected || selected.terminating || selected.call.callId !== callId ||
      selected.call.state !== "active") return;
  const selectedScope = accountScope;
  const selectedGeneration = uiAuthGeneration;
  const selectedLocator = activeCallLocator();
  // This coordinator permits Join ONLY after the recipient has accepted
  // and the canonical owner reports ACTIVE. It never creates trust or keys.
  // A real endpoint-owned MLS group and the recipient's independently
  // authenticated KeyPackage/Welcome MUST precede any signed Join.
  if(mlsPreparation)return;
  const preparation=prepareFirstPartyEndpointMls(callId,selectedScope,selectedLocator);
  mlsPreparation=preparation;
  let mlsReady;
  try{mlsReady=await preparation;}
  finally{if(mlsPreparation===preparation)mlsPreparation=null;}
  if(!mlsReady)return;
  // A slow MLS preflight can outlive Hangup or a Device switch. Revalidate
  // immediately before the irreversible signed Join request.
  if(navigating||accountScope!==selectedScope||!active||
     active.terminating||active.call.callId!==callId||
     active.call.state!=="active"||activeCallLocator()!==selectedLocator)return;
  const grant = await calls.join(callId);
  if (!grant || grant.callId !== callId) throw Error("Call admission mismatch");
  // Periodic inspection may replace the object for the SAME active Call.
  // Fence by canonical Call/Device state, not mutable UI object identity.
  if (navigating || uiAuthGeneration !== selectedGeneration ||
      accountScope !== selectedScope || !active ||
      active.terminating || active.call.callId !== callId ||
      active.call.state !== "active" ||
      activeCallLocator() !== selectedLocator) return;
  navigating = true;
  setCallStage(3, active?.call.media === "video" ? "Допуск подтверждён. Открывается защищённый видеоэкран…" : "Допуск подтверждён. Открывается защищённый экран аудиосвязи…");
  clearInterval(timer);
  const next = new URL("/client.html",location.origin);
  // The signed media Join names the derived Group Call. Preserve only the
  // accepted canonical Direct Call id for independently authenticated renewal.
  sessionStorage.setItem("ucrFirstPartyDirectCall", callId);
  next.hash = grant.joinFragment.slice(1);
  location.replace(next.href);
}
async function dial(contact,media) {
  if (active && active.call.state !== "terminated") {
    throw Error("сначала завершите текущий вызов");
  }
  // If a reload's canonical inspection failed transiently, a pending Call
  // may still be ringing. Do not create a second Call before it is resolved.
  if (activeCallLocator() !== null) {
    throw Error("сначала дождитесь проверки или завершите незавершённый вызов");
  }
  const key = contact.id + ":" + media;
  const requestId = idempotency.get(key) ?? crypto.randomUUID();
  idempotency.set(key,requestId);
  message("Соединяем с собеседником…");
  // Re-establish device authority before making an irreversible canonical Call.
  // A stale cookie must not create a Call which the UI then fails to display.
  const scope=accountScope, generation=uiAuthGeneration;
  const session = await restoreSession();
  if(!scope || scope!==accountScope || generation!==uiAuthGeneration ||
     principalScope(session)!==scope)throw Error("Device changed before Call creation");
  const call = await calls.start(contact.id,media,requestId);
  // The Call owner may have committed before a concurrent logout/revocation.
  // Never repaint that stale Call under a new or unauthenticated Device.
  if(scope!==accountScope || generation!==uiAuthGeneration)
    throw Error("Device changed during Call creation; inspect the prior Call before retry");
  active = {call,identity:session.participantId};
  rememberActiveCall(call,session.participantId);
  showActive();
  message("Вызов создан. Ожидается реальное принятие другим участником.");
}
function renderIncoming(items) {
  const list = el("incoming");
  list.replaceChildren();
  for (const call of items) {
    const li = document.createElement("li");
    const heading = document.createElement("strong");
    heading.textContent = nameFor(call.callerIdentityId);
    const description = document.createElement("div");
    description.className = "identity";
    description.textContent = "Входящий " + (call.media==="video" ? "видеовызов" : "аудиовызов")
      + " — " + call.callId;
    const actions = document.createElement("div");
    actions.className = "actions";
    actions.append(
      btn("Принять",async () => {
        const scope=accountScope, generation=uiAuthGeneration;
        const locator=activeCallLocator();
        if(!scope)throw Error("Требуется подтверждённая Device-сессия");
        if (active && active.call.state !== "terminated") throw Error("вы уже участвуете в другом вызове");
        if (locator !== null) throw Error("сначала дождитесь проверки незавершённого вызова");
        const result = await calls.signal(call.callId,"accept");
        if (!result || result.callId !== call.callId) throw Error("Call acceptance mismatch");
        // The server may have accepted this Call, but an old UI callback may
        // never install it under a new (even same-Device) login generation.
        if(accountScope!==scope || uiAuthGeneration!==generation ||
           activeCallLocator()!==locator || (active && active.call.state!=="terminated"))return;
        const session = await host.resumeAuthenticatedDevice();
        if(principalScope(session)!==scope)throw Error("Device changed during Call acceptance");
        if(accountScope!==scope || uiAuthGeneration!==generation ||
           activeCallLocator()!==locator || (active && active.call.state!=="terminated"))return;
        active = {call:result,identity:session.participantId};
        rememberActiveCall(result,session.participantId);
        showActive();
        if (result.state === "active") await beginMedia(result.callId);
      }),
      btn("Отклонить",async () => {
        await calls.signal(call.callId,"reject");
        await refresh();
      },"secondary"),
    );
    li.append(heading,description,actions);
    list.append(li);
  }
  if (!items.length) {
    const li = document.createElement("li");
    li.textContent = "Нет подтверждённых входящих вызовов.";
    list.append(li);
  }
}
async function refresh() {
  if (refreshing || navigating) return;
  // A response from an older login generation must not clear or overwrite a
  // newly authenticated Device, even when the server returns a late 401.
  const refreshScope=accountScope, refreshGeneration=uiAuthGeneration;
  refreshing = true;
  try {
    let user;
    try {
      user = await restoreSession();
    } catch (error) {
      if(refreshScope!==accountScope || refreshGeneration!==uiAuthGeneration)return;
      // Only an authorization/trust failure invalidates the visible identity.
      // Temporary network, rate-limit and 5xx failures keep the periodic
      // retry alive; no new Call/Join can succeed without server admission.
      const code=authHttpCode(error);
      if(!(error instanceof TypeError || [429,500,502,503].includes(code))){
        plClearAuthenticatedView();
      }
      throw error;
    }
    if(refreshScope!==accountScope || refreshGeneration!==uiAuthGeneration)return;
    if (accountScope !== principalScope(user)) {
      // Another tab may have changed Identity/Device while the UI was open.
      forgetActiveCall();
      plClearAuthenticatedView();
      throw Error("учётная запись сменилась — требуется повторная проверка");
    }
    if (!active) await restoreActiveCall(user);
    const verifiedGeneration=uiAuthGeneration;
    const incoming = await authTrace("incoming_calls",()=>calls.incoming());
    // Never paint a former Identity's incoming Calls after logout or Device switch.
    if (accountScope !== principalScope(user) ||
        uiAuthGeneration!==verifiedGeneration || navigating) return;
    renderIncoming(incoming);
    if (active) {
      // Snapshot the exact Call and Device generation before the async read.
      // A concurrent dial, accept, hangup, logout or replacement locator
      // must not be overwritten by a late response for the previous Call.
      const inspected = active;
      const inspectedCall = inspected.call;
      const inspectedScope = accountScope;
      const inspectedLocator = activeCallLocator();
      const fresh = await authTrace("inspect_call",()=>calls.inspect(inspectedCall.callId));
      if (accountScope !== inspectedScope || active !== inspected ||
          active.call !== inspectedCall ||
          activeCallLocator() !== inspectedLocator || navigating) return;
      if (fresh.callId !== inspectedCall.callId) throw Error("Call inspection mismatch");
      active = {...inspected,call:fresh};
      showActive();
      if (fresh.state === "active") await beginMedia(fresh.callId);
      if (fresh.state === "terminated") {
        forgetActiveCall(inspectedLocator);
        if (active.identity === fresh.callerIdentityId) clearRetryKey(fresh);
        message("Вызов завершён сервером. Старая сессия больше не используется.");
      }
    }
  } finally {refreshing = false;}
}
async function initialize() {
  authDiagnostic("initialization","started");
  clearInterval(timer);
  message("Проверяем защищённый вход…");
  const user = await restoreSession();
  rememberBinding(user);
  const currentScope = principalScope(user);
  if (accountScope !== currentScope) {
    if (accountScope !== null) forgetActiveCall();
    // Switching user or Device must never reuse another identity's selected
    // Call, cached UI state, or in-flight idempotency keys.
    uiAuthGeneration++;
    accountScope = currentScope;
    knownContacts = [];
    idempotency.clear();
    active = null;
    showActive();
    renderIncoming([]);
    renderContacts([]);
  }
  // A successful canonical Device sign-in is independent of auxiliary
  // contacts/devices reads. Do not leave a registered user on the signup screen.
  el("who").textContent = "Устройство подтверждено";
  plSetSignedIn(user.participantId);
  const optionalErrors=[];
  try {await authTrace("list_contacts",()=>updateContacts());}
  catch(error) {optionalErrors.push("контакты");renderContacts([]);}
  try {await authTrace("list_devices",()=>updateDevices());}
  catch(error) {optionalErrors.push("устройства");el("devices").replaceChildren();}
  if(optionalErrors.length)message("Вы вошли. Временно не удалось загрузить: "+
    optionalErrors.join(", ")+". Повторите проверку входа.");
  // Successful device reauthentication is independent from Call state.
  // A malformed/stale canonical Call must not invalidate a trusted Device.
  message("Доверенное устройство подтверждено. Проверяем состояние вызовов…");
  try {
    await refresh();
    message("Устройство подтверждено. Входящие звонки проверяются.");
  } catch (error) {
    message("Устройство подтверждено; проверка вызовов завершилась ошибкой: " +
      (error instanceof Error ? error.message : String(error)));
  }
  timer = setInterval(() => {
    if (busy || navigating || document.hidden) return;
    void refresh().catch(err => {
      authDiagnostic("periodic_refresh","failed",err);
      // Retain the authenticated device and keep polling rather than requiring
      // fresh registration. Do not bypass server-side Call authority.
      message("Устройство авторизовано; ошибка проверки вызовов: " +
        (err instanceof Error ? err.message : String(err)));
    });
  },2500);
}
el("device-login").addEventListener("submit", event => {
  event.preventDefault();
  void run(async () => {
    const binding = {
      tenantId:el("login-tenant").value.trim(),
      namespaceId:el("login-namespace").value.trim() || null,
      participantId:el("login-identity").value.trim(),
      deviceId:el("login-device").value.trim(),
    };
    message("Проверка владения существующим защищённым Device…");
    const verified = await authTrace("device_reauthentication",()=>authenticateUcrFirstPartyDevice(vault,{
      origin:location.origin,
    },binding));
    if (principalScope(verified)!==principalScope(binding)) {
      throw Error("сервер вернул другую Identity или Device");
    }
    rememberBinding(verified);
    await initialize();
  });
});
// A manual retry must be visible immediately, even when another action is busy.
// The existing init lock prevents duplicate requests; explain this next to the button.
el("retry").addEventListener("click",() => {
  const control = el("retry");
  control.textContent = busy ? "Проверка уже выполняется…" : "Проверяем вход…";
  control.disabled = true;
  message(busy ? "Проверка входа уже выполняется. Дождитесь результата." : "Повторная проверка защищённого устройства…");
  if (busy || navigating) {
    control.disabled = false;
    control.textContent = "Повторить проверку входа";
    return;
  }
  void run(initialize).finally(() => {
    control.disabled = false;
    control.textContent = "Повторить проверку входа";
  });
});
el("new-contact").addEventListener("submit", event => {
  event.preventDefault();
  void run(async () => {
    const name = el("contact-name").value.trim();
    const peer = el("contact-peer").value.trim();
    if(!accountScope || !plOwnIdentity)throw Error("Сначала войдите в свой профиль.");
    if(peer===plOwnIdentity)throw Error("Нельзя добавить собственный профиль.");
    if(knownContacts.some(contact=>contact.peerIdentityId===peer)){
      throw Error("Этот человек уже добавлен в контакты.");
    }
    await calls.addContact(name,peer);
    el("new-contact").reset();
    delete el("contact-peer").dataset.invitedContact;
    el("pl-invite-help").hidden=true;
    // Never retain the unverified invitation locator in a shareable URL.
    if(new URLSearchParams(location.search).has("contact")){
      const clean=new URL(location.href);
      clean.searchParams.delete("contact");
      history.replaceState(null,"",clean.href);
    }
    await updateContacts();
    message("Контакт добавлен. Теперь выберите аудио- или видеозвонок.");
  });
});
// Mark termination before the network request: an in-flight refresh or signed
// Join must never publish media after the user has requested hangup/cancel.
async function terminateActiveCall() {
  if (!active || active.terminationInFlight || active.call.state === "terminated") return;
  const selected = active;
  const callId = selected.call.callId;
  const scope = accountScope;
  const state = selected.call.state;
  const action = state === "active" || state === "reconnecting" ? "hangup" : "cancel";
  // A transport failure leaves the server outcome unknown. Preserve the
  // stop intent across retries and periodic Call inspection; never resume
  // signed Join or media merely because a network request failed.
  selected.terminating = true;
  const locator = rememberStopIntent(callId);
  selected.terminationInFlight = true;
  try {
    const result = await calls.signal(callId,action);
    if (!result || result.callId !== callId) throw Error("Call termination mismatch");
    // An old response must not replace a newer Call or mutate another Device.
    if (accountScope !== scope || !active || active.call.callId !== callId ||
        activeCallLocator() !== locator) return;
    active = {...active,call:result,
      terminating:result.state !== "terminated",terminationInFlight:false};
    if (result.state === "terminated") {
      forgetActiveCall(locator);
      if (active.identity === result.callerIdentityId) clearRetryKey(result);
    }
    showActive();
    message(result.state === "terminated"
      ? "Завершение вызова подтверждено каноническим сервером."
      : "Завершение ещё не подтверждено. Медиа заблокировано; повторите действие.");
  } finally {
    // Clear only the in-flight lock. A failed/ambiguous response MUST NOT
    // clear the user's stop fence; the button remains available for retry.
    if (accountScope === scope && active && active.call.callId === callId &&
        activeCallLocator() === locator) active.terminationInFlight = false;
  }
}
// Hangup must bypass the ordinary UI busy lock: accepting an incoming Call
// holds that lock while its signed Join is still in flight. A user click must
// fence that Join immediately rather than being silently discarded.
el("cancel").addEventListener("click", () => {
  void terminateActiveCall().catch(error => {
    message("Действие не подтверждено: " +
      (error instanceof Error ? error.message : String(error)));
  });
});

el("signup").addEventListener("click",()=>void run(async()=>{
  message("Создаём защищённый профиль…");
  const result=await registerUcrFirstPartyUser(vault,{origin:location.origin});
  showRecovery(result.recoveryCode);
  el("login-tenant").value=result.binding.tenantId;
  el("login-identity").value=result.binding.participantId;
  el("login-device").value=result.binding.deviceId;
  rememberBinding(result.binding);
  await initialize();
}));
el("recover-form").addEventListener("submit",event=>{
  event.preventDefault();
  void run(async()=>{
    const result=await recoverUcrFirstPartyDevice(vault,{origin:location.origin},
      el("recover-identity").value.trim(),el("recover-code").value.trim());
    el("recover-code").value="";
    showRecovery(result.recoveryCode);
    el("login-tenant").value=result.binding.tenantId;
    el("login-identity").value=result.binding.participantId;
    el("login-device").value=result.binding.deviceId;
    rememberBinding(result.binding);
    await initialize();
  });
});
el("copy-recovery").addEventListener("click",()=>void run(async()=>{
  await navigator.clipboard.writeText(el("recovery-code").value);
  message("Код скопирован. Сохраните его в защищённом месте.");
}));
el("rotate-recovery").addEventListener("click",()=>void run(async()=>{
  const code=await host.rotateRecoveryCode();
  showRecovery(code);
}));
el("logout").addEventListener("click",()=>void run(async()=>{
  // Immediately stop local Call/Join admission. Waiting for HTTP logout
  // could let a previously requested signed Join open media after this click.
  forgetBinding();
  forgetActiveCall();
  plClearAuthenticatedView();
  await host.logout();
  el("who").textContent="Вы вышли из учётной записи.";
  message("Серверная сессия закрыта. Приватный ключ остаётся на устройстве для повторного входа.");
}));

// Mobile tabs become hidden during permission prompts and app switching.
// Catch up immediately on foreground instead of waiting for the next interval.
document.addEventListener("visibilitychange",()=>{
  if(document.hidden || !accountScope || navigating || busy)return;
  void refresh().catch(error=>{
    authDiagnostic("periodic_refresh","failed",error);
    message("Не удалось обновить состояние звонков. Повторите проверку входа.");
  });
});
window.addEventListener("pagehide", () => clearInterval(timer));
function explainEntryFailure(error) {
  // A committed signup/recovery can fail to obtain a session under capacity.
  // Hide stale identity data, but retain the one-time recovery credential.
  plClearAuthenticatedView(true);
  const detail = error instanceof Error ? error.message : String(error);
  let hint = "Войдите с доверенного устройства, создайте учётную запись или восстановите доступ.";
  if (/HTTP 503/.test(detail)) hint = "Сервер входа не подключён: запустите first-party BFF.";
  else if (/HTTP 403/.test(detail)) hint = "Origin не совпадает с публичным HTTPS-адресом сервера.";
  else if (location.protocol !== "https:") hint += " Для защищённой сессии нужен HTTPS.";
  el("who").textContent = "Нет подтверждённой сессии. " + hint;
}
void (async () => {
  if (busy || navigating) return;
  busy = true;
  try { await initialize(); }
  catch (error) {
    explainEntryFailure(error);
    message("Действие не подтверждено: " + (error instanceof Error ? error.message : String(error)));
  }
  finally { busy = false; }
})();
