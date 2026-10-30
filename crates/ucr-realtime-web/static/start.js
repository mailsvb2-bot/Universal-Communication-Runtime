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
  try {return await authTrace("resume_session",()=>host.resumeAuthenticatedDevice());}
  catch(error) {
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
  if (!hint || typeof hint!=="object" || hint.scope!==scope ||
      accountScope!==scope || typeof hint.callId!=="string" ||
      !/^[A-Za-z0-9_.:@-]{1,128}$/.test(hint.callId)) {
    forgetActiveCall(locator);return;
  }
  try {
    const call=await calls.inspect(hint.callId);
    // Inspect checks current canonical participant, Device and Call membership.
    // A delayed response cannot restore a Call after account/Device switch.
    if (accountScope!==scope) {forgetActiveCall(locator);return;}
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
  const records = await host.listDevices();
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
        if(own){forgetBinding();forgetActiveCall();clearInterval(timer);active=null;accountScope=null;
          renderContacts([]);renderIncoming([]);showActive();message("Это устройство отозвано. Повторный вход с ним невозможен.");
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
async function updateContacts() {renderContacts(await calls.contacts());}
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
async function beginMedia(callId) {
  if (navigating) return;
  // A signed Join is valid only for the still-selected accepted Call/Device.
  // A late grant must never navigate away from a newer or ended Call.
  const selected = active;
  if (!selected || selected.terminating || selected.call.callId !== callId ||
      selected.call.state !== "active") return;
  const selectedScope = accountScope;
  const selectedLocator = activeCallLocator();
  // This coordinator permits Join ONLY after the recipient has accepted
  // and the canonical owner reports ACTIVE. It never creates trust or keys.
  const grant = await calls.join(callId);
  if (!grant || grant.callId !== callId) throw Error("Call admission mismatch");
  // Periodic inspection may replace the object for the SAME active Call.
  // Fence by canonical Call/Device state, not mutable UI object identity.
  if (navigating || accountScope !== selectedScope || !active ||
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
  const session = await restoreSession();
  const call = await calls.start(contact.id,media,requestId);
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
        if (active && active.call.state !== "terminated") throw Error("вы уже участвуете в другом вызове");
        if (activeCallLocator() !== null) throw Error("сначала дождитесь проверки незавершённого вызова");
        const result = await calls.signal(call.callId,"accept");
        const session = await host.resumeAuthenticatedDevice();
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
  refreshing = true;
  try {
    let user;
    try {
      user = await restoreSession();
    } catch (error) {
      // A missing/revoked cookie or failed trust recheck must not leave a
      // previously authenticated cabinet and invitation visible. Transient
      // errors also fail closed; manual retry performs fresh authentication.
      plClearAuthenticatedView();
      throw error;
    }
    if (accountScope !== principalScope(user)) {
      // Another tab may have changed Identity/Device while the UI was open.
      forgetActiveCall();
      plClearAuthenticatedView();
      throw Error("учётная запись сменилась — требуется повторная проверка");
    }
    if (!active) await restoreActiveCall(user);
    const incoming = await authTrace("incoming_calls",()=>calls.incoming());
    // Never paint a former Identity's incoming Calls after logout or Device switch.
    if (accountScope !== principalScope(user) || navigating) return;
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
  await host.logout();
  forgetBinding();
  forgetActiveCall();
  plClearAuthenticatedView();
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
