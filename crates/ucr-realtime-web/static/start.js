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
async function restoreSession() {
  try {return await host.resumeAuthenticatedDevice();}
  catch(error) {
    const hint=lastBinding();
    if(!hint)throw error;
    // Only a real protected, previously registered signer may re-login.
    // If the server revoked this Device, do not turn the hint into trust.
    const verified=await authenticateUcrFirstPartyDevice(
      vault,{origin:location.origin},hint);
    if(principalScope(verified)!==principalScope(hint)){
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
        if(own){forgetBinding();clearInterval(timer);active=null;accountScope=null;
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
    li.textContent = "Добавьте контакт с проверенным Identity ID.";
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
  // This coordinator permits Join ONLY after the recipient has accepted
  // and the canonical owner reports ACTIVE. It never creates trust or keys.
  const grant = await calls.join(callId);
  if (!grant || grant.callId !== callId) throw Error("Call admission mismatch");
  navigating = true;
  setCallStage(3, active?.call.media === "video" ? "Допуск подтверждён. Открывается защищённый видеоэкран…" : "Допуск подтверждён. Открывается защищённый экран аудиосвязи…");
  clearInterval(timer);
  const next = new URL("/client.html",location.origin);
  next.hash = grant.joinFragment.slice(1);
  location.replace(next.href);
}
async function dial(contact,media) {
  if (active && active.call.state !== "terminated") {
    throw Error("сначала завершите текущий вызов");
  }
  const key = contact.id + ":" + media;
  const requestId = idempotency.get(key) ?? crypto.randomUUID();
  idempotency.set(key,requestId);
  message("Проверка Device и создание канонического вызова…");
  // Re-establish device authority before making an irreversible canonical Call.
  // A stale cookie must not create a Call which the UI then fails to display.
  const session = await restoreSession();
  const call = await calls.start(contact.id,media,requestId);
  active = {call,identity:session.participantId};
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
        const result = await calls.signal(call.callId,"accept");
        const session = await host.resumeAuthenticatedDevice();
        active = {call:result,identity:session.participantId};
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
    const user = await restoreSession();
    if (accountScope !== principalScope(user)) {
      // Fail closed immediately if the user logs out or changes Device in
      // another tab. Never keep the former user's contacts/Call on screen.
      clearInterval(timer);
      accountScope = null;
      active = null;
      knownContacts = [];
      idempotency.clear();
      renderContacts([]);
      renderIncoming([]);
      showActive();
      throw Error("учётная запись сменилась — требуется повторная проверка");
    }
    const incoming = await calls.incoming();
    renderIncoming(incoming);
    if (active) {
      const fresh = await calls.inspect(active.call.callId);
      active = {...active,call:fresh};
      showActive();
      if (fresh.state === "active") await beginMedia(fresh.callId);
      if (fresh.state === "terminated") {
        if (active.identity === fresh.callerIdentityId) clearRetryKey(fresh);
        message("Вызов завершён сервером. Старая сессия больше не используется.");
      }
    }
  } finally {refreshing = false;}
}
async function initialize() {
  clearInterval(timer);
  message("Проверка независимо авторизованной Identity и Device…");
  const user = await restoreSession();
  rememberBinding(user);
  const currentScope = principalScope(user);
  if (accountScope !== currentScope) {
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
  await updateContacts();
  await updateDevices();
  el("who").textContent = "Identity: " + user.participantId + " · Device: " + user.deviceId;
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
    const verified = await authenticateUcrFirstPartyDevice(vault,{
      origin:location.origin,
    },binding);
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
    await calls.addContact(name,peer);
    el("new-contact").reset();
    await updateContacts();
    message("Контакт сохранён локально. Для звонка требуется ответ собеседника.");
  });
});
el("cancel").addEventListener("click",() => void run(async () => {
  if (!active) return;
  const state = active.call.state;
  const action = state === "active" || state === "reconnecting" ? "hangup" : "cancel";
  active.call = await calls.signal(active.call.callId,action);
  if (active.call.state === "terminated" && active.identity === active.call.callerIdentityId) {
    clearRetryKey(active.call);
  }
  showActive();
  message("Завершение вызова подтверждено каноническим сервером.");
}));

el("signup").addEventListener("click",()=>void run(async()=>{
  message("Создание Identity и первого защищённого устройства…");
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
  clearInterval(timer);
  active=null;accountScope=null;knownContacts=[];idempotency.clear();
  renderContacts([]);renderIncoming([]);el("devices").replaceChildren();
  el("who").textContent="Вы вышли из учётной записи.";
  showActive();
  el("recovery-output").hidden=true;
  el("recovery-code").value="";
  message("Серверная сессия закрыта. Приватный ключ остаётся на устройстве для повторного входа.");
}));

window.addEventListener("pagehide", () => clearInterval(timer));
function explainEntryFailure(error) {
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
