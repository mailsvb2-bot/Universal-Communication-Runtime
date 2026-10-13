import {
  createUcrBrowserProtectedDeviceVault,
  createUcrFirstPartyHttpHost,
  authenticateUcrFirstPartyDevice,
  createUcrContactCallJourney,
} from "/endpoint-media/reference_browser_media_installer.js";

const el = (id) => document.getElementById(id);
const status = el("status");
const vault = createUcrBrowserProtectedDeviceVault();
const host = createUcrFirstPartyHttpHost(vault, {origin:location.origin});
const calls = createUcrContactCallJourney(host,vault);
let active = null, busy = false, navigating = false, refreshing = false, timer = null;
let knownContacts = [];
let accountScope = null;
const idempotency = new Map();

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
    return;
  }
  const remote = active.call.callerIdentityId === active.identity
    ? active.call.calleeIdentityId : active.call.callerIdentityId;
  state.textContent = nameFor(remote) + " — " + active.call.state
    + " (" + (active.call.media === "video" ? "видео" : "аудио") + ")";
  el("cancel").hidden = active.call.state === "terminated";
}
async function beginMedia(callId) {
  if (navigating) return;
  // This coordinator permits Join ONLY after the recipient has accepted
  // and the canonical owner reports ACTIVE. It never creates trust or keys.
  const grant = await calls.join(callId);
  if (!grant || grant.callId !== callId) throw Error("Call admission mismatch");
  navigating = true;
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
  const call = await calls.start(contact.id,media,requestId);
  const session = await host.resumeAuthenticatedDevice();
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
    const user = await host.resumeAuthenticatedDevice();
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
  const user = await host.resumeAuthenticatedDevice();
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
  el("who").textContent = "Identity: " + user.participantId + " · Device: " + user.deviceId;
  await refresh();
  timer = setInterval(() => {
    if (busy || navigating || document.hidden) return;
    void refresh().catch(err => {
      clearInterval(timer);
      message("Проверка входящих остановлена: " + (err instanceof Error ? err.message : String(err)));
    });
  },2500);
  message("Учётная запись подтверждена. Исходящие и входящие проверяются каноническим сервером.");
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
    await initialize();
  });
});
el("retry").addEventListener("click",() => void run(initialize));
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
window.addEventListener("pagehide", () => clearInterval(timer));
void run(initialize);
