#!/usr/bin/env python3
"""Check that all UCR first-party page controls have a wired event path.

This is a source contract, not a substitute for live Windows/browser E2E.
"""
from html.parser import HTMLParser
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "crates/ucr-realtime-web/static/start.html").read_text(encoding="utf-8")
JS = (ROOT / "crates/ucr-realtime-web/static/start.js").read_text(encoding="utf-8")

class Controls(HTMLParser):
    def __init__(self):
        super().__init__()
        self.controls = []
        self.ids = set()
    def handle_starttag(self, tag, attrs):
        data = dict(attrs)
        if data.get("id"):
            if data["id"] in self.ids:
                raise AssertionError("duplicate element ID: " + data["id"])
            self.ids.add(data["id"])
        if tag == "button" or tag == "form":
            self.controls.append((tag, data))

parser = Controls()
parser.feed(HTML)
# The consumer cabinet is part of the production entry page, not a detached mockup.
# Its signed-in UI must exist before start.js binds click handlers.
for ident in (
    "pl-new-user", "pl-user-cabinet", "pl-friendly-identity",
    "pl-copy-invite", "pl-share-invite", "pl-signup-slot",
):
    assert ident in parser.ids, "missing PetrelLink cabinet element: " + ident
assert r"\n const recovery" not in HTML and r"\n if(recovery" not in HTML, (
    "literal newline escapes break inline onboarding JavaScript"
)
# A newly registered user must still see their one-time recovery code after
# the signed-in state hides the new-user registration panel.
assert 'document.getElementById("pl-onboard").after(recovery)' in JS, (
    "recovery code must be moved outside the hidden registration panel"
)
assert 'id="pl-invite-help"' in HTML and 'data-invited-contact' in JS, (
    "invitation must have an understandable contact-add path"
)
# CSP must not silently block the onboarding actions: all executable page
# behavior lives in the same-origin module, not inline script elements.
assert '<script type="module" src="/start.js"></script>' in HTML, (
    "first-party onboarding module is not loaded"
)
assert not re.search(r'<script\b(?![^>]*\bsrc\s*=)[^>]*>', HTML, re.I), (
    "inline scripts violate the first-party script-src self CSP"
)
assert 'if(signup&&slot)slot.appendChild(signup)' in JS, (
    "signup action is not moved into the visible onboarding card"
)
# The module awaits its browser media import, so DOMContentLoaded can have
# fired before the locale handler is registered. Both paths must initialize.
assert 'document.readyState === "loading"' in JS and (
    'initializeLanguagePicker();' in JS
), "language picker is lost when the async module loads after DOMContentLoaded"
# Switching to English must also translate dynamic incoming/contacts/call actions,
# status guidance and accessible field labels, not only initial headings.
for label in ("Аудиозвонок", "Видеозвонок", "Принять", "Отклонить", "Отозвать устройство"):
    assert f'"{label}":' in JS, f"missing English dynamic action translation: {label}"
assert 'button.textContent = localize(text);' in JS, "dynamic Call buttons remain Russian"
assert 'function message(value) { status.textContent = localize(value); }' in JS, (
    "dynamic status messages ignore the selected language"
)
assert 'el("video-guide").textContent = localize(guide);' in JS, (
    "live call guidance ignores the selected language"
)
assert 'lang=next;' in JS and 'data-pl-original-' in JS, (
    "language selection does not update current language and accessible labels"
)

assert parser.controls, "no visible forms/buttons found"

for tag, element in parser.controls:
    ident = element.get("id")
    if tag == "form":
        assert ident and re.search(r'el\(["\']' + re.escape(ident) + r'["\']\)\.addEventListener\(["\']submit', JS), (
            "form lacks submit handler: " + str(ident)
        )
    else:
        if element.get("type") == "submit":
            # Belongs to a form with a validated submit listener.
            continue
        assert ident and re.search(r'el\(["\']' + re.escape(ident) + r'["\']\)\.addEventListener\(["\']click', JS), (
            "button lacks click handler: " + str(ident)
        )

# A received invitation must remain visible after onboarding, but may not
# silently create a trusted contact or retain its identifier in the address bar.
assert 'dataset.invitedContact==="true"' in JS, "invite context lost on login"
assert 'el("contact-name").focus' in JS, "invite needs visible contact confirmation"
assert 'calls.addContact(name,peer)' in JS, "contact must use canonical owner"
assert 'clean.searchParams.delete("contact")' in JS, "invite URL remains after contact add"
# Registration succeeded even when optional list endpoints are unavailable:
# never send an authenticated user back into the anonymous signup journey.
assert JS.index('plSetSignedIn(user.participantId)') < JS.index('await authTrace("list_contacts"'), (
    "canonical sign-in must precede optional contact loading"
)
assert 'try {await authTrace("list_devices"' in JS, (
    "device inventory failure must not invalidate an authenticated profile"
)
assert 'if(peer===plOwnIdentity)' in JS and 'knownContacts.some(' in JS, (
    "contact onboarding must reject self and duplicate entries"
)
assert 'document.addEventListener("visibilitychange"' in JS, (
    "mobile foreground must recheck incoming calls"
)
# Never render a former account's contact book or active call before verified
# device reauthentication. Security diagnostics must not dominate the UI.
for ident in ("pl-contacts", "pl-incoming", "pl-current-call"):
    assert f'id="{ident}" hidden' in HTML, f"unauthenticated panel visible: {ident}"
    assert f'"{ident}"' in JS, f"panel not bound to authenticated state: {ident}"
assert '<details id="auth-diagnostics">' in HTML, "diagnostics should be collapsed"
assert 'accountScope=null;\n  active=null;\n  knownContacts=[];' in JS, (
    "failed authentication must clear prior principal's UI data"
)
# Dynamic controls must be created with the common click-binding helper.
for label in ("Аудиозвонок", "Видеозвонок", "Удалить", "Отозвать устройство", "Принять", "Отклонить"):
    assert 'btn("' + label + '"' in JS, "missing dynamic control: " + label
assert 'button.addEventListener("click", () => void run(callback))' in JS
assert "const session = await restoreSession();" in JS
assert "const call = await calls.start(contact.id,media,requestId);" in JS
# A revoked cookie, logout in another tab, or changed canonical Device must
# hide the old identity/invitation and clear sensitive UI before retry.
assert "function plClearAuthenticatedView(preserveRecoveryCode=false)" in JS
assert 'if(!preserveRecoveryCode){' in JS and (
    'plClearAuthenticatedView(true);' in JS.split("function explainEntryFailure(error)", 1)[1]
), "failed first login must not destroy a freshly issued one-time recovery code"
for sensitive in (
    'accountScope=null;', 'active=null;', 'knownContacts=[];',
    'idempotency.clear();', 'renderContacts([]);', 'renderIncoming([]);',
    'el("devices").replaceChildren();', 'plSetSignedIn(null);',
    'el("recovery-code").value="";',
):
    assert sensitive in JS.split("function plClearAuthenticatedView(preserveRecoveryCode=false){", 1)[1].split(
        "function plInviteUrl()", 1
    )[0], "stale identity UI cleanup missing: " + sensitive
refresh = JS.split("async function refresh() {", 1)[1].split(
    "async function initialize()", 1
)[0]
assert re.search(
    r"try\s*\{\s*user\s*=\s*await restoreSession\(\);\s*\}"
    r"\s*catch\s*\(error\)\s*\{[^}]*plClearAuthenticatedView\(\);",
    refresh, re.S
), "failed session revalidation must hide the former user's cabinet"
assert 'error instanceof TypeError || [429,500,502,503].includes(code)' in refresh, (
    "transient network failures must retain automatic session polling"
)
assert re.search(
    r"if\s*\(accountScope !== principalScope\(user\)\)\s*\{"
    r"[^}]*plClearAuthenticatedView\(\);",
    refresh, re.S
), "cross-tab Identity/Device change must clear the former user's cabinet"
# Delayed contact/Device reads must never repaint an old principal after
# logout, self-revoke or a fresh sign-in with the same public Identity.
assert 'let uiAuthGeneration = 0;' in JS
assert 'uiAuthGeneration++;' in JS.split(
    "function plClearAuthenticatedView(preserveRecoveryCode=false){", 1
)[1].split("function plInviteUrl()", 1)[0]
for function_name in ("updateDevices", "updateContacts"):
    body = JS.split(f"async function {function_name}() {{", 1)[1].split(
        "\n}", 1
    )[0]
    assert "generation=uiAuthGeneration" in body, f"{function_name} lacks read fence"
    assert "generation!==uiAuthGeneration" in body, f"{function_name} paints stale data"
assert 'if(own){\n          forgetBinding();forgetActiveCall();\n          plClearAuthenticatedView();' in JS, (
    "self-revoked Device must hide its former authenticated cabinet"
)
assert 'generation!==uiAuthGeneration' in JS.split("async function restoreActiveCall(user)", 1)[1].split("function setCallStage", 1)[0], (
    "late Call inspection must not restore a Call after same-Device reauthentication"
)
assert 'Device changed during Call creation' in JS and 'generation!==uiAuthGeneration' in JS.split("async function dial(contact,media)", 1)[1].split("function renderIncoming", 1)[0], (
    "late Call creation must not paint another authenticated account"
)
assert 'el("who").textContent="Нет подтверждённой сессии."' in JS, (
    "revoked session must not keep showing trusted-device status"
)
assert 'uiAuthGeneration!==verifiedGeneration' in refresh, (
    "late incoming-call response must not repaint a newer login"
)
assert 'void run(initialize)' in JS
print(f"UCR first-party UI control wiring: PASS ({len(parser.controls)} static form/button controls; 6 dynamic actions)")
