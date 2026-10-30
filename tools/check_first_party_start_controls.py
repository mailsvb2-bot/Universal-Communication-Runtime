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
assert 'document.getElementById("pl-onboard").after(recovery)' in HTML, (
    "recovery code must be moved outside the hidden registration panel"
)
assert 'id="pl-invite-help"' in HTML and 'data-invited-contact' in HTML, (
    "invitation must have an understandable contact-add path"
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
assert "const session = await restoreSession();\n  const call = await calls.start" in JS
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
    assert sensitive in JS.split("function plClearAuthenticatedView(){", 1)[1].split(
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
assert 'void run(initialize)' in JS
print(f"UCR first-party UI control wiring: PASS ({len(parser.controls)} static form/button controls; 6 dynamic actions)")
