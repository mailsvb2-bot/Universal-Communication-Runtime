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

# Dynamic controls must be created with the common click-binding helper.
for label in ("Аудиозвонок", "Видеозвонок", "Удалить", "Отозвать устройство", "Принять", "Отклонить"):
    assert 'btn("' + label + '"' in JS, "missing dynamic control: " + label
assert 'button.addEventListener("click", () => void run(callback))' in JS
assert "const session = await restoreSession();\n  const call = await calls.start" in JS
assert "const user = await restoreSession();\n    if (accountScope" in JS
assert 'void run(initialize)' in JS
print(f"UCR first-party UI control wiring: PASS ({len(parser.controls)} static form/button controls; 6 dynamic actions)")
