# PetrelLink — consumer-first call screen (2026-11-12)

This release is a presentation-only change on top of the existing first-party UCR Device / Call / MLS route.
No new call authority, shadow contact directory, account identifier, phone lookup or cryptographic shortcuts.

## Delivered
- Contacts become the first useful signed-in screen, ahead of technical call internals.
- Each private contact displays one primary audio action and one video action, both wired to `dial(contact,media)` -> `calls.start()` through the current Device-bound BFF.
- Search handles empty matches and contacts are sorted; rename/delete remain available in per-contact options.
- When a user starts or accepts a Call, the active panel is scrolled into view so the button visibly responds.
- During a call, the actual Call state is shown in ordinary language. Incoming calls are emphasized only when present.
- Detailed stages and diagnostics remain accessible but do not dominate the screen.
- Unsupported Contacts Picker browsers (notably desktop Chrome) do not display a nonworking native picker. User can still import one .vcf or send an invite.
- Consent/recovery, per-Device security, server-verified Call acceptance and MLS are unchanged.
- UI state on logout is hidden; no network directory is introduced.

## Unverified / not claimed
- An actual live A↔B audio-video call over NAT and two separate physical devices is not established by UI tests.
- SMS handoff may differ per mobile OS; .vcf is explicitly user-chosen only.
- Browser background push, native dialer integration and auto-discovery by phone number remain unavailable.
- End-user UX validation requires actual browsers, small screens and assistive technologies.

## Regression gates
```sh
node --test tests/consumer_simple_ui.test.mjs tests/consumer_phonebook.test.mjs
node tools/test_first_party_call_resume.mjs
node tools/test_first_party_invitation_buttons.mjs
node tools/test_first_party_invite_onboarding.mjs
node tools/test_first_party_action_busy_feedback.mjs
node tools/test_first_party_mls_integrity_handler.mjs
python3 tools/check_first_party_start_controls.py
```
