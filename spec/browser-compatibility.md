# Browser compatibility evidence

UCR treats browser compatibility as executable deployment evidence, not as an inference from standards support.

## Automated desktop matrix

The `Browser Compatibility` GitHub Actions workflow executes the real reference Conference page through the WebDriver binaries shipped on GitHub-hosted runner images.

Current automated browser rows are:

| Browser | Runner | Evidence |
| --- | --- | --- |
| Google Chrome desktop | Ubuntu 24.04 | real Chrome + ChromeDriver |
| Microsoft Edge desktop | Ubuntu 24.04 | real Edge + Edge WebDriver |
| Mozilla Firefox desktop | Ubuntu 24.04 | real Firefox + GeckoDriver |
| Safari desktop | macOS 15 | real Safari + SafariDriver |

The probe loads the exact committed `crates/ucr-realtime-web/static/client.html` over localhost and verifies that the browser can parse and expose the reference client, WebRTC peer APIs, ICE-restart API surface, media-policy logic, media-device API, secure-context crypto primitives and required Conference controls. It emits one JSON evidence artifact per browser. Media permission prompts and a live remote Conference are deliberately not exercised by this smoke; those belong to deployment/live-interoperability evidence.

Display-capture API presence is recorded separately rather than used to falsify the whole browser row. The reference client already disables screen sharing when `getDisplayMedia` is absent, because browser/OS capture support is not universal.

## Mobile matrix

The product requirement also includes Android Chrome and iOS Safari. Desktop user-agent or viewport emulation is **not** accepted as production evidence for those rows.

Until a real-device or simulator-backed mobile browser lab is wired into CI, the truthful status is:

| Browser | Automated source/behavior coverage | Production compatibility evidence |
| --- | --- | --- |
| Android Chrome | responsive reference UI + missing-display-capture fallback | pending real mobile browser run |
| iOS Safari | responsive reference UI + missing-display-capture fallback | pending real iOS Safari run |

This distinction is intentional. UCR must not promote mobile compatibility merely because Chromium or WebKit desktop passed.

## Browser MLS core boundary

The canonical `ucr-group-mls` crate keeps its native SQLite adapter as the default feature, while
the RFC 9420/OpenMLS core can be compiled without that adapter. CI separately compiles this
`default-features = false` core for `wasm32-unknown-unknown`. This proves the existing canonical
MLS implementation is not structurally tied to native SQLite and can be reused by a browser endpoint;
it does not introduce a second MLS implementation.

This compile gate is not proof of durable browser MLS state or live endpoint interoperability.
Browser endpoint work must still own local KeyPackage/private state, process Welcome/commit material,
persist/recover the endpoint group state across restart, and derive the current media epoch secret
locally through the same OpenMLS core. A public UCR server must not expose an MLS exporter secret as
a shortcut for browser initialization.

## Scope

This matrix proves browser execution compatibility of the reference client. It does not by itself prove TURN reachability, adverse-network recovery, 1000-browser load, camera/microphone permission UX on every OS, or production endpoint-held E2EE interoperability. Those remain separate evidence gates.
