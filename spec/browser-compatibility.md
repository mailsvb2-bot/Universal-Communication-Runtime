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

The browser endpoint now owns local KeyPackage/private state, processes Welcome/commit material,
derives the current media epoch secret locally through the same OpenMLS core, and can seal/restore
the exact OpenMLS in-memory storage as a bounded encrypted snapshot. Snapshot AEAD is bound to the
tenant/namespace, group, device, epoch and canonical state reference. Restore reloads the group through
OpenMLS storage and rejects state/device mismatches, so stale or cross-device snapshots fail closed.

The reference browser now includes an IndexedDB vault that accepts only sealed endpoint-state bytes.
The desktop Browser Compatibility matrix writes a sealed-byte probe, reloads the page, reads the same
bytes back from IndexedDB, deletes them, and verifies deletion in real Chrome, Edge, Firefox and Safari.
This is executable evidence that durable browser storage survives a page reload without exposing raw
MLS private material to the page-level persistence contract.

The versioned endpoint E2EE adapter contract now has optional persistence hooks. The reference browser
derives a stable persistence key from tenant, namespace, call, participant and device identity, restores
a sealed snapshot before endpoint start, persists a fresh sealed snapshot after start, and persists again
after successful incoming encrypted-envelope processing. The real desktop Browser Compatibility matrix
proves that a versioned adapter can seal state, reload the page, and receive the same sealed snapshot
through restoreSealedState on Chrome, Edge, Firefox and Safari.

The browser wrapping-key vault stores a non-extractable AES-GCM KEK as a structured-cloned CryptoKey
in IndexedDB. A random 32-byte endpoint wrapping key is encrypted with that KEK using per-record AES-GCM
IV and identity-bound additional authenticated data. Durable storage contains the non-extractable KEK,
IV and ciphertext only; the plaintext 32-byte wrapping key exists only in a transient mutable buffer.
The Endpoint WASM persistence bridge erases that buffer after each seal/restore operation.

The real desktop Browser Compatibility matrix verifies that the KEK remains non-extractable, raw
export is rejected, the ciphertext is not the plaintext wrapping key, and the same wrapping key can
be recovered after a page reload in Chrome, Edge, Firefox and Safari. It also exercises the database
upgrade path by creating a real version-1 endpoint-state database containing a legacy sealed snapshot,
opening it through the version-2 client, and verifying that the legacy snapshot is preserved while the
new wrapping-key vault object store is added.

This is still not proof of full MLS restore interoperability: the production browser integration must
instantiate the real WASM/OpenMLS adapter with this wrapping-key provider and then prove live
multi-endpoint MLS reload/interoperability. A public UCR server must not expose an MLS exporter secret
as a shortcut for browser initialization.

## Scope

This matrix proves browser execution compatibility of the reference client. It does not by itself prove TURN reachability, adverse-network recovery, 1000-browser load, camera/microphone permission UX on every OS, or production endpoint-held E2EE interoperability. Those remain separate evidence gates.
