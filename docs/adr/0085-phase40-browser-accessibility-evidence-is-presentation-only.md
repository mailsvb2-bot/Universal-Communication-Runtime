# ADR 0085 — Phase-40 browser accessibility evidence is presentation-only

## Decision

Phase 40 uses a checked-in browser presentation adapter as concrete accessibility evidence for the Reference Messenger. It is not a browser implementation of the UCR node.

The surface must expose semantic screen-reader structure, native keyboard controls, scalable text, visible focus, high-contrast/forced-colors support, captions, subtitles, transcript presentation and RTL-ready layout. Direction, text scale and high contrast are interactive controls with screen-reader state announcements; positive tabindex and custom div/span keyboard controls are forbidden. A repository validator makes those properties regression-checked.

## Boundary

The browser artifact owns no Identity, Conversation, Message, Call, Delivery, Sync, Recovery, policy, routing, retry or transport state. It does not call hidden UCR APIs and does not claim native LAN, background execution, filesystem, media-capture or push capabilities.

Communication remains `Reference Messenger -> public UCR SDK/API -> UCR`. The web artifact is only a concrete platform presentation adapter over the same user-facing model.

## Consequence

Phase 40 can close Accessibility with concrete platform evidence without pretending that a browser is a native node. Full cross-browser/assistive-technology conformance and production certification remain outside this focused Phase-40 proof and belong to later conformance/production work.
