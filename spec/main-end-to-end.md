# Canon Main End-to-End — §263 executable evidence

Status: **system-test integration evidence under construction**.

## Purpose

Canon §263 requires one ordered scenario that crosses chat, media, transport failover, local transport,
attachments, offline durable delivery, store-and-forward, reconciliation, restart compatibility and
device revocation. Separate unit/chaos tests remain useful but do not replace this ordered scenario.

The executable owner is:

- crate: `ucr-system-tests`;
- test: `canon_main_end_to_end`;
- file: `crates/ucr-system-tests/tests/main_end_to_end.rs`.

The system-test crate owns no communication logic. It composes existing canonical owners and is
`publish = false`.

## Ordered evidence

1. Two scoped principals open one canonical direct Conversation.
2. Multiple Messages are persisted and transported through the Internet route plan.
3. A canonical Call is created, accepted and media-negotiated; VideoRuntime opens sender/receiver
   and encodes/decodes one frame.
4. The primary Internet/Wi-Fi route reports a proven pre-accept failure.
5. TransportOrchestrator advances to a second allowed IP route and accepts the session-control
   envelope.
6. The scenario enters a shared-LAN phase.
7. A local transport route becomes eligible.
8. An Attachment descriptor/chunks are durably persisted and its encrypted transport envelope is
   accepted over the local route.
9. Recipient route availability is removed.
10. A new Message is created for the offline recipient.
11. The Message, CommunicationIntent and StoreForwardJob are persisted before transmission.
12. An intermediary route becomes available.
13. StoreForwardRuntime moves the opaque encrypted envelope to the intermediary without plaintext
    ownership.
14. Recipient route becomes available.
15. The intermediary forwards the same opaque envelope and canonical Delivery evidence reaches
    `PresentedToUser -> Delivered`.
16. Internet is considered restored for the reconciliation phase.
17. Canonical Sync/AntiEntropyStore summary/classification/reconcile APIs repair missing event state.
18. Duplicate event/message application is proven idempotent.
19. Every scenario Message remains present on both sender and recipient after reconciliation.
20. SQLite stores are closed/reopened; Messages, Attachment and Delivered state remain durable.
21. Canonical version negotiation proves a supported older 1.0 client still negotiates with the
    current 1.x implementation.
22. A Device is revoked, the store is restarted, protected access remains denied, its signing key
    is no longer trusted, and a fresh protected Device route is rejected before provider invocation.
    Revoked Device is rejected by protected route planning and receives no new protected content.

## Transport test boundary

The deterministic system scenario uses controllable `TransportProvider` implementations for
Internet loss, alternate-IP availability, LAN availability and intermediary appearance. The
routing decisions themselves are made by the production `TransportOrchestrator`; offline retry is
owned by production `StoreForwardRuntime`; durable state is production `SqliteLocalStore`.

This is executable **functional system evidence**, not a claim of live public-Internet/LAN hardware
coverage. Concrete Internet/local provider interoperability and platform/browser network evidence
remain independent production gates and MUST NOT be inferred from this test.

## Failure semantics

The test must fail when any ordered phase cannot establish its canonical postcondition. A transport
acceptance alone is not treated as user delivery: step 15 requires canonical `PresentedToUser`
evidence and `DeliveryState::Delivered`.

Restart, duplicate suppression, old-client compatibility and revoked-device protection are checked
inside the same scenario rather than delegated only to unrelated tests.
