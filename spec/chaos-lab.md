# UCR Chaos Lab — Phase 43

Status: **Prepared**.

## Purpose

Phase 43 provides a deterministic, reproducible failure-injection substrate for proving UCR behavior under adverse network, infrastructure, process, storage, time and consumer conditions. Chaos evidence must expose failures explicitly; it must not make a failed operation look delivered.

The lab is test infrastructure. It does not become a production transport, storage owner, Delivery engine, router, clock source, or integrity mechanism.

## Canonical scenario registry

The lab tracks the Canon scenario set:

1. network loss;
2. network switch;
3. DNS failure;
4. relay failure;
5. SFU failure;
6. process kill;
7. app restart;
8. peer disappearance;
9. clock drift;
10. packet duplication;
11. packet reorder;
12. corruption;
13. storage full;
14. network partition;
15. network merge;
16. old client;
17. revoked device;
18. slow consumer.

Prepared Phase 43 supplies executable fault primitives for network loss/switch, infrastructure outage, peer disappearance/revocation, clock drift, duplication, reorder, corruption, storage exhaustion, partition/merge, slow consumers, link throttling and battery-limited sending. Process kill/app restart are exercised through durable-state snapshot/restart evidence. `old client` remains owned by protocol/conformance version-negotiation evidence rather than reimplementing compatibility logic in Chaos Lab.

## Test transport fault primitives

Deterministic fault injection supports the Canon test-transport surface:

- delay through per-link latency;
- drop;
- duplicate;
- reorder;
- disconnect/reconnect through peer online state;
- corruption;
- throttle through deterministic per-link bytes/second shaping represented as additional delivery latency without truncating payload;
- network switch generation;
- DNS/relay/SFU availability;
- network partition/merge;
- clock drift;
- slow consumer delay;
- device revocation.

Every injected fault is explicit and repeatable. Random production entropy is not reused as test randomness.

## Data-safety evidence

The Prepared lab proves these boundaries:

- duplicate wire packets are suppressed by packet identity before becoming user-visible duplicates;
- corruption is rejected rather than accepted as valid data;
- partition produces an explicit failure and merge restores a valid path;
- disconnect fails explicitly and reconnect restores delivery;
- throttle adds deterministic latency while preserving the complete payload;
- storage exhaustion returns an explicit `StorageFull` state before mutating existing durable queue state;
- restart from a durable snapshot preserves pending data;
- revoked/offline peers fail closed;
- DNS/relay/SFU outages cannot return false success;
- slow consumers become bounded observable latency in the fixture, not silent loss.

The lab integrity tag is deliberately non-cryptographic. It exists only to make deterministic corruption visible in tests and MUST NOT be used as a production integrity primitive.

## Network simulation

The canonical simulation fixture instantiates 100 peers and supports per-link latency, packet loss injection, partitions/merge and peer mobility/network-switch state. It enforces an explicit minimum send-battery threshold: a peer below the configured battery limit fails with an explicit `BatteryLimited` result instead of silently transmitting or dropping data. This is a deterministic resource constraint, not a claim of complete mobile battery/thermal fidelity.

## Non-claims

Prepared Phase 43 does not claim:

- production network emulation fidelity;
- kernel-level packet shaping;
- real DNS/relay/SFU process orchestration;
- complete mobile battery/thermal simulation;
- replacement of protocol conformance for old-client compatibility;
- replacement of security, fuzz, load, benchmark or production tests.

It creates deterministic executable evidence on which those broader scenarios can be layered without adding a second UCR communication model.
