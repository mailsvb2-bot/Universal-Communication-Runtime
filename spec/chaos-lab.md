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
- bounded deterministic per-link jitter layered on top of base latency;
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

The canonical simulation fixture instantiates 100 peers and supports per-link latency, bounded deterministic jitter, packet loss injection, partitions/merge and peer mobility/network-switch state. It enforces an explicit minimum send-battery threshold: a peer below the configured battery limit fails with an explicit `BatteryLimited` result instead of silently transmitting or dropping data. This is a deterministic resource constraint, not a claim of complete mobile battery/thermal fidelity.

## Realtime and WebRTC adversity composition

Chaos Lab remains the only deterministic fault substrate; it does not implement a second realtime or WebRTC state machine. Cross-boundary tests compose its faults with the existing production-facing owners:

- a network switch is observed through the Chaos Transport generation and a dropped realtime downlink is resumed through `RealtimeSessionRegistry::attach_downlink`;
- a single-use join grant remains single-use during reconnect: a second redemption is rejected while the already authenticated realtime session resumes with a `Reconnected` attendance transition;
- deterministic packet loss is followed by `LiveWebRtcProvider::restart_session` for the same `SessionId`, proving ICE restart returns a fresh offer without creating another canonical Call/Conference;
- post-restart link latency remains explicit in Chaos Transport evidence rather than being hidden as success;
- bounded deterministic jitter varies per-packet latency inside a configured envelope and replays exactly for the same packet IDs;
- SFU worker disappearance is exercised against the real `SfuClusterDirectory`: the same canonical `CallId` fails over to a surviving healthy node, and re-registering the restarted node does not steal the live sticky placement back.

## Requirement-56 coverage

The product requirement for network adversity is represented explicitly:

- **packet loss** — deterministic `DropNext` plus a real `LiveWebRtcProvider::restart_session` ICE restart on the same realtime session;
- **jitter** — deterministic bounded per-link jitter with repeatable packet-specific latency variation;
- **high latency** — explicit base latency remains observable before/after recovery and composes with jitter/throttling;
- **Wi-Fi -> LTE / network switch** — `SwitchNetwork` advances the destination network generation while the same authenticated realtime session is retained;
- **temporary network disappearance** — peer offline/online and dropped downlink evidence fail explicitly rather than returning false success;
- **reconnect** — `RealtimeSessionRegistry::attach_downlink` resumes the existing session and emits `Reconnected` without redeeming a single-use grant again;
- **SFU node restart** — the horizontal placement directory removes the failed worker, re-places the exact same canonical Call on a survivor, then re-registers the restarted worker while preserving the survivor's sticky placement.

These are executable integration boundaries, not claims of kernel packet shaping, WAN quality, browser-radio behavior, TURN reachability, automatic failure detection, or production inter-node media continuity. The SFU restart test proves control-plane placement/failover semantics only; real worker process orchestration, inter-node encrypted-media transport and live media continuity remain separate production evidence.

## Non-claims

Prepared Phase 43 does not claim:

- production network emulation fidelity;
- kernel-level packet shaping;
- real DNS/relay/SFU process orchestration;
- complete mobile battery/thermal simulation;
- replacement of protocol conformance for old-client compatibility;
- replacement of security, fuzz, load, benchmark or production tests.

It creates deterministic executable evidence on which those broader scenarios can be layered without adding a second UCR communication model.
