# ADR-0014: Delivery attempts and evidence are separate from Message identity

Status: Accepted

## Context

UCR already persists one provider-independent Message. Delivery introduces
retries, multiple routes, relays, transport acknowledgements, device receipts,
and potentially several attempts for the same Message.

Collapsing these into one mutable provider-specific Message status would create
a second communication brain and make transport ACK indistinguishable from
user delivery.

## Decision

`MessageId` remains the canonical user-visible identity. Each operational
attempt receives a separate `DeliveryId` and monotonic state machine.

Retry or multi-path delivery creates another DeliveryAttempt rather than
rewinding a terminal attempt.

Delivery evidence is append-only and explicitly typed. Relay replication and
transport acceptance are weaker evidence than device/user delivery.`ACKNOWLEDGED` requires transport-acceptance evidence. `DELIVERED` requires
device-side evidence. `READ` requires user-read evidence. Relay replication
cannot establish either delivered or read state.

State transition plus supporting evidence is one durable transaction.

## Storage decision

SQLite schema v6 adds normalized `delivery_attempts` and `delivery_evidence`.
The memory store implements the same Core capability and remains a semantic
reference, not a second behavior model.

The Message row is not independently mutated through the same states. Future
Message-level delivery status is a deterministic projection over attempts and
evidence, avoiding competing mutable sources of truth under multi-path delivery.

## Nonclaims

This ADR does not claim exactly-once network delivery, remote receipt
authentication, receive-side deduplication, routing, retry scheduling, or real
transport adapters. Those require later Delivery/Sync/Transport work.

## Rejected alternatives- Provider-specific delivery state: rejected by the no-second-brain rule.
- Reusing one DeliveryAttempt for retry: rejected because history becomes
  non-monotonic and audit evidence becomes ambiguous.
- Relay ACK equals delivered: rejected because infrastructure possession is not
  recipient-device or user evidence.
- Mutating Message and DeliveryAttempt as independent state machines: rejected
  because concurrent/multi-path delivery would create two sources of truth.
- Exactly-once claim: rejected because network failure cannot prove that
  arbitrary remote effects occurred exactly once.