# ADR 0103: Self-hosted and managed use one protocol contract

Status: Accepted

## Context

The Canon permits Embedded, Local Daemon, Sidecar, Remote Service, Personal Node, Organization Mode and managed infrastructure, but forbids deployment mode from becoming a second Communication Core.

## Decision

Self-hosted and managed deployments use the same versioned UCR Protocol, canonical entities, authorization rules and public contract.

They may differ in scale, SLA, operations, enabled capabilities, topology and commercial terms. Managed services may supply discovery, Relay, TURN/SFU, push, backup or managed bridges, but none becomes the sole source of Identity, Conversation, Message, Intent, Delivery or Policy truth.

No managed-only hidden domain API is permitted for ClientPlatform, BusinessAIOS or any privileged consumer. Self-hosted nodes may interoperate only through the same authenticated/federated boundaries available to other compliant nodes.

A deployment may advertise unavailable capabilities rather than emulating them incorrectly. Kubernetes/cloud are deployment options, not protocol assumptions.

## Consequences

A user can move between local/personal/organization/managed topology without forking Core semantics. SLA and operational differences remain outside canonical communication ownership.
