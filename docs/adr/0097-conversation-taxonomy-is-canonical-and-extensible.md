# ADR 0097: Conversation taxonomy is canonical and extensible

Status: Accepted

## Context

The Canon requires the data model to support DIRECT, PRIVATE_GROUP, PUBLIC_GROUP, BROADCAST, COMMUNITY, ROOM, TOPIC, THREAD and SYSTEM even when not every product surface is implemented immediately.

## Decision

`ConversationKind` is the canonical taxonomy and contains exactly those nine baseline kinds. A Conversation remains provider-independent and may outlive any endpoint or bridge.

Parent/child topology is expressed through canonical conversation relationships, not by introducing product-specific message cores. Unsupported kinds are capability/maturity limits, not permission to reinterpret an existing kind.

A future stable kind requires protocol/version compatibility review. Product labels and UI names do not alter canonical taxonomy.

## Consequences

Current Direct/Group implementations remain valid while later Room/Topic/Thread/Public/Broadcast surfaces can be added without changing Message identity or creating a second Conversation owner.
