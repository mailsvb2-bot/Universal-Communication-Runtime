# ucr-chat

Prepared Phase-17 reference Chat layer.

It composes existing canonical Conversation, Message, Delivery, authorization, scope, Event/Sync, and transport boundaries. It owns no durable message database, group model, identity map, delivery state machine, route planner, or network listener.

Current Phase-17 surface: Direct conversation creation, durable text send/read, bounded explicit-ID transcript projection, explicit user-read evidence, and ephemeral TTL-bounded typing.

See `spec/chat.md` and ADR 0055 for exact scope and nonclaims.
