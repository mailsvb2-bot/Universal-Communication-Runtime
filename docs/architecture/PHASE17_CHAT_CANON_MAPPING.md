# Phase 17 Chat Canon mapping

- Messages are durable: Chat send delegates to canonical Message persistence.
- Typing is ephemeral: the only typing boundary is `EphemeralChatSink` with bounded TTL.
- `MessageRead` is a fact: Chat read requires explicit `READ_BY_USER` evidence.
- Relay/transport ACK is not user delivery/read: no ACK path maps directly to Read.
- Identity/Conversation/Message/Delivery remain canonical owners; Chat adds no parallel owner.
- Local/Internet transports remain interchangeable below Chat; Chat contains no route planner.
- Groups remain Phase 18 and non-Direct conversations are rejected by the Phase-17 reference API.
