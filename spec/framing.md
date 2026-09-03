# UCR wire framing — Phase 0 baseline

Status: **Experimental / framing version 1**

This framing defines message boundaries only. It is not authentication, encryption, or integrity protection.

## Fixed header

Every stream frame starts with a 12-byte big-endian header:

| Offset | Size | Field |
| --- | ---: | --- |
| 0 | 4 | ASCII magic `UCRF` |
| 4 | 2 | framing version |
| 6 | 1 | frame kind |
| 7 | 1 | flags |
| 8 | 4 | payload length |

Framing version 1 requires `flags == 0`. Unknown non-zero flags fail closed instead of being silently ignored.

Frame kinds are: 1 Hello, 2 NegotiationResult, 3 Command, 4 Event, 5 Error, 6 Acknowledgement.

Kind 6 carries the canonical `AcknowledgementEnvelope`: opaque acknowledged ID, non-zero-major schema version, and canonical protocol extensions. A generic acknowledgement is protocol-layer acknowledgement only. It is not `DeliveryState::ACKNOWLEDGED` and cannot be promoted into provider/transport/device/user delivery evidence.

The payload is the protobuf message corresponding to the frame kind. The framing layer rejects unsupported framing versions, unknown kinds, malformed magic, incomplete payloads, and lengths above local policy before large allocation.

The Phase-0 default maximum payload is 16 MiB. This is a local safety default, not a promise that all transports accept 16 MiB. Large attachments are not embedded in this framing; they use the attachment/file transport subsystem.

A transport may provide its own packet or message boundaries, but the canonical byte-stream representation remains defined so SDKs, IPC, relays, test transports, and future transports share one contract.

Framing version and protocol schema version are independent compatibility axes. A parser must never infer one from the other.
