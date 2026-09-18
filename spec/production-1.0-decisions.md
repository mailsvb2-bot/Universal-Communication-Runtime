# Production 1.0 Canon Decision Closure

The Canon requires twenty named architectural decisions before a Production 1.0 claim. This file is the executable mapping from each Canon item to its accepted ADR evidence; it does not replace those ADRs.

| # | Canon decision | Accepted ADR evidence |
|---|---|---|
| 1 | Root Identity Model | ADR 0043 |
| 2 | Device Identity Model | ADR 0004, ADR 0032 |
| 3 | Persona Model | ADR 0095 |
| 4 | Account Recovery | ADR 0012, ADR 0033, ADR 0039 |
| 5 | Group Cryptography | ADR 0096 |
| 6 | Protocol Framing | ADR 0002 |
| 7 | Version Negotiation | ADR 0019 |
| 8 | Conversation Taxonomy | ADR 0097 |
| 9 | Group History Policy | ADR 0098 |
| 10 | Delivery Semantics | ADR 0014, ADR 0063, ADR 0065 |
| 11 | Delete Semantics | ADR 0099 |
| 12 | Federation Trust | ADR 0074 |
| 13 | Public API Compatibility | ADR 0100 |
| 14 | Codec Baseline | ADR 0101 |
| 15 | Metadata Privacy | ADR 0102 |
| 16 | Multi-Tenant Boundary | ADR 0006 |
| 17 | Self-Hosted vs Managed Contract | ADR 0103 |
| 18 | Licensing Boundary | ADR 0104 |
| 19 | Public Extension Registry | ADR 0105 |
| 20 | Data Lifecycle | ADR 0106 |

## Release truth

Decision closure is necessary but not sufficient for Production. The exact source/artifact release must still satisfy `spec/production-hardening.md` and `spec/production-release.md`, including a successful protected publisher-signed release execution.

ADR 0104 intentionally grants no general software license by itself. A release intended for general third-party redistribution must additionally carry publisher-approved license text.
