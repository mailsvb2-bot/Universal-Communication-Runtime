# UCR negotiation and handshake contract

Status: **Experimental / Phase 7**

A peer advertises one or more supported protocol ranges, supported crypto suites, actual capabilities, extensions, and a fresh 32-byte nonce. Empty version advertisements are invalid. Each VersionRange is confined to one major protocol version; support across multiple majors is advertised as multiple ranges.

Version selection chooses the highest mutual version satisfying local minimum policy. A mutual version below the configured minimum is an explicit downgrade rejection, not a fallback opportunity.

Capability negotiation is intersection-based. A capability exists for the session only when both peers advertise it. Disabled capabilities are absent. If either peer marks a capability Deprecated, the negotiated capability remains Deprecated; it must not silently satisfy a stable maturity requirement.

Required capabilities may specify a minimum maturity. Missing or insufficient required capabilities fail negotiation explicitly. No capability is inferred from OS, transport name, provider name, or device class.

Unknown optional extensions may be tolerated. Unknown critical extensions fail negotiation.

Crypto-suite negotiation is intersection-based and policy-gated. Empty or duplicate suite advertisements fail closed. All-zero or reflected/equal peer nonces fail before authentication.

Parameter negotiation still performs no secret-key operation itself. Phase 7 cryptographically binds the exact hello/result frame bytes, both nonces through those frames, and both ephemeral agreement keys into the authenticated transcript. A successful parameter negotiation alone remains insufficient to represent an established secure session; peer signature, replay protection, contributory agreement, derivation, and key confirmation must also succeed.


Crypto suite identifiers do not encode security strength or preference. Crypto policy supplies an explicit ordered allowlist; an empty allowlist intentionally disables all suites. Negotiation selects the first policy-preferred suite advertised by both peers. A mutually advertised suite disabled by policy is an explicit downgrade rejection, not a fallback opportunity.

The legacy `NegotiationResult.transcript_binding` field is deprecated and MUST remain empty. Transcript binding cannot be embedded in the exact result bytes from which that binding is computed; the authenticated binding is carried by the subsequent handshake-authentication message.
