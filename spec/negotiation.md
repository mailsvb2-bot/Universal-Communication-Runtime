# UCR negotiation and handshake contract

Status: **Experimental / Phase 0**

A peer advertises one or more supported protocol ranges, actual capabilities, extensions, and a fresh nonce. Empty version advertisements are invalid. Each VersionRange is confined to one major protocol version; support across multiple majors is advertised as multiple ranges.

Version selection chooses the highest mutual version satisfying local minimum policy. A mutual version below the configured minimum is an explicit downgrade rejection, not a fallback opportunity.

Capability negotiation is intersection-based. A capability exists for the session only when both peers advertise it. Disabled capabilities are absent. If either peer marks a capability Deprecated, the negotiated capability remains Deprecated; it must not silently satisfy a stable maturity requirement.

Required capabilities may specify a minimum maturity. Missing or insufficient required capabilities fail negotiation explicitly. No capability is inferred from OS, transport name, provider name, or device class.

Unknown optional extensions may be tolerated. Unknown critical extensions fail negotiation.

The Phase-0 reference negotiation logic deliberately performs **no cryptography**. A production authenticated handshake must integrity-bind both peer hellos, both nonces, and the selected result.

Until that crypto layer exists, a successful parameter negotiation is not evidence of authenticated peer identity and must not be represented as an established secure session.
