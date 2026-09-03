# UCR canonical error model

Status: **Experimental / Phase 0**

Errors crossing the public UCR contract use stable machine-readable categories. Provider, OS, transport, and library error strings are diagnostics, never canonical control flow.

Canonical codes cover invalid arguments, malformed frames, unsupported protocol versions, rejected downgrade, unsupported critical extensions, capability mismatch, authentication/permission/policy failures, rate/resource/deadline/cancellation failures, temporary unavailability, integrity failure, conflict, not-found, and internal failure.

`retryable` is explicit. The default is conservative: only rate limiting and temporary unavailability are retryable by default. A retry delay may be supplied when known.

Permission, policy, integrity, malformed-input, and downgrade failures are not automatically retried.

Unknown future error codes must not be translated into success. A compatible client may surface them as an unknown failure while preserving the raw numeric code where its language/runtime permits that behavior.


## Public ErrorEnvelope wire semantics

The public `ErrorEnvelope` carries the raw protobuf error-code numeric value, explicit retry metadata, a diagnostic domain, and canonical protocol extensions. Code zero (`UNSPECIFIED`) is invalid after semantic decoding. Unknown future non-zero numeric codes remain failures and SHOULD be preserved as raw numeric values rather than translated to success or an unrelated known category.

Error-envelope extension ordering is non-semantic; shared namespace, duplicate-name, count, and payload budgets apply. A diagnostic domain remains diagnostic metadata and must not become provider-specific canonical branching logic.
