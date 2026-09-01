# UCR canonical error model

Status: **Experimental / Phase 0**

Errors crossing the public UCR contract use stable machine-readable categories. Provider, OS, transport, and library error strings are diagnostics, never canonical control flow.

Canonical codes cover invalid arguments, malformed frames, unsupported protocol versions, rejected downgrade, unsupported critical extensions, capability mismatch, authentication/permission/policy failures, rate/resource/deadline/cancellation failures, temporary unavailability, integrity failure, conflict, not-found, and internal failure.

`retryable` is explicit. The default is conservative: only rate limiting and temporary unavailability are retryable by default. A retry delay may be supplied when known.

Permission, policy, integrity, malformed-input, and downgrade failures are not automatically retried.

Unknown future error codes must not be translated into success. A compatible client may surface them as an unknown failure while preserving the raw numeric code where its language/runtime permits that behavior.
