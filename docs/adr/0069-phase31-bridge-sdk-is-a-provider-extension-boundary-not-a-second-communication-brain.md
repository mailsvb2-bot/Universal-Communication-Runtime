# ADR-0069 — Phase 31 Bridge SDK is a provider extension boundary, not a second communication brain

## Status
Accepted for Phase 31 Prepared/reference implementation.

## Problem
Later provider phases need a common outbound/inbound contract, compatibility/capability declaration, disable/revoke lifecycle, minimum-disclosure boundary, backpressure semantics and crash-safe side-effect handling. Implementing these independently in Telegram/VK/MAX would create provider-specific communication brains and inconsistent security.

## Existing state
UCR already owns canonical Integration IDs, Messages, Conversations, Identity bindings, Delivery, Intent/policy, authorization and Event APIs. Group records already have provider mapping data, but no executable Bridge trust boundary existed before Phase 31.

## Decision
Add `ucr-bridge` as a provider-agnostic host plus a language-independent `BridgeProviderService` contract. `IntegrationId` remains the integration identity. SQLite schema v27 adds only Bridge registration/security metadata and a metadata-only action ledger. It does not persist provider plaintext or duplicate Message/Delivery state.

Every provider declares exact capabilities, data permissions and SDK/protocol ranges. Core checks durable registration and the live manifest before each operation. Provider acceptance is classified separately from canonical Delivery evidence. Proven non-acceptance may retry; ambiguous acceptance is terminal. `NoExternalBridge`, canonical Message payload/attachment binding and independent authorization are enforced before provider side effects.

Inbound provider pages are bounded and scope/integration/capability checked but are not silently promoted into canonical Messages. Later provider phases normalize events through existing owners.

## Alternatives rejected
A provider-specific SDK per messenger is rejected because it creates a second brain. A stateless adapter with no durable action ledger is rejected because crash-after-provider-acceptance can duplicate side effects. Treating provider ACK as Delivered/Read is rejected because provider acceptance is weaker evidence. Persisting Bridge plaintext is rejected because it violates minimum disclosure and duplicates canonical Message state.

## Security and privacy impact
The Bridge becomes an explicit trust boundary. Disabled/revoked or incompatible providers fail closed; live capability loss is respected immediately; malicious scope/integration spoofing on inbound pages is rejected; provider payload cannot silently diverge from a referenced canonical Message; `NoExternalBridge` cannot be bypassed. Durable Bridge state contains metadata only.

## Compatibility, migration and rollback
Schema v26 migrates additively to v27 and invents no Bridge registrations/actions. Existing canonical communication state is unchanged. Rollback requires a v26-aware binary against a pre-v27 backup; v27 is intentionally rejected by older binaries rather than silently downgraded.

## Testing strategy
Reference tests cover deduplication, policy/payload binding, runtime capability loss, classified retry, unknown acceptance, crash-left recovery and malicious inbound scope. SQLite tests cover restart, terminal lifecycle and v26→v27 migration. Threat simulation, fuzzing, protocol compilation, workspace debug/release tests and RustSec audit are mandatory before merge.
