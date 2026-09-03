# ADR-0023: Native Opaque IDs use OS CSPRNG random-hex v1

Status: Accepted

## Problem

The Canon requires canonical IDs to be generated offline and independent of IP, hostname, server database sequence, and provider ID. ADR-0022 defined the OpaqueId wire/semantic representation but intentionally left the native generation algorithm undecided. Without one canonical production default, SDKs and runtime components could invent incompatible timestamp, counter, provider-derived, or weak-random schemes.

## Existing state

`ucr.v1.OpaqueId.value` semantically carries an exact non-empty UTF-8 token of at most 128 bytes. Existing/imported IDs may use any token in that semantic domain. Event ordering is explicitly not derived from opaque IDs. The repository already uses pinned `getrandom` for cryptographic randomness, but no canonical ID generator exists. Keeping entropy acquisition in the runtime rather than deterministic protocol logic preserves a clean protocol/runtime dependency boundary.

## Decision

The native UCR generation algorithm is `ucr.id.random_hex.v1`. It obtains exactly 16 bytes (128 bits) from the operating-system CSPRNG and encodes those bytes as exactly 32 lowercase hexadecimal ASCII characters. No timestamp, wall clock, monotonic clock, MAC address, IP, hostname, process identifier, provider identifier, server sequence, database row ID, or business-domain value participates.

`ucr-protocol` is the single deterministic generation-algorithm/encoding owner and exports `encode_native_opaque_id`. `ucr-core` is the Rust runtime entropy-acquisition owner and exports `generate_opaque_id`, obtaining bytes from the OS CSPRNG before delegating to protocol encoding. `ucr-model::OpaqueId` remains the single representation/validation owner. The generator does not narrow inbound OpaqueId validation: pre-existing or imported semantic IDs do not need to match native random-hex output.

If OS randomness is unavailable, generation fails explicitly. There is no fallback to time, counters, deterministic hashes, weak PRNGs, or network/server coordination. A detected storage collision must never overwrite an existing canonical entity; the creator discards the candidate and generates a fresh ID.

An ID is not a credential, authorization token, identity-verification proof, chronology value, or routing hint. Randomness makes native IDs impractical to enumerate by guessing, but Tenant/Permission/Policy remain the authority boundary.

## Rationale

128 bits of CSPRNG entropy provides a very large distributed collision space and strong resistance to guessing while keeping the language-independent representation simple. Lowercase hex is trivial to implement consistently across Rust, Python, TypeScript, Kotlin, Swift, and other SDKs without adding binary/text conversion ambiguity. Omitting timestamps avoids creating accidental ordering or privacy semantics that the Canon does not require.

## Advantages

- Fully offline and server-independent.
- No provider, host, account, or business metadata leakage.
- No clock dependency or sortable-ID semantic trap.
- Simple deterministic encoding with a small cross-language conformance surface.
- Reuses the existing OpaqueId semantic domain and SQLite TEXT storage without migration.

## Disadvantages

- Generated IDs are not human-friendly or time-sortable.
- Random uniqueness is probabilistic rather than coordinated.
- Storage/creation boundaries still need normal collision handling.

## Risks

A broken platform RNG can prevent generation; this fails closed rather than degrading security. Consumers might still try to parse or order the hex token, so specifications and architecture gates explicitly forbid attaching semantics to its representation.

## Security impact

Positive. Native IDs do not embed predictable counters or metadata and have 128 bits of OS-CSPRNG entropy. This reduces enumeration risk but does not replace authorization. RNG failure maps to an internal failure and never falls back to a predictable generator.

## Privacy impact

Positive. Generated IDs contain no time, network, device, provider, user, or business metadata.

## Compatibility impact

No protobuf field, field number, OpaqueId validation rule, fingerprint encoding, or SQLite schema changes. The algorithm governs newly generated native IDs only. Existing/imported valid OpaqueIds remain valid.

## Migration strategy

No persisted-ID migration is required. New Rust native creation paths use `ucr-core::generate_opaque_id`; other SDKs obtain secure platform entropy and apply the protocol-owned random-hex-v1 encoding. Existing IDs remain untouched. Future SDKs must implement the same random-hex-v1 default when claiming native UCR ID-generation conformance.

## Rollback strategy

The source change can be reverted before consumers depend on this generator. Once published as a supported generation algorithm, replacement requires a new ADR and algorithm identifier; existing IDs must remain valid.

## Testing strategy

Required evidence: a fixed 16-byte golden encoding vector, exact 32-character lowercase-hex output, explicit simulated OS-random failure with no fallback, production OS-CSPRNG smoke coverage, stable canonical error mapping, pinned dependency/governance checks, and architecture gates proving that no time/server/provider input participates.

## Rejected alternatives

- UUIDv7/ULID/time-ordered IDs: rejected because UCR does not need ID chronology and time-bearing formats encourage ordering/privacy assumptions.
- Server/database sequences: rejected by offline/local-first Canon requirements.
- Provider/account-derived IDs: rejected by Identity/Provider separation.
- Deterministic content hashes: rejected because equal content is not canonical entity identity and can leak correlations.
- Weak or seeded application PRNG: rejected because predictable state creates enumeration/collision risk.
- Restrict all inbound OpaqueIds to random-hex-v1: rejected because generation policy is not the wire semantic domain and would break compatible existing/imported IDs.
