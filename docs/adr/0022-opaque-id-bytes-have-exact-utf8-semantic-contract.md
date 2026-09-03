# ADR-0022: OpaqueId bytes have an exact UTF-8 semantic contract

Status: Accepted

Date: 2026-09-03

## Context

The Phase-0 bootstrap introduced two representations in the same commit without documenting how they relate: public `ucr.v1.OpaqueId.value` is protobuf `bytes`, while the Rust reference `OpaqueId` owns a bounded `String`. The Canon requires canonical IDs to be generated offline and independent of IP, hostname, server database sequence, and provider ID. It also states that Specification outlives Implementation and that Rust structures do not define the Protocol. The Canon does not select UUID, ULID, arbitrary binary IDs, or another concrete ID encoding.

Leaving the boundary implicit is unsafe. A non-Rust implementation could treat every protobuf byte sequence as canonical while the reference runtime, SQLite TEXT keys, and Phase-12 Event fingerprint only represent UTF-8 tokens. Conversely, simply widening Rust to arbitrary bytes would change durable key representation and canonical fingerprint encoding without a Canon requirement or migration plan.

The protocol is still experimental, but `OpaqueId.value` field number/type, SQLite state, and the SHA256_V1 Event fingerprint already have compatibility evidence that should not be casually invalidated.

## Decision

The v1 protobuf field remains `bytes value = 1`. Its canonical semantic domain is an exact, non-empty valid UTF-8 token whose encoded length is at most 128 bytes.

Semantic decoding rejects empty, invalid-UTF-8, and over-budget values. No Unicode normalization, case folding, trimming, transliteration, or provider-specific interpretation is performed. Equality and ordering operate on the exact token representation; byte-distinct tokens remain distinct even if they render similarly.

The Rust `OpaqueId` remains the single reference representation owner. It exposes `from_wire_bytes` and `as_wire_bytes`; no parallel binary-ID type is introduced. `OpaqueId::new` and wire decoding share the same byte-budget validation.

Canonical Event fingerprints and Anti-Entropy session bindings consume `OpaqueId::as_wire_bytes()` directly. SHA256_V1 remains byte-for-byte compatible with the existing golden vector because existing valid Rust IDs already encode to the same UTF-8 bytes.

The SQLite reference store keeps canonical IDs in TEXT columns. This is lossless for the defined semantic domain, so no schema migration or base64/hex adaptation layer is added. A restart regression test covers non-ASCII canonical IDs.

The concrete offline ID generation algorithm remains undecided. This ADR defines representation and decode validity, not UUID/ULID/key-derived/random generation.

## Error semantics

Empty or invalid UTF-8 wire values map to canonical `InvalidArgument`. Values exceeding the 128-byte semantic budget map to `ResourceExhausted`.

## Compatibility impact

The protobuf field number and type do not change. Existing Rust/reference-store IDs remain valid and retain exact fingerprints and durable keys. Implementations that previously accepted arbitrary non-UTF-8 protobuf bytes must now reject those values at semantic decoding because they were never representable by the reference canonical model.

Changing the `.proto` field from `bytes` to `string` is not done: even though both use protobuf length-delimited wire encoding, it changes generated public APIs and validation behavior. v1 keeps the existing public schema surface and makes its semantic constraint explicit instead.

## Security and privacy impact

Opaque IDs remain non-display, non-authority values. Exact-byte preservation prevents ambiguous hidden normalization rules from merging two identities. Applications must not infer identity evidence from visual similarity of Unicode tokens. Invalid input fails closed rather than being lossy-decoded or replaced.

## Migration and rollback

No durable migration is required. Existing SQLite TEXT data already lies inside the chosen semantic domain. Rollback to an implementation without explicit wire-byte helpers preserves stored data, but would reintroduce an underspecified public boundary and is therefore not a compliant long-term state.

## Testing strategy

Required evidence includes exact UTF-8 wire round-trip, invalid UTF-8 rejection, byte—not character—budget tests including multibyte text, no-normalization distinctness, canonical error mapping, unchanged Event fingerprint golden vector, SQLite restart/deduplication with non-ASCII IDs, protobuf compilation, and architecture gates binding specification/protobuf/Rust/fingerprint semantics.

## Rejected alternatives

- Admit arbitrary binary IDs immediately: rejected because it requires coordinated Rust, SQLite, fingerprint, export/API, and compatibility migration without a Canon requirement.
- Base64/hex-wrap arbitrary bytes inside the existing Rust String: rejected because it creates a second representation and changes equality/fingerprint semantics.
- Change protobuf `bytes` to `string` in place: rejected because it changes generated public APIs and validation behavior for no wire-level benefit in v1.
- Apply Unicode normalization or case folding: rejected because opaque identity must not silently merge byte-distinct values.
- Pick UUID or ULID here: rejected because generation strategy is separate from canonical representation and still requires its own production ADR.
