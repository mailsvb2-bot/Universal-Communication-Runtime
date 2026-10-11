# RT0 metadata-compromise release gate

**Status: NOT MET on the current canonical SQLite call/conference pipeline.**
This document is a security finding and release criterion, not a claim that
deleting one table makes calls anonymous.

## Attacker model and required outcomes

1. **Offline server database theft after a call:** an attacker must not be
   able to reconstruct caller–callee pairs, call times and device associations.
2. **Live server/SFU compromise:** cannot obtain audio/video plaintext or
   endpoint-owned MLS/private signing key material. A malicious HTTP origin
   serving altered browser JavaScript is a separate device-compromise vector:
   a compromised web asset delivery server can steal pre-encryption media.
3. **Relay compromise:** at most bounded live route metadata, no content keys.
   A single relay must not be relied on for strong unlinkability of callers.
4. **Global network observation:** UCR cannot promise traffic-analysis immunity
   simply by using TURN or end-to-end encryption.

## Verified current structural blockers

- `calls`: durable initiator, conversation and call identifier
- `call_participants`: durable participant association per call
- `call_signals`: durable actor and signalling facts
- `conference_join_grants`: durable exact session/call/participant/device link
- `events`: durable `ucr.conference.attendance.*` payload, actor, source
  Device and correlation; integration attendance can include external IDs
- `accepted_commands`: durable original `ucr.conference.join.issue.v1` and
  `ucr.conference.join.revoke.v1` request payloads, potentially containing
  external participant identifiers and conference affiliation **even after
  their join-grant rows are sanitized**. This is an independent privacy blocker.
  Do not silently truncate the idempotency journal; design explicit bounded
  retention / non-identifying replay commitments within the canonical owner.
- `universal_conference_participants`, `group_memberships` and
  `group_mls_transition_admissions`: durable roster/membership evidence

The schema alone demonstrates that deleting attendance logs is insufficient.
A normal developer's full-database backup or compromised storage host sees
those fields without decrypting a single media packet. A running service may
still associate IPs, TURN endpoints, timing, group handles and active sessions.

## Shipped minimization in this workstream

The existing `ConferenceJoinGrantStore` now explicitly sanitizes expired
grant fields, inclusive of expiry, using the same canonical store and the
existing realtime cleanup worker. It erases participant–device–call and
integration identifiers from that one row after a grant cannot authorize a
session, but **retains a revoked/redeemed exact-session tombstone** so replay
of an accepted IssueJoinGrant cannot recreate an old session credential.
The bounded cleanup runs no more often than every 30 seconds, overwrites
at most 4096 rows per pass, is transactional in SQLite and never modifies
unexpired grants. SQLite v51 tracks completed redaction with an explicit
`metadata_redacted` bit and a partial outstanding-work index, not by comparing
user-controlled opaque identifiers to the literal `expired`. An identical
accepted revoke can still acknowledge a retry after the row is sanitized.
The persisted session/conference identifiers remain and
may still correlate with other canonical Events. This is **partial metadata
reduction**, not the post-call graph-secrecy guarantee.
The UCR SQLite connection also enforces `PRAGMA secure_delete=ON`,
so deleted database-page payloads are overwritten instead of left on the
main-file freelist. This does not erase WAL, backups, filesystem snapshots or
historical flash blocks; do not advertise cryptographic deletion. The setting
may impose additional write I/O and requires operational performance review.

`tools/security/metadata_exposure_audit.py --strict path/to/ucr.sqlite3`
is a read-only, aggregate-only, fail-closed diagnostic to measure *indexed*
persistent call/social-graph records on a test snapshot. It neither touches
personal identifiers nor certifies anonymous networking or secure deletion.

## Remaining design change for a real private-call profile

A separately authorized private-call **profile on the existing canonical
Call/Group/Device/Trust/MLS owners** must be designed and approved under Canon.
It must not silently remove mandatory Event audit facts or replay tombstones
that enforce security. Do not create a second trust/crypto engine.

Candidate: operate short-lived call routing and membership associations
only in bounded ephemeral state, retain independent authenticated Device
and public-key lifecycle in canonical trust, use cryptographically random
short-lived connection handles, and avoid durable join/call/attendance
associations for this explicit profile. Restart should safely terminate
an unrecoverable ephemeral session; the client automatically obtains fresh
authorization rather than resurrecting stale trust. Any required durable
security/recovery evidence must be provably unlinkable to both participants
or carry an explicit user-consented retention exception.

A real privacy proof needs independent network/relay placement. The same
machine controlling Identity, signalling, network proxy, SFU and TURN can
reconstruct a live caller pair even if SQLite contains no rows. A malicious
release server can also replace same-origin browser code. Verify signed
client releases/assets, endpoint trust, TLS ingress, relay visibility and
deployment control boundaries. Using `iceTransportPolicy: relay` with one
TURN provider only removes direct peer IP disclosure; it does not conceal the
graph from that TURN/signalling operator.

## Mandatory end-to-end test before a production privacy claim

- Two independently authenticated devices perform the **one-click** call
  through real NAT/TURN, encrypted bidirectional audio/video and verified MLS.
- Terminate and wait through all leases and bounded cleanup. Power-cycle API,
  then audit the actual canonical database and all backups, WAL, event journal,
  recording/conference/bridge projections and selected integration logs.
- An attacker with the complete server storage snapshot must fail to recover
  the caller–callee link. The test must include a phone/contact lookup if any
  provider adapter is enabled.
- An attacker with the live SFU database/process must fail to obtain audio
  or video plaintext; proof must exclude secret-bearing observability.
- An attacker controlling one relay must not observe the two parties through
  an implicit shared routing/identity key; cross-relay and traffic-correlation
  limits must be explicit.
- Steal/replace public signing-key metadata: endpoints must reject forged key
  substitutions and stale membership before media capture/transmission.
- Security controls cannot require extra user steps beyond operating-system
  permission prompts. No plaintext or identity fallback to make tests pass.

**Release gate remains RED until all of the above pass with real network,
provider, build provenance and compromise artifacts.** Green unit/CI is not
this evidence.
