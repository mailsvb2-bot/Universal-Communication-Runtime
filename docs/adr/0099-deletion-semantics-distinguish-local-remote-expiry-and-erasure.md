# ADR 0099: Deletion semantics distinguish local, remote, expiry and erasure

Status: Accepted

## Context

The Canon requires distinct HIDE_LOCAL, DELETE_LOCAL_COPY, REQUEST_REMOTE_DELETE, DELETE_FOR_EVERYONE, EXPIRE and CRYPTOGRAPHIC_ERASURE semantics and explicitly forbids claiming guaranteed physical deletion from offline or compromised devices.

## Decision

Deletion is an explicit intent/state transition, never a generic destructive `delete` shortcut.

The six canonical semantics are:

- HIDE_LOCAL — presentation/local visibility only;
- DELETE_LOCAL_COPY — removes the authorized local retained copy, subject to protected/audit constraints;
- REQUEST_REMOTE_DELETE — sends a deletion request and records per-target evidence;
- DELETE_FOR_EVERYONE — policy intent composed from remote-delete requests/evidence, not a physical-erasure guarantee;
- EXPIRE — lifecycle-driven transition after explicit expiry;
- CRYPTOGRAPHIC_ERASURE — destroys controlled key material where that makes retained ciphertext unreadable.

Remote deletion tracks requested/acknowledged/pending outcomes. A missing acknowledgement is not success. Already extracted data on a compromised or offline peer is outside any absolute deletion guarantee.

## Consequences

UCR can report deletion truthfully and reconcile partial outcomes without silent loss or false “deleted everywhere” claims.
