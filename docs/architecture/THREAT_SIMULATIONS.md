# Executable Threat Simulations

Status: **required security evidence for implemented trust boundaries**.

The Canon requires threat tests to exercise the relevant boundary and failure semantics; a unit test whose name merely mentions the threat is insufficient. The dedicated `ucr-security-tests` workspace crate therefore composes public Core, Crypto, Protocol, Memory, and SQLite boundaries as an attacker would encounter them. These tests are executed by the ordinary workspace debug and release CI jobs.

| Threat scenario | Executable evidence | Boundary exercised | Required failure invariant | Status |
|---|---|---|---|---|
| Replay | `replay_simulation_survives_process_restart_and_rejects_duplicate_binding` | crypto replay contract → SQLite durable replay store → restart | exact peer+transcript replay is rejected after restart; a distinct binding still succeeds | Implemented |
| MITM signature substitution | `mitm_simulation_cannot_replace_trusted_peer_signature_or_poison_replay_state` | trusted-key resolver → session signature verification → replay boundary | attacker signature cannot authenticate the trusted peer and failed authentication does not establish session trust | Implemented for local/reference session boundary; production transport MITM remains future transport evidence |
| Forged Identity | `forged_identity_simulation_fails_even_with_valid_device_private_key` | canonical Message signature → trusted key resolver → durable Device→Identity binding | a valid Device private key cannot authenticate a different Identity | Implemented |
| Malicious tenant | `malicious_tenant_simulation_cannot_cross_scope_or_mutate_storage` | `AuthorizedDurableRuntime` → persisted grants → Device store | same operation permission in tenant A cannot mutate tenant B; denied call leaves storage untouched | Implemented |
| Malicious peer claim | `malicious_peer_simulation_cannot_self_provision_claimed_key` | peer-supplied signing descriptor → independent trusted resolver → session | a peer-provided descriptor cannot become trust or replace independently provisioned trust | Implemented |
| Malicious Service Account | `malicious_service_account_simulation_cannot_bypass_admission_proof` | ServiceAccount principal → `AuthorizedDurableRuntime` admission-proof requirement → storage | persisted permission alone cannot bypass authentication/quota admission proof; denied call leaves storage untouched | Implemented |
| Invalid permission | `invalid_permission_simulation_denies_mutation_before_storage` | permission evaluator → runtime mutation façade → Device store | read authority cannot authorize register/write and denial occurs before storage mutation | Implemented |
| Revoked Device | `revoked_device_simulation_denies_existing_signature_and_future_key_access` | Device lifecycle → trusted key lifecycle/resolver → Message verification | revocation invalidates already-signed future authentication and prevents replacement trusted-key provision | Implemented |
| Compromised Bridge | none | Core ↔ Bridge | least privilege, minimum disclosure, canonical failure mapping | **Not implemented: Bridge does not exist yet; a mock is not accepted as evidence** |

## Scope and nonclaims

The MITM scenario exercises the implemented authenticated-session/trust-resolver boundary. It is not a claim that a production network transport exists or that packet-path MITM, routing failover, DNS, relay, or remote peer integration has been tested. Those scenarios remain coupled to the corresponding future transport implementations.

Likewise, the compromised-Bridge scenario stays open until a real Bridge boundary exists. UCR intentionally does not add a fake Bridge solely to make a checklist green. When a Bridge or another new trust boundary is implemented, executable negative scenarios must arrive in the same maturity change rather than inheriting the evidence above.

This document is an evidence index, not a second security policy owner. Normative threat requirements remain in `THREAT_MODEL.md`; canonical authorization, identity, crypto, Device, and storage semantics remain owned by their existing specs and crates.
