use sha2::{Digest, Sha256};
use ucr_model::{PrincipalKind, ServiceAuditOutcome, ServiceAuditRecord, ServiceQuotaPolicy};

use crate::validate_namespaced_identifier;

pub const SERVICE_AUDIT_HASH_V1_DOMAIN: &[u8] = b"UCR-SERVICE-AUDIT-HASH-V1\0";
pub const SERVICE_AUDIT_HASH_LEN: usize = 32;
pub const MAX_SERVICE_AUDIT_READ_ITEMS: usize = 1024;
pub const MAX_SERVICE_REQUEST_PERMISSION_LEN: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceControlValidationError {
    NotServiceAccount,
    InvalidQuota,
    InvalidPermission,
    InvalidTimestamp,
    InvalidAuditSubject,
}

/// Validates one explicit fixed-window Service Principal request quota.
///
/// # Errors
/// Rejects non-service principals and zero/SQLite-incompatible quota values.
pub fn validate_service_quota_policy(
    policy: &ServiceQuotaPolicy,
) -> Result<(), ServiceControlValidationError> {
    if policy.subject.principal.kind != PrincipalKind::ServiceAccount {
        return Err(ServiceControlValidationError::NotServiceAccount);
    }
    if policy.max_requests == 0
        || policy.window_ms == 0
        || policy.max_requests > i64::MAX as u64
        || policy.window_ms > i64::MAX as u64
    {
        return Err(ServiceControlValidationError::InvalidQuota);
    }
    Ok(())
}

/// Validates one metadata-only Service Principal admission audit record.
///
/// # Errors
/// Rejects malformed permission/timestamp fields or inconsistent resolved-subject state.
pub fn validate_service_audit_record(
    record: &ServiceAuditRecord,
) -> Result<(), ServiceControlValidationError> {
    if record.permission.len() > MAX_SERVICE_REQUEST_PERMISSION_LEN {
        return Err(ServiceControlValidationError::InvalidPermission);
    }
    validate_namespaced_identifier(&record.permission)
        .map_err(|_| ServiceControlValidationError::InvalidPermission)?;
    if record.occurred_at_unix_ms < 0 {
        return Err(ServiceControlValidationError::InvalidTimestamp);
    }
    match record.outcome {
        ServiceAuditOutcome::AuthenticationFailed
        | ServiceAuditOutcome::AuthenticationUnavailable => {
            if record.subject.is_some() {
                return Err(ServiceControlValidationError::InvalidAuditSubject);
            }
        }
        ServiceAuditOutcome::RateLimited
        | ServiceAuditOutcome::QuotaUnavailable
        | ServiceAuditOutcome::PermissionDenied
        | ServiceAuditOutcome::AuthorizationUnavailable
        | ServiceAuditOutcome::Authorized => {
            let Some(subject) = &record.subject else {
                return Err(ServiceControlValidationError::InvalidAuditSubject);
            };
            if subject.principal.kind != PrincipalKind::ServiceAccount
                || subject.scope != record.presented_scope
            {
                return Err(ServiceControlValidationError::InvalidAuditSubject);
            }
        }
    }
    Ok(())
}

/// Computes the canonical tamper-evident hash for one append-only audit record.
///
/// # Panics
/// Panics only if an already-bounded canonical identifier exceeds `u32::MAX` bytes.
#[must_use]
pub fn service_audit_hash(
    previous_hash: [u8; SERVICE_AUDIT_HASH_LEN],
    record: &ServiceAuditRecord,
) -> [u8; SERVICE_AUDIT_HASH_LEN] {
    let mut hash = Sha256::new();
    hash.update(SERVICE_AUDIT_HASH_V1_DOMAIN);
    hash.update(previous_hash);
    hash_id(&mut hash, record.audit_id.as_opaque().as_wire_bytes());
    hash_id(&mut hash, record.credential_id.as_opaque().as_wire_bytes());
    hash_scope(&mut hash, &record.presented_scope);
    match &record.subject {
        Some(subject) => {
            hash.update([1]);
            hash_scope(&mut hash, &subject.scope);
            hash_id(
                &mut hash,
                subject.principal.principal_id.as_opaque().as_wire_bytes(),
            );
        }
        None => hash.update([0]),
    }
    hash_id(&mut hash, record.permission.as_bytes());
    hash_scope(&mut hash, &record.resource_scope);
    hash.update([audit_outcome_code(record.outcome)]);
    hash.update(record.occurred_at_unix_ms.to_be_bytes());
    hash.finalize().into()
}

fn hash_scope(hash: &mut Sha256, scope: &ucr_model::TenantScope) {
    hash_id(hash, scope.tenant_id.as_opaque().as_wire_bytes());
    match &scope.namespace_id {
        Some(namespace) => {
            hash.update([1]);
            hash_id(hash, namespace.as_opaque().as_wire_bytes());
        }
        None => hash.update([0]),
    }
}

fn hash_id(hash: &mut Sha256, value: &[u8]) {
    let length =
        u32::try_from(value.len()).expect("canonical identifiers are bounded below u32::MAX");
    hash.update(length.to_be_bytes());
    hash.update(value);
}

const fn audit_outcome_code(outcome: ServiceAuditOutcome) -> u8 {
    match outcome {
        ServiceAuditOutcome::AuthenticationFailed => 1,
        ServiceAuditOutcome::AuthenticationUnavailable => 2,
        ServiceAuditOutcome::RateLimited => 3,
        ServiceAuditOutcome::QuotaUnavailable => 4,
        ServiceAuditOutcome::PermissionDenied => 5,
        ServiceAuditOutcome::AuthorizationUnavailable => 6,
        ServiceAuditOutcome::Authorized => 7,
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use ucr_model::{
        AuditRecordId, NamespaceId, OpaqueId, PrincipalId, PrincipalRef, ScopedPrincipal,
        ServiceAuditOutcome, ServiceAuditRecord, ServiceCredentialId, ServiceQuotaPolicy, TenantId,
        TenantScope,
    };

    use super::*;

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("valid id")
    }

    fn scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(oid("tenant-a")),
            namespace_id: Some(NamespaceId::from_opaque(oid("ns-a"))),
        }
    }

    fn subject() -> ScopedPrincipal {
        ScopedPrincipal {
            scope: scope(),
            principal: PrincipalRef {
                principal_id: PrincipalId::from_opaque(oid("svc-a")),
                kind: PrincipalKind::ServiceAccount,
            },
        }
    }

    fn record() -> ServiceAuditRecord {
        ServiceAuditRecord {
            audit_id: AuditRecordId::from_opaque(oid("audit-a")),
            credential_id: ServiceCredentialId::from_opaque(oid("credential-a")),
            presented_scope: scope(),
            subject: Some(subject()),
            permission: "ucr.message.read".to_owned(),
            resource_scope: scope(),
            outcome: ServiceAuditOutcome::Authorized,
            occurred_at_unix_ms: 1_000,
        }
    }

    #[test]
    fn quota_policy_is_explicit_nonzero_and_service_account_only() {
        let mut policy = ServiceQuotaPolicy {
            subject: subject(),
            max_requests: 10,
            window_ms: 1_000,
        };
        assert_eq!(validate_service_quota_policy(&policy), Ok(()));
        policy.max_requests = 0;
        assert_eq!(
            validate_service_quota_policy(&policy),
            Err(ServiceControlValidationError::InvalidQuota)
        );
        policy.max_requests = 10;
        policy.subject.principal.kind = PrincipalKind::Person;
        assert_eq!(
            validate_service_quota_policy(&policy),
            Err(ServiceControlValidationError::NotServiceAccount)
        );
    }

    #[test]
    fn audit_subject_presence_matches_authentication_outcome() {
        let mut audit = record();
        assert_eq!(validate_service_audit_record(&audit), Ok(()));
        audit.outcome = ServiceAuditOutcome::AuthenticationFailed;
        assert_eq!(
            validate_service_audit_record(&audit),
            Err(ServiceControlValidationError::InvalidAuditSubject)
        );
        audit.subject = None;
        assert_eq!(validate_service_audit_record(&audit), Ok(()));
    }

    #[test]
    fn audit_hash_has_stable_golden_vector_and_binds_decision_metadata() {
        let audit = record();
        let digest = service_audit_hash([0_u8; 32], &audit);
        let mut actual = String::with_capacity(64);
        for byte in digest {
            write!(&mut actual, "{byte:02x}").expect("write hex");
        }
        assert_eq!(
            actual,
            "722e882fce879eb31f509d6deaedea36208817adac3bb99138e025907711efa4"
        );
        let mut changed = audit;
        changed.outcome = ServiceAuditOutcome::PermissionDenied;
        assert_ne!(digest, service_audit_hash([0_u8; 32], &changed));
        assert_ne!(digest, service_audit_hash([9_u8; 32], &changed));
    }
}
