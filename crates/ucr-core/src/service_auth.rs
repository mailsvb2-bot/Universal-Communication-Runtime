use core::fmt;

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use ucr_model::{
    PrincipalKind, ScopedPrincipal, ServiceCredentialId, ServiceCredentialRecord,
    ServiceCredentialState, TenantScope,
};
use zeroize::Zeroize;

use ucr_protocol::{CanonicalError, CanonicalErrorCode};

use crate::{DurableStoreError, IdGenerationError, ServiceCredentialStore, generate_opaque_id};

const SERVICE_CREDENTIAL_DIGEST_V1_DOMAIN: &[u8] = b"UCR-SERVICE-CREDENTIAL-DIGEST-V1\0";
const SERVICE_CREDENTIAL_SECRET_LEN: usize = 32;

#[derive(Clone, PartialEq, Eq)]
pub struct ServiceCredentialSecret([u8; SERVICE_CREDENTIAL_SECRET_LEN]);

impl ServiceCredentialSecret {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SERVICE_CREDENTIAL_SECRET_LEN]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SERVICE_CREDENTIAL_SECRET_LEN] {
        &self.0
    }
}

impl Drop for ServiceCredentialSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for ServiceCredentialSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ServiceCredentialSecret")
            .field(&"<secret>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceCredentialIssueError {
    NotServiceAccount,
    EntropyUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceAuthenticationError {
    AuthenticationFailed,
    Store(DurableStoreError),
}

impl From<ServiceAuthenticationError> for CanonicalError {
    fn from(error: ServiceAuthenticationError) -> Self {
        let code = match error {
            ServiceAuthenticationError::AuthenticationFailed => CanonicalErrorCode::Unauthenticated,
            ServiceAuthenticationError::Store(DurableStoreError::Full) => {
                CanonicalErrorCode::ResourceExhausted
            }
            ServiceAuthenticationError::Store(DurableStoreError::Unavailable) => {
                CanonicalErrorCode::TemporarilyUnavailable
            }
            ServiceAuthenticationError::Store(DurableStoreError::PermissionDenied) => {
                CanonicalErrorCode::PermissionDenied
            }
            ServiceAuthenticationError::Store(
                DurableStoreError::InvalidRecord
                | DurableStoreError::Conflict
                | DurableStoreError::Corrupt
                | DurableStoreError::UnsupportedSchemaVersion
                | DurableStoreError::ForeignStore
                | DurableStoreError::Internal,
            ) => CanonicalErrorCode::Internal,
        };
        Self::new(code)
    }
}

/// Creates a credential record plus a one-time plaintext secret for a canonical
/// Service Account principal. The record contains only a one-way digest.
///
/// # Errors
/// Returns `NotServiceAccount` for any non-ServiceAccount principal and fails
/// closed if OS entropy is unavailable.
pub fn issue_service_credential(
    subject: &ScopedPrincipal,
) -> Result<(ServiceCredentialRecord, ServiceCredentialSecret), ServiceCredentialIssueError> {
    if subject.principal.kind != PrincipalKind::ServiceAccount {
        return Err(ServiceCredentialIssueError::NotServiceAccount);
    }
    let credential_id =
        ServiceCredentialId::from_opaque(generate_opaque_id().map_err(map_id_generation_error)?);
    let mut secret = [0_u8; SERVICE_CREDENTIAL_SECRET_LEN];
    getrandom::fill(&mut secret).map_err(|_| ServiceCredentialIssueError::EntropyUnavailable)?;
    let secret = ServiceCredentialSecret::from_bytes(secret);
    let secret_digest = service_credential_digest(subject, &credential_id, &secret);
    Ok((
        ServiceCredentialRecord {
            credential_id,
            subject: subject.clone(),
            secret_digest,
            state: ServiceCredentialState::Active,
        },
        secret,
    ))
}

/// Authenticates one presented service credential without trusting caller-supplied
/// Principal identity. Scope, principal, state, and digest are resolved from the
/// durable credential owner.
///
/// # Errors
/// Missing, revoked, malformed-kind, scope-mismatched, and wrong-secret cases all
/// return the same non-disclosing `AuthenticationFailed` result. Storage failures
/// remain distinguishable for operators without exposing credential validity.
pub fn authenticate_service_principal<S: ServiceCredentialStore>(
    store: &S,
    scope: &TenantScope,
    credential_id: &ServiceCredentialId,
    secret: &ServiceCredentialSecret,
) -> Result<ScopedPrincipal, ServiceAuthenticationError> {
    let Some(record) = store
        .service_credential(scope, credential_id)
        .map_err(ServiceAuthenticationError::Store)?
    else {
        return Err(ServiceAuthenticationError::AuthenticationFailed);
    };

    if record.state != ServiceCredentialState::Active
        || record.subject.scope != *scope
        || record.subject.principal.kind != PrincipalKind::ServiceAccount
    {
        return Err(ServiceAuthenticationError::AuthenticationFailed);
    }
    let expected = service_credential_digest(&record.subject, &record.credential_id, secret);
    if !bool::from(expected.ct_eq(&record.secret_digest)) {
        return Err(ServiceAuthenticationError::AuthenticationFailed);
    }
    Ok(record.subject)
}

fn service_credential_digest(
    subject: &ScopedPrincipal,
    credential_id: &ServiceCredentialId,
    secret: &ServiceCredentialSecret,
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(SERVICE_CREDENTIAL_DIGEST_V1_DOMAIN);
    hash_len_prefixed(
        &mut hash,
        subject.scope.tenant_id.as_opaque().as_wire_bytes(),
    );
    match &subject.scope.namespace_id {
        Some(namespace_id) => {
            hash.update([1]);
            hash_len_prefixed(&mut hash, namespace_id.as_opaque().as_wire_bytes());
        }
        None => hash.update([0]),
    }
    hash_len_prefixed(
        &mut hash,
        subject.principal.principal_id.as_opaque().as_wire_bytes(),
    );
    hash_len_prefixed(&mut hash, credential_id.as_opaque().as_wire_bytes());
    hash.update(secret.as_bytes());
    hash.finalize().into()
}

fn hash_len_prefixed(hash: &mut Sha256, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("OpaqueId is bounded below u32::MAX");
    hash.update(length.to_be_bytes());
    hash.update(value);
}

const fn map_id_generation_error(_: IdGenerationError) -> ServiceCredentialIssueError {
    ServiceCredentialIssueError::EntropyUnavailable
}

#[cfg(test)]
mod tests {
    use ucr_model::{NamespaceId, OpaqueId, PrincipalId, PrincipalRef, TenantId};

    use super::*;

    fn opaque(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("test ID")
    }

    fn service_subject(tenant: &str, namespace: Option<&str>, principal: &str) -> ScopedPrincipal {
        ScopedPrincipal {
            scope: TenantScope {
                tenant_id: TenantId::from_opaque(opaque(tenant)),
                namespace_id: namespace.map(|value| NamespaceId::from_opaque(opaque(value))),
            },
            principal: PrincipalRef {
                principal_id: PrincipalId::from_opaque(opaque(principal)),
                kind: PrincipalKind::ServiceAccount,
            },
        }
    }

    #[test]
    fn digest_is_bound_to_scope_and_principal_and_debug_redacts_secret() {
        let secret = ServiceCredentialSecret::from_bytes([7; 32]);
        let a = service_subject("tenant-a", Some("ns-a"), "svc-a");
        let b = service_subject("tenant-a", Some("ns-b"), "svc-a");
        let c = service_subject("tenant-a", Some("ns-a"), "svc-b");
        let credential_a = ServiceCredentialId::from_opaque(opaque("credential-a"));
        let credential_b = ServiceCredentialId::from_opaque(opaque("credential-b"));
        assert_ne!(
            service_credential_digest(&a, &credential_a, &secret),
            service_credential_digest(&b, &credential_a, &secret)
        );
        assert_ne!(
            service_credential_digest(&a, &credential_a, &secret),
            service_credential_digest(&c, &credential_a, &secret)
        );
        assert_ne!(
            service_credential_digest(&a, &credential_a, &secret),
            service_credential_digest(&a, &credential_b, &secret)
        );
        assert!(!format!("{secret:?}").contains("070707"));
    }

    #[test]
    fn authentication_failure_maps_to_non_retryable_canonical_unauthenticated() {
        let error = CanonicalError::from(ServiceAuthenticationError::AuthenticationFailed);
        assert_eq!(error.code, CanonicalErrorCode::Unauthenticated);
        assert!(!error.retryable);
    }

    #[test]
    fn issuance_rejects_non_service_account() {
        let mut subject = service_subject("tenant-a", None, "person-a");
        subject.principal.kind = PrincipalKind::Person;
        assert_eq!(
            issue_service_credential(&subject),
            Err(ServiceCredentialIssueError::NotServiceAccount)
        );
    }
}
