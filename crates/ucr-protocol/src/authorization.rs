use ucr_model::{
    AuthorizationRequest, PermissionGrant, PermissionScope, PrincipalKind, ScopedPrincipal,
};

use crate::{require_exact_scope, validate_namespaced_identifier};

pub const SERVICE_CREDENTIAL_PROVISION_PERMISSION: &str =
    "ucr.authentication.service_credential.provision";
pub const SERVICE_CREDENTIAL_REVOKE_PERMISSION: &str =
    "ucr.authentication.service_credential.revoke";
pub const SERVICE_QUOTA_READ_PERMISSION: &str = "ucr.authorization.service_quota.read";
pub const SERVICE_QUOTA_WRITE_PERMISSION: &str = "ucr.authorization.service_quota.write";
pub const SERVICE_AUDIT_READ_PERMISSION: &str = "ucr.audit.service_principal.read";
pub const TRUSTED_SIGNING_KEY_PROVISION_PERMISSION: &str =
    "ucr.crypto.trusted_signing_key.provision";
pub const TRUSTED_SIGNING_KEY_ROTATE_PERMISSION: &str = "ucr.crypto.trusted_signing_key.rotate";
pub const TRUSTED_SIGNING_KEY_REVOKE_PERMISSION: &str = "ucr.crypto.trusted_signing_key.revoke";
pub const TRUSTED_SIGNING_KEY_READ_PERMISSION: &str = "ucr.crypto.trusted_signing_key.read";
pub const PERMISSION_GRANT_READ_PERMISSION: &str = "ucr.authorization.grant.read";
pub const PERMISSION_GRANT_CREATE_PERMISSION: &str = "ucr.authorization.grant.create";
pub const PERMISSION_GRANT_REVOKE_PERMISSION: &str = "ucr.authorization.grant.revoke";
pub const RECOVERY_PLAN_READ_PERMISSION: &str = "ucr.recovery.plan.read";
pub const RECOVERY_PLAN_INSTALL_PERMISSION: &str = "ucr.recovery.plan.install";
pub const RECOVERY_PLAN_ROTATE_PERMISSION: &str = "ucr.recovery.plan.rotate";
pub const RECOVERY_PLAN_REVOKE_PERMISSION: &str = "ucr.recovery.plan.revoke";
pub const COMMAND_ACCEPT_PERMISSION: &str = "ucr.command.accept";
pub const COMMAND_OUTCOME_READ_PERMISSION: &str = "ucr.command.outcome.read";
pub const COMMAND_OUTCOME_WRITE_PERMISSION: &str = "ucr.command.outcome.write";
pub const CONVERSATION_READ_PERMISSION: &str = "ucr.conversation.read";
pub const CONVERSATION_WRITE_PERMISSION: &str = "ucr.conversation.write";
pub const MESSAGE_READ_PERMISSION: &str = "ucr.message.read";
pub const MESSAGE_WRITE_PERMISSION: &str = "ucr.message.write";
pub const DELIVERY_READ_PERMISSION: &str = "ucr.delivery.read";
pub const DELIVERY_WRITE_PERMISSION: &str = "ucr.delivery.write";
pub const SYNC_READ_PERMISSION: &str = "ucr.sync.read";
pub const SYNC_WRITE_PERMISSION: &str = "ucr.sync.write";
pub const ANTI_ENTROPY_READ_PERMISSION: &str = "ucr.sync.anti_entropy.read";
pub const ANTI_ENTROPY_RECONCILE_PERMISSION: &str = "ucr.sync.anti_entropy.reconcile";
pub const EVENT_APPEND_PERMISSION: &str = "ucr.event.append";

pub const RUNTIME_PERMISSION_IDS: &[&str] = &[
    SERVICE_CREDENTIAL_PROVISION_PERMISSION,
    SERVICE_CREDENTIAL_REVOKE_PERMISSION,
    SERVICE_QUOTA_READ_PERMISSION,
    SERVICE_QUOTA_WRITE_PERMISSION,
    SERVICE_AUDIT_READ_PERMISSION,
    PERMISSION_GRANT_READ_PERMISSION,
    PERMISSION_GRANT_CREATE_PERMISSION,
    PERMISSION_GRANT_REVOKE_PERMISSION,
    TRUSTED_SIGNING_KEY_READ_PERMISSION,
    TRUSTED_SIGNING_KEY_PROVISION_PERMISSION,
    TRUSTED_SIGNING_KEY_ROTATE_PERMISSION,
    TRUSTED_SIGNING_KEY_REVOKE_PERMISSION,
    RECOVERY_PLAN_READ_PERMISSION,
    RECOVERY_PLAN_INSTALL_PERMISSION,
    RECOVERY_PLAN_ROTATE_PERMISSION,
    RECOVERY_PLAN_REVOKE_PERMISSION,
    COMMAND_ACCEPT_PERMISSION,
    COMMAND_OUTCOME_READ_PERMISSION,
    COMMAND_OUTCOME_WRITE_PERMISSION,
    CONVERSATION_READ_PERMISSION,
    CONVERSATION_WRITE_PERMISSION,
    MESSAGE_READ_PERMISSION,
    MESSAGE_WRITE_PERMISSION,
    DELIVERY_READ_PERMISSION,
    DELIVERY_WRITE_PERMISSION,
    SYNC_READ_PERMISSION,
    SYNC_WRITE_PERMISSION,
    ANTI_ENTROPY_READ_PERMISSION,
    ANTI_ENTROPY_RECONCILE_PERMISSION,
    EVENT_APPEND_PERMISSION,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantValidationError {
    InvalidPermission,
    CrossTenantScope,
    ScopeOutsidePrincipalBinding,
    TenantWideRequiresTenantRoot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationError {
    InvalidPermission,
    InvalidGrant,
    PermissionDenied,
}

/// A Service Principal is represented by the canonical Principal vocabulary,
/// not by a parallel authentication identity type.
#[must_use]
pub const fn is_service_principal(subject: &ScopedPrincipal) -> bool {
    matches!(subject.principal.kind, PrincipalKind::ServiceAccount)
}

/// Validates one permission grant before it becomes authorization state.
///
/// # Errors
/// Rejects malformed permission identifiers or grants that escape the
/// grantee's tenant/namespace binding.
pub fn validate_permission_grant(grant: &PermissionGrant) -> Result<(), GrantValidationError> {
    validate_namespaced_identifier(&grant.permission)
        .map_err(|_| GrantValidationError::InvalidPermission)?;

    match &grant.scope {
        PermissionScope::Exact(scope) => {
            if grant.grantee.scope.tenant_id != scope.tenant_id {
                return Err(GrantValidationError::CrossTenantScope);
            }
            if let Some(bound_namespace) = &grant.grantee.scope.namespace_id
                && scope.namespace_id.as_ref() != Some(bound_namespace)
            {
                return Err(GrantValidationError::ScopeOutsidePrincipalBinding);
            }
        }
        PermissionScope::TenantWide(tenant_id) => {
            if grant.grantee.scope.tenant_id != *tenant_id {
                return Err(GrantValidationError::CrossTenantScope);
            }
            if grant.grantee.scope.namespace_id.is_some() {
                return Err(GrantValidationError::TenantWideRequiresTenantRoot);
            }
        }
    }
    Ok(())
}

/// Evaluates permission grants with deny-by-default semantics.
///
/// # Errors
/// Returns an explicit failure for malformed permission input, corrupted grant
/// state, or lack of an applicable grant.
pub fn authorize(
    request: &AuthorizationRequest,
    grants: &[PermissionGrant],
) -> Result<(), AuthorizationError> {
    validate_namespaced_identifier(&request.permission)
        .map_err(|_| AuthorizationError::InvalidPermission)?;

    for grant in grants {
        if grant.grantee != request.subject {
            continue;
        }
        validate_permission_grant(grant).map_err(|_| AuthorizationError::InvalidGrant)?;
        if grant.permission != request.permission {
            continue;
        }
        let applies = match &grant.scope {
            PermissionScope::Exact(scope) => {
                require_exact_scope(scope, &request.resource_scope).is_ok()
            }
            PermissionScope::TenantWide(tenant_id) => {
                request.resource_scope.tenant_id == *tenant_id
            }
        };
        if applies {
            return Ok(());
        }
    }

    Err(AuthorizationError::PermissionDenied)
}

#[cfg(test)]
mod tests {
    use ucr_model::{
        AuthorizationRequest, NamespaceId, OpaqueId, PermissionGrant, PermissionScope, PrincipalId,
        PrincipalKind, PrincipalRef, ScopedPrincipal, TenantId, TenantScope,
    };

    use super::{
        AuthorizationError, GrantValidationError, RUNTIME_PERMISSION_IDS, authorize,
        is_service_principal, validate_namespaced_identifier, validate_permission_grant,
    };

    fn opaque(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("valid id")
    }

    fn scope(tenant: &str, namespace: Option<&str>) -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(opaque(tenant)),
            namespace_id: namespace.map(|value| NamespaceId::from_opaque(opaque(value))),
        }
    }

    fn principal(tenant: &str, namespace: Option<&str>, kind: PrincipalKind) -> ScopedPrincipal {
        ScopedPrincipal {
            scope: scope(tenant, namespace),
            principal: PrincipalRef {
                principal_id: PrincipalId::from_opaque(opaque("principal-a")),
                kind,
            },
        }
    }

    fn request(subject: ScopedPrincipal, namespace: Option<&str>) -> AuthorizationRequest {
        AuthorizationRequest {
            subject,
            permission: "ucr.message.send".to_owned(),
            resource_scope: scope("tenant-a", namespace),
        }
    }

    fn exact_grant(grantee: ScopedPrincipal, namespace: Option<&str>) -> PermissionGrant {
        PermissionGrant {
            grantee,
            permission: "ucr.message.send".to_owned(),
            scope: PermissionScope::Exact(scope("tenant-a", namespace)),
        }
    }

    #[test]
    fn deny_by_default_without_grant() {
        let subject = principal("tenant-a", Some("namespace-a"), PrincipalKind::Person);
        assert_eq!(
            authorize(&request(subject, Some("namespace-a")), &[]),
            Err(AuthorizationError::PermissionDenied)
        );
    }

    #[test]
    fn exact_grant_authorizes_only_exact_scope() {
        let subject = principal("tenant-a", Some("namespace-a"), PrincipalKind::Person);
        let grant = exact_grant(subject.clone(), Some("namespace-a"));
        assert_eq!(
            authorize(
                &request(subject.clone(), Some("namespace-a")),
                std::slice::from_ref(&grant)
            ),
            Ok(())
        );
        assert_eq!(
            authorize(&request(subject, Some("namespace-b")), &[grant]),
            Err(AuthorizationError::PermissionDenied)
        );
    }

    #[test]
    fn tenant_wide_grant_requires_tenant_root_principal() {
        let namespace_subject = principal(
            "tenant-a",
            Some("namespace-a"),
            PrincipalKind::ServiceAccount,
        );
        let invalid = PermissionGrant {
            grantee: namespace_subject,
            permission: "ucr.message.send".to_owned(),
            scope: PermissionScope::TenantWide(TenantId::from_opaque(opaque("tenant-a"))),
        };
        assert_eq!(
            validate_permission_grant(&invalid),
            Err(GrantValidationError::TenantWideRequiresTenantRoot)
        );
    }

    #[test]
    fn explicit_tenant_wide_grant_authorizes_namespaces_in_same_tenant() {
        let subject = principal("tenant-a", None, PrincipalKind::ServiceAccount);
        let grant = PermissionGrant {
            grantee: subject.clone(),
            permission: "ucr.message.send".to_owned(),
            scope: PermissionScope::TenantWide(TenantId::from_opaque(opaque("tenant-a"))),
        };
        assert_eq!(
            authorize(
                &request(subject.clone(), Some("namespace-a")),
                std::slice::from_ref(&grant)
            ),
            Ok(())
        );
        assert_eq!(
            authorize(&request(subject, Some("namespace-b")), &[grant]),
            Ok(())
        );
    }

    #[test]
    fn namespace_bound_principal_cannot_receive_other_namespace_grant() {
        let subject = principal("tenant-a", Some("namespace-a"), PrincipalKind::Person);
        let invalid = exact_grant(subject, Some("namespace-b"));
        assert_eq!(
            validate_permission_grant(&invalid),
            Err(GrantValidationError::ScopeOutsidePrincipalBinding)
        );
    }

    #[test]
    fn tenant_wide_grant_does_not_cross_tenant() {
        let subject = principal("tenant-a", None, PrincipalKind::ServiceAccount);
        let grant = PermissionGrant {
            grantee: subject.clone(),
            permission: "ucr.message.send".to_owned(),
            scope: PermissionScope::TenantWide(TenantId::from_opaque(opaque("tenant-a"))),
        };
        let mut cross_tenant = request(subject, None);
        cross_tenant.resource_scope = scope("tenant-b", None);
        assert_eq!(
            authorize(&cross_tenant, &[grant]),
            Err(AuthorizationError::PermissionDenied)
        );
    }

    #[test]
    fn service_principal_is_existing_principal_kind_not_parallel_identity() {
        let service = principal("tenant-a", None, PrincipalKind::ServiceAccount);
        let person = principal("tenant-a", None, PrincipalKind::Person);
        assert!(is_service_principal(&service));
        assert!(!is_service_principal(&person));
    }

    #[test]
    fn malformed_persisted_grant_fails_closed() {
        let subject = principal("tenant-a", None, PrincipalKind::ServiceAccount);
        let malformed = PermissionGrant {
            grantee: subject.clone(),
            permission: "send".to_owned(),
            scope: PermissionScope::TenantWide(TenantId::from_opaque(opaque("tenant-a"))),
        };
        assert_eq!(
            authorize(&request(subject, Some("namespace-a")), &[malformed]),
            Err(AuthorizationError::InvalidGrant)
        );
    }
    #[test]
    fn grant_for_other_principal_does_not_authorize() {
        let subject = principal("tenant-a", Some("namespace-a"), PrincipalKind::Person);
        let mut other = principal("tenant-a", Some("namespace-a"), PrincipalKind::Person);
        other.principal.principal_id = PrincipalId::from_opaque(opaque("principal-b"));
        let grant = exact_grant(other, Some("namespace-a"));
        assert_eq!(
            authorize(&request(subject, Some("namespace-a")), &[grant]),
            Err(AuthorizationError::PermissionDenied)
        );
    }

    #[test]
    fn malformed_requested_permission_is_invalid_argument_semantics() {
        let subject = principal("tenant-a", Some("namespace-a"), PrincipalKind::Person);
        let mut request = request(subject, Some("namespace-a"));
        request.permission = "send".to_owned();
        assert_eq!(
            authorize(&request, &[]),
            Err(AuthorizationError::InvalidPermission)
        );
    }

    #[test]
    fn runtime_permission_vocabulary_is_namespaced_and_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for permission in RUNTIME_PERMISSION_IDS {
            assert!(
                validate_namespaced_identifier(permission).is_ok(),
                "invalid runtime permission id: {permission}"
            );
            assert!(
                seen.insert(*permission),
                "duplicate runtime permission id: {permission}"
            );
        }
        assert_eq!(seen.len(), RUNTIME_PERMISSION_IDS.len());
    }
}
