use ucr_model::TenantScope;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeRelation {
    Exact,
    SameTenantDifferentNamespace,
    CrossTenant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeError {
    CrossTenant,
    NamespaceMismatch,
}

/// Classifies two explicit tenant/namespace scopes without inferring authority.
#[must_use]
pub fn scope_relation(left: &TenantScope, right: &TenantScope) -> ScopeRelation {
    if left.tenant_id != right.tenant_id {
        return ScopeRelation::CrossTenant;
    }
    if left.namespace_id != right.namespace_id {
        return ScopeRelation::SameTenantDifferentNamespace;
    }
    ScopeRelation::Exact
}

/// Requires exact tenant and namespace equality.
///
/// Absence of a namespace never implies tenant-wide authority. Broader access
/// must be granted explicitly by the authorization layer.
///
/// # Errors
/// Returns a fail-closed error for cross-tenant or cross-namespace access.
pub fn require_exact_scope(
    subject: &TenantScope,
    resource: &TenantScope,
) -> Result<(), ScopeError> {
    match scope_relation(subject, resource) {
        ScopeRelation::Exact => Ok(()),
        ScopeRelation::SameTenantDifferentNamespace => Err(ScopeError::NamespaceMismatch),
        ScopeRelation::CrossTenant => Err(ScopeError::CrossTenant),
    }
}

#[cfg(test)]
mod tests {
    use ucr_model::{NamespaceId, OpaqueId, TenantId, TenantScope};

    use super::{ScopeError, ScopeRelation, require_exact_scope, scope_relation};

    fn opaque(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("valid id")
    }

    fn scope(tenant: &str, namespace: Option<&str>) -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(opaque(tenant)),
            namespace_id: namespace.map(|value| NamespaceId::from_opaque(opaque(value))),
        }
    }

    #[test]
    fn exact_scope_is_accepted() {
        let left = scope("tenant-a", Some("namespace-a"));
        let right = scope("tenant-a", Some("namespace-a"));
        assert_eq!(scope_relation(&left, &right), ScopeRelation::Exact);
        assert_eq!(require_exact_scope(&left, &right), Ok(()));
    }

    #[test]
    fn cross_tenant_access_fails_closed() {
        let subject = scope("tenant-a", Some("namespace-a"));
        let resource = scope("tenant-b", Some("namespace-a"));
        assert_eq!(
            require_exact_scope(&subject, &resource),
            Err(ScopeError::CrossTenant)
        );
    }

    #[test]
    fn cross_namespace_access_fails_closed() {
        let subject = scope("tenant-a", Some("namespace-a"));
        let resource = scope("tenant-a", Some("namespace-b"));
        assert_eq!(
            require_exact_scope(&subject, &resource),
            Err(ScopeError::NamespaceMismatch)
        );
    }

    #[test]
    fn tenant_only_scope_is_not_implicit_namespace_wildcard() {
        let subject = scope("tenant-a", None);
        let resource = scope("tenant-a", Some("namespace-a"));
        assert_eq!(
            require_exact_scope(&subject, &resource),
            Err(ScopeError::NamespaceMismatch)
        );
    }
}
