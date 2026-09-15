use ucr_core::{DeviceLifecycleStore, IdentityStore, PermissionGrantStore};
use ucr_model::*;
use ucr_organization_mode::{OrganizationModeError, OrganizationModeRuntime};
use ucr_protocol::{
    DEVICE_READ_PERMISSION, IDENTITY_READ_PERMISSION, ORGANIZATION_DEVICE_MANAGE_PERMISSION,
    ORGANIZATION_DISCOVERY_READ_PERMISSION, ORGANIZATION_IDENTITY_MANAGE_PERMISSION,
    ORGANIZATION_MANAGE_PERMISSION, ORGANIZATION_READ_PERMISSION, ORGANIZATION_SFU_USE_PERMISSION,
};
use ucr_storage_memory::MemoryLocalStore;

fn oid(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("id")
}

fn scope() -> TenantScope {
    TenantScope {
        tenant_id: TenantId::from_opaque(oid("organization-threat-tenant")),
        namespace_id: Some(NamespaceId::from_opaque(oid("organization-threat-private"))),
    }
}

fn organization() -> PrincipalRef {
    PrincipalRef {
        principal_id: PrincipalId::from_opaque(oid("organization-threat-owner")),
        kind: PrincipalKind::Organization,
    }
}
fn admin() -> ScopedPrincipal {
    ScopedPrincipal {
        scope: scope(),
        principal: PrincipalRef {
            principal_id: PrincipalId::from_opaque(oid("organization-threat-admin")),
            kind: PrincipalKind::Person,
        },
    }
}

fn compromised_node() -> ScopedPrincipal {
    ScopedPrincipal {
        scope: scope(),
        principal: organization(),
    }
}

fn grant(store: &MemoryLocalStore, permission: &str) {
    store
        .grant_permission(&PermissionGrant {
            grantee: admin(),
            permission: permission.to_owned(),
            scope: PermissionScope::Exact(scope()),
        })
        .expect("grant");
}

fn profile() -> OrganizationModeProfile {
    OrganizationModeProfile {
        scope: scope(),
        organization: organization(),
        endpoint_id: EndpointId::from_opaque(oid("organization-threat-node")),
        endpoint_kind: EndpointKind::OrganizationNode,
        services: vec![
            OrganizationService::PrivateDiscovery,
            OrganizationService::PrivateSfu,
            OrganizationService::ManagedIdentities,
            OrganizationService::ManagedDevices,
        ],
        state: OrganizationModeState::Active,
        generation: 1,
    }
}

fn seed_managed_identity_and_device(
    store: &MemoryLocalStore,
    runtime: &OrganizationModeRuntime<'_, MemoryLocalStore, MemoryLocalStore>,
) -> (IdentityRecord, DeviceDescriptor) {
    let identity = IdentityRecord {
        scope: scope(),
        identity_id: IdentityId::from_opaque(oid("organization-threat-identity")),
        ownership: IdentityOwnership::OrganizationManaged,
        evidence: IdentityEvidence::OrganizationVerified,
        expires_at_unix_ms: None,
    };
    store.persist_identity(&identity).expect("identity");
    runtime
        .bind_managed_identity(
            &admin(),
            &OrganizationManagedIdentityBinding {
                scope: scope(),
                organization: organization(),
                identity_id: identity.identity_id.clone(),
            },
        )
        .expect("identity binding");
    let device = DeviceDescriptor {
        device_id: DeviceId::from_opaque(oid("organization-threat-device")),
        identity_id: identity.identity_id.clone(),
        state: DeviceLifecycleState::Active,
    };
    store.register_device(&scope(), &device).expect("device");
    runtime
        .bind_managed_device(
            &admin(),
            &OrganizationManagedDeviceBinding {
                scope: scope(),
                organization: organization(),
                device_id: device.device_id.clone(),
            },
        )
        .expect("device binding");
    (identity, device)
}

#[test]
fn compromised_organization_node_cannot_self_authorize_or_survive_disable() {
    let store = MemoryLocalStore::default();
    for permission in [
        ORGANIZATION_MANAGE_PERMISSION,
        ORGANIZATION_READ_PERMISSION,
        ORGANIZATION_DISCOVERY_READ_PERMISSION,
        ORGANIZATION_IDENTITY_MANAGE_PERMISSION,
        ORGANIZATION_DEVICE_MANAGE_PERMISSION,
        ORGANIZATION_SFU_USE_PERMISSION,
        IDENTITY_READ_PERMISSION,
        DEVICE_READ_PERMISSION,
    ] {
        grant(&store, permission);
    }
    let runtime = OrganizationModeRuntime::new(&store, &store);
    assert!(matches!(
        runtime.install_profile(&compromised_node(), &profile()),
        Err(OrganizationModeError::Authorization(_))
    ));
    runtime
        .install_profile(&admin(), &profile())
        .expect("authorized admin installs profile");

    let (identity, device) = seed_managed_identity_and_device(&store, &runtime);

    assert_eq!(
        runtime
            .private_directory(&admin(), &scope(), &organization(), 8)
            .expect("private directory"),
        vec![identity.clone()]
    );
    assert!(matches!(
        runtime.private_directory(&compromised_node(), &scope(), &organization(), 8),
        Err(OrganizationModeError::Authorization(_))
    ));

    runtime
        .transition_profile(
            &admin(),
            &scope(),
            &organization(),
            1,
            OrganizationModeState::Disabled,
        )
        .expect("disable");
    assert!(matches!(
        runtime.admit_sfu(&admin(), &scope(), &organization()),
        Err(OrganizationModeError::ModeDisabled)
    ));
    assert_eq!(
        store
            .identity(&scope(), &identity.identity_id)
            .expect("canonical identity")
            .expect("identity remains"),
        identity,
        "Organization Mode disable must not rewrite canonical Identity state"
    );
    assert_eq!(
        store
            .device(&scope(), &device.device_id)
            .expect("canonical device")
            .expect("device remains"),
        device,
        "Organization Mode disable must not rewrite canonical Device state"
    );
    assert!(matches!(
        runtime.transition_profile(
            &compromised_node(),
            &scope(),
            &organization(),
            2,
            OrganizationModeState::Active,
        ),
        Err(OrganizationModeError::Authorization(_))
    ));
}
