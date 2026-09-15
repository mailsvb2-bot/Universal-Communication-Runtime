use ucr_core::{PermissionGrantStore, SyncStore};
use ucr_model::*;
use ucr_personal_node::{PersonalNodeError, PersonalNodeRuntime};
use ucr_protocol::{
    PERSONAL_NODE_MANAGE_PERMISSION, PERSONAL_NODE_READ_PERMISSION, PERSONAL_NODE_USE_PERMISSION,
    SYNC_READ_PERMISSION,
};
use ucr_storage_memory::MemoryLocalStore;

fn oid(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("id")
}

fn scope() -> TenantScope {
    TenantScope {
        tenant_id: TenantId::from_opaque(oid("personal-node-threat-owner")),
        namespace_id: None,
    }
}

fn principal(scope: TenantScope, id: &str) -> ScopedPrincipal {
    ScopedPrincipal {
        scope,
        principal: PrincipalRef {
            principal_id: PrincipalId::from_opaque(oid(id)),
            kind: PrincipalKind::Person,
        },
    }
}
fn grant(store: &MemoryLocalStore, owner: &ScopedPrincipal, permission: &str) {
    store
        .grant_permission(&PermissionGrant {
            grantee: owner.clone(),
            permission: permission.to_owned(),
            scope: PermissionScope::Exact(scope()),
        })
        .expect("grant");
}

fn endpoint() -> EndpointId {
    EndpointId::from_opaque(oid("personal-node-threat-endpoint"))
}

fn profile() -> PersonalNodeProfile {
    PersonalNodeProfile {
        scope: scope(),
        endpoint_id: endpoint(),
        endpoint_kind: EndpointKind::PersonalNode,
        services: vec![
            PersonalNodeService::Sync,
            PersonalNodeService::EncryptedMailbox,
        ],
        state: PersonalNodeState::Active,
        generation: 1,
        mailbox_capacity_bytes: 4096,
        cache_capacity_bytes: 0,
    }
}
#[test]
fn compromised_personal_node_cannot_self_authorize_or_survive_disable() {
    let store = MemoryLocalStore::default();
    let owner = principal(scope(), "personal-node-threat-admin");
    let attacker_scope = TenantScope {
        tenant_id: TenantId::from_opaque(oid("personal-node-threat-attacker-tenant")),
        namespace_id: None,
    };
    let attacker = principal(attacker_scope, "personal-node-threat-attacker");
    for permission in [
        PERSONAL_NODE_MANAGE_PERMISSION,
        PERSONAL_NODE_READ_PERMISSION,
        PERSONAL_NODE_USE_PERMISSION,
        SYNC_READ_PERMISSION,
    ] {
        grant(&store, &owner, permission);
    }
    let runtime = PersonalNodeRuntime::new(&store, &store);

    assert!(matches!(
        runtime.install_profile(&attacker, &profile()),
        Err(PersonalNodeError::Authorization(_))
    ));
    assert!(matches!(
        runtime.profile(&attacker, &scope(), &endpoint()),
        Err(PersonalNodeError::Authorization(_))
    ));
    runtime
        .install_profile(&owner, &profile())
        .expect("owner installs profile");
    let sync_id = SessionId::from_opaque(oid("personal-node-threat-sync"));
    store
        .create_sync_session(&SyncSession {
            session_id: sync_id.clone(),
            scope: scope(),
            source_endpoint_id: EndpointId::from_opaque(oid("personal-node-threat-device")),
            target_endpoint_id: endpoint(),
            link_kind: SyncLinkKind::DeviceNode,
            selection: SyncSelection {
                mode: SyncMode::Full,
                conversation_ids: Vec::new(),
            },
            state: SyncState::Prepared,
        })
        .expect("create sync");
    store
        .transition_sync(&scope(), &sync_id, SyncState::Prepared, SyncState::Active)
        .expect("activate sync");

    runtime
        .admit_sync(&owner, &scope(), &endpoint(), &sync_id)
        .expect("sync before disable");
    runtime
        .transition_profile(
            &owner,
            &scope(),
            &endpoint(),
            1,
            PersonalNodeState::Disabled,
        )
        .expect("disable node");
    assert!(matches!(
        runtime.admit_sync(&owner, &scope(), &endpoint(), &sync_id),
        Err(PersonalNodeError::NodeDisabled)
    ));
    assert_eq!(
        store
            .sync_session(&scope(), &sync_id)
            .expect("sync still exists")
            .expect("sync")
            .state,
        SyncState::Active,
        "Personal Node disable must not rewrite canonical Sync state"
    );
    assert!(matches!(
        runtime.transition_profile(
            &attacker,
            &scope(),
            &endpoint(),
            2,
            PersonalNodeState::Active,
        ),
        Err(PersonalNodeError::Authorization(_))
    ));
}
