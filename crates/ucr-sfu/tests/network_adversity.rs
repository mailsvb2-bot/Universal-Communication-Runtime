use ucr_model::{CallId, NamespaceId, OpaqueId, TenantId, TenantScope};
use ucr_sfu::{SfuClusterDirectory, SfuNodeDescriptor, SfuNodeState, SfuPlacementPolicy};

fn id(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("valid opaque id")
}

fn scope() -> TenantScope {
    TenantScope {
        tenant_id: TenantId::from_opaque(id("sfu-adversity-tenant")),
        namespace_id: Some(NamespaceId::from_opaque(id("sfu-adversity-namespace"))),
    }
}

fn node(node_id: OpaqueId) -> SfuNodeDescriptor {
    SfuNodeDescriptor {
        node_id,
        region: "eu-test".to_owned(),
        state: SfuNodeState::Healthy,
        active_sessions: 0,
        max_sessions: 8,
        lease_expires_at_unix_ms: 30_000,
    }
}

#[test]
fn sfu_node_restart_fails_over_without_rebinding_canonical_call() {
    let mut directory = SfuClusterDirectory::default();
    let node_a = id("sfu-node-a");
    let node_b = id("sfu-node-b");
    directory
        .upsert_node(node(node_a.clone()))
        .expect("register node A");
    directory
        .upsert_node(node(node_b.clone()))
        .expect("register node B");

    let scope = scope();
    let call_id = CallId::from_opaque(id("sfu-adversity-call"));
    let policy = SfuPlacementPolicy {
        preferred_region: Some("eu-test".to_owned()),
        allow_cross_region_failover: false,
    };

    let initial = directory
        .place_session(&scope, &call_id, &policy, 10_000)
        .expect("initial placement");
    let failed_node = initial.node_id.clone();
    let surviving_node = if failed_node == node_a {
        node_b
    } else {
        node_a
    };

    directory.remove_node(&failed_node);

    let failed_over = directory
        .place_session(&scope, &call_id, &policy, 10_100)
        .expect("failover placement");
    assert_eq!(failed_over.node_id, surviving_node);
    assert!(!failed_over.retained_sticky_placement);

    directory
        .upsert_node(node(failed_node.clone()))
        .expect("re-register restarted node");

    let after_restart = directory
        .place_session(&scope, &call_id, &policy, 10_200)
        .expect("sticky placement after restart");
    assert_eq!(after_restart.node_id, surviving_node);
    assert!(after_restart.retained_sticky_placement);
    assert_ne!(after_restart.node_id, failed_node);
}
