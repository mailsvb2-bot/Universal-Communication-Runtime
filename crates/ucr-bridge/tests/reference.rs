use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};

use ucr_bridge::{
    BridgeError, BridgeProvider, BridgeProviderFailure, BridgeProviderFailureKind, BridgeRuntime,
};
use ucr_core::{
    AuthorizationEvaluator, BridgeActionStore, BridgeRegistrationStore, ConversationStore,
    DurableRecordStatus, DurableStoreError, MessageStore, StorageHealth, StorageProvider,
};
use ucr_model::{
    ActorId, ActorKind, ActorRef, AuthorizationRequest, BridgeAction, BridgeActionId,
    BridgeActionRecord, BridgeActionState, BridgeCapability, BridgeDataPermission,
    BridgeDegradation, BridgeDegradationReason, BridgeEventCursor, BridgeEventPage,
    BridgeInboundEvent, BridgeProviderAcceptance, BridgeProviderManifest, BridgeRegistration,
    BridgeRegistrationState, ConversationId, ConversationKind, ConversationRecord, ConversationRef,
    CorrelationContext, DeliveryPolicy, DeliveryState, DeviceId, DeviceRef, IdentityId,
    IntegrationId, MessageEnvelope, MessageId, NamespaceId, OpaqueId, OriginRef, PrincipalId,
    PrincipalKind, PrincipalRef, ProtocolVersion, ScopedPrincipal, TenantId, TenantScope,
};
use ucr_protocol::{
    BRIDGE_EXECUTE_PERMISSION, BRIDGE_SDK_VERSION, CanonicalError, CanonicalErrorCode,
    bridge_action_fingerprint,
};
use ucr_storage_memory::MemoryLocalStore;

#[derive(Debug, Default, Clone, Copy)]
struct AllowAll;
impl AuthorizationEvaluator for AllowAll {
    fn authorize(&self, _request: &AuthorizationRequest) -> Result<(), CanonicalError> {
        Ok(())
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct DenyExecute;
impl AuthorizationEvaluator for DenyExecute {
    fn authorize(&self, request: &AuthorizationRequest) -> Result<(), CanonicalError> {
        if request.permission == BRIDGE_EXECUTE_PERMISSION {
            Err(CanonicalError::new(CanonicalErrorCode::PermissionDenied))
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone)]
enum ExecuteStep {
    Accept(BridgeProviderAcceptance),
    Fail(BridgeProviderFailure),
}

#[derive(Debug)]
struct TestProvider {
    manifest: Mutex<BridgeProviderManifest>,
    steps: Mutex<Vec<ExecuteStep>>,
    execute_count: Mutex<usize>,
    page: Mutex<BridgeEventPage>,
}

impl TestProvider {
    fn new(manifest: BridgeProviderManifest, steps: Vec<ExecuteStep>) -> Self {
        Self {
            manifest: Mutex::new(manifest),
            steps: Mutex::new(steps.into_iter().rev().collect()),
            execute_count: Mutex::new(0),
            page: Mutex::new(BridgeEventPage {
                events: vec![],
                next_cursor: None,
            }),
        }
    }

    fn count(&self) -> usize {
        *self.execute_count.lock().expect("count")
    }

    fn replace_manifest(&self, manifest: BridgeProviderManifest) {
        *self.manifest.lock().expect("manifest") = manifest;
    }

    fn set_page(&self, page: BridgeEventPage) {
        *self.page.lock().expect("page") = page;
    }
}

#[derive(Debug)]
struct DuplicateInFlightStore {
    inner: MemoryLocalStore,
    duplicate_next_inflight: AtomicBool,
}

impl Default for DuplicateInFlightStore {
    fn default() -> Self {
        Self {
            inner: MemoryLocalStore::default(),
            duplicate_next_inflight: AtomicBool::new(true),
        }
    }
}

impl StorageProvider for DuplicateInFlightStore {
    fn schema_version(&self) -> Result<u32, DurableStoreError> {
        self.inner.schema_version()
    }

    fn health(&self) -> Result<StorageHealth, DurableStoreError> {
        self.inner.health()
    }
}

impl ConversationStore for DuplicateInFlightStore {
    fn persist_conversation(
        &self,
        conversation: &ConversationRecord,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        self.inner.persist_conversation(conversation)
    }

    fn conversation(
        &self,
        scope: &TenantScope,
        conversation_id: &ConversationId,
    ) -> Result<Option<ConversationRecord>, DurableStoreError> {
        self.inner.conversation(scope, conversation_id)
    }
}

impl MessageStore for DuplicateInFlightStore {
    fn persist_message(
        &self,
        message: &MessageEnvelope,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        self.inner.persist_message(message)
    }

    fn message(
        &self,
        scope: &TenantScope,
        message_id: &MessageId,
    ) -> Result<Option<MessageEnvelope>, DurableStoreError> {
        self.inner.message(scope, message_id)
    }
}

impl BridgeRegistrationStore for DuplicateInFlightStore {
    fn install_bridge_registration(
        &self,
        registration: &BridgeRegistration,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        self.inner.install_bridge_registration(registration)
    }

    fn bridge_registration(
        &self,
        scope: &TenantScope,
        integration_id: &IntegrationId,
    ) -> Result<Option<BridgeRegistration>, DurableStoreError> {
        self.inner.bridge_registration(scope, integration_id)
    }

    fn transition_bridge_registration(
        &self,
        scope: &TenantScope,
        integration_id: &IntegrationId,
        expected_generation: u64,
        next_state: BridgeRegistrationState,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        self.inner.transition_bridge_registration(
            scope,
            integration_id,
            expected_generation,
            next_state,
        )
    }
}

impl BridgeActionStore for DuplicateInFlightStore {
    fn prepare_bridge_action(
        &self,
        record: &BridgeActionRecord,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        self.inner.prepare_bridge_action(record)
    }

    fn bridge_action(
        &self,
        scope: &TenantScope,
        action_id: &BridgeActionId,
    ) -> Result<Option<BridgeActionRecord>, DurableStoreError> {
        self.inner.bridge_action(scope, action_id)
    }

    fn transition_bridge_action(
        &self,
        scope: &TenantScope,
        action_id: &BridgeActionId,
        expected_generation: u64,
        expected_state: BridgeActionState,
        next_state: BridgeActionState,
        acceptance: Option<&BridgeProviderAcceptance>,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        if next_state == BridgeActionState::InFlight
            && self.duplicate_next_inflight.swap(false, Ordering::SeqCst)
        {
            return Ok(DurableRecordStatus::Duplicate);
        }
        self.inner.transition_bridge_action(
            scope,
            action_id,
            expected_generation,
            expected_state,
            next_state,
            acceptance,
        )
    }
}

impl BridgeProvider for TestProvider {
    fn manifest(&self) -> BridgeProviderManifest {
        self.manifest.lock().expect("manifest").clone()
    }

    fn execute(
        &self,
        _action: &BridgeAction,
    ) -> Result<BridgeProviderAcceptance, BridgeProviderFailure> {
        *self.execute_count.lock().expect("count") += 1;
        match self.steps.lock().expect("steps").pop() {
            Some(ExecuteStep::Accept(value)) => Ok(value),
            Some(ExecuteStep::Fail(error)) => Err(error),
            None => Ok(acceptance(b"provider-default")),
        }
    }

    fn poll_events(
        &self,
        _scope: &TenantScope,
        _integration_id: &IntegrationId,
        _cursor: Option<&BridgeEventCursor>,
        _limit: usize,
    ) -> Result<BridgeEventPage, BridgeProviderFailure> {
        Ok(self.page.lock().expect("page").clone())
    }
}

fn oid(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("id")
}

fn scope() -> TenantScope {
    TenantScope {
        tenant_id: TenantId::from_opaque(oid("bridge-tenant")),
        namespace_id: Some(NamespaceId::from_opaque(oid("bridge-namespace"))),
    }
}

fn actor() -> ScopedPrincipal {
    ScopedPrincipal {
        scope: scope(),
        principal: PrincipalRef {
            principal_id: PrincipalId::from_opaque(oid("bridge-actor")),
            kind: PrincipalKind::Person,
        },
    }
}

fn integration() -> IntegrationId {
    IntegrationId::from_opaque(oid("bridge-integration"))
}

fn manifest(capabilities: Vec<BridgeCapability>) -> BridgeProviderManifest {
    BridgeProviderManifest {
        provider_id: "vendor.reference.bridge".to_owned(),
        sdk_min: BRIDGE_SDK_VERSION,
        sdk_max: BRIDGE_SDK_VERSION,
        protocol_min: ProtocolVersion::new(1, 0),
        protocol_max: ProtocolVersion::new(1, 0),
        capabilities,
        permissions: vec![
            BridgeDataPermission::MessageContent,
            BridgeDataPermission::ExternalIdentityReferences,
            BridgeDataPermission::InboundEvents,
        ],
        extensions: vec![],
    }
}

fn acceptance(id: &[u8]) -> BridgeProviderAcceptance {
    BridgeProviderAcceptance {
        external_message_id: Some(id.to_vec()),
        degradation: None,
    }
}

fn conversation() -> ConversationRecord {
    ConversationRecord {
        scope: scope(),
        conversation: ConversationRef {
            conversation_id: ConversationId::from_opaque(oid("bridge-conversation")),
            kind: ConversationKind::Direct,
        },
        parent_conversation_id: None,
    }
}

fn message(id: &str, content: &[u8], policy: DeliveryPolicy) -> MessageEnvelope {
    MessageEnvelope {
        message_id: MessageId::from_opaque(oid(id)),
        scope: scope(),
        conversation: conversation().conversation,
        author: ActorRef {
            actor_id: ActorId::from_opaque(oid("bridge-author")),
            kind: ActorKind::Person,
            on_behalf_of: None,
        },
        author_device: DeviceRef {
            device_id: DeviceId::from_opaque(oid("bridge-device")),
            identity_id: IdentityId::from_opaque(oid("bridge-identity")),
        },
        created_at_unix_ms: 1_700_000_000_000,
        logical_order: 1,
        content: content.to_vec(),
        attachment_ids: vec![],
        reply_to: None,
        relations: vec![],
        crypto_metadata: None,
        delivery_policy: policy,
        delivery_state: DeliveryState::Created,
        origin: OriginRef {
            principal_id: Some(PrincipalId::from_opaque(oid("bridge-origin"))),
            endpoint_id: None,
            integration_id: None,
        },
        correlation: CorrelationContext {
            correlation_id: oid(&format!("corr-{id}")),
            causation_id: None,
            idempotency_key: Some(format!("idem-{id}")),
        },
        extensions: vec![],
        external_mappings: vec![],
        signature: None,
    }
}

fn action(id: &str, message: Option<&MessageEnvelope>, payload: &[u8]) -> BridgeAction {
    BridgeAction {
        action_id: BridgeActionId::from_opaque(oid(id)),
        scope: scope(),
        integration_id: integration(),
        capability: BridgeCapability::Text,
        external_target: b"provider-target".to_vec(),
        canonical_message_id: message.map(|value| value.message_id.clone()),
        provider_payload: payload.to_vec(),
        attachment_ids: vec![],
        correlation: CorrelationContext {
            correlation_id: oid(&format!("corr-action-{id}")),
            causation_id: None,
            idempotency_key: Some(format!("idem-action-{id}")),
        },
    }
}

fn setup_message(store: &MemoryLocalStore, value: &MessageEnvelope) {
    store
        .persist_conversation(&conversation())
        .expect("conversation");
    store.persist_message(value).expect("message");
}

#[test]
fn accepted_action_deduplicates_without_second_provider_side_effect() {
    let store = MemoryLocalStore::default();
    let provider = TestProvider::new(
        manifest(vec![BridgeCapability::Text]),
        vec![ExecuteStep::Accept(BridgeProviderAcceptance {
            external_message_id: Some(b"provider-message-1".to_vec()),
            degradation: Some(BridgeDegradation {
                requested: BridgeCapability::Text,
                fallback: None,
                reason: BridgeDegradationReason::ProviderLimited,
            }),
        })],
    );
    let runtime = BridgeRuntime::new(&AllowAll, &store);
    runtime
        .register(&actor(), &integration(), &provider)
        .expect("register");
    let canonical = message("message-dedupe", b"hello", DeliveryPolicy::Durable);
    setup_message(&store, &canonical);
    let outbound = action("action-dedupe", Some(&canonical), b"hello");

    let first = runtime
        .execute(&actor(), &outbound, &provider)
        .expect("first");
    assert!(!first.replayed);
    let second = runtime
        .execute(&actor(), &outbound, &provider)
        .expect("replay");
    assert!(second.replayed);
    assert_eq!(first.acceptance, second.acceptance);
    assert_eq!(provider.count(), 1);
    assert_eq!(
        store
            .message(&scope(), &canonical.message_id)
            .expect("load")
            .expect("message")
            .delivery_state,
        DeliveryState::Persisted
    );
}

#[test]
fn policy_and_payload_tampering_fail_before_provider_side_effect() {
    let store = MemoryLocalStore::default();
    let provider = TestProvider::new(manifest(vec![BridgeCapability::Text]), vec![]);
    let runtime = BridgeRuntime::new(&AllowAll, &store);
    runtime
        .register(&actor(), &integration(), &provider)
        .expect("register");

    for (suffix, policy) in [
        ("local-only", DeliveryPolicy::LocalOnly),
        ("private-network-only", DeliveryPolicy::PrivateNetworkOnly),
        ("no-external-bridge", DeliveryPolicy::NoExternalBridge),
    ] {
        let forbidden = message(&format!("message-{suffix}"), b"private", policy);
        setup_message(&store, &forbidden);
        assert_eq!(
            runtime.execute(
                &actor(),
                &action(&format!("action-{suffix}"), Some(&forbidden), b"private"),
                &provider,
            ),
            Err(BridgeError::ExternalBridgeForbidden)
        );
    }

    let allowed = message("message-tamper", b"canonical", DeliveryPolicy::Durable);
    store.persist_message(&allowed).expect("message");
    assert_eq!(
        runtime.execute(
            &actor(),
            &action("action-tamper", Some(&allowed), b"changed"),
            &provider,
        ),
        Err(BridgeError::MessageBindingMismatch)
    );
    assert_eq!(provider.count(), 0);
}

#[test]
fn live_capability_loss_and_permission_denial_fail_closed() {
    let store = MemoryLocalStore::default();
    let provider = TestProvider::new(manifest(vec![BridgeCapability::Text]), vec![]);
    let runtime = BridgeRuntime::new(&AllowAll, &store);
    runtime
        .register(&actor(), &integration(), &provider)
        .expect("register");
    provider.replace_manifest(manifest(vec![BridgeCapability::Video]));
    assert_eq!(
        runtime.execute(
            &actor(),
            &action("action-capability-loss", None, b""),
            &provider,
        ),
        Err(BridgeError::CapabilityUnavailable)
    );

    let denied_runtime = BridgeRuntime::new(&DenyExecute, &store);
    assert!(matches!(
        denied_runtime.execute(&actor(), &action("action-denied", None, b""), &provider,),
        Err(BridgeError::Authorization(_))
    ));
    assert_eq!(provider.count(), 0);
}

#[test]
fn live_manifest_expansion_cannot_escape_registered_degradation_ceiling() {
    let store = MemoryLocalStore::default();
    let provider = TestProvider::new(
        manifest(vec![BridgeCapability::Text]),
        vec![ExecuteStep::Accept(BridgeProviderAcceptance {
            external_message_id: Some(b"provider-expanded-fallback".to_vec()),
            degradation: Some(BridgeDegradation {
                requested: BridgeCapability::Text,
                fallback: Some(BridgeCapability::Video),
                reason: BridgeDegradationReason::ProviderLimited,
            }),
        })],
    );
    let runtime = BridgeRuntime::new(&AllowAll, &store);
    runtime
        .register(&actor(), &integration(), &provider)
        .expect("register");

    provider.replace_manifest(manifest(vec![
        BridgeCapability::Text,
        BridgeCapability::Video,
    ]));
    let outbound = action("action-expanded-fallback", None, b"");
    assert_eq!(
        runtime.execute(&actor(), &outbound, &provider),
        Err(BridgeError::AcceptanceUnknown)
    );
    assert_eq!(provider.count(), 1);
    let record = store
        .bridge_action(&scope(), &outbound.action_id)
        .expect("load action")
        .expect("action record");
    assert_eq!(record.state, BridgeActionState::AcceptanceUnknown);
    assert!(record.acceptance.is_none());

    assert_eq!(
        runtime.execute(&actor(), &outbound, &provider),
        Err(BridgeError::AcceptanceUnknown)
    );
    assert_eq!(provider.count(), 1);
}

#[test]
fn duplicate_inflight_transition_never_invokes_provider_twice() {
    let store = DuplicateInFlightStore::default();
    let provider = TestProvider::new(manifest(vec![BridgeCapability::Text]), vec![]);
    let runtime = BridgeRuntime::new(&AllowAll, &store);
    runtime
        .register(&actor(), &integration(), &provider)
        .expect("register");
    let outbound = action("action-duplicate-inflight", None, b"");

    assert_eq!(
        runtime.execute(&actor(), &outbound, &provider),
        Err(BridgeError::ActionInFlight)
    );
    assert_eq!(provider.count(), 0);
}

#[test]
fn external_target_requires_explicit_identity_reference_permission() {
    let store = MemoryLocalStore::default();
    let mut restricted = manifest(vec![BridgeCapability::Text]);
    restricted
        .permissions
        .retain(|permission| *permission != BridgeDataPermission::ExternalIdentityReferences);
    let provider = TestProvider::new(restricted, vec![]);
    let runtime = BridgeRuntime::new(&AllowAll, &store);
    runtime
        .register(&actor(), &integration(), &provider)
        .expect("register");

    assert_eq!(
        runtime.execute(
            &actor(),
            &action("action-target-permission", None, b""),
            &provider,
        ),
        Err(BridgeError::DataPermissionDenied)
    );
    assert_eq!(provider.count(), 0);
}

#[test]
fn accepted_replay_survives_disable_and_revoke_without_provider_call() {
    let store = MemoryLocalStore::default();
    let provider = TestProvider::new(
        manifest(vec![BridgeCapability::Text]),
        vec![ExecuteStep::Accept(acceptance(b"provider-terminal"))],
    );
    let runtime = BridgeRuntime::new(&AllowAll, &store);
    runtime
        .register(&actor(), &integration(), &provider)
        .expect("register");
    let outbound = action("action-terminal-replay", None, b"");
    let first = runtime
        .execute(&actor(), &outbound, &provider)
        .expect("first acceptance");
    assert!(!first.replayed);
    assert_eq!(provider.count(), 1);

    runtime
        .transition_registration(
            &actor(),
            &integration(),
            1,
            BridgeRegistrationState::Disabled,
        )
        .expect("disable");
    let disabled_replay = runtime
        .execute(&actor(), &outbound, &provider)
        .expect("replay while disabled");
    assert!(disabled_replay.replayed);
    assert_eq!(disabled_replay.acceptance, first.acceptance);
    assert_eq!(provider.count(), 1);

    runtime
        .transition_registration(
            &actor(),
            &integration(),
            2,
            BridgeRegistrationState::Revoked,
        )
        .expect("revoke");
    let revoked_replay = runtime
        .execute(&actor(), &outbound, &provider)
        .expect("replay while revoked");
    assert!(revoked_replay.replayed);
    assert_eq!(revoked_replay.acceptance, first.acceptance);
    assert_eq!(provider.count(), 1);
}

#[test]
fn bridge_provider_backpressure_chaos_retries_only_proven_non_acceptance() {
    let store = MemoryLocalStore::default();
    let provider = TestProvider::new(
        manifest(vec![BridgeCapability::Text]),
        vec![
            ExecuteStep::Fail(BridgeProviderFailure::NotAccepted(
                BridgeProviderFailureKind::Backpressure,
            )),
            ExecuteStep::Accept(acceptance(b"provider-after-retry")),
        ],
    );
    let runtime = BridgeRuntime::new(&AllowAll, &store);
    runtime
        .register(&actor(), &integration(), &provider)
        .expect("register");
    let retry = action("action-retry", None, b"");
    assert_eq!(
        runtime.execute(&actor(), &retry, &provider),
        Err(BridgeError::Provider(
            BridgeProviderFailureKind::Backpressure
        ))
    );
    let outcome = runtime
        .execute(&actor(), &retry, &provider)
        .expect("safe retry");
    assert_eq!(
        outcome.acceptance.external_message_id.as_deref(),
        Some(b"provider-after-retry".as_slice())
    );
    assert_eq!(provider.count(), 2);

    let unknown_provider = TestProvider::new(
        manifest(vec![BridgeCapability::Text]),
        vec![ExecuteStep::Fail(BridgeProviderFailure::AcceptanceUnknown(
            BridgeProviderFailureKind::Unavailable,
        ))],
    );
    let second_integration = IntegrationId::from_opaque(oid("bridge-integration-unknown"));
    runtime
        .register(&actor(), &second_integration, &unknown_provider)
        .expect("register unknown provider");
    let mut uncertain = action("action-unknown", None, b"");
    uncertain.integration_id = second_integration;
    assert_eq!(
        runtime.execute(&actor(), &uncertain, &unknown_provider),
        Err(BridgeError::AcceptanceUnknown)
    );
    assert_eq!(
        runtime.execute(&actor(), &uncertain, &unknown_provider),
        Err(BridgeError::AcceptanceUnknown)
    );
    assert_eq!(unknown_provider.count(), 1);
}

#[test]
fn crash_left_inflight_requires_explicit_unknown_recovery_without_provider_call() {
    let store = MemoryLocalStore::default();
    let provider = TestProvider::new(manifest(vec![BridgeCapability::Text]), vec![]);
    let runtime = BridgeRuntime::new(&AllowAll, &store);
    runtime
        .register(&actor(), &integration(), &provider)
        .expect("register");
    let outbound = action("action-crash", None, b"");
    let record = BridgeActionRecord {
        scope: scope(),
        action_id: outbound.action_id.clone(),
        integration_id: integration(),
        capability: BridgeCapability::Text,
        fingerprint: bridge_action_fingerprint(&outbound).expect("fingerprint"),
        state: BridgeActionState::Prepared,
        acceptance: None,
        generation: 1,
    };
    store.prepare_bridge_action(&record).expect("prepare");
    store
        .transition_bridge_action(
            &scope(),
            &outbound.action_id,
            1,
            BridgeActionState::Prepared,
            BridgeActionState::InFlight,
            None,
        )
        .expect("in flight");
    assert_eq!(
        runtime.execute(&actor(), &outbound, &provider),
        Err(BridgeError::ActionInFlight)
    );
    runtime
        .recover_in_flight_as_unknown(&actor(), &outbound.action_id)
        .expect("recover ambiguity");
    assert_eq!(
        runtime.execute(&actor(), &outbound, &provider),
        Err(BridgeError::AcceptanceUnknown)
    );
    assert_eq!(provider.count(), 0);
}

#[test]
fn inbound_page_is_bounded_and_provider_cannot_spoof_scope_or_integration() {
    let store = MemoryLocalStore::default();
    let provider = TestProvider::new(manifest(vec![BridgeCapability::Text]), vec![]);
    let runtime = BridgeRuntime::new(&AllowAll, &store);
    runtime
        .register(&actor(), &integration(), &provider)
        .expect("register");
    provider.set_page(BridgeEventPage {
        events: vec![BridgeInboundEvent {
            scope: scope(),
            integration_id: integration(),
            external_event_id: b"event-1".to_vec(),
            external_conversation_id: b"conversation-1".to_vec(),
            external_actor_id: Some(b"actor-1".to_vec()),
            capability: BridgeCapability::Text,
            payload: b"hello inbound".to_vec(),
            occurred_at_unix_ms: 1_700_000_000_001,
        }],
        next_cursor: Some(BridgeEventCursor {
            token: b"next".to_vec(),
        }),
    });
    let page = runtime
        .poll_events(&actor(), &integration(), &provider, None, 10)
        .expect("valid page");
    assert_eq!(page.events.len(), 1);

    let mut wrong_scope = scope();
    wrong_scope.namespace_id = Some(NamespaceId::from_opaque(oid("spoofed")));
    provider.set_page(BridgeEventPage {
        events: vec![BridgeInboundEvent {
            scope: wrong_scope,
            integration_id: integration(),
            external_event_id: b"event-spoof".to_vec(),
            external_conversation_id: b"conversation-1".to_vec(),
            external_actor_id: None,
            capability: BridgeCapability::Text,
            payload: vec![],
            occurred_at_unix_ms: 1_700_000_000_002,
        }],
        next_cursor: None,
    });
    assert_eq!(
        runtime.poll_events(&actor(), &integration(), &provider, None, 10),
        Err(BridgeError::EventBindingMismatch)
    );
    assert_eq!(
        runtime.poll_events(&actor(), &integration(), &provider, None, 0),
        Err(BridgeError::InvalidPageLimit)
    );
}
