#![forbid(unsafe_code)]

use ucr_core::{DeviceLifecycleStore, DurableRecordStatus, DurableStoreError, OfflineGroupStore};
use ucr_crypto::{
    EstablishedSession, TrustedKeyResolutionError, TrustedMessageSignatureError,
    TrustedSigningKeyResolver, verify_message_signature_with_trust,
};
use ucr_model::{
    ConversationId, DeviceLifecycleState, GroupId, OfflineGroupChangePage,
    OfflineGroupChangeReplica, OfflineGroupCursor, OfflineGroupMessagePage,
    OfflineGroupMessageReplica, PrincipalKind, ScopedPrincipal, SessionId, SyncLinkKind, SyncMode,
    SyncSession, SyncState, TenantScope,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflineGroupsError {
    Store(DurableStoreError),
    MissingSyncSession,
    WrongSyncMode,
    GroupNotSelected,
    UnauthenticatedPeer,
    PeerDeviceInactive,
    PeerTrust(TrustedKeyResolutionError),
    SessionTrustChanged,
    MessageSignature(TrustedMessageSignatureError),
    MessageDeviceMismatch,
}

impl From<DurableStoreError> for OfflineGroupsError {
    fn from(value: DurableStoreError) -> Self {
        Self::Store(value)
    }
}

#[derive(Debug)]
pub struct OfflineGroupExportRequest<'a> {
    pub source: &'a ScopedPrincipal,
    pub peer: &'a ScopedPrincipal,
    pub sync_session_id: &'a SessionId,
    pub group_id: &'a GroupId,
    pub cursor: Option<&'a OfflineGroupCursor>,
    pub max_items: usize,
    pub session: &'a EstablishedSession,
}

#[derive(Debug)]
pub struct OfflineGroupsRuntime<'a, S> {
    store: &'a S,
}

impl<'a, S> OfflineGroupsRuntime<'a, S> {
    #[must_use]
    pub const fn new(store: &'a S) -> Self {
        Self { store }
    }
}

impl<S> OfflineGroupsRuntime<'_, S>
where
    S: OfflineGroupStore + DeviceLifecycleStore + TrustedSigningKeyResolver,
{
    /// Reuses the Phase-26 authenticated `PeerPeer` Sync admission boundary for later peer layers.
    ///
    /// This validates the active Sync selection and the current authenticated peer Device/key. It
    /// does not grant Group membership or Message authority; those remain durable Group owners.
    ///
    /// # Errors
    /// Fails closed for inactive/wrong Sync sessions, unauthenticated/revoked peers, or changed
    /// trusted signing-key state.
    pub fn authorize_peer_group_sync(
        &self,
        scope: &TenantScope,
        sync_session_id: &SessionId,
        conversation_id: &ConversationId,
        peer: &ScopedPrincipal,
        session: &EstablishedSession,
        expected_identity: Option<&ucr_model::IdentityId>,
    ) -> Result<ucr_model::DeviceId, OfflineGroupsError> {
        self.require_active_sync(scope, sync_session_id, conversation_id)?;
        self.require_current_peer(peer, session, expected_identity)
    }

    /// Exports one bounded source-authored Group-change page over an active trusted peer sync.
    ///
    /// # Errors
    /// Fails closed for missing/inactive/wrong sync sessions, stale peer trust, membership/cursor
    /// violations, or durable-store failures.
    pub fn export_changes(
        &self,
        request: &OfflineGroupExportRequest<'_>,
    ) -> Result<OfflineGroupChangePage, OfflineGroupsError> {
        let group = self
            .store
            .group(&request.source.scope, request.group_id)?
            .ok_or(OfflineGroupsError::GroupNotSelected)?;
        self.require_active_sync(
            &request.source.scope,
            request.sync_session_id,
            &group.conversation.conversation_id,
        )?;
        self.require_current_peer(request.peer, request.session, None)?;
        self.store
            .offline_group_change_page(
                request.source,
                request.peer,
                &request.source.scope,
                request.group_id,
                request.cursor,
                request.max_items,
            )
            .map_err(Into::into)
    }

    /// Exports one bounded signed Group-Message page over an active trusted peer sync.
    ///
    /// # Errors
    /// Fails closed for missing/inactive/wrong sync sessions, stale peer trust, membership/history
    /// or cursor violations, or durable-store failures.
    pub fn export_messages(
        &self,
        request: &OfflineGroupExportRequest<'_>,
    ) -> Result<OfflineGroupMessagePage, OfflineGroupsError> {
        let group = self
            .store
            .group(&request.source.scope, request.group_id)?
            .ok_or(OfflineGroupsError::GroupNotSelected)?;
        self.require_active_sync(
            &request.source.scope,
            request.sync_session_id,
            &group.conversation.conversation_id,
        )?;
        self.require_current_peer(request.peer, request.session, None)?;
        self.store
            .offline_group_message_page(
                request.source,
                request.peer,
                &request.source.scope,
                request.group_id,
                request.cursor,
                request.max_items,
            )
            .map_err(Into::into)
    }

    /// Applies one authenticated one-hop Group change through the canonical Group owner.
    ///
    /// # Errors
    /// Fails closed for untrusted/wrong peers, invalid sync selection, stale/conflicting changes,
    /// inactive membership, or durable-store failures.
    pub fn reconcile_change(
        &self,
        recipient: &ScopedPrincipal,
        sync_session_id: &SessionId,
        record: &OfflineGroupChangeReplica,
        session: &EstablishedSession,
    ) -> Result<DurableRecordStatus, OfflineGroupsError> {
        let group = self
            .store
            .group(&record.change.scope, &record.change.group_id)?
            .ok_or(OfflineGroupsError::GroupNotSelected)?;
        self.require_active_sync(
            &record.change.scope,
            sync_session_id,
            &group.conversation.conversation_id,
        )?;
        self.require_current_peer(&record.actor, session, None)?;
        self.store
            .reconcile_offline_group_change(recipient, record)
            .map_err(Into::into)
    }

    /// Applies one authenticated signed one-hop Group Message through the canonical Message owner.
    ///
    /// # Errors
    /// Fails closed for untrusted/wrong/revoked peers, invalid signatures, invalid sync selection,
    /// historical membership/history denial, conflicts, or durable-store failures.
    pub fn reconcile_message(
        &self,
        recipient: &ScopedPrincipal,
        sync_session_id: &SessionId,
        record: &OfflineGroupMessageReplica,
        session: &EstablishedSession,
    ) -> Result<DurableRecordStatus, OfflineGroupsError> {
        let group = self
            .store
            .group(&record.message.scope, &record.group_id)?
            .ok_or(OfflineGroupsError::GroupNotSelected)?;
        self.require_active_sync(
            &record.message.scope,
            sync_session_id,
            &group.conversation.conversation_id,
        )?;
        let peer_device = self.require_current_peer(
            &record.author,
            session,
            Some(&record.message.author_device.identity_id),
        )?;
        if record.message.author_device.device_id != peer_device {
            return Err(OfflineGroupsError::MessageDeviceMismatch);
        }
        verify_message_signature_with_trust(&record.message, self.store)
            .map_err(OfflineGroupsError::MessageSignature)?;
        self.store
            .reconcile_offline_group_message(recipient, record)
            .map_err(Into::into)
    }

    fn require_active_sync(
        &self,
        scope: &TenantScope,
        session_id: &SessionId,
        conversation_id: &ConversationId,
    ) -> Result<SyncSession, OfflineGroupsError> {
        let session = self
            .store
            .sync_session(scope, session_id)?
            .ok_or(OfflineGroupsError::MissingSyncSession)?;
        if session.state != SyncState::Active || session.link_kind != SyncLinkKind::PeerPeer {
            return Err(OfflineGroupsError::WrongSyncMode);
        }
        match session.selection.mode {
            SyncMode::Full => {}
            SyncMode::Partial if session.selection.conversation_ids.contains(conversation_id) => {}
            SyncMode::Partial => return Err(OfflineGroupsError::GroupNotSelected),
        }
        Ok(session)
    }

    fn require_current_peer(
        &self,
        peer: &ScopedPrincipal,
        session: &EstablishedSession,
        expected_identity: Option<&ucr_model::IdentityId>,
    ) -> Result<ucr_model::DeviceId, OfflineGroupsError> {
        if peer.principal.kind != PrincipalKind::Device {
            return Err(OfflineGroupsError::UnauthenticatedPeer);
        }
        let device_id = session
            .authenticated_peer_device_id()
            .ok_or(OfflineGroupsError::UnauthenticatedPeer)?;
        if peer.principal.principal_id.as_opaque().as_wire_bytes()
            != device_id.as_opaque().as_wire_bytes()
        {
            return Err(OfflineGroupsError::UnauthenticatedPeer);
        }
        let descriptor = self
            .store
            .device(&peer.scope, device_id)?
            .ok_or(OfflineGroupsError::PeerDeviceInactive)?;
        if descriptor.state != DeviceLifecycleState::Active
            || expected_identity.is_some_and(|identity| identity != &descriptor.identity_id)
        {
            return Err(OfflineGroupsError::PeerDeviceInactive);
        }
        let session_key = session
            .authenticated_peer_signing_descriptor()
            .ok_or(OfflineGroupsError::UnauthenticatedPeer)?;
        let current = self
            .store
            .resolve_active_signing_key(
                &peer.scope,
                device_id,
                Some(&descriptor.identity_id),
                &session_key.key_id,
            )
            .map_err(OfflineGroupsError::PeerTrust)?;
        if current != *session_key {
            return Err(OfflineGroupsError::SessionTrustChanged);
        }
        Ok(device_id.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ucr_core::{
        DeviceLifecycleStore, DurableRecordStatus, GroupStore, SyncStore, TrustedSigningKeyStore,
    };
    use ucr_crypto::{
        AgreementKeyPair, SessionHandshakeInput, SessionRole, SigningKeyMaterial,
        TranscriptBinding, TrustedSessionHandshakeInput, begin_session,
        begin_session_with_trusted_peer,
    };
    use ucr_model::*;
    use ucr_protocol::{
        ALGORITHM_VERSION, KEY_FORMAT_VERSION, SIGNATURE_ALGORITHM_ID, message_signing_binding,
    };
    use ucr_storage_memory::MemoryLocalStore;

    fn oid(v: &str) -> OpaqueId {
        OpaqueId::new(v).expect("id")
    }

    fn scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(oid("phase26-runtime-tenant")),
            namespace_id: None,
        }
    }

    fn device_subject(id: &str) -> ScopedPrincipal {
        ScopedPrincipal {
            scope: scope(),
            principal: PrincipalRef {
                principal_id: PrincipalId::from_opaque(oid(id)),
                kind: PrincipalKind::Device,
            },
        }
    }

    fn device_descriptor(id: &str, identity: &str) -> DeviceDescriptor {
        DeviceDescriptor {
            device_id: DeviceId::from_opaque(oid(id)),
            identity_id: IdentityId::from_opaque(oid(identity)),
            state: DeviceLifecycleState::Active,
        }
    }

    fn trusted_peer_session(
        store: &MemoryLocalStore,
        peer: &DeviceDescriptor,
        peer_signer: &SigningKeyMaterial,
    ) -> (EstablishedSession, PublicKeyDescriptor) {
        let descriptor = PublicKeyDescriptor {
            key_id: KeyId::from_opaque(oid("phase26-peer-key")),
            device_id: peer.device_id.clone(),
            purpose: KeyPurpose::Signing,
            algorithm_id: SIGNATURE_ALGORITHM_ID.to_owned(),
            algorithm_version: ALGORITHM_VERSION,
            key_format_version: KEY_FORMAT_VERSION,
            public_key: peer_signer.verifying_key().0.to_vec(),
        };
        store
            .provision_trusted_signing_key(&scope(), &descriptor)
            .expect("peer trust");
        let local_signer = SigningKeyMaterial::generate().expect("local signer");
        let local_agreement = AgreementKeyPair::generate().expect("local agreement");
        let peer_agreement = AgreementKeyPair::generate().expect("peer agreement");
        let local_public = local_agreement.public_key();
        let peer_public = peer_agreement.public_key();
        let binding = TranscriptBinding::from_bytes([26_u8; 32]);
        let local_pending = begin_session_with_trusted_peer(
            local_agreement,
            &TrustedSessionHandshakeInput {
                scope: scope(),
                suite: CryptoSuite::UcrV1,
                role: SessionRole::Initiator,
                peer_agreement: peer_public,
                initiator_public: local_public,
                responder_public: peer_public,
                peer_signing_descriptor: descriptor.clone(),
                peer_signature: peer_signer.sign_transcript(&binding),
                binding,
            },
            store,
            store,
        )
        .expect("trusted local pending");
        let peer_pending = begin_session(
            peer_agreement,
            SessionHandshakeInput {
                suite: CryptoSuite::UcrV1,
                role: SessionRole::Responder,
                peer_agreement: local_public,
                initiator_public: local_public,
                responder_public: peer_public,
                trusted_peer_verifying_key: local_signer.verifying_key(),
                peer_signature: local_signer.sign_transcript(&binding),
                binding,
            },
            store,
        )
        .expect("peer pending");
        let peer_tag = peer_pending.local_confirmation_tag().expect("peer tag");
        (
            local_pending.confirm_peer(peer_tag).expect("established"),
            descriptor,
        )
    }

    struct Fixture {
        store: MemoryLocalStore,
        local: ScopedPrincipal,
        peer: ScopedPrincipal,
        peer_device: DeviceDescriptor,
        peer_signer: SigningKeyMaterial,
        group: GroupRecord,
        sync: SyncSession,
        session: EstablishedSession,
    }

    fn fixture() -> Fixture {
        let store = MemoryLocalStore::default();
        let local = device_subject("phase26-local-device");
        let peer = device_subject("phase26-peer-device");
        let local_device = device_descriptor("phase26-local-device", "phase26-local-identity");
        let peer_device = device_descriptor("phase26-peer-device", "phase26-peer-identity");
        store
            .register_device(&scope(), &local_device)
            .expect("local device");
        store
            .register_device(&scope(), &peer_device)
            .expect("peer device");
        let peer_signer = SigningKeyMaterial::generate().expect("peer signer");
        let (session, _) = trusted_peer_session(&store, &peer_device, &peer_signer);
        let conversation = ConversationRecord {
            scope: scope(),
            conversation: ConversationRef {
                conversation_id: ConversationId::from_opaque(oid("phase26-group-conversation")),
                kind: ConversationKind::PrivateGroup,
            },
            parent_conversation_id: None,
        };
        let group = GroupRecord {
            scope: scope(),
            group_id: GroupId::from_opaque(oid("phase26-group")),
            conversation: conversation.conversation.clone(),
            ownership: GroupOwnership::Temporary {
                owner: Some(local.principal.clone()),
                expires_at_unix_ms: 9_999_999_999_999,
            },
            history_policy: GroupHistoryPolicy::FullHistory,
            delivery_policy: DeliveryPolicy::Durable,
            crypto_state: GroupCryptoState {
                capability_id: None,
                epoch: 0,
                state_ref: None,
            },
            public_policy: None,
            media_state: GroupMediaState::Idle,
            bridge_mappings: Vec::new(),
            replication_generation: 0,
            revision: 0,
        };
        store
            .create_group(&conversation, &group, &local)
            .expect("group");
        store
            .apply_group_change(
                &local,
                &GroupChange {
                    event_id: EventId::from_opaque(oid("phase26-add-peer")),
                    scope: scope(),
                    group_id: group.group_id.clone(),
                    expected_revision: 0,
                    kind: GroupChangeKind::AddMember {
                        member: peer.principal.clone(),
                        role: GroupRole::Admin,
                    },
                    next_crypto_state: None,
                },
            )
            .expect("add peer");
        let sync = SyncSession {
            session_id: SessionId::from_opaque(oid("phase26-sync")),
            scope: scope(),
            source_endpoint_id: EndpointId::from_opaque(oid("phase26-local-endpoint")),
            target_endpoint_id: EndpointId::from_opaque(oid("phase26-peer-endpoint")),
            link_kind: SyncLinkKind::PeerPeer,
            selection: SyncSelection {
                mode: SyncMode::Partial,
                conversation_ids: vec![conversation.conversation.conversation_id],
            },
            state: SyncState::Prepared,
        };
        store.create_sync_session(&sync).expect("sync create");
        store
            .transition_sync(
                &scope(),
                &sync.session_id,
                SyncState::Prepared,
                SyncState::Active,
            )
            .expect("sync active");
        Fixture {
            store,
            local,
            peer,
            peer_device,
            peer_signer,
            group,
            sync,
            session,
        }
    }

    fn signed_peer_message(f: &Fixture) -> OfflineGroupMessageReplica {
        let mut message = MessageEnvelope {
            message_id: MessageId::from_opaque(oid("phase26-peer-message")),
            scope: scope(),
            conversation: f.group.conversation.clone(),
            author: ActorRef {
                actor_id: ActorId::from_opaque(oid("phase26-peer-actor")),
                kind: ActorKind::Person,
                on_behalf_of: None,
            },
            author_device: DeviceRef {
                device_id: f.peer_device.device_id.clone(),
                identity_id: f.peer_device.identity_id.clone(),
            },
            created_at_unix_ms: 1,
            logical_order: 1,
            content: b"offline hello".to_vec(),
            attachment_ids: Vec::new(),
            reply_to: None,
            relations: Vec::new(),
            crypto_metadata: None,
            delivery_policy: DeliveryPolicy::Durable,
            delivery_state: DeliveryState::Persisted,
            origin: OriginRef {
                principal_id: Some(f.peer.principal.principal_id.clone()),
                endpoint_id: None,
                integration_id: None,
            },
            correlation: CorrelationContext {
                correlation_id: oid("phase26-peer-correlation"),
                causation_id: None,
                idempotency_key: Some("phase26-peer-idempotency".to_owned()),
            },
            extensions: Vec::new(),
            external_mappings: Vec::new(),
            signature: None,
        };
        let binding = message_signing_binding(&message).expect("message binding");
        message.signature = Some(MessageSignature {
            key_id: KeyId::from_opaque(oid("phase26-peer-key")),
            algorithm_id: SIGNATURE_ALGORITHM_ID.to_owned(),
            algorithm_version: ALGORITHM_VERSION,
            signature: f.peer_signer.sign_message_binding(&binding).0.to_vec(),
        });
        OfflineGroupMessageReplica {
            author: f.peer.clone(),
            group_id: f.group.group_id.clone(),
            group_generation: 1,
            message,
        }
    }

    #[test]
    fn trusted_peer_message_reconciles_and_duplicate_is_idempotent() {
        let f = fixture();
        let runtime = OfflineGroupsRuntime::new(&f.store);
        let record = signed_peer_message(&f);
        assert_eq!(
            runtime.reconcile_message(&f.local, &f.sync.session_id, &record, &f.session),
            Ok(DurableRecordStatus::Persisted)
        );
        assert_eq!(
            runtime.reconcile_message(&f.local, &f.sync.session_id, &record, &f.session),
            Ok(DurableRecordStatus::Duplicate)
        );
    }

    #[test]
    fn revoke_after_connect_invalidates_the_open_offline_sync_session() {
        let f = fixture();
        let record = signed_peer_message(&f);
        f.store
            .revoke_device(
                &scope(),
                &f.peer_device.device_id,
                &f.peer_device.identity_id,
            )
            .expect("revoke peer");
        let runtime = OfflineGroupsRuntime::new(&f.store);
        assert_eq!(
            runtime.reconcile_message(&f.local, &f.sync.session_id, &record, &f.session),
            Err(OfflineGroupsError::PeerDeviceInactive)
        );
    }

    #[test]
    fn paused_or_non_device_peer_is_rejected_before_storage_effects() {
        let f = fixture();
        f.store
            .transition_sync(
                &scope(),
                &f.sync.session_id,
                SyncState::Active,
                SyncState::Paused,
            )
            .expect("pause sync");
        let runtime = OfflineGroupsRuntime::new(&f.store);
        let record = signed_peer_message(&f);
        assert_eq!(
            runtime.reconcile_message(&f.local, &f.sync.session_id, &record, &f.session),
            Err(OfflineGroupsError::WrongSyncMode)
        );
    }
}
