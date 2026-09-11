#![forbid(unsafe_code)]

use ucr_core::{DeviceLifecycleStore, DurableRecordStatus, DurableStoreError, MeshGroupStore};
use ucr_crypto::{
    EstablishedSession, TrustedMessageSignatureError, TrustedSigningKeyResolver,
    verify_message_signature_with_trust,
};
use ucr_model::{
    DeviceId, DeviceLifecycleState, GroupId, GroupMemberState, GroupPermission,
    MeshGroupMessagePage, MeshGroupMessageReplica, PrincipalKind, ScopedPrincipal, SessionId,
};
use ucr_offline_groups::{OfflineGroupsError, OfflineGroupsRuntime};
use ucr_protocol::{
    MeshError, append_mesh_recipient, canonical_mesh_group_message_replica, validate_mesh_source,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshRuntimeError {
    Store(DurableStoreError),
    Peer(OfflineGroupsError),
    Protocol(MeshError),
    LocalDeviceInactive,
    PeerNotGroupMember,
    MessageSignature(TrustedMessageSignatureError),
}

impl From<DurableStoreError> for MeshRuntimeError {
    fn from(value: DurableStoreError) -> Self {
        Self::Store(value)
    }
}

impl From<OfflineGroupsError> for MeshRuntimeError {
    fn from(value: OfflineGroupsError) -> Self {
        Self::Peer(value)
    }
}

impl From<MeshError> for MeshRuntimeError {
    fn from(value: MeshError) -> Self {
        Self::Protocol(value)
    }
}

#[derive(Debug)]
pub struct MeshGroupExportRequest<'a> {
    pub source: &'a ScopedPrincipal,
    pub peer: &'a ScopedPrincipal,
    pub sync_session_id: &'a SessionId,
    pub group_id: &'a GroupId,
    pub cursor: Option<&'a ucr_model::MeshCursor>,
    pub max_items: usize,
    pub session: &'a EstablishedSession,
}

#[derive(Debug)]
pub struct MeshGroupsRuntime<'a, S> {
    store: &'a S,
}

impl<'a, S> MeshGroupsRuntime<'a, S> {
    #[must_use]
    pub const fn new(store: &'a S) -> Self {
        Self { store }
    }
}

impl<S> MeshGroupsRuntime<'_, S>
where
    S: MeshGroupStore + DeviceLifecycleStore + TrustedSigningKeyResolver,
{
    /// Exports one bounded multi-hop page to an authenticated active Group peer.
    ///
    /// # Errors
    /// Fails closed for invalid Sync/peer trust, inactive local Device, Group membership denial,
    /// invalid path state, or durable-store failures.
    pub fn export_messages(
        &self,
        request: &MeshGroupExportRequest<'_>,
    ) -> Result<MeshGroupMessagePage, MeshRuntimeError> {
        let group = self
            .store
            .group(&request.source.scope, request.group_id)?
            .ok_or(MeshRuntimeError::PeerNotGroupMember)?;
        self.require_active_local_device(request.source)?;
        let phase26 = OfflineGroupsRuntime::new(self.store);
        phase26.authorize_peer_group_sync(
            &request.source.scope,
            request.sync_session_id,
            &group.conversation.conversation_id,
            request.peer,
            request.session,
            None,
        )?;
        self.require_active_reader(request.peer, request.group_id)?;
        self.store
            .mesh_group_message_page(
                request.source,
                request.peer,
                &request.source.scope,
                request.group_id,
                request.cursor,
                request.max_items,
            )
            .map_err(Into::into)
    }

    /// Reconciles one signed multi-hop Group Message from an authenticated immediate peer.
    ///
    /// The immediate peer must be the current path tail. The original Message author/signature is
    /// independently reverified through the existing trusted-key owner before canonical persistence.
    ///
    /// # Errors
    /// Fails closed for peer/session/membership changes, loops/hop exhaustion, author signature
    /// failure, inactive local Device, semantic conflicts, or durable-store failures.
    pub fn reconcile_message(
        &self,
        recipient: &ScopedPrincipal,
        peer: &ScopedPrincipal,
        sync_session_id: &SessionId,
        record: &MeshGroupMessageReplica,
        session: &EstablishedSession,
    ) -> Result<DurableRecordStatus, MeshRuntimeError> {
        let canonical = canonical_mesh_group_message_replica(record)?;
        let group = self
            .store
            .group(&canonical.record.message.scope, &canonical.record.group_id)?
            .ok_or(MeshRuntimeError::PeerNotGroupMember)?;
        let recipient_device = self.require_active_local_device(recipient)?;
        let phase26 = OfflineGroupsRuntime::new(self.store);
        let peer_device = phase26.authorize_peer_group_sync(
            &canonical.record.message.scope,
            sync_session_id,
            &group.conversation.conversation_id,
            peer,
            session,
            None,
        )?;
        self.require_active_reader(peer, &canonical.record.group_id)?;
        validate_mesh_source(&canonical, &peer_device)?;
        append_mesh_recipient(&canonical, &recipient_device)?;
        verify_message_signature_with_trust(&canonical.record.message, self.store)
            .map_err(MeshRuntimeError::MessageSignature)?;
        self.store
            .reconcile_mesh_group_message(recipient, &canonical)
            .map_err(Into::into)
    }

    fn require_active_local_device(
        &self,
        principal: &ScopedPrincipal,
    ) -> Result<DeviceId, MeshRuntimeError> {
        if principal.principal.kind != PrincipalKind::Device {
            return Err(MeshRuntimeError::LocalDeviceInactive);
        }
        let device_id = DeviceId::from_opaque(principal.principal.principal_id.as_opaque().clone());
        let descriptor = self
            .store
            .device(&principal.scope, &device_id)?
            .ok_or(MeshRuntimeError::LocalDeviceInactive)?;
        if descriptor.state != DeviceLifecycleState::Active {
            return Err(MeshRuntimeError::LocalDeviceInactive);
        }
        Ok(device_id)
    }

    fn require_active_reader(
        &self,
        principal: &ScopedPrincipal,
        group_id: &GroupId,
    ) -> Result<(), MeshRuntimeError> {
        let membership = self
            .store
            .group_membership(&principal.scope, group_id, &principal.principal)?
            .filter(|membership| {
                membership.state == GroupMemberState::Active
                    && membership
                        .permissions
                        .contains(&GroupPermission::ReadHistory)
            })
            .ok_or(MeshRuntimeError::PeerNotGroupMember)?;
        if membership.member != principal.principal {
            return Err(MeshRuntimeError::PeerNotGroupMember);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ucr_core::{
        DeviceLifecycleStore, GroupStore, MeshGroupStore, SyncStore, TrustedSigningKeyStore,
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

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("id")
    }

    fn scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(oid("phase28-runtime-tenant")),
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

    fn device_descriptor(id: &str) -> DeviceDescriptor {
        DeviceDescriptor {
            device_id: DeviceId::from_opaque(oid(id)),
            identity_id: IdentityId::from_opaque(oid(&format!("identity-{id}"))),
            state: DeviceLifecycleState::Active,
        }
    }

    fn trusted_peer_session(
        store: &MemoryLocalStore,
        peer: &DeviceDescriptor,
        signer: &SigningKeyMaterial,
        key_id: &str,
        binding_byte: u8,
    ) -> EstablishedSession {
        let descriptor = PublicKeyDescriptor {
            key_id: KeyId::from_opaque(oid(key_id)),
            device_id: peer.device_id.clone(),
            purpose: KeyPurpose::Signing,
            algorithm_id: SIGNATURE_ALGORITHM_ID.to_owned(),
            algorithm_version: ALGORITHM_VERSION,
            key_format_version: KEY_FORMAT_VERSION,
            public_key: signer.verifying_key().0.to_vec(),
        };
        store
            .provision_trusted_signing_key(&scope(), &descriptor)
            .expect("peer trust");
        let local_signer = SigningKeyMaterial::generate().expect("local signer");
        let local_agreement = AgreementKeyPair::generate().expect("local agreement");
        let peer_agreement = AgreementKeyPair::generate().expect("peer agreement");
        let local_public = local_agreement.public_key();
        let peer_public = peer_agreement.public_key();
        let binding = TranscriptBinding::from_bytes([binding_byte; 32]);
        let local_pending = begin_session_with_trusted_peer(
            local_agreement,
            &TrustedSessionHandshakeInput {
                scope: scope(),
                suite: CryptoSuite::UcrV1,
                role: SessionRole::Initiator,
                peer_agreement: peer_public,
                initiator_public: local_public,
                responder_public: peer_public,
                peer_signing_descriptor: descriptor,
                peer_signature: signer.sign_transcript(&binding),
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
        local_pending
            .confirm_peer(peer_pending.local_confirmation_tag().expect("peer tag"))
            .expect("established")
    }

    fn active_sync(
        store: &MemoryLocalStore,
        id: &str,
        conversation_id: &ConversationId,
        source_suffix: &str,
        target_suffix: &str,
    ) -> SyncSession {
        let session = SyncSession {
            session_id: SessionId::from_opaque(oid(id)),
            scope: scope(),
            source_endpoint_id: EndpointId::from_opaque(oid(source_suffix)),
            target_endpoint_id: EndpointId::from_opaque(oid(target_suffix)),
            link_kind: SyncLinkKind::PeerPeer,
            selection: SyncSelection {
                mode: SyncMode::Partial,
                conversation_ids: vec![conversation_id.clone()],
            },
            state: SyncState::Prepared,
        };
        store.create_sync_session(&session).expect("sync create");
        store
            .transition_sync(
                &scope(),
                &session.session_id,
                SyncState::Prepared,
                SyncState::Active,
            )
            .expect("sync active");
        session
    }

    struct Fixture {
        store: MemoryLocalStore,
        a: ScopedPrincipal,
        b: ScopedPrincipal,
        c: ScopedPrincipal,
        a_device: DeviceDescriptor,
        a_signer: SigningKeyMaterial,
        group: GroupRecord,
        sync_a: SyncSession,
        sync_c: SyncSession,
        session_a: EstablishedSession,
        session_c: EstablishedSession,
    }

    fn fixture() -> Fixture {
        let store = MemoryLocalStore::default();
        let a = device_subject("phase28-runtime-a");
        let b = device_subject("phase28-runtime-b");
        let c = device_subject("phase28-runtime-c");
        let a_device = device_descriptor("phase28-runtime-a");
        let b_device = device_descriptor("phase28-runtime-b");
        let c_device = device_descriptor("phase28-runtime-c");
        for descriptor in [&a_device, &b_device, &c_device] {
            store
                .register_device(&scope(), descriptor)
                .expect("register device");
        }
        let a_signer = SigningKeyMaterial::generate().expect("a signer");
        let c_signer = SigningKeyMaterial::generate().expect("c signer");
        let session_a =
            trusted_peer_session(&store, &a_device, &a_signer, "phase28-runtime-a-key", 28);
        let session_c =
            trusted_peer_session(&store, &c_device, &c_signer, "phase28-runtime-c-key", 29);
        let conversation = ConversationRecord {
            scope: scope(),
            conversation: ConversationRef {
                conversation_id: ConversationId::from_opaque(oid("phase28-runtime-conversation")),
                kind: ConversationKind::PrivateGroup,
            },
            parent_conversation_id: None,
        };
        let group = GroupRecord {
            scope: scope(),
            group_id: GroupId::from_opaque(oid("phase28-runtime-group")),
            conversation: conversation.conversation.clone(),
            ownership: GroupOwnership::Temporary {
                owner: Some(b.principal.clone()),
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
            bridge_mappings: vec![],
            replication_generation: 0,
            revision: 0,
        };
        store
            .create_group(&conversation, &group, &b)
            .expect("group");
        for (event, expected_revision, member) in [
            ("phase28-runtime-add-a", 0, a.principal.clone()),
            ("phase28-runtime-add-c", 1, c.principal.clone()),
        ] {
            store
                .apply_group_change(
                    &b,
                    &GroupChange {
                        event_id: EventId::from_opaque(oid(event)),
                        scope: scope(),
                        group_id: group.group_id.clone(),
                        expected_revision,
                        kind: GroupChangeKind::AddMember {
                            member,
                            role: GroupRole::Member,
                        },
                        next_crypto_state: None,
                    },
                )
                .expect("add member");
        }
        let sync_a = active_sync(
            &store,
            "phase28-runtime-sync-a",
            &group.conversation.conversation_id,
            "phase28-runtime-b-endpoint",
            "phase28-runtime-a-endpoint",
        );
        let sync_c = active_sync(
            &store,
            "phase28-runtime-sync-c",
            &group.conversation.conversation_id,
            "phase28-runtime-b-endpoint-2",
            "phase28-runtime-c-endpoint",
        );
        Fixture {
            store,
            a,
            b,
            c,
            a_device,
            a_signer,
            group,
            sync_a,
            sync_c,
            session_a,
            session_c,
        }
    }

    fn signed_a_message(f: &Fixture) -> MeshGroupMessageReplica {
        let mut message = MessageEnvelope {
            message_id: MessageId::from_opaque(oid("phase28-runtime-message")),
            scope: scope(),
            conversation: f.group.conversation.clone(),
            author: ActorRef {
                actor_id: ActorId::from_opaque(oid("phase28-runtime-actor-a")),
                kind: ActorKind::Person,
                on_behalf_of: None,
            },
            author_device: DeviceRef {
                device_id: f.a_device.device_id.clone(),
                identity_id: f.a_device.identity_id.clone(),
            },
            created_at_unix_ms: 1,
            logical_order: 1,
            content: b"mesh runtime hello".to_vec(),
            attachment_ids: vec![],
            reply_to: None,
            relations: vec![],
            crypto_metadata: None,
            delivery_policy: DeliveryPolicy::Durable,
            delivery_state: DeliveryState::Persisted,
            origin: OriginRef {
                principal_id: Some(f.a.principal.principal_id.clone()),
                endpoint_id: None,
                integration_id: None,
            },
            correlation: CorrelationContext {
                correlation_id: oid("phase28-runtime-correlation"),
                causation_id: None,
                idempotency_key: Some("phase28-runtime-idempotency".into()),
            },
            extensions: vec![],
            external_mappings: vec![],
            signature: None,
        };
        let binding = message_signing_binding(&message).expect("message binding");
        message.signature = Some(MessageSignature {
            key_id: KeyId::from_opaque(oid("phase28-runtime-a-key")),
            algorithm_id: SIGNATURE_ALGORITHM_ID.to_owned(),
            algorithm_version: ALGORITHM_VERSION,
            signature: f.a_signer.sign_message_binding(&binding).0.to_vec(),
        });
        MeshGroupMessageReplica {
            record: OfflineGroupMessageReplica {
                author: f.a.clone(),
                group_id: f.group.group_id.clone(),
                group_generation: 2,
                message,
            },
            forward_path: vec![f.a_device.device_id.clone()],
        }
    }

    #[test]
    fn authenticated_a_to_b_message_can_be_reexported_from_b_to_c() {
        let f = fixture();
        let runtime = MeshGroupsRuntime::new(&f.store);
        let record = signed_a_message(&f);
        assert_eq!(
            runtime.reconcile_message(&f.b, &f.a, &f.sync_a.session_id, &record, &f.session_a,),
            Ok(DurableRecordStatus::Persisted)
        );
        let page = runtime
            .export_messages(&MeshGroupExportRequest {
                source: &f.b,
                peer: &f.c,
                sync_session_id: &f.sync_c.session_id,
                group_id: &f.group.group_id,
                cursor: None,
                max_items: 8,
                session: &f.session_c,
            })
            .expect("mesh export");
        assert_eq!(page.records.len(), 1);
        assert_eq!(page.records[0].record.message, record.record.message);
        assert_eq!(
            page.records[0].forward_path,
            vec![
                f.a_device.device_id,
                DeviceId::from_opaque(oid("phase28-runtime-b")),
            ]
        );
    }

    #[test]
    fn revoked_immediate_peer_is_rejected_before_mesh_persistence() {
        let f = fixture();
        let record = signed_a_message(&f);
        f.store
            .revoke_device(&scope(), &f.a_device.device_id, &f.a_device.identity_id)
            .expect("revoke a");
        let runtime = MeshGroupsRuntime::new(&f.store);
        assert_eq!(
            runtime.reconcile_message(&f.b, &f.a, &f.sync_a.session_id, &record, &f.session_a,),
            Err(MeshRuntimeError::Peer(
                OfflineGroupsError::PeerDeviceInactive
            ))
        );
        assert_eq!(
            f.store
                .mesh_group_message_page(&f.b, &f.c, &scope(), &f.group.group_id, None, 8,),
            Ok(MeshGroupMessagePage {
                scope: scope(),
                group_id: f.group.group_id,
                records: vec![],
                next_cursor: None,
            })
        );
    }
}
