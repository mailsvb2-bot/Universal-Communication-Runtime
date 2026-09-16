use std::{fmt, sync::Arc};

use tonic::{Request, Response, Status};
use ucr_core::{
    AuthorizationEvaluator, DeviceLifecycleStore, DurableStoreError, MeshGroupStore,
    ServiceAuditStore, ServiceCredentialStore, ServicePrincipalRequestGate, ServiceQuotaClock,
    ServiceQuotaStore,
};
use ucr_crypto::{EstablishedSession, TrustedSigningKeyResolver};
use ucr_mesh::{MeshGroupExportRequest, MeshGroupsRuntime, MeshRuntimeError};
use ucr_model::{
    AuthorizationRequest, DeviceId, GroupId, MeshCursor, MeshGroupMessagePage,
    MeshGroupMessageReplica, OfflineGroupMessageReplica, ScopedPrincipal, ServiceAuditOperationRef,
    SessionId, TenantScope,
};
use ucr_protocol::{
    CanonicalError, CanonicalErrorCode, SERVICE_AUDIT_MESH_EXPORT_OPERATION_KIND,
    SERVICE_AUDIT_MESH_RECONCILE_OPERATION_KIND, SYNC_READ_PERMISSION, SYNC_WRITE_PERMISSION,
    acknowledgement_for, validate_mesh_group_page_size,
};

use super::{
    GRPC_MAX_DECODING_MESSAGE_SIZE, GRPC_MAX_ENCODING_MESSAGE_SIZE, decode_credentials,
    decode_message_envelope, decode_opaque, decode_principal_ref, decode_scope, invalid_argument,
    pb, pb_acknowledgement, pb_error, pb_message_envelope, pb_opaque, pb_principal_ref, pb_scope,
};

/// One process-local binding to an already-authenticated peer transport session.
///
/// This value is adapter evidence only: it is never serialized, persisted, or accepted from a
/// public request. `MeshGroupsRuntime` independently revalidates Sync, Device, key, Group and
/// Message authority on every operation.
#[derive(Clone)]
pub struct AuthenticatedMeshPeerSession {
    source: ScopedPrincipal,
    peer: ScopedPrincipal,
    session: Arc<EstablishedSession>,
}

impl AuthenticatedMeshPeerSession {
    #[must_use]
    pub fn new(
        source: ScopedPrincipal,
        peer: ScopedPrincipal,
        session: Arc<EstablishedSession>,
    ) -> Self {
        Self {
            source,
            peer,
            session,
        }
    }
}

impl fmt::Debug for AuthenticatedMeshPeerSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedMeshPeerSession")
            .field("source", &self.source)
            .field("peer", &self.peer)
            .field("session", &"<authenticated-peer-session>")
            .finish()
    }
}

/// Host boundary for resolving live peer authentication by an existing canonical `SyncSession` ID.
///
/// Implementations must be ephemeral connection/session plumbing, never a durable trust owner.
pub trait MeshPeerSessionResolver: Send + Sync {
    fn resolve(
        &self,
        scope: &TenantScope,
        sync_session_id: &SessionId,
    ) -> Option<AuthenticatedMeshPeerSession>;
}

/// Thin Phase-40 binding over the existing Phase-28 Mesh runtime and a live peer-session resolver.
pub struct GrpcMeshService<C, A, S, R> {
    clock: Arc<C>,
    authorization: Arc<A>,
    store: Arc<S>,
    peer_sessions: Arc<R>,
}

impl<C, A, S, R> GrpcMeshService<C, A, S, R> {
    #[must_use]
    pub const fn new(
        clock: Arc<C>,
        authorization: Arc<A>,
        store: Arc<S>,
        peer_sessions: Arc<R>,
    ) -> Self {
        Self {
            clock,
            authorization,
            store,
            peer_sessions,
        }
    }
}

impl<C, A, S, R> Clone for GrpcMeshService<C, A, S, R> {
    fn clone(&self) -> Self {
        Self {
            clock: Arc::clone(&self.clock),
            authorization: Arc::clone(&self.authorization),
            store: Arc::clone(&self.store),
            peer_sessions: Arc::clone(&self.peer_sessions),
        }
    }
}

impl<C, A, S, R> fmt::Debug for GrpcMeshService<C, A, S, R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GrpcMeshService")
            .finish_non_exhaustive()
    }
}

#[must_use]
pub fn mesh_service_server<C, A, S, R>(
    service: GrpcMeshService<C, A, S, R>,
) -> pb::mesh_service_server::MeshServiceServer<GrpcMeshService<C, A, S, R>>
where
    C: ServiceQuotaClock + 'static,
    A: AuthorizationEvaluator + 'static,
    S: ServiceCredentialStore
        + ServiceQuotaStore
        + ServiceAuditStore
        + MeshGroupStore
        + DeviceLifecycleStore
        + TrustedSigningKeyResolver
        + 'static,
    R: MeshPeerSessionResolver + 'static,
{
    pb::mesh_service_server::MeshServiceServer::new(service)
        .max_decoding_message_size(GRPC_MAX_DECODING_MESSAGE_SIZE)
        .max_encoding_message_size(GRPC_MAX_ENCODING_MESSAGE_SIZE)
}

#[tonic::async_trait]
impl<C, A, S, R> pb::mesh_service_server::MeshService for GrpcMeshService<C, A, S, R>
where
    C: ServiceQuotaClock + 'static,
    A: AuthorizationEvaluator + 'static,
    S: ServiceCredentialStore
        + ServiceQuotaStore
        + ServiceAuditStore
        + MeshGroupStore
        + DeviceLifecycleStore
        + TrustedSigningKeyResolver
        + 'static,
    R: MeshPeerSessionResolver + 'static,
{
    async fn export_group_messages(
        &self,
        request: Request<pb::MeshExportGroupMessagesRequest>,
    ) -> Result<Response<pb::MeshExportGroupMessagesResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let decoded = decode_export_request(request.into_inner());
        let result = match (credentials, decoded) {
            (Ok((credential_id, secret)), Ok(decoded)) => self
                .admit(
                    &decoded.scope,
                    &credential_id,
                    &secret,
                    SYNC_READ_PERMISSION,
                    SERVICE_AUDIT_MESH_EXPORT_OPERATION_KIND,
                    &decoded.sync_session_id,
                )
                .and_then(|()| self.peer_context(&decoded.scope, &decoded.sync_session_id))
                .and_then(|context| {
                    MeshGroupsRuntime::new(&*self.store)
                        .export_messages(&MeshGroupExportRequest {
                            source: &context.source,
                            peer: &context.peer,
                            sync_session_id: &decoded.sync_session_id,
                            group_id: &decoded.group_id,
                            cursor: decoded.cursor.as_ref(),
                            max_items: decoded.max_items,
                            session: &context.session,
                        })
                        .map_err(map_mesh_error)
                }),
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(pb::MeshExportGroupMessagesResponse {
            result: Some(match result {
                Ok(page) => {
                    pb::mesh_export_group_messages_response::Result::Page(pb_mesh_page(&page))
                }
                Err(error) => {
                    pb::mesh_export_group_messages_response::Result::Error(pb_error(error))
                }
            }),
        }))
    }

    async fn reconcile_group_message(
        &self,
        request: Request<pb::MeshReconcileGroupMessageRequest>,
    ) -> Result<Response<pb::MeshReconcileGroupMessageResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let decoded = decode_reconcile_request(request.into_inner());
        let result = match (credentials, decoded) {
            (Ok((credential_id, secret)), Ok(decoded)) => self
                .admit(
                    &decoded.scope,
                    &credential_id,
                    &secret,
                    SYNC_WRITE_PERMISSION,
                    SERVICE_AUDIT_MESH_RECONCILE_OPERATION_KIND,
                    &decoded.sync_session_id,
                )
                .and_then(|()| self.peer_context(&decoded.scope, &decoded.sync_session_id))
                .and_then(|context| {
                    if decoded.record.record.message.scope != decoded.scope {
                        return Err(CanonicalError::new(CanonicalErrorCode::InvalidArgument));
                    }
                    let acknowledged_id =
                        decoded.record.record.message.message_id.as_opaque().clone();
                    MeshGroupsRuntime::new(&*self.store)
                        .reconcile_message(
                            &context.source,
                            &context.peer,
                            &decoded.sync_session_id,
                            &decoded.record,
                            &context.session,
                        )
                        .map_err(map_mesh_error)?;
                    Ok(acknowledgement_for(acknowledged_id))
                }),
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(pb::MeshReconcileGroupMessageResponse {
            result: Some(match result {
                Ok(acknowledgement) => {
                    pb::mesh_reconcile_group_message_response::Result::Acknowledgement(
                        pb_acknowledgement(acknowledgement),
                    )
                }
                Err(error) => {
                    pb::mesh_reconcile_group_message_response::Result::Error(pb_error(error))
                }
            }),
        }))
    }
}

impl<C, A, S, R> GrpcMeshService<C, A, S, R>
where
    C: ServiceQuotaClock,
    A: AuthorizationEvaluator,
    S: ServiceCredentialStore + ServiceQuotaStore + ServiceAuditStore,
    R: MeshPeerSessionResolver,
{
    fn admit(
        &self,
        scope: &TenantScope,
        credential_id: &ucr_model::ServiceCredentialId,
        secret: &ucr_core::ServiceCredentialSecret,
        permission: &str,
        operation_kind: &str,
        sync_session_id: &SessionId,
    ) -> Result<(), CanonicalError> {
        let operation = ServiceAuditOperationRef {
            operation_kind: operation_kind.to_owned(),
            operation_id: sync_session_id.as_opaque().clone(),
        };
        let request =
            ServicePrincipalRequestGate::new(&*self.clock, &*self.authorization, &*self.store)
                .authenticate_request_for_operation(
                    scope,
                    credential_id,
                    secret,
                    permission,
                    scope,
                    &operation,
                )?;
        request.authorize(&AuthorizationRequest {
            subject: request.subject().clone(),
            permission: permission.to_owned(),
            resource_scope: scope.clone(),
        })
    }

    fn peer_context(
        &self,
        scope: &TenantScope,
        sync_session_id: &SessionId,
    ) -> Result<AuthenticatedMeshPeerSession, CanonicalError> {
        let context = self
            .peer_sessions
            .resolve(scope, sync_session_id)
            .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::NotFound))?;
        if context.source.scope != *scope || context.peer.scope != *scope {
            return Err(CanonicalError::new(CanonicalErrorCode::IntegrityFailure));
        }
        Ok(context)
    }
}

struct ExportRequest {
    scope: TenantScope,
    sync_session_id: SessionId,
    group_id: GroupId,
    cursor: Option<MeshCursor>,
    max_items: usize,
}

struct ReconcileRequest {
    scope: TenantScope,
    sync_session_id: SessionId,
    record: MeshGroupMessageReplica,
}

fn decode_export_request(
    value: pb::MeshExportGroupMessagesRequest,
) -> Result<ExportRequest, CanonicalError> {
    let max_items = usize::try_from(value.max_items).map_err(|_| invalid_argument())?;
    validate_mesh_group_page_size(max_items).map_err(|_| invalid_argument())?;
    Ok(ExportRequest {
        scope: decode_scope(value.scope.ok_or_else(invalid_argument)?)?,
        sync_session_id: SessionId::from_opaque(decode_opaque(value.sync_session_id)?),
        group_id: GroupId::from_opaque(decode_opaque(value.group_id)?),
        cursor: value.cursor.map(|cursor| MeshCursor {
            token: cursor.token,
        }),
        max_items,
    })
}

fn decode_reconcile_request(
    value: pb::MeshReconcileGroupMessageRequest,
) -> Result<ReconcileRequest, CanonicalError> {
    Ok(ReconcileRequest {
        scope: decode_scope(value.scope.ok_or_else(invalid_argument)?)?,
        sync_session_id: SessionId::from_opaque(decode_opaque(value.sync_session_id)?),
        record: decode_mesh_replica(value.record.ok_or_else(invalid_argument)?)?,
    })
}

fn decode_scoped_principal(value: pb::ScopedPrincipal) -> Result<ScopedPrincipal, CanonicalError> {
    Ok(ScopedPrincipal {
        scope: decode_scope(value.scope.ok_or_else(invalid_argument)?)?,
        principal: decode_principal_ref(value.principal.ok_or_else(invalid_argument)?)?,
    })
}

fn decode_offline_message_replica(
    value: pb::OfflineGroupMessageReplica,
) -> Result<OfflineGroupMessageReplica, CanonicalError> {
    Ok(OfflineGroupMessageReplica {
        author: decode_scoped_principal(value.author.ok_or_else(invalid_argument)?)?,
        group_id: GroupId::from_opaque(decode_opaque(value.group_id)?),
        group_generation: value.group_generation,
        message: decode_message_envelope(value.message.ok_or_else(invalid_argument)?)?,
    })
}

fn decode_mesh_replica(
    value: pb::MeshGroupMessageReplica,
) -> Result<MeshGroupMessageReplica, CanonicalError> {
    Ok(MeshGroupMessageReplica {
        record: decode_offline_message_replica(value.record.ok_or_else(invalid_argument)?)?,
        forward_path: value
            .forward_device_ids
            .into_iter()
            .map(|id| decode_opaque(Some(id)).map(DeviceId::from_opaque))
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn pb_scoped_principal(value: &ScopedPrincipal) -> pb::ScopedPrincipal {
    pb::ScopedPrincipal {
        scope: Some(pb_scope(&value.scope)),
        principal: Some(pb_principal_ref(&value.principal)),
    }
}

fn pb_offline_message_replica(
    value: &OfflineGroupMessageReplica,
) -> pb::OfflineGroupMessageReplica {
    pb::OfflineGroupMessageReplica {
        author: Some(pb_scoped_principal(&value.author)),
        group_id: Some(pb_opaque(value.group_id.as_opaque())),
        group_generation: value.group_generation,
        message: Some(pb_message_envelope(&value.message)),
    }
}

fn pb_mesh_replica(value: &MeshGroupMessageReplica) -> pb::MeshGroupMessageReplica {
    pb::MeshGroupMessageReplica {
        record: Some(pb_offline_message_replica(&value.record)),
        forward_device_ids: value
            .forward_path
            .iter()
            .map(|device| pb_opaque(device.as_opaque()))
            .collect(),
    }
}

fn pb_mesh_page(value: &MeshGroupMessagePage) -> pb::MeshGroupMessagePage {
    pb::MeshGroupMessagePage {
        scope: Some(pb_scope(&value.scope)),
        group_id: Some(pb_opaque(value.group_id.as_opaque())),
        records: value.records.iter().map(pb_mesh_replica).collect(),
        next_cursor: value.next_cursor.as_ref().map(|cursor| pb::MeshCursor {
            token: cursor.token.clone(),
        }),
    }
}

const fn map_store_error(error: DurableStoreError) -> CanonicalError {
    CanonicalError::new(match error {
        DurableStoreError::InvalidRecord => CanonicalErrorCode::InvalidArgument,
        DurableStoreError::Conflict => CanonicalErrorCode::Conflict,
        DurableStoreError::Full => CanonicalErrorCode::ResourceExhausted,
        DurableStoreError::Unavailable => CanonicalErrorCode::TemporarilyUnavailable,
        DurableStoreError::PermissionDenied => CanonicalErrorCode::PermissionDenied,
        DurableStoreError::Corrupt
        | DurableStoreError::UnsupportedSchemaVersion
        | DurableStoreError::ForeignStore
        | DurableStoreError::Internal => CanonicalErrorCode::Internal,
    })
}

const fn map_mesh_error(error: MeshRuntimeError) -> CanonicalError {
    match error {
        MeshRuntimeError::Store(error) => map_store_error(error),
        MeshRuntimeError::Protocol(_) => CanonicalError::new(CanonicalErrorCode::InvalidArgument),
        MeshRuntimeError::MessageSignature(_) => {
            CanonicalError::new(CanonicalErrorCode::Unauthenticated)
        }
        MeshRuntimeError::LocalDeviceInactive | MeshRuntimeError::PeerNotGroupMember => {
            CanonicalError::new(CanonicalErrorCode::PermissionDenied)
        }
        MeshRuntimeError::Peer(error) => match error {
            ucr_offline_groups::OfflineGroupsError::Store(error) => map_store_error(error),
            ucr_offline_groups::OfflineGroupsError::MissingSyncSession => {
                CanonicalError::new(CanonicalErrorCode::NotFound)
            }
            ucr_offline_groups::OfflineGroupsError::WrongSyncMode
            | ucr_offline_groups::OfflineGroupsError::GroupNotSelected
            | ucr_offline_groups::OfflineGroupsError::UnauthenticatedPeer
            | ucr_offline_groups::OfflineGroupsError::PeerDeviceInactive
            | ucr_offline_groups::OfflineGroupsError::PeerTrust(_)
            | ucr_offline_groups::OfflineGroupsError::SessionTrustChanged
            | ucr_offline_groups::OfflineGroupsError::MessageSignature(_)
            | ucr_offline_groups::OfflineGroupsError::MessageDeviceMismatch => {
                CanonicalError::new(CanonicalErrorCode::PermissionDenied)
            }
        },
    }
}
