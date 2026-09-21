#![forbid(unsafe_code)]

use std::fmt;

use tonic::{Request, metadata::BinaryMetadataValue, transport::Channel};

/// Generated client-only mapping of the canonical versioned `ucr.v1` public contract.
#[allow(clippy::all, clippy::pedantic)]
pub mod pb {
    tonic::include_proto!("ucr.v1");
}

/// Binary gRPC metadata key for the Service Principal credential identifier.
pub const SERVICE_CREDENTIAL_ID_METADATA_KEY: &str = "ucr-service-credential-id-bin";
/// Binary gRPC metadata key for the Service Principal credential secret.
pub const SERVICE_CREDENTIAL_SECRET_METADATA_KEY: &str = "ucr-service-credential-secret-bin";
/// Transport-only receive/send ceiling for Prepared SDK clients.
///
/// Canonical semantic limits remain server/protocol-owned. This ceiling only avoids
/// reintroducing Tonic's 4 MiB default below the current public contract maxima.
pub const SDK_GRPC_MESSAGE_CEILING: usize = 128 * 1024 * 1024;

/// Public SDK transport-connection error type.
pub type TransportError = tonic::transport::Error;
/// Public SDK RPC transport/status error type. Canonical application errors remain protobuf envelopes.
pub type RpcStatus = tonic::Status;

/// Opaque Service Principal credential bytes owned by the external consumer.
#[derive(Clone, PartialEq, Eq)]
pub struct ServiceCredential {
    credential_id: Vec<u8>,
    secret: Vec<u8>,
}
impl ServiceCredential {
    /// Creates an opaque credential without interpreting its canonical meaning.
    #[must_use]
    pub fn new(credential_id: impl Into<Vec<u8>>, secret: impl Into<Vec<u8>>) -> Self {
        Self {
            credential_id: credential_id.into(),
            secret: secret.into(),
        }
    }

    /// Wraps one generated protobuf request with exact binary credential metadata.
    #[must_use]
    pub fn authenticated_request<T>(&self, message: T) -> Request<T> {
        let mut request = Request::new(message);
        self.attach(&mut request);
        request
    }

    /// Adds exact credential bytes to an existing request and marks both values sensitive.
    pub fn attach<T>(&self, request: &mut Request<T>) {
        let mut id = BinaryMetadataValue::from_bytes(&self.credential_id);
        id.set_sensitive(true);
        let mut secret = BinaryMetadataValue::from_bytes(&self.secret);
        secret.set_sensitive(true);
        request
            .metadata_mut()
            .insert_bin(SERVICE_CREDENTIAL_ID_METADATA_KEY, id);
        request
            .metadata_mut()
            .insert_bin(SERVICE_CREDENTIAL_SECRET_METADATA_KEY, secret);
    }
}
impl fmt::Debug for ServiceCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServiceCredential")
            .field("credential_id_len", &self.credential_id.len())
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

/// Prepared public SDK client over the generated Integration and Event services.
///
/// The SDK performs no automatic application retry and owns no canonical domain state.
pub struct UcrSdkClient {
    credential: ServiceCredential,
    integration: pb::integration_service_client::IntegrationServiceClient<Channel>,
    events: pb::event_service_client::EventServiceClient<Channel>,
    calls: pb::call_service_client::CallServiceClient<Channel>,
    groups: pb::group_service_client::GroupServiceClient<Channel>,
    devices: pb::device_service_client::DeviceServiceClient<Channel>,
    sync: pb::sync_service_client::SyncServiceClient<Channel>,
    store_forward: pb::store_forward_service_client::StoreForwardServiceClient<Channel>,
    local_transport: pb::local_transport_service_client::LocalTransportServiceClient<Channel>,
    mesh: pb::mesh_service_client::MeshServiceClient<Channel>,
    recovery: pb::recovery_service_client::RecoveryServiceClient<Channel>,
    universal_conference:
        pb::universal_conference_service_client::UniversalConferenceServiceClient<Channel>,
}

impl fmt::Debug for UcrSdkClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UcrSdkClient")
            .field("credential", &self.credential)
            .finish_non_exhaustive()
    }
}
impl UcrSdkClient {
    /// Connects both external-consumer services to one UCR gRPC endpoint.
    ///
    /// # Errors
    /// Returns the transport error from endpoint parsing or connection establishment.
    pub async fn connect(
        endpoint: String,
        credential: ServiceCredential,
    ) -> Result<Self, tonic::transport::Error> {
        let channel = tonic::transport::Endpoint::from_shared(endpoint)?
            .connect()
            .await?;
        let integration =
            pb::integration_service_client::IntegrationServiceClient::new(channel.clone())
                .max_decoding_message_size(SDK_GRPC_MESSAGE_CEILING)
                .max_encoding_message_size(SDK_GRPC_MESSAGE_CEILING);
        let events = pb::event_service_client::EventServiceClient::new(channel.clone())
            .max_decoding_message_size(SDK_GRPC_MESSAGE_CEILING)
            .max_encoding_message_size(SDK_GRPC_MESSAGE_CEILING);
        let calls = pb::call_service_client::CallServiceClient::new(channel.clone())
            .max_decoding_message_size(SDK_GRPC_MESSAGE_CEILING)
            .max_encoding_message_size(SDK_GRPC_MESSAGE_CEILING);
        let groups = pb::group_service_client::GroupServiceClient::new(channel.clone())
            .max_decoding_message_size(SDK_GRPC_MESSAGE_CEILING)
            .max_encoding_message_size(SDK_GRPC_MESSAGE_CEILING);
        let devices = pb::device_service_client::DeviceServiceClient::new(channel.clone())
            .max_decoding_message_size(SDK_GRPC_MESSAGE_CEILING)
            .max_encoding_message_size(SDK_GRPC_MESSAGE_CEILING);
        let sync = pb::sync_service_client::SyncServiceClient::new(channel.clone())
            .max_decoding_message_size(SDK_GRPC_MESSAGE_CEILING)
            .max_encoding_message_size(SDK_GRPC_MESSAGE_CEILING);
        let store_forward =
            pb::store_forward_service_client::StoreForwardServiceClient::new(channel.clone())
                .max_decoding_message_size(SDK_GRPC_MESSAGE_CEILING)
                .max_encoding_message_size(SDK_GRPC_MESSAGE_CEILING);
        let local_transport =
            pb::local_transport_service_client::LocalTransportServiceClient::new(channel.clone())
                .max_decoding_message_size(SDK_GRPC_MESSAGE_CEILING)
                .max_encoding_message_size(SDK_GRPC_MESSAGE_CEILING);
        let mesh = pb::mesh_service_client::MeshServiceClient::new(channel.clone())
            .max_decoding_message_size(SDK_GRPC_MESSAGE_CEILING)
            .max_encoding_message_size(SDK_GRPC_MESSAGE_CEILING);
        let recovery = pb::recovery_service_client::RecoveryServiceClient::new(channel.clone())
            .max_decoding_message_size(SDK_GRPC_MESSAGE_CEILING)
            .max_encoding_message_size(SDK_GRPC_MESSAGE_CEILING);
        let universal_conference =
            pb::universal_conference_service_client::UniversalConferenceServiceClient::new(channel)
                .max_decoding_message_size(SDK_GRPC_MESSAGE_CEILING)
                .max_encoding_message_size(SDK_GRPC_MESSAGE_CEILING);
        Ok(Self {
            credential,
            integration,
            events,
            calls,
            groups,
            devices,
            sync,
            store_forward,
            local_transport,
            mesh,
            recovery,
            universal_conference,
        })
    }
    /// Creates one authenticated request without changing its protobuf body.
    #[must_use]
    pub fn authenticated_request<T>(&self, message: T) -> Request<T> {
        self.credential.authenticated_request(message)
    }

    /// Submits one canonical Command with this SDK credential.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn submit_command(
        &mut self,
        message: pb::IntegrationCommandRequest,
    ) -> Result<pb::IntegrationCommandResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self.integration.submit_command(request).await?.into_inner())
    }

    /// Creates one canonical Root Identity.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn create_identity(
        &mut self,
        message: pb::IntegrationCreateIdentityRequest,
    ) -> Result<pb::IntegrationCreateIdentityResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self
            .integration
            .create_identity(request)
            .await?
            .into_inner())
    }

    /// Links one canonical external Identity binding.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn link_identity(
        &mut self,
        message: pb::IntegrationLinkIdentityRequest,
    ) -> Result<pb::IntegrationLinkIdentityResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self.integration.link_identity(request).await?.into_inner())
    }

    /// Reads one canonical Root Identity.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn get_identity(
        &mut self,
        message: pb::IntegrationGetIdentityRequest,
    ) -> Result<pb::IntegrationGetIdentityResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self.integration.get_identity(request).await?.into_inner())
    }

    /// Resolves one exact external Identity binding.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn resolve_identity_binding(
        &mut self,
        message: pb::IntegrationResolveIdentityBindingRequest,
    ) -> Result<pb::IntegrationResolveIdentityBindingResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self
            .integration
            .resolve_identity_binding(request)
            .await?
            .into_inner())
    }

    /// Creates one canonical Conversation.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn create_conversation(
        &mut self,
        message: pb::IntegrationCreateConversationRequest,
    ) -> Result<pb::IntegrationCreateConversationResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self
            .integration
            .create_conversation(request)
            .await?
            .into_inner())
    }

    /// Reads one canonical Conversation.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn get_conversation(
        &mut self,
        message: pb::IntegrationGetConversationRequest,
    ) -> Result<pb::IntegrationGetConversationResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self
            .integration
            .get_conversation(request)
            .await?
            .into_inner())
    }

    /// Persists one canonical Message and returns its canonical acknowledgement/error envelope.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn send_message(
        &mut self,
        message: pb::IntegrationSendMessageRequest,
    ) -> Result<pb::IntegrationSendMessageResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self.integration.send_message(request).await?.into_inner())
    }

    /// Reads one canonical persisted Message.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn get_message(
        &mut self,
        message: pb::IntegrationGetMessageRequest,
    ) -> Result<pb::IntegrationGetMessageResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self.integration.get_message(request).await?.into_inner())
    }

    /// Persists one canonical Communication Intent.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn create_communication_intent(
        &mut self,
        message: pb::IntegrationCreateCommunicationIntentRequest,
    ) -> Result<pb::IntegrationCreateCommunicationIntentResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self
            .integration
            .create_communication_intent(request)
            .await?
            .into_inner())
    }

    /// Reads one canonical Communication Intent.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn get_communication_intent(
        &mut self,
        message: pb::IntegrationGetCommunicationIntentRequest,
    ) -> Result<pb::IntegrationGetCommunicationIntentResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self
            .integration
            .get_communication_intent(request)
            .await?
            .into_inner())
    }

    /// Publishes one canonical Event.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn publish_event(
        &mut self,
        message: pb::EventPublishRequest,
    ) -> Result<pb::EventPublishResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self.events.publish_event(request).await?.into_inner())
    }

    /// Creates one canonical durable Event subscription.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn create_subscription(
        &mut self,
        message: pb::EventCreateSubscriptionRequest,
    ) -> Result<pb::EventCreateSubscriptionResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self.events.create_subscription(request).await?.into_inner())
    }

    /// Reads one canonical Event subscription.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn get_subscription(
        &mut self,
        message: pb::EventGetSubscriptionRequest,
    ) -> Result<pb::EventGetSubscriptionResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self.events.get_subscription(request).await?.into_inner())
    }

    /// Polls canonical Events while preserving the opaque cursor.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn poll_events(
        &mut self,
        message: pb::EventPollRequest,
    ) -> Result<pb::EventPollResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self.events.poll_events(request).await?.into_inner())
    }

    /// Acknowledges one canonical Event cursor.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn acknowledge_events(
        &mut self,
        message: pb::EventAcknowledgeRequest,
    ) -> Result<pb::EventAcknowledgeResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self.events.acknowledge_events(request).await?.into_inner())
    }

    /// Rejects one canonical Event cursor with the supplied canonical failure kind.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn reject_events(
        &mut self,
        message: pb::EventRejectRequest,
    ) -> Result<pb::EventRejectResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self.events.reject_events(request).await?.into_inner())
    }

    /// Requests canonical replay for one Event subscription.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn replay_subscription(
        &mut self,
        message: pb::EventReplayRequest,
    ) -> Result<pb::EventReplayResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self.events.replay_subscription(request).await?.into_inner())
    }

    /// Starts one canonical Call signalling session.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn start_call(
        &mut self,
        message: pb::CallStartRequest,
    ) -> Result<pb::CallStartResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self.calls.start_call(request).await?.into_inner())
    }

    /// Reads one canonical Call signalling session.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn get_call(
        &mut self,
        message: pb::CallGetRequest,
    ) -> Result<pb::CallGetResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self.calls.get_call(request).await?.into_inner())
    }

    /// Applies one canonical Call signalling transition.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn signal_call(
        &mut self,
        message: pb::CallSignalRequest,
    ) -> Result<pb::CallSignalResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self.calls.signal_call(request).await?.into_inner())
    }

    /// Creates one canonical Group through the public Group service.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn create_group(
        &mut self,
        message: pb::GroupCreateRequest,
    ) -> Result<pb::GroupCreateResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self.groups.create_group(request).await?.into_inner())
    }

    /// Reads one canonical Group through the public Group service.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn get_group(
        &mut self,
        message: pb::GroupGetRequest,
    ) -> Result<pb::GroupGetResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self.groups.get_group(request).await?.into_inner())
    }

    /// Reads one membership through the public Group service.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn get_group_membership(
        &mut self,
        message: pb::GroupGetMembershipRequest,
    ) -> Result<pb::GroupGetMembershipResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self.groups.get_membership(request).await?.into_inner())
    }

    /// Lists bounded canonical memberships through the public Group service.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn list_group_memberships(
        &mut self,
        message: pb::GroupListMembershipsRequest,
    ) -> Result<pb::GroupListMembershipsResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self.groups.list_memberships(request).await?.into_inner())
    }

    /// Applies one canonical Group mutation through the public Group service.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn apply_group_change(
        &mut self,
        message: pb::GroupApplyChangeRequest,
    ) -> Result<pb::GroupApplyChangeResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self.groups.apply_change(request).await?.into_inner())
    }

    /// Persists one membership-gated Group Message through the public Group service.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn send_group_message(
        &mut self,
        message: pb::GroupSendMessageRequest,
    ) -> Result<pb::GroupSendMessageResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self.groups.send_group_message(request).await?.into_inner())
    }

    /// Reads one membership/history-gated Group Message through the public Group service.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn get_group_message(
        &mut self,
        message: pb::GroupGetMessageRequest,
    ) -> Result<pb::GroupGetMessageResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self.groups.get_group_message(request).await?.into_inner())
    }

    /// Registers one canonical Device through the public Device service.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn register_device(
        &mut self,
        message: pb::DeviceRegisterRequest,
    ) -> Result<pb::DeviceRegisterResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self.devices.register_device(request).await?.into_inner())
    }

    /// Reads one canonical Device through the public Device service.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn get_device(
        &mut self,
        message: pb::DeviceGetRequest,
    ) -> Result<pb::DeviceGetResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self.devices.get_device(request).await?.into_inner())
    }

    /// Revokes one canonical Device through the public Device service.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn revoke_device(
        &mut self,
        message: pb::DeviceRevokeRequest,
    ) -> Result<pb::DeviceRevokeResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self.devices.revoke_device(request).await?.into_inner())
    }

    /// Creates or deduplicates one canonical Sync session.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn create_sync_session(
        &mut self,
        message: pb::SyncCreateRequest,
    ) -> Result<pb::SyncCreateResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self.sync.create_sync_session(request).await?.into_inner())
    }

    /// Reads one canonical Sync session.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn get_sync_session(
        &mut self,
        message: pb::SyncGetRequest,
    ) -> Result<pb::SyncGetResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self.sync.get_sync_session(request).await?.into_inner())
    }

    /// Advances one canonical Sync session by expected-state compare-and-swap.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn transition_sync(
        &mut self,
        message: pb::SyncTransitionRequest,
    ) -> Result<pb::SyncTransitionResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self.sync.transition_sync(request).await?.into_inner())
    }

    /// Records one canonical monotonic Sync checkpoint.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn record_sync_checkpoint(
        &mut self,
        message: pb::SyncRecordCheckpointRequest,
    ) -> Result<pb::SyncRecordCheckpointResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self
            .sync
            .record_sync_checkpoint(request)
            .await?
            .into_inner())
    }

    /// Reads the latest canonical Sync checkpoint.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn get_latest_sync_checkpoint(
        &mut self,
        message: pb::SyncGetLatestCheckpointRequest,
    ) -> Result<pb::SyncGetLatestCheckpointResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self
            .sync
            .get_latest_sync_checkpoint(request)
            .await?
            .into_inner())
    }

    /// Durably enqueues one Store-and-Forward job without running worker scheduling in the SDK.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn enqueue_store_forward(
        &mut self,
        message: pb::StoreForwardEnqueueRequest,
    ) -> Result<pb::StoreForwardEnqueueResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self.store_forward.enqueue(request).await?.into_inner())
    }

    /// Reads payload-free Store-and-Forward scheduling status.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn get_store_forward_status(
        &mut self,
        message: pb::StoreForwardGetStatusRequest,
    ) -> Result<pb::StoreForwardGetStatusResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self.store_forward.get_status(request).await?.into_inner())
    }

    /// Transmits one already-encrypted envelope through the public local/direct transport service.
    ///
    /// The SDK performs no discovery, route fallback or application retry.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn transmit_local(
        &mut self,
        message: pb::LocalTransportTransmitRequest,
    ) -> Result<pb::LocalTransportTransmitResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self.local_transport.transmit(request).await?.into_inner())
    }

    /// Exports one bounded page of signed Group Message replicas to an authenticated Mesh peer.
    ///
    /// Peer identity and cryptographic session state remain server-owned live-session evidence.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn export_mesh_group_messages(
        &mut self,
        message: pb::MeshExportGroupMessagesRequest,
    ) -> Result<pb::MeshExportGroupMessagesResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self.mesh.export_group_messages(request).await?.into_inner())
    }

    /// Reconciles one signed multi-hop Group Message from an authenticated Mesh peer.
    ///
    /// The SDK performs no discovery, topology selection, NAT traversal or automatic retry.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn reconcile_mesh_group_message(
        &mut self,
        message: pb::MeshReconcileGroupMessageRequest,
    ) -> Result<pb::MeshReconcileGroupMessageResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self
            .mesh
            .reconcile_group_message(request)
            .await?
            .into_inner())
    }

    /// Installs one canonical Recovery Plan through ordinary plan-administration permission.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the public UCR service.
    pub async fn install_recovery_plan(
        &mut self,
        message: pb::RecoveryInstallPlanRequest,
    ) -> Result<pb::RecoveryPlanMutationResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self.recovery.install_plan(request).await?.into_inner())
    }

    /// Rotates one canonical Recovery Plan through expected-current compare-and-swap.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the public UCR service.
    pub async fn rotate_recovery_plan(
        &mut self,
        message: pb::RecoveryRotatePlanRequest,
    ) -> Result<pb::RecoveryPlanMutationResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self.recovery.rotate_plan(request).await?.into_inner())
    }

    /// Revokes one canonical Recovery Plan.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the public UCR service.
    pub async fn revoke_recovery_plan(
        &mut self,
        message: pb::RecoveryRevokePlanRequest,
    ) -> Result<pb::RecoveryPlanMutationResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self.recovery.revoke_plan(request).await?.into_inner())
    }

    /// Reads the active canonical Recovery Plan.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the public UCR service.
    pub async fn get_active_recovery_plan(
        &mut self,
        message: pb::RecoveryGetActivePlanRequest,
    ) -> Result<pb::RecoveryGetActivePlanResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self.recovery.get_active_plan(request).await?.into_inner())
    }

    /// Requests proof-gated staging of one recovered Device.
    ///
    /// Service Principal metadata admits and audits the application channel only; the active
    /// Recovery Plan and independent verifier remain the recovery authority.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the public UCR service.
    pub async fn stage_recovered_device(
        &mut self,
        message: pb::RecoveryStageDeviceRequest,
    ) -> Result<pb::RecoveryDeviceResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self
            .recovery
            .stage_recovered_device(request)
            .await?
            .into_inner())
    }

    /// Requests independent re-verification and activation of one staged recovered Device.
    ///
    /// Service Principal metadata gates the RPC channel; independent re-verification remains
    /// the authority that can promote the staged Device to Active.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the public UCR service.
    pub async fn activate_recovered_device(
        &mut self,
        message: pb::RecoveryActivateDeviceRequest,
    ) -> Result<pb::RecoveryDeviceResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self
            .recovery
            .activate_recovered_device(request)
            .await?
            .into_inner())
    }

    /// Creates or resolves one integration-owned universal Conference.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn create_conference(
        &mut self,
        message: pb::UniversalCreateConferenceRequest,
    ) -> Result<pb::UniversalCreateConferenceResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self
            .universal_conference
            .create_conference(request)
            .await?
            .into_inner())
    }

    /// Resolves one universal Conference from the integration's external reference.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn resolve_conference(
        &mut self,
        message: pb::UniversalResolveConferenceRequest,
    ) -> Result<pb::UniversalResolveConferenceResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self
            .universal_conference
            .resolve_conference(request)
            .await?
            .into_inner())
    }

    /// Reads one integration-scoped universal Conference.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn get_conference(
        &mut self,
        message: pb::UniversalGetConferenceRequest,
    ) -> Result<pb::UniversalGetConferenceResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self
            .universal_conference
            .get_conference(request)
            .await?
            .into_inner())
    }

    /// Applies one universal Conference lifecycle transition.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn transition_conference(
        &mut self,
        message: pb::UniversalConferenceLifecycleRequest,
    ) -> Result<pb::UniversalConferenceLifecycleResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self
            .universal_conference
            .transition_conference(request)
            .await?
            .into_inner())
    }

    /// Opens or closes attendee entry for one universal Conference.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn set_entry_open(
        &mut self,
        message: pb::UniversalSetEntryOpenRequest,
    ) -> Result<pb::UniversalSetEntryOpenResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self
            .universal_conference
            .set_entry_open(request)
            .await?
            .into_inner())
    }

    /// Ensures one integration-owned participant without exposing UCR internal identifiers.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn ensure_participant(
        &mut self,
        message: pb::UniversalEnsureParticipantRequest,
    ) -> Result<pb::UniversalEnsureParticipantResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self
            .universal_conference
            .ensure_participant(request)
            .await?
            .into_inner())
    }

    /// Ensures one canonical active Device for an integration-owned participant.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn ensure_participant_device(
        &mut self,
        message: pb::UniversalEnsureParticipantDeviceRequest,
    ) -> Result<pb::UniversalEnsureParticipantDeviceResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self
            .universal_conference
            .ensure_participant_device(request)
            .await?
            .into_inner())
    }

    /// Updates one participant's role and media policy through the universal facade.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn update_participant(
        &mut self,
        message: pb::UniversalUpdateParticipantRequest,
    ) -> Result<pb::UniversalUpdateParticipantResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self
            .universal_conference
            .update_participant(request)
            .await?
            .into_inner())
    }

    /// Removes one integration-owned participant through the universal facade.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn remove_participant(
        &mut self,
        message: pb::UniversalRemoveParticipantRequest,
    ) -> Result<pb::UniversalRemoveParticipantResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self
            .universal_conference
            .remove_participant(request)
            .await?
            .into_inner())
    }

    /// Lists bounded integration-owned participant projections.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn list_participants(
        &mut self,
        message: pb::UniversalListParticipantsRequest,
    ) -> Result<pb::UniversalListParticipantsResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self
            .universal_conference
            .list_participants(request)
            .await?
            .into_inner())
    }

    /// Replaces one participant's bounded receive-subscription preference.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn set_subscriptions(
        &mut self,
        message: pb::UniversalSetSubscriptionsRequest,
    ) -> Result<pb::UniversalSetSubscriptionsResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self
            .universal_conference
            .set_subscriptions(request)
            .await?
            .into_inner())
    }

    /// Reconciles universal Conference metadata into the canonical Group/Call runtime.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn prepare_conference_runtime(
        &mut self,
        message: pb::UniversalPrepareConferenceRuntimeRequest,
    ) -> Result<pb::UniversalPrepareConferenceRuntimeResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self
            .universal_conference
            .prepare_conference_runtime(request)
            .await?
            .into_inner())
    }

    /// Issues one short-lived integration-facing Conference join grant.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn issue_join_grant(
        &mut self,
        message: pb::UniversalIssueJoinGrantRequest,
    ) -> Result<pb::UniversalIssueJoinGrantResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self
            .universal_conference
            .issue_join_grant(request)
            .await?
            .into_inner())
    }

    /// Revokes one previously issued universal Conference join grant.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn revoke_join_grant(
        &mut self,
        message: pb::UniversalRevokeJoinGrantRequest,
    ) -> Result<pb::UniversalRevokeJoinGrantResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self
            .universal_conference
            .revoke_join_grant(request)
            .await?
            .into_inner())
    }

    /// Reads the canonical attendance projection for one integration-owned participant.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn get_participant_attendance(
        &mut self,
        message: pb::UniversalGetParticipantAttendanceRequest,
    ) -> Result<pb::UniversalGetParticipantAttendanceResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self
            .universal_conference
            .get_participant_attendance(request)
            .await?
            .into_inner())
    }

    /// Reads integration-visible universal Conference capabilities.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn get_conference_capabilities(
        &mut self,
        message: pb::UniversalGetCapabilitiesRequest,
    ) -> Result<pb::UniversalGetCapabilitiesResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self
            .universal_conference
            .get_capabilities(request)
            .await?
            .into_inner())
    }

    /// Lists canonical dead letters for one Event subscription.
    ///
    /// # Errors
    /// Returns the gRPC status produced by the canonical UCR service.
    pub async fn list_dead_letters(
        &mut self,
        message: pb::EventListDeadLettersRequest,
    ) -> Result<pb::EventListDeadLettersResponse, tonic::Status> {
        let request = self.authenticated_request(message);
        Ok(self.events.list_dead_letters(request).await?.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_debug_redacts_secret_and_identifier_bytes() {
        let credential = ServiceCredential::new(b"credential-visible".to_vec(), vec![0xa5; 32]);
        let debug = format!("{credential:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("credential-visible"));
        assert!(!debug.contains("165"));
    }
    #[test]
    fn credential_metadata_is_binary_exact_and_sensitive() {
        let credential = ServiceCredential::new(b"credential-id".to_vec(), vec![0x5a; 32]);
        let request = credential.authenticated_request(());
        let id = request
            .metadata()
            .get_bin(SERVICE_CREDENTIAL_ID_METADATA_KEY)
            .expect("credential id metadata");
        assert_eq!(
            id.to_bytes().expect("decode id metadata").as_ref(),
            b"credential-id"
        );
        assert!(id.is_sensitive());
        let secret = request
            .metadata()
            .get_bin(SERVICE_CREDENTIAL_SECRET_METADATA_KEY)
            .expect("credential secret metadata");
        assert_eq!(
            secret.to_bytes().expect("decode secret metadata").as_ref(),
            &[0x5a; 32]
        );
        assert!(secret.is_sensitive());
    }
}
