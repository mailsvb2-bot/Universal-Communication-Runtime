use std::fmt;

use ucr_sdk::{RpcStatus, ServiceCredential, TransportError, UcrSdkClient, pb};

/// Thin Reference Messenger consumer of the public UCR SDK.
pub struct ReferenceMessengerClient {
    sdk: UcrSdkClient,
}

impl fmt::Debug for ReferenceMessengerClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReferenceMessengerClient")
            .field("sdk", &self.sdk)
            .finish()
    }
}

impl ReferenceMessengerClient {
    /// Connects the Reference Messenger to one public UCR endpoint.
    ///
    /// # Errors
    /// Returns the public SDK transport error if the endpoint cannot be parsed or connected.
    pub async fn connect(
        endpoint: String,
        credential: ServiceCredential,
    ) -> Result<Self, TransportError> {
        Ok(Self {
            sdk: UcrSdkClient::connect(endpoint, credential).await?,
        })
    }

    /// Creates one canonical Identity through the public Integration service.
    ///
    /// # Errors
    /// Returns transport-level gRPC status unchanged from the public SDK.
    pub async fn create_identity(
        &mut self,
        request: pb::IntegrationCreateIdentityRequest,
    ) -> Result<pb::IntegrationCreateIdentityResponse, RpcStatus> {
        self.sdk.create_identity(request).await
    }

    /// Creates one canonical Conversation through the public Integration service.
    ///
    /// # Errors
    /// Returns transport-level gRPC status unchanged from the public SDK.
    pub async fn create_conversation(
        &mut self,
        request: pb::IntegrationCreateConversationRequest,
    ) -> Result<pb::IntegrationCreateConversationResponse, RpcStatus> {
        self.sdk.create_conversation(request).await
    }

    /// Persists one canonical Message without inventing Delivery or Read success.
    ///
    /// # Errors
    /// Returns transport-level gRPC status unchanged from the public SDK.
    pub async fn send_message(
        &mut self,
        request: pb::IntegrationSendMessageRequest,
    ) -> Result<pb::IntegrationSendMessageResponse, RpcStatus> {
        self.sdk.send_message(request).await
    }

    /// Reads one canonical Message through the public Integration service.
    ///
    /// # Errors
    /// Returns transport-level gRPC status unchanged from the public SDK.
    pub async fn get_message(
        &mut self,
        request: pb::IntegrationGetMessageRequest,
    ) -> Result<pb::IntegrationGetMessageResponse, RpcStatus> {
        self.sdk.get_message(request).await
    }

    /// Creates one canonical Group through the public Group service.
    ///
    /// # Errors
    /// Returns transport-level gRPC status unchanged from the public SDK.
    pub async fn create_group(
        &mut self,
        request: pb::GroupCreateRequest,
    ) -> Result<pb::GroupCreateResponse, RpcStatus> {
        self.sdk.create_group(request).await
    }

    /// Reads one canonical Group through the public Group service.
    ///
    /// # Errors
    /// Returns transport-level gRPC status unchanged from the public SDK.
    pub async fn get_group(
        &mut self,
        request: pb::GroupGetRequest,
    ) -> Result<pb::GroupGetResponse, RpcStatus> {
        self.sdk.get_group(request).await
    }

    /// Reads one canonical Group membership through the public Group service.
    ///
    /// # Errors
    /// Returns transport-level gRPC status unchanged from the public SDK.
    pub async fn get_group_membership(
        &mut self,
        request: pb::GroupGetMembershipRequest,
    ) -> Result<pb::GroupGetMembershipResponse, RpcStatus> {
        self.sdk.get_group_membership(request).await
    }

    /// Lists bounded canonical Group memberships through the public Group service.
    ///
    /// # Errors
    /// Returns transport-level gRPC status unchanged from the public SDK.
    pub async fn list_group_memberships(
        &mut self,
        request: pb::GroupListMembershipsRequest,
    ) -> Result<pb::GroupListMembershipsResponse, RpcStatus> {
        self.sdk.list_group_memberships(request).await
    }

    /// Applies one canonical Group mutation through the public Group service.
    ///
    /// # Errors
    /// Returns transport-level gRPC status unchanged from the public SDK.
    pub async fn apply_group_change(
        &mut self,
        request: pb::GroupApplyChangeRequest,
    ) -> Result<pb::GroupApplyChangeResponse, RpcStatus> {
        self.sdk.apply_group_change(request).await
    }

    /// Sends one membership-gated Group Message through the public Group service.
    ///
    /// # Errors
    /// Returns transport-level gRPC status unchanged from the public SDK.
    pub async fn send_group_message(
        &mut self,
        request: pb::GroupSendMessageRequest,
    ) -> Result<pb::GroupSendMessageResponse, RpcStatus> {
        self.sdk.send_group_message(request).await
    }

    /// Reads one membership/history-gated Group Message through the public Group service.
    ///
    /// # Errors
    /// Returns transport-level gRPC status unchanged from the public SDK.
    pub async fn get_group_message(
        &mut self,
        request: pb::GroupGetMessageRequest,
    ) -> Result<pb::GroupGetMessageResponse, RpcStatus> {
        self.sdk.get_group_message(request).await
    }

    /// Registers one canonical Device through the public Device service.
    ///
    /// # Errors
    /// Returns transport-level gRPC status unchanged from the public SDK.
    pub async fn register_device(
        &mut self,
        request: pb::DeviceRegisterRequest,
    ) -> Result<pb::DeviceRegisterResponse, RpcStatus> {
        self.sdk.register_device(request).await
    }

    /// Reads one canonical Device through the public Device service.
    ///
    /// # Errors
    /// Returns transport-level gRPC status unchanged from the public SDK.
    pub async fn get_device(
        &mut self,
        request: pb::DeviceGetRequest,
    ) -> Result<pb::DeviceGetResponse, RpcStatus> {
        self.sdk.get_device(request).await
    }

    /// Revokes one canonical Device through the public Device service.
    ///
    /// # Errors
    /// Returns transport-level gRPC status unchanged from the public SDK.
    pub async fn revoke_device(
        &mut self,
        request: pb::DeviceRevokeRequest,
    ) -> Result<pb::DeviceRevokeResponse, RpcStatus> {
        self.sdk.revoke_device(request).await
    }

    /// Creates or deduplicates one canonical Sync session through the public Sync service.
    ///
    /// # Errors
    /// Returns transport-level gRPC status unchanged from the public SDK.
    pub async fn create_sync_session(
        &mut self,
        request: pb::SyncCreateRequest,
    ) -> Result<pb::SyncCreateResponse, RpcStatus> {
        self.sdk.create_sync_session(request).await
    }

    /// Reads one canonical Sync session through the public Sync service.
    ///
    /// # Errors
    /// Returns transport-level gRPC status unchanged from the public SDK.
    pub async fn get_sync_session(
        &mut self,
        request: pb::SyncGetRequest,
    ) -> Result<pb::SyncGetResponse, RpcStatus> {
        self.sdk.get_sync_session(request).await
    }

    /// Advances one canonical Sync session by expected-state compare-and-swap.
    ///
    /// # Errors
    /// Returns transport-level gRPC status unchanged from the public SDK.
    pub async fn transition_sync(
        &mut self,
        request: pb::SyncTransitionRequest,
    ) -> Result<pb::SyncTransitionResponse, RpcStatus> {
        self.sdk.transition_sync(request).await
    }

    /// Records one canonical monotonic Sync checkpoint.
    ///
    /// # Errors
    /// Returns transport-level gRPC status unchanged from the public SDK.
    pub async fn record_sync_checkpoint(
        &mut self,
        request: pb::SyncRecordCheckpointRequest,
    ) -> Result<pb::SyncRecordCheckpointResponse, RpcStatus> {
        self.sdk.record_sync_checkpoint(request).await
    }

    /// Reads the latest canonical Sync checkpoint.
    ///
    /// # Errors
    /// Returns transport-level gRPC status unchanged from the public SDK.
    pub async fn get_latest_sync_checkpoint(
        &mut self,
        request: pb::SyncGetLatestCheckpointRequest,
    ) -> Result<pb::SyncGetLatestCheckpointResponse, RpcStatus> {
        self.sdk.get_latest_sync_checkpoint(request).await
    }

    /// Queues one already-canonical encrypted delivery for offline Store-and-Forward handling.
    ///
    /// The Reference Messenger does not run leases, retries, route discovery or provider calls.
    ///
    /// # Errors
    /// Returns transport-level gRPC status unchanged from the public SDK.
    pub async fn queue_offline_delivery(
        &mut self,
        request: pb::StoreForwardEnqueueRequest,
    ) -> Result<pb::StoreForwardEnqueueResponse, RpcStatus> {
        self.sdk.enqueue_store_forward(request).await
    }

    /// Reads payload-free offline delivery scheduling status.
    ///
    /// # Errors
    /// Returns transport-level gRPC status unchanged from the public SDK.
    pub async fn get_offline_delivery_status(
        &mut self,
        request: pb::StoreForwardGetStatusRequest,
    ) -> Result<pb::StoreForwardGetStatusResponse, RpcStatus> {
        self.sdk.get_store_forward_status(request).await
    }

    /// Attempts one direct local transport of an already-encrypted envelope.
    ///
    /// Success is only peer transport acceptance/deduplication, never delivery/read evidence.
    /// The Reference Messenger performs no hidden retry or route fallback.
    ///
    /// # Errors
    /// Returns transport-level gRPC status unchanged from the public SDK.
    pub async fn send_direct_local(
        &mut self,
        request: pb::LocalTransportTransmitRequest,
    ) -> Result<pb::LocalTransportTransmitResponse, RpcStatus> {
        self.sdk.transmit_local(request).await
    }

    /// Exports one bounded page of signed Group Messages to an authenticated P2P/Mesh peer.
    ///
    /// The Reference Messenger does not choose topology, routes, relays or peer trust.
    ///
    /// # Errors
    /// Returns transport-level gRPC status unchanged from the public SDK.
    pub async fn export_p2p_group_messages(
        &mut self,
        request: pb::MeshExportGroupMessagesRequest,
    ) -> Result<pb::MeshExportGroupMessagesResponse, RpcStatus> {
        self.sdk.export_mesh_group_messages(request).await
    }

    /// Reconciles one signed multi-hop Group Message received from an authenticated P2P/Mesh peer.
    ///
    /// # Errors
    /// Returns transport-level gRPC status unchanged from the public SDK.
    pub async fn reconcile_p2p_group_message(
        &mut self,
        request: pb::MeshReconcileGroupMessageRequest,
    ) -> Result<pb::MeshReconcileGroupMessageResponse, RpcStatus> {
        self.sdk.reconcile_mesh_group_message(request).await
    }

    /// Installs one canonical Recovery Plan through the public Recovery service.
    ///
    /// # Errors
    /// Returns transport-level gRPC status unchanged from the public SDK.
    pub async fn install_recovery_plan(
        &mut self,
        request: pb::RecoveryInstallPlanRequest,
    ) -> Result<pb::RecoveryPlanMutationResponse, RpcStatus> {
        self.sdk.install_recovery_plan(request).await
    }

    /// Rotates one canonical Recovery Plan through expected-current compare-and-swap.
    ///
    /// # Errors
    /// Returns transport-level gRPC status unchanged from the public SDK.
    pub async fn rotate_recovery_plan(
        &mut self,
        request: pb::RecoveryRotatePlanRequest,
    ) -> Result<pb::RecoveryPlanMutationResponse, RpcStatus> {
        self.sdk.rotate_recovery_plan(request).await
    }

    /// Revokes one canonical Recovery Plan through the public Recovery service.
    ///
    /// # Errors
    /// Returns transport-level gRPC status unchanged from the public SDK.
    pub async fn revoke_recovery_plan(
        &mut self,
        request: pb::RecoveryRevokePlanRequest,
    ) -> Result<pb::RecoveryPlanMutationResponse, RpcStatus> {
        self.sdk.revoke_recovery_plan(request).await
    }

    /// Reads the active canonical Recovery Plan through the public Recovery service.
    ///
    /// # Errors
    /// Returns transport-level gRPC status unchanged from the public SDK.
    pub async fn get_active_recovery_plan(
        &mut self,
        request: pb::RecoveryGetActivePlanRequest,
    ) -> Result<pb::RecoveryGetActivePlanResponse, RpcStatus> {
        self.sdk.get_active_recovery_plan(request).await
    }

    /// Requests recovery-authority-gated staging of one recovered Device.
    ///
    /// Service Principal permission admits the application channel only; it cannot replace the
    /// active Recovery Plan or independent recovery-authority proof.
    ///
    /// # Errors
    /// Returns transport-level gRPC status unchanged from the public SDK.
    pub async fn stage_recovered_device(
        &mut self,
        request: pb::RecoveryStageDeviceRequest,
    ) -> Result<pb::RecoveryDeviceResponse, RpcStatus> {
        self.sdk.stage_recovered_device(request).await
    }

    /// Requests independent re-verification and activation of one staged recovered Device.
    ///
    /// # Errors
    /// Returns transport-level gRPC status unchanged from the public SDK.
    pub async fn activate_recovered_device(
        &mut self,
        request: pb::RecoveryActivateDeviceRequest,
    ) -> Result<pb::RecoveryDeviceResponse, RpcStatus> {
        self.sdk.activate_recovered_device(request).await
    }

    /// Starts canonical Call signalling through the public Call service.
    ///
    /// # Errors
    /// Returns transport-level gRPC status unchanged from the public SDK.
    pub async fn start_call(
        &mut self,
        request: pb::CallStartRequest,
    ) -> Result<pb::CallStartResponse, RpcStatus> {
        self.sdk.start_call(request).await
    }

    /// Reads canonical Call signalling state through the public Call service.
    ///
    /// # Errors
    /// Returns transport-level gRPC status unchanged from the public SDK.
    pub async fn get_call(
        &mut self,
        request: pb::CallGetRequest,
    ) -> Result<pb::CallGetResponse, RpcStatus> {
        self.sdk.get_call(request).await
    }

    /// Applies one canonical Call signalling transition through the public Call service.
    ///
    /// # Errors
    /// Returns transport-level gRPC status unchanged from the public SDK.
    pub async fn signal_call(
        &mut self,
        request: pb::CallSignalRequest,
    ) -> Result<pb::CallSignalResponse, RpcStatus> {
        self.sdk.signal_call(request).await
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        PrimaryConcept, ProofCapability, ProofState, StatusIndicator, phase40_proof_matrix,
    };

    #[test]
    fn proof_matrix_keeps_remaining_accessibility_gap_explicit() {
        let matrix = phase40_proof_matrix();
        assert_eq!(matrix.len(), 9);
        assert!(
            matrix
                .iter()
                .any(|item| item.capability == ProofCapability::Groups
                    && item.state == ProofState::PublicApiAvailable)
        );
        assert!(
            matrix
                .iter()
                .any(|item| item.capability == ProofCapability::Recovery
                    && item.state == ProofState::PublicApiAvailable)
        );
        assert!(
            matrix
                .iter()
                .any(|item| item.capability == ProofCapability::Calls
                    && item.state == ProofState::PublicApiAvailable)
        );
        assert!(
            matrix
                .iter()
                .any(|item| item.capability == ProofCapability::Accessibility
                    && item.state == ProofState::PresentationModelOnly)
        );
    }

    #[test]
    fn presentation_vocabulary_uses_user_concepts_not_transport_implementation_names() {
        let concepts = [
            PrimaryConcept::Person,
            PrimaryConcept::Group,
            PrimaryConcept::Message,
            PrimaryConcept::Call,
            PrimaryConcept::Result,
        ];
        let statuses = [
            StatusIndicator::SecureCommunication,
            StatusIndicator::IdentityVerified,
            StatusIndicator::DirectCommunication,
            StatusIndicator::ExternalService,
            StatusIndicator::PartiallyLimited,
            StatusIndicator::AwaitingDeliveryOpportunity,
        ];
        assert_eq!(concepts.len(), 5);
        assert_eq!(statuses.len(), 6);
    }
}
