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
    fn proof_matrix_keeps_unexposed_features_explicitly_blocked() {
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
                    && item.state == ProofState::PublicApiGap)
        );
        assert!(
            matrix
                .iter()
                .any(|item| item.capability == ProofCapability::Calls
                    && item.state == ProofState::PublicApiAvailable)
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
