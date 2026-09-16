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
        let groups = pb::group_service_client::GroupServiceClient::new(channel)
            .max_decoding_message_size(SDK_GRPC_MESSAGE_CEILING)
            .max_encoding_message_size(SDK_GRPC_MESSAGE_CEILING);
        Ok(Self {
            credential,
            integration,
            events,
            calls,
            groups,
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
