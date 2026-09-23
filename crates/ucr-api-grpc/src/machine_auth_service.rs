use core::fmt;
use std::sync::Arc;

use tonic::{Request, Response, Status};
use ucr_core::{
    AuthorizationEvaluator, ServiceAuditStore, ServiceCredentialStore, ServiceQuotaClock,
    ServiceQuotaStore,
};
use ucr_crypto::{MachineTokenPolicy, MachineTokenSigningKey};
use ucr_machine_auth::{
    MachineAuthExchangeRequest, MachineAuthRuntime, SUPPORTED_MACHINE_SCOPES,
};
use ucr_protocol::{CanonicalError, CanonicalErrorCode};

use crate::{
    GRPC_MAX_DECODING_MESSAGE_SIZE, GRPC_MAX_ENCODING_MESSAGE_SIZE, decode_credentials,
    decode_opaque, decode_scope, invalid_argument, pb, pb_error,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineAuthDiscovery {
    pub token_endpoint: String,
    pub jwks_uri: String,
}

pub struct GrpcMachineAuthService<C, A, S> {
    clock: Arc<C>,
    authorization: Arc<A>,
    store: Arc<S>,
    signing_key: Arc<MachineTokenSigningKey>,
    policy: MachineTokenPolicy,
    discovery: MachineAuthDiscovery,
}

impl<C, A, S> GrpcMachineAuthService<C, A, S> {
    #[must_use]
    pub const fn new(
        clock: Arc<C>,
        authorization: Arc<A>,
        store: Arc<S>,
        signing_key: Arc<MachineTokenSigningKey>,
        policy: MachineTokenPolicy,
        discovery: MachineAuthDiscovery,
    ) -> Self {
        Self {
            clock,
            authorization,
            store,
            signing_key,
            policy,
            discovery,
        }
    }
}

impl<C, A, S> Clone for GrpcMachineAuthService<C, A, S> {
    fn clone(&self) -> Self {
        Self {
            clock: Arc::clone(&self.clock),
            authorization: Arc::clone(&self.authorization),
            store: Arc::clone(&self.store),
            signing_key: Arc::clone(&self.signing_key),
            policy: self.policy.clone(),
            discovery: self.discovery.clone(),
        }
    }
}

impl<C, A, S> fmt::Debug for GrpcMachineAuthService<C, A, S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GrpcMachineAuthService")
            .field("policy", &self.policy)
            .field("discovery", &self.discovery)
            .field("signing_key", &"<secret>")
            .finish_non_exhaustive()
    }
}

#[must_use]
pub fn machine_auth_service_server<C, A, S>(
    service: GrpcMachineAuthService<C, A, S>,
) -> pb::machine_auth_service_server::MachineAuthServiceServer<GrpcMachineAuthService<C, A, S>>
where
    C: ServiceQuotaClock + 'static,
    A: AuthorizationEvaluator + 'static,
    S: ServiceCredentialStore + ServiceQuotaStore + ServiceAuditStore + 'static,
{
    pb::machine_auth_service_server::MachineAuthServiceServer::new(service)
        .max_decoding_message_size(GRPC_MAX_DECODING_MESSAGE_SIZE)
        .max_encoding_message_size(GRPC_MAX_ENCODING_MESSAGE_SIZE)
}

impl<C, A, S> GrpcMachineAuthService<C, A, S>
where
    C: ServiceQuotaClock,
    A: AuthorizationEvaluator,
    S: ServiceCredentialStore + ServiceQuotaStore + ServiceAuditStore,
{
    fn exchange(
        &self,
        credential_id: &ucr_model::ServiceCredentialId,
        secret: &ucr_core::ServiceCredentialSecret,
        request: pb::MachineTokenRequest,
    ) -> Result<pb::MachineAccessToken, CanonicalError> {
        let scope = decode_scope(request.scope.ok_or_else(invalid_argument)?)?;
        let client_id = decode_opaque(request.client_id)?;
        let requested_ttl_seconds =
            (request.requested_ttl_seconds != 0).then_some(request.requested_ttl_seconds);
        let runtime = MachineAuthRuntime::new(
            &*self.clock,
            &*self.authorization,
            &*self.store,
            &self.signing_key,
            &self.policy,
        );
        let grant = runtime.exchange(MachineAuthExchangeRequest {
            scope: &scope,
            credential_id,
            secret,
            client_id: &client_id,
            requested_scopes: &request.requested_scopes,
            audience: &request.audience,
            requested_ttl_seconds,
        })?;

        Ok(pb::MachineAccessToken {
            access_token: grant.access_token().as_bytes().to_vec(),
            token_type: "Bearer".to_owned(),
            expires_in_seconds: grant.expires_in_seconds,
            granted_scopes: grant.granted_scopes,
            issuer: grant.issuer,
            audience: grant.audience,
            key_id: grant.key_id.as_opaque().as_str().to_owned(),
        })
    }
}

#[tonic::async_trait]
impl<C, A, S> pb::machine_auth_service_server::MachineAuthService
    for GrpcMachineAuthService<C, A, S>
where
    C: ServiceQuotaClock + 'static,
    A: AuthorizationEvaluator + 'static,
    S: ServiceCredentialStore + ServiceQuotaStore + ServiceAuditStore + 'static,
{
    async fn exchange_client_credentials(
        &self,
        request: Request<pb::MachineTokenRequest>,
    ) -> Result<Response<pb::MachineTokenResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let body = request.into_inner();
        let result = match credentials {
            Ok((credential_id, secret)) => self.exchange(&credential_id, &secret, body),
            Err(error) => Err(error),
        };

        Ok(Response::new(pb::MachineTokenResponse {
            result: Some(match result {
                Ok(token) => pb::machine_token_response::Result::Token(token),
                Err(error) => pb::machine_token_response::Result::Error(pb_error(error)),
            }),
        }))
    }

    async fn get_metadata(
        &self,
        _request: Request<pb::MachineAuthMetadataRequest>,
    ) -> Result<Response<pb::MachineAuthMetadataResponse>, Status> {
        Ok(Response::new(pb::MachineAuthMetadataResponse {
            result: Some(pb::machine_auth_metadata_response::Result::Metadata(
                pb::MachineAuthMetadata {
                    issuer: self.policy.issuer.clone(),
                    token_endpoint: self.discovery.token_endpoint.clone(),
                    jwks_uri: self.discovery.jwks_uri.clone(),
                    supported_grant_types: vec!["client_credentials".to_owned()],
                    supported_scopes: SUPPORTED_MACHINE_SCOPES
                        .iter()
                        .map(|scope| (*scope).to_owned())
                        .collect(),
                    supported_token_endpoint_auth_methods: vec![
                        "ucr_service_credential".to_owned(),
                    ],
                },
            )),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_auth_discovery_exposes_only_bounded_public_scopes() {
        assert_eq!(SUPPORTED_MACHINE_SCOPES.len(), 6);
        assert!(SUPPORTED_MACHINE_SCOPES.contains(&"conference:create"));
        assert!(SUPPORTED_MACHINE_SCOPES.contains(&"conference:manage"));
        assert!(SUPPORTED_MACHINE_SCOPES.contains(&"conference:join:issue"));
        assert!(SUPPORTED_MACHINE_SCOPES.contains(&"conference:read"));
        assert!(SUPPORTED_MACHINE_SCOPES.contains(&"attendance:read"));
        assert!(SUPPORTED_MACHINE_SCOPES.contains(&"recording:manage"));
    }

    #[test]
    fn canonical_error_import_remains_used_by_transport_conversion() {
        let error = CanonicalError::new(CanonicalErrorCode::Unauthenticated);
        assert_eq!(error.code, CanonicalErrorCode::Unauthenticated);
    }
}
