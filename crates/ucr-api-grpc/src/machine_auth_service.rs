use core::fmt;
use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use tonic::{Request, Response, Status};
use ucr_core::{
    AuthorizationEvaluator, ServiceAuditStore, ServiceCredentialStore, ServiceQuotaClock,
    ServiceQuotaStore,
};
use ucr_crypto::{MachineTokenPolicy, MachineTokenPublicKeySet, MachineTokenSigningKey};
use ucr_machine_auth::{MachineAuthExchangeRequest, MachineAuthRuntime, SUPPORTED_MACHINE_SCOPES};
use ucr_protocol::CanonicalError;

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
    verification_keys: Arc<MachineTokenPublicKeySet>,
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
        verification_keys: Arc<MachineTokenPublicKeySet>,
        policy: MachineTokenPolicy,
        discovery: MachineAuthDiscovery,
    ) -> Self {
        Self {
            clock,
            authorization,
            store,
            signing_key,
            verification_keys,
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
            verification_keys: Arc::clone(&self.verification_keys),
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
            .field("verification_keys", &self.verification_keys)
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
    fn public_jwks(&self) -> pb::MachineAuthJwks {
        pb::MachineAuthJwks {
            keys: self
                .verification_keys
                .keys()
                .iter()
                .map(|public_key| pb::MachineAuthJwk {
                    kty: "OKP".to_owned(),
                    crv: "Ed25519".to_owned(),
                    r#use: "sig".to_owned(),
                    alg: "EdDSA".to_owned(),
                    kid: public_key.key_id.as_opaque().as_str().to_owned(),
                    x: URL_SAFE_NO_PAD.encode(public_key.verifying_key.0),
                })
                .collect(),
        }
    }

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
                    supported_token_endpoint_auth_methods: vec!["client_secret_basic".to_owned()],
                },
            )),
        }))
    }

    async fn get_jwks(
        &self,
        _request: Request<pb::MachineAuthJwksRequest>,
    ) -> Result<Response<pb::MachineAuthJwksResponse>, Status> {
        Ok(Response::new(pb::MachineAuthJwksResponse {
            result: Some(pb::machine_auth_jwks_response::Result::Jwks(
                self.public_jwks(),
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
    fn machine_auth_jwks_projects_only_public_ed25519_material() {
        let signing_key = Arc::new(MachineTokenSigningKey::from_seed(
            ucr_model::KeyId::from_opaque(
                ucr_model::OpaqueId::new("machine-jwks-key").expect("key id"),
            ),
            [7_u8; 32],
        ));
        let previous_key = MachineTokenSigningKey::from_seed(
            ucr_model::KeyId::from_opaque(
                ucr_model::OpaqueId::new("machine-jwks-key-previous").expect("previous key id"),
            ),
            [8_u8; 32],
        );
        let verification_keys = Arc::new(
            MachineTokenPublicKeySet::new(vec![
                signing_key.public_key(),
                previous_key.public_key(),
            ])
            .expect("verification key set"),
        );
        let service = GrpcMachineAuthService::new(
            Arc::new(ucr_core::SystemServiceQuotaClock),
            Arc::new(ucr_storage_memory::MemoryLocalStore::default()),
            Arc::new(ucr_storage_memory::MemoryLocalStore::default()),
            Arc::clone(&signing_key),
            verification_keys,
            MachineTokenPolicy {
                issuer: "https://auth.example.test".to_owned(),
                audience: "ucr-api".to_owned(),
                max_ttl_seconds: 900,
            },
            MachineAuthDiscovery {
                token_endpoint: "https://auth.example.test/oauth2/token".to_owned(),
                jwks_uri: "https://auth.example.test/oauth2/jwks".to_owned(),
            },
        );

        let jwks = service.public_jwks();
        assert_eq!(jwks.keys.len(), 2);
        let active = jwks
            .keys
            .iter()
            .find(|key| key.kid == "machine-jwks-key")
            .expect("active key");
        assert_eq!(active.kty, "OKP");
        assert_eq!(active.crv, "Ed25519");
        assert_eq!(active.r#use, "sig");
        assert_eq!(active.alg, "EdDSA");
        assert_eq!(
            active.x,
            URL_SAFE_NO_PAD.encode(signing_key.public_key().verifying_key.0)
        );
        assert!(
            jwks.keys
                .iter()
                .any(|key| key.kid == "machine-jwks-key-previous")
        );
    }
}
