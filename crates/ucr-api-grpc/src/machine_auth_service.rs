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
use ucr_model::KeyId;
use ucr_protocol::CanonicalError;
use ucr_secrets::{ActiveSecretSet, SecretHandle, SecretProvider, SecretPurpose, SecretVersion};

use crate::{
    GRPC_MAX_DECODING_MESSAGE_SIZE, GRPC_MAX_ENCODING_MESSAGE_SIZE, decode_credentials,
    decode_opaque, decode_scope, invalid_argument, pb, pb_error,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineAuthDiscovery {
    pub token_endpoint: String,
    pub jwks_uri: String,
}

#[derive(Clone)]
enum MachineAuthSigningSource {
    Static {
        signing_key: Arc<MachineTokenSigningKey>,
        verification_keys: Arc<MachineTokenPublicKeySet>,
    },
    Provider {
        provider: Arc<dyn SecretProvider>,
        handle: SecretHandle,
    },
}

impl fmt::Debug for MachineAuthSigningSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Static { .. } => formatter
                .debug_struct("MachineAuthSigningSource")
                .field("mode", &"static")
                .field("material", &"<secret>")
                .finish_non_exhaustive(),
            Self::Provider { handle, .. } => formatter
                .debug_struct("MachineAuthSigningSource")
                .field("mode", &"provider")
                .field("handle", handle)
                .field("material", &"<secret>")
                .finish_non_exhaustive(),
        }
    }
}

fn machine_token_key_from_version(
    version: &SecretVersion,
) -> Result<MachineTokenSigningKey, CanonicalError> {
    let seed: [u8; 32] = version.material.as_bytes().try_into().map_err(|_| {
        CanonicalError::new(ucr_protocol::CanonicalErrorCode::TemporarilyUnavailable)
    })?;
    Ok(MachineTokenSigningKey::from_seed(
        KeyId::from_opaque(version.version_id.clone()),
        seed,
    ))
}

fn provider_key_material(
    provider: &dyn SecretProvider,
    handle: &SecretHandle,
) -> Result<(MachineTokenSigningKey, MachineTokenPublicKeySet), CanonicalError> {
    if handle.purpose != SecretPurpose::MachineTokenSigning {
        return Err(CanonicalError::new(
            ucr_protocol::CanonicalErrorCode::TemporarilyUnavailable,
        ));
    }
    let active = provider.active_secret_set(handle).map_err(|_| {
        CanonicalError::new(ucr_protocol::CanonicalErrorCode::TemporarilyUnavailable)
    })?;
    machine_token_material_from_active(&active)
}

fn machine_token_material_from_active(
    active: &ActiveSecretSet,
) -> Result<(MachineTokenSigningKey, MachineTokenPublicKeySet), CanonicalError> {
    let current = machine_token_key_from_version(&active.current)?;
    let mut verification =
        MachineTokenPublicKeySet::new(vec![current.public_key()]).map_err(|_| {
            CanonicalError::new(ucr_protocol::CanonicalErrorCode::TemporarilyUnavailable)
        })?;
    if let Some(previous) = &active.previous {
        let previous = machine_token_key_from_version(previous)?;
        verification.insert(previous.public_key()).map_err(|_| {
            CanonicalError::new(ucr_protocol::CanonicalErrorCode::TemporarilyUnavailable)
        })?;
    }
    Ok((current, verification))
}

pub struct GrpcMachineAuthService<C, A, S> {
    clock: Arc<C>,
    authorization: Arc<A>,
    store: Arc<S>,
    signing_source: MachineAuthSigningSource,
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
            signing_source: MachineAuthSigningSource::Static {
                signing_key,
                verification_keys,
            },
            policy,
            discovery,
        }
    }

    /// Builds machine-auth over the shared provider-backed signing-key boundary.
    ///
    /// # Errors
    /// Rejects a wrong-purpose handle, unavailable provider, malformed key material, or duplicate
    /// overlap key identifiers.
    pub fn with_secret_provider(
        clock: Arc<C>,
        authorization: Arc<A>,
        store: Arc<S>,
        provider: Arc<dyn SecretProvider>,
        handle: SecretHandle,
        policy: MachineTokenPolicy,
        discovery: MachineAuthDiscovery,
    ) -> Result<Self, String> {
        if handle.purpose != SecretPurpose::MachineTokenSigning {
            return Err(
                "machine auth signing handle must use MachineTokenSigning purpose".to_owned(),
            );
        }
        provider_key_material(provider.as_ref(), &handle)
            .map_err(|_| "machine auth signing provider is unavailable or malformed".to_owned())?;
        Ok(Self {
            clock,
            authorization,
            store,
            signing_source: MachineAuthSigningSource::Provider { provider, handle },
            policy,
            discovery,
        })
    }
}

impl<C, A, S> Clone for GrpcMachineAuthService<C, A, S> {
    fn clone(&self) -> Self {
        Self {
            clock: Arc::clone(&self.clock),
            authorization: Arc::clone(&self.authorization),
            store: Arc::clone(&self.store),
            signing_source: self.signing_source.clone(),
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
            .field("signing_source", &self.signing_source)
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

fn jwks_from_verification_keys(
    verification_keys: &MachineTokenPublicKeySet,
) -> pb::MachineAuthJwks {
    pb::MachineAuthJwks {
        keys: verification_keys
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

impl<C, A, S> GrpcMachineAuthService<C, A, S>
where
    C: ServiceQuotaClock,
    A: AuthorizationEvaluator,
    S: ServiceCredentialStore + ServiceQuotaStore + ServiceAuditStore,
{
    fn public_jwks(&self) -> Result<pb::MachineAuthJwks, CanonicalError> {
        match &self.signing_source {
            MachineAuthSigningSource::Static {
                verification_keys, ..
            } => Ok(jwks_from_verification_keys(verification_keys)),
            MachineAuthSigningSource::Provider { provider, handle } => {
                let (_, verification_keys) = provider_key_material(provider.as_ref(), handle)?;
                Ok(jwks_from_verification_keys(&verification_keys))
            }
        }
    }

    fn exchange(
        &self,
        credential_id: &ucr_model::ServiceCredentialId,
        secret: &ucr_core::ServiceCredentialSecret,
        request: pb::MachineTokenRequest,
    ) -> Result<pb::MachineAccessToken, CanonicalError> {
        match &self.signing_source {
            MachineAuthSigningSource::Static { signing_key, .. } => {
                self.exchange_with_signing_key(credential_id, secret, signing_key, request)
            }
            MachineAuthSigningSource::Provider { provider, handle } => {
                let (signing_key, _) = provider_key_material(provider.as_ref(), handle)?;
                self.exchange_with_signing_key(credential_id, secret, &signing_key, request)
            }
        }
    }

    fn exchange_with_signing_key(
        &self,
        credential_id: &ucr_model::ServiceCredentialId,
        secret: &ucr_core::ServiceCredentialSecret,
        signing_key: &MachineTokenSigningKey,
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
            signing_key,
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
        let result = match self.public_jwks() {
            Ok(jwks) => pb::machine_auth_jwks_response::Result::Jwks(jwks),
            Err(error) => pb::machine_auth_jwks_response::Result::Error(pb_error(error)),
        };
        Ok(Response::new(pb::MachineAuthJwksResponse {
            result: Some(result),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ucr_secrets::{InMemorySecretProvider, SecretMaterial, SecretVersion};

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

        let jwks = service.public_jwks().expect("jwks");
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
    #[test]
    fn provider_rotation_updates_machine_auth_jwks_with_bounded_overlap() {
        let provider = Arc::new(InMemorySecretProvider::default());
        let handle = SecretHandle {
            secret_id: ucr_model::OpaqueId::new("machine-token-signing").expect("secret id"),
            purpose: SecretPurpose::MachineTokenSigning,
        };
        provider
            .provision(
                handle.clone(),
                SecretVersion {
                    version_id: ucr_model::OpaqueId::new("machine-key-v1").expect("version"),
                    material: SecretMaterial::new(vec![7_u8; 32]).expect("material"),
                },
            )
            .expect("provision");

        let service = GrpcMachineAuthService::with_secret_provider(
            Arc::new(ucr_core::SystemServiceQuotaClock),
            Arc::new(ucr_storage_memory::MemoryLocalStore::default()),
            Arc::new(ucr_storage_memory::MemoryLocalStore::default()),
            provider.clone(),
            handle.clone(),
            MachineTokenPolicy {
                issuer: "https://auth.example.test".to_owned(),
                audience: "ucr-api".to_owned(),
                max_ttl_seconds: 900,
            },
            MachineAuthDiscovery {
                token_endpoint: "https://auth.example.test/oauth2/token".to_owned(),
                jwks_uri: "https://auth.example.test/oauth2/jwks".to_owned(),
            },
        )
        .expect("provider-backed service");

        let before = service.public_jwks().expect("initial jwks");
        assert_eq!(before.keys.len(), 1);
        assert_eq!(before.keys[0].kid, "machine-key-v1");

        provider
            .rotate(
                &handle,
                SecretVersion {
                    version_id: ucr_model::OpaqueId::new("machine-key-v2").expect("version"),
                    material: SecretMaterial::new(vec![8_u8; 32]).expect("material"),
                },
            )
            .expect("rotate");

        let after = service.public_jwks().expect("rotated jwks");
        assert_eq!(after.keys.len(), 2);
        assert!(after.keys.iter().any(|key| key.kid == "machine-key-v2"));
        assert!(after.keys.iter().any(|key| key.kid == "machine-key-v1"));
        let rendered = format!("{:?}", service.signing_source);
        assert!(rendered.contains("<secret>"));
        assert!(!rendered.contains("[7"));
        assert!(!rendered.contains("[8"));
    }
    #[test]
    fn provider_rotation_moves_machine_signing_to_current_and_keeps_previous_verify_only() {
        let provider = Arc::new(InMemorySecretProvider::default());
        let handle = SecretHandle {
            secret_id: ucr_model::OpaqueId::new("machine-token-signing-material")
                .expect("secret id"),
            purpose: SecretPurpose::MachineTokenSigning,
        };
        provider
            .provision(
                handle.clone(),
                SecretVersion {
                    version_id: ucr_model::OpaqueId::new("machine-sign-v1").expect("version"),
                    material: SecretMaterial::new(vec![17_u8; 32]).expect("material"),
                },
            )
            .expect("provision");

        let (before_signing, before_verify) =
            provider_key_material(provider.as_ref(), &handle).expect("initial material");
        assert_eq!(
            before_signing.key_id().as_opaque().as_str(),
            "machine-sign-v1"
        );
        assert_eq!(before_verify.keys().len(), 1);

        provider
            .rotate(
                &handle,
                SecretVersion {
                    version_id: ucr_model::OpaqueId::new("machine-sign-v2").expect("version"),
                    material: SecretMaterial::new(vec![18_u8; 32]).expect("material"),
                },
            )
            .expect("rotate");

        let (after_signing, after_verify) =
            provider_key_material(provider.as_ref(), &handle).expect("rotated material");
        assert_eq!(
            after_signing.key_id().as_opaque().as_str(),
            "machine-sign-v2"
        );
        assert_eq!(after_verify.keys().len(), 2);
        assert!(
            after_verify
                .keys()
                .iter()
                .any(|key| key.key_id.as_opaque().as_str() == "machine-sign-v1")
        );
        assert!(
            after_verify
                .keys()
                .iter()
                .any(|key| key.key_id.as_opaque().as_str() == "machine-sign-v2")
        );
    }
}
