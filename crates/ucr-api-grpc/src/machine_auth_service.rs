use core::fmt;
use std::{collections::BTreeSet, sync::Arc};

use tonic::{Request, Response, Status};
use ucr_core::{
    AuthorizationEvaluator, ServiceAuditStore, ServiceCredentialStore, ServicePrincipalRequestGate,
    ServiceQuotaClock, ServiceQuotaStore, generate_opaque_id,
};
use ucr_crypto::{
    AccessTokenIssueRequest, MachineTokenError, MachineTokenPolicy, MachineTokenSigningKey,
    issue_machine_access_token,
};
use ucr_model::{AuthorizationRequest, OpaqueId, PrincipalKind, ScopedPrincipal};
use ucr_protocol::{
    CONFERENCE_ATTENDANCE_READ_PERMISSION, CONFERENCE_CREATE_PERMISSION,
    CONFERENCE_JOIN_ISSUE_PERMISSION, CONFERENCE_MANAGE_PERMISSION, CONFERENCE_READ_PERMISSION,
    CONFERENCE_RECORDING_MANAGE_PERMISSION, CanonicalError, CanonicalErrorCode,
};

use crate::{
    GRPC_MAX_DECODING_MESSAGE_SIZE, GRPC_MAX_ENCODING_MESSAGE_SIZE, decode_credentials,
    decode_opaque, decode_scope, invalid_argument, pb, pb_error,
};

const MACHINE_SCOPE_CONFERENCE_CREATE: &str = "conference:create";
const MACHINE_SCOPE_CONFERENCE_MANAGE: &str = "conference:manage";
const MACHINE_SCOPE_CONFERENCE_JOIN_ISSUE: &str = "conference:join:issue";
const MACHINE_SCOPE_CONFERENCE_READ: &str = "conference:read";
const MACHINE_SCOPE_ATTENDANCE_READ: &str = "attendance:read";
const MACHINE_SCOPE_RECORDING_MANAGE: &str = "recording:manage";

const SUPPORTED_MACHINE_SCOPES: [&str; 6] = [
    MACHINE_SCOPE_CONFERENCE_CREATE,
    MACHINE_SCOPE_CONFERENCE_MANAGE,
    MACHINE_SCOPE_CONFERENCE_JOIN_ISSUE,
    MACHINE_SCOPE_CONFERENCE_READ,
    MACHINE_SCOPE_ATTENDANCE_READ,
    MACHINE_SCOPE_RECORDING_MANAGE,
];

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
        if request.audience != self.policy.audience {
            return Err(CanonicalError::new(CanonicalErrorCode::InvalidArgument));
        }

        let permissions = requested_scope_permissions(&request.requested_scopes)?;
        let primary_permission = permissions.first().copied().ok_or_else(invalid_argument)?;

        let gate =
            ServicePrincipalRequestGate::new(&*self.clock, &*self.authorization, &*self.store);
        let admission =
            gate.authenticate_request(&scope, credential_id, secret, primary_permission, &scope)?;
        let subject = admission.subject().clone();
        admission.authorize(&AuthorizationRequest {
            subject: subject.clone(),
            permission: primary_permission.to_owned(),
            resource_scope: scope.clone(),
        })?;

        require_client_id(&subject, &client_id)?;
        for permission in permissions.iter().skip(1) {
            admission.authorize_additional_permission(permission)?;
        }

        let now_unix_s = now_unix_s(&*self.clock)?;
        let token_id =
            generate_opaque_id().map_err(|_| CanonicalError::new(CanonicalErrorCode::Internal))?;
        let requested_ttl_seconds =
            (request.requested_ttl_seconds != 0).then_some(request.requested_ttl_seconds);
        let token = issue_machine_access_token(
            &self.signing_key,
            &self.policy,
            AccessTokenIssueRequest {
                subject: &subject,
                token_id: &token_id,
                requested_scopes: &request.requested_scopes,
                allowed_scopes: &request.requested_scopes,
                issued_at_unix_s: now_unix_s,
                requested_ttl_seconds,
            },
        )
        .map_err(map_machine_token_error)?;

        let expires_in_seconds = u32::try_from(token.expires_at_unix_s.saturating_sub(now_unix_s))
            .map_err(|_| CanonicalError::new(CanonicalErrorCode::Internal))?;
        Ok(pb::MachineAccessToken {
            access_token: token.as_str().as_bytes().to_vec(),
            token_type: "Bearer".to_owned(),
            expires_in_seconds,
            granted_scopes: token.granted_scopes,
            issuer: self.policy.issuer.clone(),
            audience: self.policy.audience.clone(),
            key_id: token.key_id.as_opaque().as_str().to_owned(),
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

fn requested_scope_permissions(scopes: &[String]) -> Result<Vec<&'static str>, CanonicalError> {
    if scopes.is_empty() {
        return Err(invalid_argument());
    }
    let mut seen = BTreeSet::new();
    let mut permissions = Vec::with_capacity(scopes.len());
    for scope in scopes {
        if !seen.insert(scope.as_str()) {
            return Err(invalid_argument());
        }
        permissions.push(
            canonical_permission_for_scope(scope)
                .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::PermissionDenied))?,
        );
    }
    Ok(permissions)
}

const fn canonical_permission_for_scope(scope: &str) -> Option<&'static str> {
    match scope.as_bytes() {
        b"conference:create" => Some(CONFERENCE_CREATE_PERMISSION),
        b"conference:manage" => Some(CONFERENCE_MANAGE_PERMISSION),
        b"conference:join:issue" => Some(CONFERENCE_JOIN_ISSUE_PERMISSION),
        b"conference:read" => Some(CONFERENCE_READ_PERMISSION),
        b"attendance:read" => Some(CONFERENCE_ATTENDANCE_READ_PERMISSION),
        b"recording:manage" => Some(CONFERENCE_RECORDING_MANAGE_PERMISSION),
        _ => None,
    }
}

fn require_client_id(
    subject: &ScopedPrincipal,
    client_id: &OpaqueId,
) -> Result<(), CanonicalError> {
    if subject.principal.kind == PrincipalKind::ServiceAccount
        && subject.principal.principal_id.as_opaque() == client_id
    {
        Ok(())
    } else {
        Err(CanonicalError::new(CanonicalErrorCode::PermissionDenied))
    }
}

fn now_unix_s<C: ServiceQuotaClock>(clock: &C) -> Result<u64, CanonicalError> {
    let now_unix_ms = clock
        .now_unix_ms()
        .map_err(|_| CanonicalError::new(CanonicalErrorCode::TemporarilyUnavailable))?;
    let now_unix_ms = u64::try_from(now_unix_ms)
        .map_err(|_| CanonicalError::new(CanonicalErrorCode::TemporarilyUnavailable))?;
    Ok(now_unix_ms / 1_000)
}

const fn map_machine_token_error(error: MachineTokenError) -> CanonicalError {
    let code = match error {
        MachineTokenError::InvalidTtl | MachineTokenError::InvalidScope => {
            CanonicalErrorCode::InvalidArgument
        }
        MachineTokenError::ScopeNotAllowed | MachineTokenError::NotServiceAccount => {
            CanonicalErrorCode::PermissionDenied
        }
        MachineTokenError::TokenTooLarge => CanonicalErrorCode::ResourceExhausted,
        MachineTokenError::InvalidPolicy
        | MachineTokenError::RandomUnavailable
        | MachineTokenError::Serialization
        | MachineTokenError::MalformedToken
        | MachineTokenError::UnknownSigningKey
        | MachineTokenError::InvalidSignature
        | MachineTokenError::WrongIssuer
        | MachineTokenError::WrongAudience
        | MachineTokenError::NotYetValid
        | MachineTokenError::Expired
        | MachineTokenError::InvalidLifetime => CanonicalErrorCode::Internal,
    };
    CanonicalError::new(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn universal_machine_scopes_map_only_to_existing_canonical_permissions() {
        assert_eq!(
            canonical_permission_for_scope(MACHINE_SCOPE_CONFERENCE_CREATE),
            Some(CONFERENCE_CREATE_PERMISSION)
        );
        assert_eq!(
            canonical_permission_for_scope(MACHINE_SCOPE_CONFERENCE_MANAGE),
            Some(CONFERENCE_MANAGE_PERMISSION)
        );
        assert_eq!(
            canonical_permission_for_scope(MACHINE_SCOPE_CONFERENCE_JOIN_ISSUE),
            Some(CONFERENCE_JOIN_ISSUE_PERMISSION)
        );
        assert_eq!(
            canonical_permission_for_scope(MACHINE_SCOPE_CONFERENCE_READ),
            Some(CONFERENCE_READ_PERMISSION)
        );
        assert_eq!(
            canonical_permission_for_scope(MACHINE_SCOPE_ATTENDANCE_READ),
            Some(CONFERENCE_ATTENDANCE_READ_PERMISSION)
        );
        assert_eq!(
            canonical_permission_for_scope(MACHINE_SCOPE_RECORDING_MANAGE),
            Some(CONFERENCE_RECORDING_MANAGE_PERMISSION)
        );
        assert_eq!(canonical_permission_for_scope("admin:all"), None);
    }

    #[test]
    fn duplicate_and_unknown_scopes_fail_closed() {
        assert!(requested_scope_permissions(&[]).is_err());
        assert!(
            requested_scope_permissions(&[
                MACHINE_SCOPE_CONFERENCE_READ.to_owned(),
                MACHINE_SCOPE_CONFERENCE_READ.to_owned(),
            ])
            .is_err()
        );
        assert!(requested_scope_permissions(&["admin:all".to_owned()]).is_err());
    }
}
