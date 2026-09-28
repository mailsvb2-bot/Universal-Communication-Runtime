use std::sync::Arc;

use tonic::metadata::MetadataMap;
use ucr_core::{
    AuthorizationEvaluator, ServiceAuditStore, ServiceCredentialSecret, ServiceCredentialStore,
    ServicePrincipalRequestGate, ServiceQuotaClock, ServiceQuotaStore,
};
use ucr_crypto::{MAX_MACHINE_TOKEN_BYTES, MachineTokenPolicy, MachineTokenPublicKeySet};
use ucr_machine_auth::MachineBearerRequestGate;
use ucr_model::{AuthorizationRequest, ScopedPrincipal, ServiceCredentialId, TenantScope};
use ucr_protocol::{CanonicalError, CanonicalErrorCode};

use super::{
    SERVICE_CREDENTIAL_ID_METADATA_KEY, SERVICE_CREDENTIAL_SECRET_METADATA_KEY, decode_credentials,
    unauthenticated,
};

pub(crate) const AUTHORIZATION_METADATA_KEY: &str = "authorization";
const MAX_BEARER_AUTHORIZATION_METADATA_BYTES: usize = MAX_MACHINE_TOKEN_BYTES + 32;

pub trait MachineTokenVerificationKeyProvider: std::fmt::Debug + Send + Sync {
    /// Resolves the currently accepted machine-token verification keys.
    ///
    /// # Errors
    /// Returns a canonical fail-closed error when verification material cannot be resolved.
    fn current_verification_keys(&self) -> Result<MachineTokenPublicKeySet, CanonicalError>;
}

#[derive(Clone)]
enum MachineBearerVerificationSource {
    Static(Arc<MachineTokenPublicKeySet>),
    Provider(Arc<dyn MachineTokenVerificationKeyProvider>),
}

impl std::fmt::Debug for MachineBearerVerificationSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Static(keys) => formatter
                .debug_tuple("Static")
                .field(&keys.keys().len())
                .finish(),
            Self::Provider(_) => formatter
                .debug_tuple("Provider")
                .field(&"<dynamic>")
                .finish(),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct MachineBearerConfig {
    verification: MachineBearerVerificationSource,
    pub(crate) policy: MachineTokenPolicy,
}

impl MachineBearerConfig {
    pub(crate) fn static_keys(
        verification_keys: Arc<MachineTokenPublicKeySet>,
        policy: MachineTokenPolicy,
    ) -> Self {
        Self {
            verification: MachineBearerVerificationSource::Static(verification_keys),
            policy,
        }
    }

    pub(crate) fn provider(
        provider: Arc<dyn MachineTokenVerificationKeyProvider>,
        policy: MachineTokenPolicy,
    ) -> Self {
        Self {
            verification: MachineBearerVerificationSource::Provider(provider),
            policy,
        }
    }

    fn current_verification_keys(&self) -> Result<MachineTokenPublicKeySet, CanonicalError> {
        match &self.verification {
            MachineBearerVerificationSource::Static(keys) => Ok((**keys).clone()),
            MachineBearerVerificationSource::Provider(provider) => {
                provider.current_verification_keys()
            }
        }
    }
}

pub(crate) enum MachineApiAuthentication {
    ServiceCredential {
        credential_id: ServiceCredentialId,
        secret: ServiceCredentialSecret,
    },
    MachineBearer(String),
}

pub(crate) fn decode_machine_api_authentication(
    metadata: &MetadataMap,
) -> Result<MachineApiAuthentication, CanonicalError> {
    let has_credential_id = metadata
        .get_bin(SERVICE_CREDENTIAL_ID_METADATA_KEY)
        .is_some();
    let has_credential_secret = metadata
        .get_bin(SERVICE_CREDENTIAL_SECRET_METADATA_KEY)
        .is_some();

    let mut authorization_values = metadata.get_all(AUTHORIZATION_METADATA_KEY).iter();
    let authorization = authorization_values.next();
    if authorization_values.next().is_some() {
        return Err(unauthenticated());
    }

    if let Some(value) = authorization {
        if has_credential_id || has_credential_secret {
            return Err(unauthenticated());
        }
        let value = value.to_str().map_err(|_| unauthenticated())?;
        if value.len() > MAX_BEARER_AUTHORIZATION_METADATA_BYTES {
            return Err(unauthenticated());
        }
        let mut parts = value.split_ascii_whitespace();
        let scheme = parts.next().ok_or_else(unauthenticated)?;
        let token = parts.next().ok_or_else(unauthenticated)?;
        if !scheme.eq_ignore_ascii_case("bearer")
            || token.is_empty()
            || token.len() > MAX_MACHINE_TOKEN_BYTES
            || parts.next().is_some()
        {
            return Err(unauthenticated());
        }
        return Ok(MachineApiAuthentication::MachineBearer(token.to_owned()));
    }

    if has_credential_id != has_credential_secret {
        return Err(unauthenticated());
    }
    let (credential_id, secret) = decode_credentials(metadata)?;
    Ok(MachineApiAuthentication::ServiceCredential {
        credential_id,
        secret,
    })
}

pub(crate) fn admit_machine_api<C, A, S>(
    clock: &C,
    authorization: &A,
    store: &S,
    machine_bearer: Option<&MachineBearerConfig>,
    scope: &TenantScope,
    authentication: MachineApiAuthentication,
    permission: &str,
) -> Result<ScopedPrincipal, CanonicalError>
where
    C: ServiceQuotaClock,
    A: AuthorizationEvaluator,
    S: ServiceCredentialStore + ServiceQuotaStore + ServiceAuditStore,
{
    let admission = match authentication {
        MachineApiAuthentication::ServiceCredential {
            credential_id,
            secret,
        } => {
            let gate = ServicePrincipalRequestGate::new(clock, authorization, store);
            gate.authenticate_request(scope, &credential_id, &secret, permission, scope)?
        }
        MachineApiAuthentication::MachineBearer(encoded) => {
            let config = machine_bearer.ok_or_else(unauthenticated)?;
            let verification_keys = config.current_verification_keys()?;
            let gate = MachineBearerRequestGate::new(
                clock,
                authorization,
                store,
                &verification_keys,
                &config.policy,
            );
            gate.authenticate_permission_request(&encoded, permission, scope)?
        }
    };
    let actor = admission.subject().clone();
    admission.authorize(&AuthorizationRequest {
        subject: actor.clone(),
        permission: permission.to_owned(),
        resource_scope: scope.clone(),
    })?;
    if actor.principal.kind != ucr_model::PrincipalKind::ServiceAccount {
        return Err(CanonicalError::new(CanonicalErrorCode::PermissionDenied));
    }
    Ok(actor)
}
