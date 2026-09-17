use std::{fmt, sync::Arc};

use tonic::{Request, Response, Status};
use ucr_core::{
    AuthorizationEvaluator, DeviceLifecycleStore, DeviceReverificationVerifier,
    RecoveryAuthorityVerifier, RecoveryDeviceStagingStore, RecoveryExecutionIngress,
    RecoveryPlanIngress, RecoveryPlanStore, ReverifiedDeviceActivationStore, ServiceAuditStore,
    ServiceCredentialStore, ServiceQuotaClock, ServiceQuotaStore,
};
use ucr_model::{
    DeviceId, HistoricalMessageAccess, IdentityId, PrincipalId, RecoveryAuthority, RecoveryPlan,
    RecoveryPlanId, RecoveryRequest, RecoveryTrustModel, TenantScope,
};
use ucr_protocol::{CanonicalError, acknowledgement_for};

use super::{
    GRPC_MAX_DECODING_MESSAGE_SIZE, GRPC_MAX_ENCODING_MESSAGE_SIZE, decode_credentials,
    decode_device_lifecycle_state, decode_opaque, decode_scope, invalid_argument, pb,
    pb_acknowledgement, pb_device_descriptor, pb_device_lifecycle_state, pb_error, pb_opaque,
    pb_scope,
};

/// Thin Phase-40 binding over canonical Recovery Plan administration and proof-gated recovery.
pub struct GrpcRecoveryService<C, A, S, RV, DV> {
    clock: Arc<C>,
    authorization: Arc<A>,
    store: Arc<S>,
    recovery_verifier: Arc<RV>,
    reverification_verifier: Arc<DV>,
}

impl<C, A, S, RV, DV> GrpcRecoveryService<C, A, S, RV, DV> {
    #[must_use]
    pub const fn new(
        clock: Arc<C>,
        authorization: Arc<A>,
        store: Arc<S>,
        recovery_verifier: Arc<RV>,
        reverification_verifier: Arc<DV>,
    ) -> Self {
        Self {
            clock,
            authorization,
            store,
            recovery_verifier,
            reverification_verifier,
        }
    }
}

impl<C, A, S, RV, DV> Clone for GrpcRecoveryService<C, A, S, RV, DV> {
    fn clone(&self) -> Self {
        Self {
            clock: Arc::clone(&self.clock),
            authorization: Arc::clone(&self.authorization),
            store: Arc::clone(&self.store),
            recovery_verifier: Arc::clone(&self.recovery_verifier),
            reverification_verifier: Arc::clone(&self.reverification_verifier),
        }
    }
}

impl<C, A, S, RV, DV> fmt::Debug for GrpcRecoveryService<C, A, S, RV, DV> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GrpcRecoveryService")
            .finish_non_exhaustive()
    }
}

#[must_use]
pub fn recovery_service_server<C, A, S, RV, DV>(
    service: GrpcRecoveryService<C, A, S, RV, DV>,
) -> pb::recovery_service_server::RecoveryServiceServer<GrpcRecoveryService<C, A, S, RV, DV>>
where
    C: ServiceQuotaClock + 'static,
    A: AuthorizationEvaluator + 'static,
    S: RecoveryPlanStore
        + ServiceCredentialStore
        + ServiceQuotaStore
        + ServiceAuditStore
        + RecoveryDeviceStagingStore
        + DeviceLifecycleStore
        + ReverifiedDeviceActivationStore
        + 'static,
    RV: RecoveryAuthorityVerifier + 'static,
    DV: DeviceReverificationVerifier + 'static,
{
    pb::recovery_service_server::RecoveryServiceServer::new(service)
        .max_decoding_message_size(GRPC_MAX_DECODING_MESSAGE_SIZE)
        .max_encoding_message_size(GRPC_MAX_ENCODING_MESSAGE_SIZE)
}

type AdminIngress<'a, C, A, S> = RecoveryPlanIngress<'a, C, A, S>;

#[tonic::async_trait]
impl<C, A, S, RV, DV> pb::recovery_service_server::RecoveryService
    for GrpcRecoveryService<C, A, S, RV, DV>
where
    C: ServiceQuotaClock + 'static,
    A: AuthorizationEvaluator + 'static,
    S: RecoveryPlanStore
        + ServiceCredentialStore
        + ServiceQuotaStore
        + ServiceAuditStore
        + RecoveryDeviceStagingStore
        + DeviceLifecycleStore
        + ReverifiedDeviceActivationStore
        + 'static,
    RV: RecoveryAuthorityVerifier + 'static,
    DV: DeviceReverificationVerifier + 'static,
{
    async fn install_plan(
        &self,
        request: Request<pb::RecoveryInstallPlanRequest>,
    ) -> Result<Response<pb::RecoveryPlanMutationResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let plan = request
            .into_inner()
            .plan
            .ok_or_else(invalid_argument)
            .and_then(decode_plan);
        let result = match (credentials, plan) {
            (Ok((credential_id, secret)), Ok(plan)) => {
                AdminIngress::new(&*self.clock, &*self.authorization, &*self.store)
                    .install_plan(&plan.scope, &credential_id, &secret, &plan)
                    .map(|()| acknowledgement_for(plan.plan_id.as_opaque().clone()))
            }
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(pb_mutation_response(result)))
    }

    async fn rotate_plan(
        &self,
        request: Request<pb::RecoveryRotatePlanRequest>,
    ) -> Result<Response<pb::RecoveryPlanMutationResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let body = request.into_inner();
        let decoded = decode_rotate(body);
        let result = match (credentials, decoded) {
            (Ok((credential_id, secret)), Ok((expected, replacement))) => {
                AdminIngress::new(&*self.clock, &*self.authorization, &*self.store)
                    .rotate_plan(
                        &replacement.scope,
                        &credential_id,
                        &secret,
                        &expected,
                        &replacement,
                    )
                    .map(|()| acknowledgement_for(replacement.plan_id.as_opaque().clone()))
            }
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(pb_mutation_response(result)))
    }

    async fn revoke_plan(
        &self,
        request: Request<pb::RecoveryRevokePlanRequest>,
    ) -> Result<Response<pb::RecoveryPlanMutationResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let decoded = decode_revoke(request.into_inner());
        let result = match (credentials, decoded) {
            (Ok((credential_id, secret)), Ok((scope, identity_id, expected))) => {
                AdminIngress::new(&*self.clock, &*self.authorization, &*self.store)
                    .revoke_plan(
                        &scope,
                        &credential_id,
                        &secret,
                        &scope,
                        &identity_id,
                        &expected,
                    )
                    .map(|()| acknowledgement_for(expected.as_opaque().clone()))
            }
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(pb_mutation_response(result)))
    }

    async fn get_active_plan(
        &self,
        request: Request<pb::RecoveryGetActivePlanRequest>,
    ) -> Result<Response<pb::RecoveryGetActivePlanResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let decoded = decode_plan_lookup(request.into_inner());
        let result = match (credentials, decoded) {
            (Ok((credential_id, secret)), Ok((scope, identity_id))) => AdminIngress::new(
                &*self.clock,
                &*self.authorization,
                &*self.store,
            )
            .active_plan(&scope, &credential_id, &secret, &scope, &identity_id),
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(pb::RecoveryGetActivePlanResponse {
            result: Some(match result {
                Ok(plan) => pb::recovery_get_active_plan_response::Result::Plan(pb_plan(&plan)),
                Err(error) => pb::recovery_get_active_plan_response::Result::Error(pb_error(error)),
            }),
        }))
    }

    async fn stage_recovered_device(
        &self,
        request: Request<pb::RecoveryStageDeviceRequest>,
    ) -> Result<Response<pb::RecoveryDeviceResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let decoded = request
            .into_inner()
            .recovery
            .ok_or_else(invalid_argument)
            .and_then(decode_recovery_request);
        let result =
            match (credentials, decoded) {
                (Ok((credential_id, secret)), Ok(recovery)) => RecoveryExecutionIngress::new(
                    &*self.clock,
                    &*self.authorization,
                    &*self.store,
                    &*self.recovery_verifier,
                    &*self.reverification_verifier,
                )
                .stage_recovered_device(&recovery.scope, &credential_id, &secret, &recovery),
                (Err(error), _) | (_, Err(error)) => Err(error),
            };
        Ok(Response::new(pb_device_response(result)))
    }

    async fn activate_recovered_device(
        &self,
        request: Request<pb::RecoveryActivateDeviceRequest>,
    ) -> Result<Response<pb::RecoveryDeviceResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let decoded = decode_activate(request.into_inner());
        let result = match (credentials, decoded) {
            (Ok((credential_id, secret)), Ok((scope, device_id, identity_id))) => {
                RecoveryExecutionIngress::new(
                    &*self.clock,
                    &*self.authorization,
                    &*self.store,
                    &*self.recovery_verifier,
                    &*self.reverification_verifier,
                )
                .activate_recovered_device(
                    &scope,
                    &credential_id,
                    &secret,
                    &scope,
                    &device_id,
                    &identity_id,
                )
            }
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(pb_device_response(result)))
    }
}

fn pb_mutation_response(
    result: Result<ucr_protocol::AcknowledgementEnvelope, CanonicalError>,
) -> pb::RecoveryPlanMutationResponse {
    pb::RecoveryPlanMutationResponse {
        result: Some(match result {
            Ok(acknowledgement) => pb::recovery_plan_mutation_response::Result::Acknowledgement(
                pb_acknowledgement(acknowledgement),
            ),
            Err(error) => pb::recovery_plan_mutation_response::Result::Error(pb_error(error)),
        }),
    }
}

fn pb_device_response(
    result: Result<ucr_model::DeviceDescriptor, CanonicalError>,
) -> pb::RecoveryDeviceResponse {
    pb::RecoveryDeviceResponse {
        result: Some(match result {
            Ok(device) => {
                pb::recovery_device_response::Result::Device(pb_device_descriptor(&device))
            }
            Err(error) => pb::recovery_device_response::Result::Error(pb_error(error)),
        }),
    }
}

fn decode_rotate(
    value: pb::RecoveryRotatePlanRequest,
) -> Result<(RecoveryPlanId, RecoveryPlan), CanonicalError> {
    Ok((
        RecoveryPlanId::from_opaque(decode_opaque(value.expected_plan_id)?),
        decode_plan(value.replacement.ok_or_else(invalid_argument)?)?,
    ))
}

fn decode_revoke(
    value: pb::RecoveryRevokePlanRequest,
) -> Result<(TenantScope, IdentityId, RecoveryPlanId), CanonicalError> {
    Ok((
        decode_scope(value.scope.ok_or_else(invalid_argument)?)?,
        IdentityId::from_opaque(decode_opaque(value.identity_id)?),
        RecoveryPlanId::from_opaque(decode_opaque(value.expected_plan_id)?),
    ))
}

fn decode_plan_lookup(
    value: pb::RecoveryGetActivePlanRequest,
) -> Result<(TenantScope, IdentityId), CanonicalError> {
    Ok((
        decode_scope(value.scope.ok_or_else(invalid_argument)?)?,
        IdentityId::from_opaque(decode_opaque(value.identity_id)?),
    ))
}

fn decode_activate(
    value: pb::RecoveryActivateDeviceRequest,
) -> Result<(TenantScope, DeviceId, IdentityId), CanonicalError> {
    Ok((
        decode_scope(value.scope.ok_or_else(invalid_argument)?)?,
        DeviceId::from_opaque(decode_opaque(value.device_id)?),
        IdentityId::from_opaque(decode_opaque(value.identity_id)?),
    ))
}

fn decode_plan(value: pb::RecoveryPlan) -> Result<RecoveryPlan, CanonicalError> {
    Ok(RecoveryPlan {
        plan_id: RecoveryPlanId::from_opaque(decode_opaque(value.plan_id)?),
        scope: decode_scope(value.scope.ok_or_else(invalid_argument)?)?,
        identity_id: IdentityId::from_opaque(decode_opaque(value.identity_id)?),
        authorities: value
            .authorities
            .into_iter()
            .map(decode_authority)
            .collect::<Result<Vec<_>, _>>()?,
        historical_message_access: decode_historical_access(value.historical_message_access)?,
        trust_model: decode_trust_model(value.trust_model)?,
        recovered_device_state: decode_device_lifecycle_state(value.recovered_device_state)?,
    })
}

fn decode_recovery_request(value: pb::RecoveryRequest) -> Result<RecoveryRequest, CanonicalError> {
    Ok(RecoveryRequest {
        plan_id: RecoveryPlanId::from_opaque(decode_opaque(value.plan_id)?),
        scope: decode_scope(value.scope.ok_or_else(invalid_argument)?)?,
        identity_id: IdentityId::from_opaque(decode_opaque(value.identity_id)?),
        authority: decode_authority(value.authority.ok_or_else(invalid_argument)?)?,
        target_device_id: DeviceId::from_opaque(decode_opaque(value.target_device_id)?),
    })
}

fn decode_authority(value: pb::RecoveryAuthority) -> Result<RecoveryAuthority, CanonicalError> {
    let method = pb::RecoveryMethod::try_from(value.method).map_err(|_| invalid_argument())?;
    match method {
        pb::RecoveryMethod::RecoveryCode
            if value.device_id.is_none() && value.principal_id.is_none() =>
        {
            Ok(RecoveryAuthority::RecoveryCode)
        }
        pb::RecoveryMethod::RecoveryKey
            if value.device_id.is_none() && value.principal_id.is_none() =>
        {
            Ok(RecoveryAuthority::RecoveryKey)
        }
        pb::RecoveryMethod::TrustedDevice if value.principal_id.is_none() => {
            Ok(RecoveryAuthority::TrustedDevice(DeviceId::from_opaque(
                decode_opaque(value.device_id)?,
            )))
        }
        pb::RecoveryMethod::HardwareBacked if value.principal_id.is_none() => {
            Ok(RecoveryAuthority::HardwareBacked(DeviceId::from_opaque(
                decode_opaque(value.device_id)?,
            )))
        }
        pb::RecoveryMethod::EncryptedBackup
            if value.device_id.is_none() && value.principal_id.is_none() =>
        {
            Ok(RecoveryAuthority::EncryptedBackup)
        }
        pb::RecoveryMethod::OrganizationManaged if value.device_id.is_none() => {
            Ok(RecoveryAuthority::OrganizationManaged(
                PrincipalId::from_opaque(decode_opaque(value.principal_id)?),
            ))
        }
        _ => Err(invalid_argument()),
    }
}

fn decode_historical_access(value: i32) -> Result<HistoricalMessageAccess, CanonicalError> {
    match pb::HistoricalMessageAccess::try_from(value).map_err(|_| invalid_argument())? {
        pb::HistoricalMessageAccess::Unspecified => Err(invalid_argument()),
        pb::HistoricalMessageAccess::None => Ok(HistoricalMessageAccess::None),
        pb::HistoricalMessageAccess::ExplicitEncryptedRecovery => {
            Ok(HistoricalMessageAccess::ExplicitEncryptedRecovery)
        }
    }
}

fn decode_trust_model(value: i32) -> Result<RecoveryTrustModel, CanonicalError> {
    match pb::RecoveryTrustModel::try_from(value).map_err(|_| invalid_argument())? {
        pb::RecoveryTrustModel::Unspecified => Err(invalid_argument()),
        pb::RecoveryTrustModel::UserControlled => Ok(RecoveryTrustModel::UserControlled),
        pb::RecoveryTrustModel::OrganizationManaged => Ok(RecoveryTrustModel::OrganizationManaged),
    }
}

fn pb_plan(value: &RecoveryPlan) -> pb::RecoveryPlan {
    pb::RecoveryPlan {
        plan_id: Some(pb_opaque(value.plan_id.as_opaque())),
        scope: Some(pb_scope(&value.scope)),
        identity_id: Some(pb_opaque(value.identity_id.as_opaque())),
        authorities: value.authorities.iter().map(pb_authority).collect(),
        historical_message_access: match value.historical_message_access {
            HistoricalMessageAccess::None => pb::HistoricalMessageAccess::None,
            HistoricalMessageAccess::ExplicitEncryptedRecovery => {
                pb::HistoricalMessageAccess::ExplicitEncryptedRecovery
            }
        } as i32,
        recovered_device_state: pb_device_lifecycle_state(value.recovered_device_state),
        trust_model: match value.trust_model {
            RecoveryTrustModel::UserControlled => pb::RecoveryTrustModel::UserControlled,
            RecoveryTrustModel::OrganizationManaged => pb::RecoveryTrustModel::OrganizationManaged,
        } as i32,
    }
}

fn pb_authority(value: &RecoveryAuthority) -> pb::RecoveryAuthority {
    let (method, device_id, principal_id) = match value {
        RecoveryAuthority::RecoveryCode => (pb::RecoveryMethod::RecoveryCode, None, None),
        RecoveryAuthority::RecoveryKey => (pb::RecoveryMethod::RecoveryKey, None, None),
        RecoveryAuthority::TrustedDevice(device_id) => (
            pb::RecoveryMethod::TrustedDevice,
            Some(pb_opaque(device_id.as_opaque())),
            None,
        ),
        RecoveryAuthority::HardwareBacked(device_id) => (
            pb::RecoveryMethod::HardwareBacked,
            Some(pb_opaque(device_id.as_opaque())),
            None,
        ),
        RecoveryAuthority::EncryptedBackup => (pb::RecoveryMethod::EncryptedBackup, None, None),
        RecoveryAuthority::OrganizationManaged(principal_id) => (
            pb::RecoveryMethod::OrganizationManaged,
            None,
            Some(pb_opaque(principal_id.as_opaque())),
        ),
    };
    pb::RecoveryAuthority {
        method: method as i32,
        device_id,
        principal_id,
    }
}
