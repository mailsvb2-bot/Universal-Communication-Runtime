use std::collections::BTreeSet;

use ucr_model::{
    DeviceLifecycleState, HistoricalMessageAccess, RecoveryAuthority, RecoveryMethod, RecoveryPlan,
    RecoveryRequest, RecoveryTrustModel,
};

pub const MAX_RECOVERY_AUTHORITIES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryError {
    NoAuthorities,
    DuplicateAuthority,
    TooManyAuthorities,
    MethodNotAllowed,
    PlanMismatch,
    ScopeMismatch,
    IdentityMismatch,
    UnsafeRecoveredDeviceState,
    HistoricalAccessNotExplicit,
    TrustModelAuthorityMismatch,
    EncodingTooLarge,
}

/// Validates a recovery plan before it can authorize any workflow.
///
/// # Errors
/// Recovery is fail-closed: an empty/ambiguous plan or a plan that would make
/// a recovered device Active without re-verification is rejected.
pub fn validate_recovery_plan(plan: &RecoveryPlan) -> Result<(), RecoveryError> {
    if plan.authorities.is_empty() {
        return Err(RecoveryError::NoAuthorities);
    }
    if plan.authorities.len() > MAX_RECOVERY_AUTHORITIES {
        return Err(RecoveryError::TooManyAuthorities);
    }
    let mut seen = BTreeSet::new();
    for authority in &plan.authorities {
        if !seen.insert(authority.clone()) {
            return Err(RecoveryError::DuplicateAuthority);
        }
    }
    if plan.recovered_device_state != DeviceLifecycleState::ReverificationRequired {
        return Err(RecoveryError::UnsafeRecoveredDeviceState);
    }
    if plan.historical_message_access == HistoricalMessageAccess::ExplicitEncryptedRecovery
        && !plan.authorities.iter().any(|authority| {
            matches!(
                authority.method(),
                RecoveryMethod::RecoveryKey
                    | RecoveryMethod::TrustedDevice
                    | RecoveryMethod::HardwareBacked
                    | RecoveryMethod::EncryptedBackup
                    | RecoveryMethod::OrganizationManaged
            )
        })
    {
        return Err(RecoveryError::HistoricalAccessNotExplicit);
    }
    let organization_managed = plan
        .authorities
        .iter()
        .any(|authority| matches!(authority, RecoveryAuthority::OrganizationManaged(_)));
    match (organization_managed, plan.trust_model) {
        (true, RecoveryTrustModel::OrganizationManaged)
        | (false, RecoveryTrustModel::UserControlled) => {}
        _ => return Err(RecoveryError::TrustModelAuthorityMismatch),
    }
    Ok(())
}

/// Returns the single canonical representation of a recovery plan.
///
/// Authorities are a semantic set and are stored in deterministic order.
///
/// # Errors
/// Returns fail-closed plan validation errors.
pub fn canonical_recovery_plan(plan: &RecoveryPlan) -> Result<RecoveryPlan, RecoveryError> {
    validate_recovery_plan(plan)?;
    let mut canonical = plan.clone();
    canonical.authorities.sort();
    Ok(canonical)
}

/// Checks that a request is covered by one explicit recovery plan.
///
/// This validates policy shape only. Proof of the selected recovery method is a
/// separate cryptographic/provider responsibility and must not be inferred from
/// this successful result.
///
/// # Errors
/// Fails on plan/scope/identity mismatch or a method not enabled by the plan.
pub fn validate_recovery_request(
    plan: &RecoveryPlan,
    request: &RecoveryRequest,
) -> Result<(), RecoveryError> {
    validate_recovery_plan(plan)?;
    if request.plan_id != plan.plan_id {
        return Err(RecoveryError::PlanMismatch);
    }
    if request.scope != plan.scope {
        return Err(RecoveryError::ScopeMismatch);
    }
    if request.identity_id != plan.identity_id {
        return Err(RecoveryError::IdentityMismatch);
    }
    if !plan.authorities.contains(&request.authority) {
        return Err(RecoveryError::MethodNotAllowed);
    }
    Ok(())
}

/// Canonically encodes non-secret recovery-plan metadata for cryptographic AAD.
///
/// The encoding is deterministic and order-independent for allowed methods.
/// It is not a general serialization format and must only be used as the
/// domain-separated binding input for a recovery package.
///
/// # Errors
/// Returns the same fail-closed validation errors as [`validate_recovery_plan`].
pub fn recovery_plan_aad(plan: &RecoveryPlan) -> Result<Vec<u8>, RecoveryError> {
    let plan = canonical_recovery_plan(plan)?;
    let mut output = Vec::new();
    output.extend_from_slice(b"UCR-RECOVERY-PLAN-AAD-V1\0");
    push_field(&mut output, plan.plan_id.as_opaque().as_str().as_bytes())?;
    push_field(
        &mut output,
        plan.scope.tenant_id.as_opaque().as_str().as_bytes(),
    )?;
    match &plan.scope.namespace_id {
        Some(namespace) => {
            output.push(1);
            push_field(&mut output, namespace.as_opaque().as_str().as_bytes())?;
        }
        None => output.push(0),
    }
    push_field(
        &mut output,
        plan.identity_id.as_opaque().as_str().as_bytes(),
    )?;
    let mut authorities = plan
        .authorities
        .iter()
        .map(encode_authority)
        .collect::<Result<Vec<_>, _>>()?;
    authorities.sort();
    let authority_count =
        u32::try_from(authorities.len()).map_err(|_| RecoveryError::EncodingTooLarge)?;
    output.extend_from_slice(&authority_count.to_be_bytes());
    for authority in authorities {
        push_field(&mut output, &authority)?;
    }
    output.push(match plan.historical_message_access {
        HistoricalMessageAccess::None => 1,
        HistoricalMessageAccess::ExplicitEncryptedRecovery => 2,
    });
    output.push(match plan.trust_model {
        RecoveryTrustModel::UserControlled => 1,
        RecoveryTrustModel::OrganizationManaged => 2,
    });
    output.push(3); // REVERIFICATION_REQUIRED is the only safe Phase-8 target state.
    Ok(output)
}

fn encode_authority(authority: &RecoveryAuthority) -> Result<Vec<u8>, RecoveryError> {
    let mut output = vec![authority.method() as u8];
    match authority {
        RecoveryAuthority::TrustedDevice(device) | RecoveryAuthority::HardwareBacked(device) => {
            push_field(&mut output, device.as_opaque().as_str().as_bytes())?;
        }
        RecoveryAuthority::OrganizationManaged(principal) => {
            push_field(&mut output, principal.as_opaque().as_str().as_bytes())?;
        }
        RecoveryAuthority::RecoveryCode
        | RecoveryAuthority::RecoveryKey
        | RecoveryAuthority::EncryptedBackup => {}
    }
    Ok(output)
}

fn push_field(output: &mut Vec<u8>, value: &[u8]) -> Result<(), RecoveryError> {
    let len = u32::try_from(value.len()).map_err(|_| RecoveryError::EncodingTooLarge)?;
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use ucr_model::{
        DeviceId, DeviceLifecycleState, HistoricalMessageAccess, IdentityId, NamespaceId, OpaqueId,
        RecoveryAuthority, RecoveryPlan, RecoveryPlanId, RecoveryRequest, RecoveryTrustModel,
        TenantId, TenantScope,
    };

    use super::{
        MAX_RECOVERY_AUTHORITIES, RecoveryError, canonical_recovery_plan, recovery_plan_aad,
        validate_recovery_plan, validate_recovery_request,
    };

    fn id(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("test id")
    }

    fn plan() -> RecoveryPlan {
        RecoveryPlan {
            plan_id: RecoveryPlanId::from_opaque(id("recovery-plan-a")),
            scope: TenantScope {
                tenant_id: TenantId::from_opaque(id("tenant-a")),
                namespace_id: Some(NamespaceId::from_opaque(id("namespace-a"))),
            },
            identity_id: IdentityId::from_opaque(id("identity-a")),
            authorities: vec![
                RecoveryAuthority::RecoveryKey,
                RecoveryAuthority::TrustedDevice(DeviceId::from_opaque(id("device-trusted"))),
            ],
            historical_message_access: HistoricalMessageAccess::ExplicitEncryptedRecovery,
            trust_model: RecoveryTrustModel::UserControlled,
            recovered_device_state: DeviceLifecycleState::ReverificationRequired,
        }
    }

    fn request(authority: RecoveryAuthority) -> RecoveryRequest {
        let plan = plan();
        RecoveryRequest {
            plan_id: plan.plan_id,
            scope: plan.scope,
            identity_id: plan.identity_id,
            authority,
            target_device_id: DeviceId::from_opaque(id("device-new")),
        }
    }

    #[test]
    fn safe_recovery_plan_is_accepted() {
        assert_eq!(validate_recovery_plan(&plan()), Ok(()));
        assert_eq!(
            validate_recovery_request(&plan(), &request(RecoveryAuthority::RecoveryKey)),
            Ok(())
        );
    }

    #[test]
    fn recovery_never_auto_activates_new_device() {
        let mut unsafe_plan = plan();
        unsafe_plan.recovered_device_state = DeviceLifecycleState::Active;
        assert_eq!(
            validate_recovery_plan(&unsafe_plan),
            Err(RecoveryError::UnsafeRecoveredDeviceState)
        );
    }

    #[test]
    fn recovery_methods_are_explicit_and_unique() {
        let mut empty = plan();
        empty.authorities.clear();
        assert_eq!(
            validate_recovery_plan(&empty),
            Err(RecoveryError::NoAuthorities)
        );

        let mut duplicate = plan();
        duplicate.authorities.push(RecoveryAuthority::RecoveryKey);
        assert_eq!(
            validate_recovery_plan(&duplicate),
            Err(RecoveryError::DuplicateAuthority)
        );
    }

    #[test]
    fn organization_authority_requires_explicit_managed_trust_model() {
        let mut managed = plan();
        managed
            .authorities
            .push(RecoveryAuthority::OrganizationManaged(
                ucr_model::PrincipalId::from_opaque(id("org-admin")),
            ));
        assert_eq!(
            validate_recovery_plan(&managed),
            Err(RecoveryError::TrustModelAuthorityMismatch)
        );
        managed.trust_model = RecoveryTrustModel::OrganizationManaged;
        assert_eq!(validate_recovery_plan(&managed), Ok(()));
    }

    #[test]
    fn authority_order_does_not_change_canonical_plan_binding() {
        let first = plan();
        let mut reordered = first.clone();
        reordered.authorities.reverse();
        assert_eq!(recovery_plan_aad(&first), recovery_plan_aad(&reordered));
        assert_eq!(
            canonical_recovery_plan(&first).expect("canonical"),
            canonical_recovery_plan(&reordered).expect("canonical")
        );
    }

    #[test]
    fn recovery_authority_count_is_bounded_before_canonical_encoding() {
        let mut oversized = plan();
        oversized.authorities = (0..=MAX_RECOVERY_AUTHORITIES)
            .map(|index| {
                RecoveryAuthority::TrustedDevice(DeviceId::from_opaque(id(&format!(
                    "trusted-{index}"
                ))))
            })
            .collect();
        assert_eq!(
            validate_recovery_plan(&oversized),
            Err(RecoveryError::TooManyAuthorities)
        );
    }

    #[test]
    fn unplanned_recovery_method_fails_closed() {
        assert_eq!(
            validate_recovery_request(
                &plan(),
                &request(RecoveryAuthority::OrganizationManaged(
                    ucr_model::PrincipalId::from_opaque(id("org-admin")),
                ))
            ),
            Err(RecoveryError::MethodNotAllowed)
        );
    }
}
