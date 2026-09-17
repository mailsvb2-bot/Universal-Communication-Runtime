#![forbid(unsafe_code)]

use ucr_model::{
    ActorKind, ActorRef, AuthorizationRequest, ConversationId, PermissionGrant, PrincipalKind,
    ScopedPrincipal, TenantScope,
};
use ucr_protocol::authorize;

/// Conversation-level permission for AI processing of communication data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AiDataPolicy {
    AiForbidden,
    LocalAiOnly,
    OrganizationAi,
    ExternalAiAllowed,
}

/// Where the AI computation is performed. This is deliberately separate from transport routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AiExecutionClass {
    Local,
    Organization,
    External,
}

/// Prepared Phase-42 identity and quota binding for one canonical AI Actor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiActorProfile {
    pub scope: TenantScope,
    pub principal: ScopedPrincipal,
    pub actor: ActorRef,
    pub quota_units: u64,
    pub attribution_label: String,
}

/// AI policy attached to one canonical Conversation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationAiPolicy {
    pub scope: TenantScope,
    pub conversation_id: ConversationId,
    pub data_policy: AiDataPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AiAdmissionOutcome {
    Authorized,
    DeniedScope,
    DeniedIdentity,
    DeniedAttribution,
    DeniedDataPolicy,
    DeniedPermission,
    DeniedQuota,
}

/// Audit-safe admission evidence. It never stores prompt, response, message plaintext or credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiAdmissionAudit {
    pub scope: TenantScope,
    pub conversation_id: ConversationId,
    pub actor: ActorRef,
    pub execution: AiExecutionClass,
    pub permission: String,
    pub requested_units: u64,
    pub outcome: AiAdmissionOutcome,
}

fn policy_allows(policy: AiDataPolicy, execution: AiExecutionClass) -> bool {
    match policy {
        AiDataPolicy::AiForbidden => false,
        AiDataPolicy::LocalAiOnly => matches!(execution, AiExecutionClass::Local),
        AiDataPolicy::OrganizationAi => {
            matches!(execution, AiExecutionClass::Local | AiExecutionClass::Organization)
        }
        AiDataPolicy::ExternalAiAllowed => true,
    }
}

/// Evaluates AI admission without invoking an AI provider or changing communication delivery state.
///
/// The existing canonical authorization engine remains the permission owner. This function adds only
/// Phase-42 AI-specific identity, attribution, data-policy and quota checks and returns auditable
/// evidence. A denied AI action does not block ordinary messages, sync, calls or files.
#[must_use]
pub fn admit_ai_action(
    profile: &AiActorProfile,
    policy: &ConversationAiPolicy,
    grants: &[PermissionGrant],
    execution: AiExecutionClass,
    permission: &str,
    requested_units: u64,
) -> AiAdmissionAudit {
    let outcome = if profile.scope != policy.scope || profile.principal.scope != profile.scope {
        AiAdmissionOutcome::DeniedScope
    } else if profile.principal.principal.kind != PrincipalKind::AiAgent
        || profile.actor.kind != ActorKind::AiAgent
    {
        AiAdmissionOutcome::DeniedIdentity
    } else if profile.attribution_label.trim().is_empty() {
        AiAdmissionOutcome::DeniedAttribution
    } else if !policy_allows(policy.data_policy, execution) {
        AiAdmissionOutcome::DeniedDataPolicy
    } else if requested_units == 0 || requested_units > profile.quota_units {
        AiAdmissionOutcome::DeniedQuota
    } else {
        let request = AuthorizationRequest {
            subject: profile.principal.clone(),
            permission: permission.to_owned(),
            resource_scope: policy.scope.clone(),
        };
        if authorize(&request, grants).is_ok() {
            AiAdmissionOutcome::Authorized
        } else {
            AiAdmissionOutcome::DeniedPermission
        }
    };

    AiAdmissionAudit {
        scope: policy.scope.clone(),
        conversation_id: policy.conversation_id.clone(),
        actor: profile.actor.clone(),
        execution,
        permission: permission.to_owned(),
        requested_units,
        outcome,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ucr_model::{
        ActorId, OpaqueId, PermissionScope, PrincipalId, PrincipalRef, TenantId,
    };

    fn id(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("test opaque id")
    }

    fn scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(id("tenant-ai")),
            namespace_id: None,
        }
    }

    fn profile() -> AiActorProfile {
        let scope = scope();
        let principal_id = PrincipalId::from_opaque(id("principal-ai"));
        AiActorProfile {
            scope: scope.clone(),
            principal: ScopedPrincipal {
                scope,
                principal: PrincipalRef {
                    principal_id: principal_id.clone(),
                    kind: PrincipalKind::AiAgent,
                },
            },
            actor: ActorRef {
                actor_id: ActorId::from_opaque(id("actor-ai")),
                kind: ActorKind::AiAgent,
                on_behalf_of: Some(principal_id),
            },
            quota_units: 10,
            attribution_label: "UCR Assistant".to_owned(),
        }
    }

    fn policy(data_policy: AiDataPolicy) -> ConversationAiPolicy {
        ConversationAiPolicy {
            scope: scope(),
            conversation_id: ConversationId::from_opaque(id("conversation-ai")),
            data_policy,
        }
    }

    fn grant(profile: &AiActorProfile, permission: &str) -> PermissionGrant {
        PermissionGrant {
            grantee: profile.principal.clone(),
            permission: permission.to_owned(),
            scope: PermissionScope::Exact(profile.scope.clone()),
        }
    }

    #[test]
    fn ai_forbidden_denies_even_an_authorized_ai_principal() {
        let profile = profile();
        let permission = "ucr.message.read";
        let audit = admit_ai_action(
            &profile,
            &policy(AiDataPolicy::AiForbidden),
            &[grant(&profile, permission)],
            AiExecutionClass::Local,
            permission,
            1,
        );
        assert_eq!(audit.outcome, AiAdmissionOutcome::DeniedDataPolicy);
    }

    #[test]
    fn local_only_rejects_external_execution() {
        let profile = profile();
        let permission = "ucr.message.read";
        let audit = admit_ai_action(
            &profile,
            &policy(AiDataPolicy::LocalAiOnly),
            &[grant(&profile, permission)],
            AiExecutionClass::External,
            permission,
            1,
        );
        assert_eq!(audit.outcome, AiAdmissionOutcome::DeniedDataPolicy);
    }

    #[test]
    fn canonical_permission_and_quota_are_both_required() {
        let profile = profile();
        let permission = "ucr.message.read";
        let allowed = admit_ai_action(
            &profile,
            &policy(AiDataPolicy::ExternalAiAllowed),
            &[grant(&profile, permission)],
            AiExecutionClass::External,
            permission,
            2,
        );
        assert_eq!(allowed.outcome, AiAdmissionOutcome::Authorized);

        let missing_permission = admit_ai_action(
            &profile,
            &policy(AiDataPolicy::ExternalAiAllowed),
            &[],
            AiExecutionClass::Local,
            permission,
            2,
        );
        assert_eq!(missing_permission.outcome, AiAdmissionOutcome::DeniedPermission);

        let over_quota = admit_ai_action(
            &profile,
            &policy(AiDataPolicy::ExternalAiAllowed),
            &[grant(&profile, permission)],
            AiExecutionClass::Local,
            permission,
            11,
        );
        assert_eq!(over_quota.outcome, AiAdmissionOutcome::DeniedQuota);
    }

    #[test]
    fn human_actor_cannot_be_admitted_as_ai() {
        let mut profile = profile();
        profile.actor.kind = ActorKind::Person;
        let permission = "ucr.message.read";
        let audit = admit_ai_action(
            &profile,
            &policy(AiDataPolicy::ExternalAiAllowed),
            &[grant(&profile, permission)],
            AiExecutionClass::Local,
            permission,
            1,
        );
        assert_eq!(audit.outcome, AiAdmissionOutcome::DeniedIdentity);
    }

    #[test]
    fn audit_evidence_contains_no_prompt_or_response_payload() {
        let source = include_str!("lib.rs");
        let audit_struct = source
            .split("pub struct AiAdmissionAudit")
            .nth(1)
            .expect("audit struct")
            .split('}')
            .next()
            .expect("audit body");
        assert!(!audit_struct.contains("prompt"));
        assert!(!audit_struct.contains("response"));
        assert!(!audit_struct.contains("content"));
        assert!(!audit_struct.contains("secret"));
    }
}
