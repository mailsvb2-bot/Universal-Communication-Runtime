use ucr_model::{
    IdentityId, NamespaceId, OpaqueId, PersonId, PersonRecord, PersonaId, PersonaKind,
    PersonaRecord, TenantId, TenantScope,
};

fn id(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("valid test id")
}

#[test]
fn personas_require_explicit_identity_associations_and_do_not_auto_merge() {
    let scope = TenantScope {
        tenant_id: TenantId::from_opaque(id("tenant")),
        namespace_id: Some(NamespaceId::from_opaque(id("namespace"))),
    };
    let person_id = PersonId::from_opaque(id("person"));

    let person = PersonRecord {
        scope: scope.clone(),
        person_id: person_id.clone(),
    };
    let private = PersonaRecord {
        scope: scope.clone(),
        persona_id: PersonaId::from_opaque(id("persona-private")),
        person_id: Some(person_id.clone()),
        identity_id: IdentityId::from_opaque(id("identity-private")),
        kind: PersonaKind::Private,
        expires_at_unix_ms: None,
    };
    let work = PersonaRecord {
        scope,
        persona_id: PersonaId::from_opaque(id("persona-work")),
        person_id: Some(person_id),
        identity_id: IdentityId::from_opaque(id("identity-work")),
        kind: PersonaKind::Work,
        expires_at_unix_ms: None,
    };

    assert_eq!(person.person_id, private.person_id.clone().expect("person link"));
    assert_ne!(private.persona_id, work.persona_id);
    assert_ne!(private.identity_id, work.identity_id);
}
