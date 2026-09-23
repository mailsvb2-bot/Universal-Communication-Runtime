use core::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use ucr_model::{
    KeyId, NamespaceId, OpaqueId, PrincipalId, PrincipalKind, PrincipalRef, ScopedPrincipal,
    TenantId, TenantScope,
};
use zeroize::Zeroizing;

use crate::VerifyingKeyBytes;

pub const MAX_MACHINE_TOKEN_BYTES: usize = 8192;
pub const MAX_MACHINE_TOKEN_ISSUER_LEN: usize = 2048;
pub const MAX_MACHINE_TOKEN_AUDIENCE_LEN: usize = 512;
pub const MAX_MACHINE_TOKEN_SCOPE_LEN: usize = 128;
pub const MAX_MACHINE_TOKEN_SCOPES: usize = 32;
pub const MAX_MACHINE_TOKEN_TTL_SECONDS: u32 = 86_400;

const MACHINE_TOKEN_ALGORITHM: &str = "EdDSA";
const MACHINE_TOKEN_TYPE: &str = "at+jwt";
const ED25519_SIGNATURE_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineTokenPolicy {
    pub issuer: String,
    pub audience: String,
    pub max_ttl_seconds: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct AccessTokenIssueRequest<'a> {
    pub subject: &'a ScopedPrincipal,
    pub token_id: &'a OpaqueId,
    pub requested_scopes: &'a [String],
    pub allowed_scopes: &'a [String],
    pub issued_at_unix_s: u64,
    pub requested_ttl_seconds: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineTokenError {
    InvalidPolicy,
    NotServiceAccount,
    InvalidTtl,
    InvalidScope,
    ScopeNotAllowed,
    RandomUnavailable,
    Serialization,
    TokenTooLarge,
    MalformedToken,
    UnknownSigningKey,
    InvalidSignature,
    WrongIssuer,
    WrongAudience,
    NotYetValid,
    Expired,
    InvalidLifetime,
}

pub struct MachineTokenSigningKey {
    key_id: KeyId,
    key: SigningKey,
}

impl fmt::Debug for MachineTokenSigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MachineTokenSigningKey")
            .field("key_id", &self.key_id)
            .field("key", &"<secret>")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineTokenPublicKey {
    pub key_id: KeyId,
    pub verifying_key: VerifyingKeyBytes,
}

pub trait MachineTokenKeyResolver: fmt::Debug + Send + Sync {
    fn resolve_machine_token_key(&self, key_id: &KeyId) -> Option<VerifyingKeyBytes>;
}

impl MachineTokenKeyResolver for MachineTokenPublicKey {
    fn resolve_machine_token_key(&self, key_id: &KeyId) -> Option<VerifyingKeyBytes> {
        (self.key_id == *key_id).then_some(self.verifying_key)
    }
}

pub struct MachineAccessToken {
    encoded: String,
    pub expires_at_unix_s: u64,
    pub granted_scopes: Vec<String>,
    pub key_id: KeyId,
}

impl MachineAccessToken {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.encoded
    }
}

impl fmt::Debug for MachineAccessToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MachineAccessToken")
            .field("encoded", &"<redacted>")
            .field("encoded_len", &self.encoded.len())
            .field("expires_at_unix_s", &self.expires_at_unix_s)
            .field("granted_scopes", &self.granted_scopes)
            .field("key_id", &self.key_id)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedMachineAccessToken {
    pub subject: ScopedPrincipal,
    pub token_id: OpaqueId,
    pub granted_scopes: Vec<String>,
    pub issued_at_unix_s: u64,
    pub expires_at_unix_s: u64,
    pub key_id: KeyId,
}

#[derive(Serialize)]
struct MachineTokenHeader<'a> {
    alg: &'static str,
    typ: &'static str,
    kid: &'a str,
}

#[derive(Deserialize)]
struct DecodedMachineTokenHeader {
    alg: String,
    typ: String,
    kid: String,
}

#[derive(Serialize, Deserialize)]
struct MachineTokenClaims {
    iss: String,
    aud: String,
    sub: String,
    tenant_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    namespace_id: Option<String>,
    scope: String,
    iat: u64,
    exp: u64,
    jti: String,
}

impl MachineTokenSigningKey {
    /// Generates an Ed25519 access-token signing key from the operating-system CSPRNG.
    ///
    /// # Errors
    /// Returns `RandomUnavailable` if secure OS randomness is unavailable.
    pub fn generate(key_id: KeyId) -> Result<Self, MachineTokenError> {
        let mut seed = Zeroizing::new([0_u8; 32]);
        getrandom::fill(seed.as_mut()).map_err(|_| MachineTokenError::RandomUnavailable)?;
        Ok(Self {
            key_id,
            key: SigningKey::from_bytes(&seed),
        })
    }

    #[must_use]
    pub fn public_key(&self) -> MachineTokenPublicKey {
        MachineTokenPublicKey {
            key_id: self.key_id.clone(),
            verifying_key: VerifyingKeyBytes(self.key.verifying_key().to_bytes()),
        }
    }

    #[must_use]
    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }
}

/// Issues one short-lived Ed25519-signed JWT access token for an already authenticated
/// canonical Service Account. Requested OAuth scopes can only be drawn from the caller-provided
/// allowed scope set; this function never creates canonical Permission Grants.
///
/// # Errors
/// Fails closed for invalid policy, non-ServiceAccount subjects, invalid/duplicate scopes,
/// scope escalation, invalid TTL, serialization failure, or an oversized token.
pub fn issue_machine_access_token(
    signing_key: &MachineTokenSigningKey,
    policy: &MachineTokenPolicy,
    request: AccessTokenIssueRequest<'_>,
) -> Result<MachineAccessToken, MachineTokenError> {
    validate_policy(policy)?;
    if request.subject.principal.kind != PrincipalKind::ServiceAccount {
        return Err(MachineTokenError::NotServiceAccount);
    }

    let ttl_seconds = request
        .requested_ttl_seconds
        .unwrap_or(policy.max_ttl_seconds);
    if ttl_seconds == 0 || ttl_seconds > policy.max_ttl_seconds {
        return Err(MachineTokenError::InvalidTtl);
    }
    let expires_at_unix_s = request
        .issued_at_unix_s
        .checked_add(u64::from(ttl_seconds))
        .ok_or(MachineTokenError::InvalidTtl)?;

    let granted_scopes =
        validate_and_attenuate_scopes(request.requested_scopes, request.allowed_scopes)?;
    let header = MachineTokenHeader {
        alg: MACHINE_TOKEN_ALGORITHM,
        typ: MACHINE_TOKEN_TYPE,
        kid: signing_key.key_id.as_opaque().as_str(),
    };
    let claims = MachineTokenClaims {
        iss: policy.issuer.clone(),
        aud: policy.audience.clone(),
        sub: request
            .subject
            .principal
            .principal_id
            .as_opaque()
            .as_str()
            .to_owned(),
        tenant_id: request
            .subject
            .scope
            .tenant_id
            .as_opaque()
            .as_str()
            .to_owned(),
        namespace_id: request
            .subject
            .scope
            .namespace_id
            .as_ref()
            .map(|namespace| namespace.as_opaque().as_str().to_owned()),
        scope: granted_scopes.join(" "),
        iat: request.issued_at_unix_s,
        exp: expires_at_unix_s,
        jti: request.token_id.as_str().to_owned(),
    };

    let header_json = serde_json::to_vec(&header).map_err(|_| MachineTokenError::Serialization)?;
    let claims_json = serde_json::to_vec(&claims).map_err(|_| MachineTokenError::Serialization)?;
    let header_segment = URL_SAFE_NO_PAD.encode(header_json);
    let claims_segment = URL_SAFE_NO_PAD.encode(claims_json);
    let signing_input = format!("{header_segment}.{claims_segment}");
    let signature = signing_key.key.sign(signing_input.as_bytes());
    let signature_segment = URL_SAFE_NO_PAD.encode(signature.to_bytes());
    let encoded = format!("{signing_input}.{signature_segment}");
    if encoded.len() > MAX_MACHINE_TOKEN_BYTES {
        return Err(MachineTokenError::TokenTooLarge);
    }

    Ok(MachineAccessToken {
        encoded,
        expires_at_unix_s,
        granted_scopes,
        key_id: signing_key.key_id.clone(),
    })
}

/// Verifies signature, key ID, issuer, audience, lifetime, canonical Service Account identity,
/// tenant scope and bounded OAuth scope syntax for one machine access token.
///
/// Verification authenticates the signed Service Account identity but does not grant API
/// permission by itself. Callers must still evaluate canonical Permission Grants.
///
/// # Errors
/// Fails closed for malformed or oversized tokens, unknown keys, invalid signatures, identity
/// decoding failures, issuer/audience mismatch, invalid scope encoding, or invalid lifetime.
pub fn verify_machine_access_token<R: MachineTokenKeyResolver>(
    resolver: &R,
    policy: &MachineTokenPolicy,
    encoded: &str,
    now_unix_s: u64,
) -> Result<VerifiedMachineAccessToken, MachineTokenError> {
    validate_policy(policy)?;
    if encoded.is_empty() || encoded.len() > MAX_MACHINE_TOKEN_BYTES {
        return Err(MachineTokenError::TokenTooLarge);
    }

    let mut segments = encoded.split('.');
    let header_segment = segments.next().ok_or(MachineTokenError::MalformedToken)?;
    let claims_segment = segments.next().ok_or(MachineTokenError::MalformedToken)?;
    let signature_segment = segments.next().ok_or(MachineTokenError::MalformedToken)?;
    if segments.next().is_some()
        || header_segment.is_empty()
        || claims_segment.is_empty()
        || signature_segment.is_empty()
    {
        return Err(MachineTokenError::MalformedToken);
    }

    let header_bytes = decode_segment(header_segment)?;
    let header: DecodedMachineTokenHeader =
        serde_json::from_slice(&header_bytes).map_err(|_| MachineTokenError::MalformedToken)?;
    if header.alg != MACHINE_TOKEN_ALGORITHM || header.typ != MACHINE_TOKEN_TYPE {
        return Err(MachineTokenError::MalformedToken);
    }
    let key_id = KeyId::from_opaque(parse_opaque_id(&header.kid)?);
    let verifying_key_bytes = resolver
        .resolve_machine_token_key(&key_id)
        .ok_or(MachineTokenError::UnknownSigningKey)?;

    let signature_bytes = decode_segment(signature_segment)?;
    let signature_array: [u8; ED25519_SIGNATURE_LEN] = signature_bytes
        .try_into()
        .map_err(|_| MachineTokenError::MalformedToken)?;
    let signature = Signature::from_bytes(&signature_array);
    let verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes.0)
        .map_err(|_| MachineTokenError::InvalidSignature)?;
    let signing_input = format!("{header_segment}.{claims_segment}");
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| MachineTokenError::InvalidSignature)?;

    let claims_bytes = decode_segment(claims_segment)?;
    let claims: MachineTokenClaims =
        serde_json::from_slice(&claims_bytes).map_err(|_| MachineTokenError::MalformedToken)?;
    if claims.iss != policy.issuer {
        return Err(MachineTokenError::WrongIssuer);
    }
    if claims.aud != policy.audience {
        return Err(MachineTokenError::WrongAudience);
    }
    if claims.exp <= claims.iat
        || claims.exp.saturating_sub(claims.iat) > u64::from(policy.max_ttl_seconds)
    {
        return Err(MachineTokenError::InvalidLifetime);
    }
    if now_unix_s < claims.iat {
        return Err(MachineTokenError::NotYetValid);
    }
    if now_unix_s >= claims.exp {
        return Err(MachineTokenError::Expired);
    }

    let granted_scopes = parse_scope_claim(&claims.scope)?;
    let subject = ScopedPrincipal {
        scope: TenantScope {
            tenant_id: TenantId::from_opaque(parse_opaque_id(&claims.tenant_id)?),
            namespace_id: claims
                .namespace_id
                .as_deref()
                .map(parse_opaque_id)
                .transpose()?
                .map(NamespaceId::from_opaque),
        },
        principal: PrincipalRef {
            principal_id: PrincipalId::from_opaque(parse_opaque_id(&claims.sub)?),
            kind: PrincipalKind::ServiceAccount,
        },
    };

    Ok(VerifiedMachineAccessToken {
        subject,
        token_id: parse_opaque_id(&claims.jti)?,
        granted_scopes,
        issued_at_unix_s: claims.iat,
        expires_at_unix_s: claims.exp,
        key_id,
    })
}

fn validate_policy(policy: &MachineTokenPolicy) -> Result<(), MachineTokenError> {
    if policy.issuer.is_empty()
        || policy.issuer.len() > MAX_MACHINE_TOKEN_ISSUER_LEN
        || policy.audience.is_empty()
        || policy.audience.len() > MAX_MACHINE_TOKEN_AUDIENCE_LEN
        || policy.max_ttl_seconds == 0
        || policy.max_ttl_seconds > MAX_MACHINE_TOKEN_TTL_SECONDS
    {
        return Err(MachineTokenError::InvalidPolicy);
    }
    Ok(())
}

fn validate_and_attenuate_scopes(
    requested_scopes: &[String],
    allowed_scopes: &[String],
) -> Result<Vec<String>, MachineTokenError> {
    if requested_scopes.len() > MAX_MACHINE_TOKEN_SCOPES {
        return Err(MachineTokenError::InvalidScope);
    }
    let mut granted = requested_scopes.to_vec();
    if granted.iter().any(|scope| !valid_scope(scope)) {
        return Err(MachineTokenError::InvalidScope);
    }
    granted.sort();
    if granted.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(MachineTokenError::InvalidScope);
    }
    if granted
        .iter()
        .any(|scope| !allowed_scopes.iter().any(|allowed| allowed == scope))
    {
        return Err(MachineTokenError::ScopeNotAllowed);
    }
    Ok(granted)
}

fn parse_scope_claim(scope_claim: &str) -> Result<Vec<String>, MachineTokenError> {
    if scope_claim.is_empty() {
        return Ok(Vec::new());
    }
    let scopes = scope_claim
        .split(' ')
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if scopes.len() > MAX_MACHINE_TOKEN_SCOPES
        || scopes.iter().any(|scope| !valid_scope(scope))
        || scopes.windows(2).any(|pair| pair[0] >= pair[1])
        || scopes.join(" ") != scope_claim
    {
        return Err(MachineTokenError::InvalidScope);
    }
    Ok(scopes)
}

fn valid_scope(scope: &str) -> bool {
    !scope.is_empty()
        && scope.len() <= MAX_MACHINE_TOKEN_SCOPE_LEN
        && scope.bytes().all(|byte| {
            byte == b'!' || (b'#'..=b'[').contains(&byte) || (b']'..=b'~').contains(&byte)
        })
}

fn decode_segment(segment: &str) -> Result<Vec<u8>, MachineTokenError> {
    if segment.len() > MAX_MACHINE_TOKEN_BYTES {
        return Err(MachineTokenError::TokenTooLarge);
    }
    URL_SAFE_NO_PAD
        .decode(segment.as_bytes())
        .map_err(|_| MachineTokenError::MalformedToken)
}

fn parse_opaque_id(value: &str) -> Result<OpaqueId, MachineTokenError> {
    OpaqueId::new(value).map_err(|_| MachineTokenError::MalformedToken)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct TestKeySet(Vec<MachineTokenPublicKey>);

    impl MachineTokenKeyResolver for TestKeySet {
        fn resolve_machine_token_key(&self, key_id: &KeyId) -> Option<VerifyingKeyBytes> {
            self.0
                .iter()
                .find(|key| key.key_id == *key_id)
                .map(|key| key.verifying_key)
        }
    }

    fn opaque(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("test opaque ID")
    }

    fn key_id(value: &str) -> KeyId {
        KeyId::from_opaque(opaque(value))
    }

    fn service_subject() -> ScopedPrincipal {
        ScopedPrincipal {
            scope: TenantScope {
                tenant_id: TenantId::from_opaque(opaque("tenant-a")),
                namespace_id: Some(NamespaceId::from_opaque(opaque("namespace-a"))),
            },
            principal: PrincipalRef {
                principal_id: PrincipalId::from_opaque(opaque("integration-a")),
                kind: PrincipalKind::ServiceAccount,
            },
        }
    }

    fn policy() -> MachineTokenPolicy {
        MachineTokenPolicy {
            issuer: "https://ucr.example.test".to_owned(),
            audience: "ucr-api".to_owned(),
            max_ttl_seconds: 900,
        }
    }

    #[test]
    fn signed_machine_token_round_trips_canonical_service_subject() {
        let signing_key = MachineTokenSigningKey::generate(key_id("token-key-a")).expect("key");
        let public_key = signing_key.public_key();
        let requested = vec!["conference:read".to_owned(), "conference:create".to_owned()];
        let allowed = vec![
            "conference:create".to_owned(),
            "conference:read".to_owned(),
            "conference:manage".to_owned(),
        ];
        let token = issue_machine_access_token(
            &signing_key,
            &policy(),
            AccessTokenIssueRequest {
                subject: &service_subject(),
                token_id: &opaque("token-a"),
                requested_scopes: &requested,
                allowed_scopes: &allowed,
                issued_at_unix_s: 1_000,
                requested_ttl_seconds: Some(300),
            },
        )
        .expect("issue");
        let verified = verify_machine_access_token(&public_key, &policy(), token.as_str(), 1_100)
            .expect("verify");

        assert_eq!(verified.subject, service_subject());
        assert_eq!(verified.token_id, opaque("token-a"));
        assert_eq!(
            verified.granted_scopes,
            vec!["conference:create".to_owned(), "conference:read".to_owned()]
        );
        assert_eq!(verified.issued_at_unix_s, 1_000);
        assert_eq!(verified.expires_at_unix_s, 1_300);
        assert_eq!(verified.key_id, key_id("token-key-a"));
    }

    #[test]
    fn scope_request_cannot_escalate_beyond_allowed_scope_set() {
        let signing_key = MachineTokenSigningKey::generate(key_id("token-key-a")).expect("key");
        let error = issue_machine_access_token(
            &signing_key,
            &policy(),
            AccessTokenIssueRequest {
                subject: &service_subject(),
                token_id: &opaque("token-a"),
                requested_scopes: &["conference:manage".to_owned()],
                allowed_scopes: &["conference:read".to_owned()],
                issued_at_unix_s: 1_000,
                requested_ttl_seconds: None,
            },
        )
        .expect_err("must reject escalation");
        assert_eq!(error, MachineTokenError::ScopeNotAllowed);
    }

    #[test]
    fn verifier_rejects_wrong_audience_expiry_and_tampering() {
        let signing_key = MachineTokenSigningKey::generate(key_id("token-key-a")).expect("key");
        let public_key = signing_key.public_key();
        let scopes = vec!["conference:read".to_owned()];
        let token = issue_machine_access_token(
            &signing_key,
            &policy(),
            AccessTokenIssueRequest {
                subject: &service_subject(),
                token_id: &opaque("token-a"),
                requested_scopes: &scopes,
                allowed_scopes: &scopes,
                issued_at_unix_s: 1_000,
                requested_ttl_seconds: Some(60),
            },
        )
        .expect("issue");

        let mut wrong_audience = policy();
        wrong_audience.audience = "other-api".to_owned();
        assert_eq!(
            verify_machine_access_token(&public_key, &wrong_audience, token.as_str(), 1_010),
            Err(MachineTokenError::WrongAudience)
        );
        assert_eq!(
            verify_machine_access_token(&public_key, &policy(), token.as_str(), 1_060),
            Err(MachineTokenError::Expired)
        );

        let mut tampered = token.as_str().as_bytes().to_vec();
        let index = tampered
            .iter()
            .position(|byte| *byte == b'.')
            .expect("JWT separator")
            + 2;
        tampered[index] = if tampered[index] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(tampered).expect("ASCII token");
        assert!(matches!(
            verify_machine_access_token(&public_key, &policy(), &tampered, 1_010),
            Err(MachineTokenError::InvalidSignature | MachineTokenError::MalformedToken)
        ));
    }

    #[test]
    fn key_rotation_resolver_accepts_overlap_and_rejects_unknown_kid() {
        let old_key = MachineTokenSigningKey::generate(key_id("token-key-old")).expect("old key");
        let new_key = MachineTokenSigningKey::generate(key_id("token-key-new")).expect("new key");
        let scopes = vec!["conference:read".to_owned()];
        let old_token = issue_machine_access_token(
            &old_key,
            &policy(),
            AccessTokenIssueRequest {
                subject: &service_subject(),
                token_id: &opaque("token-old"),
                requested_scopes: &scopes,
                allowed_scopes: &scopes,
                issued_at_unix_s: 1_000,
                requested_ttl_seconds: Some(300),
            },
        )
        .expect("old token");
        let key_set = TestKeySet(vec![old_key.public_key(), new_key.public_key()]);
        assert!(
            verify_machine_access_token(&key_set, &policy(), old_token.as_str(), 1_100).is_ok()
        );

        let new_only = TestKeySet(vec![new_key.public_key()]);
        assert_eq!(
            verify_machine_access_token(&new_only, &policy(), old_token.as_str(), 1_100),
            Err(MachineTokenError::UnknownSigningKey)
        );
    }

    #[test]
    fn token_and_private_key_debug_are_redacted() {
        let signing_key = MachineTokenSigningKey::generate(key_id("token-key-a")).expect("key");
        let scopes = vec!["conference:read".to_owned()];
        let token = issue_machine_access_token(
            &signing_key,
            &policy(),
            &service_subject(),
            &opaque("token-a"),
            &scopes,
            &scopes,
            1_000,
            Some(60),
        )
        .expect("issue");
        let token_debug = format!("{token:?}");
        let key_debug = format!("{signing_key:?}");
        assert!(!token_debug.contains(token.as_str()));
        assert!(token_debug.contains("<redacted>"));
        assert!(key_debug.contains("<secret>"));
    }

    #[test]
    fn issuer_rejects_person_subject_and_overlong_ttl() {
        let signing_key = MachineTokenSigningKey::generate(key_id("token-key-a")).expect("key");
        let mut person = service_subject();
        person.principal.kind = PrincipalKind::Person;
        assert_eq!(
            issue_machine_access_token(
                &signing_key,
                &policy(),
                AccessTokenIssueRequest {
                    subject: &person,
                    token_id: &opaque("token-a"),
                    requested_scopes: &[],
                    allowed_scopes: &[],
                    issued_at_unix_s: 1_000,
                    requested_ttl_seconds: None,
                },
            )
            .expect_err("person denied"),
            MachineTokenError::NotServiceAccount
        );
        assert_eq!(
            issue_machine_access_token(
                &signing_key,
                &policy(),
                AccessTokenIssueRequest {
                    subject: &service_subject(),
                    token_id: &opaque("token-a"),
                    requested_scopes: &[],
                    allowed_scopes: &[],
                    issued_at_unix_s: 1_000,
                    requested_ttl_seconds: Some(901),
                },
            )
            .expect_err("ttl denied"),
            MachineTokenError::InvalidTtl
        );
    }
}
