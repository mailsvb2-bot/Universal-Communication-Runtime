use core::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ucr_core::ServiceCredentialSecret;
use ucr_model::{NamespaceId, OpaqueId, ServiceCredentialId, TenantId, TenantScope};
use zeroize::Zeroize;

const OAUTH_CLIENT_SECRET_PREFIX: &str = "ucr1.";
const SERVICE_CREDENTIAL_SECRET_LEN: usize = 32;
const MAX_DECODED_CLIENT_SECRET_BYTES: usize = 2
    + OpaqueId::MAX_LEN
    + 1
    + 2
    + OpaqueId::MAX_LEN
    + 2
    + OpaqueId::MAX_LEN
    + SERVICE_CREDENTIAL_SECRET_LEN;
const MAX_ENCODED_CLIENT_SECRET_LEN: usize = 640;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthClientSecretError {
    Malformed,
    TooLarge,
}

/// One external OAuth `client_secret` value.
///
/// The encoded value is deliberately opaque to an integration. It packages the existing canonical
/// Service Credential locator and exact tenant scope together with the one-time credential secret,
/// so an external service only needs to persist its canonical `client_id` plus this one secret
/// string. No second credential, identity, tenant, or permission owner is introduced.
pub struct OAuthClientSecret(String);

impl OAuthClientSecret {
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for OAuthClientSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("OAuthClientSecret")
            .field(&"<redacted>")
            .finish()
    }
}

impl Drop for OAuthClientSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Decoded transport binding for one OAuth client secret.
///
/// This value is transport evidence only. The contained canonical Service Credential must still be
/// authenticated by `ServicePrincipalRequestGate`, and the independently presented OAuth
/// `client_id` must still match the authenticated Service Account before any token is issued.
pub struct OAuthClientSecretBinding {
    scope: TenantScope,
    credential_id: ServiceCredentialId,
    secret: ServiceCredentialSecret,
}

impl OAuthClientSecretBinding {
    #[must_use]
    pub const fn scope(&self) -> &TenantScope {
        &self.scope
    }

    #[must_use]
    pub const fn credential_id(&self) -> &ServiceCredentialId {
        &self.credential_id
    }

    #[must_use]
    pub const fn secret(&self) -> &ServiceCredentialSecret {
        &self.secret
    }
}

impl fmt::Debug for OAuthClientSecretBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OAuthClientSecretBinding")
            .field("scope", &self.scope)
            .field("credential_id", &self.credential_id)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// Encodes an existing canonical Service Credential into one opaque OAuth client secret.
///
/// The transport secret carries only locator material plus the credential secret. It creates no
/// durable state and can therefore be regenerated from the one-time credential issuance output
/// without changing the canonical Service Account or Permission Grants.
#[must_use]
pub fn encode_oauth_client_secret(
    scope: &TenantScope,
    credential_id: &ServiceCredentialId,
    secret: &ServiceCredentialSecret,
) -> OAuthClientSecret {
    let mut raw = Vec::with_capacity(MAX_DECODED_CLIENT_SECRET_BYTES);
    append_opaque(&mut raw, scope.tenant_id.as_opaque());
    match &scope.namespace_id {
        Some(namespace_id) => {
            raw.push(1);
            append_opaque(&mut raw, namespace_id.as_opaque());
        }
        None => raw.push(0),
    }
    append_opaque(&mut raw, credential_id.as_opaque());
    raw.extend_from_slice(secret.as_bytes());

    let encoded = format!(
        "{OAUTH_CLIENT_SECRET_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(&raw)
    );
    raw.zeroize();
    OAuthClientSecret(encoded)
}

/// Decodes an opaque OAuth client secret into the canonical credential inputs required by the
/// shared M2M authentication runtime.
///
/// # Errors
/// Returns `TooLarge` for an input outside the bounded transport budget and `Malformed` for an
/// invalid prefix, Base64URL payload, identifier, namespace marker, length, or trailing data.
pub fn decode_oauth_client_secret(
    encoded: &str,
) -> Result<OAuthClientSecretBinding, OAuthClientSecretError> {
    if encoded.len() > MAX_ENCODED_CLIENT_SECRET_LEN {
        return Err(OAuthClientSecretError::TooLarge);
    }
    let payload = encoded
        .strip_prefix(OAUTH_CLIENT_SECRET_PREFIX)
        .ok_or(OAuthClientSecretError::Malformed)?;
    let mut raw = URL_SAFE_NO_PAD
        .decode(payload.as_bytes())
        .map_err(|_| OAuthClientSecretError::Malformed)?;
    if raw.len() > MAX_DECODED_CLIENT_SECRET_BYTES {
        raw.zeroize();
        return Err(OAuthClientSecretError::TooLarge);
    }

    let decoded = decode_binding(&raw);
    raw.zeroize();
    decoded
}

fn decode_binding(raw: &[u8]) -> Result<OAuthClientSecretBinding, OAuthClientSecretError> {
    let mut cursor = 0;
    let tenant_id = TenantId::from_opaque(read_opaque(raw, &mut cursor)?);
    let namespace_id = match take(raw, &mut cursor, 1)?[0] {
        0 => None,
        1 => Some(NamespaceId::from_opaque(read_opaque(raw, &mut cursor)?)),
        _ => return Err(OAuthClientSecretError::Malformed),
    };
    let credential_id = ServiceCredentialId::from_opaque(read_opaque(raw, &mut cursor)?);
    let mut secret_bytes = [0_u8; SERVICE_CREDENTIAL_SECRET_LEN];
    secret_bytes.copy_from_slice(take(raw, &mut cursor, SERVICE_CREDENTIAL_SECRET_LEN)?);
    if cursor != raw.len() {
        secret_bytes.zeroize();
        return Err(OAuthClientSecretError::Malformed);
    }
    let secret = ServiceCredentialSecret::from_bytes(secret_bytes);
    secret_bytes.zeroize();

    Ok(OAuthClientSecretBinding {
        scope: TenantScope {
            tenant_id,
            namespace_id,
        },
        credential_id,
        secret,
    })
}

fn append_opaque(output: &mut Vec<u8>, value: &OpaqueId) {
    let bytes = value.as_wire_bytes();
    let length = u16::try_from(bytes.len()).expect("OpaqueId is bounded below u16::MAX");
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
}

fn read_opaque(raw: &[u8], cursor: &mut usize) -> Result<OpaqueId, OAuthClientSecretError> {
    let length_bytes: [u8; 2] = take(raw, cursor, 2)?
        .try_into()
        .map_err(|_| OAuthClientSecretError::Malformed)?;
    let length = usize::from(u16::from_be_bytes(length_bytes));
    let value = take(raw, cursor, length)?;
    OpaqueId::from_wire_bytes(value).map_err(|_| OAuthClientSecretError::Malformed)
}

fn take<'a>(
    raw: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> Result<&'a [u8], OAuthClientSecretError> {
    let end = cursor
        .checked_add(length)
        .ok_or(OAuthClientSecretError::Malformed)?;
    let value = raw
        .get(*cursor..end)
        .ok_or(OAuthClientSecretError::Malformed)?;
    *cursor = end;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use ucr_core::{
        ServiceCredentialStore, authenticate_service_principal, issue_service_credential,
    };
    use ucr_model::{PrincipalId, PrincipalKind, PrincipalRef, ScopedPrincipal};
    use ucr_storage_memory::MemoryLocalStore;

    use super::*;

    fn opaque(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("test opaque ID")
    }

    fn scope(namespace: Option<&str>) -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(opaque("tenant-oauth")),
            namespace_id: namespace.map(|value| NamespaceId::from_opaque(opaque(value))),
        }
    }

    fn subject(scope: TenantScope) -> ScopedPrincipal {
        ScopedPrincipal {
            scope,
            principal: PrincipalRef {
                principal_id: PrincipalId::from_opaque(opaque("integration-oauth")),
                kind: PrincipalKind::ServiceAccount,
            },
        }
    }

    #[test]
    fn opaque_oauth_secret_round_trips_into_canonical_authentication() {
        let store = MemoryLocalStore::default();
        let subject = subject(scope(Some("namespace-oauth")));
        let (record, secret) = issue_service_credential(&subject).expect("issue credential");
        store
            .provision_service_credential(&record)
            .expect("persist credential");

        let encoded = encode_oauth_client_secret(&subject.scope, &record.credential_id, &secret);
        assert!(
            encoded
                .expose_secret()
                .starts_with(OAUTH_CLIENT_SECRET_PREFIX)
        );
        assert!(!format!("{encoded:?}").contains(encoded.expose_secret()));

        let decoded =
            decode_oauth_client_secret(encoded.expose_secret()).expect("decode client secret");
        assert_eq!(decoded.scope(), &subject.scope);
        assert_eq!(decoded.credential_id(), &record.credential_id);
        assert_eq!(decoded.secret().as_bytes(), secret.as_bytes());
        assert!(!format!("{decoded:?}").contains("070707"));

        let authenticated = authenticate_service_principal(
            &store,
            decoded.scope(),
            decoded.credential_id(),
            decoded.secret(),
        )
        .expect("canonical authentication");
        assert_eq!(authenticated, subject);
    }

    #[test]
    fn oauth_secret_round_trips_scope_without_namespace() {
        let scope = scope(None);
        let credential_id = ServiceCredentialId::from_opaque(opaque("credential-oauth"));
        let secret = ServiceCredentialSecret::from_bytes([9; SERVICE_CREDENTIAL_SECRET_LEN]);

        let encoded = encode_oauth_client_secret(&scope, &credential_id, &secret);
        let decoded =
            decode_oauth_client_secret(encoded.expose_secret()).expect("decode client secret");
        assert_eq!(decoded.scope(), &scope);
        assert_eq!(decoded.credential_id(), &credential_id);
        assert_eq!(decoded.secret().as_bytes(), secret.as_bytes());
    }

    #[test]
    fn malformed_or_oversized_oauth_secret_fails_closed() {
        assert!(matches!(
            decode_oauth_client_secret("not-ucr-secret"),
            Err(OAuthClientSecretError::Malformed)
        ));
        assert!(matches!(
            decode_oauth_client_secret("ucr1.%%%not-base64%%%"),
            Err(OAuthClientSecretError::Malformed)
        ));

        let scope = scope(Some("namespace-oauth"));
        let credential_id = ServiceCredentialId::from_opaque(opaque("credential-oauth"));
        let secret = ServiceCredentialSecret::from_bytes([7; SERVICE_CREDENTIAL_SECRET_LEN]);
        let encoded = encode_oauth_client_secret(&scope, &credential_id, &secret);
        let with_trailing = format!("{}AA", encoded.expose_secret());
        assert!(decode_oauth_client_secret(&with_trailing).is_err());

        let oversized = "x".repeat(MAX_ENCODED_CLIENT_SECRET_LEN + 1);
        assert!(matches!(
            decode_oauth_client_secret(&oversized),
            Err(OAuthClientSecretError::TooLarge)
        ));
    }
}
