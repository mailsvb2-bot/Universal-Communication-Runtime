use core::fmt;

use crate::{EndpointId, EndpointKind, PersonalNodeObjectId, TenantScope};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PersonalNodeService {
    Sync,
    EncryptedMailbox,
    Relay,
    Cache,
    Bridge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersonalNodeState {
    Active,
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonalNodeProfile {
    pub scope: TenantScope,
    pub endpoint_id: EndpointId,
    pub endpoint_kind: EndpointKind,
    pub services: Vec<PersonalNodeService>,
    pub state: PersonalNodeState,
    pub generation: u64,
    pub mailbox_capacity_bytes: u64,
    pub cache_capacity_bytes: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PersonalNodeObjectKind {
    Mailbox,
    Cache,
}

#[derive(Clone, PartialEq, Eq)]
pub struct PersonalNodeObject {
    pub object_id: PersonalNodeObjectId,
    pub scope: TenantScope,
    pub endpoint_id: EndpointId,
    pub kind: PersonalNodeObjectKind,
    pub encryption_scheme: String,
    pub ciphertext: Vec<u8>,
    pub ciphertext_sha256: [u8; 32],
    pub created_at_unix_ms: i64,
    pub expires_at_unix_ms: Option<i64>,
}

impl fmt::Debug for PersonalNodeObject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersonalNodeObject")
            .field("object_id", &self.object_id)
            .field("scope", &self.scope)
            .field("endpoint_id", &self.endpoint_id)
            .field("kind", &self.kind)
            .field("encryption_scheme", &self.encryption_scheme)
            .field("ciphertext", &"<redacted>")
            .field("ciphertext_len", &self.ciphertext.len())
            .field("ciphertext_sha256", &"<digest>")
            .field("created_at_unix_ms", &self.created_at_unix_ms)
            .field("expires_at_unix_ms", &self.expires_at_unix_ms)
            .finish()
    }
}
