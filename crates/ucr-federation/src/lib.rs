#![forbid(unsafe_code)]

use ucr_core::{
    AuthorizationEvaluator, DeviceLifecycleStore, DurableRecordStatus, DurableStoreError,
    FederationPeerStore, SyncStore,
};
use ucr_crypto::{EstablishedSession, TrustedKeyResolutionError, TrustedSigningKeyResolver};
use ucr_model::{
    AuthorizationRequest, DeviceLifecycleState, EndpointId, FederationPeerRecord,
    FederationTrustState, ScopedPrincipal, SessionId, SyncLinkKind, SyncState, TenantScope,
};
use ucr_protocol::{
    FEDERATION_PEER_MANAGE_PERMISSION, FEDERATION_PEER_READ_PERMISSION, FEDERATION_SYNC_PERMISSION,
    SYNC_READ_PERMISSION,
};

pub const FEDERATION_RUNTIME_CAPABILITY: &str = "ucr.federation";

#[derive(Debug)]
pub enum FederationError {
    Authorization(ucr_protocol::CanonicalError),
    Store(DurableStoreError),
    MissingPeer,
    StateDenied,
    CapabilityDenied,
    MissingSyncSession,
    SyncInactive,
    SyncBindingMismatch,
    SessionUnauthenticated,
    PeerDeviceMismatch,
    PeerDeviceInactive,
    PeerKeyMismatch,
    PeerTrust(TrustedKeyResolutionError),
    SessionTrustChanged,
}

impl From<DurableStoreError> for FederationError {
    fn from(value: DurableStoreError) -> Self {
        Self::Store(value)
    }
}

pub trait FederationStore:
    FederationPeerStore + SyncStore + DeviceLifecycleStore + TrustedSigningKeyResolver
{
}
impl<T> FederationStore for T where
    T: FederationPeerStore + SyncStore + DeviceLifecycleStore + TrustedSigningKeyResolver
{
}

#[derive(Debug)]
pub struct FederationSyncAdmission<'a> {
    pub local_scope: &'a TenantScope,
    pub remote_scope: &'a TenantScope,
    pub remote_endpoint_id: &'a EndpointId,
    pub sync_session_id: &'a SessionId,
    pub required_capability: &'a str,
    pub session: &'a EstablishedSession,
}

#[derive(Debug)]
pub struct FederationRuntime<'a, A, S> {
    authorization: &'a A,
    store: &'a S,
}

impl<'a, A, S> FederationRuntime<'a, A, S> {
    #[must_use]
    pub const fn new(authorization: &'a A, store: &'a S) -> Self {
        Self {
            authorization,
            store,
        }
    }
}
impl<A, S> FederationRuntime<'_, A, S>
where
    A: AuthorizationEvaluator,
    S: FederationStore,
{
    /// Installs one explicit local policy binding for a remote UCR node.
    ///
    /// # Errors
    /// Returns authorization, validation, conflict, or durable-store failures.
    pub fn install_peer(
        &self,
        actor: &ScopedPrincipal,
        record: &FederationPeerRecord,
    ) -> Result<DurableRecordStatus, FederationError> {
        authorize(
            self.authorization,
            actor,
            &record.local_scope,
            FEDERATION_PEER_MANAGE_PERMISSION,
        )?;
        self.store
            .install_federation_peer(record)
            .map_err(Into::into)
    }

    /// Reads one exact locally configured federation peer.
    ///
    /// # Errors
    /// Returns authorization or durable-store failures.
    pub fn peer(
        &self,
        actor: &ScopedPrincipal,
        local_scope: &TenantScope,
        remote_scope: &TenantScope,
        remote_endpoint_id: &EndpointId,
    ) -> Result<Option<FederationPeerRecord>, FederationError> {
        authorize(
            self.authorization,
            actor,
            local_scope,
            FEDERATION_PEER_READ_PERMISSION,
        )?;
        self.store
            .federation_peer(local_scope, remote_scope, remote_endpoint_id)
            .map_err(Into::into)
    }

    /// Verifies a live authenticated session and advances `Known -> Authenticated`.
    /// Higher non-terminal states are revalidated and treated as idempotent.
    ///
    /// # Errors
    /// Fails closed for denied policy state, stale credentials, or changed Device/key trust.
    pub fn authenticate_peer(
        &self,
        actor: &ScopedPrincipal,
        local_scope: &TenantScope,
        remote_scope: &TenantScope,
        remote_endpoint_id: &EndpointId,
        session: &EstablishedSession,
    ) -> Result<DurableRecordStatus, FederationError> {
        authorize(
            self.authorization,
            actor,
            local_scope,
            FEDERATION_PEER_MANAGE_PERMISSION,
        )?;
        let record = self.load_peer(local_scope, remote_scope, remote_endpoint_id)?;
        self.verify_live_peer(&record, session)?;
        match record.state {
            FederationTrustState::Known => self
                .store
                .transition_federation_peer(
                    local_scope,
                    remote_scope,
                    remote_endpoint_id,
                    record.generation,
                    FederationTrustState::Authenticated,
                )
                .map_err(Into::into),
            FederationTrustState::Authenticated
            | FederationTrustState::Authorized
            | FederationTrustState::Trusted => Ok(DurableRecordStatus::Duplicate),
            FederationTrustState::Revoked | FederationTrustState::Blocked => {
                Err(FederationError::StateDenied)
            }
        }
    }

    /// Applies one explicit local trust-policy transition.
    ///
    /// # Errors
    /// Returns authorization, invalid-transition, conflict, or store failures.
    pub fn transition_peer(
        &self,
        actor: &ScopedPrincipal,
        local_scope: &TenantScope,
        remote_scope: &TenantScope,
        remote_endpoint_id: &EndpointId,
        expected_generation: u64,
        next_state: FederationTrustState,
    ) -> Result<DurableRecordStatus, FederationError> {
        authorize(
            self.authorization,
            actor,
            local_scope,
            FEDERATION_PEER_MANAGE_PERMISSION,
        )?;
        self.store
            .transition_federation_peer(
                local_scope,
                remote_scope,
                remote_endpoint_id,
                expected_generation,
                next_state,
            )
            .map_err(Into::into)
    }

    /// Rotates the expected remote credential and resets trust to `Known`.
    ///
    /// # Errors
    /// Returns authorization, validation, conflict, or store failures.
    pub fn rotate_peer_credential(
        &self,
        actor: &ScopedPrincipal,
        current: &FederationPeerRecord,
        replacement: &FederationPeerRecord,
    ) -> Result<DurableRecordStatus, FederationError> {
        authorize(
            self.authorization,
            actor,
            &current.local_scope,
            FEDERATION_PEER_MANAGE_PERMISSION,
        )?;
        self.store
            .rotate_federation_peer_credential(current, replacement)
            .map_err(Into::into)
    }

    /// Admits an already configured canonical Sync session across one federation relation.
    ///
    /// Authorization, federation state/capability, Sync binding and live peer trust are all checked.
    /// No Message, Conversation, Delivery or transport state is created here.
    ///
    /// # Errors
    /// Fails closed for unauthorized callers, inactive/blocked/revoked peers, stale sessions,
    /// unlisted capabilities, wrong endpoints, or changed Device/key trust.
    pub fn admit_sync(
        &self,
        actor: &ScopedPrincipal,
        admission: &FederationSyncAdmission<'_>,
    ) -> Result<FederationPeerRecord, FederationError> {
        authorize(
            self.authorization,
            actor,
            admission.local_scope,
            FEDERATION_SYNC_PERMISSION,
        )?;
        authorize(
            self.authorization,
            actor,
            admission.local_scope,
            SYNC_READ_PERMISSION,
        )?;
        let record = self.load_peer(
            admission.local_scope,
            admission.remote_scope,
            admission.remote_endpoint_id,
        )?;
        if !matches!(
            record.state,
            FederationTrustState::Authorized | FederationTrustState::Trusted
        ) {
            return Err(FederationError::StateDenied);
        }
        if !record
            .allowed_capabilities
            .iter()
            .any(|capability| capability == admission.required_capability)
        {
            return Err(FederationError::CapabilityDenied);
        }
        self.verify_live_peer(&record, admission.session)?;
        let sync = self
            .store
            .sync_session(admission.local_scope, admission.sync_session_id)?
            .ok_or(FederationError::MissingSyncSession)?;
        if sync.state != SyncState::Active || sync.link_kind != SyncLinkKind::DeviceNode {
            return Err(FederationError::SyncInactive);
        }
        if sync.source_endpoint_id != record.local_endpoint_id
            || sync.target_endpoint_id != record.remote_endpoint_id
        {
            return Err(FederationError::SyncBindingMismatch);
        }
        Ok(record)
    }

    fn load_peer(
        &self,
        local_scope: &TenantScope,
        remote_scope: &TenantScope,
        remote_endpoint_id: &EndpointId,
    ) -> Result<FederationPeerRecord, FederationError> {
        self.store
            .federation_peer(local_scope, remote_scope, remote_endpoint_id)?
            .ok_or(FederationError::MissingPeer)
    }
    fn verify_live_peer(
        &self,
        record: &FederationPeerRecord,
        session: &EstablishedSession,
    ) -> Result<(), FederationError> {
        let session_device = session
            .authenticated_peer_device_id()
            .ok_or(FederationError::SessionUnauthenticated)?;
        if session_device != &record.expected_device_id {
            return Err(FederationError::PeerDeviceMismatch);
        }
        let session_key = session
            .authenticated_peer_signing_descriptor()
            .ok_or(FederationError::SessionUnauthenticated)?;
        if session_key.device_id != record.expected_device_id
            || session_key.key_id != record.expected_signing_key_id
        {
            return Err(FederationError::PeerKeyMismatch);
        }
        let device = self
            .store
            .device(&record.remote_scope, &record.expected_device_id)?
            .ok_or(FederationError::PeerDeviceInactive)?;
        if device.state != DeviceLifecycleState::Active {
            return Err(FederationError::PeerDeviceInactive);
        }
        let current = self
            .store
            .resolve_active_signing_key(
                &record.remote_scope,
                &record.expected_device_id,
                Some(&device.identity_id),
                &record.expected_signing_key_id,
            )
            .map_err(FederationError::PeerTrust)?;
        if current != *session_key {
            return Err(FederationError::SessionTrustChanged);
        }
        Ok(())
    }
}
fn authorize<A: AuthorizationEvaluator>(
    authorization: &A,
    actor: &ScopedPrincipal,
    scope: &TenantScope,
    permission: &str,
) -> Result<(), FederationError> {
    authorization
        .authorize(&AuthorizationRequest {
            subject: actor.clone(),
            permission: permission.to_owned(),
            resource_scope: scope.clone(),
        })
        .map_err(FederationError::Authorization)
}
