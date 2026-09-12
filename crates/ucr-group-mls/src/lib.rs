#![forbid(unsafe_code)]

use core::fmt::Write as _;

use openmls::prelude::{
    BasicCredential, Ciphersuite, CredentialWithKey, KeyPackage, KeyPackageIn, MlsGroup,
    MlsGroupCreateConfig, MlsMessageBodyIn, MlsMessageIn, MlsMessageOut, ProtocolVersion,
    StagedWelcome,
    tls_codec::{Deserialize as _, Serialize as _},
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::{Codec as OpenMlsSqliteCodec, SqliteStorageProvider};
use openmls_traits::{
    OpenMlsProvider,
    storage::{CURRENT_VERSION, StorageProvider as OpenMlsStorageProvider},
};
use rusqlite::{Connection, OptionalExtension};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use ucr_core::{DurableRecordStatus, DurableStoreError};
use ucr_crypto::GroupMediaEpochSecret;
use ucr_model::{
    ConversationRecord, DeviceId, GroupChange, GroupCryptoState, GroupId, GroupRecord, OpaqueId,
    ScopedPrincipal, TenantScope,
};
use ucr_protocol::{GROUP_MLS_CAPABILITY, group_change_fingerprint};

/// `OpenMLS` provider composed from the audited `RustCrypto` implementation and caller-owned storage.
/// This lets UCR bind MLS persistence to the same transaction as canonical Group state.
#[derive(Debug)]
pub struct UcrOpenMlsProvider<S> {
    crypto: RustCrypto,
    storage: S,
}

impl<S> UcrOpenMlsProvider<S> {
    #[must_use]
    pub fn new(storage: S) -> Self {
        Self {
            crypto: RustCrypto::default(),
            storage,
        }
    }
}

impl<S> OpenMlsProvider for UcrOpenMlsProvider<S>
where
    S: OpenMlsStorageProvider<CURRENT_VERSION>,
{
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = S;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }
    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }
    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct JsonCodec;

impl OpenMlsSqliteCodec for JsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}

pub type SqliteMlsStorage<'a> = SqliteStorageProvider<JsonCodec, &'a Connection>;
pub type SqliteMlsProvider<'a> = UcrOpenMlsProvider<SqliteMlsStorage<'a>>;

/// Opaque RFC 9420 group state used by internal durable adapters without a direct `OpenMLS` dependency.
pub type MlsGroupState = MlsGroup;

/// Installs/updates the official `OpenMLS` `SQLite` schema in the same database used by UCR.
///
/// `OpenMLS` owns only its `openmls_*` tables and its namespaced migration ledger. It does not
/// modify UCR `PRAGMA user_version` or canonical Group rows. Re-running this is idempotent.
///
/// # Errors
/// Returns an explicit MLS storage error if official migrations cannot be applied.
pub fn initialize_sqlite_storage(connection: &mut Connection) -> Result<(), GroupMlsError> {
    let mut storage = SqliteStorageProvider::<JsonCodec, &mut Connection>::new(connection);
    storage
        .run_migrations()
        .map_err(|_| GroupMlsError::StorageSchema)
}

/// Verifies that the minimum official `OpenMLS` `SQLite` tables required by this phase exist.
///
/// # Errors
/// Returns `StorageSchema` for missing or unreadable `OpenMLS` storage.
pub fn verify_sqlite_storage(connection: &Connection) -> Result<(), GroupMlsError> {
    for name in [
        "openmls_group_data",
        "openmls_signature_keys",
        "openmls_key_packages",
        "openmls_own_leaf_nodes",
        "openmls_sqlite_storage_migrations",
    ] {
        let found = connection
            .query_row(
                "SELECT name FROM sqlite_master WHERE type='table' AND name=?1",
                [name],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| GroupMlsError::StorageSchema)?;
        if found.as_deref() != Some(name) {
            return Err(GroupMlsError::StorageSchema);
        }
    }
    Ok(())
}

#[must_use]
pub fn sqlite_provider(connection: &Connection) -> SqliteMlsProvider<'_> {
    UcrOpenMlsProvider::new(SqliteStorageProvider::<JsonCodec, &Connection>::new(
        connection,
    ))
}

pub const MLS_CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
pub const GROUP_MEDIA_EXPORT_LABEL: &str = "UCR group media epoch v1";
const MLS_STATE_REF_V1_DOMAIN: &[u8] = b"UCR-GROUP-MLS-STATE-REF-V1\0";
const MLS_DEVICE_IDENTITY_V1_DOMAIN: &[u8] = b"UCR-GROUP-MLS-DEVICE-V1\0";
const MLS_CHANGE_REQUEST_V1_DOMAIN: &[u8] = b"UCR-GROUP-MLS-CHANGE-REQUEST-V1\0";
const MAX_MLS_WIRE_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupMlsError {
    OpenMls,
    InvalidWire,
    WireTooLarge,
    DeviceIdentityMismatch,
    GroupStateMismatch,
    MissingPendingCommit,
    MemberNotFound,
    ExportSecret,
    InvalidStateReference,
    StorageSchema,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceKeyPackage {
    pub bytes: Vec<u8>,
    pub signer_public_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlsCommitArtifacts {
    pub commit: Vec<u8>,
    pub welcome: Option<Vec<u8>>,
    pub next_crypto_state: GroupCryptoState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlsDeviceAdmission {
    pub device_id: DeviceId,
    pub key_package: Vec<u8>,
}

/// Canonically authorized Device-level input for one RFC 9420 epoch transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MlsTransitionInput {
    Add(Vec<MlsDeviceAdmission>),
    Remove(Vec<DeviceId>),
    Rekey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtomicMlsGroupChangeResult {
    pub status: DurableRecordStatus,
    pub applied_change: GroupChange,
    pub artifacts: Option<MlsCommitArtifacts>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupMlsStoreError {
    Durable(DurableStoreError),
    Mls(GroupMlsError),
    InvalidBootstrap,
    InvalidChangeMaterial,
    ActorDeviceMismatch,
    TargetDeviceMismatch,
}

impl From<DurableStoreError> for GroupMlsStoreError {
    fn from(error: DurableStoreError) -> Self {
        Self::Durable(error)
    }
}

impl From<GroupMlsError> for GroupMlsStoreError {
    fn from(error: GroupMlsError) -> Self {
        Self::Mls(error)
    }
}

/// Fingerprints the caller-controlled part of one atomic MLS-backed Group request.
///
/// The derived `next_crypto_state` is deliberately excluded because it is produced only by
/// verified `OpenMLS` state. Device admissions are canonicalized by Device ID so retry semantics do
/// not depend on caller ordering.
///
/// # Errors
/// Rejects duplicate Device IDs or a Group change that cannot be canonically fingerprinted.
pub fn mls_change_request_fingerprint(
    change: &GroupChange,
    actor_device_id: &DeviceId,
    added_devices: &[MlsDeviceAdmission],
) -> Result<[u8; 32], GroupMlsStoreError> {
    let mut request = change.clone();
    request.next_crypto_state = None;
    let base = group_change_fingerprint(&request)
        .map_err(|_| GroupMlsStoreError::InvalidChangeMaterial)?;
    let mut admissions = added_devices.to_vec();
    admissions.sort_by(|left, right| {
        left.device_id
            .as_opaque()
            .as_wire_bytes()
            .cmp(right.device_id.as_opaque().as_wire_bytes())
    });
    if admissions
        .windows(2)
        .any(|pair| pair[0].device_id == pair[1].device_id)
    {
        return Err(GroupMlsStoreError::InvalidChangeMaterial);
    }
    let mut hasher = Sha256::new();
    hasher.update(MLS_CHANGE_REQUEST_V1_DOMAIN);
    hasher.update(base);
    let actor_device = actor_device_id.as_opaque().as_wire_bytes();
    let actor_device_len =
        u32::try_from(actor_device.len()).map_err(|_| GroupMlsStoreError::InvalidChangeMaterial)?;
    hasher.update(actor_device_len.to_be_bytes());
    hasher.update(actor_device);
    // Hash admission material without retaining duplicate copies in the digest buffer.
    let admissions_len =
        u32::try_from(admissions.len()).map_err(|_| GroupMlsStoreError::InvalidChangeMaterial)?;
    hasher.update(admissions_len.to_be_bytes());
    for admission in admissions {
        let device_bytes = admission.device_id.as_opaque().as_wire_bytes();
        let device_len = u32::try_from(device_bytes.len())
            .map_err(|_| GroupMlsStoreError::InvalidChangeMaterial)?;
        let package_len = u32::try_from(admission.key_package.len())
            .map_err(|_| GroupMlsStoreError::InvalidChangeMaterial)?;
        hasher.update(device_len.to_be_bytes());
        hasher.update(device_bytes);
        hasher.update(package_len.to_be_bytes());
        hasher.update(Sha256::digest(&admission.key_package));
    }
    Ok(hasher.finalize().into())
}

/// Durable atomic bridge between canonical Group state and endpoint-local RFC 9420 state.
///
/// Implementations must use one durable transaction for the canonical Group mutation and all
/// `OpenMLS` writes that stage/merge the corresponding epoch transition. This trait does not make
/// MLS a second Group owner: membership/roles remain canonical Group state.
pub trait GroupMlsAtomicStore {
    /// Creates endpoint-local public `KeyPackage` material for one already Active canonical Device.
    /// Private MLS signing/HPKE material remains in the implementation-owned protected store.
    ///
    /// # Errors
    /// Returns explicit canonical Device, storage, or MLS provider failures.
    fn create_mls_device_key_package(
        &self,
        scope: &TenantScope,
        device_id: &DeviceId,
    ) -> Result<DeviceKeyPackage, GroupMlsStoreError>;

    /// Creates a new MLS-backed Group. `group_template.crypto_state` must be the explicit blank
    /// bootstrap value (`None`, epoch 0, no state ref); the implementation replaces it with the
    /// real `OpenMLS` epoch-0 state before canonical Group persistence.
    ///
    /// # Errors
    /// Rejects invalid bootstrap/device authority or atomic storage/MLS failures.
    fn create_mls_backed_group(
        &self,
        conversation: &ConversationRecord,
        group_template: &GroupRecord,
        creator: &ScopedPrincipal,
        creator_device_id: &DeviceId,
        creator_key_package: &DeviceKeyPackage,
    ) -> Result<(DurableRecordStatus, GroupRecord), GroupMlsStoreError>;

    /// Applies one security-sensitive canonical Group change and its exact MLS transition atomically.
    /// `requested_change.next_crypto_state` must be absent: it is derived from verified `OpenMLS`
    /// state, never trusted from the caller. `added_devices` is used only by `AddMember`; removals
    /// derive and remove every current MLS Device leaf bound to the removed principal.
    ///
    /// # Errors
    /// Rejects stale/conflicting canonical changes, invalid Device admission, or atomic MLS/storage failures.
    fn apply_mls_backed_group_change(
        &self,
        actor: &ScopedPrincipal,
        actor_device_id: &DeviceId,
        requested_change: &GroupChange,
        added_devices: &[MlsDeviceAdmission],
    ) -> Result<AtomicMlsGroupChangeResult, GroupMlsStoreError>;
}

/// Creates endpoint-local MLS credential/key-package material bound to one canonical UCR Device.
/// Secret signing and HPKE material stay in the provider storage and never appear in this return value.
///
/// # Errors
/// Fails for provider crypto/storage errors or oversized serialized public material.
pub fn create_device_key_package<P: OpenMlsProvider>(
    provider: &P,
    scope: &TenantScope,
    device_id: &DeviceId,
) -> Result<DeviceKeyPackage, GroupMlsError> {
    let identity = device_identity(scope, device_id);
    let credential = BasicCredential::new(identity);
    let signer = SignatureKeyPair::new(MLS_CIPHERSUITE.signature_algorithm())
        .map_err(|_| GroupMlsError::OpenMls)?;
    signer
        .store(provider.storage())
        .map_err(|_| GroupMlsError::OpenMls)?;
    let credential = CredentialWithKey {
        credential: credential.into(),
        signature_key: signer.to_public_vec().into(),
    };
    let package = KeyPackage::builder()
        .build(MLS_CIPHERSUITE, provider, &signer, credential)
        .map_err(|_| GroupMlsError::OpenMls)?;
    let bytes = package
        .key_package()
        .tls_serialize_detached()
        .map_err(|_| GroupMlsError::InvalidWire)?;
    require_wire_bound(&bytes)?;
    Ok(DeviceKeyPackage {
        bytes,
        signer_public_key: signer.to_public_vec(),
    })
}

/// Creates a new RFC 9420 group whose MLS `GroupId` is deterministically bound to UCR scope/group id.
///
/// # Errors
/// Fails when endpoint signing material is unavailable or provider storage/crypto rejects creation.
pub fn create_group<P: OpenMlsProvider>(
    provider: &P,
    scope: &TenantScope,
    group_id: &GroupId,
    creator_device_id: &DeviceId,
    signer_public_key: &[u8],
) -> Result<(MlsGroup, GroupCryptoState), GroupMlsError> {
    let signer = load_signer(provider, signer_public_key)?;
    let credential = CredentialWithKey {
        credential: BasicCredential::new(device_identity(scope, creator_device_id)).into(),
        signature_key: signer.to_public_vec().into(),
    };
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(MLS_CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build();
    let mls_group_id = openmls::prelude::GroupId::from_slice(&mls_group_id(scope, group_id));
    let group = MlsGroup::new_with_group_id(provider, &signer, &config, mls_group_id, credential)
        .map_err(|_| GroupMlsError::OpenMls)?;
    let crypto_state = crypto_state_for_group(scope, group_id, &group)?;
    Ok((group, crypto_state))
}

/// Loads the endpoint-local MLS group bound to the exact UCR scope/group id.
///
/// # Errors
/// Returns an explicit provider storage failure.
pub fn load_group<P: OpenMlsProvider>(
    provider: &P,
    scope: &TenantScope,
    group_id: &GroupId,
) -> Result<Option<MlsGroup>, GroupMlsError> {
    let id = openmls::prelude::GroupId::from_slice(&mls_group_id(scope, group_id));
    MlsGroup::load(provider.storage(), &id).map_err(|_| GroupMlsError::OpenMls)
}

/// Returns the exact UCR crypto-state reference for one loaded MLS group.
///
/// # Errors
/// Rejects invalid state-reference construction.
pub fn current_crypto_state(
    scope: &TenantScope,
    group_id: &GroupId,
    group: &MlsGroup,
) -> Result<GroupCryptoState, GroupMlsError> {
    crypto_state_for_group(scope, group_id, group)
}

/// Validates and deserializes a public `KeyPackage` for the exact UCR Device being added.
///
/// # Errors
/// Rejects malformed, oversized, cryptographically invalid or identity-mismatched packages.
pub fn decode_key_package<P: OpenMlsProvider>(
    provider: &P,
    scope: &TenantScope,
    device_id: &DeviceId,
    bytes: &[u8],
) -> Result<KeyPackage, GroupMlsError> {
    require_wire_bound(bytes)?;
    let input =
        KeyPackageIn::tls_deserialize_exact(bytes).map_err(|_| GroupMlsError::InvalidWire)?;
    let credential = BasicCredential::try_from(input.unverified_credential().credential)
        .map_err(|_| GroupMlsError::DeviceIdentityMismatch)?;
    if credential.identity() != device_identity(scope, device_id) {
        return Err(GroupMlsError::DeviceIdentityMismatch);
    }
    input
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|_| GroupMlsError::OpenMls)
}

/// Stages an MLS Add commit; caller must atomically bind `next_crypto_state` to the UCR membership change before merging it.
///
/// # Errors
/// Rejects invalid `KeyPackage` or provider/group failures.
pub fn stage_add_member<P: OpenMlsProvider>(
    provider: &P,
    group: &mut MlsGroup,
    scope: &TenantScope,
    group_id: &GroupId,
    key_package: &KeyPackage,
) -> Result<MlsCommitArtifacts, GroupMlsError> {
    stage_add_members(
        provider,
        group,
        scope,
        group_id,
        std::slice::from_ref(key_package),
    )
}

/// Stages one MLS Add commit containing all explicitly admitted Devices for a canonical principal.
///
/// # Errors
/// Rejects an empty set, duplicate Device credentials, invalid provider state, or MLS failures.
pub fn stage_add_members<P: OpenMlsProvider>(
    provider: &P,
    group: &mut MlsGroup,
    scope: &TenantScope,
    group_id: &GroupId,
    key_packages: &[KeyPackage],
) -> Result<MlsCommitArtifacts, GroupMlsError> {
    if key_packages.is_empty() {
        return Err(GroupMlsError::MemberNotFound);
    }
    let signer = current_group_signer(provider, group)?;
    let (commit, welcome, _) = group
        .add_members(provider, &signer, key_packages)
        .map_err(|_| GroupMlsError::OpenMls)?;
    pending_artifacts(scope, group_id, group, &commit, Some(&welcome))
}

/// Stages one already-authorized Device-level epoch transition.
///
/// Public `KeyPackage` bytes are still revalidated by `OpenMLS`; removals use exact Device-bound MLS
/// credential identities, while rekey changes no membership.
///
/// # Errors
/// Rejects malformed Device admissions, absent members, or provider/group failures.
pub fn stage_transition<P: OpenMlsProvider>(
    provider: &P,
    group: &mut MlsGroup,
    scope: &TenantScope,
    group_id: &GroupId,
    input: &MlsTransitionInput,
) -> Result<MlsCommitArtifacts, GroupMlsError> {
    match input {
        MlsTransitionInput::Add(admissions) => {
            let packages = admissions
                .iter()
                .map(|admission| {
                    decode_key_package(
                        provider,
                        scope,
                        &admission.device_id,
                        &admission.key_package,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            stage_add_members(provider, group, scope, group_id, &packages)
        }
        MlsTransitionInput::Remove(devices) => {
            stage_remove_members(provider, group, scope, group_id, scope, devices)
        }
        MlsTransitionInput::Rekey => stage_rekey(provider, group, scope, group_id),
    }
}

/// Stages an MLS Remove commit for a member selected by its exact credential identity bytes.
///
/// # Errors
/// Rejects absent members or provider/group failures.
pub fn stage_remove_member<P: OpenMlsProvider>(
    provider: &P,
    group: &mut MlsGroup,
    scope: &TenantScope,
    group_id: &GroupId,
    removed_scope: &TenantScope,
    removed_device_id: &DeviceId,
) -> Result<MlsCommitArtifacts, GroupMlsError> {
    stage_remove_members(
        provider,
        group,
        scope,
        group_id,
        removed_scope,
        std::slice::from_ref(removed_device_id),
    )
}

/// Stages one MLS Remove commit for every explicitly selected Device leaf.
///
/// # Errors
/// Rejects empty, duplicate, absent, cross-scope, or provider-invalid Device membership.
pub fn stage_remove_members<P: OpenMlsProvider>(
    provider: &P,
    group: &mut MlsGroup,
    scope: &TenantScope,
    group_id: &GroupId,
    removed_scope: &TenantScope,
    removed_device_ids: &[DeviceId],
) -> Result<MlsCommitArtifacts, GroupMlsError> {
    if removed_scope != scope || removed_device_ids.is_empty() {
        return Err(GroupMlsError::MemberNotFound);
    }
    let mut indices = Vec::with_capacity(removed_device_ids.len());
    for device_id in removed_device_ids {
        let expected = device_identity(removed_scope, device_id);
        let index = group
            .members()
            .find(|member| member.credential.serialized_content() == expected)
            .map(|member| member.index)
            .ok_or(GroupMlsError::MemberNotFound)?;
        if indices.contains(&index) {
            return Err(GroupMlsError::MemberNotFound);
        }
        indices.push(index);
    }
    let signer = current_group_signer(provider, group)?;
    let (commit, welcome, _) = group
        .remove_members(provider, &signer, &indices)
        .map_err(|_| GroupMlsError::OpenMls)?;
    pending_artifacts(scope, group_id, group, &commit, welcome.as_ref())
}

/// Stages a pure MLS rekey for role/ownership security changes that do not alter membership.
///
/// # Errors
/// Returns provider/group failures.
pub fn stage_rekey<P: OpenMlsProvider>(
    provider: &P,
    group: &mut MlsGroup,
    scope: &TenantScope,
    group_id: &GroupId,
) -> Result<MlsCommitArtifacts, GroupMlsError> {
    let signer = current_group_signer(provider, group)?;
    let bundle = group
        .self_update(
            provider,
            &signer,
            openmls::prelude::LeafNodeParameters::default(),
        )
        .map_err(|_| GroupMlsError::OpenMls)?;
    let welcome = bundle.to_welcome_msg();
    let commit = bundle.into_commit();
    pending_artifacts(scope, group_id, group, &commit, welcome.as_ref())
}

/// Merges the pending commit after the canonical UCR Group transition has accepted the exact next crypto state.
///
/// # Errors
/// Rejects absent/mismatched pending state or merge failures.
pub fn merge_pending<P: OpenMlsProvider>(
    provider: &P,
    group: &mut MlsGroup,
    scope: &TenantScope,
    group_id: &GroupId,
    expected: &GroupCryptoState,
) -> Result<(), GroupMlsError> {
    let pending = group
        .pending_commit()
        .ok_or(GroupMlsError::MissingPendingCommit)?;
    let actual = crypto_state_for_pending(scope, group_id, pending)?;
    if &actual != expected {
        return Err(GroupMlsError::GroupStateMismatch);
    }
    group
        .merge_pending_commit(provider)
        .map_err(|_| GroupMlsError::OpenMls)?;
    let merged = crypto_state_for_group(scope, group_id, group)?;
    if &merged != expected {
        return Err(GroupMlsError::GroupStateMismatch);
    }
    Ok(())
}

/// Joins one endpoint from a Welcome produced by an Add commit.
///
/// # Errors
/// Rejects malformed/oversized Welcome or an unexpected resulting MLS/UCR state reference.
pub fn join_from_welcome<P: OpenMlsProvider>(
    provider: &P,
    scope: &TenantScope,
    group_id: &GroupId,
    welcome_bytes: &[u8],
    expected: &GroupCryptoState,
) -> Result<MlsGroup, GroupMlsError> {
    require_wire_bound(welcome_bytes)?;
    let message = MlsMessageIn::tls_deserialize_exact(welcome_bytes)
        .map_err(|_| GroupMlsError::InvalidWire)?;
    let MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
        return Err(GroupMlsError::InvalidWire);
    };
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(MLS_CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build();
    let group = StagedWelcome::new_from_welcome(provider, config.join_config(), welcome, None)
        .map_err(|_| GroupMlsError::OpenMls)?
        .into_group(provider)
        .map_err(|_| GroupMlsError::OpenMls)?;
    if crypto_state_for_group(scope, group_id, &group)? != *expected {
        return Err(GroupMlsError::GroupStateMismatch);
    }
    Ok(group)
}

/// Processes and merges a serialized MLS commit on a non-originating member.
///
/// # Errors
/// Rejects malformed commits, invalid MLS transitions or an unexpected resulting UCR state reference.
pub fn process_commit<P: OpenMlsProvider>(
    provider: &P,
    group: &mut MlsGroup,
    scope: &TenantScope,
    group_id: &GroupId,
    commit_bytes: &[u8],
    expected: &GroupCryptoState,
) -> Result<(), GroupMlsError> {
    require_wire_bound(commit_bytes)?;
    let message = MlsMessageIn::tls_deserialize_exact(commit_bytes)
        .map_err(|_| GroupMlsError::InvalidWire)?;
    let protocol = message
        .try_into_protocol_message()
        .map_err(|_| GroupMlsError::InvalidWire)?;
    let processed = group
        .process_message(provider, protocol)
        .map_err(|_| GroupMlsError::OpenMls)?;
    let staged = match processed.into_content() {
        openmls::prelude::ProcessedMessageContent::StagedCommitMessage(value) => *value,
        _ => return Err(GroupMlsError::InvalidWire),
    };
    let actual = crypto_state_for_staged(scope, group_id, &staged)?;
    if &actual != expected {
        return Err(GroupMlsError::GroupStateMismatch);
    }
    group
        .merge_staged_commit(provider, staged)
        .map_err(|_| GroupMlsError::OpenMls)?;
    Ok(())
}

/// Exports the endpoint-only media secret for the current verified UCR/MLS state.
///
/// # Errors
/// Rejects state mismatch or MLS exporter failure.
pub fn export_group_media_secret<P: OpenMlsProvider>(
    provider: &P,
    group: &MlsGroup,
    scope: &TenantScope,
    group_id: &GroupId,
    expected: &GroupCryptoState,
) -> Result<GroupMediaEpochSecret, GroupMlsError> {
    if crypto_state_for_group(scope, group_id, group)? != *expected {
        return Err(GroupMlsError::GroupStateMismatch);
    }
    let context = state_ref_bytes(expected)?;
    let secret = group
        .export_secret(provider.crypto(), GROUP_MEDIA_EXPORT_LABEL, &context, 32)
        .map_err(|_| GroupMlsError::ExportSecret)?;
    let bytes: [u8; 32] = secret.try_into().map_err(|_| GroupMlsError::ExportSecret)?;
    Ok(GroupMediaEpochSecret::from_exporter_bytes(bytes))
}

#[must_use]
pub fn mls_group_id(scope: &TenantScope, group_id: &GroupId) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"UCR-MLS-GROUP-ID-V1\0");
    push_bytes(&mut bytes, scope.tenant_id.as_opaque().as_wire_bytes());
    match &scope.namespace_id {
        Some(value) => {
            bytes.push(1);
            push_bytes(&mut bytes, value.as_opaque().as_wire_bytes());
        }
        None => bytes.push(0),
    }
    push_bytes(&mut bytes, group_id.as_opaque().as_wire_bytes());
    Sha256::digest(bytes).to_vec()
}

fn pending_artifacts(
    scope: &TenantScope,
    group_id: &GroupId,
    group: &MlsGroup,
    commit: &MlsMessageOut,
    welcome: Option<&MlsMessageOut>,
) -> Result<MlsCommitArtifacts, GroupMlsError> {
    let pending = group
        .pending_commit()
        .ok_or(GroupMlsError::MissingPendingCommit)?;
    let next_crypto_state = crypto_state_for_pending(scope, group_id, pending)?;
    let commit = commit
        .tls_serialize_detached()
        .map_err(|_| GroupMlsError::InvalidWire)?;
    require_wire_bound(&commit)?;
    let welcome = welcome
        .map(|value| {
            let bytes = value
                .tls_serialize_detached()
                .map_err(|_| GroupMlsError::InvalidWire)?;
            require_wire_bound(&bytes)?;
            Ok(bytes)
        })
        .transpose()?;
    Ok(MlsCommitArtifacts {
        commit,
        welcome,
        next_crypto_state,
    })
}

fn crypto_state_for_group(
    scope: &TenantScope,
    group_id: &GroupId,
    group: &MlsGroup,
) -> Result<GroupCryptoState, GroupMlsError> {
    crypto_state_from_authenticator(
        scope,
        group_id,
        group.epoch().as_u64(),
        group.epoch_authenticator().as_slice(),
    )
}

fn crypto_state_for_pending(
    scope: &TenantScope,
    group_id: &GroupId,
    pending: &openmls::prelude::StagedCommit,
) -> Result<GroupCryptoState, GroupMlsError> {
    let authenticator = pending
        .epoch_authenticator()
        .ok_or(GroupMlsError::GroupStateMismatch)?;
    crypto_state_from_authenticator(
        scope,
        group_id,
        pending.epoch().as_u64(),
        authenticator.as_slice(),
    )
}

fn crypto_state_for_staged(
    scope: &TenantScope,
    group_id: &GroupId,
    staged: &openmls::prelude::StagedCommit,
) -> Result<GroupCryptoState, GroupMlsError> {
    let authenticator = staged
        .epoch_authenticator()
        .ok_or(GroupMlsError::GroupStateMismatch)?;
    crypto_state_from_authenticator(
        scope,
        group_id,
        staged.epoch().as_u64(),
        authenticator.as_slice(),
    )
}

fn crypto_state_from_authenticator(
    scope: &TenantScope,
    group_id: &GroupId,
    epoch: u64,
    authenticator: &[u8],
) -> Result<GroupCryptoState, GroupMlsError> {
    let mut hasher = Sha256::new();
    hasher.update(MLS_STATE_REF_V1_DOMAIN);
    hasher.update(mls_group_id(scope, group_id));
    hasher.update(epoch.to_be_bytes());
    hasher.update(authenticator);
    let digest = hasher.finalize();
    let mut value = String::with_capacity(64);
    for byte in digest {
        write!(&mut value, "{byte:02x}").map_err(|_| GroupMlsError::InvalidStateReference)?;
    }
    let state_ref = OpaqueId::new(value).map_err(|_| GroupMlsError::InvalidStateReference)?;
    Ok(GroupCryptoState {
        capability_id: Some(GROUP_MLS_CAPABILITY.to_owned()),
        epoch,
        state_ref: Some(state_ref),
    })
}

fn current_group_signer<P: OpenMlsProvider>(
    provider: &P,
    group: &MlsGroup,
) -> Result<SignatureKeyPair, GroupMlsError> {
    let public = group
        .own_leaf_node()
        .ok_or(GroupMlsError::OpenMls)?
        .signature_key()
        .as_slice();
    load_signer(provider, public)
}

fn load_signer<P: OpenMlsProvider>(
    provider: &P,
    public_key: &[u8],
) -> Result<SignatureKeyPair, GroupMlsError> {
    SignatureKeyPair::read(
        provider.storage(),
        public_key,
        MLS_CIPHERSUITE.signature_algorithm(),
    )
    .ok_or(GroupMlsError::OpenMls)
}

/// Returns every canonical UCR Device leaf currently present in this MLS group.
///
/// # Errors
/// Rejects foreign or malformed credentials rather than treating them as UCR Devices.
pub fn member_device_ids(
    group: &MlsGroup,
    scope: &TenantScope,
) -> Result<Vec<DeviceId>, GroupMlsError> {
    group
        .members()
        .map(|member| parse_device_identity(scope, member.credential.serialized_content()))
        .collect()
}

/// Returns the exact canonical UCR Device represented by this endpoint's own MLS leaf.
///
/// # Errors
/// Rejects absent or malformed own-leaf credentials.
pub fn own_device_id(group: &MlsGroup, scope: &TenantScope) -> Result<DeviceId, GroupMlsError> {
    let leaf = group.own_leaf_node().ok_or(GroupMlsError::MemberNotFound)?;
    let credential = BasicCredential::try_from(leaf.credential().clone())
        .map_err(|_| GroupMlsError::DeviceIdentityMismatch)?;
    parse_device_identity(scope, credential.identity())
}

fn parse_device_identity(scope: &TenantScope, bytes: &[u8]) -> Result<DeviceId, GroupMlsError> {
    let expected_prefix = MLS_DEVICE_IDENTITY_V1_DOMAIN;
    if !bytes.starts_with(expected_prefix) {
        return Err(GroupMlsError::DeviceIdentityMismatch);
    }
    let mut cursor = &bytes[expected_prefix.len()..];
    let tenant = take_len_prefixed(&mut cursor)?;
    if tenant != scope.tenant_id.as_opaque().as_wire_bytes() {
        return Err(GroupMlsError::DeviceIdentityMismatch);
    }
    let marker = *cursor
        .first()
        .ok_or(GroupMlsError::DeviceIdentityMismatch)?;
    cursor = &cursor[1..];
    match (&scope.namespace_id, marker) {
        (None, 0) => {}
        (Some(namespace), 1) => {
            if take_len_prefixed(&mut cursor)? != namespace.as_opaque().as_wire_bytes() {
                return Err(GroupMlsError::DeviceIdentityMismatch);
            }
        }
        _ => return Err(GroupMlsError::DeviceIdentityMismatch),
    }
    let device = take_len_prefixed(&mut cursor)?;
    if !cursor.is_empty() {
        return Err(GroupMlsError::DeviceIdentityMismatch);
    }
    let opaque =
        OpaqueId::from_wire_bytes(device).map_err(|_| GroupMlsError::DeviceIdentityMismatch)?;
    Ok(DeviceId::from_opaque(opaque))
}

fn take_len_prefixed<'a>(cursor: &mut &'a [u8]) -> Result<&'a [u8], GroupMlsError> {
    let len_bytes: [u8; 4] = cursor
        .get(..4)
        .ok_or(GroupMlsError::DeviceIdentityMismatch)?
        .try_into()
        .map_err(|_| GroupMlsError::DeviceIdentityMismatch)?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    let value = cursor
        .get(4..4 + len)
        .ok_or(GroupMlsError::DeviceIdentityMismatch)?;
    *cursor = cursor
        .get(4 + len..)
        .ok_or(GroupMlsError::DeviceIdentityMismatch)?;
    Ok(value)
}

fn device_identity(scope: &TenantScope, device_id: &DeviceId) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(MLS_DEVICE_IDENTITY_V1_DOMAIN);
    push_bytes(&mut bytes, scope.tenant_id.as_opaque().as_wire_bytes());
    match &scope.namespace_id {
        Some(value) => {
            bytes.push(1);
            push_bytes(&mut bytes, value.as_opaque().as_wire_bytes());
        }
        None => bytes.push(0),
    }
    push_bytes(&mut bytes, device_id.as_opaque().as_wire_bytes());
    bytes
}

fn state_ref_bytes(state: &GroupCryptoState) -> Result<Vec<u8>, GroupMlsError> {
    if state.capability_id.as_deref() != Some(GROUP_MLS_CAPABILITY) {
        return Err(GroupMlsError::GroupStateMismatch);
    }
    state
        .state_ref
        .as_ref()
        .map(|value| value.as_wire_bytes().to_vec())
        .ok_or(GroupMlsError::InvalidStateReference)
}

fn require_wire_bound(bytes: &[u8]) -> Result<(), GroupMlsError> {
    if bytes.is_empty() {
        Err(GroupMlsError::InvalidWire)
    } else if bytes.len() > MAX_MLS_WIRE_BYTES {
        Err(GroupMlsError::WireTooLarge)
    } else {
        Ok(())
    }
}

fn push_bytes(target: &mut Vec<u8>, value: &[u8]) {
    let len = u32::try_from(value.len()).expect("canonical MLS identifier input fits u32");
    target.extend_from_slice(&len.to_be_bytes());
    target.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use openmls_rust_crypto::OpenMlsRustCrypto;
    use ucr_model::{
        CallId, CryptoSuite, GroupId, GroupMediaE2eeContext, MediaKind, OpaqueId, PrincipalId,
        PrincipalKind, PrincipalRef, TenantId, TenantScope,
    };

    use super::*;

    struct ThreeMemberMls {
        scope: TenantScope,
        group_id: GroupId,
        alice_provider: OpenMlsRustCrypto,
        bob_provider: OpenMlsRustCrypto,
        charlie_provider: OpenMlsRustCrypto,
        alice_group: MlsGroup,
        bob_group: MlsGroup,
        charlie_group: MlsGroup,
        state: GroupCryptoState,
    }

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("id")
    }

    fn scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(oid("tenant-mls")),
            namespace_id: None,
        }
    }

    fn device(value: &str) -> DeviceId {
        DeviceId::from_opaque(oid(value))
    }

    fn three_member_group() -> ThreeMemberMls {
        let scope = scope();
        let group_id = GroupId::from_opaque(oid("group-mls"));
        let alice_provider = OpenMlsRustCrypto::default();
        let bob_provider = OpenMlsRustCrypto::default();
        let charlie_provider = OpenMlsRustCrypto::default();
        let alice = create_device_key_package(&alice_provider, &scope, &device("alice")).unwrap();
        let bob = create_device_key_package(&bob_provider, &scope, &device("bob")).unwrap();
        let charlie =
            create_device_key_package(&charlie_provider, &scope, &device("charlie")).unwrap();
        let (mut alice_group, state0) = create_group(
            &alice_provider,
            &scope,
            &group_id,
            &device("alice"),
            &alice.signer_public_key,
        )
        .unwrap();
        assert_eq!(state0.epoch, 0);

        let bob_package =
            decode_key_package(&alice_provider, &scope, &device("bob"), &bob.bytes).unwrap();
        let add_bob = stage_add_member(
            &alice_provider,
            &mut alice_group,
            &scope,
            &group_id,
            &bob_package,
        )
        .unwrap();
        merge_pending(
            &alice_provider,
            &mut alice_group,
            &scope,
            &group_id,
            &add_bob.next_crypto_state,
        )
        .unwrap();
        let mut bob_group = join_from_welcome(
            &bob_provider,
            &scope,
            &group_id,
            add_bob.welcome.as_deref().unwrap(),
            &add_bob.next_crypto_state,
        )
        .unwrap();

        let charlie_package =
            decode_key_package(&alice_provider, &scope, &device("charlie"), &charlie.bytes)
                .unwrap();
        let add_charlie = stage_add_member(
            &alice_provider,
            &mut alice_group,
            &scope,
            &group_id,
            &charlie_package,
        )
        .unwrap();
        merge_pending(
            &alice_provider,
            &mut alice_group,
            &scope,
            &group_id,
            &add_charlie.next_crypto_state,
        )
        .unwrap();
        process_commit(
            &bob_provider,
            &mut bob_group,
            &scope,
            &group_id,
            &add_charlie.commit,
            &add_charlie.next_crypto_state,
        )
        .unwrap();
        let charlie_group = join_from_welcome(
            &charlie_provider,
            &scope,
            &group_id,
            add_charlie.welcome.as_deref().unwrap(),
            &add_charlie.next_crypto_state,
        )
        .unwrap();
        ThreeMemberMls {
            scope,
            group_id,
            alice_provider,
            bob_provider,
            charlie_provider,
            alice_group,
            bob_group,
            charlie_group,
            state: add_charlie.next_crypto_state,
        }
    }

    fn context(fixture: &ThreeMemberMls, state: &GroupCryptoState) -> GroupMediaE2eeContext {
        GroupMediaE2eeContext {
            scope: fixture.scope.clone(),
            call_id: CallId::from_opaque(oid("call")),
            group_id: fixture.group_id.clone(),
            negotiation_ref: oid("neg"),
            negotiation_generation: 1,
            crypto_epoch: state.epoch,
            crypto_state_ref: state.state_ref.clone().unwrap(),
            crypto_suite: CryptoSuite::UcrV1,
        }
    }

    fn source() -> PrincipalRef {
        PrincipalRef {
            principal_id: PrincipalId::from_opaque(oid("alice")),
            kind: PrincipalKind::Device,
        }
    }

    fn member_traffic_key(
        provider: &OpenMlsRustCrypto,
        group: &MlsGroup,
        fixture: &ThreeMemberMls,
        state: &GroupCryptoState,
    ) -> ucr_crypto::TrafficKey {
        let secret =
            export_group_media_secret(provider, group, &fixture.scope, &fixture.group_id, state)
                .unwrap();
        ucr_crypto::derive_group_media_traffic_key(
            &secret,
            &context(fixture, state),
            &source(),
            &device("alice"),
            &oid("stream"),
            MediaKind::Video,
        )
        .unwrap()
    }

    fn assert_pre_removal_shared_key(fixture: &ThreeMemberMls) -> ucr_crypto::TrafficKey {
        let alice = member_traffic_key(
            &fixture.alice_provider,
            &fixture.alice_group,
            fixture,
            &fixture.state,
        );
        let bob = member_traffic_key(
            &fixture.bob_provider,
            &fixture.bob_group,
            fixture,
            &fixture.state,
        );
        let charlie = member_traffic_key(
            &fixture.charlie_provider,
            &fixture.charlie_group,
            fixture,
            &fixture.state,
        );
        let ciphertext = alice.encrypt(b"shared", b"epoch-before").unwrap();
        assert_eq!(
            bob.decrypt(&ciphertext, b"epoch-before").unwrap(),
            b"shared"
        );
        assert_eq!(
            charlie.decrypt(&ciphertext, b"epoch-before").unwrap(),
            b"shared"
        );
        charlie
    }

    fn remove_charlie(fixture: &mut ThreeMemberMls) -> GroupCryptoState {
        let remove = stage_remove_member(
            &fixture.alice_provider,
            &mut fixture.alice_group,
            &fixture.scope,
            &fixture.group_id,
            &fixture.scope,
            &device("charlie"),
        )
        .unwrap();
        merge_pending(
            &fixture.alice_provider,
            &mut fixture.alice_group,
            &fixture.scope,
            &fixture.group_id,
            &remove.next_crypto_state,
        )
        .unwrap();
        process_commit(
            &fixture.bob_provider,
            &mut fixture.bob_group,
            &fixture.scope,
            &fixture.group_id,
            &remove.commit,
            &remove.next_crypto_state,
        )
        .unwrap();
        assert!(
            process_commit(
                &fixture.charlie_provider,
                &mut fixture.charlie_group,
                &fixture.scope,
                &fixture.group_id,
                &remove.commit,
                &remove.next_crypto_state,
            )
            .is_err()
        );
        remove.next_crypto_state
    }

    fn assert_removed_member_isolated(
        fixture: &ThreeMemberMls,
        state: &GroupCryptoState,
        old_charlie_key: &ucr_crypto::TrafficKey,
    ) {
        let alice = member_traffic_key(
            &fixture.alice_provider,
            &fixture.alice_group,
            fixture,
            state,
        );
        let bob = member_traffic_key(&fixture.bob_provider, &fixture.bob_group, fixture, state);
        let ciphertext = alice.encrypt(b"after-removal", b"epoch-after").unwrap();
        assert_eq!(
            bob.decrypt(&ciphertext, b"epoch-after").unwrap(),
            b"after-removal"
        );
        assert!(
            old_charlie_key
                .decrypt(&ciphertext, b"epoch-after")
                .is_err()
        );
    }

    #[test]
    fn real_mls_add_and_remove_rotates_exporter_and_isolates_removed_member() {
        let mut fixture = three_member_group();
        let charlie_old_key = assert_pre_removal_shared_key(&fixture);
        let next_state = remove_charlie(&mut fixture);
        assert!(next_state.epoch > fixture.state.epoch);
        assert_removed_member_isolated(&fixture, &next_state, &charlie_old_key);
    }
}
