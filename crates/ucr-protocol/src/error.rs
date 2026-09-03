use ucr_model::{OpaqueIdError, ProtocolExtension};

use crate::{
    AcknowledgementError, AddressingError, AuthorizationError, CapabilityError, CommandError,
    ConversationError, CryptoContractError, CryptoNegotiationError, DeliveryError, EventError,
    ExtensionError, FrameError, HandshakeError, IntentError, MessageError, NegotiationResultError,
    ProvenanceError, ReceiptError, RecoveryError, ScopeError, SyncError, VersionNegotiationError,
    canonical_protocol_extensions,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum CanonicalErrorCode {
    InvalidArgument = 1,
    MalformedFrame = 2,
    UnsupportedProtocolVersion = 3,
    DowngradeRejected = 4,
    UnsupportedCriticalExtension = 5,
    CapabilityMismatch = 6,
    Unauthenticated = 7,
    PermissionDenied = 8,
    PolicyDenied = 9,
    RateLimited = 10,
    ResourceExhausted = 11,
    DeadlineExceeded = 12,
    Cancelled = 13,
    TemporarilyUnavailable = 14,
    IntegrityFailure = 15,
    Conflict = 16,
    NotFound = 17,
    Internal = 18,
}

impl CanonicalErrorCode {
    #[must_use]
    pub const fn retryable_by_default(self) -> bool {
        matches!(self, Self::RateLimited | Self::TemporarilyUnavailable)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorEnvelope {
    /// Raw protobuf enum value. Unknown future non-zero values remain failures.
    pub code: i32,
    pub retryable: bool,
    pub retry_after_ms: Option<u64>,
    pub diagnostic_domain: String,
    pub extensions: Vec<ProtocolExtension>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorEnvelopeError {
    UnspecifiedCode,
    InvalidExtension,
    DuplicateExtension,
    TooManyExtensions,
    ExtensionPayloadTooLarge,
}

/// Validates the public error envelope without collapsing unknown future codes.
///
/// # Errors
/// Rejects the protobuf UNSPECIFIED value and malformed/over-budget extensions.
pub fn validate_error_envelope(envelope: &ErrorEnvelope) -> Result<(), ErrorEnvelopeError> {
    if envelope.code == 0 {
        return Err(ErrorEnvelopeError::UnspecifiedCode);
    }
    canonical_protocol_extensions(&envelope.extensions).map_err(map_error_envelope_extension)?;
    Ok(())
}

/// Returns a deterministic wire representation while preserving the raw error code.
///
/// # Errors
/// Returns the same fail-closed errors as [`validate_error_envelope`].
pub fn canonical_error_envelope(
    envelope: &ErrorEnvelope,
) -> Result<ErrorEnvelope, ErrorEnvelopeError> {
    validate_error_envelope(envelope)?;
    let mut canonical = envelope.clone();
    canonical.extensions = canonical_protocol_extensions(&envelope.extensions)
        .map_err(map_error_envelope_extension)?;
    Ok(canonical)
}

const fn map_error_envelope_extension(error: ExtensionError) -> ErrorEnvelopeError {
    match error {
        ExtensionError::InvalidNamespace | ExtensionError::UnsupportedCritical => {
            ErrorEnvelopeError::InvalidExtension
        }
        ExtensionError::DuplicateExtension => ErrorEnvelopeError::DuplicateExtension,
        ExtensionError::TooManyExtensions => ErrorEnvelopeError::TooManyExtensions,
        ExtensionError::PayloadTooLarge => ErrorEnvelopeError::ExtensionPayloadTooLarge,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanonicalError {
    pub code: CanonicalErrorCode,
    pub retryable: bool,
    pub retry_after_ms: Option<u64>,
}

impl CanonicalError {
    #[must_use]
    pub const fn new(code: CanonicalErrorCode) -> Self {
        Self {
            code,
            retryable: code.retryable_by_default(),
            retry_after_ms: None,
        }
    }

    #[must_use]
    pub const fn with_retry_after(mut self, retry_after_ms: u64) -> Self {
        self.retryable = true;
        self.retry_after_ms = Some(retry_after_ms);
        self
    }
}

/// Builds a public base error envelope from one known canonical error.
///
/// Response extensions are not inferred automatically.
#[must_use]
pub fn error_envelope_from_canonical(
    error: CanonicalError,
    diagnostic_domain: impl Into<String>,
) -> ErrorEnvelope {
    ErrorEnvelope {
        code: i32::from(error.code as u16),
        retryable: error.retryable,
        retry_after_ms: error.retry_after_ms,
        diagnostic_domain: diagnostic_domain.into(),
        extensions: Vec::new(),
    }
}

impl From<OpaqueIdError> for CanonicalError {
    fn from(error: OpaqueIdError) -> Self {
        let code = match error {
            OpaqueIdError::TooLong => CanonicalErrorCode::ResourceExhausted,
            OpaqueIdError::Empty | OpaqueIdError::InvalidUtf8 => {
                CanonicalErrorCode::InvalidArgument
            }
        };
        Self::new(code)
    }
}

impl From<ErrorEnvelopeError> for CanonicalError {
    fn from(error: ErrorEnvelopeError) -> Self {
        let code = match error {
            ErrorEnvelopeError::TooManyExtensions
            | ErrorEnvelopeError::ExtensionPayloadTooLarge => CanonicalErrorCode::ResourceExhausted,
            ErrorEnvelopeError::UnspecifiedCode
            | ErrorEnvelopeError::InvalidExtension
            | ErrorEnvelopeError::DuplicateExtension => CanonicalErrorCode::InvalidArgument,
        };
        Self::new(code)
    }
}

impl From<IntentError> for CanonicalError {
    fn from(error: IntentError) -> Self {
        let code = match error {
            IntentError::PayloadTooLarge
            | IntentError::TooManyTransportConstraints
            | IntentError::TooManyExtensions
            | IntentError::ExtensionPayloadTooLarge => CanonicalErrorCode::ResourceExhausted,
            IntentError::InvalidTransportCapability
            | IntentError::DuplicateTransportCapability
            | IntentError::ConflictingTransportCapability
            | IntentError::InvalidExtension
            | IntentError::DuplicateExtension => CanonicalErrorCode::InvalidArgument,
        };
        Self::new(code)
    }
}

impl From<FrameError> for CanonicalError {
    fn from(error: FrameError) -> Self {
        let code = match error {
            FrameError::UnsupportedFramingVersion => CanonicalErrorCode::UnsupportedProtocolVersion,
            FrameError::PayloadTooLarge | FrameError::LengthOverflow => {
                CanonicalErrorCode::ResourceExhausted
            }
            FrameError::TruncatedHeader
            | FrameError::BadMagic
            | FrameError::UnknownKind
            | FrameError::UnsupportedFlags
            | FrameError::TruncatedPayload => CanonicalErrorCode::MalformedFrame,
        };
        Self::new(code)
    }
}

impl From<VersionNegotiationError> for CanonicalError {
    fn from(error: VersionNegotiationError) -> Self {
        let code = match error {
            VersionNegotiationError::BelowLocalMinimum => CanonicalErrorCode::DowngradeRejected,
            VersionNegotiationError::NoMutualVersion => {
                CanonicalErrorCode::UnsupportedProtocolVersion
            }
            VersionNegotiationError::InvalidRange | VersionNegotiationError::EmptyAdvertisement => {
                CanonicalErrorCode::InvalidArgument
            }
        };
        Self::new(code)
    }
}

impl From<CryptoContractError> for CanonicalError {
    fn from(_error: CryptoContractError) -> Self {
        Self::new(CanonicalErrorCode::InvalidArgument)
    }
}

impl From<CryptoNegotiationError> for CanonicalError {
    fn from(error: CryptoNegotiationError) -> Self {
        let code = match error {
            CryptoNegotiationError::PolicyRejectedMutualSuite => {
                CanonicalErrorCode::DowngradeRejected
            }
            CryptoNegotiationError::NoMutualSuite => CanonicalErrorCode::CapabilityMismatch,
            CryptoNegotiationError::EmptyAdvertisement
            | CryptoNegotiationError::DuplicateAdvertisement
            | CryptoNegotiationError::DuplicatePolicySuite => CanonicalErrorCode::InvalidArgument,
        };
        Self::new(code)
    }
}

impl From<NegotiationResultError> for CanonicalError {
    fn from(error: NegotiationResultError) -> Self {
        match error {
            NegotiationResultError::InvalidVersion
            | NegotiationResultError::DeprecatedTranscriptBindingNotEmpty => {
                Self::new(CanonicalErrorCode::InvalidArgument)
            }
            NegotiationResultError::Capability(inner) => Self::from(inner),
            NegotiationResultError::Extension(inner) => Self::from(inner),
        }
    }
}

impl From<HandshakeError> for CanonicalError {
    fn from(error: HandshakeError) -> Self {
        match error {
            HandshakeError::Version(inner) => Self::from(inner),
            HandshakeError::Crypto(inner) => Self::from(inner),
            HandshakeError::Capability(inner) => Self::from(inner),
            HandshakeError::Extension(inner) => Self::from(inner),
            HandshakeError::InvalidNonce => Self::new(CanonicalErrorCode::InvalidArgument),
            HandshakeError::NonceCollision => Self::new(CanonicalErrorCode::IntegrityFailure),
        }
    }
}

impl From<ExtensionError> for CanonicalError {
    fn from(error: ExtensionError) -> Self {
        let code = match error {
            ExtensionError::InvalidNamespace | ExtensionError::DuplicateExtension => {
                CanonicalErrorCode::InvalidArgument
            }
            ExtensionError::UnsupportedCritical => CanonicalErrorCode::UnsupportedCriticalExtension,
            ExtensionError::TooManyExtensions | ExtensionError::PayloadTooLarge => {
                CanonicalErrorCode::ResourceExhausted
            }
        };
        Self::new(code)
    }
}

impl From<ConversationError> for CanonicalError {
    fn from(_error: ConversationError) -> Self {
        Self::new(CanonicalErrorCode::InvalidArgument)
    }
}

impl From<MessageError> for CanonicalError {
    fn from(error: MessageError) -> Self {
        let code = match error {
            MessageError::ContentTooLarge
            | MessageError::TooManyAttachments
            | MessageError::TooManyRelations
            | MessageError::CryptoMetadataTooLarge
            | MessageError::TooManyExternalMappings
            | MessageError::ExternalMessageIdTooLarge
            | MessageError::TooManyExtensions
            | MessageError::ExtensionPayloadTooLarge => CanonicalErrorCode::ResourceExhausted,
            _ => CanonicalErrorCode::InvalidArgument,
        };
        Self::new(code)
    }
}

impl From<DeliveryError> for CanonicalError {
    fn from(error: DeliveryError) -> Self {
        let code = match error {
            DeliveryError::EvidenceRegression => CanonicalErrorCode::Conflict,
            DeliveryError::InvalidInitialState
            | DeliveryError::IllegalTransition
            | DeliveryError::ScopeMismatch
            | DeliveryError::MessageMismatch
            | DeliveryError::DeliveryMismatch
            | DeliveryError::EvidenceDoesNotProveState => CanonicalErrorCode::InvalidArgument,
        };
        Self::new(code)
    }
}

impl From<SyncError> for CanonicalError {
    fn from(error: SyncError) -> Self {
        let code = match error {
            SyncError::CheckpointBindingMismatch => CanonicalErrorCode::PermissionDenied,
            SyncError::TooManyConversations | SyncError::ResumeTokenTooLarge => {
                CanonicalErrorCode::ResourceExhausted
            }
            SyncError::IllegalTransition
            | SyncError::InvalidCheckpointGeneration
            | SyncError::AppliedItemsRegression => CanonicalErrorCode::Conflict,
            SyncError::SameEndpoint
            | SyncError::InvalidInitialState
            | SyncError::FullSelectionHasConversations
            | SyncError::PartialSelectionEmpty
            | SyncError::DuplicateConversation
            | SyncError::CheckpointRequiresActiveSession
            | SyncError::EmptyResumeToken => CanonicalErrorCode::InvalidArgument,
        };
        Self::new(code)
    }
}

impl From<ProvenanceError> for CanonicalError {
    fn from(_error: ProvenanceError) -> Self {
        Self::new(CanonicalErrorCode::InvalidArgument)
    }
}

impl From<RecoveryError> for CanonicalError {
    fn from(error: RecoveryError) -> Self {
        let code = match error {
            RecoveryError::MethodNotAllowed
            | RecoveryError::PlanMismatch
            | RecoveryError::ScopeMismatch
            | RecoveryError::IdentityMismatch => CanonicalErrorCode::PermissionDenied,
            RecoveryError::EncodingTooLarge | RecoveryError::TooManyAuthorities => {
                CanonicalErrorCode::ResourceExhausted
            }
            RecoveryError::NoAuthorities
            | RecoveryError::DuplicateAuthority
            | RecoveryError::UnsafeRecoveredDeviceState
            | RecoveryError::HistoricalAccessNotExplicit
            | RecoveryError::TrustModelAuthorityMismatch => CanonicalErrorCode::InvalidArgument,
        };
        Self::new(code)
    }
}

impl From<ScopeError> for CanonicalError {
    fn from(_error: ScopeError) -> Self {
        // Scope mismatches are authorization failures. Do not expose whether a
        // cross-tenant/cross-namespace resource actually exists.
        Self::new(CanonicalErrorCode::PermissionDenied)
    }
}

impl From<AuthorizationError> for CanonicalError {
    fn from(error: AuthorizationError) -> Self {
        let code = match error {
            AuthorizationError::InvalidPermission => CanonicalErrorCode::InvalidArgument,
            AuthorizationError::InvalidGrant => CanonicalErrorCode::Internal,
            AuthorizationError::PermissionDenied => CanonicalErrorCode::PermissionDenied,
        };
        Self::new(code)
    }
}

impl From<CommandError> for CanonicalError {
    fn from(error: CommandError) -> Self {
        let code = match error {
            CommandError::IdempotencyConflict => CanonicalErrorCode::Conflict,
            CommandError::InvalidCommandType
            | CommandError::MissingIdempotencyKey
            | CommandError::EmptyIdempotencyKey
            | CommandError::IdempotencyKeyTooLong
            | CommandError::InvalidSchemaVersion
            | CommandError::InvalidExtension
            | CommandError::DuplicateExtension => CanonicalErrorCode::InvalidArgument,
            CommandError::PayloadTooLarge
            | CommandError::TooManyExtensions
            | CommandError::ExtensionPayloadTooLarge => CanonicalErrorCode::ResourceExhausted,
        };
        Self::new(code)
    }
}

impl From<ReceiptError> for CanonicalError {
    fn from(error: ReceiptError) -> Self {
        let code = match error {
            ReceiptError::TooManyExtensions | ReceiptError::ExtensionPayloadTooLarge => {
                CanonicalErrorCode::ResourceExhausted
            }
            ReceiptError::AcceptedHasOriginal
            | ReceiptError::DuplicateMissingOriginal
            | ReceiptError::InvalidSchemaVersion
            | ReceiptError::InvalidExtension
            | ReceiptError::DuplicateExtension => CanonicalErrorCode::InvalidArgument,
        };
        Self::new(code)
    }
}

impl From<AcknowledgementError> for CanonicalError {
    fn from(error: AcknowledgementError) -> Self {
        let code = match error {
            AcknowledgementError::TooManyExtensions
            | AcknowledgementError::ExtensionPayloadTooLarge => {
                CanonicalErrorCode::ResourceExhausted
            }
            AcknowledgementError::InvalidSchemaVersion
            | AcknowledgementError::InvalidExtension
            | AcknowledgementError::DuplicateExtension => CanonicalErrorCode::InvalidArgument,
        };
        Self::new(code)
    }
}

impl From<EventError> for CanonicalError {
    fn from(error: EventError) -> Self {
        let code = match error {
            EventError::InvalidEventType
            | EventError::InvalidSchemaVersion
            | EventError::InvalidExtension
            | EventError::DuplicateExtension => CanonicalErrorCode::InvalidArgument,
            EventError::PayloadTooLarge
            | EventError::IntegrityMetadataTooLarge
            | EventError::TooManyExtensions
            | EventError::ExtensionPayloadTooLarge => CanonicalErrorCode::ResourceExhausted,
        };
        Self::new(code)
    }
}

impl From<CapabilityError> for CanonicalError {
    fn from(error: CapabilityError) -> Self {
        let code = match error {
            CapabilityError::InvalidIdentifier
            | CapabilityError::DuplicateAdvertisement
            | CapabilityError::InvalidRequirement
            | CapabilityError::InvalidExtension
            | CapabilityError::DuplicateExtension => CanonicalErrorCode::InvalidArgument,
            CapabilityError::TooManyExtensions | CapabilityError::ExtensionPayloadTooLarge => {
                CanonicalErrorCode::ResourceExhausted
            }
            CapabilityError::CriticalExtensionRequiresExplicitNegotiation => {
                CanonicalErrorCode::UnsupportedCriticalExtension
            }
            CapabilityError::MissingRequired | CapabilityError::RequiredBelowMaturity => {
                CanonicalErrorCode::CapabilityMismatch
            }
        };
        Self::new(code)
    }
}

impl From<AddressingError> for CanonicalError {
    fn from(error: AddressingError) -> Self {
        let code = match error {
            AddressingError::AddressValueTooLong
            | AddressingError::TooManyAddresses
            | AddressingError::TooManyCapabilities
            | AddressingError::CapabilityExtensionBudgetExceeded
            | AddressingError::ExternalEntityIdTooLong => CanonicalErrorCode::ResourceExhausted,
            AddressingError::InvalidScheme
            | AddressingError::EmptyAddressValue
            | AddressingError::DuplicateAddress
            | AddressingError::DuplicateCapability
            | AddressingError::InvalidCapability
            | AddressingError::InvalidCapabilityExtension
            | AddressingError::DeviceEndpointMissingDevice
            | AddressingError::DeviceEndpointMissingIdentity
            | AddressingError::DeviceBindingWithoutIdentity
            | AddressingError::InvalidExternalNamespace
            | AddressingError::EmptyExternalEntityId => CanonicalErrorCode::InvalidArgument,
        };
        Self::new(code)
    }
}

#[cfg(test)]
mod tests {
    use super::{CanonicalError, CanonicalErrorCode};
    use crate::{
        AcknowledgementError, AddressingError, AuthorizationError, CapabilityError, CommandError,
        ConversationError, CryptoContractError, DeliveryError, MessageError,
        NegotiationResultError, ProvenanceError, ReceiptError, RecoveryError, ScopeError,
        SyncError,
    };

    #[test]
    fn opaque_id_wire_decode_failures_keep_validation_and_budget_categories_stable() {
        use ucr_model::OpaqueIdError;

        assert_eq!(
            CanonicalError::from(OpaqueIdError::Empty).code,
            CanonicalErrorCode::InvalidArgument
        );
        assert_eq!(
            CanonicalError::from(OpaqueIdError::InvalidUtf8).code,
            CanonicalErrorCode::InvalidArgument
        );
        assert_eq!(
            CanonicalError::from(OpaqueIdError::TooLong).code,
            CanonicalErrorCode::ResourceExhausted
        );
    }

    #[test]
    fn retryability_is_explicit_and_conservative() {
        assert!(CanonicalError::new(CanonicalErrorCode::RateLimited).retryable);
        assert!(CanonicalError::new(CanonicalErrorCode::TemporarilyUnavailable).retryable);
        assert!(!CanonicalError::new(CanonicalErrorCode::IntegrityFailure).retryable);
        assert!(!CanonicalError::new(CanonicalErrorCode::PermissionDenied).retryable);
    }

    #[test]
    fn receipt_and_acknowledgement_failures_keep_validation_and_budget_categories_stable() {
        assert_eq!(
            CanonicalError::from(ReceiptError::InvalidSchemaVersion).code,
            CanonicalErrorCode::InvalidArgument
        );
        assert_eq!(
            CanonicalError::from(ReceiptError::ExtensionPayloadTooLarge).code,
            CanonicalErrorCode::ResourceExhausted
        );
        assert_eq!(
            CanonicalError::from(AcknowledgementError::DuplicateExtension).code,
            CanonicalErrorCode::InvalidArgument
        );
        assert_eq!(
            CanonicalError::from(AcknowledgementError::TooManyExtensions).code,
            CanonicalErrorCode::ResourceExhausted
        );
    }

    #[test]
    fn negotiation_extension_failures_keep_fail_closed_categories_stable() {
        assert_eq!(
            CanonicalError::from(CapabilityError::CriticalExtensionRequiresExplicitNegotiation)
                .code,
            CanonicalErrorCode::UnsupportedCriticalExtension
        );
        assert_eq!(
            CanonicalError::from(CapabilityError::ExtensionPayloadTooLarge).code,
            CanonicalErrorCode::ResourceExhausted
        );
        assert_eq!(
            CanonicalError::from(NegotiationResultError::DeprecatedTranscriptBindingNotEmpty).code,
            CanonicalErrorCode::InvalidArgument
        );
    }

    #[test]
    fn addressing_failures_map_to_stable_canonical_categories() {
        assert_eq!(
            CanonicalError::from(AddressingError::InvalidScheme).code,
            CanonicalErrorCode::InvalidArgument
        );
        assert_eq!(
            CanonicalError::from(AddressingError::TooManyAddresses).code,
            CanonicalErrorCode::ResourceExhausted
        );
    }

    #[test]
    fn empty_provenance_is_invalid_argument() {
        assert_eq!(
            CanonicalError::from(ProvenanceError::EmptyOrigin).code,
            CanonicalErrorCode::InvalidArgument
        );
    }

    #[test]
    fn scope_mismatch_is_permission_denied_without_resource_disclosure() {
        assert_eq!(
            CanonicalError::from(ScopeError::CrossTenant).code,
            CanonicalErrorCode::PermissionDenied
        );
        assert_eq!(
            CanonicalError::from(ScopeError::NamespaceMismatch).code,
            CanonicalErrorCode::PermissionDenied
        );
    }

    #[test]
    fn authorization_denial_and_corrupt_grant_have_distinct_categories() {
        assert_eq!(
            CanonicalError::from(AuthorizationError::PermissionDenied).code,
            CanonicalErrorCode::PermissionDenied
        );
        assert_eq!(
            CanonicalError::from(AuthorizationError::InvalidGrant).code,
            CanonicalErrorCode::Internal
        );
    }

    #[test]
    fn malformed_crypto_descriptor_maps_to_invalid_argument() {
        assert_eq!(
            CanonicalError::from(CryptoContractError::WrongKeyFormatVersion).code,
            CanonicalErrorCode::InvalidArgument
        );
    }

    #[test]
    fn recovery_denials_do_not_disclose_plan_or_scope_existence() {
        for error in [
            RecoveryError::MethodNotAllowed,
            RecoveryError::PlanMismatch,
            RecoveryError::ScopeMismatch,
            RecoveryError::IdentityMismatch,
        ] {
            assert_eq!(
                CanonicalError::from(error).code,
                CanonicalErrorCode::PermissionDenied
            );
        }
        assert_eq!(
            CanonicalError::from(RecoveryError::UnsafeRecoveredDeviceState).code,
            CanonicalErrorCode::InvalidArgument
        );
        assert_eq!(
            CanonicalError::from(RecoveryError::TooManyAuthorities).code,
            CanonicalErrorCode::ResourceExhausted
        );
    }

    #[test]
    fn conversation_and_message_failures_have_stable_canonical_categories() {
        assert_eq!(
            CanonicalError::from(ConversationError::InvalidParentKind).code,
            CanonicalErrorCode::InvalidArgument
        );
        assert_eq!(
            CanonicalError::from(MessageError::SelfRelation).code,
            CanonicalErrorCode::InvalidArgument
        );
        assert_eq!(
            CanonicalError::from(MessageError::ContentTooLarge).code,
            CanonicalErrorCode::ResourceExhausted
        );
        assert_eq!(
            CanonicalError::from(MessageError::ExternalMessageIdTooLarge).code,
            CanonicalErrorCode::ResourceExhausted
        );
    }

    #[test]
    fn delivery_failures_have_stable_canonical_categories() {
        assert_eq!(
            CanonicalError::from(DeliveryError::IllegalTransition).code,
            CanonicalErrorCode::InvalidArgument
        );
        assert_eq!(
            CanonicalError::from(DeliveryError::EvidenceDoesNotProveState).code,
            CanonicalErrorCode::InvalidArgument
        );
        assert_eq!(
            CanonicalError::from(DeliveryError::EvidenceRegression).code,
            CanonicalErrorCode::Conflict
        );
    }

    #[test]
    fn sync_failures_keep_conflict_scope_and_budget_categories_stable() {
        assert_eq!(
            CanonicalError::from(SyncError::IllegalTransition).code,
            CanonicalErrorCode::Conflict
        );
        assert_eq!(
            CanonicalError::from(SyncError::CheckpointBindingMismatch).code,
            CanonicalErrorCode::PermissionDenied
        );
        assert_eq!(
            CanonicalError::from(SyncError::ResumeTokenTooLarge).code,
            CanonicalErrorCode::ResourceExhausted
        );
    }

    #[test]
    fn command_failures_keep_conflict_validation_and_budget_categories_stable() {
        assert_eq!(
            CanonicalError::from(CommandError::IdempotencyConflict).code,
            CanonicalErrorCode::Conflict
        );
        assert_eq!(
            CanonicalError::from(CommandError::InvalidSchemaVersion).code,
            CanonicalErrorCode::InvalidArgument
        );
        assert_eq!(
            CanonicalError::from(CommandError::TooManyExtensions).code,
            CanonicalErrorCode::ResourceExhausted
        );
    }

    #[test]
    fn error_envelope_preserves_unknown_failure_codes_and_canonicalizes_extensions() {
        let mut envelope = super::ErrorEnvelope {
            code: 31_337,
            retryable: false,
            retry_after_ms: None,
            diagnostic_domain: "vendor.example.transport".to_owned(),
            extensions: vec![
                ucr_model::ProtocolExtension {
                    name: "vendor.example.z".to_owned(),
                    critical: false,
                    payload: b"z".to_vec(),
                },
                ucr_model::ProtocolExtension {
                    name: "ucr.example.a".to_owned(),
                    critical: false,
                    payload: b"a".to_vec(),
                },
            ],
        };
        let canonical = super::canonical_error_envelope(&envelope).expect("canonical envelope");
        assert_eq!(canonical.code, 31_337);
        assert_eq!(canonical.extensions[0].name, "ucr.example.a");

        envelope.code = 0;
        assert_eq!(
            super::validate_error_envelope(&envelope),
            Err(super::ErrorEnvelopeError::UnspecifiedCode)
        );
    }

    #[test]
    fn canonical_error_to_wire_envelope_keeps_retry_semantics_without_copying_extensions() {
        let error = CanonicalError::new(CanonicalErrorCode::RateLimited).with_retry_after(500);
        let envelope = super::error_envelope_from_canonical(error, "ucr.runtime");
        assert_eq!(envelope.code, CanonicalErrorCode::RateLimited as i32);
        assert!(envelope.retryable);
        assert_eq!(envelope.retry_after_ms, Some(500));
        assert!(envelope.extensions.is_empty());
    }

    #[test]
    fn intent_and_error_envelope_validation_map_to_stable_categories() {
        assert_eq!(
            CanonicalError::from(super::ErrorEnvelopeError::TooManyExtensions).code,
            CanonicalErrorCode::ResourceExhausted
        );
        assert_eq!(
            CanonicalError::from(crate::IntentError::ConflictingTransportCapability).code,
            CanonicalErrorCode::InvalidArgument
        );
        assert_eq!(
            CanonicalError::from(crate::IntentError::TooManyTransportConstraints).code,
            CanonicalErrorCode::ResourceExhausted
        );
    }
}
