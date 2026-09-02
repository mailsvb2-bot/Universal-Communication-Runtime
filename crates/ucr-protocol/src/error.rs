use crate::{
    AddressingError, AuthorizationError, CapabilityError, CommandError, CryptoContractError,
    CryptoNegotiationError, EventError, ExtensionError, FrameError, HandshakeError,
    ProvenanceError, RecoveryError, ScopeError, VersionNegotiationError,
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
            ExtensionError::InvalidNamespace => CanonicalErrorCode::InvalidArgument,
            ExtensionError::UnsupportedCritical => CanonicalErrorCode::UnsupportedCriticalExtension,
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
            | CommandError::IdempotencyKeyTooLong => CanonicalErrorCode::InvalidArgument,
            CommandError::PayloadTooLarge => CanonicalErrorCode::ResourceExhausted,
        };
        Self::new(code)
    }
}

impl From<EventError> for CanonicalError {
    fn from(error: EventError) -> Self {
        let code = match error {
            EventError::InvalidEventType | EventError::InvalidSchemaVersion => {
                CanonicalErrorCode::InvalidArgument
            }
            EventError::PayloadTooLarge | EventError::IntegrityMetadataTooLarge => {
                CanonicalErrorCode::ResourceExhausted
            }
        };
        Self::new(code)
    }
}

impl From<CapabilityError> for CanonicalError {
    fn from(error: CapabilityError) -> Self {
        let code = match error {
            CapabilityError::InvalidIdentifier
            | CapabilityError::DuplicateAdvertisement
            | CapabilityError::InvalidRequirement => CanonicalErrorCode::InvalidArgument,
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
            | AddressingError::ExternalEntityIdTooLong => CanonicalErrorCode::ResourceExhausted,
            AddressingError::InvalidScheme
            | AddressingError::EmptyAddressValue
            | AddressingError::DuplicateAddress
            | AddressingError::DuplicateCapability
            | AddressingError::InvalidCapability
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
        AddressingError, AuthorizationError, CommandError, CryptoContractError, ProvenanceError,
        RecoveryError, ScopeError,
    };

    #[test]
    fn retryability_is_explicit_and_conservative() {
        assert!(CanonicalError::new(CanonicalErrorCode::RateLimited).retryable);
        assert!(CanonicalError::new(CanonicalErrorCode::TemporarilyUnavailable).retryable);
        assert!(!CanonicalError::new(CanonicalErrorCode::IntegrityFailure).retryable);
        assert!(!CanonicalError::new(CanonicalErrorCode::PermissionDenied).retryable);
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
    fn idempotency_conflict_maps_to_canonical_conflict() {
        assert_eq!(
            CanonicalError::from(CommandError::IdempotencyConflict).code,
            CanonicalErrorCode::Conflict
        );
    }
}
