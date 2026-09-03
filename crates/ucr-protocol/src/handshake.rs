use ucr_model::{HandshakeNonce, ProtocolExtension};

use crate::{
    CapabilityDescriptor, CapabilityError, CapabilityRequirement, CryptoNegotiationError,
    CryptoPolicy, CryptoSuite, ExtensionError, ProtocolVersion, VersionNegotiationError,
    VersionPolicy, VersionRange, canonical_capabilities, canonical_protocol_extensions,
    negotiate_capabilities, negotiate_crypto_suite, negotiate_version_sets,
    require_supported_extensions,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerHello {
    pub supported_versions: Vec<VersionRange>,
    pub supported_crypto_suites: Vec<CryptoSuite>,
    pub nonce: HandshakeNonce,
    pub capabilities: Vec<CapabilityDescriptor>,
    pub extensions: Vec<ProtocolExtension>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiationPolicy {
    pub version: VersionPolicy,
    pub crypto: CryptoPolicy,
    pub required_capabilities: Vec<CapabilityRequirement>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiatedSession {
    pub version: ProtocolVersion,
    pub crypto_suite: CryptoSuite,
    pub capabilities: Vec<CapabilityDescriptor>,
}

/// Wire-faithful Rust representation of public `ucr.v1.NegotiationResult`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiationResultEnvelope {
    pub version: ProtocolVersion,
    pub capabilities: Vec<CapabilityDescriptor>,
    pub extensions: Vec<ProtocolExtension>,
    /// Deprecated protobuf field 4. Canonical results require this to be empty.
    pub transcript_binding: Vec<u8>,
    pub crypto_suite: CryptoSuite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegotiationResultError {
    InvalidVersion,
    Capability(CapabilityError),
    Extension(ExtensionError),
    DeprecatedTranscriptBindingNotEmpty,
}

/// Validates a public `NegotiationResult` envelope without treating it as an
/// authenticated session.
///
/// # Errors
/// Rejects invalid versions/capabilities/extensions and non-empty legacy
/// transcript binding bytes.
pub fn validate_negotiation_result(
    result: &NegotiationResultEnvelope,
) -> Result<(), NegotiationResultError> {
    if result.version.major == 0 {
        return Err(NegotiationResultError::InvalidVersion);
    }
    if !result.transcript_binding.is_empty() {
        return Err(NegotiationResultError::DeprecatedTranscriptBindingNotEmpty);
    }
    canonical_capabilities(&result.capabilities).map_err(NegotiationResultError::Capability)?;
    canonical_protocol_extensions(&result.extensions).map_err(NegotiationResultError::Extension)?;
    Ok(())
}

/// Validates and canonically orders a public `NegotiationResult` envelope.
///
/// # Errors
/// Returns the same fail-closed errors as [`validate_negotiation_result`].
pub fn canonical_negotiation_result(
    result: &NegotiationResultEnvelope,
) -> Result<NegotiationResultEnvelope, NegotiationResultError> {
    validate_negotiation_result(result)?;
    let mut canonical = result.clone();
    canonical.capabilities =
        canonical_capabilities(&result.capabilities).map_err(NegotiationResultError::Capability)?;
    canonical.extensions = canonical_protocol_extensions(&result.extensions)
        .map_err(NegotiationResultError::Extension)?;
    Ok(canonical)
}

/// Builds the base wire result from already negotiated parameters. No response
/// extensions are inferred from either peer's Hello.
#[must_use]
pub fn negotiation_result_for_session(session: &NegotiatedSession) -> NegotiationResultEnvelope {
    NegotiationResultEnvelope {
        version: session.version,
        capabilities: session.capabilities.clone(),
        extensions: Vec::new(),
        transcript_binding: Vec::new(),
        crypto_suite: session.crypto_suite,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeError {
    Version(VersionNegotiationError),
    Crypto(CryptoNegotiationError),
    Capability(CapabilityError),
    Extension(ExtensionError),
    InvalidNonce,
    NonceCollision,
}

/// Negotiates protocol parameters without performing cryptography.
///
/// The caller must cryptographically bind both hellos and the result into an
/// authenticated handshake transcript before treating the session as established.
///
/// # Errors
/// Returns explicit version, capability, or extension negotiation failures.
pub fn negotiate_session(
    local: &PeerHello,
    remote: &PeerHello,
    policy: &NegotiationPolicy,
    locally_supported_extensions: &[&str],
) -> Result<NegotiatedSession, HandshakeError> {
    if local.nonce.is_all_zero() || remote.nonce.is_all_zero() {
        return Err(HandshakeError::InvalidNonce);
    }
    if local.nonce == remote.nonce {
        return Err(HandshakeError::NonceCollision);
    }
    canonical_protocol_extensions(&local.extensions).map_err(HandshakeError::Extension)?;
    let remote_extensions =
        canonical_protocol_extensions(&remote.extensions).map_err(HandshakeError::Extension)?;
    require_supported_extensions(
        &remote_extensions,
        locally_supported_extensions.iter().copied(),
    )
    .map_err(HandshakeError::Extension)?;
    let version = negotiate_version_sets(
        &local.supported_versions,
        &remote.supported_versions,
        policy.version,
    )
    .map_err(HandshakeError::Version)?;
    let crypto_suite = negotiate_crypto_suite(
        &local.supported_crypto_suites,
        &remote.supported_crypto_suites,
        &policy.crypto,
    )
    .map_err(HandshakeError::Crypto)?;
    let capabilities = negotiate_capabilities(
        &local.capabilities,
        &remote.capabilities,
        &policy.required_capabilities,
    )
    .map_err(HandshakeError::Capability)?;
    Ok(NegotiatedSession {
        version,
        crypto_suite,
        capabilities,
    })
}

#[cfg(test)]
mod tests {
    use ucr_model::HandshakeNonce;

    use crate::{
        CapabilityDescriptor, CapabilityMaturity, CapabilityRequirement, CryptoPolicy, CryptoSuite,
        ProtocolVersion, VersionPolicy, VersionRange,
    };

    use super::{
        HandshakeError, NegotiationPolicy, NegotiationResultError, PeerHello,
        canonical_negotiation_result, negotiate_session, negotiation_result_for_session,
        validate_negotiation_result,
    };

    fn hello(version: u32, maturity: CapabilityMaturity, nonce_byte: u8) -> PeerHello {
        PeerHello {
            supported_versions: vec![
                VersionRange::new(
                    ProtocolVersion::new(version, 0),
                    ProtocolVersion::new(version, 0),
                )
                .expect("version range"),
            ],
            supported_crypto_suites: vec![CryptoSuite::UcrV1],
            nonce: HandshakeNonce::new([nonce_byte; 32]),
            capabilities: vec![CapabilityDescriptor {
                id: "ucr.message.text".to_owned(),
                maturity,
                extensions: Vec::new(),
            }],
            extensions: Vec::new(),
        }
    }

    #[test]
    fn session_requires_version_and_capability_policy() {
        let requirement = CapabilityRequirement {
            id: "ucr.message.text".to_owned(),
            minimum: CapabilityMaturity::Beta,
            allow_deprecated: false,
        };
        let result = negotiate_session(
            &hello(1, CapabilityMaturity::Production, 7),
            &hello(1, CapabilityMaturity::Beta, 8),
            &NegotiationPolicy {
                version: VersionPolicy {
                    minimum: ProtocolVersion::new(1, 0),
                },
                crypto: CryptoPolicy {
                    preferred_suites: vec![CryptoSuite::UcrV1],
                },
                required_capabilities: vec![requirement],
            },
            &[],
        )
        .expect("session");
        assert_eq!(result.version, ProtocolVersion::new(1, 0));
        assert_eq!(result.crypto_suite, CryptoSuite::UcrV1);
        assert_eq!(result.capabilities[0].maturity, CapabilityMaturity::Beta);
    }

    #[test]
    fn zero_or_reflected_nonce_fails_closed() {
        let policy = NegotiationPolicy {
            version: VersionPolicy {
                minimum: ProtocolVersion::new(1, 0),
            },
            crypto: CryptoPolicy {
                preferred_suites: vec![CryptoSuite::UcrV1],
            },
            required_capabilities: Vec::new(),
        };
        assert_eq!(
            negotiate_session(
                &hello(1, CapabilityMaturity::Production, 0),
                &hello(1, CapabilityMaturity::Production, 8),
                &policy,
                &[],
            ),
            Err(HandshakeError::InvalidNonce)
        );
        assert_eq!(
            negotiate_session(
                &hello(1, CapabilityMaturity::Production, 9),
                &hello(1, CapabilityMaturity::Production, 9),
                &policy,
                &[],
            ),
            Err(HandshakeError::NonceCollision)
        );
    }

    #[test]
    fn hello_extension_payload_shape_is_validated_before_negotiation() {
        let local = hello(1, CapabilityMaturity::Production, 7);
        let mut remote = hello(1, CapabilityMaturity::Production, 8);
        remote.extensions = vec![
            ucr_model::ProtocolExtension {
                name: "vendor.example.same".to_owned(),
                critical: false,
                payload: b"a".to_vec(),
            },
            ucr_model::ProtocolExtension {
                name: "vendor.example.same".to_owned(),
                critical: false,
                payload: b"b".to_vec(),
            },
        ];
        let policy = NegotiationPolicy {
            version: VersionPolicy {
                minimum: ProtocolVersion::new(1, 0),
            },
            crypto: CryptoPolicy {
                preferred_suites: vec![CryptoSuite::UcrV1],
            },
            required_capabilities: Vec::new(),
        };
        assert_eq!(
            negotiate_session(&local, &remote, &policy, &[]),
            Err(HandshakeError::Extension(
                crate::ExtensionError::DuplicateExtension
            ))
        );
    }

    #[test]
    fn negotiation_result_has_exact_wire_fields_and_no_implicit_extensions() {
        let result = negotiate_session(
            &hello(1, CapabilityMaturity::Production, 7),
            &hello(1, CapabilityMaturity::Beta, 8),
            &NegotiationPolicy {
                version: VersionPolicy {
                    minimum: ProtocolVersion::new(1, 0),
                },
                crypto: CryptoPolicy {
                    preferred_suites: vec![CryptoSuite::UcrV1],
                },
                required_capabilities: Vec::new(),
            },
            &[],
        )
        .expect("session");
        let mut wire = negotiation_result_for_session(&result);
        assert!(wire.extensions.is_empty());
        assert!(wire.transcript_binding.is_empty());
        assert_eq!(validate_negotiation_result(&wire), Ok(()));

        wire.extensions = vec![
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
        ];
        let canonical = canonical_negotiation_result(&wire).expect("canonical result");
        assert_eq!(canonical.extensions[0].name, "ucr.example.a");

        wire.transcript_binding = b"legacy-must-stay-empty".to_vec();
        assert_eq!(
            validate_negotiation_result(&wire),
            Err(NegotiationResultError::DeprecatedTranscriptBindingNotEmpty)
        );
    }

    #[test]
    fn unsupported_critical_extension_blocks_session() {
        let local = hello(1, CapabilityMaturity::Production, 7);
        let mut remote = hello(1, CapabilityMaturity::Production, 8);
        remote.extensions.push(ucr_model::ProtocolExtension {
            name: "vendor.example.must-understand".to_owned(),
            critical: true,
            payload: b"required-parameter".to_vec(),
        });
        assert!(matches!(
            negotiate_session(
                &local,
                &remote,
                &NegotiationPolicy {
                    version: VersionPolicy {
                        minimum: ProtocolVersion::new(1, 0),
                    },
                    crypto: CryptoPolicy {
                        preferred_suites: vec![CryptoSuite::UcrV1],
                    },
                    required_capabilities: Vec::new(),
                },
                &[],
            ),
            Err(HandshakeError::Extension(_))
        ));
    }
}
