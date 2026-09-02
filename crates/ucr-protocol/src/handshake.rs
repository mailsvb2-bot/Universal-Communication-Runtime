use ucr_model::HandshakeNonce;

use crate::{
    CapabilityDescriptor, CapabilityError, CapabilityRequirement, CryptoNegotiationError,
    CryptoPolicy, CryptoSuite, ExtensionDescriptor, ExtensionError, ProtocolVersion,
    VersionNegotiationError, VersionPolicy, VersionRange, negotiate_capabilities,
    negotiate_crypto_suite, negotiate_version_sets, require_supported_extensions,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerHello {
    pub supported_versions: Vec<VersionRange>,
    pub supported_crypto_suites: Vec<CryptoSuite>,
    pub nonce: HandshakeNonce,
    pub capabilities: Vec<CapabilityDescriptor>,
    pub extensions: Vec<ExtensionDescriptor>,
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
    require_supported_extensions(
        &remote.extensions,
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
        ExtensionDescriptor, ProtocolVersion, VersionPolicy, VersionRange,
    };

    use super::{HandshakeError, NegotiationPolicy, PeerHello, negotiate_session};

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
    fn unsupported_critical_extension_blocks_session() {
        let local = hello(1, CapabilityMaturity::Production, 7);
        let mut remote = hello(1, CapabilityMaturity::Production, 8);
        remote.extensions.push(ExtensionDescriptor {
            name: "vendor.example.must-understand".to_owned(),
            critical: true,
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
