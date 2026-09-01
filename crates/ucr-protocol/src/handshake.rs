use crate::{
    CapabilityDescriptor, CapabilityError, CapabilityRequirement, ExtensionDescriptor,
    ExtensionError, ProtocolVersion, VersionNegotiationError, VersionPolicy, VersionRange,
    negotiate_capabilities, negotiate_version_sets, require_supported_extensions,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerHello {
    pub supported_versions: Vec<VersionRange>,
    pub capabilities: Vec<CapabilityDescriptor>,
    pub extensions: Vec<ExtensionDescriptor>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiationPolicy {
    pub version: VersionPolicy,
    pub required_capabilities: Vec<CapabilityRequirement>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiatedSession {
    pub version: ProtocolVersion,
    pub capabilities: Vec<CapabilityDescriptor>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeError {
    Version(VersionNegotiationError),
    Capability(CapabilityError),
    Extension(ExtensionError),
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
    let capabilities = negotiate_capabilities(
        &local.capabilities,
        &remote.capabilities,
        &policy.required_capabilities,
    )
    .map_err(HandshakeError::Capability)?;
    Ok(NegotiatedSession {
        version,
        capabilities,
    })
}

#[cfg(test)]
mod tests {
    use crate::{
        CapabilityDescriptor, CapabilityMaturity, CapabilityRequirement, ExtensionDescriptor,
        ProtocolVersion, VersionPolicy, VersionRange,
    };

    use super::{HandshakeError, NegotiationPolicy, PeerHello, negotiate_session};

    fn hello(version: u32, maturity: CapabilityMaturity) -> PeerHello {
        PeerHello {
            supported_versions: vec![
                VersionRange::new(
                    ProtocolVersion::new(version, 0),
                    ProtocolVersion::new(version, 0),
                )
                .expect("version range"),
            ],
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
            &hello(1, CapabilityMaturity::Production),
            &hello(1, CapabilityMaturity::Beta),
            &NegotiationPolicy {
                version: VersionPolicy {
                    minimum: ProtocolVersion::new(1, 0),
                },
                required_capabilities: vec![requirement],
            },
            &[],
        )
        .expect("session");
        assert_eq!(result.version, ProtocolVersion::new(1, 0));
        assert_eq!(result.capabilities[0].maturity, CapabilityMaturity::Beta);
    }

    #[test]
    fn unsupported_critical_extension_blocks_session() {
        let local = hello(1, CapabilityMaturity::Production);
        let mut remote = hello(1, CapabilityMaturity::Production);
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
                    required_capabilities: Vec::new(),
                },
                &[],
            ),
            Err(HandshakeError::Extension(_))
        ));
    }
}
