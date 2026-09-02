pub use ucr_model::CryptoSuite;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoNegotiationError {
    EmptyAdvertisement,
    DuplicateAdvertisement,
    DuplicatePolicySuite,
    NoMutualSuite,
    PolicyRejectedMutualSuite,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoPolicy {
    /// Suites allowed by local security policy, ordered most-preferred first.
    pub preferred_suites: Vec<CryptoSuite>,
}

/// Selects the first policy-preferred suite advertised by both peers.
///
/// Numeric suite identifiers are identifiers only; they do not encode security
/// strength or preference.
///
/// # Errors
/// Fails explicitly for malformed advertisements/policy, no peer overlap, or
/// overlap consisting only of suites disabled by local policy.
pub fn negotiate_crypto_suite(
    local: &[CryptoSuite],
    remote: &[CryptoSuite],
    policy: &CryptoPolicy,
) -> Result<CryptoSuite, CryptoNegotiationError> {
    if local.is_empty() || remote.is_empty() {
        return Err(CryptoNegotiationError::EmptyAdvertisement);
    }
    if has_duplicates(local) || has_duplicates(remote) {
        return Err(CryptoNegotiationError::DuplicateAdvertisement);
    }
    if has_duplicates(&policy.preferred_suites) {
        return Err(CryptoNegotiationError::DuplicatePolicySuite);
    }

    let peers_overlap = local.iter().any(|suite| remote.contains(suite));
    for suite in &policy.preferred_suites {
        if local.contains(suite) && remote.contains(suite) {
            return Ok(*suite);
        }
    }

    if peers_overlap {
        Err(CryptoNegotiationError::PolicyRejectedMutualSuite)
    } else {
        Err(CryptoNegotiationError::NoMutualSuite)
    }
}

fn has_duplicates(values: &[CryptoSuite]) -> bool {
    values
        .iter()
        .enumerate()
        .any(|(index, value)| values[index + 1..].contains(value))
}
#[cfg(test)]
mod tests {
    use super::{CryptoNegotiationError, CryptoPolicy, CryptoSuite, negotiate_crypto_suite};

    fn policy_v1() -> CryptoPolicy {
        CryptoPolicy {
            preferred_suites: vec![CryptoSuite::UcrV1],
        }
    }

    #[test]
    fn selects_policy_allowed_mutual_suite() {
        assert_eq!(
            negotiate_crypto_suite(&[CryptoSuite::UcrV1], &[CryptoSuite::UcrV1], &policy_v1(),),
            Ok(CryptoSuite::UcrV1)
        );
    }

    #[test]
    fn duplicate_crypto_advertisement_fails_closed() {
        assert_eq!(
            negotiate_crypto_suite(
                &[CryptoSuite::UcrV1, CryptoSuite::UcrV1],
                &[CryptoSuite::UcrV1],
                &policy_v1(),
            ),
            Err(CryptoNegotiationError::DuplicateAdvertisement)
        );
    }
    #[test]
    fn empty_crypto_advertisement_fails_closed() {
        assert_eq!(
            negotiate_crypto_suite(&[], &[CryptoSuite::UcrV1], &policy_v1()),
            Err(CryptoNegotiationError::EmptyAdvertisement)
        );
    }

    #[test]
    fn deny_all_policy_and_duplicate_policy_fail_closed() {
        assert_eq!(
            negotiate_crypto_suite(
                &[CryptoSuite::UcrV1],
                &[CryptoSuite::UcrV1],
                &CryptoPolicy {
                    preferred_suites: Vec::new(),
                },
            ),
            Err(CryptoNegotiationError::PolicyRejectedMutualSuite)
        );
        assert_eq!(
            negotiate_crypto_suite(
                &[CryptoSuite::UcrV1],
                &[CryptoSuite::UcrV1],
                &CryptoPolicy {
                    preferred_suites: vec![CryptoSuite::UcrV1, CryptoSuite::UcrV1],
                },
            ),
            Err(CryptoNegotiationError::DuplicatePolicySuite)
        );
    }
}
