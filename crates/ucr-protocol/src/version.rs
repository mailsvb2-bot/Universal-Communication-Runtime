use core::cmp::{max, min};

pub use ucr_model::ProtocolVersion;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionRange {
    pub min: ProtocolVersion,
    pub max: ProtocolVersion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionNegotiationError {
    InvalidRange,
    NoMutualVersion,
    BelowLocalMinimum,
    EmptyAdvertisement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionPolicy {
    pub minimum: ProtocolVersion,
}

impl VersionRange {
    /// Creates an inclusive protocol version range.
    ///
    /// # Errors
    /// Returns [`VersionNegotiationError::InvalidRange`] if the range crosses a major version or `min > max`.
    pub const fn new(
        min: ProtocolVersion,
        max: ProtocolVersion,
    ) -> Result<Self, VersionNegotiationError> {
        if min.major != max.major || min.minor > max.minor {
            return Err(VersionNegotiationError::InvalidRange);
        }
        Ok(Self { min, max })
    }
}

/// Selects the highest mutually supported version for one pair of ranges.
///
/// # Errors
/// Returns an explicit error for invalid ranges, no overlap, or policy downgrade.
pub fn negotiate_version(
    local: VersionRange,
    remote: VersionRange,
    policy: VersionPolicy,
) -> Result<ProtocolVersion, VersionNegotiationError> {
    negotiate_version_sets(&[local], &[remote], policy)
}

/// Selects the highest mutually supported version across advertised ranges.
///
/// # Errors
/// Returns an explicit error when advertisements are empty or invalid, when no
/// ranges overlap, or when all overlaps are below the configured minimum.
pub fn negotiate_version_sets(
    local: &[VersionRange],
    remote: &[VersionRange],
    policy: VersionPolicy,
) -> Result<ProtocolVersion, VersionNegotiationError> {
    if local.is_empty() || remote.is_empty() {
        return Err(VersionNegotiationError::EmptyAdvertisement);
    }
    if local
        .iter()
        .chain(remote)
        .any(|range| range.min.major != range.max.major || range.min.minor > range.max.minor)
    {
        return Err(VersionNegotiationError::InvalidRange);
    }

    let mut best = None;
    let mut had_overlap = false;
    for local_range in local {
        for remote_range in remote {
            let overlap_min = max(local_range.min, remote_range.min);
            let overlap_max = min(local_range.max, remote_range.max);
            if overlap_min > overlap_max {
                continue;
            }
            had_overlap = true;
            if overlap_max < policy.minimum {
                continue;
            }
            best = Some(best.map_or(overlap_max, |current| max(current, overlap_max)));
        }
    }

    match best {
        Some(version) => Ok(version),
        None if had_overlap => Err(VersionNegotiationError::BelowLocalMinimum),
        None => Err(VersionNegotiationError::NoMutualVersion),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ProtocolVersion, VersionNegotiationError, VersionPolicy, VersionRange, negotiate_version,
        negotiate_version_sets,
    };

    const fn version(major: u32, minor: u32) -> ProtocolVersion {
        ProtocolVersion::new(major, minor)
    }

    #[test]
    fn selects_highest_mutual_version() {
        let local = VersionRange::new(version(2, 0), version(2, 4)).expect("local range");
        let remote = VersionRange::new(version(2, 1), version(2, 3)).expect("remote range");
        let selected = negotiate_version(
            local,
            remote,
            VersionPolicy {
                minimum: version(2, 0),
            },
        )
        .expect("mutual version");
        assert_eq!(selected, version(2, 3));
    }

    #[test]
    fn selects_highest_across_disjoint_advertisements() {
        let local = [
            VersionRange::new(version(1, 0), version(1, 4)).expect("range"),
            VersionRange::new(version(3, 0), version(3, 2)).expect("range"),
        ];
        let remote = [
            VersionRange::new(version(1, 2), version(1, 3)).expect("range"),
            VersionRange::new(version(3, 1), version(3, 5)).expect("range"),
        ];
        assert_eq!(
            negotiate_version_sets(
                &local,
                &remote,
                VersionPolicy {
                    minimum: version(1, 0)
                }
            ),
            Ok(version(3, 2))
        );
    }

    #[test]
    fn refuses_policy_downgrade() {
        let local = VersionRange::new(version(1, 0), version(1, 9)).expect("local range");
        let remote = VersionRange::new(version(1, 0), version(1, 9)).expect("remote range");
        assert_eq!(
            negotiate_version(
                local,
                remote,
                VersionPolicy {
                    minimum: version(2, 0)
                }
            ),
            Err(VersionNegotiationError::BelowLocalMinimum)
        );
    }

    #[test]
    fn rejects_empty_advertisement() {
        let remote = [VersionRange::new(version(1, 0), version(1, 0)).expect("range")];
        assert_eq!(
            negotiate_version_sets(
                &[],
                &remote,
                VersionPolicy {
                    minimum: version(1, 0)
                }
            ),
            Err(VersionNegotiationError::EmptyAdvertisement)
        );
    }

    #[test]
    fn cross_major_range_is_rejected() {
        assert_eq!(
            VersionRange::new(version(1, 9), version(2, 0)),
            Err(VersionNegotiationError::InvalidRange)
        );
    }

    #[test]
    fn manually_constructed_cross_major_range_is_rejected() {
        let invalid = VersionRange {
            min: version(1, 9),
            max: version(2, 0),
        };
        let remote = [VersionRange::new(version(1, 0), version(1, 9)).expect("range")];
        assert_eq!(
            negotiate_version_sets(
                &[invalid],
                &remote,
                VersionPolicy {
                    minimum: version(1, 0),
                },
            ),
            Err(VersionNegotiationError::InvalidRange)
        );
    }
}
