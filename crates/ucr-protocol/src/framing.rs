pub const FRAME_MAGIC: [u8; 4] = *b"UCRF";
pub const FRAME_HEADER_LEN: usize = 12;
pub const CURRENT_FRAMING_VERSION: u16 = 1;
pub const DEFAULT_MAX_PAYLOAD_LEN: u32 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameKind {
    Hello = 1,
    NegotiationResult = 2,
    Command = 3,
    Event = 4,
    Error = 5,
    Acknowledgement = 6,
}

impl TryFrom<u8> for FrameKind {
    type Error = FrameError;

    fn try_from(value: u8) -> Result<Self, FrameError> {
        match value {
            1 => Ok(Self::Hello),
            2 => Ok(Self::NegotiationResult),
            3 => Ok(Self::Command),
            4 => Ok(Self::Event),
            5 => Ok(Self::Error),
            6 => Ok(Self::Acknowledgement),
            _ => Err(FrameError::UnknownKind),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub framing_version: u16,
    pub kind: FrameKind,
    pub flags: u8,
    pub payload_len: u32,
}

impl FrameHeader {
    #[must_use]
    pub fn encode(self) -> [u8; FRAME_HEADER_LEN] {
        let mut bytes = [0_u8; FRAME_HEADER_LEN];
        bytes[..4].copy_from_slice(&FRAME_MAGIC);
        bytes[4..6].copy_from_slice(&self.framing_version.to_be_bytes());
        bytes[6] = self.kind as u8;
        bytes[7] = self.flags;
        bytes[8..12].copy_from_slice(&self.payload_len.to_be_bytes());
        bytes
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FramePolicy {
    pub minimum_framing_version: u16,
    pub maximum_framing_version: u16,
    pub max_payload_len: u32,
}

impl Default for FramePolicy {
    fn default() -> Self {
        Self {
            minimum_framing_version: CURRENT_FRAMING_VERSION,
            maximum_framing_version: CURRENT_FRAMING_VERSION,
            max_payload_len: DEFAULT_MAX_PAYLOAD_LEN,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    TruncatedHeader,
    BadMagic,
    UnsupportedFramingVersion,
    UnknownKind,
    UnsupportedFlags,
    PayloadTooLarge,
    TruncatedPayload,
    LengthOverflow,
}

/// Decodes and validates the fixed Phase-0 UCR frame header.
///
/// # Errors
/// Rejects malformed magic, unsupported versions/flags/kinds and oversized payloads.
pub fn decode_header(bytes: &[u8], policy: FramePolicy) -> Result<FrameHeader, FrameError> {
    if bytes.len() < FRAME_HEADER_LEN {
        return Err(FrameError::TruncatedHeader);
    }
    if bytes[..4] != FRAME_MAGIC {
        return Err(FrameError::BadMagic);
    }
    let framing_version = u16::from_be_bytes([bytes[4], bytes[5]]);
    if framing_version < policy.minimum_framing_version
        || framing_version > policy.maximum_framing_version
    {
        return Err(FrameError::UnsupportedFramingVersion);
    }
    let kind = FrameKind::try_from(bytes[6])?;
    let flags = bytes[7];
    if flags != 0 {
        return Err(FrameError::UnsupportedFlags);
    }
    let payload_len = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    if payload_len > policy.max_payload_len {
        return Err(FrameError::PayloadTooLarge);
    }
    Ok(FrameHeader {
        framing_version,
        kind,
        flags,
        payload_len,
    })
}

/// Decodes one complete frame prefix and returns any trailing stream bytes.
///
/// # Errors
/// Returns a framing error when the header is invalid or the declared payload is incomplete.
pub fn decode_frame_prefix(
    bytes: &[u8],
    policy: FramePolicy,
) -> Result<(FrameHeader, &[u8], &[u8]), FrameError> {
    let header = decode_header(bytes, policy)?;
    let payload_len =
        usize::try_from(header.payload_len).map_err(|_| FrameError::LengthOverflow)?;
    let payload_end = FRAME_HEADER_LEN
        .checked_add(payload_len)
        .ok_or(FrameError::LengthOverflow)?;
    if bytes.len() < payload_end {
        return Err(FrameError::TruncatedPayload);
    }
    Ok((
        header,
        &bytes[FRAME_HEADER_LEN..payload_end],
        &bytes[payload_end..],
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        CURRENT_FRAMING_VERSION, FrameError, FrameHeader, FrameKind, FramePolicy,
        decode_frame_prefix, decode_header,
    };

    #[test]
    fn frame_round_trip_preserves_stream_remainder() {
        let header = FrameHeader {
            framing_version: CURRENT_FRAMING_VERSION,
            kind: FrameKind::Command,
            flags: 0,
            payload_len: 3,
        };
        let mut bytes = header.encode().to_vec();
        bytes.extend_from_slice(b"abcNEXT");
        let (decoded, payload, remainder) =
            decode_frame_prefix(&bytes, FramePolicy::default()).expect("frame");
        assert_eq!(decoded, header);
        assert_eq!(payload, b"abc");
        assert_eq!(remainder, b"NEXT");
    }

    #[test]
    fn nonzero_reserved_flags_fail_closed() {
        let header = FrameHeader {
            framing_version: CURRENT_FRAMING_VERSION,
            kind: FrameKind::Hello,
            flags: 1,
            payload_len: 0,
        };
        assert_eq!(
            decode_header(&header.encode(), FramePolicy::default()),
            Err(FrameError::UnsupportedFlags)
        );
    }

    #[test]
    fn oversized_payload_is_rejected_before_allocation() {
        let header = FrameHeader {
            framing_version: CURRENT_FRAMING_VERSION,
            kind: FrameKind::Event,
            flags: 0,
            payload_len: 1024,
        };
        let policy = FramePolicy {
            max_payload_len: 512,
            ..FramePolicy::default()
        };
        assert_eq!(
            decode_header(&header.encode(), policy),
            Err(FrameError::PayloadTooLarge)
        );
    }

    #[test]
    fn bad_magic_is_rejected() {
        let mut bytes = FrameHeader {
            framing_version: CURRENT_FRAMING_VERSION,
            kind: FrameKind::Hello,
            flags: 0,
            payload_len: 0,
        }
        .encode();
        bytes[0] = b'X';
        assert_eq!(
            decode_header(&bytes, FramePolicy::default()),
            Err(FrameError::BadMagic)
        );
    }

    #[test]
    fn unknown_frame_kind_is_rejected() {
        let mut bytes = FrameHeader {
            framing_version: CURRENT_FRAMING_VERSION,
            kind: FrameKind::Hello,
            flags: 0,
            payload_len: 0,
        }
        .encode();
        bytes[6] = 0xff;
        assert_eq!(
            decode_header(&bytes, FramePolicy::default()),
            Err(FrameError::UnknownKind)
        );
    }

    #[test]
    fn unsupported_framing_version_is_rejected() {
        let header = FrameHeader {
            framing_version: CURRENT_FRAMING_VERSION + 1,
            kind: FrameKind::Hello,
            flags: 0,
            payload_len: 0,
        };
        assert_eq!(
            decode_header(&header.encode(), FramePolicy::default()),
            Err(FrameError::UnsupportedFramingVersion)
        );
    }

    #[test]
    fn truncated_payload_is_rejected() {
        let header = FrameHeader {
            framing_version: CURRENT_FRAMING_VERSION,
            kind: FrameKind::Command,
            flags: 0,
            payload_len: 4,
        };
        let mut bytes = header.encode().to_vec();
        bytes.extend_from_slice(b"abc");
        assert_eq!(
            decode_frame_prefix(&bytes, FramePolicy::default()),
            Err(FrameError::TruncatedPayload)
        );
    }
}
