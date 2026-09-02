use ucr_model::HandshakeNonce;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RandomError {
    OsRandomUnavailable,
}

/// Generates a cryptographic handshake nonce from the operating-system CSPRNG.
///
/// # Errors
/// Returns an explicit failure if the OS random source is unavailable.
pub fn generate_handshake_nonce() -> Result<HandshakeNonce, RandomError> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| RandomError::OsRandomUnavailable)?;
    Ok(HandshakeNonce::new(bytes))
}
