use std::{net::TcpStream, sync::Arc};

use ucr_crypto::{
    AgreementKeyPair, EstablishedSession, ReplayProtector, SessionRole, SigningKeyHandle,
    TrustedSessionError, TrustedSessionHandshakeInput, TrustedSigningKeyResolver,
    begin_session_with_trusted_peer, bind_handshake_transcript, generate_handshake_nonce,
};
use ucr_model::{
    CapabilityMaturity, DeviceId, EndpointId, KeyId, PublicKeyDescriptor, TenantScope,
};
use ucr_protocol::{
    CapabilityRequirement, HandshakeError, NegotiationPolicy, PeerHello,
    canonical_negotiation_result, negotiate_session, negotiation_result_for_session,
    validate_trusted_signing_key_descriptor,
};

use crate::route::INTERNET_TCP_CAPABILITY;
use crate::wire::{
    INTERNET_CONTEXT_EXTENSION, WireError, auth_frame, confirmation_frame, context_extension,
    decode_agreement, decode_auth, decode_confirmation, decode_hello, decode_negotiation_result,
    encode_hello, encode_negotiation_result, endpoint_from_context, key_exchange_frame, pb,
    read_message_frame, write_frame,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InternetPeerExpectation {
    pub device_id: DeviceId,
    pub signing_key_id: Option<KeyId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InternetPeerExpectationError {
    NotFound,
    Unavailable,
    Corrupt,
}

pub trait InternetPeerExpectationResolver: core::fmt::Debug + Send + Sync {
    /// Resolves the canonical expected Device/key for one exact Endpoint.
    ///
    /// The transport never creates an alternative Endpoint/Identity store.
    ///
    /// # Errors
    /// Returns an explicit absence/availability/corruption error without trusting peer claims.
    fn expected_peer(
        &self,
        scope: &TenantScope,
        endpoint_id: &EndpointId,
    ) -> Result<InternetPeerExpectation, InternetPeerExpectationError>;
}

#[derive(Debug)]
pub struct InternetTransportIdentity {
    pub scope: TenantScope,
    pub endpoint_id: EndpointId,
    pub hello_template: PeerHello,
    pub negotiation_policy: NegotiationPolicy,
    pub signing_descriptor: PublicKeyDescriptor,
    pub signing_key: Arc<dyn SigningKeyHandle>,
    pub trusted_keys: Arc<dyn TrustedSigningKeyResolver>,
    pub replay: Arc<dyn ReplayProtector>,
    pub peer_expectations: Arc<dyn InternetPeerExpectationResolver>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InternetHandshakeError {
    WireTimeout,
    WireUnavailable,
    WireMalformed,
    InvalidLocalIdentity,
    Negotiation(HandshakeError),
    NegotiationMismatch,
    PeerEndpointMismatch,
    PeerExpectation(InternetPeerExpectationError),
    PeerDeviceMismatch,
    PeerKeyMismatch,
    Crypto(TrustedSessionError),
    LocalCrypto,
}

impl InternetTransportIdentity {
    /// Validates static local identity material before any socket side effect.
    ///
    /// # Errors
    /// Returns `InvalidLocalIdentity` for malformed signing material or Internet capability state.
    pub fn validate(&self) -> Result<(), InternetHandshakeError> {
        validate_trusted_signing_key_descriptor(&self.signing_descriptor)
            .map_err(|_| InternetHandshakeError::InvalidLocalIdentity)?;
        if self.signing_descriptor.public_key.as_slice() != self.signing_key.verifying_key().0 {
            return Err(InternetHandshakeError::InvalidLocalIdentity);
        }
        let internet = self
            .hello_template
            .capabilities
            .iter()
            .filter(|capability| capability.id == INTERNET_TCP_CAPABILITY)
            .collect::<Vec<_>>();
        if internet.len() != 1
            || !matches!(
                internet[0].maturity,
                CapabilityMaturity::Prepared
                    | CapabilityMaturity::Beta
                    | CapabilityMaturity::Production
            )
            || self
                .hello_template
                .extensions
                .iter()
                .any(|extension| extension.name == INTERNET_CONTEXT_EXTENSION)
        {
            return Err(InternetHandshakeError::InvalidLocalIdentity);
        }
        Ok(())
    }

    fn fresh_hello(&self) -> Result<PeerHello, InternetHandshakeError> {
        self.validate()?;
        let mut hello = self.hello_template.clone();
        hello.nonce =
            generate_handshake_nonce().map_err(|_| InternetHandshakeError::LocalCrypto)?;
        hello
            .extensions
            .push(context_extension(&self.endpoint_id, &self.scope));
        Ok(hello)
    }

    fn effective_policy(&self) -> NegotiationPolicy {
        let mut policy = self.negotiation_policy.clone();
        if !policy
            .required_capabilities
            .iter()
            .any(|requirement| requirement.id == INTERNET_TCP_CAPABILITY)
        {
            policy.required_capabilities.push(CapabilityRequirement {
                id: INTERNET_TCP_CAPABILITY.to_owned(),
                minimum: CapabilityMaturity::Prepared,
                allow_deprecated: false,
            });
        }
        policy
    }

    fn validate_peer_claim(
        &self,
        endpoint_id: &EndpointId,
        descriptor: &PublicKeyDescriptor,
    ) -> Result<(), InternetHandshakeError> {
        let expectation = self
            .peer_expectations
            .expected_peer(&self.scope, endpoint_id)
            .map_err(InternetHandshakeError::PeerExpectation)?;
        if descriptor.device_id != expectation.device_id {
            return Err(InternetHandshakeError::PeerDeviceMismatch);
        }
        if expectation
            .signing_key_id
            .as_ref()
            .is_some_and(|expected| descriptor.key_id != *expected)
        {
            return Err(InternetHandshakeError::PeerKeyMismatch);
        }
        Ok(())
    }
}

struct PeerHandshakeMaterial {
    hello_frame: Vec<u8>,
    hello: PeerHello,
    endpoint_id: EndpointId,
    agreement_public: ucr_crypto::AgreementPublicKey,
}

fn read_peer_hello_and_key(
    stream: &mut TcpStream,
    scope: &TenantScope,
) -> Result<PeerHandshakeMaterial, InternetHandshakeError> {
    let (hello_frame, hello_pb) =
        read_message_frame::<pb::NegotiationHello>(stream, ucr_protocol::FrameKind::Hello)
            .map_err(map_wire)?;
    let hello = decode_hello(hello_pb).map_err(map_wire)?;
    let endpoint_id = endpoint_from_context(&hello, scope).map_err(map_wire)?;
    let (_, key_pb) = read_message_frame::<pb::HandshakeKeyExchange>(
        stream,
        ucr_protocol::FrameKind::HandshakeKeyExchange,
    )
    .map_err(map_wire)?;
    let agreement_public = decode_agreement(key_pb).map_err(map_wire)?;
    Ok(PeerHandshakeMaterial {
        hello_frame,
        hello,
        endpoint_id,
        agreement_public,
    })
}

pub(crate) fn initiate_handshake(
    stream: &mut TcpStream,
    identity: &InternetTransportIdentity,
    expected_peer_endpoint: &EndpointId,
) -> Result<EstablishedSession, InternetHandshakeError> {
    let local_hello = identity.fresh_hello()?;
    let local_hello_frame = encode_hello(&local_hello).map_err(map_wire)?;
    let local_agreement =
        AgreementKeyPair::generate().map_err(|_| InternetHandshakeError::LocalCrypto)?;
    let local_public = local_agreement.public_key();
    write_frame(stream, &local_hello_frame).map_err(map_wire)?;
    let key_frame = key_exchange_frame(local_public).map_err(map_wire)?;
    write_frame(stream, &key_frame).map_err(map_wire)?;
    let peer = read_peer_hello_and_key(stream, &identity.scope)?;
    if peer.endpoint_id != *expected_peer_endpoint {
        return Err(InternetHandshakeError::PeerEndpointMismatch);
    }
    let negotiated = negotiate_session(
        &local_hello,
        &peer.hello,
        &identity.effective_policy(),
        &[INTERNET_CONTEXT_EXTENSION],
    )
    .map_err(InternetHandshakeError::Negotiation)?;
    let (result_frame, result_pb) = read_message_frame::<pb::NegotiationResult>(
        stream,
        ucr_protocol::FrameKind::NegotiationResult,
    )
    .map_err(map_wire)?;
    let received = decode_negotiation_result(result_pb).map_err(map_wire)?;
    let expected = canonical_negotiation_result(&negotiation_result_for_session(&negotiated))
        .map_err(|_| InternetHandshakeError::NegotiationMismatch)?;
    let received = canonical_negotiation_result(&received)
        .map_err(|_| InternetHandshakeError::NegotiationMismatch)?;
    if received != expected {
        return Err(InternetHandshakeError::NegotiationMismatch);
    }
    let binding = bind_handshake_transcript(
        &local_hello_frame,
        &peer.hello_frame,
        &result_frame,
        local_public,
        peer.agreement_public,
    )
    .map_err(|_| InternetHandshakeError::LocalCrypto)?;
    finish_initiator_authenticated(
        stream,
        identity,
        local_agreement,
        local_public,
        binding,
        &peer,
        negotiated.crypto_suite,
    )
}

fn finish_initiator_authenticated(
    stream: &mut TcpStream,
    identity: &InternetTransportIdentity,
    local_agreement: AgreementKeyPair,
    local_public: ucr_crypto::AgreementPublicKey,
    binding: ucr_crypto::TranscriptBinding,
    peer: &PeerHandshakeMaterial,
    suite: ucr_model::CryptoSuite,
) -> Result<EstablishedSession, InternetHandshakeError> {
    let local_signature = identity
        .signing_key
        .sign_transcript(&binding)
        .map_err(|_| InternetHandshakeError::LocalCrypto)?;
    write_frame(
        stream,
        &auth_frame(&binding, &identity.signing_descriptor, local_signature).map_err(map_wire)?,
    )
    .map_err(map_wire)?;
    let (_, peer_auth) = read_message_frame::<pb::HandshakeAuthentication>(
        stream,
        ucr_protocol::FrameKind::HandshakeAuthentication,
    )
    .map_err(map_wire)?;
    let (peer_descriptor, peer_signature) = decode_auth(peer_auth, &binding).map_err(map_wire)?;
    identity.validate_peer_claim(&peer.endpoint_id, &peer_descriptor)?;
    let pending = begin_session_with_trusted_peer(
        local_agreement,
        &TrustedSessionHandshakeInput {
            scope: identity.scope.clone(),
            suite,
            role: SessionRole::Initiator,
            peer_agreement: peer.agreement_public,
            initiator_public: local_public,
            responder_public: peer.agreement_public,
            peer_signing_descriptor: peer_descriptor,
            peer_signature,
            binding,
        },
        identity.replay.as_ref(),
        identity.trusted_keys.as_ref(),
    )
    .map_err(InternetHandshakeError::Crypto)?;
    let local_confirmation = pending
        .local_confirmation_tag()
        .map_err(|_| InternetHandshakeError::LocalCrypto)?;
    write_frame(
        stream,
        &confirmation_frame(&binding, local_confirmation).map_err(map_wire)?,
    )
    .map_err(map_wire)?;
    let (_, peer_confirmation) =
        read_message_frame::<pb::KeyConfirmation>(stream, ucr_protocol::FrameKind::KeyConfirmation)
            .map_err(map_wire)?;
    let peer_confirmation = decode_confirmation(peer_confirmation, &binding).map_err(map_wire)?;
    pending
        .confirm_peer(peer_confirmation)
        .map_err(|error| InternetHandshakeError::Crypto(TrustedSessionError::Session(error)))
}

pub(crate) fn accept_handshake(
    stream: &mut TcpStream,
    identity: &InternetTransportIdentity,
) -> Result<(EstablishedSession, EndpointId), InternetHandshakeError> {
    let peer = read_peer_hello_and_key(stream, &identity.scope)?;
    let local_hello = identity.fresh_hello()?;
    let local_hello_frame = encode_hello(&local_hello).map_err(map_wire)?;
    let local_agreement =
        AgreementKeyPair::generate().map_err(|_| InternetHandshakeError::LocalCrypto)?;
    let local_public = local_agreement.public_key();
    write_frame(stream, &local_hello_frame).map_err(map_wire)?;
    write_frame(stream, &key_exchange_frame(local_public).map_err(map_wire)?).map_err(map_wire)?;
    let negotiated = negotiate_session(
        &local_hello,
        &peer.hello,
        &identity.effective_policy(),
        &[INTERNET_CONTEXT_EXTENSION],
    )
    .map_err(InternetHandshakeError::Negotiation)?;
    let (result_frame, _) = encode_negotiation_result(&negotiated).map_err(map_wire)?;
    write_frame(stream, &result_frame).map_err(map_wire)?;
    let binding = bind_handshake_transcript(
        &peer.hello_frame,
        &local_hello_frame,
        &result_frame,
        peer.agreement_public,
        local_public,
    )
    .map_err(|_| InternetHandshakeError::LocalCrypto)?;
    finish_responder_authenticated(
        stream,
        identity,
        local_agreement,
        local_public,
        binding,
        peer,
        negotiated.crypto_suite,
    )
}

fn finish_responder_authenticated(
    stream: &mut TcpStream,
    identity: &InternetTransportIdentity,
    local_agreement: AgreementKeyPair,
    local_public: ucr_crypto::AgreementPublicKey,
    binding: ucr_crypto::TranscriptBinding,
    peer: PeerHandshakeMaterial,
    suite: ucr_model::CryptoSuite,
) -> Result<(EstablishedSession, EndpointId), InternetHandshakeError> {
    let (_, peer_auth) = read_message_frame::<pb::HandshakeAuthentication>(
        stream,
        ucr_protocol::FrameKind::HandshakeAuthentication,
    )
    .map_err(map_wire)?;
    let (peer_descriptor, peer_signature) = decode_auth(peer_auth, &binding).map_err(map_wire)?;
    identity.validate_peer_claim(&peer.endpoint_id, &peer_descriptor)?;
    let local_signature = identity
        .signing_key
        .sign_transcript(&binding)
        .map_err(|_| InternetHandshakeError::LocalCrypto)?;
    write_frame(
        stream,
        &auth_frame(&binding, &identity.signing_descriptor, local_signature).map_err(map_wire)?,
    )
    .map_err(map_wire)?;
    let pending = begin_session_with_trusted_peer(
        local_agreement,
        &TrustedSessionHandshakeInput {
            scope: identity.scope.clone(),
            suite,
            role: SessionRole::Responder,
            peer_agreement: peer.agreement_public,
            initiator_public: peer.agreement_public,
            responder_public: local_public,
            peer_signing_descriptor: peer_descriptor,
            peer_signature,
            binding,
        },
        identity.replay.as_ref(),
        identity.trusted_keys.as_ref(),
    )
    .map_err(InternetHandshakeError::Crypto)?;
    let (_, peer_confirmation) =
        read_message_frame::<pb::KeyConfirmation>(stream, ucr_protocol::FrameKind::KeyConfirmation)
            .map_err(map_wire)?;
    let peer_confirmation = decode_confirmation(peer_confirmation, &binding).map_err(map_wire)?;
    let local_confirmation = pending
        .local_confirmation_tag()
        .map_err(|_| InternetHandshakeError::LocalCrypto)?;
    write_frame(
        stream,
        &confirmation_frame(&binding, local_confirmation).map_err(map_wire)?,
    )
    .map_err(map_wire)?;
    let session = pending
        .confirm_peer(peer_confirmation)
        .map_err(|error| InternetHandshakeError::Crypto(TrustedSessionError::Session(error)))?;
    Ok((session, peer.endpoint_id))
}

fn map_wire(error: WireError) -> InternetHandshakeError {
    match error {
        WireError::Io(std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock) => {
            InternetHandshakeError::WireTimeout
        }
        WireError::Io(
            std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::NotConnected
            | std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::BrokenPipe,
        ) => InternetHandshakeError::WireUnavailable,
        WireError::Io(_)
        | WireError::Frame
        | WireError::Encode
        | WireError::Decode
        | WireError::UnexpectedFrameKind
        | WireError::InvalidValue
        | WireError::PayloadTooLarge => InternetHandshakeError::WireMalformed,
    }
}
