use std::{net::TcpStream, sync::Arc};

use prost::Message;
use sha2::{Digest, Sha256};
use ucr_crypto::{
    AgreementKeyPair, EstablishedSession, ReplayProtector, SessionRole, SigningKeyHandle,
    TrustedSessionError, TrustedSessionHandshakeInput, TrustedSigningKeyResolver,
    begin_session_with_trusted_peer, bind_handshake_transcript, generate_handshake_nonce,
};
use ucr_model::{
    CapabilityMaturity, DeviceId, EndpointId, KeyId, ProtocolExtension, PublicKeyDescriptor,
    TenantScope,
};
use ucr_protocol::{
    CapabilityRequirement, HandshakeError, NegotiationPolicy, PeerHello,
    canonical_negotiation_result, negotiate_session, negotiation_result_for_session,
    validate_trusted_signing_key_descriptor,
};

use crate::handshake::{InternetPeerExpectationError, InternetPeerExpectationResolver};
use crate::local_route::LOCAL_TCP_CAPABILITY;
use crate::wire::{
    WireError, auth_frame, confirmation_frame, decode_agreement, decode_auth, decode_confirmation,
    decode_hello, decode_negotiation_result, decode_opaque, encode_hello, encode_negotiation_result,
    key_exchange_frame, pb, pb_opaque, read_message_frame, write_frame,
};

pub const LOCAL_CONTEXT_EXTENSION: &str = "ucr.transport.local.context.v1";
const LOCAL_SCOPE_DOMAIN: &[u8] = b"UCR-LOCAL-SCOPE-V1\0";

#[derive(Debug)]
pub struct LocalTransportIdentity {
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
pub enum LocalHandshakeError {
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

impl LocalTransportIdentity {
    /// Validates static local identity material before any socket side effect.
    ///
    /// # Errors
    /// Returns `InvalidLocalIdentity` for malformed signing material or local capability state.
    pub fn validate(&self) -> Result<(), LocalHandshakeError> {
        validate_trusted_signing_key_descriptor(&self.signing_descriptor)
            .map_err(|_| LocalHandshakeError::InvalidLocalIdentity)?;
        if self.signing_descriptor.public_key.as_slice() != self.signing_key.verifying_key().0 {
            return Err(LocalHandshakeError::InvalidLocalIdentity);
        }
        let local = self
            .hello_template
            .capabilities
            .iter()
            .filter(|capability| capability.id == LOCAL_TCP_CAPABILITY)
            .collect::<Vec<_>>();
        if local.len() != 1
            || !matches!(
                local[0].maturity,
                CapabilityMaturity::Prepared
                    | CapabilityMaturity::Beta
                    | CapabilityMaturity::Production
            )
            || self
                .hello_template
                .extensions
                .iter()
                .any(|extension| extension.name == LOCAL_CONTEXT_EXTENSION)
        {
            return Err(LocalHandshakeError::InvalidLocalIdentity);
        }
        Ok(())
    }

    fn fresh_hello(&self) -> Result<PeerHello, LocalHandshakeError> {
        self.validate()?;
        let mut hello = self.hello_template.clone();
        hello.nonce = generate_handshake_nonce().map_err(|_| LocalHandshakeError::LocalCrypto)?;
        hello
            .extensions
            .push(local_context_extension(&self.endpoint_id, &self.scope));
        Ok(hello)
    }

    fn effective_policy(&self) -> NegotiationPolicy {
        let mut policy = self.negotiation_policy.clone();
        if !policy
            .required_capabilities
            .iter()
            .any(|requirement| requirement.id == LOCAL_TCP_CAPABILITY)
        {
            policy.required_capabilities.push(CapabilityRequirement {
                id: LOCAL_TCP_CAPABILITY.to_owned(),
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
    ) -> Result<(), LocalHandshakeError> {
        let expectation = self
            .peer_expectations
            .expected_peer(&self.scope, endpoint_id)
            .map_err(LocalHandshakeError::PeerExpectation)?;
        if descriptor.device_id != expectation.device_id {
            return Err(LocalHandshakeError::PeerDeviceMismatch);
        }
        if expectation
            .signing_key_id
            .as_ref()
            .is_some_and(|expected| descriptor.key_id != *expected)
        {
            return Err(LocalHandshakeError::PeerKeyMismatch);
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

fn local_context_extension(endpoint_id: &EndpointId, scope: &TenantScope) -> ProtocolExtension {
    let context = pb::InternetTransportContext {
        endpoint_id: Some(pb_opaque(endpoint_id.as_opaque())),
        scope_binding: local_scope_binding(scope).to_vec(),
    };
    ProtocolExtension {
        name: LOCAL_CONTEXT_EXTENSION.to_owned(),
        critical: true,
        payload: context.encode_to_vec(),
    }
}

fn endpoint_from_local_context(
    hello: &PeerHello,
    scope: &TenantScope,
) -> Result<EndpointId, WireError> {
    let mut matches = hello
        .extensions
        .iter()
        .filter(|extension| extension.name == LOCAL_CONTEXT_EXTENSION);
    let extension = matches.next().ok_or(WireError::InvalidValue)?;
    if matches.next().is_some() || !extension.critical {
        return Err(WireError::InvalidValue);
    }
    let context = pb::InternetTransportContext::decode(extension.payload.as_slice())
        .map_err(|_| WireError::Decode)?;
    if context.scope_binding.as_slice() != local_scope_binding(scope) {
        return Err(WireError::InvalidValue);
    }
    let endpoint = decode_opaque(&context.endpoint_id.ok_or(WireError::InvalidValue)?)?;
    Ok(EndpointId::from_opaque(endpoint))
}

fn local_scope_binding(scope: &TenantScope) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(LOCAL_SCOPE_DOMAIN);
    hash_len_prefixed(&mut hasher, scope.tenant_id.as_opaque().as_wire_bytes());
    match &scope.namespace_id {
        Some(namespace) => {
            hasher.update([1]);
            hash_len_prefixed(&mut hasher, namespace.as_opaque().as_wire_bytes());
        }
        None => hasher.update([0]),
    }
    hasher.finalize().into()
}

fn hash_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn read_peer_hello_and_key(
    stream: &mut TcpStream,
    scope: &TenantScope,
) -> Result<PeerHandshakeMaterial, LocalHandshakeError> {
    let (hello_frame, hello_pb) =
        read_message_frame::<pb::NegotiationHello>(stream, ucr_protocol::FrameKind::Hello)
            .map_err(map_wire)?;
    let hello = decode_hello(hello_pb).map_err(map_wire)?;
    let endpoint_id = endpoint_from_local_context(&hello, scope).map_err(map_wire)?;
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

pub(crate) fn initiate_local_handshake(
    stream: &mut TcpStream,
    identity: &LocalTransportIdentity,
    expected_peer_endpoint: &EndpointId,
) -> Result<EstablishedSession, LocalHandshakeError> {
    let local_hello = identity.fresh_hello()?;
    let local_hello_frame = encode_hello(&local_hello).map_err(map_wire)?;
    let local_agreement =
        AgreementKeyPair::generate().map_err(|_| LocalHandshakeError::LocalCrypto)?;
    let local_public = local_agreement.public_key();
    write_frame(stream, &local_hello_frame).map_err(map_wire)?;
    let key_frame = key_exchange_frame(local_public).map_err(map_wire)?;
    write_frame(stream, &key_frame).map_err(map_wire)?;
    let peer = read_peer_hello_and_key(stream, &identity.scope)?;
    if peer.endpoint_id != *expected_peer_endpoint {
        return Err(LocalHandshakeError::PeerEndpointMismatch);
    }
    let negotiated = negotiate_session(
        &local_hello,
        &peer.hello,
        &identity.effective_policy(),
        &[LOCAL_CONTEXT_EXTENSION],
    )
    .map_err(LocalHandshakeError::Negotiation)?;
    let (result_frame, result_pb) = read_message_frame::<pb::NegotiationResult>(
        stream,
        ucr_protocol::FrameKind::NegotiationResult,
    )
    .map_err(map_wire)?;
    let received = decode_negotiation_result(result_pb).map_err(map_wire)?;
    let expected = canonical_negotiation_result(&negotiation_result_for_session(&negotiated))
        .map_err(|_| LocalHandshakeError::NegotiationMismatch)?;
    let received = canonical_negotiation_result(&received)
        .map_err(|_| LocalHandshakeError::NegotiationMismatch)?;
    if received != expected {
        return Err(LocalHandshakeError::NegotiationMismatch);
    }
    let binding = bind_handshake_transcript(
        &local_hello_frame,
        &peer.hello_frame,
        &result_frame,
        local_public,
        peer.agreement_public,
    )
    .map_err(|_| LocalHandshakeError::LocalCrypto)?;
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
    identity: &LocalTransportIdentity,
    local_agreement: AgreementKeyPair,
    local_public: ucr_crypto::AgreementPublicKey,
    binding: ucr_crypto::TranscriptBinding,
    peer: &PeerHandshakeMaterial,
    suite: ucr_model::CryptoSuite,
) -> Result<EstablishedSession, LocalHandshakeError> {
    let local_signature = identity
        .signing_key
        .sign_transcript(&binding)
        .map_err(|_| LocalHandshakeError::LocalCrypto)?;
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
    .map_err(LocalHandshakeError::Crypto)?;
    let local_confirmation = pending
        .local_confirmation_tag()
        .map_err(|_| LocalHandshakeError::LocalCrypto)?;
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
        .map_err(|error| LocalHandshakeError::Crypto(TrustedSessionError::Session(error)))
}

pub(crate) fn accept_local_handshake(
    stream: &mut TcpStream,
    identity: &LocalTransportIdentity,
) -> Result<(EstablishedSession, EndpointId), LocalHandshakeError> {
    let peer = read_peer_hello_and_key(stream, &identity.scope)?;
    let local_hello = identity.fresh_hello()?;
    let local_hello_frame = encode_hello(&local_hello).map_err(map_wire)?;
    let local_agreement =
        AgreementKeyPair::generate().map_err(|_| LocalHandshakeError::LocalCrypto)?;
    let local_public = local_agreement.public_key();
    write_frame(stream, &local_hello_frame).map_err(map_wire)?;
    write_frame(stream, &key_exchange_frame(local_public).map_err(map_wire)?).map_err(map_wire)?;
    let negotiated = negotiate_session(
        &local_hello,
        &peer.hello,
        &identity.effective_policy(),
        &[LOCAL_CONTEXT_EXTENSION],
    )
    .map_err(LocalHandshakeError::Negotiation)?;
    let (result_frame, _) = encode_negotiation_result(&negotiated).map_err(map_wire)?;
    write_frame(stream, &result_frame).map_err(map_wire)?;
    let binding = bind_handshake_transcript(
        &peer.hello_frame,
        &local_hello_frame,
        &result_frame,
        peer.agreement_public,
        local_public,
    )
    .map_err(|_| LocalHandshakeError::LocalCrypto)?;
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
    identity: &LocalTransportIdentity,
    local_agreement: AgreementKeyPair,
    local_public: ucr_crypto::AgreementPublicKey,
    binding: ucr_crypto::TranscriptBinding,
    peer: PeerHandshakeMaterial,
    suite: ucr_model::CryptoSuite,
) -> Result<(EstablishedSession, EndpointId), LocalHandshakeError> {
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
        .map_err(|_| LocalHandshakeError::LocalCrypto)?;
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
    .map_err(LocalHandshakeError::Crypto)?;
    let (_, peer_confirmation) =
        read_message_frame::<pb::KeyConfirmation>(stream, ucr_protocol::FrameKind::KeyConfirmation)
            .map_err(map_wire)?;
    let peer_confirmation = decode_confirmation(peer_confirmation, &binding).map_err(map_wire)?;
    let local_confirmation = pending
        .local_confirmation_tag()
        .map_err(|_| LocalHandshakeError::LocalCrypto)?;
    write_frame(
        stream,
        &confirmation_frame(&binding, local_confirmation).map_err(map_wire)?,
    )
    .map_err(map_wire)?;
    let session = pending
        .confirm_peer(peer_confirmation)
        .map_err(|error| LocalHandshakeError::Crypto(TrustedSessionError::Session(error)))?;
    Ok((session, peer.endpoint_id))
}

fn map_wire(error: WireError) -> LocalHandshakeError {
    match error {
        WireError::Io(std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock) => {
            LocalHandshakeError::WireTimeout
        }
        WireError::Io(
            std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::NotConnected
            | std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::BrokenPipe,
        ) => LocalHandshakeError::WireUnavailable,
        WireError::Io(_)
        | WireError::Frame
        | WireError::Encode
        | WireError::Decode
        | WireError::UnexpectedFrameKind
        | WireError::InvalidValue
        | WireError::PayloadTooLarge => LocalHandshakeError::WireMalformed,
    }
}
