#![forbid(unsafe_code)]

use wasm_bindgen::prelude::*;

use openmls_rust_crypto::OpenMlsRustCrypto;
use ucr_crypto::{
    GroupMediaEpochSecret, SigningKeyMaterial, VerifyingKeyBytes, open_endpoint_group_media_wire,
    seal_endpoint_group_media_wire,
};
use ucr_group_mls::{
    MlsGroupState, create_device_key_package, export_group_media_secret, join_from_welcome,
    process_commit,
};
use ucr_model::{
    CallId, CryptoSuite, DeviceId, GroupCryptoState, GroupId, GroupMediaE2eeContext,
    GroupMediaFrameHeader, KeyId, MediaKind, NamespaceId, OpaqueId, PrincipalId, PrincipalKind,
    PrincipalRef, TenantId, TenantScope, VideoSourceKind,
};
use ucr_protocol::{GROUP_MLS_CAPABILITY, SFU_FORWARD_WIRE_VERSION};

const ENDPOINT_WASM_CONTRACT_VERSION: &str = "ucr.endpoint-wasm.v1";

#[wasm_bindgen]
pub fn endpoint_wasm_contract_version() -> String {
    ENDPOINT_WASM_CONTRACT_VERSION.to_owned()
}

/// Browser-owned RFC 9420 state.
///
/// The endpoint creates and retains its own MLS private material, consumes Welcome/commit
/// messages locally, and derives the media epoch secret from the verified local MLS state.
/// No MLS exporter secret crosses the public UCR/server boundary.
#[wasm_bindgen]
pub struct EndpointMlsState {
    provider: OpenMlsRustCrypto,
    scope: TenantScope,
    group_id: GroupId,
    device_id: DeviceId,
    key_package: Vec<u8>,
    group: Option<MlsGroupState>,
    state: Option<GroupCryptoState>,
}

#[wasm_bindgen]
impl EndpointMlsState {
    #[wasm_bindgen(constructor)]
    pub fn new(
        tenant_id: String,
        namespace_id: Option<String>,
        group_id: String,
        device_id: String,
    ) -> Result<EndpointMlsState, JsValue> {
        let scope = tenant_scope(tenant_id, namespace_id)?;
        let group_id = GroupId::from_opaque(opaque(group_id, "group_id")?);
        let device_id = DeviceId::from_opaque(opaque(device_id, "device_id")?);
        let provider = OpenMlsRustCrypto::default();
        let key_package = create_device_key_package(&provider, &scope, &device_id)
            .map_err(debug_error)?
            .bytes;

        Ok(Self {
            provider,
            scope,
            group_id,
            device_id,
            key_package,
            group: None,
            state: None,
        })
    }

    /// Public RFC 9420 KeyPackage to submit through the canonical UCR admission flow.
    pub fn key_package(&self) -> Vec<u8> {
        self.key_package.clone()
    }

    /// Join an already-authorized group from a Welcome message.
    pub fn join_from_welcome(
        &mut self,
        welcome: &[u8],
        crypto_epoch: u64,
        crypto_state_ref: String,
    ) -> Result<(), JsValue> {
        if self.group.is_some() {
            return Err(js_error("mls_state: group already joined"));
        }
        let expected = group_crypto_state(crypto_epoch, crypto_state_ref)?;
        let group = join_from_welcome(
            &self.provider,
            &self.scope,
            &self.group_id,
            welcome,
            &expected,
        )
        .map_err(debug_error)?;
        self.group = Some(group);
        self.state = Some(expected);
        Ok(())
    }

    /// Apply and merge one canonical MLS commit and advance the local verified state.
    pub fn process_commit(
        &mut self,
        commit: &[u8],
        crypto_epoch: u64,
        crypto_state_ref: String,
    ) -> Result<(), JsValue> {
        let expected = group_crypto_state(crypto_epoch, crypto_state_ref)?;
        let group = self
            .group
            .as_mut()
            .ok_or_else(|| js_error("mls_state: group not joined"))?;
        process_commit(
            &self.provider,
            group,
            &self.scope,
            &self.group_id,
            commit,
            &expected,
        )
        .map_err(debug_error)?;
        self.state = Some(expected);
        Ok(())
    }

    pub fn crypto_epoch(&self) -> Result<u64, JsValue> {
        self.state
            .as_ref()
            .map(|state| state.epoch)
            .ok_or_else(|| js_error("mls_state: group not joined"))
    }

    /// Build a media bridge from the endpoint-local MLS exporter secret.
    ///
    /// The media signing seed remains endpoint-owned input for now; the MLS exporter secret is
    /// never accepted from JavaScript or fetched from a server API.
    #[allow(clippy::too_many_arguments)]
    pub fn media_bridge(
        &self,
        call_id: String,
        negotiation_ref: String,
        negotiation_generation: u64,
        source_principal_id: String,
        source_principal_kind: u8,
        signing_key_id: String,
        signing_seed: &[u8],
    ) -> Result<EndpointGroupMediaBridge, JsValue> {
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| js_error("mls_state: group not joined"))?;
        let group = self
            .group
            .as_ref()
            .ok_or_else(|| js_error("mls_state: group not joined"))?;
        let epoch_secret =
            export_group_media_secret(&self.provider, group, &self.scope, &self.group_id, state)
                .map_err(debug_error)?;
        let signing_seed = fixed_32(signing_seed, "signing_seed")?;
        let source = PrincipalRef {
            principal_id: PrincipalId::from_opaque(opaque(
                source_principal_id,
                "source_principal_id",
            )?),
            kind: principal_kind(source_principal_kind)?,
        };
        let crypto_state_ref = state
            .state_ref
            .clone()
            .ok_or_else(|| js_error("mls_state: missing crypto state reference"))?;
        let context = GroupMediaE2eeContext {
            scope: self.scope.clone(),
            call_id: CallId::from_opaque(opaque(call_id, "call_id")?),
            group_id: self.group_id.clone(),
            negotiation_ref: opaque(negotiation_ref, "negotiation_ref")?,
            negotiation_generation,
            crypto_epoch: state.epoch,
            crypto_state_ref,
            crypto_suite: CryptoSuite::UcrV1,
        };

        Ok(EndpointGroupMediaBridge {
            context,
            epoch_secret,
            signer: SigningKeyMaterial::from_seed(signing_seed),
            signing_key_id: KeyId::from_opaque(opaque(signing_key_id, "signing_key_id")?),
            source,
            source_device_id: self.device_id.clone(),
        })
    }
}

#[wasm_bindgen]
pub struct EndpointGroupMediaBridge {
    context: GroupMediaE2eeContext,
    epoch_secret: GroupMediaEpochSecret,
    signer: SigningKeyMaterial,
    signing_key_id: KeyId,
    source: PrincipalRef,
    source_device_id: DeviceId,
}

#[wasm_bindgen]
impl EndpointGroupMediaBridge {
    #[wasm_bindgen(constructor)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant_id: String,
        namespace_id: Option<String>,
        call_id: String,
        group_id: String,
        negotiation_ref: String,
        negotiation_generation: u64,
        crypto_epoch: u64,
        crypto_state_ref: String,
        source_principal_id: String,
        source_principal_kind: u8,
        source_device_id: String,
        signing_key_id: String,
        epoch_secret: &[u8],
        signing_seed: &[u8],
    ) -> Result<EndpointGroupMediaBridge, JsValue> {
        let epoch_secret = fixed_32(epoch_secret, "epoch_secret")?;
        let signing_seed = fixed_32(signing_seed, "signing_seed")?;
        let scope = tenant_scope(tenant_id, namespace_id)?;
        let source = PrincipalRef {
            principal_id: PrincipalId::from_opaque(opaque(
                source_principal_id,
                "source_principal_id",
            )?),
            kind: principal_kind(source_principal_kind)?,
        };
        let source_device_id = DeviceId::from_opaque(opaque(source_device_id, "source_device_id")?);
        let context = GroupMediaE2eeContext {
            scope,
            call_id: CallId::from_opaque(opaque(call_id, "call_id")?),
            group_id: GroupId::from_opaque(opaque(group_id, "group_id")?),
            negotiation_ref: opaque(negotiation_ref, "negotiation_ref")?,
            negotiation_generation,
            crypto_epoch,
            crypto_state_ref: opaque(crypto_state_ref, "crypto_state_ref")?,
            crypto_suite: CryptoSuite::UcrV1,
        };
        Ok(Self {
            context,
            epoch_secret: GroupMediaEpochSecret::from_exporter_bytes(epoch_secret),
            signer: SigningKeyMaterial::from_seed(signing_seed),
            signing_key_id: KeyId::from_opaque(opaque(signing_key_id, "signing_key_id")?),
            source,
            source_device_id,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn seal_wire(
        &self,
        stream_id: String,
        media_kind: u8,
        video_source_kind: u8,
        sequence: u64,
        media_timestamp: u64,
        keyframe: bool,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, JsValue> {
        let media_kind = media_kind_from_code(media_kind)?;
        let video_source_kind = video_source_kind_from_code(media_kind, video_source_kind)?;
        let header = GroupMediaFrameHeader {
            scope: self.context.scope.clone(),
            call_id: self.context.call_id.clone(),
            group_id: self.context.group_id.clone(),
            stream_id: opaque(stream_id, "stream_id")?,
            source: self.source.clone(),
            source_device_id: self.source_device_id.clone(),
            negotiation_ref: self.context.negotiation_ref.clone(),
            negotiation_generation: self.context.negotiation_generation,
            crypto_epoch: self.context.crypto_epoch,
            crypto_state_ref: self.context.crypto_state_ref.clone(),
            crypto_suite: self.context.crypto_suite,
            header_version: SFU_FORWARD_WIRE_VERSION,
            media_kind,
            video_source_kind,
            sequence,
            media_timestamp,
            keyframe,
        };
        seal_endpoint_group_media_wire(
            &self.epoch_secret,
            &self.context,
            header,
            plaintext,
            self.signing_key_id.clone(),
            &self.signer,
        )
        .map_err(debug_error)
    }

    pub fn open_wire(&self, wire: &[u8], source_verifying_key: &[u8]) -> Result<Vec<u8>, JsValue> {
        let source_verifying_key = fixed_32(source_verifying_key, "source_verifying_key")?;
        open_endpoint_group_media_wire(
            &self.epoch_secret,
            &self.context,
            wire,
            VerifyingKeyBytes(source_verifying_key),
        )
        .map_err(debug_error)
    }

    pub fn local_verifying_key(&self) -> Vec<u8> {
        self.signer.verifying_key().0.to_vec()
    }
}

fn tenant_scope(tenant_id: String, namespace_id: Option<String>) -> Result<TenantScope, JsValue> {
    Ok(TenantScope {
        tenant_id: TenantId::from_opaque(opaque(tenant_id, "tenant_id")?),
        namespace_id: match namespace_id {
            Some(value) => Some(NamespaceId::from_opaque(opaque(value, "namespace_id")?)),
            None => None,
        },
    })
}

fn group_crypto_state(
    crypto_epoch: u64,
    crypto_state_ref: String,
) -> Result<GroupCryptoState, JsValue> {
    Ok(GroupCryptoState {
        capability_id: Some(GROUP_MLS_CAPABILITY.to_owned()),
        epoch: crypto_epoch,
        state_ref: Some(opaque(crypto_state_ref, "crypto_state_ref")?),
    })
}

fn opaque(value: String, field: &str) -> Result<OpaqueId, JsValue> {
    OpaqueId::new(value).map_err(|error| js_error(&format!("{field}: {error:?}")))
}

fn fixed_32(value: &[u8], field: &str) -> Result<[u8; 32], JsValue> {
    value
        .try_into()
        .map_err(|_| js_error(&format!("{field}: expected exactly 32 bytes")))
}

fn principal_kind(code: u8) -> Result<PrincipalKind, JsValue> {
    match code {
        1 => Ok(PrincipalKind::Person),
        2 => Ok(PrincipalKind::Device),
        3 => Ok(PrincipalKind::ServiceAccount),
        4 => Ok(PrincipalKind::AiAgent),
        5 => Ok(PrincipalKind::Bot),
        6 => Ok(PrincipalKind::Organization),
        7 => Ok(PrincipalKind::Automation),
        8 => Ok(PrincipalKind::ExternalPlatform),
        _ => Err(js_error("source_principal_kind: unsupported code")),
    }
}

fn media_kind_from_code(code: u8) -> Result<MediaKind, JsValue> {
    match code {
        1 => Ok(MediaKind::Audio),
        2 => Ok(MediaKind::Video),
        _ => Err(js_error("media_kind: unsupported code")),
    }
}

fn video_source_kind_from_code(
    media_kind: MediaKind,
    code: u8,
) -> Result<Option<VideoSourceKind>, JsValue> {
    match (media_kind, code) {
        (MediaKind::Audio, 0) => Ok(None),
        (MediaKind::Video, 1) => Ok(Some(VideoSourceKind::Camera)),
        (MediaKind::Video, 2) => Ok(Some(VideoSourceKind::ScreenShare)),
        _ => Err(js_error("video_source_kind: invalid media/source pairing")),
    }
}

fn debug_error(error: impl core::fmt::Debug) -> JsValue {
    js_error(&format!("{error:?}"))
}

fn js_error(message: &str) -> JsValue {
    JsValue::from_str(message)
}
