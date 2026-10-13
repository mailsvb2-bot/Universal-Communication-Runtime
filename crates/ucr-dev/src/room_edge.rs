//! Loopback TURN and encrypted recording for the local room.
//!
//! Coturn is a test deployment on host loopback. Recording stores ciphertext in an
//! encrypted archive. Neither path advertises Production WebRTC or a horizontal SFU.

use std::{
    fs,
    net::SocketAddr,
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::{net::TcpStream, time::sleep};
use ucr_api_grpc::RealtimeValidatedMediaObserver;
use ucr_core::{
    RecordingMediaProvider, RecordingProviderCaptureContext, RecordingProviderError,
    RecordingProviderOperation, RecordingProviderRequest,
};
use ucr_model::{CallId, IceTransportPolicy, OpaqueId, RecordingId, TenantScope};
use ucr_protocol::{CanonicalError, CanonicalErrorCode};
use ucr_recording::EncryptedArchiveRecordingProvider;
use ucr_secrets::{
    ActiveSecretSet, SecretHandle, SecretMaterial, SecretProvider, SecretProviderError,
    SecretProviderHealth, SecretPurpose, SecretVersion,
};
use ucr_sfu::SfuValidatedSourceFrame;
use ucr_webrtc::{TurnRestCredentialIssuer, TurnRestSecret, WebRtcSessionConfigFactory};

const TURN_PORT: u16 = 53_478;
const TURN_REALM: &str = "ucr-local-room";
const TURN_TTL_SECONDS: u32 = 600;

pub(crate) struct RoomEdge {
    turn_process: Mutex<Child>,
    turn_config: std::path::PathBuf,
    pub(crate) recorder: Arc<RoomRecorder>,
    config: Arc<WebRtcSessionConfigFactory>,
}

pub(crate) struct RoomRecorder {
    provider: Arc<EncryptedArchiveRecordingProvider>,
    active: Mutex<Option<RecordingProviderCaptureContext>>,
}

struct StaticSecret {
    handle: SecretHandle,
    version: SecretVersion,
}

impl RoomEdge {
    pub(crate) async fn start() -> Result<Self, String> {
        let turn_secret = random_ascii_key()?;
        let (mut turn_process, turn_config) = spawn_turn(&turn_secret)?;
        if let Err(error) = wait_for_turn(&mut turn_process).await {
            abandon_turn(&mut turn_process, &turn_config);
            return Err(error);
        }
        let key: [u8; 32] = turn_secret
            .as_bytes()
            .try_into()
            .map_err(|_| "TURN secret must be 32 bytes".to_owned())?;
        let config = match WebRtcSessionConfigFactory::new(
            Vec::new(),
            vec![
                format!("turn:127.0.0.1:{TURN_PORT}?transport=udp"),
                format!("turn:127.0.0.1:{TURN_PORT}?transport=tcp"),
            ],
            Some(TurnRestCredentialIssuer::new(TurnRestSecret::from_bytes(
                key,
            ))),
            TURN_TTL_SECONDS,
            IceTransportPolicy::All,
        ) {
            Ok(config) => config,
            Err(error) => {
                abandon_turn(&mut turn_process, &turn_config);
                return Err(format!("TURN session config: {error:?}"));
            }
        };
        let recorder = match RoomRecorder::start() {
            Ok(recorder) => recorder,
            Err(error) => {
                abandon_turn(&mut turn_process, &turn_config);
                return Err(error);
            }
        };
        println!("UCR_ROOM_TURN=turn:127.0.0.1:{TURN_PORT}?transport=tcp");
        Ok(Self {
            turn_process: Mutex::new(turn_process),
            turn_config,
            recorder,
            config: Arc::new(config),
        })
    }

    pub(crate) fn config(this: &Self) -> Arc<WebRtcSessionConfigFactory> {
        Arc::clone(&this.config)
    }

    pub(crate) fn capabilities(&self) -> ucr_api_grpc::UniversalConferenceRuntimeCapabilities {
        let _ = &self.turn_process;
        ucr_api_grpc::UniversalConferenceRuntimeCapabilities {
            browser_realtime_gateway: true,
            production_webrtc: false,
            turn: true,
            recording: true,
            horizontal_sfu: false,
        }
    }
}

impl Drop for RoomEdge {
    fn drop(&mut self) {
        if let Ok(mut process) = self.turn_process.lock() {
            stop_turn(&mut process);
        }
        let _ = fs::remove_file(&self.turn_config);
    }
}

impl RoomRecorder {
    fn start() -> Result<Arc<Self>, String> {
        let root = std::env::temp_dir().join(format!("ucr-room-recordings-{}", std::process::id()));
        let handle = SecretHandle {
            secret_id: OpaqueId::new("room-recording-at-rest")
                .map_err(|_| "recording secret id is invalid".to_owned())?,
            purpose: SecretPurpose::RecordingAtRest,
        };
        let version = SecretVersion {
            version_id: OpaqueId::new("v1")
                .map_err(|_| "recording secret version is invalid".to_owned())?,
            material: SecretMaterial::new(random_ascii_key()?.into_bytes())
                .map_err(|_| "recording key was rejected".to_owned())?,
        };
        let provider = Arc::new(
            EncryptedArchiveRecordingProvider::new(
                root.clone(),
                Arc::new(StaticSecret {
                    handle: handle.clone(),
                    version,
                }),
                handle,
            )
            .map_err(|error| format!("recording archive: {error:?}"))?,
        );
        println!(
            "UCR_ROOM_RECORDING=encrypted-archive path={}",
            root.display()
        );
        Ok(Arc::new(Self {
            provider,
            active: Mutex::new(None),
        }))
    }

    pub(crate) fn begin(
        &self,
        scope: TenantScope,
        recording_id: RecordingId,
        call_id: CallId,
        lifecycle_revision: u64,
        expires_at_unix_ms: i64,
    ) -> Result<(), String> {
        let request = RecordingProviderRequest {
            scope: scope.clone(),
            recording_id: recording_id.clone(),
            call_id: call_id.clone(),
            lifecycle_revision,
            operation: RecordingProviderOperation::Start,
            expires_at_unix_ms,
        };
        self.provider
            .apply(&request)
            .map_err(|error| format!("start recording archive: {error:?}"))?;
        *self
            .active
            .lock()
            .map_err(|_| "recording lock poisoned".to_owned())? =
            Some(RecordingProviderCaptureContext {
                scope,
                recording_id,
                call_id,
                lifecycle_revision,
                expires_at_unix_ms,
            });
        Ok(())
    }

    pub(crate) fn end(
        &self,
        recording_id: &RecordingId,
        lifecycle_revision: u64,
    ) -> Result<(), String> {
        let context = {
            let mut active = self
                .active
                .lock()
                .map_err(|_| "recording lock poisoned".to_owned())?;
            let Some(context) = active.clone() else {
                return Ok(());
            };
            if context.recording_id != *recording_id {
                return Ok(());
            }
            active.take();
            context
        };
        let request = RecordingProviderRequest {
            scope: context.scope,
            recording_id: context.recording_id,
            call_id: context.call_id,
            lifecycle_revision,
            operation: RecordingProviderOperation::Stop,
            expires_at_unix_ms: context.expires_at_unix_ms,
        };
        self.provider
            .apply(&request)
            .map_err(|error| format!("stop recording archive: {error:?}"))?;
        Ok(())
    }
}

impl std::fmt::Debug for RoomRecorder {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RoomRecorder")
            .field("provider", &self.provider.provider_id())
            .finish_non_exhaustive()
    }
}

impl RealtimeValidatedMediaObserver for RoomRecorder {
    fn observe_validated_media(
        &self,
        frame: &SfuValidatedSourceFrame,
    ) -> Result<(), CanonicalError> {
        let active = self
            .active
            .lock()
            .map_err(|_| CanonicalError::new(CanonicalErrorCode::TemporarilyUnavailable))?
            .clone();
        let Some(context) = active else {
            return Ok(());
        };
        let media = &frame.envelope().frame;
        if context.call_id != media.header.call_id {
            return Ok(());
        }
        self.provider
            .capture_encrypted_frame(&context, media)
            .map_err(capture_error)
    }
}

impl StaticSecret {
    fn set(&self) -> ActiveSecretSet {
        ActiveSecretSet {
            handle: self.handle.clone(),
            current: self.version.clone(),
            previous: None,
        }
    }
}

impl std::fmt::Debug for StaticSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StaticSecret")
            .field("handle", &self.handle)
            .finish_non_exhaustive()
    }
}

impl SecretProvider for StaticSecret {
    fn provider_id(&self) -> &'static str {
        "room-static"
    }

    fn health(&self) -> SecretProviderHealth {
        SecretProviderHealth::Healthy
    }

    fn active_secret_set(
        &self,
        handle: &SecretHandle,
    ) -> Result<ActiveSecretSet, SecretProviderError> {
        if handle == &self.handle {
            Ok(self.set())
        } else {
            Err(SecretProviderError::NotFound)
        }
    }

    fn rotate(
        &self,
        _handle: &SecretHandle,
        _new_version: SecretVersion,
    ) -> Result<ActiveSecretSet, SecretProviderError> {
        Err(SecretProviderError::Conflict)
    }
}

fn capture_error(error: RecordingProviderError) -> CanonicalError {
    CanonicalError::new(match error {
        RecordingProviderError::Conflict => CanonicalErrorCode::Conflict,
        RecordingProviderError::CapacityExceeded => CanonicalErrorCode::ResourceExhausted,
        RecordingProviderError::TemporarilyUnavailable => {
            CanonicalErrorCode::TemporarilyUnavailable
        }
        RecordingProviderError::PolicyDenied => CanonicalErrorCode::PolicyDenied,
        RecordingProviderError::Internal => CanonicalErrorCode::Internal,
    })
}

fn stop_turn(process: &mut Child) {
    let _ = process.kill();
    let _ = process.wait();
}

fn abandon_turn(process: &mut Child, config: &std::path::Path) {
    stop_turn(process);
    let _ = fs::remove_file(config);
}

fn random_ascii_key() -> Result<String, String> {
    let mut raw = [0_u8; 16];
    fs::File::open("/dev/urandom")
        .and_then(|mut file| std::io::Read::read_exact(&mut file, &mut raw))
        .map_err(|error| format!("random key: {error}"))?;
    Ok(super::hex(&raw))
}

fn spawn_turn(secret: &str) -> Result<(Child, std::path::PathBuf), String> {
    let config_path =
        std::env::temp_dir().join(format!("ucr-room-turn-{}.conf", std::process::id()));
    let config = format!(
        "listening-ip=127.0.0.1\n\
         relay-ip=127.0.0.1\n\
         external-ip=127.0.0.1\n\
         listening-port={TURN_PORT}\n\
         min-port=53500\n\
         max-port=53520\n\
         use-auth-secret\n\
         static-auth-secret={secret}\n\
         realm={TURN_REALM}\n\
         no-tls\n\
         no-dtls\n\
         no-cli\n\
         fingerprint\n\
         pidfile=/tmp/ucr-room-turn.pid\n\
         log-file=/tmp/ucr-room-turn.log\n"
    );
    fs::write(&config_path, config).map_err(|error| format!("write TURN config: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("protect TURN config: {error}"))?;
    }
    match Command::new("turnserver")
        .arg("-c")
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => Ok((child, config_path)),
        Err(error) => {
            let _ = fs::remove_file(&config_path);
            Err(format!("start coturn: {error}"))
        }
    }
}

async fn wait_for_turn(turn_process: &mut Child) -> Result<(), String> {
    let address = SocketAddr::from(([127, 0, 0, 1], TURN_PORT));
    for _ in 0..50 {
        if TcpStream::connect(address).await.is_ok() {
            return Ok(());
        }
        if turn_process
            .try_wait()
            .map_err(|error| format!("coturn status: {error}"))?
            .is_some()
        {
            return Err("coturn exited before it accepted connections".to_owned());
        }
        sleep(Duration::from_millis(100)).await;
    }
    Err("coturn did not accept loopback connections".to_owned())
}
