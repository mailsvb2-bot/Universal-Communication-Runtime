//! Loopback room for a local webinar or call.
//!
//! The technical conference owner stays on the server so every human participant
//! can hold an endpoint MLS key. Human roles are speaker or attendee. Signing
//! seeds never leave the browser; this process stores only the public key.

use std::{
    io::Read,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Mutex as AsyncMutex,
};
use tonic::Request;
use ucr_api_grpc::pb;
use ucr_core::{
    DeviceLifecycleStore, GroupCallLookupStore, IdentityDeviceLookupStore,
    MAX_ACTIVE_RECORDINGS_PER_CALL, PrincipalIdentityBindingStore, RecordingStore,
    TrustedSigningKeyStore, UniversalConferenceStore, recording_allows_realtime_participant,
};
use ucr_model::{
    CallSession, ConferenceParticipantRole, DeviceId, DeviceLifecycleState, GroupId, IntegrationId,
    OpaqueId, PrincipalRef, RecordingId, RecordingSession, RecordingState,
};
use ucr_protocol::{ALGORITHM_VERSION, KEY_FORMAT_VERSION, SIGNATURE_ALGORITHM_ID};

use super::{DevEnvironment, attach_dev_credential, opaque, pb_id, pb_scope, wire_text};

const OWNER_EXTERNAL_ID: &[u8] = b"room-owner";
const CONFERENCE_EXTERNAL_ID: &[u8] = b"local-room";
const MAX_HTTP_BYTES: usize = 16 * 1024;

struct RoomHost {
    env: Arc<DevEnvironment>,
    grpc: String,
    state: Mutex<RoomState>,
    /// Serializes conference creation and the Waiting → Live transition.
    /// Two creators would mint different schedules and conflict, and a second
    /// join must not request Waiting after the conference is already Live.
    open_gate: AsyncMutex<()>,
    /// Serializes archive start and stop so a newcomer and the watcher cannot
    /// seal and unseal the same recording at once.
    recording_gate: AsyncMutex<()>,
    edge: Option<Arc<super::room_edge::RoomEdge>>,
}

struct RoomState {
    conference_id: Option<pb::OpaqueId>,
    opened: bool,
    /// Next archive id. The first one keeps the historical `room-recording` label.
    recording_seq: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReserveRequest {
    display_name: String,
    role: String,
    #[serde(default)]
    external_user_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TrustRequest {
    external_user_id: String,
    key_id: String,
    public_key_base64: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeviceRequest {
    device_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JoinRequest {
    external_user_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RoomError {
    ok: bool,
    message: String,
}

pub async fn spawn(
    env: Arc<DevEnvironment>,
    grpc_bind: SocketAddr,
    room_bind: SocketAddr,
    edge: Option<Arc<super::room_edge::RoomEdge>>,
) -> Result<(), String> {
    if !room_bind.ip().is_loopback() {
        return Err("local room refuses non-loopback bind addresses".to_owned());
    }
    let listener = TcpListener::bind(room_bind)
        .await
        .map_err(|error| format!("bind local room: {error}"))?;
    let address = listener
        .local_addr()
        .map_err(|error| format!("resolve local room address: {error}"))?;
    println!("UCR_ROOM_READY api=http://{address}");
    println!("UCR_ROOM_PAGE=http://127.0.0.1:43124/room");
    println!(
        "UCR_ROOM_REALTIME=UCR_REALTIME_WEB_BIND=127.0.0.1:43124 UCR_REALTIME_GRPC_UPSTREAM=http://{grpc_bind} UCR_ROOM_API=http://{address} ucr-realtime-web"
    );
    let host = Arc::new(RoomHost {
        env,
        grpc: format!("http://{grpc_bind}"),
        state: Mutex::new(RoomState {
            conference_id: None,
            opened: false,
            recording_seq: 0,
        }),
        open_gate: AsyncMutex::new(()),
        recording_gate: AsyncMutex::new(()),
        edge,
    });
    let prewarm_host = Arc::clone(&host);
    tokio::spawn(async move {
        if let Err(error) = prewarm_when_ready(prewarm_host, grpc_bind).await {
            eprintln!("ucr room prewarm: {error}");
        }
    });
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let host = Arc::clone(&host);
                    tokio::spawn(async move {
                        if let Err(error) = handle_connection(host, stream).await {
                            eprintln!("ucr room: {error}");
                        }
                    });
                }
                Err(error) => {
                    eprintln!("ucr room accept: {error}");
                    break;
                }
            }
        }
    });
    Ok(())
}

async fn handle_connection(host: Arc<RoomHost>, mut stream: TcpStream) -> Result<(), String> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 2048];
    let HttpRequest {
        method,
        path,
        origin,
        body,
    } = loop {
        if buffer.len() > MAX_HTTP_BYTES {
            return write_response(&mut stream, 413, None, &error_body("request is too large"))
                .await;
        }
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|error| format!("read room request: {error}"))?;
        if read == 0 {
            return Ok(());
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(parsed) = parse_http(&buffer)? {
            break parsed;
        }
    };
    if !origin_allowed(origin.as_deref()) {
        return write_response(
            &mut stream,
            403,
            origin.as_deref(),
            &error_body("origin denied"),
        )
        .await;
    }
    if method == "OPTIONS" {
        return write_response(&mut stream, 204, origin.as_deref(), b"").await;
    }
    let result = dispatch(&host, &method, &path, &body).await;
    let (status, payload) = match result {
        Ok(payload) => (200, payload),
        Err(message) => (400, error_body(&message)),
    };
    write_response(&mut stream, status, origin.as_deref(), &payload).await
}

async fn dispatch(
    host: &Arc<RoomHost>,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<Vec<u8>, String> {
    if method == "GET" && path == "/healthz" {
        let turn = host.edge.is_some();
        return Ok(format!(r#"{{"ok":true,"turn":{turn},"recording":{turn}}}"#).into_bytes());
    }
    if method != "POST" {
        return Err("only POST is supported".to_owned());
    }
    match path {
        "/v1/room/reserve" => reserve(host, body).await,
        "/v1/room/trust" => trust(host, body).await,
        "/v1/room/inspect" => inspect(host, body),
        "/v1/room/join" => join(host, body).await,
        _ => Err("unknown room route".to_owned()),
    }
}

async fn reserve(host: &RoomHost, body: &[u8]) -> Result<Vec<u8>, String> {
    let request: ReserveRequest =
        serde_json::from_slice(body).map_err(|_| "invalid reserve request".to_owned())?;
    validate_display_name(&request.display_name)?;
    let role = match request.role.as_str() {
        "speaker" => pb::ConferenceParticipantRole::Speaker,
        "attendee" => pb::ConferenceParticipantRole::Attendee,
        _ => return Err("role must be speaker or attendee".to_owned()),
    };
    let conference_id = ensure_conference(host).await?;
    let external_user_id = if let Some(existing) = request
        .external_user_id
        .as_deref()
        .filter(|value| reusable_external_id(value))
    {
        if let Some(identity) = returning_human(host, &conference_id, existing, role)? {
            return reserve_body(host, existing, &identity, &request.display_name);
        }
        random_external_id()?
    } else {
        random_external_id()?
    };
    ensure_human(host, &conference_id, external_user_id.as_bytes(), role).await?;
    let identity = participant_identity(host, &conference_id, external_user_id.as_bytes())?;
    reserve_body(host, &external_user_id, &identity, &request.display_name)
}

async fn trust(host: &RoomHost, body: &[u8]) -> Result<Vec<u8>, String> {
    let request: TrustRequest =
        serde_json::from_slice(body).map_err(|_| "invalid trust request".to_owned())?;
    let conference_id = conference_id(host)?;
    let identity = participant_identity(host, &conference_id, request.external_user_id.as_bytes())?;
    if request.key_id.is_empty()
        || request.key_id.len() > 128
        || request.key_id != identity_safe(&request.key_id)
    {
        return Err("invalid device key id".to_owned());
    }
    let public_key = STANDARD
        .decode(request.public_key_base64.trim())
        .map_err(|_| "invalid public key".to_owned())?;
    if public_key.len() != 32 {
        return Err("device public key must be 32 bytes".to_owned());
    }
    let mut devices = pb::device_service_client::DeviceServiceClient::connect(host.grpc.clone())
        .await
        .map_err(|error| format!("device service: {error}"))?;
    let mut provision = Request::new(pb::DeviceProvisionTrustedSigningKeyRequest {
        scope: Some(pb_scope(&host.env.scope)),
        signing_key: Some(pb::PublicKeyDescriptor {
            key_id: Some(pb_id(&request.key_id)),
            device_id: Some(pb_id(&identity.device_id)),
            purpose: pb::KeyPurpose::Signing as i32,
            algorithm_id: SIGNATURE_ALGORITHM_ID.to_owned(),
            algorithm_version: ALGORITHM_VERSION,
            key_format_version: KEY_FORMAT_VERSION,
            public_key,
        }),
    });
    attach_dev_credential(&mut provision, &host.env);
    let provisioned = devices
        .provision_trusted_signing_key(provision)
        .await
        .map_err(|error| format!("provision trusted key: {error}"))?
        .into_inner();
    if !matches!(
        provisioned.result,
        Some(pb::device_provision_trusted_signing_key_response::Result::SigningKey(_))
    ) {
        return Err("canonical trust provisioning was denied".to_owned());
    }
    Ok(br#"{"ok":true}"#.to_vec())
}

fn inspect(host: &RoomHost, body: &[u8]) -> Result<Vec<u8>, String> {
    let request: DeviceRequest =
        serde_json::from_slice(body).map_err(|_| "invalid inspect request".to_owned())?;
    if request.device_id.is_empty() || request.device_id.len() > 128 {
        return Err("invalid device id".to_owned());
    }
    let device_id = DeviceId::from_opaque(
        OpaqueId::new(request.device_id).map_err(|_| "invalid device id".to_owned())?,
    );
    let device = host
        .env
        .store
        .device(&host.env.scope, &device_id)
        .map_err(|error| format!("device lookup: {error:?}"))?
        .ok_or_else(|| "device is not registered".to_owned())?;
    let key = host
        .env
        .store
        .active_trusted_signing_key(&host.env.scope, &device_id)
        .map_err(|error| format!("trusted key lookup: {error:?}"))?;
    let (key_id, public_key_base64) = match key.as_ref() {
        Some(descriptor) => (
            Some(wire_text(descriptor.key_id.as_opaque())),
            Some(STANDARD.encode(&descriptor.public_key)),
        ),
        None => (None, None),
    };
    // EnsureParticipantDevice marks the conference slot active before any
    // signer exists. Canonical enrollment treats "active, but no key" as a
    // recovery case and will not attach a first key. This read is the trust
    // projection: a slot is active only once it has a trusted signing key.
    // Revocation stays revocation. After the possession proof, approve reads
    // this again and must observe that same key.
    let trusted = key.is_some() && device.state == DeviceLifecycleState::Active;
    serde_json::to_vec(&serde_json::json!({
        "ok": true,
        "deviceActive": trusted,
        "deviceRevoked": device.state == DeviceLifecycleState::Revoked,
        "keyId": key_id,
        "publicKeyBase64": public_key_base64,
    }))
    .map_err(|error| format!("encode inspect response: {error}"))
}

async fn join(host: &Arc<RoomHost>, body: &[u8]) -> Result<Vec<u8>, String> {
    let request: JoinRequest =
        serde_json::from_slice(body).map_err(|_| "invalid join request".to_owned())?;
    let conference_id = conference_id(host)?;
    let identity = participant_identity(host, &conference_id, request.external_user_id.as_bytes())?;
    // An active archive only admits people already in its consent snapshot.
    // A later person used to die on realtime join with "realtime join rejected"
    // before the camera opened. End that archive first so the room stays usable.
    release_recording_for_newcomer(host, &conference_id, &identity.participant).await?;
    prepare_runtime(host, &conference_id).await?;
    if open_live(host, &conference_id).await? && host.edge.is_some() {
        let host = Arc::clone(host);
        tokio::spawn(async move {
            if let Err(error) = watch_room_recording(host).await {
                eprintln!("ucr room recording: {error}");
            }
        });
    }
    let mut conference = conference_client(host).await?;
    let mut issue = Request::new(pb::UniversalIssueJoinGrantRequest {
        scope: Some(pb_scope(&host.env.scope)),
        conference_id: Some(conference_id),
        integration_id: Some(integration_id()),
        external_user_id: request.external_user_id.as_bytes().to_vec(),
        ttl_seconds: 900,
        use_policy: pb::JoinGrantUsePolicy::Reusable as i32,
        not_before_unix_ms: None,
        not_after_unix_ms: None,
        // A signed grant lasts at most 15 minutes. Replaying one idempotency
        // key after that returns Conflict and the same person cannot re-enter.
        // The same minute reuses the current grant; the next minute can mint
        // a fresh one before the open session expires.
        idempotency_key: format!(
            "room-join-{}-{}",
            request.external_user_id,
            unix_time_ms()?.div_euclid(60_000)
        ),
    });
    attach_dev_credential(&mut issue, &host.env);
    let issued = conference
        .issue_join_grant(issue)
        .await
        .map_err(|error| format!("issue join: {error}"))?
        .into_inner();
    let grant = match issued.result {
        Some(pb::universal_issue_join_grant_response::Result::Grant(grant)) => grant,
        Some(pb::universal_issue_join_grant_response::Result::Error(error)) => {
            let code = pb::ErrorCode::try_from(error.code)
                .map_or_else(|_| error.code.to_string(), |code| format!("{code:?}"));
            return Err(format!("join grant was denied: {code}"));
        }
        None => return Err("join grant was denied".to_owned()),
    };
    let fragment = grant
        .join_url
        .split_once("#ucr_join=")
        .map(|(_, token)| format!("#ucr_join={token}"))
        .ok_or_else(|| "join grant is malformed".to_owned())?;
    serde_json::to_vec(&serde_json::json!({
        "ok": true,
        "joinFragment": fragment,
    }))
    .map_err(|error| format!("encode join response: {error}"))
}

async fn ensure_conference(host: &RoomHost) -> Result<pb::OpaqueId, String> {
    let _gate = host.open_gate.lock().await;
    if let Ok(existing) = conference_id(host) {
        return Ok(existing);
    }
    let now = unix_time_ms()?;
    let mut conference = conference_client(host).await?;
    let integration_id = integration_id();
    let mut create = Request::new(pb::UniversalCreateConferenceRequest {
        scope: Some(pb_scope(&host.env.scope)),
        integration_id: Some(integration_id.clone()),
        external_conference_id: CONFERENCE_EXTERNAL_ID.to_vec(),
        idempotency_key: "room-create".to_owned(),
        mode: pb::UniversalConferenceMode::Webinar as i32,
        // The development room lives as long as this process. A planned end
        // rejects the next 15-minute grant once that grant would extend past
        // the window, so a room left running for about an hour stops admitting
        // people with "join grant was denied".
        schedule: Some(pb::ConferenceScheduleMetadata {
            starts_at_unix_ms: now,
            planned_end_unix_ms: None,
            join_before_seconds: 900,
            join_after_seconds: 0,
            timezone: Some("UTC".to_owned()),
        }),
        metadata: Vec::new(),
    });
    attach_dev_credential(&mut create, &host.env);
    let created = conference
        .create_conference(create)
        .await
        .map_err(|error| format!("create conference: {error}"))?
        .into_inner();
    let Some(pb::universal_create_conference_response::Result::Conference(descriptor)) =
        created.result
    else {
        return Err("conference creation was denied".to_owned());
    };
    let conference_id = descriptor
        .conference_id
        .ok_or_else(|| "conference id is missing".to_owned())?;
    ensure_human(
        host,
        &conference_id,
        OWNER_EXTERNAL_ID,
        pb::ConferenceParticipantRole::Owner,
    )
    .await?;
    host.state
        .lock()
        .map_err(|_| "room state lock poisoned".to_owned())?
        .conference_id = Some(conference_id.clone());
    Ok(conference_id)
}

async fn ensure_human(
    host: &RoomHost,
    conference_id: &pb::OpaqueId,
    external_user_id: &[u8],
    role: pb::ConferenceParticipantRole,
) -> Result<(), String> {
    let mut conference = conference_client(host).await?;
    let integration_id = integration_id();
    let key = String::from_utf8(external_user_id.to_vec())
        .map_err(|_| "external user id is not text".to_owned())?;
    let mut ensure = Request::new(pb::UniversalEnsureParticipantRequest {
        scope: Some(pb_scope(&host.env.scope)),
        conference_id: Some(conference_id.clone()),
        integration_id: Some(integration_id.clone()),
        external_user_id: external_user_id.to_vec(),
        role: role as i32,
        idempotency_key: format!("{key}-participant"),
    });
    attach_dev_credential(&mut ensure, &host.env);
    let ensured = conference
        .ensure_participant(ensure)
        .await
        .map_err(|error| format!("ensure participant: {error}"))?
        .into_inner();
    if !matches!(
        ensured.result,
        Some(pb::universal_ensure_participant_response::Result::Participant(_))
    ) {
        return Err("participant was denied".to_owned());
    }
    let mut device = Request::new(pb::UniversalEnsureParticipantDeviceRequest {
        scope: Some(pb_scope(&host.env.scope)),
        conference_id: Some(conference_id.clone()),
        integration_id: Some(integration_id),
        external_user_id: external_user_id.to_vec(),
        idempotency_key: format!("{key}-device"),
    });
    attach_dev_credential(&mut device, &host.env);
    let device = conference
        .ensure_participant_device(device)
        .await
        .map_err(|error| format!("ensure device: {error}"))?
        .into_inner();
    if !matches!(
        device.result,
        Some(
            pb::universal_ensure_participant_device_response::Result::Device(
                pb::UniversalParticipantDeviceStatus { active: true, .. }
            )
        )
    ) {
        return Err("device enrollment was denied".to_owned());
    }
    Ok(())
}

async fn prepare_group(host: &RoomHost, conference_id: &pb::OpaqueId) -> Result<(), String> {
    let status = request_runtime(host, conference_id).await?;
    if status.group_ready {
        Ok(())
    } else {
        Err("conference group is not ready".to_owned())
    }
}

async fn prepare_runtime(host: &RoomHost, conference_id: &pb::OpaqueId) -> Result<(), String> {
    let status = request_runtime(host, conference_id).await?;
    if status.group_ready && status.call_ready {
        Ok(())
    } else {
        Err("conference runtime is not ready for a call".to_owned())
    }
}

async fn request_runtime(
    host: &RoomHost,
    conference_id: &pb::OpaqueId,
) -> Result<pb::UniversalConferenceRuntimeStatus, String> {
    let mut conference = conference_client(host).await?;
    let mut prepare = Request::new(pb::UniversalPrepareConferenceRuntimeRequest {
        scope: Some(pb_scope(&host.env.scope)),
        conference_id: Some(conference_id.clone()),
        integration_id: Some(integration_id()),
        idempotency_key: "room-runtime".to_owned(),
    });
    attach_dev_credential(&mut prepare, &host.env);
    let runtime = conference
        .prepare_conference_runtime(prepare)
        .await
        .map_err(|error| format!("prepare runtime: {error}"))?
        .into_inner();
    match runtime.result {
        Some(pb::universal_prepare_conference_runtime_response::Result::Runtime(status)) => {
            Ok(status)
        }
        _ => Err("conference runtime preparation was denied".to_owned()),
    }
}

async fn prewarm_when_ready(host: Arc<RoomHost>, grpc_bind: SocketAddr) -> Result<(), String> {
    for _ in 0..100 {
        if TcpStream::connect(grpc_bind).await.is_ok() {
            let conference_id = ensure_conference(&host).await?;
            prepare_group(&host, &conference_id).await?;
            if open_live(&host, &conference_id).await? && host.edge.is_some() {
                let watcher = Arc::clone(&host);
                tokio::spawn(async move {
                    if let Err(error) = watch_room_recording(watcher).await {
                        eprintln!("ucr room recording: {error}");
                    }
                });
            }
            println!("UCR_ROOM_PREWARM=ready");
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    Err("development API did not accept a room prewarm connection".to_owned())
}

async fn open_live(host: &RoomHost, conference_id: &pb::OpaqueId) -> Result<bool, String> {
    let _gate = host.open_gate.lock().await;
    if host
        .state
        .lock()
        .map_err(|_| "room state lock poisoned".to_owned())?
        .opened
    {
        return Ok(false);
    }
    let mut conference = conference_client(host).await?;
    for (target, key) in [
        (pb::UniversalConferenceLifecycle::Waiting, "room-waiting"),
        (pb::UniversalConferenceLifecycle::Live, "room-live"),
    ] {
        let mut transition = Request::new(pb::UniversalConferenceLifecycleRequest {
            scope: Some(pb_scope(&host.env.scope)),
            conference_id: Some(conference_id.clone()),
            target: target as i32,
            idempotency_key: key.to_owned(),
            integration_id: Some(integration_id()),
        });
        attach_dev_credential(&mut transition, &host.env);
        let transitioned = conference
            .transition_conference(transition)
            .await
            .map_err(|error| format!("transition conference: {error}"))?
            .into_inner();
        if !matches!(
            transitioned.result,
            Some(pb::universal_conference_lifecycle_response::Result::Conference(_))
        ) {
            return Err("conference could not go live".to_owned());
        }
    }
    let mut open = Request::new(pb::UniversalSetEntryOpenRequest {
        scope: Some(pb_scope(&host.env.scope)),
        conference_id: Some(conference_id.clone()),
        entry_open: true,
        idempotency_key: "room-entry".to_owned(),
        integration_id: Some(integration_id()),
    });
    attach_dev_credential(&mut open, &host.env);
    let opened = conference
        .set_entry_open(open)
        .await
        .map_err(|error| format!("open entry: {error}"))?
        .into_inner();
    if !matches!(
        opened.result,
        Some(pb::universal_set_entry_open_response::Result::Conference(_))
    ) {
        return Err("conference entry stayed closed".to_owned());
    }
    host.state
        .lock()
        .map_err(|_| "room state lock poisoned".to_owned())?
        .opened = true;
    Ok(true)
}

async fn watch_room_recording(host: Arc<RoomHost>) -> Result<(), String> {
    let edge = host
        .edge
        .as_ref()
        .ok_or_else(|| "recording edge is missing".to_owned())?
        .clone();
    let mut previous_live = 0_usize;
    let mut stable_polls = 0_u32;
    let mut quiet_polls = 0_u32;
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let conference = match conference_id(&host) {
            Ok(conference) => conference,
            Err(error) => {
                eprintln!("ucr room recording: {error}");
                continue;
            }
        };
        let call = match active_call(&host, &conference) {
            Ok(call) => call,
            Err(error) => {
                eprintln!("ucr room recording: {error}");
                continue;
            }
        };
        let Some(call) = call else {
            previous_live = 0;
            stable_polls = 0;
            quiet_polls = 0;
            continue;
        };
        let live = match host.env.connected_realtime_participants(&call.call_id) {
            Ok(live) => live,
            Err(error) => {
                eprintln!("ucr room recording: {error}");
                continue;
            }
        };
        let _gate = host.recording_gate.lock().await;
        let recordings = match active_room_recordings(&host, &call.call_id) {
            Ok(recordings) => recordings,
            Err(error) => {
                eprintln!("ucr room recording: {error}");
                continue;
            }
        };
        if recordings.is_empty() {
            quiet_polls = 0;
            if live >= 2 && live == previous_live {
                stable_polls = stable_polls.saturating_add(1);
            } else {
                stable_polls = 0;
                previous_live = live;
            }
            // Membership on the call is not enough: the conference page still has to
            // finish realtime join. Seal only after two open media sessions stay up.
            if live >= 2 && stable_polls >= 40 {
                if let Err(error) = start_room_recording(&host, &edge, &conference).await {
                    eprintln!("ucr room recording: {error}");
                    stable_polls = 0;
                } else {
                    stable_polls = 0;
                }
            }
        } else if live < 2 {
            previous_live = live;
            stable_polls = 0;
            quiet_polls = quiet_polls.saturating_add(1);
            if quiet_polls >= 15 {
                for recording in &recordings {
                    if let Err(error) = stop_room_recording(&host, recording).await {
                        eprintln!("ucr room recording: {error}");
                    }
                }
                quiet_polls = 0;
            }
        } else {
            quiet_polls = 0;
            previous_live = live;
            stable_polls = 0;
        }
    }
}

fn active_call(
    host: &RoomHost,
    conference_id: &pb::OpaqueId,
) -> Result<Option<CallSession>, String> {
    let group_id = GroupId::from_opaque(
        OpaqueId::from_wire_bytes(&conference_id.value)
            .map_err(|_| "invalid conference id".to_owned())?,
    );
    let calls = host
        .env
        .store
        .active_calls_for_group(&host.env.scope, &group_id, 2)
        .map_err(|error| format!("call lookup: {error:?}"))?;
    match calls.as_slice() {
        [] => Ok(None),
        [call] => Ok(Some(call.clone())),
        _ => Err("room does not have exactly one active call".to_owned()),
    }
}

fn active_room_recordings(
    host: &RoomHost,
    call_id: &ucr_model::CallId,
) -> Result<Vec<RecordingSession>, String> {
    host.env
        .store
        .active_recordings_for_call(host.env.scope(), call_id, MAX_ACTIVE_RECORDINGS_PER_CALL)
        .map_err(|error| format!("recording lookup: {error:?}"))
}

async fn release_recording_for_newcomer(
    host: &RoomHost,
    conference_id: &pb::OpaqueId,
    participant: &PrincipalRef,
) -> Result<(), String> {
    let Some(call) = active_call(host, conference_id)? else {
        return Ok(());
    };
    let _gate = host.recording_gate.lock().await;
    let recordings = active_room_recordings(host, &call.call_id)?;
    let blocking = recordings
        .iter()
        .filter(|recording| !recording_allows_realtime_participant(recording, participant))
        .collect::<Vec<_>>();
    if blocking.is_empty() {
        return Ok(());
    }
    for recording in blocking {
        stop_room_recording(host, recording).await?;
    }
    Ok(())
}

fn allocate_recording_label(host: &RoomHost) -> Result<String, String> {
    let mut state = host
        .state
        .lock()
        .map_err(|_| "room state lock poisoned".to_owned())?;
    let seq = state.recording_seq.saturating_add(1);
    state.recording_seq = seq;
    if seq == 1 {
        Ok("room-recording".to_owned())
    } else {
        Ok(format!("room-recording-{seq}"))
    }
}

async fn start_room_recording(
    host: &RoomHost,
    edge: &super::room_edge::RoomEdge,
    conference_id: &pb::OpaqueId,
) -> Result<(), String> {
    let call = active_call(host, conference_id)?
        .ok_or_else(|| "room does not have exactly one active call".to_owned())?;
    let canonical_call_id = call.call_id.clone();
    let label = allocate_recording_label(host)?;
    let recording_opaque =
        OpaqueId::new(&label).map_err(|_| format!("invalid recording id {label}"))?;
    let recording_id = pb::OpaqueId {
        value: recording_opaque.as_wire_bytes().to_vec(),
    };
    let mut recording = recording_client(host).await?;
    let mut request = Request::new(pb::RecordingRequest {
        scope: Some(pb_scope(&host.env.scope)),
        recording_id: Some(recording_id.clone()),
        call_id: Some(pb::OpaqueId {
            value: canonical_call_id.as_opaque().as_wire_bytes().to_vec(),
        }),
        policy: Some(pb::RecordingPolicy {
            require_all_participant_consent: false,
            notify_all_participants: true,
            retention_seconds: 3_600,
            policy_reference: Some("local-room".to_owned()),
        }),
    });
    attach_dev_credential(&mut request, &host.env);
    let requested = recording
        .request_recording(request)
        .await
        .map_err(|error| format!("request recording: {error}"))?
        .into_inner();
    let session = recording_session(requested.result, "recording request was denied")?;
    let mut start = Request::new(pb::RecordingStartRequest {
        scope: Some(pb_scope(&host.env.scope)),
        recording_id: Some(recording_id),
        expected_revision: session.revision,
        idempotency_key: Some(format!("room-recording-start-{label}")),
    });
    attach_dev_credential(&mut start, &host.env);
    let started = recording
        .start_recording(start)
        .await
        .map_err(|error| format!("start recording: {error}"))?
        .into_inner();
    let session = recording_session(
        started.result.map(start_result),
        "recording start was denied",
    )?;
    edge.recorder.begin(
        host.env.scope.clone(),
        RecordingId::from_opaque(recording_opaque),
        canonical_call_id,
        session.revision,
        session.expires_at_unix_ms,
    )?;
    println!(
        "UCR_ROOM_RECORDING_STATE=active revision={}",
        session.revision
    );
    Ok(())
}

async fn stop_room_recording(host: &RoomHost, session: &RecordingSession) -> Result<(), String> {
    if session.state != RecordingState::Active
        && session.state != RecordingState::Ready
        && session.state != RecordingState::WaitingForConsent
    {
        return Ok(());
    }
    let mut recording = recording_client(host).await?;
    let mut stop = Request::new(pb::RecordingStopRequest {
        scope: Some(pb_scope(&host.env.scope)),
        recording_id: Some(pb::OpaqueId {
            value: session.recording_id.as_opaque().as_wire_bytes().to_vec(),
        }),
        expected_revision: session.revision,
        // Revision 2 is reused by every new archive. The key must name the
        // recording, or the second stop is rejected as a duplicate of the first.
        idempotency_key: Some(format!(
            "room-recording-stop-{}-{}",
            wire_text(session.recording_id.as_opaque()),
            session.revision
        )),
    });
    attach_dev_credential(&mut stop, &host.env);
    let stopped = recording
        .stop_recording(stop)
        .await
        .map_err(|error| format!("stop recording: {error}"))?
        .into_inner();
    let stopped_session =
        match recording_session(stopped.result.map(stop_result), "recording stop was denied") {
            Ok(session) => session,
            Err(error) => {
                // A concurrent stop already moved the revision. The archive is no
                // longer sealing the room, so the newcomer can enter.
                if recording_is_inactive(host, session) {
                    return Ok(());
                }
                return Err(error);
            }
        };
    if let Some(edge) = &host.edge
        && let Err(error) = edge
            .recorder
            .end(&session.recording_id, stopped_session.revision)
    {
        eprintln!("ucr room recording archive stop: {error}");
    }
    println!(
        "UCR_ROOM_RECORDING_STATE=stopped revision={}",
        stopped_session.revision
    );
    Ok(())
}

fn recording_is_inactive(host: &RoomHost, session: &RecordingSession) -> bool {
    host.env
        .store
        .recording(host.env.scope(), &session.recording_id)
        .ok()
        .flatten()
        .is_none_or(|current| {
            current.state != RecordingState::Active
                && current.state != RecordingState::Ready
                && current.state != RecordingState::WaitingForConsent
        })
}

fn stop_result(
    result: pb::recording_stop_response::Result,
) -> pb::recording_request_response::Result {
    match result {
        pb::recording_stop_response::Result::Recording(recording) => {
            pb::recording_request_response::Result::Recording(recording)
        }
        pb::recording_stop_response::Result::Error(error) => {
            pb::recording_request_response::Result::Error(error)
        }
    }
}

fn start_result(
    result: pb::recording_start_response::Result,
) -> pb::recording_request_response::Result {
    match result {
        pb::recording_start_response::Result::Recording(recording) => {
            pb::recording_request_response::Result::Recording(recording)
        }
        pb::recording_start_response::Result::Error(error) => {
            pb::recording_request_response::Result::Error(error)
        }
    }
}

fn recording_session(
    result: Option<pb::recording_request_response::Result>,
    empty: &str,
) -> Result<pb::RecordingSession, String> {
    match result {
        Some(pb::recording_request_response::Result::Recording(session)) => Ok(session),
        Some(pb::recording_request_response::Result::Error(error)) => {
            let code = pb::ErrorCode::try_from(error.code)
                .map_or_else(|_| error.code.to_string(), |code| format!("{code:?}"));
            Err(format!("{empty}: {code}"))
        }
        None => Err(empty.to_owned()),
    }
}

struct ParticipantIdentity {
    participant_id: String,
    device_id: String,
    participant: PrincipalRef,
}

fn participant_identity(
    host: &RoomHost,
    conference_id: &pb::OpaqueId,
    external_user_id: &[u8],
) -> Result<ParticipantIdentity, String> {
    let conference_id = GroupId::from_opaque(
        OpaqueId::from_wire_bytes(&conference_id.value)
            .map_err(|_| "invalid conference id".to_owned())?,
    );
    let integration_id = IntegrationId::from_opaque(opaque("dev-service-principal"));
    let profile = host
        .env
        .store
        .universal_conference_participant_for_external(
            &host.env.scope,
            &conference_id,
            &integration_id,
            external_user_id,
        )
        .map_err(|error| format!("participant lookup: {error:?}"))?
        .ok_or_else(|| "participant is not in this room".to_owned())?;
    let binding = host
        .env
        .store
        .principal_identity_binding(&host.env.scope, &profile.participant)
        .map_err(|error| format!("identity lookup: {error:?}"))?
        .ok_or_else(|| "participant identity is missing".to_owned())?;
    let devices = host
        .env
        .store
        .active_devices_for_identity(&host.env.scope, &binding.identity_id, 2)
        .map_err(|error| format!("device lookup: {error:?}"))?;
    let [device] = devices.as_slice() else {
        return Err("participant does not have exactly one active device".to_owned());
    };
    Ok(ParticipantIdentity {
        participant_id: wire_text(profile.participant.principal_id.as_opaque()),
        device_id: wire_text(device.device_id.as_opaque()),
        participant: profile.participant,
    })
}

fn returning_human(
    host: &RoomHost,
    conference_id: &pb::OpaqueId,
    external_user_id: &str,
    role: pb::ConferenceParticipantRole,
) -> Result<Option<ParticipantIdentity>, String> {
    let conference = GroupId::from_opaque(
        OpaqueId::from_wire_bytes(&conference_id.value)
            .map_err(|_| "invalid conference id".to_owned())?,
    );
    let integration_id = IntegrationId::from_opaque(opaque("dev-service-principal"));
    let Some(profile) = host
        .env
        .store
        .universal_conference_participant_for_external(
            &host.env.scope,
            &conference,
            &integration_id,
            external_user_id.as_bytes(),
        )
        .map_err(|error| format!("participant lookup: {error:?}"))?
    else {
        return Ok(None);
    };
    if !profile.active || !roles_match(role, profile.role) {
        return Ok(None);
    }
    match participant_identity(host, conference_id, external_user_id.as_bytes()) {
        Ok(identity) => Ok(Some(identity)),
        Err(_) => Ok(None),
    }
}

fn roles_match(
    requested: pb::ConferenceParticipantRole,
    stored: ConferenceParticipantRole,
) -> bool {
    matches!(
        (requested, stored),
        (
            pb::ConferenceParticipantRole::Speaker,
            ConferenceParticipantRole::Speaker
        ) | (
            pb::ConferenceParticipantRole::Attendee,
            ConferenceParticipantRole::Attendee
        )
    )
}

fn reusable_external_id(value: &str) -> bool {
    (8..64).contains(&value.len()) && value.starts_with("user-") && identity_safe(value) == value
}

fn reserve_body(
    host: &RoomHost,
    external_user_id: &str,
    identity: &ParticipantIdentity,
    display_name: &str,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&serde_json::json!({
        "ok": true,
        "externalUserId": external_user_id,
        "tenantId": wire_text(host.env.scope.tenant_id.as_opaque()),
        "namespaceId": host.env.scope.namespace_id.as_ref().map(|value| wire_text(value.as_opaque())),
        "participantId": identity.participant_id,
        "deviceId": identity.device_id,
        "displayName": display_name,
    }))
    .map_err(|error| format!("encode reserve response: {error}"))
}

fn unix_time_ms() -> Result<i64, String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| format!("clock: {error}"))?
        .as_millis();
    i64::try_from(now).map_err(|_| "clock exceeds i64".to_owned())
}

fn conference_id(host: &RoomHost) -> Result<pb::OpaqueId, String> {
    host.state
        .lock()
        .map_err(|_| "room state lock poisoned".to_owned())?
        .conference_id
        .clone()
        .ok_or_else(|| "room is not created".to_owned())
}

fn integration_id() -> pb::OpaqueId {
    pb_id("dev-service-principal")
}

async fn recording_client(
    host: &RoomHost,
) -> Result<pb::recording_service_client::RecordingServiceClient<tonic::transport::Channel>, String>
{
    pb::recording_service_client::RecordingServiceClient::connect(host.grpc.clone())
        .await
        .map_err(|error| format!("recording service: {error}"))
}

async fn conference_client(
    host: &RoomHost,
) -> Result<
    pb::universal_conference_service_client::UniversalConferenceServiceClient<
        tonic::transport::Channel,
    >,
    String,
> {
    pb::universal_conference_service_client::UniversalConferenceServiceClient::connect(
        host.grpc.clone(),
    )
    .await
    .map_err(|error| format!("conference service: {error}"))
}

fn validate_display_name(name: &str) -> Result<(), String> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 40 || name.chars().any(char::is_control) {
        return Err("enter a display name up to 40 characters".to_owned());
    }
    Ok(())
}

fn identity_safe(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || *character == '-')
        .collect()
}

fn random_external_id() -> Result<String, String> {
    let mut bytes = [0_u8; 8];
    let mut file =
        std::fs::File::open("/dev/urandom").map_err(|error| format!("random: {error}"))?;
    file.read_exact(&mut bytes)
        .map_err(|error| format!("random: {error}"))?;
    Ok(format!("user-{}", super::hex(&bytes)))
}

fn error_body(message: &str) -> Vec<u8> {
    serde_json::to_vec(&RoomError {
        ok: false,
        message: message.to_owned(),
    })
    .unwrap_or_else(|_| br#"{"ok":false,"message":"internal error"}"#.to_vec())
}

fn origin_allowed(origin: Option<&str>) -> bool {
    let Some(origin) = origin else {
        return true;
    };
    let Some(rest) = origin.strip_prefix("http://") else {
        return false;
    };
    let host = if let Some(bracketed) = rest.strip_prefix('[') {
        let Some((host, _)) = bracketed.split_once(']') else {
            return false;
        };
        host
    } else {
        rest.split(':').next().unwrap_or(rest)
    };
    host == "127.0.0.1" || host == "localhost" || host == "::1"
}

struct HttpRequest {
    method: String,
    path: String,
    origin: Option<String>,
    body: Vec<u8>,
}

fn parse_http(buffer: &[u8]) -> Result<Option<HttpRequest>, String> {
    let Some(split) = buffer.windows(4).position(|window| window == b"\r\n\r\n") else {
        return Ok(None);
    };
    let header = std::str::from_utf8(&buffer[..split])
        .map_err(|_| "request headers are not utf-8".to_owned())?;
    let mut lines = header.lines();
    let request_line = lines
        .next()
        .ok_or_else(|| "missing request line".to_owned())?;
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or("").to_owned();
    let path = parts
        .next()
        .unwrap_or("/")
        .split('?')
        .next()
        .unwrap_or("/")
        .to_owned();
    if !path.starts_with('/') || path.contains("..") {
        return Err("invalid request path".to_owned());
    }
    let mut content_length = 0_usize;
    let mut origin = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value
                .trim()
                .parse()
                .map_err(|_| "invalid content length".to_owned())?;
        } else if name.eq_ignore_ascii_case("origin") {
            origin = Some(value.trim().to_owned());
        }
    }
    if content_length > MAX_HTTP_BYTES {
        return Err("request is too large".to_owned());
    }
    let body_start = split + 4;
    if buffer.len() < body_start + content_length {
        return Ok(None);
    }
    Ok(Some(HttpRequest {
        method,
        path,
        origin,
        body: buffer[body_start..body_start + content_length].to_vec(),
    }))
}

async fn write_response(
    stream: &mut TcpStream,
    status: u16,
    origin: Option<&str>,
    body: &[u8],
) -> Result<(), String> {
    let reason = match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        403 => "Forbidden",
        413 => "Payload Too Large",
        _ => "Error",
    };
    let allow_origin = origin.unwrap_or("http://127.0.0.1:43124");
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\naccess-control-allow-origin: {allow_origin}\r\naccess-control-allow-methods: GET, POST, OPTIONS\r\naccess-control-allow-headers: content-type\r\nvary: Origin\r\nconnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(header.as_bytes())
        .await
        .map_err(|error| format!("write room response: {error}"))?;
    stream
        .write_all(body)
        .await
        .map_err(|error| format!("write room response: {error}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::origin_allowed;

    #[test]
    fn room_accepts_ipv4_ipv6_and_localhost_loopback_origins() {
        assert!(origin_allowed(None));
        assert!(origin_allowed(Some("http://127.0.0.1:43124")));
        assert!(origin_allowed(Some("http://localhost:43124")));
        assert!(origin_allowed(Some("http://[::1]:43124")));
        assert!(!origin_allowed(Some("http://[::1")));
        assert!(!origin_allowed(Some("http://192.168.1.1:43124")));
        assert!(!origin_allowed(Some("https://127.0.0.1:43124")));
        assert!(!origin_allowed(Some("https://[::1]:43124")));
    }
}
