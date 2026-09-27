import {
  UniversalConferenceClient,
  UniversalConferenceHttpError,
} from "./src/conference.ts";

const calls = [];
const fakeFetch = async (url, init) => {
  calls.push({ url: String(url), init });
  const path = new URL(String(url)).pathname;
  if (path === "/v1/conferences") {
    return new Response(JSON.stringify({ conference: {
      scope: { tenant_id: "tenant" },
      conference_id: "conference-1",
      integration_id: "integration",
      external_conference_id_b64: "ZXZlbnQtMQ==",
      mode: "webinar",
      lifecycle: "scheduled",
      schedule: { starts_at_unix_ms: 1000 },
      entry_open: true,
      revision: 1,
    }}), { status: 200, headers: { "content-type": "application/json" } });
  }
  if (path === "/v1/conferences/resolve") {
    return new Response(JSON.stringify({ conference: {
      scope: { tenant_id: "tenant" },
      conference_id: "conference-1",
      integration_id: "integration",
      external_conference_id_b64: "ZXZlbnQtMQ==",
      mode: "webinar",
      lifecycle: "scheduled",
      schedule: { starts_at_unix_ms: 1000 },
      entry_open: true,
      revision: 1,
    }}), { status: 200, headers: { "content-type": "application/json" } });
  }
  if (path === "/v1/participants/list") {
    return new Response(JSON.stringify({ participants: { participants: [{
      external_user_id_b64: "dXNlci0x",
      role: "attendee",
      audio_muted: false,
      camera_allowed: true,
      publish_audio_allowed: false,
      publish_video_allowed: false,
      active: true,
      screen_share_allowed: false,
    }]}}), { status: 200, headers: { "content-type": "application/json" } });
  }
  if (path === "/v1/participants/raised-hands") {
    return new Response(JSON.stringify({ raised_hands: { external_user_ids_b64: ["dXNlci0x"] }}), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }
  if (path === "/v1/capabilities") {
    return new Response(JSON.stringify({ capabilities: {
      capabilities: [],
      max_participants: 500,
      browser_realtime_gateway: true,
      production_webrtc: false,
      turn: true,
      recording: false,
      horizontal_sfu: false,
      audio: true,
      video: true,
      screen_share: true,
      webinar: true,
      rtmp: false,
      codecs: ["ucr.media.audio.opus"],
    }}), { status: 200, headers: { "content-type": "application/json" } });
  }
  if (path === "/v1/participant-devices") {
    return new Response(JSON.stringify({ device: {
      external_user_id_b64: "dXNlci0x",
      active: true,
    }}), { status: 200, headers: { "content-type": "application/json" } });
  }
  if (path === "/v1/participants") {
    return new Response(JSON.stringify({ participant: {
      external_user_id_b64: "dXNlci0x",
      role: "attendee",
      audio_muted: false,
      camera_allowed: true,
      publish_audio_allowed: false,
      publish_video_allowed: false,
      active: true,
      screen_share_allowed: false,
    }}), { status: 200, headers: { "content-type": "application/json" } });
  }
  if (path === "/v1/join-grants") {
    return new Response(JSON.stringify({ grant: {
      session_id: "session-1",
      join_url: "https://join.example/#ucr_join=opaque",
      expires_at_unix_ms: 2000,
    }}), { status: 200, headers: { "content-type": "application/json" } });
  }
  if (path === "/v1/attendance") {
    return new Response(JSON.stringify({ error: { code: "RATE_LIMITED", message: "slow down", retryable: true, retry_after_ms: 2500 } }), {
      status: 403,
      headers: { "content-type": "application/json" },
    });
  }
  return new Response(JSON.stringify({ acknowledgement: { acknowledged_id: "ok" } }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
};

const client = new UniversalConferenceClient({
  baseUrl: "https://ucr.example",
  accessToken: "machine-token",
  fetchImpl: fakeFetch,
});

const conference = await client.createConference({
  scope: { tenant_id: "tenant" },
  integrationId: "integration",
  externalConferenceId: "event-1",
  idempotencyKey: "create-1",
  mode: "webinar",
  schedule: { starts_at_unix_ms: 1000 },
});
if (conference.conference_id !== "conference-1") throw new Error("createConference response drift");

const context = {
  scope: { tenant_id: "tenant" },
  integrationId: "integration",
  conferenceId: "conference-1",
};
await client.ensureParticipant({
  ...context,
  externalUserId: "user-1",
  role: "attendee",
  idempotencyKey: "participant-1",
});
const device = await client.ensureParticipantDevice(context, "user-1", "device-1");
if (!device.active) throw new Error("device readiness was discarded");
const grant = await client.issueJoinGrant({
  ...context,
  externalUserId: "user-1",
  ttlSeconds: 900,
  usePolicy: "single_use",
  idempotencyKey: "join-1",
});
if (!grant.join_url.includes("#ucr_join=")) throw new Error("join grant boundary drift");

const resolved = await client.resolveConference({ tenant_id: "tenant" }, "integration", "event-1");
if (resolved.conference_id !== "conference-1") throw new Error("resolveConference response drift");
const participants = await client.listParticipants(context, 25);
if (participants.length !== 1 || participants[0].role !== "attendee") throw new Error("participant list drift");
const raisedHands = await client.listRaisedHands(context, 25);
if (raisedHands.length !== 1 || raisedHands[0] !== "dXNlci0x") throw new Error("raised-hands drift");
const capabilities = await client.getCapabilities({ tenant_id: "tenant" }, "integration");
if (!capabilities.browser_realtime_gateway || capabilities.production_webrtc) throw new Error("capability truth drift");
await client.removeParticipant(context, "user-1", "remove-1");

if (calls.length !== 9) throw new Error("client performed hidden retries");
for (const call of calls) {
  if (call.init.headers.authorization !== "Bearer machine-token") throw new Error("Bearer admission drift");
}
const createBody = JSON.parse(calls[0].init.body);
if (createBody.external_conference_id_b64 !== "ZXZlbnQtMQ==") throw new Error("external reference encoding drift");
const participantBody = JSON.parse(calls[1].init.body);
if (participantBody.external_user_id_b64 !== "dXNlci0x") throw new Error("external user encoding drift");

let denied = false;
try {
  await client.getAttendance(context, "user-1");
} catch (error) {
  if (!(error instanceof UniversalConferenceHttpError)) throw error;
  if (error.status !== 403 || error.code !== "RATE_LIMITED" || error.retryable !== true || error.retryAfterMs !== 2500) throw new Error("canonical error drift");
  if (String(error).includes("machine-token")) throw new Error("access token leaked through diagnostics");
  denied = true;
}
if (!denied) throw new Error("canonical error was converted to success");
if (calls.length !== 10) throw new Error("error path performed hidden retries");

const resolveBody = JSON.parse(calls[4].init.body);
if (resolveBody.external_conference_id_b64 !== "ZXZlbnQtMQ==") throw new Error("resolve external ID encoding drift");
const listBody = JSON.parse(calls[5].init.body);
if (listBody.max_items !== 25) throw new Error("participant list bound drift");
const raisedHandsBody = JSON.parse(calls[6].init.body);
if (raisedHandsBody.max_items !== 25) throw new Error("raised-hands bound drift");
const removeBody = JSON.parse(calls[8].init.body);
if (removeBody.external_user_id_b64 !== "dXNlci0x") throw new Error("remove participant encoding drift");

let rejectedInsecure = false;
try {
  new UniversalConferenceClient({
    baseUrl: "http://public.example",
    accessToken: "token",
    fetchImpl: fakeFetch,
  });
} catch {
  rejectedInsecure = true;
}
if (!rejectedInsecure) throw new Error("public plaintext HTTP was accepted");

console.log("TypeScript Universal Conference client conformance: PASS");
