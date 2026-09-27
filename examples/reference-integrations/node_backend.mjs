import process from "node:process";

const b64 = (value) => Buffer.from(value, "utf8").toString("base64");

function config() {
  const names = ["UCR_BASE_URL", "UCR_ACCESS_TOKEN", "UCR_TENANT_ID", "UCR_INTEGRATION_ID"];
  const missing = names.filter((name) => !process.env[name]);
  if (missing.length) throw new Error(`missing environment: ${missing.join(", ")}`);
  return Object.fromEntries(names.map((name) => [name, process.env[name]]));
}

async function post(cfg, path, body) {
  const response = await fetch(cfg.UCR_BASE_URL.replace(/\/$/, "") + path, {
    method: "POST",
    headers: {
      authorization: `Bearer ${cfg.UCR_ACCESS_TOKEN}`,
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
  });
  const value = await response.json();
  if (!response.ok) throw new Error(`${path}: HTTP ${response.status}: ${JSON.stringify(value)}`);
  return value;
}

export function flowPayloads(cfg, nowMs = Date.now()) {
  const scope = { tenant_id: cfg.UCR_TENANT_ID };
  const integrationId = cfg.UCR_INTEGRATION_ID;
  const create = {
    scope,
    integration_id: integrationId,
    external_conference_id_b64: b64("reference-webinar-001"),
    idempotency_key: "reference-create-001",
    mode: "webinar",
    schedule: {
      starts_at_unix_ms: nowMs + 300_000,
      planned_end_unix_ms: nowMs + 3_900_000,
      join_before_seconds: 900,
      join_after_seconds: 300,
      timezone: "UTC",
    },
  };
  return { scope, integrationId, create };
}

async function run() {
  const cfg = config();
  const { scope, integrationId, create } = flowPayloads(cfg);
  const conference = (await post(cfg, "/v1/conferences", create)).conference;
  const conferenceId = conference.conference_id;

  for (const [externalUser, role, key] of [
    ["owner-001", "owner", "reference-owner-001"],
    ["attendee-001", "attendee", "reference-attendee-001"],
  ]) {
    await post(cfg, "/v1/participants", {
      scope, conference_id: conferenceId, integration_id: integrationId,
      external_user_id_b64: b64(externalUser), role, idempotency_key: key,
    });
  }

  for (const [externalUser, key] of [
    ["owner-001", "reference-owner-device-001"],
    ["attendee-001", "reference-attendee-device-001"],
  ]) {
    await post(cfg, "/v1/participant-devices", {
      scope, conference_id: conferenceId, integration_id: integrationId,
      external_user_id_b64: b64(externalUser), idempotency_key: key,
    });
  }

  await post(cfg, "/v1/conferences/runtime", {
    scope, conference_id: conferenceId, integration_id: integrationId,
    idempotency_key: "reference-runtime-001",
  });
  for (const target of ["waiting", "live"]) {
    await post(cfg, "/v1/conferences/lifecycle", {
      scope, conference_id: conferenceId, integration_id: integrationId,
      target, idempotency_key: `reference-lifecycle-${target}`,
    });
  }

  const grant = (await post(cfg, "/v1/join-grants", {
    scope, conference_id: conferenceId, integration_id: integrationId,
    external_user_id_b64: b64("attendee-001"), ttl_seconds: 900,
    use_policy: "single_use", idempotency_key: "reference-join-001",
  })).grant;
  process.stdout.write(JSON.stringify({ conference_id: conferenceId, join_url: grant.join_url }) + "\n");
}

function selfTest() {
  const { create } = flowPayloads({ UCR_TENANT_ID: "tenant", UCR_INTEGRATION_ID: "integration" }, 1_700_000_000_000);
  if (create.mode !== "webinar") throw new Error("mode drift");
  if (create.external_conference_id_b64 !== b64("reference-webinar-001")) throw new Error("external reference drift");
  if (create.idempotency_key !== "reference-create-001") throw new Error("idempotency drift");
  if (create.schedule.join_before_seconds !== 900) throw new Error("schedule drift");
  console.log("reference Node integration self-test: PASS");
}

if (process.argv.includes("--self-test")) selfTest();
else await run();
