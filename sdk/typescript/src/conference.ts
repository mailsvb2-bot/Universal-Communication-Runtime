export type ConferenceMode = "meeting" | "webinar" | "broadcast" | "audio_room";
export type ConferenceLifecycle = "scheduled" | "waiting" | "live" | "ending" | "ended";
export type ConferenceParticipantRole = "owner" | "host" | "moderator" | "speaker" | "attendee";
export type JoinGrantUsePolicy = "single_use" | "reusable";
export type ConferenceMediaKind = "audio" | "video";

export interface TenantScope {
  readonly tenant_id: string;
  readonly namespace_id?: string;
}

export interface ConferenceSchedule {
  readonly starts_at_unix_ms: number;
  readonly planned_end_unix_ms?: number;
  readonly join_before_seconds?: number;
  readonly join_after_seconds?: number;
  readonly timezone?: string;
}

export interface ConferenceDescriptor {
  readonly scope: TenantScope;
  readonly conference_id: string;
  readonly integration_id: string;
  readonly external_conference_id_b64: string;
  readonly mode: ConferenceMode;
  readonly lifecycle: ConferenceLifecycle;
  readonly schedule: ConferenceSchedule;
  readonly entry_open: boolean;
  readonly revision: number;
}

export interface ConferenceParticipant {
  readonly external_user_id_b64: string;
  readonly role: ConferenceParticipantRole;
  readonly audio_muted: boolean;
  readonly camera_allowed: boolean;
  readonly publish_audio_allowed: boolean;
  readonly publish_video_allowed: boolean;
  readonly active: boolean;
  readonly screen_share_allowed: boolean;
}

export interface ParticipantDeviceStatus {
  readonly external_user_id_b64: string;
  readonly active: boolean;
}

export interface ConferenceCapabilities {
  readonly capabilities: readonly { readonly id: string; readonly maturity: number }[];
  readonly max_participants: number;
  readonly browser_realtime_gateway: boolean;
  readonly production_webrtc: boolean;
  readonly turn: boolean;
  readonly recording: boolean;
  readonly horizontal_sfu: boolean;
  readonly audio: boolean;
  readonly video: boolean;
  readonly screen_share: boolean;
  readonly webinar: boolean;
  readonly rtmp: boolean;
  readonly codecs: readonly string[];
}

export interface JoinGrant {
  readonly session_id: string;
  readonly join_url: string;
  readonly expires_at_unix_ms: number;
}

export interface ParticipantAttendance {
  readonly external_user_id_b64: string;
  readonly first_join_at_unix_ms: number | null;
  readonly last_leave_at_unix_ms: number | null;
  readonly first_media_ready_at_unix_ms: number | null;
  readonly total_connected_seconds: number;
  readonly current_connected_seconds: number;
  readonly join_count: number;
  readonly reconnect_count: number;
  readonly media_ready_count: number;
  readonly connected: boolean;
}

export interface UniversalConferenceClientOptions {
  readonly baseUrl: string;
  readonly accessToken: string;
  readonly fetchImpl?: typeof fetch;
}

export interface ConferenceMutationContext {
  readonly scope: TenantScope;
  readonly integrationId: string;
  readonly conferenceId: string;
}

export interface CreateConferenceInput {
  readonly scope: TenantScope;
  readonly integrationId: string;
  readonly externalConferenceId: string;
  readonly idempotencyKey: string;
  readonly mode: ConferenceMode;
  readonly schedule: ConferenceSchedule;
}

export interface EnsureParticipantInput extends ConferenceMutationContext {
  readonly externalUserId: string;
  readonly role: ConferenceParticipantRole;
  readonly idempotencyKey: string;
}

export interface UpdateParticipantInput extends ConferenceMutationContext {
  readonly externalUserId: string;
  readonly idempotencyKey: string;
  readonly role?: ConferenceParticipantRole;
  readonly audioMuted?: boolean;
  readonly cameraAllowed?: boolean;
  readonly publishAudioAllowed?: boolean;
  readonly publishVideoAllowed?: boolean;
  readonly screenShareAllowed?: boolean;
}

export interface IssueJoinGrantInput extends ConferenceMutationContext {
  readonly externalUserId: string;
  readonly ttlSeconds: number;
  readonly usePolicy: JoinGrantUsePolicy;
  readonly idempotencyKey: string;
  readonly notBeforeUnixMs?: number;
  readonly notAfterUnixMs?: number;
}

export interface MediaSubscription {
  readonly sourceExternalUserId: string;
  readonly mediaKind: ConferenceMediaKind;
}

export class UniversalConferenceHttpError extends Error {
  readonly status: number;
  readonly code?: string;
  readonly retryable?: boolean;
  readonly retryAfterMs?: number;

  constructor(status: number, message: string, code?: string, retryable?: boolean, retryAfterMs?: number) {
    super(message);
    this.name = "UniversalConferenceHttpError";
    this.status = status;
    this.code = code;
    this.retryable = retryable;
    this.retryAfterMs = retryAfterMs;
  }
}

const trimBaseUrl = (value: string): string => {
  const trimmed = value.trim().replace(/\/+$/, "");
  const url = new URL(trimmed);
  if (url.protocol !== "https:" && url.hostname !== "127.0.0.1" && url.hostname !== "localhost") {
    throw new Error("UCR base URL must use HTTPS outside loopback development");
  }
  return trimmed;
};

const base64Utf8 = (value: string): string => {
  const bytes = new TextEncoder().encode(value);
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let output = "";
  for (let index = 0; index < bytes.length; index += 3) {
    const a = bytes[index] ?? 0;
    const b = bytes[index + 1] ?? 0;
    const c = bytes[index + 2] ?? 0;
    const value24 = (a << 16) | (b << 8) | c;
    output += alphabet[(value24 >>> 18) & 63];
    output += alphabet[(value24 >>> 12) & 63];
    output += index + 1 < bytes.length ? alphabet[(value24 >>> 6) & 63] : "=";
    output += index + 2 < bytes.length ? alphabet[value24 & 63] : "=";
  }
  return output;
};

const requireToken = (value: string): string => {
  const token = value.trim();
  if (!token || /\s/.test(token)) throw new Error("UCR access token must be a non-empty token");
  return token;
};

export class UniversalConferenceClient {
  readonly #baseUrl: string;
  readonly #accessToken: string;
  readonly #fetch: typeof fetch;

  constructor(options: UniversalConferenceClientOptions) {
    this.#baseUrl = trimBaseUrl(options.baseUrl);
    this.#accessToken = requireToken(options.accessToken);
    this.#fetch = options.fetchImpl ?? fetch;
  }

  async #post(path: string, body: unknown): Promise<any> {
    const response = await this.#fetch(this.#baseUrl + path, {
      method: "POST",
      headers: {
        authorization: `Bearer ${this.#accessToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(body),
    });
    const value = await response.json() as any;
    if (!response.ok || value?.error) {
      const error = value?.error;
      throw new UniversalConferenceHttpError(
        response.status,
        typeof error?.message === "string" ? error.message : "UCR request failed",
        typeof error?.code === "string" ? error.code : undefined,
        typeof error?.retryable === "boolean" ? error.retryable : undefined,
        typeof error?.retry_after_ms === "number" ? error.retry_after_ms : undefined,
      );
    }
    return value;
  }

  async createConference(input: CreateConferenceInput): Promise<ConferenceDescriptor> {
    const value = await this.#post("/v1/conferences", {
      scope: input.scope,
      integration_id: input.integrationId,
      external_conference_id_b64: base64Utf8(input.externalConferenceId),
      idempotency_key: input.idempotencyKey,
      mode: input.mode,
      schedule: input.schedule,
    });
    return value.conference as ConferenceDescriptor;
  }

  async resolveConference(
    scope: TenantScope,
    integrationId: string,
    externalConferenceId: string,
  ): Promise<ConferenceDescriptor> {
    const value = await this.#post("/v1/conferences/resolve", {
      scope,
      integration_id: integrationId,
      external_conference_id_b64: base64Utf8(externalConferenceId),
    });
    return value.conference as ConferenceDescriptor;
  }

  async getConference(context: ConferenceMutationContext): Promise<ConferenceDescriptor> {
    const value = await this.#post("/v1/conferences/get", {
      scope: context.scope,
      conference_id: context.conferenceId,
      integration_id: context.integrationId,
    });
    return value.conference as ConferenceDescriptor;
  }

  async transitionConference(
    context: ConferenceMutationContext,
    target: ConferenceLifecycle,
    idempotencyKey: string,
  ): Promise<ConferenceDescriptor> {
    const value = await this.#post("/v1/conferences/lifecycle", {
      scope: context.scope,
      conference_id: context.conferenceId,
      integration_id: context.integrationId,
      target,
      idempotency_key: idempotencyKey,
    });
    return value.conference as ConferenceDescriptor;
  }

  async setEntryOpen(
    context: ConferenceMutationContext,
    entryOpen: boolean,
    idempotencyKey: string,
  ): Promise<ConferenceDescriptor> {
    const value = await this.#post("/v1/conferences/entry", {
      scope: context.scope,
      conference_id: context.conferenceId,
      integration_id: context.integrationId,
      entry_open: entryOpen,
      idempotency_key: idempotencyKey,
    });
    return value.conference as ConferenceDescriptor;
  }

  async ensureParticipant(input: EnsureParticipantInput): Promise<ConferenceParticipant> {
    const value = await this.#post("/v1/participants", {
      scope: input.scope,
      conference_id: input.conferenceId,
      integration_id: input.integrationId,
      external_user_id_b64: base64Utf8(input.externalUserId),
      role: input.role,
      idempotency_key: input.idempotencyKey,
    });
    return value.participant as ConferenceParticipant;
  }

  async ensureParticipantDevice(
    context: ConferenceMutationContext,
    externalUserId: string,
    idempotencyKey: string,
  ): Promise<ParticipantDeviceStatus> {
    const value = await this.#post("/v1/participant-devices", {
      scope: context.scope,
      conference_id: context.conferenceId,
      integration_id: context.integrationId,
      external_user_id_b64: base64Utf8(externalUserId),
      idempotency_key: idempotencyKey,
    });
    return value.device as ParticipantDeviceStatus;
  }

  async updateParticipant(input: UpdateParticipantInput): Promise<ConferenceParticipant> {
    const body: Record<string, unknown> = {
      scope: input.scope,
      conference_id: input.conferenceId,
      integration_id: input.integrationId,
      external_user_id_b64: base64Utf8(input.externalUserId),
      idempotency_key: input.idempotencyKey,
    };
    if (input.role !== undefined) body.role = input.role;
    if (input.audioMuted !== undefined) body.audio_muted = input.audioMuted;
    if (input.cameraAllowed !== undefined) body.camera_allowed = input.cameraAllowed;
    if (input.publishAudioAllowed !== undefined) body.publish_audio_allowed = input.publishAudioAllowed;
    if (input.publishVideoAllowed !== undefined) body.publish_video_allowed = input.publishVideoAllowed;
    if (input.screenShareAllowed !== undefined) body.screen_share_allowed = input.screenShareAllowed;
    const value = await this.#post("/v1/participants/update", body);
    return value.participant as ConferenceParticipant;
  }

  async removeParticipant(
    context: ConferenceMutationContext,
    externalUserId: string,
    idempotencyKey: string,
  ): Promise<void> {
    await this.#post("/v1/participants/remove", {
      scope: context.scope,
      conference_id: context.conferenceId,
      integration_id: context.integrationId,
      external_user_id_b64: base64Utf8(externalUserId),
      idempotency_key: idempotencyKey,
    });
  }

  async listParticipants(
    context: ConferenceMutationContext,
    maxItems = 100,
  ): Promise<readonly ConferenceParticipant[]> {
    const value = await this.#post("/v1/participants/list", {
      scope: context.scope,
      conference_id: context.conferenceId,
      integration_id: context.integrationId,
      max_items: maxItems,
    });
    return value.participants as readonly ConferenceParticipant[];
  }

  async listRaisedHands(
    context: ConferenceMutationContext,
    maxItems = 100,
  ): Promise<readonly string[]> {
    const value = await this.#post("/v1/participants/raised-hands", {
      scope: context.scope,
      conference_id: context.conferenceId,
      integration_id: context.integrationId,
      max_items: maxItems,
    });
    return value.external_user_ids_b64 as readonly string[];
  }

  async getCapabilities(scope: TenantScope, integrationId: string): Promise<ConferenceCapabilities> {
    const value = await this.#post("/v1/capabilities", {
      scope,
      integration_id: integrationId,
    });
    return value.capabilities as ConferenceCapabilities;
  }

  async prepareRuntime(context: ConferenceMutationContext, idempotencyKey: string): Promise<any> {
    const value = await this.#post("/v1/conferences/runtime", {
      scope: context.scope,
      conference_id: context.conferenceId,
      integration_id: context.integrationId,
      idempotency_key: idempotencyKey,
    });
    return value.runtime;
  }

  async issueJoinGrant(input: IssueJoinGrantInput): Promise<JoinGrant> {
    const body: Record<string, unknown> = {
      scope: input.scope,
      conference_id: input.conferenceId,
      integration_id: input.integrationId,
      external_user_id_b64: base64Utf8(input.externalUserId),
      ttl_seconds: input.ttlSeconds,
      use_policy: input.usePolicy,
      idempotency_key: input.idempotencyKey,
    };
    if (input.notBeforeUnixMs !== undefined) body.not_before_unix_ms = input.notBeforeUnixMs;
    if (input.notAfterUnixMs !== undefined) body.not_after_unix_ms = input.notAfterUnixMs;
    const value = await this.#post("/v1/join-grants", body);
    return value.grant as JoinGrant;
  }

  async revokeJoinGrant(
    context: ConferenceMutationContext,
    sessionId: string,
    idempotencyKey: string,
  ): Promise<void> {
    await this.#post("/v1/join-grants/revoke", {
      scope: context.scope,
      conference_id: context.conferenceId,
      integration_id: context.integrationId,
      session_id: sessionId,
      idempotency_key: idempotencyKey,
    });
  }

  async setSubscriptions(
    context: ConferenceMutationContext,
    externalUserId: string,
    subscriptions: readonly MediaSubscription[],
  ): Promise<void> {
    await this.#post("/v1/subscriptions", {
      scope: context.scope,
      conference_id: context.conferenceId,
      integration_id: context.integrationId,
      external_user_id_b64: base64Utf8(externalUserId),
      subscriptions: subscriptions.map((subscription) => ({
        source_external_user_id_b64: base64Utf8(subscription.sourceExternalUserId),
        media_kind: subscription.mediaKind,
      })),
    });
  }

  async getAttendance(
    context: ConferenceMutationContext,
    externalUserId: string,
  ): Promise<ParticipantAttendance> {
    const value = await this.#post("/v1/attendance", {
      scope: context.scope,
      conference_id: context.conferenceId,
      integration_id: context.integrationId,
      external_user_id_b64: base64Utf8(externalUserId),
    });
    return value.attendance as ParticipantAttendance;
  }
}
