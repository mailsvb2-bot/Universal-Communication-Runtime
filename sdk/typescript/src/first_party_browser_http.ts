import type { UcrDirectCallHost, UcrCallStartIntent, UcrDirectCallAction } from "./contact_call_journey.ts";
import type {
  UcrCanonicalDeviceKeyVault,
  UcrCanonicalDeviceTrust,
  UcrDeviceEnrollmentBinding,
  UcrDeviceVaultScope,
  UcrLocalDeviceSigner,
} from "./canonical_device_enrollment.ts";
import type {
  UcrAuthenticatedFirstEntry,
  UcrCanonicalJoinIssuance,
  UcrFirstPartyAuthenticatedUserHost,
} from "./canonical_first_party_call_entry.ts";

/**
 * First-party browser transport only: the server, not this code, owns
 * independently authenticated human sessions, canonical Device/Trust,
 * one-time possession challenges, and signed Conference Join grants.
 *
 * No machine Service Principal credentials, private keys, MLS exporter or
 * permanent user/phone registry may be passed through these endpoints.
 */
export interface UcrFirstPartyHttpOptions {
  /** Must be EXACTLY the browser document origin. Do not permit cross-origin BFFs. */
  readonly origin: string;
  readonly fetchImpl?: typeof fetch;
}

const MAX_JSON_BYTES = 16 * 1024;
const MAX_REQUEST_BYTES = 8 * 1024;
const ENROLLMENT_CHALLENGE_MIN = 32;
const ENROLLMENT_CHALLENGE_MAX = 512;
const REQUIRED_CONTENT_TYPE = "application/json";

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, names: readonly string[]): void {
  if (Object.keys(value).some(name => !names.includes(name))) {
    throw new Error("unexpected first-party authority response fields");
  }
}

function requiredId(value: unknown, name: string): string {
  if (typeof value !== "string" || !value || value.length > 128 ||
      !/^[A-Za-z0-9_.:@-]+$/.test(value)) {
    throw new Error("invalid first-party " + name);
  }
  return value;
}

function parseBinding(value: unknown): UcrAuthenticatedFirstEntry {
  if (!isObject(value)) throw new Error("first-party authenticated session missing");
  exactKeys(value, ["tenantId", "namespaceId", "participantId", "deviceId"]);
  if (!(value.namespaceId === null ||
        (typeof value.namespaceId === "string" && value.namespaceId.length > 0))) {
    throw new Error("invalid canonical namespace");
  }
  return Object.freeze({
    tenantId: requiredId(value.tenantId, "tenant"),
    namespaceId: value.namespaceId === null ? null : requiredId(value.namespaceId, "namespace"),
    participantId: requiredId(value.participantId, "participant"),
    deviceId: requiredId(value.deviceId, "device"),
  });
}

function sameBinding(a: UcrAuthenticatedFirstEntry, b: UcrAuthenticatedFirstEntry): boolean {
  return a.tenantId === b.tenantId &&
    a.namespaceId === b.namespaceId &&
    a.participantId === b.participantId &&
    a.deviceId === b.deviceId;
}

function snapshotBinding(binding: UcrDeviceEnrollmentBinding): UcrDeviceEnrollmentBinding {
  const base = parseBinding({
    tenantId: binding.tenantId,
    namespaceId: binding.namespaceId,
    participantId: binding.participantId,
    deviceId: binding.deviceId,
  });
  if ((binding.callId === undefined) !== (binding.sessionId === undefined)) {
    throw new Error("Call and Session must be supplied together");
  }
  if (binding.callId === undefined) return base;
  return Object.freeze({
    ...base,
    callId: requiredId(binding.callId, "Call"),
    sessionId: requiredId(binding.sessionId, "Session"),
  });
}

function decodeBase64Url(value: unknown, length: number | null): Uint8Array {
  if (typeof value !== "string" || value.length > 1024 ||
      !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) {
    throw new Error("malformed first-party binary descriptor");
  }
  let binary: string;
  try {
    binary = atob(value.replace(/-/g, "+").replace(/_/g, "/"));
  } catch {
    throw new Error("malformed first-party binary descriptor");
  }
  const bytes = Uint8Array.from(binary, character => character.charCodeAt(0));
  if ((length !== null && bytes.length !== length) ||
      encodeBase64Url(bytes) !== value) {
    throw new Error("noncanonical first-party binary descriptor");
  }
  return bytes;
}

function encodeBase64Url(bytes: Uint8Array): string {
  let value = "";
  for (const item of bytes) value += String.fromCharCode(item);
  return btoa(value).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Domain-separated Ed25519 proof. The server reconstructs this byte sequence
 * using its OWN authenticated session/scope and stored single-use challenge.
 * Never ask a Device signer to sign unqualified, server-chosen bytes.
 */
export function encodeUcrFirstPartyEnrollmentProof(
  binding: UcrAuthenticatedFirstEntry,
  signer: UcrLocalDeviceSigner,
  challengeId: string,
  challenge: Uint8Array,
): Uint8Array {
  const user = parseBinding(binding);
  const keyId = requiredId(signer.keyId, "key ID");
  const serverChallengeId = requiredId(challengeId, "challenge");
  if (!(signer.publicKey instanceof Uint8Array) || signer.publicKey.length !== 32 ||
      !(challenge instanceof Uint8Array) ||
      challenge.length < ENROLLMENT_CHALLENGE_MIN ||
      challenge.length > ENROLLMENT_CHALLENGE_MAX) {
    throw new Error("invalid Device enrollment signature context");
  }
  const context = [
    user.tenantId, user.namespaceId, user.participantId, user.deviceId,
    keyId, encodeBase64Url(signer.publicKey), serverChallengeId,
    encodeBase64Url(challenge),
  ];
  return new TextEncoder().encode(
    "ucr-first-party-device-enrollment.v1\u0000" + JSON.stringify(context),
  );
}

function parseTrust(raw: unknown): UcrCanonicalDeviceTrust {
  if (!isObject(raw)) throw new Error("invalid canonical Device trust response");
  exactKeys(raw, ["deviceActive", "deviceRevoked", "activeKey"]);
  if (typeof raw.deviceActive !== "boolean" || typeof raw.deviceRevoked !== "boolean") {
    throw new Error("invalid canonical Device lifecycle");
  }
  let activeKey: UcrLocalDeviceSigner | null = null;
  if (raw.activeKey !== null) {
    if (!isObject(raw.activeKey)) throw new Error("invalid trusted signing key");
    exactKeys(raw.activeKey, ["keyId", "publicKeyBase64Url"]);
    activeKey = {
      keyId: requiredId(raw.activeKey.keyId, "key ID"),
      publicKey: decodeBase64Url(raw.activeKey.publicKeyBase64Url, 32),
    };
  }
  return {
    deviceActive: raw.deviceActive,
    deviceRevoked: raw.deviceRevoked,
    activeKey,
  };
}

function parseIssuance(raw: unknown): UcrCanonicalJoinIssuance {
  if (!isObject(raw)) throw new Error("first-party Join response missing");
  exactKeys(raw, [
    "tenantId", "namespaceId", "participantId", "deviceId",
    "callId", "sessionId", "joinFragment",
  ]);
  const binding = parseBinding({
    tenantId: raw.tenantId, namespaceId: raw.namespaceId,
    participantId: raw.participantId, deviceId: raw.deviceId,
  });
  if (typeof raw.joinFragment !== "string" ||
      !/^#ucr_join=[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(raw.joinFragment) ||
      raw.joinFragment.length > 16384) {
    throw new Error("invalid signed Join fragment");
  }
  return Object.freeze({
    ...binding,
    callId: requiredId(raw.callId, "Call"),
    sessionId: requiredId(raw.sessionId, "Session"),
    joinFragment: raw.joinFragment,
  });
}

function validateOrigin(value: string): URL {
  let origin: URL;
  try { origin = new URL(value); }
  catch { throw new Error("invalid first-party origin"); }
  if (origin.origin !== value || origin.username || origin.password ||
      origin.pathname !== "/" || origin.search || origin.hash) {
    throw new Error("first-party API requires an exact origin");
  }
  const browserOrigin = globalThis.location?.origin;
  if (typeof browserOrigin !== "string" || origin.origin !== browserOrigin) {
    throw new Error("first-party API must be same-origin with the authenticated page");
  }
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(origin.hostname);
  if (origin.protocol !== "https:" && !(origin.protocol === "http:" && loopback)) {
    throw new Error("first-party user authentication requires HTTPS");
  }
  return origin;
}

async function readBoundedJson(response: Response): Promise<unknown> {
  const type = response.headers.get("content-type")?.split(";")[0]?.trim().toLowerCase();
  if (type !== REQUIRED_CONTENT_TYPE) {
    throw new Error("first-party authority returned unexpected content type");
  }
  const declaredLength = response.headers.get("content-length");
  if (declaredLength !== null && (!/^[0-9]+$/.test(declaredLength) ||
      Number(declaredLength) > MAX_JSON_BYTES)) {
    throw new Error("first-party response exceeds limit");
  }
  if (!response.body) throw new Error("first-party response missing");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      length += part.value.byteLength;
      if (length > MAX_JSON_BYTES) throw new Error("first-party response exceeds limit");
      chunks.push(part.value);
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  try { return JSON.parse(new TextDecoder("utf-8", {fatal: true}).decode(bytes)); }
  catch { throw new Error("malformed first-party JSON response"); }
}

/**
 * Opens a new first-party human session using independently verified possession
 * of the ALREADY TRUSTED canonical Device signer. This is not Device enrollment:
 * a missing local signer requires explicit existing-account recovery/pairing.
 * Neither a Join URL nor browser-entered identity fields authorize themselves.
 */
export async function authenticateUcrFirstPartyDevice(
  vault: UcrCanonicalDeviceKeyVault,
  options: UcrFirstPartyHttpOptions,
  binding: UcrAuthenticatedFirstEntry,
): Promise<UcrAuthenticatedFirstEntry> {
  const origin = validateOrigin(options.origin);
  const auth = parseBinding(binding);
  const scope: UcrDeviceVaultScope = {
    tenantId:auth.tenantId, namespaceId:auth.namespaceId, deviceId:auth.deviceId,
  };
  const signer = await vault.load(scope);
  if (!signer || !signer.publicKey || signer.publicKey.length!==32) {
    throw new Error("registered protected Device signer unavailable; account recovery required");
  }
  const http = options.fetchImpl ?? globalThis.fetch;
  if (typeof http!=="function") throw new Error("fetch API unavailable");
  const post = async (path:string,body:unknown):Promise<unknown> => {
    const data = JSON.stringify(body);
    if (new TextEncoder().encode(data).length>MAX_REQUEST_BYTES) {
      throw new Error("first-party authentication request exceeds limit");
    }
    const response = await http(new URL(path,origin),{
      method:"POST",credentials:"same-origin",redirect:"error",cache:"no-store",
      referrerPolicy:"no-referrer",mode:"same-origin",
      headers:{
        "Accept":REQUIRED_CONTENT_TYPE,
        "Content-Type":REQUIRED_CONTENT_TYPE,
        "X-UCR-First-Party-Request":"v1",
      },
      body:data,
    });
    if (response.redirected || response.url &&
        new URL(response.url).origin!==origin.origin) {
      throw new Error("first-party authentication redirect refused");
    }
    if (!response.ok) throw new Error("Device authentication denied: HTTP "+response.status);
    return readBoundedJson(response);
  };
  const challengeResponse = await post("/v1/first-party/login/challenge",auth);
  if (!isObject(challengeResponse)) throw new Error("missing Device login challenge");
  exactKeys(challengeResponse,["challengeId","challengeBytesBase64Url"]);
  const challengeId = requiredId(challengeResponse.challengeId,"login challenge");
  const nonce = decodeBase64Url(challengeResponse.challengeBytesBase64Url,32);
  const signed = new TextEncoder().encode(
    "ucr-first-party-device-login.v1\u0000"+
    JSON.stringify([
      auth.tenantId,auth.namespaceId,auth.participantId,auth.deviceId,
      challengeId,encodeBase64Url(nonce),
    ]),
  );
  const signature = await vault.signChallenge(scope,signed.slice());
  if (!(signature instanceof Uint8Array) || signature.length!==64) {
    throw new Error("protected Device refused login signature");
  }
  const key = await globalThis.crypto.subtle.importKey(
    "raw", signer.publicKey as Uint8Array<ArrayBuffer>,
    {name:"Ed25519"},false,["verify"],
  );
  if (!await globalThis.crypto.subtle.verify(
    "Ed25519",key,signature as Uint8Array<ArrayBuffer>,signed,
  )) {
    throw new Error("Device login signer does not match protected public key");
  }
  const result = parseBinding(await post("/v1/first-party/login/verify",{
    binding:auth,challengeId,signatureBase64Url:encodeBase64Url(signature),
  }));
  if (!sameBinding(auth,result)) {
    throw new Error("first-party server authenticated a different Identity or Device");
  }
  return result;
}

/**
 * Consumes existing first-party session cookies on SAME origin only. No OAuth
 * machine secrets are exposed to JS, and redirects are forbidden.
 *
 * Required server endpoints (not supplied by this SDK):
 * GET  /v1/first-party/session           -> canonical user/device binding
 * POST /v1/first-party/device/inspect    -> active canonical Device/Trust
 * POST /v1/first-party/device/challenge  -> challengeId and unpredictable challengeBytes
 * POST /v1/first-party/device/approve    -> atomically verify proof + approve trust
 * POST /v1/first-party/call/join         -> signed Conference Join fragment
 *
 * Each endpoint MUST enforce independently authenticated, active user Identity,
 * Origin and CSRF checks, canonical authorization/tenant scope and no-cache.
 * The challenge issuer MUST bind challenge to session+Device+key+expiry and
 * consume it once. The issue-Join endpoint MUST recheck trust on the server.
 */
export function createUcrFirstPartyHttpHost(
  vault: UcrCanonicalDeviceKeyVault,
  options: UcrFirstPartyHttpOptions,
): UcrDirectCallHost {
  if (!vault || typeof vault.signChallenge !== "function") {
    throw new Error("existing protected Device signer vault required");
  }
  const origin = validateOrigin(options.origin);
  const requestImpl = options.fetchImpl ?? globalThis.fetch;
  if (typeof requestImpl !== "function") throw new Error("fetch API unavailable");

  const request = async (method: "GET" | "POST", path: string, data?: unknown): Promise<unknown> => {
    const serialized = data === undefined ? undefined : JSON.stringify(data);
    if (serialized && new TextEncoder().encode(serialized).length > MAX_REQUEST_BYTES) {
      throw new Error("first-party request exceeds limit");
    }
    const response = await requestImpl(new URL(path, origin), {
      method,
      credentials: "same-origin",
      redirect: "error",
      cache: "no-store",
      referrerPolicy: "no-referrer",
      mode: "same-origin",
      headers: {
        "Accept": REQUIRED_CONTENT_TYPE,
        ...(method === "POST" ? {
          "Content-Type": REQUIRED_CONTENT_TYPE,
          "X-UCR-First-Party-Request": "v1",
        } : {}),
      },
      ...(serialized === undefined ? {} : {body: serialized}),
    });
    if (response.redirected || response.url &&
        new URL(response.url).origin !== origin.origin) {
      throw new Error("first-party authentication redirect refused");
    }
    if (!response.ok) {
      throw new Error("first-party canonical authority rejected request: HTTP " + response.status);
    }
    return readBoundedJson(response);
  };

  const session = async (): Promise<UcrAuthenticatedFirstEntry> =>
    parseBinding(await request("GET", "/v1/first-party/session"));
  const inspect = async (binding: UcrDeviceEnrollmentBinding): Promise<UcrCanonicalDeviceTrust> => {
    const context = snapshotBinding(binding);
    const user = await session();
    if (!sameBinding(context, user)) throw new Error("first-party Device session changed");
    return parseTrust(await request("POST", "/v1/first-party/device/inspect", {binding: context}));
  };

  return {
    resumeAuthenticatedDevice: session,
    inspect,
    async approveNewDevice(binding, signer) {
      const context = snapshotBinding(binding);
      const approvedPublicKey = signer?.publicKey?.slice();
      if (!approvedPublicKey || approvedPublicKey.length !== 32) {
        throw new Error("invalid local signer public key");
      }
      const keyId = requiredId(signer.keyId, "key ID");
      if (!sameBinding(context, await session())) {
        throw new Error("first-party Device session changed before enrollment");
      }
      const scope: UcrDeviceVaultScope = {
        tenantId: context.tenantId,
        namespaceId: context.namespaceId,
        deviceId: context.deviceId,
      };
      const challengeRaw = await request("POST", "/v1/first-party/device/challenge", {
        binding: context, keyId, publicKeyBase64Url: encodeBase64Url(approvedPublicKey),
      });
      if (!isObject(challengeRaw)) throw new Error("missing server possession challenge");
      exactKeys(challengeRaw, ["challengeId", "challengeBytesBase64Url"]);
      const challengeId = requiredId(challengeRaw.challengeId, "challenge");
      const challenge = decodeBase64Url(challengeRaw.challengeBytesBase64Url, null);
      if (challenge.length < ENROLLMENT_CHALLENGE_MIN ||
          challenge.length > ENROLLMENT_CHALLENGE_MAX) {
        throw new Error("invalid server possession challenge size");
      }
      const signedMessage = encodeUcrFirstPartyEnrollmentProof(context, {
        keyId, publicKey: approvedPublicKey,
      }, challengeId, challenge);
      const signature = await vault.signChallenge(scope, signedMessage.slice());
      if (!(signature instanceof Uint8Array) || signature.length !== 64) {
        throw new Error("protected signer could not prove enrollment possession");
      }
      const verifier = await globalThis.crypto.subtle.importKey(
        "raw", approvedPublicKey as Uint8Array<ArrayBuffer>,
        {name: "Ed25519"}, false, ["verify"],
      );
      if (!await globalThis.crypto.subtle.verify(
        "Ed25519", verifier, signature as Uint8Array<ArrayBuffer>, signedMessage,
      )) {
        throw new Error("server enrollment challenge signer mismatch");
      }
      if (!sameBinding(context, await session())) {
        throw new Error("first-party Device session changed during enrollment");
      }
      const result = await request("POST", "/v1/first-party/device/approve", {
        binding: context,
        keyId,
        publicKeyBase64Url: encodeBase64Url(approvedPublicKey),
        challengeId,
        signatureBase64Url: encodeBase64Url(signature),
      });
      if (!isObject(result) || Object.keys(result).length !== 1 || result.approved !== true) {
        throw new Error("canonical Device enrollment was not approved");
      }
    },
    async startDirectCall(binding, intent: UcrCallStartIntent) {
      const auth = snapshotBinding(binding);
      if (!sameBinding(auth, await session())) {
        throw new Error("first-party account changed before canonical StartCall");
      }
      return await request("POST", "/v1/first-party/call/start", {
        binding: auth,
        intent: {
          peerIdentityId: requiredId(intent.peerIdentityId,"peer Identity"),
          media: intent.media,
          idempotencyKey: requiredId(intent.idempotencyKey,"Call idempotency"),
        },
      }) as Awaited<ReturnType<UcrDirectCallHost["startDirectCall"]>>;
    },
    async getDirectCall(binding, callId) {
      const auth = snapshotBinding(binding);
      if (!sameBinding(auth, await session())) {
        throw new Error("first-party account changed before canonical GetCall");
      }
      return await request("POST", "/v1/first-party/call/get", {
        binding: auth, callId: requiredId(callId,"Call"),
      }) as Awaited<ReturnType<UcrDirectCallHost["getDirectCall"]>>;
    },
    async listIncomingDirectCalls(binding) {
      const auth = snapshotBinding(binding);
      if (!sameBinding(auth, await session())) {
        throw new Error("first-party account changed before canonical incoming Calls");
      }
      return await request("POST", "/v1/first-party/call/incoming", {
        binding: auth,
      }) as Awaited<ReturnType<UcrDirectCallHost["listIncomingDirectCalls"]>>;
    },
    async signalDirectCall(binding, input: {
      callId: string; expectedRevision: number; action: UcrDirectCallAction
    }) {
      const auth = snapshotBinding(binding);
      if (!sameBinding(auth, await session())) {
        throw new Error("first-party account changed before canonical SignalCall");
      }
      return await request("POST", "/v1/first-party/call/signal", {
        binding: auth, callId: requiredId(input.callId,"Call"),
        expectedRevision: input.expectedRevision, action: input.action,
      }) as Awaited<ReturnType<UcrDirectCallHost["signalDirectCall"]>>;
    },
    async issueSignedJoinForAcceptedCall(binding, input: {
      callId: string; expectedRevision: number
    }) {
      const auth = snapshotBinding(binding);
      if (!sameBinding(auth, await session())) {
        throw new Error("first-party account changed before accepted Call Join");
      }
      const issued = parseIssuance(await request(
        "POST", "/v1/first-party/call/join-accepted", {
          binding: auth, callId: requiredId(input.callId,"Call"),
          expectedRevision: input.expectedRevision,
        },
      ));
      if (!sameBinding(auth,issued) || issued.callId !== input.callId) {
        throw new Error("first-party Join issuer returned a foreign Call/Device");
      }
      return issued;
    },
    async issueSignedDeviceJoin(binding) {
      const context = snapshotBinding(binding);
      if (!sameBinding(context, await session())) {
        throw new Error("first-party Device session changed before Join");
      }
      const issued = parseIssuance(
        await request("POST", "/v1/first-party/call/join", context),
      );
      if (!sameBinding(context, issued)) {
        throw new Error("first-party Join issuer returned a foreign Device");
      }
      return issued;
    },
  };
}
