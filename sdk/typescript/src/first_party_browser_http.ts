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
/** Metadata for endpoint-owned MLS initialization; NOT a Join grant. */
export interface UcrEndpointMlsCallDescriptor {
  readonly callId: string;
  readonly expectedRevision: number;
  /** Null until the canonical Group is created; never guess a CAS revision. */
  readonly groupRevision: number | null;
  /** Verified against the committed two-Device MLS transition and live Trust. */
  readonly expectedPeerDeviceId: string | null;
  readonly cryptoEpoch: number | null;
  readonly cryptoStateRef: string | null;
  readonly mediaCallId: string;
  readonly groupId: string;
  readonly conversationId: string;
  readonly creatorPrincipalId: string;
  readonly peerPrincipalId: string;
  readonly deviceId: string;
  readonly cryptoCapability: string;
  readonly requiresEndpointOwnedCommit: true;
}

function parseEndpointMlsCallDescriptor(value: unknown): UcrEndpointMlsCallDescriptor {
  if (!isObject(value)) throw new Error("missing endpoint MLS descriptor");
  exactKeys(value, [
    "callId", "expectedRevision", "groupRevision", "expectedPeerDeviceId", "cryptoEpoch",
    "cryptoStateRef", "mediaCallId", "groupId", "conversationId",
    "creatorPrincipalId", "peerPrincipalId", "deviceId", "cryptoCapability",
    "requiresEndpointOwnedCommit",
  ]);
  if (!Number.isSafeInteger(value.expectedRevision) || Number(value.expectedRevision) < 0 ||
      value.requiresEndpointOwnedCommit !== true) {
    throw new Error("invalid or downgraded endpoint MLS descriptor");
  }
  const absent = value.groupRevision === null && value.cryptoEpoch === null &&
    value.cryptoStateRef === null;
  const created = Number.isSafeInteger(value.groupRevision) &&
    Number(value.groupRevision) >= 0 && Number.isSafeInteger(value.cryptoEpoch) &&
    Number(value.cryptoEpoch) >= 0 && typeof value.cryptoStateRef === "string" &&
    value.cryptoStateRef.length > 0 && value.cryptoStateRef.length <= 128;
  if (!absent && !created) {
    throw new Error("inconsistent canonical MLS Group revision or crypto epoch");
  }
  const peer = value.expectedPeerDeviceId;
  const peerRequired = created && Number(value.cryptoEpoch) > 0;
  if ((peerRequired && (typeof peer !== "string" || peer === value.deviceId)) ||
      (!peerRequired && peer !== null) ||
      (typeof peer === "string" && !/^[A-Za-z0-9_.:@-]{1,128}$/.test(peer))) {
    throw new Error("missing or untrusted committed MLS peer Device");
  }
  const epoch = value.cryptoEpoch;
  const revision = value.groupRevision;
  const stateRef = value.cryptoStateRef;
  const peerDevice = value.expectedPeerDeviceId;
  if ((epoch !== null && (!Number.isSafeInteger(epoch) || Number(epoch) < 0)) ||
      (revision !== null && (!Number.isSafeInteger(revision) || Number(revision) < 0)) ||
      (stateRef !== null && typeof stateRef !== "string") ||
      (peerDevice !== null && typeof peerDevice !== "string") ||
      (epoch === null) !== (stateRef === null) ||
      (epoch === null && revision !== null) ||
      (epoch !== null && revision === null) ||
      (epoch !== null && Number(epoch) > 0 && peerDevice === null) ||
      (epoch !== null && Number(epoch) === 0 && peerDevice !== null)) {
    throw new Error("inconsistent canonical MLS epoch, Group revision or Device roster");
  }
  return Object.freeze({
    callId: requiredId(value.callId, "Call"),
    expectedRevision: Number(value.expectedRevision),
    expectedPeerDeviceId: peerDevice === null ? null : requiredId(peerDevice, "peer Device"),
    groupRevision: revision === null ? null : Number(revision),
    cryptoEpoch: epoch === null ? null : Number(epoch),
    cryptoStateRef: stateRef === null ? null : requiredId(stateRef, "MLS state"),
    groupRevision: absent ? null : Number(value.groupRevision),
    expectedPeerDeviceId: typeof peer === "string" ? peer : null,
    cryptoEpoch: absent ? null : Number(value.cryptoEpoch),
    cryptoStateRef: absent ? null : requiredId(value.cryptoStateRef, "MLS state ref"),
    mediaCallId: requiredId(value.mediaCallId, "media Call"),
    groupId: requiredId(value.groupId, "MLS Group"),
    conversationId: requiredId(value.conversationId, "media Conversation"),
    creatorPrincipalId: requiredId(value.creatorPrincipalId, "creator"),
    peerPrincipalId: requiredId(value.peerPrincipalId, "peer"),
    deviceId: requiredId(value.deviceId, "Device"),
    cryptoCapability: requiredId(value.cryptoCapability, "crypto capability"),
    requiresEndpointOwnedCommit: true,
  });
}

export interface UcrManagedFirstPartyHost extends UcrDirectCallHost {
  describeAcceptedCallMls(binding: UcrAuthenticatedFirstEntry, input: {callId: string; expectedRevision: number}): Promise<UcrEndpointMlsCallDescriptor>;
  publishEndpointMlsGroup(binding: UcrAuthenticatedFirstEntry, input: {callId: string; expectedRevision: number; cryptoStateRef: string}): Promise<void>;
  publishEndpointMlsOffer(binding: UcrAuthenticatedFirstEntry, input: {
    callId: string; expectedRevision: number; keyPackage: Uint8Array;
  }): Promise<void>;
  listEndpointMlsOffers(binding: UcrAuthenticatedFirstEntry, input: {
    callId: string; expectedRevision: number;
  }): Promise<readonly {
    recipientDeviceId: string; recipientSignerKeyId: string;
    recipientKeyPackageBase64Url: string; recipientSignatureBase64Url: string;
  }[]>;
  prepareEndpointMlsKeyPackage(binding: UcrAuthenticatedFirstEntry, input: {callId: string; expectedRevision: number; keyPackage: Uint8Array}): Promise<{
    recipientDeviceId: string;
    recipientSignerKeyId: string;
    recipientKeyPackageBase64Url: string;
    recipientSignatureBase64Url: string;
  }>;
  addEndpointMlsPeer(binding: UcrAuthenticatedFirstEntry, input: {
    callId: string; expectedRevision: number; groupRevision: number;
    eventId: string; cryptoEpoch: number; cryptoStateRef: string;
    recipientDeviceId: string; recipientSignerKeyId: string;
    recipientKeyPackageBase64Url: string; recipientSignatureBase64Url: string;
    commit: Uint8Array; welcome: Uint8Array;
  }): Promise<void>;
  fetchEndpointMlsBootstrap(binding: UcrAuthenticatedFirstEntry, input: {
    callId: string; expectedRevision: number;
  }): Promise<{
    groupId: string; admissionEventId: string; welcome: Uint8Array;
    welcomeEpoch: number; welcomeStateRef: string;
    commits: readonly {commit: Uint8Array; cryptoEpoch: number; cryptoStateRef: string}[];
    cryptoEpoch: number; cryptoStateRef: string;
  }>;
  listDevices(): Promise<readonly {deviceId:string;state:string}[]>;
  revokeDevice(deviceId:string): Promise<void>;
  rotateRecoveryCode(): Promise<string>;
  logout(): Promise<void>;
}

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

function decodeBase64Url(
  value: unknown, length: number | null, maxBytes = 768,
): Uint8Array {
  // The default remains deliberately small for Device signatures and keys.
  // MLS public wires require an explicit, bounded larger allowance.
  const maxEncodedLength = Math.ceil(maxBytes / 3) * 4;
  if (typeof value !== "string" || value.length > maxEncodedLength ||
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
): Uint8Array<ArrayBuffer> {
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

/** Returns the server-owned shared self-service tenant. No client can mint a tenant. */
export async function ucrFirstPartyBootstrap(options: UcrFirstPartyHttpOptions): Promise<{
  tenantId:string; namespaceId:null
}> {
  const origin=validateOrigin(options.origin);
  const http=options.fetchImpl ?? globalThis.fetch;
  const response=await http(new URL("/v1/first-party/bootstrap",origin),{
    method:"GET",credentials:"same-origin",redirect:"error",cache:"no-store",
    referrerPolicy:"no-referrer",mode:"same-origin",
    headers:{"Accept":REQUIRED_CONTENT_TYPE},
  });
  if(!response.ok || response.redirected)throw Error("self-service enrollment unavailable");
  const data=await readBoundedJson(response);
  if(!isObject(data))throw Error("invalid self-service scope");
  exactKeys(data,["tenantId","namespaceId"]);
  if(data.namespaceId!==null)throw Error("unsupported self-service namespace");
  return {tenantId:requiredId(data.tenantId,"tenant"),namespaceId:null};
}

async function firstPartyAccountEnrollment(
  vault: UcrCanonicalDeviceKeyVault,
  options: UcrFirstPartyHttpOptions,
  kind: "signup" | "recover",
  recovery?: {identityId:string; recoveryCode:string},
):Promise<{binding:UcrAuthenticatedFirstEntry;recoveryCode:string}> {
  const origin=validateOrigin(options.origin);
  const http=options.fetchImpl ?? globalThis.fetch;
  const post=async(path:string,data:unknown):Promise<unknown>=>{
    const body=JSON.stringify(data);
    if(new TextEncoder().encode(body).length>MAX_REQUEST_BYTES)throw Error("enrollment request exceeds bound");
    const response=await http(new URL(path,origin),{
      method:"POST",credentials:"same-origin",redirect:"error",cache:"no-store",
      referrerPolicy:"no-referrer",mode:"same-origin",
      headers:{"Content-Type":REQUIRED_CONTENT_TYPE,
        "Accept":REQUIRED_CONTENT_TYPE,"X-UCR-First-Party-Request":"v1"},
      body,
    });
    if(response.redirected || (response.url && new URL(response.url).origin!==origin.origin)){
      throw Error("self-service redirect forbidden");
    }
    if(!response.ok)throw Error("canonical account enrollment denied: HTTP "+response.status);
    return readBoundedJson(response);
  };
  let binding:UcrAuthenticatedFirstEntry;
  let challengeId:string,nonce:Uint8Array;
  if(kind==="signup"){
    const result=await post("/v1/first-party/signup/begin",{});
    if(!isObject(result))throw Error("invalid registration challenge");
    exactKeys(result,["binding","challengeId","challengeBytesBase64Url"]);
    binding=parseBinding(result.binding);
    challengeId=requiredId(result.challengeId,"signup challenge");
    nonce=decodeBase64Url(result.challengeBytesBase64Url,32);
  }else{
    if(!recovery || !/^[A-Za-z0-9_-]{43}$/.test(recovery.recoveryCode)){
      throw Error("256-bit recovery code required");
    }
    const scope=await ucrFirstPartyBootstrap(options);
    // Recovery cannot reuse/reanimate a revoked Device identifier. Allocate
    // a new canonical Device, independent of any old browser signing seed.
    binding={...scope,participantId:requiredId(recovery.identityId,"recovery identity"),
      deviceId:"fp-device-"+globalThis.crypto.randomUUID()};
    const result=await post("/v1/first-party/recover/begin",binding);
    if(!isObject(result))throw Error("invalid recovery challenge");
    exactKeys(result,["challengeId","challengeBytesBase64Url"]);
    challengeId=requiredId(result.challengeId,"recovery challenge");
    nonce=decodeBase64Url(result.challengeBytesBase64Url,32);
  }
  const vaultScope:UcrDeviceVaultScope={
    tenantId:binding.tenantId,namespaceId:binding.namespaceId,deviceId:binding.deviceId,
  };
  const signer=await vault.stageNew(vaultScope);
  if(!(signer.publicKey instanceof Uint8Array)||signer.publicKey.length!==32){
    throw Error("protected endpoint signer unavailable");
  }
  const keyId=requiredId(signer.keyId,"signing key");
  const publicKeyBase64Url=encodeBase64Url(signer.publicKey);
  const signed=new TextEncoder().encode(
    (kind==="signup"?"ucr-first-party-signup.v1":"ucr-first-party-recover.v1")+"\u0000"+
    JSON.stringify([
      binding.tenantId,binding.namespaceId,binding.participantId,binding.deviceId,
      keyId,publicKeyBase64Url,challengeId,encodeBase64Url(nonce),
    ])
  );
  const signature=await vault.signChallenge(vaultScope,signed.slice());
  if(!(signature instanceof Uint8Array)||signature.length!==64){
    throw Error("new Device possession signature missing");
  }
  const verifying=await globalThis.crypto.subtle.importKey(
    "raw",signer.publicKey as Uint8Array<ArrayBuffer>,{name:"Ed25519"},false,["verify"],
  );
  if(!await globalThis.crypto.subtle.verify(
    "Ed25519",verifying,signature as Uint8Array<ArrayBuffer>,signed)){
    throw Error("new signer cannot prove private-key possession");
  }
  const result=await post("/v1/first-party/"+kind+"/finish",{
    binding,challengeId,keyId,publicKeyBase64Url,
    signatureBase64Url:encodeBase64Url(signature),
    ...(kind==="recover"?{recoveryCode:recovery?.recoveryCode}:{}),
  });
  if(!isObject(result))throw Error("account enrollment response missing");
  exactKeys(result,["binding","recoveryCode"]);
  const resolved=parseBinding(result.binding);
  if(!sameBinding(resolved,binding))throw Error("server enrolled a different user/Device");
  const next=decodeBase64Url(result.recoveryCode,32);
  return {binding:resolved,recoveryCode:encodeBase64Url(next)};
}

/** Create a pseudonymous canonical Identity and its FIRST trusted Device. */
export async function registerUcrFirstPartyUser(
  vault:UcrCanonicalDeviceKeyVault,options:UcrFirstPartyHttpOptions,
):Promise<{binding:UcrAuthenticatedFirstEntry;recoveryCode:string}>{
  return firstPartyAccountEnrollment(vault,options,"signup");
}

/** Consume a user-held one-time recovery code to add a fresh trusted Device. */
export async function recoverUcrFirstPartyDevice(
  vault:UcrCanonicalDeviceKeyVault,options:UcrFirstPartyHttpOptions,
  identityId:string,recoveryCode:string,
):Promise<{binding:UcrAuthenticatedFirstEntry;recoveryCode:string}>{
  return firstPartyAccountEnrollment(vault,options,"recover",{identityId,recoveryCode});
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
): UcrManagedFirstPartyHost {
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
  // A response from a previously authenticated Device must not be consumed
  // after the browser changes account or Device while the request is pending.
  const requireSameSession = async (auth: UcrAuthenticatedFirstEntry): Promise<void> => {
    if (!sameBinding(auth, await session())) {
      throw new Error("first-party account or Device changed during MLS/Join operation");
    }
  };
  const inspect = async (binding: UcrDeviceEnrollmentBinding): Promise<UcrCanonicalDeviceTrust> => {
    const context = snapshotBinding(binding);
    const user = await session();
    if (!sameBinding(context, user)) throw new Error("first-party Device session changed");
    return parseTrust(await request("POST", "/v1/first-party/device/inspect", {binding: user}));
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
    async describeAcceptedCallMls(binding, input) {
      const auth = snapshotBinding(binding);
      if (!sameBinding(auth, await session())) {
        throw new Error("first-party account changed before endpoint MLS bootstrap");
      }
      const descriptor = parseEndpointMlsCallDescriptor(await request(
        "POST", "/v1/first-party/call/mls-descriptor", {
          binding: auth, callId: requiredId(input.callId, "Call"),
          expectedRevision: input.expectedRevision,
        },
      ));
      await requireSameSession(auth);
      if (descriptor.callId !== input.callId ||
          descriptor.expectedRevision !== input.expectedRevision ||
          descriptor.deviceId !== auth.deviceId ||
          descriptor.peerPrincipalId === auth.participantId ||
          !descriptor.mediaCallId.startsWith("fp-m-") ||
          !descriptor.groupId.startsWith("fp-mg-") ||
          !descriptor.conversationId.startsWith("fp-mc-")) {
        throw new Error("endpoint MLS descriptor is not bound to the active Call/Device");
      }
      return descriptor;
    },
    async publishEndpointMlsGroup(binding, input) {
      const auth = snapshotBinding(binding);
      if (!sameBinding(auth, await session())) {
        throw new Error("first-party account changed before signed MLS creation");
      }
      const descriptor = await this.describeAcceptedCallMls(auth, input);
      if (descriptor.creatorPrincipalId !== auth.participantId) {
        throw new Error("only the authorized Call initiator may create endpoint MLS");
      }
      const scope: UcrDeviceVaultScope = {
        tenantId: auth.tenantId, namespaceId: auth.namespaceId, deviceId: auth.deviceId,
      };
      const signer = await vault.load(scope);
      if (!signer || typeof signer.keyId !== "string" ||
          !(signer.publicKey instanceof Uint8Array) || signer.publicKey.length !== 32) {
        throw new Error("canonical protected Device signing key unavailable");
      }
      const cryptoStateRef = requiredId(input.cryptoStateRef, "endpoint MLS state");
      const proof = new TextEncoder().encode(
        "ucr-first-party-endpoint-mls-create.v1\u0000" + JSON.stringify([
          auth.tenantId, auth.namespaceId, auth.participantId, auth.deviceId,
          signer.keyId, input.callId, input.expectedRevision, descriptor.groupId,
          0, cryptoStateRef,
        ])
      );
      const signature = await vault.signChallenge(scope, proof);
      if (!(signature instanceof Uint8Array) || signature.length !== 64 ||
          !sameBinding(auth, await session())) {
        throw new Error("endpoint MLS group creator signing failed");
      }
      const result = await request("POST", "/v1/first-party/call/mls-create", {
        binding: auth, callId: input.callId,
        expectedRevision: input.expectedRevision, cryptoStateRef,
        signatureBase64Url: encodeBase64Url(signature),
      });
      await requireSameSession(auth);
      if (!isObject(result) || result.callId !== input.callId ||
          result.groupId !== descriptor.groupId ||
          result.cryptoEpoch !== 0 ||
          result.cryptoStateRef !== cryptoStateRef ||
          result.requiresEndpointOwnedCommit !== true) {
        throw new Error("server did not persist authorized endpoint MLS epoch zero");
      }
    },

    async prepareEndpointMlsKeyPackage(binding, input) {
      const auth = snapshotBinding(binding);
      if (!sameBinding(auth, await session())) {
        throw new Error("first-party session changed before MLS KeyPackage proof");
      }
      const descriptor = await this.describeAcceptedCallMls(auth, input);
      if (descriptor.creatorPrincipalId === auth.participantId) {
        throw new Error("MLS recipient KeyPackage must be signed by its own Device");
      }
      const scope: UcrDeviceVaultScope = {
        tenantId: auth.tenantId, namespaceId: auth.namespaceId, deviceId: auth.deviceId,
      };
      const signer = await vault.load(scope);
      if (!signer || typeof signer.keyId !== "string" ||
          !(signer.publicKey instanceof Uint8Array) || signer.publicKey.length !== 32 ||
          !(input.keyPackage instanceof Uint8Array) || input.keyPackage.length < 1 ||
          input.keyPackage.length > 8192) {
        throw new Error("protected recipient MLS signer or KeyPackage unavailable");
      }
      const hash = new Uint8Array(await globalThis.crypto.subtle.digest(
        "SHA-256", input.keyPackage as Uint8Array<ArrayBuffer>,
      ));
      const proof = new TextEncoder().encode(
        "ucr-first-party-endpoint-mls-key-package.v1\u0000" + JSON.stringify([
          auth.tenantId, auth.namespaceId, auth.participantId, auth.deviceId,
          signer.keyId, input.callId, descriptor.groupId, encodeBase64Url(hash),
        ]),
      );
      const signature = await vault.signChallenge(scope, proof);
      if (!(signature instanceof Uint8Array) || signature.length !== 64 ||
          !sameBinding(auth, await session())) {
        throw new Error("MLS KeyPackage signer failed or session rotated");
      }
      return {
        recipientDeviceId: auth.deviceId,
        recipientSignerKeyId: signer.keyId,
        recipientKeyPackageBase64Url: encodeBase64Url(input.keyPackage),
        recipientSignatureBase64Url: encodeBase64Url(signature),
      };
    },
    async publishEndpointMlsOffer(binding, input) {
      const auth = snapshotBinding(binding);
      const descriptor = await this.describeAcceptedCallMls(auth, input);
      if (descriptor.creatorPrincipalId === auth.participantId) {
        throw new Error("initiator cannot publish peer MLS offer");
      }
      const offer = await this.prepareEndpointMlsKeyPackage(auth, input);
      const result = await request("POST", "/v1/first-party/call/mls-offer", {
        binding: auth, callId: input.callId, expectedRevision: input.expectedRevision,
        recipientSignerKeyId: offer.recipientSignerKeyId,
        recipientKeyPackageBase64Url: offer.recipientKeyPackageBase64Url,
        recipientSignatureBase64Url: offer.recipientSignatureBase64Url,
      });
      await requireSameSession(auth);
      if (!isObject(result) || result.callId !== input.callId ||
          result.groupId !== descriptor.groupId || result.deviceId !== auth.deviceId ||
          result.offerStored !== true) {
        throw new Error("recipient MLS KeyPackage was not durably published");
      }
    },
    async listEndpointMlsOffers(binding, input) {
      const auth = snapshotBinding(binding);
      const descriptor = await this.describeAcceptedCallMls(auth, input);
      if (descriptor.creatorPrincipalId !== auth.participantId) {
        throw new Error("only Call initiator can read recipient MLS offers");
      }
      const value = await request("POST", "/v1/first-party/call/mls-offers", {
        binding: auth, callId: input.callId, expectedRevision: input.expectedRevision,
      });
      await requireSameSession(auth);
      if (!isObject(value) || value.callId !== input.callId ||
          value.groupId !== descriptor.groupId || !Array.isArray(value.offers) ||
          value.offers.length > 8) {
        throw new Error("untrusted endpoint MLS KeyPackage offer list");
      }
      return value.offers.map(offer => {
        if (!isObject(offer)) throw new Error("invalid MLS offer");
        exactKeys(offer, [
          "recipientDeviceId", "recipientSignerKeyId",
          "recipientKeyPackageBase64Url", "recipientSignatureBase64Url",
        ]);
        const recipientDeviceId = requiredId(offer.recipientDeviceId, "recipient Device");
        const recipientSignerKeyId = requiredId(offer.recipientSignerKeyId, "recipient signer");
        const recipientKeyPackageBase64Url = String(offer.recipientKeyPackageBase64Url);
        const recipientSignatureBase64Url = String(offer.recipientSignatureBase64Url);
        decodeBase64Url(recipientKeyPackageBase64Url, null, 8192);
        if (decodeBase64Url(recipientSignatureBase64Url).length !== 64) {
          throw new Error("invalid recipient MLS offer signature");
        }
        return Object.freeze({
          recipientDeviceId, recipientSignerKeyId,
          recipientKeyPackageBase64Url, recipientSignatureBase64Url,
        });
      });
    },
    async addEndpointMlsPeer(binding, input) {
      const auth = snapshotBinding(binding);
      if (!sameBinding(auth, await session())) throw new Error("first-party account changed");
      const descriptor = await this.describeAcceptedCallMls(auth, input);
      if (descriptor.creatorPrincipalId !== auth.participantId ||
          descriptor.groupRevision === null ||
          input.groupRevision !== descriptor.groupRevision ||
          descriptor.cryptoEpoch === null ||
          input.cryptoEpoch !== descriptor.cryptoEpoch + 1 ||
          !Number.isSafeInteger(input.cryptoEpoch) || input.cryptoEpoch < 1) {
        throw new Error("invalid or unauthorized endpoint-owned MLS Commit");
      }
      const scope: UcrDeviceVaultScope = {
        tenantId: auth.tenantId, namespaceId: auth.namespaceId, deviceId: auth.deviceId,
      };
      const signer = await vault.load(scope);
      if (!signer || !signer.keyId) throw new Error("canonical signing Device unavailable");
      const digest = async (bytes: Uint8Array): Promise<string> => {
        if (!(bytes instanceof Uint8Array) || bytes.length < 1 || bytes.length > 8192) {
          throw new Error("endpoint MLS public wire bounds violated");
        }
        return encodeBase64Url(new Uint8Array(await globalThis.crypto.subtle.digest(
          "SHA-256", bytes as Uint8Array<ArrayBuffer>,
        )));
      };
      const recipientPackage = decodeBase64Url(input.recipientKeyPackageBase64Url, null, 8192);
      const packageHash = await digest(recipientPackage);
      const commitHash = await digest(input.commit);
      const welcomeHash = await digest(input.welcome);
      const proof = new TextEncoder().encode(
        "ucr-first-party-endpoint-mls-add-peer.v1\u0000" + JSON.stringify([
          auth.tenantId, auth.namespaceId, auth.participantId, auth.deviceId,
          signer.keyId, input.callId, input.expectedRevision, descriptor.groupId,
          input.groupRevision, input.eventId, input.cryptoEpoch, input.cryptoStateRef,
          input.recipientDeviceId, input.recipientSignerKeyId,
          packageHash, commitHash, welcomeHash,
        ]),
      );
      const signature = await vault.signChallenge(scope, proof);
      if (!(signature instanceof Uint8Array) || signature.length !== 64 ||
          !sameBinding(auth, await session())) {
        throw new Error("endpoint MLS Commit signing failed");
      }
      const result = await request("POST", "/v1/first-party/call/mls-add-peer", {
        binding: auth, callId: input.callId, expectedRevision: input.expectedRevision,
        groupRevision: input.groupRevision, eventId: input.eventId,
        cryptoEpoch: input.cryptoEpoch, cryptoStateRef: input.cryptoStateRef,
        recipientDeviceId: input.recipientDeviceId,
        recipientSignerKeyId: input.recipientSignerKeyId,
        recipientKeyPackageBase64Url: input.recipientKeyPackageBase64Url,
        recipientSignatureBase64Url: input.recipientSignatureBase64Url,
        commitBase64Url: encodeBase64Url(input.commit),
        welcomeBase64Url: encodeBase64Url(input.welcome),
        signatureBase64Url: encodeBase64Url(signature),
      });
      await requireSameSession(auth);
      if (!isObject(result) || result.callId !== input.callId ||
          result.groupId !== descriptor.groupId ||
          result.cryptoEpoch !== input.cryptoEpoch ||
          result.cryptoStateRef !== input.cryptoStateRef ||
          result.recipientDeviceId !== input.recipientDeviceId ||
          result.welcomeStored !== true) {
        throw new Error("endpoint MLS Commit was not durably accepted");
      }
    },
    async fetchEndpointMlsBootstrap(binding, input) {
      const auth = snapshotBinding(binding);
      if (!sameBinding(auth, await session())) throw new Error("first-party account changed");
      const descriptor = await this.describeAcceptedCallMls(auth, input);
      const value = await request("POST", "/v1/first-party/call/mls-bootstrap", {
        binding: auth, callId: input.callId, expectedRevision: input.expectedRevision,
      });
      await requireSameSession(auth);
      if (!isObject(value) || value.callId !== input.callId ||
          value.groupId !== descriptor.groupId || value.deviceId !== auth.deviceId ||
          !Array.isArray(value.commits) || value.commits.length > 128) {
        throw new Error("invalid recipient-bound MLS Welcome");
      }
      const epoch = (value: unknown): number => {
        if (!Number.isSafeInteger(value) || Number(value) < 0) {
          throw new Error("invalid MLS epoch");
        }
        return Number(value);
      };
      const commits = value.commits.map(item => {
        if (!isObject(item)) throw new Error("invalid MLS commit");
        return {
          commit: decodeBase64Url(String(item.commitBase64Url), null, 8192),
          cryptoEpoch: epoch(item.cryptoEpoch),
          cryptoStateRef: requiredId(item.cryptoStateRef, "MLS state ref"),
        };
      });
      const welcomeEpoch = epoch(value.welcomeEpoch);
      const cryptoEpoch = epoch(value.cryptoEpoch);
      let lastEpoch = welcomeEpoch;
      for (const item of commits) {
        if (item.cryptoEpoch !== lastEpoch + 1) throw new Error("MLS commit chain gap/replay");
        lastEpoch = item.cryptoEpoch;
      }
      if (lastEpoch !== cryptoEpoch) throw new Error("incomplete endpoint MLS chain");
      return {
        groupId: descriptor.groupId,
        admissionEventId: requiredId(value.admissionEventId, "MLS admission"),
        welcome: decodeBase64Url(String(value.welcomeBase64Url), null, 8192),
        welcomeEpoch,
        welcomeStateRef: requiredId(value.welcomeStateRef, "MLS state ref"),
        commits,
        cryptoEpoch,
        cryptoStateRef: requiredId(value.cryptoStateRef, "MLS state ref"),
      };
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
      await requireSameSession(auth);
      if (!sameBinding(auth,issued) || issued.callId !== input.callId) {
        throw new Error("first-party Join issuer returned a foreign Call/Device");
      }
      return issued;
    },
    async listDevices() {
      const auth=await session();
      const data=await request("POST","/v1/first-party/device/list",{binding:auth});
      if(!Array.isArray(data)||data.length>64)throw Error("invalid canonical Device list");
      return data.map(row=>{
        if(!isObject(row))throw Error("invalid Device record");
        exactKeys(row,["deviceId","state"]);
        const deviceId=requiredId(row.deviceId,"Device");
        if(!["active","revoked","stale","reverificationRequired","expired"].includes(String(row.state))){
          throw Error("invalid Device lifecycle");
        }
        return {deviceId,state:String(row.state)};
      });
    },
    async revokeDevice(deviceId:string) {
      const auth=await session();
      const result=await request("POST","/v1/first-party/device/revoke",{
        binding:auth,deviceId:requiredId(deviceId,"Device"),
      });
      if(!isObject(result)||result.revoked!==true)throw Error("Device revoke not confirmed");
    },
    async rotateRecoveryCode() {
      const auth=await session();
      const result=await request("POST","/v1/first-party/device/rotate-recovery",{binding:auth});
      if(!isObject(result))throw Error("missing rotated recovery code");
      return encodeBase64Url(decodeBase64Url(result.recoveryCode,32));
    },
    async logout() {
      const auth=await session();
      const result=await request("POST","/v1/first-party/logout",{binding:auth});
      if(!isObject(result)||result.signedOut!==true)throw Error("canonical logout not confirmed");
    },
    async issueSignedDeviceJoin(_binding) {
      // This legacy transport-neutral hook is intentionally unavailable in
      // the integrated first-party BFF. A Device alone is not Call admission.
      // Only issueSignedJoinForAcceptedCall may request a signed grant, after
      // the canonical recipient has accepted the exact Call/revision.
      throw new Error("unscoped Device Join forbidden: use accepted canonical Call admission");
    },
  };
}
