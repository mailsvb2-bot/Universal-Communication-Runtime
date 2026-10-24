import {
  createUcrCanonicalDevicePreparation,
  type UcrCanonicalDeviceKeyVault,
} from "./canonical_device_enrollment.ts";
import type {
  UcrAuthenticatedFirstEntry,
  UcrCanonicalJoinIssuance,
  UcrFirstPartyAuthenticatedUserHost,
} from "./canonical_first_party_call_entry.ts";
import {
  createUcrPrivateContactBook,
  type UcrPrivateContact,
  type UcrPrivateContactsStorage,
} from "./private_contacts.ts";

/**
 * Only the canonical Call owner can advance the state of a direct call.
 * This SDK deliberately has no browser CallStore or synthesized Ringing/Active.
 * The authenticated BFF must implement these operations by invoking
 * CallService.StartCall/GetCall/SignalCall and canonical participant policy.
 */
export type UcrDirectCallState =
  "inviting" | "ringing" | "active" | "reconnecting" | "terminated";
export type UcrDirectCallAction =
  "accept" | "reject" | "busy" | "cancel" | "hangup";
export type UcrDirectCallMedia = "audio" | "video";

export interface UcrDirectCall {
  readonly tenantId: string;
  readonly namespaceId: string | null;
  readonly callId: string;
  readonly callerIdentityId: string;
  readonly calleeIdentityId: string;
  readonly media: UcrDirectCallMedia;
  readonly state: UcrDirectCallState;
  readonly revision: number;
}

export interface UcrCallStartIntent {
  readonly peerIdentityId: string;
  readonly media: UcrDirectCallMedia;
  readonly idempotencyKey: string;
}

export interface UcrDirectCallHost extends UcrFirstPartyAuthenticatedUserHost {
  /** Must require an authenticated, active Device; idempotency is server-owned. */
  startDirectCall(auth: UcrAuthenticatedFirstEntry, intent: UcrCallStartIntent): Promise<UcrDirectCall>;
  /** Must verify that this caller is an actual Call participant. */
  getDirectCall(auth: UcrAuthenticatedFirstEntry, callId: string): Promise<UcrDirectCall>;
  /** Recipient-scoped incoming Calls, not a globally enumerable directory. */
  listIncomingDirectCalls(auth: UcrAuthenticatedFirstEntry): Promise<UcrDirectCall[]>;
  /** Canonical SignalCall with an atomic expected-revision check. */
  signalDirectCall(
    auth: UcrAuthenticatedFirstEntry,
    request: {callId: string; expectedRevision: number; action: UcrDirectCallAction},
  ): Promise<UcrDirectCall>;
  /** Only for a canonical ACCEPTED/ACTIVE Call. Never mint a Join from a URL. */
  issueSignedJoinForAcceptedCall(
    auth: UcrAuthenticatedFirstEntry,
    request: {callId: string; expectedRevision: number},
  ): Promise<UcrCanonicalJoinIssuance>;
}

function identifier(v: unknown, what: string): asserts v is string {
  if (typeof v !== "string" || !v || v.length > 128 ||
      !/^[A-Za-z0-9_.:@-]+$/.test(v)) {
    throw new Error("invalid canonical " + what);
  }
}
function snapshotAuth(a: UcrAuthenticatedFirstEntry): UcrAuthenticatedFirstEntry {
  if (!a || !(a.namespaceId === null || typeof a.namespaceId === "string")) {
    throw new Error("verified first-party session unavailable");
  }
  identifier(a.tenantId, "tenant"); identifier(a.participantId, "identity");
  identifier(a.deviceId, "device");
  if (a.namespaceId !== null) identifier(a.namespaceId, "namespace");
  return Object.freeze({
    tenantId:a.tenantId, namespaceId:a.namespaceId,
    participantId:a.participantId, deviceId:a.deviceId,
  });
}
function sameUser(a: UcrAuthenticatedFirstEntry, b: UcrAuthenticatedFirstEntry): boolean {
  return a.tenantId === b.tenantId && a.namespaceId === b.namespaceId &&
    a.participantId === b.participantId && a.deviceId === b.deviceId;
}
const STATES: readonly UcrDirectCallState[] =
  ["inviting","ringing","active","reconnecting","terminated"];
function checkedCall(
  raw: UcrDirectCall,
  auth: UcrAuthenticatedFirstEntry,
): UcrDirectCall {
  if (!raw || raw.tenantId !== auth.tenantId || raw.namespaceId !== auth.namespaceId) {
    throw new Error("canonical Call tenant/namespace mismatch");
  }
  identifier(raw.callId,"Call");
  identifier(raw.callerIdentityId,"caller");
  identifier(raw.calleeIdentityId,"recipient");
  if (raw.callerIdentityId === raw.calleeIdentityId ||
      ![raw.callerIdentityId,raw.calleeIdentityId].includes(auth.participantId) ||
      !["audio","video"].includes(raw.media) || !STATES.includes(raw.state) ||
      !Number.isSafeInteger(raw.revision) || raw.revision < 0) {
    throw new Error("canonical Call participants, revision or state invalid");
  }
  return Object.freeze({
    tenantId:raw.tenantId, namespaceId:raw.namespaceId, callId:raw.callId,
    callerIdentityId:raw.callerIdentityId,
    calleeIdentityId:raw.calleeIdentityId,
    media:raw.media, state:raw.state, revision:raw.revision,
  });
}
function assertCallIdentity(a: UcrDirectCall, b: UcrDirectCall): void {
  if (a.callId !== b.callId || a.tenantId !== b.tenantId ||
      a.namespaceId !== b.namespaceId ||
      a.callerIdentityId !== b.callerIdentityId ||
      a.calleeIdentityId !== b.calleeIdentityId || a.media !== b.media ||
      b.revision < a.revision) {
    throw new Error("canonical Call changed identity or rolled back");
  }
}
function checkedJoin(
  issued: UcrCanonicalJoinIssuance,
  auth: UcrAuthenticatedFirstEntry,
  callId: string,
): UcrCanonicalJoinIssuance {
  if (!issued || !sameUser(issued,auth) || issued.callId !== callId) {
    throw new Error("Join authority returned a foreign Call/Device");
  }
  identifier(issued.sessionId,"Session");
  if (typeof issued.joinFragment !== "string" ||
      !issued.joinFragment.startsWith("#ucr_join=") ||
      issued.joinFragment.length <= "#ucr_join=".length ||
      issued.joinFragment.length > 16384) {
    throw new Error("signed Call Join missing or malformed");
  }
  return Object.freeze({
    tenantId:issued.tenantId, namespaceId:issued.namespaceId,
    participantId:issued.participantId, deviceId:issued.deviceId,
    callId:issued.callId, sessionId:issued.sessionId,
    joinFragment:issued.joinFragment,
  });
}

export function createUcrContactCallJourney(
  host: UcrDirectCallHost,
  vault: UcrCanonicalDeviceKeyVault,
  storage?: UcrPrivateContactsStorage,
) {
  if (!host || typeof host.resumeAuthenticatedDevice !== "function" ||
      typeof host.startDirectCall !== "function" ||
      typeof host.getDirectCall !== "function" ||
      typeof host.listIncomingDirectCalls !== "function" ||
      typeof host.signalDirectCall !== "function" ||
      typeof host.issueSignedJoinForAcceptedCall !== "function") {
    throw new Error("independently authenticated canonical Call/Device host required");
  }
  const prepare = createUcrCanonicalDevicePreparation(host,vault);
  async function session(): Promise<UcrAuthenticatedFirstEntry> {
    return snapshotAuth(await host.resumeAuthenticatedDevice());
  }
  async function stillSame(auth: UcrAuthenticatedFirstEntry): Promise<void> {
    if (!sameUser(auth,await session())) {
      throw new Error("first-party account or Device switched during Call");
    }
  }
  function book(auth: UcrAuthenticatedFirstEntry) {
    return createUcrPrivateContactBook({
      tenantId:auth.tenantId,namespaceId:auth.namespaceId,
      identityId:auth.participantId,
    },storage);
  }
  async function retrieve(auth: UcrAuthenticatedFirstEntry,callId: string) {
    identifier(callId,"Call");
    const snapshot=checkedCall(await host.getDirectCall(auth,callId),auth);
    if (snapshot.callId!==callId) throw new Error("canonical Call lookup mismatch");
    await stillSame(auth);
    return snapshot;
  }
  return {
    /** Contacts are read only from the logged-in user's encrypted local book. */
    async contacts(): Promise<readonly UcrPrivateContact[]> {
      const auth=await session(), entries=await book(auth).list();
      await stillSame(auth);
      return entries;
    },
    async addContact(name:string,peerIdentityId:string):Promise<UcrPrivateContact> {
      const auth=await session();
      identifier(peerIdentityId,"peer Identity");
      if (peerIdentityId===auth.participantId) throw new Error("cannot add self as peer");
      const entry=await book(auth).add(name,peerIdentityId);
      await stillSame(auth);
      return entry;
    },
    async removeContact(contactId:string):Promise<void> {
      const auth=await session();
      await book(auth).remove(contactId);
      await stillSame(auth);
    },
    /** One click = one canonical StartCall; never turn a Contact into a Join. */
    async start(contactId:string,media:UcrDirectCallMedia,idempotencyKey:string):Promise<UcrDirectCall> {
      const auth=await session();
      if (!["audio","video"].includes(media)) throw new Error("invalid call media");
      identifier(idempotencyKey,"Call idempotency key");
      const contact=(await book(auth).list()).find(c=>c.id===contactId);
      if (!contact) throw new Error("selected contact no longer exists");
      const peer=contact.peerIdentityId;
      identifier(peer,"peer Identity");
      if (peer===auth.participantId) throw new Error("cannot call own Identity");
      await prepare(auth);
      await stillSame(auth);
      const call=checkedCall(await host.startDirectCall(auth,{
        peerIdentityId:peer,media,idempotencyKey,
      }),auth);
      if (call.callerIdentityId!==auth.participantId ||
          call.calleeIdentityId!==peer || call.media!==media ||
          !["inviting","ringing"].includes(call.state)) {
        throw new Error("canonical Call not addressed to selected contact");
      }
      await stillSame(auth);
      return call;
    },
    async incoming():Promise<readonly UcrDirectCall[]> {
      const auth=await session();
      const response=await host.listIncomingDirectCalls(auth);
      if (!Array.isArray(response) || response.length>100) {
        throw new Error("invalid authenticated incoming Call collection");
      }
      const calls=response.map(c=>checkedCall(c,auth));
      if (calls.some(c=>c.calleeIdentityId!==auth.participantId ||
          !["inviting","ringing"].includes(c.state)) ||
          new Set(calls.map(c=>c.callId)).size!==calls.length) {
        throw new Error("foreign or invalid incoming Call");
      }
      await stillSame(auth);
      return calls;
    },
    async inspect(callId:string):Promise<UcrDirectCall> {
      const auth=await session();
      return retrieve(auth,callId);
    },
    async signal(callId:string,action:UcrDirectCallAction):Promise<UcrDirectCall> {
      const auth=await session();
      if (!["accept","reject","busy","cancel","hangup"].includes(action)) {
        throw new Error("unsupported canonical Call signal");
      }
      const before=await retrieve(auth,callId);
      if (["accept","reject","busy"].includes(action) &&
          (before.calleeIdentityId!==auth.participantId ||
           !["inviting","ringing"].includes(before.state))) {
        throw new Error("only the invited recipient may answer a ringing Call");
      }
      if (action==="cancel" &&
          (before.callerIdentityId!==auth.participantId ||
           !["inviting","ringing"].includes(before.state))) {
        throw new Error("only the initiator may cancel an unanswered Call");
      }
      if (action==="hangup" && !["active","reconnecting"].includes(before.state)) {
        throw new Error("no active Call to end");
      }
      await prepare(auth);
      await stillSame(auth);
      const result=checkedCall(await host.signalDirectCall(auth,{
        callId,action,expectedRevision:before.revision,
      }),auth);
      assertCallIdentity(before,result);
      if (result.revision<=before.revision) throw new Error("Call signal not committed");
      // A successful HTTP response is not proof that the requested canonical
      // transition happened. Never report a completed hangup while the Call
      // owner still considers the microphone/video session active.
      const expectedState = action==="accept" ? "active" : "terminated";
      if (result.state!==expectedState) {
        throw new Error("canonical Call signal returned unexpected state");
      }
      await stillSame(auth);
      return result;
    },
    /** Entry requires live ACCEPTED canonical Call and own trusted signer. */
    async join(callId:string):Promise<UcrCanonicalJoinIssuance> {
      const auth=await session();
      const before=await retrieve(auth,callId);
      if (before.state!=="active") throw new Error("recipient has not accepted Call");
      await prepare(auth);
      await stillSame(auth);
      const issued=checkedJoin(await host.issueSignedJoinForAcceptedCall(auth,{
        callId,expectedRevision:before.revision,
      }),auth,callId);
      await prepare({...auth,callId,sessionId:issued.sessionId},true);
      const current=await retrieve(auth,callId);
      assertCallIdentity(before,current);
      // Join was issued against before.revision. An intervening Call change,
      // even one that returns to ACTIVE, makes this grant stale for the SDK.
      if (current.revision!==before.revision) {
        throw new Error("canonical Call changed during signed Join issuance");
      }
      if (current.state!=="active") throw new Error("Call ended before media admission");
      await stillSame(auth);
      return issued;
    },
  };
}
