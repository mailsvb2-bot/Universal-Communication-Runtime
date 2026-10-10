import {
  createUcrCanonicalDevicePreparation,
  type UcrCanonicalDeviceEnrollmentAuthority,
  type UcrCanonicalDeviceKeyVault,
  type UcrDeviceEnrollmentBinding,
} from "./canonical_device_enrollment.ts";

/** One authenticated principal/Device resolved by the FIRST-PARTY user auth
 * owner, never derived from an ephemeral Conference Join URL. */
export interface UcrAuthenticatedFirstEntry {
  readonly tenantId: string;
  readonly namespaceId: string | null;
  readonly participantId: string;
  readonly deviceId: string;
}

/** The existing canonical Conference issuer binds the signed join grant to the
 * exact first-entry Device and a new Call/Session. The browser cannot mint it. */
export interface UcrCanonicalJoinIssuance {
  readonly tenantId: string;
  readonly namespaceId: string | null;
  readonly participantId: string;
  readonly deviceId: string;
  readonly callId: string;
  readonly sessionId: string;
  /** An opaque, signed, expiring fragment. NEVER a bearer token in URL query. */
  readonly joinFragment: string;
}

export interface UcrFirstPartyAuthenticatedUserHost
  extends UcrCanonicalDeviceEnrollmentAuthority {
  /** Authenticate through first-party session or local/passkey Identity
   * BEFORE and independently of creating a Call or reading a join fragment.
   * Missing or revoked Identity and Device MUST fail closed on this backend. */
  resumeAuthenticatedDevice(): Promise<UcrAuthenticatedFirstEntry>;
  /** The canonical server MUST independently verify still-active Device,
   * policy, signed expiration and destination, using its existing owners. */
  issueSignedDeviceJoin(binding: UcrAuthenticatedFirstEntry): Promise<UcrCanonicalJoinIssuance>;
}

function sameScope(a: UcrAuthenticatedFirstEntry, b: UcrAuthenticatedFirstEntry): boolean {
  return a.tenantId === b.tenantId &&
    a.namespaceId === b.namespaceId &&
    a.participantId === b.participantId &&
    a.deviceId === b.deviceId;
}

/**
 * One-click first/repeat entry coordinator, not a user authentication system.
 * It creates neither Identity, trust nor join grants. Server-side first-party
 * user auth/BFF remains mandatory and is NOT currently implemented in UCR.
 */
export function createUcrFirstPartyCallEntry(
  host: UcrFirstPartyAuthenticatedUserHost,
  vault: UcrCanonicalDeviceKeyVault,
): () => Promise<UcrCanonicalJoinIssuance> {
  if (!host || typeof host.resumeAuthenticatedDevice !== "function" ||
      typeof host.issueSignedDeviceJoin !== "function") {
    throw new Error("independent first-party user-authenticated host required");
  }
  const prepare = createUcrCanonicalDevicePreparation(host, vault);
  let pending: Promise<UcrCanonicalJoinIssuance> | null = null;
  const enter = async (): Promise<UcrCanonicalJoinIssuance> => {
    // No Call, Session or signed grant is allowed at first-entry auth time.
    const auth = await host.resumeAuthenticatedDevice();
    if (!auth || typeof auth.tenantId !== "string" || !auth.tenantId ||
        typeof auth.deviceId !== "string" || !auth.deviceId ||
        typeof auth.participantId !== "string" || !auth.participantId ||
        !(auth.namespaceId === null || typeof auth.namespaceId === "string")) {
      throw new Error("independent authenticated canonical Device identity unavailable");
    }
    const original: UcrDeviceEnrollmentBinding = Object.freeze({
      tenantId: auth.tenantId, namespaceId: auth.namespaceId,
      participantId: auth.participantId, deviceId: auth.deviceId,
    });
    await prepare(original);
    // Key possession and canonical trusted descriptor are now independently
    // confirmed. Recheck on the SERVER prior to signing any join grant.
    const issued = await host.issueSignedDeviceJoin(original);
    if (!issued || !sameScope(original, issued) ||
        typeof issued.callId !== "string" || !issued.callId ||
        typeof issued.sessionId !== "string" || !issued.sessionId ||
        typeof issued.joinFragment !== "string" ||
        issued.joinFragment.length > 16384 ||
        !issued.joinFragment.startsWith("#ucr_join=") ||
        issued.joinFragment.length <= "#ucr_join=".length) {
      throw new Error("first-party join grant differs from prepared Device");
    }
    // A concurrent Device revocation or signer rotation after issuance cannot
    // allow a stale join fragment to be consumed by this endpoint.
    await prepare({...original, callId:issued.callId, sessionId:issued.sessionId});
    return Object.freeze({...issued});
  };
  return () => {
    if (pending) return pending;
    const operation = enter();
    pending = operation;
    void operation.finally(() => {
      if (pending === operation) pending = null;
    }).catch(() => {});
    return operation;
  };
}
